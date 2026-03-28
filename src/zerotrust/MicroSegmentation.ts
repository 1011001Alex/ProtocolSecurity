/**
 * Micro-Segmentation - Микросегментация Сети
 * 
 * Компонент реализует микросегментацию сети для предотвращения
 * lateral movement атак. Создаёт изолированные сегменты для рабочих
 * нагрузок и применяет детальные правила трафика между ними.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { v4 as uuidv4 } from 'uuid';
import {
  MicroSegmentationRule,
  NetworkSegment,
  NetworkSegmentType,
  ZeroTrustEvent,
  SubjectType
} from './zerotrust.types';

/**
 * Конфигурация Micro-Segmentation
 */
export interface MicroSegmentationConfig {
  /** Включить сегментацию по умолчанию */
  defaultDeny: boolean;
  
  /** Включить логирование трафика */
  enableTrafficLogging: boolean;
  
  /** Включить IDS/IPS инспекцию */
  enableInspection: boolean;
  
  /** Интервал обновления правил (секунды) */
  ruleUpdateInterval: number;
  
  /** Максимальное количество правил на сегмент */
  maxRulesPerSegment: number;
  
  /** Включить приоритизацию правил */
  enableRulePrioritization: boolean;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
}

/**
 * Статистика сегмента
 */
interface SegmentStats {
  /** Входящий трафик (байт) */
  inboundBytes: number;
  
  /** Исходящий трафик (байт) */
  outboundBytes: number;
  
  /** Количество соединений */
  connectionCount: number;
  
  /** Количество разрешённых соединений */
  allowedConnections: number;
  
  /** Количество заблокированных соединений */
  blockedConnections: number;
  
  /** Последняя активность */
  lastActivity: Date;
}

/**
 * Micro-Segmentation Engine
 * 
 * Компонент для создания и управления микросегментами сети.
 */
export class MicroSegmentation extends EventEmitter {
  /** Конфигурация */
  private config: MicroSegmentationConfig;
  
  /** Сетевые сегменты */
  private segments: Map<string, NetworkSegment>;
  
  /** Правила сегментации */
  private rules: Map<string, MicroSegmentationRule>;
  
  /** Статистика по сегментам */
  private segmentStats: Map<string, SegmentStats>;
  
  /** Индексы для быстрого поиска */
  private workloadIndex: Map<string, string>; // workload -> segmentId
  
  /** Статистика */
  private stats: {
    /** Всего сегментов */
    totalSegments: number;
    /** Всего правил */
    totalRules: number;
    /** Разрешено соединений */
    allowedConnections: number;
    /** Заблокировано соединений */
    blockedConnections: number;
  };

  constructor(config: Partial<MicroSegmentationConfig> = {}) {
    super();
    
    this.config = {
      defaultDeny: config.defaultDeny ?? true,
      enableTrafficLogging: config.enableTrafficLogging ?? true,
      enableInspection: config.enableInspection ?? false,
      ruleUpdateInterval: config.ruleUpdateInterval ?? 60,
      maxRulesPerSegment: config.maxRulesPerSegment ?? 1000,
      enableRulePrioritization: config.enableRulePrioritization ?? true,
      enableVerboseLogging: config.enableVerboseLogging ?? false
    };
    
    this.segments = new Map();
    this.rules = new Map();
    this.segmentStats = new Map();
    this.workloadIndex = new Map();
    
    this.stats = {
      totalSegments: 0,
      totalRules: 0,
      allowedConnections: 0,
      blockedConnections: 0
    };
    
    this.log('MS', 'MicroSegmentation инициализирован');
  }

  /**
   * Создать сетевой сегмент
   */
  public createSegment(segment: Omit<NetworkSegment, 'appliedRules' | 'trafficStats'>): NetworkSegment {
    const newSegment: NetworkSegment = {
      ...segment,
      appliedRules: [],
      trafficStats: {
        inboundBytes: 0,
        outboundBytes: 0,
        connectionCount: 0,
        blockedAttempts: 0
      }
    };
    
    this.segments.set(segment.id, newSegment);
    this.stats.totalSegments++;
    
    // Инициализируем статистику
    this.segmentStats.set(segment.id, {
      inboundBytes: 0,
      outboundBytes: 0,
      connectionCount: 0,
      allowedConnections: 0,
      blockedConnections: 0,
      lastActivity: new Date()
    });
    
    this.log('MS', 'Создан сетевой сегмент', {
      id: segment.id,
      name: segment.name,
      type: segment.type,
      cidr: segment.cidr
    });
    
    this.emit('segment:created', newSegment);
    
    return newSegment;
  }

  /**
   * Получить сегмент по ID
   */
  public getSegment(segmentId: string): NetworkSegment | undefined {
    return this.segments.get(segmentId);
  }

  /**
   * Удалить сегмент
   */
  public deleteSegment(segmentId: string): boolean {
    const segment = this.segments.get(segmentId);
    
    if (!segment) {
      return false;
    }
    
    // Удаляем связанные правила
    const relatedRules = Array.from(this.rules.values())
      .filter(r => 
        r.sourceSegment.segmentId === segmentId || 
        r.destinationSegment.segmentId === segmentId
      );
    
    for (const rule of relatedRules) {
      this.rules.delete(rule.id);
    }
    
    this.stats.totalRules -= relatedRules.length;
    this.segments.delete(segmentId);
    this.segmentStats.delete(segmentId);
    this.stats.totalSegments--;
    
    this.log('MS', 'Удалён сегмент', { segmentId });
    this.emit('segment:deleted', { segmentId });
    
    return true;
  }

  /**
   * Добавить правило сегментации
   */
  public addRule(rule: MicroSegmentationRule): void {
    // Проверяем лимит правил
    const sourceRules = Array.from(this.rules.values())
      .filter(r => r.sourceSegment.segmentId === rule.sourceSegment.segmentId);
    
    if (sourceRules.length >= this.config.maxRulesPerSegment) {
      throw new Error(
        `Превышен лимит правил для сегмента ${rule.sourceSegment.segmentId}`
      );
    }
    
    this.rules.set(rule.id, rule);
    this.stats.totalRules++;
    
    // Обновляем применённые правила в сегментах
    this.updateSegmentRules(rule.sourceSegment.segmentId);
    this.updateSegmentRules(rule.destinationSegment.segmentId);
    
    this.log('MS', 'Добавлено правило сегментации', {
      ruleId: rule.id,
      name: rule.name,
      source: rule.sourceSegment.segmentId,
      destination: rule.destinationSegment.segmentId,
      action: rule.action
    });
    
    this.emit('rule:added', rule);
  }

  /**
   * Обновить применённые правила сегмента
   */
  private updateSegmentRules(segmentId: string): void {
    const segment = this.segments.get(segmentId);
    
    if (!segment) {
      return;
    }
    
    const applicableRules = Array.from(this.rules.values())
      .filter(r => 
        r.sourceSegment.segmentId === segmentId || 
        r.destinationSegment.segmentId === segmentId
      )
      .filter(r => r.enabled)
      .sort((a, b) => a.priority - b.priority);
    
    segment.appliedRules = applicableRules.map(r => r.id);
    
    if (this.config.enableRulePrioritization) {
      // Сортируем правила по приоритету
      applicableRules.sort((a, b) => a.priority - b.priority);
    }
  }

  /**
   * Удалить правило
   */
  public removeRule(ruleId: string): boolean {
    const rule = this.rules.get(ruleId);
    
    if (!rule) {
      return false;
    }
    
    const sourceId = rule.sourceSegment.segmentId;
    const destId = rule.destinationSegment.segmentId;
    
    this.rules.delete(ruleId);
    this.stats.totalRules--;
    
    // Обновляем сегменты
    this.updateSegmentRules(sourceId);
    this.updateSegmentRules(destId);
    
    this.log('MS', 'Удалено правило', { ruleId });
    this.emit('rule:removed', { ruleId });
    
    return true;
  }

  /**
   * Проверить разрешение трафика
   * 
   * @param sourceId ID исходного сегмента или workload
   * @param destinationId ID целевого сегмента или workload
   * @param protocol Протокол (TCP/UDP/ICMP)
   * @param destinationPort Порт назначения
   * @returns Результат проверки
   */
  public checkTraffic(
    sourceId: string,
    destinationId: string,
    protocol: string,
    destinationPort: number
  ): {
    allowed: boolean;
    matchedRule?: MicroSegmentationRule;
    action: 'ALLOW' | 'DENY' | 'LOG';
    reason: string;
  } {
    // Получаем сегменты
    const sourceSegmentId = this.workloadIndex.get(sourceId) || sourceId;
    const destSegmentId = this.workloadIndex.get(destinationId) || destinationId;
    
    const sourceSegment = this.segments.get(sourceSegmentId);
    const destSegment = this.segments.get(destSegmentId);
    
    if (!sourceSegment || !destSegment) {
      return {
        allowed: false,
        action: 'DENY',
        reason: 'Сегмент не найден'
      };
    }
    
    // Ищем подходящее правило
    const matchedRule = this.findMatchingRule(
      sourceSegmentId,
      destSegmentId,
      protocol,
      destinationPort
    );
    
    // Обновляем статистику
    this.updateTrafficStats(sourceSegmentId, destSegmentId, matchedRule?.action === 'ALLOW');
    
    if (matchedRule) {
      const allowed = matchedRule.action === 'ALLOW';
      
      if (allowed) {
        this.stats.allowedConnections++;
      } else {
        this.stats.blockedConnections++;
      }
      
      if (this.config.enableTrafficLogging) {
        this.log('MS', 'Трафик проверен', {
          source: sourceSegmentId,
          destination: destSegmentId,
          protocol,
          port: destinationPort,
          allowed,
          ruleId: matchedRule.id
        });
      }
      
      return {
        allowed,
        matchedRule,
        action: matchedRule.action,
        reason: `Правило: ${matchedRule.name}`
      };
    }
    
    // Нет правила - применяем default deny
    this.stats.blockedConnections++;
    
    const result = {
      allowed: !this.config.defaultDeny,
      action: this.config.defaultDeny ? 'DENY' : 'ALLOW' as 'ALLOW' | 'DENY' | 'LOG',
      reason: this.config.defaultDeny 
        ? 'Default deny - нет разрешающего правила' 
        : 'Default allow - нет запрещающего правила'
    };
    
    if (this.config.enableTrafficLogging) {
      this.log('MS', 'Трафик проверен (default)', {
        source: sourceSegmentId,
        destination: destSegmentId,
        protocol,
        port: destinationPort,
        ...result
      });
    }
    
    return result;
  }

  /**
   * Найти подходящее правило
   */
  private findMatchingRule(
    sourceSegmentId: string,
    destSegmentId: string,
    protocol: string,
    destinationPort: number
  ): MicroSegmentationRule | undefined {
    // Получаем все правила для этой пары сегментов
    const candidateRules = Array.from(this.rules.values())
      .filter(r => 
        r.enabled &&
        r.sourceSegment.segmentId === sourceSegmentId &&
        r.destinationSegment.segmentId === destSegmentId
      )
      .sort((a, b) => a.priority - b.priority); // Сортируем по приоритету
    
    // Ищем первое подходящее правило
    for (const rule of candidateRules) {
      if (this.ruleMatchesProtocol(rule, protocol, destinationPort)) {
        return rule;
      }
    }
    
    return undefined;
  }

  /**
   * Проверить соответствие правила протоколу и порту
   */
  private ruleMatchesProtocol(
    rule: MicroSegmentationRule,
    protocol: string,
    destinationPort: number
  ): boolean {
    // Проверяем протокол
    const protocolMatch = rule.protocols.some(p => 
      p.protocol === protocol || p.protocol === 'ANY'
    );
    
    if (!protocolMatch) {
      return false;
    }
    
    // Проверяем порты
    const portMatch = rule.protocols.some(p => {
      if (!p.destinationPorts || p.destinationPorts.length === 0) {
        return true; // Все порты разрешены
      }
      
      return p.destinationPorts.some(portSpec => {
        if (portSpec.includes('-')) {
          // Диапазон портов
          const [start, end] = portSpec.split('-').map(Number);
          return destinationPort >= start && destinationPort <= end;
        }
        
        // Конкретный порт
        return destinationPort === Number(portSpec);
      });
    });
    
    return portMatch;
  }

  /**
   * Обновить статистику трафика
   */
  private updateTrafficStats(
    sourceId: string,
    destinationId: string,
    allowed: boolean
  ): void {
    const now = new Date();
    
    // Обновляем статистику источника
    const sourceStats = this.segmentStats.get(sourceId);
    if (sourceStats) {
      sourceStats.connectionCount++;
      sourceStats.lastActivity = now;
      
      if (allowed) {
        sourceStats.allowedConnections++;
      } else {
        sourceStats.blockedConnections++;
      }
    }
    
    // Обновляем статистику назначения
    const destStats = this.segmentStats.get(destinationId);
    if (destStats) {
      destStats.connectionCount++;
      destStats.lastActivity = now;
      
      if (allowed) {
        destStats.allowedConnections++;
      } else {
        destStats.blockedConnections++;
      }
    }
  }

  /**
   * Зарегистрировать workload в сегменте
   */
  public registerWorkload(workloadId: string, segmentId: string): void {
    const segment = this.segments.get(segmentId);
    
    if (!segment) {
      throw new Error(`Сегмент не найден: ${segmentId}`);
    }
    
    this.workloadIndex.set(workloadId, segmentId);
    
    this.log('MS', 'Workload зарегистрирован', {
      workloadId,
      segmentId,
      segmentName: segment.name
    });
    
    this.emit('workload:registered', { workloadId, segmentId });
  }

  /**
   * Отменить регистрацию workload
   */
  public unregisterWorkload(workloadId: string): void {
    this.workloadIndex.delete(workloadId);
    this.log('MS', 'Workload отменён', { workloadId });
    this.emit('workload:unregistered', { workloadId });
  }

  /**
   * Получить сегмент workload
   */
  public getWorkloadSegment(workloadId: string): NetworkSegment | undefined {
    const segmentId = this.workloadIndex.get(workloadId);
    
    if (!segmentId) {
      return undefined;
    }
    
    return this.segments.get(segmentId);
  }

  /**
   * Получить все сегменты
   */
  public getAllSegments(): NetworkSegment[] {
    return Array.from(this.segments.values());
  }

  /**
   * Получить все правила
   */
  public getAllRules(): MicroSegmentationRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Получить статистику сегмента
   */
  public getSegmentStats(segmentId: string): SegmentStats | undefined {
    return this.segmentStats.get(segmentId);
  }

  /**
   * Получить общую статистику
   */
  public getStats(): typeof this.stats & {
    /** Workload в индексе */
    indexedWorkloads: number;
  } {
    return {
      ...this.stats,
      indexedWorkloads: this.workloadIndex.size
    };
  }

  /**
   * Экспорт правил для eBPF
   * 
   * Генерирует конфигурацию для eBPF программ
   */
  public exportForEBpf(): {
    version: string;
    generatedAt: Date;
    segments: Array<{
      id: string;
      cidr: string;
      policies: Array<{
        destination: string;
        protocol: string;
        ports: string[];
        action: string;
      }>;
    }>;
  } {
    const exportData = {
      version: '1.0',
      generatedAt: new Date(),
      segments: Array.from(this.segments.values()).map(segment => ({
        id: segment.id,
        cidr: segment.cidr,
        policies: segment.appliedRules
          .map(ruleId => this.rules.get(ruleId))
          .filter((r): r is MicroSegmentationRule => r !== undefined && r.enabled)
          .map(rule => ({
            destination: rule.destinationSegment.cidr || rule.destinationSegment.segmentId,
            protocol: rule.protocols.map(p => p.protocol).join(','),
            ports: rule.protocols.flatMap(p => p.destinationPorts),
            action: rule.action
          }))
      }))
    };
    
    this.log('MS', 'Экспорт правил для eBPF выполнен', {
      segmentCount: exportData.segments.length
    });
    
    return exportData;
  }

  /**
   * Логирование
   */
  private log(component: string, message: string, data?: unknown): void {
    const logData = typeof data === 'object' && data !== null ? data : { data };
    
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'ACCESS_REQUEST',
      timestamp: new Date(),
      subject: {
        id: 'system',
        type: SubjectType.SYSTEM,
        name: component
      },
      details: { message, ...logData },
      severity: 'INFO',
      correlationId: uuidv4()
    };

    this.emit('log', event);

    if (this.config.enableVerboseLogging) {
      logger.debug(`[MS] ${message}`, { timestamp: new Date().toISOString(), ...logData });
    }
  }
}

export default MicroSegmentation;
