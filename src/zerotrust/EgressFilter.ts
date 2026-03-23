/**
 * Egress Filter - Фильтрация Исходящего Трафика
 * 
 * Компонент реализует фильтрацию исходящего трафика с DLP
 * (Data Loss Prevention) для предотвращения утечек данных.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { v4 as uuidv4 } from 'uuid';
import {
  EgressFilterRule,
  DlpEvent,
  SensitiveDataType,
  ZeroTrustEvent,
  SubjectType
} from './zerotrust.types';

/**
 * Конфигурация Egress Filter
 */
export interface EgressFilterConfig {
  /** Включить фильтрацию по умолчанию */
  defaultDeny: boolean;
  
  /** Включить DLP инспекцию */
  enableDlpInspection: boolean;
  
  /** Включить проверку URL */
  enableUrlFiltering: boolean;
  
  /** Включить проверку доменов */
  enableDomainFiltering: boolean;
  
  /** Включить проверку IP */
  enableIpFiltering: boolean;
  
  /** Включить проверку портов */
  enablePortFiltering: boolean;
  
  /** Включить SSL/TLS инспекцию */
  enableSslInspection: boolean;
  
  /** Включить логирование всего трафика */
  enableAllTrafficLogging: boolean;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
}

/**
 * DLP Pattern для обнаружения чувствительных данных
 */
interface DlpPattern {
  /** Тип данных */
  type: SensitiveDataType;
  
  /** Regex паттерн */
  pattern: RegExp;
  
  /** Описание */
  description: string;
  
  /** Вес совпадения */
  weight: number;
}

/**
 * Результат проверки egress
 */
interface EgressCheckResult {
  /** ID запроса */
  requestId: string;
  
  /** Разрешён ли трафик */
  allowed: boolean;
  
  /** Применённое правило */
  matchedRule?: EgressFilterRule;
  
  /** DLP события */
  dlpEvents: DlpEvent[];
  
  /** Действие */
  action: 'ALLOW' | 'DENY' | 'INSPECT' | 'BLOCK_WITH_DLP';
  
  /** Причина */
  reason: string;
}

/**
 * Egress Filter
 * 
 * Компонент для фильтрации исходящего трафика с DLP.
 */
export class EgressFilter extends EventEmitter {
  /** Конфигурация */
  private config: EgressFilterConfig;
  
  /** Правила фильтрации */
  private rules: Map<string, EgressFilterRule>;
  
  /** DLP паттерны */
  private dlpPatterns: DlpPattern[];
  
  /** DLP события */
  private dlpEvents: DlpEvent[];
  
  /** Статистика */
  private stats: {
    /** Всего запросов */
    totalRequests: number;
    /** Разрешено */
    allowed: number;
    /** Заблокировано */
    blocked: number;
    /** DLP событий */
    dlpEvents: number;
    /** Заблокировано DLP */
    dlpBlocked: number;
  };

  constructor(config: Partial<EgressFilterConfig> = {}) {
    super();
    
    this.config = {
      defaultDeny: config.defaultDeny ?? true,
      enableDlpInspection: config.enableDlpInspection ?? true,
      enableUrlFiltering: config.enableUrlFiltering ?? true,
      enableDomainFiltering: config.enableDomainFiltering ?? true,
      enableIpFiltering: config.enableIpFiltering ?? true,
      enablePortFiltering: config.enablePortFiltering ?? true,
      enableSslInspection: config.enableSslInspection ?? false,
      enableAllTrafficLogging: config.enableAllTrafficLogging ?? false,
      enableVerboseLogging: config.enableVerboseLogging ?? false
    };
    
    this.rules = new Map();
    this.dlpPatterns = this.initializeDlpPatterns();
    this.dlpEvents = [];
    
    this.stats = {
      totalRequests: 0,
      allowed: 0,
      blocked: 0,
      dlpEvents: 0,
      dlpBlocked: 0
    };
    
    this.log('EF', 'EgressFilter инициализирован');
  }

  /**
   * Инициализировать DLP паттерны
   */
  private initializeDlpPatterns(): DlpPattern[] {
    return [
      // Кредитные карты (PCI DSS)
      {
        type: SensitiveDataType.FINANCIAL,
        pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/,
        description: 'Credit Card Numbers',
        weight: 10
      },
      
      // SSN (US Social Security Number)
      {
        type: SensitiveDataType.PII,
        pattern: /\b\d{3}-\d{2}-\d{4}\b/,
        description: 'US Social Security Number',
        weight: 10
      },
      
      // Email адреса
      {
        type: SensitiveDataType.PII,
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
        description: 'Email Addresses',
        weight: 3
      },
      
      // Телефонные номера
      {
        type: SensitiveDataType.PII,
        pattern: /\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/,
        description: 'Phone Numbers',
        weight: 5
      },
      
      // API ключи (общий паттерн)
      {
        type: SensitiveDataType.CREDENTIALS,
        pattern: /\b(?:api[_-]?key|apikey|api_secret)["\s:=]+[A-Za-z0-9_-]{20,}\b/i,
        description: 'API Keys',
        weight: 8
      },
      
      // Пароли в URL
      {
        type: SensitiveDataType.CREDENTIALS,
        pattern: /[?&](?:password|passwd|pwd|secret|token)=([^&]+)/i,
        description: 'Passwords in URL',
        weight: 10
      },
      
      // Private ключи
      {
        type: SensitiveDataType.ENCRYPTION_KEYS,
        pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
        description: 'Private Keys',
        weight: 10
      },
      
      // JWT токены
      {
        type: SensitiveDataType.CREDENTIALS,
        pattern: /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
        description: 'JWT Tokens',
        weight: 7
      }
    ];
  }

  /**
   * Добавить правило фильтрации
   */
  public addRule(rule: EgressFilterRule): void {
    this.rules.set(rule.id, rule);
    this.log('EF', 'Правило добавлено', {
      ruleId: rule.id,
      name: rule.name,
      action: rule.action
    });
    this.emit('rule:added', rule);
  }

  /**
   * Удалить правило
   */
  public removeRule(ruleId: string): boolean {
    const removed = this.rules.delete(ruleId);
    
    if (removed) {
      this.log('EF', 'Правило удалено', { ruleId });
      this.emit('rule:removed', { ruleId });
    }
    
    return removed;
  }

  /**
   * Проверить исходящий запрос
   */
  public checkEgress(context: {
    sourceIp: string;
    sourceSegment?: string;
    destinationUrl?: string;
    destinationDomain?: string;
    destinationIp?: string;
    destinationPort?: number;
    protocol?: string;
    payload?: Buffer | string;
    subjectId?: string;
  }): EgressCheckResult {
    const requestId = uuidv4();
    this.stats.totalRequests++;
    
    this.log('EF', 'Проверка исходящего трафика', {
      requestId,
      destination: context.destinationUrl || context.destinationIp
    });
    
    const dlpEvents: DlpEvent[] = [];
    
    // Находим подходящее правило
    const matchedRule = this.findMatchingRule(context);
    
    // DLP инспекция если включена
    if (this.config.enableDlpInspection && context.payload) {
      const payload = typeof context.payload === 'string' 
        ? context.payload 
        : context.payload.toString('utf-8');
      
      const detectedData = this.inspectForDlp(payload, context);
      
      if (detectedData.length > 0) {
        const dlpEvent: DlpEvent = {
          eventId: uuidv4(),
          timestamp: new Date(),
          eventType: 'DATA_DETECTED',
          source: {
            ipAddress: context.sourceIp,
            subjectId: context.subjectId || 'unknown',
            application: 'egress-filter'
          },
          destination: {
            url: context.destinationUrl || '',
            ipAddress: context.destinationIp || '',
            port: context.destinationPort || 0
          },
          detectedData: {
            types: [...new Set(detectedData.map(d => d.type))],
            matchCount: detectedData.length,
            maskedSamples: detectedData.slice(0, 3).map(d => this.maskData(d.match)),
            confidenceScore: Math.min(100, detectedData.reduce((sum, d) => sum + d.weight, 0))
          },
          actionsTaken: [],
          severity: this.calculateDlpSeverity(detectedData)
        };
        
        dlpEvents.push(dlpEvent);
        this.dlpEvents.push(dlpEvent);
        this.stats.dlpEvents++;
        
        this.log('EF', 'DLP обнаружение', {
          requestId,
          types: dlpEvent.detectedData.types,
          severity: dlpEvent.severity
        });
        
        this.emit('dlp:detected', dlpEvent);
      }
    }
    
    // Определяем действие
    let action: EgressCheckResult['action'];
    let allowed: boolean;
    let reason: string;
    
    if (dlpEvents.length > 0) {
      // DLP обнаружил чувствительные данные
      const shouldBlock = dlpEvents.some(e => e.severity === 'HIGH' || e.severity === 'CRITICAL');
      
      if (shouldBlock) {
        action = 'BLOCK_WITH_DLP';
        allowed = false;
        reason = 'DLP: Обнаружены чувствительные данные';
        this.stats.dlpBlocked++;
        this.stats.blocked++;
        
        dlpEvents.forEach(e => e.actionsTaken.push('BLOCKED'));
      } else {
        action = 'INSPECT';
        allowed = true;
        reason = 'DLP: Данные обнаружены, но разрешены с логированием';
        this.stats.allowed++;
        
        dlpEvents.forEach(e => e.actionsTaken.push('LOGGED'));
      }
    } else if (matchedRule) {
      // Правило найдено
      if (matchedRule.action === 'ALLOW') {
        action = 'ALLOW';
        allowed = true;
        reason = `Правило: ${matchedRule.name}`;
        this.stats.allowed++;
      } else if (matchedRule.action === 'DENY') {
        action = 'DENY';
        allowed = false;
        reason = `Правило: ${matchedRule.name}`;
        this.stats.blocked++;
      } else {
        action = 'INSPECT';
        allowed = true;
        reason = `Правило: ${matchedRule.name} (inspection)`;
        this.stats.allowed++;
      }
    } else {
      // Нет правила - default deny
      if (this.config.defaultDeny) {
        action = 'DENY';
        allowed = false;
        reason = 'Default deny - нет разрешающего правила';
        this.stats.blocked++;
      } else {
        action = 'ALLOW';
        allowed = true;
        reason = 'Default allow - нет запрещающего правила';
        this.stats.allowed++;
      }
    }
    
    const result: EgressCheckResult = {
      requestId,
      allowed,
      matchedRule: matchedRule || undefined,
      dlpEvents,
      action,
      reason
    };
    
    this.emit('egress:checked', result);
    
    return result;
  }

  /**
   * Найти подходящее правило
   */
  private findMatchingRule(context: {
    sourceSegment?: string;
    destinationUrl?: string;
    destinationDomain?: string;
    destinationIp?: string;
    destinationPort?: number;
    protocol?: string;
  }): EgressFilterRule | undefined {
    const rules = Array.from(this.rules.values())
      .filter(r => r.enabled)
      .sort((a, b) => a.priority - b.priority);
    
    for (const rule of rules) {
      if (this.ruleMatches(rule, context)) {
        return rule;
      }
    }
    
    return undefined;
  }

  /**
   * Проверить соответствие правила
   */
  private ruleMatches(
    rule: EgressFilterRule,
    context: {
      sourceSegment?: string;
      destinationUrl?: string;
      destinationDomain?: string;
      destinationIp?: string;
      destinationPort?: number;
      protocol?: string;
    }
  ): boolean {
    // Проверка source segment
    if (rule.sourceSegments.length > 0 && context.sourceSegment) {
      if (!rule.sourceSegments.includes(context.sourceSegment)) {
        return false;
      }
    }
    
    // Проверка домена
    if (rule.destinations.domains && context.destinationDomain) {
      const domainMatch = rule.destinations.domains.some(d => {
        if (d.startsWith('*.')) {
          return context.destinationDomain!.endsWith(d.substring(1));
        }
        return context.destinationDomain === d;
      });
      
      if (!domainMatch) {
        return false;
      }
    }
    
    // Проверка URL паттернов
    if (rule.destinations.urlPatterns && context.destinationUrl) {
      const urlMatch = rule.destinations.urlPatterns.some(pattern => {
        const regex = new RegExp(pattern);
        return regex.test(context.destinationUrl!);
      });
      
      if (!urlMatch) {
        return false;
      }
    }
    
    // Проверка IP
    if (rule.destinations.ipRanges && context.destinationIp) {
      const ipMatch = rule.destinations.ipRanges.some(range => {
        // Простая проверка CIDR (в реальной реализации нужна полная)
        return context.destinationIp!.startsWith(range.split('/')[0].split('.').slice(0, 2).join('.'));
      });
      
      if (!ipMatch) {
        return false;
      }
    }
    
    // Проверка портов
    if (rule.destinations.ports && context.destinationPort) {
      if (!rule.destinations.ports.includes(context.destinationPort)) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * DLP инспекция контента
   */
  private inspectForDlp(
    content: string,
    context: {
      sourceIp: string;
      destinationUrl?: string;
      destinationIp?: string;
      destinationPort?: number;
    }
  ): Array<{ type: SensitiveDataType; match: string; weight: number }> {
    const detections: Array<{ type: SensitiveDataType; match: string; weight: number }> = [];
    
    for (const pattern of this.dlpPatterns) {
      const matches = content.matchAll(pattern.pattern);
      
      for (const match of matches) {
        detections.push({
          type: pattern.type,
          match: match[0],
          weight: pattern.weight
        });
      }
    }
    
    return detections;
  }

  /**
   * Замаскировать данные для логирования
   */
  private maskData(data: string): string {
    if (data.length <= 4) {
      return '*'.repeat(data.length);
    }
    
    return '*'.repeat(data.length - 4) + data.slice(-4);
  }

  /**
   * Вычислить серьёзность DLP события
   */
  private calculateDlpSeverity(
    detections: Array<{ type: SensitiveDataType; weight: number }>
  ): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
    const totalWeight = detections.reduce((sum, d) => sum + d.weight, 0);
    
    const hasCritical = detections.some(d => 
      d.type === SensitiveDataType.ENCRYPTION_KEYS ||
      d.type === SensitiveDataType.CREDENTIALS
    );
    
    if (hasCritical || totalWeight >= 20) {
      return 'CRITICAL';
    }
    
    if (totalWeight >= 15) {
      return 'HIGH';
    }
    
    if (totalWeight >= 8) {
      return 'MEDIUM';
    }
    
    return 'LOW';
  }

  /**
   * Получить DLP события
   */
  public getDlpEvents(limit: number = 100): DlpEvent[] {
    return this.dlpEvents.slice(-limit);
  }

  /**
   * Получить все правила
   */
  public getAllRules(): EgressFilterRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats & {
    /** Правила */
    ruleCount: number;
    /** DLP паттернов */
    dlpPatternCount: number;
  } {
    return {
      ...this.stats,
      ruleCount: this.rules.size,
      dlpPatternCount: this.dlpPatterns.length
    };
  }

  /**
   * Логирование
   */
  private log(component: string, message: string, data?: unknown): void {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'DLP_EVENT',
      timestamp: new Date(),
      subject: {
        id: 'system',
        type: SubjectType.SYSTEM,
        name: component
      },
      details: { message, ...data },
      severity: 'INFO',
      correlationId: uuidv4()
    };
    
    this.emit('log', event);

    if (this.config.enableVerboseLogging) {
      logger.debug(`[EF] ${message}`, { timestamp: new Date().toISOString(), ...data });
    }
  }
}

export default EgressFilter;
