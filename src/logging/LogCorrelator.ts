/**
 * ============================================================================
 * LOG CORRELATOR - КОРРЕЛЯЦИЯ СОБЫТИЙ
 * ============================================================================
 * Модуль для корреляции логов из различных источников, обнаружения
 * связанных событий, reconstruction attack chains и создания
 * контекстных security incident.
 * 
 * Особенности:
 * - Корреляция по correlation ID
 * - Сессионная корреляция
 * - Временная корреляция (time window)
 * - Pattern-based корреляция
 * - Attack chain reconstruction
 * - Distributed tracing поддержка
 * - Graph-based корреляция
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  LogEntry,
  LogContext,
  LogSource,
  LogLevel,
  ProcessingError,
  AttackDetection,
  OWASPAttackCategory,
  AttackSeverity,
  IOC
} from '../types/logging.types';

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Получение данных threat intel из метаданных лога
 */
function getThreatIntel(metadata?: Record<string, unknown>): {
  isTor?: boolean;
  isVpn?: boolean;
  isProxy?: boolean;
} {
  if (!metadata || typeof metadata.threatIntel !== 'object' || metadata.threatIntel === null) {
    return {};
  }
  return metadata.threatIntel as Record<string, unknown> as {
    isTor?: boolean;
    isVpn?: boolean;
    isProxy?: boolean;
  };
}

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/**
 * Паттерны атак для корреляции
 */
const ATTACK_PATTERNS: Record<string, AttackPattern> = {
  // SQL Injection attack chain
  sql_injection_chain: {
    name: 'SQL Injection Attack Chain',
    category: OWASPAttackCategory.INJECTION,
    severity: AttackSeverity.HIGH,
    stages: [
      { pattern: /union.*select/i, name: 'UNION SELECT attempt' },
      { pattern: /or\s+1\s*=\s*1/i, name: 'Boolean-based injection' },
      { pattern: /;\s*drop\s+table/i, name: 'Destructive injection' },
      { pattern: /sleep\s*\(/i, name: 'Time-based injection' }
    ],
    timeWindowSeconds: 300,
    minStages: 2
  },
  
  // XSS attack chain
  xss_chain: {
    name: 'Cross-Site Scripting Attack Chain',
    category: OWASPAttackCategory.CROSS_SITE_SCRIPTING,
    severity: AttackSeverity.MEDIUM,
    stages: [
      { pattern: /<script/i, name: 'Script tag injection' },
      { pattern: /javascript:/i, name: 'JavaScript protocol' },
      { pattern: /on\w+\s*=/i, name: 'Event handler injection' },
      { pattern: /<iframe/i, name: 'Iframe injection' }
    ],
    timeWindowSeconds: 300,
    minStages: 1
  },
  
  // Brute force attack chain
  brute_force_chain: {
    name: 'Brute Force Attack Chain',
    category: OWASPAttackCategory.BROKEN_AUTH,
    severity: AttackSeverity.HIGH,
    stages: [
      { pattern: /login.*fail/i, name: 'Login failure' },
      { pattern: /authentication.*fail/i, name: 'Auth failure' },
      { pattern: /invalid.*password/i, name: 'Invalid password' },
      { pattern: /account.*lock/i, name: 'Account lockout' }
    ],
    timeWindowSeconds: 600,
    minStages: 5
  },
  
  // Path traversal attack chain
  path_traversal_chain: {
    name: 'Path Traversal Attack Chain',
    category: OWASPAttackCategory.BROKEN_ACCESS_CONTROL,
    severity: AttackSeverity.HIGH,
    stages: [
      { pattern: /\.\.\//i, name: 'Directory traversal' },
      { pattern: /etc\/passwd/i, name: 'Passwd file access' },
      { pattern: /windows\/system32/i, name: 'System32 access' },
      { pattern: /boot\.ini/i, name: 'Boot.ini access' }
    ],
    timeWindowSeconds: 300,
    minStages: 1
  },
  
  // Reconnaissance attack chain
  recon_chain: {
    name: 'Reconnaissance Attack Chain',
    category: OWASPAttackCategory.SECURITY_MISCONFIGURATION,
    severity: AttackSeverity.MEDIUM,
    stages: [
      { pattern: /robots\.txt/i, name: 'Robots.txt access' },
      { pattern: /\.git/i, name: 'Git directory access' },
      { pattern: /\.env/i, name: 'Env file access' },
      { pattern: /wp-admin/i, name: 'WordPress admin probe' },
      { pattern: /phpmyadmin/i, name: 'phpMyAdmin probe' },
      { pattern: /admin/i, name: 'Admin path probe' }
    ],
    timeWindowSeconds: 600,
    minStages: 3
  }
};

/**
 * Пороги для корреляции
 */
const CORRELATION_THRESHOLDS = {
  // Минимальное количество событий для корреляции
  minEventsForCorrelation: 2,
  // Максимальное время между событиями (секунды)
  maxTimeWindowSeconds: 3600,
  // Минимальный score для correlation
  minCorrelationScore: 0.5,
  // Максимальный размер correlation группы
  maxGroupSize: 1000
};

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Паттерн атаки
 */
interface AttackPattern {
  name: string;
  category: OWASPAttackCategory;
  severity: AttackSeverity;
  stages: Array<{
    pattern: RegExp;
    name: string;
  }>;
  timeWindowSeconds: number;
  minStages: number;
}

/**
 * Correlation группа
 */
interface CorrelationGroup {
  /** Уникальный ID группы */
  id: string;
  /** Название группы */
  name: string;
  /** Тип корреляции */
  type: CorrelationType;
  /** Связанные логи */
  logs: LogEntry[];
  /** Ключевые атрибуты */
  keyAttributes: CorrelationKeyAttributes;
  /** Время начала */
  startTime: string;
  /** Время окончания */
  endTime: string;
  /** Score корреляции */
  correlationScore: number;
  /** Статус группы */
  status: 'active' | 'completed' | 'expired';
  /** Детектированные атаки */
  detectedAttacks: AttackDetection[];
  /** Добавление детектированной атаки */
  addAttack(attack: AttackDetection): void;
  /** Создана */
  createdAt: string;
  /** Обновлена */
  updatedAt: string;
}

/**
 * Тип корреляции
 */
type CorrelationType =
  | 'correlation_id'      // По correlation ID
  | 'session'             // По session ID
  | 'user'                // По user ID
  | 'ip_address'          // По IP адресу
  | 'time_window'         // По временному окну
  | 'pattern'             // По паттерну атаки
  | 'request_chain'       // По цепочке запросов
  | 'custom';             // Кастомная корреляция

/**
 * Ключевые атрибуты корреляции
 */
interface CorrelationKeyAttributes {
  /** Correlation ID */
  correlationId?: string;
  /** Session ID */
  sessionId?: string;
  /** User ID */
  userId?: string;
  /** IP адрес */
  clientIp?: string;
  /** Request ID */
  requestId?: string;
  /** Trace ID */
  traceId?: string;
  /** Span ID */
  spanId?: string;
  /** Кастомные ключи */
  customKeys?: Record<string, string>;
}

/**
 * Конфигурация LogCorrelator
 */
interface LogCorrelatorConfig {
  /** Включить correlation по correlation ID */
  enableCorrelationId: boolean;
  /** Включить сессионную корреляцию */
  enableSessionCorrelation: boolean;
  /** Включить IP корреляцию */
  enableIpCorrelation: boolean;
  /** Включить pattern-based корреляцию */
  enablePatternCorrelation: boolean;
  /** Включить time window корреляцию */
  enableTimeWindowCorrelation: boolean;
  /** Размер time window (секунды) */
  timeWindowSeconds: number;
  /** Максимальный размер группы */
  maxGroupSize: number;
  /** Максимальное время жизни группы (секунды) */
  maxGroupLifetimeSeconds: number;
  /** Включить attack chain detection */
  enableAttackChainDetection: boolean;
  /** Кастомные правила корреляции */
  customCorrelationRules?: CorrelationRule[];
}

/**
 * Правило корреляции
 */
interface CorrelationRule {
  /** ID правила */
  id: string;
  /** Название */
  name: string;
  /** Условия для группировки */
  groupBy: string[];
  /** Фильтры для применения правила */
  filters: CorrelationFilter[];
  /** Time window (секунды) */
  timeWindowSeconds: number;
  /** Минимальное количество событий */
  minEvents: number;
  /** Действия при корреляции */
  actions: CorrelationAction[];
}

/**
 * Фильтр корреляции
 */
interface CorrelationFilter {
  field: string;
  operator: 'equals' | 'contains' | 'regex' | 'exists';
  value?: string;
  pattern?: RegExp;
}

/**
 * Действие корреляции
 */
interface CorrelationAction {
  type: 'alert' | 'tag' | 'enrich' | 'escalate';
  params?: Record<string, unknown>;
}

/**
 * Результат корреляции
 */
interface CorrelationResult {
  /** Лог после корреляции */
  log: LogEntry;
  /** Найденные correlation группы */
  groups: CorrelationGroup[];
  /** Детектированные атаки */
  detectedAttacks: AttackDetection[];
  /** Примененные правила */
  appliedRules: string[];
  /** Score корреляции */
  correlationScore: number;
  /** Ошибки */
  errors: ProcessingError[];
}

/**
 * Статистика корреляции
 */
interface CorrelatorStatistics {
  /** Всего обработано логов */
  totalProcessed: number;
  /** Создано correlation групп */
  groupsCreated: number;
  /** Завершено групп */
  groupsCompleted: number;
  /** Истекло групп */
  groupsExpired: number;
  /** Детектировано атак */
  attacksDetected: number;
  /** Средний размер группы */
  avgGroupSize: number;
  /** Среднее время корреляции (мс) */
  avgCorrelationTime: number;
  /** P99 время корреляции (мс) */
  p99CorrelationTime: number;
  /** Статистика по типам корреляции */
  byCorrelationType: Record<CorrelationType, number>;
  /** Статистика по атакам */
  byAttackType: Record<OWASPAttackCategory, number>;
  /** Активные группы */
  activeGroups: number;
}

// ============================================================================
// КЛАСС CORRELATION GROUP
// ============================================================================

/**
 * Класс correlation группы
 */
class CorrelationGroupImpl implements CorrelationGroup {
  id: string;
  name: string;
  type: CorrelationType;
  logs: LogEntry[];
  keyAttributes: CorrelationKeyAttributes;
  startTime: string;
  endTime: string;
  correlationScore: number;
  status: 'active' | 'completed' | 'expired';
  detectedAttacks: AttackDetection[];
  createdAt: string;
  updatedAt: string;
  private maxLifetime: number;
  private maxGroupSize: number;
  
  constructor(
    type: CorrelationType,
    keyAttributes: CorrelationKeyAttributes,
    maxLifetimeSeconds: number,
    maxGroupSize: number
  ) {
    this.id = crypto.randomUUID();
    this.name = this.generateName(type, keyAttributes);
    this.type = type;
    this.logs = [];
    this.keyAttributes = keyAttributes;
    this.startTime = new Date().toISOString();
    this.endTime = this.startTime;
    this.correlationScore = 1.0;
    this.status = 'active';
    this.detectedAttacks = [];
    this.createdAt = new Date().toISOString();
    this.updatedAt = this.createdAt;
    this.maxLifetime = maxLifetimeSeconds * 1000;
    this.maxGroupSize = maxGroupSize;
  }
  
  /**
   * Добавление лога в группу
   */
  addLog(log: LogEntry): boolean {
    if (this.status !== 'active') {
      return false;
    }
    
    if (this.logs.length >= this.maxGroupSize) {
      this.status = 'completed';
      return false;
    }
    
    this.logs.push(log);
    this.endTime = log.timestamp;
    this.updatedAt = new Date().toISOString();
    
    // Пересчет correlation score
    this.correlationScore = this.calculateCorrelationScore();
    
    return true;
  }
  
  /**
   * Проверка истечения времени жизни
   */
  isExpired(): boolean {
    const age = Date.now() - new Date(this.createdAt).getTime();
    return age > this.maxLifetime;
  }
  
  /**
   * Завершение группы
   */
  complete(): void {
    this.status = 'completed';
    this.updatedAt = new Date().toISOString();
  }
  
  /**
   * Истечение группы
   */
  expire(): void {
    this.status = 'expired';
    this.updatedAt = new Date().toISOString();
  }
  
  /**
   * Добавление детектированной атаки
   */
  addAttack(attack: AttackDetection): void {
    this.detectedAttacks.push(attack);
  }
  
  /**
   * Получение timeline событий
   */
  getTimeline(): LogEntry[] {
    return [...this.logs].sort((a, b) => 
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
  }
  
  /**
   * Получение уникальных IP адресов
   */
  getUniqueIps(): string[] {
    const ips = new Set<string>();
    for (const log of this.logs) {
      if (log.context.clientIp) {
        ips.add(log.context.clientIp);
      }
    }
    return Array.from(ips);
  }
  
  /**
   * Получение уникальных пользователей
   */
  getUniqueUsers(): string[] {
    const users = new Set<string>();
    for (const log of this.logs) {
      if (log.context.userId) {
        users.add(log.context.userId);
      }
    }
    return Array.from(users);
  }
  
  /**
   * Получение длительности группы (мс)
   */
  getDuration(): number {
    return new Date(this.endTime).getTime() - new Date(this.startTime).getTime();
  }
  
  /**
   * Генерация названия группы
   */
  private generateName(type: CorrelationType, attrs: CorrelationKeyAttributes): string {
    const parts: string[] = [];
    
    switch (type) {
      case 'correlation_id':
        parts.push(`corr:${attrs.correlationId?.substring(0, 8)}`);
        break;
      case 'session':
        parts.push(`sess:${attrs.sessionId?.substring(0, 8)}`);
        break;
      case 'user':
        parts.push(`user:${attrs.userId}`);
        break;
      case 'ip_address':
        parts.push(`ip:${attrs.clientIp}`);
        break;
      case 'time_window':
        parts.push(`time:${new Date(this.startTime).toISOString().substring(0, 16)}`);
        break;
      case 'pattern':
        parts.push('pattern:attack');
        break;
      default:
        parts.push('custom');
    }
    
    return parts.join('_');
  }
  
  /**
   * Расчет correlation score
   */
  private calculateCorrelationScore(): number {
    if (this.logs.length < 2) {
      return 1.0;
    }
    
    let score = 1.0;
    
    // Штраф за большой разброс времени
    const duration = this.getDuration();
    const durationMinutes = duration / 60000;
    if (durationMinutes > 60) {
      score -= 0.1;
    }
    
    // Штраф за много разных IP
    const uniqueIps = this.getUniqueIps().length;
    if (uniqueIps > 5) {
      score -= 0.1;
    }
    
    // Штраф за много разных пользователей
    const uniqueUsers = this.getUniqueUsers().length;
    if (uniqueUsers > 3) {
      score -= 0.1;
    }
    
    // Бонус за последовательность событий
    const levels = this.logs.map(l => l.level);
    const hasEscalation = levels.some((l, i) => i > 0 && l < levels[i - 1]);
    if (hasEscalation) {
      score += 0.1;
    }
    
    return Math.max(0, Math.min(1, score));
  }
}

// ============================================================================
// CORRELATION INDEX
// ============================================================================

/**
 * Индекс для быстрого поиска correlation групп
 */
class CorrelationIndex {
  private byCorrelationId: Map<string, string>;
  private bySessionId: Map<string, string>;
  private byUserId: Map<string, Set<string>>;
  private byClientIp: Map<string, Set<string>>;
  private byRequestId: Map<string, string>;
  private groups: Map<string, CorrelationGroupImpl>;
  
  constructor() {
    this.byCorrelationId = new Map();
    this.bySessionId = new Map();
    this.byUserId = new Map();
    this.byClientIp = new Map();
    this.byRequestId = new Map();
    this.groups = new Map();
  }
  
  /**
   * Добавление группы в индекс
   */
  add(group: CorrelationGroupImpl): void {
    this.groups.set(group.id, group);
    
    if (group.keyAttributes.correlationId) {
      this.byCorrelationId.set(group.keyAttributes.correlationId, group.id);
    }
    
    if (group.keyAttributes.sessionId) {
      this.bySessionId.set(group.keyAttributes.sessionId, group.id);
    }
    
    if (group.keyAttributes.userId) {
      let userGroups = this.byUserId.get(group.keyAttributes.userId);
      if (!userGroups) {
        userGroups = new Set();
        this.byUserId.set(group.keyAttributes.userId, userGroups);
      }
      userGroups.add(group.id);
    }
    
    if (group.keyAttributes.clientIp) {
      let ipGroups = this.byClientIp.get(group.keyAttributes.clientIp);
      if (!ipGroups) {
        ipGroups = new Set();
        this.byClientIp.set(group.keyAttributes.clientIp, ipGroups);
      }
      ipGroups.add(group.id);
    }
    
    if (group.keyAttributes.requestId) {
      this.byRequestId.set(group.keyAttributes.requestId, group.id);
    }
  }
  
  /**
   * Удаление группы из индекса
   */
  remove(groupId: string): void {
    const group = this.groups.get(groupId);
    if (!group) return;
    
    this.groups.delete(groupId);
    
    if (group.keyAttributes.correlationId) {
      this.byCorrelationId.delete(group.keyAttributes.correlationId);
    }
    
    if (group.keyAttributes.sessionId) {
      this.bySessionId.delete(group.keyAttributes.sessionId);
    }
    
    if (group.keyAttributes.userId) {
      const userGroups = this.byUserId.get(group.keyAttributes.userId);
      if (userGroups) {
        userGroups.delete(groupId);
      }
    }
    
    if (group.keyAttributes.clientIp) {
      const ipGroups = this.byClientIp.get(group.keyAttributes.clientIp);
      if (ipGroups) {
        ipGroups.delete(groupId);
      }
    }
    
    if (group.keyAttributes.requestId) {
      this.byRequestId.delete(group.keyAttributes.requestId);
    }
  }
  
  /**
   * Поиск группы по correlation ID
   */
  findByCorrelationId(correlationId: string): CorrelationGroupImpl | null {
    const groupId = this.byCorrelationId.get(correlationId);
    return groupId ? this.groups.get(groupId) || null : null;
  }
  
  /**
   * Поиск группы по session ID
   */
  findBySessionId(sessionId: string): CorrelationGroupImpl | null {
    const groupId = this.bySessionId.get(sessionId);
    return groupId ? this.groups.get(groupId) || null : null;
  }
  
  /**
   * Поиск групп по user ID
   */
  findByUserId(userId: string): CorrelationGroupImpl[] {
    const groupIds = this.byUserId.get(userId);
    if (!groupIds) return [];
    
    return Array.from(groupIds)
      .map(id => this.groups.get(id))
      .filter((g): g is CorrelationGroupImpl => g !== undefined);
  }
  
  /**
   * Поиск групп по IP
   */
  findByClientIp(clientIp: string): CorrelationGroupImpl[] {
    const groupIds = this.byClientIp.get(clientIp);
    if (!groupIds) return [];
    
    return Array.from(groupIds)
      .map(id => this.groups.get(id))
      .filter((g): g is CorrelationGroupImpl => g !== undefined);
  }
  
  /**
   * Поиск группы по request ID
   */
  findByRequestId(requestId: string): CorrelationGroupImpl | null {
    const groupId = this.byRequestId.get(requestId);
    return groupId ? this.groups.get(groupId) || null : null;
  }
  
  /**
   * Получение группы по ID
   */
  get(groupId: string): CorrelationGroupImpl | null {
    return this.groups.get(groupId) || null;
  }
  
  /**
   * Получение всех активных групп
   */
  getAllActive(): CorrelationGroupImpl[] {
    return Array.from(this.groups.values())
      .filter(g => g.status === 'active');
  }
  
  /**
   * Размер индекса
   */
  size(): number {
    return this.groups.size;
  }
  
  /**
   * Очистка истекших групп
   */
  cleanupExpired(): number {
    let removed = 0;
    
    for (const group of this.groups.values()) {
      if (group.isExpired()) {
        group.expire();
        this.remove(group.id);
        removed++;
      }
    }
    
    return removed;
  }
}

// ============================================================================
// ATTACK CHAIN DETECTOR
// ============================================================================

/**
 * Детектор цепочек атак
 */
class AttackChainDetector {
  private patterns: Record<string, AttackPattern>;
  
  constructor() {
    this.patterns = ATTACK_PATTERNS;
  }
  
  /**
   * Анализ логов на наличие attack chain
   */
  detect(logs: LogEntry[]): AttackDetection[] {
    const detections: AttackDetection[] = [];
    
    for (const [patternName, pattern] of Object.entries(this.patterns)) {
      const detection = this.analyzePattern(logs, pattern, patternName);
      if (detection) {
        detections.push(detection);
      }
    }
    
    return detections;
  }
  
  /**
   * Анализ паттерна
   */
  private analyzePattern(
    logs: LogEntry[],
    pattern: AttackPattern,
    patternName: string
  ): AttackDetection | null {
    const matchedStages: Array<{
      stage: typeof pattern.stages[0];
      log: LogEntry;
      timestamp: number;
    }> = [];
    
    // Сортировка логов по времени
    const sortedLogs = [...logs].sort((a, b) => 
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
    
    // Поиск совпадений по стадиям
    for (const log of sortedLogs) {
      const searchText = `${log.message} ${JSON.stringify(log.fields || {})}`;
      
      for (const stage of pattern.stages) {
        if (stage.pattern.test(searchText)) {
          matchedStages.push({
            stage,
            log,
            timestamp: new Date(log.timestamp).getTime()
          });
          break;
        }
      }
    }
    
    // Проверка минимального количества стадий
    const uniqueStages = new Set(matchedStages.map(s => s.stage.name));
    if (uniqueStages.size < pattern.minStages) {
      return null;
    }
    
    // Проверка временного окна
    if (matchedStages.length > 1) {
      const firstTime = matchedStages[0].timestamp;
      const lastTime = matchedStages[matchedStages.length - 1].timestamp;
      const durationSeconds = (lastTime - firstTime) / 1000;
      
      if (durationSeconds > pattern.timeWindowSeconds) {
        return null;
      }
    }
    
    // Создание detection
    const relatedLogs = matchedStages.map(s => s.log);
    const sourceIp = relatedLogs[0]?.context.clientIp || 'unknown';
    
    return {
      id: crypto.randomUUID(),
      attackType: pattern.category,
      attackSubtype: patternName,
      severity: pattern.severity,
      confidence: Math.min(1, uniqueStages.size / pattern.stages.length),
      relatedLogs,
      source: {
        ip: sourceIp,
        isTor: getThreatIntel(relatedLogs[0]?.context.metadata).isTor || false,
        isVpn: getThreatIntel(relatedLogs[0]?.context.metadata).isVpn || false,
        isProxy: getThreatIntel(relatedLogs[0]?.context.metadata).isProxy || false
      },
      target: {
        endpoint: this.extractEndpoint(relatedLogs),
        service: this.extractService(relatedLogs)
      },
      attackVector: this.buildAttackVector(matchedStages),
      indicatorsOfCompromise: this.extractIOCs(relatedLogs),
      remediationSteps: this.getRemediationSteps(pattern.category),
      references: this.getReferences(pattern.category),
      detectedAt: new Date().toISOString(),
      investigationStatus: 'new'
    };
  }
  
  /**
   * Извлечение endpoint
   */
  private extractEndpoint(logs: LogEntry[]): string | undefined {
    for (const log of logs) {
      if (log.fields?.url) {
        return String(log.fields.url);
      }
      if (log.fields?.endpoint) {
        return String(log.fields.endpoint);
      }
    }
    return undefined;
  }
  
  /**
   * Извлечение сервиса
   */
  private extractService(logs: LogEntry[]): string | undefined {
    return logs[0]?.component;
  }
  
  /**
   * Построение attack vector
   */
  private buildAttackVector(
    stages: Array<{ stage: typeof ATTACK_PATTERNS.sql_injection_chain.stages[0]; log: LogEntry }>
  ): string {
    return stages.map(s => s.stage.name).join(' -> ');
  }
  
  /**
   * Извлечение IOC
   */
  private extractIOCs(logs: LogEntry[]): IOC[] {
    const iocs: IOC[] = [];
    const now = new Date().toISOString();
    
    for (const log of logs) {
      if (log.context.clientIp) {
        iocs.push({
          type: 'ip',
          value: log.context.clientIp,
          confidence: 0.8,
          firstSeen: log.timestamp,
          lastSeen: log.timestamp,
          tags: ['attack_source']
        });
      }
    }
    
    return iocs;
  }
  
  /**
   * Получение шагов remediation
   */
  private getRemediationSteps(category: OWASPAttackCategory): string[] {
    const remediationMap: Record<OWASPAttackCategory, string[]> = {
      [OWASPAttackCategory.INJECTION]: [
        'Использовать параметризованные запросы',
        'Валидировать все входные данные',
        'Применить WAF правила',
        'Заблокировать источник атаки'
      ],
      [OWASPAttackCategory.BROKEN_AUTH]: [
        'Включить MFA',
        'Реализовать rate limiting',
        'Заблокировать учетную запись',
        'Аудит всех действий пользователя'
      ],
      [OWASPAttackCategory.SENSITIVE_DATA_EXPOSURE]: [
        'Зашифровать чувствительные данные',
        'Ограничить доступ к данным',
        'Аудит доступа к данным',
        'Удалить избыточные данные'
      ],
      [OWASPAttackCategory.XML_EXTERNAL_ENTITIES]: [
        'Отключить XML external entities',
        'Использовать JSON вместо XML',
        'Валидировать XML схемы'
      ],
      [OWASPAttackCategory.BROKEN_ACCESS_CONTROL]: [
        'Реализовать принцип наименьших привилегий',
        'Валидировать доступ на сервере',
        'Аудит всех операций доступа'
      ],
      [OWASPAttackCategory.SECURITY_MISCONFIGURATION]: [
        'Провести security audit конфигурации',
        'Удалить дефолтные учетные записи',
        'Отключить ненужные сервисы'
      ],
      [OWASPAttackCategory.CROSS_SITE_SCRIPTING]: [
        'Экранировать вывод данных',
        'Использовать Content Security Policy',
        'Валидировать входные данные',
        'Использовать HTTPOnly cookies'
      ],
      [OWASPAttackCategory.INSECURE_DESERIALIZATION]: [
        'Избегать десериализации ненадежных данных',
        'Использовать цифровые подписи',
        'Изолировать среду десериализации'
      ],
      [OWASPAttackCategory.VULNERABLE_COMPONENTS]: [
        'Обновить уязвимые компоненты',
        'Использовать SCA инструменты',
        'Удалить неиспользуемые зависимости'
      ],
      [OWASPAttackCategory.INSUFFICIENT_LOGGING]: [
        'Включить детальное логирование',
        'Настроить alerting',
        'Реализовать мониторинг'
      ]
    };
    
    return remediationMap[category] || ['Провести расследование инцидента'];
  }
  
  /**
   * Получение ссылок на документацию
   */
  private getReferences(category: OWASPAttackCategory): string[] {
    const referencesMap: Partial<Record<OWASPAttackCategory, string[]>> = {
      [OWASPAttackCategory.INJECTION]: [
        'https://owasp.org/www-community/Injection_Flaws',
        'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.BROKEN_AUTH]: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.CROSS_SITE_SCRIPTING]: [
        'https://owasp.org/www-community/attacks/xss/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.BROKEN_ACCESS_CONTROL]: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/'
      ],
      [OWASPAttackCategory.SENSITIVE_DATA_EXPOSURE]: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_Testing/'
      ],
      [OWASPAttackCategory.XML_EXTERNAL_ENTITIES]: [
        'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'
      ],
      [OWASPAttackCategory.SECURITY_MISCONFIGURATION]: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_Testing/'
      ],
      [OWASPAttackCategory.INSECURE_DESERIALIZATION]: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.VULNERABLE_COMPONENTS]: [
        'https://owasp.org/www-community/Component_Analysis'
      ],
      [OWASPAttackCategory.INSUFFICIENT_LOGGING]: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Authentication/'
      ]
    };

    return referencesMap[category] || ['https://owasp.org/www-project-top-ten/'];
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС CORRELATOR
// ============================================================================

/**
 * Log Correlator - корреляция событий
 * 
 * Реализует:
 * - Корреляцию по correlation ID
 * - Сессионную корреляцию
 * - IP корреляцию
 * - Pattern-based корреляцию
 * - Attack chain detection
 * - Graph-based корреляцию
 */
export class LogCorrelator extends EventEmitter {
  private config: LogCorrelatorConfig;
  private index: CorrelationIndex;
  private attackDetector: AttackChainDetector;
  private statistics: CorrelatorStatistics;
  private correlationTimes: number[];
  private cleanupInterval: NodeJS.Timeout | null;
  
  constructor(config: Partial<LogCorrelatorConfig> = {}) {
    super();
    
    this.config = {
      enableCorrelationId: config.enableCorrelationId !== false,
      enableSessionCorrelation: config.enableSessionCorrelation !== false,
      enableIpCorrelation: config.enableIpCorrelation || false,
      enablePatternCorrelation: config.enablePatternCorrelation !== false,
      enableTimeWindowCorrelation: config.enableTimeWindowCorrelation !== false,
      timeWindowSeconds: config.timeWindowSeconds || 3600,
      maxGroupSize: config.maxGroupSize || 1000,
      maxGroupLifetimeSeconds: config.maxGroupLifetimeSeconds || 7200,
      enableAttackChainDetection: config.enableAttackChainDetection !== false,
      customCorrelationRules: config.customCorrelationRules || []
    };
    
    this.index = new CorrelationIndex();
    this.attackDetector = new AttackChainDetector();
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.correlationTimes = [];
    this.cleanupInterval = null;
    
    // Запуск периодической очистки
    this.startCleanup();
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): CorrelatorStatistics {
    return {
      totalProcessed: 0,
      groupsCreated: 0,
      groupsCompleted: 0,
      groupsExpired: 0,
      attacksDetected: 0,
      avgGroupSize: 0,
      avgCorrelationTime: 0,
      p99CorrelationTime: 0,
      byCorrelationType: {
        correlation_id: 0,
        session: 0,
        user: 0,
        ip_address: 0,
        time_window: 0,
        pattern: 0,
        request_chain: 0,
        custom: 0
      },
      byAttackType: {
        injection: 0,
        broken_authentication: 0,
        sensitive_data_exposure: 0,
        xml_external_entities: 0,
        broken_access_control: 0,
        security_misconfiguration: 0,
        cross_site_scripting: 0,
        insecure_deserialization: 0,
        vulnerable_components: 0,
        insufficient_logging: 0
      },
      activeGroups: 0
    };
  }
  
  /**
   * Корреляция лога
   */
  correlate(log: LogEntry): CorrelationResult {
    const startTime = Date.now();
    this.statistics.totalProcessed++;
    
    const groups: CorrelationGroup[] = [];
    const detectedAttacks: AttackDetection[] = [];
    const appliedRules: string[] = [];
    const errors: ProcessingError[] = [];
    
    try {
      // Корреляция по correlation ID
      if (this.config.enableCorrelationId && log.context.correlationId) {
        const group = this.findOrCreateGroup(
          'correlation_id',
          { correlationId: log.context.correlationId }
        );
        if (group) {
          group.addLog(log);
          groups.push(group);
          appliedRules.push('correlation_id');
          this.statistics.byCorrelationType.correlation_id++;
        }
      }
      
      // Сессионная корреляция
      if (this.config.enableSessionCorrelation && log.context.sessionId) {
        const group = this.findOrCreateGroup(
          'session',
          { sessionId: log.context.sessionId }
        );
        if (group) {
          group.addLog(log);
          groups.push(group);
          appliedRules.push('session');
          this.statistics.byCorrelationType.session++;
        }
      }
      
      // IP корреляция
      if (this.config.enableIpCorrelation && log.context.clientIp) {
        const existingGroups = this.index.findByClientIp(log.context.clientIp);
        
        for (const group of existingGroups) {
          if (group.status === 'active' && !group.isExpired()) {
            group.addLog(log);
            groups.push(group);
          }
        }
        
        // Если нет активной группы, создаем новую
        if (existingGroups.length === 0 || existingGroups.every(g => g.status !== 'active')) {
          const group = this.findOrCreateGroup(
            'ip_address',
            { clientIp: log.context.clientIp }
          );
          if (group) {
            group.addLog(log);
            groups.push(group);
            appliedRules.push('ip_address');
            this.statistics.byCorrelationType.ip_address++;
          }
        }
      }
      
      // Pattern-based корреляция
      if (this.config.enablePatternCorrelation) {
        const patternGroups = this.analyzePattern(log);
        for (const group of patternGroups) {
          groups.push(group);
          appliedRules.push('pattern');
          this.statistics.byCorrelationType.pattern++;
        }
      }
      
      // Attack chain detection для групп
      for (const group of groups) {
        if (this.config.enableAttackChainDetection && group.logs.length >= 2) {
          const attacks = this.attackDetector.detect(group.logs);
          
          for (const attack of attacks) {
            group.addAttack(attack);
            detectedAttacks.push(attack);
            this.statistics.attacksDetected++;
            this.statistics.byAttackType[attack.attackType]++;
            
            this.emit('attack_detected', attack);
          }
        }
      }
      
      // Применение кастомных правил
      for (const rule of this.config.customCorrelationRules || []) {
        if (this.matchesRule(log, rule)) {
          appliedRules.push(rule.id);
          this.statistics.byCorrelationType.custom++;
        }
      }
      
      // Обновление статистики
      const correlationTime = Date.now() - startTime;
      this.updateCorrelationTimeStats(correlationTime);
      this.statistics.activeGroups = this.index.size();
      
      return {
        log,
        groups,
        detectedAttacks,
        appliedRules,
        correlationScore: groups.length > 0 
          ? groups.reduce((sum, g) => sum + g.correlationScore, 0) / groups.length 
          : 0,
        errors
      };
    } catch (error) {
      errors.push({
        stage: 'correlation',
        code: 'CORRELATION_ERROR',
        message: error instanceof Error ? error.message : String(error),
        recoverable: true
      });
      
      return {
        log,
        groups,
        detectedAttacks,
        appliedRules,
        correlationScore: 0,
        errors
      };
    }
  }
  
  /**
   * Пакетная корреляция
   */
  correlateBatch(logs: LogEntry[]): CorrelationResult[] {
    return logs.map(log => this.correlate(log));
  }
  
  /**
   * Поиск или создание группы
   */
  private findOrCreateGroup(
    type: CorrelationType,
    keyAttributes: CorrelationKeyAttributes
  ): CorrelationGroupImpl | null {
    // Поиск существующей группы
    let group: CorrelationGroupImpl | null = null;
    
    switch (type) {
      case 'correlation_id':
        if (keyAttributes.correlationId) {
          group = this.index.findByCorrelationId(keyAttributes.correlationId);
        }
        break;
      case 'session':
        if (keyAttributes.sessionId) {
          group = this.index.findBySessionId(keyAttributes.sessionId);
        }
        break;
      case 'user':
        if (keyAttributes.userId) {
          const userGroups = this.index.findByUserId(keyAttributes.userId);
          group = userGroups.find(g => g.status === 'active') || null;
        }
        break;
      case 'ip_address':
        if (keyAttributes.clientIp) {
          const ipGroups = this.index.findByClientIp(keyAttributes.clientIp);
          group = ipGroups.find(g => g.status === 'active') || null;
        }
        break;
    }
    
    // Создание новой группы если не найдено
    if (!group) {
      group = new CorrelationGroupImpl(
        type,
        keyAttributes,
        this.config.maxGroupLifetimeSeconds,
        this.config.maxGroupSize
      );
      
      this.index.add(group);
      this.statistics.groupsCreated++;
      
      this.emit('group_created', group);
    }
    
    return group;
  }
  
  /**
   * Анализ паттерна для单个 лога
   */
  private analyzePattern(log: LogEntry): CorrelationGroup[] {
    const groups: CorrelationGroup[] = [];
    const searchText = `${log.message} ${JSON.stringify(log.fields || {})}`;
    
    // Проверка на известные паттерны атак
    for (const [patternName, pattern] of Object.entries(ATTACK_PATTERNS)) {
      for (const stage of pattern.stages) {
        if (stage.pattern.test(searchText)) {
          // Создание группы для паттерна
          const group = new CorrelationGroupImpl(
            'pattern',
            { customKeys: { pattern: patternName, stage: stage.name } },
            pattern.timeWindowSeconds,
            this.config.maxGroupSize
          );
          
          group.addLog(log);
          groups.push(group);
          
          this.index.add(group);
          break;
        }
      }
    }
    
    return groups;
  }
  
  /**
   * Проверка соответствия правилу
   */
  private matchesRule(log: LogEntry, rule: CorrelationRule): boolean {
    for (const filter of rule.filters) {
      const value = this.getFieldValue(log, filter.field);
      
      switch (filter.operator) {
        case 'equals':
          if (value !== filter.value) return false;
          break;
        case 'contains':
          if (!String(value).includes(String(filter.value))) return false;
          break;
        case 'regex':
          if (!filter.pattern?.test(String(value))) return false;
          break;
        case 'exists':
          if (value === undefined || value === null) return false;
          break;
      }
    }
    
    return true;
  }
  
  /**
   * Получение значения поля из лога
   */
  private getFieldValue(log: LogEntry, field: string): unknown {
    const parts = field.split('.');
    let value: unknown = log;
    
    for (const part of parts) {
      if (value === null || value === undefined) {
        return undefined;
      }
      
      value = (value as Record<string, unknown>)[part];
    }
    
    return value;
  }
  
  /**
   * Обновление статистики времени корреляции
   */
  private updateCorrelationTimeStats(time: number): void {
    this.correlationTimes.push(time);
    
    if (this.correlationTimes.length > 1000) {
      this.correlationTimes.shift();
    }
    
    this.statistics.avgCorrelationTime = 
      this.correlationTimes.reduce((a, b) => a + b, 0) / this.correlationTimes.length;
    
    const sorted = [...this.correlationTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99CorrelationTime = sorted[p99Index] || 0;
  }
  
  /**
   * Запуск периодической очистки
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      const expired = this.index.cleanupExpired();
      this.statistics.groupsExpired += expired;
      
      if (expired > 0) {
        this.emit('groups_expired', { count: expired });
      }
    }, 60000); // Каждую минуту
  }
  
  /**
   * Получение группы по ID
   */
  getGroup(groupId: string): CorrelationGroup | null {
    return this.index.get(groupId);
  }
  
  /**
   * Получение всех активных групп
   */
  getActiveGroups(): CorrelationGroup[] {
    return this.index.getAllActive();
  }
  
  /**
   * Получение групп по user ID
   */
  getGroupsByUser(userId: string): CorrelationGroup[] {
    return this.index.findByUserId(userId);
  }
  
  /**
   * Получение групп по IP
   */
  getGroupsByIp(ip: string): CorrelationGroup[] {
    return this.index.findByClientIp(ip);
  }
  
  /**
   * Получение статистики
   */
  getStatistics(): CorrelatorStatistics {
    return { ...this.statistics };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
    this.correlationTimes = [];
  }
  
  /**
   * Закрытие коррелятора
   */
  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    
    // Завершение всех активных групп
    for (const group of this.index.getAllActive()) {
      group.complete();
    }
    
    this.emit('closed');
  }
  
  /**
   * Добавление кастомного правила корреляции
   */
  addCorrelationRule(rule: CorrelationRule): void {
    if (this.config.customCorrelationRules) {
      this.config.customCorrelationRules.push(rule);
    }
  }
  
  /**
   * Удаление кастомного правила
   */
  removeCorrelationRule(ruleId: string): boolean {
    if (this.config.customCorrelationRules) {
      const index = this.config.customCorrelationRules.findIndex(r => r.id === ruleId);
      if (index !== -1) {
        this.config.customCorrelationRules.splice(index, 1);
        return true;
      }
    }
    return false;
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default LogCorrelator;
