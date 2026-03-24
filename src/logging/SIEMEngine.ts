/**
 * ============================================================================
 * SIEM ENGINE - RULES ENGINE ДЛЯ SIEM
 * ============================================================================
 * Движок правил SIEM для детектирования угроз безопасности, корреляции
 * событий и автоматического реагирования на инциденты.
 * 
 * Особенности:
 * - Гибкий язык правил (DSL)
 * - Поддержка агрегаций и окон времени
 * - MITRE ATT&CK интеграция
 * - OWASP Top 10 правила
 * - Compliance правила (PCI DSS, GDPR, SOX)
 * - Динамическое обновление правил
 * - Статистика выполнения правил
 * - False positive tuning
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  LogEntry,
  LogSource,
  LogLevel,
  SIEMRule,
  RuleCondition,
  RuleAction,
  RuleAggregation,
  RuleExecutionResult,
  RuleOperator,
  LogicalOperator,
  RuleActionType,
  Alert,
  AlertSeverity,
  AttackDetection,
  OWASPAttackCategory,
  AttackSeverity,
  ComplianceStandard,
  ProcessingError,
  IOC
} from '../types/logging.types';

// ============================================================================
// ВСТРОЕННЫЕ ПРАВИЛА SIEM
// ============================================================================

/**
 * Библиотека встроенных правил SIEM
 */
const BUILTIN_RULES: SIEMRule[] = [
  // =========================================================================
  // OWASP TOP 10 RULES
  // =========================================================================
  
  {
    id: 'owasp-a01-sql-injection',
    name: 'SQL Injection Detection',
    description: 'Detects SQL injection attack patterns in requests',
    category: 'injection',
    version: '1.0.0',
    enabled: true,
    priority: 1,
    conditions: [
      {
        field: 'message',
        operator: RuleOperator.REGEX,
        pattern: "(union\\s+select|or\\s+1\\s*=\\s*1|';\\s*drop\\s+table|sleep\\s*\\(|benchmark\\s*\\()",
        flags: 'i'
      }
    ],
    logicalOperator: LogicalOperator.OR,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 1,
        channels: ['security', 'soc'],
        template: 'SQL Injection attempt detected from {{context.clientIp}}'
      },
      {
        type: RuleActionType.BLOCK,
        params: { duration: 3600, scope: 'ip' }
      }
    ],
    tags: ['owasp', 'a01', 'injection', 'sql'],
    owaspCategories: [OWASPAttackCategory.INJECTION],
    mitreAttackIds: ['T1190', 'T1059'],
    complianceStandards: ['pci_dss', 'gdpr'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  {
    id: 'owasp-a01-xss-detection',
    name: 'Cross-Site Scripting Detection',
    description: 'Detects XSS attack patterns in requests',
    category: 'injection',
    version: '1.0.0',
    enabled: true,
    priority: 1,
    conditions: [
      {
        field: 'message',
        operator: RuleOperator.REGEX,
        pattern: '(<script|javascript:|on\\w+\\s*=|<iframe|<object|<embed)',
        flags: 'i'
      }
    ],
    logicalOperator: LogicalOperator.OR,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 1,
        channels: ['security', 'soc'],
        template: 'XSS attempt detected from {{context.clientIp}}'
      }
    ],
    tags: ['owasp', 'a03', 'xss', 'injection'],
    owaspCategories: [OWASPAttackCategory.CROSS_SITE_SCRIPTING],
    mitreAttackIds: ['T1189'],
    complianceStandards: ['pci_dss'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  {
    id: 'owasp-a02-brute-force',
    name: 'Brute Force Login Detection',
    description: 'Detects brute force login attempts',
    category: 'authentication',
    version: '1.0.0',
    enabled: true,
    priority: 1,
    conditions: [
      {
        field: 'message',
        operator: RuleOperator.CONTAINS,
        value: 'login'
      },
      {
        field: 'message',
        operator: RuleOperator.CONTAINS,
        value: 'fail'
      }
    ],
    logicalOperator: LogicalOperator.AND,
    aggregation: {
      type: 'count',
      windowSeconds: 300,
      threshold: 5,
      groupBy: ['context.clientIp', 'context.userId']
    },
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 1,
        channels: ['security', 'soc'],
        template: 'Brute force attack detected: {{aggregation.value}} failed logins from {{context.clientIp}}'
      },
      {
        type: RuleActionType.RATE_LIMIT,
        params: { requestsPerMinute: 1, duration: 600 }
      }
    ],
    tags: ['owasp', 'a02', 'brute-force', 'authentication'],
    owaspCategories: [OWASPAttackCategory.BROKEN_AUTH],
    mitreAttackIds: ['T1110'],
    complianceStandards: ['pci_dss', 'sox'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  {
    id: 'owasp-a05-path-traversal',
    name: 'Path Traversal Detection',
    description: 'Detects directory traversal attack attempts',
    category: 'access-control',
    version: '1.0.0',
    enabled: true,
    priority: 1,
    conditions: [
      {
        field: 'message',
        operator: RuleOperator.REGEX,
        pattern: '(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/|\\.\\.%2f)',
        flags: 'i'
      }
    ],
    logicalOperator: LogicalOperator.OR,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 1,
        channels: ['security'],
        template: 'Path traversal attempt detected from {{context.clientIp}}'
      }
    ],
    tags: ['owasp', 'a05', 'path-traversal', 'access-control'],
    owaspCategories: [OWASPAttackCategory.BROKEN_ACCESS_CONTROL],
    mitreAttackIds: ['T1083'],
    complianceStandards: ['pci_dss'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  // =========================================================================
  // AUTHENTICATION RULES
  // =========================================================================
  
  {
    id: 'auth-privilege-escalation',
    name: 'Privilege Escalation Detection',
    description: 'Detects potential privilege escalation attempts',
    category: 'authentication',
    version: '1.0.0',
    enabled: true,
    priority: 1,
    conditions: [
      {
        field: 'message',
        operator: RuleOperator.CONTAINS,
        value: 'sudo'
      },
      {
        field: 'context.userId',
        operator: RuleOperator.EXISTS
      }
    ],
    logicalOperator: LogicalOperator.AND,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 2,
        channels: ['security', 'audit'],
        template: 'Privilege escalation: User {{context.userId}} executed sudo command'
      }
    ],
    tags: ['authentication', 'privilege-escalation', 'linux'],
    mitreAttackIds: ['T1068', 'T1548'],
    complianceStandards: ['sox', 'pci_dss'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  {
    id: 'auth-after-hours-access',
    name: 'After Hours Access Detection',
    description: 'Detects access outside of business hours',
    category: 'authentication',
    version: '1.0.0',
    enabled: true,
    priority: 3,
    conditions: [
      {
        field: 'source',
        operator: RuleOperator.EQUALS,
        value: LogSource.AUTH
      },
      {
        field: 'message',
        operator: RuleOperator.CONTAINS,
        value: 'login_success'
      }
    ],
    logicalOperator: LogicalOperator.AND,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 4,
        channels: ['security'],
        template: 'After hours access: User {{context.userId}} logged in at {{timestamp}}'
      }
    ],
    tags: ['authentication', 'after-hours', 'anomaly'],
    mitreAttackIds: ['T1078'],
    complianceStandards: ['sox'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  // =========================================================================
  // NETWORK SECURITY RULES
  // =========================================================================
  
  {
    id: 'network-port-scan',
    name: 'Port Scan Detection',
    description: 'Detects port scanning activity',
    category: 'network',
    version: '1.0.0',
    enabled: true,
    priority: 2,
    conditions: [
      {
        field: 'source',
        operator: RuleOperator.EQUALS,
        value: LogSource.NETWORK
      },
      {
        field: 'fields.statusCode',
        operator: RuleOperator.EQUALS,
        value: 403
      }
    ],
    logicalOperator: LogicalOperator.AND,
    aggregation: {
      type: 'distinct_count',
      field: 'fields.destinationPort',
      windowSeconds: 60,
      threshold: 10,
      groupBy: ['context.clientIp']
    },
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 2,
        channels: ['security', 'soc'],
        template: 'Port scan detected from {{context.clientIp}}: {{aggregation.value}} ports scanned'
      },
      {
        type: RuleActionType.BLOCK,
        params: { duration: 7200, scope: 'ip' }
      }
    ],
    tags: ['network', 'port-scan', 'reconnaissance'],
    mitreAttackIds: ['T1046'],
    complianceStandards: ['pci_dss'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  {
    id: 'network-data-exfiltration',
    name: 'Data Exfiltration Detection',
    description: 'Detects potential data exfiltration',
    category: 'network',
    version: '1.0.0',
    enabled: true,
    priority: 1,
    conditions: [
      {
        field: 'source',
        operator: RuleOperator.EQUALS,
        value: LogSource.NETWORK
      },
      {
        field: 'fields.bytesTransferred',
        operator: RuleOperator.GREATER_THAN,
        value: 100000000
      }
    ],
    logicalOperator: LogicalOperator.AND,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 1,
        channels: ['security', 'soc', 'management'],
        template: 'Potential data exfiltration: {{fields.bytesTransferred}} bytes transferred to {{context.clientIp}}'
      }
    ],
    tags: ['network', 'exfiltration', 'dlp'],
    mitreAttackIds: ['T1041', 'T1048'],
    complianceStandards: ['gdpr', 'pci_dss', 'hipaa'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  // =========================================================================
  // COMPLIANCE RULES
  // =========================================================================
  
  {
    id: 'compliance-pci-card-data',
    name: 'PCI DSS - Card Data Access',
    description: 'Detects access to credit card data',
    category: 'compliance',
    version: '1.0.0',
    enabled: true,
    priority: 1,
    conditions: [
      {
        field: 'message',
        operator: RuleOperator.REGEX,
        pattern: '\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b'
      }
    ],
    logicalOperator: LogicalOperator.OR,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 1,
        channels: ['security', 'compliance', 'soc'],
        template: 'PCI DSS violation: Potential card data detected in logs'
      },
      {
        type: RuleActionType.LOG,
        params: { level: 'audit', category: 'pci_dss' }
      }
    ],
    tags: ['compliance', 'pci_dss', 'card-data', 'dlp'],
    complianceStandards: ['pci_dss'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  {
    id: 'compliance-gdpr-personal-data',
    name: 'GDPR - Personal Data Access',
    description: 'Detects access to personal data',
    category: 'compliance',
    version: '1.0.0',
    enabled: true,
    priority: 2,
    conditions: [
      {
        field: 'fields.resourceType',
        operator: RuleOperator.CONTAINS,
        value: 'user'
      },
      {
        field: 'fields.action',
        operator: RuleOperator.EQUALS,
        value: 'read'
      }
    ],
    logicalOperator: LogicalOperator.AND,
    actions: [
      {
        type: RuleActionType.LOG,
        params: { level: 'audit', category: 'gdpr' }
      }
    ],
    tags: ['compliance', 'gdpr', 'personal-data', 'audit'],
    complianceStandards: ['gdpr'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  {
    id: 'compliance-sox-config-change',
    name: 'SOX - Financial System Config Change',
    description: 'Detects configuration changes in financial systems',
    category: 'compliance',
    version: '1.0.0',
    enabled: true,
    priority: 2,
    conditions: [
      {
        field: 'source',
        operator: RuleOperator.EQUALS,
        value: LogSource.AUDIT
      },
      {
        field: 'fields.changeType',
        operator: RuleOperator.EQUALS,
        value: 'config'
      }
    ],
    logicalOperator: LogicalOperator.AND,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 3,
        channels: ['audit', 'compliance'],
        template: 'SOX audit: Configuration change by {{context.userId}}'
      }
    ],
    tags: ['compliance', 'sox', 'config-change', 'audit'],
    complianceStandards: ['sox'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  // =========================================================================
  // THREAT INTELLIGENCE RULES
  // =========================================================================
  
  {
    id: 'threat-tor-exit-node',
    name: 'Tor Exit Node Access',
    description: 'Detects access from known Tor exit nodes',
    category: 'threat-intel',
    version: '1.0.0',
    enabled: true,
    priority: 2,
    conditions: [
      {
        field: 'context.metadata.threatIntel.isTor',
        operator: RuleOperator.EQUALS,
        value: true
      }
    ],
    logicalOperator: LogicalOperator.OR,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 3,
        channels: ['security'],
        template: 'Access from Tor exit node: {{context.clientIp}}'
      }
    ],
    tags: ['threat-intel', 'tor', 'anonymizer'],
    mitreAttackIds: ['T1090'],
    complianceStandards: ['pci_dss'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  },
  
  {
    id: 'threat-malicious-ip',
    name: 'Malicious IP Detection',
    description: 'Detects access from known malicious IPs',
    category: 'threat-intel',
    version: '1.0.0',
    enabled: true,
    priority: 1,
    conditions: [
      {
        field: 'context.metadata.threatIntel.isMalicious',
        operator: RuleOperator.EQUALS,
        value: true
      }
    ],
    logicalOperator: LogicalOperator.OR,
    actions: [
      {
        type: RuleActionType.ALERT,
        priority: 1,
        channels: ['security', 'soc'],
        template: 'Access from malicious IP: {{context.clientIp}} (reputation: {{context.metadata.threatIntel.reputation}})'
      },
      {
        type: RuleActionType.BLOCK,
        params: { duration: 86400, scope: 'ip' }
      }
    ],
    tags: ['threat-intel', 'malicious-ip', 'reputation'],
    mitreAttackIds: ['T1071'],
    complianceStandards: ['pci_dss'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  }
];

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Конфигурация SIEM Engine
 */
interface SIEMEngineConfig {
  /** Включить встроенные правила */
  enableBuiltinRules: boolean;
  /** Максимальное количество правил */
  maxRules: number;
  /** Таймаут выполнения правила (мс) */
  ruleExecutionTimeout: number;
  /** Включить агрегацию */
  enableAggregation: boolean;
  /** Размер окна агрегации по умолчанию (секунды) */
  defaultAggregationWindow: number;
  /** Включить кэширование результатов */
  enableResultCache: boolean;
  /** Размер кэша */
  cacheSize: number;
  /** TTL кэша (секунды) */
  cacheTtlSeconds: number;
}

/**
 * Окно агрегации
 */
interface AggregationWindow {
  ruleId: string;
  groupKey: string;
  logs: LogEntry[];
  startTime: number;
  endTime: number;
  windowSeconds: number;
  threshold: number;
}

/**
 * Результат оценки условия
 */
interface ConditionEvaluationResult {
  matched: boolean;
  value?: unknown;
  error?: string;
}

/**
 * Статистика SIEM Engine
 */
interface SIEMEngineStatistics {
  /** Всего обработано логов */
  totalLogsProcessed: number;
  /** Всего выполнено правил */
  totalRulesExecuted: number;
  /** Сработавших правил */
  rulesTriggered: number;
  /** Сгенерировано алертов */
  alertsGenerated: number;
  /** Ошибки выполнения */
  executionErrors: number;
  /** Среднее время выполнения правила (мс) */
  avgRuleExecutionTime: number;
  /** P99 время выполнения (мс) */
  p99RuleExecutionTime: number;
  /** Статистика по правилам */
  byRule: Record<string, {
    executions: number;
    triggers: number;
    avgTime: number;
    falsePositives: number;
  }>;
  /** Статистика по категориям */
  byCategory: Record<string, number>;
  /** Активные окна агрегации */
  activeAggregationWindows: number;
}

// ============================================================================
// КЛАСС RULE EVALUATOR
// ============================================================================

/**
 * Оценщик правил
 */
class RuleEvaluator {
  /**
   * Оценка условия
   */
  evaluateCondition(condition: RuleCondition, log: LogEntry): ConditionEvaluationResult {
    try {
      const value = this.getFieldValue(log, condition.field);
      
      // Проверка EXISTS
      if (condition.operator === RuleOperator.EXISTS) {
        return {
          matched: value !== undefined && value !== null
        };
      }
      
      // Проверка NOT_EXISTS
      if (condition.operator === RuleOperator.NOT_EXISTS) {
        return {
          matched: value === undefined || value === null
        };
      }
      
      // Для остальных операторов нужно значение
      if (value === undefined || value === null) {
        return { matched: false };
      }
      
      switch (condition.operator) {
        case RuleOperator.EQUALS:
          return { matched: value === condition.value, value };
        
        case RuleOperator.NOT_EQUALS:
          return { matched: value !== condition.value, value };
        
        case RuleOperator.CONTAINS:
          return { matched: String(value).includes(String(condition.value)), value };
        
        case RuleOperator.NOT_CONTAINS:
          return { matched: !String(value).includes(String(condition.value)), value };
        
        case RuleOperator.GREATER_THAN:
          return { matched: Number(value) > Number(condition.value), value };
        
        case RuleOperator.LESS_THAN:
          return { matched: Number(value) < Number(condition.value), value };
        
        case RuleOperator.GREATER_EQUALS:
          return { matched: Number(value) >= Number(condition.value), value };
        
        case RuleOperator.LESS_EQUALS:
          return { matched: Number(value) <= Number(condition.value), value };
        
        case RuleOperator.IN:
          return { matched: condition.values?.includes(value), value };
        
        case RuleOperator.NOT_IN:
          return { matched: !condition.values?.includes(value), value };
        
        case RuleOperator.REGEX: {
          const flags = condition.flags || 'i';
          const regex = new RegExp(condition.pattern!, flags);
          return { matched: regex.test(String(value)), value };
        }
        
        default:
          return { matched: false, error: `Unknown operator: ${condition.operator}` };
      }
    } catch (error) {
      return {
        matched: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }
  
  /**
   * Оценка всех условий правила
   */
  evaluateConditions(
    conditions: RuleCondition[],
    logicalOperator: LogicalOperator,
    log: LogEntry
  ): boolean {
    if (conditions.length === 0) {
      return true;
    }
    
    const results = conditions.map(c => this.evaluateCondition(c, log));
    
    // Проверка на ошибки
    const hasErrors = results.some(r => r.error);
    if (hasErrors) {
      return false;
    }
    
    switch (logicalOperator) {
      case LogicalOperator.AND:
        return results.every(r => r.matched);
      
      case LogicalOperator.OR:
        return results.some(r => r.matched);
      
      case LogicalOperator.NOT:
        return !results.some(r => r.matched);
      
      default:
        return false;
    }
  }
  
  /**
   * Оценка вложенных условий
   */
  evaluateNestedConditions(condition: RuleCondition, log: LogEntry): boolean {
    if (condition.conditions && condition.conditions.length > 0) {
      const results = condition.conditions.map(c => this.evaluateNestedConditions(c, log));
      
      switch (condition.logicalOperator) {
        case LogicalOperator.AND:
          return results.every(r => r);
        case LogicalOperator.OR:
          return results.some(r => r);
        case LogicalOperator.NOT:
          return !results.some(r => r);
      }
    }
    
    return this.evaluateCondition(condition, log).matched;
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
}

// ============================================================================
// КЛАСС AGGREGATION MANAGER
// ============================================================================

/**
 * Менеджер агрегаций
 */
class AggregationManager {
  private windows: Map<string, AggregationWindow>;
  private cleanupInterval: NodeJS.Timeout | null;
  
  constructor() {
    this.windows = new Map();
    this.cleanupInterval = null;
    this.startCleanup();
  }
  
  /**
   * Добавление лога в окно агрегации
   */
  addLog(
    ruleId: string,
    log: LogEntry,
    aggregation: RuleAggregation,
    groupBy: string[]
  ): AggregationWindow | null {
    // Создание group key
    const groupKey = this.createGroupKey(log, groupBy);
    const windowKey = `${ruleId}:${groupKey}`;
    
    // Получение или создание окна
    let window = this.windows.get(windowKey);
    
    if (!window) {
      window = {
        ruleId,
        groupKey,
        logs: [],
        startTime: Date.now(),
        endTime: Date.now() + (aggregation.windowSeconds * 1000),
        windowSeconds: aggregation.windowSeconds,
        threshold: aggregation.threshold
      };
      this.windows.set(windowKey, window);
    }
    
    // Добавление лога
    window.logs.push(log);
    window.endTime = Date.now() + (aggregation.windowSeconds * 1000);
    
    // Проверка порога
    const aggregationValue = this.calculateAggregationValue(window, aggregation);
    
    if (aggregationValue >= aggregation.threshold) {
      // Порог достигнут
      this.windows.delete(windowKey);
      return window;
    }
    
    return null;
  }
  
  /**
   * Расчет значения агрегации
   */
  calculateAggregationValue(window: AggregationWindow, aggregation: RuleAggregation): number {
    switch (aggregation.type) {
      case 'count':
        return window.logs.length;
      
      case 'distinct_count': {
        if (!aggregation.field) return 0;
        const values = new Set(
          window.logs.map(log => this.getFieldValue(log, aggregation.field!))
        );
        return values.size;
      }
      
      case 'sum': {
        if (!aggregation.field) return 0;
        return window.logs.reduce((sum, log) => {
          const value = Number(this.getFieldValue(log, aggregation.field!) || 0);
          return sum + value;
        }, 0);
      }
      
      case 'avg': {
        if (!aggregation.field || window.logs.length === 0) return 0;
        const sum = window.logs.reduce((sum, log) => {
          const value = Number(this.getFieldValue(log, aggregation.field!) || 0);
          return sum + value;
        }, 0);
        return sum / window.logs.length;
      }
      
      case 'min': {
        if (!aggregation.field || window.logs.length === 0) return 0;
        return Math.min(...window.logs.map(log => 
          Number(this.getFieldValue(log, aggregation.field!) || 0)
        ));
      }
      
      case 'max': {
        if (!aggregation.field || window.logs.length === 0) return 0;
        return Math.max(...window.logs.map(log => 
          Number(this.getFieldValue(log, aggregation.field!) || 0)
        ));
      }
      
      default:
        return 0;
    }
  }
  
  /**
   * Создание group key
   */
  private createGroupKey(log: LogEntry, groupBy: string[]): string {
    if (groupBy.length === 0) {
      return 'default';
    }
    
    const values = groupBy.map(field => this.getFieldValue(log, field));
    return values.join('|');
  }
  
  /**
   * Получение значения поля
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
   * Запуск периодической очистки
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      
      for (const [key, window] of this.windows.entries()) {
        if (now > window.endTime) {
          this.windows.delete(key);
        }
      }
    }, 10000);
  }
  
  /**
   * Получение количества активных окон
   */
  getActiveWindowCount(): number {
    return this.windows.size;
  }
  
  /**
   * Закрытие менеджера
   */
  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.windows.clear();
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС SIEM ENGINE
// ============================================================================

/**
 * SIEM Engine - движок правил SIEM
 * 
 * Реализует:
 * - Выполнение правил SIEM
 * - Агрегацию событий
 * - Генерацию алертов
 * - MITRE ATT&CK маппинг
 * - Compliance правила
 * - Динамическое управление правилами
 */
export class SIEMEngine extends EventEmitter {
  private config: SIEMEngineConfig;
  private rules: Map<string, SIEMRule>;
  private evaluator: RuleEvaluator;
  private aggregationManager: AggregationManager;
  private statistics: SIEMEngineStatistics;
  private executionTimes: number[];
  private enabled: boolean;
  
  constructor(config: Partial<SIEMEngineConfig> = {}) {
    super();
    
    this.config = {
      enableBuiltinRules: config.enableBuiltinRules !== false,
      maxRules: config.maxRules || 1000,
      ruleExecutionTimeout: config.ruleExecutionTimeout || 5000,
      enableAggregation: config.enableAggregation !== false,
      defaultAggregationWindow: config.defaultAggregationWindow || 300,
      enableResultCache: config.enableResultCache || false,
      cacheSize: config.cacheSize || 10000,
      cacheTtlSeconds: config.cacheTtlSeconds || 300
    };
    
    this.rules = new Map();
    this.evaluator = new RuleEvaluator();
    this.aggregationManager = new AggregationManager();
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.executionTimes = [];
    this.enabled = true;
    
    // Загрузка встроенных правил
    if (this.config.enableBuiltinRules) {
      this.loadBuiltinRules();
    }
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): SIEMEngineStatistics {
    return {
      totalLogsProcessed: 0,
      totalRulesExecuted: 0,
      rulesTriggered: 0,
      alertsGenerated: 0,
      executionErrors: 0,
      avgRuleExecutionTime: 0,
      p99RuleExecutionTime: 0,
      byRule: {},
      byCategory: {},
      activeAggregationWindows: 0
    };
  }
  
  /**
   * Загрузка встроенных правил
   */
  private loadBuiltinRules(): void {
    for (const rule of BUILTIN_RULES) {
      this.rules.set(rule.id, rule);
    }
  }
  
  /**
   * Обработка лога через SIEM engine
   */
  process(log: LogEntry): Promise<RuleExecutionResult[]> {
    if (!this.enabled) {
      return Promise.resolve([]);
    }
    
    this.statistics.totalLogsProcessed++;
    
    const results: RuleExecutionResult[] = [];
    const enabledRules = Array.from(this.rules.values()).filter(r => r.enabled);
    
    // Параллельное выполнение правил
    const rulePromises = enabledRules.map(rule => this.executeRule(rule, log));
    
    return Promise.all(rulePromises).then(ruleResults => {
      for (const result of ruleResults) {
        if (result) {
          results.push(result);
          
          if (result.matched) {
            this.statistics.rulesTriggered++;
            this.updateCategoryStats(result.ruleName);
            
            // Эмиссия события срабатывания правила
            this.emit('rule_triggered', result);
            
            // Генерация алертов для действий ALERT
            for (const action of result.actionsExecuted) {
              if (action.type === RuleActionType.ALERT) {
                this.statistics.alertsGenerated++;
                this.emit('alert_generated', this.createAlert(result, log, action));
              }
            }
          }
        }
      }
      
      return results;
    });
  }
  
  /**
   * Выполнение правила
   */
  private async executeRule(rule: SIEMRule, log: LogEntry): Promise<RuleExecutionResult | null> {
    const startTime = Date.now();
    
    try {
      // Проверка таймаута
      const timeoutPromise = new Promise<null>(resolve => {
        setTimeout(() => resolve(null), this.config.ruleExecutionTimeout);
      });
      
      const executionPromise = this.doExecuteRule(rule, log);
      
      const result = await Promise.race([executionPromise, timeoutPromise]);
      
      if (result === null) {
        // Таймаут
        this.statistics.executionErrors++;
        return null;
      }
      
      // Обновление статистики выполнения
      const executionTime = Date.now() - startTime;
      this.updateExecutionStats(rule.id, rule.name, result.matched, executionTime);
      
      return result;
    } catch (error) {
      this.statistics.executionErrors++;
      
      this.emit('rule_error', {
        ruleId: rule.id,
        ruleName: rule.name,
        error
      });
      
      return null;
    }
  }
  
  /**
   * Фактическое выполнение правила
   */
  private doExecuteRule(rule: SIEMRule, log: LogEntry): RuleExecutionResult {
    const startTime = Date.now();
    
    // Проверка условий
    let matched = false;
    
    if (rule.aggregation && this.config.enableAggregation) {
      // Агрегированное правило
      const groupBy = rule.aggregation.groupBy || [];
      const window = this.aggregationManager.addLog(
        rule.id,
        log,
        rule.aggregation,
        groupBy
      );
      
      if (window) {
        matched = true;
      }
    } else {
      // Простое правило
      matched = this.evaluator.evaluateConditions(
        rule.conditions,
        rule.logicalOperator,
        log
      );
    }
    
    // Выполнение действий если правило сработало
    const actionsExecuted: RuleAction[] = [];
    
    if (matched) {
      for (const action of rule.actions) {
        // Проверка условий действия
        if (action.conditions) {
          const actionMatched = this.evaluator.evaluateConditions(
            action.conditions,
            LogicalOperator.AND,
            log
          );
          
          if (!actionMatched) {
            continue;
          }
        }
        
        actionsExecuted.push(action);
        
        // Эмиссия действия
        this.emit('action_executed', {
          ruleId: rule.id,
          action,
          log
        });
      }
    }
    
    return {
      ruleId: rule.id,
      ruleName: rule.name,
      matched,
      matchedLogs: matched ? [log] : [],
      aggregationValue: rule.aggregation 
        ? this.aggregationManager.calculateAggregationValue(
            { 
              ruleId: rule.id, 
              groupKey: '', 
              logs: [log], 
              startTime: 0, 
              endTime: 0, 
              windowSeconds: rule.aggregation.windowSeconds, 
              threshold: rule.aggregation.threshold 
            }, 
            rule.aggregation
          )
        : undefined,
      threshold: rule.aggregation?.threshold,
      triggeredAt: new Date().toISOString(),
      actionsExecuted,
      executionTime: Date.now() - startTime
    };
  }
  
  /**
   * Создание алерта
   */
  private createAlert(
    result: RuleExecutionResult,
    log: LogEntry,
    action: RuleAction
  ): Alert {
    const severity = this.getAlertSeverity(result, action);
    
    return {
      id: crypto.randomUUID(),
      ruleId: result.ruleId,
      ruleName: result.ruleName,
      title: `${result.ruleName}`,
      description: action.template 
        ? this.interpolateTemplate(action.template, log)
        : `Rule ${result.ruleName} triggered`,
      severity,
      status: 'new',
      category: this.getRuleCategory(result.ruleId),
      tags: this.getRuleTags(result.ruleId),
      relatedLogs: result.matchedLogs,
      source: log.component,
      hostname: log.hostname,
      ipAddress: log.context.clientIp,
      user: log.context.userId,
      occurredAt: log.timestamp,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      escalationHistory: [],
      notifications: [],
      fingerprint: this.createAlertFingerprint(result, log),
      occurrenceCount: 1,
      firstOccurrenceAt: log.timestamp,
      lastOccurrenceAt: log.timestamp
    };
  }
  
  /**
   * Получение severity алерта
   */
  private getAlertSeverity(result: RuleExecutionResult, action: RuleAction): AlertSeverity {
    const priority = action.priority || 3;
    
    switch (priority) {
      case 1:
        return AlertSeverity.P1_CRITICAL;
      case 2:
        return AlertSeverity.P2_HIGH;
      case 3:
        return AlertSeverity.P3_MEDIUM;
      case 4:
        return AlertSeverity.P4_LOW;
      default:
        return AlertSeverity.P5_INFO;
    }
  }
  
  /**
   * Интерполяция шаблона
   */
  private interpolateTemplate(template: string, log: LogEntry): string {
    return template.replace(/\{\{([^}]+)\}\}/g, (match, path) => {
      const value = this.getFieldValue(log, path.trim());
      return value !== undefined ? String(value) : match;
    });
  }
  
  /**
   * Получение значения поля
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
   * Создание fingerprint для дедупликации
   *
   * БЕЗОПАСНОСТЬ: Используем SHA-256 вместо MD5 для криптографической стойкости
   */
  private createAlertFingerprint(result: RuleExecutionResult, log: LogEntry): string {
    const fingerprintData = JSON.stringify({
      ruleId: result.ruleId,
      source: log.component,
      ip: log.context.clientIp,
      user: log.context.userId,
      hour: log.timestamp.substring(0, 13) // Группировка по часам
    });

    // ИСПОЛЬЗУЕМ SHA-256 вместо уязвимого MD5
    return crypto.createHash('sha256').update(fingerprintData).digest('hex');
  }
  
  /**
   * Получение категории правила
   */
  private getRuleCategory(ruleId: string): string {
    const rule = this.rules.get(ruleId);
    return rule?.category || 'unknown';
  }
  
  /**
   * Получение тегов правила
   */
  private getRuleTags(ruleId: string): string[] {
    const rule = this.rules.get(ruleId);
    return rule?.tags || [];
  }
  
  /**
   * Обновление статистики выполнения
   */
  private updateExecutionStats(
    ruleId: string,
    ruleName: string,
    matched: boolean,
    executionTime: number
  ): void {
    this.statistics.totalRulesExecuted++;
    
    // Инициализация статистики правила
    if (!this.statistics.byRule[ruleId]) {
      this.statistics.byRule[ruleId] = {
        executions: 0,
        triggers: 0,
        avgTime: 0,
        falsePositives: 0
      };
    }
    
    const ruleStats = this.statistics.byRule[ruleId];
    ruleStats.executions++;
    
    if (matched) {
      ruleStats.triggers++;
    }
    
    // Обновление среднего времени
    ruleStats.avgTime = (ruleStats.avgTime * (ruleStats.executions - 1) + executionTime) / ruleStats.executions;
    
    // Обновление общей статистики времени
    this.executionTimes.push(executionTime);
    if (this.executionTimes.length > 1000) {
      this.executionTimes.shift();
    }
    
    this.statistics.avgRuleExecutionTime = 
      this.executionTimes.reduce((a, b) => a + b, 0) / this.executionTimes.length;
    
    const sorted = [...this.executionTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99RuleExecutionTime = sorted[p99Index] || 0;
    
    // Обновление статистики агрегации
    this.statistics.activeAggregationWindows = this.aggregationManager.getActiveWindowCount();
  }
  
  /**
   * Обновление статистики по категориям
   */
  private updateCategoryStats(ruleName: string): void {
    const category = this.getRuleCategory(
      Array.from(this.rules.entries()).find(([_, r]) => r.name === ruleName)?.[0] || ''
    );
    
    this.statistics.byCategory[category] = (this.statistics.byCategory[category] || 0) + 1;
  }
  
  // ==========================================================================
  // УПРАВЛЕНИЕ ПРАВИЛАМИ
  // ==========================================================================
  
  /**
   * Добавление правила
   */
  addRule(rule: SIEMRule): boolean {
    if (this.rules.size >= this.config.maxRules) {
      return false;
    }
    
    this.rules.set(rule.id, rule);
    this.emit('rule_added', rule);
    return true;
  }
  
  /**
   * Обновление правила
   */
  updateRule(ruleId: string, updates: Partial<SIEMRule>): boolean {
    const existingRule = this.rules.get(ruleId);
    
    if (!existingRule) {
      return false;
    }
    
    const updatedRule: SIEMRule = {
      ...existingRule,
      ...updates,
      updatedAt: new Date().toISOString()
    };
    
    this.rules.set(ruleId, updatedRule);
    this.emit('rule_updated', updatedRule);
    return true;
  }
  
  /**
   * Удаление правила
   */
  removeRule(ruleId: string): boolean {
    const deleted = this.rules.delete(ruleId);
    
    if (deleted) {
      this.emit('rule_removed', ruleId);
    }
    
    return deleted;
  }
  
  /**
   * Включение правила
   */
  enableRule(ruleId: string): boolean {
    return this.updateRule(ruleId, { enabled: true });
  }
  
  /**
   * Выключение правила
   */
  disableRule(ruleId: string): boolean {
    return this.updateRule(ruleId, { enabled: false });
  }
  
  /**
   * Получение правила по ID
   */
  getRule(ruleId: string): SIEMRule | undefined {
    return this.rules.get(ruleId);
  }
  
  /**
   * Получение всех правил
   */
  getAllRules(): SIEMRule[] {
    return Array.from(this.rules.values());
  }
  
  /**
   * Получение правил по категории
   */
  getRulesByCategory(category: string): SIEMRule[] {
    return Array.from(this.rules.values()).filter(r => r.category === category);
  }
  
  /**
   * Получение правил по тегу
   */
  getRulesByTag(tag: string): SIEMRule[] {
    return Array.from(this.rules.values()).filter(r => r.tags.includes(tag));
  }
  
  /**
   * Получение правил по compliance стандарту
   */
  getRulesByCompliance(standard: ComplianceStandard): SIEMRule[] {
    return Array.from(this.rules.values()).filter(
      r => r.complianceStandards?.includes(standard)
    );
  }
  
  /**
   * Получение правил по MITRE ATT&CK ID
   */
  getRulesByMitreAttack(mitreId: string): SIEMRule[] {
    return Array.from(this.rules.values()).filter(
      r => r.mitreAttackIds?.includes(mitreId)
    );
  }
  
  /**
   * Маркировка ложного срабатывания
   */
  markFalsePositive(ruleId: string): void {
    if (this.statistics.byRule[ruleId]) {
      this.statistics.byRule[ruleId].falsePositives++;
    }
    
    this.emit('false_positive', { ruleId });
  }
  
  // ==========================================================================
  // СТАТИСТИКА И УПРАВЛЕНИЕ
  // ==========================================================================
  
  /**
   * Получение статистики
   */
  getStatistics(): SIEMEngineStatistics {
    return { ...this.statistics };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
    this.executionTimes = [];
  }
  
  /**
   * Включение engine
   */
  enable(): void {
    this.enabled = true;
  }
  
  /**
   * Выключение engine
   */
  disable(): void {
    this.enabled = false;
  }
  
  /**
   * Проверка включен ли engine
   */
  isEnabled(): boolean {
    return this.enabled;
  }
  
  /**
   * Закрытие engine
   */
  close(): void {
    this.enabled = false;
    this.aggregationManager.close();
    this.emit('closed');
  }
  
  /**
   * Экспорт правил
   */
  exportRules(): string {
    return JSON.stringify(Array.from(this.rules.values()), null, 2);
  }
  
  /**
   * Импорт правил
   */
  importRules(rulesJson: string): number {
    try {
      const rules: SIEMRule[] = JSON.parse(rulesJson);
      let importedCount = 0;
      
      for (const rule of rules) {
        if (this.addRule(rule)) {
          importedCount++;
        }
      }
      
      return importedCount;
    } catch (error) {
      this.emit('import_error', { error });
      return 0;
    }
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default SIEMEngine;
