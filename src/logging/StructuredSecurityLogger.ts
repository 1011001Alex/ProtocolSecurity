/**
 * =============================================================================
 * STRUCTURED SECURITY LOGGER
 * =============================================================================
 * Централизованный логгер для всех security событий
 * Формат: Structured JSON (CEF-compatible)
 * Интеграция: Winston + Elasticsearch + SIEM
 * =============================================================================
 */

import winston from 'winston';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';

// =============================================================================
// ТИПЫ И ИНТЕРФЕЙСЫ
// =============================================================================

/**
 * Категории security событий
 */
export enum SecurityCategory {
  AUTHENTICATION = 'AUTH',
  AUTHORIZATION = 'ACCESS',
  DATA = 'DATA',
  NETWORK = 'NETWORK',
  SYSTEM = 'SYSTEM',
  THREAT = 'THREAT',
  AUDIT = 'AUDIT',
  COMPLIANCE = 'COMPLIANCE'
}

/**
 * Уровни важности
 */
export enum SecuritySeverity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO'
}

/**
 * Результаты операций
 */
export enum SecurityOutcome {
  SUCCESS = 'SUCCESS',
  FAILURE = 'FAILURE',
  DENIED = 'DENIED',
  PARTIAL = 'PARTIAL'
}

/**
 * Базовая структура security события
 */
export interface SecurityEvent {
  /** Уникальный ID события */
  eventId: string;
  
  /** Временная метка (ISO 8601) */
  timestamp: string;
  
  /** Категория события */
  category: SecurityCategory;
  
  /** Тип события (детальный) */
  eventType: string;
  
  /** Уровень важности */
  severity: SecuritySeverity;
  
  /** Результат операции */
  outcome: SecurityOutcome;
  
  /** Actor (кто выполнил действие) */
  actor: {
    /** ID пользователя/сервиса */
    id?: string;
    /** Тип: user, service, system, anonymous */
    type: 'user' | 'service' | 'system' | 'anonymous';
    /** Email или имя */
    identifier?: string;
    /** Роли */
    roles?: string[];
  };
  
  /** Действие */
  action: string;
  
  /** Ресурс */
  resource: {
    /** Тип ресурса */
    type: string;
    /** ID ресурса */
    id?: string;
    /** Название */
    name?: string;
    /** Путь */
    path?: string;
  };
  
  /** Контекст */
  context: {
    /** IP адрес */
    ipAddress: string;
    /** User Agent */
    userAgent?: string;
    /** ID сессии */
    sessionId?: string;
    /** ID корреляции */
    correlationId: string;
    /** Геолокация */
    geoLocation?: {
      country: string;
      region: string;
      city: string;
      latitude?: number;
      longitude?: number;
    };
  };
  
  /** Дополнительные данные */
  data?: Record<string, any>;
  
  /** Ошибка (если есть) */
  error?: {
    code: string;
    message: string;
    stack?: string;
  };
  
  /** Метки для фильтрации */
  tags?: string[];
}

/**
 * Конфигурация логгера
 */
export interface SecurityLoggerConfig {
  /** Уровень логгирования */
  level: SecuritySeverity;
  
  /** Путь для file transport */
  logFilePath?: string;
  
  /** Elasticsearch конфигурация */
  elasticsearch?: {
    host: string;
    index: string;
  };
  
  /** SIEM конфигурация */
  siem?: {
    type: 'splunk' | 'elasticsearch' | 'sentinel' | 'qradar';
    endpoint: string;
    token?: string;
  };
  
  /** Включить console transport */
  enableConsole: boolean;
  
  /** Включить file transport */
  enableFile: boolean;
  
  /** Max size файла лога */
  maxSize: string;
  
  /** Количество файлов для ротации */
  maxFiles: number;
}

// =============================================================================
// SECURITY LOGGER CLASS
// =============================================================================

export class SecurityLogger extends EventEmitter {
  private logger: winston.Logger;
  private config: SecurityLoggerConfig;
  private defaultCorrelationId: string;

  constructor(config: Partial<SecurityLoggerConfig> = {}) {
    super();
    
    this.config = {
      level: config.level ?? SecuritySeverity.INFO,
      logFilePath: config.logFilePath ?? './logs/security.log',
      elasticsearch: config.elasticsearch,
      siem: config.siem,
      enableConsole: config.enableConsole ?? true,
      enableFile: config.enableFile ?? true,
      maxSize: config.maxSize ?? '50m',
      maxFiles: config.maxFiles ?? 5
    };
    
    this.defaultCorrelationId = uuidv4();
    
    this.logger = this.createLogger();
  }

  /**
   * Создание Winston логгера
   */
  private createLogger(): winston.Logger {
    const transports: winston.transport[] = [];

    // Console transport
    if (this.config.enableConsole) {
      transports.push(
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
            winston.format.printf(({ timestamp, level, message, ...meta }) => {
              return `${timestamp} [${level}] ${message} ${Object.keys(meta).length ? JSON.stringify(meta) : ''}`;
            })
          )
        })
      );
    }

    // File transport
    if (this.config.enableFile) {
      transports.push(
        new winston.transports.File({
          filename: this.config.logFilePath,
          level: this.config.level.toLowerCase(),
          maxsize: 52428800, // 50MB
          maxFiles: this.config.maxFiles,
          format: winston.format.combine(
            winston.format.timestamp({ format: 'ISO8601' }),
            winston.format.json()
          )
        })
      );
    }

    // Elasticsearch transport (если настроен)
    if (this.config.elasticsearch) {
      // В production использовать winston-elasticsearch
      // transports.push(new ElasticsearchTransport({...}))
    }

    return winston.createLogger({
      level: this.config.level.toLowerCase(),
      transports,
      defaultMeta: { service: 'protocol-security' }
    });
  }

  // =============================================================================
  // МЕТОДЫ ЛОГИРОВАНИЯ
  // =============================================================================

  /**
   * Логирование security события
   */
  log(event: Omit<SecurityEvent, 'eventId' | 'timestamp'>): void {
    const securityEvent: SecurityEvent = {
      ...event,
      eventId: uuidv4(),
      timestamp: new Date().toISOString(),
      context: {
        ...event.context,
        correlationId: event.context.correlationId || this.defaultCorrelationId
      }
    };

    // Отправка в SIEM если настроено
    if (this.config.siem) {
      this.sendToSIEM(securityEvent);
    }

    // Эмит события для внешних слушателей
    this.emit('security-event', securityEvent);

    // Логирование
    const logLevel = this.getLogLevel(securityEvent.severity);
    this.logger.log(logLevel, securityEvent.eventType, securityEvent);
  }

  /**
   * Логирование аутентификации
   */
  logAuth(event: {
    eventType: 'LOGIN' | 'LOGOUT' | 'LOGIN_FAILURE' | 'PASSWORD_CHANGE' | 'MFA_CHALLENGE' | 'MFA_SUCCESS' | 'MFA_FAILURE';
    userId?: string;
    email?: string;
    outcome: SecurityOutcome;
    ipAddress: string;
    userAgent?: string;
    sessionId?: string;
    mfaMethod?: string;
    failureReason?: string;
    correlationId?: string;
  }): void {
    this.log({
      category: SecurityCategory.AUTHENTICATION,
      eventType: event.eventType,
      severity: this.getAuthSeverity(event.eventType, event.outcome),
      outcome: event.outcome,
      actor: {
        type: event.userId ? 'user' : 'anonymous',
        id: event.userId,
        identifier: event.email
      },
      action: this.getAuthAction(event.eventType),
      resource: {
        type: 'authentication-service',
        name: 'Auth Service'
      },
      context: {
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        sessionId: event.sessionId,
        correlationId: event.correlationId || this.defaultCorrelationId
      },
      data: {
        mfaMethod: event.mfaMethod,
        failureReason: event.failureReason
      },
      tags: ['authentication', event.eventType.toLowerCase()]
    });
  }

  /**
   * Логирование доступа (авторизация)
   */
  logAccess(event: {
    eventType: 'ACCESS_GRANTED' | 'ACCESS_DENIED' | 'PERMISSION_CHECK' | 'ROLE_CHANGE';
    userId: string;
    action: string;
    resource: string;
    resourceId?: string;
    outcome: SecurityOutcome;
    ipAddress: string;
    sessionId?: string;
    correlationId?: string;
    reason?: string;
  }): void {
    this.log({
      category: SecurityCategory.AUTHORIZATION,
      eventType: event.eventType,
      severity: event.outcome === SecurityOutcome.DENIED ? SecuritySeverity.MEDIUM : SecuritySeverity.INFO,
      outcome: event.outcome,
      actor: {
        type: 'user',
        id: event.userId
      },
      action: event.action,
      resource: {
        type: 'resource',
        id: event.resourceId,
        name: event.resource
      },
      context: {
        ipAddress: event.ipAddress,
        sessionId: event.sessionId,
        correlationId: event.correlationId || this.defaultCorrelationId
      },
      data: {
        reason: event.reason
      },
      tags: ['authorization', event.eventType.toLowerCase()]
    });
  }

  /**
   * Логирование доступа к данным
   */
  logDataAccess(event: {
    eventType: 'DATA_READ' | 'DATA_WRITE' | 'DATA_DELETE' | 'DATA_EXPORT' | 'DATA_IMPORT';
    userId: string;
    dataType: string;
    recordCount?: number;
    dataSize?: number;
    outcome: SecurityOutcome;
    ipAddress: string;
    sessionId?: string;
    correlationId?: string;
  }): void {
    const severity = event.eventType === 'DATA_EXPORT'
      ? SecuritySeverity.MEDIUM
      : SecuritySeverity.INFO;

    this.log({
      category: SecurityCategory.DATA,
      eventType: event.eventType,
      severity,
      outcome: event.outcome,
      actor: {
        type: 'user',
        id: event.userId
      },
      action: event.eventType.toLowerCase(),
      resource: {
        type: 'data',
        name: event.dataType
      },
      context: {
        ipAddress: event.ipAddress,
        sessionId: event.sessionId,
        correlationId: event.correlationId || this.defaultCorrelationId
      },
      data: {
        dataType: event.dataType,
        recordCount: event.recordCount,
        dataSize: event.dataSize
      },
      tags: ['data-access', event.eventType.toLowerCase()]
    });
  }

  /**
   * Логирование сетевых событий
   */
  logNetworkEvent(event: {
    eventType: 'CONNECTION' | 'DISCONNECTION' | 'REQUEST' | 'RESPONSE' | 'FIREWALL_BLOCK';
    sourceIp: string;
    destinationIp?: string;
    port?: number;
    protocol?: string;
    outcome: SecurityOutcome;
    correlationId?: string;
  }): void {
    this.log({
      category: SecurityCategory.NETWORK,
      eventType: event.eventType,
      severity: event.eventType === 'FIREWALL_BLOCK' ? SecuritySeverity.MEDIUM : SecuritySeverity.INFO,
      outcome: event.outcome,
      actor: {
        type: 'system'
      },
      action: event.eventType.toLowerCase(),
      resource: {
        type: 'network',
        id: event.destinationIp
      },
      context: {
        ipAddress: event.sourceIp,
        correlationId: event.correlationId || this.defaultCorrelationId
      },
      data: {
        sourceIp: event.sourceIp,
        destinationIp: event.destinationIp,
        port: event.port,
        protocol: event.protocol
      },
      tags: ['network', event.eventType.toLowerCase()]
    });
  }

  /**
   * Логирование угроз
   */
  logThreat(event: {
    eventType: 'INTRUSION_ATTEMPT' | 'MALWARE_DETECTED' | 'DDOS_ATTACK' | 'BRUTE_FORCE' | 'ANOMALY_DETECTED';
    threatType: string;
    sourceIp: string;
    targetResource?: string;
    severity: SecuritySeverity;
    confidence?: number;
    mitreAttackId?: string;
    correlationId?: string;
  }): void {
    this.log({
      category: SecurityCategory.THREAT,
      eventType: event.eventType,
      severity: event.severity,
      outcome: SecurityOutcome.FAILURE,
      actor: {
        type: 'anonymous'
      },
      action: 'threat-detected',
      resource: {
        type: 'system',
        name: event.targetResource
      },
      context: {
        ipAddress: event.sourceIp,
        correlationId: event.correlationId || this.defaultCorrelationId
      },
      data: {
        threatType: event.threatType,
        confidence: event.confidence,
        mitreAttackId: event.mitreAttackId
      },
      tags: ['threat', event.eventType.toLowerCase(), 'security-alert']
    });
  }

  /**
   * Логирование системных событий
   */
  logSystemEvent(event: {
    eventType: 'STARTUP' | 'SHUTDOWN' | 'CONFIG_CHANGE' | 'ERROR' | 'MAINTENANCE';
    component: string;
    outcome: SecurityOutcome;
    details?: string;
    correlationId?: string;
  }): void {
    this.log({
      category: SecurityCategory.SYSTEM,
      eventType: event.eventType,
      severity: event.eventType === 'ERROR' ? SecuritySeverity.HIGH : SecuritySeverity.INFO,
      outcome: event.outcome,
      actor: {
        type: 'system'
      },
      action: event.eventType.toLowerCase(),
      resource: {
        type: 'component',
        name: event.component
      },
      context: {
        ipAddress: 'localhost',
        correlationId: event.correlationId || this.defaultCorrelationId
      },
      data: {
        componentName: event.component,
        details: event.details
      },
      tags: ['system', event.eventType.toLowerCase()]
    });
  }

  /**
   * Логирование audit событий (для compliance)
   */
  logAudit(event: {
    eventType: string;
    userId: string;
    action: string;
    resource: string;
    outcome: SecurityOutcome;
    details?: Record<string, any>;
    correlationId?: string;
  }): void {
    this.log({
      category: SecurityCategory.AUDIT,
      eventType: event.eventType,
      severity: SecuritySeverity.INFO,
      outcome: event.outcome,
      actor: {
        type: 'user',
        id: event.userId
      },
      action: event.action,
      resource: {
        type: 'resource',
        name: event.resource
      },
      context: {
        ipAddress: 'unknown',
        correlationId: event.correlationId || this.defaultCorrelationId
      },
      data: event.details,
      tags: ['audit', 'compliance']
    });
  }

  // =============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // =============================================================================

  /**
   * Отправка события в SIEM
   */
  private sendToSIEM(event: SecurityEvent): void {
    // В реальной реализации здесь будет отправка в SIEM
    // Elasticsearch, Splunk, Azure Sentinel, etc.
    
    if (this.config.siem?.type === 'elasticsearch') {
      // Отправка в Elasticsearch
      console.log('[SIEM] Sending to Elasticsearch:', event);
    } else if (this.config.siem?.type === 'splunk') {
      // Отправка в Splunk (HEC endpoint)
      console.log('[SIEM] Sending to Splunk:', event);
    }
    
    this.emit('siem-send', event);
  }

  /**
   * Получение уровня логирования из severity
   */
  private getLogLevel(severity: SecuritySeverity): string {
    const logLevelMap: Record<SecuritySeverity, string> = {
      [SecuritySeverity.CRITICAL]: 'error',
      [SecuritySeverity.HIGH]: 'error',
      [SecuritySeverity.MEDIUM]: 'warn',
      [SecuritySeverity.LOW]: 'info',
      [SecuritySeverity.INFO]: 'info'
    };
    
    return logLevelMap[severity] || 'info';
  }

  /**
   * Получение severity для auth события
   */
  private getAuthSeverity(eventType: string, outcome: SecurityOutcome): SecuritySeverity {
    if (outcome === SecurityOutcome.FAILURE || outcome === SecurityOutcome.DENIED) {
      return SecuritySeverity.MEDIUM;
    }
    
    if (eventType.includes('MFA')) {
      return outcome === SecurityOutcome.SUCCESS ? SecuritySeverity.INFO : SecuritySeverity.HIGH;
    }
    
    return SecuritySeverity.INFO;
  }

  /**
   * Получение действия для auth события
   */
  private getAuthAction(eventType: string): string {
    const actionMap: Record<string, string> = {
      'LOGIN': 'authenticate',
      'LOGOUT': 'logout',
      'LOGIN_FAILURE': 'authenticate-failure',
      'PASSWORD_CHANGE': 'change-password',
      'MFA_CHALLENGE': 'mfa-challenge',
      'MFA_SUCCESS': 'mfa-verify-success',
      'MFA_FAILURE': 'mfa-verify-failure'
    };
    
    return actionMap[eventType] || eventType.toLowerCase();
  }

  /**
   * Установка correlation ID по умолчанию
   */
  setDefaultCorrelationId(correlationId: string): void {
    this.defaultCorrelationId = correlationId;
  }

  /**
   * Получение статистики
   */
  getStats(): {
    eventsLogged: number;
    level: string;
    transports: number;
  } {
    return {
      eventsLogged: 0, // В реальной реализации считать события
      level: this.config.level,
      transports: this.logger.transports.length
    };
  }
}

// =============================================================================
// ЭКСПОРТ
// =============================================================================

/**
 * Создание экземпляра логгера
 */
export function createSecurityLogger(config?: Partial<SecurityLoggerConfig>): SecurityLogger {
  return new SecurityLogger(config);
}

/**
 * Singleton экземпляр
 */
export const securityLogger = new SecurityLogger({
  enableConsole: process.env.NODE_ENV !== 'production',
  enableFile: true,
  logFilePath: './logs/security.log',
  level: SecuritySeverity.INFO
});
