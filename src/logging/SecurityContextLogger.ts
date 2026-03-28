/**
 * ============================================================================
 * SECURITY CONTEXT LOGGER
 * ============================================================================
 * Обертка над SecureLogger с автоматическим добавлением контекста запроса
 * и защитой от log injection.
 *
 * Использование:
 * import { securityLogger } from './logging/SecurityContextLogger';
 * 
 * securityLogger.info('User action', { action: 'login' });
 * securityLogger.error('Operation failed', error);
 */

import { SecureLogger, LoggerFactory } from './Logger';
import { LogLevel, LogSource, LogContext, LoggerConfig, GlobalConfig } from '../types/logging.types';
import { getCurrentRequestContext, getCurrentRequestId, getCurrentUserId, getCurrentSessionId } from './RequestContextLogger';

// ============================================================================
// КОНФИГУРАЦИЯ ПО УМОЛЧАНИЮ
// ============================================================================

/**
 * Конфигурация логгера по умолчанию
 */
const DEFAULT_LOGGER_CONFIG: LoggerConfig = {
  level: LogLevel.DEBUG,
  format: 'json',
  enableColors: process.env.NODE_ENV !== 'production',
  enableTimestamp: true,
  enableProcessInfo: true,
  transports: [
    {
      type: 'console',
      level: LogLevel.DEBUG,
      params: {
        enableColors: process.env.NODE_ENV !== 'production'
      }
    }
  ]
};

/**
 * Глобальная конфигурация
 */
const DEFAULT_GLOBAL_CONFIG: GlobalConfig = {
  serviceName: 'protocol-security-api',
  environment: (process.env.NODE_ENV as 'development' | 'staging' | 'production') || 'development',
  region: process.env.REGION || 'default',
  version: process.env.APP_VERSION || '1.0.0',
  timezone: 'UTC',
  enableAudit: true,
  enableDebug: process.env.NODE_ENV !== 'production',
  traceSampleRate: 1,
  maxLogSize: 1024 * 1024,
  enableRateLimiting: true,
  rateLimiting: {
    maxAlerts: 100,
    periodSeconds: 60,
    action: 'suppress'
  }
};

// ============================================================================
// SECURITY CONTEXT LOGGER
// ============================================================================

/**
 * Логгер с автоматическим контекстом безопасности
 */
class SecurityContextLogger {
  private logger: SecureLogger;

  constructor() {
    this.logger = LoggerFactory.getLogger(
      'security-context',
      this.loadConfig(),
      DEFAULT_GLOBAL_CONFIG
    );
  }

  /**
   * Загрузка конфигурации из переменных окружения
   */
  private loadConfig(): LoggerConfig {
    const logLevel = process.env.LOG_LEVEL || 'debug';
    const logFormat = process.env.LOG_FORMAT || 'json';
    const logOutput = process.env.LOG_OUTPUT || 'console';

    const config: LoggerConfig = {
      level: this.parseLogLevel(logLevel),
      format: logFormat as 'json' | 'text' | 'structured',
      enableColors: process.env.LOG_COLORS !== 'false',
      enableTimestamp: true,
      enableProcessInfo: true,
      transports: []
    };

    // Парсинг LOG_OUTPUT (может содержать несколько транспортов через запятую)
    const outputs = logOutput.split(',').map(s => s.trim().toLowerCase());

    if (outputs.includes('console')) {
      config.transports.push({
        type: 'console',
        level: config.level,
        params: {
          enableColors: process.env.LOG_COLORS !== 'false'
        }
      });
    }

    if (outputs.includes('file') || outputs.includes('logs')) {
      const logPath = process.env.LOG_FILE_PATH || './logs/app.log';
      const logMaxSize = parseInt(process.env.LOG_MAX_SIZE_MB || '100', 10);
      const logMaxFiles = parseInt(process.env.LOG_MAX_FILES || '5', 10);

      config.transports.push({
        type: 'file',
        level: config.level,
        params: {
          path: logPath,
          maxSizeMB: logMaxSize,
          maxFiles: logMaxFiles
        }
      });
    }

    if (outputs.includes('http') || outputs.includes('remote')) {
      const httpUrl = process.env.LOG_HTTP_URL || 'http://localhost:3000/logs';
      const httpBatchSize = parseInt(process.env.LOG_HTTP_BATCH_SIZE || '100', 10);
      const httpBatchTimeout = parseInt(process.env.LOG_HTTP_BATCH_TIMEOUT_MS || '5000', 10);

      config.transports.push({
        type: 'http',
        level: config.level,
        params: {
          url: httpUrl,
          headers: {
            'Authorization': `Bearer ${process.env.LOG_HTTP_TOKEN || ''}`
          },
          batchSize: httpBatchSize,
          batchTimeoutMs: httpBatchTimeout
        }
      });
    }

    return config;
  }

  /**
   * Парсинг уровня логирования из строки
   */
  private parseLogLevel(level: string): LogLevel {
    const levelMap: Record<string, LogLevel> = {
      'emergency': LogLevel.EMERGENCY,
      'alert': LogLevel.ALERT,
      'critical': LogLevel.CRITICAL,
      'error': LogLevel.ERROR,
      'warning': LogLevel.WARNING,
      'warn': LogLevel.WARNING,
      'notice': LogLevel.NOTICE,
      'info': LogLevel.INFO,
      'debug': LogLevel.DEBUG,
      'trace': LogLevel.TRACE
    };

    return levelMap[level.toLowerCase()] ?? LogLevel.DEBUG;
  }

  /**
   * Создание контекста с автоматическими полями из запроса
   */
  private buildContext(extraContext?: LogContext): LogContext {
    const requestContext = getCurrentRequestContext();
    
    const autoContext: LogContext = {
      requestId: getCurrentRequestId(),
      userId: getCurrentUserId(),
      sessionId: getCurrentSessionId(),
      clientIp: requestContext?.clientIp,
      userAgent: requestContext?.userAgent,
      method: requestContext?.method,
      path: requestContext?.path
    };

    // Объединение с дефолтным контекстом и дополнительным
    return {
      ...autoContext,
      ...extraContext
    };
  }

  /**
   * Санитизация полей для защиты от log injection
   */
  private sanitizeFields(fields?: Record<string, unknown>): Record<string, unknown> | undefined {
    if (!fields) return undefined;

    const sanitized: Record<string, unknown> = {};
    
    for (const [key, value] of Object.entries(fields)) {
      if (typeof value === 'string') {
        // Удаление опасных символов из строк
        sanitized[key] = value
          .replace(/[\r\n]/g, '')
          .replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized;
  }

  // ==========================================================================
  // МЕТОДЫ ЛОГИРОВАНИЯ
  // ==========================================================================

  /**
   * Логирование уровня EMERGENCY
   */
  emergency(message: string, fields?: Record<string, unknown>): void {
    this.logger.emergency(
      message,
      LogSource.SECURITY,
      'security-context',
      this.buildContext(),
      this.sanitizeFields(fields)
    );
  }

  /**
   * Логирование уровня ALERT
   */
  alert(message: string, fields?: Record<string, unknown>): void {
    this.logger.alert(
      message,
      LogSource.SECURITY,
      'security-context',
      this.buildContext(),
      this.sanitizeFields(fields)
    );
  }

  /**
   * Логирование уровня CRITICAL
   */
  critical(message: string, fields?: Record<string, unknown>): void {
    this.logger.critical(
      message,
      LogSource.APPLICATION,
      'security-context',
      this.buildContext(),
      this.sanitizeFields(fields)
    );
  }

  /**
   * Логирование уровня ERROR
   */
  error(message: string, errorOrFields?: Error | Record<string, unknown>, fields?: Record<string, unknown>): void {
    const error = errorOrFields instanceof Error ? errorOrFields : undefined;
    const extraFields = errorOrFields instanceof Error ? fields : errorOrFields;

    this.logger.error(
      message,
      LogSource.APPLICATION,
      'security-context',
      this.buildContext(),
      this.sanitizeFields(extraFields),
      error
    );
  }

  /**
   * Логирование уровня WARNING
   */
  warning(message: string, fields?: Record<string, unknown>): void {
    this.logger.warning(
      message,
      LogSource.APPLICATION,
      'security-context',
      this.buildContext(),
      this.sanitizeFields(fields)
    );
  }

  /**
   * Логирование уровня NOTICE
   */
  notice(message: string, fields?: Record<string, unknown>): void {
    this.logger.notice(
      message,
      LogSource.AUDIT,
      'security-context',
      this.buildContext(),
      this.sanitizeFields(fields)
    );
  }

  /**
   * Логирование уровня TRACE
   */
  trace(message: string, fields?: Record<string, unknown>): void {
    this.logger.trace(
      message,
      LogSource.APPLICATION,
      'security-context',
      this.buildContext(),
      this.sanitizeFields(fields)
    );
  }

  /**
   * Логирование уровня INFO
   */
  info(message: string, fields?: Record<string, unknown>): void {
    this.logger.info(
      message,
      LogSource.APPLICATION,
      'security-context',
      this.buildContext(),
      this.sanitizeFields(fields)
    );
  }

  /**
   * Логирование уровня DEBUG
   */
  debug(message: string, fields?: Record<string, unknown>): void {
    this.logger.debug(
      message,
      LogSource.APPLICATION,
      'security-context',
      this.buildContext(),
      this.sanitizeFields(fields)
    );
  }

  // ==========================================================================
  // СПЕЦИАЛИЗИРОВАННЫЕ МЕТОДЫ ДЛЯ СОБЫТИЙ БЕЗОПАСНОСТИ
  // ==========================================================================

  /**
   * Событие аутентификации
   */
  authEvent(
    eventType: 'login_success' | 'login_failure' | 'logout' | 'password_change' | 'mfa_success' | 'mfa_failure',
    userId?: string,
    extraFields?: Record<string, unknown>
  ): void {
    const level = eventType.includes('failure') ? LogLevel.WARNING : LogLevel.INFO;
    const message = `Authentication event: ${eventType}`;

    if (level === LogLevel.WARNING) {
      this.logger.warning(
        message,
        LogSource.AUTH,
        'auth-service',
        this.buildContext({ userId, ...extraFields }),
        { eventType, userId }
      );
    } else {
      this.logger.info(
        message,
        LogSource.AUTH,
        'auth-service',
        this.buildContext({ userId, ...extraFields }),
        { eventType, userId }
      );
    }
  }

  /**
   * Событие авторизации
   */
  authzEvent(
    action: 'access_granted' | 'access_denied',
    resource: string,
    userId?: string,
    extraFields?: Record<string, unknown>
  ): void {
    const level = action === 'access_denied' ? LogLevel.WARNING : LogLevel.INFO;
    const message = `Authorization: ${action} - ${resource}`;

    if (level === LogLevel.WARNING) {
      this.logger.warning(
        message,
        LogSource.AUTH,
        'authz-service',
        this.buildContext({ userId, ...extraFields }),
        { action, resource, userId }
      );
    } else {
      this.logger.info(
        message,
        LogSource.AUTH,
        'authz-service',
        this.buildContext({ userId, ...extraFields }),
        { action, resource, userId }
      );
    }
  }

  /**
   * Событие доступа к данным
   */
  dataAccessEvent(
    action: 'read' | 'write' | 'delete',
    resourceType: string,
    resourceId: string,
    result: 'success' | 'denied',
    userId?: string,
    extraFields?: Record<string, unknown>
  ): void {
    const level = result === 'denied' ? LogLevel.WARNING : LogLevel.INFO;
    const message = `Data access: ${action} ${resourceType}/${resourceId} - ${result}`;

    if (level === LogLevel.WARNING) {
      this.logger.warning(
        message,
        LogSource.AUDIT,
        'audit-service',
        this.buildContext({ userId, ...extraFields }),
        { resourceType, resourceId, action, result }
      );
    } else {
      this.logger.info(
        message,
        LogSource.AUDIT,
        'audit-service',
        this.buildContext({ userId, ...extraFields }),
        { resourceType, resourceId, action, result }
      );
    }
  }

  /**
   * Событие изменения конфигурации
   */
  configChangeEvent(
    configPath: string,
    userId?: string,
    extraFields?: Record<string, unknown>
  ): void {
    this.logger.notice(
      `Configuration changed: ${configPath}`,
      LogSource.AUDIT,
      'config-service',
      this.buildContext({ userId, ...extraFields }),
      { configPath, changeType: 'update' }
    );
  }

  /**
   * Событие безопасности
   */
  securityEvent(
    eventType: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    description: string,
    extraFields?: Record<string, unknown>
  ): void {
    const message = `Security event: ${eventType} - ${description}`;

    switch (severity) {
      case 'critical':
        this.logger.critical(
          message,
          LogSource.SECURITY,
          'security-service',
          this.buildContext(extraFields),
          { eventType, severity, description, ...extraFields }
        );
        break;
      case 'high':
        this.logger.error(
          message,
          LogSource.SECURITY,
          'security-service',
          this.buildContext(extraFields),
          { eventType, severity, description, ...extraFields }
        );
        break;
      case 'medium':
        this.logger.warning(
          message,
          LogSource.SECURITY,
          'security-service',
          this.buildContext(extraFields),
          { eventType, severity, description, ...extraFields }
        );
        break;
      case 'low':
      default:
        this.logger.info(
          message,
          LogSource.SECURITY,
          'security-service',
          this.buildContext(extraFields),
          { eventType, severity, description, ...extraFields }
        );
        break;
    }
  }

  /**
   * Событие rate limiting
   */
  rateLimitEvent(
    identifier: string,
    limit: number,
    windowMs: number,
    extraFields?: Record<string, unknown>
  ): void {
    this.logger.warning(
      `Rate limit exceeded for ${identifier}`,
      LogSource.SECURITY,
      'rate-limiter',
      this.buildContext(extraFields),
      { identifier, limit, windowMs }
    );
  }

  /**
   * Событие валидации входных данных
   */
  validationEvent(
    inputType: string,
    reason: string,
    severity: 'warning' | 'error' = 'error',
    extraFields?: Record<string, unknown>
  ): void {
    if (severity === 'warning') {
      this.logger.warning(
        `Validation failed for ${inputType}: ${reason}`,
        LogSource.SECURITY,
        'input-validation',
        this.buildContext(extraFields),
        { inputType, reason }
      );
    } else {
      this.logger.error(
        `Validation failed for ${inputType}: ${reason}`,
        LogSource.SECURITY,
        'input-validation',
        this.buildContext(extraFields),
        { inputType, reason }
      );
    }
  }

  // ==========================================================================
  // МЕТОДЫ УПРАВЛЕНИЯ
  // ==========================================================================

  /**
   * Установка уровня логирования
   */
  setLevel(level: LogLevel | string): void {
    if (typeof level === 'string') {
      level = this.parseLogLevel(level);
    }
    this.logger.setLevel(level);
  }

  /**
   * Получение статистики
   */
  getStatistics() {
    return this.logger.getStatistics();
  }

  /**
   * Закрытие логгера
   */
  async close(): Promise<void> {
    await this.logger.close();
  }
}

// ============================================================================
// ЭКСПОРТ ЕДИНСТВЕННОГО ЭКЗЕМПЛЯРА
// ============================================================================

export const securityLogger = new SecurityContextLogger();
export { LogLevel, LogSource } from '../types/logging.types';
