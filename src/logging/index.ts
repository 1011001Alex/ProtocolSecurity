/**
 * ============================================================================
 * ГЛОБАЛЬНЫЙ ЭКСПОРТ ЛОГГЕРА
 * ============================================================================
 * Централизованный доступ к логгеру для всех модулей системы
 *
 * Использование:
 * import { logger, securityLogger, RequestContextManagerInstance } from './logging';
 *
 * logger.info('Сообщение', { field1: 'value1' });
 * logger.error('Ошибка', error);
 * securityLogger.authEvent('login_success', userId);
 */

import { SecureLogger, LoggerFactory } from './Logger';
import { securityLogger } from './SecurityContextLogger';
import {
  RequestContextManager,
  RequestContextManagerInstance,
  requestContextMiddleware,
  getCurrentRequestContext,
  getCurrentRequestId,
  getCurrentUserId,
  getCurrentSessionId,
  updateRequestContext,
  setRequestUserId,
  setRequestSessionId,
  runInRequestContext
} from './RequestContextLogger';
import type { RequestContext } from './RequestContextLogger';
import {
  LogLevel,
  LogSource,
  LogContext,
  LoggerConfig,
  GlobalConfig
} from '../types/logging.types';

// ============================================================================
// КОНФИГУРАЦИЯ ПО УМОЛЧАНИЮ
// ============================================================================

/**
 * Конфигурация логгера по умолчанию
 * Может быть переопределена через переменные окружения
 */
const defaultLoggerConfig: LoggerConfig = {
  level: LogLevel.DEBUG,
  format: 'structured',
  enableColors: true,
  enableTimestamp: true,
  enableProcessInfo: true,
  transports: [
    {
      type: 'console',
      level: LogLevel.DEBUG,
      params: {}
    }
  ]
};

/**
 * Глобальная конфигурация сервиса
 */
const defaultGlobalConfig: GlobalConfig = {
  serviceName: 'protocol',
  environment: (process.env.NODE_ENV as 'development' | 'staging' | 'production') || 'development',
  region: 'local',
  version: '1.0.0',
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
// ГЛОБАЛЬНЫЙ ЭКЗЕМПЛЯР ЛОГГЕРА
// ============================================================================

/**
 * Глобальный экземпляр логгера
 * Инициализируется при первом импорте
 */
let globalLogger: SecureLogger | null = null;

/**
 * Флаг инициализации
 */
let isInitialized = false;

/**
 * Получение глобального логгера
 * Если логгер еще не создан, будет создан с конфигурацией по умолчанию
 */
export function getLogger(): SecureLogger {
  if (!globalLogger) {
    globalLogger = LoggerFactory.getLogger(
      'global',
      defaultLoggerConfig,
      defaultGlobalConfig
    );
    isInitialized = true;
  }
  return globalLogger;
}

/**
 * Инициализация логгера с кастомной конфигурацией
 * Должна вызываться один раз при старте приложения
 */
export function initializeLogger(
  loggerConfig?: Partial<LoggerConfig>,
  globalConfig?: Partial<GlobalConfig>
): SecureLogger {
  if (isInitialized) {
    const logger = getLogger();
    logger.info('Logger already initialized, returning existing instance');
    return logger;
  }

  const mergedLoggerConfig: LoggerConfig = {
    ...defaultLoggerConfig,
    ...loggerConfig
  };

  const mergedGlobalConfig: GlobalConfig = {
    ...defaultGlobalConfig,
    ...globalConfig
  };

  globalLogger = LoggerFactory.getLogger(
    'global',
    mergedLoggerConfig,
    mergedGlobalConfig
  );

  isInitialized = true;

  globalLogger.info(
    'Logger initialized',
    LogSource.SYSTEM,
    'logger',
    {
      level: LogLevel[mergedLoggerConfig.level],
      format: mergedLoggerConfig.format,
      transports: mergedLoggerConfig.transports.map(t => t.type)
    }
  );

  return globalLogger;
}

/**
 * Получение логгера для конкретного компонента
 * Создает дочерний логгер с указанным компонентом
 */
export function getComponentLogger(componentName: string): SecureLogger {
  const logger = getLogger();
  logger.setDefaultContext({ metadata: { component: componentName } });
  return logger;
}

/**
 * Закрытие логгера и всех транспортов
 * Должна вызываться при завершении работы приложения
 */
export async function closeLogger(): Promise<void> {
  if (globalLogger) {
    await globalLogger.close();
    globalLogger = null;
    isInitialized = false;
  }
}

// ============================================================================
// УДОБНЫЕ ФУНКЦИИ ДЛЯ ЛОГИРОВАНИЯ
// ============================================================================

/**
 * Логирование уровня INFO
 */
export function info(
  message: string,
  context?: LogContext,
  fields?: Record<string, unknown>
): void {
  getLogger().info(message, LogSource.APPLICATION, undefined, context, fields);
}

/**
 * Логирование уровня DEBUG
 */
export function debug(
  message: string,
  context?: LogContext,
  fields?: Record<string, unknown>
): void {
  getLogger().debug(message, LogSource.APPLICATION, undefined, context, fields);
}

/**
 * Логирование уровня ERROR
 */
export function error(
  message: string,
  errorObj?: Error,
  context?: LogContext,
  fields?: Record<string, unknown>
): void {
  getLogger().error(message, LogSource.APPLICATION, undefined, context, fields, errorObj);
}

/**
 * Логирование уровня WARNING
 */
export function warn(
  message: string,
  context?: LogContext,
  fields?: Record<string, unknown>
): void {
  getLogger().warning(message, LogSource.APPLICATION, undefined, context, fields);
}

/**
 * Логирование уровня CRITICAL
 */
export function critical(
  message: string,
  context?: LogContext,
  fields?: Record<string, unknown>
): void {
  getLogger().critical(message, LogSource.APPLICATION, undefined, context, fields);
}

/**
 * Логирование уровня TRACE
 */
export function trace(
  message: string,
  context?: LogContext,
  fields?: Record<string, unknown>
): void {
  getLogger().trace(message, LogSource.APPLICATION, undefined, context, fields);
}

// ============================================================================
// ЭКСПОРТЫ
// ============================================================================

export type { LogSource };

export {
  SecureLogger,
  LoggerFactory,
  securityLogger,
  RequestContextManager,
  RequestContextManagerInstance,
  requestContextMiddleware,
  getCurrentRequestContext,
  getCurrentRequestId,
  getCurrentUserId,
  getCurrentSessionId,
  updateRequestContext,
  setRequestUserId,
  setRequestSessionId,
  runInRequestContext
};

export type {
  RequestContext,
  LogLevel,
  LogContext,
  LoggerConfig,
  GlobalConfig
};

export default getLogger;
