/**
 * =============================================================================
 * ERROR HANDLER MIDDLEWARE
 * =============================================================================
 * Централизованная обработка всех ошибок
 * Безопасные ответы клиенту без утечки информации
 * =============================================================================
 */

import { IncomingMessage, ServerResponse } from 'http';
import { BaseError, ErrorLevel, SafeError } from './BaseError';
import {
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  NotFoundError,
  RateLimitExceededError,
  InternalError
} from './BaseError';

// =============================================================================
// ТИПЫ И ИНТЕРФЕЙСЫ
// =============================================================================

/**
 * Конфигурация error handler
 */
export interface ErrorHandlerConfig {
  /** Включить детальные ошибки в development */
  detailedErrorsInDev: boolean;
  
  /** Логгер */
  logger: any;
  
  /** Интеграция с Sentry */
  sentry?: {
    enabled: boolean;
    dsn?: string;
  };
  
  /** Интеграция с Datadog */
  datadog?: {
    enabled: boolean;
    apiKey?: string;
  };
  
  /** Кастомные обработчики для типов ошибок */
  customHandlers?: {
    [errorCode: string]: (error: BaseError, req: IncomingMessage) => SafeError;
  };
}

/**
 * Контекст ошибки
 */
export interface ErrorContext {
  /** Request */
  req: IncomingMessage;
  
  /** Response */
  res: ServerResponse;
  
  /** Ошибка */
  error: unknown;
  
  /** Timestamp */
  timestamp: Date;
  
  /** Path */
  path: string;
  
  /** Method */
  method: string;
  
  /** IP адрес */
  ip: string;
  
  /** User Agent */
  userAgent?: string;
}

// =============================================================================
// ERROR HANDLER CLASS
// =============================================================================

export class ErrorHandlerMiddleware {
  private config: ErrorHandlerConfig;
  private isDevelopment: boolean;

  constructor(config: ErrorHandlerConfig) {
    this.config = config;
    this.isDevelopment = process.env.NODE_ENV === 'development';
  }

  /**
   * Middleware функция
   */
  handle(error: unknown, req: IncomingMessage, res: ServerResponse): void {
    const context: ErrorContext = {
      req,
      res,
      error,
      timestamp: new Date(),
      path: req.url || 'unknown',
      method: req.method || 'unknown',
      ip: req.socket.remoteAddress || 'unknown',
      userAgent: (req as any).headers?.['user-agent']
    };

    // Обработка ошибки
    const baseError = this.normalizeError(error, context);

    // Логирование
    this.logError(baseError, context);

    // Отправка в external сервисы
    this.sendToExternalServices(baseError, context);

    // Формирование ответа
    const safeResponse = this.createSafeResponse(baseError);

    // Отправка клиенту
    this.sendResponse(res, baseError.statusCode, safeResponse);
  }

  /**
   * Нормализация ошибки в BaseError
   */
  private normalizeError(error: unknown, context: ErrorContext): BaseError {
    // Уже BaseError
    if (error instanceof BaseError) {
      return error.withRequest(context.path, context.method);
    }

    // Native Error
    if (error instanceof Error) {
      return this.mapNativeError(error, context);
    }

    // Unknown error
    return new InternalError(
      'An unknown error occurred',
      {
        originalError: String(error),
        originalType: typeof error
      }
    ).withRequest(context.path, context.method);
  }

  /**
   * Маппинг native Error в BaseError
   */
  private mapNativeError(error: Error, context: ErrorContext): BaseError {
    const errorMessage = error.message.toLowerCase();

    // JSON parse errors
    if (errorMessage.includes('json') || errorMessage.includes('parse')) {
      return new ValidationError('Invalid JSON format', {
        originalMessage: error.message
      }).withRequest(context.path, context.method);
    }

    // Syntax errors
    if (errorMessage.includes('syntax')) {
      return new ValidationError('Syntax error in request', {
        originalMessage: error.message
      }).withRequest(context.path, context.method);
    }

    // URI errors
    if (errorMessage.includes('uri') || errorMessage.includes('url')) {
      return new ValidationError('Invalid URL format', {
        originalMessage: error.message
      }).withRequest(context.path, context.method);
    }

    // Default to Internal Error
    return new InternalError(error.message, undefined, error)
      .withRequest(context.path, context.method);
  }

  /**
   * Логирование ошибки
   */
  private logError(error: BaseError, context: ErrorContext): void {
    const logData = {
      timestamp: context.timestamp,
      level: error.level,
      category: error.category,
      code: error.code,
      message: error.message,
      path: context.path,
      method: context.method,
      ip: context.ip,
      userAgent: context.userAgent,
      correlationId: error.correlationId,
      stack: error.stack,
      metadata: error.metadata
    };

    // Логирование через предоставленный logger
    if (this.config.logger) {
      switch (error.level) {
        case ErrorLevel.CRITICAL:
          this.config.logger.error('[CRITICAL]', logData);
          break;
        case ErrorLevel.ERROR:
          this.config.logger.error('[ERROR]', logData);
          break;
        case ErrorLevel.WARNING:
          this.config.logger.warn('[WARNING]', logData);
          break;
        case ErrorLevel.INFO:
          this.config.logger.info('[INFO]', logData);
          break;
      }
    } else {
      // Fallback на console
      console.error('[ERROR]', logData);
    }
  }

  /**
   * Отправка в external сервисы
   */
  private sendToExternalServices(error: BaseError, context: ErrorContext): void {
    // Только CRITICAL и ERROR уровни
    if (error.level !== ErrorLevel.CRITICAL && error.level !== ErrorLevel.ERROR) {
      return;
    }

    // Sentry
    if (this.config.sentry?.enabled) {
      this.sendToSentry(error, context);
    }

    // Datadog
    if (this.config.datadog?.enabled) {
      this.sendToDatadog(error, context);
    }
  }

  /**
   * Отправка в Sentry
   */
  private sendToSentry(error: BaseError, context: ErrorContext): void {
    try {
      // В реальной реализации: Sentry.captureException(error, { ... })
      console.log('[Sentry] Capturing exception:', {
        code: error.code,
        correlationId: error.correlationId
      });
    } catch (sentryError) {
      console.error('[Sentry] Failed to send:', sentryError);
    }
  }

  /**
   * Отправка в Datadog
   */
  private sendToDatadog(error: BaseError, context: ErrorContext): void {
    try {
      // В реальной реализации: datadog.metrics.increment(...)
      console.log('[Datadog] Logging metric:', {
        error_code: error.code,
        level: error.level
      });
    } catch (datadogError) {
      console.error('[Datadog] Failed to send:', datadogError);
    }
  }

  /**
   * Создание безопасного ответа
   */
  private createSafeResponse(error: BaseError): SafeError {
    // Проверка custom handler
    if (this.config.customHandlers?.[error.code]) {
      const customResponse = this.config.customHandlers[error.code](error, {} as IncomingMessage);
      if (customResponse) {
        return customResponse;
      }
    }

    // Стандартный safe response
    return error.toSafeResponse(this.isDevelopment && this.config.detailedErrorsInDev);
  }

  /**
   * Отправка ответа клиенту
   */
  private sendResponse(res: ServerResponse, statusCode: number, body: SafeError): void {
    // Установка заголовков
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json');
    
    // Security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Correlation-ID', body.correlationId);

    // Отправка тела
    res.end(JSON.stringify(body));
  }

  /**
   * Обёртка async функции с обработкой ошибок
   */
  wrapAsync<T extends (...args: any[]) => Promise<any>>(
    fn: T,
    context?: string
  ): (...args: Parameters<T>) => Promise<ReturnType<T>> {
    return async (...args: Parameters<T>): Promise<ReturnType<T>> => {
      try {
        return await fn(...args);
      } catch (error) {
        throw this.normalizeError(error, {
          req: {} as IncomingMessage,
          res: {} as ServerResponse,
          error,
          timestamp: new Date(),
          path: context || 'unknown',
          method: 'unknown',
          ip: 'unknown'
        });
      }
    };
  }
}

// =============================================================================
// EXPRESS ERROR HANDLER
// =============================================================================

/**
 * Express error handler middleware
 */
export function expressErrorHandler(config: ErrorHandlerConfig) {
  const handler = new ErrorHandlerMiddleware(config);

  return (
    error: any,
    req: any,
    res: any,
    next: any
  ): void => {
    handler.handle(error, req, res);
  };
}

/**
 * Express async handler wrapper
 */
export function asyncHandler(fn: (...args: any[]) => Promise<any>) {
  return (req: any, res: any, next: any): void => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// =============================================================================
// KOA ERROR HANDLER
// =============================================================================

/**
 * Koa error handler middleware
 */
export function koaErrorHandler(config: ErrorHandlerConfig) {
  const handler = new ErrorHandlerMiddleware(config);

  return async (ctx: any, next: () => Promise<void>): Promise<void> => {
    try {
      await next();
    } catch (error) {
      handler.handle(error, ctx.req, ctx.res);
    }
  };
}

// =============================================================================
// FASTIFY ERROR HANDLER
// =============================================================================

/**
 * Fastify error handler
 */
export function fastifyErrorHandler(config: ErrorHandlerConfig) {
  const handler = new ErrorHandlerMiddleware(config);

  return function (error: any, request: any, reply: any): void {
    handler.handle(error, request.raw, reply.raw);
  };
}

// =============================================================================
// ПРЕДУСТАНОВЛЕННЫЕ КОНФИГУРАЦИИ
// =============================================================================

/**
 * Конфигурация для development
 */
export function createDevErrorHandler(logger?: any): ErrorHandlerMiddleware {
  return new ErrorHandlerMiddleware({
    detailedErrorsInDev: true,
    logger: logger || console,
    sentry: { enabled: false },
    datadog: { enabled: false }
  });
}

/**
 * Конфигурация для production
 */
export function createProdErrorHandler(
  logger: any,
  sentryDsn?: string,
  datadogApiKey?: string
): ErrorHandlerMiddleware {
  return new ErrorHandlerMiddleware({
    detailedErrorsInDev: false,
    logger,
    sentry: {
      enabled: !!sentryDsn,
      dsn: sentryDsn
    },
    datadog: {
      enabled: !!datadogApiKey,
      apiKey: datadogApiKey
    }
  });
}

// =============================================================================
// ЭКСПОРТ
// =============================================================================

export function createErrorHandler(config: ErrorHandlerConfig): ErrorHandlerMiddleware {
  return new ErrorHandlerMiddleware(config);
}

export type { ErrorHandlerConfig, ErrorContext };
