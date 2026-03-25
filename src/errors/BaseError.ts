/**
 * =============================================================================
 * BASE ERROR CLASS
 * =============================================================================
 * Базовый класс для всех ошибок в системе
 * Безопасная обработка без утечки информации
 * =============================================================================
 */

import { v4 as uuidv4 } from 'uuid';

// =============================================================================
// ТИПЫ И ИНТЕРФЕЙСЫ
// =============================================================================

/**
 * Уровни ошибок
 */
export enum ErrorLevel {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical'
}

/**
 * Категории ошибок
 */
export enum ErrorCategory {
  VALIDATION = 'VALIDATION',
  AUTHENTICATION = 'AUTHENTICATION',
  AUTHORIZATION = 'AUTHORIZATION',
  NOT_FOUND = 'NOT_FOUND',
  CONFLICT = 'CONFLICT',
  RATE_LIMIT = 'RATE_LIMIT',
  INTERNAL = 'INTERNAL',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  EXTERNAL_SERVICE = 'EXTERNAL_SERVICE',
  DATABASE = 'DATABASE',
  SECURITY = 'SECURITY'
}

/**
 * Безопасный ответ об ошибке
 */
export interface SafeError {
  /** Код ошибки */
  code: string;
  
  /** Сообщение для клиента */
  message: string;
  
  /** Уровень */
  level: ErrorLevel;
  
  /** Correlation ID */
  correlationId: string;
  
  /** Timestamp */
  timestamp: string;
  
  /** Путь */
  path?: string;
  
  /** Метод */
  method?: string;
  
  /** Детали (только в development) */
  details?: any;
}

/**
 * Полная информация об ошибке (для логирования)
 */
export interface FullError extends SafeError {
  /** Stack trace */
  stack?: string;
  
  /** Причина */
  cause?: any;
  
  /** Метаданные */
  metadata: Record<string, any>;
  
  /** Категория */
  category: ErrorCategory;
  
  /** HTTP статус код */
  statusCode: number;
  
  /** Внутренняя ошибка */
  innerError?: Error;
}

// =============================================================================
// BASE ERROR CLASS
// =============================================================================

export abstract class BaseError extends Error {
  /** Код ошибки */
  readonly code: string;
  
  /** HTTP статус код */
  readonly statusCode: number;
  
  /** Correlation ID */
  readonly correlationId: string;
  
  /** Timestamp */
  readonly timestamp: Date;
  
  /** Категория */
  readonly category: ErrorCategory;
  
  /** Уровень */
  readonly level: ErrorLevel;
  
  /** Метаданные */
  readonly metadata: Record<string, any>;
  
  /** Внутренняя ошибка */
  readonly innerError?: Error;
  
  /** Путь запроса */
  readonly path?: string;
  
  /** HTTP метод */
  readonly method?: string;

  constructor(
    message: string,
    code: string,
    statusCode: number,
    category: ErrorCategory,
    level: ErrorLevel = ErrorLevel.ERROR,
    metadata?: Record<string, any>,
    innerError?: Error
  ) {
    super(message);
    
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    this.correlationId = uuidv4();
    this.timestamp = new Date();
    this.category = category;
    this.level = level;
    this.metadata = metadata || {};
    this.innerError = innerError;
    
    // Capture stack trace
    Error.captureStackTrace(this, this.constructor);
  }

  /**
   * Получение безопасного ответа
   */
  toSafeResponse(isDevelopment: boolean = false): SafeError {
    const response: SafeError = {
      code: this.code,
      message: this.getSafeMessage(),
      level: this.level,
      correlationId: this.correlationId,
      timestamp: this.timestamp.toISOString()
    };

    if (this.path) {
      response.path = this.path;
    }

    if (this.method) {
      response.method = this.method;
    }

    // Детали только в development
    if (isDevelopment) {
      response.details = {
        stack: this.stack,
        metadata: this.metadata,
        innerError: this.innerError?.message
      };
    }

    return response;
  }

  /**
   * Получение полной информации
   */
  toFullError(): FullError {
    return {
      code: this.code,
      message: this.message,
      level: this.level,
      correlationId: this.correlationId,
      timestamp: this.timestamp.toISOString(),
      path: this.path,
      method: this.method,
      stack: this.stack,
      category: this.category,
      statusCode: this.statusCode,
      metadata: this.metadata,
      innerError: this.innerError
    };
  }

  /**
   * Получение безопасного сообщения
   * Переопределяется в подклассах для специфичных сообщений
   */
  protected getSafeMessage(): string {
    // По умолчанию возвращаем общее сообщение
    return 'An error occurred';
  }

  /**
   * Установка контекста запроса
   */
  withRequest(path: string, method: string): this {
    Object.defineProperty(this, 'path', { value: path, writable: false });
    Object.defineProperty(this, 'method', { value: method, writable: false });
    return this;
  }

  /**
   * Логирование ошибки
   */
  log(logger: any): void {
    const logData = this.toFullError();
    
    switch (this.level) {
      case ErrorLevel.CRITICAL:
        logger.error('[CRITICAL]', logData);
        break;
      case ErrorLevel.ERROR:
        logger.error('[ERROR]', logData);
        break;
      case ErrorLevel.WARNING:
        logger.warn('[WARNING]', logData);
        break;
      case ErrorLevel.INFO:
        logger.info('[INFO]', logData);
        break;
    }
  }
}

// =============================================================================
// SECURITY ERRORS
// =============================================================================

export class AuthenticationError extends BaseError {
  constructor(
    message: string = 'Authentication failed',
    metadata?: Record<string, any>,
    innerError?: Error
  ) {
    super(
      message,
      'AUTH_FAILED',
      401,
      ErrorCategory.AUTHENTICATION,
      ErrorLevel.WARNING,
      metadata,
      innerError
    );
  }

  protected override getSafeMessage(): string {
    return 'Invalid credentials';
  }
}

export class AuthorizationError extends BaseError {
  constructor(
    message: string = 'Access denied',
    metadata?: Record<string, any>,
    innerError?: Error
  ) {
    super(
      message,
      'ACCESS_DENIED',
      403,
      ErrorCategory.AUTHORIZATION,
      ErrorLevel.WARNING,
      metadata,
      innerError
    );
  }

  protected override getSafeMessage(): string {
    return 'You do not have permission to access this resource';
  }
}

export class SessionExpiredError extends BaseError {
  constructor(metadata?: Record<string, any>) {
    super(
      'Session has expired',
      'SESSION_EXPIRED',
      401,
      ErrorCategory.AUTHENTICATION,
      ErrorLevel.INFO,
      metadata
    );
  }

  protected override getSafeMessage(): string {
    return 'Your session has expired. Please log in again.';
  }
}

export class MFARequiredError extends BaseError {
  constructor(metadata?: Record<string, any>) {
    super(
      'Multi-factor authentication required',
      'MFA_REQUIRED',
      403,
      ErrorCategory.AUTHENTICATION,
      ErrorLevel.INFO,
      metadata
    );
  }

  protected override getSafeMessage(): string {
    return 'Multi-factor authentication is required';
  }
}

export class InvalidTokenError extends BaseError {
  constructor(metadata?: Record<string, any>) {
    super(
      'Invalid or expired token',
      'INVALID_TOKEN',
      401,
      ErrorCategory.AUTHENTICATION,
      ErrorLevel.WARNING,
      metadata
    );
  }

  protected override getSafeMessage(): string {
    return 'Invalid or expired token';
  }
}

export class AccountLockedError extends BaseError {
  constructor(
    retryAfter?: number,
    metadata?: Record<string, any>
  ) {
    super(
      'Account has been locked due to too many failed attempts',
      'ACCOUNT_LOCKED',
      423,
      ErrorCategory.AUTHENTICATION,
      ErrorLevel.WARNING,
      { retryAfter, ...metadata }
    );
  }

  protected override getSafeMessage(): string {
    return 'Account temporarily locked. Please try again later.';
  }
}

// =============================================================================
// VALIDATION ERRORS
// =============================================================================

export class ValidationError extends BaseError {
  constructor(
    message: string = 'Validation failed',
    metadata?: Record<string, any>,
    innerError?: Error
  ) {
    super(
      message,
      'VALIDATION_ERROR',
      400,
      ErrorCategory.VALIDATION,
      ErrorLevel.INFO,
      metadata,
      innerError
    );
  }

  protected override getSafeMessage(): string {
    return 'Invalid input provided';
  }
}

export class InvalidInputError extends BaseError {
  constructor(
    field?: string,
    metadata?: Record<string, any>
  ) {
    super(
      `Invalid input for field: ${field || 'unknown'}`,
      'INVALID_INPUT',
      400,
      ErrorCategory.VALIDATION,
      ErrorLevel.INFO,
      { field, ...metadata }
    );
  }

  protected override getSafeMessage(): string {
    return 'Invalid input provided';
  }
}

export class MissingParameterError extends BaseError {
  constructor(
    parameter: string,
    metadata?: Record<string, any>
  ) {
    super(
      `Missing required parameter: ${parameter}`,
      'MISSING_PARAMETER',
      400,
      ErrorCategory.VALIDATION,
      ErrorLevel.INFO,
      { parameter, ...metadata }
    );
  }

  protected override getSafeMessage(): string {
    return 'A required parameter is missing';
  }
}

// =============================================================================
// NOT FOUND ERROR
// =============================================================================

export class NotFoundError extends BaseError {
  constructor(
    resource: string = 'Resource',
    metadata?: Record<string, any>
  ) {
    super(
      `${resource} not found`,
      'NOT_FOUND',
      404,
      ErrorCategory.NOT_FOUND,
      ErrorLevel.INFO,
      { resource, ...metadata }
    );
  }

  protected override getSafeMessage(): string {
    return 'The requested resource was not found';
  }
}

// =============================================================================
// RATE LIMIT ERRORS
// =============================================================================

export class RateLimitExceededError extends BaseError {
  constructor(
    retryAfter?: number,
    metadata?: Record<string, any>
  ) {
    super(
      'Rate limit exceeded',
      'RATE_LIMIT_EXCEEDED',
      429,
      ErrorCategory.RATE_LIMIT,
      ErrorLevel.WARNING,
      { retryAfter, ...metadata }
    );
  }

  protected override getSafeMessage(): string {
    return 'Too many requests. Please try again later.';
  }
}

// =============================================================================
// DATABASE ERRORS
// =============================================================================

export class DatabaseError extends BaseError {
  constructor(
    message: string = 'Database error occurred',
    metadata?: Record<string, any>,
    innerError?: Error
  ) {
    super(
      message,
      'DATABASE_ERROR',
      500,
      ErrorCategory.DATABASE,
      ErrorLevel.ERROR,
      metadata,
      innerError
    );
  }

  protected override getSafeMessage(): string {
    return 'A database error occurred. Please try again later.';
  }
}

export class ConnectionError extends BaseError {
  constructor(
    service: string = 'Database',
    metadata?: Record<string, any>
  ) {
    super(
      `Connection to ${service} failed`,
      'CONNECTION_ERROR',
      503,
      ErrorCategory.DATABASE,
      ErrorLevel.CRITICAL,
      { service, ...metadata }
    );
  }

  protected override getSafeMessage(): string {
    return 'Unable to connect to the database. Please try again later.';
  }
}

// =============================================================================
// EXTERNAL SERVICE ERRORS
// =============================================================================

export class ExternalServiceError extends BaseError {
  constructor(
    serviceName: string,
    statusCode?: number,
    metadata?: Record<string, any>,
    innerError?: Error
  ) {
    super(
      `External service ${serviceName} returned an error`,
      'EXTERNAL_SERVICE_ERROR',
      statusCode || 502,
      ErrorCategory.EXTERNAL_SERVICE,
      ErrorLevel.ERROR,
      { serviceName, statusCode, ...metadata },
      innerError
    );
  }

  protected override getSafeMessage(): string {
    return 'An external service is unavailable. Please try again later.';
  }
}

export class TimeoutError extends BaseError {
  constructor(
    operation: string = 'Request',
    timeoutMs?: number,
    metadata?: Record<string, any>
  ) {
    super(
      `${operation} timed out after ${timeoutMs || 'unknown'}ms`,
      'TIMEOUT',
      504,
      ErrorCategory.SERVICE_UNAVAILABLE,
      ErrorLevel.ERROR,
      { operation, timeoutMs, ...metadata }
    );
  }

  protected override getSafeMessage(): string {
    return 'The request timed out. Please try again.';
  }
}

// =============================================================================
// INTERNAL ERROR
// =============================================================================

export class InternalError extends BaseError {
  constructor(
    message: string = 'Internal server error',
    metadata?: Record<string, any>,
    innerError?: Error
  ) {
    super(
      message,
      'INTERNAL_ERROR',
      500,
      ErrorCategory.INTERNAL,
      ErrorLevel.CRITICAL,
      metadata,
      innerError
    );
  }

  protected override getSafeMessage(): string {
    return 'An internal error occurred. Please try again later.';
  }
}

// =============================================================================
// ERROR FACTORY
// =============================================================================

export class ErrorFactory {
  /**
   * Создание ошибки из HTTP статуса
   */
  static fromStatusCode(statusCode: number, message?: string): BaseError {
    switch (statusCode) {
      case 400:
        return new ValidationError(message);
      case 401:
        return new AuthenticationError(message);
      case 403:
        return new AuthorizationError(message);
      case 404:
        return new NotFoundError();
      case 429:
        return new RateLimitExceededError();
      case 500:
        return new InternalError(message);
      case 502:
        return new ExternalServiceError('Unknown');
      case 503:
        return new ConnectionError();
      case 504:
        return new TimeoutError();
      default:
        return new InternalError(message || `HTTP ${statusCode}`);
    }
  }

  /**
   * Обёртка ошибки в BaseError
   */
  static wrap(error: unknown, context?: string): BaseError {
    if (error instanceof BaseError) {
      return error;
    }

    if (error instanceof Error) {
      return new InternalError(
        context ? `${context}: ${error.message}` : error.message,
        undefined,
        error
      );
    }

    return new InternalError(
      context || 'Unknown error occurred',
      { originalError: String(error) }
    );
  }
}

// =============================================================================
// ЭКСПОРТ
// =============================================================================
