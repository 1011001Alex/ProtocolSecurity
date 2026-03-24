/**
 * =============================================================================
 * INPUT VALIDATION MIDDLEWARE
 * =============================================================================
 * Комплексная система валидации входящих запросов с интеграцией InputValidator
 *
 * Особенности:
 * - Полная интеграция с существующим InputValidator.ts
 * - Валидация request body, query, params
 * - Schema validation (JSON Schema стиль)
 * - Rate limiting для валидации
 * - Автоматическая санитизация данных
 * - Защита от injection атак (SQL, XSS, Command, Path Traversal)
 * - Конфигурируемые правила валидации
 * - Детальное логирование ошибок
 * - Интеграция с Express middleware
 *
 * @author Theodor Munch
 * @license MIT
 * @version 1.0.0
 * =============================================================================
 */

import { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  InputValidator,
  ValidationType,
  ValidationResult,
  ValidationError,
  ValidationRule,
  ValidationContext,
  hashSensitiveData,
  maskSensitiveData
} from '../utils/InputValidator';
import { SecureLogger, LoggerFactory } from '../logging/Logger';
import { LogLevel, LogSource } from '../types/logging.types';

// =============================================================================
// ТИПЫ И ИНТЕРФЕЙСЫ
// =============================================================================

/**
 * Типы данных для валидации
 */
export type ValidationDataType = 'body' | 'query' | 'params' | 'headers';

/**
 * Схема валидации для поля
 */
export interface FieldSchema {
  /** Тип данных */
  type: ValidationType;

  /** Обязательно ли поле */
  required?: boolean;

  /** Минимальная длина (для строк) */
  minLength?: number;

  /** Максимальная длина (для строк) */
  maxLength?: number;

  /** Минимальное значение (для чисел) */
  min?: number;

  /** Максимальное значение (для чисел) */
  max?: number;

  /** Паттерн (RegExp для строк) */
  pattern?: string | RegExp;

  /** Дополнительные правила */
  rules?: ValidationRule[];

  /** Санитизировать ли значение */
  sanitize?: boolean;

  /** Сообщение об ошибке */
  message?: string;

  /** Значение по умолчанию */
  default?: unknown;

  /** Перечисление допустимых значений */
  enum?: unknown[];

  /** Вложенная схема (для объектов) */
  properties?: Record<string, FieldSchema>;

  /** Для email */
  allowedProtocols?: string[];
  allowedHosts?: string[];

  /** Для IP */
  ipVersion?: 4 | 6;

  /** Для UUID */
  uuidVersion?: 1 | 2 | 3 | 4 | 5;

  /** Для пути */
  allowAbsolutePath?: boolean;
  baseDir?: string;

  /** Для пароля */
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecial?: boolean;
}

/**
 * Схема валидации для всего запроса
 */
export interface ValidationSchema {
  /** Схема для body */
  body?: Record<string, FieldSchema>;

  /** Схема для query параметров */
  query?: Record<string, FieldSchema>;

  /** Схема для route параметров */
  params?: Record<string, FieldSchema>;

  /** Схема для headers */
  headers?: Record<string, FieldSchema>;
}

/**
 * Конфигурация middleware
 */
export interface InputValidationConfig {
  /** Включить строгий режим (блокировать при любых ошибках) */
  strictMode?: boolean;

  /** Максимальный размер body (в байтах) */
  maxBodySize?: number;

  /** Санитизировать HTML */
  sanitizeHTML?: boolean;

  /** Логировать ошибки валидации */
  logErrors?: boolean;

  /** Уровень логирования */
  logLevel?: LogLevel;

  /** Схема валидации */
  schema?: ValidationSchema;

  /** Пропускать ли определенные пути */
  skipPaths?: RegExp[];

  /** Пропускать ли определенные методы */
  skipMethods?: string[];

  /** Кастомный обработчик ошибок */
  errorHandler?: (errors: ValidationError[], req: Request) => {
    statusCode: number;
    body: unknown;
  };

  /** Включить rate limiting для валидации */
  enableRateLimit?: boolean;

  /** Максимальное количество запросов на валидацию в минуту */
  rateLimitMax?: number;

  /** Окно rate limiting (мс) */
  rateLimitWindowMs?: number;
}

/**
 * Результат валидации запроса
 */
export interface RequestValidationResult {
  /** Успешно ли */
  valid: boolean;

  /** Валидированные данные */
  data: {
    body?: unknown;
    query?: unknown;
    params?: unknown;
    headers?: unknown;
  };

  /** Ошибки */
  errors: ValidationError[];

  /** Предупреждения */
  warnings: string[];

  /** Санитизированные данные */
  sanitized: {
    body?: unknown;
    query?: unknown;
    params?: unknown;
    headers?: unknown;
  };
}

/**
 * Rate limit store для валидации
 */
interface RateLimitEntry {
  count: number;
  windowStart: number;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: Required<InputValidationConfig> = {
  strictMode: false,
  maxBodySize: 10 * 1024 * 1024, // 10 MB
  sanitizeHTML: true,
  logErrors: true,
  logLevel: LogLevel.WARNING,
  schema: {},
  skipPaths: [],
  skipMethods: ['GET', 'HEAD', 'OPTIONS'],
  errorHandler: defaultErrorHandler,
  enableRateLimit: false,
  rateLimitMax: 100,
  rateLimitWindowMs: 60000
};

/**
 * Хранилище rate limit для валидации
 */
const rateLimitStore: Map<string, RateLimitEntry> = new Map();

/**
 * Logger для middleware
 */
let cachedLogger: SecureLogger | null = null;

/**
 * Получает logger (singleton)
 */
function getLogger(): SecureLogger {
  if (!cachedLogger) {
    cachedLogger = LoggerFactory.getLogger(
      'InputValidationMiddleware',
      {
        level: LogLevel.INFO,
        transports: [{ type: 'console', params: {} }],
        enableColors: true,
        format: 'structured'
      },
      {
        environment: process.env.NODE_ENV || 'development',
        region: 'local',
        version: '1.0.0',
        serviceName: 'InputValidationMiddleware'
      }
    );
  }
  return cachedLogger;
}

/**
 * Обработчик ошибок по умолчанию
 */
function defaultErrorHandler(errors: ValidationError[]): { statusCode: number; body: unknown } {
  return {
    statusCode: 400,
    body: {
      error: 'Validation Error',
      message: 'Input validation failed',
      details: errors.map(err => ({
        field: err.field,
        code: err.code,
        message: err.message
      })),
      timestamp: new Date().toISOString()
    }
  };
}

// =============================================================================
// RATE LIMITING ДЛЯ ВАЛИДАЦИИ
// =============================================================================

/**
 * Проверка rate limit для валидации
 */
function checkRateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): { allowed: boolean; remaining: number; resetTime: number } {
  const now = Date.now();
  const entry = rateLimitStore.get(key);

  if (!entry || now - entry.windowStart > windowMs) {
    // Новое окно
    rateLimitStore.set(key, { count: 1, windowStart: now });
    return {
      allowed: true,
      remaining: maxRequests - 1,
      resetTime: now + windowMs
    };
  }

  // Существующее окно
  if (entry.count >= maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      resetTime: entry.windowStart + windowMs
    };
  }

  entry.count++;
  return {
    allowed: true,
    remaining: maxRequests - entry.count,
    resetTime: entry.windowStart + windowMs
  };
}

/**
 * Очистка устаревших записей rate limit
 */
function cleanupRateLimitStore(): void {
  const now = Date.now();
  const maxAge = 60 * 60 * 1000; // 1 час

  for (const [key, entry] of rateLimitStore.entries()) {
    if (now - entry.windowStart > maxAge) {
      rateLimitStore.delete(key);
    }
  }
}

// Запускаем очистку каждые 5 минут
setInterval(cleanupRateLimitStore, 5 * 60 * 1000);

// =============================================================================
// ФУНКЦИИ ВАЛИДАЦИИ
// =============================================================================

/**
 * Валидация одного поля согласно схеме
 */
function validateField(
  value: unknown,
  schema: FieldSchema,
  fieldName: string
): ValidationResult<unknown> {
  const errors: ValidationError[] = [];
  const warnings: string[] = [];

  // Проверка на required
  if (schema.required && (value === undefined || value === null)) {
    errors.push(new ValidationError(
      fieldName,
      'REQUIRED',
      schema.message || `Поле ${fieldName} обязательно`
    ));
    return { valid: false, errors, warnings: [] };
  }

  // Если не required и undefined/null - возвращаем default
  if (value === undefined || value === null) {
    if (schema.default !== undefined) {
      return {
        valid: true,
        value: schema.default,
        sanitized: schema.default,
        errors: [],
        warnings: []
      };
    }
    return { valid: true, value: null, sanitized: null, errors: [], warnings: [] };
  }

  // Валидация по типу
  let result: ValidationResult<unknown>;

  switch (schema.type) {
    case ValidationType.STRING:
      result = InputValidator.validateString(value, {
        minLength: schema.minLength,
        maxLength: schema.maxLength,
        pattern: schema.pattern instanceof RegExp ? schema.pattern : (schema.pattern ? new RegExp(schema.pattern) : undefined),
        trim: true,
        required: schema.required
      });
      break;

    case ValidationType.EMAIL:
      result = InputValidator.validateEmail(value);
      break;

    case ValidationType.URL:
      result = InputValidator.validateURL(value, {
        allowedProtocols: schema.allowedProtocols,
        allowedHosts: schema.allowedHosts
      });
      break;

    case ValidationType.NUMBER:
      result = InputValidator.validateNumber(value, {
        min: schema.min,
        max: schema.max,
        integer: schema.type === ValidationType.NUMBER,
        required: schema.required
      });
      break;

    case ValidationType.BOOLEAN:
      if (typeof value !== 'boolean') {
        if (value === 'true') {
          result = { valid: true, value: true, sanitized: true, errors: [], warnings: [] };
        } else if (value === 'false') {
          result = { valid: true, value: false, sanitized: false, errors: [], warnings: [] };
        } else {
          errors.push(new ValidationError(fieldName, 'INVALID_TYPE', 'Ожидается boolean', value));
          result = { valid: false, errors, warnings: [] };
        }
      } else {
        result = { valid: true, value, sanitized: value, errors: [], warnings: [] };
      }
      break;

    case ValidationType.IP:
      result = InputValidator.validateIP(value, schema.ipVersion);
      break;

    case ValidationType.UUID:
      result = InputValidator.validateUUID(value, schema.uuidVersion);
      break;

    case ValidationType.PATH:
      result = InputValidator.validatePath(value, {
        allowAbsolute: schema.allowAbsolutePath,
        baseDir: schema.baseDir
      });
      break;

    case ValidationType.PASSWORD:
      result = InputValidator.validatePassword(value, {
        minLength: schema.minLength,
        maxLength: schema.maxLength,
        requireUppercase: schema.requireUppercase,
        requireLowercase: schema.requireLowercase,
        requireNumbers: schema.requireNumbers,
        requireSpecial: schema.requireSpecial
      });
      break;

    case ValidationType.JSON:
      result = InputValidator.validateJSON(value);
      break;

    case ValidationType.DATE:
      if (typeof value !== 'string') {
        errors.push(new ValidationError(fieldName, 'INVALID_TYPE', 'Ожидается строка даты', value));
        result = { valid: false, errors, warnings: [] };
      } else {
        const date = new Date(value);
        if (isNaN(date.getTime())) {
          errors.push(new ValidationError(fieldName, 'INVALID_DATE', 'Неверный формат даты', value));
          result = { valid: false, errors, warnings: [] };
        } else {
          result = { valid: true, value, sanitized: date.toISOString(), errors: [], warnings: [] };
        }
      }
      break;

    case ValidationType.FILENAME:
      result = InputValidator.validateString(value, {
        pattern: /^[a-zA-Z0-9_\-.]+$/,
        maxLength: schema.maxLength || 255,
        required: schema.required
      });
      break;

    case ValidationType.JWT:
      // Базовая проверка формата JWT
      if (typeof value !== 'string' || !/^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/.test(value)) {
        errors.push(new ValidationError(fieldName, 'INVALID_JWT', 'Неверный формат JWT', value));
        result = { valid: false, errors, warnings: [] };
      } else {
        result = { valid: true, value, sanitized: value, errors: [], warnings: [] };
      }
      break;

    case ValidationType.API_KEY:
      result = InputValidator.validateString(value, {
        minLength: schema.minLength || 32,
        maxLength: schema.maxLength || 256,
        pattern: /^[a-zA-Z0-9_-]+$/,
        required: schema.required
      });
      break;

    default:
      // Для неизвестных типов - базовая строковая валидация
      result = InputValidator.validateString(String(value), {
        maxLength: schema.maxLength || 10000,
        required: schema.required
      });
  }

  // Проверка enum
  if (result.valid && schema.enum && !schema.enum.includes(result.value)) {
    errors.push(new ValidationError(
      fieldName,
      'INVALID_ENUM',
      schema.message || `Поле ${fieldName} должно быть одним из: ${schema.enum.join(', ')}`
    ));
    result.valid = false;
    result.errors = errors;
  }

  // Санитизация если включена
  if (result.valid && schema.sanitize && typeof result.value === 'string') {
    result.sanitized = InputValidator.sanitizeString(result.value as string);
  }

  return result;
}

/**
 * Валидация объекта по схеме
 */
function validateObject(
  data: Record<string, unknown>,
  schema: Record<string, FieldSchema>,
  parentField: string = ''
): { valid: boolean; validatedData: Record<string, unknown>; sanitizedData: Record<string, unknown>; errors: ValidationError[]; warnings: string[] } {
  const errors: ValidationError[] = [];
  const warnings: string[] = [];
  const validatedData: Record<string, unknown> = {};
  const sanitizedData: Record<string, unknown> = {};

  // Проверка всех полей схемы
  for (const [fieldName, fieldSchema] of Object.entries(schema)) {
    const fullFieldName = parentField ? `${parentField}.${fieldName}` : fieldName;
    const value = data[fieldName];

    // Если есть вложенная схема
    if (fieldSchema.properties && typeof value === 'object' && value !== null) {
      const nestedResult = validateObject(
        value as Record<string, unknown>,
        fieldSchema.properties,
        fullFieldName
      );

      if (!nestedResult.valid) {
        errors.push(...nestedResult.errors);
      }

      validatedData[fieldName] = nestedResult.validatedData;
      sanitizedData[fieldName] = nestedResult.sanitizedData;
      warnings.push(...nestedResult.warnings);
    } else {
      const result = validateField(value, fieldSchema, fullFieldName);

      if (!result.valid) {
        errors.push(...result.errors);
      } else {
        validatedData[fieldName] = result.value;
        sanitizedData[fieldName] = result.sanitized ?? result.value;
      }

      warnings.push(...result.warnings);
    }
  }

  // Проверка дополнительных полей не из схемы (в строгом режиме)
  if (data) {
    for (const key of Object.keys(data)) {
      if (!schema[key]) {
        warnings.push(`Неизвестное поле: ${parentField ? `${parentField}.${key}` : key}`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    validatedData,
    sanitizedData,
    errors,
    warnings
  };
}

/**
 * Валидация размера body
 */
function validateBodySize(req: Request, maxSize: number): boolean {
  const contentLength = req.headers['content-length'];
  if (contentLength) {
    const size = parseInt(contentLength, 10);
    if (!isNaN(size) && size > maxSize) {
      return false;
    }
  }

  // Проверка фактического размера body
  if (req.body && typeof req.body === 'object') {
    try {
      const bodySize = Buffer.byteLength(JSON.stringify(req.body), 'utf8');
      if (bodySize > maxSize) {
        return false;
      }
    } catch {
      // Игнорируем ошибки сериализации
    }
  }

  return true;
}

// =============================================================================
// MAIN MIDDLEWARE FUNCTION
// =============================================================================

/**
 * Создает middleware для валидации входных данных
 *
 * @param config - Конфигурация валидации
 * @returns Express middleware функция
 *
 * @example
 * ```typescript
 * // Простая валидация
 * app.post('/api/users',
 *   createInputValidationMiddleware({
 *     schema: {
 *       body: {
 *         email: { type: ValidationType.EMAIL, required: true },
 *         password: { type: ValidationType.PASSWORD, required: true, minLength: 12 }
 *       }
 *     }
 *   }),
 *   userController.create
 * );
 *
 * // Строгая валидация
 * app.post('/api/secure',
 *   createInputValidationMiddleware({
 *     strictMode: true,
 *     sanitizeHTML: true,
 *     schema: {
 *       body: {
 *         username: { type: ValidationType.STRING, required: true, minLength: 3, maxLength: 50 },
 *         data: { type: ValidationType.JSON, required: true }
 *       }
 *     }
 *   }),
 *   secureController.handle
 * );
 * ```
 */
export function createInputValidationMiddleware(config: InputValidationConfig = {}): RequestHandler {
  const mergedConfig: Required<InputValidationConfig> = {
    ...DEFAULT_CONFIG,
    ...config
  };

  const logger = mergedConfig.logErrors ? getLogger() : null;

  return (req: Request, res: Response, next: NextFunction): void => {
    const startTime = Date.now();

    try {
      // Проверка skip путей (в strictMode не пропускаем)
      if (!mergedConfig.strictMode && mergedConfig.skipPaths?.some(pattern => pattern.test(req.path))) {
        logger?.debug(
          `[InputValidation] Пропуск пути: ${req.path}`,
          LogSource.APPLICATION,
          'InputValidationMiddleware'
        );
        // Устанавливаем результат валидации для пропущенных путей
        const skipResult: RequestValidationResult = {
          valid: true,
          data: {},
          errors: [],
          warnings: [],
          sanitized: {}
        };
        (req as any).validationResult = skipResult;
        (req as any).sanitizedData = {};
        next();
        return;
      }

      // Проверка skip методов (в strictMode не пропускаем если есть schema)
      if (!mergedConfig.strictMode && mergedConfig.skipMethods?.includes(req.method)) {
        logger?.debug(
          `[InputValidation] Пропуск метода: ${req.method}`,
          LogSource.APPLICATION,
          'InputValidationMiddleware'
        );
        // Устанавливаем результат валидации для пропущенных методов
        const skipResult: RequestValidationResult = {
          valid: true,
          data: {},
          errors: [],
          warnings: [],
          sanitized: {}
        };
        (req as any).validationResult = skipResult;
        (req as any).sanitizedData = {};
        next();
        return;
      }

      // Проверка размера body
      if (!validateBodySize(req, mergedConfig.maxBodySize)) {
        const error = new ValidationError(
          'body',
          'TOO_LARGE',
          `Размер запроса превышает максимальный (${mergedConfig.maxBodySize} байт)`
        );

        logger?.warning(
          `[InputValidation] Превышен размер body: ${req.path}`,
          LogSource.SECURITY,
          'InputValidationMiddleware'
        );

        const errorResponse = mergedConfig.errorHandler([error], req);
        res.status(errorResponse.statusCode).json(errorResponse.body);
        return;
      }

      // Проверка rate limit
      if (mergedConfig.enableRateLimit) {
        const clientKey = req.ip || req.socket.remoteAddress || 'unknown';
        const rateLimitResult = checkRateLimit(
          clientKey,
          mergedConfig.rateLimitMax,
          mergedConfig.rateLimitWindowMs
        );

        if (!rateLimitResult.allowed) {
          logger?.warning(
            `[InputValidation] Rate limit превышен для ${clientKey}`,
            LogSource.SECURITY,
            'InputValidationMiddleware'
          );

          res.status(429).json({
            error: 'Too Many Requests',
            message: 'Превышен лимит запросов на валидацию',
            retryAfter: Math.ceil((rateLimitResult.resetTime - Date.now()) / 1000),
            timestamp: new Date().toISOString()
          });
          return;
        }

        // Установка заголовков rate limit
        res.setHeader('X-RateLimit-Limit', mergedConfig.rateLimitMax.toString());
        res.setHeader('X-RateLimit-Remaining', rateLimitResult.remaining.toString());
        res.setHeader('X-RateLimit-Reset', Math.ceil(rateLimitResult.resetTime / 1000).toString());
      }

      // Если нет схемы - пропускаем
      if (!mergedConfig.schema || Object.keys(mergedConfig.schema).length === 0) {
        logger?.debug(
          `[InputValidation] Нет схемы, пропуск: ${req.path}`,
          LogSource.APPLICATION,
          'InputValidationMiddleware'
        );
        // Устанавливаем пустой результат валидации
        const emptyResult: RequestValidationResult = {
          valid: true,
          data: {},
          errors: [],
          warnings: [],
          sanitized: {}
        };
        (req as any).validationResult = emptyResult;
        (req as any).sanitizedData = {};
        next();
        return;
      }

      // Валидация
      const result: RequestValidationResult = {
        valid: true,
        data: {},
        errors: [],
        warnings: [],
        sanitized: {}
      };

      // Валидация body
      if (mergedConfig.schema.body && req.body) {
        const bodyResult = validateObject(req.body, mergedConfig.schema.body, 'body');
        if (!bodyResult.valid) {
          result.valid = false;
          result.errors.push(...bodyResult.errors);
        }
        result.data.body = bodyResult.validatedData;
        result.sanitized.body = bodyResult.sanitizedData;
        result.warnings.push(...bodyResult.warnings);
      }

      // Валидация query
      if (mergedConfig.schema.query && req.query) {
        const queryResult = validateObject(req.query as Record<string, unknown>, mergedConfig.schema.query, 'query');
        if (!queryResult.valid) {
          result.valid = false;
          result.errors.push(...queryResult.errors);
        }
        result.data.query = queryResult.validatedData;
        result.sanitized.query = queryResult.sanitizedData;
        result.warnings.push(...queryResult.warnings);
      }

      // Валидация params
      if (mergedConfig.schema.params && req.params) {
        const paramsResult = validateObject(req.params, mergedConfig.schema.params, 'params');
        if (!paramsResult.valid) {
          result.valid = false;
          result.errors.push(...paramsResult.errors);
        }
        result.data.params = paramsResult.validatedData;
        result.sanitized.params = paramsResult.sanitizedData;
        result.warnings.push(...paramsResult.warnings);
      }

      // Валидация headers
      if (mergedConfig.schema.headers && req.headers) {
        const headersResult = validateObject(req.headers, mergedConfig.schema.headers, 'headers');
        if (!headersResult.valid) {
          result.valid = false;
          result.errors.push(...headersResult.errors);
        }
        result.data.headers = headersResult.validatedData;
        result.sanitized.headers = headersResult.sanitizedData;
        result.warnings.push(...headersResult.warnings);
      }

      // Логирование предупреждений
      if (result.warnings.length > 0 && logger) {
        logger.warning(
          `[InputValidation] Предупреждения: ${result.warnings.join('; ')}`,
          LogSource.APPLICATION,
          'InputValidationMiddleware'
        );
      }

      // Вычисляем duration
      const duration = Date.now() - startTime;

      // Обработка ошибок
      if (!result.valid) {
        logger?.warning(
          `[InputValidation] Валидация не пройдена (${duration}ms): ${req.method} ${req.path}, ошибок: ${result.errors.length}`,
          LogSource.SECURITY,
          'InputValidationMiddleware',
          undefined,
          {
            method: req.method,
            path: req.path,
            errorCount: result.errors.length,
            errors: result.errors.map(e => ({ field: e.field, code: e.code }))
          }
        );

        // Добавление результатов валидации в request ПЕРЕД обработкой ошибок
        (req as any).validationResult = result;
        (req as any).sanitizedData = result.sanitized;

        if (mergedConfig.strictMode) {
          const errorResponse = mergedConfig.errorHandler(result.errors, req);
          res.status(errorResponse.statusCode).json(errorResponse.body);
          return;
        }
      }

      // Добавление результатов валидации в request
      (req as any).validationResult = result;
      (req as any).sanitizedData = result.sanitized;

      logger?.debug(
        `[InputValidation] Валидация пройдена (${duration}ms): ${req.method} ${req.path}`,
        LogSource.APPLICATION,
        'InputValidationMiddleware'
      );

      next();

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      const duration = Date.now() - startTime;

      logger?.error(
        `[InputValidation] Критическая ошибка валидации (${duration}ms): ${errorMessage}`,
        LogSource.APPLICATION,
        'InputValidationMiddleware',
        undefined,
        undefined,
        error as Error
      );

      // В случае ошибки - пропускаем запрос (fail open) если не strict mode
      if (mergedConfig.strictMode) {
        const validationError = new ValidationError(
          'system',
          'VALIDATION_ERROR',
          'Внутренняя ошибка валидации'
        );
        const errorResponse = mergedConfig.errorHandler([validationError], req);
        res.status(errorResponse.statusCode).json(errorResponse.body);
        return;
      }

      next();
    }
  };
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Получает валидированные данные из request
 *
 * @param req - Express request
 * @param type - Тип данных (body, query, params, headers)
 * @returns Валидированные данные или undefined
 *
 * @example
 * ```typescript
 * app.post('/api/users',
 *   createInputValidationMiddleware({ schema: {...} }),
 *   (req, res) => {
 *     const validatedBody = getValidatedData(req, 'body');
 *     const sanitizedQuery = getSanitizedData(req, 'query');
 *     // ...
 *   }
 * );
 * ```
 */
export function getValidatedData<T = unknown>(req: Request, type: ValidationDataType): T | undefined {
  const result = (req as any).validationResult as RequestValidationResult | undefined;
  if (!result || !result.data[type]) {
    return undefined;
  }
  return result.data[type] as T;
}

/**
 * Получает санитизированные данные из request
 *
 * @param req - Express request
 * @param type - Тип данных (body, query, params, headers)
 * @returns Санитизированные данные или undefined
 */
export function getSanitizedData<T = unknown>(req: Request, type: ValidationDataType): T | undefined {
  const result = (req as any).validationResult as RequestValidationResult | undefined;
  if (!result || !result.sanitized[type]) {
    return undefined;
  }
  return result.sanitized[type] as T;
}

/**
 * Проверяет успешность валидации
 *
 * @param req - Express request
 * @returns true если валидация пройдена
 */
export function isValidated(req: Request): boolean {
  const result = (req as any).validationResult as RequestValidationResult | undefined;
  return result?.valid ?? false;
}

/**
 * Получает ошибки валидации
 *
 * @param req - Express request
 * @returns Массив ошибок или пустой массив
 */
export function getValidationErrors(req: Request): ValidationError[] {
  const result = (req as any).validationResult as RequestValidationResult | undefined;
  return result?.errors ?? [];
}

/**
 * Создает схему валидации для типичных случаев
 */
export function createValidationSchema(
  fields: Record<string, FieldSchema>,
  options: {
    validateBody?: boolean;
    validateQuery?: boolean;
    validateParams?: boolean;
    validateHeaders?: boolean;
  } = {}
): ValidationSchema {
  const {
    validateBody = true,
    validateQuery = false,
    validateParams = false,
    validateHeaders = false
  } = options;

  const schema: ValidationSchema = {};

  if (validateBody) {
    schema.body = fields;
  }

  if (validateQuery) {
    schema.query = fields;
  }

  if (validateParams) {
    schema.params = fields;
  }

  if (validateHeaders) {
    schema.headers = fields;
  }

  return schema;
}

/**
 * Пресеты для типичных сценариев валидации
 */
export const ValidationPresets = {
  /**
   * Валидация для регистрации пользователя
   */
  userRegistration: {
    body: {
      email: { type: ValidationType.EMAIL, required: true, maxLength: 254 },
      password: {
        type: ValidationType.PASSWORD,
        required: true,
        minLength: 12,
        maxLength: 128,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecial: true
      },
      username: { type: ValidationType.STRING, required: true, minLength: 3, maxLength: 50, pattern: /^[a-zA-Z0-9_]+$/ }
    }
  } as ValidationSchema,

  /**
   * Валидация для аутентификации
   */
  authentication: {
    body: {
      email: { type: ValidationType.EMAIL, required: true },
      password: { type: ValidationType.STRING, required: true, minLength: 8, maxLength: 128 }
    }
  } as ValidationSchema,

  /**
   * Валидация для поиска/фильтрации
   */
  search: {
    query: {
      q: { type: ValidationType.STRING, required: false, minLength: 1, maxLength: 500, sanitize: true },
      page: { type: ValidationType.NUMBER, required: false, min: 1, max: 10000, default: 1 },
      limit: { type: ValidationType.NUMBER, required: false, min: 1, max: 100, default: 20 },
      sort: { type: ValidationType.STRING, required: false, maxLength: 50, pattern: /^[a-zA-Z0-9_.,-]+$/ },
      order: { type: ValidationType.STRING, required: false, enum: ['asc', 'desc'], default: 'asc' }
    }
  } as ValidationSchema,

  /**
   * Валидация для UUID параметров
   */
  uuidParams: {
    params: {
      id: { type: ValidationType.UUID, required: true, uuidVersion: 4 }
    }
  } as ValidationSchema,

  /**
   * Валидация для pagination
   */
  pagination: {
    query: {
      page: { type: ValidationType.NUMBER, required: false, min: 1, max: 10000, default: 1 },
      limit: { type: ValidationType.NUMBER, required: false, min: 1, max: 100, default: 20 },
      offset: { type: ValidationType.NUMBER, required: false, min: 0, default: 0 }
    }
  } as ValidationSchema,

  /**
   * Строгая валидация для API ключей
   */
  apiKeyAuth: {
    headers: {
      'x-api-key': { type: ValidationType.API_KEY, required: true, minLength: 32, maxLength: 256 }
    }
  } as ValidationSchema,

  /**
   * Валидация для file upload metadata
   */
  fileUpload: {
    body: {
      filename: { type: ValidationType.FILENAME, required: true, maxLength: 255 },
      description: { type: ValidationType.STRING, required: false, maxLength: 1000, sanitize: true },
      tags: { type: ValidationType.JSON, required: false }
    }
  } as ValidationSchema,

  /**
   * Валидация для webhook payload
   */
  webhook: {
    body: {
      event: { type: ValidationType.STRING, required: true, maxLength: 100, pattern: /^[a-zA-Z0-9_.]+$/ },
      data: { type: ValidationType.JSON, required: true },
      timestamp: { type: ValidationType.DATE, required: true },
      signature: { type: ValidationType.STRING, required: true, pattern: /^[a-fA-F0-9]{64}$/ }
    }
  } as ValidationSchema
};

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  createInputValidationMiddleware,
  getValidatedData,
  getSanitizedData,
  isValidated,
  getValidationErrors,
  createValidationSchema,
  ValidationPresets
};
