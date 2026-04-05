/**
 * ============================================================================
 * INPUT VALIDATOR & SANITIZER - ВАЛИДАЦИЯ И САНИТИЗАЦИЯ ВХОДНЫХ ДАННЫХ
 * ============================================================================
 * Комплексная система валидации и защиты от injection атак
 * 
 * Особенности:
 * - Строгая типизация с TypeScript
 * - Защита от SQL/NoSQL injection
 * - Защита от XSS атак
 * - Защита от path traversal
 * - Защита от command injection
 * - Unicode normalization
 * - Rate limiting validation
 * - Schema validation
 */

import * as crypto from 'crypto';

/**
 * Типы валидации
 */
export enum ValidationType {
  STRING = 'STRING',
  NUMBER = 'NUMBER',
  BOOLEAN = 'BOOLEAN',
  EMAIL = 'EMAIL',
  URL = 'URL',
  IP = 'IP',
  UUID = 'UUID',
  DATE = 'DATE',
  PATH = 'PATH',
  FILENAME = 'FILENAME',
  JSON = 'JSON',
  JWT = 'JWT',
  API_KEY = 'API_KEY',
  PASSWORD = 'PASSWORD'
}

/**
 * Контекст валидации
 */
export interface ValidationContext {
  /** Поле */
  field: string;
  
  /** Значение */
  value: unknown;
  
  /** Тип валидации */
  type: ValidationType;
  
  /** Обязательно ли */
  required: boolean;
  
  /** Правила */
  rules?: ValidationRule[];
}

/**
 * Правило валидации
 */
export interface ValidationRule {
  /** Название правила */
  name: string;
  
  /** Параметры */
  params?: Record<string, unknown>;
  
  /** Сообщение об ошибке */
  message: string;
}

/**
 * Результат валидации
 */
export interface ValidationResult<T = unknown> {
  /** Успешно ли */
  valid: boolean;
  
  /** Валидированное значение */
  value?: T;
  
  /** Ошибки */
  errors: ValidationError[];
  
  /** Предупреждения */
  warnings: string[];
  
  /** Санитизированное значение */
  sanitized?: T;
}

/**
 * Ошибка валидации
 */
export class ValidationError extends Error {
  /** Поле */
  public readonly field: string;
  
  /** Код ошибки */
  public readonly code: string;
  
  /** Значение */
  public readonly value: unknown;
  
  constructor(field: string, code: string, message: string, value?: unknown) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
    this.code = code;
    this.value = value;
    
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ValidationError);
    }
  }
}

/**
 * Паттерны для детектирования атак
 */
const ATTACK_PATTERNS = {
  // SQL Injection паттерны
  sqlInjection: [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)/i,
    /(--|\#|\/\*|\*\/)/,
    /(\b(OR|AND)\b\s+\d+\s*=\s*\d+)/i,
    /('\s*(OR|AND)\s*')/i,
    /(;s*(DROP|DELETE|TRUNCATE|ALTER))/i,
    /(\bEXEC\b|\bEXECUTE\b)/i,
    /(xp_|sp_|fn_)/i,
    /(WAITFOR\s+DELAY)/i,
    /(BENCHMARK\s*\()/i,
    /(SLEEP\s*\()/i
  ],
  
  // XSS паттерны
  xss: [
    /<\s*script/i,
    /javascript\s*:/i,
    /on\w+\s*=/i,
    /<\s*img[^>]+onerror/i,
    /<\s*svg[^>]+onload/i,
    /<\s*iframe/i,
    /<\s*object/i,
    /<\s*embed/i,
    /<\s*form/i,
    /<\s*input[^>]+onfocus/i,
    /document\.(cookie|location|write)/i,
    /window\.(location|open)/i,
    /eval\s*\(/i,
    /alert\s*\(/i,
    /prompt\s*\(/i,
    /confirm\s*\(/i,
    /expression\s*\(/i,
    /vbscript\s*:/i,
    /data\s*:/i
  ],
  
  // Path traversal паттерны
  pathTraversal: [
    /\.\.\//,
    /\.\.\\/,
    /%2e%2e%2f/i,
    /%2e%2e%5c/i,
    /%252e%252e%252f/i,
    /\.\.%2f/i,
    /\.\.%5c/i,
    /%c0%ae\./i,
    /%c1%9c/i,
    /\.\.%255c/i,
    /\/etc\/passwd/i,
    /\/etc\/shadow/i,
    /\/proc\/self/i,
    /C:\\\\windows/i,
    /C:\\\\boot.ini/i
  ],
  
  // Command injection паттерны (более специфичные, чтобы не блокировать обычные символы)
  commandInjection: [
    /\$\([^)]+\)/,      // $() command substitution
    /`[^`]+`/,          // Backtick execution
    /;\s*(rm|cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|cmd|powershell|chmod|chown|mkdir|rmdir)\s/i,
    /\|\s*(rm|cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|cmd|powershell)\s/i,
    /&&\s*(rm|cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|cmd|powershell)\s/i,
    />\s*\/(?:etc|tmp|dev)/, // Redirection to sensitive paths
    /\b(cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|cmd|powershell|rm|chmod|chown)\s+[-\/]/i  // Commands with args
  ],
  
  // LDAP injection паттерны
  ldapInjection: [
    /[\(\)\*\\]/,
    /%28.*%29/,
    /%2[aA]/,
    /%5[cC]/,
    /\*%28.*\*\)/
  ],
  
  // NoSQL injection паттерны
  nosqlInjection: [
    /\{\s*\$/,
    /\[\s*\$/,
    /\$where/i,
    /\$ne/i,
    /\$gt/i,
    /\$lt/i,
    /\$regex/i,
    /\$or/i,
    /\$and/i,
    /\$exists/i,
    /\$type/i
  ]
};

/**
 * Универсальный валиидатор и санитизатор
 */
export class InputValidator {
  /** Максимальная длина строки по умолчанию */
  private static readonly DEFAULT_MAX_LENGTH = 10000;
  
  /** Разрешенные MIME типы для JSON */
  private static readonly ALLOWED_JSON_TYPES = [
    'application/json',
    'application/ld+json'
  ];
  
  /**
   * Валидация строки
   */
  static validateString(
    value: unknown,
    options: {
      minLength?: number;
      maxLength?: number;
      pattern?: RegExp;
      trim?: boolean;
      required?: boolean;
    } = {}
  ): ValidationResult<string> {
    const errors: ValidationError[] = [];
    const warnings: string[] = [];
    
    const {
      minLength = 0,
      maxLength = this.DEFAULT_MAX_LENGTH,
      pattern,
      trim = true,
      required = false
    } = options;
    
    // Проверка на null/undefined
    if (value === null || value === undefined) {
      if (required) {
        errors.push(new ValidationError('value', 'REQUIRED', 'Значение обязательно'));
      } else {
        return { valid: true, value: '', errors: [], warnings: [] };
      }
    }
    
    // Проверка типа
    if (typeof value !== 'string') {
      errors.push(new ValidationError('value', 'INVALID_TYPE', 'Ожидается строка', value));
      return { valid: false, errors, warnings: [] };
    }
    
    let sanitized = value;
    
    // Trim
    if (trim) {
      sanitized = sanitized.trim();
    }
    
    // Проверка длины
    if (sanitized.length < minLength) {
      errors.push(new ValidationError(
        'value',
        'TOO_SHORT',
        `Минимальная длина: ${minLength}`,
        sanitized
      ));
    }
    
    if (sanitized.length > maxLength) {
      errors.push(new ValidationError(
        'value',
        'TOO_LONG',
        `Максимальная длина: ${maxLength}`,
        sanitized
      ));
    }
    
    // Проверка паттерна
    if (pattern && !pattern.test(sanitized)) {
      errors.push(new ValidationError(
        'value',
        'PATTERN_MISMATCH',
        'Значение не соответствует паттерну',
        sanitized
      ));
    }
    
    // Проверка на injection атаки
    const injectionCheck = this.detectInjection(sanitized);
    if (injectionCheck.detected) {
      errors.push(new ValidationError(
        'value',
        'INJECTION_DETECTED',
        `Обнаружена injection атака: ${injectionCheck.types.join(', ')}`,
        sanitized
      ));
    }
    
    // Unicode normalization
    sanitized = this.normalizeUnicode(sanitized);
    
    return {
      valid: errors.length === 0,
      value: sanitized,
      sanitized,
      errors,
      warnings
    };
  }
  
  /**
   * Валидация email
   */
  static validateEmail(value: unknown): ValidationResult<string> {
    const errors: ValidationError[] = [];
    const warnings: string[] = [];
    
    if (typeof value !== 'string') {
      errors.push(new ValidationError('email', 'INVALID_TYPE', 'Ожидается строка', value));
      return { valid: false, errors, warnings: [] };
    }
    
    // RFC 5322 compliant regex (упрощенная версия)
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    
    const trimmed = value.trim().toLowerCase();
    
    if (!emailRegex.test(trimmed)) {
      errors.push(new ValidationError('email', 'INVALID_FORMAT', 'Неверный формат email', value));
    }
    
    // Проверка длины
    if (trimmed.length > 254) {
      errors.push(new ValidationError('email', 'TOO_LONG', 'Email слишком длинный', value));
    }
    
    // Проверка домена
    const domain = trimmed.split('@')[1];
    if (domain && !domain.includes('.')) {
      errors.push(new ValidationError('email', 'INVALID_DOMAIN', 'Неверный домен', value));
    }
    
    return {
      valid: errors.length === 0,
      value: trimmed,
      sanitized: trimmed,
      errors,
      warnings
    };
  }
  
  /**
   * Валидация URL
   */
  static validateURL(
    value: unknown,
    options: { allowedProtocols?: string[]; allowedHosts?: string[] } = {}
  ): ValidationResult<string> {
    const errors: ValidationError[] = [];
    const warnings: string[] = [];
    
    if (typeof value !== 'string') {
      errors.push(new ValidationError('url', 'INVALID_TYPE', 'Ожидается строка', value));
      return { valid: false, errors, warnings: [] };
    }
    
    const { allowedProtocols = ['https'], allowedHosts = [] } = options;
    
    let parsed: URL;
    
    try {
      parsed = new URL(value);
    } catch {
      errors.push(new ValidationError('url', 'INVALID_FORMAT', 'Неверный формат URL', value));
      return { valid: false, errors, warnings: [] };
    }
    
    // Проверка протокола
    if (!allowedProtocols.includes(parsed.protocol.replace(':', ''))) {
      errors.push(new ValidationError(
        'url',
        'INVALID_PROTOCOL',
        `Протокол должен быть: ${allowedProtocols.join(', ')}`,
        value
      ));
    }
    
    // Проверка host
    if (allowedHosts.length > 0 && !allowedHosts.includes(parsed.hostname)) {
      errors.push(new ValidationError(
        'url',
        'INVALID_HOST',
        'Host не в списке разрешенных',
        value
      ));
    }
    
    // Защита от SSRF
    if (this.isInternalHost(parsed.hostname)) {
      errors.push(new ValidationError(
        'url',
        'SSRF_DETECTED',
        'Внутренний хост запрещен',
        value
      ));
    }
    
    // Проверка на injection
    const injectionCheck = this.detectInjection(value);
    if (injectionCheck.detected) {
      errors.push(new ValidationError(
        'url',
        'INJECTION_DETECTED',
        'Обнаружена injection атака',
        value
      ));
    }
    
    return {
      valid: errors.length === 0,
      value: parsed.toString(),
      sanitized: parsed.toString(),
      errors,
      warnings
    };
  }
  
  /**
   * Валидация числа
   */
  static validateNumber(
    value: unknown,
    options: { min?: number; max?: number; integer?: boolean; required?: boolean } = {}
  ): ValidationResult<number> {
    const errors: ValidationError[] = [];
    const warnings: string[] = [];
    
    const { min, max, integer = false, required = false } = options;
    
    // Проверка на null/undefined
    if (value === null || value === undefined) {
      if (required) {
        errors.push(new ValidationError('value', 'REQUIRED', 'Значение обязательно'));
      } else {
        return { valid: true, value: 0, errors: [], warnings: [] };
      }
    }
    
    // Конвертация в число если строка
    let num: number;
    if (typeof value === 'string') {
      num = Number.parseFloat(value);
      if (Number.isNaN(num)) {
        errors.push(new ValidationError('value', 'INVALID_NUMBER', 'Не число', value));
        return { valid: false, errors, warnings: [] };
      }
    } else if (typeof value === 'number') {
      num = value;
    } else {
      errors.push(new ValidationError('value', 'INVALID_TYPE', 'Ожидается число', value));
      return { valid: false, errors, warnings: [] };
    }
    
    // Проверка NaN/Infinity
    if (!Number.isFinite(num)) {
      errors.push(new ValidationError('value', 'INVALID_NUMBER', 'Число должно быть конечным', value));
    }
    
    // Проверка диапазона
    if (min !== undefined && num < min) {
      errors.push(new ValidationError('value', 'TOO_SMALL', `Минимум: ${min}`, value));
    }
    
    if (max !== undefined && num > max) {
      errors.push(new ValidationError('value', 'TOO_LARGE', `Максимум: ${max}`, value));
    }
    
    // Проверка integer
    if (integer && !Number.isInteger(num)) {
      errors.push(new ValidationError('value', 'NOT_INTEGER', 'Ожидается целое число', value));
    }
    
    return {
      valid: errors.length === 0,
      value: num,
      sanitized: num,
      errors,
      warnings
    };
  }
  
  /**
   * Валидация IP адреса
   */
  static validateIP(value: unknown, version?: 4 | 6): ValidationResult<string> {
    const errors: ValidationError[] = [];
    const warnings: string[] = [];
    
    if (typeof value !== 'string') {
      errors.push(new ValidationError('ip', 'INVALID_TYPE', 'Ожидается строка', value));
      return { valid: false, errors, warnings: [] };
    }
    
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){0,6}::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$/;
    
    const trimmed = value.trim();
    
    if (version === 4) {
      if (!ipv4Regex.test(trimmed)) {
        errors.push(new ValidationError('ip', 'INVALID_IPV4', 'Неверный IPv4 адрес', value));
      }
    } else if (version === 6) {
      if (!ipv6Regex.test(trimmed)) {
        errors.push(new ValidationError('ip', 'INVALID_IPV6', 'Неверный IPv6 адрес', value));
      }
    } else {
      if (!ipv4Regex.test(trimmed) && !ipv6Regex.test(trimmed)) {
        errors.push(new ValidationError('ip', 'INVALID_IP', 'Неверный IP адрес', value));
      }
    }
    
    return {
      valid: errors.length === 0,
      value: trimmed,
      sanitized: trimmed,
      errors,
      warnings
    };
  }
  
  /**
   * Валидация UUID
   */
  static validateUUID(value: unknown, version?: 1 | 2 | 3 | 4 | 5): ValidationResult<string> {
    const errors: ValidationError[] = [];
    const warnings: string[] = [];
    
    if (typeof value !== 'string') {
      errors.push(new ValidationError('uuid', 'INVALID_TYPE', 'Ожидается строка', value));
      return { valid: false, errors, warnings: [] };
    }
    
    const uuidRegexes: Record<number, RegExp> = {
      1: /^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      2: /^[0-9a-f]{8}-[0-9a-f]{4}-2[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      3: /^[0-9a-f]{8}-[0-9a-f]{4}-3[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      4: /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
      5: /^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    };
    
    const trimmed = value.trim();
    const regex = version ? uuidRegexes[version] : uuidRegexes[4];
    
    if (!regex.test(trimmed)) {
      errors.push(new ValidationError('uuid', 'INVALID_UUID', 'Неверный UUID', value));
    }
    
    return {
      valid: errors.length === 0,
      value: trimmed.toLowerCase(),
      sanitized: trimmed.toLowerCase(),
      errors,
      warnings
    };
  }
  
  /**
   * Валидация пути к файлу
   */
  static validatePath(value: unknown, options: { allowAbsolute?: boolean; baseDir?: string } = {}): ValidationResult<string> {
    const errors: ValidationError[] = [];
    const warnings: string[] = [];
    
    const { allowAbsolute = false, baseDir } = options;
    
    if (typeof value !== 'string') {
      errors.push(new ValidationError('path', 'INVALID_TYPE', 'Ожидается строка', value));
      return { valid: false, errors, warnings: [] };
    }
    
    const trimmed = value.trim();
    
    // Проверка на path traversal
    if (trimmed.includes('..')) {
      errors.push(new ValidationError('path', 'PATH_TRAVERSAL', 'Path traversal запрещен', value));
    }
    
    // Проверка на absolute path
    if (!allowAbsolute && (trimmed.startsWith('/') || /^[a-zA-Z]:/.test(trimmed))) {
      errors.push(new ValidationError('path', 'ABSOLUTE_PATH', 'Absolute paths запрещены', value));
    }
    
    // Проверка на injection
    const injectionCheck = this.detectInjection(trimmed);
    if (injectionCheck.detected && injectionCheck.types.includes('pathTraversal')) {
      errors.push(new ValidationError('path', 'INJECTION_DETECTED', 'Обнаружена injection атака', value));
    }
    
    // Проверка baseDir
    if (baseDir && allowAbsolute) {
      const path = require('path');
      const resolved = path.resolve(trimmed);
      if (!resolved.startsWith(baseDir)) {
        errors.push(new ValidationError('path', 'OUTSIDE_BASE', 'Путь вне базовой директории', value));
      }
    }
    
    return {
      valid: errors.length === 0,
      value: trimmed,
      sanitized: trimmed,
      errors,
      warnings
    };
  }
  
  /**
   * Валидация JSON
   */
  static validateJSON(value: unknown, schema?: Record<string, unknown>): ValidationResult<Record<string, unknown>> {
    const errors: ValidationError[] = [];
    const warnings: string[] = [];
    
    if (typeof value === 'string') {
      try {
        value = JSON.parse(value);
      } catch (e) {
        errors.push(new ValidationError('json', 'INVALID_JSON', 'Неверный JSON формат', value));
        return { valid: false, errors, warnings: [] };
      }
    }
    
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      errors.push(new ValidationError('json', 'INVALID_TYPE', 'Ожидается объект', value));
      return { valid: false, errors, warnings: [] };
    }
    
    const obj = value as Record<string, unknown>;
    
    // Проверка схемы если указана
    if (schema) {
      const schemaErrors = this.validateSchema(obj, schema);
      errors.push(...schemaErrors);
    }
    
    // Проверка на injection в значениях
    for (const [key, val] of Object.entries(obj)) {
      if (typeof val === 'string') {
        const injectionCheck = this.detectInjection(val);
        if (injectionCheck.detected) {
          errors.push(new ValidationError(
            `json.${key}`,
            'INJECTION_DETECTED',
            `Обнаружена injection атака в поле ${key}`,
            val
          ));
        }
      }
    }
    
    return {
      valid: errors.length === 0,
      value: obj,
      sanitized: obj,
      errors,
      warnings
    };
  }
  
  /**
   * Валидация пароля
   */
  static validatePassword(
    value: unknown,
    options: {
      minLength?: number;
      requireUppercase?: boolean;
      requireLowercase?: boolean;
      requireNumbers?: boolean;
      requireSpecial?: boolean;
      maxLength?: number;
    } = {}
  ): ValidationResult<string> {
    const errors: ValidationError[] = [];
    const warnings: string[] = [];
    
    const {
      minLength = 12,
      maxLength = 128,
      requireUppercase = true,
      requireLowercase = true,
      requireNumbers = true,
      requireSpecial = true
    } = options;
    
    if (typeof value !== 'string') {
      errors.push(new ValidationError('password', 'INVALID_TYPE', 'Ожидается строка', value));
      return { valid: false, errors, warnings: [] };
    }
    
    // Проверка длины
    if (value.length < minLength) {
      errors.push(new ValidationError(
        'password',
        'TOO_SHORT',
        `Минимальная длина: ${minLength} символов`,
        value
      ));
    }
    
    if (value.length > maxLength) {
      errors.push(new ValidationError(
        'password',
        'TOO_LONG',
        `Максимальная длина: ${maxLength} символов`,
        value
      ));
    }
    
    // Проверка сложности
    if (requireUppercase && !/[A-Z]/.test(value)) {
      errors.push(new ValidationError('password', 'NO_UPPERCASE', 'Требуется хотя бы одна заглавная буква', value));
    }
    
    if (requireLowercase && !/[a-z]/.test(value)) {
      errors.push(new ValidationError('password', 'NO_LOWERCASE', 'Требуется хотя бы одна строчная буква', value));
    }
    
    if (requireNumbers && !/[0-9]/.test(value)) {
      errors.push(new ValidationError('password', 'NO_NUMBERS', 'Требуется хотя бы одна цифра', value));
    }
    
    if (requireSpecial && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(value)) {
      errors.push(new ValidationError('password', 'NO_SPECIAL', 'Требуется хотя бы один специальный символ', value));
    }
    
    // Проверка на распространенные пароли
    const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome'];
    if (commonPasswords.includes(value.toLowerCase())) {
      errors.push(new ValidationError('password', 'COMMON_PASSWORD', 'Пароль слишком распространенный', value));
    }
    
    return {
      valid: errors.length === 0,
      value,
      sanitized: value,
      errors,
      warnings
    };
  }
  
  /**
   * Детектирование injection атак
   */
  static detectInjection(value: string): {
    detected: boolean;
    types: string[];
    matches: Array<{ type: string; pattern: string }>;
  } {
    const types: string[] = [];
    const matches: Array<{ type: string; pattern: string }> = [];
    
    // SQL Injection
    for (const pattern of ATTACK_PATTERNS.sqlInjection) {
      if (pattern.test(value)) {
        if (!types.includes('sqlInjection')) {
          types.push('sqlInjection');
        }
        matches.push({ type: 'sqlInjection', pattern: pattern.source });
      }
    }
    
    // XSS
    for (const pattern of ATTACK_PATTERNS.xss) {
      if (pattern.test(value)) {
        if (!types.includes('xss')) {
          types.push('xss');
        }
        matches.push({ type: 'xss', pattern: pattern.source });
      }
    }
    
    // Path Traversal
    for (const pattern of ATTACK_PATTERNS.pathTraversal) {
      if (pattern.test(value)) {
        if (!types.includes('pathTraversal')) {
          types.push('pathTraversal');
        }
        matches.push({ type: 'pathTraversal', pattern: pattern.source });
      }
    }
    
    // Command Injection
    for (const pattern of ATTACK_PATTERNS.commandInjection) {
      if (pattern.test(value)) {
        if (!types.includes('commandInjection')) {
          types.push('commandInjection');
        }
        matches.push({ type: 'commandInjection', pattern: pattern.source });
      }
    }
    
    // LDAP Injection
    for (const pattern of ATTACK_PATTERNS.ldapInjection) {
      if (pattern.test(value)) {
        if (!types.includes('ldapInjection')) {
          types.push('ldapInjection');
        }
        matches.push({ type: 'ldapInjection', pattern: pattern.source });
      }
    }
    
    // NoSQL Injection
    for (const pattern of ATTACK_PATTERNS.nosqlInjection) {
      if (pattern.test(value)) {
        if (!types.includes('nosqlInjection')) {
          types.push('nosqlInjection');
        }
        matches.push({ type: 'nosqlInjection', pattern: pattern.source });
      }
    }
    
    return {
      detected: types.length > 0,
      types,
      matches
    };
  }
  
  /**
   * Санитизация строки
   */
  static sanitizeString(value: string): string {
    if (!value) return '';
    
    // Удаление control characters
    let sanitized = value.replace(/[\u0000-\u001F\u007F-\u009F]/g, '');
    
    // HTML entity encoding для защиты от XSS
    sanitized = sanitized
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
    
    // Unicode normalization
    sanitized = this.normalizeUnicode(sanitized);
    
    return sanitized;
  }
  
  /**
   * Unicode normalization
   */
  static normalizeUnicode(value: string): string {
    return value.normalize('NFKC');
  }
  
  /**
   * Проверка на внутренний хост (SSRF защита)
   */
  static isInternalHost(hostname: string): boolean {
    // localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
      return true;
    }
    
    // Private IP ranges
    const privateRanges = [
      /^10\./,                          // 10.0.0.0/8
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // 172.16.0.0/12
      /^192\.168\./,                    // 192.168.0.0/16
      /^169\.254\./,                    // 169.254.0.0/16
      /^fc00:/i,                        // fc00::/7 (IPv6)
      /^fe80:/i                         // fe80::/10 (link-local)
    ];
    
    return privateRanges.some(regex => regex.test(hostname));
  }
  
  /**
   * Валидация схемы объекта
   */
  private static validateSchema(obj: Record<string, unknown>, schema: Record<string, unknown>): ValidationError[] {
    const errors: ValidationError[] = [];
    
    for (const [key, rules] of Object.entries(schema)) {
      const rule = rules as any;
      const value = obj[key];
      
      // Required check
      if (rule.required && (value === undefined || value === null)) {
        errors.push(new ValidationError(key, 'REQUIRED', `Поле ${key} обязательно`));
        continue;
      }
      
      // Type check
      if (value !== undefined && rule.type) {
        const actualType = Array.isArray(value) ? 'array' : typeof value;
        if (actualType !== rule.type) {
          errors.push(new ValidationError(key, 'INVALID_TYPE', `Поле ${key} должно быть типа ${rule.type}`, value));
        }
      }
      
      // Min/max для чисел
      if (typeof value === 'number') {
        if (rule.min !== undefined && value < rule.min) {
          errors.push(new ValidationError(key, 'TOO_SMALL', `Поле ${key} должно быть >= ${rule.min}`, value));
        }
        if (rule.max !== undefined && value > rule.max) {
          errors.push(new ValidationError(key, 'TOO_LARGE', `Поле ${key} должно быть <= ${rule.max}`, value));
        }
      }
      
      // Min/max length для строк
      if (typeof value === 'string') {
        if (rule.minLength !== undefined && value.length < rule.minLength) {
          errors.push(new ValidationError(key, 'TOO_SHORT', `Поле ${key} должно быть >= ${rule.minLength} символов`, value));
        }
        if (rule.maxLength !== undefined && value.length > rule.maxLength) {
          errors.push(new ValidationError(key, 'TOO_LONG', `Поле ${key} должно быть <= ${rule.maxLength} символов`, value));
        }
      }
      
      // Pattern
      if (typeof value === 'string' && rule.pattern) {
        const regex = rule.pattern instanceof RegExp ? rule.pattern : new RegExp(rule.pattern);
        if (!regex.test(value)) {
          errors.push(new ValidationError(key, 'PATTERN_MISMATCH', `Поле ${key} не соответствует паттерну`, value));
        }
      }
      
      // Enum
      if (rule.enum && !rule.enum.includes(value)) {
        errors.push(new ValidationError(key, 'INVALID_ENUM', `Поле ${key} должно быть одним из: ${rule.enum.join(', ')}`, value));
      }
    }
    
    return errors;
  }
}

/**
 * Хелпер для хеширования чувствительных данных
 */
export function hashSensitiveData(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Маскирование чувствительных данных для логов
 */
export function maskSensitiveData(data: string, type: 'email' | 'phone' | 'card' | 'ssn' | 'default'): string {
  if (!data) return '';
  
  switch (type) {
    case 'email':
      const [local, domain] = data.split('@');
      if (!domain) return data;
      return `${local.substring(0, 2)}***@${domain}`;
    
    case 'phone':
      return data.replace(/(\d{2})\d{6,}(\d{2})/, '$1******$2');
    
    case 'card':
      return data.replace(/(\d{4})\d{8,}(\d{4})/, '$1********$2');
    
    case 'ssn':
      return data.replace(/(\d{3})\d{2,}(\d{4})/, '$1-**-$2');
    
    default:
      return data.length > 4
        ? `${data.substring(0, 2)}***${data.substring(data.length - 2)}`
        : '***';
  }
}
