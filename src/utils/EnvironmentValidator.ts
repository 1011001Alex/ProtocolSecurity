/**
 * =============================================================================
 * ENVIRONMENT VALIDATOR - ВАЛИДАЦИЯ ПЕРЕМЕННЫХ ОКРУЖЕНИЯ
 * =============================================================================
 * Комплексная система валидации секретов и переменных окружения
 *
 * Особенности:
 * - Проверка на дефолтные/слабые пароли
 * - Валидация формата секретов
 * - Проверка безопасности для production
 * - Детальное логирование проблем
 *
 * @author Theodor Munch
 * @license MIT
 * @version 1.0.0
 * =============================================================================
 */

import { logger } from '../logging/Logger';

// =============================================================================
// ТИПЫ И ИНТЕРФЕЙСЫ
// =============================================================================

/**
 * Результат валидации переменной окружения
 */
export interface ValidationIssue {
  /** Уровень серьезности */
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';

  /** Название переменной */
  variable: string;

  /** Тип проблемы */
  type: string;

  /** Сообщение об ошибке */
  message: string;

  /** Рекомендация по исправлению */
  recommendation: string;

  /** Текущее значение (замаскированное) */
  currentValue?: string;
}

/**
 * Результат валидации всего окружения
 */
export interface EnvironmentValidationResult {
  /** Успешно ли прошла валидация */
  isValid: boolean;

  /** Список проблем */
  issues: ValidationIssue[];

  /** Предупреждения */
  warnings: string[];

  /** Ошибки */
  errors: string[];

  /** Статус для production */
  isProductionReady: boolean;
}

/**
 * Конфигурация валидатора
 */
export interface EnvironmentValidatorConfig {
  /** Режим (development, staging, production) */
  nodeEnv: string;

  /** Блокировать запуск при критических ошибках */
  blockOnCritical: boolean;

  /** Логировать предупреждения */
  logWarnings: boolean;

  /** Минимальная длина пароля */
  minPasswordLength: number;

  /** Список запрещенных паролей */
  forbiddenPasswords: string[];

  /** Список запрещенных префиксов токенов */
  forbiddenTokenPrefixes: string[];
}

// =============================================================================
// КОНСТАНТЫ И ПАТТЕРНЫ
// =============================================================================

/**
 * Паттерны опасных/дефолтных паролей
 */
const DANGEROUS_PASSWORD_PATTERNS: RegExp[] = [
  /^change_?this_?/i,                    // change_this_password
  /^changeme$/i,                         // changeme
  /^password$/i,                         // password
  /^secret$/i,                           // secret
  /^admin$/i,                            // admin
  /^root$/i,                             // root
  /^test$/i,                             // test
  /^dev$/i,                              // dev
  /^default$/i,                          // default
  /^your_?/i,                            // your_password_here
  /^example$/i,                          // example
  /^demo$/i,                             // demo
  /^guest$/i,                            // guest
  /^user$/i,                             // user
  /^pass$/i,                             // pass
  /^qwerty$/i,                           // qwerty
  /^123456/i,                            // 123456
  /^letmein$/i,                          // letmein
  /^welcome$/i,                          // welcome
  /^monkey$/i,                           // monkey
  /^dragon$/i,                           // dragon
  /^master$/i,                           // master
  /^login$/i,                            // login
  /^abc/i,                               // abc123
  /^hello$/i,                            // hello
  /^shadow$/i,                           // shadow
  /^sunshine$/i,                         // sunshine
  /^princess$/i,                         // princess
  /^football$/i,                         // football
  /^iloveyou$/i,                         // iloveyou
  /^trustno1$/i,                         // trustno1
  /^superman$/i,                         // superman
  /^batman$/i,                           // batman
  /^starwars$/i                          // starwars
];

/**
 * Опасные префиксы токенов
 */
const DANGEROUS_TOKEN_PREFIXES: string[] = [
  'hvs.your',
  'hvs.example',
  'hvs.demo',
  'hvs.test',
  'your_',
  'example_',
  'demo_',
  'test_',
  'changeme',
  'replace_',
  'insert_',
  'put_'
];

/**
 * Паттерн валидного HVS токена HashiCorp Vault
 */
const VAULT_TOKEN_PATTERN = /^hvs\.[a-zA-Z0-9]{20,}$/;

/**
 * Паттерн валидного JWT
 */
const JWT_PATTERN = /^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*$/;

/**
 * Паттерн валидного URL webhook
 */
const WEBHOOK_URL_PATTERN = /^https:\/\/[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\/.*$/;

/**
 * Список критических переменных, которые должны быть установлены в production
 */
const CRITICAL_PRODUCTION_VARS: string[] = [
  'REDIS_PASSWORD',
  'VAULT_TOKEN',
  'ELASTICSEARCH_PASSWORD',
  'JWT_SECRET',
  'CRYPTO_KEY_ID'
];

/**
 * Список переменных с паролями
 */
const PASSWORD_VARS: string[] = [
  'REDIS_PASSWORD',
  'ELASTICSEARCH_PASSWORD',
  'JIRA_API_TOKEN',
  'PAGERDUTY_ROUTING_KEY'
];

/**
 * Список переменных с токенами
 */
const TOKEN_VARS: string[] = [
  'VAULT_TOKEN',
  'JIRA_API_TOKEN',
  'SLACK_WEBHOOK_URL'
];

// =============================================================================
// КЛАСС ENVIRONMENT VALIDATOR
// =============================================================================

/**
 * Валидатор переменных окружения и секретов
 */
export class EnvironmentValidator {
  /** Конфигурация */
  private config: EnvironmentValidatorConfig;

  /** Кэш результатов валидации */
  private validationCache: Map<string, ValidationIssue[]> = new Map();

  constructor(config?: Partial<EnvironmentValidatorConfig>) {
    this.config = {
      nodeEnv: process.env.NODE_ENV || 'development',
      blockOnCritical: config?.blockOnCritical ?? true,
      logWarnings: config?.logWarnings ?? true,
      minPasswordLength: config?.minPasswordLength ?? 20,
      forbiddenPasswords: config?.forbiddenPasswords ?? [],
      forbiddenTokenPrefixes: config?.forbiddenTokenPrefixes ?? DANGEROUS_TOKEN_PREFIXES
    };

    // Добавляем дефолтные запрещенные пароли
    this.config.forbiddenPasswords = [
      ...this.config.forbiddenPasswords,
      'change_this_password_in_production',
      'change_this_password',
      'change_this_password_before_production',
      'devpassword',
      'changeme',
      'password',
      'secret',
      'admin',
      'test',
      'dev',
      'default',
      'example',
      'demo'
    ];
  }

  // =============================================================================
  // ОСНОВНЫЕ МЕТОДЫ ВАЛИДАЦИИ
  // =============================================================================

  /**
   * Выполняет полную валидацию окружения
   */
  validateEnvironment(): EnvironmentValidationResult {
    const issues: ValidationIssue[] = [];
    const warnings: string[] = [];
    const errors: string[] = [];

    // Валидация всех критических переменных
    issues.push(...this.validateCriticalVariables());

    // Валидация паролей
    issues.push(...this.validatePasswords());

    // Валидация токенов
    issues.push(...this.validateTokens());

    // Валидация URL
    issues.push(...this.validateURLs());

    // Валидация специфичных настроек
    issues.push(...this.validateSpecificSettings());

    // Разделяем на warnings и errors
    for (const issue of issues) {
      if (issue.severity === 'critical' || issue.severity === 'high') {
        errors.push(`[${issue.variable}] ${issue.message}`);
      } else {
        warnings.push(`[${issue.variable}] ${issue.message}`);
      }
    }

    // Логирование через logger (не console)
    if (this.config.logWarnings && warnings.length > 0) {
      logger.warn('\n⚠️  ПРЕДУПРЕЖДЕНИЯ ВАЛИДАЦИИ ОКРУЖЕНИЯ:');
      warnings.forEach(w => logger.warn(`   ${w}`));
    }

    if (errors.length > 0 && this.config.logWarnings) {
      logger.error('\n❌ ОШИБКИ ВАЛИДАЦИИ ОКРУЖЕНИЯ:');
      errors.forEach(e => logger.error(`   ${e}`));
    }

    const isProduction = this.config.nodeEnv === 'production';
    const isProductionReady = errors.length === 0 && 
      !issues.some(i => i.severity === 'critical' && isProduction);

    return {
      isValid: errors.length === 0,
      issues,
      warnings,
      errors,
      isProductionReady
    };
  }

  /**
   * Валидирует критические переменные
   */
  private validateCriticalVariables(): ValidationIssue[] {
    const issues: ValidationIssue[] = [];
    const isProduction = this.config.nodeEnv === 'production';

    for (const varName of CRITICAL_PRODUCTION_VARS) {
      const value = process.env[varName];

      // Проверка наличия переменной в production
      if (isProduction && !value) {
        issues.push({
          severity: 'critical',
          variable: varName,
          type: 'MISSING_VARIABLE',
          message: `Критическая переменная отсутствует в production`,
          recommendation: `Установите переменную окружения ${varName} через secrets manager`,
          currentValue: undefined
        });
      }

      // Проверка на плейсхолдеры
      if (value && this.isPlaceholder(value)) {
        issues.push({
          severity: 'critical',
          variable: varName,
          type: 'PLACEHOLDER_VALUE',
          message: `Переменная содержит плейсхолдер вместо реального значения`,
          recommendation: `Замените плейсхолдер на реальное значение перед production deployment`,
          currentValue: this.maskValue(value)
        });
      }
    }

    return issues;
  }

  /**
   * Валидирует пароли
   */
  private validatePasswords(): ValidationIssue[] {
    const issues: ValidationIssue[] = [];

    for (const varName of PASSWORD_VARS) {
      const value = process.env[varName];
      if (!value) continue;

      // Проверка на запрещенные пароли
      if (this.isForbiddenPassword(value)) {
        issues.push({
          severity: 'critical',
          variable: varName,
          type: 'WEAK_PASSWORD',
          message: `Обнаружен дефолтный/слабый пароль`,
          recommendation: `Сгенерируйте криптографически стойкий пароль (мин. ${this.config.minPasswordLength} символов)`,
          currentValue: this.maskValue(value)
        });
      }

      // Проверка длины пароля (только warning для development)
      if (value.length < this.config.minPasswordLength) {
        const severity = this.config.nodeEnv === 'production' ? 'high' : 'medium';
        issues.push({
          severity,
          variable: varName,
          type: 'SHORT_PASSWORD',
          message: `Пароль слишком короткий (${value.length} < ${this.config.minPasswordLength})`,
          recommendation: `Увеличьте длину пароля до ${this.config.minPasswordLength}+ символов`,
          currentValue: this.maskValue(value)
        });
      }

      // Проверка на отсутствие специальных символов
      if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(value)) {
        issues.push({
          severity: 'low',
          variable: varName,
          type: 'NO_SPECIAL_CHARS',
          message: `Пароль не содержит специальных символов`,
          recommendation: `Добавьте специальные символы для увеличения стойкости`,
          currentValue: this.maskValue(value)
        });
      }
    }

    return issues;
  }

  /**
   * Валидирует токены
   */
  private validateTokens(): ValidationIssue[] {
    const issues: ValidationIssue[] = [];

    // Валидация VAULT_TOKEN
    const vaultToken = process.env.VAULT_TOKEN;
    if (vaultToken) {
      // Проверка на плейсхолдер
      if (this.isPlaceholder(vaultToken)) {
        issues.push({
          severity: 'critical',
          variable: 'VAULT_TOKEN',
          type: 'PLACEHOLDER_TOKEN',
          message: `Vault токен содержит плейсхолдер`,
          recommendation: `Сгенерируйте реальный Vault токен: vault token create -policy="your-policy"`,
          currentValue: this.maskValue(vaultToken)
        });
      }

      // Проверка формата HVS токена
      if (!vaultToken.startsWith('hvs.') && this.config.nodeEnv === 'production') {
        issues.push({
          severity: 'high',
          variable: 'VAULT_TOKEN',
          type: 'INVALID_TOKEN_FORMAT',
          message: `Vault токен должен начинаться с hvs.`,
          recommendation: `Используйте токен формата HashiCorp Vault (hvs.xxxxx)`,
          currentValue: this.maskValue(vaultToken)
        });
      }

      // Проверка на опасные префиксы
      if (this.hasDangerousPrefix(vaultToken)) {
        issues.push({
          severity: 'critical',
          variable: 'VAULT_TOKEN',
          type: 'DANGEROUS_TOKEN_PREFIX',
          message: `Токен содержит опасный префикс`,
          recommendation: `Замените токен на реальный, сгенерированный Vault`,
          currentValue: this.maskValue(vaultToken)
        });
      }
    }

    // Валидация других токенов
    for (const varName of TOKEN_VARS) {
      if (varName === 'VAULT_TOKEN') continue; // Уже проверили

      const value = process.env[varName];
      if (!value) continue;

      if (this.isPlaceholder(value)) {
        issues.push({
          severity: 'high',
          variable: varName,
          type: 'PLACEHOLDER_TOKEN',
          message: `Токен содержит плейсхолдер`,
          recommendation: `Замените плейсхолдер на реальное значение`,
          currentValue: this.maskValue(value)
        });
      }
    }

    return issues;
  }

  /**
   * Валидирует URL
   */
  private validateURLs(): ValidationIssue[] {
    const issues: ValidationIssue[] = [];

    // Валидация SLACK_WEBHOOK_URL
    const slackWebhook = process.env.SLACK_WEBHOOK_URL;
    
    // Проверка на плейсхолдеры и тестовые URL
    const placeholderPatterns = [
      'YOUR/WEBHOOK/URL',
      'REDACTED',
      'T00000000',
      'B00000000',
      'XXXXXXXXXXXXXXXXXXXXXXXX'
    ];
    
    const isPlaceholder = placeholderPatterns.some(pattern => slackWebhook?.includes(pattern));
    
    if (isPlaceholder) {
      issues.push({
        severity: 'high',
        variable: 'SLACK_WEBHOOK_URL',
        type: 'PLACEHOLDER_URL',
        message: `Webhook URL содержит плейсхолдер или тестовое значение`,
        recommendation: `Создайте webhook в Slack и замените URL`,
        currentValue: this.maskValue(slackWebhook || '')
      });
    } else if (slackWebhook && !WEBHOOK_URL_PATTERN.test(slackWebhook)) {
      issues.push({
        severity: 'medium',
        variable: 'SLACK_WEBHOOK_URL',
        type: 'INVALID_URL_FORMAT',
        message: `Webhook URL имеет неверный формат`,
        recommendation: `URL должен начинаться с https:// и содержать домен`,
        currentValue: this.maskValue(slackWebhook)
      });
    }

    // Валидация VAULT_URL
    const vaultUrl = process.env.VAULT_URL;
    if (vaultUrl && vaultUrl.includes('vault.local')) {
      issues.push({
        severity: 'medium',
        variable: 'VAULT_URL',
        type: 'LOCALHOST_URL',
        message: `Vault URL указывает на локальный хост`,
        recommendation: `Используйте production URL для Vault в production среде`,
        currentValue: vaultUrl
      });
    }

    return issues;
  }

  /**
   * Валидирует специфичные настройки
   */
  private validateSpecificSettings(): ValidationIssue[] {
    const issues: ValidationIssue[] = [];
    const isProduction = this.config.nodeEnv === 'production';

    // Проверка REDIS_TLS_ENABLED в production
    if (isProduction) {
      const redisTls = process.env.REDIS_TLS_ENABLED;
      if (redisTls && redisTls.toLowerCase() === 'false') {
        issues.push({
          severity: 'high',
          variable: 'REDIS_TLS_ENABLED',
          type: 'INSECURE_SETTING',
          message: `TLS для Redis отключен в production`,
          recommendation: `Включите TLS для шифрования трафика Redis`,
          currentValue: redisTls
        });
      }

      // Проверка MTLS_ENABLED
      const mtlsEnabled = process.env.MTLS_ENABLED;
      if (mtlsEnabled && mtlsEnabled.toLowerCase() === 'false') {
        issues.push({
          severity: 'medium',
          variable: 'MTLS_ENABLED',
          type: 'INSECURE_SETTING',
          message: `mTLS отключен в production`,
          recommendation: `Включите mTLS для Zero Trust архитектуры`,
          currentValue: mtlsEnabled
        });
      }

      // Проверка LOG_LEVEL
      const logLevel = process.env.LOG_LEVEL;
      if (logLevel && logLevel.toLowerCase() === 'debug') {
        issues.push({
          severity: 'low',
          variable: 'LOG_LEVEL',
          type: 'VERBOSE_LOGGING',
          message: `Debug логирование включено в production`,
          recommendation: `Установите LOG_LEVEL=warn или LOG_LEVEL=error`,
          currentValue: logLevel
        });
      }
    }

    return issues;
  }

  // =============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // =============================================================================

  /**
   * Проверяет, является ли значение плейсхолдером
   */
  private isPlaceholder(value: string): boolean {
    const placeholders = [
      'your_',
      'YOUR_',
      'example',
      'EXAMPLE',
      'changeme',
      'CHANGE_ME',
      'change_this',
      'CHANGE_THIS',
      'placeholder',
      'PLACEHOLDER',
      'xxx',
      'yyy',
      'zzz',
      'insert_',
      'INSERT_',
      'replace_',
      'REPLACE_',
      'generate_',
      'GENERATE_'
    ];

    const lowerValue = value.toLowerCase();
    return placeholders.some(ph => lowerValue.includes(ph.toLowerCase()));
  }

  /**
   * Проверяет, является ли пароль запрещенным
   */
  private isForbiddenPassword(password: string): boolean {
    const lowerPassword = password.toLowerCase();

    // Проверка по списку запрещенных
    if (this.config.forbiddenPasswords.includes(lowerPassword)) {
      return true;
    }

    // Проверка по паттернам
    for (const pattern of DANGEROUS_PASSWORD_PATTERNS) {
      if (pattern.test(password)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Проверяет, имеет ли токен опасный префикс
   */
  private hasDangerousPrefix(token: string): boolean {
    const lowerToken = token.toLowerCase();
    return this.config.forbiddenTokenPrefixes.some(prefix => 
      lowerToken.startsWith(prefix.toLowerCase())
    );
  }

  /**
   * Маскирует значение для безопасного логирования
   */
  private maskValue(value: string, visibleChars: number = 4): string {
    if (!value || value.length <= visibleChars) {
      return '***';
    }
    const visible = value.substring(0, visibleChars);
    const masked = '*'.repeat(value.length - visibleChars);
    return `${visible}${masked}`;
  }

  /**
   * Генерирует безопасный пароль
   */
  static generateSecurePassword(length: number = 32): string {
    const crypto = require('crypto');
    
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    const allChars = uppercase + lowercase + numbers + special;
    
    // Гарантируем наличие каждого типа символов
    let password = '';
    password += uppercase[crypto.randomInt(0, uppercase.length)];
    password += lowercase[crypto.randomInt(0, lowercase.length)];
    password += numbers[crypto.randomInt(0, numbers.length)];
    password += special[crypto.randomInt(0, special.length)];
    
    // Заполняем оставшуюся длину
    for (let i = password.length; i < length; i++) {
      password += allChars[crypto.randomInt(0, allChars.length)];
    }
    
    // Перемешиваем
    return password.split('').sort(() => crypto.randomInt(-1, 1)).join('');
  }

  /**
   * Генерирует команду для получения секрета из AWS Secrets Manager
   */
  static getAWSSecretCommand(secretName: string, region: string = 'us-east-1'): string {
    return `aws secretsmanager get-secret-value --secret-id ${secretName} --region ${region} --query SecretString --output text`;
  }

  /**
   * Генерирует команду для получения секрета из HashiCorp Vault
   */
  static getVaultSecretCommand(secretPath: string, key: string = 'value'): string {
    return `vault kv get -field=${key} ${secretPath}`;
  }

  /**
   * Генерирует команду для создания токена Vault
   */
  static getVaultTokenCommand(policy: string, ttl: string = '720h'): string {
    return `vault token create -policy="${policy}" -ttl=${ttl} -format=json | jq -r .auth.client_token`;
  }
}

// =============================================================================
// УТИЛИТЫ ДЛЯ БЫСТРОЙ ВАЛИДАЦИИ
// =============================================================================

/**
 * Быстрая валидация окружения с выводом результатов
 */
export function validateEnvironmentQuick(
  options: { 
    blockOnCritical?: boolean;
    logResults?: boolean;
  } = {}
): EnvironmentValidationResult {
  const validator = new EnvironmentValidator({
    blockOnCritical: options.blockOnCritical ?? true,
    logWarnings: options.logResults ?? true
  });

  const result = validator.validateEnvironment();

  if (options.logResults !== false) {
    if (result.isProductionReady) {
      console.log('\n✅ Окружение валидно для production\n');
    } else {
      console.error('\n❌ Окружение НЕ готово для production\n');
    }
  }

  return result;
}

/**
 * Выбрасывает ошибку если окружение не валидно для production
 */
export function assertProductionReady(): void {
  const validator = new EnvironmentValidator({
    blockOnCritical: true,
    logWarnings: true
  });

  const result = validator.validateEnvironment();

  if (!result.isProductionReady && process.env.NODE_ENV === 'production') {
    const errorMessages = result.errors.join('\n');
    throw new Error(
      `Production environment validation failed:\n${errorMessages}\n\n` +
      `Please fix these issues before deploying to production.`
    );
  }
}

// =============================================================================
// ЭКСПОРТ ПО УМОЛЧАНИЮ
// =============================================================================

export default EnvironmentValidator;
