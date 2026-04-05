/**
 * =============================================================================
 * ENVIRONMENT VALIDATOR TESTS
 * =============================================================================
 * Тесты для системы валидации переменных окружения и секретов
 *
 * @author Theodor Munch
 * @license MIT
 * @version 1.0.0
 * =============================================================================
 */

import {
  EnvironmentValidator,
  validateEnvironmentQuick,
  assertProductionReady,
  EnvironmentValidationResult,
  ValidationIssue
} from '../../src/utils/EnvironmentValidator';

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Сохраняет текущие переменные окружения
 */
function saveEnvironment(): Record<string, string | undefined> {
  return {
    NODE_ENV: process.env.NODE_ENV,
    REDIS_PASSWORD: process.env.REDIS_PASSWORD,
    VAULT_TOKEN: process.env.VAULT_TOKEN,
    ELASTICSEARCH_PASSWORD: process.env.ELASTICSEARCH_PASSWORD,
    SLACK_WEBHOOK_URL: process.env.SLACK_WEBHOOK_URL,
    JIRA_API_TOKEN: process.env.JIRA_API_TOKEN,
    REDIS_TLS_ENABLED: process.env.REDIS_TLS_ENABLED,
    MTLS_ENABLED: process.env.MTLS_ENABLED,
    LOG_LEVEL: process.env.LOG_LEVEL,
    VAULT_URL: process.env.VAULT_URL
  };
}

/**
 * Восстанавливает переменные окружения
 */
function restoreEnvironment(env: Record<string, string | undefined>) {
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
}

/**
 * Устанавливает тестовые переменные окружения
 */
function setTestEnvironment(overrides: Record<string, string> = {}) {
  const baseEnv: Record<string, string> = {
    NODE_ENV: 'test',
    REDIS_PASSWORD: 'testpassword',
    VAULT_TOKEN: 'hvs.testtoken12345678901234567890',
    ELASTICSEARCH_PASSWORD: 'testpassword123',
    // CodeQL: Тестовый URL (не реальный webhook)
    SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/TEST/BOT/TESTWEBHOOKTOKEN',
    JIRA_API_TOKEN: 'jira_test_token_12345678901234567890',
    REDIS_TLS_ENABLED: 'true',
    MTLS_ENABLED: 'true',
    LOG_LEVEL: 'warn',
    VAULT_URL: 'https://vault.test.local:8200',
    JWT_SECRET: 'test-jwt-secret-key-for-testing-only-very-long-string',
    CRYPTO_KEY_ID: 'test-crypto-key-id-12345678901234567890',
    ...overrides
  };

  for (const [key, value] of Object.entries(baseEnv)) {
    process.env[key] = value;
  }
}

// =============================================================================
// ENVIRONMENT VALIDATOR CLASS TESTS
// =============================================================================

describe('EnvironmentValidator', () => {
  let originalEnv: Record<string, string | undefined>;
  let validator: EnvironmentValidator;

  beforeEach(() => {
    originalEnv = saveEnvironment();
    setTestEnvironment();
    validator = new EnvironmentValidator({
      nodeEnv: 'test',
      blockOnCritical: false,
      logWarnings: false
    });
  });

  afterEach(() => {
    restoreEnvironment(originalEnv);
    jest.clearAllMocks();
  });

  // =============================================================================
  // CREATION TESTS
  // =============================================================================

  describe('Creation', () => {
    it('должен создавать валидатор с конфигурацией по умолчанию', () => {
      expect(validator).toBeDefined();
      expect(validator).toBeInstanceOf(EnvironmentValidator);
    });

    it('должен создавать валидатор с кастомной конфигурацией', () => {
      const customValidator = new EnvironmentValidator({
        nodeEnv: 'production',
        minPasswordLength: 40,
        blockOnCritical: true
      });

      expect(customValidator).toBeDefined();
    });
  });

  // =============================================================================
  // PASSWORD VALIDATION TESTS
  // =============================================================================

  describe('Password Validation', () => {
    it('должен обнаруживать дефолтный пароль "change_this_password"', () => {
      setTestEnvironment({ REDIS_PASSWORD: 'change_this_password_in_production' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const passwordIssue = result.issues.find(
        i => i.variable === 'REDIS_PASSWORD' && i.type === 'WEAK_PASSWORD'
      );
      expect(passwordIssue).toBeDefined();
      expect(passwordIssue?.severity).toBe('critical');
    });

    it('должен обнаруживать пароль "changeme"', () => {
      setTestEnvironment({ ELASTICSEARCH_PASSWORD: 'changeme' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const passwordIssue = result.issues.find(
        i => i.variable === 'ELASTICSEARCH_PASSWORD' && i.type === 'WEAK_PASSWORD'
      );
      expect(passwordIssue).toBeDefined();
    });

    it('должен обнаруживать пароль "password"', () => {
      setTestEnvironment({ REDIS_PASSWORD: 'password' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const passwordIssue = result.issues.find(
        i => i.variable === 'REDIS_PASSWORD' && i.type === 'WEAK_PASSWORD'
      );
      expect(passwordIssue).toBeDefined();
    });

    it('должен обнаруживать пароль "devpassword"', () => {
      setTestEnvironment({ REDIS_PASSWORD: 'devpassword' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const passwordIssue = result.issues.find(
        i => i.variable === 'REDIS_PASSWORD' && i.type === 'WEAK_PASSWORD'
      );
      expect(passwordIssue).toBeDefined();
    });

    it('должен пропускать стойкий пароль', () => {
      setTestEnvironment({ 
        REDIS_PASSWORD: 'xK9#mP2$vL5@nQ8!wR3&jT6*hY0^cF4%' 
      });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const passwordIssue = result.issues.find(
        i => i.variable === 'REDIS_PASSWORD' && i.type === 'WEAK_PASSWORD'
      );
      expect(passwordIssue).toBeUndefined();
    });

    it('должен предупреждать о коротком пароле', () => {
      setTestEnvironment({ REDIS_PASSWORD: 'short123' });
      validator = new EnvironmentValidator({ 
        logWarnings: false,
        minPasswordLength: 20
      });

      const result = validator.validateEnvironment();

      const shortPasswordIssue = result.issues.find(
        i => i.variable === 'REDIS_PASSWORD' && i.type === 'SHORT_PASSWORD'
      );
      expect(shortPasswordIssue).toBeDefined();
      expect(shortPasswordIssue?.severity).toBe('medium');
    });
  });

  // =============================================================================
  // TOKEN VALIDATION TESTS
  // =============================================================================

  describe('Token Validation', () => {
    it('должен обнаруживать плейсхолдер Vault токена', () => {
      setTestEnvironment({ VAULT_TOKEN: 'hvs.your_vault_token_here' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const tokenIssue = result.issues.find(
        i => i.variable === 'VAULT_TOKEN' && i.type === 'PLACEHOLDER_TOKEN'
      );
      expect(tokenIssue).toBeDefined();
      expect(tokenIssue?.severity).toBe('critical');
    });

    it('должен обнаруживать опасный префикс токена', () => {
      setTestEnvironment({ VAULT_TOKEN: 'hvs.example_token_12345678901234567890' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const tokenIssue = result.issues.find(
        i => i.variable === 'VAULT_TOKEN' && i.type === 'DANGEROUS_TOKEN_PREFIX'
      );
      expect(tokenIssue).toBeDefined();
    });

    it('должен пропускать валидный Vault токен', () => {
      setTestEnvironment({ VAULT_TOKEN: 'hvs.aBcDeFgHiJkLmNoPqRsTuVwXyZ123456' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const tokenIssues = result.issues.filter(
        i => i.variable === 'VAULT_TOKEN'
      );
      expect(tokenIssues.length).toBe(0);
    });

    it('должен обнаруживать плейсхолдер Slack webhook', () => {
      setTestEnvironment({ SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const webhookIssue = result.issues.find(
        i => i.variable === 'SLACK_WEBHOOK_URL' && i.type === 'PLACEHOLDER_URL'
      );
      expect(webhookIssue).toBeDefined();
    });
  });

  // =============================================================================
  // PRODUCTION VALIDATION TESTS
  // =============================================================================

  describe('Production Validation', () => {
    it('должен блокировать запуск с дефолтными паролями в production', () => {
      setTestEnvironment({ 
        NODE_ENV: 'production',
        REDIS_PASSWORD: 'change_this_password'
      });
      validator = new EnvironmentValidator({ 
        nodeEnv: 'production',
        logWarnings: false 
      });

      const result = validator.validateEnvironment();

      expect(result.isProductionReady).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('должен пропускать запуск с валидными секретами в production', () => {
      setTestEnvironment({
        NODE_ENV: 'production',
        REDIS_PASSWORD: 'xK9#mP2$vL5@nQ8!wR3&jT6*hY0^cF4%',
        VAULT_TOKEN: 'hvs.aBcDeFgHiJkLmNoPqRsTuVwXyZ123456',
        ELASTICSEARCH_PASSWORD: 'yL0@nP3$qM6#rK9!vS4&kW7^dG2%hT5',
        SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx',
        JIRA_API_TOKEN: 'jira_prod_token_12345678901234567890'
      });
      validator = new EnvironmentValidator({
        nodeEnv: 'production',
        logWarnings: false
      });

      const result = validator.validateEnvironment();

      expect(result.isProductionReady).toBe(true);
      expect(result.errors.length).toBe(0);
    });

    it('должен требовать TLS для Redis в production', () => {
      setTestEnvironment({ 
        NODE_ENV: 'production',
        REDIS_TLS_ENABLED: 'false'
      });
      validator = new EnvironmentValidator({ 
        nodeEnv: 'production',
        logWarnings: false 
      });

      const result = validator.validateEnvironment();

      const tlsIssue = result.issues.find(
        i => i.variable === 'REDIS_TLS_ENABLED' && i.type === 'INSECURE_SETTING'
      );
      expect(tlsIssue).toBeDefined();
      expect(tlsIssue?.severity).toBe('high');
    });

    it('должен предупреждать о debug логировании в production', () => {
      setTestEnvironment({ 
        NODE_ENV: 'production',
        LOG_LEVEL: 'debug'
      });
      validator = new EnvironmentValidator({ 
        nodeEnv: 'production',
        logWarnings: false 
      });

      const result = validator.validateEnvironment();

      const logIssue = result.issues.find(
        i => i.variable === 'LOG_LEVEL' && i.type === 'VERBOSE_LOGGING'
      );
      expect(logIssue).toBeDefined();
      expect(logIssue?.severity).toBe('low');
    });
  });

  // =============================================================================
  // PLACEHOLDER DETECTION TESTS
  // =============================================================================

  describe('Placeholder Detection', () => {
    it('должен обнаруживать плейсхолдер "your_"', () => {
      setTestEnvironment({ REDIS_PASSWORD: 'your_password_here' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const placeholderIssue = result.issues.find(
        i => i.variable === 'REDIS_PASSWORD' && i.type === 'PLACEHOLDER_VALUE'
      );
      expect(placeholderIssue).toBeDefined();
    });

    it('должен обнаруживать плейсхолдер "example"', () => {
      setTestEnvironment({ REDIS_PASSWORD: 'example_password' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const placeholderIssue = result.issues.find(
        i => i.variable === 'REDIS_PASSWORD' && i.type === 'PLACEHOLDER_VALUE'
      );
      expect(placeholderIssue).toBeDefined();
    });

    it('должен обнаруживать плейсхолдер "changeme"', () => {
      setTestEnvironment({ REDIS_PASSWORD: 'changeme' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const placeholderIssue = result.issues.find(
        i => i.variable === 'REDIS_PASSWORD' && i.type === 'PLACEHOLDER_VALUE'
      );
      expect(placeholderIssue).toBeDefined();
    });

    it('должен пропускать реальные значения', () => {
      setTestEnvironment({ REDIS_PASSWORD: 'aB3$kL9@mN2#pQ7!rS5&tU8*vW1^xY4%' });
      validator = new EnvironmentValidator({ logWarnings: false });

      const result = validator.validateEnvironment();

      const placeholderIssue = result.issues.find(
        i => i.variable === 'REDIS_PASSWORD' && i.type === 'PLACEHOLDER_VALUE'
      );
      expect(placeholderIssue).toBeUndefined();
    });
  });

  // =============================================================================
  // MASKING TESTS
  // =============================================================================

  describe('Value Masking', () => {
    it('должен маскировать длинные значения', () => {
      const masked = validator['maskValue']('my_secret_password_123');
      expect(masked).toBe('my_s******************'); // 4 visible + 18 masked = 22 chars
    });

    it('должен маскировать короткие значения', () => {
      const masked = validator['maskValue']('abc');
      expect(masked).toBe('***');
    });

    it('должен маскировать пустые значения', () => {
      const masked = validator['maskValue']('');
      expect(masked).toBe('***');
    });
  });

  // =============================================================================
  // PASSWORD GENERATION TESTS
  // =============================================================================

  describe('Password Generation', () => {
    it('должен генерировать пароль заданной длины', () => {
      const password = EnvironmentValidator.generateSecurePassword(32);
      expect(password.length).toBe(32);
    });

    it('должен генерировать пароль с заглавными буквами', () => {
      const password = EnvironmentValidator.generateSecurePassword(32);
      expect(/[A-Z]/.test(password)).toBe(true);
    });

    it('должен генерировать пароль со строчными буквами', () => {
      const password = EnvironmentValidator.generateSecurePassword(32);
      expect(/[a-z]/.test(password)).toBe(true);
    });

    it('должен генерировать пароль с цифрами', () => {
      const password = EnvironmentValidator.generateSecurePassword(32);
      expect(/[0-9]/.test(password)).toBe(true);
    });

    it('должен генерировать пароль со специальными символами', () => {
      const password = EnvironmentValidator.generateSecurePassword(32);
      expect(/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password)).toBe(true);
    });

    it('должен генерировать разные пароли', () => {
      const password1 = EnvironmentValidator.generateSecurePassword(32);
      const password2 = EnvironmentValidator.generateSecurePassword(32);
      expect(password1).not.toBe(password2);
    });
  });

  // =============================================================================
  // UTILITY FUNCTION TESTS
  // =============================================================================

  describe('Utility Functions', () => {
    it('должен генерировать команду для AWS Secrets Manager', () => {
      const command = EnvironmentValidator.getAWSSecretCommand('prod/redis/password', 'us-east-1');
      expect(command).toContain('aws secretsmanager get-secret-value');
      expect(command).toContain('prod/redis/password');
      expect(command).toContain('us-east-1');
    });

    it('должен генерировать команду для Vault KV', () => {
      const command = EnvironmentValidator.getVaultSecretCommand('secret/data/redis', 'password');
      expect(command).toContain('vault kv get');
      expect(command).toContain('secret/data/redis');
      expect(command).toContain('password');
    });

    it('должен генерировать команду для создания токена Vault', () => {
      const command = EnvironmentValidator.getVaultTokenCommand('production-policy', '720h');
      expect(command).toContain('vault token create');
      expect(command).toContain('production-policy');
      expect(command).toContain('720h');
    });
  });
});

// =============================================================================
// QUICK VALIDATION FUNCTION TESTS
// =============================================================================

describe('validateEnvironmentQuick', () => {
  let originalEnv: Record<string, string | undefined>;

  beforeEach(() => {
    originalEnv = saveEnvironment();
    setTestEnvironment();
  });

  afterEach(() => {
    restoreEnvironment(originalEnv);
    jest.clearAllMocks();
  });

  it('должен возвращать результат валидации', () => {
    const result = validateEnvironmentQuick({ logResults: false });

    expect(result).toBeDefined();
    expect(typeof result.isValid).toBe('boolean');
    expect(Array.isArray(result.issues)).toBe(true);
    expect(Array.isArray(result.warnings)).toBe(true);
    expect(Array.isArray(result.errors)).toBe(true);
  });
});

// =============================================================================
// ASSERT PRODUCTION READY TESTS
// =============================================================================

describe('assertProductionReady', () => {
  let originalEnv: Record<string, string | undefined>;

  beforeEach(() => {
    originalEnv = saveEnvironment();
  });

  afterEach(() => {
    restoreEnvironment(originalEnv);
    jest.clearAllMocks();
  });

  it('не должен выбрасывать ошибку с валидными секретами в production', () => {
    setTestEnvironment({ 
      NODE_ENV: 'production',
      REDIS_PASSWORD: 'xK9#mP2$vL5@nQ8!wR3&jT6*hY0^cF4%',
      VAULT_TOKEN: 'hvs.aBcDeFgHiJkLmNoPqRsTuVwXyZ123456',
      ELASTICSEARCH_PASSWORD: 'yL0@nP3$qM6#rK9!vS4&kW7^dG2%hT5'
    });

    expect(() => assertProductionReady()).not.toThrow();
  });

  it('должен выбрасывать ошибку с дефолтными паролями в production', () => {
    setTestEnvironment({ 
      NODE_ENV: 'production',
      REDIS_PASSWORD: 'change_this_password'
    });

    expect(() => assertProductionReady()).toThrow('Production environment validation failed');
  });

  it('не должен выбрасывать ошибку в development с дефолтными паролями', () => {
    setTestEnvironment({ 
      NODE_ENV: 'development',
      REDIS_PASSWORD: 'devpassword'
    });

    // В development ошибка не выбрасывается
    expect(() => assertProductionReady()).not.toThrow();
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('EnvironmentValidator Integration', () => {
  let originalEnv: Record<string, string | undefined>;

  beforeEach(() => {
    originalEnv = saveEnvironment();
  });

  afterEach(() => {
    restoreEnvironment(originalEnv);
    jest.clearAllMocks();
  });

  it('должен комплексно валидировать окружение', () => {
    // Сценарий: Плохое окружение
    setTestEnvironment({
      NODE_ENV: 'production',
      REDIS_PASSWORD: 'change_this_password_in_production',
      VAULT_TOKEN: 'hvs.your_token_here',
      ELASTICSEARCH_PASSWORD: 'changeme',
      SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
      REDIS_TLS_ENABLED: 'false',
      LOG_LEVEL: 'debug'
    });

    const validator = new EnvironmentValidator({ 
      nodeEnv: 'production',
      logWarnings: false 
    });

    const result = validator.validateEnvironment();

    // Проверяем наличие различных типов проблем
    expect(result.isProductionReady).toBe(false);
    expect(result.issues.length).toBeGreaterThan(3);

    // Проверяем наличие критических проблем
    const criticalIssues = result.issues.filter(i => i.severity === 'critical');
    expect(criticalIssues.length).toBeGreaterThan(0);

    // Проверяем наличие проблем с паролями
    const passwordIssues = result.issues.filter(i => i.type === 'WEAK_PASSWORD');
    expect(passwordIssues.length).toBeGreaterThan(0);

    // Проверяем наличие проблем с токенами
    const tokenIssues = result.issues.filter(i => i.type === 'PLACEHOLDER_TOKEN');
    expect(tokenIssues.length).toBeGreaterThan(0);

    // Проверяем наличие проблем с настройками
    const settingIssues = result.issues.filter(i => i.type === 'INSECURE_SETTING');
    expect(settingIssues.length).toBeGreaterThan(0);
  });

  it('должен успешно валидировать хорошее production окружение', () => {
    setTestEnvironment({
      NODE_ENV: 'production',
      REDIS_PASSWORD: 'xK9#mP2$vL5@nQ8!wR3&jT6*hY0^cF4%',
      VAULT_TOKEN: 'hvs.aBcDeFgHiJkLmNoPqRsTuVwXyZ123456',
      ELASTICSEARCH_PASSWORD: 'yL0@nP3$qM6#rK9!vS4&kW7^dG2%hT5',
      SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx',
      JIRA_API_TOKEN: 'jira_prod_token_12345678901234567890',
      REDIS_TLS_ENABLED: 'true',
      MTLS_ENABLED: 'true',
      LOG_LEVEL: 'warn',
      VAULT_URL: 'https://vault.production.local:8200'
    });

    const validator = new EnvironmentValidator({
      nodeEnv: 'production',
      logWarnings: false
    });

    const result = validator.validateEnvironment();

    expect(result.isProductionReady).toBe(true);
    expect(result.errors.length).toBe(0);
  });

  it('должен обнаруживать REDACTED Slack webhook URL', () => {
    setTestEnvironment({
      NODE_ENV: 'production',
      REDIS_PASSWORD: 'xK9#mP2$vL5@nQ8!wR3&jT6*hY0^cF4%',
      VAULT_TOKEN: 'hvs.aBcDeFgHiJkLmNoPqRsTuVwXyZ123456',
      ELASTICSEARCH_PASSWORD: 'yL0@nP3$qM6#rK9!vS4&kW7^dG2%hT5',
      SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/REDACTED/REDACTED/REDACTED',
      JIRA_API_TOKEN: 'jira_prod_token_12345678901234567890'
    });

    const validator = new EnvironmentValidator({
      nodeEnv: 'production',
      logWarnings: false
    });

    const result = validator.validateEnvironment();

    expect(result.isProductionReady).toBe(false);
    
    const placeholderIssue = result.issues.find(
      i => i.variable === 'SLACK_WEBHOOK_URL' && i.type === 'PLACEHOLDER_URL'
    );
    expect(placeholderIssue).toBeDefined();
  });
});
