/**
 * =============================================================================
 * TEST SETUP
 * =============================================================================
 * Глобальная настройка для тестов
 * =============================================================================
 */

// Глобальные моки
beforeAll(() => {
  // Настройка глобального таймаута
  jest.setTimeout(30000);
});

// Очистка после каждого теста
afterEach(() => {
  jest.clearAllMocks();
});

// Глобальные утилиты для тестов
global.testUtils = {
  /**
   * Создает тестового пользователя
   */
  createTestUser: (overrides = {}) => ({
    id: 'test-user-id',
    email: 'test@example.com',
    username: 'testuser',
    status: 'active' as const,
    roles: ['user'],
    ...overrides,
  }),

  /**
   * Создает тестовую сессию
   */
  createTestSession: (overrides = {}) => ({
    id: 'test-session-id',
    userId: 'test-user-id',
    type: 'web' as const,
    status: 'active' as const,
    userAgent: 'Test Browser',
    ipAddress: '127.0.0.1',
    createdAt: new Date(),
    lastUsedAt: new Date(),
    expiresAt: new Date(Date.now() + 3600000),
    absoluteExpiresAt: new Date(Date.now() + 86400000),
    authenticationMethods: [{ method: 'password', authenticatedAt: new Date() }],
    authenticationLevel: { ial: 1, aal: 1 },
    context: {
      isDeviceTrusted: false,
      isDeviceVerified: false,
      requiresReauth: false,
      jitElevated: false,
    },
    metadata: {},
    ...overrides,
  }),

  /**
   * Создает тестовый OAuth клиент
   */
  createTestOAuthClient: (overrides = {}) => ({
    clientId: 'test-client-id',
    clientName: 'Test Client',
    clientType: 'public' as const,
    redirectUris: ['https://example.com/callback'],
    grantTypes: ['authorization_code' as const],
    responseTypes: ['code' as const],
    defaultScopes: ['openid'],
    allowedScopes: ['openid', 'profile', 'email'],
    accessTokenLifetime: 3600,
    refreshTokenLifetime: 604800,
    idTokenLifetime: 3600,
    requirePkce: true,
    requireConsent: true,
    isActive: true,
    createdAt: new Date(),
    ...overrides,
  }),

  /**
   * Создает тестовый IP адрес
   */
  createTestIpAddress: () => '192.168.1.' + Math.floor(Math.random() * 255),

  /**
   * Создает тестовый User-Agent
   */
  createTestUserAgent: () => 'Mozilla/5.0 (Test OS) Test Browser/1.0.0',

  /**
   * Ждет указанное время (мс)
   */
  sleep: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
};

// Mock для crypto.getRandomValues
if (typeof crypto !== 'undefined' && !crypto.getRandomValues) {
  // @ts-ignore
  global.crypto = {
    getRandomValues: (buffer: Uint8Array) => {
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = Math.floor(Math.random() * 256);
      }
      return buffer;
    },
  };
}

// Логирование в тесты (можно отключить для CI)
const ENABLE_TEST_LOGS = process.env.ENABLE_TEST_LOGS === 'true';

if (!ENABLE_TEST_LOGS) {
  // Отключаем console.log в тестах (раскомментировать для CI)
  // console.log = jest.fn();
  // console.warn = jest.fn();
  // console.error = jest.fn();
}

// Глобальные хелперы для assertions
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidDate(): R;
      toBeUuid(): R;
    }
  }
}

expect.extend({
  toBeValidDate(received) {
    const isValid = received instanceof Date && !isNaN(received.getTime());
    return {
      pass: isValid,
      message: () => `expected ${received} to be a valid date`,
    };
  },
  toBeUuid(received) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const isValid = typeof received === 'string' && uuidRegex.test(received);
    return {
      pass: isValid,
      message: () => `expected ${received} to be a valid UUID`,
    };
  },
});

export {};
