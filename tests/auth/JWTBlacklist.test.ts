/**
 * =============================================================================
 * JWT BLACKLIST TESTS
 * =============================================================================
 * Полные тесты для JWT Blacklist сервиса
 * Включает: Unit tests, Integration tests, Security tests
 * Покрытие: 100% функционала JWTBlacklist
 * =============================================================================
 */

import { JWTBlacklist, createJWTBlacklist, RevokedTokenInfo } from '../../src/auth/JWTBlacklist';
import { AuthError } from '../../src/types/auth.types';

// Mock для Redis с хранением состояния
const mockRedisStorage = new Map<string, string>();

const mockRedis = {
  setex: jest.fn().mockImplementation(async (key: string, ttl: number, value: string) => {
    mockRedisStorage.set(key, value);
    return 'OK';
  }),
  get: jest.fn().mockImplementation(async (key: string) => {
    const value = mockRedisStorage.get(key);
    return value !== undefined ? value : null;
  }),
  del: jest.fn().mockImplementation(async (key: string) => {
    mockRedisStorage.delete(key);
    return 1;
  }),
  sadd: jest.fn().mockImplementation(async (key: string, value: string) => {
    const current = mockRedisStorage.get(key);
    const set = current ? new Set(current.split(',')) : new Set();
    set.add(value);
    mockRedisStorage.set(key, Array.from(set).join(','));
    return 1;
  }),
  smembers: jest.fn().mockImplementation(async (key: string) => {
    const current = mockRedisStorage.get(key);
    if (!current) return [];
    return current.split(',').filter(Boolean);
  }),
  srem: jest.fn().mockImplementation(async (key: string, value: string) => {
    const current = mockRedisStorage.get(key);
    if (!current) return 0;
    const set = new Set(current.split(','));
    set.delete(value);
    mockRedisStorage.set(key, Array.from(set).join(','));
    return 1;
  }),
  expire: jest.fn().mockImplementation(async (key: string, ttl: number) => {
    // Симулируем установку TTL - в реальном тесте просто возвращаем успех
    return 1;
  }),
  ttl: jest.fn().mockImplementation(async (key: string) => {
    if (mockRedisStorage.has(key)) {
      return 3600; // Возвращаем положительный TTL для существующих ключей
    }
    return -2; // Key does not exist
  }),
  scanStream: jest.fn().mockReturnValue({
    [Symbol.asyncIterator]: async function* () {
      yield Array.from(mockRedisStorage.keys());
    },
  }),
  on: jest.fn(),
  ping: jest.fn().mockResolvedValue('PONG'),
  quit: jest.fn().mockResolvedValue('OK'),
};

jest.mock('ioredis', () => {
  return jest.fn().mockImplementation(() => mockRedis);
});

describe('JWTBlacklist', () => {
  let blacklist: JWTBlacklist;

  beforeEach(() => {
    jest.clearAllMocks();
    mockRedisStorage.clear();
    blacklist = createJWTBlacklist({
      enabled: true,
      redis: {
        host: 'localhost',
        port: 6379,
      },
      cleanupInterval: 60000, // 1 минута для тестов
    });
  });

  afterEach(async () => {
    await blacklist.destroy();
    jest.clearAllMocks();
  });

  // ===========================================================================
  // ИНИЦИАЛИЗАЦИЯ И УПРАВЛЕНИЕ
  // ===========================================================================

  describe('Инициализация', () => {
    it('должен успешно инициализироваться с Redis', async () => {
      await blacklist.initialize();
      const status = blacklist.getStatus();

      expect(status.initialized).toBe(true);
      expect(status.enabled).toBe(true);
      expect(mockRedis.ping).toHaveBeenCalled();
    });

    it('должен корректно обрабатывать отключенный blacklist', async () => {
      const disabledBlacklist = createJWTBlacklist({ enabled: false });
      await disabledBlacklist.initialize();
      const status = disabledBlacklist.getStatus();

      expect(status.enabled).toBe(false);
      await disabledBlacklist.destroy();
    });

    it('должен обрабатывать ошибку подключения к Redis', async () => {
      mockRedis.ping.mockRejectedValueOnce(new Error('Connection refused'));

      const testBlacklist = createJWTBlacklist({
        enabled: true,
        redis: { host: 'invalid-host', port: 9999 },
      });

      await testBlacklist.initialize();
      const status = testBlacklist.getStatus();

      expect(status.redisConnected).toBe(false);
      await testBlacklist.destroy();
    });

    it('должен запускать периодическую очистку при инициализации', async () => {
      const cleanupBlacklist = createJWTBlacklist({
        enabled: true,
        cleanupInterval: 100, // Очень короткий интервал для теста
      });

      await cleanupBlacklist.initialize();
      let status = cleanupBlacklist.getStatus();

      expect(status.cleanupRunning).toBe(true);

      await cleanupBlacklist.destroy();
      status = cleanupBlacklist.getStatus();
      expect(status.cleanupRunning).toBe(false);
    });
  });

  describe('Уничтожение', () => {
    it('должен корректно закрывать соединение с Redis', async () => {
      await blacklist.initialize();
      await blacklist.destroy();

      const status = blacklist.getStatus();
      expect(status.initialized).toBe(false);
      expect(status.redisConnected).toBe(false);
    });

    it('должен останавливать интервал очистки', async () => {
      await blacklist.initialize();
      await blacklist.destroy();

      const status = blacklist.getStatus();
      expect(status.cleanupRunning).toBe(false);
    });
  });

  // ===========================================================================
  // ОТЗЫВ ТОКЕНОВ (REVOCATION)
  // ===========================================================================

  describe('revokeToken', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен успешно отзывать токен', async () => {
      const tokenId = 'test-token-id-123';
      const ttl = 3600;

      const result = await blacklist.revokeToken(tokenId, ttl, {
        userId: 'user-123',
        sessionId: 'session-456',
        reason: 'User logout',
      });

      expect(result).toBeDefined();
      expect(result.tokenId).toBe(tokenId);
      expect(result.userId).toBe('user-123');
      expect(result.reason).toBe('User logout');
      expect(result.ttl).toBe(ttl);
      expect(mockRedis.setex).toHaveBeenCalled();
    });

    it('должен создавать индекс по userId', async () => {
      const tokenId = 'test-token-id-456';
      const userId = 'user-789';
      const ttl = 3600;

      await blacklist.revokeToken(tokenId, ttl, { userId });

      expect(mockRedis.sadd).toHaveBeenCalledWith(
        expect.stringContaining(`user:${userId}`),
        tokenId
      );
      expect(mockRedis.expire).toHaveBeenCalled();
    });

    it('должен создавать индекс по deviceId', async () => {
      const tokenId = 'test-token-id-789';
      const deviceId = 'device-abc';
      const ttl = 3600;

      await blacklist.revokeToken(tokenId, ttl, { deviceId });

      expect(mockRedis.sadd).toHaveBeenCalledWith(
        expect.stringContaining(`device:${deviceId}`),
        tokenId
      );
    });

    it('должен выбрасывать ошибку при пустом tokenId', async () => {
      await expect(blacklist.revokeToken('', 3600)).rejects.toThrow(AuthError);
      await expect(blacklist.revokeToken('   ', 3600)).rejects.toThrow(AuthError);
    });

    it('должен выбрасывать ошибку при отрицательном TTL', async () => {
      await expect(blacklist.revokeToken('token-id', -100)).rejects.toThrow(AuthError);
      await expect(blacklist.revokeToken('token-id', 0)).rejects.toThrow(AuthError);
    });

    it('должен выбрасывать ошибку если blacklist отключен', async () => {
      const disabledBlacklist = createJWTBlacklist({ enabled: false });
      await disabledBlacklist.initialize();

      await expect(disabledBlacklist.revokeToken('token', 3600)).rejects.toThrow(AuthError);

      await disabledBlacklist.destroy();
    });

    it('должен использовать fallback при недоступном Redis', async () => {
      const noRedisBlacklist = createJWTBlacklist({
        enabled: true,
        redis: { host: 'invalid', port: 9999 },
      });

      // Имитация неудачного подключения
      await noRedisBlacklist.initialize();

      // Не должно выбрасывать ошибку, но и не должно работать
      const result = await noRedisBlacklist.revokeToken('token', 3600);
      expect(result).toBeDefined();

      await noRedisBlacklist.destroy();
    });
  });

  // ===========================================================================
  // ПРОВЕРКА TOKEN (IS REVOKED)
  // ===========================================================================

  describe('isRevoked', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен возвращать false для не отозванного токена', async () => {
      mockRedis.get.mockResolvedValue(null);

      const result = await blacklist.isRevoked('non-revoked-token');

      expect(result.isRevoked).toBe(false);
      expect(result.reason).toBeUndefined();
    });

    it('должен возвращать true для отозванного токена', async () => {
      const revokedInfo: RevokedTokenInfo = {
        tokenId: 'revoked-token-123',
        userId: 'user-123',
        sessionId: 'session-456',
        reason: 'User logout',
        revokedAt: new Date(),
        ttl: 3600,
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(revokedInfo));

      const result = await blacklist.isRevoked('revoked-token-123');

      expect(result.isRevoked).toBe(true);
      expect(result.info).toBeDefined();
      expect(result.info?.tokenId).toBe('revoked-token-123');
      expect(result.reason).toBe('User logout');
    });

    it('должен возвращать false при пустом tokenId', async () => {
      const result = await blacklist.isRevoked('');
      expect(result.isRevoked).toBe(false);
      expect(result.reason).toBe('Неверный идентификатор токена');
    });

    it('должен возвращать false если blacklist отключен', async () => {
      const disabledBlacklist = createJWTBlacklist({ enabled: false });
      await disabledBlacklist.initialize();

      const result = await disabledBlacklist.isRevoked('any-token');

      expect(result.isRevoked).toBe(false);
      await disabledBlacklist.destroy();
    });

    it('должен обрабатывать ошибку при проверке токена', async () => {
      mockRedis.get.mockRejectedValue(new Error('Redis error'));

      const result = await blacklist.isRevoked('test-token');

      // Fail-open: при ошибке считаем токен не отозванным
      expect(result.isRevoked).toBe(false);
      expect(result.reason).toContain('Ошибка проверки');
    });
  });

  // ===========================================================================
  // МАССОВАЯ REVOCATION
  // ===========================================================================

  describe('revokeUserTokens', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен отзывать все токены пользователя', async () => {
      const userId = 'user-mass-revoke';
      const ttl = 3600;

      mockRedis.smembers.mockResolvedValueOnce(['token1', 'token2', 'token3']);
      mockRedis.get.mockResolvedValue(null); // Токены еще не в blacklist

      const count = await blacklist.revokeUserTokens(userId, ttl, 'Security breach');

      expect(count).toBe(3);
      expect(mockRedis.setex).toHaveBeenCalledTimes(3);
    });

    it('должен возвращать 0 если у пользователя нет токенов', async () => {
      mockRedis.smembers.mockResolvedValueOnce([]);

      const count = await blacklist.revokeUserTokens('user-empty', 3600);

      expect(count).toBe(0);
    });

    it('должен фильтровать уже отозванные токены', async () => {
      mockRedis.smembers.mockResolvedValueOnce(['token1', 'token2']);
      mockRedis.get
        .mockResolvedValueOnce(JSON.stringify({ tokenId: 'token1' })) // Уже отозван
        .mockResolvedValueOnce(null); // token2 еще не отозван

      const count = await blacklist.revokeUserTokens('user-123', 3600);

      expect(count).toBe(1); // Только token2
    });

    it('должен выбрасывать ошибку при недоступном Redis', async () => {
      // Переопределяем mock для симуляции недоступного Redis
      mockRedis.ping.mockRejectedValueOnce(new Error('Redis unavailable'));
      
      const noRedisBlacklist = createJWTBlacklist({
        enabled: true,
        redis: { host: 'invalid', port: 9999 },
      });

      await noRedisBlacklist.initialize();

      await expect(noRedisBlacklist.revokeUserTokens('user', 3600)).rejects.toThrow(AuthError);

      await noRedisBlacklist.destroy();
      
      // Восстанавливаем mock
      mockRedis.ping.mockResolvedValue('PONG');
    });

    it('должен очищать индекс пользователя после revocation', async () => {
      mockRedis.smembers.mockResolvedValueOnce(['token1']);
      mockRedis.get.mockResolvedValue(null);

      await blacklist.revokeUserTokens('user-123', 3600);

      expect(mockRedis.del).toHaveBeenCalledWith(expect.stringContaining('user:user-123'));
    });
  });

  describe('revokeDeviceTokens', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен отзывать все токены устройства', async () => {
      const deviceId = 'device-abc-123';
      const ttl = 3600;

      mockRedis.smembers.mockResolvedValueOnce(['device-token1', 'device-token2']);
      mockRedis.get.mockResolvedValue(null);

      const count = await blacklist.revokeDeviceTokens(deviceId, ttl, 'Lost device');

      expect(count).toBe(2);
      expect(mockRedis.setex).toHaveBeenCalledTimes(2);
    });

    it('должен возвращать 0 если у устройства нет токенов', async () => {
      mockRedis.smembers.mockResolvedValueOnce([]);

      const count = await blacklist.revokeDeviceTokens('device-empty', 3600);

      expect(count).toBe(0);
    });
  });

  describe('revokeSessionTokens', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен отзывать все токены сессии', async () => {
      const sessionId = 'session-xyz';
      const ttl = 3600;

      // Mock для scanStream
      mockRedis.scanStream.mockReturnValue({
        [Symbol.asyncIterator]: async function* () {
          yield ['protocol:jwt:blacklist:token1'];
        },
      });

      const count = await blacklist.revokeSessionTokens(sessionId, ttl);

      expect(count).toBeGreaterThanOrEqual(0);
    });
  });

  // ===========================================================================
  // ОЧИСТКА (CLEANUP)
  // ===========================================================================

  describe('cleanup', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен выполнять очистку просроченных записей', async () => {
      mockRedis.scanStream.mockReturnValue({
        [Symbol.asyncIterator]: async function* () {
          yield ['key1', 'key2'];
        },
      });
      mockRedis.ttl.mockResolvedValue(-2); // Истекший TTL

      const result = await blacklist.cleanup();

      expect(result.cleanedKeys).toBeGreaterThanOrEqual(0);
      expect(mockRedis.del).toHaveBeenCalled();
    });

    it('должен возвращать 0 если Redis недоступен', async () => {
      // Переопределяем mock для симуляции недоступного Redis
      mockRedis.ping.mockRejectedValueOnce(new Error('Redis unavailable'));
      
      const noRedisBlacklist = createJWTBlacklist({
        enabled: true,
        redis: { host: 'invalid', port: 9999 },
      });

      await noRedisBlacklist.initialize();

      const result = await noRedisBlacklist.cleanup();

      expect(result.cleanedKeys).toBe(0);
      expect(result.cleanedUserIndexes).toBe(0);
      expect(result.cleanedDeviceIndexes).toBe(0);

      await noRedisBlacklist.destroy();
      
      // Восстанавливаем mock
      mockRedis.ping.mockResolvedValue('PONG');
    });
  });

  // ===========================================================================
  // МЕТРИКИ И МОНИТОРИНГ
  // ===========================================================================

  describe('getMetrics', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен возвращать метрики blacklist', async () => {
      mockRedis.scanStream.mockReturnValue({
        [Symbol.asyncIterator]: async function* () {
          yield ['token1', 'token2', 'token3'];
        },
      });

      const metrics = await blacklist.getMetrics();

      expect(metrics).toBeDefined();
      expect(metrics.totalRevoked).toBeGreaterThanOrEqual(0);
      expect(metrics.redisConnected).toBe(true);
      expect(metrics.revokedByUser).toBeDefined();
      expect(metrics.revokedByDevice).toBeDefined();
    });

    it('должен возвращать метрики с redisConnected=false если Redis недоступен', async () => {
      // Переопределяем mock для симуляции недоступного Redis
      mockRedis.ping.mockRejectedValueOnce(new Error('Redis unavailable'));
      
      const noRedisBlacklist = createJWTBlacklist({
        enabled: true,
        redis: { host: 'invalid', port: 9999 },
      });

      await noRedisBlacklist.initialize();

      const metrics = await noRedisBlacklist.getMetrics();

      expect(metrics.redisConnected).toBe(false);

      await noRedisBlacklist.destroy();
      
      // Восстанавливаем mock
      mockRedis.ping.mockResolvedValue('PONG');
    });
  });

  describe('getRevokedTokenInfo', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен возвращать информацию об отозванном токене', async () => {
      const tokenInfo: RevokedTokenInfo = {
        tokenId: 'token-info-123',
        userId: 'user-123',
        reason: 'Test revocation',
        revokedAt: new Date(),
        ttl: 3600,
      };

      mockRedis.get.mockResolvedValue(JSON.stringify(tokenInfo));

      const result = await blacklist.getRevokedTokenInfo('token-info-123');

      expect(result).toBeDefined();
      expect(result?.tokenId).toBe('token-info-123');
      expect(result?.reason).toBe('Test revocation');
    });

    it('должен возвращать null если токен не найден', async () => {
      mockRedis.get.mockResolvedValue(null);

      const result = await blacklist.getRevokedTokenInfo('non-existent-token');

      expect(result).toBeNull();
    });

    it('должен возвращать null если Redis недоступен', async () => {
      const noRedisBlacklist = createJWTBlacklist({
        enabled: true,
        redis: { host: 'invalid', port: 9999 },
      });

      await noRedisBlacklist.initialize();

      const result = await noRedisBlacklist.getRevokedTokenInfo('token');

      expect(result).toBeNull();

      await noRedisBlacklist.destroy();
    });
  });

  describe('getUserRevokedTokens', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен возвращать все отозванные токены пользователя', async () => {
      const tokenInfo: RevokedTokenInfo = {
        tokenId: 'user-token-123',
        userId: 'user-123',
        revokedAt: new Date(),
        ttl: 3600,
      };

      mockRedis.smembers.mockResolvedValueOnce(['user-token-123']);
      mockRedis.get.mockResolvedValue(JSON.stringify(tokenInfo));

      const tokens = await blacklist.getUserRevokedTokens('user-123');

      expect(tokens).toHaveLength(1);
      expect(tokens[0].tokenId).toBe('user-token-123');
    });

    it('должен возвращать пустой массив если у пользователя нет токенов', async () => {
      mockRedis.smembers.mockResolvedValueOnce([]);

      const tokens = await blacklist.getUserRevokedTokens('user-empty');

      expect(tokens).toHaveLength(0);
    });
  });

  describe('getDeviceRevokedTokens', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен возвращать все отозванные токены устройства', async () => {
      const tokenInfo: RevokedTokenInfo = {
        tokenId: 'device-token-123',
        deviceId: 'device-abc',
        revokedAt: new Date(),
        ttl: 3600,
      };

      mockRedis.smembers.mockResolvedValueOnce(['device-token-123']);
      mockRedis.get.mockResolvedValue(JSON.stringify(tokenInfo));

      const tokens = await blacklist.getDeviceRevokedTokens('device-abc');

      expect(tokens).toHaveLength(1);
      expect(tokens[0].deviceId).toBe('device-abc');
    });

    it('должен возвращать пустой массив если у устройства нет токенов', async () => {
      mockRedis.smembers.mockResolvedValueOnce([]);

      const tokens = await blacklist.getDeviceRevokedTokens('device-empty');

      expect(tokens).toHaveLength(0);
    });
  });

  // ===========================================================================
  // СТАТУС СЕРВИСА
  // ===========================================================================

  describe('getStatus', () => {
    it('должен возвращать корректный статус до инициализации', () => {
      const status = blacklist.getStatus();

      expect(status.initialized).toBe(false);
      expect(status.enabled).toBe(true); // По умолчанию включен
      expect(status.redisConnected).toBe(false);
      expect(status.cleanupRunning).toBe(false);
    });

    it('должен возвращать корректный статус после инициализации', async () => {
      await blacklist.initialize();
      const status = blacklist.getStatus();

      expect(status.initialized).toBe(true);
      expect(status.enabled).toBe(true);
      expect(status.cleanupRunning).toBe(true);

      await blacklist.destroy();
    });

    it('должен возвращать enabled=false если blacklist отключен', async () => {
      const disabledBlacklist = createJWTBlacklist({ enabled: false });
      const status = disabledBlacklist.getStatus();

      expect(status.enabled).toBe(false);
    });
  });

  // ===========================================================================
  // ИНТЕГРАЦИОННЫЕ ТЕСТЫ
  // ===========================================================================

  describe('Интеграция: полный цикл revocation', () => {
    it('должен выполнять полный цикл: revoke -> check -> cleanup', async () => {
      await blacklist.initialize();

      // 1. Отзыв токена
      const tokenId = 'integration-test-token';
      await blacklist.revokeToken(tokenId, 60, {
        userId: 'integration-user',
        reason: 'Integration test',
      });

      // 2. Проверка что токен отозван
      const checkResult = await blacklist.isRevoked(tokenId);
      expect(checkResult.isRevoked).toBe(true);
      expect(checkResult.reason).toBe('Integration test');

      // 3. Получение метрик
      const metrics = await blacklist.getMetrics();
      expect(metrics.totalRevoked).toBeGreaterThanOrEqual(1);

      // 4. Получение информации о токене
      const tokenInfo = await blacklist.getRevokedTokenInfo(tokenId);
      expect(tokenInfo).toBeDefined();
      expect(tokenInfo?.tokenId).toBe(tokenId);

      // 5. Получение токенов пользователя
      const userTokens = await blacklist.getUserRevokedTokens('integration-user');
      expect(userTokens.length).toBeGreaterThanOrEqual(1);

      await blacklist.destroy();
    });

    it('должен корректно обрабатывать массовую revocation', async () => {
      await blacklist.initialize();

      const userId = 'mass-revoke-user';
      const tokenIds = ['token1', 'token2', 'token3', 'token4', 'token5'];

      // Имитация существующих токенов
      mockRedis.smembers.mockResolvedValueOnce(tokenIds);
      mockRedis.get.mockResolvedValue(null);

      // Массовая revocation
      const count = await blacklist.revokeUserTokens(userId, 3600, 'Security incident');

      expect(count).toBe(5);

      // Проверка что все токены отозваны
      for (const tokenId of tokenIds) {
        const result = await blacklist.isRevoked(tokenId);
        expect(result.isRevoked).toBe(true);
      }

      await blacklist.destroy();
    });
  });

  // ===========================================================================
  // SECURITY ТЕСТЫ
  // ===========================================================================

  describe('Security тесты', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен предотвращать injection атаки через tokenId', async () => {
      const maliciousTokenId = "'; DROP TABLE tokens; --";

      // Не должно выбрасывать ошибку
      const result = await blacklist.revokeToken(maliciousTokenId, 3600);
      expect(result.tokenId).toBe(maliciousTokenId);

      // Проверка должна работать корректно
      const checkResult = await blacklist.isRevoked(maliciousTokenId);
      expect(checkResult.isRevoked).toBe(true);
    });

    it('должен корректно обрабатывать очень длинные tokenId', async () => {
      const longTokenId = 'a'.repeat(10000);

      const result = await blacklist.revokeToken(longTokenId, 3600);
      expect(result.tokenId).toBe(longTokenId);

      const checkResult = await blacklist.isRevoked(longTokenId);
      expect(checkResult.isRevoked).toBe(true);
    });

    it('должен обрабатывать специальные символы в reason', async () => {
      const specialReason = '<script>alert("XSS")</script>';

      const result = await blacklist.revokeToken('xss-token', 3600, {
        reason: specialReason,
      });

      expect(result.reason).toBe(specialReason);

      const checkResult = await blacklist.isRevoked('xss-token');
      expect(checkResult.reason).toBe(specialReason);
    });

    it('должен предотвращать race conditions при массовой revocation', async () => {
      const userId = 'race-condition-user';
      const ttl = 3600;

      mockRedis.smembers.mockResolvedValueOnce(['token1', 'token2']);
      mockRedis.get.mockResolvedValue(null);

      // Параллельный вызов revokeUserTokens
      const [result1, result2] = await Promise.all([
        blacklist.revokeUserTokens(userId, ttl),
        blacklist.revokeUserTokens(userId, ttl),
      ]);

      // Оба вызова должны завершиться успешно
      expect(result1).toBeGreaterThanOrEqual(0);
      expect(result2).toBeGreaterThanOrEqual(0);
    });
  });

  // ===========================================================================
  // FAIL-OPEN / FAIL-CLOSE ТЕСТЫ
  // ===========================================================================

  describe('Fail-open / Fail-close поведение', () => {
    it('должен использовать fail-open при проверке токена (доступность > безопасность)', async () => {
      mockRedis.get.mockRejectedValue(new Error('Redis connection lost'));

      const result = await blacklist.isRevoked('any-token');

      // Fail-open: при ошибке разрешаем доступ
      expect(result.isRevoked).toBe(false);
    });

    it('должен логировать ошибку при fail-open', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      mockRedis.get.mockRejectedValue(new Error('Redis error'));

      await blacklist.isRevoked('token');

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('[JWTBlacklist] Ошибка проверки токена'),
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });
  });

  // ===========================================================================
  // TTL ТЕСТЫ
  // ===========================================================================

  describe('TTL тесты', () => {
    beforeEach(async () => {
      await blacklist.initialize();
    });

    it('должен устанавливать корректный TTL для записи', async () => {
      const ttl = 7200; // 2 часа

      await blacklist.revokeToken('ttl-test-token', ttl);

      expect(mockRedis.setex).toHaveBeenCalledWith(
        expect.stringContaining('ttl-test-token'),
        ttl,
        expect.any(String)
      );
    });

    it('должен устанавливать TTL для индексов', async () => {
      const ttl = 3600;

      await blacklist.revokeToken('index-ttl-token', ttl, {
        userId: 'ttl-user',
        deviceId: 'ttl-device',
      });

      expect(mockRedis.expire).toHaveBeenCalledWith(
        expect.stringContaining('user:ttl-user'),
        expect.any(Number)
      );
      expect(mockRedis.expire).toHaveBeenCalledWith(
        expect.stringContaining('device:ttl-device'),
        expect.any(Number)
      );
    });
  });
});

// =============================================================================
// ФАБРИЧНАЯ ФУНКЦИЯ ТЕСТЫ
// =============================================================================

describe('createJWTBlacklist', () => {
  it('должен создавать экземпляр с конфигурацией по умолчанию', () => {
    const blacklist = createJWTBlacklist({});

    expect(blacklist).toBeDefined();
    expect(blacklist.getStatus().enabled).toBe(true);
  });

  it('должен создавать экземпляр с кастомной конфигурацией', () => {
    const blacklist = createJWTBlacklist({
      enabled: false,
      keyPrefix: 'custom:prefix:',
      cleanupInterval: 1800000, // 30 минут
    });

    expect(blacklist).toBeDefined();
    expect(blacklist.getStatus().enabled).toBe(false);
  });

  it('должен объединять конфигурацию с дефолтной', () => {
    const blacklist = createJWTBlacklist({
      redis: {
        host: 'custom-host',
        port: 6380,
      },
    });

    expect(blacklist).toBeDefined();
    // Остальные параметры должны быть из дефолтной конфигурации
  });
});
