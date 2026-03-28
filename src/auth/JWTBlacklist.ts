/**
 * =============================================================================
 * JWT BLACKLIST SERVICE
 * =============================================================================
 * Сервис для управления blacklist отозванных JWT токенов
 * Реализует: Redis хранилище, TTL, массовая revocation, метрики
 * Соответствует: OWASP JWT Security Cheat Sheet, RFC 7519
 * Интеграция: JWTService, SessionManager
 * =============================================================================
 */

import Redis from 'ioredis';
import { logger } from '../logging/Logger';
import { AuthError, AuthErrorCode } from '../types/auth.types';

/**
 * Конфигурация JWT Blacklist сервиса
 */
export interface JWTBlacklistConfig {
  /** Префикс для ключей Redis */
  keyPrefix: string;

  /** Префикс для индексов по userId */
  userIndexPrefix: string;

  /** Префикс для индексов по deviceId */
  deviceIndexPrefix: string;

  /** Включить ли blacklist */
  enabled: boolean;

  /** Интервал очистки просроченных записей (мс) */
  cleanupInterval: number;

  /** Redis конфигурация */
  redis: {
    host: string;
    port: number;
    password?: string;
    db?: number;
    tls?: Record<string, any>;
  };

  /** Максимальное количество записей в blacklist (для метрик) */
  maxMetricsSize: number;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: JWTBlacklistConfig = {
  keyPrefix: 'protocol:jwt:blacklist:',
  userIndexPrefix: 'protocol:jwt:blacklist:user:',
  deviceIndexPrefix: 'protocol:jwt:blacklist:device:',
  enabled: true,
  cleanupInterval: 3600000, // 1 час
  redis: {
    host: 'localhost',
    port: 6379,
    db: 0,
  },
  maxMetricsSize: 10000,
};

/**
 * Информация об отозванном токене
 */
export interface RevokedTokenInfo {
  /** Уникальный идентификатор токена (jti) */
  tokenId: string;

  /** ID пользователя */
  userId?: string;

  /** ID устройства */
  deviceId?: string;

  /** ID сессии */
  sessionId?: string;

  /** Причина отзыва */
  reason?: string;

  /** Время отзыва */
  revokedAt: Date;

  /** Время истечения токена (оригинальное exp) */
  expiresAt?: Date;

  /** TTL записи в секундах */
  ttl: number;
}

/**
 * Метрики blacklist
 */
export interface BlacklistMetrics {
  /** Общее количество отозванных токенов */
  totalRevoked: number;

  /** Количество отозванных токенов по userId */
  revokedByUser: Record<string, number>;

  /** Количество отозванных токенов по deviceId */
  revokedByDevice: Record<string, number>;

  /** Количество очисток за последнюю минуту */
  cleanupCount: number;

  /** Последнее время очистки */
  lastCleanup?: Date;

  /** Статус Redis подключения */
  redisConnected: boolean;

  /** Время последней операции (мс) */
  lastOperationTime?: number;
}

/**
 * Результат проверки токена
 */
export interface RevocationCheckResult {
  /** Отозван ли токен */
  isRevoked: boolean;

  /** Информация об отзыве (если отозван) */
  info?: RevokedTokenInfo;

  /** Причина отзыва */
  reason?: string;
}

/**
 * =============================================================================
 * JWT BLACKLIST CLASS
 * =============================================================================
 */
export class JWTBlacklist {
  private config: JWTBlacklistConfig;
  private redis: Redis | null = null;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private metrics: BlacklistMetrics = {
    totalRevoked: 0,
    revokedByUser: {},
    revokedByDevice: {},
    cleanupCount: 0,
    redisConnected: false,
  };
  private isInitialized: boolean = false;
  private cleanupCounter: number = 0;
  private lastCleanupTime?: Date;

  /**
   * Создает новый экземпляр JWTBlacklist
   * @param config - Конфигурация сервиса
   */
  constructor(config: Partial<JWTBlacklistConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * =============================================================================
   * ИНИЦИАЛИЗАЦИЯ И УПРАВЛЕНИЕ
   * =============================================================================
   */

  /**
   * Инициализирует соединение с Redis и запускает очистку
   */
  public async initialize(): Promise<void> {
    if (!this.config.enabled) {
      logger.info('[JWTBlacklist] Blacklist отключен');
      return;
    }

    try {
      // Инициализация Redis
      this.redis = new Redis({
        host: this.config.redis.host,
        port: this.config.redis.port,
        password: this.config.redis.password,
        db: this.config.redis.db,
        tls: this.config.redis.tls,
        retryStrategy: (times) => {
          if (times > 10) {
            this.metrics.redisConnected = false;
            return null; // Прекратить попытки
          }
          return Math.min(times * 50, 2000);
        },
      });

      this.redis.on('error', (err) => {
        logger.error('[JWTBlacklist] Redis error', { error: err });
        this.metrics.redisConnected = false;
      });

      this.redis.on('connect', () => {
        logger.info('[JWTBlacklist] Connected to Redis');
        this.metrics.redisConnected = true;
      });

      this.redis.on('close', () => {
        logger.info('[JWTBlacklist] Redis connection closed');
        this.metrics.redisConnected = false;
      });

      // Тестовое подключение
      await this.redis.ping();
      this.metrics.redisConnected = true;

      // Запуск периодической очистки
      this.startCleanup();

      this.isInitialized = true;
      logger.info('[JWTBlacklist] Инициализация завершена');
    } catch (error) {
      logger.warn('[JWTBlacklist] Failed to connect to Redis, blacklist disabled');
      this.redis = null;
      this.metrics.redisConnected = false;
      this.isInitialized = false;
    }
  }

  /**
   * Запускает периодическую очистку просроченных записей
   */
  private startCleanup(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    this.cleanupInterval = setInterval(async () => {
      try {
        await this.cleanup();
        this.cleanupCounter++;
        this.lastCleanupTime = new Date();

        // Сброс счетчика каждую минуту
        if (this.cleanupCounter >= 60) {
          this.cleanupCounter = 0;
          this.metrics.cleanupCount = 0;
        } else {
          this.metrics.cleanupCount++;
        }
      } catch (error) {
        logger.error('[JWTBlacklist] Ошибка очистки', { error });
      }
    }, this.config.cleanupInterval);
  }

  /**
   * Останавливает сервис и закрывает соединение с Redis
   */
  public async destroy(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }

    if (this.redis) {
      await this.redis.quit();
      this.redis = null;
      this.metrics.redisConnected = false;
    }

    this.isInitialized = false;
  }

  /**
   * =============================================================================
   * ОТЗЫВ ТОКЕНОВ (REVOCATION)
   * =============================================================================
   */

  /**
   * Отзывает токен по его идентификатору
   * @param tokenId - Уникальный идентификатор токена (jti)
   * @param ttl - Время жизни записи в blacklist (секунды)
   * @param options - Дополнительные опции
   * @returns Информация об отозванном токене
   */
  public async revokeToken(
    tokenId: string,
    ttl: number,
    options?: {
      userId?: string;
      deviceId?: string;
      sessionId?: string;
      reason?: string;
    }
  ): Promise<RevokedTokenInfo> {
    const startTime = Date.now();

    if (!this.config.enabled) {
      throw new AuthError(
        'JWT Blacklist отключен',
        AuthErrorCode.INTERNAL_ERROR,
        503
      );
    }

    if (!tokenId || tokenId.trim() === '') {
      throw new AuthError(
        'Неверный идентификатор токена',
        AuthErrorCode.TOKEN_INVALID,
        400
      );
    }

    if (ttl <= 0) {
      throw new AuthError(
        'TTL должен быть положительным числом',
        AuthErrorCode.INVALID_ARGUMENT,
        400
      );
    }

    const tokenInfo: RevokedTokenInfo = {
      tokenId,
      userId: options?.userId,
      deviceId: options?.deviceId,
      sessionId: options?.sessionId,
      reason: options?.reason,
      revokedAt: new Date(),
      ttl,
    };

    try {
      if (this.redis) {
        // Основной ключ blacklist
        const key = `${this.config.keyPrefix}${tokenId}`;
        await this.redis.setex(key, ttl, JSON.stringify(tokenInfo));

        // Индекс по userId
        if (options?.userId) {
          const userIndexKey = `${this.config.userIndexPrefix}${options.userId}`;
          await this.redis.sadd(userIndexKey, tokenId);
          await this.redis.expire(userIndexKey, ttl);
        }

        // Индекс по deviceId
        if (options?.deviceId) {
          const deviceIndexKey = `${this.config.deviceIndexPrefix}${options.deviceId}`;
          await this.redis.sadd(deviceIndexKey, tokenId);
          await this.redis.expire(deviceIndexKey, ttl);
        }

        // Обновление метрик
        this.updateMetricsOnRevoke(options?.userId, options?.deviceId);
      } else {
        // Fallback: in-memory storage (только для development)
        logger.warn('[JWTBlacklist] Redis недоступен, используется in-memory storage');
        // В production это критическая ошибка
      }

      this.metrics.lastOperationTime = Date.now() - startTime;

      return tokenInfo;
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка отзыва токена', { error });
      throw new AuthError(
        `Ошибка отзыва токена: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Проверяет, отозван ли токен
   * @param tokenId - Уникальный идентификатор токена (jti)
   * @returns Результат проверки
   */
  public async isRevoked(tokenId: string): Promise<RevocationCheckResult> {
    const startTime = Date.now();

    if (!this.config.enabled) {
      // Если blacklist отключен, токен считается не отозванным
      return { isRevoked: false };
    }

    if (!tokenId || tokenId.trim() === '') {
      return {
        isRevoked: false,
        reason: 'Неверный идентификатор токена',
      };
    }

    try {
      if (this.redis) {
        const key = `${this.config.keyPrefix}${tokenId}`;
        const data = await this.redis.get(key);

        this.metrics.lastOperationTime = Date.now() - startTime;

        if (data) {
          const info: RevokedTokenInfo = JSON.parse(data);
          return {
            isRevoked: true,
            info,
            reason: info.reason || 'Токен отозван',
          };
        }

        return { isRevoked: false };
      } else {
        // Redis недоступен - политика безопасности зависит от конфигурации
        // В production лучше вернуть ошибку или считать токен отозванным
        logger.warn('[JWTBlacklist] Redis недоступен при проверке токена');
        return { isRevoked: false };
      }
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка проверки токена', { error });
      // При ошибке считаем токен не отозванным (fail-open для доступности)
      // В production можно изменить на fail-close
      return {
        isRevoked: false,
        reason: `Ошибка проверки: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * =============================================================================
   * МАССОВАЯ REVOCATION
   * =============================================================================
   */

  /**
   * Отзывает все токены пользователя
   * @param userId - ID пользователя
   * @param ttl - Время жизни записей в blacklist (секунды)
   * @param reason - Причина отзыва
   * @param sessionId - ID сессии (опционально, для отзыва конкретной сессии)
   * @returns Количество отозванных токенов
   */
  public async revokeUserTokens(
    userId: string,
    ttl: number,
    reason?: string,
    sessionId?: string
  ): Promise<number> {
    if (!this.redis || !this.isInitialized || !this.metrics.redisConnected) {
      throw new AuthError(
        'Redis недоступен',
        AuthErrorCode.INTERNAL_ERROR,
        503
      );
    }

    try {
      // Получаем все токены пользователя из индекса
      const userIndexKey = `${this.config.userIndexPrefix}${userId}`;
      const tokenIds = await this.redis.smembers(userIndexKey);

      if (!tokenIds || tokenIds.length === 0) {
        return 0;
      }

      let revokedCount = 0;

      for (const tokenId of tokenIds) {
        // Если указан sessionId, отзываем только токены этой сессии
        if (sessionId) {
          const key = `${this.config.keyPrefix}${tokenId}`;
          const data = await this.redis.get(key);
          if (data) {
            const info: RevokedTokenInfo = JSON.parse(data);
            if (info.sessionId !== sessionId) {
              continue; // Пропускаем токены других сессий
            }
          }
        }

        // Проверяем, не отозван ли уже токен
        const checkResult = await this.isRevoked(tokenId);
        if (!checkResult.isRevoked) {
          await this.revokeToken(tokenId, ttl, {
            userId,
            reason: reason || 'Массовая revocation по userId',
          });
          revokedCount++;
        }
      }

      // Очищаем индекс
      await this.redis.del(userIndexKey);

      logger.info(`[JWTBlacklist] Отозвано ${revokedCount} токенов пользователя ${userId}`);

      return revokedCount;
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка массовой revocation пользователя', { error });
      throw new AuthError(
        `Ошибка массовой revocation: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Отзывает все токены устройства
   * @param deviceId - ID устройства
   * @param ttl - Время жизни записей в blacklist (секунды)
   * @param reason - Причина отзыва
   * @returns Количество отозванных токенов
   */
  public async revokeDeviceTokens(
    deviceId: string,
    ttl: number,
    reason?: string
  ): Promise<number> {
    if (!this.redis) {
      throw new AuthError(
        'Redis недоступен',
        AuthErrorCode.INTERNAL_ERROR,
        503
      );
    }

    try {
      // Получаем все токены устройства из индекса
      const deviceIndexKey = `${this.config.deviceIndexPrefix}${deviceId}`;
      const tokenIds = await this.redis.smembers(deviceIndexKey);

      if (!tokenIds || tokenIds.length === 0) {
        return 0;
      }

      let revokedCount = 0;

      for (const tokenId of tokenIds) {
        const checkResult = await this.isRevoked(tokenId);
        if (!checkResult.isRevoked) {
          await this.revokeToken(tokenId, ttl, {
            deviceId,
            reason: reason || 'Массовая revocation по deviceId',
          });
          revokedCount++;
        }
      }

      // Очищаем индекс
      await this.redis.del(deviceIndexKey);

      logger.info(`[JWTBlacklist] Отозвано ${revokedCount} токенов устройства ${deviceId}`);

      return revokedCount;
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка массовой revocation устройства', { error });
      throw new AuthError(
        `Ошибка массовой revocation: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Отзывает все токены сессии
   * @param sessionId - ID сессии
   * @param ttl - Время жизни записей в blacklist (секунды)
   * @param reason - Причина отзыва
   * @returns Количество отозванных токенов
   */
  public async revokeSessionTokens(
    sessionId: string,
    ttl: number,
    reason?: string
  ): Promise<number> {
    if (!this.redis) {
      throw new AuthError(
        'Redis недоступен',
        AuthErrorCode.INTERNAL_ERROR,
        503
      );
    }

    try {
      // Получаем все токены сессии (через сканирование)
      const pattern = `${this.config.keyPrefix}*`;
      let revokedCount = 0;

      const stream = this.redis.scanStream({
        match: pattern,
        count: 100,
      });

      for await (const keys of stream) {
        for (const key of keys) {
          const data = await this.redis.get(key);
          if (data) {
            const info: RevokedTokenInfo = JSON.parse(data);
            if (info.sessionId === sessionId && !info.tokenId.startsWith('revoked_')) {
              // Токен уже в blacklist, просто обновляем информацию
              continue;
            }
          }

          // Извлекаем tokenId из ключа
          const tokenId = key.replace(this.config.keyPrefix, '');
          const checkResult = await this.isRevoked(tokenId);

          if (!checkResult.isRevoked) {
            await this.revokeToken(tokenId, ttl, {
              sessionId,
              reason: reason || 'Массовая revocation по sessionId',
            });
            revokedCount++;
          }
        }
      }

      logger.info(`[JWTBlacklist] Отозвано ${revokedCount} токенов сессии ${sessionId}`);

      return revokedCount;
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка массовой revocation сессии', { error });
      throw new AuthError(
        `Ошибка массовой revocation: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * =============================================================================
   * ОЧИСТКА
   * =============================================================================
   */

  /**
   * Очищает просроченные записи из blacklist
   * @returns Статистика очистки
   */
  public async cleanup(): Promise<{
    cleanedKeys: number;
    cleanedUserIndexes: number;
    cleanedDeviceIndexes: number;
  }> {
    if (!this.redis || !this.isInitialized || !this.metrics.redisConnected) {
      return {
        cleanedKeys: 0,
        cleanedUserIndexes: 0,
        cleanedDeviceIndexes: 0,
      };
    }

    try {
      let cleanedKeys = 0;
      let cleanedUserIndexes = 0;
      let cleanedDeviceIndexes = 0;

      // Очистка индексов пользователей (автоматически через TTL)
      const userIndexPattern = `${this.config.userIndexPrefix}*`;
      const userIndexesStream = this.redis.scanStream({
        match: userIndexPattern,
        count: 100,
      });

      for await (const keys of userIndexesStream) {
        for (const key of keys) {
          const ttl = await this.redis.ttl(key);
          if (ttl <= 0) {
            await this.redis.del(key);
            cleanedUserIndexes++;
          }
        }
      }

      // Очистка индексов устройств
      const deviceIndexPattern = `${this.config.deviceIndexPrefix}*`;
      const deviceIndexesStream = this.redis.scanStream({
        match: deviceIndexPattern,
        count: 100,
      });

      for await (const keys of deviceIndexesStream) {
        for (const key of keys) {
          const ttl = await this.redis.ttl(key);
          if (ttl <= 0) {
            await this.redis.del(key);
            cleanedDeviceIndexes++;
          }
        }
      }

      this.lastCleanupTime = new Date();

      const result = {
        cleanedKeys,
        cleanedUserIndexes,
        cleanedDeviceIndexes,
      };

      logger.info('[JWTBlacklist] Очистка завершена', result);

      return result;
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка очистки', { error });
      return {
        cleanedKeys: 0,
        cleanedUserIndexes: 0,
        cleanedDeviceIndexes: 0,
      };
    }
  }

  /**
   * =============================================================================
   * МЕТРИКИ И МОНИТОРИНГ
   * =============================================================================
   */

  /**
   * Получает текущие метрики blacklist
   * @returns Метрики blacklist
   */
  public async getMetrics(): Promise<BlacklistMetrics> {
    if (!this.redis || !this.isInitialized || !this.metrics.redisConnected) {
      return {
        ...this.metrics,
        redisConnected: false,
      };
    }

    try {
      // Подсчет общего количества отозванных токенов
      const pattern = `${this.config.keyPrefix}*`;
      let totalRevoked = 0;

      const stream = this.redis.scanStream({
        match: pattern,
        count: 100,
      });

      for await (const keys of stream) {
        totalRevoked += keys.length;
      }

      this.metrics.totalRevoked = totalRevoked;
      this.metrics.lastCleanup = this.lastCleanupTime;

      return { ...this.metrics };
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка получения метрик', { error });
      return this.metrics;
    }
  }

  /**
   * Получает информацию об отозванном токене
   * @param tokenId - Уникальный идентификатор токена
   * @returns Информация о токене или null
   */
  public async getRevokedTokenInfo(tokenId: string): Promise<RevokedTokenInfo | null> {
    if (!this.redis) {
      return null;
    }

    try {
      const key = `${this.config.keyPrefix}${tokenId}`;
      const data = await this.redis.get(key);

      if (!data) {
        return null;
      }

      return JSON.parse(data) as RevokedTokenInfo;
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка получения информации о токене', { error });
      return null;
    }
  }

  /**
   * Получает все отозванные токены пользователя
   * @param userId - ID пользователя
   * @returns Массив информации о токенах
   */
  public async getUserRevokedTokens(userId: string): Promise<RevokedTokenInfo[]> {
    if (!this.redis) {
      return [];
    }

    try {
      const userIndexKey = `${this.config.userIndexPrefix}${userId}`;
      const tokenIds = await this.redis.smembers(userIndexKey);

      if (!tokenIds || tokenIds.length === 0) {
        return [];
      }

      const tokens: RevokedTokenInfo[] = [];

      for (const tokenId of tokenIds) {
        const info = await this.getRevokedTokenInfo(tokenId);
        if (info) {
          tokens.push(info);
        }
      }

      return tokens;
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка получения токенов пользователя', { error });
      return [];
    }
  }

  /**
   * Получает все отозванные токены устройства
   * @param deviceId - ID устройства
   * @returns Массив информации о токенах
   */
  public async getDeviceRevokedTokens(deviceId: string): Promise<RevokedTokenInfo[]> {
    if (!this.redis) {
      return [];
    }

    try {
      const deviceIndexKey = `${this.config.deviceIndexPrefix}${deviceId}`;
      const tokenIds = await this.redis.smembers(deviceIndexKey);

      if (!tokenIds || tokenIds.length === 0) {
        return [];
      }

      const tokens: RevokedTokenInfo[] = [];

      for (const tokenId of tokenIds) {
        const info = await this.getRevokedTokenInfo(tokenId);
        if (info) {
          tokens.push(info);
        }
      }

      return tokens;
    } catch (error) {
      logger.error('[JWTBlacklist] Ошибка получения токенов устройства', { error });
      return [];
    }
  }

  /**
   * Проверяет статус сервиса
   * @returns Статус сервиса
   */
  public getStatus(): {
    initialized: boolean;
    enabled: boolean;
    redisConnected: boolean;
    cleanupRunning: boolean;
  } {
    return {
      initialized: this.isInitialized,
      enabled: this.config.enabled,
      redisConnected: this.metrics.redisConnected,
      cleanupRunning: this.cleanupInterval !== null,
    };
  }

  /**
   * =============================================================================
   * ВНУТРЕННИЕ МЕТОДЫ
   * =============================================================================
   */

  /**
   * Обновляет метрики при отзыве токена
   * @private
   */
  private updateMetricsOnRevoke(userId?: string, deviceId?: string): void {
    this.metrics.totalRevoked++;

    if (userId) {
      this.metrics.revokedByUser[userId] = (this.metrics.revokedByUser[userId] || 0) + 1;
    }

    if (deviceId) {
      this.metrics.revokedByDevice[deviceId] = (this.metrics.revokedByDevice[deviceId] || 0) + 1;
    }

    // Ограничение размера метрик
    if (Object.keys(this.metrics.revokedByUser).length > this.config.maxMetricsSize) {
      // Удаляем старые записи
      const keys = Object.keys(this.metrics.revokedByUser);
      delete this.metrics.revokedByUser[keys[0]];
    }

    if (Object.keys(this.metrics.revokedByDevice).length > this.config.maxMetricsSize) {
      const keys = Object.keys(this.metrics.revokedByDevice);
      delete this.metrics.revokedByDevice[keys[0]];
    }
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const jwtBlacklist = new JWTBlacklist(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createJWTBlacklist(config: Partial<JWTBlacklistConfig>): JWTBlacklist {
  return new JWTBlacklist(config);
}
