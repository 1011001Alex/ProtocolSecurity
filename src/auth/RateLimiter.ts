/**
 * =============================================================================
 * RATE LIMITER SERVICE
 * =============================================================================
 * Сервис для защиты от brute-force, credential stuffing, DDoS
 * Алгоритмы: Fixed Window, Sliding Window, Token Bucket, Leaky Bucket
 * Соответствует: OWASP Rate Limiting Cheat Sheet
 * =============================================================================
 */

import { createHash } from 'crypto';
import Redis from 'ioredis';
import { logger } from '../logging/Logger';
import {
  RateLimitConfig,
  RateLimitStats,
  AuthError,
  AuthErrorCode,
  ISecurityEvent,
} from '../types/auth.types';

/**
 * Типы алгоритмов rate limiting
 */
export type RateLimitAlgorithm = 'fixed_window' | 'sliding_window' | 'token_bucket' | 'leaky_bucket';

/**
 * Конфигурация RateLimiter сервиса
 */
export interface RateLimiterConfig {
  /** Префикс для ключей Redis */
  keyPrefix: string;
  
  /** Redis конфигурация */
  redis: {
    host: string;
    port: number;
    password?: string;
    db?: number;
  };
  
  /** Правила по умолчанию */
  defaultRules: {
    /** Лимит запросов в минуту для аутентификации */
    authLimit: number;
    /** Лимит запросов в минуту для API */
    apiLimit: number;
    /** Лимит запросов в минуту для password reset */
    passwordResetLimit: number;
    /** Лимит запросов в минуту для MFA */
    mfaLimit: number;
  };
  
  /** Блокировка после превышения лимита (секунды) */
  blockDuration: number;
  
  /** Прогрессивная блокировка (умножитель) */
  progressiveBlockMultiplier: number;
  
  /** Максимальная длительность блокировки (секунды) */
  maxBlockDuration: number;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: RateLimiterConfig = {
  keyPrefix: 'protocol:ratelimit:',
  redis: {
    host: 'localhost',
    port: 6379,
    db: 0,
  },
  defaultRules: {
    authLimit: 5, // 5 попыток в минуту
    apiLimit: 100, // 100 запросов в минуту
    passwordResetLimit: 3, // 3 запроса в час
    mfaLimit: 10, // 10 попыток в минуту
  },
  blockDuration: 300, // 5 минут блокировки
  progressiveBlockMultiplier: 2,
  maxBlockDuration: 3600, // 1 час максимум
};

/**
 * Данные для fixed window алгоритма
 */
interface FixedWindowData {
  count: number;
  resetTime: number;
}

/**
 * Данные для token bucket алгоритма
 */
interface TokenBucketData {
  tokens: number;
  lastRefill: number;
}

/**
 * Результат проверки rate limit
 */
export interface RateLimitResult {
  /** Разрешен ли запрос */
  allowed: boolean;
  
  /** Текущий лимит */
  limit: number;
  
  /** Оставшееся количество запросов */
  remaining: number;
  
  /** Время сброса (timestamp) */
  resetTime: number;
  
  /** Время до сброса (секунды) */
  retryAfter: number;
  
  /** Причина блокировки */
  blockReason?: string;
  
  /** Длительность блокировки (секунды) */
  blockDuration?: number;
}

/**
 * Информация о блокировке
 */
interface BlockInfo {
  /** Причина блокировки */
  reason: string;
  
  /** Время начала блокировки */
  blockedAt: number;
  
  /** Длительность блокировки (секунды) */
  duration: number;
  
  /** Количество нарушений */
  violationCount: number;
}

/**
 * =============================================================================
 * RATE LIMITER SERVICE CLASS
 * =============================================================================
 */
export class RateLimiterService {
  private config: RateLimiterConfig;
  private redis: Redis | null = null;
  private inMemoryStore: Map<string, any> = new Map();
  private blockStore: Map<string, BlockInfo> = new Map();
  private violationCounts: Map<string, number> = new Map();

  /**
   * Создает новый экземпляр RateLimiterService
   * @param config - Конфигурация сервиса
   */
  constructor(config: RateLimiterConfig = DEFAULT_CONFIG) {
    this.config = config;
  }

  /**
   * Инициализирует соединение с Redis
   */
  public async initialize(): Promise<void> {
    try {
      this.redis = new Redis({
        host: this.config.redis.host,
        port: this.config.redis.port,
        password: this.config.redis.password,
        db: this.config.redis.db,
        retryStrategy: (times) => {
          if (times > 10) return null;
          return Math.min(times * 50, 2000);
        },
      });

      await this.redis.ping();
      logger.info('[RateLimiter] Connected to Redis');
    } catch (error) {
      logger.warn('[RateLimiter] Failed to connect to Redis, using in-memory storage');
      this.redis = null;
    }
  }

  // ===========================================================================
  // ПРОВЕРКА RATE LIMIT
  // ===========================================================================

  /**
   * Проверяет rate limit для указанного ключа
   * @param key - Уникальный ключ (например, IP + endpoint)
   * @param config - Конфигурация правила
   * @returns Результат проверки
   */
  public async checkRateLimit(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    // Проверка блокировки
    const blockInfo = await this.getBlockInfo(key);
    if (blockInfo) {
      const now = Date.now();
      const blockEnd = blockInfo.blockedAt + blockInfo.duration * 1000;
      
      if (now < blockEnd) {
        return {
          allowed: false,
          limit: 0,
          remaining: 0,
          resetTime: Math.floor(blockEnd / 1000),
          retryAfter: Math.ceil((blockEnd - now) / 1000),
          blockReason: blockInfo.reason,
          blockDuration: blockInfo.duration,
        };
      }
      
      // Блокировка истекла - удаляем
      await this.clearBlock(key);
    }

    // Проверка в зависимости от алгоритма
    let result: RateLimitResult;

    switch (config.type) {
      case 'fixed_window':
        result = await this.checkFixedWindow(key, config);
        break;
      case 'sliding_window':
        result = await this.checkSlidingWindow(key, config);
        break;
      case 'token_bucket':
        result = await this.checkTokenBucket(key, config);
        break;
      case 'leaky_bucket':
        result = await this.checkLeakyBucket(key, config);
        break;
      default:
        result = await this.checkFixedWindow(key, config);
    }

    // Если лимит превышен - создаем блокировку
    if (!result.allowed) {
      await this.recordViolation(key, config);
    }

    return result;
  }

  /**
   * Fixed Window алгоритм
   * @private
   */
  private async checkFixedWindow(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowKey = `${this.config.keyPrefix}fw:${key}`;
    const windowMs = config.windowMs;

    let data: FixedWindowData;

    if (this.redis) {
      const rawData = await this.redis.get(windowKey);
      if (rawData) {
        data = JSON.parse(rawData);
      } else {
        data = { count: 0, resetTime: now + windowMs };
      }
    } else {
      data = this.inMemoryStore.get(windowKey) || { count: 0, resetTime: now + windowMs };
    }

    // Проверка истечения окна
    if (now >= data.resetTime) {
      data = { count: 0, resetTime: now + windowMs };
    }

    // Проверка лимита
    const allowed = data.count < config.maxRequests;
    
    if (allowed) {
      data.count++;
    }

    // Сохранение
    const ttl = Math.ceil((data.resetTime - now) / 1000);
    if (this.redis) {
      await this.redis.setex(windowKey, ttl + 1, JSON.stringify(data));
    } else {
      this.inMemoryStore.set(windowKey, data);
    }

    return {
      allowed,
      limit: config.maxRequests,
      remaining: Math.max(0, config.maxRequests - data.count),
      resetTime: Math.floor(data.resetTime / 1000),
      retryAfter: allowed ? 0 : Math.ceil((data.resetTime - now) / 1000),
    };
  }

  /**
   * Sliding Window алгоритм
   * @private
   */
  private async checkSlidingWindow(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const windowKey = `${this.config.keyPrefix}sw:${key}`;
    const windowMs = config.windowMs;
    const windowStart = now - windowMs;

    let timestamps: number[] = [];

    if (this.redis) {
      const rawData = await this.redis.get(windowKey);
      if (rawData) {
        timestamps = JSON.parse(rawData);
      }
    } else {
      timestamps = this.inMemoryStore.get(windowKey) || [];
    }

    // Удаление старых записей
    timestamps = timestamps.filter(ts => ts > windowStart);

    // Проверка лимита
    const allowed = timestamps.length < config.maxRequests;
    
    if (allowed) {
      timestamps.push(now);
    }

    // Сохранение
    if (timestamps.length > 0) {
      const oldestTimestamp = Math.min(...timestamps);
      const ttl = Math.ceil((oldestTimestamp + windowMs - now) / 1000) + 1;
      
      if (this.redis) {
        await this.redis.setex(windowKey, ttl, JSON.stringify(timestamps));
      } else {
        this.inMemoryStore.set(windowKey, timestamps);
      }
    }

    const resetTime = timestamps.length > 0 
      ? Math.floor((timestamps[0] + windowMs) / 1000)
      : Math.floor((now + windowMs) / 1000);

    return {
      allowed,
      limit: config.maxRequests,
      remaining: Math.max(0, config.maxRequests - timestamps.length),
      resetTime,
      retryAfter: allowed ? 0 : Math.ceil((timestamps[0] + windowMs - now) / 1000),
    };
  }

  /**
   * Token Bucket алгоритм
   * @private
   */
  private async checkTokenBucket(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const bucketKey = `${this.config.keyPrefix}tb:${key}`;
    
    // Расчет refill rate (токенов в мс)
    const refillRate = config.maxRequests / config.windowMs;

    let data: TokenBucketData;

    if (this.redis) {
      const rawData = await this.redis.get(bucketKey);
      if (rawData) {
        data = JSON.parse(rawData);
      } else {
        data = { tokens: config.maxRequests, lastRefill: now };
      }
    } else {
      data = this.inMemoryStore.get(bucketKey) || { tokens: config.maxRequests, lastRefill: now };
    }

    // Refill токенов
    const timePassed = now - data.lastRefill;
    const tokensToAdd = timePassed * refillRate;
    data.tokens = Math.min(config.maxRequests, data.tokens + tokensToAdd);
    data.lastRefill = now;

    // Проверка лимита
    const allowed = data.tokens >= 1;
    
    if (allowed) {
      data.tokens -= 1;
    }

    // Сохранение
    const ttl = Math.ceil(config.windowMs / 1000);
    if (this.redis) {
      await this.redis.setex(bucketKey, ttl, JSON.stringify(data));
    } else {
      this.inMemoryStore.set(bucketKey, data);
    }

    // Расчет времени до следующего токена
    const retryAfter = allowed 
      ? 0 
      : Math.ceil((1 - data.tokens) / refillRate);

    return {
      allowed,
      limit: config.maxRequests,
      remaining: Math.floor(data.tokens),
      resetTime: Math.floor((now + config.windowMs) / 1000),
      retryAfter,
    };
  }

  /**
   * Leaky Bucket алгоритм
   * @private
   */
  private async checkLeakyBucket(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const bucketKey = `${this.config.keyPrefix}lb:${key}`;
    
    // Расчет leak rate (запросов в мс)
    const leakRate = config.maxRequests / config.windowMs;

    let data: { water: number; lastLeak: number };

    if (this.redis) {
      const rawData = await this.redis.get(bucketKey);
      if (rawData) {
        data = JSON.parse(rawData);
      } else {
        data = { water: 0, lastLeak: now };
      }
    } else {
      data = this.inMemoryStore.get(bucketKey) || { water: 0, lastLeak: now };
    }

    // Leak воды
    const timePassed = now - data.lastLeak;
    const waterToLeak = timePassed * leakRate;
    data.water = Math.max(0, data.water - waterToLeak);
    data.lastLeak = now;

    // Проверка лимита (емкость ведра)
    const bucketCapacity = config.maxRequests;
    const allowed = data.water < bucketCapacity;
    
    if (allowed) {
      data.water += 1;
    }

    // Сохранение
    const ttl = Math.ceil(config.windowMs / 1000);
    if (this.redis) {
      await this.redis.setex(bucketKey, ttl, JSON.stringify(data));
    } else {
      this.inMemoryStore.set(bucketKey, data);
    }

    // Расчет времени до освобождения места
    const retryAfter = allowed
      ? 0
      : Math.ceil((data.water - bucketCapacity) / leakRate);

    return {
      allowed,
      limit: bucketCapacity,
      remaining: Math.max(0, bucketCapacity - Math.floor(data.water)),
      resetTime: Math.floor((now + config.windowMs) / 1000),
      retryAfter: Math.max(0, retryAfter),
    };
  }

  // ===========================================================================
  // БЛОКИРОВКИ
  // ===========================================================================

  /**
   * Создает блокировку для ключа
   * @param key - Уникальный ключ
   * @param reason - Причина блокировки
   * @param duration - Длительность (секунды)
   */
  public async block(
    key: string,
    reason: string,
    duration: number = this.config.blockDuration
  ): Promise<void> {
    const blockInfo: BlockInfo = {
      reason,
      blockedAt: Date.now(),
      duration: Math.min(duration, this.config.maxBlockDuration),
      violationCount: (this.violationCounts.get(key) || 0) + 1,
    };

    const blockKey = `${this.config.keyPrefix}block:${key}`;
    
    if (this.redis) {
      await this.redis.setex(blockKey, blockInfo.duration, JSON.stringify(blockInfo));
    } else {
      this.blockStore.set(key, blockInfo);
    }

    this.violationCounts.set(key, blockInfo.violationCount);

    logger.info(`[RateLimiter] Blocked ${key}`, {
      duration: blockInfo.duration,
      reason,
      violationCount: blockInfo.violationCount
    });
  }

  /**
   * Проверяет наличие блокировки
   * @param key - Уникальный ключ
   * @returns Информация о блокировке или null
   */
  public async getBlockInfo(key: string): Promise<BlockInfo | null> {
    const blockKey = `${this.config.keyPrefix}block:${key}`;
    
    if (this.redis) {
      const rawData = await this.redis.get(blockKey);
      if (rawData) {
        return JSON.parse(rawData);
      }
    } else {
      const blockInfo = this.blockStore.get(key);
      if (blockInfo) {
        const now = Date.now();
        if (now < blockInfo.blockedAt + blockInfo.duration * 1000) {
          return blockInfo;
        }
        this.blockStore.delete(key);
      }
    }

    return null;
  }

  /**
   * Удаляет блокировку
   * @param key - Уникальный ключ
   */
  public async clearBlock(key: string): Promise<void> {
    const blockKey = `${this.config.keyPrefix}block:${key}`;
    
    if (this.redis) {
      await this.redis.del(blockKey);
    } else {
      this.blockStore.delete(key);
    }
  }

  /**
   * Записывает нарушение rate limit
   * @private
   */
  private async recordViolation(
    key: string,
    config: RateLimitConfig
  ): Promise<void> {
    const currentViolations = this.violationCounts.get(key) || 0;
    const newViolations = currentViolations + 1;
    this.violationCounts.set(key, newViolations);

    // Прогрессивная блокировка
    const progressiveDuration = Math.min(
      this.config.blockDuration * Math.pow(
        this.config.progressiveBlockMultiplier,
        newViolations - 1
      ),
      this.config.maxBlockDuration
    );

    // Блокируем после определенного количества нарушений
    if (newViolations >= 3) {
      await this.block(key, `Rate limit exceeded (${config.name})`, progressiveDuration);
    }
  }

  // ===========================================================================
  // ПРЕДОПРЕДЕЛЕННЫЕ ПРАВИЛА
  // ===========================================================================

  /**
   * Создает правило для аутентификации (login attempts)
   * @param identifier - Идентификатор (email, IP)
   * @returns Конфигурация правила
   */
  public createAuthRule(identifier: string): RateLimitConfig {
    return {
      name: 'auth',
      type: 'fixed_window',
      maxRequests: this.config.defaultRules.authLimit,
      windowMs: 60000, // 1 минута
      keyGenerator: () => this.hashKey(`auth:${identifier}`),
      message: 'Слишком много попыток входа',
      statusCode: 429,
      headers: true,
    };
  }

  /**
   * Создает правило для password reset
   * @param identifier - Идентификатор (email, IP)
   * @returns Конфигурация правила
   */
  public createPasswordResetRule(identifier: string): RateLimitConfig {
    return {
      name: 'password_reset',
      type: 'sliding_window',
      maxRequests: this.config.defaultRules.passwordResetLimit,
      windowMs: 3600000, // 1 час
      keyGenerator: () => this.hashKey(`pwd_reset:${identifier}`),
      message: 'Слишком много запросов сброса пароля',
      statusCode: 429,
      headers: true,
    };
  }

  /**
   * Создает правило для MFA verification
   * @param identifier - Идентификатор (userId, sessionId)
   * @returns Конфигурация правила
   */
  public createMfaRule(identifier: string): RateLimitConfig {
    return {
      name: 'mfa',
      type: 'fixed_window',
      maxRequests: this.config.defaultRules.mfaLimit,
      windowMs: 60000, // 1 минута
      keyGenerator: () => this.hashKey(`mfa:${identifier}`),
      message: 'Слишком много попыток верификации MFA',
      statusCode: 429,
      headers: true,
    };
  }

  /**
   * Создает правило для API endpoints
   * @param identifier - Идентификатор (IP, userId, apiKey)
   * @returns Конфигурация правила
   */
  public createApiRule(identifier: string): RateLimitConfig {
    return {
      name: 'api',
      type: 'token_bucket',
      maxRequests: this.config.defaultRules.apiLimit,
      windowMs: 60000, // 1 минута
      keyGenerator: () => this.hashKey(`api:${identifier}`),
      message: 'Слишком много запросов к API',
      statusCode: 429,
      headers: true,
    };
  }

  /**
   * Создает правило для защиты от credential stuffing
   * @param ip - IP адрес
   * @returns Конфигурация правила
   */
  public createCredentialStuffingRule(ip: string): RateLimitConfig {
    return {
      name: 'credential_stuffing',
      type: 'sliding_window',
      maxRequests: 10, // 10 разных аккаунтов
      windowMs: 300000, // 5 минут
      keyGenerator: () => this.hashKey(`cred_stuff:${ip}`),
      message: 'Подозрительная активность',
      statusCode: 429,
      headers: true,
    };
  }

  // ===========================================================================
  // DETECTION
  // ===========================================================================

  /**
   * Обнаруживает brute-force атаку
   * @param identifier - Идентификатор (email, IP)
   * @param threshold - Порог срабатывания
   * @returns Обнаружена ли атака
   */
  public async detectBruteForce(
    identifier: string,
    threshold: number = 10
  ): Promise<{ detected: boolean; attempts: number }> {
    const key = `brute:${identifier}`;
    const attempts = await this.getViolationCount(key);
    
    return {
      detected: attempts >= threshold,
      attempts,
    };
  }

  /**
   * Обнаружает credential stuffing атаку
   * @param ip - IP адрес
   * @param uniqueEmails - Количество уникальных email
   * @returns Обнаружена ли атака
   */
  public async detectCredentialStuffing(
    ip: string,
    uniqueEmails: number
  ): Promise<{ detected: boolean; threshold: number }> {
    const threshold = 5; // 5 разных аккаунтов с одного IP
    
    return {
      detected: uniqueEmails >= threshold,
      threshold,
    };
  }

  /**
   * Обнаруживает account takeover попытку
   * @param userId - ID пользователя
   * @param newDevice - Новое устройство
   * @param newLocation - Новая локация
   * @returns Обнаружена ли попытка
   */
  public detectAccountTakeover(
    userId: string,
    newDevice: boolean,
    newLocation: boolean
  ): { detected: boolean; riskScore: number; factors: string[] } {
    let riskScore = 0;
    const factors: string[] = [];

    if (newDevice) {
      riskScore += 40;
      factors.push('Новое устройство');
    }

    if (newLocation) {
      riskScore += 40;
      factors.push('Новая геолокация');
    }

    // Проверка скорости перемещения (impossible travel)
    // В production реализовать проверку расстояния и времени

    return {
      detected: riskScore >= 70,
      riskScore,
      factors,
    };
  }

  /**
   * Получает количество нарушений
   * @private
   */
  private async getViolationCount(key: string): Promise<number> {
    if (this.redis) {
      const count = await this.redis.get(`${this.config.keyPrefix}violations:${key}`);
      return count ? parseInt(count, 10) : 0;
    }
    return this.violationCounts.get(key) || 0;
  }

  // ===========================================================================
  // УТИЛИТЫ
  // ===========================================================================

  /**
   * Хэширует ключ для использования в Redis
   * @private
   */
  private hashKey(key: string): string {
    return createHash('sha256').update(key).digest('hex').slice(0, 16);
  }

  /**
   * Получает статистику rate limiting
   * @param key - Уникальный ключ
   * @param config - Конфигурация правила
   * @returns Статистика
   */
  public async getStats(
    key: string,
    config: RateLimitConfig
  ): Promise<RateLimitStats> {
    const result = await this.checkRateLimit(key, config);
    
    return {
      key,
      requestCount: config.maxRequests - result.remaining,
      maxRequests: config.maxRequests,
      remaining: result.remaining,
      resetTime: result.resetTime,
      retryAfter: result.retryAfter,
    };
  }

  /**
   * Сбрасывает счетчики для ключа
   * @param key - Уникальный ключ
   */
  public async reset(key: string): Promise<void> {
    const patterns = [
      `${this.config.keyPrefix}fw:${key}`,
      `${this.config.keyPrefix}sw:${key}`,
      `${this.config.keyPrefix}tb:${key}`,
      `${this.config.keyPrefix}lb:${key}`,
    ];

    if (this.redis) {
      for (const pattern of patterns) {
        await this.redis.del(pattern);
      }
    } else {
      for (const pattern of patterns) {
        this.inMemoryStore.delete(pattern);
      }
    }

    this.violationCounts.delete(key);
  }

  /**
   * Закрывает соединение с Redis
   */
  public async destroy(): Promise<void> {
    if (this.redis) {
      await this.redis.quit();
      this.redis = null;
    }
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const rateLimiterService = new RateLimiterService(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createRateLimiterService(
  config: Partial<RateLimiterConfig>
): RateLimiterService {
  return new RateLimiterService({ ...DEFAULT_CONFIG, ...config });
}
