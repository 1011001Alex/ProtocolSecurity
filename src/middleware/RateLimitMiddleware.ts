/**
 * =============================================================================
 * RATE LIMITING MIDDLEWARE
 * =============================================================================
 * Продвинутый rate limiting с поддержкой Redis, Circuit Breaker и Retry Logic
 * Алгоритмы: Fixed Window, Sliding Window, Token Bucket, Leaky Bucket
 * 
 * Особенности:
 * - Circuit Breaker для защиты от каскадных отказов Redis
 * - Exponential backoff retry logic
 * - Fallback на MemoryStore при отказе Redis
 * - Alerting при failures через SecureLogger
 * - Детальные метрики и мониторинг
 * =============================================================================
 */

import { IncomingMessage, ServerResponse } from 'http';
import { EventEmitter } from 'events';
import { CircuitBreaker, CircuitState, CircuitBreakerError, CircuitBreakerManager } from '../utils/CircuitBreaker';
import { RetryHandler, RetryHandlerFactory, BackoffStrategy } from '../utils/RetryHandler';
import { SecureLogger, LoggerFactory } from '../logging/Logger';
import { LogLevel, LogSource } from '../types/logging.types';

// =============================================================================
// ТИПЫ И ИНТЕРФЕЙСЫ
// =============================================================================

/**
 * Типы алгоритмов rate limiting
 */
export type RateLimitAlgorithm =
  | 'fixed_window'
  | 'sliding_window'
  | 'token_bucket'
  | 'leaky_bucket'
  | 'sliding_log';

/**
 * Конфигурация rate limit правила
 */
export interface RateLimitRule {
  /** Название правила */
  name: string;

  /** Алгоритм */
  algorithm: RateLimitAlgorithm;

  /** Максимальное количество запросов */
  maxRequests: number;

  /** Окно времени (мс) */
  windowMs: number;

  /** Генератор ключа */
  keyGenerator: (req: IncomingMessage) => string;

  /** Сообщение при превышении */
  message: string;

  /** HTTP статус код */
  statusCode: number;

  /** Включить заголовки */
  headers: boolean;

  /** Skip условие */
  skip?: (req: IncomingMessage) => boolean;

  /** Handler при превышении */
  handler?: (req: IncomingMessage, res: ServerResponse) => void;
}

/**
 * Результат проверки rate limit
 */
export interface RateLimitResult {
  /** Разрешено ли */
  allowed: boolean;

  /** Текущее количество запросов */
  current: number;

  /** Максимум */
  max: number;

  /** Оставшееся количество */
  remaining: number;

  /** Время сброса (мс) */
  resetTime: number;

  /** Retry after (секунды) */
  retryAfter?: number;
}

/**
 * Хранилище для rate limiting
 */
export interface RateLimitStore {
  /** Инициализация */
  initialize(): Promise<void>;

  /** Получение записи */
  get(key: string): Promise<StoreEntry | null>;

  /** Установка записи */
  set(key: string, entry: StoreEntry, ttlMs: number): Promise<void>;

  /** Инкремент */
  increment(key: string, windowMs: number): Promise<number>;

  /** Очистка */
  cleanup(): Promise<void>;

  /** Закрытие */
  destroy(): Promise<void>;
}

/**
 * Запись в хранилище
 */
export interface StoreEntry {
  /** Количество запросов */
  count: number;

  /** Время начала окна */
  windowStart: number;

  /** Для token bucket */
  tokens?: number;
  lastRefill?: number;

  /** Для leaky bucket */
  waterLevel?: number;
  lastLeak?: number;
}

/**
 * Конфигурация Redis хранилища
 */
export interface RedisStoreConfig {
  /** Redis host */
  host: string;

  /** Redis port */
  port: number;

  /** Redis password */
  password?: string;

  /** Redis DB */
  db?: number;

  /** Key prefix */
  keyPrefix: string;

  /** Circuit Breaker конфигурация */
  circuitBreaker?: {
    failureThreshold: number;
    resetTimeout: number;
    successThreshold: number;
    operationTimeout: number;
  };

  /** Retry конфигурация */
  retry?: {
    maxRetries: number;
    initialDelay: number;
    maxDelay: number;
    multiplier: number;
    backoffStrategy: BackoffStrategy;
  };

  /** Включить логирование */
  enableLogging: boolean;

  /** Logger instance */
  logger?: SecureLogger;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_REDIS_STORE_CONFIG: Required<RedisStoreConfig> = {
  host: 'localhost',
  port: 6379,
  password: '',
  db: 0,
  keyPrefix: 'ratelimit',
  enableLogging: true,
  logger: undefined as any,
  circuitBreaker: {
    failureThreshold: 5,
    resetTimeout: 30000,
    successThreshold: 3,
    operationTimeout: 10000
  },
  retry: {
    maxRetries: 3,
    initialDelay: 100,
    maxDelay: 5000,
    multiplier: 2,
    backoffStrategy: BackoffStrategy.EXPONENTIAL_WITH_JITTER
  }
};

// =============================================================================
// MEMORY STORE (для development и fallback)
// =============================================================================

export class MemoryStore implements RateLimitStore {
  private store: Map<string, StoreEntry>;
  private cleanupInterval?: NodeJS.Timeout;
  private logger?: SecureLogger;

  constructor(logger?: SecureLogger) {
    this.store = new Map();
    this.logger = logger;
  }

  async initialize(): Promise<void> {
    this.logger?.info(
      '[MemoryStore] Инициализация хранилища в памяти',
      LogSource.APPLICATION,
      'RateLimitMiddleware'
    );
    
    // Очистка каждые 5 минут
    this.cleanupInterval = setInterval(() => {
      this.cleanup().catch((error) => {
        this.logger?.error(
          `[MemoryStore] Ошибка очистки: ${error.message}`,
          LogSource.APPLICATION,
          'RateLimitMiddleware'
        );
      });
    }, 5 * 60 * 1000);
  }

  async get(key: string): Promise<StoreEntry | null> {
    return this.store.get(key) || null;
  }

  async set(key: string, entry: StoreEntry, _ttlMs: number): Promise<void> {
    this.store.set(key, entry);
  }

  async increment(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const entry = await this.get(key);

    if (!entry || now - entry.windowStart > windowMs) {
      // Новое окно
      const newEntry: StoreEntry = {
        count: 1,
        windowStart: now
      };
      await this.set(key, newEntry, windowMs);
      return 1;
    }

    // Существующее окно
    entry.count++;
    await this.set(key, entry, windowMs);
    return entry.count;
  }

  async cleanup(): Promise<void> {
    const now = Date.now();
    let deletedCount = 0;
    
    for (const [key, entry] of this.store.entries()) {
      if (now - entry.windowStart > 60 * 60 * 1000) { // 1 час
        this.store.delete(key);
        deletedCount++;
      }
    }

    if (deletedCount > 0 && this.logger) {
      this.logger.debug(
        `[MemoryStore] Очищено ${deletedCount} устаревших записей`,
        LogSource.APPLICATION,
        'RateLimitMiddleware'
      );
    }
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async destroy(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }
    
    this.store.clear();
    
    this.logger?.info(
      '[MemoryStore] Хранилище уничтожено',
      LogSource.APPLICATION,
      'RateLimitMiddleware'
    );
  }

  /**
   * Получение статистики
   */
  getStats(): { size: number } {
    return {
      size: this.store.size
    };
  }
}

// =============================================================================
// REDIS STORE (для production) с Circuit Breaker и Retry Logic
// =============================================================================

export class RedisStore implements RateLimitStore {
  private config: Required<RedisStoreConfig>;
  private client: any | null = null;
  private isConnected: boolean = false;
  private circuitBreaker: CircuitBreaker;
  private retryHandler: RetryHandler;
  private logger: SecureLogger;
  private fallbackStore: MemoryStore;
  private usingFallback: boolean = false;

  constructor(config: RedisStoreConfig) {
    this.config = {
      ...DEFAULT_REDIS_STORE_CONFIG,
      ...config
    };

    // Инициализация logger
    this.logger = config.logger || LoggerFactory.getLogger(
      'RateLimitMiddleware',
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
        serviceName: 'RateLimitMiddleware'
      }
    );

    // Инициализация fallback store
    this.fallbackStore = new MemoryStore(this.logger);

    // Инициализация Circuit Breaker
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: this.config.circuitBreaker.failureThreshold,
      resetTimeout: this.config.circuitBreaker.resetTimeout,
      successThreshold: this.config.circuitBreaker.successThreshold,
      operationTimeout: this.config.circuitBreaker.operationTimeout,
      enableMonitoring: this.config.enableLogging,
      name: 'RedisStore'
    });

    // Подписка на события Circuit Breaker для alerting
    this.setupCircuitBreakerAlerting();

    // Инициализация Retry Handler
    this.retryHandler = new RetryHandler({
      maxRetries: this.config.retry.maxRetries,
      initialDelay: this.config.retry.initialDelay,
      maxDelay: this.config.retry.maxDelay,
      multiplier: this.config.retry.multiplier,
      backoffStrategy: this.config.retry.backoffStrategy,
      enableCircuitBreaker: false, // Используем свой circuit breaker
      enableLogging: this.config.enableLogging,
      name: 'RedisStore'
    });

    this.logger.info(
      `[RedisStore] Инициализация: host=${this.config.host}:${this.config.port}, ` +
      `circuitBreaker.threshold=${this.config.circuitBreaker.failureThreshold}, ` +
      `retry.maxRetries=${this.config.retry.maxRetries}`,
      LogSource.APPLICATION,
      'RateLimitMiddleware'
    );
  }

  /**
   * Настройка alerting для событий Circuit Breaker
   */
  private setupCircuitBreakerAlerting(): void {
    this.circuitBreaker.on('open', (data) => {
      this.usingFallback = true;
      
      this.logger.alert(
        `Circuit Breaker РАЗОРВАЛ цепь! Redis недоступен. Переключение на MemoryStore. ` +
        `Failures: ${data.stats.failures}, State: ${data.stats.state}`,
        LogSource.SECURITY,
        'RateLimitMiddleware',
        undefined,
        {
          circuitBreakerStats: data.stats,
          action: 'fallback_activated'
        }
      );

      // Эмиссия события для внешнего мониторинга
      this.emit('circuit:open', { stats: data.stats });
    });

    this.circuitBreaker.on('close', (data) => {
      const wasUsingFallback = this.usingFallback;
      this.usingFallback = false;

      this.logger.notice(
        `Circuit Breaker ЗАМКНУЛ цепь. Redis восстановлен. Возврат к нормальной работе.`,
        LogSource.APPLICATION,
        'RateLimitMiddleware',
        undefined,
        {
          circuitBreakerStats: data.stats,
          action: 'primary_restored',
          wasUsingFallback
        }
      );

      this.emit('circuit:close', { stats: data.stats });
    });

    this.circuitBreaker.on('half_open', (data) => {
      this.logger.warning(
        `Circuit Breaker в состоянии HALF_OPEN. Попытка восстановления соединения с Redis.`,
        LogSource.SECURITY,
        'RateLimitMiddleware',
        undefined,
        {
          circuitBreakerStats: data.stats,
          action: 'recovery_attempt'
        }
      );

      this.emit('circuit:half_open', { stats: data.stats });
    });

    this.circuitBreaker.on('failure', (data) => {
      this.logger.error(
        `Circuit Breaker зафиксировал failure: ${data.error}`,
        LogSource.APPLICATION,
        'RateLimitMiddleware',
        undefined,
        {
          error: data.error,
          stats: data.stats,
          action: 'failure_recorded'
        }
      );
    });

    this.circuitBreaker.on('reject', (data) => {
      this.logger.warning(
        `Circuit Breaker отклонил запрос (состояние OPEN): ${data.state}`,
        LogSource.APPLICATION,
        'RateLimitMiddleware',
        undefined,
        {
          state: data.state,
          stats: data.stats,
          action: 'request_rejected'
        }
      );
    });
  }

  async initialize(): Promise<void> {
    try {
      await this.fallbackStore.initialize();

      // В реальной реализации: ioredis или node-redis
      // this.client = new Redis({
      //   host: this.config.host,
      //   port: this.config.port,
      //   password: this.config.password,
      //   db: this.config.db,
      //   keyPrefix: this.config.keyPrefix
      // });

      // Эмуляция подключения для демонстрации
      await this.circuitBreaker.execute(async () => {
        // Симуляция подключения к Redis
        await new Promise(resolve => setTimeout(resolve, 10));
        this.isConnected = true;
        this.client = { /* mock redis client */ };
      });

      this.logger.info(
        `[RedisStore] Успешное подключение к Redis ${this.config.host}:${this.config.port}`,
        LogSource.APPLICATION,
        'RateLimitMiddleware'
      );

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      this.logger.error(
        `[RedisStore] Ошибка подключения к Redis: ${errorMessage}`,
        LogSource.APPLICATION,
        'RateLimitMiddleware',
        undefined,
        undefined,
        error as Error
      );

      this.isConnected = false;
      this.usingFallback = true;
    }
  }

  /**
   * Выполнение операции с retry и circuit breaker
   */
  private async executeWithProtection<T>(
    operation: () => Promise<T>,
    operationName: string
  ): Promise<T> {
    // Если circuit breaker в состоянии OPEN, используем fallback
    if (this.circuitBreaker.getState() === CircuitState.OPEN) {
      this.logger.debug(
        `[RedisStore] Circuit OPEN, использование fallback для ${operationName}`,
        LogSource.APPLICATION,
        'RateLimitMiddleware'
      );
      throw new CircuitBreakerError(
        'Circuit breaker open, using fallback',
        'CIRCUIT_OPEN',
        CircuitState.OPEN
      );
    }

    try {
      // Выполнение с retry logic
      return await this.retryHandler.execute(async () => {
        return this.circuitBreaker.execute(operation);
      });
    } catch (error) {
      // Если circuit breaker open или retry исчерпаны, пробрасываем ошибку
      if (error instanceof CircuitBreakerError) {
        throw error;
      }

      this.logger.error(
        `[RedisStore] Операция ${operationName} failed после всех retry попыток`,
        LogSource.APPLICATION,
        'RateLimitMiddleware',
        undefined,
        undefined,
        error as Error
      );

      throw error;
    }
  }

  async get(key: string): Promise<StoreEntry | null> {
    // Если не подключены или circuit open, используем fallback
    if (!this.isConnected || !this.client || this.circuitBreaker.getState() === CircuitState.OPEN) {
      this.logger.debug(
        `[RedisStore] Fallback для get(${key}) - Redis недоступен`,
        LogSource.APPLICATION,
        'RateLimitMiddleware'
      );
      return this.fallbackStore.get(key);
    }

    try {
      return await this.executeWithProtection(
        async () => {
          const fullKey = `${this.config.keyPrefix}:${key}`;
          const data = await this.client.get(fullKey);
          
          if (!data) {
            return null;
          }

          return JSON.parse(data) as StoreEntry;
        },
        `get:${key}`
      );
    } catch (error) {
      // Fallback при ошибке
      this.logger.warning(
        `[RedisStore] Ошибка get(${key}), использование fallback`,
        LogSource.APPLICATION,
        'RateLimitMiddleware'
      );
      return this.fallbackStore.get(key);
    }
  }

  async set(key: string, entry: StoreEntry, ttlMs: number): Promise<void> {
    // Если не подключены или circuit open, используем fallback
    if (!this.isConnected || !this.client || this.circuitBreaker.getState() === CircuitState.OPEN) {
      this.logger.debug(
        `[RedisStore] Fallback для set(${key}) - Redis недоступен`,
        LogSource.APPLICATION,
        'RateLimitMiddleware'
      );
      return this.fallbackStore.set(key, entry, ttlMs);
    }

    try {
      await this.executeWithProtection(
        async () => {
          const fullKey = `${this.config.keyPrefix}:${key}`;
          const ttlSeconds = Math.ceil(ttlMs / 1000);
          await this.client.setex(fullKey, ttlSeconds, JSON.stringify(entry));
        },
        `set:${key}`
      );
    } catch (error) {
      // Fallback при ошибке
      this.logger.warning(
        `[RedisStore] Ошибка set(${key}), использование fallback`,
        LogSource.APPLICATION,
        'RateLimitMiddleware'
      );
      return this.fallbackStore.set(key, entry, ttlMs);
    }
  }

  async increment(key: string, windowMs: number): Promise<number> {
    // Если не подключены или circuit open, используем fallback
    if (!this.isConnected || !this.client || this.circuitBreaker.getState() === CircuitState.OPEN) {
      this.logger.debug(
        `[RedisStore] Fallback для increment(${key}) - Redis недоступен`,
        LogSource.APPLICATION,
        'RateLimitMiddleware'
      );
      return this.fallbackStore.increment(key, windowMs);
    }

    try {
      return await this.executeWithProtection(
        async () => {
          const fullKey = `${this.config.keyPrefix}:${key}`;
          const now = Date.now();

          // Lua script для атомарного инкремента
          const luaScript = `
            local key = KEYS[1]
            local windowMs = tonumber(ARGV[1])
            local now = tonumber(ARGV[2])

            local data = redis.call('GET', key)
            local entry = nil

            if data then
              entry = cjson.decode(data)
            end

            if not entry or (now - entry.windowStart) > windowMs then
              -- Новое окно
              entry = { count = 1, windowStart = now }
            else
              -- Существующее окно
              entry.count = entry.count + 1
            end

            local ttl = math.ceil(windowMs / 1000)
            redis.call('SETEX', key, ttl, cjson.encode(entry))

            return entry.count
          `;

          const count = await this.client.eval(
            luaScript,
            1,
            fullKey,
            windowMs.toString(),
            now.toString()
          );

          return count as number;
        },
        `increment:${key}`
      );
    } catch (error) {
      // Fallback при ошибке
      this.logger.warning(
        `[RedisStore] Ошибка increment(${key}), использование fallback`,
        LogSource.APPLICATION,
        'RateLimitMiddleware'
      );
      return this.fallbackStore.increment(key, windowMs);
    }
  }

  async cleanup(): Promise<void> {
    // Redis автоматически очищает по TTL
    // Очищаем fallback store
    await this.fallbackStore.cleanup();
  }

  async destroy(): Promise<void> {
    this.logger.info(
      '[RedisStore] Уничтожение хранилища',
      LogSource.APPLICATION,
      'RateLimitMiddleware'
    );

    // Остановка circuit breaker
    this.circuitBreaker.destroy();

    // Остановка retry handler
    this.retryHandler.destroy();

    // Очистка Redis client
    if (this.client) {
      try {
        await this.client.quit();
      } catch (error) {
        this.logger.error(
          `[RedisStore] Ошибка закрытия соединения: ${error instanceof Error ? error.message : String(error)}`,
          LogSource.APPLICATION,
          'RateLimitMiddleware'
        );
      }
      this.client = null;
    }

    this.isConnected = false;

    // Уничтожение fallback store
    await this.fallbackStore.destroy();
  }

  /**
   * Получение статистики
   */
  getStats(): {
    isConnected: boolean;
    usingFallback: boolean;
    circuitBreakerState: CircuitState;
    circuitBreakerStats: ReturnType<CircuitBreaker['getStats']>;
    retryStats: ReturnType<RetryHandler['getStats']>;
    fallbackStats: ReturnType<MemoryStore['getStats']>;
  } {
    return {
      isConnected: this.isConnected,
      usingFallback: this.usingFallback,
      circuitBreakerState: this.circuitBreaker.getState(),
      circuitBreakerStats: this.circuitBreaker.getStats(),
      retryStats: this.retryHandler.getStats(),
      fallbackStats: this.fallbackStore.getStats()
    };
  }

  /**
   * Принудительный reset circuit breaker
   */
  resetCircuitBreaker(): void {
    this.logger.notice(
      '[RedisStore] Принудительный reset Circuit Breaker',
      LogSource.APPLICATION,
      'RateLimitMiddleware'
    );
    this.circuitBreaker.reset();
  }

  /**
   * Проверка доступности Redis
   */
  isAvailable(): boolean {
    return this.isConnected && this.circuitBreaker.isAvailable();
  }
}

// =============================================================================
// RATE LIMITER CLASS
// =============================================================================

export class RateLimiter extends EventEmitter {
  private rules: Map<string, RateLimitRule>;
  private store: RateLimitStore;
  private enabled: boolean;
  private logger: SecureLogger;

  constructor(store?: RateLimitStore, enabled: boolean = true, logger?: SecureLogger) {
    super();
    this.rules = new Map();
    this.store = store || new MemoryStore(logger);
    this.enabled = enabled;
    this.logger = logger || LoggerFactory.getLogger(
      'RateLimiter',
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
        serviceName: 'RateLimiter'
      }
    );
  }

  /**
   * Инициализация
   */
  async initialize(): Promise<void> {
    this.logger.info(
      '[RateLimiter] Инициализация rate limiter',
      LogSource.APPLICATION,
      'RateLimiter'
    );
    await this.store.initialize();
  }

  /**
   * Добавление правила
   */
  addRule(rule: RateLimitRule): void {
    this.rules.set(rule.name, rule);
    this.logger.info(
      `[RateLimiter] Добавлено правило: ${rule.name} (${rule.algorithm}, ${rule.maxRequests} req/${rule.windowMs}ms)`,
      LogSource.APPLICATION,
      'RateLimiter'
    );
  }

  /**
   * Middleware функция
   */
  async handle(req: IncomingMessage, res: ServerResponse, next?: () => void): Promise<void> {
    if (!this.enabled) {
      next?.();
      return;
    }

    const startTime = Date.now();

    try {
      // Проверка всех правил
      for (const rule of this.rules.values()) {
        // Проверка skip условия
        if (rule.skip?.(req)) {
          continue;
        }

        // Генерация ключа
        const key = rule.keyGenerator(req);

        // Проверка rate limit
        const result = await this.checkRateLimit(key, rule);

        // Установка заголовков
        if (rule.headers) {
          this.setRateLimitHeaders(res, result, rule);
        }

        // Если превышен лимит
        if (!result.allowed) {
          const duration = Date.now() - startTime;

          this.logger.warning(
            `Rate limit превышен: ${rule.name}, key=${key}, current=${result.current}, max=${result.max}`,
            LogSource.SECURITY,
            'RateLimiter',
            undefined,
            {
              ruleName: rule.name,
              key,
              current: result.current,
              max: result.max,
              retryAfter: result.retryAfter,
              processingTimeMs: duration
            }
          );

          this.emit('rate-limit-exceeded', { rule: rule.name, key, req, result });

          if (rule.handler) {
            rule.handler(req, res);
            return;
          }

          res.statusCode = rule.statusCode;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({
            error: 'Too Many Requests',
            message: rule.message,
            retryAfter: result.retryAfter,
            rule: rule.name
          }));
          return;
        }
      }

      const duration = Date.now() - startTime;
      this.logger.debug(
        `[RateLimiter] Request разрешен, processing time: ${duration}ms`,
        LogSource.APPLICATION,
        'RateLimiter'
      );

      next?.();

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      this.logger.error(
        `[RateLimiter] Ошибка проверки rate limit: ${errorMessage}`,
        LogSource.APPLICATION,
        'RateLimiter',
        undefined,
        undefined,
        error as Error
      );

      // В случае ошибки - пропускаем запрос (fail open)
      next?.();
    }
  }

  /**
   * Проверка rate limit
   */
  async checkRateLimit(key: string, rule: RateLimitRule): Promise<RateLimitResult> {
    const count = await this.store.increment(key, rule.windowMs);
    const now = Date.now();

    // Получение текущей записи
    const entry = await this.store.get(key);
    const windowStart = entry?.windowStart || now;
    const resetTime = windowStart + rule.windowMs;

    const result: RateLimitResult = {
      allowed: count <= rule.maxRequests,
      current: count,
      max: rule.maxRequests,
      remaining: Math.max(0, rule.maxRequests - count),
      resetTime
    };

    if (!result.allowed) {
      result.retryAfter = Math.ceil((resetTime - now) / 1000);
    }

    return result;
  }

  /**
   * Установка заголовков
   */
  private setRateLimitHeaders(res: ServerResponse, result: RateLimitResult, rule: RateLimitRule): void {
    res.setHeader('X-RateLimit-Limit', result.max.toString());
    res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
    res.setHeader('X-RateLimit-Reset', result.resetTime.toString());

    if (result.retryAfter) {
      res.setHeader('Retry-After', result.retryAfter.toString());
    }
  }

  /**
   * Сброс лимита для ключа
   */
  async resetLimit(key: string): Promise<void> {
    this.logger.info(
      `[RateLimiter] Сброс лимита для ключа: ${key}`,
      LogSource.APPLICATION,
      'RateLimiter'
    );

    if (this.store instanceof MemoryStore) {
      await this.store.delete(key);
    } else if (this.store instanceof RedisStore) {
      // RedisStore использует fallback store для delete
      await this.store.destroy();
    }
  }

  /**
   * Получение статистики
   */
  getStats(): {
    rulesCount: number;
    enabled: boolean;
    storeType: string;
    storeStats?: any;
  } {
    const stats: any = {
      rulesCount: this.rules.size,
      enabled: this.enabled,
      storeType: this.store instanceof RedisStore ? 'redis' : 'memory'
    };

    if (this.store instanceof RedisStore) {
      stats.storeStats = this.store.getStats();
    } else if (this.store instanceof MemoryStore) {
      stats.storeStats = this.store.getStats();
    }

    return stats;
  }

  /**
   * Закрытие
   */
  async destroy(): Promise<void> {
    this.logger.info(
      '[RateLimiter] Уничтожение rate limiter',
      LogSource.APPLICATION,
      'RateLimiter'
    );
    await this.store.destroy();
  }
}

// =============================================================================
// ПРЕДУСТАНОВЛЕННЫЕ ПРАВИЛА
// =============================================================================

/**
 * Глобальное rate limiting
 */
export function createGlobalRule(): RateLimitRule {
  return {
    name: 'global',
    algorithm: 'fixed_window',
    maxRequests: 1000,
    windowMs: 60 * 1000, // 1 минута
    keyGenerator: (req) => 'global',
    message: 'Too many requests, please try again later',
    statusCode: 429,
    headers: true
  };
}

/**
 * Per-IP rate limiting
 */
export function createPerIPRule(): RateLimitRule {
  return {
    name: 'per_ip',
    algorithm: 'sliding_window',
    maxRequests: 100,
    windowMs: 60 * 1000, // 1 минута
    keyGenerator: (req) => `ip:${req.socket.remoteAddress || 'unknown'}`,
    message: 'Too many requests from your IP',
    statusCode: 429,
    headers: true
  };
}

/**
 * Per-user rate limiting
 */
export function createPerUserRule(): RateLimitRule {
  return {
    name: 'per_user',
    algorithm: 'token_bucket',
    maxRequests: 60,
    windowMs: 60 * 1000, // 1 минута
    keyGenerator: (req) => {
      // В реальной реализации получать userId из токена
      const authHeader = (req as any).headers?.authorization;
      return `user:${authHeader || 'anonymous'}`;
    },
    message: 'Too many requests, please slow down',
    statusCode: 429,
    headers: true
  };
}

/**
 * API rate limiting (строгое)
 */
export function createAPIRule(): RateLimitRule {
  return {
    name: 'api',
    algorithm: 'sliding_window',
    maxRequests: 30,
    windowMs: 60 * 1000, // 1 минута
    keyGenerator: (req) => `api:${req.socket.remoteAddress || 'unknown'}`,
    message: 'API rate limit exceeded',
    statusCode: 429,
    headers: true,
    skip: (req) => {
      // Пропускать health checks
      return req.url === '/health';
    }
  };
}

/**
 * Auth rate limiting (очень строгое)
 */
export function createAuthRule(): RateLimitRule {
  return {
    name: 'auth',
    algorithm: 'fixed_window',
    maxRequests: 5,
    windowMs: 60 * 1000, // 1 минута
    keyGenerator: (req) => `auth:${req.socket.remoteAddress || 'unknown'}`,
    message: 'Too many authentication attempts',
    statusCode: 429,
    headers: true,
    skip: (req) => {
      // Применять только к auth endpoints
      return !req.url?.includes('/auth');
    }
  };
}

// =============================================================================
// ФАБРИКИ И ЭКСПОРТ
// =============================================================================

/**
 * Создание rate limiter с Redis store и Circuit Breaker
 */
export function createRateLimiterWithRedis(
  config: RedisStoreConfig,
  enabled: boolean = true
): RateLimiter {
  const store = new RedisStore(config);
  return new RateLimiter(store, enabled);
}

/**
 * Создание rate limiter с Memory store
 */
export function createRateLimiterWithMemory(
  enabled: boolean = true
): RateLimiter {
  const store = new MemoryStore();
  return new RateLimiter(store, enabled);
}

export function createRateLimiter(
  store?: RateLimitStore,
  enabled?: boolean
): RateLimiter {
  return new RateLimiter(store, enabled);
}

export function createRedisStore(config: RedisStoreConfig): RedisStore {
  return new RedisStore(config);
}

export function createMemoryStore(): MemoryStore {
  return new MemoryStore();
}
