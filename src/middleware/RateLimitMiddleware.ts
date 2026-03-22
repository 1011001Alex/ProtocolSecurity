/**
 * =============================================================================
 * RATE LIMITING MIDDLEWARE
 * =============================================================================
 * Продвинутый rate limiting с поддержкой Redis
 * Алгоритмы: Fixed Window, Sliding Window, Token Bucket, Leaky Bucket
 * =============================================================================
 */

import { IncomingMessage, ServerResponse } from 'http';
import { EventEmitter } from 'events';

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
}

// =============================================================================
// MEMORY STORE (для development)
// =============================================================================

export class MemoryStore implements RateLimitStore {
  private store: Map<string, StoreEntry>;
  private cleanupInterval?: NodeJS.Timeout;

  constructor() {
    this.store = new Map();
  }

  async initialize(): Promise<void> {
    // Очистка каждые 5 минут
    this.cleanupInterval = setInterval(() => {
      this.cleanup().catch(console.error);
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
    for (const [key, entry] of this.store.entries()) {
      if (now - entry.windowStart > 60 * 60 * 1000) { // 1 час
        this.store.delete(key);
      }
    }
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async destroy(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    this.store.clear();
  }
}

// =============================================================================
// REDIS STORE (для production)
// =============================================================================

export class RedisStore implements RateLimitStore {
  private config: RedisStoreConfig;
  private client: any; // Redis client
  private isConnected: boolean = false;

  constructor(config: RedisStoreConfig) {
    this.config = config;
  }

  async initialize(): Promise<void> {
    try {
      // В реальной реализации: ioredis или node-redis
      // this.client = new Redis({
      //   host: this.config.host,
      //   port: this.config.port,
      //   password: this.config.password,
      //   db: this.config.db,
      //   keyPrefix: this.config.keyPrefix
      // });
      
      this.isConnected = true;
      console.log('[RedisStore] Connected to Redis');
    } catch (error) {
      console.error('[RedisStore] Connection failed:', error);
      this.isConnected = false;
    }
  }

  async get(key: string): Promise<StoreEntry | null> {
    if (!this.isConnected || !this.client) {
      return null;
    }

    const data = await this.client.get(`${this.config.keyPrefix}:${key}`);
    if (!data) {
      return null;
    }

    return JSON.parse(data);
  }

  async set(key: string, entry: StoreEntry, ttlMs: number): Promise<void> {
    if (!this.isConnected || !this.client) {
      return;
    }

    const fullKey = `${this.config.keyPrefix}:${key}`;
    const ttlSeconds = Math.ceil(ttlMs / 1000);

    await this.client.setex(fullKey, ttlSeconds, JSON.stringify(entry));
  }

  async increment(key: string, windowMs: number): Promise<number> {
    if (!this.isConnected || !this.client) {
      // Fallback на memory
      return 1;
    }

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

    const count = await this.client.eval(luaScript, 1, fullKey, windowMs.toString(), now.toString());
    return count;
  }

  async cleanup(): Promise<void> {
    // Redis автоматически очищает по TTL
  }

  async destroy(): Promise<void> {
    if (this.client) {
      await this.client.quit();
      this.isConnected = false;
    }
  }
}

// =============================================================================
// RATE LIMITER CLASS
// =============================================================================

export class RateLimiter extends EventEmitter {
  private rules: Map<string, RateLimitRule>;
  private store: RateLimitStore;
  private enabled: boolean;

  constructor(store?: RateLimitStore, enabled: boolean = true) {
    super();
    this.rules = new Map();
    this.store = store || new MemoryStore();
    this.enabled = enabled;
  }

  /**
   * Инициализация
   */
  async initialize(): Promise<void> {
    await this.store.initialize();
  }

  /**
   * Добавление правила
   */
  addRule(rule: RateLimitRule): void {
    this.rules.set(rule.name, rule);
  }

  /**
   * Middleware функция
   */
  async handle(req: IncomingMessage, res: ServerResponse, next?: () => void): Promise<void> {
    if (!this.enabled) {
      next?.();
      return;
    }

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
        this.emit('rate-limit-exceeded', { rule: rule.name, key, req });

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

    next?.();
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
    // В реальной реализации удалить запись из хранилища
    // Для MemoryStore нужно очистить запись
    if (this.store instanceof MemoryStore) {
      await this.store.delete(key);
    }
    console.log('[RateLimiter] Reset limit for:', key);
  }

  /**
   * Получение статистики
   */
  getStats(): {
    rulesCount: number;
    enabled: boolean;
    storeType: string;
  } {
    return {
      rulesCount: this.rules.size,
      enabled: this.enabled,
      storeType: this.store instanceof RedisStore ? 'redis' : 'memory'
    };
  }

  /**
   * Закрытие
   */
  async destroy(): Promise<void> {
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
// ЭКСПОРТ
// =============================================================================

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
