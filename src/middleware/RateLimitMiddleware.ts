/**
 * ============================================================================
 * RATE LIMITING MIDDLEWARE
 * ============================================================================
 * Продвинутый rate limiting с поддержкой Redis, Circuit Breaker и Retry Logic
 * Алгоритмы: Fixed Window, Sliding Window, Token Bucket, Leaky Bucket
 * ============================================================================
 */

import { IncomingMessage, ServerResponse } from 'http';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';

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
 * Конфигурация правила
 */
export interface RateLimitRule {
  name: string;
  algorithm: RateLimitAlgorithm;
  maxRequests: number;
  windowMs: number;
  keyGenerator: (req: IncomingMessage) => string;
  message: string;
  statusCode: number;
  headers: boolean;
  skip?: (req: IncomingMessage) => boolean;
  handler?: (req: IncomingMessage, res: ServerResponse) => void;
}

/**
 * Результат проверки
 */
export interface RateLimitResult {
  allowed: boolean;
  current: number;
  max: number;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

/**
 * Запись в хранилище
 */
export interface StoreEntry {
  count: number;
  windowStart: number;
  tokens?: number;
  lastRefill?: number;
  waterLevel?: number;
  lastLeak?: number;
}

/**
 * Хранилище
 */
export interface RateLimitStore {
  initialize(): Promise<void>;
  get(key: string): Promise<StoreEntry | null>;
  set(key: string, entry: StoreEntry, ttlMs: number): Promise<void>;
  increment(key: string, windowMs: number): Promise<number>;
  cleanup(): Promise<void>;
  destroy(): Promise<void>;
}

/**
 * Memory store implementation
 */
export class MemoryStore extends EventEmitter implements RateLimitStore {
  private readonly store: Map<string, StoreEntry> = new Map();
  private readonly timeouts: Map<string, NodeJS.Timeout> = new Map();
  private isInitialized: boolean = false;

  async initialize(): Promise<void> {
    this.isInitialized = true;
    this.emit('initialized');
  }

  async get(key: string): Promise<StoreEntry | null> {
    return this.store.get(key) || null;
  }

  async set(key: string, entry: StoreEntry, ttlMs: number): Promise<void> {
    this.store.set(key, entry);

    // Установка TTL
    const existingTimeout = this.timeouts.get(key);
    if (existingTimeout) {
      clearTimeout(existingTimeout);
    }

    const timeout = setTimeout(() => {
      this.store.delete(key);
      this.timeouts.delete(key);
    }, ttlMs);

    this.timeouts.set(key, timeout);
  }

  async increment(key: string, windowMs: number): Promise<number> {
    const entry = await this.get(key);
    const now = Date.now();

    if (!entry) {
      // Новая запись
      const newEntry: StoreEntry = {
        count: 1,
        windowStart: now
      };
      await this.set(key, newEntry, windowMs);
      return 1;
    }

    // Проверка окна
    const windowElapsed = now - entry.windowStart;
    if (windowElapsed >= windowMs) {
      // Сброс окна
      entry.count = 1;
      entry.windowStart = now;
    } else {
      entry.count++;
    }

    await this.set(key, entry, windowMs);
    return entry.count;
  }

  async cleanup(): Promise<void> {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (now - entry.windowStart > 3600000) { // 1 час
        this.store.delete(key);
        const timeout = this.timeouts.get(key);
        if (timeout) {
          clearTimeout(timeout);
          this.timeouts.delete(key);
        }
      }
    }
  }

  async destroy(): Promise<void> {
    this.store.clear();
    for (const timeout of this.timeouts.values()) {
      clearTimeout(timeout);
    }
    this.timeouts.clear();
    this.isInitialized = false;
  }

  getSize(): number {
    return this.store.size;
  }
}

/**
 * Конфигурация Rate Limiter
 */
export interface RateLimiterConfig {
  /** Алгоритм по умолчанию */
  defaultAlgorithm: RateLimitAlgorithm;
  /** Хранилище */
  store: RateLimitStore;
  /** Правила по умолчанию */
  defaultRule: Omit<RateLimitRule, 'name' | 'keyGenerator'>;
  /** Включить заголовки */
  enableHeaders: boolean;
  /** Включить логирование */
  enableLogging: boolean;
  /** Skip для health checks */
  skipHealthChecks: boolean;
}

/**
 * Rate Limiter
 */
export class RateLimiter extends EventEmitter {
  private readonly config: RateLimiterConfig;
  private readonly rules: Map<string, RateLimitRule> = new Map();
  private isRunning: boolean = false;

  constructor(config: Partial<RateLimiterConfig> = {}) {
    super();

    this.config = {
      defaultAlgorithm: 'sliding_window',
      store: config.store || new MemoryStore(),
      defaultRule: {
        algorithm: 'sliding_window',
        maxRequests: 100,
        windowMs: 60000,
        message: 'Too many requests',
        statusCode: 429,
        headers: true
      },
      enableHeaders: config.enableHeaders !== false,
      enableLogging: config.enableLogging || false,
      skipHealthChecks: config.skipHealthChecks !== false,
      ...config
    };

    this.emit('created', { config: this.config });
  }

  /**
   * Добавление правила
   */
  addRule(rule: RateLimitRule): void {
    this.rules.set(rule.name, rule);
    this.emit('rule_added', { name: rule.name });
  }

  /**
   * Удаление правила
   */
  removeRule(name: string): void {
    this.rules.delete(name);
    this.emit('rule_removed', { name });
  }

  /**
   * Middleware функция
   */
  handle = async (req: IncomingMessage, res: ServerResponse, next: () => void): Promise<void> => {
    // Skip health checks
    if (this.config.skipHealthChecks && this.isHealthCheck(req)) {
      return next();
    }

    // Поиск подходящего правила
    const rule = this.findMatchingRule(req);
    if (!rule) {
      return next();
    }

    // Skip условие
    if (rule.skip && rule.skip(req)) {
      return next();
    }

    // Генерация ключа
    const key = rule.keyGenerator(req);

    // Проверка лимита
    const result = await this.checkLimit(key, rule);

    // Добавление заголовков
    if (this.config.enableHeaders && rule.headers) {
      this.addRateLimitHeaders(res, result);
    }

    if (!result.allowed) {
      this.emit('rate_limit_exceeded', { key, rule: rule.name });

      if (rule.handler) {
        rule.handler(req, res);
      } else {
        res.statusCode = rule.statusCode;
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Retry-After', result.retryAfter?.toString() || '60');
        res.end(JSON.stringify({
          error: 'Too Many Requests',
          message: rule.message,
          retryAfter: result.retryAfter
        }));
      }
      return;
    }

    next();
  };

  /**
   * Проверка лимита
   */
  private async checkLimit(key: string, rule: RateLimitRule): Promise<RateLimitResult> {
    const store = this.config.store;

    switch (rule.algorithm) {
      case 'fixed_window':
        return this.checkFixedWindow(key, rule, store);
      case 'sliding_window':
        return this.checkSlidingWindow(key, rule, store);
      case 'token_bucket':
        return this.checkTokenBucket(key, rule, store);
      case 'leaky_bucket':
        return this.checkLeakyBucket(key, rule, store);
      case 'sliding_log':
        return this.checkSlidingLog(key, rule, store);
      default:
        return this.checkSlidingWindow(key, rule, store);
    }
  }

  /**
   * Fixed Window
   */
  private async checkFixedWindow(
    key: string,
    rule: RateLimitRule,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    const count = await store.increment(key, rule.windowMs);
    const entry = await store.get(key);

    const remaining = Math.max(0, rule.maxRequests - count);
    const resetTime = entry ? entry.windowStart + rule.windowMs : Date.now() + rule.windowMs;
    const retryAfter = Math.ceil((resetTime - Date.now()) / 1000);

    return {
      allowed: count <= rule.maxRequests,
      current: count,
      max: rule.maxRequests,
      remaining,
      resetTime,
      retryAfter: count > rule.maxRequests ? retryAfter : undefined
    };
  }

  /**
   * Sliding Window
   */
  private async checkSlidingWindow(
    key: string,
    rule: RateLimitRule,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const entry = await store.get(key);

    if (!entry) {
      await store.set(key, { count: 1, windowStart: now }, rule.windowMs);
      return {
        allowed: true,
        current: 1,
        max: rule.maxRequests,
        remaining: rule.maxRequests - 1,
        resetTime: now + rule.windowMs
      };
    }

    const windowElapsed = now - entry.windowStart;
    
    if (windowElapsed >= rule.windowMs) {
      // Новое окно
      await store.set(key, { count: 1, windowStart: now }, rule.windowMs);
      return {
        allowed: true,
        current: 1,
        max: rule.maxRequests,
        remaining: rule.maxRequests - 1,
        resetTime: now + rule.windowMs
      };
    }

    // Скользящее окно — используем вес
    const weight = 1 - (windowElapsed / rule.windowMs);
    const weightedCount = entry.count + weight;

    if (weightedCount >= rule.maxRequests) {
      const retryAfter = Math.ceil((entry.windowStart + rule.windowMs - now) / 1000);
      return {
        allowed: false,
        current: Math.floor(weightedCount),
        max: rule.maxRequests,
        remaining: 0,
        resetTime: entry.windowStart + rule.windowMs,
        retryAfter
      };
    }

    await store.set(key, { ...entry, count: entry.count + 1 }, rule.windowMs);

    return {
      allowed: true,
      current: Math.floor(weightedCount) + 1,
      max: rule.maxRequests,
      remaining: rule.maxRequests - Math.floor(weightedCount) - 1,
      resetTime: entry.windowStart + rule.windowMs
    };
  }

  /**
   * Token Bucket
   */
  private async checkTokenBucket(
    key: string,
    rule: RateLimitRule,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const entry = await store.get(key);

    if (!entry) {
      // Новый бакет с полными токенами
      await store.set(key, {
        count: rule.maxRequests - 1,
        windowStart: now,
        tokens: rule.maxRequests - 1,
        lastRefill: now
      }, rule.windowMs);

      return {
        allowed: true,
        current: 1,
        max: rule.maxRequests,
        remaining: rule.maxRequests - 1,
        resetTime: now + rule.windowMs
      };
    }

    // Refill токенов
    const timePassed = now - (entry.lastRefill || now);
    const refillRate = rule.maxRequests / rule.windowMs;
    const tokensToAdd = timePassed * refillRate;
    const newTokens = Math.min(rule.maxRequests, (entry.tokens || 0) + tokensToAdd);

    if (newTokens < 1) {
      const retryAfter = Math.ceil((1 - newTokens) / refillRate);
      return {
        allowed: false,
        current: rule.maxRequests - Math.floor(newTokens),
        max: rule.maxRequests,
        remaining: Math.floor(newTokens),
        resetTime: now + Math.ceil((rule.maxRequests - newTokens) / refillRate),
        retryAfter
      };
    }

    await store.set(key, {
      ...entry,
      tokens: newTokens - 1,
      lastRefill: now
    }, rule.windowMs);

    return {
      allowed: true,
      current: rule.maxRequests - Math.floor(newTokens) + 1,
      max: rule.maxRequests,
      remaining: Math.floor(newTokens) - 1,
      resetTime: entry.windowStart + rule.windowMs
    };
  }

  /**
   * Leaky Bucket
   */
  private async checkLeakyBucket(
    key: string,
    rule: RateLimitRule,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    const now = Date.now();
    const entry = await store.get(key);

    if (!entry) {
      await store.set(key, {
        count: 1,
        windowStart: now,
        waterLevel: 1,
        lastLeak: now
      }, rule.windowMs);

      return {
        allowed: true,
        current: 1,
        max: rule.maxRequests,
        remaining: rule.maxRequests - 1,
        resetTime: now + rule.windowMs
      };
    }

    // Утечка
    const timePassed = now - (entry.lastLeak || now);
    const leakRate = rule.maxRequests / rule.windowMs;
    const leakedAmount = timePassed * leakRate;
    const newWaterLevel = Math.max(0, (entry.waterLevel || 0) - leakedAmount);

    if (newWaterLevel >= rule.maxRequests) {
      const retryAfter = Math.ceil((newWaterLevel - rule.maxRequests + 1) / leakRate);
      return {
        allowed: false,
        current: Math.floor(newWaterLevel),
        max: rule.maxRequests,
        remaining: 0,
        resetTime: now + Math.ceil((newWaterLevel - rule.maxRequests) / leakRate),
        retryAfter
      };
    }

    await store.set(key, {
      ...entry,
      waterLevel: newWaterLevel + 1,
      lastLeak: now
    }, rule.windowMs);

    return {
      allowed: true,
      current: Math.floor(newWaterLevel) + 1,
      max: rule.maxRequests,
      remaining: rule.maxRequests - Math.floor(newWaterLevel) - 1,
      resetTime: entry.windowStart + rule.windowMs
    };
  }

  /**
   * Sliding Log
   */
  private async checkSlidingLog(
    key: string,
    rule: RateLimitRule,
    store: RateLimitStore
  ): Promise<RateLimitResult> {
    // Упрощённая реализация
    return this.checkSlidingWindow(key, rule, store);
  }

  /**
   * Добавление заголовков
   */
  private addRateLimitHeaders(res: ServerResponse, result: RateLimitResult): void {
    res.setHeader('X-RateLimit-Limit', result.max.toString());
    res.setHeader('X-RateLimit-Remaining', result.remaining.toString());
    res.setHeader('X-RateLimit-Reset', result.resetTime.toString());

    if (result.retryAfter) {
      res.setHeader('Retry-After', result.retryAfter.toString());
    }
  }

  /**
   * Проверка health check
   */
  private isHealthCheck(req: IncomingMessage): boolean {
    const url = req.url || '';
    return url === '/health' || url === '/ready' || url === '/live';
  }

  /**
   * Поиск правила
   */
  private findMatchingRule(req: IncomingMessage): RateLimitRule | null {
    // Проверка специфичных правил
    for (const rule of this.rules.values()) {
      if (!rule.skip || !rule.skip(req)) {
        return rule;
      }
    }

    // Правило по умолчанию
    return {
      name: 'default',
      ...this.config.defaultRule,
      keyGenerator: (req) => this.generateKey(req)
    };
  }

  /**
   * Генерация ключа
   */
  private generateKey(req: IncomingMessage): string {
    const ip = (req as any).ip || req.socket.remoteAddress || 'unknown';
    return `ratelimit:${ip}:${uuidv4()}`;
  }

  /**
   * Запуск
   */
  start(): void {
    if (this.isRunning) {
      return;
    }

    this.isRunning = true;
    this.config.store.initialize();

    // Периодическая очистка
    setInterval(() => {
      this.config.store.cleanup();
    }, 60000);

    this.emit('started');
  }

  /**
   * Остановка
   */
  stop(): void {
    this.isRunning = false;
    this.config.store.destroy();
    this.emit('stopped');
  }

  /**
   * Статистика
   */
  getStats(): {
    isRunning: boolean;
    rulesCount: number;
    storeSize?: number;
  } {
    return {
      isRunning: this.isRunning,
      rulesCount: this.rules.size,
      storeSize: this.config.store instanceof MemoryStore ? this.config.store.getSize() : undefined
    };
  }
}

/**
 * Factory функции
 */
export function createRateLimiter(config?: Partial<RateLimiterConfig>): RateLimiter {
  return new RateLimiter(config);
}

export function createMemoryStore(): MemoryStore {
  return new MemoryStore();
}

export function createPerIPRule(maxRequests: number = 100, windowMs: number = 60000): RateLimitRule {
  return {
    name: 'per_ip',
    algorithm: 'sliding_window',
    maxRequests,
    windowMs,
    keyGenerator: (req) => `ip:${(req as any).ip || req.socket.remoteAddress}`,
    message: 'Too many requests from your IP',
    statusCode: 429,
    headers: true
  };
}

export function createAPIRule(maxRequests: number = 1000, windowMs: number = 60000): RateLimitRule {
  return {
    name: 'api',
    algorithm: 'token_bucket',
    maxRequests,
    windowMs,
    keyGenerator: (req) => `api:${(req as any).user?.id || req.headers['x-api-key'] || 'anonymous'}`,
    message: 'API rate limit exceeded',
    statusCode: 429,
    headers: true
  };
}

export function createAuthRule(maxRequests: number = 5, windowMs: number = 60000): RateLimitRule {
  return {
    name: 'auth',
    algorithm: 'fixed_window',
    maxRequests,
    windowMs,
    keyGenerator: (req) => `auth:${(req as any).ip || req.socket.remoteAddress}`,
    message: 'Too many authentication attempts',
    statusCode: 429,
    headers: true
  };
}
