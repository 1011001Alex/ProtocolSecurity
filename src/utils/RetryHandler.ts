/**
 * ============================================================================
 * RETRY HANDLER - УНИВЕРСАЛЬНЫЙ МЕХАНИЗМ ПОВТОРНЫХ ПОПЫТОК
 * ============================================================================
 * Реализация retry logic с экспоненциальным backoff и jitter
 * 
 * Особенности:
 * - Экспоненциальный backoff
 * - Random jitter для предотвращения thundering herd
 * - Retry budget для ограничения ресурсов
 * - Классификация ошибок (retryable vs non-retryable)
 * - Circuit breaker интеграция
 * - Детальные метрики и логирование
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { CircuitBreaker, CircuitBreakerError } from './CircuitBreaker';

/**
 * Стратегия backoff
 */
export enum BackoffStrategy {
  /** Фиксированная задержка */
  FIXED = 'FIXED',
  /** Экспоненциальная задержка */
  EXPONENTIAL = 'EXPONENTIAL',
  /** Экспоненциальная с jitter */
  EXPONENTIAL_WITH_JITTER = 'EXPONENTIAL_WITH_JITTER',
  /** Линейная задержка */
  LINEAR = 'LINEAR'
}

/**
 * Конфигурация retry handler
 */
export interface RetryHandlerConfig {
  /** Максимум попыток */
  maxRetries: number;
  
  /** Начальная задержка (ms) */
  initialDelay: number;
  
  /** Максимальная задержка (ms) */
  maxDelay: number;
  
  /** Множитель для exponential backoff */
  multiplier: number;
  
  /** Стратегия backoff */
  backoffStrategy: BackoffStrategy;
  
  /** Включить jitter (0.0-1.0) */
  jitterFactor: number;
  
  /** Таймаут операции (ms) */
  timeout: number;
  
  /** Retryable error codes */
  retryableErrorCodes?: string[];
  
  /** Включить circuit breaker */
  enableCircuitBreaker: boolean;
  
  /** Circuit breaker конфигурация */
  circuitBreakerConfig?: {
    failureThreshold: number;
    resetTimeout: number;
  };
  
  /** Имя для идентификации */
  name: string;
  
  /** Включить логирование */
  enableLogging: boolean;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: RetryHandlerConfig = {
  maxRetries: 3,
  initialDelay: 100,
  maxDelay: 10000,
  multiplier: 2,
  backoffStrategy: BackoffStrategy.EXPONENTIAL_WITH_JITTER,
  jitterFactor: 0.2,
  timeout: 30000,
  retryableErrorCodes: [
    'ECONNRESET',
    'ETIMEDOUT',
    'ECONNREFUSED',
    'ENOTFOUND',
    'TIMEOUT',
    'RATE_LIMITED',
    'SERVICE_UNAVAILABLE',
    'CIRCUIT_OPEN'
  ],
  enableCircuitBreaker: true,
  name: 'default',
  enableLogging: true
};

/**
 * Статистика retry handler
 */
export interface RetryStats {
  /** Всего запросов */
  totalRequests: number;
  
  /** Успешных с первой попытки */
  firstAttemptSuccesses: number;
  
  /** Успешных после retries */
  retrySuccesses: number;
  
  /** Окончательных failures */
  finalFailures: number;
  
  /** Всего retry попыток */
  totalRetries: number;
  
  /** Среднее количество retries */
  averageRetries: number;
  
  /** Среднее время выполнения (ms) */
  averageLatency: number;
  
  /** Retry by attempt distribution */
  retriesByAttempt: Map<number, number>;
}

/**
 * Ошибка с retry информацией
 */
export class RetryError extends Error {
  /** Количество попыток */
  public readonly attempts: number;
  
  /** Последняя ошибка */
  public readonly lastError: Error;
  
  /** Все ошибки */
  public readonly errors: Error[];
  
  /** Время выполнения (ms) */
  public readonly duration: number;
  
  constructor(
    message: string,
    attempts: number,
    lastError: Error,
    errors: Error[],
    duration: number
  ) {
    super(message);
    this.name = 'RetryError';
    this.attempts = attempts;
    this.lastError = lastError;
    this.errors = errors;
    this.duration = duration;
    
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, RetryError);
    }
  }
}

/**
 * Контекст выполнения retry
 */
interface RetryContext<T> {
  /** Текущая попытка */
  attempt: number;
  
  /** Прошедшее время (ms) */
  elapsed: number;
  
  /** Последняя ошибка */
  lastError?: Error;
  
  /** Оставшийся бюджет retry */
  remainingRetries: number;
  
  /** Результат если успешен */
  result?: T;
}

/**
 * Универсальный Retry Handler
 */
export class RetryHandler<T = unknown> extends EventEmitter {
  /** Конфигурация */
  private readonly config: RetryHandlerConfig;
  
  /** Circuit breaker */
  private circuitBreaker?: CircuitBreaker;
  
  /** Статистика */
  private stats: RetryStats;
  
  /** Retry budget (максимум concurrent retries) */
  private retryBudget: number;
  
  /** Текущие активные retry */
  private activeRetries: number;
  
  /**
   * Создает retry handler
   */
  constructor(config: Partial<RetryHandlerConfig> = {}) {
    super();
    
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
      retryableErrorCodes: [
        ...DEFAULT_CONFIG.retryableErrorCodes!,
        ...(config.retryableErrorCodes || [])
      ]
    };
    
    this.stats = {
      totalRequests: 0,
      firstAttemptSuccesses: 0,
      retrySuccesses: 0,
      finalFailures: 0,
      totalRetries: 0,
      averageRetries: 0,
      averageLatency: 0,
      retriesByAttempt: new Map()
    };
    
    this.retryBudget = 100; // Максимум concurrent retry операций
    this.activeRetries = 0;
    
    // Инициализация circuit breaker
    if (this.config.enableCircuitBreaker && this.config.circuitBreakerConfig) {
      this.circuitBreaker = new CircuitBreaker({
        failureThreshold: this.config.circuitBreakerConfig.failureThreshold,
        resetTimeout: this.config.circuitBreakerConfig.resetTimeout,
        name: this.config.name,
        enableMonitoring: this.config.enableLogging
      });
    }
    
    this.log('INIT', `RetryHandler инициализирован: ${this.config.name}`);
  }
  
  /**
   * Выполнение операции с retry logic
   */
  async execute(operation: () => Promise<T>): Promise<T> {
    this.stats.totalRequests++;
    
    // Проверка retry budget
    if (this.activeRetries >= this.retryBudget) {
      throw new RetryError(
        'Retry budget exceeded',
        0,
        new Error('Budget exceeded'),
        [],
        0
      );
    }
    
    // Проверка circuit breaker
    if (this.circuitBreaker) {
      return this.executeWithCircuitBreaker(operation);
    }
    
    return this.executeWithRetry(operation);
  }
  
  /**
   * Выполнение с circuit breaker
   */
  private async executeWithCircuitBreaker(operation: () => Promise<T>): Promise<T> {
    if (!this.circuitBreaker) {
      throw new Error('Circuit breaker not initialized');
    }
    
    return this.circuitBreaker.execute(async () => {
      return this.executeWithRetry(operation);
    });
  }
  
  /**
   * Выполнение с retry logic
   */
  private async executeWithRetry(operation: () => Promise<T>): Promise<T> {
    this.activeRetries++;
    
    const startTime = Date.now();
    const errors: Error[] = [];
    let lastError: Error | null = null;
    
    try {
      for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
        const context: RetryContext<T> = {
          attempt: attempt + 1,
          elapsed: Date.now() - startTime,
          lastError: lastError || undefined,
          remainingRetries: this.config.maxRetries - attempt
        };
        
        try {
          // Выполнение операции с timeout
          const result = await this.withTimeout(operation, context);
          
          // Успех
          const duration = Date.now() - startTime;
          this.onSuccess(attempt, duration);
          
          context.result = result;
          this.emit('success', context);
          
          return result;
          
        } catch (error) {
          const err = error as Error;
          errors.push(err);
          lastError = err;
          
          // Проверка можно ли retry
          if (!this.isRetryable(err) || attempt === this.config.maxRetries) {
            const duration = Date.now() - startTime;
            this.onFailure(attempt, errors, duration);
            
            throw new RetryError(
              `Operation failed after ${attempt + 1} attempts`,
              attempt + 1,
              err,
              errors,
              duration
            );
          }
          
          // Логирование retry
          this.log('RETRY', `Попытка ${attempt + 1}/${this.config.maxRetries + 1}: ${err.message}`);
          this.emit('retry', { ...context, error: err });
          
          // Задержка перед следующей попыткой
          const delay = this.calculateDelay(attempt);
          await this.sleep(delay);
          
          this.stats.totalRetries++;
        }
      }
      
      // Должны были выбросить ошибку выше
      throw new Error('Unexpected retry loop exit');
      
    } finally {
      this.activeRetries--;
    }
  }
  
  /**
   * Выполнение с timeout
   */
  private async withTimeout(
    operation: () => Promise<T>,
    context: RetryContext<T>
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error(`Operation timeout after ${this.config.timeout}ms`));
      }, this.config.timeout);
      
      operation()
        .then((result) => {
          clearTimeout(timeoutId);
          resolve(result);
        })
        .catch((error) => {
          clearTimeout(timeoutId);
          reject(error);
        });
    });
  }
  
  /**
   * Проверка можно ли retry ошибку
   */
  private isRetryable(error: Error): boolean {
    // Circuit breaker error - всегда retryable
    if (error instanceof CircuitBreakerError) {
      return true;
    }
    
    // Retry error - не retryable
    if (error instanceof RetryError) {
      return false;
    }
    
    // Проверка по коду ошибки
    const errorCode = (error as any).code;
    if (errorCode && this.config.retryableErrorCodes?.includes(errorCode)) {
      return true;
    }
    
    // Проверка по сообщению
    const message = error.message.toLowerCase();
    const retryablePatterns = [
      'timeout',
      'connection refused',
      'connection reset',
      'network error',
      'service unavailable',
      'rate limit',
      'too many requests',
      'temporarily unavailable'
    ];
    
    return retryablePatterns.some(pattern => message.includes(pattern));
  }
  
  /**
   * Расчет задержки
   */
  private calculateDelay(attempt: number): number {
    const { backoffStrategy, initialDelay, maxDelay, multiplier, jitterFactor } = this.config;
    
    let delay: number;
    
    switch (backoffStrategy) {
      case BackoffStrategy.FIXED:
        delay = initialDelay;
        break;
        
      case BackoffStrategy.LINEAR:
        delay = initialDelay * (attempt + 1);
        break;
        
      case BackoffStrategy.EXPONENTIAL:
        delay = initialDelay * Math.pow(multiplier, attempt);
        break;
        
      case BackoffStrategy.EXPONENTIAL_WITH_JITTER:
        delay = initialDelay * Math.pow(multiplier, attempt);
        // Добавляем jitter
        const jitterRange = delay * jitterFactor;
        delay = delay + (Math.random() * 2 - 1) * jitterRange;
        break;
        
      default:
        delay = initialDelay;
    }
    
    // Ограничиваем maxDelay
    return Math.min(delay, maxDelay);
  }
  
  /**
   * Обработка успеха
   */
  private onSuccess(attempt: number, duration: number): void {
    if (attempt === 0) {
      this.stats.firstAttemptSuccesses++;
    } else {
      this.stats.retrySuccesses++;
    }
    
    this.updateAverageLatency(duration);
    
    // Обновление распределения по попыткам
    const count = this.stats.retriesByAttempt.get(attempt) || 0;
    this.stats.retriesByAttempt.set(attempt, count + 1);
    
    // Обновление среднего retries
    const totalSuccesses = this.stats.firstAttemptSuccesses + this.stats.retrySuccesses;
    this.stats.averageRetries =
      (this.stats.averageRetries * (totalSuccesses - 1) + attempt) / totalSuccesses;
  }
  
  /**
   * Обработка failure
   */
  private onFailure(attempt: number, errors: Error[], duration: number): void {
    this.stats.finalFailures++;
    this.updateAverageLatency(duration);
    
    this.emit('exhausted', {
      attempts: attempt + 1,
      errors,
      duration
    });
  }
  
  /**
   * Обновление средней латентности
   */
  private updateAverageLatency(duration: number): void {
    const total = this.stats.totalRequests;
    this.stats.averageLatency =
      (this.stats.averageLatency * (total - 1) + duration) / total;
  }
  
  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  /**
   * Получение статистики
   */
  getStats(): RetryStats {
    return { ...this.stats };
  }
  
  /**
   * Получение конфигурации
   */
  getConfig(): RetryHandlerConfig {
    return { ...this.config };
  }
  
  /**
   * Проверка доступности
   */
  isAvailable(): boolean {
    if (this.circuitBreaker) {
      return this.circuitBreaker.isAvailable();
    }
    return true;
  }
  
  /**
   * Логирование
   */
  private log(action: string, message: string): void {
    if (!this.config.enableLogging) {
      return;
    }

    const timestamp = new Date().toISOString();
    logger.debug(`[RetryHandler:${this.config.name}] [${action}] ${message}`);
  }
  
  /**
   * Остановка retry handler
   */
  destroy(): void {
    if (this.circuitBreaker) {
      this.circuitBreaker.destroy();
    }
    
    this.removeAllListeners();
    this.log('DESTROY', 'RetryHandler остановлен');
  }
}

/**
 * Фабрика для создания retry handlers
 */
export class RetryHandlerFactory {
  /**
   * Создать retry handler для HTTP запросов
   */
  static createForHTTP(config?: Partial<RetryHandlerConfig>): RetryHandler {
    return new RetryHandler({
      ...config,
      name: config?.name || 'http',
      maxRetries: config?.maxRetries ?? 3,
      initialDelay: config?.initialDelay ?? 100,
      maxDelay: config?.maxDelay ?? 5000,
      backoffStrategy: BackoffStrategy.EXPONENTIAL_WITH_JITTER,
      retryableErrorCodes: [
        'ECONNRESET',
        'ETIMEDOUT',
        'ECONNREFUSED',
        'ENOTFOUND',
        'ERR_SOCKET_BAD_PORT',
        'TIMEOUT',
        'RATE_LIMITED',
        'HTTP_429',
        'HTTP_502',
        'HTTP_503',
        'HTTP_504'
      ]
    });
  }
  
  /**
   * Создать retry handler для database операций
   */
  static createForDatabase(config?: Partial<RetryHandlerConfig>): RetryHandler {
    return new RetryHandler({
      ...config,
      name: config?.name || 'database',
      maxRetries: config?.maxRetries ?? 5,
      initialDelay: config?.initialDelay ?? 50,
      maxDelay: config?.maxDelay ?? 2000,
      backoffStrategy: BackoffStrategy.EXPONENTIAL,
      retryableErrorCodes: [
        'ECONNRESET',
        'ETIMEDOUT',
        'ECONNREFUSED',
        'LOCK_TIMEOUT',
        'DEADLOCK',
        'CONNECTION_LIMIT',
        'POOL_EXHAUSTED'
      ]
    });
  }
  
  /**
   * Создать retry handler для file operations
   */
  static createForFileSystem(config?: Partial<RetryHandlerConfig>): RetryHandler {
    return new RetryHandler({
      ...config,
      name: config?.name || 'filesystem',
      maxRetries: config?.maxRetries ?? 3,
      initialDelay: config?.initialDelay ?? 10,
      maxDelay: config?.maxDelay ?? 1000,
      backoffStrategy: BackoffStrategy.FIXED,
      retryableErrorCodes: [
        'EBUSY',
        'EACCES',
        'EPERM',
        'EMFILE',
        'ENFILE'
      ]
    });
  }
  
  /**
   * Создать retry handler для network операций
   */
  static createForNetwork(config?: Partial<RetryHandlerConfig>): RetryHandler {
    return new RetryHandler({
      ...config,
      name: config?.name || 'network',
      maxRetries: config?.maxRetries ?? 5,
      initialDelay: config?.initialDelay ?? 200,
      maxDelay: config?.maxDelay ?? 10000,
      backoffStrategy: BackoffStrategy.EXPONENTIAL_WITH_JITTER,
      retryableErrorCodes: [
        'ECONNRESET',
        'ETIMEDOUT',
        'ECONNREFUSED',
        'ENOTFOUND',
        'ENETUNREACH',
        'EHOSTUNREACH',
        'TIMEOUT'
      ]
    });
  }
}
