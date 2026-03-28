/**
 * ============================================================================
 * CIRCUIT BREAKER - УНИВЕРСАЛЬНЫЙ ЗАЩИТНЫЙ МЕХАНИЗМ
 * ============================================================================
 * Реализация паттерна Circuit Breaker для защиты от каскадных отказов
 * 
 * Особенности:
 * - Три состояния: CLOSED, OPEN, HALF_OPEN
 * - Автоматическое восстановление
 * - Настройка порогов failures/successes
 * - Timeout для операций
 * - Детальное логирование и метрики
 * 
 * Состояния:
 * - CLOSED: Нормальная работа, запросы проходят
 * - OPEN: Цепь разорвана, запросы блокируются
 * - HALF_OPEN: Проверка восстановления, ограниченные запросы
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';

/**
 * Состояния circuit breaker
 */
export enum CircuitState {
  /** Нормальная работа */
  CLOSED = 'CLOSED',
  /** Цепь разорвана */
  OPEN = 'OPEN',
  /** Проверка восстановления */
  HALF_OPEN = 'HALF_OPEN'
}

/**
 * Конфигурация circuit breaker
 */
export interface CircuitBreakerConfig {
  /** Максимум failures перед разрывом цепи */
  failureThreshold: number;
  
  /** Максимум successes перед замыканием цепи в HALF_OPEN */
  successThreshold: number;
  
  /** Таймаут перед попыткой восстановления (ms) */
  resetTimeout: number;
  
  /** Таймаут для отдельных операций (ms) */
  operationTimeout: number;
  
  /** Включить мониторинг */
  enableMonitoring: boolean;
  
  /** Имя для идентификации */
  name: string;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: CircuitBreakerConfig = {
  failureThreshold: 5,
  successThreshold: 3,
  resetTimeout: 30000, // 30 секунд
  operationTimeout: 10000, // 10 секунд
  enableMonitoring: true,
  name: 'default'
};

/**
 * Статистика circuit breaker
 */
export interface CircuitBreakerStats {
  /** Текущее состояние */
  state: CircuitState;

  /** Количество failures */
  failures: number;

  /** Количество successes */
  successes: number;

  /** Всего запросов */
  totalRequests: number;

  /** Всего failures */
  totalFailures: number;

  /** Всего successes */
  totalSuccesses: number;

  /** Всего rejections (отклонено из-за OPEN) */
  totalRejections: number;

  /** Среднее время выполнения (ms) */
  averageLatency: number;

  /** Порог failures для разрыва цепи */
  failureThreshold: number;

  /** Таймаут reset (ms) */
  resetTimeout: number;

  /** Имя circuit breaker */
  name: string;

  /** Последняя ошибка */
  lastError?: string;

  /** Время последнего failure */
  lastFailureAt?: Date;

  /** время последнего success */
  lastSuccessAt?: Date;

  /** Время перехода в OPEN */
  openedAt?: Date;

  /** Время следующего attempted reset */
  nextResetAt?: Date;
}

/**
 * Ошибка circuit breaker
 */
export class CircuitBreakerError extends Error {
  /** Код ошибки */
  public readonly code: string;

  /** Состояние circuit breaker */
  public readonly state: CircuitState;

  /** Оригинальная ошибка */
  public readonly cause?: Error;

  constructor(
    message: string,
    code: string,
    state: CircuitState,
    cause?: Error
  ) {
    super(message);
    this.name = 'CircuitBreakerError';
    this.code = code;
    this.state = state;
    this.cause = cause;

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, CircuitBreakerError);
    }
  }

  public override get stack(): string | undefined {
    return super.stack;
  }
}

/**
 * Универсальный Circuit Breaker
 */
export class CircuitBreaker extends EventEmitter {
  /** Конфигурация */
  private readonly config: CircuitBreakerConfig;
  
  /** Текущее состояние */
  private state: CircuitState = CircuitState.CLOSED;
  
  /** Счетчик failures */
  private failureCount = 0;
  
  /** Счетчик successes в HALF_OPEN */
  private successCount = 0;
  
  /** Таймер для reset timeout */
  private resetTimer: NodeJS.Timeout | null = null;

  /** Статистика */
  private stats: CircuitBreakerStats;

  /**
   * Создает circuit breaker
   */
  constructor(config: Partial<CircuitBreakerConfig> = {}) {
    super();
    
    this.config = {
      ...DEFAULT_CONFIG,
      ...config
    };
    
    this.stats = {
      state: CircuitState.CLOSED,
      failures: 0,
      successes: 0,
      totalRequests: 0,
      totalFailures: 0,
      totalSuccesses: 0,
      totalRejections: 0,
      averageLatency: 0,
      failureThreshold: this.config.failureThreshold,
      resetTimeout: this.config.resetTimeout,
      name: this.config.name
    };
    
    this.log('INIT', `CircuitBreaker инициализирован: ${this.config.name}`);
  }
  
  /**
   * Выполнение операции с circuit breaker
   */
  async execute<T>(operation: () => Promise<T>): Promise<T> {
    this.stats.totalRequests++;

    // Проверка состояния
    if (!this.canExecute()) {
      this.stats.totalRejections++;
      this.emit('reject', { state: this.state, stats: this.getStats() });

      throw new CircuitBreakerError(
        `Circuit breaker ${this.config.name} в состоянии ${this.state}`,
        'CIRCUIT_OPEN',
        this.state
      );
    }

    const startTime = Date.now();

    try {
      // Выполнение с timeout
      const result = await this.withTimeout(operation, startTime);

      // Успех
      await this.onSuccess(startTime);

      return result;
    } catch (error) {
      // Failure
      await this.onFailure(error as Error, startTime);
      throw error;
    }
  }
  
  /**
   * Проверка возможности выполнения
   */
  private canExecute(): boolean {
    if (this.state === CircuitState.CLOSED) {
      return true;
    }
    
    if (this.state === CircuitState.OPEN) {
      // Проверка reset timeout
      if (this.stats.nextResetAt && Date.now() >= this.stats.nextResetAt.getTime()) {
        this.transitionTo(CircuitState.HALF_OPEN);
        return true;
      }
      return false;
    }
    
    // HALF_OPEN - разрешаем ограниченные запросы
    return true;
  }
  
  /**
   * Выполнение с timeout
   */
  private async withTimeout<T>(
    operation: () => Promise<T>,
    startTime: number
  ): Promise<T> {
    const timeout = this.config.operationTimeout;
    
    const timeoutPromise = new Promise<never>((_, reject) => {
      const remaining = timeout - (Date.now() - startTime);
      if (remaining <= 0) {
        reject(new CircuitBreakerError(
          'Operation timeout',
          'TIMEOUT',
          this.state
        ));
        return;
      }
      
      setTimeout(() => {
        reject(new CircuitBreakerError(
          `Operation timeout after ${timeout}ms`,
          'TIMEOUT',
          this.state
        ));
      }, remaining);
    });
    
    return Promise.race([operation(), timeoutPromise]);
  }
  
  /**
   * Обработка успеха
   */
  private async onSuccess(startTime: number): Promise<void> {
    const latency = Date.now() - startTime;
    this.updateLatency(latency);

    // В HALF_OPEN state увеличиваем только totalSuccesses, не successes
    // successes используется для подсчета в текущем состоянии
    if (this.state !== CircuitState.HALF_OPEN) {
      this.stats.successes++;
    }
    this.stats.totalSuccesses++;
    this.stats.lastSuccessAt = new Date();

    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;

      if (this.successCount >= this.config.successThreshold) {
        this.transitionTo(CircuitState.CLOSED);
        this.emit('close', { stats: this.getStats() });
        this.log('CLOSE', `Circuit замкнут после ${this.successCount} успехов`);
      }
    }

    this.emit('success', { latency, stats: this.getStats() });
  }

  /**
   * Обработка failure
   */
  private async onFailure(error: Error, startTime: number): Promise<void> {
    const latency = Date.now() - startTime;
    this.updateLatency(latency);

    // В HALF_OPEN state увеличиваем только totalFailures, не failures
    if (this.state !== CircuitState.HALF_OPEN) {
      this.stats.failures++;
    }
    this.stats.totalFailures++;
    this.stats.lastError = error.message;
    this.stats.lastFailureAt = new Date();

    if (this.state === CircuitState.HALF_OPEN) {
      // Немедленно разрываем цепь
      this.transitionTo(CircuitState.OPEN);
      this.emit('open', { error: error.message, stats: this.getStats() });
      this.log('OPEN', `Circuit разорван в HALF_OPEN: ${error.message}`);
    } else if (this.state === CircuitState.CLOSED) {
      this.failureCount++;

      if (this.failureCount >= this.config.failureThreshold) {
        this.transitionTo(CircuitState.OPEN);
        this.emit('open', { error: error.message, stats: this.getStats() });
        this.log('OPEN', `Circuit разорван после ${this.failureCount} failures`);
      }
    }

    this.emit('failure', { error: error.message, stats: this.getStats() });
  }
  
  /**
   * Переход в новое состояние
   */
  private transitionTo(newState: CircuitState): void {
    const oldState = this.state;
    this.state = newState;
    this.stats.state = newState;

    // Очистка таймеров
    if (this.resetTimer) {
      clearTimeout(this.resetTimer);
      this.resetTimer = null;
    }

    // Логика перехода
    switch (newState) {
      case CircuitState.OPEN:
        this.stats.openedAt = new Date();
        this.stats.nextResetAt = new Date(Date.now() + this.config.resetTimeout);

        // Установка таймера для попытки восстановления
        this.resetTimer = setTimeout(() => {
          this.transitionTo(CircuitState.HALF_OPEN);
          this.emit('half_open', { stats: this.getStats() });
          this.log('HALF_OPEN', 'Попытка восстановления');
        }, this.config.resetTimeout);
        break;

      case CircuitState.HALF_OPEN:
        // Сбрасываем счетчики при переходе в HALF_OPEN
        this.failureCount = 0;
        this.successCount = 0;
        // Сбрасываем текущие счетчики для метрик
        this.stats.failures = 0;
        this.stats.successes = 0;
        break;

      case CircuitState.CLOSED:
        this.failureCount = 0;
        this.successCount = 0;
        this.stats.failures = 0;
        this.stats.successes = 0;
        this.stats.openedAt = undefined;
        this.stats.nextResetAt = undefined;
        break;
    }

    this.log('STATE_CHANGE', `${oldState} -> ${newState}`);
  }
  
  /**
   * Обновление средней латентности
   */
  private updateLatency(latency: number): void {
    const total = this.stats.totalSuccesses + this.stats.totalFailures;
    if (total === 0) {
      this.stats.averageLatency = latency;
    } else {
      this.stats.averageLatency =
        (this.stats.averageLatency * (total - 1) + latency) / total;
    }
  }
  
  /**
   * Принудительный reset circuit breaker
   */
  reset(): void {
    this.log('RESET', 'Принудительный reset');
    this.transitionTo(CircuitState.CLOSED);
    this.emit('reset', { stats: this.getStats() });
  }
  
  /**
   * Получение статистики
   */
  getStats(): CircuitBreakerStats {
    return { ...this.stats };
  }
  
  /**
   * Получение текущего состояния
   */
  getState(): CircuitState {
    return this.state;
  }
  
  /**
   * Проверка доступности
   */
  isAvailable(): boolean {
    return this.state !== CircuitState.OPEN;
  }
  
  /**
   * Остановка circuit breaker
   */
  destroy(): void {
    if (this.resetTimer) {
      clearTimeout(this.resetTimer);
      this.resetTimer = null;
    }
    
    this.removeAllListeners();
    this.log('DESTROY', 'CircuitBreaker остановлен');
  }
  
  /**
   * Логирование
   */
  private log(action: string, message: string): void {
    if (!this.config.enableMonitoring) {
      return;
    }

    const timestamp = new Date().toISOString();
    logger.debug(`[CircuitBreaker:${this.config.name}] [${action}] ${message}`);
  }
}

/**
 * Декоратор для автоматического применения circuit breaker
 */
export function circuitBreaker(
  breaker: CircuitBreaker,
  fallback?: (error: Error) => unknown
) {
  return function (
    target: unknown,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args: unknown[]) {
      try {
        return await breaker.execute(() => originalMethod.apply(this, args));
      } catch (error) {
        if (fallback) {
          return fallback(error as Error);
        }
        throw error;
      }
    };
    
    return descriptor;
  };
}

/**
 * Менеджер circuit breakers для системы
 */
export class CircuitBreakerManager extends EventEmitter {
  /** Circuit breakers по именам */
  private breakers: Map<string, CircuitBreaker> = new Map();
  
  /**
   * Создать circuit breaker
   */
  create(name: string, config: Partial<CircuitBreakerConfig> = {}): CircuitBreaker {
    if (this.breakers.has(name)) {
      return this.breakers.get(name)!;
    }
    
    const breaker = new CircuitBreaker({ ...config, name });
    this.breakers.set(name, breaker);
    
    // Проброс событий
    breaker.on('open', () => this.emit('breaker:open', { name, breaker }));
    breaker.on('close', () => this.emit('breaker:close', { name, breaker }));
    breaker.on('half_open', () => this.emit('breaker:half_open', { name, breaker }));
    breaker.on('failure', (data) => this.emit('breaker:failure', { name, ...data }));
    
    return breaker;
  }
  
  /**
   * Получить circuit breaker
   */
  get(name: string): CircuitBreaker | undefined {
    return this.breakers.get(name);
  }
  
  /**
   * Получить все circuit breakers
   */
  getAll(): CircuitBreaker[] {
    return Array.from(this.breakers.values());
  }
  
  /**
   * Получить общую статистику
   */
  getGlobalStats(): {
    total: number;
    open: number;
    closed: number;
    halfOpen: number;
  } {
    const breakers = this.getAll();
    
    return {
      total: breakers.length,
      open: breakers.filter(b => b.getState() === CircuitState.OPEN).length,
      closed: breakers.filter(b => b.getState() === CircuitState.CLOSED).length,
      halfOpen: breakers.filter(b => b.getState() === CircuitState.HALF_OPEN).length
    };
  }
  
  /**
   * Остановить все circuit breakers
   */
  destroyAll(): void {
    for (const breaker of this.breakers.values()) {
      breaker.destroy();
    }
    this.breakers.clear();
  }
}
