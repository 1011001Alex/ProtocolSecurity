/**
 * Policy Enforcement Point (PEP) - Точка Принудительного Применения Политик
 * 
 * Компонент отвечает за перехват запросов доступа, взаимодействие с PDP
 * и принудительное применение решений о доступе. Реализует паттерн
 * Request-Response с кэшированием и circuit breaker.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { v4 as uuidv4 } from 'uuid';
import {
  PolicyDecision,
  PolicyEvaluationResult,
  Identity,
  AuthContext,
  DevicePosture,
  ResourceType,
  PolicyOperation,
  ZeroTrustEvent,
  SubjectType,
  TrustLevel
} from './zerotrust.types';
import { PolicyDecisionPoint } from './PolicyDecisionPoint';

/**
 * Конфигурация Circuit Breaker
 */
interface CircuitBreakerConfig {
  /** Порог ошибок для открытия circuit */
  failureThreshold: number;
  
  /** Таймаут для полуоткрытого состояния */
  resetTimeout: number;
  
  /** Таймаут между попытками */
  retryTimeout: number;
}

/**
 * Состояние Circuit Breaker
 */
enum CircuitState {
  /** Circuit закрыт - нормальная работа */
  CLOSED = 'CLOSED',
  
  /** Circuit открыт - запросы блокируются */
  OPEN = 'OPEN',
  
  /** Circuit полуоткрыт - тестовые запросы */
  HALF_OPEN = 'HALF_OPEN'
}

/**
 * Конфигурация Policy Enforcement Point
 */
export interface PepConfig {
  /** Режим применения политик */
  enforcementMode: 'ENFORCE' | 'MONITOR' | 'DISABLE';
  
  /** Включить кэширование решений PDP */
  enableCaching: boolean;
  
  /** TTL кэша PEP (секунды) */
  cacheTtl: number;
  
  /** Включить circuit breaker */
  enableCircuitBreaker: boolean;
  
  /** Конфигурация circuit breaker */
  circuitBreaker: CircuitBreakerConfig;
  
  /** Таймаут запроса к PDP (мс) */
  pdpTimeout: number;
  
  /** Действие при недоступности PDP */
  onPdpUnavailable: 'DENY' | 'ALLOW' | 'CACHE_ONLY';
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
  
  /** Включить аудит всех запросов */
  enableAudit: boolean;
  
  /** Максимальное количество одновременных запросов */
  maxConcurrentRequests: number;
  
  /** Rate limiting */
  rateLimit: {
    /** Включить rate limiting */
    enabled: boolean;
    /** Максимум запросов в секунду */
    requestsPerSecond: number;
    /** Burst размер */
    burstSize: number;
  };
}

/**
 * Контекст запроса к PEP
 */
export interface PepRequestContext {
  /** Уникальный идентификатор запроса */
  requestId: string;
  
  /** Идентичность субъекта */
  identity: Identity;
  
  /** Контекст аутентификации */
  authContext: AuthContext;
  
  /** Posture устройства (опционально) */
  devicePosture?: DevicePosture;
  
  /** Тип ресурса */
  resourceType: ResourceType;
  
  /** ID ресурса */
  resourceId: string;
  
  /** Название ресурса */
  resourceName: string;
  
  /** Запрашиваемая операция */
  operation: PolicyOperation;
  
  /** IP адрес источника */
  sourceIp: string;
  
  /** IP адрес назначения */
  destinationIp?: string;
  
  /** Порт назначения */
  destinationPort?: number;
  
  /** Протокол */
  protocol?: string;
  
  /** Дополнительные атрибуты ресурса */
  resourceAttributes?: Record<string, unknown>;
  
  /** Время начала запроса */
  startTime: Date;
}

/**
 * Результат применения политики
 */
export interface PepEnforcementResult {
  /** Уникальный идентификатор результата */
  resultId: string;
  
  /** ID запроса */
  requestId: string;
  
  /** Решение PDP */
  decision: PolicyDecision;
  
  /** Было ли решение применено */
  enforced: boolean;
  
  /** Метод применения */
  enforcementMethod: 'INTERCEPT' | 'PROXY' | 'GATEWAY' | 'SIDECAR';
  
  /** Результат оценки PDP */
  pdpResult?: PolicyEvaluationResult;
  
  /** Ошибка (если была) */
  error?: string;
  
  /** Время применения */
  enforcedAt: Date;
  
  /** Применённые ограничения */
  appliedRestrictions: {
    /** Ограничение по времени */
    timeLimit?: number;
    /** Ограничение по операциям */
    operationLimit?: PolicyOperation[];
    /** Требуется step-up */
    requireStepUp?: boolean;
  };
}

/**
 * Кэш решений PEP
 */
interface PepDecisionCache {
  /** Кэш по ключу */
  entries: Map<string, {
    /** Результат */
    result: PolicyEvaluationResult;
    /** Время кэширования */
    cachedAt: Date;
    /** Время истечения */
    expiresAt: Date;
    /** Количество использований */
    hitCount: number;
  }>;
  
  /** Максимальный размер */
  maxSize: number;
}

/**
 * Policy Enforcement Point (PEP)
 * 
 * Компонент для перехвата запросов и принудительного применения
 * решений Policy Decision Point.
 */
export class PolicyEnforcementPoint extends EventEmitter {
  /** Конфигурация PEP */
  private config: PepConfig;
  
  /** Ссылка на PDP */
  private pdp: PolicyDecisionPoint | null;
  
  /** Кэш решений */
  private cache: PepDecisionCache;
  
  /** Состояние circuit breaker */
  private circuitState: CircuitState;
  
  /** Счётчик ошибок circuit breaker */
  private circuitFailureCount: number;
  
  /** Время последнего сброса circuit breaker */
  private circuitLastReset: Date;
  
  /** Текущие активные запросы */
  private activeRequests: Set<string>;
  
  /** Rate limiter счётчик */
  private rateLimiter: {
    /** Токены */
    tokens: number;
    /** Последнее обновление */
    lastUpdate: Date;
  };
  
  /** Статистика PEP */
  private stats: {
    /** Всего запросов */
    totalRequests: number;
    /** Разрешено */
    allowed: number;
    /** Запрещено */
    denied: number;
    /** Ошибки */
    errors: number;
    /** Попаданий в кэш */
    cacheHits: number;
    /** Circuit breaker срабатываний */
    circuitBreakerTrips: number;
    /** Rate limit срабатываний */
    rateLimitHits: number;
    /** Среднее время обработки */
    averageProcessingTime: number;
  };

  constructor(config: Partial<PepConfig> = {}) {
    super();
    
    this.config = {
      enforcementMode: config.enforcementMode ?? 'ENFORCE',
      enableCaching: config.enableCaching ?? true,
      cacheTtl: config.cacheTtl ?? 300,
      enableCircuitBreaker: config.enableCircuitBreaker ?? true,
      circuitBreaker: {
        failureThreshold: config.circuitBreaker?.failureThreshold ?? 5,
        resetTimeout: config.circuitBreaker?.resetTimeout ?? 30000,
        retryTimeout: config.circuitBreaker?.retryTimeout ?? 10000
      },
      pdpTimeout: config.pdpTimeout ?? 5000,
      onPdpUnavailable: config.onPdpUnavailable ?? 'DENY',
      enableVerboseLogging: config.enableVerboseLogging ?? false,
      enableAudit: config.enableAudit ?? true,
      maxConcurrentRequests: config.maxConcurrentRequests ?? 1000,
      rateLimit: {
        enabled: config.rateLimit?.enabled ?? true,
        requestsPerSecond: config.rateLimit?.requestsPerSecond ?? 100,
        burstSize: config.rateLimit?.burstSize ?? 200
      }
    };
    
    this.pdp = null;
    this.cache = {
      entries: new Map(),
      maxSize: 10000
    };
    this.circuitState = CircuitState.CLOSED;
    this.circuitFailureCount = 0;
    this.circuitLastReset = new Date();
    this.activeRequests = new Set();
    this.rateLimiter = {
      tokens: this.config.rateLimit.burstSize,
      lastUpdate: new Date()
    };
    
    this.stats = {
      totalRequests: 0,
      allowed: 0,
      denied: 0,
      errors: 0,
      cacheHits: 0,
      circuitBreakerTrips: 0,
      rateLimitHits: 0,
      averageProcessingTime: 0
    };
    
    this.log('PEP', 'PolicyEnforcementPoint инициализирован', { config: this.config });
  }

  /**
   * Установить ссылку на PDP
   * 
   * @param pdp Экземпляр PolicyDecisionPoint
   */
  public setPdp(pdp: PolicyDecisionPoint): void {
    this.pdp = pdp;
    this.log('PEP', 'PDP установлен', { pdpId: pdp.constructor.name });
  }

  /**
   * Получить текущий PDP
   */
  public getPdp(): PolicyDecisionPoint | null {
    return this.pdp;
  }

  /**
   * Обработать запрос доступа
   * 
   * @param context Контекст запроса
   * @returns Результат применения политики
   */
  public async enforceAccess(context: {
    identity: Identity;
    authContext: AuthContext;
    devicePosture?: DevicePosture;
    resourceType: ResourceType;
    resourceId: string;
    resourceName: string;
    operation: PolicyOperation;
    sourceIp: string;
    destinationIp?: string;
    destinationPort?: number;
    protocol?: string;
    resourceAttributes?: Record<string, unknown>;
  }): Promise<PepEnforcementResult> {
    const startTime = Date.now();
    const requestId = uuidv4();
    this.stats.totalRequests++;
    
    this.log('PEP', 'Получен запрос на доступ', {
      requestId,
      subjectId: context.identity.id,
      resource: context.resourceId,
      operation: context.operation
    });
    
    // Проверка режима работы
    if (this.config.enforcementMode === 'DISABLE') {
      return this.createBypassResult(requestId, context);
    }
    
    // Проверка rate limiting
    if (this.config.rateLimit.enabled && !this.checkRateLimit()) {
      this.stats.rateLimitHits++;
      this.log('PEP', 'Rate limit превышен', { requestId });
      
      return this.createEnforcementResult(
        requestId,
        PolicyDecision.DENY,
        false,
        'Rate limit exceeded',
        context
      );
    }
    
    // Проверка circuit breaker
    if (this.config.enableCircuitBreaker && this.circuitState === CircuitState.OPEN) {
      if (!this.shouldRetryCircuit()) {
        this.stats.circuitBreakerTrips++;
        this.log('PEP', 'Circuit breaker открыт', { requestId });
        
        return this.handleCircuitBreakerOpen(requestId, context);
      }
    }
    
    // Проверка максимального количества одновременных запросов
    if (this.activeRequests.size >= this.config.maxConcurrentRequests) {
      this.log('PEP', 'Превышено максимальное количество одновременных запросов', {
        requestId,
        activeCount: this.activeRequests.size
      });
      
      return this.createEnforcementResult(
        requestId,
        PolicyDecision.DEFERRED,
        false,
        'Too many concurrent requests',
        context
      );
    }
    
    // Добавляем запрос в активные
    this.activeRequests.add(requestId);
    
    try {
      // Проверяем кэш
      if (this.config.enableCaching) {
        const cachedResult = this.checkCache(context);
        if (cachedResult) {
          this.stats.cacheHits++;
          this.log('PEP', 'Решение найдено в кэше', { requestId });
          
          return this.applyDecision(requestId, cachedResult, context, 'CACHE');
        }
      }
      
      // Запрашиваем решение у PDP
      const pdpResult = await this.queryPdp(context, requestId);
      
      // Применяем решение
      return this.applyDecision(requestId, pdpResult, context, 'PDP');
      
    } catch (error) {
      this.stats.errors++;
      this.circuitFailureCount++;
      
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.log('PEP', 'Ошибка обработки запроса', {
        requestId,
        error: errorMessage,
        stack: error instanceof Error ? error.stack : undefined
      });
      
      // Обрабатываем ошибку circuit breaker
      this.handleCircuitBreakerFailure();
      
      // Возвращаем результат в зависимости от конфигурации
      return this.handlePdpError(requestId, context, errorMessage);
      
    } finally {
      // Удаляем из активных запросов
      this.activeRequests.delete(requestId);
      
      // Обновляем статистику
      const processingTime = Date.now() - startTime;
      this.stats.averageProcessingTime = 
        (this.stats.averageProcessingTime * (this.stats.totalRequests - 1) + processingTime) /
        this.stats.totalRequests;
    }
  }

  /**
   * Проверить rate limit
   */
  private checkRateLimit(): boolean {
    const now = new Date();
    const elapsed = (now.getTime() - this.rateLimiter.lastUpdate.getTime()) / 1000;
    
    // Восстанавливаем токены
    this.rateLimiter.tokens = Math.min(
      this.config.rateLimit.burstSize,
      this.rateLimiter.tokens + elapsed * this.config.rateLimit.requestsPerSecond
    );
    this.rateLimiter.lastUpdate = now;
    
    // Проверяем наличие токенов
    if (this.rateLimiter.tokens >= 1) {
      this.rateLimiter.tokens -= 1;
      return true;
    }
    
    return false;
  }

  /**
   * Проверить кэш решений
   */
  private checkCache(context: {
    identity: Identity;
    resourceType: ResourceType;
    resourceId: string;
    operation: PolicyOperation;
    sourceIp: string;
  }): PolicyEvaluationResult | null {
    const cacheKey = this.getCacheKey(context);
    const cached = this.cache.entries.get(cacheKey);
    
    if (!cached) {
      return null;
    }
    
    // Проверяем истечение
    if (new Date() > cached.expiresAt) {
      this.cache.entries.delete(cacheKey);
      return null;
    }
    
    cached.hitCount++;
    return cached.result;
  }

  /**
   * Получить ключ кэша
   */
  private getCacheKey(context: {
    identity: Identity;
    resourceType: ResourceType;
    resourceId: string;
    operation: PolicyOperation;
    sourceIp: string;
  }): string {
    return `${context.identity.id}:${context.resourceType}:${context.resourceId}:${context.operation}:${context.sourceIp}`;
  }

  /**
   * Запросить решение у PDP
   */
  private async queryPdp(
    context: {
      identity: Identity;
      authContext: AuthContext;
      devicePosture?: DevicePosture;
      resourceType: ResourceType;
      resourceId: string;
      resourceName: string;
      operation: PolicyOperation;
      sourceIp: string;
      destinationIp?: string;
      destinationPort?: number;
      protocol?: string;
      resourceAttributes?: Record<string, unknown>;
    },
    requestId: string
  ): Promise<PolicyEvaluationResult> {
    if (!this.pdp) {
      throw new Error('PDP не установлен. Вызовите setPdp() перед использованием.');
    }
    
    // Создаём Promise с таймаутом
    const pdpPromise = this.pdp.evaluateAccess({
      identity: context.identity,
      authContext: context.authContext,
      devicePosture: context.devicePosture,
      resourceType: context.resourceType,
      resourceId: context.resourceId,
      resourceName: context.resourceName,
      operation: context.operation,
      sourceIp: context.sourceIp,
      destinationIp: context.destinationIp,
      destinationPort: context.destinationPort,
      protocol: context.protocol,
      resourceAttributes: context.resourceAttributes
    });
    
    const timeoutPromise = new Promise<PolicyEvaluationResult>((_, reject) => {
      setTimeout(() => {
        reject(new Error(`PDP timeout: превышен лимит ${this.config.pdpTimeout}мс`));
      }, this.config.pdpTimeout);
    });
    
    // Выполняем с таймаутом
    const result = await Promise.race([pdpPromise, timeoutPromise]);
    
    // Сбрасываем счётчик ошибок circuit breaker при успехе
    this.circuitFailureCount = Math.max(0, this.circuitFailureCount - 1);
    
    return result;
  }

  /**
   * Применить решение PDP
   */
  private applyDecision(
    requestId: string,
    pdpResult: PolicyEvaluationResult,
    context: {
      resourceType: ResourceType;
      resourceId: string;
      resourceName: string;
      operation: PolicyOperation;
    },
    source: 'CACHE' | 'PDP'
  ): PepEnforcementResult {
    const { decision } = pdpResult;
    
    // В режиме MONITOR только логируем, но не блокируем
    if (this.config.enforcementMode === 'MONITOR') {
      this.log('PEP', 'Режим MONITOR - доступ разрешён с логированием', {
        requestId,
        decision,
        source
      });
      
      this.stats.allowed++;
      
      return {
        resultId: uuidv4(),
        requestId,
        decision: PolicyDecision.ALLOW,
        enforced: false,
        enforcementMethod: 'PROXY',
        pdpResult,
        enforcedAt: new Date(),
        appliedRestrictions: {
          timeLimit: pdpResult.restrictions.timeLimit,
          operationLimit: pdpResult.restrictions.operationLimit,
          requireStepUp: pdpResult.restrictions.requireStepUp
        }
      };
    }
    
    // В режиме ENFORCE применяем решение
    let enforced = false;
    
    if (decision === PolicyDecision.ALLOW ||
        decision === PolicyDecision.ALLOW_RESTRICTED ||
        decision === PolicyDecision.ALLOW_TEMPORARY) {
      enforced = true;
      this.stats.allowed++;
      
      // Кэшируем положительное решение
      if (this.config.enableCaching && source === 'PDP') {
        this.cacheDecision(context, pdpResult);
      }
      
      this.log('PEP', 'Доступ разрешён', {
        requestId,
        decision,
        restrictions: pdpResult.restrictions
      });
      
    } else if (decision === PolicyDecision.DENY) {
      this.stats.denied++;
      this.log('PEP', 'Доступ запрещён', { requestId, decision });
      
    } else if (decision === PolicyDecision.REQUIRE_STEP_UP) {
      this.stats.denied++;
      this.log('PEP', 'Требуется дополнительная аутентификация', { requestId });
    }
    
    // Эмитим событие применения
    this.emit('access:enforced', {
      requestId,
      decision,
      enforced,
      timestamp: new Date()
    });
    
    return {
      resultId: uuidv4(),
      requestId,
      decision,
      enforced,
      enforcementMethod: 'INTERCEPT',
      pdpResult,
      enforcedAt: new Date(),
      appliedRestrictions: {
        timeLimit: pdpResult.restrictions.timeLimit,
        operationLimit: pdpResult.restrictions.operationLimit,
        requireStepUp: pdpResult.restrictions.requireStepUp
      }
    };
  }

  /**
   * Кэшировать решение
   */
  private cacheDecision(
    context: {
      identity: Identity;
      resourceType: ResourceType;
      resourceId: string;
      operation: PolicyOperation;
      sourceIp: string;
    },
    result: PolicyEvaluationResult
  ): void {
    const cacheKey = this.getCacheKey(context);
    
    // Очищаем старые записи если кэш переполнен
    if (this.cache.entries.size >= this.cache.maxSize) {
      const firstKey = this.cache.entries.keys().next().value;
      if (firstKey) {
        this.cache.entries.delete(firstKey);
      }
    }
    
    this.cache.entries.set(cacheKey, {
      result,
      cachedAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.cacheTtl * 1000),
      hitCount: 0
    });
  }

  /**
   * Обработать открытие circuit breaker
   */
  private handleCircuitBreakerOpen(
    requestId: string,
    context: {
      identity: Identity;
      resourceType: ResourceType;
      resourceId: string;
      resourceName: string;
      operation: PolicyOperation;
      sourceIp: string;
    }
  ): PepEnforcementResult {
    if (this.config.onPdpUnavailable === 'DENY') {
      this.stats.denied++;
      
      return this.createEnforcementResult(
        requestId,
        PolicyDecision.DENY,
        false,
        'PDP недоступен (circuit breaker открыт)',
        context
      );
    }
    
    if (this.config.onPdpUnavailable === 'ALLOW') {
      this.stats.allowed++;
      
      return this.createEnforcementResult(
        requestId,
        PolicyDecision.ALLOW,
        false,
        'PDP недоступен - доступ разрешён по конфигурации',
        context
      );
    }
    
    // CACHE_ONLY - пытаемся найти в кэше
    const cachedResult = this.checkCache(context);
    if (cachedResult) {
      return this.applyDecision(requestId, cachedResult, context, 'CACHE');
    }
    
    // Кэша нет - deny by default
    this.stats.denied++;
    
    return this.createEnforcementResult(
      requestId,
      PolicyDecision.DENY,
      false,
      'PDP недоступен, кэш пуст - доступ запрещён',
      context
    );
  }

  /**
   * Обработать ошибку PDP
   */
  private handlePdpError(
    requestId: string,
    context: {
      identity: Identity;
      resourceType: ResourceType;
      resourceId: string;
      resourceName: string;
      operation: PolicyOperation;
      sourceIp: string;
    },
    error: string
  ): PepEnforcementResult {
    if (this.config.onPdpUnavailable === 'DENY') {
      this.stats.denied++;
      
      return this.createEnforcementResult(
        requestId,
        PolicyDecision.DENY,
        false,
        `PDP ошибка: ${error}`,
        context
      );
    }
    
    if (this.config.onPdpUnavailable === 'ALLOW') {
      this.stats.allowed++;
      
      return this.createEnforcementResult(
        requestId,
        PolicyDecision.ALLOW,
        false,
        `PDP ошибка - доступ разрешён: ${error}`,
        context
      );
    }
    
    // CACHE_ONLY
    const cachedResult = this.checkCache(context);
    if (cachedResult) {
      return this.applyDecision(requestId, cachedResult, context, 'CACHE');
    }
    
    this.stats.denied++;
    
    return this.createEnforcementResult(
      requestId,
      PolicyDecision.DENY,
      false,
      `PDP ошибка, кэш пуст: ${error}`,
      context
    );
  }

  /**
   * Обработать сбой circuit breaker
   */
  private handleCircuitBreakerFailure(): void {
    if (!this.config.enableCircuitBreaker) {
      return;
    }
    
    if (this.circuitFailureCount >= this.config.circuitBreaker.failureThreshold) {
      this.circuitState = CircuitState.OPEN;
      this.circuitLastReset = new Date();
      
      this.log('PEP', 'Circuit breaker ОТКРЫТ', {
        failureCount: this.circuitFailureCount
      });
      
      this.emit('circuit:opened', {
        timestamp: new Date(),
        failureCount: this.circuitFailureCount
      });
    }
  }

  /**
   * Проверить, можно ли retry circuit breaker
   */
  private shouldRetryCircuit(): boolean {
    const now = new Date();
    const elapsed = now.getTime() - this.circuitLastReset.getTime();
    
    if (elapsed >= this.config.circuitBreaker.resetTimeout) {
      this.circuitState = CircuitState.HALF_OPEN;
      this.circuitLastReset = now;
      
      this.log('PEP', 'Circuit breaker в полуоткрытом состоянии');
      
      return true;
    }
    
    return false;
  }

  /**
   * Создать результат bypass (режим DISABLE)
   */
  private createBypassResult(
    requestId: string,
    context: {
      resourceType: ResourceType;
      resourceId: string;
      resourceName: string;
      operation: PolicyOperation;
    }
  ): PepEnforcementResult {
    this.stats.allowed++;
    
    return {
      resultId: uuidv4(),
      requestId,
      decision: PolicyDecision.ALLOW,
      enforced: false,
      enforcementMethod: 'PROXY',
      enforcedAt: new Date(),
      appliedRestrictions: {}
    };
  }

  /**
   * Создать результат применения
   */
  private createEnforcementResult(
    requestId: string,
    decision: PolicyDecision,
    enforced: boolean,
    error?: string,
    context?: {
      resourceType: ResourceType;
      resourceId: string;
      resourceName: string;
      operation: PolicyOperation;
    }
  ): PepEnforcementResult {
    return {
      resultId: uuidv4(),
      requestId,
      decision,
      enforced,
      enforcementMethod: 'INTERCEPT',
      error,
      enforcedAt: new Date(),
      appliedRestrictions: {}
    };
  }

  /**
   * Сбросить circuit breaker
   */
  public resetCircuitBreaker(): void {
    this.circuitState = CircuitState.CLOSED;
    this.circuitFailureCount = 0;
    this.circuitLastReset = new Date();
    
    this.log('PEP', 'Circuit breaker сброшен');
    this.emit('circuit:reset', { timestamp: new Date() });
  }

  /**
   * Получить статус circuit breaker
   */
  public getCircuitState(): CircuitState {
    return this.circuitState;
  }

  /**
   * Очистить кэш
   */
  public clearCache(): void {
    this.cache.entries.clear();
    this.log('PEP', 'Кэш очищен');
  }

  /**
   * Получить статистику PEP
   */
  public getStats(): typeof this.stats & {
    /** Активные запросы */
    activeRequests: number;
    /** Размер кэша */
    cacheSize: number;
    /** Токены rate limiter */
    rateLimitTokens: number;
  } {
    return {
      ...this.stats,
      activeRequests: this.activeRequests.size,
      cacheSize: this.cache.entries.size,
      rateLimitTokens: Math.floor(this.rateLimiter.tokens)
    };
  }

  /**
   * Логирование событий PEP
   */
  private log(component: string, message: string, data?: unknown): void {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'ACCESS_REQUEST',
      timestamp: new Date(),
      subject: {
        id: 'system',
        type: SubjectType.SYSTEM,
        name: component
      },
      details: { message, ...data },
      severity: 'INFO',
      correlationId: uuidv4()
    };
    
    this.emit('log', event);

    if (this.config.enableVerboseLogging && this.config.enableAudit) {
      logger.debug(`[PEP] ${message}`, { timestamp: new Date().toISOString(), ...data });
    }
  }
}

export default PolicyEnforcementPoint;
