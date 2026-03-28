/**
 * ============================================================================
 * POLICY ENFORCEMENT POINT (PEP) — ТОЧКА ПРИНУДИТЕЛЬНОГО ПРИМЕНЕНИЯ ПОЛИТИК
 * ============================================================================
 * Полная реализация PEP для Zero Trust Architecture
 * 
 * Функционал:
 * - Перехват и проверка всех запросов доступа
 * - Применение решений PDP
 * - Enforcement ограничений и условий доступа
 * - Логирование всех попыток доступа
 * - Интеграция с Trust Verifier
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { IncomingMessage, ServerResponse } from 'http';
import { v4 as uuidv4 } from 'uuid';
import {
  PolicyDecision,
  TrustLevel,
  AccessRequest,
  AccessResponse,
  Identity,
  AuthContext,
  DevicePosture,
  ResourceType,
  PolicyOperation,
  AuthenticationMethod,
  SubjectType
} from './zerotrust.types';
import { PolicyDecisionPoint } from './PolicyDecisionPoint';
import { TrustVerifier } from './TrustVerifier';

/**
 * Конфигурация PEP
 */
export interface PepConfig {
  /** Включить enforcement */
  enableEnforcement: boolean;
  /** Режим только для аудита (без блокировки) */
  auditOnlyMode: boolean;
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
  /** Таймаут ожидания решения PDP */
  pdpTimeout: number;
  /** Действие при недоступности PDP */
  onPdpUnavailable: 'DENY' | 'ALLOW' | 'DEFER';
  /** Включить кэширование решений */
  enableDecisionCaching: boolean;
  /** TTL кэша решений */
  cacheTtl: number;
  /** Включить rate limiting для denied запросов */
  enableDeniedRateLimit: boolean;
  /** Максимум denied запросов в минуту */
  maxDeniedPerMinute: number;
}

/**
 * Запрос к PEP
 */
interface PepRequest {
  requestId: string;
  identity: Identity;
  authContext: AuthContext;
  devicePosture?: DevicePosture;
  resourceType: ResourceType;
  resourceId: string;
  operation: PolicyOperation;
  sourceIp: string;
  destinationIp?: string;
  destinationPort?: number;
  protocol?: string;
  metadata?: Record<string, unknown>;
  httpContext?: {
    request: IncomingMessage;
    response?: ServerResponse;
  };
}

/**
 * Кэш решений
 */
interface DecisionCache {
  decision: AccessResponse;
  cachedAt: Date;
  expiresAt: Date;
}

/**
 * Rate limiter для denied запросов
 */
interface DeniedRateLimit {
  count: number;
  windowStart: Date;
  blocked: boolean;
}

/**
 * Policy Enforcement Point — основная реализация
 */
export class PolicyEnforcementPoint extends EventEmitter {
  private readonly config: PepConfig;
  private readonly pdp: PolicyDecisionPoint;
  private readonly trustVerifier: TrustVerifier;
  private readonly decisionCache: Map<string, DecisionCache> = new Map();
  private readonly deniedRateLimits: Map<string, DeniedRateLimit> = new Map();
  private isInitialized: boolean = false;

  constructor(
    config: Partial<PepConfig> = {},
    pdp?: PolicyDecisionPoint,
    trustVerifier?: TrustVerifier
  ) {
    super();

    this.config = {
      enableEnforcement: true,
      auditOnlyMode: false,
      enableVerboseLogging: false,
      pdpTimeout: 5000,
      onPdpUnavailable: 'DENY',
      enableDecisionCaching: true,
      cacheTtl: 60000,
      enableDeniedRateLimit: true,
      maxDeniedPerMinute: 10,
      ...config
    };

    this.pdp = pdp || new PolicyDecisionPoint();
    this.trustVerifier = trustVerifier || new TrustVerifier();

    this.isInitialized = true;
    this.emit('initialized', { config: this.config });
  }

  /**
   * Перехват и проверка запроса
   */
  async interceptRequest(request: PepRequest): Promise<AccessResponse> {
    const requestId = request.requestId || uuidv4();
    const startTime = Date.now();

    try {
      this.emit('request_intercepted', { requestId, identity: request.identity });

      // Проверка rate limiting для denied
      if (this.config.enableDeniedRateLimit) {
        const rateLimitResult = this.checkDeniedRateLimit(request.identity.subjectId);
        if (rateLimitResult.blocked) {
          return this.createDenyResponse(
            requestId,
            'Rate limit exceeded for denied requests',
            startTime
          );
        }
      }

      // Проверка кэша
      if (this.config.enableDecisionCaching) {
        const cachedDecision = this.getCachedDecision(requestId);
        if (cachedDecision) {
          return {
            ...cachedDecision.decision,
            responseId: uuidv4(),
            requestId,
            decidedAt: new Date(),
            cached: true,
            evaluationTime: Date.now() - startTime
          };
        }
      }

      // Инициализация trust контекста если нужно
      await this.ensureTrustContext(request);

      // Построение запроса к PDP
      const accessRequest: AccessRequest = {
        requestId,
        identity: request.identity,
        authContext: request.authContext,
        devicePosture: request.devicePosture,
        resourceType: request.resourceType,
        resourceId: request.resourceId,
        operation: request.operation,
        sourceIp: request.sourceIp,
        destinationIp: request.destinationIp,
        destinationPort: request.destinationPort,
        protocol: request.protocol,
        metadata: request.metadata,
        isUnusualLocation: request.metadata?.isUnusualLocation as boolean || false,
        isUnusualTime: request.metadata?.isUnusualTime as boolean || false,
        isUnusualDevice: request.metadata?.isUnusualDevice as boolean || false,
        isAnomalousBehavior: request.metadata?.isAnomalousBehavior as boolean || false,
        riskScore: request.metadata?.riskScore as number || 0
      };

      // Запрос решения к PDP с таймаутом
      const decision = await Promise.race([
        this.pdp.evaluateAccess(accessRequest),
        this.createPdpTimeoutResponse(requestId)
      ]);

      // Применение решения
      const enforcedDecision = await this.enforceDecision(decision, request);

      // Кэширование
      if (this.config.enableDecisionCaching && decision.decision !== PolicyDecision.DENY) {
        this.cacheDecision(requestId, enforcedDecision);
      }

      // Логирование denied запросов
      if (decision.decision === PolicyDecision.DENY) {
        this.trackDeniedRequest(request.identity.subjectId);
      }

      this.emit('request_processed', {
        requestId,
        decision: enforcedDecision.decision,
        evaluationTime: Date.now() - startTime
      });

      return enforcedDecision;

    } catch (error) {
      this.emit('request_error', { requestId, error });

      return this.createErrorResponse(
        requestId,
        error instanceof Error ? error.message : 'Unknown error',
        startTime
      );
    }
  }

  /**
   * Обеспечение trust контекста
   */
  private async ensureTrustContext(request: PepRequest): Promise<void> {
    const subjectId = request.identity.subjectId;
    const existingContext = this.trustVerifier.getTrustContext(subjectId);

    if (!existingContext) {
      await this.trustVerifier.initializeTrust(
        request.identity,
        request.authContext,
        request.devicePosture
      );
    }
  }

  /**
   * Применение решения
   */
  private async enforceDecision(
    decision: AccessResponse,
    request: PepRequest
  ): Promise<AccessResponse> {
    // В audit-only режиме просто логируем
    if (this.config.auditOnlyMode) {
      this.logEnforcement(request, decision, 'AUDIT_ONLY');
      return decision;
    }

    // Если enforcement отключен
    if (!this.config.enableEnforcement) {
      return decision;
    }

    // Применение в зависимости от решения
    switch (decision.decision) {
      case PolicyDecision.ALLOW:
      case PolicyDecision.ALLOW_TEMPORARY:
        this.logEnforcement(request, decision, 'ALLOWED');
        return decision;

      case PolicyDecision.ALLOW_RESTRICTED:
        // Применение ограничений
        const restrictedDecision = await this.applyRestrictions(decision, request);
        this.logEnforcement(request, restrictedDecision, 'ALLOWED_RESTRICTED');
        return restrictedDecision;

      case PolicyDecision.REQUIRE_STEP_UP:
        this.logEnforcement(request, decision, 'STEP_UP_REQUIRED');
        return decision;

      case PolicyDecision.DENY:
        await this.applyDeny(request, decision);
        this.logEnforcement(request, decision, 'DENIED');
        return decision;

      case PolicyDecision.DEFERRED:
        this.logEnforcement(request, decision, 'DEFERRED');
        return decision;

      default:
        return decision;
    }
  }

  /**
   * Применение ограничений
   */
  private async applyRestrictions(
    decision: AccessResponse,
    request: PepRequest
  ): Promise<AccessResponse> {
    // Добавление ограничений в решение
    const restrictions: string[] = [];

    // Ограничение по времени
    if (decision.metadata?.validUntil) {
      restrictions.push(`time_limited:${decision.metadata.validUntil}`);
    }

    // Ограничение по операциям
    if (request.operation !== PolicyOperation.READ) {
      restrictions.push('read_only');
    }

    // Ограничение по объему данных
    restrictions.push('data_limit:1000');

    return {
      ...decision,
      reason: `${decision.reason} (restricted: ${restrictions.join(', ')})`,
      metadata: {
        ...decision.metadata,
        restrictions
      }
    };
  }

  /**
   * Применение DENY решения
   */
  private async applyDeny(
    request: PepRequest,
    decision: AccessResponse
  ): Promise<void> {
    // Логирование
    this.emit('access_denied', {
      requestId: request.requestId,
      subjectId: request.identity.subjectId,
      resource: request.resourceId,
      reason: decision.reason
    });

    // Обновление trust score
    const trustContext = this.trustVerifier.getTrustContext(request.identity.subjectId);
    if (trustContext) {
      this.trustVerifier.updateActivity(request.identity.subjectId, {
        type: 'ACCESS_DENIED',
        timestamp: new Date(),
        resource: request.resourceId,
        operation: request.operation,
        result: 'DENIED',
        context: { reason: decision.reason }
      });
    }
  }

  /**
   * Проверка rate limiting для denied
   */
  private checkDeniedRateLimit(subjectId: string): { blocked: boolean; count: number } {
    const now = new Date();
    let rateLimit = this.deniedRateLimits.get(subjectId);

    if (!rateLimit) {
      return { blocked: false, count: 0 };
    }

    // Сброс окна если прошло больше минуты
    const windowAge = now.getTime() - rateLimit.windowStart.getTime();
    if (windowAge > 60000) {
      rateLimit.count = 0;
      rateLimit.windowStart = now;
      rateLimit.blocked = false;
    }

    return {
      blocked: rateLimit.blocked,
      count: rateLimit.count
    };
  }

  /**
   * Отслеживание denied запроса
   */
  private trackDeniedRequest(subjectId: string): void {
    const now = new Date();
    let rateLimit = this.deniedRateLimits.get(subjectId);

    if (!rateLimit) {
      rateLimit = {
        count: 0,
        windowStart: now,
        blocked: false
      };
      this.deniedRateLimits.set(subjectId, rateLimit);
    }

    // Сброс окна если прошло больше минуты
    const windowAge = now.getTime() - rateLimit.windowStart.getTime();
    if (windowAge > 60000) {
      rateLimit.count = 0;
      rateLimit.windowStart = now;
    }

    rateLimit.count++;

    // Блокировка если превышен лимит
    if (rateLimit.count > this.config.maxDeniedPerMinute) {
      rateLimit.blocked = true;
      this.emit('rate_limit_exceeded', { subjectId, count: rateLimit.count });
    }
  }

  /**
   * Получение кэшированного решения
   */
  private getCachedDecision(requestId: string): DecisionCache | null {
    const cached = this.decisionCache.get(requestId);
    if (!cached) {
      return null;
    }

    if (new Date() > cached.expiresAt) {
      this.decisionCache.delete(requestId);
      return null;
    }

    return cached;
  }

  /**
   * Кэширование решения
   */
  private cacheDecision(requestId: string, decision: AccessResponse): void {
    const ttl = this.config.cacheTtl;
    
    this.decisionCache.set(requestId, {
      decision,
      cachedAt: new Date(),
      expiresAt: new Date(Date.now() + ttl)
    });

    // Очистка старого кэша
    if (this.decisionCache.size > 1000) {
      const firstKey = this.decisionCache.keys().next().value;
      if (firstKey) {
        this.decisionCache.delete(firstKey);
      }
    }
  }

  /**
   * Создание DENY ответа
   */
  private createDenyResponse(
    requestId: string,
    reason: string,
    startTime: number
  ): AccessResponse {
    return {
      responseId: uuidv4(),
      requestId,
      decidedAt: new Date(),
      appliedRules: [],
      decision: PolicyDecision.DENY,
      reason,
      trustLevel: TrustLevel.UNTRUSTED,
      riskAssessment: {
        level: 'high',
        score: 80,
        factors: ['enforcement_failure']
      },
      cached: false,
      evaluationTime: Date.now() - startTime,
      timestamp: new Date(),
      metadata: {
        policyId: 'pep_enforcement',
        evaluationSteps: ['PEP denied request'],
        timestamp: new Date()
      }
    };
  }

  /**
   * Создание ERROR ответа
   */
  private createErrorResponse(
    requestId: string,
    error: string,
    startTime: number
  ): AccessResponse {
    return {
      responseId: uuidv4(),
      requestId,
      decidedAt: new Date(),
      appliedRules: [],
      decision: PolicyDecision.DENY,
      reason: `Error: ${error}`,
      trustLevel: TrustLevel.UNTRUSTED,
      riskAssessment: {
        level: 'critical',
        score: 100,
        factors: ['processing_error']
      },
      cached: false,
      evaluationTime: Date.now() - startTime,
      timestamp: new Date(),
      metadata: {
        policyId: 'error',
        evaluationSteps: ['Processing error'],
        timestamp: new Date()
      }
    };
  }

  /**
   * Создание timeout ответа от PDP
   */
  private createPdpTimeoutResponse(requestId: string): Promise<AccessResponse> {
    return Promise.resolve({
      responseId: uuidv4(),
      requestId,
      decidedAt: new Date(),
      appliedRules: [],
      decision: this.config.onPdpUnavailable === 'ALLOW'
        ? PolicyDecision.ALLOW
        : PolicyDecision.DENY,
      reason: `PDP timeout (configured to ${this.config.onPdpUnavailable})`,
      trustLevel: TrustLevel.MINIMAL,
      riskAssessment: {
        level: this.config.onPdpUnavailable === 'ALLOW' ? 'medium' : 'low',
        score: this.config.onPdpUnavailable === 'ALLOW' ? 50 : 20,
        factors: ['pdp_timeout']
      },
      cached: false,
      evaluationTime: this.config.pdpTimeout,
      timestamp: new Date(),
      metadata: {
        policyId: 'timeout',
        evaluationSteps: ['PDP timeout'],
        timestamp: new Date()
      }
    });
  }

  /**
   * Логирование enforcement
   */
  private logEnforcement(
    request: PepRequest,
    decision: AccessResponse,
    action: string
  ): void {
    const logEntry = {
      timestamp: new Date(),
      requestId: request.requestId,
      subjectId: request.identity.subjectId,
      resourceType: request.resourceType,
      resourceId: request.resourceId,
      operation: request.operation,
      decision: decision.decision,
      enforcementAction: action,
      trustLevel: decision.trustLevel,
      riskScore: decision.riskAssessment?.score
    };

    if (this.config.enableVerboseLogging) {
      console.log('[PEP Enforcement]', JSON.stringify(logEntry, null, 2));
    }

    this.emit('enforcement_logged', logEntry);
  }

  /**
   * Middleware для Express
   */
  createExpressMiddleware() {
    return async (req: IncomingMessage & any, res: ServerResponse & any, next: () => void) => {
      try {
        // Извлечение контекста из HTTP запроса
        const identity: Identity = {
          id: req.user?.id || req.headers['x-user-id'] as string || uuidv4(),
          subjectId: req.user?.id || req.headers['x-user-id'] as string || 'anonymous',
          type: (req.user?.type as SubjectType) || SubjectType.USER,
          subjectType: req.user?.type || 'USER',
          displayName: req.user?.displayName || req.user?.name || 'Anonymous',
          roles: req.user?.roles || [],
          permissions: req.user?.permissions || [],
          groups: req.user?.groups || [],
          labels: req.user?.labels || {},
          domain: req.user?.domain,
          createdAt: new Date(),
          updatedAt: new Date(),
          attributes: req.user?.attributes || {}
        };

        const authContext: AuthContext = {
          method: AuthenticationMethod.JWT,
          authenticatedAt: req.authTime ? new Date(req.authTime) : new Date(),
          expiresAt: new Date(Date.now() + 3600000),
          levelOfAssurance: req.user?.loa || 1,
          factors: [AuthenticationMethod.JWT],
          sessionId: req.sessionId || req.headers['x-session-id'] as string || uuidv4(),
          refreshTokenId: undefined,
          mfaVerified: req.user?.mfaVerified || false,
          mfaMethods: [],
          authenticationMethods: req.authMethods || [AuthenticationMethod.JWT],
          tokenClaims: req.tokenClaims || {}
        };

        const pepRequest: PepRequest = {
          requestId: req.requestId || uuidv4(),
          identity,
          authContext,
          resourceType: ResourceType.HTTP_ENDPOINT,
          resourceId: req.path || req.url || '/',
          operation: this.mapHttpMethodToOperation(req.method),
          sourceIp: req.ip || req.socket.remoteAddress || 'unknown',
          destinationIp: req.headers.host as string || 'unknown',
          destinationPort: parseInt(req.headers['x-forwarded-port'] as string) || 443,
          protocol: 'HTTPS',
          httpContext: {
            request: req,
            response: res
          }
        };

        // Проверка запроса
        const decision = await this.interceptRequest(pepRequest);

        // Применение решения
        if (decision.decision === PolicyDecision.DENY) {
          res.statusCode = 403;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({
            error: 'Access Denied',
            reason: decision.reason,
            requestId: decision.requestId
          }));
          return;
        }

        if (decision.decision === PolicyDecision.REQUIRE_STEP_UP) {
          res.statusCode = 401;
          res.setHeader('Content-Type', 'application/json');
          res.setHeader('X-Step-Up-Required', 'true');
          res.end(JSON.stringify({
            error: 'Step-up Authentication Required',
            reason: decision.reason,
            requestId: decision.requestId
          }));
          return;
        }

        // Добавление заголовков с решением
        res.setHeader('X-Access-Decision', decision.decision);
        res.setHeader('X-Trust-Level', TrustLevel[decision.trustLevel]);
        res.setHeader('X-Request-ID', decision.requestId);

        if (decision.metadata?.restrictions) {
          const restrictions = decision.metadata.restrictions as {
            timeLimit?: number;
            operationLimit?: PolicyOperation[];
            dataLimit?: string[];
            requireStepUp?: boolean;
          };
          
          const restrictionsList: string[] = [];
          if (restrictions.timeLimit) {
            restrictionsList.push(`timeLimit=${restrictions.timeLimit}s`);
          }
          if (restrictions.operationLimit) {
            restrictionsList.push(`operations=${restrictions.operationLimit.join(',')}`);
          }
          if (restrictions.dataLimit) {
            restrictionsList.push(`dataLimit=${restrictions.dataLimit.join(',')}`);
          }
          if (restrictions.requireStepUp) {
            restrictionsList.push('requireStepUp=true');
          }
          res.setHeader('X-Access-Restrictions', restrictionsList.join(','));
        }

        next();

      } catch (error) {
        this.emit('middleware_error', { error, path: req.url });
        next();
      }
    };
  }

  /**
   * Маппинг HTTP метода в операцию
   */
  private mapHttpMethodToOperation(method?: string): PolicyOperation {
    switch (method?.toUpperCase()) {
      case 'GET':
      case 'HEAD':
        return PolicyOperation.READ;
      case 'POST':
        return PolicyOperation.CREATE;
      case 'PUT':
      case 'PATCH':
        return PolicyOperation.WRITE;
      case 'DELETE':
        return PolicyOperation.DELETE;
      default:
        return PolicyOperation.READ;
    }
  }

  /**
   * Принудить доступ (публичный метод для PEP)
   */
  async enforceAccess(context: {
    identity: Identity;
    authContext: AuthContext;
    resourceType: ResourceType;
    resourceId: string;
    operation: PolicyOperation;
    sourceIp: string;
    destinationIp?: string;
    destinationPort?: number;
    protocol?: string;
  }): Promise<AccessResponse> {
    const pepRequest: PepRequest = {
      requestId: uuidv4(),
      identity: {
        ...context.identity,
        subjectId: context.identity.subjectId || context.identity.id,
        subjectType: context.identity.subjectType || context.identity.type
      },
      authContext: {
        ...context.authContext,
        method: context.authContext.method || AuthenticationMethod.JWT,
        expiresAt: context.authContext.expiresAt || new Date(Date.now() + 3600000),
        levelOfAssurance: context.authContext.levelOfAssurance || 1,
        factors: context.authContext.factors || context.authContext.authenticationMethods || [],
        mfaVerified: context.authContext.mfaVerified || false,
        mfaMethods: context.authContext.mfaMethods || []
      },
      resourceType: context.resourceType,
      resourceId: context.resourceId,
      operation: context.operation,
      sourceIp: context.sourceIp,
      destinationIp: context.destinationIp,
      destinationPort: context.destinationPort,
      protocol: context.protocol
    };

    return this.interceptRequest(pepRequest);
  }

  /**
   * Получение PDP
   */
  getPdp(): PolicyDecisionPoint {
    return this.pdp;
  }

  /**
   * Получение Trust Verifier
   */
  getTrustVerifier(): TrustVerifier {
    return this.trustVerifier;
  }

  /**
   * Получение статистики
   */
  getStats(): {
    cacheSize: number;
    deniedRateLimitsCount: number;
    isInitialized: boolean;
    pdpStats: any;
    trustVerifierStats: any;
  } {
    return {
      cacheSize: this.decisionCache.size,
      deniedRateLimitsCount: this.deniedRateLimits.size,
      isInitialized: this.isInitialized,
      pdpStats: this.pdp.getStats(),
      trustVerifierStats: this.trustVerifier.getStats()
    };
  }

  /**
   * Очистка кэша
   */
  clearCache(): void {
    this.decisionCache.clear();
    this.emit('cache_cleared');
  }

  /**
   * Очистка rate limits
   */
  clearDeniedRateLimits(): void {
    this.deniedRateLimits.clear();
    this.emit('denied_rate_limits_cleared');
  }
}
