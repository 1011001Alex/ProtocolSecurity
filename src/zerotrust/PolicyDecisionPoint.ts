/**
 * ============================================================================
 * POLICY DECISION POINT (PDP) — ТОЧКА ПРИНЯТИЯ РЕШЕНИЙ
 * ============================================================================
 * Полная реализация PDP для Zero Trust Architecture (NIST SP 800-207)
 * 
 * Функционал:
 * - Оценка запросов доступа на основе политик
 * - Динамическое вычисление уровня доверия
 * - Контекстная оценка (время, местоположение, поведение)
 * - Кэширование решений с TTL
 * - Аудит и логирование всех решений
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  PolicyDecision,
  TrustLevel,
  SubjectType,
  ResourceType,
  PolicyOperation,
  AccessPolicyRule,
  PolicyCondition,
  PolicyConstraint,
  PolicyEvaluationResult,
  Identity,
  AuthContext,
  DevicePosture,
  DeviceHealthStatus,
  AuthenticationMethod,
  PolicyDecisionMetadata,
  RiskAssessment,
  AccessRequest,
  AccessResponse
} from './zerotrust.types';

/**
 * Контекст запроса доступа
 */
interface AccessRequestContext {
  requestId: string;
  identity: Identity;
  authContext: AuthContext;
  devicePosture?: DevicePosture;
  resourceType: ResourceType;
  resourceId: string;
  resourceName: string;
  operation: PolicyOperation;
  resourceAttributes: Record<string, unknown>;
  networkContext: {
    sourceIp: string;
    destinationIp: string;
    destinationPort: number;
    protocol: string;
  };
  temporalContext: {
    timestamp: Date;
    dayOfWeek: number;
    hourOfDay: number;
    timezone: string;
  };
  behavioralContext: {
    isUnusualLocation: boolean;
    isUnusualTime: boolean;
    isUnusualDevice: boolean;
    isAnomalousBehavior: boolean;
    riskScore: number;
  };
}

/**
 * Кэш решений PDP
 */
interface PolicyDecisionCache {
  decisions: Map<string, {
    result: PolicyEvaluationResult;
    cachedAt: Date;
    expiresAt: Date;
  }>;
  maxSize: number;
  defaultTtl: number;
}

/**
 * Конфигурация Policy Decision Point
 */
export interface PdpConfig {
  enableCaching: boolean;
  cacheDefaultTtl: number;
  cacheMaxSize: number;
  enableLogging: boolean;
  enableVerboseLogging: boolean;
  cacheTrustLevelThreshold: TrustLevel;
  enableBehavioralAnalysis: boolean;
  behavioralWeight: number;
  enableRiskAssessment: boolean;
  riskThresholds: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  enableTemporalConstraints: boolean;
  enableNetworkConstraints: boolean;
  enableDevicePostureEnforcement: boolean;
  stepUpAuthRequired: {
    forUnusualLocation: boolean;
    forUnusualTime: boolean;
    forUnusualDevice: boolean;
    forHighRiskScore: number;
  };
}

/**
 * Policy Decision Point — основная реализация
 */
export class PolicyDecisionPoint extends EventEmitter {
  private readonly config: PdpConfig;
  private readonly cache: PolicyDecisionCache;
  private readonly policies: Map<string, AccessPolicyRule> = new Map();
  private readonly constraints: Map<string, PolicyConstraint> = new Map();
  private readonly trustLevelWeights: Map<TrustLevel, number> = new Map();
  private isInitialized: boolean = false;

  constructor(config: Partial<PdpConfig> = {}) {
    super();
    
    this.config = {
      enableCaching: true,
      cacheDefaultTtl: 300,
      cacheMaxSize: 10000,
      enableLogging: true,
      enableVerboseLogging: false,
      cacheTrustLevelThreshold: TrustLevel.MEDIUM,
      enableBehavioralAnalysis: true,
      behavioralWeight: 0.3,
      enableRiskAssessment: true,
      riskThresholds: {
        low: 20,
        medium: 40,
        high: 60,
        critical: 80
      },
      enableTemporalConstraints: true,
      enableNetworkConstraints: true,
      enableDevicePostureEnforcement: true,
      stepUpAuthRequired: {
        forUnusualLocation: true,
        forUnusualTime: true,
        forUnusualDevice: true,
        forHighRiskScore: 60
      },
      ...config
    };

    this.cache = {
      decisions: new Map(),
      maxSize: this.config.cacheMaxSize,
      defaultTtl: this.config.cacheDefaultTtl
    };

    this.initializeTrustLevelWeights();
    this.isInitialized = true;

    this.emit('initialized', { config: this.config });
  }

  /**
   * Инициализация весов уровней доверия
   */
  private initializeTrustLevelWeights(): void {
    this.trustLevelWeights.set(TrustLevel.UNTRUSTED, 0);
    this.trustLevelWeights.set(TrustLevel.MINIMAL, 0.2);
    this.trustLevelWeights.set(TrustLevel.LOW, 0.4);
    this.trustLevelWeights.set(TrustLevel.MEDIUM, 0.6);
    this.trustLevelWeights.set(TrustLevel.HIGH, 0.8);
    this.trustLevelWeights.set(TrustLevel.FULL, 1.0);
  }

  /**
   * Добавить политику доступа
   */
  public addPolicy(policy: AccessPolicyRule): void {
    this.policies.set(policy.id, policy);
    this.emit('policy:added', { policy });
  }

  /**
   * Регистрация политики доступа
   */
  registerPolicy(policy: AccessPolicyRule): void {
    if (!policy.id) {
      policy.id = uuidv4();
    }
    this.policies.set(policy.id, policy);
    this.emit('policy_registered', { policyId: policy.id });
  }

  /**
   * Удаление политики
   */
  unregisterPolicy(policyId: string): void {
    this.policies.delete(policyId);
    this.emit('policy_unregistered', { policyId });
  }

  /**
   * Регистрация ограничения
   */
  registerConstraint(constraint: PolicyConstraint): void {
    if (!constraint.id) {
      constraint.id = uuidv4();
    }
    this.constraints.set(constraint.id, constraint);
    this.emit('constraint_registered', { constraintId: constraint.id });
  }

  /**
   * Оценка запроса доступа
   */
  async evaluateAccess(request: AccessRequest): Promise<AccessResponse> {
    const requestId = request.requestId || uuidv4();
    const startTime = Date.now();

    try {
      // Проверка кэша
      const cacheKey = this.getCacheKey(request);
      if (this.config.enableCaching) {
        const cachedDecision = this.getCachedDecision(cacheKey);
        if (cachedDecision) {
          return {
            ...cachedDecision,
            responseId: uuidv4(),
            requestId,
            decidedAt: new Date(),
            appliedRules: cachedDecision.appliedRules || [],
            cached: true,
            evaluationTime: Date.now() - startTime
          };
        }
      }

      // Построение контекста запроса
      const context = this.buildRequestContext(request, requestId);

      // Оценка уровня доверия
      const trustLevel = this.evaluateTrustLevel(context);

      // Оценка рисков
      const riskAssessment = this.assessRisk(context, trustLevel);

      // Оценка политик
      const policyResult = await this.evaluatePolicies(context, trustLevel, riskAssessment);

      // Оценка ограничений
      const constraintsResult = this.evaluateConstraints(context);

      // Финальное решение
      const finalDecision = this.makeFinalDecision(
        policyResult,
        constraintsResult,
        trustLevel,
        riskAssessment
      );

      // Кэширование решения
      if (this.config.enableCaching && finalDecision.decision !== PolicyDecision.DENY) {
        this.cacheDecision(cacheKey, finalDecision, trustLevel);
      }

      // Логирование
      if (this.config.enableLogging) {
        this.logDecision(requestId, context, finalDecision, trustLevel, riskAssessment);
      }

      const response: AccessResponse = {
        ...finalDecision,
        responseId: uuidv4(),
        requestId,
        decidedAt: new Date(),
        appliedRules: finalDecision.appliedRules || [],
        trustLevel,
        riskAssessment,
        cached: false,
        evaluationTime: Date.now() - startTime,
        timestamp: new Date()
      };

      this.emit('access_evaluated', response);
      return response;

    } catch (error) {
      const errorResponse: AccessResponse = {
        responseId: uuidv4(),
        requestId,
        decidedAt: new Date(),
        appliedRules: [],
        decision: PolicyDecision.DENY,
        reason: error instanceof Error ? error.message : 'Unknown error',
        trustLevel: TrustLevel.UNTRUSTED,
        riskAssessment: {
          level: 'critical',
          score: 100,
          factors: ['evaluation_error']
        },
        cached: false,
        evaluationTime: Date.now() - startTime,
        timestamp: new Date(),
        metadata: {
          policyId: 'error',
          evaluationSteps: [],
          timestamp: new Date()
        }
      };

      this.emit('access_error', { requestId, error });
      return errorResponse;
    }
  }

  /**
   * Построение контекста запроса
   */
  private buildRequestContext(request: AccessRequest, requestId: string): AccessRequestContext {
    const now = new Date();

    return {
      requestId,
      identity: request.identity,
      authContext: request.authContext,
      devicePosture: request.devicePosture,
      resourceType: request.resourceType,
      resourceId: request.resourceId,
      resourceName: request.resourceName || request.resourceId,
      operation: request.operation,
      resourceAttributes: request.resourceAttributes || {},
      networkContext: {
        sourceIp: request.sourceIp || 'unknown',
        destinationIp: request.destinationIp || 'unknown',
        destinationPort: request.destinationPort || 0,
        protocol: request.protocol || 'HTTPS'
      },
      temporalContext: {
        timestamp: now,
        dayOfWeek: now.getDay(),
        hourOfDay: now.getHours(),
        timezone: request.timezone || 'UTC'
      },
      behavioralContext: {
        isUnusualLocation: request.isUnusualLocation || false,
        isUnusualTime: request.isUnusualTime || false,
        isUnusualDevice: request.isUnusualDevice || false,
        isAnomalousBehavior: request.isAnomalousBehavior || false,
        riskScore: request.riskScore || 0
      }
    };
  }

  /**
   * Оценка уровня доверия
   */
  private evaluateTrustLevel(context: AccessRequestContext): TrustLevel {
    let trustScore = 0;
    const factors: string[] = [];

    // Оценка метода аутентификации
    const authMethodScore = this.evaluateAuthMethod(context.authContext);
    trustScore += authMethodScore.score;
    factors.push(...authMethodScore.factors);

    // Оценка состояния устройства
    if (context.devicePosture && this.config.enableDevicePostureEnforcement) {
      const deviceScore = this.evaluateDevicePosture(context.devicePosture);
      trustScore += deviceScore.score;
      factors.push(...deviceScore.factors);
    }

    // Оценка поведенческих факторов
    if (this.config.enableBehavioralAnalysis) {
      const behavioralScore = this.evaluateBehavioralContext(context.behavioralContext);
      trustScore += behavioralScore.score;
      factors.push(...behavioralScore.factors);
    }

    // Нормализация до 0-1
    const normalizedScore = Math.min(1, trustScore / 3);

    // Маппинг на TrustLevel
    let trustLevel: TrustLevel;
    if (normalizedScore < 0.2) {
      trustLevel = TrustLevel.UNTRUSTED;
    } else if (normalizedScore < 0.4) {
      trustLevel = TrustLevel.MINIMAL;
    } else if (normalizedScore < 0.6) {
      trustLevel = TrustLevel.LOW;
    } else if (normalizedScore < 0.8) {
      trustLevel = TrustLevel.MEDIUM;
    } else if (normalizedScore < 0.95) {
      trustLevel = TrustLevel.HIGH;
    } else {
      trustLevel = TrustLevel.FULL;
    }

    this.emit('trust_evaluated', { 
      requestId: context.requestId, 
      trustLevel, 
      trustScore: normalizedScore,
      factors 
    });

    return trustLevel;
  }

  /**
   * Оценка метода аутентификации
   */
  private evaluateAuthMethod(authContext: AuthContext): { score: number; factors: string[] } {
    let score = 0;
    const factors: string[] = [];

    const methods = authContext.authenticationMethods || [];

    if (methods.includes(AuthenticationMethod.PASSWORD)) {
      score += 0.2;
      factors.push('password_auth');
    }

    if (methods.includes(AuthenticationMethod.MFA) || 
        methods.includes(AuthenticationMethod.WEBAUTHN) ||
        methods.includes(AuthenticationMethod.BIOMETRIC)) {
      score += 0.4;
      factors.push('strong_auth');
    }

    if (methods.includes(AuthenticationMethod.CERTIFICATE) ||
        methods.includes(AuthenticationMethod.MTLS)) {
      score += 0.3;
      factors.push('certificate_auth');
    }

    if (methods.includes(AuthenticationMethod.OAUTH) ||
        methods.includes(AuthenticationMethod.JWT)) {
      score += 0.1;
      factors.push('token_auth');
    }

    // Проверка времени аутентификации
    const authAge = Date.now() - authContext.authenticatedAt.getTime();
    const maxAge = 8 * 60 * 60 * 1000; // 8 часов
    
    if (authAge > maxAge) {
      score *= 0.5;
      factors.push('stale_auth');
    }

    return { score, factors };
  }

  /**
   * Оценка состояния устройства
   */
  private evaluateDevicePosture(posture: DevicePosture): { score: number; factors: string[] } {
    let score = 0;
    const factors: string[] = [];

    // Оценка статуса здоровья
    switch (posture.healthStatus) {
      case DeviceHealthStatus.HEALTHY:
        score += 0.4;
        factors.push('device_healthy');
        break;
      case DeviceHealthStatus.UNKNOWN:
        score += 0.1;
        factors.push('device_unknown');
        break;
      case DeviceHealthStatus.UNHEALTHY:
        score += 0;
        factors.push('device_unhealthy');
        break;
      case DeviceHealthStatus.NON_COMPLIANT:
        score += 0;
        factors.push('device_non_compliant');
        break;
    }

    // Оценка соответствия
    if (posture.isCompliant) {
      score += 0.3;
      factors.push('device_compliant');
    } else {
      factors.push('device_non_compliant');
    }

    // Проверка шифрования
    if (posture.isEncrypted) {
      score += 0.15;
      factors.push('device_encrypted');
    }

    // Проверка антивируса
    if (posture.hasAntivirus) {
      score += 0.15;
      factors.push('antivirus_present');
    }

    return { score, factors };
  }

  /**
   * Оценка поведенческого контекста
   */
  private evaluateBehavioralContext(behavioral: {
    isUnusualLocation: boolean;
    isUnusualTime: boolean;
    isUnusualDevice: boolean;
    isAnomalousBehavior: boolean;
    riskScore: number;
  }): { score: number; factors: string[] } {
    let score = 1.0;
    const factors: string[] = [];

    if (behavioral.isUnusualLocation) {
      score -= 0.2;
      factors.push('unusual_location');
    }

    if (behavioral.isUnusualTime) {
      score -= 0.15;
      factors.push('unusual_time');
    }

    if (behavioral.isUnusualDevice) {
      score -= 0.2;
      factors.push('unusual_device');
    }

    if (behavioral.isAnomalousBehavior) {
      score -= 0.3;
      factors.push('anomalous_behavior');
    }

    if (behavioral.riskScore > this.config.riskThresholds.high) {
      score -= 0.25;
      factors.push('high_risk_score');
    }

    return { score: Math.max(0, score), factors };
  }

  /**
   * Оценка рисков
   */
  private assessRisk(
    context: AccessRequestContext,
    trustLevel: TrustLevel
  ): RiskAssessment {
    const factors: string[] = [];
    let riskScore = 0;

    // Базовый риск от уровня доверия
    const trustWeight = this.trustLevelWeights.get(trustLevel) || 0;
    riskScore += (1 - trustWeight) * 50;

    // Риск от необычного поведения
    if (context.behavioralContext.isUnusualLocation) {
      riskScore += 15;
      factors.push('unusual_location');
    }

    if (context.behavioralContext.isUnusualTime) {
      riskScore += 10;
      factors.push('unusual_time');
    }

    if (context.behavioralContext.isAnomalousBehavior) {
      riskScore += 25;
      factors.push('anomalous_behavior');
    }

    // Риск от типа ресурса
    if (context.resourceType === ResourceType.DATABASE ||
        context.resourceType === ResourceType.FILE_STORAGE) {
      riskScore += 10;
      factors.push('sensitive_resource');
    }

    // Риск от операции
    if (context.operation === PolicyOperation.DELETE ||
        context.operation === PolicyOperation.WRITE) {
      riskScore += 10;
      factors.push('destructive_operation');
    }

    // Определение уровня риска
    let level: 'low' | 'medium' | 'high' | 'critical';
    if (riskScore < this.config.riskThresholds.low) {
      level = 'low';
    } else if (riskScore < this.config.riskThresholds.medium) {
      level = 'medium';
    } else if (riskScore < this.config.riskThresholds.high) {
      level = 'high';
    } else {
      level = 'critical';
    }

    return {
      level,
      score: Math.min(100, Math.round(riskScore)),
      factors
    };
  }

  /**
   * Оценка политик доступа
   */
  private async evaluatePolicies(
    context: AccessRequestContext,
    trustLevel: TrustLevel,
    riskAssessment: RiskAssessment
  ): Promise<PolicyEvaluationResult> {
    const evaluationSteps: string[] = [];
    let decision = PolicyDecision.ALLOW;
    let reason = 'Access granted by default policy';
    const appliedPolicies: string[] = [];
    const appliedRules: Array<{ ruleId: string; ruleName: string; effect: 'ALLOW' | 'DENY' }> = [];
    const factors: Array<{ name: string; value: string | number | boolean; weight: number; impact: 'POSITIVE' | 'NEGATIVE' | 'NEUTRAL' }> = [];

    // Если нет политик — разрешаем по умолчанию
    if (this.policies.size === 0) {
      evaluationSteps.push('No policies registered, allowing by default');
      return {
        evaluationId: uuidv4(),
        evaluatedAt: new Date(),
        decision,
        trustLevel,
        appliedRules: [],
        factors,
        restrictions: {},
        recommendations: [],
        reason,
        appliedPolicies,
        evaluationSteps,
        metadata: {
          policyId: 'default',
          timestamp: new Date()
        }
      };
    }

    // Оценка каждой политики
    for (const [policyId, policy] of this.policies.entries()) {
      const matches = this.evaluatePolicyConditions(policy, context, trustLevel);

      if (matches) {
        appliedPolicies.push(policyId);
        appliedRules.push({
          ruleId: policy.id,
          ruleName: policy.name,
          effect: policy.effect
        });
        evaluationSteps.push(`Policy ${policyId} matched`);

        if (policy.effect === 'DENY') {
          decision = PolicyDecision.DENY;
          reason = `Access denied by policy ${policyId}`;
          evaluationSteps.push(`Policy ${policyId} denies access`);
          factors.push({
            name: `policy:${policyId}`,
            value: policy.effect,
            weight: 100,
            impact: 'NEGATIVE'
          });
          break; // DENY имеет приоритет
        } else if (policy.effect === 'ALLOW') {
          if (decision === PolicyDecision.ALLOW) {
            decision = PolicyDecision.ALLOW;
            reason = `Access granted by policy ${policyId}`;
            factors.push({
              name: `policy:${policyId}`,
              value: policy.effect,
              weight: 50,
              impact: 'POSITIVE'
            });
          }
        }
      }
    }

    // Добавляем фактор уровня доверия
    factors.push({
      name: 'trustLevel',
      value: TrustLevel[trustLevel],
      weight: 30,
      impact: trustLevel >= TrustLevel.MEDIUM ? 'POSITIVE' : 'NEUTRAL'
    });

    // Добавляем фактор риска
    factors.push({
      name: 'riskScore',
      value: riskAssessment.score,
      weight: 40,
      impact: riskAssessment.score < 30 ? 'POSITIVE' : riskAssessment.score < 70 ? 'NEUTRAL' : 'NEGATIVE'
    });

    return {
      evaluationId: uuidv4(),
      evaluatedAt: new Date(),
      decision,
      trustLevel,
      appliedRules,
      factors,
      restrictions: this.buildRestrictions(decision, trustLevel, riskAssessment),
      recommendations: this.buildRecommendations(decision, trustLevel, riskAssessment),
      reason,
      appliedPolicies,
      evaluationSteps,
      metadata: {
        policyId: appliedPolicies.length > 0 ? appliedPolicies.join(',') : 'default',
        timestamp: new Date()
      }
    };
  }

  /**
   * Построение ограничений доступа
   */
  private buildRestrictions(
    decision: PolicyDecision,
    trustLevel: TrustLevel,
    riskAssessment: RiskAssessment
  ): PolicyEvaluationResult['restrictions'] {
    const restrictions: PolicyEvaluationResult['restrictions'] = {};

    if (decision === PolicyDecision.ALLOW_RESTRICTED || decision === PolicyDecision.REQUIRE_STEP_UP) {
      restrictions.requireStepUp = decision === PolicyDecision.REQUIRE_STEP_UP;
      
      if (trustLevel < TrustLevel.MEDIUM) {
        restrictions.timeLimit = 1800; // 30 минут
      }
      
      if (riskAssessment.score > 50) {
        restrictions.operationLimit = [PolicyOperation.READ];
      }
    }

    return restrictions;
  }

  /**
   * Построение рекомендаций
   */
  private buildRecommendations(
    decision: PolicyDecision,
    trustLevel: TrustLevel,
    riskAssessment: RiskAssessment
  ): string[] {
    const recommendations: string[] = [];

    if (trustLevel < TrustLevel.LOW) {
      recommendations.push('Consider enabling MFA for higher trust level');
    }

    if (riskAssessment.score > 70) {
      recommendations.push('High risk detected - additional monitoring recommended');
    }

    if (decision === PolicyDecision.DENY) {
      recommendations.push('Review access policy or contact administrator');
    }

    return recommendations;
  }

  /**
   * Оценка условий политики
   */
  private evaluatePolicyConditions(
    policy: AccessPolicyRule,
    context: AccessRequestContext,
    trustLevel: TrustLevel
  ): boolean {
    if (!policy.conditions) {
      return true;
    }

    // Оценка всех условий (AND логика)
    for (const condition of policy.conditions) {
      if (!this.evaluateCondition(condition, context, trustLevel)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Оценка одного условия
   */
  private evaluateCondition(
    condition: PolicyCondition,
    context: AccessRequestContext,
    trustLevel: TrustLevel
  ): boolean {
    switch (condition.attribute) {
      case 'subjectType':
        return condition.operator === 'EQ'
          ? context.identity.subjectType === condition.value
          : context.identity.subjectType !== condition.value;

      case 'resourceType':
        return condition.operator === 'EQ'
          ? context.resourceType === condition.value
          : context.resourceType !== condition.value;

      case 'operation':
        return condition.operator === 'EQ'
          ? context.operation === condition.value
          : context.operation !== condition.value;

      case 'trustLevel':
        const requiredLevel = condition.value as TrustLevel;
        return trustLevel >= requiredLevel;

      case 'timeOfDay':
        if (!this.config.enableTemporalConstraints) return true;
        const hour = context.temporalContext.hourOfDay;
        const timeRange = condition.value as unknown as [number, number];
        const [startHour, endHour] = timeRange;
        return hour >= startHour && hour < endHour;

      case 'dayOfWeek':
        if (!this.config.enableTemporalConstraints) return true;
        const day = context.temporalContext.dayOfWeek;
        const daysArray = condition.value as unknown as number[];
        return daysArray.includes(day);

      case 'sourceIp':
        if (!this.config.enableNetworkConstraints) return true;
        const ipPattern = condition.value as string;
        return context.networkContext.sourceIp.match(ipPattern) !== null;

      case 'deviceHealth':
        if (!this.config.enableDevicePostureEnforcement) return true;
        const healthStatus = context.devicePosture?.healthStatus;
        return condition.operator === 'EQ'
          ? healthStatus === condition.value
          : healthStatus !== condition.value;

      default:
        return true;
    }
  }

  /**
   * Оценка ограничений
   */
  private evaluateConstraints(context: AccessRequestContext): boolean {
    if (this.constraints.size === 0) {
      return true;
    }

    for (const [, constraint] of this.constraints.entries()) {
      if (!this.evaluateConstraint(constraint, context)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Оценка одного ограничения
   */
  private evaluateConstraint(
    constraint: PolicyConstraint,
    context: AccessRequestContext
  ): boolean {
    // Простая реализация — может быть расширена
    return true;
  }

  /**
   * Принятие финального решения
   */
  private makeFinalDecision(
    policyResult: PolicyEvaluationResult,
    constraintsPass: boolean,
    trustLevel: TrustLevel,
    riskAssessment: RiskAssessment
  ): Omit<AccessResponse, 'requestId' | 'cached' | 'evaluationTime' | 'timestamp'> {
    // Если ограничения не прошли — DENY
    if (!constraintsPass) {
      return {
        responseId: uuidv4(),
        decidedAt: new Date(),
        decision: PolicyDecision.DENY,
        reason: 'Security constraints not satisfied',
        trustLevel,
        riskAssessment,
        appliedRules: policyResult.appliedRules,
        restrictions: policyResult.restrictions,
        recommendations: ['Resolve security constraint violations before requesting access again']
      };
    }

    // Проверка на step-up аутентификацию
    if (this.requiresStepUpAuth(trustLevel, riskAssessment)) {
      return {
        responseId: uuidv4(),
        decidedAt: new Date(),
        decision: PolicyDecision.REQUIRE_STEP_UP,
        reason: 'Step-up authentication required due to risk factors',
        trustLevel,
        riskAssessment,
        appliedRules: policyResult.appliedRules,
        restrictions: {
          ...policyResult.restrictions,
          requireStepUp: true
        },
        recommendations: ['Complete step-up authentication to proceed']
      };
    }

    // Возвращаем решение политик
    return {
      responseId: uuidv4(),
      decidedAt: new Date(),
      decision: policyResult.decision,
      reason: policyResult.reason,
      trustLevel,
      riskAssessment,
      appliedRules: policyResult.appliedRules,
      restrictions: policyResult.restrictions,
      recommendations: policyResult.recommendations
    };
  }

  /**
   * Проверка необходимости step-up аутентификации
   */
  private requiresStepUpAuth(
    trustLevel: TrustLevel,
    riskAssessment: RiskAssessment
  ): boolean {
    if (this.config.stepUpAuthRequired.forUnusualLocation &&
        riskAssessment.factors.includes('unusual_location')) {
      return true;
    }

    if (this.config.stepUpAuthRequired.forUnusualTime &&
        riskAssessment.factors.includes('unusual_time')) {
      return true;
    }

    if (riskAssessment.score >= this.config.stepUpAuthRequired.forHighRiskScore) {
      return true;
    }

    return false;
  }

  /**
   * Получение кэшированного решения
   */
  private getCachedDecision(cacheKey: string): PolicyEvaluationResult | null {
    const cached = this.cache.decisions.get(cacheKey);
    if (!cached) {
      return null;
    }

    if (new Date() > cached.expiresAt) {
      this.cache.decisions.delete(cacheKey);
      return null;
    }

    return cached.result;
  }

  /**
   * Кэширование решения
   */
  private cacheDecision(
    cacheKey: string,
    decision: Omit<AccessResponse, 'requestId' | 'cached' | 'evaluationTime' | 'timestamp'>,
    trustLevel: TrustLevel
  ): void {
    // Кэшируем только решения с достаточным уровнем доверия
    if (trustLevel < this.config.cacheTrustLevelThreshold) {
      return;
    }

    // Очистка старого кэша
    if (this.cache.decisions.size >= this.cache.maxSize) {
      const firstKey = this.cache.decisions.keys().next().value;
      if (firstKey) {
        this.cache.decisions.delete(firstKey);
      }
    }

    const ttl = this.cache.defaultTtl * 1000;
    this.cache.decisions.set(cacheKey, {
      result: {
        evaluationId: uuidv4(),
        evaluatedAt: new Date(),
        decision: decision.decision,
        trustLevel,
        appliedRules: decision.appliedRules || [],
        factors: [],
        restrictions: decision.restrictions || {},
        recommendations: decision.recommendations || [],
        reason: decision.reason
      },
      cachedAt: new Date(),
      expiresAt: new Date(Date.now() + ttl)
    });
  }

  /**
   * Генерация ключа кэша
   */
  private getCacheKey(request: AccessRequest): string {
    return `${request.identity.subjectId}:${request.resourceType}:${request.resourceId}:${request.operation}`;
  }

  /**
   * Логирование решения
   */
  private logDecision(
    requestId: string,
    context: AccessRequestContext,
    decision: Omit<AccessResponse, 'requestId' | 'cached' | 'evaluationTime' | 'timestamp'>,
    trustLevel: TrustLevel,
    riskAssessment: RiskAssessment
  ): void {
    const logEntry = {
      timestamp: new Date(),
      requestId,
      decision: decision.decision,
      trustLevel,
      riskScore: riskAssessment.score,
      subjectId: context.identity.subjectId,
      resourceType: context.resourceType,
      resourceId: context.resourceId,
      operation: context.operation,
      sourceIp: context.networkContext.sourceIp
    };

    if (this.config.enableVerboseLogging) {
      console.log('[PDP Decision]', JSON.stringify(logEntry, null, 2));
    }

    this.emit('decision_logged', logEntry);
  }

  /**
   * Очистка кэша
   */
  clearCache(): void {
    this.cache.decisions.clear();
    this.emit('cache_cleared');
  }

  /**
   * Получение статистики
   */
  getStats(): {
    policiesCount: number;
    constraintsCount: number;
    cacheSize: number;
    isInitialized: boolean;
  } {
    return {
      policiesCount: this.policies.size,
      constraintsCount: this.constraints.size,
      cacheSize: this.cache.decisions.size,
      isInitialized: this.isInitialized
    };
  }
}
