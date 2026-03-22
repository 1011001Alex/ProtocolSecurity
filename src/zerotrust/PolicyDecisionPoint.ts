/**
 * Policy Decision Point (PDP) - Точка Принятия Решений Политик
 * 
 * Компонент отвечает за оценку запросов доступа и принятие решений
 * на основе политик безопасности, контекста и уровня доверия.
 * Реализует логику в соответствии с NIST SP 800-207 Zero Trust Architecture.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
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
  ZeroTrustEvent,
  Identity,
  AuthContext,
  DevicePosture,
  DeviceHealthStatus
} from './zerotrust.types';

/**
 * Контекст запроса доступа
 */
interface AccessRequestContext {
  /** Уникальный идентификатор запроса */
  requestId: string;
  
  /** Идентичность субъекта */
  identity: Identity;
  
  /** Контекст аутентификации */
  authContext: AuthContext;
  
  /** Постура устройства */
  devicePosture?: DevicePosture;
  
  /** Тип ресурса */
  resourceType: ResourceType;
  
  /** ID ресурса */
  resourceId: string;
  
  /** Название ресурса */
  resourceName: string;
  
  /** Запрашиваемая операция */
  operation: PolicyOperation;
  
  /** Дополнительные атрибуты ресурса */
  resourceAttributes: Record<string, unknown>;
  
  /** Сетевой контекст */
  networkContext: {
    /** IP адрес источника */
    sourceIp: string;
    /** IP адрес назначения */
    destinationIp: string;
    /** Порт назначения */
    destinationPort: number;
    /** Протокол */
    protocol: string;
  };
  
  /** Временной контекст */
  temporalContext: {
    /** Время запроса */
    timestamp: Date;
    /** День недели */
    dayOfWeek: number;
    /** Час дня */
    hourOfDay: number;
    /** Часовой пояс */
    timezone: string;
  };
  
  /** Поведенческий контекст */
  behavioralContext: {
    /** Это необычное местоположение? */
    isUnusualLocation: boolean;
    /** Это необычное время? */
    isUnusualTime: boolean;
    /** Это необычное устройство? */
    isUnusualDevice: boolean;
    /** Аномальная активность? */
    isAnomalousBehavior: boolean;
    /** Оценка риска поведения */
    riskScore: number;
  };
}

/**
 * Кэш решений PDP
 */
interface PolicyDecisionCache {
  /** Кэш по ключу запроса */
  decisions: Map<string, {
    /** Результат решения */
    result: PolicyEvaluationResult;
    /** Время кэширования */
    cachedAt: Date;
    /** Время истечения */
    expiresAt: Date;
  }>;
  
  /** Максимальный размер кэша */
  maxSize: number;
  
  /** TTL кэша по умолчанию */
  defaultTtl: number;
}

/**
 * Конфигурация Policy Decision Point
 */
export interface PdpConfig {
  /** Включить кэширование решений */
  enableCaching: boolean;
  
 /** TTL кэша по умолчанию (секунды) */
  cacheDefaultTtl: number;
  
  /** Максимальный размер кэша */
  cacheMaxSize: number;
  
  /** Включить логирование решений */
  enableLogging: boolean;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
  
  /** Порог уровня доверия для кэширования */
  cacheTrustLevelThreshold: TrustLevel;
  
  /** Включить оценку поведенческих факторов */
  enableBehavioralAnalysis: boolean;
  
  /** Вес поведенческих факторов в оценке */
  behavioralWeight: number;
  
  /** Минимальный уровень доверия для доступа */
  minimumTrustLevel: TrustLevel;
}

/**
 * Policy Decision Point (PDP)
 * 
 * Центральный компонент системы Zero Trust для принятия решений о доступе.
 * Оценивает запросы на основе политик, контекста и уровня доверия.
 */
export class PolicyDecisionPoint extends EventEmitter {
  /** Конфигурация PDP */
  private config: PdpConfig;
  
  /** Политики доступа */
  private policies: Map<string, AccessPolicyRule>;
  
  /** Кэш решений */
  private cache: PolicyDecisionCache;
  
  /** История решений для аудита */
  private decisionHistory: PolicyEvaluationResult[];
  
  /** Максимальный размер истории */
  private maxHistorySize: number;
  
  /** Статистика PDP */
  private stats: {
    /** Всего запросов */
    totalRequests: number;
    /** Разрешающих решений */
    allowDecisions: number;
    /** Запрещающих решений */
    denyDecisions: number;
    /** Среднее время оценки */
    averageEvaluationTime: number;
    /** Попаданий в кэш */
    cacheHits: number;
    /** Промахов кэша */
    cacheMisses: number;
  };

  constructor(config: Partial<PdpConfig> = {}) {
    super();
    
    this.config = {
      enableCaching: config.enableCaching ?? true,
      cacheDefaultTtl: config.cacheDefaultTtl ?? 300, // 5 минут
      cacheMaxSize: config.cacheMaxSize ?? 10000,
      enableLogging: config.enableLogging ?? true,
      enableVerboseLogging: config.enableVerboseLogging ?? false,
      cacheTrustLevelThreshold: config.cacheTrustLevelThreshold ?? TrustLevel.MEDIUM,
      enableBehavioralAnalysis: config.enableBehavioralAnalysis ?? true,
      behavioralWeight: config.behavioralWeight ?? 0.3,
      minimumTrustLevel: config.minimumTrustLevel ?? TrustLevel.LOW
    };
    
    this.policies = new Map();
    this.cache = {
      decisions: new Map(),
      maxSize: this.config.cacheMaxSize,
      defaultTtl: this.config.cacheDefaultTtl
    };
    this.decisionHistory = [];
    this.maxHistorySize = 10000;
    
    this.stats = {
      totalRequests: 0,
      allowDecisions: 0,
      denyDecisions: 0,
      averageEvaluationTime: 0,
      cacheHits: 0,
      cacheMisses: 0
    };
    
    this.log('PDP', 'PolicyDecisionPoint инициализирован', { config: this.config });
  }

  /**
   * Загрузить политики доступа
   * 
   * @param policies Массив политик для загрузки
   */
  public loadPolicies(policies: AccessPolicyRule[]): void {
    this.policies.clear();
    
    for (const policy of policies) {
      this.policies.set(policy.id, policy);
    }
    
    // Сортируем политики по приоритету
    const sortedPolicies = Array.from(this.policies.values())
      .sort((a, b) => a.priority - b.priority);
    
    this.policies.clear();
    for (const policy of sortedPolicies) {
      this.policies.set(policy.id, policy);
    }
    
    this.log('PDP', `Загружено ${policies.length} политик доступа`);
    this.emit('policies:loaded', { count: policies.length });
  }

  /**
   * Добавить отдельную политику
   * 
   * @param policy Политика для добавления
   */
  public addPolicy(policy: AccessPolicyRule): void {
    this.policies.set(policy.id, policy);
    
    // Пересортировать политики
    const sortedPolicies = Array.from(this.policies.values())
      .sort((a, b) => a.priority - b.priority);
    
    this.policies.clear();
    for (const p of sortedPolicies) {
      this.policies.set(p.id, p);
    }
    
    this.log('PDP', `Добавлена политика: ${policy.name}`);
    this.emit('policy:added', { policyId: policy.id });
  }

  /**
   * Удалить политику
   * 
   * @param policyId ID политики для удаления
   */
  public removePolicy(policyId: string): boolean {
    const removed = this.policies.delete(policyId);
    
    if (removed) {
      this.log('PDP', `Удалена политика: ${policyId}`);
      this.emit('policy:removed', { policyId });
    }
    
    return removed;
  }

  /**
   * Оценить запрос доступа
   * 
   * @param context Контекст запроса доступа
   * @returns Результат оценки политики
   */
  public async evaluateAccess(context: {
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
  }): Promise<PolicyEvaluationResult> {
    const startTime = Date.now();
    this.stats.totalRequests++;
    
    // Создаём полный контекст запроса
    const requestContext = this.buildRequestContext(context);
    
    // Проверяем кэш
    if (this.config.enableCaching) {
      const cachedResult = this.checkCache(requestContext);
      if (cachedResult) {
        this.stats.cacheHits++;
        this.log('PDP', 'Решение найдено в кэше', { 
          requestId: requestContext.requestId,
          decision: cachedResult.decision 
        });
        return cachedResult;
      }
      this.stats.cacheMisses++;
    }
    
    // Вычисляем уровень доверия
    const trustLevel = this.calculateTrustLevel(requestContext);
    
    // Проверяем минимальный уровень доверия
    if (trustLevel < this.config.minimumTrustLevel) {
      const result = this.createDenyResult(
        requestContext,
        trustLevel,
        'Недостаточный уровень доверия'
      );
      return this.finalizeEvaluation(result, startTime, requestContext.requestId);
    }
    
    // Оцениваем политики
    const evaluationResult = this.evaluatePolicies(requestContext, trustLevel);
    
    // Финализируем оценку
    return this.finalizeEvaluation(evaluationResult, startTime, requestContext.requestId);
  }

  /**
   * Построить полный контекст запроса
   */
  private buildRequestContext(context: {
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
  }): AccessRequestContext {
    const now = new Date();
    
    return {
      requestId: uuidv4(),
      identity: context.identity,
      authContext: context.authContext,
      devicePosture: context.devicePosture,
      resourceType: context.resourceType,
      resourceId: context.resourceId,
      resourceName: context.resourceName,
      operation: context.operation,
      resourceAttributes: context.resourceAttributes ?? {},
      networkContext: {
        sourceIp: context.sourceIp,
        destinationIp: context.destinationIp ?? '0.0.0.0',
        destinationPort: context.destinationPort ?? 0,
        protocol: context.protocol ?? 'TCP'
      },
      temporalContext: {
        timestamp: now,
        dayOfWeek: now.getDay(),
        hourOfDay: now.getHours(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      behavioralContext: {
        isUnusualLocation: false, // Будет вычислено
        isUnusualTime: false,
        isUnusualDevice: false,
        isAnomalousBehavior: false,
        riskScore: 0
      }
    };
  }

  /**
   * Вычислить уровень доверия к субъекту
   */
  private calculateTrustLevel(context: AccessRequestContext): TrustLevel {
    let trustScore = 0;
    const factors: PolicyEvaluationResult['factors'] = [];
    
    // Фактор 1: Метод аутентификации (макс. 20 баллов)
    const authMethodScore = this.evaluateAuthMethod(context.authContext);
    factors.push({
      name: 'authentication_method',
      value: context.authContext.method,
      weight: 0.2,
      impact: authMethodScore >= 15 ? 'POSITIVE' : authMethodScore > 0 ? 'NEUTRAL' : 'NEGATIVE'
    });
    trustScore += authMethodScore;
    
    // Фактор 2: MFA верификация (макс. 15 баллов)
    const mfaScore = context.authContext.mfaVerified ? 15 : 0;
    factors.push({
      name: 'mfa_verified',
      value: context.authContext.mfaVerified,
      weight: 0.15,
      impact: mfaScore > 0 ? 'POSITIVE' : 'NEGATIVE'
    });
    trustScore += mfaScore;
    
    // Фактор 3: Posture устройства (макс. 25 баллов)
    const deviceScore = this.evaluateDevicePosture(context.devicePosture);
    factors.push({
      name: 'device_posture',
      value: context.devicePosture?.healthStatus ?? 'UNKNOWN',
      weight: 0.25,
      impact: deviceScore >= 20 ? 'POSITIVE' : deviceScore >= 10 ? 'NEUTRAL' : 'NEGATIVE'
    });
    trustScore += deviceScore;
    
    // Фактор 4: Поведенческий анализ (макс. 20 баллов)
    const behavioralScore = this.evaluateBehavioralContext(context);
    factors.push({
      name: 'behavioral_analysis',
      value: behavioralScore,
      weight: this.config.behavioralWeight,
      impact: behavioralScore >= 15 ? 'POSITIVE' : behavioralScore >= 8 ? 'NEUTRAL' : 'NEGATIVE'
    });
    trustScore += behavioralScore;
    
    // Фактор 5: Сетевой контекст (макс. 20 баллов)
    const networkScore = this.evaluateNetworkContext(context);
    factors.push({
      name: 'network_context',
      value: context.networkContext.sourceIp,
      weight: 0.2,
      impact: networkScore >= 15 ? 'POSITIVE' : networkScore >= 8 ? 'NEUTRAL' : 'NEGATIVE'
    });
    trustScore += networkScore;
    
    // Нормализуем score к TrustLevel (0-100 -> 0-5)
    const normalizedScore = Math.min(100, Math.max(0, trustScore));
    const trustLevel = Math.floor(normalizedScore / 20) as TrustLevel;
    
    // Эмитим событие изменения уровня доверия
    this.emit('trust:evaluated', {
      requestId: context.requestId,
      subjectId: context.identity.id,
      trustLevel,
      trustScore: normalizedScore,
      factors
    });
    
    return trustLevel;
  }

  /**
   * Оценить метод аутентификации
   */
  private evaluateAuthMethod(authContext: AuthContext): number {
    const methodScores: Record<string, number> = {
      'MTLS': 20,
      'CERTIFICATE': 18,
      'WEBAUTHN': 18,
      'MFA': 16,
      'BIOMETRIC': 16,
      'OTP': 14,
      'OAUTH': 12,
      'JWT': 10,
      'API_KEY': 8,
      'PASSWORD': 5,
      'BEHAVIORAL': 10
    };
    
    let score = methodScores[authContext.method] ?? 0;
    
    // Бонус за множественные факторы
    if (authContext.factors.length > 1) {
      score += Math.min(5, authContext.factors.length - 1);
    }
    
    // Бонус за высокий LoA
    if (authContext.levelOfAssurance >= 3) {
      score += 5;
    }
    
    return Math.min(20, score);
  }

  /**
   * Оценить posture устройства
   */
  private evaluateDevicePosture(posture?: DevicePosture): number {
    if (!posture) {
      return 0;
    }
    
    let score = 0;
    
    // Базовый score по статусу здоровья
    const healthScores: Record<DeviceHealthStatus, number> = {
      'HEALTHY': 25,
      'DEGRADED': 15,
      'NON_COMPLIANT': 5,
      'UNKNOWN': 0,
      'BLOCKED': 0
    };
    score += healthScores[posture.healthStatus] ?? 0;
    
    // Проверка соответствия
    const compliance = posture.compliance;
    if (compliance.antivirusActive) score += 2;
    if (compliance.antivirusUpdated) score += 2;
    if (compliance.firewallActive) score += 2;
    if (compliance.diskEncrypted) score += 3;
    if (compliance.secureBootEnabled) score += 2;
    if (compliance.criticalUpdatesInstalled) score += 3;
    if (!compliance.jailbreakDetected) score += 2;
    
    return Math.min(25, score);
  }

  /**
   * Оценить поведенческий контекст
   */
  private evaluateBehavioralContext(context: AccessRequestContext): number {
    if (!this.config.enableBehavioralAnalysis) {
      return 10; // Нейтральная оценка
    }
    
    let score = 20; // Начинаем с максимума и вычитаем за аномалии
    
    // Вычитаем за аномалии
    if (context.behavioralContext.isUnusualLocation) {
      score -= 5;
    }
    if (context.behavioralContext.isUnusualTime) {
      score -= 3;
    }
    if (context.behavioralContext.isUnusualDevice) {
      score -= 4;
    }
    if (context.behavioralContext.isAnomalousBehavior) {
      score -= 8;
    }
    
    // Вычитаем за высокий риск
    score -= Math.floor(context.behavioralContext.riskScore / 10);
    
    return Math.max(0, score);
  }

  /**
   * Оценить сетевой контекст
   */
  private evaluateNetworkContext(context: AccessRequestContext): number {
    let score = 10; // Базовая оценка
    
    // Проверка IP на наличие в whitelist/blacklist
    // (в реальной реализации здесь была бы проверка по базам угроз)
    const sourceIp = context.networkContext.sourceIp;
    
    // Частные IP получают больше доверия
    if (this.isPrivateIp(sourceIp)) {
      score += 5;
    }
    
    // localhost получает максимальное доверие
    if (sourceIp === '127.0.0.1' || sourceIp === '::1') {
      score += 10;
    }
    
    return Math.min(20, score);
  }

  /**
   * Проверить, является ли IP частным
   */
  private isPrivateIp(ip: string): boolean {
    // IPv4 private ranges
    const ipv4PrivatePatterns = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./
    ];
    
    // IPv6 private ranges
    const ipv6PrivatePatterns = [
      /^fe80:/,
      /^fc00:/,
      /^fd00:/,
      /^::1$/
    ];
    
    return ipv4PrivatePatterns.some(p => p.test(ip)) ||
           ipv6PrivatePatterns.some(p => p.test(ip));
  }

  /**
   * Оценить политики доступа
   */
  private evaluatePolicies(
    context: AccessRequestContext,
    trustLevel: TrustLevel
  ): PolicyEvaluationResult {
    const appliedRules: PolicyEvaluationResult['appliedRules'] = [];
    const restrictions: PolicyEvaluationResult['restrictions'] = {};
    const recommendations: string[] = [];
    
    let finalDecision: PolicyDecision = PolicyDecision.DENY;
    let denyReason: string | null = null;
    
    // Проходим по всем политикам в порядке приоритета
    for (const policy of this.policies.values()) {
      // Пропускаем неактивные политики
      if (!policy.enabled) {
        continue;
      }
      
      // Проверяем, применима ли политика к этому запросу
      if (!this.isPolicyApplicable(policy, context, trustLevel)) {
        continue;
      }
      
      // Политика применима - записываем её
      appliedRules.push({
        ruleId: policy.id,
        ruleName: policy.name,
        effect: policy.effect
      });
      
      // Проверяем условия политики
      const conditionsMet = this.checkPolicyConditions(policy, context);
      
      if (!conditionsMet.allMet) {
        // Условия не выполнены - пропускаем политику
        if (this.config.enableVerboseLogging) {
          this.log('PDP', `Условия политики не выполнены: ${policy.name}`, {
            failedConditions: conditionsMet.failed
          });
        }
        continue;
      }
      
      // Применяем политику
      if (policy.effect === 'ALLOW') {
        finalDecision = PolicyDecision.ALLOW;
        denyReason = null;
        
        // Добавляем ограничения из политики
        this.applyPolicyConstraints(policy, context, restrictions);
        
        // DENY политики имеют приоритет, поэтому если уже ALLOW,
        // продолжаем искать DENY
      } else if (policy.effect === 'DENY') {
        finalDecision = PolicyDecision.DENY;
        denyReason = `Политика запрещает доступ: ${policy.name}`;
        break; // DENY политика всегда прерывает оценку
      }
    }
    
    // Если ни одна политика не сработала, применяем default deny
    if (appliedRules.length === 0) {
      denyReason = 'Нет политик, разрешающих доступ (default deny)';
      recommendations.push('Обратитесь к администратору для настройки политик доступа');
    }
    
    // Создаём результат
    const result: PolicyEvaluationResult = {
      evaluationId: uuidv4(),
      evaluatedAt: new Date(),
      decision: finalDecision,
      trustLevel,
      appliedRules,
      factors: [], // Заполняется в calculateTrustLevel
      restrictions,
      recommendations,
      accessToken: finalDecision === PolicyDecision.ALLOW ? uuidv4() : undefined
    };
    
    return result;
  }

  /**
   * Проверить, применима ли политика к запросу
   */
  private isPolicyApplicable(
    policy: AccessPolicyRule,
    context: AccessRequestContext,
    trustLevel: TrustLevel
  ): boolean {
    // Проверка типа субъекта
    if (!policy.subjectTypes.includes(context.identity.type)) {
      return false;
    }
    
    // Проверка ролей (если указаны)
    if (policy.subjectRoles && policy.subjectRoles.length > 0) {
      const hasRole = policy.subjectRoles.some(role =>
        context.identity.roles.includes(role)
      );
      if (!hasRole) {
        return false;
      }
    }
    
    // Проверка типа ресурса
    if (!policy.resourceTypes.includes(context.resourceType)) {
      return false;
    }
    
    // Проверка ID ресурса (если указаны)
    if (policy.resourceIds && policy.resourceIds.length > 0) {
      if (!policy.resourceIds.includes(context.resourceId)) {
        return false;
      }
    }
    
    // Проверка меток ресурса (если указаны)
    if (policy.resourceLabels) {
      const resourceLabels = context.resourceAttributes['labels'] as Record<string, string> | undefined;
      if (!resourceLabels) {
        return false;
      }
      
      for (const [key, value] of Object.entries(policy.resourceLabels)) {
        if (resourceLabels[key] !== value) {
          return false;
        }
      }
    }
    
    // Проверка операции
    if (!policy.operations.includes(PolicyOperation.ANY) &&
        !policy.operations.includes(context.operation)) {
      return false;
    }
    
    // Проверка минимального уровня доверия
    if (policy.constraints.requiredTrustLevel !== undefined &&
        trustLevel < policy.constraints.requiredTrustLevel) {
      return false;
    }
    
    return true;
  }

  /**
   * Проверить условия политики
   */
  private checkPolicyConditions(
    policy: AccessPolicyRule,
    context: AccessRequestContext
  ): { allMet: boolean; failed: string[] } {
    const failed: string[] = [];
    
    for (const condition of policy.conditions) {
      const met = this.evaluateCondition(condition, context);
      if (!met) {
        failed.push(`${condition.attribute} ${condition.operator} ${condition.value}`);
      }
    }
    
    return { allMet: failed.length === 0, failed };
  }

  /**
   * Оценить отдельное условие
   */
  private evaluateCondition(
    condition: PolicyCondition,
    context: AccessRequestContext
  ): boolean {
    // Получаем значение атрибута из контекста
    const attributeValue = this.getAttributeValue(condition.attribute, context);
    
    if (attributeValue === undefined) {
      return condition.operator === 'EXISTS' ? false : false;
    }
    
    const { operator, value } = condition;
    
    switch (operator) {
      case 'EQ':
        return attributeValue === value;
      
      case 'NE':
        return attributeValue !== value;
      
      case 'GT':
        return Number(attributeValue) > Number(value);
      
      case 'LT':
        return Number(attributeValue) < Number(value);
      
      case 'GE':
        return Number(attributeValue) >= Number(value);
      
      case 'LE':
        return Number(attributeValue) <= Number(value);
      
      case 'IN':
        if (Array.isArray(value)) {
          return value.includes(String(attributeValue));
        }
        return false;
      
      case 'NOT_IN':
        if (Array.isArray(value)) {
          return !value.includes(String(attributeValue));
        }
        return true;
      
      case 'CONTAINS':
        return String(attributeValue).includes(String(value));
      
      case 'MATCHES':
        if (value instanceof RegExp) {
          return value.test(String(attributeValue));
        }
        return new RegExp(String(value)).test(String(attributeValue));
      
      case 'EXISTS':
        return attributeValue !== undefined && attributeValue !== null;
      
      default:
        return false;
    }
  }

  /**
   * Получить значение атрибута из контекста
   */
  private getAttributeValue(
    attribute: string,
    context: AccessRequestContext
  ): string | number | boolean | undefined {
    const parts = attribute.split('.');
    let value: unknown = context;
    
    for (const part of parts) {
      if (value === undefined || value === null) {
        return undefined;
      }
      
      value = (value as Record<string, unknown>)[part];
    }
    
    if (value === undefined) {
      return undefined;
    }
    
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      return value;
    }
    
    return String(value);
  }

  /**
   * Применить ограничения политики
   */
  private applyPolicyConstraints(
    policy: AccessPolicyRule,
    context: AccessRequestContext,
    restrictions: PolicyEvaluationResult['restrictions']
  ): void {
    const constraints = policy.constraints;
    
    // Ограничение по времени сессии
    if (constraints.maxSessionDuration) {
      restrictions.timeLimit = constraints.maxSessionDuration;
    }
    
    // Ограничение по операциям
    if (policy.operations.length > 0 && !policy.operations.includes(PolicyOperation.ANY)) {
      restrictions.operationLimit = policy.operations;
    }
    
    // Требуется step-up аутентификация
    if (constraints.mfaRequired && !context.authContext.mfaVerified) {
      restrictions.requireStepUp = true;
    }
    
    // Ограничение по уровню доверия
    if (constraints.requiredTrustLevel && 
        this.calculateTrustLevel(context) < constraints.requiredTrustLevel) {
      restrictions.requireStepUp = true;
    }
  }

  /**
   * Создать результат запрета доступа
   */
  private createDenyResult(
    context: AccessRequestContext,
    trustLevel: TrustLevel,
    reason: string
  ): PolicyEvaluationResult {
    return {
      evaluationId: uuidv4(),
      evaluatedAt: new Date(),
      decision: PolicyDecision.DENY,
      trustLevel,
      appliedRules: [],
      factors: [],
      restrictions: {},
      recommendations: [reason],
      accessToken: undefined
    };
  }

  /**
   * Проверить кэш решений
   */
  private checkCache(context: AccessRequestContext): PolicyEvaluationResult | null {
    const cacheKey = this.getCacheKey(context);
    const cached = this.cache.decisions.get(cacheKey);
    
    if (!cached) {
      return null;
    }
    
    // Проверяем, не истёк ли кэш
    if (new Date() > cached.expiresAt) {
      this.cache.decisions.delete(cacheKey);
      return null;
    }
    
    return cached.result;
  }

  /**
   * Получить ключ кэша для контекста
   */
  private getCacheKey(context: AccessRequestContext): string {
    return `${context.identity.id}:${context.resourceId}:${context.operation}:${context.networkContext.sourceIp}`;
  }

  /**
   * Финализировать оценку
   */
  private finalizeEvaluation(
    result: PolicyEvaluationResult,
    startTime: number,
    requestId: string
  ): PolicyEvaluationResult {
    // Вычисляем время оценки
    const evaluationTime = Date.now() - startTime;
    
    // Обновляем статистику
    this.stats.averageEvaluationTime = 
      (this.stats.averageEvaluationTime * (this.stats.totalRequests - 1) + evaluationTime) / 
      this.stats.totalRequests;
    
    if (result.decision === PolicyDecision.ALLOW || 
        result.decision === PolicyDecision.ALLOW_RESTRICTED ||
        result.decision === PolicyDecision.ALLOW_TEMPORARY) {
      this.stats.allowDecisions++;
    } else {
      this.stats.denyDecisions++;
    }
    
    // Кэшируем результат (если разрешено и решение положительное)
    if (this.config.enableCaching && 
        (result.decision === PolicyDecision.ALLOW || 
         result.decision === PolicyDecision.ALLOW_RESTRICTED) &&
        result.trustLevel >= this.config.cacheTrustLevelThreshold) {
      this.cacheDecision(requestId, result);
    }
    
    // Добавляем в историю
    this.addToHistory(result);
    
    // Логируем
    if (this.config.enableLogging) {
      this.log('PDP', 'Оценка доступа завершена', {
        requestId,
        decision: result.decision,
        trustLevel: result.trustLevel,
        evaluationTime: `${evaluationTime}ms`,
        rulesApplied: result.appliedRules.length
      });
    }
    
    // Эмитим событие
    this.emit('access:evaluated', {
      requestId,
      result,
      evaluationTime
    });
    
    // Эмитим событие нарушения если доступ запрещён
    if (result.decision === PolicyDecision.DENY) {
      this.emit('policy:violation', {
        requestId,
        result,
        timestamp: new Date()
      });
    }
    
    return result;
  }

  /**
   * Кэшировать решение
   */
  private cacheDecision(requestId: string, result: PolicyEvaluationResult): void {
    // Очищаем старые записи если кэш переполнен
    if (this.cache.decisions.size >= this.cache.maxSize) {
      const firstKey = this.cache.decisions.keys().next().value;
      if (firstKey) {
        this.cache.decisions.delete(firstKey);
      }
    }
    
    this.cache.decisions.set(requestId, {
      result,
      cachedAt: new Date(),
      expiresAt: new Date(Date.now() + this.cache.defaultTtl * 1000)
    });
  }

  /**
   * Добавить результат в историю
   */
  private addToHistory(result: PolicyEvaluationResult): void {
    this.decisionHistory.push(result);
    
    // Очищаем старую историю
    if (this.decisionHistory.length > this.maxHistorySize) {
      this.decisionHistory.splice(0, this.decisionHistory.length - this.maxHistorySize);
    }
  }

  /**
   * Получить статистику PDP
   */
  public getStats(): typeof this.stats & {
    /** Размер кэша */
    cacheSize: number;
    /** Размер истории */
    historySize: number;
    /** Количество политик */
    policyCount: number;
  } {
    return {
      ...this.stats,
      cacheSize: this.cache.decisions.size,
      historySize: this.decisionHistory.length,
      policyCount: this.policies.size
    };
  }

  /**
   * Очистить кэш
   */
  public clearCache(): void {
    this.cache.decisions.clear();
    this.log('PDP', 'Кэш решений очищен');
  }

  /**
   * Получить историю решений
   * 
   * @param limit Максимальное количество записей
   */
  public getHistory(limit: number = 100): PolicyEvaluationResult[] {
    return this.decisionHistory.slice(-limit);
  }

  /**
   * Логирование событий PDP
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
  }
}

export default PolicyDecisionPoint;
