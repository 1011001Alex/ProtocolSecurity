/**
 * =============================================================================
 * ABAC (ATTRIBUTE-BASED ACCESS CONTROL) SERVICE & POLICY ENGINE
 * =============================================================================
 * Сервис для атрибутной авторизации с policy engine
 * Соответствует: NIST ABAC guidelines, XACML principles
 * Поддерживает: сложные условия, комбинирование policy, obligations
 * =============================================================================
 */

import { v4 as uuidv4 } from 'uuid';
import {
  IPolicy,
  PolicyCondition,
  PolicyDecision,
  PolicyObligation,
  PolicyAdvice,
  PolicyContext,
  PolicyOperator,
  LogicalOperator,
  IUser,
  IUserAttributes,
  AccessCheckResult,
  AuthError,
  AuthErrorCode,
} from '../types/auth.types';

/**
 * Конфигурация ABAC сервиса
 */
export interface ABACServiceConfig {
  /** Префикс для ключей хранилища */
  keyPrefix: string;
  
  /** Включить ли логирование решений */
  enableLogging: boolean;
  
  /** Включить ли кэширование решений */
  enableCaching: boolean;
  
  /** TTL кэша (секунды) */
  cacheTTL: number;
  
  /** Стратегия комбинирования policy */
  combiningAlgorithm: 'permit_overrides' | 'deny_overrides' | 'first_applicable';
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: ABACServiceConfig = {
  keyPrefix: 'protocol:abac:',
  enableLogging: true,
  enableCaching: true,
  cacheTTL: 60, // 1 минута
  combiningAlgorithm: 'deny_overrides',
};

/**
 * Кэш решений
 */
interface DecisionCache {
  decision: PolicyDecision;
  expiresAt: number;
}

/**
 * =============================================================================
 * POLICY ENGINE CLASS
 * =============================================================================
 */
export class PolicyEngine {
  private config: ABACServiceConfig;
  private policies: Map<string, IPolicy> = new Map();
  private decisionCache: Map<string, DecisionCache> = new Map();
  private decisionLogs: Array<{
    timestamp: Date;
    context: PolicyContext;
    decision: PolicyDecision;
  }> = [];

  /**
   * Создает новый экземпляр PolicyEngine
   * @param config - Конфигурация движка
   */
  constructor(config: ABACServiceConfig = DEFAULT_CONFIG) {
    this.config = config;
    this.initializeDefaultPolicies();
  }

  /**
   * Инициализирует policy по умолчанию
   * @private
   */
  private initializeDefaultPolicies(): void {
    // Default deny policy
    const defaultDeny: IPolicy = {
      id: 'default-deny',
      name: 'Default Deny',
      description: 'Запретить всё, что не разрешено явно',
      type: 'deny',
      priority: -1000,
      resources: ['*'],
      actions: ['*'],
      subjectConditions: [],
      contextConditions: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      isActive: true,
      version: 1,
    };

    this.policies.set(defaultDeny.id, defaultDeny);
  }

  // ===========================================================================
  // УПРАВЛЕНИЕ POLICY
  // ===========================================================================

  /**
   * Создает новую policy
   * @param name - Название policy
   * @param type - Тип policy (permit/deny)
   * @param resources - Ресурсы
   * @param actions - Действия
   * @param conditions - Условия
   * @returns Созданная policy
   */
  public createPolicy(
    name: string,
    type: 'permit' | 'deny',
    resources: string[],
    actions: string[],
    conditions: {
      subject?: PolicyCondition[];
      resource?: PolicyCondition[];
      action?: PolicyCondition[];
      context?: PolicyCondition[];
    },
    options?: {
      description?: string;
      priority?: number;
      expiresAt?: Date;
    }
  ): IPolicy {
    // Проверка уникальности имени
    if (this.getPolicyByName(name)) {
      throw new AuthError(
        `Policy с именем "${name}" уже существует`,
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        400
      );
    }

    const policy: IPolicy = {
      id: uuidv4(),
      name,
      description: options?.description,
      type,
      priority: options?.priority ?? 0,
      resources,
      actions,
      subjectConditions: conditions.subject || [],
      resourceConditions: conditions.resource || [],
      actionConditions: conditions.action || [],
      contextConditions: conditions.context || [],
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: options?.expiresAt,
      isActive: true,
      version: 1,
    };

    this.policies.set(policy.id, policy);
    return policy;
  }

  /**
   * Обновляет policy
   * @param policyId - ID policy
   * @param updates - Обновления
   * @returns Обновленная policy
   */
  public updatePolicy(
    policyId: string,
    updates: Partial<IPolicy>
  ): IPolicy {
    const policy = this.getPolicyById(policyId);
    if (!policy) {
      throw new AuthError(
        'Policy не найдена',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        404
      );
    }

    if (policy.id === 'default-deny') {
      throw new AuthError(
        'Нельзя изменить default deny policy',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        403
      );
    }

    Object.assign(policy, {
      ...updates,
      updatedAt: new Date(),
      version: policy.version + 1,
    });

    // Очистка кэша решений
    this.decisionCache.clear();

    return policy;
  }

  /**
   * Удаляет policy
   * @param policyId - ID policy
   */
  public deletePolicy(policyId: string): void {
    const policy = this.getPolicyById(policyId);
    if (!policy) {
      throw new AuthError(
        'Policy не найдена',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        404
      );
    }

    if (policy.id === 'default-deny') {
      throw new AuthError(
        'Нельзя удалить default deny policy',
        AuthErrorCode.INSUFFICIENT_PERMISSIONS,
        403
      );
    }

    this.policies.delete(policyId);
    this.decisionCache.clear();
  }

  /**
   * Получает policy по ID
   * @param policyId - ID policy
   * @returns Policy или null
   */
  public getPolicyById(policyId: string): IPolicy | null {
    return this.policies.get(policyId) || null;
  }

  /**
   * Получает policy по имени
   * @param name - Название policy
   * @returns Policy или null
   */
  public getPolicyByName(name: string): IPolicy | null {
    for (const policy of this.policies.values()) {
      if (policy.name === name) {
        return policy;
      }
    }
    return null;
  }

  /**
   * Получает все активные policy
   * @returns Массив policy
   */
  public getAllPolicies(): IPolicy[] {
    return Array.from(this.policies.values()).filter(p => p.isActive);
  }

  // ===========================================================================
  // ОЦЕНКА POLICY (POLICY EVALUATION)
  // ===========================================================================

  /**
   * Оценивает доступ на основе policy
   * @param context - Контекст запроса
   * @returns Решение policy
   */
  public evaluate(context: PolicyContext): PolicyDecision {
    // Проверка кэша
    if (this.config.enableCaching) {
      const cacheKey = this.getCacheKey(context);
      const cached = this.decisionCache.get(cacheKey);
      if (cached && Date.now() < cached.expiresAt) {
        return cached.decision;
      }
    }

    // Получение применимых policy
    const applicablePolicies = this.getApplicablePolicies(context);

    // Оценка policy в зависимости от алгоритма комбинирования
    let decision: PolicyDecision;

    switch (this.config.combiningAlgorithm) {
      case 'permit_overrides':
        decision = this.combinePermitOverrides(applicablePolicies, context);
        break;
      case 'first_applicable':
        decision = this.combineFirstApplicable(applicablePolicies, context);
        break;
      case 'deny_overrides':
      default:
        decision = this.combineDenyOverrides(applicablePolicies, context);
        break;
    }

    // Логирование
    if (this.config.enableLogging) {
      this.logDecision(context, decision);
    }

    // Кэширование
    if (this.config.enableCaching) {
      const cacheKey = this.getCacheKey(context);
      this.decisionCache.set(cacheKey, {
        decision,
        expiresAt: Date.now() + this.config.cacheTTL * 1000,
      });
    }

    return decision;
  }

  /**
   * Получает применимые policy для контекста
   * @private
   */
  private getApplicablePolicies(context: PolicyContext): IPolicy[] {
    const applicable: IPolicy[] = [];

    for (const policy of this.policies.values()) {
      if (!policy.isActive) continue;
      if (policy.expiresAt && policy.expiresAt < new Date()) continue;

      // Проверка ресурсов
      if (!this.matchesResources(policy.resources, context.resource)) {
        continue;
      }

      // Проверка действий
      if (!this.matchesActions(policy.actions, context.action)) {
        continue;
      }

      applicable.push(policy);
    }

    // Сортировка по приоритету (убывание)
    applicable.sort((a, b) => b.priority - a.priority);

    return applicable;
  }

  /**
   * Алгоритм: Deny Overrides (отказ перекрывает разрешение)
   * @private
   */
  private combineDenyOverrides(
    policies: IPolicy[],
    context: PolicyContext
  ): PolicyDecision {
    let hasPermit = false;
    let hasExplicitDeny = false;  // Только явные deny policy (не default-deny)
    let applicablePolicy: IPolicy | undefined;

    for (const policy of policies) {
      // Пропускаем default-deny в основном цикле - он применяется только если нет permit
      if (policy.id === 'default-deny') continue;

      const matches = this.evaluatePolicyConditions(policy, context);

      if (matches) {
        if (policy.type === 'deny') {
          hasExplicitDeny = true;
          applicablePolicy = policy;
          break; // Deny сразу перекрывает
        } else {
          hasPermit = true;
          if (!applicablePolicy) {
            applicablePolicy = policy;
          }
        }
      }
    }

    if (hasExplicitDeny) {
      return {
        decision: 'deny',
        policyId: applicablePolicy?.id,
        reason: 'Доступ запрещен policy',
      };
    }

    if (hasPermit) {
      return {
        decision: 'permit',
        policyId: applicablePolicy?.id,
        reason: 'Доступ разрешен policy',
      };
    }

    // Default deny - применяется только если нет ни permit ни explicit deny
    return {
      decision: 'deny',
      policyId: 'default-deny',
      reason: 'Нет разрешающей policy',
    };
  }

  /**
   * Алгоритм: Permit Overrides (разрешение перекрывает отказ)
   * @private
   */
  private combinePermitOverrides(
    policies: IPolicy[],
    context: PolicyContext
  ): PolicyDecision {
    let hasPermit = false;
    let hasDeny = false;
    let applicablePolicy: IPolicy | undefined;

    for (const policy of policies) {
      const matches = this.evaluatePolicyConditions(policy, context);
      
      if (matches) {
        if (policy.type === 'permit') {
          hasPermit = true;
          applicablePolicy = policy;
          break; // Permit сразу перекрывает
        } else {
          hasDeny = true;
          if (!applicablePolicy) {
            applicablePolicy = policy;
          }
        }
      }
    }

    if (hasPermit) {
      return {
        decision: 'permit',
        policyId: applicablePolicy?.id,
        reason: 'Доступ разрешен policy',
      };
    }

    if (hasDeny) {
      return {
        decision: 'deny',
        policyId: applicablePolicy?.id,
        reason: 'Доступ запрещен policy',
      };
    }

    return {
      decision: 'deny',
      policyId: 'default-deny',
      reason: 'Нет разрешающей policy',
    };
  }

  /**
   * Алгоритм: First Applicable (первая применимая)
   * @private
   */
  private combineFirstApplicable(
    policies: IPolicy[],
    context: PolicyContext
  ): PolicyDecision {
    for (const policy of policies) {
      const matches = this.evaluatePolicyConditions(policy, context);
      
      if (matches) {
        return {
          decision: policy.type,
          policyId: policy.id,
          reason: policy.type === 'permit' ? 'Доступ разрешен policy' : 'Доступ запрещен policy',
        };
      }
    }

    return {
      decision: 'deny',
      policyId: 'default-deny',
      reason: 'Нет применимой policy',
    };
  }

  /**
   * Оценивает условия policy
   * @private
   */
  private evaluatePolicyConditions(
    policy: IPolicy,
    context: PolicyContext
  ): boolean {
    // Проверка условий subject
    if (policy.subjectConditions.length > 0) {
      if (!this.evaluateConditions(policy.subjectConditions, context.subject)) {
        return false;
      }
    }

    // Проверка условий resource
    if (policy.resourceConditions && policy.resourceConditions.length > 0) {
      if (!this.evaluateConditions(policy.resourceConditions, context.resource)) {
        return false;
      }
    }

    // Проверка условий action
    if (policy.actionConditions && policy.actionConditions.length > 0) {
      if (!this.evaluateConditions(policy.actionConditions, context.action)) {
        return false;
      }
    }

    // Проверка условий context (environment)
    if (policy.contextConditions && policy.contextConditions.length > 0) {
      if (!this.evaluateConditions(policy.contextConditions, context.environment)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Оценивает набор условий
   * @private
   */
  private evaluateConditions(
    conditions: PolicyCondition[],
    target: any,
    logicalOperator: LogicalOperator = 'and'
  ): boolean {
    if (conditions.length === 0) return true;

    const results = conditions.map(condition => 
      this.evaluateSingleCondition(condition, target)
    );

    if (logicalOperator === 'and') {
      return results.every(r => r);
    } else if (logicalOperator === 'or') {
      return results.some(r => r);
    } else if (logicalOperator === 'not') {
      return !results.some(r => r);
    }

    return true;
  }

  /**
   * Оценивает одно условие
   * @private
   */
  private evaluateSingleCondition(
    condition: PolicyCondition,
    target: any
  ): boolean {
    // Получение значения атрибута
    const value = this.getAttributeValue(condition.attribute, target);

    // Проверка условия в зависимости от оператора
    switch (condition.operator) {
      case 'eq':
        return value === condition.value;
      
      case 'neq':
        return value !== condition.value;
      
      case 'gt':
        return Number(value) > Number(condition.value);
      
      case 'gte':
        return Number(value) >= Number(condition.value);
      
      case 'lt':
        return Number(value) < Number(condition.value);
      
      case 'lte':
        return Number(value) <= Number(condition.value);
      
      case 'in':
        if (!Array.isArray(condition.value)) return false;
        return condition.value.includes(value);
      
      case 'not_in':
        if (!Array.isArray(condition.value)) return false;
        return !condition.value.includes(value);
      
      case 'contains':
        if (typeof value !== 'string') return false;
        return value.includes(String(condition.value));
      
      case 'starts_with':
        if (typeof value !== 'string') return false;
        return value.startsWith(String(condition.value));
      
      case 'ends_with':
        if (typeof value !== 'string') return false;
        return value.endsWith(String(condition.value));
      
      case 'regex':
        if (typeof value !== 'string') return false;
        const regex = new RegExp(condition.value);
        return regex.test(value);
      
      case 'exists':
        return value !== undefined && value !== null;
      
      case 'not_exists':
        return value === undefined || value === null;
      
      default:
        return false;
    }
  }

  /**
   * Получает значение атрибута из объекта
   * @private
   */
  private getAttributeValue(attribute: string, target: any): any {
    // Поддержка вложенных атрибутов (например, "attributes.department")
    const parts = attribute.split('.');
    let value: any = target;

    for (const part of parts) {
      if (value === undefined || value === null) {
        return undefined;
      }
      value = value[part];
    }

    return value;
  }

  /**
   * Проверяет соответствие ресурсов
   * @private
   */
  private matchesResources(
    policyResources: string[],
    resource: PolicyContext['resource']
  ): boolean {
    if (policyResources.includes('*')) return true;
    if (policyResources.includes(resource.type)) return true;
    if (policyResources.includes(resource.id)) return true;
    return false;
  }

  /**
   * Проверяет соответствие действий
   * @private
   */
  private matchesActions(
    policyActions: string[],
    action: PolicyContext['action']
  ): boolean {
    if (policyActions.includes('*')) return true;
    if (policyActions.includes(action.type)) return true;
    if (policyActions.includes(action.id)) return true;
    return false;
  }

  // ===========================================================================
  // УТИЛИТЫ
  // ===========================================================================

  /**
   * Генерирует ключ кэша для контекста
   * @private
   */
  private getCacheKey(context: PolicyContext): string {
    const hash = require('crypto').createHash('sha256');
    hash.update(JSON.stringify({
      subject: context.subject.id,
      resource: context.resource.id,
      action: context.action.id,
      time: Math.floor(Date.now() / 60000), // Округление до минуты
    }));
    return hash.digest('hex');
  }

  /**
   * Логирует решение
   * @private
   */
  private logDecision(context: PolicyContext, decision: PolicyDecision): void {
    this.decisionLogs.push({
      timestamp: new Date(),
      context,
      decision,
    });

    // Ограничение размера логов
    if (this.decisionLogs.length > 10000) {
      this.decisionLogs.shift();
    }
  }

  /**
   * Получает логи решений
   * @param limit - Максимальное количество записей
   * @returns Логи
   */
  public getDecisionLogs(limit: number = 100): Array<{
    timestamp: Date;
    context: PolicyContext;
    decision: PolicyDecision;
  }> {
    return this.decisionLogs.slice(-limit);
  }

  /**
   * Очищает кэш решений
   */
  public clearCache(): void {
    this.decisionCache.clear();
  }

  /**
   * Получает статистику policy
   * @returns Статистика
   */
  public getStats(): {
    totalPolicies: number;
    activePolicies: number;
    permitPolicies: number;
    denyPolicies: number;
    cachedDecisions: number;
  } {
    const policies = Array.from(this.policies.values());
    const activePolicies = policies.filter(p => p.isActive);

    return {
      totalPolicies: policies.length,
      activePolicies: activePolicies.length,
      permitPolicies: activePolicies.filter(p => p.type === 'permit').length,
      denyPolicies: activePolicies.filter(p => p.type === 'deny').length,
      cachedDecisions: this.decisionCache.size,
    };
  }
}

/**
 * =============================================================================
 * ABAC SERVICE CLASS
 * =============================================================================
 */
export class ABACService {
  private policyEngine: PolicyEngine;

  /**
   * Создает новый экземпляр ABACService
   * @param config - Конфигурация сервиса
   */
  constructor(config: ABACServiceConfig = DEFAULT_CONFIG) {
    this.policyEngine = new PolicyEngine(config);
    // Инициализация стрелочных функций после создания policyEngine
    this.createPolicy = this.policyEngine.createPolicy.bind(this.policyEngine);
    this.updatePolicy = this.policyEngine.updatePolicy.bind(this.policyEngine);
    this.deletePolicy = this.policyEngine.deletePolicy.bind(this.policyEngine);
    this.getPolicyById = this.policyEngine.getPolicyById.bind(this.policyEngine);
    this.getAllPolicies = this.policyEngine.getAllPolicies.bind(this.policyEngine);
  }

  /**
   * Создает policy через policy engine
   */
  public createPolicy!: (...args: any[]) => any;

  /**
   * Обновляет policy через policy engine
   */
  public updatePolicy!: (...args: any[]) => any;

  /**
   * Удаляет policy через policy engine
   */
  public deletePolicy!: (...args: any[]) => any;

  /**
   * Получает policy по ID
   */
  public getPolicyById!: (...args: any[]) => any;

  /**
   * Получает все policy
   */
  public getAllPolicies!: (...args: any[]) => any;

  /**
   * Проверяет доступ на основе атрибутов
   * @param user - Пользователь
   * @param resource - Ресурс
   * @param action - Действие
   * @param environment - Окружение
   * @returns Результат проверки
   */
  public checkAccess(
    user: IUser,
    resource: {
      id: string;
      type: string;
      attributes?: Record<string, any>;
      owner?: string;
    },
    action: {
      id: string;
      type: string;
    },
    environment?: {
      currentTime?: Date;
      currentLocation?: {
        country: string;
        region: string;
        city: string;
        ip: string;
      };
      deviceInfo?: {
        isTrusted: boolean;
        fingerprint?: string;
        type: string;
      };
      riskScore?: number;
    }
  ): AccessCheckResult {
    // Создание контекста
    const context: PolicyContext = {
      subject: {
        id: user.id,
        attributes: user.attributes || {},
        roles: user.roles,
        authenticationMethods: [],
        authenticationLevel: 1,
      },
      resource: {
        id: resource.id,
        type: resource.type,
        attributes: resource.attributes || {},
        owner: resource.owner,
      },
      action: {
        id: action.id,
        type: action.type,
      },
      environment: {
        currentTime: environment?.currentTime || new Date(),
        currentLocation: environment?.currentLocation,
        deviceInfo: environment?.deviceInfo,
        riskScore: environment?.riskScore,
      },
    };

    // Оценка policy
    const decision = this.policyEngine.evaluate(context);

    return {
      allowed: decision.decision === 'permit',
      denialReason: decision.decision === 'deny' ? decision.reason : undefined,
      policyId: decision.policyId,
    };
  }

  /**
   * Проверяет доступ с использованием упрощенного API
   * @param userId - ID пользователя
   * @param userAttributes - Атрибуты пользователя
   * @param resourceType - Тип ресурса
   * @param resourceId - ID ресурса
   * @param actionType - Тип действия
   * @param actionId - ID действия
   * @returns Результат проверки
   */
  public checkAccessSimple(
    userId: string,
    userAttributes: IUserAttributes,
    resourceType: string,
    resourceId: string,
    actionType: string,
    actionId: string
  ): AccessCheckResult {
    const minimalUser: Partial<IUser> & { id: string; attributes: IUserAttributes; roles: string[] } = {
      id: userId,
      email: 'unknown',
      passwordHash: '',
      passwordAlgorithm: 'argon2id',
      passwordVersion: 1,
      attributes: userAttributes,
      roles: [],
      status: 'active',
      createdAt: new Date(),
      updatedAt: new Date(),
      failedLoginAttempts: 0,
      requirePasswordChange: false,
      securityPreferences: {
        requireMfa: false,
        allowRememberDevice: false,
        rememberDeviceDays: 30,
        requireNewDeviceConfirmation: false,
        notifyOnNewLogin: false,
        restrictToTrustedIps: false,
        trustedIps: [],
        maxConcurrentSessions: 10,
        reauthIntervalMinutes: 30,
      },
      enabledMfaMethods: [],
    };

    return this.checkAccess(
      minimalUser as IUser,
      {
        id: resourceId,
        type: resourceType,
      },
      {
        id: actionId,
        type: actionType,
      }
    );
  }

  /**
   * Получает статистику
   */
  public getStats() {
    return this.policyEngine.getStats();
  }

  /**
   * Очищает кэш
   */
  public clearCache() {
    this.policyEngine.clearCache();
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const abacService = new ABACService(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createABACService(
  config: Partial<ABACServiceConfig>
): ABACService {
  return new ABACService({ ...DEFAULT_CONFIG, ...config });
}
