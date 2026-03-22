/**
 * ============================================================================
 * ACCESS POLICY - УПРАВЛЕНИЕ ПОЛИТИКАМИ ДОСТУПА К СЕКРЕТАМ
 * ============================================================================
 * 
 * Реализует систему контроля доступа на основе политик (policy-based access control).
 * Поддерживает RBAC, ABAC, условия по IP, времени, MFA и атрибутам.
 * Использует zero-trust подход и принцип наименьших привилегий.
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import {
  AccessPolicy,
  AccessPolicyRule,
  AccessContext,
  PolicyCondition,
  SecretAction,
  SecretAccessError
} from '../types/secrets.types';

/**
 * Результат проверки доступа
 */
interface AccessDecision {
  /** Разрешён ли доступ */
  allowed: boolean;
  /** ID правила, которое определило решение */
  matchedRuleId?: string;
  /** Причина отказа */
  denialReason?: string;
  /** Применённые условия */
  appliedConditions?: string[];
}

/**
 * Класс для управления политиками доступа
 * 
 * Особенности:
 * - Приоритизация правил (deny всегда имеет приоритет)
 * - Поддержка условий (IP, время, MFA, атрибуты)
 * - Глобальные и ресурсо-специфичные политики
 * - Audit logging всех проверок
 * - Кэширование результатов проверок
 */
export class AccessPolicyManager extends EventEmitter {
  /** Хранилище политик */
  private policies: Map<string, AccessPolicy>;
  
  /** Кэш результатов проверок доступа */
  private accessCache: Map<string, { allowed: boolean; timestamp: number }>;
  
  /** TTL кэша доступа (5 минут) */
  private readonly ACCESS_CACHE_TTL = 300000;
  
  /** Включено ли кэширование решений */
  private cacheEnabled = true;
  
  /** Режим строгой проверки (требует явного разрешения) */
  private strictMode = true;

  /**
   * Создаёт новый экземпляр AccessPolicyManager
   */
  constructor() {
    super();
    this.policies = new Map();
    this.accessCache = new Map();
  }

  /**
   * Инициализация менеджера политик
   * 
   * @param initialPolicies - Начальный набор политик
   * @param strictMode - Режим строгой проверки
   */
  async initialize(
    initialPolicies: AccessPolicy[] = [],
    strictMode = true
  ): Promise<void> {
    this.strictMode = strictMode;
    
    for (const policy of initialPolicies) {
      await this.addPolicy(policy);
    }
    
    // Запуск очистки кэша
    this.startCacheCleanup();
    
    console.log(`[AccessPolicy] Инициализирован. Политик: ${this.policies.size}, строгий режим: ${strictMode}`);
  }

  /**
   * Остановка менеджера
   */
  async destroy(): Promise<void> {
    this.policies.clear();
    this.accessCache.clear();
    console.log('[AccessPolicy] Остановлен');
  }

  /**
   * Добавить политику
   * 
   * @param policy - Политика для добавления
   * @throws Error если политика с таким ID уже существует
   */
  async addPolicy(policy: AccessPolicy): Promise<void> {
    if (this.policies.has(policy.policyId)) {
      throw new Error(`Политика с ID ${policy.policyId} уже существует`);
    }
    
    // Валидация правил
    this.validatePolicyRules(policy);
    
    this.policies.set(policy.policyId, policy);
    
    console.log(`[AccessPolicy] Добавлена политика: ${policy.name}`);
    this.emit('policy:added', policy);
  }

  /**
   * Обновить политику
   * 
   * @param policyId - ID политики
   * @param updates - Обновления политики
   * @throws Error если политика не найдена
   */
  async updatePolicy(
    policyId: string,
    updates: Partial<AccessPolicy>
  ): Promise<AccessPolicy> {
    const existing = this.policies.get(policyId);
    
    if (!existing) {
      throw new Error(`Политика ${policyId} не найдена`);
    }
    
    const updated: AccessPolicy = {
      ...existing,
      ...updates,
      updatedAt: new Date(),
      version: existing.version + 1
    };
    
    // Валидация обновлённых правил
    if (updates.rules) {
      this.validatePolicyRules(updated);
    }
    
    this.policies.set(policyId, updated);
    
    // Очистка кэша доступа
    this.clearAccessCache();
    
    console.log(`[AccessPolicy] Обновлена политика: ${updated.name}`);
    this.emit('policy:updated', updated);
    
    return updated;
  }

  /**
   * Удалить политику
   * 
   * @param policyId - ID политики
   * @returns Успешность удаления
   */
  async removePolicy(policyId: string): Promise<boolean> {
    const deleted = this.policies.delete(policyId);
    
    if (deleted) {
      this.clearAccessCache();
      console.log(`[AccessPolicy] Удалена политика: ${policyId}`);
      this.emit('policy:removed', policyId);
    }
    
    return deleted;
  }

  /**
   * Получить политику по ID
   * 
   * @param policyId - ID политики
   * @returns Политика или undefined
   */
  getPolicy(policyId: string): AccessPolicy | undefined {
    return this.policies.get(policyId);
  }

  /**
   * Получить все политики
   * 
   * @returns Массив всех политик
   */
  getAllPolicies(): AccessPolicy[] {
    return Array.from(this.policies.values());
  }

  /**
   * Проверить доступ к действию с ресурсом
   * 
   * @param action - Действие
   * @param resource - Ресурс (ID секрета или path)
   * @param context - Контекст запроса
   * @returns Результат проверки доступа
   */
  async checkAccess(
    action: SecretAction,
    resource: string,
    context: AccessContext
  ): Promise<AccessDecision> {
    // Проверка кэша
    const cacheKey = this.getCacheKey(action, resource, context.subjectId);
    const cached = this.getCachedDecision(cacheKey);
    
    if (cached !== null) {
      return {
        allowed: cached,
        matchedRuleId: 'cache'
      };
    }
    
    // Сбор всех применимых правил
    const applicableRules = this.collectApplicableRules(action, resource, context);
    
    // Сортировка по приоритету (deny имеют приоритет)
    applicableRules.sort((a, b) => {
      // Deny всегда primero
      if (a.effect === 'deny' && b.effect === 'allow') return -1;
      if (a.effect === 'allow' && b.effect === 'deny') return 1;
      // Затем по приоритету
      return b.priority - a.priority;
    });
    
    // Применение правил
    for (const rule of applicableRules) {
      // Проверка условий
      const conditionsMet = await this.checkConditions(rule.conditions ?? [], context);
      
      if (!conditionsMet) {
        continue;
      }
      
      // Правило применимо
      if (rule.effect === 'deny') {
        const decision: AccessDecision = {
          allowed: false,
          matchedRuleId: rule.ruleId,
          denialReason: `Запрещено правилом: ${rule.description ?? rule.ruleId}`,
          appliedConditions: rule.conditions?.map(c => c.type)
        };
        
        this.cacheDecision(cacheKey, false);
        this.emit('access:denied', { action, resource, context, rule });
        
        return decision;
      } else {
        const decision: AccessDecision = {
          allowed: true,
          matchedRuleId: rule.ruleId,
          appliedConditions: rule.conditions?.map(c => c.type)
        };
        
        this.cacheDecision(cacheKey, true);
        this.emit('access:allowed', { action, resource, context, rule });
        
        return decision;
      }
    }
    
    // Если strict mode и нет явного разрешения - отказ
    if (this.strictMode) {
      const decision: AccessDecision = {
        allowed: false,
        denialReason: 'Нет явного разрешения в strict mode'
      };
      
      this.cacheDecision(cacheKey, false);
      this.emit('access:denied', { action, resource, context, implicit: true });
      
      return decision;
    }
    
    // Если не strict mode - разрешаем по умолчанию
    return { allowed: true };
  }

  /**
   * Проверить доступ к нескольким действиям
   * 
   * @param actions - Массив действий
   * @param resource - Ресурс
   * @param context - Контекст
   * @returns Массив результатов
   */
  async checkAccessBatch(
    actions: SecretAction[],
    resource: string,
    context: AccessContext
  ): Promise<Map<SecretAction, AccessDecision>> {
    const results = new Map<SecretAction, AccessDecision>();
    
    for (const action of actions) {
      const decision = await this.checkAccess(action, resource, context);
      results.set(action, decision);
    }
    
    return results;
  }

  /**
   * Проверить имеет ли субъект роль
   * 
   * @param context - Контекст
   * @param role - Роль для проверки
   * @returns Наличие роли
   */
  hasRole(context: AccessContext, role: string): boolean {
    return context.roles.includes(role);
  }

  /**
   * Проверить имеет ли субъект любую из ролей
   * 
   * @param context - Контекст
   * @param roles - Массив ролей
   * @returns Наличие любой роли
   */
  hasAnyRole(context: AccessContext, roles: string[]): boolean {
    return roles.some(role => context.roles.includes(role));
  }

  /**
   * Проверить имеет ли субъект все роли
   * 
   * @param context - Контекст
   * @param roles - Массив ролей
   * @returns Наличие всех ролей
   */
  hasAllRoles(context: AccessContext, roles: string[]): boolean {
    return roles.every(role => context.roles.includes(role));
  }

  /**
   * Создать политику по умолчанию для администраторов
   * 
   * @returns Политика администратора
   */
  static createAdminPolicy(): AccessPolicy {
    return {
      policyId: 'admin-policy',
      name: 'Administrator Full Access',
      description: 'Полный доступ для администраторов системы',
      rules: [
        {
          ruleId: 'admin-allow-all',
          actions: Object.values(SecretAction),
          resources: ['*'],
          subjects: ['role:admin', 'role:super-admin'],
          effect: 'allow',
          priority: 100,
          description: 'Администраторы имеют полный доступ'
        }
      ],
      createdAt: new Date(),
      createdBy: 'system',
      version: 1,
      enabled: true
    };
  }

  /**
   * Создать политику по умолчанию для сервисов
   * 
   * @returns Политика сервиса
   */
  static createServicePolicy(): AccessPolicy {
    return {
      policyId: 'service-policy',
      name: 'Service Read Access',
      description: 'Только чтение для сервисов',
      rules: [
        {
          ruleId: 'service-read',
          actions: [SecretAction.READ, SecretAction.LIST],
          resources: ['*'],
          subjects: ['type:service'],
          effect: 'allow',
          priority: 50,
          description: 'Сервисы могут только читать секреты'
        },
        {
          ruleId: 'service-deny-write',
          actions: [SecretAction.WRITE, SecretAction.DELETE, SecretAction.ROTATE],
          resources: ['*'],
          subjects: ['type:service'],
          effect: 'deny',
          priority: 100,
          description: 'Сервисы не могут изменять секреты'
        }
      ],
      createdAt: new Date(),
      createdBy: 'system',
      version: 1,
      enabled: true
    };
  }

  /**
   * Создать политику с ограничением по времени
   * 
   * @param startHour - Начальный час (0-23)
   * @param endHour - Конечный час (0-23)
   * @returns Политика с временным ограничением
   */
  static createTimeRestrictedPolicy(startHour: number, endHour: number): AccessPolicy {
    return {
      policyId: `time-restricted-${startHour}-${endHour}`,
      name: `Time Restricted Access (${startHour}:00 - ${endHour}:00)`,
      description: `Доступ разрешён только с ${startHour}:00 до ${endHour}:00`,
      rules: [
        {
          ruleId: 'time-allow',
          actions: [SecretAction.READ],
          resources: ['*'],
          subjects: ['*'],
          effect: 'allow',
          priority: 50,
          conditions: [
            {
              type: 'time_range',
              value: { startHour, endHour }
            }
          ],
          description: 'Доступ разрешён в рабочее время'
        }
      ],
      createdAt: new Date(),
      createdBy: 'system',
      version: 1,
      enabled: true
    };
  }

  /**
   * Создать политику с требованием MFA
   * 
   * @returns Политика с MFA
   */
  static createMFARequiredPolicy(): AccessPolicy {
    return {
      policyId: 'mfa-required-policy',
      name: 'MFA Required for Sensitive Operations',
      description: 'MFA обязателен для критических операций',
      rules: [
        {
          ruleId: 'mfa-deny-sensitive',
          actions: [
            SecretAction.WRITE,
            SecretAction.DELETE,
            SecretAction.ROTATE,
            SecretAction.EXPORT
          ],
          resources: ['*'],
          subjects: ['*'],
          effect: 'deny',
          priority: 100,
          conditions: [
            {
              type: 'mfa_required',
              value: true,
              operator: 'equals'
            }
          ],
          description: 'Критические операции требуют MFA'
        },
        {
          ruleId: 'mfa-allow-sensitive',
          actions: [
            SecretAction.WRITE,
            SecretAction.DELETE,
            SecretAction.ROTATE,
            SecretAction.EXPORT
          ],
          resources: ['*'],
          subjects: ['*'],
          effect: 'allow',
          priority: 90,
          conditions: [
            {
              type: 'mfa_required',
              value: false,
              operator: 'equals'
            }
          ],
          description: 'Разрешено если MFA пройден'
        }
      ],
      createdAt: new Date(),
      createdBy: 'system',
      version: 1,
      enabled: true
    };
  }

  /**
   * Валидация правил политики
   * 
   * @param policy - Политика для валидации
   * @throws SecretAccessError если правила некорректны
   */
  private validatePolicyRules(policy: AccessPolicy): void {
    if (!policy.rules || policy.rules.length === 0) {
      throw new SecretAccessError(
        `Политика ${policy.policyId} должна иметь хотя бы одно правило`
      );
    }
    
    const ruleIds = new Set<string>();
    
    for (const rule of policy.rules) {
      // Проверка уникальности ID правил
      if (ruleIds.has(rule.ruleId)) {
        throw new SecretAccessError(
          `Дублирующийся ruleId: ${rule.ruleId} в политике ${policy.policyId}`
        );
      }
      ruleIds.add(rule.ruleId);
      
      // Проверка наличия обязательных полей
      if (!rule.actions || rule.actions.length === 0) {
        throw new SecretAccessError(
          `Правило ${rule.ruleId} должно иметь хотя бы одно действие`
        );
      }
      
      if (!rule.resources || rule.resources.length === 0) {
        throw new SecretAccessError(
          `Правило ${rule.ruleId} должно иметь хотя бы один ресурс`
        );
      }
      
      if (!rule.subjects || rule.subjects.length === 0) {
        throw new SecretAccessError(
          `Правило ${rule.ruleId} должно иметь хотя бы один субъект`
        );
      }
    }
  }

  /**
   * Сбор всех применимых правил
   */
  private collectApplicableRules(
    action: SecretAction,
    resource: string,
    context: AccessContext
  ): AccessPolicyRule[] {
    const applicableRules: AccessPolicyRule[] = [];
    
    for (const policy of this.policies.values()) {
      if (!policy.enabled) {
        continue;
      }
      
      for (const rule of policy.rules) {
        // Проверка действия
        if (!this.matchAction(action, rule.actions)) {
          continue;
        }
        
        // Проверка ресурса
        if (!this.matchResource(resource, rule.resources)) {
          continue;
        }
        
        // Проверка субъекта
        if (!this.matchSubject(context, rule.subjects)) {
          continue;
        }
        
        applicableRules.push(rule);
      }
    }
    
    return applicableRules;
  }

  /**
   * Проверка соответствия действия
   */
  private matchAction(action: SecretAction, actions: SecretAction[]): boolean {
    return actions.includes(action) || actions.includes(SecretAction.READ);
  }

  /**
   * Проверка соответствия ресурса
   */
  private matchResource(resource: string, resources: string[]): boolean {
    for (const pattern of resources) {
      if (pattern === '*') {
        return true;
      }
      
      // Поддержка wildcard паттернов
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        if (regex.test(resource)) {
          return true;
        }
      } else if (pattern === resource) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Проверка соответствия субъекта
   */
  private matchSubject(context: AccessContext, subjects: string[]): boolean {
    for (const pattern of subjects) {
      if (pattern === '*') {
        return true;
      }
      
      // Проверка по роли (role:admin)
      if (pattern.startsWith('role:')) {
        const role = pattern.slice(5);
        if (context.roles.includes(role)) {
          return true;
        }
        continue;
      }
      
      // Проверка по типу (type:service)
      if (pattern.startsWith('type:')) {
        const type = pattern.slice(5);
        if (context.attributes['type'] === type) {
          return true;
        }
        continue;
      }
      
      // Прямое совпадение по ID
      if (pattern === context.subjectId) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Проверка условий правила
   */
  private async checkConditions(
    conditions: PolicyCondition[],
    context: AccessContext
  ): Promise<boolean> {
    if (conditions.length === 0) {
      return true;
    }
    
    for (const condition of conditions) {
      const met = await this.checkSingleCondition(condition, context);
      
      if (!met) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Проверка одного условия
   */
  private async checkSingleCondition(
    condition: PolicyCondition,
    context: AccessContext
  ): Promise<boolean> {
    switch (condition.type) {
      case 'ip_range':
        return this.checkIPRange(condition, context);
      
      case 'time_range':
        return this.checkTimeRange(condition);
      
      case 'mfa_required':
        return this.checkMFA(condition, context);
      
      case 'role':
        return this.checkRole(condition, context);
      
      case 'attribute':
        return this.checkAttribute(condition, context);
      
      default:
        console.warn(`[AccessPolicy] Неизвестный тип условия: ${condition.type}`);
        return true;
    }
  }

  /**
   * Проверка IP диапазона
   */
  private checkIPRange(condition: PolicyCondition, context: AccessContext): boolean {
    const value = condition.value as string | string[];
    const ipRanges = Array.isArray(value) ? value : [value];
    
    for (const range of ipRanges) {
      if (this.isIPInRange(context.ipAddress, range)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Проверка IP в диапазоне
   */
  private isIPInRange(ip: string, range: string): boolean {
    // Поддержка CIDR нотации
    if (range.includes('/')) {
      const [network, prefixStr] = range.split('/');
      const prefix = parseInt(prefixStr, 10);
      
      const ipNum = this.ipToNumber(ip);
      const networkNum = this.ipToNumber(network);
      const mask = ~((1 << (32 - prefix)) - 1);
      
      return (ipNum & mask) === (networkNum & mask);
    }
    
    // Точное совпадение
    return ip === range;
  }

  /**
   * Конвертация IP в число
   */
  private ipToNumber(ip: string): number {
    return ip.split('.').reduce((acc, octet) => {
      return (acc << 8) + parseInt(octet, 10);
    }, 0) >>> 0;
  }

  /**
   * Проверка временного диапазона
   */
  private checkTimeRange(condition: PolicyCondition): boolean {
    const value = condition.value as { startHour: number; endHour: number };
    const currentHour = new Date().getHours();
    
    const { startHour, endHour } = value;
    
    if (startHour <= endHour) {
      // Обычный диапазон (например, 9-17)
      return currentHour >= startHour && currentHour < endHour;
    } else {
      // Диапазон через полночь (например, 22-6)
      return currentHour >= startHour || currentHour < endHour;
    }
  }

  /**
   * Проверка MFA
   */
  private checkMFA(condition: PolicyCondition, context: AccessContext): boolean {
    const required = condition.value as boolean;
    const operator = condition.operator ?? 'equals';
    
    if (operator === 'equals') {
      return context.mfaVerified === required;
    }
    
    return context.mfaVerified === true;
  }

  /**
   * Проверка роли
   */
  private checkRole(condition: PolicyCondition, context: AccessContext): boolean {
    const value = condition.value as string | string[];
    const roles = Array.isArray(value) ? value : [value];
    const operator = condition.operator ?? 'in';
    
    if (operator === 'in') {
      return roles.some(role => context.roles.includes(role));
    } else if (operator === 'equals') {
      return roles.some(role => context.roles.includes(role));
    }
    
    return false;
  }

  /**
   * Проверка атрибута
   */
  private checkAttribute(condition: PolicyCondition, context: AccessContext): boolean {
    const value = condition.value as Record<string, unknown>;
    const operator = condition.operator ?? 'equals';
    
    for (const [key, expectedValue] of Object.entries(value)) {
      const actualValue = context.attributes[key];
      
      switch (operator) {
        case 'equals':
          if (actualValue !== expectedValue) return false;
          break;
        
        case 'contains':
          if (!String(actualValue).includes(String(expectedValue))) return false;
          break;
        
        case 'in':
          if (!Array.isArray(expectedValue) || !expectedValue.includes(actualValue)) return false;
          break;
        
        case 'not_in':
          if (Array.isArray(expectedValue) && expectedValue.includes(actualValue)) return false;
          break;
      }
    }
    
    return true;
  }

  /**
   * Генерация ключа кэша
   */
  private getCacheKey(
    action: SecretAction,
    resource: string,
    subjectId: string
  ): string {
    return `${subjectId}:${action}:${resource}`;
  }

  /**
   * Получить решение из кэша
   */
  private getCachedDecision(cacheKey: string): boolean | null {
    if (!this.cacheEnabled) {
      return null;
    }
    
    const cached = this.accessCache.get(cacheKey);
    
    if (!cached) {
      return null;
    }
    
    // Проверка TTL
    if (Date.now() - cached.timestamp > this.ACCESS_CACHE_TTL) {
      this.accessCache.delete(cacheKey);
      return null;
    }
    
    return cached.allowed;
  }

  /**
   * Кэширование решения
   */
  private cacheDecision(cacheKey: string, allowed: boolean): void {
    if (!this.cacheEnabled) {
      return;
    }
    
    this.accessCache.set(cacheKey, {
      allowed,
      timestamp: Date.now()
    });
  }

  /**
   * Очистка кэша доступа
   */
  private clearAccessCache(): void {
    this.accessCache.clear();
  }

  /**
   * Запуск очистки кэша
   */
  private startCacheCleanup(): void {
    setInterval(() => {
      const now = Date.now();
      
      for (const [key, value] of this.accessCache.entries()) {
        if (now - value.timestamp > this.ACCESS_CACHE_TTL) {
          this.accessCache.delete(key);
        }
      }
    }, 60000); // Каждую минуту
  }

  /**
   * Получить статистику политик
   */
  getStats(): {
    totalPolicies: number;
    enabledPolicies: number;
    totalRules: number;
    cacheSize: number;
  } {
    const policies = Array.from(this.policies.values());
    
    return {
      totalPolicies: policies.length,
      enabledPolicies: policies.filter(p => p.enabled).length,
      totalRules: policies.reduce((sum, p) => sum + p.rules.length, 0),
      cacheSize: this.accessCache.size
    };
  }
}
