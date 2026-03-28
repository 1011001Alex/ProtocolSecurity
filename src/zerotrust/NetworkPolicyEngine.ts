/**
 * Network Policy Engine - Движок Сетевых Политик
 * 
 * Компонент реализует централизованный движок для управления
 * всеми сетевыми политиками Zero Trust архитектуры.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { v4 as uuidv4 } from 'uuid';
import {
  AccessPolicyRule,
  MicroSegmentationRule,
  EgressFilterRule,
  PolicyEvaluationResult,
  PolicyDecision,
  ZeroTrustEvent,
  SubjectType,
  Identity,
  AuthContext,
  ResourceType,
  PolicyOperation,
  AccessRequest
} from './zerotrust.types';
import { PolicyDecisionPoint } from './PolicyDecisionPoint';
import { MicroSegmentation } from './MicroSegmentation';
import { EgressFilter } from './EgressFilter';

/**
 * Тип политики
 */
enum PolicyType {
  /** Политика доступа */
  ACCESS = 'ACCESS',
  
  /** Политика сегментации */
  SEGMENTATION = 'SEGMENTATION',
  
  /** Политика egress */
  EGRESS = 'EGRESS',
  
  /** Глобальная политика */
  GLOBAL = 'GLOBAL'
}

/**
 * Конфигурация Network Policy Engine
 */
export interface NetworkPolicyEngineConfig {
  /** Включить кэширование решений */
  enableCaching: boolean;
  
  /** TTL кэша (секунды) */
  cacheTtl: number;
  
  /** Включить приоритизацию политик */
  enablePrioritization: boolean;
  
  /** Включить наследование политик */
  enableInheritance: boolean;
  
  /** Default действие */
  defaultAction: 'ALLOW' | 'DENY';
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
}

/**
 * Network Policy Engine
 * 
 * Централизованный движок для управления сетевыми политиками.
 */
export class NetworkPolicyEngine extends EventEmitter {
  /** Конфигурация */
  private config: NetworkPolicyEngineConfig;
  
  /** PDP для access политик */
  private pdp: PolicyDecisionPoint | null;
  
  /** Micro-segmentation engine */
  private microSegmentation: MicroSegmentation | null;
  
  /** Egress filter */
  private egressFilter: EgressFilter | null;
  
  /** Политики */
  private policies: {
    access: Map<string, AccessPolicyRule>;
    segmentation: Map<string, MicroSegmentationRule>;
    egress: Map<string, EgressFilterRule>;
    global: Map<string, {
      id: string;
      name: string;
      enabled: boolean;
      priority: number;
    }>;
  };
  
  /** Кэш решений */
  private decisionCache: Map<string, {
    decision: PolicyEvaluationResult;
    expiresAt: Date;
  }>;
  
  /** Статистика */
  private stats: {
    /** Всего политик */
    totalPolicies: number;
    /** Оценок выполнено */
    evaluationsPerformed: number;
    /** Попаданий в кэш */
    cacheHits: number;
  };

  constructor(config: Partial<NetworkPolicyEngineConfig> = {}) {
    super();
    
    this.config = {
      enableCaching: config.enableCaching ?? true,
      cacheTtl: config.cacheTtl ?? 300,
      enablePrioritization: config.enablePrioritization ?? true,
      enableInheritance: config.enableInheritance ?? false,
      defaultAction: config.defaultAction ?? 'DENY',
      enableVerboseLogging: config.enableVerboseLogging ?? false
    };
    
    this.pdp = null;
    this.microSegmentation = null;
    this.egressFilter = null;
    
    this.policies = {
      access: new Map(),
      segmentation: new Map(),
      egress: new Map(),
      global: new Map()
    };
    
    this.decisionCache = new Map();
    
    this.stats = {
      totalPolicies: 0,
      evaluationsPerformed: 0,
      cacheHits: 0
    };
    
    this.log('NPE', 'NetworkPolicyEngine инициализирован');
  }

  /**
   * Установить PDP
   */
  public setPdp(pdp: PolicyDecisionPoint): void {
    this.pdp = pdp;
    this.log('NPE', 'PDP установлен');
  }

  /**
   * Установить Micro-segmentation
   */
  public setMicroSegmentation(ms: MicroSegmentation): void {
    this.microSegmentation = ms;
    this.log('NPE', 'MicroSegmentation установлен');
  }

  /**
   * Установить Egress Filter
   */
  public setEgressFilter(ef: EgressFilter): void {
    this.egressFilter = ef;
    this.log('NPE', 'EgressFilter установлен');
  }

  /**
   * Добавить политику доступа
   */
  public addAccessPolicy(policy: AccessPolicyRule): void {
    this.policies.access.set(policy.id, policy);
    this.updatePolicyCount();
    
    // Добавляем в PDP если установлен
    if (this.pdp) {
      this.pdp.addPolicy(policy);
    }
    
    this.log('NPE', 'Политика доступа добавлена', {
      policyId: policy.id,
      name: policy.name,
      effect: policy.effect
    });
    
    this.emit('policy:added', { type: PolicyType.ACCESS, policy });
  }

  /**
   * Добавить политику сегментации
   */
  public addSegmentationPolicy(policy: MicroSegmentationRule): void {
    this.policies.segmentation.set(policy.id, policy);
    this.updatePolicyCount();
    
    // Добавляем в micro-segmentation если установлен
    if (this.microSegmentation) {
      this.microSegmentation.addRule(policy);
    }
    
    this.log('NPE', 'Политика сегментации добавлена', {
      policyId: policy.id,
      name: policy.name
    });
    
    this.emit('policy:added', { type: PolicyType.SEGMENTATION, policy });
  }

  /**
   * Добавить политику egress
   */
  public addEgressPolicy(policy: EgressFilterRule): void {
    this.policies.egress.set(policy.id, policy);
    this.updatePolicyCount();
    
    // Добавляем в egress filter если установлен
    if (this.egressFilter) {
      this.egressFilter.addRule(policy);
    }
    
    this.log('NPE', 'Egress политика добавлена', {
      policyId: policy.id,
      name: policy.name
    });
    
    this.emit('policy:added', { type: PolicyType.EGRESS, policy });
  }

  /**
   * Обновить счётчик политик
   */
  private updatePolicyCount(): void {
    this.stats.totalPolicies = 
      this.policies.access.size +
      this.policies.segmentation.size +
      this.policies.egress.size +
      this.policies.global.size;
  }

  /**
   * Оценить запрос доступа
   */
  public async evaluateAccessRequest(context: {
    identity: Identity;
    authContext: AuthContext;
    resourceType: ResourceType;
    resourceId: string;
    resourceName: string;
    operation: PolicyOperation;
    sourceIp: string;
  }): Promise<PolicyEvaluationResult> {
    this.stats.evaluationsPerformed++;

    // Проверяем кэш
    if (this.config.enableCaching) {
      const cacheKey = this.getCacheKey(context);
      const cached = this.decisionCache.get(cacheKey);

      if (cached && new Date() < cached.expiresAt) {
        this.stats.cacheHits++;
        this.log('NPE', 'Решение найдено в кэше', { cacheKey });
        return cached.decision;
      }
    }

    let result: PolicyEvaluationResult;

    // Используем PDP если установлен
    if (this.pdp) {
      // Создаём полный AccessRequest для PDP
      const accessRequest: AccessRequest = {
        requestId: uuidv4(),
        identity: context.identity,
        authContext: context.authContext,
        resourceType: context.resourceType,
        resourceId: context.resourceId,
        operation: context.operation,
        sourceIp: context.sourceIp,
        resourceName: context.resourceName,
        metadata: {}
      };
      const response = await this.pdp.evaluateAccess(accessRequest);
      
      // Преобразуем AccessResponse в PolicyEvaluationResult
      result = {
        evaluationId: response.responseId,
        evaluatedAt: response.decidedAt,
        decision: response.decision,
        trustLevel: response.trustLevel,
        appliedRules: response.appliedRules || [],
        factors: [],
        restrictions: response.restrictions || {},
        recommendations: response.recommendations || [],
        reason: response.reason
      };
    } else {
      // Fallback - простая оценка
      result = this.simpleEvaluate(context);
    }
    
    // Кэшируем результат
    if (this.config.enableCaching) {
      const cacheKey = this.getCacheKey(context);
      this.decisionCache.set(cacheKey, {
        decision: result,
        expiresAt: new Date(Date.now() + this.config.cacheTtl * 1000)
      });
      
      // Очищаем старые записи
      if (this.decisionCache.size > 10000) {
        const now = Date.now();
        for (const [key, value] of this.decisionCache.entries()) {
          if (now > value.expiresAt.getTime()) {
            this.decisionCache.delete(key);
          }
        }
      }
    }
    
    this.log('NPE', 'Оценка доступа завершена', {
      decision: result.decision,
      trustLevel: result.trustLevel
    });
    
    return result;
  }

  /**
   * Простая оценка (fallback)
   */
  private simpleEvaluate(context: {
    identity: Identity;
    authContext: AuthContext;
    resourceType: ResourceType;
    resourceId: string;
    operation: PolicyOperation;
    sourceIp: string;
  }): PolicyEvaluationResult {
    // Default deny
    return {
      evaluationId: uuidv4(),
      evaluatedAt: new Date(),
      decision: this.config.defaultAction === 'ALLOW' ? PolicyDecision.ALLOW : PolicyDecision.DENY,
      trustLevel: 0,
      appliedRules: [],
      factors: [],
      restrictions: {},
      recommendations: []
    };
  }

  /**
   * Проверить сегментацию
   */
  public checkSegmentation(
    sourceId: string,
    destinationId: string,
    protocol: string,
    port: number
  ): {
    allowed: boolean;
    reason: string;
  } {
    if (!this.microSegmentation) {
      return {
        allowed: this.config.defaultAction === 'ALLOW',
        reason: 'MicroSegmentation не установлен'
      };
    }
    
    const result = this.microSegmentation.checkTraffic(
      sourceId,
      destinationId,
      protocol,
      port
    );
    
    return {
      allowed: result.allowed,
      reason: result.reason
    };
  }

  /**
   * Проверить egress
   */
  public checkEgress(context: {
    sourceIp: string;
    destinationUrl?: string;
    destinationDomain?: string;
    destinationIp?: string;
    destinationPort?: number;
    payload?: string;
  }): {
    allowed: boolean;
    reason: string;
    dlpDetected: boolean;
  } {
    if (!this.egressFilter) {
      return {
        allowed: this.config.defaultAction === 'ALLOW',
        reason: 'EgressFilter не установлен',
        dlpDetected: false
      };
    }
    
    const result = this.egressFilter.checkEgress(context);
    
    return {
      allowed: result.allowed,
      reason: result.reason,
      dlpDetected: result.dlpEvents.length > 0
    };
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
   * Очистить кэш
   */
  public clearCache(): void {
    this.decisionCache.clear();
    this.log('NPE', 'Кэш очищен');
  }

  /**
   * Получить все политики
   */
  public getAllPolicies(): {
    access: AccessPolicyRule[];
    segmentation: MicroSegmentationRule[];
    egress: EgressFilterRule[];
  } {
    return {
      access: Array.from(this.policies.access.values()),
      segmentation: Array.from(this.policies.segmentation.values()),
      egress: Array.from(this.policies.egress.values())
    };
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats & {
    /** Размер кэша */
    cacheSize: number;
  } {
    return {
      ...this.stats,
      cacheSize: this.decisionCache.size
    };
  }

  /**
   * Экспорт политик
   */
  public exportPolicies(): {
    version: string;
    exportedAt: Date;
    policies: {
      access: AccessPolicyRule[];
      segmentation: MicroSegmentationRule[];
      egress: EgressFilterRule[];
    };
  } {
    return {
      version: '1.0',
      exportedAt: new Date(),
      policies: this.getAllPolicies()
    };
  }

  /**
   * Логирование
   */
  private log(component: string, message: string, data?: unknown): void {
    const logData = typeof data === 'object' && data !== null ? data : { data };
    
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'ACCESS_REQUEST',
      timestamp: new Date(),
      subject: {
        id: 'system',
        type: SubjectType.SYSTEM,
        name: component
      },
      details: { message, ...logData },
      severity: 'INFO',
      correlationId: uuidv4()
    };

    this.emit('log', event);

    if (this.config.enableVerboseLogging) {
      logger.debug(`[NPE] ${message}`, { timestamp: new Date().toISOString(), ...logData });
    }
  }
}

export default NetworkPolicyEngine;
