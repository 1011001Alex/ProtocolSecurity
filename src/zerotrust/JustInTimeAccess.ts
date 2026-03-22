/**
 * Just-In-Time Access - Временный Доступ по Запросу
 * 
 * Компонент реализует JIT доступ - предоставление временных
 * привилегий по запросу с обязательным утверждением и аудитом.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  JitAccessRequest,
  JitRequestStatus,
  Identity,
  ResourceType,
  PolicyOperation,
  ZeroTrustEvent,
  SubjectType
} from './zerotrust.types';
import { PolicyDecisionPoint } from './PolicyDecisionPoint';
import { TrustVerifier } from './TrustVerifier';

/**
 * Конфигурация JIT Access
 */
export interface JustInTimeAccessConfig {
  /** Требовать утверждение для всех запросов */
  requireApprovalForAll: boolean;
  
  /** Автоматически утверждать низкорисковые запросы */
  autoApproveLowRisk: boolean;
  
  /** Порог риска для автоматического утверждения */
  autoApproveRiskThreshold: number;
  
  /** Максимальная длительность доступа (секунды) */
  maxAccessDuration: number;
  
  /** Максимальное продление доступа */
  maxExtensions: number;
  
  /** Интервал проверки истёкших доступов (секунды) */
  expirationCheckInterval: number;
  
  /** Включить уведомления об истечении */
  enableExpirationNotifications: boolean;
  
  /** Время уведомления об истечении (секунды до конца) */
  expirationNotificationTime: number;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
}

/**
 * Approver - лицо, утверждающее доступ
 */
interface Approver {
  /** ID approver */
  id: string;
  
  /** Имя */
  name: string;
  
  /** Email */
  email: string;
  
  /** Роли */
  roles: string[];
  
  /** Ресурсы для утверждения */
  approvableResources: string[];
  
  /** Доступен ли */
  available: boolean;
}

/**
 * Just-In-Time Access Manager
 * 
 * Управляет запросами временного доступа.
 */
export class JustInTimeAccess extends EventEmitter {
  /** Конфигурация */
  private config: JustInTimeAccessConfig;
  
  /** PDP для проверок */
  private pdp: PolicyDecisionPoint | null;
  
  /** Trust Verifier */
  private trustVerifier: TrustVerifier | null;
  
  /** Запросы доступа */
  private requests: Map<string, JitAccessRequest>;
  
  /** Approvers */
  private approvers: Map<string, Approver>;
  
  /** Активные JIT доступы */
  private activeAccesses: Map<string, {
    requestId: string;
    subjectId: string;
    resourceId: string;
    expiresAt: Date;
    operations: PolicyOperation[];
  }>;
  
  /** Таймеры истечения */
  private expirationTimers: Map<string, NodeJS.Timeout>;
  
  /** Статистика */
  private stats: {
    /** Всего запросов */
    totalRequests: number;
    /** Утверждено */
    approved: number;
    /** Отклонено */
    denied: number;
    /** Ожидает */
    pending: number;
    /** Истекло */
    expired: number;
    /** Отозвано */
    revoked: number;
  };

  constructor(config: Partial<JustInTimeAccessConfig> = {}) {
    super();
    
    this.config = {
      requireApprovalForAll: config.requireApprovalForAll ?? false,
      autoApproveLowRisk: config.autoApproveLowRisk ?? true,
      autoApproveRiskThreshold: config.autoApproveRiskThreshold ?? 20,
      maxAccessDuration: config.maxAccessDuration ?? 28800, // 8 часов
      maxExtensions: config.maxExtensions ?? 3,
      expirationCheckInterval: config.expirationCheckInterval ?? 60,
      enableExpirationNotifications: config.enableExpirationNotifications ?? true,
      expirationNotificationTime: config.expirationNotificationTime ?? 300, // 5 минут
      enableVerboseLogging: config.enableVerboseLogging ?? false
    };
    
    this.pdp = null;
    this.trustVerifier = null;
    this.requests = new Map();
    this.approvers = new Map();
    this.activeAccesses = new Map();
    this.expirationTimers = new Map();
    
    this.stats = {
      totalRequests: 0,
      approved: 0,
      denied: 0,
      pending: 0,
      expired: 0,
      revoked: 0
    };
    
    // Запускаем проверку истёкших доступов
    this.startExpirationChecker();
    
    this.log('JIT', 'JustInTimeAccess инициализирован');
  }

  /**
   * Установить PDP
   */
  public setPdp(pdp: PolicyDecisionPoint): void {
    this.pdp = pdp;
    this.log('JIT', 'PDP установлен');
  }

  /**
   * Установить Trust Verifier
   */
  public setTrustVerifier(trustVerifier: TrustVerifier): void {
    this.trustVerifier = trustVerifier;
    this.log('JIT', 'TrustVerifier установлен');
  }

  /**
   * Зарегистрировать approver
   */
  public registerApprover(approver: Approver): void {
    this.approvers.set(approver.id, approver);
    this.log('JIT', 'Approver зарегистрирован', {
      approverId: approver.id,
      name: approver.name
    });
  }

  /**
   * Создать запрос JIT доступа
   */
  public async createRequest(context: {
    subjectId: string;
    subjectType: SubjectType;
    resourceType: ResourceType;
    resourceId: string;
    resourceName: string;
    operations: PolicyOperation[];
    duration: number;
    justification: string;
  }): Promise<JitAccessRequest> {
    const requestId = uuidv4();
    const now = new Date();
    
    this.stats.totalRequests++;
    
    this.log('JIT', 'Создание запроса JIT доступа', {
      requestId,
      subjectId: context.subjectId,
      resource: context.resourceId,
      duration: context.duration
    });
    
    // Проверяем максимальную длительность
    const requestedDuration = Math.min(context.duration, this.config.maxAccessDuration);
    
    // Создаём запрос
    const request: JitAccessRequest = {
      requestId,
      subjectId: context.subjectId,
      subjectType: context.subjectType,
      resource: {
        type: context.resourceType,
        id: context.resourceId,
        name: context.resourceName
      },
      requestedOperations: context.operations,
      justification: context.justification,
      requestedDuration: requestedDuration,
      createdAt: now,
      activatedAt: undefined,
      expiresAt: undefined,
      status: JitRequestStatus.PENDING,
      approval: undefined,
      denial: undefined,
      usage: {
        wasUsed: false,
        firstUsedAt: undefined,
        lastUsedAt: undefined,
        operationCount: 0
      }
    };
    
    this.requests.set(requestId, request);
    this.stats.pending++;
    
    // Определяем, требуется ли утверждение
    const requiresApproval = this.requiresApproval(request);
    
    if (requiresApproval) {
      // Отправляем уведомление approvers
      this.notifyApprovers(request);
      
      this.log('JIT', 'Запрос требует утверждения', { requestId });
      this.emit('request:pending', request);
    } else {
      // Автоматическое утверждение
      this.approveRequest(requestId, 'system', 'Автоматическое утверждение низкорискового запроса');
    }
    
    return request;
  }

  /**
   * Определить, требуется ли утверждение
   */
  private requiresApproval(request: JitAccessRequest): boolean {
    // Если требуется утверждение для всех
    if (this.config.requireApprovalForAll) {
      return true;
    }
    
    // Если включено автоутверждение низкорисковых
    if (this.config.autoApproveLowRisk && this.trustVerifier) {
      // Проверяем риск (в реальной реализации здесь была бы оценка риска)
      // Для демонстрации считаем низкорисковыми запросы на чтение
      const isReadOnly = request.requestedOperations.every(
        op => op === PolicyOperation.READ
      );
      
      if (isReadOnly) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Уведомить approvers
   */
  private notifyApprovers(request: JitAccessRequest): void {
    // Находим подходящих approvers
    const eligibleApprovers = Array.from(this.approvers.values())
      .filter(a => a.available)
      .filter(a => 
        a.approvableResources.length === 0 ||
        a.approvableResources.includes(request.resource.id)
      );
    
    for (const approver of eligibleApprovers) {
      this.emit('notification:approval_required', {
        approverId: approver.id,
        request
      });
    }
    
    this.log('JIT', `Уведомлено ${eligibleApprovers.length} approvers`, {
      requestId: request.requestId
    });
  }

  /**
   * Утвердить запрос
   */
  public approveRequest(
    requestId: string,
    approverId: string,
    comment?: string
  ): boolean {
    const request = this.requests.get(requestId);
    
    if (!request) {
      return false;
    }
    
    if (request.status !== JitRequestStatus.PENDING &&
        request.status !== JitRequestStatus.UNDER_REVIEW) {
      return false;
    }
    
    const approver = this.approvers.get(approverId);
    const now = new Date();
    
    request.status = JitRequestStatus.APPROVED;
    request.approval = {
      approverId,
      approverName: approver?.name ?? 'Unknown',
      approvedAt: now,
      comment
    };
    
    // Активируем доступ
    this.activateAccess(request);
    
    this.stats.pending--;
    this.stats.approved++;
    
    this.log('JIT', 'Запрос утверждён', {
      requestId,
      approverId,
      expiresAt: request.expiresAt
    });
    
    this.emit('request:approved', request);
    
    return true;
  }

  /**
   * Отклонить запрос
   */
  public denyRequest(
    requestId: string,
    denierId: string,
    reason: string
  ): boolean {
    const request = this.requests.get(requestId);
    
    if (!request) {
      return false;
    }
    
    if (request.status !== JitRequestStatus.PENDING &&
        request.status !== JitRequestStatus.UNDER_REVIEW) {
      return false;
    }
    
    const denier = this.approvers.get(denierId);
    
    request.status = JitRequestStatus.DENIED;
    request.denial = {
      denierId,
      reason,
      deniedAt: new Date()
    };
    
    this.stats.pending--;
    this.stats.denied++;
    
    this.log('JIT', 'Запрос отклонён', {
      requestId,
      denierId,
      reason
    });
    
    this.emit('request:denied', request);
    
    return true;
  }

  /**
   * Активировать доступ
   */
  private activateAccess(request: JitAccessRequest): void {
    const now = new Date();
    
    request.activatedAt = now;
    request.expiresAt = new Date(now.getTime() + request.requestedDuration * 1000);
    request.status = JitRequestStatus.ACTIVE;
    
    // Добавляем в активные доступы
    this.activeAccesses.set(request.requestId, {
      requestId: request.requestId,
      subjectId: request.subjectId,
      resourceId: request.resource.id,
      expiresAt: request.expiresAt,
      operations: request.requestedOperations
    });
    
    // Запускаем таймер истечения
    this.startExpirationTimer(request.requestId, request.expiresAt);
    
    this.log('JIT', 'Доступ активирован', {
      requestId: request.requestId,
      expiresAt: request.expiresAt
    });
  }

  /**
   * Запустить таймер истечения
   */
  private startExpirationTimer(requestId: string, expiresAt: Date): void {
    const timeUntilExpiration = expiresAt.getTime() - Date.now();
    
    // Таймер уведомления
    if (this.config.enableExpirationNotifications) {
      const notificationTime = Math.max(0, timeUntilExpiration - this.config.expirationNotificationTime * 1000);
      
      setTimeout(() => {
        this.emit('notification:access_expiring', {
          requestId,
          expiresAt,
          timeRemaining: this.config.expirationNotificationTime
        });
      }, notificationTime);
    }
    
    // Таймер истечения
    const timer = setTimeout(() => {
      this.expireAccess(requestId);
    }, timeUntilExpiration);
    
    this.expirationTimers.set(requestId, timer);
  }

  /**
   * Истечь доступ
   */
  private expireAccess(requestId: string): void {
    const request = this.requests.get(requestId);
    
    if (!request || request.status !== JitRequestStatus.ACTIVE) {
      return;
    }
    
    request.status = JitRequestStatus.EXPIRED;
    this.activeAccesses.delete(requestId);
    
    const timer = this.expirationTimers.get(requestId);
    if (timer) {
      clearTimeout(timer);
      this.expirationTimers.delete(requestId);
    }
    
    this.stats.expired++;
    
    this.log('JIT', 'Доступ истёк', { requestId });
    this.emit('request:expired', request);
  }

  /**
   * Отозвать доступ
   */
  public revokeAccess(requestId: string, reason: string): boolean {
    const request = this.requests.get(requestId);
    
    if (!request) {
      return false;
    }
    
    if (request.status !== JitRequestStatus.ACTIVE) {
      return false;
    }
    
    request.status = JitRequestStatus.REVOKED;
    this.activeAccesses.delete(requestId);
    
    const timer = this.expirationTimers.get(requestId);
    if (timer) {
      clearTimeout(timer);
      this.expirationTimers.delete(requestId);
    }
    
    this.stats.revoked++;
    
    this.log('JIT', 'Доступ отозван', { requestId, reason });
    this.emit('request:revoked', { request, reason });
    
    return true;
  }

  /**
   * Продлить доступ
   */
  public extendAccess(
    requestId: string,
    additionalDuration: number,
    justification: string
  ): boolean {
    const request = this.requests.get(requestId);
    
    if (!request || request.status !== JitRequestStatus.ACTIVE) {
      return false;
    }
    
    // Проверяем максимальное количество продлений
    const currentExtensions = (request as any).extensions || 0;
    
    if (currentExtensions >= this.config.maxExtensions) {
      this.log('JIT', 'Превышено максимальное количество продлений', { requestId });
      return false;
    }
    
    // Проверяем максимальную длительность
    const totalDuration = request.requestedDuration + additionalDuration;
    
    if (totalDuration > this.config.maxAccessDuration) {
      this.log('JIT', 'Превышена максимальная длительность доступа', { requestId });
      return false;
    }
    
    // Продлеваем доступ
    request.requestedDuration += additionalDuration;
    
    if (request.expiresAt) {
      request.expiresAt = new Date(request.expiresAt.getTime() + additionalDuration * 1000);
    }
    
    // Обновляем таймер
    const timer = this.expirationTimers.get(requestId);
    if (timer) {
      clearTimeout(timer);
    }
    
    this.startExpirationTimer(requestId, request.expiresAt!);
    
    (request as any).extensions = currentExtensions + 1;
    
    this.log('JIT', 'Доступ продлён', {
      requestId,
      additionalDuration,
      newExpiresAt: request.expiresAt
    });
    
    this.emit('request:extended', request);
    
    return true;
  }

  /**
   * Проверить активный доступ
   */
  public checkActiveAccess(subjectId: string, resourceId: string): {
    hasAccess: boolean;
    operations: PolicyOperation[];
    expiresAt?: Date;
  } {
    for (const access of this.activeAccesses.values()) {
      if (access.subjectId === subjectId && access.resourceId === resourceId) {
        if (new Date() < access.expiresAt) {
          return {
            hasAccess: true,
            operations: access.operations,
            expiresAt: access.expiresAt
          };
        }
      }
    }
    
    return {
      hasAccess: false,
      operations: []
    };
  }

  /**
   * Запустить проверку истёкших доступов
   */
  private startExpirationChecker(): void {
    setInterval(() => {
      const now = Date.now();
      
      for (const [requestId, access] of this.activeAccesses.entries()) {
        if (now >= access.expiresAt.getTime()) {
          this.expireAccess(requestId);
        }
      }
    }, this.config.expirationCheckInterval * 1000);
  }

  /**
   * Получить запрос
   */
  public getRequest(requestId: string): JitAccessRequest | undefined {
    return this.requests.get(requestId);
  }

  /**
   * Получить все запросы субъекта
   */
  public getSubjectRequests(subjectId: string): JitAccessRequest[] {
    return Array.from(this.requests.values())
      .filter(r => r.subjectId === subjectId);
  }

  /**
   * Получить все активные доступы
   */
  public getActiveAccesses(): Array<typeof this.activeAccesses extends Map<string, infer T> ? T : never> {
    return Array.from(this.activeAccesses.values());
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats & {
    /** Активные доступы */
    activeAccesses: number;
    /** Ожидают утверждения */
    pendingApproval: number;
  } {
    const pendingCount = Array.from(this.requests.values())
      .filter(r => r.status === JitRequestStatus.PENDING).length;
    
    return {
      ...this.stats,
      activeAccesses: this.activeAccesses.size,
      pendingApproval: pendingCount
    };
  }

  /**
   * Логирование
   */
  private log(component: string, message: string, data?: unknown): void {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'JIT_ACCESS_REQUESTED',
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
    
    if (this.config.enableVerboseLogging) {
      console.log(`[JIT] ${new Date().toISOString()} - ${message}`, data ?? '');
    }
  }
}

export default JustInTimeAccess;
