/**
 * ============================================================================
 * SECRET LEASE MANAGER - УПРАВЛЕНИЕ АРЕНДОЙ СЕКРЕТОВ С AUTO-RENEWAL
 * ============================================================================
 * 
 * Реализует систему lease (аренды) для секретов с автоматическим продлением,
 * отслеживанием истечения, grace period и отзывом. Поддерживает динамические
 * секреты с временными учётными данными.
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';
import { logger } from '../logging/Logger';
import {
  SecretLease,
  LeaseConfig,
  SecretStatus,
  SecretLeaseError,
  AccessContext
} from '../types/secrets.types';

/**
 * Внутреннее состояние lease
 */
interface LeaseState {
  /** Lease объект */
  lease: SecretLease;
  /** Таймер истечения */
  expirationTimer?: NodeJS.Timeout;
  /** Таймер предупреждения об истечении */
  warningTimer?: NodeJS.Timeout;
  /** Таймер автоматического продления */
  autoRenewTimer?: NodeJS.Timeout;
}

/**
 * Конфигурация Lease Manager
 */
interface LeaseManagerConfig {
  /** Включить автоматическое продление */
  enableAutoRenewal: boolean;
  /** Интервал проверки истёкших lease (сек) */
  expirationCheckInterval: number;
  /** Время предупреждения до истечения (сек) */
  expirationWarningTime: number;
  /** Максимальное количество lease на субъект */
  maxLeasesPerSubject: number;
  /** Включить audit logging */
  enableAuditLogging: boolean;
}

/**
 * Класс для управления lease секретов
 * 
 * Особенности:
 * - Автоматическое продление lease
 * - Предупреждения об истечении
 * - Отзыв lease по требованию
 * - Ограничение количества lease
 * - Grace period перед истечением
 * - Мониторинг активных lease
 */
export class SecretLeaseManager extends EventEmitter {
  /** Конфигурация менеджера */
  private readonly config: LeaseManagerConfig;
  
  /** Конфигурация lease по умолчанию */
  private readonly defaultLeaseConfig: LeaseConfig;
  
  /** Хранилище активных lease */
  private leases: Map<string, LeaseState>;
  
  /** Индекс lease по субъектам */
  private subjectLeases: Map<string, Set<string>>;
  
  /** Индекс lease по секретам */
  private secretLeases: Map<string, Set<string>>;
  
  /** История отозванных lease */
  private revokedLeases: Map<string, SecretLease>;
  
  /** Флаг работы менеджера */
  private isRunning = false;
  
  /** Интервал проверки истёкших lease */
  private expirationCheckInterval?: NodeJS.Timeout;

  /** Конфигурация по умолчанию */
  private readonly DEFAULT_MANAGER_CONFIG: LeaseManagerConfig = {
    enableAutoRenewal: true,
    expirationCheckInterval: 30,
    expirationWarningTime: 300,
    maxLeasesPerSubject: 100,
    enableAuditLogging: true
  };

  /** Конфигурация lease по умолчанию */
  private readonly DEFAULT_LEASE_CONFIG: LeaseConfig = {
    defaultTTL: 3600,
    maxTTL: 86400,
    renewable: true,
    maxRenewals: 10,
    gracePeriod: 60,
    autoRevokeOnAnomaly: true
  };

  /**
   * Создаёт новый экземпляр SecretLeaseManager
   * 
   * @param managerConfig - Конфигурация менеджера
   * @param leaseConfig - Конфигурация lease по умолчанию
   */
  constructor(
    managerConfig: Partial<LeaseManagerConfig> = {},
    leaseConfig: Partial<LeaseConfig> = {}
  ) {
    super();
    
    this.config = {
      ...this.DEFAULT_MANAGER_CONFIG,
      ...managerConfig
    };
    
    this.defaultLeaseConfig = {
      ...this.DEFAULT_LEASE_CONFIG,
      ...leaseConfig
    };
    
    this.leases = new Map();
    this.subjectLeases = new Map();
    this.secretLeases = new Map();
    this.revokedLeases = new Map();
  }

  /**
   * Инициализация менеджера lease
   */
  async initialize(): Promise<void> {
    this.isRunning = true;

    // Запуск периодической проверки истёкших lease
    this.startExpirationCheck();

    logger.info('[SecretLease] Инициализирован', {
      autoRenewal: this.config.enableAutoRenewal,
      checkInterval: this.config.expirationCheckInterval,
      maxLeasesPerSubject: this.config.maxLeasesPerSubject
    });
  }

  /**
   * Остановка менеджера
   */
  async destroy(): Promise<void> {
    this.isRunning = false;

    // Остановка всех таймеров
    if (this.expirationCheckInterval) {
      clearInterval(this.expirationCheckInterval);
    }

    // Остановка всех lease таймеров
    for (const state of this.leases.values()) {
      this.clearLeaseTimers(state);
    }

    // Отзыв всех активных lease
    for (const leaseId of this.leases.keys()) {
      await this.revokeLeaseInternal(leaseId, 'system_shutdown');
    }

    logger.info('[SecretLease] Остановлен');
  }

  /**
   * Получить lease
   * 
   * @param secretId - ID секрета
   * @param context - Контекст запроса
   * @param ttl - Желаемый TTL (опционально)
   * @returns Выданный lease
   */
  async acquireLease(
    secretId: string,
    context: AccessContext,
    ttl?: number
  ): Promise<SecretLease> {
    // Проверка лимита lease на субъекта
    const subjectLeaseSet = this.subjectLeases.get(context.subjectId);
    
    if (subjectLeaseSet && subjectLeaseSet.size >= this.config.maxLeasesPerSubject) {
      throw new SecretLeaseError(
        `Превышен лимит lease (${this.config.maxLeasesPerSubject}) для субъекта ${context.subjectId}`,
        secretId
      );
    }
    
    // Вычисление TTL
    const requestedTTL = ttl ?? this.defaultLeaseConfig.defaultTTL;
    const effectiveTTL = Math.min(requestedTTL, this.defaultLeaseConfig.maxTTL);
    
    const now = new Date();
    const expiresAt = new Date(now.getTime() + effectiveTTL * 1000);
    
    // Создание lease
    const lease: SecretLease = {
      leaseId: randomUUID(),
      secretId,
      leasedBy: context.subjectId,
      leasedAt: now,
      expiresAt,
      maxTTL: effectiveTTL,
      renewable: this.defaultLeaseConfig.renewable,
      renewCount: 0,
      status: 'active',
      metadata: {
        sessionId: context.sessionId,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent
      }
    };
    
    // Создание состояния lease
    const state: LeaseState = {
      lease
    };
    
    // Сохранение lease
    this.leases.set(lease.leaseId, state);
    
    // Обновление индексов
    this.addToSubjectIndex(context.subjectId, lease.leaseId);
    this.addToSecretIndex(secretId, lease.leaseId);

    // Установка таймеров
    this.setupLeaseTimers(state);

    logger.info(`[SecretLease] Выдан lease ${lease.leaseId}`, {
      secretId,
      ttl: effectiveTTL
    });

    this.emit('lease:acquired', lease);

    return lease;
  }

  /**
   * Продлить lease
   * 
   * @param leaseId - ID lease
   * @param context - Контекст запроса
   * @param additionalTTL - Дополнительный TTL (опционально)
   * @returns Обновлённый lease
   */
  async renewLease(
    leaseId: string,
    context: AccessContext,
    additionalTTL?: number
  ): Promise<SecretLease> {
    const state = this.leases.get(leaseId);
    
    if (!state) {
      throw new SecretLeaseError(`Lease ${leaseId} не найден`);
    }
    
    const lease = state.lease;
    
    // Проверка владельца
    if (lease.leasedBy !== context.subjectId) {
      throw new SecretLeaseError(
        'Только владелец может продлить lease',
        lease.secretId
      );
    }
    
    // Проверка возможности продления
    if (!lease.renewable) {
      throw new SecretLeaseError(
        'Lease не поддерживает продление',
        lease.secretId
      );
    }
    
    // Проверка максимального количества продлений
    if (lease.renewCount >= this.defaultLeaseConfig.maxRenewals) {
      throw new SecretLeaseError(
        `Превышено максимальное количество продлений (${this.defaultLeaseConfig.maxRenewals})`,
        lease.secretId
      );
    }
    
    // Проверка истечения
    if (new Date() > lease.expiresAt) {
      throw new SecretLeaseError(
        'Lease уже истёк',
        lease.secretId
      );
    }
    
    // Вычисление нового времени истечения
    const extendTTL = additionalTTL ?? lease.maxTTL;
    const newExpiresAt = new Date(Date.now() + extendTTL * 1000);
    
    // Проверка максимального TTL
    const totalLifetime = newExpiresAt.getTime() - lease.leasedAt.getTime();
    const maxLifetime = this.defaultLeaseConfig.maxTTL * 1000;
    
    if (totalLifetime > maxLifetime) {
      throw new SecretLeaseError(
        'Превышен максимальный общий срок жизни lease',
        lease.secretId
      );
    }
    
    // Обновление lease
    const oldExpiresAt = lease.expiresAt;
    lease.expiresAt = newExpiresAt;
    lease.renewCount++;
    lease.status = 'renewed';

    // Перенастройка таймеров
    this.clearLeaseTimers(state);
    this.setupLeaseTimers(state);

    logger.info(`[SecretLease] Продлён lease ${leaseId}`, {
      newExpiresAt: newExpiresAt.toISOString()
    });

    this.emit('lease:renewed', {
      lease,
      oldExpiresAt,
      newExpiresAt
    });

    return lease;
  }

  /**
   * Отозвать lease
   * 
   * @param leaseId - ID lease
   * @param context - Контекст запроса
   * @param reason - Причина отзыва
   * @returns Успешность отзыва
   */
  async revokeLease(
    leaseId: string,
    context: AccessContext,
    reason?: string
  ): Promise<boolean> {
    const state = this.leases.get(leaseId);
    
    if (!state) {
      return false;
    }
    
    const lease = state.lease;
    
    // Проверка прав на отзыв
    const canRevoke =
      lease.leasedBy === context.subjectId ||
      context.roles.includes('admin') ||
      context.roles.includes('secret-manager');
    
    if (!canRevoke) {
      throw new SecretLeaseError(
        'Недостаточно прав для отзыва lease',
        lease.secretId
      );
    }
    
    return await this.revokeLeaseInternal(leaseId, reason ?? 'user_requested');
  }

  /**
   * Внутренний метод отзыва lease
   */
  private async revokeLeaseInternal(
    leaseId: string,
    reason: string
  ): Promise<boolean> {
    const state = this.leases.get(leaseId);
    
    if (!state) {
      return false;
    }
    
    const lease = state.lease;
    
    // Остановка таймеров
    this.clearLeaseTimers(state);
    
    // Обновление статуса
    lease.status = 'revoked';
    
    // Перемещение в историю
    this.revokedLeases.set(leaseId, lease);
    this.leases.delete(leaseId);

    // Обновление индексов
    this.removeFromSubjectIndex(lease.leasedBy, leaseId);
    this.removeFromSecretIndex(lease.secretId, leaseId);

    logger.info(`[SecretLease] Отозван lease ${leaseId}`, {
      reason
    });

    this.emit('lease:revoked', { lease, reason });

    return true;
  }

  /**
   * Получить lease по ID
   * 
   * @param leaseId - ID lease
   * @returns Lease или null
   */
  getLease(leaseId: string): SecretLease | null {
    const state = this.leases.get(leaseId);
    return state?.lease ?? null;
  }

  /**
   * Получить все активные lease субъекта
   * 
   * @param subjectId - ID субъекта
   * @returns Массив lease
   */
  getSubjectLeases(subjectId: string): SecretLease[] {
    const leaseIds = this.subjectLeases.get(subjectId);
    
    if (!leaseIds) {
      return [];
    }
    
    const leases: SecretLease[] = [];
    
    for (const leaseId of leaseIds) {
      const state = this.leases.get(leaseId);
      if (state) {
        leases.push(state.lease);
      }
    }
    
    return leases;
  }

  /**
   * Получить все активные lease для секрета
   * 
   * @param secretId - ID секрета
   * @returns Массив lease
   */
  getSecretLeases(secretId: string): SecretLease[] {
    const leaseIds = this.secretLeases.get(secretId);
    
    if (!leaseIds) {
      return [];
    }
    
    const leases: SecretLease[] = [];
    
    for (const leaseId of leaseIds) {
      const state = this.leases.get(leaseId);
      if (state) {
        leases.push(state.lease);
      }
    }
    
    return leases;
  }

  /**
   * Отозвать все lease субъекта
   * 
   * @param subjectId - ID субъекта
   * @param reason - Причина отзыва
   * @returns Количество отозванных lease
   */
  async revokeAllSubjectLeases(
    subjectId: string,
    reason: string
  ): Promise<number> {
    const leaseIds = this.subjectLeases.get(subjectId);
    
    if (!leaseIds) {
      return 0;
    }
    
    let revokedCount = 0;
    
    // Копируем множество, так как будем модифицировать во время итерации
    for (const leaseId of Array.from(leaseIds)) {
      const revoked = await this.revokeLeaseInternal(leaseId, reason);
      if (revoked) {
        revokedCount++;
      }
    }

    logger.info(`[SecretLease] Отозвано ${revokedCount} lease`, {
      subjectId,
      count: revokedCount,
      reason
    });

    this.emit('lease:bulk-revoked', {
      subjectId,
      count: revokedCount,
      reason
    });

    return revokedCount;
  }

  /**
   * Отозвать все lease для секрета
   * 
   * @param secretId - ID секрета
   * @param reason - Причина отзыва
   * @returns Количество отозванных lease
   */
  async revokeAllSecretLeases(
    secretId: string,
    reason: string
  ): Promise<number> {
    const leaseIds = this.secretLeases.get(secretId);
    
    if (!leaseIds) {
      return 0;
    }
    
    let revokedCount = 0;
    
    for (const leaseId of Array.from(leaseIds)) {
      const revoked = await this.revokeLeaseInternal(leaseId, reason);
      if (revoked) {
        revokedCount++;
      }
    }

    logger.info(`[SecretLease] Отозвано ${revokedCount} lease`, {
      secretId,
      count: revokedCount,
      reason
    });

    this.emit('lease:bulk-revoked', {
      secretId,
      count: revokedCount,
      reason
    });

    return revokedCount;
  }

  /**
   * Продлить lease автоматически (внутренний метод)
   */
  private async autoRenewLease(leaseId: string): Promise<void> {
    const state = this.leases.get(leaseId);
    
    if (!state || !state.lease.renewable) {
      return;
    }
    
    try {
      // Создаём фиктивный контекст для автоматического продления
      const context: AccessContext = {
        subjectId: state.lease.leasedBy,
        roles: [],
        attributes: {},
        ipAddress: 'system',
        timestamp: new Date(),
        mfaVerified: false
      };
      
      await this.renewLease(leaseId, context);

      logger.info(`[SecretLease] Автоматически продлён lease ${leaseId}`);
    } catch (error) {
      logger.error(`[SecretLease] Ошибка автоматического продления lease ${leaseId}`, { error });

      this.emit('lease:auto-renew-failed', {
        leaseId,
        error
      });
    }
  }

  /**
   * Настройка таймеров для lease
   */
  private setupLeaseTimers(state: LeaseState): void {
    const lease = state.lease;
    const now = Date.now();
    const expiresAt = lease.expiresAt.getTime();
    const timeToExpiry = expiresAt - now;
    
    // Таймер предупреждения об истечении
    const warningTime = this.config.expirationWarningTime * 1000;
    
    if (timeToExpiry > warningTime) {
      state.warningTimer = setTimeout(() => {
        this.emit('lease:expiring', {
          lease,
          timeRemaining: warningTime / 1000
        });
      }, timeToExpiry - warningTime);
      
      state.warningTimer.unref();
    }
    
    // Таймер автоматического продления
    if (this.config.enableAutoRenewal && lease.renewable) {
      const autoRenewTime = timeToExpiry - warningTime;
      
      if (autoRenewTime > 0) {
        state.autoRenewTimer = setTimeout(() => {
          void this.autoRenewLease(lease.leaseId);
        }, autoRenewTime);
        
        state.autoRenewTimer.unref();
      }
    }
    
    // Таймер истечения
    state.expirationTimer = setTimeout(() => {
      void this.handleLeaseExpiration(lease.leaseId);
    }, timeToExpiry);
    
    state.expirationTimer.unref();
  }

  /**
   * Обработка истечения lease
   */
  private async handleLeaseExpiration(leaseId: string): Promise<void> {
    const state = this.leases.get(leaseId);
    
    if (!state) {
      return;
    }
    
    const lease = state.lease;
    lease.status = 'expired';

    logger.info(`[SecretLease] Истёк lease ${leaseId}`);

    this.emit('lease:expired', lease);
    
    // Grace period перед окончательным удалением
    if (this.defaultLeaseConfig.gracePeriod > 0) {
      setTimeout(() => {
        void this.revokeLeaseInternal(leaseId, 'expired');
      }, this.defaultLeaseConfig.gracePeriod * 1000);
    } else {
      await this.revokeLeaseInternal(leaseId, 'expired');
    }
  }

  /**
   * Очистка таймеров lease
   */
  private clearLeaseTimers(state: LeaseState): void {
    if (state.expirationTimer) {
      clearTimeout(state.expirationTimer);
    }
    
    if (state.warningTimer) {
      clearTimeout(state.warningTimer);
    }
    
    if (state.autoRenewTimer) {
      clearTimeout(state.autoRenewTimer);
    }
  }

  /**
   * Запуск периодической проверки истёкших lease
   */
  private startExpirationCheck(): void {
    this.expirationCheckInterval = setInterval(() => {
      this.checkExpiredLeases();
    }, this.config.expirationCheckInterval * 1000);
    
    this.expirationCheckInterval.unref();
  }

  /**
   * Проверка истёкших lease
   */
  private checkExpiredLeases(): void {
    const now = Date.now();
    
    for (const [leaseId, state] of this.leases.entries()) {
      const expiresAt = state.lease.expiresAt.getTime();
      
      if (now > expiresAt) {
        void this.handleLeaseExpiration(leaseId);
      }
    }
  }

  /**
   * Добавление в индекс субъектов
   */
  private addToSubjectIndex(subjectId: string, leaseId: string): void {
    let leaseSet = this.subjectLeases.get(subjectId);
    
    if (!leaseSet) {
      leaseSet = new Set();
      this.subjectLeases.set(subjectId, leaseSet);
    }
    
    leaseSet.add(leaseId);
  }

  /**
   * Удаление из индекса субъектов
   */
  private removeFromSubjectIndex(subjectId: string, leaseId: string): void {
    const leaseSet = this.subjectLeases.get(subjectId);
    
    if (leaseSet) {
      leaseSet.delete(leaseId);
      
      if (leaseSet.size === 0) {
        this.subjectLeases.delete(subjectId);
      }
    }
  }

  /**
   * Добавление в индекс секретов
   */
  private addToSecretIndex(secretId: string, leaseId: string): void {
    let leaseSet = this.secretLeases.get(secretId);
    
    if (!leaseSet) {
      leaseSet = new Set();
      this.secretLeases.set(secretId, leaseSet);
    }
    
    leaseSet.add(leaseId);
  }

  /**
   * Удаление из индекса секретов
   */
  private removeFromSecretIndex(secretId: string, leaseId: string): void {
    const leaseSet = this.secretLeases.get(secretId);
    
    if (leaseSet) {
      leaseSet.delete(leaseId);
      
      if (leaseSet.size === 0) {
        this.secretLeases.delete(secretId);
      }
    }
  }

  /**
   * Получить статистику lease
   */
  getStats(): {
    activeLeases: number;
    revokedLeases: number;
    leasesBySubject: Map<string, number>;
    leasesBySecret: Map<string, number>;
    expiringSoon: number;
  } {
    const now = Date.now();
    const warningTime = this.config.expirationWarningTime * 1000;
    let expiringSoon = 0;
    
    const leasesBySubject = new Map<string, number>();
    const leasesBySecret = new Map<string, number>();
    
    for (const state of this.leases.values()) {
      const lease = state.lease;
      
      // Подсчёт по субъектам
      const subjectCount = leasesBySubject.get(lease.leasedBy) ?? 0;
      leasesBySubject.set(lease.leasedBy, subjectCount + 1);
      
      // Подсчёт по секретам
      const secretCount = leasesBySecret.get(lease.secretId) ?? 0;
      leasesBySecret.set(lease.secretId, secretCount + 1);
      
      // Проверка скорого истечения
      const timeToExpiry = lease.expiresAt.getTime() - now;
      if (timeToExpiry > 0 && timeToExpiry <= warningTime) {
        expiringSoon++;
      }
    }
    
    return {
      activeLeases: this.leases.size,
      revokedLeases: this.revokedLeases.size,
      leasesBySubject,
      leasesBySecret,
      expiringSoon
    };
  }

  /**
   * Получить историю отозванных lease
   * 
   * @param limit - Максимальное количество записей
   * @returns Массив отозванных lease
   */
  getRevokedLeasesHistory(limit = 100): SecretLease[] {
    return Array.from(this.revokedLeases.values())
      .sort((a, b) => b.leasedAt.getTime() - a.leasedAt.getTime())
      .slice(0, limit);
  }

  /**
   * Очистить историю отозванных lease
   */
  clearRevokedLeasesHistory(): void {
    this.revokedLeases.clear();
    logger.info('[SecretLease] Очищена история отозванных lease');
  }

  /**
   * Принудительно истечь lease (для тестирования)
   * 
   * @param leaseId - ID lease
   */
  forceExpire(leaseId: string): void {
    const state = this.leases.get(leaseId);
    
    if (state) {
      state.lease.expiresAt = new Date(Date.now() - 1000);
      void this.handleLeaseExpiration(leaseId);
    }
  }
}
