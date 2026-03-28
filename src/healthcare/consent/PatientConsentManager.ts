/**
 * ============================================================================
 * PATIENT CONSENT MANAGER — УПРАВЛЕНИЕ СОГЛАСИЯМИ ПАЦИЕНТОВ
 * ============================================================================
 *
 * HIPAA compliant система управления согласиями пациентов
 *
 * Функциональность:
 * - Создание и управление согласиями
 * - Проверка действительности согласий
 * - Emergency Break-Glass доступ
 * - Отзыв согласий
 * - Аудит всех операций
 *
 * @package protocol/healthcare-security/consent
 * @author Protocol Security Team
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../../logging/Logger';
import {
  PatientConsent,
  ConsentType,
  ConsentStatus,
  PHIAccessRequest,
  PHIAccessDecision,
  EmergencyAccess
} from '../types/healthcare.types';

/**
 * Patient Consent Manager Service
 */
export class PatientConsentManager extends EventEmitter {
  /** Хранилище согласий */
  private consents: Map<string, PatientConsent> = new Map();

  /** Emergency access запросы */
  private emergencyAccesses: Map<string, EmergencyAccess> = new Map();

  /** Индексы для быстрого поиска */
  private patientConsentIndex: Map<string, Set<string>> = new Map();

  /** Статус инициализации */
  private isInitialized = false;

  /** Конфигурация */
  private readonly config = {
    // Требуется ли явное согласие для исследований
    researchConsentRequired: true,

    // Разрешён ли emergency break-glass доступ
    emergencyAccessEnabled: true,

    // Максимальный срок действия согласия (дни)
    maxConsentDurationDays: 365,

    // Период проверки истёкших согласий (часы)
    expiredConsentCheckIntervalHours: 24,

    // Требуется ли повторная верификация для sensitive данных
    requireReverificationForSensitive: true
  };

  /** Sensitive типы согласий */
  private readonly sensitiveConsentTypes: ConsentType[] = [
    'PSYCHOTHERAPY_NOTES',
    'SUBSTANCE_ABUSE',
    'HIV_STATUS',
    'GENETIC_TESTING',
    'REPRODUCTIVE_HEALTH'
  ];

  /**
   * Создаёт новый экземпляр PatientConsentManager
   */
  constructor() {
    super();

    logger.info('[PatientConsent] Service created');
  }

  /**
   * Инициализация сервиса
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[PatientConsent] Already initialized');
      return;
    }

    try {
      // Загрузка сохранённых согласий (из БД в production)
      // await this.loadConsents();

      // Запуск периодической проверки истёкших согласий
      this.startExpiredConsentCheck();

      this.isInitialized = true;

      logger.info('[PatientConsent] Initialized successfully');

      this.emit('initialized');

    } catch (error) {
      logger.error('[PatientConsent] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Создание нового согласия
   *
   * @param consentData - Данные согласия
   * @returns Созданное согласие
   */
  public async createConsent(consentData: {
    patientId: string;
    consentType: ConsentType;
    grantedTo: string[];
    validFrom: Date;
    validUntil?: Date;
    restrictions?: PatientConsent['restrictions'];
    purpose?: string[];
    createdBy: string;
  }): Promise<PatientConsent> {
    if (!this.isInitialized) {
      throw new Error('PatientConsent not initialized');
    }

    const consentId = `consent-${uuidv4()}`;
    const now = new Date();

    // Валидация срока действия
    if (consentData.validUntil) {
      const maxValidUntil = new Date(
        consentData.validFrom.getTime() + this.config.maxConsentDurationDays * 24 * 60 * 60 * 1000
      );

      if (consentData.validUntil > maxValidUntil) {
        throw new Error(
          `Consent duration cannot exceed ${this.config.maxConsentDurationDays} days`
        );
      }
    }

    // Проверка на sensitive данные
    if (
      this.config.requireReverificationForSensitive &&
      this.sensitiveConsentTypes.includes(consentData.consentType)
    ) {
      logger.info('[PatientConsent] Sensitive consent created, reverification required', {
        consentType: consentData.consentType
      });
    }

    // Создание согласия
    const consent: PatientConsent = {
      consentId,
      patientId: consentData.patientId,
      consentType: consentData.consentType,
      status: 'ACTIVE',
      grantedTo: consentData.grantedTo,
      validFrom: consentData.validFrom,
      validUntil: consentData.validUntil,
      restrictions: consentData.restrictions,
      purpose: consentData.purpose,
      createdAt: now,
      updatedAt: now,
      createdBy: consentData.createdBy,
      metadata: {
        version: 1,
        ipAddress: '0.0.0.0', // В production реальный IP
        userAgent: 'unknown' // В production реальный User-Agent
      }
    };

    // Сохранение
    this.consents.set(consentId, consent);

    // Обновление индекса
    if (!this.patientConsentIndex.has(consentData.patientId)) {
      this.patientConsentIndex.set(consentData.patientId, new Set());
    }

    this.patientConsentIndex.get(consentData.patientId)!.add(consentId);

    logger.info('[PatientConsent] Consent created', {
      consentId,
      patientId: consentData.patientId,
      consentType: consentData.consentType,
      validUntil: consentData.validUntil
    });

    this.emit('consent_created', consent);

    return consent;
  }

  /**
   * Проверка действительности согласия
   *
   * @param request - Запрос на доступ
   * @returns Решение о доступе
   */
  public async verifyConsent(request: {
    patientId: string;
    requestedBy: string;
    purpose: 'TREATMENT' | 'PAYMENT' | 'OPERATIONS' | 'RESEARCH' | 'OTHER';
    resourceType?: string;
    consentType?: ConsentType;
  }): Promise<PHIAccessDecision> {
    if (!this.isInitialized) {
      throw new Error('PatientConsent not initialized');
    }

    const patientConsents = this.getPatientConsents(request.patientId);

    if (patientConsents.length === 0) {
      return {
        allowed: false,
        reason: 'No consents found for patient',
        requiredActions: ['Obtain patient consent before accessing PHI']
      };
    }

    // Поиск подходящего согласия
    const now = new Date();
    let matchingConsent: PatientConsent | null = null;

    for (const consent of patientConsents) {
      // Проверка статуса
      if (consent.status !== 'ACTIVE') {
        continue;
      }

      // Проверка срока действия
      if (consent.validUntil && consent.validUntil < now) {
        continue;
      }

      // Проверка validFrom
      if (consent.validFrom > now) {
        continue;
      }

      // Проверка типа согласия
      if (request.consentType && consent.consentType !== request.consentType) {
        continue;
      }

      // Проверка grantedTo
      if (!consent.grantedTo.includes(request.requestedBy)) {
        continue;
      }

      // Проверка purpose
      if (consent.purpose && !consent.purpose.includes(request.purpose)) {
        continue;
      }

      // Проверка ограничений
      if (consent.restrictions) {
        if (request.resourceType === 'PsychotherapyNotes' && consent.restrictions.mentalHealth) {
          continue;
        }

        if (request.resourceType === 'SubstanceAbuseRecords' && consent.restrictions.substanceAbuse) {
          continue;
        }

        if (request.resourceType === 'HIVRecords' && consent.restrictions.hivStatus) {
          continue;
        }
      }

      matchingConsent = consent;
      break;
    }

    if (!matchingConsent) {
      return {
        allowed: false,
        reason: 'No valid consent found for the requested access',
        requiredActions: ['Obtain appropriate patient consent']
      };
    }

    // Доступ разрешён
    const decision: PHIAccessDecision = {
      allowed: true,
      reason: `Valid consent found: ${matchingConsent.consentId}`,
      restrictions: {
        viewOnly: false,
        noDownload: false,
        noPrint: false,
        auditRequired: true
      }
    };

    // Логирование доступа
    this.emit('consent_verified', {
      consentId: matchingConsent.consentId,
      patientId: request.patientId,
      requestedBy: request.requestedBy,
      timestamp: new Date()
    });

    return decision;
  }

  /**
   * Отзыв согласия
   *
   * @param consentId - ID согласия
   * @param reason - Причина отзыва
   * @param revokedBy - Кто отозвал
   * @returns Результат
   */
  public async revokeConsent(
    consentId: string,
    reason: string,
    revokedBy: string
  ): Promise<boolean> {
    if (!this.isInitialized) {
      throw new Error('PatientConsent not initialized');
    }

    const consent = this.consents.get(consentId);

    if (!consent) {
      throw new Error(`Consent not found: ${consentId}`);
    }

    if (consent.status === 'REVOKED') {
      throw new Error('Consent already revoked');
    }

    // Обновление статуса
    consent.status = 'REVOKED';
    consent.updatedAt = new Date();

    // Добавление метаданных отзыва
    if (!consent.metadata) {
      consent.metadata = {};
    }

    consent.metadata.revokedAt = new Date().toISOString();
    consent.metadata.revokedBy = revokedBy;
    consent.metadata.revocationReason = reason;

    this.consents.set(consentId, consent);

    logger.info('[PatientConsent] Consent revoked', {
      consentId,
      reason,
      revokedBy
    });

    this.emit('consent_revoked', {
      consentId,
      patientId: consent.patientId,
      reason,
      revokedBy,
      timestamp: new Date()
    });

    return true;
  }

  /**
   * Запрос emergency break-glass доступа
   *
   * @param requestData - Данные запроса
   * @returns Emergency access
   */
  public async requestEmergencyAccess(requestData: {
    patientId: string;
    requestedBy: string;
    justification: string;
    severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  }): Promise<EmergencyAccess> {
    if (!this.config.emergencyAccessEnabled) {
      throw new Error('Emergency access is disabled');
    }

    if (!this.isInitialized) {
      throw new Error('PatientConsent not initialized');
    }

    const accessId = `emergency-${uuidv4()}`;
    const now = new Date();

    const emergencyAccess: EmergencyAccess = {
      accessId,
      patientId: requestData.patientId,
      requestedBy: requestData.requestedBy,
      justification: requestData.justification,
      status: 'APPROVED', // Автоматическое одобрение для emergency
      requestedAt: now,
      approvedAt: now,
      approvedBy: 'SYSTEM_AUTO_APPROVE',
      expiresAt: new Date(now.getTime() + 24 * 60 * 60 * 1000), // 24 часа
      review: {
        conducted: false
      }
    };

    this.emergencyAccesses.set(accessId, emergencyAccess);

    logger.warn('[PatientConsent] Emergency access granted', {
      accessId,
      patientId: requestData.patientId,
      requestedBy: requestData.requestedBy,
      justification: requestData.justification
    });

    this.emit('emergency_access_granted', emergencyAccess);

    // Уведомление о необходимости post-incident review
    this.schedulePostIncidentReview(emergencyAccess);

    return emergencyAccess;
  }

  /**
   * Получение согласий пациента
   */
  public getPatientConsents(patientId: string): PatientConsent[] {
    const consentIds = this.patientConsentIndex.get(patientId);

    if (!consentIds) {
      return [];
    }

    const consents: PatientConsent[] = [];

    for (const consentId of consentIds) {
      const consent = this.consents.get(consentId);

      if (consent) {
        consents.push(consent);
      }
    }

    return consents.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Получение активного согласия
   */
  public getActiveConsent(
    patientId: string,
    consentType?: ConsentType
  ): PatientConsent | undefined {
    const consents = this.getPatientConsents(patientId);
    const now = new Date();

    return consents.find(consent => {
      if (consent.status !== 'ACTIVE') return false;
      if (consent.validUntil && consent.validUntil < now) return false;
      if (consent.validFrom && consent.validFrom > now) return false;
      if (consentType && consent.consentType !== consentType) return false;

      return true;
    });
  }

  /**
   * Получение истёкших согласий
   */
  public getExpiredConsents(): PatientConsent[] {
    const now = new Date();
    const expired: PatientConsent[] = [];

    for (const consent of this.consents.values()) {
      if (
        consent.status === 'ACTIVE' &&
        consent.validUntil &&
        consent.validUntil < now
      ) {
        expired.push(consent);
      }
    }

    return expired;
  }

  /**
   * Продление согласия
   */
  public async renewConsent(
    consentId: string,
    validUntil: Date,
    renewedBy: string
  ): Promise<PatientConsent> {
    const consent = this.consents.get(consentId);

    if (!consent) {
      throw new Error(`Consent not found: ${consentId}`);
    }

    if (consent.status === 'REVOKED' || consent.status === 'EXPIRED') {
      throw new Error('Cannot renew revoked or expired consent');
    }

    consent.validUntil = validUntil;
    consent.updatedAt = new Date();

    if (!consent.metadata) {
      consent.metadata = {};
    }

    consent.metadata.renewedAt = new Date().toISOString();
    consent.metadata.renewedBy = renewedBy;
    consent.metadata.version = (consent.metadata.version || 1) + 1;

    this.consents.set(consentId, consent);

    logger.info('[PatientConsent] Consent renewed', {
      consentId,
      validUntil
    });

    this.emit('consent_renewed', consent);

    return consent;
  }

  /**
   * Приостановка согласия
   */
  public async suspendConsent(
    consentId: string,
    reason: string,
    suspendedBy: string
  ): Promise<PatientConsent> {
    const consent = this.consents.get(consentId);

    if (!consent) {
      throw new Error(`Consent not found: ${consentId}`);
    }

    consent.status = 'SUSPENDED';
    consent.updatedAt = new Date();

    if (!consent.metadata) {
      consent.metadata = {};
    }

    consent.metadata.suspendedAt = new Date().toISOString();
    consent.metadata.suspendedBy = suspendedBy;
    consent.metadata.suspensionReason = reason;

    this.consents.set(consentId, consent);

    logger.warn('[PatientConsent] Consent suspended', {
      consentId,
      reason
    });

    this.emit('consent_suspended', consent);

    return consent;
  }

  /**
   * Восстановление согласия после приостановки
   */
  public async reactivateConsent(
    consentId: string,
    reactivatedBy: string
  ): Promise<PatientConsent> {
    const consent = this.consents.get(consentId);

    if (!consent) {
      throw new Error(`Consent not found: ${consentId}`);
    }

    if (consent.status !== 'SUSPENDED') {
      throw new Error('Consent is not suspended');
    }

    consent.status = 'ACTIVE';
    consent.updatedAt = new Date();

    if (!consent.metadata) {
      consent.metadata = {};
    }

    consent.metadata.reactivatedAt = new Date().toISOString();
    consent.metadata.reactivatedBy = reactivatedBy;

    this.consents.set(consentId, consent);

    logger.info('[PatientConsent] Consent reactivated', { consentId });

    this.emit('consent_reactivated', consent);

    return consent;
  }

  /**
   * Получение emergency access по ID
   */
  public getEmergencyAccess(accessId: string): EmergencyAccess | undefined {
    return this.emergencyAccesses.get(accessId);
  }

  /**
   * Получение всех активных emergency access
   */
  public getActiveEmergencyAccesses(): EmergencyAccess[] {
    const now = new Date();

    return Array.from(this.emergencyAccesses.values()).filter(
      access => access.status === 'APPROVED' && access.expiresAt > now
    );
  }

  /**
   * Закрытие emergency access
   */
  public async closeEmergencyAccess(
    accessId: string,
    closedBy: string
  ): Promise<void> {
    const access = this.emergencyAccesses.get(accessId);

    if (!access) {
      throw new Error(`Emergency access not found: ${accessId}`);
    }

    access.status = 'EXPIRED';
    access.closedAt = new Date();

    logger.info('[PatientConsent] Emergency access closed', {
      accessId,
      closedBy
    });

    this.emit('emergency_access_closed', access);
  }

  /**
   * Проведение post-incident review
   */
  public async conductPostIncidentReview(
    accessId: string,
    reviewData: {
      conductedBy: string;
      findings?: string;
      actions?: string[];
    }
  ): Promise<void> {
    const access = this.emergencyAccesses.get(accessId);

    if (!access) {
      throw new Error(`Emergency access not found: ${accessId}`);
    }

    access.review = {
      conducted: true,
      conductedAt: new Date(),
      conductedBy: reviewData.conductedBy,
      findings: reviewData.findings,
      actions: reviewData.actions
    };

    logger.info('[PatientConsent] Post-incident review conducted', {
      accessId,
      findings: reviewData.findings
    });

    this.emit('emergency_access_reviewed', access);
  }

  /**
   * Статистика согласий
   */
  public getStatistics(): {
    totalConsents: number;
    activeConsents: number;
    expiredConsents: number;
    revokedConsents: number;
    suspendedConsents: number;
    emergencyAccessesActive: number;
    consentsByType: Map<ConsentType, number>;
  } {
    const stats = {
      totalConsents: this.consents.size,
      activeConsents: 0,
      expiredConsents: 0,
      revokedConsents: 0,
      suspendedConsents: 0,
      emergencyAccessesActive: this.getActiveEmergencyAccesses().length,
      consentsByType: new Map<ConsentType, number>()
    };

    const now = new Date();

    for (const consent of this.consents.values()) {
      // По статусу
      if (consent.status === 'ACTIVE') {
        if (consent.validUntil && consent.validUntil < now) {
          stats.expiredConsents++;
        } else {
          stats.activeConsents++;
        }
      } else if (consent.status === 'REVOKED') {
        stats.revokedConsents++;
      } else if (consent.status === 'SUSPENDED') {
        stats.suspendedConsents++;
      }

      // По типу
      const count = stats.consentsByType.get(consent.consentType) || 0;
      stats.consentsByType.set(consent.consentType, count + 1);
    }

    return stats;
  }

  /**
   * Запуск периодической проверки истёкших согласий
   */
  private startExpiredConsentCheck(): void {
    const checkInterval = this.config.expiredConsentCheckIntervalHours * 60 * 60 * 1000;

    setInterval(() => {
      const expiredConsents = this.getExpiredConsents();

      for (const consent of expiredConsents) {
        consent.status = 'EXPIRED';
        this.consents.set(consent.consentId, consent);

        logger.info('[PatientConsent] Consent expired', {
          consentId: consent.consentId,
          patientId: consent.patientId
        });

        this.emit('consent_expired', consent);
      }

      if (expiredConsents.length > 0) {
        logger.debug('[PatientConsent] Expired consent check completed', {
          expiredCount: expiredConsents.length
        });
      }
    }, checkInterval);
  }

  /**
   * Планирование post-incident review
   */
  private schedulePostIncidentReview(emergencyAccess: EmergencyAccess): void {
    // Review должен быть проведён в течение 7 дней
    const reviewDeadline = 7 * 24 * 60 * 60 * 1000;

    setTimeout(() => {
      const access = this.emergencyAccesses.get(emergencyAccess.accessId);

      if (access && !access.review?.conducted) {
        logger.warn('[PatientConsent] Post-incident review overdue', {
          accessId: emergencyAccess.accessId,
          patientId: emergencyAccess.patientId
        });

        this.emit('emergency_access_review_overdue', access);
      }
    }, reviewDeadline);
  }

  /**
   * Остановка сервиса
   */
  public async destroy(): Promise<void> {
    logger.info('[PatientConsent] Shutting down...');

    this.consents.clear();
    this.emergencyAccesses.clear();
    this.patientConsentIndex.clear();
    this.isInitialized = false;

    logger.info('[PatientConsent] Destroyed');

    this.emit('destroyed');
  }

  /**
   * Проверка инициализации
   */
  public checkInitialized(): boolean {
    return this.isInitialized;
  }
}
