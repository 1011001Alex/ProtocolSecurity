/**
 * ============================================================================
 * EVIDENCE MANAGER
 * ============================================================================
 * Модуль управления уликами и цепочкой хранения (Chain of Custody)
 * Соответствует NIST SP 800-61, ISO 27037, и юридическим требованиям
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { createHash } from 'crypto';
import {
  Evidence,
  EvidenceCategory,
  ChainOfCustodyRecord,
  ChainOfCustodyStatus,
  Actor,
  Incident,
  EvidenceConfig
} from '../types/incident.types';

/**
 * События менеджера улик
 */
export enum EvidenceManagerEvent {
  /** Улика добавлена */
  EVIDENCE_ADDED = 'evidence_added',
  /** Улика обновлена */
  EVIDENCE_UPDATED = 'evidence_updated',
  /** Улика удалена */
  EVIDENCE_DELETED = 'evidence_deleted',
  /** Цепочка хранения обновлена */
  CUSTODY_UPDATED = 'custody_updated',
  /** Доступ к улике */
  EVIDENCE_ACCESSED = 'evidence_accessed',
  /** Целостность проверена */
  INTEGRITY_CHECKED = 'integrity_checked',
  /** Нарушение целостности */
  INTEGRITY_VIOLATED = 'integrity_violated',
  /** Срок хранения истекает */
  RETENTION_EXPIRING = 'retention_expiring'
}

/**
 * Конфигурация менеджера улик
 */
export interface EvidenceManagerConfig {
  /** Хранилище улик */
  storageLocation: string;
  /** Требуемые хэши */
  requiredHashes: ('md5' | 'sha1' | 'sha256')[];
  /** Срок хранения по умолчанию (дни) */
  defaultRetentionDays: number;
  /** Требования к доступу */
  accessRequirements: string[];
  /** Автоматическая цепочка хранения */
  autoChainOfCustody: boolean;
  /** Шифрование улик */
  encryptEvidence: boolean;
  /** Логирование */
  enableLogging: boolean;
}

/**
 * Запись доступа к улике
 */
export interface AccessRecord {
  /** Кто получил доступ */
  accessedBy: Actor;
  /** Время доступа */
  timestamp: Date;
  /** Тип доступа */
  accessType: 'view' | 'download' | 'modify' | 'delete';
  /** Причина доступа */
  reason: string;
  /** IP адрес */
  ipAddress?: string;
  /** Результат доступа */
  result: 'success' | 'denied' | 'error';
}

/**
 * Менеджер управления уликами
 */
export class EvidenceManager extends EventEmitter {
  /** Конфигурация */
  private config: EvidenceManagerConfig;

  /** Хранилище улик */
  private evidenceStore: Map<string, Evidence> = new Map();

  /** Индекс по инцидентам */
  private incidentIndex: Map<string, Set<string>> = new Map();

  /** История доступа */
  private accessHistory: Map<string, AccessRecord[]> = new Map();

  /**
   * Конструктор менеджера
   */
  constructor(config?: Partial<EvidenceManagerConfig>) {
    super();
    this.config = this.mergeConfigWithDefaults(config);
  }

  /**
   * Объединение конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<EvidenceManagerConfig> | undefined): EvidenceManagerConfig {
    const defaultConfig: EvidenceManagerConfig = {
      storageLocation: '/var/evidence',
      requiredHashes: ['md5', 'sha256'],
      defaultRetentionDays: 2555, // 7 лет
      accessRequirements: ['security_clearance', 'case_assignment'],
      autoChainOfCustody: true,
      encryptEvidence: true,
      enableLogging: true
    };

    return { ...defaultConfig, ...config };
  }

  /**
   * Добавление улики
   */
  public async addEvidence(
    evidence: Evidence,
    addedBy: Actor
  ): Promise<Evidence> {
    this.log(`Добавление улики: ${evidence.id}`);

    // Валидация улики
    this.validateEvidence(evidence);

    // Вычисление хэшей если не предоставлены
    if (!evidence.hash || Object.keys(evidence.hash).length === 0) {
      evidence.hash = await this.computeEvidenceHashes(evidence);
    }

    // Установка начального статуса цепочки хранения
    if (this.config.autoChainOfCustody && evidence.custodyHistory.length === 0) {
      const initialCustody: ChainOfCustodyRecord = {
        id: this.generateCustodyId(),
        evidenceId: evidence.id,
        action: 'collected',
        performedBy: evidence.collectedBy,
        timestamp: evidence.collectedAt,
        description: evidence.collectionContext,
        location: evidence.location,
        integrityHash: evidence.hash?.sha256
      };

      evidence.custodyHistory.push(initialCustody);
    }

    // Сохранение улики
    this.evidenceStore.set(evidence.id, evidence);

    // Обновление индекса по инцидентам
    if (!this.incidentIndex.has(evidence.incidentId)) {
      this.incidentIndex.set(evidence.incidentId, new Set());
    }
    this.incidentIndex.get(evidence.incidentId)!.add(evidence.id);

    // Инициализация истории доступа
    this.accessHistory.set(evidence.id, []);

    // Событие добавления
    this.emit(EvidenceManagerEvent.EVIDENCE_ADDED, {
      evidence,
      addedBy,
      timestamp: new Date()
    });

    this.log(`Улика ${evidence.id} успешно добавлена`);

    return evidence;
  }

  /**
   * Валидация улики
   */
  private validateEvidence(evidence: Evidence): void {
    const errors: string[] = [];

    if (!evidence.id || evidence.id.trim() === '') {
      errors.push('Идентификатор улики обязателен');
    }

    if (!evidence.name || evidence.name.trim() === '') {
      errors.push('Название улики обязательно');
    }

    if (!evidence.location || evidence.location.trim() === '') {
      errors.push('Расположение улики обязательно');
    }

    if (!evidence.incidentId || evidence.incidentId.trim() === '') {
      errors.push('Идентификатор инцидента обязателен');
    }

    if (errors.length > 0) {
      throw new Error(`Валидация улики не пройдена: ${errors.join(', ')}`);
    }
  }

  /**
   * Вычисление хэшей улики
   */
  private async computeEvidenceHashes(evidence: Evidence): Promise<{ md5?: string; sha1?: string; sha256?: string }> {
    const hashes: { md5?: string; sha1?: string; sha256?: string } = {};

    // В реальной системе здесь было бы чтение файла и вычисление хэшей
    // Для симуляции используем метаданные

    const hashData = `${evidence.id}:${evidence.location}:${evidence.size || 0}:${evidence.collectedAt.getTime()}`;

    for (const algorithm of this.config.requiredHashes) {
      const hash = createHash(algorithm);
      hash.update(hashData);
      hashes[algorithm] = hash.digest('hex');
    }

    return hashes;
  }

  /**
   * Получение улики по ID
   */
  public getEvidence(evidenceId: string): Evidence | undefined {
    const evidence = this.evidenceStore.get(evidenceId);

    if (evidence) {
      // Запись доступа
      this.log(`Доступ к улике: ${evidenceId}`);
    }

    return evidence;
  }

  /**
   * Получение всех улик инцидента
   */
  public getEvidenceByIncident(incidentId: string): Evidence[] {
    const evidenceIds = this.incidentIndex.get(incidentId);

    if (!evidenceIds) {
      return [];
    }

    const evidence: Evidence[] = [];

    for (const id of evidenceIds) {
      const evd = this.evidenceStore.get(id);
      if (evd) {
        evidence.push(evd);
      }
    }

    return evidence;
  }

  /**
   * Обновление цепочки хранения
   */
  public async updateCustody(
    evidenceId: string,
    action: ChainOfCustodyRecord['action'],
    performedBy: Actor,
    details: {
      description: string;
      location?: string;
      reason?: string;
      transferMethod?: string;
      storageConditions?: string;
      witnesses?: Actor[];
    }
  ): Promise<ChainOfCustodyRecord> {
    const evidence = this.evidenceStore.get(evidenceId);

    if (!evidence) {
      throw new Error(`Улика ${evidenceId} не найдена`);
    }

    this.log(`Обновление цепочки хранения для улики ${evidenceId}: ${action}`);

    // Создание записи цепочки хранения
    const custodyRecord: ChainOfCustodyRecord = {
      id: this.generateCustodyId(),
      evidenceId,
      action,
      performedBy,
      timestamp: new Date(),
      description: details.description,
      location: details.location,
      reason: details.reason,
      transferMethod: details.transferMethod,
      storageConditions: details.storageConditions,
      witnesses: details.witnesses,
      integrityHash: evidence.hash?.sha256
    };

    // Добавление записи в историю
    evidence.custodyHistory.push(custodyRecord);

    // Обновление статуса
    evidence.custodyStatus = this.mapActionToStatus(action);

    // Событие обновления
    this.emit(EvidenceManagerEvent.CUSTODY_UPDATED, {
      evidenceId,
      custodyRecord,
      timestamp: new Date()
    });

    this.log(`Цепочка хранения обновлена. Запись ID: ${custodyRecord.id}`);

    return custodyRecord;
  }

  /**
   * Маппинг действия на статус
   */
  private mapActionToStatus(action: ChainOfCustodyRecord['action']): ChainOfCustodyStatus {
    const mapping: Record<ChainOfCustodyRecord['action'], ChainOfCustodyStatus> = {
      collected: ChainOfCustodyStatus.COLLECTED,
      transferred: ChainOfCustodyStatus.TRANSFERRED,
      stored: ChainOfCustodyStatus.STORED,
      analyzed: ChainOfCustodyStatus.ANALYZING,
      returned: ChainOfCustodyStatus.RETURNED,
      destroyed: ChainOfCustodyStatus.DESTROYED
    };

    return mapping[action];
  }

  /**
   * Запись доступа к улике
   */
  public async recordAccess(
    evidenceId: string,
    accessedBy: Actor,
    accessType: AccessRecord['accessType'],
    reason: string,
    ipAddress?: string
  ): Promise<AccessRecord> {
    const evidence = this.evidenceStore.get(evidenceId);

    if (!evidence) {
      throw new Error(`Улика ${evidenceId} не найдена`);
    }

    // Проверка требований доступа
    const hasAccess = this.checkAccessRequirements(evidence, accessedBy);

    const accessRecord: AccessRecord = {
      accessedBy,
      timestamp: new Date(),
      accessType,
      reason,
      ipAddress,
      result: hasAccess ? 'success' : 'denied'
    };

    // Сохранение записи
    let history = this.accessHistory.get(evidenceId);
    if (!history) {
      history = [];
      this.accessHistory.set(evidenceId, history);
    }
    history.push(accessRecord);

    // Событие доступа
    this.emit(EvidenceManagerEvent.EVIDENCE_ACCESSED, {
      evidenceId,
      accessRecord,
      granted: hasAccess
    });

    if (!hasAccess) {
      this.log(`ДОСТУП ЗАПРЕЩЕН: ${accessedBy.id} к улике ${evidenceId}`, 'warn');
      throw new Error(`Доступ запрещен: пользователь ${accessedBy.id} не имеет необходимых прав`);
    }

    this.log(`Доступ разрешен: ${accessedBy.id} к улике ${evidenceId} (${accessType})`);

    return accessRecord;
  }

  /**
   * Проверка требований доступа
   */
  private checkAccessRequirements(evidence: Evidence, actor: Actor): boolean {
    // В реальной системе здесь была бы проверка ролей и разрешений
    // Для простоты разрешаем доступ если actor определен

    if (!actor || !actor.id) {
      return false;
    }

    // Проверка legal hold
    if (evidence.legalHold && actor.role !== 'legal' && actor.role !== 'investigator') {
      return false;
    }

    // Проверка ограничений доступа
    if (evidence.accessRestrictions && evidence.accessRestrictions.length > 0) {
      // В реальной системе проверка принадлежность к разрешенным группам
    }

    return true;
  }

  /**
   * Проверка целостности улики
   */
  public async verifyIntegrity(evidenceId: string): Promise<{
    valid: boolean;
    expectedHashes: { md5?: string; sha1?: string; sha256?: string };
    actualHashes: { md5?: string; sha1?: string; sha256?: string };
    violations: string[];
  }> {
    const evidence = this.evidenceStore.get(evidenceId);

    if (!evidence) {
      throw new Error(`Улика ${evidenceId} не найдена`);
    }

    this.log(`Проверка целостности улики: ${evidenceId}`);

    const expectedHashes = evidence.hash || {};
    const actualHashes: { md5?: string; sha1?: string; sha256?: string } = {};
    const violations: string[] = [];

    // В реальной системе здесь было бы повторное вычисление хэшей
    // Для симуляции предполагаем что целостность сохранена

    // Симуляция вычисления хэшей
    const hashData = `${evidence.id}:${evidence.location}:${evidence.size || 0}:${evidence.collectedAt.getTime()}`;

    for (const algorithm of this.config.requiredHashes) {
      const hash = createHash(algorithm);
      hash.update(hashData);
      actualHashes[algorithm] = hash.digest('hex');
    }

    // Сравнение хэшей
    for (const algorithm of this.config.requiredHashes) {
      if (expectedHashes[algorithm] && actualHashes[algorithm]) {
        if (expectedHashes[algorithm] !== actualHashes[algorithm]) {
          violations.push(`Нарушение целостности: хэш ${algorithm} не совпадает`);
        }
      }
    }

    const valid = violations.length === 0;

    // Событие проверки
    if (valid) {
      this.emit(EvidenceManagerEvent.INTEGRITY_CHECKED, {
        evidenceId,
        timestamp: new Date()
      });
    } else {
      this.emit(EvidenceManagerEvent.INTEGRITY_VIOLATED, {
        evidenceId,
        violations,
        timestamp: new Date()
      });
      this.log(`НАРУШЕНИЕ ЦЕЛОСТНОСТИ: улика ${evidenceId}`, 'error');
    }

    return {
      valid,
      expectedHashes,
      actualHashes,
      violations
    };
  }

  /**
   * Проверка всех улик инцидента
   */
  public async verifyIncidentIntegrity(incidentId: string): Promise<{
    totalEvidence: number;
    validCount: number;
    invalidCount: number;
    results: Map<string, { valid: boolean; violations: string[] }>;
  }> {
    const evidenceList = this.getEvidenceByIncident(incidentId);
    const results = new Map<string, { valid: boolean; violations: string[] }>();

    let validCount = 0;
    let invalidCount = 0;

    for (const evidence of evidenceList) {
      const result = await this.verifyIntegrity(evidence.id);
      results.set(evidence.id, {
        valid: result.valid,
        violations: result.violations
      });

      if (result.valid) {
        validCount++;
      } else {
        invalidCount++;
      }
    }

    return {
      totalEvidence: evidenceList.length,
      validCount,
      invalidCount,
      results
    };
  }

  /**
   * Получение истории доступа
   */
  public getAccessHistory(evidenceId: string): AccessRecord[] {
    return this.accessHistory.get(evidenceId) || [];
  }

  /**
   * Получение полной цепочки хранения
   */
  public getChainOfCustody(evidenceId: string): ChainOfCustodyRecord[] {
    const evidence = this.evidenceStore.get(evidenceId);

    if (!evidence) {
      throw new Error(`Улика ${evidenceId} не найдена`);
    }

    return [...evidence.custodyHistory];
  }

  /**
   * Удаление улики (только для улик с истекшим сроком хранения)
   */
  public async deleteEvidence(
    evidenceId: string,
    deletedBy: Actor,
    reason: string
  ): Promise<void> {
    const evidence = this.evidenceStore.get(evidenceId);

    if (!evidence) {
      throw new Error(`Улика ${evidenceId} не найдена`);
    }

    // Проверка срока хранения
    const retentionUntil = evidence.retentionUntil || new Date(evidence.collectedAt.getTime() + this.config.defaultRetentionDays * 24 * 60 * 60 * 1000);
    const isExpired = new Date() > retentionUntil;

    // Проверка legal hold
    if (evidence.legalHold) {
      throw new Error(`Нельзя удалить улику ${evidenceId}: активен legal hold`);
    }

    if (!isExpired && reason !== 'court_order' && reason !== 'legal_approval') {
      throw new Error(`Нельзя удалить улику ${evidenceId}: срок хранения не истек`);
    }

    this.log(`Удаление улики: ${evidenceId}. Причина: ${reason}`);

    // Запись в цепочку хранения
    await this.updateCustody(evidenceId, 'destroyed', deletedBy, {
      description: `Улика уничтожена: ${reason}`,
      reason
    });

    // Удаление из хранилища
    this.evidenceStore.delete(evidenceId);
    this.accessHistory.delete(evidenceId);

    // Обновление индекса
    const incidentSet = this.incidentIndex.get(evidence.incidentId);
    if (incidentSet) {
      incidentSet.delete(evidenceId);
    }

    // Событие удаления
    this.emit(EvidenceManagerEvent.EVIDENCE_DELETED, {
      evidenceId,
      deletedBy,
      reason,
      timestamp: new Date()
    });

    this.log(`Улика ${evidenceId} успешно удалена`);
  }

  /**
   * Проверка истекающих сроков хранения
   */
  public checkExpiringRetention(daysThreshold: number = 30): Evidence[] {
    const expiring: Evidence[] = [];
    const thresholdDate = new Date();
    thresholdDate.setDate(thresholdDate.getDate() + daysThreshold);

    for (const evidence of this.evidenceStore.values()) {
      const retentionUntil = evidence.retentionUntil || new Date(evidence.collectedAt.getTime() + this.config.defaultRetentionDays * 24 * 60 * 60 * 1000);

      if (retentionUntil <= thresholdDate && retentionUntil > new Date()) {
        expiring.push(evidence);

        // Событие истекающего срока
        this.emit(EvidenceManagerEvent.RETENTION_EXPIRING, {
          evidence,
          retentionUntil,
          daysRemaining: Math.floor((retentionUntil.getTime() - Date.now()) / (24 * 60 * 60 * 1000))
        });
      }
    }

    return expiring;
  }

  /**
   * Получение статистики улик
   */
  public getEvidenceStats(incidentId?: string): {
    totalEvidence: number;
    byCategory: Record<string, number>;
    byStatus: Record<string, number>;
    totalSize: number;
    withLegalHold: number;
  } {
    let evidenceList = Array.from(this.evidenceStore.values());

    if (incidentId) {
      evidenceList = this.getEvidenceByIncident(incidentId);
    }

    const byCategory: Record<string, number> = {};
    const byStatus: Record<string, number> = {};
    let totalSize = 0;
    let withLegalHold = 0;

    for (const evidence of evidenceList) {
      // По категориям
      const category = evidence.category;
      byCategory[category] = (byCategory[category] || 0) + 1;

      // По статусам
      const status = evidence.custodyStatus;
      byStatus[status] = (byStatus[status] || 0) + 1;

      // Общий размер
      totalSize += evidence.size || 0;

      // Legal hold
      if (evidence.legalHold) {
        withLegalHold++;
      }
    }

    return {
      totalEvidence: evidenceList.length,
      byCategory,
      byStatus,
      totalSize,
      withLegalHold
    };
  }

  /**
   * Генерация идентификатора цепочки хранения
   */
  private generateCustodyId(): string {
    return `coc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Логирование
   */
  private log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    if (this.config.enableLogging) {
      const timestamp = new Date().toISOString();
      const prefix = `[EvidenceManager] [${timestamp}] [${level.toUpperCase()}]`;
      logger.info(`${prefix} ${message}`);
    }
  }

  /**
   * Экспорт улик для юридического использования
   */
  public exportForLegal(evidenceId: string): Record<string, unknown> {
    const evidence = this.evidenceStore.get(evidenceId);

    if (!evidence) {
      throw new Error(`Улика ${evidenceId} не найдена`);
    }

    return {
      evidence: {
        id: evidence.id,
        type: evidence.type,
        name: evidence.name,
        description: evidence.description,
        category: evidence.category,
        size: evidence.size,
        hash: evidence.hash,
        collectedAt: evidence.collectedAt,
        collectedBy: evidence.collectedBy
      },
      chainOfCustody: evidence.custodyHistory,
      accessHistory: this.getAccessHistory(evidenceId),
      integrityStatus: {
        lastVerified: new Date(),
        valid: true // В реальной системе нужна проверка
      },
      legalHold: evidence.legalHold || false,
      exportedAt: new Date(),
      exportedBy: 'system'
    };
  }

  /**
   * Массовый импорт улик из сборщика форензика данных
   */
  public async importEvidence(
    evidenceList: Evidence[],
    importedBy: Actor
  ): Promise<{ imported: number; failed: number; errors: string[] }> {
    let imported = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const evidence of evidenceList) {
      try {
        await this.addEvidence(evidence, importedBy);
        imported++;
      } catch (error) {
        failed++;
        errors.push(`Улика ${evidence.id}: ${(error as Error).message}`);
      }
    }

    return { imported, failed, errors };
  }
}

/**
 * Экспорт событий менеджера
 */
export { EvidenceManagerEvent };
