/**
 * ============================================================================
 * SECRET VERSIONING - ВЕРСИОНИРОВАНИЕ СЕКРЕТОВ С ROLLBACK CAPABILITY
 * ============================================================================
 * 
 * Реализует полное версионирование секретов с возможностью отката к любой
 * предыдущей версии. Поддерживает хранение истории, мягкое удаление версий,
 * проверку целостности через хеши и audit logging всех изменений.
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { createHash } from 'crypto';
import {
  SecretVersion,
  RollbackInfo,
  SecretStatus,
  BackendSecret,
  SecretVersionError,
  ISecretBackend
} from '../types/secrets.types';
import { logger } from '../logging/Logger';

/**
 * Конфигурация системы версионирования
 */
interface VersioningConfig {
  /** Максимальное количество хранимых версий */
  maxVersions: number;
  /** Хранить удалённые версии (мягкое удаление) */
  keepDeletedVersions: boolean;
  /** Срок хранения удалённых версий (дни) */
  deletedVersionsRetentionDays: number;
  /** Требовать причину для отката */
  requireRollbackReason: boolean;
  /** Минимальный интервал между версиями (мс) */
  minVersionInterval: number;
  /** Включить проверку целостности */
  enableIntegrityCheck: boolean;
}

/**
 * Метаданные версии
 */
interface VersionMetadata {
  /** ID секрета */
  secretId: string;
  /** Предыдущая версия */
  previousVersion: number | null;
  /** Причина создания версии */
  reason?: string;
  /** Автор изменений */
  author: string;
  /** Дополнительные данные */
  extra?: Record<string, unknown>;
}

/**
 * Класс для управления версионированием секретов
 * 
 * Особенности:
 * - Полная история всех изменений
 * - Откат к любой предыдущей версии
 * - Проверка целостности через хеши
 * - Мягкое удаление версий
 * - Ограничение количества хранимых версий
 * - Audit logging всех операций
 */
export class SecretVersioningManager extends EventEmitter {
  /** Конфигурация */
  private readonly config: VersioningConfig;
  
  /** Хранилище версий по секретам */
  private versions: Map<string, Map<number, SecretVersion>>;
  
  /** Информация об откатах */
  private rollbacks: Map<string, RollbackInfo>;
  
  /** Ссылка на бэкенд для хранения данных версий */
  private backend?: ISecretBackend;
  
  /** Значения секретов в памяти (для быстрого доступа) */
  private secretValues: Map<string, Map<number, string>>;
  
  /** Время последней операции для каждого секрета */
  private lastOperationTime: Map<string, number>;

  /** Конфигурация по умолчанию */
  private readonly DEFAULT_CONFIG: VersioningConfig = {
    maxVersions: 10,
    keepDeletedVersions: true,
    deletedVersionsRetentionDays: 90,
    requireRollbackReason: true,
    minVersionInterval: 0, // 0 = отключить проверку (для тестов и быстрого создания)
    enableIntegrityCheck: true
  };

  /**
   * Создаёт новый экземпляр SecretVersioningManager
   * 
   * @param config - Конфигурация версионирования
   */
  constructor(config: Partial<VersioningConfig> = {}) {
    super();
    
    this.config = {
      ...this.DEFAULT_CONFIG,
      ...config
    };
    
    this.versions = new Map();
    this.rollbacks = new Map();
    this.secretValues = new Map();
    this.lastOperationTime = new Map();
  }

  /**
   * Инициализация менеджера версионирования
   * 
   * @param backend - Бэкенд для хранения
   */
  async initialize(backend?: ISecretBackend): Promise<void> {
    this.backend = backend;

    logger.info('[SecretVersioning] Инициализирован', {
      maxVersions: this.config.maxVersions,
      keepDeletedVersions: this.config.keepDeletedVersions,
      retentionDays: this.config.deletedVersionsRetentionDays
    });
  }

  /**
   * Остановка менеджера
   */
  async destroy(): Promise<void> {
    this.versions.clear();
    this.rollbacks.clear();
    this.secretValues.clear();
    this.lastOperationTime.clear();

    logger.info('[SecretVersioning] Остановлен');
  }

  /**
   * Создать новую версию секрета
   * 
   * @param secret - Секрет для версионирования
   * @param metadata - Метаданные версии
   * @returns Созданная версия
   */
  async createVersion(
    secret: BackendSecret,
    metadata: VersionMetadata
  ): Promise<SecretVersion> {
    const now = new Date();
    
    // Проверка минимального интервала (только если interval > 0)
    if (this.config.minVersionInterval > 0) {
      const lastTime = this.lastOperationTime.get(secret.id);
      if (lastTime && Date.now() - lastTime < this.config.minVersionInterval) {
        throw new SecretVersionError(
          'Слишком частое создание версий',
          secret.id
        );
      }
    }
    
    // Получение текущего номера версии
    const secretVersions = this.versions.get(secret.id) ?? new Map();
    const currentVersion = this.getCurrentVersion(secret.id);
    const newVersionNumber = currentVersion + 1;
    
    // Вычисление хеша содержимого
    const contentHash = this.computeContentHash(secret.value, metadata);
    
    // Создание записи версии
    const version: SecretVersion = {
      version: newVersionNumber,
      contentHash,
      createdAt: now,
      createdBy: metadata.author,
      status: SecretStatus.ACTIVE,
      reason: metadata.reason,
      metadata: metadata.extra
    };
    
    // Деактивация предыдущей версии
    if (currentVersion > 0) {
      const prevVersion = secretVersions.get(currentVersion);
      if (prevVersion) {
        prevVersion.status = SecretStatus.INACTIVE;
      }
    }
    
    // Сохранение версии
    secretVersions.set(newVersionNumber, version);
    this.versions.set(secret.id, secretVersions);
    
    // Сохранение значения секрета
    let valuesMap = this.secretValues.get(secret.id);
    if (!valuesMap) {
      valuesMap = new Map();
      this.secretValues.set(secret.id, valuesMap);
    }
    valuesMap.set(newVersionNumber, secret.value);
    
    // Очистка старых версий
    await this.cleanupOldVersions(secret.id, secretVersions);
    
    // Обновление времени операции
    this.lastOperationTime.set(secret.id, Date.now());

    logger.info(`[SecretVersioning] Создана версия ${newVersionNumber}`, {
      secretId: secret.id,
      hash: contentHash
    });

    this.emit('version:created', {
      secretId: secret.id,
      version: newVersionNumber,
      hash: contentHash
    });
    
    return version;
  }

  /**
   * Получить версию секрета
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии (0 для текущей)
   * @returns Информация о версии или null
   */
  getVersion(secretId: string, version = 0): SecretVersion | null {
    const secretVersions = this.versions.get(secretId);
    
    if (!secretVersions) {
      return null;
    }
    
    const targetVersion = version === 0 ? this.getCurrentVersion(secretId) : version;
    
    return secretVersions.get(targetVersion) ?? null;
  }

  /**
   * Получить все версии секрета
   * 
   * @param secretId - ID секрета
   * @param includeDeleted - Включать удалённые версии
   * @returns Массив версий
   */
  getAllVersions(secretId: string, includeDeleted = false): SecretVersion[] {
    const secretVersions = this.versions.get(secretId);
    
    if (!secretVersions) {
      return [];
    }
    
    const versions = Array.from(secretVersions.values());
    
    if (!includeDeleted) {
      return versions.filter(v => v.status !== SecretStatus.DELETED);
    }
    
    return versions;
  }

  /**
   * Получить значение секрета для конкретной версии
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии
   * @returns Значение секрета или null
   */
  getVersionValue(secretId: string, version: number): string | null {
    const valuesMap = this.secretValues.get(secretId);
    
    if (!valuesMap) {
      return null;
    }
    
    return valuesMap.get(version) ?? null;
  }

  /**
   * Выполнить откат к предыдущей версии
   * 
   * @param secretId - ID секрета
   * @param targetVersion - Целевая версия для отката
   * @param reason - Причина отката
   * @param author - Автор отката
   * @returns Информация об откате
   */
  async rollback(
    secretId: string,
    targetVersion: number,
    reason: string,
    author: string
  ): Promise<RollbackInfo> {
    if (this.config.requireRollbackReason && !reason) {
      throw new SecretVersionError(
        'Требуется указать причину отката',
        secretId
      );
    }
    
    const secretVersions = this.versions.get(secretId);
    
    if (!secretVersions) {
      throw new SecretVersionError(
        'Секрет не найден',
        secretId
      );
    }
    
    const currentVersion = this.getCurrentVersion(secretId);
    
    if (targetVersion <= 0 || targetVersion >= currentVersion) {
      throw new SecretVersionError(
        `Некорректная версия для отката. Текущая: ${currentVersion}, целевая: ${targetVersion}`,
        secretId
      );
    }
    
    const targetVersionData = secretVersions.get(targetVersion);
    
    if (!targetVersionData) {
      throw new SecretVersionError(
        `Версия ${targetVersion} не найдена`,
        secretId
      );
    }
    
    if (targetVersionData.status === SecretStatus.DELETED) {
      throw new SecretVersionError(
        `Невозможно откатиться к удалённой версии ${targetVersion}`,
        secretId
      );
    }
    
    // Проверка целостности целевой версии
    if (this.config.enableIntegrityCheck) {
      const storedValue = this.getVersionValue(secretId, targetVersion);
      
      if (storedValue) {
        const computedHash = this.computeContentHash(storedValue, {
          secretId,
          previousVersion: null,
          author
        });
        
        if (computedHash !== targetVersionData.contentHash) {
          throw new SecretVersionError(
            `Нарушение целостности версии ${targetVersion}`,
            secretId
          );
        }
      }
    }
    
    // Получение списка предыдущих версий
    const previousVersions = Array.from(secretVersions.keys())
      .filter(v => v < currentVersion && v !== targetVersion);
    
    // Создание информации об откате
    const rollbackInfo: RollbackInfo = {
      currentVersion,
      targetVersion,
      rolledBackAt: new Date(),
      rolledBackBy: author,
      reason,
      previousVersions
    };
    
    // Сохранение информации об откате
    this.rollbacks.set(secretId, rollbackInfo);
    
    // Создание новой версии с восстановленным значением
    const restoredValue = this.getVersionValue(secretId, targetVersion);
    
    if (restoredValue) {
      await this.createVersion(
        {
          id: secretId,
          name: `rollback-${targetVersion}`,
          value: restoredValue,
          version: currentVersion + 1,
          status: SecretStatus.ACTIVE,
          createdAt: new Date()
        },
        {
          secretId,
          previousVersion: currentVersion,
          reason: `Откат к версии ${targetVersion}: ${reason}`,
          author,
          extra: { rollback: true, targetVersion }
        }
      );
    }

    logger.info(`[SecretVersioning] Откат секрета ${secretId} к версии ${targetVersion}`, {
      fromVersion: currentVersion,
      toVersion: targetVersion,
      reason
    });

    this.emit('version:rollback', {
      secretId,
      fromVersion: currentVersion,
      toVersion: targetVersion,
      reason
    });
    
    return rollbackInfo;
  }

  /**
   * Получить историю откатов для секрета
   * 
   * @param secretId - ID секрета
   * @returns История откатов
   */
  getRollbackHistory(secretId: string): RollbackInfo[] {
    const rollback = this.rollbacks.get(secretId);
    
    if (!rollback) {
      return [];
    }
    
    return [rollback];
  }

  /**
   * Удалить версию секрета
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии
   * @param author - Автор удаления
   * @returns Успешность удаления
   */
  async deleteVersion(
    secretId: string,
    version: number,
    author: string
  ): Promise<boolean> {
    const secretVersions = this.versions.get(secretId);
    
    if (!secretVersions) {
      return false;
    }
    
    const versionData = secretVersions.get(version);
    
    if (!versionData) {
      return false;
    }
    
    // Нельзя удалить текущую версию
    if (version === this.getCurrentVersion(secretId)) {
      throw new SecretVersionError(
        'Невозможно удалить текущую версию',
        secretId
      );
    }
    
    if (this.config.keepDeletedVersions) {
      // Мягкое удаление
      versionData.status = SecretStatus.DELETED;
      versionData.deletedAt = new Date();
      versionData.deletedBy = author;
    } else {
      // Полное удаление
      secretVersions.delete(version);
      
      const valuesMap = this.secretValues.get(secretId);
      if (valuesMap) {
        valuesMap.delete(version);
      }
    }

    logger.info(`[SecretVersioning] Удалена версия ${version}`, {
      secretId,
      softDelete: this.config.keepDeletedVersions
    });

    this.emit('version:deleted', {
      secretId,
      version,
      softDelete: this.config.keepDeletedVersions
    });
    
    return true;
  }

  /**
   * Сравнить две версии секрета
   * 
   * @param secretId - ID секрета
   * @param version1 - Первая версия
   * @param version2 - Вторая версия
   * @returns Результат сравнения
   */
  compareVersions(
    secretId: string,
    version1: number,
    version2: number
  ): {
    identical: boolean;
    hash1: string;
    hash2: string;
    value1?: string;
    value2?: string;
  } {
    const v1 = this.getVersion(secretId, version1);
    const v2 = this.getVersion(secretId, version2);
    
    if (!v1 || !v2) {
      throw new SecretVersionError(
        'Одна или обе версии не найдены',
        secretId
      );
    }
    
    const value1 = this.getVersionValue(secretId, version1);
    const value2 = this.getVersionValue(secretId, version2);
    
    return {
      identical: v1.contentHash === v2.contentHash,
      hash1: v1.contentHash,
      hash2: v2.contentHash,
      value1,
      value2
    };
  }

  /**
   * Проверить целостность версии
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии
   * @returns Результат проверки
   */
  verifyIntegrity(secretId: string, version: number): {
    valid: boolean;
    expectedHash: string;
    actualHash?: string;
    error?: string;
  } {
    if (!this.config.enableIntegrityCheck) {
      return { valid: true, expectedHash: '' };
    }
    
    const versionData = this.getVersion(secretId, version);
    
    if (!versionData) {
      return {
        valid: false,
        expectedHash: '',
        error: 'Версия не найдена'
      };
    }
    
    const storedValue = this.getVersionValue(secretId, version);
    
    if (!storedValue) {
      return {
        valid: false,
        expectedHash: versionData.contentHash,
        error: 'Значение версии не найдено'
      };
    }
    
    const actualHash = this.computeContentHash(storedValue, {
      secretId,
      previousVersion: null,
      author: ''
    });
    
    if (actualHash !== versionData.contentHash) {
      return {
        valid: false,
        expectedHash: versionData.contentHash,
        actualHash,
        error: 'Хеш не совпадает'
      };
    }
    
    return {
      valid: true,
      expectedHash: versionData.contentHash,
      actualHash
    };
  }

  /**
   * Проверить целостность всех версий секрета
   * 
   * @param secretId - ID секрета
   * @returns Результаты проверки по версиям
   */
  verifyAllVersionsIntegrity(secretId: string): Map<number, {
    valid: boolean;
    error?: string;
  }> {
    const results = new Map<number, { valid: boolean; error?: string }>();
    const versions = this.getAllVersions(secretId, true);
    
    for (const version of versions) {
      const result = this.verifyIntegrity(secretId, version.version);
      results.set(version.version, {
        valid: result.valid,
        error: result.error
      });
    }
    
    return results;
  }

  /**
   * Получить текущую версию секрета
   * 
   * @param secretId - ID секрета
   * @returns Номер текущей версии
   */
  getCurrentVersion(secretId: string): number {
    const secretVersions = this.versions.get(secretId);
    
    if (!secretVersions || secretVersions.size === 0) {
      return 0;
    }
    
    // Находим максимальную активную версию
    let maxVersion = 0;
    
    for (const [version, data] of secretVersions.entries()) {
      if (data.status !== SecretStatus.DELETED && version > maxVersion) {
        maxVersion = version;
      }
    }
    
    return maxVersion;
  }

  /**
   * Вычислить хеш содержимого
   */
  private computeContentHash(value: string, metadata: VersionMetadata): string {
    const hashInput = JSON.stringify({
      value,
      secretId: metadata.secretId,
      previousVersion: metadata.previousVersion
      // Не включаем timestamp чтобы хеш был детерминированным
    });

    return createHash('sha256').update(hashInput).digest('hex');
  }

  /**
   * Очистка старых версий
   */
  private async cleanupOldVersions(
    secretId: string,
    secretVersions: Map<number, SecretVersion>
  ): Promise<void> {
    const versions = Array.from(secretVersions.entries())
      .sort((a, b) => b[0] - a[0]); // Сортировка по убыванию версии
    
    if (versions.length <= this.config.maxVersions) {
      return;
    }
    
    // Удаляем старые версии
    const toDelete = versions.slice(this.config.maxVersions);
    
    for (const [versionNumber, versionData] of toDelete) {
      if (this.config.keepDeletedVersions) {
        versionData.status = SecretStatus.DELETED;
        versionData.deletedAt = new Date();
      } else {
        secretVersions.delete(versionNumber);
        
        const valuesMap = this.secretValues.get(secretId);
        if (valuesMap) {
          valuesMap.delete(versionNumber);
        }
      }

      logger.debug(`[SecretVersioning] Удалена старая версия ${versionNumber}`, {
        secretId
      });
    }
  }

  /**
   * Очистка удалённых версий по истечении срока
   */
  async cleanupExpiredDeletedVersions(): Promise<void> {
    const now = new Date();
    const retentionMs = this.config.deletedVersionsRetentionDays * 24 * 60 * 60 * 1000;
    
    let totalCleaned = 0;
    
    for (const [secretId, secretVersions] of this.versions.entries()) {
      for (const [versionNumber, versionData] of secretVersions.entries()) {
        if (
          versionData.status === SecretStatus.DELETED &&
          versionData.deletedAt &&
          now.getTime() - versionData.deletedAt.getTime() > retentionMs
        ) {
          secretVersions.delete(versionNumber);
          
          const valuesMap = this.secretValues.get(secretId);
          if (valuesMap) {
            valuesMap.delete(versionNumber);
          }
          
          totalCleaned++;
        }
      }
    }

    if (totalCleaned > 0) {
      logger.info(`[SecretVersioning] Очищено ${totalCleaned} удалённых версий`, {
        totalCleaned
      });
    }
  }

  /**
   * Получить статистику версионирования
   */
  getStats(): {
    totalSecrets: number;
    totalVersions: number;
    avgVersionsPerSecret: number;
    totalRollbacks: number;
    deletedVersions: number;
  } {
    let totalVersions = 0;
    let deletedVersions = 0;
    
    for (const secretVersions of this.versions.values()) {
      for (const version of secretVersions.values()) {
        totalVersions++;
        
        if (version.status === SecretStatus.DELETED) {
          deletedVersions++;
        }
      }
    }
    
    const totalSecrets = this.versions.size;
    
    return {
      totalSecrets,
      totalVersions,
      avgVersionsPerSecret: totalSecrets > 0 ? totalVersions / totalSecrets : 0,
      totalRollbacks: this.rollbacks.size,
      deletedVersions
    };
  }

  /**
   * Экспорт истории версий для секрета
   * 
   * @param secretId - ID секрета
   * @returns Экспортированные данные
   */
  exportVersionHistory(secretId: string): {
    secretId: string;
    versions: SecretVersion[];
    rollbacks: RollbackInfo[];
    exportedAt: Date;
  } | null {
    const secretVersions = this.versions.get(secretId);
    
    if (!secretVersions) {
      return null;
    }
    
    return {
      secretId,
      versions: Array.from(secretVersions.values()),
      rollbacks: this.getRollbackHistory(secretId),
      exportedAt: new Date()
    };
  }
}
