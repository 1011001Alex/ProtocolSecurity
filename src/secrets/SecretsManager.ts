/**
 * ============================================================================
 * SECRETS MANAGER - ОСНОВНОЙ МЕНЕДЖЕР СЕКРЕТОВ
 * ============================================================================
 * 
 * Центральный компонент системы управления секретами, объединяющий:
 * - Множественные бэкенды (Vault, AWS, GCP, Azure)
 * - Кэширование с шифрованием
 * - Контроль доступа на основе политик
 * - Версионирование и откат
 * - Автоматическую ротацию
 * - Lease management
 * - Динамические секреты
 * - Сканирование на утечки
 * - Audit logging
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { randomUUID } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../logging/Logger';
import {
  SecretsManagerConfig,
  SecretsManagerEvents,
  ISecretsManager,
  SecretOperationResult,
  BackendSecret,
  SecretStatus,
  SecretVersion,
  RollbackInfo,
  SecretLease,
  GeneratedDynamicSecret,
  DynamicSecretConfig,
  AccessContext,
  AccessPolicy,
  SecretAction,
  AuditLogEntry,
  AuditLogFilters,
  LeakDetection,
  SecretBackendType,
  AnyBackendConfig,
  SecretOperation,
  SecretAccessError,
  SecretConfigError,
  SecretBackendError
} from '../types/secrets.types';
import { SecretCache } from './SecretCache';
import { AccessPolicyManager } from './AccessPolicy';
import { SecretVersioningManager } from './SecretVersioning';
import { SecretLeaseManager } from './SecretLeaseManager';
import { SecretRotator } from './SecretRotator';
import { DynamicSecretsManager } from './DynamicSecrets';
import { SecretScanner } from './SecretScanner';
import { VaultBackend, VaultBackendFactory } from './VaultBackend';
import { AWSSecretsBackend, AWSSecretsBackendFactory } from './AWSSecretsBackend';
import { GCPSecretBackend, GCPSecretBackendFactory } from './GCPSecretBackend';
import { AzureKeyVaultBackend, AzureKeyVaultBackendFactory } from './AzureKeyVaultBackend';

/**
 * Тип бэкенда в объединённом виде
 */
type AnyBackend = VaultBackend | AWSSecretsBackend | GCPSecretBackend | AzureKeyVaultBackend;

/**
 * Класс основного менеджера секретов
 * 
 * Особенности:
 * - Абстракция над множественными бэкендами
 * - Zero-trust архитектура
 * - Полное audit logging
 * - High availability через failover
 * - Производительность через кэширование
 */
export class SecretsManager extends EventEmitter implements ISecretsManager {
  /** Конфигурация */
  private readonly config: SecretsManagerConfig;
  
  /** Активные бэкенды */
  private backends: Map<SecretBackendType, AnyBackend>;
  
  /** Основной бэкенд (приоритетный) */
  private primaryBackend?: AnyBackend;
  
  /** Менеджер кэша */
  private cache?: SecretCache;
  
  /** Менеджер политик доступа */
  private policyManager: AccessPolicyManager;
  
  /** Менеджер версионирования */
  private versioningManager: SecretVersioningManager;
  
  /** Менеджер lease */
  private leaseManager: SecretLeaseManager;
  
  /** Менеджер ротации */
  private rotator: SecretRotator;
  
  /** Менеджер динамических секретов */
  private dynamicSecrets: DynamicSecretsManager;
  
  /** Сканер утечек */
  private scanner: SecretScanner;
  
  /** Audit логи */
  private auditLogs: AuditLogEntry[];
  
  /** Путь к audit логам */
  private readonly auditLogPath?: string;
  
  /** Флаг инициализации */
  private isInitialized = false;
  
  /** Режим работы */
  private readonly mode: 'development' | 'production';

  /**
   * Создаёт новый экземпляр SecretsManager
   * 
   * @param config - Конфигурация менеджера
   */
  constructor(config: SecretsManagerConfig) {
    super();
    
    this.config = config;
    this.mode = config.mode ?? 'production';
    this.auditLogPath = config.auditLogPath;
    
    this.backends = new Map();
    this.policyManager = new AccessPolicyManager();
    this.versioningManager = new SecretVersioningManager();
    this.leaseManager = new SecretLeaseManager(
      { enableAutoRenewal: true },
      config.defaultLease
    );
    this.rotator = new SecretRotator(
      { enableAutoRotation: true },
      config.defaultRotation
    );
    this.dynamicSecrets = new DynamicSecretsManager({
      maxActiveSecrets: 1000,
      defaultTTL: config.defaultLease?.defaultTTL ?? 3600
    });
    this.scanner = new SecretScanner(config.scanner);
    
    this.auditLogs = [];
    
    // Регистрация обработчиков событий
    this.setupEventHandlers();
  }

  /**
   * Настройка обработчиков событий
   */
  private setupEventHandlers(): void {
    // События ротации
    this.rotator.on('rotation:started', (secretId: string) => {
      this.emit('rotation:started', secretId);
      this.logAudit({
        operation: SecretOperation.ROTATE,
        secretId,
        secretName: secretId,
        performedBy: 'system',
        success: true,
        metadata: { event: 'rotation_started' }
      });
    });
    
    this.rotator.on('rotation:completed', ({ secretId }: { secretId: string }) => {
      this.emit('rotation:completed', secretId);
      this.logAudit({
        operation: SecretOperation.ROTATE,
        secretId,
        secretName: secretId,
        performedBy: 'system',
        success: true,
        metadata: { event: 'rotation_completed' }
      });
    });
    
    this.rotator.on('rotation:failed', ({ secretId, error }: { secretId: string; error: Error }) => {
      this.emit('rotation:failed', secretId, error);
      this.logAudit({
        operation: SecretOperation.ROTATE,
        secretId,
        secretName: secretId,
        performedBy: 'system',
        success: false,
        errorMessage: error.message
      });
    });
    
    // События lease
    this.leaseManager.on('lease:expiring', (lease: SecretLease) => {
      this.emit('lease:expiring', lease);
    });
    
    this.leaseManager.on('lease:expired', (lease: SecretLease) => {
      this.emit('lease:expired', lease);
      this.logAudit({
        operation: SecretOperation.REVOKE_LEASE,
        secretId: lease.secretId,
        secretName: lease.secretId,
        performedBy: 'system',
        success: true,
        metadata: { leaseId: lease.leaseId, reason: 'expired' }
      });
    });
    
    // События сканера
    this.scanner.on('leak:detected', (leak: LeakDetection) => {
      this.emit('leak:detected', leak);
      this.logAudit({
        operation: SecretOperation.SCAN,
        secretId: leak.secretId,
        secretName: leak.secretName,
        performedBy: 'scanner',
        success: true,
        metadata: { leak, event: 'leak_detected' }
      });
      
      // Авто-отзыв при обнаружении утечки
      if (this.config.scanner.autoRevokeOnLeak && leak.secretId) {
        void this.leaseManager.revokeAllSecretLeases(leak.secretId, 'leak_detected');
      }
    });
  }

  /**
   * Инициализация менеджера
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    logger.info('[SecretsManager] Начало инициализации...');

    try {
      // Инициализация кэша
      if (this.config.cache.enabled) {
        this.cache = new SecretCache(this.config.cache, this.config.encryptionKey);
        await this.cache.initialize();
      }

      // Инициализация бэкендов
      await this.initializeBackends();

      // Инициализация менеджеров
      await this.policyManager.initialize(this.config.policies, this.mode === 'production');
      await this.versioningManager.initialize(this.primaryBackend);
      await this.leaseManager.initialize();
      await this.rotator.initialize(this.primaryBackend);
      await this.dynamicSecrets.initialize(this.leaseManager);
      await this.scanner.initialize();

      this.isInitialized = true;

      logger.info('[SecretsManager] Инициализация завершена успешно');
      logger.info('[SecretsManager] Конфигурация', {
        backends: this.backends.size,
        primaryBackend: this.primaryBackend?.type,
        cache: this.config.cache.enabled,
        mode: this.mode
      });

    } catch (error) {
      logger.error('[SecretsManager] Ошибка инициализации', { error });
      await this.destroy();
      throw error;
    }
  }

  /**
   * Инициализация бэкендов
   */
  private async initializeBackends(): Promise<void> {
    for (const backendConfig of this.config.backends) {
      if (!backendConfig.enabled) {
        continue;
      }
      
      try {
        let backend: AnyBackend;
        
        switch (backendConfig.type) {
          case SecretBackendType.VAULT:
            backend = await VaultBackendFactory.getInstance(
              'vault',
              backendConfig as any
            );
            break;
          
          case SecretBackendType.AWS_SECRETS_MANAGER:
            backend = await AWSSecretsBackendFactory.getInstance(
              'aws',
              backendConfig as any
            );
            break;
          
          case SecretBackendType.GCP_SECRET_MANAGER:
            backend = await GCPSecretBackendFactory.getInstance(
              'gcp',
              backendConfig as any
            );
            break;
          
          case SecretBackendType.AZURE_KEY_VAULT:
            backend = await AzureKeyVaultBackendFactory.getInstance(
              'azure',
              backendConfig as any
            );
            break;
          
          default:
            logger.warn(`[SecretsManager] Неизвестный тип бэкенда: ${backendConfig.type}`);
            continue;
        }

        this.backends.set(backendConfig.type, backend);

        // Первый успешный бэкенд становится основным
        if (!this.primaryBackend) {
          this.primaryBackend = backend;
        }

        logger.info(`[SecretsManager] Инициализирован бэкенд: ${backendConfig.type}`);

      } catch (error) {
        logger.error(`[SecretsManager] Ошибка инициализации бэкенда ${backendConfig.type}`, { error });

        this.emit('backend:unhealthy', backendConfig.type);
      }
    }
    
    if (!this.primaryBackend) {
      // В development mode允许没有 backend (только кэш)
      if (this.mode === 'development') {
        logger.warn('[SecretsManager] Бэкенд не инициализирован, работа только с кэшем');
      } else {
        throw new SecretConfigError('Не удалось инициализировать ни один бэкенд');
      }
    }
  }

  /**
   * Получить секрет
   * 
   * @param secretId - ID секрета
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async getSecret(
    secretId: string,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>> {
    const operationId = randomUUID();
    const startTime = Date.now();
    
    try {
      // Проверка доступа
      const hasAccess = await this.checkAccess(SecretAction.READ, secretId, context);
      
      if (!hasAccess) {
        throw new SecretAccessError('Доступ запрещён', secretId);
      }
      
      // Проверка кэша
      if (this.cache) {
        const cached = await this.cache.get(secretId);
        if (cached) {
          this.logAudit({
            operation: SecretOperation.READ,
            secretId,
            secretName: secretId,
            performedBy: context.subjectId,
            success: true,
            ipAddress: context.ipAddress,
            metadata: { fromCache: true },
            operationId
          }, startTime);
          
          return {
            success: true,
            data: cached,
            operationId,
            version: cached.version
          };
        }
      }
      
      // Получение из бэкенда
      if (!this.primaryBackend) {
        throw new SecretConfigError('Бэкенд не инициализирован');
      }
      
      const secret = await this.primaryBackend.getSecret(secretId);
      
      if (!secret) {
        throw new SecretBackendError(`Секрет ${secretId} не найден`, this.primaryBackend.type);
      }
      
      // Кэширование
      if (this.cache) {
        await this.cache.set(secret);
      }
      
      // Версионирование
      await this.versioningManager.createVersion(secret, {
        secretId,
        previousVersion: null,
        author: context.subjectId
      });
      
      // Сканирование на утечки
      this.scanner.addKnownSecret(secret.value);
      
      this.logAudit({
        operation: SecretOperation.READ,
        secretId,
        secretName: secretId,
        performedBy: context.subjectId,
        success: true,
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        sessionId: context.sessionId,
        operationId
      }, startTime);
      
      return {
        success: true,
        data: secret,
        operationId,
        version: secret.version
      };
      
    } catch (error) {
      this.logAudit({
        operation: SecretOperation.READ,
        secretId,
        secretName: secretId,
        performedBy: context.subjectId,
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        ipAddress: context.ipAddress,
        operationId
      }, startTime);
      
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Создать секрет
   * 
   * @param secret - Данные секрета
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async createSecret(
    secret: Omit<BackendSecret, 'version' | 'createdAt' | 'updatedAt'>,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>> {
    const operationId = randomUUID();
    const startTime = Date.now();
    
    try {
      // Проверка доступа
      const hasAccess = await this.checkAccess(SecretAction.WRITE, secret.id, context);
      
      if (!hasAccess) {
        throw new SecretAccessError('Доступ запрещён', secret.id);
      }
      
      if (!this.primaryBackend) {
        throw new SecretConfigError('Бэкенд не инициализирован');
      }
      
      const created = await this.primaryBackend.createSecret(secret);
      
      // Версионирование
      await this.versioningManager.createVersion(created, {
        secretId: created.id,
        previousVersion: null,
        author: context.subjectId,
        reason: 'create'
      });
      
      // Кэширование
      if (this.cache) {
        await this.cache.set(created);
      }
      
      // Сканирование
      this.scanner.addKnownSecret(created.value);
      
      // Настройка ротации если включена
      if (this.config.defaultRotation.enabled) {
        this.rotator.configureRotation(created.id, this.config.defaultRotation);
      }
      
      this.logAudit({
        operation: SecretOperation.CREATE,
        secretId: created.id,
        secretName: created.name,
        performedBy: context.subjectId,
        success: true,
        ipAddress: context.ipAddress,
        operationId
      }, startTime);
      
      this.emit('secret:created', created);
      
      return {
        success: true,
        data: created,
        operationId,
        version: created.version
      };
      
    } catch (error) {
      this.logAudit({
        operation: SecretOperation.CREATE,
        secretId: secret.id,
        secretName: secret.name,
        performedBy: context.subjectId,
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      }, startTime);
      
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Обновить секрет
   * 
   * @param secretId - ID секрета
   * @param value - Новое значение
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async updateSecret(
    secretId: string,
    value: string,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>> {
    const operationId = randomUUID();
    const startTime = Date.now();
    
    try {
      // Проверка доступа
      const hasAccess = await this.checkAccess(SecretAction.WRITE, secretId, context);
      
      if (!hasAccess) {
        throw new SecretAccessError('Доступ запрещён', secretId);
      }
      
      if (!this.primaryBackend) {
        throw new SecretConfigError('Бэкенд не инициализирован');
      }
      
      const updated = await this.primaryBackend.updateSecret(secretId, value);
      
      // Версионирование
      await this.versioningManager.createVersion(updated, {
        secretId,
        previousVersion: null,
        author: context.subjectId,
        reason: 'update'
      });
      
      // Инвалидация кэша
      if (this.cache) {
        await this.cache.invalidate(secretId);
      }
      
      // Обновление в сканере
      this.scanner.addKnownSecret(value);
      
      this.logAudit({
        operation: SecretOperation.UPDATE,
        secretId,
        secretName: secretId,
        performedBy: context.subjectId,
        success: true,
        ipAddress: context.ipAddress,
        operationId
      }, startTime);
      
      this.emit('secret:updated', updated);
      
      return {
        success: true,
        data: updated,
        operationId,
        version: updated.version
      };
      
    } catch (error) {
      this.logAudit({
        operation: SecretOperation.UPDATE,
        secretId,
        secretName: secretId,
        performedBy: context.subjectId,
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      }, startTime);
      
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Удалить секрет
   * 
   * @param secretId - ID секрета
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async deleteSecret(
    secretId: string,
    context: AccessContext
  ): Promise<SecretOperationResult<void>> {
    const operationId = randomUUID();
    const startTime = Date.now();
    
    try {
      // Проверка доступа
      const hasAccess = await this.checkAccess(SecretAction.DELETE, secretId, context);
      
      if (!hasAccess) {
        throw new SecretAccessError('Доступ запрещён', secretId);
      }
      
      if (!this.primaryBackend) {
        throw new SecretConfigError('Бэкенд не инициализирован');
      }
      
      await this.primaryBackend.deleteSecret(secretId);
      
      // Инвалидация кэша
      if (this.cache) {
        await this.cache.invalidate(secretId);
      }
      
      // Отзыв всех lease
      await this.leaseManager.revokeAllSecretLeases(secretId, 'secret_deleted');
      
      this.logAudit({
        operation: SecretOperation.DELETE,
        secretId,
        secretName: secretId,
        performedBy: context.subjectId,
        success: true,
        ipAddress: context.ipAddress,
        operationId
      }, startTime);
      
      this.emit('secret:deleted', secretId);
      
      return {
        success: true,
        operationId
      };
      
    } catch (error) {
      this.logAudit({
        operation: SecretOperation.DELETE,
        secretId,
        secretName: secretId,
        performedBy: context.subjectId,
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      }, startTime);
      
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Ротировать секрет
   * 
   * @param secretId - ID секрета
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async rotateSecret(
    secretId: string,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>> {
    const operationId = randomUUID();
    
    try {
      // Проверка доступа
      const hasAccess = await this.checkAccess(SecretAction.ROTATE, secretId, context);
      
      if (!hasAccess) {
        throw new SecretAccessError('Доступ запрещён', secretId);
      }
      
      const rotated = await this.rotator.rotateSecret(secretId, undefined, 'manual');
      
      return {
        success: true,
        data: rotated,
        operationId,
        version: rotated.version
      };
      
    } catch (error) {
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Получить версию секрета
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async getVersion(
    secretId: string,
    version: number,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>> {
    const operationId = randomUUID();
    
    try {
      const hasAccess = await this.checkAccess(SecretAction.READ, secretId, context);
      
      if (!hasAccess) {
        throw new SecretAccessError('Доступ запрещён', secretId);
      }
      
      if (!this.primaryBackend) {
        throw new SecretConfigError('Бэкенд не инициализирован');
      }
      
      const secret = await this.primaryBackend.getSecretVersion(secretId, version);
      
      if (!secret) {
        throw new SecretBackendError(`Версия ${version} не найдена`, this.primaryBackend.type);
      }
      
      this.logAudit({
        operation: SecretOperation.GET_VERSION,
        secretId,
        secretName: secretId,
        performedBy: context.subjectId,
        success: true,
        metadata: { version },
        operationId
      });
      
      return {
        success: true,
        data: secret,
        operationId,
        version
      };
      
    } catch (error) {
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Откатиться к версии
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии
   * @param reason - Причина отката
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async rollback(
    secretId: string,
    version: number,
    reason: string,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>> {
    const operationId = randomUUID();
    
    try {
      const hasAccess = await this.checkAccess(SecretAction.VERSION_MANAGE, secretId, context);
      
      if (!hasAccess) {
        throw new SecretAccessError('Доступ запрещён', secretId);
      }
      
      const rolledBack = await this.versioningManager.rollback(
        secretId,
        version,
        reason,
        context.subjectId
      );
      
      // Синхронизация с бэкендом
      const rolledBackSecret = await this.rollbackToVersionInBackend(secretId, version);
      
      this.logAudit({
        operation: SecretOperation.ROLLBACK,
        secretId,
        secretName: secretId,
        performedBy: context.subjectId,
        success: true,
        metadata: { version, reason },
        operationId
      });
      
      return {
        success: true,
        data: rolledBackSecret,
        operationId,
        version
      };
      
    } catch (error) {
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Получить lease
   * 
   * @param secretId - ID секрета
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async acquireLease(
    secretId: string,
    context: AccessContext
  ): Promise<SecretOperationResult<SecretLease>> {
    const operationId = randomUUID();
    
    try {
      const hasAccess = await this.checkAccess(SecretAction.READ, secretId, context);
      
      if (!hasAccess) {
        throw new SecretAccessError('Доступ запрещён', secretId);
      }
      
      const lease = await this.leaseManager.acquireLease(secretId, context);
      
      return {
        success: true,
        data: lease,
        operationId
      };
      
    } catch (error) {
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Продлить lease
   * 
   * @param leaseId - ID lease
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async renewLease(
    leaseId: string,
    context: AccessContext
  ): Promise<SecretOperationResult<SecretLease>> {
    const operationId = randomUUID();
    
    try {
      const lease = await this.leaseManager.renewLease(leaseId, context);
      
      this.logAudit({
        operation: SecretOperation.RENEW_LEASE,
        secretId: lease.secretId,
        secretName: lease.secretId,
        performedBy: context.subjectId,
        success: true,
        metadata: { leaseId },
        operationId
      });
      
      return {
        success: true,
        data: lease,
        operationId
      };
      
    } catch (error) {
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Отозвать lease
   * 
   * @param leaseId - ID lease
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async revokeLease(
    leaseId: string,
    context: AccessContext
  ): Promise<SecretOperationResult<void>> {
    const operationId = randomUUID();
    
    try {
      const lease = this.leaseManager.getLease(leaseId);
      
      if (!lease) {
        throw new SecretAccessError(`Lease ${leaseId} не найден`);
      }
      
      await this.leaseManager.revokeLease(leaseId, context);
      
      this.logAudit({
        operation: SecretOperation.REVOKE_LEASE,
        secretId: lease.secretId,
        secretName: lease.secretId,
        performedBy: context.subjectId,
        success: true,
        metadata: { leaseId },
        operationId
      });
      
      return {
        success: true,
        operationId
      };
      
    } catch (error) {
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Создать динамический секрет
   * 
   * @param config - Конфигурация
   * @param context - Контекст доступа
   * @returns Результат операции
   */
  async createDynamicSecret(
    config: DynamicSecretConfig,
    context: AccessContext
  ): Promise<SecretOperationResult<GeneratedDynamicSecret>> {
    const operationId = randomUUID();
    
    try {
      const secret = await this.dynamicSecrets.createSecret(
        config.type,
        config,
        context.subjectId,
        config.ttl
      );
      
      this.logAudit({
        operation: SecretOperation.CREATE,
        secretId: secret.secretId,
        secretName: secret.type,
        performedBy: context.subjectId,
        success: true,
        metadata: { type: 'dynamic', dynamicType: config.type },
        operationId
      });
      
      return {
        success: true,
        data: secret,
        operationId
      };
      
    } catch (error) {
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }

  /**
   * Проверить доступ
   *
   * @param action - Действие
   * @param resource - Ресурс
   * @param context - Контекст
   * @returns Наличие доступа
   */
  async checkAccess(
    action: SecretAction,
    resource: string,
    context: AccessContext
  ): Promise<boolean> {
    const decision = await this.policyManager.checkAccess(action, resource, context);
    return decision.allowed;
  }

  /**
   * Получить audit логи
   * 
   * @param filters - Фильтры
   * @returns Массив записей
   */
  async getAuditLogs(filters: AuditLogFilters): Promise<AuditLogEntry[]> {
    let logs = [...this.auditLogs];
    
    // Применение фильтров
    if (filters.secretId) {
      logs = logs.filter(l => l.secretId === filters.secretId);
    }
    
    if (filters.operation) {
      logs = logs.filter(l => l.operation === filters.operation);
    }
    
    if (filters.performedBy) {
      logs = logs.filter(l => l.performedBy === filters.performedBy);
    }
    
    if (filters.startDate) {
      logs = logs.filter(l => l.timestamp >= filters.startDate!);
    }
    
    if (filters.endDate) {
      logs = logs.filter(l => l.timestamp <= filters.endDate!);
    }
    
    if (filters.success !== undefined) {
      logs = logs.filter(l => l.success === filters.success);
    }
    
    // Сортировка по времени (новые первые)
    logs.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    
    return logs;
  }

  /**
   * Закрыть менеджер
   */
  async destroy(): Promise<void> {
    logger.info('[SecretsManager] Остановка...');

    // Остановка компонентов
    if (this.cache) {
      await this.cache.destroy();
    }

    await this.policyManager.destroy();
    await this.versioningManager.destroy();
    await this.leaseManager.destroy();
    await this.rotator.destroy();
    await this.dynamicSecrets.destroy();
    await this.scanner.destroy();

    // Остановка бэкендов
    for (const [type, backend] of this.backends.entries()) {
      try {
        await backend.destroy();

        // Удаление из фабрик
        switch (type) {
          case SecretBackendType.VAULT:
            await VaultBackendFactory.removeInstance('vault');
            break;
          case SecretBackendType.AWS_SECRETS_MANAGER:
            await AWSSecretsBackendFactory.removeInstance('aws');
            break;
          case SecretBackendType.GCP_SECRET_MANAGER:
            await GCPSecretBackendFactory.removeInstance('gcp');
            break;
          case SecretBackendType.AZURE_KEY_VAULT:
            await AzureKeyVaultBackendFactory.removeInstance('azure');
            break;
        }
      } catch (error) {
        logger.error(`[SecretsManager] Ошибка остановки бэкенда ${type}`, { error });
      }
    }

    this.backends.clear();
    this.auditLogs = [];
    this.isInitialized = false;

    logger.info('[SecretsManager] Остановлен');
  }

  /**
   * Логирование audit события
   */
  private logAudit(entry: Omit<AuditLogEntry, 'entryId' | 'timestamp' | 'backend'>, startTime?: number): void {
    if (!this.config.auditEnabled) {
      return;
    }

    const fullEntry: AuditLogEntry = {
      ...entry,
      ipAddress: entry.ipAddress ?? 'system',
      entryId: randomUUID(),
      timestamp: new Date(),
      backend: this.primaryBackend?.type ?? SecretBackendType.LOCAL
    };

    // Добавление времени выполнения
    if (startTime) {
      fullEntry.metadata = {
        ...fullEntry.metadata,
        executionTimeMs: Date.now() - startTime
      };
    }

    this.auditLogs.push(fullEntry);

    // Ограничение размера логов в памяти
    if (this.auditLogs.length > 10000) {
      this.auditLogs = this.auditLogs.slice(-10000);
    }

    // Запись в файл если указан путь
    if (this.auditLogPath) {
      this.writeAuditLogToFile(fullEntry);
    }

    this.emit('audit:logged', fullEntry);
  }

  /**
   * Публичный метод для добавления audit записи (для тестов)
   */
  addAuditLog(action: SecretAction, secretId: string, context: Partial<AccessContext>): void {
    this.logAudit({
      operation: action as any,
      secretId,
      secretName: secretId,
      performedBy: context.subjectId ?? 'unknown',
      success: true,
      metadata: { context }
    });
  }

  /**
   * Запись audit лога в файл
   */
  private writeAuditLogToFile(entry: AuditLogEntry): void {
    try {
      const logDir = path.dirname(this.auditLogPath!);
      
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
      
      const logLine = JSON.stringify(entry) + '\n';
      fs.appendFileSync(this.auditLogPath!, logLine, 'utf8');
    } catch (error) {
      logger.error('[SecretsManager] Ошибка записи audit лога', { error });
    }
  }

  /**
   * Откат версии в бэкенде
   */
  private async rollbackToVersionInBackend(secretId: string, version: number): Promise<BackendSecret> {
    if (!this.primaryBackend) {
      throw new SecretConfigError('Бэкенд не инициализирован');
    }
    
    return await this.primaryBackend.rollbackToVersion(secretId, version);
  }

  /**
   * Получить статистику менеджера
   */
  getStats(): {
    initialized: boolean;
    backends: number;
    primaryBackend?: SecretBackendType;
    cacheStats?: ReturnType<SecretCache['getStats']>;
    policyStats?: ReturnType<AccessPolicyManager['getStats']>;
    versioningStats?: ReturnType<SecretVersioningManager['getStats']>;
    leaseStats?: ReturnType<SecretLeaseManager['getStats']>;
    rotationStats?: ReturnType<SecretRotator['getStats']>;
    dynamicSecretsStats?: ReturnType<DynamicSecretsManager['getStats']>;
    scannerStats?: ReturnType<SecretScanner['getStats']>;
    auditLogsCount: number;
  } {
    return {
      initialized: this.isInitialized,
      backends: this.backends.size,
      primaryBackend: this.primaryBackend?.type,
      cacheStats: this.cache?.getStats(),
      policyStats: this.policyManager.getStats(),
      versioningStats: this.versioningManager.getStats(),
      leaseStats: this.leaseManager.getStats(),
      rotationStats: this.rotator.getStats(),
      dynamicSecretsStats: this.dynamicSecrets.getStats(),
      scannerStats: this.scanner.getStats(),
      auditLogsCount: this.auditLogs.length
    };
  }

  /**
   * Добавить политику доступа
   * 
   * @param policy - Политика
   */
  async addPolicy(policy: AccessPolicy): Promise<void> {
    await this.policyManager.addPolicy(policy);
  }

  /**
   * Проверить здоровье бэкендов
   * 
   * @returns Статус бэкендов
   */
  async checkBackendHealth(): Promise<Map<SecretBackendType, boolean>> {
    const healthStatus = new Map<SecretBackendType, boolean>();
    
    for (const [type, backend] of this.backends.entries()) {
      const healthy = await backend.healthCheck();
      healthStatus.set(type, healthy);
      
      if (!healthy) {
        this.emit('backend:unhealthy', type);
      } else {
        this.emit('backend:recovered', type);
      }
    }
    
    return healthStatus;
  }

  /**
   * Экспорт секрета (для миграции)
   * 
   * @param secretId - ID секрета
   * @param context - Контекст
   * @returns Экспортированные данные
   */
  async exportSecret(
    secretId: string,
    context: AccessContext
  ): Promise<SecretOperationResult<{ secret: BackendSecret; versions: SecretVersion[] }>> {
    const operationId = randomUUID();
    
    try {
      const hasAccess = await this.checkAccess(SecretAction.EXPORT, secretId, context);
      
      if (!hasAccess) {
        throw new SecretAccessError('Доступ запрещён', secretId);
      }
      
      const secret = await this.getSecret(secretId, context);
      
      if (!secret.success || !secret.data) {
        return {
          success: false,
          errorCode: secret.errorCode,
          errorMessage: secret.errorMessage,
          operationId
        };
      }
      
      const versions = await this.versioningManager.getAllVersions(secretId);
      
      this.logAudit({
        operation: SecretOperation.EXPORT,
        secretId,
        secretName: secretId,
        performedBy: context.subjectId,
        success: true,
        operationId
      });
      
      return {
        success: true,
        data: {
          secret: secret.data,
          versions
        },
        operationId
      };
      
    } catch (error) {
      return {
        success: false,
        errorCode: error instanceof Error ? error.name : 'UnknownError',
        errorMessage: error instanceof Error ? error.message : String(error),
        operationId
      };
    }
  }
}

/**
 * Фабрика для создания экземпляров SecretsManager
 */
export class SecretsManagerFactory {
  private static instance?: SecretsManager;

  /**
   * Получить singleton экземпляр
   * 
   * @param config - Конфигурация
   * @returns Экземпляр SecretsManager
   */
  static async getInstance(config: SecretsManagerConfig): Promise<SecretsManager> {
    if (!this.instance) {
      this.instance = new SecretsManager(config);
      await this.instance.initialize();
    }
    
    return this.instance;
  }

  /**
   * Создать новый экземпляр
   * 
   * @param config - Конфигурация
   * @returns Новый экземпляр
   */
  static async createInstance(config: SecretsManagerConfig): Promise<SecretsManager> {
    const instance = new SecretsManager(config);
    await instance.initialize();
    return instance;
  }

  /**
   * Очистить singleton
   */
  static async clearInstance(): Promise<void> {
    if (this.instance) {
      await this.instance.destroy();
      this.instance = undefined;
    }
  }
}

// ============================================================================
// ЭКСПОРТ ВСЕХ КОМПОНЕНТОВ
// ============================================================================

export {
  SecretCache,
  SecretCacheFactory,
  AccessPolicyManager,
  SecretVersioningManager,
  SecretLeaseManager,
  SecretRotator,
  DynamicSecretsManager,
  SecretScanner,
  VaultBackend,
  VaultBackendFactory,
  AWSSecretsBackend,
  AWSSecretsBackendFactory,
  GCPSecretBackend,
  GCPSecretBackendFactory,
  AzureKeyVaultBackend,
  AzureKeyVaultBackendFactory
};
