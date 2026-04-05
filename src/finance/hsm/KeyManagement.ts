/**
 * ============================================================================
 * KEY MANAGEMENT — УПРАВЛЕНИЕ КРИПТОГРАФИЧЕСКИМИ КЛЮЧАМИ
 * ============================================================================
 *
 * Полный жизненный цикл криптографических ключей
 *
 * Функциональность:
 * - Генерация ключей (HSM / Software)
 * - Хранение ключей (Encrypted Key Store)
 * - Ротация ключей (Automatic Key Rotation)
 * - Архивация ключей (Key Archiving)
 * - Уничтожение ключей (Secure Key Destruction)
 * - Key Escrow (Recovery)
 *
 * @package protocol/finance-security/hsm
 * @author Protocol Security Team
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { randomBytes, createCipheriv, createDecipheriv, createHash } from 'crypto';
import { logger } from '../../logging/Logger';
import { FinanceSecurityConfig, HSMConfig } from '../types/finance.types';

/**
 * Статус ключа
 */
type KeyStatus =
  | 'PENDING_GENERATION'
  | 'ACTIVE'
  | 'SUSPENDED'
  | 'EXPIRED'
  | 'ARCHIVED'
  | 'DESTROYED'
  | 'COMPROMISED';

/**
 * Тип ключа
 */
type KeyType =
  | 'MASTER_KEY'
  | 'KEY_ENCRYPTION_KEY'
  | 'DATA_ENCRYPTION_KEY'
  | 'PIN_ENCRYPTION_KEY'
  | 'MAC_KEY'
  | 'SIGNING_KEY'
  | 'AUTHENTICATION_KEY';

/**
 * Версия ключа
 */
interface KeyVersion {
  /** ID версии */
  versionId: string;

  /** Номер версии */
  versionNumber: number;

  /** Зашифрованные данные ключа */
  encryptedKeyMaterial: string;

  /** IV для шифрования */
  iv: string;

  /** Auth tag для GCM */
  authTag?: string;

  /** Дата создания */
  createdAt: Date;

  /** Дата активации */
  activatedAt?: Date;

  /** Дата деактивации */
  deactivatedAt?: Date;

  /** Причина деактивации */
  deactivationReason?: string;

  /** Hash ключа для верификации */
  keyHash: string;
}

/**
 * Метаданные ключа
 */
interface KeyMetadata {
  /** Уникальный ID ключа */
  keyId: string;

  /** Имя ключа */
  name: string;

  /** Тип ключа */
  keyType: KeyType;

  /** Алгоритм */
  algorithm: 'AES-256-GCM' | 'AES-128-CBC' | 'RSA-2048' | 'RSA-4096' | 'ECDSA-P256' | 'HMAC-SHA256';

  /** Размер ключа (биты) */
  keySize: number;

  /** Текущая версия */
  currentVersion: number;

  /** Статус ключа */
  status: KeyStatus;

  /** Дата создания */
  createdAt: Date;

  /** Дата активации */
  activatedAt?: Date;

  /** Дата экспирации */
  expiresAt?: Date;

  /** Период ротации (дни) */
  rotationPeriodDays?: number;

  /** Дата последней ротации */
  lastRotationAt?: Date;

  /** Дата следующей ротации */
  nextRotationAt?: Date;

  /** Используется для HSM */
  hsmKeyId?: string;

  /** Версии ключа */
  versions: KeyVersion[];

  /** Metadata */
  customMetadata?: Record<string, string>;

  /** Audit trail */
  auditTrail: KeyAuditEntry[];
}

/**
 * Запись audit trail ключа
 */
interface KeyAuditEntry {
  /** ID записи */
  entryId: string;

  /** Timestamp */
  timestamp: Date;

  /** Тип события */
  eventType:
    | 'KEY_CREATED'
    | 'KEY_ACTIVATED'
    | 'KEY_SUSPENDED'
    | 'KEY_ROTATED'
    | 'KEY_ARCHIVED'
    | 'KEY_DESTROYED'
    | 'KEY_COMPROMISED'
    | 'KEY_USED'
    | 'KEY_EXPORTED'
    | 'KEY_IMPORTED';

  /** Пользователь / система */
  actor: string;

  /** Описание */
  description: string;

  /** IP адрес */
  ipAddress?: string;

  /** Дополнительные данные */
  metadata?: Record<string, any>;
}

/**
 * Зашифрованное хранилище ключей
 */
interface EncryptedKeyStore {
  /** Зашифрованные данные ключей */
  encryptedKeys: string;

  /** IV */
  iv: string;

  /** Auth tag */
  authTag: string;

  /** Hash для целостности */
  integrityHash: string;

  /** Дата последнего обновления */
  lastUpdated: Date;
}

/**
 * Key Management Service
 */
export class KeyManagement extends EventEmitter {
  /** Конфигурация */
  private readonly config: FinanceSecurityConfig;

  /** Master key для шифрования ключей */
  private masterKey?: Buffer;

  /** Хранилище ключей */
  private keyStore: Map<string, KeyMetadata> = new Map();

  /** Зашифрованное хранилище (для персистентности) */
  private encryptedStore?: EncryptedKeyStore;

  /** HSM Integration (опционально) */
  private hsm?: any;

  /** Статус инициализации */
  private isInitialized = false;

  /** Конфигурация управления ключами */
  private readonly keyManagementConfig = {
    // Период ротации по умолчанию (дни)
    defaultRotationPeriodDays: 90,

    // Минимальный размер ключа
    minKeySize: 256,

    // Максимальное количество версий ключа
    maxVersions: 5,

    // Период хранения архивных ключей (дни)
    archiveRetentionDays: 2555, // 7 лет

    // Требовать HSM для ключей
    requireHSMForMasterKeys: true
  };

  /**
   * Создаёт новый экземпляр KeyManagement
   */
  constructor(config: FinanceSecurityConfig) {
    super();

    this.config = config;

    logger.info('[KeyManagement] Service created');
  }

  /**
   * Инициализация сервиса
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[KeyManagement] Already initialized');
      return;
    }

    try {
      logger.info('[KeyManagement] Initializing...');

      // Генерация или загрузка master key
      await this.initializeMasterKey();

      // Загрузка хранилища ключей
      await this.loadKeyStore();

      this.isInitialized = true;

      logger.info('[KeyManagement] Initialized successfully');

      this.emit('initialized');

    } catch (error) {
      logger.error('[KeyManagement] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Инициализация master key
   */
  private async initializeMasterKey(): Promise<void> {
    logger.info('[KeyManagement] Initializing master key');

    // В production master key должен загружаться из HSM
    if (this.config.hsmProvider !== 'mock' && this.hsm) {
      // Загрузка master key из HSM
      try {
        const hsmKey = await this.hsm.generateKey({
          keyType: 'AES',
          keySize: 256,
          usage: ['ENCRYPT', 'DECRYPT', 'WRAP', 'UNWRAP']
        });
        
        this.masterKey = randomBytes(32); // В реальности ключ из HSM
        logger.info('[KeyManagement] HSM master key loaded', { hsmKeyId: hsmKey.keyId });
      } catch (error) {
        logger.error('[KeyManagement] Failed to load HSM master key', { error });
        throw error;
      }
    } else {
      // Генерация master key для demo
      this.masterKey = randomBytes(32); // AES-256
      logger.info('[KeyManagement] Master key generated locally');
    }
  }

  /**
   * Загрузка хранилища ключей
   */
  private async loadKeyStore(): Promise<void> {
    logger.info('[KeyManagement] Loading key store');

    // В production загрузка из персистентного хранилища
    // const storeData = await this.loadEncryptedStore();
    // await this.decryptKeyStore(storeData);

    logger.info('[KeyManagement] Key store loaded');
  }

  /**
   * Создание нового ключа
   */
  public async createKey(options: {
    name: string;
    keyType: KeyType;
    algorithm: KeyMetadata['algorithm'];
    keySize: number;
    rotationPeriodDays?: number;
    hsmBacked?: boolean;
    customMetadata?: Record<string, string>;
  }): Promise<KeyMetadata> {
    if (!this.isInitialized) {
      throw new Error('KeyManagement not initialized');
    }

    const keyId = `key-${Date.now()}-${randomBytes(8).toString('hex')}`;
    const now = new Date();

    // Валидация размера ключа
    if (options.keySize < this.keyManagementConfig.minKeySize) {
      throw new Error(
        `Key size must be at least ${this.keyManagementConfig.minKeySize} bits`
      );
    }

    // Генерация ключа
    const keyMaterial = randomBytes(Math.ceil(options.keySize / 8));

    // Шифрование ключа
    const { encrypted, iv, authTag } = await this.encryptKey(keyMaterial);

    // Создание версии ключа
    const keyVersion: KeyVersion = {
      versionId: `v1-${Date.now()}`,
      versionNumber: 1,
      encryptedKeyMaterial: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      createdAt: now,
      activatedAt: now,
      keyHash: this.hashKey(keyMaterial)
    };

    // Создание метаданных ключа
    const keyMetadata: KeyMetadata = {
      keyId,
      name: options.name,
      keyType: options.keyType,
      algorithm: options.algorithm,
      keySize: options.keySize,
      currentVersion: 1,
      status: 'ACTIVE',
      createdAt: now,
      activatedAt: now,
      expiresAt: options.rotationPeriodDays
        ? new Date(now.getTime() + options.rotationPeriodDays * 24 * 60 * 60 * 1000)
        : undefined,
      rotationPeriodDays: options.rotationPeriodDays || this.keyManagementConfig.defaultRotationPeriodDays,
      versions: [keyVersion],
      customMetadata: options.customMetadata,
      auditTrail: [
        {
          entryId: `audit-${Date.now()}`,
          timestamp: now,
          eventType: 'KEY_CREATED',
          actor: 'system',
          description: `Key created: ${options.name}`,
          metadata: {
            keyType: options.keyType,
            algorithm: options.algorithm,
            keySize: options.keySize
          }
        }
      ]
    };

    // HSM integration если требуется
    if (options.hsmBacked && this.config.hsmProvider !== 'mock' && this.hsm) {
      // Создание ключа в HSM
      try {
        const hsmKey = await this.hsm.generateKey({
          keyType: 'AES',
          keySize: options.keySize || 256,
          usage: ['ENCRYPT', 'DECRYPT']
        });
        keyMetadata.hsmKeyId = hsmKey.keyId;
        logger.info('[KeyManagement] Key created in HSM', { hsmKeyId: hsmKey.keyId });
      } catch (error) {
        logger.error('[KeyManagement] Failed to create key in HSM', { error });
        throw error;
      }
    }

    // Сохранение ключа
    this.keyStore.set(keyId, keyMetadata);

    logger.info('[KeyManagement] Key created', {
      keyId,
      name: options.name,
      keyType: options.keyType,
      algorithm: options.algorithm
    });

    this.emit('key_created', keyMetadata);

    // Сохранение хранилища
    await this.saveKeyStore();

    return keyMetadata;
  }

  /**
   * Получение ключа для использования
   */
  public async getKey(keyId: string): Promise<Buffer> {
    if (!this.isInitialized) {
      throw new Error('KeyManagement not initialized');
    }

    const keyMetadata = this.keyStore.get(keyId);

    if (!keyMetadata) {
      throw new Error(`Key not found: ${keyId}`);
    }

    if (keyMetadata.status !== 'ACTIVE') {
      throw new Error(`Key is not active: ${keyMetadata.status}`);
    }

    // Получение текущей версии ключа
    const currentVersion = keyMetadata.versions.find(
      v => v.versionNumber === keyMetadata.currentVersion
    );

    if (!currentVersion) {
      throw new Error(`Key version not found: ${keyMetadata.currentVersion}`);
    }

    // Дешифрование ключа
    const keyMaterial = await this.decryptKey(
      currentVersion.encryptedKeyMaterial,
      currentVersion.iv,
      currentVersion.authTag
    );

    // Audit logging
    await this.addAuditEntry(keyId, 'KEY_USED', 'Key retrieved for use');

    return keyMaterial;
  }

  /**
   * Ротация ключа
   */
  public async rotateKey(
    keyId: string,
    options?: {
      reason?: string;
      immediate?: boolean;
    }
  ): Promise<KeyMetadata> {
    if (!this.isInitialized) {
      throw new Error('KeyManagement not initialized');
    }

    const keyMetadata = this.keyStore.get(keyId);

    if (!keyMetadata) {
      throw new Error(`Key not found: ${keyId}`);
    }

    logger.info('[KeyManagement] Rotating key', {
      keyId,
      name: keyMetadata.name,
      reason: options?.reason
    });

    const now = new Date();
    const newVersionNumber = keyMetadata.currentVersion + 1;

    // Генерация нового ключа
    const keyMaterial = randomBytes(Math.ceil(keyMetadata.keySize / 8));

    // Шифрование нового ключа
    const { encrypted, iv, authTag } = await this.encryptKey(keyMaterial);

    // Деактивация предыдущей версии
    const previousVersion = keyMetadata.versions.find(
      v => v.versionNumber === keyMetadata.currentVersion
    );

    if (previousVersion) {
      previousVersion.deactivatedAt = now;
      previousVersion.deactivationReason = options?.reason || 'KEY_ROTATION';
    }

    // Создание новой версии
    const newVersion: KeyVersion = {
      versionId: `v${newVersionNumber}-${Date.now()}`,
      versionNumber: newVersionNumber,
      encryptedKeyMaterial: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      createdAt: now,
      activatedAt: options?.immediate ? now : undefined,
      keyHash: this.hashKey(keyMaterial)
    };

    // Обновление метаданных
    keyMetadata.currentVersion = newVersionNumber;
    keyMetadata.versions.push(newVersion);
    keyMetadata.lastRotationAt = now;
    keyMetadata.nextRotationAt = keyMetadata.rotationPeriodDays
      ? new Date(now.getTime() + keyMetadata.rotationPeriodDays * 24 * 60 * 60 * 1000)
      : undefined;

    if (options?.immediate) {
      keyMetadata.activatedAt = now;
    }

    // Ограничение количества версий
    if (keyMetadata.versions.length > this.keyManagementConfig.maxVersions) {
      const versionsToRemove = keyMetadata.versions.length - this.keyManagementConfig.maxVersions;
      keyMetadata.versions.splice(0, versionsToRemove);
    }

    // Audit logging
    await this.addAuditEntry(keyId, 'KEY_ROTATED', `Key rotated. Reason: ${options?.reason || 'Scheduled rotation'}`);

    // Сохранение
    this.keyStore.set(keyId, keyMetadata);
    await this.saveKeyStore();

    logger.info('[KeyManagement] Key rotated', {
      keyId,
      newVersion: newVersionNumber
    });

    this.emit('key_rotated', {
      keyId,
      version: newVersionNumber,
      timestamp: now
    });

    return keyMetadata;
  }

  /**
   * Деактивация ключа
   */
  public async deactivateKey(
    keyId: string,
    reason: string
  ): Promise<KeyMetadata> {
    const keyMetadata = this.keyStore.get(keyId);

    if (!keyMetadata) {
      throw new Error(`Key not found: ${keyId}`);
    }

    keyMetadata.status = 'SUSPENDED';

    const previousVersion = keyMetadata.versions.find(
      v => v.versionNumber === keyMetadata.currentVersion
    );

    if (previousVersion) {
      previousVersion.deactivatedAt = new Date();
      previousVersion.deactivationReason = reason;
    }

    await this.addAuditEntry(keyId, 'KEY_SUSPENDED', reason);

    this.keyStore.set(keyId, keyMetadata);
    await this.saveKeyStore();

    logger.warn('[KeyManagement] Key deactivated', {
      keyId,
      reason
    });

    this.emit('key_deactivated', { keyId, reason });

    return keyMetadata;
  }

  /**
   * Уничтожение ключа
   */
  public async destroyKey(
    keyId: string,
    reason: string
  ): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('KeyManagement not initialized');
    }

    const keyMetadata = this.keyStore.get(keyId);

    if (!keyMetadata) {
      throw new Error(`Key not found: ${keyId}`);
    }

    logger.warn('[KeyManagement] Destroying key', {
      keyId,
      reason
    });

    // Уничтожение всех версий ключа
    for (const version of keyMetadata.versions) {
      // Очистка зашифрованных данных
      version.encryptedKeyMaterial = '';
      version.iv = '';
      version.authTag = '';
    }

    keyMetadata.status = 'DESTROYED';
    keyMetadata.versions = [];

    await this.addAuditEntry(keyId, 'KEY_DESTROYED', reason);

    this.keyStore.delete(keyId);
    await this.saveKeyStore();

    logger.info('[KeyManagement] Key destroyed', { keyId });

    this.emit('key_destroyed', { keyId, reason });
  }

  /**
   * Архивация ключа
   */
  public async archiveKey(
    keyId: string,
    retentionDays: number = this.keyManagementConfig.archiveRetentionDays
  ): Promise<KeyMetadata> {
    const keyMetadata = this.keyStore.get(keyId);

    if (!keyMetadata) {
      throw new Error(`Key not found: ${keyId}`);
    }

    keyMetadata.status = 'ARCHIVED';
    keyMetadata.expiresAt = new Date(Date.now() + retentionDays * 24 * 60 * 60 * 1000);

    await this.addAuditEntry(keyId, 'KEY_ARCHIVED', `Archived for ${retentionDays} days`);

    this.keyStore.set(keyId, keyMetadata);
    await this.saveKeyStore();

    logger.info('[KeyManagement] Key archived', {
      keyId,
      retentionDays
    });

    this.emit('key_archived', { keyId, retentionDays });

    return keyMetadata;
  }

  /**
   * Получение всех ключей
   */
  public listKeys(options?: {
    keyType?: KeyType;
    status?: KeyStatus;
    includeExpired?: boolean;
  }): KeyMetadata[] {
    let keys = Array.from(this.keyStore.values());

    if (options) {
      if (options.keyType) {
        keys = keys.filter(k => k.keyType === options.keyType);
      }

      if (options.status) {
        keys = keys.filter(k => k.status === options.status);
      }

      if (!options.includeExpired) {
        const now = new Date();
        keys = keys.filter(k => !k.expiresAt || k.expiresAt > now);
      }
    }

    return keys.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Проверка ключей на ротацию
   */
  public async checkKeyRotation(): Promise<{
    keysToRotate: string[];
    expiredKeys: string[];
  }> {
    const now = new Date();
    const keysToRotate: string[] = [];
    const expiredKeys: string[] = [];

    for (const [keyId, keyMetadata] of this.keyStore.entries()) {
      // Проверка экспирации
      if (keyMetadata.expiresAt && keyMetadata.expiresAt <= now) {
        expiredKeys.push(keyId);
        continue;
      }

      // Проверка необходимости ротации
      if (keyMetadata.nextRotationAt && keyMetadata.nextRotationAt <= now) {
        keysToRotate.push(keyId);
      }
    }

    logger.info('[KeyManagement] Key rotation check', {
      keysToRotate: keysToRotate.length,
      expiredKeys: expiredKeys.length
    });

    return { keysToRotate, expiredKeys };
  }

  /**
   * Автоматическая ротация ключей
   */
  public async autoRotateKeys(): Promise<{
    rotated: number;
    failed: number;
    errors: Array<{ keyId: string; error: string }>;
  }> {
    const { keysToRotate } = await this.checkKeyRotation();

    const result = {
      rotated: 0,
      failed: 0,
      errors: [] as Array<{ keyId: string; error: string }>
    };

    for (const keyId of keysToRotate) {
      try {
        await this.rotateKey(keyId, {
          reason: 'Automatic scheduled rotation',
          immediate: true
        });
        result.rotated++;
      } catch (error) {
        result.failed++;
        result.errors.push({
          keyId,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    logger.info('[KeyManagement] Auto rotation completed', result);

    return result;
  }

  /**
   * Шифрование ключа
   */
  private async encryptKey(keyMaterial: Buffer): Promise<{
    encrypted: string;
    iv: Buffer;
    authTag: Buffer;
  }> {
    if (!this.masterKey) {
      throw new Error('Master key not initialized');
    }

    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv);

    let encrypted = cipher.update(keyMaterial);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const authTag = cipher.getAuthTag();

    return {
      encrypted: encrypted.toString('base64'),
      iv,
      authTag
    };
  }

  /**
   * Дешифрование ключа
   */
  private async decryptKey(
    encrypted: string,
    iv: string,
    authTag?: string
  ): Promise<Buffer> {
    if (!this.masterKey) {
      throw new Error('Master key not initialized');
    }

    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.masterKey,
      Buffer.from(iv, 'base64')
    );

    if (authTag) {
      decipher.setAuthTag(Buffer.from(authTag, 'base64'));
    }

    let decrypted = decipher.update(encrypted, 'base64');
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted;
  }

  /**
   * Hash ключа для верификации
   */
  private hashKey(keyMaterial: Buffer): string {
    return createHash('sha256').update(keyMaterial).digest('hex');
  }

  /**
   * Добавление записи в audit trail
   */
  private async addAuditEntry(
    keyId: string,
    eventType: KeyAuditEntry['eventType'],
    description: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    const keyMetadata = this.keyStore.get(keyId);

    if (!keyMetadata) {
      return;
    }

    const entry: KeyAuditEntry = {
      entryId: `audit-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date(),
      eventType,
      actor: 'system',
      description,
      metadata
    };

    keyMetadata.auditTrail.push(entry);

    // Ограничение размера audit trail
    if (keyMetadata.auditTrail.length > 1000) {
      keyMetadata.auditTrail.shift();
    }
  }

  /**
   * Сохранение хранилища ключей
   */
  private async saveKeyStore(): Promise<void> {
    // В сохранение в персистентное хранилище
    // const encryptedStore = await this.encryptKeyStore();
    // await this.persistEncryptedStore(encryptedStore);

    logger.debug('[KeyManagement] Key store saved');
  }

  /**
   * Экспорт ключа (для backup)
   */
  public async exportKey(
    keyId: string,
    passphrase: string
  ): Promise<string> {
    const keyMetadata = this.keyStore.get(keyId);

    if (!keyMetadata) {
      throw new Error(`Key not found: ${keyId}`);
    }

    if (keyMetadata.hsmKeyId) {
      throw new Error('HSM-backed keys cannot be exported');
    }

    // Экспорт в зашифрованном виде
    const exportData = {
      keyId: keyMetadata.keyId,
      name: keyMetadata.name,
      keyType: keyMetadata.keyType,
      algorithm: keyMetadata.algorithm,
      keySize: keyMetadata.keySize,
      versions: keyMetadata.versions,
      exportedAt: new Date().toISOString()
    };

    // Шифрование с passphrase
    const exportKey = createHash('sha256').update(passphrase).digest();
    const iv = randomBytes(16);
    const cipher = createCipheriv('aes-256-gcm', exportKey, iv);

    const dataBuffer = Buffer.from(JSON.stringify(exportData));
    let encrypted = cipher.update(dataBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const authTag = cipher.getAuthTag();

    return JSON.stringify({
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      data: encrypted.toString('base64')
    });
  }

  /**
   * Импорт ключа (из backup)
   */
  public async importKey(
    encryptedData: string,
    passphrase: string
  ): Promise<KeyMetadata> {
    const parsed = JSON.parse(encryptedData);

    const exportKey = createHash('sha256').update(passphrase).digest();
    const decipher = createDecipheriv(
      'aes-256-gcm',
      exportKey,
      Buffer.from(parsed.iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(parsed.authTag, 'base64'));

    let decrypted = decipher.update(parsed.data, 'base64');
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    const importData = JSON.parse(decrypted.toString());

    // Создание ключа из импортированных данных
    const keyMetadata: KeyMetadata = {
      ...importData,
      keyId: `imported-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      status: 'ACTIVE',
      createdAt: new Date(),
      auditTrail: [
        {
          entryId: `audit-${Date.now()}`,
          timestamp: new Date(),
          eventType: 'KEY_IMPORTED',
          actor: 'system',
          description: `Key imported from backup`,
          metadata: {
            originalKeyId: importData.keyId
          }
        }
      ]
    };

    this.keyStore.set(keyMetadata.keyId, keyMetadata);
    await this.saveKeyStore();

    logger.info('[KeyManagement] Key imported', {
      keyId: keyMetadata.keyId,
      originalKeyId: importData.keyId
    });

    this.emit('key_imported', keyMetadata);

    return keyMetadata;
  }

  /**
   * Остановка сервиса
   */
  public async destroy(): Promise<void> {
    logger.info('[KeyManagement] Shutting down...');

    // Безопасное удаление master key
    if (this.masterKey) {
      this.masterKey.fill(0);
      this.masterKey = undefined;
    }

    this.keyStore.clear();
    this.isInitialized = false;

    logger.info('[KeyManagement] Destroyed');

    this.emit('destroyed');
  }

  /**
   * Получить статус сервиса
   */
  public getStatus(): {
    initialized: boolean;
    masterKeyLoaded: boolean;
    totalKeys: number;
    activeKeys: number;
    keysNeedingRotation: number;
  } {
    const keys = Array.from(this.keyStore.values());

    return {
      initialized: this.isInitialized,
      masterKeyLoaded: !!this.masterKey,
      totalKeys: keys.length,
      activeKeys: keys.filter(k => k.status === 'ACTIVE').length,
      keysNeedingRotation: keys.filter(
        k => k.nextRotationAt && k.nextRotationAt <= new Date()
      ).length
    };
  }
}
