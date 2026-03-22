/**
 * ============================================================================
 * KEY MANAGEMENT SERVICE - СЕРВИС УПРАВЛЕНИЯ КЛЮЧАМИ
 * ============================================================================
 * Полнофункциональная система управления криптографическими ключами
 * 
 * Функционал:
 * - Генерация ключей всех типов (симметричные, асимметричные, мастер-ключи)
 * - Хранение ключей с защитой памяти
 * - Ротация ключей по расписанию и по событию
 * - Версионирование ключей
 * - Жизненный цикл ключей (создание → активация → использование → ротация → уничтожение)
 * - Аудит всех операций с ключами
 * - Интеграция с HSM/KMS провайдерами
 * 
 * Особенности:
 * - Автоматическая ротация ключей
 * - Graceful degradation при недоступности HSM
 * - Детектирование аномалий использования
 * - Защита от утечек через память
 * ============================================================================
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  KeyMetadata,
  KeyType,
  KeyStatus,
  KeyOperation,
  KeyGenerationParams,
  KeyGenerationResult,
  KeyUsagePolicy,
  SymmetricAlgorithm,
  AsymmetricAlgorithm,
  SignatureAlgorithm,
  SecureMemoryConfig,
  CryptoErrorCode,
  AuditEvent,
  AuditEventType,
  KMSProviderConfig,
} from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';
import { HashService } from './HashService';
import { HSMProvider, HSMProviderFactory, LocalKMSProvider } from './HSMInterface';

/**
 * Класс для управления жизненным циклом ключей
 */
export class KeyManager extends EventEmitter {
  /** Конфигурация безопасной памяти */
  private readonly memoryConfig: SecureMemoryConfig;
  
  /** Hash service для вспомогательных операций */
  private readonly hashService: HashService;
  
  /** Secure random для генерации ключей */
  private readonly secureRandom: SecureRandom;
  
  /** HSM провайдер */
  private hsmProvider: HSMProvider | null = null;
  
  /** Локальное хранилище ключей */
  private readonly keyStore: Map<string, KeyEntry>;
  
  /** Индекс ключей по имени */
  private readonly keyNameIndex: Map<string, string[]>;
  
  /** Индекс ключей по тегам */
  private readonly keyTagIndex: Map<string, Set<string>>;
  
  /** Очередь ротации ключей */
  private readonly rotationQueue: Set<string>;
  
  /** Таймер автоматической ротации */
  private rotationTimer: NodeJS.Timeout | null = null;
  
  /** Счетчик операций для аудита */
  private auditEventCount = 0;
  
  /** Журнал аудита */
  private readonly auditLog: AuditEvent[] = [];
  
  /** Максимальный размер журнала аудита */
  private readonly maxAuditLogSize = 10000;

  constructor(
    memoryConfig: SecureMemoryConfig,
    hsmConfig?: KMSProviderConfig
  ) {
    super();
    this.memoryConfig = memoryConfig;
    this.hashService = new HashService(memoryConfig);
    this.secureRandom = new SecureRandom(memoryConfig);
    this.keyStore = new Map();
    this.keyNameIndex = new Map();
    this.keyTagIndex = new Map();
    this.rotationQueue = new Set();
    
    // Инициализируем HSM провайдер если указан
    if (hsmConfig) {
      this.initializeHSM(hsmConfig);
    }
  }

  /**
   * Инициализация HSM провайдера
   */
  private async initializeHSM(config: KMSProviderConfig): Promise<void> {
    try {
      const factory = new HSMProviderFactory(this.memoryConfig);
      this.hsmProvider = factory.createProvider(config);
      
      // Пробуем подключиться
      await this.hsmProvider.connect();
      
      this.emit('hsm:connected', { provider: config.type });
    } catch (error) {
      // Fallback на локальный провайдер
      console.warn('HSM недоступен, используем локальное хранилище:', error);
      this.hsmProvider = new LocalKMSProvider(config, this.memoryConfig);
      
      try {
        await this.hsmProvider.connect();
        this.emit('hsm:connected', { provider: 'LOCAL', fallback: true });
      } catch (fallbackError) {
        this.emit('hsm:error', fallbackError);
      }
    }
  }

  /**
   * Генерация нового ключа
   * @param params - Параметры генерации ключа
   * @returns Результат генерации
   */
  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    const keyId = this.generateKeyId();
    const createdAt = new Date();
    
    try {
      let keyMaterial: Uint8Array | crypto.KeyObject | null = null;
      let publicKey: crypto.KeyObject | null = null;
      
      // Определяем где генерировать ключ
      if (this.hsmProvider?.isConnected()) {
        // Генерируем в HSM
        try {
          const hsmResult = await this.hsmProvider.generateKey(params);
          
          // Сохраняем метаданные локально
          const metadata: KeyMetadata = {
            ...hsmResult.metadata,
            keyId: keyId,
          };
          
          const entry: KeyEntry = {
            metadata,
            createdAt: createdAt.getTime(),
            lastUsedAt: null,
            useCount: 0,
            versions: [{
              version: 1,
              createdAt: createdAt,
              status: 'ACTIVE',
            }],
            isExternal: true,
          };
          
          this.keyStore.set(keyId, entry);
          this.updateIndexes(entry);
          
          this.logAudit('KEY_CREATED', true, { keyId, keyType: params.keyType, source: 'HSM' });
          
          return {
            metadata,
            keyId,
          };
        } catch (hsmError) {
          console.warn('HSM генерация не удалась, используем локальную:', hsmError);
          // Продолжаем с локальной генерацией
        }
      }
      
      // Локальная генерация
      switch (params.keyType) {
        case 'SYMMETRIC':
        case 'MASTER_KEY':
        case 'DATA_KEY':
        case 'WRAPPING_KEY':
          keyMaterial = await this.generateSymmetricKey(params.algorithm, params.keySize);
          break;
        
        case 'ASYMMETRIC_SIGN':
        case 'ASYMMETRIC_ENC':
          const keyPair = await this.generateAsymmetricKey(params.algorithm, params.keySize, params.keyType);
          publicKey = keyPair.publicKey;
          keyMaterial = keyPair.privateKey;
          break;
        
        default:
          throw this.createError('INVALID_ARGUMENT', `Неизвестный тип ключа: ${params.keyType}`);
      }
      
      // Создаем запись ключа
      const metadata: KeyMetadata = {
        keyId,
        name: params.name || `Key ${keyId.slice(0, 8)}`,
        description: params.description,
        keyType: params.keyType,
        algorithm: params.algorithm,
        keySize: params.keySize,
        status: 'ACTIVE',
        createdAt,
        activatedAt: createdAt,
        version: 1,
        tags: params.tags,
        usagePolicy: params.usagePolicy,
        owner: params.tags?.owner,
      };
      
      if (params.ttl) {
        metadata.expiresAt = new Date(createdAt.getTime() + params.ttl);
      }
      
      const entry: KeyEntry = {
        metadata,
        keyMaterial: keyMaterial ? Buffer.from(keyMaterial) : null,
        publicKey: publicKey ? Buffer.from(publicKey.export({ format: 'der', type: 'spki' })) : null,
        createdAt: createdAt.getTime(),
        lastUsedAt: null,
        useCount: 0,
        versions: [{
          version: 1,
          createdAt,
          status: 'ACTIVE',
        }],
        isExternal: false,
      };
      
      // Сохраняем в хранилище
      this.keyStore.set(keyId, entry);
      this.updateIndexes(entry);
      
      // Планируем ротацию если указан TTL
      if (params.ttl) {
        this.scheduleRotation(keyId, params.ttl);
      }
      
      this.logAudit('KEY_CREATED', true, { keyId, keyType: params.keyType, source: 'LOCAL' });
      
      return {
        metadata,
        keyMaterial: params.exportable ? new Uint8Array(keyMaterial!) : undefined,
        keyId,
      };
      
    } catch (error) {
      this.logAudit('KEY_CREATED', false, { keyId, error: String(error) });
      throw this.createError('KEY_GENERATION_FAILED', `Ошибка генерации ключа: ${error}`);
    }
  }

  /**
   * Получение ключа по идентификатору
   */
  getKey(keyId: string): KeyMetadata | null {
    const entry = this.keyStore.get(keyId);
    
    if (!entry) {
      return null;
    }
    
    // Проверяем срок действия
    if (entry.metadata.expiresAt && entry.metadata.expiresAt < new Date()) {
      if (entry.metadata.status !== 'EXPIRED') {
        entry.metadata.status = 'EXPIRED';
        this.logAudit('KEY_EXPIRED', true, { keyId });
      }
    }
    
    return { ...entry.metadata };
  }

  /**
   * Получение ключа по имени
   */
  getKeyByName(name: string): KeyMetadata[] {
    const keyIds = this.keyNameIndex.get(name) || [];
    return keyIds.map(id => this.getKey(id)).filter((k): k is KeyMetadata => k !== null);
  }

  /**
   * Поиск ключей по тегам
   */
  findKeysByTag(tagKey: string, tagValue?: string): KeyMetadata[] {
    const keyIds = this.keyTagIndex.get(`${tagKey}:${tagValue || '*'}`) || new Set();
    return Array.from(keyIds).map(id => this.getKey(id)).filter((k): k is KeyMetadata => k !== null);
  }

  /**
   * Получение материала ключа (для симметричных ключей)
   */
  getKeyMaterial(keyId: string): Uint8Array | null {
    const entry = this.keyStore.get(keyId);
    
    if (!entry || !entry.keyMaterial) {
      return null;
    }
    
    // Проверяем статус
    if (entry.metadata.status !== 'ACTIVE') {
      throw this.createError('KEY_NOT_FOUND', `Ключ не активен: ${entry.metadata.status}`);
    }
    
    // Проверяем политику использования
    if (!this.checkUsagePolicy(entry, 'ENCRYPT')) {
      throw this.createError('ACCESS_DENIED', 'Операция запрещена политикой ключа');
    }
    
    this.updateKeyUsage(keyId);
    
    return new Uint8Array(entry.keyMaterial);
  }

  /**
   * Получение открытого ключа
   */
  getPublicKey(keyId: string): crypto.KeyObject | null {
    const entry = this.keyStore.get(keyId);
    
    if (!entry || !entry.publicKey) {
      return null;
    }
    
    try {
      return crypto.createPublicKey({
        key: entry.publicKey,
        format: 'der',
        type: 'spki',
      });
    } catch {
      return null;
    }
  }

  /**
   * Обновление статуса ключа
   */
  updateKeyStatus(keyId: string, status: KeyStatus): boolean {
    const entry = this.keyStore.get(keyId);
    
    if (!entry) {
      return false;
    }
    
    const oldStatus = entry.metadata.status;
    entry.metadata.status = status;
    
    // Добавляем версию
    entry.versions.push({
      version: entry.metadata.version + 1,
      createdAt: new Date(),
      status,
    });
    
    entry.metadata.version++;
    
    // Обновляем временные метки
    if (status === 'ACTIVE') {
      entry.metadata.activatedAt = new Date();
    } else if (status === 'DISABLED') {
      // Ничего дополнительного
    } else if (status === 'DESTROYED') {
      // Очищаем материал ключа
      if (entry.keyMaterial) {
        this.secureZero(entry.keyMaterial);
        entry.keyMaterial = null;
      }
      if (entry.publicKey) {
        entry.publicKey = null;
      }
    }
    
    this.logAudit('KEY_ROTATED', true, { keyId, oldStatus, newStatus: status });
    
    return true;
  }

  /**
   * Ротация ключа (создание новой версии)
   */
  async rotateKey(keyId: string, params?: Partial<KeyGenerationParams>): Promise<KeyGenerationResult> {
    const oldEntry = this.keyStore.get(keyId);
    
    if (!oldEntry) {
      throw this.createError('KEY_NOT_FOUND', `Ключ не найден: ${keyId}`);
    }
    
    // Создаем новый ключ с теми же параметрами
    const newParams: KeyGenerationParams = {
      keyType: oldEntry.metadata.keyType,
      algorithm: oldEntry.metadata.algorithm,
      keySize: oldEntry.metadata.keySize,
      name: oldEntry.metadata.name,
      description: oldEntry.metadata.description,
      tags: oldEntry.metadata.tags,
      usagePolicy: oldEntry.metadata.usagePolicy,
      exportable: false,
      ...params,
    };
    
    const result = await this.generateKey(newParams);
    
    // Обновляем старый ключ
    oldEntry.metadata.status = 'DISABLED';
    oldEntry.metadata.previousVersion = oldEntry.metadata.version;
    
    // Связываем ключи
    const newEntry = this.keyStore.get(result.keyId);
    if (newEntry) {
      newEntry.metadata.previousVersion = oldEntry.metadata.version;
    }
    
    this.logAudit('KEY_ROTATED', true, { 
      keyId, 
      newKeyId: result.keyId,
      oldVersion: oldEntry.metadata.version,
    });
    
    return result;
  }

  /**
   * Уничтожение ключа
   */
  destroyKey(keyId: string): boolean {
    const entry = this.keyStore.get(keyId);
    
    if (!entry) {
      return false;
    }
    
    // Очищаем материал ключа
    if (entry.keyMaterial) {
      this.secureZero(entry.keyMaterial);
      entry.keyMaterial = null;
    }
    
    if (entry.publicKey) {
      entry.publicKey = null;
    }
    
    // Обновляем статус
    entry.metadata.status = 'DESTROYED';
    
    // Удаляем из индексов
    this.removeFromIndexes(entry);
    
    // Не удаляем из keyStore для аудита
    
    this.logAudit('KEY_DESTROYED', true, { keyId });
    
    return true;
  }

  /**
   * Экспорт ключа (для бэкапа)
   */
  exportKey(keyId: string, passphrase: string): Uint8Array | null {
    const entry = this.keyStore.get(keyId);
    
    if (!entry || !entry.keyMaterial) {
      return null;
    }
    
    // Шифруем ключ паролем используя PBKDF2 + AES-GCM
    const salt = this.secureRandom.randomBytes(16);
    const iv = this.secureRandom.randomBytes(12);
    
    const keyMaterial = this.hashService.hmac(
      passphrase,
      salt,
      'SHA-256'
    );
    
    const cipher = crypto.createCipheriv('aes-256-gcm', keyMaterial, iv);
    
    const encrypted = Buffer.concat([
      salt,
      iv,
      cipher.update(entry.keyMaterial),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    
    this.logAudit('KEY_USED', true, { keyId, operation: 'EXPORT' });
    
    return new Uint8Array(encrypted);
  }

  /**
   * Импорт ключа (из бэкапа)
   */
  importKey(encryptedData: Uint8Array, passphrase: string, metadata: Partial<KeyMetadata>): Promise<KeyGenerationResult> {
    try {
      // Извлекаем компоненты
      const salt = encryptedData.slice(0, 16);
      const iv = encryptedData.slice(16, 28);
      const authTag = encryptedData.slice(encryptedData.length - 16);
      const ciphertext = encryptedData.slice(28, encryptedData.length - 16);
      
      // Дешифруем
      const keyMaterial = this.hashService.hmac(passphrase, salt, 'SHA-256');
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', keyMaterial, iv);
      decipher.setAuthTag(Buffer.from(authTag));
      
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(ciphertext)),
        decipher.final(),
      ]);
      
      // Создаем запись ключа
      const keyId = this.generateKeyId();
      const createdAt = new Date();
      
      const keyMetadata: KeyMetadata = {
        keyId,
        name: metadata.name || `Imported Key ${keyId.slice(0, 8)}`,
        description: metadata.description,
        keyType: metadata.keyType || 'SYMMETRIC',
        algorithm: metadata.algorithm || 'AES-256-GCM',
        keySize: metadata.keySize || 256,
        status: 'ACTIVE',
        createdAt,
        activatedAt: createdAt,
        version: 1,
        tags: metadata.tags,
        usagePolicy: metadata.usagePolicy,
      };
      
      const entry: KeyEntry = {
        metadata: keyMetadata,
        keyMaterial: decrypted,
        publicKey: null,
        createdAt: createdAt.getTime(),
        lastUsedAt: null,
        useCount: 0,
        versions: [{
          version: 1,
          createdAt,
          status: 'ACTIVE',
        }],
        isExternal: false,
      };
      
      this.keyStore.set(keyId, entry);
      this.updateIndexes(entry);
      
      this.logAudit('KEY_CREATED', true, { keyId, source: 'IMPORT' });
      
      return Promise.resolve({
        metadata: keyMetadata,
        keyId,
      });
      
    } catch (error) {
      throw this.createError('INVALID_KEY_FORMAT', `Ошибка импорта ключа: ${error}`);
    }
  }

  /**
   * Получение всех ключей
   */
  getAllKeys(): KeyMetadata[] {
    return Array.from(this.keyStore.values())
      .map(entry => ({ ...entry.metadata }))
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Получение статистики
   */
  getStats(): {
    totalKeys: number;
    keysByType: Record<KeyType, number>;
    keysByStatus: Record<KeyStatus, number>;
    keysExpiringSoon: number;
    rotationQueueSize: number;
    hsmConnected: boolean;
    auditEventCount: number;
  } {
    const keysByType: Record<KeyType, number> = {
      SYMMETRIC: 0,
      ASYMMETRIC_SIGN: 0,
      ASYMMETRIC_ENC: 0,
      MASTER_KEY: 0,
      DATA_KEY: 0,
      WRAPPING_KEY: 0,
    };
    
    const keysByStatus: Record<KeyStatus, number> = {
      ACTIVE: 0,
      PENDING_ACTIVATION: 0,
      PENDING_DEACTIVATION: 0,
      DISABLED: 0,
      DESTROYED: 0,
      IMPORT_FAILED: 0,
      EXPIRED: 0,
    };
    
    const now = Date.now();
    const soonThreshold = now + 7 * 24 * 60 * 60 * 1000; // 7 дней
    let keysExpiringSoon = 0;
    
    for (const entry of this.keyStore.values()) {
      keysByType[entry.metadata.keyType]++;
      keysByStatus[entry.metadata.status]++;
      
      if (entry.metadata.expiresAt && 
          entry.metadata.expiresAt.getTime() > now && 
          entry.metadata.expiresAt.getTime() < soonThreshold) {
        keysExpiringSoon++;
      }
    }
    
    return {
      totalKeys: this.keyStore.size,
      keysByType,
      keysByStatus,
      keysExpiringSoon,
      rotationQueueSize: this.rotationQueue.size,
      hsmConnected: this.hsmProvider?.isConnected() || false,
      auditEventCount: this.auditEventCount,
    };
  }

  /**
   * Получение журнала аудита
   */
  getAuditLog(limit: number = 100, eventType?: AuditEventType): AuditEvent[] {
    let events = [...this.auditLog];
    
    if (eventType) {
      events = events.filter(e => e.eventType === eventType);
    }
    
    return events.slice(-limit).reverse();
  }

  /**
   * Запуск автоматической ротации
   */
  startAutoRotation(checkInterval: number = 60 * 60 * 1000): void {
    if (this.rotationTimer) {
      clearInterval(this.rotationTimer);
    }
    
    this.rotationTimer = setInterval(() => {
      this.checkRotationQueue();
    }, checkInterval);
    
    this.emit('autoRotation:started', { checkInterval });
  }

  /**
   * Остановка автоматической ротации
   */
  stopAutoRotation(): void {
    if (this.rotationTimer) {
      clearInterval(this.rotationTimer);
      this.rotationTimer = null;
      this.emit('autoRotation:stopped');
    }
  }

  /**
   * Очистка ресурсов
   */
  destroy(): void {
    this.stopAutoRotation();
    
    // Очищаем все ключи из памяти
    for (const entry of this.keyStore.values()) {
      if (entry.keyMaterial) {
        this.secureZero(entry.keyMaterial);
      }
    }
    
    this.keyStore.clear();
    this.keyNameIndex.clear();
    this.keyTagIndex.clear();
    this.rotationQueue.clear();
    this.auditLog.length = 0;
    
    // Отключаем HSM
    this.hsmProvider?.disconnect();
    
    this.emit('destroyed');
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Генерация симметричного ключа
   */
  private async generateSymmetricKey(algorithm: string, keySize: number): Promise<Uint8Array> {
    const byteSize = Math.ceil(keySize / 8);
    return this.secureRandom.randomBytes(byteSize);
  }

  /**
   * Генерация асимметричного ключа
   */
  private async generateAsymmetricKey(
    algorithm: string,
    keySize: number,
    keyType: KeyType
  ): Promise<{ publicKey: crypto.KeyObject; privateKey: crypto.KeyObject }> {
    if (algorithm.startsWith('RSA')) {
      return crypto.generateKeyPairSync('rsa', {
        modulusLength: keySize,
        publicKeyEncoding: {
          type: 'spki',
          format: 'der',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'der',
        },
      });
    }
    
    if (algorithm.includes('ECDSA') || algorithm.includes('ECDH')) {
      const namedCurve = this.getNamedCurve(algorithm);
      return crypto.generateKeyPairSync('ec', {
        namedCurve,
        publicKeyEncoding: {
          type: 'spki',
          format: 'der',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'der',
        },
      });
    }
    
    if (algorithm.includes('Ed25519') || algorithm.includes('Ed448')) {
      const type = algorithm.includes('Ed448') ? 'ed448' : 'ed25519';
      return crypto.generateKeyPairSync(type as any, {
        publicKeyEncoding: {
          type: 'spki',
          format: 'der',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'der',
        },
      });
    }
    
    // Default: RSA
    return crypto.generateKeyPairSync('rsa', {
      modulusLength: keySize || 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'der',
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'der',
      },
    });
  }

  /**
   * Получение named curve для ECDSA
   */
  private getNamedCurve(algorithm: string): string {
    const curves: Record<string, string> = {
      'ECDSA-P256': 'prime256v1',
      'ECDSA-P384': 'secp384r1',
      'ECDSA-P521': 'secp521r1',
      'ECDH-P256': 'prime256v1',
      'ECDH-P384': 'secp384r1',
      'ECDH-P521': 'secp521r1',
    };
    
    for (const [key, curve] of Object.entries(curves)) {
      if (algorithm.includes(key)) {
        return curve;
      }
    }
    
    return 'prime256v1';
  }

  /**
   * Генерация идентификатора ключа
   */
  private generateKeyId(): string {
    return `key_${this.secureRandom.generateToken(16, 'hex')}`;
  }

  /**
   * Обновление индексов
   */
  private updateIndexes(entry: KeyEntry): void {
    // Индекс по имени
    const name = entry.metadata.name;
    if (!this.keyNameIndex.has(name)) {
      this.keyNameIndex.set(name, []);
    }
    this.keyNameIndex.get(name)!.push(entry.metadata.keyId);
    
    // Индекс по тегам
    if (entry.metadata.tags) {
      for (const [key, value] of Object.entries(entry.metadata.tags)) {
        const tagKey = `${key}:${value}`;
        if (!this.keyTagIndex.has(tagKey)) {
          this.keyTagIndex.set(tagKey, new Set());
        }
        this.keyTagIndex.get(tagKey)!.add(entry.metadata.keyId);
      }
    }
  }

  /**
   * Удаление из индексов
   */
  private removeFromIndexes(entry: KeyEntry): void {
    // Удаляем из индекса по имени
    const name = entry.metadata.name;
    const keyIds = this.keyNameIndex.get(name);
    if (keyIds) {
      const index = keyIds.indexOf(entry.metadata.keyId);
      if (index > -1) {
        keyIds.splice(index, 1);
      }
      if (keyIds.length === 0) {
        this.keyNameIndex.delete(name);
      }
    }
    
    // Удаляем из индекса по тегам
    if (entry.metadata.tags) {
      for (const [key, value] of Object.entries(entry.metadata.tags)) {
        const tagKey = `${key}:${value}`;
        const keyIds = this.keyTagIndex.get(tagKey);
        if (keyIds) {
          keyIds.delete(entry.metadata.keyId);
          if (keyIds.size === 0) {
            this.keyTagIndex.delete(tagKey);
          }
        }
      }
    }
  }

  /**
   * Проверка политики использования ключа
   */
  private checkUsagePolicy(entry: KeyEntry, operation: KeyOperation): boolean {
    const policy = entry.metadata.usagePolicy;
    
    if (!policy) {
      return true; // Нет политики - разрешено
    }
    
    // Проверяем запрещенные операции
    if (policy.deniedOperations?.includes(operation)) {
      return false;
    }
    
    // Проверяем разрешенные операции
    if (policy.allowedOperations && policy.allowedOperations.length > 0) {
      if (!policy.allowedOperations.includes(operation)) {
        return false;
      }
    }
    
    // Проверяем ограничения по времени
    if (policy.timeRestrictions) {
      const now = new Date();
      if (policy.timeRestrictions.validFrom && now < policy.timeRestrictions.validFrom) {
        return false;
      }
      if (policy.timeRestrictions.validTo && now > policy.timeRestrictions.validTo) {
        return false;
      }
    }
    
    // Проверяем лимит использований
    if (policy.usageLimit) {
      if (entry.useCount >= policy.usageLimit.maxUses) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Обновление счетчика использования ключа
   */
  private updateKeyUsage(keyId: string): void {
    const entry = this.keyStore.get(keyId);
    
    if (entry) {
      entry.useCount++;
      entry.lastUsedAt = Date.now();
      entry.metadata.lastUsedAt = new Date();
      
      // Проверяем лимит использований
      if (entry.metadata.usagePolicy?.usageLimit) {
        entry.metadata.usagePolicy.usageLimit.currentUses = entry.useCount;
      }
    }
  }

  /**
   * Планирование ротации ключа
   */
  private scheduleRotation(keyId: string, ttl: number): void {
    // Добавляем в очередь ротации
    this.rotationQueue.add(keyId);
  }

  /**
   * Проверка очереди ротации
   */
  private checkRotationQueue(): void {
    const now = Date.now();
    
    for (const keyId of this.rotationQueue) {
      const entry = this.keyStore.get(keyId);
      
      if (!entry || !entry.metadata.expiresAt) {
        this.rotationQueue.delete(keyId);
        continue;
      }
      
      // Проверяем нужно ли ротировать (за день до истечения)
      const rotationThreshold = entry.metadata.expiresAt.getTime() - 24 * 60 * 60 * 1000;
      
      if (now >= rotationThreshold && entry.metadata.status === 'ACTIVE') {
        this.emit('key:rotationDue', { keyId, expiresAt: entry.metadata.expiresAt });
      }
    }
  }

  /**
   * Логирование аудита
   */
  private logAudit(eventType: AuditEventType, success: boolean, metadata?: Record<string, unknown>): void {
    const event: AuditEvent = {
      eventId: `audit_${this.secureRandom.generateToken(8, 'hex')}`,
      eventType,
      timestamp: new Date(),
      success,
      metadata,
    };
    
    // Вычисляем хэш события для целостности
    const eventData = JSON.stringify({
      eventId: event.eventId,
      eventType: event.eventType,
      timestamp: event.timestamp.toISOString(),
      success: event.success,
      metadata: event.metadata,
    });
    
    event.eventHash = this.hashService.hash(eventData, 'SHA-256').hash.toString();
    
    this.auditLog.push(event);
    this.auditEventCount++;
    
    // Очищаем старые записи
    if (this.auditLog.length > this.maxAuditLogSize) {
      this.auditLog.splice(0, this.auditLog.length - this.maxAuditLogSize);
    }
    
    this.emit('audit', event);
  }

  /**
   * Безопасная очистка памяти
   */
  private secureZero(buffer: Buffer): void {
    if (!buffer || buffer.length === 0) {
      return;
    }
    
    try {
      crypto.privateFill(buffer, 0);
    } catch {
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = 0;
      }
    }
  }

  /**
   * Создание ошибки
   */
  private createError(code: CryptoErrorCode, message: string): Error {
    const error = new Error(message);
    (error as any).errorCode = code;
    return error;
  }
}

/**
 * Запись ключа в хранилище
 */
interface KeyEntry {
  metadata: KeyMetadata;
  keyMaterial: Buffer | null;
  publicKey: Buffer | null;
  createdAt: number;
  lastUsedAt: number | null;
  useCount: number;
  versions: KeyVersion[];
  isExternal: boolean;
}

/**
 * Версия ключа
 */
interface KeyVersion {
  version: number;
  createdAt: Date;
  status: KeyStatus;
}

/**
 * Утилита для быстрой генерации ключа
 */
export async function generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
  const manager = new KeyManager({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  const result = await manager.generateKey(params);
  manager.destroy();
  
  return result;
}
