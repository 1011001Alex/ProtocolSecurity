/**
 * ============================================================================
 * ENVELOPE ENCRYPTION - КОНВЕРТНОЕ ШИФРОВАНИЕ
 * ============================================================================
 * Реализация конвертного шифрования с использованием иерархии ключей
 * 
 * Архитектура:
 * - KEK (Key Encryption Key) - ключ шифрования ключей (мастер-ключ)
 * - DEK (Data Encryption Key) - ключ шифрования данных
 * 
 * Процесс:
 * 1. Генерируется случайный DEK для шифрования данных
 * 2. Данные шифруются DEK с использованием AEAD (AES-GCM)
 * 3. DEK шифруется KEK и сохраняется в конверте
 * 4. Конверт содержит зашифрованные данные + метаданные
 * 
 * Особенности:
 * - Поддержка нескольких KEK для ротации
 * - Встроенная аутентификация данных (AEAD)
 * - Защита от tampering
 * - Поддержка additional authenticated data (AAD)
 * - Временные метки и срок жизни конвертов
 * ============================================================================
 */

import * as crypto from 'crypto';
import {
  EncryptionEnvelope,
  EnvelopeEncryptionParams,
  SymmetricAlgorithm,
  SecureMemoryConfig,
  CryptoErrorCode,
  KeyMetadata,
  KeyStatus,
  KeyType,
} from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';
import { HashService } from './HashService';

/**
 * Класс для работы с конвертным шифрованием
 */
export class EnvelopeEncryptionService {
  /** Версия формата конверта */
  private readonly envelopeVersion: number = 1;
  
  /** Конфигурация безопасной памяти */
  private readonly memoryConfig: SecureMemoryConfig;
  
  /** Hash service для вспомогательных операций */
  private readonly hashService: HashService;
  
  /** Secure random для генерации ключей */
  private readonly secureRandom: SecureRandom;
  
  /** Хранилище KEK (Key Encryption Keys) */
  private readonly kekStore: Map<string, KEKEntry>;
  
  /** Кэш расшифрованных DEK */
  private readonly dekCache: Map<string, CachedDEK>;
  
  /** Максимальный размер кэша DEK */
  private readonly maxDEKCacheSize: number = 1000;

  constructor(memoryConfig: SecureMemoryConfig) {
    this.memoryConfig = memoryConfig;
    this.hashService = new HashService(memoryConfig);
    this.secureRandom = new SecureRandom(memoryConfig);
    this.kekStore = new Map();
    this.dekCache = new Map();
  }

  /**
   * Регистрация мастер-ключа (KEK)
   * @param keyId - Идентификатор ключа
   * @param keyMaterial - Материал ключа (байты)
   * @param metadata - Метаданные ключа
   */
  registerKEK(
    keyId: string,
    keyMaterial: Uint8Array,
    metadata?: Partial<KeyMetadata>
  ): void {
    if (keyMaterial.length !== 32 && keyMaterial.length !== 16) {
      throw this.createError('INVALID_KEY_SIZE', 'KEK должен быть 128 или 256 бит');
    }
    
    this.kekStore.set(keyId, {
      keyMaterial: Buffer.from(keyMaterial),
      metadata: {
        keyId,
        name: metadata?.name || `KEK ${keyId.slice(0, 8)}`,
        keyType: 'MASTER_KEY',
        algorithm: 'AES-256-GCM',
        keySize: keyMaterial.length * 8,
        status: metadata?.status || 'ACTIVE',
        createdAt: metadata?.createdAt || new Date(),
        version: metadata?.version || 1,
      },
      createdAt: Date.now(),
    });
  }

  /**
   * Генерация и регистрация нового KEK
   * @param keyId - Опциональный идентификатор ключа
   * @returns Идентификатор созданного ключа
   */
  generateKEK(keyId?: string): string {
    const actualKeyId = keyId || this.secureRandom.randomUUID();
    const keyMaterial = this.secureRandom.randomBytes(32); // 256 бит
    
    this.registerKEK(actualKeyId, keyMaterial);
    
    // Очищаем ключ из памяти после регистрации
    this.secureZero(keyMaterial);
    
    return actualKeyId;
  }

  /**
   * Шифрование с использованием конвертного шифрования
   * @param params - Параметры шифрования
   * @returns Конверт с зашифрованными данными
   */
  async encrypt(params: EnvelopeEncryptionParams): Promise<EncryptionEnvelope> {
    const { plaintext, dataAlgorithm, kekId, additionalData, metadata, ttl } = params;
    
    // Проверяем наличие KEK
    const kekEntry = this.kekStore.get(kekId);
    
    if (!kekEntry) {
      throw this.createError('KEY_NOT_FOUND', `KEK с идентификатором ${kekId} не найден`);
    }
    
    if (kekEntry.metadata.status !== 'ACTIVE') {
      throw this.createError('KEY_EXPIRED', `KEK не активен: ${kekEntry.metadata.status}`);
    }
    
    try {
      // Шаг 1: Генерируем случайный DEK
      const dekKeySize = this.getDataKeySize(dataAlgorithm);
      const dek = this.secureRandom.randomBytes(dekKeySize);
      
      // Шаг 2: Генерируем nonce для шифрования данных
      const dataNonce = this.generateNonce(dataAlgorithm);
      
      // Шаг 3: Шифруем данные с помощью DEK
      const { ciphertext, authTag } = await this.encryptData(
        plaintext,
        dek,
        dataNonce,
        dataAlgorithm,
        additionalData
      );
      
      // Шаг 4: Шифруем DEK с помощью KEK
      const encryptedDek = await this.encryptDEK(dek, kekEntry.keyMaterial, kekId);
      
      // Шаг 5: Создаем конверт
      const now = Date.now();
      const envelope: EncryptionEnvelope = {
        version: this.envelopeVersion,
        envelopeId: this.secureRandom.randomUUID(),
        encryptedDek,
        kekId,
        kekAlgorithm: 'AES-256-GCM',
        dataAlgorithm,
        dataNonce,
        ciphertext,
        authTag,
        additionalData,
        metadata: {
          ...metadata,
          plaintextLength: plaintext.length,
        },
        createdAt: now,
        expiresAt: ttl ? now + ttl : undefined,
      };
      
      // Кэшируем DEK для последующей расшифровки
      this.cacheDEK(envelope.envelopeId, dek);
      
      // Очищаем DEK из памяти
      this.secureZero(dek);
      
      return envelope;
      
    } catch (error) {
      throw this.createError('ENCRYPTION_FAILED', `Ошибка шифрования: ${error}`);
    }
  }

  /**
   * Расшифрование конверта
   * @param envelope - Конверт для расшифровки
   * @returns Расшифрованные данные
   */
  async decrypt(envelope: EncryptionEnvelope): Promise<Uint8Array> {
    try {
      // Проверяем срок действия конверта
      if (envelope.expiresAt && envelope.expiresAt < Date.now()) {
        throw this.createError('KEY_EXPIRED', 'Срок действия конверта истек');
      }
      
      // Проверяем версию
      if (envelope.version !== this.envelopeVersion) {
        throw this.createError('INVALID_ARGUMENT', `Неподдерживаемая версия конверта: ${envelope.version}`);
      }
      
      // Получаем KEK
      const kekEntry = this.kekStore.get(envelope.kekId);
      
      if (!kekEntry) {
        throw this.createError('KEY_NOT_FOUND', `KEK с идентификатором ${envelope.kekId} не найден`);
      }
      
      if (kekEntry.metadata.status !== 'ACTIVE') {
        throw this.createError('KEY_EXPIRED', `KEK не активен: ${kekEntry.metadata.status}`);
      }
      
      // Пытаемся получить DEK из кэша
      let dek = this.getCachedDEK(envelope.envelopeId);
      
      if (!dek) {
        // Расшифровываем DEK
        dek = await this.decryptDEK(envelope.encryptedDek, kekEntry.keyMaterial, envelope.kekId);
        this.cacheDEK(envelope.envelopeId, dek);
      }
      
      // Расшифровываем данные
      const plaintext = await this.decryptData(
        envelope.ciphertext,
        dek,
        envelope.dataNonce,
        envelope.dataAlgorithm,
        envelope.authTag,
        envelope.additionalData
      );
      
      return plaintext;
      
    } catch (error) {
      throw this.createError('DECRYPTION_FAILED', `Ошибка расшифрования: ${error}`);
    }
  }

  /**
   * Шифрование потока данных (streaming)
   * @param stream - Поток данных для шифрования
   * @param params - Параметры шифрования
   * @returns Конверт с зашифрованными данными
   */
  async encryptStream(
    stream: AsyncIterable<Uint8Array>,
    params: Omit<EnvelopeEncryptionParams, 'plaintext'>
  ): Promise<EncryptionEnvelope> {
    const { dataAlgorithm, kekId, additionalData, metadata, ttl } = params;
    
    // Проверяем наличие KEK
    const kekEntry = this.kekStore.get(kekId);
    
    if (!kekEntry) {
      throw this.createError('KEY_NOT_FOUND', `KEK с идентификатором ${kekId} не найден`);
    }
    
    try {
      // Генерируем DEK и nonce
      const dekKeySize = this.getDataKeySize(dataAlgorithm);
      const dek = this.secureRandom.randomBytes(dekKeySize);
      const dataNonce = this.generateNonce(dataAlgorithm);
      
      // Создаем шифратор
      const { cipher, authTag } = this.createStreamCipher(
        dek,
        dataNonce,
        dataAlgorithm,
        additionalData
      );
      
      // Шифруем поток
      const encryptedChunks: Uint8Array[] = [];
      
      for await (const chunk of stream) {
        const encrypted = cipher.update(Buffer.from(chunk));
        if (encrypted.length > 0) {
          encryptedChunks.push(new Uint8Array(encrypted));
        }
      }
      
      // Финализируем шифрование
      const final = cipher.final();
      if (final.length > 0) {
        encryptedChunks.push(new Uint8Array(final));
      }
      
      // Объединяем зашифрованные чанки
      const totalLength = encryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
      const ciphertext = new Uint8Array(totalLength);
      
      let offset = 0;
      for (const chunk of encryptedChunks) {
        ciphertext.set(chunk, offset);
        offset += chunk.length;
      }
      
      // Шифруем DEK
      const encryptedDek = await this.encryptDEK(dek, kekEntry.keyMaterial, kekId);
      
      // Создаем конверт
      const now = Date.now();
      const envelope: EncryptionEnvelope = {
        version: this.envelopeVersion,
        envelopeId: this.secureRandom.randomUUID(),
        encryptedDek,
        kekId,
        kekAlgorithm: 'AES-256-GCM',
        dataAlgorithm,
        dataNonce,
        ciphertext,
        authTag: new Uint8Array(authTag),
        additionalData,
        metadata,
        createdAt: now,
        expiresAt: ttl ? now + ttl : undefined,
      };
      
      // Кэшируем DEK
      this.cacheDEK(envelope.envelopeId, dek);
      
      // Очищаем DEK
      this.secureZero(dek);
      
      return envelope;
      
    } catch (error) {
      throw this.createError('ENCRYPTION_FAILED', `Ошибка потокового шифрования: ${error}`);
    }
  }

  /**
   * Расшифрование потока данных
   * @param envelope - Конверт с зашифрованными данными
   * @returns Асинхронный итератор расшифрованных чанков
   */
  async *decryptStream(envelope: EncryptionEnvelope): AsyncGenerator<Uint8Array> {
    // Получаем KEK
    const kekEntry = this.kekStore.get(envelope.kekId);
    
    if (!kekEntry) {
      throw this.createError('KEY_NOT_FOUND', `KEK с идентификатором ${envelope.kekId} не найден`);
    }
    
    // Получаем DEK
    let dek = this.getCachedDEK(envelope.envelopeId);
    
    if (!dek) {
      dek = await this.decryptDEK(envelope.encryptedDek, kekEntry.keyMaterial, envelope.kekId);
      this.cacheDEK(envelope.envelopeId, dek);
    }
    
    // Создаем расшифровщик
    const decipher = crypto.createDecipheriv(
      this.mapAlgorithmToNode(envelope.dataAlgorithm),
      dek,
      envelope.dataNonce
    );
    
    decipher.setAuthTag(Buffer.from(envelope.authTag!));
    
    if (envelope.additionalData) {
      decipher.setAAD(Buffer.from(envelope.additionalData));
    }
    
    // Расшифровываем чанками
    const chunkSize = 64 * 1024; // 64 KB
    
    for (let offset = 0; offset < envelope.ciphertext.length; offset += chunkSize) {
      const chunk = envelope.ciphertext.slice(offset, offset + chunkSize);
      const decrypted = decipher.update(Buffer.from(chunk));
      
      if (decrypted.length > 0) {
        yield new Uint8Array(decrypted);
      }
    }
    
    const final = decipher.final();
    if (final.length > 0) {
      yield new Uint8Array(final);
    }
  }

  /**
   * Ротация KEK (перешифрование DEK новым ключом)
   * @param envelope - Конверт со старым KEK
   * @param newKekId - Идентификатор нового KEK
   * @returns Новый конверт с перешифрованным DEK
   */
  async rotateKEK(envelope: EncryptionEnvelope, newKekId: string): Promise<EncryptionEnvelope> {
    const oldKekEntry = this.kekStore.get(envelope.kekId);
    const newKekEntry = this.kekStore.get(newKekId);
    
    if (!oldKekEntry) {
      throw this.createError('KEY_NOT_FOUND', `Старый KEK не найден: ${envelope.kekId}`);
    }
    
    if (!newKekEntry) {
      throw this.createError('KEY_NOT_FOUND', `Новый KEK не найден: ${newKekId}`);
    }
    
    if (newKekEntry.metadata.status !== 'ACTIVE') {
      throw this.createError('KEY_EXPIRED', `Новый KEK не активен: ${newKekEntry.metadata.status}`);
    }
    
    try {
      // Расшифровываем DEK старым KEK
      const dek = await this.decryptDEK(envelope.encryptedDek, oldKekEntry.keyMaterial, envelope.kekId);
      
      // Шифруем DEK новым KEK
      const encryptedDek = await this.encryptDEK(dek, newKekEntry.keyMaterial, newKekId);
      
      // Создаем новый конверт
      const newEnvelope: EncryptionEnvelope = {
        ...envelope,
        envelopeId: this.secureRandom.randomUUID(),
        encryptedDek,
        kekId: newKekId,
        createdAt: Date.now(),
        metadata: {
          ...envelope.metadata,
          rotatedFrom: envelope.envelopeId,
          rotatedAt: Date.now(),
        },
      };
      
      // Кэшируем DEK
      this.cacheDEK(newEnvelope.envelopeId, dek);
      
      // Очищаем DEK
      this.secureZero(dek);
      
      return newEnvelope;
      
    } catch (error) {
      throw this.createError('ENCRYPTION_FAILED', `Ошибка ротации KEK: ${error}`);
    }
  }

  /**
   * Верификация целостности конверта
   * @param envelope - Конверт для проверки
   * @returns Результат верификации
   */
  verifyEnvelope(envelope: EncryptionEnvelope): {
    valid: boolean;
    errors: string[];
    warnings: string[];
  } {
    const errors: string[] = [];
    const warnings: string[] = [];
    
    // Проверяем версию
    if (envelope.version !== this.envelopeVersion) {
      errors.push(`Неподдерживаемая версия: ${envelope.version}`);
    }
    
    // Проверяем наличие обязательных полей
    if (!envelope.envelopeId) {
      errors.push('Отсутствует envelopeId');
    }
    
    if (!envelope.encryptedDek || envelope.encryptedDek.length === 0) {
      errors.push('Отсутствует encryptedDek');
    }
    
    if (!envelope.ciphertext || envelope.ciphertext.length === 0) {
      errors.push('Отсутствует ciphertext');
    }
    
    // Проверяем KEK
    const kekEntry = this.kekStore.get(envelope.kekId);
    
    if (!kekEntry) {
      errors.push(`KEK не найден: ${envelope.kekId}`);
    } else if (kekEntry.metadata.status !== 'ACTIVE') {
      warnings.push(`KEK не активен: ${kekEntry.metadata.status}`);
    }
    
    // Проверяем срок действия
    if (envelope.expiresAt && envelope.expiresAt < Date.now()) {
      warnings.push('Срок действия конверта истек');
    }
    
    // Проверяем auth tag для AEAD алгоритмов
    if (this.isAEADAlgorithm(envelope.dataAlgorithm) && !envelope.authTag) {
      errors.push('Отсутствует authTag для AEAD алгоритма');
    }
    
    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Получение метаданных KEK
   */
  getKEKMetadata(keyId: string): KeyMetadata | undefined {
    return this.kekStore.get(keyId)?.metadata;
  }

  /**
   * Получение всех KEK
   */
  getAllKEKs(): Array<{ keyId: string; metadata: KeyMetadata }> {
    return Array.from(this.kekStore.entries()).map(([keyId, entry]) => ({
      keyId,
      metadata: entry.metadata,
    }));
  }

  /**
   * Деактивация KEK
   */
  deactivateKEK(keyId: string): boolean {
    const entry = this.kekStore.get(keyId);
    
    if (!entry) {
      return false;
    }
    
    entry.metadata.status = 'DISABLED';
    return true;
  }

  /**
   * Очистка кэша DEK
   */
  clearDEKCache(): void {
    for (const dek of this.dekCache.values()) {
      this.secureZero(dek.key);
    }
    this.dekCache.clear();
  }

  /**
   * Получение статистики
   */
  getStats(): {
    totalKEKs: number;
    activeKEKs: number;
    cachedDEKs: number;
    envelopeVersion: number;
  } {
    const keks = Array.from(this.kekStore.values());
    
    return {
      totalKEKs: this.kekStore.size,
      activeKEKs: keks.filter(k => k.metadata.status === 'ACTIVE').length,
      cachedDEKs: this.dekCache.size,
      envelopeVersion: this.envelopeVersion,
    };
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Шифрование данных
   */
  private async encryptData(
    plaintext: Uint8Array,
    dek: Uint8Array,
    nonce: Uint8Array,
    algorithm: SymmetricAlgorithm,
    additionalData?: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; authTag: Uint8Array }> {
    const cipher = crypto.createCipheriv(
      this.mapAlgorithmToNode(algorithm),
      dek,
      nonce
    );
    
    if (additionalData) {
      cipher.setAAD(Buffer.from(additionalData));
    }
    
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(plaintext)),
      cipher.final(),
    ]);
    
    const authTag = cipher.getAuthTag();
    
    return {
      ciphertext: new Uint8Array(ciphertext),
      authTag: new Uint8Array(authTag),
    };
  }

  /**
   * Расшифрование данных
   */
  private async decryptData(
    ciphertext: Uint8Array,
    dek: Uint8Array,
    nonce: Uint8Array,
    algorithm: SymmetricAlgorithm,
    authTag?: Uint8Array,
    additionalData?: Uint8Array
  ): Promise<Uint8Array> {
    const decipher = crypto.createDecipheriv(
      this.mapAlgorithmToNode(algorithm),
      dek,
      nonce
    );
    
    if (authTag) {
      decipher.setAuthTag(Buffer.from(authTag));
    }
    
    if (additionalData) {
      decipher.setAAD(Buffer.from(additionalData));
    }
    
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(ciphertext)),
      decipher.final(),
    ]);
    
    return new Uint8Array(plaintext);
  }

  /**
   * Шифрование DEK
   */
  private async encryptDEK(
    dek: Uint8Array,
    kek: Buffer,
    kekId: string
  ): Promise<Uint8Array> {
    const nonce = this.secureRandom.randomBytes(12);
    
    const cipher = crypto.createCipheriv('aes-256-gcm', kek, nonce);
    
    const encryptedDek = Buffer.concat([
      nonce,
      cipher.update(Buffer.from(dek)),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    
    return new Uint8Array(encryptedDek);
  }

  /**
   * Расшифрование DEK
   */
  private async decryptDEK(
    encryptedDek: Uint8Array,
    kek: Buffer,
    kekId: string
  ): Promise<Uint8Array> {
    // Извлекаем компоненты
    const nonce = encryptedDek.slice(0, 12);
    const authTag = encryptedDek.slice(encryptedDek.length - 16);
    const ciphertext = encryptedDek.slice(12, encryptedDek.length - 16);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', kek, nonce);
    decipher.setAuthTag(Buffer.from(authTag));
    
    const dek = Buffer.concat([
      decipher.update(Buffer.from(ciphertext)),
      decipher.final(),
    ]);
    
    return new Uint8Array(dek);
  }

  /**
   * Создание потокового шифра
   */
  private createStreamCipher(
    dek: Uint8Array,
    nonce: Uint8Array,
    algorithm: SymmetricAlgorithm,
    additionalData?: Uint8Array
  ): { cipher: crypto.Cipher; authTag: Buffer } {
    const cipher = crypto.createCipheriv(
      this.mapAlgorithmToNode(algorithm),
      dek,
      nonce
    );
    
    if (additionalData) {
      cipher.setAAD(Buffer.from(additionalData));
    }
    
    return { cipher, authTag: cipher.getAuthTag() };
  }

  /**
   * Генерация nonce для алгоритма
   */
  private generateNonce(algorithm: SymmetricAlgorithm): Uint8Array {
    const nonceSize = this.getNonceSize(algorithm);
    return this.secureRandom.randomBytes(nonceSize);
  }

  /**
   * Получение размера nonce
   */
  private getNonceSize(algorithm: SymmetricAlgorithm): number {
    switch (algorithm) {
      case 'AES-128-GCM':
      case 'AES-256-GCM':
      case 'AES-128-CTR':
      case 'AES-256-CTR':
      case 'AES-128-CBC':
      case 'AES-256-CBC':
        return 12; // 96 бит для GCM, 128 бит для других
      
      case 'ChaCha20-Poly1305':
      case 'XChaCha20-Poly1305':
        return algorithm === 'ChaCha20-Poly1305' ? 12 : 24;
      
      default:
        return 12;
    }
  }

  /**
   * Получение размера ключа данных
   */
  private getDataKeySize(algorithm: SymmetricAlgorithm): number {
    if (algorithm.includes('128')) {
      return 16;
    }
    if (algorithm.includes('256')) {
      return 32;
    }
    // ChaCha20 всегда 256 бит
    return 32;
  }

  /**
   * Маппинг алгоритма на имя Node.js
   */
  private mapAlgorithmToNode(algorithm: SymmetricAlgorithm): string {
    const mapping: Record<SymmetricAlgorithm, string> = {
      'AES-128-GCM': 'aes-128-gcm',
      'AES-256-GCM': 'aes-256-gcm',
      'AES-128-CTR': 'aes-128-ctr',
      'AES-256-CTR': 'aes-256-ctr',
      'AES-128-CBC': 'aes-128-cbc',
      'AES-256-CBC': 'aes-256-cbc',
      'ChaCha20-Poly1305': 'chacha20-poly1305',
      'XChaCha20-Poly1305': 'xchacha20-poly1305',
    };
    
    return mapping[algorithm] || 'aes-256-gcm';
  }

  /**
   * Проверка является ли алгоритм AEAD
   */
  private isAEADAlgorithm(algorithm: SymmetricAlgorithm): boolean {
    return algorithm.includes('GCM') || algorithm.includes('Poly1305');
  }

  /**
   * Кэширование DEK
   */
  private cacheDEK(envelopeId: string, dek: Uint8Array): void {
    // Очищаем старые записи если кэш переполнен
    if (this.dekCache.size >= this.maxDEKCacheSize) {
      const oldestKey = this.dekCache.keys().next().value;
      if (oldestKey) {
        const oldDEK = this.dekCache.get(oldestKey);
        if (oldDEK) {
          this.secureZero(oldDEK.key);
        }
        this.dekCache.delete(oldestKey);
      }
    }
    
    this.dekCache.set(envelopeId, {
      key: Buffer.from(dek),
      cachedAt: Date.now(),
    });
  }

  /**
   * Получение DEK из кэша
   */
  private getCachedDEK(envelopeId: string): Uint8Array | null {
    const cached = this.dekCache.get(envelopeId);
    
    if (!cached) {
      return null;
    }
    
    // Проверяем возраст кэша (5 минут)
    if (Date.now() - cached.cachedAt > 5 * 60 * 1000) {
      this.secureZero(cached.key);
      this.dekCache.delete(envelopeId);
      return null;
    }
    
    return new Uint8Array(cached.key);
  }

  /**
   * Безопасная очистка памяти
   */
  private secureZero(buffer: Uint8Array | Buffer): void {
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
 * Запись KEK в хранилище
 */
interface KEKEntry {
  keyMaterial: Buffer;
  metadata: KeyMetadata;
  createdAt: number;
}

/**
 * Кэшированный DEK
 */
interface CachedDEK {
  key: Buffer;
  cachedAt: number;
}

/**
 * Утилита для быстрого шифрования
 */
export async function encryptEnvelope(
  plaintext: Uint8Array | string | Buffer,
  kekId: string,
  kek: Uint8Array
): Promise<EncryptionEnvelope> {
  const service = new EnvelopeEncryptionService({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  service.registerKEK(kekId, kek);
  
  const inputData = plaintext instanceof Uint8Array ? plaintext :
                    plaintext instanceof Buffer ? new Uint8Array(plaintext) :
                    new TextEncoder().encode(plaintext as string);
  
  return service.encrypt({
    plaintext: inputData,
    dataAlgorithm: 'AES-256-GCM',
    kekId,
  });
}

/**
 * Утилита для быстрого расшифрования
 */
export async function decryptEnvelope(
  envelope: EncryptionEnvelope,
  kek: Uint8Array
): Promise<Uint8Array> {
  const service = new EnvelopeEncryptionService({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  service.registerKEK(envelope.kekId, kek);
  
  return service.decrypt(envelope);
}
