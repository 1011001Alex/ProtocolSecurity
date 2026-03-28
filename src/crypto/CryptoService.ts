/**
 * ============================================================================
 * CRYPTO SERVICE - ОСНОВНОЙ КРИПТОГРАФИЧЕСКИЙ СЕРВИС
 * ============================================================================
 * Единый интерфейс для всех криптографических операций проекта
 * 
 * Функционал:
 * - Симметричное шифрование (AES-GCM, ChaCha20-Poly1305)
 * - Асимметричное шифрование (RSA-OAEP, ECDH)
 * - Цифровые подписи (EdDSA, ECDSA, RSA-PSS)
 * - Хэширование (SHA-2, SHA-3, BLAKE2, BLAKE3)
 * - Деривация ключей (Argon2id, PBKDF2, HKDF, scrypt)
 * - Конвертное шифрование (Envelope Encryption)
 * - Управление ключами (Key Management)
 * - Постквантовая криптография (CRYSTALS-Kyber, CRYSTALS-Dilithium)
 * - Интеграция с HSM/KMS
 * 
 * Особенности:
 * - Единый конфигурируемый интерфейс
 * - Автоматический выбор лучших алгоритмов
 * - Graceful degradation
 * - Детальное логирование и аудит
 * - Защита от side-channel атак
 * - Безопасное управление памятью
 * ============================================================================
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  CryptoServiceConfig,
  DEFAULT_CRYPTO_CONFIG,
  SymmetricAlgorithm,
  AsymmetricAlgorithm,
  SignatureAlgorithm,
  HashAlgorithm,
  KDFAlgorithm,
  KDFParams,
  EncryptionEnvelope,
  EnvelopeEncryptionParams,
  KeyMetadata,
  KeyType,
  KeyGenerationParams,
  KeyGenerationResult,
  KeyStatus,
  SignatureResult,
  SignatureVerificationResult,
  HashResult,
  SecureMemoryConfig,
  AuditEvent,
  AuditEventType,
  CryptoErrorCode,
  CryptoResult,
  KMSProviderConfig,
  PQCAlgorithm,
  PQCKeyPair,
  KEMEncapsulationResult,
} from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';
import { HashService } from './HashService';
import { KeyDerivationService } from './KeyDerivation';
import { DigitalSignatureService } from './DigitalSignature';
import { EnvelopeEncryptionService } from './EnvelopeEncryption';
import { KeyManager } from './KeyManager';
import { PostQuantumCrypto } from './PostQuantum';
import { HSMProvider, HSMProviderFactory } from './HSMInterface';

/**
 * Основной класс криптографического сервиса
 */
export class CryptoService extends EventEmitter {
  /** Конфигурация сервиса */
  private readonly config: CryptoServiceConfig;
  
  /** Secure random для генерации ключей */
  private readonly secureRandom: SecureRandom;
  
  /** Hash service */
  private readonly hashService: HashService;
  
  /** Key derivation service */
  private readonly keyDerivationService: KeyDerivationService;
  
  /** Digital signature service */
  private readonly signatureService: DigitalSignatureService;
  
  /** Envelope encryption service */
  private readonly envelopeEncryptionService: EnvelopeEncryptionService;
  
  /** Key manager */
  private readonly keyManager: KeyManager;
  
  /** Post-quantum crypto */
  private readonly postQuantumCrypto: PostQuantumCrypto;
  
  /** HSM провайдер */
  private hsmProvider: HSMProvider | null = null;
  
  /** Флаг инициализации */
  private isInitialized = false;
  
  /** Счетчик операций */
  private operationStats: CryptoOperationStats = {
    totalOperations: 0,
    successfulOperations: 0,
    failedOperations: 0,
    operationsByType: {},
    averageLatency: 0,
  };

  /**
   * Создает экземпляр CryptoService
   * @param config - Конфигурация сервиса
   */
  constructor(config: Partial<CryptoServiceConfig> = {}) {
    super();
    
    // Объединяем с конфигурацией по умолчанию
    this.config = {
      ...DEFAULT_CRYPTO_CONFIG,
      ...config,
      memory: { ...DEFAULT_CRYPTO_CONFIG.memory, ...config.memory },
      logging: { ...DEFAULT_CRYPTO_CONFIG.logging, ...config.logging },
      keyRotation: { ...DEFAULT_CRYPTO_CONFIG.keyRotation, ...config.keyRotation },
      security: { ...DEFAULT_CRYPTO_CONFIG.security, ...config.security },
    };
    
    // Инициализируем компоненты
    this.secureRandom = new SecureRandom(this.config.memory);
    this.hashService = new HashService(
      this.config.memory,
      this.config.allowedAlgorithms.hash
    );
    this.keyDerivationService = new KeyDerivationService(this.config.memory);
    this.signatureService = new DigitalSignatureService(this.config.memory);
    this.envelopeEncryptionService = new EnvelopeEncryptionService(this.config.memory);
    this.keyManager = new KeyManager(this.config.memory);
    this.postQuantumCrypto = new PostQuantumCrypto(this.config.memory);
    
    // Подписываемся на события компонентов
    this.subscribeToEvents();
    
    this.log('INFO', 'CryptoService создан, ожидает инициализации');
  }

  /**
   * Инициализация сервиса
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      this.log('WARN', 'CryptoService уже инициализирован');
      return;
    }
    
    try {
      // Инициализируем HSM если указан
      if (this.config.kmsProviders && this.config.kmsProviders.length > 0) {
        await this.initializeHSM(this.config.kmsProviders[0]);
      }
      
      // Генерируем мастер-ключ если не существует
      await this.ensureMasterKey();
      
      // Запускаем автоматическую ротацию если включена
      if (this.config.keyRotation.enabled) {
        this.keyManager.startAutoRotation(this.config.keyRotation.interval / 10);
      }
      
      this.isInitialized = true;
      this.log('INFO', 'CryptoService успешно инициализирован');
      
      this.emit('initialized');
      
    } catch (error) {
      this.log('ERROR', 'Ошибка инициализации CryptoService', error);
      throw error;
    }
  }

  /**
   * Остановка сервиса
   */
  async destroy(): Promise<void> {
    if (!this.isInitialized) {
      return;
    }
    
    this.keyManager.stopAutoRotation();
    this.keyManager.destroy();
    
    if (this.hsmProvider) {
      await this.hsmProvider.disconnect();
    }
    
    this.isInitialized = false;
    this.log('INFO', 'CryptoService остановлен');
    
    this.emit('destroyed');
  }

  // ============================================================================
  // СИММЕТРИЧНОЕ ШИФРОВАНИЕ
  // ============================================================================

  /**
   * Шифрование данных симметричным ключом
   */
  async encrypt(
    data: Uint8Array | string | Buffer,
    keyId: string,
    algorithm?: SymmetricAlgorithm,
    additionalData?: Uint8Array
  ): Promise<EncryptionEnvelope> {
    return this.trackOperation('encrypt', async () => {
      this.validateInitialized();
      
      const plaintext = this.normalizeInput(data);
      const selectedAlgorithm = algorithm || this.config.defaultSymmetric.algorithm;
      
      this.validateAlgorithm(selectedAlgorithm, this.config.allowedAlgorithms.symmetric);
      
      // Получаем ключ
      const keyMaterial = this.keyManager.getKeyMaterial(keyId);
      
      if (!keyMaterial) {
        throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `Ключ не найден: ${keyId}`);
      }
      
      // Регистрируем KEK и шифруем
      this.envelopeEncryptionService.registerKEK(keyId, keyMaterial);
      
      return this.envelopeEncryptionService.encrypt({
        plaintext,
        dataAlgorithm: selectedAlgorithm,
        kekId: keyId,
        additionalData,
      });
    });
  }

  /**
   * Расшифрование данных
   */
  async decrypt(
    envelope: EncryptionEnvelope,
    keyId?: string
  ): Promise<Uint8Array> {
    return this.trackOperation('decrypt', async () => {
      this.validateInitialized();
      
      // Если ключ не указан, используем из конверта
      const actualKeyId = keyId || envelope.kekId;
      
      // Получаем ключ
      const keyMaterial = this.keyManager.getKeyMaterial(actualKeyId);
      
      if (!keyMaterial) {
        throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `Ключ не найден: ${actualKeyId}`);
      }
      
      // Регистрируем KEK и расшифровываем
      this.envelopeEncryptionService.registerKEK(actualKeyId, keyMaterial);
      
      return this.envelopeEncryptionService.decrypt(envelope);
    });
  }

  // ============================================================================
  // АСИММЕТРИЧНОЕ ШИФРОВАНИЕ
  // ============================================================================

  /**
   * Шифрование асимметричным ключом
   */
  async encryptAsymmetric(
    data: Uint8Array | string | Buffer,
    publicKeyId: string
  ): Promise<Uint8Array> {
    return this.trackOperation('encryptAsymmetric', async () => {
      this.validateInitialized();
      
      const plaintext = this.normalizeInput(data);
      const publicKey = this.keyManager.getPublicKey(publicKeyId);
      
      if (!publicKey) {
        throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `Открытый ключ не найден: ${publicKeyId}`);
      }
      
      // Используем RSA-OAEP
      return new Uint8Array(crypto.publicEncrypt(
        {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        Buffer.from(plaintext)
      ));
    });
  }

  /**
   * Расшифрование асимметричным ключом
   */
  async decryptAsymmetric(
    data: Uint8Array | Buffer,
    privateKeyId: string
  ): Promise<Uint8Array> {
    return this.trackOperation('decryptAsymmetric', async () => {
      this.validateInitialized();
      
      const keyMaterial = this.keyManager.getKeyMaterial(privateKeyId);
      
      if (!keyMaterial) {
        throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `Закрытый ключ не найден: ${privateKeyId}`);
      }
      
      const privateKey = crypto.createPrivateKey({
        key: Buffer.from(keyMaterial),
        format: 'der',
        type: 'pkcs8',
      });
      
      return new Uint8Array(crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
        },
        Buffer.from(data)
      ));
    });
  }

  // ============================================================================
  // ЦИФРОВЫЕ ПОДПИСИ
  // ============================================================================

  /**
   * Создание цифровой подписи
   */
  async sign(
    data: Uint8Array | string | Buffer,
    keyId: string
  ): Promise<SignatureResult> {
    return this.trackOperation('sign', async () => {
      this.validateInitialized();
      return this.signatureService.sign(data, keyId);
    });
  }

  /**
   * Верификация цифровой подписи
   */
  async verify(
    data: Uint8Array | string | Buffer,
    signature: Uint8Array | Buffer,
    publicKeyId: string
  ): Promise<SignatureVerificationResult> {
    return this.trackOperation('verify', async () => {
      this.validateInitialized();
      return this.signatureService.verify(data, signature, publicKeyId);
    });
  }

  // ============================================================================
  // ХЭШИРОВАНИЕ
  // ============================================================================

  /**
   * Вычисление хэша
   */
  hash(
    data: Uint8Array | string | Buffer,
    algorithm?: HashAlgorithm
  ): HashResult {
    this.validateInitialized();
    
    const selectedAlgorithm = algorithm || this.config.defaultSymmetric.algorithm.includes('256') 
      ? 'SHA-256' 
      : 'SHA-512';
    
    this.validateAlgorithm(selectedAlgorithm, this.config.allowedAlgorithms.hash);
    
    return this.hashService.hash(data, selectedAlgorithm);
  }

  /**
   * Вычисление HMAC
   */
  hmac(
    data: Uint8Array | string | Buffer,
    keyId: string,
    algorithm?: HashAlgorithm
  ): Uint8Array {
    this.validateInitialized();
    
    const keyMaterial = this.keyManager.getKeyMaterial(keyId);
    
    if (!keyMaterial) {
      throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `Ключ не найден: ${keyId}`);
    }
    
    const selectedAlgorithm = algorithm || 'SHA-256';
    
    return this.hashService.hmac(data, keyMaterial, selectedAlgorithm);
  }

  // ============================================================================
  // ДЕРИВАЦИЯ КЛЮЧЕЙ
  // ============================================================================

  /**
   * Деривация ключа из пароля
   */
  deriveKey(
    password: string | Uint8Array,
    salt: Uint8Array,
    params?: KDFParams
  ): Uint8Array {
    this.validateInitialized();
    
    const kdfParams = params || this.config.defaultKDF;
    
    return this.keyDerivationService.deriveKey(password, salt, kdfParams);
  }

  /**
   * Деривация ключа с генерацией соли
   */
  deriveKeyWithSalt(
    password: string | Uint8Array,
    params?: KDFParams
  ): { key: Uint8Array; salt: Uint8Array } {
    this.validateInitialized();
    
    const kdfParams = params || this.config.defaultKDF;
    
    return this.keyDerivationService.deriveKeyWithSalt(password, kdfParams);
  }

  // ============================================================================
  // УПРАВЛЕНИЕ КЛЮЧАМИ
  // ============================================================================

  /**
   * Генерация ключа
   */
  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    this.validateInitialized();
    
    this.validateAlgorithm(params.algorithm, this.getAllowedAlgorithmsForKeyType(params.keyType));
    
    return this.keyManager.generateKey(params);
  }

  /**
   * Получение метаданных ключа
   */
  getKey(keyId: string): KeyMetadata | null {
    this.validateInitialized();
    return this.keyManager.getKey(keyId);
  }

  /**
   * Удаление ключа
   */
  destroyKey(keyId: string): boolean {
    this.validateInitialized();
    return this.keyManager.destroyKey(keyId);
  }

  /**
   * Ротация ключа
   */
  async rotateKey(keyId: string): Promise<KeyGenerationResult> {
    this.validateInitialized();
    return this.keyManager.rotateKey(keyId);
  }

  /**
   * Получение всех ключей
   */
  getAllKeys(): KeyMetadata[] {
    this.validateInitialized();
    return this.keyManager.getAllKeys();
  }

  // ============================================================================
  // ПОСТКВАНТОВАЯ КРИПТОГРАФИЯ
  // ============================================================================

  /**
   * Генерация постквантового ключа
   */
  async generatePQCKey(algorithm: PQCAlgorithm): Promise<PQCKeyPair> {
    this.validateInitialized();
    return this.postQuantumCrypto.generateKeyPair(algorithm);
  }

  /**
   * PQC инкапсуляция
   */
  async pqcEncapsulate(
    algorithm: PQCAlgorithm,
    publicKey: Uint8Array
  ): Promise<KEMEncapsulationResult> {
    this.validateInitialized();
    return this.postQuantumCrypto.kemEncapsulate(algorithm, publicKey);
  }

  /**
   * PQC деинкапсуляция
   */
  async pqcDecapsulate(
    algorithm: PQCAlgorithm,
    privateKey: Uint8Array,
    ciphertext: Uint8Array
  ): Promise<{ sharedSecret: Uint8Array; success: boolean }> {
    this.validateInitialized();
    return this.postQuantumCrypto.kemDecapsulate(algorithm, privateKey, ciphertext);
  }

  /**
   * PQC подпись
   */
  async pqcSign(
    algorithm: PQCAlgorithm,
    privateKey: Uint8Array,
    message: Uint8Array
  ): Promise<Uint8Array> {
    this.validateInitialized();
    return this.postQuantumCrypto.sign(algorithm, privateKey, message);
  }

  /**
   * PQC верификация
   */
  async pqcVerify(
    algorithm: PQCAlgorithm,
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    this.validateInitialized();
    const result = await this.postQuantumCrypto.verify(algorithm, publicKey, message, signature);
    return result.valid;
  }

  // ============================================================================
  // УТИЛИТЫ
  // ============================================================================

  /**
   * Генерация случайных байт
   */
  randomBytes(length: number): Uint8Array {
    return this.secureRandom.randomBytes(length);
  }

  /**
   * Генерация UUID
   */
  randomUUID(): string {
    return this.secureRandom.randomUUID();
  }

  /**
   * Генерация токена
   */
  generateToken(length?: number, encoding?: 'hex' | 'base64' | 'base64url'): string {
    return this.secureRandom.generateToken(length, encoding);
  }

  /**
   * Получение статистики
   */
  getStats(): {
    operations: CryptoOperationStats;
    keys: ReturnType<KeyManager['getStats']>;
    envelopeEncryption: ReturnType<EnvelopeEncryptionService['getStats']>;
    signatures: ReturnType<DigitalSignatureService['getStats']>;
    secureRandom: ReturnType<SecureRandom['getInfo']>;
  } {
    return {
      operations: { ...this.operationStats },
      keys: this.keyManager.getStats(),
      envelopeEncryption: this.envelopeEncryptionService.getStats(),
      signatures: this.signatureService.getStats(),
      secureRandom: this.secureRandom.getInfo(),
    };
  }

  /**
   * Получение журнала аудита
   */
  getAuditLog(limit?: number, eventType?: AuditEventType): AuditEvent[] {
    return this.keyManager.getAuditLog(limit, eventType);
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Инициализация HSM
   */
  private async initializeHSM(config: KMSProviderConfig): Promise<void> {
    try {
      const factory = new HSMProviderFactory(this.config.memory);
      this.hsmProvider = factory.createProvider(config);
      await this.hsmProvider.connect();
      
      this.log('INFO', `HSM подключен: ${config.type}`);
      this.emit('hsm:connected', { provider: config.type });
      
    } catch (error) {
      this.log('WARN', `HSM недоступен, используем локальное хранилище: ${error}`);
      this.emit('hsm:error', error);
    }
  }

  /**
   * Обеспечение наличия мастер-ключа
   */
  private async ensureMasterKey(): Promise<void> {
    const existingKeys = this.keyManager.getAllKeys().filter(
      k => k.keyType === 'MASTER_KEY' && k.status === 'ACTIVE'
    );
    
    if (existingKeys.length === 0) {
      await this.keyManager.generateKey({
        keyType: 'MASTER_KEY',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Master Key',
        description: 'Основной мастер-ключ системы',
        exportable: false,
      });
      
      this.log('INFO', 'Мастер-ключ сгенерирован');
    }
  }

  /**
   * Подписка на события компонентов
   */
  private subscribeToEvents(): void {
    this.keyManager.on('audit', (event: AuditEvent) => {
      this.emit('audit', event);
    });
    
    this.keyManager.on('key:rotationDue', (data: { keyId: string; expiresAt: Date }) => {
      this.emit('key:rotationDue', data);
    });
    
    this.keyManager.on('hsm:connected', (data: any) => {
      this.emit('hsm:connected', data);
    });
  }

  /**
   * Валидация инициализации
   */
  private validateInitialized(): void {
    if (!this.isInitialized) {
      throw this.createError(CryptoErrorCode.UNKNOWN_ERROR, 'CryptoService не инициализирован');
    }
  }

  /**
   * Нормализация входных данных
   */
  private normalizeInput(data: Uint8Array | string | Buffer): Uint8Array {
    if (data instanceof Buffer) {
      return new Uint8Array(data);
    }
    if (data instanceof Uint8Array) {
      return data;
    }
    if (typeof data === 'string') {
      return new TextEncoder().encode(data);
    }
    throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, 'Неподдерживаемый тип данных');
  }

  /**
   * Валидация алгоритма
   */
  private validateAlgorithm(algorithm: string, allowed: string[]): void {
    if (!allowed.includes(algorithm)) {
      throw this.createError(
        CryptoErrorCode.INVALID_ARGUMENT,
        `Алгоритм ${algorithm} не разрешен. Разрешены: ${allowed.join(', ')}`
      );
    }
  }

  /**
   * Получение разрешенных алгоритмов для типа ключа
   */
  private getAllowedAlgorithmsForKeyType(keyType: KeyType): string[] {
    switch (keyType) {
      case 'SYMMETRIC':
      case 'MASTER_KEY':
      case 'DATA_KEY':
      case 'WRAPPING_KEY':
        return this.config.allowedAlgorithms.symmetric;
      
      case 'ASYMMETRIC_SIGN':
        return this.config.allowedAlgorithms.signature;
      
      case 'ASYMMETRIC_ENC':
        return this.config.allowedAlgorithms.asymmetric;
      
      default:
        return [];
    }
  }

  /**
   * Логирование
   */
  private log(level: string, message: string, error?: unknown): void {
    if (!this.config.logging.console && level !== 'ERROR') {
      return;
    }
    
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [CryptoService] [${level}] ${message}`;
    
    if (level === 'ERROR' || error) {
      console.error(logMessage, error || '');
    } else if (level === 'WARN') {
      console.warn(logMessage);
    } else {
      console.log(logMessage);
    }
  }

  /**
   * Трекинг операций
   */
  private async trackOperation<T>(
    type: string,
    operation: () => Promise<T>
  ): Promise<T> {
    const startTime = Date.now();
    
    try {
      const result = await operation();
      
      this.operationStats.totalOperations++;
      this.operationStats.successfulOperations++;
      this.operationStats.operationsByType[type] = 
        (this.operationStats.operationsByType[type] || 0) + 1;
      
      const latency = Date.now() - startTime;
      this.operationStats.averageLatency = 
        (this.operationStats.averageLatency * (this.operationStats.totalOperations - 1) + latency) /
        this.operationStats.totalOperations;
      
      return result;
      
    } catch (error) {
      this.operationStats.totalOperations++;
      this.operationStats.failedOperations++;
      
      this.log('ERROR', `Ошибка операции ${type}`, error);
      
      throw error;
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
 * Статистика операций
 */
interface CryptoOperationStats {
  totalOperations: number;
  successfulOperations: number;
  failedOperations: number;
  operationsByType: Record<string, number>;
  averageLatency: number;
}

/**
 * Singleton экземпляр CryptoService
 */
let globalCryptoService: CryptoService | null = null;

/**
 * Получение глобального экземпляра CryptoService
 */
export function getCryptoService(config?: Partial<CryptoServiceConfig>): CryptoService {
  if (!globalCryptoService) {
    globalCryptoService = new CryptoService(config);
  }
  return globalCryptoService;
}

/**
 * Инициализация глобального сервиса
 */
export async function initializeCryptoService(
  config?: Partial<CryptoServiceConfig>
): Promise<CryptoService> {
  const service = getCryptoService(config);
  await service.initialize();
  return service;
}

/**
 * Утилита для быстрого шифрования
 */
export async function encrypt(
  data: Uint8Array | string,
  key: Uint8Array,
  keyId?: string
): Promise<EncryptionEnvelope> {
  const service = new CryptoService();
  await service.initialize();
  
  const actualKeyId = keyId || service.randomUUID();
  
  await service.generateKey({
    keyType: 'MASTER_KEY',
    algorithm: 'AES-256-GCM',
    keySize: 256,
    name: actualKeyId,
    exportable: false,
  });
  
  // Регистрируем ключ напрямую в envelope service
  const result = await service.encrypt(data, actualKeyId);
  
  await service.destroy();
  
  return result;
}

/**
 * Утилита для быстрого расшифрования
 */
export async function decrypt(
  envelope: EncryptionEnvelope,
  key: Uint8Array
): Promise<Uint8Array> {
  const service = new CryptoService();
  await service.initialize();
  
  await service.generateKey({
    keyType: 'MASTER_KEY',
    algorithm: 'AES-256-GCM',
    keySize: 256,
    name: envelope.kekId,
    exportable: false,
  });
  
  const result = await service.decrypt(envelope);
  
  await service.destroy();
  
  return result;
}
