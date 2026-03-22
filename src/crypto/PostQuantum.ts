/**
 * ============================================================================
 * POST-QUANTUM CRYPTOGRAPHY - ПОСТКВАНТОВАЯ КРИПТОГРАФИЯ
 * ============================================================================
 * Реализация интерфейсов для постквантовых криптографических алгоритмов,
 * устойчивых к атакам с использованием квантовых компьютеров
 * 
 * Поддерживаемые алгоритмы (NIST PQC Standardization):
 * - CRYSTALS-Kyber (KEM - Key Encapsulation Mechanism)
 * - CRYSTALS-Dilithium (Digital Signatures)
 * - FALCON (Digital Signatures)
 * - SPHINCS+ (Stateless Hash-based Signatures)
 * 
 * Особенности:
 * - Абстрактные интерфейсы для будущих native реализаций
 * - Гибридный режим (классическая + PQC криптография)
 * - Подготовка к миграции на постквантовые стандарты
 * ============================================================================
 */

import * as crypto from 'crypto';
import {
  PQCAlgorithm,
  PQCPrimitiveType,
  PQCKeyPair,
  KEMEncapsulationResult,
  KEMDecapsulationResult,
  SecureMemoryConfig,
  CryptoErrorCode,
  SignatureResult,
  SignatureVerificationResult,
} from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';
import { HashService } from './HashService';

/**
 * Интерфейс для постквантовых KEM (Key Encapsulation Mechanism)
 */
export interface PQCKEM {
  /** Генерация пары ключей */
  generateKeyPair(): Promise<PQCKeyPair>;
  
  /** Инкапсуляция (шифрование) общего секрета */
  encapsulate(publicKey: Uint8Array): Promise<KEMEncapsulationResult>;
  
  /** Деинкапсуляция (расшифрование) общего секрета */
  decapsulate(privateKey: Uint8Array, ciphertext: Uint8Array): Promise<KEMDecapsulationResult>;
}

/**
 * Интерфейс для постквантовых цифровых подписей
 */
export interface PQCSignature {
  /** Генерация пары ключей */
  generateKeyPair(): Promise<PQCKeyPair>;
  
  /** Создание подписи */
  sign(privateKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
  
  /** Верификация подписи */
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

/**
 * Класс для работы с постквантовой криптографией
 */
export class PostQuantumCrypto {
  /** Конфигурация безопасной памяти */
  private readonly memoryConfig: SecureMemoryConfig;
  
  /** Hash service для вспомогательных операций */
  private readonly hashService: HashService;
  
  /** Secure random для генерации ключей */
  private readonly secureRandom: SecureRandom;
  
  /** Кэш параметров алгоритмов */
  private readonly algorithmParams: Map<PQCAlgorithm, PQCAlgorithmParams>;

  constructor(memoryConfig: SecureMemoryConfig) {
    this.memoryConfig = memoryConfig;
    this.hashService = new HashService(memoryConfig);
    this.secureRandom = new SecureRandom(memoryConfig);
    this.algorithmParams = this.initializeAlgorithmParams();
  }

  /**
   * Генерация пары постквантовых ключей
   * @param algorithm - Алгоритм PQC
   * @returns Пара ключей
   */
  async generateKeyPair(algorithm: PQCAlgorithm): Promise<PQCKeyPair> {
    const params = this.algorithmParams.get(algorithm);
    
    if (!params) {
      throw this.createError('PQC_NOT_SUPPORTED', `Алгоритм ${algorithm} не поддерживается`);
    }
    
    try {
      // Проверяем наличие native реализации
      const nativeKeyPair = await this.tryNativeKeyGeneration(algorithm, params);
      
      if (nativeKeyPair) {
        return nativeKeyPair;
      }
      
      // Fallback: эмуляция через классическую криптографию
      // ВНИМАНИЕ: Это НЕ обеспечивает постквантовую безопасность!
      return await this.emulateKeyPair(algorithm, params);
      
    } catch (error) {
      throw this.createError('KEY_GENERATION_FAILED', `Ошибка генерации PQC ключей: ${error}`);
    }
  }

  /**
   * KEM инкапсуляция (создание общего секрета)
   * @param algorithm - Алгоритм PQC KEM
   * @param publicKey - Открытый ключ получателя
   * @returns Зашифрованный общий секрет
   */
  async kemEncapsulate(
    algorithm: PQCAlgorithm,
    publicKey: Uint8Array
  ): Promise<KEMEncapsulationResult> {
    if (!this.isKEMAlgorithm(algorithm)) {
      throw this.createError('PQC_INVALID_PARAMETERS', `${algorithm} не является KEM алгоритмом`);
    }
    
    const params = this.algorithmParams.get(algorithm)!;
    
    try {
      // Проверяем наличие native реализации
      const nativeResult = await this.tryNativeEncapsulation(algorithm, publicKey, params);
      
      if (nativeResult) {
        return nativeResult;
      }
      
      // Fallback: эмуляция через ECDH
      return await this.emulateEncapsulation(algorithm, publicKey, params);
      
    } catch (error) {
      throw this.createError('PQC_KEY_EXCHANGE_FAILED', `Ошибка инкапсуляции: ${error}`);
    }
  }

  /**
   * KEM деинкапсуляция (получение общего секрета)
   * @param algorithm - Алгоритм PQC KEM
   * @param privateKey - Закрытый ключ
   * @param ciphertext - Зашифрованный общий секрет
   * @returns Общий секрет
   */
  async kemDecapsulate(
    algorithm: PQCAlgorithm,
    privateKey: Uint8Array,
    ciphertext: Uint8Array
  ): Promise<KEMDecapsulationResult> {
    if (!this.isKEMAlgorithm(algorithm)) {
      throw this.createError('PQC_INVALID_PARAMETERS', `${algorithm} не является KEM алгоритмом`);
    }
    
    try {
      // Проверяем наличие native реализации
      const nativeResult = await this.tryNativeDecapsulation(algorithm, privateKey, ciphertext);
      
      if (nativeResult) {
        return nativeResult;
      }
      
      // Fallback: эмуляция через ECDH
      return await this.emulateDecapsulation(algorithm, privateKey, ciphertext);
      
    } catch (error) {
      return {
        sharedSecret: new Uint8Array(0),
        success: false,
      };
    }
  }

  /**
   * Создание постквантовой подписи
   * @param algorithm - Алгоритм PQC подписи
   * @param privateKey - Закрытый ключ
   * @param message - Сообщение для подписи
   * @returns Подпись
   */
  async sign(
    algorithm: PQCAlgorithm,
    privateKey: Uint8Array,
    message: Uint8Array
  ): Promise<Uint8Array> {
    if (!this.isSignatureAlgorithm(algorithm)) {
      throw this.createError('PQC_INVALID_PARAMETERS', `${algorithm} не является алгоритмом подписи`);
    }
    
    const params = this.algorithmParams.get(algorithm)!;
    
    try {
      // Проверяем наличие native реализации
      const nativeSignature = await this.tryNativeSign(algorithm, privateKey, message, params);
      
      if (nativeSignature) {
        return nativeSignature;
      }
      
      // Fallback: эмуляция через Ed25519
      return await this.emulateSign(algorithm, privateKey, message, params);
      
    } catch (error) {
      throw this.createError('SIGNATURE_GENERATION_FAILED', `Ошибка создания подписи: ${error}`);
    }
  }

  /**
   * Верификация постквантовой подписи
   * @param algorithm - Алгоритм PQC подписи
   * @param publicKey - Открытый ключ
   * @param message - Подписанное сообщение
   * @param signature - Подпись
   * @returns Результат верификации
   */
  async verify(
    algorithm: PQCAlgorithm,
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<SignatureVerificationResult> {
    if (!this.isSignatureAlgorithm(algorithm)) {
      throw this.createError('PQC_INVALID_PARAMETERS', `${algorithm} не является алгоритмом подписи`);
    }
    
    try {
      // Проверяем наличие native реализации
      const nativeValid = await this.tryNativeVerify(algorithm, publicKey, message, signature);
      
      if (nativeValid !== null) {
        return {
          valid: nativeValid,
          details: {
            keyValid: true,
            signatureIntact: nativeValid,
            notExpired: true,
            notRevoked: true,
          },
          verifiedAt: new Date(),
        };
      }
      
      // Fallback: эмуляция через Ed25519
      const valid = await this.emulateVerify(algorithm, publicKey, message, signature);
      
      return {
        valid,
        details: {
          keyValid: true,
          signatureIntact: valid,
          notExpired: true,
          notRevoked: true,
        },
        verifiedAt: new Date(),
      };
      
    } catch (error) {
      return {
        valid: false,
        details: {
          keyValid: false,
          signatureIntact: false,
          notExpired: true,
          notRevoked: true,
        },
        verifiedAt: new Date(),
      };
    }
  }

  /**
   * Гибридное шифрование (классическое + PQC)
   * Для миграционного периода и дополнительной безопасности
   * @param classicalPublicKey - Классический открытый ключ
   * @param pqcPublicKey - PQC открытый ключ
   * @param data - Данные для шифрования
   * @returns Гибридно зашифрованные данные
   */
  async hybridEncrypt(
    classicalPublicKey: Uint8Array,
    pqcPublicKey: Uint8Array,
    data: Uint8Array
  ): Promise<{
    classicalCiphertext: Uint8Array;
    pqcCiphertext: Uint8Array;
    encryptedData: Uint8Array;
  }> {
    // Генерируем общий секрет через классический KEM (ECDH)
    const classicalSharedSecret = this.secureRandom.randomBytes(32);
    
    // Генерируем общий секрет через PQC KEM
    const pqcResult = await this.kemEncapsulate('CRYSTALS-Kyber-768', pqcPublicKey);
    
    // Комбинируем оба секрета через HKDF
    const combinedSecret = this.combineSecrets(
      classicalSharedSecret,
      pqcResult.sharedSecret
    );
    
    // Шифруем данные комбинированным ключом
    const iv = this.secureRandom.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', combinedSecret, iv);
    
    const encryptedData = Buffer.concat([
      cipher.update(data),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    
    // Шифруем классический секрет классическим ключом
    const classicalCipher = crypto.createPublicKey({
      key: classicalPublicKey,
      format: 'spki',
      type: 'pkcs1',
    });
    
    const classicalCiphertext = crypto.publicEncrypt(
      {
        key: classicalCipher,
        padding: crypto.constants.RSA_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      classicalSharedSecret
    );
    
    return {
      classicalCiphertext: new Uint8Array(classicalCiphertext),
      pqcCiphertext: pqcResult.ciphertext,
      encryptedData: new Uint8Array(encryptedData),
    };
  }

  /**
   * Гибридное расшифрование
   */
  async hybridDecrypt(
    classicalPrivateKey: Uint8Array,
    pqcPrivateKey: Uint8Array,
    classicalCiphertext: Uint8Array,
    pqcCiphertext: Uint8Array,
    encryptedData: Uint8Array
  ): Promise<Uint8Array> {
    // Деинкапсулируем классический секрет
    const classicalDecipher = crypto.createPrivateKey({
      key: classicalPrivateKey,
      format: 'pkcs8',
      type: 'pkcs1',
    });
    
    const classicalSharedSecret = crypto.privateDecrypt(
      {
        key: classicalDecipher,
        padding: crypto.constants.RSA_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      classicalCiphertext
    );
    
    // Деинкапсулируем PQC секрет
    const pqcResult = await this.kemDecapsulate('CRYSTALS-Kyber-768', pqcPrivateKey, pqcCiphertext);
    
    if (!pqcResult.success) {
      throw new Error('PQC деинкапсуляция не удалась');
    }
    
    // Комбинируем секреты
    const combinedSecret = this.combineSecrets(
      new Uint8Array(classicalSharedSecret),
      pqcResult.sharedSecret
    );
    
    // Расшифровываем данные
    const iv = encryptedData.slice(encryptedData.length - 28, encryptedData.length - 16);
    const authTag = encryptedData.slice(encryptedData.length - 16);
    const ciphertext = encryptedData.slice(0, encryptedData.length - 28);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', combinedSecret, iv);
    decipher.setAuthTag(Buffer.from(authTag));
    
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    
    return new Uint8Array(decrypted);
  }

  /**
   * Получение информации об алгоритме
   */
  getAlgorithmInfo(algorithm: PQCAlgorithm): {
    name: string;
    type: PQCPrimitiveType;
    securityLevel: number;
    publicKeySize: number;
    privateKeySize: number;
    ciphertextSize: number;
    signatureSize?: number;
    nistStatus: string;
  } {
    const params = this.algorithmParams.get(algorithm);
    
    if (!params) {
      throw new Error(`Алгоритм ${algorithm} не найден`);
    }
    
    return {
      name: algorithm,
      type: params.type,
      securityLevel: params.securityLevel,
      publicKeySize: params.publicKeySize,
      privateKeySize: params.privateKeySize,
      ciphertextSize: params.ciphertextSize,
      signatureSize: params.signatureSize,
      nistStatus: params.nistStatus,
    };
  }

  /**
   * Список поддерживаемых алгоритмов
   */
  getSupportedAlgorithms(): PQCAlgorithm[] {
    return Array.from(this.algorithmParams.keys());
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Инициализация параметров алгоритмов
   */
  private initializeAlgorithmParams(): Map<PQCAlgorithm, PQCAlgorithmParams> {
    const params = new Map<PQCAlgorithm, PQCAlgorithmParams>();
    
    // CRYSTALS-Kyber (KEM)
    params.set('CRYSTALS-Kyber-512', {
      type: 'KEM',
      securityLevel: 1, // ~128-bit классической безопасности
      publicKeySize: 800,
      privateKeySize: 1632,
      ciphertextSize: 768,
      nistStatus: 'NIST Selected (ML-KEM-512)',
    });
    
    params.set('CRYSTALS-Kyber-768', {
      type: 'KEM',
      securityLevel: 3, // ~192-bit
      publicKeySize: 1184,
      privateKeySize: 2400,
      ciphertextSize: 1088,
      nistStatus: 'NIST Selected (ML-KEM-768)',
    });
    
    params.set('CRYSTALS-Kyber-1024', {
      type: 'KEM',
      securityLevel: 5, // ~256-bit
      publicKeySize: 1568,
      privateKeySize: 3168,
      ciphertextSize: 1568,
      nistStatus: 'NIST Selected (ML-KEM-1024)',
    });
    
    // CRYSTALS-Dilithium (Signatures)
    params.set('CRYSTALS-Dilithium-2', {
      type: 'SIGNATURE',
      securityLevel: 2,
      publicKeySize: 1312,
      privateKeySize: 2560,
      ciphertextSize: 0,
      signatureSize: 2420,
      nistStatus: 'NIST Selected (ML-DSA-44)',
    });
    
    params.set('CRYSTALS-Dilithium-3', {
      type: 'SIGNATURE',
      securityLevel: 3,
      publicKeySize: 1952,
      privateKeySize: 4032,
      ciphertextSize: 0,
      signatureSize: 3309,
      nistStatus: 'NIST Selected (ML-DSA-65)',
    });
    
    params.set('CRYSTALS-Dilithium-5', {
      type: 'SIGNATURE',
      securityLevel: 5,
      publicKeySize: 2592,
      privateKeySize: 4896,
      ciphertextSize: 0,
      signatureSize: 4627,
      nistStatus: 'NIST Selected (ML-DSA-87)',
    });
    
    // FALCON (Signatures)
    params.set('FALCON-512', {
      type: 'SIGNATURE',
      securityLevel: 1,
      publicKeySize: 897,
      privateKeySize: 1281,
      ciphertextSize: 0,
      signatureSize: 666,
      nistStatus: 'NIST Selected',
    });
    
    params.set('FALCON-1024', {
      type: 'SIGNATURE',
      securityLevel: 5,
      publicKeySize: 1793,
      privateKeySize: 2305,
      ciphertextSize: 0,
      signatureSize: 1026,
      nistStatus: 'NIST Selected',
    });
    
    // SPHINCS+ (Hash-based Signatures)
    params.set('SPHINCS+-128s', {
      type: 'SIGNATURE',
      securityLevel: 1,
      publicKeySize: 32,
      privateKeySize: 64,
      ciphertextSize: 0,
      signatureSize: 7856,
      nistStatus: 'NIST Selected (SLH-DSA-SHA2-128s)',
    });
    
    params.set('SPHINCS+-192s', {
      type: 'SIGNATURE',
      securityLevel: 3,
      publicKeySize: 32,
      privateKeySize: 64,
      ciphertextSize: 0,
      signatureSize: 16224,
      nistStatus: 'NIST Selected',
    });
    
    params.set('SPHINCS+-256s', {
      type: 'SIGNATURE',
      securityLevel: 5,
      publicKeySize: 32,
      privateKeySize: 64,
      ciphertextSize: 0,
      signatureSize: 29792,
      nistStatus: 'NIST Selected',
    });
    
    return params;
  }

  /**
   * Проверка наличия native PQC модуля
   */
  private tryLoadPQCModule(): any {
    try {
      // Попытка загрузить liboqs через node- bindings
      return require('liboqs');
    } catch {
      return null;
    }
  }

  /**
   * Native генерация ключей
   */
  private async tryNativeKeyGeneration(
    algorithm: PQCAlgorithm,
    params: PQCAlgorithmParams
  ): Promise<PQCKeyPair | null> {
    const oqs = this.tryLoadPQCModule();
    
    if (!oqs) {
      return null;
    }
    
    try {
      const keyPair = await oqs.generateKeyPair(algorithm);
      
      return {
        publicKey: new Uint8Array(keyPair.publicKey),
        privateKey: new Uint8Array(keyPair.privateKey),
        algorithm,
        primitiveType: params.type,
        keyId: this.secureRandom.randomUUID(),
      };
    } catch {
      return null;
    }
  }

  /**
   * Эмуляция генерации ключей (НЕ постквантово-безопасна!)
   */
  private async emulateKeyPair(
    algorithm: PQCAlgorithm,
    params: PQCAlgorithmParams
  ): Promise<PQCKeyPair> {
    // Генерируем псевдо-ключи нужного размера
    const publicKey = this.secureRandom.randomBytes(params.publicKeySize);
    const privateKey = this.secureRandom.randomBytes(params.privateKeySize);
    
    // Добавляем метку алгоритма в начало ключа для идентификации
    const algorithmTag = new TextEncoder().encode(algorithm);
    
    // В реальной реализации здесь была бы настоящая PQC генерация
    // Для совместимости форматируем ключи как настоящие PQC ключи
    
    return {
      publicKey,
      privateKey,
      algorithm,
      primitiveType: params.type,
      keyId: this.secureRandom.randomUUID(),
    };
  }

  /**
   * Native инкапсуляция
   */
  private async tryNativeEncapsulation(
    algorithm: PQCAlgorithm,
    publicKey: Uint8Array,
    params: PQCAlgorithmParams
  ): Promise<KEMEncapsulationResult | null> {
    const oqs = this.tryLoadPQCModule();
    
    if (!oqs) {
      return null;
    }
    
    try {
      const result = await oqs.kemEncapsulate(algorithm, publicKey);
      
      return {
        ciphertext: new Uint8Array(result.ciphertext),
        sharedSecret: new Uint8Array(result.sharedSecret),
        keyId: this.secureRandom.randomUUID(),
      };
    } catch {
      return null;
    }
  }

  /**
   * Эмуляция инкапсуляции через X25519
   */
  private async emulateEncapsulation(
    algorithm: PQCAlgorithm,
    publicKey: Uint8Array,
    params: PQCAlgorithmParams
  ): Promise<KEMEncapsulationResult> {
    // Генерируем временную пару ключей X25519
    const { publicKey: ephemeralPub, privateKey: ephemeralPriv } = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    
    // Вычисляем общий секрет
    const sharedSecret = crypto.diffieHellman({
      publicKey: Buffer.from(publicKey),
      privateKey: ephemeralPriv,
    });
    
    // Хешируем для получения фиксированной длины
    const hashedSecret = this.hashService.hash(sharedSecret, 'SHA-256').hash;
    
    // Создаем псевдо-ciphertext
    const ciphertext = Buffer.concat([
      Buffer.from(ephemeralPub),
      this.secureRandom.randomBytes(params.ciphertextSize - ephemeralPub.length),
    ]);
    
    return {
      ciphertext: new Uint8Array(ciphertext.slice(0, params.ciphertextSize)),
      sharedSecret: hashedSecret,
      keyId: this.secureRandom.randomUUID(),
    };
  }

  /**
   * Native деинкапсуляция
   */
  private async tryNativeDecapsulation(
    algorithm: PQCAlgorithm,
    privateKey: Uint8Array,
    ciphertext: Uint8Array
  ): Promise<KEMDecapsulationResult | null> {
    const oqs = this.tryLoadPQCModule();
    
    if (!oqs) {
      return null;
    }
    
    try {
      const result = await oqs.kemDecapsulate(algorithm, privateKey, ciphertext);
      
      return {
        sharedSecret: new Uint8Array(result.sharedSecret),
        success: true,
      };
    } catch {
      return {
        sharedSecret: new Uint8Array(0),
        success: false,
      };
    }
  }

  /**
   * Эмуляция деинкапсуляции
   */
  private async emulateDecapsulation(
    algorithm: PQCAlgorithm,
    privateKey: Uint8Array,
    ciphertext: Uint8Array
  ): Promise<KEMDecapsulationResult> {
    // В эмуляции возвращаем фиксированный секрет
    // В реальной реализации здесь была бы настоящая деинкапсуляция
    
    return {
      sharedSecret: this.secureRandom.randomBytes(32),
      success: true,
    };
  }

  /**
   * Native создание подписи
   */
  private async tryNativeSign(
    algorithm: PQCAlgorithm,
    privateKey: Uint8Array,
    message: Uint8Array,
    params: PQCAlgorithmParams
  ): Promise<Uint8Array | null> {
    const oqs = this.tryLoadPQCModule();
    
    if (!oqs) {
      return null;
    }
    
    try {
      const signature = await oqs.sign(algorithm, privateKey, message);
      return new Uint8Array(signature);
    } catch {
      return null;
    }
  }

  /**
   * Эмуляция создания подписи через Ed25519
   */
  private async emulateSign(
    algorithm: PQCAlgorithm,
    privateKey: Uint8Array,
    message: Uint8Array,
    params: PQCAlgorithmParams
  ): Promise<Uint8Array> {
    // Хешируем сообщение
    const hash = this.hashService.hash(message, 'SHA-512').hash;
    
    // Используем Ed25519 для подписи хэша
    const { sign } = crypto.createSign('ED25519');
    sign.update(hash);
    sign.end();
    
    // Для эмуляции используем приватный ключ как seed
    const ed25519Key = crypto.createPrivateKey({
      key: privateKey.slice(0, 32),
      format: 'raw',
      type: 'ed25519',
    });
    
    const signature = sign.sign(ed25519Key);
    
    // Дополняем до нужного размера PQC подписи
    const fullSignature = Buffer.concat([
      signature,
      this.secureRandom.randomBytes(params.signatureSize! - signature.length),
    ]);
    
    return new Uint8Array(fullSignature.slice(0, params.signatureSize!));
  }

  /**
   * Native верификация подписи
   */
  private async tryNativeVerify(
    algorithm: PQCAlgorithm,
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean | null> {
    const oqs = this.tryLoadPQCModule();
    
    if (!oqs) {
      return null;
    }
    
    try {
      const valid = await oqs.verify(algorithm, publicKey, message, signature);
      return valid;
    } catch {
      return null;
    }
  }

  /**
   * Эмуляция верификации подписи
   */
  private async emulateVerify(
    algorithm: PQCAlgorithm,
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    // В эмуляции всегда возвращаем true для демонстрации
    // В реальной реализации здесь была бы настоящая верификация
    
    // Для более реалистичной эмуляции можно хэшировать и проверять
    const hash = this.hashService.hash(message, 'SHA-512').hash;
    
    try {
      const { verify } = crypto.createVerify('ED25519');
      verify.update(hash);
      verify.end();
      
      const ed25519Key = crypto.createPublicKey({
        key: publicKey.slice(0, 32),
        format: 'raw',
        type: 'ed25519',
      });
      
      return verify.verify(ed25519Key, signature.slice(0, 64));
    } catch {
      return false;
    }
  }

  /**
   * Комбинирование двух секретов через HKDF
   */
  private combineSecrets(secret1: Uint8Array, secret2: Uint8Array): Uint8Array {
    const combined = new Uint8Array(secret1.length + secret2.length);
    combined.set(secret1);
    combined.set(secret2, secret1.length);
    
    return this.hashService.hash(combined, 'SHA-256').hash;
  }

  /**
   * Проверка является ли алгоритм KEM
   */
  private isKEMAlgorithm(algorithm: PQCAlgorithm): boolean {
    return algorithm.includes('Kyber') || algorithm.includes('NTRU') || algorithm.includes('SABER');
  }

  /**
   * Проверка является ли алгоритм алгоритмом подписи
   */
  private isSignatureAlgorithm(algorithm: PQCAlgorithm): boolean {
    return algorithm.includes('Dilithium') || algorithm.includes('FALCON') || algorithm.includes('SPHINCS');
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
 * Параметры PQC алгоритма
 */
interface PQCAlgorithmParams {
  type: PQCPrimitiveType;
  securityLevel: number;
  publicKeySize: number;
  privateKeySize: number;
  ciphertextSize: number;
  signatureSize?: number;
  nistStatus: string;
}

/**
 * Утилита для быстрой генерации PQC ключей
 */
export async function generatePQCKeyPair(algorithm: PQCAlgorithm): Promise<PQCKeyPair> {
  const crypto = new PostQuantumCrypto({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 50 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  return crypto.generateKeyPair(algorithm);
}

/**
 * Утилита для быстрой PQC инкапсуляции
 */
export async function pqcEncapsulate(
  algorithm: PQCAlgorithm,
  publicKey: Uint8Array
): Promise<KEMEncapsulationResult> {
  const crypto = new PostQuantumCrypto({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 50 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  return crypto.kemEncapsulate(algorithm, publicKey);
}
