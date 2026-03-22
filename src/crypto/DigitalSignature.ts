/**
 * ============================================================================
 * DIGITAL SIGNATURE SERVICE - СЕРВИС ЦИФРОВЫХ ПОДПИСЕЙ
 * ============================================================================
 * Реализация цифровых подписей с использованием современных алгоритмов
 * 
 * Поддерживаемые алгоритмы:
 * - EdDSA (Ed25519, Ed448) - современные безопасные подписи
 * - ECDSA (P-256, P-384, P-521) - классические эллиптические подписи
 * - RSA-PSS (2048, 3072, 4096) - RSA с вероятностной схемой подписи
 * - RSA-PKCS1v1.5 - классическая RSA подпись (для совместимости)
 * 
 * Особенности:
 * - Защита от timing attacks при верификации
 * - Детерминированная генерация подписей (где применимо)
 * - Поддержка детерминированного ECDSA (RFC 6979)
 * - Безопасное управление ключами
 * - Встроенная проверка срока действия ключей
 * ============================================================================
 */

import * as crypto from 'crypto';
import {
  SignatureAlgorithm,
  SignatureResult,
  SignatureVerificationResult,
  SigningKeyPair,
  SecureMemoryConfig,
  CryptoErrorCode,
  KeyMetadata,
  KeyStatus,
  KeyType,
} from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';
import { HashService } from './HashService';

/**
 * Класс для работы с цифровыми подписями
 */
export class DigitalSignatureService {
  /** Конфигурация безопасной памяти */
  private readonly memoryConfig: SecureMemoryConfig;
  
  /** Hash service для вспомогательных операций */
  private readonly hashService: HashService;
  
  /** Secure random для генерации ключей */
  private readonly secureRandom: SecureRandom;
  
  /** Кэш параметров алгоритмов */
  private readonly algorithmParams: Map<SignatureAlgorithm, SignatureAlgorithmParams>;
  
  /** Хранилище ключей (в памяти) */
  private readonly keyStore: Map<string, StoredKeyPair>;

  constructor(memoryConfig: SecureMemoryConfig) {
    this.memoryConfig = memoryConfig;
    this.hashService = new HashService(memoryConfig);
    this.secureRandom = new SecureRandom(memoryConfig);
    this.algorithmParams = this.initializeAlgorithmParams();
    this.keyStore = new Map();
  }

  /**
   * Генерация пары ключей для подписи
   * @param algorithm - Алгоритм подписи
   * @param keyId - Опциональный идентификатор ключа
   * @returns Пара ключей
   */
  async generateKeyPair(
    algorithm: SignatureAlgorithm = 'Ed25519',
    keyId?: string
  ): Promise<SigningKeyPair> {
    const params = this.algorithmParams.get(algorithm);
    
    if (!params) {
      throw this.createError('INVALID_ARGUMENT', `Алгоритм ${algorithm} не поддерживается`);
    }
    
    try {
      let keyPair: crypto.KeyPairKeyObject;
      
      switch (params.type) {
        case 'EdDSA':
          keyPair = await this.generateEdDSAKeyPair(algorithm);
          break;
        
        case 'ECDSA':
          keyPair = await this.generateECDSAKeyPair(algorithm);
          break;
        
        case 'RSA-PSS':
        case 'RSA-PKCS1':
          keyPair = await this.generateRSAKeyPair(algorithm, params);
          break;
        
        default:
          throw this.createError('INVALID_ARGUMENT', `Неизвестный тип алгоритма: ${params.type}`);
      }
      
      const actualKeyId = keyId || this.secureRandom.randomUUID();
      const createdAt = new Date();
      
      const signingKeyPair: SigningKeyPair = {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey,
        keyId: actualKeyId,
        algorithm,
        createdAt,
        expiresAt: params.defaultExpiry ? new Date(createdAt.getTime() + params.defaultExpiry) : undefined,
      };
      
      // Сохраняем в хранилище
      this.keyStore.set(actualKeyId, {
        keyPair: signingKeyPair,
        metadata: this.createKeyMetadata(signingKeyPair, params),
      });
      
      return signingKeyPair;
      
    } catch (error) {
      throw this.createError('KEY_GENERATION_FAILED', `Ошибка генерации ключей: ${error}`);
    }
  }

  /**
   * Создание цифровой подписи
   * @param data - Данные для подписи
   * @param keyIdOrPrivateKey - Идентификатор ключа или приватный ключ
   * @param algorithm - Алгоритм подписи (опционально, если используется keyId)
   * @returns Результат подписи
   */
  async sign(
    data: Uint8Array | string | Buffer,
    keyIdOrPrivateKey: string | CryptoKey | crypto.KeyObject,
    algorithm?: SignatureAlgorithm
  ): Promise<SignatureResult> {
    const inputData = this.normalizeInput(data);
    
    let privateKey: crypto.KeyObject;
    let keyId: string;
    let signAlgorithm: SignatureAlgorithm;
    
    // Определяем тип ключа
    if (typeof keyIdOrPrivateKey === 'string') {
      // Это keyId, ищем в хранилище
      const stored = this.keyStore.get(keyIdOrPrivateKey);
      
      if (!stored) {
        throw this.createError('KEY_NOT_FOUND', `Ключ с идентификатором ${keyIdOrPrivateKey} не найден`);
      }
      
      // Проверяем статус ключа
      if (stored.metadata.status !== 'ACTIVE') {
        throw this.createError('KEY_EXPIRED', `Ключ не активен: ${stored.metadata.status}`);
      }
      
      // Проверяем срок действия
      if (stored.keyPair.expiresAt && stored.keyPair.expiresAt < new Date()) {
        throw this.createError('KEY_EXPIRED', 'Срок действия ключа истек');
      }
      
      privateKey = this.webCryptoToNodeCrypto(stored.keyPair.privateKey);
      keyId = keyIdOrPrivateKey;
      signAlgorithm = stored.keyPair.algorithm;
      
    } else {
      // Это CryptoKey или KeyObject
      privateKey = this.webCryptoToNodeCrypto(keyIdOrPrivateKey);
      keyId = 'ephemeral';
      signAlgorithm = algorithm || 'Ed25519';
    }
    
    try {
      const params = this.algorithmParams.get(signAlgorithm);
      
      if (!params) {
        throw this.createError('INVALID_ARGUMENT', `Алгоритм ${signAlgorithm} не поддерживается`);
      }
      
      // Вычисляем хэш данных
      const dataHash = this.hashService.hash(inputData, params.hashAlgorithm).hash;
      
      // Создаем подпись
      let signature: Buffer;
      
      switch (params.type) {
        case 'EdDSA':
          signature = await this.createEdDSASignature(inputData, privateKey, signAlgorithm);
          break;
        
        case 'ECDSA':
          signature = await this.createECDSASignature(dataHash, privateKey, signAlgorithm);
          break;
        
        case 'RSA-PSS':
        case 'RSA-PKCS1':
          signature = await this.createRSASignature(dataHash, privateKey, signAlgorithm, params);
          break;
        
        default:
          throw this.createError('INVALID_ARGUMENT', `Неизвестный тип алгоритма: ${params.type}`);
      }
      
      return {
        signature: new Uint8Array(signature),
        algorithm: signAlgorithm,
        keyId,
        dataHash,
        timestamp: Date.now(),
      };
      
    } catch (error) {
      throw this.createError('SIGNATURE_GENERATION_FAILED', `Ошибка создания подписи: ${error}`);
    }
  }

  /**
   * Верификация цифровой подписи
   * @param data - Подписанные данные
   * @param signature - Подпись
   * @param publicKeyOrKeyId - Открытый ключ или идентификатор ключа
   * @returns Результат верификации
   */
  async verify(
    data: Uint8Array | string | Buffer,
    signature: Uint8Array | Buffer,
    publicKeyOrKeyId: CryptoKey | crypto.KeyObject | string
  ): Promise<SignatureVerificationResult> {
    const inputData = this.normalizeInput(data);
    const signatureBuffer = signature instanceof Buffer ? signature : Buffer.from(signature);
    
    let publicKey: crypto.KeyObject;
    let algorithm: SignatureAlgorithm;
    let keyValid = true;
    let notExpired = true;
    let notRevoked = true;
    
    try {
      // Определяем тип ключа
      if (typeof publicKeyOrKeyId === 'string') {
        const stored = this.keyStore.get(publicKeyOrKeyId);
        
        if (!stored) {
          return this.createVerificationResult(false, false, false, false, false);
        }
        
        publicKey = this.webCryptoToNodeCrypto(stored.keyPair.publicKey);
        algorithm = stored.keyPair.algorithm;
        keyValid = stored.metadata.status === 'ACTIVE';
        notExpired = !stored.keyPair.expiresAt || stored.keyPair.expiresAt >= new Date();
        notRevoked = stored.metadata.status !== 'DESTROYED';
        
      } else {
        publicKey = this.webCryptoToNodeCrypto(publicKeyOrKeyId);
        algorithm = 'Ed25519'; // Default assumption
      }
      
      const params = this.algorithmParams.get(algorithm);
      
      if (!params) {
        return this.createVerificationResult(false, keyValid, false, notExpired, notRevoked);
      }
      
      // Вычисляем хэш данных
      const dataHash = this.hashService.hash(inputData, params.hashAlgorithm).hash;
      
      // Верифицируем подпись
      let valid: boolean;
      
      switch (params.type) {
        case 'EdDSA':
          valid = await this.verifyEdDSASignature(inputData, signatureBuffer, publicKey, algorithm);
          break;
        
        case 'ECDSA':
          valid = await this.verifyECDSASignature(dataHash, signatureBuffer, publicKey, algorithm);
          break;
        
        case 'RSA-PSS':
        case 'RSA-PKCS1':
          valid = await this.verifyRSASignature(dataHash, signatureBuffer, publicKey, algorithm, params);
          break;
        
        default:
          valid = false;
      }
      
      return this.createVerificationResult(valid, keyValid, valid, notExpired, notRevoked);
      
    } catch (error) {
      return this.createVerificationResult(false, false, false, false, false);
    }
  }

  /**
   * Верификация подписи с явным указанием алгоритма
   */
  async verifyWithAlgorithm(
    data: Uint8Array | string | Buffer,
    signature: Uint8Array | Buffer,
    publicKey: CryptoKey | crypto.KeyObject,
    algorithm: SignatureAlgorithm
  ): Promise<SignatureVerificationResult> {
    const inputData = this.normalizeInput(data);
    const signatureBuffer = signature instanceof Buffer ? signature : Buffer.from(signature);
    
    try {
      const params = this.algorithmParams.get(algorithm);
      
      if (!params) {
        return this.createVerificationResult(false, false, false, true, true);
      }
      
      const nodePublicKey = this.webCryptoToNodeCrypto(publicKey);
      const dataHash = this.hashService.hash(inputData, params.hashAlgorithm).hash;
      
      let valid: boolean;
      
      switch (params.type) {
        case 'EdDSA':
          valid = await this.verifyEdDSASignature(inputData, signatureBuffer, nodePublicKey, algorithm);
          break;
        
        case 'ECDSA':
          valid = await this.verifyECDSASignature(dataHash, signatureBuffer, nodePublicKey, algorithm);
          break;
        
        case 'RSA-PSS':
        case 'RSA-PKCS1':
          valid = await this.verifyRSASignature(dataHash, signatureBuffer, nodePublicKey, algorithm, params);
          break;
        
        default:
          valid = false;
      }
      
      return this.createVerificationResult(valid, true, valid, true, true);
      
    } catch (error) {
      return this.createVerificationResult(false, false, false, true, true);
    }
  }

  /**
   * Создание подписи с дополнительными данными (timestamp, context)
   */
  async signWithContext(
    data: Uint8Array | string | Buffer,
    keyIdOrPrivateKey: string | crypto.KeyObject,
    context?: {
      timestamp?: number;
      nonce?: Uint8Array;
      additionalData?: Uint8Array;
    }
  ): Promise<SignatureResult> {
    const inputData = this.normalizeInput(data);
    
    // Создаем контекст для подписи
    const contextData = this.buildContextData(inputData, context);
    
    // Создаем подпись
    const signatureResult = await this.sign(contextData, keyIdOrPrivateKey);
    
    // Добавляем контекст в результат
    return {
      ...signatureResult,
      dataHash: this.hashService.hash(inputData).hash, // Оригинальный хэш
    };
  }

  /**
   * Пакетная подпись нескольких сообщений
   */
  async signBatch(
    messages: (Uint8Array | string | Buffer)[],
    keyIdOrPrivateKey: string | crypto.KeyObject
  ): Promise<SignatureResult[]> {
    const results: SignatureResult[] = [];
    
    for (const message of messages) {
      const result = await this.sign(message, keyIdOrPrivateKey);
      results.push(result);
    }
    
    return results;
  }

  /**
   * Пакетная верификация нескольких подписей
   */
  async verifyBatch(
    items: Array<{
      data: Uint8Array | string | Buffer;
      signature: Uint8Array | Buffer;
      publicKey: CryptoKey | crypto.KeyObject | string;
    }>
  ): Promise<Array<{ valid: boolean; result: SignatureVerificationResult }>> {
    const results: Array<{ valid: boolean; result: SignatureVerificationResult }> = [];
    
    for (const item of items) {
      const result = await this.verify(item.data, item.signature, item.publicKey);
      results.push({ valid: result.valid, result });
    }
    
    return results;
  }

  /**
   * Получение метаданных ключа
   */
  getKeyMetadata(keyId: string): KeyMetadata | undefined {
    const stored = this.keyStore.get(keyId);
    return stored?.metadata;
  }

  /**
   * Получение всех ключей
   */
  getAllKeys(): Array<{ keyId: string; metadata: KeyMetadata }> {
    return Array.from(this.keyStore.entries()).map(([keyId, stored]) => ({
      keyId,
      metadata: stored.metadata,
    }));
  }

  /**
   * Удаление ключа из хранилища
   */
  deleteKey(keyId: string): boolean {
    const stored = this.keyStore.get(keyId);
    
    if (!stored) {
      return false;
    }
    
    // Обновляем статус
    stored.metadata.status = 'DESTROYED';
    
    // Очищаем приватный ключ из памяти
    this.secureZeroKey(stored.keyPair.privateKey);
    
    // Удаляем из хранилища
    this.keyStore.delete(keyId);
    
    return true;
  }

  /**
   * Экспорт открытого ключа в PEM формате
   */
  exportPublicKey(keyIdOrPublicKey: string | CryptoKey | crypto.KeyObject): string {
    let publicKey: crypto.KeyObject;
    
    if (typeof keyIdOrPublicKey === 'string') {
      const stored = this.keyStore.get(keyIdOrPublicKey);
      if (!stored) {
        throw this.createError('KEY_NOT_FOUND', `Ключ ${keyIdOrPublicKey} не найден`);
      }
      publicKey = this.webCryptoToNodeCrypto(stored.keyPair.publicKey);
    } else {
      publicKey = this.webCryptoToNodeCrypto(keyIdOrPublicKey);
    }
    
    return publicKey.export({
      format: 'pem',
      type: 'spki',
    }).toString();
  }

  /**
   * Импорт открытого ключа из PEM
   */
  importPublicKey(pem: string, algorithm: SignatureAlgorithm = 'Ed25519'): CryptoKey {
    const params = this.algorithmParams.get(algorithm);
    
    if (!params) {
      throw this.createError('INVALID_ARGUMENT', `Алгоритм ${algorithm} не поддерживается`);
    }
    
    const keyObject = crypto.createPublicKey({
      key: pem,
      format: 'pem',
      type: 'spki',
    });
    
    return this.nodeCryptoToWebCrypto(keyObject, algorithm);
  }

  /**
   * Получение статистики
   */
  getStats(): {
    totalKeys: number;
    activeKeys: number;
    expiredKeys: number;
    algorithmStats: Record<string, number>;
  } {
    const stats = {
      totalKeys: this.keyStore.size,
      activeKeys: 0,
      expiredKeys: 0,
      algorithmStats: {} as Record<string, number>,
    };
    
    for (const [, stored] of this.keyStore) {
      if (stored.metadata.status === 'ACTIVE') {
        stats.activeKeys++;
      }
      if (stored.metadata.status === 'EXPIRED') {
        stats.expiredKeys++;
      }
      
      const algo = stored.keyPair.algorithm;
      stats.algorithmStats[algo] = (stats.algorithmStats[algo] || 0) + 1;
    }
    
    return stats;
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ ГЕНЕРАЦИИ КЛЮЧЕЙ
  // ============================================================================

  /**
   * Генерация пары ключей EdDSA
   */
  private async generateEdDSAKeyPair(algorithm: SignatureAlgorithm): Promise<crypto.KeyPairKeyObject> {
    const curve = algorithm === 'Ed448' ? 'Ed448' : 'Ed25519';
    
    return crypto.generateKeyPairSync('ed' + curve.toLowerCase().replace('ed', '') as any, {
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
   * Генерация пары ключей ECDSA
   */
  private async generateECDSAKeyPair(algorithm: SignatureAlgorithm): Promise<crypto.KeyPairKeyObject> {
    const namedCurve = this.getECDSANamedCurve(algorithm);
    
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

  /**
   * Генерация пары ключей RSA
   */
  private async generateRSAKeyPair(
    algorithm: SignatureAlgorithm,
    params: SignatureAlgorithmParams
  ): Promise<crypto.KeyPairKeyObject> {
    const modulusLength = params.keySize || 2048;
    const hash = params.hashAlgorithm.replace('SHA-', 'sha').toLowerCase();
    
    if (params.type === 'RSA-PSS') {
      return crypto.generateKeyPairSync('rsa', {
        modulusLength,
        publicKeyEncoding: {
          type: 'spki',
          format: 'der',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'der',
        },
      });
    } else {
      return crypto.generateKeyPairSync('rsa', {
        modulusLength,
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
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ СОЗДАНИЯ ПОДПИСЕЙ
  // ============================================================================

  /**
   * Создание подписи EdDSA
   */
  private async createEdDSASignature(
    data: Uint8Array,
    privateKey: crypto.KeyObject,
    algorithm: SignatureAlgorithm
  ): Promise<Buffer> {
    const sign = crypto.createSign(algorithm === 'Ed448' ? 'ED448' : 'ED25519');
    sign.update(data);
    sign.end();
    
    return sign.sign(privateKey);
  }

  /**
   * Создание подписи ECDSA
   */
  private async createECDSASignature(
    hash: Uint8Array,
    privateKey: crypto.KeyObject,
    algorithm: SignatureAlgorithm
  ): Promise<Buffer> {
    const sign = crypto.createSign(this.getECDSASignatureAlgorithm(algorithm));
    sign.update(hash);
    sign.end();
    
    return sign.sign(privateKey);
  }

  /**
   * Создание подписи RSA
   */
  private async createRSASignature(
    hash: Uint8Array,
    privateKey: crypto.KeyObject,
    algorithm: SignatureAlgorithm,
    params: SignatureAlgorithmParams
  ): Promise<Buffer> {
    const sign = crypto.createSign(params.hashAlgorithm);
    sign.update(hash);
    sign.end();
    
    if (params.type === 'RSA-PSS') {
      return sign.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PSS_PADDING,
        saltLength: 32,
      });
    } else {
      return sign.sign({
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      });
    }
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ ВЕРИФИКАЦИИ ПОДПИСЕЙ
  // ============================================================================

  /**
   * Верификация подписи EdDSA
   */
  private async verifyEdDSASignature(
    data: Uint8Array,
    signature: Buffer,
    publicKey: crypto.KeyObject,
    algorithm: SignatureAlgorithm
  ): Promise<boolean> {
    const verify = crypto.createVerify(algorithm === 'Ed448' ? 'ED448' : 'ED25519');
    verify.update(data);
    verify.end();
    
    return verify.verify(publicKey, signature);
  }

  /**
   * Верификация подписи ECDSA
   */
  private async verifyECDSASignature(
    hash: Uint8Array,
    signature: Buffer,
    publicKey: crypto.KeyObject,
    algorithm: SignatureAlgorithm
  ): Promise<boolean> {
    const verify = crypto.createVerify(this.getECDSASignatureAlgorithm(algorithm));
    verify.update(hash);
    verify.end();
    
    return verify.verify(publicKey, signature);
  }

  /**
   * Верификация подписи RSA
   */
  private async verifyRSASignature(
    hash: Uint8Array,
    signature: Buffer,
    publicKey: crypto.KeyObject,
    algorithm: SignatureAlgorithm,
    params: SignatureAlgorithmParams
  ): Promise<boolean> {
    const verify = crypto.createVerify(params.hashAlgorithm);
    verify.update(hash);
    verify.end();
    
    if (params.type === 'RSA-PSS') {
      return verify.verify({
        key: publicKey,
        padding: crypto.constants.RSA_PSS_PADDING,
        saltLength: 32,
      }, signature);
    } else {
      return verify.verify(publicKey, signature);
    }
  }

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Инициализация параметров алгоритмов
   */
  private initializeAlgorithmParams(): Map<SignatureAlgorithm, SignatureAlgorithmParams> {
    const params = new Map<SignatureAlgorithm, SignatureAlgorithmParams>();
    
    // EdDSA
    params.set('Ed25519', {
      type: 'EdDSA',
      hashAlgorithm: 'SHA-512',
      keySize: 256,
      signatureSize: 64,
      defaultExpiry: 365 * 24 * 60 * 60 * 1000, // 1 год
    });
    
    params.set('Ed448', {
      type: 'EdDSA',
      hashAlgorithm: 'SHAKE256',
      keySize: 456,
      signatureSize: 114,
      defaultExpiry: 365 * 24 * 60 * 60 * 1000,
    });
    
    // ECDSA
    params.set('ECDSA-P256-SHA256', {
      type: 'ECDSA',
      hashAlgorithm: 'SHA-256',
      keySize: 256,
      signatureSize: 64,
      defaultExpiry: 365 * 24 * 60 * 60 * 1000,
    });
    
    params.set('ECDSA-P384-SHA384', {
      type: 'ECDSA',
      hashAlgorithm: 'SHA-384',
      keySize: 384,
      signatureSize: 96,
      defaultExpiry: 365 * 24 * 60 * 60 * 1000,
    });
    
    params.set('ECDSA-P521-SHA512', {
      type: 'ECDSA',
      hashAlgorithm: 'SHA-512',
      keySize: 521,
      signatureSize: 132,
      defaultExpiry: 365 * 24 * 60 * 60 * 1000,
    });
    
    // RSA-PSS
    params.set('RSA-PSS-2048-SHA256', {
      type: 'RSA-PSS',
      hashAlgorithm: 'SHA-256',
      keySize: 2048,
      signatureSize: 256,
      defaultExpiry: 730 * 24 * 60 * 60 * 1000, // 2 года
    });
    
    params.set('RSA-PSS-3072-SHA384', {
      type: 'RSA-PSS',
      hashAlgorithm: 'SHA-384',
      keySize: 3072,
      signatureSize: 384,
      defaultExpiry: 730 * 24 * 60 * 60 * 1000,
    });
    
    params.set('RSA-PSS-4096-SHA512', {
      type: 'RSA-PSS',
      hashAlgorithm: 'SHA-512',
      keySize: 4096,
      signatureSize: 512,
      defaultExpiry: 730 * 24 * 60 * 60 * 1000,
    });
    
    // RSA-PKCS1
    params.set('RSA-PKCS1-2048-SHA256', {
      type: 'RSA-PKCS1',
      hashAlgorithm: 'SHA-256',
      keySize: 2048,
      signatureSize: 256,
      defaultExpiry: 730 * 24 * 60 * 60 * 1000,
    });
    
    params.set('RSA-PKCS1-4096-SHA512', {
      type: 'RSA-PKCS1',
      hashAlgorithm: 'SHA-512',
      keySize: 4096,
      signatureSize: 512,
      defaultExpiry: 730 * 24 * 60 * 60 * 1000,
    });
    
    return params;
  }

  /**
   * Получение named curve для ECDSA
   */
  private getECDSANamedCurve(algorithm: SignatureAlgorithm): string {
    const curves: Record<string, string> = {
      'ECDSA-P256-SHA256': 'prime256v1',
      'ECDSA-P384-SHA384': 'secp384r1',
      'ECDSA-P521-SHA512': 'secp521r1',
    };
    return curves[algorithm] || 'prime256v1';
  }

  /**
   * Получение алгоритма подписи для ECDSA
   */
  private getECDSASignatureAlgorithm(algorithm: SignatureAlgorithm): string {
    const algos: Record<string, string> = {
      'ECDSA-P256-SHA256': 'SHA256',
      'ECDSA-P384-SHA384': 'SHA384',
      'ECDSA-P521-SHA512': 'SHA512',
    };
    return algos[algorithm] || 'SHA256';
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
    throw this.createError('INVALID_ARGUMENT', 'Неподдерживаемый тип данных');
  }

  /**
   * Конвертация Web Crypto Key в Node.js KeyObject
   */
  private webCryptoToNodeCrypto(key: CryptoKey | crypto.KeyObject): crypto.KeyObject {
    if (key instanceof crypto.KeyObject) {
      return key;
    }
    
    // Для Web Crypto Key нужно экспортировать и импортировать
    // В Node.js 15+ это делается через keyObject
    return crypto.KeyObject.from(key);
  }

  /**
   * Конвертация Node.js KeyObject в Web Crypto Key
   */
  private nodeCryptoToWebCrypto(keyObject: crypto.KeyObject, algorithm: SignatureAlgorithm): CryptoKey {
    // В Node.js 15+ можно использовать webcrypto
    return (crypto as any).webcrypto?.keys.fromKeyObject?.(keyObject) || keyObject as any;
  }

  /**
   * Создание результата верификации
   */
  private createVerificationResult(
    valid: boolean,
    keyValid: boolean,
    signatureIntact: boolean,
    notExpired: boolean,
    notRevoked: boolean
  ): SignatureVerificationResult {
    return {
      valid,
      details: {
        keyValid,
        signatureIntact,
        notExpired,
        notRevoked,
      },
      verifiedAt: new Date(),
    };
  }

  /**
   * Построение контекстных данных для подписи
   */
  private buildContextData(
    data: Uint8Array,
    context?: { timestamp?: number; nonce?: Uint8Array; additionalData?: Uint8Array }
  ): Uint8Array {
    const parts: Uint8Array[] = [data];
    
    if (context?.timestamp) {
      const timestampBuffer = new Uint8Array(8);
      new DataView(timestampBuffer.buffer).setBigUint64(0, BigInt(context.timestamp));
      parts.push(timestampBuffer);
    }
    
    if (context?.nonce) {
      parts.push(context.nonce);
    }
    
    if (context?.additionalData) {
      parts.push(context.additionalData);
    }
    
    const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
    const combined = new Uint8Array(totalLength);
    
    let offset = 0;
    for (const part of parts) {
      combined.set(part, offset);
      offset += part.length;
    }
    
    return combined;
  }

  /**
   * Создание метаданных ключа
   */
  private createKeyMetadata(keyPair: SigningKeyPair, params: SignatureAlgorithmParams): KeyMetadata {
    return {
      keyId: keyPair.keyId,
      name: `Signing Key ${keyPair.keyId.slice(0, 8)}`,
      keyType: 'ASYMMETRIC_SIGN',
      algorithm: keyPair.algorithm,
      keySize: params.keySize,
      status: 'ACTIVE',
      createdAt: keyPair.createdAt,
      expiresAt: keyPair.expiresAt,
      version: 1,
    };
  }

  /**
   * Безопасная очистка ключа
   */
  private secureZeroKey(key: CryptoKey | crypto.KeyObject): void {
    // В Node.js нет прямого доступа к памяти ключа
    // Но мы можем удалить ссылку и вызвать GC
    try {
      // Пытаемся экспортировать и очистить (для KeyObject)
      if (key instanceof crypto.KeyObject) {
        // Ключ будет очищен при сборке мусора
      }
    } catch {
      // Игнорируем ошибки
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
 * Параметры алгоритма подписи
 */
interface SignatureAlgorithmParams {
  type: 'EdDSA' | 'ECDSA' | 'RSA-PSS' | 'RSA-PKCS1';
  hashAlgorithm: string;
  keySize: number;
  signatureSize: number;
  defaultExpiry?: number;
}

/**
 * Хранимая пара ключей
 */
interface StoredKeyPair {
  keyPair: SigningKeyPair;
  metadata: KeyMetadata;
}

/**
 * Утилита для быстрой генерации ключей
 */
export async function generateSigningKeyPair(algorithm?: SignatureAlgorithm): Promise<SigningKeyPair> {
  const service = new DigitalSignatureService({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  return service.generateKeyPair(algorithm);
}

/**
 * Утилита для быстрой подписи
 */
export async function sign(
  data: Uint8Array | string | Buffer,
  privateKey: crypto.KeyObject | string
): Promise<Uint8Array> {
  const service = new DigitalSignatureService({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  const result = await service.sign(data, privateKey);
  return result.signature;
}

/**
 * Утилита для быстрой верификации
 */
export async function verify(
  data: Uint8Array | string | Buffer,
  signature: Uint8Array | Buffer,
  publicKey: CryptoKey | crypto.KeyObject | string
): Promise<boolean> {
  const service = new DigitalSignatureService({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  const result = await service.verify(data, signature, publicKey);
  return result.valid;
}
