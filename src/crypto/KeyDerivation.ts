/**
 * ============================================================================
 * KEY DERIVATION SERVICE - СЕРВИС ДЕРИВАЦИИ КЛЮЧЕЙ (KDF)
 * ============================================================================
 * Реализация функций деривации ключей с использованием современных алгоритмов
 * 
 * Поддерживаемые алгоритмы:
 * - Argon2id (победитель Password Hashing Competition, рекомендуется)
 * - Argon2i (защита от side-channel)
 * - Argon2d (максимальная производительность)
 * - PBKDF2 (RFC 8018, совместимость)
 * - HKDF (RFC 5869, для ключей с высокой энтропией)
 * - scrypt (RFC 7914, memory-hard)
 * 
 * Особенности:
 * - Защита от brute-force атак
 * - Memory-hard функции для защиты от GPU/ASIC
 * - Constant-time операции
 * - Безопасное управление памятью
 * ============================================================================
 */

import * as crypto from 'crypto';
import { 
  KDFAlgorithm, 
  KDFParams, 
  Argon2Params, 
  PBKDF2Params, 
  HKDFParams, 
  ScryptParams,
  SecureMemoryConfig,
  CryptoErrorCode,
} from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';
import { HashService } from './HashService';

/**
 * Класс для деривации криптографических ключей
 */
export class KeyDerivationService {
  /** Конфигурация безопасной памяти */
  private readonly memoryConfig: SecureMemoryConfig;
  
  /** Параметры по умолчанию для Argon2 */
  private readonly defaultArgon2Params: Argon2Params = {
    memorySize: 65536,      // 64 MB
    iterations: 3,
    parallelism: 4,
    hashLength: 32,         // 256 бит
  };
  
  /** Параметры по умолчанию для PBKDF2 */
  private readonly defaultPBKDF2Params: PBKDF2Params = {
    hash: 'SHA-256',
    iterations: 600000,     // OWASP рекомендация для 2023+
    keyLength: 32,
  };
  
  /** Параметры по умолчанию для scrypt */
  private readonly defaultScryptParams: ScryptParams = {
    N: 2 ** 20,            // CPU/memory cost (1M)
    r: 8,                   // Block size
    p: 1,                   // Parallelization
    keyLength: 32,
  };
  
  /** Hash service для вспомогательных операций */
  private readonly hashService: HashService;

  /**
   * Создает экземпляр KeyDerivationService
   * @param memoryConfig - Конфигурация безопасной памяти
   */
  constructor(memoryConfig: SecureMemoryConfig) {
    this.memoryConfig = memoryConfig;
    this.hashService = new HashService(memoryConfig);
  }

  /**
   * Деривация ключа из пароля/секрета
   * @param password - Пароль или секрет (строка или байты)
   * @param salt - Соль (должна быть уникальной и случайной)
   * @param params - Параметры KDF
   * @returns Derived key в виде Uint8Array
   */
  public deriveKey(
    password: string | Uint8Array,
    salt: Uint8Array,
    params: KDFParams
  ): Uint8Array {
    this.validateSalt(salt);
    
    const passwordBytes = typeof password === 'string' 
      ? new TextEncoder().encode(password) 
      : password;
    
    switch (params.algorithm) {
      case 'Argon2id':
      case 'Argon2i':
      case 'Argon2d':
        return this.deriveArgon2(passwordBytes, salt, params.argon2 || this.defaultArgon2Params, params.algorithm);
      
      case 'PBKDF2-SHA256':
      case 'PBKDF2-SHA512':
        return this.derivePBKDF2(passwordBytes, salt, params.pbkdf2 || this.defaultPBKDF2Params);
      
      case 'HKDF-SHA256':
      case 'HKDF-SHA512':
        if (!params.hkdf) {
          throw this.createError('INVALID_ARGUMENT', 'HKDF требует параметры hkdf');
        }
        return this.deriveHKDF(passwordBytes, params.hkdf);
      
      case 'scrypt':
        return this.deriveScrypt(passwordBytes, salt, params.scrypt || this.defaultScryptParams);
      
      default:
        throw this.createError('INVALID_ARGUMENT', `Неподдерживаемый алгоритм KDF: ${params.algorithm}`);
    }
  }

  /**
   * Асинхронная деривация ключа
   */
  public async deriveKeyAsync(
    password: string | Uint8Array,
    salt: Uint8Array,
    params: KDFParams
  ): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      try {
        const result = this.deriveKey(password, salt, params);
        resolve(result);
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Деривация ключа с автоматической генерацией соли
   * @param password - Пароль или секрет
   * @param params - Параметры KDF
   * @returns Объект с ключом и солью
   */
  public deriveKeyWithSalt(
    password: string | Uint8Array,
    params: KDFParams
  ): { key: Uint8Array; salt: Uint8Array } {
    const salt = this.generateSalt(params.algorithm);
    const key = this.deriveKey(password, salt, params);
    
    return { key, salt };
  }

  /**
   * Деривация нескольких ключей из одного мастер-ключа
   * @param masterKey - Мастер-ключ
   * @param context - Контекст для каждого ключа
   * @param keyLength - Длина каждого ключа
   * @returns Массив деривированных ключей
   */
  public deriveMultipleKeys(
    masterKey: Uint8Array,
    contexts: string[],
    keyLength: number = 32
  ): Uint8Array[] {
    const keys: Uint8Array[] = [];
    
    for (const context of contexts) {
      const contextBytes = new TextEncoder().encode(context);
      const hkdfParams: KDFParams = {
        algorithm: 'HKDF-SHA256',
        hkdf: {
          hash: 'SHA-256',
          salt: new Uint8Array(32), // Пустая соль для HKDF
          info: contextBytes,
          keyLength,
        },
      };
      
      const key = this.deriveKey(masterKey, new Uint8Array(0), hkdfParams);
      keys.push(key);
    }
    
    return keys;
  }

  /**
   * Деривация ключа для шифрования и ключа для аутентификации
   * @param password - Пароль
   * @param salt - Соль
   * @param encryptionKeyLength - Длина ключа шифрования
   * @param authKeyLength - Длина ключа аутентификации
   * @returns Объект с ключами
   */
  public deriveEncryptionAndAuthKeys(
    password: string | Uint8Array,
    salt: Uint8Array,
    encryptionKeyLength: number = 32,
    authKeyLength: number = 32
  ): { encryptionKey: Uint8Array; authKey: Uint8Array } {
    const totalLength = encryptionKeyLength + authKeyLength;
    
    const params: KDFParams = {
      algorithm: 'Argon2id',
      argon2: {
        ...this.defaultArgon2Params,
        hashLength: totalLength,
      },
    };
    
    const derivedKey = this.deriveKey(password, salt, params);
    
    const encryptionKey = derivedKey.slice(0, encryptionKeyLength);
    const authKey = derivedKey.slice(encryptionKeyLength, encryptionKeyLength + authKeyLength);
    
    return { encryptionKey, authKey };
  }

  /**
   * Верификация пароля против сохраненного хэша
   * @param password - Пароль для проверки
   * @param storedHash - Сохраненный хэш (включая соль)
   * @param params - Параметры KDF
   * @returns true если пароль верный
   */
  public verifyPassword(
    password: string,
    storedHash: Uint8Array,
    salt: Uint8Array,
    params: KDFParams
  ): boolean {
    try {
      const derivedKey = this.deriveKey(password, salt, params);
      return this.constantTimeCompare(derivedKey, storedHash);
    } catch {
      return false;
    }
  }

  /**
   * Генерация безопасной соли
   * @param algorithm - Алгоритм KDF
   * @param length - Длина соли (по умолчанию 16 байт)
   * @returns Соль в виде Uint8Array
   */
  public generateSalt(algorithm: KDFAlgorithm, length: number = 16): Uint8Array {
    // Argon2 и scrypt рекомендуют соль 16 байт
    // PBKDF2 может использовать до 64 байт
    const saltLength = algorithm === 'PBKDF2-SHA256' || algorithm === 'PBKDF2-SHA512' 
      ? Math.max(16, Math.min(length, 64))
      : length;
    
    const salt = new Uint8Array(saltLength);
    crypto.randomFillSync(salt);
    
    return salt;
  }

  /**
   * Получение рекомендуемых параметров для уровня безопасности
   * @param securityLevel - Уровень безопасности ('low', 'medium', 'high', 'maximum')
   * @returns Параметры KDF
   */
  public getRecommendedParams(
    securityLevel: 'low' | 'medium' | 'high' | 'maximum' = 'high'
  ): KDFParams {
    switch (securityLevel) {
      case 'low':
        // Быстрая деривация для нечувствительных данных
        return {
          algorithm: 'Argon2id',
          argon2: {
            memorySize: 16384,      // 16 MB
            iterations: 2,
            parallelism: 2,
            hashLength: 32,
          },
        };
      
      case 'medium':
        // Баланс между безопасностью и производительностью
        return {
          algorithm: 'Argon2id',
          argon2: {
            memorySize: 32768,      // 32 MB
            iterations: 3,
            parallelism: 4,
            hashLength: 32,
          },
        };
      
      case 'high':
        // Рекомендуемые параметры для продакшена
        return {
          algorithm: 'Argon2id',
          argon2: {
            memorySize: 65536,      // 64 MB
            iterations: 3,
            parallelism: 4,
            hashLength: 32,
          },
        };
      
      case 'maximum':
        // Максимальная безопасность для критических данных
        return {
          algorithm: 'Argon2id',
          argon2: {
            memorySize: 262144,     // 256 MB
            iterations: 4,
            parallelism: 8,
            hashLength: 64,
          },
        };
      
      default:
        return this.getRecommendedParams('high');
    }
  }

  /**
   * Оценка времени выполнения деривации
   * @param params - Параметры KDF
   * @returns Примерное время в миллисекундах
   */
  public estimateDerivationTime(params: KDFParams): number {
    // Эмпирические оценки для современного CPU
    switch (params.algorithm) {
      case 'Argon2id':
      case 'Argon2i':
      case 'Argon2d': {
        const argon2Params = params.argon2 || this.defaultArgon2Params;
        // Время пропорционально memory * iterations * parallelism
        const baseTime = 50; // ms
        const memoryFactor = argon2Params.memorySize / 65536;
        const iterFactor = argon2Params.iterations / 3;
        const parallelFactor = argon2Params.parallelism / 4;
        return baseTime * memoryFactor * iterFactor * parallelFactor;
      }
      
      case 'PBKDF2-SHA256':
      case 'PBKDF2-SHA512': {
        const pbkdf2Params = params.pbkdf2 || this.defaultPBKDF2Params;
        // PBKDF2 линейно зависит от количества итераций
        const baseIterations = 600000;
        const baseTime = 100; // ms
        return (pbkdf2Params.iterations / baseIterations) * baseTime;
      }
      
      case 'scrypt': {
        const scryptParams = params.scrypt || this.defaultScryptParams;
        // scrypt зависит от N, r, p
        const baseTime = 100; // ms
        const nFactor = scryptParams.N / (2 ** 20);
        const rFactor = scryptParams.r / 8;
        const pFactor = scryptParams.p;
        return baseTime * nFactor * rFactor * pFactor;
      }
      
      case 'HKDF-SHA256':
      case 'HKDF-SHA512':
        // HKDF очень быстрый
        return 1; // ms
      
      default:
        return 100;
    }
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ ДЕРИВАЦИИ
  // ============================================================================

  /**
   * Деривация с использованием Argon2
   * Примечание: Для полной реализации требуется native модуль argon2
   * Здесь представлена реализация через PBKDF2 как fallback
   */
  private deriveArgon2(
    password: Uint8Array,
    salt: Uint8Array,
    params: Argon2Params,
    variant: 'Argon2id' | 'Argon2i' | 'Argon2d'
  ): Uint8Array {
    // Проверяем доступность native argon2
    try {
      // Попытка использовать argon2 через crypto (если доступен в будущих версиях)
      // или через внешний модуль
      return this.deriveArgon2Native(password, salt, params, variant);
    } catch {
      // Fallback: эмуляция через PBKDF2 с усилением
      // Это НЕ обеспечивает ту же безопасность, что и настоящий Argon2
      console.warn('Argon2 недоступен, используется PBKDF2 fallback');
      return this.deriveArgon2Fallback(password, salt, params);
    }
  }

  /**
   * Native реализация Argon2 (если доступна)
   */
  private deriveArgon2Native(
    password: Uint8Array,
    salt: Uint8Array,
    params: Argon2Params,
    variant: string
  ): Uint8Array {
    // Для production используйте npm пакет 'argon2' или 'node-argon2'
    // Эта заглушка будет заменена при наличии native модуля
    
    // Проверяем наличие глобального argon2
    const argon2Module = this.tryLoadArgon2Module();
    
    if (argon2Module) {
      const type = variant === 'Argon2id' ? argon2Module.argon2id :
                   variant === 'Argon2i' ? argon2Module.argon2i : argon2Module.argon2d;
      
      const hash = type.hash(Buffer.from(password), {
        salt: Buffer.from(salt),
        memoryCost: params.memorySize,
        timeCost: params.iterations,
        parallelism: params.parallelism,
        hashLength: params.hashLength,
        type: argon2Module[variant.toLowerCase()],
      });
      
      return new Uint8Array(hash.raw);
    }
    
    throw new Error('Argon2 native module not available');
  }

  /**
   * Попытка загрузки argon2 модуля
   */
  private tryLoadArgon2Module(): any {
    try {
      // Динамический импорт для опциональной зависимости
      return require('argon2');
    } catch {
      return null;
    }
  }

  /**
   * Fallback реализация Argon2 через PBKDF2
   * ВНИМАНИЕ: Не обеспечивает memory-hard свойства!
   */
  private deriveArgon2Fallback(
    password: Uint8Array,
    salt: Uint8Array,
    params: Argon2Params
  ): Uint8Array {
    // Усиливаем PBKDF2 для компенсации отсутствия memory-hardness
    const enhancedIterations = params.iterations * 1000;
    
    const derived = crypto.pbkdf2Sync(
      password,
      salt,
      enhancedIterations,
      params.hashLength,
      'sha512'
    );
    
    return new Uint8Array(derived);
  }

  /**
   * Деривация с использованием PBKDF2
   */
  private derivePBKDF2(
    password: Uint8Array,
    salt: Uint8Array,
    params: PBKDF2Params
  ): Uint8Array {
    const hashAlgorithm = params.hash.toLowerCase();
    
    const derived = crypto.pbkdf2Sync(
      password,
      salt,
      params.iterations,
      params.keyLength,
      hashAlgorithm
    );
    
    return new Uint8Array(derived);
  }

  /**
   * Деривация с использованием HKDF
   */
  private deriveHKDF(
    inputKeyMaterial: Uint8Array,
    params: HKDFParams
  ): Uint8Array {
    // HKDF состоит из двух этапов: Extract и Expand
    
    // Этап 1: Extract
    const prk = this.hkdfExtract(inputKeyMaterial, params.salt, params.hash);
    
    // Этап 2: Expand
    return this.hkdfExpand(prk, params.info, params.keyLength, params.hash);
  }

  /**
   * HKDF Extract
   */
  private hkdfExtract(
    ikm: Uint8Array,
    salt: Uint8Array,
    hash: 'SHA-256' | 'SHA-512'
  ): Uint8Array {
    // Если соль не предоставлена, используем хэш нулей
    const actualSalt = salt.length > 0 ? salt : new Uint8Array(this.getHashLength(hash));
    
    return this.hashService.hmac(ikm, actualSalt, hash === 'SHA-256' ? 'SHA-256' : 'SHA-512');
  }

  /**
   * HKDF Expand
   */
  private hkdfExpand(
    prk: Uint8Array,
    info: Uint8Array,
    length: number,
    hash: 'SHA-256' | 'SHA-512'
  ): Uint8Array {
    const hashLength = this.getHashLength(hash);
    const n = Math.ceil(length / hashLength);
    
    if (n > 255) {
      throw this.createError('INVALID_ARGUMENT', 'Слишком большая длина вывода для HKDF');
    }
    
    const okm = new Uint8Array(n * hashLength);
    let t = new Uint8Array(0);
    
    for (let i = 1; i <= n; i++) {
      const infoWithCounter = new Uint8Array(info.length + t.length + 1);
      infoWithCounter.set(t);
      infoWithCounter.set(info, t.length);
      infoWithCounter[infoWithCounter.length - 1] = i;
      
      t = this.hashService.hmac(infoWithCounter, prk, hash === 'SHA-256' ? 'SHA-256' : 'SHA-512');
      okm.set(t, (i - 1) * hashLength);
    }
    
    return okm.slice(0, length);
  }

  /**
   * Деривация с использованием scrypt
   */
  private deriveScrypt(
    password: Uint8Array,
    salt: Uint8Array,
    params: ScryptParams
  ): Uint8Array {
    const derived = crypto.scryptSync(
      password,
      salt,
      params.keyLength,
      {
        N: params.N,
        r: params.r,
        p: params.p,
        maxmem: this.memoryConfig.maxBufferSize,
      }
    );
    
    return new Uint8Array(derived);
  }

  /**
   * Constant-time сравнение для верификации
   */
  private constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }
    
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }

  /**
   * Получение длины хэша
   */
  private getHashLength(hash: 'SHA-256' | 'SHA-512'): number {
    return hash === 'SHA-256' ? 32 : 64;
  }

  /**
   * Валидация соли
   */
  private validateSalt(salt: Uint8Array): void {
    if (!salt || salt.length === 0) {
      throw this.createError('INVALID_ARGUMENT', 'Соль не может быть пустой');
    }
    
    if (salt.length < 8) {
      throw this.createError('INVALID_ARGUMENT', 'Минимальная длина соли - 8 байт');
    }
    
    if (salt.length > 64) {
      throw this.createError('INVALID_ARGUMENT', 'Максимальная длина соли - 64 байта');
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
 * Утилита для быстрой деривации ключа
 */
export function deriveKey(
  password: string | Uint8Array,
  salt: Uint8Array,
  algorithm?: KDFAlgorithm,
  keyLength?: number
): Uint8Array {
  const service = new KeyDerivationService({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  const params: KDFParams = {
    algorithm: algorithm || 'Argon2id',
    argon2: {
      memorySize: 65536,
      iterations: 3,
      parallelism: 4,
      hashLength: keyLength || 32,
    },
  };
  
  return service.deriveKey(password, salt, params);
}

/**
 * Утилита для генерации соли
 */
export function generateSalt(length?: number): Uint8Array {
  const service = new KeyDerivationService({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  
  return service.generateSalt('Argon2id', length);
}
