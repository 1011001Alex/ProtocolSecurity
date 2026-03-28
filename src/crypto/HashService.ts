/**
 * ============================================================================
 * HASH SERVICE - СЕРВИС ХЭШИРОВАНИЯ
 * ============================================================================
 * Реализация криптографических хэш-функций с поддержкой современных алгоритмов
 * 
 * Поддерживаемые алгоритмы:
 * - SHA-2 семейство (SHA-256, SHA-384, SHA-512)
 * - SHA-3 семейство (SHA3-256, SHA3-384, SHA3-512)
 * - BLAKE2b, BLAKE2s
 * - BLAKE3
 * - HMAC для всех алгоритмов
 * 
 * Особенности:
 * - Защита от timing attacks при сравнении
 * - Потоковое хэширование для больших данных
 * - Векторизованные операции для производительности
 * ============================================================================
 */

import * as crypto from 'crypto';
import { createHash, createHmac, Hash, Hmac } from 'crypto';
import { 
  HashAlgorithm, 
  HashResult, 
  CryptoErrorCode, 
  CryptoResult,
  SecureMemoryConfig 
} from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';

/**
 * Класс для выполнения операций хэширования
 */
export class HashService {
  /** Конфигурация безопасной памяти */
  private readonly memoryConfig: SecureMemoryConfig;
  
  /** Whitelist разрешенных алгоритмов */
  private readonly allowedAlgorithms: HashAlgorithm[];
  
  /** Счетчик операций */
  private operationCount = 0;
  
  /** Время последней операции */
  private lastOperationAt: Date | null = null;

  /**
   * Создает экземпляр HashService
   * @param memoryConfig - Конфигурация безопасной памяти
   * @param allowedAlgorithms - Разрешенные алгоритмы
   */
  constructor(
    memoryConfig: SecureMemoryConfig,
    allowedAlgorithms: HashAlgorithm[] = [
      'SHA-256',
      'SHA-384',
      'SHA-512',
      'SHA3-256',
      'SHA3-384',
      'SHA3-512',
      'BLAKE2b',
      'BLAKE3',
    ]
  ) {
    this.memoryConfig = memoryConfig;
    this.allowedAlgorithms = allowedAlgorithms;
  }

  /**
   * Вычисление хэша данных
   * @param data - Данные для хэширования (Uint8Array, string, Buffer)
   * @param algorithm - Алгоритм хэширования
   * @returns Результат хэширования
   */
  public hash(data: Uint8Array | string | Buffer, algorithm: HashAlgorithm = 'SHA-256'): HashResult {
    this.validateAlgorithm(algorithm);
    
    const inputData = this.normalizeInput(data);
    const nodeAlgorithm = this.mapAlgorithm(algorithm);
    
    try {
      const hashInstance = createHash(nodeAlgorithm);
      hashInstance.update(inputData);
      const hashBuffer = hashInstance.digest();
      
      this.operationCount++;
      this.lastOperationAt = new Date();
      
      return {
        hash: new Uint8Array(hashBuffer),
        algorithm,
        inputLength: inputData.length,
        outputLength: hashBuffer.length,
      };
    } catch (error) {
      throw this.createError(CryptoErrorCode.HASH_COMPUTATION_FAILED, `Ошибка вычисления хэша: ${error}`);
    }
  }

  /**
   * Асинхронное вычисление хэша
   * @param data - Данные для хэширования
   * @param algorithm - Алгоритм хэширования
   * @returns Promise с результатом
   */
  public async hashAsync(
    data: Uint8Array | string | Buffer, 
    algorithm: HashAlgorithm = 'SHA-256'
  ): Promise<HashResult> {
    return new Promise((resolve, reject) => {
      try {
        const result = this.hash(data, algorithm);
        resolve(result);
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Потоковое хэширование для больших данных
   * @returns Hash instance для потоковой записи
   * @param algorithm - Алгоритм хэширования
   */
  public createHashStream(algorithm: HashAlgorithm = 'SHA-256'): StreamingHash {
    this.validateAlgorithm(algorithm);
    const nodeAlgorithm = this.mapAlgorithm(algorithm);
    
    return new StreamingHash(
      createHash(nodeAlgorithm),
      algorithm,
      this.memoryConfig
    );
  }

  /**
   * Вычисление HMAC (Hash-based Message Authentication Code)
   * @param data - Данные для аутентификации
   * @param key - Секретный ключ
   * @param algorithm - Алгоритм хэширования
   * @returns HMAC в виде Uint8Array
   */
  public hmac(
    data: Uint8Array | string | Buffer,
    key: Uint8Array | string | Buffer,
    algorithm: HashAlgorithm = 'SHA-256'
  ): Uint8Array {
    this.validateAlgorithm(algorithm);
    
    const inputData = this.normalizeInput(data);
    const keyData = this.normalizeInput(key);
    const nodeAlgorithm = this.mapAlgorithm(algorithm);
    
    try {
      const hmacInstance = createHmac(nodeAlgorithm, keyData);
      hmacInstance.update(inputData);
      const hmacBuffer = hmacInstance.digest();
      
      this.operationCount++;
      this.lastOperationAt = new Date();
      
      return new Uint8Array(hmacBuffer);
    } catch (error) {
      throw this.createError(CryptoErrorCode.HASH_COMPUTATION_FAILED, `Ошибка вычисления HMAC: ${error}`);
    }
  }

  /**
   * Асинхронное вычисление HMAC
   */
  public async hmacAsync(
    data: Uint8Array | string | Buffer,
    key: Uint8Array | string | Buffer,
    algorithm: HashAlgorithm = 'SHA-256'
  ): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      try {
        const result = this.hmac(data, key, algorithm);
        resolve(result);
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Вычисление хэша файла
   * @param filePath - Путь к файлу
   * @param algorithm - Алгоритм хэширования
   * @param chunkSize - Размер чанка для чтения (байт)
   * @returns Результат хэширования
   */
  public async hashFile(
    filePath: string,
    algorithm: HashAlgorithm = 'SHA-256',
    chunkSize: number = 64 * 1024
  ): Promise<HashResult> {
    this.validateAlgorithm(algorithm);
    
    const fs = await import('fs');
    const nodeAlgorithm = this.mapAlgorithm(algorithm);
    
    return new Promise((resolve, reject) => {
      const hashInstance = createHash(nodeAlgorithm);
      let totalBytes = 0;

      const stream = fs.createReadStream(filePath, {
        highWaterMark: chunkSize
        // Binary mode по умолчанию для createReadStream
      });

      stream.on('data', (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += buffer.length;
        hashInstance.update(buffer);
      });
      
      stream.on('end', () => {
        const hashBuffer = hashInstance.digest();
        this.operationCount++;
        this.lastOperationAt = new Date();
        
        resolve({
          hash: new Uint8Array(hashBuffer),
          algorithm,
          inputLength: totalBytes,
          outputLength: hashBuffer.length,
        });
      });
      
      stream.on('error', (error) => {
        reject(this.createError(CryptoErrorCode.HASH_COMPUTATION_FAILED, `Ошибка чтения файла: ${error}`));
      });
    });
  }

  /**
   * Вычисление хэша нескольких файлов (Merkle tree root)
   * @param filePaths - Пути к файлам
   * @param algorithm - Алгоритм хэширования
   * @returns Корень дерева Меркла
   */
  public async computeMerkleRoot(
    filePaths: string[],
    algorithm: HashAlgorithm = 'SHA-256'
  ): Promise<{ root: Uint8Array; leaves: Uint8Array[] }> {
    if (filePaths.length === 0) {
      throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, 'Список файлов не может быть пустым');
    }
    
    // Вычисляем хэши всех файлов (листья дерева)
    const leaves: Uint8Array[] = [];
    
    for (const filePath of filePaths) {
      const result = await this.hashFile(filePath, algorithm);
      leaves.push(result.hash);
    }
    
    // Строим дерево Меркла
    const root = this.buildMerkleTree(leaves, algorithm);
    
    return { root, leaves };
  }

  /**
   * Сравнение двух хэшей с защитой от timing attacks
   * @param hash1 - Первый хэш
   * @param hash2 - Второй хэш
   * @returns true если хэши равны
   */
  public constantTimeCompare(hash1: Uint8Array | string, hash2: Uint8Array | string): boolean {
    const buf1 = typeof hash1 === 'string' ? Buffer.from(hash1, 'hex') : Buffer.from(hash1);
    const buf2 = typeof hash2 === 'string' ? Buffer.from(hash2, 'hex') : Buffer.from(hash2);
    
    // Используем встроенную функцию для constant-time сравнения
    return crypto.timingSafeEqual(buf1, buf2);
  }

  /**
   * Проверка целостности данных
   * @param data - Данные для проверки
   * @param expectedHash - Ожидаемый хэш
   * @param algorithm - Алгоритм хэширования
   * @returns Результат проверки
   */
  public verifyIntegrity(
    data: Uint8Array | string | Buffer,
    expectedHash: Uint8Array | string,
    algorithm: HashAlgorithm = 'SHA-256'
  ): { valid: boolean; computedHash: Uint8Array } {
    const result = this.hash(data, algorithm);
    const valid = this.constantTimeCompare(result.hash, expectedHash);
    
    return {
      valid,
      computedHash: result.hash,
    };
  }

  /**
   * Вычисление двойного хэша (hash(hash(data)))
   * Используется в некоторых криптографических протоколах
   * @param data - Данные
   * @param algorithm - Алгоритм
   * @returns Двойной хэш
   */
  public doubleHash(data: Uint8Array | string | Buffer, algorithm: HashAlgorithm = 'SHA-256'): Uint8Array {
    const firstHash = this.hash(data, algorithm).hash;
    const secondHash = this.hash(firstHash, algorithm).hash;
    return secondHash;
  }

  /**
   * Вычисление хэш-цепочки
   * @param dataItems - Массив данных для последовательного хэширования
   * @param algorithm - Алгоритм
   * @returns Финальный хэш цепочки
   */
  public hashChain(dataItems: (Uint8Array | string | Buffer)[], algorithm: HashAlgorithm = 'SHA-256'): Uint8Array {
    if (dataItems.length === 0) {
      throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, 'Список данных не может быть пустым');
    }

    let currentHash = this.hash(dataItems[0], algorithm).hash;

    for (let i = 1; i < dataItems.length; i++) {
      const item = dataItems[i];
      const itemBuffer = item instanceof Uint8Array ? Buffer.from(item) :
                         Buffer.isBuffer(item) ? item :
                         Buffer.from(String(item));
      
      const combined = new Uint8Array(currentHash.length + itemBuffer.length);
      combined.set(currentHash);
      combined.set(itemBuffer, currentHash.length);
      currentHash = this.hash(combined, algorithm).hash;
    }

    return currentHash;
  }

  /**
   * Получение статистики операций
   */
  public getStats(): {
    operationCount: number;
    lastOperationAt: Date | null;
    allowedAlgorithms: HashAlgorithm[];
  } {
    return {
      operationCount: this.operationCount,
      lastOperationAt: this.lastOperationAt,
      allowedAlgorithms: [...this.allowedAlgorithms],
    };
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Проверка алгоритма на разрешенность
   */
  private validateAlgorithm(algorithm: string): void {
    if (!this.allowedAlgorithms.includes(algorithm as HashAlgorithm)) {
      throw this.createError(
        CryptoErrorCode.INVALID_ARGUMENT,
        `Алгоритм ${algorithm} не разрешен. Разрешены: ${this.allowedAlgorithms.join(', ')}`
      );
    }
  }

  /**
   * Маппинг алгоритма на имя Node.js crypto
   */
  private mapAlgorithm(algorithm: HashAlgorithm): string {
    const mapping: Record<HashAlgorithm, string> = {
      'SHA-1': 'sha1',
      'SHA-256': 'sha256',
      'SHA-384': 'sha384',
      'SHA-512': 'sha512',
      'SHA3-256': 'sha3-256',
      'SHA3-384': 'sha3-384',
      'SHA3-512': 'sha3-512',
      'BLAKE2b': 'blake2b512',
      'BLAKE2s': 'blake2s256',
      'BLAKE3': 'blake3',
    };
    
    return mapping[algorithm] || algorithm.toLowerCase();
  }

  /**
   * Нормализация входных данных
   */
  private normalizeInput(data: Uint8Array | string | Buffer): Buffer {
    if (data instanceof Buffer) {
      return data;
    }
    if (data instanceof Uint8Array) {
      return Buffer.from(data);
    }
    if (typeof data === 'string') {
      return Buffer.from(data, 'utf8');
    }
    throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, 'Неподдерживаемый тип данных');
  }

  /**
   * Создание ошибки
   */
  private createError(code: CryptoErrorCode, message: string): Error {
    const error = new Error(message);
    (error as any).errorCode = code;
    return error;
  }

  /**
   * Построение дерева Меркла
   */
  private buildMerkleTree(leaves: Uint8Array[], algorithm: HashAlgorithm): Uint8Array {
    if (leaves.length === 0) {
      throw new Error('Пустое дерево Меркла');
    }
    
    if (leaves.length === 1) {
      return leaves[0];
    }
    
    let currentLevel = [...leaves];
    
    while (currentLevel.length > 1) {
      const nextLevel: Uint8Array[] = [];
      
      // Если нечетное количество, дублируем последний элемент
      if (currentLevel.length % 2 === 1) {
        currentLevel.push(currentLevel[currentLevel.length - 1]);
      }
      
      for (let i = 0; i < currentLevel.length; i += 2) {
        const combined = new Uint8Array(currentLevel[i].length + currentLevel[i + 1].length);
        combined.set(currentLevel[i]);
        combined.set(currentLevel[i + 1], currentLevel[i].length);
        nextLevel.push(this.hash(combined, algorithm).hash);
      }
      
      currentLevel = nextLevel;
    }
    
    return currentLevel[0];
  }
}

/**
 * Класс для потокового хэширования
 */
export class StreamingHash {
  private hashInstance: Hash;
  private algorithm: HashAlgorithm;
  private memoryConfig: SecureMemoryConfig;
  private bytesProcessed = 0;
  private isFinalized = false;

  constructor(hashInstance: Hash, algorithm: HashAlgorithm, memoryConfig: SecureMemoryConfig) {
    this.hashInstance = hashInstance;
    this.algorithm = algorithm;
    this.memoryConfig = memoryConfig;
  }

  /**
   * Добавление данных в поток
   */
  public update(data: Uint8Array | string | Buffer): this {
    if (this.isFinalized) {
      throw new Error('Хэш уже финализирован, нельзя добавлять данные');
    }
    
    const buffer = data instanceof Buffer ? data : 
                   data instanceof Uint8Array ? Buffer.from(data) : 
                   Buffer.from(data, 'utf8');
    
    this.hashInstance.update(buffer);
    this.bytesProcessed += buffer.length;
    
    return this;
  }

  /**
   * Финализация и получение результата
   */
  public finalize(): HashResult {
    if (this.isFinalized) {
      throw new Error('Хэш уже финализирован');
    }
    
    const hashBuffer = this.hashInstance.digest();
    this.isFinalized = true;
    
    // Очищаем ссылку на инстанс
    this.hashInstance = null as any;
    
    return {
      hash: new Uint8Array(hashBuffer),
      algorithm: this.algorithm,
      inputLength: this.bytesProcessed,
      outputLength: hashBuffer.length,
    };
  }

  /**
   * Получение промежуточного хэша (без финализации)
   */
  public digest(): Uint8Array {
    // Создаем копию для получения промежуточного хэша
    const copy = this.hashInstance.copy?.() || this.hashInstance;
    return new Uint8Array(copy.digest());
  }

  /**
   * Получение количества обработанных байт
   */
  public getBytesProcessed(): number {
    return this.bytesProcessed;
  }
}

/**
 * Утилита для быстрого хэширования
 */
export function hash(data: Uint8Array | string | Buffer, algorithm?: HashAlgorithm): Uint8Array {
  const service = new HashService({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  return service.hash(data, algorithm).hash;
}

/**
 * Утилита для быстрого вычисления HMAC
 */
export function hmac(
  data: Uint8Array | string | Buffer,
  key: Uint8Array | string | Buffer,
  algorithm?: HashAlgorithm
): Uint8Array {
  const service = new HashService({
    noSwap: true,
    autoZero: true,
    preventCopy: true,
    useProtectedMemory: false,
    maxBufferSize: 10 * 1024 * 1024,
    defaultTTL: 60000,
  });
  return service.hmac(data, key, algorithm);
}
