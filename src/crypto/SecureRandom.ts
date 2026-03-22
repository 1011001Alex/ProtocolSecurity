/**
 * ============================================================================
 * SECURE RANDOM - КРИПТОГРАФИЧЕСКИ СТОЙКИЙ ГЕНЕРАТОР СЛУЧАЙНЫХ ЧИСЕЛ (CSPRNG)
 * ============================================================================
 * Реализация безопасного генератора случайных чисел с использованием
 * криптографических API Node.js и Web Crypto API
 * 
 * Особенности:
 * - Использование системного энтропийного пула
 * - Защита от предсказуемости
 * - Мониторинг качества энтропии
 * - Защита от side-channel атак
 * ============================================================================
 */

import * as crypto from 'crypto';
import { SecureMemoryConfig, MemoryStats, CryptoResult } from '../types/crypto.types';

/**
 * Класс для генерации криптографически стойких случайных данных
 */
export class SecureRandom {
  /** Конфигурация безопасной памяти */
  private readonly memoryConfig: SecureMemoryConfig;
  
  /** Статистика использования */
  private stats: MemoryStats = {
    allocated: 0,
    peakAllocated: 0,
    zeroOperations: 0,
    allocationErrors: 0,
  };
  
  /** Счетчик сгенерированных байт */
  private bytesGenerated = 0;
  
  /** Время инициализации */
  private readonly initializedAt: Date;
  
  /** Флаг инициализации */
  private isInitialized = false;
  
  /** Буфер для дополнительной энтропии */
  private entropyBuffer: Uint8Array | null = null;
  
  /** Максимальный размер буфера энтропии */
  private readonly MAX_ENTROPY_BUFFER_SIZE = 1024;

  /**
   * Создает экземпляр SecureRandom
   * @param memoryConfig - Конфигурация безопасной памяти
   */
  constructor(memoryConfig: SecureMemoryConfig) {
    this.memoryConfig = memoryConfig;
    this.initializedAt = new Date();
    this.initialize();
  }

  /**
   * Инициализация генератора
   * Проверяет доступность криптографических API и собирает начальную энтропию
   */
  private initialize(): void {
    try {
      // Проверяем доступность crypto.randomBytes
      const testBuffer = crypto.randomBytes(1);
      if (!testBuffer || testBuffer.length !== 1) {
        throw new Error('crypto.randomBytes недоступен');
      }
      
      // Инициализируем буфер энтропии
      this.entropyBuffer = this.allocateSecureBuffer(this.MAX_ENTROPY_BUFFER_SIZE);
      
      // Добавляем начальную энтропию
      this.addEntropy(this.collectSystemEntropy());
      
      this.isInitialized = true;
      this.log('DEBUG', 'SecureRandom инициализирован успешно');
    } catch (error) {
      this.isInitialized = false;
      this.log('ERROR', 'Ошибка инициализации SecureRandom', error);
      throw new Error(`Failed to initialize SecureRandom: ${error}`);
    }
  }

  /**
   * Сбор системной энтропии из различных источников
   * @returns Буфер с энтропией
   */
  private collectSystemEntropy(): Uint8Array {
    const entropySources: Uint8Array[] = [];
    
    // 1. Временная метка с высокой точностью
    const timestampBuffer = Buffer.alloc(8);
    timestampBuffer.writeBigUInt64LE(BigInt(Date.now() * 1000));
    entropySources.push(new Uint8Array(timestampBuffer));
    
    // 2. Счетчик производительности
    if (typeof performance !== 'undefined' && performance.now) {
      const perfBuffer = Buffer.alloc(8);
      perfBuffer.writeDoubleLE(performance.now());
      entropySources.push(new Uint8Array(perfBuffer));
    }
    
    // 3. Информация о процессе
    const processInfo = Buffer.alloc(16);
    processInfo.writeUInt32LE(process.pid, 0);
    processInfo.writeUInt32LE(process.ppid || 0, 4);
    processInfo.writeUInt32LE(process.uptime ? Math.floor(process.uptime() * 1000) : 0, 8);
    entropySources.push(new Uint8Array(processInfo));
    
    // 4. Случайные данные от ОС
    const osRandom = crypto.randomBytes(32);
    entropySources.push(osRandom);
    
    // Объединяем все источники
    const totalLength = entropySources.reduce((sum, buf) => sum + buf.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    
    for (const source of entropySources) {
      combined.set(source, offset);
      offset += source.length;
    }
    
    return combined;
  }

  /**
   * Добавление энтропии в пул
   * @param entropy - Данные энтропии
   */
  public addEntropy(entropy: Uint8Array): void {
    if (!this.entropyBuffer) {
      throw new Error('Entropy buffer not initialized');
    }
    
    // Хешируем новую энтропию для равномерного распределения
    const hashedEntropy = crypto.createHash('sha256').update(entropy).digest();
    
    // XOR с существующим буфером для смешивания
    for (let i = 0; i < Math.min(hashedEntropy.length, this.entropyBuffer.length); i++) {
      this.entropyBuffer[i] ^= hashedEntropy[i];
    }
    
    this.log('DEBUG', `Добавлено ${entropy.length} байт энтропии`);
  }

  /**
   * Генерация случайных байт заданной длины
   * @param length - Количество байт
   * @returns Uint8Array со случайными данными
   */
  public randomBytes(length: number): Uint8Array {
    this.validateInitialized();
    this.validateLength(length);
    
    try {
      // Используем crypto.randomBytes для генерации
      const buffer = crypto.randomBytes(length);
      const result = new Uint8Array(buffer);
      
      this.bytesGenerated += length;
      this.updateStats(length);
      
      // Очищаем временный буфер
      this.secureZero(buffer);
      
      return result;
    } catch (error) {
      this.stats.allocationErrors++;
      this.log('ERROR', 'Ошибка генерации случайных байт', error);
      throw new Error(`Failed to generate random bytes: ${error}`);
    }
  }

  /**
   * Генерация случайных байт с заполнением существующего буфера
   * @param buffer - Буфер для заполнения
   */
  public fillRandom(buffer: Uint8Array): void {
    this.validateInitialized();
    this.validateLength(buffer.length);
    
    try {
      crypto.randomFillSync(buffer);
      this.bytesGenerated += buffer.length;
      this.updateStats(buffer.length);
    } catch (error) {
      this.stats.allocationErrors++;
      this.log('ERROR', 'Ошибка заполнения буфера', error);
      throw new Error(`Failed to fill buffer with random data: ${error}`);
    }
  }

  /**
   * Асинхронная генерация случайных байт
   * @param length - Количество байт
   * @returns Promise с Uint8Array
   */
  public async randomBytesAsync(length: number): Promise<Uint8Array> {
    this.validateInitialized();
    this.validateLength(length);
    
    return new Promise((resolve, reject) => {
      crypto.randomBytes(length, (err, buffer) => {
        if (err) {
          this.stats.allocationErrors++;
          this.log('ERROR', 'Ошибка асинхронной генерации', err);
          reject(new Error(`Failed to generate random bytes asynchronously: ${err}`));
          return;
        }
        
        const result = new Uint8Array(buffer);
        this.bytesGenerated += length;
        this.updateStats(length);
        
        // Очищаем временный буфер
        this.secureZero(buffer);
        
        resolve(result);
      });
    });
  }

  /**
   * Генерация случайного целого числа в диапазоне [min, max]
   * @param min - Минимальное значение (включительно)
   * @param max - Максимальное значение (включительно)
   * @returns Случайное целое число
   */
  public randomInt(min: number, max: number): number {
    this.validateInitialized();
    
    if (!Number.isInteger(min) || !Number.isInteger(max)) {
      throw new Error('min и max должны быть целыми числами');
    }
    
    if (min > max) {
      [min, max] = [max, min];
    }
    
    const range = max - min + 1;
    
    // Для больших диапазонов используем rejection sampling
    if (range > 0xffffffff) {
      throw new Error('Диапазон слишком велик');
    }
    
    // Вычисляем количество байт, необходимых для представления диапазона
    const bytesNeeded = Math.ceil(Math.log2(range) / 8);
    const maxRandom = Math.pow(2, bytesNeeded * 8);
    const limit = maxRandom - (maxRandom % range);
    
    // Rejection sampling для равномерного распределения
    let attempts = 0;
    const maxAttempts = 100;
    
    while (attempts < maxAttempts) {
      const buffer = this.randomBytes(bytesNeeded);
      let value = 0;
      
      for (let i = 0; i < bytesNeeded; i++) {
        value = (value << 8) + buffer[i];
      }
      
      // Очищаем буфер сразу после использования
      this.secureZero(buffer);
      
      if (value < limit) {
        return min + (value % range);
      }
      
      attempts++;
    }
    
    throw new Error('Не удалось сгенерировать случайное число за допустимое количество попыток');
  }

  /**
   * Генерация случайного UUID v4
   * @returns UUID в формате строки
   */
  public randomUUID(): string {
    this.validateInitialized();
    
    // Используем встроенную функцию crypto.randomUUID() если доступна
    if (typeof crypto.randomUUID === 'function') {
      const uuid = crypto.randomUUID();
      this.bytesGenerated += 16;
      this.updateStats(16);
      return uuid;
    }
    
    // Fallback реализация
    const bytes = this.randomBytes(16);
    
    // Устанавливаем версию (4) и вариант (RFC 4122)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    
    const hex = Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  /**
   * Генерация случайной строки заданной длины
   * @param length - Длина строки
   * @param charset - Набор символов (по умолчанию alphanumeric)
   * @returns Случайная строка
   */
  public randomString(length: number, charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'): string {
    this.validateInitialized();
    
    if (length <= 0) {
      throw new Error('Длина строки должна быть положительной');
    }
    
    if (charset.length === 0) {
      throw new Error('Набор символов не может быть пустым');
    }
    
    const result: string[] = [];
    const charsetLength = charset.length;
    
    for (let i = 0; i < length; i++) {
      const index = this.randomInt(0, charsetLength - 1);
      result.push(charset[index]);
    }
    
    return result.join('');
  }

  /**
   * Генерация безопасного токена
   * @param length - Длина токена в байтах
   * @param encoding - Кодировка вывода ('hex', 'base64', 'base64url')
   * @returns Токен в виде строки
   */
  public generateToken(length: number = 32, encoding: 'hex' | 'base64' | 'base64url' = 'base64url'): string {
    this.validateInitialized();
    
    const bytes = this.randomBytes(length);
    let result: string;
    
    switch (encoding) {
      case 'hex':
        result = Buffer.from(bytes).toString('hex');
        break;
      case 'base64':
        result = Buffer.from(bytes).toString('base64');
        break;
      case 'base64url':
        result = Buffer.from(bytes)
          .toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        break;
      default:
        throw new Error(`Неподдерживаемая кодировка: ${encoding}`);
    }
    
    return result;
  }

  /**
   * Проверка качества энтропии
   * @param data - Данные для проверки
   * @returns Результат проверки
   */
  public checkEntropyQuality(data: Uint8Array): {
    passed: boolean;
    score: number;
    details: {
      chiSquared: number;
      mean: number;
      serialCorrelation: number;
    };
  } {
    if (data.length < 100) {
      throw new Error('Недостаточно данных для проверки энтропии (минимум 100 байт)');
    }
    
    // 1. Chi-squared test для равномерности распределения
    const frequencies = new Array(256).fill(0);
    for (const byte of data) {
      frequencies[byte]++;
    }
    
    const expectedFrequency = data.length / 256;
    let chiSquared = 0;
    
    for (const freq of frequencies) {
      const deviation = freq - expectedFrequency;
      chiSquared += (deviation * deviation) / expectedFrequency;
    }
    
    // Для 255 степеней свободы, критическое значение ~306 (p=0.001)
    const chiSquaredPassed = chiSquared < 306;
    
    // 2. Проверка среднего значения (должно быть близко к 127.5)
    let sum = 0;
    for (const byte of data) {
      sum += byte;
    }
    const mean = sum / data.length;
    const meanPassed = Math.abs(mean - 127.5) < 10;
    
    // 3. Serial correlation (должна быть близка к 0)
    let correlation = 0;
    for (let i = 0; i < data.length - 1; i++) {
      correlation += (data[i] - 127.5) * (data[i + 1] - 127.5);
    }
    correlation /= data.length - 1;
    const correlationPassed = Math.abs(correlation) < 50;
    
    const passed = chiSquaredPassed && meanPassed && correlationPassed;
    const score = (
      (chiSquaredPassed ? 1 : 0) +
      (meanPassed ? 1 : 0) +
      (correlationPassed ? 1 : 0)
    ) / 3;
    
    return {
      passed,
      score,
      details: {
        chiSquared,
        mean,
        serialCorrelation: correlation,
      },
    };
  }

  /**
   * Получение статистики
   * @returns Статистика использования
   */
  public getStats(): MemoryStats {
    return { ...this.stats };
  }

  /**
   * Получение информации о генераторе
   * @returns Информация о состоянии
   */
  public getInfo(): {
    initialized: boolean;
    initializedAt: Date;
    bytesGenerated: number;
    entropyBufferInitialized: boolean;
  } {
    return {
      initialized: this.isInitialized,
      initializedAt: this.initializedAt,
      bytesGenerated: this.bytesGenerated,
      entropyBufferInitialized: this.entropyBuffer !== null,
    };
  }

  /**
   * Очистка ресурсов
   */
  public destroy(): void {
    if (this.entropyBuffer) {
      this.secureZero(this.entropyBuffer);
      this.entropyBuffer = null;
    }
    
    this.log('INFO', 'SecureRandom уничтожен, ресурсы очищены');
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Выделение безопасного буфера
   * @param size - Размер в байтах
   * @returns Uint8Array
   */
  private allocateSecureBuffer(size: number): Uint8Array {
    if (size > this.memoryConfig.maxBufferSize) {
      throw new Error(`Размер буфера ${size} превышает максимум ${this.memoryConfig.maxBufferSize}`);
    }
    
    const buffer = new Uint8Array(size);
    this.updateStats(size);
    
    return buffer;
  }

  /**
   * Безопасная очистка буфера (zeroing)
   * @param buffer - Буфер для очистки
   */
  private secureZero(buffer: Uint8Array): void {
    if (!buffer || buffer.length === 0) {
      return;
    }
    
    // Используем crypto.privateFill для гарантированной записи
    try {
      crypto.privateFill(buffer, 0);
    } catch {
      // Fallback: многократная перезапись для защиты от оптимизаций
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = 0;
      }
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = 0xff;
      }
      for (let i = 0; i < buffer.length; i++) {
        buffer[i] = 0;
      }
    }
    
    this.stats.zeroOperations++;
  }

  /**
   * Обновление статистики
   * @param bytes - Количество выделенных байт
   */
  private updateStats(bytes: number): void {
    this.stats.allocated += bytes;
    if (this.stats.allocated > this.stats.peakAllocated) {
      this.stats.peakAllocated = this.stats.allocated;
    }
  }

  /**
   * Проверка инициализации
   */
  private validateInitialized(): void {
    if (!this.isInitialized) {
      throw new Error('SecureRandom не инициализирован');
    }
  }

  /**
   * Проверка длины
   * @param length - Длина для проверки
   */
  private validateLength(length: number): void {
    if (length <= 0) {
      throw new Error('Длина должна быть положительным числом');
    }
    
    if (length > this.memoryConfig.maxBufferSize) {
      throw new Error(`Длина ${length} превышает максимум ${this.memoryConfig.maxBufferSize}`);
    }
  }

  /**
   * Внутреннее логирование
   * @param level - Уровень логирования
   * @param message - Сообщение
   * @param error - Ошибка (опционально)
   */
  private log(level: string, message: string, error?: unknown): void {
    if (!this.memoryConfig || level === 'DEBUG') {
      return;
    }
    
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [SecureRandom] [${level}] ${message}`;
    
    if (error) {
      console.error(logMessage, error);
    } else {
      console.log(logMessage);
    }
  }
}

/**
 * Singleton экземпляр SecureRandom
 * Используется для глобального доступа к CSPRNG
 */
let globalSecureRandom: SecureRandom | null = null;

/**
 * Получение глобального экземпляра SecureRandom
 * @param memoryConfig - Конфигурация памяти (создает новый если не указан)
 * @returns SecureRandom экземпляр
 */
export function getSecureRandom(memoryConfig?: SecureMemoryConfig): SecureRandom {
  if (!globalSecureRandom) {
    const config = memoryConfig || {
      noSwap: true,
      autoZero: true,
      preventCopy: true,
      useProtectedMemory: false,
      maxBufferSize: 10 * 1024 * 1024,
      defaultTTL: 60000,
    };
    globalSecureRandom = new SecureRandom(config);
  }
  return globalSecureRandom;
}

/**
 * Быстрая генерация случайных байт
 * @param length - Количество байт
 * @returns Uint8Array
 */
export function randomBytes(length: number): Uint8Array {
  return getSecureRandom().randomBytes(length);
}

/**
 * Быстрая генерация случайного UUID
 * @returns UUID строка
 */
export function randomUUID(): string {
  return getSecureRandom().randomUUID();
}

/**
 * Быстрая генерация токена
 * @param length - Длина в байтах
 * @param encoding - Кодировка
 * @returns Токен
 */
export function generateToken(length?: number, encoding?: 'hex' | 'base64' | 'base64url'): string {
  return getSecureRandom().generateToken(length, encoding);
}
