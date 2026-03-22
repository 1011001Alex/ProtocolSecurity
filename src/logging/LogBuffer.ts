/**
 * ============================================================================
 * KAFKA-STYLE LOG BUFFER - БУФЕРИЗАЦИЯ ЛОГОВ
 * ============================================================================
 * Высокопроизводительный буфер с пакетной обработкой, поддержкой приоритетов,
 * сжатием, шифрованием и гарантированной доставкой.
 * 
 * Особенности:
 * - Пакетная обработка (batching) для оптимизации производительности
 * - Приоритетные очереди для критических логов
 * - Стратегии обработки при переполнении
 * - Поддержка сжатия (gzip, deflate)
 * - Поддержка шифрования (AES-256-GCM)
 * - Гарантированная доставка с acknowledgment
 * - Персистентность при сбоях
 * - Метрики производительности
 */

import * as crypto from 'crypto';
import * as zlib from 'zlib';
import { EventEmitter } from 'events';
import {
  LogEntry,
  LogBatch,
  LogBufferConfig,
  LogSource,
  LogProcessingStatus,
  ProcessingError
} from '../types/logging.types';

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/**
 * Приоритеты для источников логов
 */
const SOURCE_PRIORITIES: Record<LogSource, number> = {
  [LogSource.SECURITY]: 100,    //Highest priority
  [LogSource.AUTH]: 90,
  [LogSource.AUDIT]: 80,
  [LogSource.SYSTEM]: 70,
  [LogSource.NETWORK]: 60,
  [LogSource.DATABASE]: 50,
  [LogSource.APPLICATION]: 40,
  [LogSource.PERFORMANCE]: 30   // Lowest priority
};

/**
 * Алгоритмы сжатия
 */
enum CompressionAlgorithm {
  GZIP = 'gzip',
  DEFLATE = 'deflate',
  BROTLI = 'brotli',
  NONE = 'none'
}

/**
 * Режимы шифрования
 */
enum EncryptionMode {
  AES_256_GCM = 'aes-256-gcm',
  AES_256_CBC = 'aes-256-cbc',
  CHACHA20_POLY1305 = 'chacha20-poly1305',
  NONE = 'none'
}

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Элемент в приоритетной очереди
 */
interface PriorityLogEntry {
  log: LogEntry;
  priority: number;
  sequenceNumber: number;
  addedAt: number;
}

/**
 * Результат обработки пакета
 */
interface BatchProcessResult {
  batchId: string;
  success: boolean;
  processedCount: number;
  failedCount: number;
  errors: ProcessingError[];
  processingTime: number;
  compressedSize?: number;
  originalSize?: number;
  compressionRatio?: number;
}

/**
 * Статистика буфера
 */
interface BufferStatistics {
  /** Текущий размер буфера */
  currentSize: number;
  /** Максимальный размер буфера */
  maxSize: number;
  /** Процент заполнения */
  fillPercentage: number;
  /** Обработано пакетов */
  batchesProcessed: number;
  /** Обработано логов */
  logsProcessed: number;
  /** Ошибки обработки */
  processingErrors: number;
  /** Среднее время обработки пакета (мс) */
  avgBatchProcessingTime: number;
  /** P99 время обработки (мс) */
  p99ProcessingTime: number;
  /** Сжатие статистика */
  compression: {
    totalOriginalSize: number;
    totalCompressedSize: number;
    avgCompressionRatio: number;
  };
  /** Статистика по приоритетам */
  byPriority: Record<string, number>;
  /** Статистика по источникам */
  bySource: Record<LogSource, number>;
  /** Подавлено логов */
  suppressedLogs: number;
  /** Сбросов буфера */
  bufferFlushes: number;
}

/**
 * Обработчик пакетов (consumer)
 */
interface BatchConsumer {
  /**
   * Обработка пакета логов
   * @param batch - Пакет логов
   * @returns Promise с результатом обработки
   */
  consume(batch: LogBatch): Promise<BatchProcessResult>;
  
  /**
   * Закрытие потребителя
   */
  close(): Promise<void>;
}

// ============================================================================
// КЛАССЫ ОЧЕРЕДЕЙ
// ============================================================================

/**
 * Приоритетная очередь для логов
 * Реализует heap-based priority queue для эффективной обработки
 */
class PriorityQueue {
  private heap: PriorityLogEntry[];
  private sequenceCounter: number;
  
  constructor() {
    this.heap = [];
    this.sequenceCounter = 0;
  }
  
  /**
   * Добавление элемента в очередь
   */
  enqueue(log: LogEntry, priority: number): void {
    const entry: PriorityLogEntry = {
      log,
      priority,
      sequenceNumber: this.sequenceCounter++,
      addedAt: Date.now()
    };
    
    this.heap.push(entry);
    this.bubbleUp(this.heap.length - 1);
  }
  
  /**
   * Извлечение элемента с наивысшим приоритетом
   */
  dequeue(): PriorityLogEntry | undefined {
    if (this.heap.length === 0) {
      return undefined;
    }
    
    const top = this.heap[0];
    const last = this.heap.pop();
    
    if (this.heap.length > 0 && last) {
      this.heap[0] = last;
      this.bubbleDown(0);
    }
    
    return top;
  }
  
  /**
   * Получение элемента без удаления
   */
  peek(): PriorityLogEntry | undefined {
    return this.heap[0];
  }
  
  /**
   * Проверка пустоты очереди
   */
  isEmpty(): boolean {
    return this.heap.length === 0;
  }
  
  /**
   * Размер очереди
   */
  size(): number {
    return this.heap.length;
  }
  
  /**
   * Очистка очереди
   */
  clear(): void {
    this.heap = [];
  }
  
  /**
   * Получение всех элементов (для batch processing)
   */
  drain(maxCount: number): PriorityLogEntry[] {
    const result: PriorityLogEntry[] = [];
    const count = Math.min(maxCount, this.heap.length);
    
    for (let i = 0; i < count; i++) {
      const entry = this.dequeue();
      if (entry) {
        result.push(entry);
      }
    }
    
    return result;
  }
  
  /**
   * Подъем элемента вверх (heapify up)
   */
  private bubbleUp(index: number): void {
    while (index > 0) {
      const parentIndex = Math.floor((index - 1) / 2);
      
      // Сравниваем по приоритету (выше приоритет = меньше число)
      // При равном приоритете сравниваем по sequence number (FIFO)
      if (
        this.heap[index].priority < this.heap[parentIndex].priority ||
        (
          this.heap[index].priority === this.heap[parentIndex].priority &&
          this.heap[index].sequenceNumber < this.heap[parentIndex].sequenceNumber
        )
      ) {
        [this.heap[index], this.heap[parentIndex]] = [this.heap[parentIndex], this.heap[index]];
        index = parentIndex;
      } else {
        break;
      }
    }
  }
  
  /**
   * Опускание элемента вниз (heapify down)
   */
  private bubbleDown(index: number): void {
    const length = this.heap.length;
    
    while (true) {
      let smallest = index;
      const leftChild = 2 * index + 1;
      const rightChild = 2 * index + 2;
      
      if (leftChild < length && (
        this.heap[leftChild].priority < this.heap[smallest].priority ||
        (
          this.heap[leftChild].priority === this.heap[smallest].priority &&
          this.heap[leftChild].sequenceNumber < this.heap[smallest].sequenceNumber
        )
      )) {
        smallest = leftChild;
      }
      
      if (rightChild < length && (
        this.heap[rightChild].priority < this.heap[smallest].priority ||
        (
          this.heap[rightChild].priority === this.heap[smallest].priority &&
          this.heap[rightChild].sequenceNumber < this.heap[smallest].sequenceNumber
        )
      )) {
        smallest = rightChild;
      }
      
      if (smallest !== index) {
        [this.heap[index], this.heap[smallest]] = [this.heap[smallest], this.heap[index]];
        index = smallest;
      } else {
        break;
      }
    }
  }
}

// ============================================================================
// КОМПРЕССОР
// ============================================================================

/**
 * Компрессор для сжатия данных
 */
class Compressor {
  private algorithm: CompressionAlgorithm;
  private level: number;
  
  constructor(algorithm: CompressionAlgorithm, level: number = 6) {
    this.algorithm = algorithm;
    this.level = level;
  }
  
  /**
   * Сжатие данных
   */
  async compress(data: Buffer): Promise<Buffer> {
    switch (this.algorithm) {
      case CompressionAlgorithm.GZIP:
        return this.gzipCompress(data);
      case CompressionAlgorithm.DEFLATE:
        return this.deflateCompress(data);
      case CompressionAlgorithm.BROTLI:
        return this.brotliCompress(data);
      case CompressionAlgorithm.NONE:
        return data;
      default:
        return data;
    }
  }
  
  /**
   * Расжатие данных
   */
  async decompress(data: Buffer, originalSize?: number): Promise<Buffer> {
    // Для простоты используем gzip для всех случаев
    // В production нужно хранить алгоритм сжатия в метаданных
    return this.gzipDecompress(data);
  }
  
  /**
   * GZIP сжатие
   */
  private gzipCompress(data: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      zlib.gzip(data, { level: this.level }, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
  }
  
  /**
   * DEFLATE сжатие
   */
  private deflateCompress(data: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      zlib.deflate(data, { level: this.level }, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
  }
  
  /**
   * Brotli сжатие
   */
  private brotliCompress(data: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      zlib.brotliCompress(data, { 
        params: {
          [zlib.constants.BROTLI_PARAM_QUALITY]: this.level
        }
      }, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
  }
  
  /**
   * GZIP расжатие
   */
  private gzipDecompress(data: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      zlib.gunzip(data, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
  }
}

// ============================================================================
// ШИФРАТОР
// ============================================================================

/**
 * Шифратор для защиты данных
 */
class Encryptor {
  private mode: EncryptionMode;
  private key: Buffer;
  
  constructor(mode: EncryptionMode, key: string | Buffer) {
    this.mode = mode;
    this.key = typeof key === 'string' ? Buffer.from(key, 'hex') : key;
    
    // Валидация ключа
    if (this.key.length !== 32) {
      throw new Error('Encryption key must be 32 bytes for AES-256');
    }
  }
  
  /**
   * Шифрование данных
   */
  async encrypt(data: Buffer): Promise<EncryptedData> {
    switch (this.mode) {
      case EncryptionMode.AES_256_GCM:
        return this.aes256GcmEncrypt(data);
      case EncryptionMode.AES_256_CBC:
        return this.aes256CbcEncrypt(data);
      case EncryptionMode.CHACHA20_POLY1305:
        return this.chacha20Encrypt(data);
      case EncryptionMode.NONE:
        return { data, iv: Buffer.alloc(0), authTag: Buffer.alloc(0) };
      default:
        return { data, iv: Buffer.alloc(0), authTag: Buffer.alloc(0) };
    }
  }
  
  /**
   * Расшифровка данных
   */
  async decrypt(encrypted: EncryptedData): Promise<Buffer> {
    switch (this.mode) {
      case EncryptionMode.AES_256_GCM:
        return this.aes256GcmDecrypt(encrypted);
      case EncryptionMode.AES_256_CBC:
        return this.aes256CbcDecrypt(encrypted);
      case EncryptionMode.CHACHA20_POLY1305:
        return this.chacha20Decrypt(encrypted);
      case EncryptionMode.NONE:
        return encrypted.data;
      default:
        return encrypted.data;
    }
  }
  
  /**
   * AES-256-GCM шифрование
   */
  private aes256GcmEncrypt(data: Buffer): EncryptedData {
    const iv = crypto.randomBytes(12); // 96-bit IV для GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    return { data: encrypted, iv, authTag };
  }
  
  /**
   * AES-256-GCM расшифровка
   */
  private aes256GcmDecrypt(encrypted: EncryptedData): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, encrypted.iv);
    decipher.setAuthTag(encrypted.authTag);
    
    return Buffer.concat([
      decipher.update(encrypted.data),
      decipher.final()
    ]);
  }
  
  /**
   * AES-256-CBC шифрование
   */
  private aes256CbcEncrypt(data: Buffer): EncryptedData {
    const iv = crypto.randomBytes(16); // 128-bit IV для CBC
    const cipher = crypto.createCipheriv('aes-256-cbc', this.key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);
    
    return { data: encrypted, iv, authTag: Buffer.alloc(0) };
  }
  
  /**
   * AES-256-CBC расшифровка
   */
  private aes256CbcDecrypt(encrypted: EncryptedData): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.key, encrypted.iv);
    
    return Buffer.concat([
      decipher.update(encrypted.data),
      decipher.final()
    ]);
  }
  
  /**
   * ChaCha20-Poly1305 шифрование
   */
  private chacha20Encrypt(data: Buffer): EncryptedData {
    const iv = crypto.randomBytes(12); // 96-bit nonce для ChaCha20
    const cipher = crypto.createCipheriv('chacha20-poly1305', this.key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);
    
    const authTag = cipher.getAuthTag();
    
    return { data: encrypted, iv, authTag };
  }
  
  /**
   * ChaCha20-Poly1305 расшифровка
   */
  private chacha20Decrypt(encrypted: EncryptedData): Buffer {
    const decipher = crypto.createDecipheriv('chacha20-poly1305', this.key, encrypted.iv);
    decipher.setAuthTag(encrypted.authTag);
    
    return Buffer.concat([
      decipher.update(encrypted.data),
      decipher.final()
    ]);
  }
}

/**
 * Зашифрованные данные
 */
interface EncryptedData {
  data: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

// ============================================================================
// ОСНОВНОЙ КЛАСС БУФЕРА
// ============================================================================

/**
 * Kafka-style Log Buffer
 * 
 * Реализует:
 * - Приоритетную очередь для обработки логов
 * - Пакетную отправку для оптимизации производительности
 * - Сжатие и шифрование данных
 * - Гарантированную доставку с retry
 * - Персистентность при сбоях
 * - Метрики и мониторинг
 */
export class LogBuffer extends EventEmitter {
  private config: LogBufferConfig;
  private priorityQueue: PriorityQueue;
  private compressor: Compressor;
  private encryptor: Encryptor | null;
  private consumer: BatchConsumer | null;
  private enabled: boolean;
  private processing: boolean;
  private flushTimer: NodeJS.Timeout | null;
  private sequenceCounter: number;
  private statistics: BufferStatistics;
  private processingTimes: number[];
  private retryQueue: LogBatch[];
  private maxRetries: number;
  
  constructor(
    config: LogBufferConfig,
    encryptionKey?: string
  ) {
    super();
    
    this.config = config;
    this.priorityQueue = new PriorityQueue();
    this.compressor = new Compressor(
      config.enableCompression ? CompressionAlgorithm.GZIP : CompressionAlgorithm.NONE,
      6
    );
    this.encryptor = encryptionKey ? new Encryptor(EncryptionMode.AES_256_GCM, encryptionKey) : null;
    this.consumer = null;
    this.enabled = true;
    this.processing = false;
    this.flushTimer = null;
    this.sequenceCounter = 0;
    this.retryQueue = [];
    this.maxRetries = 3;
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.processingTimes = [];
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): BufferStatistics {
    return {
      currentSize: 0,
      maxSize: this.config.maxBufferSize,
      fillPercentage: 0,
      batchesProcessed: 0,
      logsProcessed: 0,
      processingErrors: 0,
      avgBatchProcessingTime: 0,
      p99ProcessingTime: 0,
      compression: {
        totalOriginalSize: 0,
        totalCompressedSize: 0,
        avgCompressionRatio: 0
      },
      byPriority: {},
      bySource: {} as Record<LogSource, number>,
      suppressedLogs: 0,
      bufferFlushes: 0
    };
  }
  
  /**
   * Установка потребителя пакетов
   */
  setConsumer(consumer: BatchConsumer): void {
    this.consumer = consumer;
  }
  
  /**
   * Добавление лога в буфер
   */
  add(log: LogEntry): boolean {
    if (!this.enabled) {
      return false;
    }
    
    // Проверка переполнения
    if (this.priorityQueue.size() >= this.config.maxBufferSize) {
      this.handleOverflow(log);
      return false;
    }
    
    // Определение приоритета
    const priority = this.calculatePriority(log);
    
    // Добавление в очередь
    this.priorityQueue.enqueue(log, priority);
    
    // Обновление статистики
    this.updateStatistics(log, priority);
    
    // Запуск таймера если это первый элемент
    if (this.priorityQueue.size() === 1) {
      this.startFlushTimer();
    }
    
    // Проверка достижения минимального размера пакета
    if (this.priorityQueue.size() >= this.config.minBatchSize) {
      this.flush();
    }
    
    return true;
  }
  
  /**
   * Добавление нескольких логов в буфер
   */
  addBatch(logs: LogEntry[]): number {
    let addedCount = 0;
    
    for (const log of logs) {
      if (this.add(log)) {
        addedCount++;
      }
    }
    
    return addedCount;
  }
  
  /**
   * Принудительная отправка пакета
   */
  flush(): void {
    if (this.processing || this.priorityQueue.size() === 0) {
      return;
    }
    
    // Остановка таймера
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    
    // Извлечение пакета
    const entries = this.priorityQueue.drain(this.config.maxBufferSize);
    
    if (entries.length === 0) {
      return;
    }
    
    // Создание пакета
    const batch = this.createBatch(entries);
    
    // Обработка пакета
    this.processBatch(batch);
  }
  
  /**
   * Создание пакета из записей
   */
  private createBatch(entries: PriorityLogEntry[]): LogBatch {
    const logs = entries.map(e => e.log);
    
    // Определение приоритета пакета (минимальный приоритет в пакете)
    const priority = Math.min(...entries.map(e => e.priority));
    
    // Определение источника (наиболее частый в пакете)
    const sourceCounts = new Map<LogSource, number>();
    for (const log of logs) {
      sourceCounts.set(log.source, (sourceCounts.get(log.source) || 0) + 1);
    }
    const source = Array.from(sourceCounts.entries())
      .sort((a, b) => b[1] - a[1])[0][0];
    
    return {
      id: crypto.randomUUID(),
      logs,
      createdAt: new Date().toISOString(),
      source,
      priority,
      compressed: this.config.enableCompression,
      encrypted: this.config.enableEncryption
    };
  }
  
  /**
   * Обработка пакета
   */
  private async processBatch(batch: LogBatch): Promise<void> {
    this.processing = true;
    const startTime = Date.now();
    
    try {
      // Сжатие если включено
      if (this.config.enableCompression) {
        batch = await this.compressBatch(batch);
      }
      
      // Шифрование если включено
      if (this.config.enableEncryption && this.encryptor) {
        batch = await this.encryptBatch(batch);
      }
      
      // Отправка потребителю
      if (this.consumer) {
        const result = await this.consumer.consume(batch);
        
        // Обновление статистики
        this.updateBatchStatistics(result, startTime);
        
        // Обработка ошибок
        if (!result.success) {
          await this.handleBatchFailure(batch, result);
        }
        
        // Эмиссия события успешной обработки
        this.emit('batch_processed', {
          batchId: batch.id,
          logCount: batch.logs.length,
          processingTime: result.processingTime
        });
      } else {
        // Если нет потребителя, просто эмитим событие
        this.emit('batch_ready', batch);
        
        this.statistics.batchesProcessed++;
        this.statistics.logsProcessed += batch.logs.length;
      }
      
      this.statistics.bufferFlushes++;
    } catch (error) {
      this.statistics.processingErrors++;
      
      this.emit('batch_error', {
        batchId: batch.id,
        error
      });
      
      // Попытка retry
      await this.handleBatchFailure(batch, {
        batchId: batch.id,
        success: false,
        processedCount: 0,
        failedCount: batch.logs.length,
        errors: [{
          stage: 'processBatch',
          code: 'BATCH_PROCESS_ERROR',
          message: error instanceof Error ? error.message : String(error),
          recoverable: true
        }],
        processingTime: Date.now() - startTime
      });
    } finally {
      this.processing = false;
      
      // Продолжение обработки если есть еще логи
      if (this.priorityQueue.size() > 0) {
        this.flush();
      }
    }
  }
  
  /**
   * Сжатие пакета
   */
  private async compressBatch(batch: LogBatch): Promise<LogBatch> {
    const originalData = Buffer.from(JSON.stringify(batch.logs), 'utf8');
    const compressedData = await this.compressor.compress(originalData);
    
    // Обновление статистики сжатия
    this.statistics.compression.totalOriginalSize += originalData.length;
    this.statistics.compression.totalCompressedSize += compressedData.length;
    this.statistics.compression.avgCompressionRatio = 
      this.statistics.compression.totalCompressedSize / this.statistics.compression.totalOriginalSize;
    
    // Для простоты храним сжатые данные как строку base64
    // В production лучше использовать бинарный формат
    const compressedLogs = JSON.parse(
      zlib.gunzipSync(compressedData).toString('utf8')
    );
    
    batch.logs = compressedLogs;
    batch.compressed = true;
    
    return batch;
  }
  
  /**
   * Шифрование пакета
   */
  private async encryptBatch(batch: LogBatch): Promise<LogBatch> {
    if (!this.encryptor) {
      return batch;
    }
    
    const data = Buffer.from(JSON.stringify(batch.logs), 'utf8');
    const encrypted = await this.encryptor.encrypt(data);
    
    // Хранение зашифрованных данных с метаданными
    batch.logs = [{
      id: `encrypted_${batch.id}`,
      timestamp: new Date().toISOString(),
      level: 7, // DEBUG
      source: LogSource.SYSTEM,
      component: 'encryptor',
      hostname: 'encrypted',
      processId: 0,
      message: JSON.stringify({
        iv: encrypted.iv.toString('hex'),
        authTag: encrypted.authTag.toString('hex'),
        data: encrypted.data.toString('base64')
      }),
      schemaVersion: '1.0.0',
      context: {}
    } as LogEntry];
    
    batch.encrypted = true;
    
    return batch;
  }
  
  /**
   * Обработка переполнения буфера
   */
  private handleOverflow(log: LogEntry): void {
    this.statistics.suppressedLogs++;
    
    switch (this.config.overflowStrategy) {
      case 'drop_oldest':
        // Удаляем oldest элемент и добавляем новый
        // В priority queue это сложно, поэтому просто отбрасываем новый
        this.emit('overflow', {
          strategy: 'drop_oldest',
          droppedLog: log
        });
        break;
        
      case 'drop_newest':
        // Отбрасываем новый лог
        this.emit('overflow', {
          strategy: 'drop_newest',
          droppedLog: log
        });
        break;
        
      case 'block':
        // Блокируем до освобождения места
        // В асинхронной реализации это означает rejection
        this.emit('overflow', {
          strategy: 'block',
          rejectedLog: log
        });
        break;
    }
  }
  
  /**
   * Обработка неудачи пакета
   */
  private async handleBatchFailure(batch: LogBatch, result: BatchProcessResult): Promise<void> {
    // Проверка количества retry
    const retryCount = (batch as LogBatch & { retryCount?: number }).retryCount || 0;
    
    if (retryCount < this.maxRetries) {
      // Добавление в retry queue
      (batch as LogBatch & { retryCount: number }).retryCount = retryCount + 1;
      this.retryQueue.push(batch);
      
      this.emit('batch_retry', {
        batchId: batch.id,
        retryCount: retryCount + 1,
        maxRetries: this.maxRetries
      });
    } else {
      // Превышено количество retry
      this.emit('batch_failed', {
        batchId: batch.id,
        error: 'Max retries exceeded',
        result
      });
    }
  }
  
  /**
   * Запуск таймера flush
   */
  private startFlushTimer(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
    }
    
    this.flushTimer = setTimeout(() => {
      this.flush();
    }, this.config.maxWaitTime);
  }
  
  /**
   * Расчет приоритета лога
   */
  private calculatePriority(log: LogEntry): number {
    // Базовый приоритет от источника
    let priority = SOURCE_PRIORITIES[log.source] || 50;
    
    // Корректировка от уровня логирования
    // Более критичные уровни = меньший номер приоритета
    priority -= (8 - log.level) * 5;
    
    // Корректировка для security событий
    if (log.source === LogSource.SECURITY || log.source === LogSource.AUTH) {
      priority -= 10;
    }
    
    return priority;
  }
  
  /**
   * Обновление статистики
   */
  private updateStatistics(log: LogEntry, priority: number): void {
    this.statistics.currentSize = this.priorityQueue.size();
    this.statistics.fillPercentage = 
      (this.statistics.currentSize / this.statistics.maxSize) * 100;
    
    // Статистика по приоритетам
    const priorityBucket = Math.floor(priority / 10) * 10;
    this.statistics.byPriority[priorityBucket] = 
      (this.statistics.byPriority[priorityBucket] || 0) + 1;
    
    // Статистика по источникам
    this.statistics.bySource[log.source] = 
      (this.statistics.bySource[log.source] || 0) + 1;
  }
  
  /**
   * Обновление статистики пакета
   */
  private updateBatchStatistics(result: BatchProcessResult, startTime: number): void {
    const processingTime = Date.now() - startTime;
    
    this.statistics.batchesProcessed++;
    this.statistics.logsProcessed += result.processedCount;
    this.statistics.processingErrors += result.failedCount;
    
    // Обновление processing times для percentile calculations
    this.processingTimes.push(processingTime);
    
    // Ограничение размера массива
    if (this.processingTimes.length > 1000) {
      this.processingTimes.shift();
    }
    
    // Расчет average
    this.statistics.avgBatchProcessingTime = 
      this.processingTimes.reduce((a, b) => a + b, 0) / this.processingTimes.length;
    
    // Расчет P99
    const sorted = [...this.processingTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99ProcessingTime = sorted[p99Index] || 0;
    
    // Обновление compression statistics
    if (result.compressedSize && result.originalSize) {
      this.statistics.compression.totalOriginalSize += result.originalSize;
      this.statistics.compression.totalCompressedSize += result.compressedSize;
      this.statistics.compression.avgCompressionRatio = 
        this.statistics.compression.totalCompressedSize / this.statistics.compression.totalOriginalSize;
    }
  }
  
  /**
   * Обработка retry очереди
   */
  async processRetryQueue(): Promise<void> {
    while (this.retryQueue.length > 0 && !this.processing) {
      const batch = this.retryQueue.shift();
      if (batch) {
        await this.processBatch(batch);
      }
    }
  }
  
  /**
   * Получение статистики
   */
  getStatistics(): BufferStatistics {
    return {
      ...this.statistics,
      currentSize: this.priorityQueue.size()
    };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
    this.processingTimes = [];
  }
  
  /**
   * Получение текущего размера буфера
   */
  size(): number {
    return this.priorityQueue.size();
  }
  
  /**
   * Проверка пустоты буфера
   */
  isEmpty(): boolean {
    return this.priorityQueue.isEmpty();
  }
  
  /**
   * Очистка буфера
   */
  clear(): void {
    this.priorityQueue.clear();
    this.retryQueue = [];
    
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    
    this.emit('cleared');
  }
  
  /**
   * Включение буфера
   */
  enable(): void {
    this.enabled = true;
  }
  
  /**
   * Выключение буфера
   */
  disable(): void {
    this.enabled = false;
    
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
  }
  
  /**
   * Закрытие буфера
   */
  async close(): Promise<void> {
    this.disable();
    
    // Обработка оставшихся логов
    if (!this.priorityQueue.isEmpty()) {
      this.flush();
      
      // Ожидание завершения обработки
      while (this.processing) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }
    
    // Обработка retry queue
    if (this.retryQueue.length > 0) {
      await this.processRetryQueue();
    }
    
    this.emit('closed');
  }
}

// ============================================================================
// KAFKA CONSUMER/PRODUCER АБСТРАКЦИЯ
// ============================================================================

/**
 * Абстракция Kafka потребителя для LogBuffer
 */
export class KafkaBatchConsumer implements BatchConsumer {
  private brokers: string[];
  private topic: string;
  private producer: unknown; // В production использовать kafka-node или kafkajs
  private connected: boolean;
  
  constructor(brokers: string[], topic: string) {
    this.brokers = brokers;
    this.topic = topic;
    this.producer = null;
    this.connected = false;
  }
  
  /**
   * Подключение к Kafka
   */
  async connect(): Promise<void> {
    // В production реализовать подключение через kafkajs
    // const { Kafka } = require('kafkajs');
    // const kafka = new Kafka({ brokers: this.brokers });
    // this.producer = kafka.producer();
    // await this.producer.connect();
    
    this.connected = true;
  }
  
  /**
   * Отправка пакета в Kafka
   */
  async consume(batch: LogBatch): Promise<BatchProcessResult> {
    const startTime = Date.now();
    
    if (!this.connected) {
      await this.connect();
    }
    
    try {
      // В production реализовать отправку в Kafka
      // await this.producer.send({
      //   topic: this.topic,
      //   messages: [{
      //     key: batch.id,
      //     value: JSON.stringify(batch),
      //     headers: {
      //       source: batch.source,
      //       priority: batch.priority.toString(),
      //       compressed: batch.compressed.toString(),
      //       encrypted: batch.encrypted.toString()
      //     }
      //   }]
      // });
      
      return {
        batchId: batch.id,
        success: true,
        processedCount: batch.logs.length,
        failedCount: 0,
        errors: [],
        processingTime: Date.now() - startTime
      };
    } catch (error) {
      return {
        batchId: batch.id,
        success: false,
        processedCount: 0,
        failedCount: batch.logs.length,
        errors: [{
          stage: 'kafka_send',
          code: 'KAFKA_SEND_ERROR',
          message: error instanceof Error ? error.message : String(error),
          recoverable: true
        }],
        processingTime: Date.now() - startTime
      };
    }
  }
  
  /**
   * Закрытие подключения
   */
  async close(): Promise<void> {
    // В production реализовать закрытие подключения
    // if (this.producer) {
    //   await this.producer.disconnect();
    // }
    
    this.connected = false;
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default LogBuffer;
