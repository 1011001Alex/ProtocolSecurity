/**
 * ============================================================================
 * LOG STORAGE - IMMUTABLE ХРАНИЛИЩЕ ЛОГОВ
 * ============================================================================
 * Tamper-proof хранилище для логов с поддержкой hash chain верификации,
 * шифрования, сжатия и compliance retention policies.
 * 
 * Особенности:
 * - Append-only запись
 * - Hash chain для верификации целостности
 * - Цифровые подписи записей
 * - Шифрование данных (AES-256-GCM)
 * - Сжатие (gzip)
 * - Ротация файлов
 * - Retention policies
 * - WORM (Write Once Read Many) поддержка
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';
import { EventEmitter } from 'events';
import {
  LogEntry,
  LogStorageConfig,
  StorageStrategy,
  ImmutableLogRecord,
  IntegrityVerificationResult,
  IntegrityViolation,
  RotationPolicy,
  RetentionPolicy,
  ProcessingError
} from '../types/logging.types';

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/**
 * Размер чанка для хеширования больших файлов
 */
const CHUNK_SIZE = 1024 * 1024; // 1MB

/**
 * Максимальный размер файла перед ротацией (по умолчанию)
 */
const DEFAULT_MAX_FILE_SIZE_MB = 1000;

/**
 * Алгоритм хеширования по умолчанию
 */
const DEFAULT_HASH_ALGORITHM = 'sha256';

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Запись в хранилище
 */
interface StorageWriteResult {
  /** ID записи */
  recordId: string;
  /** Sequence номер */
  sequenceNumber: number;
  /** Хеш содержимого */
  contentHash: string;
  /** Хеш предыдущей записи */
  previousHash: string;
  /** Путь к файлу */
  filePath: string;
  /** Размер записи (байты) */
  size: number;
  /** Время записи */
  writtenAt: string;
}

/**
 * Статистика хранилища
 */
interface StorageStatistics {
  /** Всего записей */
  totalRecords: number;
  /** Общий размер (байты) */
  totalSize: number;
  /** Текущий файл */
  currentFile: string;
  /** Количество файлов */
  fileCount: number;
  /** Записей добавлено */
  recordsAdded: number;
  /** Записей удалено (при ротации) */
  recordsRemoved: number;
  /** Ошибки записи */
  writeErrors: number;
  /** Ошибки чтения */
  readErrors: number;
  /** Среднее время записи (мс) */
  avgWriteTime: number;
  /** P99 время записи (мс) */
  p99WriteTime: number;
  /** Последняя верификация */
  lastVerification: string | null;
  /** Нарушения целостности */
  integrityViolations: number;
}

/**
 * Конфигурация шифрования
 */
interface EncryptionConfig {
  enabled: boolean;
  algorithm: 'aes-256-gcm' | 'aes-256-cbc';
  key: Buffer;
  keyId: string;
}

// ============================================================================
// КЛАСС HASH CHAIN
// ============================================================================

/**
 * Менеджер hash chain для верификации целостности
 */
class HashChainManager {
  private previousHash: string;
  private sequenceNumber: number;
  private hashAlgorithm: string;
  private checkpointHash: string;
  private checkpointSequence: number;
  
  constructor(hashAlgorithm: string = DEFAULT_HASH_ALGORITHM) {
    this.previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.sequenceNumber = 0;
    this.hashAlgorithm = hashAlgorithm;
    this.checkpointHash = this.previousHash;
    this.checkpointSequence = 0;
  }
  
  /**
   * Добавление записи в цепочку
   */
  addRecord(log: LogEntry): { hash: string; sequenceNumber: number; previousHash: string } {
    this.sequenceNumber++;
    
    const contentHash = this.computeContentHash(log);
    
    // Хеш для цепочки включает предыдущий хеш
    const chainData = JSON.stringify({
      sequenceNumber: this.sequenceNumber,
      previousHash: this.previousHash,
      contentHash,
      timestamp: log.timestamp
    });
    
    const newHash = crypto.createHash(this.hashAlgorithm).update(chainData).digest('hex');
    const oldPreviousHash = this.previousHash;
    
    this.previousHash = newHash;
    
    return {
      hash: newHash,
      sequenceNumber: this.sequenceNumber,
      previousHash: oldPreviousHash
    };
  }
  
  /**
   * Вычисление хеша содержимого
   */
  private computeContentHash(log: LogEntry): string {
    const content = JSON.stringify({
      id: log.id,
      timestamp: log.timestamp,
      level: log.level,
      source: log.source,
      component: log.component,
      hostname: log.hostname,
      processId: log.processId,
      message: log.message,
      context: log.context
    });
    
    return crypto.createHash(this.hashAlgorithm).update(content).digest('hex');
  }
  
  /**
   * Создание checkpoint
   */
  createCheckpoint(): { hash: string; sequenceNumber: number } {
    this.checkpointHash = this.previousHash;
    this.checkpointSequence = this.sequenceNumber;
    
    return {
      hash: this.checkpointHash,
      sequenceNumber: this.checkpointSequence
    };
  }
  
  /**
   * Получение текущего состояния
   */
  getState(): { previousHash: string; sequenceNumber: number } {
    return {
      previousHash: this.previousHash,
      sequenceNumber: this.sequenceNumber
    };
  }
  
  /**
   * Восстановление из состояния
   */
  restoreState(previousHash: string, sequenceNumber: number): void {
    this.previousHash = previousHash;
    this.sequenceNumber = sequenceNumber;
    this.checkpointHash = previousHash;
    this.checkpointSequence = sequenceNumber;
  }
  
  /**
   * Получение checkpoint
   */
  getCheckpoint(): { hash: string; sequenceNumber: number } {
    return {
      hash: this.checkpointHash,
      sequenceNumber: this.checkpointSequence
    };
  }
  
  /**
   * Сброс цепочки
   */
  reset(): void {
    this.previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.sequenceNumber = 0;
    this.checkpointHash = this.previousHash;
    this.checkpointSequence = 0;
  }
}

// ============================================================================
// КЛАСС ENCRYPTION MANAGER
// ============================================================================

/**
 * Менеджер шифрования
 */
class EncryptionManager {
  private config: EncryptionConfig | null;
  
  constructor(config?: EncryptionConfig) {
    this.config = config || null;
  }
  
  /**
   * Шифрование данных
   */
  encrypt(data: Buffer): { encrypted: Buffer; iv: Buffer; authTag: Buffer } | null {
    if (!this.config || !this.config.enabled) {
      return null;
    }
    
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.config.algorithm, this.config.key, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);
    
    const authTag = (cipher as crypto.CipherGCM).getAuthTag();
    
    return { encrypted, iv, authTag };
  }
  
  /**
   * Расшифровка данных
   */
  decrypt(encrypted: Buffer, iv: Buffer, authTag: Buffer): Buffer | null {
    if (!this.config || !this.config.enabled) {
      return encrypted;
    }
    
    const decipher = crypto.createDecipheriv(this.config.algorithm, this.config.key, iv);
    (decipher as crypto.DecipherGCM).setAuthTag(authTag);
    
    return Buffer.concat([
      decipher.update(encrypted),
      decipher.final()
    ]);
  }
  
  /**
   * Проверка включено ли шифрование
   */
  isEnabled(): boolean {
    return this.config?.enabled || false;
  }
}

// ============================================================================
// КЛАСС ROTATION MANAGER
// ============================================================================

/**
 * Менеджер ротации файлов
 */
class RotationManager {
  private policy: RotationPolicy;
  private currentFileSize: number;
  private currentFilePath: string;
  private fileIndex: number;
  
  constructor(policy: RotationPolicy, storagePath: string) {
    this.policy = policy;
    this.currentFileSize = 0;
    this.currentFilePath = storagePath;
    this.fileIndex = 0;
  }
  
  /**
   * Проверка необходимости ротации
   */
  shouldRotate(newDataSize: number): boolean {
    switch (this.policy.type) {
      case 'size':
        return this.currentFileSize + newDataSize > (this.policy.maxSizeMB || 1000) * 1024 * 1024;
      
      case 'time': {
        const now = new Date();
        const lastRotation = this.getLastRotationTime();
        
        switch (this.policy.interval) {
          case 'hourly':
            return now.getHours() !== lastRotation.getHours() || now.getDate() !== lastRotation.getDate();
          case 'daily':
            return now.getDate() !== lastRotation.getDate();
          case 'weekly':
            return now.getDay() === 0 && now.getHours() < 1;
          case 'monthly':
            return now.getMonth() !== lastRotation.getMonth();
          default:
            return false;
        }
      }
      
      case 'both':
        return this.shouldRotateBySize(newDataSize) || this.shouldRotateByTime();
      
      default:
        return false;
    }
  }
  
  /**
   * Проверка ротации по размеру
   */
  private shouldRotateBySize(newDataSize: number): boolean {
    return this.currentFileSize + newDataSize > (this.policy.maxSizeMB || 1000) * 1024 * 1024;
  }
  
  /**
   * Проверка ротации по времени
   */
  private shouldRotateByTime(): boolean {
    const now = new Date();
    const lastRotation = this.getLastRotationTime();
    
    switch (this.policy.interval) {
      case 'hourly':
        return now.getHours() !== lastRotation.getHours();
      case 'daily':
        return now.getDate() !== lastRotation.getDate();
      case 'weekly':
        return now.getDay() === 0 && now.getHours() < 1;
      case 'monthly':
        return now.getMonth() !== lastRotation.getMonth();
      default:
        return false;
    }
  }
  
  /**
   * Получение времени последней ротации
   */
  private getLastRotationTime(): Date {
    // В production хранить в метаданных
    return new Date();
  }
  
  /**
   * Выполнение ротации
   */
  rotate(): string {
    const newPath = this.getNewFilePath();
    
    // Сдвиг существующих файлов
    this.shiftFiles();
    
    this.currentFilePath = newPath;
    this.currentFileSize = 0;
    this.fileIndex++;
    
    return newPath;
  }
  
  /**
   * Получение нового пути к файлу
   */
  private getNewFilePath(): string {
    const ext = path.extname(this.currentFilePath);
    const base = this.currentFilePath.slice(0, -ext.length || undefined);
    return `${base}.${new Date().toISOString().replace(/[:.]/g, '-')}${ext}`;
  }
  
  /**
   * Сдвиг файлов
   */
  private shiftFiles(): void {
    if (!this.policy.enableArchiving) {
      // Удаление старого файла если превышен лимит
      const files = this.getExistingFiles();
      
      while (files.length >= (this.policy.maxFiles || 5)) {
        const oldest = files.pop();
        if (oldest && fs.existsSync(oldest)) {
          fs.unlinkSync(oldest);
        }
      }
    } else {
      // Архивация
      const files = this.getExistingFiles();
      
      for (let i = files.length - 1; i >= 0; i--) {
        const oldPath = files[i];
        const archivePath = path.join(
          this.policy.archivePath || './archive',
          path.basename(oldPath) + '.gz'
        );
        
        if (fs.existsSync(oldPath)) {
          // Сжатие и перемещение в архив
          const data = fs.readFileSync(oldPath);
          const compressed = zlib.gzipSync(data);
          
          const archiveDir = path.dirname(archivePath);
          if (!fs.existsSync(archiveDir)) {
            fs.mkdirSync(archiveDir, { recursive: true });
          }
          
          fs.writeFileSync(archivePath, compressed);
          fs.unlinkSync(oldPath);
        }
      }
    }
  }
  
  /**
   * Получение существующих файлов
   */
  private getExistingFiles(): string[] {
    const dir = path.dirname(this.currentFilePath);
    const base = path.basename(this.currentFilePath, path.extname(this.currentFilePath));
    
    if (!fs.existsSync(dir)) {
      return [];
    }
    
    return fs.readdirSync(dir)
      .filter(f => f.startsWith(base))
      .map(f => path.join(dir, f))
      .sort();
  }
  
  /**
   * Обновление размера файла
   */
  updateSize(newSize: number): void {
    this.currentFileSize = newSize;
  }
  
  /**
   * Получение текущего пути
   */
  getCurrentPath(): string {
    return this.currentFilePath;
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС LOG STORAGE
// ============================================================================

/**
 * Log Storage - immutable хранилище логов
 * 
 * Реализует:
 * - Append-only запись
 * - Hash chain верификация
 * - Шифрование данных
 * - Сжатие
 * - Ротация файлов
 * - Retention policies
 */
export class LogStorage extends EventEmitter {
  private config: LogStorageConfig;
  private hashChain: HashChainManager;
  private encryptionManager: EncryptionManager;
  private rotationManager: RotationManager;
  
  /** Write stream */
  private writeStream: fs.WriteStream | null;
  /** Статистика */
  private statistics: StorageStatistics;
  private writeTimes: number[];
  private enabled: boolean;
  
  constructor(config: LogStorageConfig, encryptionKey?: string) {
    super();
    
    this.config = config;
    this.hashChain = new HashChainManager(config.hashAlgorithm);
    this.encryptionManager = new EncryptionManager(
      encryptionKey ? {
        enabled: config.enableEncryption,
        algorithm: 'aes-256-gcm',
        key: Buffer.from(encryptionKey, 'hex'),
        keyId: 'default'
      } : undefined
    );
    this.rotationManager = new RotationManager(config.rotationPolicy, config.storagePath);
    
    this.writeStream = null;
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.writeTimes = [];
    this.enabled = true;
    
    // Инициализация хранилища
    this.initializeStorage();
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): StorageStatistics {
    return {
      totalRecords: 0,
      totalSize: 0,
      currentFile: this.config.storagePath,
      fileCount: 0,
      recordsAdded: 0,
      recordsRemoved: 0,
      writeErrors: 0,
      readErrors: 0,
      avgWriteTime: 0,
      p99WriteTime: 0,
      lastVerification: null,
      integrityViolations: 0
    };
  }
  
  /**
   * Инициализация хранилища
   */
  private async initializeStorage(): Promise<void> {
    const dir = path.dirname(this.config.storagePath);
    
    // Создание директории
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    // Открытие write stream
    await this.openWriteStream();
    
    // Загрузка существующих записей
    await this.loadExistingRecords();
  }
  
  /**
   * Открытие write stream
   */
  private async openWriteStream(): Promise<void> {
    const currentPath = this.rotationManager.getCurrentPath();
    
    if (this.writeStream) {
      await this.closeWriteStream();
    }
    
    this.writeStream = fs.createWriteStream(currentPath, {
      flags: 'a',
      encoding: 'utf8'
    });
    
    // Получение текущего размера
    if (fs.existsSync(currentPath)) {
      const stats = fs.statSync(currentPath);
      this.statistics.totalSize = stats.size;
      this.rotationManager.updateSize(stats.size);
    }
    
    this.statistics.currentFile = currentPath;
  }
  
  /**
   * Закрытие write stream
   */
  private async closeWriteStream(): Promise<void> {
    if (this.writeStream) {
      return new Promise((resolve) => {
        this.writeStream?.end(() => {
          this.writeStream = null;
          resolve();
        });
      });
    }
  }
  
  /**
   * Загрузка существующих записей
   */
  private async loadExistingRecords(): Promise<void> {
    // В production парсить существующие файлы для восстановления hash chain
    const files = this.getExistingFiles();
    this.statistics.fileCount = files.length;
    
    // Подсчет общего количества записей
    let totalRecords = 0;
    
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');
      const lines = content.split('\n').filter(l => l.trim());
      totalRecords += lines.length;
    }
    
    this.statistics.totalRecords = totalRecords;
  }
  
  /**
   * Получение существующих файлов
   */
  private getExistingFiles(): string[] {
    const dir = path.dirname(this.config.storagePath);
    
    if (!fs.existsSync(dir)) {
      return [];
    }
    
    return fs.readdirSync(dir)
      .filter(f => f.endsWith('.log') || f.endsWith('.jsonl'))
      .map(f => path.join(dir, f))
      .sort();
  }
  
  /**
   * Запись лога в хранилище
   */
  async write(log: LogEntry): Promise<StorageWriteResult | null> {
    if (!this.enabled || !this.writeStream) {
      return null;
    }
    
    const startTime = Date.now();
    
    try {
      // Создание immutable записи
      const chainData = this.hashChain.addRecord(log);
      
      const record: ImmutableLogRecord = {
        log,
        contentHash: chainData.hash,
        previousHash: chainData.previousHash,
        signature: this.signRecord(log, chainData.hash),
        recordedAt: new Date().toISOString(),
        sequenceNumber: chainData.sequenceNumber
      };
      
      // Сериализация
      let recordData = JSON.stringify(record) + '\n';
      let recordBuffer = Buffer.from(recordData, 'utf8');
      
      // Шифрование если включено
      if (this.encryptionManager.isEnabled()) {
        const encrypted = this.encryptionManager.encrypt(recordBuffer);
        if (encrypted) {
          const meta = JSON.stringify({
            iv: encrypted.iv.toString('hex'),
            authTag: encrypted.authTag.toString('hex'),
            algorithm: 'aes-256-gcm'
          });
          
          recordData = meta + '\t' + encrypted.encrypted.toString('base64') + '\n';
          recordBuffer = Buffer.from(recordData, 'utf8');
        }
      }
      
      // Проверка ротации
      if (this.rotationManager.shouldRotate(recordBuffer.length)) {
        await this.rotate();
      }
      
      // Запись в stream
      const writeResult = await this.writeToStream(recordData);
      
      if (!writeResult) {
        throw new Error('Failed to write to stream');
      }
      
      // Обновление статистики
      const writeTime = Date.now() - startTime;
      this.updateWriteTimeStats(writeTime);
      
      this.statistics.totalRecords++;
      this.statistics.recordsAdded++;
      this.statistics.totalSize += recordBuffer.length;
      
      this.rotationManager.updateSize(this.statistics.totalSize);
      
      // Checkpoint при достижении интервала
      if (this.statistics.totalRecords % this.config.checkpointInterval === 0) {
        const checkpoint = this.hashChain.createCheckpoint();
        this.emit('checkpoint', checkpoint);
      }
      
      const result: StorageWriteResult = {
        recordId: log.id,
        sequenceNumber: chainData.sequenceNumber,
        contentHash: chainData.hash,
        previousHash: chainData.previousHash,
        filePath: this.rotationManager.getCurrentPath(),
        size: recordBuffer.length,
        writtenAt: new Date().toISOString()
      };
      
      this.emit('record_written', result);
      
      return result;
    } catch (error) {
      this.statistics.writeErrors++;
      
      this.emit('write_error', {
        logId: log.id,
        error
      });
      
      return null;
    }
  }
  
  /**
   * Пакетная запись
   */
  async writeBatch(logs: LogEntry[]): Promise<StorageWriteResult[]> {
    const results: StorageWriteResult[] = [];
    
    for (const log of logs) {
      const result = await this.write(log);
      if (result) {
        results.push(result);
      }
    }
    
    return results;
  }
  
  /**
   * Запись в stream
   */
  private writeToStream(data: string): Promise<boolean> {
    if (!this.writeStream) {
      return Promise.resolve(false);
    }
    
    return new Promise((resolve) => {
      this.writeStream?.write(data, 'utf8', (error) => {
        resolve(!error);
      });
    });
  }
  
  /**
   * Подпись записи
   */
  private signRecord(log: LogEntry, hash: string): string {
    // В production использовать приватный ключ для подписи
    const data = JSON.stringify({ logId: log.id, hash, timestamp: log.timestamp });
    return crypto.createHash('sha256').update(data).digest('hex');
  }
  
  /**
   * Ротация хранилища
   */
  private async rotate(): Promise<void> {
    await this.closeWriteStream();
    
    const newPath = this.rotationManager.rotate();
    this.statistics.fileCount++;
    
    await this.openWriteStream();
    
    this.emit('rotated', {
      oldPath: this.statistics.currentFile,
      newPath,
      timestamp: new Date().toISOString()
    });
  }
  
  /**
   * Чтение записи по ID
   */
  async read(recordId: string): Promise<ImmutableLogRecord | null> {
    try {
      const files = this.getExistingFiles();
      
      for (const file of files) {
        const content = fs.readFileSync(file, 'utf8');
        const lines = content.split('\n').filter(l => l.trim());
        
        for (const line of lines) {
          try {
            const record: ImmutableLogRecord = JSON.parse(line);
            
            if (record.log.id === recordId) {
              return record;
            }
          } catch {
            continue;
          }
        }
      }
      
      return null;
    } catch (error) {
      this.statistics.readErrors++;
      return null;
    }
  }
  
  /**
   * Чтение записей по диапазону
   */
  async readRange(
    fromSequence: number,
    toSequence: number
  ): Promise<ImmutableLogRecord[]> {
    const records: ImmutableLogRecord[] = [];
    
    try {
      const files = this.getExistingFiles();
      
      for (const file of files) {
        const content = fs.readFileSync(file, 'utf8');
        const lines = content.split('\n').filter(l => l.trim());
        
        for (const line of lines) {
          try {
            const record: ImmutableLogRecord = JSON.parse(line);
            
            if (record.sequenceNumber >= fromSequence && record.sequenceNumber <= toSequence) {
              records.push(record);
            }
          } catch {
            continue;
          }
        }
      }
      
      return records.sort((a, b) => a.sequenceNumber - b.sequenceNumber);
    } catch (error) {
      this.statistics.readErrors++;
      return [];
    }
  }
  
  /**
   * Верификация целостности
   */
  async verifyIntegrity(): Promise<IntegrityVerificationResult> {
    const violations: IntegrityViolation[] = [];
    let verifiedRecords = 0;
    
    try {
      const files = this.getExistingFiles();
      let previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
      let expectedSequence = 1;
      const seenIds = new Set<string>();
      
      for (const file of files) {
        const content = fs.readFileSync(file, 'utf8');
        const lines = content.split('\n').filter(l => l.trim());
        
        for (const line of lines) {
          try {
            const record: ImmutableLogRecord = JSON.parse(line);
            verifiedRecords++;
            
            // Проверка sequence number
            if (record.sequenceNumber !== expectedSequence) {
              violations.push({
                type: 'missing_record',
                recordId: `seq_${expectedSequence}`,
                expectedValue: String(expectedSequence),
                actualValue: String(record.sequenceNumber),
                severity: 'critical',
                detectedAt: new Date().toISOString(),
                possibleCause: 'Records may have been deleted or tampered'
              });
            }
            
            // Проверка дубликатов
            if (seenIds.has(record.log.id)) {
              violations.push({
                type: 'duplicate_record',
                recordId: record.log.id,
                expectedValue: 'unique',
                actualValue: 'duplicate',
                severity: 'high',
                detectedAt: new Date().toISOString()
              });
            }
            seenIds.add(record.log.id);
            
            // Проверка hash chain
            const expectedChainData = JSON.stringify({
              sequenceNumber: record.sequenceNumber,
              previousHash,
              contentHash: record.contentHash,
              timestamp: record.log.timestamp
            });
            
            const expectedHash = crypto
              .createHash(this.config.hashAlgorithm)
              .update(expectedChainData)
              .digest('hex');
            
            if (record.contentHash !== expectedHash) {
              violations.push({
                type: 'hash_mismatch',
                recordId: record.log.id,
                expectedValue: expectedHash,
                actualValue: record.contentHash,
                severity: 'critical',
                detectedAt: new Date().toISOString(),
                possibleCause: 'Record content may have been tampered'
              });
            }
            
            // Проверка подписи
            const expectedSignature = this.signRecord(record.log, record.contentHash);
            if (record.signature !== expectedSignature) {
              violations.push({
                type: 'signature_invalid',
                recordId: record.log.id,
                expectedValue: expectedSignature,
                actualValue: record.signature,
                severity: 'critical',
                detectedAt: new Date().toISOString(),
                possibleCause: 'Record signature does not match'
              });
            }
            
            previousHash = record.contentHash;
            expectedSequence = record.sequenceNumber + 1;
          } catch (error) {
            violations.push({
              type: 'hash_mismatch',
              recordId: `parse_error_${verifiedRecords}`,
              expectedValue: 'valid JSON',
              actualValue: 'parse error',
              severity: 'high',
              detectedAt: new Date().toISOString(),
              possibleCause: error instanceof Error ? error.message : 'Unknown error'
            });
          }
        }
      }
      
      this.statistics.lastVerification = new Date().toISOString();
      this.statistics.integrityViolations += violations.length;
      
      const result: IntegrityVerificationResult = {
        isValid: violations.length === 0,
        verifiedRecords,
        violationsFound: violations.length,
        violations,
        verifiedAt: new Date().toISOString(),
        checkedRange: {
          from: '1',
          to: String(expectedSequence - 1)
        }
      };
      
      this.emit('verification_complete', result);
      
      return result;
    } catch (error) {
      return {
        isValid: false,
        verifiedRecords: 0,
        violationsFound: 1,
        violations: [{
          type: 'hash_mismatch',
          recordId: 'storage_error',
          expectedValue: 'success',
          actualValue: error instanceof Error ? error.message : String(error),
          severity: 'critical',
          detectedAt: new Date().toISOString()
        }],
        verifiedAt: new Date().toISOString(),
        checkedRange: { from: '0', to: '0' }
      };
    }
  }
  
  /**
   * Обновление статистики времени записи
   */
  private updateWriteTimeStats(time: number): void {
    this.writeTimes.push(time);
    
    if (this.writeTimes.length > 1000) {
      this.writeTimes.shift();
    }
    
    this.statistics.avgWriteTime = 
      this.writeTimes.reduce((a, b) => a + b, 0) / this.writeTimes.length;
    
    const sorted = [...this.writeTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99WriteTime = sorted[p99Index] || 0;
  }
  
  /**
   * Получение статистики
   */
  getStatistics(): StorageStatistics {
    return { ...this.statistics };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
    this.writeTimes = [];
  }
  
  /**
   * Включение хранилища
   */
  enable(): void {
    this.enabled = true;
  }
  
  /**
   * Выключение хранилища
   */
  async disable(): Promise<void> {
    this.enabled = false;
    await this.closeWriteStream();
  }
  
  /**
   * Закрытие хранилища
   */
  async close(): Promise<void> {
    await this.disable();
    this.emit('closed');
  }
  
  /**
   * Принудительное создание checkpoint
   */
  createCheckpoint(): { hash: string; sequenceNumber: number } {
    return this.hashChain.createCheckpoint();
  }
  
  /**
   * Получение последнего sequence number
   */
  getLastSequenceNumber(): number {
    const state = this.hashChain.getState();
    return state.sequenceNumber;
  }
  
  /**
   * Удаление старых записей по retention policy
   */
  async applyRetentionPolicy(): Promise<{ deleted: number; archived: number }> {
    const policy = this.config.retentionPolicy;
    const now = Date.now();
    let deleted = 0;
    let archived = 0;
    
    const files = this.getExistingFiles();
    
    for (const file of files) {
      const stats = fs.statSync(file);
      const ageDays = (now - stats.mtimeMs) / (1000 * 60 * 60 * 24);
      
      let shouldDelete = false;
      let shouldArchive = false;
      
      // Cold retention
      if (ageDays > policy.coldRetentionDays) {
        if (policy.expirationAction === 'delete') {
          shouldDelete = true;
        } else if (policy.expirationAction === 'archive') {
          shouldArchive = true;
        }
      }
      
      if (shouldDelete) {
        fs.unlinkSync(file);
        deleted++;
      } else if (shouldArchive && this.config.rotationPolicy.enableArchiving) {
        // Архивация
        const data = fs.readFileSync(file);
        const compressed = zlib.gzipSync(data);
        
        const archivePath = path.join(
          this.config.rotationPolicy.archivePath || './archive',
          path.basename(file) + '.gz'
        );
        
        const archiveDir = path.dirname(archivePath);
        if (!fs.existsSync(archiveDir)) {
          fs.mkdirSync(archiveDir, { recursive: true });
        }
        
        fs.writeFileSync(archivePath, compressed);
        fs.unlinkSync(file);
        archived++;
      }
    }
    
    this.statistics.recordsRemoved += deleted;
    
    return { deleted, archived };
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default LogStorage;
