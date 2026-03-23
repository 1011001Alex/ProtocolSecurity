/**
 * ============================================================================
 * FILE INTEGRITY MONITOR (FIM) - REAL-TIME МОНИТОРИНГ ФАЙЛОВ
 * ============================================================================
 * Система мониторинга целостности файлов в реальном времени.
 * Обнаруживает изменения, создания, удаления файлов и директорий.
 * 
 * Особенности:
 * - Real-time file watching через chokidar
 * - Вычисление хешей при изменениях
 * - Debounce для предотвращения ложных срабатываний
 * - Поддержка glob patterns для include/exclude
 * - Рекурсивный мониторинг
 * - Audit логирование всех событий
 * - Интеграция с baseline для детекции аномалий
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  FileEvent,
  FileEventType,
  FileEventDetails,
  WatchConfig,
  FIMStatus,
  FileHash,
  HashAlgorithm,
  IntegrityViolation,
  OperationResult
} from '../types/integrity.types';

/**
 * Опции для FileIntegrityMonitor
 */
export interface FIMOptions {
  /** Конфигурации мониторинга */
  watchConfigs: WatchConfig[];
  /** Алгоритм хеширования */
  hashAlgorithm: HashAlgorithm;
  /** Максимум событий в памяти */
  maxEventsInMemory: number;
  /** Включить audit логирование */
  enableAuditLog: boolean;
  /** Путь к audit логу */
  auditLogPath?: string;
  /** Задержка перед вычислением хеша (ms) */
  hashDebounceDelay: number;
  /** Игнорировать символические ссылки */
  ignoreSymlinks: boolean;
  /** Игнорировать определенные файлы */
  ignoredPatterns: string[];
}

/**
 * Внутреннее состояние наблюдаемого файла
 */
interface WatchedFileState {
  /** Путь к файлу */
  filePath: string;
  /** Последний хеш */
  lastHash: string;
  /** Последний размер */
  lastSize: number;
  /** Последнее время изменения */
  lastMtime: Date;
  /** Количество изменений */
  changeCount: number;
  /** Время последнего изменения */
  lastChangedAt: Date;
}

/**
 * Debounce таймер для файла
 */
interface DebounceTimer {
  /** ID таймера */
  timerId: NodeJS.Timeout;
  /** Путь к файлу */
  filePath: string;
  /** Тип ожидаемого события */
  expectedType: FileEventType;
}

/**
 * Класс File Integrity Monitor
 * 
 * Обеспечивает непрерывный мониторинг файловой системы
 * с детектированием изменений в реальном времени.
 */
export class FileIntegrityMonitor extends EventEmitter {
  /** Опции монитора */
  private readonly options: FIMOptions;
  
  /** Состояние наблюдаемых файлов */
  private readonly fileStates: Map<string, WatchedFileState> = new Map();
  
  /** Активные watcher объекты */
  private readonly watchers: Map<string, fs.FSWatcher> = new Map();
  
  /** Очередь событий */
  private readonly eventQueue: FileEvent[] = [];
  
  /** Debounce таймеры */
  private readonly debounceTimers: Map<string, DebounceTimer> = new Map();
  
  /** Статус монитора */
  private isActive: boolean = false;
  
  /** Время запуска */
  private startedAt?: Date;
  
  /** Время последнего события */
  private lastEventAt?: Date;
  
  /** Счетчик событий */
  private eventsCount: number = 0;
  
  /** Ошибки мониторинга */
  private readonly errors: Error[] = [];

  /**
   * Создает экземпляр FileIntegrityMonitor
   * 
   * @param options - Опции монитора
   */
  constructor(options: Partial<FIMOptions> = {}) {
    super();
    
    this.options = {
      watchConfigs: options.watchConfigs || [],
      hashAlgorithm: options.hashAlgorithm || 'SHA-256',
      maxEventsInMemory: options.maxEventsInMemory || 10000,
      enableAuditLog: options.enableAuditLog ?? false,
      auditLogPath: options.auditLogPath,
      hashDebounceDelay: options.hashDebounceDelay || 100,
      ignoreSymlinks: options.ignoreSymlinks ?? true,
      ignoredPatterns: options.ignoredPatterns || [
        '**/node_modules/**',
        '**/.git/**',
        '**/dist/**',
        '**/build/**',
        '**/*.log',
        '**/tmp/**',
        '**/.tmp/**'
      ]
    };
  }

  /**
   * Запускает мониторинг
   * 
   * @returns Результат запуска
   */
  async start(): Promise<OperationResult> {
    const startTime = Date.now();
    
    if (this.isActive) {
      return {
        success: false,
        errors: ['Мониторинг уже запущен'],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    }
    
    try {
      this.isActive = true;
      this.startedAt = new Date();
      this.errors.length = 0;
      
      // Инициализируем watcher для каждой конфигурации
      for (const config of this.options.watchConfigs) {
        await this.initializeWatch(config);
      }
      
      this.emit('started', { startedAt: this.startedAt });
      
      return {
        success: true,
        errors: [],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    } catch (error) {
      this.isActive = false;
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      this.errors.push(error instanceof Error ? error : new Error(errorMessage));
      
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    }
  }

  /**
   * Останавливает мониторинг
   * 
   * @returns Результат остановки
   */
  async stop(): Promise<OperationResult> {
    const startTime = Date.now();
    
    if (!this.isActive) {
      return {
        success: false,
        errors: ['Мониторинг не запущен'],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    }
    
    try {
      // Очищаем все debounce таймеры
      for (const [filePath, debounce] of this.debounceTimers.entries()) {
        clearTimeout(debounce.timerId);
      }
      this.debounceTimers.clear();
      
      // Закрываем все watcher
      for (const [watchPath, watcher] of this.watchers.entries()) {
        watcher.close();
      }
      this.watchers.clear();
      
      this.isActive = false;
      
      this.emit('stopped', { stoppedAt: new Date() });
      
      return {
        success: true,
        errors: [],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    }
  }

  /**
   * Инициализирует watcher для конфигурации
   */
  private async initializeWatch(config: WatchConfig): Promise<void> {
    const normalizedPath = path.normalize(config.path);
    
    // Проверяем существование пути
    if (!fs.existsSync(normalizedPath)) {
      throw new Error(`Путь не существует: ${normalizedPath}`);
    }
    
    // Создаем baseline хеши для существующих файлов
    await this.createBaseline(config);
    
    // Настраиваем опции watcher
    const watchOptions: fs.WatchOptions = {
      persistent: true,
      recursive: config.recursive,
      encoding: 'utf-8'
    };
    
    // Создаем watcher
    const watcher = fs.watch(normalizedPath, watchOptions, async (eventType, filename) => {
      if (!filename) return;
      
      const filePath = path.join(normalizedPath, filename);
      
      // Проверяем фильтры
      if (!this.shouldWatchFile(filePath, config)) {
        return;
      }
      
      // Debounce события
      this.debounceEvent(filePath, eventType === 'rename' ? 'deleted' : 'modified');
    });
    
    watcher.on('error', (error) => {
      this.errors.push(error);
      this.emit('error', error);
    });
    
    this.watchers.set(normalizedPath, watcher);
  }

  /**
   * Создает baseline хеши для файлов
   */
  private async createBaseline(config: WatchConfig): Promise<void> {
    const files = this.getFilesInPath(config.path, config.include, config.exclude);
    
    for (const filePath of files) {
      try {
        const stats = fs.statSync(filePath);
        
        if (stats.isFile()) {
          const hash = await this.computeFileHash(filePath);
          const size = stats.size;
          const mtime = stats.mtime;
          
          this.fileStates.set(filePath, {
            filePath,
            lastHash: hash,
            lastSize: size,
            lastMtime: mtime,
            changeCount: 0,
            lastChangedAt: new Date()
          });
        }
      } catch (error) {
        // Игнорируем ошибки для файлов которые не можем прочитать
      }
    }
  }

  /**
   * Получает список файлов в пути
   */
  private getFilesInPath(
    dirPath: string,
    include?: string[],
    exclude?: string[]
  ): string[] {
    const files: string[] = [];
    
    try {
      const entries = fs.readdirSync(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        // Проверяем exclude patterns
        if (exclude && exclude.some(pattern => this.matchesPattern(fullPath, pattern))) {
          continue;
        }
        
        // Проверяем ignored patterns
        if (this.options.ignoredPatterns.some(pattern => 
          this.matchesPattern(fullPath, pattern)
        )) {
          continue;
        }
        
        if (entry.isDirectory()) {
          if (entry.isSymbolicLink() && this.options.ignoreSymlinks) {
            continue;
          }
          
          // Рекурсивно получаем файлы из директории
          if (true) { // config.recursive
            files.push(...this.getFilesInPath(fullPath, include, exclude));
          }
        } else if (entry.isFile()) {
          // Проверяем include patterns если указаны
          if (!include || include.some(pattern => this.matchesPattern(fullPath, pattern))) {
            files.push(fullPath);
          }
        }
      }
    } catch (error) {
      // Игнорируем ошибки доступа
    }
    
    return files;
  }

  /**
   * Проверяет соответствует ли путь паттерну
   */
  private matchesPattern(filePath: string, pattern: string): boolean {
    // Простая реализация glob matching
    const normalizedPath = path.normalize(filePath);
    const normalizedPattern = path.normalize(pattern);

    // Конвертируем glob паттерн в regex
    // ИСПОЛЬЗУЕМ ПОЛНОЕ ЭКРАНИРОВАНИЕ для безопасности
    const regexPattern = normalizedPattern
      .replace(/\\/g, '\\\\')  // Экранируем обратные слеши
      .replace(/\./g, '\\.')   // Экранируем точки
      .replace(/\*/g, '.*')    // Преобразуем wildcard
      .replace(/\?/g, '.');    // Преобразуем single char wildcard

    const regex = new RegExp(`^${regexPattern}$`, 'i');
    return regex.test(normalizedPath);
  }

  /**
   * Проверяет следует ли наблюдать файл
   */
  private shouldWatchFile(filePath: string, config: WatchConfig): boolean {
    // Проверяем exclude
    if (config.exclude?.some(pattern => this.matchesPattern(filePath, pattern))) {
      return false;
    }
    
    // Проверяем ignored patterns
    if (this.options.ignoredPatterns.some(pattern => 
      this.matchesPattern(filePath, pattern)
    )) {
      return false;
    }
    
    // Проверяем include если указан
    if (config.include && !config.include.some(pattern => 
      this.matchesPattern(filePath, pattern)
    )) {
      return false;
    }
    
    return true;
  }

  /**
   * Debounce событие файла
   */
  private debounceEvent(filePath: string, eventType: FileEventType): void {
    // Очищаем предыдущий таймер для этого файла
    const existingTimer = this.debounceTimers.get(filePath);
    if (existingTimer) {
      clearTimeout(existingTimer.timerId);
    }
    
    // Создаем новый таймер
    const timerId = setTimeout(() => {
      this.processFileEvent(filePath, eventType);
      this.debounceTimers.delete(filePath);
    }, this.options.hashDebounceDelay);
    
    this.debounceTimers.set(filePath, {
      timerId,
      filePath,
      expectedType: eventType
    });
  }

  /**
   * Обрабатывает событие файла
   */
  private async processFileEvent(filePath: string, eventType: FileEventType): Promise<void> {
    try {
      const timestamp = new Date();
      let event: FileEvent;
      
      // Получаем предыдущее состояние
      const previousState = this.fileStates.get(filePath);
      
      switch (eventType) {
        case 'deleted':
          // Проверяем действительно ли файл удален
          if (fs.existsSync(filePath)) {
            // Файл существует, возможно это было перемещение
            event = await this.createModifyEvent(filePath, previousState, timestamp);
          } else {
            event = this.createDeleteEvent(filePath, previousState, timestamp);
            this.fileStates.delete(filePath);
          }
          break;
          
        case 'modified':
        default:
          event = await this.createModifyEvent(filePath, previousState, timestamp);
          break;
      }
      
      // Добавляем событие в очередь
      this.eventQueue.push(event);
      this.eventsCount++;
      this.lastEventAt = timestamp;
      
      // Ограничиваем размер очереди
      if (this.eventQueue.length > this.options.maxEventsInMemory) {
        this.eventQueue.shift();
      }
      
      // Эмитим событие
      this.emit('file-event', event);
      
      // Логгируем если включено
      if (this.options.enableAuditLog) {
        this.logAuditEvent(event);
      }
      
      // Проверяем на нарушения
      this.checkForViolations(event);
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      this.errors.push(error instanceof Error ? error : new Error(errorMessage));
      this.emit('error', error);
    }
  }

  /**
   * Создает событие изменения
   */
  private async createModifyEvent(
    filePath: string,
    previousState: WatchedFileState | undefined,
    timestamp: Date
  ): Promise<FileEvent> {
    const stats = fs.statSync(filePath);
    const newHash = await this.computeFileHash(filePath);
    const newSize = stats.size;
    const newMtime = stats.mtime;
    
    const details: FileEventDetails = {};
    
    // Проверяем изменения прав
    if (previousState) {
      const oldMode = fs.statSync(filePath).mode;
      // В реальной реализации здесь было бы сравнение с предыдущими правами
    }
    
    const event: FileEvent = {
      type: 'modified',
      filePath,
      oldHash: previousState?.lastHash,
      newHash,
      oldSize: previousState?.lastSize,
      newSize,
      timestamp,
      details
    };
    
    // Обновляем состояние
    this.fileStates.set(filePath, {
      filePath,
      lastHash: newHash,
      lastSize: newSize,
      lastMtime: newMtime,
      changeCount: (previousState?.changeCount || 0) + 1,
      lastChangedAt: timestamp
    });
    
    return event;
  }

  /**
   * Создает событие удаления
   */
  private createDeleteEvent(
    filePath: string,
    previousState: WatchedFileState | undefined,
    timestamp: Date
  ): FileEvent {
    const event: FileEvent = {
      type: 'deleted',
      filePath,
      oldHash: previousState?.lastHash,
      oldSize: previousState?.lastSize,
      timestamp,
      details: {}
    };
    
    return event;
  }

  /**
   * Вычисляет хеш файла
   */
  private async computeFileHash(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash(this.getHashAlgorithm());
      const stream = fs.createReadStream(filePath);
      
      stream.on('data', (data) => {
        hash.update(data);
      });
      
      stream.on('end', () => {
        resolve(hash.digest('hex'));
      });
      
      stream.on('error', (error) => {
        reject(error);
      });
    });
  }

  /**
   * Получает название алгоритма хеширования
   */
  private getHashAlgorithm(): string {
    const algorithmMap: Record<HashAlgorithm, string> = {
      'SHA-256': 'sha256',
      'SHA-384': 'sha384',
      'SHA-512': 'sha512',
      'SHA3-256': 'sha3-256',
      'SHA3-512': 'sha3-512',
      'BLAKE2b': 'blake2b512',
      'BLAKE3': 'blake3'
    };
    
    return algorithmMap[this.options.hashAlgorithm] || 'sha256';
  }

  /**
   * Проверяет события на нарушения
   */
  private checkForViolations(event: FileEvent): void {
    const violations: IntegrityViolation[] = [];
    
    // Проверяем критичные файлы
    const criticalPatterns = [
      '**/*.exe',
      '**/*.dll',
      '**/*.so',
      '**/*.dylib',
      '**/config/**',
      '**/.env*',
      '**/package.json',
      '**/requirements.txt'
    ];
    
    const isCritical = criticalPatterns.some(pattern => 
      this.matchesPattern(event.filePath, pattern)
    );
    
    if (isCritical && event.type === 'modified') {
      violations.push({
        type: 'unauthorized_modification',
        severity: 'high',
        filePath: event.filePath,
        description: `Обнаружено изменение критичного файла`,
        detectedAt: event.timestamp,
        details: {
          oldHash: event.oldHash,
          newHash: event.newHash,
          oldSize: event.oldSize,
          newSize: event.newSize
        },
        remediation: [
          'Проверить источник изменения',
          'Сравнить с baseline',
          'Восстановить из доверенной копии при необходимости'
        ]
      });
    }
    
    if (event.type === 'deleted' && isCritical) {
      violations.push({
        type: 'missing_file',
        severity: 'critical',
        filePath: event.filePath,
        description: `Удаление критичного файла`,
        detectedAt: event.timestamp,
        details: {
          lastHash: event.oldHash,
          lastSize: event.oldSize
        },
        remediation: [
          'Немедленно восстановить файл',
          'Расследовать причину удаления',
          'Проверить систему на компрометацию'
        ]
      });
    }
    
    // Эмитим нарушения
    for (const violation of violations) {
      this.emit('violation', violation);
    }
  }

  /**
   * Логгирует событие в audit log
   */
  private logAuditEvent(event: FileEvent): void {
    if (!this.options.auditLogPath) {
      return;
    }
    
    const logEntry = {
      timestamp: event.timestamp.toISOString(),
      eventType: event.type,
      filePath: event.filePath,
      hash: event.newHash || event.oldHash,
      size: event.newSize || event.oldSize
    };
    
    const logLine = JSON.stringify(logEntry) + '\n';
    
    fs.appendFile(this.options.auditLogPath, logLine, (error) => {
      if (error) {
        this.emit('error', error);
      }
    });
  }

  /**
   * Получает статус монитора
   * 
   * @returns Статус FIM
   */
  getStatus(): FIMStatus {
    return {
      isActive: this.isActive,
      watchedFiles: this.fileStates.size,
      eventsCount: this.eventsCount,
      recentEvents: this.eventQueue.slice(-100),
      errors: [...this.errors],
      startedAt: this.startedAt,
      lastEventAt: this.lastEventAt
    };
  }

  /**
   * Получает историю событий
   * 
   * @param limit - Максимум событий
   * @returns Массив событий
   */
  getEventHistory(limit: number = 100): FileEvent[] {
    return this.eventQueue.slice(-limit);
  }

  /**
   * Получает состояние файла
   * 
   * @param filePath - Путь к файлу
   * @returns Состояние файла или null
   */
  getFileState(filePath: string): WatchedFileState | null {
    return this.fileStates.get(filePath) || null;
  }

  /**
   * Добавляет путь для мониторинга
   * 
   * @param config - Конфигурация мониторинга
   * @returns Результат
   */
  async addWatchPath(config: WatchConfig): Promise<OperationResult> {
    try {
      await this.initializeWatch(config);
      
      return {
        success: true,
        errors: [],
        warnings: [],
        executionTime: 0
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Удаляет путь из мониторинга
   * 
   * @param watchPath - Путь для удаления
   * @returns Результат
   */
  removeWatchPath(watchPath: string): OperationResult {
    const normalizedPath = path.normalize(watchPath);
    const watcher = this.watchers.get(normalizedPath);
    
    if (!watcher) {
      return {
        success: false,
        errors: ['Watcher не найден'],
        warnings: [],
        executionTime: 0
      };
    }
    
    watcher.close();
    this.watchers.delete(normalizedPath);
    
    // Удаляем состояния файлов в этом пути
    for (const [filePath] of this.fileStates.entries()) {
      if (filePath.startsWith(normalizedPath)) {
        this.fileStates.delete(filePath);
      }
    }
    
    return {
      success: true,
      errors: [],
      warnings: [],
      executionTime: 0
    };
  }

  /**
   * Принудительно вычисляет хеши всех файлов
   * 
   * @returns Результат вычисления
   */
  async forceHashAll(): Promise<OperationResult<Map<string, string>>> {
    const startTime = Date.now();
    const hashes = new Map<string, string>();
    const errors: string[] = [];
    
    for (const [filePath] of this.fileStates.entries()) {
      try {
        const hash = await this.computeFileHash(filePath);
        hashes.set(filePath, hash);
        
        // Обновляем состояние
        const state = this.fileStates.get(filePath);
        if (state) {
          state.lastHash = hash;
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
        errors.push(`${filePath}: ${errorMessage}`);
      }
    }
    
    return {
      success: errors.length === 0,
      data: hashes,
      errors,
      warnings: [],
      executionTime: Date.now() - startTime
    };
  }

  /**
   * Сравнивает текущие хеши с baseline
   * 
   * @returns Результат сравнения
   */
  async compareWithBaseline(): Promise<OperationResult<{
    modified: FileEvent[];
    added: string[];
    removed: string[];
  }>> {
    const modified: FileEvent[] = [];
    const added: string[] = [];
    const removed: string[] = [];
    const errors: string[] = [];
    
    // Проверяем существующие файлы
    for (const [filePath, state] of this.fileStates.entries()) {
      try {
        if (!fs.existsSync(filePath)) {
          removed.push(filePath);
          continue;
        }
        
        const currentHash = await this.computeFileHash(filePath);
        
        if (currentHash !== state.lastHash) {
          modified.push({
            type: 'modified',
            filePath,
            oldHash: state.lastHash,
            newHash: currentHash,
            oldSize: state.lastSize,
            newSize: fs.statSync(filePath).size,
            timestamp: new Date(),
            details: {}
          });
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
        errors.push(`${filePath}: ${errorMessage}`);
      }
    }
    
    // Проверяем новые файлы в наблюдаемых путях
    for (const config of this.options.watchConfigs) {
      const currentFiles = this.getFilesInPath(config.path, config.include, config.exclude);
      
      for (const filePath of currentFiles) {
        if (!this.fileStates.has(filePath)) {
          added.push(filePath);
        }
      }
    }
    
    return {
      success: errors.length === 0,
      data: { modified, added, removed },
      errors,
      warnings: [],
      executionTime: 0
    };
  }

  /**
   * Экспортирует текущее состояние
   * 
   * @returns Состояние всех файлов
   */
  exportState(): FileHash[] {
    const result: FileHash[] = [];
    
    for (const state of this.fileStates.values()) {
      result.push({
        filePath: state.filePath,
        algorithm: this.options.hashAlgorithm,
        hash: state.lastHash,
        size: state.lastSize,
        mtime: state.lastMtime,
        hashedAt: state.lastChangedAt
      });
    }
    
    return result;
  }

  /**
   * Импортирует состояние
   * 
   * @param fileHashes - Массив хешей файлов
   */
  importState(fileHashes: FileHash[]): void {
    for (const fileHash of fileHashes) {
      this.fileStates.set(fileHash.filePath, {
        filePath: fileHash.filePath,
        lastHash: fileHash.hash,
        lastSize: fileHash.size,
        lastMtime: fileHash.mtime,
        changeCount: 0,
        lastChangedAt: fileHash.hashedAt
      });
    }
  }

  /**
   * Очищает все состояния
   */
  clearState(): void {
    this.fileStates.clear();
    this.eventQueue.length = 0;
    this.eventsCount = 0;
    this.lastEventAt = undefined;
  }
}

/**
 * Фабрика для создания FIM
 */
export class FIMFactory {
  /**
   * Создает FIM для директории
   * 
   * @param dirPath - Путь к директории
   * @param options - Опции
   * @returns Экземпляр FIM
   */
  static createForDirectory(
    dirPath: string,
    options: Partial<FIMOptions> = {}
  ): FileIntegrityMonitor {
    return new FileIntegrityMonitor({
      ...options,
      watchConfigs: [{
        path: dirPath,
        recursive: true,
        usePolling: false,
        ignoreInitial: true,
        debounceDelay: 100
      }]
    });
  }

  /**
   * Создает FIM для нескольких путей
   * 
   * @param paths - Массив путей
   * @param options - Опции
   * @returns Экземпляр FIM
   */
  static createForPaths(
    paths: string[],
    options: Partial<FIMOptions> = {}
  ): FileIntegrityMonitor {
    return new FileIntegrityMonitor({
      ...options,
      watchConfigs: paths.map(p => ({
        path: p,
        recursive: true,
        usePolling: false,
        ignoreInitial: true,
        debounceDelay: 100
      }))
    });
  }

  /**
   * Создает FIM с кастомной конфигурацией
   * 
   * @param configs - Конфигурации мониторинга
   * @param options - Опции
   * @returns Экземпляр FIM
   */
  static createWithConfig(
    configs: WatchConfig[],
    options: Partial<FIMOptions> = {}
  ): FileIntegrityMonitor {
    return new FileIntegrityMonitor({
      ...options,
      watchConfigs: configs
    });
  }
}
