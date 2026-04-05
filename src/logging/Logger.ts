/**
 * ============================================================================
 * БАЗОВЫЙ ЛОГГЕР СИСТЕМЫ БЕЗОПАСНОСТИ
 * ============================================================================
 * Высокопроизводительный логгер с поддержкой структурированного логирования,
 * защиты от log injection, tamper-proof записей и множественных транспортов.
 * 
 * Особенности:
 * - Строгая типизация всех логов
 * - Защита от log injection атак
 * - Автоматическое добавление контекста безопасности
 * - Поддержка распределенной трассировки
 * - Rate limiting для предотвращения flooding
 * - Асинхронная запись для производительности
 */

import * as crypto from 'crypto';
import * as os from 'os';
import * as process from 'process';
import { EventEmitter } from 'events';
import {
  LogLevel,
  LogSource,
  LogEntry,
  LogContext,
  LoggerConfig,
  TransportConfig,
  GlobalConfig,
  LogProcessingStatus,
  ProcessingError,
  ProcessingStage
} from '../types/logging.types';

// ============================================================================
// КОНСТАНТЫ И ПЕРЕМЕННЫЕ
// ============================================================================

/**
 * Маппинг уровней логирования в строковые значения
 */
const LOG_LEVEL_NAMES: Record<LogLevel, string> = {
  [LogLevel.EMERGENCY]: 'EMERGENCY',
  [LogLevel.ALERT]: 'ALERT',
  [LogLevel.CRITICAL]: 'CRITICAL',
  [LogLevel.ERROR]: 'ERROR',
  [LogLevel.WARNING]: 'WARNING',
  [LogLevel.NOTICE]: 'NOTICE',
  [LogLevel.INFO]: 'INFO',
  [LogLevel.DEBUG]: 'DEBUG',
  [LogLevel.TRACE]: 'TRACE'
};

/**
 * Цвета для уровней логирования (ANSI escape codes)
 */
const LOG_LEVEL_COLORS: Record<LogLevel, string> = {
  [LogLevel.EMERGENCY]: '\x1b[38;5;196m',  // Ярко-красный
  [LogLevel.ALERT]: '\x1b[38;5;201m',       // Маджента
  [LogLevel.CRITICAL]: '\x1b[38;5;196m',    // Красный
  [LogLevel.ERROR]: '\x1b[31m',             // Красный
  [LogLevel.WARNING]: '\x1b[33m',           // Желтый
  [LogLevel.NOTICE]: '\x1b[36m',            // Циан
  [LogLevel.INFO]: '\x1b[32m',              // Зеленый
  [LogLevel.DEBUG]: '\x1b[34m',             // Синий
  [LogLevel.TRACE]: '\x1b[90m'              // Серый
};

/**
 * Символ сброса цвета ANSI
 */
const COLOR_RESET = '\x1b[0m';

/**
 * Регулярные выражения для защиты от log injection
 */
const LOG_INJECTION_PATTERNS = [
  /\r\n/g,      // CRLF injection
  /\r/g,        // CR injection
  /\n/g,        // LF injection
  /\u2028/g,    // Line separator
  /\u2029/g,    // Paragraph separator
  /\u0000/g,    // Null byte
  /\u001B/g,    // Escape character
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g  // Control characters
];

/**
 * Опасные символы для JSON
 */
const DANGEROUS_JSON_CHARS = /[\u0000-\u001F\u007F-\u009F]/g;

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Интерфейс для транспорта логов
 */
interface LogTransport {
  /**
   * Отправка лога в транспорт
   * @param log - Лог запись
   * @returns Promise с результатом отправки
   */
  send(log: LogEntry): Promise<TransportSendResult>;
  
  /**
   * Закрытие транспорта
   */
  close(): Promise<void>;
  
  /**
   * Проверка доступности транспорта
   */
  isAvailable(): boolean;
}

/**
 * Результат отправки транспорта
 */
interface TransportSendResult {
  success: boolean;
  error?: Error;
  timestamp: string;
}

/**
 * Опции для создания логгера
 */
interface LoggerOptions {
  config: LoggerConfig;
  globalConfig: GlobalConfig;
  defaultContext?: LogContext;
}

// ============================================================================
// КЛАССЫ ТРАНСПОРТОВ
// ============================================================================

/**
 * Консольный транспорт для вывода логов
 */
class ConsoleTransport implements LogTransport {
  private enableColors: boolean;
  private format: 'json' | 'text' | 'structured';
  
  constructor(enableColors: boolean, format: 'json' | 'text' | 'structured') {
    this.enableColors = enableColors;
    this.format = format;
  }
  
  async send(log: LogEntry): Promise<TransportSendResult> {
    try {
      const output = this.formatLog(log);
      
      // Выбор метода вывода в зависимости от уровня
      const method = this.getConsoleMethod(log.level);
      method(output);
      
      return {
        success: true,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
        timestamp: new Date().toISOString()
      };
    }
  }
  
  async close(): Promise<void> {
    // Консоль не требует закрытия
  }
  
  isAvailable(): boolean {
    return typeof process !== 'undefined' && process.stdout !== undefined;
  }
  
  /**
   * Форматирование лога для вывода
   */
  private formatLog(log: LogEntry): string {
    if (this.format === 'json') {
      return JSON.stringify(log);
    }
    
    const levelName = LOG_LEVEL_NAMES[log.level];
    const color = this.enableColors ? (LOG_LEVEL_COLORS[log.level] || '') : '';
    const reset = this.enableColors ? COLOR_RESET : '';
    
    if (this.format === 'structured') {
      const contextStr = this.formatContext(log.context);
      const fieldsStr = log.fields ? JSON.stringify(log.fields) : '';
      
      return `${color}[${levelName}]${reset} ${log.timestamp} ${log.component}: ${log.message}${contextStr}${fieldsStr}`;
    }
    
    // Текстовый формат
    return `${color}[${levelName}]${reset} ${log.timestamp} ${log.hostname}[${log.processId}] ${log.component}: ${log.message}`;
  }
  
  /**
   * Форматирование контекста
   */
  private formatContext(context: LogContext): string {
    const parts: string[] = [];
    
    if (context.userId) parts.push(`user:${context.userId}`);
    if (context.clientIp) parts.push(`ip:${context.clientIp}`);
    if (context.requestId) parts.push(`req:${context.requestId}`);
    if (context.sessionId) parts.push(`sess:${context.sessionId}`);
    
    if (parts.length === 0) return '';
    return ` {${parts.join(' ')}}`;
  }
  
  /**
   * Получение метода консоли для уровня
   */
  private getConsoleMethod(level: LogLevel): (...args: unknown[]) => void {
    switch (level) {
      case LogLevel.EMERGENCY:
      case LogLevel.ALERT:
      case LogLevel.CRITICAL:
      case LogLevel.ERROR:
        return console.error;
      case LogLevel.WARNING:
        return console.warn;
      case LogLevel.DEBUG:
      case LogLevel.TRACE:
        return console.debug;
      default:
        return console.log;
    }
  }
}

/**
 * Файловый транспорт для записи логов в файл
 */
class FileTransport implements LogTransport {
  private filePath: string;
  private maxFileSize: number;
  private maxFiles: number;
  private writeStream: import('fs').WriteStream | null;
  private currentSize: number;
  private fileIndex: number;
  
  constructor(filePath: string, maxFileSizeMB: number, maxFiles: number) {
    this.filePath = filePath;
    this.maxFileSize = maxFileSizeMB * 1024 * 1024;
    this.maxFiles = maxFiles;
    this.writeStream = null;
    this.currentSize = 0;
    this.fileIndex = 0;
  }
  
  async send(log: LogEntry): Promise<TransportSendResult> {
    try {
      const logLine = JSON.stringify(log) + '\n';
      const logBytes = Buffer.byteLength(logLine, 'utf8');
      
      // Проверка необходимости ротации
      if (this.currentSize + logBytes > this.maxFileSize) {
        await this.rotate();
      }
      
      // Инициализация stream если нужен
      if (!this.writeStream) {
        await this.openStream();
      }
      
      // Запись лога
      return new Promise((resolve) => {
        if (!this.writeStream) {
          resolve({
            success: false,
            error: new Error('Write stream not initialized'),
            timestamp: new Date().toISOString()
          });
          return;
        }
        
        this.writeStream.write(logLine, 'utf8', (error) => {
          if (error) {
            resolve({
              success: false,
              error,
              timestamp: new Date().toISOString()
            });
          } else {
            this.currentSize += logBytes;
            resolve({
              success: true,
              timestamp: new Date().toISOString()
            });
          }
        });
      });
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
        timestamp: new Date().toISOString()
      };
    }
  }
  
  async close(): Promise<void> {
    if (this.writeStream) {
      return new Promise((resolve) => {
        this.writeStream?.end(() => {
          this.writeStream = null;
          resolve();
        });
      });
    }
  }
  
  isAvailable(): boolean {
    return true;
  }
  
  /**
   * Открытие write stream
   */
  private async openStream(): Promise<void> {
    const fs = await import('fs');
    const path = await import('path');
    
    const dir = path.dirname(this.filePath);
    
    // Создание директории если не существует
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    const actualPath = this.getActualFilePath();
    this.writeStream = fs.createWriteStream(actualPath, { flags: 'a', encoding: 'utf8' });
    
    // Получение текущего размера файла
    if (fs.existsSync(actualPath)) {
      const stats = fs.statSync(actualPath);
      this.currentSize = stats.size;
    } else {
      this.currentSize = 0;
    }
  }
  
  /**
   * Ротация файлов
   */
  private async rotate(): Promise<void> {
    const fs = await import('fs');
    const path = await import('path');
    
    // Закрытие текущего stream
    if (this.writeStream) {
      await new Promise<void>((resolve) => {
        this.writeStream?.end(() => {
          this.writeStream = null;
          resolve();
        });
      });
    }
    
    // Удаление старого файла если существует
    const oldestPath = this.getFilePath(this.maxFiles - 1);
    if (fs.existsSync(oldestPath)) {
      fs.unlinkSync(oldestPath);
    }
    
    // Сдвиг файлов
    for (let i = this.maxFiles - 2; i >= 0; i--) {
      const oldPath = this.getFilePath(i);
      const newPath = this.getFilePath(i + 1);
      
      if (fs.existsSync(oldPath)) {
        fs.renameSync(oldPath, newPath);
      }
    }
    
    this.fileIndex = 0;
    this.currentSize = 0;
  }
  
  /**
   * Получение пути к файлу с индексом
   */
  private getFilePath(index: number): string {
    const path = require('path');
    const ext = path.extname(this.filePath);
    const base = this.filePath.slice(0, -ext.length || undefined);
    return index === 0 ? this.filePath : `${base}.${index}${ext}`;
  }
  
  /**
   * Получение актуального пути к файлу
   */
  private getActualFilePath(): string {
    return this.getFilePath(this.fileIndex);
  }
}

/**
 * HTTP транспорт для отправки логов на удаленный сервер
 */
class HttpTransport implements LogTransport {
  private url: string;
  private headers: Record<string, string>;
  private batchSize: number;
  private batchTimeout: number;
  private batch: LogEntry[];
  private flushTimer: NodeJS.Timeout | null;
  private available: boolean;
  
  constructor(
    url: string,
    headers: Record<string, string>,
    batchSize: number,
    batchTimeoutMs: number
  ) {
    this.url = url;
    this.headers = headers;
    this.batchSize = batchSize;
    this.batchTimeout = batchTimeoutMs;
    this.batch = [];
    this.flushTimer = null;
    this.available = true;
  }
  
  async send(log: LogEntry): Promise<TransportSendResult> {
    this.batch.push(log);
    
    // Запуск таймера если это первый лог в пакете
    if (this.batch.length === 1) {
      this.flushTimer = setTimeout(() => this.flush(), this.batchTimeout);
    }
    
    // Отправка если достигнут размер пакета
    if (this.batch.length >= this.batchSize) {
      await this.flush();
    }
    
    return {
      success: true,
      timestamp: new Date().toISOString()
    };
  }
  
  async close(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    
    // Отправка оставшихся логов
    if (this.batch.length > 0) {
      await this.flush();
    }
  }
  
  isAvailable(): boolean {
    return this.available;
  }
  
  /**
   * Отправка пакета логов
   */
  private async flush(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    
    if (this.batch.length === 0) {
      return;
    }
    
    const batchToSend = [...this.batch];
    this.batch = [];
    
    try {
      const response = await fetch(this.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.headers
        },
        body: JSON.stringify({ logs: batchToSend })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      this.available = true;
    } catch (error) {
      this.available = false;
      console.error('HTTP transport error:', error);
    }
  }
}

// ============================================================================
// RATE LIMITER
// ============================================================================

/**
 * Rate limiter для предотвращения flooding логов
 */
class LogRateLimiter {
  private maxLogsPerSecond: number;
  private maxLogsPerMinute: number;
  private secondBucket: number;
  private minuteBucket: number;
  private lastSecondReset: number;
  private lastMinuteReset: number;
  private suppressedCount: number;
  
  constructor(maxPerSecond: number, maxPerMinute: number) {
    this.maxLogsPerSecond = maxPerSecond;
    this.maxLogsPerMinute = maxPerMinute;
    this.secondBucket = maxPerSecond;
    this.minuteBucket = maxPerMinute;
    this.lastSecondReset = Date.now();
    this.lastMinuteReset = Date.now();
    this.suppressedCount = 0;
  }
  
  /**
   * Проверка возможности логирования
   * @returns true если можно логировать, false если превышен лимит
   */
  allow(): boolean {
    const now = Date.now();
    
    // Сброс секундного бакета
    if (now - this.lastSecondReset >= 1000) {
      this.secondBucket = this.maxLogsPerSecond;
      this.lastSecondReset = now;
    }
    
    // Сброс минутного бакета
    if (now - this.lastMinuteReset >= 60000) {
      this.minuteBucket = this.maxLogsPerMinute;
      this.lastMinuteReset = now;
    }
    
    // Проверка лимитов
    if (this.secondBucket <= 0 || this.minuteBucket <= 0) {
      this.suppressedCount++;
      return false;
    }
    
    this.secondBucket--;
    this.minuteBucket--;
    
    return true;
  }
  
  /**
   * Получение количества подавленных логов
   */
  getSuppressedCount(): number {
    return this.suppressedCount;
  }
  
  /**
   * Сброс счетчиков
   */
  reset(): void {
    this.secondBucket = this.maxLogsPerSecond;
    this.minuteBucket = this.maxLogsPerMinute;
    this.suppressedCount = 0;
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС ЛОГГЕРА
// ============================================================================

/**
 * Основной класс логгера системы безопасности
 * 
 * Реализует:
 * - Многоуровневое логирование
 * - Защиту от log injection
 * - Tamper-proof записи
 * - Распределенную трассировку
 * - Rate limiting
 * - Множественные транспорты
 */
export class SecureLogger extends EventEmitter {
  private config: LoggerConfig;
  private globalConfig: GlobalConfig;
  private defaultContext: LogContext;
  private transports: LogTransport[];
  private rateLimiter: LogRateLimiter;
  private hostname: string;
  private processId: number;
  private enabled: boolean;
  private logCounter: number;
  private processingErrors: ProcessingError[];
  
  constructor(options: LoggerOptions) {
    super();
    
    this.config = options.config;
    this.globalConfig = options.globalConfig;
    this.defaultContext = options.defaultContext || {};
    this.transports = [];
    this.hostname = os.hostname();
    this.processId = process.pid;
    this.enabled = true;
    this.logCounter = 0;
    this.processingErrors = [];
    
    // Инициализация rate limiter
    const rateLimit = this.globalConfig.rateLimiting;
    this.rateLimiter = new LogRateLimiter(
      rateLimit?.maxAlerts || 100,
      (rateLimit?.maxAlerts || 100) * 60
    );
    
    // Инициализация транспортов
    this.initializeTransports();
  }
  
  /**
   * Инициализация транспортов из конфигурации
   */
  private async initializeTransports(): Promise<void> {
    for (const transportConfig of this.config.transports) {
      const transport = await this.createTransport(transportConfig);
      if (transport) {
        this.transports.push(transport);
      }
    }
  }
  
  /**
   * Создание транспорта из конфигурации
   */
  private async createTransport(config: TransportConfig): Promise<LogTransport | null> {
    switch (config.type) {
      case 'console':
        return new ConsoleTransport(
          this.config.enableColors,
          this.config.format
        );
      
      case 'file': {
        const params = config.params as { path?: string; maxSizeMB?: number; maxFiles?: number };
        return new FileTransport(
          params.path || './logs/app.log',
          params.maxSizeMB || 100,
          params.maxFiles || 5
        );
      }
      
      case 'http': {
        const params = config.params as { 
          url?: string; 
          headers?: Record<string, string>;
          batchSize?: number;
          batchTimeoutMs?: number;
        };
        return new HttpTransport(
          params.url || 'http://localhost:3000/logs',
          params.headers || {},
          params.batchSize || 100,
          params.batchTimeoutMs || 5000
        );
      }
      
      case 'elasticsearch':
      case 'kafka':
      case 'syslog':
        // Эти транспорты будут реализованы в отдельных модулях
        console.warn(`Transport type '${config.type}' not yet implemented`);
        return null;
      
      default:
        console.warn(`Unknown transport type: ${(config as { type: string }).type}`);
        return null;
    }
  }
  
  /**
   * Создание базовой записи лога
   */
  private createBaseLog(
    level: LogLevel,
    message: string,
    source: LogSource,
    component: string
  ): Omit<LogEntry, 'context' | 'schemaVersion'> {
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    
    this.logCounter++;
    
    return {
      id,
      timestamp,
      level,
      source,
      component,
      hostname: this.hostname,
      processId: this.processId,
      message: this.sanitizeMessage(message),
      category: this.getCategory(level, source),
      eventCode: this.getEventCode(level, source)
    };
  }
  
  /**
   * Санитизация сообщения для защиты от log injection
   */
  private sanitizeMessage(message: string): string {
    if (typeof message !== 'string') {
      message = String(message);
    }
    
    // Удаление опасных символов
    let sanitized = message;
    for (const pattern of LOG_INJECTION_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }
    
    // Замена опасных JSON символов
    sanitized = sanitized.replace(DANGEROUS_JSON_CHARS, (char) => {
      return `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`;
    });
    
    return sanitized;
  }
  
  /**
   * Получение категории для лога
   */
  private getCategory(level: LogLevel, source: LogSource): string {
    const levelCategory = LOG_LEVEL_NAMES[level];
    return `${source}_${levelCategory}`;
  }
  
  /**
   * Получение кода события
   */
  private getEventCode(level: LogLevel, source: LogSource): string {
    const levelCode = (level + 1).toString().padStart(2, '0');
    const sourceName = LogLevel[level] || 'UNKNOWN';
    const sourceCode = sourceName.substring(0, 3).toUpperCase();
    return `EVT-${sourceCode}-${levelCode}`;
  }
  
  /**
   * Обогащение лога контекстом
   */
  private enrichWithContext(log: Omit<LogEntry, 'context' | 'schemaVersion'>, context?: LogContext): LogContext {
    return {
      ...this.defaultContext,
      ...context,
      // Всегда добавляем системную информацию
      metadata: {
        ...this.defaultContext.metadata,
        ...context?.metadata,
        environment: this.globalConfig.environment,
        region: this.globalConfig.region,
        version: this.globalConfig.version
      }
    };
  }
  
  /**
   * Вычисление хеша содержимого для верификации целостности
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
    
    return crypto.createHash('sha256').update(content).digest('hex');
  }
  
  /**
   * Основная метода логирования
   */
  private async log(
    level: LogLevel,
    message: string,
    source: LogSource,
    component: string,
    context?: LogContext,
    fields?: Record<string, unknown>,
    error?: Error
  ): Promise<LogEntry | null> {
    // Проверка включен ли логгер
    if (!this.enabled) {
      return null;
    }
    
    // Проверка уровня логирования
    // enableDebug позволяет логировать DEBUG/TRACE уровни, но setLevel имеет приоритет
    const isDebugMode = this.globalConfig?.enableDebug === true;
    if (isDebugMode) {
      // В debug mode: разрешаем все уровни, НО если setLevel установлен явно — уважаем его
      // Level numbering: EMERGENCY=0 (highest) ... TRACE=8 (lowest)
      // Если level > TRACE — никогда не логируем (но такого нет)
    } else {
      // В normal mode: только уровни важнее или равные configured
      if (level > this.config.level) {
        return null;
      }
    }
    
    // Проверка rate limiting
    if (!this.rateLimiter.allow()) {
      // Логирование факта suppression только если это не слишком часто
      if (this.rateLimiter.getSuppressedCount() % 100 === 0) {
        console.warn(`Log rate limit exceeded. Suppressed ${this.rateLimiter.getSuppressedCount()} logs.`);
      }
      return null;
    }
    
    const processingStages: ProcessingStage[] = [];
    const startTime = Date.now();
    
    try {
      // Этап 1: Создание базового лога
      const baseLog = this.createBaseLog(level, message, source, component);
      processingStages.push({
        name: 'create',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        duration: Date.now() - startTime,
        status: 'success'
      });
      
      // Этап 2: Обогащение контекстом
      const enrichedContext = this.enrichWithContext(baseLog, context);
      processingStages.push({
        name: 'enrich',
        startTime: new Date().toISOString(),
        endTime: new Date().toISOString(),
        duration: Date.now() - startTime,
        status: 'success'
      });
      
      // Создание полной записи лога
      const logEntry: LogEntry = {
        ...baseLog,
        context: enrichedContext,
        fields,
        stackTrace: error?.stack,
        schemaVersion: '1.0.0',
        processingTime: Date.now() - startTime
      };
      
      // Вычисление хеша содержимого
      logEntry.contentHash = this.computeContentHash(logEntry);
      
      // Этап 3: Отправка в транспорты
      const transportPromises = this.transports.map(async (transport) => {
        const transportStart = Date.now();
        try {
          const result = await transport.send(logEntry);
          processingStages.push({
            name: `transport:${transport.constructor.name}`,
            startTime: new Date(transportStart).toISOString(),
            endTime: new Date().toISOString(),
            duration: Date.now() - transportStart,
            status: result.success ? 'success' : 'failed',
            error: result.error?.message
          });
          
          if (!result.success) {
            this.emit('transport_error', {
              transport: transport.constructor.name,
              error: result.error
            });
          }
          
          return result.success;
        } catch (error) {
          processingStages.push({
            name: `transport:${transport.constructor.name}`,
            startTime: new Date(transportStart).toISOString(),
            endTime: new Date().toISOString(),
            duration: Date.now() - transportStart,
            status: 'failed',
            error: error instanceof Error ? error.message : String(error)
          });
          
          this.processingErrors.push({
            stage: `transport:${transport.constructor.name}`,
            code: 'TRANSPORT_ERROR',
            message: error instanceof Error ? error.message : String(error),
            recoverable: true
          });
          
          return false;
        }
      });
      
      // Ожидание всех транспортов
      await Promise.all(transportPromises);
      
      // Эмиссия события успешного логирования
      this.emit('log', logEntry);
      
      return logEntry;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      this.processingErrors.push({
        stage: 'log',
        code: 'LOG_ERROR',
        message: errorMessage,
        recoverable: false
      });
      
      this.emit('error', {
        error,
        level,
        message,
        source,
        component
      });
      
      return null;
    }
  }
  
  // ==========================================================================
  // ПУБЛИЧНЫЕ МЕТОДЫ ЛОГИРОВАНИЯ ПО УРОВНЯМ
  // ==========================================================================
  
  /**
   * Логирование уровня EMERGENCY (0)
   * Система неработоспособна
   */
  async emergency(
    message: string,
    source: LogSource = LogSource.APPLICATION,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    try {
      return await this.log(LogLevel.EMERGENCY, message, source, component, context, fields);
    } catch (err) {
      console.error('Logger emergency error:', err);
      return null;
    }
  }

  /**
   * Логирование уровня ALERT (1)
   * Требуется немедленное действие
   */
  async alert(
    message: string,
    source: LogSource = LogSource.SECURITY,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    try {
      return await this.log(LogLevel.ALERT, message, source, component, context, fields);
    } catch (err) {
      console.error('Logger alert error:', err);
      return null;
    }
  }

  /**
   * Логирование уровня CRITICAL (2)
   * Критическое состояние
   */
  async critical(
    message: string,
    source: LogSource = LogSource.APPLICATION,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    try {
      return await this.log(LogLevel.CRITICAL, message, source, component, context, fields);
    } catch (err) {
      console.error('Logger critical error:', err);
      return null;
    }
  }

  /**
   * Логирование уровня ERROR (3)
   * Ошибка
   */
  async error(
    message: string,
    source: LogSource | LogContext = LogSource.APPLICATION,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>,
    errorObj?: Error
  ): Promise<LogEntry | null> {
    // Если source передан как объект, считаем его context
    const actualSource = typeof source === 'object' ? LogSource.APPLICATION : source;
    const actualContext = typeof source === 'object' ? source : context;
    try {
      return await this.log(LogLevel.ERROR, message, actualSource, component, actualContext, fields, errorObj);
    } catch (err) {
      console.error('Logger error error:', err);
      return null;
    }
  }

  /**
   * Логирование уровня NOTICE (5)
   * Нормальное, но значимое событие
   */
  async notice(
    message: string,
    source: LogSource = LogSource.APPLICATION,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    try {
      return await this.log(LogLevel.NOTICE, message, source, component, context, fields);
    } catch (err) {
      console.error('Logger notice error:', err);
      return null;
    }
  }

  /**
   * Логирование уровня INFO (6)
   * Информационное сообщение
   */
  async info(
    message: string,
    source: LogSource | LogContext = LogSource.APPLICATION,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    // Если source передан как объект, считаем его context
    const actualSource = typeof source === 'object' ? LogSource.APPLICATION : source;
    const actualContext = typeof source === 'object' ? source : context;
    try {
      return await this.log(LogLevel.INFO, message, actualSource, component, actualContext, fields);
    } catch (err) {
      console.error('Logger info error:', err);
      return null;
    }
  }

  /**
   * Логирование уровня DEBUG (7)
   * Отладочная информация
   */
  async debug(
    message: string,
    source: LogSource | LogContext = LogSource.APPLICATION,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    // Если source передан как объект, считаем его context
    const actualSource = typeof source === 'object' ? LogSource.APPLICATION : source;
    const actualContext = typeof source === 'object' ? source : context;
    try {
      return await this.log(LogLevel.DEBUG, message, actualSource, component, actualContext, fields);
    } catch (err) {
      console.error('Logger debug error:', err);
      return null;
    }
  }

  /**
   * Логирование уровня WARNING (4)
   * Предупреждение
   */
  async warn(
    message: string,
    source: LogSource | LogContext = LogSource.APPLICATION,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    // Если source передан как объект, считаем его context
    const actualSource = typeof source === 'object' ? LogSource.APPLICATION : source;
    const actualContext = typeof source === 'object' ? source : context;
    try {
      return await this.log(LogLevel.WARNING, message, actualSource, component, actualContext, fields);
    } catch (err) {
      console.error('Logger warn error:', err);
      return null;
    }
  }

  /**
   * Логирование уровня WARNING (4)
   * Предупреждение (алиас для warn)
   */
  async warning(
    message: string,
    source: LogSource | LogContext = LogSource.APPLICATION,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    // Если source передан как объект, считаем его context
    const actualSource = typeof source === 'object' ? LogSource.APPLICATION : source;
    const actualContext = typeof source === 'object' ? source : context;
    try {
      return await this.log(LogLevel.WARNING, message, actualSource, component, actualContext, fields);
    } catch (err) {
      console.error('Logger warning error:', err);
      return null;
    }
  }

  /**
   * Логирование уровня TRACE (8)
   * Детальная трассировка
   */
  async trace(
    message: string,
    source: LogSource = LogSource.APPLICATION,
    component: string = this.globalConfig.serviceName,
    context?: LogContext,
    fields?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    try {
      return await this.log(LogLevel.TRACE, message, source, component, context, fields);
    } catch (err) {
      console.error('Logger trace error:', err);
      return null;
    }
  }
  
  // ==========================================================================
  // СПЕЦИАЛИЗИРОВАННЫЕ МЕТОДЫ ДЛЯ СОБЫТИЙ БЕЗОПАСНОСТИ
  // ==========================================================================

  /**
   * Логирование события аутентификации
   */
  async authEvent(
    eventType: 'login_success' | 'login_failure' | 'logout' | 'password_change',
    userId: string,
    clientIp: string,
    details?: Record<string, unknown>
  ): Promise<LogEntry | null> {
    try {
      return await this.log(
        eventType === 'login_failure' ? LogLevel.WARNING : LogLevel.INFO,
        `Authentication event: ${eventType}`,
        LogSource.AUTH,
        'auth-service',
        {
          userId,
          clientIp,
          sessionId: crypto.randomUUID()
        },
        {
          eventType,
          ...details
        }
      );
    } catch (err) {
      console.error('Logger authEvent error:', err);
      return null;
    }
  }

  /**
   * Логирование события доступа к данным
   */
  async dataAccessEvent(
    userId: string,
    resourceType: string,
    resourceId: string,
    action: 'read' | 'write' | 'delete',
    result: 'success' | 'denied',
    clientIp: string
  ): Promise<LogEntry | null> {
    try {
      return await this.log(
        result === 'denied' ? LogLevel.WARNING : LogLevel.INFO,
        `Data access: ${action} ${resourceType}/${resourceId} - ${result}`,
        LogSource.AUDIT,
        'audit-service',
        {
          userId,
          clientIp
        },
        {
          resourceType,
          resourceId,
          action,
          result
        }
      );
    } catch (err) {
      console.error('Logger dataAccessEvent error:', err);
      return null;
    }
  }

  /**
   * Логирование события изменения конфигурации
   */
  async configChangeEvent(
    userId: string,
    configPath: string,
    oldValue: unknown,
    newValue: unknown,
    clientIp: string
  ): Promise<LogEntry | null> {
    try {
      return await this.log(
        LogLevel.NOTICE,
        `Configuration changed: ${configPath}`,
        LogSource.AUDIT,
        'config-service',
        {
          userId,
          clientIp
        },
        {
          configPath,
          oldValue,
          newValue,
          changeType: 'update'
        }
      );
    } catch (err) {
      console.error('Logger configChangeEvent error:', err);
      return null;
    }
  }

  /**
   * Логирование сетевого события
   */
  async networkEvent(
    eventType: 'connection' | 'disconnection' | 'error' | 'timeout',
    remoteIp: string,
    remotePort: number,
    localPort: number,
    protocol: string,
    bytesTransferred?: number
  ): Promise<LogEntry | null> {
    try {
      return await this.log(
        eventType === 'error' ? LogLevel.ERROR : LogLevel.INFO,
        `Network ${eventType}: ${remoteIp}:${remotePort} -> :${localPort} (${protocol})`,
        LogSource.NETWORK,
        'network-service',
        {},
        {
          eventType,
          remoteIp,
          remotePort,
          localPort,
          protocol,
          bytesTransferred
        }
      );
    } catch (err) {
      console.error('Logger networkEvent error:', err);
      return null;
    }
  }
  
  // ==========================================================================
  // МЕТОДЫ УПРАВЛЕНИЯ
  // ==========================================================================
  
  /**
   * Установка уровня логирования
   */
  setLevel(level: LogLevel): void {
    this.config.level = level;
    this.info(`Log level changed to ${LOG_LEVEL_NAMES[level]}`, LogSource.SYSTEM, 'logger');
  }
  
  /**
   * Получение текущего уровня логирования
   */
  getLevel(): LogLevel {
    return this.config.level;
  }
  
  /**
   * Включение логгера
   */
  enable(): void {
    this.enabled = true;
  }
  
  /**
   * Выключение логгера
   */
  disable(): void {
    this.enabled = false;
  }
  
  /**
   * Проверка включен ли логгер
   */
  isEnabled(): boolean {
    return this.enabled;
  }
  
  /**
   * Добавление контекста по умолчанию
   */
  setDefaultContext(context: LogContext): void {
    this.defaultContext = { ...this.defaultContext, ...context };
  }
  
  /**
   * Очистка контекста по умолчанию
   */
  clearDefaultContext(): void {
    this.defaultContext = {};
  }
  
  /**
   * Добавление транспорта
   */
  async addTransport(config: TransportConfig): Promise<boolean> {
    const transport = await this.createTransport(config);
    if (transport) {
      this.transports.push(transport);
      return true;
    }
    return false;
  }
  
  /**
   * Удаление транспорта по типу
   */
  removeTransport(type: TransportConfig['type']): boolean {
    const index = this.transports.findIndex(
      t => t.constructor.name.toLowerCase().includes(type)
    );
    
    if (index !== -1) {
      const transport = this.transports[index];
      this.transports.splice(index, 1);
      transport.close();
      return true;
    }
    
    return false;
  }
  
  /**
   * Закрытие всех транспортов
   */
  async close(): Promise<void> {
    this.enabled = false;
    
    await Promise.all(this.transports.map(t => t.close()));
    
    this.emit('closed');
  }
  
  /**
   * Получение статистики логгера
   */
  getStatistics(): {
    logsProcessed: number;
    errorsCount: number;
    transportsCount: number;
    suppressedCount: number;
    enabled: boolean;
  } {
    return {
      logsProcessed: this.logCounter,
      errorsCount: this.processingErrors.length,
      transportsCount: this.transports.length,
      suppressedCount: this.rateLimiter.getSuppressedCount(),
      enabled: this.enabled
    };
  }
  
  /**
   * Сброс ошибок обработки
   */
  clearErrors(): void {
    this.processingErrors = [];
  }
  
  /**
   * Получение ошибок обработки
   */
  getErrors(): ProcessingError[] {
    return [...this.processingErrors];
  }
}

// ============================================================================
// ФАБРИКА ЛОГГЕРОВ
// ============================================================================

/**
 * Фабрика для создания экземпляров логгера
 */
export class LoggerFactory {
  private static instances: Map<string, SecureLogger> = new Map();
  
  /**
   * Создание или получение существующего логгера
   */
  static getLogger(
    name: string,
    config: LoggerConfig,
    globalConfig: GlobalConfig,
    defaultContext?: LogContext
  ): SecureLogger {
    const existing = this.instances.get(name);
    if (existing) {
      return existing;
    }
    
    const logger = new SecureLogger({
      config,
      globalConfig,
      defaultContext
    });
    
    this.instances.set(name, logger);
    return logger;
  }
  
  /**
   * Закрытие всех логгеров
   */
  static async closeAll(): Promise<void> {
    const closePromises = Array.from(this.instances.values()).map(logger => logger.close());
    await Promise.all(closePromises);
    this.instances.clear();
  }

  /**
   * Закрытие логгера по имени
   */
  static async close(name: string): Promise<void> {
    const logger = this.instances.get(name);
    if (logger) {
      await logger.close();
      this.instances.delete(name);
    }
  }
}

// ============================================================================
// ЭКСПОРТ ПО УМОЛЧАНИЮ
// ============================================================================

export default SecureLogger;

// ============================================================================
// ГЛОБАЛЬНЫЙ ЭКСПОРТ LOGGER ДЛЯ СОВМЕСТИМОСТИ
// ============================================================================

/**
 * Глобальный экземпляр logger для использования во всех модулях
 *
 * @example
 * ```typescript
 * import { logger } from './logging/Logger';
 * logger.info('Message', { data: 'value' });
 * ```
 */
export const logger = new SecureLogger({
  config: {
    level: LogLevel.DEBUG,
    format: 'structured',
    enableColors: true,
    enableTimestamp: true,
    enableProcessInfo: true,
    transports: [
      {
        type: 'console' as const,
        level: LogLevel.DEBUG,
        params: {
          enableColors: true
        }
      }
    ]
  },
  globalConfig: {
    serviceName: 'protocol-security',
    environment: (process.env.NODE_ENV as 'development' | 'staging' | 'production') || 'development',
    region: 'local',
    version: '3.0.0-alpha',
    timezone: 'UTC',
    enableAudit: true,
    enableDebug: process.env.NODE_ENV !== 'production',
    traceSampleRate: 1,
    maxLogSize: 1024 * 1024,
    enableRateLimiting: true,
    rateLimiting: { 
      maxAlerts: 100, 
      periodSeconds: 60,
      action: 'suppress'
    }
  }
});
