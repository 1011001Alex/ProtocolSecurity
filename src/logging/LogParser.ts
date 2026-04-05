/**
 * ============================================================================
 * LOG PARSER - ПАРСИНГ РАЗЛИЧНЫХ ФОРМАТОВ ЛОГОВ
 * ============================================================================
 * Универсальный парсер для поддержки множественных форматов логов:
 * JSON, Syslog, Apache/Nginx, Windows Event Log, CEF, LEEF, и другие.
 * 
 * Особенности:
 * - Поддержка 15+ форматов логов
 * - Авто-детектирование формата
 * - Извлечение полей безопасности
 * - Нормализация к единой схеме
 * - Обработка malformed записей
 * - Поддержка мультисстрочных логов
 * - Парсинг timestamp в различных форматах
 */

import * as crypto from 'crypto';
import {
  LogEntry,
  LogContext,
  LogLevel,
  LogSource,
  GeoLocation,
  ProcessingError,
  ProcessingStage
} from '../types/logging.types';

// ============================================================================
// КОНСТАНТЫ И РЕГУЛЯРНЫЕ ВЫРАЖЕНИЯ
// ============================================================================

/**
 * Регулярные выражения для различных форматов логов
 */
const PATTERNS = {
  // Syslog RFC 5424
  SYSLOG_RFC5424: /^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/,
  
  // Syslog RFC 3164 (BSD)
  SYSLOG_RFC3164: /^<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[(\d+)\])?:\s*(.*)$/,
  
  // Apache Combined Log Format
  APACHE_COMBINED: /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"/,
  
  // Apache Common Log Format
  APACHE_COMMON: /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+|-)/,
  
  // Nginx Log Format
  NGINX: /^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/,
  
  // Windows Event Log (XML-like)
  WINDOWS_EVENT: /<Event><System><Provider[^>]*Name="([^"]*)".*?<TimeCreated[^>]*SystemTime="([^"]*)".*?<Level>(\d+)<\/Level>.*?<Message>(.*?)<\/Message>/s,
  
  // CEF (Common Event Format)
  CEF: /^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$/,
  
  // LEEF (Log Event Extended Format)
  LEEF: /^LEEF:(\d+\.\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\s+(.*)$/,
  
  // ISO 8601 Timestamp
  TIMESTAMP_ISO8601: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$/,
  
  // Common timestamp formats
  TIMESTAMP_COMMON: [
    /^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?$/,
    /^\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}$/,
    /^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$/,
    /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}$/
  ],
  
  // IP Address
  IP_ADDRESS: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,

  // Email
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,

  // URL
  URL: /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g,
  
  // JWT Token
  JWT: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/,
  
  // SQL Injection patterns
  SQL_INJECTION: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b.*\b(FROM|INTO|TABLE|WHERE|SET)\b|--|\bOR\b\s+\d+\s*=\s*\d+)/i,
  
  // XSS patterns
  XSS: /(<script|javascript:|on\w+\s*=|<iframe|<object|<embed|<svg\s+onload)/i,
  
  // Path traversal
  PATH_TRAVERSAL: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)/i,
  
  // Command injection
  COMMAND_INJECTION: /[;&|`$(){}[\]<>&]/,

  // Credit card numbers (13-19 digits)
  CREDIT_CARD: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,7}\b/g,

  // SSN
  SSN: /\b\d{3}-\d{2}-\d{4}\b/g,

  // Phone numbers
  PHONE: /\+?[\d\s-()]{10,}/g
};

/**
 * Маппинг syslog приоритетов в LogLevel
 */
const SYSLOG_SEVERITY_MAP: Record<number, LogLevel> = {
  0: LogLevel.EMERGENCY,
  1: LogLevel.ALERT,
  2: LogLevel.CRITICAL,
  3: LogLevel.ERROR,
  4: LogLevel.WARNING,
  5: LogLevel.NOTICE,
  6: LogLevel.INFO,
  7: LogLevel.DEBUG
};

/**
 * Маппинг Windows Event Level в LogLevel
 */
const WINDOWS_LEVEL_MAP: Record<string, LogLevel> = {
  '1': LogLevel.CRITICAL,
  '2': LogLevel.ERROR,
  '3': LogLevel.WARNING,
  '4': LogLevel.INFO,
  '5': LogLevel.DEBUG
};

/**
 * Маппинг CEF severity в LogLevel
 */
const CEF_SEVERITY_MAP: Record<string, LogLevel> = {
  '0': LogLevel.INFO,
  '1': LogLevel.NOTICE,
  '2': LogLevel.NOTICE,
  '3': LogLevel.WARNING,
  '4': LogLevel.WARNING,
  '5': LogLevel.ERROR,
  '6': LogLevel.ERROR,
  '7': LogLevel.CRITICAL,
  '8': LogLevel.ALERT,
  '9': LogLevel.EMERGENCY,
  '10': LogLevel.EMERGENCY
};

/**
 * Названия месяцев для парсинга дат
 */
const MONTH_NAMES: Record<string, number> = {
  'Jan': 0, 'Feb': 1, 'Mar': 2, 'Apr': 3,
  'May': 4, 'Jun': 5, 'Jul': 6, 'Aug': 7,
  'Sep': 8, 'Oct': 9, 'Nov': 10, 'Dec': 11
};

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Результат парсинга
 */
interface ParseResult {
  /** Успешность парсинга */
  success: boolean;
  /** Распознанный формат */
  format?: LogFormat;
  /** Распарсенная запись */
  log?: LogEntry;
  /** Ошибки парсинга */
  errors?: ProcessingError[];
  /** Исходные данные */
  raw?: string;
  /** Извлеченные поля */
  extractedFields?: Record<string, unknown>;
}

/**
 * Поддерживаемые форматы логов
 */
type LogFormat =
  | 'json'
  | 'syslog_rfc5424'
  | 'syslog_rfc3164'
  | 'apache_combined'
  | 'apache_common'
  | 'nginx'
  | 'windows_event'
  | 'cef'
  | 'leef'
  | 'key_value'
  | 'logfmt'
  | 'grok'
  | 'custom';

/**
 * Конфигурация парсера
 */
interface LogParserConfig {
  /** Формат по умолчанию */
  defaultFormat?: LogFormat;
  /** Авто-детектирование формата */
  autoDetectFormat: boolean;
  /** Строгость парсинга */
  strictMode: boolean;
  /** Часовой пояс для парсинга дат */
  timezone: string;
  /** Кастомные паттерны */
  customPatterns?: Record<string, RegExp>;
  /** Поля для извлечения */
  extractFields?: string[];
  /** Поля для маскирования */
  maskFields?: string[];
  /** Максимальный размер записи */
  maxEntrySize: number;
  /** Включить валидацию */
  enableValidation: boolean;
}

/**
 * Статистика парсера
 */
interface ParserStatistics {
  /** Всего распарсено записей */
  totalParsed: number;
  /** Успешно распарсено */
  successCount: number;
  /** Ошибки парсинга */
  errorCount: number;
  /** Распознано по форматам */
  byFormat: Record<LogFormat, number>;
  /** Среднее время парсинга (мс) */
  avgParseTime: number;
  /** P99 время парсинга (мс) */
  p99ParseTime: number;
  /** Извлечено полей */
  fieldsExtracted: number;
  /** Маскировано значений */
  valuesMasked: number;
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ КЛАССЫ
// ============================================================================

/**
 * Маскировщик чувствительных данных
 */
class DataMasker {
  private readonly MASK = '***';
  private patterns: Array<{ pattern: RegExp; name: string }>;
  
  constructor() {
    this.patterns = [
      { pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, name: 'email' },
      { pattern: /\b\d{13,19}\b/g, name: 'credit_card' },
      { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, name: 'ssn' },
      { pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g, name: 'jwt' },
      { pattern: /\b[a-fA-F0-9]{32}\b/g, name: 'md5_hash' },
      { pattern: /\b[a-fA-F0-9]{40}\b/g, name: 'sha1_hash' },
      { pattern: /\b[a-fA-F0-9]{64}\b/g, name: 'sha256_hash' },
      { pattern: /password["']?\s*[:=]\s*["']?[^"'\s,}]+/gi, name: 'password' },
      { pattern: /secret["']?\s*[:=]\s*["']?[^"'\s,}]+/gi, name: 'secret' },
      { pattern: /api[_-]?key["']?\s*[:=]\s*["']?[^"'\s,}]+/gi, name: 'api_key' },
      { pattern: /token["']?\s*[:=]\s*["']?[^"'\s,}]+/gi, name: 'token' },
      { pattern: /bearer\s+[a-zA-Z0-9\-_]+/gi, name: 'bearer_token' }
    ];
  }
  
  /**
   * Маскирование чувствительных данных в строке
   */
  mask(value: string): string {
    let masked = value;
    
    for (const { pattern, name } of this.patterns) {
      masked = masked.replace(pattern, (match) => {
        // Для key=value форматов сохраняем ключ
        const eqIndex = match.indexOf('=');
        const colonIndex = match.indexOf(':');
        const sepIndex = Math.max(eqIndex, colonIndex);
        
        if (sepIndex > 0) {
          return match.substring(0, sepIndex + 1) + this.MASK;
        }
        
        // Для bearer token сохраняем префикс
        if (name === 'bearer_token') {
          return 'Bearer ' + this.MASK;
        }
        
        return this.MASK;
      });
    }
    
    return masked;
  }
  
  /**
   * Маскирование объекта
   */
  maskObject(obj: Record<string, unknown>, fields?: string[]): Record<string, unknown> {
    const masked: Record<string, unknown> = {};
    const sensitiveFields = new Set([
      ...(fields || []),
      'password', 'passwd', 'pwd',
      'secret', 'api_key', 'apikey', 'api-key',
      'token', 'access_token', 'refresh_token',
      'authorization', 'auth',
      'credit_card', 'cc_number', 'card_number',
      'ssn', 'social_security',
      'private_key', 'priv_key'
    ]);
    
    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      
      if (sensitiveFields.has(lowerKey)) {
        masked[key] = this.MASK;
      } else if (typeof value === 'string') {
        masked[key] = this.mask(value);
      } else if (typeof value === 'object' && value !== null) {
        masked[key] = this.maskObject(value as Record<string, unknown>, fields);
      } else {
        masked[key] = value;
      }
    }
    
    return masked;
  }
}

/**
 * Парсер временных меток
 */
class TimestampParser {
  private timezone: string;
  
  constructor(timezone: string = 'UTC') {
    this.timezone = timezone;
  }
  
  /**
   * Парсинг временной метки из строки
   */
  parse(timestamp: string): Date | null {
    if (!timestamp) {
      return null;
    }
    
    // Попытка парсинга ISO 8601
    if (PATTERNS.TIMESTAMP_ISO8601.test(timestamp)) {
      const date = new Date(timestamp);
      if (!isNaN(date.getTime())) {
        return date;
      }
    }
    
    // Попытка парсинга syslog формата (MMM dd HH:mm:ss)
    const syslogMatch = timestamp.match(/^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/);
    if (syslogMatch) {
      const [, month, day, hours, minutes, seconds] = syslogMatch;
      const now = new Date();
      const monthNum = MONTH_NAMES[month];
      
      if (monthNum !== undefined) {
        const date = new Date(now.getFullYear(), monthNum, parseInt(day), 
          parseInt(hours), parseInt(minutes), parseInt(seconds));
        
        // Если дата в будущем, предполагаем предыдущий год
        if (date > now) {
          date.setFullYear(date.getFullYear() - 1);
        }
        
        return date;
      }
    }
    
    // Попытка парсинга Apache/Nginx формата (dd/Mon/yyyy:HH:mm:ss +ZZZZ)
    const apacheMatch = timestamp.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})$/);
    if (apacheMatch) {
      const [, day, month, year, hours, minutes, seconds, tzOffset] = apacheMatch;
      const monthNum = MONTH_NAMES[month];
      
      if (monthNum !== undefined) {
        // Парсинг timezone offset
        const tzHours = parseInt(tzOffset.substring(0, 3));
        const tzMinutes = parseInt(tzOffset.substring(3, 5));
        const tzOffsetMs = (tzHours * 60 + tzMinutes) * 60 * 1000;
        
        const date = new Date(Date.UTC(
          parseInt(year), monthNum, parseInt(day),
          parseInt(hours), parseInt(minutes), parseInt(seconds)
        ));
        
        // Корректировка на timezone
        date.setTime(date.getTime() - tzOffsetMs);
        
        return date;
      }
    }
    
    // Попытка парсинга Unix timestamp
    const unixTimestamp = parseInt(timestamp);
    if (!isNaN(unixTimestamp)) {
      // Проверка на миллисекунды vs секунды
      const ms = unixTimestamp > 10000000000 ? unixTimestamp : unixTimestamp * 1000;
      const date = new Date(ms);
      if (!isNaN(date.getTime())) {
        return date;
      }
    }
    
    // Общая попытка парсинга
    const date = new Date(timestamp);
    if (!isNaN(date.getTime())) {
      return date;
    }
    
    return null;
  }
  
  /**
   * Форматирование даты в ISO 8601
   */
  toISO8601(date: Date): string {
    return date.toISOString();
  }
}

/**
 * Детектор формата логов
 */
class FormatDetector {
  /**
   * Авто-детектирование формата лога
   */
  detect(line: string): LogFormat {
    const trimmed = line.trim();
    
    // JSON detection
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        JSON.parse(trimmed);
        return 'json';
      } catch {
        // Не валидный JSON, продолжаем детектирование
      }
    }
    
    // CEF detection
    if (trimmed.startsWith('CEF:')) {
      return 'cef';
    }
    
    // LEEF detection
    if (trimmed.startsWith('LEEF:')) {
      return 'leef';
    }
    
    // Syslog RFC 5424 detection
    if (PATTERNS.SYSLOG_RFC5424.test(trimmed)) {
      return 'syslog_rfc5424';
    }
    
    // Syslog RFC 3164 detection
    if (PATTERNS.SYSLOG_RFC3164.test(trimmed)) {
      return 'syslog_rfc3164';
    }
    
    // Apache Combined detection
    if (PATTERNS.APACHE_COMBINED.test(trimmed)) {
      return 'apache_combined';
    }
    
    // Apache Common detection
    if (PATTERNS.APACHE_COMMON.test(trimmed)) {
      return 'apache_common';
    }
    
    // Nginx detection
    if (PATTERNS.NGINX.test(trimmed)) {
      return 'nginx';
    }
    
    // Key-value / logfmt detection
    if (/^\w+=[^\s]+(\s+\w+=[^\s]+)*$/.test(trimmed)) {
      return 'logfmt';
    }
    
    // Windows Event (простая эвристика)
    if (trimmed.includes('<Event>') && trimmed.includes('</Event>')) {
      return 'windows_event';
    }
    
    // По умолчанию key_value
    return 'key_value';
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС ПАРСЕРА
// ============================================================================

/**
 * Универсальный парсер логов
 * 
 * Поддерживает:
 * - Множественные форматы ввода
 * - Авто-детектирование формата
 * - Нормализацию к единой схеме
 * - Извлечение полей безопасности
 * - Маскирование чувствительных данных
 * - Валидацию распарсенных записей
 */
export class LogParser {
  private config: LogParserConfig;
  private masker: DataMasker;
  private timestampParser: TimestampParser;
  private formatDetector: FormatDetector;
  private statistics: ParserStatistics;
  private parseTimes: number[];
  private hostname: string;
  
  constructor(config: Partial<LogParserConfig> = {}) {
    this.config = {
      defaultFormat: config.defaultFormat || 'json',
      autoDetectFormat: config.autoDetectFormat !== false,
      strictMode: config.strictMode || false,
      timezone: config.timezone || 'UTC',
      customPatterns: config.customPatterns || {},
      extractFields: config.extractFields || [],
      maskFields: config.maskFields || [],
      maxEntrySize: config.maxEntrySize || 1024 * 1024, // 1MB
      enableValidation: config.enableValidation !== false
    };
    
    this.masker = new DataMasker();
    this.timestampParser = new TimestampParser(this.config.timezone);
    this.formatDetector = new FormatDetector();
    this.hostname = require('os').hostname();
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.parseTimes = [];
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): ParserStatistics {
    return {
      totalParsed: 0,
      successCount: 0,
      errorCount: 0,
      byFormat: {
        json: 0,
        syslog_rfc5424: 0,
        syslog_rfc3164: 0,
        apache_combined: 0,
        apache_common: 0,
        nginx: 0,
        windows_event: 0,
        cef: 0,
        leef: 0,
        key_value: 0,
        logfmt: 0,
        grok: 0,
        custom: 0
      },
      avgParseTime: 0,
      p99ParseTime: 0,
      fieldsExtracted: 0,
      valuesMasked: 0
    };
  }
  
  /**
   * Парсинг строки лога
   */
  parse(line: string, source?: LogSource): ParseResult {
    const startTime = Date.now();
    
    // Проверка размера
    if (line.length > this.config.maxEntrySize) {
      return {
        success: false,
        errors: [{
          stage: 'parse',
          code: 'ENTRY_TOO_LARGE',
          message: `Log entry exceeds maximum size of ${this.config.maxEntrySize} bytes`,
          recoverable: false
        }],
        raw: line.substring(0, 1000) + '...[truncated]'
      };
    }
    
    this.statistics.totalParsed++;

    try {
      // Определение формата
      const format = this.config.autoDetectFormat
        ? this.formatDetector.detect(line)
        : this.config.defaultFormat!;

      // Парсинг в зависимости от формата
      let result: ParseResult;

      switch (format) {
        case 'json':
          result = this.parseJson(line);
          break;
        case 'syslog_rfc5424':
          result = this.parseSyslogRfc5424(line);
          break;
        case 'syslog_rfc3164':
          result = this.parseSyslogRfc3164(line);
          break;
        case 'apache_combined':
          result = this.parseApacheCombined(line);
          break;
        case 'apache_common':
          result = this.parseApacheCommon(line);
          break;
        case 'nginx':
          result = this.parseNginx(line);
          break;
        case 'windows_event':
          result = this.parseWindowsEvent(line);
          break;
        case 'cef':
          result = this.parseCef(line);
          break;
        case 'leef':
          result = this.parseLeef(line);
          break;
        case 'logfmt':
        case 'key_value':
          result = this.parseKeyValue(line);
          break;
        default:
          result = this.parseGeneric(line);
      }
      
      // Обновление статистики по формату
      if (result.success) {
        this.statistics.byFormat[format]++;
        this.statistics.successCount++;
        
        // Обновление времени парсинга
        const parseTime = Date.now() - startTime;
        this.updateParseTimeStats(parseTime);
        
        // Извлечение полей безопасности и маскировка
        if (result.log) {
          this.extractSecurityFields(result.log);
          this.statistics.fieldsExtracted += Object.keys(result.extractedFields || {}).length;
          
          // Маскировка чувствительных данных в сообщении
          if (result.log.message) {
            result.log.message = this.maskSensitiveData(result.log.message);
          }
        }
      } else {
        this.statistics.errorCount++;
      }
      
      return result;
    } catch (error) {
      this.statistics.errorCount++;
      
      return {
        success: false,
        errors: [{
          stage: 'parse',
          code: 'PARSE_ERROR',
          message: error instanceof Error ? error.message : String(error),
          recoverable: this.config.strictMode ? false : true
        }],
        raw: line
      };
    }
  }
  
  /**
   * Пакетный парсинг
   */
  parseBatch(lines: string[], source?: LogSource): ParseResult[] {
    return lines.map(line => this.parse(line, source));
  }
  
  /**
   * Парсинг JSON формата
   */
  private parseJson(line: string): ParseResult {
    try {
      const data = JSON.parse(line);
      
      // Нормализация JSON лога к LogEntry
      const log = this.normalizeJsonLog(data);
      
      return {
        success: true,
        format: 'json',
        log,
        raw: line,
        extractedFields: this.extractFields(data)
      };
    } catch (error) {
      return {
        success: false,
        errors: [{
          stage: 'parse_json',
          code: 'INVALID_JSON',
          message: `Invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
          recoverable: false
        }],
        raw: line
      };
    }
  }
  
  /**
   * Нормализация JSON лога к LogEntry
   */
  private normalizeJsonLog(data: Record<string, unknown>): LogEntry {
    const now = new Date().toISOString();
    
    // Извлечение стандартных полей
    const timestamp = this.extractTimestamp(data) || now;
    const level = this.extractLogLevel(data);
    const message = this.extractMessage(data);
    const source = this.extractLogSource(data);
    const component = this.extractComponent(data);
    const context = this.extractContext(data);
    
    return {
      id: crypto.randomUUID(),
      timestamp,
      level,
      source,
      component: typeof component === 'string' ? component : 'unknown',
      hostname: typeof context.hostname === 'string' ? context.hostname : this.hostname,
      processId: (typeof context.metadata?.processId === 'number' ? context.metadata.processId : process.pid) as number,
      message,
      context,
      fields: this.masker.maskObject(data),
      schemaVersion: '1.0.0'
    };
  }
  
  /**
   * Парсинг Syslog RFC 5424
   */
  private parseSyslogRfc5424(line: string): ParseResult {
    const match = line.match(PATTERNS.SYSLOG_RFC5424);
    
    if (!match) {
      return {
        success: false,
        errors: [{
          stage: 'parse_syslog',
          code: 'INVALID_SYSLOG_FORMAT',
          message: 'Does not match RFC 5424 format',
          recoverable: false
        }],
        raw: line
      };
    }
    
    const [, pri, version, timestamp, hostname, appName, procId, msgId, sd, message] = match;
    const priority = parseInt(pri);
    const facility = Math.floor(priority / 8);
    const severity = priority % 8;
    
    const structuredData = this.parseStructuredData(sd);
    
    const log: LogEntry = {
      id: crypto.randomUUID(),
      timestamp: this.timestampParser.parse(timestamp)?.toISOString() || new Date().toISOString(),
      level: SYSLOG_SEVERITY_MAP[severity] || LogLevel.INFO,
      source: this.mapFacilityToSource(facility),
      component: appName || 'syslog',
      hostname: hostname !== '-' ? hostname : this.hostname,
      processId: procId !== '-' ? parseInt(procId) : process.pid,
      message: this.masker.mask(message),
      context: {
        metadata: {
          facility,
          severity,
          version: parseInt(version),
          msgId: msgId !== '-' ? msgId : undefined,
          structuredData
        }
      },
      schemaVersion: '1.0.0'
    };
    
    return {
      success: true,
      format: 'syslog_rfc5424',
      log,
      raw: line,
      extractedFields: { facility, severity, appName, procId, msgId }
    };
  }
  
  /**
   * Парсинг структурированных данных Syslog
   */
  private parseStructuredData(sd: string): Record<string, unknown> {
    if (sd === '-' || !sd) {
      return {};
    }
    
    const result: Record<string, unknown> = {};
    const sdPattern = /\[([^\]]+)\]/g;
    let match;
    
    while ((match = sdPattern.exec(sd)) !== null) {
      const sdContent = match[1];
      const spaceIndex = sdContent.indexOf(' ');
      
      if (spaceIndex === -1) {
        result[sdContent] = true;
      } else {
        const sdId = sdContent.substring(0, spaceIndex);
        const params = sdContent.substring(spaceIndex + 1);
        
        const paramPattern = /(\w+)="([^"]*)"/g;
        const paramsObj: Record<string, string> = {};
        
        let paramMatch;
        while ((paramMatch = paramPattern.exec(params)) !== null) {
          paramsObj[paramMatch[1]] = paramMatch[2];
        }
        
        result[sdId] = paramsObj;
      }
    }
    
    return result;
  }
  
  /**
   * Парсинг Syslog RFC 3164 (BSD)
   */
  private parseSyslogRfc3164(line: string): ParseResult {
    const match = line.match(PATTERNS.SYSLOG_RFC3164);
    
    if (!match) {
      return {
        success: false,
        errors: [{
          stage: 'parse_syslog',
          code: 'INVALID_SYSLOG_FORMAT',
          message: 'Does not match RFC 3164 format',
          recoverable: false
        }],
        raw: line
      };
    }
    
    const [, pri, timestamp, hostname, tag, pid, message] = match;
    const priority = parseInt(pri);
    const severity = priority % 8;
    
    const log: LogEntry = {
      id: crypto.randomUUID(),
      timestamp: this.timestampParser.parse(timestamp)?.toISOString() || new Date().toISOString(),
      level: SYSLOG_SEVERITY_MAP[severity] || LogLevel.INFO,
      source: LogSource.SYSTEM,
      component: tag || 'syslog',
      hostname: hostname !== '-' ? hostname : this.hostname,
      processId: pid ? parseInt(pid) : process.pid,
      message: this.masker.mask(message),
      context: {
        metadata: {
          priority,
          severity,
          format: 'rfc3164'
        }
      },
      schemaVersion: '1.0.0'
    };
    
    return {
      success: true,
      format: 'syslog_rfc3164',
      log,
      raw: line,
      extractedFields: { priority, severity, tag, pid }
    };
  }
  
  /**
   * Парсинг Apache Combined Log Format
   */
  private parseApacheCombined(line: string): ParseResult {
    const match = line.match(PATTERNS.APACHE_COMBINED);
    
    if (!match) {
      return this.parseApacheCommon(line);
    }
    
    const [, remoteIp, ident, user, timestamp, method, url, protocol, status, size, referer, userAgent] = match;
    
    const log: LogEntry = {
      id: crypto.randomUUID(),
      timestamp: this.timestampParser.parse(timestamp)?.toISOString() || new Date().toISOString(),
      level: this.getLogLevelForStatus(parseInt(status)),
      source: LogSource.NETWORK,
      component: 'apache',
      hostname: this.hostname,
      processId: process.pid,
      message: `${method} ${url} ${status}`,
      context: {
        clientIp: remoteIp !== '-' ? remoteIp : undefined,
        userAgent: userAgent !== '-' ? userAgent : undefined,
        sessionId: ident !== '-' ? ident : undefined,
        metadata: {
          user: user !== '-' ? user : undefined,
          referer: referer !== '-' ? referer : undefined
        }
      },
      fields: {
        method,
        url: this.masker.mask(url),
        protocol,
        statusCode: parseInt(status),
        responseSize: size === '-' ? 0 : parseInt(size),
        requestType: 'http'
      },
      schemaVersion: '1.0.0'
    };
    
    return {
      success: true,
      format: 'apache_combined',
      log,
      raw: line,
      extractedFields: { remoteIp, method, url, status, userAgent }
    };
  }
  
  /**
   * Парсинг Apache Common Log Format
   */
  private parseApacheCommon(line: string): ParseResult {
    const match = line.match(PATTERNS.APACHE_COMMON);
    
    if (!match) {
      return {
        success: false,
        errors: [{
          stage: 'parse_apache',
          code: 'INVALID_APACHE_FORMAT',
          message: 'Does not match Apache Common/Combined format',
          recoverable: false
        }],
        raw: line
      };
    }
    
    const [, remoteIp, ident, user, timestamp, method, url, protocol, status, size] = match;
    
    const log: LogEntry = {
      id: crypto.randomUUID(),
      timestamp: this.timestampParser.parse(timestamp)?.toISOString() || new Date().toISOString(),
      level: this.getLogLevelForStatus(parseInt(status)),
      source: LogSource.NETWORK,
      component: 'apache',
      hostname: this.hostname,
      processId: process.pid,
      message: `${method} ${url} ${status}`,
      context: {
        clientIp: remoteIp !== '-' ? remoteIp : undefined,
        metadata: {
          user: user !== '-' ? user : undefined,
          ident: ident !== '-' ? ident : undefined
        }
      },
      fields: {
        method,
        url: this.masker.mask(url),
        protocol,
        statusCode: parseInt(status),
        responseSize: size === '-' ? 0 : parseInt(size)
      },
      schemaVersion: '1.0.0'
    };
    
    return {
      success: true,
      format: 'apache_common',
      log,
      raw: line,
      extractedFields: { remoteIp, method, url, status }
    };
  }
  
  /**
   * Парсинг Nginx Log Format
   */
  private parseNginx(line: string): ParseResult {
    const match = line.match(PATTERNS.NGINX);
    
    if (!match) {
      return {
        success: false,
        errors: [{
          stage: 'parse_nginx',
          code: 'INVALID_NGINX_FORMAT',
          message: 'Does not match Nginx log format',
          recoverable: false
        }],
        raw: line
      };
    }
    
    const [, remoteIp, user, timestamp, method, url, protocol, status, size, referer, userAgent] = match;
    
    const log: LogEntry = {
      id: crypto.randomUUID(),
      timestamp: this.timestampParser.parse(timestamp)?.toISOString() || new Date().toISOString(),
      level: this.getLogLevelForStatus(parseInt(status)),
      source: LogSource.NETWORK,
      component: 'nginx',
      hostname: this.hostname,
      processId: process.pid,
      message: `${method} ${url} ${status}`,
      context: {
        clientIp: remoteIp,
        userAgent: userAgent !== '-' ? userAgent : undefined,
        metadata: {
          referer: referer !== '-' ? referer : undefined,
          user: user !== '-' ? user : undefined
        }
      },
      fields: {
        method,
        url: this.masker.mask(url),
        protocol,
        statusCode: parseInt(status),
        responseSize: parseInt(size),
        requestType: 'http'
      },
      schemaVersion: '1.0.0'
    };
    
    return {
      success: true,
      format: 'nginx',
      log,
      raw: line,
      extractedFields: { remoteIp, method, url, status, userAgent }
    };
  }
  
  /**
   * Парсинг Windows Event Log
   */
  private parseWindowsEvent(line: string): ParseResult {
    // Упрощенный парсинг, в production использовать полноценный XML парсер
    const eventMatch = line.match(/<EventID[^>]*>(\d+)<\/EventID>/);
    const levelMatch = line.match(/<Level>(\d+)<\/Level>/);
    const messageMatch = line.match(/<Message>(.*?)<\/Message>/s);
    const timeMatch = line.match(/<TimeCreated[^>]*SystemTime="([^"]*)"/);
    const providerMatch = line.match(/<Provider[^>]*Name="([^"]*)"/);
    const computerMatch = line.match(/<Computer>([^<]*)<\/Computer>/);
    
    if (!eventMatch && !messageMatch) {
      return {
        success: false,
        errors: [{
          stage: 'parse_windows',
          code: 'INVALID_WINDOWS_EVENT_FORMAT',
          message: 'Does not match Windows Event Log format',
          recoverable: false
        }],
        raw: line
      };
    }
    
    const eventId = eventMatch ? eventMatch[1] : '0';
    const level = levelMatch ? WINDOWS_LEVEL_MAP[levelMatch[1]] || LogLevel.INFO : LogLevel.INFO;
    const message = messageMatch ? this.masker.mask(messageMatch[1].trim()) : '';
    const timestamp = timeMatch ? this.timestampParser.parse(timeMatch[1])?.toISOString() : new Date().toISOString();
    const provider = providerMatch ? providerMatch[1] : 'unknown';
    const computer = computerMatch ? computerMatch[1] : this.hostname;

    const log: LogEntry = {
      id: crypto.randomUUID(),
      timestamp: timestamp || new Date().toISOString(),
      level,
      source: LogSource.SYSTEM,
      component: provider || 'unknown',
      hostname: computer || this.hostname,
      processId: process.pid,
      message,
      context: {
        metadata: {
          eventId,
          format: 'windows_event'
        }
      },
      fields: {
        eventId: parseInt(eventId),
        level: levelMatch?.[1],
        provider
      },
      schemaVersion: '1.0.0'
    };
    
    return {
      success: true,
      format: 'windows_event',
      log,
      raw: line,
      extractedFields: { eventId, provider, computer }
    };
  }
  
  /**
   * Парсинг CEF (Common Event Format)
   */
  private parseCef(line: string): ParseResult {
    const match = line.match(PATTERNS.CEF);
    
    if (!match) {
      return {
        success: false,
        errors: [{
          stage: 'parse_cef',
          code: 'INVALID_CEF_FORMAT',
          message: 'Does not match CEF format',
          recoverable: false
        }],
        raw: line
      };
    }
    
    const [, version, vendor, product, productVersion, signatureId, name, severity, extension] = match;
    
    // Парсинг extension (key=value pairs)
    const extensionFields = this.parseCefExtension(extension);
    
    const log: LogEntry = {
      id: crypto.randomUUID(),
      timestamp: extensionFields.rt 
        ? this.timestampParser.parse(String(extensionFields.rt))?.toISOString() || new Date().toISOString()
        : new Date().toISOString(),
      level: CEF_SEVERITY_MAP[severity] || LogLevel.INFO,
      source: LogSource.SECURITY,
      component: `${vendor}/${product}`,
      hostname: extensionFields.dhost as string || this.hostname,
      processId: process.pid,
      message: this.masker.mask(name),
      context: {
        clientIp: extensionFields.src as string,
        metadata: {
          destinationIp: extensionFields.dst,
          sourcePort: extensionFields.spt,
          destinationPort: extensionFields.dpt,
          protocol: extensionFields.proto,
          userId: extensionFields.suser
        }
      },
      fields: {
        cefVersion: version,
        vendor,
        product,
        productVersion,
        signatureId,
        severity: parseInt(severity),
        ...extensionFields
      },
      schemaVersion: '1.0.0'
    };
    
    return {
      success: true,
      format: 'cef',
      log,
      raw: line,
      extractedFields: { vendor, product, signatureId, name, severity, src: extensionFields.src, dst: extensionFields.dst }
    };
  }
  
  /**
   * Парсинг CEF extension
   */
  private parseCefExtension(extension: string): Record<string, unknown> {
    const fields: Record<string, unknown> = {};
    
    // CEF extension использует key=value с экранированием пробелов через \=
    const pattern = /(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)/g;
    let match;
    
    while ((match = pattern.exec(extension)) !== null) {
      const [, key, value] = match;
      
      // Попытка преобразования типов
      if (/^\d+$/.test(value)) {
        fields[key] = parseInt(value);
      } else if (/^\d+\.\d+$/.test(value)) {
        fields[key] = parseFloat(value);
      } else {
        fields[key] = value;
      }
    }
    
    return fields;
  }
  
  /**
   * Парсинг LEEF (Log Event Extended Format)
   */
  private parseLeef(line: string): ParseResult {
    const match = line.match(PATTERNS.LEEF);
    
    if (!match) {
      return {
        success: false,
        errors: [{
          stage: 'parse_leef',
          code: 'INVALID_LEEF_FORMAT',
          message: 'Does not match LEEF format',
          recoverable: false
        }],
        raw: line
      };
    }
    
    const [, version, vendor, product, versionNum, eventId, attributes] = match;
    
    // Парсинг атрибутов (key=value)
    const attributeFields = this.parseLeefAttributes(attributes);
    
    const log: LogEntry = {
      id: crypto.randomUUID(),
      timestamp: attributeFields.time 
        ? this.timestampParser.parse(String(attributeFields.time))?.toISOString() || new Date().toISOString()
        : new Date().toISOString(),
      level: this.getLogLevelForLeef(attributeFields.sev as string),
      source: LogSource.SECURITY,
      component: `${vendor}/${product}`,
      hostname: attributeFields.srcHost as string || this.hostname,
      processId: process.pid,
      message: this.masker.mask(eventId),
      context: {
        clientIp: attributeFields.src as string,
        metadata: {
          destinationIp: attributeFields.dst,
          sourcePort: attributeFields.sPort,
          destinationPort: attributeFields.dPort,
          protocol: attributeFields.proto,
          userId: attributeFields.usrName
        }
      },
      fields: {
        leefVersion: version,
        vendor,
        product,
        versionNum,
        eventId,
        ...attributeFields
      },
      schemaVersion: '1.0.0'
    };
    
    return {
      success: true,
      format: 'leef',
      log,
      raw: line,
      extractedFields: { vendor, product, eventId, src: attributeFields.src, dst: attributeFields.dst }
    };
  }
  
  /**
   * Парсинг LEEF атрибутов
   */
  private parseLeefAttributes(attributes: string): Record<string, unknown> {
    const fields: Record<string, unknown> = {};
    const pattern = /(\w+)=([^\t\n]+)/g;
    let match;
    
    while ((match = pattern.exec(attributes)) !== null) {
      const [, key, value] = match;
      fields[key] = value;
    }
    
    return fields;
  }
  
  /**
   * Парсинг Key-Value / Logfmt формата
   */
  private parseKeyValue(line: string): ParseResult {
    const fields = this.parseLogfmt(line);

    if (Object.keys(fields).length === 0) {
      return this.parseGeneric(line);
    }

    const log = this.normalizeKeyValueLog(fields);

    return {
      success: true,
      format: 'logfmt',
      log,
      raw: line,
      extractedFields: fields
    };
  }
  
  /**
   * Парсинг Logfmt строки
   */
  private parseLogfmt(line: string): Record<string, unknown> {
    const fields: Record<string, unknown> = {};
    
    // Паттерн для key=value или key="value with spaces"
    const pattern = /(\w+)=("(?:[^"\\]|\\.)*"|'[^\']*'|[^\s]+)/g;
    let match;
    
    while ((match = pattern.exec(line)) !== null) {
      const [, key, value] = match;
      
      // Удаление кавычек
      const unquotedValue = value.replace(/^["']|["']$/g, '');
      
      // Преобразование типов
      if (unquotedValue === 'true') {
        fields[key] = true;
      } else if (unquotedValue === 'false') {
        fields[key] = false;
      } else if (unquotedValue === 'null') {
        fields[key] = null;
      } else if (/^-?\d+$/.test(unquotedValue)) {
        fields[key] = parseInt(unquotedValue);
      } else if (/^-?\d+\.\d+$/.test(unquotedValue)) {
        fields[key] = parseFloat(unquotedValue);
      } else {
        fields[key] = unquotedValue;
      }
    }
    
    return fields;
  }
  
  /**
   * Нормализация key-value лога
   */
  private normalizeKeyValueLog(fields: Record<string, unknown>): LogEntry {
    const timestamp = this.extractTimestamp(fields) || new Date().toISOString();
    const level = this.extractLogLevel(fields);
    const rawMessage = this.extractMessage(fields);
    const message = this.masker.mask(rawMessage); // Маскируем сообщение
    const source = this.extractLogSource(fields);
    const component = this.extractComponent(fields);
    const context = this.extractContext(fields);

    return {
      id: crypto.randomUUID(),
      timestamp,
      level,
      source,
      component: typeof component === 'string' ? component : 'unknown',
      hostname: typeof context.hostname === 'string' ? context.hostname : this.hostname,
      processId: (typeof context.metadata?.processId === 'number' ? context.metadata.processId : process.pid) as number,
      message,
      context,
      fields: this.masker.maskObject(fields),
      schemaVersion: '1.0.0'
    };
  }
  
  /**
   * Парсинг-generic формата (fallback)
   */
  private parseGeneric(line: string): ParseResult {
    // Попытка извлечь что-то полезное из строки
    const extractedFields: Record<string, unknown> = {};

    // Извлечение IP адресов
    const ipMatches = line.matchAll(PATTERNS.IP_ADDRESS);
    const ips = Array.from(ipMatches, m => m[0]);
    if (ips.length > 0) {
      extractedFields.ips = ips;
      extractedFields.clientIp = ips[0];
    }

    // Извлечение email
    const emailMatches = line.matchAll(PATTERNS.EMAIL);
    const emails = Array.from(emailMatches, m => m[0]);
    if (emails.length > 0) {
      extractedFields.emails = emails;
    }

    // Извлечение URL
    const urlMatches = line.matchAll(PATTERNS.URL);
    const urls = Array.from(urlMatches, m => m[0]);
    if (urls.length > 0) {
      extractedFields.urls = urls;
    }

    // Детектирование уровня логирования из текста
    const level = this.detectLevelFromText(line);

    const log: LogEntry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      level,
      source: LogSource.APPLICATION,
      component: 'unknown',
      hostname: this.hostname,
      processId: process.pid,
      message: this.masker.mask(line),
      context: {
        clientIp: extractedFields.clientIp as string,
        metadata: { ...extractedFields } // Копируем extractedFields в metadata
      },
      fields: extractedFields,
      schemaVersion: '1.0.0'
    };

    return {
      success: true,
      format: 'custom',
      log,
      raw: line,
      extractedFields
    };
  }
  
  // ==========================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ ИЗВЛЕЧЕНИЯ
  // ==========================================================================
  
  /**
   * Извлечение timestamp из данных
   */
  private extractTimestamp(data: Record<string, unknown>): string | null {
    const timestampFields = ['timestamp', 'time', '@timestamp', 'datetime', 'date', 'ts', 'created', 'occurred_at'];
    
    for (const field of timestampFields) {
      if (data[field]) {
        const parsed = this.timestampParser.parse(String(data[field]));
        if (parsed) {
          return parsed.toISOString();
        }
      }
    }
    
    return null;
  }
  
  /**
   * Извлечение уровня логирования из данных
   */
  private extractLogLevel(data: Record<string, unknown>): LogLevel {
    const levelFields = ['level', 'severity', 'log_level', 'loglevel', 'lvl', 'priority'];
    
    for (const field of levelFields) {
      const value = data[field];
      if (value !== undefined) {
        const levelValue = typeof value === 'string' ? value.toLowerCase() : value;
        
        // Проверка числового значения
        if (typeof levelValue === 'number' && levelValue >= 0 && levelValue <= 8) {
          return levelValue as LogLevel;
        }
        
        // Проверка строкового значения
        if (typeof levelValue === 'string') {
          const levelMap: Record<string, LogLevel> = {
            'emergency': LogLevel.EMERGENCY,
            'alert': LogLevel.ALERT,
            'critical': LogLevel.CRITICAL,
            'crit': LogLevel.CRITICAL,
            'error': LogLevel.ERROR,
            'err': LogLevel.ERROR,
            'warning': LogLevel.WARNING,
            'warn': LogLevel.WARNING,
            'notice': LogLevel.NOTICE,
            'info': LogLevel.INFO,
            'information': LogLevel.INFO,
            'debug': LogLevel.DEBUG,
            'dbg': LogLevel.DEBUG,
            'trace': LogLevel.TRACE,
            'trc': LogLevel.TRACE
          };
          
          if (levelMap[levelValue] !== undefined) {
            return levelMap[levelValue];
          }
        }
      }
    }
    
    return LogLevel.INFO;
  }
  
  /**
   * Извлечение сообщения из данных
   */
  private extractMessage(data: Record<string, unknown>): string {
    const messageFields = ['message', 'msg', 'text', 'log', 'content', 'body', 'description'];
    
    for (const field of messageFields) {
      if (data[field] !== undefined) {
        return String(data[field]);
      }
    }
    
    // Если сообщения нет, создаем из доступных данных
    return JSON.stringify(data);
  }
  
  /**
   * Извлечение источника лога из данных
   */
  private extractLogSource(data: Record<string, unknown>): LogSource {
    const sourceFields = ['source', 'log_source', 'category', 'type'];
    
    for (const field of sourceFields) {
      const value = String(data[field] || '').toLowerCase();
      
      if (value.includes('security') || value.includes('auth')) {
        return LogSource.SECURITY;
      }
      if (value.includes('network') || value.includes('http')) {
        return LogSource.NETWORK;
      }
      if (value.includes('database') || value.includes('db') || value.includes('sql')) {
        return LogSource.DATABASE;
      }
      if (value.includes('system') || value.includes('os')) {
        return LogSource.SYSTEM;
      }
      if (value.includes('audit')) {
        return LogSource.AUDIT;
      }
      if (value.includes('performance') || value.includes('perf')) {
        return LogSource.PERFORMANCE;
      }
    }
    
    return LogSource.APPLICATION;
  }
  
  /**
   * Извлечение компонента из данных
   */
  private extractComponent(data: Record<string, unknown>): string | undefined {
    const componentFields = ['component', 'service', 'app', 'application', 'module', 'logger', 'name'];
    
    for (const field of componentFields) {
      if (data[field] !== undefined) {
        return String(data[field]);
      }
    }
    
    return undefined;
  }
  
  /**
   * Извлечение контекста из данных
   */
  private extractContext(data: Record<string, unknown>): LogContext {
    const context: LogContext = {};
    
    // Пользователь
    const userFields = ['user', 'userId', 'user_id', 'username', 'uid', 'account'];
    for (const field of userFields) {
      if (data[field]) {
        context.userId = String(data[field]);
        break;
      }
    }
    
    // IP адрес
    const ipFields = ['ip', 'clientIp', 'client_ip', 'remote_addr', 'remote_ip', 'src_ip', 'source_ip'];
    for (const field of ipFields) {
      if (data[field]) {
        context.clientIp = String(data[field]);
        break;
      }
    }
    
    // Session ID
    const sessionFields = ['session', 'sessionId', 'session_id', 'sid', 'sess'];
    for (const field of sessionFields) {
      if (data[field]) {
        context.sessionId = String(data[field]);
        break;
      }
    }
    
    // Request ID
    const requestFields = ['request', 'requestId', 'request_id', 'req_id', 'trace_id', 'x-request-id'];
    for (const field of requestFields) {
      if (data[field]) {
        context.requestId = String(data[field]);
        break;
      }
    }
    
    // User Agent
    const uaFields = ['userAgent', 'user_agent', 'ua', 'http_user_agent'];
    for (const field of uaFields) {
      if (data[field]) {
        context.userAgent = String(data[field]);
        break;
      }
    }
    
    // Hostname
    const hostFields = ['host', 'hostname', 'server', 'server_name'];
    for (const field of hostFields) {
      if (data[field]) {
        context.metadata = { ...context.metadata, hostname: String(data[field]) };
        break;
      }
    }
    
    return context;
  }
  
  /**
   * Извлечение дополнительных полей
   */
  private extractFields(data: Record<string, unknown>): Record<string, unknown> {
    const extracted: Record<string, unknown> = {};
    
    if (this.config.extractFields) {
      for (const field of this.config.extractFields) {
        if (data[field] !== undefined) {
          extracted[field] = data[field];
        }
      }
    }
    
    return extracted;
  }
  
  /**
   * Маскировка чувствительных данных
   */
  private maskSensitiveData(message: string): string {
    let masked = message;

    // Маскировка email
    masked = masked.replace(PATTERNS.EMAIL, (match) => {
      const parts = match.split('@');
      if (parts.length === 2) {
        const user = parts[0];
        const domain = parts[1];
        const maskedUser = user.charAt(0) + '***' + user.charAt(user.length - 1);
        return maskedUser + '@' + domain;
      }
      return '***@***.***';
    });

    // Маскировка credit cards
    masked = masked.replace(PATTERNS.CREDIT_CARD, (match) => {
      const digits = match.replace(/\D/g, '');
      if (digits.length >= 13) {
        return '****-****-****-' + digits.slice(-4);
      }
      return '****';
    });

    // Маскировка SSN
    masked = masked.replace(PATTERNS.SSN, '***-**-****');

    return masked;
  }

  /**
   * Извлечение полей безопасности
   */
  private extractSecurityFields(log: LogEntry): void {
    const fields = log.fields || {};

    // Проверка на SQL injection (приоритет 1)
    if (typeof log.message === 'string' && PATTERNS.SQL_INJECTION.test(log.message)) {
      log.context.metadata = {
        ...log.context.metadata,
        securityThreat: 'sql_injection',
        threatLevel: 'high'
      };
    }
    // Проверка на XSS (приоритет 2)
    else if (typeof log.message === 'string' && PATTERNS.XSS.test(log.message)) {
      log.context.metadata = {
        ...log.context.metadata,
        securityThreat: 'xss',
        threatLevel: 'high'
      };
    }
    // Проверка на path traversal (приоритет 3)
    else if (typeof log.message === 'string' && PATTERNS.PATH_TRAVERSAL.test(log.message)) {
      log.context.metadata = {
        ...log.context.metadata,
        securityThreat: 'path_traversal',
        threatLevel: 'medium'
      };
    }
    // Проверка на command injection (приоритет 4 - самый общий паттерн)
    else if (typeof log.message === 'string' && PATTERNS.COMMAND_INJECTION.test(log.message)) {
      log.context.metadata = {
        ...log.context.metadata,
        securityThreat: 'command_injection',
        threatLevel: 'critical'
      };
    }
  }
  
  /**
   * Детектирование уровня логирования из текста
   */
  private detectLevelFromText(text: string): LogLevel {
    const lowerText = text.toLowerCase();
    
    if (/\b(emergency|fatal|panic)\b/i.test(lowerText)) return LogLevel.EMERGENCY;
    if (/\balert\b/i.test(lowerText)) return LogLevel.ALERT;
    if (/\b(critical|crit|fatal)\b/i.test(lowerText)) return LogLevel.CRITICAL;
    if (/\b(error|err|failed|failure)\b/i.test(lowerText)) return LogLevel.ERROR;
    if (/\b(warning|warn)\b/i.test(lowerText)) return LogLevel.WARNING;
    if (/\bnotice\b/i.test(lowerText)) return LogLevel.NOTICE;
    if (/\bdebug\b/i.test(lowerText)) return LogLevel.DEBUG;
    if (/\btrace\b/i.test(lowerText)) return LogLevel.TRACE;
    
    return LogLevel.INFO;
  }
  
  /**
   * Получение уровня логирования для HTTP статуса
   */
  private getLogLevelForStatus(status: number): LogLevel {
    if (status >= 500) return LogLevel.ERROR;
    if (status >= 400) return LogLevel.WARNING;
    if (status >= 300) return LogLevel.NOTICE;
    return LogLevel.INFO;
  }
  
  /**
   * Получение уровня логирования для LEEF severity
   */
  private getLogLevelForLeef(sev?: string): LogLevel {
    if (!sev) return LogLevel.INFO;
    
    const severity = parseInt(sev);
    if (severity >= 9) return LogLevel.EMERGENCY;
    if (severity >= 7) return LogLevel.CRITICAL;
    if (severity >= 5) return LogLevel.ERROR;
    if (severity >= 3) return LogLevel.WARNING;
    if (severity >= 1) return LogLevel.INFO;
    return LogLevel.DEBUG;
  }
  
  /**
   * Маппинг syslog facility в LogSource
   */
  private mapFacilityToSource(facility: number): LogSource {
    const facilityMap: Record<number, LogSource> = {
      0: LogSource.SYSTEM,    // kern
      1: LogSource.SYSTEM,    // user
      2: LogSource.SYSTEM,    // mail
      3: LogSource.SYSTEM,    // daemon
      4: LogSource.SYSTEM,    // auth
      5: LogSource.SYSTEM,    // syslog
      6: LogSource.SYSTEM,    // lpr
      7: LogSource.SYSTEM,    // news
      8: LogSource.SYSTEM,    // uucp
      9: LogSource.SYSTEM,    // cron
      10: LogSource.SECURITY, // authpriv
      11: LogSource.SYSTEM,   // ftp
      16: LogSource.SYSTEM,   // local0
      17: LogSource.SYSTEM,   // local1
      18: LogSource.SYSTEM,   // local2
      19: LogSource.SYSTEM,   // local3
      20: LogSource.SYSTEM,   // local4
      21: LogSource.SYSTEM,   // local5
      22: LogSource.SYSTEM,   // local6
      23: LogSource.SYSTEM    // local7
    };
    
    return facilityMap[facility] || LogSource.SYSTEM;
  }
  
  /**
   * Обновление статистики времени парсинга
   */
  private updateParseTimeStats(parseTime: number): void {
    this.parseTimes.push(parseTime);
    
    // Ограничение размера массива
    if (this.parseTimes.length > 1000) {
      this.parseTimes.shift();
    }
    
    // Расчет average
    this.statistics.avgParseTime = 
      this.parseTimes.reduce((a, b) => a + b, 0) / this.parseTimes.length;
    
    // Расчет P99
    const sorted = [...this.parseTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99ParseTime = sorted[p99Index] || 0;
  }
  
  // ==========================================================================
  // ПУБЛИЧНЫЕ МЕТОДЫ
  // ==========================================================================
  
  /**
   * Получение статистики
   */
  getStatistics(): ParserStatistics {
    return { ...this.statistics };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
    this.parseTimes = [];
  }
  
  /**
   * Добавление кастомного паттерна
   */
  addCustomPattern(name: string, pattern: RegExp): void {
    if (this.config.customPatterns) {
      this.config.customPatterns[name] = pattern;
    }
  }
  
  /**
   * Установка формата по умолчанию
   */
  setDefaultFormat(format: LogFormat): void {
    this.config.defaultFormat = format;
    this.config.autoDetectFormat = false;
  }
  
  /**
   * Включение авто-детектирования
   */
  enableAutoDetect(): void {
    this.config.autoDetectFormat = true;
  }
  
  /**
   * Выключение авто-детектирования
   */
  disableAutoDetect(): void {
    this.config.autoDetectFormat = false;
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default LogParser;
