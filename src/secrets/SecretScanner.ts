/**
 * ============================================================================
 * SECRET SCANNER - СКАНИРОВАНИЕ И DETECTION УТЕЧЕК СЕКРЕТОВ
 * ============================================================================
 * 
 * Реализует систему обнаружения утечек секретов через сканирование:
 * - Лог файлов
 * - Исходного кода
 * - Конфигурационных файлов
 * - Environment variables
 * - Git history
 * - Сетевого трафика
 * 
 * Также обнаруживает подозрительный доступ и аномальное использование.
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../logging/Logger';
import {
  LeakDetection,
  LeakType,
  LeakSeverity,
  ScannerConfig,
  SecretBackendType,
  AuditLogEntry,
  SecretOperation
} from '../types/secrets.types';

/**
 * Паттерн для обнаружения секретов
 */
interface SecretPattern {
  /** Название паттерна */
  name: string;
  /** Регулярное выражение */
  regex: RegExp;
  /** Тип секрета */
  secretType: string;
  /** Уровень серьёзности */
  severity: LeakSeverity;
}

/**
 * Результат сканирования файла
 */
interface ScanResult {
  /** Путь к файлу */
  filePath: string;
  /** Найдённые утечки */
  leaks: LeakDetection[];
  /** Время сканирования */
  scannedAt: Date;
  /** Ошибки сканирования */
  errors: string[];
}

/**
 * Конфигурация сканера
 */
interface ScannerInternalConfig {
  /** Включено ли сканирование */
  enabled: boolean;
  /** Интервал сканирования (сек) */
  scanInterval: number;
  /** Паттерны для поиска */
  patterns: SecretPattern[];
  /** Пути для сканирования */
  scanPaths: string[];
  /** Исключения */
  excludePatterns: RegExp[];
  /** Авто-отзыв при обнаружении */
  autoRevokeOnLeak: boolean;
  /** Уведомлять при обнаружении */
  notifyOnDetection: boolean;
  /** Максимальный размер файла (байты) */
  maxFileSize: number;
  /** Кодировка файлов */
  fileEncoding: BufferEncoding;
}

/**
 * Статистика сканирования
 */
interface ScanStats {
  /** Количество сканирований */
  totalScans: number;
  /** Количество обнаруженных утечек */
  totalLeaks: number;
  /** Утечки по типам */
  leaksByType: Map<LeakType, number>;
  /** Утечки по серьёзности */
  leaksBySeverity: Map<LeakSeverity, number>;
  /** Просканировано файлов */
  filesScanned: number;
  /** Ошибки сканирования */
  scanErrors: number;
  /** Ложные срабатывания */
  falsePositives: number;
}

/**
 * Класс для сканирования и обнаружения утечек секретов
 * 
 * Особенности:
 * - Множество паттернов для разных типов секретов
 * - Сканирование файлов и логов
 * - Обнаружение аномального доступа
 * - Интеграция с системами отзыва
 * - Статистика и отчётность
 */
export class SecretScanner extends EventEmitter {
  /** Конфигурация сканера */
  private readonly config: ScannerInternalConfig;
  
  /** Обнаруженные утечки */
  private detections: Map<string, LeakDetection>;
  
  /** История сканирований */
  private scanHistory: ScanResult[];
  
  /** Статистика */
  private stats: ScanStats;
  
  /** Интервал периодического сканирования */
  private scanInterval?: NodeJS.Timeout;
  
  /** Флаг работы сканера */
  private isRunning = false;
  
  /** Известные хеши секретов для быстрого поиска */
  private knownSecretHashes: Set<string>;

  /** Конфигурация по умолчанию */
  private readonly DEFAULT_CONFIG: ScannerInternalConfig = {
    enabled: true,
    scanInterval: 300, // 5 минут
    patterns: [],
    scanPaths: [],
    excludePatterns: [
      /node_modules/i,
      /\.git/i,
      /dist/i,
      /build/i,
      /\.min\./i,
      /vendor/i
    ],
    autoRevokeOnLeak: true,
    notifyOnDetection: true,
    maxFileSize: 10 * 1024 * 1024, // 10 MB
    fileEncoding: 'utf8'
  };

  /**
   * Создаёт новый экземпляр SecretScanner
   * 
   * @param config - Конфигурация сканера
   */
  constructor(config: Partial<ScannerConfig> = {}) {
    super();
    
    this.config = {
      ...this.DEFAULT_CONFIG,
      enabled: config.enabled ?? true,
      scanInterval: config.scanInterval ?? 300,
      scanPaths: config.scanPaths ?? [],
      autoRevokeOnLeak: config.autoRevokeOnLeak ?? true,
      notifyOnDetection: config.notifyOnDetection ?? true
    };
    
    // Добавляем стандартные паттерны
    this.config.patterns = this.createDefaultPatterns();
    
    // Если есть пользовательские паттерны, добавляем их
    if (config.secretPatterns) {
      config.secretPatterns.forEach(regex => {
        this.config.patterns.push({
          name: 'custom',
          regex,
          secretType: 'custom',
          severity: LeakSeverity.HIGH
        });
      });
    }
    
    this.detections = new Map();
    this.scanHistory = [];
    this.knownSecretHashes = new Set();
    
    this.stats = {
      totalScans: 0,
      totalLeaks: 0,
      leaksByType: new Map(),
      leaksBySeverity: new Map(),
      filesScanned: 0,
      scanErrors: 0,
      falsePositives: 0
    };
  }

  /**
   * Создание стандартных паттернов для обнаружения секретов
   */
  private createDefaultPatterns(): SecretPattern[] {
    return [
      // AWS Access Key ID
      {
        name: 'AWS Access Key ID',
        regex: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/gi,
        secretType: 'aws_access_key',
        severity: LeakSeverity.CRITICAL
      },
      
      // AWS Secret Access Key
      {
        name: 'AWS Secret Access Key',
        regex: /aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi,
        secretType: 'aws_secret_key',
        severity: LeakSeverity.CRITICAL
      },
      
      // GitHub Personal Access Token
      {
        name: 'GitHub PAT',
        regex: /ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/gi,
        secretType: 'github_token',
        severity: LeakSeverity.CRITICAL
      },
      
      // GitHub OAuth Token
      {
        name: 'GitHub OAuth Token',
        regex: /gho_[A-Za-z0-9]{36}/gi,
        secretType: 'github_oauth',
        severity: LeakSeverity.HIGH
      },
      
      // Slack Token
      {
        name: 'Slack Token',
        regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/gi,
        secretType: 'slack_token',
        severity: LeakSeverity.HIGH
      },
      
      // Slack Webhook
      {
        name: 'Slack Webhook',
        regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9]+\/[A-Za-z0-9]+\/[A-Za-z0-9]+/gi,
        secretType: 'slack_webhook',
        severity: LeakSeverity.MEDIUM
      },
      
      // Google API Key
      {
        name: 'Google API Key',
        regex: /AIza[0-9A-Za-z-_]{35}/gi,
        secretType: 'google_api_key',
        severity: LeakSeverity.HIGH
      },
      
      // Google OAuth Token
      {
        name: 'Google OAuth Token',
        regex: /ya29\.[0-9A-Za-z-_]+/gi,
        secretType: 'google_oauth',
        severity: LeakSeverity.HIGH
      },
      
      // Stripe API Key
      {
        name: 'Stripe API Key',
        regex: /sk_live_[0-9a-zA-Z]{24}|rk_live_[0-9a-zA-Z]{24}/gi,
        secretType: 'stripe_key',
        severity: LeakSeverity.CRITICAL
      },
      
      // Stripe Restricted Key
      {
        name: 'Stripe Restricted Key',
        regex: /sk_test_[0-9a-zA-Z]{24}|rk_test_[0-9a-zA-Z]{24}/gi,
        secretType: 'stripe_test_key',
        severity: LeakSeverity.MEDIUM
      },
      
      // Twilio API Key
      {
        name: 'Twilio API Key',
        regex: /SK[0-9a-fA-F]{32}/gi,
        secretType: 'twilio_key',
        severity: LeakSeverity.HIGH
      },
      
      // SendGrid API Key
      {
        name: 'SendGrid API Key',
        regex: /SG\.[0-9A-Za-z-_]{22}\.[0-9A-Za-z-_]{43}/gi,
        secretType: 'sendgrid_key',
        severity: LeakSeverity.HIGH
      },
      
      // Mailgun API Key
      {
        name: 'Mailgun API Key',
        regex: /key-[0-9a-zA-Z]{32}/gi,
        secretType: 'mailgun_key',
        severity: LeakSeverity.HIGH
      },
      
      // Heroku API Key
      {
        name: 'Heroku API Key',
        regex: /[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/gi,
        secretType: 'heroku_key',
        severity: LeakSeverity.HIGH
      },
      
      // Generic API Key
      {
        name: 'Generic API Key',
        regex: /api[_-]?key['"]?\s*[:=]\s*['"]?[a-zA-Z0-9]{20,}['"]?/gi,
        secretType: 'generic_api_key',
        severity: LeakSeverity.MEDIUM
      },
      
      // Generic Secret
      {
        name: 'Generic Secret',
        regex: /secret['"]?\s*[:=]\s*['"]?[a-zA-Z0-9]{20,}['"]?/gi,
        secretType: 'generic_secret',
        severity: LeakSeverity.MEDIUM
      },
      
      // Password in URL
      {
        name: 'Password in URL',
        regex: /:[^:@\s]{8,}@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/gi,
        secretType: 'password_url',
        severity: LeakSeverity.HIGH
      },
      
      // Private Key Header
      {
        name: 'Private Key',
        regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/gi,
        secretType: 'private_key',
        severity: LeakSeverity.CRITICAL
      },
      
      // JWT Token
      {
        name: 'JWT Token',
        regex: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/gi,
        secretType: 'jwt',
        severity: LeakSeverity.HIGH
      },
      
      // NPM Token
      {
        name: 'NPM Token',
        regex: //npm_[A-Za-z0-9]{36}/gi,
        secretType: 'npm_token',
        severity: LeakSeverity.HIGH
      },
      
      // Docker Hub Token
      {
        name: 'Docker Hub Token',
        regex: /dckr_pat_[A-Za-z0-9-_]{56}/gi,
        secretType: 'docker_token',
        severity: LeakSeverity.HIGH
      },
      
      // Azure Storage Account Key
      {
        name: 'Azure Storage Key',
        regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}/gi,
        secretType: 'azure_storage_key',
        severity: LeakSeverity.CRITICAL
      },
      
      // SSH Private Key
      {
        name: 'SSH Private Key',
        regex: /ssh-rsa [A-Za-z0-9+/=]+[A-Za-z0-9+/=][A-Za-z0-9+/=]/gi,
        secretType: 'ssh_key',
        severity: LeakSeverity.HIGH
      },
      
      // Database Connection String
      {
        name: 'Database Connection String',
        regex: /(mongodb|mysql|postgres|postgresql|redis|amqp):\/\/[^:]+:[^@]+@/gi,
        secretType: 'db_connection',
        severity: LeakSeverity.CRITICAL
      },
      
      // Base64 encoded secret (эвристика)
      {
        name: 'Base64 Secret',
        regex: /(?:^|[^a-zA-Z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?:[^a-zA-Z0-9+/]|$)/gi,
        secretType: 'base64_secret',
        severity: LeakSeverity.LOW
      }
    ];
  }

  /**
   * Инициализация сканера
   */
  async initialize(): Promise<void> {
    if (!this.config.enabled) {
      logger.info('[SecretScanner] Отключён');
      return;
    }

    this.isRunning = true;

    // Запуск периодического сканирования
    this.scanInterval = setInterval(() => {
      void this.performScheduledScan();
    }, this.config.scanInterval * 1000);

    this.scanInterval.unref();

    logger.info('[SecretScanner] Инициализирован', {
      patterns: this.config.patterns.length,
      scanPaths: this.config.scanPaths.length,
      interval: this.config.scanInterval
    });
  }

  /**
   * Остановка сканера
   */
  async destroy(): Promise<void> {
    this.isRunning = false;

    if (this.scanInterval) {
      clearInterval(this.scanInterval);
    }

    logger.info('[SecretScanner] Остановлен');
  }

  /**
   * Периодическое сканирование
   */
  private async performScheduledScan(): Promise<void> {
    if (this.config.scanPaths.length === 0) {
      return;
    }

    logger.info('[SecretScanner] Запуск периодического сканирования...');
    
    const results: ScanResult[] = [];
    
    for (const scanPath of this.config.scanPaths) {
      const result = await this.scanPath(scanPath);
      results.push(result);
    }
    
    // Сохранение в историю
    this.scanHistory.push(...results);
    
    // Ограничение истории
    if (this.scanHistory.length > 100) {
      this.scanHistory = this.scanHistory.slice(-100);
    }
    
    this.stats.totalScans++;
    
    // Подсчёт статистики
    for (const result of results) {
      this.stats.filesScanned++;
      this.stats.totalLeaks += result.leaks.length;
      
      for (const leak of result.leaks) {
        const typeCount = this.stats.leaksByType.get(leak.leakType) ?? 0;
        this.stats.leaksByType.set(leak.leakType, typeCount + 1);
        
        const severityCount = this.stats.leaksBySeverity.get(leak.severity) ?? 0;
        this.stats.leaksBySeverity.set(leak.severity, severityCount + 1);
      }
      
      this.stats.scanErrors += result.errors.length;
    }
  }

  /**
   * Сканирование пути (файл или директория)
   */
  private async scanPath(scanPath: string): Promise<ScanResult> {
    const result: ScanResult = {
      filePath: scanPath,
      leaks: [],
      scannedAt: new Date(),
      errors: []
    };
    
    try {
      const stat = fs.statSync(scanPath);
      
      if (stat.isFile()) {
        await this.scanFile(scanPath, result);
      } else if (stat.isDirectory()) {
        await this.scanDirectory(scanPath, result);
      }
    } catch (error) {
      result.errors.push(error instanceof Error ? error.message : String(error));
      this.stats.scanErrors++;
    }
    
    return result;
  }

  /**
   * Сканирование файла
   */
  private async scanFile(filePath: string, result: ScanResult): Promise<void> {
    // Проверка исключений
    if (this.isExcluded(filePath)) {
      return;
    }
    
    // Проверка размера
    try {
      const stat = fs.statSync(filePath);
      
      if (stat.size > this.config.maxFileSize) {
        result.errors.push(`Файл слишком большой: ${filePath}`);
        return;
      }
    } catch (error) {
      result.errors.push(error instanceof Error ? error.message : String(error));
      return;
    }
    
    // Чтение файла
    let content: string;
    
    try {
      content = fs.readFileSync(filePath, this.config.fileEncoding);
    } catch (error) {
      result.errors.push(`Не удалось прочитать файл: ${filePath}`);
      return;
    }
    
    // Сканирование содержимого
    this.scanContent(content, filePath, result, LeakType.CODE_EXPOSURE);
  }

  /**
   * Сканирование директории
   */
  private async scanDirectory(dirPath: string, result: ScanResult): Promise<void> {
    let entries: fs.Dirent[];
    
    try {
      entries = fs.readdirSync(dirPath, { withFileTypes: true });
    } catch (error) {
      result.errors.push(error instanceof Error ? error.message : String(error));
      return;
    }
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      
      if (this.isExcluded(fullPath)) {
        continue;
      }
      
      if (entry.isFile()) {
        await this.scanFile(fullPath, result);
      } else if (entry.isDirectory()) {
        await this.scanDirectory(fullPath, result);
      }
    }
  }

  /**
   * Сканирование содержимого
   */
  private scanContent(
    content: string,
    location: string,
    result: ScanResult,
    leakType: LeakType
  ): void {
    const lines = content.split('\n');
    
    for (const [lineNum, line] of lines.entries()) {
      for (const pattern of this.config.patterns) {
        // Сброс lastIndex для глобальных regex
        pattern.regex.lastIndex = 0;
        
        let match: RegExpExecArray | null;
        
        while ((match = pattern.regex.exec(line)) !== null) {
          const matchedValue = match[0];
          const valueHash = this.hashValue(matchedValue);
          
          // Проверка на уже известный секрет
          if (this.knownSecretHashes.has(valueHash)) {
            continue;
          }
          
          // Создание обнаружения
          const detection: LeakDetection = {
            detectionId: this.generateDetectionId(),
            leakType,
            severity: pattern.severity,
            secretId: '', // Будет заполнено при сопоставлении
            secretName: pattern.name,
            description: `Обнаружен ${pattern.name} в ${location}:${lineNum + 1}`,
            location: `${location}:${lineNum + 1}`,
            detectedAt: new Date(),
            detectedBy: 'scanner',
            status: 'new',
            remediationSteps: this.getRemediationSteps(pattern.secretType),
            metadata: {
              pattern: pattern.name,
              secretType: pattern.secretType,
              lineContent: this.maskSecret(line, matchedValue),
              valueHash
            }
          };
          
          result.leaks.push(detection);
          this.detections.set(detection.detectionId, detection);
          
          // Добавление в известные хеши
          this.knownSecretHashes.add(valueHash);
          
          // Уведомление
          this.emit('leak:detected', detection);

          logger.warn(`[SecretScanner] Обнаружена утечка: ${pattern.name}`, {
            location,
            line: lineNum + 1
          });
        }
      }
    }
  }

  /**
   * Сканирование лога на наличие секретов
   */
  scanLog(logContent: string, logSource: string): LeakDetection[] {
    const result: ScanResult = {
      filePath: logSource,
      leaks: [],
      scannedAt: new Date(),
      errors: []
    };
    
    this.scanContent(logContent, logSource, result, LeakType.LOG_EXPOSURE);
    
    return result.leaks;
  }

  /**
   * Сканирование environment variables
   */
  scanEnvironment(): LeakDetection[] {
    const result: ScanResult = {
      filePath: 'process.env',
      leaks: [],
      scannedAt: new Date(),
      errors: []
    };
    
    const envContent = JSON.stringify(process.env, null, 2);
    
    this.scanContent(envContent, 'environment', result, LeakType.ENV_EXPOSURE);
    
    return result.leaks;
  }

  /**
   * Проверка значения на наличие в известных секретах
   * 
   * @param value - Значение для проверки
   * @param secretId - ID секрета
   * @returns Обнаружена ли утечка
   */
  checkSecretLeak(value: string, secretId: string): LeakDetection | null {
    const valueHash = this.hashValue(value);
    
    // Проверка в известных хешах
    if (this.knownSecretHashes.has(valueHash)) {
      // Поиск существующего обнаружения
      for (const detection of this.detections.values()) {
        if (detection.metadata?.valueHash === valueHash) {
          return detection;
        }
      }
    }
    
    // Сканирование на наличие значения в файлах
    for (const scanPath of this.config.scanPaths) {
      try {
        const stat = fs.statSync(scanPath);
        
        if (stat.isFile()) {
          const content = fs.readFileSync(scanPath, this.config.fileEncoding);
          
          if (content.includes(value)) {
            const detection: LeakDetection = {
              detectionId: this.generateDetectionId(),
              leakType: LeakType.CODE_EXPOSURE,
              severity: LeakSeverity.CRITICAL,
              secretId,
              secretName: 'Known Secret',
              description: `Известный секрет обнаружен в ${scanPath}`,
              location: scanPath,
              detectedAt: new Date(),
              detectedBy: 'leak-check',
              status: 'new',
              remediationSteps: [
                'Немедленно отозвать секрет',
                'Удалить секрет из кода',
                'Создать новый секрет',
                'Провести аудит доступа'
              ],
              metadata: {
                valueHash,
                originalSecretId: secretId
              }
            };
            
            this.detections.set(detection.detectionId, detection);
            this.emit('leak:detected', detection);
            
            return detection;
          }
        }
      } catch (error) {
        // Игнорируем ошибки чтения
      }
    }
    
    return null;
  }

  /**
   * Обнаружение подозрительного доступа
   * 
   * @param secretId - ID секрета
   * @param accessPattern - Паттерн доступа
   * @returns Обнаружена ли аномалия
   */
  detectSuspiciousAccess(
    secretId: string,
    accessPattern: {
      ipAddress: string;
      timestamp: Date;
      userAgent?: string;
      action: string;
    }
  ): LeakDetection | null {
    // Эвристики для обнаружения подозрительного доступа
    
    const anomalies: string[] = [];
    
    // Проверка на необычное время доступа
    const hour = accessPattern.timestamp.getHours();
    if (hour < 6 || hour > 22) {
      anomalies.push('Доступ в нерабочее время');
    }
    
    // Проверка на необычный user agent
    if (accessPattern.userAgent) {
      const suspiciousUA = [
        'curl',
        'wget',
        'python-requests',
        'httpie'
      ];
      
      if (suspiciousUA.some(ua => accessPattern.userAgent?.toLowerCase().includes(ua))) {
        anomalies.push('Подозрительный User-Agent');
      }
    }
    
    // Если есть аномалии - создаём обнаружение
    if (anomalies.length > 0) {
      const detection: LeakDetection = {
        detectionId: this.generateDetectionId(),
        leakType: LeakType.SUSPICIOUS_ACCESS,
        severity: LeakSeverity.MEDIUM,
        secretId,
        secretName: `Secret ${secretId}`,
        description: `Подозрительный доступ: ${anomalies.join(', ')}`,
        location: accessPattern.ipAddress,
        detectedAt: new Date(),
        detectedBy: 'anomaly-detection',
        status: 'new',
        remediationSteps: [
          'Проверить легитимность доступа',
          'При необходимости отозвать секрет',
          'Добавить IP в whitelist/blacklist',
          'Включить MFA'
        ],
        metadata: {
          ipAddress: accessPattern.ipAddress,
          userAgent: accessPattern.userAgent,
          action: accessPattern.action,
          anomalies
        }
      };
      
      this.detections.set(detection.detectionId, detection);
      this.emit('leak:detected', detection);
      
      return detection;
    }
    
    return null;
  }

  /**
   * Обнаружение брутфорс атаки
   * 
   * @param secretId - ID секрета
   * @param failedAttempts - Количество неудачных попыток
   * @param timeWindow - Временное окно (сек)
   * @returns Обнаружена ли атака
   */
  detectBruteForce(
    secretId: string,
    failedAttempts: number,
    timeWindow: number
  ): LeakDetection | null {
    const threshold = 10; // Порог срабатывания
    
    if (failedAttempts >= threshold) {
      const detection: LeakDetection = {
        detectionId: this.generateDetectionId(),
        leakType: LeakType.BRUTE_FORCE,
        severity: LeakSeverity.HIGH,
        secretId,
        secretName: `Secret ${secretId}`,
        description: `Обнаружена брутфорс атака: ${failedAttempts} неудачных попыток за ${timeWindow}s`,
        detectedAt: new Date(),
        detectedBy: 'brute-force-detection',
        status: 'new',
        remediationSteps: [
          'Временно заблокировать доступ',
          'Включить rate limiting',
          'Включить CAPTCHA',
          'Уведомить администратора'
        ],
        metadata: {
          failedAttempts,
          timeWindow,
          threshold
        }
      };
      
      this.detections.set(detection.detectionId, detection);
      this.emit('leak:detected', detection);
      
      return detection;
    }
    
    return null;
  }

  /**
   * Получить обнаружение по ID
   */
  getDetection(detectionId: string): LeakDetection | null {
    return this.detections.get(detectionId) ?? null;
  }

  /**
   * Получить все обнаружения
   */
  getAllDetections(status?: LeakDetection['status']): LeakDetection[] {
    const detections = Array.from(this.detections.values());
    
    if (status) {
      return detections.filter(d => d.status === status);
    }
    
    return detections;
  }

  /**
   * Обновить статус обнаружения
   */
  updateDetectionStatus(
    detectionId: string,
    status: LeakDetection['status']
  ): boolean {
    const detection = this.detections.get(detectionId);
    
    if (!detection) {
      return false;
    }
    
    detection.status = status;
    this.detections.set(detectionId, detection);
    
    this.emit('leak:status-updated', { detectionId, status });
    
    return true;
  }

  /**
   * Отметить как ложное срабатывание
   */
  markAsFalsePositive(detectionId: string): boolean {
    const detection = this.detections.get(detectionId);
    
    if (!detection) {
      return false;
    }
    
    detection.status = 'false_positive';
    this.stats.falsePositives++;

    // Удаление из известных хешей
    if (detection.metadata?.valueHash) {
      this.knownSecretHashes.delete(detection.metadata.valueHash);
    }

    logger.info(`[SecretScanner] Ложное срабатывание: ${detectionId}`);

    return true;
  }

  /**
   * Проверка исключения
   */
  private isExcluded(filePath: string): boolean {
    return this.config.excludePatterns.some(pattern => pattern.test(filePath));
  }

  /**
   * Хеширование значения
   */
  private hashValue(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  /**
   * Генерация ID обнаружения
   */
  private generateDetectionId(): string {
    return `leak_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Маскировка секрета в строке
   */
  private maskSecret(line: string, secret: string): string {
    if (secret.length <= 8) {
      return line.replace(secret, '***');
    }
    
    const masked = secret.slice(0, 4) + '***' + secret.slice(-4);
    return line.replace(secret, masked);
  }

  /**
   * Получение шагов по устранению
   */
  private getRemediationSteps(secretType: string): string[] {
    const steps: Record<string, string[]> = {
      aws_access_key: [
        'Немедленно отозвать AWS access key в IAM Console',
        'Создать новый access key',
        'Обновить все системы, использующие старый ключ',
        'Проверить CloudTrail на предмет несанкционированного доступа'
      ],
      github_token: [
        'Отозвать токен в GitHub Settings > Developer Settings',
        'Создать новый токен',
        'Проверить GitHub audit log',
        'Включить SSO для организации'
      ],
      private_key: [
        'Сгенерировать новую ключевую пару',
        'Заменить публичный ключ на всех серверах',
        'Отозвать старый приватный ключ',
        'Проверить логи доступа'
      ],
      db_connection: [
        'Сменить пароль пользователя БД',
        'Обновить конфигурацию приложений',
        'Проверить логи БД на предмет несанкционированного доступа',
        'Включить шифрование соединений'
      ],
      jwt: [
        'Сменить секретный ключ подписи JWT',
        'Инвалидировать все выданные токены',
        'Требовать повторную аутентификацию',
        'Проверить логи аутентификации'
      ]
    };
    
    return steps[secretType] ?? [
      'Отозвать скомпрометированный секрет',
      'Создать новый секрет',
      'Обновить конфигурацию',
      'Провести аудит доступа'
    ];
  }

  /**
   * Получить статистику сканера
   */
  getStats(): ScanStats {
    return { ...this.stats };
  }

  /**
   * Добавить известный хеш секрета
   * 
   * @param secretValue - Значение секрета
   */
  addKnownSecret(secretValue: string): void {
    const hash = this.hashValue(secretValue);
    this.knownSecretHashes.add(hash);
  }

  /**
   * Удалить известный хеш секрета
   * 
   * @param secretValue - Значение секрета
   */
  removeKnownSecret(secretValue: string): void {
    const hash = this.hashValue(secretValue);
    this.knownSecretHashes.delete(hash);
  }

  /**
   * Очистить все известные хеши
   */
  clearKnownSecrets(): void {
    this.knownSecretHashes.clear();
  }

  /**
   * Экспорт отчёта об обнаружениях
   */
  exportReport(): {
    generatedAt: Date;
    totalDetections: number;
    byStatus: Record<string, number>;
    bySeverity: Record<string, number>;
    byType: Record<string, number>;
    detections: LeakDetection[];
  } {
    const byStatus: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const byType: Record<string, number> = {};
    
    for (const detection of this.detections.values()) {
      byStatus[detection.status] = (byStatus[detection.status] ?? 0) + 1;
      bySeverity[detection.severity] = (bySeverity[detection.severity] ?? 0) + 1;
      byType[detection.leakType] = (byType[detection.leakType] ?? 0) + 1;
    }
    
    return {
      generatedAt: new Date(),
      totalDetections: this.detections.size,
      byStatus,
      bySeverity,
      byType,
      detections: Array.from(this.detections.values())
    };
  }
}
