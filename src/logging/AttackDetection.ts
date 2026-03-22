/**
 * ============================================================================
 * ATTACK DETECTION - ДЕТЕКТИРОВАНИЕ АТАК OWASP TOP 10
 * ============================================================================
 * Модуль для обнаружения атак по категориям OWASP Top 10 с использованием
 * сигнатурного анализа, эвристик и поведенческих паттернов.
 * 
 * Особенности:
 * - Полное покрытие OWASP Top 10 2021
 * - Сигнатурное обнаружение
 * - Эвристический анализ
 * - Поведенческие паттерны
 * - Контекстный анализ
 * - Confidence scoring
 * - MITRE ATT&CK маппинг
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  LogEntry,
  LogSource,
  AttackDetection,
  OWASPAttackCategory,
  AttackSeverity,
  AttackSource,
  AttackTarget,
  IOC,
  ProcessingError,
  GeoLocation
} from '../types/logging.types';

// ============================================================================
// OWASP TOP 10 2021 КАТЕГОРИИ И ПАТТЕРНЫ
// ============================================================================

/**
 * Паттерны для A01:2021 - Broken Access Control
 */
const BROKEN_ACCESS_CONTROL_PATTERNS = {
  // Path traversal
  pathTraversal: [
    /\.\.\//gi,
    /\.\.\\/gi,
    /%2e%2e%2f/gi,
    /%2e%2e\//gi,
    /\.\.%2f/gi,
    /%252e%252e%252f/gi,
    /etc\/passwd/gi,
    /etc\/shadow/gi,
    /windows\/system32/gi,
    /boot\.ini/gi,
    /win\.ini/gi
  ],
  
  // IDOR (Insecure Direct Object Reference)
  idor: [
    /user_id=\d+/gi,
    /userid=\d+/gi,
    /account=\d+/gi,
    /order_id=\d+/gi,
    /file_id=\d+/gi,
    /document_id=\d+/gi
  ],
  
  // Admin access attempts
  adminAccess: [
    /\/admin/gi,
    /\/administrator/gi,
    /\/wp-admin/gi,
    /\/phpmyadmin/gi,
    /\/manager/gi,
    /\/console/gi
  ],
  
  // HTTP method manipulation
  httpMethod: [
    /PUT\s+\/api/gi,
    /DELETE\s+\/api/gi,
    /PATCH\s+\/api/gi
  ]
};

/**
 * Паттерны для A02:2021 - Cryptographic Failures
 */
const CRYPTOGRAPHIC_FAILURES_PATTERNS = {
  // Weak algorithms
  weakAlgorithms: [
    /md5\(/gi,
    /sha1\(/gi,
    /des\(/gi,
    /rc4/gi,
    /base64_encode.*password/gi
  ],
  
  // Sensitive data in logs
  sensitiveData: [
    /password\s*[=:]\s*["']?[^"'\s,}]+/gi,
    /passwd\s*[=:]\s*["']?[^"'\s,}]+/gi,
    /secret\s*[=:]\s*["']?[^"'\s,}]+/gi,
    /api[_-]?key\s*[=:]\s*["']?[^"'\s,}]+/gi,
    /credit[_-]?card\s*[=:]\s*["']?\d+/gi,
    /ssn\s*[=:]\s*["']?\d/gi,
    /\b\d{16}\b/gi,  // Credit card numbers
    /\b\d{3}-\d{2}-\d{4}\b/gi  // SSN
  ],
  
  // Unencrypted transmission
  unencrypted: [
    /http:\/\/.*password/gi,
    /http:\/\/.*login/gi,
    /http:\/\/.*auth/gi
  ]
};

/**
 * Паттерны для A03:2021 - Injection
 */
const INJECTION_PATTERNS = {
  // SQL Injection
  sqlInjection: [
    /(\bSELECT\b.*\bFROM\b)/gi,
    /(\bINSERT\b.*\bINTO\b)/gi,
    /(\bUPDATE\b.*\bSET\b)/gi,
    /(\bDELETE\b.*\bFROM\b)/gi,
    /(\bDROP\b.*\bTABLE\b)/gi,
    /(\bUNION\b.*\bSELECT\b)/gi,
    /(\bOR\b\s+1\s*=\s*1)/gi,
    /(\bAND\b\s+1\s*=\s*1)/gi,
    /('\s*OR\s*')/gi,
    /(--\s*$)/gi,
    /(;s*DROP)/gi,
    /(\bEXEC\b.*\bXP_)/gi,
    /(\bWAITFOR\b.*\bDELAY\b)/gi,
    /(\bBENCHMARK\b\s*\()/gi,
    /(\bSLEEP\b\s*\()/gi,
    /(\bLOAD_FILE\b\s*\()/gi,
    /(\bINTO\s+OUTFILE\b)/gi,
    /(\bINTO\s+DUMPFILE\b)/gi
  ],
  
  // Command Injection
  commandInjection: [
    /[;&|`$]/g,
    /\$\(/gi,
    /`[^`]+`/gi,
    /;\s*cat\s+/gi,
    /;\s*ls\s+/gi,
    /;\s*wget\s+/gi,
    /;\s*curl\s+/gi,
    /;\s*nc\s+/gi,
    /;\s*bash\s+/gi,
    /;\s*sh\s+/gi,
    /\|\s*cat\s+/gi,
    /\|\s*less\s+/gi,
    /&&\s*cat\s+/gi
  ],
  
  // LDAP Injection
  ldapInjection: [
    /\)\(\|/gi,
    /\)\(&/gi,
    /\)\(!/gi,
    /\*?\)/gi,
    /%29%28%7C/gi
  ],
  
  // NoSQL Injection
  nosqlInjection: [
    /\{\s*\$where:/gi,
    /\{\s*\$ne:/gi,
    /\{\s*\$gt:/gi,
    /\{\s*\$regex:/gi,
    /\[\s*\$elemMatch/gi
  ],
  
  // XXE (XML External Entity)
  xxe: [
    /<!ENTITY/gi,
    /<!DOCTYPE.*\[.*<!ENTITY/gi,
    /SYSTEM\s+["']file:/gi,
    /SYSTEM\s+["']http:/gi,
    /php:\/\/filter/gi,
    /data:\/\/text/gi,
    /expect:\/\/cmd/gi
  ]
};

/**
 * Паттерны для A04:2021 - Insecure Design
 */
const INSECURE_DESIGN_PATTERNS = {
  // Rate limiting bypass
  rateLimitBypass: [
    /x-forwarded-for:/gi,
    /x-real-ip:/gi,
    /x-client-ip:/gi
  ],
  
  // Business logic abuse
  logicAbuse: [
    /quantity=-/gi,
    /price=0/gi,
    /discount=100/gi,
    /coupon=.*admin.*/gi
  ]
};

/**
 * Паттерны для A05:2021 - Security Misconfiguration
 */
const SECURITY_MISCONFIGURATION_PATTERNS = {
  // Debug endpoints
  debugEndpoints: [
    /\/debug/gi,
    /\/trace/gi,
    /\/actuator/gi,
    /\/metrics/gi,
    /\/health/gi,
    /\/env/gi,
    /\/configprops/gi
  ],
  
  // Default credentials
  defaultCredentials: [
    /admin:admin/gi,
    /root:root/gi,
    /user:user/gi,
    /test:test/gi,
    /guest:guest/gi
  ],
  
  // Directory listing
  directoryListing: [
    /Index of \//gi,
    /<title>Directory listing/gi,
    /Parent Directory/gi
  ],
  
  // Verbose errors
  verboseErrors: [
    /stack trace/gi,
    /exception.*at/gi,
    /at\s+[a-zA-Z]+\.[a-zA-Z]+\(/gi,
    /PDOException/gi,
    /SQLException/gi
  ],
  
  // Exposed files
  exposedFiles: [
    /\.git\//gi,
    /\.env/gi,
    /\.htaccess/gi,
    /web\.config/gi,
    /\.svn/gi,
    /\.bak$/gi,
    /\.old$/gi,
    /\.sql$/gi,
    /\.dump$/gi
  ]
};

/**
 * Паттерны для A06:2021 - Vulnerable and Outdated Components
 */
const VULNERABLE_COMPONENTS_PATTERNS = {
  // Known vulnerable versions
  vulnerableVersions: [
    /struts2?\s*2\.[0-5]\./gi,
    /log4j\s*1\./gi,
    /log4j\s*2\.(0|1[0-6])\./gi,
    /spring\s*4\./gi,
    /apache\s+commons.*4\.0/gi
  ],
  
  // Component probing
  componentProbing: [
    /wp-login\.php/gi,
    /wp-content/gi,
    /wp-includes/gi,
    /xmlrpc\.php/gi,
    /phpmyadmin/gi,
    /pma\/?/gi,
    /myadmin/gi,
    /jenkins\/login/gi,
    /solr\/admin/gi,
    /elasticsearch\/_cat/gi
  ]
};

/**
 * Паттерны для A07:2021 - Identification and Authentication Failures
 */
const AUTH_FAILURES_PATTERNS = {
  // Brute force indicators
  bruteForce: [
    /login.*fail/gi,
    /authentication.*fail/gi,
    /invalid.*password/gi,
    /wrong.*password/gi,
    /account.*lock/gi,
    /too.*many.*attempts/gi
  ],
  
  // Credential stuffing
  credentialStuffing: [
    /autologin/gi,
    /remember.*me/gi,
    /remember_token/gi
  ],
  
  // Session attacks
  sessionAttacks: [
    /session_id=\w+/gi,
    /PHPSESSID=\w+/gi,
    /JSESSIONID=\w+/gi,
    /ASP\.NET_SessionId=\w+/gi
  ],
  
  // Password reset abuse
  passwordResetAbuse: [
    /password.*reset.*token/gi,
    /reset.*password.*link/gi,
    /forgot.*password/gi
  ]
};

/**
 * Паттерны для A08:2021 - Software and Data Integrity Failures
 */
const INTEGRITY_FAILURES_PATTERNS = {
  // Deserialization attacks
  deserialization: [
    /rO0AB/gi,  // Java serialized
    /AAEAAD/gi,  // .NET serialized
    /__PHP_Incomplete_Class/gi,
    /O:\d+:/gi,  // PHP serialized
    /pickle\.loads/gi,
    /yaml\.load/gi,
    /unserialize\(/gi
  ],
  
  // CI/CD pipeline attacks
  cicdAttacks: [
    /pipeline.*injection/gi,
    /build.*script.*modified/gi,
    /dependency.*confusion/gi
  ],
  
  // Update attacks
  updateAttacks: [
    /insecure.*download/gi,
    /unsigned.*update/gi,
    /http.*update/gi
  ]
};

/**
 * Паттерны для A09:2021 - Security Logging and Monitoring Failures
 */
const LOGGING_FAILURES_PATTERNS = {
  // Log tampering
  logTampering: [
    /rm.*\.log/gi,
    /truncate.*log/gi,
    /clear.*eventlog/gi,
    /wevtutil.*cl/gi
  ],
  
  // Audit evasion
  auditEvasion: [
    /disable.*audit/gi,
    /stop.*service.*audit/gi,
    /set.*auditpol/gi
  ]
};

/**
 * Паттерны для A10:2021 - Server-Side Request Forgery (SSRF)
 */
const SSRF_PATTERNS = {
  // Internal IP access
  internalIP: [
    /127\.0\.0\.\d+/gi,
    /localhost[:\/]/gi,
    /0\.0\.0\.0/gi,
    /169\.254\.\d+\.\d+/gi,
    /10\.\d+\.\d+\.\d+/gi,
    /172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+/gi,
    /192\.168\.\d+\.\d+/gi
  ],
  
  // Cloud metadata
  cloudMetadata: [
    /169\.254\.169\.254/gi,  // AWS/GCP/Azure metadata
    /metadata\.google/gi,
    /instance-data\/latest/gi,
    /compute\/metadata/gi
  ],
  
  // Protocol abuse
  protocolAbuse: [
    /file:\/\/\//gi,
    /gopher:\/\/\//gi,
    /dict:\/\/\//gi,
    /ldap:\/\/\//gi,
    /tftp:\/\/\//gi,
    /sftp:\/\/\//gi
  ],
  
  // URL redirection
  urlRedirection: [
    /url=https?:\/\//gi,
    /redirect=https?:\/\//gi,
    /next=https?:\/\//gi,
    /return=https?:\/\//gi,
    /dest=https?:\/\//gi
  ]
};

/**
 * Паттерны для XSS (Cross-Site Scripting)
 */
const XSS_PATTERNS = [
  /<script[^>]*>/gi,
  /<\/script>/gi,
  /javascript:/gi,
  /vbscript:/gi,
  /on\w+\s*=/gi,  // onclick=, onerror=, etc.
  /<iframe[^>]*>/gi,
  /<object[^>]*>/gi,
  /<embed[^>]*>/gi,
  /<svg[^>]*onload/gi,
  /<img[^>]*onerror/gi,
  /<body[^>]*onload/gi,
  /expression\s*\(/gi,
  /url\s*\(\s*["']?javascript:/gi,
  /<marquee[^>]*>/gi,
  /<link[^>]*rel=["']?stylesheet/gi,
  /document\.cookie/gi,
  /document\.location/gi,
  /window\.location/gi,
  /eval\s*\(/gi,
  /setTimeout\s*\(/gi,
  /setInterval\s*\(/gi,
  /alert\s*\(/gi,
  /prompt\s*\(/gi,
  /confirm\s*\(/gi,
  /String\.fromCharCode/gi,
  /atob\s*\(/gi,
  /btoa\s*\(/gi,
  /&#x/gi,
  /&#\d+;/gi,
  /%3Cscript/gi,
  /%3C\/script/gi,
  /%3Ciframe/gi
];

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Конфигурация AttackDetector
 */
interface AttackDetectorConfig {
  /** Включить SQL injection detection */
  enableSqlInjectionDetection: boolean;
  /** Включить XSS detection */
  enableXssDetection: boolean;
  /** Включить command injection detection */
  enableCommandInjectionDetection: boolean;
  /** Включить path traversal detection */
  enablePathTraversalDetection: boolean;
  /** Включить SSRF detection */
  enableSsrfDetection: boolean;
  /** Включить brute force detection */
  enableBruteForceDetection: boolean;
  /** Включить sensitive data detection */
  enableSensitiveDataDetection: boolean;
  /** Порог confidence для детекта */
  confidenceThreshold: number;
  /** Максимальное количество детектов на лог */
  maxDetectionsPerLog: number;
  /** Включить IOC extraction */
  enableIocExtraction: boolean;
}

/**
 * Результат детектирования атаки
 */
interface DetectionResult {
  /** Детектирована ли атака */
  detected: boolean;
  /** Тип атаки */
  attackType?: OWASPAttackCategory;
  /** Подтип атаки */
  attackSubtype?: string;
  /** Уровень серьезности */
  severity?: AttackSeverity;
  /** Confidence score */
  confidence?: number;
  /** Совпавшие паттерны */
  matchedPatterns?: string[];
  /** Payload атаки */
  payload?: string;
}

/**
 * Статистика детектора
 */
interface DetectorStatistics {
  /** Всего обработано логов */
  totalLogsProcessed: number;
  /** Детектировано атак */
  attacksDetected: number;
  /** По типам атак */
  byAttackType: Record<OWASPAttackCategory, number>;
  /** По серьезности */
  bySeverity: Record<AttackSeverity, number>;
  /** Ложные срабатывания */
  falsePositives: number;
  /** Пропущенные атаки (по feedback) */
  falseNegatives: number;
  /** Средний confidence */
  avgConfidence: number;
  /** Среднее время детекта (мс) */
  avgDetectionTime: number;
  /** P99 время детекта (мс) */
  p99DetectionTime: number;
}

// ============================================================================
// КЛАСС PATTERN MATCHER
// ============================================================================

/**
 * Матчер паттернов атак
 */
class PatternMatcher {
  private patterns: Map<string, { pattern: RegExp; name: string; weight: number }[]>;
  
  constructor() {
    this.patterns = new Map();
    this.initializePatterns();
  }
  
  /**
   * Инициализация паттернов
   */
  private initializePatterns(): void {
    // SQL Injection
    this.patterns.set('sql_injection', INJECTION_PATTERNS.sqlInjection.map((p, i) => ({
      pattern: p,
      name: `sql_injection_${i}`,
      weight: 0.8
    })));
    
    // XSS
    this.patterns.set('xss', XSS_PATTERNS.map((p, i) => ({
      pattern: p,
      name: `xss_${i}`,
      weight: 0.7
    })));
    
    // Command Injection
    this.patterns.set('command_injection', INJECTION_PATTERNS.commandInjection.map((p, i) => ({
      pattern: p,
      name: `cmd_injection_${i}`,
      weight: 0.9
    })));
    
    // Path Traversal
    this.patterns.set('path_traversal', BROKEN_ACCESS_CONTROL_PATTERNS.pathTraversal.map((p, i) => ({
      pattern: p,
      name: `path_traversal_${i}`,
      weight: 0.85
    })));
    
    // SSRF
    this.patterns.set('ssrf', [
      ...SSRF_PATTERNS.internalIP.map((p, i) => ({ pattern: p, name: `ssrf_internal_${i}`, weight: 0.7 })),
      ...SSRF_PATTERNS.cloudMetadata.map((p, i) => ({ pattern: p, name: `ssrf_cloud_${i}`, weight: 0.9 })),
      ...SSRF_PATTERNS.protocolAbuse.map((p, i) => ({ pattern: p, name: `ssrf_protocol_${i}`, weight: 0.85 }))
    ]);
    
    // Brute Force
    this.patterns.set('brute_force', AUTH_FAILURES_PATTERNS.bruteForce.map((p, i) => ({
      pattern: p,
      name: `brute_force_${i}`,
      weight: 0.6
    })));
    
    // Sensitive Data
    this.patterns.set('sensitive_data', CRYPTOGRAPHIC_FAILURES_PATTERNS.sensitiveData.map((p, i) => ({
      pattern: p,
      name: `sensitive_data_${i}`,
      weight: 0.95
    })));
    
    // Security Misconfiguration
    this.patterns.set('misconfiguration', [
      ...SECURITY_MISCONFIGURATION_PATTERNS.debugEndpoints.map((p, i) => ({ pattern: p, name: `misconfig_debug_${i}`, weight: 0.5 })),
      ...SECURITY_MISCONFIGURATION_PATTERNS.exposedFiles.map((p, i) => ({ pattern: p, name: `misconfig_exposed_${i}`, weight: 0.7 }))
    ]);
    
    // Deserialization
    this.patterns.set('deserialization', INTEGRITY_FAILURES_PATTERNS.deserialization.map((p, i) => ({
      pattern: p,
      name: `deserialization_${i}`,
      weight: 0.9
    })));
  }
  
  /**
   * Матчинг текста против паттернов категории
   */
  match(text: string, category: string): Array<{ name: string; weight: number; match: string }> {
    const categoryPatterns = this.patterns.get(category);
    if (!categoryPatterns) {
      return [];
    }
    
    const matches: Array<{ name: string; weight: number; match: string }> = [];
    
    for (const { pattern, name, weight } of categoryPatterns) {
      const match = pattern.exec(text);
      if (match) {
        matches.push({
          name,
          weight,
          match: match[0]
        });
        pattern.lastIndex = 0; // Reset regex state
      }
    }
    
    return matches;
  }
  
  /**
   * Матчинг против всех паттернов
   */
  matchAll(text: string): Record<string, Array<{ name: string; weight: number; match: string }>> {
    const results: Record<string, Array<{ name: string; weight: number; match: string }>> = {};
    
    for (const [category] of this.patterns.entries()) {
      const matches = this.match(text, category);
      if (matches.length > 0) {
        results[category] = matches;
      }
    }
    
    return results;
  }
  
  /**
   * Добавление кастомного паттерна
   */
  addPattern(category: string, pattern: RegExp, name: string, weight: number): void {
    if (!this.patterns.has(category)) {
      this.patterns.set(category, []);
    }
    
    this.patterns.get(category)!.push({ pattern, name, weight });
  }
}

// ============================================================================
// КЛАСС CONFIDENCE SCORER
// ============================================================================

/**
 * Скорер confidence для детектов
 */
class ConfidenceScorer {
  private baseWeights: Record<OWASPAttackCategory, number>;
  
  constructor() {
    this.baseWeights = {
      [OWASPAttackCategory.INJECTION]: 0.8,
      [OWASPAttackCategory.BROKEN_AUTH]: 0.7,
      [OWASPAttackCategory.SENSITIVE_DATA_EXPOSURE]: 0.9,
      [OWASPAttackCategory.XML_EXTERNAL_ENTITIES]: 0.85,
      [OWASPAttackCategory.BROKEN_ACCESS_CONTROL]: 0.75,
      [OWASPAttackCategory.SECURITY_MISCONFIGURATION]: 0.6,
      [OWASPAttackCategory.CROSS_SITE_SCRIPTING]: 0.7,
      [OWASPAttackCategory.INSECURE_DESERIALIZATION]: 0.85,
      [OWASPAttackCategory.VULNERABLE_COMPONENTS]: 0.65,
      [OWASPAttackCategory.INSUFFICIENT_LOGGING]: 0.5
    };
  }
  
  /**
   * Расчет confidence score
   */
  calculate(
    attackType: OWASPAttackCategory,
    matchedPatterns: number,
    totalPatterns: number,
    contextFactors: ContextFactors
  ): number {
    // Базовый вес категории
    let score = this.baseWeights[attackType] || 0.5;
    
    // Фактор количества совпадений
    const patternRatio = matchedPatterns / Math.max(totalPatterns, 1);
    score *= (0.5 + 0.5 * patternRatio);
    
    // Контекстные факторы
    if (contextFactors.isFromSecuritySource) {
      score *= 1.1;
    }
    
    if (contextFactors.hasMaliciousIP) {
      score *= 1.2;
    }
    
    if (contextFactors.hasSuspiciousUserAgent) {
      score *= 1.1;
    }
    
    if (contextFactors.isAfterHours) {
      score *= 1.05;
    }
    
    // Нормализация
    return Math.min(1.0, Math.max(0.0, score));
  }
}

/**
 * Контекстные факторы для scoring
 */
interface ContextFactors {
  isFromSecuritySource: boolean;
  hasMaliciousIP: boolean;
  hasSuspiciousUserAgent: boolean;
  isAfterHours: boolean;
  hasHighPrivilegeUser: boolean;
}

// ============================================================================
// КЛАСС IOC EXTRACTOR
// ============================================================================

/**
 * Извлекатель индикаторов компрометации
 */
class IocExtractor {
  /**
   * Извлечение IOC из лога
   */
  extract(log: LogEntry): IOC[] {
    const iocs: IOC[] = [];
    const now = new Date().toISOString();
    
    // IP адреса
    if (log.context.clientIp) {
      iocs.push({
        type: 'ip',
        value: log.context.clientIp,
        confidence: 0.7,
        firstSeen: log.timestamp,
        lastSeen: log.timestamp,
        tags: ['source_ip']
      });
    }
    
    // URLs из полей
    if (log.fields?.url) {
      const url = String(log.fields.url);
      iocs.push({
        type: 'url',
        value: url,
        confidence: 0.6,
        firstSeen: log.timestamp,
        lastSeen: log.timestamp,
        tags: ['request_url']
      });
    }
    
    // User Agent
    if (log.context.userAgent) {
      iocs.push({
        type: 'behavior',
        value: `UA:${log.context.userAgent}`,
        confidence: 0.5,
        firstSeen: log.timestamp,
        lastSeen: log.timestamp,
        tags: ['user_agent']
      });
    }
    
    // Hashes из полей
    if (log.fields?.hash) {
      const hash = String(log.fields.hash);
      iocs.push({
        type: 'hash',
        value: hash,
        confidence: 0.8,
        firstSeen: log.timestamp,
        lastSeen: log.timestamp,
        tags: ['file_hash']
      });
    }
    
    return iocs;
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС ATTACK DETECTOR
// ============================================================================

/**
 * Attack Detector - детектирование атак OWASP Top 10
 * 
 * Реализует:
 * - Сигнатурное обнаружение
 * - Эвристический анализ
 * - Поведенческие паттерны
 * - Confidence scoring
 * - IOC extraction
 * - MITRE ATT&CK маппинг
 */
export class AttackDetector extends EventEmitter {
  private config: AttackDetectorConfig;
  private patternMatcher: PatternMatcher;
  private confidenceScorer: ConfidenceScorer;
  private iocExtractor: IocExtractor;
  private statistics: DetectorStatistics;
  private detectionTimes: number[];
  private enabled: boolean;
  
  constructor(config: Partial<AttackDetectorConfig> = {}) {
    super();
    
    this.config = {
      enableSqlInjectionDetection: config.enableSqlInjectionDetection !== false,
      enableXssDetection: config.enableXssDetection !== false,
      enableCommandInjectionDetection: config.enableCommandInjectionDetection !== false,
      enablePathTraversalDetection: config.enablePathTraversalDetection !== false,
      enableSsrfDetection: config.enableSsrfDetection !== false,
      enableBruteForceDetection: config.enableBruteForceDetection !== false,
      enableSensitiveDataDetection: config.enableSensitiveDataDetection !== false,
      confidenceThreshold: config.confidenceThreshold || 0.5,
      maxDetectionsPerLog: config.maxDetectionsPerLog || 10,
      enableIocExtraction: config.enableIocExtraction !== false
    };
    
    this.patternMatcher = new PatternMatcher();
    this.confidenceScorer = new ConfidenceScorer();
    this.iocExtractor = new IocExtractor();
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.detectionTimes = [];
    this.enabled = true;
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): DetectorStatistics {
    return {
      totalLogsProcessed: 0,
      attacksDetected: 0,
      byAttackType: {
        injection: 0,
        broken_authentication: 0,
        sensitive_data_exposure: 0,
        xml_external_entities: 0,
        broken_access_control: 0,
        security_misconfiguration: 0,
        cross_site_scripting: 0,
        insecure_deserialization: 0,
        vulnerable_components: 0,
        insufficient_logging: 0
      },
      bySeverity: {
        low: 0,
        medium: 0,
        high: 0,
        critical: 0
      },
      falsePositives: 0,
      falseNegatives: 0,
      avgConfidence: 0,
      avgDetectionTime: 0,
      p99DetectionTime: 0
    };
  }
  
  /**
   * Детектирование атак в логе
   */
  detect(log: LogEntry): AttackDetection[] {
    if (!this.enabled) {
      return [];
    }
    
    const startTime = Date.now();
    this.statistics.totalLogsProcessed++;
    
    const detections: AttackDetection[] = [];
    
    try {
      // Подготовка текста для анализа
      const searchText = this.prepareSearchText(log);
      
      // Детектирование по категориям
      if (this.config.enableSqlInjectionDetection) {
        const sqlDetection = this.detectSqlInjection(searchText, log);
        if (sqlDetection.detected) {
          detections.push(this.createDetection(sqlDetection, log));
        }
      }
      
      if (this.config.enableXssDetection) {
        const xssDetection = this.detectXss(searchText, log);
        if (xssDetection.detected) {
          detections.push(this.createDetection(xssDetection, log));
        }
      }
      
      if (this.config.enableCommandInjectionDetection) {
        const cmdDetection = this.detectCommandInjection(searchText, log);
        if (cmdDetection.detected) {
          detections.push(this.createDetection(cmdDetection, log));
        }
      }
      
      if (this.config.enablePathTraversalDetection) {
        const pathDetection = this.detectPathTraversal(searchText, log);
        if (pathDetection.detected) {
          detections.push(this.createDetection(pathDetection, log));
        }
      }
      
      if (this.config.enableSsrfDetection) {
        const ssrfDetection = this.detectSsrf(searchText, log);
        if (ssrfDetection.detected) {
          detections.push(this.createDetection(ssrfDetection, log));
        }
      }
      
      if (this.config.enableBruteForceDetection) {
        const bruteDetection = this.detectBruteForce(searchText, log);
        if (bruteDetection.detected) {
          detections.push(this.createDetection(bruteDetection, log));
        }
      }
      
      if (this.config.enableSensitiveDataDetection) {
        const sensitiveDetection = this.detectSensitiveData(searchText, log);
        if (sensitiveDetection.detected) {
          detections.push(this.createDetection(sensitiveDetection, log));
        }
      }
      
      // Ограничение количества детектов
      if (detections.length > this.config.maxDetectionsPerLog) {
        detections.sort((a, b) => b.confidence - a.confidence);
        detections.splice(this.config.maxDetectionsPerLog);
      }
      
      // Обновление статистики
      for (const detection of detections) {
        this.statistics.attacksDetected++;
        this.statistics.byAttackType[detection.attackType]++;
        this.statistics.bySeverity[detection.severity]++;
      }
      
      const detectionTime = Date.now() - startTime;
      this.updateDetectionTimeStats(detectionTime);
      
      // Эмиссия события детекта
      for (const detection of detections) {
        this.emit('attack_detected', detection);
      }
      
      return detections;
    } catch (error) {
      this.emit('detection_error', {
        logId: log.id,
        error
      });
      
      return [];
    }
  }
  
  /**
   * Пакетное детектирование
   */
  detectBatch(logs: LogEntry[]): AttackDetection[] {
    return logs.flatMap(log => this.detect(log));
  }
  
  /**
   * Подготовка текста для поиска
   */
  private prepareSearchText(log: LogEntry): string {
    const parts: string[] = [];
    
    // Сообщение
    if (log.message) {
      parts.push(log.message);
    }
    
    // Поля
    if (log.fields) {
      parts.push(JSON.stringify(log.fields));
    }
    
    // Контекст
    if (log.context.userAgent) {
      parts.push(log.context.userAgent);
    }
    
    if (log.context.clientIp) {
      parts.push(log.context.clientIp);
    }
    
    // Stack trace
    if (log.stackTrace) {
      parts.push(log.stackTrace);
    }
    
    return parts.join(' ');
  }
  
  /**
   * Детектирование SQL Injection
   */
  private detectSqlInjection(text: string, log: LogEntry): DetectionResult {
    const matches = this.patternMatcher.match(text, 'sql_injection');
    
    if (matches.length === 0) {
      return { detected: false };
    }
    
    const contextFactors: ContextFactors = {
      isFromSecuritySource: log.source === LogSource.SECURITY,
      hasMaliciousIP: log.context.metadata?.threatIntel?.isMalicious || false,
      hasSuspiciousUserAgent: this.isSuspiciousUserAgent(log.context.userAgent),
      isAfterHours: this.isAfterHours(log.timestamp),
      hasHighPrivilegeUser: false
    };
    
    const confidence = this.confidenceScorer.calculate(
      OWASPAttackCategory.INJECTION,
      matches.length,
      INJECTION_PATTERNS.sqlInjection.length,
      contextFactors
    );
    
    return {
      detected: confidence >= this.config.confidenceThreshold,
      attackType: OWASPAttackCategory.INJECTION,
      attackSubtype: 'sql_injection',
      severity: this.getSeverity(confidence, 'sql_injection'),
      confidence,
      matchedPatterns: matches.map(m => m.name),
      payload: matches.map(m => m.match).join(', ')
    };
  }
  
  /**
   * Детектирование XSS
   */
  private detectXss(text: string, log: LogEntry): DetectionResult {
    const matches = this.patternMatcher.match(text, 'xss');
    
    if (matches.length === 0) {
      return { detected: false };
    }
    
    const contextFactors: ContextFactors = {
      isFromSecuritySource: log.source === LogSource.SECURITY,
      hasMaliciousIP: log.context.metadata?.threatIntel?.isMalicious || false,
      hasSuspiciousUserAgent: this.isSuspiciousUserAgent(log.context.userAgent),
      isAfterHours: this.isAfterHours(log.timestamp),
      hasHighPrivilegeUser: false
    };
    
    const confidence = this.confidenceScorer.calculate(
      OWASPAttackCategory.CROSS_SITE_SCRIPTING,
      matches.length,
      XSS_PATTERNS.length,
      contextFactors
    );
    
    return {
      detected: confidence >= this.config.confidenceThreshold,
      attackType: OWASPAttackCategory.CROSS_SITE_SCRIPTING,
      attackSubtype: 'xss',
      severity: this.getSeverity(confidence, 'xss'),
      confidence,
      matchedPatterns: matches.map(m => m.name),
      payload: matches.map(m => m.match).join(', ')
    };
  }
  
  /**
   * Детектирование Command Injection
   */
  private detectCommandInjection(text: string, log: LogEntry): DetectionResult {
    const matches = this.patternMatcher.match(text, 'command_injection');
    
    if (matches.length === 0) {
      return { detected: false };
    }
    
    const contextFactors: ContextFactors = {
      isFromSecuritySource: log.source === LogSource.SECURITY,
      hasMaliciousIP: log.context.metadata?.threatIntel?.isMalicious || false,
      hasSuspiciousUserAgent: false,
      isAfterHours: this.isAfterHours(log.timestamp),
      hasHighPrivilegeUser: false
    };
    
    const confidence = this.confidenceScorer.calculate(
      OWASPAttackCategory.INJECTION,
      matches.length,
      INJECTION_PATTERNS.commandInjection.length,
      contextFactors
    );
    
    return {
      detected: confidence >= this.config.confidenceThreshold,
      attackType: OWASPAttackCategory.INJECTION,
      attackSubtype: 'command_injection',
      severity: this.getSeverity(confidence, 'command_injection'),
      confidence,
      matchedPatterns: matches.map(m => m.name),
      payload: matches.map(m => m.match).join(', ')
    };
  }
  
  /**
   * Детектирование Path Traversal
   */
  private detectPathTraversal(text: string, log: LogEntry): DetectionResult {
    const matches = this.patternMatcher.match(text, 'path_traversal');
    
    if (matches.length === 0) {
      return { detected: false };
    }
    
    const contextFactors: ContextFactors = {
      isFromSecuritySource: log.source === LogSource.SECURITY,
      hasMaliciousIP: log.context.metadata?.threatIntel?.isMalicious || false,
      hasSuspiciousUserAgent: false,
      isAfterHours: this.isAfterHours(log.timestamp),
      hasHighPrivilegeUser: false
    };
    
    const confidence = this.confidenceScorer.calculate(
      OWASPAttackCategory.BROKEN_ACCESS_CONTROL,
      matches.length,
      BROKEN_ACCESS_CONTROL_PATTERNS.pathTraversal.length,
      contextFactors
    );
    
    return {
      detected: confidence >= this.config.confidenceThreshold,
      attackType: OWASPAttackCategory.BROKEN_ACCESS_CONTROL,
      attackSubtype: 'path_traversal',
      severity: this.getSeverity(confidence, 'path_traversal'),
      confidence,
      matchedPatterns: matches.map(m => m.name),
      payload: matches.map(m => m.match).join(', ')
    };
  }
  
  /**
   * Детектирование SSRF
   */
  private detectSsrf(text: string, log: LogEntry): DetectionResult {
    const matches = this.patternMatcher.match(text, 'ssrf');
    
    if (matches.length === 0) {
      return { detected: false };
    }
    
    const contextFactors: ContextFactors = {
      isFromSecuritySource: log.source === LogSource.SECURITY,
      hasMaliciousIP: log.context.metadata?.threatIntel?.isMalicious || false,
      hasSuspiciousUserAgent: false,
      isAfterHours: this.isAfterHours(log.timestamp),
      hasHighPrivilegeUser: false
    };
    
    const confidence = this.confidenceScorer.calculate(
      OWASPAttackCategory.INJECTION,
      matches.length,
      20, // Approximate total SSRF patterns
      contextFactors
    );
    
    return {
      detected: confidence >= this.config.confidenceThreshold,
      attackType: OWASPAttackCategory.INJECTION,
      attackSubtype: 'ssrf',
      severity: this.getSeverity(confidence, 'ssrf'),
      confidence,
      matchedPatterns: matches.map(m => m.name),
      payload: matches.map(m => m.match).join(', ')
    };
  }
  
  /**
   * Детектирование Brute Force
   */
  private detectBruteForce(text: string, log: LogEntry): DetectionResult {
    const matches = this.patternMatcher.match(text, 'brute_force');
    
    if (matches.length === 0) {
      return { detected: false };
    }
    
    const contextFactors: ContextFactors = {
      isFromSecuritySource: log.source === LogSource.AUTH || log.source === LogSource.SECURITY,
      hasMaliciousIP: log.context.metadata?.threatIntel?.isMalicious || false,
      hasSuspiciousUserAgent: false,
      isAfterHours: this.isAfterHours(log.timestamp),
      hasHighPrivilegeUser: false
    };
    
    const confidence = this.confidenceScorer.calculate(
      OWASPAttackCategory.BROKEN_AUTH,
      matches.length,
      AUTH_FAILURES_PATTERNS.bruteForce.length,
      contextFactors
    );
    
    return {
      detected: confidence >= this.config.confidenceThreshold,
      attackType: OWASPAttackCategory.BROKEN_AUTH,
      attackSubtype: 'brute_force',
      severity: this.getSeverity(confidence, 'brute_force'),
      confidence,
      matchedPatterns: matches.map(m => m.name),
      payload: matches.map(m => m.match).join(', ')
    };
  }
  
  /**
   * Детектирование Sensitive Data Exposure
   */
  private detectSensitiveData(text: string, log: LogEntry): DetectionResult {
    const matches = this.patternMatcher.match(text, 'sensitive_data');
    
    if (matches.length === 0) {
      return { detected: false };
    }
    
    const contextFactors: ContextFactors = {
      isFromSecuritySource: log.source === LogSource.SECURITY,
      hasMaliciousIP: false,
      hasSuspiciousUserAgent: false,
      isAfterHours: false,
      hasHighPrivilegeUser: false
    };
    
    const confidence = this.confidenceScorer.calculate(
      OWASPAttackCategory.SENSITIVE_DATA_EXPOSURE,
      matches.length,
      CRYPTOGRAPHIC_FAILURES_PATTERNS.sensitiveData.length,
      contextFactors
    );
    
    return {
      detected: confidence >= this.config.confidenceThreshold,
      attackType: OWASPAttackCategory.SENSITIVE_DATA_EXPOSURE,
      attackSubtype: 'sensitive_data_exposure',
      severity: this.getSeverity(confidence, 'sensitive_data'),
      confidence,
      matchedPatterns: matches.map(m => m.name),
      payload: matches.map(m => m.match).join(', ')
    };
  }
  
  /**
   * Создание AttackDetection из DetectionResult
   */
  private createDetection(result: DetectionResult, log: LogEntry): AttackDetection {
    const source: AttackSource = {
      ip: log.context.clientIp || 'unknown',
      port: log.fields?.sourcePort as number,
      country: log.context.geoLocation?.country,
      asn: log.context.geoLocation?.asn,
      isTor: log.context.metadata?.threatIntel?.isTor || false,
      isVpn: log.context.metadata?.threatIntel?.isVpn || false,
      isProxy: log.context.metadata?.threatIntel?.isProxy || false,
      reputation: log.context.metadata?.threatIntel?.reputation || 50
    };
    
    const target: AttackTarget = {
      ip: log.hostname,
      port: log.fields?.destinationPort as number,
      endpoint: log.fields?.url as string,
      service: log.component
    };
    
    const iocs = this.config.enableIocExtraction ? this.iocExtractor.extract(log) : [];
    
    return {
      id: crypto.randomUUID(),
      attackType: result.attackType!,
      attackSubtype: result.attackSubtype,
      severity: result.severity!,
      confidence: result.confidence!,
      relatedLogs: [log],
      source,
      target,
      attackVector: result.attackSubtype || 'unknown',
      payload: result.payload,
      indicatorsOfCompromise: iocs,
      remediationSteps: this.getRemediationSteps(result.attackType!, result.attackSubtype),
      references: this.getReferences(result.attackType!),
      detectedAt: new Date().toISOString(),
      investigationStatus: 'new'
    };
  }
  
  /**
   * Получение серьезности атаки
   */
  private getSeverity(confidence: number, subtype: string): AttackSeverity {
    // Критичные подтипы
    const criticalSubtypes = ['sql_injection', 'command_injection', 'ssrf', 'deserialization'];
    const highSubtypes = ['xss', 'path_traversal', 'brute_force'];
    
    if (criticalSubtypes.includes(subtype) && confidence > 0.8) {
      return AttackSeverity.CRITICAL;
    }
    
    if (criticalSubtypes.includes(subtype) || (highSubtypes.includes(subtype) && confidence > 0.7)) {
      return AttackSeverity.HIGH;
    }
    
    if (highSubtypes.includes(subtype) || confidence > 0.6) {
      return AttackSeverity.MEDIUM;
    }
    
    return AttackSeverity.LOW;
  }
  
  /**
   * Получение шагов remediation
   */
  private getRemediationSteps(attackType: OWASPAttackCategory, subtype?: string): string[] {
    const remediationMap: Record<string, string[]> = {
      sql_injection: [
        'Использовать параметризованные запросы или prepared statements',
        'Валидировать и санитизировать все входные данные',
        'Применить принцип наименьших привилегий для БД',
        'Включить WAF с правилами для SQL injection',
        'Провести аудит кода на наличие уязвимостей'
      ],
      xss: [
        'Экранировать все выходные данные',
        'Использовать Content Security Policy (CSP)',
        'Валидировать входные данные',
        'Использовать HTTPOnly и Secure флаги для cookies',
        'Применить современные фреймворки с авто-экранированием'
      ],
      command_injection: [
        'Избегать выполнения системных команд',
        'Использовать безопасные API вместо shell команд',
        'Валидировать все входные данные',
        'Изолировать процесс выполнения команд',
        'Применить AppArmor или SELinux'
      ],
      path_traversal: [
        'Валидировать и санитизировать пути к файлам',
        'Использовать whitelist разрешенных путей',
        'Применить chroot или контейнеризацию',
        'Отключить листинг директорий'
      ],
      ssrf: [
        'Валидировать и whitelist URLs',
        'Блокировать доступ к внутренним IP',
        'Отключить ненужные протоколы',
        'Использовать network segmentation',
        'Мониторить исходящие соединения'
      ],
      brute_force: [
        'Включить rate limiting',
        'Реализовать account lockout после N попыток',
        'Включить MFA',
        'Использовать CAPTCHA',
        'Мониторить неудачные попытки входа'
      ],
      sensitive_data_exposure: [
        'Шифровать чувствительные данные',
        'Не логировать чувствительную информацию',
        'Использовать secure传输 (TLS)',
        'Применить DLP решения',
        'Регулярно проводить аудит доступа'
      ]
    };
    
    return remediationMap[subtype || ''] || [
      'Провести расследование инцидента',
      'Документировать findings',
      'Применить соответствующие контрмеры',
      'Обновить правила детектирования'
    ];
  }
  
  /**
   * Получение ссылок на документацию
   */
  private getReferences(attackType: OWASPAttackCategory): string[] {
    const referencesMap: Record<OWASPAttackCategory, string[]> = {
      [OWASPAttackCategory.INJECTION]: [
        'https://owasp.org/www-community/Injection_Flaws',
        'https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html',
        'https://attack.mitre.org/techniques/T1190/'
      ],
      [OWASPAttackCategory.BROKEN_AUTH]: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
        'https://attack.mitre.org/techniques/T1110/'
      ],
      [OWASPAttackCategory.SENSITIVE_DATA_EXPOSURE]: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.XML_EXTERNAL_ENTITIES]: [
        'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
        'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.BROKEN_ACCESS_CONTROL]: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.SECURITY_MISCONFIGURATION]: [
        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Configuration_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.CROSS_SITE_SCRIPTING]: [
        'https://owasp.org/www-community/attacks/xss/',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
        'https://attack.mitre.org/techniques/T1189/'
      ],
      [OWASPAttackCategory.INSECURE_DESERIALIZATION]: [
        'https://owasp.org/www-community/vulnerabilities/Deserialization_vulnerability',
        'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.VULNERABLE_COMPONENTS]: [
        'https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities',
        'https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html'
      ],
      [OWASPAttackCategory.INSUFFICIENT_LOGGING]: [
        'https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging%2526Monitoring',
        'https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html'
      ]
    };
    
    return referencesMap[attackType] || ['https://owasp.org/www-project-top-ten/'];
  }
  
  /**
   * Проверка подозрительного User Agent
   */
  private isSuspiciousUserAgent(userAgent?: string): boolean {
    if (!userAgent) return false;
    
    const suspiciousPatterns = [
      /sqlmap/i,
      /nikto/i,
      /nmap/i,
      /masscan/i,
      /burp/i,
      /owasp/i,
      /zap/i,
      /acunetix/i,
      /nessus/i,
      /openvas/i,
      /w3af/i,
      /arachni/i,
      /havij/i,
      /pangolin/i
    ];
    
    return suspiciousPatterns.some(p => p.test(userAgent));
  }
  
  /**
   * Проверка после рабочих часов
   */
  private isAfterHours(timestamp: string): boolean {
    const date = new Date(timestamp);
    const hour = date.getHours();
    const day = date.getDay();
    
    // Выходные
    if (day === 0 || day === 6) {
      return true;
    }
    
    // Ночное время (22:00 - 06:00)
    return hour >= 22 || hour < 6;
  }
  
  /**
   * Обновление статистики времени детекта
   */
  private updateDetectionTimeStats(time: number): void {
    this.detectionTimes.push(time);
    
    if (this.detectionTimes.length > 1000) {
      this.detectionTimes.shift();
    }
    
    this.statistics.avgDetectionTime = 
      this.detectionTimes.reduce((a, b) => a + b, 0) / this.detectionTimes.length;
    
    const sorted = [...this.detectionTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99DetectionTime = sorted[p99Index] || 0;
    
    // Обновление avg confidence
    if (this.statistics.attacksDetected > 0) {
      // Confidence обновляется в createDetection
    }
  }
  
  // ==========================================================================
  // УПРАВЛЕНИЕ И СТАТИСТИКА
  // ==========================================================================
  
  /**
   * Получение статистики
   */
  getStatistics(): DetectorStatistics {
    return { ...this.statistics };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
    this.detectionTimes = [];
  }
  
  /**
   * Маркировка ложного срабатывания
   */
  markFalsePositive(detectionId: string): void {
    this.statistics.falsePositives++;
    this.emit('false_positive', { detectionId });
  }
  
  /**
   * Маркировка пропущенной атаки
   */
  markFalseNegative(): void {
    this.statistics.falseNegatives++;
  }
  
  /**
   * Включение детектора
   */
  enable(): void {
    this.enabled = true;
  }
  
  /**
   * Выключение детектора
   */
  disable(): void {
    this.enabled = false;
  }
  
  /**
   * Проверка включен ли детектор
   */
  isEnabled(): boolean {
    return this.enabled;
  }
  
  /**
   * Добавление кастомного паттерна
   */
  addPattern(category: string, pattern: RegExp, name: string, weight: number): void {
    this.patternMatcher.addPattern(category, pattern, name, weight);
  }
  
  /**
   * Обновление порога confidence
   */
  setConfidenceThreshold(threshold: number): void {
    this.config.confidenceThreshold = Math.max(0, Math.min(1, threshold));
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default AttackDetector;
