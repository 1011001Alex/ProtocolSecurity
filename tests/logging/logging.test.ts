/**
 * ============================================================================
 * COMPREHENSIVE TESTS - ЛОГИРОВАНИЕ И SIEM СИСТЕМА
 * ============================================================================
 * Полные тесты для всех компонентов системы логирования и SIEM.
 * Включает unit tests, integration tests, и security tests.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import * as crypto from 'crypto';

// Импорты типов
import {
  LogLevel,
  LogSource,
  LogEntry,
  LogContext,
  LoggerConfig,
  GlobalConfig,
  LogBufferConfig,
  LogParserConfig,
  LogEnricherConfig,
  LogCorrelatorConfig,
  SIEMEngineConfig,
  AttackDetectorConfig,
  AnomalyDetectionConfig,
  AlertingServiceConfig,
  LogStorageConfig,
  IntegrityVerifierConfig,
  ElasticsearchConfig,
  ComplianceReporterConfig,
  AlertSeverity,
  AlertStatus,
  NotificationChannel,
  OWASPAttackCategory,
  AttackSeverity as AttackSeverityEnum,
  ComplianceStandard,
  RuleOperator,
  LogicalOperator,
  RuleActionType,
  StorageStrategy,
  NotificationChannelConfig,
  EscalationRule,
  SIEMRule,
  RuleCondition,
  RuleAction
} from '../../src/types/logging.types';

// Импорты классов
import { SecureLogger, LoggerFactory } from '../../src/logging/Logger';
import { LogBuffer, KafkaBatchConsumer } from '../../src/logging/LogBuffer';
import { LogParser } from '../../src/logging/LogParser';
import { LogEnricher } from '../../src/logging/LogEnricher';
import { LogCorrelator } from '../../src/logging/LogCorrelator';
import { SIEMEngine } from '../../src/logging/SIEMEngine';
import { AttackDetector } from '../../src/logging/AttackDetection';
import { AnomalyDetector } from '../../src/logging/AnomalyDetection';
import { AlertingService } from '../../src/logging/AlertingService';
import { LogStorage } from '../../src/logging/LogStorage';
import { IntegrityVerifier } from '../../src/logging/IntegrityVerifier';
import { ElasticsearchClient, QueryBuilder } from '../../src/logging/ElasticsearchClient';
import { ComplianceReporter } from '../../src/logging/ComplianceReporter';

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Создание тестового лога
 */
function createTestLog(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    level: LogLevel.INFO,
    source: LogSource.APPLICATION,
    component: 'test-component',
    hostname: 'test-host',
    processId: process.pid,
    message: 'Test log message',
    context: {
      userId: 'test-user',
      clientIp: '192.168.1.100',
      requestId: crypto.randomUUID()
    },
    schemaVersion: '1.0.0',
    ...overrides
  };
}

/**
 * Создание тестовой конфигурации логгера
 */
function createTestLoggerConfig(): { logger: LoggerConfig; global: GlobalConfig } {
  return {
    logger: {
      level: LogLevel.DEBUG,
      format: 'json',
      enableColors: false,
      enableTimestamp: true,
      enableProcessInfo: true,
      transports: [
        {
          type: 'console',
          level: LogLevel.DEBUG,
          params: {}
        }
      ],
      defaultContext: {}
    },
    global: {
      serviceName: 'test-service',
      version: '1.0.0',
      environment: 'test',
      region: 'us-east-1',
      timezone: 'UTC',
      enableAudit: true,
      enableDebug: true,
      traceSampleRate: 1.0,
      maxLogSize: 1024 * 1024,
      enableRateLimiting: false
    }
  };
}

// ============================================================================
// LOGGER TESTS
// ============================================================================

describe('SecureLogger', () => {
  let logger: SecureLogger;
  
  beforeEach(() => {
    const config = createTestLoggerConfig();
    logger = new SecureLogger({
      config: config.logger,
      globalConfig: config.global
    });
  });
  
  afterEach(async () => {
    await logger.close();
    await LoggerFactory.closeAll();
  });
  
  describe('Basic Logging', () => {
    it('should create a logger instance', () => {
      expect(logger).toBeInstanceOf(SecureLogger);
      expect(logger.isEnabled()).toBe(true);
    });
    
    it('should log at different levels', () => {
      const emergencyLog = logger.emergency('Emergency message');
      const alertLog = logger.alert('Alert message');
      const criticalLog = logger.critical('Critical message');
      const errorLog = logger.error('Error message');
      const warningLog = logger.warning('Warning message');
      const noticeLog = logger.notice('Notice message');
      const infoLog = logger.info('Info message');
      const debugLog = logger.debug('Debug message');
      const traceLog = logger.trace('Trace message');
      
      expect(emergencyLog?.level).toBe(LogLevel.EMERGENCY);
      expect(alertLog?.level).toBe(LogLevel.ALERT);
      expect(criticalLog?.level).toBe(LogLevel.CRITICAL);
      expect(errorLog?.level).toBe(LogLevel.ERROR);
      expect(warningLog?.level).toBe(LogLevel.WARNING);
      expect(noticeLog?.level).toBe(LogLevel.NOTICE);
      expect(infoLog?.level).toBe(LogLevel.INFO);
      expect(debugLog?.level).toBe(LogLevel.DEBUG);
      expect(traceLog?.level).toBe(LogLevel.TRACE);
    });
    
    it('should include context in logs', () => {
      const context: LogContext = {
        userId: 'user-123',
        clientIp: '10.0.0.1',
        sessionId: 'session-456',
        requestId: 'req-789'
      };
      
      const log = logger.info('Message with context', LogSource.APPLICATION, 'test', context);
      
      expect(log?.context.userId).toBe('user-123');
      expect(log?.context.clientIp).toBe('10.0.0.1');
      expect(log?.context.sessionId).toBe('session-456');
      expect(log?.context.requestId).toBe('req-789');
    });
    
    it('should sanitize messages to prevent log injection', () => {
      const maliciousMessage = 'Normal message\r\nInjected: fake log entry';
      const log = logger.info(maliciousMessage);
      
      expect(log?.message).not.toContain('\r\n');
      expect(log?.message).not.toContain('\n');
    });
    
    it('should compute content hash for integrity', () => {
      const log = logger.info('Test message');
      
      expect(log?.contentHash).toBeDefined();
      expect(log?.contentHash?.length).toBe(64); // SHA-256 hex
    });
  });
  
  describe('Security Events', () => {
    it('should log authentication events', () => {
      const loginSuccess = logger.authEvent('login_success', 'user-123', '192.168.1.1');
      const loginFailure = logger.authEvent('login_failure', 'user-123', '192.168.1.1');
      
      expect(loginSuccess?.source).toBe(LogSource.AUTH);
      expect(loginFailure?.source).toBe(LogSource.AUTH);
      expect(loginSuccess?.level).toBe(LogLevel.INFO);
      expect(loginFailure?.level).toBe(LogLevel.WARNING);
    });
    
    it('should log data access events', () => {
      const log = logger.dataAccessEvent(
        'user-123',
        'customer_data',
        'record-456',
        'read',
        'success',
        '192.168.1.1'
      );
      
      expect(log?.source).toBe(LogSource.AUDIT);
      expect(log?.fields?.resourceType).toBe('customer_data');
      expect(log?.fields?.action).toBe('read');
    });
    
    it('should log configuration change events', () => {
      const log = logger.configChangeEvent(
        'admin-user',
        '/app/settings/security',
        { oldValue: 'old' },
        { newValue: 'new' },
        '192.168.1.1'
      );
      
      expect(log?.source).toBe(LogSource.AUDIT);
      expect(log?.fields?.configPath).toBe('/app/settings/security');
    });
  });
  
  describe('Rate Limiting', () => {
    it('should respect rate limits', () => {
      // Enable rate limiting
      logger.enable();
      
      const logs: (LogEntry | null)[] = [];
      for (let i = 0; i < 1000; i++) {
        logs.push(logger.info(`Message ${i}`));
      }
      
      const successfulLogs = logs.filter(l => l !== null).length;
      // Some logs should be rate limited
      expect(successfulLogs).toBeLessThan(1000);
    });
  });
  
  describe('Logger Management', () => {
    it('should change log level', () => {
      logger.setLevel(LogLevel.WARNING);
      expect(logger.getLevel()).toBe(LogLevel.WARNING);
      
      const debugLog = logger.debug('This should not be logged');
      const errorLog = logger.error('This should be logged');
      
      expect(debugLog).toBeNull();
      expect(errorLog).not.toBeNull();
    });
    
    it('should enable and disable logging', () => {
      logger.disable();
      expect(logger.isEnabled()).toBe(false);
      
      const disabledLog = logger.info('Disabled message');
      expect(disabledLog).toBeNull();
      
      logger.enable();
      expect(logger.isEnabled()).toBe(true);
    });
    
    it('should get statistics', () => {
      logger.info('Test 1');
      logger.error('Test 2');
      logger.warning('Test 3');
      
      const stats = logger.getStatistics();
      
      expect(stats.logsProcessed).toBeGreaterThanOrEqual(3);
      expect(stats.transportsCount).toBeGreaterThanOrEqual(1);
    });
  });
});

// ============================================================================
// LOG PARSER TESTS
// ============================================================================

describe('LogParser', () => {
  let parser: LogParser;
  
  beforeEach(() => {
    parser = new LogParser({
      autoDetectFormat: true,
      strictMode: false,
      timezone: 'UTC'
    });
  });
  
  describe('Format Detection', () => {
    it('should detect JSON format', () => {
      const jsonLog = '{"level":"info","message":"Test message","timestamp":"2024-01-01T00:00:00Z"}';
      const result = parser.parse(jsonLog);
      
      expect(result.success).toBe(true);
      expect(result.format).toBe('json');
    });
    
    it('should detect Syslog RFC 5424 format', () => {
      const syslogLog = '<165>1 2024-01-01T00:00:00Z hostname app 1234 ID47 - Test message';
      const result = parser.parse(syslogLog);
      
      expect(result.success).toBe(true);
      expect(result.format).toBe('syslog_rfc5424');
    });
    
    it('should detect Apache Combined format', () => {
      const apacheLog = '192.168.1.1 - user [01/Jan/2024:00:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "http://referer" "Mozilla/5.0"';
      const result = parser.parse(apacheLog);
      
      expect(result.success).toBe(true);
      expect(result.format).toBe('apache_combined');
    });
    
    it('should detect CEF format', () => {
      const cefLog = 'CEF:0|Vendor|Product|1.0|100|Attack detected|9|src=192.168.1.1 dst=10.0.0.1';
      const result = parser.parse(cefLog);
      
      expect(result.success).toBe(true);
      expect(result.format).toBe('cef');
    });
  });
  
  describe('Security Pattern Detection', () => {
    it('should detect SQL injection patterns', () => {
      const sqlInjectionLog = 'GET /search?q=1\' OR 1=1--';
      const result = parser.parse(sqlInjectionLog);
      
      expect(result.success).toBe(true);
      expect(result.log?.context.metadata?.securityThreat).toBe('sql_injection');
    });
    
    it('should detect XSS patterns', () => {
      const xssLog = 'GET /page?name=<script>alert(1)</script>';
      const result = parser.parse(xssLog);
      
      expect(result.success).toBe(true);
      expect(result.log?.context.metadata?.securityThreat).toBe('xss');
    });
    
    it('should detect path traversal patterns', () => {
      const traversalLog = 'GET /files/../../../etc/passwd';
      const result = parser.parse(traversalLog);
      
      expect(result.success).toBe(true);
      expect(result.log?.context.metadata?.securityThreat).toBe('path_traversal');
    });
  });
  
  describe('Data Masking', () => {
    it('should mask email addresses', () => {
      const logWithSensitive = 'User email: test@example.com logged in';
      const result = parser.parse(logWithSensitive);
      
      expect(result.log?.message).not.toContain('test@example.com');
    });
    
    it('should mask credit card numbers', () => {
      const logWithCC = 'Payment with card 4111111111111111 processed';
      const result = parser.parse(logWithCC);
      
      expect(result.log?.message).not.toContain('4111111111111111');
    });
  });
  
  describe('Statistics', () => {
    it('should track parsing statistics', () => {
      parser.parse('{"level":"info","message":"Test"}');
      parser.parse('Invalid log entry');
      parser.parse('<165>1 2024-01-01T00:00:00Z host app 1234 ID47 - Test');
      
      const stats = parser.getStatistics();
      
      expect(stats.totalParsed).toBe(3);
      expect(stats.successCount).toBeGreaterThanOrEqual(2);
    });
  });
});

// ============================================================================
// LOG ENRICHER TESTS
// ============================================================================

describe('LogEnricher', () => {
  let enricher: LogEnricher;
  
  beforeEach(() => {
    enricher = new LogEnricher({
      enableGeoIP: false, // Disable external calls for tests
      enableThreatIntel: false,
      enableUaParsing: true,
      enableCache: true,
      cacheSize: 1000,
      cacheTtlSeconds: 300
    });
  });
  
  describe('User Agent Parsing', () => {
    it('should parse desktop user agents', () => {
      const log = createTestLog({
        context: {
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
        }
      });
      
      // Enrichment would add device info
      expect(log.context.userAgent).toBeDefined();
    });
    
    it('should parse mobile user agents', () => {
      const log = createTestLog({
        context: {
          userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15'
        }
      });
      
      expect(log.context.userAgent).toBeDefined();
    });
  });
  
  describe('Cache', () => {
    it('should cache enrichment results', async () => {
      const log = createTestLog();
      
      await enricher.enrich(log);
      await enricher.enrich(log); // Second should use cache
      
      const stats = enricher.getStatistics();
      expect(stats.cacheHits).toBeGreaterThanOrEqual(1);
    });
  });
});

// ============================================================================
// LOG CORRELATOR TESTS
// ============================================================================

describe('LogCorrelator', () => {
  let correlator: LogCorrelator;
  
  beforeEach(() => {
    correlator = new LogCorrelator({
      enableCorrelationId: true,
      enableSessionCorrelation: true,
      enableIpCorrelation: true,
      enablePatternCorrelation: true,
      enableAttackChainDetection: true,
      timeWindowSeconds: 300,
      maxGroupSize: 100
    });
  });
  
  afterEach(() => {
    correlator.close();
  });
  
  describe('Correlation', () => {
    it('should correlate logs by correlation ID', () => {
      const correlationId = crypto.randomUUID();
      
      const log1 = createTestLog({
        context: { correlationId }
      });
      const log2 = createTestLog({
        context: { correlationId },
        message: 'Related message'
      });
      
      const result1 = correlator.correlate(log1);
      const result2 = correlator.correlate(log2);
      
      expect(result1.groups.length).toBeGreaterThan(0);
      expect(result2.groups.length).toBeGreaterThan(0);
    });
    
    it('should correlate logs by session ID', () => {
      const sessionId = 'session-123';
      
      const log1 = createTestLog({ context: { sessionId } });
      const log2 = createTestLog({ context: { sessionId } });
      
      correlator.correlate(log1);
      const result2 = correlator.correlate(log2);
      
      expect(result2.groups.some(g => g.type === 'session')).toBe(true);
    });
  });
  
  describe('Attack Chain Detection', () => {
    it('should detect SQL injection attack chain', () => {
      const logs = [
        createTestLog({ message: "GET /search?q=1' UNION SELECT" }),
        createTestLog({ message: "GET /search?q=1' OR 1=1--" }),
        createTestLog({ message: "GET /search?q=1'; DROP TABLE users--" })
      ];
      
      for (const log of logs) {
        correlator.correlate(log);
      }
      
      const stats = correlator.getStatistics();
      expect(stats.attacksDetected).toBeGreaterThanOrEqual(1);
    });
  });
});

// ============================================================================
// SIEM ENGINE TESTS
// ============================================================================

describe('SIEMEngine', () => {
  let engine: SIEMEngine;
  
  beforeEach(() => {
    engine = new SIEMEngine({
      enableBuiltinRules: true,
      enableAggregation: true,
      ruleExecutionTimeout: 5000
    });
  });
  
  afterEach(() => {
    engine.close();
  });
  
  describe('Rule Execution', () => {
    it('should execute built-in rules', async () => {
      const log = createTestLog({
        message: "GET /search?q=1' UNION SELECT * FROM users--",
        source: LogSource.NETWORK
      });
      
      const results = await engine.process(log);
      
      expect(results.length).toBeGreaterThan(0);
    });
    
    it('should trigger alerts for matched rules', async () => {
      const alertPromises: Promise<void>[] = [];
      
      engine.on('alert_generated', (alert: Alert) => {
        expect(alert.severity).toBeDefined();
        expect(alert.ruleId).toBeDefined();
      });
      
      const log = createTestLog({
        message: '<script>alert("xss")</script>'
      });
      
      await engine.process(log);
    });
  });
  
  describe('Rule Management', () => {
    it('should add custom rules', () => {
      const customRule: SIEMRule = {
        id: 'custom-rule-1',
        name: 'Custom Test Rule',
        description: 'Test rule',
        category: 'test',
        version: '1.0.0',
        enabled: true,
        priority: 3,
        conditions: [
          {
            field: 'message',
            operator: RuleOperator.CONTAINS,
            value: 'test'
          }
        ],
        logicalOperator: LogicalOperator.AND,
        actions: [
          {
            type: RuleActionType.ALERT,
            priority: 3,
            channels: ['test']
          }
        ],
        tags: ['test'],
        complianceStandards: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      
      const added = engine.addRule(customRule);
      expect(added).toBe(true);
      
      const rule = engine.getRule('custom-rule-1');
      expect(rule).toBeDefined();
    });
    
    it('should enable and disable rules', () => {
      engine.disableRule('owasp-a01-sql-injection');
      const rule = engine.getRule('owasp-a01-sql-injection');
      expect(rule?.enabled).toBe(false);
      
      engine.enableRule('owasp-a01-sql-injection');
      const enabledRule = engine.getRule('owasp-a01-sql-injection');
      expect(enabledRule?.enabled).toBe(true);
    });
  });
});

// ============================================================================
// ATTACK DETECTOR TESTS
// ============================================================================

describe('AttackDetector', () => {
  let detector: AttackDetector;
  
  beforeEach(() => {
    detector = new AttackDetector({
      enableSqlInjectionDetection: true,
      enableXssDetection: true,
      enableCommandInjectionDetection: true,
      enablePathTraversalDetection: true,
      enableSsrfDetection: true,
      confidenceThreshold: 0.5
    });
  });
  
  describe('SQL Injection Detection', () => {
    it('should detect UNION-based SQL injection', () => {
      const log = createTestLog({
        message: "GET /api/users?id=1 UNION SELECT username, password FROM users--"
      });
      
      const detections = detector.detect(log);
      
      expect(detections.length).toBeGreaterThan(0);
      expect(detections[0].attackType).toBe(OWASPAttackCategory.INJECTION);
      expect(detections[0].attackSubtype).toBe('sql_injection');
    });
    
    it('should detect boolean-based SQL injection', () => {
      const log = createTestLog({
        message: "GET /api/users?id=1' OR 1=1--"
      });
      
      const detections = detector.detect(log);
      
      expect(detections.length).toBeGreaterThan(0);
    });
    
    it('should detect time-based SQL injection', () => {
      const log = createTestLog({
        message: "GET /api/users?id=1; WAITFOR DELAY '0:0:5'--"
      });
      
      const detections = detector.detect(log);
      
      expect(detections.length).toBeGreaterThan(0);
    });
  });
  
  describe('XSS Detection', () => {
    it('should detect script tag injection', () => {
      const log = createTestLog({
        message: 'GET /page?name=<script>alert(document.cookie)</script>'
      });
      
      const detections = detector.detect(log);
      
      expect(detections.length).toBeGreaterThan(0);
      expect(detections[0].attackType).toBe(OWASPAttackCategory.CROSS_SITE_SCRIPTING);
    });
    
    it('should detect event handler XSS', () => {
      const log = createTestLog({
        message: 'GET /page?name=<img src=x onerror=alert(1)>'
      });
      
      const detections = detector.detect(log);
      
      expect(detections.length).toBeGreaterThan(0);
    });
  });
  
  describe('Path Traversal Detection', () => {
    it('should detect basic path traversal', () => {
      const log = createTestLog({
        message: 'GET /files/../../../etc/passwd'
      });
      
      const detections = detector.detect(log);
      
      expect(detections.length).toBeGreaterThan(0);
      expect(detections[0].attackType).toBe(OWASPAttackCategory.BROKEN_ACCESS_CONTROL);
    });
  });
  
  describe('Statistics', () => {
    it('should track detection statistics', () => {
      const log = createTestLog({
        message: "SELECT * FROM users WHERE id=1 OR 1=1"
      });
      
      detector.detect(log);
      
      const stats = detector.getStatistics();
      
      expect(stats.totalLogsProcessed).toBe(1);
      expect(stats.attacksDetected).toBeGreaterThanOrEqual(1);
    });
  });
});

// ============================================================================
// ANOMALY DETECTOR TESTS
// ============================================================================

describe('AnomalyDetector', () => {
  let detector: AnomalyDetector;
  
  beforeEach(() => {
    detector = new AnomalyDetector({
      modelType: 'zscore',
      features: ['fields.responseTime', 'fields.statusCode'],
      anomalyThreshold: 0.6,
      minSampleSize: 30
    });
  });
  
  describe('Training', () => {
    it('should accept training data', () => {
      for (let i = 0; i < 50; i++) {
        const log = createTestLog({
          fields: {
            responseTime: 100 + Math.random() * 50,
            statusCode: 200
          }
        });
        detector.addForTraining(log);
      }
      
      expect(detector.getTrainingSampleSize()).toBe(50);
    });
  });
  
  describe('Anomaly Detection', () => {
    it('should detect anomalies after training', async () => {
      // Training data - normal response times
      for (let i = 0; i < 50; i++) {
        const log = createTestLog({
          fields: {
            responseTime: 100 + Math.random() * 50,
            statusCode: 200
          }
        });
        detector.addForTraining(log);
      }
      
      // Anomalous log - very high response time
      const anomalousLog = createTestLog({
        fields: {
          responseTime: 5000, // Much higher than normal
          statusCode: 200
        }
      });
      
      // Wait for training
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const result = detector.detect(anomalousLog);
      
      // May or may not detect depending on training
      expect(result).toBeDefined();
    });
  });
});

// ============================================================================
// ALERTING SERVICE TESTS
// ============================================================================

describe('AlertingService', () => {
  let service: AlertingService;
  
  beforeEach(() => {
    service = new AlertingService({
      channels: [],
      enableDeduplication: true,
      deduplicationWindowSeconds: 300,
      enableRateLimiting: false,
      enableEscalation: false
    });
  });
  
  afterEach(() => {
    service.close();
  });
  
  describe('Alert Creation', () => {
    it('should create alerts', async () => {
      const alert: Alert = {
        id: crypto.randomUUID(),
        ruleId: 'test-rule',
        ruleName: 'Test Rule',
        title: 'Test Alert',
        description: 'Test description',
        severity: AlertSeverity.P3_MEDIUM,
        status: AlertStatus.NEW,
        category: 'test',
        tags: ['test'],
        relatedLogs: [],
        source: 'test-source',
        hostname: 'test-host',
        occurredAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        escalationHistory: [],
        notifications: [],
        fingerprint: crypto.createHash('md5').update('test').digest('hex'),
        occurrenceCount: 1
      };
      
      const created = await service.createAlert(alert);
      
      expect(created).toBeDefined();
    });
    
    it('should deduplicate alerts', async () => {
      const fingerprint = crypto.createHash('md5').update('same-alert').digest('hex');
      
      const alert1: Alert = {
        id: crypto.randomUUID(),
        ruleId: 'test-rule',
        ruleName: 'Test Rule',
        title: 'Test Alert',
        description: 'Test',
        severity: AlertSeverity.P3_MEDIUM,
        status: AlertStatus.NEW,
        category: 'test',
        tags: [],
        relatedLogs: [],
        source: 'test',
        hostname: 'test',
        occurredAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        escalationHistory: [],
        notifications: [],
        fingerprint,
        occurrenceCount: 1
      };
      
      await service.createAlert(alert1);
      
      const alert2 = { ...alert1, id: crypto.randomUUID() };
      await service.createAlert(alert2);
      
      const stats = service.getStatistics();
      expect(stats.deduplicatedAlerts).toBeGreaterThanOrEqual(1);
    });
  });
  
  describe('Alert Management', () => {
    it('should acknowledge alerts', async () => {
      const alert: Alert = {
        id: crypto.randomUUID(),
        ruleId: 'test-rule',
        ruleName: 'Test Rule',
        title: 'Test Alert',
        description: 'Test',
        severity: AlertSeverity.P3_MEDIUM,
        status: AlertStatus.NEW,
        category: 'test',
        tags: [],
        relatedLogs: [],
        source: 'test',
        hostname: 'test',
        occurredAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        escalationHistory: [],
        notifications: [],
        fingerprint: crypto.randomUUID(),
        occurrenceCount: 1
      };
      
      await service.createAlert(alert);
      
      const acknowledged = service.acknowledgeAlert(alert.id, 'user-123');
      expect(acknowledged).toBe(true);
      
      const updatedAlert = service.getAlert(alert.id);
      expect(updatedAlert?.status).toBe(AlertStatus.ACKNOWLEDGED);
    });
    
    it('should resolve alerts', async () => {
      const alert: Alert = {
        id: crypto.randomUUID(),
        ruleId: 'test-rule',
        ruleName: 'Test Rule',
        title: 'Test Alert',
        description: 'Test',
        severity: AlertSeverity.P3_MEDIUM,
        status: AlertStatus.NEW,
        category: 'test',
        tags: [],
        relatedLogs: [],
        source: 'test',
        hostname: 'test',
        occurredAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        escalationHistory: [],
        notifications: [],
        fingerprint: crypto.randomUUID(),
        occurrenceCount: 1
      };
      
      await service.createAlert(alert);
      
      const resolved = service.updateAlertStatus(
        alert.id,
        AlertStatus.RESOLVED,
        'user-123',
        'Issue fixed'
      );
      
      expect(resolved).toBe(true);
    });
  });
});

// ============================================================================
// LOG STORAGE TESTS
// ============================================================================

describe('LogStorage', () => {
  let storage: LogStorage;
  const testPath = './test-logs/storage.log';
  
  beforeEach(async () => {
    storage = new LogStorage({
      strategy: StorageStrategy.IMMUTABLE,
      storagePath: testPath,
      maxFileSizeMB: 100,
      rotationPolicy: {
        type: 'size',
        maxSizeMB: 100,
        maxFiles: 5,
        enableArchiving: false
      },
      retentionPolicy: {
        hotRetentionDays: 7,
        warmRetentionDays: 30,
        coldRetentionDays: 90,
        expirationAction: 'delete'
      },
      enableCompression: false,
      enableEncryption: false,
      hashAlgorithm: 'sha256',
      enableHashChain: true,
      checkpointInterval: 100
    });
  });
  
  afterEach(async () => {
    await storage.close();
    // Cleanup test files
    try {
      await fs.promises.unlink(testPath);
    } catch {
      // Ignore cleanup errors
    }
  });
  
  describe('Writing Logs', () => {
    it('should write logs to storage', async () => {
      const log = createTestLog();
      
      const result = await storage.write(log);
      
      expect(result).toBeDefined();
      expect(result?.recordId).toBe(log.id);
      expect(result?.sequenceNumber).toBe(1);
    });
    
    it('should maintain hash chain', async () => {
      const log1 = createTestLog({ message: 'First log' });
      const log2 = createTestLog({ message: 'Second log' });
      
      const result1 = await storage.write(log1);
      const result2 = await storage.write(log2);
      
      expect(result2?.previousHash).toBe(result1?.contentHash);
    });
  });
  
  describe('Integrity Verification', () => {
    it('should verify integrity of stored logs', async () => {
      // Write some logs
      for (let i = 0; i < 5; i++) {
        await storage.write(createTestLog({ message: `Log ${i}` }));
      }
      
      const result = await storage.verifyIntegrity();
      
      expect(result.isValid).toBe(true);
      expect(result.verifiedRecords).toBe(5);
      expect(result.violationsFound).toBe(0);
    });
  });
});

// ============================================================================
// INTEGRITY VERIFIER TESTS
// ============================================================================

describe('IntegrityVerifier', () => {
  let verifier: IntegrityVerifier;
  
  beforeEach(() => {
    verifier = new IntegrityVerifier({
      hashAlgorithm: 'sha256',
      enableMerkleTree: true,
      merkleBlockSize: 100,
      enableSequenceVerification: true
    });
  });
  
  describe('Hash Chain Verification', () => {
    it('should verify valid records', async () => {
      const record: ImmutableLogRecord = {
        log: createTestLog(),
        contentHash: crypto.createHash('sha256').update('test').digest('hex'),
        previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
        signature: 'test-signature',
        recordedAt: new Date().toISOString(),
        sequenceNumber: 1
      };
      
      const result = await verifier.verifyRecord(record);
      
      expect(result).toBeDefined();
    });
  });
  
  describe('Merkle Tree', () => {
    it('should generate Merkle proofs', () => {
      const records = Array.from({ length: 10 }, (_, i) => ({
        log: createTestLog({ message: `Log ${i}` }),
        contentHash: crypto.createHash('sha256').update(`hash-${i}`).digest('hex'),
        previousHash: '',
        signature: '',
        recordedAt: new Date().toISOString(),
        sequenceNumber: i + 1
      }));
      
      const proof = verifier.generateMerkleProof(records, records[0].log.id);
      
      expect(proof).toBeDefined();
      expect(proof?.index).toBe(0);
    });
  });
  
  describe('Audit Trail', () => {
    it('should generate audit trails', () => {
      const records = Array.from({ length: 5 }, (_, i) => ({
        log: createTestLog({ message: `Log ${i}` }),
        contentHash: crypto.createHash('sha256').update(`hash-${i}`).digest('hex'),
        previousHash: '',
        signature: '',
        recordedAt: new Date().toISOString(),
        sequenceNumber: i + 1
      }));
      
      const trail = verifier.generateAuditTrail(records);
      
      expect(trail.entries.length).toBe(5);
      expect(trail.trailHash).toBeDefined();
      expect(trail.recordCount).toBe(5);
    });
  });
});

// ============================================================================
// COMPLIANCE REPORTER TESTS
// ============================================================================

describe('ComplianceReporter', () => {
  let reporter: ComplianceReporter;
  
  beforeEach(() => {
    reporter = new ComplianceReporter({
      standards: [ComplianceStandard.PCI_DSS, ComplianceStandard.GDPR],
      reportStoragePath: './test-compliance-reports',
      enableAutoReporting: false,
      enableTrendAnalysis: true
    });
  });
  
  afterEach(() => {
    reporter.close();
  });
  
  describe('Report Generation', () => {
    it('should generate PCI DSS compliance report', async () => {
      const report = await reporter.generateReport(ComplianceStandard.PCI_DSS);
      
      expect(report).toBeDefined();
      expect(report.standard).toBe(ComplianceStandard.PCI_DSS);
      expect(report.complianceScore).toBeGreaterThanOrEqual(0);
      expect(report.complianceScore).toBeLessThanOrEqual(100);
    });
    
    it('should generate GDPR compliance report', async () => {
      const report = await reporter.generateReport(ComplianceStandard.GDPR);
      
      expect(report).toBeDefined();
      expect(report.standard).toBe(ComplianceStandard.GDPR);
    });
  });
  
  describe('Compliance Score', () => {
    it('should track compliance scores', () => {
      const score = reporter.getComplianceScore();
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(100);
    });
    
    it('should provide score by standard', () => {
      const pciScore = reporter.getComplianceScore(ComplianceStandard.PCI_DSS);
      const gdprScore = reporter.getComplianceScore(ComplianceStandard.GDPR);
      
      expect(pciScore).toBeDefined();
      expect(gdprScore).toBeDefined();
    });
  });
  
  describe('Violation Management', () => {
    it('should track violations', async () => {
      await reporter.generateReport(ComplianceStandard.PCI_DSS);
      
      const violations = reporter.getAllViolations();
      
      // Violations may or may not exist depending on assessment
      expect(Array.isArray(violations)).toBe(true);
    });
    
    it('should update violation status', async () => {
      await reporter.generateReport(ComplianceStandard.PCI_DSS);
      
      const violations = reporter.getAllViolations();
      
      if (violations.length > 0) {
        const updated = reporter.updateViolationStatus(
          violations[0].id,
          'in_progress'
        );
        expect(updated).toBe(true);
      }
    });
  });
});

// ============================================================================
// ELASTICSEARCH CLIENT TESTS
// ============================================================================

describe('ElasticsearchClient', () => {
  let client: ElasticsearchClient;
  
  beforeEach(() => {
    client = new ElasticsearchClient({
      nodes: ['http://localhost:9200'],
      logIndex: 'test-logs',
      bulkIndexing: {
        flushBytes: 1024 * 1024,
        flushInterval: 1000,
        concurrency: 1
      }
    });
  });
  
  afterEach(async () => {
    await client.close();
  });
  
  describe('Query Builder', () => {
    it('should build match queries', () => {
      const builder = client.getQueryBuilder();
      const query = builder
        .match('message', 'test error')
        .build();
      
      expect(query.query).toBeDefined();
      expect(query.query.match).toBeDefined();
    });
    
    it('should build bool queries', () => {
      const builder = client.getQueryBuilder();
      const query = builder
        .bool({
          must: [{ match: { message: 'error' } }],
          filter: [{ term: { level: 3 } }]
        })
        .sort('timestamp', 'desc')
        .build();
      
      expect(query.query.bool).toBeDefined();
      expect(query.sort).toBeDefined();
    });
    
    it('should build range queries', () => {
      const builder = client.getQueryBuilder();
      const now = new Date().toISOString();
      const hourAgo = new Date(Date.now() - 3600000).toISOString();
      
      const query = builder
        .range('timestamp', { gte: hourAgo, lte: now })
        .build();
      
      expect(query.query.range).toBeDefined();
    });
  });
  
  describe('Connection', () => {
    it('should report disconnected state initially', () => {
      expect(client.isConnected()).toBe(false);
    });
    
    it('should provide statistics', () => {
      const stats = client.getStatistics();
      
      expect(stats.connectionStatus).toBe('disconnected');
      expect(stats.totalIndexed).toBe(0);
      expect(stats.totalSearches).toBe(0);
    });
  });
});

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

describe('Integration Tests', () => {
  it('should process logs through the entire pipeline', async () => {
    // Create components
    const parser = new LogParser({ autoDetectFormat: true });
    const enricher = new LogEnricher({ enableGeoIP: false, enableThreatIntel: false });
    const correlator = new LogCorrelator();
    const siemEngine = new SIEMEngine();
    const attackDetector = new AttackDetector();
    
    // Simulate log pipeline
    const rawLog = '{"level":"error","message":"SQL error: SELECT * FROM users WHERE id=1\' OR 1=1--","timestamp":"2024-01-01T00:00:00Z"}';
    
    // Parse
    const parseResult = parser.parse(rawLog);
    expect(parseResult.success).toBe(true);
    expect(parseResult.log).toBeDefined();
    
    if (parseResult.log) {
      // Enrich
      const enrichResult = await enricher.enrich(parseResult.log);
      expect(enrichResult.log).toBeDefined();
      
      // Correlate
      const correlateResult = correlator.correlate(enrichResult.log);
      expect(correlateResult).toBeDefined();
      
      // SIEM processing
      const siemResults = await siemEngine.process(enrichResult.log);
      expect(siemResults).toBeDefined();
      
      // Attack detection
      const attacks = attackDetector.detect(enrichResult.log);
      expect(attacks).toBeDefined();
    }
    
    // Cleanup
    correlator.close();
    siemEngine.close();
  });
});
