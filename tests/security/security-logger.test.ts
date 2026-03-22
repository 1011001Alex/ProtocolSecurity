/**
 * =============================================================================
 * COMPREHENSIVE TESTS FOR SECURITY LOGGING SYSTEM
 * =============================================================================
 * Полное покрытие всех компонентов security logging:
 * - StructuredSecurityLogger
 * - SecurityEventTypes
 * - RealTimeAlerter
 * =============================================================================
 */

import {
  SecurityLogger,
  createSecurityLogger,
  SecurityCategory,
  SecuritySeverity,
  SecurityOutcome,
  SecurityEvent,
  SecurityLoggerConfig
} from '../../src/logging/StructuredSecurityLogger';

import {
  AuthenticationEvent,
  AuthorizationEvent,
  DataEvent,
  ThreatEvent,
  SystemEvent,
  AuditEvent,
  EventTypes
} from '../../src/logging/SecurityEventTypes';

import {
  RealTimeAlerter,
  createRealTimeAlerter,
  AlertConfig,
  AlertChannel,
  EscalationLevel,
  AlertStatus,
  RealTimeAlerterConfig
} from '../../src/logging/RealTimeAlerter';

// =============================================================================
// MOCKS
// =============================================================================

const mockLogger = {
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn()
};

const mockSIEM = {
  send: jest.fn()
};

// =============================================================================
// STRUCTURED SECURITY LOGGER TESTS
// =============================================================================

describe('StructuredSecurityLogger', () => {
  let logger: SecurityLogger;

  beforeEach(() => {
    logger = createSecurityLogger({
      enableConsole: false,
      enableFile: false,
      level: SecuritySeverity.INFO
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // CREATION TESTS
  // =============================================================================

  describe('Creation', () => {
    it('должен создавать logger с конфигурацией по умолчанию', () => {
      expect(logger).toBeDefined();
      expect(logger).toBeInstanceOf(SecurityLogger);
    });

    it('должен создавать logger с кастомной конфигурацией', () => {
      const config: SecurityLoggerConfig = {
        level: SecuritySeverity.HIGH,
        enableConsole: true,
        enableFile: false
      };

      const customLogger = createSecurityLogger(config);
      expect(customLogger).toBeDefined();
    });

    it('должен эмитить события при логировании', (done) => {
      logger.on('security-event', (event) => {
        expect(event).toBeDefined();
        expect(event.eventId).toBeDefined();
        expect(event.timestamp).toBeDefined();
        done();
      });

      logger.log({
        category: SecurityCategory.AUTHENTICATION,
        eventType: 'LOGIN',
        severity: SecuritySeverity.INFO,
        outcome: SecurityOutcome.SUCCESS,
        actor: { type: 'user', id: 'user123' },
        action: 'login',
        resource: { type: 'auth-service' },
        context: { ipAddress: '127.0.0.1', correlationId: 'test-123' }
      });
    });
  });

  // =============================================================================
  // AUTHENTICATION LOGGING TESTS
  // =============================================================================

  describe('Authentication Logging', () => {
    it('должен логировать успешный login', (done) => {
      logger.on('security-event', (event) => {
        expect(event.category).toBe(SecurityCategory.AUTHENTICATION);
        expect(event.eventType).toBe('LOGIN_SUCCESS');
        expect(event.severity).toBe(SecuritySeverity.INFO);
        expect(event.outcome).toBe(SecurityOutcome.SUCCESS);
        expect(event.actor.id).toBe('user123');
        done();
      });

      logger.logAuth({
        eventType: 'LOGIN_SUCCESS',
        userId: 'user123',
        email: 'user@example.com',
        outcome: SecurityOutcome.SUCCESS,
        ipAddress: '192.168.1.1',
        sessionId: 'sess_abc123'
      });
    });

    it('должен логировать failed login с MEDIUM severity', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('LOGIN_FAILURE');
        expect(event.severity).toBe(SecuritySeverity.MEDIUM);
        expect(event.outcome).toBe(SecurityOutcome.FAILURE);
        expect(event.data?.failureReason).toBe('INVALID_PASSWORD');
        done();
      });

      logger.logAuth({
        eventType: 'LOGIN_FAILURE',
        email: 'user@example.com',
        outcome: SecurityOutcome.FAILURE,
        ipAddress: '192.168.1.1',
        failureReason: 'INVALID_PASSWORD'
      });
    });

    it('должен логировать MFA challenge', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('MFA_CHALLENGE');
        expect(event.data?.mfaMethod).toBe('totp');
        done();
      });

      logger.logAuth({
        eventType: 'MFA_CHALLENGE',
        userId: 'user123',
        outcome: SecurityOutcome.SUCCESS,
        ipAddress: '192.168.1.1',
        mfaMethod: 'totp'
      });
    });

    it('должен логировать MFA failure с MEDIUM severity', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('MFA_FAILURE');
        expect(event.severity).toBe(SecuritySeverity.MEDIUM);
        done();
      });

      logger.logAuth({
        eventType: 'MFA_FAILURE',
        userId: 'user123',
        outcome: SecurityOutcome.FAILURE,
        ipAddress: '192.168.1.1'
      });
    });

    it('должен логировать logout', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('LOGOUT');
        expect(event.outcome).toBe(SecurityOutcome.SUCCESS);
        done();
      });

      logger.logAuth({
        eventType: 'LOGOUT',
        userId: 'user123',
        outcome: SecurityOutcome.SUCCESS,
        ipAddress: '192.168.1.1',
        sessionId: 'sess_abc123'
      });
    });

    it('должен логировать password change', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('PASSWORD_CHANGE_SUCCESS');
        done();
      });

      logger.logAuth({
        eventType: 'PASSWORD_CHANGE_SUCCESS',
        userId: 'user123',
        outcome: SecurityOutcome.SUCCESS,
        ipAddress: '192.168.1.1'
      });
    });
  });

  // =============================================================================
  // AUTHORIZATION LOGGING TESTS
  // =============================================================================

  describe('Authorization Logging', () => {
    it('должен логировать access granted', (done) => {
      logger.on('security-event', (event) => {
        expect(event.category).toBe(SecurityCategory.AUTHORIZATION);
        expect(event.eventType).toBe('ACCESS_GRANTED');
        expect(event.outcome).toBe(SecurityOutcome.SUCCESS);
        expect(event.actor.id).toBe('user123');
        expect(event.resource.name).toBe('document-123');
        done();
      });

      logger.logAccess({
        eventType: 'ACCESS_GRANTED',
        userId: 'user123',
        action: 'read',
        resource: 'document-123',
        resourceId: 'doc-123',
        outcome: SecurityOutcome.SUCCESS,
        ipAddress: '192.168.1.1'
      });
    });

    it('должен логировать access denied с MEDIUM severity', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('ACCESS_DENIED');
        expect(event.severity).toBe(SecuritySeverity.MEDIUM);
        expect(event.outcome).toBe(SecurityOutcome.DENIED);
        expect(event.data?.reason).toBe('INSUFFICIENT_PERMISSIONS');
        done();
      });

      logger.logAccess({
        eventType: 'ACCESS_DENIED',
        userId: 'user123',
        action: 'delete',
        resource: 'document-456',
        outcome: SecurityOutcome.DENIED,
        ipAddress: '192.168.1.1',
        reason: 'INSUFFICIENT_PERMISSIONS'
      });
    });

    it('должен логировать role change', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('ROLE_CHANGE');
        done();
      });

      logger.logAccess({
        eventType: 'ROLE_CHANGE',
        userId: 'user123',
        action: 'role_assignment',
        resource: 'admin-role',
        outcome: SecurityOutcome.SUCCESS,
        ipAddress: '192.168.1.1'
      });
    });
  });

  // =============================================================================
  // DATA ACCESS LOGGING TESTS
  // =============================================================================

  describe('Data Access Logging', () => {
    it('должен логировать data read', (done) => {
      logger.on('security-event', (event) => {
        expect(event.category).toBe(SecurityCategory.DATA);
        expect(event.eventType).toBe('DATA_READ');
        // Данные передаются через event.data как Record
        const data = event as any;
        expect(data.data.dataType).toBe('users');
        expect(data.data.recordCount).toBe(100);
        done();
      });

      logger.logDataAccess({
        eventType: 'DATA_READ',
        userId: 'user123',
        dataType: 'users',
        recordCount: 100,
        outcome: SecurityOutcome.SUCCESS,
        ipAddress: '192.168.1.1'
      });
    });

    it('должен логировать data export с MEDIUM severity', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('DATA_EXPORT');
        expect(event.severity).toBe(SecuritySeverity.MEDIUM);
        expect((event as any).data.dataSize).toBe(5000000);
        done();
      });

      logger.logDataAccess({
        eventType: 'DATA_EXPORT',
        userId: 'user123',
        dataType: 'customers',
        dataSize: 5000000,
        outcome: SecurityOutcome.SUCCESS,
        ipAddress: '192.168.1.1'
      });
    });

    it('должен логировать data delete', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('DATA_DELETE');
        done();
      });

      logger.logDataAccess({
        eventType: 'DATA_DELETE',
        userId: 'user123',
        dataType: 'logs',
        outcome: SecurityOutcome.SUCCESS,
        ipAddress: '192.168.1.1'
      });
    });
  });

  // =============================================================================
  // NETWORK LOGGING TESTS
  // =============================================================================

  describe('Network Logging', () => {
    it('должен логировать connection established', (done) => {
      logger.on('security-event', (event) => {
        expect(event.category).toBe(SecurityCategory.NETWORK);
        expect(event.eventType).toBe('CONNECTION');
        expect((event as any).data.sourceIp).toBe('192.168.1.100');
        expect((event as any).data.destinationIp).toBe('10.0.0.1');
        done();
      });

      logger.logNetworkEvent({
        eventType: 'CONNECTION',
        sourceIp: '192.168.1.100',
        destinationIp: '10.0.0.1',
        port: 443,
        protocol: 'HTTPS',
        outcome: SecurityOutcome.SUCCESS
      });
    });

    it('должен логировать firewall block', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('FIREWALL_BLOCK');
        expect(event.severity).toBe(SecuritySeverity.MEDIUM);
        done();
      });

      logger.logNetworkEvent({
        eventType: 'FIREWALL_BLOCK',
        sourceIp: '203.0.113.42',
        destinationIp: '10.0.0.1',
        port: 22,
        outcome: SecurityOutcome.DENIED
      });
    });
  });

  // =============================================================================
  // THREAT LOGGING TESTS
  // =============================================================================

  describe('Threat Logging', () => {
    it('должен логировать brute force detected', (done) => {
      logger.on('security-event', (event) => {
        expect(event.category).toBe(SecurityCategory.THREAT);
        expect(event.eventType).toBe('BRUTE_FORCE');
        expect(event.severity).toBe(SecuritySeverity.HIGH);
        expect(event.data.threatType).toBe('credential_stuffing');
        done();
      });

      logger.logThreat({
        eventType: 'BRUTE_FORCE',
        threatType: 'credential_stuffing',
        sourceIp: '203.0.113.42',
        severity: SecuritySeverity.HIGH,
        confidence: 0.95
      });
    });

    it('должен логировать intrusion attempt с CRITICAL severity', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('INTRUSION_ATTEMPT');
        expect(event.severity).toBe(SecuritySeverity.CRITICAL);
        expect(event.data?.mitreAttackId).toBe('T1190');
        done();
      });

      logger.logThreat({
        eventType: 'INTRUSION_ATTEMPT',
        threatType: 'exploit',
        sourceIp: '198.51.100.42',
        severity: SecuritySeverity.CRITICAL,
        confidence: 0.99,
        mitreAttackId: 'T1190'
      });
    });

    it('должен логировать anomaly detected', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('ANOMALY_DETECTED');
        expect(event.data?.confidence).toBe(0.87);
        done();
      });

      logger.logThreat({
        eventType: 'ANOMALY_DETECTED',
        threatType: 'behavioral_anomaly',
        sourceIp: '192.168.1.50',
        severity: SecuritySeverity.MEDIUM,
        confidence: 0.87
      });
    });
  });

  // =============================================================================
  // SYSTEM LOGGING TESTS
  // =============================================================================

  describe('System Logging', () => {
    it('должен логировать system startup', (done) => {
      logger.on('security-event', (event) => {
        expect(event.category).toBe(SecurityCategory.SYSTEM);
        expect(event.eventType).toBe('STARTUP');
        expect((event as any).data.componentName).toBe('Auth Service');
        done();
      });

      logger.logSystemEvent({
        eventType: 'STARTUP',
        component: 'Auth Service',
        outcome: SecurityOutcome.SUCCESS
      });
    });

    it('должен логировать error с HIGH severity', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('ERROR');
        expect(event.severity).toBe(SecuritySeverity.HIGH);
        expect(event.data.details).toBe('Connection timeout');
        done();
      });

      logger.logSystemEvent({
        eventType: 'ERROR',
        component: 'Database',
        outcome: SecurityOutcome.FAILURE,
        details: 'Connection timeout'
      });
    });

    it('должен логировать config change', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('CONFIG_CHANGE');
        done();
      });

      logger.logSystemEvent({
        eventType: 'CONFIG_CHANGE',
        component: 'Security Module',
        outcome: SecurityOutcome.SUCCESS,
        details: 'Updated CSP policy'
      });
    });
  });

  // =============================================================================
  // AUDIT LOGGING TESTS
  // =============================================================================

  describe('Audit Logging', () => {
    it('должен логировать audit событие', (done) => {
      logger.on('security-event', (event) => {
        expect(event.category).toBe(SecurityCategory.AUDIT);
        expect(event.tags).toContain('audit');
        expect(event.tags).toContain('compliance');
        done();
      });

      logger.logAudit({
        eventType: 'USER_CREATED',
        userId: 'admin123',
        action: 'create_user',
        resource: 'new-user',
        outcome: SecurityOutcome.SUCCESS,
        details: { email: 'new@example.com' }
      });
    });

    it('должен логировать secret access', (done) => {
      logger.on('security-event', (event) => {
        expect(event.eventType).toBe('SECRET_ACCESSED');
        done();
      });

      logger.logAudit({
        eventType: 'SECRET_ACCESSED',
        userId: 'user123',
        action: 'read',
        resource: 'api-key-prod',
        outcome: SecurityOutcome.SUCCESS
      });
    });
  });

  // =============================================================================
  // CORRELATION ID TESTS
  // =============================================================================

  describe('Correlation ID', () => {
    it('должен использовать correlationId из события', (done) => {
      const customCorrelationId = 'custom-corr-123';

      logger.on('security-event', (event) => {
        expect(event.context.correlationId).toBe(customCorrelationId);
        done();
      });

      logger.log({
        category: SecurityCategory.AUTHENTICATION,
        eventType: 'LOGIN',
        severity: SecuritySeverity.INFO,
        outcome: SecurityOutcome.SUCCESS,
        actor: { type: 'user' },
        action: 'login',
        resource: { type: 'auth' },
        context: { ipAddress: '127.0.0.1', correlationId: customCorrelationId }
      });
    });

    it('должен использовать default correlationId если не указан', () => {
      const spy = jest.fn();
      logger.on('security-event', spy);

      logger.log({
        category: SecurityCategory.AUTHENTICATION,
        eventType: 'LOGIN',
        severity: SecuritySeverity.INFO,
        outcome: SecurityOutcome.SUCCESS,
        actor: { type: 'user' },
        action: 'login',
        resource: { type: 'auth' },
        context: { ipAddress: '127.0.0.1' }
      });

      expect(spy).toHaveBeenCalled();
      const event = spy.mock.calls[0][0];
      expect(event.context.correlationId).toBeDefined();
      expect(event.context.correlationId).toBeTruthy();
    });

    it('должен позволять устанавливать default correlationId', () => {
      const newCorrelationId = 'new-default-123';
      logger.setDefaultCorrelationId(newCorrelationId);
      expect(logger).toBeDefined();
    });
  });

  // =============================================================================
  // STATS TESTS
  // =============================================================================

  describe('Stats', () => {
    it('должен возвращать статистику', () => {
      const stats = logger.getStats();
      
      expect(stats).toBeDefined();
      expect(stats.level).toBeDefined();
      expect(stats.transports).toBeDefined();
    });
  });
});

// =============================================================================
// REAL-TIME ALERTER TESTS
// =============================================================================

describe('RealTimeAlerter', () => {
  let alerter: RealTimeAlerter;

  beforeEach(() => {
    const config: RealTimeAlerterConfig = {
      channels: {
        slack: {
          webhookUrl: 'https://hooks.slack.com/test',
          defaultChannel: '#security-alerts'
        },
        pagerduty: {
          routingKey: 'test-key',
          serviceId: 'test-service'
        },
        email: {
          smtpHost: 'smtp.example.com',
          smtpPort: 587,
          from: 'security@example.com',
          recipients: ['soc@example.com']
        }
      },
      rules: [
        {
          ruleId: 'critical-auth-failures',
          ruleName: 'Critical Authentication Failures',
          severityFilter: [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH],
          eventTypes: ['LOGIN_FAILURE', 'MFA_FAILURE'],
          channels: [AlertChannel.SLACK, AlertChannel.PAGERDUTY],
          defaultEscalationLevel: EscalationLevel.L1,
          escalationTimeoutMinutes: 15,
          rateLimitPerMinute: 10,
          enableDeduplication: true,
          deduplicationWindowMinutes: 5
        }
      ],
      enabled: true,
      globalRateLimitPerHour: 100
    };

    alerter = createRealTimeAlerter(config);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // CREATION TESTS
  // =============================================================================

  describe('Creation', () => {
    it('должен создавать alerter с конфигурацией', () => {
      expect(alerter).toBeDefined();
      expect(alerter).toBeInstanceOf(RealTimeAlerter);
    });

    it('должен эмитить события при создании алерта', (done) => {
      alerter.on('alert-created', (alert) => {
        expect(alert).toBeDefined();
        expect(alert.alertId).toBeDefined();
        expect(alert.status).toBe(AlertStatus.TRIGGERED);
        done();
      });

      alerter.processEvent({
        eventId: 'test-123',
        timestamp: new Date().toISOString(),
        category: SecurityCategory.AUTHENTICATION,
        eventType: 'LOGIN_FAILURE',
        severity: SecuritySeverity.HIGH,
        outcome: SecurityOutcome.FAILURE,
        actor: { type: 'user', id: 'user123' },
        action: 'login',
        resource: { type: 'auth' },
        context: { ipAddress: '192.168.1.1', correlationId: 'test-123' }
      });
    });
  });

  // =============================================================================
  // ALERT CREATION TESTS
  // =============================================================================

  describe('Alert Creation', () => {
    it('должен создавать алерт для matching правила', (done) => {
      alerter.on('alert-created', (alert) => {
        expect(alert.title).toContain('HIGH');
        expect(alert.severity).toBe(SecuritySeverity.HIGH);
        expect(alert.escalationLevel).toBe(EscalationLevel.L1);
        done();
      });

      alerter.processEvent({
        eventId: 'test-123',
        timestamp: new Date().toISOString(),
        category: SecurityCategory.AUTHENTICATION,
        eventType: 'MFA_FAILURE',
        severity: SecuritySeverity.HIGH,
        outcome: SecurityOutcome.FAILURE,
        actor: { type: 'user', id: 'user123' },
        action: 'mfa',
        resource: { type: 'auth' },
        context: { ipAddress: '192.168.1.1', correlationId: 'test-123' }
      });
    });

    it('должен игнорировать события не из правила', () => {
      const mockHandler = jest.fn();
      alerter.on('alert-created', mockHandler);

      alerter.processEvent({
        eventId: 'test-456',
        timestamp: new Date().toISOString(),
        category: SecurityCategory.SYSTEM,
        eventType: 'SYSTEM_STARTUP',
        severity: SecuritySeverity.INFO,
        outcome: SecurityOutcome.SUCCESS,
        actor: { type: 'system' },
        action: 'startup',
        resource: { type: 'system' },
        context: { ipAddress: '127.0.0.1', correlationId: 'test-456' }
      });

      expect(mockHandler).not.toHaveBeenCalled();
    });
  });

  // =============================================================================
  // RATE LIMITING TESTS
  // =============================================================================

  describe('Rate Limiting', () => {
    it('должен применять rate limiting для правил', (done) => {
      let alertCount = 0;
      let rateLimitExceededCalled = false;

      alerter.on('alert-created', () => {
        alertCount++;
      });

      alerter.on('rate-limit-exceeded', () => {
        if (!rateLimitExceededCalled) {
          rateLimitExceededCalled = true;
          expect(alertCount).toBeLessThan(15);
          done();
        }
      });

      // Быстрая отправка множества событий
      for (let i = 0; i < 15; i++) {
        alerter.processEvent({
          eventId: `test-${i}`,
          timestamp: new Date().toISOString(),
          category: SecurityCategory.AUTHENTICATION,
          eventType: 'LOGIN_FAILURE',
          severity: SecuritySeverity.HIGH,
          outcome: SecurityOutcome.FAILURE,
          actor: { type: 'user', id: 'user123' },
          action: 'login',
          resource: { type: 'auth' },
          context: { ipAddress: '192.168.1.1', correlationId: `test-${i}` }
        });
      }
    });
  });

  // =============================================================================
  // DEDUPLICATION TESTS
  // =============================================================================

  describe('Deduplication', () => {
    it('должен deduplicate одинаковые события', (done) => {
      let alertCount = 0;
      let duplicateCount = 0;

      alerter.on('alert-created', () => {
        alertCount++;
      });

      alerter.on('duplicate-suppressed', () => {
        duplicateCount++;
        if (duplicateCount >= 2) {
          expect(alertCount).toBe(1);
          done();
        }
      });

      // Отправка одинаковых событий
      const event = {
        eventId: 'test-dedup',
        timestamp: new Date().toISOString(),
        category: SecurityCategory.AUTHENTICATION,
        eventType: 'LOGIN_FAILURE',
        severity: SecuritySeverity.HIGH,
        outcome: SecurityOutcome.FAILURE,
        actor: { type: 'user', id: 'user123' },
        action: 'login',
        resource: { type: 'auth' },
        context: { ipAddress: '192.168.1.1', correlationId: 'test-dedup' }
      };

      alerter.processEvent(event);
      alerter.processEvent(event);
      alerter.processEvent(event);
    });
  });

  // =============================================================================
  // ALERT MANAGEMENT TESTS
  // =============================================================================

  describe('Alert Management', () => {
    it('должен acknowledge алерт', (done) => {
      alerter.on('alert-created', (alert) => {
        const result = alerter.acknowledgeAlert(alert.alertId, 'user456');
        expect(result).toBe(true);
        done();
      });

      alerter.processEvent({
        eventId: 'test-ack',
        timestamp: new Date().toISOString(),
        category: SecurityCategory.AUTHENTICATION,
        eventType: 'LOGIN_FAILURE',
        severity: SecuritySeverity.HIGH,
        outcome: SecurityOutcome.FAILURE,
        actor: { type: 'user', id: 'user123' },
        action: 'login',
        resource: { type: 'auth' },
        context: { ipAddress: '192.168.1.1', correlationId: 'test-ack' }
      });
    });

    it('должен resolve алерт', (done) => {
      alerter.on('alert-created', (alert) => {
        alerter.acknowledgeAlert(alert.alertId, 'user456');
        const result = alerter.resolveAlert(alert.alertId, 'user456');
        expect(result).toBe(true);
        done();
      });

      alerter.processEvent({
        eventId: 'test-resolve',
        timestamp: new Date().toISOString(),
        category: SecurityCategory.AUTHENTICATION,
        eventType: 'LOGIN_FAILURE',
        severity: SecuritySeverity.HIGH,
        outcome: SecurityOutcome.FAILURE,
        actor: { type: 'user', id: 'user123' },
        action: 'login',
        resource: { type: 'auth' },
        context: { ipAddress: '192.168.1.1', correlationId: 'test-resolve' }
      });
    });

    it('должен возвращать false для несуществующего алерта', () => {
      const result = alerter.acknowledgeAlert('non-existent-id', 'user456');
      expect(result).toBe(false);
    });
  });

  // =============================================================================
  // STATS TESTS
  // =============================================================================

  describe('Stats', () => {
    it('должен возвращать статистику', () => {
      const stats = alerter.getStats();
      
      expect(stats).toBeDefined();
      expect(typeof stats.activeAlerts).toBe('number');
      expect(typeof stats.totalAlerts).toBe('number');
      expect(stats.alertsBySeverity).toBeDefined();
      expect(stats.alertsByStatus).toBeDefined();
    });
  });
});

// =============================================================================
// EVENT TYPES TESTS
// =============================================================================

describe('SecurityEventTypes', () => {
  describe('EventTypes Constants', () => {
    it('должен экспортировать константы событий', () => {
      expect(EventTypes.LOGIN).toBe('LOGIN_SUCCESS');
      expect(EventTypes.LOGIN_FAILURE).toBe('LOGIN_FAILURE');
      expect(EventTypes.LOGOUT).toBe('LOGOUT');
      expect(EventTypes.ACCESS_GRANTED).toBe('ACCESS_GRANTED');
      expect(EventTypes.ACCESS_DENIED).toBe('ACCESS_DENIED');
    });
  });
});
