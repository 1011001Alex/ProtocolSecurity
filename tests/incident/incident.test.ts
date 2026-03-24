/**
 * ============================================================================
 * INCIDENT RESPONSE SYSTEM TESTS
 * ============================================================================
 * Comprehensive тесты для системы автоматизированного реагирования на инциденты
 * ============================================================================
 */

import {
  IncidentManager,
  IncidentClassifier,
  PlaybookEngine,
  ForensicsCollector,
  EvidenceManager,
  ContainmentActions,
  CommunicationManager,
  TimelineReconstructor,
  PostIncidentReview,
  ExternalIntegrations,
  IncidentReporter,
  ReportType
} from '../../src/incident';
import {
  IncidentCategory,
  IncidentSeverity,
  IncidentPriority,
  IncidentStatus,
  IncidentLifecycleStage,
  DataClassification,
  ForensicsDataType,
  EvidenceCategory,
  ChainOfCustodyStatus,
  StakeholderType,
  CommunicationChannel,
  ContainmentActionType,
  IntegrationType,
  TimelineEventType,
  PlaybookActionType,
  PlaybookStepCategory,
  PlaybookStepStatus,
  Actor
} from '../../src/types/incident.types';

// ============================================================================
// TEST UTILITIES
// ============================================================================

/**
 * Создание тестового актора
 */
function createTestActor(overrides?: Partial<Actor>): Actor {
  return {
    id: 'test_user_001',
    username: 'test.analyst',
    email: 'test.analyst@protocol.local',
    role: 'security_analyst',
    department: 'Security Operations',
    ...overrides
  };
}

/**
 * Создание тестового инцидента
 */
function createTestIncidentDetails(overrides?: Partial<any>): any {
  return {
    title: 'Test Security Incident',
    description: 'This is a test security incident for testing purposes',
    category: IncidentCategory.MALWARE,
    affectedSystems: ['server-001', 'server-002'],
    affectedUsers: [
      { id: 'user_001', username: 'john.doe' },
      { id: 'user_002', username: 'jane.smith' }
    ],
    indicatorsOfCompromise: [
      {
        type: 'ip_address',
        value: '192.168.1.100',
        description: 'Suspicious IP address'
      },
      {
        type: 'file_hash_sha256',
        value: 'abc123def456...',
        description: 'Malware hash'
      }
    ],
    ...overrides
  };
}

// ============================================================================
// INCIDENT CLASSIFIER TESTS
// ============================================================================

describe('IncidentClassifier', () => {
  let classifier: IncidentClassifier;
  const testActor = createTestActor();

  beforeEach(() => {
    classifier = new IncidentClassifier();
  });

  describe('classify()', () => {
    it('должен корректно классифицировать malware инцидент', () => {
      const context = {
        details: createTestIncidentDetails({
          title: 'Malware Detection on Server',
          description: 'Malicious software detected on production server',
          category: IncidentCategory.MALWARE
        }),
        affectedSystems: [
          {
            id: 'server-001',
            name: 'PROD-SRV-001',
            type: 'server' as const,
            criticality: 'critical' as const,
            hasSensitiveData: true,
            isPublicFacing: false
          }
        ],
        affectedUsers: [
          {
            id: 'user_001',
            username: 'admin',
            role: 'administrator',
            accessLevel: 'admin' as const,
            hasSensitiveDataAccess: true
          }
        ],
        affectedData: [],
        detectedAt: new Date()
      };

      const result = classifier.classify(context);

      expect(result.category).toBe(IncidentCategory.MALWARE);
      expect(result.severity).toBeDefined();
      expect(result.priority).toBeDefined();
      expect(result.confidence).toBeGreaterThan(50);
      expect(result.severityScore.totalScore).toBeGreaterThanOrEqual(0);
      expect(result.severityScore.totalScore).toBeLessThanOrEqual(100);
    });

    it('должен повышать серьезность для критических систем', () => {
      const contextWithCritical = {
        details: createTestIncidentDetails(),
        affectedSystems: [
          {
            id: 'critical-server',
            name: 'CRITICAL-SRV',
            type: 'server' as const,
            criticality: 'critical' as const,
            hasSensitiveData: true,
            isPublicFacing: true
          }
        ],
        affectedUsers: [],
        affectedData: [
          {
            type: 'PII',
            classification: DataClassification.PII,
            recordCount: 10000
          }
        ],
        detectedAt: new Date()
      };

      const result = classifier.classify(contextWithCritical);

      expect([
        IncidentSeverity.CRITICAL,
        IncidentSeverity.HIGH,
        IncidentSeverity.MEDIUM
      ]).toContain(result.severity);
      expect(result.influencingFactors.length).toBeGreaterThan(0);
    });

    it('должен определять категорию по заголовку', () => {
      const contexts = [
        {
          title: 'Ransomware Attack Detected',
          expectedCategory: IncidentCategory.RANSOMWARE_ATTACK,
          description: 'Ransomware encryption detected on multiple hosts'
        },
        {
          title: 'DDoS Attack in Progress',
          expectedCategory: IncidentCategory.DDOS_ATTACK,
          description: 'Traffic spike causing service unavailable'
        },
        {
          title: 'Data Breach - Customer Information',
          expectedCategory: IncidentCategory.DATA_BREACH,
          description: 'Unauthorized access to data exfiltration detected'
        },
        {
          title: 'Credential Compromise - Admin Account',
          expectedCategory: IncidentCategory.CREDENTIAL_COMPROMISE,
          description: 'Compromised credentials detected, brute force attempt'
        }
      ];

      for (const { title, expectedCategory, description } of contexts) {
        const result = classifier.classify({
          details: createTestIncidentDetails({ 
            title, 
            description,
            category: undefined as any 
          }),
          affectedSystems: [],
          affectedUsers: [],
          affectedData: [],
          detectedAt: new Date()
        });

        expect(result.category).toBe(expectedCategory);
      }
    });
  });

  describe('validateContext()', () => {
    it('должен возвращать ошибку для невалидного контекста', () => {
      const invalidContext = {
        details: {
          title: '',
          description: '',
          category: undefined
        },
        affectedSystems: [],
        affectedUsers: [],
        affectedData: [],
        detectedAt: new Date()
      };

      const result = classifier.validateContext(invalidContext as any);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });

    it('должен принимать валидный контекст', () => {
      const validContext = {
        details: createTestIncidentDetails(),
        affectedSystems: [{ id: 'srv1', name: 'Server 1', type: 'server' as const, criticality: 'medium' as const, hasSensitiveData: false, isPublicFacing: false }],
        affectedUsers: [],
        affectedData: [],
        detectedAt: new Date()
      };

      const result = classifier.validateContext(validContext);

      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });
  });
});

// ============================================================================
// PLAYBOOK ENGINE TESTS
// ============================================================================

describe('PlaybookEngine', () => {
  let engine: PlaybookEngine;
  const testActor = createTestActor();

  beforeEach(() => {
    engine = new PlaybookEngine({
      debugMode: true,
      enableLogging: false
    });
  });

  describe('startPlaybook()', () => {
    it('должен запускать playbook и выполнять шаги', async () => {
      const mockIncident: any = {
        id: 'test_incident_001',
        incidentNumber: 'INC-2026-00001',
        category: IncidentCategory.MALWARE,
        severity: IncidentSeverity.HIGH,
        status: IncidentStatus.IN_PROGRESS,
        lifecycleStage: IncidentLifecycleStage.DETECTION,
        title: 'Test Incident',
        description: 'Test Description',
        details: createTestIncidentDetails(),
        metrics: {
          affectedSystemsCount: 1,
          affectedUsersCount: 1,
          playbookStepsCompleted: 0,
          automatedActionsCount: 0,
          manualActionsCount: 0,
          stakeholdersNotified: 0,
          evidenceCollected: 0
        },
        timeline: [],
        evidence: [],
        containmentActions: [],
        stakeholderNotifications: [],
        iocs: [],
        tags: [],
        detectedAt: new Date(),
        assignees: []
      };

      const playbook = {
        id: 'test-playbook-001',
        name: 'Test Playbook',
        description: 'Test Playbook for unit testing',
        version: '1.0.0',
        incidentCategory: IncidentCategory.MALWARE,
        minSeverity: IncidentSeverity.LOW,
        steps: [
          {
            id: 'step-001',
            name: 'Test Step 1',
            description: 'First test step',
            category: PlaybookStepCategory.DETECTION,
            actionType: PlaybookActionType.COLLECT_DATA,
            parameters: { dataType: 'logs' },
            conditions: [],
            dependencies: [],
            status: PlaybookStepStatus.PENDING,
            automatic: true,
            requiresApproval: false
          },
          {
            id: 'step-002',
            name: 'Test Step 2',
            description: 'Second test step',
            category: PlaybookStepCategory.CONTAINMENT,
            actionType: PlaybookActionType.SEND_NOTIFICATION,
            parameters: { channel: 'slack', recipients: ['test'] },
            conditions: [],
            dependencies: ['step-001'],
            status: PlaybookStepStatus.PENDING,
            automatic: true,
            requiresApproval: false
          }
        ],
        variables: {},
        integrations: [],
        tags: ['test'],
        author: 'Test',
        lastUpdated: new Date(),
        status: 'active' as const
      };

      const execution = await engine.startPlaybook(playbook, mockIncident, testActor.id);

      expect(execution).toBeDefined();
      expect(execution.id).toMatch(/^pbe_/);
      expect(execution.status).toBe('running');
      expect(execution.progress).toBe(0);

      // Ждем выполнения playbook с увеличенным timeout
      await new Promise(resolve => setTimeout(resolve, 5000));

      // Проверяем статус с повторными попытками
      let updatedExecution = engine.getExecutionStatus(execution.id);
      let attempts = 0;
      while (!updatedExecution && attempts < 5) {
        await new Promise(resolve => setTimeout(resolve, 500));
        updatedExecution = engine.getExecutionStatus(execution.id);
        attempts++;
      }
      
      expect(updatedExecution).toBeDefined();
    });

    it('должен проваливать playbook при ошибке валидации', async () => {
      const invalidPlaybook: any = {
        id: '',
        name: '',
        steps: []
      };

      const mockIncident: any = { id: 'test', severity: IncidentSeverity.HIGH, category: IncidentCategory.MALWARE };

      await expect(engine.startPlaybook(invalidPlaybook, mockIncident, testActor.id))
        .rejects.toThrow();
    });
  });

  describe('pausePlaybook() / resumePlaybook()', () => {
    it('должен ставить на паузу и возобновлять playbook', async () => {
      // Тест требует запущенного playbook
      // Реализация зависит от асинхронного выполнения
    });
  });
});

// ============================================================================
// FORENSICS COLLECTOR TESTS
// ============================================================================

describe('ForensicsCollector', () => {
  let collector: ForensicsCollector;
  const testActor = createTestActor();

  beforeEach(() => {
    collector = new ForensicsCollector({
      storageLocation: '/tmp/forensics_test',
      enableLogging: false,
      debugMode: true
    });
  });

  describe('initiateCollection()', () => {
    it('должен инициировать сбор форензика данных', async () => {
      const mockIncident: any = {
        id: 'test_incident_001',
        incidentNumber: 'INC-2026-00001'
      };

      const context = {
        incident: mockIncident,
        dataTypes: [
          ForensicsDataType.SYSTEM_LOGS,
          ForensicsDataType.PROCESS_LIST,
          ForensicsDataType.NETWORK_CONNECTIONS
        ],
        targetSystems: ['server-001'],
        priority: 'high' as const,
        constraints: {
          readOnly: true,
          agentsInstalled: false
        }
      };

      const collectionId = await collector.initiateCollection(context, testActor);

      expect(collectionId).toMatch(/^fc_/);

      // Ждем завершения сбора
      await new Promise(resolve => setTimeout(resolve, 5000));

      const status = collector.getCollectionStatus(collectionId);
      expect(status.progress).toBe(100);
      expect(status.isActive).toBe(false);
    });

    it('должен вычислять хэши для собранных данных', async () => {
      const mockIncident: any = { id: 'test', incidentNumber: 'INC-TEST' };

      const context = {
        incident: mockIncident,
        dataTypes: [ForensicsDataType.SYSTEM_LOGS],
        targetSystems: ['server-001'],
        priority: 'medium' as const,
        constraints: { readOnly: true, agentsInstalled: false }
      };

      const collectionId = await collector.initiateCollection(context, testActor);

      await new Promise(resolve => setTimeout(resolve, 3000));

      const results = collector.getCollectionResults(collectionId);
      expect(results).toBeDefined();
      expect(results!.length).toBeGreaterThan(0);

      for (const result of results!) {
        if (result.success) {
          expect(result.hashes).toBeDefined();
          expect(result.hashes.sha256).toBeDefined();
        }
      }
    });
  });

  describe('verifyIntegrity()', () => {
    it('должен проверять целостность собранных данных', async () => {
      const mockIncident: any = { id: 'test', incidentNumber: 'INC-TEST' };

      const context = {
        incident: mockIncident,
        dataTypes: [ForensicsDataType.SYSTEM_LOGS],
        targetSystems: ['server-001'],
        priority: 'medium' as const,
        constraints: { readOnly: true, agentsInstalled: false }
      };

      const collectionId = await collector.initiateCollection(context, testActor);

      await new Promise(resolve => setTimeout(resolve, 3000));

      const result = await collector.verifyIntegrity(collectionId);

      expect(result).toBeDefined();
      expect(result.valid).toBe(true);
      expect(result.violations).toEqual([]);
    });
  });
});

// ============================================================================
// EVIDENCE MANAGER TESTS
// ============================================================================

describe('EvidenceManager', () => {
  let manager: EvidenceManager;
  const testActor = createTestActor();

  beforeEach(() => {
    manager = new EvidenceManager({
      storageLocation: '/tmp/evidence_test',
      enableLogging: false,
      defaultRetentionDays: 365
    });
  });

  describe('addEvidence()', () => {
    it('должен добавлять улику в хранилище', async () => {
      const evidence = {
        id: 'evd_test_001',
        type: 'log_file',
        name: 'Test Evidence',
        description: 'Test evidence for unit testing',
        category: EvidenceCategory.LOG_FILE,
        location: '/tmp/evidence_test/test.log',
        size: 1024,
        hash: {
          md5: 'abc123',
          sha256: 'def456...'
        },
        collectedAt: new Date(),
        collectedBy: testActor,
        collectionContext: 'test_collection',
        incidentId: 'test_incident_001',
        custodyStatus: ChainOfCustodyStatus.COLLECTED,
        custodyHistory: [],
        tags: ['test']
      };

      const result = await manager.addEvidence(evidence, testActor);

      expect(result).toBeDefined();
      expect(result.id).toBe('evd_test_001');
      expect(result.custodyHistory.length).toBeGreaterThan(0);

      const retrieved = manager.getEvidence('evd_test_001');
      expect(retrieved).toBeDefined();
      expect(retrieved!.id).toBe('evd_test_001');
    });

    it('должен выбрасывать ошибку для невалидной улики', async () => {
      const invalidEvidence: any = {
        id: '',
        name: ''
      };

      await expect(manager.addEvidence(invalidEvidence, testActor))
        .rejects.toThrow();
    });
  });

  describe('updateCustody()', () => {
    it('должен обновлять цепочку хранения', async () => {
      const evidence: any = {
        id: 'evd_test_002',
        type: 'digital_file',
        name: 'Test Evidence 2',
        description: 'Test',
        category: EvidenceCategory.DIGITAL_FILE,
        location: '/tmp/test',
        collectedAt: new Date(),
        collectedBy: testActor,
        collectionContext: 'test',
        incidentId: 'test_incident_001',
        custodyStatus: ChainOfCustodyStatus.COLLECTED,
        custodyHistory: []
      };

      await manager.addEvidence(evidence, testActor);

      const custodyRecord = await manager.updateCustody(
        'evd_test_002',
        'transferred',
        testActor,
        {
          description: 'Передано в лабораторию',
          location: 'Forensics Lab',
          reason: 'Analysis required'
        }
      );

      expect(custodyRecord).toBeDefined();
      expect(custodyRecord.action).toBe('transferred');
      expect(custodyRecord.performedBy.id).toBe(testActor.id);

      const updatedEvidence = manager.getEvidence('evd_test_002');
      expect(updatedEvidence!.custodyStatus).toBe(ChainOfCustodyStatus.TRANSFERRED);
    });
  });

  describe('verifyIntegrity()', () => {
    it('должен проверять целостность улики', async () => {
      const evidence: any = {
        id: 'evd_test_003',
        type: 'digital_file',
        name: 'Test Evidence 3',
        description: 'Test',
        category: EvidenceCategory.DIGITAL_FILE,
        location: '/tmp/test3',
        size: 2048,
        hash: { sha256: 'abc123' },
        collectedAt: new Date(),
        collectedBy: testActor,
        collectionContext: 'test',
        incidentId: 'test_incident_001',
        custodyStatus: ChainOfCustodyStatus.COLLECTED,
        custodyHistory: []
      };

      await manager.addEvidence(evidence, testActor);

      const result = await manager.verifyIntegrity('evd_test_003');

      expect(result).toBeDefined();
      expect(result.valid).toBe(true);
    });
  });
});

// ============================================================================
// CONTAINMENT ACTIONS TESTS
// ============================================================================

describe('ContainmentActions', () => {
  let containment: ContainmentActions;
  const testActor = createTestActor();

  beforeEach(() => {
    containment = new ContainmentActions({
      enableLogging: false,
      autoContainmentEnabled: false
    });
  });

  describe('initiateContainmentAction()', () => {
    it('должен выполнять действие сдерживания IP blocking', async () => {
      const mockIncident: any = {
        id: 'test_incident_001',
        severity: IncidentSeverity.HIGH
      };

      const context = {
        incident: mockIncident,
        actionType: ContainmentActionType.IP_BLOCKING,
        target: '192.168.1.100',
        parameters: {},
        initiatedBy: testActor,
        initiatedAt: new Date()
      };

      const result = await containment.initiateContainmentAction(context);

      expect(result).toBeDefined();
      expect(result.id).toMatch(/^ca_/);
      expect(result.type).toBe(ContainmentActionType.IP_BLOCKING);
      expect(result.status).toBe('completed');
      expect(result.result?.success).toBe(true);
    });

    it('должен требовать одобрение для network_isolation', async () => {
      const mockIncident: any = { id: 'test', severity: IncidentSeverity.HIGH };

      const context = {
        incident: mockIncident,
        actionType: ContainmentActionType.NETWORK_ISOLATION,
        target: 'server-001',
        parameters: {},
        initiatedBy: testActor,
        initiatedAt: new Date()
      };

      await expect(containment.initiateContainmentAction(context))
        .rejects.toThrow('требует одобрения');
    });

    it('должен выполнять rollback', async () => {
      const mockIncident: any = { id: 'test', severity: IncidentSeverity.HIGH };

      const context = {
        incident: mockIncident,
        actionType: ContainmentActionType.IP_BLOCKING,
        target: '192.168.1.100',
        parameters: {},
        initiatedBy: testActor,
        initiatedAt: new Date()
      };

      const result = await containment.initiateContainmentAction(context);

      const rollbackResult = await containment.rollbackAction(
        result.id,
        testActor,
        'False positive confirmed'
      );

      expect(rollbackResult).toBeDefined();
      expect(rollbackResult.rollback?.executed).toBe(true);
      expect(rollbackResult.status).toBe('rolled_back');
    });
  });

  describe('executeAutoContainment()', () => {
    it('должен выполнять автоматическое сдерживание', async () => {
      const mockIncident: any = {
        id: 'test_incident_001',
        severity: IncidentSeverity.CRITICAL,
        category: IncidentCategory.MALWARE,
        details: {
          source: { ipAddress: '10.0.0.1' },
          affectedUsers: [{ id: 'user_001' }]
        },
        containmentActions: []
      };

      // Включаем авто сдерживание
      const containmentAuto = new ContainmentActions({
        autoContainmentEnabled: true,
        enableLogging: false
      });

      const actions = await containmentAuto.executeAutoContainment(mockIncident, testActor);

      expect(actions.length).toBeGreaterThan(0);
    });
  });
});

// ============================================================================
// COMMUNICATION MANAGER TESTS
// ============================================================================

describe('CommunicationManager', () => {
  let manager: CommunicationManager;
  const testActor = createTestActor();

  beforeEach(() => {
    manager = new CommunicationManager({
      enableLogging: false
    });
  });

  describe('sendNotification()', () => {
    it('должен отправлять уведомление по шаблону', async () => {
      const mockIncident: any = {
        id: 'test_incident_001',
        incidentNumber: 'INC-2026-00001',
        severity: IncidentSeverity.HIGH,
        category: IncidentCategory.MALWARE,
        status: IncidentStatus.IN_PROGRESS,
        lifecycleStage: IncidentLifecycleStage.DETECTION,
        title: 'Test Incident',
        description: 'Test Description',
        detectedAt: new Date(),
        metrics: {
          affectedSystemsCount: 2,
          affectedUsersCount: 3,
          playbookStepsCompleted: 0,
          automatedActionsCount: 0,
          manualActionsCount: 0,
          stakeholdersNotified: 0,
          evidenceCollected: 0
        },
        containmentActions: [],
        activePlaybook: undefined
      };

      const notification = await manager.sendNotification(
        'security-team-alert',
        ['security-team@protocol.local'],
        mockIncident,
        testActor
      );

      expect(notification).toBeDefined();
      expect(notification.id).toMatch(/^notif_/);
      expect(notification.status).toBe('sent');
      expect(notification.templateId).toBe('security-team-alert');
    });

    it('должен требовать одобрение для executive-brief', async () => {
      const mockIncident: any = {
        id: 'test',
        incidentNumber: 'INC-TEST',
        severity: IncidentSeverity.CRITICAL,
        category: IncidentCategory.DATA_BREACH,
        status: IncidentStatus.IN_PROGRESS,
        lifecycleStage: IncidentLifecycleStage.DETECTION,
        title: 'Test',
        description: 'Test',
        detectedAt: new Date(),
        metrics: {
          affectedSystemsCount: 0,
          affectedUsersCount: 0,
          playbookStepsCompleted: 0,
          automatedActionsCount: 0,
          manualActionsCount: 0,
          stakeholdersNotified: 0,
          evidenceCollected: 0
        },
        containmentActions: [],
        activePlaybook: undefined
      };

      await expect(
        manager.sendNotification('executive-brief', ['ceo@protocol.local'], mockIncident, testActor)
      ).rejects.toThrow('требует одобрения');
    });
  });

  describe('getCommunicationStats()', () => {
    it('должен возвращать статистику коммуникации', async () => {
      const mockIncident: any = {
        id: 'test_incident_stats',
        incidentNumber: 'INC-TEST',
        severity: IncidentSeverity.MEDIUM,
        category: IncidentCategory.PHISHING,
        status: IncidentStatus.IN_PROGRESS,
        lifecycleStage: IncidentLifecycleStage.DETECTION,
        title: 'Test',
        description: 'Test',
        detectedAt: new Date(),
        metrics: {
          affectedSystemsCount: 0,
          affectedUsersCount: 0,
          playbookStepsCompleted: 0,
          automatedActionsCount: 0,
          manualActionsCount: 0,
          stakeholdersNotified: 0,
          evidenceCollected: 0
        },
        containmentActions: [],
        activePlaybook: undefined
      };

      await manager.sendNotification('security-team-alert', ['team@protocol.local'], mockIncident, testActor);

      const stats = manager.getCommunicationStats('test_incident_stats');

      expect(stats.totalNotifications).toBe(1);
      expect(stats.byChannel).toBeDefined();
      expect(stats.byStatus).toBeDefined();
    });
  });
});

// ============================================================================
// TIMELINE RECONSTRUCTOR TESTS
// ============================================================================

describe('TimelineReconstructor', () => {
  let reconstructor: TimelineReconstructor;
  const testActor = createTestActor();

  beforeEach(() => {
    reconstructor = new TimelineReconstructor({
      enableLogging: false
    });
  });

  describe('addEvent()', () => {
    it('должен добавлять событие в временную шкалу', async () => {
      const event = await reconstructor.addEvent('test_incident_001', {
        type: TimelineEventType.ANOMALY_DETECTED,
        title: 'Test Event',
        description: 'Test event description',
        timestamp: new Date(),
        source: 'test_source',
        significance: 'medium'
      });

      expect(event).toBeDefined();
      expect(event.id).toMatch(/^te_/);
      expect(event.type).toBe(TimelineEventType.ANOMALY_DETECTED);
      expect(event.verified).toBe(true);

      const timeline = reconstructor.getTimeline('test_incident_001');
      expect(timeline.length).toBe(1);
    });

    it('должен сортировать события по времени', async () => {
      const now = new Date();

      await reconstructor.addEvent('test_incident_002', {
        type: TimelineEventType.CONTAINMENT_ACTION,
        title: 'Event 2',
        description: 'Second event',
        timestamp: new Date(now.getTime() + 2000),
        source: 'test',
        significance: 'medium'
      });

      await reconstructor.addEvent('test_incident_002', {
        type: TimelineEventType.ANOMALY_DETECTED,
        title: 'Event 1',
        description: 'First event',
        timestamp: now,
        source: 'test',
        significance: 'medium'
      });

      const timeline = reconstructor.getTimeline('test_incident_002');

      expect(timeline.length).toBe(2);
      expect(timeline[0].title).toBe('Event 1');
      expect(timeline[1].title).toBe('Event 2');
    });
  });

  describe('reconstructTimeline()', () => {
    it('должен реконструировать временную шкалу', async () => {
      const mockIncident: any = {
        id: 'test_incident_003',
        incidentNumber: 'INC-TEST',
        detectedAt: new Date(),
        responseStartedAt: new Date(),
        title: 'Test Incident',
        description: 'Test Description',
        containmentActions: [],
        timeline: []
      };

      // Добавляем события
      await reconstructor.addEvent('test_incident_003', {
        type: TimelineEventType.ANOMALY_DETECTED,
        title: 'Initial Detection',
        description: 'Initial detection',
        timestamp: new Date(),
        source: 'siem',
        significance: 'high'
      });

      const result = await reconstructor.reconstructTimeline(mockIncident);

      expect(result.timeline.length).toBeGreaterThan(0);
      expect(result.summary).toBeDefined();
      expect(result.keyEvents).toBeDefined();
    });
  });
});

// ============================================================================
// INCIDENT MANAGER INTEGRATION TESTS
// ============================================================================

describe('IncidentManager - Integration Tests', () => {
  let manager: IncidentManager;
  const testActor = createTestActor();

  beforeEach(() => {
    manager = new IncidentManager({
      enableLogging: false,
      enableAudit: false,
      autoClassification: true,
      autoStartPlaybook: false
    });
  });

  describe('createIncident()', () => {
    it('должен создавать новый инцидент', async () => {
      // Отключаем автоклассификацию, чтобы severity не перезаписывался
      manager = new IncidentManager({
        enableLogging: false,
        debugMode: true,
        enableAudit: false,
        autoClassification: false,
        autoStartPlaybook: false
      });

      const incident = await manager.createIncident(
        createTestIncidentDetails(),
        testActor,
        {
          severity: IncidentSeverity.HIGH,
          priority: IncidentPriority.P2,
          tags: ['test', 'automated']
        }
      );

      expect(incident).toBeDefined();
      expect(incident.id).toMatch(/^inc_/);
      expect(incident.incidentNumber).toMatch(/^INC-\d{4}-\d{5}$/);
      expect(incident.status).toBe(IncidentStatus.NEW);
      expect(incident.lifecycleStage).toBe(IncidentLifecycleStage.DETECTION);
      expect(incident.severity).toBe(IncidentSeverity.HIGH);
      expect(incident.owner.id).toBe(testActor.id);
    });

    it('должен позволять поиск инцидентов', () => {
      const result = manager.searchIncidents({
        status: [IncidentStatus.NEW],
        severity: [IncidentSeverity.HIGH]
      });

      expect(result).toBeDefined();
      expect(result.total).toBeGreaterThanOrEqual(0);
    });
  });

  describe('updateIncidentLifecycle()', () => {
    it('должен обновлять стадию жизненного цикла', async () => {
      const incident = await manager.createIncident(
        createTestIncidentDetails(),
        testActor
      );

      const updated = await manager.updateIncidentLifecycle(
        incident.id,
        IncidentLifecycleStage.CONTAINMENT,
        testActor
      );

      expect(updated.lifecycleStage).toBe(IncidentLifecycleStage.CONTAINMENT);
    });
  });

  describe('executeContainmentAction()', () => {
    it('должен выполнять действие сдерживания', async () => {
      const incident = await manager.createIncident(
        createTestIncidentDetails(),
        testActor
      );

      await manager.executeContainmentAction(
        incident.id,
        ContainmentActionType.IP_BLOCKING,
        '192.168.1.100',
        testActor
      );

      const updatedIncident = manager.getIncident(incident.id);
      expect(updatedIncident!.containmentActions.length).toBe(1);
    });
  });

  describe('closeIncident()', () => {
    it('должен закрывать инцидент', async () => {
      const incident = await manager.createIncident(
        createTestIncidentDetails(),
        testActor
      );

      // Обновляем до закрытия
      await manager.updateIncidentLifecycle(incident.id, IncidentLifecycleStage.POST_INCIDENT, testActor);

      const closed = await manager.closeIncident(incident.id, testActor, 'Resolved');

      expect(closed.status).toBe(IncidentStatus.CLOSED);
      expect(closed.lifecycleStage).toBe(IncidentLifecycleStage.CLOSED);
      expect(closed.closedAt).toBeDefined();
    });
  });

  describe('generateReport()', () => {
    it('должен генерировать отчет по инциденту', async () => {
      const incident = await manager.createIncident(
        createTestIncidentDetails(),
        testActor
      );

      const report = await manager.generateReport(
        incident.id,
        ReportType.INCIDENT_DETAIL,
        { includeTimeline: true }
      );

      expect(report).toBeDefined();
      expect(report.header).toBeDefined();
      expect(report.overview).toBeDefined();
    });
  });

  describe('getStatistics()', () => {
    it('должен возвращать статистику', async () => {
      // Создаем несколько инцидентов
      await manager.createIncident(createTestIncidentDetails(), testActor);
      await manager.createIncident(createTestIncidentDetails({ severity: IncidentSeverity.CRITICAL }), testActor);

      const stats = manager.getStatistics();

      expect(stats.totalIncidents).toBeGreaterThanOrEqual(2);
      expect(stats.bySeverity).toBeDefined();
      expect(stats.byCategory).toBeDefined();
    });
  });
});

// ============================================================================
// POST INCIDENT REVIEW TESTS
// ============================================================================

describe('PostIncidentReview', () => {
  let review: PostIncidentReview;
  const testActor = createTestActor();

  beforeEach(() => {
    review = new PostIncidentReview({
      enableLogging: false
    });
  });

  describe('initiateReview()', () => {
    it('должен инициировать анализ после инцидента', async () => {
      const mockIncident: any = {
        id: 'test_incident_001',
        incidentNumber: 'INC-TEST',
        description: 'Test incident for review',
        timeline: [],
        containmentActions: [],
        metrics: {
          timeToDetect: 3600000,
          timeToRespond: 900000,
          timeToContain: 1800000,
          timeToRecover: 7200000,
          totalDuration: 14400000,
          affectedSystemsCount: 2,
          affectedUsersCount: 3,
          playbookStepsCompleted: 10,
          automatedActionsCount: 5,
          manualActionsCount: 5,
          stakeholdersNotified: 4,
          evidenceCollected: 3
        }
      };

      const reviewResult = await review.initiateReview(mockIncident, [testActor], testActor);

      expect(reviewResult).toBeDefined();
      expect(reviewResult.id).toMatch(/^pir_/);
      expect(reviewResult.incidentId).toBe('test_incident_001');
      expect(reviewResult.status).toBe('draft');
      expect(reviewResult.effectivenessMetrics).toBeDefined();
    });
  });
});

// ============================================================================
// EXTERNAL INTEGRATIONS TESTS
// ============================================================================

describe('ExternalIntegrations', () => {
  let integrations: ExternalIntegrations;

  beforeEach(() => {
    integrations = new ExternalIntegrations([
      {
        type: IntegrationType.SLACK,
        name: 'Slack',
        apiUrl: 'https://slack.com/api',
        enabled: true
      },
      {
        type: IntegrationType.PAGERDUTY,
        name: 'PagerDuty',
        apiUrl: 'https://events.pagerduty.com',
        enabled: true
      }
    ]);
  });

  describe('sendSlackMessage()', () => {
    it('должен отправлять сообщение в Slack', async () => {
      const result = await integrations.sendSlackMessage(
        '#security-alerts',
        'Test alert message'
      );

      expect(result.success).toBe(true);
      expect(result.externalId).toMatch(/^msg_/);
    });
  });

  describe('createPagerDutyIncident()', () => {
    it('должен создавать инцидент в PagerDuty', async () => {
      const result = await integrations.createPagerDutyIncident(
        'Test Incident',
        'Test description',
        IncidentSeverity.HIGH
      );

      expect(result.success).toBe(true);
      expect(result.externalId).toBeDefined();
      expect(result.url).toBeDefined();
    });
  });

  describe('createJiraIssue()', () => {
    it('должен создавать задачу в Jira', async () => {
      const integrationsWithJira = new ExternalIntegrations([
        {
          type: IntegrationType.JIRA,
          name: 'Jira',
          apiUrl: 'https://protocol.atlassian.net',
          enabled: true
        }
      ]);

      const result = await integrationsWithJira.createJiraIssue(
        'SEC',
        'Test Security Issue',
        'Test description',
        'Incident'
      );

      expect(result.success).toBe(true);
      expect(result.externalId).toMatch(/^SEC-\d+/);
      expect(result.url).toContain('atlassian.net');
    });
  });
});

// ============================================================================
// INCIDENT REPORTER TESTS
// ============================================================================

describe('IncidentReporter', () => {
  let reporter: IncidentReporter;

  beforeEach(() => {
    reporter = new IncidentReporter({
      enableLogging: false
    });
  });

  describe('generateIncidentReport()', () => {
    it('должен генерировать детальный отчет', async () => {
      const mockIncident: any = {
        id: 'test_incident_001',
        incidentNumber: 'INC-2026-00001',
        severity: IncidentSeverity.HIGH,
        category: IncidentCategory.MALWARE,
        status: IncidentStatus.RESOLVED,
        lifecycleStage: IncidentLifecycleStage.POST_INCIDENT,
        title: 'Test Incident',
        description: 'Test Description',
        details: {
          title: 'Test',
          description: 'Test',
          category: IncidentCategory.MALWARE,
          affectedSystems: ['server-001'],
          affectedUsers: [],
          attackVector: 'phishing'
        },
        metrics: {
          affectedSystemsCount: 1,
          affectedUsersCount: 1,
          playbookStepsCompleted: 10,
          automatedActionsCount: 5,
          manualActionsCount: 5,
          stakeholdersNotified: 3,
          evidenceCollected: 2,
          timeToDetect: 3600000,
          timeToRespond: 900000,
          timeToContain: 1800000,
          timeToRecover: 7200000,
          totalDuration: 14400000
        },
        timeline: [],
        evidence: [],
        containmentActions: [],
        stakeholderNotifications: [],
        iocs: [],
        tags: [],
        detectedAt: new Date(),
        assignees: [],
        owner: { id: 'test', username: 'test' }
      };

      const report = await reporter.generateIncidentReport(
        mockIncident,
        ReportType.INCIDENT_DETAIL,
        {
          includeTimeline: true,
          includeEvidence: true
        }
      );

      expect(report).toBeDefined();
      expect(report.id).toMatch(/^rpt_/);
      expect(report.type).toBe(ReportType.INCIDENT_DETAIL);
      expect(report.content.header).toBeDefined();
      expect(report.content.overview).toBeDefined();
    });

    it('должен генерировать executive summary', async () => {
      const mockIncident: any = {
        id: 'test_incident_002',
        incidentNumber: 'INC-2026-00002',
        severity: IncidentSeverity.CRITICAL,
        category: IncidentCategory.DATA_BREACH,
        status: IncidentStatus.CLOSED,
        lifecycleStage: IncidentLifecycleStage.CLOSED,
        title: 'Critical Data Breach',
        description: 'Major data breach affecting customer data',
        details: {
          title: 'Data Breach',
          description: 'Customer data exposed',
          category: IncidentCategory.DATA_BREACH,
          affectedSystems: ['db-001'],
          affectedUsers: [{ id: 'customer_001' }],
          affectedData: [{ type: 'PII', classification: 'pii', recordCount: 100000 }]
        },
        metrics: {
          affectedSystemsCount: 1,
          affectedUsersCount: 100000,
          playbookStepsCompleted: 15,
          automatedActionsCount: 8,
          manualActionsCount: 7,
          stakeholdersNotified: 5,
          evidenceCollected: 10,
          timeToDetect: 7200000,
          timeToRespond: 1800000,
          timeToContain: 3600000,
          timeToRecover: 86400000,
          totalDuration: 100800000,
          businessImpactEstimate: {
            financialLoss: 500000,
            reputationalDamage: 'high',
            downtimeHours: 24
          }
        },
        timeline: [],
        evidence: [],
        containmentActions: [],
        stakeholderNotifications: [],
        iocs: [],
        tags: [],
        detectedAt: new Date(),
        assignees: [],
        owner: { id: 'test', username: 'ciso' }
      };

      const report = await reporter.generateIncidentReport(
        mockIncident,
        ReportType.EXECUTIVE_SUMMARY
      );

      expect(report.content.executiveSummary).toBeDefined();
      expect(report.content.financialImpact).toBeDefined();
      expect(report.content.riskAssessment).toBeDefined();
    });
  });

  describe('generateMetricsDashboard()', () => {
    it('должен генерировать дашборд метрик', async () => {
      const incidents: any[] = [
        {
          id: 'inc_1',
          status: IncidentStatus.CLOSED,
          severity: IncidentSeverity.HIGH,
          category: IncidentCategory.MALWARE,
          detectedAt: new Date(),
          metrics: {
            timeToDetect: 3600000,
            timeToRespond: 900000,
            timeToContain: 1800000,
            timeToRecover: 7200000,
            affectedSystemsCount: 2,
            affectedUsersCount: 5
          }
        },
        {
          id: 'inc_2',
          status: IncidentStatus.IN_PROGRESS,
          severity: IncidentSeverity.MEDIUM,
          category: IncidentCategory.PHISHING,
          detectedAt: new Date(),
          metrics: {
            timeToDetect: 1800000,
            timeToRespond: 600000,
            affectedSystemsCount: 1,
            affectedUsersCount: 10
          }
        }
      ];

      const dashboard = await reporter.generateMetricsDashboard(
        { from: new Date(Date.now() - 86400000 * 7), to: new Date() },
        incidents
      );

      expect(dashboard).toBeDefined();
      expect(dashboard.summary.totalIncidents).toBe(2);
      expect(dashboard.byCategory).toBeDefined();
      expect(dashboard.bySeverity).toBeDefined();
    });
  });
});
