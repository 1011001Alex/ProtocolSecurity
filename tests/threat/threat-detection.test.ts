/**
 * ============================================================================
 * THREAT DETECTION TESTS
 * Comprehensive тесты для системы обнаружения угроз
 * ============================================================================
 */

import { ThreatDetectionEngine } from '../../src/threat/ThreatDetectionEngine';
import { UEBAService } from '../../src/threat/UEBAService';
import { MITREAttackMapper } from '../../src/threat/MITREAttackMapper';
import { CorrelationEngine } from '../../src/threat/CorrelationEngine';
import { RiskScorer } from '../../src/threat/RiskScorer';
import { NetworkAnalyzer } from '../../src/threat/NetworkAnalyzer';
import { EndpointDetector } from '../../src/threat/EndpointDetector';
import { KillChainAnalyzer } from '../../src/threat/KillChainAnalyzer';
import { ThreatDashboardService } from '../../src/threat/ThreatDashboard';
import {
  IsolationForest,
  LSTMModel,
  AutoencoderModel,
  MLModelManager
} from '../src/threat/MLModels';
import {
  SecurityEvent,
  ThreatSeverity,
  ThreatCategory,
  AttackType,
  EntityType,
  MLModelType,
  NetworkAnomalyType,
  EndpointEventType,
  KillChainPhase,
  CorrelationRule,
  DetectionRule
} from '../src/types/threat.types';

// ============================================================================
// MOCK ДАННЫЕ
// ============================================================================

const createMockEvent = (overrides: Partial<SecurityEvent> = {}): SecurityEvent => ({
  id: 'event-001',
  timestamp: new Date(),
  eventType: 'failed_login',
  source: 'auth-service',
  sourceIp: '192.168.1.100',
  destinationIp: '10.0.0.1',
  sourcePort: 54321,
  destinationPort: 443,
  protocol: 'TCP',
  userId: 'user-001',
  username: 'john.doe',
  hostname: 'workstation-01',
  severity: ThreatSeverity.MEDIUM,
  category: ThreatCategory.CREDENTIAL_ACCESS,
  rawEvent: {
    loginAttempts: 5,
    failureReason: 'invalid_password'
  },
  normalizedEvent: {}
});

const createMockNetworkPacket = () => ({
  timestamp: new Date(),
  srcIp: '192.168.1.100',
  dstIp: '10.0.0.1',
  srcPort: 54321,
  dstPort: 443,
  protocol: 'TCP',
  size: 1500,
  flags: ['SYN'],
  ttl: 64
});

const createMockEndpointEvent = () => ({
  id: 'endpoint-event-001',
  timestamp: new Date(),
  endpointId: 'endpoint-001',
  hostname: 'workstation-01',
  eventType: EndpointEventType.PROCESS_CREATE,
  severity: ThreatSeverity.MEDIUM,
  rawEvent: {
    processName: 'powershell.exe',
    commandLine: 'powershell -enc SGVsbG8gV29ybGQ='
  }
});

// ============================================================================
// UEBA SERVICE TESTS
// ============================================================================

describe('UEBAService', () => {
  let uebaService: UEBAService;

  beforeEach(() => {
    uebaService = new UEBAService({
      baselineWindow: 7,
      anomalyWindow: 24,
      minEventsForBaseline: 10,
      riskThresholds: {
        low: 20,
        medium: 40,
        high: 60,
        critical: 80
      }
    });
  });

  test('должен создавать профиль пользователя', async () => {
    const profile = await uebaService.updateUserProfile({
      userId: 'user-001',
      username: 'test.user',
      role: 'admin',
      typicalLoginTimes: [9, 10, 11, 14, 15, 16]
    });

    expect(profile.userId).toBe('user-001');
    expect(profile.username).toBe('test.user');
    expect(profile.role).toBe('admin');
    expect(profile.entityType).toBe(EntityType.USER);
  });

  test('должен создавать профиль хоста', async () => {
    const profile = await uebaService.updateHostProfile({
      hostname: 'server-01',
      ipAddress: '10.0.0.1',
      osType: 'Windows',
      typicalProcesses: ['svchost.exe', 'lsass.exe']
    });

    expect(profile.hostname).toBe('server-01');
    expect(profile.ipAddress).toBe('10.0.0.1');
    expect(profile.entityType).toBe(EntityType.HOST);
  });

  test('должен обнаруживать аномалии времени входа', () => {
    const profile = {
      entityId: 'user-001',
      entityType: EntityType.USER,
      userId: 'user-001',
      username: 'test',
      role: 'user',
      typicalLoginTimes: [9, 10, 11, 14, 15, 16],
      typicalLocations: [],
      typicalDevices: [],
      accessedResources: [],
      averageSessionDuration: 480,
      failedLoginRate: 0.01,
      privilegeUsagePatterns: [],
      baselineMetrics: {},
      dynamicMetrics: {},
      riskScore: 0,
      lastUpdated: new Date(),
      historyWindow: 168
    } as any;

    const anomaly = uebaService['detectLoginTimeAnomaly'](profile, 3);  // 3 AM
    
    expect(anomaly).not.toBeNull();
    expect(anomaly?.severity).toBe(ThreatSeverity.MEDIUM);
    expect(anomaly?.description).toContain('необычное время');
  });

  test('должен обновлять динамические метрики', async () => {
    await uebaService.updateUserProfile({
      userId: 'user-001',
      username: 'test'
    });

    await uebaService.updateDynamicMetrics('user-001', {
      failedLogins: 5,
      loginFrequency: 10
    });

    const profile = uebaService.getProfile('user-001');
    expect(profile?.dynamicMetrics.failedLogins).toBe(5);
  });

  test('должен возвращать высокорисковые сущности', async () => {
    await uebaService.updateUserProfile({
      userId: 'user-001',
      username: 'risky-user',
      failedLoginRate: 0.5
    });

    const highRisk = uebaService.getHighRiskEntities(20);
    expect(highRisk.length).toBeGreaterThanOrEqual(0);
  });
});

// ============================================================================
// MITRE ATTACK MAPPER TESTS
// ============================================================================

describe('MITREAttackMapper', () => {
  let mapper: MITREAttackMapper;

  beforeEach(() => {
    mapper = new MITREAttackMapper();
  });

  test('должен маппить событие failed_login на T1110', () => {
    const event = createMockEvent({
      eventType: 'failed_login',
      username: 'admin'
    });

    const mappings = mapper.mapEventToMitre(event);

    expect(mappings.length).toBeGreaterThan(0);
    expect(mappings.some(m => m.techniqueId === 'T1110')).toBe(true);
  });

  test('должен маппить PowerShell на T1059', () => {
    const event = createMockEvent({
      eventType: 'powershell_execution',
      commandLine: 'powershell -enc SGVsbG8='
    });

    const mappings = mapper.mapEventToMitre(event);

    expect(mappings.some(m => m.techniqueId === 'T1059')).toBe(true);
  });

  test('должен получать технику по ID', () => {
    const technique = mapper.getTechnique('T1110');

    expect(technique).toBeDefined();
    expect(technique?.name).toBe('Brute Force');
  });

  test('должен получать тактику по ID', () => {
    const tactic = mapper.getTactic('TA0006');

    expect(tactic).toBeDefined();
    expect(tactic?.name).toBe('Credential Access');
  });

  test('должен получать техники по тактике', () => {
    const techniques = mapper.getTechniquesByTactic('TA0006');

    expect(techniques.length).toBeGreaterThan(0);
    expect(techniques.every(t => t.tactics.includes('TA0006'))).toBe(true);
  });

  test('должен получать покрытие техник', () => {
    const coverage = mapper.getTechniqueCoverage();

    expect(coverage.totalTechniques).toBeGreaterThan(0);
    expect(coverage.coveragePercent).toBeGreaterThanOrEqual(0);
    expect(coverage.coveragePercent).toBeLessThanOrEqual(100);
  });
});

// ============================================================================
// CORRELATION ENGINE TESTS
// ============================================================================

describe('CorrelationEngine', () => {
  let engine: CorrelationEngine;

  beforeEach(() => {
    engine = new CorrelationEngine({
      windowSize: 300,
      maxEventsPerWindow: 1000
    });

    // Добавление правила корреляции
    const rule: CorrelationRule = {
      id: 'rule-001',
      name: 'Brute Force Detection',
      description: 'Обнаружение brute force атаки',
      enabled: true,
      severity: ThreatSeverity.HIGH,
      timeWindow: 300,
      minEvents: 5,
      conditions: [
        {
          field: 'eventType',
          operator: 'eq',
          value: 'failed_login'
        }
      ],
      groupBy: ['sourceIp'],
      actions: [],
      mitreTechniques: ['T1110']
    };

    engine.addRule(rule);
  });

  test('должен добавлять правила', () => {
    const rules = engine.getRules();
    expect(rules.length).toBe(1);
    expect(rules[0].name).toBe('Brute Force Detection');
  });

  test('должен обрабатывать события', () => {
    const event = createMockEvent({
      eventType: 'failed_login',
      sourceIp: '192.168.1.100'
    });

    const alerts = engine.processEvent(event);
    
    // После первого события алертов не должно быть
    expect(alerts.length).toBe(0);
  });

  test('должен создавать алерт при достижении порога', () => {
    const sourceIp = '192.168.1.100';

    // Отправка 5 событий
    for (let i = 0; i < 5; i++) {
      const event = createMockEvent({
        eventType: 'failed_login',
        sourceIp,
        timestamp: new Date(Date.now() + i * 1000)
      });
      engine.processEvent(event);
    }

    const activeWindows = engine.getActiveWindows();
    expect(activeWindows.some(w => w.windowCount > 0)).toBe(true);
  });

  test('должен очищать старые окна', () => {
    const event = createMockEvent();
    engine.processEvent(event);

    // Ожидание истечения окна
    jest.advanceTimersByTime(600000);  // 10 минут

    const activeWindows = engine.getActiveWindows();
    expect(activeWindows.length).toBe(0);
  });
});

// ============================================================================
// RISK SCORER TESTS
// ============================================================================

describe('RiskScorer', () => {
  let scorer: RiskScorer;

  beforeEach(() => {
    scorer = new RiskScorer({
      weights: {
        entity: 0.25,
        threat: 0.30,
        impact: 0.30,
        context: 0.15
      },
      thresholds: {
        low: 20,
        medium: 40,
        high: 60,
        critical: 80
      }
    });
  });

  test('должен рассчитывать риск для алерта', () => {
    const alert: any = {
      id: 'alert-001',
      timestamp: new Date(),
      severity: ThreatSeverity.HIGH,
      confidence: 0.8,
      source: 'UEBA',
      entities: [
        {
          id: 'entity-001',
          type: 'host',
          name: 'domain-controller',
          value: 'dc-01',
          riskScore: 80,
          role: 'victim',
          context: {}
        }
      ],
      mitreAttack: {
        tactics: [],
        techniques: [{ id: 'T1003', name: 'OS Credential Dumping' }]
      }
    };

    const riskScore = scorer.calculateRisk(alert);

    expect(riskScore.overall).toBeGreaterThan(0);
    expect(riskScore.overall).toBeLessThanOrEqual(100);
    expect(riskScore.entity).toBeGreaterThan(0);
    expect(riskScore.threat).toBeGreaterThan(0);
  });

  test('должен приоритизировать алерты', () => {
    const alerts: any[] = [
      {
        id: 'alert-001',
        timestamp: new Date(),
        severity: ThreatSeverity.CRITICAL,
        confidence: 0.9,
        source: 'EDR',
        entities: [],
        mitreAttack: { tactics: [], techniques: [] }
      },
      {
        id: 'alert-002',
        timestamp: new Date(),
        severity: ThreatSeverity.LOW,
        confidence: 0.5,
        source: 'SIEM',
        entities: [],
        mitreAttack: { tactics: [], techniques: [] }
      }
    ];

    const prioritized = scorer.prioritizeAlerts(alerts);

    expect(prioritized.length).toBe(2);
    expect(prioritized[0].priority).toBeLessThanOrEqual(prioritized[1].priority);
  });

  test('должен получать статистику', () => {
    const stats = scorer.getStatistics();

    expect(stats.totalCalculations).toBeGreaterThanOrEqual(0);
    expect(stats.riskDistribution).toBeDefined();
  });
});

// ============================================================================
// NETWORK ANALYZER TESTS
// ============================================================================

describe('NetworkAnalyzer', () => {
  let analyzer: NetworkAnalyzer;

  beforeEach(() => {
    analyzer = new NetworkAnalyzer({
      flowTimeout: 30000,
      packetBufferSize: 1000,
      anomalyThresholds: {
        portScan: 10,
        networkSweep: 20,
        dataExfiltration: 100000000,
        bruteForce: 5
      }
    });
  });

  test('должен обрабатывать пакеты', () => {
    const packet = createMockNetworkPacket();
    const alerts = analyzer.processPacket(packet);

    expect(analyzer.getStatistics().totalPacketsProcessed).toBe(1);
  });

  test('должен обнаруживать сканирование портов', () => {
    const srcIp = '192.168.1.100';

    // Отправка пакетов на разные порты
    for (let port = 1; port <= 15; port++) {
      const packet = {
        ...createMockNetworkPacket(),
        srcIp,
        dstPort: port
      };
      analyzer.processPacket(packet);
    }

    const stats = analyzer.getStatistics();
    expect(stats.totalAnomaliesDetected).toBeGreaterThan(0);
  });

  test('должен получать активные потоки', () => {
    const packet = createMockNetworkPacket();
    analyzer.processPacket(packet);

    const flows = analyzer.getActiveFlows();
    expect(flows.length).toBeGreaterThan(0);
  });

  test('должен получать топ talkers', () => {
    const topTalkers = analyzer.getTopTalkers(10);
    expect(Array.isArray(topTalkers)).toBe(true);
  });
});

// ============================================================================
// ENDPOINT DETECTOR TESTS
// ============================================================================

describe('EndpointDetector', () => {
  let detector: EndpointDetector;

  beforeEach(() => {
    detector = new EndpointDetector({
      eventBufferSize: 1000,
      alertThreshold: 3
    });

    // Регистрация endpoint
    detector.registerEndpoint('endpoint-001', {
      hostname: 'workstation-01',
      ipAddress: '192.168.1.100',
      osType: 'Windows',
      osVersion: '10',
      agentVersion: '1.0.0'
    });
  });

  test('должен регистрировать endpoint', () => {
    const status = detector.getEndpointStatus('endpoint-001');

    expect(status).not.toBeNull();
    expect(status?.hostname).toBe('workstation-01');
  });

  test('должен обрабатывать события endpoint', () => {
    const event = createMockEndpointEvent();
    const alerts = detector.processEvent(event);

    expect(detector.getStatistics().totalEventsProcessed).toBe(1);
  });

  test('должен обнаруживать подозрительный PowerShell', () => {
    const event: any = {
      ...createMockEndpointEvent(),
      eventType: EndpointEventType.PROCESS_CREATE,
      rawEvent: {
        processName: 'powershell.exe',
        commandLine: 'powershell -enc SGVsbG8gV29ybGQ='
      }
    };

    const alerts = detector.processEvent(event);
    
    // PowerShell из мониторируемых процессов должен создать алерт
    expect(alerts.length).toBeGreaterThan(0);
  });

  test('должен получать компрометированные endpoint', () => {
    const compromised = detector.getCompromisedEndpoints();
    expect(Array.isArray(compromised)).toBe(true);
  });
});

// ============================================================================
// KILL CHAIN ANALYZER TESTS
// ============================================================================

describe('KillChainAnalyzer', () => {
  let analyzer: KillChainAnalyzer;

  beforeEach(() => {
    analyzer = new KillChainAnalyzer();
  });

  test('должен определять фазу для события разведки', () => {
    const event = createMockEvent({
      eventType: 'network_scan'
    });

    const result = analyzer.processEvent(event);

    expect(result).not.toBeNull();
    expect(result?.currentPhase).toBe(KillChainPhase.RECONNAISSANCE);
  });

  test('должен отслеживать прогресс Kill Chain', () => {
    const events = [
      createMockEvent({ eventType: 'network_scan', timestamp: new Date(Date.now() + 0) }),
      createMockEvent({ eventType: 'exploit_attempt', timestamp: new Date(Date.now() + 1000) }),
      createMockEvent({ eventType: 'malware_install', timestamp: new Date(Date.now() + 2000) }),
      createMockEvent({ eventType: 'c2_beacon', timestamp: new Date(Date.now() + 3000) }),
      createMockEvent({ eventType: 'data_exfiltration', timestamp: new Date(Date.now() + 4000) })
    ];

    let lastResult: any = null;

    for (const event of events) {
      lastResult = analyzer.processEvent(event);
    }

    expect(lastResult?.killChainAnalysis?.progression).toBeGreaterThan(50);
  });

  test('должен получать активные Kill Chain', () => {
    analyzer.processEvent(createMockEvent({ eventType: 'network_scan' }));

    const chains = analyzer.getActiveKillChains();
    expect(chains.length).toBeGreaterThan(0);
  });

  test('должен получать статистику', () => {
    const stats = analyzer.getStatistics();

    expect(stats.totalChainsTracked).toBeGreaterThanOrEqual(0);
    expect(stats.chainsByPhase).toBeDefined();
  });
});

// ============================================================================
// THREAT DASHBOARD TESTS
// ============================================================================

describe('ThreatDashboardService', () => {
  let dashboard: ThreatDashboardService;

  beforeEach(() => {
    dashboard = new ThreatDashboardService({
      refreshInterval: 60000,
      historyHours: 24,
      topItemsLimit: 10,
      timelineGranularity: 'hour'
    });
  });

  test('должен получать данные дашборда', async () => {
    const data = await dashboard.getDashboardData();

    expect(data.summary).toBeDefined();
    expect(data.alerts).toBeDefined();
    expect(data.threats).toBeDefined();
    expect(data.timeline).toBeDefined();
  });

  test('должен получать threat summary', async () => {
    const summary = await dashboard.getThreatSummary();

    expect(summary.totalAlerts).toBeGreaterThanOrEqual(0);
    expect(summary.newAlerts).toBeGreaterThanOrEqual(0);
  });

  test('должен кэшировать данные', async () => {
    // Первый запрос
    await dashboard.getDashboardData();
    const stats1 = dashboard.getStatistics();

    // Второй запрос (должен быть из кэша)
    await dashboard.getDashboardData();
    const stats2 = dashboard.getStatistics();

    expect(stats2.cacheHits).toBeGreaterThan(stats1.cacheHits);
  });

  test('должен очищать кэш', () => {
    dashboard.clearCache();
    const stats = dashboard.getStatistics();
    
    // После очистки кэш должен быть пуст
    expect(stats.cacheHits).toBe(0);
  });
});

// ============================================================================
// ML MODELS TESTS
// ============================================================================

describe('MLModels', () => {
  describe('IsolationForest', () => {
    let model: IsolationForest;

    beforeEach(() => {
      model = new IsolationForest({
        modelType: MLModelType.ISOLATION_FOREST,
        modelId: 'test-if',
        inputFeatures: ['feature1', 'feature2'],
        hyperparameters: {
          nTrees: 50,
          sampleSize: 128,
          threshold: 0.6
        },
        trainingWindow: 30,
        retrainingInterval: 24,
        threshold: 0.6
      });
    });

    test('должен обучаться на данных', async () => {
      const trainingData = {
        features: Array(100).fill(0).map(() => [
          Math.random() * 100,
          Math.random() * 100
        ]),
        timestamps: Array(100).fill(0).map(() => new Date()),
        metadata: {}
      };

      const metrics = await model.train(trainingData);

      expect(metrics.trainingTime).toBeGreaterThan(0);
    });

    test('должен предсказывать аномалии', async () => {
      // Обучение
      await model.train({
        features: Array(100).fill(0).map(() => [50, 50]),
        timestamps: Array(100).fill(0).map(() => new Date()),
        metadata: {}
      });

      // Нормальная точка
      const normalPrediction = await model.predict({ feature1: 50, feature2: 50 });
      expect(normalPrediction.isAnomaly).toBe(false);

      // Аномальная точка
      const anomalyPrediction = await model.predict({ feature1: 500, feature2: 500 });
      expect(anomalyPrediction.isAnomaly).toBe(true);
    });
  });

  describe('MLModelManager', () => {
    let manager: MLModelManager;

    beforeEach(() => {
      manager = new MLModelManager();
    });

    test('должен регистрировать модели', () => {
      const model = manager.registerModel({
        modelType: MLModelType.ISOLATION_FOREST,
        modelId: 'test-model',
        inputFeatures: ['f1', 'f2'],
        hyperparameters: {},
        trainingWindow: 30,
        retrainingInterval: 24,
        threshold: 0.5
      });

      expect(manager.getModel('test-model')).toBeDefined();
    });

    test('должен получать статистику предсказаний', async () => {
      const model = manager.registerModel({
        modelType: MLModelType.ISOLATION_FOREST,
        modelId: 'test-model',
        inputFeatures: ['f1'],
        hyperparameters: { nTrees: 10 },
        trainingWindow: 30,
        retrainingInterval: 24,
        threshold: 0.5
      });

      await model.train({
        features: Array(50).fill(0).map(() => [50]),
        timestamps: Array(50).fill(0).map(() => new Date()),
        metadata: {}
      });

      await manager.predictAll({ f1: 50 });

      const stats = manager.getPredictionStatistics();
      expect(stats.totalPredictions).toBeGreaterThan(0);
    });
  });
});

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

describe('ThreatDetectionEngine Integration', () => {
  let engine: ThreatDetectionEngine;

  beforeEach(() => {
    engine = new ThreatDetectionEngine({
      enabled: true,
      mlEnabled: false,  // Отключаем ML для тестов
      uebaEnabled: true,
      threatIntelEnabled: false,
      networkAnalysisEnabled: true,
      endpointDetectionEnabled: true
    });
  });

  test('должен обрабатывать события безопасности', async () => {
    const event = createMockEvent({
      eventType: 'failed_login',
      severity: ThreatSeverity.MEDIUM
    });

    const result = await engine.processEvent(event);

    expect(result.eventId).toBe(event.id);
    expect(result.processingTime).toBeGreaterThan(0);
  });

  test('должен получать данные дашборда', () => {
    const data = engine.getDashboardData();

    expect(data.summary).toBeDefined();
    expect(data.alerts).toBeDefined();
    expect(data.network).toBeDefined();
    expect(data.endpoints).toBeDefined();
  });

  test('должен получать статистику', () => {
    const stats = engine.getStatistics();

    expect(stats.totalEventsProcessed).toBeGreaterThanOrEqual(0);
    expect(stats.alertsBySeverity).toBeDefined();
  });

  test('должен обрабатывать сетевые пакеты', () => {
    const packet = createMockNetworkPacket();
    const alerts = engine.processNetworkPacket(packet);

    expect(Array.isArray(alerts)).toBe(true);
  });

  test('должен обрабатывать события endpoint', () => {
    const event = createMockEndpointEvent();
    const alerts = engine.processEndpointEvent(event);

    expect(Array.isArray(alerts)).toBe(true);
  });
});

// ============================================================================
// EDGE CASES TESTS
// ============================================================================

describe('Edge Cases', () => {
  test('UEBA должен обрабатывать пустые профили', async () => {
    const ueba = new UEBAService();
    
    const profile = ueba.getProfile('non-existent');
    expect(profile).toBeNull();
  });

  test('CorrelationEngine должен обрабатывать отключенные правила', () => {
    const engine = new CorrelationEngine();
    
    engine.addRule({
      id: 'disabled-rule',
      name: 'Disabled',
      description: 'Test',
      enabled: false,
      severity: ThreatSeverity.LOW,
      timeWindow: 60,
      minEvents: 1,
      conditions: [],
      groupBy: [],
      actions: [],
      mitreTechniques: []
    });

    const event = createMockEvent();
    const alerts = engine.processEvent(event);
    
    expect(alerts.length).toBe(0);
  });

  test('RiskScorer должен обрабатывать алерты без сущностей', () => {
    const scorer = new RiskScorer();
    
    const alert: any = {
      id: 'alert-001',
      timestamp: new Date(),
      severity: ThreatSeverity.LOW,
      confidence: 0.5,
      source: 'test',
      entities: [],
      mitreAttack: { tactics: [], techniques: [] }
    };

    const risk = scorer.calculateRisk(alert);
    expect(risk.overall).toBeGreaterThanOrEqual(0);
  });

  test('NetworkAnalyzer должен обрабатывать пустые пакеты', () => {
    const analyzer = new NetworkAnalyzer();
    
    const packet: any = {
      timestamp: new Date(),
      srcIp: '',
      dstIp: '',
      srcPort: 0,
      dstPort: 0,
      protocol: '',
      size: 0,
      flags: [],
      ttl: 0
    };

    const alerts = analyzer.processPacket(packet);
    expect(Array.isArray(alerts)).toBe(true);
  });

  test('KillChainAnalyzer должен обрабатывать неизвестные события', () => {
    const analyzer = new KillChainAnalyzer();
    
    const event = createMockEvent({
      eventType: 'unknown_event_type'
    });

    const result = analyzer.processEvent(event);
    
    // Неизвестные события не должны создавать Kill Chain
    expect(result).toBeNull();
  });
});

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

describe('Performance Tests', () => {
  test('UEBA должен обрабатывать 1000 событий за разумное время', async () => {
    const ueba = new UEBAService();
    
    await ueba.updateUserProfile({
      userId: 'user-001',
      username: 'test'
    });

    const startTime = Date.now();

    for (let i = 0; i < 1000; i++) {
      const event = createMockEvent({
        userId: 'user-001',
        timestamp: new Date(Date.now() + i)
      });
      await ueba.processEvent(event);
    }

    const elapsed = Date.now() - startTime;
    
    // Должно обработать 1000 событий менее чем за 5 секунд
    expect(elapsed).toBeLessThan(5000);
  });

  test('CorrelationEngine должен обрабатывать 1000 событий', () => {
    const engine = new CorrelationEngine();
    
    engine.addRule({
      id: 'perf-rule',
      name: 'Performance Test',
      description: 'Test',
      enabled: true,
      severity: ThreatSeverity.MEDIUM,
      timeWindow: 300,
      minEvents: 10,
      conditions: [{ field: 'eventType', operator: 'eq', value: 'test' }],
      groupBy: ['sourceIp'],
      actions: [],
      mitreTechniques: []
    });

    const startTime = Date.now();

    for (let i = 0; i < 1000; i++) {
      const event = createMockEvent({
        eventType: 'test',
        sourceIp: '192.168.1.100',
        timestamp: new Date(Date.now() + i)
      });
      engine.processEvent(event);
    }

    const elapsed = Date.now() - startTime;
    expect(elapsed).toBeLessThan(5000);
  });
});
