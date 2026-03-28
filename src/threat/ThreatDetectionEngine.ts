/**
 * ============================================================================
 * THREAT DETECTION ENGINE
 * Основной движок системы обнаружения угроз
 * Объединяет все компоненты: ML, UEBA, MITRE, Threat Intel, Correlation, Risk
 * ============================================================================
 */

import { UEBAService } from './UEBAService';
import { MITREAttackMapper } from './MITREAttackMapper';
import { ThreatIntelligenceService } from './ThreatIntelligence';
import { CorrelationEngine } from './CorrelationEngine';
import { RiskScorer } from './RiskScorer';
import { NetworkAnalyzer } from './NetworkAnalyzer';
import { EndpointDetector } from './EndpointDetector';
import { MLModelManager, IsolationForest, LSTMModel, AutoencoderModel } from './MLModels';

import {
  SecurityEvent,
  SecurityAlert,
  PrioritizedAlert,
  ThreatDetectionConfig,
  ThreatSeverity,
  ThreatStatus,
  ThreatCategory,
  AttackType,
  EntityType,
  MitreAttackInfo,
  ThreatDashboardData,
  ThreatSummary,
  AlertMetrics,
  ThreatMetrics,
  NetworkMetrics,
  EndpointMetrics,
  UserMetrics,
  TimelineData,
  TopThreat,
  MitreHeatmapData,
  RiskTrendData,
  MLModelConfig,
  MLModelType,
  TrainingData,
  MLPrediction,
  UserProfile,
  HostProfile,
  NetworkPacket,
  NetworkFlow,
  EndpointEvent,
  StixIndicator,
  ThreatFeed,
  DetectionRule,
  CorrelationRule,
  ResponsePlaybook,
  KillChainAnalysis
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Контекст безопасности для обработки событий
 */
interface SecurityContext {
  userId?: string;
  sessionId?: string;
  source?: string;
  tags?: string[];
}

/**
 * Результат обработки события
 */
interface EventProcessingResult {
  eventId: string;
  alerts: PrioritizedAlert[];
  mlPredictions: Map<string, MLPrediction>;
  threatIntelMatches: StixIndicator[];
  mitreMappings: MitreAttackInfo;
  killChainAnalysis?: KillChainAnalysis;
  processingTime: number;
}

/**
 * ============================================================================
 * THREAT DETECTION ENGINE CLASS
 * ============================================================================
 */
export class ThreatDetectionEngine {
  // Основные компоненты
  private uebaService: UEBAService;
  private mitreMapper: MITREAttackMapper;
  private threatIntel: ThreatIntelligenceService;
  private correlationEngine: CorrelationEngine;
  private riskScorer: RiskScorer;
  private networkAnalyzer: NetworkAnalyzer;
  private endpointDetector: EndpointDetector;
  private mlModelManager: MLModelManager;
  
  // Конфигурация
  private config: ThreatDetectionConfig;
  
  // Хранилище алертов
  private alerts: Map<string, PrioritizedAlert> = new Map();
  private alertHistory: PrioritizedAlert[] = [];
  private maxAlertHistory: number = 10000;
  
  // Обработанные события
  private processedEvents: Map<string, EventProcessingResult> = new Map();
  private maxEventHistory: number = 50000;
  
  // Статистика
  private statistics: ThreatDetectionStatistics = {
    totalEventsProcessed: 0,
    totalAlertsGenerated: 0,
    alertsBySeverity: new Map(),
    alertsByCategory: new Map(),
    meanTimeToDetect: 0,
    falsePositiveRate: 0,
    lastUpdated: new Date()
  };

  constructor(config?: Partial<ThreatDetectionConfig>) {
    // Конфигурация по умолчанию
    this.config = {
      enabled: config?.enabled ?? true,
      mlEnabled: config?.mlEnabled ?? true,
      uebaEnabled: config?.uebaEnabled ?? true,
      threatIntelEnabled: config?.threatIntelEnabled ?? true,
      networkAnalysisEnabled: config?.networkAnalysisEnabled ?? true,
      endpointDetectionEnabled: config?.endpointDetectionEnabled ?? true,
      ml: config?.ml || {
        modelsDirectory: './models',
        trainingDataRetention: 30,
        retrainingSchedule: '0 0 * * *',
        anomalyThreshold: 0.6,
        minTrainingSamples: 1000,
        featureEngineering: {
          enabled: true,
          features: [],
          normalization: 'zscore',
          dimensionalityReduction: 'none'
        }
      },
      ueba: config?.ueba || {
        baselineWindow: 30,
        anomalyWindow: 24,
        minEventsForBaseline: 100,
        behaviorMetrics: [],
        riskThresholds: {
          low: 20,
          medium: 40,
          high: 60,
          critical: 80
        }
      },
      threatIntel: config?.threatIntel || {
        feeds: [],
        updateInterval: 15,
        indicatorExpiration: 30,
        minConfidence: 50,
        taxiiServers: []
      },
      correlation: config?.correlation || {
        enabled: true,
        windowSize: 300,
        maxEventsPerWindow: 1000,
        rules: []
      },
      riskScoring: config?.riskScoring || {
        enabled: true,
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
        },
        adjustments: []
      },
      automatedResponse: config?.automatedResponse || {
        enabled: true,
        requireApprovalFor: [ThreatSeverity.CRITICAL],
        playbooksDirectory: './playbooks',
        maxConcurrentPlaybooks: 10,
        defaultTimeout: 300
      },
      storage: config?.storage || {
        type: 'elasticsearch',
        connectionStrings: {},
        retention: {
          events: 90,
          alerts: 365,
          metrics: 30
        },
        indexes: []
      },
      notifications: config?.notifications || []
    };
    
    // Инициализация компонентов
    this.uebaService = new UEBAService(this.config.ueba);
    this.mitreMapper = new MITREAttackMapper();
    this.threatIntel = new ThreatIntelligenceService();
    this.correlationEngine = new CorrelationEngine({
      windowSize: this.config.correlation.windowSize,
      maxEventsPerWindow: this.config.correlation.maxEventsPerWindow
    });
    this.riskScorer = new RiskScorer({
      weights: this.config.riskScoring.weights,
      thresholds: this.config.riskScoring.thresholds,
      adjustments: this.config.riskScoring.adjustments
    });
    this.networkAnalyzer = new NetworkAnalyzer();
    this.endpointDetector = new EndpointDetector();
    this.mlModelManager = new MLModelManager();
    
    // Инициализация ML моделей
    if (this.config.mlEnabled) {
      this.initializeMLModels();
    }
    
    // Инициализация правил корреляции
    if (this.config.correlation.enabled) {
      this.initializeCorrelationRules();
    }
    
    console.log('[ThreatDetectionEngine] Инициализация завершена');
    console.log(`[ThreatDetectionEngine] ML: ${this.config.mlEnabled}, UEBA: ${this.config.uebaEnabled}, ThreatIntel: ${this.config.threatIntelEnabled}`);
  }

  // ============================================================================
  // ИНИЦИАЛИЗАЦИЯ
  // ============================================================================

  /**
   * Инициализация ML моделей
   */
  private initializeMLModels(): void {
    // Isolation Forest для обнаружения аномалий
    const ifConfig: MLModelConfig = {
      modelType: MLModelType.ISOLATION_FOREST,
      modelId: 'isolation-forest-001',
      inputFeatures: ['loginFrequency', 'accessVolume', 'failedLogins', 'privilegeUsage'],
      hyperparameters: {
        nTrees: 100,
        sampleSize: 256,
        threshold: this.config.ml.anomalyThreshold
      },
      trainingWindow: 30,
      retrainingInterval: 24,
      threshold: this.config.ml.anomalyThreshold
    };
    
    this.mlModelManager.registerModel(ifConfig);
    
    // Autoencoder для снижения размерности
    const aeConfig: MLModelConfig = {
      modelType: MLModelType.AUTOENCODER,
      modelId: 'autoencoder-001',
      inputFeatures: ['cpuUsage', 'memoryUsage', 'networkTraffic', 'diskIO'],
      hyperparameters: {
        encodingDim: 16,
        dropoutRate: 0.2,
        learningRate: 0.001,
        epochs: 100,
        batchSize: 32,
        reconstructionThreshold: 0.1
      },
      trainingWindow: 30,
      retrainingInterval: 24,
      threshold: 0.5
    };
    
    this.mlModelManager.registerModel(aeConfig);
    
    console.log('[ThreatDetectionEngine] ML модели инициализированы');
  }

  /**
   * Инициализация правил корреляции
   */
  private initializeCorrelationRules(): void {
    // Правило: Brute Force -> Successful Login
    this.correlationEngine.addRule({
      id: 'CORR-001',
      name: 'Brute Force с последующим успешным входом',
      description: 'Обнаружение успешного входа после множественных неудачных попыток',
      enabled: true,
      severity: ThreatSeverity.HIGH,
      timeWindow: 300,  // 5 минут
      minEvents: 5,
      conditions: [
        { field: 'eventType', operator: 'in', value: ['failed_login', 'successful_login'] },
        { field: 'severity', operator: 'gte', value: ThreatSeverity.MEDIUM }
      ],
      groupBy: ['userId', 'sourceIp'],
      actions: [],
      mitreTechniques: ['T1110']
    });
    
    // Правило: Reconnaissance -> Exploitation
    this.correlationEngine.addRule({
      id: 'CORR-002',
      name: 'Разведка с последующей эксплуатацией',
      description: 'Обнаружение атаки после фазы разведки',
      enabled: true,
      severity: ThreatSeverity.CRITICAL,
      timeWindow: 600,  // 10 минут
      minEvents: 3,
      conditions: [
        { field: 'category', operator: 'in', value: [ThreatCategory.DISCOVERY, ThreatCategory.EXPLOITATION] }
      ],
      groupBy: ['sourceIp', 'destinationIp'],
      actions: [],
      mitreTechniques: ['T1046', 'T1190']
    });
    
    // Правило: Lateral Movement
    this.correlationEngine.addRule({
      id: 'CORR-003',
      name: 'Перемещение внутри сети',
      description: 'Обнаружение перемещения между системами',
      enabled: true,
      severity: ThreatSeverity.HIGH,
      timeWindow: 300,
      minEvents: 3,
      conditions: [
        { field: 'eventType', operator: 'contains', value: 'remote' }
      ],
      groupBy: ['userId'],
      actions: [],
      mitreTechniques: ['T1021']
    });
    
    console.log('[ThreatDetectionEngine] Правила корреляции инициализированы');
  }

  // ============================================================================
  // ОБРАБОТКА СОБЫТИЙ
  // ============================================================================

  /**
   * Обработка события безопасности
   */
  async processEvent(event: SecurityEvent, context?: SecurityContext): Promise<EventProcessingResult> {
    const startTime = Date.now();
    
    // Генерация ID события если отсутствует
    if (!event.id) {
      event.id = uuidv4();
    }
    
    // Добавление контекста
    if (context) {
      event.rawEvent = { ...event.rawEvent, ...context };
    }
    
    this.statistics.totalEventsProcessed++;
    
    // 1. ML предсказания
    const mlPredictions = await this.runMLAnalysis(event);
    
    // 2. UEBA анализ
    const uebaAlerts = await this.runUEBAAnalysis(event);
    
    // 3. Threat Intelligence matching
    const threatIntelMatches = await this.runThreatIntelMatching(event);
    
    // 4. MITRE ATT&CK маппинг
    const mitreMappings = this.mitreMapper.mapEventToMitre(event);
    
    // 5. Корреляция событий
    const correlationAlerts = this.correlationEngine.processEvent(event);
    
    // 6. Создание объединенного алерта
    const alerts = await this.createAlerts(event, {
      mlPredictions,
      uebaAlerts,
      threatIntelMatches,
      mitreMappings,
      correlationAlerts
    });
    
    // 7. Приоритизация алертов
    const prioritizedAlerts = this.riskScorer.prioritizeAlerts(alerts);
    
    // 8. Сохранение результатов
    for (const alert of prioritizedAlerts) {
      this.alerts.set(alert.id, alert);
      this.alertHistory.push(alert);
      
      if (this.alertHistory.length > this.maxAlertHistory) {
        this.alertHistory.shift();
      }
      
      this.statistics.totalAlertsGenerated++;
      this.updateAlertStatistics(alert);
    }
    
    // 9. Сохранение в историю событий
    const result: EventProcessingResult = {
      eventId: event.id,
      alerts: prioritizedAlerts,
      mlPredictions,
      threatIntelMatches,
      mitreMappings: this.buildMitreAttackInfo(mitreMappings),
      killChainAnalysis: this.mitreMapper['determineKillChainPhase']?.(mitreMappings.map(m => this.mitreMapper.getTactic(m.tacticId)).filter(Boolean)),
      processingTime: Date.now() - startTime
    };
    
    this.processedEvents.set(event.id, result);
    
    if (this.processedEvents.size > this.maxEventHistory) {
      const firstKey = this.processedEvents.keys().next().value;
      if (firstKey) {
        this.processedEvents.delete(firstKey);
      }
    }
    
    // 10. Обновление статистики времени обнаружения
    this.updateDetectionTime(result.processingTime);
    
    return result;
  }

  /**
   * Пакетная обработка событий
   */
  async processEvents(events: SecurityEvent[], context?: SecurityContext): Promise<EventProcessingResult[]> {
    const results: EventProcessingResult[] = [];
    
    for (const event of events) {
      const result = await this.processEvent(event, context);
      results.push(result);
    }
    
    return results;
  }

  // ============================================================================
  // АНАЛИЗ КОМПОНЕНТАМИ
  // ============================================================================

  /**
   * ML анализ события
   */
  private async runMLAnalysis(event: SecurityEvent): Promise<Map<string, MLPrediction>> {
    if (!this.config.mlEnabled) {
      return new Map();
    }
    
    try {
      // Извлечение признаков из события
      const features = this.extractMLFeatures(event);
      
      // Предсказание всеми моделями
      const predictions = await this.mlModelManager.ensemblePredict(features);
      
      return new Map([['ensemble', predictions]]);
    } catch (error) {
      console.error('[ThreatDetectionEngine] Ошибка ML анализа:', error);
      return new Map();
    }
  }

  /**
   * Извлечение ML признаков из события
   */
  private extractMLFeatures(event: SecurityEvent): Record<string, number> {
    const features: Record<string, number> = {
      loginFrequency: 0,
      accessVolume: 0,
      failedLogins: 0,
      privilegeUsage: 0,
      cpuUsage: 0,
      memoryUsage: 0,
      networkTraffic: 0,
      diskIO: 0
    };
    
    // Извлечение из rawEvent
    const raw = event.rawEvent;
    
    if (raw.loginFrequency) features.loginFrequency = Number(raw.loginFrequency);
    if (raw.accessVolume) features.accessVolume = Number(raw.accessVolume);
    if (raw.failedLogins) features.failedLogins = Number(raw.failedLogins);
    if (raw.privilegeUsage) features.privilegeUsage = Number(raw.privilegeUsage);
    if (raw.cpuUsage) features.cpuUsage = Number(raw.cpuUsage);
    if (raw.memoryUsage) features.memoryUsage = Number(raw.memoryUsage);
    if (raw.networkTraffic) features.networkTraffic = Number(raw.networkTraffic);
    if (raw.diskIO) features.diskIO = Number(raw.diskIO);
    
    return features;
  }

  /**
   * UEBA анализ события
   */
  private async runUEBAAnalysis(event: SecurityEvent): Promise<SecurityAlert[]> {
    if (!this.config.uebaEnabled) {
      return [];
    }

    try {
      return await this.uebaService.processEvent(event);
    } catch (error) {
      console.error('[ThreatDetectionEngine] Ошибка UEBA анализа:', error);
      return [];
    }
  }

  /**
   * Threat Intelligence matching
   */
  private async runThreatIntelMatching(event: SecurityEvent): Promise<StixIndicator[]> {
    if (!this.config.threatIntelEnabled) {
      return [];
    }
    
    try {
      // В реальной реализации здесь был бы вызов threatIntel.matchEventToThreatIntel
      return [];
    } catch (error) {
      console.error('[ThreatDetectionEngine] Ошибка Threat Intel matching:', error);
      return [];
    }
  }

  // ============================================================================
  // СОЗДАНИЕ АЛЕРТОВ
  // ============================================================================

  /**
   * Создание алертов из результатов анализа
   */
  private async createAlerts(
    event: SecurityEvent,
    analysis: {
      mlPredictions: Map<string, MLPrediction>;
      uebaAlerts: SecurityAlert[];
      threatIntelMatches: StixIndicator[];
      mitreMappings: any[];
      correlationAlerts: SecurityAlert[];
    }
  ): Promise<SecurityAlert[]> {
    const alerts: SecurityAlert[] = [];
    
    // Добавление UEBA алертов
    alerts.push(...analysis.uebaAlerts);
    
    // Добавление корреляционных алертов
    alerts.push(...analysis.correlationAlerts);
    
    // Создание алерта на основе ML предсказаний
    for (const [modelId, prediction] of analysis.mlPredictions.entries()) {
      if (prediction.isAnomaly && prediction.anomalyScore && prediction.anomalyScore > 0.6) {
        alerts.push(this.createMLAlert(event, prediction));
      }
    }
    
    // Создание алерта на основе Threat Intel
    if (analysis.threatIntelMatches.length > 0) {
      alerts.push(this.createThreatIntelAlert(event, analysis.threatIntelMatches));
    }
    
    return alerts;
  }

  /**
   * Создание ML алерта
   */
  private createMLAlert(event: SecurityEvent, prediction: MLPrediction): SecurityAlert {
    return {
      id: uuidv4(),
      timestamp: new Date(),
      title: `ML Anomaly Detection: ${prediction.modelId}`,
      description: `Обнаружена аномалия с score ${prediction.anomalyScore?.toFixed(3)}`,
      severity: this.mlScoreToSeverity(prediction.anomalyScore || 0),
      status: ThreatStatus.NEW,
      category: ThreatCategory.ANOMALY,
      attackType: AttackType.ANOMALY,
      source: 'ML',
      events: [event],
      entities: [],
      mitreAttack: { tactics: [], techniques: [] },
      riskScore: (prediction.anomalyScore || 0) * 100,
      confidence: prediction.confidence,
      falsePositiveProbability: 1 - prediction.confidence,
      investigationStatus: {
        stage: 'triage',
        progress: 0,
        findings: [],
        evidenceCollected: []
      },
      tags: ['ml', 'anomaly'],
      timeline: [],
      evidence: [],
      response: {
        automatedActions: [],
        manualActions: [],
        playbooksExecuted: [],
        containmentStatus: 'not_started',
        eradicationStatus: 'not_started',
        recoveryStatus: 'not_started'
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };
  }

  /**
   * Создание Threat Intel алерта
   */
  private createThreatIntelAlert(event: SecurityEvent, matches: StixIndicator[]): SecurityAlert {
    const maxConfidence = Math.max(...matches.map(m => m.confidence));

    return {
      id: uuidv4(),
      timestamp: new Date(),
      title: `Threat Intelligence Match: ${matches.length} индикаторов`,
      description: `Обнаружено совпадение с threat intelligence индикаторами`,
      severity: this.confidenceToSeverity(maxConfidence),
      status: ThreatStatus.NEW,
      category: ThreatCategory.UNKNOWN,
      attackType: AttackType.UNKNOWN,
      source: 'ThreatIntelligence',
      events: [event],
      entities: [],
      mitreAttack: { tactics: [], techniques: [] },
      riskScore: maxConfidence,
      confidence: maxConfidence / 100,
      falsePositiveProbability: 1 - maxConfidence / 100,
      investigationStatus: {
        stage: 'triage',
        progress: 0,
        findings: [],
        evidenceCollected: []
      },
      tags: ['threat-intel', 'stix'],
      timeline: [],
      evidence: [],
      response: {
        automatedActions: [],
        manualActions: [],
        playbooksExecuted: [],
        containmentStatus: 'not_started',
        eradicationStatus: 'not_started',
        recoveryStatus: 'not_started'
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };
  }

  /**
   * Конвертация ML score в серьезность
   */
  private mlScoreToSeverity(score: number): ThreatSeverity {
    if (score >= 0.9) return ThreatSeverity.CRITICAL;
    if (score >= 0.7) return ThreatSeverity.HIGH;
    if (score >= 0.5) return ThreatSeverity.MEDIUM;
    if (score >= 0.3) return ThreatSeverity.LOW;
    return ThreatSeverity.INFO;
  }

  /**
   * Конвертация confidence в серьезность
   */
  private confidenceToSeverity(confidence: number): ThreatSeverity {
    if (confidence >= 90) return ThreatSeverity.CRITICAL;
    if (confidence >= 70) return ThreatSeverity.HIGH;
    if (confidence >= 50) return ThreatSeverity.MEDIUM;
    if (confidence >= 30) return ThreatSeverity.LOW;
    return ThreatSeverity.INFO;
  }

  /**
   * Построение MitreAttackInfo
   */
  private buildMitreAttackInfo(mappings: any[]): MitreAttackInfo {
    const tactics = mappings.map(m => this.mitreMapper.getTactic(m.tacticId)).filter(Boolean);
    const techniques = mappings.map(m => this.mitreMapper.getTechnique(m.techniqueId)).filter(Boolean);
    
    return {
      tactics: tactics as any[],
      techniques: techniques as any[],
      killChainPhase: undefined,
      threatGroups: []
    };
  }

  // ============================================================================
  // ОБРАБОТКА СЕТЕВЫХ СОБЫТИЙ
  // ============================================================================

  /**
   * Обработка сетевого пакета
   */
  processNetworkPacket(packet: NetworkPacket): SecurityAlert[] {
    if (!this.config.networkAnalysisEnabled) {
      return [];
    }
    
    return this.networkAnalyzer.processPacket(packet);
  }

  /**
   * Обработка сетевого потока
   */
  processNetworkFlow(flow: NetworkFlow): SecurityAlert[] {
    if (!this.config.networkAnalysisEnabled) {
      return [];
    }
    
    // Конвертация потока в событие
    const event: SecurityEvent = {
      id: uuidv4(),
      timestamp: flow.startTime,
      eventType: 'network_flow',
      source: 'NetworkAnalyzer',
      sourceIp: flow.srcIp,
      destinationIp: flow.dstIp,
      sourcePort: flow.srcPort,
      destinationPort: flow.dstPort,
      protocol: flow.protocol,
      severity: ThreatSeverity.INFO,
      category: ThreatCategory.NETWORK,
      rawEvent: {
        packetsCount: flow.packetsCount,
        bytesSent: flow.bytesSent,
        bytesReceived: flow.bytesReceived,
        duration: flow.duration
      },
      normalizedEvent: {}
    };
    
    return [event];
  }

  // ============================================================================
  // ОБРАБОТКА ENDPOINT СОБЫТИЙ
  // ============================================================================

  /**
   * Обработка события endpoint
   */
  processEndpointEvent(event: EndpointEvent): SecurityAlert[] {
    if (!this.config.endpointDetectionEnabled) {
      return [];
    }
    
    return this.endpointDetector.processEvent(event);
  }

  // ============================================================================
  // УПРАВЛЕНИЕ ML МОДЕЛЯМИ
  // ============================================================================

  /**
   * Обучение ML моделей
   */
  async trainMLModels(trainingData: Map<string, TrainingData>): Promise<void> {
    if (!this.config.mlEnabled) {
      console.warn('[ThreatDetectionEngine] ML отключен, обучение пропущено');
      return;
    }
    
    console.log('[ThreatDetectionEngine] Начало обучения ML моделей');
    
    const results = await this.mlModelManager.trainAllModels(trainingData);
    
    for (const [modelId, metrics] of results.entries()) {
      console.log(`[ThreatDetectionEngine] Модель ${modelId} обучена за ${metrics.trainingTime}мс`);
    }
  }

  /**
   * Сохранение ML моделей
   */
  async saveMLModels(): Promise<void> {
    await this.mlModelManager.saveAllModels(this.config.ml.modelsDirectory);
  }

  /**
   * Загрузка ML моделей
   */
  async loadMLModels(): Promise<void> {
    // В реальной реализации здесь была бы загрузка конфигураций
    // await this.mlModelManager.loadAllModels(this.config.ml.modelsDirectory, configs);
  }

  // ============================================================================
  // THREAT INTELLIGENCE
  // ============================================================================

  /**
   * Добавление threat feed
   */
  addThreatFeed(feed: ThreatFeed): void {
    this.threatIntel.addFeed(feed);
  }

  /**
   * Синхронизация threat intelligence
   */
  async syncThreatIntelligence(): Promise<void> {
    if (!this.config.threatIntelEnabled) {
      return;
    }
    
    await this.threatIntel.syncAllFeeds();
  }

  // ============================================================================
  // СТАТИСТИКА И ДАШБОРД
  // ============================================================================

  /**
   * Получение статистики
   */
  getStatistics(): ThreatDetectionStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }

  /**
   * Получение данных для дашборда
   */
  getDashboardData(): ThreatDashboardData {
    const alerts = Array.from(this.alerts.values());
    
    // Summary
    const summary: ThreatSummary = {
      totalAlerts: alerts.length,
      newAlerts: alerts.filter(a => a.status === 'new').length,
      criticalAlerts: alerts.filter(a => a.severity === ThreatSeverity.CRITICAL).length,
      highAlerts: alerts.filter(a => a.severity === ThreatSeverity.HIGH).length,
      activeThreats: alerts.filter(a => a.status === 'investigating').length,
      containedThreats: alerts.filter(a => a.status === 'contained').length,
      falsePositives: alerts.filter(a => a.status === 'false_positive').length,
      meanTimeToDetect: this.statistics.meanTimeToDetect,
      meanTimeToRespond: 0  // В реальной реализации
    };
    
    // Alert Metrics
    const alertMetrics: AlertMetrics = {
      bySeverity: {
        [ThreatSeverity.CRITICAL]: summary.criticalAlerts,
        [ThreatSeverity.HIGH]: summary.highAlerts,
        [ThreatSeverity.MEDIUM]: alerts.filter(a => a.severity === ThreatSeverity.MEDIUM).length,
        [ThreatSeverity.LOW]: alerts.filter(a => a.severity === ThreatSeverity.LOW).length,
        [ThreatSeverity.INFO]: alerts.filter(a => a.severity === ThreatSeverity.INFO).length
      },
      byCategory: {},
      byStatus: {},
      byAttackType: {},
      trend: 0
    };
    
    // Заполнение метрик по категориям
    for (const alert of alerts) {
      alertMetrics.byCategory[alert.category] = (alertMetrics.byCategory[alert.category] || 0) + 1;
      alertMetrics.byStatus[alert.status] = (alertMetrics.byStatus[alert.status] || 0) + 1;
      alertMetrics.byAttackType[alert.attackType] = (alertMetrics.byAttackType[alert.attackType] || 0) + 1;
    }
    
    // Network Metrics
    const networkStats = this.networkAnalyzer.getStatistics();
    const networkMetrics: NetworkMetrics = {
      totalFlows: networkStats.totalFlowsCreated,
      suspiciousFlows: networkStats.totalAnomaliesDetected,
      blockedConnections: 0,
      topTalkers: this.networkAnalyzer.getTopTalkers(10),
      topDestinations: [],
      anomaliesDetected: networkStats.totalAnomaliesDetected
    };
    
    // Endpoint Metrics
    const endpointStats = this.endpointDetector.getStatistics();
    const endpointMetrics: EndpointMetrics = {
      totalEndpoints: endpointStats.endpointsMonitored,
      onlineEndpoints: endpointStats.endpointsMonitored,
      compromisedEndpoints: this.endpointDetector.getCompromisedEndpoints().length,
      isolatedEndpoints: 0,
      eventsByType: {},
      topAlertedEndpoints: []
    };
    
    // User Metrics
    const userProfiles = this.uebaService.getAllUserProfiles();
    const highRiskUsers = this.uebaService.getHighRiskEntities(60);
    const userMetrics: UserMetrics = {
      totalUsers: userProfiles.length,
      highRiskUsers: highRiskUsers.length,
      anomalousBehaviors: 0,
      failedLogins: 0,
      privilegeEscalations: 0,
      topRiskUsers: highRiskUsers.slice(0, 10).map(p => ({
        userId: p.userId,
        username: p.username,
        riskScore: p.riskScore,
        anomalyScore: 0,
        topRisks: []
      }))
    };
    
    // Timeline
    const timeline: TimelineData[] = this.generateTimelineData(alerts);
    
    // Top Threats
    const topThreats: TopThreat[] = this.generateTopThreats(alerts);
    
    // MITRE Heatmap
    const mitreHeatmap: MitreHeatmapData = this.generateMitreHeatmap(alerts);
    
    // Risk Trend
    const riskTrend: RiskTrendData[] = this.generateRiskTrend(alerts);
    
    return {
      summary,
      alerts: alertMetrics,
      threats: {
        activeAttacks: summary.activeThreats,
        blockedAttacks: 0,
        detectedTechniques: [],
        threatActors: [],
        killChainProgress: {}
      },
      network: networkMetrics,
      endpoints: endpointMetrics,
      users: userMetrics,
      timeline,
      topThreats,
      mitreHeatmap,
      riskTrend
    };
  }

  /**
   * Генерация timeline данных
   */
  private generateTimelineData(alerts: PrioritizedAlert[]): TimelineData[] {
    // Группировка по часам
    const hourlyData: Map<string, TimelineData> = new Map();
    
    for (const alert of alerts) {
      const hour = alert.timestamp.toISOString().slice(0, 13);
      
      if (!hourlyData.has(hour)) {
        hourlyData.set(hour, {
          timestamp: new Date(hour + ':00:00'),
          alerts: 0,
          events: 0,
          blocked: 0,
          critical: 0
        });
      }
      
      const data = hourlyData.get(hour)!;
      data.alerts++;
      
      if (alert.severity === ThreatSeverity.CRITICAL) {
        data.critical++;
      }
    }
    
    return Array.from(hourlyData.values()).sort((a, b) => 
      a.timestamp.getTime() - b.timestamp.getTime()
    ).slice(-24);
  }

  /**
   * Генерация топ угроз
   */
  private generateTopThreats(alerts: PrioritizedAlert[]): TopThreat[] {
    const threatCounts: Map<string, { count: number; severity: ThreatSeverity }> = new Map();
    
    for (const alert of alerts) {
      const key = alert.attackType || 'unknown';
      
      if (!threatCounts.has(key)) {
        threatCounts.set(key, { count: 0, severity: alert.severity });
      }
      
      const data = threatCounts.get(key)!;
      data.count++;
      
      if (alert.severity === ThreatSeverity.CRITICAL || alert.severity === ThreatSeverity.HIGH) {
        data.severity = alert.severity;
      }
    }
    
    return Array.from(threatCounts.entries())
      .map(([type, data]) => ({
        id: uuidv4(),
        name: type,
        type: type as AttackType,
        count: data.count,
        severity: data.severity,
        mitreTechniques: [],
        trend: 'stable' as const
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  /**
   * Генерация MITRE heatmap
   */
  private generateMitreHeatmap(alerts: PrioritizedAlert[]): MitreHeatmapData {
    // В реальной реализации здесь был бы анализ mitreAttack из алертов
    return {
      tactics: []
    };
  }

  /**
   * Генерация risk trend
   */
  private generateRiskTrend(alerts: PrioritizedAlert[]): RiskTrendData[] {
    const hourlyRisk: Map<string, RiskTrendData> = new Map();
    
    for (const alert of alerts) {
      const hour = alert.timestamp.toISOString().slice(0, 13);
      
      if (!hourlyRisk.has(hour)) {
        hourlyRisk.set(hour, {
          timestamp: new Date(hour + ':00:00'),
          overallRisk: 0,
          entityRisk: 0,
          threatRisk: 0,
          impactRisk: 0
        });
      }
      
      const data = hourlyRisk.get(hour)!;
      data.overallRisk = Math.max(data.overallRisk, alert.riskScore.overall);
    }
    
    return Array.from(hourlyRisk.values())
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime())
      .slice(-24);
  }

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Обновление статистики алертов
   */
  private updateAlertStatistics(alert: PrioritizedAlert): void {
    // По серьезности
    const severityCount = this.statistics.alertsBySeverity.get(alert.severity) || 0;
    this.statistics.alertsBySeverity.set(alert.severity, severityCount + 1);
    
    // По категории
    const categoryCount = this.statistics.alertsByCategory.get(alert.category) || 0;
    this.statistics.alertsByCategory.set(alert.category, categoryCount + 1);
  }

  /**
   * Обновление времени обнаружения
   */
  private updateDetectionTime(processingTime: number): void {
    const total = this.statistics.totalEventsProcessed;
    const oldMean = this.statistics.meanTimeToDetect;
    this.statistics.meanTimeToDetect = oldMean + (processingTime - oldMean) / total;
  }

  /**
   * Получение алерта по ID
   */
  getAlert(alertId: string): PrioritizedAlert | undefined {
    return this.alerts.get(alertId);
  }

  /**
   * Получение всех алертов
   */
  getAllAlerts(): PrioritizedAlert[] {
    return Array.from(this.alerts.values());
  }

  /**
   * Получение алертов по серьезности
   */
  getAlertsBySeverity(severity: ThreatSeverity): PrioritizedAlert[] {
    return Array.from(this.alerts.values()).filter(a => a.severity === severity);
  }

  /**
   * Обновление статуса алерта
   */
  updateAlertStatus(alertId: string, status: SecurityAlert['status']): void {
    const alert = this.alerts.get(alertId);
    
    if (alert) {
      alert.status = status;
      alert.updatedAt = new Date();
      this.alerts.set(alertId, alert);
    }
  }

  /**
   * Отметка ложного срабатывания
   */
  markFalsePositive(alertId: string): void {
    this.updateAlertStatus(alertId, ThreatStatus.FALSE_POSITIVE);
  }

  /**
   * Закрытие алерта
   */
  closeAlert(alertId: string): void {
    this.updateAlertStatus(alertId, ThreatStatus.CLOSED);
  }

  /**
   * Назначение ответственного
   */
  assignAlert(alertId: string, userId: string): void {
    const alert = this.alerts.get(alertId);
    
    if (alert) {
      alert.assignedTo = userId;
      alert.updatedAt = new Date();
      this.alerts.set(alertId, alert);
    }
  }
}

/**
 * Статистика Threat Detection Engine
 */
interface ThreatDetectionStatistics {
  totalEventsProcessed: number;
  totalAlertsGenerated: number;
  alertsBySeverity: Map<ThreatSeverity, number>;
  alertsByCategory: Map<ThreatCategory, number>;
  meanTimeToDetect: number;
  falsePositiveRate: number;
  lastUpdated: Date;
}
