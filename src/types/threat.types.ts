/**
 * ============================================================================
 * THREAT DETECTION TYPES
 * Полная система типов для продвинутой системы обнаружения угроз
 * ============================================================================
 */

import { Tensor } from '@tensorflow/tfjs';

// ============================================================================
// ОСНОВНЫЕ ТИПЫ УГРОЗ
// ============================================================================

/**
 * Уровень серьезности угрозы
 */
export enum ThreatSeverity {
  CRITICAL = 'critical',  // Критическая - немедленное реагирование
  HIGH = 'high',          // Высокая - реагирование в течение 1 часа
  MEDIUM = 'medium',      // Средняя - реагирование в течение 24 часов
  LOW = 'low',            // Низкая - реагирование в течение 7 дней
  INFO = 'info'           // Информационная - для анализа
}

/**
 * Статус угрозы
 */
export enum ThreatStatus {
  NEW = 'new',              // Новая угроза
  INVESTIGATING = 'investigating',  // В расследовании
  CONFIRMED = 'confirmed',  // Подтвержденная
  FALSE_POSITIVE = 'false_positive',  // Ложное срабатывание
  CONTAINED = 'contained',  // Локализована
  REMEDIATED = 'remediated',  // Устранена
  CLOSED = 'closed'         // Закрыта
}

/**
 * Категория угрозы по MITRE ATT&CK
 */
export enum ThreatCategory {
  INITIAL_ACCESS = 'initial_access',      // Первоначальный доступ
  EXECUTION = 'execution',                // Выполнение кода
  PERSISTENCE = 'persistence',            // Закрепление
  PRIVILEGE_ESCALATION = 'privilege_escalation',  // Повышение привилегий
  DEFENSE_EVASION = 'defense_evasion',    // Обход защиты
  CREDENTIAL_ACCESS = 'credential_access',  // Доступ к учетным данным
  DISCOVERY = 'discovery',                // Разведка
  LATERAL_MOVEMENT = 'lateral_movement',  // Перемещение внутри сети
  COLLECTION = 'collection',              // Сбор данных
  COMMAND_AND_CONTROL = 'command_and_control',  // Управление
  EXFILTRATION = 'exfiltration',          // Хищение данных
  IMPACT = 'impact'                       // Воздействие
}

/**
 * Тип атаки
 */
export enum AttackType {
  MALWARE = 'malware',
  RANSOMWARE = 'ransomware',
  PHISHING = 'phishing',
  SQL_INJECTION = 'sql_injection',
  XSS = 'xss',
  DDoS = 'ddos',
  BRUTE_FORCE = 'brute_force',
  ZERO_DAY = 'zero_day',
  INSIDER_THREAT = 'insider_threat',
  APT = 'apt',  // Advanced Persistent Threat
  CRYPTO_MINING = 'crypto_mining',
  DATA_EXFILTRATION = 'data_exfiltration',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  LATERAL_MOVEMENT = 'lateral_movement',
  C2_COMMUNICATION = 'c2_communication',
  SUSPICIOUS_BEHAVIOR = 'suspicious_behavior',
  ANOMALY = 'anomaly',
  POLICY_VIOLATION = 'policy_violation',
  UNKNOWN = 'unknown'
}

// ============================================================================
// ТИПЫ ДЛЯ АНАЛИЗА ПОВЕДЕНИЯ (UEBA)
// ============================================================================

/**
 * Тип сущности для анализа поведения
 */
export enum EntityType {
  USER = 'user',
  HOST = 'host',
  SERVICE = 'service',
  APPLICATION = 'application',
  NETWORK_DEVICE = 'network_device',
  DATABASE = 'database',
  API = 'api',
  CONTAINER = 'container',
  CLOUD_RESOURCE = 'cloud_resource'
}

/**
 * Базовый профиль поведения сущности
 */
export interface BehaviorProfile {
  entityId: string;
  entityType: EntityType;
  baselineMetrics: Record<string, number>;  // Базовые метрики поведения
  dynamicMetrics: Record<string, number>;   // Текущие метрики
  riskScore: number;                         // Расчетный риск (0-100)
  lastUpdated: Date;
  historyWindow: number;  // Окно анализа в часах
}

/**
 * Профиль поведения пользователя
 */
export interface UserProfile extends BehaviorProfile {
  userId: string;
  username: string;
  department?: string;
  role: string;
  typicalLoginTimes: number[];  // Часы типичных входов (0-23)
  typicalLocations: GeoLocation[];
  typicalDevices: string[];
  accessedResources: string[];
  averageSessionDuration: number;
  failedLoginRate: number;
  privilegeUsagePatterns: PrivilegePattern[];
}

/**
 * Профиль поведения хоста
 */
export interface HostProfile extends BehaviorProfile {
  hostname: string;
  ipAddress: string;
  osType: string;
  osVersion: string;
  typicalProcesses: string[];
  typicalConnections: NetworkConnection[];
  averageCPUUsage: number;
  averageMemoryUsage: number;
  averageNetworkTraffic: number;
  installedSoftware: string[];
  openPorts: number[];
}

/**
 * Паттерн использования привилегий
 */
export interface PrivilegePattern {
  privilege: string;
  typicalUsageTimes: number[];
  typicalResources: string[];
  frequency: number;
}

/**
 * Геолокация
 */
export interface GeoLocation {
  latitude: number;
  longitude: number;
  country: string;
  city: string;
  isTypical: boolean;
}

/**
 * Сетевое подключение
 */
export interface NetworkConnection {
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  bytesSent: number;
  bytesReceived: number;
  isTypical: boolean;
}

// ============================================================================
// ТИПЫ ДЛЯ ML МОДЕЛЕЙ
// ============================================================================

/**
 * Типы поддерживаемых ML моделей
 */
export enum MLModelType {
  ISOLATION_FOREST = 'isolation_forest',  // Для обнаружения аномалий
  LSTM = 'lstm',                          // Для временных рядов
  AUTOENCODER = 'autoencoder',            // Для снижения размерности
  RANDOM_FOREST = 'random_forest',        // Для классификации
  GRADIENT_BOOSTING = 'gradient_boosting', // Для классификации
  CLUSTERING = 'clustering'               // Для кластеризации
}

/**
 * Конфигурация ML модели
 */
export interface MLModelConfig {
  modelType: MLModelType;
  modelId: string;
  inputFeatures: string[];
  outputClasses?: string[];
  hyperparameters: Record<string, number | boolean | string>;
  trainingWindow: number;  // Окно обучения в днях
  retrainingInterval: number;  // Интервал переобучения в часах
  threshold: number;  // Порог срабатывания
}

/**
 * Результат предсказания ML модели
 */
export interface MLPrediction {
  modelId: string;
  timestamp: Date;
  input: Record<string, number>;
  prediction: number | number[];  // Score или probabilities
  confidence: number;
  isAnomaly?: boolean;
  anomalyScore?: number;
  featureImportance?: Record<string, number>;
}

/**
 * Данные для обучения модели
 */
export interface TrainingData {
  features: number[][];
  labels?: number[];
  timestamps: Date[];
  metadata: Record<string, unknown>;
}

/**
 * Метрики качества модели
 */
export interface ModelMetrics {
  modelId: string;
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1Score?: number;
  auc?: number;
  falsePositiveRate?: number;
  falseNegativeRate?: number;
  trainingTime: number;
  lastTrained: Date;
}

// ============================================================================
// ТИПЫ ДЛЯ MITRE ATT&CK
// ============================================================================

/**
 * Тактика MITRE ATT&CK
 */
export interface MitreTactic {
  id: string;  // TA0001, TA0002, ...
  name: string;
  description: string;
  url: string;
}

/**
 * Техника MITRE ATT&CK
 */
export interface MitreTechnique {
  id: string;  // T1001, T1003, ...
  name: string;
  description: string;
  url: string;
  tactics: string[];  // IDs тактик
  platforms: string[];  // Платформы (Windows, Linux, etc.)
  permissionsRequired: string[];
  dataSources: string[];
  detection: string;
  mitigation: string;
  subTechniques?: MitreTechnique[];
}

/**
 * Процедура (процедуры атакующих)
 */
export interface MitreProcedure {
  techniqueId: string;
  description: string;
  examples: string[];
}

/**
 * Группа угроз (Threat Actor Group)
 */
export interface MitreThreatGroup {
  id: string;  // G0001, G0002, ...
  name: string;
  aliases: string[];
  description: string;
  url: string;
  associatedTechniques: string[];
  targets: string[];
  regions: string[];
}

/**
 * Маппинг событий на MITRE ATT&CK
 */
export interface MitreMapping {
  eventId: string;
  techniqueId: string;
  tacticId: string;
  confidence: number;  // 0-1
  evidence: string[];
}

/**
 * Kill Chain этап
 */
export enum KillChainPhase {
  RECONNAISSANCE = 'reconnaissance',      // Разведка
  WEAPONIZATION = 'weaponization',        // Создание оружия
  DELIVERY = 'delivery',                  // Доставка
  EXPLOITATION = 'exploitation',          // Эксплуатация
  INSTALLATION = 'installation',          // Установка
  COMMAND_AND_CONTROL = 'command_and_control',  // Управление
  ACTIONS_ON_OBJECTIVES = 'actions_on_objectives'  // Достижение целей
}

/**
 * Анализ Kill Chain
 */
export interface KillChainAnalysis {
  attackId: string;
  phases: KillChainPhase[];
  currentPhase: KillChainPhase;
  completedPhases: KillChainPhase[];
  indicators: KillChainIndicator[];
  progression: number;  // 0-100%
  estimatedTimeToObjective: number;  // В минутах
}

export interface KillChainIndicator {
  phase: KillChainPhase;
  indicatorType: string;
  value: string;
  confidence: number;
  timestamp: Date;
}

// ============================================================================
// ТИПЫ ДЛЯ THREAT INTELLIGENCE (STIX/TAXII)
// ============================================================================

/**
 * STIX Domain Objects
 */
export enum StixType {
  ATTACK_PATTERN = 'attack-pattern',
  CAMPAIGN = 'campaign',
  IDENTITY = 'identity',
  INDICATOR = 'indicator',
  INFRASTRUCTURE = 'infrastructure',
  INTRUSION_SET = 'intrusion-set',
  MALWARE = 'malware',
  OBSERVED_DATA = 'observed-data',
  THREAT_ACTOR = 'threat-actor',
  TOOL = 'tool',
  VULNERABILITY = 'vulnerability'
}

/**
 * STIX Indicator Pattern Types
 */
export enum IndicatorPatternType {
  STIX = 'stix',
  SNORT = 'snort',
  SURICATA = 'suricata',
  YARA = 'yara',
  SIGMA = 'sigma',
  CYPATTERN = 'cybox'
}

/**
 * STIX Indicator
 */
export interface StixIndicator {
  id: string;
  type: StixType.INDICATOR;
  name: string;
  description: string;
  pattern: string;
  patternType: IndicatorPatternType;
  validFrom: Date;
  validUntil?: Date;
  labels: string[];
  confidence: number;  // 0-100
  severity: ThreatSeverity;
  externalReferences: StixExternalReference[];
  killChainPhases: KillChainPhase[];
  createdBy: string;
  created: Date;
  modified: Date;
}

/**
 * STIX Threat Actor
 */
export interface StixThreatActor {
  id: string;
  type: StixType.THREAT_ACTOR;
  name: string;
  description: string;
  aliases: string[];
  goals: string[];
  sophistication: 'none' | 'minimal' | 'intermediate' | 'advanced' | 'expert' | 'innovator' | 'strategic';
  resourceLevel: 'individual' | 'club' | 'contest' | 'team' | 'organization' | 'government';
  primaryMotivation: string;
  secondaryMotivations: string[];
  personalMotivations: string[];
  externalReferences: StixExternalReference[];
  createdBy: string;
  created: Date;
  modified: Date;
}

/**
 * STIX Malware
 */
export interface StixMalware {
  id: string;
  type: StixType.MALWARE;
  name: string;
  description: string;
  aliases: string[];
  malwareTypes: string[];
  malwareFamilies: string[];
  isFamily: boolean;
  firstSeen?: Date;
  lastSeen?: Date;
  operatingSystems: string[];
  architectureExecutionEnvs: string[];
  implementationLanguages: string[];
  capabilities: string[];
  externalReferences: StixExternalReference[];
  createdBy: string;
  created: Date;
  modified: Date;
}

/**
 * STIX External Reference
 */
export interface StixExternalReference {
  sourceName: string;
  description?: string;
  url?: string;
  externalId?: string;
}

/**
 * TAXII Server Configuration
 */
export interface TaxiiServerConfig {
  url: string;
  apiRoot?: string;
  username?: string;
  password?: string;
  token?: string;
  collections: string[];
  pollingInterval: number;  // В минутах
}

/**
 * Threat Intelligence Feed
 */
export interface ThreatFeed {
  id: string;
  name: string;
  type: 'stix-taxii' | 'opencti' | 'misp' | 'custom';
  url: string;
  enabled: boolean;
  lastSync?: Date;
  syncStatus: 'idle' | 'syncing' | 'error';
  indicatorsCount: number;
  config: TaxiiServerConfig | Record<string, unknown>;
}

// ============================================================================
// ТИПЫ ДЛЯ DETECTION ENGINE
// ============================================================================

/**
 * Тип детектора угроз
 */
export enum DetectorType {
  SIGNATURE_BASED = 'signature_based',    // Сигнатурный анализ
  ANOMALY_BASED = 'anomaly_based',        // Аномалии
  BEHAVIOR_BASED = 'behavior_based',      // Поведенческий анализ
  HEURISTIC = 'heuristic',                // Эвристический анализ
  ML_BASED = 'ml_based',                  // ML модели
  CORRELATION = 'correlation',            // Корреляция событий
  THREAT_INTEL = 'threat_intel',          // Threat intelligence
  COMPLIANCE = 'compliance'               // Проверка соответствия
}

/**
 * Правило обнаружения
 */
export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: ThreatSeverity;
  category: ThreatCategory;
  attackType: AttackType;
  detectorType: DetectorType;
  mitreTechniques: string[];  // IDs техник MITRE ATT&CK
  condition: DetectionCondition;
  threshold?: number;
  window: number;  // Временное окно в секундах
  actions: DetectionAction[];
  tags: string[];
  references: string[];
  falsePositiveRate?: number;
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
}

/**
 * Условие обнаружения
 */
export interface DetectionCondition {
  type: 'threshold' | 'pattern' | 'sequence' | 'absence' | 'statistical';
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'lt' | 'gte' | 'lte' | 'in' | 'contains' | 'regex' | 'between';
  value: unknown;
  groupBy?: string[];
  aggregation?: 'count' | 'sum' | 'avg' | 'min' | 'max' | 'stddev';
}

/**
 * Действие при обнаружении
 */
export interface DetectionAction {
  type: 'alert' | 'block' | 'quarantine' | 'terminate' | 'isolate' | 'notify' | 'execute_playbook';
  target?: string;
  parameters?: Record<string, unknown>;
  playbookId?: string;
}

/**
 * Событие безопасности
 */
export interface SecurityEvent {
  id: string;
  timestamp: Date;
  eventType: string;
  source: string;
  sourceIp?: string;
  destinationIp?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  userId?: string;
  username?: string;
  hostname?: string;
  processName?: string;
  processId?: number;
  commandLine?: string;
  filePath?: string;
  hash?: string;
  severity: ThreatSeverity;
  category: ThreatCategory;
  rawEvent: Record<string, unknown>;
  normalizedEvent: Record<string, unknown>;
  enrichmentData?: Record<string, unknown>;
  mitreMappings?: MitreMapping[];
  correlationId?: string;
}

/**
 * Алерт безопасности
 */
export interface SecurityAlert {
  id: string;
  timestamp: Date;
  title: string;
  description: string;
  severity: ThreatSeverity;
  status: ThreatStatus;
  category: ThreatCategory;
  attackType: AttackType;
  source: string;
  ruleId?: string;
  ruleName?: string;
  events: SecurityEvent[];
  entities: AlertEntity[];
  mitreAttack: MitreAttackInfo;
  riskScore: number;
  confidence: number;
  falsePositiveProbability: number;
  investigationStatus: InvestigationStatus;
  assignedTo?: string;
  tags: string[];
  timeline: AlertTimelineEntry[];
  evidence: Evidence[];
  response: AlertResponse;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Сущность в алерте
 */
export interface AlertEntity {
  id: string;
  type: EntityType;
  name: string;
  value: string;
  riskScore: number;
  role: 'attacker' | 'victim' | 'intermediary' | 'unknown';
  context: Record<string, unknown>;
}

/**
 * Информация об атаке MITRE
 */
export interface MitreAttackInfo {
  tactics: MitreTactic[];
  techniques: MitreTechnique[];
  killChainPhase?: KillChainPhase;
  threatGroups?: MitreThreatGroup[];
}

/**
 * Статус расследования
 */
export interface InvestigationStatus {
  stage: 'triage' | 'investigation' | 'containment' | 'eradication' | 'recovery' | 'lessons_learned';
  progress: number;  // 0-100
  findings: string[];
  evidenceCollected: string[];
  rootCause?: string;
  impact?: string;
}

/**
 * Запись временной шкалы алерта
 */
export interface AlertTimelineEntry {
  timestamp: Date;
  event: string;
  actor?: string;
  details?: string;
}

/**
 * Доказательства
 */
export interface Evidence {
  id: string;
  type: 'file' | 'log' | 'network_capture' | 'memory_dump' | 'screenshot' | 'artifact';
  name: string;
  path: string;
  hash?: string;
  collectedAt: Date;
  collectedBy: string;
  chainOfCustody: ChainOfCustodyEntry[];
}

export interface ChainOfCustodyEntry {
  timestamp: Date;
  actor: string;
  action: 'collected' | 'transferred' | 'analyzed' | 'stored';
  notes?: string;
}

/**
 * Ответ на алерт
 */
export interface AlertResponse {
  automatedActions: AutomatedAction[];
  manualActions: ManualAction[];
  playbooksExecuted: string[];
  containmentStatus: 'not_started' | 'in_progress' | 'completed' | 'failed';
  eradicationStatus: 'not_started' | 'in_progress' | 'completed' | 'failed';
  recoveryStatus: 'not_started' | 'in_progress' | 'completed' | 'failed';
}

export interface AutomatedAction {
  id: string;
  type: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  executedAt?: Date;
  result?: string;
  error?: string;
}

export interface ManualAction {
  id: string;
  type: string;
  description: string;
  status: 'pending' | 'in_progress' | 'completed' | 'blocked';
  assignedTo?: string;
  dueDate?: Date;
  completedAt?: Date;
  notes?: string;
}

// ============================================================================
// ТИПЫ ДЛЯ КОРРЕЛЯЦИИ
// ============================================================================

/**
 * Правило корреляции
 */
export interface CorrelationRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: ThreatSeverity;
  timeWindow: number;  // В секундах
  minEvents: number;
  conditions: CorrelationCondition[];
  groupBy: string[];
  actions: DetectionAction[];
  mitreTechniques: string[];
}

export interface CorrelationCondition {
  field: string;
  operator: 'eq' | 'ne' | 'contains' | 'regex' | 'gt' | 'lt';
  value: unknown;
  sequence?: boolean;  // Последовательность событий
  sequenceOrder?: string[];  // Порядок событий
}

/**
 * Коррелированное событие
 */
export interface CorrelatedEvent {
  id: string;
  ruleId: string;
  ruleName: string;
  events: SecurityEvent[];
  startTime: Date;
  endTime: Date;
  eventCount: number;
  uniqueSources: string[];
  uniqueTargets: string[];
  severity: ThreatSeverity;
  mitreAttack: MitreAttackInfo;
  killChainAnalysis?: KillChainAnalysis;
}

// ============================================================================
// ТИПЫ ДЛЯ RISK SCORING
// ============================================================================

/**
 * Факторы риска
 */
export interface RiskFactors {
  // Факторы сущности
  entityRisk: {
    criticality: number;  // Критичность актива (0-100)
    exposure: number;     // Уровень экспозиции (0-100)
    vulnerability: number;  // Уровень уязвимости (0-100)
  };
  
  // Факторы угрозы
  threatRisk: {
    severity: number;     // Серьезность угрозы (0-100)
    confidence: number;   // Уверенность (0-100)
    credibility: number;  // Достоверность источника (0-100)
  };
  
  // Факторы воздействия
  impactRisk: {
    confidentiality: number;  // Воздействие на конфиденциальность
    integrity: number;        // Воздействие на целостность
    availability: number;     // Воздействие на доступность
    financial: number;        // Финансовое воздействие
    reputational: number;     // Репутационное воздействие
  };
  
  // Контекстные факторы
  contextRisk: {
    timeOfDay: number;      // Риск времени суток
    location: number;       // Географический риск
    networkZone: number;    // Риск сетевой зоны
    userBehavior: number;   // Аномалия поведения
  };
}

/**
 * Расчет риска
 */
export interface RiskScore {
  overall: number;  // Общий риск (0-100)
  entity: number;
  threat: number;
  impact: number;
  context: number;
  factors: RiskFactors;
  calculation: RiskCalculation;
  timestamp: Date;
}

export interface RiskCalculation {
  formula: string;
  weights: Record<string, number>;
  normalizedScores: Record<string, number>;
  adjustments: RiskAdjustment[];
}

export interface RiskAdjustment {
  factor: string;
  adjustment: number;
  reason: string;
}

/**
 * Приоритизированный алерт
 */
export interface PrioritizedAlert extends SecurityAlert {
  riskScore: RiskScore;
  priority: number;  // 1-5 (1 - наивысший)
  slaResponseTime: number;  // В минутах
  estimatedImpact: string;
  recommendedActions: string[];
}

// ============================================================================
// ТИПЫ ДЛЯ THREAT HUNTING
// ============================================================================

/**
 * Query для threat hunting
 */
export interface HuntQuery {
  id: string;
  name: string;
  description: string;
  category: ThreatCategory;
  mitreTechniques: string[];
  hypothesis: string;
  query: string;
  queryLanguage: 'sql' | 'lucene' | 'kql' | 'spl' | 'custom';
  dataSource: string;
  parameters: HuntParameter[];
  expectedResults: string;
  falsePositiveGuidance: string;
  tags: string[];
  author: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface HuntParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'date' | 'ip' | 'domain';
  required: boolean;
  defaultValue?: unknown;
  description: string;
}

/**
 * Результат hunting query
 */
export interface HuntResult {
  queryId: string;
  executedAt: Date;
  executionTime: number;  // В мс
  resultCount: number;
  findings: HuntFinding[];
  statistics: HuntStatistics;
  recommendations: string[];
}

export interface HuntFinding {
  id: string;
  severity: ThreatSeverity;
  title: string;
  description: string;
  evidence: Record<string, unknown>;
  mitreMappings: MitreMapping[];
  recommendedActions: string[];
  falsePositiveProbability: number;
}

export interface HuntStatistics {
  totalEvents: number;
  uniqueEntities: number;
  timeRange: {
    start: Date;
    end: Date;
  };
  topFindings: string[];
  anomaliesDetected: number;
}

/**
 * Playbook для threat hunting
 */
export interface HuntPlaybook {
  id: string;
  name: string;
  description: string;
  objective: string;
  scope: string;
  prerequisites: string[];
  steps: HuntStep[];
  estimatedDuration: number;  // В минутах
  difficulty: 'beginner' | 'intermediate' | 'advanced';
  mitreTechniques: string[];
  tags: string[];
}

export interface HuntStep {
  order: number;
  title: string;
  description: string;
  query?: string;
  expectedOutcome: string;
  nextSteps: {
    ifPositive: string;
    ifNegative: string;
  };
}

// ============================================================================
// ТИПЫ ДЛЯ AUTOMATED RESPONSE
// ============================================================================

/**
 * Playbook автоматического реагирования
 */
export interface ResponsePlaybook {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  triggerConditions: TriggerCondition[];
  severity: ThreatSeverity;
  categories: ThreatCategory[];
  attackTypes: AttackType[];
  steps: ResponseStep[];
  rollbackSteps: ResponseStep[];
  notifications: NotificationConfig[];
  approvals: ApprovalConfig[];
  tags: string[];
  version: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface TriggerCondition {
  field: string;
  operator: string;
  value: unknown;
  alertSeverity?: ThreatSeverity;
  riskScoreMin?: number;
  mitreTechnique?: string;
}

export interface ResponseStep {
  order: number;
  id: string;
  name: string;
  type: 'api_call' | 'script' | 'command' | 'notification' | 'approval' | 'wait';
  action: string;
  parameters: Record<string, unknown>;
  timeout: number;  // В секундах
  retryCount: number;
  retryDelay: number;
  condition?: string;  // Условие выполнения
  onError: 'abort' | 'continue' | 'rollback';
  requiresApproval?: boolean;
  approvalId?: string;
}

export interface NotificationConfig {
  channel: 'email' | 'slack' | 'teams' | 'pagerduty' | 'webhook';
  recipients: string[];
  template: string;
  severity: ThreatSeverity;
  throttleMinutes: number;
}

export interface ApprovalConfig {
  id: string;
  name: string;
  approvers: string[];
  approvalType: 'any' | 'all' | 'quorum';
  quorumCount?: number;
  timeout: number;  // В минутах
  escalationPolicy?: string;
}

/**
 * Выполнение playbook
 */
export interface PlaybookExecution {
  id: string;
  playbookId: string;
  alertId: string;
  status: 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'rolled_back';
  startedAt: Date;
  completedAt?: Date;
  currentStep?: number;
  stepsResults: StepResult[];
  approvals: ApprovalResult[];
  error?: string;
  rolledBackSteps: number[];
}

export interface StepResult {
  stepId: string;
  order: number;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  startedAt?: Date;
  completedAt?: Date;
  result?: Record<string, unknown>;
  error?: string;
  approvalRequired?: boolean;
  approvalStatus?: 'pending' | 'approved' | 'rejected';
}

export interface ApprovalResult {
  approvalId: string;
  status: 'pending' | 'approved' | 'rejected' | 'timeout';
  approvers: ApproverResponse[];
  completedAt?: Date;
}

export interface ApproverResponse {
  approver: string;
  decision: 'approved' | 'rejected';
  timestamp: Date;
  comment?: string;
}

// ============================================================================
// ТИПЫ ДЛЯ NETWORK ANALYSIS
// ============================================================================

/**
 * Пакет сетевого трафика
 */
export interface NetworkPacket {
  timestamp: Date;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  size: number;
  flags: string[];
  payload?: Buffer;
  ttl: number;
}

/**
 * Сетевой поток
 */
export interface NetworkFlow {
  id: string;
  startTime: Date;
  endTime?: Date;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: string;
  packetsCount: number;
  bytesSent: number;
  bytesReceived: number;
  duration: number;  // В мс
  state: 'new' | 'established' | 'closing' | 'closed';
  applicationProtocol?: string;
  tlsVersion?: string;
  tlsCipher?: string;
  dnsQuery?: string;
  httpMethod?: string;
  httpUri?: string;
  httpUserAgent?: string;
}

/**
 * Сетевая аномалия
 */
export interface NetworkAnomaly {
  id: string;
  type: NetworkAnomalyType;
  severity: ThreatSeverity;
  description: string;
  evidence: NetworkEvidence;
  timestamp: Date;
  confidence: number;
}

export enum NetworkAnomalyType {
  PORT_SCAN = 'port_scan',
  NETWORK_SWEEP = 'network_sweep',
  DATA_EXFILTRATION = 'data_exfiltration',
  C2_COMMUNICATION = 'c2_communication',
  DNS_TUNNELING = 'dns_tunneling',
  LATERAL_MOVEMENT = 'lateral_movement',
  BRUTE_FORCE = 'brute_force',
  DDOS = 'ddos',
  SUSPICIOUS_CONNECTION = 'suspicious_connection',
  PROTOCOL_ANOMALY = 'protocol_anomaly',
  CERTIFICATE_ANOMALY = 'certificate_anomaly'
}

export interface NetworkEvidence {
  flows: NetworkFlow[];
  packets?: NetworkPacket[];
  statistics: NetworkStatistics;
  indicators: string[];
}

export interface NetworkStatistics {
  packetsPerSecond: number;
  bytesPerSecond: number;
  connectionsPerSecond: number;
  uniqueDestinations: number;
  protocolDistribution: Record<string, number>;
  portDistribution: Record<string, number>;
}

/**
 * Сетевая сессия
 */
export interface NetworkSession {
  id: string;
  userId?: string;
  srcIp: string;
  startTime: Date;
  lastActivity: Date;
  flows: NetworkFlow[];
  bytesTransferred: number;
  riskScore: number;
  anomalies: NetworkAnomaly[];
}

// ============================================================================
// ТИПЫ ДЛЯ ENDPOINT DETECTION
// ============================================================================

/**
 * Событие endpoint
 */
export interface EndpointEvent {
  id: string;
  timestamp: Date;
  endpointId: string;
  hostname: string;
  eventType: EndpointEventType;
  process?: ProcessInfo;
  file?: FileInfo;
  registry?: RegistryInfo;
  network?: NetworkConnectionInfo;
  user?: UserInfo;
  severity: ThreatSeverity;
  rawEvent: Record<string, unknown>;
}

export enum EndpointEventType {
  PROCESS_CREATE = 'process_create',
  PROCESS_TERMINATE = 'process_terminate',
  FILE_CREATE = 'file_create',
  FILE_MODIFY = 'file_modify',
  FILE_DELETE = 'file_delete',
  FILE_READ = 'file_read',
  REGISTRY_CREATE = 'registry_create',
  REGISTRY_MODIFY = 'registry_modify',
  REGISTRY_DELETE = 'registry_delete',
  NETWORK_CONNECTION = 'network_connection',
  MODULE_LOAD = 'module_load',
  DRIVER_LOAD = 'driver_load',
  SCHEDULED_TASK = 'scheduled_task',
  SERVICE_CREATE = 'service_create',
  SERVICE_MODIFY = 'service_modify',
  USER_LOGON = 'user_logon',
  USER_LOGOFF = 'user_logoff',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  CREDENTIAL_ACCESS = 'credential_access'
}

export interface ProcessInfo {
  pid: number;
  ppid: number;
  name: string;
  path: string;
  commandLine: string;
  hash?: FileHash;
  signature?: SignatureInfo;
  integrity: string;
  elevationRequired: boolean;
  isSystem: boolean;
  sessionId: number;
  user: string;
  startTime: Date;
  endTime?: Date;
  childProcesses?: ProcessInfo[];
}

export interface FileInfo {
  path: string;
  name: string;
  size: number;
  hash?: FileHash;
  createdTime: Date;
  modifiedTime: Date;
  accessedTime: Date;
  attributes: string[];
  signature?: SignatureInfo;
}

export interface FileHash {
  md5?: string;
  sha1?: string;
  sha256?: string;
  sha512?: string;
  imphash?: string;
}

export interface SignatureInfo {
  signed: boolean;
  signer?: string;
  issuer?: string;
  validFrom?: Date;
  validTo?: Date;
  verified: boolean;
  trusted: boolean;
}

export interface RegistryInfo {
  key: string;
  value?: string;
  data?: string;
  dataType: string;
}

export interface NetworkConnectionInfo {
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  protocol: string;
  state: string;
  processId?: number;
}

export interface UserInfo {
  sid: string;
  name: string;
  domain: string;
  type: string;
  groups: string[];
  privileges: string[];
}

/**
 * Статус endpoint
 */
export interface EndpointStatus {
  endpointId: string;
  hostname: string;
  ipAddress: string;
  osType: string;
  osVersion: string;
  agentVersion: string;
  lastSeen: Date;
  status: 'online' | 'offline' | 'compromised' | 'isolated';
  riskScore: number;
  activeThreats: number;
  policies: EndpointPolicy[];
}

export interface EndpointPolicy {
  id: string;
  name: string;
  enabled: boolean;
  lastApplied: Date;
  status: 'compliant' | 'non_compliant' | 'error';
}

// ============================================================================
// ТИПЫ ДЛЯ DASHBOARD
// ============================================================================

/**
 * Данные для дашборда
 */
export interface ThreatDashboardData {
  summary: ThreatSummary;
  alerts: AlertMetrics;
  threats: ThreatMetrics;
  network: NetworkMetrics;
  endpoints: EndpointMetrics;
  users: UserMetrics;
  timeline: TimelineData[];
  topThreats: TopThreat[];
  mitreHeatmap: MitreHeatmapData;
  riskTrend: RiskTrendData[];
}

export interface ThreatSummary {
  totalAlerts: number;
  newAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  activeThreats: number;
  containedThreats: number;
  falsePositives: number;
  meanTimeToDetect: number;  // В минутах
  meanTimeToRespond: number;  // В минутах
}

export interface AlertMetrics {
  bySeverity: Record<ThreatSeverity, number>;
  byCategory: Record<ThreatCategory, number>;
  byStatus: Record<ThreatStatus, number>;
  byAttackType: Record<AttackType, number>;
  trend: number;  // Процент изменения
}

export interface ThreatMetrics {
  activeAttacks: number;
  blockedAttacks: number;
  detectedTechniques: string[];
  threatActors: string[];
  killChainProgress: Record<KillChainPhase, number>;
}

export interface NetworkMetrics {
  totalFlows: number;
  suspiciousFlows: number;
  blockedConnections: number;
  topTalkers: NetworkTopEntity[];
  topDestinations: NetworkTopEntity[];
  anomaliesDetected: number;
}

export interface NetworkTopEntity {
  ip: string;
  hostname?: string;
  bytes: number;
  connections: number;
  riskScore: number;
}

export interface EndpointMetrics {
  totalEndpoints: number;
  onlineEndpoints: number;
  compromisedEndpoints: number;
  isolatedEndpoints: number;
  eventsByType: Record<EndpointEventType, number>;
  topAlertedEndpoints: EndpointAlertCount[];
}

export interface EndpointAlertCount {
  endpointId: string;
  hostname: string;
  alertCount: number;
  riskScore: number;
}

export interface UserMetrics {
  totalUsers: number;
  highRiskUsers: number;
  anomalousBehaviors: number;
  failedLogins: number;
  privilegeEscalations: number;
  topRiskUsers: UserRisk[];
}

export interface UserRisk {
  userId: string;
  username: string;
  riskScore: number;
  anomalyScore: number;
  topRisks: string[];
}

export interface TimelineData {
  timestamp: Date;
  alerts: number;
  events: number;
  blocked: number;
  critical: number;
}

export interface TopThreat {
  id: string;
  name: string;
  type: AttackType;
  count: number;
  severity: ThreatSeverity;
  mitreTechniques: string[];
  trend: 'increasing' | 'decreasing' | 'stable';
}

export interface MitreHeatmapData {
  tactics: MitreTacticHeatmap[];
}

export interface MitreTacticHeatmap {
  tactic: MitreTactic;
  techniques: MitreTechniqueHeatmap[];
}

export interface MitreTechniqueHeatmap {
  technique: MitreTechnique;
  count: number;
  severity: ThreatSeverity;
  lastDetected: Date;
}

export interface RiskTrendData {
  timestamp: Date;
  overallRisk: number;
  entityRisk: number;
  threatRisk: number;
  impactRisk: number;
}

// ============================================================================
// КОНФИГУРАЦИЯ И УПРАВЛЕНИЕ
// ============================================================================

/**
 * Конфигурация системы threat detection
 */
export interface ThreatDetectionConfig {
  enabled: boolean;
  mlEnabled: boolean;
 uebaEnabled: boolean;
  threatIntelEnabled: boolean;
  networkAnalysisEnabled: boolean;
  endpointDetectionEnabled: boolean;
  
  // Настройки ML
  ml: MLConfig;
  
  // Настройки UEBA
  ueba: UEBAConfig;
  
  // Настройки threat intelligence
  threatIntel: ThreatIntelConfig;
  
  // Настройки корреляции
  correlation: CorrelationConfig;
  
  // Настройки risk scoring
  riskScoring: RiskScoringConfig;
  
  // Настройки автоматического ответа
  automatedResponse: AutomatedResponseConfig;
  
  // Настройки хранения данных
  storage: StorageConfig;
  
  // Настройки уведомлений
  notifications: NotificationConfig[];
}

export interface MLConfig {
  modelsDirectory: string;
  trainingDataRetention: number;  // Дней
  retrainingSchedule: string;  // Cron expression
  anomalyThreshold: number;
  minTrainingSamples: number;
  featureEngineering: FeatureEngineeringConfig;
}

export interface FeatureEngineeringConfig {
  enabled: boolean;
  features: string[];
  normalization: 'minmax' | 'zscore' | 'none';
  dimensionalityReduction: 'pca' | 'autoencoder' | 'none';
}

export interface UEBAConfig {
  baselineWindow: number;  // Дней для базовой линии
  anomalyWindow: number;   // Часов для анализа аномалий
  minEventsForBaseline: number;
  behaviorMetrics: string[];
  riskThresholds: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
}

export interface ThreatIntelConfig {
  feeds: ThreatFeed[];
  updateInterval: number;  // Минут
  indicatorExpiration: number;  // Дней
  minConfidence: number;  // Минимальная уверенность (0-100)
  taxiiServers: TaxiiServerConfig[];
}

export interface CorrelationConfig {
  enabled: boolean;
  windowSize: number;  // Секунд
  maxEventsPerWindow: number;
  rules: CorrelationRule[];
}

export interface RiskScoringConfig {
  enabled: boolean;
  weights: RiskWeights;
  thresholds: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  adjustments: RiskAdjustment[];
}

export interface RiskWeights {
  entity: number;
  threat: number;
  impact: number;
  context: number;
}

export interface AutomatedResponseConfig {
  enabled: boolean;
  requireApprovalFor: ThreatSeverity[];
  playbooksDirectory: string;
  maxConcurrentPlaybooks: number;
  defaultTimeout: number;  // Секунд
}

export interface StorageConfig {
  type: 'elasticsearch' | 'mongodb' | 'postgresql' | 'hybrid';
  connectionStrings: Record<string, string>;
  retention: {
    events: number;  // Дней
    alerts: number;  // Дней
    metrics: number;  // Дней
  };
  indexes: IndexConfig[];
}

export interface IndexConfig {
  name: string;
  type: string;
  shards: number;
  replicas: number;
  rotation: 'daily' | 'weekly' | 'monthly';
}
