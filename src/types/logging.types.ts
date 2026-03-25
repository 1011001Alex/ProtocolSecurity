/**
 * ============================================================================
 * ТИПЫ И ИНТЕРФЕЙСЫ СИСТЕМЫ ЛОГИРОВАНИЯ И SIEM
 * ============================================================================
 * Полная типизация для всех компонентов системы логирования
 * Включает типы для логов, алертов, правил SIEM, compliance отчетов
 */

// ============================================================================
// БАЗОВЫЕ ТИПЫ УРОВНЕЙ ЛОГИРОВАНИЯ
// ============================================================================

/**
 * Уровни логирования согласно RFC 5424 (Syslog)
 * Используется для классификации важности событий
 */
export enum LogLevel {
  EMERGENCY = 0,    // Система неработоспособна
  ALERT = 1,        // Требуется немедленное действие
  CRITICAL = 2,     // Критическое состояние
  ERROR = 3,        // Ошибка
  WARNING = 4,      // Предупреждение
  NOTICE = 5,       // Нормальное, но значимое событие
  INFO = 6,         // Информационное сообщение
  DEBUG = 7,        // Отладочная информация
  TRACE = 8         // Детальная трассировка
}

/**
 * Категории источников логов
 */
export enum LogSource {
  APPLICATION = 'application',      // Логи приложения
  SYSTEM = 'system',                // Системные логи
  NETWORK = 'network',              // Сетевые события
  SECURITY = 'security',            // События безопасности
  DATABASE = 'database',            // Логи БД
  AUTH = 'auth',                    // Аутентификация/авторизация
  AUDIT = 'audit',                  // Аудит действий
  PERFORMANCE = 'performance'       // Метрики производительности
}

/**
 * Типы событий безопасности
 */
export enum SecurityEventType {
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILURE = 'login_failure',
  LOGOUT = 'logout',
  PASSWORD_CHANGE = 'password_change',
  PERMISSION_DENIED = 'permission_denied',
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  DATA_ACCESS = 'data_access',
  DATA_MODIFICATION = 'data_modification',
  DATA_DELETION = 'data_deletion',
  CONFIG_CHANGE = 'config_change',
  API_ACCESS = 'api_access',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  ATTACK_DETECTED = 'attack_detected'
}

// ============================================================================
// ТИПЫ ДЛЯ OWASP TOP 10 АТАК
// ============================================================================

/**
 * Категории атак OWASP Top 10
 */
export enum OWASPAttackCategory {
  INJECTION = 'injection',                          // A01:2021
  BROKEN_AUTH = 'broken_authentication',            // A02:2021
  SENSITIVE_DATA_EXPOSURE = 'sensitive_data_exposure', // A03:2021
  XML_EXTERNAL_ENTITIES = 'xml_external_entities',  // A04:2021
  BROKEN_ACCESS_CONTROL = 'broken_access_control',  // A05:2021
  SECURITY_MISCONFIGURATION = 'security_misconfiguration', // A06:2021
  CROSS_SITE_SCRIPTING = 'cross_site_scripting',    // A07:2021
  INSECURE_DESERIALIZATION = 'insecure_deserialization', // A08:2021
  VULNERABLE_COMPONENTS = 'vulnerable_components',  // A09:2021
  INSUFFICIENT_LOGGING = 'insufficient_logging'     // A10:2021
}

/**
 * Уровень серьезности атаки
 */
export enum AttackSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

// ============================================================================
// ОСНОВНЫЕ ТИПЫ ЛОГОВ
// ============================================================================

/**
 * Базовый интерфейс для всех логов
 * Содержит обязательные поля для любого лог-сообщения
 */
export interface BaseLog {
  /** Уникальный идентификатор лога (UUID v4) */
  id: string;
  /** Временная метка в формате ISO 8601 */
  timestamp: string;
  /** Уровень логирования */
  level: LogLevel;
  /** Источник лога */
  source: LogSource;
  /** Название компонента/сервиса */
  component: string;
  /** Хост, сгенерировавший лог */
  hostname: string;
  /** Процесс ID */
  processId: number;
  /** ID потока выполнения */
  threadId?: number;
  /** Сообщение лога */
  message: string;
  /** Категория события */
  category?: string;
  /** Код события (для классификации) */
  eventCode?: string;
}

/**
 * Контекст выполнения для обогащения логов
 */
export interface LogContext {
  /** ID пользователя */
  userId?: string;
  /** Username */
  username?: string;
  /** IP адрес клиента */
  clientIp?: string;
  /** User Agent */
  userAgent?: string;
  /** ID сессии */
  sessionId?: string;
  /** ID запроса (для трассировки) */
  requestId?: string;
  /** ID корреляции (для распределенных систем) */
  correlationId?: string;
  /** Географическое положение */
  geoLocation?: GeoLocation;
  /** Устройство клиента */
  device?: DeviceInfo;
  /** Дополнительные метаданные */
  metadata?: Record<string, unknown>;
}

/**
 * Географическое положение
 */
export interface GeoLocation {
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  isp?: string;
  asn?: string;
}

/**
 * Информация об устройстве
 */
export interface DeviceInfo {
  type?: 'desktop' | 'mobile' | 'tablet' | 'server' | 'iot' | 'unknown';
  os?: string;
  osVersion?: string;
  browser?: string;
  browserVersion?: string;
}

/**
 * Полное лог-сообщение с контекстом
 */
export interface LogEntry extends BaseLog {
  /** Контекст выполнения */
  context: LogContext;
  /** Дополнительные поля (структурированные данные) */
  fields?: Record<string, unknown>;
  /** Стек ошибки (если есть) */
  stackTrace?: string;
  /** Хеш содержимого для верификации целостности */
  contentHash?: string;
  /** Подпись для tamper-proof хранения */
  signature?: string;
  /** Время обработки в пайплайне */
  processingTime?: number;
  /** Версия схемы лога */
  schemaVersion: string;
}

// ============================================================================
// ТИПЫ ДЛЯ АГРЕГАЦИИ И БУФЕРИЗАЦИИ
// ============================================================================

/**
 * Статус обработки лога в пайплайне
 */
export enum LogProcessingStatus {
  PENDING = 'pending',
  PARSING = 'parsing',
  ENRICHING = 'enriching',
  CORRELATING = 'correlating',
  ANALYZING = 'analyzing',
  STORING = 'storing',
  COMPLETED = 'completed',
  FAILED = 'failed'
}

/**
 * Результат обработки лога
 */
export interface LogProcessingResult {
  log: LogEntry;
  status: LogProcessingStatus;
  errors?: ProcessingError[];
  warnings?: string[];
  processingStages: ProcessingStage[];
}

/**
 * Этап обработки
 */
export interface ProcessingStage {
  name: string;
  startTime: string;
  endTime?: string;
  duration?: number;
  status: 'success' | 'failed' | 'skipped';
  error?: string;
}

/**
 * Ошибка обработки
 */
export interface ProcessingError {
  stage: string;
  code: string;
  message: string;
  recoverable: boolean;
}

/**
 * Конфигурация буфера логов
 */
export interface LogBufferConfig {
  /** Максимальный размер буфера (сообщения) */
  maxBufferSize: number;
  /** Максимальное время ожидания перед отправкой (мс) */
  maxWaitTime: number;
  /** Минимальное количество сообщений для пакетной отправки */
  minBatchSize: number;
  /** Стратегия при переполнении */
  overflowStrategy: 'drop_oldest' | 'drop_newest' | 'block';
  /** Количество воркеров для обработки */
  workerCount: number;
  /** Включить сжатие */
  enableCompression: boolean;
  /** Включить шифрование */
  enableEncryption: boolean;
}

/**
 * Пакет логов для пакетной обработки
 */
export interface LogBatch {
  id: string;
  logs: LogEntry[];
  createdAt: string;
  source: LogSource;
  priority: number;
  compressed?: boolean;
  encrypted?: boolean;
}

// ============================================================================
// ТИПЫ ДЛЯ SIEM RULES ENGINE
// ============================================================================

/**
 * Операторы для правил SIEM
 */
export enum RuleOperator {
  EQUALS = 'equals',
  NOT_EQUALS = 'not_equals',
  CONTAINS = 'contains',
  NOT_CONTAINS = 'not_contains',
  GREATER_THAN = 'greater_than',
  LESS_THAN = 'less_than',
  GREATER_EQUALS = 'greater_equals',
  LESS_EQUALS = 'less_equals',
  IN = 'in',
  NOT_IN = 'not_in',
  REGEX = 'regex',
  EXISTS = 'exists',
  NOT_EXISTS = 'not_exists'
}

/**
 * Логические операторы для комбинации условий
 */
export enum LogicalOperator {
  AND = 'AND',
  OR = 'OR',
  NOT = 'NOT'
}

/**
 * Условие в правиле SIEM
 */
export interface RuleCondition {
  /** Поле для проверки */
  field: string;
  /** Оператор сравнения */
  operator: RuleOperator;
  /** Значение для сравнения */
  value?: unknown;
  /** Массив значений для IN/NOT_IN */
  values?: unknown[];
  /** Regex паттерн */
  pattern?: string;
  /** Флаги для regex */
  flags?: string;
  /** Вложенные условия */
  conditions?: RuleCondition[];
  /** Логический оператор для вложенных условий */
  logicalOperator?: LogicalOperator;
}

/**
 * Действие при срабатывании правила
 */
export enum RuleActionType {
  ALERT = 'alert',
  BLOCK = 'block',
  RATE_LIMIT = 'rate_limit',
  LOG = 'log',
  NOTIFY = 'notify',
  ESCALATE = 'escalate',
  QUARANTINE = 'quarantine',
  TRIGGER_WEBHOOK = 'trigger_webhook'
}

/**
 * Конфигурация действия
 */
export interface RuleAction {
  type: RuleActionType;
  /** Параметры действия */
  params?: Record<string, unknown>;
  /** Каналы уведомления */
  channels?: string[];
  /** Шаблон сообщения */
  template?: string;
  /** Приоритет действия */
  priority?: number;
  /** Задержка выполнения (мс) */
  delay?: number;
  /** Условия выполнения действия */
  conditions?: RuleCondition[];
}

/**
 * Агрегация для правил (окно времени)
 */
export interface RuleAggregation {
  /** Тип агрегации */
  type: 'count' | 'sum' | 'avg' | 'min' | 'max' | 'distinct_count';
  /** Поле для агрегации */
  field?: string;
  /** Окно времени (секунды) */
  windowSeconds: number;
  /** Пороговое значение */
  threshold: number;
  /** Группировка по полям */
  groupBy?: string[];
}

/**
 * Правило SIEM
 */
export interface SIEMRule {
  /** Уникальный ID правила */
  id: string;
  /** Название правила */
  name: string;
  /** Описание */
  description: string;
  /** Категория правила */
  category: string;
  /** Версия правила */
  version: string;
  /** Включено ли правило */
  enabled: boolean;
  /** Приоритет правила */
  priority: number;
  /** Условия срабатывания */
  conditions: RuleCondition[];
  /** Логический оператор для условий */
  logicalOperator: LogicalOperator;
  /** Агрегация (опционально) */
  aggregation?: RuleAggregation;
  /** Действия при срабатывании */
  actions: RuleAction[];
  /** Теги для классификации */
  tags: string[];
  /** MITRE ATT&CK тактики (если применимо) */
  mitreAttackIds?: string[];
  /** OWASP категории */
  owaspCategories?: OWASPAttackCategory[];
  /** Compliance стандарты */
  complianceStandards?: string[];
  /** Ложные срабатывания (для tuning) */
  falsePositiveRate?: number;
  /** Дата создания */
  createdAt: string;
  /** Дата обновления */
  updatedAt: string;
  /** Автор правила */
  author?: string;
}

/**
 * Результат выполнения правила
 */
export interface RuleExecutionResult {
  ruleId: string;
  ruleName: string;
  matched: boolean;
  matchedLogs: LogEntry[];
  aggregationValue?: number;
  threshold?: number;
  triggeredAt: string;
  actionsExecuted: RuleAction[];
  executionTime: number;
}

// ============================================================================
// ТИПЫ ДЛЯ DETECTION
// ============================================================================

/**
 * Детектированное событие атаки
 */
export interface AttackDetection {
  /** Уникальный ID детекта */
  id: string;
  /** Тип атаки */
  attackType: OWASPAttackCategory;
  /** Подтип атаки */
  attackSubtype?: string;
  /** Уровень серьезности */
  severity: AttackSeverity;
  /** Уверенность детекта (0-1) */
  confidence: number;
  /** Связанные логи */
  relatedLogs: LogEntry[];
  /** Источник атаки */
  source: AttackSource;
  /** Цель атаки */
  target: AttackTarget;
  /** Вектор атаки */
  attackVector: string;
  /** Payload (если есть) */
  payload?: string;
  /** Индикаторы компрометации (IOC) */
  indicatorsOfCompromise: IOC[];
  /** Рекомендации по реагированию */
  remediationSteps: string[];
  /** Ссылки на документацию */
  references: string[];
  /** Время детекта */
  detectedAt: string;
  /** Статус расследования */
  investigationStatus: 'new' | 'investigating' | 'confirmed' | 'false_positive' | 'resolved';
}

/**
 * Источник атаки
 */
export interface AttackSource {
  ip: string;
  port?: number;
  country?: string;
  asn?: string;
  isTor?: boolean;
  isProxy?: boolean;
  isVpn?: boolean;
  reputation?: number;
  previousAttacks?: number;
}

/**
 * Цель атаки
 */
export interface AttackTarget {
  ip?: string;
  port?: number;
  endpoint?: string;
  service?: string;
  vulnerability?: string;
  dataAccessed?: string[];
}

/**
 * Индикатор компрометации
 */
export interface IOC {
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'file' | 'registry' | 'behavior';
  value: string;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  tags?: string[];
}

/**
 * Конфигурация ML модели для anomaly detection
 */
export interface AnomalyDetectionConfig {
  /** Тип модели */
  modelType: 'isolation_forest' | 'one_class_svm' | 'autoencoder' | 'statistical';
  /** Поля для анализа */
  features: string[];
  /** Порог аномалии (0-1) */
  anomalyThreshold: number;
  /** Период обучения (часы) */
  trainingPeriodHours: number;
  /** Частота переобучения (часы) */
  retrainingFrequencyHours: number;
  /** Минимальный размер выборки */
  minSampleSize: number;
  /** Метод нормализации */
  normalizationMethod: 'z-score' | 'min-max' | 'robust';
  /** Включить сезонность */
  enableSeasonality: boolean;
  /** Период сезонности (часы) */
  seasonalityPeriodHours?: number;
}

/**
 * Результат анализа аномалий
 */
export interface AnomalyDetectionResult {
  /** Является ли аномалией */
  isAnomaly: boolean;
  /** Score аномалии (0-1) */
  anomalyScore: number;
  /** Тип аномалии */
  anomalyType?: 'point' | 'contextual' | 'collective';
  /** Поля, внесшие вклад в аномалию */
  contributingFeatures: FeatureContribution[];
  /** Базовое значение (expected) */
  expectedValue?: number;
  /** Фактическое значение */
  actualValue?: number;
  /** Отклонение в стандартных отклонениях */
  deviationSigma?: number;
  /** Контекст аномалии */
  context?: AnomalyContext;
}

/**
 * Вклад признака в аномалию
 */
export interface FeatureContribution {
  feature: string;
  contribution: number;
  direction: 'increase' | 'decrease';
}

/**
 * Контекст аномалии
 */
export interface AnomalyContext {
  timeOfDay?: string;
  dayOfWeek?: string;
  isHoliday?: boolean;
  isBusinessHours?: boolean;
  concurrentEvents?: number;
  historicalPattern?: string;
}

// ============================================================================
// ТИПЫ ДЛЯ ALERTING
// ============================================================================

/**
 * Уровень серьезности алерта
 */
export enum AlertSeverity {
  P1_CRITICAL = 'p1_critical',    // Критический, требует немедленного действия
  P2_HIGH = 'p2_high',            // Высокий, требует быстрого действия
  P3_MEDIUM = 'p3_medium',        // Средний, требует действия в течение дня
  P4_LOW = 'p4_low',              // Низкий, требует действия в течение недели
  P5_INFO = 'p5_info'             // Информационный, для отслеживания
}

/**
 * Статус алерта
 */
export enum AlertStatus {
  NEW = 'new',
  ACKNOWLEDGED = 'acknowledged',
  INVESTIGATING = 'investigating',
  RESOLVED = 'resolved',
  FALSE_POSITIVE = 'false_positive',
  SUPPRESSED = 'suppressed'
}

/**
 * Канал уведомления
 */
export enum NotificationChannel {
  EMAIL = 'email',
  SLACK = 'slack',
  PAGERDUTY = 'pagerduty',
  TELEGRAM = 'telegram',
  WEBHOOK = 'webhook',
  SMS = 'sms',
  PUSH = 'push'
}

/**
 * Конфигурация канала уведомления
 */
export interface NotificationChannelConfig {
  type: NotificationChannel;
  name: string;
  enabled: boolean;
  /** Параметры канала */
  params: Record<string, unknown>;
  /** Фильтры для канала */
  filters?: AlertFilter[];
  /** Rate limiting для канала */
  rateLimit?: RateLimitConfig;
  /** Часы работы (для эскалации) */
  workingHours?: WorkingHours;
  /** Шаблон сообщения */
  messageTemplate?: string;
}

/**
 * Фильтр алертов
 */
export interface AlertFilter {
  field: string;
  operator: RuleOperator;
  value: unknown;
}

/**
 * Конфигурация rate limiting
 */
export interface RateLimitConfig {
  /** Максимум алертов в период */
  maxAlerts: number;
  /** Период (секунды) */
  periodSeconds: number;
  /** Действие при превышении */
  action: 'suppress' | 'aggregate' | 'escalate';
}

/**
 * Рабочие часы
 */
export interface WorkingHours {
  timezone: string;
  weekdays: {
    start: string;  // HH:mm
    end: string;    // HH:mm
  };
  weekends: {
    start: string;
    end: string;
  };
  holidays?: string[];  // ISO даты
}

/**
 * Правило эскалации
 */
export interface EscalationRule {
  /** ID правила */
  id: string;
  /** Название */
  name: string;
  /** Условия применения */
  conditions: RuleCondition[];
  /** Уровни эскалации */
  levels: EscalationLevel[];
  /** Включено ли */
  enabled: boolean;
}

/**
 * Уровень эскалации
 */
export interface EscalationLevel {
  /** Порядок уровня */
  order: number;
  /** Задержка перед эскалацией (минуты) */
  delayMinutes: number;
  /** Каналы уведомления */
  channels: string[];
  /** Получатели */
  recipients: string[];
  /** Условия выполнения */
  conditions?: RuleCondition[];
}

/**
 * Алерт
 */
export interface Alert {
  /** Уникальный ID алерта */
  id: string;
  /** ID сгенерировавшего правила */
  ruleId: string;
  /** Название правила */
  ruleName: string;
  /** Заголовок алерта */
  title: string;
  /** Описание */
  description: string;
  /** Уровень серьезности */
  severity: AlertSeverity;
  /** Статус */
  status: AlertStatus;
  /** Категория */
  category: string;
  /** Теги */
  tags: string[];
  /** Связанные детекты атак */
  attackDetections?: AttackDetection[];
  /** Связанные логи */
  relatedLogs: LogEntry[];
  /** Источник алерта */
  source: string;
  /** Хост */
  hostname: string;
  /** IP адрес */
  ipAddress?: string;
  /** Пользователь (если применимо) */
  user?: string;
  /** Время возникновения */
  occurredAt: string;
  /** Время создания алерта */
  createdAt: string;
  /** Время последнего обновления */
  updatedAt: string;
  /** Время разрешения */
  resolvedAt?: string;
  /** Кто разрешил */
  resolvedBy?: string;
  /** Причина разрешения */
  resolutionReason?: string;
  /** История эскалации */
  escalationHistory: EscalationEvent[];
  /** Отправленные уведомления */
  notifications: NotificationEvent[];
  /** Дополнительные данные */
  metadata?: Record<string, unknown>;
  /** Хеш для дедупликации */
  fingerprint: string;
  /** Количество повторений */
  occurrenceCount: number;
  /** Время первого возникновения */
  firstOccurrenceAt?: string;
  /** Время последнего возникновения */
  lastOccurrenceAt?: string;
}

/**
 * Событие эскалации
 */
export interface EscalationEvent {
  /** ID события */
  id: string;
  /** Уровень эскалации */
  level: number;
  /** Время эскалации */
  escalatedAt: string;
  /** Причина */
  reason: string;
  /** Каналы уведомления */
  channels: string[];
  /** Получатели */
  recipients: string[];
  /** Статус выполнения */
  status: 'pending' | 'sent' | 'failed';
  /** Ошибка (если есть) */
  error?: string;
}

/**
 * Событие уведомления
 */
export interface NotificationEvent {
  /** ID события */
  id: string;
  /** Канал */
  channel: NotificationChannel;
  /** Получатель */
  recipient: string;
  /** Время отправки */
  sentAt: string;
  /** Статус доставки */
  deliveryStatus: 'pending' | 'sent' | 'delivered' | 'failed';
  /** Время доставки */
  deliveredAt?: string;
  /** Ошибка (если есть) */
  error?: string;
  /** Ответ получателя (если применимо) */
  response?: string;
}

// ============================================================================
// ТИПЫ ДЛЯ ХРАНЕНИЯ И ВЕРИФИКАЦИИ
// ============================================================================

/**
 * Стратегия хранения логов
 */
export enum StorageStrategy {
  APPEND_ONLY = 'append_only',      // Только добавление
  IMMUTABLE = 'immutable',          // Неизменяемое
  WRITE_ONCE_READ_MANY = 'worm',    // WORM storage
  BLOCKCHAIN = 'blockchain'         // Blockchain-based
}

/**
 * Конфигурация хранилища
 */
export interface LogStorageConfig {
  /** Стратегия хранения */
  strategy: StorageStrategy;
  /** Путь к хранилищу */
  storagePath: string;
  /** Максимальный размер файла (MB) */
  maxFileSizeMB: number;
  /** Политика ротации */
  rotationPolicy: RotationPolicy;
  /** Политика хранения */
  retentionPolicy: RetentionPolicy;
  /** Включить сжатие */
  enableCompression: boolean;
  /** Включить шифрование */
  enableEncryption: boolean;
  /** Алгоритм хеширования */
  hashAlgorithm: 'sha256' | 'sha384' | 'sha512' | 'blake2b';
  /** Включить цепочку хешей */
  enableHashChain: boolean;
  /** Интервал создания checkpoint (сообщения) */
  checkpointInterval: number;
}

/**
 * Политика ротации
 */
export interface RotationPolicy {
  /** Тип ротации */
  type: 'size' | 'time' | 'both';
  /** Максимальный размер (MB) */
  maxSizeMB?: number;
  /** Интервал ротации */
  interval?: 'hourly' | 'daily' | 'weekly' | 'monthly';
  /** Количество файлов для хранения */
  maxFiles: number;
  /** Включить архивацию */
  enableArchiving: boolean;
  /** Путь к архиву */
  archivePath?: string;
}

/**
 * Политика хранения
 */
export interface RetentionPolicy {
  /** Период хранения горячих данных (дни) */
  hotRetentionDays: number;
  /** Период хранения теплых данных (дни) */
  warmRetentionDays: number;
  /** Период хранения холодных данных (дни) */
  coldRetentionDays: number;
  /** Действие после истечения */
  expirationAction: 'delete' | 'archive' | 'freeze';
  /** Compliance требования (минимальный период) */
  complianceMinDays?: number;
}

/**
 * Запись в immutable хранилище
 */
export interface ImmutableLogRecord {
  /** Лог данные */
  log: LogEntry;
  /** Хеш содержимого */
  contentHash: string;
  /** Хеш предыдущей записи (для цепочки) */
  previousHash: string;
  /** Подпись записи */
  signature: string;
  /** Временная метка записи */
  recordedAt: string;
  /** Sequence номер */
  sequenceNumber: number;
  /** ID блока (если используется blockchain) */
  blockId?: string;
  /** Меркле рут (если используется) */
  merkleRoot?: string;
}

/**
 * Результат верификации целостности
 */
export interface IntegrityVerificationResult {
  /** Успешна ли верификация */
  isValid: boolean;
  /** Проверенные записи */
  verifiedRecords: number;
  /** Найдено нарушений */
  violationsFound: number;
  /** Детали нарушений */
  violations: IntegrityViolation[];
  /** Время проверки */
  verifiedAt: string;
  /** Проверенный диапазон */
  checkedRange: {
    from: string;
    to: string;
  };
}

/**
 * Нарушение целостности
 */
export interface IntegrityViolation {
  /** Тип нарушения */
  type: 'hash_mismatch' | 'signature_invalid' | 'chain_broken' | 'missing_record' | 'duplicate_record' | 'timestamp_invalid';
  /** ID записи */
  recordId: string;
  /** Ожидаемое значение */
  expectedValue: string;
  /** Фактическое значение */
  actualValue: string;
  /** Серьезность */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Время обнаружения */
  detectedAt: string;
  /** Возможная причина */
  possibleCause?: string;
}

// ============================================================================
// ТИПЫ ДЛЯ ELASTICSEARCH
// ============================================================================

/**
 * Конфигурация Elasticsearch клиента
 */
export interface ElasticsearchConfig {
  /** URL ноды/кластера */
  nodes: string[];
  /** API ключ */
  apiKey?: string;
  /** Basic auth */
  auth?: {
    username: string;
    password: string;
  };
  /** SSL/TLS настройки */
  tls?: {
    ca: string;
    cert: string;
    key: string;
    rejectUnauthorized: boolean;
  };
  /** Индекс для логов */
  logIndex: string;
  /** Шаблон индекса */
  indexTemplate: string;
  /** Политика ILM */
  ilmPolicy: ILMPolicy;
  /** Настройки bulk indexing */
  bulkIndexing: {
    flushBytes: number;
    flushInterval: number;
    concurrency: number;
  };
  /** Таймауты */
  timeouts: {
    request: number;
    ping: number;
  };
}

/**
 * Политика ILM (Index Lifecycle Management)
 */
export interface ILMPolicy {
  /** Название политики */
  name: string;
  /** Hot фаза */
  hot: {
    priority: number;
    rollover: {
      maxSize: string;
      maxAge: string;
    };
  };
  /** Warm фаза */
  warm: {
    minAge: string;
    priority: number;
    forceMerge: {
      maxNumSegments: number;
    };
  };
  /** Cold фаза */
  cold: {
    minAge: string;
    priority: number;
  };
  /** Frozen фаза */
  frozen: {
    minAge: string;
  };
  /** Delete фаза */
  delete: {
    minAge: string;
  };
}

/**
 * Результат поиска в Elasticsearch
 */
export interface ElasticsearchSearchResult<T = LogEntry> {
  /** Всего найдено */
  total: number;
  /** Максимальный score */
  maxScore: number;
  /** Найденные документы */
  hits: ElasticsearchHit<T>[];
  /** Агрегации */
  aggregations?: Record<string, unknown>;
  /** Время выполнения запроса (мс) */
  took: number;
  /** Таймаут */
  timedOut: boolean;
}

/**
 * Хит в результатах поиска
 */
export interface ElasticsearchHit<T> {
  /** Индекс */
  _index: string;
  /** ID документа */
  _id: string;
  /** Score */
  _score: number;
  /** Источник */
  _source: T;
  /** Подсветка */
  highlight?: Record<string, string[]>;
  /** Sort значения */
  sort?: (string | number)[];
}

/**
 * Параметры запроса поиска
 */
export interface SearchQuery {
  /** Индекс/индексы */
  indices: string[];
  /** Query DSL */
  query: Record<string, unknown>;
  /** Фильтры */
  filters?: Record<string, unknown>[];
  /** Агрегации */
  aggregations?: Record<string, unknown>;
  /** Сортировка */
  sort?: Record<string, unknown>[];
  /** Размер страницы */
  size: number;
  /** Offset */
  from: number;
  /** Поля для возврата */
  source?: string[] | boolean;
  /** Подсветка */
  highlight?: Record<string, unknown>;
  /** Время ожидания */
  timeout?: string;
  /** Search after для pagination */
  searchAfter?: (string | number)[];
}

// ============================================================================
// ТИПЫ ДЛЯ COMPLIANCE
// ============================================================================

/**
 * Стандарты compliance
 */
export enum ComplianceStandard {
  PCI_DSS = 'pci_dss',        // Payment Card Industry
  GDPR = 'gdpr',              // General Data Protection Regulation
  SOX = 'sox',                // Sarbanes-Oxley Act
  HIPAA = 'hipaa',            // Health Insurance Portability
  ISO_27001 = 'iso_27001',    // Information Security Management
  NIST = 'nist',              // NIST Cybersecurity Framework
  CIS = 'cis',                // Center for Internet Security
  SOC2 = 'soc2'               // Service Organization Control 2
}

/**
 * Требование compliance
 */
export interface ComplianceRequirement {
  /** ID требования */
  id: string;
  /** Стандарт */
  standard: ComplianceStandard;
  /** Контроль/требование */
  control: string;
  /** Описание */
  description: string;
  /** Категория */
  category: string;
  /** Приоритет */
  priority: 'critical' | 'high' | 'medium' | 'low';
  /** Связанные правила SIEM */
  relatedRules: string[];
  /** Связанные логи */
  relatedLogTypes: string[];
  /** Метрики соответствия */
  metrics: ComplianceMetric[];
  /** Доказательства */
  evidence: EvidenceRequirement[];
  /** Частота проверки */
  checkFrequency: 'continuous' | 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly';
}

/**
 * Метрика compliance
 */
export interface ComplianceMetric {
  /** Название метрики */
  name: string;
  /** Описание */
  description: string;
  /** Тип метрики */
  type: 'percentage' | 'count' | 'boolean' | 'duration';
  /** Формула/запрос */
  query: string;
  /** Целевое значение */
  targetValue: number;
  /** Порог предупреждения */
  warningThreshold: number;
  /** Порог нарушения */
  violationThreshold: number;
}

/**
 * Требование к доказательствам
 */
export interface EvidenceRequirement {
  /** Тип доказательства */
  type: 'log' | 'report' | 'screenshot' | 'config' | 'policy';
  /** Описание */
  description: string;
  /** Частота сбора */
  frequency: string;
  /** Минимальный период хранения */
  retentionDays: number;
  /** Формат */
  format: string;
}

/**
 * Отчет о соответствии
 */
export interface ComplianceReport {
  /** ID отчета */
  id: string;
  /** Стандарт */
  standard: ComplianceStandard;
  /** Период отчета */
  period: {
    start: string;
    end: string;
  };
  /** Дата генерации */
  generatedAt: string;
  /** Общий статус соответствия */
  overallStatus: 'compliant' | 'partially_compliant' | 'non_compliant';
  /** Процент соответствия */
  complianceScore: number;
  /** Статус по требованиям */
  requirements: ComplianceRequirementStatus[];
  /** Найденные нарушения */
  violations: ComplianceViolation[];
  /** Рекомендации */
  recommendations: Recommendation[];
  /** Приложения */
  appendices: Record<string, unknown>;
  /** Подпись аудитора */
  auditorSignature?: string;
  /** Статус отчета */
  reportStatus: 'draft' | 'review' | 'final' | 'archived';
}

/**
 * Статус требования compliance
 */
export interface ComplianceRequirementStatus {
  /** ID требования */
  requirementId: string;
  /** Контроль */
  control: string;
  /** Статус */
  status: 'compliant' | 'non_compliant' | 'partial' | 'not_applicable';
  /** Процент соответствия */
  compliancePercentage: number;
  /** Доказательства */
  evidence: EvidenceRecord[];
  /** Метрики */
  metrics: MetricResult[];
  /** Примечания */
  notes?: string;
  /** Дата последней проверки */
  lastChecked: string;
}

/**
 * Запись доказательства
 */
export interface EvidenceRecord {
  /** ID доказательства */
  id: string;
  /** Тип */
  type: string;
  /** Описание */
  description: string;
  /** Путь/ссылка */
  location: string;
  /** Дата создания */
  createdAt: string;
  /** Хеш для верификации */
  hash: string;
  /** Срок действия */
  expiresAt?: string;
}

/**
 * Результат метрики
 */
export interface MetricResult {
  /** Название метрики */
  name: string;
  /** Фактическое значение */
  actualValue: number;
  /** Целевое значение */
  targetValue: number;
  /** Статус */
  status: 'pass' | 'warning' | 'fail';
  /** Тренд */
  trend?: 'improving' | 'stable' | 'degrading';
  /** Изменение */
  change?: number;
}

/**
 * Нарушение compliance
 */
export interface ComplianceViolation {
  /** ID нарушения */
  id: string;
  /** Требование */
  requirementId: string;
  /** Контроль */
  control: string;
  /** Описание нарушения */
  description: string;
  /** Серьезность */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Влияние */
  impact: string;
  /** Причина */
  rootCause?: string;
  /** Рекомендации по исправлению */
  remediation: string[];
  /** Срок исправления */
  remediationDeadline?: string;
  /** Ответственный */
  owner?: string;
  /** Статус исправления */
  remediationStatus: 'open' | 'in_progress' | 'resolved' | 'accepted_risk';
  /** Дата обнаружения */
  detectedAt: string;
  /** Дата разрешения */
  resolvedAt?: string;
}

/**
 * Рекомендация
 */
export interface Recommendation {
  /** ID рекомендации */
  id: string;
  /** Название */
  title: string;
  /** Описание */
  description: string;
  /** Приоритет */
  priority: 'critical' | 'high' | 'medium' | 'low';
  /** Связанные нарушения */
  relatedViolations: string[];
  /** Рекомендуемые действия */
  actions: string[];
  /** Ожидаемый эффект */
  expectedImpact: string;
  /** Сложность реализации */
  implementationComplexity: 'low' | 'medium' | 'high';
  /** Оценка затрат */
  estimatedCost?: string;
}

// ============================================================================
// ОБЩИЕ ТИПЫ КОНФИГУРАЦИИ
// ============================================================================

/**
 * Полная конфигурация системы логирования
 */
export interface LoggingSystemConfig {
  /** Конфигурация логгера */
  logger: LoggerConfig;
  /** Конфигурация буфера */
  buffer: LogBufferConfig;
  /** Конфигурация хранилища */
  storage: LogStorageConfig;
  /** Конфигурация Elasticsearch */
  elasticsearch: ElasticsearchConfig;
  /** Конфигурация SIEM правил */
  siemRules: SIEMRule[];
  /** Конфигурация anomaly detection */
  anomalyDetection: AnomalyDetectionConfig;
  /** Конфигурация уведомлений */
  notifications: NotificationChannelConfig[];
  /** Правила эскалации */
  escalationRules: EscalationRule[];
  /** Compliance требования */
  complianceRequirements: ComplianceRequirement[];
  /** Глобальные настройки */
  global: GlobalConfig;
}

/**
 * Конфигурация логгера
 */
export interface LoggerConfig {
  /** Уровень логирования */
  level: LogLevel;
  /** Формат вывода */
  format: 'json' | 'text' | 'structured';
  /** Включить цвета */
  enableColors: boolean;
  /** Включить timestamp */
  enableTimestamp: boolean;
  /** Включить метаданные процесса */
  enableProcessInfo: boolean;
  /** Транспорты */
  transports: TransportConfig[];
  /** По умолчанию контекст */
  defaultContext?: LogContext;
}

/**
 * Конфигурация транспорта
 */
export interface TransportConfig {
  /** Тип транспорта */
  type: 'console' | 'file' | 'elasticsearch' | 'kafka' | 'http' | 'syslog';
  /** Уровень логирования */
  level: LogLevel;
  /** Параметры транспорта */
  params: Record<string, unknown>;
  /** Форматирование */
  format?: string;
  /** Фильтры */
  filters?: RuleCondition[];
}

/**
 * Глобальные настройки
 */
export interface GlobalConfig {
  /** Название сервиса/приложения */
  serviceName: string;
  /** Версия */
  version: string;
  /** Окружение */
  environment: 'development' | 'staging' | 'production';
  /** Регион */
  region: string;
  /** Часовой пояс */
  timezone: string;
  /** Включить аудит */
  enableAudit: boolean;
  /** Включить отладку */
  enableDebug: boolean;
  /** Sample rate для трассировки */
  traceSampleRate: number;
  /** Максимальный размер лога (байты) */
  maxLogSize: number;
  /** Включить rate limiting */
  enableRateLimiting: boolean;
  /** Rate limit конфигурация */
  rateLimiting?: RateLimitConfig;
}

/**
 * Статистика системы логирования
 */
export interface LoggingStatistics {
  /** Период статистики */
  period: {
    start: string;
    end: string;
  };
  /** Обработано логов */
  logsProcessed: number;
  /** Логи по уровням */
  logsByLevel: Record<LogLevel, number>;
  /** Логи по источникам */
  logsBySource: Record<LogSource, number>;
  /** Ошибки обработки */
  processingErrors: number;
  /** Детектировано атак */
  attacksDetected: number;
  /** Аномалии */
  anomaliesDetected: number;
  /** Сгенерировано алертов */
  alertsGenerated: number;
  /** Среднее время обработки (мс) */
  avgProcessingTime: number;
  /** P99 время обработки (мс) */
  p99ProcessingTime: number;
  /** Размер хранилища (байты) */
  storageSize: number;
  /** Количество записей в хранилище */
  storageRecords: number;
  /** Нарушения целостности */
  integrityViolations: number;
  /** Compliance score */
  complianceScore: number;
}
