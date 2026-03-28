/**
 * ============================================================================
 * INCIDENT RESPONSE TYPES
 * ============================================================================
 * Полная система типов для автоматизированного реагирования на инциденты
 * Соответствует NIST SP 800-61 и SANS Incident Response Methodology
 * ============================================================================
 */

/**
 * Стадии жизненного цикла инцидента по NIST SP 800-61
 */
export enum IncidentLifecycleStage {
  /** Обнаружение инцидента */
  DETECTION = 'detection',
  /** Анализ и оценка */
  ANALYSIS = 'analysis',
  /** Сдерживание угрозы */
  CONTAINMENT = 'containment',
  /** Устранение угрозы */
  ERADICATION = 'eradication',
  /** Восстановление систем */
  RECOVERY = 'recovery',
  /** Завершение и анализ */
  POST_INCIDENT = 'post_incident',
  /** Инцидент закрыт */
  CLOSED = 'closed'
}

/**
 * Уровни серьезности инцидента
 */
export enum IncidentSeverity {
  /** Критический - немедленная угроза бизнесу */
  CRITICAL = 'critical',
  /** Высокий - значительное воздействие */
  HIGH = 'high',
  /** Средний - умеренное воздействие */
  MEDIUM = 'medium',
  /** Низкий - минимальное воздействие */
  LOW = 'low',
  /** Информационный - требует мониторинга */
  INFORMATIONAL = 'informational'
}

/**
 * Приоритет реагирования (1 - наивысший)
 */
export enum IncidentPriority {
  P1 = 1, // Критический - ответ в течение 15 минут
  P2 = 2, // Высокий - ответ в течение 1 часа
  P3 = 3, // Средний - ответ в течение 4 часов
  P4 = 4, // Низкий - ответ в течение 24 часов
  P5 = 5  // Информационный - ответ в течение 72 часов
}

/**
 * Категории инцидентов безопасности
 */
export enum IncidentCategory {
  /** Вредоносное ПО */
  MALWARE = 'malware',
  /** Утечка данных */
  DATA_BREACH = 'data_breach',
  /** DDoS атака */
  DDOS_ATTACK = 'ddos_attack',
  /** Угроза изнутри */
  INSIDER_THREAT = 'insider_threat',
  /** Компрометация учетных данных */
  CREDENTIAL_COMPROMISE = 'credential_compromise',
  /** Ransomware атака */
  RANSOMWARE_ATTACK = 'ransomware_attack',
  /** Несанкционированный доступ */
  UNAUTHORIZED_ACCESS = 'unauthorized_access',
  /** Фишинг */
  PHISHING = 'phishing',
  /** Атака на веб-приложение */
  WEB_APPLICATION_ATTACK = 'web_application_attack',
  /** Сетевая атака */
  NETWORK_ATTACK = 'network_attack',
  /** Физическая безопасность */
  PHYSICAL_SECURITY = 'physical_security',
  /** Compliance нарушение */
  COMPLIANCE_VIOLATION = 'compliance_violation',
  /** Другое */
  OTHER = 'other'
}

/**
 * Статус выполнения шага playbook
 */
export enum PlaybookStepStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  FAILED = 'failed',
  SKIPPED = 'skipped',
  ROLLED_BACK = 'rolled_back'
}

/**
 * Типы автоматических действий сдерживания
 */
export enum ContainmentActionType {
  /** Изоляция хоста от сети */
  NETWORK_ISOLATION = 'network_isolation',
  /** Блокировка учетной записи */
  ACCOUNT_LOCKOUT = 'account_lockout',
  /** Отзыв сессионных токенов */
  TOKEN_REVOCATION = 'token_revocation',
  /** Блокировка IP адреса */
  IP_BLOCKING = 'ip_blocking',
  /** Блокировка домена/URL */
  DOMAIN_BLOCKING = 'domain_blocking',
  /** Остановка сервиса/процесса */
  SERVICE_STOP = 'service_stop',
  /** Карантин файла */
  FILE_QUARANTINE = 'file_quarantine',
  /** Отключение порта коммутатора */
  PORT_DISABLE = 'port_disable',
  /** Блокировка устройства */
  DEVICE_BLOCKING = 'device_blocking',
  /** Ограничение прав доступа */
  ACCESS_RESTRICTION = 'access_restriction'
}

/**
 * Типы форензика данных для сбора
 */
export enum ForensicsDataType {
  /** Дамп памяти */
  MEMORY_DUMP = 'memory_dump',
  /** Дамп диска */
  DISK_IMAGE = 'disk_image',
  /** Сетевые пакеты */
  NETWORK_PACKETS = 'network_packets',
  /** Системные логи */
  SYSTEM_LOGS = 'system_logs',
  /** Логи приложений */
  APPLICATION_LOGS = 'application_logs',
  /** Логи безопасности */
  SECURITY_LOGS = 'security_logs',
  /** Реестр (Windows) */
  REGISTRY_HIVES = 'registry_hives',
  /** Список процессов */
  PROCESS_LIST = 'process_list',
  /** Сетевые соединения */
  NETWORK_CONNECTIONS = 'network_connections',
  /** Автозагрузка */
  AUTOSTART_ENTRIES = 'autostart_entries',
  /** Пользовательские сессии */
  USER_SESSIONS = 'user_sessions',
  /** История команд */
  COMMAND_HISTORY = 'command_history',
  /** Временные файлы */
  TEMP_FILES = 'temp_files',
  /** Метаданные файлов */
  FILE_METADATA = 'file_metadata'
}

/**
 * Статус цепочки хранения улик (Chain of Custody)
 */
export enum ChainOfCustodyStatus {
  /** Улика собрана */
  COLLECTED = 'collected',
  /** Улика передана */
  TRANSFERRED = 'transferred',
  /** Улика хранится */
  STORED = 'stored',
  /** Улика анализируется */
  ANALYZING = 'analyzing',
  /** Улика возвращена */
  RETURNED = 'returned',
  /** Улика уничтожена */
  DESTROYED = 'destroyed'
}

/**
 * Типы стейкхолдеров для коммуникации
 */
export enum StakeholderType {
  /** Команда безопасности */
  SECURITY_TEAM = 'security_team',
  /** Руководство */
  EXECUTIVE_MANAGEMENT = 'executive_management',
  /** IT отдел */
  IT_OPERATIONS = 'it_operations',
  /** Юридический отдел */
  LEGAL_TEAM = 'legal_team',
  /** PR отдел */
  PUBLIC_RELATIONS = 'public_relations',
  /** Регуляторы */
  REGULATORS = 'regulators',
  /** Клиенты */
  CUSTOMERS = 'customers',
  /** Партнеры */
  PARTNERS = 'partners',
  /** Правоохранительные органы */
  LAW_ENFORCEMENT = 'law_enforcement'
}

/**
 * Каналы коммуникации
 */
export enum CommunicationChannel {
  EMAIL = 'email',
  SLACK = 'slack',
  PAGERDUTY = 'pagerduty',
  PHONE = 'phone',
  SMS = 'sms',
  SERVICENOW = 'servicenow',
  JIRA = 'jira',
  WEBHOOK = 'webhook'
}

/**
 * Типы событий временной шкалы
 */
export enum TimelineEventType {
  /** Первоначальное событие инцидента */
  INITIAL_COMPROMISE = 'initial_compromise',
  /** Обнаружение аномалии */
  ANOMALY_DETECTED = 'anomaly_detected',
  /** Эскалация привилегий */
  PRIVILEGE_ESCALATION = 'privilege_escalation',
  /** Перемещение внутри сети */
  LATERAL_MOVEMENT = 'lateral_movement',
  /** Сбор данных */
  DATA_COLLECTION = 'data_collection',
  /** Экфильтрация данных */
  DATA_EXFILTRATION = 'data_exfiltration',
  /** Выполнение вредоносного кода */
  MALWARE_EXECUTION = 'malware_execution',
  /** Действия сдерживания */
  CONTAINMENT_ACTION = 'containment_action',
  /** Действия по устранению */
  ERADICATION_ACTION = 'eradication_action',
  /** Восстановление системы */
  RECOVERY_ACTION = 'recovery_action',
  /** Уведомление стейкхолдеров */
  STAKEHOLDER_NOTIFICATION = 'stakeholder_notification',
  /** Сбор форензика данных */
  FORENSICS_COLLECTION = 'forensics_collection',
  /** Другое событие */
  OTHER = 'other'
}

/**
 * MITRE ATT&CK тактики
 */
export enum MITREAttackTactic {
  RECONNAISSANCE = 'TA0043',
  RESOURCE_DEVELOPMENT = 'TA0042',
  INITIAL_ACCESS = 'TA0001',
  EXECUTION = 'TA0002',
  PERSISTENCE = 'TA0003',
  PRIVILEGE_ESCALATION = 'TA0004',
  DEFENSE_EVASION = 'TA0005',
  CREDENTIAL_ACCESS = 'TA0006',
  DISCOVERY = 'TA0007',
  LATERAL_MOVEMENT = 'TA0008',
  COLLECTION = 'TA0009',
  COMMAND_AND_CONTROL = 'TA0011',
  EXFILTRATION = 'TA0010',
  IMPACT = 'TA0040'
}

/**
 * Интерфейс для уникального идентификатора
 */
export interface UniqueId {
  /** UUID идентификатор */
  id: string;
  /** Время создания */
  createdAt: Date;
}

/**
 * Информация о пользователе/субъекте
 */
export interface Actor {
  /** Уникальный идентификатор */
  id: string;
  /** Имя пользователя */
  username?: string;
  /** Email */
  email?: string;
  /** IP адрес */
  ipAddress?: string;
  /** Геолокация */
  geoLocation?: GeoLocation;
  /** User agent */
  userAgent?: string;
  /** Отпечаток устройства */
  deviceFingerprint?: string;
  /** Роль пользователя */
  role?: string;
  /** Отдел */
  department?: string;
}

/**
 * Геолокация
 */
export interface GeoLocation {
  /** Страна */
  country: string;
  /** Город */
  city: string;
  /** Регион */
  region?: string;
  /** Координаты [широта, долгота] */
  coordinates: [number, number];
  /** ISP */
  isp?: string;
  /** ASN */
  asn?: string;
}

/**
 * Детали инцидента
 */
export interface IncidentDetails {
  /** Заголовок инцидента */
  title: string;
  /** Описание */
  description: string;
  /** Категория */
  category: IncidentCategory;
  /** Подкатегория */
  subCategory?: string;
  /** Вектор атаки */
  attackVector?: string;
  /** Затронутые системы */
  affectedSystems: string[];
  /** Затронутые пользователи */
  affectedUsers: Actor[];
  /** Затронутые данные */
  affectedData?: DataAsset[];
  /** Источник инцидента */
  source?: Actor;
  /** MITRE ATT&CK техники */
  mitreTechniques?: string[];
  /** IOC (Indicators of Compromise) */
  indicatorsOfCompromise?: IOC[];
}

/**
 * Актив данных
 */
export interface DataAsset {
  /** Тип данных */
  type: string;
  /** Описание */
  description: string;
  /** Классификация */
  classification: DataClassification;
  /** Объем данных */
  volume?: number;
  /** Количество записей */
  recordCount?: number;
  /** Путь к данным */
  location?: string;
}

/**
 * Классификация данных
 */
export enum DataClassification {
  PUBLIC = 'public',
  INTERNAL = 'internal',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted',
  PII = 'pii',
  PHI = 'phi',
  PCI = 'pci',
  CRITICAL = 'critical'
}

/**
 * Indicator of Compromise (IOC)
 */
export interface IOC {
  /** Тип IOC */
  type: IOCType;
  /** Значение */
  value: string;
  /** Описание */
  description?: string;
  /** Уровень доверия (0-100) */
  confidence?: number;
  /** Источник */
  source?: string;
  /** Дата первого обнаружения */
  firstSeen?: Date;
  /** Дата последнего обнаружения */
  lastSeen?: Date;
  /** Связанные инциденты */
  relatedIncidents?: string[];
  /** Теги */
  tags?: string[];
}

/**
 * Типы IOC
 */
export enum IOCType {
  IP_ADDRESS = 'ip_address',
  DOMAIN = 'domain',
  URL = 'url',
  FILE_HASH_MD5 = 'file_hash_md5',
  FILE_HASH_SHA1 = 'file_hash_sha1',
  FILE_HASH_SHA256 = 'file_hash_sha256',
  FILE_NAME = 'file_name',
  EMAIL_ADDRESS = 'email_address',
  MAC_ADDRESS = 'mac_address',
  REGISTRY_KEY = 'registry_key',
  MUTEX = 'mutex',
  USER_AGENT = 'user_agent',
  CVE = 'cve',
  YARA_RULE = 'yara_rule'
}

/**
 * Оценка серьезности инцидента
 */
export interface SeverityScore {
  /** Общий балл (0-100) */
  totalScore: number;
  /** Балл воздействия на бизнес */
  businessImpactScore: number;
  /** Балл срочности */
  urgencyScore: number;
  /** Балл сложности */
  complexityScore: number;
  /** Факторы оценки */
  scoringFactors: ScoringFactor[];
  /** Обоснование оценки */
  rationale: string;
}

/**
 * Фактор оценки
 */
export interface ScoringFactor {
  /** Название фактора */
  name: string;
  /** Описание */
  description: string;
  /** Вес фактора (0-1) */
  weight: number;
  /** Значение фактора (0-100) */
  value: number;
  /** Взвешенный балл */
  weightedScore: number;
}

/**
 * Шаг playbook
 */
export interface PlaybookStep {
  /** Уникальный идентификатор шага */
  id: string;
  /** Название шага */
  name: string;
  /** Описание */
  description: string;
  /** Категория шага */
  category: PlaybookStepCategory;
  /** Тип действия */
  actionType: PlaybookActionType;
  /** Параметры действия */
  parameters?: Record<string, unknown>;
  /** Условия выполнения */
  conditions?: PlaybookCondition[];
  /** Зависимости от других шагов */
  dependencies?: string[];
  /** Таймаут выполнения (мс) */
  timeout?: number;
  /** Количество попыток */
  retryCount?: number;
  /** Интервал между попытками (мс) */
  retryInterval?: number;
  /** Статус выполнения */
  status: PlaybookStepStatus;
  /** Результат выполнения */
  result?: PlaybookStepResult;
  /** Время начала */
  startedAt?: Date;
  /** Время завершения */
  completedAt?: Date;
  /** Исполнитель */
  executedBy?: string;
  /** Ошибки */
  errors?: string[];
  /** Rollback действие */
  rollbackAction?: PlaybookStep;
  /** Требует подтверждения */
  requiresApproval?: boolean;
  /** Автоматическое выполнение */
  automatic?: boolean;
}

/**
 * Категория шага playbook
 */
export enum PlaybookStepCategory {
  DETECTION = 'detection',
  ANALYSIS = 'analysis',
  CONTAINMENT = 'containment',
  ERADICATION = 'eradication',
  RECOVERY = 'recovery',
  COMMUNICATION = 'communication',
  DOCUMENTATION = 'documentation',
  FORENSICS = 'forensics'
}

/**
 * Тип действия playbook
 */
export enum PlaybookActionType {
  /** Сбор данных */
  COLLECT_DATA = 'collect_data',
  /** Анализ данных */
  ANALYZE_DATA = 'analyze_data',
  /** Блокировка IP */
  BLOCK_IP = 'block_ip',
  /** Блокировка домена */
  BLOCK_DOMAIN = 'block_domain',
  /** Изоляция хоста */
  ISOLATE_HOST = 'isolate_host',
  /** Блокировка учетной записи */
  LOCK_ACCOUNT = 'lock_account',
  /** Отзыв токенов */
  REVOKE_TOKENS = 'revoke_tokens',
  /** Остановка процесса */
  STOP_PROCESS = 'stop_process',
  /** Карантин файла */
  QUARANTINE_FILE = 'quarantine_file',
  /** Удаление вредоносного ПО */
  REMOVE_MALWARE = 'remove_malware',
  /** Восстановление из бэкапа */
  RESTORE_FROM_BACKUP = 'restore_from_backup',
  /** Сброс пароля */
  RESET_PASSWORD = 'reset_password',
  /** Уведомление */
  SEND_NOTIFICATION = 'send_notification',
  /** Создание тикета */
  CREATE_TICKET = 'create_ticket',
  /** Запуск скрипта */
  RUN_SCRIPT = 'run_script',
  /** Обновление правил */
  UPDATE_RULES = 'update_rules',
  /** Эскалация */
  ESCALATE = 'escalate',
  /** Документирование */
  DOCUMENT = 'document'
}

/**
 * Условие выполнения шага
 */
export interface PlaybookCondition {
  /** Тип условия */
  type: ConditionType;
  /** Поле для проверки */
  field: string;
  /** Оператор */
  operator: ConditionOperator;
  /** Значение для сравнения */
  value: unknown;
  /** Логический оператор для группы условий */
  logicalOperator?: 'AND' | 'OR';
}

/**
 * Тип условия
 */
export enum ConditionType {
  FIELD_VALUE = 'field_value',
  SEVERITY_LEVEL = 'severity_level',
  INCIDENT_CATEGORY = 'incident_category',
  TIME_OF_DAY = 'time_of_day',
  DAY_OF_WEEK = 'day_of_week',
  CUSTOM_SCRIPT = 'custom_script'
}

/**
 * Оператор условия
 */
export enum ConditionOperator {
  EQUALS = 'equals',
  NOT_EQUALS = 'not_equals',
  GREATER_THAN = 'greater_than',
  LESS_THAN = 'less_than',
  CONTAINS = 'contains',
  STARTS_WITH = 'starts_with',
  ENDS_WITH = 'ends_with',
  IN = 'in',
  NOT_IN = 'not_in',
  EXISTS = 'exists',
  NOT_EXISTS = 'not_exists'
}

/**
 * Результат выполнения шага
 */
export interface PlaybookStepResult {
  /** Успешно ли выполнено */
  success: boolean;
  /** Выходные данные */
  output?: Record<string, unknown>;
  /** Сообщение */
  message?: string;
  /** Артефакты */
  artifacts?: PlaybookArtifact[];
  /** Метрики выполнения */
  metrics?: {
    /** Время выполнения (мс) */
    durationMs: number;
    /** Количество попыток */
    attempts: number;
    /** Использованные ресурсы */
    resourcesUsed?: string[];
  };
}

/**
 * Артефакт playbook
 */
export interface PlaybookArtifact {
  /** Тип артефакта */
  type: string;
  /** Название */
  name: string;
  /** Описание */
  description?: string;
  /** Путь к файлу/данным */
  location?: string;
  /** Хэш для целостности */
  hash?: string;
  /** Время создания */
  createdAt: Date;
  /** Создатель */
  createdBy?: string;
}

/**
 * Конфигурация playbook
 */
export interface PlaybookConfiguration {
  /** Уникальный идентификатор playbook */
  id: string;
  /** Название */
  name: string;
  /** Описание */
  description: string;
  /** Версия */
  version: string;
  /** Категория инцидента */
  incidentCategory: IncidentCategory;
  /** Минимальная серьезность для активации */
  minSeverity: IncidentSeverity;
  /** Шаги playbook */
  steps: PlaybookStep[];
  /** Переменные playbook */
  variables?: Record<string, unknown>;
  /** Интеграции */
  integrations?: string[];
  /** Теги */
  tags?: string[];
  /** Автор */
  author?: string;
  /** Дата последнего обновления */
  lastUpdated: Date;
  /** Статус playbook */
  status: 'active' | 'draft' | 'deprecated';
}

/**
 * Событие временной шкалы инцидента
 */
export interface TimelineEvent {
  /** Уникальный идентификатор события */
  id: string;
  /** Тип события */
  type: TimelineEventType;
  /** Название события */
  title: string;
  /** Описание */
  description: string;
  /** Время события */
  timestamp: Date;
  /** Источник события */
  source: string;
  /** Субъект события */
  actor?: Actor;
  /** Затронутые объекты */
  targets?: string[];
  /** Связанные IOC */
  iocs?: IOC[];
  /** Связанные шаги playbook */
  playbookSteps?: string[];
  /** Метки */
  tags?: string[];
  /** Важность события */
  significance: 'low' | 'medium' | 'high' | 'critical';
  /** Проверено аналитиком */
  verified: boolean;
  /** Проверил */
  verifiedBy?: string;
  /** Время проверки */
  verifiedAt?: Date;
}

/**
 * Запись цепочки хранения улик
 */
export interface ChainOfCustodyRecord {
  /** Уникальный идентификатор записи */
  id: string;
  /** Идентификатор улики */
  evidenceId: string;
  /** Тип действия */
  action: 'collected' | 'transferred' | 'stored' | 'analyzed' | 'returned' | 'destroyed';
  /** Кто выполнил действие */
  performedBy: Actor;
  /** Время действия */
  timestamp: Date;
  /** Описание действия */
  description: string;
  /** Местоположение */
  location?: string;
  /** Причина действия */
  reason?: string;
  /** Подпись (для юридической силы) */
  signature?: string;
  /** Свидетели */
  witnesses?: Actor[];
  /** Метод передачи */
  transferMethod?: string;
  /** Условия хранения */
  storageConditions?: string;
  /** Хэш для целостности */
  integrityHash?: string;
}

/**
 * Улика (Evidence)
 */
export interface Evidence {
  /** Уникальный идентификатор */
  id: string;
  /** Тип улики */
  type: string;
  /** Название */
  name: string;
  /** Описание */
  description: string;
  /** Категория */
  category: EvidenceCategory;
  /** Путь к файлу/данным */
  location: string;
  /** Размер */
  size?: number;
  /** Хэш */
  hash?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
  /** Время сбора */
  collectedAt: Date;
  /** Кто собрал */
  collectedBy: Actor;
  /** Контекст сбора */
  collectionContext: string;
  /** Связанный инцидент */
  incidentId: string;
  /** Статус цепочки хранения */
  custodyStatus: ChainOfCustodyStatus;
  /** История цепочки хранения */
  custodyHistory: ChainOfCustodyRecord[];
  /** Срок хранения */
  retentionUntil?: Date;
  /** Ограничения доступа */
  accessRestrictions?: string[];
  /** Юридические ограничения */
  legalHold?: boolean;
  /** Теги */
  tags?: string[];
}

/**
 * Категория улики
 */
export enum EvidenceCategory {
  DIGITAL_FILE = 'digital_file',
  LOG_FILE = 'log_file',
  MEMORY_DUMP = 'memory_dump',
  DISK_IMAGE = 'disk_image',
  NETWORK_CAPTURE = 'network_capture',
  SCREENSHOT = 'screenshot',
  DOCUMENT = 'document',
  EMAIL = 'email',
  CHAT_LOG = 'chat_log',
  DATABASE_RECORD = 'database_record',
  CONFIGURATION_FILE = 'configuration_file',
  MALWARE_SAMPLE = 'malware_sample',
  OTHER = 'other'
}

/**
 * Шаблон коммуникации
 */
export interface CommunicationTemplate {
  /** Уникальный идентификатор шаблона */
  id: string;
  /** Название шаблона */
  name: string;
  /** Описание */
  description: string;
  /** Тип стейкхолдера */
  stakeholderType: StakeholderType;
  /** Канал коммуникации */
  channel: CommunicationChannel;
  /** Тема сообщения */
  subject: string;
  /** Тело сообщения (с поддержкой переменных) */
  body: string;
  /** Приоритет */
  priority: IncidentPriority;
  /** Переменные для подстановки */
  variables: string[];
  /** Требует одобрения */
  requiresApproval: boolean;
  /** Автоматическая отправка */
  automatic: boolean;
  /** Условия отправки */
  conditions?: PlaybookCondition[];
  /** Вложения */
  attachments?: string[];
  /** Язык */
  language: string;
  /** Версия шаблона */
  version: string;
}

/**
 * Настройки внешних интеграций
 */
export interface IntegrationConfig {
  /** Тип интеграции */
  type: IntegrationType;
  /** Название интеграции */
  name: string;
  /** URL API */
  apiUrl: string;
  /** API ключ */
  apiKey?: string;
  /** API секрет */
  apiSecret?: string;
  /** Токен доступа */
  accessToken?: string;
  /** Токен обновления */
  refreshToken?: string;
  /** Webhook URL */
  webhookUrl?: string;
  /** Webhook секрет */
  webhookSecret?: string;
  /** Таймаут запросов (мс) */
  timeout?: number;
  /** Количество попыток */
  retryCount?: number;
  /** Включена ли интеграция */
  enabled: boolean;
  /** Дополнительные настройки */
  settings?: Record<string, unknown>;
}

/**
 * Типы интеграций
 */
export enum IntegrationType {
  SLACK = 'slack',
  PAGERDUTY = 'pagerduty',
  JIRA = 'jira',
  SERVICENOW = 'servicenow',
  EMAIL = 'email',
  WEBHOOK = 'webhook',
  CUSTOM = 'custom'
}

/**
 * Полный объект инцидента
 */
export interface Incident extends UniqueId {
  /** Номер инцидента (для отображения) */
  incidentNumber: string;
  /** Текущая стадия жизненного цикла */
  lifecycleStage: IncidentLifecycleStage;
  /** Категория */
  category: IncidentCategory;
  /** Подкатегория */
  subCategory?: string;
  /** Серьезность */
  severity: IncidentSeverity;
  /** Приоритет */
  priority: IncidentPriority;
  /** Оценка серьезности */
  severityScore?: SeverityScore;
  /** Статус инцидента */
  status: IncidentStatus;
  /** Заголовок */
  title: string;
  /** Описание */
  description: string;
  /** Детали инцидента */
  details: IncidentDetails;
  /** Владелец инцидента */
  owner?: Actor;
  /** Назначенные исполнители */
  assignees: Actor[];
  /** Активный playbook */
  activePlaybook?: PlaybookExecution;
  /** Временная шкала событий */
  timeline: TimelineEvent[];
  /** Собранные улики */
  evidence: Evidence[];
  /** Предпринятые действия сдерживания */
  containmentActions: ContainmentActionRecord[];
  /** Уведомленные стейкхолдеры */
  stakeholderNotifications: StakeholderNotification[];
  /** Связанные IOC */
  iocs: IOC[];
  /** MITRE ATT&CK маппинг */
  mitreMapping?: MITREAttackMapping;
  /** Метрики инцидента */
  metrics: IncidentMetrics;
  /** Теги */
  tags: string[];
  /** Пользовательские поля */
  customFields?: Record<string, unknown>;
  /** Время обнаружения */
  detectedAt: Date;
  /** Время начала реагирования */
  responseStartedAt?: Date;
  /** время сдерживания */
  containedAt?: Date;
  /** Время устранения */
  eradicatedAt?: Date;
  /** Время восстановления */
  recoveredAt?: Date;
  /** Время закрытия */
  closedAt?: Date;
  /** Отчет после инцидента */
  postIncidentReview?: PostIncidentReview;
}

/**
 * Статус инцидента
 */
export enum IncidentStatus {
  /** Новый инцидент */
  NEW = 'new',
  /** В работе */
  IN_PROGRESS = 'in_progress',
  /** Ожидает подтверждения */
  PENDING_VERIFICATION = 'pending_verification',
  /** Ожидает действий третьей стороны */
  PENDING_EXTERNAL = 'pending_external',
  /** Под наблюдением */
  MONITORING = 'monitoring',
  /** Решен */
  RESOLVED = 'resolved',
  /** Закрыт */
  CLOSED = 'closed'
}

/**
 * Выполнение playbook
 */
export interface PlaybookExecution extends UniqueId {
  /** Идентификатор инцидента */
  incidentId: string;
  /** Конфигурация playbook */
  configuration: PlaybookConfiguration;
  /** Текущий шаг */
  currentStepId?: string;
  /** Выполненные шаги */
  completedSteps: string[];
  /** Все шаги с результатами */
  allSteps: PlaybookStep[];
  /** Статус выполнения */
  status: 'running' | 'paused' | 'completed' | 'failed' | 'rolled_back';
  /** Прогресс (0-100) */
  progress: number;
  /** Время начала */
  startedAt: Date;
  /** Время завершения */
  completedAt?: Date;
  /** Кто запустил */
  initiatedBy: string;
  /** Ошибки выполнения */
  errors?: string[];
  /** Артефакты выполнения */
  artifacts: PlaybookArtifact[];
  /** История изменений статуса */
  statusHistory: PlaybookStatusChange[];
}

/**
 * Изменение статуса playbook
 */
export interface PlaybookStatusChange {
  /** Предыдущий статус */
  previousStatus: PlaybookExecution['status'];
  /** Новый статус */
  newStatus: PlaybookExecution['status'];
  /** Причина изменения */
  reason?: string;
  /** Кто изменил */
  changedBy: string;
  /** Время изменения */
  timestamp: Date;
}

/**
 * Запись действия сдерживания
 */
export interface ContainmentActionRecord {
  /** Уникальный идентификатор */
  id: string;
  /** Тип действия */
  type: ContainmentActionType;
  /** Название */
  name: string;
  /** Описание */
  description: string;
  /** Цель действия */
  target: string;
  /** Статус выполнения */
  status: 'pending' | 'executing' | 'completed' | 'failed' | 'rolled_back';
  /** Кто выполнил */
  executedBy: string;
  /** Кто одобрил */
  approvedBy?: string;
  /** Время выполнения */
  executedAt: Date;
  /** Результат */
  result?: {
    success: boolean;
    message?: string;
    details?: Record<string, unknown>;
  };
  /** Rollback информация */
  rollback?: {
    available: boolean;
    executed: boolean;
    executedAt?: Date;
    result?: string;
  };
  /** Воздействие на бизнес */
  businessImpact?: string;
  /** Длительность (мс) */
  durationMs?: number;
}

/**
 * Уведомление стейкхолдера
 */
export interface StakeholderNotification {
  /** Уникальный идентификатор */
  id: string;
  /** Тип стейкхолдера */
  stakeholderType: StakeholderType;
  /** Канал коммуникации */
  channel: CommunicationChannel;
  /** Использованный шаблон */
  templateId: string;
  /** Тема сообщения */
  subject: string;
  /** Тело сообщения */
  body: string;
  /** Получатели */
  recipients: string[];
  /** Статус отправки */
  status: 'pending' | 'sent' | 'delivered' | 'read' | 'failed';
  /** Время отправки */
  sentAt?: Date;
  /** Время доставки */
  deliveredAt?: Date;
  /** Время прочтения */
  readAt?: Date;
  /** Ошибки */
  errors?: string[];
  /** Ответы */
  responses?: NotificationResponse[];
  /** Кто отправил */
  sentBy: string;
}

/**
 * Ответ на уведомление
 */
export interface NotificationResponse {
  /** От кого */
  from: string;
  /** Время ответа */
  timestamp: Date;
  /** Содержание ответа */
  content: string;
  /** Тип ответа */
  type: 'acknowledgment' | 'question' | 'action_required' | 'other';
}

/**
 * MITRE ATT&CK маппинг
 */
export interface MITREAttackMapping {
  /** Тактики */
  tactics: MITREAttackTactic[];
  /** Техники */
  techniques: MITRETechnique[];
  /** Программное обеспечение */
  software?: MITRESoftware[];
  /** Группы угроз */
  groups?: MITREGroup[];
  /** Кампании */
  campaigns?: MITRECampaign[];
}

/**
 * MITRE техника
 */
export interface MITRETechnique {
  /** ID техники */
  id: string;
  /** Название */
  name: string;
  /** Подтехники */
  subTechniques?: string[];
  /** Описание */
  description?: string;
  /** URL */
  url?: string;
}

/**
 * MITRE программное обеспечение
 */
export interface MITRESoftware {
  /** ID */
  id: string;
  /** Название */
  name: string;
  /** Тип */
  type: 'malware' | 'tool';
  /** Описание */
  description?: string;
}

/**
 * MITRE группа
 */
export interface MITREGroup {
  /** ID */
  id: string;
  /** Название */
  name: string;
  /** Описание */
  description?: string;
  /** Связанные техники */
  techniques?: string[];
}

/**
 * MITRE кампания
 */
export interface MITRECampaign {
  /** ID */
  id: string;
  /** Название */
  name: string;
  /** Описание */
  description?: string;
  /** Цели */
  objectives?: string[];
}

/**
 * Метрики инцидента
 */
export interface IncidentMetrics {
  /** Время обнаружения (мс от начала инцидента) */
  timeToDetect?: number;
  /** Время реагирования (мс от обнаружения до начала работ) */
  timeToRespond?: number;
  /** Время сдерживания (мс от начала работ до сдерживания) */
  timeToContain?: number;
  /** Время устранения (мс от сдерживания до устранения) */
  timeToEradicate?: number;
  /** Время восстановления (мс от устранения до восстановления) */
  timeToRecover?: number;
  /** Общее время инцидента (мс) */
  totalDuration?: number;
  /** Количество затронутых систем */
  affectedSystemsCount: number;
  /** Количество затронутых пользователей */
  affectedUsersCount: number;
  /** Объем затронутых данных (байты) */
  affectedDataVolume?: number;
  /** Количество выполненных шагов playbook */
  playbookStepsCompleted: number;
  /** Количество автоматических действий */
  automatedActionsCount: number;
  /** Количество ручных действий */
  manualActionsCount: number;
  /** Количество уведомленных стейкхолдеров */
  stakeholdersNotified: number;
  /** Количество собранных улик */
  evidenceCollected: number;
  /** Оценка воздействия на бизнес */
  businessImpactEstimate?: BusinessImpactEstimate;
}

/**
 * Оценка воздействия на бизнес
 */
export interface BusinessImpactEstimate {
  /** Финансовые потери (USD) */
  financialLoss?: number;
  /** Простой систем (часы) */
  downtimeHours?: number;
  /** Затронутые бизнес-процессы */
  affectedProcesses?: string[];
  /** Репутационный ущерб */
  reputationalDamage?: 'low' | 'medium' | 'high' | 'critical';
  /** Регуляторные последствия */
  regulatoryImpact?: string[];
  /** Юридические последствия */
  legalImpact?: string[];
  /** Операционное воздействие */
  operationalImpact?: string;
}

/**
 * Отчет после инцидента (Post-Incident Review)
 */
export interface PostIncidentReview {
  /** Уникальный идентификатор */
  id: string;
  /** Идентификатор инцидента */
  incidentId: string;
  /** Дата проведения анализа */
  reviewDate: Date;
  /** Участники анализа */
  participants: Actor[];
  /** Резюме инцидента */
  incidentSummary: string;
  /** Хронология событий */
  timeline: TimelineSummary;
  /** Что сработало хорошо */
  whatWentWell: string[];
  /** Что можно улучшить */
  whatCouldBeImproved: string[];
  /** Корневые причины */
  rootCauses: RootCause[];
  /** Извлеченные уроки */
  lessonsLearned: LessonLearned[];
  /** Рекомендации */
  recommendations: Recommendation[];
  /** План действий */
  actionItems: ActionItem[];
  /** Метрики эффективности */
  effectivenessMetrics: EffectivenessMetrics;
  /** Обновления playbook */
  playbookUpdates?: PlaybookUpdate[];
  /** Статус завершения */
  status: 'draft' | 'in_review' | 'approved' | 'published';
  /** Кто составил */
  authoredBy: Actor;
  /** Кто утвердил */
  approvedBy?: Actor;
  /** Дата утверждения */
  approvedAt?: Date;
}

/**
 * Сводка временной шкалы
 */
export interface TimelineSummary {
  /** Первое событие */
  firstEvent?: TimelineEvent;
  /** Последнее событие */
  lastEvent?: TimelineEvent;
  /** Ключевые события */
  keyEvents: TimelineEvent[];
  /** Общая длительность (мс) */
  totalDuration?: number;
  /** Визуализация (ASCII/мермайд) */
  visualization?: string;
}

/**
 * Корневая причина
 */
export interface RootCause {
  /** Описание причины */
  description: string;
  /** Категория */
  category: string;
  /** Метод анализа (5 Why, Fishbone, etc.) */
  analysisMethod: string;
  /** Доказательства */
  evidence: string[];
  /** Уровень уверенности (0-100) */
  confidenceLevel: number;
}

/**
 * Извлеченный урок
 */
export interface LessonLearned {
  /** Описание урока */
  description: string;
  /** Категория */
  category: string;
  /** Применимость */
  applicability: string[];
  /** Приоритет внедрения */
  priority: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Рекомендация
 */
export interface Recommendation {
  /** Описание рекомендации */
  description: string;
  /** Обоснование */
  rationale: string;
  /** Приоритет */
  priority: 'low' | 'medium' | 'high' | 'critical';
  /** Сложность реализации */
  implementationComplexity: 'low' | 'medium' | 'high';
  /** Ожидаемый эффект */
  expectedImpact: string;
  /** Необходимые ресурсы */
  requiredResources?: string[];
}

/**
 * Элемент плана действий
 */
export interface ActionItem {
  /** Уникальный идентификатор */
  id: string;
  /** Описание действия */
  description: string;
  /** Связанная рекомендация */
  recommendationId?: string;
  /** Приоритет */
  priority: 'low' | 'medium' | 'high' | 'critical';
  /** Назначенный исполнитель */
  assignee?: Actor;
  /** Дедлайн */
  dueDate?: Date;
  /** Статус */
  status: 'pending' | 'in_progress' | 'completed' | 'blocked' | 'cancelled';
  /** Прогресс (0-100) */
  progress: number;
  /** Зависимости */
  dependencies?: string[];
  /** Дата завершения */
  completedAt?: Date;
}

/**
 * Метрики эффективности
 */
export interface EffectivenessMetrics {
  /** Общая оценка эффективности (0-100) */
  overallEffectiveness: number;
  /** Эффективность обнаружения */
  detectionEffectiveness: number;
  /** Эффективность реагирования */
  responseEffectiveness: number;
  /** Эффективность сдерживания */
  containmentEffectiveness: number;
  /** Эффективность устранения */
  eradicationEffectiveness: number;
  /** Эффективность восстановления */
  recoveryEffectiveness: number;
  /** Эффективность коммуникации */
  communicationEffectiveness: number;
  /** SLA compliance */
  slaCompliance: {
    /** Время реагирования в рамках SLA */
    responseTimeMet: boolean;
    /** Время сдерживания в рамках SLA */
    containmentTimeMet: boolean;
    /** Время восстановления в рамках SLA */
    recoveryTimeMet: boolean;
  };
}

/**
 * Обновление playbook
 */
export interface PlaybookUpdate {
  /** Идентификатор playbook */
  playbookId: string;
  /** Тип обновления */
  updateType: 'step_added' | 'step_removed' | 'step_modified' | 'condition_changed' | 'version_bump';
  /** Описание изменения */
  description: string;
  /** Обоснование */
  rationale: string;
  /** Дата обновления */
  updatedAt: Date;
}

/**
 * Конфигурация системы Incident Response
 */
export interface IncidentResponseConfig {
  /** Настройки классификации */
  classification: ClassificationConfig;
  /** Настройки playbook */
  playbook: PlaybookConfig;
  /** Настройки форензики */
  forensics: ForensicsConfig;
  /** Настройки улик */
  evidence: EvidenceConfig;
  /** Настройки сдерживания */
  containment: ContainmentConfig;
  /** Настройки коммуникации */
  communication: CommunicationConfig;
  /** Настройки интеграций */
  integrations: IntegrationConfig[];
  /** Настройки эскалации */
  escalation: EscalationConfig;
  /** Настройки SLA */
  sla: SLAConfig;
  /** Настройки аудита */
  audit: AuditConfig;
}

/**
 * Конфигурация классификации
 */
export interface ClassificationConfig {
  /** Веса факторов серьезности */
  severityWeights: {
    businessImpact: number;
    urgency: number;
    complexity: number;
  };
  /** Пороги серьезности */
  severityThresholds: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** Авто-классификация включена */
  autoClassificationEnabled: boolean;
  /** Требует подтверждения классификации */
  requiresConfirmation: boolean;
}

/**
 * Конфигурация playbook
 */
export interface PlaybookConfig {
  /** Автоматический запуск playbook */
  autoStartEnabled: boolean;
  /** Требует подтверждения для критических действий */
  requiresApprovalForCritical: boolean;
  /** Таймаут шага по умолчанию (мс) */
  defaultStepTimeout: number;
  /** Количество попыток по умолчанию */
  defaultRetryCount: number;
  /** Параллельное выполнение шагов */
  allowParallelSteps: boolean;
  /** Rollback при ошибке */
  autoRollbackOnError: boolean;
}

/**
 * Конфигурация форензики
 */
export interface ForensicsConfig {
  /** Автоматический сбор форензики */
  autoCollectionEnabled: boolean;
  /** Типы данных для сбора по умолчанию */
  defaultDataTypes: ForensicsDataType[];
  /** Максимальный размер собираемых данных (байты) */
  maxCollectionSize: number;
  /** Сжатие данных */
  compressData: boolean;
  /** Шифрование данных */
  encryptData: boolean;
  /** Хранилище форензики данных */
  storageLocation: string;
  /** Срок хранения (дни) */
  retentionDays: number;
}

/**
 * Конфигурация улик
 */
export interface EvidenceConfig {
  /** Автоматическое создание записей chain of custody */
  autoChainOfCustody: boolean;
  /** Требуемые хэши для улик */
  requiredHashes: ('md5' | 'sha1' | 'sha256')[];
  /** Хранилище улик */
  storageLocation: string;
  /** Срок хранения по умолчанию (дни) */
  defaultRetentionDays: number;
  /** Требования к доступу */
  accessRequirements: string[];
}

/**
 * Конфигурация сдерживания
 */
export interface ContainmentConfig {
  /** Автоматическое сдерживание включено */
  autoContainmentEnabled: boolean;
  /** Действия, требующие одобрения */
  actionsRequiringApproval: ContainmentActionType[];
  /** Максимальное время сдерживания (мс) */
  maxContainmentDuration: number;
  /** Rollback сдерживания при ложной тревоге */
  autoRollbackOnFalsePositive: boolean;
  /** Уведомление о сдерживании */
  notifyOnContainment: boolean;
}

/**
 * Конфигурация коммуникации
 */
export interface CommunicationConfig {
  /** Шаблоны коммуникации */
  templates: CommunicationTemplate[];
  /** Каналы по умолчанию для типов стейкхолдеров */
  defaultChannels: Record<StakeholderType, CommunicationChannel[]>;
  /** Эскалация при отсутствии ответа */
  escalationOnNoResponse: boolean;
  /** Время ожидания ответа (мс) */
  responseTimeout: number;
  /** Частота обновлений (мс) */
  updateFrequency: number;
}

/**
 * Конфигурация эскалации
 */
export interface EscalationConfig {
  /** Правила эскалации */
  rules: EscalationRule[];
  /** Автоматическая эскалация включена */
  autoEscalationEnabled: boolean;
  /** Уровни эскалации */
  levels: EscalationLevel[];
}

/**
 * Правило эскалации
 */
export interface EscalationRule {
  /** Уникальный идентификатор */
  id: string;
  /** Название */
  name: string;
  /** Условия */
  conditions: PlaybookCondition[];
  /** Действия при эскалации */
  actions: EscalationAction[];
  /** Задержка перед эскалацией (мс) */
  delayBeforeEscation: number;
}

/**
 * Действие эскалации
 */
export interface EscalationAction {
  /** Тип действия */
  type: 'notify' | 'assign' | 'change_priority' | 'create_ticket';
  /** Параметры */
  parameters: Record<string, unknown>;
}

/**
 * Уровень эскалации
 */
export interface EscalationLevel {
  /** Уровень */
  level: number;
  /** Название */
  name: string;
  /** Описание */
  description: string;
  /** Ответственные */
  responders: Actor[];
  /** Время реакции (мс) */
  responseTime: number;
}

/**
 * Конфигурация SLA
 */
export interface SLAConfig {
  /** SLA для уровней серьезности */
  bySeverity: Record<IncidentSeverity, SLATargets>;
  /** Часы работы (для бизнес-часов SLA) */
  businessHours: {
    start: string;
    end: string;
    timezone: string;
    excludeWeekends: boolean;
    holidays: string[];
  };
  /** Отслеживание нарушений SLA */
  trackBreaches: boolean;
  /** Уведомление о приближении к нарушению SLA */
  notifyOnApproachingBreach: boolean;
  /** Время предупреждения (мс) */
  breachWarningTime: number;
}

/**
 * Цели SLA
 */
export interface SLATargets {
  /** Время реагирования (мс) */
  responseTime: number;
  /** Время сдерживания (мс) */
  containmentTime: number;
  /** Время устранения (мс) */
  eradicationTime: number;
  /** Время восстановления (мс) */
  recoveryTime: number;
  /** Время обновления статуса (мс) */
  statusUpdateTime: number;
}

/**
 * Конфигурация аудита
 */
export interface AuditConfig {
  /** Включить аудит */
  enabled: boolean;
  /** События для аудита */
  eventsToAudit: AuditEvent[];
  /** Хранилище аудита */
  storageLocation: string;
  /** Срок хранения (дни) */
  retentionDays: number;
  /** Шифрование логов аудита */
  encryptLogs: boolean;
  /** Немедленная запись (без буферизации) */
  immediateWrite: boolean;
}

/**
 * События аудита
 */
export enum AuditEvent {
  INCIDENT_CREATED = 'incident_created',
  INCIDENT_UPDATED = 'incident_updated',
  INCIDENT_STATUS_CHANGED = 'incident_status_changed',
  PLAYBOOK_STARTED = 'playbook_started',
  PLAYBOOK_STEP_EXECUTED = 'playbook_step_executed',
  CONTAINMENT_ACTION_EXECUTED = 'containment_action_executed',
  EVIDENCE_COLLECTED = 'evidence_collected',
  EVIDENCE_ACCESSED = 'evidence_accessed',
  STAKEHOLDER_NOTIFIED = 'stakeholder_notified',
  CONFIGURATION_CHANGED = 'configuration_changed',
  ACCESS_GRANTED = 'access_granted',
  ACCESS_DENIED = 'access_denied'
}

/**
 * Результат поиска инцидентов
 */
export interface IncidentSearchResult {
  /** Найденные инциденты */
  incidents: Incident[];
  /** Общее количество */
  total: number;
  /** Страница */
  page: number;
  /** Размер страницы */
  pageSize: number;
  /** Фильтры */
  filters?: IncidentFilters;
  /** Сортировка */
  sort?: IncidentSort;
}

// ============================================================================
// ДОПОЛНИТЕЛЬНЫЕ ИНТЕРФЕЙСЫ ДЛЯ INCIDENT CLASSIFIER
// ============================================================================

/**
 * Контекст классификации инцидента
 */
export interface ClassificationContext {
  /** Детали инцидента */
  details: IncidentDetails;
  /** Затронутые системы */
  affectedSystems: Array<{
    id: string;
    name: string;
    type: string;
    criticality: 'low' | 'medium' | 'high' | 'critical';
    hasSensitiveData: boolean;
    isPublicFacing: boolean;
  }>;
  /** Затронутые пользователи */
  affectedUsers: Array<{
    id: string;
    username: string;
    role: string;
    accessLevel: string;
    hasSensitiveDataAccess: boolean;
  }>;
  /** Затронутые данные */
  affectedData: Array<{
    type: string;
    classification: DataClassification;
    volume?: number;
    recordCount?: number;
  }>;
  /** Время обнаружения */
  detectedAt: Date;
  /** Индикаторы компрометации */
  iocs?: IOC[];
  /** MITRE техники */
  mitreTechniques?: string[];
  /** Источник инцидента */
  source?: string;
  /** Вектор атаки */
  attackVector?: string;
}

/**
 * Результат классификации
 */
export interface ClassificationResult {
  /** Категория инцидента */
  category: IncidentCategory;
  /** Подкатегория */
  subCategory?: string;
  /** Серьезность */
  severity: IncidentSeverity;
  /** Приоритет */
  priority: IncidentPriority;
  /** Оценка серьезности */
  severityScore: SeverityScore;
  /** Влияющие факторы */
  influencingFactors: ClassificationFactor[];
  /** Обоснование классификации */
  rationale: string;
  /** Рекомендуемые playbook */
  recommendedPlaybooks: string[];
  /** Требуется эскалация */
  requiresEscalation: boolean;
  /** SLA цели */
  slaTargets?: SLATargets;
}

/**
 * Фактор классификации
 */
export interface ClassificationFactor {
  /** Название фактора */
  name: string;
  /** Описание */
  description: string;
  /** Категория фактора */
  category: 'business_impact' | 'urgency' | 'complexity' | 'threat_intel' | 'context';
  /** Вес фактора (0-1) */
  weight: number;
  /** Значение фактора (0-100) */
  value: number;
  /** Взвешенный балл */
  weightedScore: number;
  /** Источники данных для фактора */
  dataSources: string[];
  /** Уверенность в факторе (0-100) */
  confidence: number;
}

// ============================================================================
// ДОПОЛНИТЕЛЬНЫЕ ИНТЕРФЕЙСЫ ДЛЯ PLAYBOOK ENGINE
// ============================================================================

/**
 * Конфигурация Playbook Engine
 */
export interface PlaybookEngineConfig {
  /** Таймаут шага по умолчанию (мс) */
  defaultStepTimeout: number;
  /** Количество попыток по умолчанию */
  defaultRetryCount: number;
  /** Интервал между попытками по умолчанию (мс) */
  defaultRetryInterval: number;
  /** Разрешить параллельное выполнение шагов */
  allowParallelSteps: boolean;
  /** Автоматический rollback при ошибке */
  autoRollbackOnError: boolean;
  /** Требует одобрения для критических действий */
  requiresApprovalForCritical: boolean;
  /** Логирование */
  enableLogging: boolean;
  /** Максимальное количество одновременных playbook */
  maxConcurrentPlaybooks: number;
  /** Хранилище состояний */
  stateStorage: 'memory' | 'redis' | 'database';
}

/**
 * Контекст выполнения Playbook
 */
export interface PlaybookExecutionContext {
  /** ID инцидента */
  incidentId: string;
  /** Инцидент */
  incident: Incident;
  /** ID выполнения playbook */
  executionId: string;
  /** Конфигурация playbook */
  playbook: PlaybookConfiguration;
  /** Текущий шаг */
  currentStep?: PlaybookStep;
  /** Выполненные шаги */
  completedSteps: PlaybookStep[];
  /** Ожидающие шаги */
  pendingSteps: PlaybookStep[];
  /** Проваленные шаги */
  failedSteps: PlaybookStep[];
  /** Пропущенные шаги */
  skippedSteps: PlaybookStep[];
  /** Переменные контекста */
  variables: Record<string, unknown>;
  /** Результат выполнения */
  result?: PlaybookExecutionResult;
  /** Кто инициировал */
  initiatedBy: Actor;
  /** Время начала */
  startedAt: Date;
  /** Время последнего обновления */
  lastUpdatedAt: Date;
  /** Статус выполнения */
  status: 'running' | 'paused' | 'completed' | 'failed' | 'rolled_back';
  /** Прогресс (0-100) */
  progress: number;
  /** Ошибки */
  errors: string[];
  /** Журнал выполнения */
  executionLog: PlaybookExecutionLogEntry[];
}

/**
 * Результат выполнения Playbook
 */
export interface PlaybookExecutionResult {
  /** Успешно ли выполнено */
  success: boolean;
  /** Выходные данные */
  output?: Record<string, unknown>;
  /** Сообщение */
  message?: string;
  /** Артефакты */
  artifacts: PlaybookArtifact[];
  /** Метрики выполнения */
  metrics: {
    /** Время выполнения (мс) */
    durationMs: number;
    /** Количество выполненных шагов */
    stepsCompleted: number;
    /** Количество проваленных шагов */
    stepsFailed: number;
    /** Количество пропущенных шагов */
    stepsSkipped: number;
    /** Использованные ресурсы */
    resourcesUsed?: string[];
  };
}

/**
 * Запись журнала выполнения Playbook
 */
export interface PlaybookExecutionLogEntry {
  /** Временная метка */
  timestamp: Date;
  /** Уровень лога */
  level: 'info' | 'warn' | 'error' | 'debug';
  /** Сообщение */
  message: string;
  /** ID шага */
  stepId?: string;
  /** Детали */
  details?: Record<string, unknown>;
}

// ============================================================================
// ДОПОЛНИТЕЛЬНЫЕ ИНТЕРФЕЙСЫ ДЛЯ FORENSICS COLLECTOR
// ============================================================================

/**
 * Контекст сбора форензика данных
 */
export interface ForensicsCollectionContext {
  /** Инцидент */
  incident: Incident;
  /** Типы данных для сбора */
  dataTypes: ForensicsDataType[];
  /** Целевые системы */
  targetSystems: string[];
  /** Кто инициировал сбор */
  initiatedBy: Actor;
  /** Время инициации */
  initiatedAt: Date;
  /** Параметры сбора */
  collectionParams?: {
    /** Сжатие данных */
    compressData: boolean;
    /** Шифрование данных */
    encryptData: boolean;
    /** Ключ шифрования */
    encryptionKey?: string;
    /** Сохранять оригинальные имена файлов */
    preserveFilenames: boolean;
    /** Вычисляемые хэши */
    hashAlgorithms: ('md5' | 'sha1' | 'sha256')[];
  };
  /** Прогресс сбора */
  progress: number;
  /** Собранные данные */
  collectedData: CollectionResult[];
  /** Ошибки сбора */
  errors: string[];
}

/**
 * Результат сбора данных
 */
export interface CollectionResult {
  /** Тип собранных данных */
  dataType: ForensicsDataType;
  /** Успешно ли собрано */
  success: boolean;
  /** Путь к собранным данным */
  location?: string;
  /** Размер данных (байты) */
  size?: number;
  /** Хэши для целостности */
  hashes: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
  /** Время сбора */
  collectedAt: Date;
  /** Кто собрал */
  collectedBy: Actor;
  /** Метод сбора */
  collectionMethod: string;
  /** Ошибки */
  errors?: string[];
  /** Метаданные */
  metadata?: Record<string, unknown>;
}

// ============================================================================
// ДОПОЛНИТЕЛЬНЫЕ ИНТЕРФЕЙСЫ ДЛЯ TIMELINE RECONSTRUCTOR
// ============================================================================

/**
 * Источник событий для временной шкалы
 */
export interface EventSource {
  /** Уникальный идентификатор источника */
  id: string;
  /** Название источника */
  name: string;
  /** Тип источника */
  type: 'log' | 'siem' | 'edr' | 'firewall' | 'ids' | 'manual' | 'api' | 'webhook';
  /** URL или путь к источнику */
  url?: string;
  /** Параметры подключения */
  connectionParams?: Record<string, unknown>;
  /** Формат данных */
  dataFormat: 'json' | 'syslog' | 'cef' | 'leef' | 'csv' | 'text';
  /** Парсер данных */
  parser?: string;
  /** Фильтры событий */
  eventFilters?: Array<{
    field: string;
    operator: 'equals' | 'contains' | 'regex' | 'gt' | 'lt';
    value: unknown;
  }>;
  /** Маппинг полей */
  fieldMapping?: Record<string, string>;
  /** Включен ли источник */
  enabled: boolean;
  /** Интервал опроса (мс) */
  pollingInterval?: number;
  /** Последнее событие */
  lastEventTimestamp?: Date;
  /** Статистика источника */
  stats?: {
    eventsProcessed: number;
    errors: number;
    lastError?: string;
  };
}

// ============================================================================
// ДОПОЛНИТЕЛЬНЫЕ ИНТЕРФЕЙСЫ ДЛЯ INCIDENT REPORTER
// ============================================================================

/**
 * Конфигурация Incident Reporter
 */
export interface IncidentReporterConfig {
  /** Путь к хранилищу отчетов */
  reportStoragePath: string;
  /** Форматы отчетов */
  outputFormats: ('pdf' | 'html' | 'markdown' | 'json' | 'docx')[];
  /** Шаблоны отчетов */
  templates: {
    incidentDetail?: string;
    executiveSummary?: string;
    technicalAnalysis?: string;
    complianceReport?: string;
    lessonsLearned?: string;
  };
  /** Настройки PDF */
  pdfSettings?: {
    pageSize: 'A4' | 'Letter' | 'Legal';
    orientation: 'portrait' | 'landscape';
    includeHeader: boolean;
    includeFooter: boolean;
    includePageNumbers: boolean;
  };
  /** Логирование */
  enableLogging: boolean;
  /** Максимальный размер отчета (МБ) */
  maxReportSizeMB: number;
  /** Включить приложения */
  includeAttachments: boolean;
  /** Язык отчетов */
  defaultLanguage: string;
}

/**
 * Фильтры для поиска инцидентов
 */
export interface IncidentFilters {
  /** Статус */
  status?: IncidentStatus[];
  /** Категория */
  category?: IncidentCategory[];
  /** Серьезность */
  severity?: IncidentSeverity[];
  /** Приоритет */
  priority?: IncidentPriority[];
  /** Дата от */
  dateFrom?: Date;
  /** Дата до */
  dateTo?: Date;
  /** Владелец */
  owner?: string;
  /** Теги */
  tags?: string[];
  /** Поиск по тексту */
  searchText?: string;
}

/**
 * Сортировка инцидентов
 */
export interface IncidentSort {
  /** Поле для сортировки */
  field: keyof Incident;
  /** Порядок */
  order: 'asc' | 'desc';
}

/**
 * Дашборд метрик инцидентов
 */
export interface IncidentMetricsDashboard {
  /** Период отчета */
  period: {
    from: Date;
    to: Date;
  };
  /** Сводные метрики */
  summary: {
    /** Всего инцидентов */
    totalIncidents: number;
    /** Открытые инциденты */
    openIncidents: number;
    /** Закрытые инциденты */
    closedIncidents: number;
    /** Среднее время обнаружения (мс) */
    avgTimeToDetect: number;
    /** Среднее время реагирования (мс) */
    avgTimeToRespond: number;
    /** Среднее время сдерживания (мс) */
    avgTimeToContain: number;
    /** Среднее время восстановления (мс) */
    avgTimeToRecover: number;
    /** SLA compliance % */
    slaCompliance: number;
  };
  /** Инциденты по категориям */
  byCategory: Record<IncidentCategory, number>;
  /** Инциденты по серьезности */
  bySeverity: Record<IncidentSeverity, number>;
  /** Инциденты по времени (для графика) */
  overTime: TimeSeriesData[];
  /** Топ IOC */
  topIOCs: IOC[];
  /** Топ MITRE техник */
  topTechniques: MITRETechnique[];
  /** Эффективность playbook */
  playbookEffectiveness: PlaybookEffectiveness[];
}

/**
 * Временные ряды данных
 */
export interface TimeSeriesData {
  /** Метка времени */
  timestamp: Date;
  /** Значение */
  value: number;
  /** Метка */
  label?: string;
}

/**
 * Эффективность playbook
 */
export interface PlaybookEffectiveness {
  /** Идентификатор playbook */
  playbookId: string;
  /** Название */
  name: string;
  /** Количество выполнений */
  executionCount: number;
  /** Успешные выполнения (%) */
  successRate: number;
  /** Среднее время выполнения (мс) */
  avgExecutionTime: number;
  /** Среднее количество шагов */
  avgStepsCompleted: number;
  /** Количество rollback */
  rollbackCount: number;
}

