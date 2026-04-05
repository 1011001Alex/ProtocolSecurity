/**
 * ============================================================================
 * ТИПЫ И ИНТЕРФЕЙСЫ ДЛЯ СИСТЕМЫ УПРАВЛЕНИЯ СЕКРЕТАМИ
 * ============================================================================
 * 
 * Этот файл содержит все типы данных, интерфейсы и перечисления,
 * необходимые для работы системы управления секретами.
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

// ============================================================================
// ОСНОВНЫЕ ТИПЫ СЕКРЕТОВ
// ============================================================================

/**
 * Типы бэкендов для хранения секретов
 */
export enum SecretBackendType {
  /** HashiCorp Vault - enterprise-grade решение */
  VAULT = 'vault',
  /** AWS Secrets Manager - облачное решение Amazon */
  AWS_SECRETS_MANAGER = 'aws-secrets-manager',
  /** GCP Secret Manager - облачное решение Google */
  GCP_SECRET_MANAGER = 'gcp-secret-manager',
  /** Azure Key Vault - облачное решение Microsoft */
  AZURE_KEY_VAULT = 'azure-key-vault',
  /** Локальное хранилище (для разработки/тестирования) */
  LOCAL = 'local'
}

/**
 * Статус секрета в системе
 */
export enum SecretStatus {
  /** Секрет активен и готов к использованию */
  ACTIVE = 'active',
  /** Секрет ожидает активации (после ротации) */
  PENDING = 'pending',
  /** Секрет деактивирован, но не удалён */
  INACTIVE = 'inactive',
  /** Секрет помечен на удаление */
  DELETED = 'deleted',
  /** Секрет истёк (expired lease) */
  EXPIRED = 'expired',
  /** Секрет скомпрометирован */
  COMPROMISED = 'compromised'
}

/**
 * Уровни классификации секретов по чувствительности
 */
export enum SecretClassification {
  /** Публичные данные, не требующие защиты */
  PUBLIC = 'public',
  /** Внутренние данные, доступные сотрудникам */
  INTERNAL = 'internal',
  /** Конфиденциальные данные */
  CONFIDENTIAL = 'confidential',
  /** Строго секретные данные */
  SECRET = 'secret',
  /** Критически важные данные (top secret) */
  TOP_SECRET = 'top-secret'
}

/**
 * Типы операций с секретами для аудита
 */
export enum SecretOperation {
  /** Чтение секрета */
  READ = 'read',
  /** Создание нового секрета */
  CREATE = 'create',
  /** Обновление существующего секрета */
  UPDATE = 'update',
  /** Удаление секрета */
  DELETE = 'delete',
  /** Ротация секрета */
  ROTATE = 'rotate',
  /** Получение версии секрета */
  GET_VERSION = 'get_version',
  /** Откат к предыдущей версии */
  ROLLBACK = 'rollback',
  /** Продление lease */
  RENEW_LEASE = 'renew_lease',
  /** Возврат lease */
  REVOKE_LEASE = 'revoke_lease',
  /** Изменение политик доступа */
  UPDATE_POLICY = 'update_policy',
  /** Сканирование на утечки */
  SCAN = 'scan',
  /** Экспорт секрета */
  EXPORT = 'export',
  /** Импорт секрета */
  IMPORT = 'import'
}

/**
 * Результат операции с секретом
 */
export interface SecretOperationResult<T = unknown> {
  /** Успешно ли выполнена операция */
  success: boolean;
  /** Данные результата (если есть) */
  data?: T;
  /** Код ошибки (если произошла) */
  errorCode?: string;
  /** Сообщение об ошибке */
  errorMessage?: string;
  /** Время выполнения операции в мс */
  executionTimeMs?: number;
  /** ID операции для аудита */
  operationId: string;
  /** Версия секрета после операции */
  version?: number;
}

// ============================================================================
// ТИПЫ ДЛЯ ВЕРСИОНИРОВАНИЯ
// ============================================================================

/**
 * Информация о версии секрета
 */
export interface SecretVersion {
  /** Номер версии (начинается с 1) */
  version: number;
  /** Хеш содержимого версии */
  contentHash: string;
  /** Время создания версии */
  createdAt: Date;
  /** Создатель версии (user/service) */
  createdBy: string;
  /** Статус версии */
  status: SecretStatus;
  /** Причина создания версии (ротация, обновление, etc.) */
  reason?: string;
  /** Метаданные версии */
  metadata?: Record<string, unknown>;
  /** Время удаления версии (если удалена) */
  deletedAt?: Date;
  /** Кто удалил версию */
  deletedBy?: string;
}

/**
 * Данные для отката к предыдущей версии
 */
export interface RollbackInfo {
  /** Текущая версия */
  currentVersion: number;
  /** Целевая версия для отката */
  targetVersion: number;
  /** Время отката */
  rolledBackAt: Date;
  /** Кто выполнил откат */
  rolledBackBy: string;
  /** Причина отката */
  reason: string;
  /** Предыдущие версии (история) */
  previousVersions: number[];
}

// ============================================================================
// ТИПЫ ДЛЯ LEASE MANAGEMENT
// ============================================================================

/**
 * Информация о lease (аренде) секрета
 */
export interface SecretLease {
  /** Уникальный ID lease */
  leaseId: string;
  /** ID секрета */
  secretId: string;
  /** Кто получил lease */
  leasedBy: string;
  /** Время получения lease */
  leasedAt: Date;
  /** Время истечения lease */
  expiresAt: Date;
  /** Максимальное время lease (TTL) */
  maxTTL: number;
  /** Можно ли продлевать lease */
  renewable: boolean;
  /** Количество продлений */
  renewCount: number;
  /** Статус lease */
  status: 'active' | 'expired' | 'revoked' | 'renewed';
  /** Метаданные lease */
  metadata?: Record<string, unknown>;
}

/**
 * Конфигурация lease для секрета
 */
export interface LeaseConfig {
  /** Default TTL в секундах */
  defaultTTL: number;
  /** Максимальный TTL в секундах */
  maxTTL: number;
  /** Можно ли продлевать */
  renewable: boolean;
  /** Максимальное количество продлений */
  maxRenewals: number;
  /** Grace period перед истечением (сек) */
  gracePeriod: number;
  /** Автоматически отзывать при обнаружении аномалий */
  autoRevokeOnAnomaly: boolean;
}

// ============================================================================
// ТИПЫ ДЛЯ РОТАЦИИ СЕКРЕТОВ
// ============================================================================

/**
 * Конфигурация ротации секрета
 */
export interface RotationConfig {
  /** Включена ли автоматическая ротация */
  enabled: boolean;
  /** Интервал ротации в секундах */
  rotationInterval: number;
  /** Grace period в секундах (время на переход) */
  gracePeriod: number;
  /** Автоматически активировать новую версию */
  autoActivate: boolean;
  /** Уведомлять при ротации */
  notifyOnRotation: boolean;
  /** Сохранять историю версий */
  keepHistory: boolean;
  /** Количество версий для хранения */
  historyLimit: number;
  /** Минимальное время между ротациями */
  minRotationInterval: number;
}

/**
 * Статус процесса ротации
 */
export interface RotationStatus {
  /** ID секрета */
  secretId: string;
  /** Статус ротации */
  status: 'idle' | 'rotating' | 'completed' | 'failed' | 'pending';
  /** Текущая версия */
  currentVersion: number;
  /** Новая версия (если создаётся) */
  newVersion?: number;
  /** Время последней ротации */
  lastRotationAt?: Date;
  /** Время следующей ротации */
  nextRotationAt?: Date;
  /** Ошибка (если произошла) */
  error?: string;
  /** Прогресс ротации (0-100) */
  progress?: number;
}

// ============================================================================
// ТИПЫ ДЛЯ ДИНАМИЧЕСКИХ СЕКРЕТОВ
// ============================================================================

/**
 * Типы динамических секретов
 */
export enum DynamicSecretType {
  /** Учётные данные базы данных */
  DATABASE_CREDENTIALS = 'database_credentials',
  /** API ключи */
  API_KEY = 'api_key',
  /** OAuth токены */
  OAUTH_TOKEN = 'oauth_token',
  /** SSH ключи */
  SSH_KEY = 'ssh_key',
  /** TLS сертификаты */
  TLS_CERTIFICATE = 'tls_certificate',
  /** AWS временные credentials */
  AWS_TEMP_CREDENTIALS = 'aws_temp_credentials',
  /** Kubernetes service account */
  K8S_SERVICE_ACCOUNT = 'k8s_service_account',
  /** Пользовательский тип */
  CUSTOM = 'custom'
}

/**
 * Конфигурация динамического секрета
 */
export interface DynamicSecretConfig {
  /** Тип динамического секрета */
  type: DynamicSecretType;
  /** Параметры генерации */
  generationParams: Record<string, unknown>;
  /** TTL секрета */
  ttl: number;
  /** Параметры подключения к источнику */
  sourceConfig: Record<string, unknown>;
  /** Параметры ротации */
  rotationConfig?: RotationConfig;
}

/**
 * Сгенерированный динамический секрет
 */
export interface GeneratedDynamicSecret {
  /** ID секрета */
  secretId: string;
  /** Тип секрета */
  type: DynamicSecretType;
  /** Сгенерированные данные */
  credentials: Record<string, string>;
  /** Время создания */
  createdAt: Date;
  /** Время истечения */
  expiresAt: Date;
  /** Lease ID */
  leaseId: string;
  /** Метаданные */
  metadata?: Record<string, unknown>;
}

// ============================================================================
// ТИПЫ ДЛЯ ПОЛИТИК ДОСТУПА
// ============================================================================

/**
 * Действия, которые можно выполнять с секретами
 */
export enum SecretAction {
  /** Чтение значения секрета */
  READ = 'read',
  /** Запись/создание секрета */
  WRITE = 'write',
  /** Удаление секрета */
  DELETE = 'delete',
  /** Ротация секрета */
  ROTATE = 'rotate',
  /** Просмотр метаданных */
  LIST = 'list',
  /** Управление версиями */
  VERSION_MANAGE = 'version_manage',
  /** Управление lease */
  LEASE_MANAGE = 'lease_manage',
  /** Изменение политик */
  POLICY_MANAGE = 'policy_manage',
  /** Аудит операций */
  AUDIT = 'audit',
  /** Экспорт секрета */
  EXPORT = 'export'
}

/**
 * Условия для политик доступа
 */
export interface PolicyCondition {
  /** Тип условия */
  type: 'ip_range' | 'time_range' | 'mfa_required' | 'role' | 'attribute';
  /** Значение условия */
  value: string | string[] | Record<string, unknown> | boolean;
  /** Оператор сравнения */
  operator?: 'equals' | 'contains' | 'in' | 'not_in' | 'greater_than' | 'less_than';
}

/**
 * Правило политики доступа
 */
export interface AccessPolicyRule {
  /** ID правила */
  ruleId: string;
  /** Действия, которые разрешает/запрещает правило */
  actions: SecretAction[];
  /** Ресурсы (секреты), к которым применяется правило */
  resources: string[];
  /** Субъекты (пользователи/сервисы), к которым применяется */
  subjects: string[];
  /** Разрешать или запрещать */
  effect: 'allow' | 'deny';
  /** Условия выполнения правила */
  conditions?: PolicyCondition[];
  /** Приоритет правила (чем выше, тем важнее) */
  priority: number;
  /** Описание правила */
  description?: string;
}

/**
 * Политика доступа к секретам
 */
export interface AccessPolicy {
  /** ID политики */
  policyId: string;
  /** Название политики */
  name: string;
  /** Описание */
  description?: string;
  /** Правила политики */
  rules: AccessPolicyRule[];
  /** Время создания */
  createdAt: Date;
  /** Кто создал */
  createdBy: string;
  /** Время последнего изменения */
  updatedAt?: Date;
  /** Кто изменил */
  updatedBy?: string;
  /** Версия политики */
  version: number;
  /** Включена ли политика */
  enabled: boolean;
}

/**
 * Контекст запроса доступа
 */
export interface AccessContext {
  /** ID пользователя/сервиса */
  subjectId: string;
  /** Роли субъекта */
  roles: string[];
  /** Атрибуты субъекта */
  attributes: Record<string, unknown>;
  /** IP адрес */
  ipAddress: string;
  /** Время запроса */
  timestamp: Date;
  /** Прошёл ли MFA */
  mfaVerified: boolean;
  /** ID сессии */
  sessionId?: string;
  /** User agent */
  userAgent?: string;
}

// ============================================================================
// ТИПЫ ДЛЯ АУДИТА
// ============================================================================

/**
 * Запись аудита операции с секретом
 */
export interface AuditLogEntry {
  /** Уникальный ID записи */
  entryId: string;
  /** Тип операции */
  operation: SecretOperation;
  /** ID секрета */
  secretId: string;
  /** Название секрета */
  secretName: string;
  /** Кто выполнил операцию */
  performedBy: string;
  /** Время операции */
  timestamp: Date;
  /** Успешна ли операция */
  success: boolean;
  /** Код ошибки (если была) */
  errorCode?: string;
  /** Сообщение об ошибке */
  errorMessage?: string;
  /** IP адрес */
  ipAddress: string;
  /** User agent */
  userAgent?: string;
  /** Дополнительные данные */
  metadata?: Record<string, unknown>;
  /** Изменения (для update операций) */
  changes?: {
    field: string;
    oldValue?: unknown;
    newValue?: unknown;
  }[];
  /** ID сессии */
  sessionId?: string;
  /** ID операции для трекинга */
  operationId?: string;
  /** Backend, который использовался */
  backend: SecretBackendType;
}

/**
 * Фильтры для поиска в audit логах
 */
export interface AuditLogFilters {
  /** ID секрета */
  secretId?: string;
  /** Тип операции */
  operation?: SecretOperation;
  /** Кто выполнил */
  performedBy?: string;
  /** Дата начала */
  startDate?: Date;
  /** Дата окончания */
  endDate?: Date;
  /** Успешные операции */
  success?: boolean;
  /** Backend */
  backend?: SecretBackendType;
  /** IP адрес */
  ipAddress?: string;
}

// ============================================================================
// ТИПЫ ДЛЯ СКАНИРОВАНИЯ И DETECTION
// ============================================================================

/**
 * Типы обнаруженных утечек
 */
export enum LeakType {
  /** Секрет найден в логах */
  LOG_EXPOSURE = 'log_exposure',
  /** Секрет найден в коде */
  CODE_EXPOSURE = 'code_exposure',
  /** Секрет найден в конфиге */
  CONFIG_EXPOSURE = 'config_exposure',
  /** Секрет найден в environment variables */
  ENV_EXPOSURE = 'env_exposure',
  /** Секрет найден в Git history */
  GIT_HISTORY_EXPOSURE = 'git_history_exposure',
  /** Подозрительный доступ */
  SUSPICIOUS_ACCESS = 'suspicious_access',
  /** Брутфорс атака */
  BRUTE_FORCE = 'brute_force',
  /** Аномальное использование */
  ANOMALOUS_USAGE = 'anomalous_usage',
  /** Секрет скомпрометирован внешне */
  EXTERNAL_COMPROMISE = 'external_compromise'
}

/**
 * Уровень серьёзности утечки
 */
export enum LeakSeverity {
  /** Низкий риск */
  LOW = 'low',
  /** Средний риск */
  MEDIUM = 'medium',
  /** Высокий риск */
  HIGH = 'high',
  /** Критический риск */
  CRITICAL = 'critical'
}

/**
 * Информация об обнаруженной утечке
 */
export interface LeakDetection {
  /** ID обнаружения */
  detectionId: string;
  /** Тип утечки */
  leakType: LeakType;
  /** Уровень серьёзности */
  severity: LeakSeverity;
  /** ID затронутого секрета */
  secretId: string;
  /** Название секрета */
  secretName: string;
  /** Описание проблемы */
  description: string;
  /** Где обнаружено */
  location?: string;
  /** Время обнаружения */
  detectedAt: Date;
  /** Кто обнаружил */
  detectedBy: string;
  /** Статус обработки */
  status: 'new' | 'investigating' | 'mitigated' | 'resolved' | 'false_positive';
  /** Рекомендации по устранению */
  remediationSteps?: string[];
  /** Дополнительные данные */
  metadata?: Record<string, unknown>;
}

/**
 * Конфигурация сканера секретов
 */
export interface ScannerConfig {
  /** Включено ли сканирование */
  enabled: boolean;
  /** Интервал сканирования (сек) */
  scanInterval: number;
  /** Паттерны для поиска секретов */
  secretPatterns: RegExp[];
  /** Пути для сканирования */
  scanPaths: string[];
  /** Исключения из сканирования */
  excludePatterns: RegExp[];
  /** Авто-отзыв при обнаружении утечки */
  autoRevokeOnLeak: boolean;
  /** Уведомлять при обнаружении */
  notifyOnDetection: boolean;
}

// ============================================================================
// ТИПЫ ДЛЯ КЭШИРОВАНИЯ
// ============================================================================

/**
 * Конфигурация кэша секретов
 */
export interface CacheConfig {
  /** Включено ли кэширование */
  enabled: boolean;
  /** TTL кэша в секундах */
  ttl: number;
  /** Максимальное количество записей */
  maxEntries: number;
  /** Шифровать ли кэш в памяти */
  encryptInMemory: boolean;
  /** Алгоритм шифрования */
  encryptionAlgorithm: 'aes-256-gcm' | 'chacha20-poly1305';
  /** Стратегия вытеснения */
  evictionStrategy: 'lru' | 'lfu' | 'fifo';
}

/**
 * Запись в кэше секретов
 */
export interface CachedSecret {
  /** Ключ кэша */
  cacheKey: string;
  /** Зашифрованное значение секрета */
  encryptedValue: Buffer;
  /** IV для шифрования */
  iv: Buffer;
  /** Auth tag для GCM */
  authTag?: Buffer;
  /** Время создания */
  cachedAt: Date;
  /** Время истечения */
  expiresAt: Date;
  /** Версия секрета */
  version: number;
  /** Частота доступа (для LFU) */
  accessCount: number;
  /** Время последнего доступа */
  lastAccessedAt: Date;
}

// ============================================================================
// ТИПЫ ДЛЯ БЭКЕНДОВ
// ============================================================================

/**
 * Базовая конфигурация бэкенда
 */
export interface BackendConfig {
  /** Тип бэкенда */
  type: SecretBackendType;
  /** Приоритет бэкенда (чем выше, тем важнее) */
  priority: number;
  /** Включён ли бэкенд */
  enabled: boolean;
  /** Таймаут операций (мс) */
  timeout: number;
  /** Максимальное количество retries */
  maxRetries: number;
  /** Health check interval (сек) */
  healthCheckInterval: number;
}

/**
 * Конфигурация HashiCorp Vault
 */
export interface VaultBackendConfig extends BackendConfig {
  type: SecretBackendType.VAULT;
  /** URL Vault сервера */
  vaultUrl: string;
  /** Токен доступа */
  token: string;
  /** Путь к секретам */
  secretsPath: string;
  /** Namespace (для Vault Enterprise) */
  namespace?: string;
  /** TLS сертификат */
  caCert?: string;
  /** Client сертификат */
  clientCert?: string;
  /** Client ключ */
  clientKey?: string;
  /** Пропускать проверку TLS */
  skipTLSVerify: boolean;
}

/**
 * Конфигурация AWS Secrets Manager
 */
export interface AWSSecretsBackendConfig extends BackendConfig {
  type: SecretBackendType.AWS_SECRETS_MANAGER;
  /** AWS регион */
  region: string;
  /** Access Key ID */
  accessKeyId?: string;
  /** Secret Access Key */
  secretAccessKey?: string;
  /** Role ARN для assume role */
  roleArn?: string;
  /** External ID для assume role */
  externalId?: string;
  /** Endpoint (для localstack) */
  endpoint?: string;
}

/**
 * Конфигурация GCP Secret Manager
 */
export interface GCPSecretsBackendConfig extends BackendConfig {
  type: SecretBackendType.GCP_SECRET_MANAGER;
  /** ID проекта GCP */
  projectId: string;
  /** Путь к credentials файлу */
  credentialsPath?: string;
  /** Credentials объект */
  credentials?: Record<string, string>;
  /** API endpoint */
  apiEndpoint?: string;
}

/**
 * Конфигурация Azure Key Vault
 */
export interface AzureKeyVaultBackendConfig extends BackendConfig {
  type: SecretBackendType.AZURE_KEY_VAULT;
  /** URL Key Vault */
  vaultUrl: string;
  /** Tenant ID */
  tenantId: string;
  /** Client ID */
  clientId: string;
  /** Client Secret */
  clientSecret?: string;
  /** Certificate path для auth */
  certificatePath?: string;
  /** Managed Identity */
  useManagedIdentity: boolean;
}

/**
 * Конфигурация локального бэкенда
 */
export interface LocalBackendConfig extends BackendConfig {
  type: SecretBackendType.LOCAL;
  /** Путь к файлу хранилища */
  storagePath: string;
  /** Ключ шифрования */
  encryptionKey: string;
}

/**
 * Объединённый тип конфигурации бэкенда
 */
export type AnyBackendConfig =
  | VaultBackendConfig
  | AWSSecretsBackendConfig
  | GCPSecretsBackendConfig
  | AzureKeyVaultBackendConfig
  | LocalBackendConfig;

/**
 * Информация о секрете в бэкенде
 */
export interface BackendSecret {
  /** ID секрета */
  id: string;
  /** Название секрета */
  name: string;
  /** Значение секрета */
  value: string;
  /** Версия */
  version: number;
  /** Метаданные */
  metadata?: Record<string, unknown>;
  /** Время создания */
  createdAt: Date;
  /** Время обновления */
  updatedAt?: Date;
  /** Статус */
  status: SecretStatus;
  /** Тип контента */
  contentType?: string;
}

/**
 * Интерфейс бэкенда секретов
 */
export interface ISecretBackend {
  /** Тип бэкенда */
  readonly type: SecretBackendType;
  
  /** Инициализация бэкенда */
  initialize(): Promise<void>;
  
  /** Проверка доступности бэкенда */
  healthCheck(): Promise<boolean>;
  
  /** Получить секрет */
  getSecret(secretId: string): Promise<BackendSecret | null>;
  
  /** Получить конкретную версию секрета */
  getSecretVersion(secretId: string, version: number): Promise<BackendSecret | null>;
  
  /** Создать новый секрет */
  createSecret(secret: Omit<BackendSecret, 'version' | 'createdAt' | 'updatedAt'>): Promise<BackendSecret>;
  
  /** Обновить секрет */
  updateSecret(secretId: string, value: string, metadata?: Record<string, unknown>): Promise<BackendSecret>;
  
  /** Удалить секрет */
  deleteSecret(secretId: string): Promise<void>;
  
  /** Получить все версии секрета */
  listVersions(secretId: string): Promise<SecretVersion[]>;
  
  /** Откатиться к версии */
  rollbackToVersion(secretId: string, version: number): Promise<BackendSecret>;
  
  /** Закрыть соединение */
  destroy(): Promise<void>;
}

// ============================================================================
// ТИПЫ ДЛЯ ОСНОВНОГО МЕНЕДЖЕРА
// ============================================================================

/**
 * Конфигурация Secrets Manager
 */
export interface SecretsManagerConfig {
  /** Конфигурации бэкендов */
  backends: AnyBackendConfig[];
  /** Конфигурация кэша */
  cache: CacheConfig;
  /** Конфигурация ротации по умолчанию */
  defaultRotation: RotationConfig;
  /** Конфигурация lease по умолчанию */
  defaultLease: LeaseConfig;
  /** Конфигурация сканера */
  scanner: ScannerConfig;
  /** Включить audit логирование */
  auditEnabled: boolean;
  /** Путь к audit логам */
  auditLogPath?: string;
  /** Политики доступа */
  policies: AccessPolicy[];
  /** Ключ шифрования для кэша */
  encryptionKey: string;
  /** Режим работы (development/production) */
  mode: 'development' | 'production';
}

/**
 * События Secrets Manager для EventEmitter
 */
export interface SecretsManagerEvents {
  /** Секрет создан */
  'secret:created': (secret: BackendSecret) => void;
  /** Секрет обновлён */
  'secret:updated': (secret: BackendSecret) => void;
  /** Секрет удалён */
  'secret:deleted': (secretId: string) => void;
  /** Секрет скомпрометирован */
  'secret:compromised': (secretId: string) => void;
  /** Обнаружена утечка */
  'leak:detected': (leak: LeakDetection) => void;
  /** Ротация началась */
  'rotation:started': (secretId: string) => void;
  /** Ротация завершена */
  'rotation:completed': (secretId: string) => void;
  /** Ротация не удалась */
  'rotation:failed': (secretId: string, error: Error) => void;
  /** Lease истекает */
  'lease:expiring': (lease: SecretLease) => void;
  /** Lease истёк */
  'lease:expired': (lease: SecretLease) => void;
  /** Audit событие */
  'audit:logged': (entry: AuditLogEntry) => void;
  /** Backend стал недоступен */
  'backend:unhealthy': (backendType: SecretBackendType) => void;
  /** Backend восстановлен */
  'backend:recovered': (backendType: SecretBackendType) => void;
}

/**
 * Интерфейс основного Secrets Manager
 */
export interface ISecretsManager {
  /** Инициализация менеджера */
  initialize(): Promise<void>;
  
  /** Получить секрет */
  getSecret(secretId: string, context: AccessContext): Promise<SecretOperationResult<BackendSecret>>;
  
  /** Создать секрет */
  createSecret(
    secret: Omit<BackendSecret, 'version' | 'createdAt' | 'updatedAt'>,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>>;
  
  /** Обновить секрет */
  updateSecret(
    secretId: string,
    value: string,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>>;
  
  /** Удалить секрет */
  deleteSecret(secretId: string, context: AccessContext): Promise<SecretOperationResult<void>>;
  
  /** Ротировать секрет */
  rotateSecret(secretId: string, context: AccessContext): Promise<SecretOperationResult<BackendSecret>>;
  
  /** Получить версию секрета */
  getVersion(
    secretId: string,
    version: number,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>>;
  
  /** Откатиться к версии */
  rollback(
    secretId: string,
    version: number,
    reason: string,
    context: AccessContext
  ): Promise<SecretOperationResult<BackendSecret>>;
  
  /** Получить lease */
  acquireLease(secretId: string, context: AccessContext): Promise<SecretOperationResult<SecretLease>>;
  
  /** Продлить lease */
  renewLease(leaseId: string, context: AccessContext): Promise<SecretOperationResult<SecretLease>>;
  
  /** Отозвать lease */
  revokeLease(leaseId: string, context: AccessContext): Promise<SecretOperationResult<void>>;
  
  /** Создать динамический секрет */
  createDynamicSecret(
    config: DynamicSecretConfig,
    context: AccessContext
  ): Promise<SecretOperationResult<GeneratedDynamicSecret>>;
  
  /** Проверить доступ */
  checkAccess(action: SecretAction, resource: string, context: AccessContext): Promise<boolean>;
  
  /** Получить audit логи */
  getAuditLogs(filters: AuditLogFilters): Promise<AuditLogEntry[]>;
  
  /** Закрыть менеджер */
  destroy(): Promise<void>;
}

// ============================================================================
// ТИПЫ ДЛЯ ОШИБОК
// ============================================================================

/**
 * Базовый класс ошибок секретов
 */
export class SecretError extends Error {
  constructor(
    message: string,
    public readonly errorCode: string,
    public readonly secretId?: string
  ) {
    super(message);
    this.name = 'SecretError';
  }
}

/**
 * Ошибка доступа к секрету
 */
export class SecretAccessError extends SecretError {
  constructor(message: string, secretId?: string) {
    super(message, 'ACCESS_DENIED', secretId);
    this.name = 'SecretAccessError';
  }
}

/**
 * Ошибка версии секрета
 */
export class SecretVersionError extends SecretError {
  constructor(message: string, secretId?: string) {
    super(message, 'VERSION_ERROR', secretId);
    this.name = 'SecretVersionError';
  }
}

/**
 * Ошибка lease
 */
export class SecretLeaseError extends SecretError {
  constructor(message: string, secretId?: string) {
    super(message, 'LEASE_ERROR', secretId);
    this.name = 'SecretLeaseError';
  }
}

/**
 * Ошибка бэкенда
 */
export class SecretBackendError extends SecretError {
  constructor(
    message: string,
    public readonly backendType: SecretBackendType
  ) {
    super(message, 'BACKEND_ERROR');
    this.name = 'SecretBackendError';
  }
}

/**
 * Ошибка шифрования
 */
export class SecretEncryptionError extends SecretError {
  constructor(message: string) {
    super(message, 'ENCRYPTION_ERROR');
    this.name = 'SecretEncryptionError';
  }
}

/**
 * Ошибка валидации
 */
export class SecretValidationError extends SecretError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR');
    this.name = 'SecretValidationError';
  }
}

/**
 * Ошибка конфигурации
 */
export class SecretConfigError extends SecretError {
  constructor(message: string) {
    super(message, 'CONFIG_ERROR');
    this.name = 'SecretConfigError';
  }
}
