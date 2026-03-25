/**
 * Zero Trust Network Architecture - Типы и Интерфейсы
 * 
 * Данный модуль определяет полную систему типов для реализации
 * Zero Trust Network Architecture (ZTNA) в соответствии с NIST SP 800-207.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

// ============================================================================
// БАЗОВЫЕ ТИПЫ ZERO TRUST
// ============================================================================

/**
 * Уровень доверия к субъекту в системе Zero Trust
 * 
 * Zero Trust принцип: "Никогда не доверяй, всегда проверяй"
 * Доверие вычисляется динамически на основе множества факторов
 */
export enum TrustLevel {
  /** Полное отсутствие доверия - требуется полная верификация */
  UNTRUSTED = 0,
  
  /** Минимальное доверие - базовая аутентификация пройдена */
  MINIMAL = 1,
  
  /** Низкое доверие - аутентификация + базовая проверка устройства */
  LOW = 2,
  
  /** Среднее доверие - MFA + проверка соответствия политикам */
  MEDIUM = 3,
  
  /** Высокое доверие - полная верификация с непрерывным мониторингом */
  HIGH = 4,
  
  /** Полное доверие - привилегированный доступ с усиленным мониторингом */
  FULL = 5
}

/**
 * Статус решения PDP (Policy Decision Point)
 */
export enum PolicyDecision {
  /** Доступ разрешён */
  ALLOW = 'ALLOW',
  
  /** Доступ запрещён */
  DENY = 'DENY',
  
  /** Доступ разрешён с ограничениями */
  ALLOW_RESTRICTED = 'ALLOW_RESTRICTED',
  
  /** Требуется дополнительная верификация */
  REQUIRE_STEP_UP = 'REQUIRE_STEP_UP',
  
  /** Доступ разрешён временно (JIT) */
  ALLOW_TEMPORARY = 'ALLOW_TEMPORARY',
  
  /** Решение отложено для дополнительного анализа */
  DEFERRED = 'DEFERRED'
}

/**
 * Тип субъекта в Zero Trust архитектуре
 */
export enum SubjectType {
  /** Человек-пользователь */
  USER = 'USER',
  
  /** Сервис или микросервис */
  SERVICE = 'SERVICE',
  
  /** Устройство (IoT, рабочая станция) */
  DEVICE = 'DEVICE',
  
  /** Контейнер или Pod */
  WORKLOAD = 'WORKLOAD',
  
  /** API клиент */
  API_CLIENT = 'API_CLIENT',
  
  /** Система или процесс */
  SYSTEM = 'SYSTEM'
}

/**
 * Тип ресурса для доступа
 */
export enum ResourceType {
  /** HTTP/HTTPS эндпоинт */
  HTTP_ENDPOINT = 'HTTP_ENDPOINT',
  
  /** База данных */
  DATABASE = 'DATABASE',
  
  /** Файловое хранилище */
  FILE_STORAGE = 'FILE_STORAGE',
  
  /** Очередь сообщений */
  MESSAGE_QUEUE = 'MESSAGE_QUEUE',
  
  /** API сервис */
  API_SERVICE = 'API_SERVICE',
  
  /** Внутренний микросервис */
  MICROSERVICE = 'MICROSERVICE',
  
  /** Сетевой сегмент */
  NETWORK_SEGMENT = 'NETWORK_SEGMENT',
  
  /** Облачный ресурс */
  CLOUD_RESOURCE = 'CLOUD_RESOURCE'
}

// ============================================================================
// ТИПЫ АУТЕНТИФИКАЦИИ И ИДЕНТИФИКАЦИИ
// ============================================================================

/**
 * Методы аутентификации
 */
export enum AuthenticationMethod {
  /** Базовая аутентификация (логин/пароль) */
  PASSWORD = 'PASSWORD',
  
  /** Многофакторная аутентификация */
  MFA = 'MFA',
  
  /** Аутентификация по сертификату */
  CERTIFICATE = 'CERTIFICATE',
  
  /** mTLS взаимная аутентификация */
  MTLS = 'MTLS',
  
  /** OAuth 2.1 / OIDC */
  OAUTH = 'OAUTH',
  
  /** JWT токен */
  JWT = 'JWT',
  
  /** API ключ */
  API_KEY = 'API_KEY',
  
  /** Биометрическая аутентификация */
  BIOMETRIC = 'BIOMETRIC',
  
  /** WebAuthn / FIDO2 */
  WEBAUTHN = 'WEBAUTHN',
  
  /** Одноразовый пароль (TOTP/HOTP) */
  OTP = 'OTP',
  
  /** Аутентификация на основе поведения */
  BEHAVIORAL = 'BEHAVIORAL'
}

/**
 * Информация об идентичности субъекта
 */
export interface Identity {
  /** Уникальный идентификатор субъекта */
  id: string;

  /** Уникальный идентификатор субъекта (алиас для id) */
  subjectId: string;

  /** Тип субъекта */
  type: SubjectType;

  /** Тип субъекта (строка, алиас для type) */
  subjectType: string;

  /** Отображаемое имя */
  displayName: string;

  /** Роли субъекта */
  roles: string[];

  /** Прямые разрешения */
  permissions: string[];

  /** Группы членства */
  groups: string[];

  /** Метки атрибутов (labels) */
  labels: Record<string, string>;

  /** Домен или арендатор */
  domain?: string;

  /** Время создания идентичности */
  createdAt: Date;

  /** Время последнего обновления */
  updatedAt: Date;
}

/**
 * Контекст аутентификации
 */
export interface AuthContext {
  /** Используемый метод аутентификации */
  method: AuthenticationMethod;

  /** Время успешной аутентификации */
  authenticatedAt: Date;

  /** Время истечения сессии */
  expiresAt: Date;

  /** Уровень аутентификации (LoA) */
  levelOfAssurance: number;

  /** Факторы аутентификации */
  factors: AuthenticationMethod[];

  /** ID сессии */
  sessionId: string;

  /** Refresh token ID */
  refreshTokenId?: string;

  /** Была ли пройдена MFA */
  mfaVerified: boolean;

  /** Методы MFA */
  mfaMethods: AuthenticationMethod[];

  /** Методы аутентификации (алиас для factors) */
  authenticationMethods: AuthenticationMethod[];

  /** Claims из токена */
  tokenClaims?: Record<string, any>;
}

// ============================================================================
// ТИПЫ УСТРОЙСТВА И POSTURE CHECKING
// ============================================================================

/**
 * Статус здоровья устройства
 */
export enum DeviceHealthStatus {
  /** Устройство полностью соответствует политикам */
  HEALTHY = 'HEALTHY',

  /** Устройство имеет незначительные отклонения */
  DEGRADED = 'DEGRADED',

  /** Устройство не соответствует критическим политикам */
  NON_COMPLIANT = 'NON_COMPLIANT',

  /** Статус устройства неизвестен */
  UNKNOWN = 'UNKNOWN',

  /** Устройство заблокировано */
  BLOCKED = 'BLOCKED',

  /** Устройство нездорово (алиас для NON_COMPLIANT) */
  UNHEALTHY = 'NON_COMPLIANT'
}

/**
 * Тип устройства
 */
export enum DeviceType {
  /** Рабочая станция */
  WORKSTATION = 'WORKSTATION',
  
  /** Мобильное устройство */
  MOBILE = 'MOBILE',
  
  /** Сервер */
  SERVER = 'SERVER',
  
  /** IoT устройство */
  IOT = 'IOT',
  
  /** Контейнер */
  CONTAINER = 'CONTAINER',
  
  /** Виртуальная машина */
  VM = 'VM',
  
  /** Сетевое устройство */
  NETWORK_DEVICE = 'NETWORK_DEVICE'
}

/**
 * Состояние устройства (Device Posture)
 */
export interface DevicePosture {
  /** Уникальный идентификатор устройства */
  deviceId: string;

  /** Тип устройства */
  deviceType: DeviceType;

  /** Операционная система */
  operatingSystem: {
    name: string;
    version: string;
    build: string;
    patchLevel: string;
  };

  /** Статус здоровья */
  healthStatus: DeviceHealthStatus;

  /** Соответствие политикам безопасности */
  compliance: {
    /** Антивирус активен */
    antivirusActive: boolean;
    /** Антивирус обновлён */
    antivirusUpdated: boolean;
    /** Фаервол активен */
    firewallActive: boolean;
    /** Диск зашифрован */
    diskEncrypted: boolean;
    /** Secure Boot включён */
    secureBootEnabled: boolean;
    /** TPM присутствует */
    tpmPresent: boolean;
    /** Последняя проверка обновлений */
    lastUpdateCheck: Date;
    /** Критические обновления установлены */
    criticalUpdatesInstalled: boolean;
    /** Jailbreak/Rootkit обнаружен */
    jailbreakDetected: boolean;
  };

  /** Устройство соответствует политикам (вычисляемое поле) */
  isCompliant: boolean;

  /** Диск зашифрован (алиас для compliance.diskEncrypted) */
  isEncrypted: boolean;

  /** Сетевая информация */
  network: {
    /** IP адрес */
    ipAddress: string;
    /** MAC адрес */
    macAddress: string;
    /** SSID сети */
    ssid?: string;
    /** Тип подключения */
    connectionType: 'WiFi' | 'Ethernet' | 'Cellular' | 'VPN';
    /** Домен сети */
    networkDomain?: string;
  };

  /** Географическое положение */
  location?: {
    /** Страна */
    country: string;
    /** Город */
    city: string;
    /** Координаты */
    coordinates: [number, number];
    /** Часовой пояс */
    timezone: string;
  };

  /** Время последней проверки */
  lastCheckedAt: Date;

  /** Время следующей проверки */
  nextCheckAt: Date;

  /** Оценка риска устройства (0-100) */
  riskScore: number;
}

// ============================================================================
// ТИПЫ ПОЛИТИК БЕЗОПАСНОСТИ
// ============================================================================

/**
 * Операция в политике доступа
 */
export enum PolicyOperation {
  /** Чтение */
  READ = 'READ',
  
  /** Запись */
  WRITE = 'WRITE',
  
  /** Удаление */
  DELETE = 'DELETE',
  
  /** Выполнение */
  EXECUTE = 'EXECUTE',
  
  /** Администрирование */
  ADMIN = 'ADMIN',
  
  /** Любая операция */
  ANY = 'ANY'
}

/**
 * Условие политики (ABAC)
 */
export interface PolicyCondition {
  /** Атрибут для проверки */
  attribute: string;
  
  /** Оператор сравнения */
  operator: 'EQ' | 'NE' | 'GT' | 'LT' | 'GE' | 'LE' | 'IN' | 'NOT_IN' | 'CONTAINS' | 'MATCHES' | 'EXISTS';
  
  /** Значение для сравнения */
  value: string | number | boolean | string[] | RegExp;
  
  /** Логический оператор для следующего условия */
  logicalOperator?: 'AND' | 'OR' | 'NOT';
}

/**
 * Ограничение политики
 */
export interface PolicyConstraint {
  /** Whitelist IP адресов */
  ipWhitelist?: string[];
  
  /** Blacklist IP адресов */
  ipBlacklist?: string[];
  
  /** Разрешённые страны */
  allowedCountries?: string[];
  
  /** Запрещённые страны */
  deniedCountries?: string[];
  
  /** Требуемый уровень доверия */
  requiredTrustLevel?: TrustLevel;
  
  /** Требуемая MFA */
  mfaRequired?: boolean;
  
  /** Требуемые методы аутентификации */
  requiredAuthMethods?: AuthenticationMethod[];
  
  /** Ограничение по времени */
  timeRestriction?: {
    /** Начало разрешённого периода */
    startTime: string; // HH:MM format
    /** Конец разрешённого периода */
    endTime: string;
    /** Дни недели */
    daysOfWeek: number[]; // 0-6, где 0 = воскресенье
    /** Часовой пояс */
    timezone: string;
  };
  
  /** Максимальная длительность сессии */
  maxSessionDuration?: number; // в секундах
  
  /** Максимальное количество одновременных сессий */
  maxConcurrentSessions?: number;
  
  /** Требуемый статус устройства */
  requiredDeviceHealth?: DeviceHealthStatus;
  
  /** Требуемые метки устройства */
  requiredDeviceLabels?: Record<string, string>;
  
  /** Ограничение скорости запросов */
  rateLimit?: {
    /** Количество запросов */
    requests: number;
    /** Период в секундах */
    periodSeconds: number;
  };
}

/**
 * Правило политики доступа
 */
export interface AccessPolicyRule {
  /** Уникальный идентификатор правила */
  id: string;
  
  /** Название правила */
  name: string;
  
  /** Описание правила */
  description: string;
  
  /** Приоритет правила (меньше = выше приоритет) */
  priority: number;
  
  /** Эффект правила */
  effect: 'ALLOW' | 'DENY';
  
  /** Типы субъектов */
  subjectTypes: SubjectType[];
  
  /** Роли субъектов */
  subjectRoles?: string[];
  
  /** Типы ресурсов */
  resourceTypes: ResourceType[];
  
  /** Идентификаторы ресурсов */
  resourceIds?: string[];
  
  /** Метки ресурсов */
  resourceLabels?: Record<string, string>;
  
  /** Разрешённые операции */
  operations: PolicyOperation[];
  
  /** Условия доступа (ABAC) */
  conditions: PolicyCondition[];
  
  /** Ограничения */
  constraints: PolicyConstraint;
  
  /** Действия при нарушении */
  enforcementActions: {
    /** Логировать нарушение */
    logViolation: boolean;
    /** Отправить алерт */
    sendAlert: boolean;
    /** Заблокировать субъект */
    blockSubject: boolean;
    /** Уничтожить сессию */
    terminateSession: boolean;
  };
  
  /** Активно ли правило */
  enabled: boolean;
  
  /** Время создания */
  createdAt: Date;
  
  /** Время обновления */
  updatedAt: Date;
  
  /** Время истечения правила */
  expiresAt?: Date;
}

// ============================================================================
// ТИПЫ СЕТЕВОЙ СЕГМЕНТАЦИИ
// ============================================================================

/**
 * Тип сетевого сегмента
 */
export enum NetworkSegmentType {
  /** Публичная зона */
  PUBLIC = 'PUBLIC',
  
  /** Частная зона */
  PRIVATE = 'PRIVATE',
  
  /** Изолированная зона */
  ISOLATED = 'ISOLATED',
  
  /** Зона управления */
  MANAGEMENT = 'MANAGEMENT',
  
  /** DMZ */
  DMZ = 'DMZ',
  
  /** Зона данных */
  DATA = 'DATA'
}

/**
 * Правило микросегментации
 */
export interface MicroSegmentationRule {
  /** Уникальный идентификатор правила */
  id: string;
  
  /** Название правила */
  name: string;
  
  /** Исходный сегмент */
  sourceSegment: {
    /** ID сегмента */
    segmentId: string;
    /** Тип сегмента */
    type: NetworkSegmentType;
    /** CIDR блок */
    cidr?: string;
    /** Метки */
    labels?: Record<string, string>;
    /** Workload names */
    workloadNames?: string[];
  };
  
  /** Целевой сегмент */
  destinationSegment: {
    /** ID сегмента */
    segmentId: string;
    /** Тип сегмента */
    type: NetworkSegmentType;
    /** CIDR блок */
    cidr?: string;
    /** Метки */
    labels?: Record<string, string>;
    /** Workload names */
    workloadNames?: string[];
  };
  
  /** Разрешённые протоколы */
  protocols: {
    /** Протокол */
    protocol: 'TCP' | 'UDP' | 'ICMP' | 'ANY';
    /** Порты источника */
    sourcePorts?: string[]; // e.g., ["80", "443", "8000-9000"]
    /** Порты назначения */
    destinationPorts: string[];
  }[];
  
  /** Действие */
  action: 'ALLOW' | 'DENY' | 'LOG';
  
  /** Приоритет */
  priority: number;
  
  /** Логировать трафик */
  logTraffic: boolean;
  
  /** Включить IDS/IPS инспекцию */
  enableInspection: boolean;
  
  /** Активно ли правило */
  enabled: boolean;
}

/**
 * Конфигурация сетевого сегмента
 */
export interface NetworkSegment {
  /** Уникальный идентификатор сегмента */
  id: string;
  
  /** Название сегмента */
  name: string;
  
  /** Тип сегмента */
  type: NetworkSegmentType;
  
  /** CIDR блок */
  cidr: string;
  
  /** VLAN ID */
  vlanId?: number;
  
  /** VRF (Virtual Routing and Forwarding) */
  vrf?: string;
  
  /** Метки для идентификации */
  labels: Record<string, string>;
  
  /** Политики сегмента */
  policies: {
    /** Разрешить outbound по умолчанию */
    defaultOutbound: 'ALLOW' | 'DENY';
    /** Разрешить inbound по умолчанию */
    defaultInbound: 'ALLOW' | 'DENY';
    /** Разрешить межсегментный трафик по умолчанию */
    defaultInterSegment: 'ALLOW' | 'DENY';
  };
  
  /** Применённые правила сегментации */
  appliedRules: string[];
  
  /** Статистика трафика */
  trafficStats: {
    /** Входящий трафик (байт) */
    inboundBytes: number;
    /** Исходящий трафик (байт) */
    outboundBytes: number;
    /** Количество соединений */
    connectionCount: number;
    /** Количество заблокированных попыток */
    blockedAttempts: number;
  };
}

// ============================================================================
// ТИПЫ SOFTWARE-DEFINED PERIMETER (SDP)
// ============================================================================

/**
 * Статус SDP контроллера
 */
export enum SdpControllerStatus {
  /** Активен и готов */
  ACTIVE = 'ACTIVE',
  
  /** Ожидание подключения */
  STANDBY = 'STANDBY',
  
  /** Обработка запроса */
  PROCESSING = 'PROCESSING',
  
  /** Ошибка */
  ERROR = 'ERROR'
}

/**
 * Конфигурация SDP клиента
 */
export interface SdpClientConfig {
  /** Уникальный идентификатор клиента */
  clientId: string;
  
  /** Сертификат клиента */
  clientCertificate: string;
  
  /** Закрытый ключ (в зашифрованном виде) */
  encryptedPrivateKey: string;
  
  /** Адреса SDP контроллеров */
  controllerAddresses: string[];
  
  /** Адреса SDP шлюзов */
  gatewayAddresses: string[];
  
  /** Разрешённые ресурсы */
  allowedResources: string[];
  
  /** Время жизни конфигурации */
  validUntil: Date;
  
  /** Интервал обновления */
  refreshInterval: number; // в секундах
}

/**
 * Сессия SDP подключения
 */
export interface SdpSession {
  /** Уникальный идентификатор сессии */
  sessionId: string;
  
  /** ID клиента */
  clientId: string;
  
  /** ID контроллера */
  controllerId: string;
  
  /** ID шлюза */
  gatewayId: string;
  
  /** Время начала сессии */
  startedAt: Date;
  
  /** Время истечения сессии */
  expiresAt: Date;
  
  /** Статус сессии */
  status: 'ACTIVE' | 'SUSPENDED' | 'TERMINATED' | 'EXPIRED';
  
  /** Выделенные ресурсы */
  allocatedResources: {
    /** Виртуальный IP */
    virtualIp: string;
    /** Выделенные порты */
    allocatedPorts: number[];
    /** Туннельный интерфейс */
    tunnelInterface: string;
  };
  
  /** Статистика сессии */
  stats: {
    /** Отправлено байт */
    bytesSent: number;
    /** Получено байт */
    bytesReceived: number;
    /** Количество пакетов */
    packetCount: number;
  };
}

// ============================================================================
// ТИПЫ MTLS SERVICE MESH
// ============================================================================

/**
 * Статус mTLS сертификата
 */
export enum CertificateStatus {
  /** Активен и валиден */
  ACTIVE = 'ACTIVE',
  
  /** Скоро истекает */
  EXPIRING_SOON = 'EXPIRING_SOON',
  
  /** Истёк */
  EXPIRED = 'EXPIRED',
  
  /** Отозван */
  REVOKED = 'REVOKED',
  
  /** Приостановлен */
  SUSPENDED = 'SUSPENDED'
}

/**
 * Конфигурация mTLS сертификата
 */
export interface MtlsCertificate {
  /** Уникальный идентификатор */
  id: string;
  
  /** Серийный номер */
  serialNumber: string;
  
  /** Субъект (CN) */
  commonName: string;
  
  /** Альтернативные имена (SAN) */
  subjectAltNames: string[];
  
  /** PEM кодированный сертификат */
  certificatePem: string;
  
  /** PEM кодированный закрытый ключ */
  privateKeyPem?: string;
  
  /** PEM кодированный CA сертификат */
  caCertificatePem: string;
  
  /** Время выдачи */
  issuedAt: Date;
  
  /** Время истечения */
  expiresAt: Date;
  
  /** Статус */
  status: CertificateStatus;
  
  /** Использованные ключи */
  keyUsage: string[];
  
  /** Расширенные ключи */
  extendedKeyUsage: string[];
  
  /** Отпечаток SHA256 */
  fingerprint: string;
  
  /** SPIFFE ID */
  spiffeId?: string;
}

/**
 * Конфигурация Service Mesh
 */
export interface ServiceMeshConfig {
  /** Имя mesh */
  meshName: string;
  
  /** Версия конфигурации */
  version: string;
  
  /** Настройки mTLS */
  mtls: {
    /** Режим mTLS */
    mode: 'STRICT' | 'PERMISSIVE' | 'DISABLE';
    /** Минимальная версия TLS */
    minTlsVersion: 'TLS1.2' | 'TLS1.3';
    /** Набор шифров */
    cipherSuites: string[];
    /** Rotatioin интервал сертификатов */
    certificateRotationInterval: number; // в часах
    /** Срок жизни сертификата */
    certificateLifetime: number; // в часах
  };
  
  /** Настройки сервисов */
  services: {
    /** Имя сервиса */
    name: string;
    /** Namespace */
    namespace: string;
    /** Версия */
    version: string;
    /** Порты */
    ports: number[];
    /** Метки */
    labels: Record<string, string>;
  }[];
  
  /** Политики трафика */
  trafficPolicies: {
    /** Load balancing алгоритм */
    loadBalancer: 'ROUND_ROBIN' | 'LEAST_CONN' | 'RANDOM' | 'CONSISTENT_HASH';
    /** Connection pool настройки */
    connectionPool: {
      maxConnections: number;
      maxPendingRequests: number;
      maxRequests: number;
      maxRetries: number;
    };
    /** Outlier detection */
    outlierDetection: {
      consecutiveErrors: number;
      interval: number;
      baseEjectionTime: number;
      maxEjectionPercent: number;
    };
  };
}

// ============================================================================
// ТИПЫ JUST-IN-TIME ACCESS
// ============================================================================

/**
 * Статус JIT запроса
 */
export enum JitRequestStatus {
  /** Запрос создан */
  PENDING = 'PENDING',
  
  /** Запрос на рассмотрении */
  UNDER_REVIEW = 'UNDER_REVIEW',
  
  /** Запрос одобрен */
  APPROVED = 'APPROVED',
  
  /** Запрос отклонён */
  DENIED = 'DENIED',
  
  /** Доступ активен */
  ACTIVE = 'ACTIVE',
  
  /** Доступ истёк */
  EXPIRED = 'EXPIRED',
  
  /** Доступ отозван */
  REVOKED = 'REVOKED'
}

/**
 * Запрос JIT доступа
 */
export interface JitAccessRequest {
  /** Уникальный идентификатор запроса */
  requestId: string;
  
  /** ID запрашивающего субъекта */
  subjectId: string;
  
  /** Тип субъекта */
  subjectType: SubjectType;
  
  /** Запрашиваемый ресурс */
  resource: {
    /** Тип ресурса */
    type: ResourceType;
    /** ID ресурса */
    id: string;
    /** Название ресурса */
    name: string;
  };
  
  /** Запрашиваемые операции */
  requestedOperations: PolicyOperation[];
  
  /** Обоснование запроса */
  justification: string;
  
  /** Требуемый срок доступа */
  requestedDuration: number; // в секундах
  
  /** Время создания запроса */
  createdAt: Date;
  
  /** Время начала доступа */
  activatedAt?: Date;
  
  /** Время истечения доступа */
  expiresAt?: Date;
  
  /** Статус запроса */
  status: JitRequestStatus;
  
  /** Информация об одобрении */
  approval?: {
    /** ID одобрившего */
    approverId: string;
    /** Имя одобрившего */
    approverName: string;
    /** Время одобрения */
    approvedAt: Date;
    /** Комментарий */
    comment?: string;
  };
  
  /** Информация об отклонении */
  denial?: {
    /** ID отклонившего */
    denierId: string;
    /** Причина отклонения */
    reason: string;
    /** Время отклонения */
    deniedAt: Date;
  };
  
  /** Использованный доступ */
  usage: {
    /** Был ли использован доступ */
    wasUsed: boolean;
    /** Время первого использования */
    firstUsedAt?: Date;
    /** Время последнего использования */
    lastUsedAt?: Date;
    /** Количество операций */
    operationCount: number;
  };
}

// ============================================================================
// ТИПЫ EGRESS FILTERING И DLP
// ============================================================================

/**
 * Тип чувствительных данных
 */
export enum SensitiveDataType {
  /** Персональные данные */
  PII = 'PII',
  
  /** Финансовые данные */
  FINANCIAL = 'FINANCIAL',
  
  /** Медицинские данные */
  PHI = 'PHI',
  
  /** Коммерческая тайна */
  TRADE_SECRET = 'TRADE_SECRET',
  
  /** Учётные данные */
  CREDENTIALS = 'CREDENTIALS',
  
  /** Ключи шифрования */
  ENCRYPTION_KEYS = 'ENCRYPTION_KEYS',
  
  /** Исходный код */
  SOURCE_CODE = 'SOURCE_CODE',
  
  /** Конфиденциальная переписка */
  CONFIDENTIAL = 'CONFIDENTIAL'
}

/**
 * Правило egress фильтрации
 */
export interface EgressFilterRule {
  /** Уникальный идентификатор правила */
  id: string;
  
  /** Название правила */
  name: string;
  
  /** Приоритет */
  priority: number;
  
  /** Исходные сегменты */
  sourceSegments: string[];
  
  /** Назначения */
  destinations: {
    /** Домены */
    domains?: string[];
    /** IP адреса / CIDR */
    ipRanges?: string[];
    /** Порты */
    ports?: number[];
    /** Протоколы */
    protocols?: string[];
    /** URL паттерны */
    urlPatterns?: string[];
  };
  
  /** Действие */
  action: 'ALLOW' | 'DENY' | 'INSPECT';
  
  /** DLP проверка */
  dlpInspection?: {
    /** Включить DLP */
    enabled: boolean;
    /** Типы данных для проверки */
    sensitiveDataTypes: SensitiveDataType[];
    /** Действие при обнаружении */
    onDetection: 'BLOCK' | 'ALLOW_WITH_WARNING' | 'ALLOW_WITH_ENCRYPTION';
    /** Паттерны для поиска */
    customPatterns: RegExp[];
  };
  
  /** Логирование */
  logging: {
    /** Логировать все запросы */
    logAll: boolean;
    /** Логировать только заблокированные */
    logBlocked: boolean;
    /** Логировать чувствительные данные */
    logSensitiveData: boolean;
  };
  
  /** Активно ли правило */
  enabled: boolean;
}

/**
 * Событие DLP
 */
export interface DlpEvent {
  /** Уникальный идентификатор события */
  eventId: string;
  
  /** Время события */
  timestamp: Date;
  
  /** Тип события */
  eventType: 'DATA_DETECTED' | 'DATA_BLOCKED' | 'POLICY_VIOLATION' | 'SUSPICIOUS_ACTIVITY';
  
  /** Источник данных */
  source: {
    /** IP адрес */
    ipAddress: string;
    /** ID субъекта */
    subjectId: string;
    /** Приложение */
    application: string;
  };
  
  /** Назначение */
  destination: {
    /** URL / домен */
    url: string;
    /** IP адрес */
    ipAddress: string;
    /** Порт */
    port: number;
  };
  
  /** Обнаруженные данные */
  detectedData: {
    /** Типы данных */
    types: SensitiveDataType[];
    /** Количество совпадений */
    matchCount: number;
    /** Примеры совпадений (маскированные) */
    maskedSamples: string[];
    /** Уровень уверенности */
    confidenceScore: number;
  };
  
  /** Предпринятые действия */
  actionsTaken: string[];
  
  /** Уровень серьёзности */
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

// ============================================================================
// ТИПЫ TLS КОНФИГУРАЦИИ
// ============================================================================

/**
 * Версия TLS
 */
export enum TlsVersion {
  TLS1_0 = 'TLS1.0',
  TLS1_1 = 'TLS1.1',
  TLS1_2 = 'TLS1.2',
  TLS1_3 = 'TLS1.3'
}

/**
 * Конфигурация TLS
 */
export interface TlsConfiguration {
  /** Минимальная версия TLS */
  minVersion: TlsVersion;
  
  /** Максимальная версия TLS */
  maxVersion: TlsVersion;
  
  /** Разрешённые наборы шифров */
  cipherSuites: string[];
  
  /** Кривые для ECDHE */
  curves: string[];
  
  /** Режим аутентификации */
  authenticationMode: 'SERVER' | 'MUTUAL';
  
  /** Сертификаты */
  certificates: {
    /** Сертификат сервера */
    serverCert: string;
    /** Закрытый ключ сервера */
    serverKey: string;
    /** CA сертификат */
    caCert: string;
    /** CRL / OCSP */
    revocationList?: string;
  };
  
  /** Настройки сессии */
  session: {
    /** Включить session tickets */
    ticketsEnabled: boolean;
    /** Timeout сессии */
    timeout: number;
    /** Размер кэша сессий */
    cacheSize: number;
  };
  
  /** HSTS настройки */
  hsts?: {
    /** Включить HSTS */
    enabled: boolean;
    /** Max-age */
    maxAge: number;
    /** Включить subdomains */
    includeSubDomains: boolean;
    /** Включить preload */
    preload: boolean;
  };
}

// ============================================================================
// ТИПЫ РЕШЕНИЙ И СОБЫТИЙ
// ============================================================================

/**
 * Результат проверки политики
 */
export interface PolicyEvaluationResult {
  /** Уникальный идентификатор оценки */
  evaluationId: string;
  
  /** Время оценки */
  evaluatedAt: Date;
  
  /** Решение */
  decision: PolicyDecision;
  
  /** Уровень доверия */
  trustLevel: TrustLevel;
  
  /** Применённые правила */
  appliedRules: {
    /** ID правила */
    ruleId: string;
    /** Название правила */
    ruleName: string;
    /** Эффект правила */
    effect: 'ALLOW' | 'DENY';
  }[];
  
  /** Факторы, повлиявшие на решение */
  factors: {
    /** Фактор */
    name: string;
    /** Значение */
    value: string | number | boolean;
    /** Вес фактора */
    weight: number;
    /** Влияние на решение */
    impact: 'POSITIVE' | 'NEGATIVE' | 'NEUTRAL';
  }[];
  
  /** Ограничения доступа */
  restrictions: {
    /** Ограничения по времени */
    timeLimit?: number;
    /** Ограничения по операциям */
    operationLimit?: PolicyOperation[];
    /** Ограничения по данным */
    dataLimit?: string[];
    /** Требуется step-up аутентификация */
    requireStepUp?: boolean;
  };
  
  /** Рекомендации */
  recommendations: string[];
  
  /** Токен доступа (если разрешено) */
  accessToken?: string;
}

/**
 * Событие безопасности Zero Trust
 */
export interface ZeroTrustEvent {
  /** Уникальный идентификатор события */
  eventId: string;
  
  /** Тип события */
  eventType: 
    | 'ACCESS_REQUEST'
    | 'ACCESS_GRANTED'
    | 'ACCESS_DENIED'
    | 'TRUST_LEVEL_CHANGED'
    | 'DEVICE_POSTURE_CHANGED'
    | 'POLICY_VIOLATION'
    | 'SESSION_CREATED'
    | 'SESSION_TERMINATED'
    | 'CERTIFICATE_ISSUED'
    | 'CERTIFICATE_REVOKED'
    | 'JIT_ACCESS_REQUESTED'
    | 'JIT_ACCESS_GRANTED'
    | 'JIT_ACCESS_EXPIRED'
    | 'DLP_EVENT'
    | 'THREAT_DETECTED';
  
  /** Время события */
  timestamp: Date;
  
  /** Субъект */
  subject: {
    /** ID субъекта */
    id: string;
    /** Тип субъекта */
    type: SubjectType;
    /** Имя */
    name: string;
  };
  
  /** Ресурс */
  resource?: {
    /** Тип ресурса */
    type: ResourceType;
    /** ID ресурса */
    id: string;
    /** Имя ресурса */
    name: string;
  };
  
  /** Контекст */
  context?: {
    /** IP адрес */
    ipAddress: string;
    /** User agent */
    userAgent?: string;
    /** ID устройства */
    deviceId?: string;
    /** ID сессии */
    sessionId?: string;
    /** ID запроса */
    requestId?: string;
  };
  
  /** Детали события */
  details: Record<string, unknown>;
  
  /** Уровень серьёзности */
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  
  /** Корреляционный ID */
  correlationId: string;
}

// ============================================================================
// ТИПЫ ЗАПРОСОВ И ОТВЕТОВ ДОСТУПА
// ============================================================================

/**
 * Запрос доступа к ресурсу
 */
export interface AccessRequest {
  /** Уникальный идентификатор запроса */
  requestId: string;

  /** Идентичность субъекта */
  identity: Identity;

  /** Контекст аутентификации */
  authContext: AuthContext;

  /** Состояние устройства */
  devicePosture?: DevicePosture;

  /** Тип ресурса */
  resourceType: ResourceType;

  /** ID ресурса */
  resourceId: string;

  /** Запрошенная операция */
  operation: PolicyOperation;

  /** IP адрес источника */
  sourceIp: string;

  /** IP адрес назначения */
  destinationIp?: string;

  /** Порт назначения */
  destinationPort?: number;

  /** Протокол */
  protocol?: string;

  /** Дополнительные метаданные */
  metadata?: Record<string, unknown>;

  /** Имя ресурса */
  resourceName?: string;

  /** Атрибуты ресурса */
  resourceAttributes?: Record<string, unknown>;

  /** Часовой пояс */
  timezone?: string;

  /** Необычное ли местоположение */
  isUnusualLocation?: boolean;

  /** Необычное ли время */
  isUnusualTime?: boolean;

  /** Необычное ли устройство */
  isUnusualDevice?: boolean;

  /** Аномальное ли поведение */
  isAnomalousBehavior?: boolean;

  /** Оценка риска */
  riskScore?: number;
}

/**
 * Ответ на запрос доступа
 */
export interface AccessResponse {
  /** Уникальный идентификатор ответа */
  responseId: string;

  /** ID запроса */
  requestId: string;

  /** Решение */
  decision: PolicyDecision;

  /** Уровень доверия */
  trustLevel: TrustLevel;

  /** Время принятия решения */
  decidedAt: Date;

  /** Применённые правила */
  appliedRules: {
    ruleId: string;
    ruleName: string;
    effect: 'ALLOW' | 'DENY';
  }[];

  /** Ограничения доступа */
  restrictions?: {
    timeLimit?: number;
    operationLimit?: PolicyOperation[];
    dataLimit?: string[];
    requireStepUp?: boolean;
  };

  /** Токен доступа (если разрешено) */
  accessToken?: string;

  /** Время истечения доступа */
  expiresAt?: Date;

  /** Причина отказа (если отказано) */
  denialReason?: string;

  /** Причина решения */
  reason?: string;

  /** Рекомендации */
  recommendations?: string[];

  /** Оценка риска */
  riskAssessment?: {
    level: string;
    score: number;
    factors: string[];
  };

  /** Метаданные */
  metadata?: Record<string, unknown>;

  /** Кэшировано ли решение */
  cached?: boolean;

  /** Время оценки (мс) */
  evaluationTime?: number;

  /** Timestamp */
  timestamp?: Date;
}
