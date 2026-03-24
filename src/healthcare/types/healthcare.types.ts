/**
 * ============================================================================
 * HEALTHCARE SECURITY TYPES & INTERFACES
 * ============================================================================
 *
 * Типы и интерфейсы для Healthcare Security Branch
 *
 * Стандарты:
 * - HIPAA (Health Insurance Portability and Accountability Act)
 * - HITECH (Health Information Technology for Economic and Clinical Health Act)
 * - FHIR R4 (Fast Healthcare Interoperability Resources)
 * - HL7 v2.x
 * - DICOM (Digital Imaging and Communications in Medicine)
 *
 * @package protocol/healthcare-security
 * @author Protocol Security Team
 * @version 1.0.0
 */

/**
 * Конфигурация Healthcare Security Module
 */
export interface HealthcareSecurityConfig {
  /** ID организации */
  organizationId: string;

  /** Название организации */
  organizationName?: string;

  /** Юрисдикция */
  jurisdiction: 'US' | 'EU' | 'UK' | 'CA' | 'AU';

  /** HIPAA compliance статус */
  hipaaCompliant: boolean;

  /** Версия HIPAA */
  hipaaVersion?: '2013' | '2020' | '2023';

  /** Конфигурация аудита */
  auditConfig?: {
    enabled: boolean;
    retentionDays: number;
  };

  /** Конфигурация compliance проверок */
  complianceConfig?: {
    autoCheckEnabled: boolean;
    checkInterval: number; // часы
    minimumScore: number;
  };

  /** Конфигурация модулей */
  modules?: {
    phiProtection?: PHIProtectionConfig;
    consentManager?: ConsentManagerConfig;
    ehrIntegration?: EHRIntegrationConfig;
    fhirSecurity?: FHIRSecurityConfig;
    deviceSecurity?: DeviceSecurityConfig;
    telehealthSecurity?: TelehealthSecurityConfig;
    identity?: IdentityConfig;
  };
}

/**
 * PHI Protection конфигурация
 */
export interface PHIProtectionConfig {
  /** Алгоритм шифрования */
  encryptionAlgorithm: 'AES-256-GCM' | 'AES-128-CBC' | 'ChaCha20-Poly1305';

  /** Метод де-идентификации */
  deidentificationMethod: 'SAFE_HARBOR' | 'EXPERT_DETERMINATION' | 'LIMITED_DATA_SET';

  /** Ключ шифрования (в production из HSM) */
  encryptionKey?: Buffer;
}

/**
 * Consent Manager конфигурация
 */
export interface ConsentManagerConfig {
  /** Типы согласий */
  consentTypes: ConsentType[];

  /** Требуется ли согласие для исследований */
  researchConsentRequired: boolean;

  /** Emergency break-glass доступ разрешён */
  emergencyAccessEnabled: boolean;

  /** Максимальный срок действия согласия (дни) */
  maxConsentDurationDays?: number;
}

/**
 * EHR Integration конфигурация
 */
export interface EHRIntegrationConfig {
  /** EHR система */
  ehrSystem: 'epic' | 'cerner' | 'allscripts' | 'meditech' | 'custom';

  /** FHIR базовый URL */
  fhirBaseUrl: string;

  /** OAuth конфигурация */
  oauthConfig?: {
    clientId: string;
    clientSecret: string;
    tokenEndpoint: string;
  };

  /** HL7 конфигурация */
  hl7Config?: {
    enabled: boolean;
    version: 'v2.3' | 'v2.4' | 'v2.5' | 'v2.6' | 'v2.7' | 'v2.8' | 'v2.9';
    host: string;
    port: number;
  };
}

/**
 * FHIR Security конфигурация
 */
export interface FHIRSecurityConfig {
  /** FHIR базовый URL */
  baseUrl: string;

  /** OAuth конфигурация */
  oauthConfig?: {
    clientId: string;
    clientSecret: string;
  };

  /** Требуется ли SMART on FHIR */
  smartOnFHIR: boolean;

  /** Разрешённые ресурсы */
  allowedResources: string[];
}

/**
 * Device Security конфигурация
 */
export interface DeviceSecurityConfig {
  /** Требуется ли проверка posture */
  postureCheckEnabled: boolean;

  /** Интервал проверки posture (минуты) */
  postureCheckInterval: number;

  /** Автоматический карантин при нарушении */
  autoQuarantineEnabled: boolean;
}

/**
 * Telehealth Security конфигурация
 */
export interface TelehealthSecurityConfig {
  /** Видео платформа */
  videoProvider: 'twilio' | 'zoom' | 'webex' | 'custom';

  /** Требуется ли шифрование End-to-End */
  e2eEncryptionRequired: boolean;

  /** Максимальная длительность сессии (минуты) */
  maxSessionDuration: number;
}

/**
 * Identity конфигурация
 */
export interface IdentityConfig {
  /** Уровень уверенности (Identity Assurance Level) */
  defaultIAL: 'IAL1' | 'IAL2' | 'IAL3';

  /** Требуется ли верификация NPI */
  npiVerificationRequired: boolean;

  /** Интеграция с MPI (Master Patient Index) */
  mpiIntegration: {
    enabled: boolean;
    provider: 'ibm-initiative' | 'nextgate' | 'verato' | 'custom';
  };
}

/**
 * Типы согласий пациента
 */
export type ConsentType =
  | 'TPO' // Treatment, Payment, Operations
  | 'RESEARCH'
  | 'MARKETING'
  | 'FUNDRAISING'
  | 'FAMILY_DISCLOSURE'
  | 'PSYCHOTHERAPY_NOTES'
  | 'SUBSTANCE_ABUSE'
  | 'HIV_STATUS'
  | 'GENETIC_TESTING'
  | 'ORGAN_DONATION';

/**
 * Статус согласия
 */
export type ConsentStatus =
  | 'ACTIVE'
  | 'INACTIVE'
  | 'EXPIRED'
  | 'REVOKED'
  | 'SUSPENDED'
  | 'PENDING';

/**
 * PHI (Protected Health Information) данные
 */
export interface PHIData {
  /** ID пациента */
  patientId: string;

  /** Демографические данные */
  demographics?: {
    name?: string;
    dateOfBirth?: Date;
    gender?: 'M' | 'F' | 'O' | 'U';
    address?: string;
    phone?: string;
    email?: string;
    ssn?: string;
    mrn?: string; // Medical Record Number
  };

  /** Медицинские данные */
  medicalData?: {
    diagnoses?: Diagnosis[];
    medications?: Medication[];
    allergies?: Allergy[];
    procedures?: Procedure[];
    labResults?: LabResult[];
    vitalSigns?: VitalSign[];
    clinicalNotes?: string[];
  };

  /** Метаданные */
  metadata: {
    createdAt: Date;
    updatedAt: Date;
    source: string;
    version: number;
  };
}

/**
 * Диагноз
 */
export interface Diagnosis {
  /** Код (ICD-10) */
  code: string;

  /** Описание */
  description: string;

  /** Дата диагностики */
  diagnosedAt: Date;

  /** Статус */
  status: 'ACTIVE' | 'RESOLVED' | 'CHRONIC' | 'INACTIVE';

  /** Врач */
  provider?: string;
}

/**
 * Медикамент
 */
export interface Medication {
  /** Название */
  name: string;

  /** Код (RxNorm) */
  rxNormCode?: string;

  /** Дозировка */
  dosage?: string;

  /** Частота */
  frequency?: string;

  /** Дата назначения */
  prescribedAt: Date;

  /** Статус */
  status: 'ACTIVE' | 'DISCONTINUED' | 'COMPLETED';
}

/**
 * Аллергия
 */
export interface Allergy {
  /** Название аллергена */
  allergen: string;

  /** Тип реакции */
  reactionType: string;

  /** Тяжесть */
  severity: 'MILD' | 'MODERATE' | 'SEVERE' | 'LIFE_THREATENING';

  /** Дата выявления */
  identifiedAt: Date;
}

/**
 * Процедура
 */
export interface Procedure {
  /** Название */
  name: string;

  /** Код (CPT/HCPCS) */
  cptCode?: string;

  /** Дата выполнения */
  performedAt: Date;

  /** Врач */
  provider?: string;

  /** Результат */
  outcome?: string;
}

/**
 * Результат лабораторного анализа
 */
export interface LabResult {
  /** Название теста */
  testName: string;

  /** Код (LOINC) */
  loincCode?: string;

  /** Значение */
  value: string | number;

  /** Единицы измерения */
  units?: string;

  /** Референсный диапазон */
  referenceRange?: string;

  /** Флаг отклонения */
  flag?: 'LOW' | 'HIGH' | 'CRITICAL_LOW' | 'CRITICAL_HIGH' | 'NORMAL';

  /** Дата анализа */
  analyzedAt: Date;
}

/**
 * Витальные признаки
 */
export interface VitalSign {
  /** Тип */
  type: 'BLOOD_PRESSURE' | 'HEART_RATE' | 'TEMPERATURE' | 'RESPIRATORY_RATE' | 'OXYGEN_SATURATION' | 'WEIGHT' | 'HEIGHT';

  /** Значение */
  value: number;

  /** Единицы */
  units: string;

  /** Дата измерения */
  measuredAt: Date;
}

/**
 * Согласие пациента
 */
export interface PatientConsent {
  /** ID согласия */
  consentId: string;

  /** ID пациента */
  patientId: string;

  /** Тип согласия */
  consentType: ConsentType;

  /** Статус */
  status: ConsentStatus;

  /** Предоставлено кому */
  grantedTo: string[];

  /** Дата начала действия */
  validFrom: Date;

  /** Дата окончания действия */
  validUntil?: Date;

  /** Ограничения */
  restrictions?: {
    mentalHealth?: boolean;
    substanceAbuse?: boolean;
    hivStatus?: boolean;
    geneticTesting?: boolean;
    reproductiveHealth?: boolean;
    custom?: Record<string, boolean>;
  };

  /** Цель использования */
  purpose?: string[];

  /** Дата создания */
  createdAt: Date;

  /** Дата обновления */
  updatedAt: Date;

  /** Кто создал */
  createdBy: string;

  /** Метаданные */
  metadata?: Record<string, any>;
}

/**
 * Запрос на доступ к PHI
 */
export interface PHIAccessRequest {
  /** ID запроса */
  requestId: string;

  /** ID пациента */
  patientId: string;

  /** Запрошено кем */
  requestedBy: {
    userId: string;
    role: string;
    department?: string;
    organization?: string;
  };

  /** Тип доступа */
  accessType: 'READ' | 'WRITE' | 'AMEND' | 'DISCLOSE';

  /** Цель доступа */
  purpose: 'TREATMENT' | 'PAYMENT' | 'OPERATIONS' | 'RESEARCH' | 'LEGAL' | 'PATIENT_REQUEST';

  /** Запрошенные ресурсы */
  requestedResources: string[];

  /** Обоснование */
  justification?: string;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Результат проверки доступа к PHI
 */
export interface PHIAccessDecision {
  /** Доступ разрешён */
  allowed: boolean;

  /** Причина */
  reason?: string;

  /** Требуемые действия */
  requiredActions?: string[];

  /** Ограничения доступа */
  restrictions?: {
    viewOnly: boolean;
    noDownload: boolean;
    noPrint: boolean;
    auditRequired: boolean;
  };
}

/**
 * Emergency Break-Glass доступ
 */
export interface EmergencyAccess {
  /** ID доступа */
  accessId: string;

  /** ID пациента */
  patientId: string;

  /** Запрошено кем */
  requestedBy: string;

  /** Обоснование */
  justification: string;

  /** Статус */
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'EXPIRED' | 'REVIEWED';

  /** Дата запроса */
  requestedAt: Date;

  /** Дата одобрения */
  approvedAt?: Date;

  /** Одобрено кем */
  approvedBy?: string;

  /** Дата истечения */
  expiresAt: Date;

  /** Дата закрытия */
  closedAt?: Date;

  /** Post-incident review */
  review?: {
    conducted: boolean;
    conductedAt?: Date;
    conductedBy?: string;
    findings?: string;
    actions?: string[];
  };
}

/**
 * FHIR Resource
 */
export interface FHIRResource {
  /** Тип ресурса */
  resourceType: string;

  /** ID ресурса */
  id: string;

  /** Метаданные */
  meta?: {
    versionId: string;
    lastUpdated: string;
    profile?: string[];
    tag?: { system: string; code: string; display?: string }[];
  };

  /** Данные ресурса */
  [key: string]: any;
}

/**
 * HL7 v2 сообщение
 */
export interface HL7Message {
  /** Тип сообщения */
  messageType: string;

  /** Trigger event */
  triggerEvent: string;

  /** Сегменты */
  segments: HL7Segment[];

  /** Оригинальное сообщение */
  rawMessage: string;
}

/**
 * HL7 сегмент
 */
export interface HL7Segment {
  /** ID сегмента (MSH, PID, PV1 и т.д.) */
  segmentId: string;

  /** Поля */
  fields: string[];
}

/**
 * Медицинское устройство (IoMT)
 */
export interface MedicalDevice {
  /** ID устройства */
  deviceId: string;

  /** Тип устройства */
  deviceType: DeviceType;

  /** Производитель */
  manufacturer: string;

  /** Модель */
  model: string;

  /** Серийный номер */
  serialNumber: string;

  /** Версия ПО */
  firmwareVersion?: string;

  /** Статус */
  status: 'ACTIVE' | 'INACTIVE' | 'QUARANTINED' | 'MAINTENANCE' | 'RETIRED';

  /** Дата регистрации */
  registeredAt: Date;

  /** Дата последнего подключения */
  lastSeenAt?: Date;

  /** Posture статус */
  postureStatus?: DevicePostureStatus;

  /** Назначенный пациент */
  assignedPatient?: string;

  /** Расположение */
  location?: string;

  /** Сетевая информация */
  networkInfo?: {
    ipAddress?: string;
    macAddress?: string;
    ssid?: string;
  };
}

/**
 * Тип медицинского устройства
 */
export type DeviceType =
  | 'INFUSION_PUMP'
  | 'VENTILATOR'
  | 'PATIENT_MONITOR'
  | 'DEFIBRILLATOR'
  | 'IMAGING_DEVICE'
  | 'LAB_ANALYZER'
  | 'WEARABLE'
  | 'IMPLANTABLE'
  | 'MOBILE_DEVICE'
  | 'WORKSTATION'
  | 'OTHER';

/**
 * Device Posture статус
 */
export interface DevicePostureStatus {
  /** Соответствует требованиям */
  compliant: boolean;

  /** Проблемы */
  issues: string[];

  /** Дата проверки */
  checkedAt: Date;

  /** Антивирус обновлён */
  antivirusUpdated?: boolean;

  /** ОС обновлена */
  osPatched?: boolean;

  /** Сертификаты валидны */
  certificatesValid?: boolean;

  /** Конфигурация валидна */
  configurationValid?: boolean;
}

/**
 * Telehealth сессия
 */
export interface TelehealthSession {
  /** ID сессии */
  sessionId: string;

  /** ID пациента */
  patientId: string;

  /** ID провайдера */
  providerId: string;

  /** Статус */
  status: 'SCHEDULED' | 'IN_PROGRESS' | 'COMPLETED' | 'CANCELLED' | 'NO_SHOW';

  /** Дата начала */
  scheduledStart: Date;

  /** Фактическая дата начала */
  actualStart?: Date;

  /** Дата окончания */
  actualEnd?: Date;

  /** Тип сессии */
  sessionType: 'VIDEO' | 'AUDIO' | 'CHAT' | 'HYBRID';

  /** Платформа */
  platform: string;

  /** Meeting URL/ID */
  meetingDetails?: {
    url?: string;
    meetingId?: string;
    passcode?: string;
  };

  /** Запись сессии */
  recording?: {
    enabled: boolean;
    recordingId?: string;
    storageLocation?: string;
  };
}

/**
 * MPI (Master Patient Index) запись
 */
export interface MPIRecord {
  /** Глобальный ID пациента */
  globalPatientId: string;

  /** Локальные ID */
  localIds: {
    system: string;
    id: string;
  }[];

  /** Демографические данные */
  demographics: {
    name: string;
    dateOfBirth: Date;
    gender: string;
    address?: string;
    phone?: string;
  };

  /** MPI статус */
  status: 'ACTIVE' | 'INACTIVE' | 'MERGED' | 'DUPLICATE';

  /** Связанные записи */
  linkedRecords?: string[];

  /** Дата создания */
  createdAt: Date;

  /** Дата обновления */
  updatedAt: Date;
}

/**
 * HIPAA Compliance статус
 */
export interface HIPAAComplianceStatus {
  /** Общий score */
  overallScore: number;

  /** Категории */
  categories: {
    /** Privacy Rule compliance */
    privacy: number;

    /** Security Rule compliance */
    security: number;

    /** Breach Notification Rule compliance */
    breachNotification: number;

    /** Enforcement Rule compliance */
    enforcement: number;
  };

  /** Нарушения */
  violations: ComplianceViolation[];

  /** Рекомендации */
  recommendations: string[];

  /** Дата проверки */
  checkDate: Date;
}

/**
 * Нарушение compliance
 */
export interface ComplianceViolation {
  /** ID нарушения */
  violationId: string;

  /** Категория */
  category: string;

  /** Описание */
  description: string;

  /** Тяжесть */
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  /** Дата обнаружения */
  detectedAt: Date;

  /** Статус */
  status: 'OPEN' | 'IN_PROGRESS' | 'RESOLVED' | 'CLOSED';

  /** Исправительные действия */
  remediationActions?: string[];

  /** Дата разрешения */
  resolvedAt?: Date;
}

/**
 * Breach Notification данные
 */
export interface BreachNotification {
  /** ID инцидента */
  incidentId: string;

  /** Тип нарушения */
  breachType: 'UNAUTHORIZED_ACCESS' | 'UNAUTHORIZED_DISCLOSURE' | 'LOSS' | 'THEFT' | 'HACKING';

  /** Дата нарушения */
  breachDate: Date;

  /** Дата обнаружения */
  discoveryDate: Date;

  /** Количество затронутых пациентов */
  affectedPatients: number;

  /** Описание нарушения */
  description: string;

  /** Затронутые данные */
  dataInvolved: string[];

  /** Статус уведомления */
  notificationStatus: {
    /** Уведомлены ли пациенты */
    patientsNotified: boolean;

    /** Дата уведомления пациентов */
    patientNotificationDate?: Date;

    /** Уведомлено ли HHS */
    hhsNotified: boolean;

    /** Дата уведомления HHS */
    hhsNotificationDate?: Date;

    /** Уведомлены ли СМИ */
    mediaNotified: boolean;

    /** Дата уведомления СМИ */
    mediaNotificationDate?: Date;
  };

  /** Расследование */
  investigation: {
    status: 'PENDING' | 'IN_PROGRESS' | 'COMPLETED';
    findings?: string;
    rootCause?: string;
  };
}
