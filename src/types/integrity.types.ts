/**
 * ============================================================================
 * ТИПЫ И ИНТЕРФЕЙСЫ СИСТЕМЫ КОНТРОЛЯ ЦЕЛОСТНОСТИ
 * ============================================================================
 * Полная типизация для всех компонентов системы integrity
 * Включает типы для: Code Signing, FIM, Merkle Tree, SBOM, SLSA, Transparency Log
 */

import type { EventEmitter } from 'events';
import type { Readable, Writable } from 'stream';

// ============================================================================
// БАЗОВЫЕ ТИПЫ ХЕШИРОВАНИЯ
// ============================================================================

/**
 * Алгоритмы хеширования, поддерживаемые системой
 */
export type HashAlgorithm = 
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'SHA3-256'
  | 'SHA3-512'
  | 'BLAKE2b'
  | 'BLAKE3';

/**
 * Результат хеширования файла
 */
export interface FileHash {
  /** Полный путь к файлу */
  filePath: string;
  /** Алгоритм хеширования */
  algorithm: HashAlgorithm;
  /** Hex представление хеша */
  hash: string;
  /** Размер файла в байтах */
  size: number;
  /** Время последнего изменения */
  mtime: Date;
  /** Время создания хеша */
  hashedAt: Date;
  /** Дополнительные метаданные */
  metadata?: Record<string, unknown>;
}

/**
 * Результат хеширования нескольких файлов
 */
export interface HashResult {
  /** Список хешей файлов */
  files: FileHash[];
  /** Общий хеш всех файлов (Merkle root) */
  rootHash: string;
  /** Время создания результата */
  timestamp: Date;
  /** Ошибки при хешировании */
  errors: HashError[];
}

/**
 * Ошибка хеширования
 */
export interface HashError {
  /** Путь к файлу */
  filePath: string;
  /** Код ошибки */
  code: string;
  /** Сообщение об ошибке */
  message: string;
  /** Stack trace */
  stack?: string;
}

// ============================================================================
// ТИПЫ CODE SIGNING (GPG/SSH/X.509)
// ============================================================================

/**
 * Типы поддерживаемых подписей
 */
export type SignatureType = 'GPG' | 'SSH' | 'X509' | 'COSIGN';

/**
 * Конфигурация подписывающего ключа
 */
export interface SigningKeyConfig {
  /** Тип ключа */
  type: SignatureType;
  /** Идентификатор ключа (fingerprint, serial, etc.) */
  keyId: string;
  /** Путь к файлу ключа */
  keyPath?: string;
  /** Путь к сертификату (для X.509) */
  certificatePath?: string;
  /** Путь к цепочке CA (для X.509) */
  caChainPath?: string;
  /** Passphrase для ключа */
  passphrase?: string;
  /** Хранитель ключа (HSM, KMS, file) */
  keyStore: 'file' | 'hsm' | 'kms' | 'env';
  /** Дополнительные параметры */
  options?: Record<string, unknown>;
}

/**
 * Результат подписания
 */
export interface SignatureResult {
  /** Тип подписи */
  type: SignatureType;
  /** Hex представление подписи */
  signature: string;
  /** Алгоритм подписания */
  algorithm: string;
  /** Идентификатор ключа */
  keyId: string;
  /** Время подписания */
  signedAt: Date;
  /** Срок действия подписи */
  expiresAt?: Date;
  /** Сертификат (для X.509/Cosign) */
  certificate?: string;
  /** Доказательства (для Cosign) */
  proof?: Record<string, unknown>;
  /** Сырые данные подписи */
  rawSignature?: Buffer;
}

/**
 * Результат верификации подписи
 */
export interface SignatureVerificationResult {
  /** Верифицировано ли */
  verified: boolean;
  /** Тип подписи */
  type: SignatureType;
  /** Идентификатор ключа */
  keyId: string;
  /** Время проверки */
  verifiedAt: Date;
  /** Ошибки верификации */
  errors: string[];
  /** Предупреждения */
  warnings: string[];
  /** Информация о подписанте */
  signerInfo?: SignerInfo;
  /** Статус сертификата */
  certificateStatus?: CertificateStatus;
}

/**
 * Информация о подписанте
 */
export interface SignerInfo {
  /** Имя */
  name?: string;
  /** Email */
  email?: string;
  /** Организация */
  organization?: string;
  /** Публичный ключ */
  publicKey?: string;
  /** Доверен ли ключ */
  trusted: boolean;
}

/**
 * Статус сертификата X.509
 */
export interface CertificateStatus {
  /** Валиден ли сертификат */
  valid: boolean;
  /** Выдан кем */
  issuer: string;
  /** Выдан кому */
  subject: string;
  /** Действителен с */
  notBefore: Date;
  /** Действителен до */
  notAfter: Date;
  /** Серийный номер */
  serialNumber: string;
  /** Статус отзыва */
  revoked: boolean;
  /** CRL/OCSP информация */
  revocationInfo?: RevocationInfo;
}

/**
 * Информация об отзыве сертификата
 */
export interface RevocationInfo {
  /** Тип проверки (CRL/OCSP) */
  type: 'CRL' | 'OCSP';
  /** Время проверки */
  checkedAt: Date;
  /** Причина отзыва */
  reason?: string;
  /** Время отзыва */
  revokedAt?: Date;
}

// ============================================================================
// ТИПЫ FILE INTEGRITY MONITORING (FIM)
// ============================================================================

/**
 * Типы событий файловой системы
 */
export type FileEventType = 
  | 'created'
  | 'modified'
  | 'deleted'
  | 'renamed'
  | 'permission_changed'
  | 'attribute_changed';

/**
 * Событие изменения файла
 */
export interface FileEvent {
  /** Тип события */
  type: FileEventType;
  /** Путь к файлу */
  filePath: string;
  /** Новый путь (для rename) */
  newFilePath?: string;
  /** Старый хеш */
  oldHash?: string;
  /** Новый хеш */
  newHash?: string;
  /** Старый размер */
  oldSize?: number;
  /** Новый размер */
  newSize?: number;
  /** Время события */
  timestamp: Date;
  /** Детали события */
  details: FileEventDetails;
}

/**
 * Детали события файла
 */
export interface FileEventDetails {
  /** Изменения прав доступа */
  permissions?: {
    old: string;
    new: string;
  };
  /** Изменения владельца */
  owner?: {
    old: { uid: number; gid: number };
    new: { uid: number; gid: number };
  };
  /** Изменения атрибутов */
  attributes?: {
    added: string[];
    removed: string[];
  };
  /** Причина изменения (если известна) */
  cause?: string;
  /** Процесс, вызвавший изменение */
  process?: {
    pid: number;
    name: string;
  };
}

/**
 * Конфигурация мониторинга директории
 */
export interface WatchConfig {
  /** Путь для мониторинга */
  path: string;
  /** Глобы для включения */
  include?: string[];
  /** Глобы для исключения */
  exclude?: string[];
  /** Рекурсивный мониторинг */
  recursive: boolean;
  /** Интервал опроса (ms) */
  pollInterval?: number;
  /** Использовать ли native fs.watch */
  usePolling: boolean;
  /** Игнорировать начальные события */
  ignoreInitial: boolean;
  /** Задержка перед событием (ms) */
  debounceDelay: number;
}

/**
 * Статус File Integrity Monitor
 */
export interface FIMStatus {
  /** Активен ли мониторинг */
  isActive: boolean;
  /** Количество наблюдаемых файлов */
  watchedFiles: number;
  /** Количество событий */
  eventsCount: number;
  /** Последние события */
  recentEvents: FileEvent[];
  /** Ошибки */
  errors: Error[];
  /** Время начала */
  startedAt?: Date;
  /** Время последнего события */
  lastEventAt?: Date;
}

// ============================================================================
// ТИПЫ MERKLE TREE
// ============================================================================

/**
 * Узел дерева Меркла
 */
export interface MerkleNode {
  /** Хеш узла */
  hash: string;
  /** Левый потомок */
  left?: MerkleNode;
  /** Правый потомок */
  right?: MerkleNode;
  /** Данные листа (для листовых узлов) */
  data?: MerkleLeafData;
  /** Высота узла */
  height: number;
}

/**
 * Данные листового узла
 */
export interface MerkleLeafData {
  /** Путь к файлу */
  filePath: string;
  /** Хеш файла */
  fileHash: string;
  /** Индекс в дереве */
  index: number;
}

/**
 * Доказательство Меркла (Merkle Proof)
 */
export interface MerkleProof {
  /** Хеш листа */
  leaf: string;
  /** Путь к листу (индексы) */
  path: number[];
  /** Соседние хеши для верификации */
  siblings: { hash: string; position: 'left' | 'right' }[];
  /** Корневой хеш */
  root: string;
}

/**
 * Результат верификации Merkle proof
 */
export interface MerkleVerificationResult {
  /** Верифицировано ли */
  verified: boolean;
  /** Вычисленный корень */
  computedRoot: string;
  /** Ожидаемый корень */
  expectedRoot: string;
  /** Ошибки */
  errors: string[];
}

// ============================================================================
// ТИПЫ SBOM (SOFTWARE BILL OF MATERIALS)
// ============================================================================

/**
 * Форматы SBOM
 */
export type SBOMFormat = 'SPDX' | 'CycloneDX' | 'SWID';

/**
 * SBOM документ
 */
export interface SBOMDocument {
  /** Формат SBOM */
  format: SBOMFormat;
  /** Версия спецификации */
  specVersion: string;
  /** Уникальный идентификатор SBOM */
  id: string;
  /** Имя продукта */
  productName: string;
  /** Версия продукта */
  productVersion: string;
  /** Поставщик */
  supplier: SBOMSupplier;
  /** Время создания */
  createdAt: Date;
  /** Компоненты */
  components: SBOMComponent[];
  /** Зависимости */
  dependencies: SBOMDependency[];
  /** Уязвимости */
  vulnerabilities?: SBOMVulnerability[];
  /** Лицензии */
  licenses: SBOMLicense[];
  /** Метаданные */
  metadata: SBOMMetadata;
}

/**
 * Поставщик в SBOM
 */
export interface SBOMSupplier {
  /** Имя */
  name: string;
  /** URL */
  url?: string;
  /** Контакт */
  contact?: string;
}

/**
 * Компонент в SBOM
 */
export interface SBOMComponent {
  /** Тип компонента */
  type: 'library' | 'application' | 'framework' | 'container' | 'file' | 'os';
  /** Имя */
  name: string;
  /** Версия */
  version: string;
  /** Поставщик */
  supplier?: string;
  /** Лицензии */
  licenses: string[];
  /** Хеш компонента */
  hashes: { algorithm: string; value: string }[];
  /** PURL (Package URL) */
  purl?: string;
  /** CPE (Common Platform Enumeration) */
  cpe?: string;
  /** Описание */
  description?: string;
  /** Внешние ссылки */
  externalReferences?: SBOMExternalReference[];
}

/**
 * Зависимость в SBOM
 */
export interface SBOMDependency {
  /** Ref компонента */
  ref: string;
  /** Зависимости */
  dependsOn: string[];
}

/**
 * Уязвимость в SBOM
 */
export interface SBOMVulnerability {
  /** ID уязвимости (CVE) */
  id: string;
  /** Источник */
  source: string;
  /** Затронутые компоненты */
  affectedComponents: string[];
  /** Оценка CVSS */
  cvss?: {
    version: string;
    score: number;
    vector: string;
  };
  /** Описание */
  description?: string;
  /** Рекомендации */
  recommendation?: string;
}

/**
 * Лицензия в SBOM
 */
export interface SBOMLicense {
  /** ID лицензии */
  id: string;
  /** Название */
  name: string;
  /** URL текста лицензии */
  url?: string;
}

/**
 * Внешняя ссылка в SBOM
 */
export interface SBOMExternalReference {
  /** Тип ссылки */
  type: 'vcs' | 'issue-tracker' | 'website' | 'advisories' | 'bom' | 'mailing-list' | 'social' | 'chat' | 'documentation' | 'support' | 'distribution' | 'license' | 'build-meta' | 'other';
  /** URL */
  url: string;
  /** Комментарий */
  comment?: string;
}

/**
 * Метаданные SBOM
 */
export interface SBOMMetadata {
  /** Авторы */
  authors: { name: string; email?: string }[];
  /** Инструмент создания */
  tools: { name: string; version: string }[];
  /** Время сборки */
  buildTimestamp?: Date;
  /** Сборщик */
  buildHost?: string;
}

// ============================================================================
// ТИПЫ SLSA (SUPPLY-CHAIN LEVELS FOR SOFTWARE ARTIFACTS)
// ============================================================================

/**
 * Уровни SLSA
 */
export type SLSALevel = 0 | 1 | 2 | 3 | 4;

/**
 * Результат верификации SLSA
 */
export interface SLSAVerificationResult {
  /** Достигнутый уровень */
  achievedLevel: SLSALevel;
  /** Требуемый уровень */
  requiredLevel: SLSALevel;
  /** Соответствует ли требованиям */
  compliant: boolean;
  /** Время проверки */
  verifiedAt: Date;
  /** Доказательства */
  provenance?: SLSAProvenance;
  /** Проверки по уровням */
  levelChecks: SLSALevelCheck[];
  /** Ошибки */
  errors: string[];
  /** Предупреждения */
  warnings: string[];
}

/**
 * Проверка уровня SLSA
 */
export interface SLSALevelCheck {
  /** Уровень */
  level: SLSALevel;
  /** Название проверки */
  check: string;
  /** Описание требования */
  requirement: string;
  /** Пройдена ли */
  passed: boolean;
  /** Доказательства */
  evidence?: string[];
  /** Ошибки */
  errors?: string[];
}

/**
 * SLSA Provenance (доказательство происхождения)
 */
export interface SLSAProvenance {
  /** Формат */
  format: 'SLSA' | 'in-toto';
  /** Версия спецификации */
  specVersion: string;
  /** Сборщик */
  builder: {
    id: string;
    version?: string;
  };
  /** Сборка */
  build: {
    buildType: string;
    invokedBy?: {
      id: string;
      caller?: string;
    };
    externalParameters?: Record<string, unknown>;
    internalParameters?: Record<string, unknown>;
    resolvedDependencies?: {
      uri: string;
      digest?: Record<string, string>;
    }[];
  };
  /** Метаданные */
  metadata: {
    buildInvocationId: string;
    buildStartedOn?: Date;
    buildFinishedOn?: Date;
    completeness?: {
      parameters: boolean;
      environment: boolean;
      materials: boolean;
    };
    reproducible?: boolean;
  };
  /** Артефакты */
  artifacts: {
    name: string;
    digest: Record<string, string>;
  }[];
  /** Подпись */
  signature?: SignatureResult;
}

// ============================================================================
// ТИПЫ TRANSPARENCY LOG
// ============================================================================

/**
 * Запись в transparency log
 */
export interface TransparencyLogEntry {
  /** Уникальный ID записи */
  uuid: string;
  /** Тип записи */
  kind: 'intoto' | 'hashedrekord' | 'dsse' | 'rpm' | 'jar' | 'other';
  /** API версия */
  apiVersion: string;
  /** Spec записи */
  spec: Record<string, unknown>;
  /** Время записи */
  timestamp: Date;
  /** Интегрированное время */
  integratedTime: Date;
  /** Log ID */
  logID: string;
  /** Log Index */
  logIndex: number;
  /** Root Hash на момент записи */
  rootHash: string;
  /** Tree Size */
  treeSize: number;
  /** Inclusion proof */
  inclusionProof?: InclusionProof;
  /** Подпись TLog */
  tlogSignature?: string;
}

/**
 * Inclusion proof для Rekor
 */
export interface InclusionProof {
  /** Log Index */
  logIndex: number;
  /** Root Hash */
  rootHash: string;
  /** Tree Size */
  treeSize: number;
  /** Hashes для верификации */
  hashes: string[];
  /**Checkpoint*/
  checkpoint?: {
    envelope: string;
  };
}

/**
 * Client конфигурация Transparency Log
 */
export interface TransparencyLogConfig {
  /** URL сервера (например, https://rekor.sigstore.dev) */
  serverUrl: string;
  /** Публичный ключ TLog */
  publicKey?: string;
  /** Таймаут запросов (ms) */
  timeout: number;
  /** Максимум retries */
  maxRetries: number;
  /** Backoff multiplier */
  retryMultiplier: number;
}

/**
 * Результат поиска в TLog
 */
export interface TLogSearchResult {
  /** Найдено записей */
  count: number;
  /** Записи */
  entries: TransparencyLogEntry[];
  /** Время поиска */
  searchedAt: Date;
}

// ============================================================================
// ТИПЫ RUNTIME VERIFICATION
// ============================================================================

/**
 * Статус runtime верификации
 */
export interface RuntimeVerificationStatus {
  /** Верифицировано ли */
  verified: boolean;
  /** Время проверки */
  verifiedAt: Date;
  /** Проверенные компоненты */
  components: RuntimeComponentStatus[];
  /** Нарушения целостности */
  violations: IntegrityViolation[];
  /** Общая оценка */
  score: number;
}

/**
 * Статус компонента runtime
 */
export interface RuntimeComponentStatus {
  /** Имя компонента */
  name: string;
  /** Тип */
  type: 'binary' | 'library' | 'config' | 'script';
  /** Путь */
  path: string;
  /** Ожидаемый хеш */
  expectedHash: string;
  /** Текущий хеш */
  currentHash: string;
  /** Соответствует ли */
  matches: boolean;
  /** Загружен ли в память */
  loaded: boolean;
  /** PID процесса (если применимо) */
  pid?: number;
}

/**
 * Нарушение целостности
 */
export interface IntegrityViolation {
  /** Тип нарушения */
  type: 'hash_mismatch' | 'missing_file' | 'unauthorized_modification' | 'signature_invalid' | 'certificate_expired' | 'rollback_detected';
  /** Серьезность */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Путь к файлу */
  filePath: string;
  /** Описание */
  description: string;
  /** Время обнаружения */
  detectedAt: Date;
  /** Детали */
  details: Record<string, unknown>;
  /** Рекомендуемые действия */
  remediation?: string[];
}

// ============================================================================
// ТИПЫ BASELINE MANAGER
// ============================================================================

/**
 * Базовая линия целостности
 */
export interface IntegrityBaseline {
  /** ID базовой линии */
  id: string;
  /** Название */
  name: string;
  /** Описание */
  description: string;
  /** Версия */
  version: string;
  /** Время создания */
  createdAt: Date;
  /** Создатель */
  createdBy: string;
  /** Хеш базовой линии */
  baselineHash: string;
  /** Подпись базовой линии */
  signature?: SignatureResult;
  /** Файлы в базовой линии */
  files: FileHash[];
  /** Корневой хеш Merkle tree */
  merkleRoot: string;
  /** Доказательства Merkle */
  merkleProofs: Record<string, MerkleProof>;
  /** Метаданные */
  metadata: BaselineMetadata;
}

/**
 * Метаданные базовой линии
 */
export interface BaselineMetadata {
  /** Окружение */
  environment: 'development' | 'staging' | 'production' | 'test';
  /** Ветка Git */
  gitBranch?: string;
  /** Git commit */
  gitCommit?: string;
  /** Git tag */
  gitTag?: string;
  /** Build ID */
  buildId?: string;
  /** Теги */
  tags: string[];
  /** Заметки */
  notes?: string;
}

/**
 * Результат сравнения с базовой линией
 */
export interface BaselineComparisonResult {
  /** ID базовой линии */
  baselineId: string;
  /** Время сравнения */
  comparedAt: Date;
  /** Соответствует ли */
  matches: boolean;
  /** Измененные файлы */
  modified: FileChange[];
  /** Добавленные файлы */
  added: FileHash[];
  /** Удаленные файлы */
  removed: { filePath: string; lastHash: string }[];
  /** Статистика */
  statistics: {
    totalFiles: number;
    matchedFiles: number;
    modifiedFiles: number;
    addedFiles: number;
    removedFiles: number;
  };
}

/**
 * Изменение файла
 */
export interface FileChange {
  /** Путь к файлу */
  filePath: string;
  /** Старый хеш */
  oldHash: string;
  /** Новый хеш */
  newHash: string;
  /** Тип изменения */
  changeType: 'content' | 'permissions' | 'metadata';
  /** Время изменения */
  changedAt: Date;
}

// ============================================================================
// ТИПЫ HASH CHAIN
// ============================================================================

/**
 * Запись в hash chain
 */
export interface HashChainEntry {
  /** Индекс записи */
  index: number;
  /** Данные записи */
  data: string;
  /** Хеш данных */
  hash: string;
  /** Предыдущий хеш */
  previousHash: string;
  /** Время записи */
  timestamp: Date;
  /** Подпись записи */
  signature?: string;
}

/**
 * Hash chain
 */
export interface HashChain {
  /** ID цепи */
  id: string;
  /** Название */
  name: string;
  /** Записи */
  entries: HashChainEntry[];
  /** Текущий хеш */
  currentHash: string;
  /** Время создания */
  createdAt: Date;
  /** Последнее обновление */
  updatedAt: Date;
}

// ============================================================================
// ТИПЫ MODIFICATION DETECTOR
// ============================================================================

/**
 * Результат детекции модификаций
 */
export interface ModificationDetectionResult {
  /** Время проверки */
  checkedAt: Date;
  /** Обнаружены ли модификации */
  modificationsDetected: boolean;
  /** Типы модификаций */
  modificationTypes: ModificationType[];
  /** Детали модификаций */
  modifications: DetectedModification[];
  /** Оценка риска */
  riskScore: number;
  /** Рекомендации */
  recommendations: string[];
}

/**
 * Типы модификаций
 */
export type ModificationType = 
  | 'content_change'
  | 'permission_change'
  | 'ownership_change'
  | 'timestamp_manipulation'
  | 'file_swap'
  | 'injection'
  | 'deletion'
  | 'addition';

/**
 * Обнаруженная модификация
 */
export interface DetectedModification {
  /** Тип */
  type: ModificationType;
  /** Путь к файлу */
  filePath: string;
  /** Описание */
  description: string;
  /** Серьезность */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Индикаторы компрометации */
  iocs: string[];
  /** Время обнаружения */
  detectedAt: Date;
  /** Контекст */
  context?: Record<string, unknown>;
}

// ============================================================================
// ТИПЫ INTEGRITY SERVICE
// ============================================================================

/**
 * Конфигурация Integrity Service
 */
export interface IntegrityServiceConfig {
  /** Путь к хранилищу */
  storagePath: string;
  /** Алгоритм хеширования по умолчанию */
  defaultHashAlgorithm: HashAlgorithm;
  /** Конфигурация подписания */
  signing?: SigningKeyConfig;
  /** Конфигурация FIM */
  fim?: WatchConfig[];
  /** Конфигурация Transparency Log */
  transparencyLog?: TransparencyLogConfig;
  /** Интервал проверки (ms) */
  verificationInterval: number;
  /** Включить audit логирование */
  enableAuditLog: boolean;
  /** Путь к audit логу */
  auditLogPath?: string;
  /** Максимум записей в памяти */
  maxInMemoryEntries: number;
  /** SLSA требования */
  slsaRequirements?: {
    requiredLevel: SLSALevel;
    enforceProvenance: boolean;
  };
}

/**
 * События Integrity Service
 */
export interface IntegrityServiceEvents {
  /** Файл изменен */
  'file:modified': (event: FileEvent) => void;
  /** Нарушение обнаружено */
  'violation:detected': (violation: IntegrityViolation) => void;
  /** Подпись создана */
  'signature:created': (result: SignatureResult) => void;
  /** SBOM сгенерирован */
  'sbom:generated': (sbom: SBOMDocument) => void;
  /** Baseline обновлена */
  'baseline:updated': (baseline: IntegrityBaseline) => void;
  /** Ошибка */
  'error': (error: Error) => void;
}

/**
 * Результат полной проверки целостности
 */
export interface FullIntegrityReport {
  /** Время проверки */
  checkedAt: Date;
  /** Общая оценка */
  overallScore: number;
  /** Статус верификации */
  verificationStatus: RuntimeVerificationStatus;
  /** Статус подписей */
  signatureStatus: SignatureVerificationResult[];
  /** Статус FIM */
  fimStatus: FIMStatus;
  /** SLSA верификация */
  slsaStatus?: SLSAVerificationResult;
  /** Нарушения */
  violations: IntegrityViolation[];
  /** Рекомендации */
  recommendations: string[];
  /** Метаданные */
  metadata: {
    version: string;
    environment: string;
    hostname: string;
  };
}

/**
 * Аудит запись
 */
export interface AuditLogEntry {
  /** ID записи */
  id: string;
  /** Время */
  timestamp: Date;
  /** Тип события */
  eventType: string;
  /** Пользователь */
  user?: string;
  /** Действие */
  action: string;
  /** Ресурс */
  resource?: string;
  /** Результат */
  result: 'success' | 'failure' | 'warning';
  /** Детали */
  details?: Record<string, unknown>;
  /** IP адрес */
  ipAddress?: string;
  /** User agent */
  userAgent?: string;
}

// ============================================================================
// УТИЛИТАРНЫЕ ТИПЫ
// ============================================================================

/**
 * Результат операции
 */
export interface OperationResult<T = void> {
  /** Успешно ли */
  success: boolean;
  /** Данные результата */
  data?: T;
  /** Ошибки */
  errors: string[];
  /** Предупреждения */
  warnings: string[];
  /** Время выполнения (ms) */
  executionTime: number;
}

/**
 * Пагинация результатов
 */
export interface PaginatedResult<T> {
  /** Элементы */
  items: T[];
  /** Всего элементов */
  total: number;
  /** Страница */
  page: number;
  /** Размер страницы */
  pageSize: number;
  /** Всего страниц */
  totalPages: number;
  /** Есть ли следующая страница */
  hasNext: boolean;
  /** Есть ли предыдущая страница */
  hasPrev: boolean;
}

/**
 * Опции верификации
 */
export interface VerificationOptions {
  /** Строгость проверки */
  strictness: 'strict' | 'normal' | 'relaxed';
  /** Игнорировать определенные проверки */
  ignoreChecks?: string[];
  /** Таймаут (ms) */
  timeout?: number;
  /** Кэшировать результаты */
  cache?: boolean;
  /** Логировать детали */
  verbose?: boolean;
}

/**
 * Опции подписания
 */
export interface SigningOptions {
  /** Тип подписи */
  type: SignatureType;
  /** ID ключа */
  keyId: string;
  /** Дополнительные данные */
  additionalData?: Record<string, unknown>;
  /** Время жизни подписи */
  expiresIn?: number;
  /** Включить timestamp */
  includeTimestamp: boolean;
}
