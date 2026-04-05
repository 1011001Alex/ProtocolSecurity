/**
 * ============================================================================
 * ATTESTATION TYPES — ТИПЫ ДЛЯ МОДУЛЯ АТТЕСТАЦИИ ЦЕЛОСТНОСТИ
 * ============================================================================
 * Определяет структуры данных для Runtime Bill of Materials (RBOM),
 * attestation reports, drift detection и integrity monitoring.
 * ============================================================================
 */

/** Статус компонента при сравнении SBOM ↔ RBOM */
export type ComponentStatus = 'expected' | 'unexpected' | 'modified' | 'missing';

/** Severity уровня drift (отклонения) */
export type DriftSeverity = 'critical' | 'high' | 'medium' | 'low' | 'none';

/** Тип аттестации */
export type AttestationType = 'initial' | 'periodic' | 'on-demand' | 'event-driven';

/** Информация о пакете */
export interface PackageInfo {
  name: string;
  version: string;
  hash: string;           // SHA-256 hash файла package.json или модуля
  path: string;
  status: ComponentStatus;
}

/** Информация о сервисе */
export interface ServiceInfo {
  name: string;
  protocol: string;
  host: string;
  port: number;
  tlsEnabled: boolean;
  status: ComponentStatus;
}

/** Информация о соединении */
export interface ConnectionInfo {
  remoteAddress: string;
  remotePort: number;
  localPort: number;
  protocol: 'tcp' | 'udp' | 'tls' | 'http' | 'https';
  state: 'ESTABLISHED' | 'LISTENING' | 'TIME_WAIT' | 'CLOSE_WAIT';
}

/** Состояние криптографии */
export interface CryptoState {
  algorithms: string[];           // Активные алгоритмы
  keyFingerprints: string[];      // Fingerprints ключей (не сами ключи!)
  tlsVersion: string;
  cipherSuite: string;
}

/** Отчёт аттестации — криптографическое доказательство состояния runtime */
export interface AttestationReport {
  reportId: string;
  timestamp: Date;
  type: AttestationType;
  componentHashes: Record<string, string>;  // module path → SHA-256 hash
  loadedPackages: PackageInfo[];
  activeServices: ServiceInfo[];
  activeConnections: ConnectionInfo[];
  cryptoState: CryptoState;
  environmentHash: string;        // Hash env vars (без значений — только ключи + hash значений)
  memoryFootprint: number;        // RSS в байтах
  uptime: number;                 // ms
  pid: number;
  previousReportHash: string;     // Hash предыдущего отчёта (hash chain)
  signature: string;              // HMAC всего отчёта
}

/** Компонент в RBOM */
export interface RBOMComponent {
  type: 'library' | 'framework' | 'container' | 'service' | 'crypto' | 'config' | 'runtime';
  name: string;
  version: string;
  hash: string;
  path: string;
  status: ComponentStatus;
  licenses?: string[];
  purl?: string;   // Package URL (package-url specification)
}

/** Сервис в RBOM */
export interface RBOMService {
  name: string;
  protocol: string;
  endpoints: string[];
  authentication: string;
  tlsVersion: string;
}

/** Runtime Bill of Materials */
export interface RBOM {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;             // UUID
  version: number;
  metadata: {
    timestamp: Date;
    component: {
      name: string;
      version: string;
      type: 'application';
    };
    attestationReportId: string;
  };
  components: RBOMComponent[];
  services: RBOMService[];
  dependencies: { ref: string; dependsOn: string[] }[];
  attestations: {
    reportId: string;
    timestamp: Date;
    hash: string;
    verified: boolean;
  }[];
}

/** Модифицированный компонент (при сравнении SBOM ↔ RBOM) */
export interface ModifiedComponent {
  name: string;
  expectedVersion: string;
  actualVersion: string;
  expectedHash: string;
  actualHash: string;
  riskDescription: string;
}

/** Отчёт о drift (отклонении SBOM от RBOM) */
export interface DriftReport {
  driftId: string;
  timestamp: Date;
  sbomHash: string;
  rbomSerialNumber: string;
  missing: RBOMComponent[];         // В SBOM есть, но НЕ загружено в runtime
  unexpected: RBOMComponent[];      // Загружено в runtime, но НЕТ в SBOM (potential injection!)
  modified: ModifiedComponent[];    // Версии/хэши не совпадают
  severity: DriftSeverity;
  riskSummary: string;
  recommendation: string;
  attestationReportId: string;
  signature: string;
}

/** Конфигурация IntegrityMonitor */
export interface IntegrityMonitorConfig {
  /** Интервал периодической аттестации (ms) */
  attestationInterval: number;
  /** Включить automatic alerts при drift */
  autoAlert: boolean;
  /** Включить hash chain для immutability */
  enableHashChain: boolean;
  /** HMAC secret для подписи отчётов */
  hmacSecret: string;
  /** Путь к SBOM файлу для сравнения */
  sbomPath?: string;
  /** Максимальная длина истории аттестаций */
  maxHistoryLength: number;
  /** Логировать каждую аттестацию */
  logEachAttestation: boolean;
}

/** Результат верификации аттестации */
export interface AttestationVerification {
  reportId: string;
  verified: boolean;
  signatureValid: boolean;
  hashChainValid: boolean;
  driftDetected: boolean;
  driftReport?: DriftReport;
  timestamp: Date;
  errors: string[];
}

/** Событие IntegrityMonitor */
export interface IntegrityEvent {
  eventId: string;
  timestamp: Date;
  type: 'attestation_completed' | 'drift_detected' | 'verification_failed' | 'hash_chain_broken' | 'monitor_started' | 'monitor_stopped';
  severity: DriftSeverity;
  message: string;
  details?: Record<string, unknown>;
}

/** Статистика IntegrityMonitor */
export interface IntegrityMonitorStats {
  totalAttestations: number;
  totalDriftsDetected: number;
  lastAttestationTime: Date | null;
  lastDriftTime: Date | null;
  currentSeverity: DriftSeverity;
  historyLength: number;
  uptime: number;
  averageAttestationTimeMs: number;
}
