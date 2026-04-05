/**
 * ============================================================================
 * ATTESTATION MODULE — ЭКСПОРТЫ МОДУЛЯ АТТЕСТАЦИИ
 * ============================================================================
 * Runtime Bill of Materials (RBOM) с Continuous Attestation
 *
 * KILLER FEATURE: Автоматическое обнаружение расхождений между тем, что
 * было собрано (SBOM), и тем, что реально работает (RBOM).
 * ============================================================================
 */

export { AttestationEngine, createAttestationEngine } from './AttestationEngine';
export { RBOMGenerator, createRBOMGenerator } from './RBOMGenerator';
export { SBOMComparator, createSBOMComparator } from './SBOMComparator';
export { IntegrityMonitor, createIntegrityMonitor } from './IntegrityMonitor';

export type { SBOM, SBOMComponent } from './SBOMComparator';

export type {
  ComponentStatus,
  DriftSeverity,
  AttestationType,
  PackageInfo,
  ServiceInfo,
  ConnectionInfo,
  CryptoState,
  AttestationReport,
  RBOM,
  RBOMComponent,
  RBOMService,
  ModifiedComponent,
  DriftReport,
  IntegrityMonitorConfig,
  AttestationVerification,
  IntegrityEvent,
  IntegrityMonitorStats
} from './attestation.types';
