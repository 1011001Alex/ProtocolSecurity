/**
 * ============================================================================
 * INTEGRITY MODULE INDEX
 * ============================================================================
 *
 * Контроль целостности кода и артефактов
 *
 * Components:
 * - Merkle Tree для верификации данных
 * - Hash Chain для audit logging
 * - Code Signing (GPG, SSH, X.509, Sigstore)
 * - File Integrity Monitoring (FIM)
 * - SBOM Generation (SPDX, CycloneDX)
 * - SLSA Provenance Verification
 * - Supply Chain Security
 *
 * @package protocol/integrity
 * @author Protocol Security Team
 * @version 3.0.0
 */

// Merkle Tree
export { MerkleTree, MerkleTreeUtils } from './MerkleTree';

// Hash Chain
export { HashChain, HashChainManager } from './HashChain';

// Code Signer
export { CodeSigner, CodeSignerFactory } from './CodeSigner';

// Artifact Signer
export { ArtifactSigner, SigstoreUtils } from './ArtifactSigner';

// File Integrity Monitor
export { FileIntegrityMonitor, FIMFactory } from './FileIntegrityMonitor';

// SBOM Generator
export { SBOMGenerator, SBOMGeneratorFactory } from './SBOMGenerator';

// Supply Chain Verifier
export { SupplyChainVerifier, SupplyChainVerifierFactory } from './SupplyChainVerifier';

// SLSA Verifier
export { SLSAVerifier, SLSAVerifierFactory } from './SLSAVerifier';

// Transparency Log
export { TransparencyLogClient, TransparencyLogClientFactory } from './TransparencyLog';

// Baseline Manager
export { BaselineManager } from './BaselineManager';

// Runtime Verifier
export { RuntimeVerifier, RuntimeVerifierFactory } from './RuntimeVerifier';

// Modification Detector
export { ModificationDetector, ModificationDetectorFactory } from './ModificationDetector';

// Integrity Service
export { IntegrityService, IntegrityServiceFactory } from './IntegrityService';

// Re-exports types from integrity.types
// Export all types (type aliases and interfaces)
export type {
  // Basic types
  HashAlgorithm,
  FileHash,
  HashResult,
  HashError,

  // Signature types
  SignatureType,
  SigningKeyConfig,
  SignatureResult,
  SignatureVerificationResult,
  SignerInfo,
  CertificateStatus,
  RevocationInfo,

  // FIM types
  FileEventType,
  FileEvent,
  FileEventDetails,
  WatchConfig,
  FIMStatus,

  // Merkle Tree types
  MerkleNode,
  MerkleLeafData,
  MerkleProof,
  MerkleVerificationResult,

  // SBOM types
  SBOMFormat,
  SBOMDocument,
  SBOMSupplier,
  SBOMComponent,
  SBOMDependency,
  SBOMVulnerability,
  SBOMLicense,
  SBOMExternalReference,
  SBOMMetadata,

  // SLSA types
  SLSALevel,
  SLSAVerificationResult,
  SLSALevelCheck,
  SLSAProvenance,

  // Transparency Log types
  TransparencyLogEntry,
  InclusionProof,
  TransparencyLogConfig,
  TLogSearchResult,

  // Runtime types
  RuntimeVerificationStatus,
  RuntimeComponentStatus,
  IntegrityViolation,

  // Baseline types
  IntegrityBaseline,
  BaselineMetadata,
  BaselineComparisonResult,
  FileChange,

  // Hash Chain types
  HashChainEntry,

  // Modification Detection types
  ModificationDetectionResult,
  ModificationType,
  DetectedModification,

  // Integrity Service types
  IntegrityServiceConfig,
  IntegrityServiceEvents,
  FullIntegrityReport,
  AuditLogEntry,
  OperationResult,
  PaginatedResult,
  VerificationOptions,
  SigningOptions,

  // Legacy type names for backward compatibility
  MerkleTreeConfig,
  HashChainConfig,
  CodeSignature,
  SigningConfig,
  SigningResult,
  ArtifactSignature,
  SigstoreConfig,
  FIMConfig,
  FIMEvent,
  SBOM,
  SBOMConfig,
  SupplyChainProof,
  VerificationResult,
  SLSAConfig,
  Baseline,
  BaselineConfig,
  RuntimeConfig,
  RuntimeCheck,
  ModificationEvent,
  DetectionConfig,
  IntegrityConfig,
  IntegrityStatus,
  IntegrityAlgorithm,
  IntegrityLevel,
  SigningKey,
  VerificationKey,
  IntegrityReport
} from '../types/integrity.types';
