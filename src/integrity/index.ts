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
export type { MerkleNode, MerkleProof, MerkleTreeConfig } from './MerkleTree';

// Hash Chain
export { HashChain, HashChainManager } from './HashChain';
export type { HashChainEntry, HashChainProof, HashChainConfig } from './HashChain';

// Code Signer
export { CodeSigner, CodeSignerFactory } from './CodeSigner';
export type { CodeSignature, SigningConfig, SigningResult } from './CodeSigner';

// Artifact Signer
export { ArtifactSigner, SigstoreUtils } from './ArtifactSigner';
export type { ArtifactSignature, SigstoreConfig } from './ArtifactSigner';

// File Integrity Monitor
export { FileIntegrityMonitor, FIMFactory } from './FileIntegrityMonitor';
export type { FileHash, HashAlgorithm, FIMConfig, FIMEvent } from './FileIntegrityMonitor';

// SBOM Generator
export { SBOMGenerator, SBOMGeneratorFactory } from './SBOMGenerator';
export type { SBOM, SBOMFormat, SBOMConfig } from './SBOMGenerator';

// Supply Chain Verifier
export { SupplyChainVerifier, SupplyChainVerifierFactory } from './SupplyChainVerifier';
export type { SupplyChainProof, VerificationResult } from './SupplyChainVerifier';

// SLSA Verifier
export { SLSAVerifier, SLSAVerifierFactory } from './SLSAVerifier';
export type { SLSAProvenance, SLSALevel, SLSAConfig } from './SLSAVerifier';

// Transparency Log
export { TransparencyLogClient, TransparencyLogClientFactory } from './TransparencyLog';
export type { TransparencyLogEntry, TransparencyLogConfig } from './TransparencyLog';

// Baseline Manager
export { BaselineManager } from './BaselineManager';
export type { Baseline, BaselineConfig } from './BaselineManager';

// Runtime Verifier
export { RuntimeVerifier, RuntimeVerifierFactory } from './RuntimeVerifier';
export type { RuntimeConfig, RuntimeCheck } from './RuntimeVerifier';

// Modification Detector
export { ModificationDetector, ModificationDetectorFactory } from './ModificationDetector';
export type { ModificationEvent, DetectionConfig } from './ModificationDetector';

// Integrity Service
export { IntegrityService, IntegrityServiceFactory } from './IntegrityService';
export type { IntegrityConfig, IntegrityStatus } from './IntegrityService';

// Re-exports from types
export type {
  IntegrityAlgorithm,
  IntegrityLevel,
  SigningKey,
  VerificationKey,
  IntegrityReport
} from '../types/integrity.types';
