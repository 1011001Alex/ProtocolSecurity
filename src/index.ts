/**
 * ============================================================================
 * PROTOCOL INTEGRITY - ЭКСПОРТ МОДУЛЕЙ
 * ============================================================================
 * Центральный файл экспорта для системы контроля целостности.
 */

// ============================================================================
// ТИПЫ
// ============================================================================
export * from './types/integrity.types';

// ============================================================================
// MERKLE TREE
// ============================================================================
export { MerkleTree, MerkleTreeUtils } from './integrity/MerkleTree';
export type {
  MerkleNode,
  MerkleProof,
  MerkleLeafData,
  MerkleVerificationResult
} from './types/integrity.types';

// ============================================================================
// HASH CHAIN
// ============================================================================
export { HashChain, HashChainManager } from './integrity/HashChain';
export type {
  HashChainEntry,
  HashChain,
  ChainData,
  HashChainConfig
} from './integrity/HashChain';

// ============================================================================
// CODE SIGNER
// ============================================================================
export { CodeSigner, CodeSignerFactory } from './integrity/CodeSigner';
export type {
  GPGSigningConfig,
  SSHSigningConfig,
  X509SigningConfig,
  TimestampData
} from './integrity/CodeSigner';

// ============================================================================
// ARTIFACT SIGNER
// ============================================================================
export { ArtifactSigner, SigstoreUtils } from './integrity/ArtifactSigner';
export type {
  ArtifactSignerConfig,
  OIDCToken,
  SigstoreBundle,
  DSSEEnvelope,
  DSSESignature,
  ArtifactSignatureResult
} from './integrity/ArtifactSigner';

// ============================================================================
// FILE INTEGRITY MONITOR
// ============================================================================
export { FileIntegrityMonitor, FIMFactory } from './integrity/FileIntegrityMonitor';
export type {
  FIMOptions,
  WatchedFileState,
  DebounceTimer
} from './integrity/FileIntegrityMonitor';

// ============================================================================
// SBOM GENERATOR
// ============================================================================
export { SBOMGenerator, SBOMGeneratorFactory } from './integrity/SBOMGenerator';
export type {
  SBOMGeneratorConfig,
  PackageJSON,
  PackageLock,
  PackageLockEntry,
  PackageLockDependency
} from './integrity/SBOMGenerator';

// ============================================================================
// SUPPLY CHAIN VERIFIER
// ============================================================================
export { SupplyChainVerifier, SupplyChainVerifierFactory } from './integrity/SupplyChainVerifier';
export type {
  SupplyChainVerifierConfig,
  ComponentVerificationStatus,
  VerificationCheck,
  RegistryMetadata
} from './integrity/SupplyChainVerifier';

// ============================================================================
// SLSA VERIFIER
// ============================================================================
export { SLSAVerifier, SLSAVerifierFactory } from './integrity/SLSAVerifier';
export type {
  SLSAVerifierConfig,
  IntotoStatement,
  SLSAProvenancePredicate
} from './integrity/SLSAVerifier';

// ============================================================================
// TRANSPARENCY LOG
// ============================================================================
export { TransparencyLogClient, TransparencyLogClientFactory } from './integrity/TransparencyLog';
export type {
  TLogEntryKind,
  HashedRekordData,
  IntotoData,
  LogEntryOptions,
  Checkpoint
} from './integrity/TransparencyLog';

// ============================================================================
// BASELINE MANAGER
// ============================================================================
export { BaselineManager } from './integrity/BaselineManager';
export type {
  BaselineManagerConfig,
  BaselineStorage
} from './integrity/BaselineManager';

// ============================================================================
// RUNTIME VERIFIER
// ============================================================================
export { RuntimeVerifier, RuntimeVerifierFactory } from './integrity/RuntimeVerifier';
export type {
  RuntimeVerifierConfig,
  MonitoredComponent
} from './integrity/RuntimeVerifier';

// ============================================================================
// MODIFICATION DETECTOR
// ============================================================================
export { ModificationDetector, ModificationDetectorFactory } from './integrity/ModificationDetector';
export type {
  ModificationDetectorConfig,
  IOCPattern,
  BehavioralSignature,
  BehavioralDetector,
  FileAnalysisResult,
  IOCMatch,
  BehavioralAnomaly
} from './integrity/ModificationDetector';

// ============================================================================
// INTEGRITY SERVICE
// ============================================================================
export { IntegrityService, IntegrityServiceFactory } from './integrity/IntegrityService';
export type {
  ServiceStatus
} from './integrity/IntegrityService';

// ============================================================================
// ВЕРСИЯ
// ============================================================================
export const VERSION = '1.0.0';
export const VERSION_MAJOR = 1;
export const VERSION_MINOR = 0;
export const VERSION_PATCH = 0;

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/**
 * Поддерживаемые алгоритмы хеширования
 */
export const SUPPORTED_HASH_ALGORITHMS = [
  'SHA-256',
  'SHA-384',
  'SHA-512',
  'SHA3-256',
  'SHA3-512',
  'BLAKE2b',
  'BLAKE3'
] as const;

/**
 * Поддерживаемые форматы SBOM
 */
export const SUPPORTED_SBOM_FORMATS = [
  'SPDX',
  'CycloneDX',
  'SWID'
] as const;

/**
 * Поддерживаемые типы подписей
 */
export const SUPPORTED_SIGNATURE_TYPES = [
  'GPG',
  'SSH',
  'X509',
  'COSIGN'
] as const;

/**
 * Уровни SLSA
 */
export const SLSA_LEVELS = [0, 1, 2, 3, 4] as const;

/**
 * Типы записей Transparency Log
 */
export const TLOG_ENTRY_KINDS = [
  'hashedrekord',
  'intoto',
  'dsse',
  'rpm',
  'jar',
  'apk',
  'tuf',
  'helm',
  'rfc3161',
  'alpine',
  'cosign'
] as const;

/**
 * Серьезности нарушений
 */
export const SEVERITY_LEVELS = [
  'critical',
  'high',
  'medium',
  'low'
] as const;

/**
 * Типы модификаций
 */
export const MODIFICATION_TYPES = [
  'content_change',
  'permission_change',
  'ownership_change',
  'timestamp_manipulation',
  'file_swap',
  'injection',
  'deletion',
  'addition'
] as const;

// ============================================================================
// УТИЛИТЫ
// ============================================================================

/**
 * Проверяет поддерживается ли алгоритм хеширования
 */
export function isSupportedHashAlgorithm(algorithm: string): algorithm is typeof SUPPORTED_HASH_ALGORITHMS[number] {
  return SUPPORTED_HASH_ALGORITHMS.includes(algorithm as any);
}

/**
 * Проверяется поддерживается ли формат SBOM
 */
export function isSupportedSBOMFormat(format: string): format is typeof SUPPORTED_SBOM_FORMATS[number] {
  return SUPPORTED_SBOM_FORMATS.includes(format as any);
}

/**
 * Проверяется поддерживается ли тип подписи
 */
export function isSupportedSignatureType(type: string): type is typeof SUPPORTED_SIGNATURE_TYPES[number] {
  return SUPPORTED_SIGNATURE_TYPES.includes(type as any);
}

/**
 * Проверяется валидный ли уровень SLSA
 */
export function isValidSLSALevel(level: number): level is typeof SLSA_LEVELS[number] {
  return SLSA_LEVELS.includes(level as any);
}

/**
 * Получает вес серьезности
 */
export function getSeverityWeight(severity: string): number {
  const weights: Record<string, number> = {
    critical: 40,
    high: 25,
    medium: 15,
    low: 5
  };
  return weights[severity] || 0;
}

/**
 * Сравнивает две версии
 */
export function compareVersions(v1: string, v2: string): number {
  const parts1 = v1.split('.').map(Number);
  const parts2 = v2.split('.').map(Number);
  
  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const a = parts1[i] || 0;
    const b = parts2[i] || 0;
    
    if (a > b) return 1;
    if (a < b) return -1;
  }
  
  return 0;
}

/**
 * Генерирует уникальный ID
 */
export function generateId(prefix: string = ''): string {
  const hash = require('crypto').createHash('sha256');
  hash.update(`${prefix}-${Date.now()}-${Math.random()}`);
  return `${prefix}${prefix ? '-' : ''}${hash.digest('hex').substring(0, 16)}`;
}
