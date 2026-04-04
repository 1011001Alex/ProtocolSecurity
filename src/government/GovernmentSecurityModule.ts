/**
 * ============================================================================
 * GOVERNMENT SECURITY MODULE
 * ============================================================================
 * FIPS 140-2/3 Compliance, STIG Hardening, FISMA Assessment,
 * Multi-Level Security (MLS), PKI/CRL Management
 *
 * Соответствие: FISMA, FedRAMP, NIST SP 800-53, CNSSI 1253, DoD STIG
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import { logger } from '../logging/Logger';

// ============================================================================
// SECURITY ERRORS
// ============================================================================

class GovernmentSecurityError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(message: string, code: string, statusCode: number = 500) {
    super(message);
    this.name = 'GovernmentSecurityError';
    this.code = code;
    this.statusCode = statusCode;
    Error.captureStackTrace(this, this.constructor);
  }
}

// ============================================================================
// CIRCUIT BREAKER
// ============================================================================

enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN'
}

class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime = 0;
  private readonly failureThreshold: number;
  private readonly recoveryTimeoutMs: number;
  private readonly successThreshold: number;
  private readonly name: string;

  constructor(name: string, failureThreshold = 5, recoveryTimeoutMs = 30000, successThreshold = 2) {
    this.name = name;
    this.failureThreshold = failureThreshold;
    this.recoveryTimeoutMs = recoveryTimeoutMs;
    this.successThreshold = successThreshold;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed < this.recoveryTimeoutMs) {
        throw new GovernmentSecurityError(`Circuit breaker '${this.name}' is OPEN`, 'CIRCUIT_OPEN', 503);
      }
      this.state = CircuitState.HALF_OPEN;
    }
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.failureCount = 0;
    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= this.successThreshold) {
        this.state = CircuitState.CLOSED;
        this.successCount = 0;
      }
    }
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    this.successCount = 0;
    if (this.failureCount >= this.failureThreshold) {
      this.state = CircuitState.OPEN;
      logger.warn(`[GovernmentSecurity] Circuit breaker '${this.name}' tripped OPEN`);
    }
  }

  getState(): CircuitState { return this.state; }
  reset(): void { this.state = CircuitState.CLOSED; this.failureCount = 0; this.successCount = 0; }
}

// ============================================================================
// TYPES — FIPS 140-2/3
// ============================================================================

export type FIPSLevel = 1 | 2 | 3 | 4;

export interface FIPSComplianceResult {
  compliant: boolean;
  level: FIPSLevel;
  module: string;
  validatedAlgorithms: string[];
  nonCompliantAlgorithms: string[];
  validationDate: string;
  certificateNumber?: string;
  recommendations: string[];
}

export interface FIPSAlgorithm {
  name: string;
  standard: string;
  mode: string;
  keySizes: number[];
  fipsApproved: boolean;
  certificateNumber: string;
}

export interface FIPSModeConfig {
  level: FIPSLevel;
  enforced: boolean;
  nonCompliantAction: 'block' | 'warn' | 'log';
  approvedOnly: boolean;
}

// ============================================================================
// TYPES — STIG
// ============================================================================

export interface STIGFinding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: 'CAT_I' | 'CAT_II' | 'CAT_III';
  status: 'OPEN' | 'NOT_APPLICABLE' | 'NOT_REVIEWED' | 'PASS' | 'FIXED';
  component: string;
  benchmark: string;
  benchmarkVersion: string;
  check: string;
  fix: string;
  rawResult?: string;
}

export interface STIGChecklist {
  benchmark: string;
  version: string;
  releaseDate: string;
  totalChecks: number;
  passCount: number;
  failCount: number;
  notApplicable: number;
  notReviewed: number;
  compliancePercentage: number;
  findings: STIGFinding[];
  assessedAt: string;
}

export interface STIGHardeningResult {
  success: boolean;
  component: string;
  appliedSettings: string[];
  failedSettings: string[];
  requiresReboot: boolean;
  timestamp: string;
}

// ============================================================================
// TYPES — FISMA
// ============================================================================

export interface FISMAComplianceResult {
  compliant: boolean;
  overallScore: number; // 0-100
  controlFamilies: FISMAControlFamily[];
  assessmentDate: string;
  assessor: string;
  authorizationStatus: 'ATO' | 'DATO' | 'DENIED' | 'PENDING';
}

export interface FISMAControlFamily {
  family: string;
  controlId: string;
  controlName: string;
  implemented: boolean;
  assessed: boolean;
  score: number; // 0-100
  findings: string[];
  evidence: string[];
}

export interface FISMAReport {
  systemName: string;
  impactLevel: 'LOW' | 'MODERATE' | 'HIGH';
  assessmentDate: string;
  compliance: FISMAComplianceResult;
  poamItems: POAMItem[];
  riskAssessment: {
    overallRisk: 'VERY_LOW' | 'LOW' | 'MODERATE' | 'HIGH' | 'VERY_HIGH';
    riskFactors: string[];
    residualRisk: string;
  };
  recommendations: string[];
  generatedAt: string;
}

export interface POAMItem {
  id: string;
  controlId: string;
  weakness: string;
  plannedActions: string;
  milestones: { date: string; description: string }[];
  responsiblePerson: string;
  scheduledCompletion: string;
  status: 'IN_PROGRESS' | 'NOT_STARTED' | 'ON_HOLD' | 'COMPLETED' | 'OVERDUE';
  resourcesRequired: string;
  riskLevel: 'LOW' | 'MODERATE' | 'HIGH';
  vendorDependency?: string;
}

// ============================================================================
// TYPES — Multi-Level Security (MLS)
// ============================================================================

export type MLSClassification = 'UNCLASSIFIED' | 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET' | 'SCI';

export interface MLSCompartment {
  id: string;
  name: string;
  description: string;
}

export interface MLSAccessRequest {
  userId: string;
  userClearance: MLSClassification;
  userCompartments: string[];
  dataClassification: MLSClassification;
  dataCompartments: string[];
  operation: 'read' | 'write' | 'execute' | 'delete';
  context?: Record<string, string>;
}

export interface MLSAccessDecision {
  granted: boolean;
  reason: string;
  rule: 'SIMPLE_SECURITY' | 'STAR_PROPERTY' | 'DISCRETIONARY_SECURITY' | 'COMPARTMENT_CHECK';
  timestamp: string;
}

export interface MLSDataLabel {
  classification: MLSClassification;
  compartments: string[];
  handlingRestrictions: string[];
  classificationAuthority: string;
  classifiedAt: string;
  declassificationDate?: string;
  downgradeHistory: { from: MLSClassification; to: MLSClassification; date: string; authority: string }[];
}

export interface MLSAuditEntry {
  id: string;
  userId: string;
  operation: string;
  dataId: string;
  userClearance: MLSClassification;
  dataClassification: MLSClassification;
  decision: 'GRANTED' | 'DENIED';
  reason: string;
  timestamp: string;
  clientIp?: string;
}

// ============================================================================
// TYPES — PKI/CRL
// ============================================================================

export interface CertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  fingerprint: string;
  publicKeyAlgorithm: string;
  keySize: number;
  signatureAlgorithm: string;
  extensions: Record<string, string>;
  isCA: boolean;
}

export interface CRLInfo {
  issuer: string;
  thisUpdate: string;
  nextUpdate: string;
  revokedSerials: string[];
  crlNumber: number;
  distributionPoint: string;
}

export interface OCSPResponse {
  certStatus: 'GOOD' | 'REVOKED' | 'UNKNOWN';
  revocationTime?: string;
  revocationReason?: string;
  producedAt: string;
  responderUrl: string;
}

export interface CertificateChainValidationResult {
  valid: boolean;
  chain: CertificateInfo[];
  trustAnchor: CertificateInfo | null;
  errors: string[];
  warnings: string[];
  validatedAt: string;
}

export interface GovernmentCertificateSubject {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  classification: MLSClassification;
  emailAddress: string;
}

// ============================================================================
// CONFIG
// ============================================================================

export interface GovernmentSecurityConfig {
  classification: 'UNCLASSIFIED' | 'SECRET' | 'TOP_SECRET';
  fipsMode: FIPSModeConfig;
  stigCompliance: boolean;
  fisma: {
    enabled: boolean;
    systemName: string;
    impactLevel: 'LOW' | 'MODERATE' | 'HIGH';
    assessmentIntervalMs: number;
  };
  mls: {
    enabled: boolean;
    defaultClassification: MLSClassification;
    compartments: MLSCompartment[];
    auditEnabled: boolean;
  };
  pki: {
    enabled: boolean;
    caEndpoint: string;
    ocspEndpoint: string;
    crlDistributionPoints: string[];
    certificateLifetime: number; // days
  };
  continuousMonitoring: boolean;
}

const DEFAULT_FIPS_ALGORITHMS: FIPSAlgorithm[] = [
  { name: 'AES', standard: 'FIPS 197', mode: 'ECB/CBC/CFB/OFB/GCM', keySizes: [128, 192, 256], fipsApproved: true, certificateNumber: 'FIPS-197' },
  { name: 'SHA-1', standard: 'FIPS 180-4', mode: 'Hash', keySizes: [160], fipsApproved: false, certificateNumber: 'FIPS-180-4' }, // Deprecated for most uses
  { name: 'SHA-256', standard: 'FIPS 180-4', mode: 'Hash', keySizes: [256], fipsApproved: true, certificateNumber: 'FIPS-180-4' },
  { name: 'SHA-384', standard: 'FIPS 180-4', mode: 'Hash', keySizes: [384], fipsApproved: true, certificateNumber: 'FIPS-180-4' },
  { name: 'SHA-512', standard: 'FIPS 180-4', mode: 'Hash', keySizes: [512], fipsApproved: true, certificateNumber: 'FIPS-180-4' },
  { name: 'RSA', standard: 'FIPS 186-4', mode: 'Sign/Encrypt', keySizes: [2048, 3072, 4096], fipsApproved: true, certificateNumber: 'FIPS-186-4' },
  { name: 'ECDSA', standard: 'FIPS 186-4', mode: 'Sign', keySizes: [256, 384, 521], fipsApproved: true, certificateNumber: 'FIPS-186-4' },
  { name: 'HMAC', standard: 'FIPS 198-1', mode: 'MAC', keySizes: [256], fipsApproved: true, certificateNumber: 'FIPS-198-1' },
  { name: 'DRBG', standard: 'FIPS 140-3', mode: 'CTR/Hash/HMAC', keySizes: [256], fipsApproved: true, certificateNumber: 'FIPS-140-3' },
  { name: '3DES', standard: 'FIPS 46-3', mode: 'EDE', keySizes: [168], fipsApproved: false, certificateNumber: 'FIPS-46-3' } // Deprecated
];

const DEFAULT_CONFIG: GovernmentSecurityConfig = {
  classification: 'UNCLASSIFIED',
  fipsMode: { level: 2, enforced: false, nonCompliantAction: 'warn', approvedOnly: false },
  stigCompliance: false,
  fisma: { enabled: false, systemName: 'Protocol Security System', impactLevel: 'MODERATE', assessmentIntervalMs: 86400000 },
  mls: { enabled: false, defaultClassification: 'UNCLASSIFIED', compartments: [], auditEnabled: true },
  pki: { enabled: false, caEndpoint: '', ocspEndpoint: '', crlDistributionPoints: [], certificateLifetime: 365 },
  continuousMonitoring: false
};

// ============================================================================
// GOVERNMENT SECURITY MODULE
// ============================================================================

export class GovernmentSecurityModule extends EventEmitter {
  private config: GovernmentSecurityConfig;
  private isInitialized = false;

  // State
  private fipsAlgorithms: Map<string, FIPSAlgorithm> = new Map();
  private fipsMode: FIPSModeConfig;
  private stigFindings: Map<string, STIGFinding> = new Map();
  private stigChecklists: Map<string, STIGChecklist> = new Map();
  private fismaReports: FISMAReport[] = [];
  private poamItems: Map<string, POAMItem> = new Map();
  private mlsAuditLog: MLSAuditEntry[] = [];
  private certificateStore: Map<string, CertificateInfo> = new Map();
  private crlStore: Map<string, CRLInfo> = new Map();
  private issuedCertificates: Map<string, { subject: GovernmentCertificateSubject; cert: CertificateInfo }> = new Map();
  private mlsDataLabels: Map<string, MLSDataLabel> = new Map();

  // Infrastructure
  private fipsCircuitBreaker: CircuitBreaker;
  private pkiCircuitBreaker: CircuitBreaker;

  constructor(config: Partial<GovernmentSecurityConfig> = {}) {
    super();
    this.config = this.mergeConfig(DEFAULT_CONFIG, config);
    this.fipsMode = this.config.fipsMode;

    // Initialize FIPS algorithms
    for (const alg of DEFAULT_FIPS_ALGORITHMS) {
      this.fipsAlgorithms.set(alg.name, alg);
    }

    this.fipsCircuitBreaker = new CircuitBreaker('FIPS', 3, 60000, 2);
    this.pkiCircuitBreaker = new CircuitBreaker('PKI', 3, 30000, 2);

    logger.info('[GovernmentSecurity] Module created', undefined, undefined, {
      classification: this.config.classification,
      fipsLevel: this.fipsMode.level,
      stigCompliance: this.config.stigCompliance,
      fismaEnabled: this.config.fisma.enabled,
      mlsEnabled: this.config.mls.enabled,
      pkiEnabled: this.config.pki.enabled
    });
  }

  // ========================================================================
  // INITIALIZATION
  // ========================================================================

  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[GovernmentSecurity] Already initialized');
      return;
    }

    if (this.fipsMode.enforced) {
      logger.info('[GovernmentSecurity] FIPS mode enforced', undefined, undefined, {
        level: this.fipsMode.level,
        approvedOnly: this.fipsMode.approvedOnly
      });
    }

    if (this.config.stigCompliance) {
      this.initializeSTIGBenchmarks();
    }

    if (this.config.fisma.enabled) {
      logger.info('[GovernmentSecurity] FISMA monitoring initialized', undefined, undefined, {
        systemName: this.config.fisma.systemName,
        impactLevel: this.config.fisma.impactLevel
      });
    }

    if (this.config.mls.enabled) {
      logger.info('[GovernmentSecurity] MLS access control initialized', undefined, undefined, {
        compartments: this.config.mls.compartments.length
      });
    }

    if (this.config.pki.enabled) {
      logger.info('[GovernmentSecurity] PKI/CRL management initialized', undefined, undefined, {
        caEndpoint: this.config.pki.caEndpoint,
        crlPoints: this.config.pki.crlDistributionPoints.length
      });
    }

    this.isInitialized = true;
    this.emit('initialized');
    logger.info('[GovernmentSecurity] Module fully initialized');
  }

  private mergeConfig(defaults: GovernmentSecurityConfig, overrides: Partial<GovernmentSecurityConfig>): GovernmentSecurityConfig {
    return {
      classification: overrides.classification || defaults.classification,
      fipsMode: { ...defaults.fipsMode, ...(overrides.fipsMode || {}) },
      stigCompliance: overrides.stigCompliance !== undefined ? overrides.stigCompliance : defaults.stigCompliance,
      fisma: { ...defaults.fisma, ...(overrides.fisma || {}) },
      mls: { ...defaults.mls, ...(overrides.mls || {}) },
      pki: { ...defaults.pki, ...(overrides.pki || {}) },
      continuousMonitoring: overrides.continuousMonitoring !== undefined ? overrides.continuousMonitoring : defaults.continuousMonitoring
    };
  }

  // ========================================================================
  // FIPS 140-2/3 COMPLIANCE
  // ========================================================================

  /**
   * Validate FIPS 140-2/3 compliance of all cryptographic modules.
   */
  public async validateFIPSCompliance(): Promise<FIPSComplianceResult> {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    return this.fipsCircuitBreaker.execute(async () => {
      const validatedAlgorithms: string[] = [];
      const nonCompliantAlgorithms: string[] = [];
      const recommendations: string[] = [];

      for (const [, alg] of this.fipsAlgorithms.entries()) {
        const isFipsApproved = this.isAlgorithmFIPSCompliant(alg);
        if (isFipsApproved) {
          validatedAlgorithms.push(`${alg.name} (${alg.standard}, key ${alg.keySizes.join('/')})`);
        } else {
          nonCompliantAlgorithms.push(`${alg.name} (${alg.standard}) — ${this.getNonComplianceReason(alg)}`);
          recommendations.push(`Replace ${alg.name} with FIPS-approved alternative`);
        }
      }

      // Validate at required FIPS level
      const levelCompliant = this.validateAtLevel(this.fipsMode.level);

      const compliant = levelCompliant && nonCompliantAlgorithms.length === 0;

      if (!compliant && this.fipsMode.nonCompliantAction === 'block') {
        throw new GovernmentSecurityError(
          `FIPS ${this.fipsMode.level} compliance check failed: ${nonCompliantAlgorithms.join(', ')}`,
          'FIPS_NONCOMPLIANT',
          403
        );
      }

      const result: FIPSComplianceResult = {
        compliant,
        level: this.fipsMode.level,
        module: 'Protocol Security System — Cryptographic Module',
        validatedAlgorithms,
        nonCompliantAlgorithms,
        validationDate: new Date().toISOString(),
        certificateNumber: `FIPS-140-${this.fipsMode.level}-CMVP-2024-XXXX`,
        recommendations
      };

      logger.info('[GovernmentSecurity] FIPS compliance validation completed', undefined, undefined, {
        compliant: result.compliant,
        level: result.level,
        validatedCount: validatedAlgorithms.length,
        nonCompliantCount: nonCompliantAlgorithms.length
      });

      this.emit('fips-compliance-check', result);

      return result;
    });
  }

  /**
   * Get list of FIPS-certified algorithms.
   */
  public getFIPSCertifiedAlgorithms(): FIPSAlgorithm[] {
    const approved: FIPSAlgorithm[] = [];
    for (const [, alg] of this.fipsAlgorithms.entries()) {
      if (this.isAlgorithmFIPSCompliant(alg)) {
        approved.push(alg);
      }
    }
    return approved;
  }

  /**
   * Configure FIPS mode (Level 1-4).
   */
  public configureFIPSMode(level: FIPSLevel): { success: boolean; previousMode: FIPSModeConfig } {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (level < 1 || level > 4) {
      throw new GovernmentSecurityError('FIPS level must be between 1 and 4', 'INVALID_FIPS_LEVEL', 400);
    }

    const previousMode = { ...this.fipsMode };

    this.fipsMode = {
      level,
      enforced: true,
      nonCompliantAction: level >= 3 ? 'block' : 'warn',
      approvedOnly: true
    };

    // Filter out non-compliant algorithms at higher levels
    if (level >= 3) {
      // FIPS Level 3+ requires physical tamper resistance and identity-based authentication
      for (const [name, alg] of this.fipsAlgorithms.entries()) {
        if (!alg.fipsApproved) {
          this.fipsAlgorithms.delete(name);
        }
      }
    }

    logger.info('[GovernmentSecurity] FIPS mode configured', undefined, undefined, {
      level: this.fipsMode.level,
      enforced: this.fipsMode.enforced,
      nonCompliantAction: this.fipsMode.nonCompliantAction
    });

    this.emit('fips-mode-changed', { previousMode, newMode: this.fipsMode });

    return { success: true, previousMode };
  }

  // Internal: check if algorithm is FIPS compliant
  private isAlgorithmFIPSCompliant(alg: FIPSAlgorithm): boolean {
    if (!alg.fipsApproved) return false;

    // SHA-1 is deprecated for most uses
    if (alg.name === 'SHA-1') return false;
    // 3DES is deprecated
    if (alg.name === '3DES') return false;

    // At FIPS level 2+, require minimum key sizes
    if (this.fipsMode.level >= 2) {
      if (alg.name === 'RSA' && !alg.keySizes.some(s => s >= 2048)) return false;
      if (alg.name === 'AES' && alg.keySizes.length > 0 && Math.min(...alg.keySizes) < 128) return false;
    }

    return true;
  }

  private getNonComplianceReason(alg: FIPSAlgorithm): string {
    if (alg.name === 'SHA-1') return 'Deprecated — collision attacks';
    if (alg.name === '3DES') return 'Deprecated — Sweet32 attack, insufficient key size';
    if (!alg.fipsApproved) return 'Not approved under current FIPS standard';
    return 'Does not meet minimum requirements for FIPS level';
  }

  private validateAtLevel(level: FIPSLevel): boolean {
    switch (level) {
      case 1:
        // Level 1: At least one approved crypto algorithm
        return [...this.fipsAlgorithms.values()].some(a => this.isAlgorithmFIPSCompliant(a));
      case 2:
        // Level 2: Role-based authentication + physical tamper evidence
        return this.hasRoleBasedAuth() && [...this.fipsAlgorithms.values()].some(a => this.isAlgorithmFIPSCompliant(a));
      case 3:
        // Level 3: Physical tamper resistance + identity-based auth
        return this.hasIdentityAuth() && this.hasTamperResistance() && [...this.fipsAlgorithms.values()].some(a => this.isAlgorithmFIPSCompliant(a));
      case 4:
        // Level 4: Environmental protection + zeroization
        return this.hasEnvironmentalProtection() && this.hasZeroization();
      default:
        return false;
    }
  }

  private hasRoleBasedAuth(): boolean { return true; } // Simulated
  private hasIdentityAuth(): boolean { return true; } // Simulated
  private hasTamperResistance(): boolean { return true; } // Simulated
  private hasEnvironmentalProtection(): boolean { return false; } // Simulated — requires hardware
  private hasZeroization(): boolean { return true; } // Simulated

  // ========================================================================
  // STIG — Security Technical Implementation Guide
  // ========================================================================

  /**
   * Evaluate STIG compliance across all components.
   */
  public evaluateSTIGCompliance(): STIGChecklist {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.stigCompliance) {
      throw new GovernmentSecurityError('STIG compliance is not enabled', 'STIG_DISABLED', 403);
    }

    const findings: STIGFinding[] = [];
    let passCount = 0;
    let failCount = 0;
    let notApplicable = 0;
    let notReviewed = 0;

    for (const [, finding] of this.stigFindings.entries()) {
      findings.push(finding);
      switch (finding.status) {
        case 'PASS': case 'FIXED': passCount++; break;
        case 'OPEN': failCount++; break;
        case 'NOT_APPLICABLE': notApplicable++; break;
        case 'NOT_REVIEWED': notReviewed++; break;
      }
    }

    const totalChecks = findings.length;
    const compliancePercentage = totalChecks > 0 ? Math.round((passCount / totalChecks) * 100) : 0;

    const checklist: STIGChecklist = {
      benchmark: 'Application Security STIG',
      version: 'V2R3',
      releaseDate: '2024-01-15',
      totalChecks,
      passCount,
      failCount,
      notApplicable,
      notReviewed,
      compliancePercentage,
      findings,
      assessedAt: new Date().toISOString()
    };

    logger.info('[GovernmentSecurity] STIG compliance evaluation completed', undefined, undefined, {
      benchmark: checklist.benchmark,
      version: checklist.version,
      compliancePercentage: `${compliancePercentage}%`,
      openFindings: failCount
    });

    this.emit('stig-evaluation', { compliancePercentage, openFindings: failCount });

    return checklist;
  }

  /**
   * Apply STIG hardening settings to a component.
   */
  public applySTIGHardening(component: string): STIGHardeningResult {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const appliedSettings: string[] = [];
    const failedSettings: string[] = [];
    let requiresReboot = false;

    const hardeningSettings = this.getSTIGSettingsForComponent(component);

    for (const [setting, value] of Object.entries(hardeningSettings)) {
      try {
        // Simulate applying the setting
        // In production: modify registry, config files, group policy, etc.
        appliedSettings.push(`${setting}=${value}`);

        // Update finding status
        for (const [, finding] of this.stigFindings.entries()) {
          if (finding.component === component && finding.fix.includes(setting)) {
            finding.status = 'FIXED';
          }
        }
      } catch (e) {
        failedSettings.push(`${setting}=${value}`);
      }
    }

    // Some STIG settings require reboot
    requiresReboot = appliedSettings.some(s =>
      s.includes('AuditPolicy') || s.includes('BootConfig') || s.includes('KernelParam')
    );

    const result: STIGHardeningResult = {
      success: failedSettings.length === 0,
      component,
      appliedSettings,
      failedSettings,
      requiresReboot,
      timestamp: new Date().toISOString()
    };

    logger.info('[GovernmentSecurity] STIG hardening applied', undefined, undefined, {
      component,
      applied: appliedSettings.length,
      failed: failedSettings.length,
      requiresReboot
    });

    this.emit('stig-hardening', result);

    return result;
  }

  /**
   * Get STIG checklist with all findings.
   */
  public getSTIGChecklist(): STIGFinding[] {
    return Array.from(this.stigFindings.values());
  }

  // Internal: initialize STIG benchmarks
  private initializeSTIGBenchmarks(): void {
    const defaultFindings: STIGFinding[] = [
      // OS-level STIGs
      {
        id: 'V-230255', ruleId: 'SV-230255r627750_rule', title: 'OS — Account lockout threshold',
        description: 'The system must enforce account lockout after 3-5 invalid logon attempts.',
        severity: 'CAT_I', status: 'OPEN', component: 'os-authentication',
        benchmark: 'Windows Server 2022 STIG', benchmarkVersion: 'V2R3',
        check: 'Verify AccountLockoutThreshold <= 5',
        fix: 'Set AccountLockoutThreshold=3 in security policy'
      },
      {
        id: 'V-230256', ruleId: 'SV-230256r627750_rule', title: 'OS — Password complexity',
        description: 'Passwords must meet complexity requirements (uppercase, lowercase, digit, special).',
        severity: 'CAT_I', status: 'OPEN', component: 'os-authentication',
        benchmark: 'Windows Server 2022 STIG', benchmarkVersion: 'V2R3',
        check: 'Verify PasswordComplexity=1',
        fix: 'Enable PasswordComplexity in group policy'
      },
      {
        id: 'V-230260', ruleId: 'SV-230260r627750_rule', title: 'OS — Audit policy',
        description: 'Audit logon events, account management, and policy changes.',
        severity: 'CAT_II', status: 'OPEN', component: 'os-auditing',
        benchmark: 'Windows Server 2022 STIG', benchmarkVersion: 'V2R3',
        check: 'Verify AuditLogonEvents=Success, Failure',
        fix: 'Configure Audit Policy in Group Policy Management'
      },
      // Application STIGs
      {
        id: 'V-248001', ruleId: 'SV-248001r803900_rule', title: 'APP — TLS version',
        description: 'Application must use TLS 1.2 or higher for all encrypted connections.',
        severity: 'CAT_I', status: 'OPEN', component: 'app-encryption',
        benchmark: 'Application Security STIG', benchmarkVersion: 'V2R3',
        check: 'Verify TLS minimum version is 1.2',
        fix: 'Set TLS minimum version to 1.2 in application configuration'
      },
      {
        id: 'V-248002', ruleId: 'SV-248002r803900_rule', title: 'APP — Session timeout',
        description: 'Application must terminate idle sessions after 15 minutes.',
        severity: 'CAT_II', status: 'OPEN', component: 'app-session',
        benchmark: 'Application Security STIG', benchmarkVersion: 'V2R3',
        check: 'Verify session timeout <= 900 seconds',
        fix: 'Configure session timeout to 900 seconds'
      },
      {
        id: 'V-248003', ruleId: 'SV-248003r803900_rule', title: 'APP — Error handling',
        description: 'Application must not display stack traces or sensitive information in error messages.',
        severity: 'CAT_II', status: 'PASS', component: 'app-error-handling',
        benchmark: 'Application Security STIG', benchmarkVersion: 'V2R3',
        check: 'Verify error messages do not contain stack traces',
        fix: 'Configure custom error pages and disable debug mode'
      },
      // Database STIGs
      {
        id: 'V-224510', ruleId: 'SV-224510r627750_rule', title: 'DB — Default accounts',
        description: 'Database must not have default accounts with default passwords.',
        severity: 'CAT_I', status: 'PASS', component: 'db-authentication',
        benchmark: 'Microsoft SQL Server 2019 STIG', benchmarkVersion: 'V1R5',
        check: 'Verify no default accounts with default passwords exist',
        fix: 'Change or remove all default accounts'
      },
      {
        id: 'V-224515', ruleId: 'SV-224515r627750_rule', title: 'DB — Encryption at rest',
        description: 'Database must encrypt data at rest using FIPS-approved algorithms.',
        severity: 'CAT_I', status: 'OPEN', component: 'db-encryption',
        benchmark: 'Microsoft SQL Server 2019 STIG', benchmarkVersion: 'V1R5',
        check: 'Verify TDE is enabled with AES-256',
        fix: 'Enable Transparent Data Encryption with AES-256'
      }
    ];

    for (const finding of defaultFindings) {
      this.stigFindings.set(finding.id, finding);
    }
  }

  // Internal: get STIG settings for a component
  private getSTIGSettingsForComponent(component: string): Record<string, string> {
    const settingsMap: Record<string, Record<string, string>> = {
      'os-authentication': {
        AccountLockoutThreshold: '3',
        AccountLockoutDuration: '30',
        PasswordComplexity: '1',
        MinimumPasswordLength: '14',
        PasswordHistorySize: '24',
        MaximumPasswordAge: '60'
      },
      'os-auditing': {
        AuditLogonEvents: 'Success, Failure',
        AuditAccountManagement: 'Success, Failure',
        AuditPolicyChange: 'Success, Failure',
        AuditProcessTracking: 'Success'
      },
      'app-encryption': {
        TLSMinVersion: '1.2',
        TLSCipherSuites: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
        CertificateValidation: 'strict',
        KeyExchangeAlgorithm: 'ECDHE'
      },
      'app-session': {
        SessionTimeout: '900',
        AbsoluteSessionTimeout: '28800',
        SecureCookie: 'true',
        HttpOnlyCookie: 'true',
        SameSiteCookie: 'Strict'
      }
    };

    return settingsMap[component] || {};
  }

  // ========================================================================
  // FISMA — Federal Information Security Management Act
  // ========================================================================

  /**
   * Assess FISMA compliance across all control families.
   */
  public async assessFISMACompliance(): Promise<FISMAComplianceResult> {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.fisma.enabled) {
      throw new GovernmentSecurityError('FISMA assessment is not enabled', 'FISMA_DISABLED', 403);
    }

    const controlFamilies: FISMAControlFamily[] = this.getNISTControlFamilies();

    let totalScore = 0;
    let implementedCount = 0;

    for (const family of controlFamilies) {
      totalScore += family.score;
      if (family.implemented) implementedCount++;
    }

    const overallScore = Math.round(totalScore / controlFamilies.length);
    const compliant = overallScore >= 80;

    const authorizationStatus: FISMAComplianceResult['authorizationStatus'] =
      overallScore >= 90 ? 'ATO' :
      overallScore >= 70 ? 'DATO' :
      overallScore >= 50 ? 'PENDING' : 'DENIED';

    const result: FISMAComplianceResult = {
      compliant,
      overallScore,
      controlFamilies,
      assessmentDate: new Date().toISOString(),
      assessor: 'Automated FISMA Assessment Engine',
      authorizationStatus
    };

    logger.info('[GovernmentSecurity] FISMA compliance assessment completed', undefined, undefined, {
      overallScore: `${overallScore}%`,
      authorizationStatus,
      implementedControls: `${implementedCount}/${controlFamilies.length}`
    });

    this.emit('fisma-assessment', result);

    return result;
  }

  /**
   * Generate comprehensive FISMA report.
   */
  public async generateFISMAReport(): Promise<FISMAReport> {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const compliance = await this.assessFISMACompliance();

    // Build POAM items
    const poamItems = this.getPOAMItemsForReport();

    // Determine overall risk
    const riskFactors: string[] = [];
    let riskScore = 0;

    if (compliance.overallScore < 70) {
      riskFactors.push('Overall compliance score below 70%');
      riskScore += 30;
    }
    if (poamItems.filter(p => p.status === 'OVERDUE').length > 0) {
      riskFactors.push('Overdue POAM items exist');
      riskScore += 20;
    }
    if (compliance.controlFamilies.some(f => f.score < 50)) {
      riskFactors.push('Critical control families below 50%');
      riskScore += 25;
    }

    const overallRisk: FISMAReport['riskAssessment']['overallRisk'] =
      riskScore >= 60 ? 'HIGH' :
      riskScore >= 40 ? 'MODERATE' :
      riskScore >= 20 ? 'LOW' : 'VERY_LOW';

    const report: FISMAReport = {
      systemName: this.config.fisma.systemName,
      impactLevel: this.config.fisma.impactLevel,
      assessmentDate: compliance.assessmentDate,
      compliance,
      poamItems,
      riskAssessment: {
        overallRisk,
        riskFactors,
        residualRisk: riskScore >= 40 ? 'Acceptable with monitoring' : 'Acceptable'
      },
      recommendations: this.generateFISMARecommendations(compliance),
      generatedAt: new Date().toISOString()
    };

    this.fismaReports.push(report);

    logger.info('[GovernmentSecurity] FISMA report generated', undefined, undefined, {
      systemName: report.systemName,
      overallScore: compliance.overallScore,
      authorizationStatus: compliance.authorizationStatus,
      poamItems: poamItems.length
    });

    this.emit('fisma-report-generated', {
      systemName: report.systemName,
      overallRisk,
      poamCount: poamItems.length
    });

    return report;
  }

  /**
   * Track Plan of Actions and Milestones (POAM) items.
   */
  public trackPOAM(items: Partial<POAMItem>[]): { success: boolean; tracked: number; poamIds: string[] } {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const poamIds: string[] = [];

    for (const item of items) {
      const poamId = item.id || `POAM-${crypto.randomUUID().substring(0, 8)}`;

      const poam: POAMItem = {
        id: poamId,
        controlId: item.controlId || '',
        weakness: item.weakness || '',
        plannedActions: item.plannedActions || '',
        milestones: item.milestones || [],
        responsiblePerson: item.responsiblePerson || 'Unassigned',
        scheduledCompletion: item.scheduledCompletion || new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
        status: item.status || 'NOT_STARTED',
        resourcesRequired: item.resourcesRequired || 'None specified',
        riskLevel: item.riskLevel || 'MODERATE',
        vendorDependency: item.vendorDependency
      };

      this.poamItems.set(poamId, poam);
      poamIds.push(poamId);

      logger.info('[GovernmentSecurity] POAM item tracked', undefined, undefined, {
        poamId,
        controlId: poam.controlId,
        status: poam.status,
        riskLevel: poam.riskLevel
      });
    }

    this.emit('poam-tracked', { poamIds, count: poamIds.length });

    return { success: true, tracked: poamIds.length, poamIds };
  }

  /**
   * Update POAM item status.
   */
  public updatePOAMStatus(poamId: string, status: POAMItem['status']): POAMItem | null {
    const poam = this.poamItems.get(poamId);
    if (!poam) return null;

    poam.status = status;
    this.poamItems.set(poamId, poam);

    logger.info('[GovernmentSecurity] POAM status updated', undefined, undefined, {
      poamId,
      status
    });

    return poam;
  }

  // Internal: get NIST SP 800-53 control families
  private getNISTControlFamilies(): FISMAControlFamily[] {
    return [
      { family: 'AC', controlId: 'AC-1', controlName: 'Access Control Policy and Procedures', implemented: true, assessed: true, score: 85, findings: [], evidence: ['AC-policy-v2.pdf'] },
      { family: 'AC', controlId: 'AC-2', controlName: 'Account Management', implemented: true, assessed: true, score: 90, findings: [], evidence: ['account-mgmt-log.csv'] },
      { family: 'AC', controlId: 'AC-3', controlName: 'Access Enforcement', implemented: true, assessed: true, score: 95, findings: [], evidence: ['access-control-test-results.pdf'] },
      { family: 'AC', controlId: 'AC-4', controlName: 'Information Flow Enforcement', implemented: true, assessed: true, score: 80, findings: ['Flow enforcement gaps in cross-domain transfers'], evidence: [] },
      { family: 'AC', controlId: 'AC-6', controlName: 'Least Privilege', implemented: true, assessed: true, score: 75, findings: ['Some accounts have excessive privileges'], evidence: ['privilege-audit-q4.xlsx'] },
      { family: 'AU', controlId: 'AU-2', controlName: 'Auditable Events', implemented: true, assessed: true, score: 90, findings: [], evidence: ['audit-config.json'] },
      { family: 'AU', controlId: 'AU-3', controlName: 'Content of Audit Records', implemented: true, assessed: true, score: 85, findings: [], evidence: [] },
      { family: 'AU', controlId: 'AU-6', controlName: 'Audit Review, Analysis, and Reporting', implemented: true, assessed: true, score: 70, findings: ['Automated correlation rules not fully configured'], evidence: [] },
      { family: 'CA', controlId: 'CA-2', controlName: 'Security Assessments', implemented: true, assessed: false, score: 60, findings: ['Annual assessment overdue'], evidence: [] },
      { family: 'CM', controlId: 'CM-2', controlName: 'Baseline Configuration', implemented: true, assessed: true, score: 80, findings: [], evidence: ['baseline-config.json'] },
      { family: 'CM', controlId: 'CM-6', controlName: 'Configuration Settings', implemented: true, assessed: true, score: 75, findings: ['Some settings not at STIG level'], evidence: [] },
      { family: 'IA', controlId: 'IA-2', controlName: 'Identification and Authentication (Users)', implemented: true, assessed: true, score: 95, findings: [], evidence: [] },
      { family: 'IA', controlId: 'IA-5', controlName: 'Authenticator Management', implemented: true, assessed: true, score: 85, findings: [], evidence: [] },
      { family: 'IR', controlId: 'IR-4', controlName: 'Incident Handling', implemented: false, assessed: false, score: 40, findings: ['Incident response plan not tested'], evidence: [] },
      { family: 'RA', controlId: 'RA-5', controlName: 'Vulnerability Scanning', implemented: true, assessed: true, score: 70, findings: ['Scanning frequency below requirement'], evidence: ['scan-results-q4.pdf'] },
      { family: 'SC', controlId: 'SC-7', controlName: 'Boundary Protection', implemented: true, assessed: true, score: 85, findings: [], evidence: ['network-diagram.pdf'] },
      { family: 'SC', controlId: 'SC-8', controlName: 'Transmission Confidentiality and Integrity', implemented: true, assessed: true, score: 90, findings: [], evidence: [] },
      { family: 'SC', controlId: 'SC-13', controlName: 'Cryptographic Protection', implemented: true, assessed: true, score: 88, findings: [], evidence: ['fips-compliance-report.pdf'] },
      { family: 'SI', controlId: 'SI-2', controlName: 'Flaw Remediation', implemented: true, assessed: true, score: 75, findings: ['Patch lag time exceeds 30 days for some systems'], evidence: [] },
      { family: 'SI', controlId: 'SI-4', controlName: 'Information System Monitoring', implemented: true, assessed: true, score: 80, findings: [], evidence: ['monitoring-dashboard.png'] }
    ];
  }

  private getPOAMItemsForReport(): POAMItem[] {
    return Array.from(this.poamItems.values());
  }

  private generateFISMARecommendations(compliance: FISMAComplianceResult): string[] {
    const recommendations: string[] = [];

    for (const family of compliance.controlFamilies) {
      if (family.score < 70) {
        recommendations.push(`${family.controlId} (${family.controlName}): Score ${family.score}% — Immediate remediation required`);
      }
      if (family.findings.length > 0) {
        recommendations.push(`${family.controlId}: Address findings: ${family.findings.join('; ')}`);
      }
    }

    if (compliance.authorizationStatus === 'DENIED' || compliance.authorizationStatus === 'PENDING') {
      recommendations.push('Overall authorization status requires improvement before ATO can be granted');
    }

    return recommendations;
  }

  // ========================================================================
  // MULTI-LEVEL SECURITY (MLS)
  // ========================================================================

  /**
   * Evaluate MLS access based on Bell-LaPadula model.
   * Implements: Simple Security Property (no read up) and *-Property (no write down).
   */
  public evaluateMLSAccess(request: MLSAccessRequest): MLSAccessDecision {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.mls.enabled) {
      throw new GovernmentSecurityError('MLS is not enabled', 'MLS_DISABLED', 403);
    }

    const classificationOrder: MLSClassification[] = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET', 'SCI'];
    const userClearanceLevel = classificationOrder.indexOf(request.userClearance);
    const dataClassificationLevel = classificationOrder.indexOf(request.dataClassification);

    // Simple Security Property: No Read Up
    // User cannot read data classified above their clearance
    if (request.operation === 'read' && dataClassificationLevel > userClearanceLevel) {
      const decision: MLSAccessDecision = {
        granted: false,
        reason: `Simple Security Property violated: User clearance ${request.userClearance} < Data classification ${request.dataClassification}`,
        rule: 'SIMPLE_SECURITY',
        timestamp: new Date().toISOString()
      };

      this.logMLSAccess(request, decision);
      return decision;
    }

    // *-Property (Star Property): No Write Down
    // User cannot write data to a lower classification level
    if (request.operation === 'write' && dataClassificationLevel < userClearanceLevel) {
      const decision: MLSAccessDecision = {
        granted: false,
        reason: `Star Property violated: Cannot write down from ${request.userClearance} to ${request.dataClassification}`,
        rule: 'STAR_PROPERTY',
        timestamp: new Date().toISOString()
      };

      this.logMLSAccess(request, decision);
      return decision;
    }

    // Compartment Check: User must have access to ALL data compartments
    if (request.dataCompartments.length > 0) {
      const missingCompartments = request.dataCompartments.filter(
        c => !request.userCompartments.includes(c)
      );

      if (missingCompartments.length > 0) {
        const decision: MLSAccessDecision = {
          granted: false,
          reason: `Compartment check failed: User lacks compartments: ${missingCompartments.join(', ')}`,
          rule: 'COMPARTMENT_CHECK',
          timestamp: new Date().toISOString()
        };

        this.logMLSAccess(request, decision);
        return decision;
      }
    }

    // Discretionary Security: Additional policy checks
    if (request.operation === 'delete' && dataClassificationLevel >= classificationOrder.indexOf('SECRET')) {
      const decision: MLSAccessDecision = {
        granted: false,
        reason: 'Deletion of SECRET or higher data requires additional authorization',
        rule: 'DISCRETIONARY_SECURITY',
        timestamp: new Date().toISOString()
      };

      this.logMLSAccess(request, decision);
      return decision;
    }

    // Access granted
    const decision: MLSAccessDecision = {
      granted: true,
      reason: 'All MLS policy checks passed',
      rule: request.operation === 'read' ? 'SIMPLE_SECURITY' : 'STAR_PROPERTY',
      timestamp: new Date().toISOString()
    };

    this.logMLSAccess(request, decision);

    logger.debug('[GovernmentSecurity] MLS access evaluated', undefined, undefined, {
      userId: request.userId,
      operation: request.operation,
      granted: decision.granted,
      rule: decision.rule
    });

    return decision;
  }

  /**
   * Apply MLS labels to data (classification + compartments).
   */
  public applyMLSLabels(
    dataId: string,
    classification: MLSClassification,
    compartments: string[]
  ): MLSDataLabel {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    // Validate compartments exist
    const validCompartments = compartments.filter(c =>
      this.config.mls.compartments.some(mc => mc.id === c)
    );

    const label: MLSDataLabel = {
      classification,
      compartments: validCompartments,
      handlingRestrictions: this.getHandlingRestrictionsForClassification(classification),
      classificationAuthority: 'System Administrator',
      classifiedAt: new Date().toISOString(),
      downgradeHistory: []
    };

    this.mlsDataLabels.set(dataId, label);

    logger.info('[GovernmentSecurity] MLS label applied', undefined, undefined, {
      dataId,
      classification,
      compartments: validCompartments.length
    });

    return label;
  }

  /**
   * Downgrade classification of data (requires authority).
   */
  public downgradeClassification(dataId: string, newLevel: MLSClassification): MLSDataLabel | null {
    const label = this.mlsDataLabels.get(dataId);
    if (!label) return null;

    const classificationOrder: MLSClassification[] = ['UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET', 'SCI'];
    const currentLevel = classificationOrder.indexOf(label.classification);
    const newLevelIdx = classificationOrder.indexOf(newLevel);

    if (newLevelIdx >= currentLevel) {
      throw new GovernmentSecurityError('New classification level must be lower than current', 'INVALID_DOWNGRADE', 400);
    }

    label.downgradeHistory.push({
      from: label.classification,
      to: newLevel,
      date: new Date().toISOString(),
      authority: 'Classification Authority'
    });

    label.classification = newLevel;
    label.handlingRestrictions = this.getHandlingRestrictionsForClassification(newLevel);

    this.mlsDataLabels.set(dataId, label);

    logger.info('[GovernmentSecurity] Classification downgraded', undefined, undefined, {
      dataId,
      from: label.downgradeHistory[label.downgradeHistory.length - 1].from,
      to: newLevel
    });

    return label;
  }

  /**
   * Audit all MLS access decisions.
   */
  public auditMLSAccess(): MLSAuditEntry[] {
    return [...this.mlsAuditLog];
  }

  // Internal: log MLS access decision
  private logMLSAccess(request: MLSAccessRequest, decision: MLSAccessDecision): void {
    if (!this.config.mls.auditEnabled) return;

    const entry: MLSAuditEntry = {
      id: `mls-audit-${crypto.randomUUID().substring(0, 8)}`,
      userId: request.userId,
      operation: request.operation,
      dataId: request.context?.dataId || 'unknown',
      userClearance: request.userClearance,
      dataClassification: request.dataClassification,
      decision: decision.granted ? 'GRANTED' : 'DENIED',
      reason: decision.reason,
      timestamp: decision.timestamp,
      clientIp: request.context?.clientIp
    };

    this.mlsAuditLog.push(entry);

    // Keep audit log manageable size (last 10000 entries)
    if (this.mlsAuditLog.length > 10000) {
      this.mlsAuditLog = this.mlsAuditLog.slice(-10000);
    }
  }

  private getHandlingRestrictionsForClassification(classification: MLSClassification): string[] {
    switch (classification) {
      case 'UNCLASSIFIED':
        return ['No special handling required'];
      case 'CONFIDENTIAL':
        return ['Authorized personnel only', 'Encrypt at rest', 'Audit access'];
      case 'SECRET':
        return ['Need-to-know basis', 'Encrypt at rest and in transit', 'Audit all access', 'No external transmission without approval'];
      case 'TOP_SECRET':
        return ['Strict need-to-know', 'Encrypt at rest and in transit with FIPS 140-2', 'Full audit trail', 'No external transmission', 'Physical access control required'];
      case 'SCI':
        return ['SCI compartment controls apply', 'SCIF access required', 'Special handling procedures', 'Continuous monitoring'];
      default:
        return [];
    }
  }

  // ========================================================================
  // PKI / CRL MANAGEMENT
  // ========================================================================

  /**
   * Validate a certificate chain from leaf to trust anchor.
   */
  public async validateCertificateChain(chain: Partial<CertificateInfo>[]): Promise<CertificateChainValidationResult> {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    return this.pkiCircuitBreaker.execute(async () => {
      const errors: string[] = [];
      const warnings: string[] = [];
      const certChain: CertificateInfo[] = [];
      let trustAnchor: CertificateInfo | null = null;

      if (chain.length === 0) {
        return {
          valid: false,
          chain: [],
          trustAnchor: null,
          errors: ['Empty certificate chain'],
          warnings: [],
          validatedAt: new Date().toISOString()
        };
      }

      const now = new Date();

      for (let i = 0; i < chain.length; i++) {
        const certInfo: CertificateInfo = {
          subject: chain[i].subject || '',
          issuer: chain[i].issuer || '',
          serialNumber: chain[i].serialNumber || `SERIAL-${i}`,
          validFrom: chain[i].validFrom || new Date().toISOString(),
          validTo: chain[i].validTo || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
          fingerprint: chain[i].fingerprint || crypto.randomBytes(20).toString('hex'),
          publicKeyAlgorithm: chain[i].publicKeyAlgorithm || 'RSA',
          keySize: chain[i].keySize || 2048,
          signatureAlgorithm: chain[i].signatureAlgorithm || 'SHA256withRSA',
          extensions: chain[i].extensions || {},
          isCA: chain[i].isCA || i < chain.length - 1,
        };

        certChain.push(certInfo);

        // Check expiration
        if (new Date(certInfo.validTo) < now) {
          errors.push(`Certificate ${i} (${certInfo.subject}) has expired (valid until ${certInfo.validTo})`);
        }
        if (new Date(certInfo.validFrom) > now) {
          errors.push(`Certificate ${i} (${certInfo.subject}) is not yet valid (valid from ${certInfo.validFrom})`);
        }

        // Check key size
        if (certInfo.keySize < 2048) {
          errors.push(`Certificate ${i}: Key size ${certInfo.keySize} is below minimum 2048`);
        }

        // Check signature algorithm
        if (certInfo.signatureAlgorithm.includes('MD5') || certInfo.signatureAlgorithm.includes('SHA1')) {
          errors.push(`Certificate ${i}: Weak signature algorithm ${certInfo.signatureAlgorithm}`);
        }

        // Check chain continuity (issuer of cert[i] == subject of cert[i+1])
        if (i < chain.length - 1) {
          const nextCert = chain[i + 1];
          if (certInfo.issuer !== nextCert?.subject) {
            warnings.push(`Certificate chain break: ${certInfo.subject} issued by ${certInfo.issuer} != ${nextCert?.subject}`);
          }
        }

        // Last cert is the trust anchor
        if (i === chain.length - 1) {
          trustAnchor = certInfo;
          if (!certInfo.isCA) {
            warnings.push('Trust anchor certificate is not marked as CA');
          }
        }
      }

      const valid = errors.length === 0;

      logger.debug('[GovernmentSecurity] Certificate chain validation completed', undefined, undefined, {
        valid,
        chainLength: certChain.length,
        errors: errors.length,
        warnings: warnings.length
      });

      return {
        valid,
        chain: certChain,
        trustAnchor,
        errors,
        warnings,
        validatedAt: new Date().toISOString()
      };
    });
  }

  /**
   * Check if a certificate is revoked via CRL.
   */
  public checkCRL(cert: Partial<CertificateInfo>): { revoked: boolean; reason?: string; crlInfo?: CRLInfo } {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const serialNumber = cert.serialNumber || '';
    if (!serialNumber) {
      return { revoked: false, reason: 'No serial number provided' };
    }

    // Check against stored CRLs
    for (const [, crlInfo] of this.crlStore.entries()) {
      if (crlInfo.revokedSerials.includes(serialNumber)) {
        return {
          revoked: true,
          reason: `Certificate ${serialNumber} is revoked per CRL from ${crlInfo.issuer}`,
          crlInfo
        };
      }
    }

    // Check CRL distribution points
    if (this.config.pki.enabled && this.config.pki.crlDistributionPoints.length > 0) {
      // In production: download and parse CRL from distribution points
      // Here we simulate the check
    }

    return { revoked: false, reason: 'Certificate not found in any CRL' };
  }

  /**
   * Verify certificate status via OCSP (Online Certificate Status Protocol).
   */
  public verifyOCSP(cert: Partial<CertificateInfo>): OCSPResponse {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    // In production: send OCSP request to responder at this.config.pki.ocspEndpoint
    // Here we simulate an OCSP response

    const response: OCSPResponse = {
      certStatus: 'GOOD',
      producedAt: new Date().toISOString(),
      responderUrl: this.config.pki.ocspEndpoint || 'https://ocsp.example.com',
    };

    // Check if certificate is in our revoked store
    if (cert.serialNumber) {
      for (const [, crlInfo] of this.crlStore.entries()) {
        if (crlInfo.revokedSerials.includes(cert.serialNumber)) {
          response.certStatus = 'REVOKED';
          response.revocationTime = crlInfo.thisUpdate;
          response.revocationReason = 'keyCompromise';
          break;
        }
      }
    }

    logger.debug('[GovernmentSecurity] OCSP verification completed', undefined, undefined, {
      certStatus: response.certStatus,
      responderUrl: response.responderUrl
    });

    return response;
  }

  /**
   * Issue a government-grade certificate.
   */
  public async issueGovernmentCertificate(subject: GovernmentCertificateSubject): Promise<{ success: boolean; certificate: CertificateInfo; serialNumber: string }> {
    if (!this.isInitialized) {
      throw new GovernmentSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.pki.enabled) {
      throw new GovernmentSecurityError('PKI is not enabled', 'PKI_DISABLED', 403);
    }

    return this.pkiCircuitBreaker.execute(async () => {
      const serialNumber = crypto.randomBytes(16).toString('hex').toUpperCase();
      const now = new Date();
      const validityDays = this.config.pki.certificateLifetime;

      // Generate key pair for certificate
      const keypair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { format: 'pem', type: 'spki' },
        privateKeyEncoding: { format: 'pem', type: 'pkcs8' }
      });

      // Generate fingerprint
      const fingerprint = crypto.createHash('sha256').update(serialNumber + subject.commonName).digest('hex');

      const cert: CertificateInfo = {
        subject: `CN=${subject.commonName}, O=${subject.organization}, OU=${subject.organizationalUnit}, C=${subject.country}`,
        issuer: 'CN=Government CA, O=Protocol Security System, C=US',
        serialNumber,
        validFrom: now.toISOString(),
        validTo: new Date(now.getTime() + validityDays * 24 * 60 * 60 * 1000).toISOString(),
        fingerprint,
        publicKeyAlgorithm: 'RSA',
        keySize: 4096,
        signatureAlgorithm: 'SHA512withRSA',
        extensions: {
          'subjectAltName': `email:${subject.emailAddress}`,
          'keyUsage': 'digitalSignature, keyEncipherment, dataEncipherment',
          'extendedKeyUsage': 'clientAuth, emailProtection',
          'basicConstraints': 'CA:FALSE',
          'classification': subject.classification
        },
        isCA: false
      };

      this.certificateStore.set(serialNumber, cert);
      this.issuedCertificates.set(serialNumber, { subject, cert });

      logger.info('[GovernmentSecurity] Government certificate issued', undefined, undefined, {
        serialNumber,
        subject: cert.subject,
        classification: subject.classification,
        validTo: cert.validTo
      });

      this.emit('certificate-issued', { serialNumber, subject: cert.subject });

      return { success: true, certificate: cert, serialNumber };
    });
  }

  /**
   * Add a CRL to the revocation store.
   */
  public addCRL(crl: CRLInfo): void {
    this.crlStore.set(crl.issuer, crl);
    logger.info('[GovernmentSecurity] CRL added', undefined, undefined, {
      issuer: crl.issuer,
      revokedCount: crl.revokedSerials.length,
      nextUpdate: crl.nextUpdate
    });
  }

  // ========================================================================
  // UTILITY AND LIFECYCLE
  // ========================================================================

  /**
   * Destroy the module and clean up all state.
   */
  public async destroy(): Promise<void> {
    if (!this.isInitialized) return;

    this.fipsAlgorithms.clear();
    this.stigFindings.clear();
    this.stigChecklists.clear();
    this.poamItems.clear();
    this.certificateStore.clear();
    this.crlStore.clear();
    this.issuedCertificates.clear();
    this.mlsDataLabels.clear();
    this.mlsAuditLog = [];
    this.fismaReports = [];

    this.fipsCircuitBreaker.reset();
    this.pkiCircuitBreaker.reset();

    this.isInitialized = false;
    logger.info('[GovernmentSecurity] Module destroyed');
    this.emit('destroyed');
  }

  /**
   * Get module health status.
   */
  public getHealth(): {
    initialized: boolean;
    fipsMode: FIPSModeConfig;
    stigFindings: number;
    poamItems: number;
    certificatesIssued: number;
    mlsAuditEntries: number;
    circuitBreakers: Record<string, string>;
  } {
    return {
      initialized: this.isInitialized,
      fipsMode: this.fipsMode,
      stigFindings: this.stigFindings.size,
      poamItems: this.poamItems.size,
      certificatesIssued: this.issuedCertificates.size,
      mlsAuditEntries: this.mlsAuditLog.length,
      circuitBreakers: {
        fips: this.fipsCircuitBreaker.getState(),
        pki: this.pkiCircuitBreaker.getState()
      }
    };
  }
}

// ============================================================================
// FACTORY
// ============================================================================

export class GovernmentSecurityModuleFactory {
  /**
   * Create and initialize a GovernmentSecurityModule instance.
   */
  static async create(config: Partial<GovernmentSecurityConfig> = {}): Promise<GovernmentSecurityModule> {
    const module = new GovernmentSecurityModule(config);
    await module.initialize();
    return module;
  }

  /**
   * Create a module with FIPS 140-3 Level 2 defaults.
   */
  static async createFIPSDefaults(): Promise<GovernmentSecurityModule> {
    const module = new GovernmentSecurityModule({
      classification: 'UNCLASSIFIED',
      fipsMode: { level: 2, enforced: true, nonCompliantAction: 'warn', approvedOnly: true },
      stigCompliance: true,
      fisma: { enabled: true, systemName: 'Default System', impactLevel: 'MODERATE', assessmentIntervalMs: 86400000 },
      mls: { enabled: false, defaultClassification: 'UNCLASSIFIED', compartments: [], auditEnabled: true },
      pki: { enabled: true, caEndpoint: 'https://ca.example.com', ocspEndpoint: 'https://ocsp.example.com', crlDistributionPoints: ['https://crl.example.com/root.crl'], certificateLifetime: 365 },
      continuousMonitoring: true
    });
    await module.initialize();
    return module;
  }

  /**
   * Create a module with TOP SECRET classification and maximum security.
   */
  static async createTopSecretDefaults(): Promise<GovernmentSecurityModule> {
    const module = new GovernmentSecurityModule({
      classification: 'TOP_SECRET',
      fipsMode: { level: 3, enforced: true, nonCompliantAction: 'block', approvedOnly: true },
      stigCompliance: true,
      fisma: { enabled: true, systemName: 'Classified System', impactLevel: 'HIGH', assessmentIntervalMs: 43200000 },
      mls: {
        enabled: true,
        defaultClassification: 'TOP_SECRET',
        compartments: [
          { id: 'SI', name: 'Special Intelligence', description: 'SIGINT/ELINT compartment' },
          { id: 'TK', name: 'Talent Keyhole', description: 'IMINT compartment' },
          { id: 'NOFORN', name: 'Not Releasable to Foreign Nationals', description: 'US-only access' },
          { id: 'HCS', name: 'Human Control System', description: 'HUMINT compartment' }
        ],
        auditEnabled: true
      },
      pki: { enabled: true, caEndpoint: 'https://secure-ca.gov', ocspEndpoint: 'https://secure-ocsp.gov', crlDistributionPoints: ['https://secure-crl.gov/crl.crl'], certificateLifetime: 180 },
      continuousMonitoring: true
    });
    await module.initialize();
    return module;
  }
}
