/**
 * ============================================================================
 * CLOUD-NATIVE SECURITY MODULE
 * ============================================================================
 * Kubernetes Security, CSPM, Infrastructure as Code Security,
 * Container Runtime Security, Cloud Workload Protection
 *
 * Соответствие: CIS Kubernetes Benchmark, NIST SP 800-190,
 * CIS AWS/Azure/GCP Benchmarks, NSA/CISA Kubernetes Hardening Guide
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import { logger } from '../logging/Logger';

// ============================================================================
// SECURITY ERRORS
// ============================================================================

class CloudSecurityError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(message: string, code: string, statusCode: number = 500) {
    super(message);
    this.name = 'CloudSecurityError';
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
        throw new CloudSecurityError(`Circuit breaker '${this.name}' is OPEN`, 'CIRCUIT_OPEN', 503);
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
      logger.warn(`[CloudSecurity] Circuit breaker '${this.name}' tripped OPEN`);
    }
  }

  getState(): CircuitState { return this.state; }
  reset(): void { this.state = CircuitState.CLOSED; this.failureCount = 0; this.successCount = 0; }
}

// ============================================================================
// TYPES — Kubernetes Security
// ============================================================================

export interface PodSecurityPolicy {
  name: string;
  privileged: boolean;
  hostNetwork: boolean;
  hostPID: boolean;
  hostIPC: boolean;
  runAsUser: { rule: 'MustRunAs' | 'MustRunAsNonRoot' | 'RunAsAny'; ranges?: { min: number; max: number }[] };
  seLinux: { rule: 'MustRunAs' | 'RunAsAny'; level?: string };
  volumes: string[];
  allowedCapabilities: string[];
  requiredDropCapabilities: string[];
  readOnlyRootFilesystem: boolean;
  allowPrivilegeEscalation: boolean;
}

export interface PodSecurityEvaluationResult {
  compliant: boolean;
  policyName: string;
  violations: PodSecurityViolation[];
  warnings: string[];
  evaluatedAt: string;
}

export interface PodSecurityViolation {
  field: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  message: string;
  recommendation: string;
}

export interface ContainerImageScanResult {
  imageRef: string;
  scanId: string;
  vulnerabilities: ContainerVulnerability[];
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  scanCompletedAt: string;
  scanner: string;
  passed: boolean;
}

export interface ContainerVulnerability {
  id: string;
  package: string;
  installedVersion: string;
  fixedVersion: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  description: string;
  cvssScore: number;
  cvssVector: string;
  nvdUrl: string;
}

export interface NetworkPolicy {
  name: string;
  namespace: string;
  podSelector: Record<string, string>;
  policyTypes: ('Ingress' | 'Egress')[];
  ingressRules: NetworkPolicyRule[];
  egressRules: NetworkPolicyRule[];
}

export interface NetworkPolicyRule {
  from?: { podSelector?: Record<string, string>; namespaceSelector?: Record<string, string>; ipBlock?: { cidr: string; except?: string[] } }[];
  to?: { podSelector?: Record<string, string>; namespaceSelector?: Record<string, string>; ipBlock?: { cidr: string; except?: string[] } }[];
  ports?: { protocol: string; port: number }[];
}

export interface RBACBindingAudit {
  clusterRole: string;
  subjects: Array<{ kind: string; name: string; namespace?: string }>;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  riskReasons: string[];
  isClusterAdmin: boolean;
  isDefaultNamespace: boolean;
  overprivileged: boolean;
  recommendations: string[];
}

export interface PrivilegedContainerInfo {
  namespace: string;
  podName: string;
  containerName: string;
  image: string;
  privileged: boolean;
  hostNetwork: boolean;
  hostPID: boolean;
  capabilities: string[];
  runAsRoot: boolean;
  riskScore: number;
}

// ============================================================================
// TYPES — CSPM
// ============================================================================

export type CloudProvider = 'aws' | 'azure' | 'gcp' | 'oci';

export interface CloudPostureAssessment {
  cloudProvider: CloudProvider;
  overallScore: number; // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  misconfigurations: CloudMisconfiguration[];
  complianceFrameworks: ComplianceFrameworkResult[];
  assessedAt: string;
}

export interface CloudMisconfiguration {
  id: string;
  resourceType: string;
  resourceId: string;
  cloudProvider: CloudProvider;
  region: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  expected: string;
  actual: string;
  remediation: string;
  cisBenchmarkId?: string;
  nistControlId?: string;
  detectedAt: string;
}

export interface RemediationResult {
  success: boolean;
  misconfigurationId: string;
  action: string;
  details: string;
  timestamp: string;
  error?: string;
}

export interface ComplianceFrameworkResult {
  framework: string;
  version: string;
  compliancePercentage: number;
  totalControls: number;
  passedControls: number;
  failedControls: number;
  applicableControls: number;
}

// ============================================================================
// TYPES — Infrastructure as Code Security
// ============================================================================

export type IaCFormat = 'terraform' | 'cloudformation' | 'kubernetes' | 'arm' | 'pulumi' | 'helm';

export interface IaCScanResult {
  filePath: string;
  format: IaCFormat;
  scanId: string;
  violations: IaCViolation[];
  vulnerabilities: IaCVulnerability[];
  totalIssues: number;
  criticalCount: number;
  highCount: number;
  passed: boolean;
  scannedAt: string;
}

export interface IaCViolation {
  id: string;
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  resource: string;
  attribute: string;
  message: string;
  recommendation: string;
  cisBenchmark?: string;
}

export interface IaCVulnerability {
  id: string;
  cveId?: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  component: string;
  description: string;
  fixAvailable: boolean;
  fixVersion?: string;
}

export interface IaCReport {
  totalFilesScanned: number;
  totalViolations: number;
  totalVulnerabilities: number;
  criticalCount: number;
  highCount: number;
  scanResults: IaCScanResult[];
  summary: {
    passRate: number;
    topViolations: Array<{ rule: string; count: number }>;
    topVulnerabilities: Array<{ component: string; count: number }>;
  };
  generatedAt: string;
}

// ============================================================================
// TYPES — Container Runtime Security
// ============================================================================

export interface RuntimeAnomalyResult {
  containerId: string;
  anomaliesDetected: boolean;
  anomalies: ContainerAnomaly[];
  riskScore: number;
  assessedAt: string;
}

export interface ContainerAnomaly {
  type: 'process' | 'network' | 'file' | 'user' | 'capability' | 'syscall';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  evidence: string;
  timestamp: string;
}

export interface SeccompProfile {
  defaultAction: 'SCMP_ACT_ALLOW' | 'SCMP_ACT_ERRNO' | 'SCMP_ACT_LOG';
  architectures: string[];
  syscalls: SeccompSyscall[];
}

export interface SeccompSyscall {
  action: 'SCMP_ACT_ALLOW' | 'SCMP_ACT_ERRNO' | 'SCMP_ACT_LOG' | 'SCMP_ACT_KILL' | 'SCMP_ACT_TRAP';
  names: string[];
  args?: Array<{ index: number; value: number; op: string }>;
}

export interface SyscallMonitorResult {
  containerId: string;
  totalSyscalls: number;
  uniqueSyscalls: number;
  suspiciousSyscalls: string[];
  blockedSyscalls: string[];
  topSyscalls: Array<{ name: string; count: number }>;
  monitoredAt: string;
}

export interface CryptoMiningDetectionResult {
  miningDetected: boolean;
  indicators: CryptoMiningIndicator[];
  confidence: number; // 0-100
  affectedContainers: string[];
  detectedAt: string;
}

export interface CryptoMiningIndicator {
  type: 'process' | 'network' | 'cpu' | 'dns' | 'file';
  evidence: string;
  severity: 'critical' | 'high' | 'medium';
  containerId: string;
}

// ============================================================================
// TYPES — Cloud Workload Protection
// ============================================================================

export interface WorkloadIdentity {
  workloadName: string;
  namespace: string;
  cloudProvider: CloudProvider;
  identityProvider: string;
  roleArn?: string;
  serviceAccountEmail?: string;
  managedIdentityId?: string;
  permissions: string[];
  trustedEntities: string[];
  createdAt: string;
}

export interface WorkloadIdentityEvaluation {
  workload: string;
  identityFound: boolean;
  permissionsCount: number;
  overprivileged: boolean;
  unusedPermissions: string[];
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  recommendations: string[];
}

export interface LeastPrivilegeEnforcement {
  workload: string;
  originalPermissions: string[];
  recommendedPermissions: string[];
  removedPermissions: string[];
  enforced: boolean;
  timestamp: string;
}

export interface CloudPermissionAudit {
  cloudProvider: CloudProvider;
  totalIdentities: number;
  overprivilegedIdentities: number;
  unusedRoles: number;
  criticalFindings: CloudPermissionFinding[];
  auditedAt: string;
}

export interface CloudPermissionFinding {
  id: string;
  resourceId: string;
  resourceType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  recommendation: string;
}

export interface LateralMovementDetectionResult {
  detected: boolean;
  indicators: LateralMovementIndicator[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  timeline: string[];
  affectedResources: string[];
  detectedAt: string;
}

export interface LateralMovementIndicator {
  type: 'credential_access' | 'lateral_movement' | 'discovery' | 'privilege_escalation';
  evidence: string;
  sourceResource: string;
  targetResource: string;
  timestamp: string;
  mitreTechnique: string;
}

// ============================================================================
// CONFIG
// ============================================================================

export interface CloudNativeSecurityConfig {
  kubernetes: {
    enabled: boolean;
    admissionController: 'opa' | 'kyverno' | 'built-in';
    networkPolicy: 'calico' | 'cilium' | 'none';
    podSecurityStandard: 'privileged' | 'baseline' | 'restricted';
    clusterName: string;
  };
  cspm: {
    enabled: boolean;
    providers: CloudProvider[];
    autoRemediate: boolean;
    scanIntervalMs: number;
  };
  iac: {
    enabled: boolean;
    formats: IaCFormat[];
    failOnSeverity: 'critical' | 'high' | 'medium' | 'low';
  };
  containerRuntime: {
    enabled: boolean;
    seccompEnabled: boolean;
    apparmorEnabled: boolean;
    monitoringIntervalMs: number;
    miningDetectionEnabled: boolean;
  };
  workloadProtection: {
    enabled: boolean;
    identityDetection: boolean;
    leastPrivilegeEnforcement: boolean;
    lateralMovementDetection: boolean;
  };
}

const DEFAULT_CONFIG: CloudNativeSecurityConfig = {
  kubernetes: {
    enabled: false,
    admissionController: 'built-in',
    networkPolicy: 'none',
    podSecurityStandard: 'baseline',
    clusterName: 'default-cluster'
  },
  cspm: {
    enabled: false,
    providers: [],
    autoRemediate: false,
    scanIntervalMs: 3600000
  },
  iac: {
    enabled: false,
    formats: ['terraform'],
    failOnSeverity: 'high'
  },
  containerRuntime: {
    enabled: false,
    seccompEnabled: false,
    apparmorEnabled: false,
    monitoringIntervalMs: 60000,
    miningDetectionEnabled: false
  },
  workloadProtection: {
    enabled: false,
    identityDetection: false,
    leastPrivilegeEnforcement: false,
    lateralMovementDetection: false
  }
};

// ============================================================================
// CLOUD-NATIVE SECURITY MODULE
// ============================================================================

export class CloudNativeSecurityModule extends EventEmitter {
  private config: CloudNativeSecurityConfig;
  private isInitialized = false;

  // State
  private podSecurityPolicies: Map<string, PodSecurityPolicy> = new Map();
  private containerScanResults: Map<string, ContainerImageScanResult> = new Map();
  private networkPolicies: Map<string, NetworkPolicy> = new Map();
  private rbacAuditResults: Map<string, RBACBindingAudit[]> = new Map();
  private privilegedContainers: PrivilegedContainerInfo[] = [];
  private cloudPostureResults: Map<string, CloudPostureAssessment> = new Map();
  private misconfigurations: Map<string, CloudMisconfiguration> = new Map();
  private iacScanResults: Map<string, IaCScanResult> = new Map();
  private runtimeAnomalyResults: Map<string, RuntimeAnomalyResult> = new Map();
  private seccompProfiles: Map<string, SeccompProfile> = new Map();
  private syscallMonitorResults: Map<string, SyscallMonitorResult> = new Map();
  private workloadIdentities: Map<string, WorkloadIdentity> = new Map();
  private lateralMovementResults: Map<string, LateralMovementDetectionResult> = new Map();
  private securityEvents: Array<{ event: string; severity: string; timestamp: string; detail: string }> = [];

  // Infrastructure
  private k8sCircuitBreaker: CircuitBreaker;
  private cspmCircuitBreaker: CircuitBreaker;
  private runtimeCircuitBreaker: CircuitBreaker;

  constructor(config: Partial<CloudNativeSecurityConfig> = {}) {
    super();
    this.config = this.mergeConfig(DEFAULT_CONFIG, config);
    this.k8sCircuitBreaker = new CircuitBreaker('K8s', 5, 30000, 2);
    this.cspmCircuitBreaker = new CircuitBreaker('CSPM', 3, 60000, 2);
    this.runtimeCircuitBreaker = new CircuitBreaker('Runtime', 3, 30000, 2);

    this.initializeDefaultSeccompProfile();
    this.initializeDefaultPodSecurityPolicies();

    logger.info('[CloudSecurity] Module created', undefined, undefined, {
      kubernetes: this.config.kubernetes.enabled,
      cspm: this.config.cspm.enabled,
      iac: this.config.iac.enabled,
      containerRuntime: this.config.containerRuntime.enabled,
      workloadProtection: this.config.workloadProtection.enabled
    });
  }

  // ========================================================================
  // INITIALIZATION
  // ========================================================================

  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[CloudSecurity] Already initialized');
      return;
    }

    if (this.config.kubernetes.enabled) {
      logger.info('[CloudSecurity] Kubernetes security initialized', undefined, undefined, {
        clusterName: this.config.kubernetes.clusterName,
        admissionController: this.config.kubernetes.admissionController,
        podSecurityStandard: this.config.kubernetes.podSecurityStandard
      });
    }

    if (this.config.cspm.enabled) {
      logger.info('[CloudSecurity] CSPM initialized', undefined, undefined, {
        providers: this.config.cspm.providers
      });
    }

    if (this.config.iac.enabled) {
      logger.info('[CloudSecurity] IaC security initialized', undefined, undefined, {
        formats: this.config.iac.formats,
        failOnSeverity: this.config.iac.failOnSeverity
      });
    }

    if (this.config.containerRuntime.enabled) {
      logger.info('[CloudSecurity] Container runtime security initialized', undefined, undefined, {
        seccomp: this.config.containerRuntime.seccompEnabled,
        miningDetection: this.config.containerRuntime.miningDetectionEnabled
      });
    }

    if (this.config.workloadProtection.enabled) {
      logger.info('[CloudSecurity] Workload protection initialized');
    }

    this.isInitialized = true;
    this.emit('initialized');
    logger.info('[CloudSecurity] Module fully initialized');
  }

  private mergeConfig(defaults: CloudNativeSecurityConfig, overrides: Partial<CloudNativeSecurityConfig>): CloudNativeSecurityConfig {
    return {
      kubernetes: { ...defaults.kubernetes, ...(overrides.kubernetes || {}) },
      cspm: { ...defaults.cspm, ...(overrides.cspm || {}) },
      iac: { ...defaults.iac, ...(overrides.iac || {}) },
      containerRuntime: { ...defaults.containerRuntime, ...(overrides.containerRuntime || {}) },
      workloadProtection: { ...defaults.workloadProtection, ...(overrides.workloadProtection || {}) }
    };
  }

  // ========================================================================
  // KUBERNETES SECURITY
  // ========================================================================

  /**
   * Evaluate Pod Security Policy compliance.
   * Supports Kubernetes Pod Security Standards (PSS): privileged, baseline, restricted.
   */
  public evaluatePodSecurity(policy: Partial<PodSecurityPolicy>): PodSecurityEvaluationResult {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.kubernetes.enabled) {
      throw new CloudSecurityError('Kubernetes security is not enabled', 'K8S_DISABLED', 403);
    }

    const pssLevel = this.config.kubernetes.podSecurityStandard;
    const violations: PodSecurityViolation[] = [];
    const warnings: string[] = [];

    // Check privileged mode
    if (policy.privileged && pssLevel !== 'privileged') {
      violations.push({
        field: 'privileged',
        severity: 'critical',
        message: 'Privileged containers are not allowed',
        recommendation: 'Remove privileged: true or use baseline/restricted with specific capabilities'
      });
    }

    // Check host namespaces
    if (policy.hostNetwork && pssLevel === 'restricted') {
      violations.push({
        field: 'hostNetwork',
        severity: 'high',
        message: 'Host network access is not allowed in restricted mode',
        recommendation: 'Remove hostNetwork: true or use baseline mode'
      });
    }

    if (policy.hostPID && pssLevel !== 'privileged') {
      violations.push({
        field: 'hostPID',
        severity: 'high',
        message: 'Host PID namespace sharing is not allowed',
        recommendation: 'Remove hostPID: true'
      });
    }

    if (policy.hostIPC && pssLevel !== 'privileged') {
      violations.push({
        field: 'hostIPC',
        severity: 'high',
        message: 'Host IPC namespace sharing is not allowed',
        recommendation: 'Remove hostIPC: true'
      });
    }

    // Check runAsUser
    if (policy.runAsUser && policy.runAsUser.rule === 'RunAsAny' && pssLevel === 'restricted') {
      violations.push({
        field: 'runAsUser',
        severity: 'high',
        message: 'runAsUser must be MustRunAsNonRoot in restricted mode',
        recommendation: 'Set runAsUser.rule to MustRunAsNonRoot'
      });
    }

    // Check readOnlyRootFilesystem
    if (!policy.readOnlyRootFilesystem && pssLevel === 'restricted') {
      warnings.push('readOnlyRootFilesystem should be set to true for restricted mode');
    }

    // Check allowPrivilegeEscalation
    if (policy.allowPrivilegeEscalation && pssLevel === 'restricted') {
      violations.push({
        field: 'allowPrivilegeEscalation',
        severity: 'high',
        message: 'Privilege escalation is not allowed in restricted mode',
        recommendation: 'Set allowPrivilegeEscalation to false'
      });
    }

    // Check required drop capabilities
    const requiredDrops = pssLevel === 'restricted' ? ['ALL'] : [];
    const missingDrops = requiredDrops.filter(cap => !policy.requiredDropCapabilities?.includes(cap));
    if (missingDrops.length > 0) {
      violations.push({
        field: 'requiredDropCapabilities',
        severity: 'medium',
        message: `Missing required capability drops: ${missingDrops.join(', ')}`,
        recommendation: `Add ${missingDrops.join(', ')} to requiredDropCapabilities`
      });
    }

    // Check allowed capabilities (NET_RAW is dangerous)
    const dangerousCapabilities = ['NET_RAW', 'SYS_ADMIN', 'SYS_PTRACE', 'DAC_READ_SEARCH'];
    const foundDangerous = policy.allowedCapabilities?.filter(cap => dangerousCapabilities.includes(cap));
    if (foundDangerous && foundDangerous.length > 0) {
      violations.push({
        field: 'allowedCapabilities',
        severity: 'high',
        message: `Dangerous capabilities granted: ${foundDangerous.join(', ')}`,
        recommendation: `Remove dangerous capabilities: ${foundDangerous.join(', ')}`
      });
    }

    // Check volume types
    const dangerousVolumeTypes = ['hostPath', 'nfs', 'iscsi'];
    if (pssLevel === 'restricted') {
      const foundDangerousVolumes = policy.volumes?.filter(v => dangerousVolumeTypes.includes(v));
      if (foundDangerousVolumes && foundDangerousVolumes.length > 0) {
        violations.push({
          field: 'volumes',
          severity: 'high',
          message: `Dangerous volume types in restricted mode: ${foundDangerousVolumes.join(', ')}`,
          recommendation: 'Use configMap, secret, emptyDir, or persistentVolumeClaim instead'
        });
      }
    }

    const compliant = violations.length === 0;
    const policyName = policy.name || `evaluated-${crypto.randomUUID().substring(0, 8)}`;

    const result: PodSecurityEvaluationResult = {
      compliant,
      policyName,
      violations,
      warnings,
      evaluatedAt: new Date().toISOString()
    };

    // Store the policy if it passes
    if (compliant) {
      const fullPolicy: PodSecurityPolicy = {
        name: policyName,
        privileged: policy.privileged || false,
        hostNetwork: policy.hostNetwork || false,
        hostPID: policy.hostPID || false,
        hostIPC: policy.hostIPC || false,
        runAsUser: policy.runAsUser || { rule: 'RunAsAny' },
        seLinux: policy.seLinux || { rule: 'RunAsAny' },
        volumes: policy.volumes || ['*'],
        allowedCapabilities: policy.allowedCapabilities || [],
        requiredDropCapabilities: policy.requiredDropCapabilities || [],
        readOnlyRootFilesystem: policy.readOnlyRootFilesystem || false,
        allowPrivilegeEscalation: policy.allowPrivilegeEscalation || false
      };
      this.podSecurityPolicies.set(policyName, fullPolicy);
    }

    logger.info('[CloudSecurity] Pod security policy evaluated', undefined, undefined, {
      policyName,
      pssLevel,
      compliant,
      violations: violations.length,
      warnings: warnings.length
    });

    this.emit('pod-security-evaluated', result);

    return result;
  }

  /**
   * Scan a container image for vulnerabilities.
   */
  public scanContainerImage(imageRef: string): Promise<ContainerImageScanResult> {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.kubernetes.enabled && !this.config.containerRuntime.enabled) {
      throw new CloudSecurityError('Neither Kubernetes nor Container Runtime security is enabled', 'DISABLED', 403);
    }

    return this.k8sCircuitBreaker.execute(async () => {
      const scanId = `scan-${crypto.randomUUID().substring(0, 8)}`;

      // Simulate image scan — in production, use Trivy, Clair, Grype, Snyk
      const vulnerabilities = this.simulateImageScan(imageRef);

      const criticalCount = vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
      const highCount = vulnerabilities.filter(v => v.severity === 'HIGH').length;
      const mediumCount = vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
      const lowCount = vulnerabilities.filter(v => v.severity === 'LOW').length;

      const passed = criticalCount === 0 && highCount === 0;

      const result: ContainerImageScanResult = {
        imageRef,
        scanId,
        vulnerabilities,
        totalVulnerabilities: vulnerabilities.length,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        scanCompletedAt: new Date().toISOString(),
        scanner: 'Protocol Cloud Security Scanner v1.0',
        passed
      };

      this.containerScanResults.set(scanId, result);

      logger.info('[CloudSecurity] Container image scan completed', undefined, undefined, {
        scanId,
        imageRef,
        totalVulnerabilities: result.totalVulnerabilities,
        critical: criticalCount,
        high: highCount,
        passed
      });

      this.emit('container-image-scanned', { scanId, imageRef, passed });

      return result;
    });
  }

  /**
   * Enforce network policy in a namespace.
   */
  public enforceNetworkPolicy(namespace: string, policy: NetworkPolicy): { success: boolean; policyId: string } {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.kubernetes.enabled) {
      throw new CloudSecurityError('Kubernetes security is not enabled', 'K8S_DISABLED', 403);
    }

    const policyId = `${namespace}/${policy.name}`;
    policy.namespace = namespace;

    this.networkPolicies.set(policyId, policy);

    logger.info('[CloudSecurity] Network policy enforced', undefined, undefined, {
      policyId,
      namespace,
      policyTypes: policy.policyTypes,
      ingressRules: policy.ingressRules.length,
      egressRules: policy.egressRules.length
    });

    this.emit('network-policy-enforced', { policyId, namespace });

    return { success: true, policyId };
  }

  /**
   * Audit RBAC bindings for security issues.
   */
  public auditRBACBindings(cluster: string): RBACBindingAudit[] {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.kubernetes.enabled) {
      throw new CloudSecurityError('Kubernetes security is not enabled', 'K8S_DISABLED', 403);
    }

    const audits: RBACBindingAudit[] = [];

    // Simulate RBAC audit — in production, query Kubernetes API for ClusterRoleBindings and RoleBindings
    const simulatedBindings = this.getSimulatedRBACBindings();

    for (const binding of simulatedBindings) {
      const riskReasons: string[] = [];
      const recommendations: string[] = [];
      let riskLevel: RBACBindingAudit['riskLevel'] = 'low';

      // Check for cluster-admin binding
      const isClusterAdmin = binding.clusterRole === 'cluster-admin';
      if (isClusterAdmin) {
        riskReasons.push('Bound to cluster-admin role — full cluster access');
        recommendations.push('Avoid binding users to cluster-admin; use namespace-scoped roles');
        riskLevel = 'critical';
      }

      // Check for default namespace
      const isDefaultNamespace = binding.subjects.some(s => s.namespace === 'default');
      if (isDefaultNamespace) {
        riskReasons.push('Subject in default namespace');
        recommendations.push('Use dedicated namespaces for workloads');
        if (riskLevel === 'low') riskLevel = 'medium';
      }

      // Check for wildcard subjects
      const hasWildcard = binding.subjects.some(s => s.name === '*');
      if (hasWildcard) {
        riskReasons.push('Wildcard subject — applies to all entities');
        recommendations.push('Use specific subject names instead of wildcards');
        riskLevel = 'critical';
      }

      // Check for overprivileged
      const overprivileged = isClusterAdmin && binding.subjects.length > 3;
      if (overprivileged) {
        riskReasons.push('Multiple subjects bound to cluster-admin — overprivileged');
        recommendations.push('Apply principle of least privilege; audit each binding');
        riskLevel = 'critical';
      }

      audits.push({
        clusterRole: binding.clusterRole,
        subjects: binding.subjects,
        riskLevel,
        riskReasons,
        isClusterAdmin,
        isDefaultNamespace,
        overprivileged,
        recommendations
      });
    }

    this.rbacAuditResults.set(cluster, audits);

    const criticalFindings = audits.filter(a => a.riskLevel === 'critical').length;
    const highFindings = audits.filter(a => a.riskLevel === 'high').length;

    logger.info('[CloudSecurity] RBAC audit completed', undefined, undefined, {
      cluster,
      totalBindings: audits.length,
      criticalFindings,
      highFindings
    });

    this.emit('rbac-audit-completed', { cluster, totalBindings: audits.length, criticalFindings });

    return audits;
  }

  /**
   * Detect privileged containers running in the cluster.
   */
  public detectPrivilegedContainers(): PrivilegedContainerInfo[] {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.kubernetes.enabled) {
      throw new CloudSecurityError('Kubernetes security is not enabled', 'K8S_DISABLED', 403);
    }

    // Simulate detection of privileged containers
    // In production: query Kubernetes API for pods with securityContext.privileged=true
    const simulatedContainers = this.getSimulatedPrivilegedContainers();

    this.privilegedContainers = simulatedContainers;

    const criticalContainers = simulatedContainers.filter(c => c.riskScore >= 80);

    logger.warn('[CloudSecurity] Privileged container detection completed', undefined, undefined, {
      totalPrivileged: simulatedContainers.length,
      criticalRisk: criticalContainers.length
    });

    if (criticalContainers.length > 0) {
      this.emit('privileged-containers-detected', {
        total: simulatedContainers.length,
        critical: criticalContainers.length,
        containers: criticalContainers
      });
    }

    return simulatedContainers;
  }

  // ========================================================================
  // CSPM — Cloud Security Posture Management
  // ========================================================================

  /**
   * Assess cloud security posture for a provider.
   */
  public assessCloudPosture(cloudProvider: CloudProvider): Promise<CloudPostureAssessment> {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.cspm.enabled) {
      throw new CloudSecurityError('CSPM is not enabled', 'CSPM_DISABLED', 403);
    }

    return this.cspmCircuitBreaker.execute(async () => {
      const misconfigurations = this.detectMisconfigurations(cloudProvider, []);
      const complianceFrameworks = this.getComplianceFrameworks(cloudProvider);

      const totalMisconfigs = misconfigurations.length;
      const criticalMisconfigs = misconfigurations.filter(m => m.severity === 'CRITICAL').length;
      const highMisconfigs = misconfigurations.filter(m => m.severity === 'HIGH').length;

      // Calculate posture score
      const score = this.calculatePostureScore(misconfigurations, complianceFrameworks);
      const grade = this.scoreToGrade(score);

      // Store misconfigurations
      for (const mc of misconfigurations) {
        this.misconfigurations.set(mc.id, mc);
      }

      const assessment: CloudPostureAssessment = {
        cloudProvider,
        overallScore: score,
        grade,
        misconfigurations,
        complianceFrameworks,
        assessedAt: new Date().toISOString()
      };

      this.cloudPostureResults.set(cloudProvider, assessment);

      logger.info('[CloudSecurity] Cloud posture assessed', undefined, undefined, {
        provider: cloudProvider,
        score,
        grade,
        misconfigurations: totalMisconfigs,
        critical: criticalMisconfigs,
        high: highMisconfigs
      });

      this.emit('cloud-posture-assessed', assessment);

      return assessment;
    });
  }

  /**
   * Detect misconfigurations in cloud resources.
   */
  public detectMisconfigurations(cloudProvider: CloudProvider, resources: Array<{ type: string; id: string }>): CloudMisconfiguration[] {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const misconfigurations: CloudMisconfiguration[] = [];

    // Simulate misconfiguration detection based on provider
    // In production: use cloud APIs (AWS Config, Azure Policy, GCP Security Command Center)
    const simulatedMisconfigs = this.getSimulatedMisconfigurations(cloudProvider);

    for (const mc of simulatedMisconfigs) {
      misconfigurations.push({ ...mc, cloudProvider, detectedAt: new Date().toISOString() });
    }

    logger.debug('[CloudSecurity] Misconfiguration detection completed', undefined, undefined, {
      provider: cloudProvider,
      misconfigurationCount: misconfigurations.length
    });

    return misconfigurations;
  }

  /**
   * Remediate a misconfiguration automatically.
   */
  public remediateMisconfiguration(finding: CloudMisconfiguration): Promise<RemediationResult> {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.cspm.autoRemediate) {
      throw new CloudSecurityError('Auto-remediation is not enabled', 'AUTO_REMEDIATION_DISABLED', 403);
    }

    return this.cspmCircuitBreaker.execute(async () => {
      // Simulate remediation
      // In production: use cloud SDK/API to apply the fix
      const remediationActions: Record<string, string> = {
        's3-public-bucket': 'Applied bucket policy to deny public access; enabled block public Access',
        'sg-open-ingress': 'Modified security group to restrict 0.0.0.0/0 ingress; applied least-privilege rules',
        'rds-public': 'Disabled public accessibility; placed in private subnet',
        'iam-wildcard-policy': 'Replaced wildcard (*) resource with specific ARN; applied least privilege',
        'encryption-disabled': 'Enabled default encryption with AWS-managed KMS key',
        'logging-disabled': 'Enabled CloudTrail logging with multi-region and log file validation',
        'mfa-disabled': 'Enforced MFA for all IAM users with console access',
        'no-backup': 'Enabled automated backups with 35-day retention; configured cross-region replication',
        'default-network-acl': 'Replaced default NACL with custom restrictive rules',
        'root-account-active': 'Disabled root account access keys; enabled MFA on root'
      };

      const action = remediationActions[finding.id] || `Applied recommended fix for ${finding.id}`;

      // Update finding
      const storedFinding = this.misconfigurations.get(finding.id);
      if (storedFinding) {
        storedFinding.remediation = action;
      }

      const result: RemediationResult = {
        success: true,
        misconfigurationId: finding.id,
        action,
        details: `Auto-remediated: ${action}`,
        timestamp: new Date().toISOString()
      };

      logger.info('[CloudSecurity] Misconfiguration remediated', undefined, undefined, {
        misconfigurationId: finding.id,
        action,
        severity: finding.severity
      });

      this.emit('misconfiguration-remediated', result);

      return result;
    });
  }

  /**
   * Get compliance framework results for a cloud provider.
   */
  public getComplianceFrameworks(cloudProvider: CloudProvider): ComplianceFrameworkResult[] {
    return [
      {
        framework: 'CIS',
        version: '1.5.0',
        compliancePercentage: 78,
        totalControls: 120,
        passedControls: 94,
        failedControls: 26,
        applicableControls: 120
      },
      {
        framework: 'NIST CSF',
        version: '1.1',
        compliancePercentage: 82,
        totalControls: 108,
        passedControls: 89,
        failedControls: 19,
        applicableControls: 108
      },
      {
        framework: 'SOC 2',
        version: '2017',
        compliancePercentage: 75,
        totalControls: 64,
        passedControls: 48,
        failedControls: 16,
        applicableControls: 64
      },
      {
        framework: 'PCI DSS',
        version: '4.0',
        compliancePercentage: 70,
        totalControls: 250,
        passedControls: 175,
        failedControls: 75,
        applicableControls: 200
      }
    ];
  }

  // ========================================================================
  // INFRASTRUCTURE AS CODE SECURITY
  // ========================================================================

  /**
   * Scan IaC file for security issues.
   */
  public scanIaCFile(filePath: string, format: IaCFormat): IaCScanResult {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.iac.enabled) {
      throw new CloudSecurityError('IaC scanning is not enabled', 'IAC_DISABLED', 403);
    }

    const scanId = `iac-scan-${crypto.randomUUID().substring(0, 8)}`;

    // Simulate IaC scan — in production, use Checkov, tfsec, cfn-lint, kube-score
    const { violations, vulnerabilities } = this.simulateIaCScan(filePath, format);

    const criticalCount = violations.filter(v => v.severity === 'critical').length +
                          vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highCount = violations.filter(v => v.severity === 'high').length +
                      vulnerabilities.filter(v => v.severity === 'HIGH').length;

    const failSeverity = this.config.iac.failOnSeverity;
    const failed = (failSeverity === 'critical' && criticalCount > 0) ||
                   (failSeverity === 'high' && (criticalCount + highCount) > 0) ||
                   (failSeverity === 'medium' && true) ||
                   (failSeverity === 'low' && true);

    const result: IaCScanResult = {
      filePath,
      format,
      scanId,
      violations,
      vulnerabilities,
      totalIssues: violations.length + vulnerabilities.length,
      criticalCount,
      highCount,
      passed: !failed,
      scannedAt: new Date().toISOString()
    };

    this.iacScanResults.set(scanId, result);

    logger.info('[CloudSecurity] IaC file scan completed', undefined, undefined, {
      scanId,
      filePath,
      format,
      totalIssues: result.totalIssues,
      critical: criticalCount,
      high: highCount,
      passed: result.passed
    });

    this.emit('iac-scan-completed', result);

    return result;
  }

  /**
   * Detect vulnerabilities in IaC scan results.
   */
  public detectIaCVulnerabilities(scanResult: IaCScanResult): IaCVulnerability[] {
    return scanResult.vulnerabilities.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH');
  }

  /**
   * Generate comprehensive IaC scanning report.
   */
  public generateIaCReport(): IaCReport {
    const scanResults = Array.from(this.iacScanResults.values());
    const totalFilesScanned = scanResults.length;
    const totalViolations = scanResults.reduce((sum, r) => sum + r.violations.length, 0);
    const totalVulnerabilities = scanResults.reduce((sum, r) => sum + r.vulnerabilities.length, 0);
    const criticalCount = scanResults.reduce((sum, r) => sum + r.criticalCount, 0);
    const highCount = scanResults.reduce((sum, r) => sum + r.highCount, 0);

    const passedFiles = scanResults.filter(r => r.passed).length;
    const passRate = totalFilesScanned > 0 ? Math.round((passedFiles / totalFilesScanned) * 100) : 100;

    // Top violations by rule
    const violationCounts: Record<string, number> = {};
    for (const result of scanResults) {
      for (const violation of result.violations) {
        violationCounts[violation.rule] = (violationCounts[violation.rule] || 0) + 1;
      }
    }

    const topViolations = Object.entries(violationCounts)
      .map(([rule, count]) => ({ rule, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Top vulnerabilities by component
    const vulnCounts: Record<string, number> = {};
    for (const result of scanResults) {
      for (const vuln of result.vulnerabilities) {
        vulnCounts[vuln.component] = (vulnCounts[vuln.component] || 0) + 1;
      }
    }

    const topVulnerabilities = Object.entries(vulnCounts)
      .map(([component, count]) => ({ component, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const report: IaCReport = {
      totalFilesScanned,
      totalViolations,
      totalVulnerabilities,
      criticalCount,
      highCount,
      scanResults,
      summary: {
        passRate,
        topViolations,
        topVulnerabilities
      },
      generatedAt: new Date().toISOString()
    };

    logger.info('[CloudSecurity] IaC report generated', undefined, undefined, {
      totalFilesScanned,
      totalViolations,
      totalVulnerabilities,
      criticalCount,
      passRate: `${passRate}%`
    });

    return report;
  }

  // ========================================================================
  // CONTAINER RUNTIME SECURITY
  // ========================================================================

  /**
   * Detect runtime anomalies in a running container.
   */
  public detectRuntimeAnomalies(containerId: string): Promise<RuntimeAnomalyResult> {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.containerRuntime.enabled) {
      throw new CloudSecurityError('Container runtime security is not enabled', 'RUNTIME_DISABLED', 403);
    }

    return this.runtimeCircuitBreaker.execute(async () => {
      const anomalies: ContainerAnomaly[] = [];

      // Check 1: Unexpected processes
      const unexpectedProcesses = this.checkUnexpectedProcesses(containerId);
      for (const proc of unexpectedProcesses) {
        anomalies.push({
          type: 'process',
          severity: proc.severity,
          description: `Unexpected process running: ${proc.name}`,
          evidence: `PID ${proc.pid}: ${proc.cmd}`,
          timestamp: new Date().toISOString()
        });
      }

      // Check 2: Suspicious network connections
      const suspiciousConnections = this.checkSuspiciousNetworkConnections(containerId);
      for (const conn of suspiciousConnections) {
        anomalies.push({
          type: 'network',
          severity: conn.severity,
          description: `Suspicious network connection: ${conn.remote}`,
          evidence: `Port ${conn.port} → ${conn.remote}`,
          timestamp: new Date().toISOString()
        });
      }

      // Check 3: File system modifications
      const fileModifications = this.checkFileModifications(containerId);
      for (const mod of fileModifications) {
        anomalies.push({
          type: 'file',
          severity: mod.severity,
          description: `Unexpected file modification: ${mod.path}`,
          evidence: `Modified: ${mod.timestamp}`,
          timestamp: mod.timestamp
        });
      }

      // Check 4: Privilege escalation attempts
      const privEsc = this.checkPrivilegeEscalation(containerId);
      for (const attempt of privEsc) {
        anomalies.push({
          type: 'capability',
          severity: 'critical',
          description: `Privilege escalation attempt: ${attempt.method}`,
          evidence: attempt.evidence,
          timestamp: new Date().toISOString()
        });
      }

      const riskScore = this.calculateAnomalyRiskScore(anomalies);

      const result: RuntimeAnomalyResult = {
        containerId,
        anomaliesDetected: anomalies.length > 0,
        anomalies,
        riskScore,
        assessedAt: new Date().toISOString()
      };

      this.runtimeAnomalyResults.set(containerId, result);

      if (anomalies.length > 0) {
        logger.warn('[CloudSecurity] Runtime anomalies detected', undefined, undefined, {
          containerId,
          anomalyCount: anomalies.length,
          riskScore,
          highestSeverity: anomalies.reduce((max, a) => {
            const levels = { low: 1, medium: 2, high: 3, critical: 4 };
            return levels[a.severity] > levels[max] ? a.severity : max;
          }, 'low' as 'low' | 'medium' | 'high' | 'critical')
        });

        this.emit('runtime-anomaly-detected', { containerId, anomalies, riskScore });
      }

      return result;
    });
  }

  /**
   * Enforce a Seccomp profile on a container.
   */
  public enforceSeccompProfile(profile: SeccompProfile): { success: boolean; profileId: string } {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.containerRuntime.enabled) {
      throw new CloudSecurityError('Container runtime security is not enabled', 'RUNTIME_DISABLED', 403);
    }
    if (!this.config.containerRuntime.seccompEnabled) {
      throw new CloudSecurityError('Seccomp is not enabled', 'SECCOMP_DISABLED', 403);
    }

    const profileId = `seccomp-${crypto.randomUUID().substring(0, 8)}`;
    this.seccompProfiles.set(profileId, profile);

    const allowedCount = profile.syscalls.filter(s => s.action === 'SCMP_ACT_ALLOW')
      .reduce((sum, s) => sum + s.names.length, 0);
    const blockedCount = profile.syscalls.filter(s => s.action === 'SCMP_ACT_ERRNO' || s.action === 'SCMP_ACT_KILL')
      .reduce((sum, s) => sum + s.names.length, 0);

    logger.info('[CloudSecurity] Seccomp profile enforced', undefined, undefined, {
      profileId,
      defaultAction: profile.defaultAction,
      allowedSyscalls: allowedCount,
      blockedSyscalls: blockedCount
    });

    this.emit('seccomp-enforced', { profileId, allowedCount, blockedCount });

    return { success: true, profileId };
  }

  /**
   * Monitor syscalls for a container.
   */
  public monitorSyscalls(containerId: string): SyscallMonitorResult {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    // Simulate syscall monitoring — in production, use Falco, eBPF, strace
    const suspiciousSyscallList = ['ptrace', 'process_vm_readv', 'process_vm_writev', 'kexec_load', 'init_module', 'finit_module'];
    const allSyscalls = ['read', 'write', 'open', 'close', 'stat', 'fstat', 'mmap', 'mprotect', 'munmap', 'brk', 'clone', 'execve', 'exit', 'wait4', 'kill', 'getpid', 'socket', 'connect', 'accept', 'sendto', 'recvfrom'];

    // Simulate active syscalls
    const activeSyscalls = allSyscalls.slice(0, 12 + Math.floor(Math.random() * 5));
    const suspicious = activeSyscalls.filter(s => suspiciousSyscallList.includes(s));

    const topSyscalls = activeSyscalls
      .map(name => ({ name, count: Math.floor(Math.random() * 10000) + 100 }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const blocked = this.getBlockedSyscallsForContainer(containerId);

    const result: SyscallMonitorResult = {
      containerId,
      totalSyscalls: activeSyscalls.reduce((sum, _, i) => sum + topSyscalls[i]?.count || 0, 0),
      uniqueSyscalls: activeSyscalls.length,
      suspiciousSyscalls: suspicious,
      blockedSyscalls: blocked,
      topSyscalls,
      monitoredAt: new Date().toISOString()
    };

    this.syscallMonitorResults.set(containerId, result);

    if (suspicious.length > 0) {
      logger.warn('[CloudSecurity] Suspicious syscalls detected', undefined, undefined, {
        containerId,
        suspicious
      });
    }

    return result;
  }

  /**
   * Detect cryptocurrency mining activity in containers.
   */
  public detectCryptoMining(): Promise<CryptoMiningDetectionResult> {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.containerRuntime.miningDetectionEnabled) {
      throw new CloudSecurityError('Crypto mining detection is not enabled', 'MINING_DETECTION_DISABLED', 403);
    }

    return this.runtimeCircuitBreaker.execute(async () => {
      const indicators: CryptoMiningIndicator[] = [];
      const affectedContainers: string[] = [];
      let confidence = 0;

      // Check 1: Known mining processes
      const miningProcesses = ['xmrig', 'minerd', 'cpuminer', 'ethminer', 'cgminer', 'bfgminer', 'nicehash', 'coinhive'];
      for (const [containerId] of this.runtimeAnomalyResults.entries()) {
        const result = this.runtimeAnomalyResults.get(containerId);
        if (!result) continue;

        for (const anomaly of result.anomalies) {
          if (anomaly.type === 'process' && miningProcesses.some(mp => anomaly.description.toLowerCase().includes(mp))) {
            indicators.push({
              type: 'process',
              evidence: anomaly.evidence,
              severity: 'critical',
              containerId
            });
            if (!affectedContainers.includes(containerId)) affectedContainers.push(containerId);
          }
        }
      }

      // Check 2: Known mining pool connections (DNS and network)
      const miningPools = ['pool.minexmr.com', 'stratum+tcp://', 'mine.moneropool.com', 'us-east.ethermine.org'];
      // Simulate check
      const poolConnections = false;
      if (poolConnections) {
        indicators.push({
          type: 'network',
          evidence: `Connection to mining pool: ${miningPools[0]}`,
          severity: 'critical',
          containerId: 'container-simulated'
        });
        confidence += 40;
      }

      // Check 3: High CPU usage patterns
      const highCpuContainers: string[] = [];
      // Simulate check
      if (highCpuContainers.length > 0) {
        for (const cid of highCpuContainers) {
          indicators.push({
            type: 'cpu',
            evidence: `Sustained 95%+ CPU usage for 30+ minutes`,
            severity: 'high',
            containerId: cid
          });
          confidence += 20;
        }
      }

      // Check 4: Known mining config files
      const miningConfigFiles = ['config.json', 'xmrig.conf', 'miner.cfg'];
      // Simulate file check
      const miningFilesFound = false;
      if (miningFilesFound) {
        indicators.push({
          type: 'file',
          evidence: `Mining configuration file found: ${miningConfigFiles[0]}`,
          severity: 'high',
          containerId: 'container-simulated'
        });
        confidence += 25;
      }

      // Check 5: DNS queries to mining domains
      const miningDnsQueries = ['cryptonight.net', 'hashvault.pro', 'nanopool.org'];
      // Simulate
      const miningDnsDetected = false;
      if (miningDnsDetected) {
        indicators.push({
          type: 'dns',
          evidence: `DNS query to mining domain: ${miningDnsQueries[0]}`,
          severity: 'medium',
          containerId: 'container-simulated'
        });
        confidence += 15;
      }

      const miningDetected = indicators.length > 0;
      if (miningDetected) confidence = Math.min(confidence + 30, 100);

      const result: CryptoMiningDetectionResult = {
        miningDetected,
        indicators,
        confidence,
        affectedContainers,
        detectedAt: new Date().toISOString()
      };

      if (miningDetected) {
        logger.error('[CloudSecurity] Cryptocurrency mining detected', undefined, undefined, {
          confidence,
          affectedContainers,
          indicatorCount: indicators.length
        });

        this.emit('crypto-mining-detected', result);
      }

      return result;
    });
  }

  // ========================================================================
  // CLOUD WORKLOAD PROTECTION
  // ========================================================================

  /**
   * Evaluate workload identity security.
   */
  public evaluateWorkloadIdentity(workload: Partial<WorkloadIdentity>): WorkloadIdentityEvaluation {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.workloadProtection.enabled) {
      throw new CloudSecurityError('Workload protection is not enabled', 'WORKLOAD_DISABLED', 403);
    }

    const workloadName = workload.workloadName || 'unknown';
    const namespace = workload.namespace || 'default';
    const permissions = workload.permissions || [];

    // Check for identity existence
    const identityFound = workload.roleArn !== undefined || workload.serviceAccountEmail !== undefined || workload.managedIdentityId !== undefined;

    // Analyze permissions for overprivilege
    const dangerousPermissions = ['*', 'iam:*', 's3:*', 'ec2:*', 'sts:AssumeRole', 'organizations:*'];
    const unusedPermissions: string[] = [];
    let overprivileged = false;

    for (const perm of permissions) {
      if (dangerousPermissions.includes(perm)) {
        overprivileged = true;
        unusedPermissions.push(perm);
      }
      // Simulate unused permission detection
      if (perm.includes('ReadOnly') && Math.random() < 0.3) {
        unusedPermissions.push(perm);
      }
    }

    // Determine risk level
    let riskLevel: WorkloadIdentityEvaluation['riskLevel'] = 'low';
    const recommendations: string[] = [];

    if (permissions.includes('*')) {
      riskLevel = 'critical';
      recommendations.push('CRITICAL: Wildcard (*) permissions detected — replace with specific permissions');
    }

    if (overprivileged) {
      if (riskLevel !== 'critical') riskLevel = 'high';
      recommendations.push(`Remove or scope down ${unusedPermissions.length} overprivileged permissions`);
    }

    if (!identityFound) {
      riskLevel = 'medium';
      recommendations.push('Configure workload identity (IAM Role for Service Accounts / Workload Identity Federation)');
    }

    if (permissions.length === 0 && identityFound) {
      riskLevel = 'low';
      recommendations.push('Workload has identity but no permissions attached — verify this is intentional');
    }

    if (unusedPermissions.length > permissions.length * 0.5) {
      recommendations.push('More than 50% of permissions appear unused — review and remove');
    }

    // Add general recommendations
    if (recommendations.length === 0) {
      recommendations.push('Workload identity appears properly configured');
    }

    const evaluation: WorkloadIdentityEvaluation = {
      workload: workloadName,
      identityFound,
      permissionsCount: permissions.length,
      overprivileged,
      unusedPermissions,
      riskLevel,
      recommendations
    };

    logger.info('[CloudSecurity] Workload identity evaluated', undefined, undefined, {
      workload: workloadName,
      identityFound,
      riskLevel,
      overprivileged,
      unusedPermissionCount: unusedPermissions.length
    });

    this.emit('workload-identity-evaluated', evaluation);

    return evaluation;
  }

  /**
   * Enforce least privilege for a workload.
   */
  public enforceLeastPrivilege(workload: string, permissions: string[]): LeastPrivilegeEnforcement {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    // Analyze permissions and recommend minimal set
    const recommendedPermissions = this.recommendMinimalPermissions(permissions);
    const removedPermissions = permissions.filter(p => !recommendedPermissions.includes(p));

    const enforced = this.config.workloadProtection.leastPrivilegeEnforcement;

    const result: LeastPrivilegeEnforcement = {
      workload,
      originalPermissions: permissions,
      recommendedPermissions: recommendedPermissions,
      removedPermissions: removedPermissions,
      enforced,
      timestamp: new Date().toISOString()
    };

    logger.info('[CloudSecurity] Least privilege enforced', undefined, undefined, {
      workload,
      originalCount: permissions.length,
      recommendedCount: recommendedPermissions.length,
      removedCount: removedPermissions.length,
      enforced
    });

    this.emit('least-privilege-enforced', result);

    return result;
  }

  /**
   * Audit cloud permissions across a provider.
   */
  public auditCloudPermissions(cloudProvider: CloudProvider): CloudPermissionAudit {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.workloadProtection.enabled) {
      throw new CloudSecurityError('Workload protection is not enabled', 'WORKLOAD_DISABLED', 403);
    }

    const criticalFindings: CloudPermissionFinding[] = [];
    let totalIdentities = 0;
    let overprivilegedIdentities = 0;
    let unusedRoles = 0;

    // Simulate audit — in production, use AWS IAM Access Analyzer, Azure AD Privileged Identity Management
    const simulatedFindings = this.getSimulatedCloudPermissionFindings(cloudProvider);

    for (const finding of simulatedFindings) {
      criticalFindings.push(finding);
      if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
        overprivilegedIdentities++;
      }
      if (finding.description.includes('unused')) {
        unusedRoles++;
      }
    }

    totalIdentities = 15 + Math.floor(Math.random() * 20); // Simulated

    const result: CloudPermissionAudit = {
      cloudProvider,
      totalIdentities,
      overprivilegedIdentities,
      unusedRoles,
      criticalFindings,
      auditedAt: new Date().toISOString()
    };

    logger.info('[CloudSecurity] Cloud permission audit completed', undefined, undefined, {
      provider: cloudProvider,
      totalIdentities,
      overprivileged: overprivilegedIdentities,
      unusedRoles,
      criticalFindings: criticalFindings.length
    });

    this.emit('cloud-permission-audit', result);

    return result;
  }

  /**
   * Detect lateral movement in cloud environment.
   */
  public detectLateralMovement(cloudProvider: CloudProvider, logs: Array<{ event: string; source: string; target: string; timestamp: string }>): LateralMovementDetectionResult {
    if (!this.isInitialized) {
      throw new CloudSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.workloadProtection.lateralMovementDetection) {
      throw new CloudSecurityError('Lateral movement detection is not enabled', 'LMD_DISABLED', 403);
    }

    const indicators: LateralMovementIndicator[] = [];
    const timeline: string[] = [];
    const affectedResources = new Set<string>();

    // Check 1: Credential access patterns
    const credentialEvents = logs.filter(l =>
      l.event.includes('AssumeRole') || l.event.includes('GetSessionToken') ||
      l.event.includes('CreateAccessKey') || l.event.includes('sts:')
    );

    for (const event of credentialEvents) {
      indicators.push({
        type: 'credential_access',
        evidence: `Event: ${event.event} from ${event.source}`,
        sourceResource: event.source,
        targetResource: event.target,
        timestamp: event.timestamp,
        mitreTechnique: 'T1078 — Valid Accounts'
      });
      affectedResources.add(event.source);
      affectedResources.add(event.target);
    }

    // Check 2: Lateral movement via API calls
    const lateralEvents = logs.filter(l =>
      l.event.includes('RunInstances') || l.event.includes('CreateFunction') ||
      l.event.includes('UpdateLoginProfile') || l.event.includes('ModifyInstanceAttribute')
    );

    for (const event of lateralEvents) {
      indicators.push({
        type: 'lateral_movement',
        evidence: `Event: ${event.event} from ${event.source} to ${event.target}`,
        sourceResource: event.source,
        targetResource: event.target,
        timestamp: event.timestamp,
        mitreTechnique: 'T1021 — Remote Services'
      });
      affectedResources.add(event.target);
    }

    // Check 3: Discovery activities
    const discoveryEvents = logs.filter(l =>
      l.event.includes('DescribeInstances') || l.event.includes('ListBuckets') ||
      l.event.includes('GetCallerIdentity') || l.event.includes('DescribeSecurityGroups')
    );

    for (const event of discoveryEvents) {
      indicators.push({
        type: 'discovery',
        evidence: `Discovery event: ${event.event} from ${event.source}`,
        sourceResource: event.source,
        targetResource: event.target,
        timestamp: event.timestamp,
        mitreTechnique: 'T1087 — Account Discovery'
      });
    }

    // Check 4: Privilege escalation
    const privEscEvents = logs.filter(l =>
      l.event.includes('AttachRolePolicy') || l.event.includes('PutUserPolicy') ||
      l.event.includes('CreatePolicyVersion') || l.event.includes('UpdateAssumeRolePolicy')
    );

    for (const event of privEscEvents) {
      indicators.push({
        type: 'privilege_escalation',
        evidence: `Privilege escalation: ${event.event} by ${event.source}`,
        sourceResource: event.source,
        targetResource: event.target,
        timestamp: event.timestamp,
        mitreTechnique: 'T1078.004 — Cloud Accounts'
      });
    }

    const detected = indicators.length >= 3; // Minimum threshold for lateral movement detection
    const severity: LateralMovementDetectionResult['severity'] =
      indicators.length >= 10 ? 'critical' :
      indicators.length >= 5 ? 'high' : 'medium';

    timeline.push(...indicators.map(i => `${i.timestamp}: ${i.type} — ${i.mitreTechnique}`));

    const result: LateralMovementDetectionResult = {
      detected,
      indicators,
      severity,
      timeline: timeline.slice(0, 20),
      affectedResources: Array.from(affectedResources),
      detectedAt: new Date().toISOString()
    };

    this.lateralMovementResults.set(`${cloudProvider}-${Date.now()}`, result);

    if (detected) {
      logger.error('[CloudSecurity] Lateral movement detected', undefined, undefined, {
        provider: cloudProvider,
        indicatorCount: indicators.length,
        severity,
        affectedResources: affectedResources.size
      });

      this.emit('lateral-movement-detected', result);
    }

    return result;
  }

  // ========================================================================
  // SIMULATED DATA GENERATORS (replace with real cloud/K8s API calls)
  // ========================================================================

  private simulateImageScan(imageRef: string): ContainerVulnerability[] {
    const vulnerabilities: ContainerVulnerability[] = [];

    // Simulate common CVEs found in container images
    const simulatedCVEs = [
      { id: 'CVE-2024-21626', package: 'runc', installedVersion: '1.1.10', fixedVersion: '1.1.11', severity: 'CRITICAL' as const, cvssScore: 8.6 },
      { id: 'CVE-2023-44487', package: 'golang.org/x/net/http2', installedVersion: '0.14.0', fixedVersion: '0.17.0', severity: 'HIGH' as const, cvssScore: 7.5 },
      { id: 'CVE-2024-2961', package: 'glibc', installedVersion: '2.31', fixedVersion: '2.31-14', severity: 'HIGH' as const, cvssScore: 7.0 },
      { id: 'CVE-2023-42364', package: 'bash', installedVersion: '5.0', fixedVersion: '5.0-8', severity: 'MEDIUM' as const, cvssScore: 5.5 },
      { id: 'CVE-2024-0567', package: 'openssl', installedVersion: '1.1.1k', fixedVersion: '1.1.1w', severity: 'CRITICAL' as const, cvssScore: 9.1 },
      { id: 'CVE-2023-39325', package: 'curl', installedVersion: '7.68.0', fixedVersion: '8.4.0', severity: 'MEDIUM' as const, cvssScore: 5.9 },
      { id: 'CVE-2024-21762', package: 'linux-kernel', installedVersion: '5.4.0', fixedVersion: '5.4.267', severity: 'CRITICAL' as const, cvssScore: 9.8 },
      { id: 'CVE-2023-32681', package: 'systemd', installedVersion: '245', fixedVersion: '245.4-4', severity: 'LOW' as const, cvssScore: 3.3 }
    ];

    // Random subset based on image
    const seed = imageRef.split('').reduce((sum, c) => sum + c.charCodeAt(0), 0);
    for (let i = 0; i < simulatedCVEs.length; i++) {
      if ((seed + i) % 3 !== 0) {
        const cve = simulatedCVEs[i];
        vulnerabilities.push({
          ...cve,
          description: `Vulnerability in ${cve.package} ${cve.installedVersion}`,
          cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          nvdUrl: `https://nvd.nist.gov/vuln/detail/${cve.id}`
        });
      }
    }

    return vulnerabilities;
  }

  private simulateIaCScan(filePath: string, format: IaCFormat): { violations: IaCViolation[]; vulnerabilities: IaCVulnerability[] } {
    const violations: IaCViolation[] = [];
    const vulnerabilities: IaCVulnerability[] = [];

    if (format === 'terraform') {
      violations.push(
        { id: 'CKV_AWS_20', rule: 'CKV_AWS_20', severity: 'critical', resource: 'aws_s3_bucket.public', attribute: 'acl', message: 'S3 bucket has public read ACL', recommendation: 'Set ACL to private', cisBenchmark: 'CIS 1.4.0 §2.1.1' },
        { id: 'CKV_AWS_21', rule: 'CKV_AWS_21', severity: 'critical', resource: 'aws_s3_bucket.public', attribute: 'versioning', message: 'S3 bucket versioning is not enabled', recommendation: 'Enable versioning', cisBenchmark: 'CIS 1.4.0 §2.1.3' },
        { id: 'CKV_AWS_53', rule: 'CKV_AWS_53', severity: 'high', resource: 'aws_s3_bucket.public', attribute: 'server_side_encryption_configuration', message: 'S3 bucket encryption not configured', recommendation: 'Enable AES-256 or KMS encryption' },
        { id: 'CKV_AWS_144', rule: 'CKV_AWS_144', severity: 'high', resource: 'aws_db_instance.main', attribute: 'storage_encrypted', message: 'RDS instance storage not encrypted', recommendation: 'Enable storage_encrypted = true' },
        { id: 'CKV_AWS_24', rule: 'CKV_AWS_24', severity: 'medium', resource: 'aws_security_group.allow_all', attribute: 'ingress', message: 'Security group allows 0.0.0.0/0 on all ports', recommendation: 'Restrict ingress to specific CIDR blocks' },
        { id: 'CKV_AWS_150', rule: 'CKV_AWS_150', severity: 'medium', resource: 'aws_lambda_function.fn', attribute: 'tracing_config', message: 'Lambda X-Ray tracing not enabled', recommendation: 'Enable X-Ray tracing for observability' },
        { id: 'CKV_AWS_117', rule: 'CKV_AWS_117', severity: 'low', resource: 'aws_ecs_service.svc', attribute: 'deployment_maximum_percent', message: 'ECS deployment maximum percent not set to 200', recommendation: 'Set deployment_maximum_percent to 200 for zero-downtime' }
      );
    }

    if (format === 'kubernetes') {
      violations.push(
        { id: 'KSV001', rule: 'KSV001', severity: 'critical', resource: 'Deployment/app', attribute: 'securityContext.privileged', message: 'Container running in privileged mode', recommendation: 'Set securityContext.privileged to false' },
        { id: 'KSV002', rule: 'KSV002', severity: 'high', resource: 'Deployment/app', attribute: 'securityContext.runAsUser', message: 'Container running as root (UID 0)', recommendation: 'Set runAsUser to non-zero value' },
        { id: 'KSV003', rule: 'KSV003', severity: 'high', resource: 'Deployment/app', attribute: 'resources.limits', message: 'Resource limits not set', recommendation: 'Set CPU and memory limits' },
        { id: 'KSV004', rule: 'KSV004', severity: 'medium', resource: 'Service/web', attribute: 'type', message: 'Service type is LoadBalancer (exposed externally)', recommendation: 'Use ClusterIP unless external access is required' }
      );
    }

    if (format === 'cloudformation') {
      violations.push(
        { id: 'CKV_AWS_79', rule: 'CKV_AWS_79', severity: 'critical', resource: 'AWS::IAM::Role', attribute: 'AssumeRolePolicyDocument', message: 'IAM role allows assume role from any principal', recommendation: 'Restrict Principal to specific AWS accounts or services' },
        { id: 'CKV_AWS_78', rule: 'CKV_AWS_78', severity: 'high', resource: 'AWS::Lambda::Function', attribute: 'Environment.Variables', message: 'Lambda function has secrets in environment variables', recommendation: 'Use AWS Secrets Manager or SSM Parameter Store' }
      );
    }

    return { violations, vulnerabilities };
  }

  private getSimulatedRBACBindings(): Array<{ clusterRole: string; subjects: Array<{ kind: string; name: string; namespace?: string }> }> {
    return [
      { clusterRole: 'cluster-admin', subjects: [{ kind: 'User', name: 'admin@corp.com' }, { kind: 'User', name: 'dev-lead@corp.com' }, { kind: 'User', name: 'intern@corp.com' }, { kind: 'Group', name: 'developers' }] },
      { clusterRole: 'view', subjects: [{ kind: 'ServiceAccount', name: 'monitoring-sa', namespace: 'monitoring' }] },
      { clusterRole: 'edit', subjects: [{ kind: 'ServiceAccount', name: 'deploy-sa', namespace: 'default' }, { kind: 'ServiceAccount', name: 'ci-cd-sa', namespace: 'ci-cd' }] },
      { clusterRole: 'system:authenticated', subjects: [{ kind: 'Group', name: '*' }] },
      { clusterRole: 'pod-security-policy:privileged', subjects: [{ kind: 'ServiceAccount', name: 'privileged-sa', namespace: 'kube-system' }] }
    ];
  }

  private getSimulatedPrivilegedContainers(): PrivilegedContainerInfo[] {
    return [
      { namespace: 'kube-system', podName: 'kube-proxy-abc12', containerName: 'kube-proxy', image: 'k8s.gcr.io/kube-proxy:v1.28.0', privileged: true, hostNetwork: true, hostPID: false, capabilities: ['NET_ADMIN', 'NET_RAW'], runAsRoot: true, riskScore: 75 },
      { namespace: 'monitoring', podName: 'node-exporter-xyz', containerName: 'node-exporter', image: 'prom/node-exporter:v1.6.1', privileged: false, hostNetwork: true, hostPID: true, capabilities: ['SYS_ADMIN'], runAsRoot: true, riskScore: 85 },
      { namespace: 'debug', podName: 'debug-pod-001', containerName: 'debug', image: 'ubuntu:latest', privileged: true, hostNetwork: true, hostPID: true, capabilities: ['ALL'], runAsRoot: true, riskScore: 95 }
    ];
  }

  private getSimulatedMisconfigurations(provider: CloudProvider): Omit<CloudMisconfiguration, 'cloudProvider' | 'detectedAt'>[] {
    const allMisconfigs: Omit<CloudMisconfiguration, 'cloudProvider' | 'detectedAt'>[] = [
      { id: 's3-public-bucket', resourceType: 'AWS::S3::Bucket', resourceId: 'arn:aws:s3:::company-public-data', region: 'us-east-1', severity: 'CRITICAL', description: 'S3 bucket is publicly accessible', expected: 'Block public access enabled', actual: 'Public read ACL configured', remediation: 'Enable S3 Block Public Access and remove public ACL', cisBenchmarkId: 'CIS 2.1.1', nistControlId: 'AC-3' },
      { id: 'sg-open-ingress', resourceType: 'AWS::EC2::SecurityGroup', resourceId: 'sg-0abc123def', region: 'us-east-1', severity: 'HIGH', description: 'Security group allows 0.0.0.0/0 on port 22 (SSH)', expected: 'Restrict SSH to specific CIDR', actual: 'Ingress rule: 0.0.0.0/0:22', remediation: 'Limit SSH to bastion host IP range', cisBenchmarkId: 'CIS 5.2.4' },
      { id: 'rds-public', resourceType: 'AWS::RDS::DBInstance', resourceId: 'my-production-db', region: 'us-east-1', severity: 'CRITICAL', description: 'RDS instance is publicly accessible', expected: 'PubliclyAccessible = false', actual: 'PubliclyAccessible = true', remediation: 'Set PubliclyAccessible to false and use VPC endpoints', cisBenchmarkId: 'CIS 6.1.1' },
      { id: 'iam-wildcard-policy', resourceType: 'AWS::IAM::Policy', resourceId: 'arn:aws:iam::123456789:policy/DevPolicy', region: 'global', severity: 'HIGH', description: 'IAM policy uses wildcard (*) for actions on sensitive services', expected: 'Specific actions and resources', actual: 'Action: *, Resource: *', remediation: 'Apply least privilege principle with specific actions', cisBenchmarkId: 'CIS 1.4.1' },
      { id: 'encryption-disabled', resourceType: 'AWS::EBS::Volume', resourceId: 'vol-0def456abc', region: 'us-west-2', severity: 'MEDIUM', description: 'EBS volume encryption is disabled', expected: 'Encrypted = true', actual: 'Encrypted = false', remediation: 'Enable encryption and migrate data', cisBenchmarkId: 'CIS 2.3.1' },
      { id: 'logging-disabled', resourceType: 'AWS::CloudTrail::Trail', resourceId: 'management-trail', region: 'us-east-1', severity: 'MEDIUM', description: 'CloudTrail logging is not enabled for all regions', expected: 'Multi-region trail enabled', actual: 'Single region trail', remediation: 'Enable multi-region CloudTrail with log file validation', cisBenchmarkId: 'CIS 3.1' },
      { id: 'mfa-disabled', resourceType: 'AWS::IAM::User', resourceId: 'arn:aws:iam::123456789:user/dev-user', region: 'global', severity: 'HIGH', description: 'IAM user does not have MFA enabled', expected: 'MFA enabled for all users', actual: 'MFA not configured', remediation: 'Enable MFA for all IAM users', cisBenchmarkId: 'CIS 1.4' },
      { id: 'no-backup', resourceType: 'AWS::DynamoDB::Table', resourceId: 'user-sessions', region: 'us-east-1', severity: 'MEDIUM', description: 'DynamoDB table has no backup or point-in-time recovery', expected: 'PITR enabled', actual: 'No backup configured', remediation: 'Enable point-in-time recovery', cisBenchmarkId: 'CIS 2.3.2' },
      { id: 'default-network-acl', resourceType: 'AWS::EC2::NetworkAcl', resourceId: 'acl-default', region: 'us-east-1', severity: 'LOW', description: 'Default NACL allows all inbound and outbound traffic', expected: 'Custom restrictive NACL', actual: 'Allow all inbound/outbound', remediation: 'Create custom NACL with least-privilege rules', cisBenchmarkId: 'CIS 5.3.1' },
      { id: 'root-account-active', resourceType: 'AWS::IAM::Root', resourceId: 'root', region: 'global', severity: 'CRITICAL', description: 'Root account has active access keys', expected: 'No access keys for root', actual: 'Access key active since 2023-01-15', remediation: 'Delete root access keys and use IAM roles', cisBenchmarkId: 'CIS 1.1' }
    ];

    // Filter/provider-specific misconfigs
    switch (provider) {
      case 'aws':
        return allMisconfigs;
      case 'azure':
        return allMisconfigs.slice(0, 6).map(mc => ({
          ...mc,
          resourceType: mc.resourceType.replace('AWS', 'Azure').replace('S3', 'BlobStorage').replace('EC2', 'Network').replace('RDS', 'SQL').replace('IAM', 'AAD').replace('EBS', 'Disk').replace('DynamoDB', 'CosmosDB'),
          resourceId: mc.resourceId.replace('arn:aws', '/subscriptions/00000000-0000-0000-0000-000000000000')
        }));
      case 'gcp':
        return allMisconfigs.slice(0, 5).map(mc => ({
          ...mc,
          resourceType: mc.resourceType.replace('AWS', 'GCP').replace('S3', 'Storage').replace('EC2', 'VPC').replace('RDS', 'CloudSQL').replace('IAM', 'IAM'),
          resourceId: `projects/my-project/${mc.resourceType.split('::').pop()?.toLowerCase()}/${mc.resourceId}`
        }));
      case 'oci':
        return allMisconfigs.slice(0, 4);
      default:
        return allMisconfigs;
    }
  }

  private getSimulatedCloudPermissionFindings(provider: CloudProvider): CloudPermissionFinding[] {
    return [
      { id: 'CP-001', resourceId: 'arn:aws:iam::123456789:user/unused-user', resourceType: 'IAM User', severity: 'MEDIUM', description: 'IAM user has not logged in for 90+ days — unused credentials', recommendation: 'Disable or delete unused IAM user' },
      { id: 'CP-002', resourceId: 'arn:aws:iam::123456789:role/AdminRole', resourceType: 'IAM Role', severity: 'CRITICAL', description: 'IAM role with admin permissions is assumed by 12 different entities', recommendation: 'Restrict role trust policy to specific entities' },
      { id: 'CP-003', resourceId: 'arn:aws:iam::123456789:policy/WildcardPolicy', resourceType: 'IAM Policy', severity: 'HIGH', description: 'Policy grants s3:* on all resources', recommendation: 'Scope down to specific buckets and actions' },
      { id: 'CP-004', resourceId: 'arn:aws:iam::123456789:user/service-account', resourceType: 'IAM User', severity: 'MEDIUM', description: 'Service account has inline policy instead of managed policy', recommendation: 'Convert inline policy to customer-managed policy' },
      { id: 'CP-005', resourceId: 'arn:aws:iam::123456789:role/LambdaRole', resourceType: 'IAM Role', severity: 'LOW', description: 'Lambda execution role has unused ec2:* permissions', recommendation: 'Remove unused ec2:* permissions' },
      { id: 'CP-006', resourceId: 'arn:aws:iam::123456789:group/Developers', resourceType: 'IAM Group', severity: 'HIGH', description: 'Group has iam:CreateUser and iam:AttachUserPolicy — potential privilege escalation', recommendation: 'Remove IAM management permissions from developer group' },
      { id: 'CP-007', resourceId: 'arn:aws:iam::123456789:policy/CrossAccountAccess', resourceType: 'Cross-Account Policy', severity: 'CRITICAL', description: 'Cross-account access grants sts:AssumeRole to external account without external ID', recommendation: 'Add external ID condition and restrict source account' }
    ];
  }

  private getBlockedSyscallsForContainer(containerId: string): string[] {
    const profile = this.seccompProfiles.get(containerId);
    if (!profile) return ['kexec_load', 'init_module', 'finit_module', 'ptrace'];
    return profile.syscalls
      .filter(s => s.action === 'SCMP_ACT_ERRNO' || s.action === 'SCMP_ACT_KILL')
      .flatMap(s => s.names);
  }

  // Internal simulated anomaly detection helpers
  private checkUnexpectedProcesses(containerId: string): Array<{ name: string; pid: number; cmd: string; severity: 'critical' | 'high' | 'medium' | 'low' }> {
    return []; // Simulated — would use /proc or containerd API
  }

  private checkSuspiciousNetworkConnections(containerId: string): Array<{ remote: string; port: number; severity: 'critical' | 'high' | 'medium' | 'low' }> {
    return []; // Simulated — would use netstat/ss within container
  }

  private checkFileModifications(containerId: string): Array<{ path: string; timestamp: string; severity: 'critical' | 'high' | 'medium' | 'low' }> {
    return []; // Simulated — would use inotify or filesystem monitoring
  }

  private checkPrivilegeEscalation(containerId: string): Array<{ method: string; evidence: string }> {
    return []; // Simulated — would check for su, sudo, setuid binaries
  }

  private calculateAnomalyRiskScore(anomalies: ContainerAnomaly[]): number {
    const severityWeights = { critical: 25, high: 15, medium: 8, low: 3 };
    let score = 0;
    for (const a of anomalies) {
      score += severityWeights[a.severity];
    }
    return Math.min(Math.round(score), 100);
  }

  private calculatePostureScore(misconfigurations: CloudMisconfiguration[], frameworks: ComplianceFrameworkResult[]): number {
    if (misconfigurations.length === 0 && frameworks.length === 0) return 100;

    const severityPenalties = { CRITICAL: 15, HIGH: 10, MEDIUM: 5, LOW: 2 };
    let penalty = 0;
    for (const mc of misconfigurations) {
      penalty += severityPenalties[mc.severity] || 0;
    }

    const avgFrameworkCompliance = frameworks.length > 0
      ? frameworks.reduce((sum, f) => sum + f.compliancePercentage, 0) / frameworks.length
      : 100;

    const score = Math.max(0, Math.min(100, avgFrameworkCompliance - penalty));
    return Math.round(score);
  }

  private scoreToGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
  }

  private recommendMinimalPermissions(permissions: string[]): string[] {
    // Simple least-privilege recommendation algorithm
    const dangerousPerms = ['*', 'iam:*', 's3:*', 'ec2:*', 'sts:AssumeRole', 'organizations:*'];
    const safePerms = permissions.filter(p => !dangerousPerms.includes(p));

    // If wildcard was used, recommend read-only alternatives
    if (permissions.includes('*')) {
      return ['s3:GetObject', 's3:ListBucket', 'logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'];
    }

    return safePerms.length > 0 ? safePerms : ['logs:PutLogEvents'];
  }

  // ========================================================================
  // DEFAULT INITIALIZATION HELPERS
  // ========================================================================

  private initializeDefaultSeccompProfile(): void {
    const defaultProfile: SeccompProfile = {
      defaultAction: 'SCMP_ACT_ERRNO',
      architectures: ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_AARCH64'],
      syscalls: [
        { action: 'SCMP_ACT_ALLOW', names: ['read', 'write', 'open', 'close', 'stat', 'fstat', 'lstat', 'poll', 'lseek', 'mmap', 'mprotect', 'munmap', 'brk', 'ioctl', 'access', 'pipe', 'select', 'sched_yield', 'mremap', 'msync', 'mincore', 'madvise', 'dup', 'dup2', 'nanosleep', 'getpid', 'socket', 'connect', 'accept', 'sendto', 'recvfrom', 'clone', 'execve', 'exit', 'wait4', 'kill', 'uname', 'fcntl', 'flock', 'fsync', 'fdatasync', 'truncate', 'ftruncate', 'getdents', 'getcwd', 'chdir', 'rename', 'mkdir', 'rmdir', 'creat', 'link', 'unlink', 'symlink', 'readlink', 'chmod', 'chown', 'lchown', 'umask', 'gettimeofday', 'getrlimit', 'getrusage', 'sysinfo', 'times', 'getuid', 'getgid', 'setuid', 'setgid', 'geteuid', 'getegid', 'setpgid', 'getppid', 'getpgrp', 'setsid', 'setuid', 'setgid', 'getgroups', 'setgroups', 'setresuid', 'getresuid', 'setresgid', 'getresgid', 'gettid', 'set_tid_address', 'clock_gettime', 'clock_getres', 'exit_group', 'futex', 'set_robust_list', 'get_robust_list', 'epoll_create', 'epoll_ctl', 'epoll_wait', 'epoll_pwait', 'setsockopt', 'getsockopt', 'bind', 'listen', 'recv', 'send', 'shutdown', 'accept4', 'eventfd', 'eventfd2', 'signalfd', 'signalfd4', 'timerfd_create', 'timerfd_settime', 'timerfd_gettime', 'prlimit64', 'getrandom', 'memfd_create', 'statx'] },
        { action: 'SCMP_ACT_LOG', names: ['mount', 'umount2', 'swapon', 'swapoff'] },
        { action: 'SCMP_ACT_ERRNO', names: ['kexec_load', 'init_module', 'finit_module', 'delete_module', 'ptrace', 'process_vm_readv', 'process_vm_writev', 'personality', 'lookup_dcookie', 'perf_event_open', 'open_by_handle_at', 'fanotify_init'] }
      ]
    };

    this.seccompProfiles.set('runtime-default', defaultProfile);
  }

  private initializeDefaultPodSecurityPolicies(): void {
    const restrictedPolicy: PodSecurityPolicy = {
      name: 'restricted',
      privileged: false,
      hostNetwork: false,
      hostPID: false,
      hostIPC: false,
      runAsUser: { rule: 'MustRunAsNonRoot' },
      seLinux: { rule: 'RunAsAny' },
      volumes: ['configMap', 'emptyDir', 'projected', 'secret', 'downwardAPI', 'persistentVolumeClaim'],
      allowedCapabilities: [],
      requiredDropCapabilities: ['ALL'],
      readOnlyRootFilesystem: true,
      allowPrivilegeEscalation: false
    };

    const baselinePolicy: PodSecurityPolicy = {
      name: 'baseline',
      privileged: false,
      hostNetwork: false,
      hostPID: false,
      hostIPC: false,
      runAsUser: { rule: 'RunAsAny' },
      seLinux: { rule: 'RunAsAny' },
      volumes: ['*'],
      allowedCapabilities: [],
      requiredDropCapabilities: [],
      readOnlyRootFilesystem: false,
      allowPrivilegeEscalation: false
    };

    this.podSecurityPolicies.set('restricted', restrictedPolicy);
    this.podSecurityPolicies.set('baseline', baselinePolicy);
  }

  // ========================================================================
  // UTILITY AND LIFECYCLE
  // ========================================================================

  /**
   * Destroy the module and clean up all state.
   */
  public async destroy(): Promise<void> {
    if (!this.isInitialized) return;

    this.podSecurityPolicies.clear();
    this.containerScanResults.clear();
    this.networkPolicies.clear();
    this.rbacAuditResults.clear();
    this.cloudPostureResults.clear();
    this.misconfigurations.clear();
    this.iacScanResults.clear();
    this.runtimeAnomalyResults.clear();
    this.seccompProfiles.clear();
    this.syscallMonitorResults.clear();
    this.workloadIdentities.clear();
    this.lateralMovementResults.clear();
    this.securityEvents = [];
    this.privilegedContainers = [];

    this.k8sCircuitBreaker.reset();
    this.cspmCircuitBreaker.reset();
    this.runtimeCircuitBreaker.reset();

    this.isInitialized = false;
    logger.info('[CloudSecurity] Module destroyed');
    this.emit('destroyed');
  }

  /**
   * Get module health status.
   */
  public getHealth(): {
    initialized: boolean;
    podSecurityPolicies: number;
    containerScans: number;
    networkPolicies: number;
    misconfigurations: number;
    iacScans: number;
    runtimeAnomalies: number;
    seccompProfiles: number;
    workloadIdentities: number;
    circuitBreakers: Record<string, string>;
  } {
    return {
      initialized: this.isInitialized,
      podSecurityPolicies: this.podSecurityPolicies.size,
      containerScans: this.containerScanResults.size,
      networkPolicies: this.networkPolicies.size,
      misconfigurations: this.misconfigurations.size,
      iacScans: this.iacScanResults.size,
      runtimeAnomalies: this.runtimeAnomalyResults.size,
      seccompProfiles: this.seccompProfiles.size,
      workloadIdentities: this.workloadIdentities.size,
      circuitBreakers: {
        k8s: this.k8sCircuitBreaker.getState(),
        cspm: this.cspmCircuitBreaker.getState(),
        runtime: this.runtimeCircuitBreaker.getState()
      }
    };
  }
}

// ============================================================================
// FACTORY
// ============================================================================

export class CloudNativeSecurityModuleFactory {
  /**
   * Create and initialize a CloudNativeSecurityModule instance.
   */
  static async create(config: Partial<CloudNativeSecurityConfig> = {}): Promise<CloudNativeSecurityModule> {
    const module = new CloudNativeSecurityModule(config);
    await module.initialize();
    return module;
  }

  /**
   * Create a module with secure defaults for Kubernetes + AWS.
   */
  static async createSecureDefaults(): Promise<CloudNativeSecurityModule> {
    const module = new CloudNativeSecurityModule({
      kubernetes: {
        enabled: true,
        admissionController: 'built-in',
        networkPolicy: 'calico',
        podSecurityStandard: 'restricted',
        clusterName: 'production-cluster'
      },
      cspm: {
        enabled: true,
        providers: ['aws'],
        autoRemediate: false,
        scanIntervalMs: 3600000
      },
      iac: {
        enabled: true,
        formats: ['terraform', 'kubernetes'],
        failOnSeverity: 'high'
      },
      containerRuntime: {
        enabled: true,
        seccompEnabled: true,
        apparmorEnabled: false,
        monitoringIntervalMs: 60000,
        miningDetectionEnabled: true
      },
      workloadProtection: {
        enabled: true,
        identityDetection: true,
        leastPrivilegeEnforcement: true,
        lateralMovementDetection: true
      }
    });
    await module.initialize();
    return module;
  }

  /**
   * Create a module with multi-cloud CSPM (AWS + Azure + GCP).
   */
  static async createMultiCloudCSPM(): Promise<CloudNativeSecurityModule> {
    const module = new CloudNativeSecurityModule({
      kubernetes: {
        enabled: false,
        admissionController: 'built-in',
        networkPolicy: 'none',
        podSecurityStandard: 'baseline',
        clusterName: 'default'
      },
      cspm: {
        enabled: true,
        providers: ['aws', 'azure', 'gcp'],
        autoRemediate: false,
        scanIntervalMs: 7200000
      },
      iac: {
        enabled: true,
        formats: ['terraform', 'cloudformation', 'arm'],
        failOnSeverity: 'critical'
      },
      containerRuntime: {
        enabled: false,
        seccompEnabled: false,
        apparmorEnabled: false,
        monitoringIntervalMs: 60000,
        miningDetectionEnabled: false
      },
      workloadProtection: {
        enabled: true,
        identityDetection: true,
        leastPrivilegeEnforcement: false,
        lateralMovementDetection: true
      }
    });
    await module.initialize();
    return module;
  }
}
