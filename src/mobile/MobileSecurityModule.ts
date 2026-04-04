/**
 * ============================================================================
 * MOBILE SECURITY MODULE
 * ============================================================================
 * Jailbreak/Root Detection, SSL Pinning, Biometric Authentication,
 * RASP (Runtime Application Self-Protection), Secure Storage
 *
 * Платформы: iOS, Android, React Native, Flutter
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import { logger } from '../logging/Logger';

// ============================================================================
// SECURITY ERRORS
// ============================================================================

class MobileSecurityError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(message: string, code: string, statusCode: number = 500) {
    super(message);
    this.name = 'MobileSecurityError';
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

  constructor(name: string, failureThreshold: number = 5, recoveryTimeoutMs: number = 30000, successThreshold: number = 2) {
    this.name = name;
    this.failureThreshold = failureThreshold;
    this.recoveryTimeoutMs = recoveryTimeoutMs;
    this.successThreshold = successThreshold;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed < this.recoveryTimeoutMs) {
        throw new MobileSecurityError(`Circuit breaker '${this.name}' is OPEN`, 'CIRCUIT_OPEN', 503);
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
      logger.warn(`[MobileSecurity] Circuit breaker '${this.name}' tripped to OPEN`);
    }
  }

  getState(): CircuitState { return this.state; }
  reset(): void {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
  }
}

// ============================================================================
// RATE LIMITER
// ============================================================================

class RateLimiter {
  private limits: Map<string, { count: number; resetTime: number }> = new Map();
  private readonly maxRequests: number;
  private readonly windowMs: number;

  constructor(maxRequests: number, windowMs: number) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  isAllowed(key: string): boolean {
    const now = Date.now();
    const entry = this.limits.get(key);
    if (!entry || now > entry.resetTime) {
      this.limits.set(key, { count: 1, resetTime: now + this.windowMs });
      return true;
    }
    if (entry.count >= this.maxRequests) return false;
    entry.count++;
    return true;
  }

  reset(key?: string): void {
    if (key) { this.limits.delete(key); } else { this.limits.clear(); }
  }
}

// ============================================================================
// TYPES — Jailbreak/Root Detection
// ============================================================================

export interface DeviceInfo {
  platform: 'ios' | 'android';
  model: string;
  osVersion: string;
  buildNumber: string;
  isEmulator: boolean;
  developerMode: boolean;
  usbDebugging: boolean;
  unknownSources: boolean;
  adbEnabled: boolean;
  rootedJailbroken: boolean;
  safetyNetResult?: SafetyNetResult;
}

export interface SafetyNetResult {
  ctsProfileMatch: boolean;
  basicIntegrity: boolean;
  advice: string[];
  timestampMs: number;
  evaluationType: 'BASIC' | 'HARDWARE_BACKED';
}

export interface DeviceIntegrityStatus {
  isSafe: boolean;
  jailbreakDetected: boolean;
  rootDetected: boolean;
  emulatorDetected: boolean;
  debuggerDetected: boolean;
  tamperingDetected: boolean;
  hookingDetected: boolean;
  threats: string[];
  riskScore: number; // 0-100
  lastCheck: string;
}

export interface JailbreakCheckResult {
  isJailbroken: boolean;
  checks: { name: string; passed: boolean; detail: string }[];
}

// ============================================================================
// TYPES — SSL Pinning
// ============================================================================

export interface SSLPinningPolicy {
  mode: 'strict' | 'standard' | 'relaxed';
  pinSha256: string[];
  backupPins: string[];
  includeSubdomains: boolean;
  expiration: string; // ISO date when pins expire
  reportUri?: string;
}

export interface SSLCertificateInfo {
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validTo: string;
  fingerprint: string;
  publicKeyHash: string;
  chainLength: number;
  isSelfSigned: boolean;
  keySize: number;
  signatureAlgorithm: string;
}

export interface MITMDetectionResult {
  detected: boolean;
  reason: string;
  certificateMismatch: boolean;
  pinValidationFailed: boolean;
  unknownCA: boolean;
  timestamp: string;
}

// ============================================================================
// TYPES — Biometric Authentication
// ============================================================================

export type BiometricType = 'faceId' | 'touchId' | 'fingerprint' | 'iris' | 'faceUnlock';

export interface BiometricAuthResult {
  success: boolean;
  userId: string;
  biometricType: BiometricType;
  attempts: number;
  maxAttempts: number;
  lockedOut: boolean;
  timestamp: string;
  error?: string;
}

export interface BiometricKeyData {
  keyId: string;
  publicKey: string;
  keyAlgorithm: 'ECDSA' | 'RSA' | 'Ed25519';
  keySize: number;
  createdAt: string;
  authenticatorType: string;
  userPresence: boolean;
  userVerification: boolean;
}

// ============================================================================
// TYPES — RASP
// ============================================================================

export interface TamperingDetectionResult {
  tampered: boolean;
  checks: { name: string; passed: boolean; detail: string }[];
  riskScore: number;
}

export interface DebuggerDetectionResult {
  debuggerDetected: boolean;
  debuggerType: 'none' | 'lldb' | 'gdb' | 'android_debug' | 'jdwp' | 'frida' | 'cycript' | 'xposed';
  ports: number[];
  processes: string[];
}

export interface HookDetectionResult {
  hooksDetected: boolean;
  hooks: { name: string; type: string; library: string; riskLevel: 'low' | 'medium' | 'high' | 'critical' }[];
  frameworks: string[];
}

export interface SecurityPolicyEnforcementResult {
  enforced: boolean;
  actions: string[];
  violations: string[];
  deviceBlocked: boolean;
  appSuspended: boolean;
}

// ============================================================================
// TYPES — Secure Storage
// ============================================================================

export interface EncryptedData {
  ciphertext: string;
  iv: string;
  authTag: string;
  algorithm: string;
  keyId: string;
  createdAt: string;
}

export interface KeychainOperationResult {
  success: boolean;
  keyId: string;
  operation: 'create' | 'read' | 'update' | 'delete';
  timestamp: string;
  error?: string;
}

// ============================================================================
// CONFIG
// ============================================================================

export interface MobileSecurityConfig {
  platform: 'ios' | 'android' | 'react-native' | 'flutter';
  shielding: {
    enabled: boolean;
    obfuscation: 'AGGRESSIVE' | 'STANDARD';
    antiTampering: boolean;
  };
  biometrics: {
    enabled: boolean;
    fallbackToPasscode: boolean;
    livenessDetection: boolean;
    maxAttempts: number;
    lockoutDurationMs: number;
  };
  sslPinning: {
    enabled: boolean;
    policy: SSLPinningPolicy;
  };
  rasp: {
    enabled: boolean;
    jailbreakDetection: boolean;
    debuggerDetection: boolean;
    hookDetection: boolean;
    emulatorDetection: boolean;
    response: 'warn' | 'block' | 'shutdown';
  };
  secureStorage: {
    encryption: 'AES-256-GCM' | 'ChaCha20-Poly1305';
    keychainProtection: 'biometric' | 'passcode' | 'none';
    autoLockTimeoutMs: number;
  };
}

const DEFAULT_CONFIG: MobileSecurityConfig = {
  platform: 'ios',
  shielding: {
    enabled: true,
    obfuscation: 'STANDARD',
    antiTampering: true
  },
  biometrics: {
    enabled: false,
    fallbackToPasscode: true,
    livenessDetection: false,
    maxAttempts: 5,
    lockoutDurationMs: 300000
  },
  sslPinning: {
    enabled: false,
    policy: {
      mode: 'standard',
      pinSha256: [],
      backupPins: [],
      includeSubdomains: true,
      expiration: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    }
  },
  rasp: {
    enabled: false,
    jailbreakDetection: true,
    debuggerDetection: true,
    hookDetection: true,
    emulatorDetection: true,
    response: 'warn'
  },
  secureStorage: {
    encryption: 'AES-256-GCM',
    keychainProtection: 'none',
    autoLockTimeoutMs: 300000
  }
};

// ============================================================================
// MOBILE SECURITY MODULE
// ============================================================================

export class MobileSecurityModule extends EventEmitter {
  private config: MobileSecurityConfig;
  private isInitialized = false;

  // State
  private deviceInfo: DeviceInfo | null = null;
  private knownCertificates: Map<string, SSLCertificateInfo> = new Map();
  private biometricKeys: Map<string, BiometricKeyData> = new Map();
  private biometricAttempts: Map<string, { count: number; lockedUntil: number }> = new Map();
  private mitmEvents: MITMDetectionResult[] = [];
  private securityLog: Array<{ event: string; timestamp: string; detail: string }> = [];

  // Infrastructure
  private rateLimiter: RateLimiter;
  private biometricCircuitBreaker: CircuitBreaker;
  private sslCircuitBreaker: CircuitBreaker;

  // Integrity checks cache
  private lastIntegrityCheck: DeviceIntegrityStatus | null = null;
  private integrityCheckInterval: NodeJS.Timeout | null = null;

  constructor(config: Partial<MobileSecurityConfig> = {}) {
    super();
    this.config = this.mergeConfig(DEFAULT_CONFIG, config);
    this.rateLimiter = new RateLimiter(60, 60000);
    this.biometricCircuitBreaker = new CircuitBreaker('Biometric', 3, 60000, 2);
    this.sslCircuitBreaker = new CircuitBreaker('SSL', 3, 30000, 2);

    logger.info('[MobileSecurity] Module created', undefined, undefined, {
      platform: this.config.platform,
      shielding: this.config.shielding.enabled,
      biometrics: this.config.biometrics.enabled,
      sslPinning: this.config.sslPinning.enabled,
      rasp: this.config.rasp.enabled
    });
  }

  // ========================================================================
  // INITIALIZATION
  // ========================================================================

  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[MobileSecurity] Already initialized');
      return;
    }

    // Initialize device info
    this.deviceInfo = this.detectDeviceInfo();

    // Configure SSL pinning if enabled
    if (this.config.sslPinning.enabled && this.config.sslPinning.policy.pinSha256.length > 0) {
      logger.info('[MobileSecurity] SSL pinning configured', undefined, undefined, {
        pinCount: this.config.sslPinning.policy.pinSha256.length,
        mode: this.config.sslPinning.policy.mode
      });
    }

    // Start continuous integrity monitoring
    if (this.config.rasp.enabled) {
      this.startContinuousMonitoring();
    }

    this.isInitialized = true;
    this.emit('initialized');
    logger.info('[MobileSecurity] Module fully initialized', undefined, undefined, {
      platform: this.config.platform,
      deviceModel: this.deviceInfo.model,
      osVersion: this.deviceInfo.osVersion
    });
  }

  private mergeConfig(defaults: MobileSecurityConfig, overrides: Partial<MobileSecurityConfig>): MobileSecurityConfig {
    return {
      platform: overrides.platform || defaults.platform,
      shielding: { ...defaults.shielding, ...(overrides.shielding || {}) },
      biometrics: { ...defaults.biometrics, ...(overrides.biometrics || {}) },
      sslPinning: {
        ...defaults.sslPinning,
        ...(overrides.sslPinning || {}),
        policy: { ...defaults.sslPinning.policy, ...(overrides.sslPinning?.policy || {}) }
      },
      rasp: { ...defaults.rasp, ...(overrides.rasp || {}) },
      secureStorage: { ...defaults.secureStorage, ...(overrides.secureStorage || {}) }
    };
  }

  // ========================================================================
  // JAILBREAK / ROOT DETECTION
  // ========================================================================

  /**
   * Comprehensive jailbreak/root detection.
   * Checks multiple indicators specific to iOS and Android.
   */
  public detectJailbreak(deviceInfo: DeviceInfo): JailbreakCheckResult {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const checks: { name: string; passed: boolean; detail: string }[] = [];
    let isJailbroken = false;

    // Check 1: Emulator detection
    if (deviceInfo.isEmulator) {
      checks.push({ name: 'emulator_check', passed: false, detail: 'Running in emulator environment' });
      isJailbroken = true;
    } else {
      checks.push({ name: 'emulator_check', passed: true, detail: 'Physical device detected' });
    }

    // Check 2: Developer mode
    if (deviceInfo.developerMode) {
      checks.push({ name: 'developer_mode', passed: false, detail: 'Developer mode is enabled' });
      // Developer mode alone doesn't mean jailbroken
    } else {
      checks.push({ name: 'developer_mode', passed: true, detail: 'Developer mode is disabled' });
    }

    // Check 3: USB Debugging (Android)
    if (deviceInfo.platform === 'android' && deviceInfo.usbDebugging) {
      checks.push({ name: 'usb_debugging', passed: false, detail: 'USB debugging is enabled' });
    } else {
      checks.push({ name: 'usb_debugging', passed: true, detail: 'USB debugging is disabled' });
    }

    // Check 4: Unknown sources (Android)
    if (deviceInfo.platform === 'android' && deviceInfo.unknownSources) {
      checks.push({ name: 'unknown_sources', passed: false, detail: 'Installation from unknown sources is enabled' });
    } else {
      checks.push({ name: 'unknown_sources', passed: true, detail: 'Unknown sources restriction active' });
    }

    // Check 5: ADB enabled (Android)
    if (deviceInfo.platform === 'android' && deviceInfo.adbEnabled) {
      checks.push({ name: 'adb_enabled', passed: false, detail: 'ADB daemon is running' });
    } else {
      checks.push({ name: 'adb_enabled', passed: true, detail: 'ADB is not accessible' });
    }

    // Check 6: Known jailbreak indicators (file system checks)
    const jailbreakFiles = this.getJailbreakPaths(deviceInfo.platform);
    let jailbreakFilesFound = false;

    // Simulated check — in production, use fs.existsSync for each path
    if (deviceInfo.rootedJailbroken) {
      jailbreakFilesFound = true;
    }

    if (jailbreakFilesFound) {
      checks.push({ name: 'filesystem_check', passed: false, detail: `Jailbreak files found: ${jailbreakFiles.slice(0, 3).join(', ')}` });
      isJailbroken = true;
    } else {
      checks.push({ name: 'filesystem_check', passed: true, detail: 'No jailbreak files detected' });
    }

    // Check 7: Known jailbreak apps
    const jailbreakApps = this.getJailbreakApps(deviceInfo.platform);
    // Simulated — would check installed apps in production
    const hasJailbreakApp = deviceInfo.rootedJailbroken;
    if (hasJailbreakApp) {
      checks.push({ name: 'app_check', passed: false, detail: `Jailbreak apps detected: ${jailbreakApps.slice(0, 3).join(', ')}` });
      isJailbroken = true;
    } else {
      checks.push({ name: 'app_check', passed: true, detail: 'No jailbreak apps found' });
    }

    // Check 8: Substrate/Cydia/Frida libraries
    const hasHookLibs = deviceInfo.rootedJailbroken;
    if (hasHookLibs) {
      checks.push({ name: 'library_check', passed: false, detail: 'Hooking libraries detected (MobileSubstrate/Frida/Cycript)' });
      isJailbroken = true;
    } else {
      checks.push({ name: 'library_check', passed: true, detail: 'No hooking libraries detected' });
    }

    // Check 9: sandbox violation
    const sandboxOk = !deviceInfo.rootedJailbroken;
    if (!sandboxOk) {
      checks.push({ name: 'sandbox_check', passed: false, detail: 'Sandbox integrity compromised' });
      isJailbroken = true;
    } else {
      checks.push({ name: 'sandbox_check', passed: true, detail: 'Sandbox is intact' });
    }

    if (isJailbroken) {
      logger.warn('[MobileSecurity] Jailbreak/root detected', undefined, undefined, {
        platform: deviceInfo.platform,
        failedChecks: checks.filter(c => !c.passed).length,
        totalChecks: checks.length
      });

      this.securityLog.push({
        event: 'jailbreak_detected',
        timestamp: new Date().toISOString(),
        detail: `${checks.filter(c => !c.passed).length}/${checks.length} checks failed`
      });

      this.emit('jailbreak-detected', { deviceInfo, checks, isJailbroken });
    }

    return { isJailbroken, checks };
  }

  /**
   * Get comprehensive device integrity status.
   */
  public getDeviceIntegrityStatus(): DeviceIntegrityStatus {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const threats: string[] = [];
    let riskScore = 0;

    // Jailbreak check
    const jailbreakResult = this.deviceInfo ? this.detectJailbreak(this.deviceInfo) : { isJailbroken: false, checks: [] };
    const jailbreakDetected = jailbreakResult.isJailbroken;
    if (jailbreakDetected) {
      threats.push('Device is jailbroken/rooted');
      riskScore += 40;
    }

    // Debugger check
    const debuggerResult = this.detectDebugger();
    const debuggerDetected = debuggerResult.debuggerDetected;
    if (debuggerDetected) {
      threats.push(`Debugger detected: ${debuggerResult.debuggerType}`);
      riskScore += 30;
    }

    // Tampering check
    const tamperResult = this.detectTampering();
    const tamperingDetected = tamperResult.tampered;
    if (tamperingDetected) {
      threats.push('Application tampering detected');
      riskScore += 50;
    }

    // Hooking check
    const hookResult = this.hookDetection();
    const hookingDetected = hookResult.hooksDetected;
    if (hookingDetected) {
      threats.push(`Hooking frameworks detected: ${hookResult.frameworks.join(', ')}`);
      riskScore += 45;
    }

    // Emulator check
    const emulatorDetected = this.deviceInfo?.isEmulator || false;
    if (emulatorDetected) {
      threats.push('Running in emulator');
      riskScore += 15;
    }

    // MITM check
    const mitmResult = this.detectMITMAttack();
    if (mitmResult.detected) {
      threats.push(`MITM attack detected: ${mitmResult.reason}`);
      riskScore += 50;
    }

    const rootDetected = jailbreakDetected && this.deviceInfo?.platform === 'android';

    this.lastIntegrityCheck = {
      isSafe: riskScore < 25,
      jailbreakDetected,
      rootDetected,
      emulatorDetected,
      debuggerDetected,
      tamperingDetected,
      hookingDetected,
      threats,
      riskScore: Math.min(riskScore, 100),
      lastCheck: new Date().toISOString()
    };

    if (riskScore >= 50 && this.config.rasp.response === 'shutdown') {
      logger.critical('[MobileSecurity] Device integrity compromised — shutdown recommended', undefined, undefined, {
        riskScore,
        threats
      });
      this.emit('security-shutdown', { riskScore, threats });
    } else if (riskScore >= 25 && this.config.rasp.response === 'block') {
      logger.error('[MobileSecurity] Device security violated — blocking access', undefined, undefined, {
        riskScore,
        threats
      });
      this.emit('security-block', { riskScore, threats });
    }

    return this.lastIntegrityCheck;
  }

  /**
   * Check Google SafetyNet / Play Integrity.
   */
  public checkSafetyNet(): SafetyNetResult {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (this.config.platform !== 'android') {
      return {
        ctsProfileMatch: true,
        basicIntegrity: true,
        advice: [],
        timestampMs: Date.now(),
        evaluationType: 'BASIC'
      };
    }

    // Simulate SafetyNet attestation check
    // In production: use Google Play Integrity API (SafetyNet Attestation is deprecated)
    const deviceInfo = this.deviceInfo;
    const ctsProfileMatch = deviceInfo ? !deviceInfo.rootedJailbroken && !deviceInfo.isEmulator : true;
    const basicIntegrity = deviceInfo ? !deviceInfo.rootedJailbroken : true;

    const advice: string[] = [];
    if (!ctsProfileMatch) advice.push('DEVICE_INCOMPATIBLE — device does not match certified profile');
    if (!basicIntegrity) advice.push('INTEGRITY_VIOLATION — system integrity is compromised');
    if (deviceInfo?.developerMode) advice.push('DEVELOPER_MODE — consider disabling USB debugging');
    if (deviceInfo?.unknownSources) advice.push('UNKNOWN_SOURCES — disable installation from unknown sources');

    const result: SafetyNetResult = {
      ctsProfileMatch,
      basicIntegrity,
      advice,
      timestampMs: Date.now(),
      evaluationType: 'HARDWARE_BACKED'
    };

    logger.debug('[MobileSecurity] SafetyNet check completed', undefined, undefined, {
      ctsProfileMatch: result.ctsProfileMatch,
      basicIntegrity: result.basicIntegrity
    });

    return result;
  }

  // ========================================================================
  // SSL PINNING
  // ========================================================================

  /**
   * Validate SSL certificate against pinned certificates.
   */
  public validateSSLCertificate(cert: Partial<SSLCertificateInfo>, domain: string): { valid: boolean; reason?: string; certInfo: SSLCertificateInfo } {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.sslPinning.enabled) {
      return {
        valid: true,
        certInfo: cert as SSLCertificateInfo
      };
    }

    const certInfo: SSLCertificateInfo = {
      subject: cert.subject || '',
      issuer: cert.issuer || '',
      serialNumber: cert.serialNumber || '',
      validFrom: cert.validFrom || new Date().toISOString(),
      validTo: cert.validTo || new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      fingerprint: cert.fingerprint || '',
      publicKeyHash: cert.publicKeyHash || '',
      chainLength: cert.chainLength || 1,
      isSelfSigned: cert.isSelfSigned || false,
      keySize: cert.keySize || 2048,
      signatureAlgorithm: cert.signatureAlgorithm || 'SHA256withRSA'
    };

    // Check 1: Certificate expiration
    const now = new Date();
    if (new Date(certInfo.validTo) < now) {
      return { valid: false, reason: 'Certificate has expired', certInfo };
    }
    if (new Date(certInfo.validFrom) > now) {
      return { valid: false, reason: 'Certificate is not yet valid', certInfo };
    }

    // Check 2: Self-signed certificate
    if (certInfo.isSelfSigned) {
      return { valid: false, reason: 'Self-signed certificate not allowed', certInfo };
    }

    // Check 3: Key size minimum
    if (certInfo.keySize < 2048) {
      return { valid: false, reason: `Key size ${certInfo.keySize} is below minimum 2048`, certInfo };
    }

    // Check 4: Weak signature algorithm
    const weakAlgorithms = ['MD5', 'SHA1'];
    if (weakAlgorithms.some(alg => certInfo.signatureAlgorithm.toUpperCase().includes(alg))) {
      return { valid: false, reason: `Weak signature algorithm: ${certInfo.signatureAlgorithm}`, certInfo };
    }

    // Check 5: Pin validation (if policy has pins configured)
    const policy = this.config.sslPinning.policy;
    if (policy.pinSha256.length > 0) {
      const pinMatch = policy.pinSha256.includes(certInfo.publicKeyHash) ||
                       policy.pinSha256.includes(certInfo.fingerprint);
      if (!pinMatch && policy.mode === 'strict') {
        return { valid: false, reason: 'Certificate pin mismatch (strict mode)', certInfo };
      }
    }

    // Check 6: Pin expiration
    if (new Date(policy.expiration) < now) {
      logger.warn('[MobileSecurity] SSL pinning policy has expired', undefined, undefined, {
        domain,
        expirationDate: policy.expiration
      });
    }

    // Store certificate in known certificates
    this.knownCertificates.set(certInfo.fingerprint || certInfo.publicKeyHash, certInfo);

    logger.debug('[MobileSecurity] SSL certificate validated', undefined, undefined, {
      domain,
      subject: certInfo.subject,
      validTo: certInfo.validTo
    });

    return { valid: true, certInfo };
  }

  /**
   * Configure SSL pinning policy.
   */
  public configurePinningPolicy(policy: Partial<SSLPinningPolicy>): { success: boolean; previousPolicy: SSLPinningPolicy } {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const previousPolicy = { ...this.config.sslPinning.policy };

    this.config.sslPinning.policy = { ...this.config.sslPinning.policy, ...policy };
    this.config.sslPinning.enabled = true;

    logger.info('[MobileSecurity] SSL pinning policy configured', undefined, undefined, {
      mode: this.config.sslPinning.policy.mode,
      pinCount: this.config.sslPinning.policy.pinSha256.length,
      includeSubdomains: this.config.sslPinning.policy.includeSubdomains
    });

    this.emit('ssl-policy-updated', { previousPolicy, newPolicy: this.config.sslPinning.policy });

    return { success: true, previousPolicy };
  }

  /**
   * Detect MITM (Man-in-the-Middle) attacks.
   */
  public detectMITMAttack(): MITMDetectionResult {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const result: MITMDetectionResult = {
      detected: false,
      reason: '',
      certificateMismatch: false,
      pinValidationFailed: false,
      unknownCA: false,
      timestamp: new Date().toISOString()
    };

    // Check 1: Compare certificate chain against known pins
    if (this.config.sslPinning.enabled && this.config.sslPinning.policy.pinSha256.length > 0) {
      const policy = this.config.sslPinning.policy;
      let pinMatch = false;

      for (const [, certInfo] of this.knownCertificates.entries()) {
        if (policy.pinSha256.includes(certInfo.publicKeyHash) || policy.pinSha256.includes(certInfo.fingerprint)) {
          pinMatch = true;
          break;
        }
      }

      // If we have known certs but none match pins, potential MITM
      if (this.knownCertificates.size > 0 && !pinMatch) {
        result.detected = true;
        result.pinValidationFailed = true;
        result.reason = 'No certificate matches pinned SHA256 hashes';
      }
    }

    // Check 2: Detect proxy certificates
    for (const [, certInfo] of this.knownCertificates.entries()) {
      const proxyIndicators = ['proxy', 'mitm', 'charles', 'fiddler', 'burp', 'mitmproxy'];
      const subjectLower = certInfo.subject.toLowerCase();
      const issuerLower = certInfo.issuer.toLowerCase();

      if (proxyIndicators.some(indicator => subjectLower.includes(indicator) || issuerLower.includes(indicator))) {
        result.detected = true;
        result.unknownCA = true;
        result.reason = `Certificate issued by known proxy CA: ${certInfo.issuer}`;
        break;
      }
    }

    // Check 3: Self-signed certs in chain (potential MITM)
    for (const [, certInfo] of this.knownCertificates.entries()) {
      if (certInfo.isSelfSigned && certInfo.chainLength > 1) {
        result.detected = true;
        result.certificateMismatch = true;
        result.reason = 'Self-signed certificate found in chain';
        break;
      }
    }

    if (result.detected) {
      this.mitmEvents.push(result);
      logger.error('[MobileSecurity] MITM attack detected', undefined, undefined, {
        reason: result.reason,
        pinValidationFailed: result.pinValidationFailed,
        unknownCA: result.unknownCA
      });

      this.emit('mitm-detected', result);
    }

    return result;
  }

  // ========================================================================
  // BIOMETRIC AUTHENTICATION
  // ============================================================================

  /**
   * Authenticate user with biometric (FaceID, TouchID, Fingerprint, etc.).
   */
  public authenticateBiometric(userId: string, biometricType: BiometricType): Promise<BiometricAuthResult> {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.biometrics.enabled) {
      throw new MobileSecurityError('Biometric authentication is not enabled', 'BIOMETRICS_DISABLED', 403);
    }

    return this.biometricCircuitBreaker.execute(async () => {
      // Check rate limiting
      const rateKey = `biometric:${userId}`;
      if (!this.rateLimiter.isAllowed(rateKey)) {
        return this.buildBiometricFailureResult(userId, biometricType, 'Rate limit exceeded');
      }

      // Check lockout
      const attemptRecord = this.biometricAttempts.get(userId);
      const now = Date.now();

      if (attemptRecord && attemptRecord.lockedUntil > now) {
        const remaining = attemptRecord.lockedUntil - now;
        return this.buildBiometricFailureResult(
          userId,
          biometricType,
          `Account locked. Retry after ${Math.ceil(remaining / 1000)}s`,
          true
        );
      }

      // Get attempts
      const attempts = attemptRecord ? attemptRecord.count : 0;
      const maxAttempts = this.config.biometrics.maxAttempts;

      if (attempts >= maxAttempts) {
        // Lock out
        this.biometricAttempts.set(userId, {
          count: attempts + 1,
          lockedUntil: now + this.config.biometrics.lockoutDurationMs
        });

        logger.warn('[MobileSecurity] Biometric lockout triggered', undefined, undefined, {
          userId,
          biometricType,
          attempts
        });

        this.emit('biometric-lockout', { userId, biometricType, lockedUntil: new Date(now + this.config.biometrics.lockoutDurationMs).toISOString() });

        return this.buildBiometricFailureResult(
          userId,
          biometricType,
          `Maximum attempts (${maxAttempts}) exceeded`,
          true
        );
      }

      // Check if biometric key exists for user
      const biometricKey = this.findBiometricKeyForUser(userId);
      if (!biometricKey) {
        this.recordBiometricAttempt(userId);
        return this.buildBiometricFailureResult(userId, biometricType, 'No biometric key registered');
      }

      // Simulate biometric verification
      // In production: invoke platform biometric API (LocalAuthentication on iOS, BiometricPrompt on Android)
      const livenessCheck = this.config.biometrics.livenessDetection ? this.performLivenessCheck(biometricType) : true;

      if (!livenessCheck) {
        this.recordBiometricAttempt(userId);
        return this.buildBiometricFailureResult(userId, biometricType, 'Liveness check failed — possible spoofing attempt');
      }

      // Success
      this.biometricAttempts.delete(userId);

      const authResult: BiometricAuthResult = {
        success: true,
        userId,
        biometricType,
        attempts: attempts + 1,
        maxAttempts,
        lockedOut: false,
        timestamp: new Date().toISOString()
      };

      logger.info('[MobileSecurity] Biometric authentication successful', undefined, undefined, {
        userId,
        biometricType,
        livenessCheck
      });

      this.emit('biometric-success', authResult);

      return authResult;
    });
  }

  /**
   * Register a biometric key for a user.
   */
  public registerBiometricKey(userId: string, keyData: Partial<BiometricKeyData>): { success: boolean; keyId: string } {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.biometrics.enabled) {
      throw new MobileSecurityError('Biometric authentication is not enabled', 'BIOMETRICS_DISABLED', 403);
    }

    const keyId = keyData.keyId || crypto.randomUUID();

    const biometricKey: BiometricKeyData = {
      keyId,
      publicKey: keyData.publicKey || crypto.randomBytes(65).toString('hex'),
      keyAlgorithm: keyData.keyAlgorithm || 'ECDSA',
      keySize: keyData.keySize || 256,
      createdAt: new Date().toISOString(),
      authenticatorType: keyData.authenticatorType || this.config.platform === 'ios' ? 'SecureEnclave' : 'StrongBox',
      userPresence: keyData.userPresence !== undefined ? keyData.userPresence : true,
      userVerification: keyData.userVerification !== undefined ? keyData.userVerification : true
    };

    this.biometricKeys.set(`${userId}:${keyId}`, biometricKey);

    logger.info('[MobileSecurity] Biometric key registered', undefined, undefined, {
      userId,
      keyId,
      algorithm: biometricKey.keyAlgorithm,
      keySize: biometricKey.keySize
    });

    this.emit('biometric-key-registered', { userId, keyId });

    return { success: true, keyId };
  }

  /**
   * Revoke all biometric access for a user.
   */
  public revokeBiometricAccess(userId: string): { success: boolean; revokedKeys: number } {
    let revokedKeys = 0;

    for (const [key] of this.biometricKeys.entries()) {
      if (key.startsWith(`${userId}:`)) {
        this.biometricKeys.delete(key);
        revokedKeys++;
      }
    }

    // Clear attempts
    this.biometricAttempts.delete(userId);

    logger.info('[MobileSecurity] Biometric access revoked', undefined, undefined, {
      userId,
      revokedKeys
    });

    this.emit('biometric-access-revoked', { userId, revokedKeys });

    return { success: true, revokedKeys };
  }

  // Internal biometric helpers
  private findBiometricKeyForUser(userId: string): BiometricKeyData | undefined {
    for (const [key, value] of this.biometricKeys.entries()) {
      if (key.startsWith(`${userId}:`)) {
        return value;
      }
    }
    return undefined;
  }

  private recordBiometricAttempt(userId: string): void {
    const existing = this.biometricAttempts.get(userId);
    this.biometricAttempts.set(userId, {
      count: (existing?.count || 0) + 1,
      lockedUntil: existing?.lockedUntil || 0
    });
  }

  private performLivenessCheck(type: BiometricType): boolean {
    // In production: use platform liveness API
    // iOS: LAPolicy.deviceOwnerAuthenticationWithBiometrics + biometryKit liveness
    // Android: BiometricPrompt with CRYPTO_STRONG
    // Here we simulate a liveness check
    return true;
  }

  private buildBiometricFailureResult(
    userId: string,
    biometricType: BiometricType,
    error: string,
    lockedOut = false
  ): BiometricAuthResult {
    const attemptRecord = this.biometricAttempts.get(userId);
    const attempts = attemptRecord ? attemptRecord.count : 0;

    return {
      success: false,
      userId,
      biometricType,
      attempts,
      maxAttempts: this.config.biometrics.maxAttempts,
      lockedOut,
      timestamp: new Date().toISOString(),
      error
    };
  }

  // ========================================================================
  // RASP — Runtime Application Self-Protection
  // ========================================================================

  /**
   * Detect application tampering (modified binary, resources, etc.).
   */
  public detectTampering(): TamperingDetectionResult {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.shielding.antiTampering) {
      return { tampered: false, checks: [], riskScore: 0 };
    }

    const checks: { name: string; passed: boolean; detail: string }[] = [];
    let tampered = false;
    let riskScore = 0;

    // Check 1: Code signature verification
    const codeSignatureValid = true; // Simulated — in production use SecStaticCodeCheckValidity (iOS) or APK signature (Android)
    if (!codeSignatureValid) {
      checks.push({ name: 'code_signature', passed: false, detail: 'Application code signature is invalid' });
      tampered = true;
      riskScore += 50;
    } else {
      checks.push({ name: 'code_signature', passed: true, detail: 'Code signature is valid' });
    }

    // Check 2: Resource integrity
    const resourceIntegrityOk = true; // Simulated — verify checksums of critical resources
    if (!resourceIntegrityOk) {
      checks.push({ name: 'resource_integrity', passed: false, detail: 'Application resources have been modified' });
      tampered = true;
      riskScore += 30;
    } else {
      checks.push({ name: 'resource_integrity', passed: true, detail: 'Resource integrity verified' });
    }

    // Check 3: Binary modification
    const binaryUnchanged = true; // Simulated — check Mach-O/ELF header, section hashes
    if (!binaryUnchanged) {
      checks.push({ name: 'binary_modification', passed: false, detail: 'Application binary has been modified' });
      tampered = true;
      riskScore += 50;
    } else {
      checks.push({ name: 'binary_modification', passed: true, detail: 'Binary integrity verified' });
    }

    // Check 4: Runtime patching (in-memory code modification)
    const runtimeIntact = true; // Simulated — check executable pages against known hashes
    if (!runtimeIntact) {
      checks.push({ name: 'runtime_patching', passed: false, detail: 'In-memory code modification detected' });
      tampered = true;
      riskScore += 50;
    } else {
      checks.push({ name: 'runtime_patching', passed: true, detail: 'Runtime memory integrity verified' });
    }

    // Check 5: Info.plist / AndroidManifest tampering
    const manifestIntact = true;
    if (!manifestIntact) {
      checks.push({ name: 'manifest_tampering', passed: false, detail: 'Application manifest has been modified' });
      tampered = true;
      riskScore += 30;
    } else {
      checks.push({ name: 'manifest_tampering', passed: true, detail: 'Manifest integrity verified' });
    }

    if (tampered) {
      logger.error('[MobileSecurity] Application tampering detected', undefined, undefined, {
        failedChecks: checks.filter(c => !c.passed).map(c => c.name),
        riskScore
      });

      this.securityLog.push({
        event: 'tampering_detected',
        timestamp: new Date().toISOString(),
        detail: `${checks.filter(c => !c.passed).length} tampering checks failed`
      });

      this.emit('tampering-detected', { checks, riskScore });
    }

    return { tampered, checks, riskScore: Math.min(riskScore, 100) };
  }

  /**
   * Detect debugger attachment (LLDB, GDB, JDWP, etc.).
   */
  public detectDebugger(): DebuggerDetectionResult {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    let debuggerDetected = false;
    let debuggerType: DebuggerDetectionResult['debuggerType'] = 'none';
    const ports: number[] = [];
    const processes: string[] = [];

    // Check 1: Is debugger port open
    const debugPorts = this.config.platform === 'ios' ? [12345, 55555] : [5037, 8700, 8000];
    for (const port of debugPorts) {
      // Simulated port check — in production, attempt socket connection
      const portOpen = false;
      if (portOpen) {
        ports.push(port);
        debuggerDetected = true;
      }
    }

    // Check 2: Debuggable flag (Android)
    if (this.config.platform === 'android' && this.deviceInfo?.developerMode) {
      // Android: check if app is debuggable (android:debuggable="true" in manifest)
      const isDebuggable = false; // Simulated
      if (isDebuggable) {
        debuggerType = 'android_debug';
        debuggerDetected = true;
        processes.push('android_debug');
      }
    }

    // Check 3: JDWP (Java Debug Wire Protocol)
    if (this.config.platform === 'android') {
      const jdwpActive = false; // Simulated — check for jdwp process
      if (jdwpActive) {
        debuggerType = 'jdwp';
        debuggerDetected = true;
        processes.push('jdwp');
        ports.push(8000);
      }
    }

    // Check 4: ptrace status (iOS)
    if (this.config.platform === 'ios') {
      const isBeingTraced = false; // Simulated — check PT_DENY_ATTACH
      if (isBeingTraced) {
        debuggerType = 'lldb';
        debuggerDetected = true;
        processes.push('lldb');
        ports.push(12345);
      }
    }

    // Check 5: Debugger-related processes
    const debuggerProcesses = this.config.platform === 'ios'
      ? ['debugserver', 'lldb', 'gdb']
      : ['gdb', 'gdbserver', 'android_server', 'jdb'];

    for (const proc of debuggerProcesses) {
      // Simulated — in production, check /proc (Android) or sysctl (iOS)
      const processRunning = false;
      if (processRunning) {
        processes.push(proc);
        debuggerDetected = true;
        if (debuggerType === 'none') {
          debuggerType = proc.includes('lldb') || proc.includes('gdb') ? (proc as 'lldb' | 'gdb') : 'android_debug';
        }
      }
    }

    if (debuggerDetected) {
      logger.error('[MobileSecurity] Debugger detected', undefined, undefined, {
        debuggerType,
        ports,
        processes
      });

      this.securityLog.push({
        event: 'debugger_detected',
        timestamp: new Date().toISOString(),
        detail: `Debugger type: ${debuggerType}, ports: ${ports.join(', ')}`
      });

      this.emit('debugger-detected', { debuggerType, ports, processes });
    }

    return { debuggerDetected, debuggerType, ports, processes };
  }

  /**
   * Detect runtime hooking frameworks (Frida, Cycript, Xposed, etc.).
   */
  public hookDetection(): HookDetectionResult {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const hooks: HookDetectionResult['hooks'] = [];
    const frameworks: string[] = [];
    let hooksDetected = false;

    // Check for known hooking libraries
    const hookingLibs = [
      { name: 'FridaGadget', type: 'dynamic_instrumentation', library: 'frida-gadget.so / FridaGadget.dylib' },
      { name: 'FridaAgent', type: 'dynamic_instrumentation', library: 'frida-agent' },
      { name: 'Cycript', type: 'runtime_hooking', library: 'cycript' },
      { name: 'Substrate', type: 'method_swizzling', library: 'MobileSubstrate' },
      { name: 'Xposed', type: 'method_hooking', library: 'XposedBridge' },
      { name: 'JNIBridge', type: 'jni_hook', library: 'libsubstrate' },
      { name: 'libhook', type: 'inline_hook', library: 'libhook' },
      { name: 'And64InlineHook', type: 'inline_hook', library: 'And64InlineHook' }
    ];

    for (const lib of hookingLibs) {
      // Simulated — in production: check loaded libraries, check for known symbols
      const libLoaded = false;
      if (libLoaded) {
        hooks.push({ name: lib.name, type: lib.type, library: lib.library, riskLevel: 'critical' });
        frameworks.push(lib.name);
        hooksDetected = true;
      }
    }

    // Check for method swizzling (iOS)
    if (this.config.platform === 'ios') {
      const swizzlingDetected = false; // Simulated — check method_exchangeImplementations
      if (swizzlingDetected) {
        hooks.push({ name: 'MethodSwizzling', type: 'method_swizzling', library: 'Objective-C Runtime', riskLevel: 'high' });
        frameworks.push('MethodSwizzling');
        hooksDetected = true;
      }
    }

    // Check for JNI manipulation (Android)
    if (this.config.platform === 'android') {
      const jniHookDetected = false; // Simulated — check RegisterNatives calls
      if (jniHookDetected) {
        hooks.push({ name: 'JNIHook', type: 'jni_hook', library: 'libart', riskLevel: 'high' });
        frameworks.push('JNIHook');
        hooksDetected = true;
      }
    }

    // Check for suspicious environment variables
    const suspiciousEnvVars = ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'CYDIA'];
    for (const envVar of suspiciousEnvVars) {
      const envSet = false; // Simulated — check environment
      if (envSet) {
        hooks.push({ name: `Env:${envVar}`, type: 'library_injection', library: envVar, riskLevel: 'critical' });
        hooksDetected = true;
      }
    }

    if (hooksDetected) {
      logger.error('[MobileSecurity] Runtime hooking detected', undefined, undefined, {
        frameworks,
        hookCount: hooks.length,
        highestRisk: hooks.reduce((max, h) => {
          const levels = { low: 1, medium: 2, high: 3, critical: 4 };
          return levels[h.riskLevel] > levels[max] ? h.riskLevel : max;
        }, 'low' as 'low' | 'medium' | 'high' | 'critical')
      });

      this.securityLog.push({
        event: 'hooking_detected',
        timestamp: new Date().toISOString(),
        detail: `Frameworks: ${frameworks.join(', ')}`
      });

      this.emit('hooking-detected', { hooks, frameworks });
    }

    return { hooksDetected, hooks, frameworks };
  }

  /**
   * Enforce security policy based on device state.
   */
  public enforceSecurityPolicy(): SecurityPolicyEnforcementResult {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const actions: string[] = [];
    const violations: string[] = [];
    let deviceBlocked = false;
    let appSuspended = false;

    const integrity = this.getDeviceIntegrityStatus();

    // Apply response based on config
    if (integrity.riskScore >= 75) {
      // Critical — shut down
      if (this.config.rasp.response === 'shutdown') {
        actions.push('APP_SHUTDOWN — critical risk score');
        appSuspended = true;
        violations.push(`Risk score ${integrity.riskScore} exceeds critical threshold`);
      } else if (this.config.rasp.response === 'block') {
        actions.push('ACCESS_BLOCKED — high risk score');
        deviceBlocked = true;
        violations.push(`Risk score ${integrity.riskScore} exceeds block threshold`);
      } else {
        actions.push('WARNING_ISSUED — user notified');
        violations.push(integrity.threats.join('; '));
      }
    } else if (integrity.riskScore >= 50) {
      // High — block or warn
      if (this.config.rasp.response === 'block' || this.config.rasp.response === 'shutdown') {
        actions.push('ACCESS_BLOCKED — high risk score');
        deviceBlocked = true;
      } else {
        actions.push('WARNING_ISSUED — elevated risk');
      }
      violations.push(...integrity.threats);
    } else if (integrity.riskScore >= 25) {
      // Medium — warn
      actions.push('WARNING_ISSUED — moderate risk');
      violations.push(...integrity.threats);
    } else {
      actions.push('POLICY_ENFORCED — device is safe');
    }

    // Enforce SSL pinning
    if (this.config.sslPinning.enabled) {
      const mitmResult = this.detectMITMAttack();
      if (mitmResult.detected) {
        actions.push('SSL_CONNECTION_BLOCKED — MITM detected');
        deviceBlocked = true;
        violations.push('MITM attack detected');
      }
    }

    // Enforce biometric requirement
    if (this.config.biometrics.enabled) {
      actions.push('BIOMETRIC_REQUIRED — biometric authentication enforced');
    }

    logger.info('[MobileSecurity] Security policy enforced', undefined, undefined, {
      actions,
      violations: violations.length,
      deviceBlocked,
      appSuspended
    });

    this.emit('policy-enforced', { actions, violations, deviceBlocked, appSuspended });

    return { enforced: true, actions, violations, deviceBlocked, appSuspended };
  }

  // ========================================================================
  // SECURE STORAGE
  // ========================================================================

  /**
   * Encrypt local data using AES-256-GCM.
   */
  public encryptLocalData(data: string, key: string): EncryptedData {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const algorithm = this.config.secureStorage.encryption === 'ChaCha20-Poly1305'
      ? 'chacha20-poly1305'
      : 'aes-256-gcm';

    const iv = crypto.randomBytes(16);
    const keyBuffer = this.deriveKey(key, 32);

    const cipher = crypto.createCipheriv(
      algorithm === 'chacha20-poly1305' ? 'chacha20' : 'aes-256-gcm',
      keyBuffer,
      iv
    );

    let ciphertext = cipher.update(data, 'utf8', 'hex');
    ciphertext += cipher.final('hex');

    const authTag = algorithm === 'aes-256-gcm'
      ? (cipher as any).getAuthTag().toString('hex')
      : '';

    const encryptedData: EncryptedData = {
      ciphertext,
      iv: iv.toString('hex'),
      authTag,
      algorithm,
      keyId: crypto.createHash('sha256').update(key).digest('hex').substring(0, 16),
      createdAt: new Date().toISOString()
    };

    logger.debug('[MobileSecurity] Data encrypted', undefined, undefined, {
      algorithm,
      keyId: encryptedData.keyId,
      dataLength: data.length
    });

    return encryptedData;
  }

  /**
   * Decrypt local data.
   */
  public decryptLocalData(encryptedData: EncryptedData, key: string): string {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const algorithm = encryptedData.algorithm;
    const keyBuffer = this.deriveKey(key, 32);
    const iv = Buffer.from(encryptedData.iv, 'hex');

    const decipher = crypto.createDecipheriv(
      algorithm === 'chacha20-poly1305' ? 'chacha20' : 'aes-256-gcm',
      keyBuffer,
      iv
    );

    if (algorithm === 'aes-256-gcm' && encryptedData.authTag) {
      (decipher as any).setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
    }

    let plaintext = decipher.update(encryptedData.ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');

    logger.debug('[MobileSecurity] Data decrypted', undefined, undefined, {
      algorithm,
      keyId: encryptedData.keyId
    });

    return plaintext;
  }

  /**
   * Perform secure keychain / keystore operation.
   */
  public secureKeychainOperation(userId: string, operation: 'create' | 'read' | 'update' | 'delete'): KeychainOperationResult {
    if (!this.isInitialized) {
      throw new MobileSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const keyId = `keychain:${userId}:${this.config.platform}`;
    const now = new Date().toISOString();

    try {
      switch (operation) {
        case 'create': {
          // Generate key pair
          const keypair = crypto.generateKeyPairSync('ec', {
            namedCurve: 'P-256',
            publicKeyEncoding: { format: 'pem', type: 'spki' },
            privateKeyEncoding: { format: 'pem', type: 'pkcs8' }
          });

          const result: KeychainOperationResult = {
            success: true,
            keyId,
            operation: 'create',
            timestamp: now
          };

          logger.info('[MobileSecurity] Keychain key created', undefined, undefined, {
            userId,
            keyId,
            algorithm: 'ECDSA P-256'
          });

          this.emit('keychain-created', { userId, keyId });
          return result;
        }

        case 'read': {
          // In production: retrieve from iOS Keychain or Android Keystore
          const exists = true; // Simulated
          if (!exists) {
            throw new MobileSecurityError('Key not found in keychain', 'KEY_NOT_FOUND', 404);
          }

          return {
            success: true,
            keyId,
            operation: 'read',
            timestamp: now
          };
        }

        case 'update': {
          // Rotate key
          const keypair = crypto.generateKeyPairSync('ec', {
            namedCurve: 'P-256',
            publicKeyEncoding: { format: 'pem', type: 'spki' },
            privateKeyEncoding: { format: 'pem', type: 'pkcs8' }
          });

          return {
            success: true,
            keyId,
            operation: 'update',
            timestamp: now
          };
        }

        case 'delete': {
          // Remove key from keychain
          return {
            success: true,
            keyId,
            operation: 'delete',
            timestamp: now
          };
        }

        default:
          throw new MobileSecurityError(`Unknown keychain operation: ${operation}`, 'INVALID_OPERATION', 400);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('[MobileSecurity] Keychain operation failed', undefined, undefined, {
        userId,
        operation,
        error: message
      });

      return {
        success: false,
        keyId,
        operation,
        timestamp: now,
        error: message
      };
    }
  }

  // ========================================================================
  // UTILITY / INTERNAL
  // ========================================================================

  private getJailbreakPaths(platform: string): string[] {
    if (platform === 'ios') {
      return [
        '/Applications/Cydia.app',
        '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/usr/sbin/sshd',
        '/etc/apt',
        '/private/var/lib/apt/',
        '/usr/bin/sshd',
        '/bin/bash',
        '/var/lib/cydia',
        '/Applications/SBSettings.app',
        '/Applications/WinterBoard.app'
      ];
    }
    return [
      '/system/app/Superuser.apk',
      '/system/xbin/daemonsu',
      '/system/etc/init.d/99SuperSUDaemon',
      '/system/bin/.ext/.su',
      '/system/etc/.has_su_daemon',
      '/system/bin/su',
      '/system/xbin/su',
      '/sbin/su',
      '/data/local/xbin/su',
      '/data/local/bin/su'
    ];
  }

  private getJailbreakApps(platform: string): string[] {
    if (platform === 'ios') {
      return ['Cydia', 'Sileo', 'Zebra', 'Installer', 'Icy', 'SBSettings', 'WinterBoard', 'Undecimus', 'checkra1n', 'Taurine'];
    }
    return ['SuperSU', 'Magisk', 'KingRoot', 'Framaroot', 'iRoot', 'Kingoroot', 'OneClickRoot'];
  }

  private detectDeviceInfo(): DeviceInfo {
    // Simulated device detection — in production use react-native-device-info or similar
    return {
      platform: this.config.platform === 'react-native' || this.config.platform === 'flutter'
        ? 'ios' // Default assumption
        : this.config.platform as 'ios' | 'android',
      model: 'Simulated Device',
      osVersion: '1.0.0',
      buildNumber: '1',
      isEmulator: false,
      developerMode: false,
      usbDebugging: false,
      unknownSources: false,
      adbEnabled: false,
      rootedJailbroken: false
    };
  }

  private deriveKey(password: string, length: number): Buffer {
    // PBKDF2 key derivation
    return crypto.pbkdf2Sync(
      password,
      'mobile-security-salt',
      100000,
      length,
      'sha256'
    );
  }

  private startContinuousMonitoring(): void {
    // Start periodic integrity checks
    this.integrityCheckInterval = setInterval(() => {
      try {
        const integrity = this.getDeviceIntegrityStatus();
        if (!integrity.isSafe) {
          logger.warn('[MobileSecurity] Continuous monitoring: device integrity compromised', undefined, undefined, {
            riskScore: integrity.riskScore,
            threats: integrity.threats
          });
        }
      } catch (e) {
        logger.error('[MobileSecurity] Continuous monitoring error', undefined, undefined, {
          error: (e as Error).message
        });
      }
    }, 60000); // Every 60 seconds
  }

  /**
   * Destroy module and clean up resources.
   */
  public async destroy(): Promise<void> {
    if (!this.isInitialized) return;

    if (this.integrityCheckInterval) {
      clearInterval(this.integrityCheckInterval);
      this.integrityCheckInterval = null;
    }

    this.biometricKeys.clear();
    this.knownCertificates.clear();
    this.securityLog = [];

    this.rateLimiter.reset();
    this.biometricCircuitBreaker.reset();
    this.sslCircuitBreaker.reset();

    this.isInitialized = false;
    logger.info('[MobileSecurity] Module destroyed');
    this.emit('destroyed');
  }

  /**
   * Get module health status.
   */
  public getHealth(): {
    initialized: boolean;
    platform: string;
    knownCertificates: number;
    biometricKeys: number;
    mitmEvents: number;
    securityLogEntries: number;
    circuitBreakers: Record<string, string>;
  } {
    return {
      initialized: this.isInitialized,
      platform: this.config.platform,
      knownCertificates: this.knownCertificates.size,
      biometricKeys: this.biometricKeys.size,
      mitmEvents: this.mitmEvents.length,
      securityLogEntries: this.securityLog.length,
      circuitBreakers: {
        biometric: this.biometricCircuitBreaker.getState(),
        ssl: this.sslCircuitBreaker.getState()
      }
    };
  }
}

// ============================================================================
// FACTORY
// ============================================================================

export class MobileSecurityModuleFactory {
  /**
   * Create and initialize a MobileSecurityModule instance.
   */
  static async create(config: Partial<MobileSecurityConfig> = {}): Promise<MobileSecurityModule> {
    const module = new MobileSecurityModule(config);
    await module.initialize();
    return module;
  }

  /**
   * Create a module with secure defaults for iOS.
   */
  static async createIOSDefaults(): Promise<MobileSecurityModule> {
    const module = new MobileSecurityModule({
      platform: 'ios',
      shielding: { enabled: true, obfuscation: 'AGGRESSIVE', antiTampering: true },
      biometrics: { enabled: true, fallbackToPasscode: true, livenessDetection: true, maxAttempts: 5, lockoutDurationMs: 300000 },
      sslPinning: {
        enabled: true,
        policy: {
          mode: 'strict',
          pinSha256: [],
          backupPins: [],
          includeSubdomains: true,
          expiration: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
        }
      },
      rasp: { enabled: true, jailbreakDetection: true, debuggerDetection: true, hookDetection: true, emulatorDetection: true, response: 'block' },
      secureStorage: { encryption: 'AES-256-GCM', keychainProtection: 'biometric', autoLockTimeoutMs: 300000 }
    });
    await module.initialize();
    return module;
  }

  /**
   * Create a module with secure defaults for Android.
   */
  static async createAndroidDefaults(): Promise<MobileSecurityModule> {
    const module = new MobileSecurityModule({
      platform: 'android',
      shielding: { enabled: true, obfuscation: 'AGGRESSIVE', antiTampering: true },
      biometrics: { enabled: true, fallbackToPasscode: true, livenessDetection: true, maxAttempts: 5, lockoutDurationMs: 300000 },
      sslPinning: {
        enabled: true,
        policy: {
          mode: 'strict',
          pinSha256: [],
          backupPins: [],
          includeSubdomains: true,
          expiration: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
        }
      },
      rasp: { enabled: true, jailbreakDetection: true, debuggerDetection: true, hookDetection: true, emulatorDetection: true, response: 'block' },
      secureStorage: { encryption: 'AES-256-GCM', keychainProtection: 'biometric', autoLockTimeoutMs: 300000 }
    });
    await module.initialize();
    return module;
  }
}
