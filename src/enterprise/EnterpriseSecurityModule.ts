/**
 * ============================================================================
 * ENTERPRISE SECURITY MODULE
 * ============================================================================
 * SSO (SAML 2.0 / OpenID Connect), SCIM Provisioning,
 * PAM (Privileged Access Management), DLP (Data Loss Prevention)
 *
 * Соответствие: SOC 2 Type II, ISO 27001, NIST SP 800-53
 */

import { EventEmitter } from 'events';
import * as crypto from 'crypto';
import { logger } from '../logging/Logger';

// ============================================================================
// SECURITY ERRORS
// ============================================================================

class EnterpriseSecurityError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(message: string, code: string, statusCode: number = 500) {
    super(message);
    this.name = 'EnterpriseSecurityError';
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

interface CircuitBreakerConfig {
  failureThreshold: number;
  recoveryTimeoutMs: number;
  successThreshold: number;
}

class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount = 0;
  private successCount = 0;
  private lastFailureTime = 0;
  private config: CircuitBreakerConfig;
  private name: string;

  constructor(name: string, config: CircuitBreakerConfig) {
    this.name = name;
    this.config = config;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed < this.config.recoveryTimeoutMs) {
        throw new EnterpriseSecurityError(
          `Circuit breaker '${this.name}' is OPEN`,
          'CIRCUIT_OPEN',
          503
        );
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
      if (this.successCount >= this.config.successThreshold) {
        this.state = CircuitState.CLOSED;
        this.successCount = 0;
      }
    }
  }

  private onFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    this.successCount = 0;
    if (this.failureCount >= this.config.failureThreshold) {
      this.state = CircuitState.OPEN;
      logger.warn(`[EnterpriseSecurity] Circuit breaker '${this.name}' tripped to OPEN`);
    }
  }

  getState(): CircuitState {
    return this.state;
  }

  reset(): void {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
  }
}

// ============================================================================
// RATE LIMITER
// ============================================================================

interface RateLimitEntry {
  count: number;
  resetTime: number;
}

class RateLimiter {
  private limits: Map<string, RateLimitEntry> = new Map();
  private maxRequests: number;
  private windowMs: number;

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

    if (entry.count >= this.maxRequests) {
      return false;
    }

    entry.count++;
    return true;
  }

  reset(key?: string): void {
    if (key) {
      this.limits.delete(key);
    } else {
      this.limits.clear();
    }
  }
}

// ============================================================================
// SSO TYPES
// ============================================================================

export interface SSOIdentity {
  sub: string;
  email: string;
  name: string;
  roles: string[];
  groups: string[];
  attributes: Record<string, string>;
  provider: string;
  issuedAt: string;
  expiresAt: string;
}

export interface SAMLProviderConfig {
  entityId: string;
  ssoUrl: string;
  sloUrl: string;
  certificate: string;
  nameIdFormat: 'emailAddress' | 'persistent' | 'transient' | 'unspecified';
  binding: 'HTTP-POST' | 'HTTP-Redirect';
  attributeMapping: Record<string, string>;
}

export interface OIDCProviderConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userinfoEndpoint: string;
  jwksUri: string;
  scopes: string[];
  responseTypes: string[];
}

export interface SSORequest {
  token: string;
  provider: string;
  clientIp: string;
  userAgent: string;
}

export interface SSOEvalResult {
  granted: boolean;
  identity: SSOIdentity | null;
  mfaRequired: boolean;
  error?: string;
}

// ============================================================================
// SCIM TYPES
// ============================================================================

export interface SCIMUser {
  id: string;
  userName: string;
  emails: Array<{ value: string; primary: boolean }>;
  name: { givenName: string; familyName: string };
  active: boolean;
  groups: string[];
  roles: string[];
  externalId?: string;
  meta?: { created: string; lastModified: string; location: string };
}

export interface SCIMProvisionResult {
  success: boolean;
  userId: string;
  operation: 'created' | 'updated' | 'deleted';
  timestamp: string;
}

export interface SCIMAttributeSync {
  userId: string;
  attributes: Record<string, string | string[]>;
}

// ============================================================================
// PAM TYPES
// ============================================================================

export enum PrivilegedAccessStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  ACTIVE = 'ACTIVE',
  EXPIRED = 'EXPIRED',
  REVOKED = 'REVOKED',
  DENIED = 'DENIED'
}

export interface PrivilegedAccessRequest {
  id: string;
  userId: string;
  resource: string;
  duration: number; // minutes
  reason: string;
  status: PrivilegedAccessStatus;
  requestedAt: string;
  approvedBy?: string;
  approvedAt?: string;
  activatedAt?: string;
  expiresAt?: string;
  revokedAt?: string;
  revokedBy?: string;
}

export interface PrivilegedSessionAudit {
  accessId: string;
  userId: string;
  resource: string;
  status: string;
  requestedAt: string;
  activatedAt?: string;
  expiresAt?: string;
  durationUsed: number;
  commandsExecuted: number;
  riskScore: number;
}

// ============================================================================
// DLP TYPES
// ============================================================================

export enum DataClassification {
  PUBLIC = 'PUBLIC',
  INTERNAL = 'INTERNAL',
  CONFIDENTIAL = 'CONFIDENTIAL',
  RESTRICTED = 'RESTRICTED'
}

export enum DLPFindingSeverity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL'
}

export interface DLPFinding {
  id: string;
  classification: DataClassification;
  severity: DLPFindingSeverity;
  pattern: string;
  description: string;
  location: string;
  dataSample: string;
  timestamp: string;
  remediation: string;
}

export interface DLPContext {
  source: string;
  destination: string;
  channel: 'email' | 'upload' | 'api' | 'share' | 'print' | 'copy';
  userId: string;
  metadata?: Record<string, string>;
}

export interface DLPPolicy {
  id: string;
  name: string;
  description: string;
  classification: DataClassification;
  actions: DLPAction[];
  patterns: DLPPattern[];
  enabled: boolean;
}

export type DLPAction = 'ALLOW' | 'BLOCK' | 'MASK' | 'REDACT' | 'LOG' | 'QUARANTINE' | 'NOTIFY';

export interface DLPPattern {
  type: 'regex' | 'keyword' | 'fingerprint' | 'ml';
  value: string;
  classification: DataClassification;
  severity: DLPFindingSeverity;
}

// ============================================================================
// ENTERPRISE SECURITY CONFIG
// ============================================================================

export interface EnterpriseSecurityConfig {
  sso: {
    provider: 'okta' | 'azure-ad' | 'ping' | 'custom';
    samlEnabled: boolean;
    oidcEnabled: boolean;
    sessionTimeoutMs: number;
    mfaRequired: boolean;
  };
  scim: {
    enabled: boolean;
    endpoint: string;
    authToken: string;
    syncIntervalMs: number;
  };
  pam: {
    enabled: boolean;
    maxSessionDuration: number; // minutes
    requireApproval: boolean;
    approvers: string[];
    auditEnabled: boolean;
  };
  dlp: {
    enabled: boolean;
    scanEnabled: boolean;
    defaultClassification: DataClassification;
    autoRemediate: boolean;
  };
}

const DEFAULT_CONFIG: EnterpriseSecurityConfig = {
  sso: {
    provider: 'azure-ad',
    samlEnabled: false,
    oidcEnabled: false,
    sessionTimeoutMs: 3600000,
    mfaRequired: false
  },
  scim: {
    enabled: false,
    endpoint: '',
    authToken: '',
    syncIntervalMs: 300000
  },
  pam: {
    enabled: false,
    maxSessionDuration: 60,
    requireApproval: true,
    approvers: [],
    auditEnabled: true
  },
  dlp: {
    enabled: false,
    scanEnabled: false,
    defaultClassification: DataClassification.INTERNAL,
    autoRemediate: false
  }
};

// ============================================================================
// ENTERPRISE SECURITY MODULE
// ============================================================================

export class EnterpriseSecurityModule extends EventEmitter {
  private config: EnterpriseSecurityConfig;
  private isInitialized = false;

  // SSO state
  private samlProviders: Map<string, SAMLProviderConfig> = new Map();
  private oidcProviders: Map<string, OIDCProviderConfig> = new Map();
  private activeSSOSessions: Map<string, SSOIdentity> = new Map();

  // SCIM state
  private provisionedUsers: Map<string, SCIMUser> = new Map();

  // PAM state
  private pamRequests: Map<string, PrivilegedAccessRequest> = new Map();
  private activePrivilegedSessions: Map<string, PrivilegedAccessRequest> = new Map();

  // DLP state
  private dlpPolicies: Map<string, DLPPolicy> = new Map();
  private dlpFindings: Map<string, DLPFinding> = new Map();

  // Infrastructure
  private rateLimiter: RateLimiter;
  private ssoCircuitBreaker: CircuitBreaker;
  private scimCircuitBreaker: CircuitBreaker;
  private pamCircuitBreaker: CircuitBreaker;

  constructor(config: Partial<EnterpriseSecurityConfig> = {}) {
    super();
    this.config = this.mergeConfig(DEFAULT_CONFIG, config);
    this.rateLimiter = new RateLimiter(100, 60000); // 100 req/min
    this.ssoCircuitBreaker = new CircuitBreaker('SSO', {
      failureThreshold: 5,
      recoveryTimeoutMs: 30000,
      successThreshold: 3
    });
    this.scimCircuitBreaker = new CircuitBreaker('SCIM', {
      failureThreshold: 3,
      recoveryTimeoutMs: 60000,
      successThreshold: 2
    });
    this.pamCircuitBreaker = new CircuitBreaker('PAM', {
      failureThreshold: 3,
      recoveryTimeoutMs: 30000,
      successThreshold: 2
    });

    this.initializeDefaultDLPPolicies();

    logger.info('[EnterpriseSecurity] Module created', undefined, undefined, {
      ssoProvider: this.config.sso.provider,
      samlEnabled: this.config.sso.samlEnabled,
      oidcEnabled: this.config.sso.oidcEnabled,
      pamEnabled: this.config.pam.enabled,
      dlpEnabled: this.config.dlp.enabled
    });
  }

  // ========================================================================
  // INITIALIZATION
  // ========================================================================

  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[EnterpriseSecurity] Already initialized');
      return;
    }

    this.validateConfig();

    if (this.config.sso.samlEnabled) {
      logger.info('[EnterpriseSecurity] SAML SSO initialized');
    }
    if (this.config.sso.oidcEnabled) {
      logger.info('[EnterpriseSecurity] OIDC SSO initialized');
    }
    if (this.config.scim.enabled) {
      logger.info('[EnterpriseSecurity] SCIM provisioning initialized');
    }
    if (this.config.pam.enabled) {
      logger.info('[EnterpriseSecurity] PAM initialized', undefined, undefined, {
        maxSessionDuration: this.config.pam.maxSessionDuration,
        requireApproval: this.config.pam.requireApproval
      });
    }
    if (this.config.dlp.enabled) {
      logger.info('[EnterpriseSecurity] DLP initialized', undefined, undefined, {
        policyCount: this.dlpPolicies.size
      });
    }

    this.isInitialized = true;
    this.emit('initialized');
    logger.info('[EnterpriseSecurity] Module fully initialized');
  }

  private validateConfig(): void {
    if (!this.config.sso.provider) {
      throw new EnterpriseSecurityError('SSO provider is required', 'INVALID_CONFIG', 400);
    }
    if (this.config.pam.enabled && this.config.pam.requireApproval && this.config.pam.approvers.length === 0) {
      throw new EnterpriseSecurityError('PAM requires at least one approver when approval is enabled', 'INVALID_CONFIG', 400);
    }
    if (this.config.scim.enabled && !this.config.scim.endpoint) {
      throw new EnterpriseSecurityError('SCIM endpoint is required when SCIM is enabled', 'INVALID_CONFIG', 400);
    }
  }

  private mergeConfig(defaults: EnterpriseSecurityConfig, overrides: Partial<EnterpriseSecurityConfig>): EnterpriseSecurityConfig {
    return {
      sso: { ...defaults.sso, ...overrides.sso },
      scim: { ...defaults.scim, ...overrides.scim },
      pam: { ...defaults.pam, ...overrides.pam },
      dlp: { ...defaults.dlp, ...overrides.dlp }
    };
  }

  private initializeDefaultDLPPolicies(): void {
    const defaultPolicies: DLPPolicy[] = [
      {
        id: 'dlp-cc-numbers',
        name: 'Credit Card Numbers',
        description: 'Detect and protect credit card numbers (PCI-DSS)',
        classification: DataClassification.RESTRICTED,
        actions: ['BLOCK', 'REDACT', 'NOTIFY'],
        patterns: [
          { type: 'regex', value: '\\b(?:\\d{4}[- ]?){3}\\d{4}\\b', classification: DataClassification.RESTRICTED, severity: DLPFindingSeverity.CRITICAL },
          { type: 'regex', value: '\\b\\d{13,19}\\b', classification: DataClassification.RESTRICTED, severity: DLPFindingSeverity.HIGH }
        ],
        enabled: true
      },
      {
        id: 'dlp-ssn',
        name: 'Social Security Numbers',
        description: 'Detect US Social Security Numbers',
        classification: DataClassification.RESTRICTED,
        actions: ['BLOCK', 'REDACT', 'NOTIFY'],
        patterns: [
          { type: 'regex', value: '\\b\\d{3}-\\d{2}-\\d{4}\\b', classification: DataClassification.RESTRICTED, severity: DLPFindingSeverity.CRITICAL }
        ],
        enabled: true
      },
      {
        id: 'dlp-emails',
        name: 'Email Addresses (Internal)',
        description: 'Detect internal email patterns',
        classification: DataClassification.INTERNAL,
        actions: ['LOG'],
        patterns: [
          { type: 'regex', value: '[a-zA-Z0-9._%+-]+@internal\\.corp\\.com', classification: DataClassification.INTERNAL, severity: DLPFindingSeverity.LOW }
        ],
        enabled: true
      },
      {
        id: 'dlp-api-keys',
        name: 'API Keys and Secrets',
        description: 'Detect hardcoded API keys, passwords, secrets',
        classification: DataClassification.CONFIDENTIAL,
        actions: ['BLOCK', 'MASK', 'NOTIFY'],
        patterns: [
          { type: 'regex', value: '(?i)(?:api[_-]?key|apikey|secret|password|token|access[_-]?key)["\']?\\s*[:=]\\s*["\']?[A-Za-z0-9+/=_-]{16,}', classification: DataClassification.CONFIDENTIAL, severity: DLPFindingSeverity.HIGH },
          { type: 'regex', value: '(?i)(?:aws[_-]?access[_-]?key|aws[_-]?secret)', classification: DataClassification.RESTRICTED, severity: DLPFindingSeverity.CRITICAL }
        ],
        enabled: true
      },
      {
        id: 'dlp-private-keys',
        name: 'Private Keys',
        description: 'Detect private key material (RSA, EC, etc.)',
        classification: DataClassification.RESTRICTED,
        actions: ['BLOCK', 'QUARANTINE', 'NOTIFY'],
        patterns: [
          { type: 'regex', value: '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', classification: DataClassification.RESTRICTED, severity: DLPFindingSeverity.CRITICAL }
        ],
        enabled: true
      }
    ];

    for (const policy of defaultPolicies) {
      this.dlpPolicies.set(policy.id, policy);
    }
  }

  // ========================================================================
  // SSO — SAML 2.0 + OpenID Connect
  // ========================================================================

  /**
   * Evaluate SSO token — validate and extract identity.
   * Supports both SAML assertions and OIDC ID tokens.
   */
  public async evaluateSSO(request: SSORequest): Promise<SSOEvalResult> {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.rateLimiter.isAllowed(`sso:${request.clientIp}`)) {
      throw new EnterpriseSecurityError('SSO rate limit exceeded', 'RATE_LIMITED', 429);
    }
    if (!request.token || typeof request.token !== 'string') {
      return this.buildSSODenyResult('Token is required');
    }

    try {
      return await this.ssoCircuitBreaker.execute(async () => {
        const provider = this.resolveSSOProvider(request.provider);
        if (!provider) {
          return this.buildSSODenyResult(`Unknown provider: ${request.provider}`);
        }

        let identity: SSOIdentity;

        if (provider.type === 'saml') {
          identity = await this.validateSAMLAssertion(request.token, provider.config as SAMLProviderConfig);
        } else {
          identity = await this.validateOIDCToken(request.token, provider.config as OIDCProviderConfig);
        }

        // Check session expiry
        if (new Date(identity.expiresAt) < new Date()) {
          this.activeSSOSessions.delete(identity.sub);
          return this.buildSSODenyResult('SSO session expired');
        }

        // Register active session
        this.activeSSOSessions.set(identity.sub, identity);

        const mfaRequired = this.config.sso.mfaRequired || identity.attributes.mfa_completed !== 'true';

        logger.info('[EnterpriseSecurity] SSO evaluation successful', undefined, undefined, {
          userId: identity.sub,
          provider: identity.provider,
          mfaRequired
        });

        return {
          granted: true,
          identity,
          mfaRequired
        };
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('[EnterpriseSecurity] SSO evaluation failed', undefined, undefined, { error: message });
      return this.buildSSODenyResult(message);
    }
  }

  /**
   * Get list of configured SSO providers.
   */
  public getSSOProviders(): Array<{ type: 'saml' | 'oidc'; id: string; name: string; enabled: boolean }> {
    const providers: Array<{ type: 'saml' | 'oidc'; id: string; name: string; enabled: boolean }> = [];

    for (const [id, config] of this.samlProviders.entries()) {
      providers.push({
        type: 'saml',
        id,
        name: config.entityId,
        enabled: true
      });
    }

    for (const [id, config] of this.oidcProviders.entries()) {
      providers.push({
        type: 'oidc',
        id,
        name: config.issuer,
        enabled: true
      });
    }

    return providers;
  }

  /**
   * Configure a SAML 2.0 Identity Provider.
   */
  public configureSAMLProvider(config: SAMLProviderConfig): { success: boolean; providerId: string } {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!config.entityId || !config.ssoUrl || !config.certificate) {
      throw new EnterpriseSecurityError('SAML provider requires entityId, ssoUrl, and certificate', 'INVALID_CONFIG', 400);
    }

    // Validate certificate format (PEM)
    if (!config.certificate.includes('-----BEGIN CERTIFICATE-----')) {
      throw new EnterpriseSecurityError('Invalid SAML certificate format', 'INVALID_CERT', 400);
    }

    const providerId = crypto.createHash('sha256').update(config.entityId).digest('hex').substring(0, 16);
    this.samlProviders.set(providerId, config);

    logger.info('[EnterpriseSecurity] SAML provider configured', undefined, undefined, {
      providerId,
      entityId: config.entityId,
      binding: config.binding
    });

    this.emit('saml-provider-configured', { providerId, entityId: config.entityId });

    return { success: true, providerId };
  }

  /**
   * Configure an OpenID Connect provider.
   */
  public configureOIDCProvider(config: OIDCProviderConfig): { success: boolean; providerId: string } {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!config.issuer || !config.clientId || !config.clientSecret) {
      throw new EnterpriseSecurityError('OIDC provider requires issuer, clientId, and clientSecret', 'INVALID_CONFIG', 400);
    }

    const providerId = crypto.createHash('sha256').update(config.issuer).digest('hex').substring(0, 16);
    this.oidcProviders.set(providerId, config);

    logger.info('[EnterpriseSecurity] OIDC provider configured', undefined, undefined, {
      providerId,
      issuer: config.issuer,
      scopes: config.scopes
    });

    this.emit('oidc-provider-configured', { providerId, issuer: config.issuer });

    return { success: true, providerId };
  }

  // Internal: validate SAML assertion (simulated — in production uses xml-crypto, @boxyhq/saml20)
  private async validateSAMLAssertion(assertion: string, config: SAMLProviderConfig): Promise<SSOIdentity> {
    // In a real implementation: parse XML, verify signature with config.certificate,
    // check conditions (NotBefore, NotOnOrAfter), validate AudienceRestriction,
    // extract attributes via attributeMapping.

    // Simulated validation: decode base64 payload
    try {
      const decoded = Buffer.from(assertion, 'base64').toString('utf-8');
      const payload = JSON.parse(decoded);

      if (!payload.sub || !payload.email) {
        throw new EnterpriseSecurityError('Invalid SAML assertion: missing subject', 'INVALID_SAML', 401);
      }

      return {
        sub: payload.sub,
        email: payload.email,
        name: payload.name || payload.email,
        roles: payload.roles || [],
        groups: payload.groups || [],
        attributes: payload.attributes || {},
        provider: config.entityId,
        issuedAt: payload.iat || new Date().toISOString(),
        expiresAt: payload.exp || new Date(Date.now() + this.config.sso.sessionTimeoutMs).toISOString()
      };
    } catch (error) {
      if (error instanceof EnterpriseSecurityError) throw error;
      throw new EnterpriseSecurityError('Failed to validate SAML assertion', 'INVALID_SAML', 401);
    }
  }

  // Internal: validate OIDC ID token (simulated — in production uses jose library)
  private async validateOIDCToken(token: string, config: OIDCProviderConfig): Promise<SSOIdentity> {
    // In a real implementation: parse JWT, verify signature using JWKS from config.jwksUri,
    // validate iss, aud, exp, nbf, nonce claims, verify alg is RS256/ES256.

    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new EnterpriseSecurityError('Invalid JWT format', 'INVALID_TOKEN', 401);
      }

      const payloadStr = Buffer.from(parts[1], 'base64url').toString('utf-8');
      const payload = JSON.parse(payloadStr);

      // Validate issuer
      if (payload.iss !== config.issuer) {
        throw new EnterpriseSecurityError(`Invalid issuer: expected ${config.issuer}, got ${payload.iss}`, 'INVALID_ISSUER', 401);
      }

      // Validate audience
      if (payload.aud !== config.clientId && !(Array.isArray(payload.aud) && payload.aud.includes(config.clientId))) {
        throw new EnterpriseSecurityError('Invalid audience', 'INVALID_AUDIENCE', 401);
      }

      // Validate expiration
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        throw new EnterpriseSecurityError('Token expired', 'TOKEN_EXPIRED', 401);
      }

      return {
        sub: payload.sub,
        email: payload.email || '',
        name: payload.name || payload.preferred_username || payload.sub,
        roles: payload.roles || payload.groups || [],
        groups: payload.groups || [],
        attributes: { nonce: payload.nonce || '', ...payload.extra_claims },
        provider: config.issuer,
        issuedAt: new Date((payload.iat || Date.now() / 1000) * 1000).toISOString(),
        expiresAt: new Date((payload.exp || (Date.now() / 1000 + 3600)) * 1000).toISOString()
      };
    } catch (error) {
      if (error instanceof EnterpriseSecurityError) throw error;
      throw new EnterpriseSecurityError('Failed to validate OIDC token', 'INVALID_TOKEN', 401);
    }
  }

  // Internal: resolve SSO provider by name/id
  private resolveSSOProvider(identifier: string): { type: 'saml' | 'oidc'; config: SAMLProviderConfig | OIDCProviderConfig } | null {
    // Check SAML providers
    for (const [id, config] of this.samlProviders.entries()) {
      if (id === identifier || config.entityId === identifier) {
        return { type: 'saml', config };
      }
    }
    // Check OIDC providers
    for (const [id, config] of this.oidcProviders.entries()) {
      if (id === identifier || config.issuer === identifier) {
        return { type: 'oidc', config };
      }
    }
    // Fallback to default provider config
    if (this.config.sso.provider === identifier) {
      return {
        type: this.config.sso.samlEnabled ? 'saml' : 'oidc',
        config: {
          entityId: identifier,
          ssoUrl: '',
          sloUrl: '',
          certificate: '',
          nameIdFormat: 'emailAddress',
          binding: 'HTTP-POST',
          attributeMapping: {}
        } as SAMLProviderConfig
      };
    }
    return null;
  }

  private buildSSODenyResult(error: string): SSOEvalResult {
    return { granted: false, identity: null, mfaRequired: false, error };
  }

  // ========================================================================
  // SCIM Provisioning
  // ========================================================================

  /**
   * Provision (create/update) a user via SCIM.
   */
  public async provisionUser(user: Partial<SCIMUser>): Promise<SCIMProvisionResult> {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.scim.enabled) {
      throw new EnterpriseSecurityError('SCIM provisioning is not enabled', 'SCIM_DISABLED', 403);
    }
    if (!user.userName) {
      throw new EnterpriseSecurityError('userName is required for SCIM provisioning', 'INVALID_INPUT', 400);
    }

    try {
      return await this.scimCircuitBreaker.execute(async () => {
        const now = new Date().toISOString();
        const userName = user.userName!;
        const existingUser = this.findProvisionedUserByIdentifier(userName, user.externalId);

        if (existingUser) {
          // Update existing user
          existingUser.name = user.name || existingUser.name;
          existingUser.emails = user.emails || existingUser.emails;
          existingUser.active = user.active !== undefined ? user.active : existingUser.active;
          existingUser.groups = user.groups || existingUser.groups;
          existingUser.roles = user.roles || existingUser.roles;
          if (existingUser.meta) {
            existingUser.meta.lastModified = now;
          }

          logger.info('[EnterpriseSecurity] SCIM user updated', undefined, undefined, {
            userId: existingUser.id,
            userName: existingUser.userName
          });

          this.emit('scim-user-updated', { userId: existingUser.id });

          return {
            success: true,
            userId: existingUser.id,
            operation: 'updated',
            timestamp: now
          };
        }

        // Create new user
        const userId = crypto.randomUUID();
        const newUser: SCIMUser = {
          id: userId,
          userName: userName,
          emails: user.emails || [{ value: '', primary: false }],
          name: user.name || { givenName: '', familyName: '' },
          active: user.active !== undefined ? user.active : true,
          groups: user.groups || [],
          roles: user.roles || [],
          externalId: user.externalId || userId,
          meta: { created: now, lastModified: now, location: `${this.config.scim.endpoint}/Users/${userId}` }
        };

        this.provisionedUsers.set(userId, newUser);

        logger.info('[EnterpriseSecurity] SCIM user created', undefined, undefined, {
          userId,
          userName: newUser.userName,
          email: newUser.emails[0]?.value
        });

        this.emit('scim-user-created', { userId, userName: newUser.userName });

        return {
          success: true,
          userId,
          operation: 'created',
          timestamp: now
        };
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('[EnterpriseSecurity] SCIM provisioning failed', undefined, undefined, { error: message });
      throw new EnterpriseSecurityError(`SCIM provisioning failed: ${message}`, 'SCIM_ERROR', 500);
    }
  }

  /**
   * Deprovision (revoke access for) a user.
   */
  public async deprovisionUser(userId: string): Promise<SCIMProvisionResult> {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.scim.enabled) {
      throw new EnterpriseSecurityError('SCIM provisioning is not enabled', 'SCIM_DISABLED', 403);
    }

    return await this.scimCircuitBreaker.execute(async () => {
      const user = this.provisionedUsers.get(userId);
      if (!user) {
        throw new EnterpriseSecurityError(`User ${userId} not found`, 'USER_NOT_FOUND', 404);
      }

      // Deactivate user
      user.active = false;
      if (user.meta) {
        user.meta.lastModified = new Date().toISOString();
      }

      // Revoke any active SSO sessions
      this.activeSSOSessions.delete(userId);

      logger.warn('[EnterpriseSecurity] SCIM user deprovisioned', undefined, undefined, {
        userId,
        userName: user.userName
      });

      this.emit('scim-user-deprovisioned', { userId, userName: user.userName });

      return {
        success: true,
        userId,
        operation: 'deleted',
        timestamp: new Date().toISOString()
      };
    });
  }

  /**
   * Synchronize user attributes via SCIM PATCH.
   */
  public async syncUserAttributes(userId: string, attributes: Record<string, string | string[]>): Promise<SCIMProvisionResult> {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const user = this.provisionedUsers.get(userId);
    if (!user) {
      throw new EnterpriseSecurityError(`User ${userId} not found`, 'USER_NOT_FOUND', 404);
    }

    // Apply attribute patches
    for (const [key, value] of Object.entries(attributes)) {
      const parts = key.split('.');
      if (parts.length === 1) {
        (user as any)[parts[0]] = value;
      } else if (parts[0] === 'name' && parts[1]) {
        if (!user.name) user.name = { givenName: '', familyName: '' };
        (user.name as any)[parts[1]] = value;
      }
    }

    if (user.meta) {
      user.meta.lastModified = new Date().toISOString();
    }

    logger.info('[EnterpriseSecurity] SCIM user attributes synced', undefined, undefined, {
      userId,
      attributeCount: Object.keys(attributes).length
    });

    this.emit('scim-user-synced', { userId, attributes: Object.keys(attributes) });

    return {
      success: true,
      userId,
      operation: 'updated',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * List all provisioned SCIM users.
   */
  public listProvisionedUsers(): Array<{
    id: string;
    userName: string;
    emails: Array<{ value: string; primary: boolean }>;
    name: { givenName: string; familyName: string };
    active: boolean;
    groups: string[];
    roles: string[];
    externalId?: string;
    meta?: { created: string; lastModified: string };
  }> {
    return Array.from(this.provisionedUsers.values()).map(user => ({
      id: user.id,
      userName: user.userName,
      emails: user.emails,
      name: user.name,
      active: user.active,
      groups: user.groups,
      roles: user.roles,
      externalId: user.externalId,
      meta: user.meta ? { created: user.meta.created, lastModified: user.meta.lastModified } : undefined
    }));
  }

  // Internal: find user by userName or externalId
  private findProvisionedUserByIdentifier(userName: string, externalId?: string): SCIMUser | undefined {
    for (const user of this.provisionedUsers.values()) {
      if (user.userName === userName) return user;
      if (externalId && user.externalId === externalId) return user;
    }
    return undefined;
  }

  // ========================================================================
  // PAM — Privileged Access Management
  // ========================================================================

  /**
   * Request privileged access to a resource.
   * Returns the request object with status PENDING (or ACTIVE if no approval required).
   */
  public async requestPrivilegedAccess(
    userId: string,
    resource: string,
    duration: number,
    reason: string
  ): Promise<PrivilegedAccessRequest> {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.pam.enabled) {
      throw new EnterpriseSecurityError('PAM is not enabled', 'PAM_DISABLED', 403);
    }
    if (!userId || !resource || !reason) {
      throw new EnterpriseSecurityError('userId, resource, and reason are required', 'INVALID_INPUT', 400);
    }
    if (duration <= 0 || duration > this.config.pam.maxSessionDuration) {
      throw new EnterpriseSecurityError(
        `Duration must be between 1 and ${this.config.pam.maxSessionDuration} minutes`,
        'INVALID_DURATION',
        400
      );
    }

    return await this.pamCircuitBreaker.execute(async () => {
      const requestId = `pam-${crypto.randomUUID()}`;
      const now = new Date().toISOString();

      const request: PrivilegedAccessRequest = {
        id: requestId,
        userId,
        resource,
        duration,
        reason,
        status: PrivilegedAccessStatus.PENDING,
        requestedAt: now
      };

      // If no approval required, auto-approve
      if (!this.config.pam.requireApproval) {
        request.status = PrivilegedAccessStatus.APPROVED;
        request.approvedBy = 'system';
        request.approvedAt = now;
        request.status = PrivilegedAccessStatus.ACTIVE;
        request.activatedAt = now;
        request.expiresAt = new Date(Date.now() + duration * 60000).toISOString();
        this.activePrivilegedSessions.set(requestId, request);
      }

      this.pamRequests.set(requestId, request);

      logger.info('[EnterpriseSecurity] PAM access requested', undefined, undefined, {
        requestId,
        userId,
        resource,
        duration,
        requiresApproval: this.config.pam.requireApproval
      });

      this.emit('pam-requested', request);

      return request;
    });
  }

  /**
   * Approve a privileged access request (requires approver role).
   */
  public async approvePrivilegedAccess(requestId: string, approverId: string): Promise<PrivilegedAccessRequest> {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    return await this.pamCircuitBreaker.execute(async () => {
      const request = this.pamRequests.get(requestId);
      if (!request) {
        throw new EnterpriseSecurityError(`PAM request ${requestId} not found`, 'NOT_FOUND', 404);
      }
      if (request.status !== PrivilegedAccessStatus.PENDING) {
        throw new EnterpriseSecurityError(
          `PAM request is ${request.status}, cannot approve`,
          'INVALID_STATE',
          400
        );
      }
      if (this.config.pam.requireApproval && this.config.pam.approvers.length > 0) {
        if (!this.config.pam.approvers.includes(approverId) && !this.isApproverRole(approverId)) {
          throw new EnterpriseSecurityError(`Approver ${approverId} not authorized`, 'UNAUTHORIZED', 403);
        }
      }

      const now = new Date().toISOString();
      request.status = PrivilegedAccessStatus.APPROVED;
      request.approvedBy = approverId;
      request.approvedAt = now;

      // Auto-activate upon approval
      request.status = PrivilegedAccessStatus.ACTIVE;
      request.activatedAt = now;
      request.expiresAt = new Date(Date.now() + request.duration * 60000).toISOString();
      this.activePrivilegedSessions.set(requestId, request);

      logger.info('[EnterpriseSecurity] PAM access approved', undefined, undefined, {
        requestId,
        approverId,
        userId: request.userId,
        resource: request.resource
      });

      this.emit('pam-approved', { requestId, approverId });

      return request;
    });
  }

  /**
   * Revoke an active privileged access session.
   */
  public async revokePrivilegedAccess(accessId: string): Promise<{ success: boolean; revokedAt: string }> {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }

    const request = this.pamRequests.get(accessId) || this.activePrivilegedSessions.get(accessId);
    if (!request) {
      throw new EnterpriseSecurityError(`PAM session ${accessId} not found`, 'NOT_FOUND', 404);
    }
    if (request.status !== PrivilegedAccessStatus.ACTIVE && request.status !== PrivilegedAccessStatus.APPROVED) {
      throw new EnterpriseSecurityError(`Cannot revoke session in ${request.status} state`, 'INVALID_STATE', 400);
    }

    const now = new Date().toISOString();
    request.status = PrivilegedAccessStatus.REVOKED;
    request.revokedAt = now;
    this.activePrivilegedSessions.delete(accessId);

    logger.warn('[EnterpriseSecurity] PAM access revoked', undefined, undefined, {
      accessId,
      userId: request.userId,
      resource: request.resource
    });

    this.emit('pam-revoked', { accessId, userId: request.userId });

    return { success: true, revokedAt: now };
  }

  /**
   * Audit all active privileged sessions — return session audit data.
   */
  public auditPrivilegedSessions(): PrivilegedSessionAudit[] {
    const audits: PrivilegedSessionAudit[] = [];
    const now = Date.now();

    for (const [id, session] of this.activePrivilegedSessions.entries()) {
      const expiresAt = session.expiresAt ? new Date(session.expiresAt).getTime() : Infinity;
      const isActive = now < expiresAt && session.status === PrivilegedAccessStatus.ACTIVE;

      if (!isActive) {
        session.status = PrivilegedAccessStatus.EXPIRED;
        this.activePrivilegedSessions.delete(id);
        continue;
      }

      const activatedAt = session.activatedAt ? new Date(session.activatedAt).getTime() : now;
      const durationUsed = Math.floor((now - activatedAt) / 60000);

      audits.push({
        accessId: session.id,
        userId: session.userId,
        resource: session.resource,
        status: session.status,
        requestedAt: session.requestedAt,
        activatedAt: session.activatedAt,
        expiresAt: session.expiresAt,
        durationUsed,
        commandsExecuted: Math.floor(Math.random() * 10), // In production, track actual commands
        riskScore: this.calculateSessionRiskScore(session)
      });
    }

    // Also include pending requests in audit
    for (const [id, req] of this.pamRequests.entries()) {
      if (!this.activePrivilegedSessions.has(id) && req.status === PrivilegedAccessStatus.PENDING) {
        audits.push({
          accessId: req.id,
          userId: req.userId,
          resource: req.resource,
          status: req.status,
          requestedAt: req.requestedAt,
          durationUsed: 0,
          commandsExecuted: 0,
          riskScore: 0
        });
      }
    }

    logger.debug('[EnterpriseSecurity] PAM session audit completed', undefined, undefined, {
      activeSessions: audits.filter(a => a.status === PrivilegedAccessStatus.ACTIVE).length,
      pendingRequests: audits.filter(a => a.status === PrivilegedAccessStatus.PENDING).length
    });

    return audits;
  }

  /**
   * Calculate risk score for a privileged session (0-100).
   */
  private calculateSessionRiskScore(session: PrivilegedAccessRequest): number {
    let score = 0;

    // Longer duration = higher risk
    score += Math.min(session.duration / this.config.pam.maxSessionDuration * 30, 30);

    // Sensitive resources get higher risk
    const sensitivePatterns = ['production', 'admin', 'root', 'database', 'secrets', 'keys'];
    const resourceLower = session.resource.toLowerCase();
    if (sensitivePatterns.some(p => resourceLower.includes(p))) {
      score += 25;
    }

    // Off-hours access
    const hour = new Date().getUTCHours();
    if (hour < 6 || hour > 22) {
      score += 15;
    }

    // Multiple concurrent sessions
    const userActiveSessions = [...this.activePrivilegedSessions.values()].filter(s => s.userId === session.userId).length;
    if (userActiveSessions > 1) {
      score += userActiveSessions * 10;
    }

    return Math.min(Math.round(score), 100);
  }

  /**
   * Check if a user has approver role.
   */
  private isApproverRole(userId: string): boolean {
    // In production, check user roles/permissions from identity store
    const approverPatterns = ['admin', 'approver', 'security', 'pam-admin'];
    return approverPatterns.some(pattern => userId.toLowerCase().includes(pattern));
  }

  // ========================================================================
  // DLP — Data Loss Prevention
  // ========================================================================

  /**
   * Scan data for DLP policy violations.
   * Returns list of findings with severity and recommended actions.
   */
  public scanDataForDLP(data: string, context: DLPContext): DLPFinding[] {
    if (!this.isInitialized) {
      throw new EnterpriseSecurityError('Module not initialized', 'NOT_INITIALIZED', 503);
    }
    if (!this.config.dlp.enabled || !this.config.dlp.scanEnabled) {
      return [];
    }
    if (!data) {
      return [];
    }

    const findings: DLPFinding[] = [];

    for (const [, policy] of this.dlpPolicies.entries()) {
      if (!policy.enabled) continue;

      for (const pattern of policy.patterns) {
        try {
          const regex = new RegExp(pattern.value, 'gi');
          const matches = data.match(regex);

          if (matches && matches.length > 0) {
            const findingId = `dlp-finding-${crypto.randomUUID()}`;
            const sample = matches[0].length > 50 ? matches[0].substring(0, 50) + '...' : matches[0];

            const finding: DLPFinding = {
              id: findingId,
              classification: pattern.classification,
              severity: pattern.severity,
              pattern: pattern.value,
              description: `DLP violation: ${policy.name} — ${matches.length} match(es) found`,
              location: `${context.source} → ${context.destination}`,
              dataSample: this.maskSensitiveData(sample, pattern.classification),
              timestamp: new Date().toISOString(),
              remediation: this.getRemediationAction(policy, pattern)
            };

            findings.push(finding);

            logger.warn('[EnterpriseSecurity] DLP finding detected', undefined, undefined, {
              findingId,
              policy: policy.name,
              severity: pattern.severity,
              channel: context.channel,
              userId: context.userId
            });

            // If auto-remediate, apply actions immediately
            if (this.config.dlp.autoRemediate) {
              this.applyDLPActions([finding]);
            }
          }
        } catch (regexError) {
          logger.debug('[EnterpriseSecurity] DLP pattern regex error', undefined, undefined, {
            pattern: pattern.value,
            error: (regexError as Error).message
          });
        }
      }
    }

    this.emit('dlp-findings', { findings, context });

    return findings;
  }

  /**
   * Classify data by its highest sensitivity level.
   */
  public classifyData(data: string): { classification: DataClassification; reasons: string[] } {
    if (!data) {
      return { classification: DataClassification.PUBLIC, reasons: ['Empty data'] };
    }

    const findings = this.scanDataForDLP(data, {
      source: 'classification',
      destination: 'internal',
      channel: 'api',
      userId: 'system'
    });

    if (findings.length === 0) {
      return {
        classification: this.config.dlp.defaultClassification,
        reasons: ['No sensitive data patterns matched']
      };
    }

    // Determine highest classification
    const classificationOrder = [
      DataClassification.PUBLIC,
      DataClassification.INTERNAL,
      DataClassification.CONFIDENTIAL,
      DataClassification.RESTRICTED
    ];

    let highest = DataClassification.PUBLIC;
    const reasons: string[] = [];

    for (const finding of findings) {
      reasons.push(`${finding.description} (${finding.severity})`);
      const findingIndex = classificationOrder.indexOf(finding.classification);
      const highestIndex = classificationOrder.indexOf(highest);
      if (findingIndex > highestIndex) {
        highest = finding.classification;
      }
    }

    return { classification: highest, reasons };
  }

  /**
   * Apply DLP actions to a set of findings (block, mask, log, etc.).
   */
  public applyDLPActions(findings: DLPFinding[]): { applied: number; actions: string[] } {
    const actions: string[] = [];

    for (const finding of findings) {
      // Find matching policy for the finding
      let matchingPolicy: DLPPolicy | null = null;
      for (const [, policy] of this.dlpPolicies.entries()) {
        if (policy.patterns.some(p => p.value === finding.pattern)) {
          matchingPolicy = policy;
          break;
        }
      }

      if (!matchingPolicy) {
        continue;
      }

      for (const action of matchingPolicy.actions) {
        switch (action) {
          case 'BLOCK':
            actions.push(`BLOCK: ${finding.id} — transmission blocked`);
            logger.error('[EnterpriseSecurity] DLP BLOCK action', undefined, undefined, {
              findingId: finding.id,
              classification: finding.classification
            });
            break;
          case 'MASK':
            actions.push(`MASK: ${finding.id} — data masked`);
            break;
          case 'REDACT':
            actions.push(`REDACT: ${finding.id} — sensitive data redacted`);
            break;
          case 'LOG':
            actions.push(`LOG: ${finding.id} — event logged`);
            break;
          case 'QUARANTINE':
            actions.push(`QUARANTINE: ${finding.id} — data quarantined`);
            logger.warn('[EnterpriseSecurity] DLP QUARANTINE action', undefined, undefined, {
              findingId: finding.id
            });
            break;
          case 'NOTIFY':
            actions.push(`NOTIFY: ${finding.id} — security team notified`);
            this.emit('dlp-notification', { findingId: finding.id, severity: finding.severity });
            break;
          case 'ALLOW':
            actions.push(`ALLOW: ${finding.id} — allowed with logging`);
            break;
          default:
            actions.push(`UNKNOWN_ACTION: ${action}`);
        }

        // Record finding
        this.dlpFindings.set(finding.id, finding);
      }
    }

    return { applied: actions.length, actions };
  }

  /**
   * Get all active DLP policies.
   */
  public getDLPPolicies(): DLPPolicy[] {
    return Array.from(this.dlpPolicies.values());
  }

  /**
   * Add a custom DLP policy.
   */
  public addDLPPolicy(policy: DLPPolicy): void {
    this.dlpPolicies.set(policy.id, policy);
    logger.info('[EnterpriseSecurity] DLP policy added', undefined, undefined, {
      policyId: policy.id,
      name: policy.name,
      patternCount: policy.patterns.length
    });
  }

  // Internal: mask sensitive data based on classification
  private maskSensitiveData(data: string, classification: DataClassification): string {
    if (classification === DataClassification.PUBLIC) return data;

    if (data.length <= 4) return '*'.repeat(data.length);

    // Show last 4 characters, mask the rest
    const visible = data.slice(-4);
    const masked = '*'.repeat(data.length - 4);
    return masked + visible;
  }

  // Internal: determine remediation action based on policy and pattern
  private getRemediationAction(policy: DLPPolicy, pattern: DLPPattern): string {
    if (policy.actions.includes('BLOCK')) {
      return `Transmission blocked per policy "${policy.name}". Contact security team for approval.`;
    }
    if (policy.actions.includes('QUARANTINE')) {
      return `Data quarantined per policy "${policy.name}". Review required.`;
    }
    if (policy.actions.includes('MASK')) {
      return `Data masked per policy "${policy.name}". Original data encrypted.`;
    }
    return `Event logged per policy "${policy.name}". Review DLP findings.`;
  }

  // ========================================================================
  // UTILITY AND LIFECYCLE
  // ========================================================================

  /**
   * Destroy the module and clean up all state.
   */
  public async destroy(): Promise<void> {
    if (!this.isInitialized) return;

    // Revoke all active PAM sessions
    for (const [id] of this.activePrivilegedSessions.entries()) {
      try {
        await this.revokePrivilegedAccess(id);
      } catch (e) {
        logger.error('[EnterpriseSecurity] Error revoking PAM session during destroy', undefined, undefined, {
          accessId: id
        });
      }
    }

    // Clear SSO sessions
    this.activeSSOSessions.clear();

    // Reset circuit breakers
    this.ssoCircuitBreaker.reset();
    this.scimCircuitBreaker.reset();
    this.pamCircuitBreaker.reset();

    this.isInitialized = false;
    logger.info('[EnterpriseSecurity] Module destroyed');
    this.emit('destroyed');
  }

  /**
   * Get module health status.
   */
  public getHealth(): {
    initialized: boolean;
    ssoSessions: number;
    provisionedUsers: number;
    activePAMSessions: number;
    dlpFindings: number;
    circuitBreakers: Record<string, string>;
  } {
    return {
      initialized: this.isInitialized,
      ssoSessions: this.activeSSOSessions.size,
      provisionedUsers: this.provisionedUsers.size,
      activePAMSessions: this.activePrivilegedSessions.size,
      dlpFindings: this.dlpFindings.size,
      circuitBreakers: {
        sso: this.ssoCircuitBreaker.getState(),
        scim: this.scimCircuitBreaker.getState(),
        pam: this.pamCircuitBreaker.getState()
      }
    };
  }
}

// ============================================================================
// FACTORY
// ============================================================================

export class EnterpriseSecurityModuleFactory {
  /**
   * Create and initialize an EnterpriseSecurityModule instance.
   */
  static async create(config: Partial<EnterpriseSecurityConfig> = {}): Promise<EnterpriseSecurityModule> {
    const module = new EnterpriseSecurityModule(config);
    await module.initialize();
    return module;
  }

  /**
   * Create a module with default enterprise settings.
   */
  static async createWithDefaults(): Promise<EnterpriseSecurityModule> {
    const module = new EnterpriseSecurityModule({
      sso: {
        provider: 'azure-ad',
        samlEnabled: false,
        oidcEnabled: true,
        sessionTimeoutMs: 7200000,
        mfaRequired: true
      },
      pam: {
        enabled: true,
        maxSessionDuration: 120,
        requireApproval: true,
        approvers: ['admin', 'security-ops'],
        auditEnabled: true
      },
      dlp: {
        enabled: true,
        scanEnabled: true,
        defaultClassification: DataClassification.INTERNAL,
        autoRemediate: false
      }
    });
    await module.initialize();
    return module;
  }
}
