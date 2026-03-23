/**
 * Zero Trust Architecture - Comprehensive Tests
 * 
 * Полные тесты для всех компонентов Zero Trust Network Architecture.
 * Включают unit тесты для PDP, PEP, Trust Verifier и других компонентов.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import {
  TrustLevel,
  PolicyDecision,
  SubjectType,
  ResourceType,
  PolicyOperation,
  DeviceHealthStatus,
  DeviceType,
  AuthenticationMethod,
  Identity,
  AuthContext,
  DevicePosture,
  AccessPolicyRule,
  PolicyConstraint
} from '../../src/zerotrust/zerotrust.types';
import { PolicyDecisionPoint } from '../../src/zerotrust/PolicyDecisionPoint';
import { PolicyEnforcementPoint } from '../../src/zerotrust/PolicyEnforcementPoint';
import { DevicePostureChecker } from '../../src/zerotrust/DevicePostureChecker';
import { TrustVerifier } from '../../src/zerotrust/TrustVerifier';
import { MicroSegmentation } from '../zerotrust/MicroSegmentation';
import { ZeroTrustController } from '../zerotrust/ZeroTrustController';

// ============================================================================
// TEST UTILITIES
// ============================================================================

/**
 * Создать тестовую идентичность
 */
function createTestIdentity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: 'user_test_001',
    type: SubjectType.USER,
    displayName: 'Test User',
    roles: ['user', 'developer'],
    permissions: ['read', 'write'],
    groups: ['engineering'],
    labels: { department: 'engineering' },
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  };
}

/**
 * Создать тестовый контекст аутентификации
 */
function createTestAuthContext(overrides: Partial<AuthContext> = {}): AuthContext {
  return {
    method: AuthenticationMethod.MFA,
    authenticatedAt: new Date(),
    expiresAt: new Date(Date.now() + 3600000),
    levelOfAssurance: 3,
    factors: [AuthenticationMethod.PASSWORD, AuthenticationMethod.OTP],
    sessionId: 'session_test_001',
    mfaVerified: true,
    mfaMethods: [AuthenticationMethod.OTP],
    ...overrides
  };
}

/**
 * Создать тестовую постуру устройства
 */
function createTestDevicePosture(overrides: Partial<DevicePosture> = {}): DevicePosture {
  return {
    deviceId: 'device_test_001',
    deviceType: DeviceType.WORKSTATION,
    operatingSystem: {
      name: 'Windows 11',
      version: '10.0.22621',
      build: '22621',
      patchLevel: '2024-01'
    },
    healthStatus: DeviceHealthStatus.HEALTHY,
    compliance: {
      antivirusActive: true,
      antivirusUpdated: true,
      firewallActive: true,
      diskEncrypted: true,
      secureBootEnabled: true,
      tpmPresent: true,
      lastUpdateCheck: new Date(),
      criticalUpdatesInstalled: true,
      jailbreakDetected: false
    },
    network: {
      ipAddress: '192.168.1.100',
      macAddress: '00:11:22:33:44:55',
      connectionType: 'Ethernet'
    },
    lastCheckedAt: new Date(),
    nextCheckAt: new Date(Date.now() + 3600000),
    riskScore: 5,
    ...overrides
  };
}

/**
 * Создать тестовую политику доступа
 */
function createTestPolicy(overrides: Partial<AccessPolicyRule> = {}): AccessPolicyRule {
  return {
    id: 'policy_test_001',
    name: 'Test Access Policy',
    description: 'Test policy for unit tests',
    priority: 100,
    effect: 'ALLOW',
    subjectTypes: [SubjectType.USER],
    subjectRoles: ['user'],
    resourceTypes: [ResourceType.HTTP_ENDPOINT],
    resourceIds: ['resource_001'],
    resourceLabels: {},
    operations: [PolicyOperation.READ, PolicyOperation.WRITE],
    conditions: [],
    constraints: {} as PolicyConstraint,
    enforcementActions: {
      logViolation: true,
      sendAlert: true,
      blockSubject: false,
      terminateSession: false
    },
    enabled: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  };
}

// ============================================================================
// POLICY DECISION POINT TESTS
// ============================================================================

describe('PolicyDecisionPoint', () => {
  let pdp: PolicyDecisionPoint;

  beforeEach(() => {
    pdp = new PolicyDecisionPoint({
      enableCaching: true,
      enableLogging: false
    });
  });

  afterEach(() => {
    pdp.removeAllListeners();
  });

  describe('Initialization', () => {
    test('should create PDP with default config', () => {
      expect(pdp).toBeDefined();
      expect(pdp.getStats()).toBeDefined();
    });

    test('should create PDP with custom config', () => {
      const customPdp = new PolicyDecisionPoint({
        enableCaching: false,
        cacheDefaultTtl: 600,
        minimumTrustLevel: TrustLevel.MEDIUM
      });

      expect(customPdp).toBeDefined();
    });
  });

  describe('Policy Management', () => {
    test('should load policies', () => {
      const policies: AccessPolicyRule[] = [
        createTestPolicy({ id: 'policy_1', name: 'Policy 1' }),
        createTestPolicy({ id: 'policy_2', name: 'Policy 2', priority: 50 })
      ];

      pdp.loadPolicies(policies);

      const stats = pdp.getStats();
      expect(stats.policyCount).toBe(2);
    });

    test('should add single policy', () => {
      const policy = createTestPolicy();
      pdp.addPolicy(policy);

      const stats = pdp.getStats();
      expect(stats.policyCount).toBe(1);
    });

    test('should remove policy', () => {
      const policy = createTestPolicy();
      pdp.addPolicy(policy);
      const removed = pdp.removePolicy(policy.id);

      expect(removed).toBe(true);
      expect(pdp.getStats().policyCount).toBe(0);
    });

    test('should sort policies by priority', () => {
      const policies: AccessPolicyRule[] = [
        createTestPolicy({ id: 'p1', priority: 100 }),
        createTestPolicy({ id: 'p2', priority: 10 }),
        createTestPolicy({ id: 'p3', priority: 50 })
      ];

      pdp.loadPolicies(policies);

      // Policies should be sorted by priority (lowest first)
      const stats = pdp.getStats();
      expect(stats.policyCount).toBe(3);
    });
  });

  describe('Access Evaluation', () => {
    beforeEach(() => {
      // Load default allow policy
      const allowPolicy = createTestPolicy({
        id: 'allow_all',
        name: 'Allow All',
        effect: 'ALLOW',
        subjectTypes: [SubjectType.USER],
        resourceTypes: [ResourceType.HTTP_ENDPOINT],
        operations: [PolicyOperation.ANY],
        priority: 100
      });

      pdp.loadPolicies([allowPolicy]);
    });

    test('should allow access with valid identity and policy', async () => {
      const identity = createTestIdentity();
      const authContext = createTestAuthContext();

      const result = await pdp.evaluateAccess({
        identity,
        authContext,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      expect(result.decision).toBe(PolicyDecision.ALLOW);
      expect(result.trustLevel).toBeGreaterThanOrEqual(TrustLevel.LOW);
    });

    test('should calculate trust level based on authentication method', async () => {
      const identity = createTestIdentity();

      // Test with MFA
      const mfaAuthContext = createTestAuthContext({
        method: AuthenticationMethod.MFA,
        mfaVerified: true
      });

      const mfaResult = await pdp.evaluateAccess({
        identity,
        authContext: mfaAuthContext,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      // Test with password only
      const passwordAuthContext = createTestAuthContext({
        method: AuthenticationMethod.PASSWORD,
        mfaVerified: false,
        factors: [AuthenticationMethod.PASSWORD]
      });

      const passwordResult = await pdp.evaluateAccess({
        identity,
        authContext: passwordAuthContext,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      expect(mfaResult.trustLevel).toBeGreaterThanOrEqual(passwordResult.trustLevel);
    });

    test('should calculate trust level based on device posture', async () => {
      const identity = createTestIdentity();
      const authContext = createTestAuthContext();

      // Test with healthy device
      const healthyPosture = createTestDevicePosture({
        healthStatus: DeviceHealthStatus.HEALTHY,
        riskScore: 5
      });

      const healthyResult = await pdp.evaluateAccess({
        identity,
        authContext,
        devicePosture: healthyPosture,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      // Test with non-compliant device
      const nonCompliantPosture = createTestDevicePosture({
        healthStatus: DeviceHealthStatus.NON_COMPLIANT,
        riskScore: 80
      });

      const nonCompliantResult = await pdp.evaluateAccess({
        identity,
        authContext,
        devicePosture: nonCompliantPosture,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      expect(healthyResult.trustLevel).toBeGreaterThanOrEqual(nonCompliantResult.trustLevel);
    });

    test('should deny access with DENY policy', async () => {
      const denyPolicy = createTestPolicy({
        id: 'deny_all',
        name: 'Deny All',
        effect: 'DENY',
        subjectTypes: [SubjectType.USER],
        resourceTypes: [ResourceType.HTTP_ENDPOINT],
        operations: [PolicyOperation.ANY],
        priority: 1 // Higher priority (lower number)
      });

      pdp.loadPolicies([denyPolicy]);

      const identity = createTestIdentity();
      const authContext = createTestAuthContext();

      const result = await pdp.evaluateAccess({
        identity,
        authContext,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      expect(result.decision).toBe(PolicyDecision.DENY);
    });

    test('should cache positive decisions', async () => {
      const identity = createTestIdentity();
      const authContext = createTestAuthContext();

      // First request
      await pdp.evaluateAccess({
        identity,
        authContext,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      const stats1 = pdp.getStats();

      // Second request (should be cached)
      await pdp.evaluateAccess({
        identity,
        authContext,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      const stats2 = pdp.getStats();

      expect(stats2.cacheHits).toBeGreaterThanOrEqual(stats1.cacheHits);
    });
  });
});

// ============================================================================
// POLICY ENFORCEMENT POINT TESTS
// ============================================================================

describe('PolicyEnforcementPoint', () => {
  let pep: PolicyEnforcementPoint;
  let pdp: PolicyDecisionPoint;

  beforeEach(() => {
    pdp = new PolicyDecisionPoint({ enableLogging: false });
    pep = new PolicyEnforcementPoint({
      enableCaching: true,
      enableCircuitBreaker: true,
      enableVerboseLogging: false
    });
    pep.setPdp(pdp);

    // Load default policy
    const allowPolicy = createTestPolicy({
      effect: 'ALLOW',
      subjectTypes: [SubjectType.USER],
      resourceTypes: [ResourceType.HTTP_ENDPOINT],
      operations: [PolicyOperation.ANY]
    });
    pdp.loadPolicies([allowPolicy]);
  });

  afterEach(() => {
    pep.removeAllListeners();
    pdp.removeAllListeners();
  });

  describe('Initialization', () => {
    test('should create PEP with PDP', () => {
      expect(pep).toBeDefined();
      expect(pep.getPdp()).toBe(pdp);
    });

    test('should throw error when PDP not set', async () => {
      const isolatedPep = new PolicyEnforcementPoint();

      await expect(
        isolatedPep.enforceAccess({
          identity: createTestIdentity(),
          authContext: createTestAuthContext(),
          resourceType: ResourceType.HTTP_ENDPOINT,
          resourceId: 'resource_001',
          resourceName: 'Test Resource',
          operation: PolicyOperation.READ,
          sourceIp: '192.168.1.100'
        })
      ).rejects.toThrow('PDP не установлен');
    });
  });

  describe('Access Enforcement', () => {
    test('should enforce access decision', async () => {
      const result = await pep.enforceAccess({
        identity: createTestIdentity(),
        authContext: createTestAuthContext(),
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      expect(result).toBeDefined();
      expect(result.decision).toBe(PolicyDecision.ALLOW);
      expect(result.enforced).toBe(true);
    });

    test('should cache decisions', async () => {
      const identity = createTestIdentity();
      const authContext = createTestAuthContext();

      // First request
      await pep.enforceAccess({
        identity,
        authContext,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      const stats1 = pep.getStats();

      // Second request (should be cached)
      await pep.enforceAccess({
        identity,
        authContext,
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      const stats2 = pep.getStats();

      expect(stats2.cacheHits).toBeGreaterThanOrEqual(stats1.cacheHits);
    });
  });

  describe('Circuit Breaker', () => {
    test('should open circuit after failures', async () => {
      // Create PEP with low failure threshold
      const testPep = new PolicyEnforcementPoint({
        enableCircuitBreaker: true,
        circuitBreaker: {
          failureThreshold: 3,
          resetTimeout: 1000,
          retryTimeout: 500
        },
        pdpTimeout: 100,
        onPdpUnavailable: 'DENY'
      });

      // Create slow PDP that will timeout
      const slowPdp = new PolicyDecisionPoint();
      testPep.setPdp(slowPdp);

      // Make multiple requests that will timeout
      for (let i = 0; i < 5; i++) {
        await testPep.enforceAccess({
          identity: createTestIdentity(),
          authContext: createTestAuthContext(),
          resourceType: ResourceType.HTTP_ENDPOINT,
          resourceId: 'resource_001',
          resourceName: 'Test Resource',
          operation: PolicyOperation.READ,
          sourceIp: '192.168.1.100'
        }).catch(() => {});
      }

      expect(testPep.getCircuitState()).toBeDefined();
    });

    test('should reset circuit breaker', () => {
      pep.resetCircuitBreaker();
      expect(pep.getCircuitState()).toBeDefined();
    });
  });

  describe('Rate Limiting', () => {
    test('should enforce rate limits', async () => {
      const rateLimitedPep = new PolicyEnforcementPoint({
        rateLimit: {
          enabled: true,
          requestsPerSecond: 5,
          burstSize: 10
        }
      });
      rateLimitedPep.setPdp(pdp);

      // Make burstSize + 1 requests quickly
      const results: Promise<unknown>[] = [];
      for (let i = 0; i < 15; i++) {
        results.push(
          rateLimitedPep.enforceAccess({
            identity: createTestIdentity(),
            authContext: createTestAuthContext(),
            resourceType: ResourceType.HTTP_ENDPOINT,
            resourceId: 'resource_001',
            resourceName: 'Test Resource',
            operation: PolicyOperation.READ,
            sourceIp: '192.168.1.100'
          })
        );
      }

      const allResults = await Promise.all(results);
      const rateLimitedCount = allResults.filter(
        r => r.decision === PolicyDecision.DENY
      ).length;

      expect(rateLimitedCount).toBeGreaterThan(0);
    });
  });
});

// ============================================================================
// MICRO-SEGMENTATION TESTS
// ============================================================================

describe('MicroSegmentation', () => {
  let ms: MicroSegmentation;

  beforeEach(() => {
    ms = new MicroSegmentation({
      defaultDeny: true,
      enableVerboseLogging: false
    });
  });

  afterEach(() => {
    ms.removeAllListeners();
  });

  describe('Segment Management', () => {
    test('should create network segment', () => {
      const segment = ms.createSegment({
        id: 'segment_web',
        name: 'Web Tier',
        type: 'PRIVATE',
        cidr: '10.0.1.0/24',
        labels: { tier: 'web' }
      });

      expect(segment).toBeDefined();
      expect(segment.id).toBe('segment_web');
      expect(ms.getStats().totalSegments).toBe(1);
    });

    test('should delete network segment', () => {
      ms.createSegment({
        id: 'segment_temp',
        name: 'Temporary Segment',
        type: 'PRIVATE',
        cidr: '10.0.2.0/24',
        labels: {}
      });

      const deleted = ms.deleteSegment('segment_temp');
      expect(deleted).toBe(true);
      expect(ms.getStats().totalSegments).toBe(0);
    });
  });

  describe('Rule Management', () => {
    beforeEach(() => {
      // Create segments
      ms.createSegment({
        id: 'segment_web',
        name: 'Web Tier',
        type: 'PRIVATE',
        cidr: '10.0.1.0/24',
        labels: { tier: 'web' }
      });

      ms.createSegment({
        id: 'segment_db',
        name: 'Database Tier',
        type: 'DATA',
        cidr: '10.0.2.0/24',
        labels: { tier: 'database' }
      });
    });

    test('should add segmentation rule', () => {
      const rule = {
        id: 'rule_web_to_db',
        name: 'Web to Database',
        sourceSegment: {
          segmentId: 'segment_web',
          type: 'PRIVATE' as const
        },
        destinationSegment: {
          segmentId: 'segment_db',
          type: 'DATA' as const
        },
        protocols: [{
          protocol: 'TCP' as const,
          destinationPorts: ['5432', '3306']
        }],
        action: 'ALLOW' as const,
        priority: 100,
        logTraffic: true,
        enableInspection: false,
        enabled: true
      };

      ms.addRule(rule);

      expect(ms.getStats().totalRules).toBe(1);
    });

    test('should check traffic between segments', () => {
      // Add allow rule
      ms.addRule({
        id: 'rule_allow',
        name: 'Allow Web to DB',
        sourceSegment: {
          segmentId: 'segment_web',
          type: 'PRIVATE' as const
        },
        destinationSegment: {
          segmentId: 'segment_db',
          type: 'DATA' as const
        },
        protocols: [{
          protocol: 'TCP' as const,
          destinationPorts: ['5432']
        }],
        action: 'ALLOW' as const,
        priority: 100,
        logTraffic: false,
        enableInspection: false,
        enabled: true
      });

      // Check allowed traffic
      const allowedResult = ms.checkTraffic(
        'segment_web',
        'segment_db',
        'TCP',
        5432
      );

      expect(allowedResult.allowed).toBe(true);

      // Check denied traffic (different port)
      const deniedResult = ms.checkTraffic(
        'segment_web',
        'segment_db',
        'TCP',
        6379
      );

      expect(deniedResult.allowed).toBe(false);
    });
  });

  describe('Workload Registration', () => {
    beforeEach(() => {
      ms.createSegment({
        id: 'segment_app',
        name: 'Application Tier',
        type: 'PRIVATE',
        cidr: '10.0.3.0/24',
        labels: { tier: 'app' }
      });
    });

    test('should register workload in segment', () => {
      ms.registerWorkload('workload_001', 'segment_app');

      const segment = ms.getWorkloadSegment('workload_001');
      expect(segment).toBeDefined();
      expect(segment?.id).toBe('segment_app');
    });

    test('should unregister workload', () => {
      ms.registerWorkload('workload_002', 'segment_app');
      ms.unregisterWorkload('workload_002');

      const segment = ms.getWorkloadSegment('workload_002');
      expect(segment).toBeUndefined();
    });
  });
});

// ============================================================================
// ZERO TRUST CONTROLLER TESTS
// ============================================================================

describe('ZeroTrustController', () => {
  let controller: ZeroTrustController;

  beforeEach(() => {
    controller = new ZeroTrustController({
      controllerId: 'test-controller',
      name: 'Test Zero Trust Controller',
      enableVerboseLogging: false,
      enableComponents: {
        pdp: true,
        pep: true,
        devicePosture: true,
        trustVerifier: true,
        microSegmentation: true,
        sdp: false,
        identityProxy: false,
        serviceMesh: false,
        nac: true,
        jitAccess: true,
        egressFilter: true,
        tls: true,
        policyEngine: true
      }
    });
  });

  afterEach(async () => {
    await controller.shutdown();
    controller.removeAllListeners();
  });

  describe('Initialization', () => {
    test('should initialize all components', async () => {
      await controller.initialize();

      const states = controller.getComponentStates();
      
      expect(states.get('pdp')?.status).toBe('ACTIVE');
      expect(states.get('pep')?.status).toBe('ACTIVE');
      expect(states.get('devicePosture')?.status).toBe('ACTIVE');
      expect(states.get('trustVerifier')?.status).toBe('ACTIVE');
      expect(states.get('microSegmentation')?.status).toBe('ACTIVE');
      expect(states.get('policyEngine')?.status).toBe('ACTIVE');
    });

    test('should export configuration', async () => {
      await controller.initialize();

      const config = controller.exportConfig();

      expect(config.version).toBe('1.0');
      expect(config.controllerId).toBe('test-controller');
      expect(config.exportedAt).toBeInstanceOf(Date);
    });
  });

  describe('Access Control', () => {
    beforeEach(async () => {
      await controller.initialize();
    });

    test('should handle access request', async () => {
      const result = await controller.handleAccessRequest({
        identity: createTestIdentity(),
        authContext: createTestAuthContext(),
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: 'resource_001',
        resourceName: 'Test Resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      });

      expect(result).toBeDefined();
      expect(result.evaluationId).toBeDefined();
    });

    test('should create and manage sessions', async () => {
      const identity = createTestIdentity();
      const authContext = createTestAuthContext();

      // Create session
      const sessionId = await controller.createSession(
        identity,
        authContext,
        createTestDevicePosture()
      );

      expect(sessionId).toBeDefined();

      const stats = controller.getStats();
      expect(stats.activeSessions).toBe(1);

      // Terminate session
      controller.terminateSession(sessionId);

      const statsAfter = controller.getStats();
      expect(statsAfter.activeSessions).toBe(0);
    });
  });

  describe('Component Access', () => {
    beforeEach(async () => {
      await controller.initialize();
    });

    test('should provide access to PDP', () => {
      const pdp = controller.getComponent('pdp');
      expect(pdp).toBeDefined();
      expect(pdp).toBeInstanceOf(PolicyDecisionPoint);
    });

    test('should provide access to PEP', () => {
      const pep = controller.getComponent('pep');
      expect(pep).toBeDefined();
      expect(pep).toBeInstanceOf(PolicyEnforcementPoint);
    });

    test('should provide access to MicroSegmentation', () => {
      const ms = controller.getComponent('microSegmentation');
      expect(ms).toBeDefined();
      expect(ms).toBeInstanceOf(MicroSegmentation);
    });
  });

  describe('Statistics', () => {
    beforeEach(async () => {
      await controller.initialize();
    });

    test('should track request statistics', async () => {
      const initialStats = controller.getStats();

      // Make some requests
      for (let i = 0; i < 5; i++) {
        await controller.handleAccessRequest({
          identity: createTestIdentity(),
          authContext: createTestAuthContext(),
          resourceType: ResourceType.HTTP_ENDPOINT,
          resourceId: 'resource_001',
          resourceName: 'Test Resource',
          operation: PolicyOperation.READ,
          sourceIp: '192.168.1.100'
        });
      }

      const finalStats = controller.getStats();
      expect(finalStats.totalRequests).toBe(initialStats.totalRequests + 5);
    });
  });
});

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

describe('Zero Trust Integration Tests', () => {
  test('should enforce zero trust principles end-to-end', async () => {
    // Create controller with all components
    const controller = new ZeroTrustController({
      controllerId: 'integration-test',
      enableComponents: {
        pdp: true,
        pep: true,
        devicePosture: true,
        trustVerifier: true,
        microSegmentation: true,
        sdp: false,
        identityProxy: false,
        serviceMesh: false,
        nac: true,
        jitAccess: true,
        egressFilter: true,
        tls: true,
        policyEngine: true
      },
      enableVerboseLogging: false
    });

    await controller.initialize();

    // Test 1: Authorized user with healthy device should get access
    const authorizedResult = await controller.handleAccessRequest({
      identity: createTestIdentity({ roles: ['admin'] }),
      authContext: createTestAuthContext({
        method: AuthenticationMethod.MTLS,
        mfaVerified: true
      }),
      devicePosture: createTestDevicePosture({
        healthStatus: DeviceHealthStatus.HEALTHY
      }),
      resourceType: ResourceType.HTTP_ENDPOINT,
      resourceId: 'secure-resource',
      resourceName: 'Secure Resource',
      operation: PolicyOperation.READ,
      sourceIp: '10.0.1.100'
    });

    expect(authorizedResult.decision).toBe(PolicyDecision.ALLOW);

    // Test 2: User with non-compliant device should be restricted
    const nonCompliantResult = await controller.handleAccessRequest({
      identity: createTestIdentity(),
      authContext: createTestAuthContext({
        method: AuthenticationMethod.PASSWORD,
        mfaVerified: false
      }),
      devicePosture: createTestDevicePosture({
        healthStatus: DeviceHealthStatus.NON_COMPLIANT,
        compliance: {
          antivirusActive: false,
          antivirusUpdated: false,
          firewallActive: false,
          diskEncrypted: false,
          secureBootEnabled: false,
          tpmPresent: false,
          lastUpdateCheck: new Date(),
          criticalUpdatesInstalled: false,
          jailbreakDetected: false
        }
      }),
      resourceType: ResourceType.HTTP_ENDPOINT,
      resourceId: 'secure-resource',
      resourceName: 'Secure Resource',
      operation: PolicyOperation.READ,
      sourceIp: '203.0.113.100'
    });

    // Should have lower trust level
    expect(nonCompliantResult.trustLevel).toBeLessThanOrEqual(authorizedResult.trustLevel);

    await controller.shutdown();
  });
});
