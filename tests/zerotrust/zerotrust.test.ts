/**
 * ============================================================================
 * ZERO TRUST ARCHITECTURE TESTS
 * ============================================================================
 */

import { describe, it, beforeEach, afterEach } from '@jest/globals';
import * as assert from 'assert';
import {
  PolicyDecisionPoint,
  PdpConfig
} from '../../src/zerotrust/PolicyDecisionPoint';
import {
  TrustVerifier,
  TrustVerifierConfig
} from '../../src/zerotrust/TrustVerifier';
import {
  PolicyEnforcementPoint,
  PepConfig
} from '../../src/zerotrust/PolicyEnforcementPoint';
import {
  ZeroTrustController,
  createZeroTrustController,
  getZeroTrustController
} from '../../src/zerotrust/ZeroTrustController';
import {
  TrustLevel,
  PolicyDecision,
  SubjectType,
  ResourceType,
  PolicyOperation,
  AuthenticationMethod,
  DeviceHealthStatus
} from '../../src/zerotrust/zerotrust.types';

describe('Zero Trust Architecture', () => {
  
  describe('PolicyDecisionPoint', () => {
    let pdp: PolicyDecisionPoint;

    beforeEach(() => {
      pdp = new PolicyDecisionPoint({
        enableCaching: true,
        cacheDefaultTtl: 300,
        cacheMaxSize: 100,
        enableLogging: false,
        enableBehavioralAnalysis: true
      });
    });

    afterEach(() => {
      pdp.clearCache();
      pdp.removeAllListeners();
    });

    it('должен создавать PDP с конфигурацией', () => {
      assert.ok(pdp);
      const stats = pdp.getStats();
      assert.strictEqual(stats.isInitialized, true);
    });

    it('должен регистрировать политики', () => {
      const policy = {
        id: 'test-policy',
        name: 'Test Policy',
        effect: 'ALLOW' as const,
        conditions: [
          {
            attribute: 'trustLevel' as const,
            operator: 'gte' as const,
            value: TrustLevel.MEDIUM
          }
        ]
      };

      pdp.registerPolicy(policy);
      const stats = pdp.getStats();
      assert.strictEqual(stats.policiesCount, 1);
    });

    it('должен оценивать доступ с высоким trust level', async () => {
      const request = {
        identity: {
          subjectId: 'user123',
          subjectType: SubjectType.USER,
          roles: ['admin'],
          permissions: [],
          attributes: {}
        },
        authContext: {
          authenticationMethods: [AuthenticationMethod.MFA],
          authenticatedAt: new Date(),
          sessionId: 'session123',
          tokenClaims: {}
        },
        devicePosture: {
          healthStatus: DeviceHealthStatus.HEALTHY,
          isCompliant: true,
          isEncrypted: true,
          hasAntivirus: true
        },
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: '/api/data',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.1'
      };

      const response = await pdp.evaluateAccess(request as any);
      
      assert.ok(response);
      assert.ok(response.requestId);
      assert.ok(response.trustLevel);
      assert.ok(response.riskAssessment);
    });

    it('должен кэшировать решения', async () => {
      const request = {
        identity: {
          subjectId: 'user456',
          subjectType: SubjectType.USER,
          roles: [],
          permissions: [],
          attributes: {}
        },
        authContext: {
          authenticationMethods: [AuthenticationMethod.JWT],
          authenticatedAt: new Date(),
          sessionId: 'session456',
          tokenClaims: {}
        },
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: '/api/test',
        operation: PolicyOperation.READ,
        sourceIp: '10.0.0.1'
      };

      // Первый запрос
      const response1 = await pdp.evaluateAccess(request as any);
      assert.strictEqual(response1.cached, false);

      // Второй запрос (должен быть из кэша)
      const response2 = await pdp.evaluateAccess(request as any);
      assert.strictEqual(response2.cached, true);
    });

    it('должен очищать кэш', () => {
      pdp.clearCache();
      const stats = pdp.getStats();
      assert.strictEqual(stats.cacheSize, 0);
    });
  });

  describe('TrustVerifier', () => {
    let trustVerifier: TrustVerifier;

    beforeEach(() => {
      trustVerifier = new TrustVerifier({
        verificationInterval: 60000,
        maxSessionDuration: 3600000,
        inactivityTimeout: 300000,
        enableBehavioralAnalysis: true
      });
    });

    afterEach(() => {
      trustVerifier.stop();
      trustVerifier.clearAllSessions();
      trustVerifier.removeAllListeners();
    });

    it('должен создавать Trust Verifier', () => {
      assert.ok(trustVerifier);
      const stats = trustVerifier.getStats();
      assert.strictEqual(stats.isRunning, false);
    });

    it('должен запускаться и останавливаться', () => {
      trustVerifier.start();
      let stats = trustVerifier.getStats();
      assert.strictEqual(stats.isRunning, true);

      trustVerifier.stop();
      stats = trustVerifier.getStats();
      assert.strictEqual(stats.isRunning, false);
    });

    it('должен инициализировать trust контекст', async () => {
      const identity = {
        subjectId: 'user789',
        subjectType: SubjectType.USER,
        roles: ['user'],
        permissions: [],
        attributes: {}
      };

      const authContext = {
        authenticationMethods: [AuthenticationMethod.MFA],
        authenticatedAt: new Date(),
        sessionId: 'session789',
        tokenClaims: {}
      };

      const context = await trustVerifier.initializeTrust(identity, authContext);
      
      assert.ok(context);
      assert.strictEqual(context.identity.subjectId, 'user789');
      assert.ok(context.currentTrustLevel);
    });

    it('должен обновлять активность', async () => {
      const identity = {
        subjectId: 'user999',
        subjectType: SubjectType.USER,
        roles: [],
        permissions: [],
        attributes: {}
      };

      await trustVerifier.initializeTrust(identity, {
        authenticationMethods: [AuthenticationMethod.JWT],
        authenticatedAt: new Date(),
        sessionId: 'session999',
        tokenClaims: {}
      });

      trustVerifier.updateActivity('user999', {
        type: 'ACCESS',
        resource: '/api/data',
        operation: 'READ',
        result: 'SUCCESS'
      });

      const context = trustVerifier.getTrustContext('user999');
      assert.ok(context);
      assert.ok(context.lastActivity);
    });

    it('должен завершать сессию', async () => {
      const identity = {
        subjectId: 'user-temp',
        subjectType: SubjectType.USER,
        roles: [],
        permissions: [],
        attributes: {}
      };

      await trustVerifier.initializeTrust(identity, {
        authenticationMethods: [AuthenticationMethod.JWT],
        authenticatedAt: new Date(),
        sessionId: 'session-temp',
        tokenClaims: {}
      });

      trustVerifier.terminateSession('user-temp');
      
      const context = trustVerifier.getTrustContext('user-temp');
      assert.strictEqual(context, undefined);
    });

    it('должен возвращать статистику', async () => {
      const identity1 = {
        subjectId: 'user1',
        subjectType: SubjectType.USER,
        roles: [],
        permissions: [],
        attributes: {}
      };

      const identity2 = {
        subjectId: 'user2',
        subjectType: SubjectType.USER,
        roles: [],
        permissions: [],
        attributes: {}
      };

      await trustVerifier.initializeTrust(identity1, {
        authenticationMethods: [AuthenticationMethod.MFA],
        authenticatedAt: new Date(),
        sessionId: 's1',
        tokenClaims: {}
      });

      await trustVerifier.initializeTrust(identity2, {
        authenticationMethods: [AuthenticationMethod.JWT],
        authenticatedAt: new Date(),
        sessionId: 's2',
        tokenClaims: {}
      });

      const stats = trustVerifier.getStats();
      assert.strictEqual(stats.activeSessions, 2);
      assert.ok(stats.trustLevelDistribution);
    });
  });

  describe('PolicyEnforcementPoint', () => {
    let pep: PolicyEnforcementPoint;

    beforeEach(() => {
      pep = new PolicyEnforcementPoint({
        enableEnforcement: true,
        auditOnlyMode: false,
        enableDecisionCaching: true
      });
    });

    afterEach(() => {
      pep.clearCache();
      pep.removeAllListeners();
    });

    it('должен создавать PEP', () => {
      assert.ok(pep);
      const stats = pep.getStats();
      assert.strictEqual(stats.isInitialized, true);
    });

    it('должен перехватывать запросы', async () => {
      const request = {
        requestId: 'test-request',
        identity: {
          subjectId: 'user-pep',
          subjectType: SubjectType.USER,
          roles: ['user'],
          permissions: [],
          attributes: {}
        },
        authContext: {
          authenticationMethods: [AuthenticationMethod.JWT],
          authenticatedAt: new Date(),
          sessionId: 'session-pep',
          tokenClaims: {}
        },
        resourceType: ResourceType.HTTP_ENDPOINT,
        resourceId: '/api/resource',
        operation: PolicyOperation.READ,
        sourceIp: '192.168.1.100'
      };

      const response = await pep.interceptRequest(request as any);
      
      assert.ok(response);
      assert.ok(response.requestId);
      assert.ok(response.decision);
    });

    it('должен возвращать PDP', () => {
      const pdp = pep.getPdp();
      assert.ok(pdp);
    });

    it('должен возвращать Trust Verifier', () => {
      const tv = pep.getTrustVerifier();
      assert.ok(tv);
    });
  });

  describe('ZeroTrustController', () => {
    let controller: ZeroTrustController;

    beforeEach(() => {
      controller = createZeroTrustController({
        enabled: true,
        enforcementMode: 'balanced',
        enableMonitoring: false,
        enableAudit: true
      });
    });

    afterEach(() => {
      controller.stop();
      controller.removeAllListeners();
    });

    it('должен создавать контроллер', () => {
      assert.ok(controller);
      const config = controller.exportConfig();
      assert.strictEqual(config.enabled, true);
    });

    it('должен запускаться и останавливаться', () => {
      controller.start();
      let stats = controller.getStats();
      assert.strictEqual(stats.isRunning, true);

      controller.stop();
      stats = controller.getStats();
      assert.strictEqual(stats.isRunning, false);
    });

    it('должен создавать сессии', async () => {
      const identity = {
        subjectId: 'zt-user',
        subjectType: SubjectType.USER,
        roles: ['admin'],
        permissions: [],
        attributes: {}
      };

      const authContext = {
        authenticationMethods: [AuthenticationMethod.MFA],
        authenticatedAt: new Date(),
        sessionId: 'zt-session',
        tokenClaims: {}
      };

      const session = await controller.createSession(identity, authContext);
      
      assert.ok(session);
      assert.strictEqual(session.identity.subjectId, 'zt-user');
      assert.ok(session.sessionId);
    });

    it('должен запрашивать доступ', async () => {
      const identity = {
        subjectId: 'zt-user2',
        subjectType: SubjectType.USER,
        roles: [],
        permissions: [],
        attributes: {}
      };

      await controller.createSession(identity, {
        authenticationMethods: [AuthenticationMethod.JWT],
        authenticatedAt: new Date(),
        sessionId: 'zt-s2',
        tokenClaims: {}
      });

      const decision = await controller.requestAccess(
        'zt-user2',
        ResourceType.HTTP_ENDPOINT,
        '/api/data',
        PolicyOperation.READ
      );

      assert.ok(decision);
      assert.ok(decision.decision);
    });

    it('должен возвращать все сессии', async () => {
      const identity1 = {
        subjectId: 'u1',
        subjectType: SubjectType.USER,
        roles: [],
        permissions: [],
        attributes: {}
      };

      const identity2 = {
        subjectId: 'u2',
        subjectType: SubjectType.USER,
        roles: [],
        permissions: [],
        attributes: {}
      };

      await controller.createSession(identity1, {
        authenticationMethods: [AuthenticationMethod.JWT],
        authenticatedAt: new Date(),
        sessionId: 's1',
        tokenClaims: {}
      });

      await controller.createSession(identity2, {
        authenticationMethods: [AuthenticationMethod.JWT],
        authenticatedAt: new Date(),
        sessionId: 's2',
        tokenClaims: {}
      });

      const sessions = controller.getAllSessions();
      assert.strictEqual(sessions.length, 2);
    });

    it('должен возвращать события', async () => {
      const events = controller.getEvents(10);
      assert.ok(Array.isArray(events));
    });

    it('должен возвращать статистику', () => {
      const stats = controller.getStats();
      assert.ok(stats.installationId);
      assert.ok(stats.trustLevelDistribution);
    });

    it('должен возвращать компоненты', () => {
      assert.ok(controller.getPdp());
      assert.ok(controller.getPep());
      assert.ok(controller.getTrustVerifier());
    });
  });

  describe('Singleton', () => {
    it('должен возвращать singleton instance', () => {
      const instance1 = getZeroTrustController({ installationId: 'test-1' });
      const instance2 = getZeroTrustController({ installationId: 'test-2' });
      
      assert.strictEqual(instance1, instance2);
    });
  });
});
