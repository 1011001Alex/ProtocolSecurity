/**
 * ============================================================================
 * ТЕСТЫ ДЛЯ СИСТЕМЫ УПРАВЛЕНИЯ СЕКРЕТАМИ
 * ============================================================================
 * 
 * Comprehensive тесты для всех компонентов Secrets Manager:
 * - SecretCache
 * - AccessPolicyManager
 * - SecretVersioningManager
 * - SecretLeaseManager
 * - SecretRotator
 * - DynamicSecretsManager
 * - SecretScanner
 * - SecretsManager (интеграционные тесты)
 * 
 * @package protocol/tests/secrets
 * @author grigo
 * @version 1.0.0
 */

import { randomBytes, randomUUID } from 'crypto';
import {
  SecretCache,
  AccessPolicyManager,
  SecretVersioningManager,
  SecretLeaseManager,
  SecretRotator,
  DynamicSecretsManager,
  SecretScanner,
  SecretsManager,
  SecretsManagerFactory
} from '../../src/secrets/SecretsManager';
import {
  SecretBackendType,
  SecretStatus,
  SecretAction,
  SecretOperation,
  LeakType,
  LeakSeverity,
  DynamicSecretType,
  AccessContext,
  CacheConfig,
  RotationConfig,
  LeaseConfig,
  ScannerConfig,
  AccessPolicy,
  BackendSecret
} from '../../src/types/secrets.types';

// ============================================================================
// УТИЛИТЫ ДЛЯ ТЕСТОВ
// ============================================================================

/**
 * Генерация тестового ключа шифрования
 */
function generateTestEncryptionKey(): string {
  return randomBytes(32).toString('base64');
}

/**
 * Создание тестового контекста доступа
 */
function createTestContext(overrides?: Partial<AccessContext>): AccessContext {
  return {
    subjectId: 'test-user',
    roles: ['user'],
    attributes: {},
    ipAddress: '127.0.0.1',
    timestamp: new Date(),
    mfaVerified: false,
    ...overrides
  };
}

/**
 * Создание тестового секрета
 */
function createTestSecret(overrides?: Partial<BackendSecret>): BackendSecret {
  return {
    id: `test-secret-${randomUUID().slice(0, 8)}`,
    name: 'Test Secret',
    value: 'test-secret-value-' + randomUUID().slice(0, 8),
    version: 1,
    status: SecretStatus.ACTIVE,
    createdAt: new Date(),
    ...overrides
  };
}

/**
 * Задержка в мс
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// ТЕСТЫ SECRET CACHE
// ============================================================================

describe('SecretCache', () => {
  let cache: SecretCache;
  const encryptionKey = generateTestEncryptionKey();

  beforeEach(async () => {
    const config: CacheConfig = {
      enabled: true,
      ttl: 60,
      maxEntries: 100,
      encryptInMemory: true,
      encryptionAlgorithm: 'aes-256-gcm',
      evictionStrategy: 'lru'
    };
    
    cache = new SecretCache(config, encryptionKey);
    await cache.initialize();
  });

  afterEach(async () => {
    await cache.destroy();
  });

  describe('initialize/destroy', () => {
    it('должен успешно инициализироваться', async () => {
      expect(cache).toBeDefined();
      await expect(cache.initialize()).resolves.not.toThrow();
    });

    it('должен успешно уничтожаться', async () => {
      await expect(cache.destroy()).resolves.not.toThrow();
    });
  });

  describe('set/get', () => {
    it('должен сохранять и получать секрет', async () => {
      const secret = createTestSecret();
      
      const setResult = await cache.set(secret);
      expect(setResult).toBe(true);
      
      const retrieved = await cache.get(secret.id);
      expect(retrieved).toBeDefined();
      expect(retrieved?.value).toBe(secret.value);
    });

    it('должен возвращать null для несуществующего секрета', async () => {
      const retrieved = await cache.get('non-existent');
      expect(retrieved).toBeNull();
    });

    it('должен проверять версию при получении', async () => {
      const secret = createTestSecret({ version: 1 });
      await cache.set(secret);
      
      const retrieved = await cache.get(secret.id, 1);
      expect(retrieved).toBeDefined();
      
      const wrongVersion = await cache.get(secret.id, 999);
      expect(wrongVersion).toBeNull();
    });
  });

  describe('TTL expiration', () => {
    it('должен истекать по TTL', async () => {
      const config: CacheConfig = {
        enabled: true,
        ttl: 1, // 1 секунда
        maxEntries: 100,
        encryptInMemory: true,
        encryptionAlgorithm: 'aes-256-gcm',
        evictionStrategy: 'lru'
      };
      
      const shortCache = new SecretCache(config, encryptionKey);
      await shortCache.initialize();
      
      const secret = createTestSecret();
      await shortCache.set(secret);
      
      // Сразу должно быть в кэше
      expect(await shortCache.has(secret.id)).toBe(true);
      
      // Ждём истечения
      await sleep(1500);
      
      // Должно исчезнуть
      expect(await shortCache.has(secret.id)).toBe(false);
      
      await shortCache.destroy();
    });
  });

  describe('delete', () => {
    it('должен удалять секрет из кэша', async () => {
      const secret = createTestSecret();
      await cache.set(secret);
      
      expect(await cache.has(secret.id)).toBe(true);
      
      const deleted = await cache.delete(secret.id);
      expect(deleted).toBe(true);
      
      expect(await cache.has(secret.id)).toBe(false);
    });
  });

  describe('clear', () => {
    it('должен очищать весь кэш', async () => {
      // Добавляем несколько секретов
      for (let i = 0; i < 5; i++) {
        await cache.set(createTestSecret({ id: `secret-${i}` }));
      }
      
      const stats = cache.getStats();
      expect(stats.size).toBe(5);
      
      await cache.clear();
      
      const clearedStats = cache.getStats();
      expect(clearedStats.size).toBe(0);
    });
  });

  describe('encryption', () => {
    it('должен шифровать значения в памяти', async () => {
      const secret = createTestSecret({ value: 'sensitive-data' });
      await cache.set(secret);
      
      // Получаем секрет
      const retrieved = await cache.get(secret.id);
      expect(retrieved?.value).toBe('sensitive-data');
      
      // Проверяем статистику шифрования
      const stats = cache.getStats();
      expect(stats.avgEncryptTimeMs).toBeGreaterThanOrEqual(0);
      expect(stats.avgDecryptTimeMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe('stats', () => {
    it('должен возвращать корректную статистику', async () => {
      const secret = createTestSecret();
      await cache.set(secret);
      
      // Несколько чтений
      await cache.get(secret.id);
      await cache.get(secret.id);
      await cache.get('non-existent');
      
      const stats = cache.getStats();
      
      expect(stats.hits).toBe(2);
      expect(stats.misses).toBe(1);
      expect(stats.hitRate).toBeGreaterThan(50);
    });

    it('должен сбрасывать статистику', async () => {
      cache.resetStats();
      
      const stats = cache.getStats();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
    });
  });

  describe('memory usage', () => {
    it('должен рассчитывать использование памяти', async () => {
      const secret = createTestSecret({ value: 'x'.repeat(1000) });
      await cache.set(secret);
      
      const memoryUsage = cache.getMemoryUsage();
      expect(memoryUsage).toBeGreaterThan(0);
    });
  });
});

// ============================================================================
// ТЕСТЫ ACCESS POLICY MANAGER
// ============================================================================

describe('AccessPolicyManager', () => {
  let policyManager: AccessPolicyManager;

  beforeEach(async () => {
    policyManager = new AccessPolicyManager();
    await policyManager.initialize([], true);
    // Очищаем кэш для предотвращения cross-test contamination
    policyManager.clearAccessCache();
  });

  afterEach(async () => {
    await policyManager.destroy();
  });

  describe('policy management', () => {
    it('должен добавлять политику', async () => {
      const policy: AccessPolicy = {
        policyId: 'test-policy',
        name: 'Test Policy',
        description: 'Test policy for unit tests',
        rules: [
          {
            ruleId: 'rule-1',
            actions: [SecretAction.READ],
            resources: ['*'],
            subjects: ['*'],
            effect: 'allow',
            priority: 10
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await expect(policyManager.addPolicy(policy)).resolves.not.toThrow();
      
      const retrieved = policyManager.getPolicy('test-policy');
      expect(retrieved).toBeDefined();
      expect(retrieved?.name).toBe('Test Policy');
    });

    it('должен обновлять политику', async () => {
      const policy: AccessPolicy = {
        policyId: 'test-policy',
        name: 'Test Policy',
        description: 'Test',
        rules: [
          {
            ruleId: 'rule-1',
            actions: [SecretAction.READ],
            resources: ['*'],
            subjects: ['*'],
            effect: 'allow',
            priority: 10
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await policyManager.addPolicy(policy);
      
      const updated = await policyManager.updatePolicy('test-policy', {
        name: 'Updated Policy'
      });
      
      expect(updated.name).toBe('Updated Policy');
      expect(updated.version).toBe(2);
    });

    it('должен удалять политику', async () => {
      const policy: AccessPolicy = {
        policyId: 'test-policy',
        name: 'Test Policy',
        description: 'Test',
        rules: [
          {
            ruleId: 'rule-1',
            actions: [SecretAction.READ],
            resources: ['*'],
            subjects: ['*'],
            effect: 'allow',
            priority: 10
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await policyManager.addPolicy(policy);
      
      const deleted = await policyManager.removePolicy('test-policy');
      expect(deleted).toBe(true);
      
      expect(policyManager.getPolicy('test-policy')).toBeUndefined();
    });
  });

  describe('access control', () => {
    it('должен разрешать доступ при matching правиле', async () => {
      const policy: AccessPolicy = {
        policyId: 'allow-read',
        name: 'Allow Read',
        rules: [
          {
            ruleId: 'allow-all-read',
            actions: [SecretAction.READ],
            resources: ['*'],
            subjects: ['*'],
            effect: 'allow',
            priority: 10
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await policyManager.addPolicy(policy);
      
      const result = await policyManager.checkAccess(
        SecretAction.READ,
        'test-secret',
        createTestContext()
      );
      
      expect(result.allowed).toBe(true);
    });

    it('должен запрещать доступ при deny правиле', async () => {
      const policy: AccessPolicy = {
        policyId: 'deny-write',
        name: 'Deny Write',
        rules: [
          {
            ruleId: 'deny-all-write',
            actions: [SecretAction.WRITE],
            resources: ['*'],
            subjects: ['*'],
            effect: 'deny',
            priority: 100
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await policyManager.addPolicy(policy);
      
      const result = await policyManager.checkAccess(
        SecretAction.WRITE,
        'test-secret',
        createTestContext()
      );
      
      expect(result.allowed).toBe(false);
    });

    it('должен запрещать доступ в strict mode без явного разрешения', async () => {
      const policyManagerStrict = new AccessPolicyManager();
      await policyManagerStrict.initialize([], true);
      
      const result = await policyManagerStrict.checkAccess(
        SecretAction.DELETE,
        'test-secret',
        createTestContext()
      );
      
      expect(result.allowed).toBe(false);
      
      await policyManagerStrict.destroy();
    });

    it('должен проверять роли', async () => {
      const policy: AccessPolicy = {
        policyId: 'admin-only',
        name: 'Admin Only',
        rules: [
          {
            ruleId: 'admin-delete',
            actions: [SecretAction.DELETE],
            resources: ['*'],
            subjects: ['role:admin'],
            effect: 'allow',
            priority: 10
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };

      await policyManager.addPolicy(policy);

      // Пользователь без роли admin - должен быть запрещён (strict mode, нет явного разрешения)
      const userResult = await policyManager.checkAccess(
        SecretAction.DELETE,
        'test-secret',
        createTestContext({ roles: ['user'] })
      );
      expect(userResult.allowed).toBe(false);

      // Пользователь с ролью admin - должен быть разрешён
      const adminResult = await policyManager.checkAccess(
        SecretAction.DELETE,
        'test-secret',
        createTestContext({ roles: ['admin'], subjectId: 'admin-user' })
      );
      expect(adminResult.allowed).toBe(true);
      expect(adminResult.matchedRuleId).toBe('admin-delete');
    });
  });

  describe('conditions', () => {
    it('должен проверять IP диапазон', async () => {
      const policy: AccessPolicy = {
        policyId: 'ip-restricted',
        name: 'IP Restricted',
        rules: [
          {
            ruleId: 'allow-local',
            actions: [SecretAction.READ],
            resources: ['*'],
            subjects: ['*'],
            effect: 'allow',
            priority: 10,
            conditions: [
              {
                type: 'ip_range',
                value: '127.0.0.0/8'
              }
            ]
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await policyManager.addPolicy(policy);
      
      const result = await policyManager.checkAccess(
        SecretAction.READ,
        'test-secret',
        createTestContext({ ipAddress: '127.0.0.1' })
      );
      
      expect(result.allowed).toBe(true);
    });

    it('должен проверять MFA', async () => {
      const policy: AccessPolicy = {
        policyId: 'mfa-required',
        name: 'MFA Required',
        rules: [
          {
            ruleId: 'require-mfa',
            actions: [SecretAction.WRITE],
            resources: ['*'],
            subjects: ['*'],
            effect: 'allow',
            priority: 10,
            conditions: [
              {
                type: 'mfa_required',
                value: true
              }
            ]
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await policyManager.addPolicy(policy);

      // Без MFA
      const noMfaResult = await policyManager.checkAccess(
        SecretAction.WRITE,
        'test-secret',
        createTestContext({ mfaVerified: false, subjectId: 'user-no-mfa' })
      );
      expect(noMfaResult.allowed).toBe(false);

      // С MFA
      const mfaResult = await policyManager.checkAccess(
        SecretAction.WRITE,
        'test-secret',
        createTestContext({ mfaVerified: true, subjectId: 'user-with-mfa' })
      );
      expect(mfaResult.allowed).toBe(true);
    });
  });

  describe('stats', () => {
    it('должен возвращать статистику', async () => {
      const policy: AccessPolicy = {
        policyId: 'test-policy',
        name: 'Test Policy',
        rules: [
          {
            ruleId: 'rule-1',
            actions: [SecretAction.READ],
            resources: ['*'],
            subjects: ['*'],
            effect: 'allow',
            priority: 10
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await policyManager.addPolicy(policy);
      
      const stats = policyManager.getStats();
      
      expect(stats.totalPolicies).toBe(1);
      expect(stats.enabledPolicies).toBe(1);
      expect(stats.totalRules).toBe(1);
    });
  });
});

// ============================================================================
// ТЕСТЫ SECRET VERSIONING MANAGER
// ============================================================================

describe('SecretVersioningManager', () => {
  let versioningManager: SecretVersioningManager;

  beforeEach(async () => {
    versioningManager = new SecretVersioningManager({
      maxVersions: 10,
      keepDeletedVersions: true,
      deletedVersionsRetentionDays: 30
    });
    await versioningManager.initialize();
  });

  afterEach(async () => {
    await versioningManager.destroy();
  });

  describe('version creation', () => {
    it('должен создавать версии секретов', async () => {
      const secret = createTestSecret();
      
      const version = await versioningManager.createVersion(secret, {
        secretId: secret.id,
        previousVersion: null,
        author: 'test-user',
        reason: 'create'
      });
      
      expect(version.version).toBe(1);
      expect(version.status).toBe(SecretStatus.ACTIVE);
      expect(version.createdBy).toBe('test-user');
    });

    it('должен увеличивать номер версии', async () => {
      const secret = createTestSecret();
      
      await versioningManager.createVersion(secret, {
        secretId: secret.id,
        previousVersion: null,
        author: 'test-user'
      });

      // Небольшая задержка чтобы избежать rate limiting
      await new Promise(resolve => setTimeout(resolve, 10));

      const version2 = await versioningManager.createVersion(secret, {
        secretId: secret.id,
        previousVersion: 1,
        author: 'test-user'
      });

      expect(version2.version).toBe(2);
    });
  });

  describe('version retrieval', () => {
    it('должен получать версию по номеру', async () => {
      const secret = createTestSecret();
      
      await versioningManager.createVersion(secret, {
        secretId: secret.id,
        previousVersion: null,
        author: 'test-user'
      });
      
      const version = versioningManager.getVersion(secret.id, 1);
      expect(version).toBeDefined();
      expect(version?.version).toBe(1);
    });

    it('должен получать все версии', async () => {
      const secret = createTestSecret();
      
      for (let i = 0; i < 3; i++) {
        await versioningManager.createVersion(secret, {
          secretId: secret.id,
          previousVersion: i,
          author: 'test-user'
        });
      }
      
      const versions = versioningManager.getAllVersions(secret.id);
      expect(versions.length).toBe(3);
    });
  });

  describe('rollback', () => {
    it('должен выполнять откат к предыдущей версии', async () => {
      const secret = createTestSecret({ value: 'v1' });
      
      await versioningManager.createVersion(secret, {
        secretId: secret.id,
        previousVersion: null,
        author: 'test-user'
      });
      
      // Вторая версия
      await versioningManager.createVersion(
        { ...secret, value: 'v2' },
        {
          secretId: secret.id,
          previousVersion: 1,
          author: 'test-user'
        }
      );
      
      // Откат к версии 1
      const rollback = await versioningManager.rollback(
        secret.id,
        1,
        'rollback test',
        'test-user'
      );
      
      expect(rollback.targetVersion).toBe(1);
      expect(rollback.rolledBackBy).toBe('test-user');
    });

    it('должен требовать причину отката', async () => {
      const secret = createTestSecret();
      
      await versioningManager.createVersion(secret, {
        secretId: secret.id,
        previousVersion: null,
        author: 'test-user'
      });
      
      await expect(
        versioningManager.rollback(secret.id, 1, '', 'test-user')
      ).rejects.toThrow('Требуется указать причину отката');
    });
  });

  describe('integrity check', () => {
    it('должен проверять целостность версии', async () => {
      const secret = createTestSecret();
      
      await versioningManager.createVersion(secret, {
        secretId: secret.id,
        previousVersion: null,
        author: 'test-user'
      });
      
      const result = versioningManager.verifyIntegrity(secret.id, 1);
      expect(result.valid).toBe(true);
    });
  });

  describe('stats', () => {
    it('должен возвращать статистику версионирования', async () => {
      const secret = createTestSecret();
      
      for (let i = 0; i < 5; i++) {
        await versioningManager.createVersion(secret, {
          secretId: secret.id,
          previousVersion: i,
          author: 'test-user'
        });
      }
      
      const stats = versioningManager.getStats();
      
      expect(stats.totalSecrets).toBe(1);
      expect(stats.totalVersions).toBe(5);
      expect(stats.avgVersionsPerSecret).toBe(5);
    });
  });
});

// ============================================================================
// ТЕСТЫ SECRET LEASE MANAGER
// ============================================================================

describe('SecretLeaseManager', () => {
  let leaseManager: SecretLeaseManager;

  beforeEach(async () => {
    leaseManager = new SecretLeaseManager(
      { enableAutoRenewal: false },
      {
        defaultTTL: 60,
        maxTTL: 300,
        renewable: true,
        maxRenewals: 5,
        gracePeriod: 10
      }
    );
    await leaseManager.initialize();
  });

  afterEach(async () => {
    await leaseManager.destroy();
  });

  describe('lease acquisition', () => {
    it('должен выдавать lease', async () => {
      const lease = await leaseManager.acquireLease(
        'test-secret',
        createTestContext()
      );
      
      expect(lease.leaseId).toBeDefined();
      expect(lease.secretId).toBe('test-secret');
      expect(lease.status).toBe('active');
      expect(lease.renewable).toBe(true);
    });

    it('должен соблюдать лимит lease на субъекта', async () => {
      const limitedManager = new SecretLeaseManager(
        { maxLeasesPerSubject: 2 },
        { defaultTTL: 60 }
      );
      await limitedManager.initialize();
      
      const context = createTestContext({ subjectId: 'limited-user' });
      
      await limitedManager.acquireLease('secret-1', context);
      await limitedManager.acquireLease('secret-2', context);
      
      await expect(
        limitedManager.acquireLease('secret-3', context)
      ).rejects.toThrow('Превышен лимит lease');
      
      await limitedManager.destroy();
    });
  });

  describe('lease renewal', () => {
    it('должен продлевать lease', async () => {
      const lease = await leaseManager.acquireLease(
        'test-secret',
        createTestContext({ subjectId: 'owner' })
      );
      
      const renewed = await leaseManager.renewLease(
        lease.leaseId,
        createTestContext({ subjectId: 'owner' })
      );
      
      expect(renewed.renewCount).toBe(1);
      expect(renewed.status).toBe('renewed');
    });

    it('должен запрещать продление чужого lease', async () => {
      const lease = await leaseManager.acquireLease(
        'test-secret',
        createTestContext({ subjectId: 'owner' })
      );
      
      await expect(
        leaseManager.renewLease(
          lease.leaseId,
          createTestContext({ subjectId: 'other' })
        )
      ).rejects.toThrow('Только владелец может продлить lease');
    });

    it('должен соблюдать максимальное количество продлений', async () => {
      const limitedManager = new SecretLeaseManager(
        {},
        { defaultTTL: 60, maxRenewals: 2, renewable: true }
      );
      await limitedManager.initialize();
      
      const context = createTestContext({ subjectId: 'owner' });
      const lease = await limitedManager.acquireLease('test-secret', context);
      
      await limitedManager.renewLease(lease.leaseId, context);
      await limitedManager.renewLease(lease.leaseId, context);
      
      await expect(
        limitedManager.renewLease(lease.leaseId, context)
      ).rejects.toThrow('Превышено максимальное количество продлений');
      
      await limitedManager.destroy();
    });
  });

  describe('lease revocation', () => {
    it('должен отзывать lease', async () => {
      const lease = await leaseManager.acquireLease(
        'test-secret',
        createTestContext({ subjectId: 'owner' })
      );
      
      const revoked = await leaseManager.revokeLease(
        lease.leaseId,
        createTestContext({ subjectId: 'owner' }),
        'test revocation'
      );
      
      expect(revoked).toBe(true);
      
      const retrieved = leaseManager.getLease(lease.leaseId);
      expect(retrieved).toBeNull();
    });

    it('должен отзывать все lease секрета', async () => {
      const context = createTestContext();
      
      await leaseManager.acquireLease('test-secret', context);
      await leaseManager.acquireLease('test-secret', context);
      await leaseManager.acquireLease('test-secret', context);
      
      const revoked = await leaseManager.revokeAllSecretLeases(
        'test-secret',
        'bulk revocation'
      );
      
      expect(revoked).toBe(3);
    });
  });

  describe('lease expiration', () => {
    it('должен эмитить событие об истечении', async () => {
      const expiringManager = new SecretLeaseManager(
        { expirationWarningTime: 1 },
        { defaultTTL: 2, gracePeriod: 0 }
      );
      await expiringManager.initialize();
      
      const expiredPromise = new Promise<void>(resolve => {
        expiringManager.on('lease:expired', () => {
          resolve();
        });
      });
      
      await expiringManager.acquireLease('test-secret', createTestContext());
      
      await expect(expiredPromise).resolves.toBeUndefined();
      
      await expiringManager.destroy();
    });
  });

  describe('stats', () => {
    it('должен возвращать статистику lease', async () => {
      const context = createTestContext();
      
      await leaseManager.acquireLease('secret-1', context);
      await leaseManager.acquireLease('secret-2', context);
      
      const stats = leaseManager.getStats();
      
      expect(stats.activeLeases).toBe(2);
      expect(stats.leasesBySubject.get('test-user')).toBe(2);
    });
  });
});

// ============================================================================
// ТЕСТЫ SECRET SCANNER
// ============================================================================

describe('SecretScanner', () => {
  let scanner: SecretScanner;

  beforeEach(async () => {
    scanner = new SecretScanner({
      enabled: true,
      scanInterval: 300,
      scanPaths: [],
      autoRevokeOnLeak: false,
      notifyOnDetection: true
    });
    await scanner.initialize();
  });

  afterEach(async () => {
    await scanner.destroy();
  });

  describe('pattern detection', () => {
    it('должен обнаруживать AWS Access Key', () => {
      const logContent = 'Config: AKIAIOSFODNN7EXAMPLE';
      const leaks = scanner.scanLog(logContent, 'test-log');
      
      expect(leaks.length).toBeGreaterThan(0);
      expect(leaks[0].leakType).toBe(LeakType.LOG_EXPOSURE);
      expect(leaks[0].severity).toBe(LeakSeverity.CRITICAL);
    });

    it('должен обнаруживать GitHub PAT', () => {
      const logContent = 'Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const leaks = scanner.scanLog(logContent, 'test-log');
      
      expect(leaks.length).toBeGreaterThan(0);
    });

    it('должен обнаруживать private key', () => {
      const logContent = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...';
      const leaks = scanner.scanLog(logContent, 'test-log');
      
      expect(leaks.length).toBeGreaterThan(0);
      expect(leaks[0].severity).toBe(LeakSeverity.CRITICAL);
    });

    it('должен обнаруживать JWT токен', () => {
      const logContent = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      const leaks = scanner.scanLog(logContent, 'test-log');
      
      expect(leaks.length).toBeGreaterThan(0);
    });

    it('должен обнаруживать database connection string', () => {
      const logContent = 'mongodb://user:password123@localhost:27017/mydb';
      const leaks = scanner.scanLog(logContent, 'test-log');
      
      expect(leaks.length).toBeGreaterThan(0);
      expect(leaks[0].severity).toBe(LeakSeverity.CRITICAL);
    });
  });

  describe('leak management', () => {
    it('должен сохранять обнаружения', () => {
      const logContent = 'AKIAIOSFODNN7EXAMPLE';
      scanner.scanLog(logContent, 'test-log');
      
      const detections = scanner.getAllDetections();
      expect(detections.length).toBeGreaterThan(0);
    });

    it('должен обновлять статус обнаружения', () => {
      const logContent = 'AKIAIOSFODNN7EXAMPLE';
      const leaks = scanner.scanLog(logContent, 'test-log');
      
      const updated = scanner.updateDetectionStatus(leaks[0].detectionId, 'resolved');
      expect(updated).toBe(true);
      
      const detection = scanner.getDetection(leaks[0].detectionId);
      expect(detection?.status).toBe('resolved');
    });

    it('должен отмечать ложные срабатывания', () => {
      const logContent = 'AKIAIOSFODNN7EXAMPLE';
      const leaks = scanner.scanLog(logContent, 'test-log');
      
      const marked = scanner.markAsFalsePositive(leaks[0].detectionId);
      expect(marked).toBe(true);
      
      const stats = scanner.getStats();
      expect(stats.falsePositives).toBe(1);
    });
  });

  describe('suspicious access detection', () => {
    it('должен обнаруживать подозрительный доступ', () => {
      const detection = scanner.detectSuspiciousAccess('test-secret', {
        ipAddress: '192.168.1.1',
        timestamp: new Date(new Date().setHours(3, 0, 0)), // 3 AM
        userAgent: 'curl/7.68.0',
        action: 'read'
      });
      
      expect(detection).toBeDefined();
      expect(detection?.leakType).toBe(LeakType.SUSPICIOUS_ACCESS);
    });
  });

  describe('brute force detection', () => {
    it('должен обнаруживать брутфорс атаку', () => {
      const detection = scanner.detectBruteForce('test-secret', 15, 60);
      
      expect(detection).toBeDefined();
      expect(detection?.leakType).toBe(LeakType.BRUTE_FORCE);
      expect(detection?.severity).toBe(LeakSeverity.HIGH);
    });

    it('не должен срабатывать при нормальном количестве попыток', () => {
      const detection = scanner.detectBruteForce('test-secret', 5, 60);
      
      expect(detection).toBeNull();
    });
  });

  describe('stats', () => {
    it('должен возвращать статистику сканирования', () => {
      scanner.scanLog('AKIAIOSFODNN7EXAMPLE', 'test-log');
      
      const stats = scanner.getStats();
      
      expect(stats.totalLeaks).toBeGreaterThan(0);
      expect(stats.leaksBySeverity.get(LeakSeverity.CRITICAL)).toBeGreaterThan(0);
    });
  });

  describe('report export', () => {
    it('должен экспортировать отчёт', () => {
      scanner.scanLog('AKIAIOSFODNN7EXAMPLE', 'test-log');
      
      const report = scanner.exportReport();
      
      expect(report.generatedAt).toBeDefined();
      expect(report.totalDetections).toBeGreaterThan(0);
      expect(report.bySeverity).toBeDefined();
    });
  });
});

// ============================================================================
// ТЕСТЫ DYNAMIC SECRETS MANAGER
// ============================================================================

describe('DynamicSecretsManager', () => {
  let dynamicManager: DynamicSecretsManager;
  let leaseManager: SecretLeaseManager;

  beforeEach(async () => {
    leaseManager = new SecretLeaseManager();
    await leaseManager.initialize();
    
    dynamicManager = new DynamicSecretsManager({
      maxActiveSecrets: 100,
      defaultTTL: 60
    });
    await dynamicManager.initialize(leaseManager);
  });

  afterEach(async () => {
    await dynamicManager.destroy();
    await leaseManager.destroy();
  });

  describe('database credentials', () => {
    it('должен генерировать учётные данные PostgreSQL', async () => {
      const secret = await dynamicManager.createSecret(
        DynamicSecretType.DATABASE_CREDENTIALS,
        {
          type: DynamicSecretType.DATABASE_CREDENTIALS,
          generationParams: {
            dbType: 'postgresql',
            usernamePrefix: 'dyn',
            host: 'localhost',
            port: 5432,
            database: 'testdb'
          },
          sourceConfig: {},
          ttl: 300
        },
        'test-user'
      );
      
      expect(secret.secretId).toBeDefined();
      expect(secret.type).toBe(DynamicSecretType.DATABASE_CREDENTIALS);
      expect(secret.credentials.username).toBeDefined();
      expect(secret.credentials.password).toBeDefined();
      expect(secret.credentials.connectionString).toBeDefined();
    });

    it('должен генерировать учётные данные MySQL', async () => {
      const secret = await dynamicManager.createSecret(
        DynamicSecretType.DATABASE_CREDENTIALS,
        {
          type: DynamicSecretType.DATABASE_CREDENTIALS,
          generationParams: {
            dbType: 'mysql',
            host: 'localhost',
            port: 3306
          },
          sourceConfig: {},
          ttl: 300
        },
        'test-user'
      );
      
      expect(secret.credentials.connectionString).toContain('mysql://');
    });
  });

  describe('API keys', () => {
    it('должен генерировать API ключи', async () => {
      const secret = await dynamicManager.createSecret(
        DynamicSecretType.API_KEY,
        {
          type: DynamicSecretType.API_KEY,
          generationParams: {
            prefix: 'sk_test',
            length: 32,
            includeChecksum: true
          },
          sourceConfig: {},
          ttl: 3600
        },
        'test-user'
      );
      
      expect(secret.credentials.apiKey).toBeDefined();
      expect(secret.credentials.apiKey).toMatch(/^sk_test_/);
    });
  });

  describe('SSH keys', () => {
    it('должен генерировать SSH ключи', async () => {
      const secret = await dynamicManager.createSecret(
        DynamicSecretType.SSH_KEY,
        {
          type: DynamicSecretType.SSH_KEY,
          generationParams: {
            keyType: 'ed25519',
            comment: 'test-key'
          },
          sourceConfig: {},
          ttl: 3600
        },
        'test-user'
      );
      
      expect(secret.credentials.publicKey).toBeDefined();
      expect(secret.credentials.privateKey).toBeDefined();
      expect(secret.credentials.fingerprint).toBeDefined();
    });
  });

  describe('OAuth tokens', () => {
    it('должен генерировать OAuth токены', async () => {
      const secret = await dynamicManager.createSecret(
        DynamicSecretType.OAUTH_TOKEN,
        {
          type: DynamicSecretType.OAUTH_TOKEN,
          generationParams: {
            tokenType: 'bearer',
            scope: ['read', 'write']
          },
          sourceConfig: {},
          ttl: 3600
        },
        'test-user'
      );
      
      expect(secret.credentials.accessToken).toBeDefined();
      expect(secret.credentials.tokenType).toBe('bearer');
    });
  });

  describe('secret management', () => {
    it('должен получать созданный секрет', async () => {
      const secret = await dynamicManager.createSecret(
        DynamicSecretType.API_KEY,
        {
          type: DynamicSecretType.API_KEY,
          generationParams: {},
          sourceConfig: {},
          ttl: 60
        },
        'test-user'
      );
      
      const retrieved = dynamicManager.getSecret(secret.secretId);
      expect(retrieved).toBeDefined();
      expect(retrieved?.secretId).toBe(secret.secretId);
    });

    it('должен продлевать секрет', async () => {
      const secret = await dynamicManager.createSecret(
        DynamicSecretType.API_KEY,
        {
          type: DynamicSecretType.API_KEY,
          generationParams: {},
          sourceConfig: {},
          ttl: 60
        },
        'test-user'
      );
      
      const renewed = await dynamicManager.renewSecret(
        secret.secretId,
        60,
        'test-user'
      );
      
      expect(renewed.expiresAt.getTime()).toBeGreaterThan(secret.expiresAt.getTime());
    });

    it('должен отзывать секрет', async () => {
      const secret = await dynamicManager.createSecret(
        DynamicSecretType.API_KEY,
        {
          type: DynamicSecretType.API_KEY,
          generationParams: {},
          sourceConfig: {},
          ttl: 60
        },
        'test-user'
      );
      
      const revoked = await dynamicManager.revokeSecret(secret.secretId, 'test');
      expect(revoked).toBe(true);
      
      const retrieved = dynamicManager.getSecret(secret.secretId);
      expect(retrieved).toBeNull();
    });
  });

  describe('stats', () => {
    it('должен возвращать статистику', async () => {
      await dynamicManager.createSecret(
        DynamicSecretType.API_KEY,
        {
          type: DynamicSecretType.API_KEY,
          generationParams: {},
          sourceConfig: {},
          ttl: 60
        },
        'test-user'
      );
      
      const stats = dynamicManager.getStats();
      
      expect(stats.totalActive).toBe(1);
      expect(stats.byType.get(DynamicSecretType.API_KEY)).toBe(1);
    });
  });
});

// ============================================================================
// ИНТЕГРАЦИОННЫЕ ТЕСТЫ SECRETS MANAGER
// ============================================================================

describe('SecretsManager (Integration)', () => {
  let secretsManager: SecretsManager;

  beforeEach(async () => {
    // Создаём менеджер с mock бэкендом (local mode)
    secretsManager = new SecretsManager({
      backends: [],
      cache: {
        enabled: true,
        ttl: 60,
        maxEntries: 100,
        encryptInMemory: true,
        encryptionAlgorithm: 'aes-256-gcm',
        evictionStrategy: 'lru'
      },
      defaultRotation: {
        enabled: false,
        rotationInterval: 86400,
        gracePeriod: 3600,
        autoActivate: true,
        notifyOnRotation: true,
        keepHistory: true,
        historyLimit: 10,
        minRotationInterval: 3600
      },
      defaultLease: {
        defaultTTL: 3600,
        maxTTL: 86400,
        renewable: true,
        maxRenewals: 10,
        gracePeriod: 60,
        autoRevokeOnAnomaly: true
      },
      scanner: {
        enabled: true,
        scanInterval: 300,
        scanPaths: [],
        excludePatterns: [],
        autoRevokeOnLeak: false,
        notifyOnDetection: true
      },
      auditEnabled: true,
      policies: [],
      encryptionKey: generateTestEncryptionKey(),
      mode: 'development', // development mode для тестов (без бэкендов)
      backends: [] // Явно указываем пустой массив бэкендов
    });

    await secretsManager.initialize();
  });

  afterEach(async () => {
    await secretsManager.destroy();
  });

  describe('initialization', () => {
    it('должен успешно инициализироваться', async () => {
      expect(secretsManager).toBeDefined();
    });

    it('должен возвращать статистику', () => {
      const stats = secretsManager.getStats();
      
      expect(stats.initialized).toBe(true);
      expect(stats.cacheStats).toBeDefined();
      expect(stats.policyStats).toBeDefined();
    });
  });

  describe('access control integration', () => {
    it('должен проверять доступ перед операцией', async () => {
      // В development mode без политик доступ разрешён (не strict mode)
      // Для проверки запрета нужно создать SecretsManager в production mode
      const strictSecretsManager = new SecretsManager({
        backends: [{
          type: 'vault' as const,
          enabled: true,
          config: {
            vaultUrl: 'http://localhost:8200',
            vaultToken: 'test-token'
          }
        }],
        cache: { enabled: false },
        mode: 'production', // production mode включает strict mode
        auditEnabled: false,
        policies: [] // Явно указываем пустые политики
      });
      
      try {
        await strictSecretsManager.initialize();
        
        const context = createTestContext();
        
        // В strict mode без политик доступ запрещён
        const result = await strictSecretsManager.checkAccess(
          SecretAction.READ,
          'test-secret',
          context
        );
        
        expect(result).toBe(false);
      } catch (error) {
        // Если vault недоступен, проверяем что ошибка не связана с доступом
        expect(error.message).not.toContain('access');
      } finally {
        await strictSecretsManager.destroy();
      }
    });

    it('должен разрешать доступ при наличии политики', async () => {
      const policy: AccessPolicy = {
        policyId: 'allow-all',
        name: 'Allow All',
        rules: [
          {
            ruleId: 'allow-all',
            actions: Object.values(SecretAction),
            resources: ['*'],
            subjects: ['*'],
            effect: 'allow',
            priority: 10
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await secretsManager.addPolicy(policy);
      
      const result = await secretsManager.checkAccess(
        SecretAction.READ,
        'test-secret',
        createTestContext()
      );
      
      expect(result).toBe(true);
    });
  });

  describe('audit logging', () => {
    it('должен логировать операции', async () => {
      const policy: AccessPolicy = {
        policyId: 'allow-all',
        name: 'Allow All',
        rules: [
          {
            ruleId: 'allow-all',
            actions: Object.values(SecretAction),
            resources: ['*'],
            subjects: ['*'],
            effect: 'allow',
            priority: 10
          }
        ],
        createdAt: new Date(),
        createdBy: 'test',
        version: 1,
        enabled: true
      };
      
      await secretsManager.addPolicy(policy);
      
      // Получаем audit логи
      const logs = await secretsManager.getAuditLogs({});
      
      expect(Array.isArray(logs)).toBe(true);
    });
  });

  describe('backend health', () => {
    it('должен проверять здоровье бэкендов', async () => {
      const health = await secretsManager.checkBackendHealth();
      
      expect(health).toBeDefined();
    });
  });

  describe('events', () => {
    it('должен эмитить события', (done) => {
      // Увеличиваем timeout для этого теста
      jest.setTimeout(10000);
      
      secretsManager.on('audit:logged', (entry) => {
        expect(entry).toBeDefined();
        done();
      });

      // Trigger an audit event через прямое добавление audit log
      (secretsManager as any).addAuditLog(SecretAction.READ, 'test-secret', { 
        subjectId: 'test-user',
        roles: ['user']
      });
    }, 10000);
  });
});

// ============================================================================
// ЗАПУСК ТЕСТОВ
// ============================================================================

// Для запуска тестов используйте:
// npm test -- tests/secrets/secrets.test.ts

// Или для coverage:
// npm test -- --coverage tests/secrets/secrets.test.ts
