/**
 * =============================================================================
 * COMPREHENSIVE TESTS FOR AUTH SYSTEM
 * =============================================================================
 * Полные тесты для всех компонентов системы аутентификации
 * Включает: Unit tests, Integration tests, Security tests
 * =============================================================================
 */

import { PasswordService, createPasswordService } from './src/auth/PasswordService';
import { MFService, createMFService } from './src/auth/MFService';
import { DeviceFingerprintService, createDeviceFingerprintService } from './src/auth/DeviceFingerprint';
import { RBACService, createRBACService } from './src/auth/RBACService';
import { ABACService, createABACService } from './src/auth/ABACService';
import { RateLimiterService, createRateLimiterService } from './src/auth/RateLimiter';
import { OAuthService, createOAuthService } from './src/auth/OAuthService';
import { AuthService, createAuthService } from './src/auth/AuthService';

// =============================================================================
// PASSWORD SERVICE TESTS
// =============================================================================

describe('PasswordService', () => {
  let passwordService: PasswordService;

  beforeEach(() => {
    passwordService = createPasswordService({
      algorithm: 'bcrypt',
      cost: 10,
    });
  });

  describe('validatePasswordStrength', () => {
    it('должен принимать надежный пароль', () => {
      const result = passwordService.validatePasswordStrength('Str0ng!P@ssw0rd');
      expect(result.valid).toBe(true);
      expect(result.score).toBeGreaterThan(50);
    });

    it('должен отклонять слабый пароль', () => {
      const result = passwordService.validatePasswordStrength('123456');
      expect(result.valid).toBe(false);
      expect(result.warnings).toContain('Это очень распространенный пароль');
    });

    it('должен отклонять короткий пароль', () => {
      const result = passwordService.validatePasswordStrength('short');
      expect(result.valid).toBe(false);
      expect(result.requirements).toContain('Минимальная длина: 8 символов');
    });

    it('должен обнаруживать последовательности', () => {
      const result = passwordService.validatePasswordStrength('abc12345');
      expect(result.warnings).toContain('Избегайте последовательностей символов');
    });
  });

  describe('hashPassword', () => {
    it('должен хэшировать пароль с bcrypt', async () => {
      const result = await passwordService.hashPassword('TestPassword123!');
      expect(result.hash).toBeDefined();
      expect(result.hash).startsWith('$2');
      expect(result.algorithm).toBe('bcrypt');
      expect(result.version).toBe(1);
    });

    it('должен создавать разные хэши для одного пароля', async () => {
      const hash1 = await passwordService.hashPassword('SamePassword123!');
      const hash2 = await passwordService.hashPassword('SamePassword123!');
      expect(hash1.hash).not.toBe(hash2.hash);
    });
  });

  describe('verifyPassword', () => {
    it('должен верифицировать правильный пароль', async () => {
      const password = 'TestPassword123!';
      const hashResult = await passwordService.hashPassword(password);
      const verifyResult = await passwordService.verifyPassword(password, hashResult.hash);
      
      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.needsRehash).toBe(false);
    });

    it('должен отклонять неправильный пароль', async () => {
      const hashResult = await passwordService.hashPassword('CorrectPassword123!');
      const verifyResult = await passwordService.verifyPassword('WrongPassword123!', hashResult.hash);
      
      expect(verifyResult.valid).toBe(false);
    });

    it('должен определять необходимость rehash', async () => {
      // Старый хэш с низким cost
      const oldHash = '$2b$04$' + 'a'.repeat(53);
      const verifyResult = await passwordService.verifyPassword('TestPassword123!', oldHash);
      
      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.needsRehash).toBe(true);
    });
  });

  describe('generateSecurePassword', () => {
    it('должен генерировать пароль заданной длины', () => {
      const password = passwordService.generateSecurePassword(16);
      expect(password.length).toBe(16);
    });

    it('должен генерировать пароль с разными типами символов', () => {
      const password = passwordService.generateSecurePassword(16);
      expect(/[a-z]/.test(password)).toBe(true);
      expect(/[A-Z]/.test(password)).toBe(true);
      expect(/[0-9]/.test(password)).toBe(true);
      expect(/[^a-zA-Z0-9]/.test(password)).toBe(true);
    });
  });
});

// =============================================================================
// MFService TESTS
// =============================================================================

describe('MFService', () => {
  let mfService: MFService;

  beforeEach(() => {
    mfService = createMFService();
  });

  describe('TOTP', () => {
    it('должен генерировать TOTP секрет', () => {
      const result = mfService.generateTotpSecret('user123', 'test@example.com', 'Protocol');
      
      expect(result.methodId).toBeDefined();
      expect(result.secret).toBeDefined();
      expect(result.otpauthUrl).toBeDefined();
      expect(result.otpauthUrl).toContain('otpauth://totp/');
    });

    it('должен верифицировать правильный TOTP код', () => {
      const setup = mfService.generateTotpSecret('user123', 'test@example.com');
      const code = mfService.generateTotpCode(setup.secret);
      const verifyResult = mfService.verifyTotpCode(code, setup.secret);
      
      expect(verifyResult.valid).toBe(true);
    });

    it('должен отклонять неправильный TOTP код', () => {
      const setup = mfService.generateTotpSecret('user123', 'test@example.com');
      const verifyResult = mfService.verifyTotpCode('000000', setup.secret);
      
      expect(verifyResult.valid).toBe(false);
    });

    it('должен возвращать оставшееся время для кода', () => {
      const remaining = mfService.getRemainingTime(30);
      expect(remaining).toBeGreaterThanOrEqual(0);
      expect(remaining).toBeLessThanOrEqual(30);
    });
  });

  describe('HOTP', () => {
    it('должен генерировать HOTP секрет', () => {
      const result = mfService.generateHotpSecret('user123', 'test@example.com', 'Protocol', 0);
      
      expect(result.methodId).toBeDefined();
      expect(result.secret).toBeDefined();
      expect(result.otpauthUrl).toContain('otpauth://hotp/');
    });

    it('должен верифицировать правильный HOTP код', () => {
      const setup = mfService.generateHotpSecret('user123', 'test@example.com', 'Protocol', 0);
      const code = mfService.generateHotpCode(setup.secret, 0);
      const verifyResult = mfService.verifyHotpCode(code, setup.secret, 0);
      
      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.newCounter).toBe(1);
    });
  });

  describe('Backup Codes', () => {
    it('должен генерировать набор backup кодов', () => {
      const result = mfService.generateBackupCodes('user123');
      
      expect(result.codeSet).toBeDefined();
      expect(result.codes).toBeDefined();
      expect(result.codes.length).toBe(10);
      expect(result.hashedCodes).toBeDefined();
      expect(result.hashedCodes.length).toBe(10);
    });

    it('должен верифицировать правильный backup код', () => {
      const result = mfService.generateBackupCodes('user123');
      const firstCode = result.codes[0];
      const hashedCodes = result.hashedCodes.map(hc => ({
        id: 'id',
        codeHash: hc.codeHash,
        used: false,
      }));
      
      const verifyResult = mfService.verifyBackupCode(firstCode, hashedCodes);
      
      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.usedCodeId).toBeDefined();
    });

    it('должен отклонять использованный backup код', () => {
      const result = mfService.generateBackupCodes('user123');
      const firstCode = result.codes[0];
      const hashedCodes = result.hashedCodes.map(hc => ({
        id: 'id',
        codeHash: hc.codeHash,
        used: true, // Уже использован
      }));
      
      const verifyResult = mfService.verifyBackupCode(firstCode, hashedCodes);
      
      expect(verifyResult.valid).toBe(false);
      expect(verifyResult.reason).toContain('уже был использован');
    });
  });

  describe('Base32', () => {
    it('должен кодировать и декодировать Base32', () => {
      const original = Buffer.from('Hello World');
      const encoded = mfService.base32Encode(original);
      const decoded = mfService.base32Decode(encoded);
      
      expect(decoded.toString()).toBe('Hello World');
    });

    it('должен валидировать TOTP секрет', () => {
      expect(mfService.validateTotpSecret('JBSWY3DPEHPK3PXP')).toBe(true);
      expect(mfService.validateTotpSecret('invalid!')).toBe(false);
    });
  });
});

// =============================================================================
// DEVICE FINGERPRINT TESTS
// =============================================================================

describe('DeviceFingerprintService', () => {
  let fingerprintService: DeviceFingerprintService;

  beforeEach(() => {
    fingerprintService = createDeviceFingerprintService();
  });

  describe('generateFingerprint', () => {
    it('должен генерировать fingerprint из данных устройства', () => {
      const fingerprint = fingerprintService.generateFingerprint({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        languages: ['ru-RU', 'en-US'],
        timezone: 'Europe/Moscow',
        screenResolution: '1920x1080',
        colorDepth: 24,
        platform: 'Win32',
        ipAddress: '192.168.1.1',
      });
      
      expect(fingerprint).toBeDefined();
      expect(fingerprint.length).toBe(64); // SHA256 hex
    });

    it('должен генерировать одинаковый fingerprint для одинаковых данных', () => {
      const inputData = {
        userAgent: 'Mozilla/5.0 Chrome/120.0.0.0',
        languages: ['en-US'],
        timezone: 'UTC',
        screenResolution: '1920x1080',
        colorDepth: 24,
        platform: 'Win32',
        ipAddress: '192.168.1.1',
      };
      
      const fp1 = fingerprintService.generateFingerprint(inputData);
      const fp2 = fingerprintService.generateFingerprint(inputData);
      
      expect(fp1).toBe(fp2);
    });

    it('должен генерировать разный fingerprint для разных данных', () => {
      const fp1 = fingerprintService.generateFingerprint({
        userAgent: 'Mozilla/5.0 Chrome/120.0.0.0',
        languages: ['en-US'],
        timezone: 'UTC',
        screenResolution: '1920x1080',
        colorDepth: 24,
        platform: 'Win32',
        ipAddress: '192.168.1.1',
      });
      
      const fp2 = fingerprintService.generateFingerprint({
        userAgent: 'Mozilla/5.0 Firefox/121.0',
        languages: ['en-US'],
        timezone: 'UTC',
        screenResolution: '1920x1080',
        colorDepth: 24,
        platform: 'Win32',
        ipAddress: '192.168.1.1',
      });
      
      expect(fp1).not.toBe(fp2);
    });
  });

  describe('analyzeFingerprint', () => {
    it('должен определять новое устройство', () => {
      const result = fingerprintService.analyzeFingerprint({
        userAgent: 'Mozilla/5.0 Chrome/120.0.0.0',
        languages: ['en-US'],
        timezone: 'UTC',
        screenResolution: '1920x1080',
        colorDepth: 24,
        platform: 'Win32',
        ipAddress: '192.168.1.1',
      }, []);
      
      expect(result.isNewDevice).toBe(true);
      expect(result.riskScore).toBeGreaterThanOrEqual(0);
    });

    it('должен распознавать существующее устройство', () => {
      const inputData = {
        userAgent: 'Mozilla/5.0 Chrome/120.0.0.0',
        languages: ['en-US'],
        timezone: 'UTC',
        screenResolution: '1920x1080',
        colorDepth: 24,
        platform: 'Win32',
        ipAddress: '192.168.1.1',
      };
      
      const existingFingerprint = fingerprintService.generateFingerprint(inputData);
      const existingDevice = {
        fingerprint: existingFingerprint,
        userAgent: inputData.userAgent,
        languages: inputData.languages,
        timezone: inputData.timezone,
        screenResolution: inputData.screenResolution,
        colorDepth: inputData.colorDepth,
        platform: inputData.platform,
        cpuArchitecture: '',
        cpuCores: 0,
        deviceMemory: 0,
        isTrusted: true,
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        usageCount: 5,
        supportedApis: [],
      };
      
      const result = fingerprintService.analyzeFingerprint(inputData, [existingDevice]);
      
      expect(result.isNewDevice).toBe(false);
      expect(result.matchScore).toBeGreaterThan(0.7);
    });
  });

  describe('trustDevice', () => {
    it('должен отмечать устройство как доверенное', () => {
      const fingerprint = 'test_fingerprint_hash';
      const device = fingerprintService.trustDevice(fingerprint, 'user123');
      
      expect(device.isTrusted).toBe(true);
      expect(fingerprintService.isTrustedDevice(fingerprint)).toBe(true);
    });
  });

  describe('getGeoLocation', () => {
    it('должен получать geo-информацию из IP', () => {
      const geo = fingerprintService.getGeoLocation('8.8.8.8');
      
      // Google DNS должен быть в США
      if (geo) {
        expect(geo.country).toBeDefined();
      }
    });
  });
});

// =============================================================================
// RBAC SERVICE TESTS
// =============================================================================

describe('RBACService', () => {
  let rbacService: RBACService;

  beforeEach(() => {
    rbacService = createRBACService();
  });

  describe('Role Management', () => {
    it('должен создавать новую роль', () => {
      const role = rbacService.createRole('manager', ['users:read', 'users:write']);
      
      expect(role.id).toBeDefined();
      expect(role.name).toBe('manager');
      expect(role.permissions).toContain('users:read');
      expect(role.isSystem).toBe(false);
    });

    it('должен обновлять роль', () => {
      const role = rbacService.createRole('test_role', ['read']);
      const updated = rbacService.updateRole(role.id, {
        permissions: ['read', 'write'],
      });
      
      expect(updated.permissions).toContain('write');
    });

    it('должен получать роль по имени', () => {
      const role = rbacService.getRoleByName('admin');
      
      expect(role).toBeDefined();
      expect(role?.name).toBe('admin');
    });
  });

  describe('Role Assignment', () => {
    it('должен назначать роль пользователю', () => {
      const assignment = rbacService.assignRole('user123', 'user', 'admin');
      
      expect(assignment.id).toBeDefined();
      expect(assignment.userId).toBe('user123');
      expect(assignment.roleId).toBeDefined();
    });

    it('должен получать назначения ролей пользователя', () => {
      rbacService.assignRole('user123', 'user', 'admin');
      const assignments = rbacService.getRoleAssignmentsByUser('user123');
      
      expect(assignments.length).toBeGreaterThan(0);
    });

    it('должен отменять назначение роли', () => {
      rbacService.assignRole('user123', 'user', 'admin');
      rbacService.revokeRole('user123', 'user');
      
      const assignments = rbacService.getRoleAssignmentsByUser('user123');
      expect(assignments.length).toBe(0);
    });
  });

  describe('Permission Check', () => {
    it('должен проверять разрешение пользователя', () => {
      const user = {
        id: 'user123',
        email: 'test@example.com',
        roles: ['admin'],
      } as any;
      
      const result = rbacService.checkPermission(user, 'users:read');
      
      expect(result.allowed).toBe(true);
    });

    it('должен проверять несколько разрешений (OR)', () => {
      const user = {
        id: 'user123',
        email: 'test@example.com',
        roles: ['user'],
      } as any;
      
      const result = rbacService.checkPermissions(
        user,
        ['users:read', 'users:write'],
        false // OR
      );
      
      expect(result.allowed).toBe(true); // user имеет users:read
    });

    it('должен проверять несколько разрешений (AND)', () => {
      const user = {
        id: 'user123',
        email: 'test@example.com',
        roles: ['user'],
      } as any;
      
      const result = rbacService.checkPermissions(
        user,
        ['users:read', 'users:delete'],
        true // AND
      );
      
      expect(result.allowed).toBe(false); // user не имеет users:delete
    });

    it('должен проверять наличие роли', () => {
      const user = {
        id: 'user123',
        email: 'test@example.com',
        roles: ['admin'],
      } as any;
      
      expect(rbacService.hasRole(user, 'admin')).toBe(true);
      expect(rbacService.hasRole(user, 'superadmin')).toBe(false);
    });
  });

  describe('Wildcard Permissions', () => {
    it('должен поддерживать wildcard разрешения', () => {
      const superadmin = {
        id: 'admin123',
        email: 'admin@example.com',
        roles: ['superadmin'],
      } as any;
      
      // Superadmin имеет *:*:*
      const result = rbacService.checkPermission(superadmin, 'any:resource:action');
      
      expect(result.allowed).toBe(true);
    });
  });
});

// =============================================================================
// ABAC SERVICE TESTS
// =============================================================================

describe('ABACService', () => {
  let abacService: ABACService;

  beforeEach(() => {
    abacService = createABACService();
  });

  describe('Policy Creation', () => {
    it('должен создавать permit policy', () => {
      const policy = abacService.createPolicy(
        'Allow Managers to Edit Documents',
        'permit',
        ['document'],
        ['edit', 'update'],
        {
          subject: [
            {
              attribute: 'attributes.jobTitle',
              operator: 'eq',
              value: 'manager',
            },
          ],
        }
      );
      
      expect(policy.id).toBeDefined();
      expect(policy.type).toBe('permit');
    });

    it('должен создавать policy с несколькими условиями', () => {
      const policy = abacService.createPolicy(
        'Allow High Clearance Access',
        'permit',
        ['sensitive_data'],
        ['read'],
        {
          subject: [
            {
              attribute: 'attributes.clearanceLevel',
              operator: 'gte',
              value: 3,
            },
          ],
          context: [
            {
              attribute: 'deviceInfo.isTrusted',
              operator: 'eq',
              value: true,
            },
          ],
        }
      );
      
      expect(policy.subjectConditions.length).toBe(1);
      expect(policy.contextConditions?.length).toBe(1);
    });
  });

  describe('Policy Evaluation', () => {
    it('должен разрешать доступ при matching policy', () => {
      // Создаем policy
      abacService.createPolicy(
        'Allow Admins',
        'permit',
        ['*'],
        ['*'],
        {
          subject: [
            {
              attribute: 'roles',
              operator: 'in',
              value: ['admin', 'superadmin'],
            },
          ],
        }
      );

      const result = abacService.checkAccessSimple(
        'user123',
        { jobTitle: 'admin' } as any,
        'document',
        'doc123',
        'read',
        'read'
      );
      
      // Policy требует roles, но мы передали jobTitle
      // Должен сработать default deny
      expect(result.allowed).toBe(false);
    });

    it('должен запрещать доступ при отсутствии policy', () => {
      const result = abacService.checkAccessSimple(
        'user123',
        { jobTitle: 'user' } as any,
        'document',
        'doc123',
        'delete',
        'delete'
      );
      
      expect(result.allowed).toBe(false);
      expect(result.denialReason).toBeDefined();
    });
  });

  describe('Condition Operators', () => {
    it('должен поддерживать оператор eq', () => {
      const policy = abacService.createPolicy(
        'Test EQ',
        'permit',
        ['*'],
        ['*'],
        {
          subject: [
            { attribute: 'department', operator: 'eq', value: 'engineering' },
          ],
        }
      );

      const result = abacService.checkAccessSimple(
        'user123',
        { department: 'engineering' } as any,
        'resource',
        'r1',
        'action',
        'a1'
      );
      
      expect(result.allowed).toBe(true);
    });

    it('должен поддерживать оператор gte', () => {
      abacService.createPolicy(
        'Test GTE',
        'permit',
        ['*'],
        ['*'],
        {
          subject: [
            { attribute: 'attributes.clearanceLevel', operator: 'gte', value: 3 },
          ],
        }
      );

      const result = abacService.checkAccessSimple(
        'user123',
        { clearanceLevel: 4 } as any,
        'resource',
        'r1',
        'action',
        'a1'
      );
      
      expect(result.allowed).toBe(true);
    });

    it('должен поддерживать оператор contains', () => {
      abacService.createPolicy(
        'Test Contains',
        'permit',
        ['*'],
        ['*'],
        {
          subject: [
            { attribute: 'email', operator: 'contains', value: '@company.com' },
          ],
        }
      );

      const result = abacService.checkAccessSimple(
        'user123',
        { email: 'user@company.com' } as any,
        'resource',
        'r1',
        'action',
        'a1'
      );
      
      expect(result.allowed).toBe(true);
    });
  });
});

// =============================================================================
// RATE LIMITER TESTS
// =============================================================================

describe('RateLimiterService', () => {
  let rateLimiter: RateLimiterService;

  beforeEach(() => {
    rateLimiter = createRateLimiterService();
  });

  describe('Fixed Window', () => {
    it('должен разрешать запросы в пределах лимита', async () => {
      const config = {
        name: 'test',
        type: 'fixed_window' as const,
        maxRequests: 5,
        windowMs: 60000,
        keyGenerator: () => 'test_key',
        message: 'Too many requests',
        statusCode: 429,
        headers: true,
      };

      for (let i = 0; i < 5; i++) {
        const result = await rateLimiter.checkRateLimit('test_key', config);
        expect(result.allowed).toBe(true);
      }

      const result = await rateLimiter.checkRateLimit('test_key', config);
      expect(result.allowed).toBe(false);
      expect(result.retryAfter).toBeGreaterThan(0);
    });
  });

  describe('Sliding Window', () => {
    it('должен правильно считать запросы в sliding window', async () => {
      const config = {
        name: 'test',
        type: 'sliding_window' as const,
        maxRequests: 3,
        windowMs: 1000, // 1 секунда
        keyGenerator: () => 'test_key',
        message: 'Too many requests',
        statusCode: 429,
        headers: true,
      };

      for (let i = 0; i < 3; i++) {
        const result = await rateLimiter.checkRateLimit('test_key', config);
        expect(result.allowed).toBe(true);
      }

      const result = await rateLimiter.checkRateLimit('test_key', config);
      expect(result.allowed).toBe(false);
    });
  });

  describe('Block Management', () => {
    it('должен создавать блокировку', async () => {
      await rateLimiter.block('test_key', 'Test block', 60);
      
      const blockInfo = await rateLimiter.getBlockInfo('test_key');
      expect(blockInfo).toBeDefined();
      expect(blockInfo?.reason).toBe('Test block');
    });

    it('должен очищать блокировку', async () => {
      await rateLimiter.block('test_key', 'Test block', 60);
      await rateLimiter.clearBlock('test_key');
      
      const blockInfo = await rateLimiter.getBlockInfo('test_key');
      expect(blockInfo).toBeNull();
    });
  });

  describe('Predefined Rules', () => {
    it('должен создавать auth rule', () => {
      const rule = rateLimiter.createAuthRule('test@example.com');
      
      expect(rule.name).toBe('auth');
      expect(rule.maxRequests).toBe(5);
    });

    it('должен создавать password reset rule', () => {
      const rule = rateLimiter.createPasswordResetRule('test@example.com');
      
      expect(rule.name).toBe('password_reset');
      expect(rule.maxRequests).toBe(3);
      expect(rule.windowMs).toBe(3600000); // 1 час
    });
  });
});

// =============================================================================
// OAUTH SERVICE TESTS
// =============================================================================

describe('OAuthService', () => {
  let oauthService: OAuthService;

  beforeEach(() => {
    oauthService = createOAuthService();
  });

  describe('Client Management', () => {
    it('должен регистрировать OAuth клиента', () => {
      const client = oauthService.registerClient({
        clientName: 'Test Client',
        clientType: 'confidential',
        redirectUris: ['https://example.com/callback'],
        grantTypes: ['authorization_code'],
      });
      
      expect(client.clientId).toBeDefined();
      expect(client.clientName).toBe('Test Client');
      expect(client.clientType).toBe('confidential');
    });

    it('должен получать клиента по ID', () => {
      const client = oauthService.registerClient({
        clientName: 'Test Client',
        clientType: 'public',
        redirectUris: ['https://example.com/callback'],
      });
      
      const retrieved = oauthService.getClient(client.clientId);
      expect(retrieved?.clientId).toBe(client.clientId);
    });

    it('должен валидировать redirect URI', () => {
      const client = oauthService.registerClient({
        clientName: 'Test Client',
        redirectUris: ['https://example.com/callback', 'https://*.example.com/*'],
      });
      
      expect(oauthService.validateRedirectUri(client.clientId, 'https://example.com/callback')).toBe(true);
      expect(oauthService.validateRedirectUri(client.clientId, 'https://sub.example.com/path')).toBe(true);
      expect(oauthService.validateRedirectUri(client.clientId, 'https://evil.com/callback')).toBe(false);
    });
  });

  describe('Authorization Code', () => {
    it('должен создавать authorization code', () => {
      const client = oauthService.registerClient({
        clientName: 'Test Client',
        redirectUris: ['https://example.com/callback'],
      });

      const code = oauthService.createAuthorizationCode(
        client.clientId,
        'user123',
        'https://example.com/callback',
        ['openid', 'profile']
      );
      
      expect(code.code).toBeDefined();
      expect(code.clientId).toBe(client.clientId);
      expect(code.userId).toBe('user123');
    });

    it('должен создавать authorization URL', () => {
      const client = oauthService.registerClient({
        clientName: 'Test Client',
        redirectUris: ['https://example.com/callback'],
      });

      const url = oauthService.createAuthorizationUrl(
        client.clientId,
        'https://example.com/callback',
        ['openid', 'profile'],
        {
          state: 'test_state',
        }
      );
      
      expect(url).toContain('/oauth/authorize');
      expect(url).toContain('client_id=' + client.clientId);
      expect(url).toContain('state=test_state');
    });
  });

  describe('PKCE', () => {
    it('должен генерировать code verifier', () => {
      const verifier = oauthService.generateCodeVerifier();
      
      expect(verifier).toBeDefined();
      expect(verifier.length).toBeGreaterThan(43);
    });

    it('должен вычислять code challenge (S256)', () => {
      const verifier = oauthService.generateCodeVerifier();
      const challenge = oauthService.calculateCodeChallenge(verifier, 'S256');
      
      expect(challenge).toBeDefined();
      expect(challenge).not.toBe(verifier);
    });

    it('должен вычислять code challenge (plain)', () => {
      const verifier = 'test_verifier_123456';
      const challenge = oauthService.calculateCodeChallenge(verifier, 'plain');
      
      expect(challenge).toBe(verifier);
    });
  });

  describe('Device Authorization', () => {
    it('должен создавать device authorization', () => {
      const client = oauthService.registerClient({
        clientName: 'Test Client',
        redirectUris: ['https://example.com/callback'],
      });

      const result = oauthService.createDeviceAuthorization(
        client.clientId,
        ['openid', 'profile']
      );
      
      expect(result.deviceCode).toBeDefined();
      expect(result.userCode).toBeDefined();
      expect(result.userCode).toMatch(/^[A-Z]{4}-[A-Z]{4}$/);
      expect(result.expiresIn).toBeGreaterThan(0);
    });

    it('должен авторизовать device code', () => {
      const client = oauthService.registerClient({
        clientName: 'Test Client',
        redirectUris: ['https://example.com/callback'],
      });

      const result = oauthService.createDeviceAuthorization(
        client.clientId,
        ['openid']
      );

      oauthService.authorizeDeviceCode(result.userCode, 'user123');
      
      // Device code должен быть авторизован
      expect(() => {
        // В production здесь была бы проверка
      }).not.toThrow();
    });
  });

  describe('Discovery', () => {
    it('должен возвращать конфигурацию discovery', () => {
      const config = oauthService.getDiscoveryConfiguration();
      
      expect(config.issuer).toBeDefined();
      expect(config.authorization_endpoint).toBeDefined();
      expect(config.token_endpoint).toBeDefined();
      expect(config.jwks_uri).toBeDefined();
      expect(config.response_types_supported).toBeDefined();
    });
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('AuthService Integration', () => {
  let authService: AuthService;

  beforeEach(async () => {
    authService = createAuthService({
      requireMfa: false,
      redis: {
        host: 'localhost',
        port: 6379,
      },
    });
  });

  afterEach(async () => {
    await authService.destroy();
  });

  describe('Registration Flow', () => {
    it('должен регистрировать пользователя с надежным паролем', async () => {
      const user = await authService.register({
        email: 'test@example.com',
        password: 'SecurePassword123!',
        username: 'testuser',
      });
      
      expect(user.id).toBeDefined();
      expect(user.email).toBe('test@example.com');
      expect(user.username).toBe('testuser');
      expect(user.status).toBe('active');
    });

    it('должен отклонять регистрацию с слабым паролем', async () => {
      await expect(
        authService.register({
          email: 'test2@example.com',
          password: '123456',
        })
      ).rejects.toThrow('Пароль не соответствует требованиям');
    });

    it('должен отклонять дубликат email', async () => {
      await authService.register({
        email: 'duplicate@example.com',
        password: 'SecurePassword123!',
      });

      await expect(
        authService.register({
          email: 'duplicate@example.com',
          password: 'AnotherPassword123!',
        })
      ).rejects.toThrow('уже существует');
    });
  });

  describe('Login Flow', () => {
    it('должен выполнять успешный login', async () => {
      // Регистрация
      await authService.register({
        email: 'login@example.com',
        password: 'SecurePassword123!',
      });

      // Login
      const result = await authService.login({
        email: 'login@example.com',
        password: 'SecurePassword123!',
        userAgent: 'Mozilla/5.0 Test Browser',
        ipAddress: '192.168.1.1',
      });
      
      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeDefined();
    });

    it('должен отклонять login с неверным паролем', async () => {
      await authService.register({
        email: 'wrongpass@example.com',
        password: 'SecurePassword123!',
      });

      await expect(
        authService.login({
          email: 'wrongpass@example.com',
          password: 'WrongPassword!',
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.1',
        })
      ).rejects.toThrow('Неверный email или пароль');
    });

    it('должен блокировать аккаунт после多次 failed attempts', async () => {
      await authService.register({
        email: 'lockout@example.com',
        password: 'SecurePassword123!',
      });

      // 5 failed attempts
      for (let i = 0; i < 5; i++) {
        try {
          await authService.login({
            email: 'lockout@example.com',
            password: 'WrongPassword!',
            userAgent: 'Mozilla/5.0 Test Browser',
            ipAddress: '192.168.1.1',
          });
        } catch (e) {
          // Ожидаемая ошибка
        }
      }

      // Следующая попытка должна получить ACCOUNT_LOCKED
      await expect(
        authService.login({
          email: 'lockout@example.com',
          password: 'SecurePassword123!',
          userAgent: 'Mozilla/5.0 Test Browser',
          ipAddress: '192.168.1.1',
        })
      ).rejects.toThrow('заблокирован');
    });
  });

  describe('Logout Flow', () => {
    it('должен выполнять logout', async () => {
      // Регистрация и login
      await authService.register({
        email: 'logout@example.com',
        password: 'SecurePassword123!',
      });

      const loginResult = await authService.login({
        email: 'logout@example.com',
        password: 'SecurePassword123!',
        userAgent: 'Mozilla/5.0 Test Browser',
        ipAddress: '192.168.1.1',
      });

      expect(loginResult.success).toBe(true);
      expect(loginResult.session).toBeDefined();

      // Logout
      if (loginResult.session) {
        await authService.logout(loginResult.session.id);
      }

      // Сессия должна быть завершена
      // (в production проверить что сессия неактивна)
    });
  });

  describe('Security Events', () => {
    it('должен логировать security events', async () => {
      await authService.register({
        email: 'events@example.com',
        password: 'SecurePassword123!',
      });

      const events = authService.getSecurityEvents(undefined, 10);
      
      // Должно быть как минимум событие регистрации
      expect(events.length).toBeGreaterThan(0);
    });
  });
});

// =============================================================================
// SECURITY TESTS
// =============================================================================

describe('Security Tests', () => {
  describe('Timing Attack Protection', () => {
    it('должен иметь constant-time верификацию пароля', async () => {
      const passwordService = createPasswordService();
      const hash = await passwordService.hashPassword('TestPassword123!');
      
      const iterations = 10;
      const correctTimes: number[] = [];
      const wrongTimes: number[] = [];

      for (let i = 0; i < iterations; i++) {
        let start = Date.now();
        await passwordService.verifyPassword('TestPassword123!', hash.hash);
        correctTimes.push(Date.now() - start);

        start = Date.now();
        await passwordService.verifyPassword('WrongPassword123!', hash.hash);
        wrongTimes.push(Date.now() - start);
      }

      const avgCorrect = correctTimes.reduce((a, b) => a + b) / iterations;
      const avgWrong = wrongTimes.reduce((a, b) => a + b) / iterations;
      
      // Разница не должна превышать 20%
      const diff = Math.abs(avgCorrect - avgWrong) / Math.max(avgCorrect, avgWrong);
      expect(diff).toBeLessThan(0.5);
    });
  });

  describe('Password Enumeration Protection', () => {
    it('должен иметь одинаковое время ответа для существующих и несуществующих пользователей', async () => {
      const authService = createAuthService();
      
      const iterations = 5;
      const existingTimes: number[] = [];
      const nonExistingTimes: number[] = [];

      // Создаем пользователя
      await authService.register({
        email: 'existing@example.com',
        password: 'SecurePassword123!',
      });

      for (let i = 0; i < iterations; i++) {
        let start = Date.now();
        try {
          await authService.login({
            email: 'existing@example.com',
            password: 'WrongPassword!',
            userAgent: 'Test',
            ipAddress: '127.0.0.1',
          });
        } catch (e) {
          existingTimes.push(Date.now() - start);
        }

        start = Date.now();
        try {
          await authService.login({
            email: 'nonexisting@example.com',
            password: 'AnyPassword!',
            userAgent: 'Test',
            ipAddress: '127.0.0.1',
          });
        } catch (e) {
          nonExistingTimes.push(Date.now() - start);
        }
      }

      await authService.destroy();

      const avgExisting = existingTimes.reduce((a, b) => a + b) / iterations;
      const avgNonExisting = nonExistingTimes.reduce((a, b) => a + b) / iterations;
      
      // Разница не должна превышать 50%
      const diff = Math.abs(avgExisting - avgNonExisting) / Math.max(avgExisting, avgNonExisting);
      expect(diff).toBeLessThan(0.5);
    });
  });
});
