/**
 * ============================================================================
 * AUTH BENCHMARKS — ТЕСТЫ ПРОИЗВОДИТЕЛЬНОСТИ АУТЕНТИФИКАЦИИ
 * ============================================================================
 *
 * Измеряет производительность:
 * - JWT Generate (RS256 через jose)
 * - JWT Verify (RS256 через jose)
 * - Password Hash (Argon2id)
 * - Password Verify (Argon2id)
 * - Password Hash (bcrypt)
 * - Password Verify (bcrypt)
 * - MFA TOTP Generate
 * - MFA TOTP Verify
 * - Session Create
 *
 * Использует process.hrtime.bigint() для точных замеров.
 * НЕ использует console.log внутри loop.
 */

import * as crypto from 'crypto';
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
import * as argon2 from 'argon2';
import * as bcrypt from 'bcrypt';
import * as OTPAuth from 'otpauth';
import { BenchmarkRunner } from './BenchmarkRunner';
import { BenchmarkResult, DEFAULT_THRESHOLDS } from './types';

/**
 * Запуск всех auth benchmarks
 */
export async function runAuthBenchmarks(runner: BenchmarkRunner, iterations?: number): Promise<BenchmarkResult[]> {
  const results: BenchmarkResult[] = [];
  // Для auth benchmarks меньше итераций — argon2/bcrypt медленные
  const iters = iterations ?? 100;

  // ========================================================================
  // Подготовить RSA ключи для JWT
  // ========================================================================
  const { privateKey: privateKeyPem, publicKey: publicKeyPem } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const privateKey = await importPKCS8(privateKeyPem, 'RS256');
  const publicKey = await importSPKI(publicKeyPem, 'RS256');

  const jwtPayload = {
    sub: 'user-123',
    iss: 'protocol-auth',
    aud: 'protocol-api',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: crypto.randomUUID(),
    roles: ['admin', 'user'],
  };

  // ========================================================================
  // JWT GENERATE (RS256)
  // ========================================================================
  const jwtGenResult = await runner.run(
    'JWT Generate (RS256)',
    async () => {
      await new SignJWT(jwtPayload)
        .setProtectedHeader({ alg: 'RS256', kid: 'bench-key' })
        .setIssuedAt()
        .setIssuer('protocol-auth')
        .setAudience('protocol-api')
        .setExpirationTime('1h')
        .sign(privateKey);
    },
    iters,
    DEFAULT_THRESHOLDS['JWT Generate (RS256)']
  );
  (jwtGenResult as any).category = 'auth';
  runner.setLastCategory('auth');
  results.push(jwtGenResult);

  // ========================================================================
  // JWT VERIFY (RS256)
  // ========================================================================
  // Pre-generate токены для verify
  const jwtTokens: string[] = [];
  for (let i = 0; i < Math.min(iters, 20); i++) {
    const token = await new SignJWT({ ...jwtPayload, jti: `token-${i}` })
      .setProtectedHeader({ alg: 'RS256', kid: 'bench-key' })
      .sign(privateKey);
    jwtTokens.push(token);
  }

  let jwtVerifyIdx = 0;
  const jwtVerifyResult = await runner.run(
    'JWT Verify (RS256)',
    async () => {
      const token = jwtTokens[jwtVerifyIdx % jwtTokens.length];
      jwtVerifyIdx++;
      await jwtVerify(token, publicKey, {
        issuer: 'protocol-auth',
        audience: 'protocol-api',
      });
    },
    iters,
    DEFAULT_THRESHOLDS['JWT Verify (RS256)']
  );
  (jwtVerifyResult as any).category = 'auth';
  runner.setLastCategory('auth');
  results.push(jwtVerifyResult);

  // ========================================================================
  // PASSWORD HASH (ARGON2ID)
  // Argon2 медленный — используем меньше итераций
  // ========================================================================
  const argon2Iters = Math.min(iters, 10);
  const testPassword = 'BenchmarkP@ssw0rd!2024';

  const argon2HashResult = await runner.run(
    'Password Hash (Argon2id)',
    async () => {
      await argon2.hash(testPassword, {
        type: argon2.argon2id,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
        hashLength: 32,
      });
    },
    argon2Iters,
    DEFAULT_THRESHOLDS['Password Hash (Argon2id)']
  );
  (argon2HashResult as any).category = 'auth';
  runner.setLastCategory('auth');
  results.push(argon2HashResult);

  // ========================================================================
  // PASSWORD VERIFY (ARGON2ID)
  // ========================================================================
  const argon2Hash = await argon2.hash(testPassword, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    hashLength: 32,
  });

  const argon2VerifyResult = await runner.run(
    'Password Verify (Argon2id)',
    async () => {
      await argon2.verify(argon2Hash, testPassword);
    },
    argon2Iters,
    DEFAULT_THRESHOLDS['Password Verify (Argon2id)']
  );
  (argon2VerifyResult as any).category = 'auth';
  runner.setLastCategory('auth');
  results.push(argon2VerifyResult);

  // ========================================================================
  // PASSWORD HASH (BCRYPT)
  // ========================================================================
  const bcryptIters = Math.min(iters, 20);
  const bcryptCost = 10; // стандартный cost factor

  const bcryptHashResult = await runner.run(
    'Password Hash (bcrypt)',
    async () => {
      await bcrypt.hash(testPassword, bcryptCost);
    },
    bcryptIters,
    DEFAULT_THRESHOLDS['Password Hash (bcrypt)']
  );
  (bcryptHashResult as any).category = 'auth';
  runner.setLastCategory('auth');
  results.push(bcryptHashResult);

  // ========================================================================
  // PASSWORD VERIFY (BCRYPT)
  // ========================================================================
  const bcryptHash = await bcrypt.hash(testPassword, bcryptCost);

  const bcryptVerifyResult = await runner.run(
    'Password Verify (bcrypt)',
    async () => {
      await bcrypt.compare(testPassword, bcryptHash);
    },
    bcryptIters,
    DEFAULT_THRESHOLDS['Password Verify (bcrypt)']
  );
  (bcryptVerifyResult as any).category = 'auth';
  runner.setLastCategory('auth');
  results.push(bcryptVerifyResult);

  // ========================================================================
  // MFA TOTP GENERATE
  // ========================================================================
  const totpSecret = crypto.randomBytes(20).toString('base32');
  const totp = new OTPAuth.TOTP({
    issuer: 'Protocol',
    label: 'benchmark-user',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: totpSecret,
  });

  const mfaGenResult = await runner.run(
    'MFA TOTP Generate',
    () => {
      totp.generate();
    },
    iters,
    DEFAULT_THRESHOLDS['MFA TOTP Generate']
  );
  (mfaGenResult as any).category = 'auth';
  runner.setLastCategory('auth');
  results.push(mfaGenResult);

  // ========================================================================
  // MFA TOTP VERIFY
  // ========================================================================
  const mfaVerifyResult = await runner.run(
    'MFA TOTP Verify',
    () => {
      const token = totp.generate();
      totp.validate({ token, window: 1 });
    },
    iters,
    DEFAULT_THRESHOLDS['MFA TOTP Verify']
  );
  (mfaVerifyResult as any).category = 'auth';
  runner.setLastCategory('auth');
  results.push(mfaVerifyResult);

  // ========================================================================
  // SESSION CREATE
  // ========================================================================
  const sessionCreateResult = await runner.run(
    'Session Create',
    () => {
      // Эмуляция создания сессии: генерация ID + подпись
      const sessionId = crypto.randomUUID();
      const sessionData = JSON.stringify({
        id: sessionId,
        userId: 'user-123',
        createdAt: Date.now(),
        expiresAt: Date.now() + 3600000,
      });
      const hmac = crypto.createHmac('sha256', Buffer.from('session-secret-benchmark'));
      hmac.update(sessionData);
      hmac.digest('hex');
    },
    iters,
    DEFAULT_THRESHOLDS['Session Create']
  );
  (sessionCreateResult as any).category = 'auth';
  runner.setLastCategory('auth');
  results.push(sessionCreateResult);

  return results;
}
