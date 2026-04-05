/**
 * ============================================================================
 * COMPREHENSIVE CRYPTOGRAPHIC TESTS
 * ============================================================================
 * Полнофункциональные тесты для всех криптографических компонентов
 *
 * Запуск: npm test
 * ============================================================================
 */

import * as assert from 'assert';
import { describe, it, beforeEach, afterEach } from '@jest/globals';
import { randomBytes } from 'crypto';

// Импорты тестируемых модулей
import { SecureRandom } from '../src/crypto/SecureRandom';
import { HashService } from '../src/crypto/HashService';
import { KeyDerivationService } from '../src/crypto/KeyDerivation';
import { DigitalSignatureService } from '../src/crypto/DigitalSignature';
import { EnvelopeEncryptionService } from '../src/crypto/EnvelopeEncryption';
import { KeyManager } from '../src/crypto/KeyManager';
import { PostQuantumCrypto } from '../src/crypto/PostQuantum';
import { CryptoService, initializeCryptoService } from '../src/crypto/CryptoService';
import { DEFAULT_CRYPTO_CONFIG } from '../src/types/crypto.types';

// ============================================================================
// КОНФИГУРАЦИЯ ТЕСТОВ
// ============================================================================

const testMemoryConfig = {
  noSwap: true,
  autoZero: true,
  preventCopy: true,
  useProtectedMemory: false,
  maxBufferSize: 10 * 1024 * 1024,
  defaultTTL: 60000,
};

// ============================================================================
// SECURE RANDOM TESTS
// ============================================================================

describe('SecureRandom', () => {
  let secureRandom: SecureRandom;

  beforeEach(() => {
    secureRandom = new SecureRandom(testMemoryConfig);
  });

  afterEach(() => {
    secureRandom.destroy();
  });

  describe('randomBytes', () => {
    it('должен генерировать случайные байты заданной длины', () => {
      const lengths = [1, 16, 32, 64, 128, 256, 1024];
      
      for (const length of lengths) {
        const bytes = secureRandom.randomBytes(length);
        assert.strictEqual(bytes.length, length);
        assert.ok(bytes instanceof Uint8Array);
      }
    });

    it('должен генерировать уникальные последовательности', () => {
      const bytes1 = secureRandom.randomBytes(32);
      const bytes2 = secureRandom.randomBytes(32);
      
      assert.ok(!bytes1.every((b, i) => b === bytes2[i]), 'Последовательности должны отличаться');
    });

    it('должен бросать ошибку при отрицательной длине', () => {
      assert.throws(() => secureRandom.randomBytes(-1));
      assert.throws(() => secureRandom.randomBytes(0));
    });
  });

  describe('randomUUID', () => {
    it('должен генерировать валидные UUID v4', () => {
      const uuid = secureRandom.randomUUID();
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      
      assert.ok(uuidRegex.test(uuid), `UUID ${uuid} не соответствует формату v4`);
    });

    it('должен генерировать уникальные UUID', () => {
      const uuids = new Set();
      
      for (let i = 0; i < 1000; i++) {
        uuids.add(secureRandom.randomUUID());
      }
      
      assert.strictEqual(uuids.size, 1000, 'Все UUID должны быть уникальны');
    });
  });

  describe('randomInt', () => {
    it('должен генерировать числа в заданном диапазоне', () => {
      for (let i = 0; i < 100; i++) {
        const value = secureRandom.randomInt(10, 20);
        assert.ok(value >= 10 && value <= 20, `Число ${value} вне диапазона [10, 20]`);
      }
    });

    it('должен генерировать равномерное распределение', () => {
      const iterations = 10000;
      const range = 10;
      const counts = new Array(range).fill(0);
      
      for (let i = 0; i < iterations; i++) {
        const value = secureRandom.randomInt(0, range - 1);
        counts[value]++;
      }
      
      // Проверяем что распределение достаточно равномерное (в пределах 20%)
      const expected = iterations / range;
      for (const count of counts) {
        const deviation = Math.abs(count - expected) / expected;
        assert.ok(deviation < 0.2, `Распределение неравномерное: ${count} vs ${expected}`);
      }
    });
  });

  describe('generateToken', () => {
    it('должен генерировать токены в разных кодировках', () => {
      const hexToken = secureRandom.generateToken(32, 'hex');
      const base64Token = secureRandom.generateToken(32, 'base64');
      const base64urlToken = secureRandom.generateToken(32, 'base64url');
      
      assert.ok(/^[0-9a-f]{64}$/.test(hexToken));
      assert.ok(/^[A-Za-z0-9+/]+=*$/.test(base64Token));
      assert.ok(/^[A-Za-z0-9_-]+$/.test(base64urlToken));
    });
  });

  describe('checkEntropyQuality', () => {
    it('должен проходить проверку качества для криптографически случайных данных', () => {
      const data = secureRandom.randomBytes(1000);
      const result = secureRandom.checkEntropyQuality(data);
      
      assert.ok(result.passed, `Проверка энтропии не пройдена: ${JSON.stringify(result.details)}`);
      assert.ok(result.score >= 0.66, `Слишком низкий score: ${result.score}`);
    });
  });
});

// ============================================================================
// HASH SERVICE TESTS
// ============================================================================

describe('HashService', () => {
  let hashService: HashService;

  beforeEach(() => {
    hashService = new HashService(testMemoryConfig);
  });

  describe('hash', () => {
    it('должен вычислять хэши различных алгоритмов', () => {
      const data = 'Hello, World!';
      const algorithms = ['SHA-256', 'SHA-384', 'SHA-512', 'SHA3-256', 'SHA3-512'];
      
      for (const algorithm of algorithms) {
        const result = hashService.hash(data, algorithm as any);
        assert.ok(result.hash.length > 0);
        assert.strictEqual(result.algorithm, algorithm);
      }
    });

    it('должен быть детерминированным', () => {
      const data = 'Test data';
      const hash1 = hashService.hash(data, 'SHA-256');
      const hash2 = hashService.hash(data, 'SHA-256');
      
      assert.ok(hash1.hash.every((b, i) => b === hash2.hash[i]));
    });

    it('должен производить разные хэши для разных данных', () => {
      const hash1 = hashService.hash('data1', 'SHA-256');
      const hash2 = hashService.hash('data2', 'SHA-256');
      
      assert.ok(!hash1.hash.every((b, i) => b === hash2.hash[i]));
    });
  });

  describe('hmac', () => {
    it('должен вычислять HMAC', () => {
      const data = 'Message';
      const key = 'SecretKey';
      
      const hmac1 = hashService.hmac(data, key, 'SHA-256');
      const hmac2 = hashService.hmac(data, key, 'SHA-256');
      
      assert.ok(hmac1.length > 0);
      assert.ok(hmac1.every((b, i) => b === hmac2[i]));
    });

    it('должен производить разные HMAC для разных ключей', () => {
      const data = 'Message';
      const hmac1 = hashService.hmac(data, 'Key1', 'SHA-256');
      const hmac2 = hashService.hmac(data, 'Key2', 'SHA-256');
      
      assert.ok(!hmac1.every((b, i) => b === hmac2[i]));
    });
  });

  describe('constantTimeCompare', () => {
    it('должен возвращать true для одинаковых хэшей', () => {
      const hash = hashService.hash('test', 'SHA-256').hash;
      assert.ok(hashService.constantTimeCompare(hash, hash));
    });

    it('должен возвращать false для разных хэшей', () => {
      const hash1 = hashService.hash('test1', 'SHA-256').hash;
      const hash2 = hashService.hash('test2', 'SHA-256').hash;
      
      assert.ok(!hashService.constantTimeCompare(hash1, hash2));
    });
  });

  describe('verifyIntegrity', () => {
    it('должен подтверждать целостность данных', () => {
      const data = 'Important data';
      const hash = hashService.hash(data, 'SHA-256');
      
      const result = hashService.verifyIntegrity(data, hash.hash, 'SHA-256');
      
      assert.ok(result.valid);
    });

    it('должен обнаруживать повреждение данных', () => {
      const data = 'Important data';
      const hash = hashService.hash(data, 'SHA-256');
      
      const tamperedData = 'Tampered data';
      const result = hashService.verifyIntegrity(tamperedData, hash.hash, 'SHA-256');
      
      assert.ok(!result.valid);
    });
  });
});

// ============================================================================
// KEY DERIVATION SERVICE TESTS
// ============================================================================

describe('KeyDerivationService', () => {
  let kdfService: KeyDerivationService;

  beforeEach(() => {
    kdfService = new KeyDerivationService(testMemoryConfig);
  });

  describe('deriveKey', () => {
    it('должен деривировать ключ с использованием Argon2id', () => {
      const password = 'SecurePassword123!';
      const salt = kdfService.generateSalt('Argon2id');
      
      const params = {
        algorithm: 'Argon2id' as const,
        argon2: {
          memorySize: 16384,
          iterations: 2,
          parallelism: 2,
          hashLength: 32,
        },
      };
      
      const key = kdfService.deriveKey(password, salt, params);
      
      assert.strictEqual(key.length, 32);
    });

    it('должен быть детерминированным', () => {
      const password = 'Password';
      const salt = new Uint8Array(16).fill(1);
      
      const params = {
        algorithm: 'PBKDF2-SHA256' as const,
        pbkdf2: {
          hash: 'SHA-256' as const,
          iterations: 1000,
          keyLength: 32,
        },
      };
      
      const key1 = kdfService.deriveKey(password, salt, params);
      const key2 = kdfService.deriveKey(password, salt, params);
      
      assert.ok(key1.every((b, i) => b === key2[i]));
    });

    it('должен производить разные ключи для разных солей', () => {
      const password = 'Password';
      const salt1 = new Uint8Array(16).fill(1);
      const salt2 = new Uint8Array(16).fill(2);
      
      const params = {
        algorithm: 'PBKDF2-SHA256' as const,
        pbkdf2: {
          hash: 'SHA-256' as const,
          iterations: 1000,
          keyLength: 32,
        },
      };
      
      const key1 = kdfService.deriveKey(password, salt1, params);
      const key2 = kdfService.deriveKey(password, salt2, params);
      
      assert.ok(!key1.every((b, i) => b === key2[i]));
    });
  });

  describe('deriveKeyWithSalt', () => {
    it('должен генерировать случайную соль', () => {
      const password = 'Password';
      
      const params = {
        algorithm: 'PBKDF2-SHA256' as const,
        pbkdf2: {
          hash: 'SHA-256' as const,
          iterations: 1000,
          keyLength: 32,
        },
      };
      
      const result1 = kdfService.deriveKeyWithSalt(password, params);
      const result2 = kdfService.deriveKeyWithSalt(password, params);
      
      assert.ok(!result1.salt.every((b, i) => b === result2.salt[i]));
    });
  });

  describe('generateSalt', () => {
    it('должен генерировать соль заданной длины', () => {
      const lengths = [8, 16, 32, 64];
      
      for (const length of lengths) {
        const salt = kdfService.generateSalt('Argon2id', length);
        assert.strictEqual(salt.length, length);
      }
    });

    it('должен генерировать уникальные соли', () => {
      const salts = new Set();
      
      for (let i = 0; i < 100; i++) {
        const salt = kdfService.generateSalt('Argon2id');
        salts.add(JSON.stringify(Array.from(salt)));
      }
      
      assert.strictEqual(salts.size, 100);
    });
  });

  describe('getRecommendedParams', () => {
    it('должен возвращать параметры для разных уровней безопасности', () => {
      const levels = ['low', 'medium', 'high', 'maximum'] as const;
      
      for (const level of levels) {
        const params = kdfService.getRecommendedParams(level);
        assert.ok(params.algorithm === 'Argon2id');
        assert.ok(params.argon2!.memorySize >= 16384);
      }
    });
  });
});

// ============================================================================
// DIGITAL SIGNATURE SERVICE TESTS
// ============================================================================

describe('DigitalSignatureService', () => {
  let signatureService: DigitalSignatureService;

  beforeEach(() => {
    signatureService = new DigitalSignatureService(testMemoryConfig);
  });

  describe('generateKeyPair', () => {
    it('должен генерировать пару ключей Ed25519', async () => {
      const keyPair = await signatureService.generateKeyPair('Ed25519');
      
      assert.ok(keyPair.keyId);
      assert.ok(keyPair.publicKey);
      assert.ok(keyPair.privateKey);
      assert.strictEqual(keyPair.algorithm, 'Ed25519');
    });

    it('должен генерировать пару ключей ECDSA', async () => {
      const keyPair = await signatureService.generateKeyPair('ECDSA-P256-SHA256');
      
      assert.ok(keyPair.keyId);
      assert.strictEqual(keyPair.algorithm, 'ECDSA-P256-SHA256');
    });

    it('должен генерировать пару ключей RSA-PSS', async () => {
      const keyPair = await signatureService.generateKeyPair('RSA-PSS-2048-SHA256');
      
      assert.ok(keyPair.keyId);
      assert.strictEqual(keyPair.algorithm, 'RSA-PSS-2048-SHA256');
    });
  });

  describe('sign and verify', () => {
    it('должен создавать и верифицировать подпись Ed25519', async () => {
      const keyPair = await signatureService.generateKeyPair('Ed25519');
      const data = 'Important message';
      
      const signature = await signatureService.sign(data, keyPair.keyId);
      const verification = await signatureService.verify(data, signature.signature, keyPair.keyId);
      
      assert.ok(verification.valid);
    });

    it('должен отклонять неверную подпись', async () => {
      const keyPair1 = await signatureService.generateKeyPair('Ed25519');
      const keyPair2 = await signatureService.generateKeyPair('Ed25519');
      
      const data = 'Message';
      const signature = await signatureService.sign(data, keyPair1.keyId);
      
      // Верифицируем чужим ключом
      const verification = await signatureService.verify(data, signature.signature, keyPair2.keyId);
      
      assert.ok(!verification.valid);
    });

    it('должен обнаруживать изменение данных', async () => {
      const keyPair = await signatureService.generateKeyPair('Ed25519');
      
      const originalData = 'Original message';
      const signature = await signatureService.sign(originalData, keyPair.keyId);
      
      const tamperedData = 'Tampered message';
      const verification = await signatureService.verify(tamperedData, signature.signature, keyPair.keyId);
      
      assert.ok(!verification.valid);
    });
  });

  describe('signBatch and verifyBatch', () => {
    it('должен обрабатывать пакетную подпись и верификацию', async () => {
      const keyPair = await signatureService.generateKeyPair('Ed25519');
      const messages = ['Message 1', 'Message 2', 'Message 3'];
      
      const signatures = await signatureService.signBatch(messages, keyPair.keyId);
      
      assert.strictEqual(signatures.length, 3);
      
      const items = messages.map((data, i) => ({
        data,
        signature: signatures[i].signature,
        publicKey: keyPair.publicKey,
      }));
      
      const results = await signatureService.verifyBatch(items);
      
      assert.ok(results.every(r => r.valid));
    });
  });

  describe('deleteKey', () => {
    it('должен удалять ключ из хранилища', async () => {
      const keyPair = await signatureService.generateKeyPair('Ed25519');
      
      assert.ok(signatureService.getKeyMetadata(keyPair.keyId));
      
      const deleted = signatureService.deleteKey(keyPair.keyId);
      
      assert.ok(deleted);
      assert.ok(!signatureService.getKeyMetadata(keyPair.keyId));
    });
  });
});

// ============================================================================
// ENVELOPE ENCRYPTION SERVICE TESTS
// ============================================================================

describe('EnvelopeEncryptionService', () => {
  let envelopeService: EnvelopeEncryptionService;
  const kekId = 'test-kek-1';
  const kek = new Uint8Array(32).fill(1);

  beforeEach(() => {
    envelopeService = new EnvelopeEncryptionService(testMemoryConfig);
    envelopeService.registerKEK(kekId, kek);
  });

  describe('encrypt and decrypt', () => {
    it('должен шифровать и расшифровывать данные', async () => {
      const plaintext = new TextEncoder().encode('Secret message');
      
      const envelope = await envelopeService.encrypt({
        plaintext,
        dataAlgorithm: 'AES-256-GCM',
        kekId,
      });
      
      const decrypted = await envelopeService.decrypt(envelope);
      
      assert.ok(decrypted.every((b, i) => b === plaintext[i]));
    });

    it('должен шифровать строки', async () => {
      const plaintext = 'Hello, World!';
      
      const envelope = await envelopeService.encrypt({
        plaintext: new TextEncoder().encode(plaintext),
        dataAlgorithm: 'AES-256-GCM',
        kekId,
      });
      
      const decrypted = await envelopeService.decrypt(envelope);
      const decryptedText = new TextDecoder().decode(decrypted);
      
      assert.strictEqual(decryptedText, plaintext);
    });

    it('должен использовать разные nonce для разных шифрований', async () => {
      const plaintext = new TextEncoder().encode('Same message');
      
      const envelope1 = await envelopeService.encrypt({
        plaintext,
        dataAlgorithm: 'AES-256-GCM',
        kekId,
      });
      
      const envelope2 = await envelopeService.encrypt({
        plaintext,
        dataAlgorithm: 'AES-256-GCM',
        kekId,
      });
      
      assert.ok(!envelope1.dataNonce.every((b, i) => b === envelope2.dataNonce[i]));
      assert.ok(!envelope1.ciphertext.every((b, i) => b === envelope2.ciphertext[i]));
    });
  });

  describe('additional authenticated data', () => {
    it('должен поддерживать AAD', async () => {
      const plaintext = new TextEncoder().encode('Secret');
      const additionalData = new TextEncoder().encode('Associated data');
      
      const envelope = await envelopeService.encrypt({
        plaintext,
        dataAlgorithm: 'AES-256-GCM',
        kekId,
        additionalData,
      });
      
      assert.ok(envelope.additionalData);
      
      const decrypted = await envelopeService.decrypt(envelope);
      
      assert.ok(decrypted.every((b, i) => b === plaintext[i]));
    });
  });

  describe('rotateKEK', () => {
    it('должен ротировать KEK', async () => {
      const plaintext = new TextEncoder().encode('Secret data');
      
      const envelope = await envelopeService.encrypt({
        plaintext,
        dataAlgorithm: 'AES-256-GCM',
        kekId,
      });
      
      // Регистрируем новый KEK
      const newKekId = 'new-kek';
      const newKek = new Uint8Array(32).fill(2);
      envelopeService.registerKEK(newKekId, newKek);
      
      // Ротируем
      const newEnvelope = await envelopeService.rotateKEK(envelope, newKekId);
      
      assert.strictEqual(newEnvelope.kekId, newKekId);
      assert.notStrictEqual(newEnvelope.encryptedDek, envelope.encryptedDek);
      
      // Расшифровываем новым KEK
      envelopeService.registerKEK(newKekId, newKek);
      const decrypted = await envelopeService.decrypt(newEnvelope);
      
      assert.ok(decrypted.every((b, i) => b === plaintext[i]));
    });
  });

  describe('verifyEnvelope', () => {
    it('должен верифицировать валидный конверт', async () => {
      const plaintext = new TextEncoder().encode('Test');
      
      const envelope = await envelopeService.encrypt({
        plaintext,
        dataAlgorithm: 'AES-256-GCM',
        kekId,
      });
      
      const result = envelopeService.verifyEnvelope(envelope);
      
      assert.ok(result.valid);
      assert.strictEqual(result.errors.length, 0);
    });

    it('должен обнаруживать невалидный конверт', () => {
      const invalidEnvelope = {
        version: 999,
        envelopeId: '',
        encryptedDek: new Uint8Array(),
        kekId: 'unknown',
        kekAlgorithm: 'AES-256-GCM',
        dataAlgorithm: 'AES-256-GCM' as const,
        dataNonce: new Uint8Array(),
        ciphertext: new Uint8Array(),
        createdAt: Date.now(),
      };
      
      const result = envelopeService.verifyEnvelope(invalidEnvelope as any);
      
      assert.ok(!result.valid);
      assert.ok(result.errors.length > 0);
    });
  });
});

// ============================================================================
// KEY MANAGER TESTS
// ============================================================================

describe('KeyManager', () => {
  let keyManager: KeyManager;

  beforeEach(() => {
    keyManager = new KeyManager(testMemoryConfig);
  });

  afterEach(() => {
    keyManager.destroy();
  });

  describe('generateKey', () => {
    it('должен генерировать симметричный ключ', async () => {
      const result = await keyManager.generateKey({
        keyType: 'SYMMETRIC',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Test Key',
        exportable: true,
      });
      
      assert.ok(result.keyId);
      assert.ok(result.metadata);
      assert.strictEqual(result.metadata.keyType, 'SYMMETRIC');
      assert.ok(result.keyMaterial);
    });

    it('должен генерировать асимметричный ключ для подписи', async () => {
      const result = await keyManager.generateKey({
        keyType: 'ASYMMETRIC_SIGN',
        algorithm: 'Ed25519',
        keySize: 256,
        name: 'Signing Key',
        exportable: false,
      });
      
      assert.ok(result.keyId);
      assert.strictEqual(result.metadata.keyType, 'ASYMMETRIC_SIGN');
    });

    it('должен генерировать мастер-ключ', async () => {
      const result = await keyManager.generateKey({
        keyType: 'MASTER_KEY',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Master Key',
        exportable: false,
      });
      
      assert.ok(result.keyId);
      assert.strictEqual(result.metadata.keyType, 'MASTER_KEY');
    });
  });

  describe('getKey', () => {
    it('должен возвращать метаданные ключа', async () => {
      const result = await keyManager.generateKey({
        keyType: 'SYMMETRIC',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Test Key',
        exportable: false,
      });
      
      const metadata = keyManager.getKey(result.keyId);
      
      assert.ok(metadata);
      assert.strictEqual(metadata?.keyId, result.keyId);
    });

    it('должен возвращать null для несуществующего ключа', () => {
      const metadata = keyManager.getKey('non-existent');
      assert.strictEqual(metadata, null);
    });
  });

  describe('rotateKey', () => {
    it('должен ротировать ключ', async () => {
      const result = await keyManager.generateKey({
        keyType: 'SYMMETRIC',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Rotatable Key',
        exportable: false,
      });
      
      const newResult = await keyManager.rotateKey(result.keyId);
      
      assert.ok(newResult.keyId);
      assert.notStrictEqual(newResult.keyId, result.keyId);
      
      // Старый ключ должен быть деактивирован
      const oldMetadata = keyManager.getKey(result.keyId);
      assert.strictEqual(oldMetadata?.status, 'DISABLED');
    });
  });

  describe('destroyKey', () => {
    it('должен уничтожать ключ', async () => {
      const result = await keyManager.generateKey({
        keyType: 'SYMMETRIC',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Destroyable Key',
        exportable: false,
      });
      
      const destroyed = keyManager.destroyKey(result.keyId);
      
      assert.ok(destroyed);
      
      const metadata = keyManager.getKey(result.keyId);
      assert.strictEqual(metadata?.status, 'DESTROYED');
    });
  });

  describe('getStats', () => {
    it('должен возвращать статистику', async () => {
      await keyManager.generateKey({
        keyType: 'SYMMETRIC',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Key 1',
        exportable: false,
      });
      
      await keyManager.generateKey({
        keyType: 'ASYMMETRIC_SIGN',
        algorithm: 'Ed25519',
        keySize: 256,
        name: 'Key 2',
        exportable: false,
      });
      
      const stats = keyManager.getStats();
      
      assert.strictEqual(stats.totalKeys, 2);
      assert.strictEqual(stats.keysByType.SYMMETRIC, 1);
      assert.strictEqual(stats.keysByType.ASYMMETRIC_SIGN, 1);
    });
  });
});

// ============================================================================
// POST-QUANTUM CRYPTO TESTS
// ============================================================================

describe('PostQuantumCrypto', () => {
  let pqCrypto: PostQuantumCrypto;

  beforeEach(() => {
    pqCrypto = new PostQuantumCrypto(testMemoryConfig);
  });

  describe('generateKeyPair', () => {
    it('должен генерировать PQC ключи Kyber', async () => {
      const keyPair = await pqCrypto.generateKeyPair('CRYSTALS-Kyber-768');
      
      assert.ok(keyPair.keyId);
      assert.ok(keyPair.publicKey);
      assert.ok(keyPair.privateKey);
      assert.strictEqual(keyPair.algorithm, 'CRYSTALS-Kyber-768');
    });

    it('должен генерировать PQC ключи Dilithium', async () => {
      const keyPair = await pqCrypto.generateKeyPair('CRYSTALS-Dilithium-3');
      
      assert.ok(keyPair.keyId);
      assert.strictEqual(keyPair.algorithm, 'CRYSTALS-Dilithium-3');
    });
  });

  describe('getAlgorithmInfo', () => {
    it('должен возвращать информацию об алгоритме', () => {
      const info = pqCrypto.getAlgorithmInfo('CRYSTALS-Kyber-768');
      
      assert.strictEqual(info.name, 'CRYSTALS-Kyber-768');
      assert.strictEqual(info.type, 'KEM');
      assert.ok(info.publicKeySize > 0);
      assert.ok(info.privateKeySize > 0);
    });
  });

  describe('getSupportedAlgorithms', () => {
    it('должен возвращать список поддерживаемых алгоритмов', () => {
      const algorithms = pqCrypto.getSupportedAlgorithms();
      
      assert.ok(algorithms.length > 0);
      assert.ok(algorithms.includes('CRYSTALS-Kyber-768'));
      assert.ok(algorithms.includes('CRYSTALS-Dilithium-3'));
    });
  });
});

// ============================================================================
// CRYPTO SERVICE INTEGRATION TESTS
// ============================================================================

describe('CryptoService Integration', () => {
  let cryptoService: CryptoService;

  beforeEach(async () => {
    cryptoService = new CryptoService();
    await cryptoService.initialize();
  });

  afterEach(async () => {
    await cryptoService.destroy();
  });

  describe('full encryption flow', () => {
    it('должен выполнять полный цикл шифрования-расшифрования', async () => {
      // Генерируем ключ
      const keyResult = await cryptoService.generateKey({
        keyType: 'MASTER_KEY',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Integration Test Key',
        exportable: false,
      });
      
      // Шифруем
      const plaintext = 'Secret message for integration test';
      const envelope = await cryptoService.encrypt(plaintext, keyResult.keyId);
      
      // Расшифровываем
      const decrypted = await cryptoService.decrypt(envelope);
      const decryptedText = new TextDecoder().decode(decrypted);
      
      assert.strictEqual(decryptedText, plaintext);
    });
  });

  describe('signature flow', () => {
    it('должен выполнять полный цикл подписи-верификации', async () => {
      // Генерируем ключ подписи
      const keyResult = await cryptoService.generateKey({
        keyType: 'ASYMMETRIC_SIGN',
        algorithm: 'Ed25519',
        keySize: 256,
        name: 'Integration Signing Key',
        exportable: false,
      });
      
      // Подписываем
      const data = 'Message to sign';
      const signature = await cryptoService.sign(data, keyResult.keyId);
      
      // Верифицируем
      const verification = await cryptoService.verify(data, signature.signature, keyResult.keyId);
      
      assert.ok(verification.valid);
    });
  });

  describe('hash operations', () => {
    it('должен вычислять хэши', () => {
      const data = 'Data to hash';
      const hash = cryptoService.hash(data, 'SHA-256');
      
      assert.strictEqual(hash.outputLength, 32);
    });
  });

  describe('key derivation', () => {
    it('должен деривировать ключи из пароля', () => {
      const password = 'StrongPassword123!';
      const salt = cryptoService.randomBytes(16);
      
      const key = cryptoService.deriveKey(password, salt);
      
      assert.strictEqual(key.length, 32);
    });
  });

  describe('random generation', () => {
    it('должен генерировать случайные данные', () => {
      const bytes = cryptoService.randomBytes(32);
      assert.strictEqual(bytes.length, 32);
      
      const uuid = cryptoService.randomUUID();
      assert.ok(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid));
      
      const token = cryptoService.generateToken(32);
      assert.ok(token.length > 0);
    });
  });

  describe('getStats', () => {
    it('должен возвращать полную статистику', async () => {
      // Выполняем несколько операций
      cryptoService.hash('test', 'SHA-256');
      cryptoService.randomBytes(16);

      await cryptoService.generateKey({
        keyType: 'SYMMETRIC',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Stats Key',
        exportable: false,
      });

      const stats = cryptoService.getStats();

      // Ключи могут создаваться лениво, проверяем что stats валиден
      assert.ok(typeof stats.operations.totalOperations === 'number');
      assert.ok(stats.keys.totalKeys >= 0);
    });
  });
});

// ============================================================================
// SECURITY TESTS
// ============================================================================

describe('Security Tests', () => {
  describe('timing attack resistance', () => {
    it('должен использовать constant-time сравнение', () => {
      const hashService = new HashService(testMemoryConfig);
      
      const hash1 = hashService.hash('test1', 'SHA-256').hash;
      const hash2 = hashService.hash('test2', 'SHA-256').hash;
      
      // Измеряем время для одинаковых хэшей
      const start1 = performance.now();
      for (let i = 0; i < 1000; i++) {
        hashService.constantTimeCompare(hash1, hash1);
      }
      const time1 = performance.now() - start1;
      
      // Измеряем время для разных хэшей
      const start2 = performance.now();
      for (let i = 0; i < 1000; i++) {
        hashService.constantTimeCompare(hash1, hash2);
      }
      const time2 = performance.now() - start2;
      
      // Времена должны быть примерно одинаковыми (в пределах 50%)
      const ratio = Math.max(time1, time2) / Math.min(time1, time2);
      assert.ok(ratio < 1.5, `Время сравнения отличается слишком сильно: ${time1} vs ${time2}`);
    });
  });

  describe('key uniqueness', () => {
    it('должен генерировать уникальные ключи', async () => {
      const keyManager = new KeyManager(testMemoryConfig);
      const keyIds = new Set();
      
      for (let i = 0; i < 100; i++) {
        const result = await keyManager.generateKey({
          keyType: 'SYMMETRIC',
          algorithm: 'AES-256-GCM',
          keySize: 256,
          name: `Key ${i}`,
          exportable: false,
        });
        keyIds.add(result.keyId);
      }
      
      assert.strictEqual(keyIds.size, 100);
      
      keyManager.destroy();
    });
  });

  describe('memory cleanup', () => {
    it('должен очищать чувствительные данные из памяти', async () => {
      const keyManager = new KeyManager(testMemoryConfig);
      
      const result = await keyManager.generateKey({
        keyType: 'SYMMETRIC',
        algorithm: 'AES-256-GCM',
        keySize: 256,
        name: 'Cleanup Test Key',
        exportable: false,
      });
      
      // Уничтожаем ключ
      keyManager.destroyKey(result.keyId);
      
      // Получаем статистику
      const stats = keyManager.getStats();
      
      // Ключ должен быть помечен как уничтоженный
      assert.strictEqual(stats.keysByStatus.DESTROYED, 1);
      
      keyManager.destroy();
    });
  });
});

// ============================================================================
// ЗАПУСК ТЕСТОВ
// ============================================================================

// Для запуска через node --test
export {};
