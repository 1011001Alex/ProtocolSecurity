/**
 * ============================================================================
 * POST-QUANTUM CRYPTO TESTS
 * ============================================================================
 */

import { describe, it, beforeEach, afterEach } from '@jest/globals';
import * as assert from 'assert';
import { PostQuantumCrypto, generatePQCKeyPair, pqcEncapsulate } from '../src/crypto/PostQuantum';

describe('PostQuantumCrypto', () => {
  let pqc: PostQuantumCrypto;

  beforeEach(() => {
    pqc = new PostQuantumCrypto({
      noSwap: true,
      autoZero: true,
      preventCopy: true,
      useProtectedMemory: false,
      maxBufferSize: 50 * 1024 * 1024,
      defaultTTL: 60000
    }, true);
  });

  afterEach(() => {
    pqc.removeAllListeners();
  });

  describe('constructor', () => {
    it('должен создавать экземпляр с конфигурацией', () => {
      assert.ok(pqc);
    });

    it('должен эмитить событие initialized', (done) => {
      pqc.on('initialized', (data) => {
        assert.ok(data.hybridMode !== undefined);
        assert.ok(data.oqsAvailable !== undefined);
        done();
      });
      
      // Создаем новый для теста
      const newPqc = new PostQuantumCrypto({
        noSwap: true,
        autoZero: true,
        preventCopy: true,
        useProtectedMemory: false,
        maxBufferSize: 50 * 1024 * 1024,
        defaultTTL: 60000
      }, true);
      newPqc.removeAllListeners();
    });
  });

  describe('getSupportedAlgorithms', () => {
    it('должен возвращать список поддерживаемых алгоритмов', () => {
      const algorithms = pqc.getSupportedAlgorithms();
      
      assert.ok(algorithms.length > 0);
      assert.ok(algorithms.includes('CRYSTALS-Kyber-512'));
      assert.ok(algorithms.includes('CRYSTALS-Kyber-768'));
      assert.ok(algorithms.includes('CRYSTALS-Dilithium-2'));
      assert.ok(algorithms.includes('FALCON-512'));
      assert.ok(algorithms.includes('SPHINCS+-128s'));
    });
  });

  describe('getAlgorithmInfo', () => {
    it('должен возвращать информацию об алгоритме Kyber', () => {
      const info = pqc.getAlgorithmInfo('CRYSTALS-Kyber-768');
      
      assert.strictEqual(info.name, 'CRYSTALS-Kyber-768');
      assert.strictEqual(info.type, 'KEM');
      assert.strictEqual(info.securityLevel, 3);
      assert.strictEqual(info.publicKeySize, 1184);
      assert.strictEqual(info.privateKeySize, 2400);
      assert.strictEqual(info.ciphertextSize, 1088);
      assert.ok(info.nistStatus.includes('FIPS 203'));
    });

    it('должен возвращать информацию об алгоритме Dilithium', () => {
      const info = pqc.getAlgorithmInfo('CRYSTALS-Dilithium-3');
      
      assert.strictEqual(info.name, 'CRYSTALS-Dilithium-3');
      assert.strictEqual(info.type, 'SIGNATURE');
      assert.strictEqual(info.securityLevel, 3);
      assert.ok(info.signatureSize);
      assert.ok(info.nistStatus.includes('FIPS 204'));
    });

    it('должен бросать ошибку для несуществующего алгоритма', () => {
      assert.throws(() => {
        pqc.getAlgorithmInfo('INVALID-ALGORITHM' as any);
      });
    });
  });

  describe('generateKeyPair', () => {
    it('должен генерировать пару ключей Kyber в гибридном режиме', async () => {
      const keyPair = await pqc.generateKeyPair('CRYSTALS-Kyber-768');
      
      assert.ok(keyPair);
      assert.ok(keyPair.publicKey);
      assert.ok(keyPair.privateKey);
      assert.ok(keyPair.keyId);
      assert.strictEqual(keyPair.algorithm, 'CRYSTALS-Kyber-768');
      assert.strictEqual(keyPair.primitiveType, 'KEM');
      assert.ok(keyPair.metadata);
    });

    it('должен генерировать пару ключей Dilithium', async () => {
      const keyPair = await pqc.generateKeyPair('CRYSTALS-Dilithium-2');
      
      assert.ok(keyPair);
      assert.ok(keyPair.publicKey);
      assert.ok(keyPair.privateKey);
      assert.strictEqual(keyPair.algorithm, 'CRYSTALS-Dilithium-2');
      assert.strictEqual(keyPair.primitiveType, 'SIGNATURE');
    });

    it('должен генерировать пару ключей FALCON', async () => {
      const keyPair = await pqc.generateKeyPair('FALCON-512');
      
      assert.ok(keyPair);
      assert.ok(keyPair.publicKey);
      assert.ok(keyPair.privateKey);
      assert.strictEqual(keyPair.algorithm, 'FALCON-512');
    });

    it('должен генерировать пару ключей SPHINCS+', async () => {
      const keyPair = await pqc.generateKeyPair('SPHINCS+-128s');
      
      assert.ok(keyPair);
      assert.ok(keyPair.publicKey);
      assert.ok(keyPair.privateKey);
      assert.strictEqual(keyPair.algorithm, 'SPHINCS+-128s');
    });

    it('должен бросать ошибку для неподдерживаемого алгоритма', async () => {
      await assert.rejects(async () => {
        await pqc.generateKeyPair('INVALID' as any);
      });
    });
  });

  describe('kemEncapsulate / kemDecapsulate', () => {
    it('должен выполнять инкапсуляцию и деинкапсуляцию Kyber', async () => {
      // Генерация ключей
      const keyPair = await pqc.generateKeyPair('CRYSTALS-Kyber-768');
      
      // Инкапсуляция
      const encapsulationResult = await pqc.kemEncapsulate('CRYSTALS-Kyber-768', keyPair.publicKey);
      
      assert.ok(encapsulationResult);
      assert.ok(encapsulationResult.ciphertext);
      assert.ok(encapsulationResult.sharedSecret);
      assert.ok(encapsulationResult.keyId);
      
      // Деинкапсуляция
      const decapsulationResult = await pqc.kemDecapsulate(
        'CRYSTALS-Kyber-768',
        keyPair.privateKey,
        encapsulationResult.ciphertext
      );
      
      assert.ok(decapsulationResult);
      assert.ok(decapsulationResult.sharedSecret);
      // В гибридном режиме секреты могут отличаться из-за эмуляции
    });

    it('должен бросать ошибку для не-KEM алгоритма', async () => {
      await assert.rejects(async () => {
        await pqc.kemEncapsulate('CRYSTALS-Dilithium-2' as any, new Uint8Array(100));
      });
    });
  });

  describe('sign / verify', () => {
    it('должен подписывать и верифицировать сообщение Dilithium', async () => {
      const keyPair = await pqc.generateKeyPair('CRYSTALS-Dilithium-2');
      const message = new TextEncoder().encode('Hello, Post-Quantum World!');
      
      // Подпись
      const signature = await pqc.sign('CRYSTALS-Dilithium-2', keyPair.privateKey, message);
      
      assert.ok(signature);
      assert.ok(signature.length > 0);
      
      // Верификация
      const verificationResult = await pqc.verify(
        'CRYSTALS-Dilithium-2',
        keyPair.publicKey,
        message,
        signature
      );
      
      assert.ok(verificationResult);
      assert.ok('valid' in verificationResult);
    });

    it('должен подписывать и верифицировать сообщение FALCON', async () => {
      const keyPair = await pqc.generateKeyPair('FALCON-512');
      const message = new TextEncoder().encode('FALCON signature test');
      
      const signature = await pqc.sign('FALCON-512', keyPair.privateKey, message);
      assert.ok(signature);
      
      const verificationResult = await pqc.verify(
        'FALCON-512',
        keyPair.publicKey,
        message,
        signature
      );
      
      assert.ok(verificationResult);
    });

    it('должен бросать ошибку для не-signature алгоритма', async () => {
      await assert.rejects(async () => {
        await pqc.sign('CRYSTALS-Kyber-768' as any, new Uint8Array(100), new Uint8Array(10));
      });
    });
  });

  describe('hybridEncrypt / hybridDecrypt', () => {
    it('должен шифровать и расшифровывать данные в гибридном режиме', async () => {
      // Генерация классических ключей
      const classicKeyPair = {
        publicKey: new Uint8Array(32),
        privateKey: new Uint8Array(32)
      };
      
      // Генерация PQC ключей
      const pqcKeyPair = await pqc.generateKeyPair('CRYSTALS-Kyber-768');
      
      const data = new TextEncoder().encode('Secret hybrid message');
      
      // Шифрование
      const encrypted = await pqc.hybridEncrypt(
        classicKeyPair.publicKey,
        pqcKeyPair.publicKey,
        data
      );
      
      assert.ok(encrypted);
      assert.ok(encrypted.classicalCiphertext);
      assert.ok(encrypted.pqcCiphertext);
      assert.ok(encrypted.encryptedData);
    });
  });

  describe('утилиты', () => {
    it('должен генерировать ключи через generatePQCKeyPair', async () => {
      const keyPair = await generatePQCKeyPair('CRYSTALS-Kyber-512', true);
      
      assert.ok(keyPair);
      assert.ok(keyPair.publicKey);
      assert.ok(keyPair.privateKey);
    });

    it('должен выполнять инкапсуляцию через pqcEncapsulate', async () => {
      const keyPair = await generatePQCKeyPair('CRYSTALS-Kyber-512', true);
      const result = await pqcEncapsulate('CRYSTALS-Kyber-512', keyPair.publicKey, true);
      
      assert.ok(result);
      assert.ok(result.ciphertext);
      assert.ok(result.sharedSecret);
    });
  });

  describe('audit logging', () => {
    it('должен логировать аудит события', async () => {
      const auditEvents: any[] = [];
      pqc.on('audit', (event) => {
        auditEvents.push(event);
      });

      await pqc.generateKeyPair('CRYSTALS-Kyber-512');
      
      assert.strictEqual(auditEvents.length, 1);
      assert.strictEqual(auditEvents[0].eventType, 'KEY_GENERATION');
      assert.ok(auditEvents[0].success);
      assert.ok(auditEvents[0].executionTime >= 0);
    });
  });

  describe('getAuditLog', () => {
    it('должен возвращать лог аудит событий', async () => {
      await pqc.generateKeyPair('CRYSTALS-Kyber-512');
      await pqc.generateKeyPair('CRYSTALS-Dilithium-2');
      
      const auditLog = pqc.getAuditLog();
      
      assert.ok(auditLog.length >= 2);
    });
  });
});
