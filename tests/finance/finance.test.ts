/**
 * ============================================================================
 * FINANCE SECURITY TESTS
 * ============================================================================
 */

import { describe, it, beforeEach, afterEach } from '@jest/globals';
import * as assert from 'assert';
import {
  PaymentCardEncryption,
  createPaymentCardEncryption,
  CardType,
  PaymentCardData
} from '../../src/finance/payment/PaymentCardEncryption';
import { HSMIntegration } from '../../src/finance/hsm/HSMIntegration';

describe('Finance Security', () => {
  
  describe('PaymentCardEncryption', () => {
    let encryption: PaymentCardEncryption;

    beforeEach(() => {
      encryption = createPaymentCardEncryption({
        encryptionKey: Buffer.alloc(32, 'test-key-32-bytes-long-string!'),
        tokenizationKey: Buffer.alloc(32, 'token-key-32-bytes-long-string!'),
        hmacKey: Buffer.alloc(32, 'hmac-key-32-bytes-long-string!!'),
        algorithm: 'AES-256-GCM',
        enableTokenization: true,
        tokenTtlHours: 24,
        enableAudit: true
      });
    });

    afterEach(() => {
      encryption.secureCleanup();
      encryption.removeAllListeners();
    });

    it('должен создавать сервис шифрования', () => {
      assert.ok(encryption);
      const stats = encryption.getStats();
      assert.strictEqual(stats.algorithm, 'AES-256-GCM');
      assert.strictEqual(stats.tokenizationEnabled, true);
    });

    it('должен определять тип карты VISA', () => {
      const cardType = encryption.detectCardType('4111111111111111');
      assert.strictEqual(cardType, CardType.VISA);
    });

    it('должен определять тип карты Mastercard', () => {
      const cardType = encryption.detectCardType('5500000000000004');
      assert.strictEqual(cardType, CardType.MASTERCARD);
    });

    it('должен определять тип карты American Express', () => {
      const cardType = encryption.detectCardType('340000000000009');
      assert.strictEqual(cardType, CardType.AMERICAN_EXPRESS);
    });

    it('должен определять тип карты MIR', () => {
      const cardType = encryption.detectCardType('2200000000000004');
      assert.strictEqual(cardType, CardType.MIR);
    });

    it('должен проходить Luhn валидацию для валидной карты', () => {
      const valid = encryption.validateLuhn('4111111111111111');
      assert.strictEqual(valid, true);
    });

    it('должен проваливать Luhn валидацию для невалидной карты', () => {
      const valid = encryption.validateLuhn('4111111111111112');
      assert.strictEqual(valid, false);
    });

    it('должен шифровать данные карты', async () => {
      const cardData: PaymentCardData = {
        pan: '4111111111111111',
        expiryDate: '12/25',
        cvv: '123',
        cardholderName: 'Test User'
      };

      const encrypted = await encryption.encryptCard(cardData);

      assert.ok(encrypted);
      assert.ok(encrypted.encryptedPan);
      assert.ok(encrypted.cardToken);
      assert.strictEqual(encrypted.lastFourDigits, '1111');
      assert.strictEqual(encrypted.bin, '411111');
      assert.strictEqual(encrypted.cardType, CardType.VISA);
      assert.ok(encrypted.encryptionMetadata);
    });

    it('должен расшифровывать данные карты', async () => {
      const cardData: PaymentCardData = {
        pan: '5500000000000004',
        expiryDate: '06/26',
        cvv: '456'
      };

      const encrypted = await encryption.encryptCard(cardData);
      const decrypted = await encryption.decryptCard(encrypted);

      assert.strictEqual(decrypted.pan, cardData.pan);
      assert.strictEqual(decrypted.expiryDate, cardData.expiryDate);
    });

    it('должен маскировать PAN', () => {
      const masked = encryption.maskPAN('4111111111111111');
      assert.strictEqual(masked, '•••• •••• •••• 1111');
    });

    it('должен маскировать PAN с показом первых цифр', () => {
      const masked = encryption.maskPAN('4111111111111111', 4);
      assert.ok(masked.startsWith('4111'));
      assert.ok(masked.endsWith('1111'));
    });

    it('должен хэшировать PAN', () => {
      const hash1 = encryption.hashPAN('4111111111111111');
      const hash2 = encryption.hashPAN('4111111111111111');
      
      assert.strictEqual(hash1, hash2);
      assert.strictEqual(hash1.length, 64);
    });

    it('должен вычислять CVV', () => {
      const cvv = encryption.calculateCVV('4111111111111111', '1225', '101');
      assert.ok(cvv);
      assert.strictEqual(cvv.length, 3);
    });

    it('должен генерировать токен', async () => {
      const cardData: PaymentCardData = {
        pan: '4111111111111111',
        expiryDate: '12/25'
      };

      const encrypted = await encryption.encryptCard(cardData);
      const valid = await encryption.validateToken(encrypted.cardToken);
      
      assert.strictEqual(valid, true);
    });

    it('должен отзывать токен', async () => {
      const cardData: PaymentCardData = {
        pan: '4111111111111111',
        expiryDate: '12/25'
      };

      const encrypted = await encryption.encryptCard(cardData);
      encryption.revokeToken(encrypted.cardToken);
      
      const valid = await encryption.validateToken(encrypted.cardToken);
      assert.strictEqual(valid, false);
    });

    it('должен делать BIN lookup', async () => {
      const result = await encryption.binLookup('411111');
      
      assert.ok(result);
      assert.strictEqual(result.cardType, CardType.VISA);
    });

    it('должен очищать просроченные токены', async () => {
      // Создаем токен
      const cardData: PaymentCardData = {
        pan: '4111111111111111',
        expiryDate: '12/25'
      };

      await encryption.encryptCard(cardData);
      
      const removed = encryption.cleanupExpiredTokens();
      assert.ok(removed >= 0);
    });

    it('должен возвращать статистику', () => {
      const stats = encryption.getStats();
      assert.ok('tokensCached' in stats);
      assert.ok('auditLogSize' in stats);
    });

    it('должен эмитить аудит события', (done) => {
      encryption.on('audit', (event) => {
        assert.ok(event);
        assert.ok(event.eventType);
        done();
      });

      encryption.encryptCard({
        pan: '4111111111111111',
        expiryDate: '12/25'
      }).catch(() => {});
    });
  });

  describe('HSMIntegration', () => {
    let hsm: HSMIntegration;

    beforeEach(() => {
      hsm = new HSMIntegration({
        hsmProvider: 'mock',
        enableHSM: true,
        encryptionAlgorithm: 'AES-256-GCM',
        signingAlgorithm: 'RSA-PSS-256',
        keyRotationDays: 90,
        enableKeyVersioning: true
      });
    });

    afterEach(async () => {
      await hsm.destroy();
      hsm.removeAllListeners();
    });

    it('должен создавать HSM интеграцию', () => {
      assert.ok(hsm);
    });

    it('должен инициализироваться', async () => {
      await hsm.initialize();
      const status = hsm.getStatus();
      assert.strictEqual(status.initialized, true);
    });

    it('должен генерировать ключи', async () => {
      await hsm.initialize();
      
      const key = await hsm.generateKey({
        keyType: 'AES',
        keySize: 256,
        usage: ['ENCRYPT', 'DECRYPT']
      });

      assert.ok(key);
      assert.ok(key.keyId);
      assert.strictEqual(key.keyType, 'AES');
      assert.strictEqual(key.status, 'ACTIVE');
    });

    it('должен шифровать данные', async () => {
      await hsm.initialize();
      
      const key = await hsm.generateKey({
        keyType: 'AES',
        keySize: 256,
        usage: ['ENCRYPT', 'DECRYPT']
      });

      const result = await hsm.encrypt(key.keyId, 'Secret message');
      
      assert.ok(result);
      assert.ok(result.operationId);
      assert.strictEqual(result.operationType, 'ENCRYPT');
      assert.ok(result.data);
    });

    it('должен дешифровать данные', async () => {
      await hsm.initialize();
      
      const key = await hsm.generateKey({
        keyType: 'AES',
        keySize: 256,
        usage: ['ENCRYPT', 'DECRYPT']
      });

      const encrypted = await hsm.encrypt(key.keyId, 'Secret message');
      const decrypted = await hsm.decrypt(key.keyId, encrypted.data);

      assert.strictEqual(decrypted.data, 'Secret message');
    });

    it('должен подписывать данные', async () => {
      await hsm.initialize();
      
      const key = await hsm.generateKey({
        keyType: 'RSA',
        keySize: 2048,
        usage: ['SIGN', 'VERIFY']
      });

      const result = await hsm.sign(key.keyId, 'Message to sign');
      
      assert.ok(result);
      assert.strictEqual(result.operationType, 'SIGN');
      assert.ok(result.data);
    });

    it('должен верифицировать подпись', async () => {
      await hsm.initialize();
      
      const key = await hsm.generateKey({
        keyType: 'RSA',
        keySize: 2048,
        usage: ['SIGN', 'VERIFY']
      });

      const signed = await hsm.sign(key.keyId, 'Message');
      const verified = await hsm.verify(key.keyId, 'Message', signed.data);

      assert.ok(verified);
      assert.strictEqual(verified.valid, true);
    });

    it('должен проверять здоровье', async () => {
      await hsm.initialize();
      
      const health = await hsm.healthCheck();
      
      assert.ok(health);
      assert.ok(health.status);
      assert.ok('latency' in health);
    });

    it('должен возвращать статус', () => {
      const status = hsm.getStatus();
      assert.ok('initialized' in status);
      assert.ok('connected' in status);
      assert.ok('keysCached' in status);
    });

    it('должен эмитить события', (done) => {
      hsm.on('initialized', () => {
        done();
      });

      hsm.initialize().catch(() => {});
    });

    it('должен получать информацию о ключе', async () => {
      await hsm.initialize();
      
      const key = await hsm.generateKey({
        keyType: 'AES',
        keySize: 256,
        usage: ['ENCRYPT']
      });

      const info = await hsm.getKeyInfo(key.keyId);
      
      assert.strictEqual(info.keyId, key.keyId);
      assert.strictEqual(info.keyType, 'AES');
    });

    it('должен уничтожать ключи', async () => {
      await hsm.initialize();
      
      const key = await hsm.generateKey({
        keyType: 'AES',
        keySize: 256,
        usage: ['ENCRYPT']
      });

      await hsm.destroyKey(key.keyId);
      
      await assert.rejects(async () => {
        await hsm.getKeyInfo(key.keyId);
      });
    });
  });
});
