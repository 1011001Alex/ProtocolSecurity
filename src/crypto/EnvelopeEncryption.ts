/**
 * ============================================================================
 * ENVELOPE ENCRYPTION - КОНВЕРТНОЕ ШИФРОВАНИЕ
 * ============================================================================
 */

import * as crypto from 'crypto';
import {
  EncryptionEnvelope,
  EnvelopeEncryptionParams,
  SymmetricAlgorithm,
  SecureMemoryConfig,
  CryptoErrorCode,
  KeyMetadata,
  KeyStatus,
  KeyType,
} from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';
import { HashService } from './HashService';

interface KEKEntry { keyMaterial: Buffer; metadata: KeyMetadata; createdAt: number; }
interface CachedDEK { key: Buffer; cachedAt: number; }

export class EnvelopeEncryptionService {
  private readonly envelopeVersion: number = 1;
  private readonly memoryConfig: SecureMemoryConfig;
  private readonly hashService: HashService;
  private readonly secureRandom: SecureRandom;
  private readonly kekStore: Map<string, KEKEntry>;
  private readonly dekCache: Map<string, CachedDEK>;
  private readonly maxDEKCacheSize: number = 1000;

  constructor(memoryConfig: SecureMemoryConfig) {
    this.memoryConfig = memoryConfig;
    this.hashService = new HashService(memoryConfig);
    this.secureRandom = new SecureRandom(memoryConfig);
    this.kekStore = new Map();
    this.dekCache = new Map();
  }

  registerKEK(keyId: string, keyMaterial: Uint8Array, metadata?: Partial<KeyMetadata>): void {
    if (keyMaterial.length !== 32 && keyMaterial.length !== 16) {
      throw this.createError(CryptoErrorCode.INVALID_KEY_SIZE, 'KEK должен быть 128 или 256 бит');
    }
    this.kekStore.set(keyId, {
      keyMaterial: Buffer.from(keyMaterial),
      metadata: { keyId, name: metadata?.name || `KEK ${keyId.slice(0, 8)}`, keyType: 'MASTER_KEY', algorithm: 'AES-256-GCM', keySize: keyMaterial.length * 8, status: metadata?.status || 'ACTIVE', createdAt: metadata?.createdAt || new Date(), version: metadata?.version || 1 },
      createdAt: Date.now(),
    });
  }

  generateKEK(keyId?: string): string {
    const actualKeyId = keyId || this.secureRandom.randomUUID();
    const keyMaterial = this.secureRandom.randomBytes(32);
    this.registerKEK(actualKeyId, keyMaterial);
    this.secureZero(keyMaterial);
    return actualKeyId;
  }

  async encrypt(params: EnvelopeEncryptionParams): Promise<EncryptionEnvelope> {
    const { plaintext, dataAlgorithm, kekId, additionalData, metadata, ttl } = params;
    const kekEntry = this.kekStore.get(kekId);
    if (!kekEntry) throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `KEK с идентификатором ${kekId} не найден`);
    if (kekEntry.metadata.status !== 'ACTIVE') throw this.createError(CryptoErrorCode.KEY_EXPIRED, `KEK не активен: ${kekEntry.metadata.status}`);

    try {
      const dekKeySize = this.getDataKeySize(dataAlgorithm);
      const dek = this.secureRandom.randomBytes(dekKeySize);
      const dataNonce = this.generateNonce(dataAlgorithm);
      const { ciphertext, authTag } = await this.encryptData(plaintext, dek, dataNonce, dataAlgorithm, additionalData);
      const encryptedDek = await this.encryptDEK(dek, kekEntry.keyMaterial, kekId);

      const now = Date.now();
      const envelope: EncryptionEnvelope = {
        version: this.envelopeVersion, envelopeId: this.secureRandom.randomUUID(), encryptedDek, kekId,
        kekAlgorithm: 'AES-256-GCM', dataAlgorithm, dataNonce, ciphertext, authTag, additionalData,
        metadata: { ...metadata, plaintextLength: plaintext.length },
        createdAt: now, expiresAt: ttl ? now + ttl : undefined,
      };

      this.cacheDEK(envelope.envelopeId, dek);
      this.secureZero(dek);
      return envelope;
    } catch (error) {
      throw this.createError(CryptoErrorCode.ENCRYPTION_FAILED, `Ошибка шифрования: ${error}`);
    }
  }

  async decrypt(envelope: EncryptionEnvelope): Promise<Uint8Array> {
    try {
      if (envelope.expiresAt && envelope.expiresAt < Date.now()) throw this.createError(CryptoErrorCode.KEY_EXPIRED, 'Срок действия конверта истек');
      if (envelope.version !== this.envelopeVersion) throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, `Неподдерживаемая версия конверта: ${envelope.version}`);

      const kekEntry = this.kekStore.get(envelope.kekId);
      if (!kekEntry) throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `KEK с идентификатором ${envelope.kekId} не найден`);
      if (kekEntry.metadata.status !== 'ACTIVE') throw this.createError(CryptoErrorCode.KEY_EXPIRED, `KEK не активен: ${kekEntry.metadata.status}`);

      let dek = this.getCachedDEK(envelope.envelopeId);
      if (!dek) { dek = await this.decryptDEK(envelope.encryptedDek, kekEntry.keyMaterial, envelope.kekId); this.cacheDEK(envelope.envelopeId, dek); }

      return await this.decryptData(envelope.ciphertext, dek, envelope.dataNonce, envelope.dataAlgorithm, envelope.authTag, envelope.additionalData);
    } catch (error) {
      throw this.createError(CryptoErrorCode.DECRYPTION_FAILED, `Ошибка расшифрования: ${error}`);
    }
  }

  async encryptStream(stream: AsyncIterable<Uint8Array>, params: Omit<EnvelopeEncryptionParams, 'plaintext'>): Promise<EncryptionEnvelope> {
    const { dataAlgorithm, kekId, additionalData, metadata, ttl } = params;
    const kekEntry = this.kekStore.get(kekId);
    if (!kekEntry) throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `KEK с идентификатором ${kekId} не найден`);

    try {
      const dekKeySize = this.getDataKeySize(dataAlgorithm);
      const dek = this.secureRandom.randomBytes(dekKeySize);
      const dataNonce = this.generateNonce(dataAlgorithm);

      const cipher = crypto.createCipheriv(this.mapAlgorithmToNode(dataAlgorithm), dek, dataNonce) as crypto.CipherGCM;
      if (additionalData) cipher.setAAD(Buffer.from(additionalData));

      const encryptedChunks: Uint8Array[] = [];
      for await (const chunk of stream) {
        const encrypted = cipher.update(Buffer.from(chunk));
        if (encrypted.length > 0) encryptedChunks.push(new Uint8Array(encrypted));
      }
      const final = cipher.final();
      if (final.length > 0) encryptedChunks.push(new Uint8Array(final));

      const totalLength = encryptedChunks.reduce((sum, chunk) => sum + chunk.length, 0);
      const ciphertext = new Uint8Array(totalLength);
      let offset = 0;
      for (const chunk of encryptedChunks) { ciphertext.set(chunk, offset); offset += chunk.length; }

      const encryptedDek = await this.encryptDEK(dek, kekEntry.keyMaterial, kekId);
      const now = Date.now();
      const envelope: EncryptionEnvelope = {
        version: this.envelopeVersion, envelopeId: this.secureRandom.randomUUID(), encryptedDek, kekId,
        kekAlgorithm: 'AES-256-GCM', dataAlgorithm, dataNonce, ciphertext,
        authTag: new Uint8Array(cipher.getAuthTag()), additionalData, metadata,
        createdAt: now, expiresAt: ttl ? now + ttl : undefined,
      };

      this.cacheDEK(envelope.envelopeId, dek);
      this.secureZero(dek);
      return envelope;
    } catch (error) {
      throw this.createError(CryptoErrorCode.ENCRYPTION_FAILED, `Ошибка потокового шифрования: ${error}`);
    }
  }

  async *decryptStream(envelope: EncryptionEnvelope): AsyncGenerator<Uint8Array> {
    const kekEntry = this.kekStore.get(envelope.kekId);
    if (!kekEntry) throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `KEK с идентификатором ${envelope.kekId} не найден`);

    let dek = this.getCachedDEK(envelope.envelopeId);
    if (!dek) { dek = await this.decryptDEK(envelope.encryptedDek, kekEntry.keyMaterial, envelope.kekId); this.cacheDEK(envelope.envelopeId, dek); }

    const decipher = crypto.createDecipheriv(this.mapAlgorithmToNode(envelope.dataAlgorithm), dek, envelope.dataNonce) as crypto.DecipherGCM;
    if (envelope.authTag) decipher.setAuthTag(Buffer.from(envelope.authTag));
    if (envelope.additionalData) decipher.setAAD(Buffer.from(envelope.additionalData));

    const chunkSize = 64 * 1024;
    for (let offset = 0; offset < envelope.ciphertext.length; offset += chunkSize) {
      const chunk = envelope.ciphertext.slice(offset, offset + chunkSize);
      const decrypted = decipher.update(Buffer.from(chunk));
      if (decrypted.length > 0) yield new Uint8Array(decrypted);
    }
    const final = decipher.final();
    if (final.length > 0) yield new Uint8Array(final);
  }

  async rotateKEK(envelope: EncryptionEnvelope, newKekId: string): Promise<EncryptionEnvelope> {
    const oldKekEntry = this.kekStore.get(envelope.kekId);
    const newKekEntry = this.kekStore.get(newKekId);
    if (!oldKekEntry) throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `Старый KEK не найден: ${envelope.kekId}`);
    if (!newKekEntry) throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `Новый KEK не найден: ${newKekId}`);
    if (newKekEntry.metadata.status !== 'ACTIVE') throw this.createError(CryptoErrorCode.KEY_EXPIRED, `Новый KEK не активен: ${newKekEntry.metadata.status}`);

    try {
      const dek = await this.decryptDEK(envelope.encryptedDek, oldKekEntry.keyMaterial, envelope.kekId);
      const encryptedDek = await this.encryptDEK(dek, newKekEntry.keyMaterial, newKekId);
      const newEnvelope: EncryptionEnvelope = {
        ...envelope, envelopeId: this.secureRandom.randomUUID(), encryptedDek, kekId: newKekId,
        createdAt: Date.now(), metadata: { ...envelope.metadata, rotatedFrom: envelope.envelopeId, rotatedAt: Date.now() },
      };
      this.cacheDEK(newEnvelope.envelopeId, dek);
      this.secureZero(dek);
      return newEnvelope;
    } catch (error) {
      throw this.createError(CryptoErrorCode.ENCRYPTION_FAILED, `Ошибка ротации KEK: ${error}`);
    }
  }

  verifyEnvelope(envelope: EncryptionEnvelope): { valid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];
    if (envelope.version !== this.envelopeVersion) errors.push(`Неподдерживаемая версия: ${envelope.version}`);
    if (!envelope.envelopeId) errors.push('Отсутствует envelopeId');
    if (!envelope.encryptedDek || envelope.encryptedDek.length === 0) errors.push('Отсутствует encryptedDek');
    if (!envelope.ciphertext || envelope.ciphertext.length === 0) errors.push('Отсутствует ciphertext');

    const kekEntry = this.kekStore.get(envelope.kekId);
    if (!kekEntry) errors.push(`KEK не найден: ${envelope.kekId}`);
    else if (kekEntry.metadata.status !== 'ACTIVE') warnings.push(`KEK не активен: ${kekEntry.metadata.status}`);

    if (envelope.expiresAt && envelope.expiresAt < Date.now()) warnings.push('Срок действия конверта истек');
    if (this.isAEADAlgorithm(envelope.dataAlgorithm) && !envelope.authTag) errors.push('Отсутствует authTag для AEAD алгоритма');

    return { valid: errors.length === 0, errors, warnings };
  }

  getKEKMetadata(keyId: string): KeyMetadata | undefined { return this.kekStore.get(keyId)?.metadata; }
  getAllKEKs(): Array<{ keyId: string; metadata: KeyMetadata }> { return Array.from(this.kekStore.entries()).map(([keyId, entry]) => ({ keyId, metadata: entry.metadata })); }

  deactivateKEK(keyId: string): boolean {
    const entry = this.kekStore.get(keyId);
    if (!entry) return false;
    entry.metadata.status = 'DISABLED';
    return true;
  }

  clearDEKCache(): void {
    for (const dek of this.dekCache.values()) { this.secureZero(dek.key); }
    this.dekCache.clear();
  }

  getStats(): { totalKEKs: number; activeKEKs: number; cachedDEKs: number; envelopeVersion: number } {
    const keks = Array.from(this.kekStore.values());
    return { totalKEKs: this.kekStore.size, activeKEKs: keks.filter(k => k.metadata.status === 'ACTIVE').length, cachedDEKs: this.dekCache.size, envelopeVersion: this.envelopeVersion };
  }

  private async encryptData(plaintext: Uint8Array, dek: Uint8Array, nonce: Uint8Array, algorithm: SymmetricAlgorithm, additionalData?: Uint8Array): Promise<{ ciphertext: Uint8Array; authTag: Uint8Array }> {
    const cipher = crypto.createCipheriv(this.mapAlgorithmToNode(algorithm), dek, nonce) as crypto.CipherGCM;
    if (additionalData) cipher.setAAD(Buffer.from(additionalData));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return { ciphertext: new Uint8Array(ciphertext), authTag: new Uint8Array(authTag) };
  }

  private async decryptData(ciphertext: Uint8Array, dek: Uint8Array, nonce: Uint8Array, algorithm: SymmetricAlgorithm, authTag?: Uint8Array, additionalData?: Uint8Array): Promise<Uint8Array> {
    const decipher = crypto.createDecipheriv(this.mapAlgorithmToNode(algorithm), dek, nonce) as crypto.DecipherGCM;
    if (authTag) decipher.setAuthTag(Buffer.from(authTag));
    if (additionalData) decipher.setAAD(Buffer.from(additionalData));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
    return new Uint8Array(plaintext);
  }

  private async encryptDEK(dek: Uint8Array, kek: Buffer, kekId: string): Promise<Uint8Array> {
    const nonce = this.secureRandom.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', kek, nonce) as crypto.CipherGCM;
    const encryptedDek = Buffer.concat([nonce, cipher.update(Buffer.from(dek)), cipher.final(), cipher.getAuthTag()]);
    return new Uint8Array(encryptedDek);
  }

  private async decryptDEK(encryptedDek: Uint8Array, kek: Buffer, kekId: string): Promise<Uint8Array> {
    const nonce = encryptedDek.slice(0, 12);
    const authTag = encryptedDek.slice(encryptedDek.length - 16);
    const ciphertext = encryptedDek.slice(12, encryptedDek.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', kek, nonce) as crypto.DecipherGCM;
    decipher.setAuthTag(Buffer.from(authTag));
    const dek = Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
    return new Uint8Array(dek);
  }

  private generateNonce(algorithm: SymmetricAlgorithm): Uint8Array { return this.secureRandom.randomBytes(this.getNonceSize(algorithm)); }

  private getNonceSize(algorithm: SymmetricAlgorithm): number {
    switch (algorithm) {
      case 'AES-128-GCM': case 'AES-256-GCM': case 'AES-128-CTR': case 'AES-256-CTR': case 'AES-128-CBC': case 'AES-256-CBC': return 12;
      case 'ChaCha20-Poly1305': case 'XChaCha20-Poly1305': return algorithm === 'ChaCha20-Poly1305' ? 12 : 24;
      default: return 12;
    }
  }

  private getDataKeySize(algorithm: SymmetricAlgorithm): number {
    if (algorithm.includes('128')) return 16;
    if (algorithm.includes('256')) return 32;
    return 32;
  }

  private mapAlgorithmToNode(algorithm: SymmetricAlgorithm): string {
    const mapping: Record<SymmetricAlgorithm, string> = {
      'AES-128-GCM': 'aes-128-gcm', 'AES-256-GCM': 'aes-256-gcm', 'AES-128-CTR': 'aes-128-ctr', 'AES-256-CTR': 'aes-256-ctr',
      'AES-128-CBC': 'aes-128-cbc', 'AES-256-CBC': 'aes-256-cbc', 'ChaCha20-Poly1305': 'chacha20-poly1305', 'XChaCha20-Poly1305': 'xchacha20-poly1305',
    };
    return mapping[algorithm] || 'aes-256-gcm';
  }

  private isAEADAlgorithm(algorithm: SymmetricAlgorithm): boolean { return algorithm.includes('GCM') || algorithm.includes('Poly1305'); }

  private cacheDEK(envelopeId: string, dek: Uint8Array): void {
    if (this.dekCache.size >= this.maxDEKCacheSize) {
      const oldestKey = this.dekCache.keys().next().value;
      if (oldestKey) { const oldDEK = this.dekCache.get(oldestKey); if (oldDEK) { this.secureZero(oldDEK.key); } this.dekCache.delete(oldestKey); }
    }
    this.dekCache.set(envelopeId, { key: Buffer.from(dek), cachedAt: Date.now() });
  }

  private getCachedDEK(envelopeId: string): Uint8Array | null {
    const cached = this.dekCache.get(envelopeId);
    if (!cached) return null;
    if (Date.now() - cached.cachedAt > 5 * 60 * 1000) { this.secureZero(cached.key); this.dekCache.delete(envelopeId); return null; }
    return new Uint8Array(cached.key);
  }

  private secureZero(buffer: Uint8Array | Buffer): void {
    if (!buffer || buffer.length === 0) return;
    try { const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer); buf.fill(0); }
    catch { for (let i = 0; i < buffer.length; i++) buffer[i] = 0; }
  }

  private createError(code: CryptoErrorCode, message: string): Error { const error = new Error(message); (error as any).errorCode = code; return error; }
}

export async function encryptEnvelope(plaintext: Uint8Array | string | Buffer, kekId: string, kek: Uint8Array): Promise<EncryptionEnvelope> {
  const service = new EnvelopeEncryptionService({ noSwap: true, autoZero: true, preventCopy: true, useProtectedMemory: false, maxBufferSize: 10 * 1024 * 1024, defaultTTL: 60000 });
  service.registerKEK(kekId, kek);
  const inputData = plaintext instanceof Uint8Array ? plaintext : Buffer.isBuffer(plaintext) ? new Uint8Array(plaintext) : new TextEncoder().encode(plaintext as string);
  return service.encrypt({ plaintext: inputData, dataAlgorithm: 'AES-256-GCM', kekId });
}

export async function decryptEnvelope(envelope: EncryptionEnvelope, kek: Uint8Array): Promise<Uint8Array> {
  const service = new EnvelopeEncryptionService({ noSwap: true, autoZero: true, preventCopy: true, useProtectedMemory: false, maxBufferSize: 10 * 1024 * 1024, defaultTTL: 60000 });
  service.registerKEK(envelope.kekId, kek);
  return service.decrypt(envelope);
}
