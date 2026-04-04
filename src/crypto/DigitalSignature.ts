/**
 * ============================================================================
 * DIGITAL SIGNATURE SERVICE - СЕРВИС ЦИФРОВЫХ ПОДПИСЕЙ
 * ============================================================================
 */

import * as crypto from 'crypto';
import { KeyObject } from 'crypto';
import { SignatureAlgorithm, SignatureResult, SignatureVerificationResult, SigningKeyPair, SecureMemoryConfig, CryptoErrorCode, KeyMetadata, KeyStatus, KeyType, CryptoKey, HashAlgorithm } from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';
import { HashService } from './HashService';

interface SignatureAlgorithmParams { type: 'EdDSA' | 'ECDSA' | 'RSA-PSS' | 'RSA-PKCS1'; hashAlgorithm: HashAlgorithm; keySize: number; signatureSize: number; defaultExpiry?: number; }
interface StoredKeyPair { keyPair: SigningKeyPair; metadata: KeyMetadata; }

export class DigitalSignatureService {
  private readonly memoryConfig: SecureMemoryConfig;
  private readonly hashService: HashService;
  private readonly secureRandom: SecureRandom;
  private readonly algorithmParams: Map<SignatureAlgorithm, SignatureAlgorithmParams>;
  private readonly keyStore: Map<string, StoredKeyPair>;

  constructor(memoryConfig: SecureMemoryConfig) {
    this.memoryConfig = memoryConfig;
    this.hashService = new HashService(memoryConfig);
    this.secureRandom = new SecureRandom(memoryConfig);
    this.algorithmParams = this.initializeAlgorithmParams();
    this.keyStore = new Map();
  }

  async generateKeyPair(algorithm: SignatureAlgorithm = 'Ed25519', keyId?: string): Promise<SigningKeyPair> {
    const params = this.algorithmParams.get(algorithm);
    if (!params) throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, `Алгоритм ${algorithm} не поддерживается`);

    try {
      let keyPair: { publicKey: KeyObject; privateKey: KeyObject };
      switch (params.type) {
        case 'EdDSA': keyPair = this.generateEdDSAKeyPair(algorithm); break;
        case 'ECDSA': keyPair = this.generateECDSAKeyPair(algorithm); break;
        case 'RSA-PSS': case 'RSA-PKCS1': keyPair = this.generateRSAKeyPair(algorithm, params); break;
        default: throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, `Неизвестный тип алгоритма: ${params.type}`);
      }

      const actualKeyId = keyId || this.secureRandom.randomUUID();
      const createdAt = new Date();
      const signingKeyPair: SigningKeyPair = {
        publicKey: keyPair.publicKey, privateKey: keyPair.privateKey, keyId: actualKeyId, algorithm, createdAt,
        expiresAt: params.defaultExpiry ? new Date(createdAt.getTime() + params.defaultExpiry) : undefined,
      };
      this.keyStore.set(actualKeyId, { keyPair: signingKeyPair, metadata: this.createKeyMetadata(signingKeyPair, params) });
      return signingKeyPair;
    } catch (error) {
      throw this.createError(CryptoErrorCode.KEY_GENERATION_FAILED, `Ошибка генерации ключей: ${error}`);
    }
  }

  async sign(data: Uint8Array | string | Buffer, keyIdOrPrivateKey: string | CryptoKey | crypto.KeyObject, algorithm?: SignatureAlgorithm): Promise<SignatureResult> {
    const inputData = this.normalizeInput(data);
    let privateKey: crypto.KeyObject;
    let keyId: string;
    let signAlgorithm: SignatureAlgorithm;

    if (typeof keyIdOrPrivateKey === 'string') {
      const stored = this.keyStore.get(keyIdOrPrivateKey);
      if (!stored) throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `Ключ с идентификатором ${keyIdOrPrivateKey} не найден`);
      if (stored.metadata.status !== 'ACTIVE') throw this.createError(CryptoErrorCode.KEY_EXPIRED, `Ключ не активен: ${stored.metadata.status}`);
      if (stored.keyPair.expiresAt && stored.keyPair.expiresAt < new Date()) throw this.createError(CryptoErrorCode.KEY_EXPIRED, 'Срок действия ключа истек');
      privateKey = stored.keyPair.privateKey;
      keyId = keyIdOrPrivateKey;
      signAlgorithm = stored.keyPair.algorithm;
    } else {
      privateKey = this.webCryptoToNodeCrypto(keyIdOrPrivateKey);
      keyId = 'ephemeral';
      signAlgorithm = algorithm || 'Ed25519';
    }

    try {
      const params = this.algorithmParams.get(signAlgorithm);
      if (!params) throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, `Алгоритм ${signAlgorithm} не поддерживается`);
      const dataHash = this.hashService.hash(inputData, params.hashAlgorithm).hash;
      let signature: Buffer;

      switch (params.type) {
        case 'EdDSA': signature = await this.createEdDSASignature(inputData, privateKey, signAlgorithm); break;
        case 'ECDSA': signature = await this.createECDSASignature(dataHash, privateKey, signAlgorithm); break;
        case 'RSA-PSS': case 'RSA-PKCS1': signature = await this.createRSASignature(dataHash, privateKey, signAlgorithm, params); break;
        default: throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, `Неизвестный тип алгоритма: ${params.type}`);
      }

      return { signature: new Uint8Array(signature), algorithm: signAlgorithm, keyId, dataHash, timestamp: Date.now() };
    } catch (error) {
      throw this.createError(CryptoErrorCode.SIGNATURE_GENERATION_FAILED, `Ошибка создания подписи: ${error}`);
    }
  }

  async verify(data: Uint8Array | string | Buffer, signature: Uint8Array | Buffer, publicKeyOrKeyId: CryptoKey | crypto.KeyObject | string): Promise<SignatureVerificationResult> {
    const inputData = this.normalizeInput(data);
    const signatureBuffer = signature instanceof Buffer ? signature : Buffer.from(signature);
    let publicKey: crypto.KeyObject;
    let algorithm: SignatureAlgorithm;
    let keyValid = true, notExpired = true, notRevoked = true;

    try {
      if (typeof publicKeyOrKeyId === 'string') {
        const stored = this.keyStore.get(publicKeyOrKeyId);
        if (!stored) return this.createVerificationResult(false, false, false, false, false);
        publicKey = stored.keyPair.publicKey;
        algorithm = stored.keyPair.algorithm;
        keyValid = stored.metadata.status === 'ACTIVE';
        notExpired = !stored.keyPair.expiresAt || stored.keyPair.expiresAt >= new Date();
        notRevoked = stored.metadata.status !== 'DESTROYED';
      } else {
        publicKey = this.webCryptoToNodeCrypto(publicKeyOrKeyId);
        algorithm = 'Ed25519';
      }

      const params = this.algorithmParams.get(algorithm);
      if (!params) return this.createVerificationResult(false, keyValid, false, notExpired, notRevoked);

      const dataHash = this.hashService.hash(inputData, params.hashAlgorithm).hash;
      let valid: boolean;

      switch (params.type) {
        case 'EdDSA': valid = await this.verifyEdDSASignature(inputData, signatureBuffer, publicKey, algorithm); break;
        case 'ECDSA': valid = await this.verifyECDSASignature(dataHash, signatureBuffer, publicKey, algorithm); break;
        case 'RSA-PSS': case 'RSA-PKCS1': valid = await this.verifyRSASignature(dataHash, signatureBuffer, publicKey, algorithm, params); break;
        default: valid = false;
      }

      return this.createVerificationResult(valid, keyValid, valid, notExpired, notRevoked);
    } catch (error) {
      return this.createVerificationResult(false, false, false, false, false);
    }
  }

  async verifyWithAlgorithm(data: Uint8Array | string | Buffer, signature: Uint8Array | Buffer, publicKey: CryptoKey | crypto.KeyObject, algorithm: SignatureAlgorithm): Promise<SignatureVerificationResult> {
    const inputData = this.normalizeInput(data);
    const signatureBuffer = signature instanceof Buffer ? signature : Buffer.from(signature);
    try {
      const params = this.algorithmParams.get(algorithm);
      if (!params) return this.createVerificationResult(false, false, false, true, true);
      const nodePublicKey = this.webCryptoToNodeCrypto(publicKey);
      const dataHash = this.hashService.hash(inputData, params.hashAlgorithm).hash;
      let valid: boolean;

      switch (params.type) {
        case 'EdDSA': valid = await this.verifyEdDSASignature(inputData, signatureBuffer, nodePublicKey, algorithm); break;
        case 'ECDSA': valid = await this.verifyECDSASignature(dataHash, signatureBuffer, nodePublicKey, algorithm); break;
        case 'RSA-PSS': case 'RSA-PKCS1': valid = await this.verifyRSASignature(dataHash, signatureBuffer, nodePublicKey, algorithm, params); break;
        default: valid = false;
      }

      return this.createVerificationResult(valid, true, valid, true, true);
    } catch (error) {
      return this.createVerificationResult(false, false, false, true, true);
    }
  }

  async signWithContext(data: Uint8Array | string | Buffer, keyIdOrPrivateKey: string | crypto.KeyObject, context?: { timestamp?: number; nonce?: Uint8Array; additionalData?: Uint8Array }): Promise<SignatureResult> {
    const inputData = this.normalizeInput(data);
    const contextData = this.buildContextData(inputData, context);
    const signatureResult = await this.sign(contextData, keyIdOrPrivateKey);
    return { ...signatureResult, dataHash: this.hashService.hash(inputData).hash };
  }

  async signBatch(messages: (Uint8Array | string | Buffer)[], keyIdOrPrivateKey: string | crypto.KeyObject): Promise<SignatureResult[]> {
    const results: SignatureResult[] = [];
    for (const message of messages) { const result = await this.sign(message, keyIdOrPrivateKey); results.push(result); }
    return results;
  }

  async verifyBatch(items: Array<{ data: Uint8Array | string | Buffer; signature: Uint8Array | Buffer; publicKey: CryptoKey | crypto.KeyObject | string }>): Promise<Array<{ valid: boolean; result: SignatureVerificationResult }>> {
    const results: Array<{ valid: boolean; result: SignatureVerificationResult }> = [];
    for (const item of items) { const result = await this.verify(item.data, item.signature, item.publicKey); results.push({ valid: result.valid, result }); }
    return results;
  }

  getKeyMetadata(keyId: string): KeyMetadata | undefined { const stored = this.keyStore.get(keyId); return stored?.metadata; }
  getAllKeys(): Array<{ keyId: string; metadata: KeyMetadata }> { return Array.from(this.keyStore.entries()).map(([keyId, stored]) => ({ keyId, metadata: stored.metadata })); }

  deleteKey(keyId: string): boolean {
    const stored = this.keyStore.get(keyId);
    if (!stored) return false;
    stored.metadata.status = 'DESTROYED';
    this.secureZeroKey(stored.keyPair.privateKey);
    this.keyStore.delete(keyId);
    return true;
  }

  exportPublicKey(keyIdOrPublicKey: string | CryptoKey | crypto.KeyObject): string {
    let publicKey: crypto.KeyObject;
    if (typeof keyIdOrPublicKey === 'string') {
      const stored = this.keyStore.get(keyIdOrPublicKey);
      if (!stored) throw this.createError(CryptoErrorCode.KEY_NOT_FOUND, `Ключ ${keyIdOrPublicKey} не найден`);
      publicKey = stored.keyPair.publicKey;
    } else {
      publicKey = this.webCryptoToNodeCrypto(keyIdOrPublicKey);
    }
    return publicKey.export({ format: 'pem', type: 'spki' }).toString();
  }

  importPublicKey(pem: string, algorithm: SignatureAlgorithm = 'Ed25519'): CryptoKey {
    const params = this.algorithmParams.get(algorithm);
    if (!params) throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, `Алгоритм ${algorithm} не поддерживается`);
    const keyObject = crypto.createPublicKey({ key: pem, format: 'pem', type: 'spki' });
    return this.nodeCryptoToWebCrypto(keyObject, algorithm);
  }

  getStats(): { totalKeys: number; activeKeys: number; expiredKeys: number; algorithmStats: Record<string, number> } {
    const stats = { totalKeys: this.keyStore.size, activeKeys: 0, expiredKeys: 0, algorithmStats: {} as Record<string, number> };
    for (const [, stored] of this.keyStore) {
      if (stored.metadata.status === 'ACTIVE') stats.activeKeys++;
      if (stored.metadata.status === 'EXPIRED') stats.expiredKeys++;
      const algo = stored.keyPair.algorithm;
      stats.algorithmStats[algo] = (stats.algorithmStats[algo] || 0) + 1;
    }
    return stats;
  }

  private generateEdDSAKeyPair(algorithm: SignatureAlgorithm): { publicKey: KeyObject; privateKey: KeyObject } {
    const curve = algorithm === 'Ed448' ? 'Ed448' : 'Ed25519';
    const keyPair = crypto.generateKeyPairSync(curve.toLowerCase() as 'ed25519' | 'ed448');
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
  }

  private generateECDSAKeyPair(algorithm: SignatureAlgorithm): { publicKey: KeyObject; privateKey: KeyObject } {
    const namedCurve = this.getECDSANamedCurve(algorithm);
    const keyPair = crypto.generateKeyPairSync('ec', { namedCurve });
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
  }

  private generateRSAKeyPair(algorithm: SignatureAlgorithm, params: SignatureAlgorithmParams): { publicKey: KeyObject; privateKey: KeyObject } {
    const modulusLength = params.keySize || 2048;
    const keyPair = crypto.generateKeyPairSync('rsa', { modulusLength });
    return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
  }

  private async createEdDSASignature(data: Uint8Array, privateKey: crypto.KeyObject, algorithm: SignatureAlgorithm): Promise<Buffer> {
    // EdDSA (Ed25519/Ed448) не использует digest — передаем undefined
    // Node.js crypto.sign для EdDSA ожидает undefined вместо названия digest
    return crypto.sign(undefined, data, privateKey);
  }

  private async createECDSASignature(hash: Uint8Array, privateKey: crypto.KeyObject, algorithm: SignatureAlgorithm): Promise<Buffer> {
    const sign = crypto.createSign(this.getECDSASignatureAlgorithm(algorithm));
    sign.update(hash); sign.end();
    return sign.sign(privateKey);
  }

  private async createRSASignature(hash: Uint8Array, privateKey: crypto.KeyObject, algorithm: SignatureAlgorithm, params: SignatureAlgorithmParams): Promise<Buffer> {
    const sign = crypto.createSign(params.hashAlgorithm);
    sign.update(hash); sign.end();
    if (params.type === 'RSA-PSS') return sign.sign({ key: privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
    return sign.sign({ key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
  }

  private async verifyEdDSASignature(data: Uint8Array, signature: Buffer, publicKey: crypto.KeyObject, algorithm: SignatureAlgorithm): Promise<boolean> {
    // EdDSA (Ed25519/Ed448) не использует digest — передаем undefined
    return crypto.verify(undefined, data, publicKey, signature);
  }

  private async verifyECDSASignature(hash: Uint8Array, signature: Buffer, publicKey: crypto.KeyObject, algorithm: SignatureAlgorithm): Promise<boolean> {
    const verify = crypto.createVerify(this.getECDSASignatureAlgorithm(algorithm));
    verify.update(hash); verify.end();
    return verify.verify(publicKey, signature);
  }

  private async verifyRSASignature(hash: Uint8Array, signature: Buffer, publicKey: crypto.KeyObject, algorithm: SignatureAlgorithm, params: SignatureAlgorithmParams): Promise<boolean> {
    const verify = crypto.createVerify(params.hashAlgorithm);
    verify.update(hash); verify.end();
    if (params.type === 'RSA-PSS') return verify.verify({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
    return verify.verify(publicKey, signature);
  }

  private initializeAlgorithmParams(): Map<SignatureAlgorithm, SignatureAlgorithmParams> {
    const params = new Map<SignatureAlgorithm, SignatureAlgorithmParams>();
    params.set('Ed25519', { type: 'EdDSA', hashAlgorithm: 'SHA-512', keySize: 256, signatureSize: 64, defaultExpiry: 365 * 24 * 60 * 60 * 1000 });
    params.set('Ed448', { type: 'EdDSA', hashAlgorithm: 'SHA-512', keySize: 456, signatureSize: 114, defaultExpiry: 365 * 24 * 60 * 60 * 1000 });
    params.set('ECDSA-P256-SHA256', { type: 'ECDSA', hashAlgorithm: 'SHA-256', keySize: 256, signatureSize: 64, defaultExpiry: 365 * 24 * 60 * 60 * 1000 });
    params.set('ECDSA-P384-SHA384', { type: 'ECDSA', hashAlgorithm: 'SHA-384', keySize: 384, signatureSize: 96, defaultExpiry: 365 * 24 * 60 * 60 * 1000 });
    params.set('ECDSA-P521-SHA512', { type: 'ECDSA', hashAlgorithm: 'SHA-512', keySize: 521, signatureSize: 132, defaultExpiry: 365 * 24 * 60 * 60 * 1000 });
    params.set('RSA-PSS-2048-SHA256', { type: 'RSA-PSS', hashAlgorithm: 'SHA-256', keySize: 2048, signatureSize: 256, defaultExpiry: 730 * 24 * 60 * 60 * 1000 });
    params.set('RSA-PSS-3072-SHA384', { type: 'RSA-PSS', hashAlgorithm: 'SHA-384', keySize: 3072, signatureSize: 384, defaultExpiry: 730 * 24 * 60 * 60 * 1000 });
    params.set('RSA-PSS-4096-SHA512', { type: 'RSA-PSS', hashAlgorithm: 'SHA-512', keySize: 4096, signatureSize: 512, defaultExpiry: 730 * 24 * 60 * 60 * 1000 });
    params.set('RSA-PKCS1-2048-SHA256', { type: 'RSA-PKCS1', hashAlgorithm: 'SHA-256', keySize: 2048, signatureSize: 256, defaultExpiry: 730 * 24 * 60 * 60 * 1000 });
    params.set('RSA-PKCS1-4096-SHA512', { type: 'RSA-PKCS1', hashAlgorithm: 'SHA-512', keySize: 4096, signatureSize: 512, defaultExpiry: 730 * 24 * 60 * 60 * 1000 });
    return params;
  }

  private getECDSANamedCurve(algorithm: SignatureAlgorithm): string {
    const curves: Record<string, string> = { 'ECDSA-P256-SHA256': 'prime256v1', 'ECDSA-P384-SHA384': 'secp384r1', 'ECDSA-P521-SHA512': 'secp521r1' };
    return curves[algorithm] || 'prime256v1';
  }

  private getECDSASignatureAlgorithm(algorithm: SignatureAlgorithm): string {
    const algos: Record<string, string> = { 'ECDSA-P256-SHA256': 'SHA256', 'ECDSA-P384-SHA384': 'SHA384', 'ECDSA-P521-SHA512': 'SHA512' };
    return algos[algorithm] || 'SHA256';
  }

  private normalizeInput(data: Uint8Array | string | Buffer): Uint8Array {
    if (data instanceof Buffer) return new Uint8Array(data);
    if (data instanceof Uint8Array) return data;
    if (typeof data === 'string') return new TextEncoder().encode(data);
    throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, 'Неподдерживаемый тип данных');
  }

  private webCryptoToNodeCrypto(key: CryptoKey | crypto.KeyObject | Buffer | Uint8Array | string): crypto.KeyObject {
    if (key instanceof crypto.KeyObject) return key;
    if (Buffer.isBuffer(key) || key instanceof Uint8Array) {
      try { return crypto.createSecretKey(Buffer.from(key)); }
      catch { throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, 'Не удалось импортировать ключ из Buffer'); }
    }
    if (typeof key === 'string') return crypto.createPrivateKey(key);
    if (typeof key === 'object' && 'type' in key && 'extractable' in key) {
      try {
        const webCrypto = (crypto as any).webcrypto;
        if (webCrypto && webCrypto.keys && webCrypto.keys.fromKeyObject) return webCrypto.keys.fromKeyObject(key as any);
        return crypto.createSecretKey(Buffer.from('fallback'));
      } catch { throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, 'Не удалось конвертировать CryptoKey'); }
    }
    if (key && typeof key === 'object' && 'type' in key && 'export' in key) return key as crypto.KeyObject;
    throw this.createError(CryptoErrorCode.INVALID_ARGUMENT, 'Неподдерживаемый тип ключа');
  }

  private nodeCryptoToWebCrypto(keyObject: crypto.KeyObject, algorithm: SignatureAlgorithm): CryptoKey {
    return (crypto as any).webcrypto?.keys.fromKeyObject?.(keyObject) || keyObject as any;
  }

  private createVerificationResult(valid: boolean, keyValid: boolean, signatureIntact: boolean, notExpired: boolean, notRevoked: boolean): SignatureVerificationResult {
    return { valid, details: { keyValid, signatureIntact, notExpired, notRevoked }, verifiedAt: new Date() };
  }

  private buildContextData(data: Uint8Array, context?: { timestamp?: number; nonce?: Uint8Array; additionalData?: Uint8Array }): Uint8Array {
    const parts: Uint8Array[] = [data];
    if (context?.timestamp) { const timestampBuffer = new Uint8Array(8); new DataView(timestampBuffer.buffer).setBigUint64(0, BigInt(context.timestamp)); parts.push(timestampBuffer); }
    if (context?.nonce) parts.push(context.nonce);
    if (context?.additionalData) parts.push(context.additionalData);
    const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of parts) { combined.set(part, offset); offset += part.length; }
    return combined;
  }

  private createKeyMetadata(keyPair: SigningKeyPair, params: SignatureAlgorithmParams): KeyMetadata {
    return { keyId: keyPair.keyId, name: `Signing Key ${keyPair.keyId.slice(0, 8)}`, keyType: 'ASYMMETRIC_SIGN', algorithm: keyPair.algorithm, keySize: params.keySize, status: 'ACTIVE', createdAt: keyPair.createdAt, expiresAt: keyPair.expiresAt, version: 1 };
  }

  private secureZeroKey(key: CryptoKey | crypto.KeyObject): void { }
  private createError(code: CryptoErrorCode, message: string): Error { const error = new Error(message); (error as any).errorCode = code; return error; }
}

export async function generateSigningKeyPair(algorithm?: SignatureAlgorithm): Promise<SigningKeyPair> {
  const service = new DigitalSignatureService({ noSwap: true, autoZero: true, preventCopy: true, useProtectedMemory: false, maxBufferSize: 10 * 1024 * 1024, defaultTTL: 60000 });
  return service.generateKeyPair(algorithm);
}

export async function sign(data: Uint8Array | string | Buffer, privateKey: crypto.KeyObject | string): Promise<Uint8Array> {
  const service = new DigitalSignatureService({ noSwap: true, autoZero: true, preventCopy: true, useProtectedMemory: false, maxBufferSize: 10 * 1024 * 1024, defaultTTL: 60000 });
  const result = await service.sign(data, privateKey);
  return result.signature;
}

export async function verify(data: Uint8Array | string | Buffer, signature: Uint8Array | Buffer, publicKey: CryptoKey | crypto.KeyObject | string): Promise<boolean> {
  const service = new DigitalSignatureService({ noSwap: true, autoZero: true, preventCopy: true, useProtectedMemory: false, maxBufferSize: 10 * 1024 * 1024, defaultTTL: 60000 });
  const result = await service.verify(data, signature, publicKey);
  return result.valid;
}
