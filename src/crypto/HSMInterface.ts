/**
 * ============================================================================
 * HSM/KMS INTERFACE - ИНТЕРФЕЙС АППАРАТНЫХ МОДУЛЕЙ БЕЗОПАСНОСТИ
 * ============================================================================
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  KMSProviderType,
  KMSProviderConfig,
  KMSConnectionStatus,
  KeyMetadata,
  KeyType,
  KeyStatus,
  KeyOperation,
  KeyGenerationParams,
  KeyGenerationResult,
  CryptoErrorCode,
  SecureMemoryConfig,
  AuditEvent,
  AuditEventType,
} from '../types/crypto.types';
import { SecureRandom } from './SecureRandom';

export abstract class HSMProvider extends EventEmitter {
  protected readonly config: KMSProviderConfig;
  protected connected: boolean = false;
  protected lastConnectedAt: Date | null = null;
  protected stats: KMSConnectionStatus['stats'] = {
    totalOperations: 0,
    successfulOperations: 0,
    failedOperations: 0,
    averageLatency: 0,
  };
  protected readonly memoryConfig: SecureMemoryConfig;

  constructor(config: KMSProviderConfig, memoryConfig: SecureMemoryConfig) {
    super();
    this.config = config;
    this.memoryConfig = memoryConfig;
  }

  abstract connect(): Promise<void>;
  abstract disconnect(): Promise<void>;
  abstract isConnected(): boolean;
  abstract generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult>;
  abstract encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array>;
  abstract decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array>;
  abstract sign(keyId: string, data: Uint8Array): Promise<Uint8Array>;
  abstract verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean>;
  abstract getKeyMetadata(keyId: string): Promise<KeyMetadata>;
  abstract deleteKey(keyId: string): Promise<void>;

  getConnectionStatus(): KMSConnectionStatus {
    const errorRate = this.stats.totalOperations > 0 ? this.stats.failedOperations / this.stats.totalOperations : 0;
    let healthStatus: KMSConnectionStatus['health']['status'] = 'HEALTHY';
    if (errorRate > 0.1) healthStatus = 'DEGRADED';
    if (errorRate > 0.5) healthStatus = 'UNHEALTHY';

    return {
      connected: this.connected,
      lastConnected: this.lastConnectedAt || undefined,
      stats: { ...this.stats },
      health: { status: healthStatus, latency: this.stats.averageLatency, errorRate },
    };
  }

  getProviderType(): KMSProviderType { return this.config.type; }
  getProviderId(): string { return this.config.providerId; }

  protected updateStats(success: boolean, latency: number): void {
    this.stats.totalOperations++;
    if (success) this.stats.successfulOperations++;
    else this.stats.failedOperations++;
    const alpha = 0.1;
    this.stats.averageLatency = alpha * latency + (1 - alpha) * this.stats.averageLatency;
  }

  protected createAuditEvent(eventType: AuditEventType, success: boolean, metadata?: Record<string, unknown>): AuditEvent {
    return { eventId: this.generateEventId(), eventType, timestamp: new Date(), success, metadata };
  }

  private generateEventId(): string {
    const random = new SecureRandom(this.memoryConfig);
    return `evt_${random.generateToken(16, 'hex')}`;
  }

  protected wrapError(code: CryptoErrorCode, error: unknown): Error {
    const wrapped = new Error(`${code}: ${error instanceof Error ? error.message : String(error)}`);
    (wrapped as any).errorCode = code;
    return wrapped;
  }
}

export class AWSKMSProvider extends HSMProvider {
  private client: any = null;

  async connect(): Promise<void> {
    const startTime = Date.now();
    try {
      const kmsModule = await import('@aws-sdk/client-kms');
      const KMSClient = kmsModule.KMSClient;
      const ListKeysCommand = kmsModule.ListKeysCommand;
      
      this.client = new KMSClient({
        region: this.config.region || 'us-east-1',
        credentials: this.config.credentials ? {
          accessKeyId: this.config.credentials.accessKeyId,
          secretAccessKey: this.config.credentials.secretAccessKey,
        } : undefined,
      });
      
      await this.client.send(new ListKeysCommand({ Limit: 1 }));
      this.connected = true;
      this.lastConnectedAt = new Date();
      this.updateStats(true, Date.now() - startTime);
      this.emit('connected', { provider: 'AWS_KMS', latency: Date.now() - startTime });
    } catch (error) {
      this.connected = false;
      this.updateStats(false, Date.now() - startTime);
      this.emit('error', { provider: 'AWS_KMS', error });
      throw this.wrapError(CryptoErrorCode.HSM_COMMUNICATION_ERROR, error);
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) { this.client.destroy?.(); this.client = null; }
    this.connected = false;
    this.emit('disconnected', { provider: 'AWS_KMS' });
  }

  isConnected(): boolean { return this.connected && this.client !== null; }

  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    const startTime = Date.now();
    try {
      const kmsModule = await import('@aws-sdk/client-kms');
      const CreateKeyCommand = kmsModule.CreateKeyCommand;
      const DescribeKeyCommand = kmsModule.DescribeKeyCommand;
      
      const createResponse = await this.client.send(new CreateKeyCommand({
        Description: params.description,
        KeyUsage: params.keyType === 'ASYMMETRIC_SIGN' ? 'SIGN_VERIFY' : 'ENCRYPT_DECRYPT',
        KeySpec: this.mapAWSKeySpec(params),
        Tags: params.tags ? Object.entries(params.tags).map(([Key, Value]) => ({ Key, Value })) : undefined,
      }));
      
      const describeResponse = await this.client.send(new DescribeKeyCommand({ KeyId: createResponse.KeyMetadata?.KeyId }));
      this.updateStats(true, Date.now() - startTime);
      const metadata = this.convertAWSKeyMetadata(describeResponse.KeyMetadata, params);
      this.emit('audit', this.createAuditEvent('KEY_CREATED', true, { keyId: metadata.keyId }));
      
      return { metadata, keyId: metadata.keyId };
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.KEY_GENERATION_FAILED, error);
    }
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const kmsModule = await import('@aws-sdk/client-kms');
      const EncryptCommand = kmsModule.EncryptCommand;
      const response = await this.client.send(new EncryptCommand({ KeyId: keyId, Plaintext: Buffer.from(data) }));
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('ENCRYPTION_PERFORMED', true, { keyId }));
      return new Uint8Array(response.CiphertextBlob as Buffer);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.ENCRYPTION_FAILED, error);
    }
  }

  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const kmsModule = await import('@aws-sdk/client-kms');
      const DecryptCommand = kmsModule.DecryptCommand;
      const response = await this.client.send(new DecryptCommand({ CiphertextBlob: Buffer.from(data) }));
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('DECRYPTION_PERFORMED', true, { keyId }));
      return new Uint8Array(response.Plaintext as Buffer);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.DECRYPTION_FAILED, error);
    }
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const kmsModule = await import('@aws-sdk/client-kms');
      const SignCommand = kmsModule.SignCommand;
      const response = await this.client.send(new SignCommand({
        KeyId: keyId, Message: Buffer.from(data), MessageType: 'RAW', SigningAlgorithm: 'RSASSA_PSS_SHA_512',
      }));
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('SIGNATURE_CREATED', true, { keyId }));
      return new Uint8Array(response.Signature as Buffer);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.SIGNATURE_GENERATION_FAILED, error);
    }
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const startTime = Date.now();
    try {
      const kmsModule = await import('@aws-sdk/client-kms');
      const VerifyCommand = kmsModule.VerifyCommand;
      const response = await this.client.send(new VerifyCommand({
        KeyId: keyId, Message: Buffer.from(data), MessageType: 'RAW',
        Signature: Buffer.from(signature), SigningAlgorithm: 'RSASSA_PSS_SHA_512',
      }));
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('SIGNATURE_VERIFIED', true, { keyId, valid: response.SignatureValid }));
      return response.SignatureValid as boolean;
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.SIGNATURE_VERIFICATION_FAILED, error);
    }
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    try {
      const kmsModule = await import('@aws-sdk/client-kms');
      const DescribeKeyCommand = kmsModule.DescribeKeyCommand;
      const response = await this.client.send(new DescribeKeyCommand({ KeyId: keyId }));
      return this.convertAWSKeyMetadata(response.KeyMetadata, { keyType: 'SYMMETRIC', algorithm: 'AES-256', keySize: 256, name: 'Key', exportable: false });
    } catch (error) {
      throw this.wrapError(CryptoErrorCode.KEY_NOT_FOUND, error);
    }
  }

  async deleteKey(keyId: string): Promise<void> {
    try {
      const kmsModule = await import('@aws-sdk/client-kms');
      const ScheduleKeyDeletionCommand = kmsModule.ScheduleKeyDeletionCommand;
      await this.client.send(new ScheduleKeyDeletionCommand({ KeyId: keyId, PendingWindowInDays: 7 }));
      this.emit('audit', this.createAuditEvent('KEY_DESTROYED', true, { keyId }));
    } catch (error) {
      throw this.wrapError(CryptoErrorCode.UNKNOWN_ERROR, error);
    }
  }

  private mapAWSKeySpec(params: KeyGenerationParams): import('@aws-sdk/client-kms').KeySpec | undefined {
    if (params.keyType === 'SYMMETRIC') return 'SYMMETRIC_DEFAULT';
    switch (params.algorithm) {
      case 'RSA-OAEP-4096': case 'RSA-PSS-4096-SHA512': return 'RSA_4096';
      case 'RSA-OAEP-2048': case 'RSA-PSS-2048-SHA256': return 'RSA_2048';
      case 'ECDSA-P256-SHA256': return 'ECC_NIST_P256';
      case 'ECDSA-P384-SHA384': return 'ECC_NIST_P384';
      case 'ECDSA-P521-SHA512': return 'ECC_NIST_P521';
      default: return 'SYMMETRIC_DEFAULT';
    }
  }

  private convertAWSKeyMetadata(awsMetadata: any, params: KeyGenerationParams): KeyMetadata {
    const statusMap: Record<string, KeyStatus> = { 'Enabled': 'ACTIVE', 'Disabled': 'DISABLED', 'PendingDeletion': 'PENDING_DEACTIVATION', 'PendingImport': 'PENDING_ACTIVATION' };
    return {
      keyId: awsMetadata.KeyId,
      name: awsMetadata.Description || params.name || 'Unnamed Key',
      description: awsMetadata.Description,
      keyType: params.keyType,
      algorithm: params.algorithm,
      keySize: params.keySize,
      status: statusMap[awsMetadata.KeyState] || 'DISABLED',
      createdAt: awsMetadata.CreationDate ? new Date(awsMetadata.CreationDate) : new Date(),
      version: 1,
      tags: awsMetadata.Tags?.reduce((acc: any, tag: any) => ({ ...acc, [tag.Key]: tag.Value }), {}),
    };
  }
}

export class GCPKMSProvider extends HSMProvider {
  private client: any = null;
  private parentPath: string = '';

  async connect(): Promise<void> {
    const startTime = Date.now();
    try {
      const kmsModule = await import('@google-cloud/kms');
      const KeyManagementServiceClient = kmsModule.KeyManagementServiceClient;
      this.client = new KeyManagementServiceClient({ credentials: this.config.credentials ? JSON.parse(JSON.stringify(this.config.credentials)) : undefined });
      this.parentPath = `projects/${this.config.extra?.projectId}/locations/${this.config.region || 'global'}`;
      await this.client.listKeyRings({ parent: this.parentPath });
      this.connected = true;
      this.lastConnectedAt = new Date();
      this.updateStats(true, Date.now() - startTime);
      this.emit('connected', { provider: 'GCP_KMS', latency: Date.now() - startTime });
    } catch (error) {
      this.connected = false;
      this.updateStats(false, Date.now() - startTime);
      this.emit('error', { provider: 'GCP_KMS', error });
      throw this.wrapError(CryptoErrorCode.HSM_COMMUNICATION_ERROR, error);
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) { this.client.close(); this.client = null; }
    this.connected = false;
    this.emit('disconnected', { provider: 'GCP_KMS' });
  }

  isConnected(): boolean { return this.connected && this.client !== null; }

  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    const startTime = Date.now();
    try {
      const cryptoKeyId = params.name || `key-${Date.now()}`;
      const cryptoKeyResult = await this.client.createCryptoKey({
        parent: this.parentPath, cryptoKeyId,
        cryptoKey: {
          purpose: params.keyType === 'ASYMMETRIC_SIGN' ? 'ASYMMETRIC_SIGN' : 'ENCRYPT_DECRYPT',
          versionTemplate: { algorithm: this.mapGCPAlgorithm(params) }, labels: params.tags,
        },
      });
      this.updateStats(true, Date.now() - startTime);
      const keyId = cryptoKeyResult[0].name as string;
      this.emit('audit', this.createAuditEvent('KEY_CREATED', true, { keyId }));
      return {
        metadata: { keyId, name: params.name || 'Unnamed Key', description: params.description, keyType: params.keyType, algorithm: params.algorithm, keySize: params.keySize, status: 'ACTIVE', createdAt: new Date(), version: 1, tags: params.tags },
        keyId,
      };
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.KEY_GENERATION_FAILED, error);
    }
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const result = await this.client.encrypt({ name: keyId, plaintext: Buffer.from(data) });
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('ENCRYPTION_PERFORMED', true, { keyId }));
      return new Uint8Array(result[0].ciphertext as Buffer);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.ENCRYPTION_FAILED, error);
    }
  }

  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const result = await this.client.decrypt({ name: keyId, ciphertext: Buffer.from(data) });
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('DECRYPTION_PERFORMED', true, { keyId }));
      return new Uint8Array(result[0].plaintext as Buffer);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.DECRYPTION_FAILED, error);
    }
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const result = await this.client.asymmetricSign({ name: keyId, digest: { sha512: Buffer.from(data).toString('hex') } });
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('SIGNATURE_CREATED', true, { keyId }));
      return new Uint8Array(result[0].signature as Buffer);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.SIGNATURE_GENERATION_FAILED, error);
    }
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    throw new Error('GCP KMS не поддерживает прямую верификацию подписей');
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    try {
      const result = await this.client.getCryptoKey({ name: keyId });
      return { keyId, name: result[0].name || 'Unnamed Key', description: result[0].description, keyType: 'SYMMETRIC', algorithm: result[0].versionTemplate?.algorithm || 'UNKNOWN', keySize: 256, status: 'ACTIVE', createdAt: result[0].createTime ? new Date(result[0].createTime as any) : new Date(), version: 1 };
    } catch (error) {
      throw this.wrapError(CryptoErrorCode.KEY_NOT_FOUND, error);
    }
  }

  async deleteKey(keyId: string): Promise<void> {
    try {
      await this.client.destroyCryptoKeyVersion({ name: keyId });
      this.emit('audit', this.createAuditEvent('KEY_DESTROYED', true, { keyId }));
    } catch (error) {
      throw this.wrapError(CryptoErrorCode.UNKNOWN_ERROR, error);
    }
  }

  private mapGCPAlgorithm(params: KeyGenerationParams): string {
    switch (params.algorithm) {
      case 'RSA-OAEP-4096': return 'RSA_OAEP_4096_SHA256';
      case 'RSA-OAEP-2048': return 'RSA_OAEP_2048_SHA256';
      case 'AES-256-GCM': return 'GOOGLE_SYMMETRIC_ENCRYPTION';
      case 'ECDSA-P256-SHA256': return 'EC_SIGN_P256_SHA256';
      case 'ECDSA-P384-SHA384': return 'EC_SIGN_P384_SHA384';
      default: return 'GOOGLE_SYMMETRIC_ENCRYPTION';
    }
  }
}

export class AzureKeyVaultProvider extends HSMProvider {
  private client: any = null;
  private vaultUrl: string = '';

  async connect(): Promise<void> {
    const startTime = Date.now();
    try {
      const keysModule = await import('@azure/keyvault-keys');
      const identityModule = await import('@azure/identity');
      const KeyClient = keysModule.KeyClient;
      const DefaultAzureCredential = identityModule.DefaultAzureCredential;
      const ClientSecretCredential = identityModule.ClientSecretCredential;
      
      this.vaultUrl = this.config.endpoint || `https://${this.config.extra?.vaultName}.vault.azure.net`;
      const credential = this.config.credentials
        ? new ClientSecretCredential(this.config.credentials.tenantId as string, this.config.credentials.clientId as string, this.config.credentials.clientSecret as string)
        : new DefaultAzureCredential();
      this.client = new KeyClient(this.vaultUrl, credential);
      const pager = this.client.listPropertiesOfKeys();
      await pager.next();
      this.connected = true;
      this.lastConnectedAt = new Date();
      this.updateStats(true, Date.now() - startTime);
      this.emit('connected', { provider: 'AZURE_KEY_VAULT', latency: Date.now() - startTime });
    } catch (error) {
      this.connected = false;
      this.updateStats(false, Date.now() - startTime);
      this.emit('error', { provider: 'AZURE_KEY_VAULT', error });
      throw this.wrapError(CryptoErrorCode.HSM_COMMUNICATION_ERROR, error);
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) { await this.client.close(); this.client = null; }
    this.connected = false;
    this.emit('disconnected', { provider: 'AZURE_KEY_VAULT' });
  }

  isConnected(): boolean { return this.connected && this.client !== null; }

  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    const startTime = Date.now();
    try {
      const keyType = this.mapAzureKeyType(params);
      const result = await this.client.createKey(params.name || `key-${Date.now()}`, keyType, { keySize: params.keySize, keyOps: this.mapAzureKeyOps(params.keyType) });
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('KEY_CREATED', true, { keyId: result.key.id }));
      return {
        metadata: { keyId: result.key.id as string, name: result.key.name as string, description: params.description, keyType: params.keyType, algorithm: params.algorithm, keySize: params.keySize, status: 'ACTIVE', createdAt: result.key.createdOn || new Date(), version: 1 },
        keyId: result.key.id as string,
      };
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.KEY_GENERATION_FAILED, error);
    }
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const result = await this.client.encrypt(keyId, data, { algorithm: 'RSA-OAEP-256' });
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('ENCRYPTION_PERFORMED', true, { keyId }));
      return new Uint8Array(result.result as Buffer);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.ENCRYPTION_FAILED, error);
    }
  }

  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const result = await this.client.decrypt(keyId, data, { algorithm: 'RSA-OAEP-256' });
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('DECRYPTION_PERFORMED', true, { keyId }));
      return new Uint8Array(result.result as Buffer);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.DECRYPTION_FAILED, error);
    }
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const result = await this.client.sign(keyId, data, { algorithm: 'RS512' });
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('SIGNATURE_CREATED', true, { keyId }));
      return new Uint8Array(result.result as Buffer);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.SIGNATURE_GENERATION_FAILED, error);
    }
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const startTime = Date.now();
    try {
      const result = await this.client.verify(keyId, data, signature, { algorithm: 'RS512' });
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('SIGNATURE_VERIFIED', true, { keyId, valid: result.value }));
      return result.value as boolean;
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.SIGNATURE_VERIFICATION_FAILED, error);
    }
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    try {
      const result = await this.client.getKey(keyId);
      return { keyId: result.key.id as string, name: result.key.name as string, keyType: 'SYMMETRIC', algorithm: 'RSA-OAEP', keySize: result.key.keySize || 2048, status: 'ACTIVE', createdAt: result.key.createdOn || new Date(), version: 1 };
    } catch (error) {
      throw this.wrapError(CryptoErrorCode.KEY_NOT_FOUND, error);
    }
  }

  async deleteKey(keyId: string): Promise<void> {
    try {
      await this.client.beginDeleteKey(keyId);
      this.emit('audit', this.createAuditEvent('KEY_DESTROYED', true, { keyId }));
    } catch (error) {
      throw this.wrapError(CryptoErrorCode.UNKNOWN_ERROR, error);
    }
  }

  private mapAzureKeyType(params: KeyGenerationParams): string {
    switch (params.algorithm) {
      case 'RSA-OAEP-4096': case 'RSA-PSS-4096-SHA512': return 'RSA-HSM';
      case 'RSA-OAEP-2048': case 'RSA-PSS-2048-SHA256': return 'RSA';
      case 'ECDSA-P256-SHA256': return 'EC';
      default: return 'oct';
    }
  }

  private mapAzureKeyOps(keyType: KeyType): string[] {
    switch (keyType) {
      case 'ASYMMETRIC_SIGN': return ['sign', 'verify'];
      case 'ASYMMETRIC_ENC': return ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
      default: return ['encrypt', 'decrypt'];
    }
  }
}

export class LocalKMSProvider extends HSMProvider {
  private keys: Map<string, { metadata: KeyMetadata; keyMaterial: Buffer }> = new Map();

  async connect(): Promise<void> { this.connected = true; this.lastConnectedAt = new Date(); this.emit('connected', { provider: 'LOCAL_KMS' }); }
  async disconnect(): Promise<void> { this.keys.clear(); this.connected = false; this.emit('disconnected', { provider: 'LOCAL_KMS' }); }
  isConnected(): boolean { return this.connected; }

  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    const startTime = Date.now();
    try {
      const keyId = `local-key-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      let keyMaterial: Buffer;
      if (params.keyType === 'SYMMETRIC') {
        keyMaterial = crypto.randomBytes(params.keySize / 8);
      } else {
        const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: params.keySize, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
        keyMaterial = Buffer.from(privateKey as unknown as crypto.KeyObject);
      }
      const metadata: KeyMetadata = { keyId, name: params.name || 'Local Key', description: params.description, keyType: params.keyType, algorithm: params.algorithm, keySize: params.keySize, status: 'ACTIVE', createdAt: new Date(), version: 1, tags: params.tags };
      this.keys.set(keyId, { metadata, keyMaterial });
      this.updateStats(true, Date.now() - startTime);
      this.emit('audit', this.createAuditEvent('KEY_CREATED', true, { keyId }));
      return { metadata, keyId };
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.KEY_GENERATION_FAILED, error);
    }
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) throw new Error('Key not found');
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', keyEntry.keyMaterial.slice(0, 32), iv);
      const encrypted = Buffer.concat([cipher.update(data), cipher.final(), iv, cipher.getAuthTag()]);
      this.updateStats(true, Date.now() - startTime);
      return new Uint8Array(encrypted);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.ENCRYPTION_FAILED, error);
    }
  }

  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) throw new Error('Key not found');
      const iv = data.slice(data.length - 28, data.length - 16);
      const authTag = data.slice(data.length - 16);
      const ciphertext = data.slice(0, data.length - 28);
      const decipher = crypto.createDecipheriv('aes-256-gcm', keyEntry.keyMaterial.slice(0, 32), iv);
      decipher.setAuthTag(authTag);
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      this.updateStats(true, Date.now() - startTime);
      return new Uint8Array(decrypted);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.DECRYPTION_FAILED, error);
    }
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) throw new Error('Key not found');
      const signer = crypto.createSign('SHA512');
      signer.update(data);
      signer.end();
      const signature = signer.sign(keyEntry.keyMaterial.toString('utf-8'));
      this.updateStats(true, Date.now() - startTime);
      return new Uint8Array(signature);
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.SIGNATURE_GENERATION_FAILED, error);
    }
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const startTime = Date.now();
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) throw new Error('Key not found');
      const verifier = crypto.createVerify('SHA512');
      verifier.update(data);
      verifier.end();
      const valid = verifier.verify(keyEntry.keyMaterial.toString('utf-8'), signature);
      this.updateStats(true, Date.now() - startTime);
      return valid;
    } catch (error) {
      this.updateStats(false, Date.now() - startTime);
      throw this.wrapError(CryptoErrorCode.SIGNATURE_VERIFICATION_FAILED, error);
    }
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) throw this.wrapError(CryptoErrorCode.KEY_NOT_FOUND, new Error('Key not found'));
    return keyEntry.metadata;
  }

  async deleteKey(keyId: string): Promise<void> {
    if (!this.keys.has(keyId)) throw this.wrapError(CryptoErrorCode.KEY_NOT_FOUND, new Error('Key not found'));
    this.keys.delete(keyId);
    this.emit('audit', this.createAuditEvent('KEY_DESTROYED', true, { keyId }));
  }
}

export class HSMProviderFactory {
  private readonly memoryConfig: SecureMemoryConfig;
  constructor(memoryConfig: SecureMemoryConfig) { this.memoryConfig = memoryConfig; }

  createProvider(config: KMSProviderConfig): HSMProvider {
    switch (config.type) {
      case 'AWS_KMS': return new AWSKMSProvider(config, this.memoryConfig);
      case 'GCP_KMS': return new GCPKMSProvider(config, this.memoryConfig);
      case 'AZURE_KEY_VAULT': return new AzureKeyVaultProvider(config, this.memoryConfig);
      case 'LOCAL_SECURE_ENCLAVE': case 'CUSTOM': return new LocalKMSProvider(config, this.memoryConfig);
      default: throw new Error(`Неподдерживаемый тип провайдера: ${config.type}`);
    }
  }

  createMultiProvider(configs: KMSProviderConfig[]): MultiKMSProvider { return new MultiKMSProvider(configs, this.memoryConfig); }
}

export class MultiKMSProvider extends HSMProvider {
  private providers: HSMProvider[] = [];
  private currentProviderIndex = 0;

  constructor(configs: KMSProviderConfig[], memoryConfig: SecureMemoryConfig) {
    super(configs[0], memoryConfig);
    const factory = new HSMProviderFactory(memoryConfig);
    this.providers = configs.map(config => factory.createProvider(config));
  }

  async connect(): Promise<void> {
    for (const provider of this.providers) {
      try { await provider.connect(); this.connected = true; this.lastConnectedAt = new Date(); return; }
      catch (error) { console.warn(`Failed to connect to provider ${provider.getProviderType()}:`, error); }
    }
    throw new Error('Не удалось подключиться ни к одному KMS провайдеру');
  }

  async disconnect(): Promise<void> { for (const provider of this.providers) { await provider.disconnect(); } this.connected = false; }
  isConnected(): boolean { return this.providers[this.currentProviderIndex]?.isConnected() || false; }
  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> { return this.executeWithFailover('generateKey', params); }
  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> { return this.executeWithFailover('encrypt', keyId, data); }
  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> { return this.executeWithFailover('decrypt', keyId, data); }
  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> { return this.executeWithFailover('sign', keyId, data); }
  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> { return this.executeWithFailover('verify', keyId, data, signature); }
  async getKeyMetadata(keyId: string): Promise<KeyMetadata> { return this.executeWithFailover('getKeyMetadata', keyId); }
  async deleteKey(keyId: string): Promise<void> { return this.executeWithFailover('deleteKey', keyId); }

  private async executeWithFailover(method: string, ...args: any[]): Promise<any> {
    let lastError: Error | null = null;
    for (let i = 0; i < this.providers.length; i++) {
      const providerIndex = (this.currentProviderIndex + i) % this.providers.length;
      const provider = this.providers[providerIndex];
      if (!provider.isConnected()) continue;
      try { const result = await (provider as any)[method](...args); this.currentProviderIndex = providerIndex; return result; }
      catch (error) { lastError = error as Error; console.warn(`Provider ${provider.getProviderType()} failed:`, error); }
    }
    throw lastError || new Error('Все провайдеры недоступны');
  }
}
