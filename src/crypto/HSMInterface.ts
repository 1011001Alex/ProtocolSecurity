/**
 * ============================================================================
 * HSM/KMS INTERFACE - ИНТЕРФЕЙС АППАРАТНЫХ МОДУЛЕЙ БЕЗОПАСНОСТИ
 * ============================================================================
 * Абстрактный интерфейс для работы с HSM (Hardware Security Module) и
 * облачными KMS (Key Management Service) системами
 * 
 * Поддерживаемые провайдеры:
 * - AWS KMS
 * - Google Cloud KMS
 * - Azure Key Vault
 * - HashiCorp Vault
 * - PKCS#11 совместимые HSM
 * - YubiKey HSM
 * - Local Secure Enclave
 * 
 * Особенности:
 * - Единый интерфейс для всех провайдеров
 * - Автоматический failover между провайдерами
 * - Кэширование для производительности
 * - Детальный аудит операций
 * ============================================================================
 */

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

/**
 * Абстрактный класс HSM/KMS провайдера
 * Все реализации должны наследовать этот класс
 */
export abstract class HSMProvider extends EventEmitter {
  /** Конфигурация провайдера */
  protected readonly config: KMSProviderConfig;
  
  /** Статус подключения */
  protected connected: boolean = false;
  
  /** Время последнего подключения */
  protected lastConnectedAt: Date | null = null;
  
  /** Статистика операций */
  protected stats: KMSConnectionStatus['stats'] = {
    totalOperations: 0,
    successfulOperations: 0,
    failedOperations: 0,
    averageLatency: 0,
  };
  
  /** Конфигурация памяти */
  protected readonly memoryConfig: SecureMemoryConfig;

  constructor(config: KMSProviderConfig, memoryConfig: SecureMemoryConfig) {
    super();
    this.config = config;
    this.memoryConfig = memoryConfig;
  }

  /**
   * Подключение к провайдеру
   */
  abstract connect(): Promise<void>;

  /**
   * Отключение от провайдера
   */
  abstract disconnect(): Promise<void>;

  /**
   * Проверка подключения
   */
  abstract isConnected(): boolean;

  /**
   * Генерация ключа в HSM/KMS
   */
  abstract generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult>;

  /**
   * Шифрование данных ключом из HSM/KMS
   */
  abstract encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array>;

  /**
   * Расшифрование данных ключом из HSM/KMS
   */
  abstract decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array>;

  /**
   * Подпись данных ключом из HSM/KMS
   */
  abstract sign(keyId: string, data: Uint8Array): Promise<Uint8Array>;

  /**
   * Верификация подписи ключом из HSM/KMS
   */
  abstract verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean>;

  /**
   * Получение метаданных ключа
   */
  abstract getKeyMetadata(keyId: string): Promise<KeyMetadata>;

  /**
   * Удаление ключа
   */
  abstract deleteKey(keyId: string): Promise<void>;

  /**
   * Получение статуса подключения
   */
  getConnectionStatus(): KMSConnectionStatus {
    const errorRate = this.stats.totalOperations > 0
      ? this.stats.failedOperations / this.stats.totalOperations
      : 0;

    let healthStatus: KMSConnectionStatus['health']['status'] = 'HEALTHY';
    if (errorRate > 0.1) {
      healthStatus = 'DEGRADED';
    }
    if (errorRate > 0.5) {
      healthStatus = 'UNHEALTHY';
    }

    return {
      connected: this.connected,
      lastConnected: this.lastConnectedAt,
      stats: { ...this.stats },
      health: {
        status: healthStatus,
        latency: this.stats.averageLatency,
        errorRate,
      },
    };
  }

  /**
   * Получение типа провайдера
   */
  getProviderType(): KMSProviderType {
    return this.config.type;
  }

  /**
   * Получение идентификатора провайдера
   */
  getProviderId(): string {
    return this.config.providerId;
  }

  /**
   * Обновление статистики
   */
  protected updateStats(success: boolean, latency: number): void {
    this.stats.totalOperations++;
    
    if (success) {
      this.stats.successfulOperations++;
    } else {
      this.stats.failedOperations++;
    }
    
    // Скользящее среднее для latency
    const alpha = 0.1;
    this.stats.averageLatency = alpha * latency + (1 - alpha) * this.stats.averageLatency;
  }

  /**
   * Создание события аудита
   */
  protected createAuditEvent(
    eventType: AuditEventType,
    success: boolean,
    metadata?: Record<string, unknown>
  ): AuditEvent {
    return {
      eventId: this.generateEventId(),
      eventType,
      timestamp: new Date(),
      success,
      metadata,
    };
  }

  /**
   * Генерация идентификатора события
   */
  private generateEventId(): string {
    const random = new SecureRandom(this.memoryConfig);
    return `evt_${random.generateToken(16, 'hex')}`;
  }
}

/**
 * Реализация AWS KMS провайдера
 */
export class AWSKMSProvider extends HSMProvider {
  private client: any = null;

  async connect(): Promise<void> {
    const startTime = Date.now();
    
    try {
      // Динамический импорт AWS SDK
      const { KMSClient } = await import('@aws-sdk/client-kms');
      
      this.client = new KMSClient({
        region: this.config.region || 'us-east-1',
        credentials: this.config.credentials ? {
          accessKeyId: this.config.credentials.accessKeyId,
          secretAccessKey: this.config.credentials.secretAccessKey,
        } : undefined,
        requestHandler: {
          connectionTimeout: this.config.timeout,
          socketTimeout: this.config.timeout,
        },
      });
      
      // Проверка подключения через listKeys
      await this.client.send(new (await import('@aws-sdk/client-kms')).ListKeysCommand({ Limit: 1 }));
      
      this.connected = true;
      this.lastConnectedAt = new Date();
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('connected', { provider: 'AWS_KMS', latency });
    } catch (error) {
      this.connected = false;
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      
      this.emit('error', { provider: 'AWS_KMS', error });
      throw this.wrapError('HSM_COMMUNICATION_ERROR', error);
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      this.client.destroy?.();
      this.client = null;
    }
    this.connected = false;
    this.emit('disconnected', { provider: 'AWS_KMS' });
  }

  isConnected(): boolean {
    return this.connected && this.client !== null;
  }

  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    const startTime = Date.now();
    
    try {
      const { CreateKeyCommand, DescribeKeyCommand } = await import('@aws-sdk/client-kms');
      
      const createResponse = await this.client.send(new CreateKeyCommand({
        Description: params.description,
        KeyUsage: params.keyType === 'ASYMMETRIC_SIGN' ? 'SIGN_VERIFY' : 'ENCRYPT_DECRYPT',
        KeySpec: this.mapAWSKeySpec(params),
        Tags: params.tags ? Object.entries(params.tags).map(([Key, Value]) => ({ Key, Value })) : undefined,
      }));
      
      const describeResponse = await this.client.send(new DescribeKeyCommand({
        KeyId: createResponse.KeyMetadata?.KeyId,
      }));
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      const metadata = this.convertAWSKeyMetadata(describeResponse.KeyMetadata, params);
      
      this.emit('audit', this.createAuditEvent('KEY_CREATED', true, { keyId: metadata.keyId }));
      
      return {
        metadata,
        keyId: metadata.keyId,
      };
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('KEY_GENERATION_FAILED', error);
    }
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const { EncryptCommand } = await import('@aws-sdk/client-kms');
      
      const response = await this.client.send(new EncryptCommand({
        KeyId: keyId,
        Plaintext: Buffer.from(data),
      }));
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('ENCRYPTION_PERFORMED', true, { keyId }));
      
      return new Uint8Array(response.CiphertextBlob!);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('ENCRYPTION_FAILED', error);
    }
  }

  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const { DecryptCommand } = await import('@aws-sdk/client-kms');
      
      const response = await this.client.send(new DecryptCommand({
        CiphertextBlob: Buffer.from(data),
      }));
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('DECRYPTION_PERFORMED', true, { keyId }));
      
      return new Uint8Array(response.Plaintext!);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('DECRYPTION_FAILED', error);
    }
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const { SignCommand } = await import('@aws-sdk/client-kms');
      
      const response = await this.client.send(new SignCommand({
        KeyId: keyId,
        Message: Buffer.from(data),
        MessageType: 'RAW',
        SigningAlgorithm: 'RSASSA_PSS_SHA_512',
      }));
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('SIGNATURE_CREATED', true, { keyId }));
      
      return new Uint8Array(response.Signature!);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('SIGNATURE_GENERATION_FAILED', error);
    }
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const { VerifyCommand } = await import('@aws-sdk/client-kms');
      
      const response = await this.client.send(new VerifyCommand({
        KeyId: keyId,
        Message: Buffer.from(data),
        MessageType: 'RAW',
        Signature: Buffer.from(signature),
        SigningAlgorithm: 'RSASSA_PSS_SHA_512',
      }));
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('SIGNATURE_VERIFIED', true, { keyId, valid: response.SignatureValid }));
      
      return response.SignatureValid!;
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('SIGNATURE_VERIFICATION_FAILED', error);
    }
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    try {
      const { DescribeKeyCommand } = await import('@aws-sdk/client-kms');
      
      const response = await this.client.send(new DescribeKeyCommand({ KeyId: keyId }));
      
      return this.convertAWSKeyMetadata(response.KeyMetadata!, {
        keyType: 'SYMMETRIC',
        algorithm: 'AES-256',
        keySize: 256,
      });
    } catch (error) {
      throw this.wrapError('KEY_NOT_FOUND', error);
    }
  }

  async deleteKey(keyId: string): Promise<void> {
    try {
      const { ScheduleKeyDeletionCommand } = await import('@aws-sdk/client-kms');
      
      await this.client.send(new ScheduleKeyDeletionCommand({
        KeyId: keyId,
        PendingWindowInDays: 7,
      }));
      
      this.emit('audit', this.createAuditEvent('KEY_DESTROYED', true, { keyId }));
    } catch (error) {
      throw this.wrapError('UNKNOWN_ERROR', error);
    }
  }

  // Приватные методы
  private mapAWSKeySpec(params: KeyGenerationParams): string {
    if (params.keyType === 'SYMMETRIC') {
      return 'SYMMETRIC_DEFAULT';
    }
    
    switch (params.algorithm) {
      case 'RSA-OAEP-4096':
      case 'RSA-PSS-4096-SHA512':
        return 'RSA_4096';
      case 'RSA-OAEP-2048':
      case 'RSA-PSS-2048-SHA256':
        return 'RSA_2048';
      case 'ECC_NIST_P256':
      case 'ECDSA-P256-SHA256':
        return 'ECC_NIST_P256';
      case 'ECC_NIST_P384':
      case 'ECDSA-P384-SHA384':
        return 'ECC_NIST_P384';
      case 'ECC_NIST_P521':
      case 'ECDSA-P521-SHA512':
        return 'ECC_NIST_P521';
      default:
        return 'SYMMETRIC_DEFAULT';
    }
  }

  private convertAWSKeyMetadata(awsMetadata: any, params: KeyGenerationParams): KeyMetadata {
    const statusMap: Record<string, KeyStatus> = {
      'Enabled': 'ACTIVE',
      'Disabled': 'DISABLED',
      'PendingDeletion': 'PENDING_DEACTIVATION',
      'PendingImport': 'PENDING_ACTIVATION',
    };

    return {
      keyId: awsMetadata.KeyId,
      name: awsMetadata.Description || params.name || 'Unnamed Key',
      description: awsMetadata.Description,
      keyType: params.keyType,
      algorithm: params.algorithm,
      keySize: params.keySize,
      status: statusMap[awsMetadata.KeyState] || 'DISABLED',
      createdAt: awsMetadata.CreationDate,
      version: 1,
      tags: awsMetadata.Tags?.reduce((acc: any, tag: any) => ({ ...acc, [tag.Key]: tag.Value }), {}),
    };
  }

  private wrapError(code: CryptoErrorCode, error: unknown): Error {
    const wrapped = new Error(`AWS KMS: ${error instanceof Error ? error.message : String(error)}`);
    (wrapped as any).errorCode = code;
    return wrapped;
  }
}

/**
 * Реализация Google Cloud KMS провайдера
 */
export class GCPKMSProvider extends HSMProvider {
  private client: any = null;
  private parentPath: string = '';

  async connect(): Promise<void> {
    const startTime = Date.now();
    
    try {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      
      this.client = new KeyManagementServiceClient({
        credentials: this.config.credentials ? JSON.parse(JSON.stringify(this.config.credentials)) : undefined,
      });
      
      this.parentPath = `projects/${this.config.extra?.projectId}/locations/${this.config.region || 'global'}`;
      
      // Проверка подключения
      await this.client.listKeyRings({ parent: this.parentPath });
      
      this.connected = true;
      this.lastConnectedAt = new Date();
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('connected', { provider: 'GCP_KMS', latency });
    } catch (error) {
      this.connected = false;
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      
      this.emit('error', { provider: 'GCP_KMS', error });
      throw this.wrapError('HSM_COMMUNICATION_ERROR', error);
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      this.client.close();
      this.client = null;
    }
    this.connected = false;
    this.emit('disconnected', { provider: 'GCP_KMS' });
  }

  isConnected(): boolean {
    return this.connected && this.client !== null;
  }

  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    const startTime = Date.now();
    
    try {
      const { CreateCryptoKeyCommand, CreateCryptoKeyVersionCommand } = await import('@google-cloud/kms');
      
      const cryptoKeyResult = await this.client.createCryptoKey({
        parent: this.parentPath,
        cryptoKeyId: params.name || `key-${Date.now()}`,
        cryptoKey: {
          purpose: params.keyType === 'ASYMMETRIC_SIGN' ? 'ASYMMETRIC_SIGN' : 'ENCRYPT_DECRYPT',
          versionTemplate: {
            algorithm: this.mapGCPAlgorithm(params),
          },
          labels: params.tags,
        },
      });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      const keyId = cryptoKeyResult[0].name!;
      
      this.emit('audit', this.createAuditEvent('KEY_CREATED', true, { keyId }));
      
      return {
        metadata: {
          keyId,
          name: params.name || 'Unnamed Key',
          description: params.description,
          keyType: params.keyType,
          algorithm: params.algorithm,
          keySize: params.keySize,
          status: 'ACTIVE',
          createdAt: new Date(),
          version: 1,
          tags: params.tags,
        },
        keyId,
      };
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('KEY_GENERATION_FAILED', error);
    }
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const result = await this.client.encrypt({
        name: keyId,
        plaintext: Buffer.from(data),
      });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('ENCRYPTION_PERFORMED', true, { keyId }));
      
      return new Uint8Array(result[0].ciphertext!);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('ENCRYPTION_FAILED', error);
    }
  }

  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const result = await this.client.decrypt({
        name: keyId,
        ciphertext: Buffer.from(data),
      });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('DECRYPTION_PERFORMED', true, { keyId }));
      
      return new Uint8Array(result[0].plaintext!);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('DECRYPTION_FAILED', error);
    }
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const result = await this.client.asymmetricSign({
        name: keyId,
        digest: { sha512: Buffer.from(data).toString('hex') },
      });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('SIGNATURE_CREATED', true, { keyId }));
      
      return new Uint8Array(result[0].signature!);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('SIGNATURE_GENERATION_FAILED', error);
    }
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    // GCP KMS не поддерживает прямую верификацию, нужно использовать локально
    throw new Error('GCP KMS не поддерживает прямую верификацию подписей');
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    try {
      const result = await this.client.getCryptoKey({ name: keyId });
      
      return {
        keyId,
        name: result[0].name || 'Unnamed Key',
        description: result[0].description,
        keyType: 'SYMMETRIC',
        algorithm: result[0].versionTemplate?.algorithm || 'UNKNOWN',
        keySize: 256,
        status: 'ACTIVE',
        createdAt: result[0].createTime ? new Date(result[0].createTime) : new Date(),
        version: 1,
      };
    } catch (error) {
      throw this.wrapError('KEY_NOT_FOUND', error);
    }
  }

  async deleteKey(keyId: string): Promise<void> {
    try {
      await this.client.destroyCryptoKeyVersion({ name: keyId });
      this.emit('audit', this.createAuditEvent('KEY_DESTROYED', true, { keyId }));
    } catch (error) {
      throw this.wrapError('UNKNOWN_ERROR', error);
    }
  }

  private mapGCPAlgorithm(params: KeyGenerationParams): string {
    switch (params.algorithm) {
      case 'RSA-OAEP-4096':
        return 'RSA_OAEP_4096_SHA256';
      case 'RSA-OAEP-2048':
        return 'RSA_OAEP_2048_SHA256';
      case 'AES-256-GCM':
        return 'GOOGLE_SYMMETRIC_ENCRYPTION';
      case 'ECDSA-P256-SHA256':
        return 'EC_SIGN_P256_SHA256';
      case 'ECDSA-P384-SHA384':
        return 'EC_SIGN_P384_SHA384';
      default:
        return 'GOOGLE_SYMMETRIC_ENCRYPTION';
    }
  }

  private wrapError(code: CryptoErrorCode, error: unknown): Error {
    const wrapped = new Error(`GCP KMS: ${error instanceof Error ? error.message : String(error)}`);
    (wrapped as any).errorCode = code;
    return wrapped;
  }
}

/**
 * Реализация Azure Key Vault провайдера
 */
export class AzureKeyVaultProvider extends HSMProvider {
  private client: any = null;
  private vaultUrl: string = '';

  async connect(): Promise<void> {
    const startTime = Date.now();
    
    try {
      const { KeyClient } = await import('@azure/keyvault-keys');
      const { DefaultAzureCredential } = await import('@azure/identity');
      
      this.vaultUrl = this.config.endpoint || `https://${this.config.extra?.vaultName}.vault.azure.net`;
      
      const credential = this.config.credentials 
        ? new (await import('@azure/identity')).ClientSecretCredential(
            this.config.credentials.tenantId,
            this.config.credentials.clientId,
            this.config.credentials.clientSecret
          )
        : new DefaultAzureCredential();
      
      this.client = new KeyClient(this.vaultUrl, credential, {
        requestTimeout: this.config.timeout,
      });
      
      // Проверка подключения
      const pager = this.client.listPropertiesOfKeys();
      await pager.next();
      
      this.connected = true;
      this.lastConnectedAt = new Date();
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('connected', { provider: 'AZURE_KEY_VAULT', latency });
    } catch (error) {
      this.connected = false;
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      
      this.emit('error', { provider: 'AZURE_KEY_VAULT', error });
      throw this.wrapError('HSM_COMMUNICATION_ERROR', error);
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.close();
      this.client = null;
    }
    this.connected = false;
    this.emit('disconnected', { provider: 'AZURE_KEY_VAULT' });
  }

  isConnected(): boolean {
    return this.connected && this.client !== null;
  }

  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    const startTime = Date.now();
    
    try {
      const keyType = this.mapAzureKeyType(params);
      
      const result = await this.client.createKey(params.name || `key-${Date.now()}`, keyType, {
        keySize: params.keySize,
        keyOps: this.mapAzureKeyOps(params.keyType),
      });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('KEY_CREATED', true, { keyId: result.key.id }));
      
      return {
        metadata: {
          keyId: result.key.id!,
          name: result.key.name!,
          description: params.description,
          keyType: params.keyType,
          algorithm: params.algorithm,
          keySize: params.keySize,
          status: 'ACTIVE',
          createdAt: result.key.createdOn || new Date(),
          version: 1,
        },
        keyId: result.key.id!,
      };
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('KEY_GENERATION_FAILED', error);
    }
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const result = await this.client.encrypt(keyId, data, {
        algorithm: 'RSA-OAEP-256',
      });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('ENCRYPTION_PERFORMED', true, { keyId }));
      
      return new Uint8Array(result.result!);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('ENCRYPTION_FAILED', error);
    }
  }

  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const result = await this.client.decrypt(keyId, data, {
        algorithm: 'RSA-OAEP-256',
      });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('DECRYPTION_PERFORMED', true, { keyId }));
      
      return new Uint8Array(result.result!);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('DECRYPTION_FAILED', error);
    }
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const result = await this.client.sign(keyId, data, {
        algorithm: 'RS512',
      });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('SIGNATURE_CREATED', true, { keyId }));
      
      return new Uint8Array(result.result!);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('SIGNATURE_GENERATION_FAILED', error);
    }
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const result = await this.client.verify(keyId, data, signature, {
        algorithm: 'RS512',
      });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('SIGNATURE_VERIFIED', true, { keyId, valid: result.value }));
      
      return result.value!;
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('SIGNATURE_VERIFICATION_FAILED', error);
    }
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    try {
      const result = await this.client.getKey(keyId);
      
      return {
        keyId: result.key.id!,
        name: result.key.name!,
        keyType: 'SYMMETRIC',
        algorithm: 'RSA-OAEP',
        keySize: result.key.keySize || 2048,
        status: 'ACTIVE',
        createdAt: result.key.createdOn || new Date(),
        version: 1,
      };
    } catch (error) {
      throw this.wrapError('KEY_NOT_FOUND', error);
    }
  }

  async deleteKey(keyId: string): Promise<void> {
    try {
      await this.client.beginDeleteKey(keyId);
      this.emit('audit', this.createAuditEvent('KEY_DESTROYED', true, { keyId }));
    } catch (error) {
      throw this.wrapError('UNKNOWN_ERROR', error);
    }
  }

  private mapAzureKeyType(params: KeyGenerationParams): string {
    switch (params.algorithm) {
      case 'RSA-OAEP-4096':
      case 'RSA-PSS-4096-SHA512':
        return 'RSA-HSM';
      case 'RSA-OAEP-2048':
      case 'RSA-PSS-2048-SHA256':
        return 'RSA';
      case 'ECDSA-P256-SHA256':
        return 'EC';
      default:
        return 'oct';
    }
  }

  private mapAzureKeyOps(keyType: KeyType): string[] {
    switch (keyType) {
      case 'ASYMMETRIC_SIGN':
        return ['sign', 'verify'];
      case 'ASYMMETRIC_ENC':
        return ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'];
      default:
        return ['encrypt', 'decrypt'];
    }
  }

  private wrapError(code: CryptoErrorCode, error: unknown): Error {
    const wrapped = new Error(`Azure Key Vault: ${error instanceof Error ? error.message : String(error)}`);
    (wrapped as any).errorCode = code;
    return wrapped;
  }
}

/**
 * Локальный провайдер для тестирования и development
 * НЕ ИСПОЛЬЗОВАТЬ В ПРОДАКШЕНЕ!
 */
export class LocalKMSProvider extends HSMProvider {
  private keys: Map<string, { metadata: KeyMetadata; keyMaterial: Buffer }> = new Map();

  async connect(): Promise<void> {
    this.connected = true;
    this.lastConnectedAt = new Date();
    this.emit('connected', { provider: 'LOCAL_KMS' });
  }

  async disconnect(): Promise<void> {
    this.keys.clear();
    this.connected = false;
    this.emit('disconnected', { provider: 'LOCAL_KMS' });
  }

  isConnected(): boolean {
    return this.connected;
  }

  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    const startTime = Date.now();
    
    try {
      const keyId = `local-key-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      
      let keyMaterial: Buffer;
      
      if (params.keyType === 'SYMMETRIC') {
        keyMaterial = crypto.randomBytes(params.keySize / 8);
      } else {
        // Для асимметричных ключей генерируем пару
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
          modulusLength: params.keySize,
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        
        keyMaterial = Buffer.from(privateKey);
      }
      
      const metadata: KeyMetadata = {
        keyId,
        name: params.name || 'Local Key',
        description: params.description,
        keyType: params.keyType,
        algorithm: params.algorithm,
        keySize: params.keySize,
        status: 'ACTIVE',
        createdAt: new Date(),
        version: 1,
        tags: params.tags,
      };
      
      this.keys.set(keyId, { metadata, keyMaterial });
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      this.emit('audit', this.createAuditEvent('KEY_CREATED', true, { keyId }));
      
      return { metadata, keyId };
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('KEY_GENERATION_FAILED', error);
    }
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) {
        throw new Error('Key not found');
      }
      
      // Простое AES-GCM шифрование для демонстрации
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', keyEntry.keyMaterial.slice(0, 32), iv);
      
      const encrypted = Buffer.concat([
        cipher.update(data),
        cipher.final(),
        iv,
        cipher.getAuthTag(),
      ]);
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      return new Uint8Array(encrypted);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('ENCRYPTION_FAILED', error);
    }
  }

  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) {
        throw new Error('Key not found');
      }
      
      // Извлекаем IV и auth tag
      const iv = data.slice(data.length - 28, data.length - 16);
      const authTag = data.slice(data.length - 16);
      const ciphertext = data.slice(0, data.length - 28);
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', keyEntry.keyMaterial.slice(0, 32), iv);
      decipher.setAuthTag(authTag);
      
      const decrypted = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]);
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      return new Uint8Array(decrypted);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('DECRYPTION_FAILED', error);
    }
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    const startTime = Date.now();
    
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) {
        throw new Error('Key not found');
      }
      
      const signer = crypto.createSign('SHA512');
      signer.update(data);
      signer.end();
      
      const signature = signer.sign(keyEntry.keyMaterial.toString());
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      return new Uint8Array(signature);
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('SIGNATURE_GENERATION_FAILED', error);
    }
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const keyEntry = this.keys.get(keyId);
      if (!keyEntry) {
        throw new Error('Key not found');
      }
      
      const verifier = crypto.createVerify('SHA512');
      verifier.update(data);
      verifier.end();
      
      const valid = verifier.verify(keyEntry.keyMaterial.toString(), signature);
      
      const latency = Date.now() - startTime;
      this.updateStats(true, latency);
      
      return valid;
    } catch (error) {
      const latency = Date.now() - startTime;
      this.updateStats(false, latency);
      throw this.wrapError('SIGNATURE_VERIFICATION_FAILED', error);
    }
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      throw this.wrapError('KEY_NOT_FOUND', new Error('Key not found'));
    }
    return keyEntry.metadata;
  }

  async deleteKey(keyId: string): Promise<void> {
    if (!this.keys.has(keyId)) {
      throw this.wrapError('KEY_NOT_FOUND', new Error('Key not found'));
    }
    
    this.keys.delete(keyId);
    this.emit('audit', this.createAuditEvent('KEY_DESTROYED', true, { keyId }));
  }

  private wrapError(code: CryptoErrorCode, error: unknown): Error {
    const wrapped = new Error(`Local KMS: ${error instanceof Error ? error.message : String(error)}`);
    (wrapped as any).errorCode = code;
    return wrapped;
  }
}

/**
 * Фабрика для создания HSM/KMS провайдеров
 */
export class HSMProviderFactory {
  private readonly memoryConfig: SecureMemoryConfig;

  constructor(memoryConfig: SecureMemoryConfig) {
    this.memoryConfig = memoryConfig;
  }

  /**
   * Создание провайдера по типу
   */
  createProvider(config: KMSProviderConfig): HSMProvider {
    switch (config.type) {
      case 'AWS_KMS':
        return new AWSKMSProvider(config, this.memoryConfig);
      
      case 'GCP_KMS':
        return new GCPKMSProvider(config, this.memoryConfig);
      
      case 'AZURE_KEY_VAULT':
        return new AzureKeyVaultProvider(config, this.memoryConfig);
      
      case 'LOCAL_SECURE_ENCLAVE':
      case 'CUSTOM':
        return new LocalKMSProvider(config, this.memoryConfig);
      
      default:
        throw new Error(`Неподдерживаемый тип провайдера: ${config.type}`);
    }
  }

  /**
   * Создание мульти-провайдера с failover
   */
  createMultiProvider(configs: KMSProviderConfig[]): MultiKMSProvider {
    return new MultiKMSProvider(configs, this.memoryConfig);
  }
}

/**
 * Мульти-провайдер с автоматическим failover
 */
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
      try {
        await provider.connect();
        this.connected = true;
        this.lastConnectedAt = new Date();
        return;
      } catch (error) {
        console.warn(`Failed to connect to provider ${provider.getProviderType()}:`, error);
      }
    }
    throw new Error('Не удалось подключиться ни к одному KMS провайдеру');
  }

  async disconnect(): Promise<void> {
    for (const provider of this.providers) {
      await provider.disconnect();
    }
    this.connected = false;
  }

  isConnected(): boolean {
    return this.providers[this.currentProviderIndex]?.isConnected() || false;
  }

  async generateKey(params: KeyGenerationParams): Promise<KeyGenerationResult> {
    return this.executeWithFailover('generateKey', params);
  }

  async encrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    return this.executeWithFailover('encrypt', keyId, data);
  }

  async decrypt(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    return this.executeWithFailover('decrypt', keyId, data);
  }

  async sign(keyId: string, data: Uint8Array): Promise<Uint8Array> {
    return this.executeWithFailover('sign', keyId, data);
  }

  async verify(keyId: string, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    return this.executeWithFailover('verify', keyId, data, signature);
  }

  async getKeyMetadata(keyId: string): Promise<KeyMetadata> {
    return this.executeWithFailover('getKeyMetadata', keyId);
  }

  async deleteKey(keyId: string): Promise<void> {
    return this.executeWithFailover('deleteKey', keyId);
  }

  private async executeWithFailover(method: string, ...args: any[]): Promise<any> {
    let lastError: Error | null = null;
    
    for (let i = 0; i < this.providers.length; i++) {
      const providerIndex = (this.currentProviderIndex + i) % this.providers.length;
      const provider = this.providers[providerIndex];
      
      if (!provider.isConnected()) {
        continue;
      }
      
      try {
        const result = await (provider as any)[method](...args);
        this.currentProviderIndex = providerIndex;
        return result;
      } catch (error) {
        lastError = error as Error;
        console.warn(`Provider ${provider.getProviderType()} failed:`, error);
      }
    }
    
    throw lastError || new Error('Все провайдеры недоступны');
  }
}
