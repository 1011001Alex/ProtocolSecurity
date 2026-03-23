/**
 * ============================================================================
 * DYNAMIC SECRETS - ДИНАМИЧЕСКАЯ ГЕНЕРАЦИЯ СЕКРЕТОВ
 * ============================================================================
 * 
 * Реализует систему динамической генерации секретов по запросу:
 * - Database credentials (PostgreSQL, MySQL, MongoDB, Redis)
 * - API keys и токены
 * - OAuth токены
 * - SSH ключи
 * - TLS сертификаты
 * - AWS временные credentials
 * - Kubernetes service accounts
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { randomBytes, createHash, generateKeyPairSync, createSign, createVerify } from 'crypto';
import {
  DynamicSecretType,
  DynamicSecretConfig,
  GeneratedDynamicSecret,
  SecretLease,
  SecretLeaseError,
  SecretBackendError,
  RotationConfig
} from '../types/secrets.types';
import { SecretLeaseManager } from './SecretLeaseManager';

/**
 * Конфигурация генератора динамических секретов
 */
interface DynamicSecretsConfig {
  /** Максимальное количество активных динамических секретов */
  maxActiveSecrets: number;
  /** Default TTL для динамических секретов */
  defaultTTL: number;
  /** Включить автоматическую очистку */
  enableAutoCleanup: boolean;
  /** Интервал очистки (сек) */
  cleanupInterval: number;
}

/**
 * Сгенерированные учётные данные базы данных
 */
interface DatabaseCredentials {
  username: string;
  password: string;
  host?: string;
  port?: number;
  database?: string;
  connectionString?: string;
}

/**
 * Сгенерированные AWS credentials
 */
interface AWSTempCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: Date;
}

/**
 * Сгенерированный SSH ключ
 */
interface SSHKeyPair {
  publicKey: string;
  privateKey: string;
  fingerprint: string;
  keyType: 'rsa' | 'ed25519' | 'ecdsa';
}

/**
 * Сгенерированный TLS сертификат
 */
interface TLSCertificate {
  certificate: string;
  privateKey: string;
  caCertificate?: string;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  commonName: string;
}

/**
 * Состояние динамического секрета
 */
interface DynamicSecretState {
  secret: GeneratedDynamicSecret;
  lease?: SecretLease;
  createdAt: Date;
  expiresAt: Date;
  renewed: boolean;
  revoked: boolean;
}

/**
 * Интерфейс генератора секретов
 */
interface SecretTypeGenerator {
  generate(config: DynamicSecretConfig): Promise<Record<string, string>>;
  validate?(credentials: Record<string, string>): Promise<boolean>;
  revoke?(credentials: Record<string, string>): Promise<void>;
}

/**
 * Класс для управления динамическими секретами
 * 
 * Особенности:
 * - Генерация секретов по запросу
 * - Автоматическое истечение
 * - Интеграция с внешними системами (БД, облака)
 * - Валидация сгенерированных секретов
 * - Отзыв при компрометации
 */
export class DynamicSecretsManager extends EventEmitter {
  /** Конфигурация менеджера */
  private readonly config: DynamicSecretsConfig;
  
  /** Хранилище активных динамических секретов */
  private secrets: Map<string, DynamicSecretState>;
  
  /** Генераторы для разных типов секретов */
  private generators: Map<DynamicSecretType, SecretTypeGenerator>;
  
  /** Менеджер lease */
  private leaseManager?: SecretLeaseManager;
  
  /** Интервал очистки */
  private cleanupInterval?: NodeJS.Timeout;

  /** Конфигурация по умолчанию */
  private readonly DEFAULT_CONFIG: DynamicSecretsConfig = {
    maxActiveSecrets: 1000,
    defaultTTL: 3600,
    enableAutoCleanup: true,
    cleanupInterval: 60
  };

  /**
   * Создаёт новый экземпляр DynamicSecretsManager
   * 
   * @param config - Конфигурация менеджера
   */
  constructor(config: Partial<DynamicSecretsConfig> = {}) {
    super();
    
    this.config = {
      ...this.DEFAULT_CONFIG,
      ...config
    };
    
    this.secrets = new Map();
    this.generators = new Map();
    
    // Регистрация генераторов
    this.registerGenerators();
  }

  /**
   * Регистрация генераторов для всех типов секретов
   */
  private registerGenerators(): void {
    this.generators.set(DynamicSecretType.DATABASE_CREDENTIALS, {
      generate: async (config) => this.generateDatabaseCredentials(config)
    });
    
    this.generators.set(DynamicSecretType.API_KEY, {
      generate: async (config) => this.generateApiKey(config)
    });
    
    this.generators.set(DynamicSecretType.OAUTH_TOKEN, {
      generate: async (config) => this.generateOAuthToken(config)
    });
    
    this.generators.set(DynamicSecretType.SSH_KEY, {
      generate: async (config) => this.generateSSHKey(config)
    });
    
    this.generators.set(DynamicSecretType.TLS_CERTIFICATE, {
      generate: async (config) => this.generateTLSCertificate(config)
    });
    
    this.generators.set(DynamicSecretType.AWS_TEMP_CREDENTIALS, {
      generate: async (config) => this.generateAWSCredentials(config)
    });
    
    this.generators.set(DynamicSecretType.K8S_SERVICE_ACCOUNT, {
      generate: async (config) => this.generateK8SServiceAccount(config)
    });
    
    this.generators.set(DynamicSecretType.CUSTOM, {
      generate: async (config) => this.generateCustomSecret(config)
    });
  }

  /**
   * Инициализация менеджера
   * 
   * @param leaseManager - Менеджер lease для интеграции
   */
  async initialize(leaseManager?: SecretLeaseManager): Promise<void> {
    this.leaseManager = leaseManager;
    
    // Запуск автоматической очистки
    if (this.config.enableAutoCleanup) {
      this.cleanupInterval = setInterval(() => {
        this.cleanupExpiredSecrets();
      }, this.config.cleanupInterval * 1000);
      
      this.cleanupInterval.unref();
    }

    logger.info('[DynamicSecrets] Инициализирован', {
      maxActiveSecrets: this.config.maxActiveSecrets,
      defaultTTL: this.config.defaultTTL
    });
  }

  /**
   * Остановка менеджера
   */
  async destroy(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }

    // Отзыв всех активных секретов
    for (const [secretId, state] of this.secrets.entries()) {
      await this.revokeSecret(secretId, 'system_shutdown');
    }

    logger.info('[DynamicSecrets] Остановлен');
  }

  /**
   * Создать динамический секрет
   * 
   * @param type - Тип секрета
   * @param config - Конфигурация
   * @param requestedBy - Кто запросил
   * @param ttl - Время жизни (опционально)
   * @returns Сгенерированный секрет
   */
  async createSecret(
    type: DynamicSecretType,
    config: DynamicSecretConfig,
    requestedBy: string,
    ttl?: number
  ): Promise<GeneratedDynamicSecret> {
    // Проверка лимита
    if (this.secrets.size >= this.config.maxActiveSecrets) {
      throw new SecretLeaseError(
        `Превышен лимит активных секретов (${this.config.maxActiveSecrets})`
      );
    }
    
    // Получение генератора
    const generator = this.generators.get(type);
    
    if (!generator) {
      throw new SecretBackendError(`Неизвестный тип секрета: ${type}`, 'unknown' as any);
    }
    
    // Генерация секретных данных
    const credentials = await generator.generate(config);
    
    // Вычисление TTL
    const effectiveTTL = ttl ?? config.ttl ?? this.config.defaultTTL;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + effectiveTTL * 1000);
    
    // Создание ID секрета
    const secretId = this.generateSecretId(type);
    
    // Создание объекта секрета
    const secret: GeneratedDynamicSecret = {
      secretId,
      type,
      credentials,
      createdAt: now,
      expiresAt,
      leaseId: '',
      metadata: {
        requestedBy,
        generationParams: config.generationParams,
        sourceConfig: config.sourceConfig
      }
    };
    
    // Создание lease если подключён менеджер
    if (this.leaseManager) {
      const lease = await this.leaseManager.acquireLease(
        secretId,
        {
          subjectId: requestedBy,
          roles: [],
          attributes: { type: 'dynamic-secret' },
          ipAddress: 'internal',
          timestamp: now,
          mfaVerified: false
        },
        effectiveTTL
      );
      
      secret.leaseId = lease.leaseId;
    }
    
    // Сохранение состояния
    const state: DynamicSecretState = {
      secret,
      createdAt: now,
      expiresAt,
      renewed: false,
      revoked: false
    };
    
    this.secrets.set(secretId, state);

    logger.info(`[DynamicSecrets] Создан динамический секрет ${secretId}`, {
      type
    });

    this.emit('secret:created', {
      secretId,
      type,
      expiresAt
    });
    
    // Возвращаем секрет без чувствительных данных в metadata
    return {
      ...secret,
      credentials: { ...credentials } // Копия для безопасности
    };
  }

  /**
   * Получить динамический секрет
   * 
   * @param secretId - ID секрета
   * @returns Секрет или null
   */
  getSecret(secretId: string): GeneratedDynamicSecret | null {
    const state = this.secrets.get(secretId);
    
    if (!state || state.revoked) {
      return null;
    }
    
    // Проверка истечения
    if (new Date() > state.expiresAt) {
      void this.revokeSecret(secretId, 'expired');
      return null;
    }
    
    return state.secret;
  }

  /**
   * Продлить динамический секрет
   * 
   * @param secretId - ID секрета
   * @param additionalTTL - Дополнительный TTL
   * @param requestedBy - Кто запросил
   * @returns Обновлённый секрет
   */
  async renewSecret(
    secretId: string,
    additionalTTL: number,
    requestedBy: string
  ): Promise<GeneratedDynamicSecret> {
    const state = this.secrets.get(secretId);
    
    if (!state) {
      throw new SecretLeaseError(`Секрет ${secretId} не найден`);
    }
    
    if (state.revoked) {
      throw new SecretLeaseError(`Секрет ${secretId} отозван`);
    }
    
    // Проверка истечения
    if (new Date() > state.expiresAt) {
      throw new SecretLeaseError(`Секрет ${secretId} истёк`);
    }
    
    // Продление lease
    if (this.leaseManager && state.lease) {
      await this.leaseManager.renewLease(
        state.lease.leaseId,
        {
          subjectId: requestedBy,
          roles: [],
          attributes: {},
          ipAddress: 'internal',
          timestamp: new Date(),
          mfaVerified: false
        },
        additionalTTL
      );
    }
    
    // Обновление времени истечения
    state.expiresAt = new Date(Date.now() + additionalTTL * 1000);
    state.secret.expiresAt = state.expiresAt;
    state.renewed = true;

    logger.info(`[DynamicSecrets] Продлён секрет ${secretId}`);

    this.emit('secret:renewed', {
      secretId,
      newExpiresAt: state.expiresAt
    });
    
    return state.secret;
  }

  /**
   * Отозвать динамический секрет
   * 
   * @param secretId - ID секрета
   * @param reason - Причина отзыва
   * @returns Успешность отзыва
   */
  async revokeSecret(secretId: string, reason: string): Promise<boolean> {
    const state = this.secrets.get(secretId);
    
    if (!state || state.revoked) {
      return false;
    }
    
    // Отзыв через генератор если есть метод revoke
    const generator = this.generators.get(state.secret.type);
    
    if (generator?.revoke) {
      try {
        await generator.revoke(state.secret.credentials);
      } catch (error) {
        logger.error(`[DynamicSecrets] Ошибка отзыва секрета ${secretId}`, { error });
      }
    }
    
    // Отзыв lease
    if (this.leaseManager && state.lease) {
      try {
        await this.leaseManager.revokeLease(
          state.lease.leaseId,
          {
            subjectId: 'system',
            roles: ['admin'],
            attributes: {},
            ipAddress: 'internal',
            timestamp: new Date(),
            mfaVerified: false
          },
          reason
        );
      } catch (error) {
        logger.error(`[DynamicSecrets] Ошибка отзыва lease для ${secretId}`, { error });
      }
    }
    
    // Обновление состояния
    state.revoked = true;
    
    // Удаление из хранилища
    this.secrets.delete(secretId);

    logger.info(`[DynamicSecrets] Отозван секрет ${secretId}`, {
      reason
    });

    this.emit('secret:revoked', {
      secretId,
      reason,
      type: state.secret.type
    });
    
    return true;
  }

  /**
   * Очистка истёкших секретов
   */
  private cleanupExpiredSecrets(): void {
    const now = Date.now();
    let cleanedCount = 0;
    
    for (const [secretId, state] of this.secrets.entries()) {
      if (now > state.expiresAt.getTime()) {
        void this.revokeSecret(secretId, 'expired').then(() => {
          cleanedCount++;
        });
      }
    }
    
    if (cleanedCount > 0) {
      logger.info(`[DynamicSecrets] Очищено ${cleanedCount} истёкших секретов`);
    }
  }

  /**
   * Генерация ID секрета
   */
  private generateSecretId(type: DynamicSecretType): string {
    const prefix = this.getTypePrefix(type);
    const timestamp = Date.now().toString(36);
    const random = randomBytes(8).toString('hex');
    
    return `${prefix}_${timestamp}_${random}`;
  }

  /**
   * Префикс для типа секрета
   */
  private getTypePrefix(type: DynamicSecretType): string {
    switch (type) {
      case DynamicSecretType.DATABASE_CREDENTIALS:
        return 'db';
      case DynamicSecretType.API_KEY:
        return 'api';
      case DynamicSecretType.OAUTH_TOKEN:
        return 'oauth';
      case DynamicSecretType.SSH_KEY:
        return 'ssh';
      case DynamicSecretType.TLS_CERTIFICATE:
        return 'tls';
      case DynamicSecretType.AWS_TEMP_CREDENTIALS:
        return 'aws';
      case DynamicSecretType.K8S_SERVICE_ACCOUNT:
        return 'k8s';
      case DynamicSecretType.CUSTOM:
        return 'cust';
      default:
        return 'sec';
    }
  }

  // ============================================================================
  // ГЕНЕРАТОРЫ СЕКРЕТОВ
  // ============================================================================

  /**
   * Генерация учётных данных базы данных
   */
  private async generateDatabaseCredentials(
    config: DynamicSecretConfig
  ): Promise<Record<string, string>> {
    const params = config.generationParams as {
      dbType?: 'postgresql' | 'mysql' | 'mongodb' | 'redis';
      usernamePrefix?: string;
      passwordLength?: number;
      host?: string;
      port?: number;
      database?: string;
    };
    
    const dbType = params.dbType ?? 'postgresql';
    const usernamePrefix = params.usernamePrefix ?? 'dyn';
    const passwordLength = params.passwordLength ?? 32;
    
    // Генерация уникального username
    const username = `${usernamePrefix}_${randomBytes(6).toString('hex')}`;
    
    // Генерация сложного пароля
    const password = this.generateSecurePassword(passwordLength);
    
    const credentials: DatabaseCredentials = {
      username,
      password,
      host: params.host,
      port: params.port,
      database: params.database
    };
    
    // Формирование connection string в зависимости от типа БД
    switch (dbType) {
      case 'postgresql':
        credentials.connectionString = `postgresql://${username}:${password}@${params.host ?? 'localhost'}:${params.port ?? 5432}/${params.database ?? ''}`;
        break;
      case 'mysql':
        credentials.connectionString = `mysql://${username}:${password}@${params.host ?? 'localhost'}:${params.port ?? 3306}/${params.database ?? ''}`;
        break;
      case 'mongodb':
        credentials.connectionString = `mongodb://${username}:${password}@${params.host ?? 'localhost'}:${params.port ?? 27017}/${params.database ?? ''}`;
        break;
      case 'redis':
        credentials.connectionString = `redis://${username}:${password}@${params.host ?? 'localhost'}:${params.port ?? 6379}`;
        break;
    }
    
    // Здесь должна быть интеграция с БД для создания пользователя
    // await this.createDatabaseUser(dbType, credentials, config.sourceConfig);
    
    return {
      username: credentials.username,
      password: credentials.password,
      connectionString: credentials.connectionString!,
      host: credentials.host ?? 'localhost',
      port: String(credentials.port ?? this.getDefaultDbPort(dbType)),
      database: credentials.database ?? ''
    };
  }

  /**
   * Порт по умолчанию для БД
   */
  private getDefaultDbPort(dbType: string): number {
    switch (dbType) {
      case 'postgresql': return 5432;
      case 'mysql': return 3306;
      case 'mongodb': return 27017;
      case 'redis': return 6379;
      default: return 5432;
    }
  }

  /**
   * Генерация API ключа
   */
  private async generateApiKey(
    config: DynamicSecretConfig
  ): Promise<Record<string, string>> {
    const params = config.generationParams as {
      prefix?: string;
      length?: number;
      includeChecksum?: boolean;
    };
    
    const prefix = params.prefix ?? 'sk';
    const length = params.length ?? 32;
    const includeChecksum = params.includeChecksum ?? true;
    
    // Генерация случайной части
    const randomPart = randomBytes(length).toString('hex');
    
    // Формирование ключа
    let apiKey = `${prefix}_${randomPart}`;
    
    // Добавление checksum если требуется
    if (includeChecksum) {
      const checksum = createHash('sha256')
        .update(apiKey)
        .digest('hex')
        .slice(0, 4);
      apiKey = `${apiKey}_${checksum}`;
    }
    
    return {
      apiKey,
      keyId: randomBytes(8).toString('hex'),
      createdAt: new Date().toISOString()
    };
  }

  /**
   * Генерация OAuth токена
   */
  private async generateOAuthToken(
    config: DynamicSecretConfig
  ): Promise<Record<string, string>> {
    const params = config.generationParams as {
      tokenType?: 'bearer' | 'macaroon' | 'jwt';
      scope?: string[];
      audience?: string;
      issuer?: string;
      subject?: string;
    };
    
    const tokenType = params.tokenType ?? 'bearer';
    
    switch (tokenType) {
      case 'bearer': {
        const token = `Bearer_${randomBytes(32).toString('hex')}`;
        return {
          accessToken: token,
          tokenType: 'bearer',
          scope: params.scope?.join(' ') ?? '',
          expiresIn: String(config.ttl ?? 3600)
        };
      }
      
      case 'jwt': {
        // Упрощённая генерация JWT (для production использовать jose)
        const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
        const now = Math.floor(Date.now() / 1000);
        const payload = Buffer.from(JSON.stringify({
          sub: params.subject ?? 'dynamic-secret',
          iss: params.issuer ?? 'protocol-secrets',
          aud: params.audience ?? '',
          exp: now + (config.ttl ?? 3600),
          iat: now,
          scope: params.scope?.join(' ')
        })).toString('base64url');
        
        const signatureInput = `${header}.${payload}`;
        const signature = createHash('sha256')
          .update(signatureInput)
          .digest('base64url');
        
        return {
          accessToken: `${signatureInput}.${signature}`,
          tokenType: 'bearer',
          expiresIn: String(config.ttl ?? 3600)
        };
      }
      
      default: {
        const token = `token_${randomBytes(32).toString('hex')}`;
        return {
          accessToken: token,
          tokenType,
          scope: params.scope?.join(' ') ?? '',
          expiresIn: String(config.ttl ?? 3600)
        };
      }
    }
  }

  /**
   * Генерация SSH ключа
   */
  private async generateSSHKey(
    config: DynamicSecretConfig
  ): Promise<Record<string, string>> {
    const params = config.generationParams as {
      keyType?: 'rsa' | 'ed25519' | 'ecdsa';
      keyLength?: number;
      comment?: string;
    };
    
    const keyType = params.keyType ?? 'ed25519';
    const keyLength = params.keyLength ?? 256;
    const comment = params.comment ?? 'dynamic-secret';
    
    let keyPair: { publicKey: string; privateKey: string };
    
    try {
      // Генерация ключевой пары
      keyPair = generateKeyPairSync(keyType, {
        modulusLength: keyLength,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });
    } catch (error) {
      // Fallback для ed25519 который не поддерживает modulusLength
      keyPair = generateKeyPairSync('ed25519', {
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });
    }
    
    // Вычисление fingerprint
    const fingerprint = this.computeSSHFP(keyPair.publicKey);
    
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      fingerprint,
      keyType,
      comment
    };
  }

  /**
   * Вычисление SSH fingerprint
   */
  private computeSSHFP(publicKey: string): string {
    const keyData = Buffer.from(publicKey, 'utf8');
    const fingerprint = createHash('sha256')
      .update(keyData)
      .digest('base64')
      .replace(/=+$/, '');
    
    return `SHA256:${fingerprint}`;
  }

  /**
   * Генерация TLS сертификата
   */
  private async generateTLSCertificate(
    config: DynamicSecretConfig
  ): Promise<Record<string, string>> {
    const params = config.generationParams as {
      commonName: string;
      altNames?: string[];
      organization?: string;
      validityDays?: number;
    };
    
    const commonName = params.commonName ?? 'localhost';
    const validityDays = params.validityDays ?? 365;
    
    // Генерация ключевой пары
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    
    // Создание self-signed сертификата (упрощённо)
    // Для production использовать node-forge или openssl
    const serialNumber = randomBytes(16).toString('hex');
    const validFrom = new Date();
    const validTo = new Date(validFrom.getTime() + validityDays * 24 * 60 * 60 * 1000);
    
    // В реальной реализации здесь было бы создание X.509 сертификата
    const certificate = `-----BEGIN CERTIFICATE-----
[Self-signed certificate for ${commonName}]
Serial: ${serialNumber}
Valid From: ${validFrom.toISOString()}
Valid To: ${validTo.toISOString()}
-----END CERTIFICATE-----`;
    
    return {
      certificate,
      privateKey,
      serialNumber,
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      commonName
    };
  }

  /**
   * Генерация AWS временных credentials
   */
  private async generateAWSCredentials(
    config: DynamicSecretConfig
  ): Promise<Record<string, string>> {
    const params = config.sourceConfig as {
      region?: string;
      roleArn?: string;
      durationSeconds?: number;
    };
    
    const region = params.region ?? 'us-east-1';
    const durationSeconds = params.durationSeconds ?? 3600;
    
    // Генерация временных credentials
    // В реальной реализации здесь был бы вызов AWS STS AssumeRole
    const accessKeyId = `ASIA${randomBytes(16).toString('hex').toUpperCase()}`;
    const secretAccessKey = randomBytes(40).toString('hex');
    const sessionToken = randomBytes(64).toString('hex');
    
    const expiration = new Date(Date.now() + durationSeconds * 1000);
    
    return {
      accessKeyId,
      secretAccessKey,
      sessionToken,
      expiration: expiration.toISOString(),
      region
    };
  }

  /**
   * Генерация Kubernetes service account
   */
  private async generateK8SServiceAccount(
    config: DynamicSecretConfig
  ): Promise<Record<string, string>> {
    const params = config.generationParams as {
      namespace?: string;
      name?: string;
      roles?: string[];
    };
    
    const namespace = params.namespace ?? 'default';
    const name = params.name ?? `sa-${randomBytes(8).toString('hex')}`;
    
    // Генерация токена service account
    // В реальной реализации здесь был бы вызов Kubernetes API
    const token = `eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.${Buffer.from(JSON.stringify({
      "kubernetes.io": {
        namespace,
        serviceaccount: {
          name,
          uid: randomBytes(16).toString('hex')
        }
      },
      exp: Math.floor(Date.now() / 1000) + (config.ttl ?? 3600)
    })).toString('base64url')}.${randomBytes(64).toString('hex')}`;
    
    return {
      namespace,
      name,
      token,
      caCertificate: 'kubernetes-ca-cert',
      apiServer: 'https://kubernetes.default.svc'
    };
  }

  /**
   * Генерация кастомного секрета
   */
  private async generateCustomSecret(
    config: DynamicSecretConfig
  ): Promise<Record<string, string>> {
    const params = config.generationParams as Record<string, unknown>;
    
    // Генерация на основе параметров
    const result: Record<string, string> = {};
    
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string') {
        result[key] = value;
      } else if (typeof value === 'number') {
        result[key] = String(value);
      } else if (value === true || value === false) {
        result[key] = String(value);
      } else {
        result[key] = JSON.stringify(value);
      }
    }
    
    // Добавление случайного секрета если не указано
    if (!result.secret) {
      result.secret = randomBytes(32).toString('hex');
    }
    
    return result;
  }

  /**
   * Генерация безопасного пароля
   */
  private generateSecurePassword(length: number): string {
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    const allChars = uppercase + lowercase + numbers + symbols;
    
    // Гарантируем наличие хотя бы одного символа каждого типа
    let password = '';
    password += uppercase[randomBytes(1)[0] % uppercase.length];
    password += lowercase[randomBytes(1)[0] % lowercase.length];
    password += numbers[randomBytes(1)[0] % numbers.length];
    password += symbols[randomBytes(1)[0] % symbols.length];
    
    // Заполняем оставшуюся длину
    for (let i = password.length; i < length; i++) {
      password += allChars[randomBytes(1)[0] % allChars.length];
    }
    
    // Перемешиваем
    return password.split('').sort(() => Math.random() - 0.5).join('');
  }

  /**
   * Получить статистику динамических секретов
   */
  getStats(): {
    totalActive: number;
    byType: Map<DynamicSecretType, number>;
    expiringSoon: number;
    totalRevoked: number;
  } {
    const now = Date.now();
    const byType = new Map<DynamicSecretType, number>();
    let expiringSoon = 0;
    
    for (const state of this.secrets.values()) {
      // Подсчёт по типам
      const count = byType.get(state.secret.type) ?? 0;
      byType.set(state.secret.type, count + 1);
      
      // Проверка скорого истечения (5 минут)
      if (state.expiresAt.getTime() - now < 300000) {
        expiringSoon++;
      }
    }
    
    return {
      totalActive: this.secrets.size,
      byType,
      expiringSoon,
      totalRevoked: 0 // Можно добавить счётчик отозванных
    };
  }

  /**
   * Получить все активные секреты типа
   * 
   * @param type - Тип секрета
   * @returns Массив секретов
   */
  getSecretsByType(type: DynamicSecretType): GeneratedDynamicSecret[] {
    const result: GeneratedDynamicSecret[] = [];
    
    for (const state of this.secrets.values()) {
      if (state.secret.type === type && !state.revoked) {
        result.push(state.secret);
      }
    }
    
    return result;
  }
}
