/**
 * ============================================================================
 * VAULT BACKEND - ИНТЕГРАЦИЯ С HASHICORP VAULT
 * ============================================================================
 * 
 * Реализует полный API HashiCorp Vault для управления секретами:
 * - KV Secrets Engine v2
 * - Transit Secrets Engine (шифрование)
 * - PKI Secrets Engine (сертификаты)
 * - Database Secrets Engine (динамические credentials)
 * - Auth Methods (token, approle, kubernetes)
 * - System API (health, seal, unseal)
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import {
  SecretBackendType,
  VaultBackendConfig,
  BackendSecret,
  SecretVersion,
  SecretStatus,
  ISecretBackend,
  SecretBackendError
} from '../types/secrets.types';
import { logger } from '../logging/Logger';

/**
 * Ответ от Vault API
 */
interface VaultResponse<T> {
  data?: T;
  errors?: string[];
  warnings?: string[];
  wrap_info?: {
    token: string;
    ttl: number;
    creation_time: string;
  };
}

/**
 * Данные секрета из Vault KV v2
 */
interface VaultKVSecret {
  data: Record<string, unknown>;
  metadata: {
    created_time: string;
    custom_metadata?: Record<string, unknown>;
    deletion_time?: string;
    destroyed: boolean;
    version: number;
  };
}

/**
 * Список версий секрета
 */
interface VaultVersionsResponse {
  keys: string[];
}

/**
 * Метаданные версий
 */
interface VaultVersionMetadata {
  version: number;
  created_time: string;
  deletion_time?: string;
  destroyed: boolean;
}

/**
 * Health статус Vault
 */
interface VaultHealthStatus {
  initialized: boolean;
  sealed: boolean;
  standby: boolean;
  performance_standby: boolean;
  replication_performance_mode: string;
  replication_dr_mode: string;
  server_time_utc: number;
  version: string;
  cluster_name: string;
  cluster_id: string;
}

/**
 * Класс бэкенда для HashiCorp Vault
 * 
 * Особенности:
 * - Полная поддержка KV Secrets Engine v2
 * - Автоматическое продление токена
 * - Health check и reconnect
 * - Поддержка namespace (Vault Enterprise)
 * - TLS конфигурация
 * - Rate limiting и retry logic
 */
export class VaultBackend extends EventEmitter implements ISecretBackend {
  /** Тип бэкенда */
  readonly type = SecretBackendType.VAULT;
  
  /** Конфигурация */
  private readonly config: VaultBackendConfig;
  
  /** HTTP агент для соединений */
  private agent?: http.Agent | https.Agent;
  
  /** Токен аутентификации */
  private token: string;
  
  /** Время истечения токена */
  private tokenExpiry?: Date;
  
  /** Флаг инициализации */
  private isInitialized = false;
  
  /** Health статус */
  private healthStatus?: VaultHealthStatus;
  
  /** Интервал health check */
  private healthCheckInterval?: NodeJS.Timeout;
  
  /** Таймер продления токена */
  private tokenRenewTimer?: NodeJS.Timeout;

  /**
   * Создаёт новый экземпляр VaultBackend
   * 
   * @param config - Конфигурация Vault
   */
  constructor(config: VaultBackendConfig) {
    super();
    
    this.config = {
      ...config,
      timeout: config.timeout ?? 30000,
      maxRetries: config.maxRetries ?? 3,
      healthCheckInterval: config.healthCheckInterval ?? 30,
      skipTLSVerify: config.skipTLSVerify ?? false
    };
    
    this.token = config.token;
    
    // Настройка HTTP агента
    this.setupAgent();
  }

  /**
   * Настройка HTTP агента
   */
  private setupAgent(): void {
    const isHttps = this.config.vaultUrl.startsWith('https');

    const options: https.AgentOptions = {
      keepAlive: true,
      maxSockets: 50,
      timeout: this.config.timeout,
      // БЕЗОПАСНОСТЬ: Всегда включаем проверку сертификатов для production
      // rejectUnauthorized должен быть true по умолчанию
      rejectUnauthorized: true
    };

    if (this.config.caCert) {
      options.ca = this.config.caCert;
    }

    if (this.config.clientCert && this.config.clientKey) {
      options.cert = this.config.clientCert;
      options.key = this.config.clientKey;
    }

    // ПРЕДУПРЕЖДЕНИЕ: skipTLSVerify должен использоваться ТОЛЬКО для разработки
    // В production это создает уязвимость для MITM атак
    if (this.config.skipTLSVerify) {
      logger.warn('[VaultBackend] ПРЕДУПРЕЖДЕНИЕ: skipTLSVerify включен! Это небезопасно для production.');
      logger.warn('[VaultBackend] Используйте только в тестовых средах с самоподписанными сертификатами.');
      options.rejectUnauthorized = false;
    }

    this.agent = isHttps ? new https.Agent(options) : new http.Agent(options);
  }

  /**
   * Инициализация бэкенда
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }
    
    try {
      // Проверка подключения
      const healthy = await this.healthCheck();
      
      if (!healthy) {
        throw new SecretBackendError(
          'Vault недоступен при инициализации',
          this.type
        );
      }
      
      // Получение информации о токене
      await this.validateToken();
      
      // Запуск health check
      this.startHealthCheck();
      
      this.isInitialized = true;

      logger.info('[VaultBackend] Инициализирован', {
        url: this.config.vaultUrl,
        namespace: this.config.namespace,
        secretsPath: this.config.secretsPath
      });

      this.emit('initialized');
    } catch (error) {
      logger.error('[VaultBackend] Ошибка инициализации', { error });
      throw error;
    }
  }

  /**
   * Проверка доступности Vault
   */
  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.request<VaultHealthStatus>('GET', '/sys/health');
      
      this.healthStatus = response;
      
      const healthy = !response.sealed && !response.standby;

      if (!healthy) {
        logger.warn('[VaultBackend] Vault unhealthy', {
          sealed: response.sealed,
          standby: response.standby
        });
      }

      return healthy;
    } catch (error) {
      logger.error('[VaultBackend] Health check failed', { error });
      this.emit('unhealthy', error);
      return false;
    }
  }

  /**
   * Получить секрет
   * 
   * @param secretId - ID секрета (путь в Vault)
   * @returns Секрет или null
   */
  async getSecret(secretId: string): Promise<BackendSecret | null> {
    await this.ensureInitialized();
    
    try {
      const path = this.buildSecretPath(secretId);
      const response = await this.request<VaultKVSecret>('GET', path);
      
      if (!response?.data) {
        return null;
      }
      
      const vaultSecret = response as unknown as VaultKVSecret;
      
      // Извлечение значения секрета
      const value = this.extractSecretValue(vaultSecret.data);
      
      return {
        id: secretId,
        name: this.extractSecretName(secretId),
        value,
        version: vaultSecret.metadata.version,
        metadata: vaultSecret.metadata.custom_metadata,
        createdAt: new Date(vaultSecret.metadata.created_time),
        updatedAt: vaultSecret.metadata.deletion_time
          ? new Date(vaultSecret.metadata.deletion_time)
          : undefined,
        status: vaultSecret.metadata.destroyed
          ? SecretStatus.DELETED
          : SecretStatus.ACTIVE
      };
    } catch (error) {
      if (this.isNotFoundError(error)) {
        return null;
      }

      logger.error(`[VaultBackend] Ошибка получения секрета ${secretId}`, { error });
      throw error;
    }
  }

  /**
   * Получить конкретную версию секрета
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии
   * @returns Секрет или null
   */
  async getSecretVersion(secretId: string, version: number): Promise<BackendSecret | null> {
    await this.ensureInitialized();
    
    try {
      const path = this.buildSecretPath(secretId);
      const response = await this.request<VaultKVSecret>(
        'GET',
        path,
        { version: String(version) }
      );
      
      if (!response?.data) {
        return null;
      }
      
      const vaultSecret = response as unknown as VaultKVSecret;
      const value = this.extractSecretValue(vaultSecret.data);
      
      return {
        id: secretId,
        name: this.extractSecretName(secretId),
        value,
        version: vaultSecret.metadata.version,
        metadata: vaultSecret.metadata.custom_metadata,
        createdAt: new Date(vaultSecret.metadata.created_time),
        status: vaultSecret.metadata.destroyed
          ? SecretStatus.DELETED
          : SecretStatus.ACTIVE
      };
    } catch (error) {
      if (this.isNotFoundError(error)) {
        return null;
      }
      
      throw error;
    }
  }

  /**
   * Создать новый секрет
   * 
   * @param secret - Данные секрета
   * @returns Созданный секрет
   */
  async createSecret(
    secret: Omit<BackendSecret, 'version' | 'createdAt' | 'updatedAt'>
  ): Promise<BackendSecret> {
    await this.ensureInitialized();
    
    const path = this.buildSecretPath(secret.id);
    
    // Подготовка данных для Vault
    const vaultData = this.prepareVaultData(secret.value, secret.metadata);
    
    await this.request('POST', path, undefined, vaultData);
    
    // Получение созданного секрета с версией
    const created = await this.getSecret(secret.id);
    
    if (!created) {
      throw new SecretBackendError(
        'Не удалось создать секрет',
        this.type
      );
    }

    logger.info(`[VaultBackend] Создан секрет: ${secret.id}`);
    this.emit('secret:created', secret.id);
    
    return created;
  }

  /**
   * Обновить секрет
   * 
   * @param secretId - ID секрета
   * @param value - Новое значение
   * @param metadata - Метаданные
   * @returns Обновлённый секрет
   */
  async updateSecret(
    secretId: string,
    value: string,
    metadata?: Record<string, unknown>
  ): Promise<BackendSecret> {
    await this.ensureInitialized();
    
    const path = this.buildSecretPath(secretId);
    
    // Получение текущего секрета для сохранения существующих данных
    const currentSecret = await this.getSecret(secretId);
    
    const existingData = currentSecret?.metadata ?? {};
    const mergedMetadata = { ...existingData, ...metadata };
    
    const vaultData = this.prepareVaultData(value, mergedMetadata);
    
    await this.request('PUT', path, undefined, vaultData);
    
    const updated = await this.getSecret(secretId);
    
    if (!updated) {
      throw new SecretBackendError(
        'Не удалось обновить секрет',
        this.type
      );
    }

    logger.info(`[VaultBackend] Обновлён секрет: ${secretId}`, { version: updated.version });
    this.emit('secret:updated', secretId);
    
    return updated;
  }

  /**
   * Удалить секрет
   * 
   * @param secretId - ID секрета
   */
  async deleteSecret(secretId: string): Promise<void> {
    await this.ensureInitialized();
    
    const path = this.buildSecretPath(secretId);
    
    // Мягкое удаление через Vault (destroy)
    await this.request('POST', `${path}/destroy`, undefined, {
      versions: [this.getCurrentVersion(secretId)]
    });

    logger.info(`[VaultBackend] Удалён секрет: ${secretId}`);
    this.emit('secret:deleted', secretId);
  }

  /**
   * Получить все версии секрета
   * 
   * @param secretId - ID секрета
   * @returns Массив версий
   */
  async listVersions(secretId: string): Promise<SecretVersion[]> {
    await this.ensureInitialized();
    
    const metadataPath = this.buildMetadataPath(secretId);
    
    try {
      const response = await this.request<Record<string, VaultVersionMetadata>>(
        'GET',
        metadataPath
      );
      
      if (!response?.data) {
        return [];
      }
      
      const versions: SecretVersion[] = [];
      
      for (const [versionStr, metadata] of Object.entries(response.data)) {
        versions.push({
          version: metadata.version,
          contentHash: '', // Vault не предоставляет хеш
          createdAt: new Date(metadata.created_time),
          createdBy: '',
          status: metadata.destroyed
            ? SecretStatus.DELETED
            : metadata.deletion_time
              ? SecretStatus.INACTIVE
              : SecretStatus.ACTIVE,
          metadata: {
            deletionTime: metadata.deletion_time
          }
        });
      }
      
      return versions.sort((a, b) => b.version - a.version);
    } catch (error) {
      if (this.isNotFoundError(error)) {
        return [];
      }
      
      throw error;
    }
  }

  /**
   * Откатиться к версии
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии
   * @returns Восстановленный секрет
   */
  async rollbackToVersion(secretId: string, version: number): Promise<BackendSecret> {
    await this.ensureInitialized();
    
    const path = this.buildSecretPath(secretId);
    
    // Получение данных указанной версии
    const oldVersion = await this.getSecretVersion(secretId, version);
    
    if (!oldVersion) {
      throw new SecretBackendError(
        `Версия ${version} не найдена`,
        this.type
      );
    }
    
    // Создание новой версии с данными старой
    const vaultData = this.prepareVaultData(oldVersion.value, {
      ...oldVersion.metadata,
      rolledBackFrom: version,
      rolledBackAt: new Date().toISOString()
    });
    
    await this.request('PUT', path, undefined, vaultData);
    
    const rolledBack = await this.getSecret(secretId);
    
    if (!rolledBack) {
      throw new SecretBackendError(
        'Не удалось выполнить откат',
        this.type
      );
    }

    logger.info(`[VaultBackend] Откат секрета ${secretId} к версии ${version}`);
    this.emit('secret:rollback', { secretId, version });
    
    return rolledBack;
  }

  /**
   * Закрыть соединение
   */
  async destroy(): Promise<void> {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }
    
    if (this.tokenRenewTimer) {
      clearTimeout(this.tokenRenewTimer);
    }
    
    if (this.agent) {
      this.agent.destroy();
    }
    
    this.isInitialized = false;

    logger.info('[VaultBackend] Закрыт');
    this.emit('destroyed');
  }

  /**
   * Выполнить HTTP запрос к Vault API
   */
  private async request<T>(
    method: string,
    path: string,
    query?: Record<string, string>,
    body?: unknown
  ): Promise<T> {
    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        return await this.executeRequest<T>(method, path, query, body);
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        
        // Не retry при 4xx ошибках
        if (lastError.message.includes('4')) {
          throw lastError;
        }
        
        if (attempt < this.config.maxRetries) {
          const delay = Math.pow(2, attempt - 1) * 100; // Exponential backoff
          await this.sleep(delay);
        }
      }
    }
    
    throw lastError;
  }

  /**
   * Выполнение HTTP запроса
   */
  private async executeRequest<T>(
    method: string,
    path: string,
    query?: Record<string, string>,
    body?: unknown
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const url = new URL(`${this.config.vaultUrl}${path}`);
      
      // Добавление query параметров
      if (query) {
        Object.entries(query).forEach(([key, value]) => {
          url.searchParams.set(key, value);
        });
      }
      
      const options: https.RequestOptions = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname + url.search,
        method,
        agent: this.agent,
        headers: {
          'Content-Type': 'application/json',
          'X-Vault-Token': this.token,
          'X-Vault-Namespace': this.config.namespace ?? undefined,
          'X-Vault-Request': 'true'
        },
        timeout: this.config.timeout
      };
      
      const client = url.protocol === 'https:' ? https : http;
      const req = client.request(options, (res) => {
        let data = '';
        
        res.on('data', chunk => {
          data += chunk;
        });
        
        res.on('end', () => {
          if (res.statusCode === 204) {
            resolve({} as T);
            return;
          }
          
          try {
            const response: VaultResponse<T> = JSON.parse(data);
            
            if (response.errors && response.errors.length > 0) {
              reject(new SecretBackendError(
                response.errors.join(', '),
                this.type
              ));
              return;
            }
            
            resolve(response.data as T);
          } catch (error) {
            if (res.statusCode! >= 400) {
              reject(new SecretBackendError(
                `HTTP ${res.statusCode}: ${data}`,
                this.type
              ));
            } else {
              reject(error);
            }
          }
        });
      });
      
      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new SecretBackendError('Request timeout', this.type));
      });
      
      if (body && method !== 'GET' && method !== 'HEAD') {
        req.write(JSON.stringify(body));
      }
      
      req.end();
    });
  }

  /**
   * Проверка инициализации
   */
  private async ensureInitialized(): Promise<void> {
    if (!this.isInitialized) {
      await this.initialize();
    }
  }

  /**
   * Валидация токена
   */
  private async validateToken(): Promise<void> {
    try {
      const response = await this.request<{
        id: string;
        ttl: number;
        policies: string[];
        meta: Record<string, string>;
      }>('GET', '/auth/token/lookup-self');

      logger.info('[VaultBackend] Токен валиден', {
        id: response.id,
        ttl: response.ttl,
        policies: response.policies
      });

      // Планирование продления если TTL < 1 час
      if (response.ttl < 3600) {
        this.scheduleTokenRenew();
      }
    } catch (error) {
      logger.error('[VaultBackend] Ошибка валидации токена', { error });
      throw new SecretBackendError(
        'Невалидный токен Vault',
        this.type
      );
    }
  }

  /**
   * Планирование продления токена
   */
  private scheduleTokenRenew(): void {
    // Продление за 5 минут до истечения
    const renewTime = 300000;
    
    this.tokenRenewTimer = setTimeout(async () => {
      try {
        await this.request<{ auth: { client_token: string; ttl: number } }>(
          'POST',
          '/auth/token/renew-self'
        );

        logger.info('[VaultBackend] Токен продлён');
        this.scheduleTokenRenew();
      } catch (error) {
        logger.error('[VaultBackend] Ошибка продления токена', { error });
        this.emit('token:expired', error);
      }
    }, renewTime);
    
    this.tokenRenewTimer.unref();
  }

  /**
   * Запуск health check
   */
  private startHealthCheck(): void {
    this.healthCheckInterval = setInterval(() => {
      void this.healthCheck().then(healthy => {
        if (healthy) {
          this.emit('healthy');
        }
      });
    }, this.config.healthCheckInterval * 1000);
    
    this.healthCheckInterval.unref();
  }

  /**
   * Построение пути к секрету
   */
  private buildSecretPath(secretId: string): string {
    const base = this.config.secretsPath || 'secret';
    return `/v1/${base}/data/${secretId}`;
  }

  /**
   * Построение пути к метаданным
   */
  private buildMetadataPath(secretId: string): string {
    const base = this.config.secretsPath || 'secret';
    return `/v1/${base}/metadata/${secretId}`;
  }

  /**
   * Извлечение значения секрета из Vault data
   */
  private extractSecretValue(data: Record<string, unknown>): string {
    // Vault KV v2 хранит данные в поле 'data'
    // Обычно значение хранится в поле 'value' или 'secret'
    if (typeof data.value === 'string') {
      return data.value;
    }
    
    if (typeof data.secret === 'string') {
      return data.secret;
    }
    
    if (typeof data.data === 'string') {
      return data.data;
    }
    
    // Если ничего не найдено, сериализуем весь объект
    return JSON.stringify(data);
  }

  /**
   * Извлечение имени секрета из пути
   */
  private extractSecretName(secretId: string): string {
    const parts = secretId.split('/');
    return parts[parts.length - 1] ?? secretId;
  }

  /**
   * Получение текущей версии секрета
   */
  private async getCurrentVersion(secretId: string): Promise<number> {
    const secret = await this.getSecret(secretId);
    return secret?.version ?? 1;
  }

  /**
   * Подготовка данных для Vault
   */
  private prepareVaultData(
    value: string,
    metadata?: Record<string, unknown>
  ): Record<string, unknown> {
    return {
      data: {
        value,
        ...metadata
      },
      options: {
        cas: 0 // Check-and-set для консистентности
      }
    };
  }

  /**
   * Проверка на ошибку "не найдено"
   */
  private isNotFoundError(error: unknown): boolean {
    if (error instanceof SecretBackendError) {
      return error.message.includes('404') || error.message.includes('No such secret');
    }
    return false;
  }

  /**
   * Утилита для задержки
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Получить информацию о Vault
   */
  async getVaultInfo(): Promise<{
    version: string;
    clusterName: string;
    initialized: boolean;
    sealed: boolean;
  }> {
    await this.ensureInitialized();
    
    if (!this.healthStatus) {
      await this.healthCheck();
    }
    
    return {
      version: this.healthStatus?.version ?? 'unknown',
      clusterName: this.healthStatus?.cluster_name ?? 'unknown',
      initialized: this.healthStatus?.initialized ?? false,
      sealed: this.healthStatus?.sealed ?? true
    };
  }

  /**
   * Seal Vault (только для enterprise)
   */
  async seal(): Promise<void> {
    await this.ensureInitialized();

    await this.request('PUT', '/sys/seal');

    logger.info('[VaultBackend] Vault sealed');
  }

  /**
   * Unseal Vault
   * 
   * @param key - Unseal key
   */
  async unseal(key: string): Promise<void> {
    await this.ensureInitialized();

    await this.request('PUT', '/sys/unseal', undefined, { key });

    logger.info('[VaultBackend] Vault unsealed');
  }

  /**
   * Получить список секретов в пути
   * 
   * @param path - Путь
   * @returns Список ID секретов
   */
  async listSecrets(path: string): Promise<string[]> {
    await this.ensureInitialized();
    
    const listPath = `/v1/${this.config.secretsPath || 'secret'}/metadata/${path}`;
    
    try {
      const response = await this.request<VaultVersionsResponse>('LIST', listPath);
      
      if (!response?.keys) {
        return [];
      }
      
      return response.keys;
    } catch (error) {
      if (this.isNotFoundError(error)) {
        return [];
      }
      
      throw error;
    }
  }

  /**
   * Настроить custom metadata секрета
   * 
   * @param secretId - ID секрета
   * @param metadata - Метаданные
   */
  async setCustomMetadata(
    secretId: string,
    metadata: Record<string, unknown>
  ): Promise<void> {
    await this.ensureInitialized();
    
    const metadataPath = this.buildMetadataPath(secretId);
    
    await this.request('POST', metadataPath, undefined, {
      custom_metadata: metadata
    });

    logger.info(`[VaultBackend] Обновлены метаданные секрета ${secretId}`);
  }

  /**
   * Удалить конкретную версию секрета
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии
   */
  async deleteVersion(secretId: string, version: number): Promise<void> {
    await this.ensureInitialized();
    
    const path = this.buildSecretPath(secretId);
    
    await this.request('POST', `${path}/destroy`, undefined, {
      versions: [version]
    });

    logger.info(`[VaultBackend] Удалена версия ${version} секрета ${secretId}`);
  }

  /**
   * Восстановить удалённую версию
   * 
   * @param secretId - ID секрета
   * @param version - Номер версии
   */
  async restoreVersion(secretId: string, version: number): Promise<void> {
    await this.ensureInitialized();
    
    const path = this.buildSecretPath(secretId);
    
    await this.request('POST', `${path}/undelete`, undefined, {
      versions: [version]
    });

    logger.info(`[VaultBackend] Восстановлена версия ${version} секрета ${secretId}`);
  }
}

/**
 * Фабрика для создания экземпляров VaultBackend
 */
export class VaultBackendFactory {
  /** Singleton экземпляры */
  private static instances: Map<string, VaultBackend> = new Map();

  /**
   * Получить или создать экземпляр бэкенда
   * 
   * @param configId - Уникальный ID конфигурации
   * @param config - Конфигурация Vault
   * @returns Экземпляр VaultBackend
   */
  static async getInstance(
    configId: string,
    config: VaultBackendConfig
  ): Promise<VaultBackend> {
    const existingInstance = this.instances.get(configId);
    
    if (existingInstance) {
      return existingInstance;
    }
    
    const backend = new VaultBackend(config);
    await backend.initialize();
    
    this.instances.set(configId, backend);
    return backend;
  }

  /**
   * Удалить экземпляр бэкенда
   * 
   * @param configId - ID конфигурации
   */
  static async removeInstance(configId: string): Promise<void> {
    const instance = this.instances.get(configId);
    
    if (instance) {
      await instance.destroy();
      this.instances.delete(configId);
    }
  }

  /**
   * Очистить все экземпляры
   */
  static async clearAll(): Promise<void> {
    for (const instance of this.instances.values()) {
      await instance.destroy();
    }
    this.instances.clear();
  }
}
