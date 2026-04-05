/**
 * ============================================================================
 * SECRET CACHE - КЭШИРОВАНИЕ СЕКРЕТОВ С ШИФРОВАНИЕМ IN-MEMORY
 * ============================================================================
 * 
 * Реализует безопасное кэширование секретов в памяти с использованием
 * AES-256-GCM шифрования. Поддерживает LRU/LFU/FIFO стратегии вытеснения,
 * автоматическую инвалидацию по TTL и версионированию.
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import { logger } from '../logging/Logger';
import {
  CacheConfig,
  CachedSecret,
  SecretBackendType,
  SecretEncryptionError,
  BackendSecret
} from '../types/secrets.types';

/**
 * Класс для управления кэшем секретов с шифрованием
 * 
 * Особенности:
 * - Шифрование AES-256-GCM для каждой записи
 * - Уникальный IV для каждой операции шифрования
 * - Стратегии вытеснения: LRU, LFU, FIFO
 * - Автоматическая очистка истёкших записей
 * - Thread-safe операции
 * - Метрики производительности
 */
export class SecretCache extends EventEmitter {
  /** Конфигурация кэша */
  private readonly config: CacheConfig;
  
  /** Ключ шифрования (32 байта для AES-256) */
  private readonly encryptionKey: Buffer;
  
  /** Внутреннее хранилище кэша */
  private readonly cache: Map<string, CachedSecret>;
  
  /** Счётчики доступа для LFU стратегии */
  private readonly accessCounts: Map<string, number>;
  
  /** Очередь для FIFO стратегии */
  private readonly fifoQueue: string[];
  
  /** Интервал очистки истёкших записей */
  private cleanupInterval?: NodeJS.Timeout;
  
  /** Статистика кэша */
  private stats: {
    hits: number;
    misses: number;
    evictions: number;
    expirations: number;
    encryptTimeMs: number;
    decryptTimeMs: number;
  };
  
  /** Флаг инициализации */
  private isInitialized = false;
  
  /** Максимальное время жизни записи по умолчанию (5 минут) */
  private readonly DEFAULT_TTL = 300;
  
  /** Интервал очистки по умолчанию (30 секунд) */
  private readonly CLEANUP_INTERVAL = 30000;

  /**
   * Создаёт новый экземпляр SecretCache
   * 
   * @param config - Конфигурация кэша
   * @param encryptionKey - Ключ шифрования (минимум 32 байта)
   */
  constructor(config: CacheConfig, encryptionKey: string) {
    super();
    
    this.config = {
      ...config,
      enabled: config.enabled ?? true,
      ttl: config.ttl ?? this.DEFAULT_TTL,
      maxEntries: config.maxEntries ?? 1000,
      encryptInMemory: config.encryptInMemory ?? true,
      encryptionAlgorithm: config.encryptionAlgorithm ?? 'aes-256-gcm',
      evictionStrategy: config.evictionStrategy ?? 'lru'
    };
    
    // Валидация ключа шифрования
    const keyBuffer = Buffer.from(encryptionKey, 'base64');
    if (keyBuffer.length < 32) {
      throw new SecretEncryptionError(
        'Ключ шифрования должен быть минимум 32 байта (256 бит)'
      );
    }
    this.encryptionKey = keyBuffer.slice(0, 32);
    
    this.cache = new Map();
    this.accessCounts = new Map();
    this.fifoQueue = [];
    
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0,
      expirations: 0,
      encryptTimeMs: 0,
      decryptTimeMs: 0
    };
  }

  /**
   * Инициализация кэша
   * Запускает фоновую очистку истёкших записей
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    if (!this.config.enabled) {
      logger.info('[SecretCache] Кэширование отключено');
      this.isInitialized = true;
      return;
    }

    // Запускаем периодическую очистку
    this.cleanupInterval = setInterval(
      () => this.cleanupExpired(),
      this.CLEANUP_INTERVAL
    );

    // Unref для предотвращения блокировки выхода процесса
    this.cleanupInterval.unref();

    this.isInitialized = true;
    logger.info('[SecretCache] Инициализирован', {
      ttl: this.config.ttl,
      maxEntries: this.config.maxEntries,
      encryption: this.config.encryptInMemory ? 'enabled' : 'disabled',
      strategy: this.config.evictionStrategy
    });
  }

  /**
   * Остановка кэша
   * Очищает интервалы и сбрасывает кэш
   */
  async destroy(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }

    // Безопасная очистка данных
    this.cache.clear();
    this.accessCounts.clear();
    this.fifoQueue.length = 0;

    this.isInitialized = false;
    logger.info('[SecretCache] Остановлен');
  }

  /**
   * Получить секрет из кэша
   * 
   * @param secretId - ID секрета
   * @param version - Ожидаемая версия (для валидации)
   * @returns Расшифрованный секрет или null
   */
  async get(secretId: string, version?: number): Promise<BackendSecret | null> {
    if (!this.config.enabled || !this.isInitialized) {
      return null;
    }
    
    const cachedSecret = this.cache.get(secretId);
    
    if (!cachedSecret) {
      this.stats.misses++;
      return null;
    }
    
    // Проверка истечения
    if (new Date() > cachedSecret.expiresAt) {
      await this.delete(secretId);
      this.stats.expirations++;
      this.stats.misses++;
      return null;
    }
    
    // Проверка версии
    if (version !== undefined && cachedSecret.version !== version) {
      this.stats.misses++;
      return null;
    }
    
    // Обновление статистики доступа
    this.updateAccessStats(secretId);
    
    // Расшифровка значения
    const startTime = Date.now();
    const decryptedValue = await this.decryptValue(
      cachedSecret.encryptedValue,
      cachedSecret.iv,
      cachedSecret.authTag
    );
    this.stats.decryptTimeMs += Date.now() - startTime;
    
    this.stats.hits++;
    
    // Возвращаем десериализованный секрет
    try {
      const secretData = JSON.parse(decryptedValue);
      return {
        id: secretData.id,
        name: secretData.name,
        value: secretData.value,
        version: cachedSecret.version,
        metadata: secretData.metadata,
        createdAt: new Date(secretData.createdAt),
        updatedAt: secretData.updatedAt ? new Date(secretData.updatedAt) : undefined,
        status: secretData.status
      };
    } catch (error) {
      logger.error('[SecretCache] Ошибка десериализации', { error });
      return null;
    }
  }

  /**
   * Сохранить секрет в кэш
   * 
   * @param secret - Секрет для кэширования
   * @param ttl - Время жизни в секундах (опционально)
   * @returns Успешность операции
   */
  async set(secret: BackendSecret, ttl?: number): Promise<boolean> {
    if (!this.config.enabled || !this.isInitialized) {
      return false;
    }
    
    const startTime = Date.now();
    
    // Серилизация секрета
    const secretData = {
      id: secret.id,
      name: secret.name,
      value: secret.value,
      metadata: secret.metadata,
      createdAt: secret.createdAt.toISOString(),
      updatedAt: secret.updatedAt?.toISOString(),
      status: secret.status
    };
    const secretJson = JSON.stringify(secretData);
    
    // Шифрование
    const { encrypted, iv, authTag } = await this.encryptValue(secretJson);
    this.stats.encryptTimeMs += Date.now() - startTime;
    
    const now = new Date();
    const cacheTTL = ttl ?? this.config.ttl;
    
    const cachedSecret: CachedSecret = {
      cacheKey: secret.id,
      encryptedValue: encrypted,
      iv,
      authTag,
      cachedAt: now,
      expiresAt: new Date(now.getTime() + cacheTTL * 1000),
      version: secret.version,
      accessCount: 1,
      lastAccessedAt: now
    };
    
    // Проверка лимита записей
    if (this.cache.size >= this.config.maxEntries) {
      await this.evictOldest();
    }
    
    // Сохранение в кэш
    this.cache.set(secret.id, cachedSecret);
    
    // Обновление стратегий вытеснения
    this.updateEvictionStrategy(secret.id);
    
    return true;
  }

  /**
   * Удалить секрет из кэша
   * 
   * @param secretId - ID секрета
   * @returns Успешность операции
   */
  async delete(secretId: string): Promise<boolean> {
    const deleted = this.cache.delete(secretId);
    
    if (deleted) {
      this.accessCounts.delete(secretId);
      const fifoIndex = this.fifoQueue.indexOf(secretId);
      if (fifoIndex > -1) {
        this.fifoQueue.splice(fifoIndex, 1);
      }
    }
    
    return deleted;
  }

  /**
   * Очистить весь кэш
   */
  async clear(): Promise<void> {
    this.cache.clear();
    this.accessCounts.clear();
    this.fifoQueue.length = 0;
  }

  /**
   * Проверить наличие секрета в кэше
   * 
   * @param secretId - ID секрета
   * @returns Наличие в кэше
   */
  has(secretId: string): boolean {
    const cachedSecret = this.cache.get(secretId);
    
    if (!cachedSecret) {
      return false;
    }
    
    // Проверка истечения
    if (new Date() > cachedSecret.expiresAt) {
      void this.delete(secretId);
      return false;
    }
    
    return true;
  }

  /**
   * Получить статистику кэша
   * 
   * @returns Статистика производительности
   */
  getStats(): {
    size: number;
    hits: number;
    misses: number;
    hitRate: number;
    evictions: number;
    expirations: number;
    avgEncryptTimeMs: number;
    avgDecryptTimeMs: number;
  } {
    const total = this.stats.hits + this.stats.misses;
    return {
      size: this.cache.size,
      hits: this.stats.hits,
      misses: this.stats.misses,
      hitRate: total > 0 ? (this.stats.hits / total) * 100 : 0,
      evictions: this.stats.evictions,
      expirations: this.stats.expirations,
      avgEncryptTimeMs: this.stats.hits > 0 ? this.stats.encryptTimeMs / this.stats.hits : 0,
      avgDecryptTimeMs: this.stats.hits > 0 ? this.stats.decryptTimeMs / this.stats.hits : 0
    };
  }

  /**
   * Сбросить статистику
   */
  resetStats(): void {
    this.stats = {
      hits: 0,
      misses: 0,
      evictions: 0,
      expirations: 0,
      encryptTimeMs: 0,
      decryptTimeMs: 0
    };
  }

  /**
   * Очистка истёкших записей
   */
  private async cleanupExpired(): Promise<void> {
    const now = new Date();
    const expiredKeys: string[] = [];
    
    for (const [key, cachedSecret] of this.cache.entries()) {
      if (now > cachedSecret.expiresAt) {
        expiredKeys.push(key);
      }
    }
    
    for (const key of expiredKeys) {
      await this.delete(key);
      this.stats.expirations++;
    }

    if (expiredKeys.length > 0) {
      logger.info(`[SecretCache] Очищено ${expiredKeys.length} истёкших записей`);
    }
  }

  /**
   * Вытеснение старой записи при переполнении
   */
  private async evictOldest(): Promise<void> {
    if (this.cache.size === 0) {
      return;
    }
    
    let oldestKey: string | null = null;
    
    switch (this.config.evictionStrategy) {
      case 'lru':
        oldestKey = this.findLRUOldest();
        break;
      case 'lfu':
        oldestKey = this.findLFUOldest();
        break;
      case 'fifo':
        oldestKey = this.findFIFOOldest();
        break;
    }
    
    if (oldestKey) {
      await this.delete(oldestKey);
      this.stats.evictions++;
      logger.info(`[SecretCache] Вытеснена запись: ${oldestKey}`);
    }
  }

  /**
   * Найти oldest запись для LRU стратегии
   */
  private findLRUOldest(): string | null {
    let oldestTime = Date.now();
    let oldestKey: string | null = null;
    
    for (const [key, cachedSecret] of this.cache.entries()) {
      if (cachedSecret.lastAccessedAt.getTime() < oldestTime) {
        oldestTime = cachedSecret.lastAccessedAt.getTime();
        oldestKey = key;
      }
    }
    
    return oldestKey;
  }

  /**
   * Найти oldest запись для LFU стратегии
   */
  private findLFUOldest(): string | null {
    let minCount = Infinity;
    let oldestKey: string | null = null;
    
    for (const [key, count] of this.accessCounts.entries()) {
      if (count < minCount) {
        minCount = count;
        oldestKey = key;
      }
    }
    
    return oldestKey;
  }

  /**
   * Найти oldest запись для FIFO стратегии
   */
  private findFIFOOldest(): string | null {
    return this.fifoQueue[0] ?? null;
  }

  /**
   * Обновление статистики доступа
   */
  private updateAccessStats(secretId: string): void {
    const currentCount = this.accessCounts.get(secretId) ?? 0;
    this.accessCounts.set(secretId, currentCount + 1);
    
    const cachedSecret = this.cache.get(secretId);
    if (cachedSecret) {
      cachedSecret.accessCount = currentCount + 1;
      cachedSecret.lastAccessedAt = new Date();
    }
  }

  /**
   * Обновление стратегии вытеснения
   */
  private updateEvictionStrategy(secretId: string): void {
    if (this.config.evictionStrategy === 'fifo') {
      // Удаляем если уже есть в очереди
      const existingIndex = this.fifoQueue.indexOf(secretId);
      if (existingIndex > -1) {
        this.fifoQueue.splice(existingIndex, 1);
      }
      // Добавляем в конец
      this.fifoQueue.push(secretId);
    }
  }

  /**
   * Шифрование значения
   * 
   * @param value - Значение для шифрования
   * @returns Зашифрованные данные с IV и auth tag
   */
  private async encryptValue(value: string): Promise<{
    encrypted: Buffer;
    iv: Buffer;
    authTag: Buffer;
  }> {
    if (!this.config.encryptInMemory) {
      // Если шифрование отключено, возвращаем как есть
      return {
        encrypted: Buffer.from(value, 'utf8'),
        iv: Buffer.alloc(0),
        authTag: Buffer.alloc(0)
      };
    }
    
    try {
      // Генерация случайного IV (12 байт для GCM)
      const iv = randomBytes(12);
      
      // Создание cipher
      const cipher = createCipheriv('aes-256-gcm', this.encryptionKey, iv);

      // Шифрование
      let encrypted = cipher.update(value, 'utf8');
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      
      // Получение auth tag
      const authTag = cipher.getAuthTag();
      
      return { encrypted, iv, authTag };
    } catch (error) {
      logger.error('[SecretCache] Ошибка шифрования', { error });
      throw new SecretEncryptionError(
        `Не удалось зашифровать данные: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Расшифровка значения
   * 
   * @param encrypted - Зашифрованные данные
   * @param iv - Вектор инициализации
   * @param authTag - Auth tag для GCM
   * @returns Расшифрованное значение
   */
  private async decryptValue(
    encrypted: Buffer,
    iv: Buffer,
    authTag?: Buffer
  ): Promise<string> {
    if (!this.config.encryptInMemory || iv.length === 0) {
      // Если шифрование отключено, возвращаем как есть
      return encrypted.toString('utf8');
    }
    
    try {
      // Создание decipher
      const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey, iv);
      decipher.setAuthTag(authTag!);

      // Расшифровка
      let decrypted = decipher.update(encrypted, undefined, 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      logger.error('[SecretCache] Ошибка расшифровки', { error });
      throw new SecretEncryptionError(
        `Не удалось расшифровать данные: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Генерация ключа кэша на основе параметров
   * 
   * @param secretId - ID секрета
   * @param backendType - Тип бэкенда
   * @returns Уникальный ключ кэша
   */
  static generateCacheKey(secretId: string, backendType?: SecretBackendType): string {
    const data = backendType ? `${secretId}:${backendType}` : secretId;
    return createHash('sha256').update(data).digest('hex');
  }

  /**
   * Получить размер кэша в байтах (приблизительно)
   */
  getMemoryUsage(): number {
    let totalBytes = 0;
    
    for (const cachedSecret of this.cache.values()) {
      // Приблизительный расчёт размера
      totalBytes += cachedSecret.encryptedValue.length;
      totalBytes += cachedSecret.iv.length;
      totalBytes += cachedSecret.authTag?.length ?? 0;
      totalBytes += 100; // Накладные расходы на объект
    }
    
    return totalBytes;
  }

  /**
   * Инвалидировать кэш для конкретного секрета
   * 
   * @param secretId - ID секрета
   */
  async invalidate(secretId: string): Promise<void> {
    await this.delete(secretId);
    logger.info(`[SecretCache] Инвалидирован кэш для: ${secretId}`);
  }

  /**
   * Инвалидировать все кэши с префиксом
   *
   * @param prefix - Префикс ключей
   */
  async invalidateByPrefix(prefix: string): Promise<void> {
    const keysToDelete: string[] = [];

    for (const key of this.cache.keys()) {
      if (key.startsWith(prefix)) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      await this.delete(key);
    }

    logger.info(`[SecretCache] Инвалидировано ${keysToDelete.length} записей с префиксом: ${prefix}`);
  }
}

/**
 * Фабрика для создания экземпляров SecretCache
 */
export class SecretCacheFactory {
  /** Singleton экземпляры */
  private static instances: Map<string, SecretCache> = new Map();

  /**
   * Получить или создать экземпляр кэша
   * 
   * @param configId - Уникальный ID конфигурации
   * @param config - Конфигурация кэша
   * @param encryptionKey - Ключ шифрования
   * @returns Экземпляр SecretCache
   */
  static async getInstance(
    configId: string,
    config: CacheConfig,
    encryptionKey: string
  ): Promise<SecretCache> {
    const existingInstance = this.instances.get(configId);
    
    if (existingInstance) {
      return existingInstance;
    }
    
    const cache = new SecretCache(config, encryptionKey);
    await cache.initialize();
    
    this.instances.set(configId, cache);
    return cache;
  }

  /**
   * Удалить экземпляр кэша
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
