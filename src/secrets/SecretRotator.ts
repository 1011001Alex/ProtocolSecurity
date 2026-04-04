/**
 * ============================================================================
 * SECRET ROTATOR - АВТОМАТИЧЕСКАЯ РОТАЦИЯ СЕКРЕТОВ С GRACE PERIOD
 * ============================================================================
 * 
 * Реализует автоматическую ротацию секретов с настраиваемыми интервалами,
 * grace period для плавного перехода, уведомлениями и откатом при ошибках.
 * Поддерживает различные стратегии генерации новых секретов.
 * 
 * @package protocol/secrets
 * @author grigo
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { randomBytes, randomUUID } from 'crypto';
import { logger } from '../logging/Logger';
import {
  RotationConfig,
  RotationStatus,
  SecretStatus,
  BackendSecret,
  SecretVersion,
  ISecretBackend,
  SecretBackendError
} from '../types/secrets.types';

/**
 * Генератор секретов
 */
interface SecretGenerator {
  /** Генерация нового значения секрета */
  generate(length?: number): string;
  /** Генерация пароля */
  generatePassword(length?: number): string;
  /** Генерация API ключа */
  generateApiKey(): string;
  /** Генерация токена */
  generateToken(): string;
}

/**
 * Конфигурация ротатора
 */
interface RotatorConfig {
  /** Включить автоматическую ротацию */
  enableAutoRotation: boolean;
  /** Интервал проверки ротации (сек) */
  checkInterval: number;
  /** Максимальное количество одновременных ротаций */
  maxConcurrentRotations: number;
  /** Таймаут ротации (сек) */
  rotationTimeout: number;
  /** Количество попыток при ошибке */
  retryAttempts: number;
  /** Задержка между попытками (мс) */
  retryDelay: number;
  /** Включить уведомления */
  enableNotifications: boolean;
}

/**
 * Состояние ротации для секрета
 */
interface RotationState {
  /** Статус ротации */
  status: RotationStatus;
  /** Таймер следующей ротации */
  nextRotationTimer?: NodeJS.Timeout;
  /** Текущий процесс ротации */
  currentProcess?: Promise<BackendSecret>;
  /** История ротаций */
  history: RotationHistoryEntry[];
}

/**
 * Запись истории ротации
 */
interface RotationHistoryEntry {
  /** Время ротации */
  timestamp: Date;
  /** Старая версия */
  oldVersion: number;
  /** Новая версия */
  newVersion: number;
  /** Успешно ли */
  success: boolean;
  /** Ошибка (если была) */
  error?: string;
  /** Время выполнения (мс) */
  durationMs: number;
}

/**
 * Класс для управления автоматической ротацией секретов
 * 
 * Особенности:
 * - Автоматическая ротация по расписанию
 * - Grace period для плавного перехода
 * - Поддержка нескольких версий одновременно
 * - Откат при ошибках
 * - Уведомления о ротации
 * - Стратегии генерации секретов
 */
export class SecretRotator extends EventEmitter {
  /** Конфигурация ротатора */
  private readonly config: RotatorConfig;
  
  /** Конфигурация ротации по умолчанию */
  private readonly defaultRotationConfig: RotationConfig;
  
  /** Конфигурации ротации для каждого секрета */
  private secretConfigs: Map<string, RotationConfig>;
  
  /** Состояния ротации для каждого секрета */
  private rotationStates: Map<string, RotationState>;
  
  /** Ссылка на бэкенд */
  private backend?: ISecretBackend;
  
  /** Генератор секретов */
  private readonly generator: SecretGenerator;
  
  /** Флаг работы ротатора */
  private isRunning = false;
  
  /** Интервал проверки ротации */
  private checkInterval?: NodeJS.Timeout;
  
  /** Счётчик активных ротаций */
  private activeRotations = 0;

  /** Конфигурация по умолчанию */
  private readonly DEFAULT_ROTATOR_CONFIG: RotatorConfig = {
    enableAutoRotation: true,
    checkInterval: 60,
    maxConcurrentRotations: 5,
    rotationTimeout: 300,
    retryAttempts: 3,
    retryDelay: 1000,
    enableNotifications: true
  };

  /** Конфигурация ротации по умолчанию */
  private readonly DEFAULT_ROTATION_CONFIG: RotationConfig = {
    enabled: true,
    rotationInterval: 86400, // 24 часа
    gracePeriod: 3600, // 1 час
    autoActivate: true,
    notifyOnRotation: true,
    keepHistory: true,
    historyLimit: 10,
    minRotationInterval: 3600 // 1 час
  };

  /**
   * Создаёт новый экземпляр SecretRotator
   * 
   * @param rotatorConfig - Конфигурация ротатора
   * @param rotationConfig - Конфигурация ротации по умолчанию
   */
  constructor(
    rotatorConfig: Partial<RotatorConfig> = {},
    rotationConfig: Partial<RotationConfig> = {}
  ) {
    super();
    
    this.config = {
      ...this.DEFAULT_ROTATOR_CONFIG,
      ...rotatorConfig
    };
    
    this.defaultRotationConfig = {
      ...this.DEFAULT_ROTATION_CONFIG,
      ...rotationConfig
    };
    
    this.secretConfigs = new Map();
    this.rotationStates = new Map();
    
    this.generator = this.createGenerator();
  }

  /**
   * Создание генератора секретов
   */
  private createGenerator(): SecretGenerator {
    return {
      generate: (length = 32): string => {
        return randomBytes(length).toString('hex');
      },
      
      generatePassword: (length = 32): string => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        let password = '';
        const charArray = new Uint8Array(length);
        
        // ИСПОЛЬЗУЕМ REJECTION SAMPLING для устранения bias
        // Modulo оператор создает неравномерное распределение
        for (let i = 0; i < length; i++) {
          let randomValue: number;
          const maxValidValue = Math.floor(256 / chars.length) * chars.length;
          
          do {
            const randByte = randomBytes(1)[0];
            randomValue = randByte;
          } while (randomValue! >= maxValidValue);
          
          password += chars[randomValue! % chars.length];
        }

        return password;
      },
      
      generateApiKey: (): string => {
        return `sk_${randomBytes(24).toString('hex')}`;
      },
      
      generateToken: (): string => {
        return randomUUID().replace(/-/g, '');
      }
    };
  }

  /**
   * Инициализация ротатора
   * 
   * @param backend - Бэкенд для хранения секретов
   */
  async initialize(backend?: ISecretBackend): Promise<void> {
    this.backend = backend;
    this.isRunning = true;

    // Запуск периодической проверки
    if (this.config.enableAutoRotation) {
      this.startRotationCheck();
    }

    logger.info('[SecretRotator] Инициализирован', {
      autoRotation: this.config.enableAutoRotation,
      checkInterval: this.config.checkInterval,
      maxConcurrent: this.config.maxConcurrentRotations
    });
  }

  /**
   * Остановка ротатора
   */
  async destroy(): Promise<void> {
    this.isRunning = false;

    if (this.checkInterval) {
      clearInterval(this.checkInterval);
    }

    // Остановка всех таймеров ротации
    for (const state of this.rotationStates.values()) {
      if (state.nextRotationTimer) {
        clearTimeout(state.nextRotationTimer);
      }
    }

    logger.info('[SecretRotator] Остановлен');
  }

  /**
   * Настроить ротацию для секрета
   * 
   * @param secretId - ID секрета
   * @param config - Конфигурация ротации
   */
  configureRotation(secretId: string, config: Partial<RotationConfig>): void {
    const existingConfig = this.secretConfigs.get(secretId) ?? {
      ...this.defaultRotationConfig
    };
    
    const newConfig: RotationConfig = {
      ...existingConfig,
      ...config
    };
    
    this.secretConfigs.set(secretId, newConfig);
    
    // Инициализация состояния
    if (!this.rotationStates.has(secretId)) {
      this.rotationStates.set(secretId, {
        status: {
          secretId,
          status: 'idle',
          currentVersion: 0
        },
        history: []
      });
    }
    
    // Планирование следующей ротации
    this.scheduleNextRotation(secretId);

    logger.info(`[SecretRotator] Настроена ротация для ${secretId}`, {
      rotationInterval: newConfig.rotationInterval
    });

    this.emit('rotation:configured', { secretId, config: newConfig });
  }

  /**
   * Выполнить ротацию секрета
   * 
   * @param secretId - ID секрета
   * @param newSecretValue - Новое значение секрета (опционально)
   * @param reason - Причина ротации
   * @returns Новый секрет
   */
  async rotateSecret(
    secretId: string,
    newSecretValue?: string,
    reason?: string
  ): Promise<BackendSecret> {
    const state = this.rotationStates.get(secretId);
    
    if (!state) {
      throw new SecretBackendError(
        `Секрет ${secretId} не настроен для ротации`,
        'unknown' as any
      );
    }
    
    // Проверка лимита одновременных ротаций
    if (this.activeRotations >= this.config.maxConcurrentRotations) {
      throw new SecretBackendError(
        'Превышен лимит одновременных ротаций',
        'unknown' as any
      );
    }
    
    const config = this.secretConfigs.get(secretId) ?? this.defaultRotationConfig;
    
    // Проверка минимального интервала
    const lastRotation = state.history[state.history.length - 1];
    
    if (lastRotation) {
      const timeSinceLastRotation = Date.now() - lastRotation.timestamp.getTime();
      const minInterval = config.minRotationInterval * 1000;
      
      if (timeSinceLastRotation < minInterval) {
        throw new SecretBackendError(
          `Слишком частая ротация. Минимальный интервал: ${config.minRotationInterval}s`,
          'unknown' as any
        );
      }
    }
    
    // Обновление статуса
    state.status = {
      secretId,
      status: 'rotating',
      currentVersion: state.status.currentVersion,
      progress: 0
    };
    
    this.activeRotations++;
    
    this.emit('rotation:started', secretId);
    
    try {
      // Выполнение ротации с retry
      const result = await this.executeRotationWithRetry(
        secretId,
        newSecretValue,
        config,
        reason
      );
      
      // Обновление статуса
      state.status = {
        secretId,
        status: 'completed',
        currentVersion: result.version,
        lastRotationAt: new Date(),
        nextRotationAt: new Date(Date.now() + config.rotationInterval * 1000)
      };
      
      // Добавление в историю
      state.history.push({
        timestamp: new Date(),
        oldVersion: state.status.currentVersion,
        newVersion: result.version,
        success: true,
        durationMs: 0 // Будет обновлено
      });
      
      // Ограничение истории
      if (config.keepHistory && state.history.length > config.historyLimit) {
        state.history = state.history.slice(-config.historyLimit);
      }

      logger.info(`[SecretRotator] Ротация секрета ${secretId} завершена успешно`, {
        newVersion: result.version
      });

      this.emit('rotation:completed', {
        secretId,
        newVersion: result.version
      });
      
      // Планирование следующей ротации
      this.scheduleNextRotation(secretId);
      
      return result;
    } catch (error) {
      // Обновление статуса при ошибке
      state.status = {
        secretId,
        status: 'failed',
        currentVersion: state.status.currentVersion,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
      
      // Добавление в историю
      state.history.push({
        timestamp: new Date(),
        oldVersion: state.status.currentVersion,
        newVersion: state.status.currentVersion,
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        durationMs: 0
      });

      logger.error(`[SecretRotator] Ошибка ротации секрета ${secretId}`, { error });

      this.emit('rotation:failed', {
        secretId,
        error
      });
      
      throw error;
    } finally {
      this.activeRotations--;
    }
  }

  /**
   * Выполнение ротации с retry
   */
  private async executeRotationWithRetry(
    secretId: string,
    newSecretValue: string | undefined,
    config: RotationConfig,
    reason?: string
  ): Promise<BackendSecret> {
    let lastError: Error | null = null;
    
    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        return await this.executeRotation(
          secretId,
          newSecretValue,
          config,
          reason
        );
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));

        if (attempt < this.config.retryAttempts) {
          logger.info(`[SecretRotator] Попытка ${attempt} не удалась, повтор через ${this.config.retryDelay}мс`);
          await this.sleep(this.config.retryDelay);
        }
      }
    }
    
    throw lastError;
  }

  /**
   * Выполнение ротации
   */
  private async executeRotation(
    secretId: string,
    newSecretValue: string | undefined,
    config: RotationConfig,
    reason?: string
  ): Promise<BackendSecret> {
    const startTime = Date.now();
    
    if (!this.backend) {
      throw new SecretBackendError('Бэкенд не инициализирован', 'unknown' as any);
    }
    
    // Получение текущего секрета
    const currentSecret = await this.backend.getSecret(secretId);
    
    if (!currentSecret) {
      throw new SecretBackendError(`Секрет ${secretId} не найден`, 'unknown' as any);
    }
    
    // Генерация нового значения
    const newValue = newSecretValue ?? this.generator.generate(32);
    
    // Grace period: создание новой версии без деактивации старой
    const newSecret: Omit<BackendSecret, 'version' | 'createdAt' | 'updatedAt'> = {
      id: secretId,
      name: currentSecret.name,
      value: newValue,
      status: config.autoActivate ? SecretStatus.ACTIVE : SecretStatus.PENDING,
      metadata: {
        ...currentSecret.metadata,
        rotatedFrom: currentSecret.version,
        rotationReason: reason ?? 'scheduled',
        gracePeriodEnd: config.gracePeriod > 0
          ? new Date(Date.now() + config.gracePeriod * 1000).toISOString()
          : undefined
      }
    };
    
    // Обновление секрета (создание новой версии)
    const updatedSecret = await this.backend.updateSecret(
      secretId,
      newValue,
      newSecret.metadata
    );
    
    // Если grace period включён, планируем деактивацию старой версии
    if (config.gracePeriod > 0 && !config.autoActivate) {
      setTimeout(async () => {
        try {
          await this.activateNewVersion(secretId, updatedSecret.version);
        } catch (error) {
          logger.error(`[SecretRotator] Ошибка активации новой версии ${secretId}`, { error });
        }
      }, config.gracePeriod * 1000);
    }
    
    const durationMs = Date.now() - startTime;
    
    // Обновление истории с длительностью
    const state = this.rotationStates.get(secretId);
    if (state && state.history.length > 0) {
      state.history[state.history.length - 1].durationMs = durationMs;
    }
    
    return updatedSecret;
  }

  /**
   * Активация новой версии после grace period
   */
  private async activateNewVersion(
    secretId: string,
    version: number
  ): Promise<void> {
    if (!this.backend) {
      throw new SecretBackendError('Бэкенд не инициализирован', 'unknown' as any);
    }

    logger.info(`[SecretRotator] Активация версии ${version}`, {
      secretId
    });

    // Логика активации зависит от реализации бэкенда
    this.emit('rotation:version-activated', { secretId, version });
  }

  /**
   * Планирование следующей ротации
   */
  private scheduleNextRotation(secretId: string): void {
    const state = this.rotationStates.get(secretId);
    const config = this.secretConfigs.get(secretId) ?? this.defaultRotationConfig;
    
    if (!state || !config.enabled) {
      return;
    }
    
    // Остановка предыдущего таймера
    if (state.nextRotationTimer) {
      clearTimeout(state.nextRotationTimer);
    }
    
    // Планирование новой ротации
    state.nextRotationTimer = setTimeout(() => {
      if (this.isRunning && config.enabled) {
        logger.info(`[SecretRotator] Запуск запланированной ротации для ${secretId}`);

        this.rotateSecret(secretId, undefined, 'scheduled')
          .catch(error => {
            logger.error(`[SecretRotator] Ошибка запланированной ротации ${secretId}`, { error });
          });
      }
    }, config.rotationInterval * 1000);
    
    state.nextRotationTimer.unref();
    
    // Обновление статуса
    state.status.nextRotationAt = new Date(Date.now() + config.rotationInterval * 1000);
  }

  /**
   * Запуск периодической проверки ротации
   */
  private startRotationCheck(): void {
    this.checkInterval = setInterval(() => {
      this.checkRotations();
    }, this.config.checkInterval * 1000);
    
    this.checkInterval.unref();
  }

  /**
   * Проверка необходимости ротации
   */
  private checkRotations(): void {
    const now = Date.now();
    
    for (const [secretId, state] of this.rotationStates.entries()) {
      const config = this.secretConfigs.get(secretId) ?? this.defaultRotationConfig;
      
      if (!config.enabled || state.status.status === 'rotating') {
        continue;
      }
      
      // Проверка времени следующей ротации
      if (state.status.nextRotationAt) {
        const nextRotationTime = state.status.nextRotationAt.getTime();

        if (now >= nextRotationTime) {
          logger.info(`[SecretRotator] Время ротации для ${secretId} наступило`);

          this.rotateSecret(secretId, undefined, 'scheduled')
            .catch(error => {
              logger.error(`[SecretRotator] Ошибка ротации ${secretId}`, { error });
            });
        }
      }
    }
  }

  /**
   * Получить статус ротации для секрета
   * 
   * @param secretId - ID секрета
   * @returns Статус ротации
   */
  getRotationStatus(secretId: string): RotationStatus | null {
    const state = this.rotationStates.get(secretId);
    return state?.status ?? null;
  }

  /**
   * Получить историю ротаций для секрета
   * 
   * @param secretId - ID секрета
   * @returns История ротаций
   */
  getRotationHistory(secretId: string): RotationHistoryEntry[] {
    const state = this.rotationStates.get(secretId);
    return state?.history ?? [];
  }

  /**
   * Отключить ротацию для секрета
   * 
   * @param secretId - ID секрета
   */
  disableRotation(secretId: string): void {
    const config = this.secretConfigs.get(secretId);
    
    if (config) {
      config.enabled = false;
      this.secretConfigs.set(secretId, config);
    }
    
    const state = this.rotationStates.get(secretId);

    if (state && state.nextRotationTimer) {
      clearTimeout(state.nextRotationTimer);
      state.nextRotationTimer = undefined;
    }

    logger.info(`[SecretRotator] Ротация отключена для ${secretId}`);
    this.emit('rotation:disabled', secretId);
  }

  /**
   * Включить ротацию для секрета
   *
   * @param secretId - ID секрета
   */
  enableRotation(secretId: string): void {
    const config = this.secretConfigs.get(secretId);

    if (config) {
      config.enabled = true;
      this.secretConfigs.set(secretId, config);
      this.scheduleNextRotation(secretId);
    }

    logger.info(`[SecretRotator] Ротация включена для ${secretId}`);
    this.emit('rotation:enabled', secretId);
  }

  /**
   * Получить статистику ротатора
   */
  getStats(): {
    totalSecrets: number;
    enabledRotations: number;
    activeRotations: number;
    failedRotations: number;
    totalRotationsPerformed: number;
    avgRotationDurationMs: number;
  } {
    let enabledCount = 0;
    let failedCount = 0;
    let totalPerformed = 0;
    let totalDuration = 0;
    
    for (const state of this.rotationStates.values()) {
      const config = this.secretConfigs.get(state.status.secretId);
      
      if (config?.enabled) {
        enabledCount++;
      }
      
      if (state.status.status === 'failed') {
        failedCount++;
      }
      
      for (const entry of state.history) {
        totalPerformed++;
        totalDuration += entry.durationMs;
      }
    }
    
    return {
      totalSecrets: this.rotationStates.size,
      enabledRotations: enabledCount,
      activeRotations: this.activeRotations,
      failedRotations: failedCount,
      totalRotationsPerformed: totalPerformed,
      avgRotationDurationMs: totalPerformed > 0 ? totalDuration / totalPerformed : 0
    };
  }

  /**
   * Принудительная ротация всех секретов (для тестирования)
   */
  async forceRotateAll(): Promise<Map<string, BackendSecret | Error>> {
    const results = new Map<string, BackendSecret | Error>();
    
    for (const secretId of this.secretConfigs.keys()) {
      try {
        const result = await this.rotateSecret(secretId, undefined, 'forced');
        results.set(secretId, result);
      } catch (error) {
        results.set(secretId, error instanceof Error ? error : new Error(String(error)));
      }
    }
    
    return results;
  }

  /**
   * Утилита для задержки
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Сгенерировать новое значение секрета
   * 
   * @param type - Тип секрета
   * @param length - Длина (опционально)
   * @returns Сгенерированное значение
   */
  generateSecretValue(type: 'password' | 'apikey' | 'token' | 'random', length?: number): string {
    switch (type) {
      case 'password':
        return this.generator.generatePassword(length);
      case 'apikey':
        return this.generator.generateApiKey();
      case 'token':
        return this.generator.generateToken();
      case 'random':
      default:
        return this.generator.generate(length);
    }
  }
}
