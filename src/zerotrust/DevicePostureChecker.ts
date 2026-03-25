/**
 * Device Posture Checker - Проверка Состояния Устройств
 * 
 * Компонент отвечает за непрерывную проверку соответствия устройств
 * политикам безопасности организации. Реализует проверку антивируса,
 * фаервола, шифрования диска, обновлений ОС и других параметров.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import {
  DevicePosture,
  DeviceHealthStatus,
  DeviceType,
  ZeroTrustEvent,
  SubjectType
} from './zerotrust.types';

/**
 * Конфигурация проверок устройства
 */
interface PostureCheckConfig {
  /** Проверка антивируса */
  antivirus: {
    /** Включить проверку */
    enabled: boolean;
    /** Требуется активный антивирус */
    required: boolean;
    /** Требуется обновление баз */
    requireUpdated: boolean;
    /** Максимальная возраст баз (часы) */
    maxDatabaseAgeHours: number;
  };
  
  /** Проверка фаервола */
  firewall: {
    /** Включить проверку */
    enabled: boolean;
    /** Требуется активный фаервол */
    required: boolean;
  };
  
  /** Проверка шифрования диска */
  diskEncryption: {
    /** Включить проверку */
    enabled: boolean;
    /** Требуется шифрование */
    required: boolean;
    /** Минимальный процент зашифрованных дисков */
    minEncryptedPercentage: number;
  };
  
  /** Проверка обновлений ОС */
  osUpdates: {
    /** Включить проверку */
    enabled: boolean;
    /** Требуются критические обновления */
    requireCriticalUpdates: boolean;
    /** Максимальная задержка обновлений (дни) */
    maxUpdateDelayDays: number;
  };
  
  /** Проверка Secure Boot */
  secureBoot: {
    /** Включить проверку */
    enabled: boolean;
    /** Требуется Secure Boot */
    required: boolean;
  };
  
  /** Проверка TPM */
  tpm: {
    /** Включить проверку */
    enabled: boolean;
    /** Требуется TPM */
    required: boolean;
    /** Минимальная версия TPM */
    minVersion: '1.2' | '2.0';
  };
  
  /** Проверка на jailbreak/rootkit */
  jailbreakDetection: {
    /** Включить проверку */
    enabled: boolean;
    /** Блокировать при обнаружении */
    blockOnDetection: boolean;
  };
}

/**
 * Конфигурация Device Posture Checker
 */
export interface DevicePostureCheckerConfig {
  /** Конфигурация проверок */
  checks: PostureCheckConfig;
  
  /** Интервал проверки (секунды) */
  checkInterval: number;
  
  /** Время жизни posture (секунды) */
  postureLifetime: number;
  
  /** Порог risk score для блокировки */
  blockRiskThreshold: number;
  
  /** Порог risk score для предупреждения */
  warningRiskThreshold: number;
  
  /** Включить непрерывный мониторинг */
  enableContinuousMonitoring: boolean;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
  
  /** Кэшировать результаты проверок */
  enableCaching: boolean;
  
  /** TTL кэша (секунды) */
  cacheTtl: number;
}

/**
 * Результат отдельной проверки
 */
interface CheckResult {
  /** Название проверки */
  checkName: string;
  
  /** Пройдена ли проверка */
  passed: boolean;
  
  /** Сообщение результата */
  message: string;
  
  /** Детали проверки */
  details: Record<string, unknown>;
  
  /** Вес проверки в общей оценке */
  weight: number;
  
  /** Критичность проверки */
  criticality: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

/**
 * Кэш результатов проверок
 */
interface PostureCache {
  /** Кэш по device ID */
  entries: Map<string, {
    /** Posture устройства */
    posture: DevicePosture;
    /** Время кэширования */
    cachedAt: Date;
    /** Время истечения */
    expiresAt: Date;
  }>;
  
  /** Максимальный размер */
  maxSize: number;
}

/**
 * Агент проверки устройства (абстрактный интерфейс)
 */
interface DeviceCheckAgent {
  /** Проверить антивирус */
  checkAntivirus(): Promise<CheckResult>;
  
  /** Проверить фаервол */
  checkFirewall(): Promise<CheckResult>;
  
  /** Проверить шифрование диска */
  checkDiskEncryption(): Promise<CheckResult>;
  
  /** Проверить обновления ОС */
  checkOsUpdates(): Promise<CheckResult>;
  
  /** Проверить Secure Boot */
  checkSecureBoot(): Promise<CheckResult>;
  
  /** Проверить TPM */
  checkTpm(): Promise<CheckResult>;
  
  /** Проверить на jailbreak */
  checkJailbreak(): Promise<CheckResult>;
  
  /** Получить информацию об устройстве */
  getDeviceInfo(): Promise<{
    deviceId: string;
    deviceType: DeviceType;
    operatingSystem: DevicePosture['operatingSystem'];
    network: DevicePosture['network'];
  }>;
}

/**
 * Device Posture Checker
 * 
 * Компонент для проверки соответствия устройств политикам безопасности.
 */
export class DevicePostureChecker extends EventEmitter {
  /** Конфигурация */
  private config: DevicePostureCheckerConfig;
  
  /** Агент проверок (платформо-зависимый) */
  private checkAgent: DeviceCheckAgent | null;
  
  /** Кэш результатов */
  private cache: PostureCache;
  
  /** Активные проверки */
  private activeChecks: Map<string, Promise<DevicePosture>>;
  
  /** Таймеры непрерывного мониторинга */
  private monitoringTimers: Map<string, NodeJS.Timeout>;
  
  /** Статистика проверок */
  private stats: {
    /** Всего проверок */
    totalChecks: number;
    /** Успешных проверок */
    successfulChecks: number;
    /** Проваленных проверок */
    failedChecks: number;
    /** Устройств в кэше */
    cachedDevices: number;
    /** Среднее время проверки */
    averageCheckTime: number;
  };

  constructor(config: Partial<DevicePostureCheckerConfig> = {}) {
    super();
    
    this.config = {
      checks: {
        antivirus: {
          enabled: config.checks?.antivirus?.enabled ?? true,
          required: config.checks?.antivirus?.required ?? true,
          requireUpdated: config.checks?.antivirus?.requireUpdated ?? true,
          maxDatabaseAgeHours: config.checks?.antivirus?.maxDatabaseAgeHours ?? 24
        },
        firewall: {
          enabled: config.checks?.firewall?.enabled ?? true,
          required: config.checks?.firewall?.required ?? true
        },
        diskEncryption: {
          enabled: config.checks?.diskEncryption?.enabled ?? true,
          required: config.checks?.diskEncryption?.required ?? true,
          minEncryptedPercentage: config.checks?.diskEncryption?.minEncryptedPercentage ?? 100
        },
        osUpdates: {
          enabled: config.checks?.osUpdates?.enabled ?? true,
          requireCriticalUpdates: config.checks?.osUpdates?.requireCriticalUpdates ?? true,
          maxUpdateDelayDays: config.checks?.osUpdates?.maxUpdateDelayDays ?? 7
        },
        secureBoot: {
          enabled: config.checks?.secureBoot?.enabled ?? true,
          required: config.checks?.secureBoot?.required ?? false
        },
        tpm: {
          enabled: config.checks?.tpm?.enabled ?? true,
          required: config.checks?.tpm?.required ?? false,
          minVersion: config.checks?.tpm?.minVersion ?? '2.0'
        },
        jailbreakDetection: {
          enabled: config.checks?.jailbreakDetection?.enabled ?? true,
          blockOnDetection: config.checks?.jailbreakDetection?.blockOnDetection ?? true
        }
      },
      checkInterval: config.checkInterval ?? 3600, // 1 час
      postureLifetime: config.postureLifetime ?? 900, // 15 минут
      blockRiskThreshold: config.blockRiskThreshold ?? 80,
      warningRiskThreshold: config.warningRiskThreshold ?? 50,
      enableContinuousMonitoring: config.enableContinuousMonitoring ?? true,
      enableVerboseLogging: config.enableVerboseLogging ?? false,
      enableCaching: config.enableCaching ?? true,
      cacheTtl: config.cacheTtl ?? 300
    };
    
    this.checkAgent = null;
    this.cache = {
      entries: new Map(),
      maxSize: 10000
    };
    this.activeChecks = new Map();
    this.monitoringTimers = new Map();
    
    this.stats = {
      totalChecks: 0,
      successfulChecks: 0,
      failedChecks: 0,
      cachedDevices: 0,
      averageCheckTime: 0
    };
    
    this.log('DPC', 'DevicePostureChecker инициализирован');
  }

  /**
   * Установить агент проверок
   * 
   * @param agent Платформо-зависимый агент проверок
   */
  public setCheckAgent(agent: DeviceCheckAgent): void {
    this.checkAgent = agent;
    this.log('DPC', 'Агент проверок установлен', { agentType: agent.constructor.name });
  }

  /**
   * Проверить posture устройства
   * 
   * @param deviceId ID устройства для проверки
   * @param forceForce Принудительная проверка (игнорировать кэш)
   * @returns Posture устройства
   */
  public async checkDevicePosture(
    deviceId: string,
    force: boolean = false
  ): Promise<DevicePosture> {
    const startTime = Date.now();
    this.stats.totalChecks++;
    
    this.log('DPC', 'Начало проверки устройства', { deviceId, force });
    
    // Проверяем кэш
    if (!force && this.config.enableCaching) {
      const cached = this.getCachedPosture(deviceId);
      if (cached) {
        this.log('DPC', 'Posture найдено в кэше', { deviceId });
        return cached;
      }
    }
    
    // Проверяем активную проверку
    const activeCheck = this.activeChecks.get(deviceId);
    if (activeCheck && !force) {
      this.log('DPC', 'Используем результат активной проверки', { deviceId });
      return activeCheck;
    }
    
    // Создаём новую проверку
    const checkPromise = this.performPostureCheck(deviceId);
    this.activeChecks.set(deviceId, checkPromise);
    
    try {
      const posture = await checkPromise;
      
      // Кэшируем результат
      if (this.config.enableCaching) {
        this.cachePosture(deviceId, posture);
      }
      
      // Обновляем статистику
      const checkTime = Date.now() - startTime;
      this.stats.averageCheckTime = 
        (this.stats.averageCheckTime * (this.stats.totalChecks - 1) + checkTime) /
        this.stats.totalChecks;
      
      if (posture.healthStatus === DeviceHealthStatus.HEALTHY) {
        this.stats.successfulChecks++;
      } else {
        this.stats.failedChecks++;
      }
      
      // Эмитим событие
      this.emit('posture:checked', {
        deviceId,
        posture,
        checkTime
      });
      
      // Запускаем непрерывный мониторинг если включено
      if (this.config.enableContinuousMonitoring && !this.monitoringTimers.has(deviceId)) {
        this.startContinuousMonitoring(deviceId);
      }
      
      return posture;
      
    } catch (error) {
      this.log('DPC', 'Ошибка проверки устройства', {
        deviceId,
        error: error instanceof Error ? error.message : String(error)
      });
      
      // Возвращаем UNKNOWN posture при ошибке
      const errorPosture = this.createUnknownPosture(deviceId);
      this.emit('posture:error', { deviceId, error });
      
      return errorPosture;
      
    } finally {
      this.activeChecks.delete(deviceId);
    }
  }

  /**
   * Выполнить полную проверку устройства
   */
  private async performPostureCheck(deviceId: string): Promise<DevicePosture> {
    if (!this.checkAgent) {
      throw new Error('Агент проверок не установлен. Вызовите setCheckAgent().');
    }
    
    // Получаем информацию об устройстве
    const deviceInfo = await this.checkAgent.getDeviceInfo();
    
    // Выполняем все проверки параллельно
    const checkResults = await Promise.allSettled([
      this.config.checks.antivirus.enabled ? 
        this.checkAgent.checkAntivirus() : 
        Promise.resolve(this.createSkippedResult('antivirus')),
      
      this.config.checks.firewall.enabled ? 
        this.checkAgent.checkFirewall() : 
        Promise.resolve(this.createSkippedResult('firewall')),
      
      this.config.checks.diskEncryption.enabled ? 
        this.checkAgent.checkDiskEncryption() : 
        Promise.resolve(this.createSkippedResult('diskEncryption')),
      
      this.config.checks.osUpdates.enabled ? 
        this.checkAgent.checkOsUpdates() : 
        Promise.resolve(this.createSkippedResult('osUpdates')),
      
      this.config.checks.secureBoot.enabled ? 
        this.checkAgent.checkSecureBoot() : 
        Promise.resolve(this.createSkippedResult('secureBoot')),
      
      this.config.checks.tpm.enabled ? 
        this.checkAgent.checkTpm() : 
        Promise.resolve(this.createSkippedResult('tpm')),
      
      this.config.checks.jailbreakDetection.enabled ? 
        this.checkAgent.checkJailbreak() : 
        Promise.resolve(this.createSkippedResult('jailbreak'))
    ]);
    
    // Обрабатываем результаты проверок
    const results: CheckResult[] = [];
    
    for (const result of checkResults) {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      } else {
        this.log('DPC', 'Проверка завершилась ошибкой', {
          error: result.reason
        });
      }
    }
    
    // Вычисляем health status и risk score
    const healthStatus = this.calculateHealthStatus(results);
    const riskScore = this.calculateRiskScore(results);
    
    // Создаём posture
    const now = new Date();
    const posture: DevicePosture = {
      deviceId,
      deviceType: deviceInfo.deviceType,
      operatingSystem: deviceInfo.operatingSystem,
      healthStatus,
      compliance: {
        antivirusActive: this.getCheckResult(results, 'antivirus', 'details')?.active ?? false,
        antivirusUpdated: this.getCheckResult(results, 'antivirus', 'details')?.updated ?? false,
        firewallActive: this.getCheckResult(results, 'firewall', 'details')?.active ?? false,
        diskEncrypted: this.getCheckResult(results, 'diskEncryption', 'details')?.encrypted ?? false,
        secureBootEnabled: this.getCheckResult(results, 'secureBoot', 'details')?.enabled ?? false,
        tpmPresent: this.getCheckResult(results, 'tpm', 'details')?.present ?? false,
        lastUpdateCheck: this.getCheckResult(results, 'osUpdates', 'details')?.lastCheck ?? now,
        criticalUpdatesInstalled: this.getCheckResult(results, 'osUpdates', 'details')?.criticalInstalled ?? false,
        jailbreakDetected: this.getCheckResult(results, 'jailbreak', 'details')?.detected ?? false
      },
      network: deviceInfo.network,
      location: undefined, // Может быть заполнено агентом
      lastCheckedAt: now,
      nextCheckAt: new Date(now.getTime() + this.config.checkInterval * 1000),
      riskScore
    };
    
    // Эмитим событие изменения posture
    if (healthStatus !== DeviceHealthStatus.HEALTHY) {
      this.emit('posture:degraded', {
        deviceId,
        posture,
        healthStatus,
        riskScore
      });
    }
    
    return posture;
  }

  /**
   * Создать результат пропущенной проверки
   */
  private createSkippedResult(checkName: string): CheckResult {
    return {
      checkName,
      passed: true,
      message: 'Проверка отключена в конфигурации',
      details: { skipped: true },
      weight: 0,
      criticality: 'LOW'
    };
  }

  /**
   * Получить результат конкретной проверки
   */
  private getCheckResult(
    results: CheckResult[],
    checkName: string,
    field?: string
  ): Record<string, unknown> | boolean {
    const result = results.find(r => r.checkName === checkName);
    
    if (!result) {
      return field ? false : {};
    }
    
    if (field && typeof result.details === 'object' && result.details !== null) {
      return (result.details as Record<string, unknown>)[field] as Record<string, unknown>;
    }
    
    return result.details;
  }

  /**
   * Вычислить статус здоровья устройства
   */
  private calculateHealthStatus(results: CheckResult[]): DeviceHealthStatus {
    const criticalFailed = results.some(
      r => !r.passed && r.criticality === 'CRITICAL'
    );
    
    if (criticalFailed) {
      return DeviceHealthStatus.NON_COMPLIANT;
    }
    
    const highFailed = results.some(
      r => !r.passed && r.criticality === 'HIGH'
    );
    
    if (highFailed) {
      return DeviceHealthStatus.DEGRADED;
    }
    
    const anyFailed = results.some(r => !r.passed && r.weight > 0);
    
    if (anyFailed) {
      return DeviceHealthStatus.DEGRADED;
    }
    
    return DeviceHealthStatus.HEALTHY;
  }

  /**
   * Вычислить оценку риска
   */
  private calculateRiskScore(results: CheckResult[]): number {
    let totalWeight = 0;
    let failedWeight = 0;
    
    for (const result of results) {
      if (result.weight === 0) continue;
      
      totalWeight += result.weight;
      
      if (!result.passed) {
        // Увеличиваем вес проваленной проверки в зависимости от критичности
        const criticalityMultiplier = {
          'LOW': 1,
          'MEDIUM': 2,
          'HIGH': 3,
          'CRITICAL': 5
        };
        
        failedWeight += result.weight * criticalityMultiplier[result.criticality];
      }
    }
    
    if (totalWeight === 0) {
      return 0;
    }
    
    // Нормализуем к 0-100
    const rawScore = (failedWeight / totalWeight) * 100;
    
    // Проверяем на jailbreak - это автоматически высокий риск
    const jailbreakDetected = results.find(r => r.checkName === 'jailbreak');
    if (jailbreakDetected && !jailbreakDetected.passed) {
      return 100;
    }
    
    return Math.min(100, Math.round(rawScore));
  }

  /**
   * Создать UNKNOWN posture
   */
  private createUnknownPosture(deviceId: string): DevicePosture {
    const now = new Date();
    
    return {
      deviceId,
      deviceType: DeviceType.WORKSTATION,
      operatingSystem: {
        name: 'Unknown',
        version: 'Unknown',
        build: 'Unknown',
        patchLevel: 'Unknown'
      },
      healthStatus: DeviceHealthStatus.UNKNOWN,
      compliance: {
        antivirusActive: false,
        antivirusUpdated: false,
        firewallActive: false,
        diskEncrypted: false,
        secureBootEnabled: false,
        tpmPresent: false,
        lastUpdateCheck: now,
        criticalUpdatesInstalled: false,
        jailbreakDetected: false
      },
      network: {
        ipAddress: '0.0.0.0',
        macAddress: '00:00:00:00:00:00',
        connectionType: 'Ethernet'
      },
      lastCheckedAt: now,
      nextCheckAt: new Date(now.getTime() + this.config.checkInterval * 1000),
      riskScore: 50 // Средний риск для неизвестных устройств
    };
  }

  /**
   * Получить posture из кэша
   */
  private getCachedPosture(deviceId: string): DevicePosture | null {
    const cached = this.cache.entries.get(deviceId);
    
    if (!cached) {
      return null;
    }
    
    // Проверяем истечение
    if (new Date() > cached.expiresAt) {
      this.cache.entries.delete(deviceId);
      return null;
    }
    
    return cached.posture;
  }

  /**
   * Кэшировать posture
   */
  private cachePosture(deviceId: string, posture: DevicePosture): void {
    // Очищаем старые записи если кэш переполнен
    if (this.cache.entries.size >= this.cache.maxSize) {
      const firstKey = this.cache.entries.keys().next().value;
      if (firstKey) {
        this.cache.entries.delete(firstKey);
      }
    }
    
    this.cache.entries.set(deviceId, {
      posture,
      cachedAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.cacheTtl * 1000)
    });
    
    this.stats.cachedDevices = this.cache.entries.size;
  }

  /**
   * Запустить непрерывный мониторинг устройства
   */
  private startContinuousMonitoring(deviceId: string): void {
    const timer = setInterval(() => {
      this.log('DPC', 'Непрерывный мониторинг', { deviceId });
      
      // Проверяем posture
      this.checkDevicePosture(deviceId, false).catch(error => {
        this.log('DPC', 'Ошибка непрерывного мониторинга', { deviceId, error });
      });
    }, this.config.checkInterval * 1000);
    
    this.monitoringTimers.set(deviceId, timer);
    
    this.log('DPC', 'Непрерывный мониторинг запущен', {
      deviceId,
      interval: this.config.checkInterval
    });
  }

  /**
   * Остановить непрерывный мониторинг устройства
   */
  public stopContinuousMonitoring(deviceId: string): void {
    const timer = this.monitoringTimers.get(deviceId);
    
    if (timer) {
      clearInterval(timer);
      this.monitoringTimers.delete(deviceId);
      
      this.log('DPC', 'Непрерывный мониторинг остановлен', { deviceId });
    }
  }

  /**
   * Остановить весь непрерывный мониторинг
   */
  public stopAllMonitoring(): void {
    for (const [deviceId, timer] of this.monitoringTimers.entries()) {
      clearInterval(timer);
      this.log('DPC', 'Непрерывный мониторинг остановлен', { deviceId });
    }
    
    this.monitoringTimers.clear();
  }

  /**
   * Очистить кэш
   */
  public clearCache(): void {
    this.cache.entries.clear();
    this.stats.cachedDevices = 0;
    this.log('DPC', 'Кэш очищен');
  }

  /**
   * Проверить здоровье устройства
   *
   * @param posture Состояние устройства для проверки
   * @returns true если устройство здорово, false если нет
   */
  public async checkHealth(posture: DevicePosture): Promise<boolean> {
    this.log('DPC', 'Проверка здоровья устройства', {
      deviceId: posture.deviceId,
      currentHealthStatus: posture.healthStatus
    });

    // Устройство считается здоровым если:
    // 1. healthStatus === HEALTHY
    // 2. riskScore ниже порога предупреждения
    // 3. Все критические проверки пройдены

    if (posture.healthStatus !== DeviceHealthStatus.HEALTHY) {
      this.log('DPC', 'Устройство нездорово', {
        deviceId: posture.deviceId,
        healthStatus: posture.healthStatus
      });
      return false;
    }

    if (posture.riskScore >= this.config.warningRiskThreshold) {
      this.log('DPC', 'Риск устройства превышает порог', {
        deviceId: posture.deviceId,
        riskScore: posture.riskScore,
        threshold: this.config.warningRiskThreshold
      });
      return false;
    }

    // Проверка критических параметров
    const criticalChecks = [
      posture.compliance.antivirusActive,
      posture.compliance.firewallActive,
      !posture.compliance.jailbreakDetected
    ];

    const allCriticalPassed = criticalChecks.every(check => check === true);

    if (!allCriticalPassed) {
      this.log('DPC', 'Критическая проверка не пройдена', {
        deviceId: posture.deviceId,
        criticalChecks: {
          antivirusActive: posture.compliance.antivirusActive,
          firewallActive: posture.compliance.firewallActive,
          jailbreakDetected: posture.compliance.jailbreakDetected
        }
      });
      return false;
    }

    this.log('DPC', 'Устройство здорово', {
      deviceId: posture.deviceId,
      riskScore: posture.riskScore
    });

    return true;
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats & {
    /** Активные проверки */
    activeChecks: number;
    /** Устройства под мониторингом */
    monitoredDevices: number;
  } {
    return {
      ...this.stats,
      activeChecks: this.activeChecks.size,
      monitoredDevices: this.monitoringTimers.size
    };
  }

  /**
   * Получить конфигурацию проверок
   */
  public getCheckConfig(): PostureCheckConfig {
    return { ...this.config.checks };
  }

  /**
   * Обновить конфигурацию проверок
   * 
   * @param checks Новая конфигурация проверок
   */
  public updateCheckConfig(checks: Partial<PostureCheckConfig>): void {
    this.config.checks = {
      antivirus: { ...this.config.checks.antivirus, ...checks.antivirus },
      firewall: { ...this.config.checks.firewall, ...checks.firewall },
      diskEncryption: { ...this.config.checks.diskEncryption, ...checks.diskEncryption },
      osUpdates: { ...this.config.checks.osUpdates, ...checks.osUpdates },
      secureBoot: { ...this.config.checks.secureBoot, ...checks.secureBoot },
      tpm: { ...this.config.checks.tpm, ...checks.tpm },
      jailbreakDetection: { ...this.config.checks.jailbreakDetection, ...checks.jailbreakDetection }
    };
    
    this.log('DPC', 'Конфигурация проверок обновлена');
    this.emit('config:updated', { checks: this.config.checks });
  }

  /**
   * Логирование событий
   */
  private log(component: string, message: string, data?: unknown): void {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'DEVICE_POSTURE_CHANGED',
      timestamp: new Date(),
      subject: {
        id: 'system',
        type: SubjectType.SYSTEM,
        name: component
      },
      details: { message, ...data },
      severity: 'INFO',
      correlationId: uuidv4()
    };
    
    this.emit('log', event);

    if (this.config.enableVerboseLogging) {
      logger.debug(`[DPC] ${message}`, { timestamp: new Date().toISOString(), ...data });
    }
  }
}

export default DevicePostureChecker;
