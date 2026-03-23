/**
 * Network Access Control (NAC) - Контроль Сетевого Доступа
 * 
 * Компонент реализует контекстно-зависимый контроль доступа к сети
 * на основе идентичности, устройства, местоположения и других факторов.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { v4 as uuidv4 } from 'uuid';
import {
  Identity,
  AuthContext,
  DevicePosture,
  DeviceHealthStatus,
  TrustLevel,
  ZeroTrustEvent,
  SubjectType
} from './zerotrust.types';
import { PolicyDecisionPoint } from './PolicyDecisionPoint';
import { DevicePostureChecker } from './DevicePostureChecker';

/**
 * Тип сетевого доступа
 */
enum NetworkAccessType {
  /** Полный доступ к сети */
  FULL_ACCESS = 'FULL_ACCESS',
  
  /** Ограниченный доступ */
  RESTRICTED_ACCESS = 'RESTRICTED_ACCESS',
  
  /** Доступ только к шлюзу */
  GATEWAY_ONLY = 'GATEWAY_ONLY',
  
  /** Изолированная сеть (quarantine) */
  QUARANTINE = 'QUARANTINE',
  
  /** Доступ запрещён */
  DENY = 'DENY'
}

/**
 * Конфигурация NAC
 */
export interface NetworkAccessControlConfig {
  /** Включить контекстную оценку */
  enableContextAware: boolean;
  
  /** Включить оценку устройства */
  enableDevicePosture: boolean;
  
  /** Включить оценку местоположения */
  enableLocationCheck: boolean;
  
  /** Включить оценку времени */
  enableTimeCheck: boolean;
  
  /** Включить поведенческий анализ */
  enableBehavioralAnalysis: boolean;
  
  /** Минимальный уровень доверия для доступа */
  minimumTrustLevel: TrustLevel;
  
  /** Минимальный статус устройства для доступа */
  minimumDeviceHealth: DeviceHealthStatus;
  
  /** Разрешённые страны */
  allowedCountries: string[];
  
  /** Запрещённые страны */
  deniedCountries: string[];
  
  /** Разрешённое время доступа */
  allowedTimeRange: {
    startHour: number;
    endHour: number;
    allowedDays: number[];
  };
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
}

/**
 * Контекст сетевого доступа
 */
interface NetworkAccessContext {
  /** ID запроса */
  requestId: string;
  
  /** Идентичность */
  identity: Identity;
  
  /** Контекст аутентификации */
  authContext: AuthContext;
  
  /** Posture устройства */
  devicePosture?: DevicePosture;
  
  /** Сетевой контекст */
  network: {
    /** IP адрес */
    ipAddress: string;
    /** MAC адрес */
    macAddress?: string;
    /** SSID сети */
    ssid?: string;
    /** Тип подключения */
    connectionType: 'WiFi' | 'Ethernet' | 'VPN' | 'Cellular';
    /** VLAN ID */
    vlanId?: number;
  };
  
  /** Контекст местоположения */
  location: {
    /** Страна */
    country: string;
    /** Город */
    city?: string;
    /** Координаты */
    coordinates?: [number, number];
    /** Часовой пояс */
    timezone: string;
  };
  
  /** Временной контекст */
  temporal: {
    /** Время запроса */
    timestamp: Date;
    /** День недели */
    dayOfWeek: number;
    /** Час дня */
    hourOfDay: number;
  };
}

/**
 * Результат NAC проверки
 */
interface NetworkAccessResult {
  /** ID запроса */
  requestId: string;
  
  /** Разрешён ли доступ */
  allowed: boolean;
  
  /** Тип доступа */
  accessType: NetworkAccessType;
  
  /** Уровень доверия */
  trustLevel: TrustLevel;
  
  /** Оценка риска */
  riskScore: number;
  
  /** Применённые политики */
  appliedPolicies: string[];
  
  /** Ограничения */
  restrictions: {
    /** VLAN для назначения */
    vlanId?: number;
    /** ACL для применения */
    aclId?: string;
    /** Bandwidth лимит */
    bandwidthLimit?: number;
    /** Сегмент сети */
    networkSegment?: string;
  };
  
  /** Причина решения */
  reason: string;
}

/**
 * Network Access Control
 * 
 * Компонент для контекстно-зависимого контроля сетевого доступа.
 */
export class NetworkAccessControl extends EventEmitter {
  /** Конфигурация */
  private config: NetworkAccessControlConfig;
  
  /** PDP для проверок политик */
  private pdp: PolicyDecisionPoint | null;
  
  /** Device Posture Checker */
  private postureChecker: DevicePostureChecker | null;
  
  /** Активные сессии доступа */
  private activeSessions: Map<string, NetworkAccessResult>;
  
  /** История решений */
  private decisionHistory: Array<{
    timestamp: Date;
    context: NetworkAccessContext;
    result: NetworkAccessResult;
  }>;
  
  /** Статистика */
  private stats: {
    /** Всего запросов */
    totalRequests: number;
    /** Разрешено */
    allowed: number;
    /** Запрещено */
    denied: number;
    /** Ограниченный доступ */
    restricted: number;
    /** Карантин */
    quarantine: number;
  };

  constructor(config: Partial<NetworkAccessControlConfig> = {}) {
    super();
    
    this.config = {
      enableContextAware: config.enableContextAware ?? true,
      enableDevicePosture: config.enableDevicePosture ?? true,
      enableLocationCheck: config.enableLocationCheck ?? true,
      enableTimeCheck: config.enableTimeCheck ?? false,
      enableBehavioralAnalysis: config.enableBehavioralAnalysis ?? true,
      minimumTrustLevel: config.minimumTrustLevel ?? TrustLevel.LOW,
      minimumDeviceHealth: config.minimumDeviceHealth ?? DeviceHealthStatus.DEGRADED,
      allowedCountries: config.allowedCountries ?? [],
      deniedCountries: config.deniedCountries ?? [],
      allowedTimeRange: config.allowedTimeRange ?? {
        startHour: 0,
        endHour: 24,
        allowedDays: [0, 1, 2, 3, 4, 5, 6]
      },
      enableVerboseLogging: config.enableVerboseLogging ?? false
    };
    
    this.pdp = null;
    this.postureChecker = null;
    this.activeSessions = new Map();
    this.decisionHistory = [];
    
    this.stats = {
      totalRequests: 0,
      allowed: 0,
      denied: 0,
      restricted: 0,
      quarantine: 0
    };
    
    this.log('NAC', 'NetworkAccessControl инициализирован');
  }

  /**
   * Установить PDP
   */
  public setPdp(pdp: PolicyDecisionPoint): void {
    this.pdp = pdp;
    this.log('NAC', 'PDP установлен');
  }

  /**
   * Установить Device Posture Checker
   */
  public setPostureChecker(checker: DevicePostureChecker): void {
    this.postureChecker = checker;
    this.log('NAC', 'DevicePostureChecker установлен');
  }

  /**
   * Проверить доступ к сети
   */
  public async checkNetworkAccess(context: {
    identity: Identity;
    authContext: AuthContext;
    deviceId?: string;
    ipAddress: string;
    macAddress?: string;
    ssid?: string;
    connectionType?: 'WiFi' | 'Ethernet' | 'VPN' | 'Cellular';
    country?: string;
    city?: string;
  }): Promise<NetworkAccessResult> {
    const requestId = uuidv4();
    this.stats.totalRequests++;
    
    this.log('NAC', 'Проверка сетевого доступа', {
      requestId,
      identityId: context.identity.id,
      ipAddress: context.ipAddress
    });
    
    // Создаём полный контекст
    const accessContext = this.buildAccessContext(requestId, context);
    
    // Проверяем устройство если включено
    if (this.config.enableDevicePosture && context.deviceId && this.postureChecker) {
      try {
        accessContext.devicePosture = await this.postureChecker.checkDevicePosture(context.deviceId);
      } catch (error) {
        this.log('NAC', 'Ошибка проверки устройства', {
          requestId,
          deviceId: context.deviceId,
          error
        });
      }
    }
    
    // Вычисляем уровень доверия
    const trustLevel = this.calculateTrustLevel(accessContext);
    
    // Вычисляем оценку риска
    const riskScore = this.calculateRiskScore(accessContext);
    
    // Проверяем политики
    const result = this.evaluatePolicies(accessContext, trustLevel, riskScore);
    
    // Сохраняем сессию
    if (result.allowed) {
      this.activeSessions.set(requestId, result);
    }
    
    // Добавляем в историю
    this.addToHistory(accessContext, result);
    
    // Обновляем статистику
    this.updateStats(result);
    
    this.log('NAC', 'Решение о доступе принято', {
      requestId,
      allowed: result.allowed,
      accessType: result.accessType,
      trustLevel,
      riskScore
    });
    
    this.emit('access:decided', { requestId, result });
    
    return result;
  }

  /**
   * Построить контекст доступа
   */
  private buildAccessContext(
    requestId: string,
    context: {
      identity: Identity;
      authContext: AuthContext;
      deviceId?: string;
      ipAddress: string;
      macAddress?: string;
      ssid?: string;
      connectionType?: 'WiFi' | 'Ethernet' | 'VPN' | 'Cellular';
      country?: string;
      city?: string;
    }
  ): NetworkAccessContext {
    const now = new Date();
    
    return {
      requestId,
      identity: context.identity,
      authContext: context.authContext,
      network: {
        ipAddress: context.ipAddress,
        macAddress: context.macAddress,
        ssid: context.ssid,
        connectionType: context.connectionType ?? 'Ethernet',
        vlanId: undefined
      },
      location: {
        country: context.country ?? 'Unknown',
        city: context.city,
        coordinates: undefined,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      },
      temporal: {
        timestamp: now,
        dayOfWeek: now.getDay(),
        hourOfDay: now.getHours()
      }
    };
  }

  /**
   * Вычислить уровень доверия
   */
  private calculateTrustLevel(context: NetworkAccessContext): TrustLevel {
    let score = 0;
    
    // Фактор 1: Метод аутентификации (0-25)
    const authScores: Record<string, number> = {
      'MTLS': 25,
      'CERTIFICATE': 23,
      'WEBAUTHN': 23,
      'MFA': 20,
      'BIOMETRIC': 20,
      'OTP': 15,
      'OAUTH': 12,
      'JWT': 10,
      'API_KEY': 8,
      'PASSWORD': 5
    };
    score += authScores[context.authContext.method] ?? 0;
    
    // Бонус за MFA
    if (context.authContext.mfaVerified) {
      score += 10;
    }
    
    // Фактор 2: Устройство (0-25)
    if (context.devicePosture) {
      const postureScores: Record<DeviceHealthStatus, number> = {
        'HEALTHY': 25,
        'DEGRADED': 15,
        'NON_COMPLIANT': 5,
        'UNKNOWN': 0,
        'BLOCKED': 0
      };
      score += postureScores[context.devicePosture.healthStatus] ?? 0;
    }
    
    // Фактор 3: Местоположение (0-25)
    if (this.config.enableLocationCheck) {
      if (this.config.allowedCountries.length > 0) {
        if (this.config.allowedCountries.includes(context.location.country)) {
          score += 25;
        } else {
          score += 0;
        }
      } else if (this.config.deniedCountries.includes(context.location.country)) {
        score += 0;
      } else {
        score += 20;
      }
    } else {
      score += 15;
    }
    
    // Фактор 4: Время (0-15)
    if (this.config.enableTimeCheck) {
      const { startHour, endHour, allowedDays } = this.config.allowedTimeRange;
      const isAllowedTime = 
        context.temporal.hourOfDay >= startHour &&
        context.temporal.hourOfDay < endHour &&
        allowedDays.includes(context.temporal.dayOfWeek);
      
      score += isAllowedTime ? 15 : 5;
    } else {
      score += 10;
    }
    
    // Фактор 5: Сетевой контекст (0-10)
    if (context.network.connectionType === 'VPN') {
      score += 10;
    } else if (context.network.connectionType === 'Ethernet') {
      score += 8;
    } else if (context.network.connectionType === 'WiFi') {
      score += 5;
    } else {
      score += 3;
    }
    
    // Конвертируем score в TrustLevel (0-100 -> 0-5)
    return Math.min(5, Math.floor(score / 20)) as TrustLevel;
  }

  /**
   * Вычислить оценку риска
   */
  private calculateRiskScore(context: NetworkAccessContext): number {
    let risk = 0;
    
    // Риск от метода аутентификации
    const authRisks: Record<string, number> = {
      'PASSWORD': 30,
      'API_KEY': 20,
      'JWT': 15,
      'OAUTH': 10,
      'OTP': 10,
      'MFA': 5,
      'WEBAUTHN': 5,
      'BIOMETRIC': 5,
      'CERTIFICATE': 5,
      'MTLS': 0
    };
    risk += authRisks[context.authContext.method] ?? 20;
    
    // Риск от устройства
    if (context.devicePosture) {
      risk += context.devicePosture.riskScore / 3;
    }
    
    // Риск от местоположения
    if (this.config.deniedCountries.includes(context.location.country)) {
      risk += 40;
    }
    
    // Риск от времени
    if (this.config.enableTimeCheck) {
      const { startHour, endHour, allowedDays } = this.config.allowedTimeRange;
      const isOutsideAllowed = 
        context.temporal.hourOfDay < startHour ||
        context.temporal.hourOfDay >= endHour ||
        !allowedDays.includes(context.temporal.dayOfWeek);
      
      if (isOutsideAllowed) {
        risk += 15;
      }
    }
    
    // Риск от типа подключения
    if (context.network.connectionType === 'Cellular') {
      risk += 10;
    } else if (context.network.connectionType === 'WiFi') {
      risk += 5;
    }
    
    return Math.min(100, Math.round(risk));
  }

  /**
   * Оценить политики доступа
   */
  private evaluatePolicies(
    context: NetworkAccessContext,
    trustLevel: TrustLevel,
    riskScore: number
  ): NetworkAccessResult {
    const appliedPolicies: string[] = [];
    const restrictions: NetworkAccessResult['restrictions'] = {};
    
    // Проверка минимального уровня доверия
    if (trustLevel < this.config.minimumTrustLevel) {
      return {
        requestId: context.requestId,
        allowed: false,
        accessType: NetworkAccessType.DENY,
        trustLevel,
        riskScore,
        appliedPolicies: ['minimum_trust_level'],
        restrictions: {},
        reason: `Уровень доверия ${trustLevel} ниже минимального ${this.config.minimumTrustLevel}`
      };
    }
    
    // Проверка устройства
    if (this.config.enableDevicePosture && context.devicePosture) {
      const healthOrder = [
        DeviceHealthStatus.BLOCKED,
        DeviceHealthStatus.NON_COMPLIANT,
        DeviceHealthStatus.UNKNOWN,
        DeviceHealthStatus.DEGRADED,
        DeviceHealthStatus.HEALTHY
      ];
      
      const minHealthIndex = healthOrder.indexOf(this.config.minimumDeviceHealth);
      const currentHealthIndex = healthOrder.indexOf(context.devicePosture.healthStatus);
      
      if (currentHealthIndex < minHealthIndex) {
        return {
          requestId: context.requestId,
          allowed: false,
          accessType: NetworkAccessType.QUARANTINE,
          trustLevel,
          riskScore,
          appliedPolicies: ['device_health_requirement'],
          restrictions: {
            networkSegment: 'quarantine',
            vlanId: 999
          },
          reason: `Статус устройства ${context.devicePosture.healthStatus} не соответствует требованиям`
        };
      }
    }
    
    // Проверка местоположения
    if (this.config.enableLocationCheck) {
      if (this.config.deniedCountries.includes(context.location.country)) {
        return {
          requestId: context.requestId,
          allowed: false,
          accessType: NetworkAccessType.DENY,
          trustLevel,
          riskScore,
          appliedPolicies: ['geo_blocking'],
          restrictions: {},
          reason: `Доступ из страны ${context.location.country} запрещён`
        };
      }
      
      if (this.config.allowedCountries.length > 0 &&
          !this.config.allowedCountries.includes(context.location.country)) {
        return {
          requestId: context.requestId,
          allowed: false,
          accessType: NetworkAccessType.DENY,
          trustLevel,
          riskScore,
          appliedPolicies: ['geo_whitelist'],
          restrictions: {},
          reason: `Страна ${context.location.country} не в списке разрешённых`
        };
      }
    }
    
    // Проверка времени
    if (this.config.enableTimeCheck) {
      const { startHour, endHour, allowedDays } = this.config.allowedTimeRange;
      const isOutsideAllowed = 
        context.temporal.hourOfDay < startHour ||
        context.temporal.hourOfDay >= endHour ||
        !allowedDays.includes(context.temporal.dayOfWeek);
      
      if (isOutsideAllowed) {
        appliedPolicies.push('time_restriction');
        
        // Ограниченный доступ вне разрешённого времени
        restrictions.vlanId = 100;
        restrictions.networkSegment = 'restricted';
      }
    }
    
    // Определяем тип доступа на основе риска
    let accessType: NetworkAccessType;
    
    if (riskScore >= 80) {
      accessType = NetworkAccessType.QUARANTINE;
      restrictions.vlanId = 999;
      restrictions.networkSegment = 'quarantine';
      appliedPolicies.push('high_risk_quarantine');
    } else if (riskScore >= 50) {
      accessType = NetworkAccessType.RESTRICTED_ACCESS;
      restrictions.vlanId = 100;
      restrictions.networkSegment = 'restricted';
      restrictions.bandwidthLimit = 1000000; // 1 Mbps
      appliedPolicies.push('medium_risk_restriction');
    } else if (trustLevel >= TrustLevel.HIGH) {
      accessType = NetworkAccessType.FULL_ACCESS;
      appliedPolicies.push('high_trust_full_access');
    } else {
      accessType = NetworkAccessType.RESTRICTED_ACCESS;
      restrictions.vlanId = 10;
      appliedPolicies.push('standard_access');
    }
    
    return {
      requestId: context.requestId,
      allowed: accessType !== NetworkAccessType.DENY,
      accessType,
      trustLevel,
      riskScore,
      appliedPolicies,
      restrictions,
      reason: `Доступ разрешён: ${accessType}`
    };
  }

  /**
   * Добавить решение в историю
   */
  private addToHistory(context: NetworkAccessContext, result: NetworkAccessResult): void {
    this.decisionHistory.push({
      timestamp: new Date(),
      context,
      result
    });
    
    // Ограничиваем размер истории
    if (this.decisionHistory.length > 10000) {
      this.decisionHistory.splice(0, this.decisionHistory.length - 10000);
    }
  }

  /**
   * Обновить статистику
   */
  private updateStats(result: NetworkAccessResult): void {
    if (!result.allowed) {
      this.stats.denied++;
    } else {
      switch (result.accessType) {
        case NetworkAccessType.FULL_ACCESS:
          this.stats.allowed++;
          break;
        case NetworkAccessType.RESTRICTED_ACCESS:
        case NetworkAccessType.GATEWAY_ONLY:
          this.stats.restricted++;
          break;
        case NetworkAccessType.QUARANTINE:
          this.stats.quarantine++;
          break;
      }
    }
  }

  /**
   * Получить активную сессию
   */
  public getActiveSession(requestId: string): NetworkAccessResult | undefined {
    return this.activeSessions.get(requestId);
  }

  /**
   * Завершить сессию
   */
  public terminateSession(requestId: string): boolean {
    const removed = this.activeSessions.delete(requestId);
    
    if (removed) {
      this.log('NAC', 'Сессия завершена', { requestId });
      this.emit('session:terminated', { requestId });
    }
    
    return removed;
  }

  /**
   * Получить все активные сессии
   */
  public getActiveSessions(): NetworkAccessResult[] {
    return Array.from(this.activeSessions.values());
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats & {
    /** Активные сессии */
    activeSessions: number;
    /** Размер истории */
    historySize: number;
  } {
    return {
      ...this.stats,
      activeSessions: this.activeSessions.size,
      historySize: this.decisionHistory.length
    };
  }

  /**
   * Логирование
   */
  private log(component: string, message: string, data?: unknown): void {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'ACCESS_REQUEST',
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
      logger.debug(`[NAC] ${message}`, { timestamp: new Date().toISOString(), ...data });
    }
  }
}

export default NetworkAccessControl;
