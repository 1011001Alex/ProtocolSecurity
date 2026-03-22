/**
 * Trust Verifier - Непрерывная Верификация Доверия
 * 
 * Компонент реализует continuous trust verification - непрерывную
 * оценку и пере оценку уровня доверия к субъектам в реальном времени.
 * Использует поведенческий анализ, ML-детекцию аномалий и контекстную
 * оценку для динамического изменения уровня доверия.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  TrustLevel,
  Identity,
  AuthContext,
  DevicePosture,
  DeviceHealthStatus,
  ZeroTrustEvent,
  SubjectType,
  PolicyEvaluationResult
} from './zerotrust.types';
import { DevicePostureChecker } from './DevicePostureChecker';

/**
 * Типы событий доверия
 */
enum TrustEventType {
  /** Начальная верификация */
  INITIAL_VERIFICATION = 'INITIAL_VERIFICATION',
  
  /** Периодическая реверификация */
  PERIODIC_REVERIFICATION = 'PERIODIC_REVERIFICATION',
  
  /** Событие изменения контекста */
  CONTEXT_CHANGE = 'CONTEXT_CHANGE',
  
  /** Подозрительное событие */
  SUSPICIOUS_EVENT = 'SUSPICIOUS_EVENT',
  
  /** Изменение posture устройства */
  DEVICE_POSTURE_CHANGE = 'DEVICE_POSTURE_CHANGE',
  
  /** Аномальное поведение */
  ANOMALOUS_BEHAVIOR = 'ANOMALOUS_BEHAVIOR',
  
  /** Превышение порога риска */
  RISK_THRESHOLD_EXCEEDED = 'RISK_THRESHOLD_EXCEEDED',
  
  /** Step-up аутентификация */
  STEP_UP_AUTHENTICATION = 'STEP_UP_AUTHENTICATION',
  
  /** Сессия истекла */
  SESSION_EXPIRED = 'SESSION_EXPIRED'
}

/**
 * Контекст доверия субъекта
 */
interface TrustContext {
  /** Идентичность субъекта */
  identity: Identity;
  
  /** Контекст аутентификации */
  authContext: AuthContext;
  
  /** Posture устройства */
  devicePosture?: DevicePosture;
  
  /** История поведения */
  behaviorHistory: BehaviorEvent[];
  
  /** Текущий уровень доверия */
  currentTrustLevel: TrustLevel;
  
  /** Оценка риска (0-100) */
  riskScore: number;
  
  /** Время последней верификации */
  lastVerification: Date;
  
  /** Время следующей верификации */
  nextVerification: Date;
  
  /** Счётчик подозрительных событий */
  suspiciousEventCount: number;
  
  /** Флаги аномалий */
  anomalyFlags: string[];
  
  /** История изменений доверия */
  trustHistory: TrustChange[];
}

/**
 * Событие поведения
 */
interface BehaviorEvent {
  /** Тип события */
  type: string;
  
  /** Время события */
  timestamp: Date;
  
  /** Ресурс */
  resource?: string;
  
  /** Операция */
  operation?: string;
  
  /** Результат */
  result: 'SUCCESS' | 'FAILURE' | 'DENIED';
  
  /** Контекст */
  context: Record<string, unknown>;
}

/**
 * Изменение уровня доверия
 */
interface TrustChange {
  /** Время изменения */
  timestamp: Date;
  
  /** Предыдущий уровень */
  previousLevel: TrustLevel;
  
  /** Новый уровень */
  newLevel: TrustLevel;
  
  /** Причина изменения */
  reason: string;
  
  /** Факторы изменения */
  factors: string[];
}

/**
 * Конфигурация Trust Verifier
 */
export interface TrustVerifierConfig {
  /** Интервал периодической верификации (секунды) */
  verificationInterval: number;
  
  /** Максимальная длительность сессии (секунды) */
  maxSessionDuration: number;
  
  /** Порог risk score для понижения доверия */
  riskThresholdLow: number;
  
  /** Порог risk score для блокировки */
  riskThresholdHigh: number;
  
  /** Количество подозрительных событий для блокировки */
  suspiciousEventThreshold: number;
  
  /** Включить поведенческий анализ */
  enableBehavioralAnalysis: boolean;
  
  /** Окно анализа поведения (секунды) */
  behaviorAnalysisWindow: number;
  
  /** Включить ML-детекцию аномалий */
  enableAnomalyDetection: boolean;
  
  /** Порог аномалий */
  anomalyThreshold: number;
  
  /** Включить автоматическую step-up аутентификацию */
  enableStepUpAuth: boolean;
  
  /** Минимальный уровень доверия для step-up */
  stepUpTrustThreshold: TrustLevel;
  
  /** Включить непрерывный мониторинг */
  enableContinuousMonitoring: boolean;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
}

/**
 * Профиль поведения субъекта
 */
interface BehaviorProfile {
  /** ID субъекта */
  subjectId: string;
  
  /** Обычные часы активности */
  activeHours: number[];
  
  /** Обычные дни активности */
  activeDays: number[];
  
  /** Обычные IP адреса */
  commonIpAddresses: string[];
  
  /** Обычные устройства */
  commonDevices: string[];
  
  /** Обычные ресурсы */
  commonResources: string[];
  
  /** Средняя частота запросов */
  averageRequestRate: number;
  
  /** Время создания профиля */
  createdAt: Date;
  
  /** Время последнего обновления */
  updatedAt: Date;
}

/**
 * Trust Verifier
 * 
 * Компонент для непрерывной верификации доверия к субъектам.
 */
export class TrustVerifier extends EventEmitter {
  /** Конфигурация */
  private config: TrustVerifierConfig;
  
  /** Контексты доверия по session ID */
  private trustContexts: Map<string, TrustContext>;
  
  /** Профили поведения по subject ID */
  private behaviorProfiles: Map<string, BehaviorProfile>;
  
  /** Device Posture Checker */
  private postureChecker: DevicePostureChecker | null;
  
  /** Таймеры верификации */
  private verificationTimers: Map<string, NodeJS.Timeout>;
  
  /** Таймеры истечения сессий */
  private sessionTimers: Map<string, NodeJS.Timeout>;
  
  /** Статистика */
  private stats: {
    /** Всего верификаций */
    totalVerifications: number;
    /** Повышений доверия */
    trustIncreases: number;
    /** Понижений доверия */
    trustDecreases: number;
    /** Step-up аутентификаций */
    stepUpAuths: number;
    /** Блокировок */
    blocks: number;
    /** Аномалий обнаружено */
    anomaliesDetected: number;
  };

  constructor(config: Partial<TrustVerifierConfig> = {}) {
    super();
    
    this.config = {
      verificationInterval: config.verificationInterval ?? 300, // 5 минут
      maxSessionDuration: config.maxSessionDuration ?? 28800, // 8 часов
      riskThresholdLow: config.riskThresholdLow ?? 50,
      riskThresholdHigh: config.riskThresholdHigh ?? 80,
      suspiciousEventThreshold: config.suspiciousEventThreshold ?? 5,
      enableBehavioralAnalysis: config.enableBehavioralAnalysis ?? true,
      behaviorAnalysisWindow: config.behaviorAnalysisWindow ?? 3600, // 1 час
      enableAnomalyDetection: config.enableAnomalyDetection ?? true,
      anomalyThreshold: config.anomalyThreshold ?? 0.7,
      enableStepUpAuth: config.enableStepUpAuth ?? true,
      stepUpTrustThreshold: config.stepUpTrustThreshold ?? TrustLevel.MEDIUM,
      enableContinuousMonitoring: config.enableContinuousMonitoring ?? true,
      enableVerboseLogging: config.enableVerboseLogging ?? false
    };
    
    this.trustContexts = new Map();
    this.behaviorProfiles = new Map();
    this.postureChecker = null;
    this.verificationTimers = new Map();
    this.sessionTimers = new Map();
    
    this.stats = {
      totalVerifications: 0,
      trustIncreases: 0,
      trustDecreases: 0,
      stepUpAuths: 0,
      blocks: 0,
      anomaliesDetected: 0
    };
    
    this.log('TV', 'TrustVerifier инициализирован');
  }

  /**
   * Установить Device Posture Checker
   */
  public setPostureChecker(checker: DevicePostureChecker): void {
    this.postureChecker = checker;
    
    // Подписываемся на события posture
    checker.on('posture:degraded', (data: { deviceId: string; posture: DevicePosture }) => {
      this.handlePostureChange(data.deviceId, data.posture);
    });
    
    this.log('TV', 'DevicePostureChecker установлен');
  }

  /**
   * Инициализировать доверие для новой сессии
   */
  public async initializeTrust(
    sessionId: string,
    identity: Identity,
    authContext: AuthContext,
    devicePosture?: DevicePosture
  ): Promise<TrustLevel> {
    this.log('TV', 'Инициализация доверия', {
      sessionId,
      subjectId: identity.id,
      authMethod: authContext.method
    });
    
    // Создаём контекст доверия
    const now = new Date();
    const context: TrustContext = {
      identity,
      authContext,
      devicePosture,
      behaviorHistory: [],
      currentTrustLevel: this.calculateInitialTrustLevel(authContext, devicePosture),
      riskScore: this.calculateInitialRiskScore(authContext, devicePosture),
      lastVerification: now,
      nextVerification: new Date(now.getTime() + this.config.verificationInterval * 1000),
      suspiciousEventCount: 0,
      anomalyFlags: [],
      trustHistory: [{
        timestamp: now,
        previousLevel: TrustLevel.UNTRUSTED,
        newLevel: this.calculateInitialTrustLevel(authContext, devicePosture),
        reason: 'Initial trust establishment',
        factors: ['authentication', 'device_posture']
      }]
    };
    
    this.trustContexts.set(sessionId, context);
    
    // Запускаем таймеры
    this.startVerificationTimer(sessionId);
    this.startSessionTimer(sessionId);
    
    // Загружаем или создаём профиль поведения
    await this.loadBehaviorProfile(identity.id);
    
    // Эмитим событие
    this.emit('trust:initialized', {
      sessionId,
      trustLevel: context.currentTrustLevel,
      riskScore: context.riskScore
    });
    
    this.log('TV', 'Доверие инициализировано', {
      sessionId,
      trustLevel: context.currentTrustLevel,
      riskScore: context.riskScore
    });
    
    return context.currentTrustLevel;
  }

  /**
   * Вычислить начальный уровень доверия
   */
  private calculateInitialTrustLevel(
    authContext: AuthContext,
    devicePosture?: DevicePosture
  ): TrustLevel {
    let score = 0;
    
    // Базовый score от метода аутентификации
    const authScores: Record<string, number> = {
      'MTLS': 5,
      'CERTIFICATE': 5,
      'WEBAUTHN': 5,
      'MFA': 4,
      'BIOMETRIC': 4,
      'OTP': 3,
      'OAUTH': 3,
      'JWT': 2,
      'API_KEY': 2,
      'PASSWORD': 1
    };
    score += authScores[authContext.method] ?? 0;
    
    // Бонус за MFA
    if (authContext.mfaVerified) {
      score += 1;
    }
    
    // Бонус за множественные факторы
    if (authContext.factors.length > 1) {
      score += 1;
    }
    
    // Device posture bonus
    if (devicePosture) {
      const postureScores: Record<DeviceHealthStatus, number> = {
        'HEALTHY': 2,
        'DEGRADED': 1,
        'NON_COMPLIANT': 0,
        'UNKNOWN': 0,
        'BLOCKED': 0
      };
      score += postureScores[devicePosture.healthStatus] ?? 0;
    }
    
    // Конвертируем score в TrustLevel (0-10 -> 0-5)
    return Math.min(5, Math.floor(score / 2)) as TrustLevel;
  }

  /**
   * Вычислить начальный риск
   */
  private calculateInitialRiskScore(
    authContext: AuthContext,
    devicePosture?: DevicePosture
  ): number {
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
    risk += authRisks[authContext.method] ?? 20;
    
    // Риск от устройства
    if (devicePosture) {
      risk += devicePosture.riskScore / 5; // Нормализуем 0-100 -> 0-20
    }
    
    return Math.min(100, risk);
  }

  /**
   * Верифицировать доверие сессии
   */
  public async verifyTrust(sessionId: string): Promise<{
    trustLevel: TrustLevel;
    riskScore: number;
    requiresStepUp: boolean;
    shouldBlock: boolean;
  }> {
    const context = this.trustContexts.get(sessionId);
    
    if (!context) {
      throw new Error(`Сессия не найдена: ${sessionId}`);
    }
    
    this.stats.totalVerifications++;
    
    this.log('TV', 'Верификация доверия', { sessionId });
    
    // Обновляем posture устройства
    if (this.postureChecker && context.devicePosture) {
      try {
        context.devicePosture = await this.postureChecker.checkDevicePosture(
          context.devicePosture.deviceId,
          true
        );
      } catch (error) {
        this.log('TV', 'Ошибка обновления posture', {
          sessionId,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
    
    // Пересчитываем риск
    const previousRisk = context.riskScore;
    context.riskScore = this.calculateCurrentRiskScore(context);
    
    // Анализируем поведение
    if (this.config.enableBehavioralAnalysis) {
      const behaviorRisk = this.analyzeBehavior(context);
      context.riskScore = Math.min(100, context.riskScore + behaviorRisk);
    }
    
    // Проверяем аномалии
    if (this.config.enableAnomalyDetection) {
      const anomalies = this.detectAnomalies(context);
      if (anomalies.length > 0) {
        context.anomalyFlags.push(...anomalies);
        context.riskScore = Math.min(100, context.riskScore + anomalies.length * 10);
        this.stats.anomaliesDetected += anomalies.length;
      }
    }
    
    // Определяем новый уровень доверия
    const previousTrust = context.currentTrustLevel;
    const newTrust = this.calculateTrustFromRisk(context.riskScore, context.authContext);
    
    // Обновляем историю доверия если изменилось
    if (newTrust !== previousTrust) {
      context.currentTrustLevel = newTrust;
      context.trustHistory.push({
        timestamp: new Date(),
        previousLevel: previousTrust,
        newLevel: newTrust,
        reason: this.getTrustChangeReason(previousTrust, newTrust, context),
        factors: context.anomalyFlags
      });
      
      if (newTrust > previousTrust) {
        this.stats.trustIncreases++;
      } else {
        this.stats.trustDecreases++;
      }
    }
    
    // Обновляем время верификации
    context.lastVerification = new Date();
    context.nextVerification = new Date(
      Date.now() + this.config.verificationInterval * 1000
    );
    
    // Проверяем необходимость step-up аутентификации
    const requiresStepUp = this.config.enableStepUpAuth && 
      newTrust < this.config.stepUpTrustThreshold &&
      newTrust > TrustLevel.UNTRUSTED;
    
    // Проверяем необходимость блокировки
    const shouldBlock = 
      context.riskScore >= this.config.riskThresholdHigh ||
      context.suspiciousEventCount >= this.config.suspiciousEventThreshold ||
      newTrust === TrustLevel.UNTRUSTED;
    
    if (shouldBlock) {
      this.stats.blocks++;
      this.emit('trust:blocked', {
        sessionId,
        reason: 'Risk threshold exceeded',
        riskScore: context.riskScore,
        trustLevel: newTrust
      });
    }
    
    if (requiresStepUp) {
      this.stats.stepUpAuths++;
      this.emit('trust:stepup_required', {
        sessionId,
        currentTrust: newTrust,
        requiredTrust: this.config.stepUpTrustThreshold
      });
    }
    
    // Эмитим событие верификации
    this.emit('trust:verified', {
      sessionId,
      trustLevel: newTrust,
      riskScore: context.riskScore,
      requiresStepUp,
      shouldBlock,
      anomalyFlags: context.anomalyFlags
    });
    
    this.log('TV', 'Верификация завершена', {
      sessionId,
      trustLevel: newTrust,
      riskScore: context.riskScore,
      requiresStepUp,
      shouldBlock
    });
    
    return {
      trustLevel: newTrust,
      riskScore: context.riskScore,
      requiresStepUp,
      shouldBlock
    };
  }

  /**
   * Вычислить текущий риск
   */
  private calculateCurrentRiskScore(context: TrustContext): number {
    let risk = 0;
    
    // Риск от posture устройства
    if (context.devicePosture) {
      risk += context.devicePosture.riskScore / 3; // 0-33
    }
    
    // Риск от возраста сессии
    const sessionAge = Date.now() - context.authContext.authenticatedAt.getTime();
    const maxSessionAge = this.config.maxSessionDuration * 1000;
    risk += (sessionAge / maxSessionAge) * 20; // 0-20
    
    // Риск от подозрительных событий
    risk += context.suspiciousEventCount * 5; // 0-25+
    
    // Риск от истечения времени верификации
    const timeSinceVerification = Date.now() - context.lastVerification.getTime();
    if (timeSinceVerification > this.config.verificationInterval * 1000) {
      risk += 10;
    }
    
    return Math.min(100, risk);
  }

  /**
   * Анализ поведения
   */
  private analyzeBehavior(context: TrustContext): number {
    let riskAdd = 0;
    const recentEvents = context.behaviorHistory.filter(
      e => Date.now() - e.timestamp.getTime() < this.config.behaviorAnalysisWindow * 1000
    );
    
    // Профиль поведения
    const profile = this.behaviorProfiles.get(context.identity.id);
    
    if (profile) {
      // Проверяем необычное время
      const currentHour = new Date().getHours();
      if (!profile.activeHours.includes(currentHour)) {
        riskAdd += 10;
      }
      
      // Проверяем необычный день
      const currentDay = new Date().getDay();
      if (!profile.activeDays.includes(currentDay)) {
        riskAdd += 5;
      }
      
      // Проверяем частоту запросов
      const recentFailureCount = recentEvents.filter(e => e.result === 'FAILURE').length;
      const failureRate = recentEvents.length > 0 ? recentFailureCount / recentEvents.length : 0;
      
      if (failureRate > 0.3) {
        riskAdd += 15;
      }
    }
    
    return riskAdd;
  }

  /**
   * Детекция аномалий
   */
  private detectAnomalies(context: TrustContext): string[] {
    const anomalies: string[] = [];
    const profile = this.behaviorProfiles.get(context.identity.id);
    
    if (!profile) {
      return anomalies;
    }
    
    // Проверяем IP адрес
    // (в реальной реализации здесь была бы проверка по истории)
    
    // Проверяем устройство
    // (проверка device fingerprint)
    
    // Проверяем географию
    // (проверка location на невозможные перемещения)
    
    return anomalies;
  }

  /**
   * Вычислить уровень доверия из риска
   */
  private calculateTrustFromRisk(riskScore: number, authContext: AuthContext): TrustLevel {
    // Базовый уровень от риска
    let trustLevel: TrustLevel;
    
    if (riskScore >= this.config.riskThresholdHigh) {
      trustLevel = TrustLevel.UNTRUSTED;
    } else if (riskScore >= this.config.riskThresholdLow) {
      trustLevel = TrustLevel.LOW;
    } else if (riskScore >= 30) {
      trustLevel = TrustLevel.MEDIUM;
    } else if (riskScore >= 15) {
      trustLevel = TrustLevel.HIGH;
    } else {
      trustLevel = TrustLevel.FULL;
    }
    
    // Ограничиваем максимальный уровень методом аутентификации
    const maxTrustFromAuth: Record<string, TrustLevel> = {
      'PASSWORD': TrustLevel.MEDIUM,
      'API_KEY': TrustLevel.MEDIUM,
      'JWT': TrustLevel.HIGH,
      'OAUTH': TrustLevel.HIGH,
      'OTP': TrustLevel.HIGH,
      'MFA': TrustLevel.FULL,
      'WEBAUTHN': TrustLevel.FULL,
      'BIOMETRIC': TrustLevel.FULL,
      'CERTIFICATE': TrustLevel.FULL,
      'MTLS': TrustLevel.FULL
    };
    
    const maxTrust = maxTrustFromAuth[authContext.method] ?? TrustLevel.MEDIUM;
    
    return Math.min(trustLevel, maxTrust) as TrustLevel;
  }

  /**
   * Получить причину изменения доверия
   */
  private getTrustChangeReason(
    previous: TrustLevel,
    current: TrustLevel,
    context: TrustContext
  ): string {
    if (current < previous) {
      if (context.anomalyFlags.length > 0) {
        return `Обнаружены аномалии: ${context.anomalyFlags.join(', ')}`;
      }
      if (context.riskScore >= this.config.riskThresholdHigh) {
        return 'Превышен порог риска';
      }
      if (context.suspiciousEventCount >= this.config.suspiciousEventThreshold) {
        return 'Превышен лимит подозрительных событий';
      }
      return 'Снижение уровня доверия';
    }
    
    return 'Повышение уровня доверия';
  }

  /**
   * Записать событие поведения
   */
  public recordBehaviorEvent(
    sessionId: string,
    event: Omit<BehaviorEvent, 'timestamp'>
  ): void {
    const context = this.trustContexts.get(sessionId);
    
    if (!context) {
      return;
    }
    
    const behaviorEvent: BehaviorEvent = {
      ...event,
      timestamp: new Date()
    };
    
    context.behaviorHistory.push(behaviorEvent);
    
    // Ограничиваем размер истории
    const maxHistorySize = 1000;
    if (context.behaviorHistory.length > maxHistorySize) {
      context.behaviorHistory.splice(0, context.behaviorHistory.length - maxHistorySize);
    }
    
    // Обновляем профиль поведения
    this.updateBehaviorProfile(context.identity.id, behaviorEvent);
    
    // Проверяем на подозрительность
    if (this.isSuspiciousEvent(behaviorEvent)) {
      context.suspiciousEventCount++;
      this.emit('trust:suspicious_event', {
        sessionId,
        event: behaviorEvent,
        suspiciousCount: context.suspiciousEventCount
      });
    }
  }

  /**
   * Проверить событие на подозрительность
   */
  private isSuspiciousEvent(event: BehaviorEvent): boolean {
    // Подозрительные паттерны
    const suspiciousPatterns = [
      event.result === 'FAILURE' && event.type === 'AUTHENTICATION',
      event.result === 'DENIED' && event.operation === 'ADMIN',
      event.type === 'DATA_ACCESS' && event.context['volume'] && 
        (event.context['volume'] as number) > 1000000 // 1MB
    ];
    
    return suspiciousPatterns.some(p => p);
  }

  /**
   * Загрузить профиль поведения
   */
  private async loadBehaviorProfile(subjectId: string): Promise<BehaviorProfile> {
    let profile = this.behaviorProfiles.get(subjectId);
    
    if (!profile) {
      // Создаём новый профиль
      const now = new Date();
      profile = {
        subjectId,
        activeHours: [9, 10, 11, 12, 13, 14, 15, 16, 17, 18], // 9-18 часов
        activeDays: [1, 2, 3, 4, 5], // Пн-Пт
        commonIpAddresses: [],
        commonDevices: [],
        commonResources: [],
        averageRequestRate: 0,
        createdAt: now,
        updatedAt: now
      };
      
      this.behaviorProfiles.set(subjectId, profile);
    }
    
    return profile;
  }

  /**
   * Обновить профиль поведения
   */
  private updateBehaviorProfile(subjectId: string, event: BehaviorEvent): void {
    const profile = this.behaviorProfiles.get(subjectId);
    
    if (!profile) {
      return;
    }
    
    profile.updatedAt = new Date();
    
    // Обновляем активные часы
    const hour = event.timestamp.getHours();
    if (!profile.activeHours.includes(hour)) {
      profile.activeHours.push(hour);
    }
    
    // Обновляем активные дни
    const day = event.timestamp.getDay();
    if (!profile.activeDays.includes(day)) {
      profile.activeDays.push(day);
    }
  }

  /**
   * Обработать изменение posture устройства
   */
  private handlePostureChange(deviceId: string, posture: DevicePosture): void {
    this.log('TV', 'Изменение posture устройства', {
      deviceId,
      healthStatus: posture.healthStatus,
      riskScore: posture.riskScore
    });
    
    // Находим все сессии с этим устройством
    for (const [sessionId, context] of this.trustContexts.entries()) {
      if (context.devicePosture?.deviceId === deviceId) {
        context.devicePosture = posture;
        
        // Пересчитываем доверие
        this.verifyTrust(sessionId).catch(error => {
          this.log('TV', 'Ошибка пересчёта доверия', { sessionId, error });
        });
      }
    }
    
    this.emit('trust:posture_change', { deviceId, posture });
  }

  /**
   * Запустить таймер верификации
   */
  private startVerificationTimer(sessionId: string): void {
    const timer = setInterval(() => {
      this.verifyTrust(sessionId).catch(error => {
        this.log('TV', 'Ошибка периодической верификации', { sessionId, error });
      });
    }, this.config.verificationInterval * 1000);
    
    this.verificationTimers.set(sessionId, timer);
  }

  /**
   * Запустить таймер сессии
   */
  private startSessionTimer(sessionId: string): void {
    const timer = setTimeout(() => {
      this.expireSession(sessionId);
    }, this.config.maxSessionDuration * 1000);
    
    this.sessionTimers.set(sessionId, timer);
  }

  /**
   * Истечь сессию
   */
  private expireSession(sessionId: string): void {
    const context = this.trustContexts.get(sessionId);
    
    if (context) {
      context.currentTrustLevel = TrustLevel.UNTRUSTED;
      context.trustHistory.push({
        timestamp: new Date(),
        previousLevel: context.trustHistory[context.trustHistory.length - 1]?.newLevel ?? TrustLevel.UNTRUSTED,
        newLevel: TrustLevel.UNTRUSTED,
        reason: 'Session expired',
        factors: ['timeout']
      });
    }
    
    this.emit('trust:expired', { sessionId });
    this.log('TV', 'Сессия истекла', { sessionId });
    
    // Очищаем таймеры
    this.cleanupSession(sessionId);
  }

  /**
   * Очистить сессию
   */
  public cleanupSession(sessionId: string): void {
    // Останавливаем таймеры
    const verificationTimer = this.verificationTimers.get(sessionId);
    if (verificationTimer) {
      clearInterval(verificationTimer);
      this.verificationTimers.delete(sessionId);
    }
    
    const sessionTimer = this.sessionTimers.get(sessionId);
    if (sessionTimer) {
      clearTimeout(sessionTimer);
      this.sessionTimers.delete(sessionId);
    }
    
    // Удаляем контекст
    this.trustContexts.delete(sessionId);
    
    this.log('TV', 'Сессия очищена', { sessionId });
  }

  /**
   * Получить контекст доверия
   */
  public getTrustContext(sessionId: string): TrustContext | undefined {
    return this.trustContexts.get(sessionId);
  }

  /**
   * Получить текущий уровень доверия
   */
  public getTrustLevel(sessionId: string): TrustLevel {
    const context = this.trustContexts.get(sessionId);
    return context?.currentTrustLevel ?? TrustLevel.UNTRUSTED;
  }

  /**
   * Получить оценку риска
   */
  public getRiskScore(sessionId: string): number {
    const context = this.trustContexts.get(sessionId);
    return context?.riskScore ?? 100;
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats & {
    /** Активные сессии */
    activeSessions: number;
    /** Профилей поведения */
    behaviorProfiles: number;
  } {
    return {
      ...this.stats,
      activeSessions: this.trustContexts.size,
      behaviorProfiles: this.behaviorProfiles.size
    };
  }

  /**
   * Логирование
   */
  private log(component: string, message: string, data?: unknown): void {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'TRUST_LEVEL_CHANGED',
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
      console.log(`[TV] ${new Date().toISOString()} - ${message}`, data ?? '');
    }
  }
}

export default TrustVerifier;
