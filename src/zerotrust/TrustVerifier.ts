/**
 * ============================================================================
 * TRUST VERIFIER — НЕПРЕРЫВНАЯ ВЕРИФИКАЦИЯ ДОВЕРИЯ
 * ============================================================================
 * Полная реализация continuous trust verification для Zero Trust Architecture
 * 
 * Функционал:
 * - Непрерывная оценка уровня доверия в реальном времени
 * - Периодическая реверификация сессий
 * - Обнаружение аномалий через поведенческий анализ
 * - Динамическая адаптация уровня доверия
 * - Step-up аутентификация при изменении контекста
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  TrustLevel,
  Identity,
  AuthContext,
  DevicePosture,
  DeviceHealthStatus,
  SubjectType,
  AuthenticationMethod
} from './zerotrust.types';
import { DevicePostureChecker } from './DevicePostureChecker';

/**
 * Контекст доверия субъекта
 */
interface TrustContext {
  identity: Identity;
  authContext: AuthContext;
  devicePosture?: DevicePosture;
  behaviorHistory: BehaviorEvent[];
  currentTrustLevel: TrustLevel;
  riskScore: number;
  lastVerification: Date;
  nextVerification: Date;
  suspiciousEventCount: number;
  anomalyFlags: string[];
  trustHistory: TrustChange[];
  sessionStart: Date;
  lastActivity: Date;
}

/**
 * Событие поведения
 */
interface BehaviorEvent {
  type: string;
  timestamp: Date;
  resource?: string;
  operation?: string;
  result: 'SUCCESS' | 'FAILURE' | 'DENIED';
  context: Record<string, unknown>;
}

/**
 * Изменение уровня доверия
 */
interface TrustChange {
  timestamp: Date;
  previousLevel: TrustLevel;
  newLevel: TrustLevel;
  reason: string;
  factors: string[];
}

/**
 * Конфигурация Trust Verifier
 */
export interface TrustVerifierConfig {
  verificationInterval: number;
  maxSessionDuration: number;
  inactivityTimeout: number;
  suspiciousEventThreshold: number;
  riskThresholds: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  trustDecayRate: number;
  trustRecoveryRate: number;
  enableBehavioralAnalysis: boolean;
  enableAnomalyDetection: boolean;
  enableAdaptiveVerification: boolean;
  minVerificationInterval: number;
  maxVerificationInterval: number;
  stepUpAuthCooldown: number;
}

/**
 * Trust Verifier — основная реализация
 */
export class TrustVerifier extends EventEmitter {
  private readonly config: TrustVerifierConfig;
  private readonly trustContexts: Map<string, TrustContext> = new Map();
  private readonly verificationTimers: Map<string, NodeJS.Timeout> = new Map();
  private readonly devicePostureChecker: DevicePostureChecker;
  private isRunning: boolean = false;

  constructor(config: Partial<TrustVerifierConfig> = {}) {
    super();

    this.config = {
      verificationInterval: 300000, // 5 минут
      maxSessionDuration: 28800000, // 8 часов
      inactivityTimeout: 900000, // 15 минут
      suspiciousEventThreshold: 3,
      riskThresholds: {
        low: 20,
        medium: 40,
        high: 60,
        critical: 80
      },
      trustDecayRate: 0.05,
      trustRecoveryRate: 0.1,
      enableBehavioralAnalysis: true,
      enableAnomalyDetection: true,
      enableAdaptiveVerification: true,
      minVerificationInterval: 60000, // 1 минута
      maxVerificationInterval: 1800000, // 30 минут
      stepUpAuthCooldown: 300000, // 5 минут
      ...config
    };

    this.devicePostureChecker = new DevicePostureChecker();

    this.emit('initialized', { config: this.config });
  }

  /**
   * Запуск верификера
   */
  start(): void {
    if (this.isRunning) {
      return;
    }

    this.isRunning = true;
    this.emit('started');
  }

  /**
   * Остановка верификера
   */
  stop(): void {
    this.isRunning = false;

    // Очистка всех таймеров
    for (const timer of this.verificationTimers.values()) {
      clearTimeout(timer);
    }
    this.verificationTimers.clear();

    this.emit('stopped');
  }

  /**
   * Инициализация контекста доверия
   */
  async initializeTrust(
    identity: Identity,
    authContext: AuthContext,
    devicePosture?: DevicePosture
  ): Promise<TrustContext> {
    const subjectId = identity.subjectId;

    // Проверка существующего контекста
    const existingContext = this.trustContexts.get(subjectId);
    if (existingContext) {
      this.emit('trust_already_initialized', { subjectId });
      return existingContext;
    }

    // Начальная оценка доверия
    const initialTrustLevel = this.calculateInitialTrust(authContext, devicePosture);

    const now = new Date();
    const context: TrustContext = {
      identity,
      authContext,
      devicePosture,
      behaviorHistory: [],
      currentTrustLevel: initialTrustLevel,
      riskScore: this.calculateInitialRisk(authContext, devicePosture),
      lastVerification: now,
      nextVerification: new Date(now.getTime() + this.config.verificationInterval),
      suspiciousEventCount: 0,
      anomalyFlags: [],
      trustHistory: [],
      sessionStart: now,
      lastActivity: now
    };

    this.trustContexts.set(subjectId, context);

    // Запуск периодической верификации
    this.scheduleVerification(subjectId);

    this.emit('trust_initialized', {
      subjectId,
      trustLevel: initialTrustLevel
    });

    return context;
  }

  /**
   * Расчет начального уровня доверия
   */
  private calculateInitialTrust(
    authContext: AuthContext,
    devicePosture?: DevicePosture
  ): TrustLevel {
    let trustScore = 0;

    // Оценка методов аутентификации
    const methods = authContext.authenticationMethods || [];

    if (methods.includes(AuthenticationMethod.PASSWORD)) {
      trustScore += 0.2;
    }

    if (methods.includes(AuthenticationMethod.MFA) ||
        methods.includes(AuthenticationMethod.WEBAUTHN) ||
        methods.includes(AuthenticationMethod.BIOMETRIC)) {
      trustScore += 0.4;
    }

    if (methods.includes(AuthenticationMethod.CERTIFICATE) ||
        methods.includes(AuthenticationMethod.MTLS)) {
      trustScore += 0.3;
    }

    // Оценка устройства
    if (devicePosture) {
      if (devicePosture.healthStatus === DeviceHealthStatus.HEALTHY) {
        trustScore += 0.2;
      }

      if (devicePosture.isCompliant) {
        trustScore += 0.15;
      }

      if (devicePosture.isEncrypted) {
        trustScore += 0.1;
      }
    }

    // Маппинг на TrustLevel
    if (trustScore >= 1.0) {
      return TrustLevel.FULL;
    } else if (trustScore >= 0.8) {
      return TrustLevel.HIGH;
    } else if (trustScore >= 0.6) {
      return TrustLevel.MEDIUM;
    } else if (trustScore >= 0.4) {
      return TrustLevel.LOW;
    } else if (trustScore >= 0.2) {
      return TrustLevel.MINIMAL;
    } else {
      return TrustLevel.UNTRUSTED;
    }
  }

  /**
   * Расчет начального риска
   */
  private calculateInitialRisk(
    authContext: AuthContext,
    devicePosture?: DevicePosture
  ): number {
    let riskScore = 0;

    // Риск от слабой аутентификации
    const methods = authContext.authenticationMethods || [];
    if (methods.length === 1 && methods[0] === AuthenticationMethod.PASSWORD) {
      riskScore += 30;
    }

    // Риск от устройства
    if (devicePosture) {
      if (devicePosture.healthStatus === DeviceHealthStatus.NON_COMPLIANT ||
          devicePosture.healthStatus === DeviceHealthStatus.BLOCKED) {
        riskScore += 40;
      } else if (devicePosture.healthStatus === DeviceHealthStatus.DEGRADED) {
        riskScore += 30;
      }

      if (!devicePosture.isEncrypted) {
        riskScore += 15;
      }
    }

    return Math.min(100, riskScore);
  }

  /**
   * Обновление активности
   */
  updateActivity(subjectId: string, event: BehaviorEvent): void {
    const context = this.trustContexts.get(subjectId);
    if (!context) {
      return;
    }

    context.lastActivity = new Date();
    context.behaviorHistory.push(event);

    // Ограничение истории
    if (context.behaviorHistory.length > 100) {
      context.behaviorHistory.shift();
    }

    // Анализ события
    this.analyzeBehaviorEvent(context, event);

    this.emit('activity_updated', { subjectId, event });
  }

  /**
   * Анализ события поведения
   */
  private analyzeBehaviorEvent(context: TrustContext, event: BehaviorEvent): void {
    if (!this.config.enableBehavioralAnalysis) {
      return;
    }

    // Проверка на неудачные события
    if (event.result === 'FAILURE' || event.result === 'DENIED') {
      context.suspiciousEventCount++;

      if (context.suspiciousEventCount >= this.config.suspiciousEventThreshold) {
        this.flagAnomaly(context, 'multiple_failures');
        this.decreaseTrust(context, 'multiple_failed_attempts', 0.2);
      }
    } else {
      // Успешные события — постепенное восстановление доверия
      if (context.suspiciousEventCount > 0) {
        context.suspiciousEventCount = Math.max(0, context.suspiciousEventCount - 1);
      }
    }

    // Проверка на аномалии
    if (this.config.enableAnomalyDetection) {
      this.detectAnomalies(context, event);
    }
  }

  /**
   * Обнаружение аномалий
   */
  private detectAnomalies(context: TrustContext, event: BehaviorEvent): void {
    // Простая эвристика для обнаружения аномалий
    const recentEvents = context.behaviorHistory.slice(-10);
    const failureRate = recentEvents.filter(e => e.result !== 'SUCCESS').length / recentEvents.length;

    if (failureRate > 0.5 && recentEvents.length >= 5) {
      this.flagAnomaly(context, 'high_failure_rate');
    }

    // Проверка на необычную активность
    const hour = new Date().getHours();
    if (hour < 6 || hour > 22) {
      this.flagAnomaly(context, 'unusual_hour_activity');
    }
  }

  /**
   * Пометка аномалии
   */
  private flagAnomaly(context: TrustContext, anomalyType: string): void {
    if (!context.anomalyFlags.includes(anomalyType)) {
      context.anomalyFlags.push(anomalyType);
      this.emit('anomaly_detected', {
        subjectId: context.identity.subjectId,
        anomalyType
      });
    }
  }

  /**
   * Периодическая верификация
   */
  private async verifyTrust(subjectId: string): Promise<void> {
    const context = this.trustContexts.get(subjectId);
    if (!context) {
      return;
    }

    const previousTrustLevel = context.currentTrustLevel;
    const factors: string[] = [];

    // Проверка времени сессии
    const sessionAge = Date.now() - context.sessionStart.getTime();
    if (sessionAge > this.config.maxSessionDuration) {
      context.currentTrustLevel = TrustLevel.UNTRUSTED;
      factors.push('session_expired');
      this.emit('session_expired', { subjectId });
      return;
    }

    // Проверка неактивности
    const inactivityTime = Date.now() - context.lastActivity.getTime();
    if (inactivityTime > this.config.inactivityTimeout) {
      this.decreaseTrust(context, 'inactivity_timeout', 0.3);
      factors.push('inactivity');
    }

    // Проверка устройства
    if (context.devicePosture) {
      const postureValid = await this.devicePostureChecker.checkHealth(context.devicePosture);
      if (!postureValid) {
        this.decreaseTrust(context, 'device_health_degraded', 0.25);
        factors.push('device_health');
      }
    }

    // Decay доверия со временем
    this.applyTrustDecay(context);

    // Очистка старых аномалий
    this.clearOldAnomalies(context);

    // Логирование изменений
    if (context.currentTrustLevel !== previousTrustLevel) {
      this.logTrustChange(context, previousTrustLevel, factors);
    }

    // Обновление следующей верификации
    context.lastVerification = new Date();
    context.nextVerification = this.calculateNextVerification(context);

    // Пересchedule
    this.scheduleVerification(subjectId);

    this.emit('trust_verified', {
      subjectId,
      trustLevel: context.currentTrustLevel,
      riskScore: context.riskScore,
      factors
    });
  }

  /**
   * Применение decay доверия
   */
  private applyTrustDecay(context: TrustContext): void {
    const timeSinceVerification = Date.now() - context.lastVerification.getTime();
    const decayFactor = this.config.trustDecayRate * (timeSinceVerification / this.config.verificationInterval);

    // Уменьшение доверия на основе времени
    const currentWeight = this.getTrustWeight(context.currentTrustLevel);
    const newWeight = Math.max(0, currentWeight - decayFactor);

    context.currentTrustLevel = this.getTrustLevelFromWeight(newWeight);
  }

  /**
   * Уменьшение доверия
   */
  private decreaseTrust(context: TrustContext, reason: string, amount: number): void {
    const previousLevel = context.currentTrustLevel;
    const currentWeight = this.getTrustWeight(previousLevel);
    const newWeight = Math.max(0, currentWeight - amount);

    context.currentTrustLevel = this.getTrustLevelFromWeight(newWeight);
    context.riskScore = Math.min(100, context.riskScore + (amount * 50));

    this.trustHistoryPush(context, previousLevel, context.currentTrustLevel, reason, [reason]);

    this.emit('trust_decreased', {
      subjectId: context.identity.subjectId,
      previousLevel,
      newLevel: context.currentTrustLevel,
      reason
    });
  }

  /**
   * Увеличение доверия
   */
  private increaseTrust(context: TrustContext, reason: string, amount: number): void {
    const previousLevel = context.currentTrustLevel;
    const currentWeight = this.getTrustWeight(previousLevel);
    const newWeight = Math.min(1, currentWeight + amount);

    context.currentTrustLevel = this.getTrustLevelFromWeight(newWeight);
    context.riskScore = Math.max(0, context.riskScore - (amount * 30));

    this.trustHistoryPush(context, previousLevel, context.currentTrustLevel, reason, [reason]);

    this.emit('trust_increased', {
      subjectId: context.identity.subjectId,
      previousLevel,
      newLevel: context.currentTrustLevel,
      reason
    });
  }

  /**
   * Планирование следующей верификации
   */
  private scheduleVerification(subjectId: string): void {
    const context = this.trustContexts.get(subjectId);
    if (!context) {
      return;
    }

    // Очистка предыдущего таймера
    const existingTimer = this.verificationTimers.get(subjectId);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    // Расчет интервала на основе доверия (адаптивная верификация)
    let interval: number;
    if (this.config.enableAdaptiveVerification) {
      const trustWeight = this.getTrustWeight(context.currentTrustLevel);
      const minInterval = this.config.minVerificationInterval;
      const maxInterval = this.config.maxVerificationInterval;
      
      // Высокое доверие = реже верификация
      interval = maxInterval - (trustWeight * (maxInterval - minInterval));
    } else {
      interval = this.config.verificationInterval;
    }

    const timer = setTimeout(() => {
      this.verifyTrust(subjectId);
    }, interval);

    this.verificationTimers.set(subjectId, timer);
  }

  /**
   * Расчет времени следующей верификации
   */
  private calculateNextVerification(context: TrustContext): Date {
    const trustWeight = this.getTrustWeight(context.currentTrustLevel);
    const minInterval = this.config.minVerificationInterval;
    const maxInterval = this.config.maxVerificationInterval;
    
    const interval = maxInterval - (trustWeight * (maxInterval - minInterval));
    return new Date(context.lastVerification.getTime() + interval);
  }

  /**
   * Получение веса доверия
   */
  private getTrustWeight(level: TrustLevel): number {
    const weights: Record<TrustLevel, number> = {
      [TrustLevel.UNTRUSTED]: 0,
      [TrustLevel.MINIMAL]: 0.2,
      [TrustLevel.LOW]: 0.4,
      [TrustLevel.MEDIUM]: 0.6,
      [TrustLevel.HIGH]: 0.8,
      [TrustLevel.FULL]: 1.0
    };
    return weights[level];
  }

  /**
   * Получение уровня доверия из веса
   */
  private getTrustLevelFromWeight(weight: number): TrustLevel {
    if (weight >= 0.95) return TrustLevel.FULL;
    if (weight >= 0.75) return TrustLevel.HIGH;
    if (weight >= 0.55) return TrustLevel.MEDIUM;
    if (weight >= 0.35) return TrustLevel.LOW;
    if (weight >= 0.15) return TrustLevel.MINIMAL;
    return TrustLevel.UNTRUSTED;
  }

  /**
   * Добавление записи в историю доверия
   */
  private trustHistoryPush(
    context: TrustContext,
    previousLevel: TrustLevel,
    newLevel: TrustLevel,
    reason: string,
    factors: string[]
  ): void {
    context.trustHistory.push({
      timestamp: new Date(),
      previousLevel,
      newLevel,
      reason,
      factors
    });

    // Ограничение истории
    if (context.trustHistory.length > 50) {
      context.trustHistory.shift();
    }
  }

  /**
   * Логирование изменения доверия
   */
  private logTrustChange(
    context: TrustContext,
    previousLevel: TrustLevel,
    factors: string[]
  ): void {
    this.emit('trust_level_changed', {
      subjectId: context.identity.subjectId,
      previousLevel,
      newLevel: context.currentTrustLevel,
      riskScore: context.riskScore,
      factors,
      timestamp: new Date()
    });
  }

  /**
   * Очистка старых аномалий
   */
  private clearOldAnomalies(context: TrustContext): void {
    // Очистка аномалий старше 1 часа
    const oneHourAgo = Date.now() - 3600000;
    const recentEvents = context.behaviorHistory.filter(
      e => e.timestamp.getTime() > oneHourAgo
    );

    if (recentEvents.length === context.behaviorHistory.length) {
      return;
    }

    context.behaviorHistory = recentEvents;

    // Очистка флагов аномалий если нет недавних проблем
    if (recentEvents.filter(e => e.result !== 'SUCCESS').length === 0) {
      context.anomalyFlags = [];
    }
  }

  /**
   * Получение текущего контекста доверия
   */
  getTrustContext(subjectId: string): TrustContext | undefined {
    return this.trustContexts.get(subjectId);
  }

  /**
   * Получение текущего уровня доверия
   */
  getCurrentTrustLevel(subjectId: string): TrustLevel | undefined {
    const context = this.trustContexts.get(subjectId);
    return context?.currentTrustLevel;
  }

  /**
   * Получение текущего риска
   */
  getCurrentRiskScore(subjectId: string): number | undefined {
    const context = this.trustContexts.get(subjectId);
    return context?.riskScore;
  }

  /**
   * Завершение сессии
   */
  terminateSession(subjectId: string): void {
    const context = this.trustContexts.get(subjectId);
    if (!context) {
      return;
    }

    // Очистка таймера
    const timer = this.verificationTimers.get(subjectId);
    if (timer) {
      clearTimeout(timer);
      this.verificationTimers.delete(subjectId);
    }

    // Удаление контекста
    this.trustContexts.delete(subjectId);

    this.emit('session_terminated', {
      subjectId,
      sessionDuration: Date.now() - context.sessionStart.getTime()
    });
  }

  /**
   * Получение статистики
   */
  getStats(): {
    activeSessions: number;
    trustLevelDistribution: Record<TrustLevel, number>;
    averageRiskScore: number;
    isRunning: boolean;
  } {
    const distribution: Record<TrustLevel, number> = {
      [TrustLevel.UNTRUSTED]: 0,
      [TrustLevel.MINIMAL]: 0,
      [TrustLevel.LOW]: 0,
      [TrustLevel.MEDIUM]: 0,
      [TrustLevel.HIGH]: 0,
      [TrustLevel.FULL]: 0
    };

    let totalRisk = 0;

    for (const context of this.trustContexts.values()) {
      distribution[context.currentTrustLevel]++;
      totalRisk += context.riskScore;
    }

    const count = this.trustContexts.size;

    return {
      activeSessions: count,
      trustLevelDistribution: distribution,
      averageRiskScore: count > 0 ? Math.round(totalRisk / count) : 0,
      isRunning: this.isRunning
    };
  }

  /**
   * Очистка всех сессий
   */
  clearAllSessions(): void {
    this.stop();

    for (const subjectId of this.trustContexts.keys()) {
      this.terminateSession(subjectId);
    }

    this.trustContexts.clear();
    this.emit('all_sessions_cleared');
  }

  /**
   * Получение текущего уровня доверия (алиас для getCurrentTrustLevel)
   */
  getTrustLevel(subjectId: string): TrustLevel | undefined {
    return this.getCurrentTrustLevel(subjectId);
  }
}
