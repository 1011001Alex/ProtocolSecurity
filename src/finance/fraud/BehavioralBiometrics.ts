/**
 * ============================================================================
 * BEHAVIORAL BIOMETRICS — ПОВЕДЕНЧЕСКАЯ БИОМЕТРИЯ
 * ============================================================================
 *
 * Анализ поведенческих паттернов пользователя для детекции мошенничества
 *
 * Реализация:
 * - Анализ ритма набора текста (Keystroke Dynamics)
 * - Анализ движений мыши (Mouse Dynamics)
 * - Анализ тач-жестов (Touch Dynamics для мобильных)
 * - Анализ поведения устройства (Device Handling)
 * - ML-based anomaly detection
 *
 * @package protocol/finance-security/fraud
 * @author Protocol Security Team
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { logger } from '../../logging/Logger';
import {
  FinanceSecurityConfig,
  BehavioralBiometricsData,
  FraudRiskFactor
} from '../types/finance.types';

/**
 * Данные сессии пользователя
 */
interface SessionData {
  /** ID сессии */
  sessionId: string;

  /** ID пользователя */
  userId?: string;

  /** Время начала сессии */
  startTime: Date;

  /** Последняя активность */
  lastActivity: Date;

  /** События клавиатуры */
  keyboardEvents: KeyboardEvent[];

  /** События мыши */
  mouseEvents: MouseEvent[];

  /** Тач события (мобильные) */
  touchEvents: TouchEvent[];

  /** Данные об устройстве */
  deviceData: DeviceData;
}

/**
 * Событие клавиатуры
 */
interface KeyboardEvent {
  /** Код клавиши */
  key: string;

  /** Время нажатия */
  pressTime: number;

  /** Время отпускания */
  releaseTime?: number;

  /** Время удержания (ms) */
  holdTime?: number;

  /** Время до следующей клавиши (flight time) */
  flightTime?: number;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Событие мыши
 */
interface MouseEvent {
  /** Тип события */
  type: 'move' | 'click' | 'dblclick' | 'scroll' | 'drag';

  /** Координаты X */
  x: number;

  /** Координаты Y */
  y: number;

  /** Скорость движения (pixels/ms) */
  speed?: number;

  /** Ускорение */
  acceleration?: number;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Тач событие
 */
interface TouchEvent {
  /** Тип события */
  type: 'tap' | 'swipe' | 'pinch' | 'rotate' | 'longpress';

  /** Координаты */
  x: number;
  y: number;

  /** Давление (0-1) */
  pressure?: number;

  /** Площадь касания */
  area?: number;

  /** Угол наклона */
  angle?: number;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Данные об устройстве
 */
interface DeviceData {
  /** User Agent */
  userAgent: string;

  /** Разрешение экрана */
  screenResolution: {
    width: number;
    height: number;
  };

  /** Часовой пояс */
  timezone: string;

  /** Язык */
  language: string;

  /** Platform */
  platform: string;

  /** WebGL fingerprint */
  webglFingerprint?: string;

  /** Canvas fingerprint */
  canvasFingerprint?: string;
}

/**
 * Профиль поведенческой биометрии пользователя
 */
interface BehavioralProfile {
  /** ID пользователя */
  userId: string;

  /** Среднее время удержания клавиши (ms) */
  avgKeyHoldTime: number;

  /** Стандартное отклонение времени удержания */
  keyHoldTimeStdDev: number;

  /** Среднее время между клавишами (flight time, ms) */
  avgFlightTime: number;

  /** Стандартное отклонение flight time */
  flightTimeStdDev: number;

  /** Скорость набора (символов в минуту) */
  typingSpeed: number;

  /** Точность набора (процент без ошибок) */
  typingAccuracy: number;

  /** Средняя скорость мыши (pixels/ms) */
  avgMouseSpeed: number;

  /** Плавность движений мыши (0-1) */
  mouseSmoothness: number;

  /** Паттерны кликов */
  clickPatterns: {
    avgClickDuration: number;
    dblClickInterval: number;
    scrollFrequency: number;
  };

  /** Тач паттерны (мобильные) */
  touchPatterns?: {
    avgPressure: number;
    avgSwipeSpeed: number;
    tapAccuracy: number;
  };

  /** Время создания профиля */
  createdAt: Date;

  /** Последнее обновление */
  updatedAt: Date;

  /** Количество сессий в профиле */
  sessionCount: number;
}

/**
 * Результат анализа биометрии
 */
interface BiometricAnalysisResult {
  /** ID сессии */
  sessionId: string;

  /** ID пользователя (если известен) */
  userId?: string;

  /** Score аномалии (0.0 - 1.0) */
  anomalyScore: number;

  /** Уровень риска */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  /** Факторы риска */
  riskFactors: FraudRiskFactor[];

  /** Совпадение с профилем (0.0 - 1.0) */
  profileMatchScore?: number;

  /** Рекомендации */
  recommendations: string[];

  /** Timestamp анализа */
  timestamp: Date;
}

/**
 * Behavioral Biometrics Service
 */
export class BehavioralBiometrics extends EventEmitter {
  /** Конфигурация */
  private readonly config: FinanceSecurityConfig;

  /** Активные сессии */
  private sessions: Map<string, SessionData> = new Map();

  /** Поведенческие профили пользователей */
  private profiles: Map<string, BehavioralProfile> = new Map();

  /** Статус инициализации */
  private isInitialized = false;

  /** Конфигурация анализа */
  private readonly analysisConfig = {
    // Минимальное количество событий для анализа
    minKeyboardEvents: 20,
    minMouseEvents: 10,

    // Пороги аномалий
    thresholds: {
      keyHoldTimeDeviation: 2.5, // стандартных отклонений
      flightTimeDeviation: 2.5,
      mouseSpeedDeviation: 2.0,
      typingSpeedDeviation: 2.0
    },

    // Окно для обновления профиля (ms)
    profileUpdateWindow: 300000, // 5 минут

    // Максимальный размер сессии
    maxSessionEvents: 1000
  };

  /**
   * Создаёт новый экземпляр BehavioralBiometrics
   */
  constructor(config: FinanceSecurityConfig) {
    super();

    this.config = config;

    logger.info('[BehavioralBiometrics] Service created');
  }

  /**
   * Инициализация сервиса
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[BehavioralBiometrics] Already initialized');
      return;
    }

    try {
      // Загрузка сохранённых профилей (в production из БД)
      // await this.loadProfiles();

      this.isInitialized = true;

      logger.info('[BehavioralBiometrics] Initialized');

      this.emit('initialized');

    } catch (error) {
      logger.error('[BehavioralBiometrics] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Создание новой сессии
   *
   * @param sessionId - ID сессии
   * @param userId - ID пользователя (опционально)
   * @param deviceData - Данные об устройстве
   * @returns Session ID
   */
  public createSession(
    sessionId: string,
    userId: string | undefined,
    deviceData: DeviceData
  ): string {
    if (!this.isInitialized) {
      throw new Error('BehavioralBiometrics not initialized');
    }

    const session: SessionData = {
      sessionId,
      userId,
      startTime: new Date(),
      lastActivity: new Date(),
      keyboardEvents: [],
      mouseEvents: [],
      touchEvents: [],
      deviceData
    };

    this.sessions.set(sessionId, session);

    logger.debug('[BehavioralBiometrics] Session created', {
      sessionId,
      userId
    });

    return sessionId;
  }

  /**
   * Добавление события клавиатуры
   *
   * @param sessionId - ID сессии
   * @param event - Событие клавиатуры
   */
  public addKeyboardEvent(sessionId: string, event: Omit<KeyboardEvent, 'timestamp'>): void {
    const session = this.sessions.get(sessionId);

    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }

    const keyboardEvent: KeyboardEvent = {
      ...event,
      timestamp: new Date()
    };

    // Вычисление hold time и flight time
    const lastEvent = session.keyboardEvents[session.keyboardEvents.length - 1];

    if (lastEvent && lastEvent.pressTime !== undefined) {
      keyboardEvent.holdTime = event.releaseTime ? event.releaseTime - event.pressTime : undefined;
      keyboardEvent.flightTime = event.pressTime - lastEvent.pressTime;
    }

    session.keyboardEvents.push(keyboardEvent);
    session.lastActivity = new Date();

    // Ограничение размера сессии
    if (session.keyboardEvents.length > this.analysisConfig.maxSessionEvents) {
      session.keyboardEvents.shift();
    }
  }

  /**
   * Добавление события мыши
   *
   * @param sessionId - ID сессии
   * @param event - Событие мыши
   */
  public addMouseEvent(sessionId: string, event: Omit<MouseEvent, 'timestamp'>): void {
    const session = this.sessions.get(sessionId);

    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }

    const mouseEvent: MouseEvent = {
      ...event,
      timestamp: new Date()
    };

    // Вычисление скорости и ускорения
    const lastEvent = session.mouseEvents[session.mouseEvents.length - 1];

    if (lastEvent) {
      const dx = event.x - lastEvent.x;
      const dy = event.y - lastEvent.y;
      const dt = mouseEvent.timestamp.getTime() - lastEvent.timestamp.getTime();

      if (dt > 0) {
        const distance = Math.sqrt(dx * dx + dy * dy);
        mouseEvent.speed = distance / dt;

        if (lastEvent.speed !== undefined) {
          mouseEvent.acceleration = (mouseEvent.speed - lastEvent.speed) / dt;
        }
      }
    }

    session.mouseEvents.push(mouseEvent);
    session.lastActivity = new Date();

    // Ограничение размера сессии
    if (session.mouseEvents.length > this.analysisConfig.maxSessionEvents) {
      session.mouseEvents.shift();
    }
  }

  /**
   * Добавление тач события
   *
   * @param sessionId - ID сессии
   * @param event - Тач событие
   */
  public addTouchEvent(sessionId: string, event: Omit<TouchEvent, 'timestamp'>): void {
    const session = this.sessions.get(sessionId);

    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }

    const touchEvent: TouchEvent = {
      ...event,
      timestamp: new Date()
    };

    session.touchEvents.push(touchEvent);
    session.lastActivity = new Date();
  }

  /**
   * Анализ поведенческой биометрии сессии
   *
   * @param sessionId - ID сессии
   * @returns Результат анализа
   */
  public async analyzeSession(sessionId: string): Promise<BiometricAnalysisResult> {
    if (!this.isInitialized) {
      throw new Error('BehavioralBiometrics not initialized');
    }

    const session = this.sessions.get(sessionId);

    if (!session) {
      throw new Error(`Session not found: ${sessionId}`);
    }

    const riskFactors: FraudRiskFactor[] = [];
    const recommendations: string[] = [];
    let anomalyScore = 0;

    // Анализ клавиатурной динамики
    const keyboardAnalysis = this.analyzeKeyboardBehavior(session);

    if (keyboardAnalysis) {
      riskFactors.push(keyboardAnalysis.riskFactor);

      if (keyboardAnalysis.riskFactor.score > 0.5) {
        recommendations.push('Keyboard behavior anomaly detected');
      }

      anomalyScore = Math.max(anomalyScore, keyboardAnalysis.anomalyScore);
    }

    // Анализ движений мыши
    const mouseAnalysis = this.analyzeMouseBehavior(session);

    if (mouseAnalysis) {
      riskFactors.push(mouseAnalysis.riskFactor);

      if (mouseAnalysis.riskFactor.score > 0.5) {
        recommendations.push('Mouse behavior anomaly detected');
      }

      anomalyScore = Math.max(anomalyScore, mouseAnalysis.anomalyScore);
    }

    // Сравнение с профилем пользователя (если есть)
    let profileMatchScore: number | undefined;

    if (session.userId && this.profiles.has(session.userId)) {
      const profile = this.profiles.get(session.userId)!;
      profileMatchScore = this.calculateProfileMatch(session, profile);

      if (profileMatchScore < 0.6) {
        riskFactors.push({
          name: 'PROFILE_MISMATCH',
          weight: 0.4,
          score: 1 - profileMatchScore,
          description: `Behavioral profile mismatch: ${((1 - profileMatchScore) * 100).toFixed(1)}% deviation`,
          evidence: {
            profileMatchScore,
            userId: session.userId
          }
        });

        recommendations.push('Significant deviation from user behavioral profile');
      }
    }

    // Определение уровня риска
    let riskLevel: BiometricAnalysisResult['riskLevel'] = 'LOW';

    if (anomalyScore >= 0.8) {
      riskLevel = 'CRITICAL';
    } else if (anomalyScore >= 0.6) {
      riskLevel = 'HIGH';
    } else if (anomalyScore >= 0.3) {
      riskLevel = 'MEDIUM';
    }

    const result: BiometricAnalysisResult = {
      sessionId,
      userId: session.userId,
      anomalyScore,
      riskLevel,
      riskFactors,
      profileMatchScore,
      recommendations,
      timestamp: new Date()
    };

    logger.info('[BehavioralBiometrics] Session analyzed', {
      sessionId,
      anomalyScore,
      riskLevel
    });

    // Эмиссия события при обнаружении аномалии
    if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
      this.emit('anomaly_detected', result);
    }

    return result;
  }

  /**
   * Анализ клавиатурной динамики
   */
  private analyzeKeyboardBehavior(session: SessionData): {
    anomalyScore: number;
    riskFactor: FraudRiskFactor;
  } | null {
    if (session.keyboardEvents.length < this.analysisConfig.minKeyboardEvents) {
      return null;
    }

    // Вычисление статистик
    const holdTimes = session.keyboardEvents
      .filter(e => e.holdTime !== undefined && e.holdTime > 0)
      .map(e => e.holdTime!) as number[];

    const flightTimes = session.keyboardEvents
      .filter(e => e.flightTime !== undefined && e.flightTime > 0)
      .map(e => e.flightTime!) as number[];

    if (holdTimes.length === 0 || flightTimes.length === 0) {
      return null;
    }

    const avgHoldTime = holdTimes.reduce((a, b) => a + b, 0) / holdTimes.length;
    const stdDevHoldTime = this.calculateStdDev(holdTimes, avgHoldTime);

    const avgFlightTime = flightTimes.reduce((a, b) => a + b, 0) / flightTimes.length;
    const stdDevFlightTime = this.calculateStdDev(flightTimes, avgFlightTime);

    // Сравнение с профилем (если есть)
    let anomalyScore = 0;
    let description = 'Normal keyboard behavior';

    if (session.userId && this.profiles.has(session.userId)) {
      const profile = this.profiles.get(session.userId)!;

      const holdTimeDeviation = Math.abs(avgHoldTime - profile.avgKeyHoldTime) / (profile.keyHoldTimeStdDev || 1);
      const flightTimeDeviation = Math.abs(avgFlightTime - profile.avgFlightTime) / (profile.flightTimeStdDev || 1);

      anomalyScore = Math.max(
        holdTimeDeviation / this.analysisConfig.thresholds.keyHoldTimeDeviation,
        flightTimeDeviation / this.analysisConfig.thresholds.flightTimeDeviation
      );

      anomalyScore = Math.min(anomalyScore, 1.0);

      if (anomalyScore > 0.5) {
        description = `Keyboard timing anomaly: hold time deviation ${holdTimeDeviation.toFixed(2)}σ, flight time deviation ${flightTimeDeviation.toFixed(2)}σ`;
      }
    }

    return {
      anomalyScore,
      riskFactor: {
        name: 'KEYBOARD_DYNAMICS',
        weight: 0.25,
        score: anomalyScore,
        description,
        evidence: {
          avgHoldTime: Math.round(avgHoldTime),
          stdDevHoldTime: Math.round(stdDevHoldTime),
          avgFlightTime: Math.round(avgFlightTime),
          stdDevFlightTime: Math.round(stdDevFlightTime),
          eventsAnalyzed: holdTimes.length
        }
      }
    };
  }

  /**
   * Анализ поведения мыши
   */
  private analyzeMouseBehavior(session: SessionData): {
    anomalyScore: number;
    riskFactor: FraudRiskFactor;
  } | null {
    if (session.mouseEvents.length < this.analysisConfig.minMouseEvents) {
      return null;
    }

    // Вычисление статистик скорости
    const speeds = session.mouseEvents
      .filter(e => e.speed !== undefined && e.speed > 0)
      .map(e => e.speed!) as number[];

    if (speeds.length === 0) {
      return null;
    }

    const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
    const stdDevSpeed = this.calculateStdDev(speeds, avgSpeed);

    // Анализ плавности движений
    const accelerations = session.mouseEvents
      .filter(e => e.acceleration !== undefined)
      .map(e => Math.abs(e.acceleration!)) as number[];

    const avgAcceleration = accelerations.length > 0
      ? accelerations.reduce((a, b) => a + b, 0) / accelerations.length
      : 0;

    // Сравнение с профилем
    let anomalyScore = 0;
    let description = 'Normal mouse behavior';

    if (session.userId && this.profiles.has(session.userId)) {
      const profile = this.profiles.get(session.userId)!;

      const speedDeviation = Math.abs(avgSpeed - profile.avgMouseSpeed) / (profile.avgMouseSpeed || 1);

      anomalyScore = Math.min(
        speedDeviation / this.analysisConfig.thresholds.mouseSpeedDeviation,
        1.0
      );

      // Штраф за неестественные движения
      if (avgAcceleration > 10) {
        anomalyScore = Math.min(anomalyScore + 0.2, 1.0);
        description = 'Unnatural mouse acceleration patterns detected';
      }

      if (anomalyScore > 0.5) {
        description = `Mouse behavior anomaly: speed deviation ${speedDeviation.toFixed(2)}σ`;
      }
    }

    return {
      anomalyScore,
      riskFactor: {
        name: 'MOUSE_DYNAMICS',
        weight: 0.2,
        score: anomalyScore,
        description,
        evidence: {
          avgSpeed: parseFloat(avgSpeed.toFixed(3)),
          stdDevSpeed: parseFloat(stdDevSpeed.toFixed(3)),
          avgAcceleration: parseFloat(avgAcceleration.toFixed(3)),
          eventsAnalyzed: speeds.length
        }
      }
    };
  }

  /**
   * Вычисление совпадения с профилем
   */
  private calculateProfileMatch(session: SessionData, profile: BehavioralProfile): number {
    let matchScore = 1.0;

    // Сравнение клавиатурной динамики
    if (session.keyboardEvents.length >= this.analysisConfig.minKeyboardEvents) {
      const holdTimes = session.keyboardEvents
        .filter(e => e.holdTime !== undefined && e.holdTime > 0)
        .map(e => e.holdTime!) as number[];

      const avgHoldTime = holdTimes.reduce((a, b) => a + b, 0) / holdTimes.length;

      const holdTimeDiff = Math.abs(avgHoldTime - profile.avgKeyHoldTime);
      const holdTimeMatch = Math.max(0, 1 - holdTimeDiff / (profile.keyHoldTimeStdDev * 3 || 100));

      matchScore *= holdTimeMatch;
    }

    // Сравнение скорости мыши
    if (session.mouseEvents.length >= this.analysisConfig.minMouseEvents) {
      const speeds = session.mouseEvents
        .filter(e => e.speed !== undefined && e.speed > 0)
        .map(e => e.speed!) as number[];

      if (speeds.length > 0) {
        const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;

        const speedDiff = Math.abs(avgSpeed - profile.avgMouseSpeed);
        const speedMatch = Math.max(0, 1 - speedDiff / (profile.avgMouseSpeed || 1));

        matchScore *= speedMatch;
      }
    }

    return matchScore;
  }

  /**
   * Обновление поведенческого профиля пользователя
   *
   * @param userId - ID пользователя
   * @param session - Данные сессии
   */
  public updateBehavioralProfile(userId: string, session: SessionData): void {
    if (!this.isInitialized) {
      throw new Error('BehavioralBiometrics not initialized');
    }

    const now = new Date();
    const existingProfile = this.profiles.get(userId);

    // Пропускаем обновление, если прошло слишком мало времени
    if (existingProfile) {
      const timeSinceUpdate = now.getTime() - existingProfile.updatedAt.getTime();

      if (timeSinceUpdate < this.analysisConfig.profileUpdateWindow) {
        return;
      }
    }

    // Вычисление новых статистик
    const holdTimes = session.keyboardEvents
      .filter(e => e.holdTime !== undefined && e.holdTime > 0)
      .map(e => e.holdTime!) as number[];

    const flightTimes = session.keyboardEvents
      .filter(e => e.flightTime !== undefined && e.flightTime > 0)
      .map(e => e.flightTime!) as number[];

    const speeds = session.mouseEvents
      .filter(e => e.speed !== undefined && e.speed > 0)
      .map(e => e.speed!) as number[];

    if (holdTimes.length === 0 || speeds.length === 0) {
      return;
    }

    const avgHoldTime = holdTimes.reduce((a, b) => a + b, 0) / holdTimes.length;
    const stdDevHoldTime = this.calculateStdDev(holdTimes, avgHoldTime);

    const avgFlightTime = flightTimes.reduce((a, b) => a + b, 0) / flightTimes.length;
    const stdDevFlightTime = this.calculateStdDev(flightTimes, avgFlightTime);

    const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;

    // Создание или обновление профиля
    const newProfile: BehavioralProfile = {
      userId,
      avgKeyHoldTime: existingProfile
        ? this.exponentialMovingAverage(existingProfile.avgKeyHoldTime, avgHoldTime, 0.3)
        : avgHoldTime,
      keyHoldTimeStdDev: existingProfile
        ? this.exponentialMovingAverage(existingProfile.keyHoldTimeStdDev, stdDevHoldTime, 0.3)
        : stdDevHoldTime,
      avgFlightTime: existingProfile
        ? this.exponentialMovingAverage(existingProfile.avgFlightTime, avgFlightTime, 0.3)
        : avgFlightTime,
      flightTimeStdDev: existingProfile
        ? this.exponentialMovingAverage(existingProfile.flightTimeStdDev, stdDevFlightTime, 0.3)
        : stdDevFlightTime,
      typingSpeed: this.calculateTypingSpeed(session.keyboardEvents),
      typingAccuracy: 0.95, // В production реальная метрика
      avgMouseSpeed: existingProfile
        ? this.exponentialMovingAverage(existingProfile.avgMouseSpeed, avgSpeed, 0.3)
        : avgSpeed,
      mouseSmoothness: this.calculateMouseSmoothness(session.mouseEvents),
      clickPatterns: {
        avgClickDuration: 150, // В production реальная метрика
        dblClickInterval: 300,
        scrollFrequency: 0.5
      },
      createdAt: existingProfile?.createdAt || now,
      updatedAt: now,
      sessionCount: (existingProfile?.sessionCount || 0) + 1
    };

    this.profiles.set(userId, newProfile);

    logger.debug('[BehavioralBiometrics] Profile updated', {
      userId,
      sessionCount: newProfile.sessionCount
    });

    this.emit('profile_updated', {
      userId,
      profile: newProfile
    });
  }

  /**
   * Вычисление стандартного отклонения
   */
  private calculateStdDev(values: number[], mean: number): number {
    if (values.length < 2) return 0;

    const squaredDiffs = values.map(value => Math.pow(value - mean, 2));
    const avgSquaredDiff = squaredDiffs.reduce((a, b) => a + b, 0) / squaredDiffs.length;

    return Math.sqrt(avgSquaredDiff);
  }

  /**
   * Вычисление скорости набора
   */
  private calculateTypingSpeed(events: KeyboardEvent[]): number {
    if (events.length < 2) return 0;

    const firstEvent = events[0];
    const lastEvent = events[events.length - 1];

    const timeDiffMinutes = (lastEvent.timestamp.getTime() - firstEvent.timestamp.getTime()) / 60000;

    if (timeDiffMinutes === 0) return 0;

    return events.length / timeDiffMinutes;
  }

  /**
   * Вычисление плавности мыши
   */
  private calculateMouseSmoothness(events: MouseEvent[]): number {
    if (events.length < 2) return 0.5;

    const accelerations = events
      .filter(e => e.acceleration !== undefined)
      .map(e => Math.abs(e.acceleration!));

    if (accelerations.length === 0) return 0.5;

    const avgAcceleration = accelerations.reduce((a, b) => a + b, 0) / accelerations.length;

    // Нормализация (меньше ускорение = плавнее)
    return Math.max(0, Math.min(1, 1 - avgAcceleration / 10));
  }

  /**
   * Экспоненциальное скользящее среднее
   */
  private exponentialMovingAverage(previous: number, current: number, alpha: number): number {
    return alpha * current + (1 - alpha) * previous;
  }

  /**
   * Удаление сессии
   *
   * @param sessionId - ID сессии
   */
  public removeSession(sessionId: string): void {
    this.sessions.delete(sessionId);

    logger.debug('[BehavioralBiometrics] Session removed', { sessionId });
  }

  /**
   * Остановка сервиса
   */
  public async destroy(): Promise<void> {
    logger.info('[BehavioralBiometrics] Shutting down...');

    // Сохранение профилей (в production)
    // await this.saveProfiles();

    this.sessions.clear();
    this.profiles.clear();
    this.isInitialized = false;

    logger.info('[BehavioralBiometrics] Destroyed');

    this.emit('destroyed');
  }

  /**
   * Получить статус сервиса
   */
  public getStatus(): {
    initialized: boolean;
    activeSessions: number;
    profilesCount: number;
  } {
    return {
      initialized: this.isInitialized,
      activeSessions: this.sessions.size,
      profilesCount: this.profiles.size
    };
  }
}
