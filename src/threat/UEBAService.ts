/**
 * ============================================================================
 * UEBA SERVICE - USER AND ENTITY BEHAVIOR ANALYTICS
 * Анализ поведения пользователей и сущностей для обнаружения аномалий
 * ============================================================================
 */

import {
  UserProfile,
  HostProfile,
  BehaviorProfile,
  EntityType,
  GeoLocation,
  NetworkConnection,
  PrivilegePattern,
  SecurityEvent,
  SecurityAlert,
  ThreatSeverity,
  ThreatStatus,
  ThreatCategory,
  AttackType,
  UEBAConfig,
  RiskScore
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Интерфейс для детектора аномалий поведения
 */
interface IAnomalyDetector {
  detect(profile: BehaviorProfile, currentBehavior: Record<string, number>): AnomalyResult;
  updateBaseline(profile: BehaviorProfile, newData: Record<string, number>): void;
}

/**
 * Результат обнаружения аномалии
 */
interface AnomalyResult {
  isAnomaly: boolean;
  anomalyScore: number;
  anomalyFactors: AnomalyFactor[];
  confidence: number;
}

/**
 * Фактор аномалии
 */
interface AnomalyFactor {
  metric: string;
  expectedValue: number;
  actualValue: number;
  deviation: number;
  severity: ThreatSeverity;
  description: string;
}

/**
 * ============================================================================
 * UEBA SERVICE - ОСНОВНОЙ КЛАСС
 * ============================================================================
 */
export class UEBAService {
  private config: UEBAConfig;
  
  // Профили пользователей
  private userProfiles: Map<string, UserProfile> = new Map();
  
  // Профили хостов
  private hostProfiles: Map<string, HostProfile> = new Map();
  
  // Профили других сущностей
  private entityProfiles: Map<string, BehaviorProfile> = new Map();
  
  // История событий для анализа
  private eventHistory: Map<string, SecurityEvent[]> = new Map();
  
  // Детекторы аномалий
  private anomalyDetectors: Map<EntityType, IAnomalyDetector> = new Map();
  
  // Кэш рисков
  private riskCache: Map<string, { score: number; timestamp: Date }> = new Map();
  
  // Статистика
  private statistics: UEBAStatistics = {
    totalProfiles: 0,
    anomaliesDetected: 0,
    falsePositives: 0,
    truePositives: 0,
    lastUpdated: new Date()
  };

  constructor(config?: Partial<UEBAConfig>) {
    // Конфигурация по умолчанию
    this.config = {
      baselineWindow: config?.baselineWindow || 30,  // 30 дней
      anomalyWindow: config?.anomalyWindow || 24,    // 24 часа
      minEventsForBaseline: config?.minEventsForBaseline || 100,
      behaviorMetrics: config?.behaviorMetrics || [
        'loginFrequency',
        'accessVolume',
        'sessionDuration',
        'failedLogins',
        'privilegeUsage',
        'networkConnections',
        'fileAccess',
        'processExecution'
      ],
      riskThresholds: config?.riskThresholds || {
        low: 20,
        medium: 40,
        high: 60,
        critical: 80
      }
    };
    
    // Инициализация детекторов аномалий
    this.initializeAnomalyDetectors();
    
    console.log('[UEBAService] Инициализация завершена');
    console.log(`[UEBAService] Окно базовой линии: ${this.config.baselineWindow} дней`);
    console.log(`[UEBAService] Окно аномалий: ${this.config.anomalyWindow} часов`);
  }

  /**
   * Инициализация детекторов аномалий для разных типов сущностей
   */
  private initializeAnomalyDetectors(): void {
    // Детектор для пользователей
    this.anomalyDetectors.set(EntityType.USER, new UserAnomalyDetector(this.config));
    
    // Детектор для хостов
    this.anomalyDetectors.set(EntityType.HOST, new HostAnomalyDetector(this.config));
    
    // Детектор для сервисов
    this.anomalyDetectors.set(EntityType.SERVICE, new ServiceAnomalyDetector(this.config));
    
    // Общий детектор для остальных типов
    this.anomalyDetectors.set(EntityType.APPLICATION, new GenericAnomalyDetector(this.config));
  }

  // ============================================================================
  // УПРАВЛЕНИЕ ПРОФИЛЯМИ
  // ============================================================================

  /**
   * Создание или обновление профиля пользователя
   */
  async updateUserProfile(userData: Partial<UserProfile>): Promise<UserProfile> {
    const userId = userData.userId || userData.entityId || uuidv4();
    
    let profile = this.userProfiles.get(userId);
    
    if (!profile) {
      // Создание нового профиля
      profile = {
        entityId: userId,
        entityType: EntityType.USER,
        userId,
        username: userData.username || 'unknown',
        role: userData.role || 'user',
        department: userData.department,
        baselineMetrics: {},
        dynamicMetrics: {},
        riskScore: 0,
        lastUpdated: new Date(),
        historyWindow: this.config.baselineWindow * 24,  // В часах
        typicalLoginTimes: userData.typicalLoginTimes || [],
        typicalLocations: userData.typicalLocations || [],
        typicalDevices: userData.typicalDevices || [],
        accessedResources: userData.accessedResources || [],
        averageSessionDuration: userData.averageSessionDuration || 0,
        failedLoginRate: userData.failedLoginRate || 0,
        privilegeUsagePatterns: userData.privilegeUsagePatterns || []
      };
      
      this.userProfiles.set(userId, profile);
      console.log(`[UEBAService] Создан профиль пользователя: ${userId}`);
    } else {
      // Обновление существующего профиля
      profile = {
        ...profile,
        ...userData,
        lastUpdated: new Date()
      };
      
      this.userProfiles.set(userId, profile);
    }
    
    this.statistics.totalProfiles = this.userProfiles.size + this.hostProfiles.size + this.entityProfiles.size;
    
    return profile;
  }

  /**
   * Создание или обновление профиля хоста
   */
  async updateHostProfile(hostData: Partial<HostProfile>): Promise<HostProfile> {
    const hostId = hostData.entityId || hostData.hostname || uuidv4();
    
    let profile = this.hostProfiles.get(hostId);
    
    if (!profile) {
      profile = {
        entityId: hostId,
        entityType: EntityType.HOST,
        hostname: hostData.hostname || 'unknown',
        ipAddress: hostData.ipAddress || '',
        osType: hostData.osType || 'unknown',
        osVersion: hostData.osVersion || '',
        baselineMetrics: {},
        dynamicMetrics: {},
        riskScore: 0,
        lastUpdated: new Date(),
        historyWindow: this.config.baselineWindow * 24,
        typicalProcesses: hostData.typicalProcesses || [],
        typicalConnections: hostData.typicalConnections || [],
        averageCPUUsage: hostData.averageCPUUsage || 0,
        averageMemoryUsage: hostData.averageMemoryUsage || 0,
        averageNetworkTraffic: hostData.averageNetworkTraffic || 0,
        installedSoftware: hostData.installedSoftware || [],
        openPorts: hostData.openPorts || []
      };
      
      this.hostProfiles.set(hostId, profile);
      console.log(`[UEBAService] Создан профиль хоста: ${hostId}`);
    } else {
      profile = {
        ...profile,
        ...hostData,
        lastUpdated: new Date()
      };
      
      this.hostProfiles.set(hostId, profile);
    }
    
    this.statistics.totalProfiles = this.userProfiles.size + this.hostProfiles.size + this.entityProfiles.size;
    
    return profile;
  }

  /**
   * Обновление динамических метрик профиля
   */
  async updateDynamicMetrics(entityId: string, metrics: Record<string, number>): Promise<void> {
    // Поиск профиля в любом хранилище
    let profile = this.userProfiles.get(entityId) as BehaviorProfile | undefined;
    let profileType: 'user' | 'host' | 'entity' = 'user';
    
    if (!profile) {
      profile = this.hostProfiles.get(entityId);
      profileType = 'host';
    }
    
    if (!profile) {
      profile = this.entityProfiles.get(entityId);
      profileType = 'entity';
    }
    
    if (!profile) {
      console.warn(`[UEBAService] Профиль ${entityId} не найден`);
      return;
    }
    
    // Обновление динамических метрик
    profile.dynamicMetrics = {
      ...profile.dynamicMetrics,
      ...metrics
    };
    
    // Пересчет risk score
    profile.riskScore = this.calculateEntityRisk(profile);
    profile.lastUpdated = new Date();
    
    // Обновление кэша рисков
    this.riskCache.set(entityId, {
      score: profile.riskScore,
      timestamp: new Date()
    });
    
    // Сохранение обновленного профиля
    switch (profileType) {
      case 'user':
        this.userProfiles.set(entityId, profile as UserProfile);
        break;
      case 'host':
        this.hostProfiles.set(entityId, profile as HostProfile);
        break;
      case 'entity':
        this.entityProfiles.set(entityId, profile);
        break;
    }
  }

  // ============================================================================
  // АНАЛИЗ СОБЫТИЙ
  // ============================================================================

  /**
   * Обработка события безопасности
   */
  async processEvent(event: SecurityEvent): Promise<SecurityAlert[]> {
    try {
      // Сохранение события в историю
      this.addToEventHistory(event);

      // Определение сущности
      const entityId = this.extractEntityId(event);
      if (!entityId) {
        return [];
      }

      // Обновление профиля сущности
      await this.updateProfileFromEvent(entityId, event);

      // Обнаружение аномалий
      const anomalyResult = await this.detectAnomalies(entityId, event);

      if (anomalyResult.isAnomaly) {
        // Создание алерта
        const alert = this.createAnomalyAlert(entityId, event, anomalyResult);

        this.statistics.anomaliesDetected++;

        return [alert];
      }

      return [];
    } catch (error) {
      // При ошибке — возвращаем пустой массив, не ломаем pipeline
      console.error(`[UEBAService] Ошибка обработки события: ${error}`);
      return [];
    }
  }

  /**
   * Пакетная обработка событий
   */
  async processEvents(events: SecurityEvent[]): Promise<SecurityAlert[]> {
    const alerts: SecurityAlert[] = [];
    
    for (const event of events) {
      const alert = await this.processEvent(event);
      if (alert) {
        alerts.push(alert);
      }
    }
    
    return alerts;
  }

  /**
   * Извлечение ID сущности из события
   */
  private extractEntityId(event: SecurityEvent): string | null {
    // Приоритет: пользователь -> хост -> IP адрес
    if (event.userId) {
      return event.userId;
    }
    if (event.hostname) {
      return event.hostname;
    }
    if (event.sourceIp) {
      return event.sourceIp;
    }
    
    return null;
  }

  /**
   * Добавление события в историю
   */
  private addToEventHistory(event: SecurityEvent): void {
    const entityId = this.extractEntityId(event);
    if (!entityId) return;
    
    let history = this.eventHistory.get(entityId);
    
    if (!history) {
      history = [];
      this.eventHistory.set(entityId, history);
    }
    
    history.push(event);
    
    // Ограничение размера истории
    const maxHistorySize = this.config.baselineWindow * 24 * 60;  // Событий за период
    if (history.length > maxHistorySize) {
      history.shift();
    }
  }

  /**
   * Обновление профиля из события
   */
  private async updateProfileFromEvent(entityId: string, event: SecurityEvent): Promise<void> {
    const metrics = this.extractMetricsFromEvent(event);
    await this.updateDynamicMetrics(entityId, metrics);
  }

  /**
   * Извлечение метрик из события
   */
  private extractMetricsFromEvent(event: SecurityEvent): Record<string, number> {
    const metrics: Record<string, number> = {};
    
    // Метрики входа
    if (event.eventType.includes('login') || event.eventType.includes('logon')) {
      metrics.loginFrequency = 1;
      if (event.severity === ThreatSeverity.HIGH || event.severity === ThreatSeverity.CRITICAL) {
        metrics.failedLogins = 1;
      }
    }
    
    // Метрики доступа
    if (event.eventType.includes('access') || event.eventType.includes('read')) {
      metrics.accessVolume = 1;
    }
    
    // Метрики сессии
    if (event.eventType.includes('session')) {
      metrics.sessionDuration = 1;
    }
    
    // Метрики привилегий
    if (event.eventType.includes('privilege') || event.eventType.includes('admin')) {
      metrics.privilegeUsage = 1;
    }
    
    // Сетевые метрики
    if (event.eventType.includes('network') || event.eventType.includes('connection')) {
      metrics.networkConnections = 1;
    }
    
    // Метрики файлов
    if (event.eventType.includes('file')) {
      metrics.fileAccess = 1;
    }
    
    // Метрики процессов
    if (event.eventType.includes('process') || event.eventType.includes('exec')) {
      metrics.processExecution = 1;
    }
    
    return metrics;
  }

  // ============================================================================
  // ОБНАРУЖЕНИЕ АНОМАЛИЙ
  // ============================================================================

  /**
   * Обнаружение аномалий для сущности
   */
  async detectAnomalies(entityId: string, currentEvent: SecurityEvent): Promise<AnomalyResult> {
    // Получение профиля
    const profile = this.getProfile(entityId);
    
    if (!profile) {
      return {
        isAnomaly: false,
        anomalyScore: 0,
        anomalyFactors: [],
        confidence: 0
      };
    }
    
    // Извлечение текущих метрик из события
    const currentMetrics = this.extractMetricsFromEvent(currentEvent);
    
    // Получение детектора для типа сущности
    const detector = this.anomalyDetectors.get(profile.entityType);
    
    if (!detector) {
      return {
        isAnomaly: false,
        anomalyScore: 0,
        anomalyFactors: [],
        confidence: 0
      };
    }
    
    // Обнаружение аномалий
    const result = detector.detect(profile, currentMetrics);
    
    return result;
  }

  /**
   * Обнаружение аномалий времени входа
   */
  detectLoginTimeAnomaly(profile: UserProfile, loginHour: number): AnomalyFactor | null {
    if (profile.typicalLoginTimes.length === 0) {
      return null;  // Нет базовой линии
    }
    
    // Проверка, попадает ли время входа в типичные
    const isTypical = profile.typicalLoginTimes.some(
      typicalHour => Math.abs(typicalHour - loginHour) <= 2  // Окно ±2 часа
    );
    
    if (!isTypical) {
      // Расчет отклонения
      const minDiff = Math.min(
        ...profile.typicalLoginTimes.map(h => Math.abs(h - loginHour))
      );
      
      return {
        metric: 'loginTime',
        expectedValue: profile.typicalLoginTimes[0] || 0,
        actualValue: loginHour,
        deviation: minDiff,
        severity: minDiff > 6 ? ThreatSeverity.HIGH : ThreatSeverity.MEDIUM,
        description: `Вход в необычное время: ${loginHour}:00 (типично: ${profile.typicalLoginTimes.join(', ')})`
      };
    }
    
    return null;
  }

  /**
   * Обнаружение аномалий местоположения
   */
  detectLocationAnomaly(profile: UserProfile, currentLocation: GeoLocation): AnomalyFactor | null {
    if (profile.typicalLocations.length === 0) {
      return null;  // Нет базовой линии
    }
    
    // Проверка, является ли местоположение типичным
    const isTypical = profile.typicalLocations.some(
      loc => loc.country === currentLocation.country && loc.city === currentLocation.city
    );
    
    if (!isTypical && !currentLocation.isTypical) {
      return {
        metric: 'location',
        expectedValue: 0,
        actualValue: 1,
        deviation: 1,
        severity: ThreatSeverity.HIGH,
        description: `Вход из необычного местоположения: ${currentLocation.city}, ${currentLocation.country}`
      };
    }
    
    return null;
  }

  /**
   * Обнаружение аномалий устройства
   */
  detectDeviceAnomaly(profile: UserProfile, deviceId: string): AnomalyFactor | null {
    if (profile.typicalDevices.length === 0) {
      return null;  // Нет базовой линии
    }
    
    const isTypical = profile.typicalDevices.includes(deviceId);
    
    if (!isTypical) {
      return {
        metric: 'device',
        expectedValue: 0,
        actualValue: 1,
        deviation: 1,
        severity: ThreatSeverity.MEDIUM,
        description: `Вход с нового устройства: ${deviceId}`
      };
    }
    
    return null;
  }

  /**
   * Обнаружение аномалий привилегий
   */
  detectPrivilegeAnomaly(profile: UserProfile, currentHour: number, resource: string): AnomalyFactor | null {
    // Проверка паттернов использования привилегий
    for (const pattern of profile.privilegeUsagePatterns) {
      const isTypicalTime = pattern.typicalUsageTimes.some(
        h => Math.abs(h - currentHour) <= 2
      );
      
      const isTypicalResource = pattern.typicalResources.includes(resource);
      
      if (!isTypicalTime || !isTypicalResource) {
        return {
          metric: 'privilegeUsage',
          expectedValue: 0,
          actualValue: 1,
          deviation: 1,
          severity: ThreatSeverity.HIGH,
          description: `Использование привилегий в необычное время или для необычного ресурса`
        };
      }
    }
    
    return null;
  }

  // ============================================================================
  // РАСЧЕТ РИСКА
  // ============================================================================

  /**
   * Расчет риска для сущности
   */
  calculateEntityRisk(profile: BehaviorProfile): number {
    let riskScore = 0;
    
    // Факторы риска
    const factors: { weight: number; value: number }[] = [];
    
    // Частота неудачных входов
    if ('failedLoginRate' in profile) {
      const userProfile = profile as UserProfile;
      factors.push({
        weight: 0.2,
        value: Math.min(userProfile.failedLoginRate * 10, 100)
      });
    }
    
    // Отклонение динамических метрик от базовых
    const metricDeviation = this.calculateMetricDeviation(profile);
    factors.push({
      weight: 0.3,
      value: metricDeviation
    });
    
    // Время с последнего обновления
    const hoursSinceUpdate = (Date.now() - profile.lastUpdated.getTime()) / (1000 * 60 * 60);
    factors.push({
      weight: 0.1,
      value: Math.min(hoursSinceUpdate, 100)
    });
    
    // Расчет итогового риска
    riskScore = factors.reduce((sum, f) => sum + f.weight * f.value, 0);
    
    // Ограничение 0-100
    return Math.min(Math.max(riskScore, 0), 100);
  }

  /**
   * Расчет отклонения метрик
   */
  private calculateMetricDeviation(profile: BehaviorProfile): number {
    let totalDeviation = 0;
    let count = 0;
    
    for (const metric of this.config.behaviorMetrics) {
      const baseline = profile.baselineMetrics[metric] || 0;
      const current = profile.dynamicMetrics[metric] || 0;
      
      if (baseline > 0) {
        const deviation = Math.abs(current - baseline) / baseline;
        totalDeviation += Math.min(deviation * 100, 100);  // Ограничение 100%
        count++;
      }
    }
    
    return count > 0 ? totalDeviation / count : 0;
  }

  /**
   * Получение риска сущности
   */
  getEntityRisk(entityId: string): number {
    const cached = this.riskCache.get(entityId);
    
    if (cached && (Date.now() - cached.timestamp.getTime()) < 5 * 60 * 1000) {
      // Кэш действителен 5 минут
      return cached.score;
    }
    
    const profile = this.getProfile(entityId);
    
    if (!profile) {
      return 0;
    }
    
    return profile.riskScore;
  }

  // ============================================================================
  // СОЗДАНИЕ АЛЕРТОВ
  // ============================================================================

  /**
   * Создание алерта аномалии
   */
  private createAnomalyAlert(
    entityId: string,
    event: SecurityEvent,
    anomalyResult: AnomalyResult
  ): SecurityAlert {
    // Определение серьезности на основе anomaly score
    let severity = ThreatSeverity.LOW;
    
    if (anomalyResult.anomalyScore >= this.config.riskThresholds.critical) {
      severity = ThreatSeverity.CRITICAL;
    } else if (anomalyResult.anomalyScore >= this.config.riskThresholds.high) {
      severity = ThreatSeverity.HIGH;
    } else if (anomalyResult.anomalyScore >= this.config.riskThresholds.medium) {
      severity = ThreatSeverity.MEDIUM;
    }
    
    // Формирование описания
    const descriptions = anomalyResult.anomalyFactors.map(f => f.description).join('; ');
    
    const alert: SecurityAlert = {
      id: uuidv4(),
      timestamp: new Date(),
      title: `Обнаружена аномалия поведения: ${entityId}`,
      description: descriptions,
      severity,
      status: ThreatStatus.NEW,
      category: ThreatCategory.ANOMALY,
      attackType: AttackType.SUSPICIOUS_BEHAVIOR,
      source: 'UEBA',
      events: [event],
      entities: [{
        id: entityId,
        type: this.getEntityType(entityId),
        name: entityId,
        value: entityId,
        riskScore: anomalyResult.anomalyScore,
        role: 'unknown',
        context: anomalyResult.anomalyFactors.reduce((acc, f) => {
          acc[f.metric] = f.actualValue;
          return acc;
        }, {} as Record<string, number>)
      }],
      mitreAttack: {
        tactics: [],
        techniques: []
      },
      riskScore: anomalyResult.anomalyScore,
      confidence: anomalyResult.confidence,
      falsePositiveProbability: 1 - anomalyResult.confidence,
      investigationStatus: {
        stage: 'triage',
        progress: 0,
        findings: [],
        evidenceCollected: []
      },
      assignedTo: undefined,
      tags: ['ueba', 'anomaly', 'behavior'],
      timeline: [{
        timestamp: new Date(),
        event: 'Alert created',
        actor: 'UEBAService'
      }],
      evidence: [],
      response: {
        automatedActions: [],
        manualActions: [],
        playbooksExecuted: [],
        containmentStatus: 'not_started',
        eradicationStatus: 'not_started',
        recoveryStatus: 'not_started'
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    return alert;
  }

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Получение профиля сущности
   */
  getProfile(entityId: string): BehaviorProfile | null {
    return this.userProfiles.get(entityId) as BehaviorProfile ||
           this.hostProfiles.get(entityId) as BehaviorProfile ||
           this.entityProfiles.get(entityId) ||
           null;
  }

  /**
   * Получение типа сущности
   */
  getEntityType(entityId: string): EntityType {
    if (this.userProfiles.has(entityId)) return EntityType.USER;
    if (this.hostProfiles.has(entityId)) return EntityType.HOST;
    return EntityType.APPLICATION;
  }

  /**
   * Получение всех профилей пользователей
   */
  getAllUserProfiles(): UserProfile[] {
    return Array.from(this.userProfiles.values());
  }

  /**
   * Получение всех профилей хостов
   */
  getAllHostProfiles(): HostProfile[] {
    return Array.from(this.hostProfiles.values());
  }

  /**
   * Получение высокорисковых сущностей
   */
  getHighRiskEntities(threshold: number = 60): BehaviorProfile[] {
    const allProfiles = [
      ...this.userProfiles.values(),
      ...this.hostProfiles.values(),
      ...this.entityProfiles.values()
    ];
    
    return allProfiles.filter(p => p.riskScore >= threshold);
  }

  /**
   * Сброс базовой линии для сущности
   */
  async resetBaseline(entityId: string): Promise<void> {
    const profile = this.getProfile(entityId);
    
    if (profile) {
      profile.baselineMetrics = { ...profile.dynamicMetrics };
      profile.dynamicMetrics = {};
      profile.riskScore = 0;
      profile.lastUpdated = new Date();
      
      console.log(`[UEBAService] Базовая линия сброшена для ${entityId}`);
    }
  }

  /**
   * Получение статистики
   */
  getStatistics(): UEBAStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }

  /**
   * Отметка ложного срабатывания
   */
  markFalsePositive(alertId: string): void {
    this.statistics.falsePositives++;
  }

  /**
   * Отметка истинного срабатывания
   */
  markTruePositive(alertId: string): void {
    this.statistics.truePositives++;
  }
}

/**
 * ============================================================================
 * DETECTORS - ДЕТЕКТОРЫ АНОМАЛИЙ
 * ============================================================================
 */

/**
 * Детектор аномалий для пользователей
 */
class UserAnomalyDetector implements IAnomalyDetector {
  constructor(private config: UEBAConfig) {}

  detect(profile: BehaviorProfile, currentBehavior: Record<string, number>): AnomalyResult {
    const userProfile = profile as UserProfile;
    const anomalyFactors: AnomalyFactor[] = [];
    
    // Проверка частоты входов
    if (currentBehavior.loginFrequency !== undefined) {
      const baseline = userProfile.baselineMetrics.loginFrequency || 0;
      const current = currentBehavior.loginFrequency;
      
      if (baseline > 0 && current > baseline * 3) {
        anomalyFactors.push({
          metric: 'loginFrequency',
          expectedValue: baseline,
          actualValue: current,
          deviation: (current - baseline) / baseline,
          severity: ThreatSeverity.MEDIUM,
          description: `Аномально высокая частота входов: ${current} (база: ${baseline})`
        });
      }
    }
    
    // Проверка неудачных входов
    if (currentBehavior.failedLogins !== undefined) {
      const baseline = userProfile.baselineMetrics.failedLogins || 0;
      const current = currentBehavior.failedLogins;
      
      if (current > 5) {
        anomalyFactors.push({
          metric: 'failedLogins',
          expectedValue: baseline,
          actualValue: current,
          deviation: current,
          severity: ThreatSeverity.HIGH,
          description: `Множественные неудачные входы: ${current}`
        });
      }
    }
    
    // Проверка использования привилегий
    if (currentBehavior.privilegeUsage !== undefined) {
      const baseline = userProfile.baselineMetrics.privilegeUsage || 0;
      const current = currentBehavior.privilegeUsage;
      
      if (baseline === 0 && current > 0) {
        anomalyFactors.push({
          metric: 'privilegeUsage',
          expectedValue: baseline,
          actualValue: current,
          deviation: 1,
          severity: ThreatSeverity.HIGH,
          description: `Использование привилегий без истории`
        });
      }
    }
    
    // Расчет общего anomaly score
    const anomalyScore = this.calculateAnomalyScore(anomalyFactors);
    const isAnomaly = anomalyScore >= this.config.riskThresholds.medium;
    
    return {
      isAnomaly,
      anomalyScore,
      anomalyFactors,
      confidence: this.calculateConfidence(anomalyFactors)
    };
  }

  updateBaseline(profile: BehaviorProfile, newData: Record<string, number>): void {
    // Экспоненциальное скользящее среднее для обновления базовой линии
    const alpha = 0.1;  // Коэффициент сглаживания
    
    for (const [metric, value] of Object.entries(newData)) {
      const baseline = profile.baselineMetrics[metric] || value;
      profile.baselineMetrics[metric] = alpha * value + (1 - alpha) * baseline;
    }
  }

  private calculateAnomalyScore(factors: AnomalyFactor[]): number {
    if (factors.length === 0) return 0;
    
    const severityWeights: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 1.0,
      [ThreatSeverity.HIGH]: 0.8,
      [ThreatSeverity.MEDIUM]: 0.5,
      [ThreatSeverity.LOW]: 0.2,
      [ThreatSeverity.INFO]: 0.1
    };
    
    let totalScore = 0;
    
    for (const factor of factors) {
      const weight = severityWeights[factor.severity] || 0.2;
      const normalizedDeviation = Math.min(factor.deviation, 1);
      totalScore += weight * normalizedDeviation * 100;
    }
    
    return Math.min(totalScore, 100);
  }

  private calculateConfidence(factors: AnomalyFactor[]): number {
    if (factors.length === 0) return 0;
    
    // Уверенность растет с количеством факторов
    const baseConfidence = Math.min(factors.length * 0.2, 0.6);
    
    // Уверенность растет с серьезностью факторов
    const severityConfidence = factors.reduce((acc, f) => {
      const severityScore: Record<ThreatSeverity, number> = {
        [ThreatSeverity.CRITICAL]: 0.3,
        [ThreatSeverity.HIGH]: 0.25,
        [ThreatSeverity.MEDIUM]: 0.15,
        [ThreatSeverity.LOW]: 0.05,
        [ThreatSeverity.INFO]: 0.01
      };
      return acc + (severityScore[f.severity] || 0);
    }, 0);
    
    return Math.min(baseConfidence + severityConfidence, 0.95);
  }
}

/**
 * Детектор аномалий для хостов
 */
class HostAnomalyDetector implements IAnomalyDetector {
  constructor(private config: UEBAConfig) {}

  detect(profile: BehaviorProfile, currentBehavior: Record<string, number>): AnomalyResult {
    const hostProfile = profile as HostProfile;
    const anomalyFactors: AnomalyFactor[] = [];
    
    // Проверка использования CPU
    if (currentBehavior.cpuUsage !== undefined) {
      const baseline = hostProfile.averageCPUUsage;
      const current = currentBehavior.cpuUsage;
      
      if (baseline > 0 && current > baseline * 2) {
        anomalyFactors.push({
          metric: 'cpuUsage',
          expectedValue: baseline,
          actualValue: current,
          deviation: (current - baseline) / baseline,
          severity: current > 90 ? ThreatSeverity.HIGH : ThreatSeverity.MEDIUM,
          description: `Аномально высокое использование CPU: ${current}% (база: ${baseline}%)`
        });
      }
    }
    
    // Проверка использования памяти
    if (currentBehavior.memoryUsage !== undefined) {
      const baseline = hostProfile.averageMemoryUsage;
      const current = currentBehavior.memoryUsage;
      
      if (baseline > 0 && current > baseline * 1.5) {
        anomalyFactors.push({
          metric: 'memoryUsage',
          expectedValue: baseline,
          actualValue: current,
          deviation: (current - baseline) / baseline,
          severity: current > 90 ? ThreatSeverity.HIGH : ThreatSeverity.MEDIUM,
          description: `Аномально высокое использование памяти: ${current}% (база: ${baseline}%)`
        });
      }
    }
    
    // Проверка сетевого трафика
    if (currentBehavior.networkTraffic !== undefined) {
      const baseline = hostProfile.averageNetworkTraffic;
      const current = currentBehavior.networkTraffic;
      
      if (baseline > 0 && current > baseline * 3) {
        anomalyFactors.push({
          metric: 'networkTraffic',
          expectedValue: baseline,
          actualValue: current,
          deviation: (current - baseline) / baseline,
          severity: ThreatSeverity.HIGH,
          description: `Аномально высокий сетевой трафик: ${current} байт/с (база: ${baseline} байт/с)`
        });
      }
    }
    
    // Проверка новых процессов
    if (currentBehavior.newProcesses !== undefined && currentBehavior.newProcesses > 0) {
      anomalyFactors.push({
        metric: 'newProcesses',
        expectedValue: 0,
        actualValue: currentBehavior.newProcesses,
        deviation: 1,
        severity: ThreatSeverity.MEDIUM,
        description: `Запуск новых процессов: ${currentBehavior.newProcesses}`
      });
    }
    
    const anomalyScore = this.calculateAnomalyScore(anomalyFactors);
    const isAnomaly = anomalyScore >= this.config.riskThresholds.medium;
    
    return {
      isAnomaly,
      anomalyScore,
      anomalyFactors,
      confidence: this.calculateConfidence(anomalyFactors)
    };
  }

  updateBaseline(profile: BehaviorProfile, newData: Record<string, number>): void {
    const alpha = 0.1;
    
    for (const [metric, value] of Object.entries(newData)) {
      const baseline = profile.baselineMetrics[metric] || value;
      profile.baselineMetrics[metric] = alpha * value + (1 - alpha) * baseline;
    }
  }

  private calculateAnomalyScore(factors: AnomalyFactor[]): number {
    if (factors.length === 0) return 0;
    
    const severityWeights: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 1.0,
      [ThreatSeverity.HIGH]: 0.8,
      [ThreatSeverity.MEDIUM]: 0.5,
      [ThreatSeverity.LOW]: 0.2,
      [ThreatSeverity.INFO]: 0.1
    };
    
    let totalScore = 0;
    
    for (const factor of factors) {
      const weight = severityWeights[factor.severity] || 0.2;
      const normalizedDeviation = Math.min(factor.deviation, 1);
      totalScore += weight * normalizedDeviation * 100;
    }
    
    return Math.min(totalScore, 100);
  }

  private calculateConfidence(factors: AnomalyFactor[]): number {
    if (factors.length === 0) return 0;
    
    const baseConfidence = Math.min(factors.length * 0.2, 0.6);
    
    const severityConfidence = factors.reduce((acc, f) => {
      const severityScore: Record<ThreatSeverity, number> = {
        [ThreatSeverity.CRITICAL]: 0.3,
        [ThreatSeverity.HIGH]: 0.25,
        [ThreatSeverity.MEDIUM]: 0.15,
        [ThreatSeverity.LOW]: 0.05,
        [ThreatSeverity.INFO]: 0.01
      };
      return acc + (severityScore[f.severity] || 0);
    }, 0);
    
    return Math.min(baseConfidence + severityConfidence, 0.95);
  }
}

/**
 * Детектор аномалий для сервисов
 */
class ServiceAnomalyDetector implements IAnomalyDetector {
  constructor(private config: UEBAConfig) {}

  detect(profile: BehaviorProfile, currentBehavior: Record<string, number>): AnomalyResult {
    const anomalyFactors: AnomalyFactor[] = [];
    
    // Проверка количества запросов
    if (currentBehavior.requestCount !== undefined) {
      const baseline = profile.baselineMetrics.requestCount || 0;
      const current = currentBehavior.requestCount;
      
      if (baseline > 0 && (current > baseline * 3 || current < baseline * 0.3)) {
        anomalyFactors.push({
          metric: 'requestCount',
          expectedValue: baseline,
          actualValue: current,
          deviation: Math.abs(current - baseline) / baseline,
          severity: ThreatSeverity.MEDIUM,
          description: `Аномальное количество запросов: ${current} (база: ${baseline})`
        });
      }
    }
    
    // Проверка времени ответа
    if (currentBehavior.responseTime !== undefined) {
      const baseline = profile.baselineMetrics.responseTime || 0;
      const current = currentBehavior.responseTime;
      
      if (baseline > 0 && current > baseline * 2) {
        anomalyFactors.push({
          metric: 'responseTime',
          expectedValue: baseline,
          actualValue: current,
          deviation: (current - baseline) / baseline,
          severity: ThreatSeverity.MEDIUM,
          description: `Аномальное время ответа: ${current}мс (база: ${baseline}мс)`
        });
      }
    }
    
    // Проверка ошибок
    if (currentBehavior.errorRate !== undefined) {
      const baseline = profile.baselineMetrics.errorRate || 0;
      const current = currentBehavior.errorRate;
      
      if (current > 0.1) {  // Более 10% ошибок
        anomalyFactors.push({
          metric: 'errorRate',
          expectedValue: baseline,
          actualValue: current,
          deviation: current,
          severity: ThreatSeverity.HIGH,
          description: `Высокий уровень ошибок: ${(current * 100).toFixed(1)}%`
        });
      }
    }
    
    const anomalyScore = this.calculateAnomalyScore(anomalyFactors);
    const isAnomaly = anomalyScore >= this.config.riskThresholds.medium;
    
    return {
      isAnomaly,
      anomalyScore,
      anomalyFactors,
      confidence: this.calculateConfidence(anomalyFactors)
    };
  }

  updateBaseline(profile: BehaviorProfile, newData: Record<string, number>): void {
    const alpha = 0.1;
    
    for (const [metric, value] of Object.entries(newData)) {
      const baseline = profile.baselineMetrics[metric] || value;
      profile.baselineMetrics[metric] = alpha * value + (1 - alpha) * baseline;
    }
  }

  private calculateAnomalyScore(factors: AnomalyFactor[]): number {
    if (factors.length === 0) return 0;
    
    const severityWeights: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 1.0,
      [ThreatSeverity.HIGH]: 0.8,
      [ThreatSeverity.MEDIUM]: 0.5,
      [ThreatSeverity.LOW]: 0.2,
      [ThreatSeverity.INFO]: 0.1
    };
    
    let totalScore = 0;
    
    for (const factor of factors) {
      const weight = severityWeights[factor.severity] || 0.2;
      const normalizedDeviation = Math.min(factor.deviation, 1);
      totalScore += weight * normalizedDeviation * 100;
    }
    
    return Math.min(totalScore, 100);
  }

  private calculateConfidence(factors: AnomalyFactor[]): number {
    if (factors.length === 0) return 0;
    
    const baseConfidence = Math.min(factors.length * 0.2, 0.6);
    
    const severityConfidence = factors.reduce((acc, f) => {
      const severityScore: Record<ThreatSeverity, number> = {
        [ThreatSeverity.CRITICAL]: 0.3,
        [ThreatSeverity.HIGH]: 0.25,
        [ThreatSeverity.MEDIUM]: 0.15,
        [ThreatSeverity.LOW]: 0.05,
        [ThreatSeverity.INFO]: 0.01
      };
      return acc + (severityScore[f.severity] || 0);
    }, 0);
    
    return Math.min(baseConfidence + severityConfidence, 0.95);
  }
}

/**
 * Общий детектор аномалий
 */
class GenericAnomalyDetector implements IAnomalyDetector {
  constructor(private config: UEBAConfig) {}

  detect(profile: BehaviorProfile, currentBehavior: Record<string, number>): AnomalyResult {
    const anomalyFactors: AnomalyFactor[] = [];
    
    // Общее обнаружение отклонений метрик
    for (const [metric, value] of Object.entries(currentBehavior)) {
      const baseline = profile.baselineMetrics[metric] || 0;
      
      if (baseline > 0) {
        const deviation = Math.abs(value - baseline) / baseline;
        
        if (deviation > 1) {  // Более 100% отклонение
          anomalyFactors.push({
            metric,
            expectedValue: baseline,
            actualValue: value,
            deviation,
            severity: deviation > 3 ? ThreatSeverity.HIGH : ThreatSeverity.MEDIUM,
            description: `Аномалия метрики ${metric}: ${value} (база: ${baseline})`
          });
        }
      }
    }
    
    const anomalyScore = this.calculateAnomalyScore(anomalyFactors);
    const isAnomaly = anomalyScore >= this.config.riskThresholds.medium;
    
    return {
      isAnomaly,
      anomalyScore,
      anomalyFactors,
      confidence: this.calculateConfidence(anomalyFactors)
    };
  }

  updateBaseline(profile: BehaviorProfile, newData: Record<string, number>): void {
    const alpha = 0.1;
    
    for (const [metric, value] of Object.entries(newData)) {
      const baseline = profile.baselineMetrics[metric] || value;
      profile.baselineMetrics[metric] = alpha * value + (1 - alpha) * baseline;
    }
  }

  private calculateAnomalyScore(factors: AnomalyFactor[]): number {
    if (factors.length === 0) return 0;
    
    const severityWeights: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 1.0,
      [ThreatSeverity.HIGH]: 0.8,
      [ThreatSeverity.MEDIUM]: 0.5,
      [ThreatSeverity.LOW]: 0.2,
      [ThreatSeverity.INFO]: 0.1
    };
    
    let totalScore = 0;
    
    for (const factor of factors) {
      const weight = severityWeights[factor.severity] || 0.2;
      const normalizedDeviation = Math.min(factor.deviation, 1);
      totalScore += weight * normalizedDeviation * 100;
    }
    
    return Math.min(totalScore, 100);
  }

  private calculateConfidence(factors: AnomalyFactor[]): number {
    if (factors.length === 0) return 0;
    
    const baseConfidence = Math.min(factors.length * 0.2, 0.6);
    
    const severityConfidence = factors.reduce((acc, f) => {
      const severityScore: Record<ThreatSeverity, number> = {
        [ThreatSeverity.CRITICAL]: 0.3,
        [ThreatSeverity.HIGH]: 0.25,
        [ThreatSeverity.MEDIUM]: 0.15,
        [ThreatSeverity.LOW]: 0.05,
        [ThreatSeverity.INFO]: 0.01
      };
      return acc + (severityScore[f.severity] || 0);
    }, 0);
    
    return Math.min(baseConfidence + severityConfidence, 0.95);
  }
}

/**
 * Статистика UEBA
 */
interface UEBAStatistics {
  totalProfiles: number;
  anomaliesDetected: number;
  falsePositives: number;
  truePositives: number;
  lastUpdated: Date;
}
