/**
 * ============================================================================
 * RISK SCORER
 * Движок расчета и приоритизации рисков для security alerts
 * ============================================================================
 */

import {
  RiskScore,
  RiskFactors,
  RiskCalculation,
  RiskAdjustment,
  RiskWeights,
  PrioritizedAlert,
  SecurityAlert,
  ThreatSeverity,
  ThreatStatus,
  EntityType,
  AlertEntity,
  KillChainAnalysis,
  MitreAttackInfo
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Конфигурация Risk Scorer
 */
interface RiskScorerConfig {
  weights: RiskWeights;
  thresholds: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  adjustments: RiskAdjustment[];
  entityCriticality: Map<string, number>;
  timeDecayFactor: number;
}

/**
 * Контекст для расчета риска
 */
interface RiskContext {
  timeOfDay: number;  // 0-23
  dayOfWeek: number;  // 0-6
  isBusinessHours: boolean;
  isWeekend: boolean;
  networkZone: string;
  geographicLocation: string;
  threatLandscape: ThreatLandscapeLevel;
}

/**
 * Уровень угрозы в ландшафте
 */
type ThreatLandscapeLevel = 'low' | 'moderate' | 'elevated' | 'high' | 'critical';

/**
 * ============================================================================
 * RISK SCORER CLASS
 * ============================================================================
 */
export class RiskScorer {
  private config: RiskScorerConfig;
  private entityRiskCache: Map<string, { score: number; timestamp: Date }> = new Map();
  private calculationHistory: RiskCalculationRecord[] = [];
  private maxHistorySize: number = 1000;
  
  // Статистика
  private statistics: RiskScorerStatistics = {
    totalCalculations: 0,
    averageRiskScore: 0,
    riskDistribution: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    },
    lastUpdated: new Date()
  };

  constructor(config?: Partial<RiskScorerConfig>) {
    // Конфигурация по умолчанию
    this.config = {
      weights: config?.weights || {
        entity: 0.25,
        threat: 0.30,
        impact: 0.30,
        context: 0.15
      },
      thresholds: config?.thresholds || {
        low: 20,
        medium: 40,
        high: 60,
        critical: 80
      },
      adjustments: config?.adjustments || [],
      entityCriticality: config?.entityCriticality || new Map([
        ['domain_controller', 95],
        ['database_server', 90],
        ['file_server', 75],
        ['web_server', 70],
        ['workstation', 40],
        ['guest_device', 30]
      ]),
      timeDecayFactor: config?.timeDecayFactor || 0.95
    };
    
    console.log('[RiskScorer] Инициализация завершена');
    console.log(`[RiskScorer] Веса: Entity=${this.config.weights.entity}, Threat=${this.config.weights.threat}, Impact=${this.config.weights.impact}, Context=${this.config.weights.context}`);
  }

  // ============================================================================
  // ОСНОВНОЙ РАСЧЕТ РИСКА
  // ============================================================================

  /**
   * Расчет риска для алерта
   */
  calculateRisk(alert: SecurityAlert, context?: Partial<RiskContext>): RiskScore {
    const riskContext = this.buildContext(context);
    
    // Расчет факторных рисков
    const factors = this.calculateRiskFactors(alert, riskContext);
    
    // Нормализация факторов
    const normalizedScores = this.normalizeFactors(factors);
    
    // Применение весов
    const weightedScores = this.applyWeights(normalizedScores);
    
    // Расчет базового риска
    let baseRisk = this.calculateBaseRisk(weightedScores);
    
    // Применение корректировок
    const adjustments = this.applyAdjustments(alert, riskContext, baseRisk);
    baseRisk += adjustments.total;
    
    // Применение временного затухания
    const timeDecayedRisk = this.applyTimeDecay(alert, baseRisk);
    
    // Ограничение 0-100
    const overallRisk = Math.min(Math.max(timeDecayedRisk, 0), 100);
    
    // Создание объекта RiskScore
    const riskScore: RiskScore = {
      overall: Math.round(overallRisk),
      entity: Math.round(normalizedScores.entity * 100),
      threat: Math.round(normalizedScores.threat * 100),
      impact: Math.round(normalizedScores.impact * 100),
      context: Math.round(normalizedScores.context * 100),
      factors,
      calculation: {
        formula: this.getFormula(),
        weights: { ...this.config.weights },
        normalizedScores,
        adjustments: adjustments.items
      },
      timestamp: new Date()
    };
    
    // Обновление статистики
    this.updateStatistics(riskScore);
    
    // Сохранение в историю
    this.saveCalculation(alert.id, riskScore);
    
    return riskScore;
  }

  /**
   * Приоритизация алерта
   */
  prioritizeAlert(alert: SecurityAlert, context?: Partial<RiskContext>): PrioritizedAlert {
    const riskScore = this.calculateRisk(alert, context);
    
    // Определение приоритета (1-5, где 1 - наивысший)
    const priority = this.determinePriority(riskScore.overall);
    
    // Расчет SLA времени ответа
    const slaResponseTime = this.calculateSLA(priority);
    
    // Оценка воздействия
    const estimatedImpact = this.estimateImpact(riskScore, alert);
    
    // Рекомендуемые действия
    const recommendedActions = this.getRecommendedActions(alert, riskScore);
    
    const prioritizedAlert: PrioritizedAlert = {
      ...alert,
      riskScore,
      priority,
      slaResponseTime,
      estimatedImpact,
      recommendedActions
    };
    
    return prioritizedAlert;
  }

  /**
   * Пакетная приоритизация алертов
   */
  prioritizeAlerts(alerts: SecurityAlert[], context?: Partial<RiskContext>): PrioritizedAlert[] {
    const prioritized = alerts.map(alert => this.prioritizeAlert(alert, context));
    
    // Сортировка по приоритету (1 - наивысший)
    prioritized.sort((a, b) => a.priority - b.priority);
    
    return prioritized;
  }

  // ============================================================================
  // РАСЧЕТ ФАКТОРОВ РИСКА
  // ============================================================================

  /**
   * Расчет факторов риска
   */
  private calculateRiskFactors(alert: SecurityAlert, context: RiskContext): RiskFactors {
    return {
      entityRisk: this.calculateEntityRiskFactors(alert, context),
      threatRisk: this.calculateThreatRiskFactors(alert, context),
      impactRisk: this.calculateImpactRiskFactors(alert, context),
      contextRisk: this.calculateContextRiskFactors(alert, context)
    };
  }

  /**
   * Факторы риска сущности
   */
  private calculateEntityRiskFactors(alert: SecurityAlert, context: RiskContext): RiskFactors['entityRisk'] {
    let criticality = 50;
    let exposure = 50;
    let vulnerability = 50;
    
    // Анализ сущностей в алерте
    for (const entity of alert.entities) {
      // Критичность на основе типа сущности
      const entityCriticality = this.getEntityCriticality(entity);
      criticality = Math.max(criticality, entityCriticality);
      
      // Экспозиция на основе роли
      if (entity.role === 'victim') {
        exposure = Math.max(exposure, 70);
      } else if (entity.role === 'attacker') {
        exposure = Math.max(exposure, 50);
      }
      
      // Уязвимость на основе контекста
      vulnerability = this.calculateEntityVulnerability(entity);
    }
    
    // Кэширование риска сущности
    for (const entity of alert.entities) {
      const entityRisk = (criticality + exposure + vulnerability) / 3;
      this.entityRiskCache.set(entity.id, {
        score: entityRisk,
        timestamp: new Date()
      });
    }
    
    return { criticality, exposure, vulnerability };
  }

  /**
   * Получение критичности сущности
   */
  private getEntityCriticality(entity: AlertEntity): number {
    // Проверка кэша
    const cached = this.entityRiskCache.get(entity.id);
    if (cached && (Date.now() - cached.timestamp.getTime()) < 5 * 60 * 1000) {
      return cached.score;
    }
    
    // Определение по типу и контексту
    const entityType = entity.type.toLowerCase();
    
    if (entityType.includes('domain') || entityType.includes('controller')) {
      return 95;
    }
    if (entityType.includes('database')) {
      return 90;
    }
    if (entityType.includes('server')) {
      return 75;
    }
    if (entityType.includes('workstation')) {
      return 40;
    }
    
    // Проверка по имени
    const name = entity.name.toLowerCase();
    
    for (const [key, criticality] of this.config.entityCriticality.entries()) {
      if (name.includes(key)) {
        return criticality;
      }
    }
    
    return 50;  // По умолчанию
  }

  /**
   * Расчет уязвимости сущности
   */
  private calculateEntityVulnerability(entity: AlertEntity): number {
    let vulnerability = 50;
    
    // Увеличение уязвимости на основе контекста
    if (entity.context?.outdatedSoftware) {
      vulnerability += 20;
    }
    if (entity.context?.missingPatches) {
      vulnerability += 15;
    }
    if (entity.context?.weakCredentials) {
      vulnerability += 25;
    }
    if (entity.context?.openPorts && (entity.context.openPorts as number[]).length > 5) {
      vulnerability += 10;
    }
    
    return Math.min(vulnerability, 100);
  }

  /**
   * Факторы риска угрозы
   */
  private calculateThreatRiskFactors(alert: SecurityAlert, context: RiskContext): RiskFactors['threatRisk'] {
    // Серьезность на основе типа алерта
    const severityScores: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 95,
      [ThreatSeverity.HIGH]: 75,
      [ThreatSeverity.MEDIUM]: 50,
      [ThreatSeverity.LOW]: 25,
      [ThreatSeverity.INFO]: 10
    };
    
    const severity = severityScores[alert.severity] || 50;
    
    // Уверенность на основе confidence алерта
    const confidence = alert.confidence * 100;
    
    // Достоверность источника
    let credibility = 70;
    
    if (alert.source === 'UEBA') {
      credibility = 75;
    } else if (alert.source === 'ThreatIntelligence') {
      credibility = 85;
    } else if (alert.source === 'CorrelationEngine') {
      credibility = 80;
    } else if (alert.source === 'ML') {
      credibility = 70;
    }
    
    // Увеличение за наличие MITRE маппинга
    if (alert.mitreAttack?.techniques && alert.mitreAttack.techniques.length > 0) {
      credibility += 10;
    }
    
    // Увеличение за Kill Chain прогресс
    if (alert.mitreAttack?.killChainPhase) {
      credibility += 5;
    }
    
    return {
      severity: Math.min(severity, 100),
      confidence: Math.min(confidence, 100),
      credibility: Math.min(credibility, 100)
    };
  }

  /**
   * Факторы риска воздействия
   */
  private calculateImpactRiskFactors(alert: SecurityAlert, context: RiskContext): RiskFactors['impactRisk'] {
    // Базовые значения CIA
    let confidentiality = 50;
    let integrity = 50;
    let availability = 50;
    
    // Определение на основе категории и типа атаки
    const attackType = alert.attackType?.toLowerCase() || '';
    const category = alert.category?.toLowerCase() || '';
    
    // Воздействие на конфиденциальность
    if (attackType.includes('exfil') || category.includes('collection') || attackType.includes('steal')) {
      confidentiality = 90;
    }
    
    // Воздействие на целостность
    if (attackType.includes('modify') || attackType.includes('tamper') || attackType.includes('ransomware')) {
      integrity = 90;
    }
    
    // Воздействие на доступность
    if (attackType.includes('ddos') || attackType.includes('encrypt') || attackType.includes('delete')) {
      availability = 90;
    }
    
    // Финансовое воздействие (оценка)
    let financial = 30;
    
    if (alert.entities.some(e => e.context?.financialValue === 'high')) {
      financial = 80;
    } else if (alert.entities.some(e => e.context?.financialValue === 'medium')) {
      financial = 50;
    }
    
    // Репутационное воздействие
    let reputational = 20;
    
    if (alert.severity === ThreatSeverity.CRITICAL) {
      reputational = 70;
    } else if (alert.severity === ThreatSeverity.HIGH) {
      reputational = 50;
    }
    
    return {
      confidentiality,
      integrity,
      availability,
      financial,
      reputational
    };
  }

  /**
   * Факторы контекстного риска
   */
  private calculateContextRiskFactors(alert: SecurityAlert, context: RiskContext): RiskFactors['contextRisk'] {
    // Риск времени суток
    let timeOfDay = 30;
    
    if (!context.isBusinessHours) {
      timeOfDay = 60;  // Вне рабочего времени - выше риск
    }
    
    if (context.timeOfDay >= 0 && context.timeOfDay <= 6) {
      timeOfDay = 70;  // Ночное время
    }
    
    // Географический риск
    let location = 30;
    
    const highRiskLocations = ['CN', 'RU', 'KP', 'IR'];
    if (context.geographicLocation && highRiskLocations.includes(context.geographicLocation)) {
      location = 70;
    }
    
    // Риск сетевой зоны
    let networkZone = 30;
    
    if (context.networkZone === 'dmz') {
      networkZone = 60;
    } else if (context.networkZone === 'external') {
      networkZone = 70;
    } else if (context.networkZone === 'internal') {
      networkZone = 40;
    }
    
    // Аномалия поведения (из UEBA)
    let userBehavior = 30;
    
    for (const entity of alert.entities) {
      if (entity.context?.anomalyScore) {
        userBehavior = Math.max(userBehavior, (entity.context.anomalyScore as number) * 100);
      }
    }
    
    // Увеличение за текущий ландшафт угроз
    const threatLandscapeMultiplier = this.getThreatLandscapeMultiplier(context.threatLandscape);
    
    return {
      timeOfDay: Math.min(timeOfDay * threatLandscapeMultiplier, 100),
      location: Math.min(location * threatLandscapeMultiplier, 100),
      networkZone: Math.min(networkZone * threatLandscapeMultiplier, 100),
      userBehavior: Math.min(userBehavior * threatLandscapeMultiplier, 100)
    };
  }

  // ============================================================================
  // НОРМАЛИЗАЦИЯ И ВЗВЕШИВАНИЕ
  // ============================================================================

  /**
   * Нормализация факторов
   */
  private normalizeFactors(factors: RiskFactors): Record<string, number> {
    // Entity risk (среднее по подфакторам)
    const entityRisk = (
      factors.entityRisk.criticality +
      factors.entityRisk.exposure +
      factors.entityRisk.vulnerability
    ) / 3 / 100;
    
    // Threat risk (среднее по подфакторам)
    const threatRisk = (
      factors.threatRisk.severity * 0.5 +
      factors.threatRisk.confidence * 0.3 +
      factors.threatRisk.credibility * 0.2
    ) / 100;
    
    // Impact risk (среднее CIA + финансовое + репутационное)
    const impactRisk = (
      factors.impactRisk.confidentiality * 0.3 +
      factors.impactRisk.integrity * 0.3 +
      factors.impactRisk.availability * 0.2 +
      factors.impactRisk.financial * 0.1 +
      factors.impactRisk.reputational * 0.1
    ) / 100;
    
    // Context risk (среднее по подфакторам)
    const contextRisk = (
      factors.contextRisk.timeOfDay +
      factors.contextRisk.location +
      factors.contextRisk.networkZone +
      factors.contextRisk.userBehavior
    ) / 4 / 100;
    
    return { entity: entityRisk, threat: threatRisk, impact: impactRisk, context: contextRisk };
  }

  /**
   * Применение весов
   */
  private applyWeights(normalizedScores: Record<string, number>): Record<string, number> {
    return {
      entity: normalizedScores.entity * this.config.weights.entity,
      threat: normalizedScores.threat * this.config.weights.threat,
      impact: normalizedScores.impact * this.config.weights.impact,
      context: normalizedScores.context * this.config.weights.context
    };
  }

  /**
   * Расчет базового риска
   */
  private calculateBaseRisk(weightedScores: Record<string, number>): number {
    // Сумма взвешенных скорингов
    const baseRisk = Object.values(weightedScores).reduce((a, b) => a + b, 0);
    
    // Нормализация к 0-100
    const maxPossibleRisk = Object.values(this.config.weights).reduce((a, b) => a + b, 0);
    
    return (baseRisk / maxPossibleRisk) * 100;
  }

  // ============================================================================
  // КОРРЕКТИРОВКИ
  // ============================================================================

  /**
   * Применение корректировок
   */
  private applyAdjustments(alert: SecurityAlert, context: RiskContext, baseRisk: number): {
    total: number;
    items: RiskAdjustment[];
  } {
    const adjustments: RiskAdjustment[] = [];
    let totalAdjustment = 0;
    
    // Корректировка за критичность цели
    for (const entity of alert.entities) {
      if (entity.role === 'victim') {
        const criticality = this.getEntityCriticality(entity);
        
        if (criticality >= 90) {
          adjustments.push({
            factor: 'critical_asset',
            adjustment: 15,
            reason: `Критичный актив: ${entity.name}`
          });
          totalAdjustment += 15;
        } else if (criticality >= 70) {
          adjustments.push({
            factor: 'high_value_asset',
            adjustment: 10,
            reason: `Ценный актив: ${entity.name}`
          });
          totalAdjustment += 10;
        }
      }
    }
    
    // Корректировка за время
    if (!context.isBusinessHours) {
      adjustments.push({
        factor: 'off_hours',
        adjustment: 5,
        reason: 'Событие вне рабочего времени'
      });
      totalAdjustment += 5;
    }
    
    // Корректировка за выходные
    if (context.isWeekend) {
      adjustments.push({
        factor: 'weekend',
        adjustment: 5,
        reason: 'Событие в выходной день'
      });
      totalAdjustment += 5;
    }
    
    // Корректировка за ландшафт угроз
    const landscapeAdjustment = this.getThreatLandscapeAdjustment(context.threatLandscape);
    if (landscapeAdjustment !== 0) {
      adjustments.push({
        factor: 'threat_landscape',
        adjustment: landscapeAdjustment,
        reason: `Текущий уровень угроз: ${context.threatLandscape}`
      });
      totalAdjustment += landscapeAdjustment;
    }
    
    // Корректировка за повторяющиеся алерты
    const isRepeat = this.isRepeatAlert(alert);
    if (isRepeat) {
      adjustments.push({
        factor: 'repeat_alert',
        adjustment: 10,
        reason: 'Повторяющийся алерт'
      });
      totalAdjustment += 10;
    }
    
    // Применение пользовательских корректировок
    for (const customAdjustment of this.config.adjustments) {
      if (this.shouldApplyAdjustment(alert, customAdjustment)) {
        adjustments.push(customAdjustment);
        totalAdjustment += customAdjustment.adjustment;
      }
    }
    
    return { total: totalAdjustment, items: adjustments };
  }

  /**
   * Применение временного затухания
   */
  private applyTimeDecay(alert: SecurityAlert, risk: number): number {
    const alertAge = Date.now() - alert.timestamp.getTime();
    const ageInHours = alertAge / (1000 * 60 * 60);
    
    // Затухание: риск уменьшается со временем
    const decayMultiplier = Math.pow(this.config.timeDecayFactor, ageInHours);
    
    return risk * decayMultiplier;
  }

  // ============================================================================
  // ПРИОРИТИЗАЦИЯ
  // ============================================================================

  /**
   * Определение приоритета
   */
  private determinePriority(riskScore: number): number {
    if (riskScore >= this.config.thresholds.critical) {
      return 1;  // Критический
    }
    if (riskScore >= this.config.thresholds.high) {
      return 2;  // Высокий
    }
    if (riskScore >= this.config.thresholds.medium) {
      return 3;  // Средний
    }
    if (riskScore >= this.config.thresholds.low) {
      return 4;  // Низкий
    }
    return 5;  // Информационный
  }

  /**
   * Расчет SLA времени ответа
   */
  private calculateSLA(priority: number): number {
    const slaMap: Record<number, number> = {
      1: 15,   // Критический - 15 минут
      2: 60,   // Высокий - 1 час
      3: 240,  // Средний - 4 часа
      4: 1440, // Низкий - 24 часа
      5: 4320  // Информационный - 3 дня
    };
    
    return slaMap[priority] || 1440;
  }

  /**
   * Оценка воздействия
   */
  private estimateImpact(riskScore: RiskScore, alert: SecurityAlert): string {
    const impacts: string[] = [];
    
    // Воздействие на основе risk factors
    if (riskScore.factors.impactRisk.confidentiality >= 70) {
      impacts.push('Утечка конфиденциальных данных');
    }
    if (riskScore.factors.impactRisk.integrity >= 70) {
      impacts.push('Компрометация целостности данных');
    }
    if (riskScore.factors.impactRisk.availability >= 70) {
      impacts.push('Нарушение доступности сервисов');
    }
    if (riskScore.factors.impactRisk.financial >= 70) {
      impacts.push('Финансовые потери');
    }
    if (riskScore.factors.impactRisk.reputational >= 70) {
      impacts.push('Репутационный ущерб');
    }
    
    // Воздействие на основе сущностей
    const criticalEntities = alert.entities.filter(e => this.getEntityCriticality(e) >= 80);
    if (criticalEntities.length > 0) {
      impacts.push(`Затронуты критичные активы: ${criticalEntities.map(e => e.name).join(', ')}`);
    }
    
    return impacts.join('; ') || 'Минимальное воздействие';
  }

  /**
   * Рекомендуемые действия
   */
  private getRecommendedActions(alert: SecurityAlert, riskScore: RiskScore): string[] {
    const actions: string[] = [];
    
    // Действия на основе серьезности
    if (alert.severity === ThreatSeverity.CRITICAL) {
      actions.push('Немедленная эскалация в SOC');
      actions.push('Изоляция затронутых систем');
      actions.push('Активация incident response playbook');
    } else if (alert.severity === ThreatSeverity.HIGH) {
      actions.push('Эскалация старшему аналитику');
      actions.push('Сбор дополнительной информации');
      actions.push('Подготовка к изоляции систем');
    }
    
    // Действия на основе типа атаки
    if (alert.attackType?.includes('ransomware')) {
      actions.push('Проверка бэкапов');
      actions.push('Блокировка распространения');
    }
    
    if (alert.attackType?.includes('exfil')) {
      actions.push('Анализ сетевого трафика');
      actions.push('Проверка DLP логов');
    }
    
    // Действия на основе risk factors
    if (riskScore.factors.contextRisk.userBehavior >= 70) {
      actions.push('Проверка активности пользователя');
      actions.push('Анализ UEBA профиля');
    }
    
    if (actions.length === 0) {
      actions.push('Стандартное расследование');
      actions.push('Документирование инцидента');
    }
    
    return actions;
  }

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Построение контекста
   */
  private buildContext(context?: Partial<RiskContext>): RiskContext {
    const now = new Date();
    const hour = now.getHours();
    const dayOfWeek = now.getDay();
    
    const isBusinessHours = dayOfWeek !== 0 && dayOfWeek !== 6 && hour >= 9 && hour <= 18;
    const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
    
    return {
      timeOfDay: hour,
      dayOfWeek,
      isBusinessHours: context?.isBusinessHours ?? isBusinessHours,
      isWeekend: context?.isWeekend ?? isWeekend,
      networkZone: context?.networkZone ?? 'internal',
      geographicLocation: context?.geographicLocation ?? '',
      threatLandscape: context?.threatLandscape ?? 'moderate'
    };
  }

  /**
   * Множитель ландшафта угроз
   */
  private getThreatLandscapeMultiplier(level: ThreatLandscapeLevel): number {
    const multipliers: Record<ThreatLandscapeLevel, number> = {
      low: 0.8,
      moderate: 1.0,
      elevated: 1.2,
      high: 1.4,
      critical: 1.6
    };
    
    return multipliers[level] || 1.0;
  }

  /**
   * Корректировка ландшафта угроз
   */
  private getThreatLandscapeAdjustment(level: ThreatLandscapeLevel): number {
    const adjustments: Record<ThreatLandscapeLevel, number> = {
      low: -5,
      moderate: 0,
      elevated: 5,
      high: 10,
      critical: 15
    };
    
    return adjustments[level] || 0;
  }

  /**
   * Проверка повторяющегося алерта
   */
  private isRepeatAlert(alert: SecurityAlert): boolean {
    // Проверка истории вычислений
    const recentCalculations = this.calculationHistory.filter(
      c => c.alertId !== alert.id &&
           (Date.now() - c.timestamp.getTime()) < 60 * 60 * 1000  // За последний час
    );
    
    // Проверка на схожесть с предыдущими алертами
    for (const calc of recentCalculations) {
      if (calc.riskScore.overall >= 70) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Проверка применения корректировки
   */
  private shouldApplyAdjustment(alert: SecurityAlert, adjustment: RiskAdjustment): boolean {
    // Простая реализация - всегда применяем пользовательские корректировки
    // В полной реализации здесь была бы логика проверки условий
    return true;
  }

  /**
   * Получение формулы расчета
   */
  private getFormula(): string {
    return 'Risk = (Entity * 0.25 + Threat * 0.30 + Impact * 0.30 + Context * 0.15) + Adjustments';
  }

  // ============================================================================
  // СТАТИСТИКА И ИСТОРИЯ
  // ============================================================================

  /**
   * Обновление статистики
   */
  private updateStatistics(riskScore: RiskScore): void {
    this.statistics.totalCalculations++;
    
    // Обновление распределения
    if (riskScore.overall >= this.config.thresholds.critical) {
      this.statistics.riskDistribution.critical++;
    } else if (riskScore.overall >= this.config.thresholds.high) {
      this.statistics.riskDistribution.high++;
    } else if (riskScore.overall >= this.config.thresholds.medium) {
      this.statistics.riskDistribution.medium++;
    } else {
      this.statistics.riskDistribution.low++;
    }
    
    // Обновление среднего
    const totalRisk = this.statistics.averageRiskScore * (this.statistics.totalCalculations - 1) + riskScore.overall;
    this.statistics.averageRiskScore = totalRisk / this.statistics.totalCalculations;
    
    this.statistics.lastUpdated = new Date();
  }

  /**
   * Сохранение вычисления в историю
   */
  private saveCalculation(alertId: string, riskScore: RiskScore): void {
    const record: RiskCalculationRecord = {
      alertId,
      riskScore,
      timestamp: new Date()
    };
    
    this.calculationHistory.push(record);
    
    // Ограничение размера истории
    if (this.calculationHistory.length > this.maxHistorySize) {
      this.calculationHistory.shift();
    }
  }

  /**
   * Получение статистики
   */
  getStatistics(): RiskScorerStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }

  /**
   * Получение истории вычислений
   */
  getCalculationHistory(limit: number = 100): RiskCalculationRecord[] {
    return this.calculationHistory.slice(-limit);
  }

  /**
   * Получение риска сущности
   */
  getEntityRisk(entityId: string): number {
    const cached = this.entityRiskCache.get(entityId);
    
    if (cached) {
      // Применение затухания
      const age = (Date.now() - cached.timestamp.getTime()) / (1000 * 60 * 60);
      const decayedScore = cached.score * Math.pow(this.config.timeDecayFactor, age);
      
      return Math.round(decayedScore);
    }
    
    return 0;
  }

  /**
   * Сброс кэша сущностей
   */
  clearEntityCache(): void {
    this.entityRiskCache.clear();
    console.log('[RiskScorer] Кэш сущностей очищен');
  }

  /**
   * Обновление конфигурации
   */
  updateConfig(newConfig: Partial<RiskScorerConfig>): void {
    this.config = { ...this.config, ...newConfig };
    console.log('[RiskScorer] Конфигурация обновлена');
  }
}

/**
 * Запись вычисления риска
 */
interface RiskCalculationRecord {
  alertId: string;
  riskScore: RiskScore;
  timestamp: Date;
}

/**
 * Статистика Risk Scorer
 */
interface RiskScorerStatistics {
  totalCalculations: number;
  averageRiskScore: number;
  riskDistribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  lastUpdated: Date;
}
