/**
 * ============================================================================
 * CORRELATION ENGINE
 * Движок корреляции событий для обнаружения multi-stage атак
 * ============================================================================
 */

import {
  CorrelationRule,
  CorrelationCondition,
  CorrelatedEvent,
  SecurityEvent,
  SecurityAlert,
  ThreatSeverity,
  ThreatCategory,
  AttackType,
  MitreAttackInfo,
  MitreTactic,
  MitreTechnique,
  KillChainPhase,
  KillChainAnalysis
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Окно корреляции для хранения событий
 */
interface CorrelationWindow {
  ruleId: string;
  events: SecurityEvent[];
  startTime: Date;
  lastActivity: Date;
  groupByKey: string;
}

/**
 * Результат оценки правила
 */
interface RuleEvaluationResult {
  ruleId: string;
  matched: boolean;
  matchedEvents: SecurityEvent[];
  confidence: number;
}

/**
 * ============================================================================
 * CORRELATION ENGINE CLASS
 * ============================================================================
 */
export class CorrelationEngine {
  private rules: Map<string, CorrelationRule> = new Map();
  private windows: Map<string, CorrelationWindow[]> = new Map();
  private correlatedEvents: Map<string, CorrelatedEvent> = new Map();
  private eventBuffer: Map<string, SecurityEvent[]> = new Map();
  
  // Конфигурация
  private windowSize: number = 300;  // 5 минут в секундах
  private maxEventsPerWindow: number = 1000;
  private maxBufferSize: number = 10000;
  
  // Статистика
  private statistics: CorrelationStatistics = {
    totalEventsProcessed: 0,
    totalCorrelations: 0,
    rulesTriggered: new Map<string, number>(),
    falsePositives: 0,
    truePositives: 0,
    lastUpdated: new Date()
  };

  constructor(config?: {
    windowSize?: number;
    maxEventsPerWindow?: number;
  }) {
    if (config?.windowSize) {
      this.windowSize = config.windowSize;
    }
    if (config?.maxEventsPerWindow) {
      this.maxEventsPerWindow = config.maxEventsPerWindow;
    }
    
    console.log('[CorrelationEngine] Инициализация завершена');
    console.log(`[CorrelationEngine] Размер окна: ${this.windowSize} секунд`);
    console.log(`[CorrelationEngine] Максимум событий в окне: ${this.maxEventsPerWindow}`);
  }

  // ============================================================================
  // УПРАВЛЕНИЕ ПРАВИЛАМИ
  // ============================================================================

  /**
   * Добавление правила корреляции
   */
  addRule(rule: CorrelationRule): void {
    this.rules.set(rule.id, rule);
    this.windows.set(rule.id, []);
    
    console.log(`[CorrelationEngine] Добавлено правило: ${rule.name} (${rule.id})`);
  }

  /**
   * Удаление правила
   */
  removeRule(ruleId: string): void {
    this.rules.delete(ruleId);
    this.windows.delete(ruleId);
    
    console.log(`[CorrelationEngine] Удалено правило: ${ruleId}`);
  }

  /**
   * Получение всех правил
   */
  getRules(): CorrelationRule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Включение/выключение правила
   */
  toggleRule(ruleId: string, enabled: boolean): void {
    const rule = this.rules.get(ruleId);
    
    if (rule) {
      rule.enabled = enabled;
      this.rules.set(ruleId, rule);
    }
  }

  // ============================================================================
  // ОБРАБОТКА СОБЫТИЙ
  // ============================================================================

  /**
   * Обработка события
   */
  processEvent(event: SecurityEvent): SecurityAlert[] {
    this.statistics.totalEventsProcessed++;
    
    // Добавление события в буфер
    this.addToBuffer(event);
    
    const alerts: SecurityAlert[] = [];
    
    // Проверка всех активных правил
    for (const rule of this.rules.values()) {
      if (!rule.enabled) {
        continue;
      }
      
      // Проверка соответствия события правилу
      if (this.eventMatchesRule(event, rule)) {
        // Добавление события в окно корреляции
        this.addToWindow(rule, event);
        
        // Оценка правила
        const result = this.evaluateRule(rule);
        
        if (result.matched) {
          // Создание коррелированного события
          const correlatedEvent = this.createCorrelatedEvent(rule, result.matchedEvents);
          
          // Создание алерта
          const alert = this.createAlert(correlatedEvent);
          alerts.push(alert);
          
          // Сброс окна после срабатывания
          this.resetWindow(rule.id);
          
          // Обновление статистики
          this.statistics.totalCorrelations++;
          const currentCount = this.statistics.rulesTriggered.get(rule.id) || 0;
          this.statistics.rulesTriggered.set(rule.id, currentCount + 1);
        }
      }
    }
    
    // Очистка старых окон
    this.cleanupWindows();
    
    return alerts;
  }

  /**
   * Пакетная обработка событий
   */
  processEvents(events: SecurityEvent[]): SecurityAlert[] {
    const allAlerts: SecurityAlert[] = [];
    
    for (const event of events) {
      const alerts = this.processEvent(event);
      allAlerts.push(...alerts);
    }
    
    return allAlerts;
  }

  /**
   * Добавление события в буфер
   */
  private addToBuffer(event: SecurityEvent): void {
    const sourceKey = event.sourceIp || event.hostname || 'unknown';
    
    let buffer = this.eventBuffer.get(sourceKey);
    
    if (!buffer) {
      buffer = [];
      this.eventBuffer.set(sourceKey, buffer);
    }
    
    buffer.push(event);
    
    // Ограничение размера буфера
    if (buffer.length > this.maxBufferSize) {
      buffer.shift();
    }
  }

  /**
   * Проверка соответствия события правилу
   */
  private eventMatchesRule(event: SecurityEvent, rule: CorrelationRule): boolean {
    // Проверка условий правила
    for (const condition of rule.conditions) {
      const eventValue = this.getEventFieldValue(event, condition.field);
      
      if (!this.evaluateCondition(eventValue, condition)) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Получение значения поля события
   */
  private getEventFieldValue(event: SecurityEvent, field: string): any {
    const fields = field.split('.');
    let value: any = event;
    
    for (const f of fields) {
      if (value === null || value === undefined) {
        return undefined;
      }
      value = (value as any)[f];
    }
    
    return value;
  }

  /**
   * Оценка условия
   */
  private evaluateCondition(value: any, condition: CorrelationCondition): boolean {
    if (value === undefined) {
      return false;
    }
    
    switch (condition.operator) {
      case 'eq':
        return value === condition.value;
      case 'ne':
        return value !== condition.value;
      case 'gt':
        return Number(value) > Number(condition.value);
      case 'lt':
        return Number(value) < Number(condition.value);
      case 'contains':
        return String(value).includes(String(condition.value));
      case 'regex':
        return new RegExp(condition.value as string).test(String(value));
      default:
        return false;
    }
  }

  /**
   * Добавление события в окно корреляции
   */
  private addToWindow(rule: CorrelationRule, event: SecurityEvent): void {
    const groupByKey = this.getGroupKey(event, rule.groupBy);
    
    let windows = this.windows.get(rule.id);
    
    if (!windows) {
      windows = [];
      this.windows.set(rule.id, windows);
    }
    
    // Поиск существующего окна для этой группы
    let window = windows.find(w => w.groupByKey === groupByKey);
    
    if (!window) {
      // Создание нового окна
      window = {
        ruleId: rule.id,
        events: [],
        startTime: event.timestamp,
        lastActivity: event.timestamp,
        groupByKey
      };
      windows.push(window);
    }
    
    // Добавление события в окно
    window.events.push(event);
    window.lastActivity = event.timestamp;
    
    // Ограничение количества событий в окне
    if (window.events.length > this.maxEventsPerWindow) {
      window.events.shift();
    }
  }

  /**
   * Получение ключа группировки
   */
  private getGroupKey(event: SecurityEvent, groupBy: string[]): string {
    return groupBy.map(field => this.getEventFieldValue(event, field)).join('|') || 'default';
  }

  // ============================================================================
  // ОЦЕНКА ПРАВИЛ
  // ============================================================================

  /**
   * Оценка правила на предмет срабатывания
   */
  private evaluateRule(rule: CorrelationRule): RuleEvaluationResult {
    const windows = this.windows.get(rule.id) || [];
    const matchedEvents: SecurityEvent[] = [];
    let totalConfidence = 0;
    
    for (const window of windows) {
      // Проверка временного окна
      const windowDuration = (window.lastActivity.getTime() - window.startTime.getTime()) / 1000;
      
      if (windowDuration > rule.timeWindow) {
        continue;  // Окно истекло
      }
      
      // Проверка количества событий
      if (window.events.length >= rule.minEvents) {
        // Проверка последовательности если требуется
        if (rule.conditions.some(c => c.sequence)) {
          if (this.checkSequence(window.events, rule)) {
            matchedEvents.push(...window.events);
            totalConfidence += this.calculateConfidence(window.events, rule);
          }
        } else {
          matchedEvents.push(...window.events);
          totalConfidence += this.calculateConfidence(window.events, rule);
        }
      }
    }
    
    return {
      ruleId: rule.id,
      matched: matchedEvents.length >= rule.minEvents,
      matchedEvents,
      confidence: matchedEvents.length > 0 ? totalConfidence / matchedEvents.length : 0
    };
  }

  /**
   * Проверка последовательности событий
   */
  private checkSequence(events: SecurityEvent[], rule: CorrelationRule): boolean {
    const sequenceOrder = rule.conditions.find(c => c.sequenceOrder)?.sequenceOrder;
    
    if (!sequenceOrder || sequenceOrder.length === 0) {
      return true;
    }
    
    // Проверка порядка событий
    const eventTypes = events.map(e => e.eventType);
    
    let lastIndex = -1;
    
    for (const expectedType of sequenceOrder) {
      const index = eventTypes.indexOf(expectedType);
      
      if (index === -1 || index <= lastIndex) {
        return false;
      }
      
      lastIndex = index;
    }
    
    return true;
  }

  /**
   * Расчет уверенности в корреляции
   */
  private calculateConfidence(events: SecurityEvent[], rule: CorrelationRule): number {
    let confidence = 0.5;  // Базовая уверенность
    
    // Увеличение уверенности за количество событий
    const eventFactor = Math.min(events.length / rule.minEvents, 2) * 0.2;
    confidence += eventFactor;
    
    // Увеличение уверенности за серьезность событий
    const severityWeights: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 0.15,
      [ThreatSeverity.HIGH]: 0.12,
      [ThreatSeverity.MEDIUM]: 0.08,
      [ThreatSeverity.LOW]: 0.03,
      [ThreatSeverity.INFO]: 0.01
    };
    
    for (const event of events) {
      confidence += severityWeights[event.severity] || 0.01;
    }
    
    // Увеличение уверенности за временную близость
    if (events.length >= 2) {
      const timeSpan = (events[events.length - 1].timestamp.getTime() - events[0].timestamp.getTime()) / 1000;
      const expectedSpan = rule.timeWindow / 2;
      
      if (timeSpan < expectedSpan) {
        confidence += 0.1;
      }
    }
    
    return Math.min(confidence, 0.95);
  }

  // ============================================================================
  // СОЗДАНИЕ КОРРЕЛИРОВАННЫХ СОБЫТИЙ
  // ============================================================================

  /**
   * Создание коррелированного события
   */
  private createCorrelatedEvent(rule: CorrelationRule, events: SecurityEvent[]): CorrelatedEvent {
    const startTime = events[0].timestamp;
    const endTime = events[events.length - 1].timestamp;
    
    const uniqueSources = new Set(events.map(e => e.sourceIp || e.hostname).filter(Boolean));
    const uniqueTargets = new Set(events.map(e => e.destinationIp).filter(Boolean));
    
    // Определение серьезности
    let severity = ThreatSeverity.LOW;
    const severities = events.map(e => e.severity);
    
    if (severities.includes(ThreatSeverity.CRITICAL)) {
      severity = ThreatSeverity.CRITICAL;
    } else if (severities.includes(ThreatSeverity.HIGH)) {
      severity = ThreatSeverity.HIGH;
    } else if (severities.includes(ThreatSeverity.MEDIUM)) {
      severity = ThreatSeverity.MEDIUM;
    }
    
    // Маппинг на MITRE ATT&CK
    const mitreAttack = this.mapToMitre(rule, events);
    
    // Анализ Kill Chain
    const killChainAnalysis = this.analyzeKillChain(events);
    
    const correlatedEvent: CorrelatedEvent = {
      id: uuidv4(),
      ruleId: rule.id,
      ruleName: rule.name,
      events,
      startTime,
      endTime,
      eventCount: events.length,
      uniqueSources: Array.from(uniqueSources),
      uniqueTargets: Array.from(uniqueTargets),
      severity,
      mitreAttack,
      killChainAnalysis
    };
    
    this.correlatedEvents.set(correlatedEvent.id, correlatedEvent);
    
    return correlatedEvent;
  }

  /**
   * Маппинг на MITRE ATT&CK
   */
  private mapToMitre(rule: CorrelationRule, events: SecurityEvent[]): MitreAttackInfo {
    const tactics: MitreTactic[] = [];
    const techniques: MitreTechnique[] = [];
    
    // В реальной реализации здесь был бы маппинг на основе правил и событий
    // Для демонстрации создадим заглушки
    
    return {
      tactics,
      techniques,
      killChainPhase: this.determineKillChainPhase(events),
      threatGroups: []
    };
  }

  /**
   * Определение Kill Chain фазы
   */
  private determineKillChainPhase(events: SecurityEvent[]): KillChainPhase | undefined {
    // Анализ типов событий для определения фазы
    const eventTypes = events.map(e => e.eventType.toLowerCase());
    
    if (eventTypes.some(t => t.includes('recon') || t.includes('scan') || t.includes('discovery'))) {
      return KillChainPhase.RECONNAISSANCE;
    }
    
    if (eventTypes.some(t => t.includes('exploit') || t.includes('delivery'))) {
      return KillChainPhase.DELIVERY;
    }
    
    if (eventTypes.some(t => t.includes('install') || t.includes('persist'))) {
      return KillChainPhase.INSTALLATION;
    }
    
    if (eventTypes.some(t => t.includes('c2') || t.includes('beacon') || t.includes('callback'))) {
      return KillChainPhase.COMMAND_AND_CONTROL;
    }
    
    if (eventTypes.some(t => t.includes('exfil') || t.includes('steal'))) {
      return KillChainPhase.ACTIONS_ON_OBJECTIVES;
    }
    
    return undefined;
  }

  /**
   * Анализ Kill Chain
   */
  private analyzeKillChain(events: SecurityEvent[]): KillChainAnalysis | undefined {
    const phases: KillChainPhase[] = [];
    const indicators: Array<{ phase: KillChainPhase; indicatorType: string; value: string; confidence: number; timestamp: Date }> = [];
    
    for (const event of events) {
      const phase = this.determineKillChainPhase([event]);
      
      if (phase) {
        if (!phases.includes(phase)) {
          phases.push(phase);
        }
        
        indicators.push({
          phase,
          indicatorType: event.eventType,
          value: event.sourceIp || event.hostname || 'unknown',
          confidence: 0.8,
          timestamp: event.timestamp
        });
      }
    }
    
    if (phases.length === 0) {
      return undefined;
    }
    
    // Сортировка фаз по порядку Kill Chain
    const phaseOrder = Object.values(KillChainPhase);
    phases.sort((a, b) => phaseOrder.indexOf(a) - phaseOrder.indexOf(b));
    
    const currentPhase = phases[phases.length - 1];
    const completedPhases = phases;
    
    // Расчет прогрессии
    const progression = (completedPhases.length / 7) * 100;
    
    // Оценка времени до цели
    const estimatedTimeToObjective = Math.max(0, (7 - completedPhases.length) * 30);  // 30 минут на фазу
    
    return {
      attackId: uuidv4(),
      phases,
      currentPhase,
      completedPhases,
      indicators,
      progression,
      estimatedTimeToObjective
    };
  }

  // ============================================================================
  // СОЗДАНИЕ АЛЕРТОВ
  // ============================================================================

  /**
   * Создание алерта из коррелированного события
   */
  private createAlert(correlatedEvent: CorrelatedEvent): SecurityAlert {
    // Формирование описания
    const description = this.generateAlertDescription(correlatedEvent);
    
    // Определение серьезности
    const severity = correlatedEvent.severity;
    
    // Создание алерта
    const alert: SecurityAlert = {
      id: uuidv4(),
      timestamp: new Date(),
      title: `Корреляция: ${correlatedEvent.ruleName}`,
      description,
      severity,
      status: 'new',
      category: ThreatCategory.UNKNOWN,
      attackType: AttackType.UNKNOWN,
      source: 'CorrelationEngine',
      ruleId: correlatedEvent.ruleId,
      ruleName: correlatedEvent.ruleName,
      events: correlatedEvent.events,
      entities: this.extractEntities(correlatedEvent),
      mitreAttack: correlatedEvent.mitreAttack,
      riskScore: this.calculateAlertRiskScore(correlatedEvent),
      confidence: correlatedEvent.events.length > 0 ? 
        (correlatedEvent.events.reduce((acc, e) => acc + (e.severity === ThreatSeverity.CRITICAL ? 1 : 0), 0) / correlatedEvent.events.length) : 0,
      falsePositiveProbability: 0.3,
      investigationStatus: {
        stage: 'triage',
        progress: 0,
        findings: [],
        evidenceCollected: []
      },
      assignedTo: undefined,
      tags: ['correlation', 'multi-stage'],
      timeline: correlatedEvent.events.map(e => ({
        timestamp: e.timestamp,
        event: e.eventType,
        details: e.description
      })),
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

  /**
   * Генерация описания алерта
   */
  private generateAlertDescription(correlatedEvent: CorrelatedEvent): string {
    const { events, ruleName, eventCount } = correlatedEvent;
    
    const timeSpan = (correlatedEvent.endTime.getTime() - correlatedEvent.startTime.getTime()) / 1000;
    
    const sources = correlatedEvent.uniqueSources.join(', ');
    const targets = correlatedEvent.uniqueTargets.join(', ');
    
    return `Правило "${ruleName}" сработало: обнаружено ${eventCount} связанных событий ` +
           `за ${timeSpan} секунд. ` +
           `Источники: ${sources}. Цели: ${targets || 'N/A'}.`;
  }

  /**
   * Извлечение сущностей из коррелированного события
   */
  private extractEntities(correlatedEvent: CorrelatedEvent): any[] {
    const entities: any[] = [];
    
    // Добавление источников как сущностей
    for (const source of correlatedEvent.uniqueSources) {
      entities.push({
        id: uuidv4(),
        type: 'host',
        name: source,
        value: source,
        riskScore: 50,
        role: 'source',
        context: {}
      });
    }
    
    // Добавление целей как сущностей
    for (const target of correlatedEvent.uniqueTargets) {
      entities.push({
        id: uuidv4(),
        type: 'host',
        name: target,
        value: target,
        riskScore: 70,
        role: 'target',
        context: {}
      });
    }
    
    return entities;
  }

  /**
   * Расчет risk score для алерта
   */
  private calculateAlertRiskScore(correlatedEvent: CorrelatedEvent): number {
    let score = 30;  // Базовый риск
    
    // Увеличение за количество событий
    score += Math.min(correlatedEvent.eventCount * 5, 20);
    
    // Увеличение за серьезность
    const severityBonus: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 30,
      [ThreatSeverity.HIGH]: 20,
      [ThreatSeverity.MEDIUM]: 10,
      [ThreatSeverity.LOW]: 5,
      [ThreatSeverity.INFO]: 0
    };
    score += severityBonus[correlatedEvent.severity];
    
    // Увеличение за Kill Chain прогресс
    if (correlatedEvent.killChainAnalysis) {
      score += correlatedEvent.killChainAnalysis.progression * 0.3;
    }
    
    // Увеличение за количество уникальных источников
    score += Math.min(correlatedEvent.uniqueSources.length * 5, 10);
    
    return Math.min(score, 100);
  }

  // ============================================================================
  // УПРАВЛЕНИЕ ОКНАМИ
  // ============================================================================

  /**
   * Сброс окна правила
   */
  private resetWindow(ruleId: string): void {
    this.windows.set(ruleId, []);
  }

  /**
   * Очистка старых окон
   */
  private cleanupWindows(): void {
    const now = Date.now();
    
    for (const [ruleId, windows] of this.windows.entries()) {
      const rule = this.rules.get(ruleId);
      
      if (!rule) {
        continue;
      }
      
      // Удаление окон, неактивных более чем windowSize
      const validWindows = windows.filter(w => {
        const inactiveTime = (now - w.lastActivity.getTime()) / 1000;
        return inactiveTime < rule.timeWindow;
      });
      
      this.windows.set(ruleId, validWindows);
    }
  }

  // ============================================================================
  // СТАТИСТИКА И МОНИТОРИНГ
  // ============================================================================

  /**
   * Получение статистики
   */
  getStatistics(): CorrelationStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }

  /**
   * Получение коррелированных событий
   */
  getCorrelatedEvents(limit: number = 100): CorrelatedEvent[] {
    return Array.from(this.correlatedEvents.values()).slice(-limit);
  }

  /**
   * Получение активных окон
   */
  getActiveWindows(): { ruleId: string; windowCount: number; totalEvents: number }[] {
    const result: { ruleId: string; windowCount: number; totalEvents: number }[] = [];
    
    for (const [ruleId, windows] of this.windows.entries()) {
      const totalEvents = windows.reduce((acc, w) => acc + w.events.length, 0);
      
      if (windows.length > 0) {
        result.push({
          ruleId,
          windowCount: windows.length,
          totalEvents
        });
      }
    }
    
    return result;
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

  /**
   * Получение правил с наибольшим количеством срабатываний
   */
  getTopTriggeredRules(limit: number = 10): { ruleId: string; ruleName: string; count: number }[] {
    const rules = Array.from(this.statistics.rulesTriggered.entries())
      .map(([ruleId, count]) => {
        const rule = this.rules.get(ruleId);
        return {
          ruleId,
          ruleName: rule?.name || 'Unknown',
          count
        };
      })
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);
    
    return rules;
  }
}

/**
 * Статистика корреляции
 */
interface CorrelationStatistics {
  totalEventsProcessed: number;
  totalCorrelations: number;
  rulesTriggered: Map<string, number>;
  falsePositives: number;
  truePositives: number;
  lastUpdated: Date;
}
