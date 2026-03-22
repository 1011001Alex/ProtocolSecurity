/**
 * ============================================================================
 * KILL CHAIN ANALYZER
 * Анализ и отслеживание прогрессии атаки по Kill Chain
 * ============================================================================
 */

import {
  KillChainPhase,
  KillChainAnalysis,
  KillChainIndicator,
  SecurityEvent,
  SecurityAlert,
  MitreTactic,
  MitreTechnique,
  ThreatSeverity
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Конфигурация Kill Chain Analyzer
 */
interface KillChainAnalyzerConfig {
  phaseTimeout: number;  // мс до считания фазы завершенной
  progressionWeights: Record<KillChainPhase, number>;
}

/**
 * Состояние Kill Chain для атаки
 */
interface KillChainState {
  attackId: string;
  phases: Map<KillChainPhase, PhaseState>;
  currentPhase: KillChainPhase;
  startTime: Date;
  lastActivity: Date;
  events: SecurityEvent[];
  indicators: KillChainIndicator[];
  confidence: number;
  isComplete: boolean;
}

/**
 * Состояние фазы
 */
interface PhaseState {
  phase: KillChainPhase;
  enteredAt: Date;
  exitedAt?: Date;
  events: SecurityEvent[];
  indicators: KillChainIndicator[];
  confidence: number;
  isComplete: boolean;
}

/**
 * ============================================================================
 * KILL CHAIN ANALYZER CLASS
 * ============================================================================
 */
export class KillChainAnalyzer {
  private config: KillChainAnalyzerConfig;
  
  // Активные Kill Chain
  private activeKillChains: Map<string, KillChainState> = new Map();
  
  // Завершенные Kill Chain
  private completedKillChains: KillChainAnalysis[] = [];
  private maxCompletedChains: number = 1000;
  
  // Маппинг событий на фазы
  private eventPhaseMapping: Map<string, KillChainPhase> = new Map();
  
  // Статистика
  private statistics: KillChainStatistics = {
    totalChainsTracked: 0,
    chainsByPhase: new Map(),
    averageProgression: 0,
    averageTimeToComplete: 0,
    lastUpdated: new Date()
  };

  constructor(config?: Partial<KillChainAnalyzerConfig>) {
    this.config = {
      phaseTimeout: config?.phaseTimeout || 30 * 60 * 1000,  // 30 минут
      progressionWeights: config?.progressionWeights || {
        [KillChainPhase.RECONNAISSANCE]: 1,
        [KillChainPhase.WEAPONIZATION]: 2,
        [KillChainPhase.DELIVERY]: 3,
        [KillChainPhase.EXPLOITATION]: 4,
        [KillChainPhase.INSTALLATION]: 5,
        [KillChainPhase.COMMAND_AND_CONTROL]: 6,
        [KillChainPhase.ACTIONS_ON_OBJECTIVES]: 7
      }
    };
    
    this.initializeEventPhaseMapping();
    
    console.log('[KillChainAnalyzer] Инициализация завершена');
  }

  // ============================================================================
  // ИНИЦИАЛИЗАЦИЯ
  // ============================================================================

  /**
   * Инициализация маппинга событий на фазы
   */
  private initializeEventPhaseMapping(): void {
    // Reconnaissance
    const reconEvents = [
      'network_scan', 'port_scan', 'service_discovery', 'dns_query',
      'whois_lookup', 'subdomain_enumeration', 'vulnerability_scan'
    ];
    reconEvents.forEach(e => this.eventPhaseMapping.set(e, KillChainPhase.RECONNAISSANCE));
    
    // Weaponization
    const weaponizationEvents = [
      'malware_compile', 'exploit_create', 'payload_generate',
      'c2_infrastructure_setup', 'domain_registration'
    ];
    weaponizationEvents.forEach(e => this.eventPhaseMapping.set(e, KillChainPhase.WEAPONIZATION));
    
    // Delivery
    const deliveryEvents = [
      'phishing_email', 'malicious_attachment', 'drive_by_download',
      'usb_insert', 'supply_chain_delivery'
    ];
    deliveryEvents.forEach(e => this.eventPhaseMapping.set(e, KillChainPhase.DELIVERY));
    
    // Exploitation
    const exploitationEvents = [
      'exploit_attempt', 'vulnerability_exploit', 'code_execution',
      'buffer_overflow', 'sql_injection', 'xss_attack'
    ];
    exploitationEvents.forEach(e => this.eventPhaseMapping.set(e, KillChainPhase.EXPLOITATION));
    
    // Installation
    const installationEvents = [
      'malware_install', 'persistence_create', 'registry_modify',
      'scheduled_task_create', 'service_install', 'backdoor_install'
    ];
    installationEvents.forEach(e => this.eventPhaseMapping.set(e, KillChainPhase.INSTALLATION));
    
    // Command and Control
    const c2Events = [
      'c2_beacon', 'c2_callback', 'dns_tunnel', 'encrypted_channel',
      'http_c2', 'domain_generation'
    ];
    c2Events.forEach(e => this.eventPhaseMapping.set(e, KillChainPhase.COMMAND_AND_CONTROL));
    
    // Actions on Objectives
    const objectivesEvents = [
      'data_exfiltration', 'data_encryption', 'credential_dump',
      'lateral_movement', 'privilege_escalation', 'data_destruction'
    ];
    objectivesEvents.forEach(e => this.eventPhaseMapping.set(e, KillChainPhase.ACTIONS_ON_OBJECTIVES));
  }

  // ============================================================================
  // АНАЛИЗ СОБЫТИЙ
  // ============================================================================

  /**
   * Обработка события
   */
  processEvent(event: SecurityEvent): KillChainUpdate | null {
    // Определение фазы для события
    const phase = this.determinePhaseForEvent(event);
    
    if (!phase) {
      return null;  // Событие не относится к Kill Chain
    }
    
    // Поиск или создание Kill Chain
    const chainId = this.getChainId(event);
    let chain = this.activeKillChains.get(chainId);
    
    if (!chain) {
      // Создание новой Kill Chain
      chain = this.createKillChain(chainId, event, phase);
    }
    
    // Обновление Kill Chain
    const update = this.updateKillChain(chain, event, phase);
    
    // Проверка завершения
    if (chain.isComplete) {
      this.completeKillChain(chain);
    }
    
    return update;
  }

  /**
   * Обработка алерта
   */
  processAlert(alert: SecurityAlert): KillChainAnalysis | null {
    // Обработка всех событий алерта
    let chainAnalysis: KillChainAnalysis | null = null;
    
    for (const event of alert.events) {
      const update = this.processEvent(event);
      
      if (update?.killChainAnalysis) {
        chainAnalysis = update.killChainAnalysis;
      }
    }
    
    return chainAnalysis;
  }

  /**
   * Определение фазы для события
   */
  private determinePhaseForEvent(event: SecurityEvent): KillChainPhase | null {
    // Проверка прямого маппинга
    const mappedPhase = this.eventPhaseMapping.get(event.eventType);
    
    if (mappedPhase) {
      return mappedPhase;
    }
    
    // Проверка по MITRE техникам
    if (event.rawEvent.mitreTechniques) {
      const techniques = event.rawEvent.mitreTechniques as string[];
      
      for (const technique of techniques) {
        const phase = this.getPhaseForTechnique(technique);
        if (phase) {
          return phase;
        }
      }
    }
    
    // Проверка по категории
    const categoryPhaseMapping: Record<string, KillChainPhase> = {
      'discovery': KillChainPhase.RECONNAISSANCE,
      'initial_access': KillChainPhase.DELIVERY,
      'execution': KillChainPhase.EXPLOITATION,
      'persistence': KillChainPhase.INSTALLATION,
      'command_and_control': KillChainPhase.COMMAND_AND_CONTROL,
      'exfiltration': KillChainPhase.ACTIONS_ON_OBJECTIVES,
      'impact': KillChainPhase.ACTIONS_ON_OBJECTIVES
    };
    
    const categoryKey = event.category?.toLowerCase();
    if (categoryKey && categoryPhaseMapping[categoryKey]) {
      return categoryPhaseMapping[categoryKey];
    }
    
    return null;
  }

  /**
   * Получение фазы для MITRE техники
   */
  private getPhaseForTechnique(techniqueId: string): KillChainPhase | null {
    // Маппинг популярных техник на фазы
    const techniquePhaseMapping: Record<string, KillChainPhase> = {
      'T1046': KillChainPhase.RECONNAISSANCE,  // Network Service Scanning
      'T1595': KillChainPhase.RECONNAISSANCE,  // Active Scanning
      'T1566': KillChainPhase.DELIVERY,        // Phishing
      'T1190': KillChainPhase.EXPLOITATION,    // Exploit Public-Facing Application
      'T1059': KillChainPhase.EXPLOITATION,    // Command and Scripting Interpreter
      'T1053': KillChainPhase.INSTALLATION,    // Scheduled Task/Job
      'T1547': KillChainPhase.INSTALLATION,    // Boot or Logon Autostart Execution
      'T1071': KillChainPhase.COMMAND_AND_CONTROL,  // Application Layer Protocol
      'T1041': KillChainPhase.ACTIONS_ON_OBJECTIVES,  // Exfiltration Over C2 Channel
      'T1486': KillChainPhase.ACTIONS_ON_OBJECTIVES   // Data Encrypted for Impact
    };
    
    return techniquePhaseMapping[techniqueId] || null;
  }

  /**
   * Получение ID Kill Chain для события
   */
  private getChainId(event: SecurityEvent): string {
    // Генерация ID на основе атрибутов атаки
    const attributes = [
      event.sourceIp,
      event.destinationIp,
      event.userId,
      event.hostname
    ].filter(Boolean);
    
    if (attributes.length === 0) {
      return uuidv4();
    }
    
    return attributes.join('|');
  }

  // ============================================================================
  // УПРАВЛЕНИЕ KILL CHAIN
  // ============================================================================

  /**
   * Создание новой Kill Chain
   */
  private createKillChain(
    chainId: string,
    event: SecurityEvent,
    phase: KillChainPhase
  ): KillChainState {
    const chain: KillChainState = {
      attackId: chainId,
      phases: new Map(),
      currentPhase: phase,
      startTime: event.timestamp,
      lastActivity: event.timestamp,
      events: [],
      indicators: [],
      confidence: 0.5,
      isComplete: false
    };
    
    // Инициализация всех фаз
    const allPhases = Object.values(KillChainPhase);
    
    for (const p of allPhases) {
      chain.phases.set(p, {
        phase: p,
        enteredAt: new Date(),
        events: [],
        indicators: [],
        confidence: 0,
        isComplete: false
      });
    }
    
    // Добавление первого события
    this.addEventToPhase(chain, phase, event);
    
    this.activeKillChains.set(chainId, chain);
    this.statistics.totalChainsTracked++;
    
    console.log(`[KillChainAnalyzer] Создана новая Kill Chain: ${chainId}, фаза: ${phase}`);
    
    return chain;
  }

  /**
   * Обновление Kill Chain
   */
  private updateKillChain(
    chain: KillChainState,
    event: SecurityEvent,
    phase: KillChainPhase
  ): KillChainUpdate {
    // Добавление события
    this.addEventToPhase(chain, phase, event);
    
    // Создание индикатора
    const indicator = this.createIndicator(chain, phase, event);
    chain.indicators.push(indicator);
    
    // Обновление текущей фазы
    const previousPhase = chain.currentPhase;
    
    if (this.shouldAdvancePhase(chain, phase)) {
      chain.currentPhase = phase;
      const phaseState = chain.phases.get(phase);
      
      if (phaseState) {
        phaseState.enteredAt = event.timestamp;
      }
      
      // Отметка предыдущей фазы как завершенной
      const previousPhaseState = chain.phases.get(previousPhase);
      if (previousPhaseState) {
        previousPhaseState.exitedAt = event.timestamp;
        previousPhaseState.isComplete = true;
      }
    }
    
    // Обновление времени активности
    chain.lastActivity = event.timestamp;
    
    // Пересчет уверенности
    chain.confidence = this.calculateChainConfidence(chain);
    
    // Проверка завершения
    chain.isComplete = phase === KillChainPhase.ACTIONS_ON_OBJECTIVES;
    
    // Обновление статистики
    this.updatePhaseStatistics(chain);
    
    return {
      chainId: chain.attackId,
      previousPhase,
      currentPhase: chain.currentPhase,
      phaseAdvanced: previousPhase !== chain.currentPhase,
      killChainAnalysis: this.buildKillChainAnalysis(chain)
    };
  }

  /**
   * Добавление события к фазе
   */
  private addEventToPhase(chain: KillChainState, phase: KillChainPhase, event: SecurityEvent): void {
    const phaseState = chain.phases.get(phase);
    
    if (phaseState) {
      phaseState.events.push(event);
      phaseState.confidence = this.calculatePhaseConfidence(phaseState);
    }
    
    chain.events.push(event);
  }

  /**
   * Создание индикатора
   */
  private createIndicator(
    chain: KillChainState,
    phase: KillChainPhase,
    event: SecurityEvent
  ): KillChainIndicator {
    return {
      phase,
      indicatorType: event.eventType,
      value: event.sourceIp || event.hostname || event.userId || 'unknown',
      confidence: 0.8,
      timestamp: event.timestamp
    };
  }

  /**
   * Проверка необходимости перехода к следующей фазе
   */
  private shouldAdvancePhase(chain: KillChainState, newPhase: KillChainPhase): boolean {
    const currentPhaseIndex = Object.values(KillChainPhase).indexOf(chain.currentPhase);
    const newPhaseIndex = Object.values(KillChainPhase).indexOf(newPhase);
    
    // Переход только вперед
    if (newPhaseIndex <= currentPhaseIndex) {
      return false;
    }
    
    // Проверка минимального количества событий в текущей фазе
    const currentPhaseState = chain.phases.get(chain.currentPhase);
    
    if (currentPhaseState && currentPhaseState.events.length < 2) {
      return false;  // Нужно минимум 2 события для завершения фазы
    }
    
    return true;
  }

  /**
   * Расчет уверенности Kill Chain
   */
  private calculateChainConfidence(chain: KillChainState): number {
    const phaseConfidences: number[] = [];
    
    for (const phaseState of chain.phases.values()) {
      if (phaseState.events.length > 0) {
        phaseConfidences.push(phaseState.confidence);
      }
    }
    
    if (phaseConfidences.length === 0) {
      return 0;
    }
    
    // Среднее с весом на более поздние фазы
    let totalWeight = 0;
    let weightedSum = 0;
    
    const allPhases = Object.values(KillChainPhase);
    
    for (let i = 0; i < allPhases.length; i++) {
      const phase = allPhases[i];
      const phaseState = chain.phases.get(phase);
      
      if (phaseState && phaseState.events.length > 0) {
        const weight = this.config.progressionWeights[phase] || 1;
        weightedSum += phaseState.confidence * weight;
        totalWeight += weight;
      }
    }
    
    return totalWeight > 0 ? weightedSum / totalWeight : 0;
  }

  /**
   * Расчет уверенности фазы
   */
  private calculatePhaseConfidence(phaseState: PhaseState): number {
    const eventCount = phaseState.events.length;
    
    if (eventCount === 0) {
      return 0;
    }
    
    // Базовая уверенность от количества событий
    let confidence = Math.min(eventCount * 0.2, 0.6);
    
    // Увеличение за серьезность событий
    const severityWeights: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 0.15,
      [ThreatSeverity.HIGH]: 0.12,
      [ThreatSeverity.MEDIUM]: 0.08,
      [ThreatSeverity.LOW]: 0.03,
      [ThreatSeverity.INFO]: 0.01
    };
    
    for (const event of phaseState.events) {
      confidence += severityWeights[event.severity] || 0.01;
    }
    
    return Math.min(confidence, 0.95);
  }

  /**
   * Завершение Kill Chain
   */
  private completeKillChain(chain: KillChainState): void {
    const analysis = this.buildKillChainAnalysis(chain);
    
    this.completedKillChains.push(analysis);
    
    // Ограничение размера
    if (this.completedKillChains.length > this.maxCompletedChains) {
      this.completedKillChains.shift();
    }
    
    // Удаление из активных
    this.activeKillChains.delete(chain.attackId);
    
    console.log(`[KillChainAnalyzer] Kill Chain завершена: ${chain.attackId}`);
  }

  // ============================================================================
  // ПОСТРОЕНИЕ АНАЛИЗА
  // ============================================================================

  /**
   * Построение KillChainAnalysis
   */
  private buildKillChainAnalysis(chain: KillChainState): KillChainAnalysis {
    const completedPhases: KillChainPhase[] = [];
    const allPhases = Object.values(KillChainPhase);
    
    for (const phase of allPhases) {
      const phaseState = chain.phases.get(phase);
      
      if (phaseState && phaseState.isComplete) {
        completedPhases.push(phase);
      }
    }
    
    // Расчет прогрессии
    const progression = (completedPhases.length / allPhases.length) * 100;
    
    // Оценка времени до цели
    const elapsed = chain.lastActivity.getTime() - chain.startTime.getTime();
    const estimatedTimeToObjective = chain.isComplete ? 0 : 
      Math.max(0, (allPhases.length - completedPhases.length) * elapsed / completedPhases.length);
    
    return {
      attackId: chain.attackId,
      phases: Array.from(chain.phases.keys()),
      currentPhase: chain.currentPhase,
      completedPhases,
      indicators: chain.indicators,
      progression,
      estimatedTimeToObjective
    };
  }

  /**
   * Обновление статистики фаз
   */
  private updatePhaseStatistics(chain: KillChainState): void {
    const phaseCount = this.statistics.chainsByPhase.get(chain.currentPhase) || 0;
    this.statistics.chainsByPhase.set(chain.currentPhase, phaseCount + 1);
  }

  // ============================================================================
  // ЗАПРОСЫ И АНАЛИЗ
  // ============================================================================

  /**
   * Получение Kill Chain по ID
   */
  getKillChain(chainId: string): KillChainAnalysis | null {
    const chain = this.activeKillChains.get(chainId);
    
    if (chain) {
      return this.buildKillChainAnalysis(chain);
    }
    
    // Поиск в завершенных
    return this.completedKillChains.find(c => c.attackId === chainId) || null;
  }

  /**
   * Получение всех активных Kill Chain
   */
  getActiveKillChains(): KillChainAnalysis[] {
    return Array.from(this.activeKillChains.values()).map(c => this.buildKillChainAnalysis(c));
  }

  /**
   * Получение Kill Chain по фазе
   */
  getKillChainsByPhase(phase: KillChainPhase): KillChainAnalysis[] {
    const results: KillChainAnalysis[] = [];
    
    for (const chain of this.activeKillChains.values()) {
      if (chain.currentPhase === phase) {
        results.push(this.buildKillChainAnalysis(chain));
      }
    }
    
    return results;
  }

  /**
   * Получение высокорисковых Kill Chain
   */
  getHighRiskKillChains(minProgression: number = 50): KillChainAnalysis[] {
    return this.getActiveKillChains().filter(c => c.progression >= minProgression);
  }

  /**
   * Получение статистики
   */
  getStatistics(): KillChainStatistics {
    // Расчет средней прогрессии
    const chains = this.getActiveKillChains();
    const avgProgression = chains.length > 0 
      ? chains.reduce((acc, c) => acc + c.progression, 0) / chains.length 
      : 0;
    
    return {
      ...this.statistics,
      averageProgression: avgProgression,
      lastUpdated: new Date()
    };
  }

  /**
   * Получение завершенных Kill Chain
   */
  getCompletedKillChains(limit: number = 50): KillChainAnalysis[] {
    return this.completedKillChains.slice(-limit);
  }

  /**
   * Очистка старых Kill Chain
   */
  cleanup(timeout: number = 60 * 60 * 1000): number {
    const now = Date.now();
    let removed = 0;
    
    for (const [chainId, chain] of this.activeKillChains.entries()) {
      const inactiveTime = now - chain.lastActivity.getTime();
      
      if (inactiveTime > timeout) {
        // Завершение неактивной цепочки
        this.completeKillChain(chain);
        removed++;
      }
    }
    
    console.log(`[KillChainAnalyzer] Очищено ${removed} неактивных Kill Chain`);
    
    return removed;
  }
}

/**
 * Результат обновления Kill Chain
 */
interface KillChainUpdate {
  chainId: string;
  previousPhase: KillChainPhase;
  currentPhase: KillChainPhase;
  phaseAdvanced: boolean;
  killChainAnalysis: KillChainAnalysis;
}

/**
 * Статистика Kill Chain Analyzer
 */
interface KillChainStatistics {
  totalChainsTracked: number;
  chainsByPhase: Map<KillChainPhase, number>;
  averageProgression: number;
  averageTimeToComplete: number;
  lastUpdated: Date;
}

/**
 * Экспорт основного класса
 */
export { KillChainAnalyzer };
