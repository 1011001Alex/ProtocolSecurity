/**
 * ============================================================================
 * THREAT DASHBOARD
 * Генерация данных для визуализации security мониторинга
 * ============================================================================
 */

import {
  ThreatDashboardData,
  ThreatSummary,
  AlertMetrics,
  ThreatMetrics,
  NetworkMetrics,
  EndpointMetrics,
  UserMetrics,
  TimelineData,
  TopThreat,
  MitreHeatmapData,
  MitreTacticHeatmap,
  MitreTechniqueHeatmap,
  RiskTrendData,
  SecurityAlert,
  PrioritizedAlert,
  ThreatSeverity,
  ThreatStatus,
  ThreatCategory,
  AttackType,
  KillChainPhase,
  MitreTactic,
  MitreTechnique
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Конфигурация Threat Dashboard
 */
interface ThreatDashboardConfig {
  refreshInterval: number;  // мс
  historyHours: number;
  topItemsLimit: number;
  timelineGranularity: 'minute' | 'hour' | 'day';
}

/**
 * Агрегированные метрики за период
 */
interface AggregatedMetrics {
  alerts: SecurityAlert[];
  startTime: Date;
  endTime: Date;
}

/**
 * ============================================================================
 * THREAT DASHBOARD SERVICE
 * ============================================================================
 */
export class ThreatDashboardService {
  private config: ThreatDashboardConfig;
  
  // Кэш данных
  private metricsCache: Map<string, { data: any; timestamp: Date }> = new Map();
  private cacheTTL: number = 30000;  // 30 секунд
  
  // Источники данных (в реальной реализации - ссылки на сервисы)
  private alertsSource: SecurityAlert[] = [];
  private networkMetricsSource: NetworkMetricsData = {
    totalFlows: 0,
    suspiciousFlows: 0,
    blockedConnections: 0,
    anomaliesDetected: 0
  };
  private endpointMetricsSource: EndpointMetricsData = {
    totalEndpoints: 0,
    onlineEndpoints: 0,
    compromisedEndpoints: 0,
    isolatedEndpoints: 0
  };
  private userMetricsSource: UserMetricsData = {
    totalUsers: 0,
    highRiskUsers: 0,
    anomalousBehaviors: 0,
    failedLogins: 0
  };
  
  // Статистика
  private statistics: DashboardStatistics = {
    totalRequests: 0,
    cacheHits: 0,
    cacheMisses: 0,
    averageResponseTime: 0,
    lastUpdated: new Date()
  };

  constructor(config?: Partial<ThreatDashboardConfig>) {
    this.config = {
      refreshInterval: config?.refreshInterval || 60000,
      historyHours: config?.historyHours || 24,
      topItemsLimit: config?.topItemsLimit || 10,
      timelineGranularity: config?.timelineGranularity || 'hour'
    };
    
    console.log('[ThreatDashboard] Инициализация завершена');
  }

  // ============================================================================
  // ПОЛУЧЕНИЕ ДАННЫХ ДАШБОРДА
  // ============================================================================

  /**
   * Получение полных данных дашборда
   */
  async getDashboardData(): Promise<ThreatDashboardData> {
    const startTime = Date.now();
    this.statistics.totalRequests++;
    
    // Проверка кэша
    const cached = this.getCachedData<ThreatDashboardData>('full_dashboard');
    
    if (cached) {
      this.statistics.cacheHits++;
      return cached;
    }
    
    this.statistics.cacheMisses++;
    
    // Сбор данных из всех источников
    const data: ThreatDashboardData = {
      summary: await this.getThreatSummary(),
      alerts: await this.getAlertMetrics(),
      threats: await this.getThreatMetrics(),
      network: await this.getNetworkMetrics(),
      endpoints: await this.getEndpointMetrics(),
      users: await this.getUserMetrics(),
      timeline: await this.getTimelineData(),
      topThreats: await this.getTopThreats(),
      mitreHeatmap: await this.getMitreHeatmap(),
      riskTrend: await this.getRiskTrendData()
    };
    
    // Кэширование
    this.cacheData('full_dashboard', data);
    
    // Обновление статистики
    this.statistics.averageResponseTime = 
      (this.statistics.averageResponseTime * (this.statistics.totalRequests - 1) + 
       (Date.now() - startTime)) / this.statistics.totalRequests;
    
    this.statistics.lastUpdated = new Date();
    
    return data;
  }

  /**
   * Получение summary данных
   */
  async getThreatSummary(): Promise<ThreatSummary> {
    const cached = this.getCachedData<ThreatSummary>('summary');
    if (cached) return cached;
    
    const alerts = this.getRecentAlerts();
    
    const summary: ThreatSummary = {
      totalAlerts: alerts.length,
      newAlerts: alerts.filter(a => a.status === 'new').length,
      criticalAlerts: alerts.filter(a => a.severity === ThreatSeverity.CRITICAL).length,
      highAlerts: alerts.filter(a => a.severity === ThreatSeverity.HIGH).length,
      activeThreats: alerts.filter(a => 
        a.status === 'investigating' || a.status === 'confirmed'
      ).length,
      containedThreats: alerts.filter(a => a.status === 'contained').length,
      falsePositives: alerts.filter(a => a.status === 'false_positive').length,
      meanTimeToDetect: this.calculateMeanTimeToDetect(alerts),
      meanTimeToRespond: this.calculateMeanTimeToRespond(alerts)
    };
    
    this.cacheData('summary', summary);
    return summary;
  }

  /**
   * Получение метрик алертов
   */
  async getAlertMetrics(): Promise<AlertMetrics> {
    const cached = this.getCachedData<AlertMetrics>('alert_metrics');
    if (cached) return cached;
    
    const alerts = this.getRecentAlerts();
    
    // Группировка по серьезности
    const bySeverity: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 0,
      [ThreatSeverity.HIGH]: 0,
      [ThreatSeverity.MEDIUM]: 0,
      [ThreatSeverity.LOW]: 0,
      [ThreatSeverity.INFO]: 0
    };
    
    // Группировка по категориям
    const byCategory: Record<ThreatCategory, number> = {} as any;
    
    // Группировка по статусу
    const byStatus: Record<ThreatStatus, number> = {} as any;
    
    // Группировка по типу атаки
    const byAttackType: Record<AttackType, number> = {} as any;
    
    for (const alert of alerts) {
      bySeverity[alert.severity]++;
      byCategory[alert.category] = (byCategory[alert.category] || 0) + 1;
      byStatus[alert.status] = (byStatus[alert.status] || 0) + 1;
      byAttackType[alert.attackType] = (byAttackType[alert.attackType] || 0) + 1;
    }
    
    // Расчет тренда (сравнение с предыдущим периодом)
    const trend = this.calculateAlertTrend(alerts);
    
    const metrics: AlertMetrics = {
      bySeverity,
      byCategory,
      byStatus,
      byAttackType,
      trend
    };
    
    this.cacheData('alert_metrics', metrics);
    return metrics;
  }

  /**
   * Получение метрик угроз
   */
  async getThreatMetrics(): Promise<ThreatMetrics> {
    const cached = this.getCachedData<ThreatMetrics>('threat_metrics');
    if (cached) return cached;
    
    const alerts = this.getRecentAlerts();
    
    // Активные атаки
    const activeAttacks = alerts.filter(a => 
      a.status === 'investigating' || a.status === 'confirmed'
    ).length;
    
    // Заблокированные атаки
    const blockedAttacks = alerts.filter(a => 
      a.status === 'contained' || a.status === 'remediated'
    ).length;
    
    // Обнаруженные техники
    const detectedTechniques = new Set<string>();
    const threatActors = new Set<string>();
    
    for (const alert of alerts) {
      if (alert.mitreAttack?.techniques) {
        for (const tech of alert.mitreAttack.techniques) {
          detectedTechniques.add(tech.id);
        }
      }
      
      if (alert.mitreAttack?.threatGroups) {
        for (const group of alert.mitreAttack.threatGroups) {
          threatActors.add(group.name);
        }
      }
    }
    
    // Прогресс Kill Chain
    const killChainProgress: Record<KillChainPhase, number> = {
      [KillChainPhase.RECONNAISSANCE]: 0,
      [KillChainPhase.WEAPONIZATION]: 0,
      [KillChainPhase.DELIVERY]: 0,
      [KillChainPhase.EXPLOITATION]: 0,
      [KillChainPhase.INSTALLATION]: 0,
      [KillChainPhase.COMMAND_AND_CONTROL]: 0,
      [KillChainPhase.ACTIONS_ON_OBJECTIVES]: 0
    };
    
    for (const alert of alerts) {
      if (alert.mitreAttack?.killChainPhase) {
        killChainProgress[alert.mitreAttack.killChainPhase]++;
      }
    }
    
    const metrics: ThreatMetrics = {
      activeAttacks,
      blockedAttacks,
      detectedTechniques: Array.from(detectedTechniques),
      threatActors: Array.from(threatActors),
      killChainProgress
    };
    
    this.cacheData('threat_metrics', metrics);
    return metrics;
  }

  /**
   * Получение сетевых метрик
   */
  async getNetworkMetrics(): Promise<NetworkMetrics> {
    const cached = this.getCachedData<NetworkMetrics>('network_metrics');
    if (cached) return cached;
    
    const metrics: NetworkMetrics = {
      totalFlows: this.networkMetricsSource.totalFlows,
      suspiciousFlows: this.networkMetricsSource.suspiciousFlows,
      blockedConnections: this.networkMetricsSource.blockedConnections,
      topTalkers: this.generateTopTalkers(),
      topDestinations: this.generateTopDestinations(),
      anomaliesDetected: this.networkMetricsSource.anomaliesDetected
    };
    
    this.cacheData('network_metrics', metrics);
    return metrics;
  }

  /**
   * Получение метрик endpoint
   */
  async getEndpointMetrics(): Promise<EndpointMetrics> {
    const cached = this.getCachedData<EndpointMetrics>('endpoint_metrics');
    if (cached) return cached;
    
    const alerts = this.getRecentAlerts();
    
    // Группировка событий по типу
    const eventsByType: Record<string, number> = {};
    
    // Топ затронутых endpoint
    const endpointAlerts: Map<string, { count: number; riskScore: number }> = new Map();
    
    for (const alert of alerts) {
      for (const event of alert.events) {
        eventsByType[event.eventType] = (eventsByType[event.eventType] || 0) + 1;
      }
      
      for (const entity of alert.entities) {
        if (entity.type === 'host') {
          const existing = endpointAlerts.get(entity.value) || { count: 0, riskScore: 0 };
          existing.count++;
          existing.riskScore = Math.max(existing.riskScore, entity.riskScore);
          endpointAlerts.set(entity.value, existing);
        }
      }
    }
    
    const topAlertedEndpoints = Array.from(endpointAlerts.entries())
      .map(([endpointId, data]) => ({
        endpointId,
        hostname: endpointId,
        alertCount: data.count,
        riskScore: data.riskScore
      }))
      .sort((a, b) => b.alertCount - a.alertCount)
      .slice(0, this.config.topItemsLimit);
    
    const metrics: EndpointMetrics = {
      totalEndpoints: this.endpointMetricsSource.totalEndpoints,
      onlineEndpoints: this.endpointMetricsSource.onlineEndpoints,
      compromisedEndpoints: this.endpointMetricsSource.compromisedEndpoints,
      isolatedEndpoints: this.endpointMetricsSource.isolatedEndpoints,
      eventsByType: eventsByType as any,
      topAlertedEndpoints
    };
    
    this.cacheData('endpoint_metrics', metrics);
    return metrics;
  }

  /**
   * Получение метрик пользователей
   */
  async getUserMetrics(): Promise<UserMetrics> {
    const cached = this.getCachedData<UserMetrics>('user_metrics');
    if (cached) return cached;
    
    const alerts = this.getRecentAlerts();
    
    // Сбор данных о пользователях
    const userRisks: Map<string, { 
      userId: string; 
      username: string; 
      riskScore: number; 
      anomalyScore: number;
      risks: string[] 
    }> = new Map();
    
    for (const alert of alerts) {
      for (const entity of alert.entities) {
        if (entity.type === 'user') {
          const existing = userRisks.get(entity.value) || {
            userId: entity.value,
            username: entity.name,
            riskScore: 0,
            anomalyScore: 0,
            risks: []
          };
          
          existing.riskScore = Math.max(existing.riskScore, entity.riskScore);
          existing.anomalyScore += 10;
          
          if (alert.attackType) {
            existing.risks.push(alert.attackType);
          }
          
          userRisks.set(entity.value, existing);
        }
      }
    }
    
    const topRiskUsers = Array.from(userRisks.values())
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, this.config.topItemsLimit)
      .map(u => ({
        userId: u.userId,
        username: u.username,
        riskScore: u.riskScore,
        anomalyScore: Math.min(u.anomalyScore, 100),
        topRisks: [...new Set(u.risks)].slice(0, 5)
      }));
    
    const metrics: UserMetrics = {
      totalUsers: this.userMetricsSource.totalUsers,
      highRiskUsers: this.userMetricsSource.highRiskUsers,
      anomalousBehaviors: this.userMetricsSource.anomalousBehaviors,
      failedLogins: this.userMetricsSource.failedLogins,
      privilegeEscalations: alerts.filter(a => 
        a.attackType === AttackType.PRIVILEGE_ESCALATION
      ).length,
      topRiskUsers
    };
    
    this.cacheData('user_metrics', metrics);
    return metrics;
  }

  // ============================================================================
  // TIMELINE И ТРЕНДЫ
  // ============================================================================

  /**
   * Получение данных timeline
   */
  async getTimelineData(): Promise<TimelineData[]> {
    const cached = this.getCachedData<TimelineData[]>('timeline');
    if (cached) return cached;
    
    const alerts = this.getRecentAlerts();
    const granularity = this.config.timelineGranularity;
    
    // Группировка по временным интервалам
    const timeBuckets: Map<string, TimelineData> = new Map();
    
    for (const alert of alerts) {
      const bucketKey = this.getBucketKey(alert.timestamp, granularity);
      
      if (!timeBuckets.has(bucketKey)) {
        timeBuckets.set(bucketKey, {
          timestamp: this.getBucketTimestamp(bucketKey, granularity),
          alerts: 0,
          events: 0,
          blocked: 0,
          critical: 0
        });
      }
      
      const bucket = timeBuckets.get(bucketKey)!;
      bucket.alerts++;
      bucket.events += alert.events.length;
      
      if (alert.status === 'contained' || alert.status === 'remediated') {
        bucket.blocked++;
      }
      
      if (alert.severity === ThreatSeverity.CRITICAL) {
        bucket.critical++;
      }
    }
    
    const timeline = Array.from(timeBuckets.values())
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    
    this.cacheData('timeline', timeline);
    return timeline;
  }

  /**
   * Получение топ угроз
   */
  async getTopThreats(): Promise<TopThreat[]> {
    const cached = this.getCachedData<TopThreat[]>('top_threats');
    if (cached) return cached;
    
    const alerts = this.getRecentAlerts();
    
    // Группировка по типу атаки
    const threatCounts: Map<AttackType, { 
      count: number; 
      severity: ThreatSeverity;
      mitreTechniques: Set<string>
    }> = new Map();
    
    for (const alert of alerts) {
      const attackType = alert.attackType || AttackType.UNKNOWN;
      
      if (!threatCounts.has(attackType)) {
        threatCounts.set(attackType, {
          count: 0,
          severity: alert.severity,
          mitreTechniques: new Set()
        });
      }
      
      const data = threatCounts.get(attackType)!;
      data.count++;
      
      // Обновление серьезности до максимальной
      if (this.isSeverityHigher(alert.severity, data.severity)) {
        data.severity = alert.severity;
      }
      
      // Сбор MITRE техник
      if (alert.mitreAttack?.techniques) {
        for (const tech of alert.mitreAttack.techniques) {
          data.mitreTechniques.add(tech.id);
        }
      }
    }
    
    const topThreats: TopThreat[] = Array.from(threatCounts.entries())
      .map(([type, data]) => ({
        id: uuidv4(),
        name: type,
        type,
        count: data.count,
        severity: data.severity,
        mitreTechniques: Array.from(data.mitreTechniques),
        trend: this.calculateThreatTrend(type, alerts)
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, this.config.topItemsLimit);
    
    this.cacheData('top_threats', topThreats);
    return topThreats;
  }

  /**
   * Получение MITRE heatmap
   */
  async getMitreHeatmap(): Promise<MitreHeatmapData> {
    const cached = this.getCachedData<MitreHeatmapData>('mitre_heatmap');
    if (cached) return cached;
    
    const alerts = this.getRecentAlerts();
    
    // Группировка по тактикам и техникам
    const tacticData: Map<string, {
      tactic: MitreTactic;
      techniques: Map<string, MitreTechniqueHeatmap>
    }> = new Map();
    
    for (const alert of alerts) {
      if (alert.mitreAttack?.techniques) {
        for (const technique of alert.mitreAttack.techniques) {
          // Получение тактики для техники
          const tacticId = this.getTacticForTechnique(technique.id);
          
          if (!tacticData.has(tacticId)) {
            tacticData.set(tacticId, {
              tactic: {
                id: tacticId,
                name: this.getTacticName(tacticId),
                description: '',
                url: ''
              },
              techniques: new Map()
            });
          }
          
          const tactic = tacticData.get(tacticId)!;
          
          if (!tactic.techniques.has(technique.id)) {
            tactic.techniques.set(technique.id, {
              technique: {
                id: technique.id,
                name: technique.name || technique.id,
                description: '',
                url: '',
                tactics: [tacticId],
                platforms: [],
                permissionsRequired: [],
                dataSources: [],
                detection: '',
                mitigation: ''
              },
              count: 0,
              severity: alert.severity,
              lastDetected: alert.timestamp
            });
          }
          
          const techData = tactic.techniques.get(technique.id)!;
          techData.count++;
          
          if (this.isSeverityHigher(alert.severity, techData.severity)) {
            techData.severity = alert.severity;
          }
          
          if (alert.timestamp > techData.lastDetected) {
            techData.lastDetected = alert.timestamp;
          }
        }
      }
    }
    
    const heatmap: MitreHeatmapData = {
      tactics: Array.from(tacticData.values()).map(t => ({
        tactic: t.tactic,
        techniques: Array.from(t.techniques.values())
      }))
    };
    
    this.cacheData('mitre_heatmap', heatmap);
    return heatmap;
  }

  /**
   * Получение risk trend
   */
  async getRiskTrendData(): Promise<RiskTrendData[]> {
    const cached = this.getCachedData<RiskTrendData[]>('risk_trend');
    if (cached) return cached;
    
    const alerts = this.getRecentAlerts();
    
    // Группировка по часам
    const hourlyRisk: Map<string, RiskTrendData> = new Map();
    
    for (const alert of alerts) {
      const bucketKey = this.getBucketKey(alert.timestamp, 'hour');
      
      if (!hourlyRisk.has(bucketKey)) {
        hourlyRisk.set(bucketKey, {
          timestamp: this.getBucketTimestamp(bucketKey, 'hour'),
          overallRisk: 0,
          entityRisk: 0,
          threatRisk: 0,
          impactRisk: 0
        });
      }
      
      const bucket = hourlyRisk.get(bucketKey)!;

      // Обновление максимальных значений риска
      bucket.overallRisk = Math.max(bucket.overallRisk, alert.riskScore);
      bucket.entityRisk = Math.max(bucket.entityRisk, alert.riskScore);
      bucket.threatRisk = Math.max(bucket.threatRisk, alert.riskScore);
      bucket.impactRisk = Math.max(bucket.impactRisk, alert.riskScore);
    }
    
    const riskTrend = Array.from(hourlyRisk.values())
      .sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
    
    this.cacheData('risk_trend', riskTrend);
    return riskTrend;
  }

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Получение недавних алертов
   */
  private getRecentAlerts(): PrioritizedAlert[] {
    const cutoffTime = Date.now() - (this.config.historyHours * 60 * 60 * 1000);
    
    return this.alertsSource
      .filter(a => a.timestamp.getTime() > cutoffTime)
      .map(a => a as PrioritizedAlert);
  }

  /**
   * Получение ключа временного интервала
   */
  private getBucketKey(timestamp: Date, granularity: string): string {
    switch (granularity) {
      case 'minute':
        return timestamp.toISOString().slice(0, 16);  // YYYY-MM-DDTHH:mm
      case 'hour':
        return timestamp.toISOString().slice(0, 13);  // YYYY-MM-DDTHH
      case 'day':
        return timestamp.toISOString().slice(0, 10);  // YYYY-MM-DD
      default:
        return timestamp.toISOString().slice(0, 13);
    }
  }

  /**
   * Получение timestamp для bucket
   */
  private getBucketTimestamp(bucketKey: string, granularity: string): Date {
    switch (granularity) {
      case 'minute':
        return new Date(bucketKey + ':00');
      case 'hour':
        return new Date(bucketKey + ':00:00');
      case 'day':
        return new Date(bucketKey + 'T00:00:00');
      default:
        return new Date(bucketKey + ':00:00');
    }
  }

  /**
   * Расчет среднего времени обнаружения
   */
  private calculateMeanTimeToDetect(alerts: SecurityAlert[]): number {
    if (alerts.length === 0) return 0;
    
    // В реальной реализации здесь был бы расчет времени от события до алерта
    return 5;  // 5 минут (mock)
  }

  /**
   * Расчет среднего времени реагирования
   */
  private calculateMeanTimeToRespond(alerts: SecurityAlert[]): number {
    const respondedAlerts = alerts.filter(a => 
      a.status === 'contained' || a.status === 'remediated' || a.status === 'closed'
    );
    
    if (respondedAlerts.length === 0) return 0;
    
    // В реальной реализации здесь был бы расчет времени от алерта до ответа
    return 30;  // 30 минут (mock)
  }

  /**
   * Расчет тренда алертов
   */
  private calculateAlertTrend(alerts: SecurityAlert[]): number {
    // Сравнение с предыдущим периодом
    const currentPeriod = alerts.length;
    const previousPeriod = Math.floor(currentPeriod * 0.9);  // Mock
    
    if (previousPeriod === 0) return 0;
    
    return Math.round(((currentPeriod - previousPeriod) / previousPeriod) * 100);
  }

  /**
   * Расчет тренда угрозы
   */
  private calculateThreatTrend(attackType: AttackType, alerts: SecurityAlert[]): 'increasing' | 'decreasing' | 'stable' {
    const currentCount = alerts.filter(a => a.attackType === attackType).length;
    const previousCount = Math.floor(currentCount * 0.8);  // Mock
    
    if (currentCount > previousCount * 1.2) return 'increasing';
    if (currentCount < previousCount * 0.8) return 'decreasing';
    return 'stable';
  }

  /**
   * Проверка серьезности
   */
  private isSeverityHigher(a: ThreatSeverity, b: ThreatSeverity): boolean {
    const order: ThreatSeverity[] = [
      ThreatSeverity.INFO,
      ThreatSeverity.LOW,
      ThreatSeverity.MEDIUM,
      ThreatSeverity.HIGH,
      ThreatSeverity.CRITICAL
    ];
    
    return order.indexOf(a) > order.indexOf(b);
  }

  /**
   * Получение тактики для техники
   */
  private getTacticForTechnique(techniqueId: string): string {
    // Упрощенный маппинг
    const tacticMapping: Record<string, string> = {
      'T1046': 'TA0007',  // Discovery
      'T1595': 'TA0007',
      'T1566': 'TA0001',  // Initial Access
      'T1190': 'TA0001',
      'T1059': 'TA0002',  // Execution
      'T1053': 'TA0003',  // Persistence
      'T1547': 'TA0003',
      'T1071': 'TA0011',  // Command and Control
      'T1041': 'TA0010',  // Exfiltration
      'T1486': 'TA0040'   // Impact
    };
    
    return tacticMapping[techniqueId] || 'TA0001';
  }

  /**
   * Получение названия тактики
   */
  private getTacticName(tacticId: string): string {
    const names: Record<string, string> = {
      'TA0001': 'Initial Access',
      'TA0002': 'Execution',
      'TA0003': 'Persistence',
      'TA0004': 'Privilege Escalation',
      'TA0005': 'Defense Evasion',
      'TA0006': 'Credential Access',
      'TA0007': 'Discovery',
      'TA0008': 'Lateral Movement',
      'TA0009': 'Collection',
      'TA0010': 'Exfiltration',
      'TA0011': 'Command and Control',
      'TA0040': 'Impact'
    };
    
    return names[tacticId] || 'Unknown';
  }

  /**
   * Генерация топ talkers
   */
  private generateTopTalkers(): any[] {
    // Mock данные
    return [
      { ip: '192.168.1.100', hostname: 'workstation-01', bytes: 1000000000, connections: 500, riskScore: 30 },
      { ip: '192.168.1.101', hostname: 'workstation-02', bytes: 800000000, connections: 400, riskScore: 25 },
      { ip: '192.168.1.102', hostname: 'server-01', bytes: 5000000000, connections: 2000, riskScore: 40 }
    ];
  }

  /**
   * Генерация топ destinations
   */
  private generateTopDestinations(): any[] {
    // Mock данные
    return [
      { ip: '10.0.0.1', hostname: 'gateway', bytes: 10000000000, connections: 5000, riskScore: 20 },
      { ip: '10.0.0.2', hostname: 'dns-server', bytes: 500000000, connections: 10000, riskScore: 15 }
    ];
  }

  // ============================================================================
  // КЭШИРОВАНИЕ
  // ============================================================================

  /**
   * Получение данных из кэша
   */
  private getCachedData<T>(key: string): T | null {
    const cached = this.metricsCache.get(key);
    
    if (cached && (Date.now() - cached.timestamp.getTime()) < this.cacheTTL) {
      return cached.data as T;
    }
    
    return null;
  }

  /**
   * Кэширование данных
   */
  private cacheData(key: string, data: any): void {
    this.metricsCache.set(key, {
      data,
      timestamp: new Date()
    });
  }

  /**
   * Очистка кэша
   */
  clearCache(): void {
    this.metricsCache.clear();
  }

  // ============================================================================
  // ОБНОВЛЕНИЕ ДАННЫХ
  // ============================================================================

  /**
   * Обновление источника алертов
   */
  updateAlertsSource(alerts: SecurityAlert[]): void {
    this.alertsSource = alerts;
    this.clearCache();
  }

  /**
   * Обновление сетевых метрик
   */
  updateNetworkMetrics(metrics: Partial<NetworkMetricsData>): void {
    this.networkMetricsSource = { ...this.networkMetricsSource, ...metrics };
  }

  /**
   * Обновление endpoint метрик
   */
  updateEndpointMetrics(metrics: Partial<EndpointMetricsData>): void {
    this.endpointMetricsSource = { ...this.endpointMetricsSource, ...metrics };
  }

  /**
   * Обновление пользовательских метрик
   */
  updateUserMetrics(metrics: Partial<UserMetricsData>): void {
    this.userMetricsSource = { ...this.userMetricsSource, ...metrics };
  }

  /**
   * Получение статистики
   */
  getStatistics(): DashboardStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }
}

/**
 * Сетевые метрики (источник)
 */
interface NetworkMetricsData {
  totalFlows: number;
  suspiciousFlows: number;
  blockedConnections: number;
  anomaliesDetected: number;
}

/**
 * Endpoint метрики (источник)
 */
interface EndpointMetricsData {
  totalEndpoints: number;
  onlineEndpoints: number;
  compromisedEndpoints: number;
  isolatedEndpoints: number;
}

/**
 * Пользовательские метрики (источник)
 */
interface UserMetricsData {
  totalUsers: number;
  highRiskUsers: number;
  anomalousBehaviors: number;
  failedLogins: number;
}

/**
 * Статистика Dashboard
 */
interface DashboardStatistics {
  totalRequests: number;
  cacheHits: number;
  cacheMisses: number;
  averageResponseTime: number;
  lastUpdated: Date;
}
