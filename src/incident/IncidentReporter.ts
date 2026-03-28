/**
 * ============================================================================
 * INCIDENT REPORTER
 * ============================================================================
 * Модуль генерации отчетов по инцидентам
 * Поддерживает различные форматы и шаблоны отчетов
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import {
  Incident,
  IncidentSeverity,
  IncidentCategory,
  IncidentMetricsDashboard,
  TimeSeriesData,
  PlaybookEffectiveness,
  IOC,
  MITRETechnique
} from '../types/incident.types';

/**
 * События репортера
 */
export enum IncidentReporterEvent {
  /** Отчет сгенерирован */
  REPORT_GENERATED = 'report_generated',
  /** Дашборд обновлен */
  DASHBOARD_UPDATED = 'dashboard_updated',
  /** Экспорт выполнен */
  EXPORT_COMPLETED = 'export_completed'
}

/**
 * Тип отчета
 */
export enum ReportType {
  /** Детальный отчет по инциденту */
  INCIDENT_DETAIL = 'incident_detail',
  /** Краткий отчет для руководства */
  EXECUTIVE_SUMMARY = 'executive_summary',
  /** Технический отчет */
  TECHNICAL_REPORT = 'technical_report',
  /** Отчет для регуляторов */
  REGULATORY_REPORT = 'regulatory_report',
  /** Еженедельная сводка */
  WEEKLY_SUMMARY = 'weekly_summary',
  /** Ежемесячная сводка */
  MONTHLY_SUMMARY = 'monthly_summary',
  /** Квартальный отчет */
  QUARTERLY_REPORT = 'quarterly_report'
}

/**
 * Конфигурация репортера
 */
export interface IncidentReporterConfig {
  /** Форматы экспорта */
  exportFormats: ('pdf' | 'html' | 'json' | 'csv')[];
  /** Шаблоны отчетов */
  templates: Map<ReportType, string>;
  /** Логирование */
  enableLogging: boolean;
}

/**
 * Модуль генерации отчетов
 */
export class IncidentReporter extends EventEmitter {
  /** Конфигурация */
  private config: IncidentReporterConfig;

  /** Хранилище инцидентов для отчетов */
  private incidents: Map<string, Incident> = new Map();

  /**
   * Конструктор репортера
   */
  constructor(config?: Partial<IncidentReporterConfig>) {
    super();
    this.config = this.mergeConfigWithDefaults(config);
  }

  /**
   * Объединение конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<IncidentReporterConfig> | undefined): IncidentReporterConfig {
    const defaultConfig: IncidentReporterConfig = {
      exportFormats: ['pdf', 'html', 'json'],
      templates: new Map(),
      enableLogging: true
    };

    return { ...defaultConfig, ...config };
  }

  /**
   * Добавление инцидента для отчетности
   */
  public addIncident(incident: Incident): void {
    this.incidents.set(incident.id, incident);
  }

  /**
   * Генерация отчета по инциденту
   */
  public async generateIncidentReport(
    incident: Incident,
    reportType: ReportType,
    options?: {
      includeTimeline?: boolean;
      includeEvidence?: boolean;
      includePlaybookDetails?: boolean;
      includeRecommendations?: boolean;
    }
  ): Promise<IncidentReport> {
    this.log(`Генерация отчета типа ${reportType} для инцидента ${incident.id}`);

    const report: IncidentReport = {
      id: this.generateReportId(),
      type: reportType,
      incidentId: incident.id,
      generatedAt: new Date(),
      content: await this.generateReportContent(incident, reportType, options)
    };

    // Событие генерации
    this.emit(IncidentReporterEvent.REPORT_GENERATED, {
      reportId: report.id,
      reportType,
      incidentId: incident.id
    });

    return report;
  }

  /**
   * Генерация содержимого отчета
   */
  private async generateReportContent(
    incident: Incident,
    reportType: ReportType,
    options?: Record<string, boolean>
  ): Promise<Record<string, unknown>> {
    switch (reportType) {
      case ReportType.INCIDENT_DETAIL:
        return this.generateDetailReport(incident, options);

      case ReportType.EXECUTIVE_SUMMARY:
        return this.generateExecutiveSummary(incident);

      case ReportType.TECHNICAL_REPORT:
        return this.generateTechnicalReport(incident, options);

      case ReportType.REGULATORY_REPORT:
        return this.generateRegulatoryReport(incident);

      default:
        throw new Error(`Неподдерживаемый тип отчета: ${reportType}`);
    }
  }

  /**
   * Детальный отчет
   */
  private async generateDetailReport(
    incident: Incident,
    options?: Record<string, boolean>
  ): Promise<Record<string, unknown>> {
    return {
      header: {
        title: `Incident Report: ${incident.incidentNumber}`,
        classification: 'CONFIDENTIAL',
        generatedAt: new Date().toISOString()
      },
      overview: {
        incidentNumber: incident.incidentNumber,
        severity: incident.severity,
        priority: incident.priority,
        category: incident.category,
        status: incident.status,
        lifecycleStage: incident.lifecycleStage,
        title: incident.title,
        description: incident.description
      },
      timeline: options?.includeTimeline ? {
        detectedAt: incident.detectedAt,
        responseStartedAt: incident.responseStartedAt,
        containedAt: incident.containedAt,
        eradicatedAt: incident.eradicatedAt,
        recoveredAt: incident.recoveredAt,
        closedAt: incident.closedAt,
        events: incident.timeline.map(e => ({
          timestamp: e.timestamp,
          type: e.type,
          title: e.title,
          description: e.description
        }))
      } : undefined,
      impact: {
        affectedSystems: incident.details.affectedSystems,
        affectedUsers: incident.details.affectedUsers.length,
        affectedData: incident.details.affectedData,
        businessImpact: incident.metrics.businessImpactEstimate
      },
      response: {
        containmentActions: incident.containmentActions.map(a => ({
          type: a.type,
          name: a.name,
          status: a.status,
          executedAt: a.executedAt
        })),
        playbook: incident.activePlaybook ? {
          name: incident.activePlaybook.configuration.name,
          progress: incident.activePlaybook.progress,
          status: incident.activePlaybook.status
        } : undefined
      },
      metrics: {
        timeToDetect: incident.metrics.timeToDetect,
        timeToRespond: incident.metrics.timeToRespond,
        timeToContain: incident.metrics.timeToContain,
        timeToRecover: incident.metrics.timeToRecover,
        totalDuration: incident.metrics.totalDuration
      },
      evidence: options?.includeEvidence ? {
        count: incident.evidence.length,
        items: incident.evidence.map(e => ({
          id: e.id,
          type: e.type,
          name: e.name,
          collectedAt: e.collectedAt
        }))
      } : undefined,
      recommendations: options?.includeRecommendations ? {
        // Будут добавлены из PostIncidentReview
      } : undefined
    };
  }

  /**
   * Краткий отчет для руководства
   */
  private async generateExecutiveSummary(incident: Incident): Promise<Record<string, unknown>> {
    return {
      header: {
        title: `Executive Summary: ${incident.incidentNumber}`,
        classification: 'CONFIDENTIAL',
        generatedAt: new Date().toISOString()
      },
      executiveSummary: {
        incident: incident.title,
        severity: incident.severity,
        businessImpact: this.assessBusinessImpact(incident),
        currentStatus: incident.status,
        keyFindings: this.extractKeyFindings(incident),
        actionsRequired: this.extractActionsRequired(incident)
      },
      financialImpact: {
        estimatedLoss: incident.metrics.businessImpactEstimate?.financialLoss,
        responseCost: this.estimateResponseCost(incident),
        potentialRegulatoryFines: this.estimateRegulatoryFines(incident)
      },
      riskAssessment: {
        reputationalRisk: incident.metrics.businessImpactEstimate?.reputationalDamage || 'medium',
        operationalRisk: this.assessOperationalRisk(incident),
        regulatoryRisk: this.assessRegulatoryRisk(incident)
      },
      recommendations: [
        'Continue monitoring for related activity',
        'Review and update security controls',
        'Conduct lessons learned session'
      ]
    };
  }

  /**
   * Технический отчет
   */
  private async generateTechnicalReport(
    incident: Incident,
    options?: Record<string, boolean>
  ): Promise<Record<string, unknown>> {
    return {
      header: {
        title: `Technical Report: ${incident.incidentNumber}`,
        classification: 'INTERNAL USE ONLY',
        generatedAt: new Date().toISOString()
      },
      technicalDetails: {
        attackVector: incident.details.attackVector,
        mitreTechniques: incident.details.mitreTechniques,
        iocs: incident.details.indicatorsOfCompromise,
        affectedSystems: incident.details.affectedSystems.map(s => ({
          name: s,
          details: 'System details would be here'
        }))
      },
      forensics: {
        evidenceCollected: incident.evidence.length,
        analysisResults: {
          // Детали форензика анализа
        }
      },
      containmentDetails: {
        actions: incident.containmentActions.map(a => ({
          type: a.type,
          target: a.target,
          result: a.result
        }))
      },
      eradicationDetails: {
        // Детали устранения
      },
      recoveryDetails: {
        // Детали восстановления
      }
    };
  }

  /**
   * Отчет для регуляторов
   */
  private async generateRegulatoryReport(incident: Incident): Promise<Record<string, unknown>> {
    return {
      header: {
        title: `Regulatory Notification: ${incident.incidentNumber}`,
        classification: 'REGULATORY',
        generatedAt: new Date().toISOString()
      },
      notification: {
        organizationName: 'Protocol Inc.',
        incidentDate: incident.detectedAt.toISOString(),
        discoveryDate: incident.detectedAt.toISOString(),
        notificationDate: new Date().toISOString()
      },
      breachDetails: {
        nature: incident.description,
        categories: incident.details.affectedData?.map(d => d.type) || [],
        volume: incident.details.affectedData?.reduce((sum, d) => sum + (d.volume || 0), 0) || 0,
        recordCount: incident.details.affectedData?.reduce((sum, d) => sum + (d.recordCount || 0), 0) || 0
      },
      affectedIndividuals: {
        count: incident.metrics.affectedUsersCount,
        notified: incident.stakeholderNotifications.filter(n =>
          n.stakeholderType === 'customers'
        ).length
      },
      measuresTaken: {
        containment: incident.containmentActions.map(a => a.name),
        remediation: 'Ongoing monitoring and security enhancements'
      },
      contactInfo: {
        dpo: 'dpo@protocol.local',
        securityTeam: 'security@protocol.local'
      }
    };
  }

  /**
   * Генерация дашборда метрик
   */
  public async generateMetricsDashboard(
    period: { from: Date; to: Date },
    incidents: Incident[]
  ): Promise<IncidentMetricsDashboard> {
    this.log(`Генерация дашборда метрик за период ${period.from} - ${period.to}`);

    const dashboard: IncidentMetricsDashboard = {
      period,
      summary: {
        totalIncidents: incidents.length,
        openIncidents: incidents.filter(i => i.status !== 'closed').length,
        closedIncidents: incidents.filter(i => i.status === 'closed').length,
        avgTimeToDetect: this.calculateAverage(incidents.map(i => i.metrics.timeToDetect)),
        avgTimeToRespond: this.calculateAverage(incidents.map(i => i.metrics.timeToRespond)),
        avgTimeToContain: this.calculateAverage(incidents.map(i => i.metrics.timeToContain)),
        avgTimeToRecover: this.calculateAverage(incidents.map(i => i.metrics.timeToRecover)),
        slaCompliance: this.calculateSLACompliance(incidents)
      },
      byCategory: this.groupByCategory(incidents),
      bySeverity: this.groupBySeverity(incidents),
      overTime: this.generateTimeSeries(incidents),
      topIOCs: this.extractTopIOCs(incidents),
      topTechniques: this.extractTopTechniques(incidents),
      playbookEffectiveness: this.calculatePlaybookEffectiveness(incidents)
    };

    // Событие обновления дашборда
    this.emit(IncidentReporterEvent.DASHBOARD_UPDATED, {
      period,
      incidentCount: incidents.length
    });

    return dashboard;
  }

  /**
   * Вспомогательные методы
   */

  private assessBusinessImpact(incident: Incident): string {
    const estimate = incident.metrics.businessImpactEstimate;
    if (!estimate) return 'Assessing...';

    const parts: string[] = [];
    if (estimate.financialLoss) {
      parts.push(`Financial: $${estimate.financialLoss.toLocaleString()}`);
    }
    if (estimate.downtimeHours) {
      parts.push(`Downtime: ${estimate.downtimeHours}h`);
    }
    if (estimate.reputationalDamage) {
      parts.push(`Reputation: ${estimate.reputationalDamage}`);
    }

    return parts.join(', ') || 'Minimal impact';
  }

  private extractKeyFindings(incident: Incident): string[] {
    const findings: string[] = [];

    if (incident.details.mitreTechniques?.length) {
      findings.push(`Attack techniques identified: ${incident.details.mitreTechniques.length}`);
    }

    if (incident.details.indicatorsOfCompromise?.length) {
      findings.push(`IOCs collected: ${incident.details.indicatorsOfCompromise.length}`);
    }

    if (incident.evidence.length) {
      findings.push(`Evidence items: ${incident.evidence.length}`);
    }

    return findings;
  }

  private extractActionsRequired(incident: Incident): string[] {
    const actions: string[] = [];

    if (incident.status !== 'closed') {
      actions.push('Complete incident remediation');
    }

    if (!incident.postIncidentReview) {
      actions.push('Conduct post-incident review');
    }

    if (incident.metrics.businessImpactEstimate?.financialLoss &&
        incident.metrics.businessImpactEstimate.financialLoss > 100000) {
      actions.push('Executive briefing required');
    }

    return actions;
  }

  private estimateResponseCost(incident: Incident): number {
    // Простая оценка стоимости реагирования
    const hours = (incident.metrics.totalDuration || 0) / 3600000;
    const responders = incident.assignees.length || 3;
    const hourlyRate = 150;

    return Math.round(hours * responders * hourlyRate);
  }

  private estimateRegulatoryFines(incident: Incident): number | undefined {
    // Оценка потенциальных штрафов
    if (incident.category === IncidentCategory.DATA_BREACH) {
      const affectedRecords = incident.details.affectedData?.reduce(
        (sum, d) => sum + (d.recordCount || 0), 0
      ) || 0;

      if (affectedRecords > 10000) {
        return affectedRecords * 100; // GDPR-style fine estimation
      }
    }

    return undefined;
  }

  private assessOperationalRisk(incident: Incident): string {
    const affectedSystems = incident.metrics.affectedSystemsCount;

    if (affectedSystems > 10) return 'high';
    if (affectedSystems > 3) return 'medium';
    return 'low';
  }

  private assessRegulatoryRisk(incident: Incident): string {
    if (incident.category === IncidentCategory.DATA_BREACH) {
      const affectedRecords = incident.details.affectedData?.reduce(
        (sum, d) => sum + (d.recordCount || 0), 0
      ) || 0;

      if (affectedRecords > 100000) return 'critical';
      if (affectedRecords > 10000) return 'high';
      if (affectedRecords > 1000) return 'medium';
    }

    return 'low';
  }

  private calculateAverage(values: (number | undefined)[]): number {
    const validValues = values.filter((v): v is number => v !== undefined);
    if (validValues.length === 0) return 0;
    return Math.round(validValues.reduce((sum, v) => sum + v, 0) / validValues.length);
  }

  private calculateSLACompliance(incidents: Incident[]): number {
    if (incidents.length === 0) return 100;

    const compliant = incidents.filter(i => {
      const responseMet = (i.metrics.timeToRespond || 0) < 900000;
      const containmentMet = (i.metrics.timeToContain || 0) < 3600000;
      return responseMet && containmentMet;
    }).length;

    return Math.round((compliant / incidents.length) * 100);
  }

  private groupByCategory(incidents: Incident[]): Record<string, number> {
    const result: Record<string, number> = {};

    for (const incident of incidents) {
      const category = incident.category;
      result[category] = (result[category] || 0) + 1;
    }

    return result;
  }

  private groupBySeverity(incidents: Incident[]): Record<string, number> {
    const result: Record<string, number> = {};

    for (const incident of incidents) {
      const severity = incident.severity;
      result[severity] = (result[severity] || 0) + 1;
    }

    return result;
  }

  private generateTimeSeries(incidents: Incident[]): TimeSeriesData[] {
    // Группировка по дням
    const byDay: Map<string, number> = new Map();

    for (const incident of incidents) {
      const day = incident.detectedAt.toISOString().substring(0, 10);
      byDay.set(day, (byDay.get(day) || 0) + 1);
    }

    return Array.from(byDay.entries()).map(([timestamp, value]) => ({
      timestamp: new Date(timestamp),
      value
    }));
  }

  private extractTopIOCs(incidents: Incident[], limit: number = 10): IOC[] {
    const iocCount: Map<string, { ioc: IOC; count: number }> = new Map();

    for (const incident of incidents) {
      const details = incident.details;
      if (!details) continue;

      for (const ioc of details.indicatorsOfCompromise || []) {
        const key = `${ioc.type}:${ioc.value}`;
        const existing = iocCount.get(key);
        if (existing) {
          existing.count++;
        } else {
          iocCount.set(key, { ioc: { ...ioc }, count: 1 });
        }
      }
    }

    return Array.from(iocCount.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, limit)
      .map(({ ioc }) => ioc);
  }

  private extractTopTechniques(incidents: Incident[], limit: number = 10): MITRETechnique[] {
    const techniqueCount: Map<string, number> = new Map();

    for (const incident of incidents) {
      for (const technique of incident.details?.mitreTechniques || []) {
        techniqueCount.set(technique, (techniqueCount.get(technique) || 0) + 1);
      }
    }

    return Array.from(techniqueCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([id, count]) => ({
        id,
        name: `Техника ${id}`,
        description: `MITRE ATT&CK техника`,
        url: `https://attack.mitre.org/techniques/${id}/`
      }));
  }

  private calculatePlaybookEffectiveness(incidents: Incident[]): PlaybookEffectiveness[] {
    const playbookStats: Map<string, { executions: number; successes: number; totalTime: number }> = new Map();

    for (const incident of incidents) {
      if (incident.activePlaybook) {
        const pb = incident.activePlaybook;
        const stats = playbookStats.get(pb.configuration.id) || {
          executions: 0,
          successes: 0,
          totalTime: 0
        };

        stats.executions++;
        if (pb.status === 'completed') {
          stats.successes++;
        }
        if (pb.completedAt && pb.startedAt) {
          stats.totalTime += pb.completedAt.getTime() - pb.startedAt.getTime();
        }

        playbookStats.set(pb.configuration.id, stats);
      }
    }

    return Array.from(playbookStats.entries()).map(([id, stats]) => ({
      playbookId: id,
      name: id,
      executionCount: stats.executions,
      successRate: Math.round((stats.successes / stats.executions) * 100),
      avgExecutionTime: Math.round(stats.totalTime / stats.executions),
      avgStepsCompleted: 0,
      rollbackCount: 0
    }));
  }

  /**
   * Генерация идентификатора отчета
   */
  private generateReportId(): string {
    return `rpt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Логирование
   */
  private log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    if (this.config.enableLogging) {
      const timestamp = new Date().toISOString();
      const prefix = `[IncidentReporter] [${timestamp}] [${level.toUpperCase()}]`;
      logger.info(`${prefix} ${message}`);
    }
  }
}

/**
 * Интерфейс отчета
 */
export interface IncidentReport {
  id: string;
  type: ReportType;
  incidentId: string;
  generatedAt: Date;
  content: Record<string, unknown>;
}
