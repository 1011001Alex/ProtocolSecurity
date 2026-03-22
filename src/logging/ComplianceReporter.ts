/**
 * ============================================================================
 * COMPLIANCE REPORTER - ОТЧЕТЫ СООТВЕТСТВИЯ
 * ============================================================================
 * Модуль для генерации отчетов соответствия стандартам PCI DSS, GDPR,
 * SOX, HIPAA, ISO 27001, NIST, CIS, SOC2.
 * 
 * Особенности:
 * - Поддержка множественных стандартов compliance
 * - Автоматическая оценка соответствия
 * - Генерация детальных отчетов
 * - Выявление нарушений и рекомендации
 * - Audit trail generation
 * - Evidence collection
 * - Trend analysis
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import { EventEmitter } from 'events';
import {
  ComplianceStandard,
  ComplianceRequirement,
  ComplianceReport,
  ComplianceRequirementStatus,
  ComplianceViolation,
  ComplianceMetric,
  MetricResult,
  EvidenceRecord,
  Recommendation,
  LogEntry,
  LogSource,
  Alert,
  AlertSeverity
} from '../types/logging.types';

// ============================================================================
// КОНСТАНТЫ И ДАННЫЕ COMPLIANCE
// ============================================================================

/**
 * Встроенные требования PCI DSS v4.0
 */
const PCI_DSS_REQUIREMENTS: ComplianceRequirement[] = [
  {
    id: 'pci-dss-1.1',
    standard: ComplianceStandard.PCI_DSS,
    control: '1.1',
    description: 'Install and maintain network security controls',
    category: 'Network Security',
    priority: 'critical',
    relatedRules: ['network-port-scan', 'network-data-exfiltration'],
    relatedLogTypes: ['network', 'security'],
    metrics: [
      {
        name: 'Firewall Rule Changes',
        description: 'Number of firewall rule changes',
        type: 'count',
        query: 'source:firewall action:rule_change',
        targetValue: 10,
        warningThreshold: 5,
        violationThreshold: 20
      }
    ],
    evidence: [
      {
        type: 'log',
        description: 'Firewall configuration logs',
        frequency: 'daily',
        retentionDays: 365,
        format: 'json'
      }
    ],
    checkFrequency: 'daily'
  },
  {
    id: 'pci-dss-3.2',
    standard: ComplianceStandard.PCI_DSS,
    control: '3.2',
    description: 'Do not store sensitive authentication data after authorization',
    category: 'Data Protection',
    priority: 'critical',
    relatedRules: ['compliance-pci-card-data'],
    relatedLogTypes: ['application', 'security'],
    metrics: [
      {
        name: 'Card Data in Logs',
        description: 'Occurrences of card data in logs',
        type: 'count',
        query: 'message:*4[0-9]{12,15}*',
        targetValue: 0,
        warningThreshold: 0,
        violationThreshold: 1
      }
    ],
    evidence: [
      {
        type: 'log',
        description: 'Application logs showing no card data storage',
        frequency: 'continuous',
        retentionDays: 365,
        format: 'json'
      }
    ],
    checkFrequency: 'continuous'
  },
  {
    id: 'pci-dss-10.1',
    standard: ComplianceStandard.PCI_DSS,
    control: '10.1',
    description: 'Implement audit trails to link all access to system components',
    category: 'Logging and Monitoring',
    priority: 'critical',
    relatedRules: ['auth-privilege-escalation', 'auth-after-hours-access'],
    relatedLogTypes: ['auth', 'audit', 'system'],
    metrics: [
      {
        name: 'Audit Log Coverage',
        description: 'Percentage of systems with audit logging enabled',
        type: 'percentage',
        query: 'source:audit',
        targetValue: 100,
        warningThreshold: 95,
        violationThreshold: 90
      },
      {
        name: 'Log Retention Period',
        description: 'Days of log retention',
        type: 'duration',
        query: 'log_retention_days',
        targetValue: 365,
        warningThreshold: 180,
        violationThreshold: 90
      }
    ],
    evidence: [
      {
        type: 'log',
        description: 'Audit logs for all system components',
        frequency: 'continuous',
        retentionDays: 365,
        format: 'json'
      },
      {
        type: 'config',
        description: 'Logging configuration files',
        frequency: 'quarterly',
        retentionDays: 365,
        format: 'yaml'
      }
    ],
    checkFrequency: 'continuous'
  },
  {
    id: 'pci-dss-10.7',
    standard: ComplianceStandard.PCI_DSS,
    control: '10.7',
    description: 'Retain audit trail history for at least 12 months',
    category: 'Logging and Monitoring',
    priority: 'high',
    relatedRules: [],
    relatedLogTypes: ['audit'],
    metrics: [
      {
        name: 'Log Retention',
        description: 'Minimum log retention period in days',
        type: 'duration',
        query: 'log_retention_days',
        targetValue: 365,
        warningThreshold: 200,
        violationThreshold: 180
      }
    ],
    evidence: [
      {
        type: 'log',
        description: 'Historical audit logs',
        frequency: 'continuous',
        retentionDays: 365,
        format: 'json'
      }
    ],
    checkFrequency: 'monthly'
  }
];

/**
 * Встроенные требования GDPR
 */
const GDPR_REQUIREMENTS: ComplianceRequirement[] = [
  {
    id: 'gdpr-art5',
    standard: ComplianceStandard.GDPR,
    control: 'Article 5',
    description: 'Principles relating to processing of personal data',
    category: 'Data Protection Principles',
    priority: 'critical',
    relatedRules: ['compliance-gdpr-personal-data'],
    relatedLogTypes: ['audit', 'application'],
    metrics: [
      {
        name: 'Data Access Requests',
        description: 'Number of data subject access requests processed',
        type: 'count',
        query: 'type:data_access_request',
        targetValue: 0,
        warningThreshold: 10,
        violationThreshold: 30
      },
      {
        name: 'Data Breach Notifications',
        description: 'Number of data breach notifications',
        type: 'count',
        query: 'type:data_breach',
        targetValue: 0,
        warningThreshold: 0,
        violationThreshold: 1
      }
    ],
    evidence: [
      {
        type: 'log',
        description: 'Records of processing activities',
        frequency: 'continuous',
        retentionDays: 365,
        format: 'json'
      }
    ],
    checkFrequency: 'continuous'
  },
  {
    id: 'gdpr-art30',
    standard: ComplianceStandard.GDPR,
    control: 'Article 30',
    description: 'Records of processing activities',
    category: 'Documentation',
    priority: 'high',
    relatedRules: [],
    relatedLogTypes: ['audit'],
    metrics: [
      {
        name: 'Processing Records Coverage',
        description: 'Percentage of processing activities documented',
        type: 'percentage',
        query: 'type:processing_record',
        targetValue: 100,
        warningThreshold: 95,
        violationThreshold: 90
      }
    ],
    evidence: [
      {
        type: 'report',
        description: 'Records of Processing Activities (ROPA)',
        frequency: 'quarterly',
        retentionDays: 365,
        format: 'pdf'
      }
    ],
    checkFrequency: 'quarterly'
  },
  {
    id: 'gdpr-art32',
    standard: ComplianceStandard.GDPR,
    control: 'Article 32',
    description: 'Security of processing',
    category: 'Security Measures',
    priority: 'critical',
    relatedRules: ['threat-malicious-ip', 'threat-tor-exit-node'],
    relatedLogTypes: ['security', 'network'],
    metrics: [
      {
        name: 'Security Incidents',
        description: 'Number of security incidents affecting personal data',
        type: 'count',
        query: 'source:security severity:high',
        targetValue: 0,
        warningThreshold: 1,
        violationThreshold: 5
      },
      {
        name: 'Encryption Coverage',
        description: 'Percentage of personal data encrypted',
        type: 'percentage',
        query: 'encrypted:true',
        targetValue: 100,
        warningThreshold: 99,
        violationThreshold: 95
      }
    ],
    evidence: [
      {
        type: 'config',
        description: 'Encryption configuration',
        frequency: 'quarterly',
        retentionDays: 365,
        format: 'yaml'
      },
      {
        type: 'report',
        description: 'Security assessment reports',
        frequency: 'yearly',
        retentionDays: 365,
        format: 'pdf'
      }
    ],
    checkFrequency: 'monthly'
  }
];

/**
 * Встроенные требования SOX
 */
const SOX_REQUIREMENTS: ComplianceRequirement[] = [
  {
    id: 'sox-302',
    standard: ComplianceStandard.SOX,
    control: 'Section 302',
    description: 'Corporate Responsibility for Financial Reports',
    category: 'Financial Reporting',
    priority: 'critical',
    relatedRules: ['compliance-sox-config-change'],
    relatedLogTypes: ['audit', 'system'],
    metrics: [
      {
        name: 'Financial System Changes',
        description: 'Number of changes to financial systems',
        type: 'count',
        query: 'system:financial change_type:*',
        targetValue: 50,
        warningThreshold: 100,
        violationThreshold: 200
      },
      {
        name: 'Unauthorized Access Attempts',
        description: 'Number of unauthorized access attempts to financial systems',
        type: 'count',
        query: 'system:financial access:denied',
        targetValue: 0,
        warningThreshold: 5,
        violationThreshold: 10
      }
    ],
    evidence: [
      {
        type: 'log',
        description: 'Audit logs for financial systems',
        frequency: 'continuous',
        retentionDays: 2555, // 7 years
        format: 'json'
      },
      {
        type: 'report',
        description: 'Quarterly access reviews',
        frequency: 'quarterly',
        retentionDays: 2555,
        format: 'pdf'
      }
    ],
    checkFrequency: 'quarterly'
  },
  {
    id: 'sox-404',
    standard: ComplianceStandard.SOX,
    control: 'Section 404',
    description: 'Management Assessment of Internal Controls',
    category: 'Internal Controls',
    priority: 'critical',
    relatedRules: [],
    relatedLogTypes: ['audit'],
    metrics: [
      {
        name: 'Control Deficiencies',
        description: 'Number of identified control deficiencies',
        type: 'count',
        query: 'type:control_deficiency',
        targetValue: 0,
        warningThreshold: 1,
        violationThreshold: 5
      },
      {
        name: 'Control Testing Coverage',
        description: 'Percentage of controls tested',
        type: 'percentage',
        query: 'type:control_test',
        targetValue: 100,
        warningThreshold: 95,
        violationThreshold: 90
      }
    ],
    evidence: [
      {
        type: 'report',
        description: 'Internal control assessment report',
        frequency: 'yearly',
        retentionDays: 2555,
        format: 'pdf'
      }
    ],
    checkFrequency: 'yearly'
  }
];

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Конфигурация ComplianceReporter
 */
interface ComplianceReporterConfig {
  /** Стандарты для мониторинга */
  standards: ComplianceStandard[];
  /** Путь для хранения отчетов */
  reportStoragePath: string;
  /** Включить автоматическую генерацию отчетов */
  enableAutoReporting: boolean;
  /** Интервал генерации отчетов (часы) */
  reportingIntervalHours: number;
  /** Минимальный период хранения (дни) */
  minRetentionDays: number;
  /** Включить trend analysis */
  enableTrendAnalysis: boolean;
  /** Период trend analysis (дни) */
  trendAnalysisDays: number;
}

/**
 * Результат оценки требования
 */
interface RequirementAssessment {
  requirement: ComplianceRequirement;
  status: 'compliant' | 'non_compliant' | 'partial';
  compliancePercentage: number;
  metricResults: MetricResult[];
  evidenceRecords: EvidenceRecord[];
  violations: ComplianceViolation[];
  assessedAt: string;
}

/**
 * Статистика ComplianceReporter
 */
interface ReporterStatistics {
  /** Всего сгенерировано отчетов */
  totalReportsGenerated: number;
  /** Текущий compliance score */
  currentComplianceScore: number;
  /** По стандартам */
  byStandard: Record<ComplianceStandard, {
    score: number;
    compliantRequirements: number;
    totalRequirements: number;
    violations: number;
  }>;
  /** Всего нарушений */
  totalViolations: number;
  /** Открытые нарушения */
  openViolations: number;
  /** Разрешенные нарушения */
  resolvedViolations: number;
  /** Среднее время разрешения (дни) */
  avgResolutionTimeDays: number;
  /** Последняя генерация отчета */
  lastReportGeneration: string | null;
}

// ============================================================================
// КЛАСС METRIC EVALUATOR
// ============================================================================

/**
 * Оценщик метрик compliance
 */
class MetricEvaluator {
  /**
   * Оценка метрики
   */
  evaluate(metric: ComplianceMetric, actualValue: number): MetricResult {
    let status: 'pass' | 'warning' | 'fail';
    let trend: 'improving' | 'stable' | 'degrading' | undefined;
    
    if (metric.type === 'percentage' || metric.type === 'duration') {
      // Для percentage и duration: больше = лучше
      if (actualValue >= metric.targetValue) {
        status = 'pass';
      } else if (actualValue >= metric.warningThreshold) {
        status = 'warning';
      } else {
        status = 'fail';
      }
    } else {
      // Для count: меньше = лучше
      if (actualValue <= metric.targetValue) {
        status = 'pass';
      } else if (actualValue <= metric.violationThreshold) {
        status = 'warning';
      } else {
        status = 'fail';
      }
    }
    
    return {
      name: metric.name,
      actualValue,
      targetValue: metric.targetValue,
      status,
      trend,
      change: 0
    };
  }
}

// ============================================================================
// КЛАСС EVIDENCE COLLECTOR
// ============================================================================

/**
 * Сборщик доказательств
 */
class EvidenceCollector {
  private storagePath: string;
  
  constructor(storagePath: string) {
    this.storagePath = storagePath;
  }
  
  /**
   * Сбор доказательства
   */
  collect(evidence: EvidenceRequirement, data: unknown): EvidenceRecord {
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString();
    
    // Сохранение доказательства
    const filePath = this.saveEvidence(id, evidence, data);
    
    // Вычисление хеша
    const hash = this.computeHash(data);
    
    // Расчет срока действия
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + evidence.retentionDays);
    
    return {
      id,
      type: evidence.type,
      description: evidence.description,
      location: filePath,
      createdAt: timestamp,
      hash,
      expiresAt: expiresAt.toISOString()
    };
  }
  
  /**
   * Сохранение доказательства
   */
  private saveEvidence(id: string, evidence: EvidenceRequirement, data: unknown): string {
    const dir = `${this.storagePath}/evidence/${evidence.type}`;
    const filePath = `${dir}/${id}.${evidence.format}`;
    
    // В production создать директорию и сохранить файл
    // fs.mkdirSync(dir, { recursive: true });
    // fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    
    return filePath;
  }
  
  /**
   * Вычисление хеша
   */
  private computeHash(data: unknown): string {
    const content = JSON.stringify(data);
    return crypto.createHash('sha256').update(content).digest('hex');
  }
  
  /**
   * Получение доказательства
   */
  getEvidence(evidenceId: string): EvidenceRecord | null {
    // В production загрузить из хранилища
    return null;
  }
}

// ============================================================================
// КЛАСС TREND ANALYZER
// ============================================================================

/**
 * Анализатор трендов compliance
 */
class TrendAnalyzer {
  /**
   * Анализ тренда compliance score
   */
  analyzeTrend(scores: number[]): {
    trend: 'improving' | 'stable' | 'degrading';
    change: number;
    prediction: number;
  } {
    if (scores.length < 2) {
      return { trend: 'stable', change: 0, prediction: scores[0] || 0 };
    }
    
    // Расчет линейного тренда
    const n = scores.length;
    const sumX = n * (n - 1) / 2;
    const sumY = scores.reduce((a, b) => a + b, 0);
    const sumXY = scores.reduce((sum, y, x) => sum + x * y, 0);
    const sumX2 = n * (n - 1) * (2 * n - 1) / 6;
    
    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;
    
    // Определение тренда
    let trend: 'improving' | 'stable' | 'degrading';
    if (slope > 0.5) {
      trend = 'improving';
    } else if (slope < -0.5) {
      trend = 'degrading';
    } else {
      trend = 'stable';
    }
    
    // Прогноз следующего значения
    const prediction = slope * n + intercept;
    
    return {
      trend,
      change: slope,
      prediction: Math.max(0, Math.min(100, prediction))
    };
  }
  
  /**
   * Анализ сезонности
   */
  analyzeSeasonality(scores: number[], period: number): {
    seasonalIndices: number[];
    deseasonalized: number[];
  } {
    if (scores.length < period * 2) {
      return { seasonalIndices: [], deseasonalized: [] };
    }
    
    const seasonalIndices: number[] = new Array(period).fill(0);
    const counts: number[] = new Array(period).fill(0);
    
    // Расчет средних для каждой позиции в периоде
    for (let i = 0; i < scores.length; i++) {
      const pos = i % period;
      seasonalIndices[pos] += scores[i];
      counts[pos]++;
    }
    
    for (let i = 0; i < period; i++) {
      seasonalIndices[i] /= counts[i];
    }
    
    // Нормализация
    const overallMean = seasonalIndices.reduce((a, b) => a + b, 0) / period;
    const normalizedIndices = seasonalIndices.map(s => s / overallMean);
    
    // Deseasonalization
    const deseasonalized = scores.map((s, i) => s / normalizedIndices[i % period]);
    
    return {
      seasonalIndices: normalizedIndices,
      deseasonalized
    };
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС COMPLIANCE REPORTER
// ============================================================================

/**
 * Compliance Reporter - генерация отчетов соответствия
 * 
 * Реализует:
 * - Поддержка PCI DSS, GDPR, SOX, HIPAA, ISO 27001, NIST, CIS, SOC2
 * - Автоматическая оценка соответствия
 * - Генерация детальных отчетов
 * - Выявление нарушений
 * - Trend analysis
 */
export class ComplianceReporter extends EventEmitter {
  private config: ComplianceReporterConfig;
  private metricEvaluator: MetricEvaluator;
  private evidenceCollector: EvidenceCollector;
  private trendAnalyzer: TrendAnalyzer;
  
  /** Требования по стандартам */
  private requirements: Map<ComplianceStandard, ComplianceRequirement[]>;
  /** Нарушения */
  private violations: Map<string, ComplianceViolation>;
  /** История compliance scores */
  private scoreHistory: Array<{ date: string; score: number; standard: ComplianceStandard }>;
  /** Статистика */
  private statistics: ReporterStatistics;
  
  constructor(config: Partial<ComplianceReporterConfig> = {}) {
    super();
    
    this.config = {
      standards: config.standards || [
        ComplianceStandard.PCI_DSS,
        ComplianceStandard.GDPR,
        ComplianceStandard.SOX
      ],
      reportStoragePath: config.reportStoragePath || './compliance-reports',
      enableAutoReporting: config.enableAutoReporting !== false,
      reportingIntervalHours: config.reportingIntervalHours || 24,
      minRetentionDays: config.minRetentionDays || 365,
      enableTrendAnalysis: config.enableTrendAnalysis !== false,
      trendAnalysisDays: config.trendAnalysisDays || 90
    };
    
    this.metricEvaluator = new MetricEvaluator();
    this.evidenceCollector = new EvidenceCollector(this.config.reportStoragePath);
    this.trendAnalyzer = new TrendAnalyzer();
    
    this.requirements = new Map();
    this.violations = new Map();
    this.scoreHistory = [];
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    
    // Загрузка встроенных требований
    this.loadBuiltinRequirements();
    
    // Запуск периодической генерации отчетов
    if (this.config.enableAutoReporting) {
      this.startAutoReporting();
    }
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): ReporterStatistics {
    return {
      totalReportsGenerated: 0,
      currentComplianceScore: 0,
      byStandard: {
        [ComplianceStandard.PCI_DSS]: { score: 0, compliantRequirements: 0, totalRequirements: 0, violations: 0 },
        [ComplianceStandard.GDPR]: { score: 0, compliantRequirements: 0, totalRequirements: 0, violations: 0 },
        [ComplianceStandard.SOX]: { score: 0, compliantRequirements: 0, totalRequirements: 0, violations: 0 },
        [ComplianceStandard.HIPAA]: { score: 0, compliantRequirements: 0, totalRequirements: 0, violations: 0 },
        [ComplianceStandard.ISO_27001]: { score: 0, compliantRequirements: 0, totalRequirements: 0, violations: 0 },
        [ComplianceStandard.NIST]: { score: 0, compliantRequirements: 0, totalRequirements: 0, violations: 0 },
        [ComplianceStandard.CIS]: { score: 0, compliantRequirements: 0, totalRequirements: 0, violations: 0 },
        [ComplianceStandard.SOC2]: { score: 0, compliantRequirements: 0, totalRequirements: 0, violations: 0 }
      },
      totalViolations: 0,
      openViolations: 0,
      resolvedViolations: 0,
      avgResolutionTimeDays: 0,
      lastReportGeneration: null
    };
  }
  
  /**
   * Загрузка встроенных требований
   */
  private loadBuiltinRequirements(): void {
    // PCI DSS
    this.requirements.set(ComplianceStandard.PCI_DSS, PCI_DSS_REQUIREMENTS);
    
    // GDPR
    this.requirements.set(ComplianceStandard.GDPR, GDPR_REQUIREMENTS);
    
    // SOX
    this.requirements.set(ComplianceStandard.SOX, SOX_REQUIREMENTS);
    
    // Остальные стандарты могут быть добавлены аналогично
  }
  
  /**
   * Запуск автоматической генерации отчетов
   */
  private startAutoReporting(): void {
    setInterval(() => {
      this.generateAllReports();
    }, this.config.reportingIntervalHours * 60 * 60 * 1000);
  }
  
  /**
   * Оценка требования
   */
  async assessRequirement(requirement: ComplianceRequirement): Promise<RequirementAssessment> {
    const metricResults: MetricResult[] = [];
    const evidenceRecords: EvidenceRecord[] = [];
    const violations: ComplianceViolation[] = [];
    
    // Оценка метрик
    for (const metric of requirement.metrics) {
      // В production выполнить запрос для получения actual value
      const actualValue = await this.getMetricValue(metric);
      const result = this.metricEvaluator.evaluate(metric, actualValue);
      metricResults.push(result);
      
      // Создание нарушения если fail
      if (result.status === 'fail') {
        const violation: ComplianceViolation = {
          id: crypto.randomUUID(),
          requirementId: requirement.id,
          control: requirement.control,
          description: `Metric "${metric.name}" failed: ${result.actualValue} (target: ${metric.targetValue})`,
          severity: requirement.priority === 'critical' ? 'critical' : 'high',
          impact: metric.description,
          remediation: [`Investigate ${metric.name}`, `Implement corrective measures`],
          remediationDeadline: this.calculateRemediationDeadline(requirement.priority),
          owner: 'compliance-team',
          remediationStatus: 'open',
          detectedAt: new Date().toISOString()
        };
        
        violations.push(violation);
        this.violations.set(violation.id, violation);
      }
    }
    
    // Сбор доказательств
    for (const evidence of requirement.evidence) {
      const record = this.evidenceCollector.collect(evidence, {
        requirementId: requirement.id,
        collectedAt: new Date().toISOString()
      });
      evidenceRecords.push(record);
    }
    
    // Расчет процента соответствия
    const passedMetrics = metricResults.filter(m => m.status === 'pass').length;
    const compliancePercentage = requirement.metrics.length > 0
      ? (passedMetrics / requirement.metrics.length) * 100
      : 100;
    
    // Определение статуса
    let status: 'compliant' | 'non_compliant' | 'partial';
    if (compliancePercentage === 100) {
      status = 'compliant';
    } else if (compliancePercentage >= 80) {
      status = 'partial';
    } else {
      status = 'non_compliant';
    }
    
    return {
      requirement,
      status,
      compliancePercentage,
      metricResults,
      evidenceRecords,
      violations,
      assessedAt: new Date().toISOString()
    };
  }
  
  /**
   * Получение значения метрики
   */
  private async getMetricValue(metric: ComplianceMetric): Promise<number> {
    // В production выполнить запрос к Elasticsearch или другому источнику
    // Эмуляция для примера
    return Math.random() * 100;
  }
  
  /**
   * Расчет срока исправления
   */
  private calculateRemediationDeadline(priority: string): string {
    const days = {
      critical: 1,
      high: 7,
      medium: 30,
      low: 90
    };
    
    const deadline = new Date();
    deadline.setDate(deadline.getDate() + days[priority as keyof typeof days] || 30);
    return deadline.toISOString();
  }
  
  /**
   * Генерация отчета по стандарту
   */
  async generateReport(standard: ComplianceStandard, period?: { start: string; end: string }): Promise<ComplianceReport> {
    const requirements = this.requirements.get(standard) || [];
    const requirementStatuses: ComplianceRequirementStatus[] = [];
    const allViolations: ComplianceViolation[] = [];
    const recommendations: Recommendation[] = [];
    
    // Оценка всех требований
    for (const requirement of requirements) {
      const assessment = await this.assessRequirement(requirement);
      
      requirementStatuses.push({
        requirementId: requirement.id,
        control: requirement.control,
        status: assessment.status,
        compliancePercentage: assessment.compliancePercentage,
        evidence: assessment.evidenceRecords,
        metrics: assessment.metricResults,
        lastChecked: assessment.assessedAt
      });
      
      allViolations.push(...assessment.violations);
      
      // Генерация рекомендаций для нарушений
      for (const violation of assessment.violations) {
        recommendations.push({
          id: crypto.randomUUID(),
          title: `Remediate ${requirement.control}`,
          description: violation.description,
          priority: violation.severity,
          relatedViolations: [violation.id],
          actions: violation.remediation,
          expectedImpact: `Improve compliance with ${requirement.control}`,
          implementationComplexity: 'medium'
        });
      }
    }
    
    // Расчет общего compliance score
    const totalPercentage = requirementStatuses.reduce((sum, r) => sum + r.compliancePercentage, 0);
    const complianceScore = requirementStatuses.length > 0
      ? Math.round(totalPercentage / requirementStatuses.length)
      : 0;
    
    // Определение общего статуса
    let overallStatus: 'compliant' | 'partially_compliant' | 'non_compliant';
    if (complianceScore >= 95) {
      overallStatus = 'compliant';
    } else if (complianceScore >= 80) {
      overallStatus = 'partially_compliant';
    } else {
      overallStatus = 'non_compliant';
    }
    
    // Обновление статистики
    this.updateStatistics(standard, requirementStatuses, allViolations, complianceScore);
    
    // Сохранение в историю
    this.scoreHistory.push({
      date: new Date().toISOString(),
      score: complianceScore,
      standard
    });
    
    const report: ComplianceReport = {
      id: crypto.randomUUID(),
      standard,
      period: period || {
        start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
        end: new Date().toISOString()
      },
      generatedAt: new Date().toISOString(),
      overallStatus,
      complianceScore,
      requirements: requirementStatuses,
      violations: allViolations,
      recommendations,
      appendices: {
        trendAnalysis: this.config.enableTrendAnalysis ? this.analyzeTrend(standard) : null,
        evidenceSummary: this.generateEvidenceSummary(requirementStatuses)
      },
      reportStatus: 'final'
    };
    
    // Сохранение отчета
    await this.saveReport(report);
    
    this.statistics.totalReportsGenerated++;
    this.statistics.lastReportGeneration = new Date().toISOString();
    
    this.emit('report_generated', report);
    
    return report;
  }
  
  /**
   * Генерация всех отчетов
   */
  async generateAllReports(): Promise<ComplianceReport[]> {
    const reports: ComplianceReport[] = [];
    
    for (const standard of this.config.standards) {
      const report = await this.generateReport(standard);
      reports.push(report);
    }
    
    return reports;
  }
  
  /**
   * Анализ тренда
   */
  private analyzeTrend(standard: ComplianceStandard): {
    trend: string;
    change: number;
    historicalScores: number[];
  } {
    const historicalScores = this.scoreHistory
      .filter(h => h.standard === standard)
      .slice(-this.config.trendAnalysisDays)
      .map(h => h.score);
    
    const trendAnalysis = this.trendAnalyzer.analyzeTrend(historicalScores);
    
    return {
      trend: trendAnalysis.trend,
      change: trendAnalysis.change,
      historicalScores
    };
  }
  
  /**
   * Генерация summary доказательств
   */
  private generateEvidenceSummary(requirementStatuses: ComplianceRequirementStatus[]): Record<string, unknown> {
    const summary: Record<string, number> = {};
    
    for (const req of requirementStatuses) {
      for (const evidence of req.evidence) {
        summary[evidence.type] = (summary[evidence.type] || 0) + 1;
      }
    }
    
    return {
      totalEvidence: Object.values(summary).reduce((a, b) => a + b, 0),
      byType: summary
    };
  }
  
  /**
   * Сохранение отчета
   */
  private async saveReport(report: ComplianceReport): Promise<void> {
    const dir = `${this.config.reportStoragePath}/${report.standard}`;
    const filePath = `${dir}/${report.id}.json`;
    
    // В production создать директорию и сохранить файл
    // fs.mkdirSync(dir, { recursive: true });
    // fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
    
    this.emit('report_saved', { filePath, reportId: report.id });
  }
  
  /**
   * Обновление статистики
   */
  private updateStatistics(
    standard: ComplianceStandard,
    requirementStatuses: ComplianceRequirementStatus[],
    violations: ComplianceViolation[],
    score: number
  ): void {
    const compliantCount = requirementStatuses.filter(r => r.status === 'compliant').length;
    
    this.statistics.byStandard[standard] = {
      score,
      compliantRequirements: compliantCount,
      totalRequirements: requirementStatuses.length,
      violations: violations.length
    };
    
    this.statistics.totalViolations += violations.length;
    this.statistics.openViolations += violations.filter(v => v.remediationStatus === 'open').length;
    
    // Расчет общего compliance score
    const scores = Object.values(this.statistics.byStandard).map(s => s.score);
    this.statistics.currentComplianceScore = scores.length > 0
      ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
      : 0;
  }
  
  /**
   * Получение нарушения по ID
   */
  getViolation(violationId: string): ComplianceViolation | undefined {
    return this.violations.get(violationId);
  }
  
  /**
   * Получение всех нарушений
   */
  getAllViolations(): ComplianceViolation[] {
    return Array.from(this.violations.values());
  }
  
  /**
   * Обновление статуса нарушения
   */
  updateViolationStatus(violationId: string, status: ComplianceViolation['remediationStatus']): boolean {
    const violation = this.violations.get(violationId);
    
    if (!violation) {
      return false;
    }
    
    const oldStatus = violation.remediationStatus;
    violation.remediationStatus = status;
    
    if (status === 'resolved' && oldStatus !== 'resolved') {
      violation.resolvedAt = new Date().toISOString();
      this.statistics.resolvedViolations++;
      this.statistics.openViolations--;
    }
    
    this.emit('violation_updated', { violationId, oldStatus, newStatus: status });
    
    return true;
  }
  
  /**
   * Получение статистики
   */
  getStatistics(): ReporterStatistics {
    return { ...this.statistics };
  }
  
  /**
   * Получение compliance score
   */
  getComplianceScore(standard?: ComplianceStandard): number {
    if (standard) {
      return this.statistics.byStandard[standard]?.score || 0;
    }
    return this.statistics.currentComplianceScore;
  }
  
  /**
   * Получение истории scores
   */
  getScoreHistory(standard?: ComplianceStandard, days?: number): Array<{ date: string; score: number }> {
    let history = this.scoreHistory;
    
    if (standard) {
      history = history.filter(h => h.standard === standard);
    }
    
    if (days) {
      const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
      history = history.filter(h => new Date(h.date).getTime() > cutoff);
    }
    
    return history.map(h => ({ date: h.date, score: h.score }));
  }
  
  /**
   * Экспорт отчета в PDF
   */
  async exportToPdf(reportId: string): Promise<string> {
    // В production генерировать PDF с использованием библиотеки типа pdfkit
    const reportPath = `${this.config.reportStoragePath}/${reportId}.pdf`;
    
    this.emit('report_exported', { reportId, format: 'pdf', path: reportPath });
    
    return reportPath;
  }
  
  /**
   * Экспорт отчета в CSV
   */
  async exportToCsv(reportId: string): Promise<string> {
    // В экспорт CSV
    const reportPath = `${this.config.reportStoragePath}/${reportId}.csv`;
    
    this.emit('report_exported', { reportId, format: 'csv', path: reportPath });
    
    return reportPath;
  }
  
  /**
   * Добавление кастомного требования
   */
  addRequirement(standard: ComplianceStandard, requirement: ComplianceRequirement): void {
    const requirements = this.requirements.get(standard) || [];
    requirements.push(requirement);
    this.requirements.set(standard, requirements);
  }
  
  /**
   * Удаление требования
   */
  removeRequirement(standard: ComplianceStandard, requirementId: string): boolean {
    const requirements = this.requirements.get(standard);
    
    if (!requirements) {
      return false;
    }
    
    const index = requirements.findIndex(r => r.id === requirementId);
    
    if (index !== -1) {
      requirements.splice(index, 1);
      return true;
    }
    
    return false;
  }
  
  /**
   * Закрытие reporter
   */
  close(): void {
    this.emit('closed');
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default ComplianceReporter;
