/**
 * ============================================================================
 * INCIDENT MANAGER
 * ============================================================================
 * Основной менеджер системы реагирования на инциденты
 * Оркестрирует все компоненты и предоставляет единый API
 * Соответствует NIST SP 800-61 и SANS Incident Response Methodology
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import {
  Incident,
  IncidentLifecycleStage,
  IncidentStatus,
  IncidentSeverity,
  IncidentPriority,
  IncidentDetails,
  Actor,
  IncidentResponseConfig,
  IncidentSearchResult,
  IncidentFilters,
  IncidentSort,
  AuditEvent
} from '../types/incident.types';
import { IncidentClassifier, ClassificationContext } from './IncidentClassifier';
import { PlaybookEngine, PlaybookEngineEvent } from './PlaybookEngine';
import { ForensicsCollector, ForensicsCollectorEvent } from './ForensicsCollector';
import { EvidenceManager, EvidenceManagerEvent } from './EvidenceManager';
import { ContainmentActions, ContainmentActionsEvent } from './ContainmentActions';
import { CommunicationManager, CommunicationManagerEvent } from './CommunicationManager';
import { TimelineReconstructor, TimelineReconstructorEvent } from './TimelineReconstructor';
import { PostIncidentReview, PostIncidentReviewEvent } from './PostIncidentReview';
import { ExternalIntegrations } from './ExternalIntegrations';
import { IncidentReporter, IncidentReporterEvent, ReportType } from './IncidentReporter';
import {
  createMalwareOutbreakPlaybook,
  createDataBreachPlaybook,
  createDDoSAttackPlaybook,
  createInsiderThreatPlaybook,
  createCredentialCompromisePlaybook,
  createRansomwareAttackPlaybook
} from './Playbooks';

/**
 * События Incident Manager
 */
export enum IncidentManagerEvent {
  /** Инцидент создан */
  INCIDENT_CREATED = 'incident_created',
  /** Инцидент обновлен */
  INCIDENT_UPDATED = 'incident_updated',
  /** Инцидент закрыт */
  INCIDENT_CLOSED = 'incident_closed',
  /** Стадия изменена */
  LIFECYCLE_STAGE_CHANGED = 'lifecycle_stage_changed',
  /** Статус изменен */
  STATUS_CHANGED = 'status_changed',
  /** Эскалация */
  ESCALATED = 'escalated',
  /** Аудит событие */
  AUDIT_EVENT = 'audit_event'
}

/**
 * Конфигурация Incident Manager
 */
export interface IncidentManagerConfig {
  /** Конфигурация системы */
  responseConfig: IncidentResponseConfig;
  /** Автозапуск playbook */
  autoStartPlaybook: boolean;
  /** Автоклассификация */
  autoClassification: boolean;
  /** Логирование */
  enableLogging: boolean;
  /** Аудит */
  enableAudit: boolean;
}

/**
 * Основной менеджер системы реагирования на инциденты
 */
export class IncidentManager extends EventEmitter {
  /** Конфигурация */
  private config: IncidentManagerConfig;

  /** Компоненты системы */
  private classifier: IncidentClassifier;
  private playbookEngine: PlaybookEngine;
  private forensicsCollector: ForensicsCollector;
  private evidenceManager: EvidenceManager;
  private containmentActions: ContainmentActions;
  private communicationManager: CommunicationManager;
  private timelineReconstructor: TimelineReconstructor;
  private postIncidentReview: PostIncidentReview;
  private externalIntegrations: ExternalIntegrations;
  private incidentReporter: IncidentReporter;

  /** Хранилище инцидентов */
  private incidents: Map<string, Incident> = new Map();

  /** Индекс по номерам инцидентов */
  private incidentNumberIndex: Map<string, string> = new Map();

  /** Счетчик инцидентов для генерации номеров */
  private incidentCounter: number = 0;

  /**
   * Конструктор Incident Manager
   */
  constructor(config?: Partial<IncidentManagerConfig>) {
    super();
    this.config = this.mergeConfigWithDefaults(config);

    // Инициализация компонентов
    this.classifier = new IncidentClassifier(this.config.responseConfig.classification);
    this.playbookEngine = this.initializePlaybookEngine();
    this.forensicsCollector = new ForensicsCollector(this.config.responseConfig.forensics);
    this.evidenceManager = new EvidenceManager(this.config.responseConfig.evidence);
    this.containmentActions = new ContainmentActions(this.config.responseConfig.containment);
    this.communicationManager = new CommunicationManager(this.config.responseConfig.communication);
    this.timelineReconstructor = new TimelineReconstructor();
    this.postIncidentReview = new PostIncidentReview();
    this.externalIntegrations = new ExternalIntegrations(this.config.responseConfig.integrations);
    this.incidentReporter = new IncidentReporter();

    // Регистрация встроенных playbook
    this.registerBuiltInPlaybooks();

    // Подписка на события компонентов
    this.subscribeToComponentEvents();

    this.log('Incident Manager инициализирован');
  }

  /**
   * Объединение конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<IncidentManagerConfig> | undefined): IncidentManagerConfig {
    const defaultConfig: IncidentManagerConfig = {
      responseConfig: this.getDefaultResponseConfig(),
      autoStartPlaybook: true,
      autoClassification: true,
      enableLogging: true,
      enableAudit: true
    };

    return { ...defaultConfig, ...config };
  }

  /**
   * Конфигурация по умолчанию
   */
  private getDefaultResponseConfig(): IncidentResponseConfig {
    return {
      classification: {
        severityWeights: { businessImpact: 0.4, urgency: 0.35, complexity: 0.25 },
        severityThresholds: { critical: 80, high: 60, medium: 40, low: 20 },
        autoClassificationEnabled: true,
        requiresConfirmation: false
      },
      playbook: {
        autoStartEnabled: true,
        requiresApprovalForCritical: true,
        defaultStepTimeout: 300000,
        defaultRetryCount: 3,
        allowParallelSteps: true,
        autoRollbackOnError: false
      },
      forensics: {
        autoCollectionEnabled: true,
        defaultDataTypes: ['system_logs', 'security_logs', 'process_list', 'network_connections'],
        maxCollectionSize: 10737418240,
        compressData: true,
        encryptData: true,
        storageLocation: '/var/forensics',
        retentionDays: 365
      },
      evidence: {
        autoChainOfCustody: true,
        requiredHashes: ['md5', 'sha256'],
        storageLocation: '/var/evidence',
        defaultRetentionDays: 2555,
        accessRequirements: ['security_clearance']
      },
      containment: {
        autoContainmentEnabled: true,
        actionsRequiringApproval: ['network_isolation', 'account_lockout'],
        maxContainmentDuration: 86400000,
        autoRollbackOnFalsePositive: true,
        notifyOnContainment: true
      },
      communication: {
        templates: [],
        defaultChannels: {},
        escalationOnNoResponse: true,
        responseTimeout: 3600000,
        updateFrequency: 900000
      },
      integrations: [],
      escalation: {
        rules: [],
        autoEscalationEnabled: true,
        levels: []
      },
      sla: {
        bySeverity: {
          critical: { responseTime: 900000, containmentTime: 3600000, eradicationTime: 14400000, recoveryTime: 28800000, statusUpdateTime: 900000 },
          high: { responseTime: 3600000, containmentTime: 14400000, eradicationTime: 28800000, recoveryTime: 86400000, statusUpdateTime: 3600000 },
          medium: { responseTime: 14400000, containmentTime: 28800000, eradicationTime: 86400000, recoveryTime: 172800000, statusUpdateTime: 14400000 },
          low: { responseTime: 86400000, containmentTime: 172800000, eradicationTime: 259200000, recoveryTime: 604800000, statusUpdateTime: 86400000 }
        },
        businessHours: { start: '09:00', end: '18:00', timezone: 'UTC', excludeWeekends: true, holidays: [] },
        trackBreaches: true,
        notifyOnApproachingBreach: true,
        breachWarningTime: 3600000
      },
      audit: {
        enabled: true,
        eventsToAudit: [
          AuditEvent.INCIDENT_CREATED,
          AuditEvent.INCIDENT_UPDATED,
          AuditEvent.INCIDENT_STATUS_CHANGED,
          AuditEvent.PLAYBOOK_STARTED,
          AuditEvent.CONTAINMENT_ACTION_EXECUTED,
          AuditEvent.EVIDENCE_COLLECTED
        ],
        storageLocation: '/var/audit',
        retentionDays: 2555,
        encryptLogs: true,
        immediateWrite: true
      }
    };
  }

  /**
   * Инициализация Playbook Engine
   */
  private initializePlaybookEngine(): PlaybookEngine {
    const engine = new PlaybookEngine({
      defaultStepTimeout: this.config.responseConfig.playbook.defaultStepTimeout,
      defaultRetryCount: this.config.responseConfig.playbook.defaultRetryCount,
      allowParallelSteps: this.config.responseConfig.playbook.allowParallelSteps,
      autoRollbackOnError: this.config.responseConfig.playbook.autoRollbackOnError,
      requiresApprovalForCritical: this.config.responseConfig.playbook.requiresApprovalForCritical
    });

    return engine;
  }

  /**
   * Регистрация встроенных playbook
   */
  private registerBuiltInPlaybooks(): void {
    // Playbook регистрируются в PlaybookEngine при создании
    const playbooks = [
      createMalwareOutbreakPlaybook(),
      createDataBreachPlaybook(),
      createDDoSAttackPlaybook(),
      createInsiderThreatPlaybook(),
      createCredentialCompromisePlaybook(),
      createRansomwareAttackPlaybook()
    ];

    this.log(`Зарегистрировано ${playbooks.length} встроенных playbook`);
  }

  /**
   * Подписка на события компонентов
   */
  private subscribeToComponentEvents(): void {
    // Playbook Engine events
    this.playbookEngine.on(PlaybookEngineEvent.PLAYBOOK_COMPLETED, ({ execution }) => {
      this.log(`Playbook завершен для инцидента ${execution.incidentId}`);
      this.updateIncidentLifecycle(execution.incidentId, IncidentLifecycleStage.ERADICATION);
    });

    // Containment Actions events
    this.containmentActions.on(ContainmentActionsEvent.ACTION_COMPLETED, ({ actionId }) => {
      this.log(`Действие сдерживания ${actionId} завершено`);
    });

    // Evidence Manager events
    this.evidenceManager.on(EvidenceManagerEvent.EVIDENCE_ADDED, ({ evidence }) => {
      this.log(`Улика добавлена: ${evidence.id}`);
      this.audit(AuditEvent.EVIDENCE_COLLECTED, { evidenceId: evidence.id });
    });

    // Communication Manager events
    this.communicationManager.on(CommunicationManagerEvent.NOTIFICATION_SENT, ({ notification }) => {
      this.log(`Уведомление отправлено: ${notification.id}`);
      this.audit(AuditEvent.STAKEHOLDER_NOTIFIED, { notificationId: notification.id });
    });

    // Timeline Reconstructor events
    this.timelineReconstructor.on(TimelineReconstructorEvent.EVENT_ADDED, ({ event }) => {
      this.log(`Событие добавлено в временную шкалу: ${event.id}`);
    });
  }

  /**
   * Создание нового инцидента
   */
  public async createIncident(
    details: IncidentDetails,
    createdBy: Actor,
    options?: {
      severity?: IncidentSeverity;
      priority?: IncidentPriority;
      assignees?: Actor[];
      tags?: string[];
    }
  ): Promise<Incident> {
    this.log(`Создание нового инцидента: ${details.title}`);

    // Генерация номера инцидента
    this.incidentCounter++;
    const incidentNumber = `INC-${new Date().getFullYear()}-${String(this.incidentCounter).padStart(5, '0')}`;

    // Создание инцидента
    const incident: Incident = {
      id: this.generateIncidentId(),
      incidentNumber,
      lifecycleStage: IncidentLifecycleStage.DETECTION,
      category: details.category,
      subCategory: details.subCategory,
      severity: options?.severity || IncidentSeverity.MEDIUM,
      priority: options?.priority || IncidentPriority.P3,
      status: IncidentStatus.NEW,
      title: details.title,
      description: details.description,
      details,
      owner: createdBy,
      assignees: options?.assignees || [],
      activePlaybook: undefined,
      timeline: [],
      evidence: [],
      containmentActions: [],
      stakeholderNotifications: [],
      iocs: details.indicatorsOfCompromise || [],
      mitreMapping: undefined,
      metrics: {
        affectedSystemsCount: details.affectedSystems.length,
        affectedUsersCount: details.affectedUsers.length,
        playbookStepsCompleted: 0,
        automatedActionsCount: 0,
        manualActionsCount: 0,
        stakeholdersNotified: 0,
        evidenceCollected: 0
      },
      tags: options?.tags || [],
      detectedAt: new Date()
    };

    // Сохранение инцидента
    this.incidents.set(incident.id, incident);
    this.incidentNumberIndex.set(incidentNumber, incident.id);

    // Автоклассификация
    if (this.config.autoClassification) {
      await this.classifyIncident(incident, createdBy);
    }

    // Автозапуск playbook
    if (this.config.autoStartPlaybook) {
      await this.startApplicablePlaybook(incident, createdBy);
    }

    // Добавление первого события в временную шкалу
    await this.timelineReconstructor.addEvent(incident.id, {
      type: 'anomaly_detected',
      title: 'Инцидент создан',
      description: `Инцидент ${incidentNumber} создан пользователем ${createdBy.username}`,
      timestamp: new Date(),
      source: 'incident_manager',
      significance: 'high',
      actor: createdBy
    });

    // Событие создания
    this.emit(IncidentManagerEvent.INCIDENT_CREATED, { incident, createdBy });
    this.audit(AuditEvent.INCIDENT_CREATED, { incidentId: incident.id });

    this.log(`Инцидент ${incidentNumber} успешно создан`);

    return incident;
  }

  /**
   * Классификация инцидента
   */
  private async classifyIncident(incident: Incident, classifiedBy: Actor): Promise<void> {
    this.log(`Классификация инцидента ${incident.id}`);

    try {
      const context: ClassificationContext = {
        details: incident.details,
        affectedSystems: incident.details.affectedSystems.map(s => ({
          id: s,
          name: s,
          type: 'server',
          criticality: 'medium',
          hasSensitiveData: false,
          isPublicFacing: false
        })),
        affectedUsers: incident.details.affectedUsers.map(u => ({
          id: u.id,
          username: u.username || 'unknown',
          role: u.role || 'user',
          accessLevel: 'standard',
          hasSensitiveDataAccess: false
        })),
        affectedData: incident.details.affectedData?.map(d => ({
          type: d.type,
          classification: d.classification,
          volume: d.volume,
          recordCount: d.recordCount
        })) || [],
        detectedAt: incident.detectedAt
      };

      const classification = this.classifier.classify(context);

      // Обновление инцидента
      incident.category = classification.category;
      incident.subCategory = classification.subCategory;
      incident.severity = classification.severity;
      incident.priority = classification.priority;
      incident.severityScore = classification.severityScore;

      this.emit(IncidentManagerEvent.INCIDENT_UPDATED, {
        incident,
        changes: ['classification'],
        updatedBy: classifiedBy
      });

      this.log(`Инцидент ${incident.id} классифицирован: ${classification.severity}, ${classification.category}`);
    } catch (error) {
      this.log(`Ошибка классификации: ${error}`, 'error');
    }
  }

  /**
   * Запуск применимого playbook
   */
  private async startApplicablePlaybook(incident: Incident, initiatedBy: Actor): Promise<void> {
    this.log(`Поиск применимого playbook для инцидента ${incident.id}`);

    // В реальной системе здесь был бы выбор playbook на основе категории
    // Для простоты используем заглушку

    this.log(`Playbook будет запущен для инцидента ${incident.id}`);
  }

  /**
   * Получение инцидента по ID
   */
  public getIncident(incidentId: string): Incident | undefined {
    return this.incidents.get(incidentId);
  }

  /**
   * Получение инцидента по номеру
   */
  public getIncidentByNumber(incidentNumber: string): Incident | undefined {
    const incidentId = this.incidentNumberIndex.get(incidentNumber);
    if (incidentId) {
      return this.incidents.get(incidentId);
    }
    return undefined;
  }

  /**
   * Поиск инцидентов
   */
  public searchIncidents(filters?: IncidentFilters, sort?: IncidentSort): IncidentSearchResult {
    let results = Array.from(this.incidents.values());

    // Применение фильтров
    if (filters) {
      if (filters.status) {
        results = results.filter(i => filters.status!.includes(i.status));
      }
      if (filters.category) {
        results = results.filter(i => filters.category!.includes(i.category));
      }
      if (filters.severity) {
        results = results.filter(i => filters.severity!.includes(i.severity));
      }
      if (filters.dateFrom) {
        results = results.filter(i => i.detectedAt >= filters.dateFrom!);
      }
      if (filters.dateTo) {
        results = results.filter(i => i.detectedAt <= filters.dateTo!);
      }
      if (filters.searchText) {
        const searchLower = filters.searchText.toLowerCase();
        results = results.filter(i =>
          i.title.toLowerCase().includes(searchLower) ||
          i.description.toLowerCase().includes(searchLower)
        );
      }
    }

    // Сортировка
    if (sort) {
      results.sort((a, b) => {
        const aVal = a[sort.field];
        const bVal = b[sort.field];

        if (aVal === undefined || bVal === undefined) {
          return 0;
        }

        const comparison = aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
        return sort.order === 'asc' ? comparison : -comparison;
      });
    }

    return {
      incidents: results,
      total: results.length,
      page: 1,
      pageSize: results.length,
      filters,
      sort
    };
  }

  /**
   * Обновление стадии жизненного цикла
   */
  public async updateIncidentLifecycle(
    incidentId: string,
    newStage: IncidentLifecycleStage,
    updatedBy: Actor
  ): Promise<Incident> {
    const incident = this.incidents.get(incidentId);

    if (!incident) {
      throw new Error(`Инцидент ${incidentId} не найден`);
    }

    const oldStage = incident.lifecycleStage;
    incident.lifecycleStage = newStage;

    // Обновление временных меток в зависимости от стадии
    switch (newStage) {
      case IncidentLifecycleStage.CONTAINMENT:
        incident.containedAt = new Date();
        break;
      case IncidentLifecycleStage.ERADICATION:
        incident.eradicatedAt = new Date();
        break;
      case IncidentLifecycleStage.RECOVERY:
        incident.recoveredAt = new Date();
        break;
      case IncidentLifecycleStage.POST_INCIDENT:
        // Запуск post-incident review
        await this.postIncidentReview.initiateReview(incident, [updatedBy], updatedBy);
        break;
      case IncidentLifecycleStage.CLOSED:
        incident.closedAt = new Date();
        incident.status = IncidentStatus.CLOSED;
        break;
    }

    // Событие изменения стадии
    this.emit(IncidentManagerEvent.LIFECYCLE_STAGE_CHANGED, {
      incidentId,
      oldStage,
      newStage,
      updatedBy
    });

    this.emit(IncidentManagerEvent.INCIDENT_UPDATED, {
      incident,
      changes: ['lifecycleStage'],
      updatedBy
    });

    this.audit(AuditEvent.INCIDENT_UPDATED, {
      incidentId,
      changes: { lifecycleStage: { from: oldStage, to: newStage } }
    });

    this.log(`Стадия инцидента ${incidentId} изменена: ${oldStage} -> ${newStage}`);

    return incident;
  }

  /**
   * Выполнение действия сдерживания
   */
  public async executeContainmentAction(
    incidentId: string,
    actionType: string,
    target: string,
    executedBy: Actor,
    parameters?: Record<string, unknown>
  ): Promise<void> {
    const incident = this.incidents.get(incidentId);

    if (!incident) {
      throw new Error(`Инцидент ${incidentId} не найден`);
    }

    this.log(`Выполнение действия сдерживания ${actionType} для инцидента ${incidentId}`);

    // В реальной системе здесь был бы вызов ContainmentActions
    // Для простоты создаем запись действия

    const actionRecord = {
      id: `ca_${Date.now()}`,
      type: actionType,
      name: actionType,
      description: `Действие сдерживания: ${actionType}`,
      target,
      status: 'completed' as const,
      executedBy: executedBy.id,
      executedAt: new Date(),
      result: { success: true, message: 'Выполнено успешно' }
    };

    incident.containmentActions.push(actionRecord);
    incident.metrics.automatedActionsCount++;

    // Добавление события в временную шкалу
    await this.timelineReconstructor.addEvent(incidentId, {
      type: 'containment_action',
      title: actionRecord.name,
      description: actionRecord.description,
      timestamp: new Date(),
      source: 'containment_system',
      significance: 'high',
      verified: true
    });

    this.emit(IncidentManagerEvent.INCIDENT_UPDATED, {
      incident,
      changes: ['containmentActions'],
      updatedBy: executedBy
    });

    this.audit(AuditEvent.CONTAINMENT_ACTION_EXECUTED, {
      incidentId,
      actionType,
      target
    });

    this.log(`Действие сдерживания ${actionType} выполнено для инцидента ${incidentId}`);
  }

  /**
   * Сбор форензика данных
   */
  public async collectForensics(
    incidentId: string,
    dataTypes: string[],
    targetSystems: string[],
    collectedBy: Actor
  ): Promise<string> {
    const incident = this.incidents.get(incidentId);

    if (!incident) {
      throw new Error(`Инцидент ${incidentId} не найден`);
    }

    this.log(`Сбор форензика данных для инцидента ${incidentId}`);

    // В реальной системе здесь был бы вызов ForensicsCollector
    const collectionId = `fc_${Date.now()}`;

    // Преобразование в улики
    const evidence = this.evidenceManager.convertToEvidence(collectionId, incidentId, collectedBy);

    for (const evd of evidence) {
      await this.evidenceManager.addEvidence(evd, collectedBy);
      incident.evidence.push(evd);
    }

    incident.metrics.evidenceCollected = evidence.length;

    // Добавление события в временную шкалу
    await this.timelineReconstructor.addEvent(incidentId, {
      type: 'forensics_collection',
      title: 'Сбор форензика данных',
      description: `Собрано ${evidence.length} улик`,
      timestamp: new Date(),
      source: 'forensics_system',
      significance: 'medium',
      verified: true
    });

    this.emit(IncidentManagerEvent.INCIDENT_UPDATED, {
      incident,
      changes: ['evidence'],
      updatedBy: collectedBy
    });

    this.audit(AuditEvent.EVIDENCE_COLLECTED, {
      incidentId,
      evidenceCount: evidence.length
    });

    return collectionId;
  }

  /**
   * Отправка уведомления стейкхолдерам
   */
  public async notifyStakeholders(
    incidentId: string,
    templateId: string,
    recipients: string[],
    sentBy: Actor
  ): Promise<void> {
    const incident = this.incidents.get(incidentId);

    if (!incident) {
      throw new Error(`Инцидент ${incidentId} не найден`);
    }

    this.log(`Отправка уведомления стейкхолдерам для инцидента ${incidentId}`);

    const notification = await this.communicationManager.sendNotification(
      templateId,
      recipients,
      incident,
      sentBy
    );

    incident.stakeholderNotifications.push(notification);
    incident.metrics.stakeholdersNotified++;

    // Добавление события в временную шкалу
    await this.timelineReconstructor.addEvent(incidentId, {
      type: 'stakeholder_notification',
      title: 'Уведомление стейкхолдеров',
      description: `Отправлено ${recipients.length} получателям`,
      timestamp: new Date(),
      source: 'communication_system',
      significance: 'medium',
      verified: true
    });

    this.emit(IncidentManagerEvent.INCIDENT_UPDATED, {
      incident,
      changes: ['stakeholderNotifications'],
      updatedBy: sentBy
    });

    this.audit(AuditEvent.STAKEHOLDER_NOTIFIED, {
      incidentId,
      recipientCount: recipients.length
    });
  }

  /**
   * Закрытие инцидента
   */
  public async closeIncident(
    incidentId: string,
    closedBy: Actor,
    reason: string
  ): Promise<Incident> {
    const incident = this.incidents.get(incidentId);

    if (!incident) {
      throw new Error(`Инцидент ${incidentId} не найден`);
    }

    this.log(`Закрытие инцидента ${incidentId}. Причина: ${reason}`);

    // Обновление стадии и статуса
    await this.updateIncidentLifecycle(incidentId, IncidentLifecycleStage.CLOSED, closedBy);

    incident.status = IncidentStatus.CLOSED;
    incident.closedAt = new Date();

    // Генерация финального отчета
    const report = await this.incidentReporter.generateIncidentReport(
      incident,
      ReportType.INCIDENT_DETAIL,
      {
        includeTimeline: true,
        includeEvidence: true,
        includePlaybookDetails: true
      }
    );

    // Событие закрытия
    this.emit(IncidentManagerEvent.INCIDENT_CLOSED, {
      incident,
      closedBy,
      reason,
      report
    });

    this.audit(AuditEvent.INCIDENT_UPDATED, {
      incidentId,
      changes: { status: 'closed' }
    });

    this.log(`Инцидент ${incidentId} закрыт`);

    return incident;
  }

  /**
   * Генерация отчета
   */
  public async generateReport(
    incidentId: string,
    reportType: ReportType,
    options?: Record<string, boolean>
  ): Promise<Record<string, unknown>> {
    const incident = this.incidents.get(incidentId);

    if (!incident) {
      throw new Error(`Инцидент ${incidentId} не найден`);
    }

    this.log(`Генерация отчета типа ${reportType} для инцидента ${incidentId}`);

    const report = await this.incidentReporter.generateIncidentReport(
      incident,
      reportType,
      options
    );

    return report.content;
  }

  /**
   * Реконструкция временной шкалы
   */
  public async reconstructTimeline(incidentId: string): Promise<Record<string, unknown>> {
    const incident = this.incidents.get(incidentId);

    if (!incident) {
      throw new Error(`Инцидент ${incidentId} не найден`);
    }

    this.log(`Реконструкция временной шкалы для инцидента ${incidentId}`);

    const result = await this.timelineReconstructor.reconstructTimeline(incident);

    return {
      timeline: result.timeline,
      keyEvents: result.keyEvents,
      gaps: result.gaps,
      summary: result.summary
    };
  }

  /**
   * Аудит событие
   */
  private audit(event: AuditEvent, data: Record<string, unknown>): void {
    if (!this.config.enableAudit) {
      return;
    }

    if (this.config.responseConfig.audit.eventsToAudit.includes(event)) {
      this.emit(IncidentManagerEvent.AUDIT_EVENT, {
        event,
        data,
        timestamp: new Date()
      });

      this.log(`Audit: ${event}`, 'info');
    }
  }

  /**
   * Генерация идентификатора инцидента
   */
  private generateIncidentId(): string {
    return `inc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Логирование
   */
  private log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    if (this.config.enableLogging) {
      const timestamp = new Date().toISOString();
      const prefix = `[IncidentManager] [${timestamp}] [${level.toUpperCase()}]`;
      logger.info(`${prefix} ${message}`);
    }
  }

  /**
   * Получение статистики
   */
  public getStatistics(period?: { from: Date; to: Date }): {
    totalIncidents: number;
    byStatus: Record<string, number>;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
    avgResponseTime: number;
    avgContainmentTime: number;
  } {
    let incidents = Array.from(this.incidents.values());

    if (period) {
      incidents = incidents.filter(
        i => i.detectedAt >= period.from && i.detectedAt <= period.to
      );
    }

    const byStatus: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    let totalResponseTime = 0;
    let totalContainmentTime = 0;
    let responseTimeCount = 0;
    let containmentTimeCount = 0;

    for (const incident of incidents) {
      byStatus[incident.status] = (byStatus[incident.status] || 0) + 1;
      bySeverity[incident.severity] = (bySeverity[incident.severity] || 0) + 1;
      byCategory[incident.category] = (byCategory[incident.category] || 0) + 1;

      if (incident.metrics.timeToRespond) {
        totalResponseTime += incident.metrics.timeToRespond;
        responseTimeCount++;
      }

      if (incident.metrics.timeToContain) {
        totalContainmentTime += incident.metrics.timeToContain;
        containmentTimeCount++;
      }
    }

    return {
      totalIncidents: incidents.length,
      byStatus,
      bySeverity,
      byCategory,
      avgResponseTime: responseTimeCount > 0 ? Math.round(totalResponseTime / responseTimeCount) : 0,
      avgContainmentTime: containmentTimeCount > 0 ? Math.round(totalContainmentTime / containmentTimeCount) : 0
    };
  }
}

/**
 * Экспорт событий менеджера
 */
export { IncidentManagerEvent };
