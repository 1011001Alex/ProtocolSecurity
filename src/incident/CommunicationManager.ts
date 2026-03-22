/**
 * ============================================================================
 * COMMUNICATION MANAGER
 * ============================================================================
 * Модуль управления коммуникацией со стейкхолдерами
 * Реализует шаблоны уведомлений и мультиканальную рассылку
 * ============================================================================
 */

import { EventEmitter } from 'events';
import {
  CommunicationTemplate,
  StakeholderType,
  CommunicationChannel,
  StakeholderNotification,
  Incident,
  IncidentSeverity,
  IncidentPriority,
  CommunicationConfig,
  Actor
} from '../types/incident.types';

/**
 * События менеджера коммуникации
 */
export enum CommunicationManagerEvent {
  /** Уведомление отправлено */
  NOTIFICATION_SENT = 'notification_sent',
  /** Уведомление доставлено */
  NOTIFICATION_DELIVERED = 'notification_delivered',
  /** Уведомление прочитано */
  NOTIFICATION_READ = 'notification_read',
  /** Ошибка отправки */
  SEND_ERROR = 'send_error',
  /** Шаблон использован */
  TEMPLATE_USED = 'template_used',
  /** Требуется одобрение */
  APPROVAL_REQUIRED = 'approval_required'
}

/**
 * Конфигурация менеджера коммуникации
 */
export interface CommunicationManagerConfig {
  /** Шаблоны коммуникации */
  templates: CommunicationTemplate[];
  /** Каналы по умолчанию */
  defaultChannels: Partial<Record<StakeholderType, CommunicationChannel[]>>;
  /** Эскалация при отсутствии ответа */
  escalationOnNoResponse: boolean;
  /** Время ожидания ответа (мс) */
  responseTimeout: number;
  /** Частота обновлений (мс) */
  updateFrequency: number;
  /** Логирование */
  enableLogging: boolean;
}

/**
 * Менеджер коммуникации со стейкхолдерами
 */
export class CommunicationManager extends EventEmitter {
  /** Конфигурация */
  private config: CommunicationManagerConfig;

  /** История уведомлений */
  private notificationHistory: Map<string, StakeholderNotification[]> = new Map();

  /** Шаблоны */
  private templates: Map<string, CommunicationTemplate> = new Map();

  /**
   * Конструктор менеджера
   */
  constructor(config?: Partial<CommunicationManagerConfig>) {
    super();
    this.config = this.mergeConfigWithDefaults(config);
    this.initializeTemplates();
  }

  /**
   * Объединение конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<CommunicationManagerConfig> | undefined): CommunicationManagerConfig {
    const defaultConfig: CommunicationManagerConfig = {
      templates: [],
      defaultChannels: {
        [StakeholderType.SECURITY_TEAM]: [CommunicationChannel.SLACK, CommunicationChannel.PAGERDUTY],
        [StakeholderType.EXECUTIVE_MANAGEMENT]: [CommunicationChannel.EMAIL, CommunicationChannel.PHONE],
        [StakeholderType.IT_OPERATIONS]: [CommunicationChannel.SLACK],
        [StakeholderType.LEGAL_TEAM]: [CommunicationChannel.EMAIL],
        [StakeholderType.PUBLIC_RELATIONS]: [CommunicationChannel.EMAIL],
        [StakeholderType.REGULATORS]: [CommunicationChannel.EMAIL],
        [StakeholderType.CUSTOMERS]: [CommunicationChannel.EMAIL],
        [StakeholderType.PARTNERS]: [CommunicationChannel.EMAIL],
        [StakeholderType.LAW_ENFORCEMENT]: [CommunicationChannel.PHONE, CommunicationChannel.EMAIL]
      },
      escalationOnNoResponse: true,
      responseTimeout: 3600000, // 1 час
      updateFrequency: 900000, // 15 минут
      enableLogging: true
    };

    return { ...defaultConfig, ...config };
  }

  /**
   * Инициализация шаблонов
   */
  private initializeTemplates(): void {
    // Встроенные шаблоны
    const builtInTemplates: CommunicationTemplate[] = [
      // Security Team Alert
      {
        id: 'security-team-alert',
        name: 'Security Team Alert',
        description: 'Экстренное уведомление команды безопасности',
        stakeholderType: StakeholderType.SECURITY_TEAM,
        channel: CommunicationChannel.SLACK,
        subject: '🚨 SECURITY INCIDENT: {{incidentNumber}} - {{severity}}',
        body: `**SECURITY INCIDENT ALERT**

**Incident Number:** {{incidentNumber}}
**Severity:** {{severity}}
**Category:** {{category}}
**Title:** {{title}}

**Description:**
{{description}}

**Detected At:** {{detectedAt}}
**Affected Systems:** {{affectedSystemsCount}}

**Immediate Actions Required:**
1. Review incident details in the dashboard
2. Join the incident response channel
3. Begin initial assessment

**Incident Link:** {{incidentUrl}}`,
        priority: IncidentPriority.P1,
        variables: ['incidentNumber', 'severity', 'category', 'title', 'description', 'detectedAt', 'affectedSystemsCount', 'incidentUrl'],
        requiresApproval: false,
        automatic: true,
        language: 'en',
        version: '1.0.0'
      },

      // Executive Brief
      {
        id: 'executive-brief',
        name: 'Executive Management Brief',
        description: 'Краткий отчет для руководства',
        stakeholderType: StakeholderType.EXECUTIVE_MANAGEMENT,
        channel: CommunicationChannel.EMAIL,
        subject: 'CONFIDENTIAL: Security Incident {{incidentNumber}} - {{severity}}',
        body: `**CONFIDENTIAL - EXECUTIVE BRIEF**

**Incident Reference:** {{incidentNumber}}
**Classification:** {{severity}}
**Type:** {{category}}

**Executive Summary:**
{{executiveSummary}}

**Business Impact:**
{{businessImpact}}

**Current Status:** {{status}}
**Response Team:** Activated

**Actions Taken:**
{{actionsTaken}}

**Next Update:** {{nextUpdateTime}}

**Contact:** {{incidentCommander}}

---
*This is an automated message. Please do not reply.*`,
        priority: IncidentPriority.P1,
        variables: ['incidentNumber', 'severity', 'category', 'executiveSummary', 'businessImpact', 'status', 'actionsTaken', 'nextUpdateTime', 'incidentCommander'],
        requiresApproval: true,
        automatic: false,
        language: 'en',
        version: '1.0.0'
      },

      // User Notice
      {
        id: 'user-notice',
        name: 'Affected User Notice',
        description: 'Уведомление затронутых пользователей',
        stakeholderType: StakeholderType.CUSTOMERS,
        channel: CommunicationChannel.EMAIL,
        subject: 'Important Security Notice - Account {{accountReference}}',
        body: `Dear Valued User,

We are writing to inform you about a security incident that may have affected your account.

**What Happened:**
{{incidentDescription}}

**What Information Was Involved:**
{{affectedData}}

**What We Are Doing:**
{{remediationActions}}

**What You Can Do:**
{{userActions}}

**For More Information:**
{{contactInfo}}

We sincerely apologize for any inconvenience this may cause.

Sincerely,
{{companyName}} Security Team`,
        priority: IncidentPriority.P3,
        variables: ['accountReference', 'incidentDescription', 'affectedData', 'remediationActions', 'userActions', 'contactInfo', 'companyName'],
        requiresApproval: true,
        automatic: false,
        language: 'en',
        version: '1.0.0'
      },

      // Regulatory Notice
      {
        id: 'regulatory-notice',
        name: 'Regulatory Authority Notice',
        description: 'Уведомление регуляторных органов',
        stakeholderType: StakeholderType.REGULATORS,
        channel: CommunicationChannel.EMAIL,
        subject: 'Data Breach Notification - {{organizationName}} - {{referenceNumber}}',
        body: `**DATA BREACH NOTIFICATION**

**Organization:** {{organizationName}}
**Reference Number:** {{referenceNumber}}
**Date of Notification:** {{notificationDate}}

**Nature of Breach:**
{{breachDescription}}

**Categories of Data Affected:**
{{dataCategories}}

**Number of Individuals Affected:** {{affectedCount}}

**Date of Breach:** {{breachDate}}
**Date of Discovery:** {{discoveryDate}}

**Measures Taken:**
{{measuresTaken}}

**Data Protection Officer Contact:**
{{dpoContact}}

This notification is submitted in accordance with {{regulation}}.`,
        priority: IncidentPriority.P2,
        variables: ['organizationName', 'referenceNumber', 'notificationDate', 'breachDescription', 'dataCategories', 'affectedCount', 'breachDate', 'discoveryDate', 'measuresTaken', 'dpoContact', 'regulation'],
        requiresApproval: true,
        automatic: false,
        language: 'en',
        version: '1.0.0'
      },

      // Status Update
      {
        id: 'status-update',
        name: 'Incident Status Update',
        description: 'Обновление статуса инцидента',
        stakeholderType: StakeholderType.SECURITY_TEAM,
        channel: CommunicationChannel.SLACK,
        subject: '📋 Status Update: {{incidentNumber}}',
        body: `**INCIDENT STATUS UPDATE**

**Incident:** {{incidentNumber}}
**Current Status:** {{status}}
**Lifecycle Stage:** {{lifecycleStage}}

**Update Summary:**
{{updateSummary}}

**Progress:**
{{progress}}

**Blockers:**
{{blockers}}

**Next Milestone:** {{nextMilestone}}

**Incident Channel:** {{channelLink}}`,
        priority: IncidentPriority.P3,
        variables: ['incidentNumber', 'status', 'lifecycleStage', 'updateSummary', 'progress', 'blockers', 'nextMilestone', 'channelLink'],
        requiresApproval: false,
        automatic: true,
        language: 'en',
        version: '1.0.0'
      }
    ];

    // Регистрация шаблонов
    for (const template of builtInTemplates) {
      this.templates.set(template.id, template);
    }

    // Добавление пользовательских шаблонов из конфига
    for (const template of this.config.templates) {
      this.templates.set(template.id, template);
    }
  }

  /**
   * Отправка уведомления
   */
  public async sendNotification(
    templateId: string,
    recipients: string[],
    incident: Incident,
    sentBy: Actor,
    customVariables?: Record<string, string>
  ): Promise<StakeholderNotification> {
    this.log(`Отправка уведомления по шаблону: ${templateId}`);

    // Получение шаблона
    const template = this.templates.get(templateId);

    if (!template) {
      throw new Error(`Шаблон ${templateId} не найден`);
    }

    // Проверка одобрения
    if (template.requiresApproval) {
      this.emit(CommunicationManagerEvent.APPROVAL_REQUIRED, {
        template,
        recipients,
        incident
      });
      throw new Error(`Шаблон ${templateId} требует одобрения`);
    }

    // Подготовка переменных
    const variables = this.prepareVariables(template, incident, customVariables);

    // Рендеринг сообщения
    const subject = this.renderTemplate(template.subject, variables);
    const body = this.renderTemplate(template.body, variables);

    // Создание уведомления
    const notification: StakeholderNotification = {
      id: this.generateNotificationId(),
      stakeholderType: template.stakeholderType,
      channel: template.channel,
      templateId,
      subject,
      body,
      recipients,
      status: 'pending',
      sentBy: sentBy.id
    };

    // Отправка через канал
    try {
      await this.sendViaChannel(notification, template);

      notification.status = 'sent';
      notification.sentAt = new Date();

      // Событие отправки
      this.emit(CommunicationManagerEvent.NOTIFICATION_SENT, {
        notification,
        template
      });

      this.log(`Уведомление ${notification.id} успешно отправлено`);
    } catch (error) {
      notification.status = 'failed';
      notification.errors = [(error as Error).message];

      this.emit(CommunicationManagerEvent.SEND_ERROR, {
        notification,
        error: (error as Error).message
      });

      this.log(`Ошибка отправки уведомления: ${error}`, 'error');
      throw error;
    }

    // Сохранение в историю
    this.addToHistory(incident.id, notification);

    // Событие использования шаблона
    this.emit(CommunicationManagerEvent.TEMPLATE_USED, {
      templateId,
      notification
    });

    return notification;
  }

  /**
   * Подготовка переменных для шаблона
   */
  private prepareVariables(
    template: CommunicationTemplate,
    incident: Incident,
    customVariables?: Record<string, string>
  ): Record<string, string> {
    const variables: Record<string, string> = {
      incidentNumber: incident.incidentNumber,
      severity: incident.severity,
      category: incident.category,
      title: incident.title,
      description: incident.description,
      detectedAt: incident.detectedAt.toISOString(),
      status: incident.status,
      lifecycleStage: incident.lifecycleStage,
      affectedSystemsCount: incident.metrics.affectedSystemsCount.toString(),
      affectedUsersCount: incident.metrics.affectedUsersCount.toString(),
      priority: `P${incident.priority}`,
      executiveSummary: incident.details.description.substring(0, 200) + '...',
      businessImpact: incident.metrics.businessImpactEstimate?.operationalImpact || 'Assessing...',
      actionsTaken: incident.containmentActions.length.toString(),
      nextUpdateTime: new Date(Date.now() + this.config.updateFrequency).toISOString(),
      incidentCommander: incident.owner?.username || 'TBD',
      incidentUrl: `https://incident.protocol.local/${incident.id}`,
      channelLink: `https://slack.protocol.local/incident-${incident.id}`,
      organizationName: 'Protocol Inc.',
      referenceNumber: incident.incidentNumber,
      notificationDate: new Date().toISOString(),
      breachDescription: incident.description,
      dataCategories: incident.details.affectedData?.map(d => d.type).join(', ') || 'TBD',
      affectedCount: incident.metrics.affectedUsersCount.toString(),
      breachDate: incident.detectedAt.toISOString(),
      discoveryDate: incident.detectedAt.toISOString(),
      measuresTaken: 'Containment and eradication in progress',
      dpoContact: 'dpo@protocol.local',
      regulation: 'GDPR Article 33',
      companyName: 'Protocol Inc.',
      accountReference: incident.id,
      incidentDescription: incident.description,
      affectedData: incident.details.affectedData?.map(d => d.description).join(', ') || 'TBD',
      remediationActions: incident.containmentActions.map(a => a.name).join(', '),
      userActions: 'Please change your password and enable MFA',
      contactInfo: 'security@protocol.local',
      updateSummary: 'Investigation ongoing',
      progress: `${incident.activePlaybook?.progress || 0}%`,
      blockers: 'None',
      nextMilestone: 'Containment completion'
    };

    // Добавление пользовательских переменных
    if (customVariables) {
      Object.assign(variables, customVariables);
    }

    return variables;
  }

  /**
   * Рендеринг шаблона
   */
  private renderTemplate(template: string, variables: Record<string, string>): string {
    let result = template;

    for (const [key, value] of Object.entries(variables)) {
      const placeholder = new RegExp(`{{${key}}}`, 'g');
      result = result.replace(placeholder, value);
    }

    return result;
  }

  /**
   * Отправка через канал
   */
  private async sendViaChannel(
    notification: StakeholderNotification,
    template: CommunicationTemplate
  ): Promise<void> {
    // Симуляция отправки через различные каналы
    await this.sleep(500);

    this.log(`Отправка через ${notification.channel} получателям: ${notification.recipients.join(', ')}`);

    // В реальной системе здесь была бы интеграция с внешними сервисами
    switch (notification.channel) {
      case CommunicationChannel.SLACK:
        await this.sendToSlack(notification);
        break;
      case CommunicationChannel.EMAIL:
        await this.sendToEmail(notification);
        break;
      case CommunicationChannel.PAGERDUTY:
        await this.sendToPagerDuty(notification);
        break;
      case CommunicationChannel.PHONE:
        await this.sendToPhone(notification);
        break;
      case CommunicationChannel.SMS:
        await this.sendToSMS(notification);
        break;
      default:
        throw new Error(`Неподдерживаемый канал: ${notification.channel}`);
    }
  }

  /**
   * Отправка в Slack
   */
  private async sendToSlack(notification: StakeholderNotification): Promise<void> {
    // Симуляция отправки в Slack
    this.log(`Slack: Отправка сообщения в канал security-alerts`);
  }

  /**
   * Отправка по Email
   */
  private async sendToEmail(notification: StakeholderNotification): Promise<void> {
    // Симуляция отправки email
    this.log(`Email: Отправка письма получателям: ${notification.recipients.join(', ')}`);
  }

  /**
   * Отправка в PagerDuty
   */
  private async sendToPagerDuty(notification: StakeholderNotification): Promise<void> {
    // Симуляция создания инцидента в PagerDuty
    this.log(`PagerDuty: Создание инцидента`);
  }

  /**
   * Отправка через Phone
   */
  private async sendToPhone(notification: StakeholderNotification): Promise<void> {
    // Симуляция телефонного звонка
    this.log(`Phone: Звонок получателю: ${notification.recipients[0]}`);
  }

  /**
   * Отправка через SMS
   */
  private async sendToSMS(notification: StakeholderNotification): Promise<void> {
    // Симуляция отправки SMS
    this.log(`SMS: Отправка сообщения получателю: ${notification.recipients[0]}`);
  }

  /**
   * Добавление в историю
   */
  private addToHistory(incidentId: string, notification: StakeholderNotification): void {
    if (!this.notificationHistory.has(incidentId)) {
      this.notificationHistory.set(incidentId, []);
    }
    this.notificationHistory.get(incidentId)!.push(notification);
  }

  /**
   * Получение истории уведомлений инцидента
   */
  public getNotificationHistory(incidentId: string): StakeholderNotification[] {
    return this.notificationHistory.get(incidentId) || [];
  }

  /**
   * Получение шаблона
   */
  public getTemplate(templateId: string): CommunicationTemplate | undefined {
    return this.templates.get(templateId);
  }

  /**
   * Получение всех шаблонов
   */
  public getAllTemplates(): CommunicationTemplate[] {
    return Array.from(this.templates.values());
  }

  /**
   * Добавление пользовательского шаблона
   */
  public addTemplate(template: CommunicationTemplate): void {
    this.templates.set(template.id, template);
    this.log(`Шаблон ${template.id} добавлен`);
  }

  /**
   * Массовая отправка уведомлений
   */
  public async sendBulkNotification(
    templateId: string,
    recipientGroups: Map<StakeholderType, string[]>,
    incident: Incident,
    sentBy: Actor
  ): Promise<{
    sent: number;
    failed: number;
    results: StakeholderNotification[];
  }> {
    const results: StakeholderNotification[] = [];
    let sent = 0;
    let failed = 0;

    for (const [stakeholderType, recipients] of recipientGroups.entries()) {
      try {
        const notification = await this.sendNotification(
          templateId,
          recipients,
          incident,
          sentBy
        );
        results.push(notification);
        sent++;
      } catch (error) {
        failed++;
        this.log(`Ошибка отправки для ${stakeholderType}: ${error}`, 'error');
      }
    }

    return { sent, failed, results };
  }

  /**
   * Генерация идентификатора уведомления
   */
  private generateNotificationId(): string {
    return `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Утилита для задержки
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Логирование
   */
  private log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    if (this.config.enableLogging) {
      const timestamp = new Date().toISOString();
      const prefix = `[CommunicationManager] [${timestamp}] [${level.toUpperCase()}]`;
      console.log(`${prefix} ${message}`);
    }
  }

  /**
   * Получение статистики коммуникации
   */
  public getCommunicationStats(incidentId?: string): {
    totalNotifications: number;
    byChannel: Record<string, number>;
    byStatus: Record<string, number>;
    byStakeholder: Record<string, number>;
  } {
    let notifications: StakeholderNotification[] = [];

    if (incidentId) {
      notifications = this.getNotificationHistory(incidentId);
    } else {
      for (const history of this.notificationHistory.values()) {
        notifications = notifications.concat(history);
      }
    }

    const byChannel: Record<string, number> = {};
    const byStatus: Record<string, number> = {};
    const byStakeholder: Record<string, number> = {};

    for (const notification of notifications) {
      byChannel[notification.channel] = (byChannel[notification.channel] || 0) + 1;
      byStatus[notification.status] = (byStatus[notification.status] || 0) + 1;
      byStakeholder[notification.stakeholderType] = (byStakeholder[notification.stakeholderType] || 0) + 1;
    }

    return {
      totalNotifications: notifications.length,
      byChannel,
      byStatus,
      byStakeholder
    };
  }
}

/**
 * Экспорт событий менеджера
 */
export { CommunicationManagerEvent };
