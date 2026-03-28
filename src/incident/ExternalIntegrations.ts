/**
 * ============================================================================
 * EXTERNAL INTEGRATIONS
 * ============================================================================
 * Модуль интеграции с внешними сервисами (Slack, PagerDuty, Jira, ServiceNow)
 * Реализует унифицированный API для внешних коммуникаций
 * ============================================================================
 */

import { EventEmitter } from 'events';
import {
  IntegrationConfig,
  IntegrationType,
  Incident,
  IncidentSeverity,
  IncidentPriority
} from '../types/incident.types';

/**
 * События интеграций
 */
export enum ExternalIntegrationsEvent {
  /** Интеграция подключена */
  INTEGRATION_CONNECTED = 'integration_connected',
  /** Интеграция отключена */
  INTEGRATION_DISCONNECTED = 'integration_disconnected',
  /** Ошибка интеграции */
  INTEGRATION_ERROR = 'integration_error',
  /** Webhook получен */
  WEBHOOK_RECEIVED = 'webhook_received',
  /** Данные отправлены */
  DATA_SENT = 'data_sent'
}

/**
 * Результат вызова интеграции
 */
export interface IntegrationResult {
  /** Успешно ли выполнено */
  success: boolean;
  /** ID ресурса во внешней системе */
  externalId?: string;
  /** URL ресурса */
  url?: string;
  /** Сообщение */
  message?: string;
  /** Данные ответа */
  responseData?: Record<string, unknown>;
  /** Время выполнения (мс) */
  durationMs: number;
}

/**
 * Модуль внешних интеграций
 */
export class ExternalIntegrations extends EventEmitter {
  /** Конфигурации интеграций */
  private integrations: Map<IntegrationType, IntegrationConfig> = new Map();

  /** Статус подключений */
  private connectionStatus: Map<IntegrationType, boolean> = new Map();

  /**
   * Конструктор интеграций
   */
  constructor(integrationConfigs?: IntegrationConfig[]) {
    super();
    if (integrationConfigs) {
      this.initializeIntegrations(integrationConfigs);
    }
  }

  /**
   * Инициализация интеграций
   */
  private initializeIntegrations(configs: IntegrationConfig[]): void {
    for (const config of configs) {
      this.integrations.set(config.type, config);
      this.connectionStatus.set(config.type, config.enabled);
    }
  }

  /**
   * Добавление интеграции
   */
  public addIntegration(config: IntegrationConfig): void {
    this.integrations.set(config.type, config);
    this.connectionStatus.set(config.type, config.enabled);
    this.emit(ExternalIntegrationsEvent.INTEGRATION_CONNECTED, {
      type: config.type,
      name: config.name
    });
  }

  /**
   * Удаление интеграции
   */
  public removeIntegration(type: IntegrationType): void {
    this.integrations.delete(type);
    this.connectionStatus.delete(type);
    this.emit(ExternalIntegrationsEvent.INTEGRATION_DISCONNECTED, {
      type
    });
  }

  /**
   * Получение конфигурации интеграции
   */
  public getIntegration(type: IntegrationType): IntegrationConfig | undefined {
    return this.integrations.get(type);
  }

  /**
   * Проверка доступности интеграции
   */
  public isIntegrationEnabled(type: IntegrationType): boolean {
    const config = this.integrations.get(type);
    return config?.enabled === true;
  }

  // ============================================================================
  // SLACK INTEGRATION
  // ============================================================================

  /**
   * Отправка сообщения в Slack
   */
  public async sendSlackMessage(
    channel: string,
    message: string,
    options?: {
      blocks?: Record<string, unknown>[];
      attachments?: Record<string, unknown>[];
      threadTs?: string;
    }
  ): Promise<IntegrationResult> {
    const startTime = Date.now();
    const config = this.integrations.get(IntegrationType.SLACK);

    if (!config?.enabled) {
      throw new Error('Slack integration is not enabled');
    }

    try {
      // Симуляция отправки в Slack API
      await this.sleep(200);

      const result: IntegrationResult = {
        success: true,
        externalId: `msg_${Date.now()}`,
        message: `Message sent to ${channel}`,
        durationMs: Date.now() - startTime,
        responseData: {
          channel,
          ts: Date.now().toString()
        }
      };

      this.emit(ExternalIntegrationsEvent.DATA_SENT, {
        type: IntegrationType.SLACK,
        channel
      });

      return result;
    } catch (error) {
      this.emit(ExternalIntegrationsEvent.INTEGRATION_ERROR, {
        type: IntegrationType.SLACK,
        error: (error as Error).message
      });

      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  /**
   * Создание Slack канала для инцидента
   */
  public async createSlackChannel(incident: Incident): Promise<IntegrationResult> {
    const channelName = `incident-${incident.incidentNumber.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;

    return this.sendSlackMessage(channelName, `Incident channel created for ${incident.incidentNumber}`, {
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `🚨 Incident: ${incident.incidentNumber}`
          }
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Severity:* ${incident.severity}` },
            { type: 'mrkdwn', text: `*Category:* ${incident.category}` },
            { type: 'mrkdwn', text: `*Status:* ${incident.status}` },
            { type: 'mrkdwn', text: `*Priority:* P${incident.priority}` }
          ]
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: incident.title
          }
        }
      ]
    });
  }

  // ============================================================================
  // PAGERDUTY INTEGRATION
  // ============================================================================

  /**
   * Создание инцидента в PagerDuty
   */
  public async createPagerDutyIncident(
    title: string,
    description: string,
    severity: IncidentSeverity,
    options?: {
      serviceId?: string;
      routingKey?: string;
      customDetails?: Record<string, unknown>;
    }
  ): Promise<IntegrationResult> {
    const startTime = Date.now();
    const config = this.integrations.get(IntegrationType.PAGERDUTY);

    if (!config?.enabled) {
      throw new Error('PagerDuty integration is not enabled');
    }

    try {
      // Симуляция создания инцидента в PagerDuty Events API v2
      await this.sleep(300);

      const pdSeverity = this.mapSeverityToPagerDuty(severity);

      const result: IntegrationResult = {
        success: true,
        externalId: `pd_${Date.now()}`,
        url: `https://protocol.pagerduty.com/incidents/pd_${Date.now()}`,
        message: `PagerDuty incident created: ${title}`,
        durationMs: Date.now() - startTime,
        responseData: {
          incident_key: `incident_${Date.now()}`,
          status: 'triggered',
          urgency: pdSeverity
        }
      };

      this.emit(ExternalIntegrationsEvent.DATA_SENT, {
        type: IntegrationType.PAGERDUTY,
        incidentId: result.externalId
      });

      return result;
    } catch (error) {
      this.emit(ExternalIntegrationsEvent.INTEGRATION_ERROR, {
        type: IntegrationType.PAGERDUTY,
        error: (error as Error).message
      });

      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  /**
   * Обновление статуса в PagerDuty
   */
  public async updatePagerDutyIncident(
    externalId: string,
    status: 'acknowledged' | 'resolved'
  ): Promise<IntegrationResult> {
    const startTime = Date.now();
    const config = this.integrations.get(IntegrationType.PAGERDUTY);

    if (!config?.enabled) {
      throw new Error('PagerDuty integration is not enabled');
    }

    try {
      await this.sleep(200);

      return {
        success: true,
        externalId,
        message: `PagerDuty incident ${status}`,
        durationMs: Date.now() - startTime,
        responseData: { status }
      };
    } catch (error) {
      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  /**
   * Маппинг серьезности на PagerDuty urgency
   */
  private mapSeverityToPagerDuty(severity: IncidentSeverity): string {
    const mapping: Record<IncidentSeverity, string> = {
      [IncidentSeverity.CRITICAL]: 'high',
      [IncidentSeverity.HIGH]: 'high',
      [IncidentSeverity.MEDIUM]: 'low',
      [IncidentSeverity.LOW]: 'low',
      [IncidentSeverity.INFORMATIONAL]: 'low'
    };
    return mapping[severity] || 'low';
  }

  // ============================================================================
  // JIRA INTEGRATION
  // ============================================================================

  /**
   * Создание задачи в Jira
   */
  public async createJiraIssue(
    projectKey: string,
    summary: string,
    description: string,
    issueType: string = 'Incident',
    options?: {
      priority?: string;
      assignee?: string;
      labels?: string[];
      components?: string[];
      customFields?: Record<string, unknown>;
    }
  ): Promise<IntegrationResult> {
    const startTime = Date.now();
    const config = this.integrations.get(IntegrationType.JIRA);

    if (!config?.enabled) {
      throw new Error('Jira integration is not enabled');
    }

    try {
      // Симуляция создания задачи в Jira REST API
      await this.sleep(400);

      const issueKey = `${projectKey}-${Math.floor(Math.random() * 10000)}`;

      const result: IntegrationResult = {
        success: true,
        externalId: issueKey,
        url: `https://protocol.atlassian.net/browse/${issueKey}`,
        message: `Jira issue created: ${issueKey}`,
        durationMs: Date.now() - startTime,
        responseData: {
          key: issueKey,
          self: `https://protocol.atlassian.net/rest/api/3/issue/${issueKey}`
        }
      };

      this.emit(ExternalIntegrationsEvent.DATA_SENT, {
        type: IntegrationType.JIRA,
        issueKey
      });

      return result;
    } catch (error) {
      this.emit(ExternalIntegrationsEvent.INTEGRATION_ERROR, {
        type: IntegrationType.JIRA,
        error: (error as Error).message
      });

      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  /**
   * Обновление задачи в Jira
   */
  public async updateJiraIssue(
    issueKey: string,
    updates: {
      status?: string;
      assignee?: string;
      description?: string;
      labels?: string[];
    }
  ): Promise<IntegrationResult> {
    const startTime = Date.now();
    const config = this.integrations.get(IntegrationType.JIRA);

    if (!config?.enabled) {
      throw new Error('Jira integration is not enabled');
    }

    try {
      await this.sleep(300);

      return {
        success: true,
        externalId: issueKey,
        message: `Jira issue ${issueKey} updated`,
        durationMs: Date.now() - startTime,
        responseData: updates
      };
    } catch (error) {
      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  /**
   * Добавление комментария в Jira
   */
  public async addJiraComment(issueKey: string, comment: string): Promise<IntegrationResult> {
    const startTime = Date.now();
    const config = this.integrations.get(IntegrationType.JIRA);

    if (!config?.enabled) {
      throw new Error('Jira integration is not enabled');
    }

    try {
      await this.sleep(200);

      return {
        success: true,
        externalId: issueKey,
        message: 'Comment added',
        durationMs: Date.now() - startTime,
        responseData: {
          body: comment
        }
      };
    } catch (error) {
      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  // ============================================================================
  // SERVICENOW INTEGRATION
  // ============================================================================

  /**
   * Создание инцидента в ServiceNow
   */
  public async createServiceNowIncident(
    shortDescription: string,
    description: string,
    options?: {
      callerId?: string;
      category?: string;
      subcategory?: string;
      impact?: string;
      urgency?: string;
      assignmentGroup?: string;
      cmdbCi?: string;
    }
  ): Promise<IntegrationResult> {
    const startTime = Date.now();
    const config = this.integrations.get(IntegrationType.SERVICENOW);

    if (!config?.enabled) {
      throw new Error('ServiceNow integration is not enabled');
    }

    try {
      // Симуляция создания инцидента в ServiceNow Table API
      await this.sleep(400);

      const incidentNumber = `INC${Date.now()}`;

      const result: IntegrationResult = {
        success: true,
        externalId: incidentNumber,
        url: `https://protocol.service-now.com/nav_to.do?uri=incident.do?sys_id=${incidentNumber}`,
        message: `ServiceNow incident created: ${incidentNumber}`,
        durationMs: Date.now() - startTime,
        responseData: {
          number: incidentNumber,
          state: '1', // New
          sys_id: incidentNumber
        }
      };

      this.emit(ExternalIntegrationsEvent.DATA_SENT, {
        type: IntegrationType.SERVICENOW,
        incidentNumber
      });

      return result;
    } catch (error) {
      this.emit(ExternalIntegrationsEvent.INTEGRATION_ERROR, {
        type: IntegrationType.SERVICENOW,
        error: (error as Error).message
      });

      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  /**
   * Обновление инцидента в ServiceNow
   */
  public async updateServiceNowIncident(
    incidentNumber: string,
    updates: {
      state?: string;
      workNotes?: string;
      closeCode?: string;
      closeNotes?: string;
    }
  ): Promise<IntegrationResult> {
    const startTime = Date.now();
    const config = this.integrations.get(IntegrationType.SERVICENOW);

    if (!config?.enabled) {
      throw new Error('ServiceNow integration is not enabled');
    }

    try {
      await this.sleep(300);

      return {
        success: true,
        externalId: incidentNumber,
        message: `ServiceNow incident ${incidentNumber} updated`,
        durationMs: Date.now() - startTime,
        responseData: updates
      };
    } catch (error) {
      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  // ============================================================================
  // WEBHOOK INTEGRATION
  // ============================================================================

  /**
   * Отправка webhook
   */
  public async sendWebhook(
    url: string,
    payload: Record<string, unknown>,
    options?: {
      method?: 'POST' | 'PUT' | 'PATCH';
      headers?: Record<string, string>;
      secret?: string;
    }
  ): Promise<IntegrationResult> {
    const startTime = Date.now();

    try {
      // Симуляция отправки webhook
      await this.sleep(200);

      // В реальной системе здесь был бы HTTP запрос
      // const response = await fetch(url, { ... })

      const result: IntegrationResult = {
        success: true,
        message: `Webhook sent to ${url}`,
        durationMs: Date.now() - startTime,
        responseData: {
          url,
          method: options?.method || 'POST',
          payloadSize: JSON.stringify(payload).length
        }
      };

      this.emit(ExternalIntegrationsEvent.DATA_SENT, {
        type: IntegrationType.WEBHOOK,
        url
      });

      return result;
    } catch (error) {
      this.emit(ExternalIntegrationsEvent.INTEGRATION_ERROR, {
        type: IntegrationType.WEBHOOK,
        error: (error as Error).message
      });

      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  /**
   * Обработка входящего webhook
   */
  public async handleIncomingWebhook(
    payload: Record<string, unknown>,
    signature?: string
  ): Promise<{ valid: boolean; data: Record<string, unknown> }> {
    // Симуляция обработки webhook
    this.emit(ExternalIntegrationsEvent.WEBHOOK_RECEIVED, {
      payload,
      timestamp: new Date()
    });

    return {
      valid: true,
      data: payload
    };
  }

  // ============================================================================
  // EMAIL INTEGRATION
  // ============================================================================

  /**
   * Отправка email
   */
  public async sendEmail(
    to: string[],
    subject: string,
    body: string,
    options?: {
      cc?: string[];
      bcc?: string[];
      attachments?: { filename: string; content: string }[];
      html?: boolean;
    }
  ): Promise<IntegrationResult> {
    const startTime = Date.now();
    const config = this.integrations.get(IntegrationType.EMAIL);

    if (!config?.enabled) {
      throw new Error('Email integration is not enabled');
    }

    try {
      // Симуляция отправки email
      await this.sleep(300);

      return {
        success: true,
        externalId: `email_${Date.now()}`,
        message: `Email sent to ${to.join(', ')}`,
        durationMs: Date.now() - startTime,
        responseData: {
          messageId: `msg_${Date.now()}`,
          accepted: to
        }
      };
    } catch (error) {
      return {
        success: false,
        message: (error as Error).message,
        durationMs: Date.now() - startTime
      };
    }
  }

  // ============================================================================
  // ОБЩИЕ МЕТОДЫ
  // ============================================================================

  /**
   * Тестирование подключения интеграции
   */
  public async testIntegration(type: IntegrationType): Promise<{ success: boolean; message: string }> {
    const config = this.integrations.get(type);

    if (!config) {
      return {
        success: false,
        message: `Integration ${type} not configured`
      };
    }

    try {
      // Симуляция теста подключения
      await this.sleep(500);

      return {
        success: config.enabled,
        message: config.enabled
          ? `Connection to ${config.name} successful`
          : `Integration ${config.name} is disabled`
      };
    } catch (error) {
      return {
        success: false,
        message: `Connection test failed: ${(error as Error).message}`
      };
    }
  }

  /**
   * Получение статуса всех интеграций
   */
  public getIntegrationStatus(): Map<IntegrationType, { enabled: boolean; connected: boolean }> {
    const status = new Map<IntegrationType, { enabled: boolean; connected: boolean }>();

    for (const [type, config] of this.integrations.entries()) {
      status.set(type, {
        enabled: config.enabled,
        connected: this.connectionStatus.get(type) || false
      });
    }

    return status;
  }

  /**
   * Утилита для задержки
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
