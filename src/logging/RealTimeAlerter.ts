/**
 * =============================================================================
 * REAL-TIME ALERTER
 * =============================================================================
 * Система real-time алертинга для критических security событий
 * Интеграция: Slack, PagerDuty, Email, SMS, Teams
 * Эскалация, deduplication, rate limiting
 * =============================================================================
 */

import { EventEmitter } from 'events';
import { logger } from './Logger';
import { v4 as uuidv4 } from 'uuid';
import { SecurityEvent, SecuritySeverity } from './StructuredSecurityLogger';

// =============================================================================
// ТИПЫ И ИНТЕРФЕЙСЫ
// =============================================================================

/**
 * Каналы уведомлений
 */
export enum AlertChannel {
  SLACK = 'slack',
  PAGERDUTY = 'pagerduty',
  EMAIL = 'email',
  SMS = 'sms',
  TEAMS = 'teams',
  WEBHOOK = 'webhook'
}

/**
 * Уровни эскалации
 */
export enum EscalationLevel {
  L1 = 'L1', // Initial response
  L2 = 'L2', // Team lead
  L3 = 'L3', // Manager
  L4 = 'L4'  // Executive
}

/**
 * Статус алерта
 */
export enum AlertStatus {
  TRIGGERED = 'triggered',
  ACKNOWLEDGED = 'acknowledged',
  RESOLVED = 'resolved',
  SUPPRESSED = 'suppressed',
  ESCALATED = 'escalated'
}

/**
 * Конфигурация алерта
 */
export interface AlertConfig {
  /** ID правила */
  ruleId: string;
  
  /** Название правила */
  ruleName: string;
  
  /** Какие severity триггерят алерт */
  severityFilter: SecuritySeverity[];
  
  /** Какие типы событий триггерят алерт */
  eventTypes: string[];
  
  /** Каналы для отправки */
  channels: AlertChannel[];
  
  /** Уровень эскалации по умолчанию */
  defaultEscalationLevel: EscalationLevel;
  
  /** Время до эскалации (минуты) */
  escalationTimeoutMinutes: number;
  
  /** Rate limiting (максимум алертов в минуту) */
  rateLimitPerMinute: number;
  
  /** Включить deduplication */
  enableDeduplication: boolean;
  
  /** Окно deduplication (минуты) */
  deduplicationWindowMinutes: number;
}

/**
 * Алерт
 */
export interface Alert {
  /** Уникальный ID алерта */
  alertId: string;
  
  /** ID корреляции */
  correlationId: string;
  
  /** Статус */
  status: AlertStatus;
  
  /** Уровень эскалации */
  escalationLevel: EscalationLevel;
  
  /** Триггерное событие */
  triggerEvent: SecurityEvent;
  
  /** Название алерта */
  title: string;
  
  /** Описание */
  description: string;
  
  /** Severity */
  severity: SecuritySeverity;
  
  /** Время создания */
  createdAt: Date;
  
  /** Время ack */
  acknowledgedAt?: Date;
  
  /** Время решения */
  resolvedAt?: Date;
  
  /** Кто ack */
  acknowledgedBy?: string;
  
  /** Кто решил */
  resolvedBy?: string;
  
  /** Отправленные уведомления */
  notifications: Notification[];
  
  /** Дополнительные данные */
  metadata: Record<string, any>;
}

/**
 * Уведомление
 */
export interface Notification {
  /** ID уведомления */
  notificationId: string;
  
  /** Канал */
  channel: AlertChannel;
  
  /** Статус отправки */
  status: 'sent' | 'failed' | 'pending';
  
  /** Время отправки */
  sentAt?: Date;
  
  /** Ошибка */
  error?: string;
  
  /** Ответ от сервиса */
  response?: any;
}

/**
 * Конфигурация каналов
 */
export interface ChannelConfig {
  slack?: {
    webhookUrl: string;
    defaultChannel: string;
    mentionUsers?: string[];
  };
  pagerduty?: {
    routingKey: string;
    serviceId: string;
  };
  email?: {
    smtpHost: string;
    smtpPort: number;
    from: string;
    recipients: string[];
  };
  sms?: {
    provider: 'twilio' | 'sns';
    fromNumber?: string;
    toNumbers: string[];
  };
  teams?: {
    webhookUrl: string;
  };
  webhook?: {
    url: string;
    headers?: Record<string, string>;
  };
}

/**
 * Конфигурация алертера
 */
export interface RealTimeAlerterConfig {
  /** Конфигурация каналов */
  channels: ChannelConfig;
  
  /** Правила алертинга */
  rules: AlertConfig[];
  
  /** Включить алертинг */
  enabled: boolean;
  
  /** Global rate limiting (алертов в час) */
  globalRateLimitPerHour: number;
  
  /** Тихие часы (не слать алерты) */
  quietHours?: {
    enabled: boolean;
    startHour: number; // 0-23
    endHour: number; // 0-23
  };
}

// =============================================================================
// REAL-TIME ALERTER CLASS
// =============================================================================

export class RealTimeAlerter extends EventEmitter {
  private config: RealTimeAlerterConfig;
  private activeAlerts: Map<string, Alert>;
  private alertHistory: Alert[];
  private deduplicationCache: Map<string, number>;
  private rateLimitCounters: Map<string, number[]>;
  private globalRateLimitCounter: number[];
  private escalationTimers: Map<string, NodeJS.Timeout>;

  constructor(config: RealTimeAlerterConfig) {
    super();
    
    this.config = config;
    this.activeAlerts = new Map();
    this.alertHistory = [];
    this.deduplicationCache = new Map();
    this.rateLimitCounters = new Map();
    this.globalRateLimitCounter = [];
    this.escalationTimers = new Map();
  }

  // =============================================================================
  // ОБРАБОТКА СОБЫТИЙ
  // =============================================================================

  /**
   * Обработка security события
   */
  processEvent(event: SecurityEvent): void {
    if (!this.config.enabled) {
      return;
    }

    // Проверка quiet hours
    if (this.isQuietHours()) {
      this.emit('quiet-hours', event);
      return;
    }

    // Проверка global rate limit
    if (!this.checkGlobalRateLimit()) {
      this.emit('rate-limit-exceeded', { type: 'global', event });
      return;
    }

    // Поиск подходящих правил
    const matchingRules = this.config.rules.filter(rule => 
      this.eventMatchesRule(event, rule)
    );

    for (const rule of matchingRules) {
      this.handleRuleMatch(event, rule);
    }
  }

  /**
   * Проверка соответствия события правилу
   */
  private eventMatchesRule(event: SecurityEvent, rule: AlertConfig): boolean {
    // Проверка severity
    if (!rule.severityFilter.includes(event.severity)) {
      return false;
    }

    // Проверка типа события
    if (rule.eventTypes.length > 0 && !rule.eventTypes.includes(event.eventType)) {
      return false;
    }

    return true;
  }

  /**
   * Обработка совпадения с правилом
   */
  private handleRuleMatch(event: SecurityEvent, rule: AlertConfig): void {
    // Проверка rate limiting для правила
    if (!this.checkRuleRateLimit(rule.ruleId)) {
      this.emit('rate-limit-exceeded', { type: 'rule', ruleId: rule.ruleId, event });
      return;
    }

    // Проверка deduplication
    const dedupKey = this.getDeduplicationKey(event, rule);
    if (rule.enableDeduplication && this.isDuplicate(dedupKey, rule.deduplicationWindowMinutes)) {
      this.emit('duplicate-suppressed', { event, ruleId: rule.ruleId });
      return;
    }

    // Создание алерта
    const alert = this.createAlert(event, rule);

    // Отправка уведомлений
    this.sendNotifications(alert, rule.channels);

    // Запуск таймера эскалации
    this.startEscalationTimer(alert, rule);

    // Сохранение алерта
    this.activeAlerts.set(alert.alertId, alert);
    this.alertHistory.push(alert);

    // Обновление deduplication cache
    if (rule.enableDeduplication) {
      this.updateDeduplicationCache(dedupKey);
    }

    this.emit('alert-created', alert);
  }

  // =============================================================================
  // СОЗДАНИЕ АЛЕРТА
  // =============================================================================

  /**
   * Создание алерта
   */
  private createAlert(event: SecurityEvent, rule: AlertConfig): Alert {
    return {
      alertId: uuidv4(),
      correlationId: event.context.correlationId,
      status: AlertStatus.TRIGGERED,
      escalationLevel: rule.defaultEscalationLevel,
      triggerEvent: event,
      title: this.generateAlertTitle(event),
      description: this.generateAlertDescription(event),
      severity: event.severity,
      createdAt: new Date(),
      notifications: [],
      metadata: {
        ruleId: rule.ruleId,
        ruleName: rule.ruleName
      }
    };
  }

  /**
   * Генерация заголовка алерта
   */
  private generateAlertTitle(event: SecurityEvent): string {
    const actorInfo = event.actor.identifier || event.actor.id || 'Unknown';
    return `[${event.severity}] ${event.eventType} - ${actorInfo}`;
  }

  /**
   * Генерация описания алерта
   */
  private generateAlertDescription(event: SecurityEvent): string {
    const lines: string[] = [
      `**Event Type:** ${event.eventType}`,
      `**Category:** ${event.category}`,
      `**Severity:** ${event.severity}`,
      `**Outcome:** ${event.outcome}`,
      `**Timestamp:** ${event.timestamp}`,
      `**IP Address:** ${event.context.ipAddress}`
    ];

    if (event.actor.identifier) {
      lines.push(`**Actor:** ${event.actor.identifier}`);
    }

    if (event.resource.name) {
      lines.push(`**Resource:** ${event.resource.name}`);
    }

    if (event.error) {
      lines.push(`**Error:** ${event.error.message}`);
    }

    return lines.join('\n');
  }

  // =============================================================================
  // ОТПРАВКА УВЕДОМЛЕНИЙ
  // =============================================================================

  /**
   * Отправка уведомлений по каналам
   */
  private async sendNotifications(alert: Alert, channels: AlertChannel[]): Promise<void> {
    for (const channel of channels) {
      const notification: Notification = {
        notificationId: uuidv4(),
        channel,
        status: 'pending'
      };

      try {
        switch (channel) {
          case AlertChannel.SLACK:
            await this.sendSlackNotification(alert, notification);
            break;
          case AlertChannel.PAGERDUTY:
            await this.sendPagerDutyNotification(alert, notification);
            break;
          case AlertChannel.EMAIL:
            await this.sendEmailNotification(alert, notification);
            break;
          case AlertChannel.SMS:
            await this.sendSMSNotification(alert, notification);
            break;
          case AlertChannel.TEAMS:
            await this.sendTeamsNotification(alert, notification);
            break;
          case AlertChannel.WEBHOOK:
            await this.sendWebhookNotification(alert, notification);
            break;
        }

        notification.status = 'sent';
        notification.sentAt = new Date();
      } catch (error) {
        notification.status = 'failed';
        notification.error = error instanceof Error ? error.message : 'Unknown error';
      }

      alert.notifications.push(notification);
    }
  }

  /**
   * Отправка в Slack
   */
  private async sendSlackNotification(alert: Alert, notification: Notification): Promise<void> {
    const config = this.config.channels.slack;
    if (!config) {
      throw new Error('Slack not configured');
    }

    const color = this.getSeverityColor(alert.severity);
    const mentionUsers = config.mentionUsers?.map(u => `<@${u}>`).join(' ') || '';

    const payload: {
      channel: string;
      username: string;
      icon_emoji: string;
      attachments: Array<{
        color: string;
        title: string;
        text: string;
        fields: Array<{ title: string; value: string; short: boolean }>;
        footer: string;
        ts: number;
      }>;
      text?: string;
    } = {
      channel: config.defaultChannel,
      username: 'Protocol Security',
      icon_emoji: ':shield:',
      text: mentionUsers && alert.severity >= SecuritySeverity.HIGH ? `${mentionUsers} ${alert.title}` : undefined,
      attachments: [{
        color,
        title: alert.title,
        text: alert.description,
        fields: [
          { title: 'Severity', value: alert.severity, short: true },
          { title: 'Status', value: alert.status, short: true },
          { title: 'Escalation', value: alert.escalationLevel, short: true },
          { title: 'Alert ID', value: alert.alertId, short: true }
        ],
        footer: 'Protocol Security System',
        ts: Math.floor(alert.createdAt.getTime() / 1000)
      }]
    };

    // В реальной реализации: fetch(config.webhookUrl, { method: 'POST', body: JSON.stringify(payload) })
    console.log('[Slack] Sending notification:', payload);
    notification.response = { success: true };
  }

  /**
   * Отправка в PagerDuty
   */
  private async sendPagerDutyNotification(alert: Alert, notification: Notification): Promise<void> {
    const config = this.config.channels.pagerduty;
    if (!config) {
      throw new Error('PagerDuty not configured');
    }

    const severity = this.mapSeverityToPagerDuty(alert.severity);

    const payload = {
      routing_key: config.routingKey,
      event_action: 'trigger',
      dedup_key: alert.alertId,
      payload: {
        summary: alert.title,
        severity,
        source: 'protocol-security',
        timestamp: alert.createdAt.toISOString(),
        component: 'security',
        custom_details: {
          alertId: alert.alertId,
          eventType: alert.triggerEvent.eventType,
          actor: alert.triggerEvent.actor,
          correlationId: alert.correlationId
        }
      }
    };

    // В реальной реализации: fetch('https://events.pagerduty.com/v2/enqueue', ...)
    console.log('[PagerDuty] Sending notification:', payload);
    notification.response = { success: true };
  }

  /**
   * Отправка Email
   */
  private async sendEmailNotification(alert: Alert, notification: Notification): Promise<void> {
    const config = this.config.channels.email;
    if (!config) {
      throw new Error('Email not configured');
    }

    const subject = `[${alert.severity}] ${alert.title}`;
    const html = this.generateEmailHtml(alert);

    // В реальной реализации: nodemailer.sendMail(...)
    console.log('[Email] Sending notification:', { to: config.recipients, subject });
    notification.response = { success: true };
  }

  /**
   * Отправка SMS
   */
  private async sendSMSNotification(alert: Alert, notification: Notification): Promise<void> {
    const config = this.config.channels.sms;
    if (!config) {
      throw new Error('SMS not configured');
    }

    // SMS только для CRITICAL и HIGH
    if (alert.severity < SecuritySeverity.HIGH) {
      return;
    }

    const message = `[${alert.severity}] ${alert.title}`;

    // В реальной реализации: Twilio SNS API
    console.log('[SMS] Sending notification:', { to: config.toNumbers, message });
    notification.response = { success: true };
  }

  /**
   * Отправка в Teams
   */
  private async sendTeamsNotification(alert: Alert, notification: Notification): Promise<void> {
    const config = this.config.channels.teams;
    if (!config) {
      throw new Error('Teams not configured');
    }

    const themeColor = this.getSeverityColor(alert.severity);

    const payload = {
      '@type': 'MessageCard',
      '@context': 'http://schema.org/extensions',
      themeColor,
      summary: alert.title,
      sections: [{
        activityTitle: alert.title,
        activitySubtitle: alert.description,
        facts: [
          { name: 'Severity', value: alert.severity },
          { name: 'Status', value: alert.status },
          { name: 'Alert ID', value: alert.alertId }
        ]
      }]
    };

    // В реальной реализации: fetch(config.webhookUrl, ...)
    console.log('[Teams] Sending notification:', payload);
    notification.response = { success: true };
  }

  /**
   * Отправка Webhook
   */
  private async sendWebhookNotification(alert: Alert, notification: Notification): Promise<void> {
    const config = this.config.channels.webhook;
    if (!config) {
      throw new Error('Webhook not configured');
    }

    const payload = {
      alertId: alert.alertId,
      correlationId: alert.correlationId,
      title: alert.title,
      description: alert.description,
      severity: alert.severity,
      status: alert.status,
      escalationLevel: alert.escalationLevel,
      createdAt: alert.createdAt,
      triggerEvent: alert.triggerEvent
    };

    // В реальной реализации: fetch(config.url, ...)
    console.log('[Webhook] Sending notification:', payload);
    notification.response = { success: true };
  }

  // =============================================================================
  // ЭСКАЛАЦИЯ
  // =============================================================================

  /**
   * Запуск таймера эскалации
   */
  private startEscalationTimer(alert: Alert, rule: AlertConfig): void {
    const timeout = rule.escalationTimeoutMinutes * 60 * 1000;

    const timer = setTimeout(() => {
      if (this.activeAlerts.has(alert.alertId)) {
        this.escalateAlert(alert, rule);
      }
    }, timeout);

    this.escalationTimers.set(alert.alertId, timer);
  }

  /**
   * Эскалация алерта
   */
  private escalateAlert(alert: Alert, rule: AlertConfig): void {
    const nextLevel = this.getNextEscalationLevel(alert.escalationLevel);
    
    if (nextLevel) {
      alert.escalationLevel = nextLevel;
      alert.status = AlertStatus.ESCALATED;
      
      // Отправка уведомлений о эскалации
      this.sendNotifications(alert, rule.channels);
      
      this.emit('alert-escalated', alert);
    }
  }

  /**
   * Получение следующего уровня эскалации
   */
  private getNextEscalationLevel(current: EscalationLevel): EscalationLevel | null {
    const levels = [EscalationLevel.L1, EscalationLevel.L2, EscalationLevel.L3, EscalationLevel.L4];
    const currentIndex = levels.indexOf(current);
    
    if (currentIndex < levels.length - 1) {
      return levels[currentIndex + 1];
    }
    
    return null;
  }

  // =============================================================================
  // УПРАВЛЕНИЕ АЛЕРТАМИ
  // =============================================================================

  /**
   * Acknowledge алерта
   */
  acknowledgeAlert(alertId: string, userId: string): boolean {
    const alert = this.activeAlerts.get(alertId);
    
    if (!alert) {
      return false;
    }

    alert.status = AlertStatus.ACKNOWLEDGED;
    alert.acknowledgedAt = new Date();
    alert.acknowledgedBy = userId;

    // Остановка таймера эскалации
    const timer = this.escalationTimers.get(alertId);
    if (timer) {
      clearTimeout(timer);
      this.escalationTimers.delete(alertId);
    }

    this.emit('alert-acknowledged', alert);
    return true;
  }

  /**
   * Resolve алерта
   */
  resolveAlert(alertId: string, userId: string): boolean {
    const alert = this.activeAlerts.get(alertId);
    
    if (!alert) {
      return false;
    }

    alert.status = AlertStatus.RESOLVED;
    alert.resolvedAt = new Date();
    alert.resolvedBy = userId;

    // Перемещение в историю
    this.activeAlerts.delete(alertId);

    this.emit('alert-resolved', alert);
    return true;
  }

  // =============================================================================
  // RATE LIMITING
  // =============================================================================

  /**
   * Проверка global rate limit
   */
  private checkGlobalRateLimit(): boolean {
    const now = Date.now();
    const hourAgo = now - 60 * 60 * 1000;

    // Очистка старых записей
    this.globalRateLimitCounter = this.globalRateLimitCounter.filter(t => t > hourAgo);

    if (this.globalRateLimitCounter.length >= this.config.globalRateLimitPerHour) {
      return false;
    }

    this.globalRateLimitCounter.push(now);
    return true;
  }

  /**
   * Проверка rate limit для правила
   */
  private checkRuleRateLimit(ruleId: string): boolean {
    const now = Date.now();
    const minuteAgo = now - 60 * 1000;

    let counters = this.rateLimitCounters.get(ruleId) || [];
    counters = counters.filter(t => t > minuteAgo);

    const rule = this.config.rules.find(r => r.ruleId === ruleId);
    if (!rule) {
      return true;
    }

    if (counters.length >= rule.rateLimitPerMinute) {
      return false;
    }

    counters.push(now);
    this.rateLimitCounters.set(ruleId, counters);
    return true;
  }

  // =============================================================================
  // DEDUPLICATION
  // =============================================================================

  /**
   * Получение ключа deduplication
   */
  private getDeduplicationKey(event: SecurityEvent, rule: AlertConfig): string {
    return `${rule.ruleId}:${event.eventType}:${event.actor.id || 'anonymous'}:${event.context.ipAddress}`;
  }

  /**
   * Проверка на дубликат
   */
  private isDuplicate(key: string, windowMinutes: number): boolean {
    const lastSeen = this.deduplicationCache.get(key);
    
    if (!lastSeen) {
      return false;
    }

    const now = Date.now();
    const windowMs = windowMinutes * 60 * 1000;

    return now - lastSeen < windowMs;
  }

  /**
   * Обновление deduplication cache
   */
  private updateDeduplicationCache(key: string): void {
    this.deduplicationCache.set(key, Date.now());
  }

  // =============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // =============================================================================

  /**
   * Проверка quiet hours
   */
  private isQuietHours(): boolean {
    const quietHours = this.config.quietHours;
    
    if (!quietHours?.enabled) {
      return false;
    }

    const currentHour = new Date().getUTCHours();
    
    if (quietHours.startHour <= quietHours.endHour) {
      return currentHour >= quietHours.startHour && currentHour < quietHours.endHour;
    } else {
      // Переход через полночь
      return currentHour >= quietHours.startHour || currentHour < quietHours.endHour;
    }
  }

  /**
   * Получение цвета для severity
   */
  private getSeverityColor(severity: SecuritySeverity): string {
    const colors: Record<SecuritySeverity, string> = {
      [SecuritySeverity.CRITICAL]: '#dc3545',
      [SecuritySeverity.HIGH]: '#fd7e14',
      [SecuritySeverity.MEDIUM]: '#ffc107',
      [SecuritySeverity.LOW]: '#17a2b8',
      [SecuritySeverity.INFO]: '#28a745'
    };
    
    return colors[severity] || '#6c757d';
  }

  /**
   * Маппинг severity для PagerDuty
   */
  private mapSeverityToPagerDuty(severity: SecuritySeverity): string {
    const mapping: Record<SecuritySeverity, string> = {
      [SecuritySeverity.CRITICAL]: 'critical',
      [SecuritySeverity.HIGH]: 'error',
      [SecuritySeverity.MEDIUM]: 'warning',
      [SecuritySeverity.LOW]: 'info',
      [SecuritySeverity.INFO]: 'info'
    };
    
    return mapping[severity] || 'info';
  }

  /**
   * Генерация HTML для email
   */
  private generateEmailHtml(alert: Alert): string {
    return `
      <!DOCTYPE html>
      <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; }
            .header { background: ${this.getSeverityColor(alert.severity)}; color: white; padding: 20px; }
            .content { padding: 20px; }
            .field { margin: 10px 0; }
            .label { font-weight: bold; }
          </style>
        </head>
        <body>
          <div class="header">
            <h1>${alert.title}</h1>
          </div>
          <div class="content">
            <div class="field"><span class="label">Severity:</span> ${alert.severity}</div>
            <div class="field"><span class="label">Status:</span> ${alert.status}</div>
            <div class="field"><span class="label">Escalation:</span> ${alert.escalationLevel}</div>
            <div class="field"><span class="label">Alert ID:</span> ${alert.alertId}</div>
            <hr/>
            <pre>${alert.description}</pre>
          </div>
        </body>
      </html>
    `;
  }

  // =============================================================================
  // СТАТИСТИКА
  // =============================================================================

  /**
   * Получение статистики
   */
  getStats(): {
    activeAlerts: number;
    totalAlerts: number;
    alertsBySeverity: Record<SecuritySeverity, number>;
    alertsByStatus: Record<AlertStatus, number>;
    notificationsSent: number;
  } {
    const stats = {
      activeAlerts: this.activeAlerts.size,
      totalAlerts: this.alertHistory.length,
      alertsBySeverity: {} as Record<SecuritySeverity, number>,
      alertsByStatus: {} as Record<AlertStatus, number>,
      notificationsSent: 0
    };

    // Подсчёт по severity
    for (const severity of Object.values(SecuritySeverity)) {
      stats.alertsBySeverity[severity] = this.alertHistory.filter(a => a.severity === severity).length;
    }

    // Подсчёт по статусам
    for (const status of Object.values(AlertStatus)) {
      stats.alertsByStatus[status] = [...this.activeAlerts.values()].filter(a => a.status === status).length;
    }

    // Подсчёт уведомлений
    stats.notificationsSent = this.alertHistory.reduce(
      (sum, alert) => sum + alert.notifications.length, 
      0
    );

    return stats;
  }
}

// =============================================================================
// ЭКСПОРТ
// =============================================================================

export function createRealTimeAlerter(config: RealTimeAlerterConfig): RealTimeAlerter {
  return new RealTimeAlerter(config);
}
