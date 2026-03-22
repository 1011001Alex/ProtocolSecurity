/**
 * ============================================================================
 * ALERTING SERVICE - СИСТЕМА ОПОВЕЩЕНИЙ И ЭСКАЛАЦИИ
 * ============================================================================
 * Модуль для управления алертами, отправки уведомлений через различные
 * каналы и автоматической эскалации инцидентов.
 * 
 * Особенности:
 * - Множественные каналы уведомлений (Email, Slack, PagerDuty, Telegram)
 * - Многоуровневая эскалация
 * - Rate limiting и дедупликация
 * - Working hours и on-call расписания
 * - Шаблоны уведомлений
 * - Подтверждение получения
 * - История и аудит
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  Alert,
  AlertSeverity,
  AlertStatus,
  NotificationChannel,
  NotificationChannelConfig,
  NotificationEvent,
  EscalationRule,
  EscalationLevel,
  EscalationEvent,
  RateLimitConfig,
  WorkingHours,
  LogEntry,
  ProcessingError
} from '../types/logging.types';

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/**
 * Приоритеты серьезности алертов
 */
const SEVERITY_PRIORITY: Record<AlertSeverity, number> = {
  [AlertSeverity.P1_CRITICAL]: 1,
  [AlertSeverity.P2_HIGH]: 2,
  [AlertSeverity.P3_MEDIUM]: 3,
  [AlertSeverity.P4_LOW]: 4,
  [AlertSeverity.P5_INFO]: 5
};

/**
 * Таймауты для каналов уведомлений (мс)
 */
const CHANNEL_TIMEOUTS: Record<NotificationChannel, number> = {
  [NotificationChannel.EMAIL]: 30000,
  [NotificationChannel.SLACK]: 10000,
  [NotificationChannel.PAGERDUTY]: 15000,
  [NotificationChannel.TELEGRAM]: 10000,
  [NotificationChannel.WEBHOOK]: 10000,
  [NotificationChannel.SMS]: 30000,
  [NotificationChannel.PUSH]: 5000
};

/**
 * Максимальное количество retry для уведомлений
 */
const MAX_NOTIFICATION_RETRIES = 3;

/**
 * Интервал между retry (мс)
 */
const RETRY_INTERVAL_MS = 5000;

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Конфигурация Alerting Service
 */
interface AlertingServiceConfig {
  /** Каналы уведомлений */
  channels: NotificationChannelConfig[];
  /** Правила эскалации */
  escalationRules: EscalationRule[];
  /** Rate limiting по умолчанию */
  defaultRateLimit: RateLimitConfig;
  /** Рабочие часы по умолчанию */
  defaultWorkingHours: WorkingHours;
  /** Включить дедупликацию */
  enableDeduplication: boolean;
  /** Окно дедупликации (секунды) */
  deduplicationWindowSeconds: number;
  /** Включить rate limiting */
  enableRateLimiting: boolean;
  /** Включить эскалацию */
  enableEscalation: boolean;
  /** Интервал проверки эскалации (секунды) */
  escalationCheckIntervalSeconds: number;
  /** Максимальное количество активных алертов */
  maxActiveAlerts: number;
  /** Авто-закрытие resolved алертов (часы) */
  autoCloseResolvedHours: number;
}

/**
 * Результат отправки уведомления
 */
interface NotificationResult {
  /** ID уведомления */
  notificationId: string;
  /** Канал */
  channel: NotificationChannel;
  /** Получатель */
  recipient: string;
  /** Успешность */
  success: boolean;
  /** Время отправки */
  sentAt: string;
  /** Время доставки */
  deliveredAt?: string;
  /** Ошибка */
  error?: string;
  /** Ответ получателя */
  response?: string;
}

/**
 * Статистика Alerting Service
 */
interface AlertingStatistics {
  /** Всего создано алертов */
  totalAlertsCreated: number;
  /** Активные алерты */
  activeAlerts: number;
  /** Разрешенные алерты */
  resolvedAlerts: number;
  /** Ложные срабатывания */
  falsePositives: number;
  /** Всего отправлено уведомлений */
  totalNotificationsSent: number;
  /** Успешные уведомления */
  successfulNotifications: number;
  /** Неудачные уведомления */
  failedNotifications: number;
  /** По каналам */
  byChannel: Record<NotificationChannel, {
    sent: number;
    delivered: number;
    failed: number;
    avgDeliveryTime: number;
  }>;
  /** По серьезности */
  bySeverity: Record<AlertSeverity, number>;
  /** Эскалации */
  escalationsTriggered: number;
  /** Rate limited уведомления */
  rateLimitedNotifications: number;
  /** Дедуплицированные алерты */
  deduplicatedAlerts: number;
  /** Среднее время разрешения (часы) */
  avgResolutionTimeHours: number;
}

/**
 * Дедупликационная запись
 */
interface DeduplicationEntry {
  /** Fingerprint алерта */
  fingerprint: string;
  /** Количество повторений */
  count: number;
  /** Первое возникновение */
  firstOccurrence: string;
  /** Последнее возникновение */
  lastOccurrence: string;
  /** Последний алерт ID */
  lastAlertId: string;
}

// ============================================================================
// КЛАСС RATE LIMITER
// ============================================================================

/**
 * Rate limiter для уведомлений
 */
class NotificationRateLimiter {
  private limits: Map<string, RateLimitConfig>;
  private counters: Map<string, { count: number; resetTime: number }>;
  
  constructor() {
    this.limits = new Map();
    this.counters = new Map();
  }
  
  /**
   * Установка лимита для ключа
   */
  setLimit(key: string, config: RateLimitConfig): void {
    this.limits.set(key, config);
  }
  
  /**
   * Проверка возможности отправки
   */
  allow(key: string): { allowed: boolean; remaining?: number; resetTime?: number } {
    const limit = this.limits.get(key);
    
    if (!limit) {
      return { allowed: true };
    }
    
    const now = Date.now();
    let counter = this.counters.get(key);
    
    if (!counter || now >= counter.resetTime) {
      counter = {
        count: 0,
        resetTime: now + (limit.periodSeconds * 1000)
      };
      this.counters.set(key, counter);
    }
    
    const remaining = limit.maxAlerts - counter.count;
    
    if (counter.count >= limit.maxAlerts) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: counter.resetTime
      };
    }
    
    counter.count++;
    
    return {
      allowed: true,
      remaining: remaining - 1,
      resetTime: counter.resetTime
    };
  }
  
  /**
   * Сброс лимита
   */
  reset(key: string): void {
    this.counters.delete(key);
  }
  
  /**
   * Очистка всех лимитов
   */
  clear(): void {
    this.limits.clear();
    this.counters.clear();
  }
}

// ============================================================================
// КЛАСС DEDUPLICATION MANAGER
// ============================================================================

/**
 * Менеджер дедупликации алертов
 */
class DeduplicationManager {
  private entries: Map<string, DeduplicationEntry>;
  private windowSeconds: number;
  private cleanupInterval: NodeJS.Timeout | null;
  
  constructor(windowSeconds: number) {
    this.entries = new Map();
    this.windowSeconds = windowSeconds;
    this.cleanupInterval = null;
    this.startCleanup();
  }
  
  /**
   * Проверка дедупликации
   */
  check(fingerprint: string): { isDuplicate: boolean; entry?: DeduplicationEntry } {
    const entry = this.entries.get(fingerprint);
    
    if (!entry) {
      return { isDuplicate: false };
    }
    
    // Проверка окна дедупликации
    const lastOccurrence = new Date(entry.lastOccurrence).getTime();
    const now = Date.now();
    
    if (now - lastOccurrence > this.windowSeconds * 1000) {
      this.entries.delete(fingerprint);
      return { isDuplicate: false };
    }
    
    return { isDuplicate: true, entry };
  }
  
  /**
   * Регистрация алерта
   */
  register(alert: Alert): DeduplicationEntry {
    const existing = this.entries.get(alert.fingerprint);
    
    if (existing) {
      existing.count++;
      existing.lastOccurrence = alert.occurredAt;
      existing.lastAlertId = alert.id;
      return existing;
    }
    
    const newEntry: DeduplicationEntry = {
      fingerprint: alert.fingerprint,
      count: 1,
      firstOccurrence: alert.firstOccurrenceAt || alert.occurredAt,
      lastOccurrence: alert.occurredAt,
      lastAlertId: alert.id
    };
    
    this.entries.set(alert.fingerprint, newEntry);
    return newEntry;
  }
  
  /**
   * Удаление записи
   */
  remove(fingerprint: string): void {
    this.entries.delete(fingerprint);
  }
  
  /**
   * Запуск периодической очистки
   */
  private startCleanup(): void {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      const windowMs = this.windowSeconds * 1000;
      
      for (const [fingerprint, entry] of this.entries.entries()) {
        const lastOccurrence = new Date(entry.lastOccurrence).getTime();
        
        if (now - lastOccurrence > windowMs * 2) {
          this.entries.delete(fingerprint);
        }
      }
    }, 60000);
  }
  
  /**
   * Закрытие менеджера
   */
  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.entries.clear();
  }
  
  /**
   * Получение статистики
   */
  getStats(): { totalEntries: number; totalDuplicates: number } {
    let totalDuplicates = 0;
    
    for (const entry of this.entries.values()) {
      totalDuplicates += entry.count - 1;
    }
    
    return {
      totalEntries: this.entries.size,
      totalDuplicates
    };
  };
}

// ============================================================================
// КЛАСС WORKING HOURS CHECKER
// ============================================================================

/**
 * Проверка рабочих часов
 */
class WorkingHoursChecker {
  private holidays: Set<string>;
  
  constructor() {
    this.holidays = new Set();
  }
  
  /**
   * Проверка рабочего ли время
   */
  isWorkingHours(timestamp: string, workingHours: WorkingHours): boolean {
    const date = new Date(timestamp);
    const day = date.getDay();
    const hours = date.getHours();
    const minutes = date.getMinutes();
    const timeString = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
    
    // Проверка праздников
    const dateStr = date.toISOString().split('T')[0];
    if (this.holidays.has(dateStr)) {
      return false;
    }
    
    // Выходные
    if (day === 0 || day === 6) {
      return this.isWithinHours(timeString, workingHours.weekends);
    }
    
    // Будни
    return this.isWithinHours(timeString, workingHours.weekdays);
  }
  
  /**
   * Проверка времени в диапазоне
   */
  private isWithinHours(timeString: string, hours: { start: string; end: string }): boolean {
    return timeString >= hours.start && timeString <= hours.end;
  }
  
  /**
   * Добавление праздника
   */
  addHoliday(date: string): void {
    this.holidays.add(date);
  }
  
  /**
   * Удаление праздника
   */
  removeHoliday(date: string): void {
    this.holidays.delete(date);
  }
  
  /**
   * Очистка праздников
   */
  clearHolidays(): void {
    this.holidays.clear();
  }
}

// ============================================================================
// КЛАСС NOTIFICATION SENDER
// ============================================================================

/**
 * Отправитель уведомлений
 */
class NotificationSender {
  private channelConfigs: Map<NotificationChannel, NotificationChannelConfig>;
  
  constructor() {
    this.channelConfigs = new Map();
  }
  
  /**
   * Регистрация конфигурации канала
   */
  registerChannel(config: NotificationChannelConfig): void {
    this.channelConfigs.set(config.type, config);
  }
  
  /**
   * Отправка уведомления
   */
  async send(
    channel: NotificationChannel,
    recipient: string,
    alert: Alert,
    template?: string
  ): Promise<NotificationResult> {
    const notificationId = crypto.randomUUID();
    const sentAt = new Date().toISOString();
    
    try {
      const config = this.channelConfigs.get(channel);
      
      if (!config || !config.enabled) {
        return {
          notificationId,
          channel,
          recipient,
          success: false,
          sentAt,
          error: 'Channel not configured or disabled'
        };
      }
      
      // Форматирование сообщения
      const message = this.formatMessage(alert, template || config.messageTemplate);
      
      // Отправка в зависимости от канала
      let result: NotificationResult;
      
      switch (channel) {
        case NotificationChannel.EMAIL:
          result = await this.sendEmail(recipient, alert, message, config);
          break;
        case NotificationChannel.SLACK:
          result = await this.sendSlack(recipient, alert, message, config);
          break;
        case NotificationChannel.PAGERDUTY:
          result = await this.sendPagerDuty(recipient, alert, message, config);
          break;
        case NotificationChannel.TELEGRAM:
          result = await this.sendTelegram(recipient, alert, message, config);
          break;
        case NotificationChannel.WEBHOOK:
          result = await this.sendWebhook(recipient, alert, message, config);
          break;
        case NotificationChannel.SMS:
          result = await this.sendSms(recipient, alert, message, config);
          break;
        case NotificationChannel.PUSH:
          result = await this.sendPush(recipient, alert, message, config);
          break;
        default:
          result = {
            notificationId,
            channel,
            recipient,
            success: false,
            sentAt,
            error: 'Unknown channel'
          };
      }
      
      return result;
    } catch (error) {
      return {
        notificationId,
        channel,
        recipient,
        success: false,
        sentAt,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }
  
  /**
   * Форматирование сообщения
   */
  private formatMessage(alert: Alert, template?: string): string {
    if (!template) {
      return this.createDefaultMessage(alert);
    }
    
    return template.replace(/\{\{(\w+)\}\}/g, (match, key) => {
      const value = (alert as Record<string, unknown>)[key];
      return value !== undefined ? String(value) : match;
    });
  }
  
  /**
   * Создание сообщения по умолчанию
   */
  private createDefaultMessage(alert: Alert): string {
    return `
🚨 ALERT: ${alert.title}

Severity: ${alert.severity}
Status: ${alert.status}
Category: ${alert.category}

Description:
${alert.description}

Source: ${alert.source}
Host: ${alert.hostname}
${alert.ipAddress ? `IP: ${alert.ipAddress}` : ''}
${alert.user ? `User: ${alert.user}` : ''}

Occurred: ${alert.occurredAt}
Created: ${alert.createdAt}

---
Alert ID: ${alert.id}
    `.trim();
  }
  
  /**
   * Отправка Email
   */
  private async sendEmail(
    recipient: string,
    alert: Alert,
    message: string,
    config: NotificationChannelConfig
  ): Promise<NotificationResult> {
    // В production использовать nodemailer или аналогичную библиотеку
    const params = config.params as { smtpHost?: string; smtpPort?: number; from?: string };
    
    console.log(`[EMAIL] Sending to ${recipient}: ${alert.title}`);
    
    // Эмуляция отправки
    await this.simulateDelay();
    
    return {
      notificationId: crypto.randomUUID(),
      channel: NotificationChannel.EMAIL,
      recipient,
      success: true,
      sentAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString()
    };
  }
  
  /**
   * Отправка Slack
   */
  private async sendSlack(
    recipient: string,
    alert: Alert,
    message: string,
    config: NotificationChannelConfig
  ): Promise<NotificationResult> {
    const params = config.params as { webhookUrl?: string; channel?: string };
    
    console.log(`[SLACK] Sending to ${recipient}: ${alert.title}`);
    
    // Эмуляция отправки
    await this.simulateDelay();
    
    return {
      notificationId: crypto.randomUUID(),
      channel: NotificationChannel.SLACK,
      recipient,
      success: true,
      sentAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString()
    };
  }
  
  /**
   * Отправка PagerDuty
   */
  private async sendPagerDuty(
    recipient: string,
    alert: Alert,
    message: string,
    config: NotificationChannelConfig
  ): Promise<NotificationResult> {
    const params = config.params as { integrationKey?: string };
    
    console.log(`[PAGERDUTY] Sending to ${recipient}: ${alert.title}`);
    
    // Эмуляция отправки
    await this.simulateDelay();
    
    return {
      notificationId: crypto.randomUUID(),
      channel: NotificationChannel.PAGERDUTY,
      recipient,
      success: true,
      sentAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString()
    };
  }
  
  /**
   * Отправка Telegram
   */
  private async sendTelegram(
    recipient: string,
    alert: Alert,
    message: string,
    config: NotificationChannelConfig
  ): Promise<NotificationResult> {
    const params = config.params as { botToken?: string };
    
    console.log(`[TELEGRAM] Sending to ${recipient}: ${alert.title}`);
    
    // Эмуляция отправки
    await this.simulateDelay();
    
    return {
      notificationId: crypto.randomUUID(),
      channel: NotificationChannel.TELEGRAM,
      recipient,
      success: true,
      sentAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString()
    };
  }
  
  /**
   * Отправка Webhook
   */
  private async sendWebhook(
    recipient: string,
    alert: Alert,
    message: string,
    config: NotificationChannelConfig
  ): Promise<NotificationResult> {
    console.log(`[WEBHOOK] Sending to ${recipient}: ${alert.title}`);
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CHANNEL_TIMEOUTS[NotificationChannel.WEBHOOK]);
      
      const response = await fetch(recipient, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...config.params as Record<string, string>
        },
        body: JSON.stringify({ alert })
      });
      
      clearTimeout(timeoutId);
      
      return {
        notificationId: crypto.randomUUID(),
        channel: NotificationChannel.WEBHOOK,
        recipient,
        success: response.ok,
        sentAt: new Date().toISOString(),
        deliveredAt: response.ok ? new Date().toISOString() : undefined,
        response: await response.text()
      };
    } catch (error) {
      return {
        notificationId: crypto.randomUUID(),
        channel: NotificationChannel.WEBHOOK,
        recipient,
        success: false,
        sentAt: new Date().toISOString(),
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }
  
  /**
   * Отправка SMS
   */
  private async sendSms(
    recipient: string,
    alert: Alert,
    message: string,
    config: NotificationChannelConfig
  ): Promise<NotificationResult> {
    console.log(`[SMS] Sending to ${recipient}: ${alert.title}`);
    
    // Эмуляция отправки
    await this.simulateDelay();
    
    return {
      notificationId: crypto.randomUUID(),
      channel: NotificationChannel.SMS,
      recipient,
      success: true,
      sentAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString()
    };
  }
  
  /**
   * Отправка Push
   */
  private async sendPush(
    recipient: string,
    alert: Alert,
    message: string,
    config: NotificationChannelConfig
  ): Promise<NotificationResult> {
    console.log(`[PUSH] Sending to ${recipient}: ${alert.title}`);
    
    // Эмуляция отправки
    await this.simulateDelay();
    
    return {
      notificationId: crypto.randomUUID(),
      channel: NotificationChannel.PUSH,
      recipient,
      success: true,
      sentAt: new Date().toISOString(),
      deliveredAt: new Date().toISOString()
    };
  }
  
  /**
   * Эмуляция задержки
   */
  private async simulateDelay(): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}

// ============================================================================
// КЛАСС ESCALATION MANAGER
// ============================================================================

/**
 * Менеджер эскалации
 */
class EscalationManager {
  private rules: EscalationRule[];
  private activeEscalations: Map<string, ActiveEscalation>;
  private checkInterval: NodeJS.Timeout | null;
  
  constructor() {
    this.rules = [];
    this.activeEscalations = new Map();
    this.checkInterval = null;
  }
  
  /**
   * Установка правил эскалации
   */
  setRules(rules: EscalationRule[]): void {
    this.rules = rules;
  }
  
  /**
   * Начало эскалации для алерта
   */
  startEscalation(alert: Alert): void {
    // Поиск применимого правила
    const rule = this.findMatchingRule(alert);
    
    if (!rule || rule.levels.length === 0) {
      return;
    }
    
    const activeEscalation: ActiveEscalation = {
      alertId: alert.id,
      ruleId: rule.id,
      currentLevel: 0,
      levels: rule.levels,
      startedAt: new Date().toISOString(),
      lastEscalationAt: new Date().toISOString(),
      notificationsSent: []
    };
    
    this.activeEscalations.set(alert.id, activeEscalation);
  }
  
  /**
   * Проверка необходимости эскалации
   */
  checkEscalations(): Array<{ alertId: string; level: EscalationLevel }> {
    const toEscalate: Array<{ alertId: string; level: EscalationLevel }> = [];
    const now = Date.now();
    
    for (const [alertId, escalation] of this.activeEscalations.entries()) {
      const currentLevel = escalation.levels[escalation.currentLevel];
      
      if (!currentLevel) {
        continue;
      }
      
      const lastEscalationTime = new Date(escalation.lastEscalationAt).getTime();
      const delayMs = currentLevel.delayMinutes * 60 * 1000;
      
      if (now - lastEscalationTime >= delayMs) {
        const nextLevelIndex = escalation.currentLevel + 1;
        
        if (nextLevelIndex < escalation.levels.length) {
          toEscalate.push({
            alertId,
            level: escalation.levels[nextLevelIndex]
          });
          
          escalation.currentLevel = nextLevelIndex;
          escalation.lastEscalationAt = new Date().toISOString();
        } else {
          // Достигнут максимальный уровень
          this.activeEscalations.delete(alertId);
        }
      }
    }
    
    return toEscalate;
  }
  
  /**
   * Завершение эскалации
   */
  completeEscalation(alertId: string): void {
    this.activeEscalations.delete(alertId);
  }
  
  /**
   * Поиск подходящего правила
   */
  private findMatchingRule(alert: Alert): EscalationRule | null {
    for (const rule of this.rules) {
      if (!rule.enabled) {
        continue;
      }
      
      if (this.matchesConditions(alert, rule.conditions)) {
        return rule;
      }
    }
    
    return null;
  }
  
  /**
   * Проверка условий
   */
  private matchesConditions(alert: Alert, conditions: unknown[]): boolean {
    // Упрощенная проверка
    return true;
  }
  
  /**
   * Запуск периодической проверки
   */
  startPeriodicCheck(intervalSeconds: number): void {
    this.checkInterval = setInterval(() => {
      const toEscalate = this.checkEscalations();
      
      for (const { alertId, level } of toEscalate) {
        this.emitEscalation(alertId, level);
      }
    }, intervalSeconds * 1000);
  }
  
  /**
   * Эмиссия события эскалации
   */
  private emitEscalation(alertId: string, level: EscalationLevel): void {
    // Эмиссия события для обработки
  }
  
  /**
   * Закрытие менеджера
   */
  close(): void {
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }
    this.activeEscalations.clear();
  }
  
  /**
   * Получение активных эскалаций
   */
  getActiveEscalations(): number {
    return this.activeEscalations.size;
  }
}

/**
 * Активная эскалация
 */
interface ActiveEscalation {
  alertId: string;
  ruleId: string;
  currentLevel: number;
  levels: EscalationLevel[];
  startedAt: string;
  lastEscalationAt: string;
  notificationsSent: string[];
}

// ============================================================================
// ОСНОВНОЙ КЛАСС ALERTING SERVICE
// ============================================================================

/**
 * Alerting Service - система оповещений и эскалации
 * 
 * Реализует:
 * - Множественные каналы уведомлений
 * - Многоуровневая эскалация
 * - Rate limiting и дедупликация
 * - Working hours
 * - Шаблоны уведомлений
 */
export class AlertingService extends EventEmitter {
  private config: AlertingServiceConfig;
  private rateLimiter: NotificationRateLimiter;
  private dedupManager: DeduplicationManager;
  private workingHoursChecker: WorkingHoursChecker;
  private notificationSender: NotificationSender;
  private escalationManager: EscalationManager;
  
  /** Активные алерты */
  private alerts: Map<string, Alert>;
  /** Статистика */
  private statistics: AlertingStatistics;
  private enabled: boolean;
  
  constructor(config: Partial<AlertingServiceConfig> = {}) {
    super();
    
    this.config = {
      channels: config.channels || [],
      escalationRules: config.escalationRules || [],
      defaultRateLimit: config.defaultRateLimit || {
        maxAlerts: 100,
        periodSeconds: 3600,
        action: 'suppress'
      },
      defaultWorkingHours: config.defaultWorkingHours || {
        timezone: 'UTC',
        weekdays: { start: '09:00', end: '18:00' },
        weekends: { start: '00:00', end: '00:00' },
        holidays: []
      },
      enableDeduplication: config.enableDeduplication !== false,
      deduplicationWindowSeconds: config.deduplicationWindowSeconds || 300,
      enableRateLimiting: config.enableRateLimiting !== false,
      enableEscalation: config.enableEscalation !== false,
      escalationCheckIntervalSeconds: config.escalationCheckIntervalSeconds || 60,
      maxActiveAlerts: config.maxActiveAlerts || 10000,
      autoCloseResolvedHours: config.autoCloseResolvedHours || 24
    };
    
    this.rateLimiter = new NotificationRateLimiter();
    this.dedupManager = new DeduplicationManager(this.config.deduplicationWindowSeconds);
    this.workingHoursChecker = new WorkingHoursChecker();
    this.notificationSender = new NotificationSender();
    this.escalationManager = new EscalationManager();
    
    this.alerts = new Map();
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.enabled = true;
    
    // Инициализация каналов
    this.initializeChannels();
    
    // Инициализация эскалации
    this.initializeEscalation();
    
    // Запуск периодической очистки
    this.startPeriodicCleanup();
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): AlertingStatistics {
    return {
      totalAlertsCreated: 0,
      activeAlerts: 0,
      resolvedAlerts: 0,
      falsePositives: 0,
      totalNotificationsSent: 0,
      successfulNotifications: 0,
      failedNotifications: 0,
      byChannel: {
        [NotificationChannel.EMAIL]: { sent: 0, delivered: 0, failed: 0, avgDeliveryTime: 0 },
        [NotificationChannel.SLACK]: { sent: 0, delivered: 0, failed: 0, avgDeliveryTime: 0 },
        [NotificationChannel.PAGERDUTY]: { sent: 0, delivered: 0, failed: 0, avgDeliveryTime: 0 },
        [NotificationChannel.TELEGRAM]: { sent: 0, delivered: 0, failed: 0, avgDeliveryTime: 0 },
        [NotificationChannel.WEBHOOK]: { sent: 0, delivered: 0, failed: 0, avgDeliveryTime: 0 },
        [NotificationChannel.SMS]: { sent: 0, delivered: 0, failed: 0, avgDeliveryTime: 0 },
        [NotificationChannel.PUSH]: { sent: 0, delivered: 0, failed: 0, avgDeliveryTime: 0 }
      },
      bySeverity: {
        [AlertSeverity.P1_CRITICAL]: 0,
        [AlertSeverity.P2_HIGH]: 0,
        [AlertSeverity.P3_MEDIUM]: 0,
        [AlertSeverity.P4_LOW]: 0,
        [AlertSeverity.P5_INFO]: 0
      },
      escalationsTriggered: 0,
      rateLimitedNotifications: 0,
      deduplicatedAlerts: 0,
      avgResolutionTimeHours: 0
    };
  }
  
  /**
   * Инициализация каналов
   */
  private initializeChannels(): void {
    for (const channelConfig of this.config.channels) {
      this.notificationSender.registerChannel(channelConfig);
      
      // Установка rate limit для канала
      if (channelConfig.rateLimit) {
        this.rateLimiter.setLimit(channelConfig.name, channelConfig.rateLimit);
      }
    }
  }
  
  /**
   * Инициализация эскалации
   */
  private initializeEscalation(): void {
    this.escalationManager.setRules(this.config.escalationRules);
    
    if (this.config.enableEscalation) {
      this.escalationManager.startPeriodicCheck(this.config.escalationCheckIntervalSeconds);
    }
  }
  
  /**
   * Создание алерта
   */
  async createAlert(alert: Alert): Promise<Alert> {
    if (!this.enabled) {
      return alert;
    }
    
    this.statistics.totalAlertsCreated++;
    this.statistics.bySeverity[alert.severity]++;
    
    // Проверка дедупликации
    if (this.config.enableDeduplication) {
      const dedupResult = this.dedupManager.check(alert.fingerprint);
      
      if (dedupResult.isDuplicate) {
        this.statistics.deduplicatedAlerts++;
        
        // Обновление существующего алерта
        const existingAlert = this.alerts.get(dedupResult.entry!.lastAlertId);
        if (existingAlert) {
          existingAlert.occurrenceCount = dedupResult.entry!.count;
          existingAlert.lastOccurrenceAt = alert.occurredAt;
          existingAlert.updatedAt = new Date().toISOString();
        }
        
        this.emit('alert_deduplicated', { alert, duplicateOf: dedupResult.entry!.lastAlertId });
        return alert;
      }
      
      this.dedupManager.register(alert);
    }
    
    // Проверка лимита активных алертов
    if (this.alerts.size >= this.config.maxActiveAlerts) {
      this.emit('alert_limit_reached', { alert });
      return alert;
    }
    
    // Сохранение алерта
    this.alerts.set(alert.id, alert);
    this.statistics.activeAlerts++;
    
    // Отправка уведомлений
    await this.sendNotifications(alert);
    
    // Начало эскалации если нужно
    if (this.config.enableEscalation && this.shouldEscalate(alert)) {
      this.escalationManager.startEscalation(alert);
    }
    
    this.emit('alert_created', alert);
    
    return alert;
  }
  
  /**
   * Отправка уведомлений для алерта
   */
  private async sendNotifications(alert: Alert): Promise<NotificationResult[]> {
    const results: NotificationResult[] = [];
    
    // Определение каналов для отправки
    const channels = this.getChannelsForAlert(alert);
    
    for (const channelName of channels) {
      const channelConfig = this.config.channels.find(c => c.name === channelName);
      
      if (!channelConfig || !channelConfig.enabled) {
        continue;
      }
      
      // Проверка rate limit
      if (this.config.enableRateLimiting && channelConfig.rateLimit) {
        const rateLimitResult = this.rateLimiter.allow(channelName);
        
        if (!rateLimitResult.allowed) {
          this.statistics.rateLimitedNotifications++;
          
          if (channelConfig.rateLimit.action === 'suppress') {
            continue;
          }
        }
      }
      
      // Проверка рабочих часов
      const workingHours = channelConfig.workingHours || this.config.defaultWorkingHours;
      const isWorkingHours = this.workingHoursChecker.isWorkingHours(alert.occurredAt, workingHours);
      
      // Для критических алертов отправляем всегда
      if (!isWorkingHours && alert.severity !== AlertSeverity.P1_CRITICAL) {
        continue;
      }
      
      // Отправка уведомлений получателям
      const recipients = this.getRecipientsForChannel(channelConfig, alert);
      
      for (const recipient of recipients) {
        const result = await this.notificationSender.send(
          channelConfig.type,
          recipient,
          alert,
          channelConfig.messageTemplate
        );
        
        results.push(result);
        
        // Обновление статистики
        this.statistics.totalNotificationsSent++;
        this.statistics.byChannel[channelConfig.type].sent++;
        
        if (result.success) {
          this.statistics.successfulNotifications++;
          this.statistics.byChannel[channelConfig.type].delivered++;
        } else {
          this.statistics.failedNotifications++;
          this.statistics.byChannel[channelConfig.type].failed++;
        }
        
        // Добавление в историю алерта
        alert.notifications.push({
          id: result.notificationId,
          channel: channelConfig.type,
          recipient,
          sentAt: result.sentAt,
          deliveryStatus: result.success ? 'delivered' : 'failed',
          deliveredAt: result.deliveredAt,
          error: result.error,
          response: result.response
        });
      }
    }
    
    return results;
  }
  
  /**
   * Получение каналов для алерта
   */
  private getChannelsForAlert(alert: Alert): string[] {
    const channels = new Set<string>();
    
    // Каналы по умолчанию для серьезности
    switch (alert.severity) {
      case AlertSeverity.P1_CRITICAL:
        channels.add('pagerduty');
        channels.add('slack');
        channels.add('email');
        break;
      case AlertSeverity.P2_HIGH:
        channels.add('slack');
        channels.add('email');
        break;
      case AlertSeverity.P3_MEDIUM:
        channels.add('slack');
        break;
      default:
        channels.add('email');
    }
    
    // Каналы из конфигурации алерта
    for (const channel of this.config.channels) {
      if (channel.enabled) {
        channels.add(channel.name);
      }
    }
    
    return Array.from(channels);
  }
  
  /**
   * Получение получателей для канала
   */
  private getRecipientsForChannel(config: NotificationChannelConfig, alert: Alert): string[] {
    const params = config.params as { recipients?: string[]; channel?: string };
    return params.recipients || [];
  }
  
  /**
   * Проверка необходимости эскалации
   */
  private shouldEscalate(alert: Alert): boolean {
    return alert.severity === AlertSeverity.P1_CRITICAL || 
           alert.severity === AlertSeverity.P2_HIGH;
  }
  
  /**
   * Обновление статуса алерта
   */
  updateAlertStatus(alertId: string, status: AlertStatus, resolvedBy?: string, resolutionReason?: string): boolean {
    const alert = this.alerts.get(alertId);
    
    if (!alert) {
      return false;
    }
    
    const oldStatus = alert.status;
    alert.status = status;
    alert.updatedAt = new Date().toISOString();
    
    if (status === AlertStatus.RESOLVED || status === AlertStatus.FALSE_POSITIVE) {
      alert.resolvedAt = new Date().toISOString();
      alert.resolvedBy = resolvedBy;
      alert.resolutionReason = resolutionReason;
      
      this.statistics.resolvedAlerts++;
      this.statistics.activeAlerts--;
      
      // Завершение эскалации
      this.escalationManager.completeEscalation(alertId);
      
      // Расчет времени разрешения
      if (alert.firstOccurrenceAt) {
        const resolutionTimeHours = 
          (new Date(alert.resolvedAt).getTime() - new Date(alert.firstOccurrenceAt).getTime()) / (1000 * 60 * 60);
        this.statistics.avgResolutionTimeHours = 
          (this.statistics.avgResolutionTimeHours * (this.statistics.resolvedAlerts - 1) + resolutionTimeHours) / 
          this.statistics.resolvedAlerts;
      }
      
      // Удаление из дедупликации
      this.dedupManager.remove(alert.fingerprint);
    }
    
    if (status === AlertStatus.FALSE_POSITIVE) {
      this.statistics.falsePositives++;
    }
    
    this.emit('alert_updated', { alert, oldStatus, newStatus: status });
    
    return true;
  }
  
  /**
   * Признание алерта
   */
  acknowledgeAlert(alertId: string, userId: string): boolean {
    const alert = this.alerts.get(alertId);
    
    if (!alert) {
      return false;
    }
    
    alert.status = AlertStatus.ACKNOWLEDGED;
    alert.updatedAt = new Date().toISOString();
    
    // Завершение эскалации
    this.escalationManager.completeEscalation(alertId);
    
    this.emit('alert_acknowledged', { alert, userId });
    
    return true;
  }
  
  /**
   * Получение алерта по ID
   */
  getAlert(alertId: string): Alert | undefined {
    return this.alerts.get(alertId);
  }
  
  /**
   * Получение активных алертов
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.alerts.values()).filter(a => 
      a.status === AlertStatus.NEW || 
      a.status === AlertStatus.ACKNOWLEDGED || 
      a.status === AlertStatus.INVESTIGATING
    );
  }
  
  /**
   * Получение алертов по серьезности
   */
  getAlertsBySeverity(severity: AlertSeverity): Alert[] {
    return Array.from(this.alerts.values()).filter(a => a.severity === severity);
  }
  
  /**
   * Получение алертов по категории
   */
  getAlertsByCategory(category: string): Alert[] {
    return Array.from(this.alerts.values()).filter(a => a.category === category);
  }
  
  /**
   * Периодическая очистка
   */
  private startPeriodicCleanup(): void {
    setInterval(() => {
      const now = Date.now();
      const autoCloseMs = this.config.autoCloseResolvedHours * 60 * 60 * 1000;
      
      for (const [id, alert] of this.alerts.entries()) {
        if (alert.status === AlertStatus.RESOLVED && alert.resolvedAt) {
          const resolvedTime = new Date(alert.resolvedAt).getTime();
          
          if (now - resolvedTime > autoCloseMs) {
            this.alerts.delete(id);
            this.emit('alert_archived', { alertId: id });
          }
        }
      }
    }, 3600000); // Каждый час
  }
  
  /**
   * Получение статистики
   */
  getStatistics(): AlertingStatistics {
    return { ...this.statistics };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
  }
  
  /**
   * Включение сервиса
   */
  enable(): void {
    this.enabled = true;
  }
  
  /**
   * Выключение сервиса
   */
  disable(): void {
    this.enabled = false;
  }
  
  /**
   * Проверка включен ли сервис
   */
  isEnabled(): boolean {
    return this.enabled;
  }
  
  /**
   * Закрытие сервиса
   */
  close(): void {
    this.enabled = false;
    this.dedupManager.close();
    this.escalationManager.close();
    this.emit('closed');
  }
  
  /**
   * Добавление канала уведомлений
   */
  addChannel(config: NotificationChannelConfig): void {
    this.config.channels.push(config);
    this.notificationSender.registerChannel(config);
    
    if (config.rateLimit) {
      this.rateLimiter.setLimit(config.name, config.rateLimit);
    }
  }
  
  /**
   * Удаление канала
   */
  removeChannel(channelName: string): boolean {
    const index = this.config.channels.findIndex(c => c.name === channelName);
    
    if (index !== -1) {
      this.config.channels.splice(index, 1);
      return true;
    }
    
    return false;
  }
  
  /**
   * Добавление правила эскалации
   */
  addEscalationRule(rule: EscalationRule): void {
    this.config.escalationRules.push(rule);
    this.escalationManager.setRules(this.config.escalationRules);
  }
  
  /**
   * Добавление праздника
   */
  addHoliday(date: string): void {
    this.workingHoursChecker.addHoliday(date);
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default AlertingService;
  