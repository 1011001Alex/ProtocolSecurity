/**
 * ============================================================================
 * TIMELINE RECONSTRUCTOR
 * ============================================================================
 * Модуль реконструкции временной шкалы инцидента
 * Агрегирует события из различных источников для создания полной картины
 * ============================================================================
 */

import { EventEmitter } from 'events';
import {
  TimelineEvent,
  TimelineEventType,
  Incident,
  Actor,
  IOC,
  PlaybookStep
} from '../types/incident.types';

/**
 * События реконструктора
 */
export enum TimelineReconstructorEvent {
  /** Событие добавлено */
  EVENT_ADDED = 'event_added',
  /** Временная шкала обновлена */
  TIMELINE_UPDATED = 'timeline_updated',
  /** Аномалия обнаружена */
  ANOMALY_DETECTED = 'anomaly_detected',
  /** Корреляция найдена */
  CORRELATION_FOUND = 'correlation_found',
  /** Реконструкция завершена */
  RECONSTRUCTION_COMPLETED = 'reconstruction_completed'
}

/**
 * Источник событий
 */
export interface EventSource {
  /** Тип источника */
  type: 'log' | 'siem' | 'edr' | 'firewall' | 'ids' | 'manual';
  /** Название источника */
  name: string;
  /** Подключение к источнику */
  connection: Record<string, unknown>;
}

/**
 * Конфигурация реконструктора
 */
export interface TimelineReconstructorConfig {
  /** Источники событий */
  eventSources: EventSource[];
  /** Автокорреляция включена */
  autoCorrelation: boolean;
  /** Обнаружение аномалий */
  anomalyDetection: boolean;
  /** Минимальная значимость событий */
  minSignificance: 'low' | 'medium' | 'high' | 'critical';
  /** Логирование */
  enableLogging: boolean;
}

/**
 * Реконструктор временной шкалы инцидента
 */
export class TimelineReconstructor extends EventEmitter {
  /** Конфигурация */
  private config: TimelineReconstructorConfig;

  /** Временные шкалы по инцидентам */
  private timelines: Map<string, TimelineEvent[]> = new Map();

  /** Источники событий */
  private sources: Map<string, EventSource> = new Map();

  /**
   * Конструктор реконструктора
   */
  constructor(config?: Partial<TimelineReconstructorConfig>) {
    super();
    this.config = this.mergeConfigWithDefaults(config);
    this.initializeSources();
  }

  /**
   * Объединение конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<TimelineReconstructorConfig> | undefined): TimelineReconstructorConfig {
    const defaultConfig: TimelineReconstructorConfig = {
      eventSources: [],
      autoCorrelation: true,
      anomalyDetection: true,
      minSignificance: 'low',
      enableLogging: true
    };

    return { ...defaultConfig, ...config };
  }

  /**
   * Инициализация источников
   */
  private initializeSources(): void {
    for (const source of this.config.eventSources) {
      this.sources.set(source.name, source);
    }
  }

  /**
   * Добавление события в временную шкалу
   */
  public async addEvent(
    incidentId: string,
    event: Omit<TimelineEvent, 'id' | 'verified'>,
    addedBy?: Actor
  ): Promise<TimelineEvent> {
    this.log(`Добавление события в инцидент ${incidentId}: ${event.type}`);

    // Создание полного события
    const timelineEvent: TimelineEvent = {
      id: this.generateEventId(),
      ...event,
      verified: false
    };

    // Добавление в временную шкалу
    if (!this.timelines.has(incidentId)) {
      this.timelines.set(incidentId, []);
    }

    const timeline = this.timelines.get(incidentId)!;
    timeline.push(timelineEvent);

    // Сортировка по времени
    timeline.sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

    // Авто-верификация если добавлено системой
    if (!addedBy) {
      timelineEvent.verified = true;
      timelineEvent.verifiedAt = new Date();
      timelineEvent.verifiedBy = 'system';
    }

    // Событие добавления
    this.emit(TimelineReconstructorEvent.EVENT_ADDED, {
      incidentId,
      event: timelineEvent
    });

    // Автокорреляция
    if (this.config.autoCorrelation) {
      await this.findCorrelations(incidentId, timelineEvent);
    }

    // Обнаружение аномалий
    if (this.config.anomalyDetection) {
      await this.detectAnomalies(incidentId, timelineEvent);
    }

    this.log(`Событие ${timelineEvent.id} добавлено в временную шкалу`);

    return timelineEvent;
  }

  /**
   * Получение временной шкалы инцидента
   */
  public getTimeline(incidentId: string): TimelineEvent[] {
    return this.timelines.get(incidentId) || [];
  }

  /**
   * Получение событий по типу
   */
  public getEventsByType(incidentId: string, type: TimelineEventType): TimelineEvent[] {
    const timeline = this.getTimeline(incidentId);
    return timeline.filter(event => event.type === type);
  }

  /**
   * Получение событий в диапазоне времени
   */
  public getEventsInRange(
    incidentId: string,
    startTime: Date,
    endTime: Date
  ): TimelineEvent[] {
    const timeline = this.getTimeline(incidentId);
    return timeline.filter(
      event => event.timestamp >= startTime && event.timestamp <= endTime
    );
  }

  /**
   * Верификация события
   */
  public async verifyEvent(
    incidentId: string,
    eventId: string,
    verifiedBy: Actor
  ): Promise<TimelineEvent> {
    const timeline = this.timelines.get(incidentId);

    if (!timeline) {
      throw new Error(`Временная шкала для инцидента ${incidentId} не найдена`);
    }

    const event = timeline.find(e => e.id === eventId);

    if (!event) {
      throw new Error(`Событие ${eventId} не найдено`);
    }

    event.verified = true;
    event.verifiedBy = verifiedBy.id;
    event.verifiedAt = new Date();

    this.emit(TimelineReconstructorEvent.TIMELINE_UPDATED, {
      incidentId,
      eventId,
      verifiedBy
    });

    return event;
  }

  /**
   * Поиск корреляций между событиями
   */
  private async findCorrelations(
    incidentId: string,
    newEvent: TimelineEvent
  ): Promise<void> {
    const timeline = this.getTimeline(incidentId);

    // Поиск событий с похожими IOC
    if (newEvent.iocs && newEvent.iocs.length > 0) {
      for (const event of timeline) {
        if (event.iocs && event.iocs.length > 0) {
          const commonIOCs = newEvent.iocs.filter(newIoc =>
            event.iocs!.some(oldIoc => oldIoc.value === newIoc.value)
          );

          if (commonIOCs.length > 0) {
            this.emit(TimelineReconstructorEvent.CORRELATION_FOUND, {
              incidentId,
              event1: newEvent.id,
              event2: event.id,
              commonIOCs
            });
          }
        }
      }
    }

    // Поиск событий с тем же актором
    if (newEvent.actor) {
      const eventsBySameActor = timeline.filter(
        e => e.actor?.id === newEvent.actor?.id && e.id !== newEvent.id
      );

      if (eventsBySameActor.length > 0) {
        this.emit(TimelineReconstructorEvent.CORRELATION_FOUND, {
          incidentId,
          event1: newEvent.id,
          event2: eventsBySameActor.map(e => e.id),
          correlation: 'same_actor'
        });
      }
    }
  }

  /**
   * Обнаружение аномалий
   */
  private async detectAnomalies(
    incidentId: string,
    newEvent: TimelineEvent
  ): Promise<void> {
    const timeline = this.getTimeline(incidentId);

    // Обнаружение необычного времени событий
    const hour = newEvent.timestamp.getHours();
    if (hour < 6 || hour > 22) {
      this.emit(TimelineReconstructorEvent.ANOMALY_DETECTED, {
        incidentId,
        eventId: newEvent.id,
        anomaly: 'unusual_time',
        description: `Событие произошло в нерабочее время (${hour}:00)`
      });
    }

    // Обнаружение высокой частоты событий
    const recentEvents = timeline.filter(
      e => Date.now() - e.timestamp.getTime() < 300000 // 5 минут
    );

    if (recentEvents.length > 10) {
      this.emit(TimelineReconstructorEvent.ANOMALY_DETECTED, {
        incidentId,
        eventId: newEvent.id,
        anomaly: 'high_frequency',
        description: `Высокая частота событий: ${recentEvents.length} за 5 минут`
      });
    }
  }

  /**
   * Реконструкция полной временной шкалы
   */
  public async reconstructTimeline(incident: Incident): Promise<{
    timeline: TimelineEvent[];
    keyEvents: TimelineEvent[];
    gaps: { start: Date; end: Date; description: string }[];
    summary: TimelineSummary;
  }> {
    this.log(`Реконструкция временной шкалы для инцидента ${incident.id}`);

    let timeline = this.getTimeline(incident.id);

    // Если временная шкала пуста, создаем базовые события из инцидента
    if (timeline.length === 0) {
      timeline = await this.createBaseTimeline(incident);
    }

    // Определение ключевых событий
    const keyEvents = this.identifyKeyEvents(timeline);

    // Поиск пробелов
    const gaps = this.identifyGaps(timeline);

    // Создание сводки
    const summary = this.createTimelineSummary(timeline, keyEvents);

    // Событие завершения реконструкции
    this.emit(TimelineReconstructorEvent.RECONSTRUCTION_COMPLETED, {
      incidentId: incident.id,
      eventCount: timeline.length,
      keyEventCount: keyEvents.length
    });

    return {
      timeline,
      keyEvents,
      gaps,
      summary
    };
  }

  /**
   * Создание базовой временной шкалы из инцидента
   */
  private async createBaseTimeline(incident: Incident): Promise<TimelineEvent[]> {
    const events: TimelineEvent[] = [];

    // Событие обнаружения
    events.push({
      id: this.generateEventId(),
      type: TimelineEventType.ANOMALY_DETECTED,
      title: 'Инцидент обнаружен',
      description: incident.description,
      timestamp: incident.detectedAt,
      source: 'incident_system',
      significance: 'high',
      verified: true,
      verifiedBy: 'system',
      verifiedAt: new Date()
    });

    // Событие начала реагирования
    if (incident.responseStartedAt) {
      events.push({
        id: this.generateEventId(),
        type: TimelineEventType.CONTAINMENT_ACTION,
        title: 'Начало реагирования',
        description: 'Команда реагирования приступила к работе',
        timestamp: incident.responseStartedAt,
        source: 'incident_system',
        significance: 'high',
        verified: true,
        verifiedBy: 'system',
        verifiedAt: new Date()
      });
    }

    // События сдерживания
    for (const action of incident.containmentActions) {
      events.push({
        id: this.generateEventId(),
        type: TimelineEventType.CONTAINMENT_ACTION,
        title: action.name,
        description: action.description,
        timestamp: action.executedAt,
        source: 'containment_system',
        targets: [action.target],
        significance: 'medium',
        verified: true,
        verifiedBy: 'system',
        verifiedAt: new Date()
      });
    }

    return events;
  }

  /**
   * Идентификация ключевых событий
   */
  private identifyKeyEvents(timeline: TimelineEvent[]): TimelineEvent[] {
    const keyEventTypes: TimelineEventType[] = [
      TimelineEventType.INITIAL_COMPROMISE,
      TimelineEventType.DATA_EXFILTRATION,
      TimelineEventType.MALWARE_EXECUTION,
      TimelineEventType.CONTAINMENT_ACTION
    ];

    return timeline.filter(event =>
      keyEventTypes.includes(event.type) ||
      event.significance === 'critical' ||
      event.significance === 'high'
    );
  }

  /**
   * Идентификация пробелов во временной шкале
   */
  private identifyGaps(timeline: TimelineEvent[]): {
    start: Date;
    end: Date;
    description: string;
  }[] {
    const gaps: { start: Date; end: Date; description: string }[] = [];

    if (timeline.length < 2) {
      return gaps;
    }

    for (let i = 1; i < timeline.length; i++) {
      const prevEvent = timeline[i - 1];
      const currEvent = timeline[i];

      const timeDiff = currEvent.timestamp.getTime() - prevEvent.timestamp.getTime();

      // Пробел больше 1 часа
      if (timeDiff > 3600000) {
        gaps.push({
          start: prevEvent.timestamp,
          end: currEvent.timestamp,
          description: `Пробел ${Math.round(timeDiff / 3600000)} ч между событиями`
        });
      }
    }

    return gaps;
  }

  /**
   * Создание сводки временной шкалы
   */
  private createTimelineSummary(
    timeline: TimelineEvent[],
    keyEvents: TimelineEvent[]
  ): TimelineSummary {
    if (timeline.length === 0) {
      return {
        keyEvents: [],
        totalDuration: 0
      };
    }

    const firstEvent = timeline[0];
    const lastEvent = timeline[timeline.length - 1];

    return {
      firstEvent,
      lastEvent,
      keyEvents,
      totalDuration: lastEvent.timestamp.getTime() - firstEvent.timestamp.getTime(),
      visualization: this.generateTimelineVisualization(timeline)
    };
  }

  /**
   * Генерация визуализации временной шкалы
   */
  private generateTimelineVisualization(timeline: TimelineEvent[]): string {
    if (timeline.length === 0) {
      return 'Нет событий';
    }

    let visualization = 'Временная шкала:\n';
    visualization += '='.repeat(50) + '\n';

    for (const event of timeline.slice(0, 20)) {
      const time = event.timestamp.toISOString().substring(11, 16);
      const icon = this.getEventIcon(event.type);
      const verified = event.verified ? '✓' : '○';

      visualization += `${time} ${icon} [${verified}] ${event.title}\n`;
    }

    if (timeline.length > 20) {
      visualization += `... и еще ${timeline.length - 20} событий\n`;
    }

    visualization += '='.repeat(50);

    return visualization;
  }

  /**
   * Получение иконки для типа события
   */
  private getEventIcon(type: TimelineEventType): string {
    const icons: Record<TimelineEventType, string> = {
      [TimelineEventType.INITIAL_COMPROMISE]: '🔓',
      [TimelineEventType.ANOMALY_DETECTED]: '⚠️',
      [TimelineEventType.PRIVILEGE_ESCALATION]: '⬆️',
      [TimelineEventType.LATERAL_MOVEMENT]: '↔️',
      [TimelineEventType.DATA_COLLECTION]: '📥',
      [TimelineEventType.DATA_EXFILTRATION]: '📤',
      [TimelineEventType.MALWARE_EXECUTION]: '🦠',
      [TimelineEventType.CONTAINMENT_ACTION]: '🛡️',
      [TimelineEventType.ERADICATION_ACTION]: '🧹',
      [TimelineEventType.RECOVERY_ACTION]: '♻️',
      [TimelineEventType.STAKEHOLDER_NOTIFICATION]: '📢',
      [TimelineEventType.FORENSICS_COLLECTION]: '🔍',
      [TimelineEventType.OTHER]: '📌'
    };

    return icons[type] || '📌';
  }

  /**
   * Генерация идентификатора события
   */
  private generateEventId(): string {
    return `te_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Логирование
   */
  private log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    if (this.config.enableLogging) {
      const timestamp = new Date().toISOString();
      const prefix = `[TimelineReconstructor] [${timestamp}] [${level.toUpperCase()}]`;
      console.log(`${prefix} ${message}`);
    }
  }

  /**
   * Экспорт временной шкалы в формат отчета
   */
  public exportTimeline(incidentId: string): Record<string, unknown> {
    const timeline = this.getTimeline(incidentId);

    return {
      incidentId,
      eventCount: timeline.length,
      events: timeline.map(event => ({
        id: event.id,
        type: event.type,
        title: event.title,
        description: event.description,
        timestamp: event.timestamp.toISOString(),
        source: event.source,
        significance: event.significance,
        verified: event.verified,
        actor: event.actor,
        targets: event.targets,
        iocs: event.iocs
      })),
      exportedAt: new Date()
    };
  }
}

/**
 * Сводка временной шкалы
 */
interface TimelineSummary {
  firstEvent?: TimelineEvent;
  lastEvent?: TimelineEvent;
  keyEvents: TimelineEvent[];
  totalDuration?: number;
  visualization?: string;
}

/**
 * Экспорт событий реконструктора
 */
export { TimelineReconstructorEvent };
