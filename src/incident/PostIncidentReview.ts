/**
 * ============================================================================
 * POST INCIDENT REVIEW
 * ============================================================================
 * Модуль анализа после инцидента (Lessons Learned)
 * Реализует автоматизированный сбор данных для post-mortem
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import {
  PostIncidentReview as PostIncidentReviewType,
  Incident,
  TimelineEvent,
  Actor,
  RootCause,
  LessonLearned,
  Recommendation,
  ActionItem,
  EffectivenessMetrics
} from '../types/incident.types';

/**
 * События модуля
 */
export enum PostIncidentReviewEvent {
  /** Анализ начат */
  REVIEW_STARTED = 'review_started',
  /** Анализ завершен */
  REVIEW_COMPLETED = 'review_completed',
  /** Урок извлечен */
  LESSON_IDENTIFIED = 'lesson_identified',
  /** Рекомендация создана */
  RECOMMENDATION_CREATED = 'recommendation_created',
  /** План действий обновлен */
  ACTION_PLAN_UPDATED = 'action_plan_updated'
}

/**
 * Конфигурация модуля
 */
export interface PostIncidentReviewConfig {
  /** Автозапуск анализа после закрытия */
  autoStartOnClose: boolean;
  /** Требуемые участники */
  requiredParticipants: string[];
  /** Шаблон отчета */
  reportTemplate: string;
  /** Логирование */
  enableLogging: boolean;
}

/**
 * Модуль анализа после инцидента
 */
export class PostIncidentReview extends EventEmitter {
  /** Конфигурация */
  private config: PostIncidentReviewConfig;

  /** Хранилище отчетов */
  private reviews: Map<string, PostIncidentReviewType> = new Map();

  /**
   * Конструктор модуля
   */
  constructor(config?: Partial<PostIncidentReviewConfig>) {
    super();
    this.config = this.mergeConfigWithDefaults(config);
  }

  /**
   * Объединение конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<PostIncidentReviewConfig> | undefined): PostIncidentReviewConfig {
    const defaultConfig: PostIncidentReviewConfig = {
      autoStartOnClose: true,
      requiredParticipants: ['incident_owner', 'security_lead'],
      reportTemplate: 'standard',
      enableLogging: true
    };

    return { ...defaultConfig, ...config };
  }

  /**
   * Инициация анализа после инцидента
   */
  public async initiateReview(
    incident: Incident,
    participants: Actor[],
    initiatedBy: Actor
  ): Promise<PostIncidentReviewType> {
    this.log(`Инициация анализа после инцидента для ${incident.id}`);

    // Событие начала
    this.emit(PostIncidentReviewEvent.REVIEW_STARTED, {
      incidentId: incident.id,
      initiatedBy
    });

    // Создание отчета
    const review: PostIncidentReviewType = {
      id: this.generateReviewId(),
      incidentId: incident.id,
      reviewDate: new Date(),
      participants,
      incidentSummary: incident.description,
      timeline: {
        keyEvents: incident.timeline.slice(0, 10),
        totalDuration: incident.metrics.totalDuration
      },
      whatWentWell: [],
      whatCouldBeImproved: [],
      rootCauses: [],
      lessonsLearned: [],
      recommendations: [],
      actionItems: [],
      effectivenessMetrics: this.calculateEffectivenessMetrics(incident),
      status: 'draft',
      authoredBy: initiatedBy
    };

    // Сохранение
    this.reviews.set(review.id, review);

    // Автогенерация начальных данных
    await this.autoGenerateInsights(review, incident);

    return review;
  }

  /**
   * Автогенерация инсайтов
   */
  private async autoGenerateInsights(
    review: PostIncidentReviewType,
    incident: Incident
  ): Promise<void> {
    // Анализ метрик для выявления что сработало хорошо
    if (incident.metrics.timeToContain && incident.metrics.timeToContain < 3600000) {
      review.whatWentWell.push('Быстрое сдерживание инцидента (< 1 часа)');
    }

    if (incident.metrics.automatedActionsCount > 5) {
      review.whatWentWell.push('Эффективная автоматизация реагирования');
    }

    // Анализ для выявления областей улучшения
    if (incident.metrics.timeToDetect && incident.metrics.timeToDetect > 86400000) {
      review.whatCouldBeImproved.push('Улучшение обнаружения (время > 24 часов)');
    }

    if (incident.metrics.manualActionsCount > incident.metrics.automatedActionsCount * 2) {
      review.whatCouldBeImproved.push('Увеличить автоматизацию ручных действий');
    }

    // Автогенерация уроков
    const lessons = this.generateLessonsLearned(incident);
    review.lessonsLearned.push(...lessons);

    // Автогенерация рекомендаций
    const recommendations = this.generateRecommendations(incident);
    review.recommendations.push(...recommendations);

    // События
    for (const lesson of lessons) {
      this.emit(PostIncidentReviewEvent.LESSON_IDENTIFIED, {
        incidentId: incident.id,
        lesson
      });
    }

    for (const rec of recommendations) {
      this.emit(PostIncidentReviewEvent.RECOMMENDATION_CREATED, {
        incidentId: incident.id,
        recommendation: rec
      });
    }
  }

  /**
   * Генерация извлеченных уроков
   */
  private generateLessonsLearned(incident: Incident): LessonLearned[] {
    const lessons: LessonLearned[] = [];

    // Урок по времени обнаружения
    if (incident.metrics.timeToDetect) {
      const hoursToDetect = incident.metrics.timeToDetect / 3600000;

      if (hoursToDetect > 24) {
        lessons.push({
          description: 'Длительное время обнаружения позволяет атаке развиться',
          category: 'detection',
          applicability: ['monitoring', 'alerting'],
          priority: 'high'
        });
      }
    }

    // Урок по коммуникации
    if (incident.metrics.stakeholdersNotified > 10) {
      lessons.push({
        description: 'Массовая коммуникация может быть неэффективной',
        category: 'communication',
        applicability: ['stakeholder_management'],
        priority: 'medium'
      });
    }

    // Урок по playbook
    if (incident.activePlaybook) {
      const playbookProgress = incident.activePlaybook.progress;

      if (playbookProgress < 100) {
        lessons.push({
          description: 'Playbook не был выполнен полностью - требуется пересмотр',
          category: 'process',
          applicability: ['playbook_design'],
          priority: 'high'
        });
      }
    }

    return lessons;
  }

  /**
   * Генерация рекомендаций
   */
  private generateRecommendations(incident: Incident): Recommendation[] {
    const recommendations: Recommendation[] = [];

    // Рекомендация по обнаружению
    if (!incident.metrics.timeToDetect || incident.metrics.timeToDetect > 3600000) {
      recommendations.push({
        description: 'Внедрить дополнительные средства мониторинга',
        rationale: 'Длительное время обнаружения увеличивает ущерб',
        priority: 'high',
        implementationComplexity: 'medium',
        expectedImpact: 'Сокращение времени обнаружения на 50%',
        requiredResources: ['SIEM enhancement', 'Additional sensors']
      });
    }

    // Рекомендация по автоматизации
    if (incident.metrics.manualActionsCount > 10) {
      recommendations.push({
        description: 'Автоматизировать рутинные действия реагирования',
        rationale: 'Большое количество ручных действий замедляет реагирование',
        priority: 'medium',
        implementationComplexity: 'medium',
        expectedImpact: 'Сокращение времени реагирования на 30%',
        requiredResources: ['Playbook development', 'Automation tools']
      });
    }

    // Рекомендация по обучению
    if (incident.category === 'phishing' || incident.category === 'credential_compromise') {
      recommendations.push({
        description: 'Провести дополнительное обучение пользователей',
        rationale: 'Человеческий фактор остается ключевым вектором атак',
        priority: 'high',
        implementationComplexity: 'low',
        expectedImpact: 'Снижение успешности фишинговых атак',
        requiredResources: ['Training platform', 'Security awareness content']
      });
    }

    return recommendations;
  }

  /**
   * Расчет метрик эффективности
   */
  private calculateEffectivenessMetrics(incident: Incident): EffectivenessMetrics {
    const metrics: EffectivenessMetrics = {
      overallEffectiveness: 0,
      detectionEffectiveness: 0,
      responseEffectiveness: 0,
      containmentEffectiveness: 0,
      eradicationEffectiveness: 0,
      recoveryEffectiveness: 0,
      communicationEffectiveness: 0,
      slaCompliance: {
        responseTimeMet: false,
        containmentTimeMet: false,
        recoveryTimeMet: false
      }
    };

    // Расчет эффективности обнаружения
    if (incident.metrics.timeToDetect) {
      const hoursToDetect = incident.metrics.timeToDetect / 3600000;
      metrics.detectionEffectiveness = Math.max(0, 100 - hoursToDetect * 10);
    }

    // Расчет эффективности реагирования
    if (incident.metrics.timeToRespond) {
      const minutesToRespond = incident.metrics.timeToRespond / 60000;
      metrics.responseEffectiveness = Math.max(0, 100 - minutesToRespond * 5);
    }

    // Расчет эффективности сдерживания
    if (incident.metrics.timeToContain) {
      const hoursToContain = incident.metrics.timeToContain / 3600000;
      metrics.containmentEffectiveness = Math.max(0, 100 - hoursToContain * 15);
    }

    // SLA compliance
    metrics.slaCompliance.responseTimeMet = (incident.metrics.timeToRespond || 0) < 900000; // 15 минут
    metrics.slaCompliance.containmentTimeMet = (incident.metrics.timeToContain || 0) < 3600000; // 1 час
    metrics.slaCompliance.recoveryTimeMet = (incident.metrics.timeToRecover || 0) < 28800000; // 8 часов

    // Общая эффективность (среднее)
    const scores = [
      metrics.detectionEffectiveness,
      metrics.responseEffectiveness,
      metrics.containmentEffectiveness,
      metrics.eradicationEffectiveness,
      metrics.recoveryEffectiveness,
      metrics.communicationEffectiveness
    ].filter(s => s > 0);

    if (scores.length > 0) {
      metrics.overallEffectiveness = Math.round(
        scores.reduce((sum, s) => sum + s, 0) / scores.length
      );
    }

    return metrics;
  }

  /**
   * Добавление корневой причины
   */
  public async addRootCause(
    reviewId: string,
    rootCause: Omit<RootCause, 'confidenceLevel'>,
    addedBy: Actor
  ): Promise<RootCause> {
    const review = this.reviews.get(reviewId);

    if (!review) {
      throw new Error(`Отчет ${reviewId} не найден`);
    }

    const cause: RootCause = {
      ...rootCause,
      confidenceLevel: 80 // По умолчанию
    };

    review.rootCauses.push(cause);

    this.log(`Добавлена корневая причина в отчет ${reviewId}`);

    return cause;
  }

  /**
   * Добавление элемента плана действий
   */
  public async addActionItem(
    reviewId: string,
    actionItem: Omit<ActionItem, 'id' | 'progress' | 'status'>,
    addedBy: Actor
  ): Promise<ActionItem> {
    const review = this.reviews.get(reviewId);

    if (!review) {
      throw new Error(`Отчет ${reviewId} не найден`);
    }

    const item: ActionItem = {
      ...actionItem,
      id: this.generateActionItemId(),
      progress: 0,
      status: 'pending'
    };

    review.actionItems.push(item);

    // Событие обновления
    this.emit(PostIncidentReviewEvent.ACTION_PLAN_UPDATED, {
      reviewId,
      actionItem: item
    });

    this.log(`Добавлен элемент плана действий в отчет ${reviewId}`);

    return item;
  }

  /**
   * Обновление статуса элемента плана действий
   */
  public async updateActionItemStatus(
    reviewId: string,
    actionItemId: string,
    status: ActionItem['status'],
    progress?: number
  ): Promise<void> {
    const review = this.reviews.get(reviewId);

    if (!review) {
      throw new Error(`Отчет ${reviewId} не найден`);
    }

    const item = review.actionItems.find(i => i.id === actionItemId);

    if (!item) {
      throw new Error(`Элемент плана действий ${actionItemId} не найден`);
    }

    item.status = status;
    if (progress !== undefined) {
      item.progress = progress;
    }

    if (status === 'completed') {
      item.progress = 100;
      item.completedAt = new Date();
    }

    this.log(`Статус элемента плана действий обновлен: ${actionItemId} -> ${status}`);
  }

  /**
   * Завершение анализа
   */
  public async completeReview(
    reviewId: string,
    completedBy: Actor
  ): Promise<PostIncidentReviewType> {
    const review = this.reviews.get(reviewId);

    if (!review) {
      throw new Error(`Отчет ${reviewId} не найден`);
    }

    review.status = 'approved';
    review.approvedBy = completedBy;
    review.approvedAt = new Date();

    // Событие завершения
    this.emit(PostIncidentReviewEvent.REVIEW_COMPLETED, {
      reviewId,
      status: 'approved'
    });

    this.log(`Анализ после инцидента ${reviewId} завершен`);

    return review;
  }

  /**
   * Получение отчета
   */
  public getReview(reviewId: string): PostIncidentReviewType | undefined {
    return this.reviews.get(reviewId);
  }

  /**
   * Получение отчетов по инциденту
   */
  public getReviewByIncident(incidentId: string): PostIncidentReviewType | undefined {
    for (const review of this.reviews.values()) {
      if (review.incidentId === incidentId) {
        return review;
      }
    }
    return undefined;
  }

  /**
   * Генерация идентификатора отчета
   */
  private generateReviewId(): string {
    return `pir_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Генерация идентификатора элемента плана действий
   */
  private generateActionItemId(): string {
    return `ai_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Логирование
   */
  private log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    if (this.config.enableLogging) {
      const timestamp = new Date().toISOString();
      const prefix = `[PostIncidentReview] [${timestamp}] [${level.toUpperCase()}]`;
      logger.info(`${prefix} ${message}`);
    }
  }

  /**
   * Экспорт отчета в формат для презентации
   */
  public exportReport(reviewId: string): Record<string, unknown> {
    const review = this.reviews.get(reviewId);

    if (!review) {
      throw new Error(`Отчет ${reviewId} не найден`);
    }

    return {
      reportId: review.id,
      incidentId: review.incidentId,
      reviewDate: review.reviewDate.toISOString(),
      participants: review.participants.map(p => ({
        id: p.id,
        username: p.username,
        role: p.role
      })),
      incidentSummary: review.incidentSummary,
      whatWentWell: review.whatWentWell,
      whatCouldBeImproved: review.whatCouldBeImproved,
      rootCauses: review.rootCauses,
      lessonsLearned: review.lessonsLearned,
      recommendations: review.recommendations,
      actionItems: review.actionItems,
      effectivenessMetrics: review.effectivenessMetrics,
      status: review.status,
      exportedAt: new Date()
    };
  }
}
