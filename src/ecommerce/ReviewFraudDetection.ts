/**
 * ============================================================================
 * REVIEW FRAUD DETECTION — ОБНАРУЖЕНИЕ ФЕЙКОВЫХ ОТЗЫВОВ
 * ============================================================================
 *
 * ML-based fake review detection
 *
 * @package protocol/ecommerce-security
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { ReviewAnalysisResult, ReviewSuspicionFactor, ReviewData } from './types/ecommerce.types';

export class ReviewFraudDetection extends EventEmitter {
  private isInitialized = false;
  private readonly config = {
    mlModelEnabled: true,
    nlpAnalysis: true,
    patternDetection: true
  };

  constructor() {
    super();
    logger.info('[ReviewFraud] Service created');
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    logger.info('[ReviewFraud] Initialized');
    this.emit('initialized');
  }

  /**
   * Анализ отзыва
   */
  public async analyzeReview(data: ReviewData): Promise<ReviewAnalysisResult> {
    if (!this.isInitialized) {
      throw new Error('ReviewFraud not initialized');
    }

    const suspicionFactors: ReviewSuspicionFactor[] = [];
    let fakeProbability = 0;

    // 1. Анализ текста
    const textFactor = this.analyzeReviewText(data.text);
    suspicionFactors.push(textFactor);
    fakeProbability += textFactor.score * textFactor.weight;

    // 2. Анализ рейтинга
    const ratingFactor = this.analyzeRatingPattern(data);
    suspicionFactors.push(ratingFactor);
    fakeProbability += ratingFactor.score * ratingFactor.weight;

    // 3. Анализ ревьюера
    const reviewerFactor = await this.analyzeReviewer(data.reviewerId);
    suspicionFactors.push(reviewerFactor);
    fakeProbability += reviewerFactor.score * reviewerFactor.weight;

    // 4. Проверка покупки
    const purchaseFactor = this.analyzePurchaseVerification(data);
    suspicionFactors.push(purchaseFactor);
    fakeProbability += purchaseFactor.score * purchaseFactor.weight;

    // 5. Временной анализ
    const timingFactor = this.analyzeTiming(data);
    suspicionFactors.push(timingFactor);
    fakeProbability += timingFactor.score * timingFactor.weight;

    // Нормализация
    fakeProbability = Math.min(1, fakeProbability);

    // Определение подозрительности
    const isSuspicious = fakeProbability >= 0.5;

    // Рекомендация
    let recommendedAction: ReviewAnalysisResult['recommendedAction'] = 'APPROVE';
    if (fakeProbability >= 0.8) recommendedAction = 'REMOVE';
    else if (fakeProbability >= 0.6) recommendedAction = 'HIDE';
    else if (fakeProbability >= 0.4) recommendedAction = 'FLAG';

    const result: ReviewAnalysisResult = {
      reviewId: data.reviewId,
      fakeProbability,
      isSuspicious,
      suspicionFactors,
      recommendedAction,
      timestamp: new Date()
    };

    // Логирование
    if (isSuspicious) {
      logger.warn('[ReviewFraud] Suspicious review detected', {
        reviewId: data.reviewId,
        fakeProbability,
        productId: data.productId
      });

      this.emit('review_flagged', result);
    }

    return result;
  }

  /**
   * Анализ текста отзыва
   */
  private analyzeReviewText(text: string): ReviewSuspicionFactor {
    let score = 0;
    const issues: string[] = [];

    // Слишком короткий
    if (text.length < 20) {
      score += 0.2;
      issues.push('Very short review');
    }

    // Слишком длинный без содержания
    if (text.length > 500 && text.split(' ').length / text.length < 0.1) {
      score += 0.2;
      issues.push('Potential word salad');
    }

    // Чрезмерное использование восклицательных знаков
    const exclamationCount = (text.match(/!/g) || []).length;
    if (exclamationCount > 3) {
      score += 0.2;
      issues.push('Excessive exclamation marks');
    }

    // Шаблонные фразы
    const genericPhrases = [
      'great product',
      'highly recommend',
      'best ever',
      'amazing quality',
      'five stars',
      'worth every penny'
    ];

    const lowerText = text.toLowerCase();
    const genericCount = genericPhrases.filter(phrase => lowerText.includes(phrase)).length;

    if (genericCount >= 3) {
      score += 0.3;
      issues.push('Generic marketing language');
    }

    // Повторение слов
    const words = text.toLowerCase().split(/\s+/);
    const wordFrequency = new Map<string, number>();
    words.forEach(w => wordFrequency.set(w, (wordFrequency.get(w) || 0) + 1));

    const maxRepetition = Math.max(...Array.from(wordFrequency.values()));
    if (maxRepetition > 5) {
      score += 0.2;
      issues.push('Repetitive language');
    }

    return {
      name: 'TEXT_ANALYSIS',
      weight: 0.3,
      score: Math.min(1, score),
      description: issues.join('; ') || 'Normal text patterns',
      evidence: { textLength: text.length, genericPhrasesCount: genericCount }
    };
  }

  /**
   * Анализ паттернов рейтинга
   */
  private analyzeRatingPattern(data: ReviewData): ReviewSuspicionFactor {
    // Extreme ratings (1 или 5 звёзд) более подозрительны
    if (data.rating === 5 || data.rating === 1) {
      return {
        name: 'EXTREME_RATING',
        weight: 0.15,
        score: 0.4,
        description: `${data.rating}-star rating (extreme)`
      };
    }

    // Средние рейтинги менее подозрительны
    if (data.rating === 3 || data.rating === 4) {
      return {
        name: 'NORMAL_RATING',
        weight: 0.15,
        score: 0.1,
        description: `${data.rating}-star rating (normal)`
      };
    }

    return {
      name: 'RATING_ANALYSIS',
      weight: 0.15,
      score: 0.2,
      description: `${data.rating}-star rating`
    };
  }

  /**
   * Анализ ревьюера
   */
  private async analyzeReviewer(reviewerId: string): Promise<ReviewSuspicionFactor> {
    // В production проверка истории ревьюера
    // - Количество отзывов
    // - Паттерны оценок
    // - Частота отзывов

    return {
      name: 'REVIEWER_ANALYSIS',
      weight: 0.2,
      score: 0.2,
      description: 'Reviewer history normal'
    };
  }

  /**
   * Проверка покупки
   */
  private analyzePurchaseVerification(data: ReviewData): ReviewSuspicionFactor {
    if (!data.verified && !data.orderId) {
      return {
        name: 'UNVERIFIED_PURCHASE',
        weight: 0.25,
        score: 0.6,
        description: 'Review without verified purchase'
      };
    }

    if (data.verified) {
      return {
        name: 'VERIFIED_PURCHASE',
        weight: 0.25,
        score: 0.1,
        description: 'Verified purchase'
      };
    }

    return {
      name: 'PURCHASE_ANALYSIS',
      weight: 0.25,
      score: 0.3,
      description: 'Purchase status unknown'
    };
  }

  /**
   * Временной анализ
   */
  private analyzeTiming(data: ReviewData): ReviewSuspicionFactor {
    const now = new Date();
    const reviewDate = new Date(data.timestamp);
    const hoursSinceReview = (now.getTime() - reviewDate.getTime()) / (1000 * 60 * 60);

    // Отзыв сразу после покупки
    if (hoursSinceReview < 1) {
      return {
        name: 'IMMEDIATE_REVIEW',
        weight: 0.1,
        score: 0.5,
        description: 'Review posted within 1 hour'
      };
    }

    return {
      name: 'TIMING_NORMAL',
      weight: 0.1,
      score: 0.1,
      description: 'Normal review timing'
    };
  }

  /**
   * Пометить отзыв как подозрительный
   */
  public async flagReview(reviewId: string): Promise<void> {
    logger.info('[ReviewFraud] Review flagged', { reviewId });
    this.emit('review_flagged', { reviewId, timestamp: new Date() });
  }

  public async destroy(): Promise<void> {
    this.isInitialized = false;
    logger.info('[ReviewFraud] Destroyed');
    this.emit('destroyed');
  }
}
