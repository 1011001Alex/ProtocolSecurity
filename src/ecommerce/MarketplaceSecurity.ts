/**
 * ============================================================================
 * MARKETPLACE SECURITY — БЕЗОПАСНОСТЬ МАРКЕТПЛЕЙСА
 * ============================================================================
 *
 * Защита от мошенничества на маркетплейсе
 * 
 * Features:
 * - Seller fraud detection
 * - Fake product detection
 * - Price manipulation detection
 * - Review manipulation detection
 */

import { EventEmitter } from 'events';

export class MarketplaceSecurity extends EventEmitter {
  private isInitialized = false;
  private readonly sellerHistory: Map<string, SellerEvent[]> = new Map();
  private readonly productReports: Map<string, Report[]> = new Map();

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    this.emit('initialized');
  }

  public async destroy(): Promise<void> {
    this.sellerHistory.clear();
    this.productReports.clear();
    this.isInitialized = false;
    this.emit('destroyed');
  }

  /**
   * Анализ продавца
   */
  public async analyzeSeller(data: {
    sellerId: string;
    accountAge: number;
    totalSales: number;
    totalListings: number;
    averageRating: number;
    reviewCount: number;
    returnRate: number;
    disputeRate: number;
  }): Promise<{
    riskScore: number;
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
    riskFactors: string[];
    recommendedAction: 'APPROVE' | 'REVIEW' | 'SUSPEND';
  }> {
    if (!this.isInitialized) {
      throw new Error('MarketplaceSecurity not initialized');
    }

    const riskFactors: string[] = [];
    let riskScore = 0;

    // 1. Новый аккаунт с большой активностью
    if (data.accountAge < 30 && data.totalListings > 100) {
      riskScore += 0.3;
      riskFactors.push('New account with high listing volume');
    }

    // 2. Подозрительный рейтинг
    if (data.reviewCount > 0) {
      const averageRating = data.averageRating;
      
      // Слишком много 5-звёздочных отзывов
      if (averageRating > 4.9 && data.reviewCount < 50) {
        riskScore += 0.2;
        riskFactors.push('Suspiciously high rating with few reviews');
      }
      
      // Очень низкий рейтинг
      if (averageRating < 2.5) {
        riskScore += 0.4;
        riskFactors.push('Low seller rating');
      }
    }

    // 3. Высокий процент возвратов
    if (data.returnRate > 0.2) {
      riskScore += 0.3;
      riskFactors.push(`High return rate: ${(data.returnRate * 100).toFixed(1)}%`);
    }

    // 4. Высокий процент споров
    if (data.disputeRate > 0.1) {
      riskScore += 0.4;
      riskFactors.push(`High dispute rate: ${(data.disputeRate * 100).toFixed(1)}%`);
    }

    // 5. Несоответствие продаж и отзывов
    if (data.totalSales > 1000 && data.reviewCount < 10) {
      riskScore += 0.3;
      riskFactors.push('High sales with few reviews');
    }

    // Определение risk level
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
    if (riskScore >= 0.7) riskLevel = 'HIGH';
    else if (riskScore >= 0.4) riskLevel = 'MEDIUM';

    // Recommended action
    let recommendedAction: 'APPROVE' | 'REVIEW' | 'SUSPEND' = 'APPROVE';
    if (riskLevel === 'HIGH') recommendedAction = 'SUSPEND';
    else if (riskLevel === 'MEDIUM') recommendedAction = 'REVIEW';

    return {
      riskScore: Math.min(1, riskScore),
      riskLevel,
      riskFactors,
      recommendedAction
    };
  }

  /**
   * Детекция fake products
   */
  public async detectFakeProduct(data: {
    productId: string;
    title: string;
    description: string;
    price: number;
    marketAveragePrice: number;
    brandName?: string;
    sellerId: string;
    images: string[];
  }): Promise<{
    isFake: boolean;
    confidence: number;
    indicators: string[];
  }> {
    const indicators: string[] = [];
    let confidence = 0;

    // 1. Подозрительно низкая цена
    if (data.marketAveragePrice > 0) {
      const discount = (data.marketAveragePrice - data.price) / data.marketAveragePrice;
      if (discount > 0.7) {
        indicators.push('Price significantly below market average');
        confidence += 0.4;
      } else if (discount > 0.5) {
        indicators.push('Price below market average');
        confidence += 0.2;
      }
    }

    // 2. Бренд в названии
    if (data.brandName && data.title.toLowerCase().includes(data.brandName.toLowerCase())) {
      // Проверка на подделку бренда
      const luxuryBrands = ['gucci', 'prada', 'louis vuitton', 'chanel', 'hermes', 'rolex'];
      if (luxuryBrands.some(brand => data.title.toLowerCase().includes(brand))) {
        if (data.price < data.marketAveragePrice * 0.3) {
          indicators.push('Luxury brand at suspiciously low price');
          confidence += 0.5;
        }
      }
    }

    // 3. Подозрительный продавец
    const sellerRisk = await this.getSellerRisk(data.sellerId);
    if (sellerRisk > 0.5) {
      indicators.push('High-risk seller');
      confidence += 0.3;
    }

    // 4. Мало изображений
    if (data.images.length < 3) {
      indicators.push('Few product images');
      confidence += 0.1;
    }

    // 5. Ключевые слова подделок
    const fakeKeywords = ['replica', 'copy', 'inspired', 'dupe', 'knockoff'];
    if (fakeKeywords.some(keyword => data.description.toLowerCase().includes(keyword))) {
      indicators.push('Suspicious keywords in description');
      confidence += 0.4;
    }

    return {
      isFake: confidence >= 0.6,
      confidence: Math.min(1, confidence),
      indicators
    };
  }

  /**
   * Детекция price manipulation
   */
  public async detectPriceManipulation(data: {
    productId: string;
    currentPrice: number;
    priceHistory: Array<{ price: number; date: Date }>;
    competitorPrices: number[];
  }): Promise<{
    isManipulated: boolean;
    manipulationType?: 'INFLATION' | 'DUMPING' | 'COLLUSION';
    confidence: number;
  }> {
    if (!this.isInitialized) {
      throw new Error('MarketplaceSecurity not initialized');
    }

    // 1. Проверка на искусственное завышение
    const avgHistoricalPrice = data.priceHistory.length > 0
      ? data.priceHistory.reduce((sum, p) => sum + p.price, 0) / data.priceHistory.length
      : data.currentPrice;

    const priceIncrease = (data.currentPrice - avgHistoricalPrice) / avgHistoricalPrice;

    if (priceIncrease > 2) {
      return {
        isManipulated: true,
        manipulationType: 'INFLATION',
        confidence: Math.min(1, priceIncrease / 3)
      };
    }

    // 2. Проверка на демпинг
    if (data.competitorPrices.length > 0) {
      const avgCompetitorPrice = data.competitorPrices.reduce((sum, p) => sum + p, 0) / data.competitorPrices.length;
      const undercut = (avgCompetitorPrice - data.currentPrice) / avgCompetitorPrice;

      if (undercut > 0.5) {
        return {
          isManipulated: true,
          manipulationType: 'DUMPING',
          confidence: Math.min(1, undercut)
        };
      }
    }

    // 3. Проверка на сговор (одинаковые цены у конкурентов)
    if (data.competitorPrices.length >= 3) {
      const uniquePrices = new Set(data.competitorPrices.map(p => Math.round(p)));
      if (uniquePrices.size === 1) {
        return {
          isManipulated: true,
          manipulationType: 'COLLUSION',
          confidence: 0.7
        };
      }
    }

    return {
      isManipulated: false,
      confidence: 0
    };
  }

  /**
   * Отчёт о подделке
   */
  public async reportFakeProduct(data: {
    productId: string;
    reporterId: string;
    reason: string;
    evidence?: string[];
  }): Promise<{
    reportId: string;
    status: 'PENDING' | 'UNDER_REVIEW' | 'CONFIRMED' | 'REJECTED';
  }> {
    const reportId = `report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const report: Report = {
      reportId,
      productId: data.productId,
      reporterId: data.reporterId,
      reason: data.reason,
      evidence: data.evidence || [],
      status: 'PENDING',
      createdAt: new Date()
    };

    // Сохранение отчёта
    if (!this.productReports.has(data.productId)) {
      this.productReports.set(data.productId, []);
    }
    this.productReports.get(data.productId)!.push(report);

    // Автоматическая проверка при множественных жалобах
    const productReports = this.productReports.get(data.productId) || [];
    const pendingReports = productReports.filter(r => r.status === 'PENDING').length;

    if (pendingReports >= 5) {
      // Эскалация
      report.status = 'UNDER_REVIEW';
      this.emit('escalation_required', { productId: data.productId, reportCount: pendingReports });
    }

    this.emit('report_submitted', report);

    return {
      reportId,
      status: report.status
    };
  }

  private async getSellerRisk(sellerId: string): Promise<number> {
    // В production запрос к базе данных
    const history = this.sellerHistory.get(sellerId) || [];
    
    if (history.length === 0) return 0.5; // Новый продавец

    const negativeEvents = history.filter(e => e.type === 'COMPLAINT' || e.type === 'DISPUTE').length;
    return Math.min(1, negativeEvents / history.length);
  }

  private saveSellerEvent(sellerId: string, event: SellerEvent): void {
    if (!this.sellerHistory.has(sellerId)) {
      this.sellerHistory.set(sellerId, []);
    }
    this.sellerHistory.get(sellerId)!.push(event);

    // Ограничение истории
    if (this.sellerHistory.get(sellerId)!.length > 100) {
      this.sellerHistory.set(sellerId, this.sellerHistory.get(sellerId)!.slice(-100));
    }
  }

  public getStats(): {
    initialized: boolean;
    trackedSellers: number;
    activeReports: number;
  } {
    const activeReports = Array.from(this.productReports.values())
      .reduce((sum, reports) => sum + reports.filter(r => r.status === 'PENDING').length, 0);

    return {
      initialized: this.isInitialized,
      trackedSellers: this.sellerHistory.size,
      activeReports
    };
  }
}

interface SellerEvent {
  type: 'SALE' | 'COMPLAINT' | 'DISPUTE' | 'RETURN' | 'REVIEW';
  timestamp: number;
  details?: any;
}

interface Report {
  reportId: string;
  productId: string;
  reporterId: string;
  reason: string;
  evidence: string[];
  status: string;
  createdAt: Date;
}
