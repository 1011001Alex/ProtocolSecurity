/**
 * ============================================================================
 * INVENTORY FRAUD — ДЕТЕКЦИЯ ФРОДА СКЛАДСКИХ ОПЕРАЦИЙ
 * ============================================================================
 *
 * Обнаружение мошенничества с инвентарём
 * 
 * Features:
 * - Stock manipulation detection
 * - Fake returns detection
 * - Inventory shrinkage analysis
 */

import { EventEmitter } from 'events';

export class InventoryFraud extends EventEmitter {
  private isInitialized = false;
  private readonly inventoryHistory: Map<string, InventoryEvent[]> = new Map();

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    this.emit('initialized');
  }

  public async destroy(): Promise<void> {
    this.inventoryHistory.clear();
    this.isInitialized = false;
    this.emit('destroyed');
  }

  /**
   * Анализ операции с инвентарём
   */
  public async analyzeOperation(data: {
    operationType: 'ADD' | 'REMOVE' | 'ADJUST' | 'RETURN';
    productId: string;
    quantity: number;
    userId: string;
    warehouseId: string;
    reason?: string;
  }): Promise<{
    isSuspicious: boolean;
    riskScore: number;
    riskFactors: string[];
    recommendedAction: 'ALLOW' | 'REVIEW' | 'BLOCK';
  }> {
    if (!this.isInitialized) {
      throw new Error('InventoryFraud not initialized');
    }

    const riskFactors: string[] = [];
    let riskScore = 0;

    // 1. Необычно большие количества
    if (Math.abs(data.quantity) > 100) {
      riskScore += 0.3;
      riskFactors.push('Large quantity adjustment');
    }

    // 2. Частые корректировки
    const history = this.inventoryHistory.get(data.productId) || [];
    const recentAdjustments = history.filter(
      event => Date.now() - event.timestamp < 3600000
    ).length;

    if (recentAdjustments > 5) {
      riskScore += 0.4;
      riskFactors.push('Frequent adjustments in last hour');
    }

    // 3. Отрицательные корректировки без причины
    if (data.quantity < 0 && !data.reason) {
      riskScore += 0.3;
      riskFactors.push('Negative adjustment without reason');
    }

    // 4. Подозрительные возвраты
    if (data.operationType === 'RETURN') {
      const returnHistory = history.filter(e => e.operationType === 'RETURN');
      if (returnHistory.length > 10) {
        riskScore += 0.5;
        riskFactors.push('Excessive returns for this product');
      }
    }

    // 5. Ночные операции
    const hour = new Date().getHours();
    if (hour >= 2 && hour <= 5) {
      riskScore += 0.2;
      riskFactors.push('Operation during night hours');
    }

    // Сохранение в историю
    this.saveToHistory(data);

    // Определение действия
    let recommendedAction: 'ALLOW' | 'REVIEW' | 'BLOCK' = 'ALLOW';
    if (riskScore >= 0.7) recommendedAction = 'BLOCK';
    else if (riskScore >= 0.4) recommendedAction = 'REVIEW';

    return {
      isSuspicious: riskScore >= 0.4,
      riskScore: Math.min(1, riskScore),
      riskFactors,
      recommendedAction
    };
  }

  /**
   * Детекция fake returns
   */
  public async detectFakeReturns(data: {
    orderId: string;
    productId: string;
    userId: string;
    returnReason: string;
    returnCondition: string;
  }): Promise<{
    isFake: boolean;
    confidence: number;
    indicators: string[];
  }> {
    const indicators: string[] = [];
    let confidence = 0;

    // Проверка истории возвратов пользователя
    const userReturns = await this.getUserReturnHistory(data.userId);
    
    if (userReturns > 10) {
      indicators.push('High return frequency');
      confidence += 0.3;
    }

    // Проверка причины возврата
    const vagueReasons = ['not as described', 'changed mind', 'no longer needed'];
    if (vagueReasons.includes(data.returnReason.toLowerCase())) {
      indicators.push('Vague return reason');
      confidence += 0.2;
    }

    // Проверка состояния товара
    if (data.returnCondition === 'used' || data.returnCondition === 'damaged') {
      indicators.push('Product condition suspicious');
      confidence += 0.2;
    }

    // Проверка времени возврата
    const orderDate = await this.getOrderDate(data.orderId);
    if (orderDate) {
      const daysSinceOrder = (Date.now() - orderDate) / 86400000;
      if (daysSinceOrder > 30) {
        indicators.push('Late return');
        confidence += 0.2;
      }
    }

    return {
      isFake: confidence >= 0.6,
      confidence: Math.min(1, confidence),
      indicators
    };
  }

  /**
   * Анализ shrinkage (потерь инвентаря)
   */
  public async analyzeShrinkage(warehouseId: string): Promise<{
    shrinkageRate: number;
    isAbnormal: boolean;
    topLostProducts: string[];
    estimatedLoss: number;
  }> {
    // Получение данных по складу
    const warehouseHistory = this.getWarehouseHistory(warehouseId);
    
    const totalAdditions = warehouseHistory
      .filter(e => e.quantity > 0)
      .reduce((sum, e) => sum + e.quantity, 0);

    const totalRemovals = warehouseHistory
      .filter(e => e.quantity < 0 && e.operationType !== 'SALE')
      .reduce((sum, e) => sum + Math.abs(e.quantity), 0);

    const shrinkageRate = totalAdditions > 0 
      ? totalRemovals / totalAdditions 
      : 0;

    // Нормальный shrinkage: 1-3%
    const isAbnormal = shrinkageRate > 0.05;

    // Топ потерянных товаров
    const productLosses = new Map<string, number>();
    for (const event of warehouseHistory) {
      if (event.quantity < 0 && event.operationType !== 'SALE') {
        const current = productLosses.get(event.productId) || 0;
        productLosses.set(event.productId, current + Math.abs(event.quantity));
      }
    }

    const topLostProducts = Array.from(productLosses.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([productId]) => productId);

    return {
      shrinkageRate,
      isAbnormal,
      topLostProducts,
      estimatedLoss: totalRemovals
    };
  }

  private async getUserReturnHistory(userId: string): Promise<number> {
    // В production запрос к базе данных
    return Math.floor(Math.random() * 20);
  }

  private async getOrderDate(orderId: string): Promise<number | null> {
    // В production запрос к базе данных
    return Date.now() - Math.random() * 2592000000; // Last 30 days
  }

  private getWarehouseHistory(warehouseId: string): InventoryEvent[] {
    const allEvents: InventoryEvent[] = [];
    for (const events of this.inventoryHistory.values()) {
      allEvents.push(...events.filter(e => e.warehouseId === warehouseId));
    }
    return allEvents;
  }

  private saveToHistory(data: any): void {
    const key = data.productId;
    
    if (!this.inventoryHistory.has(key)) {
      this.inventoryHistory.set(key, []);
    }

    const event: InventoryEvent = {
      operationType: data.operationType,
      productId: data.productId,
      quantity: data.quantity,
      userId: data.userId,
      warehouseId: data.warehouseId,
      reason: data.reason,
      timestamp: Date.now()
    };

    this.inventoryHistory.get(key)!.push(event);

    // Ограничение истории
    if (this.inventoryHistory.get(key)!.length > 1000) {
      this.inventoryHistory.set(key, this.inventoryHistory.get(key)!.slice(-1000));
    }
  }

  public getStats(): {
    initialized: boolean;
    trackedProducts: number;
    totalEvents: number;
  } {
    const totalEvents = Array.from(this.inventoryHistory.values())
      .reduce((sum, arr) => sum + arr.length, 0);

    return {
      initialized: this.isInitialized,
      trackedProducts: this.inventoryHistory.size,
      totalEvents
    };
  }
}

interface InventoryEvent {
  operationType: string;
  productId: string;
  quantity: number;
  userId: string;
  warehouseId: string;
  reason?: string;
  timestamp: number;
}
