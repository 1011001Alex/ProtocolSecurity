/**
 * ============================================================================
 * CHECKOUT SECURITY — БЕЗОПАСНОСТЬ ОФОРМЛЕНИЯ ЗАКАЗА
 * ============================================================================
 *
 * Fraud detection для checkout процесса
 *
 * @package protocol/ecommerce-security
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../logging/Logger';
import { CheckoutRiskResult, CheckoutRiskFactor, CheckoutData } from './types/ecommerce.types';

export class CheckoutSecurity extends EventEmitter {
  private isInitialized = false;
  private readonly config = {
    addressValidation: true,
    emailRiskScoring: true,
    phoneVerification: false
  };

  constructor() {
    super();
    logger.info('[CheckoutSecurity] Service created');
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    logger.info('[CheckoutSecurity] Initialized');
    this.emit('initialized');
  }

  /**
   * Анализ checkout сессии
   */
  public async analyzeCheckout(data: CheckoutData): Promise<CheckoutRiskResult> {
    if (!this.isInitialized) {
      throw new Error('CheckoutSecurity not initialized');
    }

    const riskFactors: CheckoutRiskFactor[] = [];
    let fraudScore = 0;

    // 1. Анализ корзины
    const cartFactor = this.analyzeCart(data.cart);
    riskFactors.push(cartFactor);
    fraudScore += cartFactor.score * cartFactor.weight;

    // 2. Анализ клиента
    const customerFactor = await this.analyzeCustomer(data.customer);
    riskFactors.push(customerFactor);
    fraudScore += customerFactor.score * customerFactor.weight;

    // 3. Анализ доставки
    const shippingFactor = await this.analyzeShipping(data.shipping);
    riskFactors.push(shippingFactor);
    fraudScore += shippingFactor.score * shippingFactor.weight;

    // 4. Анализ платежа
    const paymentFactor = this.analyzePayment(data.payment);
    riskFactors.push(paymentFactor);
    fraudScore += paymentFactor.score * paymentFactor.weight;

    // 5. Анализ устройства
    const deviceFactor = await this.analyzeDevice(data.device);
    riskFactors.push(deviceFactor);
    fraudScore += deviceFactor.score * deviceFactor.weight;

    // Определение уровня риска
    let riskLevel: CheckoutRiskResult['riskLevel'] = 'LOW';
    if (fraudScore >= 0.8) riskLevel = 'CRITICAL';
    else if (fraudScore >= 0.6) riskLevel = 'HIGH';
    else if (fraudScore >= 0.3) riskLevel = 'MEDIUM';

    // Рекомендация
    let recommendedAction: CheckoutRiskResult['recommendedAction'] = 'APPROVE';
    if (riskLevel === 'CRITICAL') recommendedAction = 'BLOCK';
    else if (riskLevel === 'HIGH') recommendedAction = 'REQUIRE_VERIFICATION';
    else if (riskLevel === 'MEDIUM') recommendedAction = 'REVIEW';

    const result: CheckoutRiskResult = {
      sessionId: data.sessionId,
      fraudScore,
      riskLevel,
      riskFactors,
      recommendedAction,
      requiresAdditionalVerification: recommendedAction !== 'APPROVE',
      timestamp: new Date()
    };

    // Логирование
    if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
      logger.warn('[CheckoutSecurity] High risk checkout detected', {
        sessionId: data.sessionId,
        fraudScore,
        riskLevel
      });

      this.emit('fraud_detected', result);
    }

    return result;
  }

  /**
   * Анализ корзины
   */
  private analyzeCart(cart: CheckoutData['cart']): CheckoutRiskFactor {
    let score = 0;
    const issues: string[] = [];

    // Высокая стоимость
    if (cart.totalValue > 5000) {
      score += 0.3;
      issues.push('High order value');
    }

    // Много товаров
    if (cart.items > 10) {
      score += 0.2;
      issues.push('Large quantity of items');
    }

    // Товары высокого риска
    if (cart.highRiskItems && cart.highRiskItems.length > 0) {
      score += 0.3;
      issues.push(`High-risk items: ${cart.highRiskItems.join(', ')}`);
    }

    return {
      name: 'CART_ANALYSIS',
      weight: 0.2,
      score: Math.min(1, score),
      description: issues.join('; ') || 'Normal cart',
      evidence: { items: cart.items, totalValue: cart.totalValue }
    };
  }

  /**
   * Анализ клиента
   */
  private async analyzeCustomer(customer: CheckoutData['customer']): Promise<CheckoutRiskFactor> {
    let score = 0;
    const issues: string[] = [];

    // Гостевой заказ
    if (customer.isGuest) {
      score += 0.2;
      issues.push('Guest checkout');
    }

    // Новый email
    if (customer.emailAge === 'NEW') {
      score += 0.3;
      issues.push('Recently created email');
    }

    // Телефон не верифицирован
    if (!customer.phoneVerified) {
      score += 0.2;
      issues.push('Phone not verified');
    }

    // Нет истории заказов
    if (customer.previousOrders === 0) {
      score += 0.1;
      issues.push('First-time customer');
    }

    return {
      name: 'CUSTOMER_ANALYSIS',
      weight: 0.25,
      score: Math.min(1, score),
      description: issues.join('; ') || 'Established customer',
      evidence: { isGuest: customer.isGuest, emailAge: customer.emailAge }
    };
  }

  /**
   * Анализ доставки
   */
  private async analyzeShipping(shipping: CheckoutData['shipping']): Promise<CheckoutRiskFactor> {
    let score = 0;
    const issues: string[] = [];

    // Высокий риск адреса
    if (shipping.addressRisk === 'HIGH') {
      score += 0.4;
      issues.push('High-risk shipping address');
    }

    // Провал velocity check
    if (shipping.velocityCheck === 'FAILED') {
      score += 0.3;
      issues.push('Velocity check failed');
    }

    // Международная доставка
    if (shipping.country && shipping.country !== 'US') {
      score += 0.1;
      issues.push('International shipping');
    }

    return {
      name: 'SHIPPING_ANALYSIS',
      weight: 0.2,
      score: Math.min(1, score),
      description: issues.join('; ') || 'Normal shipping',
      evidence: { addressRisk: shipping.addressRisk, velocityCheck: shipping.velocityCheck }
    };
  }

  /**
   * Анализ платежа
   */
  private analyzePayment(payment: CheckoutData['payment']): CheckoutRiskFactor {
    let score = 0;
    const issues: string[] = [];

    // Криптовалюта
    if (payment.method === 'CRYPTO') {
      score += 0.2;
      issues.push('Cryptocurrency payment');
    }

    // Наложенный платёж
    if (payment.method === 'COD') {
      score += 0.2;
      issues.push('Cash on delivery');
    }

    // Несовпадение billing адреса
    if (payment.billingAddressMatch === false) {
      score += 0.3;
      issues.push('Billing address mismatch');
    }

    // Несовпадение CVV
    if (payment.cvvMatch === false) {
      score += 0.4;
      issues.push('CVV mismatch');
    }

    return {
      name: 'PAYMENT_ANALYSIS',
      weight: 0.25,
      score: Math.min(1, score),
      description: issues.join('; ') || 'Normal payment',
      evidence: { method: payment.method, cvvMatch: payment.cvvMatch }
    };
  }

  /**
   * Анализ устройства
   */
  private async analyzeDevice(device: CheckoutData['device']): Promise<CheckoutRiskFactor> {
    // В production проверка fingerprint и IP репутации
    return {
      name: 'DEVICE_ANALYSIS',
      weight: 0.1,
      score: 0.1,
      description: 'Normal device',
      evidence: { ipAddress: device.ipAddress }
    };
  }

  /**
   * Требовать дополнительную верификацию
   */
  public async requireAdditionalVerification(): Promise<{
    methods: string[];
    required: boolean;
  }> {
    return {
      methods: ['EMAIL_VERIFICATION', 'SMS_VERIFICATION', 'DOCUMENT_UPLOAD'],
      required: true
    };
  }

  public async destroy(): Promise<void> {
    this.isInitialized = false;
    logger.info('[CheckoutSecurity] Destroyed');
    this.emit('destroyed');
  }
}
