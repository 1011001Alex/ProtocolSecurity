/**
 * ============================================================================
 * E-COMMERCE SECURITY MODULE - ГЛАВНЫЙ МОДУЛЬ
 * ============================================================================
 *
 * Fraud Prevention, Bot Protection, Account Takeover Prevention
 *
 * @package protocol/ecommerce-security
 */

import { EventEmitter } from 'events';
import { logger } from '../utils/StubLogger';
import { EcommerceSecurityConfig } from './types/ecommerce.types';
import { BotProtection } from './BotProtection';
import { AccountTakeoverPrevention } from './AccountTakeoverPrevention';
import { CheckoutSecurity } from './CheckoutSecurity';
import { PaymentFraudDetection } from './PaymentFraudDetection';
import { ReviewFraudDetection } from './ReviewFraudDetection';
import { InventoryFraud } from './InventoryFraud';
import { CouponAbusePrevention } from './CouponAbusePrevention';
import { MarketplaceSecurity } from './MarketplaceSecurity';

/**
 * E-commerce Security Module
 */
export class EcommerceSecurityModule extends EventEmitter {
  /** Конфигурация */
  private readonly config: EcommerceSecurityConfig;

  /** Bot Protection */
  public readonly botProtection: BotProtection;

  /** Account Takeover Prevention */
  public readonly accountTakeover: AccountTakeoverPrevention;

  /** Checkout Security */
  public readonly checkout: CheckoutSecurity;

  /** Payment Fraud Detection */
  public readonly paymentFraud: PaymentFraudDetection;

  /** Review Fraud Detection */
  public readonly reviewFraud: ReviewFraudDetection;

  /** Inventory Fraud */
  public readonly inventory: InventoryFraud;

  /** Coupon Abuse Prevention */
  public readonly coupon: CouponAbusePrevention;

  /** Marketplace Security */
  public readonly marketplace: MarketplaceSecurity;

  /** Статус инициализации */
  private isInitialized = false;

  /** Время инициализации */
  private initializedAt?: Date;

  /**
   * Создаёт новый экземпляр EcommerceSecurityModule
   */
  constructor(config: EcommerceSecurityConfig) {
    super();

    this.config = {
      botProtection: config.botProtection ?? { enabled: true, mode: 'AGGRESSIVE' },
      fraudDetection: config.fraudDetection ?? { enabled: true, mlModel: 'ecommerce-fraud-v3' },
      accountTakeover: config.accountTakeover ?? { enabled: true },
      checkoutSecurity: config.checkoutSecurity ?? { enabled: true },
      audit: config.audit ?? { enabled: true, retentionDays: 2555 }
    };

    // Инициализация подмодулей
    this.botProtection = new BotProtection();
    this.accountTakeover = new AccountTakeoverPrevention();
    this.checkout = new CheckoutSecurity();
    this.paymentFraud = new PaymentFraudDetection();
    this.reviewFraud = new ReviewFraudDetection();
    this.inventory = new InventoryFraud();
    this.coupon = new CouponAbusePrevention();
    this.marketplace = new MarketplaceSecurity();

    logger.info('[EcommerceSecurity] Module created', {
      botProtectionEnabled: this.config.botProtection.enabled,
      fraudDetectionEnabled: this.config.fraudDetection.enabled
    });
  }

  /**
   * Инициализация модуля
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[EcommerceSecurity] Already initialized');
      return;
    }

    try {
      await this.botProtection.initialize();
      await this.accountTakeover.initialize();
      await this.checkout.initialize();
      await this.paymentFraud.initialize();
      await this.reviewFraud.initialize();
      await this.inventory.initialize();
      await this.coupon.initialize();
      await this.marketplace.initialize();

      this.isInitialized = true;
      this.initializedAt = new Date();

      logger.info('[EcommerceSecurity] Module fully initialized');
      this.emit('initialized');

    } catch (error) {
      logger.error('[EcommerceSecurity] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Проверка активности bot protection
   */
  public isBotProtectionActive(): boolean {
    return this.isInitialized && this.config.botProtection.enabled;
  }

  /**
   * Проверка активности fraud detection
   */
  public isFraudDetectionActive(): boolean {
    return this.isInitialized && this.config.fraudDetection.enabled;
  }

  /**
   * Получение security dashboard
   */
  public getDashboard(): any {
    return {
      timestamp: new Date(),
      botProtectionActive: this.isBotProtectionActive(),
      fraudDetectionActive: this.isFraudDetectionActive(),
      blockedBots24h: 0,
      preventedATO24h: 0,
      blockedCheckouts24h: 0,
      flaggedReviews24h: 0,
      recentFraudCases: []
    };
  }

  /**
   * Остановка модуля
   */
  public async destroy(): Promise<void> {
    logger.info('[EcommerceSecurity] Shutting down...');

    await this.botProtection.destroy();
    await this.accountTakeover.destroy();
    await this.checkout.destroy();
    await this.paymentFraud.destroy();
    await this.reviewFraud.destroy();
    await this.inventory.destroy();
    await this.coupon.destroy();
    await this.marketplace.destroy();

    this.isInitialized = false;

    logger.info('[EcommerceSecurity] Module shut down');
    this.emit('destroyed');
  }

  /**
   * Проверка инициализации
   */
  public isReady(): boolean {
    return this.isInitialized;
  }

  /**
   * Получение uptime
   */
  public getUptime(): number {
    if (!this.initializedAt) return 0;
    return Date.now() - this.initializedAt.getTime();
  }

  /**
   * Получение статуса
   */
  public getStatus(): {
    initialized: boolean;
    botProtectionActive: boolean;
    fraudDetectionActive: boolean;
  } {
    return {
      initialized: this.isInitialized,
      botProtectionActive: this.isBotProtectionActive(),
      fraudDetectionActive: this.isFraudDetectionActive()
    };
  }
}

/**
 * Factory для создания E-commerce Security Module
 */
export function createEcommerceSecurityModule(config: EcommerceSecurityConfig): EcommerceSecurityModule {
  return new EcommerceSecurityModule(config);
}
