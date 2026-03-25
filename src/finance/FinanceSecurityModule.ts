/**
 * ============================================================================
 * FINANCE SECURITY MODULE - ГЛАВНЫЙ МОДУЛЬ
 * ============================================================================
 *
 * Центральный модуль управления безопасностью финансовых приложений
 *
 * @package protocol/finance-security
 */

import { EventEmitter } from 'events';
import { FinanceSecurityConfig, TransactionData, FraudScore, AMLCheckResult } from '../types/finance.types';
import { PaymentCardEncryption } from './payment/PaymentCardEncryption';
import { TokenizationService } from './payment/TokenizationService';
import { FraudDetectionEngine } from './fraud/FraudDetectionEngine';
import { TransactionMonitoring } from './fraud/TransactionMonitoring';
import { AMLChecker } from './aml/AMLChecker';
import { HSMIntegration } from './hsm/HSMIntegration';

// Logger для совместимости
const logger = {
  info: (msg: string, data?: any) => console.log('[FinanceSecurity]', msg, data),
  warn: (msg: string, data?: any) => console.warn('[FinanceSecurity]', msg, data),
  error: (msg: string, data?: any) => console.error('[FinanceSecurity]', msg, data),
  debug: (msg: string, data?: any) => console.debug('[FinanceSecurity]', msg, data)
};

/**
 * Finance Security Module
 */
export class FinanceSecurityModule extends EventEmitter {
  /** Конфигурация */
  private readonly config: FinanceSecurityConfig;
  
  /** Payment card encryption */
  public readonly paymentEncryption: PaymentCardEncryption;
  
  /** Tokenization service */
  public readonly tokenization: TokenizationService;
  
  /** Fraud detection engine */
  public readonly fraud: FraudDetectionEngine;
  
  /** Transaction monitoring */
  public readonly monitoring: TransactionMonitoring;
  
  /** AML checker */
  public readonly aml: AMLChecker;
  
  /** HSM integration */
  public readonly hsm: HSMIntegration;
  
  /** Статус инициализации */
  private isInitialized = false;
  
  /**
   * Создаёт новый экземпляр FinanceSecurityModule
   * 
   * @param config - Конфигурация модуля
   */
  constructor(config: FinanceSecurityConfig) {
    super();
    
    this.config = {
      pciCompliant: config.pciCompliant ?? true,
      hsmProvider: config.hsmProvider ?? 'mock',
      tokenization: {
        enabled: config.tokenization?.enabled ?? true,
        algorithm: config.tokenization?.algorithm ?? 'AES-256-GCM',
        preserveLength: config.tokenization?.preserveLength ?? true
      },
      fraudDetection: {
        enabled: config.fraudDetection?.enabled ?? true,
        mlModel: config.fraudDetection?.mlModel ?? 'xgboost-fraud-v2',
        threshold: config.fraudDetection?.threshold ?? 0.85,
        realTimeScoring: config.fraudDetection?.realTimeScoring ?? true
      },
      aml: {
        enabled: config.aml?.enabled ?? true,
        transactionThreshold: config.aml?.transactionThreshold ?? 10000,
        reportingCurrency: config.aml?.reportingCurrency ?? 'USD',
        sanctionsLists: config.aml?.sanctionsLists ?? ['OFAC', 'UN', 'EU']
      },
      transactionMonitoring: {
        enabled: config.transactionMonitoring?.enabled ?? true,
        velocityChecks: config.transactionMonitoring?.velocityChecks ?? true,
        geolocationChecks: config.transactionMonitoring?.geolocationChecks ?? true,
        amountPatternAnalysis: config.transactionMonitoring?.amountPatternAnalysis ?? true
      },
      audit: {
        enabled: config.audit?.enabled ?? true,
        retentionDays: config.audit?.retentionDays ?? 2555, // 7 лет для PCI DSS
        immutable: config.audit?.immutable ?? true
      }
    };
    
    // Инициализация подмодулей
    this.paymentEncryption = new PaymentCardEncryption(this.config);
    this.tokenization = new TokenizationService(this.config);
    this.fraud = new FraudDetectionEngine(this.config);
    this.monitoring = new TransactionMonitoring(this.config);
    this.aml = new AMLChecker(this.config);
    this.hsm = new HSMIntegration(this.config);
    
    logger.info('[FinanceSecurity] Module created', {
      pciCompliant: this.config.pciCompliant,
      hsmProvider: this.config.hsmProvider,
      fraudDetectionEnabled: this.config.fraudDetection.enabled
    });
  }
  
  /**
   * Инициализация модуля
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[FinanceSecurity] Already initialized');
      return;
    }
    
    try {
      // Инициализация HSM
      if (this.config.hsmProvider !== 'mock') {
        await this.hsm.initialize();
        logger.info('[FinanceSecurity] HSM initialized', {
          provider: this.config.hsmProvider
        });
      }
      
      // Инициализация токенизации
      if (this.config.tokenization.enabled) {
        await this.tokenization.initialize();
        logger.info('[FinanceSecurity] Tokenization initialized');
      }
      
      // Инициализация fraud detection
      if (this.config.fraudDetection.enabled) {
        await this.fraud.initialize();
        logger.info('[FinanceSecurity] Fraud detection initialized', {
          model: this.config.fraudDetection.mlModel
        });
      }
      
      // Инициализация AML
      if (this.config.aml.enabled) {
        await this.aml.initialize();
        logger.info('[FinanceSecurity] AML initialized', {
          threshold: this.config.aml.transactionThreshold,
          sanctionsLists: this.config.aml.sanctionsLists
        });
      }
      
      // Инициализация мониторинга транзакций
      if (this.config.transactionMonitoring.enabled) {
        await this.monitoring.initialize();
        logger.info('[FinanceSecurity] Transaction monitoring initialized');
      }
      
      this.isInitialized = true;
      
      logger.info('[FinanceSecurity] Module fully initialized');
      
      this.emit('initialized');
      
    } catch (error) {
      logger.error('[FinanceSecurity] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }
  
  /**
   * Обработка финансовой транзакции
   * 
   * @param transaction - Данные транзакции
   * @returns Результат обработки
   */
  public async processTransaction(transaction: TransactionData): Promise<{
    approved: boolean;
    fraudScore?: FraudScore;
    amlCheck?: AMLCheckResult;
    tokenizedData?: any;
  }> {
    if (!this.isInitialized) {
      throw new Error('FinanceSecurity module not initialized');
    }
    
    const result: any = {
      approved: true,
      timestamp: new Date()
    };
    
    // 1. Fraud detection
    if (this.config.fraudDetection.enabled) {
      const fraudScore = await this.fraud.analyzeTransaction(transaction);
      result.fraudScore = fraudScore;
      
      if (fraudScore.riskLevel === 'CRITICAL' || fraudScore.riskLevel === 'HIGH') {
        result.approved = false;
        result.blockReason = 'HIGH_FRAUD_RISK';
        
        logger.warn('[FinanceSecurity] Transaction blocked due to high fraud risk', {
          transactionId: transaction.transactionId,
          fraudScore: fraudScore.score
        });
        
        this.emit('transaction:blocked', {
          transaction,
          reason: 'FRAUD',
          fraudScore
        });
        
        return result;
      }
    }
    
    // 2. AML check для крупных транзакций
    if (this.config.aml.enabled && transaction.amount >= this.config.aml.transactionThreshold) {
      const amlCheck = await this.aml.checkTransaction(transaction);
      result.amlCheck = amlCheck;
      
      if (!amlCheck.passed) {
        result.approved = false;
        result.blockReason = 'AML_CHECK_FAILED';
        
        logger.warn('[FinanceSecurity] Transaction blocked due to AML check failure', {
          transactionId: transaction.transactionId,
          amount: transaction.amount
        });
        
        this.emit('transaction:blocked', {
          transaction,
          reason: 'AML',
          amlCheck
        });
        
        return result;
      }
      
      // SAR filing если требуется
      if (amlCheck.sarRequired) {
        await this.aml.fileSuspiciousActivityReport(transaction, amlCheck);
      }
    }
    
    // 3. Velocity checks
    if (this.config.transactionMonitoring.velocityChecks) {
      const velocityCheck = await this.monitoring.checkVelocity(transaction);
      result.velocityCheck = velocityCheck;
      
      if (!velocityCheck.passed) {
        result.approved = false;
        result.blockReason = 'VELOCITY_EXCEEDED';
        
        logger.warn('[FinanceSecurity] Transaction blocked due to velocity check', {
          transactionId: transaction.transactionId,
          exceededBy: velocityCheck.exceededBy
        });
        
        this.emit('transaction:blocked', {
          transaction,
          reason: 'VELOCITY',
          velocityCheck
        });
        
        return result;
      }
    }
    
    // 4. Tokenization чувствительных данных
    if (this.config.tokenization.enabled && transaction.paymentMethod) {
      const tokenizedData = await this.tokenization.tokenizePaymentMethod(transaction.paymentMethod);
      result.tokenizedData = tokenizedData;
    }
    
    // 5. Audit logging
    if (this.config.audit.enabled) {
      await this.logAuditEvent({
        transactionId: transaction.transactionId,
        eventType: 'TRANSACTION_PROCESSED',
        result: result.approved ? 'SUCCESS' : 'BLOCKED',
        amount: transaction.amount,
        fraudScore: result.fraudScore?.score,
        amlCheck: result.amlCheck?.passed
      });
    }
    
    logger.info('[FinanceSecurity] Transaction processed', {
      transactionId: transaction.transactionId,
      approved: result.approved,
      amount: transaction.amount
    });
    
    this.emit('transaction:processed', {
      transaction,
      result
    });
    
    return result;
  }
  
  /**
   * PCI DSS audit logging
   */
  private async logAuditEvent(event: {
    transactionId: string;
    eventType: string;
    result: string;
    amount?: number;
    fraudScore?: number;
    amlCheck?: boolean;
  }): Promise<void> {
    // Реализация будет зависеть от системы логирования
    logger.info('[FinanceSecurity] PCI DSS Audit', event);
  }
  
  /**
   * Остановка модуля
   */
  public async destroy(): Promise<void> {
    logger.info('[FinanceSecurity] Shutting down...');
    
    if (this.hsm) {
      await this.hsm.destroy();
    }
    
    if (this.fraud) {
      await this.fraud.destroy();
    }
    
    if (this.monitoring) {
      await this.monitoring.destroy();
    }
    
    if (this.aml) {
      await this.aml.destroy();
    }
    
    this.isInitialized = false;
    
    logger.info('[FinanceSecurity] Module shut down');
    
    this.emit('destroyed');
  }
  
  /**
   * Получить статус модуля
   */
  public getStatus(): {
    initialized: boolean;
    pciCompliant: boolean;
    hsmConnected: boolean;
    fraudModelLoaded: boolean;
    amlEnabled: boolean;
  } {
    return {
      initialized: this.isInitialized,
      pciCompliant: this.config.pciCompliant,
      hsmConnected: this.isInitialized && this.config.hsmProvider !== 'mock',
      fraudModelLoaded: this.isInitialized && this.config.fraudDetection.enabled,
      amlEnabled: this.config.aml.enabled
    };
  }
}
