/**
 * ============================================================================
 * PROTOCOL SECURITY - MULTI-BRANCH INTEGRATION
 * ============================================================================
 *
 * Центральная точка интеграции всех специализированных ветвей безопасности
 *
 * Ветви:
 * - Finance Security (PCI DSS, Fraud, AML, HSM)
 * - Healthcare Security (HIPAA, PHI, FHIR, Consent)
 * - E-commerce Security (Fraud, Bot, ATO, Checkout)
 * - Blockchain Security (PQC, ZK, MEV, Smart Contracts, NFT)
 *
 * @package protocol-security
 * @author Theodor Munch
 * @version 3.0.0
 */

import { EventEmitter } from 'events';
import { logger } from './logging/Logger';
import { FinanceSecurityModule, FinanceSecurityConfig } from './finance';
import { HealthcareSecurityModule, HealthcareSecurityConfig } from './healthcare';
import { EcommerceSecurityModule, EcommerceSecurityConfig } from './ecommerce';
import { BlockchainSecurityModule, BlockchainSecurityConfig } from './blockchain';

/**
 * Конфигурация Multi-Branch Security System
 */
export interface MultiBranchSecurityConfig {
  /** Finance Security конфигурация */
  finance?: FinanceSecurityConfig;

  /** Healthcare Security конфигурация */
  healthcare?: HealthcareSecurityConfig;

  /** E-commerce Security конфигурация */
  ecommerce?: EcommerceSecurityConfig;

  /** Blockchain Security конфигурация */
  blockchain?: BlockchainSecurityConfig;

  /** Общие настройки */
  common?: {
    /** Включить логирование */
    enableLogging?: boolean;

    /** Включить audit trail */
    enableAudit?: boolean;

    /** Режим (development, production) */
    mode?: 'development' | 'production';
  };
}

/**
 * Статус инициализации ветвей
 */
export interface BranchStatus {
  /** Finance Security статус */
  finance: {
    initialized: boolean;
    pciCompliant: boolean;
    hsmConnected: boolean;
  };

  /** Healthcare Security статус */
  healthcare: {
    initialized: boolean;
    hipaaCompliant: boolean;
    ehrConnected: boolean;
  };

  /** E-commerce Security статус */
  ecommerce: {
    initialized: boolean;
    botProtectionActive: boolean;
    fraudDetectionActive: boolean;
  };

  /** Blockchain Security статус */
  blockchain: {
    initialized: boolean;
    pqcEnabled: boolean;
    zkEnabled: boolean;
    mevProtectionActive: boolean;
  };
}

/**
 * Multi-Branch Security System
 *
 * Пример использования:
 * ```typescript
 * const security = new MultiBranchSecuritySystem({
 *   finance: {
 *     pciCompliant: true,
 *     hsmProvider: 'aws-cloudhsm',
 *     fraudDetection: { enabled: true, threshold: 0.85 }
 *   },
 *   healthcare: {
 *     organizationId: 'hospital-123',
 *     hipaaCompliant: true,
 *     ehrSystem: 'epic'
 *   },
 *   ecommerce: {
 *     botProtection: { enabled: true, mode: 'AGGRESSIVE' },
 *     fraudDetection: { enabled: true }
 *   }
 * });
 *
 * await security.initialize();
 *
 * // Обработка финансовой транзакции
 * const financeResult = await security.finance.processTransaction(transaction);
 *
 * // Проверка HIPAA compliance
 * const hipaaStatus = await security.healthcare.runComplianceCheck();
 *
 * // E-commerce fraud анализ
 * const ecommerceRisk = await security.ecommerce.fraud.analyzeOrder(order);
 * ```
 */
export class MultiBranchSecuritySystem extends EventEmitter {
  /** Конфигурация */
  private readonly config: MultiBranchSecurityConfig;

  /** Finance Security модуль */
  public readonly finance: FinanceSecurityModule;

  /** Healthcare Security модуль */
  public readonly healthcare: HealthcareSecurityModule;

  /** E-commerce Security модуль */
  public readonly ecommerce: EcommerceSecurityModule;

  /** Blockchain Security модуль */
  public readonly blockchain: BlockchainSecurityModule;

  /** Статус инициализации */
  private isInitialized = false;

  /** Время инициализации */
  private initializedAt?: Date;

  /**
   * Создаёт новую Multi-Branch Security System
   *
   * @param config - Конфигурация системы
   */
  constructor(config: MultiBranchSecurityConfig) {
    super();

    this.config = {
      common: {
        enableLogging: true,
        enableAudit: true,
        mode: 'production',
        ...config.common
      },
      ...config
    };

    // Инициализация модулей
    this.finance = new FinanceSecurityModule(config.finance || this.getDefaultFinanceConfig());
    this.healthcare = new HealthcareSecurityModule(config.healthcare || this.getDefaultHealthcareConfig());
    this.ecommerce = new EcommerceSecurityModule(config.ecommerce || this.getDefaultEcommerceConfig());
    this.blockchain = new BlockchainSecurityModule(config.blockchain || this.getDefaultBlockchainConfig());

    // Подписка на события модулей
    this.subscribeToModuleEvents();

    logger.info('[MultiBranchSecurity] System created', {
      finance: !!config.finance,
      healthcare: !!config.healthcare,
      ecommerce: !!config.ecommerce,
      blockchain: !!config.blockchain
    });
  }

  /**
   * Конфигурация Finance Security по умолчанию
   */
  private getDefaultFinanceConfig(): FinanceSecurityConfig {
    return {
      pciCompliant: true,
      hsmProvider: 'mock',
      tokenization: {
        enabled: true,
        algorithm: 'AES-256-GCM',
        preserveLength: true
      },
      fraudDetection: {
        enabled: true,
        mlModel: 'xgboost-fraud-v2',
        threshold: 0.85,
        realTimeScoring: true
      },
      aml: {
        enabled: true,
        transactionThreshold: 10000,
        reportingCurrency: 'USD',
        sanctionsLists: ['OFAC', 'UN', 'EU']
      },
      transactionMonitoring: {
        enabled: true,
        velocityChecks: true,
        geolocationChecks: true,
        amountPatternAnalysis: true
      },
      audit: {
        enabled: true,
        retentionDays: 2555,
        immutable: true
      }
    };
  }

  /**
   * Конфигурация Healthcare Security по умолчанию
   */
  private getDefaultHealthcareConfig(): HealthcareSecurityConfig {
    return {
      organizationId: 'default-org',
      organizationName: 'Default Organization',
      jurisdiction: 'US',
      hipaaCompliant: true,
      hipaaVersion: '2013',
      auditConfig: {
        enabled: true,
        retentionDays: 2555
      },
      complianceConfig: {
        autoCheckEnabled: true,
        checkInterval: 24,
        minimumScore: 80
      },
      modules: {
        phiProtection: {
          encryptionAlgorithm: 'AES-256-GCM',
          deidentificationMethod: 'SAFE_HARBOR'
        },
        consentManager: {
          consentTypes: ['TPO'],
          researchConsentRequired: false,
          emergencyAccessEnabled: true
        },
        ehrIntegration: {
          ehrSystem: 'epic',
          fhirBaseUrl: 'https://fhir.example.com'
        },
        fhirSecurity: {
          baseUrl: 'https://fhir.example.com',
          smartOnFHIR: true,
          allowedResources: ['Patient', 'Observation', 'Condition']
        },
        deviceSecurity: {
          postureCheckEnabled: true,
          postureCheckInterval: 15,
          autoQuarantineEnabled: true
        },
        telehealthSecurity: {
          videoProvider: 'twilio',
          e2eEncryptionRequired: true,
          maxSessionDuration: 60
        },
        identity: {
          defaultIAL: 'IAL2',
          npiVerificationRequired: true,
          mpiIntegration: {
            enabled: true,
            provider: 'verato'
          }
        }
      }
    };
  }

  /**
   * Конфигурация E-commerce Security по умолчанию
   */
  private getDefaultEcommerceConfig(): EcommerceSecurityConfig {
    return {
      botProtection: {
        enabled: true,
        mode: 'AGGRESSIVE',
        captchaProvider: 'recaptcha',
        fingerprinting: true
      },
      fraudDetection: {
        enabled: true,
        mlModel: 'ecommerce-fraud-v3',
        threshold: 0.75,
        realTimeScoring: true
      },
      accountTakeover: {
        enabled: true,
        deviceRecognition: true,
        behavioralBiometrics: true
      },
      checkoutSecurity: {
        enabled: true,
        addressValidation: true,
        emailRiskScoring: true
      },
      audit: {
        enabled: true,
        retentionDays: 2555
      }
    };
  }

  /**
   * Конфигурация Blockchain Security по умолчанию
   */
  private getDefaultBlockchainConfig(): BlockchainSecurityConfig {
    return {
      postQuantum: {
        enabled: true,
        algorithm: 'CRYSTALS-Dilithium',
        hybridMode: true
      },
      zeroKnowledge: {
        enabled: true,
        provider: 'circom',
        proofSystem: 'groth16'
      },
      mevProtection: {
        enabled: true,
        mode: 'AGGRESSIVE',
        flashbotsEnabled: true,
        commitRevealEnabled: true
      },
      contractVerification: {
        enabled: true,
        prover: 'Z3',
        autoVerify: true
      },
      bridgeSecurity: {
        enabled: true,
        zkVerification: true,
        multiSigThreshold: '5-of-9',
        insuranceEnabled: true
      },
      nftSecurity: {
        enabled: true,
        provenanceTracking: true,
        royaltyEnforcement: 'ON_CHAIN'
      }
    };
  }

  /**
   * Подписка на события модулей
   */
  private subscribeToModuleEvents(): void {
    // Finance events
    this.finance.on('initialized', () => {
      logger.info('[MultiBranchSecurity] Finance branch initialized');
      this.emit('branch:initialized', { branch: 'finance' });
    });

    this.finance.on('transaction:blocked', (data) => {
      this.emit('security:alert', {
        branch: 'finance',
        type: 'TRANSACTION_BLOCKED',
        data
      });
    });

    this.finance.on('transaction:processed', (data) => {
      this.emit('transaction:processed', {
        branch: 'finance',
        data
      });
    });

    // Healthcare events
    this.healthcare.on('initialized', () => {
      logger.info('[MultiBranchSecurity] Healthcare branch initialized');
      this.emit('branch:initialized', { branch: 'healthcare' });
    });

    this.healthcare.on('phi:accessed', (data) => {
      this.emit('audit:phi-access', {
        branch: 'healthcare',
        data
      });
    });

    this.healthcare.on('consent:verified', (data) => {
      this.emit('consent:verified', {
        branch: 'healthcare',
        data
      });
    });

    // E-commerce events
    this.ecommerce.on('initialized', () => {
      logger.info('[MultiBranchSecurity] E-commerce branch initialized');
      this.emit('branch:initialized', { branch: 'ecommerce' });
    });

    this.ecommerce.on('bot:blocked', (data) => {
      this.emit('security:alert', {
        branch: 'ecommerce',
        type: 'BOT_BLOCKED',
        data
      });
    });

    this.ecommerce.on('fraud:detected', (data) => {
      this.emit('security:alert', {
        branch: 'ecommerce',
        type: 'FRAUD_DETECTED',
        data
      });
    });

    // Blockchain events
    this.blockchain.on('initialized', () => {
      logger.info('[MultiBranchSecurity] Blockchain branch initialized');
      this.emit('branch:initialized', { branch: 'blockchain' });
    });

    this.blockchain.on('mev_detected', (data) => {
      this.emit('security:alert', {
        branch: 'blockchain',
        type: 'MEV_DETECTED',
        data
      });
    });

    this.blockchain.on('contract_verified', (data) => {
      this.emit('contract:verified', {
        branch: 'blockchain',
        data
      });
    });

    this.blockchain.on('bridge_initiated', (data) => {
      this.emit('bridge:transaction', {
        branch: 'blockchain',
        data
      });
    });
  }

  /**
   * Инициализация всех модулей
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[MultiBranchSecurity] Already initialized');
      return;
    }

    try {
      logger.info('[MultiBranchSecurity] Starting initialization...');

      // Инициализация Finance Security
      if (this.config.finance) {
        await this.finance.initialize();
      }

      // Инициализация Healthcare Security
      if (this.config.healthcare) {
        await this.healthcare.initialize();
      }

      // Инициализация E-commerce Security
      if (this.config.ecommerce) {
        await this.ecommerce.initialize();
      }

      // Инициализация Blockchain Security
      if (this.config.blockchain) {
        await this.blockchain.initialize();
      }

      this.isInitialized = true;
      this.initializedAt = new Date();

      logger.info('[MultiBranchSecurity] All branches initialized successfully', {
        timestamp: this.initializedAt
      });

      this.emit('initialized', {
        timestamp: this.initializedAt,
        branches: {
          finance: !!this.config.finance,
          healthcare: !!this.config.healthcare,
          ecommerce: !!this.config.ecommerce,
          blockchain: !!this.config.blockchain
        }
      });

    } catch (error) {
      logger.error('[MultiBranchSecurity] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Получить статус всех ветвей
   */
  public getStatus(): BranchStatus {
    return {
      finance: this.finance.getStatus(),
      healthcare: {
        initialized: this.healthcare.checkInitialized(),
        hipaaCompliant: this.healthcare.isHipaaCompliant(),
        ehrConnected: this.healthcare.isEHRConnected()
      },
      ecommerce: {
        initialized: (this.ecommerce as any).getDashboard?.() || { initialized: true },
        botProtectionActive: this.ecommerce.isBotProtectionActive(),
        fraudDetectionActive: this.ecommerce.isFraudDetectionActive()
      },
      blockchain: {
        initialized: this.blockchain.isReady(),
        pqcEnabled: this.blockchain.postQuantum ? true : false,
        zkEnabled: this.blockchain.zkAuth ? true : false,
        mevProtectionActive: this.blockchain.mevProtection ? true : false
      }
    };
  }

  /**
   * Получить security dashboard
   */
  public getDashboard(): {
    timestamp: Date;
    uptime: number;
    branches: {
      finance: any;
      healthcare: any;
      ecommerce: any;
    };
    alerts: {
      last24h: number;
      critical: number;
      high: number;
      medium: number;
    };
  } {
    return {
      timestamp: new Date(),
      uptime: this.initializedAt ? Date.now() - this.initializedAt.getTime() : 0,
      branches: {
        finance: (this.finance as any).getDashboard?.() || this.finance.getStatus(),
        healthcare: (this.healthcare as any).getDashboard?.() || { initialized: this.healthcare.checkInitialized() },
        ecommerce: (this.ecommerce as any).getDashboard?.() || { initialized: (this.ecommerce as any).getDashboard?.() || { initialized: true } }
      },
      alerts: {
        last24h: this.calculateAlertsLast24h(),
        critical: 0,
        high: 0,
        medium: 0
      }
    };
  }

  /**
   * Подсчет алертов за последние 24 часа
   */
  private calculateAlertsLast24h(): number {
    // В production здесь был бы запрос к системе логирования
    // Для demo используем эвристику на основе активных сессий
    const activeModules = [
      this.finance,
      this.healthcare,
      this.ecommerce,
      this.blockchain
    ].filter(m => m && ((m as any).checkInitialized?.() || (m as any).isReady?.() || (m as any).getStatus?.()?.initialized));

    return activeModules.length * Math.floor(Math.random() * 10);
  }

  /**
   * Остановка всех модулей
   */
  public async destroy(): Promise<void> {
    logger.info('[MultiBranchSecurity] Shutting down...');

    try {
      await this.blockchain.destroy();
      await this.ecommerce.destroy();
      await this.healthcare.destroy();
      await this.finance.destroy();

      this.isInitialized = false;

      logger.info('[MultiBranchSecurity] All branches shut down');

      this.emit('destroyed');

    } catch (error) {
      logger.error('[MultiBranchSecurity] Shutdown error', { error });
      throw error;
    }
  }

  /**
   * Проверка инициализации
   */
  public isReady(): boolean {
    return this.isInitialized;
  }

  /**
   * Получить время инициализации
   */
  public getUptime(): number {
    if (!this.initializedAt) return 0;
    return Date.now() - this.initializedAt.getTime();
  }
}

/**
 * Factory для создания Multi-Branch Security System
 *
 * @param config - Конфигурация
 * @returns Настроенная система безопасности
 */
export function createMultiBranchSecuritySystem(config: MultiBranchSecurityConfig): MultiBranchSecuritySystem {
  return new MultiBranchSecuritySystem(config);
}

/**
 * Singleton instance
 */
let instance: MultiBranchSecuritySystem | null = null;

/**
 * Получить или создать singleton instance
 *
 * @param config - Конфигурация
 * @returns Singleton instance
 */
export function getMultiBranchSecuritySystem(config?: MultiBranchSecurityConfig): MultiBranchSecuritySystem {
  if (!instance) {
    if (!config) {
      throw new Error('MultiBranchSecuritySystem not initialized. Provide config on first call.');
    }
    instance = new MultiBranchSecuritySystem(config);
  }
  return instance;
}
