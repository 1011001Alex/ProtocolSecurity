/**
 * AML CHECKER - ПРОВЕРКА НА ОТМЫВАНИЕ ДЕНЕГ
 */

import { EventEmitter } from 'events';
import { logger } from '../../logging/Logger';
import { FinanceSecurityConfig, TransactionData, AMLCheckResult, SanctionsMatch } from '../types/finance.types';

export class AMLChecker extends EventEmitter {
  private readonly config: FinanceSecurityConfig;
  private sanctionsLists: Map<string, any[]> = new Map();
  private isInitialized = false;
  
  constructor(config: FinanceSecurityConfig) {
    super();
    this.config = config;
  }
  
  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    
    try {
      // Загрузка sanctions списков
      for (const listName of this.config.aml.sanctionsLists) {
        logger.info('[AML] Loading sanctions list', { list: listName });
        // В production загрузка реальных списков
        this.sanctionsLists.set(listName, []);
      }
      
      this.isInitialized = true;
      logger.info('[AML] Initialized');
      this.emit('initialized');
    } catch (error) {
      logger.error('[AML] Initialization failed', { error });
      throw error;
    }
  }
  
  public async checkTransaction(transaction: TransactionData): Promise<AMLCheckResult> {
    if (!this.isInitialized) throw new Error('AML not initialized');
    
    const sanctionsMatches: SanctionsMatch[] = [];
    let riskScore = 0;
    
    // Проверка на превышение порога
    if (transaction.amount >= this.config.aml.transactionThreshold) {
      riskScore += 0.3;
    }
    
    // Проверка sanctions списков
    for (const [listName, list] of this.sanctionsLists.entries()) {
      // В production реальная проверка
      const match = list.find(entity => entity.name === transaction.customerId);
      if (match) {
        sanctionsMatches.push({
          listName,
          matchedName: match.name,
          matchScore: 0.95,
          entityType: match.type,
          referenceId: match.id,
          programs: match.programs || []
        });
        riskScore += 0.5;
      }
    }
    
    const passed = riskScore < 0.5 && sanctionsMatches.length === 0;
    
    return {
      passed,
      riskScore,
      sanctionsMatches,
      pepMatch: false,
      adverseMediaMatch: false,
      recommendedAction: passed ? 'PROCEED' : 'REVIEW',
      sarRequired: riskScore >= 0.7
    };
  }
  
  public async fileSuspiciousActivityReport(
    transaction: TransactionData,
    amlCheck: AMLCheckResult
  ): Promise<void> {
    logger.warn('[AML] SAR filing required', {
      transactionId: transaction.transactionId,
      amount: transaction.amount,
      riskScore: amlCheck.riskScore
    });
    
    this.emit('sar_filed', {
      transaction,
      amlCheck,
      filedAt: new Date()
    });
  }
  
  public async destroy(): Promise<void> {
    this.sanctionsLists.clear();
    this.isInitialized = false;
    logger.info('[AML] Destroyed');
  }
}
