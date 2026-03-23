/**
 * TRANSACTION MONITORING - МОНИТОРИНГ ТРАНЗАКЦИЙ
 */

import { EventEmitter } from 'events';
import { logger } from '../../logging/Logger';
import { FinanceSecurityConfig, TransactionData, VelocityCheckResult } from '../types/finance.types';

export class TransactionMonitoring extends EventEmitter {
  private readonly config: FinanceSecurityConfig;
  private transactionHistory: Map<string, TransactionData[]> = new Map();
  private isInitialized = false;
  
  constructor(config: FinanceSecurityConfig) {
    super();
    this.config = config;
  }
  
  public async initialize(): Promise<void> {
    this.isInitialized = true;
    logger.info('[TransactionMonitoring] Initialized');
    this.emit('initialized');
  }
  
  public async checkVelocity(transaction: TransactionData): Promise<VelocityCheckResult> {
    if (!this.isInitialized) throw new Error('Not initialized');
    
    const customerId = transaction.customerId || transaction.ipAddress || 'unknown';
    const history = this.transactionHistory.get(customerId) || [];
    
    // Проверка за последний час
    const oneHourAgo = new Date(Date.now() - 3600000);
    const recentTransactions = history.filter(t => new Date(t.timestamp) > oneHourAgo);
    
    const threshold = 10;
    const passed = recentTransactions.length <= threshold;
    
    // Сохранение в историю
    history.push(transaction);
    this.transactionHistory.set(customerId, history);
    
    return {
      passed,
      checkType: 'TRANSACTION_COUNT',
      timeWindow: '1h',
      currentValue: recentTransactions.length,
      threshold,
      exceededBy: passed ? 0 : recentTransactions.length - threshold
    };
  }
  
  public async destroy(): Promise<void> {
    this.transactionHistory.clear();
    this.isInitialized = false;
    logger.info('[TransactionMonitoring] Destroyed');
  }
}
