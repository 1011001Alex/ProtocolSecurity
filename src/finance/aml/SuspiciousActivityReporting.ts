/**
 * ============================================================================
 * SUSPICIOUS ACTIVITY REPORTING — ОТЧЁТНОСТЬ ПО ПОДОЗРИТЕЛЬНЫМ ОПЕРАЦИЯМ
 * ============================================================================
 *
 * Автоматизированная генерация и подача SAR (Suspicious Activity Report)
 *
 * Реализация:
 * - FinCEN SAR (USA)
 * - AUSTRAC SAR (Australia)
 * - FIU-IND SAR (India)
 * - ROSFINMONITORING (Russia)
 * - EU SAR форматы
 *
 * @package protocol/finance-security/aml
 * @author Protocol Security Team
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../../logging/Logger';
import {
  FinanceSecurityConfig,
  TransactionData,
  AMLCheckResult,
  SuspiciousActivityReport,
  SARSubject
} from '../types/finance.types';

/**
 * Типы подозрительной активности
 */
type SuspiciousActivityType =
  | 'MONEY_LAUNDERING'
  | 'TERRORIST_FINANCING'
  | 'SANCTIONS_EVASION'
  | 'FRAUD'
  | 'CORRUPTION'
  | 'TAX_EVASION'
  | 'CYBERCRIME'
  | 'NARCOTICS_TRAFFICKING'
  | 'HUMAN_TRAFFICKING'
  | 'ARMS_TRAFFICKING'
  | 'PROLIFERATION_FINANCING'
  | 'STRUCTURING_SMURFING'
  | 'TRADE_BASED_MONEY_LAUNDERING'
  | 'SHELL_COMPANY'
  | 'PEP_RELATED'
  | 'OTHER';

/**
 * SAR filing status
 */
type SARFilingStatus =
  | 'DRAFT'
  | 'PENDING_REVIEW'
  | 'PENDING_APPROVAL'
  | 'FILED'
  | 'SUBMITTED'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'CLOSED';

/**
 * Данные для SAR
 */
interface SARData {
  /** Транзакции, вызвавшие подозрения */
  transactions: TransactionData[];

  /** Результаты AML проверок */
  amlCheckResults: AMLCheckResult[];

  /** Подозрительная активность */
  suspiciousActivity: SuspiciousActivityType[];

  /** Дополнительная информация */
  narrative: string;

  /** Прикрепленные документы */
  supportingDocuments: string[];
}

/**
 * Suspicious Activity Reporting Service
 */
export class SuspiciousActivityReporting extends EventEmitter {
  /** Конфигурация */
  private readonly config: FinanceSecurityConfig;

  /** Очередь SAR на подачу */
  private sarQueue: Map<string, SuspiciousActivityReport> = new Map();

  /** История поданных SAR */
  private sarHistory: SuspiciousActivityReport[] = [];

  /** Статус инициализации */
  private isInitialized = false;

  /** Конфигурация отчётности */
  private readonly reportingConfig = {
    // Юрисдикция для отчётности
    jurisdiction: 'US' as 'US' | 'EU' | 'AU' | 'IN' | 'RU',

    // Финансовый институт
    filingInstitution: {
      name: 'Default Financial Institution',
      lei: 'DEFAULTLEI123456789',
      address: '123 Finance Street, New York, NY 10001',
      phone: '+1-555-123-4567',
      email: 'compliance@fi.example.com'
    },

    // Пороги для автоматической подачи
    autoFileThreshold: {
      amount: 50000, // USD
      riskScore: 0.9
    },

    // Срок хранения SAR (лет)
    retentionYears: 5,

    // Требуемые уровни одобрения
    approvalLevels: {
      draft: 0,
      pendingReview: 1,
      pendingApproval: 2,
      filed: 3
    }
  };

  /**
   * Создаёт новый экземпляр SuspiciousActivityReporting
   */
  constructor(config: FinanceSecurityConfig) {
    super();

    this.config = config;

    logger.info('[SARReporting] Service created');
  }

  /**
   * Инициализация сервиса
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[SARReporting] Already initialized');
      return;
    }

    try {
      // Загрузка истории SAR (из БД в production)
      // await this.loadHistory();

      this.isInitialized = true;

      logger.info('[SARReporting] Initialized');

      this.emit('initialized');

    } catch (error) {
      logger.error('[SARReporting] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Создание SAR из транзакции и AML проверки
   *
   * @param transaction - Транзакция
   * @param amlCheck - Результат AML проверки
   * @param activityTypes - Типы подозрительной активности
   * @returns Созданный SAR
   */
  public async createSAR(
    transaction: TransactionData,
    amlCheck: AMLCheckResult,
    activityTypes: SuspiciousActivityType[] = ['MONEY_LAUNDERING']
  ): Promise<SuspiciousActivityReport> {
    if (!this.isInitialized) {
      throw new Error('SARReporting not initialized');
    }

    const sarId = `SAR-${Date.now()}-${uuidv4().slice(0, 8).toUpperCase()}`;

    // Определение субъектов (отправитель и получатель)
    const subjects: SARSubject[] = [];

    if (transaction.customerId) {
      subjects.push({
        subjectId: `SUBJ-SENDER-${Date.now()}`,
        type: 'INDIVIDUAL',
        name: transaction.customerId, // В production реальное имя
        role: 'SENDER'
      });
    }

    if (transaction.metadata?.beneficiaryId) {
      subjects.push({
        subjectId: `SUBJ-BENEFICIARY-${Date.now()}`,
        type: 'INDIVIDUAL',
        name: transaction.metadata.beneficiaryId,
        role: 'BENEFICIARY'
      });
    }

    // Формирование narrative
    const narrative = this.generateNarrative(transaction, amlCheck, activityTypes);

    const sar: SuspiciousActivityReport = {
      sarId,
      filingInstitution: this.reportingConfig.filingInstitution.name,
      activityDate: transaction.timestamp,
      activityType: activityTypes.join(', '),
      amountInvolved: transaction.amount,
      narrative,
      subjects,
      supportingDocs: [],
      status: 'DRAFT',
      createdAt: new Date()
    };

    // Добавление в очередь
    this.sarQueue.set(sarId, sar);

    logger.info('[SARReporting] SAR created', {
      sarId,
      status: sar.status,
      amount: transaction.amount,
      activityTypes
    });

    this.emit('sar_created', {
      sar,
      transaction
    });

    return sar;
  }

  /**
   * Подача SAR в регулирующий орган
   *
   * @param sarId - ID SAR
   * @returns Результат подачи
   */
  public async fileSAR(sarId: string): Promise<{
    success: boolean;
    filedAt?: Date;
    confirmationNumber?: string;
    error?: string;
  }> {
    if (!this.isInitialized) {
      throw new Error('SARReporting not initialized');
    }

    const sar = this.sarQueue.get(sarId);

    if (!sar) {
      throw new Error(`SAR not found: ${sarId}`);
    }

    if (sar.status !== 'PENDING_APPROVAL' && sar.status !== 'DRAFT') {
      throw new Error(`Invalid SAR status for filing: ${sar.status}`);
    }

    try {
      logger.info('[SARReporting] Filing SAR', {
        sarId,
        jurisdiction: this.reportingConfig.jurisdiction
      });

      // В production реальная подача через:
      // - FinCEN BSA E-Filing System (USA)
      // - AUSTRAC Online (Australia)
      // - ROSFINMONITORING (Russia)

      // Симуляция подачи
      const confirmationNumber = this.generateConfirmationNumber(sarId);
      const filedAt = new Date();

      // Обновление статуса
      sar.status = 'FILED';
      sar.filingDate = filedAt;

      // Добавление в историю
      this.sarHistory.push(sar);
      this.sarQueue.delete(sarId);

      logger.info('[SARReporting] SAR filed successfully', {
        sarId,
        confirmationNumber,
        filedAt
      });

      this.emit('sar_filed', {
        sar,
        confirmationNumber,
        filedAt
      });

      return {
        success: true,
        filedAt,
        confirmationNumber
      };

    } catch (error) {
      logger.error('[SARReporting] SAR filing failed', {
        sarId,
        error
      });

      sar.status = 'REJECTED';

      this.emit('sar_rejected', {
        sar,
        error
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      };
    }
  }

  /**
   * Обновление статуса SAR
   *
   * @param sarId - ID SAR
   * @param newStatus - Новый статус
   * @returns Обновлённый SAR
   */
  public updateSARStatus(
    sarId: string,
    newStatus: SARFilingStatus
  ): SuspiciousActivityReport {
    if (!this.isInitialized) {
      throw new Error('SARReporting not initialized');
    }

    let sar = this.sarQueue.get(sarId);

    if (!sar) {
      // Поиск в истории
      sar = this.sarHistory.find(s => s.sarId === sarId);

      if (!sar) {
        throw new Error(`SAR not found: ${sarId}`);
      }
    }

    const oldStatus = sar.status;
    sar.status = newStatus;

    logger.info('[SARReporting] SAR status updated', {
      sarId,
      oldStatus,
      newStatus
    });

    this.emit('sar_status_updated', {
      sar,
      oldStatus,
      newStatus
    });

    return sar;
  }

  /**
   * Добавление документа к SAR
   *
   * @param sarId - ID SAR
   * @param documentUrl - URL документа
   * @param documentType - Тип документа
   */
  public addSupportingDocument(
    sarId: string,
    documentUrl: string,
    documentType: string
  ): void {
    if (!this.isInitialized) {
      throw new Error('SARReporting not initialized');
    }

    const sar = this.sarQueue.get(sarId);

    if (!sar) {
      throw new Error(`SAR not found: ${sarId}`);
    }

    sar.supportingDocs.push(`${documentType}:${documentUrl}`);

    logger.debug('[SARReporting] Document added to SAR', {
      sarId,
      documentType,
      documentUrl
    });

    this.emit('document_added', {
      sarId,
      documentUrl,
      documentType
    });
  }

  /**
   * Получение SAR по ID
   */
  public getSAR(sarId: string): SuspiciousActivityReport | undefined {
    return this.sarQueue.get(sarId) || this.sarHistory.find(s => s.sarId === sarId);
  }

  /**
   * Получение всех SAR в очереди
   */
  public getSARQueue(): SuspiciousActivityReport[] {
    return Array.from(this.sarQueue.values());
  }

  /**
   * Получение истории SAR
   */
  public getSARHistory(options?: {
    fromDate?: Date;
    toDate?: Date;
    status?: SARFilingStatus;
    minAmount?: number;
  }): SuspiciousActivityReport[] {
    let history = [...this.sarHistory];

    if (options) {
      if (options.fromDate) {
        history = history.filter(sar => sar.activityDate >= options.fromDate!);
      }

      if (options.toDate) {
        history = history.filter(sar => sar.activityDate <= options.toDate!);
      }

      if (options.status) {
        history = history.filter(sar => sar.status === options.status);
      }

      if (options.minAmount) {
        history = history.filter(sar => sar.amountInvolved >= options.minAmount!);
      }
    }

    return history.sort((a, b) => b.activityDate.getTime() - a.activityDate.getTime());
  }

  /**
   * Статистика SAR
   */
  public getSARStatistics(period: {
    fromDate: Date;
    toDate: Date;
  }): {
    totalFiled: number;
    totalAmount: number;
    byActivityType: Map<string, number>;
    byStatus: Map<string, number>;
    averageProcessingTime: number; // ms
  } {
    const history = this.getSARHistory({
      fromDate: period.fromDate,
      toDate: period.toDate
    });

    const totalFiled = history.filter(s => s.status === 'FILED' || s.status === 'ACCEPTED').length;
    const totalAmount = history.reduce((sum, sar) => sum + sar.amountInvolved, 0);

    const byActivityType = new Map<string, number>();
    const byStatus = new Map<string, number>();

    for (const sar of history) {
      // По типам активности
      const types = sar.activityType.split(', ');

      for (const type of types) {
        byActivityType.set(type, (byActivityType.get(type) || 0) + 1);
      }

      // По статусам
      byStatus.set(sar.status, (byStatus.get(sar.status) || 0) + 1);
    }

    // Среднее время обработки (от создания до подачи)
    const filedSARs = history.filter(s => s.filingDate);
    const averageProcessingTime = filedSARs.length > 0
      ? filedSARs.reduce((sum, sar) => {
          const processingTime = sar.filingDate!.getTime() - sar.createdAt.getTime();
          return sum + processingTime;
        }, 0) / filedSARs.length
      : 0;

    return {
      totalFiled,
      totalAmount,
      byActivityType,
      byStatus,
      averageProcessingTime
    };
  }

  /**
   * Генерация narrative для SAR
   */
  private generateNarrative(
    transaction: TransactionData,
    amlCheck: AMLCheckResult,
    activityTypes: SuspiciousActivityType[]
  ): string {
    const parts: string[] = [];

    // Введение
    parts.push(
      `On ${transaction.timestamp.toLocaleDateString()}, a suspicious transaction ` +
      `was detected involving ${transaction.amount.toLocaleString('en-US', { style: 'currency', currency: transaction.currency })}.`
    );

    // Описание транзакции
    parts.push(
      `Transaction ID: ${transaction.transactionId}. ` +
      `Type: ${transaction.transactionType}. ` +
      `Channel: ${transaction.channel}.`
    );

    // AML результаты
    if (amlCheck.sanctionsMatches.length > 0) {
      parts.push(
        `SANCTIONS MATCH: The transaction matched ${amlCheck.sanctionsMatches.length} ` +
        `sanctions list entries. Matches: ${amlCheck.sanctionsMatches.map(m => m.matchedName).join(', ')}.`
      );
    }

    if (amlCheck.pepMatch) {
      parts.push('PEP MATCH: The transaction involved a Politically Exposed Person.');
    }

    if (amlCheck.adverseMediaMatch) {
      parts.push('ADVERSE MEDIA: Negative news found related to the transaction parties.');
    }

    // Типы подозрительной активности
    if (activityTypes.length > 0) {
      parts.push(
        `SUSPICIOUS ACTIVITY TYPES: ${activityTypes.join(', ')}.`
      );
    }

    // Обоснование подозрений
    parts.push(
      `This transaction is being reported due to: ` +
      `${this.getActivityDescription(activityTypes)}. ` +
      `Risk Score: ${(amlCheck.riskScore * 100).toFixed(1)}%.`
    );

    // Заключение
    parts.push(
      `No apparent legitimate business purpose was identified for this transaction. ` +
      `Further investigation is recommended.`
    );

    return parts.join(' ');
  }

  /**
   * Описание подозрительной активности
   */
  private getActivityDescription(activityTypes: SuspiciousActivityType[]): string {
    const descriptions: { [key in SuspiciousActivityType]: string } = {
      MONEY_LAUNDERING: 'potential money laundering activities',
      TERRORIST_FINANCING: 'potential terrorist financing',
      SANCTIONS_EVASION: 'attempted sanctions evasion',
      FRAUD: 'fraudulent activity indicators',
      CORRUPTION: 'potential corruption or bribery',
      TAX_EVASION: 'potential tax evasion',
      CYBERCRIME: 'cybercrime-related transactions',
      NARCOTICS_TRAFFICKING: 'narcotics trafficking indicators',
      HUMAN_TRAFFICKING: 'human trafficking indicators',
      ARMS_TRAFFICKING: 'arms trafficking indicators',
      PROLIFERATION_FINANCING: 'proliferation financing concerns',
      STRUCTURING_SMURFING: 'structuring/smurfing to avoid reporting thresholds',
      TRADE_BASED_MONEY_LAUNDERING: 'trade-based money laundering indicators',
      SHELL_COMPANY: 'shell company involvement suspected',
      PEP_RELATED: 'PEP-related high-risk transaction',
      OTHER: 'other suspicious patterns'
    };

    return activityTypes.map(t => descriptions[t]).join('; ');
  }

  /**
   * Генерация confirmation number
   */
  private generateConfirmationNumber(sarId: string): string {
    const timestamp = Date.now().toString(36).toUpperCase();
    const hash = createHash('sha256').update(sarId + timestamp).digest('hex').slice(0, 8).toUpperCase();

    return `SAR-${this.reportingConfig.jurisdiction}-${timestamp}-${hash}`;
  }

  /**
   * Массовая подача SAR из очереди
   *
   * @param options - Опции массовой filing
   * @returns Результаты подачи
   */
  public async bulkFileSARs(options?: {
    minRiskScore?: number;
    minAmount?: number;
    autoApprove?: boolean;
  }): Promise<{
    total: number;
    filed: number;
    failed: number;
    results: Array<{ sarId: string; success: boolean; error?: string }>;
  }> {
    if (!this.isInitialized) {
      throw new Error('SARReporting not initialized');
    }

    const queue = this.getSARQueue();
    const results: Array<{ sarId: string; success: boolean; error?: string }> = [];
    let filed = 0;
    let failed = 0;

    for (const sar of queue) {
      // Фильтрация по параметрам
      if (options?.minRiskScore && sar.amountInvolved < options.minRiskScore) {
        continue;
      }

      if (options?.minAmount && sar.amountInvolved < options.minAmount) {
        continue;
      }

      // Авто-одобрение если включено
      if (options?.autoApprove && sar.status === 'DRAFT') {
        this.updateSARStatus(sar.sarId, 'PENDING_APPROVAL');
        this.updateSARStatus(sar.sarId, 'FILED');
      }

      const result = await this.fileSAR(sar.sarId);

      results.push({
        sarId: sar.sarId,
        success: result.success,
        error: result.error
      });

      if (result.success) {
        filed++;
      } else {
        failed++;
      }
    }

    logger.info('[SARReporting] Bulk filing completed', {
      total: queue.length,
      filed,
      failed
    });

    return {
      total: queue.length,
      filed,
      failed,
      results
    };
  }

  /**
   * Экспорт SAR в формате XML (FinCEN)
   */
  public exportToXML(sarId: string): string {
    const sar = this.getSAR(sarId);

    if (!sar) {
      throw new Error(`SAR not found: ${sarId}`);
    }

    // FinCEN XML format
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<FincenSAR xmlns="urn:fincen:sar:2.0">
  <SARIdentification>
    <SARNumber>${sar.sarId}</SARNumber>
    <FilingInstitution>${sar.filingInstitution}</FilingInstitution>
  </SARIdentification>
  <SuspiciousActivity>
    <ActivityType>${sar.activityType}</ActivityType>
    <ActivityDate>${sar.activityDate.toISOString()}</ActivityDate>
    <AmountInvolved currency="USD">${sar.amountInvolved}</AmountInvolved>
  </SuspiciousActivity>
  <Narrative>${this.escapeXML(sar.narrative)}</Narrative>
  <Subjects>
    ${sar.subjects.map(s => `
    <Subject>
      <SubjectId>${s.subjectId}</SubjectId>
      <Type>${s.type}</Type>
      <Name>${this.escapeXML(s.name)}</Name>
      <Role>${s.role}</Role>
    </Subject>
    `).join('')}
  </Subjects>
  <FilingStatus>${sar.status}</FilingStatus>
  <FilingDate>${sar.filingDate?.toISOString() || ''}</FilingDate>
</FincenSAR>`;

    return xml;
  }

  /**
   * Экспорт SAR в формате JSON
   */
  public exportToJSON(sarId: string): string {
    const sar = this.getSAR(sarId);

    if (!sar) {
      throw new Error(`SAR not found: ${sarId}`);
    }

    return JSON.stringify(sar, null, 2);
  }

  /**
   * Escape XML special characters
   */
  private escapeXML(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }

  /**
   * Остановка сервиса
   */
  public async destroy(): Promise<void> {
    logger.info('[SARReporting] Shutting down...');

    // Сохранение очереди (в production)
    // await this.saveQueue();

    this.sarQueue.clear();
    this.sarHistory = [];
    this.isInitialized = false;

    logger.info('[SARReporting] Destroyed');

    this.emit('destroyed');
  }

  /**
   * Получить статус сервиса
   */
  public getStatus(): {
    initialized: boolean;
    queueSize: number;
    historySize: number;
    jurisdiction: string;
  } {
    return {
      initialized: this.isInitialized,
      queueSize: this.sarQueue.size,
      historySize: this.sarHistory.length,
      jurisdiction: this.reportingConfig.jurisdiction
    };
  }
}

// Import для hash
import { createHash } from 'crypto';
