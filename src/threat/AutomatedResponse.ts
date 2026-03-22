/**
 * ============================================================================
 * AUTOMATED RESPONSE
 * Автоматизированное реагирование на инциденты с использованием playbooks
 * ============================================================================
 */

import {
  ResponsePlaybook,
  TriggerCondition,
  ResponseStep,
  NotificationConfig,
  ApprovalConfig,
  PlaybookExecution,
  StepResult,
  ApprovalResult,
  SecurityAlert,
  ThreatSeverity,
  ThreatCategory,
  AttackType
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Конфигурация Automated Response
 */
interface AutomatedResponseConfig {
  enabled: boolean;
  requireApprovalFor: ThreatSeverity[];
  maxConcurrentPlaybooks: number;
  defaultTimeout: number;  // секунд
  dryRunMode: boolean;  // Режим тестирования без реальных действий
  webhookUrl?: string;
}

/**
 * Контекст выполнения playbook
 */
interface PlaybookContext {
  alertId: string;
  alert: SecurityAlert;
  variables: Map<string, any>;
  currentStep: number;
  startTime: Date;
}

/**
 * Результат выполнения действия
 */
interface ActionResult {
  success: boolean;
  output?: any;
  error?: string;
  duration: number;
}

/**
 * ============================================================================
 * AUTOMATED RESPONSE SERVICE
 * ============================================================================
 */
export class AutomatedResponseService {
  private config: AutomatedResponseConfig;
  
  // Playbooks
  private playbooks: Map<string, ResponsePlaybook> = new Map();
  
  // Активные выполнения
  private activeExecutions: Map<string, PlaybookExecution> = new Map();
  
  // История выполнений
  private executionHistory: PlaybookExecution[] = [];
  private maxHistorySize: number = 1000;
  
  // Утверждения
  private pendingApprovals: Map<string, ApprovalResult> = new Map();
  
  // Статистика
  private statistics: AutomatedResponseStatistics = {
    totalExecutions: 0,
    successfulExecutions: 0,
    failedExecutions: 0,
    pendingApprovals: 0,
    averageExecutionTime: 0,
    actionsByType: new Map(),
    lastUpdated: new Date()
  };

  constructor(config?: Partial<AutomatedResponseConfig>) {
    this.config = {
      enabled: config?.enabled ?? true,
      requireApprovalFor: config?.requireApprovalFor || [ThreatSeverity.CRITICAL],
      maxConcurrentPlaybooks: config?.maxConcurrentPlaybooks || 10,
      defaultTimeout: config?.defaultTimeout || 300,
      dryRunMode: config?.dryRunMode ?? false
    };
    
    this.initializePlaybooks();
    
    console.log('[AutomatedResponse] Инициализация завершена');
    console.log(`[AutomatedResponse] Dry Run Mode: ${this.config.dryRunMode}`);
    console.log(`[AutomatedResponse] Max Concurrent Playbooks: ${this.config.maxConcurrentPlaybooks}`);
  }

  // ============================================================================
  // ИНИЦИАЛИЗАЦИЯ PLAYBOOKS
  // ============================================================================

  /**
   * Инициализация встроенных playbooks
   */
  private initializePlaybooks(): void {
    // Playbook: Изоляция хоста
    this.addPlaybook({
      id: 'RESPONSE-001',
      name: 'Изоляция Хоста',
      description: 'Автоматическая изоляция скомпрометированного хоста от сети',
      enabled: true,
      triggerConditions: [
        {
          field: 'severity',
          operator: 'eq',
          value: ThreatSeverity.CRITICAL
        },
        {
          field: 'attackType',
          operator: 'in',
          value: [AttackType.RANSOMWARE, AttackType.MALWARE]
        }
      ],
      severity: ThreatSeverity.CRITICAL,
      categories: [ThreatCategory.IMPACT, ThreatCategory.MALWARE],
      attackTypes: [AttackType.RANSOMWARE, AttackType.MALWARE],
      steps: [
        {
          order: 1,
          id: 'step-1',
          name: 'Создание снимка системы',
          type: 'api_call',
          action: 'create_snapshot',
          parameters: {
            provider: 'hypervisor',
            includeMemory: true
          },
          timeout: 120,
          retryCount: 3,
          retryDelay: 10,
          onError: 'continue'
        },
        {
          order: 2,
          id: 'step-2',
          name: 'Отключение сетевого адаптера',
          type: 'api_call',
          action: 'disable_network',
          parameters: {
            adapter: 'all'
          },
          timeout: 30,
          retryCount: 3,
          retryDelay: 5,
          onError: 'abort'
        },
        {
          order: 3,
          id: 'step-3',
          name: 'Блокировка учетной записи',
          type: 'api_call',
          action: 'disable_account',
          parameters: {
            account: '${alert.entities[0].name}'
          },
          timeout: 30,
          retryCount: 2,
          retryDelay: 5,
          onError: 'continue'
        },
        {
          order: 4,
          id: 'step-4',
          name: 'Уведомление SOC',
          type: 'notification',
          action: 'send_notification',
          parameters: {
            channel: 'slack',
            template: 'host_isolated',
            recipients: ['soc-team']
          },
          timeout: 30,
          retryCount: 3,
          retryDelay: 5,
          onError: 'continue'
        }
      ],
      rollbackSteps: [
        {
          order: 1,
          id: 'rollback-1',
          name: 'Восстановление сети',
          type: 'api_call',
          action: 'enable_network',
          parameters: {},
          timeout: 30,
          retryCount: 3,
          retryDelay: 5,
          onError: 'continue'
        }
      ],
      notifications: [
        {
          channel: 'slack',
          recipients: ['soc-team'],
          template: 'host_isolation_complete',
          severity: ThreatSeverity.CRITICAL,
          throttleMinutes: 5
        }
      ],
      approvals: [],
      tags: ['isolation', 'containment', 'ransomware'],
      version: '1.0',
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    // Playbook: Блокировка индикаторов
    this.addPlaybook({
      id: 'RESPONSE-002',
      name: 'Блокировка Индикаторов',
      description: 'Автоматическая блокировка IOC в защитных системах',
      enabled: true,
      triggerConditions: [
        {
          field: 'severity',
          operator: 'gte',
          value: ThreatSeverity.HIGH
        }
      ],
      severity: ThreatSeverity.HIGH,
      categories: [ThreatCategory.MALWARE, ThreatCategory.C2_COMMUNICATION],
      attackTypes: [AttackType.MALWARE, AttackType.C2_COMMUNICATION],
      steps: [
        {
          order: 1,
          id: 'step-1',
          name: 'Блокировка IP адресов',
          type: 'api_call',
          action: 'block_ip',
          parameters: {
            firewall: 'primary',
            ips: '${alert.entities[?].value}'
          },
          timeout: 60,
          retryCount: 3,
          retryDelay: 10,
          onError: 'continue'
        },
        {
          order: 2,
          id: 'step-2',
          name: 'Блокировка доменов',
          type: 'api_call',
          action: 'block_domain',
          parameters: {
            dns: 'internal',
            domains: '${alert.evidence[?].domain}'
          },
          timeout: 60,
          retryCount: 3,
          retryDelay: 10,
          onError: 'continue'
        },
        {
          order: 3,
          id: 'step-3',
          name: 'Блокировка хешей файлов',
          type: 'api_call',
          action: 'block_hash',
          parameters: {
            edr: 'primary',
            hashes: '${alert.evidence[?].hash}'
          },
          timeout: 60,
          retryCount: 3,
          retryDelay: 10,
          onError: 'continue'
        },
        {
          order: 4,
          id: 'step-4',
          name: 'Обновление threat intelligence',
          type: 'api_call',
          action: 'update_ti',
          parameters: {
            platform: 'ti-platform',
            indicators: '${alert}'
          },
          timeout: 120,
          retryCount: 2,
          retryDelay: 30,
          onError: 'continue'
        }
      ],
      rollbackSteps: [
        {
          order: 1,
          id: 'rollback-1',
          name: 'Разблокировка индикаторов',
          type: 'api_call',
          action: 'unblock_indicators',
          parameters: {},
          timeout: 60,
          retryCount: 3,
          retryDelay: 10,
          onError: 'continue'
        }
      ],
      notifications: [
        {
          channel: 'email',
          recipients: ['security-team@company.com'],
          template: 'indicators_blocked',
          severity: ThreatSeverity.HIGH,
          throttleMinutes: 15
        }
      ],
      approvals: [],
      tags: ['blocking', 'ioc', 'containment'],
      version: '1.0',
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    // Playbook: Сброс учетных данных
    this.addPlaybook({
      id: 'RESPONSE-003',
      name: 'Сброс Учетных Данных',
      description: 'Принудительный сброс паролей скомпрометированных учетных записей',
      enabled: true,
      triggerConditions: [
        {
          field: 'attackType',
          operator: 'eq',
          value: AttackType.BRUTE_FORCE
        },
        {
          riskScoreMin: 70
        }
      ],
      severity: ThreatSeverity.HIGH,
      categories: [ThreatCategory.CREDENTIAL_ACCESS],
      attackTypes: [AttackType.BRUTE_FORCE],
      steps: [
        {
          order: 1,
          id: 'step-1',
          name: 'Определение скомпрометированных учеток',
          type: 'script',
          action: 'identify_compromised_accounts',
          parameters: {
            source: '${alert.entities}',
            lookback: '24h'
          },
          timeout: 120,
          retryCount: 2,
          retryDelay: 30,
          onError: 'abort'
        },
        {
          order: 2,
          id: 'step-2',
          name: 'Принудительный сброс пароля',
          type: 'api_call',
          action: 'force_password_reset',
          parameters: {
            accounts: '${step-1.output.accounts}',
            notifyUser: true
          },
          timeout: 60,
          retryCount: 3,
          retryDelay: 10,
          onError: 'continue'
        },
        {
          order: 3,
          id: 'step-3',
          name: 'Блокировка сессий',
          type: 'api_call',
          action: 'revoke_sessions',
          parameters: {
            accounts: '${step-1.output.accounts}'
          },
          timeout: 60,
          retryCount: 3,
          retryDelay: 10,
          onError: 'continue'
        },
        {
          order: 4,
          id: 'step-4',
          name: 'Уведомление пользователей',
          type: 'notification',
          action: 'send_notification',
          parameters: {
            channel: 'email',
            template: 'password_reset_required',
            recipients: '${step-1.output.user_emails}'
          },
          timeout: 60,
          retryCount: 3,
          retryDelay: 10,
          onError: 'continue'
        }
      ],
      rollbackSteps: [],
      notifications: [
        {
          channel: 'pagerduty',
          recipients: ['security-oncall'],
          template: 'credentials_compromised',
          severity: ThreatSeverity.HIGH,
          throttleMinutes: 30
        }
      ],
      approvals: [
        {
          id: 'approval-1',
          name: 'Подтверждение сброса паролей',
          approvers: ['security-lead', 'it-manager'],
          approvalType: 'any',
          timeout: 15,
          escalationPolicy: 'security-director'
        }
      ],
      tags: ['credentials', 'password-reset', 'containment'],
      version: '1.0',
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    // Playbook: Сбор артефактов
    this.addPlaybook({
      id: 'RESPONSE-004',
      name: 'Сбор Артефактов',
      description: 'Автоматический сбор форензических артефактов',
      enabled: true,
      triggerConditions: [
        {
          field: 'severity',
          operator: 'in',
          value: [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]
        }
      ],
      severity: ThreatSeverity.HIGH,
      categories: [],
      attackTypes: [],
      steps: [
        {
          order: 1,
          id: 'step-1',
          name: 'Сбор памяти',
          type: 'command',
          action: 'collect_memory',
          parameters: {
            tool: 'winpmem',
            destination: 'forensics-server'
          },
          timeout: 300,
          retryCount: 2,
          retryDelay: 30,
          onError: 'continue'
        },
        {
          order: 2,
          id: 'step-2',
          name: 'Сбор логов',
          type: 'command',
          action: 'collect_logs',
          parameters: {
            sources: ['eventlog', 'syslog', 'application'],
            destination: 'forensics-server'
          },
          timeout: 300,
          retryCount: 2,
          retryDelay: 30,
          onError: 'continue'
        },
        {
          order: 3,
          id: 'step-3',
          name: 'Сбор сетевых подключений',
          type: 'command',
          action: 'collect_network',
          parameters: {
            tool: 'netstat',
            destination: 'forensics-server'
          },
          timeout: 60,
          retryCount: 2,
          retryDelay: 10,
          onError: 'continue'
        },
        {
          order: 4,
          id: 'step-4',
          name: 'Создание timeline',
          type: 'script',
          action: 'create_timeline',
          parameters: {
            artifacts: '${step-1.output} ${step-2.output} ${step-3.output}',
            format: 'bodyfile'
          },
          timeout: 600,
          retryCount: 1,
          retryDelay: 0,
          onError: 'continue'
        }
      ],
      rollbackSteps: [],
      notifications: [
        {
          channel: 'slack',
          recipients: ['forensics-team'],
          template: 'artifacts_collected',
          severity: ThreatSeverity.HIGH,
          throttleMinutes: 60
        }
      ],
      approvals: [],
      tags: ['forensics', 'artifacts', 'collection'],
      version: '1.0',
      createdAt: new Date(),
      updatedAt: new Date()
    });
  }

  // ============================================================================
  // УПРАВЛЕНИЕ PLAYBOOKS
  // ============================================================================

  /**
   * Добавление playbook
   */
  addPlaybook(playbook: ResponsePlaybook): void {
    this.playbooks.set(playbook.id, playbook);
  }

  /**
   * Удаление playbook
   */
  removePlaybook(playbookId: string): void {
    this.playbooks.delete(playbookId);
  }

  /**
   * Получение playbook по ID
   */
  getPlaybook(playbookId: string): ResponsePlaybook | undefined {
    return this.playbooks.get(playbookId);
  }

  /**
   * Получение всех playbooks
   */
  getAllPlaybooks(): ResponsePlaybook[] {
    return Array.from(this.playbooks.values());
  }

  /**
   * Включение/выключение playbook
   */
  togglePlaybook(playbookId: string, enabled: boolean): void {
    const playbook = this.playbooks.get(playbookId);
    
    if (playbook) {
      playbook.enabled = enabled;
      this.playbooks.set(playbookId, playbook);
    }
  }

  // ============================================================================
  // АВТОМАТИЧЕСКОЕ ВЫПОЛНЕНИЕ
  // ============================================================================

  /**
   * Проверка алерта на соответствие триггерам
   */
  async evaluateAlert(alert: SecurityAlert): Promise<PlaybookExecution[]> {
    if (!this.config.enabled) {
      return [];
    }
    
    const executions: PlaybookExecution[] = [];
    
    // Проверка лимита concurrent executions
    if (this.activeExecutions.size >= this.config.maxConcurrentPlaybooks) {
      console.warn('[AutomatedResponse] Достигнут лимит concurrent playbooks');
      return executions;
    }
    
    // Поиск подходящих playbooks
    for (const playbook of this.playbooks.values()) {
      if (!playbook.enabled) {
        continue;
      }
      
      if (this.matchesTriggerConditions(alert, playbook.triggerConditions)) {
        // Проверка необходимости approval
        const requiresApproval = this.requiresApproval(alert.severity, playbook.approvals);
        
        if (requiresApproval && !this.config.dryRunMode) {
          // Создание pending approval
          await this.createApproval(alert, playbook);
        } else {
          // Немедленное выполнение
          const execution = await this.executePlaybook(playbook.id, alert);
          executions.push(execution);
        }
      }
    }
    
    return executions;
  }

  /**
   * Проверка соответствия условиям триггера
   */
  private matchesTriggerConditions(
    alert: SecurityAlert,
    conditions: TriggerCondition[]
  ): boolean {
    for (const condition of conditions) {
      const alertValue = this.getAlertFieldValue(alert, condition.field);
      
      if (!this.evaluateCondition(alertValue, condition)) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Получение значения поля из алерта
   */
  private getAlertFieldValue(alert: SecurityAlert, field: string): any {
    const parts = field.split('.');
    let value: any = alert;
    
    for (const part of parts) {
      if (value === null || value === undefined) {
        return undefined;
      }
      value = (value as any)[part];
    }
    
    return value;
  }

  /**
   * Оценка условия
   */
  private evaluateCondition(value: any, condition: TriggerCondition): boolean {
    switch (condition.operator) {
      case 'eq':
        return value === condition.value;
      case 'gte':
        return value >= (condition.value || condition.riskScoreMin);
      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(value);
      default:
        return false;
    }
  }

  /**
   * Проверка необходимости approval
   */
  private requiresApproval(
    severity: ThreatSeverity,
    approvals: ApprovalConfig[]
  ): boolean {
    if (this.config.requireApprovalFor.includes(severity)) {
      return true;
    }
    
    return approvals.length > 0;
  }

  // ============================================================================
  // ВЫПОЛНЕНИЕ PLAYBOOK
  // ============================================================================

  /**
   * Выполнение playbook
   */
  async executePlaybook(playbookId: string, alert: SecurityAlert): Promise<PlaybookExecution> {
    const playbook = this.playbooks.get(playbookId);
    
    if (!playbook) {
      throw new Error(`Playbook ${playbookId} не найден`);
    }
    
    const execution: PlaybookExecution = {
      id: uuidv4(),
      playbookId,
      alertId: alert.id,
      status: 'running',
      startedAt: new Date(),
      currentStep: 0,
      stepsResults: [],
      approvals: [],
      error: undefined,
      rolledBackSteps: []
    };
    
    this.activeExecutions.set(execution.id, execution);
    this.statistics.totalExecutions++;
    
    try {
      // Создание контекста
      const context: PlaybookContext = {
        alertId: alert.id,
        alert,
        variables: new Map(),
        currentStep: 0,
        startTime: new Date()
      };
      
      // Выполнение шагов
      for (const step of playbook.steps) {
        execution.currentStep = step.order;
        
        const stepResult = await this.executeStep(step, context, playbook);
        execution.stepsResults.push(stepResult);
        
        // Проверка результата
        if (stepResult.status === 'failed' && step.onError === 'abort') {
          execution.status = 'failed';
          execution.error = stepResult.error;
          break;
        }
        
        // Проверка необходимости approval
        if (step.requiresApproval && step.approvalId) {
          const approval = await this.waitForApproval(step.approvalId);
          execution.approvals.push(approval);
          
          if (approval.status === 'rejected') {
            execution.status = 'failed';
            execution.error = 'Approval rejected';
            break;
          }
        }
      }
      
      // Успешное завершение
      if (execution.status !== 'failed') {
        execution.status = 'completed';
        execution.completedAt = new Date();
        this.statistics.successfulExecutions++;
      }
      
    } catch (error) {
      execution.status = 'failed';
      execution.error = (error as Error).message;
      this.statistics.failedExecutions++;
      
      // Выполнение rollback
      await this.executeRollback(execution, playbook);
    }
    
    // Обновление статистики
    this.updateStatistics(execution);
    
    // Перемещение в историю
    this.activeExecutions.delete(execution.id);
    this.executionHistory.push(execution);
    
    if (this.executionHistory.length > this.maxHistorySize) {
      this.executionHistory.shift();
    }
    
    return execution;
  }

  /**
   * Выполнение шага
   */
  private async executeStep(
    step: ResponseStep,
    context: PlaybookContext,
    playbook: ResponsePlaybook
  ): Promise<StepResult> {
    const stepResult: StepResult = {
      stepId: step.id,
      order: step.order,
      status: 'running',
      startedAt: new Date()
    };
    
    try {
      // Проверка условия выполнения
      if (step.condition && !this.evaluateConditionString(step.condition, context)) {
        stepResult.status = 'skipped';
        stepResult.completedAt = new Date();
        return stepResult;
      }
      
      let actionResult: ActionResult;
      
      // Выполнение действия в зависимости от типа
      switch (step.type) {
        case 'api_call':
          actionResult = await this.executeApiCall(step, context);
          break;
        case 'script':
          actionResult = await this.executeScript(step, context);
          break;
        case 'command':
          actionResult = await this.executeCommand(step, context);
          break;
        case 'notification':
          actionResult = await this.executeNotification(step, context);
          break;
        case 'wait':
          actionResult = await this.executeWait(step);
          break;
        default:
          throw new Error(`Неизвестный тип шага: ${step.type}`);
      }
      
      stepResult.status = actionResult.success ? 'completed' : 'failed';
      stepResult.result = actionResult.output;
      stepResult.error = actionResult.error;
      stepResult.completedAt = new Date();
      
      // Сохранение результата в контекст
      context.variables.set(`step-${step.id}.output`, actionResult.output);
      
    } catch (error) {
      stepResult.status = 'failed';
      stepResult.error = (error as Error).message;
      stepResult.completedAt = new Date();
    }
    
    return stepResult;
  }

  /**
   * Выполнение API вызова
   */
  private async executeApiCall(step: ResponseStep, context: PlaybookContext): Promise<ActionResult> {
    const startTime = Date.now();
    
    if (this.config.dryRunMode) {
      return {
        success: true,
        output: { dryRun: true },
        duration: 0
      };
    }
    
    try {
      // В реальной реализации здесь был бы вызов API
      // Для демонстрации возвращаем mock результат
      
      console.log(`[AutomatedResponse] API Call: ${step.action}`, step.parameters);
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return {
        success: true,
        output: { executed: true, action: step.action },
        duration: Date.now() - startTime
      };
    } catch (error) {
      return {
        success: false,
        error: (error as Error).message,
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Выполнение скрипта
   */
  private async executeScript(step: ResponseStep, context: PlaybookContext): Promise<ActionResult> {
    const startTime = Date.now();
    
    if (this.config.dryRunMode) {
      return {
        success: true,
        output: { dryRun: true },
        duration: 0
      };
    }
    
    try {
      // В реальной реализации здесь был бы вызов скрипта
      console.log(`[AutomatedResponse] Script: ${step.action}`, step.parameters);
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return {
        success: true,
        output: { executed: true, action: step.action },
        duration: Date.now() - startTime
      };
    } catch (error) {
      return {
        success: false,
        error: (error as Error).message,
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Выполнение команды
   */
  private async executeCommand(step: ResponseStep, context: PlaybookContext): Promise<ActionResult> {
    const startTime = Date.now();
    
    if (this.config.dryRunMode) {
      return {
        success: true,
        output: { dryRun: true },
        duration: 0
      };
    }
    
    try {
      // В реальной реализации здесь был бы вызов команды
      console.log(`[AutomatedResponse] Command: ${step.action}`, step.parameters);
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return {
        success: true,
        output: { executed: true, action: step.action },
        duration: Date.now() - startTime
      };
    } catch (error) {
      return {
        success: false,
        error: (error as Error).message,
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Выполнение уведомления
   */
  private async executeNotification(step: ResponseStep, context: PlaybookContext): Promise<ActionResult> {
    const startTime = Date.now();
    
    if (this.config.dryRunMode) {
      return {
        success: true,
        output: { dryRun: true },
        duration: 0
      };
    }
    
    try {
      // В реальной реализации здесь была бы отправка уведомления
      console.log(`[AutomatedResponse] Notification: ${step.parameters.channel}`, step.parameters.recipients);
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return {
        success: true,
        output: { sent: true },
        duration: Date.now() - startTime
      };
    } catch (error) {
      return {
        success: false,
        error: (error as Error).message,
        duration: Date.now() - startTime
      };
    }
  }

  /**
   * Выполнение ожидания
   */
  private async executeWait(step: ResponseStep): Promise<ActionResult> {
    const startTime = Date.now();
    const waitTime = (step.parameters?.seconds as number) || 10;
    
    await new Promise(resolve => setTimeout(resolve, waitTime * 1000));
    
    return {
      success: true,
      output: { waited: waitTime },
      duration: Date.now() - startTime
    };
  }

  /**
   * Оценка строкового условия
   */
  private evaluateConditionString(condition: string, context: PlaybookContext): boolean {
    // В реальной реализации здесь был бы парсинг и оценка условия
    return true;
  }

  // ============================================================================
  // ROLLBACK
  // ============================================================================

  /**
   * Выполнение rollback
   */
  private async executeRollback(execution: PlaybookExecution, playbook: ResponsePlaybook): Promise<void> {
    if (playbook.rollbackSteps.length === 0) {
      return;
    }
    
    console.log(`[AutomatedResponse] Выполнение rollback для ${execution.id}`);
    
    execution.status = 'rolled_back';
    
    const context: PlaybookContext = {
      alertId: execution.alertId,
      alert: {} as SecurityAlert,
      variables: new Map(),
      currentStep: 0,
      startTime: new Date()
    };
    
    for (const step of playbook.rollbackSteps) {
      const stepResult = await this.executeStep(step, context, playbook);
      execution.rolledBackSteps.push(step.order);
      
      if (stepResult.status === 'failed') {
        console.error(`[AutomatedResponse] Rollback step ${step.id} failed: ${stepResult.error}`);
      }
    }
  }

  // ============================================================================
  // APPROVALS
  // ============================================================================

  /**
   * Создание approval
   */
  private async createApproval(alert: SecurityAlert, playbook: ResponsePlaybook): Promise<void> {
    for (const approvalConfig of playbook.approvals) {
      const approval: ApprovalResult = {
        approvalId: approvalConfig.id,
        status: 'pending',
        approvers: approvalConfig.approvers.map(a => ({
          approver: a,
          decision: 'approved',
          timestamp: new Date()
        })),
        completedAt: undefined
      };
      
      this.pendingApprovals.set(approvalConfig.id, approval);
      this.statistics.pendingApprovals++;
      
      // Отправка уведомлений аппруверам
      await this.notifyApprovers(approvalConfig, alert);
    }
  }

  /**
   * Уведомление аппруверов
   */
  private async notifyApprovers(config: ApprovalConfig, alert: SecurityAlert): Promise<void> {
    console.log(`[AutomatedResponse] Уведомление аппруверов: ${config.approvers.join(', ')}`);
    
    // В реальной реализации здесь была бы отправка уведомлений
  }

  /**
   * Ожидание approval
   */
  private async waitForApproval(approvalId: string): Promise<ApprovalResult> {
    // В реальной реализации здесь было бы ожидание ответа
    return {
      approvalId,
      status: 'approved',
      approvers: [],
      completedAt: new Date()
    };
  }

  /**
   * Ответ на approval
   */
  async respondToApproval(
    approvalId: string,
    approver: string,
    decision: 'approved' | 'rejected',
    comment?: string
  ): Promise<void> {
    const approval = this.pendingApprovals.get(approvalId);
    
    if (!approval) {
      throw new Error(`Approval ${approvalId} не найден`);
    }
    
    const approverResponse = approval.approvers.find(a => a.approver === approver);
    
    if (approverResponse) {
      approverResponse.decision = decision;
      approverResponse.timestamp = new Date();
      approverResponse.comment = comment;
    }
    
    // Проверка завершения approval
    this.checkApprovalComplete(approval);
  }

  /**
   * Проверка завершения approval
   */
  private checkApprovalComplete(approval: ApprovalResult): void {
    // В реальной реализации здесь была бы логика проверки
    approval.status = 'approved';
    approval.completedAt = new Date();
    this.pendingApprovals.delete(approval.approvalId);
    this.statistics.pendingApprovals--;
  }

  // ============================================================================
  // СТАТИСТИКА
  // ============================================================================

  /**
   * Обновление статистики
   */
  private updateStatistics(execution: PlaybookExecution): void {
    const duration = (execution.completedAt?.getTime() || Date.now()) - execution.startedAt.getTime();
    
    this.statistics.averageExecutionTime = 
      (this.statistics.averageExecutionTime * (this.statistics.totalExecutions - 1) + duration) / 
      this.statistics.totalExecutions;
    
    // Подсчет действий по типам
    for (const stepResult of execution.stepsResults) {
      // В реальной реализации здесь был бы подсчет
    }
    
    this.statistics.lastUpdated = new Date();
  }

  /**
   * Получение статистики
   */
  getStatistics(): AutomatedResponseStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }

  /**
   * Получение активных выполнений
   */
  getActiveExecutions(): PlaybookExecution[] {
    return Array.from(this.activeExecutions.values());
  }

  /**
   * Получение истории выполнений
   */
  getExecutionHistory(limit: number = 50): PlaybookExecution[] {
    return this.executionHistory.slice(-limit);
  }

  /**
   * Получение pending approvals
   */
  getPendingApprovals(): ApprovalResult[] {
    return Array.from(this.pendingApprovals.values());
  }

  /**
   * Включение/выключение dry run mode
   */
  setDryRunMode(enabled: boolean): void {
    this.config.dryRunMode = enabled;
    console.log(`[AutomatedResponse] Dry Run Mode: ${enabled}`);
  }
}

/**
 * Статистика Automated Response
 */
interface AutomatedResponseStatistics {
  totalExecutions: number;
  successfulExecutions: number;
  failedExecutions: number;
  pendingApprovals: number;
  averageExecutionTime: number;
  actionsByType: Map<string, number>;
  lastUpdated: Date;
}

/**
 * Экспорт основного класса
 */
export { AutomatedResponseService };
