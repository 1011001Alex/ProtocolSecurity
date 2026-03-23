/**
 * ============================================================================
 * PLAYBOOK ENGINE
 * ============================================================================
 * Движок выполнения playbook для автоматизированного реагирования на инциденты
 * Реализует оркестрацию шагов, управление состоянием, rollback и интеграции
 * Соответствует NIST SP 800-61 и SANS Incident Response Methodology
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import {
  PlaybookConfiguration,
  PlaybookExecution,
  PlaybookStep,
  PlaybookStepStatus,
  PlaybookStepResult,
  PlaybookCondition,
  ConditionType,
  ConditionOperator,
  PlaybookStatusChange,
  PlaybookArtifact,
  Incident,
  IncidentSeverity,
  PlaybookActionType,
  PlaybookStepCategory
} from '../types/incident.types';
import { IncidentClassifier } from './IncidentClassifier';

/**
 * События движка playbook
 */
export enum PlaybookEngineEvent {
  /** Playbook запущен */
  PLAYBOOK_STARTED = 'playbook_started',
  /** Шаг начал выполнение */
  STEP_STARTED = 'step_started',
  /** Шаг завершен */
  STEP_COMPLETED = 'step_completed',
  /** Шаг провален */
  STEP_FAILED = 'step_failed',
  /** Шаг пропущен */
  STEP_SKIPPED = 'step_skipped',
  /** Playbook завершен */
  PLAYBOOK_COMPLETED = 'playbook_completed',
  /** Playbook провален */
  PLAYBOOK_FAILED = 'playbook_failed',
  /** Playbook поставлен на паузу */
  PLAYBOOK_PAUSED = 'playbook_paused',
  /** Playbook возобновлен */
  PLAYBOOK_RESUMED = 'playbook_resumed',
  /** Выполнен rollback */
  ROLLBACK_EXECUTED = 'rollback_executed',
  /** Требуется одобрение */
  APPROVAL_REQUIRED = 'approval_required',
  /** Ошибка движка */
  ERROR = 'error'
}

/**
 * Контекст выполнения playbook
 */
export interface PlaybookExecutionContext {
  /** Инцидент */
  incident: Incident;
  /** Переменные playbook */
  variables: Record<string, unknown>;
  /** Результаты выполненных шагов */
  stepResults: Map<string, PlaybookStepResult>;
  /** Артефакты */
  artifacts: PlaybookArtifact[];
  /** История выполнения */
  executionHistory: ExecutionHistoryEntry[];
  /** Время начала */
  startedAt: Date;
  /** Кто инициировал */
  initiatedBy: string;
}

/**
 * Запись истории выполнения
 */
export interface ExecutionHistoryEntry {
  /** Идентификатор шага */
  stepId: string;
  /** Действие */
  action: 'started' | 'completed' | 'failed' | 'skipped' | 'retried';
  /** Время */
  timestamp: Date;
  /** Результат */
  result?: PlaybookStepResult;
  /** Ошибка */
  error?: string;
}

/**
 * Конфигурация движка playbook
 */
export interface PlaybookEngineConfig {
  /** Таймаут шага по умолчанию (мс) */
  defaultStepTimeout: number;
  /** Количество попыток по умолчанию */
  defaultRetryCount: number;
  /** Интервал между попытками (мс) */
  defaultRetryInterval: number;
  /** Параллельное выполнение шагов */
  allowParallelSteps: boolean;
  /** Максимальное количество параллельных шагов */
  maxParallelSteps: number;
  /** Автоматический rollback при ошибке */
  autoRollbackOnError: boolean;
  /** Требует одобрения для критических действий */
  requiresApprovalForCritical: boolean;
  /** Логирование выполнения */
  enableLogging: boolean;
  /** Отладочный режим */
  debugMode: boolean;
}

/**
 * Обработчик действия playbook
 */
export interface PlaybookActionHandler {
  /** Тип действия */
  actionType: PlaybookActionType;
  /** Обработчик */
  handler: (step: PlaybookStep, context: PlaybookExecutionContext) => Promise<PlaybookStepResult>;
}

/**
 * Движок выполнения playbook
 * Реализует:
 * - Последовательное и параллельное выполнение шагов
 * - Условное выполнение на основе условий
 * - Механизм retry при ошибках
 * - Rollback выполненных шагов
 * - Управление переменными и артефактами
 * - Событийную модель
 */
export class PlaybookEngine extends EventEmitter {
  /** Конфигурация движка */
  private config: PlaybookEngineConfig;

  /** Зарегистрированные обработчики действий */
  private actionHandlers: Map<PlaybookActionType, PlaybookActionHandler['handler']> = new Map();

  /** Активные выполнения playbook */
  private activeExecutions: Map<string, PlaybookExecution> = new Map();

  /** Классификатор для оценки инцидентов */
  private classifier: IncidentClassifier;

  /** Конструктор движка */
  constructor(config?: Partial<PlaybookEngineConfig>) {
    super();
    this.config = this.mergeConfigWithDefaults(config);
    this.classifier = new IncidentClassifier();
    this.registerDefaultHandlers();
  }

  /**
   * Объединение конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<PlaybookEngineConfig> | undefined): PlaybookEngineConfig {
    const defaultConfig: PlaybookEngineConfig = {
      defaultStepTimeout: 300000, // 5 минут
      defaultRetryCount: 3,
      defaultRetryInterval: 5000, // 5 секунд
      allowParallelSteps: true,
      maxParallelSteps: 5,
      autoRollbackOnError: false,
      requiresApprovalForCritical: true,
      enableLogging: true,
      debugMode: false
    };

    return { ...defaultConfig, ...config };
  }

  /**
   * Регистрация обработчиков действий по умолчанию
   */
  private registerDefaultHandlers(): void {
    // Обработчик сбора данных
    this.registerActionHandler(PlaybookActionType.COLLECT_DATA, async (step, context) => {
      return this.handleCollectData(step, context);
    });

    // Обработчик анализа данных
    this.registerActionHandler(PlaybookActionType.ANALYZE_DATA, async (step, context) => {
      return this.handleAnalyzeData(step, context);
    });

    // Обработчик блокировки IP
    this.registerActionHandler(PlaybookActionType.BLOCK_IP, async (step, context) => {
      return this.handleBlockIP(step, context);
    });

    // Обработчик блокировки домена
    this.registerActionHandler(PlaybookActionType.BLOCK_DOMAIN, async (step, context) => {
      return this.handleBlockDomain(step, context);
    });

    // Обработчик изоляции хоста
    this.registerActionHandler(PlaybookActionType.ISOLATE_HOST, async (step, context) => {
      return this.handleIsolateHost(step, context);
    });

    // Обработчик блокировки учетной записи
    this.registerActionHandler(PlaybookActionType.LOCK_ACCOUNT, async (step, context) => {
      return this.handleLockAccount(step, context);
    });

    // Обработчик отзыва токенов
    this.registerActionHandler(PlaybookActionType.REVOKE_TOKENS, async (step, context) => {
      return this.handleRevokeTokens(step, context);
    });

    // Обработчик уведомления
    this.registerActionHandler(PlaybookActionType.SEND_NOTIFICATION, async (step, context) => {
      return this.handleSendNotification(step, context);
    });

    // Обработчик создания тикета
    this.registerActionHandler(PlaybookActionType.CREATE_TICKET, async (step, context) => {
      return this.handleCreateTicket(step, context);
    });

    // Обработчик документирования
    this.registerActionHandler(PlaybookActionType.DOCUMENT, async (step, context) => {
      return this.handleDocument(step, context);
    });
  }

  /**
   * Регистрация обработчика действия
   */
  public registerActionHandler(
    actionType: PlaybookActionType,
    handler: (step: PlaybookStep, context: PlaybookExecutionContext) => Promise<PlaybookStepResult>
  ): void {
    this.actionHandlers.set(actionType, handler);
    this.log(`Зарегистрирован обработчик для действия: ${actionType}`);
  }

  /**
   * Запуск выполнения playbook
   */
  public async startPlaybook(
    configuration: PlaybookConfiguration,
    incident: Incident,
    initiatedBy: string
  ): Promise<PlaybookExecution> {
    this.log(`Запуск playbook: ${configuration.name} для инцидента: ${incident.id}`);

    // Валидация конфигурации
    this.validateConfiguration(configuration);

    // Проверка совместимости playbook с инцидентом
    this.validatePlaybookForIncident(configuration, incident);

    // Создание выполнения
    const execution: PlaybookExecution = {
      id: this.generateExecutionId(),
      incidentId: incident.id,
      configuration,
      currentStepId: undefined,
      completedSteps: [],
      allSteps: this.initializeSteps(configuration.steps),
      status: 'running',
      progress: 0,
      startedAt: new Date(),
      initiatedBy,
      artifacts: [],
      statusHistory: []
    };

    // Сохраняем выполнение
    this.activeExecutions.set(execution.id, execution);

    // Создаем контекст выполнения
    const context: PlaybookExecutionContext = {
      incident,
      variables: { ...configuration.variables },
      stepResults: new Map(),
      artifacts: [],
      executionHistory: [],
      startedAt: execution.startedAt,
      initiatedBy
    };

    // Событие запуска
    this.emit(PlaybookEngineEvent.PLAYBOOK_STARTED, { execution, context });

    // Запускаем выполнение шагов
    this.executePlaybookSteps(execution, context).catch(error => {
      this.log(`Ошибка выполнения playbook: ${error.message}`, 'error');
      this.failPlaybook(execution, error);
    });

    return execution;
  }

  /**
   * Инициализация шагов
   */
  private initializeSteps(steps: PlaybookStep[]): PlaybookStep[] {
    return steps.map(step => ({
      ...step,
      status: PlaybookStepStatus.PENDING,
      timeout: step.timeout || this.config.defaultStepTimeout,
      retryCount: step.retryCount ?? this.config.defaultRetryCount,
      retryInterval: step.retryInterval ?? this.config.defaultRetryInterval
    }));
  }

  /**
   * Валидация конфигурации playbook
   */
  private validateConfiguration(configuration: PlaybookConfiguration): void {
    if (!configuration.id || configuration.id.trim() === '') {
      throw new Error('Playbook должен иметь идентификатор');
    }

    if (!configuration.name || configuration.name.trim() === '') {
      throw new Error('Playbook должен иметь название');
    }

    if (!configuration.steps || configuration.steps.length === 0) {
      throw new Error('Playbook должен иметь хотя бы один шаг');
    }

    // Проверка на циклические зависимости
    this.checkForCyclicDependencies(configuration.steps);

    // Проверка существования зависимостей
    this.validateStepDependencies(configuration.steps);
  }

  /**
   * Проверка на циклические зависимости
   */
  private checkForCyclicDependencies(steps: PlaybookStep[]): void {
    const visited = new Set<string>();
    const recursionStack = new Set<string>();

    const hasCycle = (stepId: string): boolean => {
      if (recursionStack.has(stepId)) {
        return true;
      }
      if (visited.has(stepId)) {
        return false;
      }

      visited.add(stepId);
      recursionStack.add(stepId);

      const step = steps.find(s => s.id === stepId);
      if (step?.dependencies) {
        for (const depId of step.dependencies) {
          if (hasCycle(depId)) {
            return true;
          }
        }
      }

      recursionStack.delete(stepId);
      return false;
    };

    for (const step of steps) {
      if (hasCycle(step.id)) {
        throw new Error(`Обнаружена циклическая зависимость в шаге: ${step.id}`);
      }
    }
  }

  /**
   * Валидация зависимостей шагов
   */
  private validateStepDependencies(steps: PlaybookStep[]): void {
    const stepIds = new Set(steps.map(s => s.id));

    for (const step of steps) {
      if (step.dependencies) {
        for (const depId of step.dependencies) {
          if (!stepIds.has(depId)) {
            throw new Error(`Шаг ${step.id} зависит от несуществующего шага: ${depId}`);
          }
        }
      }
    }
  }

  /**
   * Проверка совместимости playbook с инцидентом
   */
  private validatePlaybookForIncident(configuration: PlaybookConfiguration, incident: Incident): void {
    // Проверка категории
    if (configuration.incidentCategory !== incident.category) {
      this.log(`Предупреждение: Playbook категории ${configuration.incidentCategory} используется для инцидента категории ${incident.category}`, 'warn');
    }

    // Проверка минимальной серьезности
    const severityOrder = [
      IncidentSeverity.INFORMATIONAL,
      IncidentSeverity.LOW,
      IncidentSeverity.MEDIUM,
      IncidentSeverity.HIGH,
      IncidentSeverity.CRITICAL
    ];

    const configSeverityIndex = severityOrder.indexOf(configuration.minSeverity);
    const incidentSeverityIndex = severityOrder.indexOf(incident.severity);

    if (incidentSeverityIndex < configSeverityIndex) {
      throw new Error(
        `Серьезность инцидента (${incident.severity}) ниже минимальной для playbook (${configuration.minSeverity})`
      );
    }
  }

  /**
   * Основное выполнение шагов playbook
   */
  private async executePlaybookSteps(
    execution: PlaybookExecution,
    context: PlaybookExecutionContext
  ): Promise<void> {
    const steps = execution.allSteps;

    // Определяем порядок выполнения с учетом зависимостей
    const executionOrder = this.topologicalSort(steps);

    this.log(`Порядок выполнения шагов: ${executionOrder.map(s => s.id).join(' -> ')}`);

    // Выполняем шаги в определенном порядке
    for (const step of executionOrder) {
      if (execution.status !== 'running') {
        this.log(`Выполнение playbook остановлено. Статус: ${execution.status}`);
        break;
      }

      // Проверяем условия выполнения
      if (!this.checkStepConditions(step, context)) {
        this.log(`Шаг ${step.id} пропущен: условия не выполнены`);
        this.skipStep(execution, step);
        continue;
      }

      // Проверяем зависимости
      if (!this.areDependenciesMet(step, execution)) {
        this.log(`Шаг ${step.id} пропущен: зависимости не выполнены`);
        this.skipStep(execution, step);
        continue;
      }

      // Проверяем, требуется ли одобрение
      if (step.requiresApproval && !this.config.debugMode) {
        this.log(`Шаг ${step.id} требует одобрения`);
        this.emit(PlaybookEngineEvent.APPROVAL_REQUIRED, { execution, step, context });
        // Ожидаем одобрения (в реальной системе здесь была бы пауза)
      }

      // Выполняем шаг
      await this.executeStep(execution, step, context);
    }

    // Завершаем playbook
    if (execution.status === 'running') {
      this.completePlaybook(execution, context);
    }
  }

  /**
   * Топологическая сортировка шагов
   */
  private topologicalSort(steps: PlaybookStep[]): PlaybookStep[] {
    const sorted: PlaybookStep[] = [];
    const visited = new Set<string>();
    const visiting = new Set<string>();

    const visit = (step: PlaybookStep): void => {
      if (visited.has(step.id)) {
        return;
      }

      if (visiting.has(step.id)) {
        throw new Error(`Циклическая зависимость обнаружена при сортировке: ${step.id}`);
      }

      visiting.add(step.id);

      // Сначала посещаем зависимости
      if (step.dependencies) {
        for (const depId of step.dependencies) {
          const depStep = steps.find(s => s.id === depId);
          if (depStep) {
            visit(depStep);
          }
        }
      }

      visiting.delete(step.id);
      visited.add(step.id);
      sorted.push(step);
    };

    for (const step of steps) {
      visit(step);
    }

    return sorted;
  }

  /**
   * Проверка условий шага
   */
  private checkStepConditions(step: PlaybookStep, context: PlaybookExecutionContext): boolean {
    if (!step.conditions || step.conditions.length === 0) {
      return true;
    }

    // Проверяем все условия
    const results = step.conditions.map(condition =>
      this.evaluateCondition(condition, context)
    );

    // Если есть логический оператор, применяем его
    const logicalOp = step.conditions[0]?.logicalOperator || 'AND';

    if (logicalOp === 'AND') {
      return results.every(r => r);
    } else {
      return results.some(r => r);
    }
  }

  /**
   * Вычисление условия
   */
  private evaluateCondition(condition: PlaybookCondition, context: PlaybookExecutionContext): boolean {
    const value = this.getConditionValue(condition, context);

    switch (condition.operator) {
      case ConditionOperator.EQUALS:
        return value === condition.value;

      case ConditionOperator.NOT_EQUALS:
        return value !== condition.value;

      case ConditionOperator.GREATER_THAN:
        return Number(value) > Number(condition.value);

      case ConditionOperator.LESS_THAN:
        return Number(value) < Number(condition.value);

      case ConditionOperator.CONTAINS:
        return String(value).includes(String(condition.value));

      case ConditionOperator.STARTS_WITH:
        return String(value).startsWith(String(condition.value));

      case ConditionOperator.ENDS_WITH:
        return String(value).endsWith(String(condition.value));

      case ConditionOperator.IN:
        return (condition.value as unknown[]).includes(value);

      case ConditionOperator.NOT_IN:
        return !(condition.value as unknown[]).includes(value);

      case ConditionOperator.EXISTS:
        return value !== undefined && value !== null;

      case ConditionOperator.NOT_EXISTS:
        return value === undefined || value === null;

      default:
        return false;
    }
  }

  /**
   * Получение значения для условия
   */
  private getConditionValue(condition: PlaybookCondition, context: PlaybookExecutionContext): unknown {
    switch (condition.type) {
      case ConditionType.FIELD_VALUE:
        // Получаем значение из контекста
        return this.getFieldValue(condition.field, context);

      case ConditionType.SEVERITY_LEVEL:
        return context.incident.severity;

      case ConditionType.INCIDENT_CATEGORY:
        return context.incident.category;

      case ConditionType.TIME_OF_DAY:
        return new Date().getHours();

      case ConditionType.DAY_OF_WEEK:
        return new Date().getDay();

      case ConditionType.CUSTOM_SCRIPT:
        // В реальной системе здесь было бы выполнение скрипта
        return true;

      default:
        return undefined;
    }
  }

  /**
   * Получение значения поля из контекста
   */
  private getFieldValue(field: string, context: PlaybookExecutionContext): unknown {
    const parts = field.split('.');
    let value: unknown = context;

    for (const part of parts) {
      if (value && typeof value === 'object') {
        value = (value as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Проверка выполнения зависимостей
   */
  private areDependenciesMet(step: PlaybookStep, execution: PlaybookExecution): boolean {
    if (!step.dependencies) {
      return true;
    }

    return step.dependencies.every(depId =>
      execution.completedSteps.includes(depId)
    );
  }

  /**
   * Выполнение отдельного шага
   */
  private async executeStep(
    execution: PlaybookExecution,
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<void> {
    this.log(`Выполнение шага: ${step.id} - ${step.name}`);

    execution.currentStepId = step.id;
    step.status = PlaybookStepStatus.IN_PROGRESS;
    step.startedAt = new Date();

    // Событие начала шага
    this.emit(PlaybookEngineEvent.STEP_STARTED, { execution, step, context });

    // Добавляем запись в историю
    context.executionHistory.push({
      stepId: step.id,
      action: 'started',
      timestamp: new Date()
    });

    let attempts = 0;
    let lastError: Error | undefined;

    while (attempts <= (step.retryCount || 0)) {
      try {
        attempts++;

        // Получаем обработчик действия
        const handler = this.actionHandlers.get(step.actionType);

        if (!handler) {
          throw new Error(`Обработчик для действия ${step.actionType} не найден`);
        }

        // Выполняем действие
        const result = await handler(step, context);

        // Сохраняем результат
        step.result = result;
        step.completedAt = new Date();

        if (result.success) {
          step.status = PlaybookStepStatus.COMPLETED;
          execution.completedSteps.push(step.id);
          context.stepResults.set(step.id, result);

          // Обновляем прогресс
          this.updateProgress(execution);

          // Событие успешного завершения
          this.emit(PlaybookEngineEvent.STEP_COMPLETED, { execution, step, context, result });

          this.log(`Шаг ${step.id} успешно выполнен за ${Date.now() - (step.startedAt?.getTime() || 0)}мс`);
          return;
        } else {
          // Действие вернуло failure
          throw new Error(result.message || 'Действие не выполнено');
        }
      } catch (error) {
        lastError = error as Error;
        this.log(`Попытка ${attempts} выполнения шага ${step.id} не удалась: ${error}`);

        // Добавляем запись в историю
        context.executionHistory.push({
          stepId: step.id,
          action: attempts <= (step.retryCount || 0) ? 'retried' : 'failed',
          timestamp: new Date(),
          error: (error as Error).message
        });

        if (attempts <= (step.retryCount || 0)) {
          // Ждем перед следующей попыткой
          await this.sleep(step.retryInterval || this.config.defaultRetryInterval);
        }
      }
    }

    // Все попытки исчерпаны
    step.status = PlaybookStepStatus.FAILED;
    step.completedAt = new Date();
    step.errors = [lastError?.message || 'Неизвестная ошибка'];

    // Событие ошибки
    this.emit(PlaybookEngineEvent.STEP_FAILED, { execution, step, context, error: lastError });

    this.log(`Шаг ${step.id} провален после ${attempts} попыток`);

    // Обработка ошибки
    await this.handleStepFailure(execution, step, context, lastError);
  }

  /**
   * Обработка ошибки шага
   */
  private async handleStepFailure(
    execution: PlaybookExecution,
    step: PlaybookStep,
    context: PlaybookExecutionContext,
    error?: Error
  ): Promise<void> {
    // Если включен автоматический rollback, откатываем выполненные шаги
    if (this.config.autoRollbackOnError && step.rollbackAction) {
      this.log(`Выполнение rollback для шага ${step.id}`);
      await this.executeRollback(execution, step, context);
    }

    // Если шаг критический, останавливаем playbook
    if (step.actionType === PlaybookActionType.ISOLATE_HOST ||
        step.actionType === PlaybookActionType.LOCK_ACCOUNT ||
        step.actionType === PlaybookActionType.BLOCK_IP) {
      this.log(`Критический шаг ${step.id} провален. Остановка playbook.`, 'error');
      this.failPlaybook(execution, error || new Error('Критический шаг провален'));
    }
  }

  /**
   * Выполнение rollback
   */
  private async executeRollback(
    execution: PlaybookExecution,
    failedStep: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<void> {
    if (!failedStep.rollbackAction) {
      this.log(`Rollback действие для шага ${failedStep.id} не определено`);
      return;
    }

    const rollbackStep = failedStep.rollbackAction;
    rollbackStep.status = PlaybookStepStatus.IN_PROGRESS;

    try {
      const handler = this.actionHandlers.get(rollbackStep.actionType);

      if (handler) {
        const result = await handler(rollbackStep, context);
        rollbackStep.result = result;
        rollbackStep.status = result.success
          ? PlaybookStepStatus.COMPLETED
          : PlaybookStepStatus.FAILED;
      }

      failedStep.status = PlaybookStepStatus.ROLLED_BACK;

      this.emit(PlaybookEngineEvent.ROLLBACK_EXECUTED, {
        execution,
        step: failedStep,
        rollbackStep
      });

      this.log(`Rollback для шага ${failedStep.id} выполнен`);
    } catch (error) {
      this.log(`Ошибка rollback для шага ${failedStep.id}: ${error}`, 'error');
    }
  }

  /**
   * Пропуск шага
   */
  private skipStep(execution: PlaybookExecution, step: PlaybookStep): void {
    step.status = PlaybookStepStatus.SKIPPED;
    step.completedAt = new Date();

    execution.completedSteps.push(step.id);
    this.updateProgress(execution);

    this.emit(PlaybookEngineEvent.STEP_SKIPPED, { execution, step });
  }

  /**
   * Обновление прогресса выполнения
   */
  private updateProgress(execution: PlaybookExecution): void {
    const totalSteps = execution.allSteps.length;
    const completedSteps = execution.completedSteps.length;
    execution.progress = Math.round((completedSteps / totalSteps) * 100);
  }

  /**
   * Завершение playbook
   */
  private completePlaybook(
    execution: PlaybookExecution,
    context: PlaybookExecutionContext
  ): void {
    execution.status = 'completed';
    execution.completedAt = new Date();
    execution.progress = 100;

    // Добавляем запись в историю статуса
    this.addStatusChange(execution, 'running', 'completed', 'Все шаги выполнены успешно');

    // Событие завершения
    this.emit(PlaybookEngineEvent.PLAYBOOK_COMPLETED, { execution, context });

    this.log(`Playbook ${execution.configuration.name} завершен успешно`);

    // Удаляем из активных
    this.activeExecutions.delete(execution.id);
  }

  /**
   * Провал playbook
   */
  private failPlaybook(execution: PlaybookExecution, error?: Error): void {
    execution.status = 'failed';
    execution.completedAt = new Date();

    if (error) {
      execution.errors = [...(execution.errors || []), error.message];
    }

    // Добавляем запись в историю статуса
    this.addStatusChange(execution, 'running', 'failed', error?.message || 'Неизвестная ошибка');

    // Событие провала
    this.emit(PlaybookEngineEvent.PLAYBOOK_FAILED, { execution, error });

    this.log(`Playbook ${execution.configuration.name} провален: ${error?.message}`, 'error');

    // Удаляем из активных
    this.activeExecutions.delete(execution.id);
  }

  /**
   * Добавление изменения статуса в историю
   */
  private addStatusChange(
    execution: PlaybookExecution,
    previousStatus: PlaybookExecution['status'],
    newStatus: PlaybookExecution['status'],
    reason?: string
  ): void {
    const change: PlaybookStatusChange = {
      previousStatus,
      newStatus,
      reason,
      changedBy: execution.initiatedBy,
      timestamp: new Date()
    };

    execution.statusHistory.push(change);
  }

  /**
   * Пауза выполнения playbook
   */
  public pausePlaybook(executionId: string): void {
    const execution = this.activeExecutions.get(executionId);

    if (!execution) {
      throw new Error(`Выполнение ${executionId} не найдено`);
    }

    if (execution.status !== 'running') {
      throw new Error(`Нельзя поставить на паузу playbook в статусе ${execution.status}`);
    }

    const previousStatus = execution.status;
    execution.status = 'paused';
    this.addStatusChange(execution, previousStatus, 'paused', 'Пауза пользователем');

    this.emit(PlaybookEngineEvent.PLAYBOOK_PAUSED, { execution });
    this.log(`Playbook ${executionId} поставлен на паузу`);
  }

  /**
   * Возобновление выполнения playbook
   */
  public async resumePlaybook(executionId: string): Promise<void> {
    const execution = this.activeExecutions.get(executionId);

    if (!execution) {
      throw new Error(`Выполнение ${executionId} не найдено`);
    }

    if (execution.status !== 'paused') {
      throw new Error(`Нельзя возобновить playbook в статусе ${execution.status}`);
    }

    const previousStatus = execution.status;
    execution.status = 'running';
    this.addStatusChange(execution, previousStatus, 'running', 'Возобновление пользователем');

    this.emit(PlaybookEngineEvent.PLAYBOOK_RESUMED, { execution });
    this.log(`Playbook ${executionId} возобновлен`);

    // Продолжаем выполнение
    const context: PlaybookExecutionContext = {
      incident: execution.configuration as unknown as Incident,
      variables: { ...execution.configuration.variables },
      stepResults: new Map(),
      artifacts: execution.artifacts,
      executionHistory: [],
      startedAt: execution.startedAt,
      initiatedBy: execution.initiatedBy
    };

    await this.executePlaybookSteps(execution, context);
  }

  /**
   * Получение статуса выполнения
   */
  public getExecutionStatus(executionId: string): PlaybookExecution | undefined {
    return this.activeExecutions.get(executionId);
  }

  /**
   * Получение всех активных выполнений
   */
  public getActiveExecutions(): PlaybookExecution[] {
    return Array.from(this.activeExecutions.values());
  }

  /**
   * Генерация идентификатора выполнения
   */
  private generateExecutionId(): string {
    return `pbe_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Утилита для задержки
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Логирование
   */
  private log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    if (this.config.enableLogging) {
      const timestamp = new Date().toISOString();
      const prefix = `[PlaybookEngine] [${timestamp}] [${level.toUpperCase()}]`;
      logger.info(`${prefix} ${message}`);
    }
  }

  // ============================================================================
  // ОБРАБОТЧИКИ ДЕЙСТВИЙ ПО УМОЛЧАНИЮ
  // ============================================================================

  /**
   * Обработчик сбора данных
   */
  private async handleCollectData(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const dataType = step.parameters?.dataType as string || 'logs';

    this.log(`Сбор данных типа: ${dataType}`);

    // Симуляция сбора данных
    await this.sleep(1000);

    return {
      success: true,
      message: `Данные типа ${dataType} успешно собраны`,
      output: {
        dataType,
        collectedAt: new Date(),
        recordCount: Math.floor(Math.random() * 1000)
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }

  /**
   * Обработчик анализа данных
   */
  private async handleAnalyzeData(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const analysisType = step.parameters?.analysisType as string || 'general';

    this.log(`Анализ данных типа: ${analysisType}`);

    // Симуляция анализа
    await this.sleep(1500);

    return {
      success: true,
      message: `Анализ ${analysisType} завершен`,
      output: {
        analysisType,
        findings: ['Найдено аномалий: 3', 'Подозрительная активность обнаружена'],
        riskScore: Math.floor(Math.random() * 100)
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }

  /**
   * Обработчик блокировки IP
   */
  private async handleBlockIP(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const ipAddress = step.parameters?.ipAddress as string;

    if (!ipAddress) {
      return {
        success: false,
        message: 'IP адрес не указан'
      };
    }

    this.log(`Блокировка IP адреса: ${ipAddress}`);

    // Симуляция блокировки
    await this.sleep(500);

    return {
      success: true,
      message: `IP адрес ${ipAddress} заблокирован`,
      output: {
        ipAddress,
        blockedAt: new Date(),
        blockDuration: 'permanent'
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }

  /**
   * Обработчик блокировки домена
   */
  private async handleBlockDomain(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const domain = step.parameters?.domain as string;

    if (!domain) {
      return {
        success: false,
        message: 'Домен не указан'
      };
    }

    this.log(`Блокировка домена: ${domain}`);

    // Симуляция блокировки
    await this.sleep(500);

    return {
      success: true,
      message: `Домен ${domain} заблокирован`,
      output: {
        domain,
        blockedAt: new Date(),
        blockMethod: 'DNS sinkhole'
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }

  /**
   * Обработчик изоляции хоста
   */
  private async handleIsolateHost(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const hostId = step.parameters?.hostId as string;

    if (!hostId) {
      return {
        success: false,
        message: 'Идентификатор хоста не указан'
      };
    }

    this.log(`Изоляция хоста: ${hostId}`);

    // Симуляция изоляции
    await this.sleep(1000);

    return {
      success: true,
      message: `Хост ${hostId} изолирован от сети`,
      output: {
        hostId,
        isolatedAt: new Date(),
        isolationMethod: 'network_quarantine'
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }

  /**
   * Обработчик блокировки учетной записи
   */
  private async handleLockAccount(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const accountId = step.parameters?.accountId as string;

    if (!accountId) {
      return {
        success: false,
        message: 'Идентификатор учетной записи не указан'
      };
    }

    this.log(`Блокировка учетной записи: ${accountId}`);

    // Симуляция блокировки
    await this.sleep(500);

    return {
      success: true,
      message: `Учетная запись ${accountId} заблокирована`,
      output: {
        accountId,
        lockedAt: new Date(),
        lockReason: 'security_incident'
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }

  /**
   * Обработчик отзыва токенов
   */
  private async handleRevokeTokens(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const userId = step.parameters?.userId as string;

    if (!userId) {
      return {
        success: false,
        message: 'Идентификатор пользователя не указан'
      };
    }

    this.log(`Отзыв токенов пользователя: ${userId}`);

    // Симуляция отзыва
    await this.sleep(500);

    return {
      success: true,
      message: `Все токены пользователя ${userId} отозваны`,
      output: {
        userId,
        revokedAt: new Date(),
        tokensRevoked: Math.floor(Math.random() * 10)
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }

  /**
   * Обработчик уведомления
   */
  private async handleSendNotification(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const channel = step.parameters?.channel as string || 'email';
    const recipients = step.parameters?.recipients as string[] || [];

    this.log(`Отправка уведомления через ${channel} получателям: ${recipients.join(', ')}`);

    // Симуляция отправки
    await this.sleep(300);

    return {
      success: true,
      message: `Уведомление отправлено ${recipients.length} получателям`,
      output: {
        channel,
        recipients,
        sentAt: new Date(),
        messageId: `msg_${Date.now()}`
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }

  /**
   * Обработчик создания тикета
   */
  private async handleCreateTicket(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const system = step.parameters?.system as string || 'jira';
    const title = step.parameters?.title as string || 'Security Incident';

    this.log(`Создание тикета в ${system}: ${title}`);

    // Симуляция создания
    await this.sleep(500);

    return {
      success: true,
      message: `Тикет создан в ${system}`,
      output: {
        system,
        title,
        ticketId: `INC-${Date.now()}`,
        createdAt: new Date(),
        url: `https://${system}.local/issue/INC-${Date.now()}`
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }

  /**
   * Обработчик документирования
   */
  private async handleDocument(
    step: PlaybookStep,
    context: PlaybookExecutionContext
  ): Promise<PlaybookStepResult> {
    const startTime = Date.now();
    const documentType = step.parameters?.documentType as string || 'incident_log';

    this.log(`Документирование: ${documentType}`);

    // Симуляция документирования
    await this.sleep(300);

    return {
      success: true,
      message: `Документ ${documentType} создан`,
      output: {
        documentType,
        createdAt: new Date(),
        documentId: `doc_${Date.now()}`
      },
      metrics: {
        durationMs: Date.now() - startTime,
        attempts: 1
      }
    };
  }
}

/**
 * Экспорт событий движка
 */
export { PlaybookEngineEvent };
