/**
 * ============================================================================
 * CONTAINMENT ACTIONS
 * ============================================================================
 * Модуль автоматизированного сдерживания угроз
 * Реализует автоматические действия по изоляции и блокировке
 * Соответствует NIST SP 800-61 и SANS Incident Response Methodology
 * ============================================================================
 */

import { EventEmitter } from 'events';
import {
  ContainmentActionType,
  ContainmentActionRecord,
  Incident,
  IncidentSeverity,
  Actor,
  ContainmentConfig
} from '../types/incident.types';

/**
 * События модуля сдерживания
 */
export enum ContainmentActionsEvent {
  /** Действие начато */
  ACTION_STARTED = 'action_started',
  /** Действие завершено */
  ACTION_COMPLETED = 'action_completed',
  /** Действие провалено */
  ACTION_FAILED = 'action_failed',
  /** Действие откатано */
  ACTION_ROLLED_BACK = 'action_rolled_back',
  /** Требуется одобрение */
  APPROVAL_REQUIRED = 'approval_required',
  /** Автоматическое сдерживание активировано */
  AUTO_CONTAINMENT_ACTIVATED = 'auto_containment_activated'
}

/**
 * Результат выполнения действия сдерживания
 */
export interface ContainmentActionResult {
  /** Успешно ли выполнено */
  success: boolean;
  /** Сообщение */
  message: string;
  /** Детали результата */
  details?: Record<string, unknown>;
  /** Время выполнения (мс) */
  durationMs: number;
  /** Воздействие на бизнес */
  businessImpact?: string;
}

/**
 * Конфигурация модуля сдерживания
 */
export interface ContainmentModuleConfig {
  /** Автоматическое сдерживание включено */
  autoContainmentEnabled: boolean;
  /** Действия, требующие одобрения */
  actionsRequiringApproval: ContainmentActionType[];
  /** Максимальное время сдерживания (мс) */
  maxContainmentDuration: number;
  /** Авто rollback при ложной тревоге */
  autoRollbackOnFalsePositive: boolean;
  /** Уведомление о сдерживании */
  notifyOnContainment: boolean;
  /** Логирование */
  enableLogging: boolean;
}

/**
 * Контекст действия сдерживания
 */
export interface ContainmentActionContext {
  /** Инцидент */
  incident: Incident;
  /** Тип действия */
  actionType: ContainmentActionType;
  /** Цель действия */
  target: string;
  /** Параметры действия */
  parameters?: Record<string, unknown>;
  /** Кто инициировал */
  initiatedBy: Actor;
  /** Кто одобрил */
  approvedBy?: Actor;
  /** Время инициации */
  initiatedAt: Date;
}

/**
 * Модуль автоматизированного сдерживания угроз
 */
export class ContainmentActions extends EventEmitter {
  /** Конфигурация */
  private config: ContainmentModuleConfig;

  /** Активные действия сдерживания */
  private activeActions: Map<string, ContainmentActionRecord> = new Map();

  /** История выполненных действий */
  private actionHistory: Map<string, ContainmentActionRecord[]> = new Map();

  /** Состояние сдерживания по инцидентам */
  private incidentContainmentState: Map<string, Set<string>> = new Map();

  /**
   * Конструктор модуля
   */
  constructor(config?: Partial<ContainmentModuleConfig>) {
    super();
    this.config = this.mergeConfigWithDefaults(config);
  }

  /**
   * Объединение конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<ContainmentModuleConfig> | undefined): ContainmentModuleConfig {
    const defaultConfig: ContainmentModuleConfig = {
      autoContainmentEnabled: true,
      actionsRequiringApproval: [
        ContainmentActionType.NETWORK_ISOLATION,
        ContainmentActionType.ACCOUNT_LOCKOUT,
        ContainmentActionType.DEVICE_BLOCKING
      ],
      maxContainmentDuration: 86400000, // 24 часа
      autoRollbackOnFalsePositive: true,
      notifyOnContainment: true,
      enableLogging: true
    };

    return { ...defaultConfig, ...config };
  }

  /**
   * Инициация действия сдерживания
   */
  public async initiateContainmentAction(
    context: ContainmentActionContext
  ): Promise<ContainmentActionRecord> {
    this.log(`Инициация действия сдерживания: ${context.actionType} для цели: ${context.target}`);

    // Проверка, требует ли действие одобрения
    const requiresApproval = this.config.actionsRequiringApproval.includes(context.actionType);

    if (requiresApproval && !context.approvedBy) {
      this.log(`Действие ${context.actionType} требует одобрения`);
      
      // Событие требования одобрения
      this.emit(ContainmentActionsEvent.APPROVAL_REQUIRED, {
        context,
        requiresApproval: true
      });

      throw new Error(`Действие ${context.actionType} требует одобрения руководителя`);
    }

    // Создание записи действия
    const actionRecord: ContainmentActionRecord = {
      id: this.generateActionId(),
      type: context.actionType,
      name: this.getActionName(context.actionType),
      description: this.getActionDescription(context.actionType, context.target),
      target: context.target,
      status: 'executing',
      executedBy: context.initiatedBy.id,
      approvedBy: context.approvedBy?.id,
      executedAt: new Date(),
      result: undefined,
      rollback: {
        available: this.isRollbackAvailable(context.actionType),
        executed: false
      }
    };

    // Сохранение активного действия
    this.activeActions.set(actionRecord.id, actionRecord);

    // Обновление индекса по инцидентам
    if (!this.incidentContainmentState.has(context.incident.id)) {
      this.incidentContainmentState.set(context.incident.id, new Set());
    }
    this.incidentContainmentState.get(context.incident.id)!.add(actionRecord.id);

    // Событие начала
    this.emit(ContainmentActionsEvent.ACTION_STARTED, {
      actionId: actionRecord.id,
      actionType: context.actionType,
      target: context.target
    });

    // Выполнение действия
    try {
      const result = await this.executeAction(context);

      actionRecord.status = result.success ? 'completed' : 'failed';
      actionRecord.result = {
        success: result.success,
        message: result.message,
        details: result.details
      };
      actionRecord.durationMs = result.durationMs;
      actionRecord.businessImpact = result.businessImpact;

      // Сохранение в историю
      this.addToHistory(context.incident.id, actionRecord);

      // Удаление из активных
      this.activeActions.delete(actionRecord.id);

      // Событие завершения
      if (result.success) {
        this.emit(ContainmentActionsEvent.ACTION_COMPLETED, {
          actionId: actionRecord.id,
          result
        });
        this.log(`Действие сдерживания ${actionRecord.id} успешно выполнено`);
      } else {
        this.emit(ContainmentActionsEvent.ACTION_FAILED, {
          actionId: actionRecord.id,
          error: result.message
        });
        this.log(`Действие сдерживания ${actionRecord.id} провалено: ${result.message}`, 'error');
      }

      return actionRecord;
    } catch (error) {
      actionRecord.status = 'failed';
      actionRecord.result = {
        success: false,
        message: (error as Error).message
      };

      this.activeActions.delete(actionRecord.id);
      this.addToHistory(context.incident.id, actionRecord);

      this.emit(ContainmentActionsEvent.ACTION_FAILED, {
        actionId: actionRecord.id,
        error: (error as Error).message
      });

      throw error;
    }
  }

  /**
   * Выполнение действия сдерживания
   */
  private async executeAction(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    const startTime = Date.now();

    switch (context.actionType) {
      case ContainmentActionType.NETWORK_ISOLATION:
        return this.executeNetworkIsolation(context);

      case ContainmentActionType.ACCOUNT_LOCKOUT:
        return this.executeAccountLockout(context);

      case ContainmentActionType.TOKEN_REVOCATION:
        return this.executeTokenRevocation(context);

      case ContainmentActionType.IP_BLOCKING:
        return this.executeIPBlocking(context);

      case ContainmentActionType.DOMAIN_BLOCKING:
        return this.executeDomainBlocking(context);

      case ContainmentActionType.SERVICE_STOP:
        return this.executeServiceStop(context);

      case ContainmentActionType.FILE_QUARANTINE:
        return this.executeFileQuarantine(context);

      case ContainmentActionType.PORT_DISABLE:
        return this.executePortDisable(context);

      case ContainmentActionType.DEVICE_BLOCKING:
        return this.executeDeviceBlocking(context);

      case ContainmentActionType.ACCESS_RESTRICTION:
        return this.executeAccessRestriction(context);

      default:
        throw new Error(`Неизвестный тип действия: ${context.actionType}`);
    }
  }

  /**
   * Изоляция сети
   */
  private async executeNetworkIsolation(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение изоляции сети для хоста: ${context.target}`);

    // Симуляция изоляции
    await this.sleep(2000);

    return {
      success: true,
      message: `Хост ${context.target} успешно изолирован от сети`,
      details: {
        isolationMethod: 'network_quarantine',
        managementAccessPreserved: true,
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Полная потеря сетевого доступа для изолированного хоста'
    };
  }

  /**
   * Блокировка учетной записи
   */
  private async executeAccountLockout(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение блокировки учетной записи: ${context.target}`);

    // Симуляция блокировки
    await this.sleep(1500);

    return {
      success: true,
      message: `Учетная запись ${context.target} успешно заблокирована`,
      details: {
        lockoutType: 'security_lockout',
        indefinite: true,
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Пользователь не сможет войти в систему до разблокировки'
    };
  }

  /**
   * Отзыв токенов
   */
  private async executeTokenRevocation(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение отзыва токенов для пользователя: ${context.target}`);

    // Симуляция отзыва
    await this.sleep(1000);

    return {
      success: true,
      message: `Все токены пользователя ${context.target} отозваны`,
      details: {
        tokensRevoked: Math.floor(Math.random() * 20) + 5,
        sessionsTerminated: Math.floor(Math.random() * 10) + 1,
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Все активные сессии пользователя будут завершены'
    };
  }

  /**
   * Блокировка IP адреса
   */
  private async executeIPBlocking(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение блокировки IP адреса: ${context.target}`);

    // Симуляция блокировки
    await this.sleep(500);

    return {
      success: true,
      message: `IP адрес ${context.target} успешно заблокирован на периметре`,
      details: {
        blockType: 'firewall_rule',
        direction: 'bidirectional',
        permanent: true,
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Минимальное - блокируется только указанный IP'
    };
  }

  /**
   * Блокировка домена
   */
  private async executeDomainBlocking(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение блокировки домена: ${context.target}`);

    // Симуляция блокировки
    await this.sleep(500);

    return {
      success: true,
      message: `Домен ${context.target} успешно заблокирован`,
      details: {
        blockType: 'dns_sinkhole',
        appliedTo: ['DNS', 'Proxy', 'Firewall'],
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Доступ к домену будет невозможен для всех пользователей'
    };
  }

  /**
   * Остановка сервиса
   */
  private async executeServiceStop(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение остановки сервиса: ${context.target}`);

    // Симуляция остановки
    await this.sleep(1000);

    return {
      success: true,
      message: `Сервис ${context.target} успешно остановлен`,
      details: {
        stopMethod: 'graceful',
        processTerminated: true,
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Сервис будет недоступен до перезапуска'
    };
  }

  /**
   * Карантин файла
   */
  private async executeFileQuarantine(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение карантина файла: ${context.target}`);

    // Симуляция карантина
    await this.sleep(1000);

    return {
      success: true,
      message: `Файл ${context.target} успешно перемещен в карантин`,
      details: {
        quarantineMethod: 'move_and_encrypt',
        quarantineLocation: '/var/quarantine',
        hashPreserved: true,
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Файл будет недоступен до анализа'
    };
  }

  /**
   * Отключение порта
   */
  private async executePortDisable(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение отключения порта: ${context.target}`);

    // Симуляция отключения
    await this.sleep(1500);

    return {
      success: true,
      message: `Порт ${context.target} успешно отключен`,
      details: {
        switchPort: context.target,
        adminStatus: 'down',
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Устройства, подключенные к порту, потеряют сетевой доступ'
    };
  }

  /**
   * Блокировка устройства
   */
  private async executeDeviceBlocking(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение блокировки устройства: ${context.target}`);

    // Симуляция блокировки
    await this.sleep(1500);

    return {
      success: true,
      message: `Устройство ${context.target} успешно заблокировано`,
      details: {
        blockType: 'mac_address_block',
        appliedTo: ['NAC', 'Switch', 'Wireless'],
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Устройство не сможет подключиться к корпоративной сети'
    };
  }

  /**
   * Ограничение доступа
   */
  private async executeAccessRestriction(context: ContainmentActionContext): Promise<ContainmentActionResult> {
    this.log(`Выполнение ограничения доступа для: ${context.target}`);

    // Симуляция ограничения
    await this.sleep(1000);

    return {
      success: true,
      message: `Доступ для ${context.target} успешно ограничен`,
      details: {
        restrictionType: 'privilege_reduction',
        appliedRestrictions: ['admin_access_revoked', 'data_access_limited'],
        timestamp: new Date()
      },
      durationMs: Date.now() - context.initiatedAt.getTime(),
      businessImpact: 'Пользователь потеряет привилегированный доступ'
    };
  }

  /**
   * Откат действия сдерживания
   */
  public async rollbackAction(
    actionId: string,
    rolledBackBy: Actor,
    reason: string
  ): Promise<ContainmentActionRecord> {
    const action = this.activeActions.get(actionId) || this.findActionInHistory(actionId);

    if (!action) {
      throw new Error(`Действие сдерживания ${actionId} не найдено`);
    }

    if (!action.rollback?.available) {
      throw new Error(`Rollback для действия ${actionId} недоступен`);
    }

    this.log(`Выполнение rollback для действия ${actionId}. Причина: ${reason}`);

    // Выполнение rollback
    await this.executeRollback(action, reason);

    action.rollback.executed = true;
    action.rollback.executedAt = new Date();
    action.rollback.result = `Rollback выполнен: ${reason}`;
    action.status = 'rolled_back';

    // Событие rollback
    this.emit(ContainmentActionsEvent.ACTION_ROLLED_BACK, {
      actionId,
      reason,
      rolledBackBy
    });

    this.log(`Rollback для действия ${actionId} успешно выполнен`);

    return action;
  }

  /**
   * Выполнение rollback
   */
  private async executeRollback(action: ContainmentActionRecord, reason: string): Promise<void> {
    // Симуляция rollback
    await this.sleep(1000);

    this.log(`Rollback действия ${action.type} для цели ${action.target}`);

    // В реальной системе здесь была бы логика отката для каждого типа действия
  }

  /**
   * Автоматическое сдерживание на основе серьезности инцидента
   */
  public async executeAutoContainment(
    incident: Incident,
    initiatedBy: Actor
  ): Promise<ContainmentActionRecord[]> {
    this.log(`Выполнение автоматического сдерживания для инцидента ${incident.id}`);

    if (!this.config.autoContainmentEnabled) {
      this.log('Автоматическое сдерживание отключено');
      return [];
    }

    const actions: ContainmentActionRecord[] = [];

    // Определение действий на основе категории и серьезности
    const actionsToExecute = this.determineAutoContainmentActions(incident);

    // Событие активации
    this.emit(ContainmentActionsEvent.AUTO_CONTAINMENT_ACTIVATED, {
      incidentId: incident.id,
      actionsCount: actionsToExecute.length
    });

    // Выполнение действий
    for (const actionType of actionsToExecute) {
      try {
        const context: ContainmentActionContext = {
          incident,
          actionType,
          target: this.determineTarget(incident, actionType),
          parameters: this.getAutoContainmentParameters(incident, actionType),
          initiatedBy,
          initiatedAt: new Date()
        };

        const record = await this.initiateContainmentAction(context);
        actions.push(record);
      } catch (error) {
        this.log(`Ошибка выполнения действия ${actionType}: ${error}`, 'error');
      }
    }

    return actions;
  }

  /**
   * Определение действий для автоматического сдерживания
   */
  private determineAutoContainmentActions(incident: Incident): ContainmentActionType[] {
    const actions: ContainmentActionType[] = [];

    // На основе серьезности
    if (incident.severity === IncidentSeverity.CRITICAL || incident.severity === IncidentSeverity.HIGH) {
      actions.push(ContainmentActionType.IP_BLOCKING);
      actions.push(ContainmentActionType.TOKEN_REVOCATION);
    }

    // На основе категории
    switch (incident.category) {
      case 'malware':
      case 'ransomware_attack':
        actions.push(ContainmentActionType.NETWORK_ISOLATION);
        actions.push(ContainmentActionType.FILE_QUARANTINE);
        break;

      case 'credential_compromise':
        actions.push(ContainmentActionType.ACCOUNT_LOCKOUT);
        actions.push(ContainmentActionType.TOKEN_REVOCATION);
        break;

      case 'insider_threat':
        actions.push(ContainmentActionType.ACCESS_RESTRICTION);
        actions.push(ContainmentActionType.ACCOUNT_LOCKOUT);
        break;

      case 'ddos_attack':
        actions.push(ContainmentActionType.IP_BLOCKING);
        break;

      case 'data_breach':
        actions.push(ContainmentActionType.ACCOUNT_LOCKOUT);
        actions.push(ContainmentActionType.TOKEN_REVOCATION);
        break;
    }

    // Удаление дубликатов
    return [...new Set(actions)];
  }

  /**
   * Определение цели для действия
   */
  private determineTarget(incident: Incident, actionType: ContainmentActionType): string {
    // В реальной системе здесь был бы анализ инцидента для определения цели
    // Для симуляции возвращаем заглушку

    if (incident.details?.source?.ipAddress && actionType === ContainmentActionType.IP_BLOCKING) {
      return incident.details.source.ipAddress;
    }

    if (incident.details?.affectedUsers?.[0]?.id && actionType === ContainmentActionType.ACCOUNT_LOCKOUT) {
      return incident.details.affectedUsers[0].id;
    }

    return 'auto_detected';
  }

  /**
   * Получение параметров для автоматического сдерживания
   */
  private getAutoContainmentParameters(
    incident: Incident,
    actionType: ContainmentActionType
  ): Record<string, unknown> {
    return {
      automatic: true,
      incidentId: incident.id,
      severity: incident.severity
    };
  }

  /**
   * Получение активных действий сдерживания
   */
  public getActiveActions(incidentId?: string): ContainmentActionRecord[] {
    if (incidentId) {
      const actionIds = this.incidentContainmentState.get(incidentId);
      if (!actionIds) {
        return [];
      }

      const actions: ContainmentActionRecord[] = [];
      for (const id of actionIds) {
        const action = this.activeActions.get(id);
        if (action) {
          actions.push(action);
        }
      }
      return actions;
    }

    return Array.from(this.activeActions.values());
  }

  /**
   * Получение истории действий по инциденту
   */
  public getActionHistory(incidentId: string): ContainmentActionRecord[] {
    return this.actionHistory.get(incidentId) || [];
  }

  /**
   * Добавление действия в историю
   */
  private addToHistory(incidentId: string, action: ContainmentActionRecord): void {
    if (!this.actionHistory.has(incidentId)) {
      this.actionHistory.set(incidentId, []);
    }
    this.actionHistory.get(incidentId)!.push(action);
  }

  /**
   * Поиск действия в истории
   */
  private findActionInHistory(actionId: string): ContainmentActionRecord | undefined {
    for (const actions of this.actionHistory.values()) {
      const action = actions.find(a => a.id === actionId);
      if (action) {
        return action;
      }
    }
    return undefined;
  }

  /**
   * Проверка доступности rollback
   */
  private isRollbackAvailable(actionType: ContainmentActionType): boolean {
    // Rollback доступен для большинства действий
    const noRollback: ContainmentActionType[] = [
      ContainmentActionType.TOKEN_REVOCATION // Токены нельзя восстановить
    ];

    return !noRollback.includes(actionType);
  }

  /**
   * Получение названия действия
   */
  private getActionName(actionType: ContainmentActionType): string {
    const names: Record<ContainmentActionType, string> = {
      [ContainmentActionType.NETWORK_ISOLATION]: 'Изоляция сети',
      [ContainmentActionType.ACCOUNT_LOCKOUT]: 'Блокировка учетной записи',
      [ContainmentActionType.TOKEN_REVOCATION]: 'Отзыв токенов',
      [ContainmentActionType.IP_BLOCKING]: 'Блокировка IP',
      [ContainmentActionType.DOMAIN_BLOCKING]: 'Блокировка домена',
      [ContainmentActionType.SERVICE_STOP]: 'Остановка сервиса',
      [ContainmentActionType.FILE_QUARANTINE]: 'Карантин файла',
      [ContainmentActionType.PORT_DISABLE]: 'Отключение порта',
      [ContainmentActionType.DEVICE_BLOCKING]: 'Блокировка устройства',
      [ContainmentActionType.ACCESS_RESTRICTION]: 'Ограничение доступа'
    };

    return names[actionType] || actionType;
  }

  /**
   * Получение описания действия
   */
  private getActionDescription(actionType: ContainmentActionType, target: string): string {
    return `Выполнение действия ${actionType} для цели ${target}`;
  }

  /**
   * Генерация идентификатора действия
   */
  private generateActionId(): string {
    return `ca_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
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
      const prefix = `[ContainmentActions] [${timestamp}] [${level.toUpperCase()}]`;
      console.log(`${prefix} ${message}`);
    }
  }

  /**
   * Получение статистики сдерживания
   */
  public getContainmentStats(incidentId?: string): {
    totalActions: number;
    successfulActions: number;
    failedActions: number;
    rolledBackActions: number;
    byType: Record<string, number>;
  } {
    let actions: ContainmentActionRecord[] = [];

    if (incidentId) {
      actions = this.getActionHistory(incidentId);
    } else {
      for (const history of this.actionHistory.values()) {
        actions = actions.concat(history);
      }
    }

    const byType: Record<string, number> = {};
    let successfulActions = 0;
    let failedActions = 0;
    let rolledBackActions = 0;

    for (const action of actions) {
      byType[action.type] = (byType[action.type] || 0) + 1;

      switch (action.status) {
        case 'completed':
          successfulActions++;
          break;
        case 'failed':
          failedActions++;
          break;
        case 'rolled_back':
          rolledBackActions++;
          break;
      }
    }

    return {
      totalActions: actions.length,
      successfulActions,
      failedActions,
      rolledBackActions,
      byType
    };
  }
}

/**
 * Экспорт событий модуля
 */
export { ContainmentActionsEvent };
