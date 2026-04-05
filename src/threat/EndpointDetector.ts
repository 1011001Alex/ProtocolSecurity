/**
 * ============================================================================
 * ENDPOINT DETECTOR
 * EDR (Endpoint Detection and Response) интеграция
 * ============================================================================
 */

import {
  EndpointEvent,
  EndpointEventType,
  EndpointStatus,
  EndpointPolicy,
  ProcessInfo,
  FileInfo,
  FileHash,
  SignatureInfo,
  RegistryInfo,
  NetworkConnectionInfo,
  UserInfo,
  SecurityAlert,
  SecurityEvent,
  ThreatSeverity,
  ThreatCategory,
  AttackType
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Конфигурация Endpoint Detector
 */
interface EndpointDetectorConfig {
  eventBufferSize: number;
  alertThreshold: number;
  monitoredProcesses: Set<string>;
  suspiciousPaths: Set<string>;
  knownMaliciousHashes: Set<string>;
  policyEnforcement: boolean;
}

/**
 * Состояние endpoint
 */
interface EndpointState {
  status: EndpointStatus;
  recentEvents: EndpointEvent[];
  activeProcesses: Map<number, ProcessInfo>;
  riskScore: number;
  lastHeartbeat: Date;
  alerts: SecurityAlert[];
}

/**
 * Правило обнаружения для endpoint
 */
interface EndpointDetectionRule {
  id: string;
  name: string;
  enabled: boolean;
  eventType: EndpointEventType;
  conditions: EndpointCondition[];
  severity: ThreatSeverity;
  mitreTechniques: string[];
}

/**
 * Условие обнаружения
 */
interface EndpointCondition {
  field: string;
  operator: 'eq' | 'ne' | 'contains' | 'regex' | 'gt' | 'lt' | 'exists';
  value: any;
}

/**
 * ============================================================================
 * ENDPOINT DETECTOR CLASS
 * ============================================================================
 */
export class EndpointDetector {
  private config: EndpointDetectorConfig;
  
  // Endpoint состояния
  private endpoints: Map<string, EndpointState> = new Map();
  
  // Правила обнаружения
  private detectionRules: Map<string, EndpointDetectionRule> = new Map();
  
  // Буфер событий
  private eventBuffer: EndpointEvent[] = [];
  
  // Статистика
  private statistics: EndpointDetectorStatistics = {
    totalEventsProcessed: 0,
    totalAlertsGenerated: 0,
    endpointsMonitored: 0,
    eventsByType: new Map(),
    lastUpdated: new Date()
  };

  constructor(config?: Partial<EndpointDetectorConfig>) {
    this.config = {
      eventBufferSize: config?.eventBufferSize || 10000,
      alertThreshold: config?.alertThreshold || 3,
      monitoredProcesses: config?.monitoredProcesses || new Set([
        'powershell.exe', 'cmd.exe', 'bash.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe'
      ]),
      suspiciousPaths: config?.suspiciousPaths || new Set([
        'C:\\Temp', 'C:\\Windows\\Temp', '/tmp', '/var/tmp',
        'AppData\\Local\\Temp', 'Downloads'
      ]),
      knownMaliciousHashes: config?.knownMaliciousHashes || new Set(),
      policyEnforcement: config?.policyEnforcement ?? true
    };
    
    this.initializeDetectionRules();
    
    console.log('[EndpointDetector] Инициализация завершена');
    console.log(`[EndpointDetector] Мониторинг процессов: ${this.config.monitoredProcesses.size}`);
    console.log(`[EndpointDetector] Подозрительные пути: ${this.config.suspiciousPaths.size}`);
  }

  // ============================================================================
  // ИНИЦИАЛИЗАЦИЯ ПРАВИЛ
  // ============================================================================

  /**
   * Инициализация правил обнаружения
   */
  private initializeDetectionRules(): void {
    // Правило: Подозрительный процесс
    this.addDetectionRule({
      id: 'EDR-001',
      name: 'Подозрительный процесс',
      enabled: true,
      eventType: EndpointEventType.PROCESS_CREATE,
      conditions: [
        { field: 'rawEvent.processName', operator: 'in', value: Array.from(this.config.monitoredProcesses) }
      ],
      severity: ThreatSeverity.MEDIUM,
      mitreTechniques: ['T1059']
    });

    // Правило: Процесс из временной директории
    this.addDetectionRule({
      id: 'EDR-002',
      name: 'Процесс из временной директории',
      enabled: true,
      eventType: EndpointEventType.PROCESS_CREATE,
      conditions: [
        { field: 'rawEvent.path', operator: 'contains', value: 'Temp' },
        { field: 'rawEvent.commandLine', operator: 'contains', value: 'Temp' }
      ],
      severity: ThreatSeverity.HIGH,
      mitreTechniques: ['T1059', 'T1547']
    });
    
    // Правило: Изменение реестра (автозагрузка)
    this.addDetectionRule({
      id: 'EDR-003',
      name: 'Изменение реестра (автозагрузка)',
      enabled: true,
      eventType: EndpointEventType.REGISTRY_CREATE,
      conditions: [
        { field: 'registry.key', operator: 'contains', value: 'CurrentVersion\\Run' }
      ],
      severity: ThreatSeverity.HIGH,
      mitreTechniques: ['T1547']
    });
    
    // Правило: Доступ к LSASS
    this.addDetectionRule({
      id: 'EDR-004',
      name: 'Доступ к LSASS',
      enabled: true,
      eventType: EndpointEventType.PROCESS_CREATE,
      conditions: [
        { field: 'rawEvent.commandLine', operator: 'regex', value: 'lsass|dump|credential' }
      ],
      severity: ThreatSeverity.CRITICAL,
      mitreTechniques: ['T1003']
    });
    
    // Правило: Создание файла с известным хешем
    this.addDetectionRule({
      id: 'EDR-005',
      name: 'Известный вредоносный файл',
      enabled: true,
      eventType: EndpointEventType.FILE_CREATE,
      conditions: [
        { field: 'rawEvent.hash', operator: 'in', value: Array.from(this.config.knownMaliciousHashes) }
      ],
      severity: ThreatSeverity.CRITICAL,
      mitreTechniques: ['T1204']
    });
    
    // Правило: Подозрительное сетевое подключение
    this.addDetectionRule({
      id: 'EDR-006',
      name: 'Подозрительное сетевое подключение',
      enabled: true,
      eventType: EndpointEventType.NETWORK_CONNECTION,
      conditions: [
        { field: 'rawEvent.remotePort', operator: 'in', value: [4444, 5555, 6666, 8080, 1337] }
      ],
      severity: ThreatSeverity.HIGH,
      mitreTechniques: ['T1071']
    });
    
    // Правило: Повышение привилегий
    this.addDetectionRule({
      id: 'EDR-007',
      name: 'Повышение привилегий',
      enabled: true,
      eventType: EndpointEventType.PRIVILEGE_ESCALATION,
      conditions: [],
      severity: ThreatSeverity.CRITICAL,
      mitreTechniques: ['T1068']
    });
    
    // Правило: Доступ к учетным данным
    this.addDetectionRule({
      id: 'EDR-008',
      name: 'Доступ к учетным данным',
      enabled: true,
      eventType: EndpointEventType.CREDENTIAL_ACCESS,
      conditions: [],
      severity: ThreatSeverity.CRITICAL,
      mitreTechniques: ['T1003']
    });
    
    // Правило: Загрузка драйвера
    this.addDetectionRule({
      id: 'EDR-009',
      name: 'Загрузка драйвера',
      enabled: true,
      eventType: EndpointEventType.DRIVER_LOAD,
      conditions: [],
      severity: ThreatSeverity.HIGH,
      mitreTechniques: ['T1547.015']
    });
    
    // Правило: Создание службы
    this.addDetectionRule({
      id: 'EDR-010',
      name: 'Создание службы',
      enabled: true,
      eventType: EndpointEventType.SERVICE_CREATE,
      conditions: [],
      severity: ThreatSeverity.MEDIUM,
      mitreTechniques: ['T1543']
    });
  }

  /**
   * Добавление правила обнаружения
   */
  addDetectionRule(rule: EndpointDetectionRule): void {
    this.detectionRules.set(rule.id, rule);
  }

  /**
   * Удаление правила
   */
  removeDetectionRule(ruleId: string): void {
    this.detectionRules.delete(ruleId);
  }

  // ============================================================================
  // РЕГИСТРАЦИЯ ENDPOINT
  // ============================================================================

  /**
   * Регистрация endpoint
   */
  registerEndpoint(endpointId: string, endpointInfo: {
    hostname: string;
    ipAddress: string;
    osType: string;
    osVersion: string;
    agentVersion: string;
  }): EndpointStatus {
    const status: EndpointStatus = {
      endpointId,
      hostname: endpointInfo.hostname,
      ipAddress: endpointInfo.ipAddress,
      osType: endpointInfo.osType,
      osVersion: endpointInfo.osVersion,
      agentVersion: endpointInfo.agentVersion,
      lastSeen: new Date(),
      status: 'online',
      riskScore: 0,
      activeThreats: 0,
      policies: []
    };
    
    const state: EndpointState = {
      status,
      recentEvents: [],
      activeProcesses: new Map(),
      riskScore: 0,
      lastHeartbeat: new Date(),
      alerts: []
    };
    
    this.endpoints.set(endpointId, state);
    this.statistics.endpointsMonitored = this.endpoints.size;
    
    console.log(`[EndpointDetector] Зарегистрирован endpoint: ${endpointInfo.hostname}`);
    
    return status;
  }

  /**
   * Обновление heartbeat
   */
  updateHeartbeat(endpointId: string): void {
    const state = this.endpoints.get(endpointId);
    
    if (state) {
      state.lastHeartbeat = new Date();
      state.status.status = 'online';
      state.status.lastSeen = state.lastHeartbeat;
    }
  }

  /**
   * Удаление endpoint
   */
  unregisterEndpoint(endpointId: string): void {
    this.endpoints.delete(endpointId);
    this.statistics.endpointsMonitored = this.endpoints.size;
  }

  // ============================================================================
  // ОБРАБОТКА СОБЫТИЙ
  // ============================================================================

  /**
   * Обработка события endpoint
   */
  processEvent(event: EndpointEvent): SecurityAlert[] {
    this.statistics.totalEventsProcessed++;
    
    // Обновление статистики по типам
    const eventTypeCount = this.statistics.eventsByType.get(event.eventType) || 0;
    this.statistics.eventsByType.set(event.eventType, eventTypeCount + 1);
    
    // Добавление в буфер
    this.addToEventBuffer(event);
    
    // Обновление состояния endpoint
    this.updateEndpointState(event);
    
    // Проверка правил обнаружения
    const alerts = this.evaluateRules(event);
    
    // Обновление статистики
    this.statistics.totalAlertsGenerated += alerts.length;
    
    return alerts;
  }

  /**
   * Пакетная обработка событий
   */
  processEvents(events: EndpointEvent[]): SecurityAlert[] {
    const allAlerts: SecurityAlert[] = [];
    
    for (const event of events) {
      const alerts = this.processEvent(event);
      allAlerts.push(...alerts);
    }
    
    return allAlerts;
  }

  /**
   * Добавление события в буфер
   */
  private addToEventBuffer(event: EndpointEvent): void {
    this.eventBuffer.push(event);
    
    if (this.eventBuffer.length > this.config.eventBufferSize) {
      this.eventBuffer.shift();
    }
  }

  /**
   * Обновление состояния endpoint
   */
  private updateEndpointState(event: EndpointEvent): void {
    const state = this.endpoints.get(event.endpointId);
    
    if (!state) {
      return;
    }
    
    // Добавление события в историю
    state.recentEvents.push(event);
    
    if (state.recentEvents.length > 1000) {
      state.recentEvents.shift();
    }
    
    // Обновление активных процессов
    if (event.eventType === EndpointEventType.PROCESS_CREATE && event.process) {
      state.activeProcesses.set(event.process.pid, event.process);
    } else if (event.eventType === EndpointEventType.PROCESS_TERMINATE && event.process) {
      state.activeProcesses.delete(event.process.pid);
    }
    
    // Обновление risk score
    state.riskScore = this.calculateEndpointRisk(state);
    state.status.riskScore = state.riskScore;
    
    // Обновление статуса при высоком риске
    if (state.riskScore >= 80) {
      state.status.status = 'compromised';
    }
  }

  // ============================================================================
  // ОЦЕНКА ПРАВИЛ
  // ============================================================================

  /**
   * Оценка правил для события
   */
  private evaluateRules(event: EndpointEvent): SecurityAlert[] {
    const alerts: SecurityAlert[] = [];
    
    for (const rule of this.detectionRules.values()) {
      if (!rule.enabled) {
        continue;
      }
      
      // Проверка типа события
      if (rule.eventType !== event.eventType) {
        continue;
      }
      
      // Проверка условий
      if (this.evaluateConditions(event, rule.conditions)) {
        // Создание алерта
        const alert = this.createAlert(event, rule);
        alerts.push(alert);
        
        // Добавление алерта в состояние endpoint
        const state = this.endpoints.get(event.endpointId);
        if (state) {
          state.alerts.push(alert);
          state.status.activeThreats = state.alerts.filter(a => a.status === 'new').length;
        }
      }
    }
    
    return alerts;
  }

  /**
   * Оценка условий правила
   */
  private evaluateConditions(event: EndpointEvent, conditions: EndpointCondition[]): boolean {
    if (conditions.length === 0) {
      return true;  // Нет условий - правило срабатывает
    }
    
    for (const condition of conditions) {
      const value = this.getFieldValue(event, condition.field);
      
      if (!this.evaluateCondition(value, condition)) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Получение значения поля из события
   */
  private getFieldValue(event: EndpointEvent, field: string): any {
    const parts = field.split('.');
    let value: any = event;
    
    for (const part of parts) {
      if (value === null || value === undefined) {
        return undefined;
      }
      value = (value as any)[part];
    }
    
    return value;
  }

  /**
   * Оценка отдельного условия
   */
  private evaluateCondition(value: any, condition: EndpointCondition): boolean {
    if (value === undefined && condition.operator !== 'exists') {
      return false;
    }
    
    switch (condition.operator) {
      case 'eq':
        return value === condition.value;
      case 'ne':
        return value !== condition.value;
      case 'contains':
        return String(value).includes(String(condition.value));
      case 'regex':
        return new RegExp(condition.value).test(String(value));
      case 'gt':
        return Number(value) > Number(condition.value);
      case 'lt':
        return Number(value) < Number(condition.value);
      case 'exists':
        return value !== undefined && value !== null;
      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(value);
      default:
        return false;
    }
  }

  // ============================================================================
  // СОЗДАНИЕ АЛЕРТОВ
  // ============================================================================

  /**
   * Создание алерта из события
   */
  private createAlert(event: EndpointEvent, rule: EndpointDetectionRule): SecurityAlert {
    const description = this.generateAlertDescription(event, rule);
    
    const alert: SecurityAlert = {
      id: uuidv4(),
      timestamp: event.timestamp,
      title: `EDR: ${rule.name}`,
      description,
      severity: rule.severity,
      status: 'new',
      category: ThreatCategory.UNKNOWN,
      attackType: this.mapEventTypeToAttackType(event.eventType),
      source: 'EndpointDetector',
      events: [this.convertToSecurityEvent(event)],
      entities: [
        {
          id: uuidv4(),
          type: 'host',
          name: event.hostname,
          value: event.endpointId,
          riskScore: event.severity === ThreatSeverity.CRITICAL ? 90 : 70,
          role: 'victim',
          context: {
            osType: event.rawEvent.osType,
            user: event.user?.name
          }
        }
      ],
      mitreAttack: {
        tactics: [],
        techniques: rule.mitreTechniques.map(id => ({ id, name: '' }))
      },
      riskScore: this.calculateAlertRiskScore(event, rule),
      confidence: 0.8,
      falsePositiveProbability: 0.2,
      investigationStatus: {
        stage: 'triage',
        progress: 0,
        findings: [],
        evidenceCollected: []
      },
      tags: ['edr', 'endpoint', rule.id],
      timeline: [{
        timestamp: event.timestamp,
        event: event.eventType,
        details: description
      }],
      evidence: this.extractEvidence(event),
      response: {
        automatedActions: [],
        manualActions: [],
        playbooksExecuted: [],
        containmentStatus: 'not_started',
        eradicationStatus: 'not_started',
        recoveryStatus: 'not_started'
      },
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    return alert;
  }

  /**
   * Генерация описания алерта
   */
  private generateAlertDescription(event: EndpointEvent, rule: EndpointDetectionRule): string {
    const parts: string[] = [];
    
    parts.push(`Правило "${rule.name}" сработало на ${event.hostname}`);
    
    if (event.process) {
      parts.push(`Процесс: ${event.process.name} (PID: ${event.process.pid})`);
      
      if (event.process.commandLine) {
        parts.push(`Команда: ${event.process.commandLine}`);
      }
      
      if (event.process.path) {
        parts.push(`Путь: ${event.process.path}`);
      }
    }
    
    if (event.file) {
      parts.push(`Файл: ${event.file.path}`);
      
      if (event.file.hash?.sha256) {
        parts.push(`SHA256: ${event.file.hash.sha256}`);
      }
    }
    
    if (event.user) {
      parts.push(`Пользователь: ${event.user.domain}\\${event.user.name}`);
    }
    
    if (event.network) {
      parts.push(`Подключение: ${event.network.localIp}:${event.network.localPort} -> ${event.network.remoteIp}:${event.network.remotePort}`);
    }
    
    return parts.join('. ');
  }

  /**
   * Конвертация в SecurityEvent
   */
  private convertToSecurityEvent(event: EndpointEvent): SecurityEvent {
    return {
      id: event.id,
      timestamp: event.timestamp,
      eventType: event.eventType,
      source: 'EndpointDetector',
      sourceIp: event.network?.localIp,
      destinationIp: event.network?.remoteIp,
      sourcePort: event.network?.localPort,
      destinationPort: event.network?.remotePort,
      protocol: event.network?.protocol,
      userId: event.user?.sid,
      username: event.user?.name,
      hostname: event.hostname,
      processName: event.process?.name,
      processId: event.process?.pid,
      commandLine: event.process?.commandLine,
      filePath: event.file?.path,
      hash: event.file?.hash?.sha256,
      severity: event.severity,
      category: ThreatCategory.UNKNOWN,
      rawEvent: event.rawEvent,
      normalizedEvent: {}
    };
  }

  /**
   * Извлечение доказательств
   */
  private extractEvidence(event: EndpointEvent): any[] {
    const evidence: any[] = [];
    
    if (event.process) {
      evidence.push({
        type: 'process',
        name: event.process.name,
        path: event.process.path,
        pid: event.process.pid,
        hash: event.process.hash
      });
    }
    
    if (event.file) {
      evidence.push({
        type: 'file',
        name: event.file.name,
        path: event.file.path,
        hash: event.file.hash
      });
    }
    
    if (event.registry) {
      evidence.push({
        type: 'registry',
        key: event.registry.key,
        value: event.registry.value,
        data: event.registry.data
      });
    }
    
    return evidence;
  }

  /**
   * Маппинг типа события на тип атаки
   */
  private mapEventTypeToAttackType(eventType: EndpointEventType): AttackType {
    const mapping: Record<EndpointEventType, AttackType> = {
      [EndpointEventType.PROCESS_CREATE]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.PROCESS_TERMINATE]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.FILE_CREATE]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.FILE_MODIFY]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.FILE_DELETE]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.FILE_READ]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.REGISTRY_CREATE]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.REGISTRY_MODIFY]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.REGISTRY_DELETE]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.NETWORK_CONNECTION]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.MODULE_LOAD]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.DRIVER_LOAD]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.SCHEDULED_TASK]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.SERVICE_CREATE]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.SERVICE_MODIFY]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.USER_LOGON]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.USER_LOGOFF]: AttackType.SUSPICIOUS_BEHAVIOR,
      [EndpointEventType.PRIVILEGE_ESCALATION]: AttackType.PRIVILEGE_ESCALATION,
      [EndpointEventType.CREDENTIAL_ACCESS]: AttackType.SUSPICIOUS_BEHAVIOR
    };
    
    return mapping[eventType] || AttackType.UNKNOWN;
  }

  /**
   * Расчет risk score для алерта
   */
  private calculateAlertRiskScore(event: EndpointEvent, rule: EndpointDetectionRule): number {
    let score = 50;
    
    // Базовый риск на основе серьезности
    const severityScores: Record<ThreatSeverity, number> = {
      [ThreatSeverity.CRITICAL]: 40,
      [ThreatSeverity.HIGH]: 30,
      [ThreatSeverity.MEDIUM]: 20,
      [ThreatSeverity.LOW]: 10,
      [ThreatSeverity.INFO]: 0
    };
    score += severityScores[rule.severity];
    
    // Увеличение за критичные события
    if (event.eventType === EndpointEventType.CREDENTIAL_ACCESS) {
      score += 20;
    }
    if (event.eventType === EndpointEventType.PRIVILEGE_ESCALATION) {
      score += 20;
    }
    
    // Увеличение за известные вредоносные хеши
    if (event.file?.hash?.sha256 && this.config.knownMaliciousHashes.has(event.file.hash.sha256)) {
      score += 30;
    }
    
    return Math.min(score, 100);
  }

  /**
   * Расчет риска endpoint
   */
  private calculateEndpointRisk(state: EndpointState): number {
    let risk = 0;
    
    // Риск на основе алертов
    const criticalAlerts = state.alerts.filter(a => a.severity === ThreatSeverity.CRITICAL).length;
    const highAlerts = state.alerts.filter(a => a.severity === ThreatSeverity.HIGH).length;
    
    risk += criticalAlerts * 30;
    risk += highAlerts * 15;
    
    // Риск на основе активных процессов
    for (const process of state.activeProcesses.values()) {
      if (this.config.monitoredProcesses.has(process.name.toLowerCase())) {
        risk += 5;
      }
      
      // Проверка пути
      for (const suspiciousPath of this.config.suspiciousPaths) {
        if (process.path?.includes(suspiciousPath)) {
          risk += 10;
        }
      }
    }
    
    // Риск на основе времени с последнего heartbeat
    const timeSinceHeartbeat = Date.now() - state.lastHeartbeat.getTime();
    const hoursOffline = timeSinceHeartbeat / (1000 * 60 * 60);
    
    if (hoursOffline > 24) {
      risk += 10;
    }
    
    return Math.min(risk, 100);
  }

  // ============================================================================
  // СТАТИСТИКА И МОНИТОРИНГ
  // ============================================================================

  /**
   * Получение статистики
   */
  getStatistics(): EndpointDetectorStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }

  /**
   * Получение статуса endpoint
   */
  getEndpointStatus(endpointId: string): EndpointStatus | null {
    const state = this.endpoints.get(endpointId);
    return state?.status || null;
  }

  /**
   * Получение всех статусов endpoint
   */
  getAllEndpointStatuses(): EndpointStatus[] {
    return Array.from(this.endpoints.values()).map(s => s.status);
  }

  /**
   * Получение компрометированных endpoint
   */
  getCompromisedEndpoints(): EndpointStatus[] {
    return Array.from(this.endpoints.values())
      .filter(s => s.status.status === 'compromised')
      .map(s => s.status);
  }

  /**
   * Получение активных процессов endpoint
   */
  getActiveProcesses(endpointId: string): ProcessInfo[] {
    const state = this.endpoints.get(endpointId);
    return state ? Array.from(state.activeProcesses.values()) : [];
  }

  /**
   * Получение недавних событий endpoint
   */
  getRecentEvents(endpointId: string, limit: number = 100): EndpointEvent[] {
    const state = this.endpoints.get(endpointId);
    return state ? state.recentEvents.slice(-limit) : [];
  }

  /**
   * Добавление хеша в список известных вредоносных
   */
  addMaliciousHash(hash: string): void {
    this.config.knownMaliciousHashes.add(hash.toLowerCase());
    
    // Обновление правила
    const rule = this.detectionRules.get('EDR-005');
    if (rule) {
      rule.conditions[0].value = Array.from(this.config.knownMaliciousHashes);
    }
  }

  /**
   * Изоляция endpoint
   */
  isolateEndpoint(endpointId: string): void {
    const state = this.endpoints.get(endpointId);
    
    if (state) {
      state.status.status = 'isolated';
      console.log(`[EndpointDetector] Endpoint ${state.status.hostname} изолирован`);
    }
  }

  /**
   * Восстановление endpoint
   */
  restoreEndpoint(endpointId: string): void {
    const state = this.endpoints.get(endpointId);
    
    if (state) {
      state.status.status = 'online';
      console.log(`[EndpointDetector] Endpoint ${state.status.hostname} восстановлен`);
    }
  }
}

/**
 * Статистика Endpoint Detector
 */
interface EndpointDetectorStatistics {
  totalEventsProcessed: number;
  totalAlertsGenerated: number;
  endpointsMonitored: number;
  eventsByType: Map<EndpointEventType, number>;
  lastUpdated: Date;
}
