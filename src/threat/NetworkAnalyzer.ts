/**
 * ============================================================================
 * NETWORK ANALYZER
 * Анализ сетевого трафика для обнаружения угроз
 * ============================================================================
 */

import {
  NetworkPacket,
  NetworkFlow,
  NetworkAnomaly,
  NetworkAnomalyType,
  NetworkEvidence,
  NetworkStatistics,
  NetworkSession,
  SecurityEvent,
  SecurityAlert,
  ThreatSeverity,
  ThreatCategory,
  ThreatStatus,
  EntityType,
  AttackType
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Конфигурация Network Analyzer
 */
interface NetworkAnalyzerConfig {
  flowTimeout: number;  // мс
  packetBufferSize: number;
  anomalyThresholds: {
    portScan: number;
    networkSweep: number;
    dataExfiltration: number;
    bruteForce: number;
  };
  whitelistedIPs: Set<string>;
  monitoredPorts: Set<number>;
}

/**
 * Агрегатор потоков
 */
interface FlowAggregator {
  flows: NetworkFlow[];
  statistics: NetworkStatistics;
  anomalies: NetworkAnomaly[];
}

/**
 * ============================================================================
 * NETWORK ANALYZER CLASS
 * ============================================================================
 */
export class NetworkAnalyzer {
  private config: NetworkAnalyzerConfig;
  
  // Активные потоки
  private activeFlows: Map<string, NetworkFlow> = new Map();
  
  // Завершенные потоки
  private completedFlows: NetworkFlow[] = [];
  private maxCompletedFlows: number = 10000;
  
  // Буфер пакетов
  private packetBuffer: NetworkPacket[] = [];
  
  // Сетевые сессии
  private sessions: Map<string, NetworkSession> = new Map();
  
  // Агрегаторы по IP
  private flowAggregators: Map<string, FlowAggregator> = new Map();
  
  // Статистика
  private statistics: NetworkAnalyzerStatistics = {
    totalPacketsProcessed: 0,
    totalFlowsCreated: 0,
    totalAnomaliesDetected: 0,
    anomaliesByType: new Map(),
    lastUpdated: new Date()
  };

  constructor(config?: Partial<NetworkAnalyzerConfig>) {
    this.config = {
      flowTimeout: config?.flowTimeout || 30000,  // 30 секунд
      packetBufferSize: config?.packetBufferSize || 10000,
      anomalyThresholds: {
        portScan: config?.anomalyThresholds?.portScan || 20,
        networkSweep: config?.anomalyThresholds?.networkSweep || 50,
        dataExfiltration: config?.anomalyThresholds?.dataExfiltration || 100000000,  // 100MB
        bruteForce: config?.anomalyThresholds?.bruteForce || 10
      },
      whitelistedIPs: config?.whitelistedIPs || new Set(),
      monitoredPorts: config?.monitoredPorts || new Set([22, 23, 80, 443, 3389, 445, 139])
    };
    
    console.log('[NetworkAnalyzer] Инициализация завершена');
  }

  // ============================================================================
  // ОБРАБОТКА ПАКЕТОВ
  // ============================================================================

  /**
   * Обработка сетевого пакета
   */
  processPacket(packet: NetworkPacket): SecurityAlert[] {
    this.statistics.totalPacketsProcessed++;
    
    // Добавление в буфер
    this.addToPacketBuffer(packet);
    
    // Обновление или создание потока
    const flow = this.updateFlow(packet);
    
    // Проверка на аномалии
    const anomalies = this.detectPacketAnomalies(packet, flow);
    
    // Обновление сессий
    this.updateSession(packet, flow);
    
    // Создание алертов для аномалий
    const alerts: SecurityAlert[] = [];
    
    for (const anomaly of anomalies) {
      const alert = this.createAnomalyAlert(anomaly, flow);
      alerts.push(alert);
      
      this.statistics.totalAnomaliesDetected++;
      const count = this.statistics.anomaliesByType.get(anomaly.type) || 0;
      this.statistics.anomaliesByType.set(anomaly.type, count + 1);
    }
    
    // Очистка старых потоков
    this.cleanupFlows();
    
    return alerts;
  }

  /**
   * Пакетная обработка пакетов
   */
  processPackets(packets: NetworkPacket[]): SecurityAlert[] {
    const allAlerts: SecurityAlert[] = [];
    
    for (const packet of packets) {
      const alerts = this.processPacket(packet);
      allAlerts.push(...alerts);
    }
    
    return allAlerts;
  }

  /**
   * Добавление пакета в буфер
   */
  private addToPacketBuffer(packet: NetworkPacket): void {
    this.packetBuffer.push(packet);
    
    if (this.packetBuffer.length > this.config.packetBufferSize) {
      this.packetBuffer.shift();
    }
  }

  /**
   * Обновление потока
   */
  private updateFlow(packet: NetworkPacket): NetworkFlow {
    const flowId = this.getFlowId(packet);

    let flow = this.activeFlows.get(flowId);

    if (!flow) {
      // Создание нового потока
      flow = {
        id: flowId,
        startTime: packet.timestamp,
        srcIp: packet.srcIp,
        dstIp: packet.dstIp,
        srcPort: packet.srcPort,
        dstPort: packet.dstPort,
        protocol: packet.protocol,
        packetsCount: 1,
        bytesSent: packet.size,
        bytesReceived: 0,
        duration: 0,
        state: 'new'
      };

      this.activeFlows.set(flowId, flow);
      this.statistics.totalFlowsCreated++;

      // Добавляем flow в агрегатор источника
      const srcAggregator = this.getOrCreateAggregator(packet.srcIp);
      srcAggregator.flows.push(flow);

      // Добавляем flow в агрегатор назначения
      const dstAggregator = this.getOrCreateAggregator(packet.dstIp);
      dstAggregator.flows.push(flow);
    } else {
      // Обновление существующего потока
      flow.packetsCount++;
      flow.bytesSent += packet.size;
      flow.duration = packet.timestamp.getTime() - flow.startTime.getTime();
      flow.state = 'established';

      // Проверка направления
      if (packet.srcIp === flow.dstIp) {
        flow.bytesReceived += packet.size;
      }
    }

    // Обновление времени последней активности
    flow.endTime = packet.timestamp;

    return flow;
  }

  /**
   * Получение ID потока
   */
  private getFlowId(packet: NetworkPacket): string {
    // Уникальный ID на основе 5-кортежа
    const src = `${packet.srcIp}:${packet.srcPort}`;
    const dst = `${packet.dstIp}:${packet.dstPort}`;
    
    // Нормализация для двунаправленных потоков
    return [src, dst, packet.protocol].sort().join('|');
  }

  // ============================================================================
  // ОБНАРУЖЕНИЕ АНОМАЛИЙ
  // ============================================================================

  /**
   * Обнаружение аномалий пакета
   */
  private detectPacketAnomalies(packet: NetworkPacket, flow: NetworkFlow): NetworkAnomaly[] {
    const anomalies: NetworkAnomaly[] = [];
    
    // Проверка на сканирование портов
    const portScanAnomaly = this.detectPortScan(packet);
    if (portScanAnomaly) {
      anomalies.push(portScanAnomaly);
    }
    
    // Проверка на сканирование сети
    const networkSweepAnomaly = this.detectNetworkSweep(packet);
    if (networkSweepAnomaly) {
      anomalies.push(networkSweepAnomaly);
    }
    
    // Проверка на эксфильтрацию данных
    const exfilAnomaly = this.detectDataExfiltration(flow);
    if (exfilAnomaly) {
      anomalies.push(exfilAnomaly);
    }
    
    // Проверка на brute force
    const bruteForceAnomaly = this.detectBruteForce(packet, flow);
    if (bruteForceAnomaly) {
      anomalies.push(bruteForceAnomaly);
    }
    
    // Проверка на C2 коммуникацию
    const c2Anomaly = this.detectC2Communication(packet, flow);
    if (c2Anomaly) {
      anomalies.push(c2Anomaly);
    }
    
    // Проверка на DNS туннелирование
    const dnsTunnelAnomaly = this.detectDNSTunneling(packet);
    if (dnsTunnelAnomaly) {
      anomalies.push(dnsTunnelAnomaly);
    }
    
    // Проверка на аномалии протокола
    const protocolAnomaly = this.detectProtocolAnomaly(packet);
    if (protocolAnomaly) {
      anomalies.push(protocolAnomaly);
    }
    
    return anomalies;
  }

  /**
   * Обнаружение сканирования портов
   */
  private detectPortScan(packet: NetworkPacket): NetworkAnomaly | null {
    const srcIp = packet.srcIp;

    // Получение агрегатора для источника
    const aggregator = this.getOrCreateAggregator(srcIp);

    // Подсчет уникальных портов назначения за последнее время
    const recentFlows = aggregator.flows.filter(
      f => f.srcIp === srcIp &&
           (Date.now() - f.startTime.getTime()) < 60000  // За последнюю минуту
    );

    const uniquePorts = new Set(recentFlows.map(f => f.dstPort));

    if (uniquePorts.size >= this.config.anomalyThresholds.portScan) {
      return {
        id: uuidv4(),
        type: NetworkAnomalyType.PORT_SCAN,
        severity: ThreatSeverity.MEDIUM,
        description: `Обнаружено сканирование портов с ${srcIp}: ${uniquePorts.size} уникальных портов`,
        evidence: {
          flows: recentFlows.slice(0, 10),
          statistics: aggregator.statistics,
          indicators: [`Source IP: ${srcIp}`, `Unique ports: ${uniquePorts.size}`],
          packets: []
        },
        timestamp: packet.timestamp,
        confidence: Math.min(uniquePorts.size / this.config.anomalyThresholds.portScan, 0.95)
      };
    }

    return null;
  }

  /**
   * Обнаружение сканирования сети
   */
  private detectNetworkSweep(packet: NetworkPacket): NetworkAnomaly | null {
    const srcIp = packet.srcIp;
    const aggregator = this.getOrCreateAggregator(srcIp);
    
    // Подсчет уникальных IP назначений за последнее время
    const recentFlows = aggregator.flows.filter(
      f => f.srcIp === srcIp && 
           (Date.now() - f.startTime.getTime()) < 60000
    );
    
    const uniqueDestinations = new Set(recentFlows.map(f => f.dstIp));
    
    if (uniqueDestinations.size >= this.config.anomalyThresholds.networkSweep) {
      return {
        id: uuidv4(),
        type: NetworkAnomalyType.NETWORK_SWEEP,
        severity: ThreatSeverity.MEDIUM,
        description: `Обнаружено сканирование сети с ${srcIp}: ${uniqueDestinations.size} уникальных хостов`,
        evidence: {
          flows: recentFlows.slice(0, 10),
          statistics: aggregator.statistics,
          indicators: [`Source IP: ${srcIp}`, `Unique destinations: ${uniqueDestinations.size}`],
          packets: []
        },
        timestamp: packet.timestamp,
        confidence: Math.min(uniqueDestinations.size / this.config.anomalyThresholds.networkSweep, 0.95)
      };
    }
    
    return null;
  }

  /**
   * Обнаружение эксфильтрации данных
   */
  private detectDataExfiltration(flow: NetworkFlow): NetworkAnomaly | null {
    // Проверка на большой объем исходящих данных
    if (flow.bytesSent >= this.config.anomalyThresholds.dataExfiltration) {
      return {
        id: uuidv4(),
        type: NetworkAnomalyType.DATA_EXFILTRATION,
        severity: ThreatSeverity.HIGH,
        description: `Обнаружена потенциальная эксфильтрация данных: ${flow.bytesSent} байт отправлено с ${flow.srcIp}`,
        evidence: {
          flows: [flow],
          statistics: this.getFlowStatistics(flow),
          indicators: [`Large outbound transfer: ${(flow.bytesSent / 1000000).toFixed(2)} MB`],
          packets: []
        },
        timestamp: flow.endTime || new Date(),
        confidence: 0.7
      };
    }
    
    return null;
  }

  /**
   * Обнаружение brute force атаки
   */
  private detectBruteForce(packet: NetworkPacket, flow: NetworkFlow): NetworkAnomaly | null {
    // Проверка портов аутентификации
    const authPorts = [22, 23, 3389, 445, 21];
    
    if (!authPorts.includes(packet.dstPort)) {
      return null;
    }
    
    const aggregator = this.getOrCreateAggregator(packet.srcIp);
    
    // Подсчет попыток подключения к портам аутентификации
    const recentAuthFlows = aggregator.flows.filter(
      f => f.srcIp === packet.srcIp && 
           authPorts.includes(f.dstPort) &&
           (Date.now() - f.startTime.getTime()) < 300000  // За 5 минут
    );
    
    if (recentAuthFlows.length >= this.config.anomalyThresholds.bruteForce) {
      return {
        id: uuidv4(),
        type: NetworkAnomalyType.BRUTE_FORCE,
        severity: ThreatSeverity.HIGH,
        description: `Обнаружена brute force атака с ${packet.srcIp}: ${recentAuthFlows.length} попыток`,
        evidence: {
          flows: recentAuthFlows.slice(0, 20),
          statistics: this.getFlowStatistics(flow),
          indicators: [`Source: ${packet.srcIp}`, `Attempts: ${recentAuthFlows.length}`, `Target port: ${packet.dstPort}`],
          packets: []
        },
        timestamp: packet.timestamp,
        confidence: Math.min(recentAuthFlows.length / this.config.anomalyThresholds.bruteForce, 0.95)
      };
    }
    
    return null;
  }

  /**
   * Обнаружение C2 коммуникации
   */
  private detectC2Communication(packet: NetworkPacket, flow: NetworkFlow): NetworkAnomaly | null {
    // Проверка на периодические подключения (beaconing)
    const aggregator = this.getOrCreateAggregator(packet.srcIp);
    
    const flowsToSameDest = aggregator.flows.filter(
      f => f.srcIp === packet.srcIp && f.dstIp === packet.dstIp
    );
    
    if (flowsToSameDest.length >= 5) {
      // Анализ интервалов между подключениями
      const intervals: number[] = [];
      
      for (let i = 1; i < flowsToSameDest.length; i++) {
        const interval = flowsToSameDest[i].startTime.getTime() - flowsToSameDest[i - 1].startTime.getTime();
        intervals.push(interval);
      }
      
      // Проверка на регулярность интервалов
      if (intervals.length >= 4) {
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((a, b) => a + Math.pow(b - avgInterval, 2), 0) / intervals.length;
        const stdDev = Math.sqrt(variance);
        
        // Низкая вариативность указывает на beaconing
        if (stdDev < avgInterval * 0.2) {
          return {
            id: uuidv4(),
            type: NetworkAnomalyType.C2_COMMUNICATION,
            severity: ThreatSeverity.CRITICAL,
            description: `Обнаружена потенциальная C2 коммуникация (beaconing): ${packet.srcIp} -> ${packet.dstIp}`,
            evidence: {
              flows: flowsToSameDest,
              statistics: { ...this.getFlowStatistics(flow), beaconInterval: avgInterval },
              indicators: [`Beacon interval: ${(avgInterval / 1000).toFixed(1)}s`, `StdDev: ${(stdDev / 1000).toFixed(1)}s`],
              packets: []
            },
            timestamp: packet.timestamp,
            confidence: 0.8
          };
        }
      }
    }
    
    return null;
  }

  /**
   * Обнаружение DNS туннелирования
   */
  private detectDNSTunneling(packet: NetworkPacket): NetworkAnomaly | null {
    // DNS использует порт 53
    if (packet.dstPort !== 53 && packet.srcPort !== 53) {
      return null;
    }
    
    // Проверка на большие DNS запросы (признак туннелирования)
    if (packet.size > 512) {
      return {
        id: uuidv4(),
        type: NetworkAnomalyType.DNS_TUNNELING,
        severity: ThreatSeverity.HIGH,
        description: `Обнаружено потенциальное DNS туннелирование: большой DNS пакет (${packet.size} байт)`,
        evidence: {
          flows: [],
          statistics: this.getFlowStatistics({} as NetworkFlow),
          indicators: [`Packet size: ${packet.size} bytes`, `DNS port: 53`],
          packets: [packet]
        },
        timestamp: packet.timestamp,
        confidence: 0.6
      };
    }
    
    return null;
  }

  /**
   * Обнаружение аномалий протокола
   */
  private detectProtocolAnomaly(packet: NetworkPacket): NetworkAnomaly | null {
    // Проверка на необычные флаги TCP
    if (packet.protocol === 'TCP') {
      const flags = packet.flags || [];
      
      // SYN+FIN (некорректная комбинация)
      if (flags.includes('SYN') && flags.includes('FIN')) {
        return {
          id: uuidv4(),
          type: NetworkAnomalyType.PROTOCOL_ANOMALY,
          severity: ThreatSeverity.MEDIUM,
          description: `Обнаружена аномалия TCP: некорректная комбинация флагов SYN+FIN`,
          evidence: {
            flows: [],
            statistics: {
              packetsPerSecond: 0,
              bytesPerSecond: 0,
              connectionsPerSecond: 0,
              uniqueDestinations: 0,
              protocolDistribution: {},
              portDistribution: {}
            },
            indicators: [`Flags: ${flags.join(',')}`],
            packets: [packet]
          },
          timestamp: packet.timestamp,
          confidence: 0.9
        };
      }

      // NULL scan (нет флагов)
      if (flags.length === 0) {
        return {
          id: uuidv4(),
          type: NetworkAnomalyType.PROTOCOL_ANOMALY,
          severity: ThreatSeverity.MEDIUM,
          description: `Обнаружена аномалия TCP: NULL scan (отсутствие флагов)`,
          evidence: {
            flows: [],
            statistics: {
              packetsPerSecond: 0,
              bytesPerSecond: 0,
              connectionsPerSecond: 0,
              uniqueDestinations: 0,
              protocolDistribution: {},
              portDistribution: {}
            },
            indicators: ['No TCP flags'],
            packets: [packet]
          },
          timestamp: packet.timestamp,
          confidence: 0.85
        };
      }

      // XMAS scan (все флаги)
      if (flags.includes('FIN') && flags.includes('PSH') && flags.includes('URG')) {
        return {
          id: uuidv4(),
          type: NetworkAnomalyType.PROTOCOL_ANOMALY,
          severity: ThreatSeverity.MEDIUM,
          description: `Обнаружена аномалия TCP: XMAS scan`,
          evidence: {
            flows: [],
            statistics: {
              packetsPerSecond: 0,
              bytesPerSecond: 0,
              connectionsPerSecond: 0,
              uniqueDestinations: 0,
              protocolDistribution: {},
              portDistribution: {}
            },
            indicators: [`Flags: ${flags.join(',')}`],
            packets: [packet]
          },
          timestamp: packet.timestamp,
          confidence: 0.9
        };
      }
    }
    
    return null;
  }

  // ============================================================================
  // АГРЕГАЦИЯ И СТАТИСТИКА
  // ============================================================================

  /**
   * Получение или создание агрегатора
   */
  private getOrCreateAggregator(ip: string): FlowAggregator {
    let aggregator = this.flowAggregators.get(ip);
    
    if (!aggregator) {
      aggregator = {
        flows: [],
        statistics: {
          packetsPerSecond: 0,
          bytesPerSecond: 0,
          connectionsPerSecond: 0,
          uniqueDestinations: 0,
          protocolDistribution: {},
          portDistribution: {}
        },
        anomalies: []
      };
      
      this.flowAggregators.set(ip, aggregator);
    }
    
    return aggregator;
  }

  /**
   * Получение статистики потока
   */
  private getFlowStatistics(flow: NetworkFlow): NetworkStatistics {
    const duration = flow.duration || 1;
    
    return {
      packetsPerSecond: flow.packetsCount / (duration / 1000),
      bytesPerSecond: (flow.bytesSent + flow.bytesReceived) / (duration / 1000),
      connectionsPerSecond: 1 / (duration / 1000),
      uniqueDestinations: 1,
      protocolDistribution: { [flow.protocol]: 1 },
      portDistribution: { [flow.dstPort.toString()]: 1 }
    };
  }

  /**
   * Обновление сессии
   */
  private updateSession(packet: NetworkPacket, flow: NetworkFlow): void {
    const sessionId = `${packet.srcIp}|${packet.timestamp.toISOString().slice(0, 13)}`;
    
    let session = this.sessions.get(sessionId);
    
    if (!session) {
      session = {
        id: sessionId,
        srcIp: packet.srcIp,
        startTime: packet.timestamp,
        lastActivity: packet.timestamp,
        flows: [],
        bytesTransferred: 0,
        riskScore: 0,
        anomalies: []
      };
      
      this.sessions.set(sessionId, session);
    }
    
    session.flows.push(flow);
    session.bytesTransferred += packet.size;
    session.lastActivity = packet.timestamp;
  }

  // ============================================================================
  // ОЧИСТКА
  // ============================================================================

  /**
   * Очистка старых потоков
   */
  private cleanupFlows(): void {
    const now = Date.now();
    
    for (const [flowId, flow] of this.activeFlows.entries()) {
      const lastActivity = flow.endTime?.getTime() || flow.startTime.getTime();
      
      if (now - lastActivity > this.config.flowTimeout) {
        // Перемещение в завершенные
        flow.state = 'closed';
        this.completedFlows.push(flow);
        this.activeFlows.delete(flowId);
        
        // Ограничение размера completed flows
        if (this.completedFlows.length > this.maxCompletedFlows) {
          this.completedFlows.shift();
        }
      }
    }
  }

  // ============================================================================
  // СОЗДАНИЕ АЛЕРТОВ
  // ============================================================================

  /**
   * Создание алерта из аномалии
   */
  private createAnomalyAlert(anomaly: NetworkAnomaly, flow: NetworkFlow): SecurityAlert {
    return {
      id: uuidv4(),
      timestamp: anomaly.timestamp,
      title: `Сетевая аномалия: ${anomaly.type}`,
      description: anomaly.description,
      severity: anomaly.severity,
      status: ThreatStatus.NEW,
      category: ThreatCategory.NETWORK,
      attackType: this.mapAnomalyToAttackType(anomaly.type),
      source: 'NetworkAnalyzer',
      events: this.createSecurityEvents(anomaly, flow),
      entities: [
        {
          id: uuidv4(),
          type: EntityType.HOST,
          name: flow.srcIp,
          value: flow.srcIp,
          riskScore: anomaly.confidence * 100,
          role: 'attacker',
          context: {}
        },
        {
          id: uuidv4(),
          type: EntityType.HOST,
          name: flow.dstIp,
          value: flow.dstIp,
          riskScore: 50,
          role: 'victim',
          context: {}
        }
      ],
      mitreAttack: {
        tactics: [],
        techniques: this.mapAnomalyToMitre(anomaly.type)
      },
      riskScore: anomaly.confidence * 100,
      confidence: anomaly.confidence,
      falsePositiveProbability: 1 - anomaly.confidence,
      investigationStatus: {
        stage: 'triage',
        progress: 0,
        findings: [],
        evidenceCollected: []
      },
      tags: ['network', 'anomaly', anomaly.type],
      timeline: [{
        timestamp: anomaly.timestamp,
        event: 'Anomaly detected',
        actor: 'NetworkAnalyzer'
      }],
      evidence: [],
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
  }

  /**
   * Создание security events из аномалии
   */
  private createSecurityEvents(anomaly: NetworkAnomaly, flow: NetworkFlow): SecurityEvent[] {
    return anomaly.evidence.flows.map(f => ({
      id: uuidv4(),
      timestamp: f.startTime,
      eventType: `network_${anomaly.type.toLowerCase()}`,
      source: 'NetworkAnalyzer',
      sourceIp: f.srcIp,
      destinationIp: f.dstIp,
      sourcePort: f.srcPort,
      destinationPort: f.dstPort,
      protocol: f.protocol,
      severity: anomaly.severity,
      category: ThreatCategory.NETWORK,
      rawEvent: {
        packetsCount: f.packetsCount,
        bytesSent: f.bytesSent,
        bytesReceived: f.bytesReceived
      },
      normalizedEvent: {}
    }));
  }

  /**
   * Маппинг типа аномалии на тип атаки
   */
  private mapAnomalyToAttackType(anomalyType: NetworkAnomalyType): AttackType {
    const mapping: Record<NetworkAnomalyType, AttackType> = {
      [NetworkAnomalyType.PORT_SCAN]: AttackType.SUSPICIOUS_BEHAVIOR,
      [NetworkAnomalyType.NETWORK_SWEEP]: AttackType.SUSPICIOUS_BEHAVIOR,
      [NetworkAnomalyType.DATA_EXFILTRATION]: AttackType.DATA_EXFILTRATION,
      [NetworkAnomalyType.C2_COMMUNICATION]: AttackType.C2_COMMUNICATION,
      [NetworkAnomalyType.DNS_TUNNELING]: AttackType.C2_COMMUNICATION,
      [NetworkAnomalyType.LATERAL_MOVEMENT]: AttackType.LATERAL_MOVEMENT,
      [NetworkAnomalyType.BRUTE_FORCE]: AttackType.BRUTE_FORCE,
      [NetworkAnomalyType.DDOS]: AttackType.DDoS,
      [NetworkAnomalyType.SUSPICIOUS_CONNECTION]: AttackType.SUSPICIOUS_BEHAVIOR,
      [NetworkAnomalyType.PROTOCOL_ANOMALY]: AttackType.SUSPICIOUS_BEHAVIOR,
      [NetworkAnomalyType.CERTIFICATE_ANOMALY]: AttackType.SUSPICIOUS_BEHAVIOR
    };
    
    return mapping[anomalyType] || AttackType.UNKNOWN;
  }

  /**
   * Маппинг аномалии на MITRE техники
   */
  private mapAnomalyToMitre(anomalyType: NetworkAnomalyType): any[] {
    const mapping: Record<NetworkAnomalyType, string[]> = {
      [NetworkAnomalyType.PORT_SCAN]: ['T1046'],  // Network Service Scanning
      [NetworkAnomalyType.NETWORK_SWEEP]: ['T1018'],  // Remote System Discovery
      [NetworkAnomalyType.DATA_EXFILTRATION]: ['T1041'],  // Exfiltration Over C2 Channel
      [NetworkAnomalyType.C2_COMMUNICATION]: ['T1071'],  // Application Layer Protocol
      [NetworkAnomalyType.DNS_TUNNELING]: ['T1071.004'],  // DNS
      [NetworkAnomalyType.BRUTE_FORCE]: ['T1110'],  // Brute Force
      [NetworkAnomalyType.LATERAL_MOVEMENT]: ['T1021'],  // Remote Services
      [NetworkAnomalyType.DDOS]: ['T1498'],  // Network Denial of Service
      [NetworkAnomalyType.SUSPICIOUS_CONNECTION]: [],
      [NetworkAnomalyType.PROTOCOL_ANOMALY]: [],
      [NetworkAnomalyType.CERTIFICATE_ANOMALY]: []
    };
    
    return mapping[anomalyType]?.map(id => ({ id, name: '' })) || [];
  }

  // ============================================================================
  // СТАТИСТИКА И МОНИТОРИНГ
  // ============================================================================

  /**
   * Получение статистики
   */
  getStatistics(): NetworkAnalyzerStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }

  /**
   * Получение активных потоков
   */
  getActiveFlows(): NetworkFlow[] {
    return Array.from(this.activeFlows.values());
  }

  /**
   * Получение завершенных потоков
   */
  getCompletedFlows(limit: number = 100): NetworkFlow[] {
    return this.completedFlows.slice(-limit);
  }

  /**
   * Получение сессий
   */
  getSessions(): NetworkSession[] {
    return Array.from(this.sessions.values());
  }

  /**
   * Получение топ talkers
   */
  getTopTalkers(limit: number = 10): { ip: string; bytes: number; connections: number }[] {
    const stats: Map<string, { bytes: number; connections: number }> = new Map();
    
    for (const [ip, aggregator] of this.flowAggregators.entries()) {
      const totalBytes = aggregator.flows.reduce((acc, f) => acc + f.bytesSent + f.bytesReceived, 0);
      stats.set(ip, {
        bytes: totalBytes,
        connections: aggregator.flows.length
      });
    }
    
    return Array.from(stats.entries())
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, limit);
  }

  /**
   * Добавление IP в whitelist
   */
  addToWhitelist(ip: string): void {
    this.config.whitelistedIPs.add(ip);
  }

  /**
   * Удаление IP из whitelist
   */
  removeFromWhitelist(ip: string): void {
    this.config.whitelistedIPs.delete(ip);
  }
}

/**
 * Статистика Network Analyzer
 */
interface NetworkAnalyzerStatistics {
  totalPacketsProcessed: number;
  totalFlowsCreated: number;
  totalAnomaliesDetected: number;
  anomaliesByType: Map<NetworkAnomalyType, number>;
  lastUpdated: Date;
}
