/**
 * Software Defined Perimeter (SDP) - Программно-Определяемый Периметр
 * 
 * Компонент реализует SDP архитектуру для скрытия ресурсов от
 * неавторизованных клиентов. Ресурсы становятся видимыми только
 * после успешной аутентификации и авторизации.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import {
  SdpClientConfig,
  SdpSession,
  Identity,
  ZeroTrustEvent,
  SubjectType,
  ResourceType,
  TrustLevel
} from './zerotrust.types';
import { PolicyDecisionPoint } from './PolicyDecisionPoint';
import { TrustVerifier } from './TrustVerifier';

/**
 * Статус SDP шлюза
 */
enum SdpGatewayStatus {
  /** Шлюз активен */
  ACTIVE = 'ACTIVE',
  
  /** Шлюз недоступен */
  UNAVAILABLE = 'UNAVAILABLE',
  
  /** Шлюз перегружен */
  OVERLOADED = 'OVERLOADED',
  
  /** Шлюз на обслуживании */
  MAINTENANCE = 'MAINTENANCE'
}

/**
 * Конфигурация SDP шлюза
 */
interface SdpGatewayConfig {
  /** ID шлюза */
  gatewayId: string;
  
  /** Адрес шлюза */
  address: string;
  
  /** Порт управления */
  managementPort: number;
  
  /** Порт данных */
  dataPort: number;
  
  /** Максимальное количество сессий */
  maxSessions: number;
  
  /** Вес для load balancing */
  weight: number;
}

/**
 * Конфигурация SDP
 */
export interface SdpConfig {
  /** ID контроллера */
  controllerId: string;
  
  /** Шлюзы */
  gateways: SdpGatewayConfig[];
  
  /** Время жизни сессии (секунды) */
  sessionLifetime: number;
  
  /** Интервал обновления сессии (секунды) */
  sessionRefreshInterval: number;
  
  /** Включить mutual TLS */
  enableMtls: boolean;
  
  /** Включить single packet authorization */
  enableSpa: boolean;
  
  /** Включить knock последовательности */
  enableKnockSequence: boolean;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
}

/**
 * SDP Resource - защищённый ресурс
 */
interface SdpResource {
  /** ID ресурса */
  id: string;
  
  /** Название ресурса */
  name: string;
  
  /** Тип ресурса */
  type: ResourceType;
  
  /** Адрес ресурса */
  address: string;
  
  /** Порт ресурса */
  port: number;
  
  /** Протокол */
  protocol: string;
  
  /** Метки */
  labels: Record<string, string>;
  
  /** Требуемый уровень доверия */
  requiredTrustLevel: TrustLevel;
  
  /** Разрешённые identity */
  allowedIdentities: string[];
  
  /** Активен ли ресурс */
  enabled: boolean;
}

/**
 * SPA Packet - Single Packet Authorization
 */
interface SpaPacket {
  /** Зашифрованный payload */
  encryptedPayload: string;
  
  /** Подпись */
  signature: string;
  
  /** Временная метка */
  timestamp: number;
  
  /** Nonce для защиты от replay */
  nonce: string;
}

/**
 * Software Defined Perimeter Controller
 * 
 * Контроллер SDP для управления доступом к скрытым ресурсам.
 */
export class SoftwareDefinedPerimeter extends EventEmitter {
  /** Конфигурация */
  private config: SdpConfig;
  
  /** PDP для проверок политик */
  private pdp: PolicyDecisionPoint | null;
  
  /** Trust Verifier для проверок доверия */
  private trustVerifier: TrustVerifier | null;
  
  /** SDP шлюзы */
  private gateways: Map<string, SdpGatewayConfig & { status: SdpGatewayStatus; activeSessions: number }>;
  
  /** SDP ресурсы */
  private resources: Map<string, SdpResource>;
  
  /** Активные сессии */
  private sessions: Map<string, SdpSession>;
  
  /** Конфигурации клиентов */
  private clientConfigs: Map<string, SdpClientConfig>;
  
  /** SPA nonces для защиты от replay */
  private spaNonces: Set<string>;
  
  /** Статистика */
  private stats: {
    /** Всего сессий создано */
    totalSessionsCreated: number;
    /** Активные сессии */
    activeSessions: number;
    /** Всего подключений */
    totalConnections: number;
    /** SPA пакетов обработано */
    spaPacketsProcessed: number;
    /** Отклонённых SPA пакетов */
    spaPacketsRejected: number;
  };

  constructor(config: Partial<SdpConfig> = {}) {
    super();
    
    this.config = {
      controllerId: config.controllerId ?? `sdp-controller-${uuidv4().substring(0, 8)}`,
      gateways: config.gateways ?? [],
      sessionLifetime: config.sessionLifetime ?? 3600, // 1 час
      sessionRefreshInterval: config.sessionRefreshInterval ?? 300, // 5 минут
      enableMtls: config.enableMtls ?? true,
      enableSpa: config.enableSpa ?? true,
      enableKnockSequence: config.enableKnockSequence ?? false,
      enableVerboseLogging: config.enableVerboseLogging ?? false
    };
    
    this.pdp = null;
    this.trustVerifier = null;
    this.gateways = new Map();
    this.resources = new Map();
    this.sessions = new Map();
    this.clientConfigs = new Map();
    this.spaNonces = new Set();
    
    this.stats = {
      totalSessionsCreated: 0,
      activeSessions: 0,
      totalConnections: 0,
      spaPacketsProcessed: 0,
      spaPacketsRejected: 0
    };
    
    // Инициализируем шлюзы
    for (const gateway of this.config.gateways) {
      this.gateways.set(gateway.gatewayId, {
        ...gateway,
        status: SdpGatewayStatus.ACTIVE,
        activeSessions: 0
      });
    }
    
    this.log('SDP', 'SoftwareDefinedPerimeter инициализирован', {
      controllerId: this.config.controllerId,
      gatewayCount: this.gateways.size
    });
  }

  /**
   * Установить PDP
   */
  public setPdp(pdp: PolicyDecisionPoint): void {
    this.pdp = pdp;
    this.log('SDP', 'PDP установлен');
  }

  /**
   * Установить Trust Verifier
   */
  public setTrustVerifier(trustVerifier: TrustVerifier): void {
    this.trustVerifier = trustVerifier;
    this.log('SDP', 'TrustVerifier установлен');
  }

  /**
   * Зарегистрировать ресурс
   */
  public registerResource(resource: SdpResource): void {
    this.resources.set(resource.id, resource);
    
    this.log('SDP', 'Ресурс зарегистрирован', {
      resourceId: resource.id,
      name: resource.name,
      address: resource.address
    });
    
    this.emit('resource:registered', resource);
  }

  /**
   * Отменить регистрацию ресурса
   */
  public unregisterResource(resourceId: string): boolean {
    const removed = this.resources.delete(resourceId);
    
    if (removed) {
      this.log('SDP', 'Ресурс отменён', { resourceId });
      this.emit('resource:unregistered', { resourceId });
    }
    
    return removed;
  }

  /**
   * Обработать SPA пакет (Single Packet Authorization)
   */
  public async processSpaPacket(
    spaPacket: SpaPacket,
    clientPublicKey: string
  ): Promise<{
    success: boolean;
    identity?: Identity;
    requestedResources?: string[];
    error?: string;
  }> {
    this.stats.spaPacketsProcessed++;
    
    if (!this.config.enableSpa) {
      return {
        success: false,
        error: 'SPA отключён'
      };
    }
    
    // Проверяем nonce для защиты от replay
    if (this.spaNonces.has(spaPacket.nonce)) {
      this.stats.spaPacketsRejected++;
      return {
        success: false,
        error: 'Replay attack detected - nonce уже использован'
      };
    }
    
    // Проверяем временную метку (защита от replay с задержкой)
    const now = Date.now();
    const maxAge = 60000; // 1 минута
    
    if (Math.abs(now - spaPacket.timestamp) > maxAge) {
      this.stats.spaPacketsRejected++;
      return {
        success: false,
        error: 'SPA packet expired'
      };
    }
    
    // Сохраняем nonce
    this.spaNonces.add(spaPacket.nonce);
    
    // Очищаем старые nonces
    if (this.spaNonces.size > 10000) {
      const toDelete = Array.from(this.spaNonces).slice(0, 5000);
      toDelete.forEach(n => this.spaNonces.delete(n));
    }
    
    try {
      // Расшифровываем payload
      const payload = this.decryptSpaPayload(spaPacket.encryptedPayload, clientPublicKey);
      
      // Проверяем подпись
      const signatureValid = this.verifySpaSignature(spaPacket, clientPublicKey);
      
      if (!signatureValid) {
        this.stats.spaPacketsRejected++;
        return {
          success: false,
          error: 'Invalid signature'
        };
      }
      
      // Парсим payload
      const parsedPayload = JSON.parse(payload);
      
      return {
        success: true,
        identity: parsedPayload.identity,
        requestedResources: parsedPayload.resources
      };
      
    } catch (error) {
      this.stats.spaPacketsRejected++;
      return {
        success: false,
        error: error instanceof Error ? error.message : 'SPA decryption failed'
      };
    }
  }

  /**
   * Расшифровать SPA payload
   */
  private decryptSpaPayload(encryptedPayload: string, clientPublicKey: string): string {
    // В реальной реализации здесь была бы расшифровка
    // с использованием закрытого ключа контроллера
    return Buffer.from(encryptedPayload, 'base64').toString('utf-8');
  }

  /**
   * Проверить подпись SPA
   */
  private verifySpaSignature(spaPacket: SpaPacket, clientPublicKey: string): boolean {
    // В реальной реализации здесь была бы проверка подписи
    // с использованием публичного ключа клиента
    return true;
  }

  /**
   * Создать сессию SDP
   */
  public async createSession(
    clientId: string,
    identity: Identity,
    requestedResourceIds: string[],
    trustLevel: TrustLevel
  ): Promise<SdpSession> {
    this.log('SDP', 'Создание сессии SDP', {
      clientId,
      identityId: identity.id,
      resourceCount: requestedResourceIds.length
    });
    
    // Проверяем доверие
    if (this.trustVerifier) {
      const currentTrust = this.trustVerifier.getTrustLevel(clientId);
      
      if (currentTrust < TrustLevel.LOW) {
        throw new Error('Недостаточный уровень доверия для создания сессии SDP');
      }
    }
    
    // Проверяем ресурсы
    const allowedResources: SdpResource[] = [];
    
    for (const resourceId of requestedResourceIds) {
      const resource = this.resources.get(resourceId);
      
      if (!resource || !resource.enabled) {
        continue;
      }
      
      // Проверяем уровень доверия
      if (trustLevel < resource.requiredTrustLevel) {
        continue;
      }
      
      // Проверяем доступ по identity
      if (resource.allowedIdentities.length > 0 &&
          !resource.allowedIdentities.includes(identity.id)) {
        continue;
      }
      
      allowedResources.push(resource);
    }
    
    if (allowedResources.length === 0) {
      throw new Error('Нет доступных ресурсов для клиента');
    }
    
    // Выбираем шлюз
    const gateway = this.selectGateway();
    
    if (!gateway) {
      throw new Error('Нет доступных шлюзов');
    }
    
    // Создаём сессию
    const sessionId = uuidv4();
    const now = new Date();
    
    const session: SdpSession = {
      sessionId,
      clientId,
      controllerId: this.config.controllerId,
      gatewayId: gateway.gatewayId,
      startedAt: now,
      expiresAt: new Date(now.getTime() + this.config.sessionLifetime * 1000),
      status: 'ACTIVE',
      allocatedResources: {
        virtualIp: this.generateVirtualIp(),
        allocatedPorts: allowedResources.map(r => r.port),
        tunnelInterface: `sdp-${sessionId.substring(0, 8)}`
      },
      stats: {
        bytesSent: 0,
        bytesReceived: 0,
        packetCount: 0
      }
    };
    
    this.sessions.set(sessionId, session);
    this.stats.totalSessionsCreated++;
    this.stats.activeSessions = this.sessions.size;
    
    // Обновляем статистику шлюза
    const gw = this.gateways.get(gateway.gatewayId);
    if (gw) {
      gw.activeSessions++;
    }
    
    // Создаём конфигурацию клиента
    const clientConfig = this.createClientConfig(clientId, identity, session, allowedResources);
    this.clientConfigs.set(clientId, clientConfig);
    
    this.log('SDP', 'Сессия SDP создана', {
      sessionId,
      gatewayId: gateway.gatewayId,
      resourceCount: allowedResources.length,
      expiresAt: session.expiresAt
    });
    
    this.emit('session:created', { session, clientConfig });
    
    return session;
  }

  /**
   * Выбрать шлюз для сессии
   */
  private selectGateway(): SdpGatewayConfig & { status: SdpGatewayStatus; activeSessions: number } | undefined {
    // Фильтруем активные шлюзы
    const availableGateways = Array.from(this.gateways.values())
      .filter(gw => gw.status === SdpGatewayStatus.ACTIVE)
      .filter(gw => gw.activeSessions < gw.maxSessions);
    
    if (availableGateways.length === 0) {
      return undefined;
    }
    
    // Выбираем шлюз с наименьшей загрузкой (weighted least connections)
    return availableGateways.reduce((best, current) => {
      const bestLoad = best.activeSessions / best.weight;
      const currentLoad = current.activeSessions / current.weight;
      
      return currentLoad < bestLoad ? current : best;
    });
  }

  /**
   * Сгенерировать виртуальный IP
   */
  private generateVirtualIp(): string {
    // Генерируем IP из диапазона 100.64.0.0/10 (CGNAT range)
    const second = 64 + Math.floor(Math.random() * 64);
    const third = Math.floor(Math.random() * 256);
    const fourth = Math.floor(Math.random() * 254) + 1;
    
    return `100.${second}.${third}.${fourth}`;
  }

  /**
   * Создать конфигурацию клиента
   */
  private createClientConfig(
    clientId: string,
    identity: Identity,
    session: SdpSession,
    resources: SdpResource[]
  ): SdpClientConfig {
    const gateway = this.gateways.get(session.gatewayId);
    
    // Генерируем сертификат клиента
    const { certificate, privateKey } = this.generateClientCertificate(clientId, identity);
    
    return {
      clientId,
      clientCertificate: certificate,
      encryptedPrivateKey: privateKey, // В реальности должен быть зашифрован
      controllerAddresses: [`https://${this.config.controllerId}.local:8443`],
      gatewayAddresses: [`${gateway?.address}:${gateway?.dataPort}`],
      allowedResources: resources.map(r => r.id),
      validUntil: session.expiresAt,
      refreshInterval: this.config.sessionRefreshInterval
    };
  }

  /**
   * Сгенерировать сертификат клиента
   */
  private generateClientCertificate(clientId: string, identity: Identity): {
    certificate: string;
    privateKey: string;
  } {
    // В реальной реализации здесь была бы генерация сертификата
    // с использованием CA контроллера
    return {
      certificate: `-----BEGIN CERTIFICATE-----\nMIIC...${clientId}...${identity.id}...`,
      privateKey: `-----BEGIN PRIVATE KEY-----\nMIIE...encrypted...`
    };
  }

  /**
   * Получить сессию
   */
  public getSession(sessionId: string): SdpSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * Обновить сессию
   */
  public refreshSession(sessionId: string): SdpSession {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      throw new Error(`Сессия не найдена: ${sessionId}`);
    }
    
    if (session.status !== 'ACTIVE') {
      throw new Error(`Сессия не активна: ${session.status}`);
    }
    
    // Продлеваем сессию
    session.expiresAt = new Date(Date.now() + this.config.sessionLifetime * 1000);
    
    this.log('SDP', 'Сессия обновлена', { sessionId });
    this.emit('session:refreshed', { sessionId });
    
    return session;
  }

  /**
   * Завершить сессию
   */
  public terminateSession(sessionId: string, reason?: string): boolean {
    const session = this.sessions.get(sessionId);
    
    if (!session) {
      return false;
    }
    
    session.status = 'TERMINATED';
    this.sessions.delete(sessionId);
    this.stats.activeSessions = this.sessions.size;
    
    // Обновляем статистику шлюза
    const gw = this.gateways.get(session.gatewayId);
    if (gw) {
      gw.activeSessions = Math.max(0, gw.activeSessions - 1);
    }
    
    this.log('SDP', 'Сессия завершена', { sessionId, reason });
    this.emit('session:terminated', { sessionId, reason });
    
    return true;
  }

  /**
   * Завершить все сессии клиента
   */
  public terminateClientSessions(clientId: string): number {
    let terminated = 0;
    
    for (const [sessionId, session] of this.sessions.entries()) {
      if (session.clientId === clientId) {
        this.terminateSession(sessionId, 'Client terminated');
        terminated++;
      }
    }
    
    this.log('SDP', 'Завершены сессии клиента', { clientId, count: terminated });
    
    return terminated;
  }

  /**
   * Получить конфигурацию клиента
   */
  public getClientConfig(clientId: string): SdpClientConfig | undefined {
    return this.clientConfigs.get(clientId);
  }

  /**
   * Получить все активные сессии
   */
  public getActiveSessions(): SdpSession[] {
    return Array.from(this.sessions.values())
      .filter(s => s.status === 'ACTIVE');
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats & {
    /** Количество шлюзов */
    gatewayCount: number;
    /** Количество ресурсов */
    resourceCount: number;
    /** Клиентских конфигураций */
    clientConfigCount: number;
  } {
    return {
      ...this.stats,
      gatewayCount: this.gateways.size,
      resourceCount: this.resources.size,
      clientConfigCount: this.clientConfigs.size
    };
  }

  /**
   * Получить статус шлюзов
   */
  public getGatewayStatus(): Array<{
    gatewayId: string;
    address: string;
    status: SdpGatewayStatus;
    activeSessions: number;
    maxSessions: number;
    utilization: number;
  }> {
    return Array.from(this.gateways.values()).map(gw => ({
      gatewayId: gw.gatewayId,
      address: gw.address,
      status: gw.status,
      activeSessions: gw.activeSessions,
      maxSessions: gw.maxSessions,
      utilization: gw.maxSessions > 0 ? gw.activeSessions / gw.maxSessions : 0
    }));
  }

  /**
   * Логирование
   */
  private log(component: string, message: string, data?: unknown): void {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'SESSION_CREATED',
      timestamp: new Date(),
      subject: {
        id: 'system',
        type: SubjectType.SYSTEM,
        name: component
      },
      details: { message, ...data },
      severity: 'INFO',
      correlationId: uuidv4()
    };
    
    this.emit('log', event);
    
    if (this.config.enableVerboseLogging) {
      console.log(`[SDP] ${new Date().toISOString()} - ${message}`, data ?? '');
    }
  }
}

export default SoftwareDefinedPerimeter;
