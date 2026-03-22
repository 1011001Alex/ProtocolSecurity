/**
 * Service Mesh mTLS - Mutual TLS для Микросервисов
 * 
 * Компонент управляет взаимной TLS аутентификацией между сервисами
 * в service mesh архитектуре. Обеспечивает автоматическую генерацию,
 * ротацию и отзыв сертификатов для каждого сервиса.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import * as tls from 'tls';
import {
  MtlsCertificate,
  CertificateStatus,
  ServiceMeshConfig,
  ZeroTrustEvent,
  SubjectType
} from './zerotrust.types';

/**
 * Конфигурация CA (Certificate Authority)
 */
interface CaConfig {
  /** ID CA */
  caId: string;
  
  /** Название CA */
  name: string;
  
  /** PEM кодированный CA сертификат */
  certificatePem: string;
  
  /** PEM кодированный закрытый ключ CA */
  privateKeyPem: string;
  
  /** Срок жизни выдаваемых сертификатов (часы) */
  certificateLifetimeHours: number;
  
  /** Алгоритм подписи */
  signatureAlgorithm: string;
}

/**
 * Конфигурация Service Mesh mTLS
 */
export interface ServiceMeshMtlsConfig {
  /** Название mesh */
  meshName: string;
  
  /** CA конфигурация */
  ca: CaConfig;
  
  /** Режим mTLS */
  mtlsMode: 'STRICT' | 'PERMISSIVE' | 'DISABLE';
  
  /** Минимальная версия TLS */
  minTlsVersion: 'TLS1.2' | 'TLS1.3';
  
  /** Разрешённые cipher suites */
  cipherSuites: string[];
  
  /** Интервал ротации сертификатов (часы) */
  rotationIntervalHours: number;
  
  /** Порог предупреждения об истечении (часы) */
  expirationWarningHours: number;
  
  /** Включить автоматическую ротацию */
  enableAutoRotation: boolean;
  
  /** Включить CRL (Certificate Revocation List) */
  enableCrl: boolean;
  
  /** Включить OCSP stapling */
  enableOcspStapling: boolean;
  
  /** Включить SPIFFE ID */
  enableSpiffeId: boolean;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
}

/**
 * Сервис в service mesh
 */
interface MeshService {
  /** ID сервиса */
  serviceId: string;
  
  /** Название сервиса */
  name: string;
  
  /** Namespace */
  namespace: string;
  
  /** Версия сервиса */
  version: string;
  
  /** Порты сервиса */
  ports: number[];
  
  /** Метки */
  labels: Record<string, string>;
  
  /** Текущий сертификат */
  certificate?: MtlsCertificate;
  
  /** Время последнего обновления */
  lastUpdatedAt: Date;
  
  /** Статус сервиса */
  status: 'ACTIVE' | 'INACTIVE' | 'DEGRADED';
}

/**
 * Service Mesh mTLS Manager
 * 
 * Управляет mTLS сертификатами и конфигурацией service mesh.
 */
export class ServiceMeshMTLS extends EventEmitter {
  /** Конфигурация */
  private config: ServiceMeshMtlsConfig;
  
  /** Сервисы в mesh */
  private services: Map<string, MeshService>;
  
  /** Выданные сертификаты */
  private certificates: Map<string, MtlsCertificate>;
  
  /** Отозванные сертификаты (serial numbers) */
  private revokedCertificates: Set<string>;
  
  /** CRL (Certificate Revocation List) */
  private crl: {
    /** Номер версии CRL */
    version: number;
    /** Время выпуска */
    thisUpdate: Date;
    /** Время следующего выпуска */
    nextUpdate: Date;
    /** Отозванные сертификаты */
    revokedCertificates: Array<{
      serialNumber: string;
      revocationDate: Date;
      reason: string;
    }>;
  };
  
  /** Таймеры ротации */
  private rotationTimers: Map<string, NodeJS.Timeout>;
  
  /** Статистика */
  private stats: {
    /** Всего сервисов */
    totalServices: number;
    /** Активных сертификатов */
    activeCertificates: number;
    /** Отозванных сертификатов */
    revokedCertificates: number;
    /** Ротаций выполнено */
    rotationsPerformed: number;
    /** Предупреждений об истечении */
    expirationWarnings: number;
  };

  constructor(config: Partial<ServiceMeshMtlsConfig> = {}) {
    super();
    
    this.config = {
      meshName: config.meshName ?? `mesh-${uuidv4().substring(0, 8)}`,
      ca: config.ca ?? {
        caId: 'root-ca',
        name: 'Root CA',
        certificatePem: '',
        privateKeyPem: '',
        certificateLifetimeHours: 8760, // 1 год
        signatureAlgorithm: 'SHA384'
      },
      mtlsMode: config.mtlsMode ?? 'STRICT',
      minTlsVersion: config.minTlsVersion ?? 'TLS1.3',
      cipherSuites: config.cipherSuites ?? [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256'
      ],
      rotationIntervalHours: config.rotationIntervalHours ?? 24,
      expirationWarningHours: config.expirationWarningHours ?? 72,
      enableAutoRotation: config.enableAutoRotation ?? true,
      enableCrl: config.enableCrl ?? true,
      enableOcspStapling: config.enableOcspStapling ?? false,
      enableSpiffeId: config.enableSpiffeId ?? true,
      enableVerboseLogging: config.enableVerboseLogging ?? false
    };
    
    this.services = new Map();
    this.certificates = new Map();
    this.revokedCertificates = new Set();
    this.crl = {
      version: 1,
      thisUpdate: new Date(),
      nextUpdate: new Date(Date.now() + 86400000), // 24 часа
      revokedCertificates: []
    };
    this.rotationTimers = new Map();
    
    this.stats = {
      totalServices: 0,
      activeCertificates: 0,
      revokedCertificates: 0,
      rotationsPerformed: 0,
      expirationWarnings: 0
    };
    
    this.log('mTLS', 'ServiceMeshMTLS инициализирован', {
      meshName: this.config.meshName,
      mtlsMode: this.config.mtlsMode
    });
  }

  /**
   * Зарегистрировать сервис в mesh
   */
  public registerService(service: Omit<MeshService, 'lastUpdatedAt' | 'status'>): MeshService {
    const now = new Date();
    
    const newService: MeshService = {
      ...service,
      lastUpdatedAt: now,
      status: 'ACTIVE'
    };
    
    this.services.set(service.serviceId, newService);
    this.stats.totalServices = this.services.size;
    
    this.log('mTLS', 'Сервис зарегистрирован', {
      serviceId: service.serviceId,
      name: service.name,
      namespace: service.namespace
    });
    
    // Выдаём сертификат сервису
    this.issueCertificate(service.serviceId).catch(error => {
      this.log('mTLS', 'Ошибка выдачи сертификата', {
        serviceId: service.serviceId,
        error
      });
    });
    
    this.emit('service:registered', newService);
    
    return newService;
  }

  /**
   * Отменить регистрацию сервиса
   */
  public unregisterService(serviceId: string): boolean {
    const service = this.services.get(serviceId);
    
    if (!service) {
      return false;
    }
    
    // Отозываем сертификат
    if (service.certificate) {
      this.revokeCertificate(service.certificate.id, 'Service unregistered');
    }
    
    // Останавливаем ротацию
    const timer = this.rotationTimers.get(serviceId);
    if (timer) {
      clearInterval(timer);
      this.rotationTimers.delete(serviceId);
    }
    
    this.services.delete(serviceId);
    this.stats.totalServices = this.services.size;
    
    this.log('mTLS', 'Сервис отменён', { serviceId });
    this.emit('service:unregistered', { serviceId });
    
    return true;
  }

  /**
   * Выдать сертификат сервису
   */
  public async issueCertificate(serviceId: string): Promise<MtlsCertificate> {
    const service = this.services.get(serviceId);
    
    if (!service) {
      throw new Error(`Сервис не найден: ${serviceId}`);
    }
    
    this.log('mTLS', 'Выдача сертификата', { serviceId });
    
    // Генерируем ключевую пару
    const { publicKey, privateKey } = this.generateKeyPair();
    
    // Создаём SPIFFE ID
    const spiffeId = this.config.enableSpiffeId ? 
      `spiffe://${this.config.meshName}.local/ns/${service.namespace}/sa/${service.name}` : 
      undefined;
    
    // Генерируем SAN (Subject Alternative Names)
    const subjectAltNames = this.generateSubjectAltNames(service, spiffeId);
    
    // Создаём сертификат
    const certificate = this.createCertificate({
      publicKey,
      subjectAltNames,
      spiffeId,
      service
    });
    
    // Сохраняем сертификат
    this.certificates.set(certificate.id, certificate);
    service.certificate = certificate;
    service.lastUpdatedAt = new Date();
    
    this.stats.activeCertificates = this.certificates.size;
    
    // Настраиваем автоматическую ротацию
    if (this.config.enableAutoRotation) {
      this.scheduleRotation(serviceId, certificate.expiresAt);
    }
    
    this.log('mTLS', 'Сертификат выдан', {
      certificateId: certificate.id,
      serviceId,
      expiresAt: certificate.expiresAt,
      spiffeId
    });
    
    this.emit('certificate:issued', certificate);
    
    return certificate;
  }

  /**
   * Сгенерировать ключевую пару
   */
  private generateKeyPair(): { publicKey: string; privateKey: string } {
    // В реальной реализации здесь была бы генерация ключей
    // с использованием crypto.generateKeyPairSync
    const keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-384',
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey
    };
  }

  /**
   * Сгенерировать Subject Alternative Names
   */
  private generateSubjectAltNames(
    service: MeshService,
    spiffeId?: string
  ): string[] {
    const sans: string[] = [];
    
    // DNS names
    sans.push(`${service.name}.${service.namespace}.svc`);
    sans.push(`${service.name}.${service.namespace}.svc.cluster.local`);
    sans.push(`${service.name}`);
    
    // SPIFFE ID
    if (spiffeId && this.config.enableSpiffeId) {
      sans.push(`URI:${spiffeId}`);
    }
    
    return sans;
  }

  /**
   * Создать сертификат
   */
  private createCertificate(options: {
    publicKey: string;
    subjectAltNames: string[];
    spiffeId?: string;
    service: MeshService;
  }): MtlsCertificate {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.config.ca.certificateLifetimeHours * 3600000);
    
    // Генерируем серийный номер
    const serialNumber = crypto.randomBytes(20).toString('hex');
    
    // Создаём сертификат (в упрощённом виде)
    const certificateId = uuidv4();
    
    const certificate: MtlsCertificate = {
      id: certificateId,
      serialNumber,
      commonName: `${options.service.name}.${options.service.namespace}.svc`,
      subjectAltNames: options.subjectAltNames,
      certificatePem: `-----BEGIN CERTIFICATE-----\nMIIC...${certificateId}...${serialNumber}...`,
      privateKeyPem: options.service.certificate?.privateKeyPem,
      caCertificatePem: this.config.ca.certificatePem,
      issuedAt: now,
      expiresAt,
      status: CertificateStatus.ACTIVE,
      keyUsage: ['digitalSignature', 'keyEncipherment'],
      extendedKeyUsage: ['serverAuth', 'clientAuth'],
      fingerprint: crypto.createHash('sha256').update(serialNumber).digest('hex'),
      spiffeId: options.spiffeId
    };
    
    return certificate;
  }

  /**
   * Запланировать ротацию сертификата
   */
  private scheduleRotation(serviceId: string, expiresAt: Date): void {
    // Очищаем предыдущий таймер
    const existingTimer = this.rotationTimers.get(serviceId);
    if (existingTimer) {
      clearInterval(existingTimer);
    }
    
    // Вычисляем время до ротации (за 24 часа до истечения)
    const rotationTime = expiresAt.getTime() - (24 * 3600000);
    const delay = Math.max(0, rotationTime - Date.now());
    
    // Планируем следующую ротацию
    const timer = setTimeout(() => {
      this.rotateCertificate(serviceId).catch(error => {
        this.log('mTLS', 'Ошибка ротации сертификата', { serviceId, error });
      });
    }, delay);
    
    this.rotationTimers.set(serviceId, timer);
    
    this.log('mTLS', 'Ротация сертификата запланирована', {
      serviceId,
      delay: Math.round(delay / 1000 / 60) + ' минут'
    });
  }

  /**
   * Ротировать сертификат сервиса
   */
  public async rotateCertificate(serviceId: string): Promise<MtlsCertificate> {
    const service = this.services.get(serviceId);
    
    if (!service) {
      throw new Error(`Сервис не найден: ${serviceId}`);
    }
    
    this.log('mTLS', 'Ротация сертификата', { serviceId });
    
    // Отзываем старый сертификат
    if (service.certificate) {
      this.revokeCertificate(service.certificate.id, 'Rotation');
    }
    
    // Выдаём новый сертификат
    const newCertificate = await this.issueCertificate(serviceId);
    
    this.stats.rotationsPerformed++;
    
    this.emit('certificate:rotated', {
      serviceId,
      newCertificate
    });
    
    return newCertificate;
  }

  /**
   * Отозвать сертификат
   */
  public revokeCertificate(certificateId: string, reason: string): boolean {
    const certificate = this.certificates.get(certificateId);
    
    if (!certificate) {
      return false;
    }
    
    // Обновляем статус сертификата
    certificate.status = CertificateStatus.REVOKED;
    
    // Добавляем в список отозванных
    this.revokedCertificates.add(certificate.serialNumber);
    this.stats.revokedCertificates = this.revokedCertificates.size;
    
    // Добавляем в CRL
    this.crl.revokedCertificates.push({
      serialNumber: certificate.serialNumber,
      revocationDate: new Date(),
      reason
    });
    
    // Обновляем CRL
    this.crl.version++;
    this.crl.thisUpdate = new Date();
    
    this.log('mTLS', 'Сертификат отозван', {
      certificateId,
      serialNumber: certificate.serialNumber,
      reason
    });
    
    this.emit('certificate:revoked', {
      certificateId,
      reason
    });
    
    return true;
  }

  /**
   * Получить TLS опции для сервера
   */
  public getServerTlsOptions(serviceId: string): tls.TlsOptions {
    const service = this.services.get(serviceId);
    
    if (!service || !service.certificate) {
      throw new Error(`Сервис или сертификат не найдены: ${serviceId}`);
    }
    
    const options: tls.TlsOptions = {
      key: service.certificate.privateKeyPem,
      cert: service.certificate.certificatePem,
      ca: this.config.ca.certificatePem,
      
      // Требовать клиентский сертификат
      requestCert: this.config.mtlsMode === 'STRICT',
      rejectUnauthorized: this.config.mtlsMode === 'STRICT',
      
      // Минимальная версия TLS
      minVersion: this.config.minTlsVersion === 'TLS1.3' ? 'TLSv1.3' : 'TLSv1.2',
      
      // Cipher suites
      ciphers: this.config.cipherSuites.join(':'),
      
      // Honor server cipher preference
      honorCipherOrder: true,
      
      // Session settings
      sessionTimeout: 600
    };
    
    // OCSP stapling
    if (this.config.enableOcspStapling) {
      options.OCSPStapling = true;
    }
    
    return options;
  }

  /**
   * Получить TLS опции для клиента
   */
  public getClientTlsOptions(serviceId: string): tls.ConnectionOptions {
    const service = this.services.get(serviceId);
    
    if (!service || !service.certificate) {
      throw new Error(`Сервис или сертификат не найдены: ${serviceId}`);
    }
    
    const options: tls.ConnectionOptions = {
      key: service.certificate.privateKeyPem,
      cert: service.certificate.certificatePem,
      ca: this.config.ca.certificatePem,
      
      // Проверка сервера
      rejectUnauthorized: true,
      
      // Минимальная версия TLS
      minVersion: this.config.minTlsVersion === 'TLS1.3' ? 'TLSv1.3' : 'TLSv1.2',
      
      // Servername для SNI
      servername: `${service.name}.${service.namespace}.svc`
    };
    
    return options;
  }

  /**
   * Проверить сертификат на отзыв
   */
  public isCertificateRevoked(serialNumber: string): boolean {
    return this.revokedCertificates.has(serialNumber);
  }

  /**
   * Получить CRL
   */
  public getCrl(): typeof this.crl {
    return { ...this.crl };
  }

  /**
   * Проверить истечение сертификатов
   */
  public checkExpiringCertificates(): MtlsCertificate[] {
    const now = new Date();
    const warningThreshold = new Date(now.getTime() + this.config.expirationWarningHours * 3600000);
    
    const expiringCertificates: MtlsCertificate[] = [];
    
    for (const certificate of this.certificates.values()) {
      if (certificate.status !== CertificateStatus.ACTIVE) {
        continue;
      }
      
      if (certificate.expiresAt <= warningThreshold) {
        expiringCertificates.push(certificate);
        this.stats.expirationWarnings++;
        
        this.log('mTLS', 'Предупреждение об истечении сертификата', {
          certificateId: certificate.id,
          expiresAt: certificate.expiresAt,
          serviceId: this.getServiceIdByCertificate(certificate.id)
        });
        
        this.emit('certificate:expiring_soon', certificate);
      }
    }
    
    return expiringCertificates;
  }

  /**
   * Получить ID сервиса по сертификату
   */
  private getServiceIdByCertificate(certificateId: string): string | undefined {
    for (const [serviceId, service] of this.services.entries()) {
      if (service.certificate?.id === certificateId) {
        return serviceId;
      }
    }
    return undefined;
  }

  /**
   * Получить сервис
   */
  public getService(serviceId: string): MeshService | undefined {
    return this.services.get(serviceId);
  }

  /**
   * Получить сертификат
   */
  public getCertificate(certificateId: string): MtlsCertificate | undefined {
    return this.certificates.get(certificateId);
  }

  /**
   * Получить все сервисы
   */
  public getAllServices(): MeshService[] {
    return Array.from(this.services.values());
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats & {
    /** Сертификаты с истекающим сроком */
    expiringCertificates: number;
  } {
    const expiringCount = this.checkExpiringCertificates().length;
    
    return {
      ...this.stats,
      expiringCertificates: expiringCount
    };
  }

  /**
   * Экспорт конфигурации mesh
   */
  public exportMeshConfig(): ServiceMeshConfig {
    return {
      meshName: this.config.meshName,
      version: '1.0',
      mtls: {
        mode: this.config.mtlsMode,
        minTlsVersion: this.config.minTlsVersion === 'TLS1.3' ? 'TLS1.3' : 'TLS1.2',
        cipherSuites: this.config.cipherSuites,
        certificateRotationInterval: this.config.rotationIntervalHours,
        certificateLifetime: this.config.ca.certificateLifetimeHours
      },
      services: this.getAllServices().map(s => ({
        name: s.name,
        namespace: s.namespace,
        version: s.version,
        ports: s.ports,
        labels: s.labels
      })),
      trafficPolicies: {
        loadBalancer: 'ROUND_ROBIN',
        connectionPool: {
          maxConnections: 100,
          maxPendingRequests: 100,
          maxRequests: 1000,
          maxRetries: 3
        },
        outlierDetection: {
          consecutiveErrors: 5,
          interval: 30,
          baseEjectionTime: 30,
          maxEjectionPercent: 50
        }
      }
    };
  }

  /**
   * Логирование
   */
  private log(component: string, message: string, data?: unknown): void {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'CERTIFICATE_ISSUED',
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
      console.log(`[mTLS] ${new Date().toISOString()} - ${message}`, data ?? '');
    }
  }
}

export default ServiceMeshMTLS;
