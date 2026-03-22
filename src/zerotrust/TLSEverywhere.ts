/**
 * TLS Everywhere - TLS 1.3 Везде
 * 
 * Компонент управляет TLS конфигурацией для обеспечения
 * шифрования всего трафика в системе.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import * as tls from 'tls';
import * as crypto from 'crypto';
import {
  TlsConfiguration,
  TlsVersion,
  ZeroTrustEvent,
  SubjectType
} from './zerotrust.types';

/**
 * Конфигурация TLS Everywhere
 */
export interface TlsEverywhereConfig {
  /** Минимальная версия TLS */
  minTlsVersion: TlsVersion;
  
  /** Предпочтительная версия TLS */
  preferredTlsVersion: TlsVersion;
  
  /** Разрешённые cipher suites */
  cipherSuites: string[];
  
  /** Кривые для ECDHE */
  curves: string[];
  
  /** Включить HSTS */
  enableHsts: boolean;
  
  /** HSTS max-age */
  hstsMaxAge: number;
  
  /** Включить OCSP stapling */
  enableOcspStapling: boolean;
  
  /** Включить session tickets */
  enableSessionTickets: boolean;
  
  /** Session timeout (секунды) */
  sessionTimeout: number;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
}

/**
 * TLS сертификат
 */
interface TlsCertificate {
  /** ID сертификата */
  id: string;
  
  /** Common Name */
  commonName: string;
  
  /** SAN */
  subjectAltNames: string[];
  
  /** PEM сертификат */
  certificatePem: string;
  
  /** PEM ключ */
  privateKeyPem: string;
  
  /** PEM CA */
  caCertificatePem: string;
  
  /** Дата выдачи */
  issuedAt: Date;
  
  /** Дата истечения */
  expiresAt: Date;
  
  /** Отпечаток */
  fingerprint: string;
}

/**
 * TLS Everywhere Manager
 * 
 * Управляет TLS конфигурацией для всех компонентов.
 */
export class TlsEverywhere extends EventEmitter {
  /** Конфигурация */
  private config: TlsEverywhereConfig;
  
  /** Сертификаты */
  private certificates: Map<string, TlsCertificate>;
  
  /** TLS контексты */
  private tlsContexts: Map<string, tls.TLSOptions>;
  
  /** Статистика */
  private stats: {
    /** Сертификатов */
    certificateCount: number;
    /** TLS контекстов */
    contextCount: number;
    /** Истекающих сертификатов */
    expiringCertificates: number;
  };

  constructor(config: Partial<TlsEverywhereConfig> = {}) {
    super();
    
    this.config = {
      minTlsVersion: config.minTlsVersion ?? TlsVersion.TLS1_3,
      preferredTlsVersion: config.preferredTlsVersion ?? TlsVersion.TLS1_3,
      cipherSuites: config.cipherSuites ?? [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256'
      ],
      curves: config.curves ?? [
        'X25519',
        'P-384',
        'P-256'
      ],
      enableHsts: config.enableHsts ?? true,
      hstsMaxAge: config.hstsMaxAge ?? 31536000, // 1 год
      enableOcspStapling: config.enableOcspStapling ?? true,
      enableSessionTickets: config.enableSessionTickets ?? true,
      sessionTimeout: config.sessionTimeout ?? 600,
      enableVerboseLogging: config.enableVerboseLogging ?? false
    };
    
    this.certificates = new Map();
    this.tlsContexts = new Map();
    
    this.stats = {
      certificateCount: 0,
      contextCount: 0,
      expiringCertificates: 0
    };
    
    this.log('TLS', 'TlsEverywhere инициализирован');
  }

  /**
   * Получить TLS конфигурацию
   */
  public getTlsConfiguration(): TlsConfiguration {
    return {
      minVersion: this.config.minTlsVersion,
      maxVersion: this.config.preferredTlsVersion,
      cipherSuites: this.config.cipherSuites,
      curves: this.config.curves,
      authenticationMode: 'MUTUAL',
      certificates: {
        serverCert: '',
        serverKey: '',
        caCert: ''
      },
      session: {
        ticketsEnabled: this.config.enableSessionTickets,
        timeout: this.config.sessionTimeout,
        cacheSize: 10000
      },
      hsts: this.config.enableHsts ? {
        enabled: true,
        maxAge: this.config.hstsMaxAge,
        includeSubDomains: true,
        preload: true
      } : undefined
    };
  }

  /**
   * Создать TLS контекст для сервера
   */
  public createServerTlsContext(
    contextId: string,
    certificateId: string
  ): tls.TLSOptions {
    const certificate = this.certificates.get(certificateId);
    
    if (!certificate) {
      throw new Error(`Сертификат не найден: ${certificateId}`);
    }
    
    const tlsOptions: tls.TLSOptions = {
      // Версия TLS
      minVersion: this.tlsVersionToString(this.config.minTlsVersion),
      maxVersion: this.tlsVersionToString(this.config.preferredTlsVersion),
      
      // Cipher suites
      ciphers: this.config.cipherSuites.join(':'),
      honorCipherOrder: true,
      
      // Кривые
      ecdhCurve: this.config.curves.join(':'),
      
      // Сертификаты
      key: certificate.privateKeyPem,
      cert: certificate.certificatePem,
      ca: certificate.caCertificatePem,
      
      // mTLS
      requestCert: true,
      rejectUnauthorized: true,
      
      // Session
      sessionTimeout: this.config.sessionTimeout
    };
    
    // Session tickets
    if (this.config.enableSessionTickets) {
      // В Node.js session tickets управляются автоматически
      tlsOptions.sessionTickets = true;
    }
    
    // OCSP
    if (this.config.enableOcspStapling) {
      tlsOptions.OCSPStapling = true;
    }
    
    this.tlsContexts.set(contextId, tlsOptions);
    this.stats.contextCount = this.tlsContexts.size;
    
    this.log('TLS', 'TLS контекст сервера создан', {
      contextId,
      certificateId
    });
    
    this.emit('tls:context_created', { contextId, type: 'server' });
    
    return tlsOptions;
  }

  /**
   * Создать TLS контекст для клиента
   */
  public createClientTlsContext(
    contextId: string,
    certificateId?: string
  ): tls.ConnectionOptions {
    const certificate = certificateId ? this.certificates.get(certificateId) : undefined;
    
    const tlsOptions: tls.ConnectionOptions = {
      // Версия TLS
      minVersion: this.tlsVersionToString(this.config.minTlsVersion),
      maxVersion: this.tlsVersionToString(this.config.preferredTlsVersion),
      
      // Cipher suites
      ciphers: this.config.cipherSuites.join(':'),
      
      // Кривые
      ecdhCurve: this.config.curves.join(':'),
      
      // Проверка сервера
      rejectUnauthorized: true,
      
      // CA для проверки сервера
      ca: certificate?.caCertificatePem
    };
    
    // Клиентский сертификат для mTLS
    if (certificate) {
      tlsOptions.key = certificate.privateKeyPem;
      tlsOptions.cert = certificate.certificatePem;
    }
    
    this.tlsContexts.set(contextId, tlsOptions as tls.TLSOptions);
    this.stats.contextCount = this.tlsContexts.size;
    
    this.log('TLS', 'TLS контекст клиента создан', { contextId });
    this.emit('tls:context_created', { contextId, type: 'client' });
    
    return tlsOptions;
  }

  /**
   * Конвертировать TLS версию в строку
   */
  private tlsVersionToString(version: TlsVersion): string {
    const mapping: Record<TlsVersion, string> = {
      [TlsVersion.TLS1_0]: 'TLSv1',
      [TlsVersion.TLS1_1]: 'TLSv1.1',
      [TlsVersion.TLS1_2]: 'TLSv1.2',
      [TlsVersion.TLS1_3]: 'TLSv1.3'
    };
    
    return mapping[version];
  }

  /**
   * Добавить сертификат
   */
  public addCertificate(certificate: TlsCertificate): void {
    this.certificates.set(certificate.id, certificate);
    this.stats.certificateCount = this.certificates.size;
    
    this.log('TLS', 'Сертификат добавлен', {
      certificateId: certificate.id,
      commonName: certificate.commonName,
      expiresAt: certificate.expiresAt
    });
    
    this.emit('tls:certificate_added', certificate);
  }

  /**
   * Удалить сертификат
   */
  public removeCertificate(certificateId: string): boolean {
    const removed = this.certificates.delete(certificateId);
    
    if (removed) {
      this.stats.certificateCount = this.certificates.size;
      this.log('TLS', 'Сертификат удалён', { certificateId });
      this.emit('tls:certificate_removed', { certificateId });
    }
    
    return removed;
  }

  /**
   * Проверить истекающие сертификаты
   */
  public checkExpiringCertificates(daysThreshold: number = 30): TlsCertificate[] {
    const now = new Date();
    const threshold = new Date(now.getTime() + daysThreshold * 24 * 60 * 60 * 1000);
    
    const expiring: TlsCertificate[] = [];
    
    for (const cert of this.certificates.values()) {
      if (cert.expiresAt <= threshold) {
        expiring.push(cert);
      }
    }
    
    this.stats.expiringCertificates = expiring.length;
    
    if (expiring.length > 0) {
      this.log('TLS', `Найдено ${expiring.length} истекающих сертификатов`, {
        certificates: expiring.map(c => c.id)
      });
      
      this.emit('tls:certificates_expiring', {
        certificates: expiring,
        daysThreshold
      });
    }
    
    return expiring;
  }

  /**
   * Получить TLS контекст
   */
  public getTlsContext(contextId: string): tls.TLSOptions | undefined {
    return this.tlsContexts.get(contextId);
  }

  /**
   * Получить сертификат
   */
  public getCertificate(certificateId: string): TlsCertificate | undefined {
    return this.certificates.get(certificateId);
  }

  /**
   * Получить все сертификаты
   */
  public getAllCertificates(): TlsCertificate[] {
    return Array.from(this.certificates.values());
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats {
    return { ...this.stats };
  }

  /**
   * Сгенерировать самоподписанный сертификат (для тестов)
   */
  public generateSelfSignedCertificate(
    commonName: string,
    days: number = 365
  ): TlsCertificate {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });
    
    // В реальной реализации здесь было бы создание сертификата
    // с использованием crypto.createCertificate или external CA
    
    const now = new Date();
    const expiresAt = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);
    
    const certificate: TlsCertificate = {
      id: uuidv4(),
      commonName,
      subjectAltNames: [commonName],
      certificatePem: `-----BEGIN CERTIFICATE-----\nMIIC...${commonName}...self-signed...`,
      privateKeyPem: privateKey,
      caCertificatePem: `-----BEGIN CERTIFICATE-----\nMIIC...${commonName}...CA...`,
      issuedAt: now,
      expiresAt,
      fingerprint: crypto.createHash('sha256').update(publicKey).digest('hex')
    };
    
    this.addCertificate(certificate);
    
    return certificate;
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
      console.log(`[TLS] ${new Date().toISOString()} - ${message}`, data ?? '');
    }
  }
}

export default TlsEverywhere;
