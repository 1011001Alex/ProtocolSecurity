/**
 * Identity-Aware Proxy - Прокси с Учётом Идентичности
 * 
 * Компонент реализует прокси-сервер, который принимает решения
 * о маршрутизации запросов на основе идентичности пользователя,
 * контекста и политик доступа.
 * 
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { v4 as uuidv4 } from 'uuid';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import {
  Identity,
  AuthContext,
  PolicyEvaluationResult,
  PolicyDecision,
  ZeroTrustEvent,
  SubjectType,
  ResourceType,
  PolicyOperation
} from './zerotrust.types';
import { PolicyEnforcementPoint } from './PolicyEnforcementPoint';
import { TrustVerifier } from './TrustVerifier';

/**
 * Конфигурация Identity-Aware Proxy
 */
export interface IdentityAwareProxyConfig {
  /** Порт прослушивания */
  listenPort: number;
  
  /** Хост прослушивания */
  listenHost: string;
  
  /** Включить HTTPS */
  enableHttps: boolean;
  
  /** HTTPS сертификат */
  httpsCert?: string;
  
  /** HTTPS ключ */
  httpsKey?: string;
  
  /** Таймаут запроса (мс) */
  requestTimeout: number;
  
  /** Максимальный размер тела запроса */
  maxBodySize: number;
  
  /** Включить кэширование ответов */
  enableResponseCaching: boolean;
  
  /** TTL кэша ответов (секунды) */
  responseCacheTtl: number;
  
  /** Включить компрессию */
  enableCompression: boolean;
  
  /** Включить детальное логирование */
  enableVerboseLogging: boolean;
  
  /** Заголовки для проброса */
  forwardedHeaders: string[];
  
  /** Заголовки для удаления */
  removedHeaders: string[];
}

/**
 * Контекст проксируемого запроса
 */
interface ProxyRequestContext {
  /** Уникальный ID запроса */
  requestId: string;
  
  /** Исходный запрос */
  originalRequest: http.IncomingMessage;
  
  /** Identity пользователя */
  identity: Identity;
  
  /** Контекст аутентификации */
  authContext: AuthContext;
  
  /** Целевой URL */
  targetUrl: URL;
  
  /** Метод запроса */
  method: string;
  
  /** Путь запроса */
  path: string;
  
  /** Заголовки */
  headers: Record<string, string>;
  
  /** Тело запроса */
  body?: Buffer;
  
  /** Время начала */
  startTime: Date;
}

/**
 * Результат проксирования
 */
interface ProxyResult {
  /** ID запроса */
  requestId: string;
  
  /** Статус код */
  statusCode: number;
  
  /** Заголовки ответа */
  headers: Record<string, string>;
  
  /** Тело ответа */
  body?: Buffer;
  
  /** Время выполнения (мс) */
  duration: number;
  
  /** Было ли кэшировано */
  cached: boolean;
}

/**
 * Кэш ответов
 */
interface ResponseCache {
  entries: Map<string, {
    response: ProxyResult;
    cachedAt: Date;
    expiresAt: Date;
  }>;
  maxSize: number;
}

/**
 * Identity-Aware Proxy
 * 
 * Прокси-сервер с проверкой идентичности и политик доступа.
 */
export class IdentityAwareProxy extends EventEmitter {
  /** Конфигурация */
  private config: IdentityAwareProxyConfig;
  
  /** PEP для проверок политик */
  private pep: PolicyEnforcementPoint | null;
  
  /** Trust Verifier */
  private trustVerifier: TrustVerifier | null;
  
  /** HTTP сервер */
  private httpServer: http.Server | null;
  
  /** HTTPS сервер */
  private httpsServer: https.Server | null;
  
  /** Кэш ответов */
  private responseCache: ResponseCache;
  
  /** Активные запросы */
  private activeRequests: Map<string, ProxyRequestContext>;
  
  /** Статистика */
  private stats: {
    /** Всего запросов */
    totalRequests: number;
    /** Успешных запросов */
    successfulRequests: number;
    /** Заблокированных запросов */
    blockedRequests: number;
    /** Ошибок проксирования */
    proxyErrors: number;
    /** Попаданий в кэш */
    cacheHits: number;
    /** Среднее время обработки */
    averageProcessingTime: number;
  };

  constructor(config: Partial<IdentityAwareProxyConfig> = {}) {
    super();
    
    this.config = {
      listenPort: config.listenPort ?? 8080,
      listenHost: config.listenHost ?? '0.0.0.0',
      enableHttps: config.enableHttps ?? false,
      httpsCert: config.httpsCert,
      httpsKey: config.httpsKey,
      requestTimeout: config.requestTimeout ?? 30000,
      maxBodySize: config.maxBodySize ?? 10 * 1024 * 1024, // 10MB
      enableResponseCaching: config.enableResponseCaching ?? false,
      responseCacheTtl: config.responseCacheTtl ?? 60,
      enableCompression: config.enableCompression ?? true,
      enableVerboseLogging: config.enableVerboseLogging ?? false,
      forwardedHeaders: config.forwardedHeaders ?? [
        'X-Forwarded-For',
        'X-Forwarded-Proto',
        'X-Forwarded-Host',
        'X-Real-IP'
      ],
      removedHeaders: config.removedHeaders ?? [
        'X-Powered-By',
        'Server'
      ]
    };
    
    this.pep = null;
    this.trustVerifier = null;
    this.httpServer = null;
    this.httpsServer = null;
    this.responseCache = {
      entries: new Map(),
      maxSize: 1000
    };
    this.activeRequests = new Map();
    
    this.stats = {
      totalRequests: 0,
      successfulRequests: 0,
      blockedRequests: 0,
      proxyErrors: 0,
      cacheHits: 0,
      averageProcessingTime: 0
    };
    
    this.log('IAP', 'IdentityAwareProxy инициализирован');
  }

  /**
   * Установить PEP
   */
  public setPep(pep: PolicyEnforcementPoint): void {
    this.pep = pep;
    this.log('IAP', 'PEP установлен');
  }

  /**
   * Установить Trust Verifier
   */
  public setTrustVerifier(trustVerifier: TrustVerifier): void {
    this.trustVerifier = trustVerifier;
    this.log('IAP', 'TrustVerifier установлен');
  }

  /**
   * Запустить прокси сервер
   */
  public start(): Promise<void> {
    return new Promise((resolve, reject) => {
      // Создаём обработчик запросов
      const requestHandler = this.handleRequest.bind(this);
      
      // HTTP сервер
      this.httpServer = http.createServer(requestHandler);
      
      this.httpServer.listen(this.config.listenPort, this.config.listenHost, () => {
        this.log('IAP', `HTTP сервер запущен на ${this.config.listenHost}:${this.config.listenPort}`);
        resolve();
      });
      
      this.httpServer.on('error', (error) => {
        this.log('IAP', 'Ошибка HTTP сервера', { error });
        reject(error);
      });
      
      // HTTPS сервер (если включён)
      if (this.config.enableHttps && this.config.httpsCert && this.config.httpsKey) {
        this.httpsServer = https.createServer(
          {
            cert: this.config.httpsCert,
            key: this.config.httpsKey
          },
          requestHandler
        );
        
        const httpsPort = this.config.listenPort + 1;
        
        this.httpsServer.listen(httpsPort, this.config.listenHost, () => {
          this.log('IAP', `HTTPS сервер запущен на ${this.config.listenHost}:${httpsPort}`);
        });
      }
    });
  }

  /**
   * Остановить прокси сервер
   */
  public stop(): Promise<void> {
    return new Promise((resolve) => {
      const promises: Promise<void>[] = [];
      
      if (this.httpServer) {
        promises.push(new Promise((resolve) => {
          this.httpServer?.close(() => {
            this.log('IAP', 'HTTP сервер остановлен');
            resolve();
          });
        }));
      }
      
      if (this.httpsServer) {
        promises.push(new Promise((resolve) => {
          this.httpsServer?.close(() => {
            this.log('IAP', 'HTTPS сервер остановлен');
            resolve();
          });
        }));
      }
      
      Promise.all(promises).then(() => resolve());
    });
  }

  /**
   * Обработать входящий запрос
   */
  private async handleRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse
  ): Promise<void> {
    const requestId = uuidv4();
    const startTime = Date.now();
    this.stats.totalRequests++;
    
    this.log('IAP', 'Получен запрос', {
      requestId,
      method: req.method,
      url: req.url,
      ip: req.socket.remoteAddress
    });
    
    try {
      // Извлекаем идентичность из запроса
      const identity = await this.extractIdentity(req);
      
      if (!identity) {
        this.sendError(res, 401, 'Unauthorized', requestId);
        this.stats.blockedRequests++;
        return;
      }
      
      // Извлекаем контекст аутентификации
      const authContext = await this.extractAuthContext(req, identity);
      
      // Определяем целевой URL
      const targetUrl = this.determineTargetUrl(req, identity);
      
      // Создаём контекст запроса
      const context: ProxyRequestContext = {
        requestId,
        originalRequest: req,
        identity,
        authContext,
        targetUrl,
        method: req.method || 'GET',
        path: req.url || '/',
        headers: this.sanitizeHeaders(req.headers),
        startTime: new Date()
      };
      
      // Читаем тело запроса
      if (['POST', 'PUT', 'PATCH'].includes(context.method)) {
        context.body = await this.readRequestBody(req);
      }
      
      // Сохраняем активный запрос
      this.activeRequests.set(requestId, context);
      
      // Проверяем политику доступа
      const policyResult = await this.checkAccessPolicy(context);
      
      if (policyResult.decision !== PolicyDecision.ALLOW &&
          policyResult.decision !== PolicyDecision.ALLOW_RESTRICTED) {
        this.sendError(res, 403, 'Forbidden', requestId);
        this.stats.blockedRequests++;
        this.activeRequests.delete(requestId);
        return;
      }
      
      // Проверяем кэш (для GET запросов)
      if (this.config.enableResponseCaching && context.method === 'GET') {
        const cachedResponse = this.getCachedResponse(context);
        if (cachedResponse) {
          this.stats.cacheHits++;
          this.sendResponse(res, cachedResponse);
          this.activeRequests.delete(requestId);
          return;
        }
      }
      
      // Проксируем запрос
      const proxyResult = await this.proxyRequest(context);
      
      // Кэшируем ответ (для GET запросов)
      if (this.config.enableResponseCaching && 
          context.method === 'GET' && 
          proxyResult.statusCode === 200) {
        this.cacheResponse(context, proxyResult);
      }
      
      // Отправляем ответ
      this.sendResponse(res, proxyResult);
      
      this.stats.successfulRequests++;
      this.log('IAP', 'Запрос обработан', {
        requestId,
        statusCode: proxyResult.statusCode,
        duration: proxyResult.duration
      });
      
    } catch (error) {
      this.stats.proxyErrors++;
      this.log('IAP', 'Ошибка обработки запроса', {
        requestId,
        error: error instanceof Error ? error.message : String(error)
      });
      
      this.sendError(res, 502, 'Bad Gateway', requestId);
      
    } finally {
      this.activeRequests.delete(requestId);
      
      // Обновляем статистику
      const duration = Date.now() - startTime;
      this.stats.averageProcessingTime = 
        (this.stats.averageProcessingTime * (this.stats.totalRequests - 1) + duration) /
        this.stats.totalRequests;
    }
  }

  /**
   * Извлечь идентичность из запроса
   */
  private async extractIdentity(req: http.IncomingMessage): Promise<Identity | null> {
    // Проверяем заголовок авторизации
    const authHeader = req.headers['authorization'];
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      
      // В реальной реализации здесь была бы валидация JWT токена
      // и извлечение identity из claims
      return {
        id: `user_${uuidv4().substring(0, 8)}`,
        type: SubjectType.USER,
        displayName: 'Authenticated User',
        roles: ['user'],
        permissions: [],
        groups: [],
        labels: {},
        createdAt: new Date(),
        updatedAt: new Date()
      };
    }
    
    // Проверяем mTLS сертификат
    const tlsSocket = req.socket as https.TLSSocket;
    const peerCertificate = tlsSocket.getPeerCertificate?.();
    
    if (peerCertificate && Object.keys(peerCertificate).length > 0) {
      return {
        id: `cert_${peerCertificate.fingerprint?.replace(/:/g, '').toLowerCase() || uuidv4()}`,
        type: SubjectType.USER,
        displayName: peerCertificate.subject?.CN || 'Certificate User',
        roles: ['user'],
        permissions: [],
        groups: [],
        labels: {
          authMethod: 'mtls'
        },
        createdAt: new Date(),
        updatedAt: new Date()
      };
    }
    
    return null;
  }

  /**
   * Извлечь контекст аутентификации
   */
  private async extractAuthContext(
    req: http.IncomingMessage,
    identity: Identity
  ): Promise<AuthContext> {
    const authHeader = req.headers['authorization'];
    const hasMfa = req.headers['x-mfa-verified'] === 'true';
    
    return {
      method: authHeader ? 
        (identity.labels?.authMethod === 'mtls' ? 'MTLS' : 'JWT') : 
        'PASSWORD',
      authenticatedAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      levelOfAssurance: hasMfa ? 3 : 1,
      factors: [
        authHeader ? 'JWT' : 'PASSWORD',
        hasMfa ? 'MFA' : null
      ].filter(Boolean) as ('JWT' | 'MFA' | 'MTLS')[],
      sessionId: uuidv4(),
      mfaVerified: hasMfa,
      mfaMethods: hasMfa ? ['TOTP'] : []
    };
  }

  /**
   * Определить целевой URL
   */
  private determineTargetUrl(
    req: http.IncomingMessage,
    identity: Identity
  ): URL {
    // В реальной реализации здесь была бы логика маршрутизации
    // на основе identity и политик
    
    const host = req.headers['host'] || 'localhost';
    const protocol = this.config.enableHttps ? 'https' : 'http';
    const targetHost = this.config.listenHost === '0.0.0.0' ? 'localhost' : this.config.listenHost;
    const targetPort = this.config.enableHttps ? 
      this.config.listenPort + 1 : 
      this.config.listenPort;
    
    return new URL(`${protocol}://${targetHost}:${targetPort}${req.url}`);
  }

  /**
   * Санитизировать заголовки
   */
  private sanitizeHeaders(headers: http.IncomingHttpHeaders): Record<string, string> {
    const sanitized: Record<string, string> = {};
    
    for (const [key, value] of Object.entries(headers)) {
      // Пропускаем hop-by-hop заголовки
      if (['connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer', 'upgrade'].includes(key.toLowerCase())) {
        continue;
      }
      
      // Удаляем указанные заголовки
      if (this.config.removedHeaders.some(h => h.toLowerCase() === key.toLowerCase())) {
        continue;
      }
      
      if (value !== undefined) {
        sanitized[key] = Array.isArray(value) ? value.join(', ') : value;
      }
    }
    
    return sanitized;
  }

  /**
   * Прочитать тело запроса
   */
  private readRequestBody(req: http.IncomingMessage): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let totalSize = 0;
      
      req.on('data', (chunk: Buffer) => {
        totalSize += chunk.length;
        
        if (totalSize > this.config.maxBodySize) {
          reject(new Error('Request body too large'));
          req.destroy();
          return;
        }
        
        chunks.push(chunk);
      });
      
      req.on('end', () => {
        resolve(Buffer.concat(chunks));
      });
      
      req.on('error', reject);
    });
  }

  /**
   * Проверить политику доступа
   */
  private async checkAccessPolicy(context: ProxyRequestContext): Promise<PolicyEvaluationResult> {
    if (!this.pep) {
      // Если PEP не установлен, разрешаем доступ
      return {
        evaluationId: uuidv4(),
        evaluatedAt: new Date(),
        decision: PolicyDecision.ALLOW,
        trustLevel: 3,
        appliedRules: [],
        factors: [],
        restrictions: {},
        recommendations: []
      };
    }
    
    // Определяем операцию
    const operation = this.methodToOperation(context.method);
    
    // Запрашиваем решение у PEP
    const result = await this.pep.enforceAccess({
      identity: context.identity,
      authContext: context.authContext,
      resourceType: ResourceType.HTTP_ENDPOINT,
      resourceId: context.targetUrl.pathname,
      resourceName: context.targetUrl.hostname,
      operation,
      sourceIp: context.originalRequest.socket.remoteAddress || '0.0.0.0',
      destinationIp: context.targetUrl.hostname,
      destinationPort: parseInt(context.targetUrl.port) || 443,
      protocol: 'TCP'
    });
    
    return result;
  }

  /**
   * Преобразовать HTTP метод в операцию
   */
  private methodToOperation(method: string): PolicyOperation {
    switch (method.toUpperCase()) {
      case 'GET':
      case 'HEAD':
        return PolicyOperation.READ;
      case 'POST':
      case 'PUT':
      case 'PATCH':
        return PolicyOperation.WRITE;
      case 'DELETE':
        return PolicyOperation.DELETE;
      default:
        return PolicyOperation.ANY;
    }
  }

  /**
   * Проксировать запрос
   */
  private async proxyRequest(context: ProxyRequestContext): Promise<ProxyResult> {
    const startTime = Date.now();
    
    return new Promise((resolve, reject) => {
      const options = {
        hostname: context.targetUrl.hostname,
        port: context.targetUrl.port,
        path: context.targetUrl.pathname + context.targetUrl.search,
        method: context.method,
        headers: {
          ...context.headers,
          'Host': context.targetUrl.host,
          'X-Request-ID': context.requestId,
          'X-Forwarded-For': context.originalRequest.socket.remoteAddress,
          'X-Forwarded-Proto': this.config.enableHttps ? 'https' : 'http',
          'X-User-ID': context.identity.id,
          'X-User-Roles': context.identity.roles.join(','),
          'Content-Length': context.body ? context.body.length : 0
        }
      };
      
      const protocol = context.targetUrl.protocol === 'https:' ? https : http;
      const proxyReq = protocol.request(options, (proxyRes: http.IncomingMessage) => {
        const chunks: Buffer[] = [];
        
        proxyRes.on('data', (chunk: Buffer) => chunks.push(chunk));
        
        proxyRes.on('end', () => {
          const duration = Date.now() - startTime;
          
          resolve({
            requestId: context.requestId,
            statusCode: proxyRes.statusCode || 500,
            headers: this.sanitizeHeaders(proxyRes.headers),
            body: Buffer.concat(chunks),
            duration,
            cached: false
          });
        });
      });
      
      proxyReq.on('error', (error) => {
        reject(error);
      });
      
      proxyReq.setTimeout(this.config.requestTimeout, () => {
        proxyReq.destroy();
        reject(new Error('Proxy request timeout'));
      });
      
      if (context.body) {
        proxyReq.write(context.body);
      }
      
      proxyReq.end();
    });
  }

  /**
   * Получить кэшированный ответ
   */
  private getCachedResponse(context: ProxyRequestContext): ProxyResult | null {
    const cacheKey = this.getCacheKey(context);
    const cached = this.responseCache.entries.get(cacheKey);
    
    if (!cached) {
      return null;
    }
    
    if (new Date() > cached.expiresAt) {
      this.responseCache.entries.delete(cacheKey);
      return null;
    }
    
    return cached.response;
  }

  /**
   * Получить ключ кэша
   */
  private getCacheKey(context: ProxyRequestContext): string {
    return `${context.method}:${context.targetUrl.toString()}`;
  }

  /**
   * Кэшировать ответ
   */
  private cacheResponse(context: ProxyRequestContext, result: ProxyResult): void {
    // Очищаем старые записи если кэш переполнен
    if (this.responseCache.entries.size >= this.responseCache.maxSize) {
      const firstKey = this.responseCache.entries.keys().next().value;
      if (firstKey) {
        this.responseCache.entries.delete(firstKey);
      }
    }
    
    const cacheKey = this.getCacheKey(context);
    
    this.responseCache.entries.set(cacheKey, {
      response: result,
      cachedAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.responseCacheTtl * 1000)
    });
  }

  /**
   * Отправить ответ
   */
  private sendResponse(res: http.ServerResponse, result: ProxyResult): void {
    res.statusCode = result.statusCode;
    
    for (const [key, value] of Object.entries(result.headers)) {
      res.setHeader(key, value);
    }
    
    res.setHeader('X-Request-ID', result.requestId);
    res.setHeader('X-Response-Time', `${result.duration}ms`);
    res.setHeader('X-Cache', result.cached ? 'HIT' : 'MISS');
    
    if (result.body) {
      res.end(result.body);
    } else {
      res.end();
    }
  }

  /**
   * Отправить ошибку
   */
  private sendError(res: http.ServerResponse, statusCode: number, message: string, requestId: string): void {
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Request-ID', requestId);
    
    res.end(JSON.stringify({
      error: statusCode === 401 ? 'Unauthorized' : statusCode === 403 ? 'Forbidden' : 'Error',
      message,
      requestId
    }));
  }

  /**
   * Получить статистику
   */
  public getStats(): typeof this.stats & {
    /** Активные запросы */
    activeRequests: number;
    /** Размер кэша */
    cacheSize: number;
  } {
    return {
      ...this.stats,
      activeRequests: this.activeRequests.size,
      cacheSize: this.responseCache.entries.size
    };
  }

  /**
   * Очистить кэш
   */
  public clearCache(): void {
    this.responseCache.entries.clear();
    this.log('IAP', 'Кэш ответов очищен');
  }

  /**
   * Логирование
   */
  private log(component: string, message: string, data?: unknown): void {
    const event: ZeroTrustEvent = {
      eventId: uuidv4(),
      eventType: 'ACCESS_REQUEST',
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
      logger.debug(`[IAP] ${message}`, { timestamp: new Date().toISOString(), ...data });
    }
  }
}

export default IdentityAwareProxy;
