/**
 * =============================================================================
 * SECURITY HEADERS MIDDLEWARE
 * =============================================================================
 * Полный набор security headers для защиты веб-приложений
 * Соответствует: OWASP Secure Headers Project
 * =============================================================================
 */

import { IncomingMessage, ServerResponse } from 'http';

// =============================================================================
// ТИПЫ И ИНТЕРФЕЙСЫ
// =============================================================================

/**
 * Конфигурация security headers
 */
export interface SecurityHeadersConfig {
  /** Content-Security-Policy настройки */
  csp: CSPConfig;
  
  /** HSTS настройки */
  hsts: HSTSConfig;
  
  /** X-Frame-Options */
  xFrameOptions: 'DENY' | 'SAMEORIGIN';
  
  /** X-Content-Type-Options */
  xContentTypeOptions: 'nosniff';
  
  /** X-XSS-Protection */
  xXSSProtection: '1; mode=block';
  
  /** Referrer-Policy */
  referrerPolicy: ReferrerPolicy;
  
  /** Permissions-Policy */
  permissionsPolicy: PermissionsPolicyConfig;
  
  /** Cross-Origin-Policy */
  crossOriginPolicies: CrossOriginPoliciesConfig;
  
  /** Cache-Control для чувствительных данных */
  cacheControl: CacheControlConfig;
  
  /** Удалить заголовки информации */
  removeHeaders: string[];
}

/**
 * CSP директивы
 */
export interface CSPConfig {
  /** Default source */
  defaultSrc: string[];
  
  /** Script source */
  scriptSrc: string[];
  
  /** Style source */
  styleSrc: string[];
  
  /** Image source */
  imgSrc: string[];
  
  /** Font source */
  fontSrc: string[];
  
  /** Connect source (AJAX, WebSocket) */
  connectSrc: string[];
  
  /** Media source */
  mediaSrc: string[];
  
  /** Object source */
  objectSrc: string[];
  
  /** Frame source */
  frameSrc: string[];
  
  /** Worker source */
  workerSrc: string[];
  
  /** Base URI */
  baseUri: string[];
  
  /** Form action */
  formAction: string[];
  
  /** Frame ancestors */
  frameAncestors: string[];
  
  /** Upgrade insecure requests */
  upgradeInsecureRequests: boolean;
  
  /** Block all mixed content */
  blockAllMixedContent: boolean;
  
  /** Report URI */
  reportUri?: string;
  
  /** Report-To */
  reportTo?: string;
  
  /** Strict dynamic */
  strictDynamic: boolean;
  
  /** Use unsafe-inline (fallback) */
  useUnsafeInline: boolean;
}

/**
 * HSTS конфигурация
 */
export interface HSTSConfig {
  /** Максимальный возраст (секунды) */
  maxAge: number;
  
  /** Включить subdomains */
  includeSubDomains: boolean;
  
  /** Включить preload */
  preload: boolean;
}

/**
 * Referrer Policy
 */
export type ReferrerPolicy = 
  | 'no-referrer'
  | 'no-referrer-when-downgrade'
  | 'origin'
  | 'origin-when-cross-origin'
  | 'same-origin'
  | 'strict-origin'
  | 'strict-origin-when-cross-origin'
  | 'unsafe-url';

/**
 * Permissions Policy
 */
export interface PermissionsPolicyConfig {
  /** Геолокация */
  geolocation: string[];
  
  /** Микрофон */
  microphone: string[];
  
  /** Камера */
  camera: string[];
  
  /** Payment */
  payment: string[];
  
  /** USB */
  usb: string[];
  
  /** Fullscreen */
  fullscreen: string[];
  
  /** Accelerometer */
  accelerometer: string[];
  
  /** Gyroscope */
  gyroscope: string[];
  
  /** Magnetometer */
  magnetometer: string[];
  
  /** Ambient light sensor */
  ambientLightSensor: string[];
  
  /** Autoplay */
  autoplay: string[];
  
  /** Encrypted media */
  encryptedMedia: string[];
  
  /** Picture-in-picture */
  pictureInPicture: string[];
  
  /** SyncXHR */
  syncXhr: string[];
  
  /** Wake lock */
  wakeLock: string[];
  
  /** Serial */
  serial: string[];
  
  /** Trust Token Redemption */
  trustTokenRedemption: string[];
}

/**
 * Cross-Origin Policies
 */
export interface CrossOriginPoliciesConfig {
  /** Cross-Origin-Opener-Policy */
  coop: 'same-origin' | 'same-origin-allow-popups' | 'unsafe-none';
  
  /** Cross-Origin-Embedder-Policy */
  coep: 'require-corp' | 'unsafe-none';
  
  /** Cross-Origin-Resource-Policy */
  corp: 'same-origin' | 'same-site' | 'cross-origin';
}

/**
 * Cache Control
 */
export interface CacheControlConfig {
  /** Для чувствительных страниц */
  sensitive: string;
  
  /** Для статических ресурсов */
  static: string;
  
  /** Для API */
  api: string;
}

// =============================================================================
// ПРЕДУСТАНОВЛЕННЫЕ КОНФИГУРАЦИИ
// =============================================================================

/**
 * Строгая CSP для production
 */
export const CSP_STRICT: CSPConfig = {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'"],
  styleSrc: ["'self'"],
  imgSrc: ["'self'", 'data:', 'blob:'],
  fontSrc: ["'self'"],
  connectSrc: ["'self'"],
  mediaSrc: ["'self'"],
  objectSrc: ["'none'"],
  frameSrc: ["'none'"],
  workerSrc: ["'self'"],
  baseUri: ["'self'"],
  formAction: ["'self'"],
  frameAncestors: ["'none'"],
  upgradeInsecureRequests: true,
  blockAllMixedContent: true,
  reportUri: undefined,
  reportTo: undefined,
  strictDynamic: false,
  useUnsafeInline: false
};

/**
 * CSP для development
 */
export const CSP_DEVELOPMENT: CSPConfig = {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'localhost:*'],
  styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:', 'blob:', 'localhost:*'],
  fontSrc: ["'self'", 'data:', 'localhost:*'],
  connectSrc: ["'self'", 'localhost:*', 'ws:', 'wss:'],
  mediaSrc: ["'self'", 'localhost:*'],
  objectSrc: ["'none'"],
  frameSrc: ["'self'", 'localhost:*'],
  workerSrc: ["'self'", 'blob:'],
  baseUri: ["'self'"],
  formAction: ["'self'", 'localhost:*'],
  frameAncestors: ["'self'"],
  upgradeInsecureRequests: false,
  blockAllMixedContent: false,
  reportUri: undefined,
  reportTo: undefined,
  strictDynamic: false,
  useUnsafeInline: true
};

/**
 * Конфигурация по умолчанию для production
 */
export const DEFAULT_SECURITY_CONFIG: SecurityHeadersConfig = {
  csp: CSP_STRICT,
  hsts: {
    maxAge: 31536000, // 1 год
    includeSubDomains: true,
    preload: true
  },
  xFrameOptions: 'DENY',
  xContentTypeOptions: 'nosniff',
  xXSSProtection: '1; mode=block',
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: {
    geolocation: ["'none'"],
    microphone: ["'none'"],
    camera: ["'none'"],
    payment: ["'none'"],
    usb: ["'none'"],
    fullscreen: ["'self'"],
    accelerometer: ["'none'"],
    gyroscope: ["'none'"],
    magnetometer: ["'none'"],
    ambientLightSensor: ["'none'"],
    autoplay: ["'none'"],
    encryptedMedia: ["'self'"],
    pictureInPicture: ["'self'"],
    syncXhr: ["'none'"],
    wakeLock: ["'none'"],
    serial: ["'none'"],
    trustTokenRedemption: ["'none'"]
  },
  crossOriginPolicies: {
    coop: 'same-origin',
    coep: 'require-corp',
    corp: 'same-origin'
  },
  cacheControl: {
    sensitive: 'no-store, no-cache, must-revalidate, proxy-revalidate',
    static: 'public, max-age=31536000, immutable',
    api: 'no-store, no-cache, must-revalidate'
  },
  removeHeaders: ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-AspNetMvc-Version']
};

// =============================================================================
// MIDDLEWARE CLASS
// =============================================================================

export class SecurityHeadersMiddleware {
  private config: SecurityHeadersConfig;
  private nonceGenerator?: () => string;

  constructor(config: Partial<SecurityHeadersConfig> = {}) {
    this.config = this.mergeConfig(config);
  }

  /**
   * Слияние конфигураций
   */
  private mergeConfig(custom: Partial<SecurityHeadersConfig>): SecurityHeadersConfig {
    return {
      ...DEFAULT_SECURITY_CONFIG,
      ...custom,
      csp: { ...DEFAULT_SECURITY_CONFIG.csp, ...custom.csp },
      hsts: { ...DEFAULT_SECURITY_CONFIG.hsts, ...custom.hsts },
      permissionsPolicy: { ...DEFAULT_SECURITY_CONFIG.permissionsPolicy, ...custom.permissionsPolicy },
      crossOriginPolicies: { ...DEFAULT_SECURITY_CONFIG.crossOriginPolicies, ...custom.crossOriginPolicies },
      cacheControl: { ...DEFAULT_SECURITY_CONFIG.cacheControl, ...custom.cacheControl }
    };
  }

  /**
   * Middleware функция
   */
  handle(req: IncomingMessage, res: ServerResponse, next?: () => void): void {
    // Content-Security-Policy
    this.setCSP(res, req);

    // Strict-Transport-Security
    this.setHSTS(res);

    // X-Frame-Options
    this.setXFrameOptions(res);

    // X-Content-Type-Options
    this.setXContentTypeOptions(res);

    // X-XSS-Protection
    this.setXXSSProtection(res);

    // Referrer-Policy
    this.setReferrerPolicy(res);

    // Permissions-Policy
    this.setPermissionsPolicy(res);

    // Cross-Origin-Policies
    this.setCrossOriginPolicies(res);

    // Cache-Control
    this.setCacheControl(res, req);

    // Remove headers
    this.removeHeaders(res);

    if (next) {
      next();
    }
  }

  // =============================================================================
  // УСТАНОВКА HEADERS
  // =============================================================================

  /**
   * Установка Content-Security-Policy
   */
  private setCSP(res: ServerResponse, req: IncomingMessage): void {
    const csp = this.config.csp;
    const directives: string[] = [];

    // Генерация nonce если нужно
    const nonce = this.nonceGenerator?.();
    const nonceValue = nonce ? `'nonce-${nonce}'` : undefined;

    if (csp.defaultSrc?.length) {
      directives.push(`default-src ${csp.defaultSrc.join(' ')}`);
    }

    if (csp.scriptSrc?.length) {
      const scriptSrc = [...csp.scriptSrc];
      if (nonceValue) scriptSrc.push(nonceValue);
      if (csp.useUnsafeInline) scriptSrc.push("'unsafe-inline'");
      if (csp.strictDynamic) scriptSrc.push("'strict-dynamic'");
      directives.push(`script-src ${scriptSrc.join(' ')}`);
    }

    if (csp.styleSrc?.length) {
      const styleSrc = [...csp.styleSrc];
      if (nonceValue) styleSrc.push(nonceValue);
      if (csp.useUnsafeInline) styleSrc.push("'unsafe-inline'");
      directives.push(`style-src ${styleSrc.join(' ')}`);
    }

    if (csp.imgSrc?.length) {
      directives.push(`img-src ${csp.imgSrc.join(' ')}`);
    }

    if (csp.fontSrc?.length) {
      directives.push(`font-src ${csp.fontSrc.join(' ')}`);
    }

    if (csp.connectSrc?.length) {
      directives.push(`connect-src ${csp.connectSrc.join(' ')}`);
    }

    if (csp.mediaSrc?.length) {
      directives.push(`media-src ${csp.mediaSrc.join(' ')}`);
    }

    if (csp.objectSrc?.length) {
      directives.push(`object-src ${csp.objectSrc.join(' ')}`);
    }

    if (csp.frameSrc?.length) {
      directives.push(`frame-src ${csp.frameSrc.join(' ')}`);
    }

    if (csp.workerSrc?.length) {
      directives.push(`worker-src ${csp.workerSrc.join(' ')}`);
    }

    if (csp.baseUri?.length) {
      directives.push(`base-uri ${csp.baseUri.join(' ')}`);
    }

    if (csp.formAction?.length) {
      directives.push(`form-action ${csp.formAction.join(' ')}`);
    }

    if (csp.frameAncestors?.length) {
      directives.push(`frame-ancestors ${csp.frameAncestors.join(' ')}`);
    }

    if (csp.upgradeInsecureRequests) {
      directives.push('upgrade-insecure-requests');
    }

    if (csp.blockAllMixedContent) {
      directives.push('block-all-mixed-content');
    }

    if (csp.reportUri) {
      directives.push(`report-uri ${csp.reportUri}`);
    }

    if (csp.reportTo) {
      directives.push(`report-to ${csp.reportTo}`);
    }

    res.setHeader('Content-Security-Policy', directives.join('; '));

    // Сохранение nonce в response locals для использования в шаблоне
    if (nonce) {
      (res as any).locals = (res as any).locals || {};
      (res as any).locals.nonce = nonce;
    }
  }

  /**
   * Установка Strict-Transport-Security
   */
  private setHSTS(res: ServerResponse): void {
    const hsts = this.config.hsts;
    let value = `max-age=${hsts.maxAge}`;

    if (hsts.includeSubDomains) {
      value += '; includeSubDomains';
    }

    if (hsts.preload) {
      value += '; preload';
    }

    res.setHeader('Strict-Transport-Security', value);
  }

  /**
   * Установка X-Frame-Options
   */
  private setXFrameOptions(res: ServerResponse): void {
    res.setHeader('X-Frame-Options', this.config.xFrameOptions);
  }

  /**
   * Установка X-Content-Type-Options
   */
  private setXContentTypeOptions(res: ServerResponse): void {
    res.setHeader('X-Content-Type-Options', this.config.xContentTypeOptions);
  }

  /**
   * Установка X-XSS-Protection
   */
  private setXXSSProtection(res: ServerResponse): void {
    res.setHeader('X-XSS-Protection', this.config.xXSSProtection);
  }

  /**
   * Установка Referrer-Policy
   */
  private setReferrerPolicy(res: ServerResponse): void {
    res.setHeader('Referrer-Policy', this.config.referrerPolicy);
  }

  /**
   * Установка Permissions-Policy
   */
  private setPermissionsPolicy(res: ServerResponse): void {
    const policy = this.config.permissionsPolicy;
    const directives: string[] = [];

    const features = [
      'geolocation', 'microphone', 'camera', 'payment', 'usb',
      'fullscreen', 'accelerometer', 'gyroscope', 'magnetometer',
      'ambient-light-sensor', 'autoplay', 'encrypted-media',
      'picture-in-picture', 'sync-xhr', 'wake-lock', 'serial',
      'trust-token-redemption'
    ];

    for (const feature of features) {
      const value = (policy as any)[feature];
      if (value && Array.isArray(value)) {
        directives.push(`${feature}=(${value.join(' ')})`);
      }
    }

    if (directives.length > 0) {
      res.setHeader('Permissions-Policy', directives.join(', '));
    }
  }

  /**
   * Установка Cross-Origin-Policies
   */
  private setCrossOriginPolicies(res: ServerResponse): void {
    const policies = this.config.crossOriginPolicies;

    res.setHeader('Cross-Origin-Opener-Policy', policies.coop);
    res.setHeader('Cross-Origin-Embedder-Policy', policies.coep);
    res.setHeader('Cross-Origin-Resource-Policy', policies.corp);
  }

  /**
   * Установка Cache-Control
   */
  private setCacheControl(res: ServerResponse, req: IncomingMessage): void {
    const cache = this.config.cacheControl;
    const url = req.url || '';

    // API endpoints
    if (url.startsWith('/api/')) {
      res.setHeader('Cache-Control', cache.api);
      return;
    }

    // Статические ресурсы
    if (/\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/.test(url)) {
      res.setHeader('Cache-Control', cache.static);
      return;
    }

    // Чувствительные страницы
    if (/\/(login|logout|account|settings|admin|dashboard)/.test(url)) {
      res.setHeader('Cache-Control', cache.sensitive);
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      return;
    }

    // По умолчанию
    res.setHeader('Cache-Control', 'public, max-age=300');
  }

  /**
   * Удаление информационных headers
   */
  private removeHeaders(res: ServerResponse): void {
    for (const header of this.config.removeHeaders) {
      res.removeHeader(header);
    }
  }

  // =============================================================================
  // УТИЛИТЫ
  // =============================================================================

  /**
   * Установка генератора nonce
   */
  setNonceGenerator(generator: () => string): void {
    this.nonceGenerator = generator;
  }

  /**
   * Получение CSP для meta тега
   */
  getCSPMetaTag(): string {
    const csp = this.config.csp;
    const directives: string[] = [];

    if (csp.defaultSrc?.length) {
      directives.push(`default-src ${csp.defaultSrc.join(' ')}`);
    }

    if (csp.scriptSrc?.length) {
      directives.push(`script-src ${csp.scriptSrc.join(' ')}`);
    }

    if (csp.styleSrc?.length) {
      directives.push(`style-src ${csp.styleSrc.join(' ')}`);
    }

    return directives.join('; ');
  }

  /**
   * Получение конфигурации
   */
  getConfig(): SecurityHeadersConfig {
    return { ...this.config };
  }

  /**
   * Обновление конфигурации
   */
  updateConfig(updates: Partial<SecurityHeadersConfig>): void {
    this.config = this.mergeConfig(updates);
  }
}

// =============================================================================
// ЭКСПОРТ
// =============================================================================

export function createSecurityHeadersMiddleware(
  config?: Partial<SecurityHeadersConfig>
): SecurityHeadersMiddleware {
  return new SecurityHeadersMiddleware(config);
}

/**
 * Express middleware wrapper
 */
export function expressSecurityHeaders(config?: Partial<SecurityHeadersConfig>) {
  const middleware = new SecurityHeadersMiddleware(config);
  return (req: any, res: any, next: () => void) => {
    middleware.handle(req, res, next);
  };
}

/**
 * Koa middleware wrapper
 */
export function koaSecurityHeaders(config?: Partial<SecurityHeadersConfig>) {
  const middleware = new SecurityHeadersMiddleware(config);
  return async (ctx: any, next: () => Promise<void>) => {
    middleware.handle(ctx.req, ctx.res);
    await next();
  };
}
