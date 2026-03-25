/**
 * ============================================================================
 * SECURITY HEADERS MIDDLEWARE
 * ============================================================================
 * Полный набор security headers для защиты веб-приложений
 * Соответствует: OWASP Secure Headers Project
 * ============================================================================
 */

import { IncomingMessage, ServerResponse } from 'http';

/**
 * Конфигурация security headers
 */
export interface SecurityHeadersConfig {
  csp: CSPConfig;
  hsts: HSTSConfig;
  xFrameOptions: 'DENY' | 'SAMEORIGIN';
  xContentTypeOptions: 'nosniff';
  xXSSProtection: '1; mode=block';
  referrerPolicy: ReferrerPolicy;
  permissionsPolicy: PermissionsPolicyConfig;
  crossOriginPolicies: CrossOriginPoliciesConfig;
  cacheControl: CacheControlConfig;
  removeHeaders: string[];
}

/**
 * CSP директивы
 */
export interface CSPConfig {
  defaultSrc: string[];
  scriptSrc: string[];
  styleSrc: string[];
  imgSrc: string[];
  fontSrc: string[];
  connectSrc: string[];
  mediaSrc: string[];
  objectSrc: string[];
  frameSrc: string[];
  workerSrc: string[];
  baseUri: string[];
  formAction: string[];
  frameAncestors: string[];
  upgradeInsecureRequests: boolean;
  blockAllMixedContent: boolean;
  reportUri?: string;
  reportTo?: string;
  strictDynamic: boolean;
  useUnsafeInline: boolean;
}

/**
 * HSTS конфигурация
 */
export interface HSTSConfig {
  maxAge: number;
  includeSubDomains: boolean;
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
  geolocation: string[];
  microphone: string[];
  camera: string[];
  payment: string[];
  usb: string[];
  fullscreen: string[];
  accelerometer: string[];
  gyroscope: string[];
  magnetometer: string[];
  ambientLightSensor: string[];
  autoplay: string[];
  encryptedMedia: string[];
  pictureInPicture: string[];
  syncXhr: string[];
  wakeLock: string[];
  serial: string[];
  trustTokenRedemption: string[];
}

/**
 * Cross-Origin Policies
 */
export interface CrossOriginPoliciesConfig {
  openerPolicy: 'same-origin' | 'same-origin-allow-popouts' | 'unsafe-none';
  embedderPolicy: 'unsafe-none' | 'require-corp' | 'same-origin';
  resourcePolicy: 'same-site' | 'same-origin' | 'cross-origin';
}

/**
 * Cache Control
 */
export interface CacheControlConfig {
  noStore: boolean;
  noCache: boolean;
  maxAge?: number;
  private: boolean;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: SecurityHeadersConfig = {
  csp: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'"],
    imgSrc: ["'self'", 'data:', 'https:'],
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
    strictDynamic: false,
    useUnsafeInline: false
  },
  hsts: {
    maxAge: 31536000,
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
    autoplay: ["'self'"],
    encryptedMedia: ["'self'"],
    pictureInPicture: ["'self'"],
    syncXhr: ["'none'"],
    wakeLock: ["'none'"],
    serial: ["'none'"],
    trustTokenRedemption: ["'none'"]
  },
  crossOriginPolicies: {
    openerPolicy: 'same-origin',
    embedderPolicy: 'require-corp',
    resourcePolicy: 'same-origin'
  },
  cacheControl: {
    noStore: false,
    noCache: false,
    private: true
  },
  removeHeaders: ['X-Powered-By', 'Server']
};

/**
 * Security Headers Middleware
 */
export class SecurityHeadersMiddleware {
  private readonly config: SecurityHeadersConfig;

  constructor(config: Partial<SecurityHeadersConfig> = {}) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
      csp: { ...DEFAULT_CONFIG.csp, ...config.csp },
      hsts: { ...DEFAULT_CONFIG.hsts, ...config.hsts },
      permissionsPolicy: { ...DEFAULT_CONFIG.permissionsPolicy, ...config.permissionsPolicy },
      crossOriginPolicies: { ...DEFAULT_CONFIG.crossOriginPolicies, ...config.crossOriginPolicies },
      cacheControl: { ...DEFAULT_CONFIG.cacheControl, ...config.cacheControl }
    };
  }

  /**
   * Middleware функция
   */
  handle = (req: IncomingMessage, res: ServerResponse, next: () => void): void => {
    // Content-Security-Policy
    this.setCSP(res);

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

    // Cross-Origin-Policy
    this.setCrossOriginPolicies(res);

    // Cache-Control
    this.setCacheControl(res);

    // Remove headers
    this.removeHeaders(res);

    next();
  };

  /**
   * Content-Security-Policy
   */
  private setCSP(res: ServerResponse): void {
    const csp = this.config.csp;
    const directives: string[] = [];

    // Helper для построения директивы
    const buildDirective = (name: string, values: string[]): string => {
      if (!values || values.length === 0) return '';
      return `${name} ${values.join(' ')}`;
    };

    // Основные директивы
    if (csp.defaultSrc) directives.push(buildDirective('default-src', csp.defaultSrc));
    if (csp.scriptSrc) {
      const scriptValues = [...csp.scriptSrc];
      if (csp.strictDynamic) scriptValues.push("'strict-dynamic'");
      if (csp.useUnsafeInline) scriptValues.push("'unsafe-inline'");
      directives.push(buildDirective('script-src', scriptValues));
    }
    if (csp.styleSrc) directives.push(buildDirective('style-src', csp.styleSrc));
    if (csp.imgSrc) directives.push(buildDirective('img-src', csp.imgSrc));
    if (csp.fontSrc) directives.push(buildDirective('font-src', csp.fontSrc));
    if (csp.connectSrc) directives.push(buildDirective('connect-src', csp.connectSrc));
    if (csp.mediaSrc) directives.push(buildDirective('media-src', csp.mediaSrc));
    if (csp.objectSrc) directives.push(buildDirective('object-src', csp.objectSrc));
    if (csp.frameSrc) directives.push(buildDirective('frame-src', csp.frameSrc));
    if (csp.workerSrc) directives.push(buildDirective('worker-src', csp.workerSrc));
    if (csp.baseUri) directives.push(buildDirective('base-uri', csp.baseUri));
    if (csp.formAction) directives.push(buildDirective('form-action', csp.formAction));
    if (csp.frameAncestors) directives.push(buildDirective('frame-ancestors', csp.frameAncestors));

    // Дополнительные директивы
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

    const cspHeader = directives.filter(d => d).join('; ');
    res.setHeader('Content-Security-Policy', cspHeader);
  }

  /**
   * Strict-Transport-Security
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
   * X-Frame-Options
   */
  private setXFrameOptions(res: ServerResponse): void {
    res.setHeader('X-Frame-Options', this.config.xFrameOptions);
  }

  /**
   * X-Content-Type-Options
   */
  private setXContentTypeOptions(res: ServerResponse): void {
    res.setHeader('X-Content-Type-Options', this.config.xContentTypeOptions);
  }

  /**
   * X-XSS-Protection
   */
  private setXXSSProtection(res: ServerResponse): void {
    res.setHeader('X-XSS-Protection', this.config.xXSSProtection);
  }

  /**
   * Referrer-Policy
   */
  private setReferrerPolicy(res: ServerResponse): void {
    res.setHeader('Referrer-Policy', this.config.referrerPolicy);
  }

  /**
   * Permissions-Policy
   */
  private setPermissionsPolicy(res: ServerResponse): void {
    const policy = this.config.permissionsPolicy;
    const directives: string[] = [];

    const buildFeature = (name: string, values: string[]): string => {
      return `${name}=(${values.join(' ')})`;
    };

    if (policy.geolocation) directives.push(buildFeature('geolocation', policy.geolocation));
    if (policy.microphone) directives.push(buildFeature('microphone', policy.microphone));
    if (policy.camera) directives.push(buildFeature('camera', policy.camera));
    if (policy.payment) directives.push(buildFeature('payment', policy.payment));
    if (policy.usb) directives.push(buildFeature('usb', policy.usb));
    if (policy.fullscreen) directives.push(buildFeature('fullscreen', policy.fullscreen));
    if (policy.accelerometer) directives.push(buildFeature('accelerometer', policy.accelerometer));
    if (policy.gyroscope) directives.push(buildFeature('gyroscope', policy.gyroscope));
    if (policy.magnetometer) directives.push(buildFeature('magnetometer', policy.magnetometer));
    if (policy.ambientLightSensor) directives.push(buildFeature('ambient-light-sensor', policy.ambientLightSensor));
    if (policy.autoplay) directives.push(buildFeature('autoplay', policy.autoplay));
    if (policy.encryptedMedia) directives.push(buildFeature('encrypted-media', policy.encryptedMedia));
    if (policy.pictureInPicture) directives.push(buildFeature('picture-in-picture', policy.pictureInPicture));
    if (policy.syncXhr) directives.push(buildFeature('sync-xhr', policy.syncXhr));
    if (policy.wakeLock) directives.push(buildFeature('wake-lock', policy.wakeLock));
    if (policy.serial) directives.push(buildFeature('serial', policy.serial));
    if (policy.trustTokenRedemption) directives.push(buildFeature('trust-token-redemption', policy.trustTokenRedemption));

    res.setHeader('Permissions-Policy', directives.join(', '));
  }

  /**
   * Cross-Origin-Policy
   */
  private setCrossOriginPolicies(res: ServerResponse): void {
    const policies = this.config.crossOriginPolicies;

    res.setHeader('Cross-Origin-Opener-Policy', policies.openerPolicy);
    res.setHeader('Cross-Origin-Embedder-Policy', policies.embedderPolicy);
    res.setHeader('Cross-Origin-Resource-Policy', policies.resourcePolicy);
  }

  /**
   * Cache-Control
   */
  private setCacheControl(res: ServerResponse): void {
    const cache = this.config.cacheControl;
    const directives: string[] = [];

    if (cache.noStore) directives.push('no-store');
    if (cache.noCache) directives.push('no-cache');
    if (cache.private) directives.push('private');
    if (cache.maxAge !== undefined) directives.push(`max-age=${cache.maxAge}`);

    if (directives.length > 0) {
      res.setHeader('Cache-Control', directives.join(', '));
    }
  }

  /**
   * Remove headers
   */
  private removeHeaders(res: ServerResponse): void {
    for (const header of this.config.removeHeaders) {
      res.removeHeader(header);
    }
  }

  /**
   * Получение конфигурации
   */
  getConfig(): SecurityHeadersConfig {
    return { ...this.config };
  }
}

/**
 * Factory функция
 */
export function createSecurityHeadersMiddleware(
  config?: Partial<SecurityHeadersConfig>
): SecurityHeadersMiddleware {
  return new SecurityHeadersMiddleware(config);
}

/**
 * Presets для быстрого использования
 */
export const SecurityHeadersPresets = {
  /** Строгий preset для API */
  strict: {
    csp: {
      defaultSrc: ["'none'"],
      scriptSrc: ["'none'"],
      styleSrc: ["'none'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: true,
      blockAllMixedContent: true,
      strictDynamic: false,
      useUnsafeInline: false
    },
    hsts: {
      maxAge: 63072000,
      includeSubDomains: true,
      preload: true
    },
    xFrameOptions: 'DENY' as const,
    xContentTypeOptions: 'nosniff' as const,
    xXSSProtection: '1; mode=block' as const,
    referrerPolicy: 'no-referrer' as const,
    permissionsPolicy: {
      geolocation: ["'none'"],
      microphone: ["'none'"],
      camera: ["'none'"],
      payment: ["'none'"],
      usb: ["'none'"],
      fullscreen: ["'none'"],
      accelerometer: ["'none'"],
      gyroscope: ["'none'"],
      magnetometer: ["'none'"],
      ambientLightSensor: ["'none'"],
      autoplay: ["'none'"],
      encryptedMedia: ["'none'"],
      pictureInPicture: ["'none'"],
      syncXhr: ["'none'"],
      wakeLock: ["'none'"],
      serial: ["'none'"],
      trustTokenRedemption: ["'none'"]
    },
    crossOriginPolicies: {
      openerPolicy: 'same-origin' as const,
      embedderPolicy: 'require-corp' as const,
      resourcePolicy: 'same-origin' as const
    },
    cacheControl: {
      noStore: true,
      noCache: true,
      private: true
    },
    removeHeaders: ['X-Powered-By', 'Server', 'X-AspNet-Version']
  },

  /** Standard preset для веб-приложений */
  standard: {
    ...DEFAULT_CONFIG
  },

  /** Relax preset для разработки */
  development: {
    csp: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      fontSrc: ["'self'", 'https:', 'data:'],
      connectSrc: ["'self'", 'ws:', 'wss:'],
      mediaSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'self'"],
      workerSrc: ["'self'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
      upgradeInsecureRequests: false,
      blockAllMixedContent: false,
      strictDynamic: false,
      useUnsafeInline: true
    },
    hsts: {
      maxAge: 0,
      includeSubDomains: false,
      preload: false
    },
    xFrameOptions: 'SAMEORIGIN' as const,
    xContentTypeOptions: 'nosniff' as const,
    xXSSProtection: '1; mode=block' as const,
    referrerPolicy: 'strict-origin-when-cross-origin' as const,
    permissionsPolicy: {
      geolocation: ["'self'"],
      microphone: ["'self'"],
      camera: ["'self'"],
      payment: ["'none'"],
      usb: ["'none'"],
      fullscreen: ["'self'"],
      accelerometer: ["'self'"],
      gyroscope: ["'self'"],
      magnetometer: ["'self'"],
      ambientLightSensor: ["'self'"],
      autoplay: ["'self'"],
      encryptedMedia: ["'self'"],
      pictureInPicture: ["'self'"],
      syncXhr: ["'self'"],
      wakeLock: ["'self'"],
      serial: ["'self'"],
      trustTokenRedemption: ["'none'"]
    },
    crossOriginPolicies: {
      openerPolicy: 'same-origin-allow-popouts' as const,
      embedderPolicy: 'unsafe-none' as const,
      resourcePolicy: 'cross-origin' as const
    },
    cacheControl: {
      noStore: false,
      noCache: false,
      private: false
    },
    removeHeaders: ['X-Powered-By']
  }
};
