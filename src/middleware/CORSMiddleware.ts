/**
 * =============================================================================
 * CORS MIDDLEWARE
 * =============================================================================
 * Cross-Origin Resource Sharing (CORS) security middleware
 * 
 * Features:
 * - Domain whitelist/blacklist
 * - Dynamic origin validation
 * - Preflight request caching
 * - Credentials support
 * - Custom headers/methods configuration
 * 
 * @author Theodor Munch
 * @license MIT
 * @version 2.0.0
 * =============================================================================
 */

import { Request, Response, NextFunction } from 'express';

/**
 * CORS Configuration interface
 */
export interface CORSConfig {
  /**
   * Allowed origins (can be string, RegExp, or function)
   */
  origin?: string | RegExp | ((origin: string, callback: (err: Error | null, allow?: boolean) => void) => void) | Array<string | RegExp>;
  
  /**
   * Allowed HTTP methods
   * @default ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
   */
  methods?: string | string[];
  
  /**
   * Allowed headers
   * @default ['Content-Type', 'Authorization', 'X-Requested-With']
   */
  allowedHeaders?: string | string[];
  
  /**
   * Exposed headers (client can access)
   */
  exposedHeaders?: string | string[];
  
  /**
   * Allow credentials (cookies, authorization headers)
   * @default false
   */
  credentials?: boolean;
  
  /**
   * Max age for preflight cache (in seconds)
   * @default 86400 (24 hours)
   */
  maxAge?: number;
  
  /**
   * Preflight continue - pass control to next middleware
   * @default false
   */
  preflightContinue?: boolean;
  
  /**
   * Options success status code
   * @default 204
   */
  optionsSuccessStatus?: number;
  
  /**
   * Enable strict CORS mode (validate origin strictly)
   * @default false
   */
  strict?: boolean;
  
  /**
   * Blacklisted origins (always block)
   */
  blacklistedOrigins?: string[];
  
  /**
   * Enable dynamic origin reflection (use with caution!)
   * @default false
   */
  dynamicOrigin?: boolean;
}

/**
 * Default CORS configuration
 */
const DEFAULT_CONFIG: CORSConfig = {
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID'],
  exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
  credentials: false,
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204,
  strict: false,
  blacklistedOrigins: [],
  dynamicOrigin: false,
};

/**
 * Compile origin matcher from string, RegExp, or array
 */
function compileOriginMatcher(origin: CORSConfig['origin']): Function {
  if (!origin) {
    return () => true;
  }
  
  if (typeof origin === 'string') {
    if (origin === '*') {
      return () => '*';
    }
    return (reqOrigin: string) => reqOrigin === origin ? origin : false;
  }
  
  if (origin instanceof RegExp) {
    return (reqOrigin: string) => origin.test(reqOrigin) ? reqOrigin : false;
  }
  
  if (Array.isArray(origin)) {
    const matchers = origin.map(o => {
      if (typeof o === 'string') {
        return (reqOrigin: string) => reqOrigin === o ? o : false;
      }
      if (o instanceof RegExp) {
        return (reqOrigin: string) => o.test(reqOrigin) ? reqOrigin : false;
      }
      return () => false;
    });
    
    return (reqOrigin: string) => {
      for (const matcher of matchers) {
        const result = matcher(reqOrigin);
        if (result) return result;
      }
      return false;
    };
  }
  
  if (typeof origin === 'function') {
    return origin;
  }
  
  return () => false;
}

/**
 * Normalize headers array to comma-separated string
 */
function normalizeHeaders(headers: string | string[] | undefined): string {
  if (!headers) {
    return '';
  }
  return Array.isArray(headers) ? headers.join(', ') : headers;
}

/**
 * Check if origin is blacklisted
 */
function isBlacklisted(origin: string | undefined, blacklist: string[]): boolean {
  if (!origin) return false;
  return blacklist.some(bl => {
    if (bl.includes('*')) {
      const pattern = bl.replace(/\./g, '\\.').replace(/\*/g, '.*');
      return new RegExp(`^${pattern}$`).test(origin);
    }
    return origin === bl;
  });
}

/**
 * CORS Middleware Factory
 * 
 * @param config - CORS configuration
 * @returns Express middleware function
 * 
 * @example
 * ```typescript
 * const corsMiddleware = createCORS({
 *   origin: ['https://app.example.com', 'https://admin.example.com'],
 *   credentials: true,
 *   maxAge: 86400,
 * });
 * 
 * app.use(corsMiddleware);
 * ```
 */
export function createCORS(config: CORSConfig = {}) {
  const mergedConfig: CORSConfig = { ...DEFAULT_CONFIG, ...config };
  const originMatcher = compileOriginMatcher(mergedConfig.origin);
  
  return (req: Request, res: Response, next: NextFunction): void => {
    const reqOrigin = req.headers.origin as string | undefined;
    
    // Check blacklist first
    if (isBlacklisted(reqOrigin, mergedConfig.blacklistedOrigins || [])) {
      res.setHeader('Access-Control-Allow-Origin', 'null');
      res.setHeader('Access-Control-Allow-Methods', 'NONE');
      res.setHeader('Access-Control-Allow-Headers', 'NONE');
      next();
      return;
    }
    
    // Determine allowed origin
    let allowedOrigin: string | null = null;
    
    if (typeof originMatcher === 'function') {
      const result = originMatcher(reqOrigin || '');
      if (result === true || result === '*') {
        allowedOrigin = '*';
      } else if (result) {
        allowedOrigin = result as string;
      }
    } else {
      allowedOrigin = originMatcher as string;
    }
    
    // Dynamic origin reflection (use with caution!)
    if (mergedConfig.dynamicOrigin && reqOrigin && allowedOrigin === '*') {
      allowedOrigin = reqOrigin;
    }
    
    // Set CORS headers
    if (allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    }
    
    // Vary header (important for caching)
    const varyHeaders = ['Origin'];
    if (mergedConfig.allowedHeaders) {
      varyHeaders.push('Access-Control-Request-Headers');
    }
    res.setHeader('Vary', varyHeaders.join(', '));
    
    // Allow credentials
    if (mergedConfig.credentials && allowedOrigin && allowedOrigin !== '*') {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    
    // Exposed headers
    if (mergedConfig.exposedHeaders) {
      res.setHeader('Access-Control-Expose-Headers', normalizeHeaders(mergedConfig.exposedHeaders));
    }
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      // Allow methods
      if (mergedConfig.methods) {
        res.setHeader('Access-Control-Allow-Methods', normalizeHeaders(mergedConfig.methods));
      }
      
      // Allow headers
      if (mergedConfig.allowedHeaders) {
        res.setHeader('Access-Control-Allow-Headers', normalizeHeaders(mergedConfig.allowedHeaders));
      }
      
      // Max age
      if (mergedConfig.maxAge !== undefined) {
        res.setHeader('Access-Control-Max-Age', String(mergedConfig.maxAge));
      }
      
      // Send response
      res.statusCode = mergedConfig.optionsSuccessStatus || 204;
      res.setHeader('Content-Length', '0');
      
      if (!mergedConfig.preflightContinue) {
        res.end();
        return;
      }
    } else {
      // For non-preflight requests, still set allow methods/headers
      if (mergedConfig.methods) {
        res.setHeader('Access-Control-Allow-Methods', normalizeHeaders(mergedConfig.methods));
      }
      if (mergedConfig.allowedHeaders) {
        res.setHeader('Access-Control-Allow-Headers', normalizeHeaders(mergedConfig.allowedHeaders));
      }
    }
    
    next();
  };
}

/**
 * Pre-configured CORS presets for common scenarios
 */
export const CORSPresets = {
  /**
   * Public API - allow all origins
   */
  public: createCORS({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: false,
    maxAge: 3600,
  }),
  
  /**
   * Private API - specific origins only
   */
  private: (allowedOrigins: string[]) => createCORS({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID'],
    credentials: true,
    maxAge: 86400,
    strict: true,
  }),
  
  /**
   * Development - allow localhost with dynamic origin
   */
  dev: createCORS({
    origin: [/^https?:\/\/localhost(:\d+)?$/, /^https?:\/\/127\.0\.0\.1(:\d+)?$/],
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    maxAge: 600,
    dynamicOrigin: true,
  }),
  
  /**
   * API Gateway - strict with credentials
   */
  apiGateway: (domains: string[]) => createCORS({
    origin: domains,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-Request-ID', 'X-API-Key'],
    exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
    credentials: true,
    maxAge: 86400,
    strict: true,
    blacklistedOrigins: [],
  }),
  
  /**
   * Microservice - internal only
   */
  microservice: createCORS({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Service-Key'],
    credentials: false,
    maxAge: 86400,
  }),
};

/**
 * Validate CORS configuration
 */
export function validateCORSConfig(config: CORSConfig): Error[] {
  const errors: Error[] = [];
  
  // Check for dangerous wildcard with credentials
  if (config.origin === '*' && config.credentials === true) {
    errors.push(new Error('Cannot use wildcard origin (*) with credentials enabled'));
  }
  
  // Check max age
  if (config.maxAge !== undefined && (config.maxAge < 0 || config.maxAge > 86400 * 30)) {
    errors.push(new Error('maxAge must be between 0 and 2592000 seconds (30 days)'));
  }
  
  // Check for dynamic origin with strict mode
  if (config.dynamicOrigin === true && config.strict === true) {
    errors.push(new Error('Cannot use dynamicOrigin with strict mode'));
  }
  
  // Validate origin patterns
  if (Array.isArray(config.origin)) {
    config.origin.forEach((origin, index) => {
      if (typeof origin === 'string' && origin.includes('*') && origin !== '*') {
        // Wildcard in domain - should be RegExp
        errors.push(new Error(`Origin at index ${index} contains wildcard - use RegExp instead`));
      }
    });
  }
  
  return errors;
}

export default createCORS;
