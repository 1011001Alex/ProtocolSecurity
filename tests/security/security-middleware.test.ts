/**
 * =============================================================================
 * COMPREHENSIVE TESTS FOR SECURITY MIDDLEWARE
 * =============================================================================
 * Полное покрытие всех security middleware:
 * - SecurityHeadersMiddleware
 * - RateLimitMiddleware
 * =============================================================================
 */

import { IncomingMessage, ServerResponse } from 'http';
import {
  SecurityHeadersMiddleware,
  createSecurityHeadersMiddleware,
  expressSecurityHeaders,
  CSP_STRICT,
  CSP_DEVELOPMENT,
  DEFAULT_SECURITY_CONFIG
} from '../../src/middleware/SecurityHeadersMiddleware';

import {
  RateLimiter,
  createRateLimiter,
  createMemoryStore,
  createRedisStore,
  createGlobalRule,
  createPerIPRule,
  createPerUserRule,
  createAPIRule,
  createAuthRule,
  RateLimitRule,
  MemoryStore,
  RateLimitResult
} from '../../src/middleware/RateLimitMiddleware';

// =============================================================================
// MOCKS
// =============================================================================

const createMockRequest = (overrides: Partial<IncomingMessage> = {}): IncomingMessage => {
  return {
    url: '/api/test',
    method: 'GET',
    headers: {},
    socket: {
      remoteAddress: '192.168.1.100'
    },
    ...overrides
  } as IncomingMessage;
};

const createMockResponse = (): ServerResponse => {
  const res: Partial<ServerResponse> = {
    statusCode: 200,
    headers: {} as any,
    setHeader: jest.fn(function (name: string, value: string) {
      (this.headers as any)[name] = value;
      return this;
    }),
    getHeader: jest.fn(function (name: string) {
      return (this.headers as any)[name];
    }),
    removeHeader: jest.fn(function (name: string) {
      delete (this.headers as any)[name];
    }),
    end: jest.fn()
  };
  return res as ServerResponse;
};

// =============================================================================
// SECURITY HEADERS MIDDLEWARE TESTS
// =============================================================================

describe('SecurityHeadersMiddleware', () => {
  let middleware: SecurityHeadersMiddleware;
  let req: IncomingMessage;
  let res: ServerResponse;

  beforeEach(() => {
    middleware = createSecurityHeadersMiddleware();
    req = createMockRequest();
    res = createMockResponse();
  });

  // =============================================================================
  // CREATION TESTS
  // =============================================================================

  describe('Creation', () => {
    it('должен создавать middleware с конфигурацией по умолчанию', () => {
      expect(middleware).toBeDefined();
      expect(middleware).toBeInstanceOf(SecurityHeadersMiddleware);
    });

    it('должен создавать middleware с кастомной конфигурацией', () => {
      const customMiddleware = createSecurityHeadersMiddleware({
        xFrameOptions: 'SAMEORIGIN',
        hsts: {
          maxAge: 3600,
          includeSubDomains: false,
          preload: false
        }
      });

      expect(customMiddleware).toBeDefined();
    });
  });

  // =============================================================================
  // CSP TESTS
  // =============================================================================

  describe('Content-Security-Policy', () => {
    it('должен устанавливать CSP header', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Content-Security-Policy',
        expect.stringContaining('default-src')
      );
    });

    it('должен устанавливать строгий CSP для production', () => {
      const strictMiddleware = createSecurityHeadersMiddleware({
        csp: CSP_STRICT
      });

      strictMiddleware.handle(req, res);

      const cspHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Content-Security-Policy'
      )?.[1];

      expect(cspHeader).toContain("default-src 'self'");
      expect(cspHeader).toContain("script-src 'self'");
      expect(cspHeader).toContain("object-src 'none'");
    });

    it('должен устанавливать relaxed CSP для development', () => {
      const devMiddleware = createSecurityHeadersMiddleware({
        csp: CSP_DEVELOPMENT
      });

      devMiddleware.handle(req, res);

      const cspHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Content-Security-Policy'
      )?.[1];

      expect(cspHeader).toContain("'unsafe-inline'");
      expect(cspHeader).toContain("'unsafe-eval'");
    });

    it('должен добавлять upgrade-insecure-requests', () => {
      middleware.handle(req, res);

      const cspHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Content-Security-Policy'
      )?.[1];

      expect(cspHeader).toContain('upgrade-insecure-requests');
    });

    it('должен добавлять block-all-mixed-content', () => {
      middleware.handle(req, res);

      const cspHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Content-Security-Policy'
      )?.[1];

      expect(cspHeader).toContain('block-all-mixed-content');
    });

    it('должен возвращать CSP meta tag', () => {
      const metaTag = middleware.getCSPMetaTag();
      
      expect(metaTag).toBeDefined();
      expect(metaTag).toContain('default-src');
      expect(typeof metaTag).toBe('string');
    });
  });

  // =============================================================================
  // HSTS TESTS
  // =============================================================================

  describe('Strict-Transport-Security', () => {
    it('должен устанавливать HSTS header', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        expect.stringContaining('max-age=')
      );
    });

    it('должен включать includeSubDomains', () => {
      middleware.handle(req, res);

      const hstsHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Strict-Transport-Security'
      )?.[1];

      expect(hstsHeader).toContain('includeSubDomains');
    });

    it('должен включать preload', () => {
      middleware.handle(req, res);

      const hstsHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Strict-Transport-Security'
      )?.[1];

      expect(hstsHeader).toContain('preload');
    });

    it('должен позволять настраивать max-age', () => {
      const customMiddleware = createSecurityHeadersMiddleware({
        hsts: {
          maxAge: 31536000,
          includeSubDomains: true,
          preload: false
        }
      });

      customMiddleware.handle(req, res);

      const hstsHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Strict-Transport-Security'
      )?.[1];

      expect(hstsHeader).toContain('max-age=31536000');
    });
  });

  // =============================================================================
  // X-FRAME-OPTIONS TESTS
  // =============================================================================

  describe('X-Frame-Options', () => {
    it('должен устанавливать X-Frame-Options: DENY', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'X-Frame-Options',
        'DENY'
      );
    });

    it('должен позволять устанавливать SAMEORIGIN', () => {
      const customMiddleware = createSecurityHeadersMiddleware({
        xFrameOptions: 'SAMEORIGIN'
      });

      customMiddleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'X-Frame-Options',
        'SAMEORIGIN'
      );
    });
  });

  // =============================================================================
  // X-CONTENT-TYPE-OPTIONS TESTS
  // =============================================================================

  describe('X-Content-Type-Options', () => {
    it('должен устанавливать X-Content-Type-Options: nosniff', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'X-Content-Type-Options',
        'nosniff'
      );
    });
  });

  // =============================================================================
  // X-XSS-PROTECTION TESTS
  // =============================================================================

  describe('X-XSS-Protection', () => {
    it('должен устанавливать X-XSS-Protection', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'X-XSS-Protection',
        '1; mode=block'
      );
    });
  });

  // =============================================================================
  // REFERRER-POLICY TESTS
  // =============================================================================

  describe('Referrer-Policy', () => {
    it('должен устанавливать Referrer-Policy', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Referrer-Policy',
        expect.any(String)
      );
    });
  });

  // =============================================================================
  // PERMISSIONS-POLICY TESTS
  // =============================================================================

  describe('Permissions-Policy', () => {
    it('должен устанавливать Permissions-Policy', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Permissions-Policy',
        expect.any(String)
      );
    });

    it('должен запрещать геолокацию', () => {
      middleware.handle(req, res);

      const policyHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Permissions-Policy'
      )?.[1];

      expect(policyHeader).toContain('geolocation');
    });

    it('должен запрещать микрофон', () => {
      middleware.handle(req, res);

      const policyHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Permissions-Policy'
      )?.[1];

      expect(policyHeader).toContain('microphone');
    });

    it('должен запрещать камеру', () => {
      middleware.handle(req, res);

      const policyHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Permissions-Policy'
      )?.[1];

      expect(policyHeader).toContain('camera');
    });
  });

  // =============================================================================
  // CROSS-ORIGIN-POLICIES TESTS
  // =============================================================================

  describe('Cross-Origin-Policies', () => {
    it('должен устанавливать Cross-Origin-Opener-Policy', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Cross-Origin-Opener-Policy',
        'same-origin'
      );
    });

    it('должен устанавливать Cross-Origin-Embedder-Policy', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Cross-Origin-Embedder-Policy',
        'require-corp'
      );
    });

    it('должен устанавливать Cross-Origin-Resource-Policy', () => {
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Cross-Origin-Resource-Policy',
        'same-origin'
      );
    });
  });

  // =============================================================================
  // CACHE-CONTROL TESTS
  // =============================================================================

  describe('Cache-Control', () => {
    it('должен устанавливать no-cache для чувствительных endpoints', () => {
      req = createMockRequest({ url: '/login' });
      middleware.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Cache-Control',
        expect.stringContaining('no-cache')
      );
    });

    it('должен устанавливать public cache для статики', () => {
      req = createMockRequest({ url: '/static/app.js' });
      middleware.handle(req, res);

      const cacheHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Cache-Control'
      )?.[1];

      expect(cacheHeader).toContain('public');
      expect(cacheHeader).toContain('max-age=31536000');
    });

    it('должен устанавливать no-store для API', () => {
      req = createMockRequest({ url: '/api/users' });
      middleware.handle(req, res);

      const cacheHeader = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Cache-Control'
      )?.[1];

      expect(cacheHeader).toContain('no-store');
    });
  });

  // =============================================================================
  // REMOVE HEADERS TESTS
  // =============================================================================

  describe('Remove Headers', () => {
    it('должен удалять X-Powered-By', () => {
      middleware.handle(req, res);

      expect(res.removeHeader).toHaveBeenCalledWith('X-Powered-By');
    });

    it('должен удалять Server header', () => {
      middleware.handle(req, res);

      expect(res.removeHeader).toHaveBeenCalledWith('Server');
    });
  });

  // =============================================================================
  // CONFIGURATION TESTS
  // =============================================================================

  describe('Configuration', () => {
    it('должен возвращать конфигурацию', () => {
      const config = middleware.getConfig();
      
      expect(config).toBeDefined();
      expect(config.csp).toBeDefined();
      expect(config.hsts).toBeDefined();
    });

    it('должен обновлять конфигурацию', () => {
      middleware.updateConfig({
        xFrameOptions: 'SAMEORIGIN'
      });

      const config = middleware.getConfig();
      expect(config.xFrameOptions).toBe('SAMEORIGIN');
    });
  });
});

// =============================================================================
// RATE LIMITING MIDDLEWARE TESTS
// =============================================================================

describe('RateLimitMiddleware', () => {
  let rateLimiter: RateLimiter;
  let store: MemoryStore;
  let req: IncomingMessage;
  let res: ServerResponse;

  beforeEach(async () => {
    store = createMemoryStore();
    rateLimiter = createRateLimiter(store, true);
    await rateLimiter.initialize();

    req = createMockRequest();
    res = createMockResponse();
  });

  afterEach(async () => {
    await rateLimiter.destroy();
    jest.clearAllMocks();
  });

  // =============================================================================
  // CREATION TESTS
  // =============================================================================

  describe('Creation', () => {
    it('должен создавать rate limiter', () => {
      expect(rateLimiter).toBeDefined();
      expect(rateLimiter).toBeInstanceOf(RateLimiter);
    });

    it('должен создавать memory store', () => {
      expect(store).toBeDefined();
      expect(store).toBeInstanceOf(MemoryStore);
    });

    it('должен создавать redis store', () => {
      const redisStore = createRedisStore({
        host: 'localhost',
        port: 6379,
        keyPrefix: 'test'
      });

      expect(redisStore).toBeDefined();
    });
  });

  // =============================================================================
  // RULE CREATION TESTS
  // =============================================================================

  describe('Rule Creation', () => {
    it('должен создавать global rule', () => {
      const rule = createGlobalRule();

      expect(rule).toBeDefined();
      expect(rule.name).toBe('global');
      expect(rule.maxRequests).toBe(1000);
      expect(rule.windowMs).toBe(60000);
    });

    it('должен создавать per-IP rule', () => {
      const rule = createPerIPRule();

      expect(rule).toBeDefined();
      expect(rule.name).toBe('per_ip');
      expect(rule.maxRequests).toBe(100);
    });

    it('должен создавать per-user rule', () => {
      const rule = createPerUserRule();

      expect(rule).toBeDefined();
      expect(rule.name).toBe('per_user');
      expect(rule.maxRequests).toBe(60);
    });

    it('должен создавать API rule', () => {
      const rule = createAPIRule();

      expect(rule).toBeDefined();
      expect(rule.name).toBe('api');
      expect(rule.maxRequests).toBe(30);
    });

    it('должен создавать auth rule', () => {
      const rule = createAuthRule();

      expect(rule).toBeDefined();
      expect(rule.name).toBe('auth');
      expect(rule.maxRequests).toBe(5);
    });
  });

  // =============================================================================
  // RATE LIMITING TESTS
  // =============================================================================

  describe('Rate Limiting', () => {
    it('должен разрешать запросы в пределах лимита', async () => {
      const rule: RateLimitRule = {
        name: 'test',
        algorithm: 'fixed_window',
        maxRequests: 5,
        windowMs: 60000,
        keyGenerator: (req) => 'test-key',
        message: 'Too many requests',
        statusCode: 429,
        headers: true
      };

      rateLimiter.addRule(rule);

      for (let i = 0; i < 5; i++) {
        await rateLimiter.handle(req, res, jest.fn());
        expect(res.statusCode).toBe(200);
      }
    });

    it('должен блокировать запросы при превышении лимита', async () => {
      const rule: RateLimitRule = {
        name: 'test',
        algorithm: 'fixed_window',
        maxRequests: 3,
        windowMs: 60000,
        keyGenerator: (req) => 'test-key',
        message: 'Too many requests',
        statusCode: 429,
        headers: true
      };

      rateLimiter.addRule(rule);

      // Первые 3 запроса успешны
      for (let i = 0; i < 3; i++) {
        await rateLimiter.handle(req, res, jest.fn());
      }

      // 4-й запрос должен быть заблокирован
      await rateLimiter.handle(req, res);
      expect(res.statusCode).toBe(429);
    });

    it('должен устанавливать rate limit headers', async () => {
      const rule: RateLimitRule = {
        name: 'test',
        algorithm: 'fixed_window',
        maxRequests: 5,
        windowMs: 60000,
        keyGenerator: (req) => 'test-key',
        message: 'Too many requests',
        statusCode: 429,
        headers: true
      };

      rateLimiter.addRule(rule);
      await rateLimiter.handle(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Limit',
        expect.any(String)
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Remaining',
        expect.any(String)
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Reset',
        expect.any(String)
      );
    });

    it('должен устанавливать Retry-After header при блокировке', async () => {
      const rule: RateLimitRule = {
        name: 'test',
        algorithm: 'fixed_window',
        maxRequests: 1,
        windowMs: 60000,
        keyGenerator: (req) => 'test-key',
        message: 'Too many requests',
        statusCode: 429,
        headers: true
      };

      rateLimiter.addRule(rule);

      // Первый запрос успешен
      await rateLimiter.handle(req, res, jest.fn());

      // Второй запрос заблокирован
      res = createMockResponse();
      await rateLimiter.handle(req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'Retry-After',
        expect.any(String)
      );
    });
  });

  // =============================================================================
  // KEY GENERATOR TESTS
  // =============================================================================

  describe('Key Generator', () => {
    it('должен использовать IP адрес для ключа', async () => {
      const rule: RateLimitRule = {
        name: 'test',
        algorithm: 'fixed_window',
        maxRequests: 2,
        windowMs: 60000,
        keyGenerator: (req) => `ip:${req.socket.remoteAddress || 'unknown'}`,
        message: 'Too many requests',
        statusCode: 429,
        headers: true
      };

      rateLimiter.addRule(rule);

      // Два запроса с одного IP
      await rateLimiter.handle(req, res, jest.fn());
      await rateLimiter.handle(req, res, jest.fn());

      // Третий запрос с того же IP заблокирован
      res = createMockResponse();
      await rateLimiter.handle(req, res);

      expect(res.statusCode).toBe(429);
    });

    it('должен использовать разные ключи для разных IP', async () => {
      const rule: RateLimitRule = {
        name: 'test',
        algorithm: 'fixed_window',
        maxRequests: 1,
        windowMs: 60000,
        keyGenerator: (req) => `ip:${req.socket.remoteAddress || 'unknown'}`,
        message: 'Too many requests',
        statusCode: 429,
        headers: true
      };

      rateLimiter.addRule(rule);

      // Первый запрос с первого IP
      await rateLimiter.handle(req, res, jest.fn());

      // Второй запрос со второго IP должен быть успешен
      req = createMockRequest({ socket: { remoteAddress: '192.168.1.101' } });
      await rateLimiter.handle(req, res, jest.fn());

      expect(res.statusCode).toBe(200);
    });
  });

  // =============================================================================
  // SKIP CONDITION TESTS
  // =============================================================================

  describe('Skip Condition', () => {
    it('должен пропускать запросы по условию', async () => {
      const rule: RateLimitRule = {
        name: 'test',
        algorithm: 'fixed_window',
        maxRequests: 1,
        windowMs: 60000,
        keyGenerator: (req) => 'test-key',
        message: 'Too many requests',
        statusCode: 429,
        headers: true,
        skip: (req) => req.url === '/health'
      };

      rateLimiter.addRule(rule);

      // Health check должен быть пропущен
      req = createMockRequest({ url: '/health' });
      await rateLimiter.handle(req, res, jest.fn());
      expect(res.statusCode).toBe(200);

      // Обычный запрос должен быть ограничен
      req = createMockRequest({ url: '/api/test' });
      await rateLimiter.handle(req, res, jest.fn());
      res = createMockResponse();
      await rateLimiter.handle(req, res);
      expect(res.statusCode).toBe(429);
    });
  });

  // =============================================================================
  // CUSTOM HANDLER TESTS
  // =============================================================================

  describe('Custom Handler', () => {
    it('должен использовать кастомный handler', async () => {
      const customHandler = jest.fn((req, res) => {
        res.statusCode = 429;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Custom error' }));
      });

      const rule: RateLimitRule = {
        name: 'test',
        algorithm: 'fixed_window',
        maxRequests: 1,
        windowMs: 60000,
        keyGenerator: (req) => 'test-key',
        message: 'Too many requests',
        statusCode: 429,
        headers: true,
        handler: customHandler
      };

      rateLimiter.addRule(rule);

      // Первый запрос успешен
      await rateLimiter.handle(req, res, jest.fn());

      // Второй запрос использует кастомный handler
      res = createMockResponse();
      await rateLimiter.handle(req, res);

      expect(customHandler).toHaveBeenCalled();
    });
  });

  // =============================================================================
  // STATS TESTS
  // =============================================================================

  describe('Stats', () => {
    it('должен возвращать статистику', () => {
      const stats = rateLimiter.getStats();

      expect(stats).toBeDefined();
      expect(typeof stats.rulesCount).toBe('number');
      expect(typeof stats.enabled).toBe('boolean');
      expect(stats.storeType).toBeDefined();
    });
  });

  // =============================================================================
  // RESET LIMIT TESTS
  // =============================================================================

  describe('Reset Limit', () => {
    it('должен сбрасывать лимит', async () => {
      const rule: RateLimitRule = {
        name: 'test',
        algorithm: 'fixed_window',
        maxRequests: 1,
        windowMs: 60000,
        keyGenerator: (req) => 'test-key',
        message: 'Too many requests',
        statusCode: 429,
        headers: true
      };

      rateLimiter.addRule(rule);

      // Первый запрос успешен
      await rateLimiter.handle(req, res, jest.fn());

      // Сброс лимита
      await rateLimiter.resetLimit('test-key');

      // Второй запрос должен быть успешен
      res = createMockResponse();
      await rateLimiter.handle(req, res, jest.fn());

      expect(res.statusCode).toBe(200);
    });
  });
});

// =============================================================================
// EXPRESS INTEGRATION TESTS
// =============================================================================

describe('Express Integration', () => {
  it('должен создавать Express middleware для security headers', () => {
    const expressMiddleware = expressSecurityHeaders();
    
    expect(expressMiddleware).toBeDefined();
    expect(typeof expressMiddleware).toBe('function');
  });

  it('должен создавать Express middleware с кастомной конфигурацией', () => {
    const expressMiddleware = expressSecurityHeaders({
      xFrameOptions: 'SAMEORIGIN'
    });
    
    expect(expressMiddleware).toBeDefined();
  });
});
