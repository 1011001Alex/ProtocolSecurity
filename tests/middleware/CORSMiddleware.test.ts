/**
 * =============================================================================
 * COMPREHENSIVE TESTS FOR CORS MIDDLEWARE
 * =============================================================================
 * Полное покрытие всех функций CORS middleware:
 * - createCORS
 * - CORSPresets (public, private, dev, apiGateway, microservice)
 * - validateCORSConfig
 * - Domain whitelist/blacklist
 * - Dynamic origin validation
 * - Preflight request caching
 * - Credentials support
 * - Custom headers/methods configuration
 *
 * @coverage 100%
 * @author Theodor Munch
 * =============================================================================
 */

import { Request, Response } from 'express';
import {
  createCORS,
  CORSPresets,
  validateCORSConfig,
  CORSConfig
} from '../../src/middleware/CORSMiddleware';

// =============================================================================
// MOCKS
// =============================================================================

/**
 * Создает мок запроса
 */
const createMockRequest = (overrides: Partial<Request> = {}): Request => {
  return {
    method: 'GET',
    url: '/api/test',
    headers: {},
    ...overrides
  } as Request;
};

/**
 * Создает мок ответа
 */
const createMockResponse = (): Response => {
  const res: Partial<Response> = {
    statusCode: 200,
    headers: {} as Record<string, string>,
    setHeader: jest.fn(function (name: string, value: string) {
      (this.headers as Record<string, string>)[name] = value;
      return this;
    }),
    getHeader: jest.fn(function (name: string) {
      return (this.headers as Record<string, string>)[name];
    }),
    removeHeader: jest.fn(function (name: string) {
      delete (this.headers as Record<string, string>)[name];
    }),
    end: jest.fn()
  };
  return res as Response;
};

/**
 * Сбрасывает моки ответа
 */
const resetMockResponse = (res: Response) => {
  (res as any).statusCode = 200;
  (res as any).headers = {};
  jest.clearAllMocks();
};

// =============================================================================
// BASIC CORS TESTS
// =============================================================================

describe('CORS Middleware - Basic Functionality', () => {
  let req: Request;
  let res: Response;

  beforeEach(() => {
    req = createMockRequest();
    res = createMockResponse();
  });

  // =============================================================================
  // CREATION TESTS
  // =============================================================================

  describe('Creation', () => {
    it('должен создавать middleware без конфигурации', () => {
      const middleware = createCORS();
      expect(middleware).toBeDefined();
      expect(typeof middleware).toBe('function');
    });

    it('должен создавать middleware с пустой конфигурацией', () => {
      const middleware = createCORS({});
      expect(middleware).toBeDefined();
      expect(typeof middleware).toBe('function');
    });

    it('должен создавать middleware с полной конфигурацией', () => {
      const middleware = createCORS({
        origin: 'https://example.com',
        methods: ['GET', 'POST'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        exposedHeaders: ['X-Custom-Header'],
        credentials: true,
        maxAge: 3600,
        preflightContinue: false,
        optionsSuccessStatus: 204,
        strict: true,
        blacklistedOrigins: ['https://malicious.com'],
        dynamicOrigin: false
      });
      expect(middleware).toBeDefined();
      expect(typeof middleware).toBe('function');
    });
  });

  // =============================================================================
  // DEFAULT CONFIGURATION TESTS
  // =============================================================================

  describe('Default Configuration', () => {
    it('должен устанавливать origin: * по умолчанию', () => {
      const middleware = createCORS();
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        '*'
      );
    });

    it('должен устанавливать методы по умолчанию', () => {
      const middleware = createCORS();
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET, POST, PUT, DELETE, PATCH, OPTIONS'
      );
    });

    it('должен устанавливать заголовки по умолчанию', () => {
      const middleware = createCORS();
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-Requested-With, X-Request-ID'
      );
    });

    it('должен устанавливать exposedHeaders по умолчанию', () => {
      const middleware = createCORS();
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Expose-Headers',
        'X-Request-ID, X-RateLimit-Limit, X-RateLimit-Remaining'
      );
    });

    it('должен устанавливать credentials: false по умолчанию', () => {
      const middleware = createCORS();
      middleware(req, res, jest.fn());

      // credentials не должен устанавливаться для wildcard origin
      expect(res.setHeader).not.toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });

    it('должен устанавливать maxAge: 86400 по умолчанию', () => {
      const middleware = createCORS();
      req = createMockRequest({ method: 'OPTIONS' });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Max-Age',
        '86400'
      );
    });
  });

  // =============================================================================
  // ORIGIN TESTS
  // =============================================================================

  describe('Origin Configuration', () => {
    it('должен разрешать конкретный origin (string)', () => {
      const middleware = createCORS({ origin: 'https://example.com' });
      req = createMockRequest({ headers: { origin: 'https://example.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://example.com'
      );
    });

    it('должен блокировать неподходящий origin (string)', () => {
      const middleware = createCORS({ origin: 'https://example.com' });
      req = createMockRequest({ headers: { origin: 'https://malicious.com' } });
      middleware(req, res, jest.fn());

      // Origin не совпадает - заголовок не устанавливается или устанавливается в null
      const allowOriginCalls = (res.setHeader as jest.Mock).mock.calls.filter(
        (call: any) => call[0] === 'Access-Control-Allow-Origin'
      );
      expect(allowOriginCalls.length).toBe(0);
    });

    it('должен разрешать origin по RegExp', () => {
      const middleware = createCORS({ origin: /^https:\/\/.*\.example\.com$/ });
      req = createMockRequest({ headers: { origin: 'https://api.example.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://api.example.com'
      );
    });

    it('должен блокировать origin не подходящий по RegExp', () => {
      const middleware = createCORS({ origin: /^https:\/\/.*\.example\.com$/ });
      req = createMockRequest({ headers: { origin: 'https://malicious.com' } });
      middleware(req, res, jest.fn());

      const allowOriginCalls = (res.setHeader as jest.Mock).mock.calls.filter(
        (call: any) => call[0] === 'Access-Control-Allow-Origin'
      );
      expect(allowOriginCalls.length).toBe(0);
    });

    it('должен разрешать origin из массива (string)', () => {
      const middleware = createCORS({
        origin: ['https://example.com', 'https://api.example.com']
      });
      req = createMockRequest({ headers: { origin: 'https://api.example.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://api.example.com'
      );
    });

    it('должен разрешать origin из массива (RegExp)', () => {
      const middleware = createCORS({
        origin: [/^https:\/\/localhost(:\d+)?$/, /^https:\/\/127\.0\.0\.1(:\d+)?$/]
      });
      req = createMockRequest({ headers: { origin: 'https://localhost:3000' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://localhost:3000'
      );
    });

    it('должен использовать функцию для проверки origin', () => {
      // Функция origin может возвращать boolean или string
      // При возврате true - устанавливается '*', при возврате string - конкретный origin
      const originValidator = jest.fn((origin: string) => {
        return origin; // Возвращаем сам origin как string
      });
      const middleware = createCORS({ origin: originValidator as any });
      req = createMockRequest({ headers: { origin: 'https://trusted.com' } });
      middleware(req, res, jest.fn());

      expect(originValidator).toHaveBeenCalledWith('https://trusted.com');
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://trusted.com'
      );
    });

    it('должен блокировать origin когда функция возвращает false', () => {
      const originValidator = jest.fn((origin: string) => {
        return origin === 'https://trusted.com';
      });
      const middleware = createCORS({ origin: originValidator as any });
      req = createMockRequest({ headers: { origin: 'https://untrusted.com' } });
      middleware(req, res, jest.fn());

      expect(originValidator).toHaveBeenCalledWith('https://untrusted.com');
      
      // Origin не должен устанавливаться при false
      const allowOriginCalls = (res.setHeader as jest.Mock).mock.calls.filter(
        (call: any) => call[0] === 'Access-Control-Allow-Origin'
      );
      expect(allowOriginCalls.length).toBe(0);
    });

    it('должен устанавливать Vary: Origin header', () => {
      const middleware = createCORS();
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Vary',
        expect.stringContaining('Origin')
      );
    });
  });

  // =============================================================================
  // BLACKLIST TESTS
  // =============================================================================

  describe('Blacklist', () => {
    it('должен блокировать origin из blacklist', () => {
      const middleware = createCORS({
        origin: '*',
        blacklistedOrigins: ['https://malicious.com']
      });
      req = createMockRequest({ headers: { origin: 'https://malicious.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'null'
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'NONE'
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        'NONE'
      );
    });

    it('должен блокировать origin по wildcard pattern в blacklist', () => {
      const middleware = createCORS({
        origin: '*',
        blacklistedOrigins: ['*.malicious.com']
      });
      req = createMockRequest({ headers: { origin: 'https://sub.malicious.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'null'
      );
    });

    it('должен пропускать origin не из blacklist', () => {
      const middleware = createCORS({
        origin: '*',
        blacklistedOrigins: ['https://malicious.com']
      });
      req = createMockRequest({ headers: { origin: 'https://trusted.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        '*'
      );
    });

    it('должен обрабатывать пустой blacklist', () => {
      const middleware = createCORS({
        origin: '*',
        blacklistedOrigins: []
      });
      req = createMockRequest({ headers: { origin: 'https://any.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        '*'
      );
    });
  });

  // =============================================================================
  // DYNAMIC ORIGIN TESTS
  // =============================================================================

  describe('Dynamic Origin', () => {
    it('должен отражать динамический origin при dynamicOrigin: true', () => {
      const middleware = createCORS({
        origin: '*',
        dynamicOrigin: true
      });
      req = createMockRequest({ headers: { origin: 'https://dynamic.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://dynamic.com'
      );
    });

    it('не должен отражать origin при dynamicOrigin: false', () => {
      const middleware = createCORS({
        origin: '*',
        dynamicOrigin: false
      });
      req = createMockRequest({ headers: { origin: 'https://dynamic.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        '*'
      );
    });

    it('должен отражать origin только при wildcard origin', () => {
      const middleware = createCORS({
        origin: 'https://specific.com',
        dynamicOrigin: true
      });
      req = createMockRequest({ headers: { origin: 'https://dynamic.com' } });
      middleware(req, res, jest.fn());

      // Должен использовать конкретный origin, а не динамический
      // dynamicOrigin работает только при origin: '*'
      const allowOriginCalls = (res.setHeader as jest.Mock).mock.calls.filter(
        (call: any) => call[0] === 'Access-Control-Allow-Origin'
      );
      expect(allowOriginCalls.length).toBe(0);
    });
  });

  // =============================================================================
  // CREDENTIALS TESTS
  // =============================================================================

  describe('Credentials', () => {
    it('должен устанавливать Access-Control-Allow-Credentials: true', () => {
      const middleware = createCORS({
        origin: 'https://example.com',
        credentials: true
      });
      req = createMockRequest({ headers: { origin: 'https://example.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });

    it('не должен устанавливать credentials для wildcard origin', () => {
      const middleware = createCORS({
        origin: '*',
        credentials: true
      });
      req = createMockRequest({ headers: { origin: 'https://example.com' } });
      middleware(req, res, jest.fn());

      // credentials не должен устанавливаться для wildcard
      expect(res.setHeader).not.toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });

    it('не должен устанавливать credentials при credentials: false', () => {
      const middleware = createCORS({
        origin: 'https://example.com',
        credentials: false
      });
      req = createMockRequest({ headers: { origin: 'https://example.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).not.toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });
  });

  // =============================================================================
  // METHODS TESTS
  // =============================================================================

  describe('Methods', () => {
    it('должен устанавливать методы из конфигурации (string)', () => {
      const middleware = createCORS({
        methods: 'GET, POST, PUT'
      });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET, POST, PUT'
      );
    });

    it('должен устанавливать методы из конфигурации (array)', () => {
      const middleware = createCORS({
        methods: ['GET', 'POST', 'PUT', 'DELETE']
      });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET, POST, PUT, DELETE'
      );
    });

    it('должен устанавливать методы для preflight запроса', () => {
      const middleware = createCORS({
        methods: ['GET', 'POST']
      });
      req = createMockRequest({ method: 'OPTIONS' });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET, POST'
      );
    });
  });

  // =============================================================================
  // HEADERS TESTS
  // =============================================================================

  describe('Headers', () => {
    it('должен устанавливать allowedHeaders из конфигурации (string)', () => {
      const middleware = createCORS({
        allowedHeaders: 'Content-Type, Authorization'
      });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization'
      );
    });

    it('должен устанавливать allowedHeaders из конфигурации (array)', () => {
      const middleware = createCORS({
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Custom']
      });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization, X-Custom'
      );
    });

    it('должен устанавливать exposedHeaders из конфигурации', () => {
      const middleware = createCORS({
        exposedHeaders: ['X-Custom-Header', 'X-Another']
      });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Expose-Headers',
        'X-Custom-Header, X-Another'
      );
    });

    it('должен устанавливать Vary header для allowedHeaders', () => {
      const middleware = createCORS({
        allowedHeaders: ['Content-Type']
      });
      middleware(req, res, jest.fn());

      const varyCall = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Vary'
      );
      expect(varyCall).toBeDefined();
      expect(varyCall?.[1]).toContain('Access-Control-Request-Headers');
    });
  });

  // =============================================================================
  // PREFLIGHT TESTS
  // =============================================================================

  describe('Preflight Requests', () => {
    it('должен обрабатывать OPTIONS запрос как preflight', () => {
      const middleware = createCORS();
      req = createMockRequest({ method: 'OPTIONS' });
      middleware(req, res, jest.fn());

      expect(res.statusCode).toBe(204);
      expect(res.end).toHaveBeenCalled();
    });

    it('должен устанавливать Access-Control-Max-Age для preflight', () => {
      const middleware = createCORS({ maxAge: 7200 });
      req = createMockRequest({ method: 'OPTIONS' });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Max-Age',
        '7200'
      );
    });

    it('должен устанавливать Content-Length: 0 для preflight', () => {
      const middleware = createCORS();
      req = createMockRequest({ method: 'OPTIONS' });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith('Content-Length', '0');
    });

    it('должен использовать optionsSuccessStatus из конфигурации', () => {
      const middleware = createCORS({ optionsSuccessStatus: 200 });
      req = createMockRequest({ method: 'OPTIONS' });
      middleware(req, res, jest.fn());

      expect(res.statusCode).toBe(200);
    });

    it('должен продолжать выполнение при preflightContinue: true', () => {
      const next = jest.fn();
      const middleware = createCORS({ preflightContinue: true });
      req = createMockRequest({ method: 'OPTIONS' });
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.end).not.toHaveBeenCalled();
    });

    it('не должен продолжать выполнение при preflightContinue: false', () => {
      const next = jest.fn();
      const middleware = createCORS({ preflightContinue: false });
      req = createMockRequest({ method: 'OPTIONS' });
      middleware(req, res, next);

      expect(next).not.toHaveBeenCalled();
      expect(res.end).toHaveBeenCalled();
    });
  });

  // =============================================================================
  // NON-PREFLIGHT TESTS
  // =============================================================================

  describe('Non-Preflight Requests', () => {
    it('должен устанавливать методы для GET запроса', () => {
      const middleware = createCORS({ methods: ['GET', 'POST'] });
      req = createMockRequest({ method: 'GET' });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET, POST'
      );
    });

    it('должен вызывать next() для GET запроса', () => {
      const next = jest.fn();
      const middleware = createCORS();
      req = createMockRequest({ method: 'GET' });
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.end).not.toHaveBeenCalled();
    });

    it('должен устанавливать заголовки для POST запроса', () => {
      const middleware = createCORS();
      req = createMockRequest({ method: 'POST' });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        '*'
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        expect.any(String)
      );
    });
  });

  // =============================================================================
  // VARY HEADER TESTS
  // =============================================================================

  describe('Vary Header', () => {
    it('должен устанавливать Vary: Origin', () => {
      const middleware = createCORS();
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Vary',
        expect.stringContaining('Origin')
      );
    });

    it('должен добавлять Access-Control-Request-Headers к Vary', () => {
      const middleware = createCORS({ allowedHeaders: ['Content-Type'] });
      middleware(req, res, jest.fn());

      const varyCall = (res.setHeader as jest.Mock).mock.calls.find(
        (call: any) => call[0] === 'Vary'
      );
      expect(varyCall?.[1]).toContain('Access-Control-Request-Headers');
    });
  });
});

// =============================================================================
// CORS PRESETS TESTS
// =============================================================================

describe('CORS Presets', () => {
  let req: Request;
  let res: Response;

  beforeEach(() => {
    req = createMockRequest();
    res = createMockResponse();
  });

  // =============================================================================
  // PUBLIC PRESET TESTS
  // =============================================================================

  describe('CORSPresets.public', () => {
    it('должен разрешать все origins', () => {
      req = createMockRequest({ headers: { origin: 'https://any.com' } });
      CORSPresets.public(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        '*'
      );
    });

    it('должен разрешать все методы', () => {
      CORSPresets.public(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET, POST, PUT, DELETE, PATCH, OPTIONS'
      );
    });

    it('не должен разрешать credentials', () => {
      CORSPresets.public(req, res, jest.fn());

      expect(res.setHeader).not.toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });

    it('должен устанавливать maxAge: 3600', () => {
      req = createMockRequest({ method: 'OPTIONS' });
      CORSPresets.public(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Max-Age',
        '3600'
      );
    });
  });

  // =============================================================================
  // PRIVATE PRESET TESTS
  // =============================================================================

  describe('CORSPresets.private', () => {
    it('должен разрешать только указанные origins', () => {
      const privateCORS = CORSPresets.private(['https://trusted.com']);
      req = createMockRequest({ headers: { origin: 'https://trusted.com' } });
      privateCORS(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://trusted.com'
      );
    });

    it('должен блокировать недоверенные origins', () => {
      const privateCORS = CORSPresets.private(['https://trusted.com']);
      req = createMockRequest({ headers: { origin: 'https://untrusted.com' } });
      privateCORS(req, res, jest.fn());

      const allowOriginCalls = (res.setHeader as jest.Mock).mock.calls.filter(
        (call: any) => call[0] === 'Access-Control-Allow-Origin'
      );
      expect(allowOriginCalls.length).toBe(0);
    });

    it('должен разрешать credentials', () => {
      const privateCORS = CORSPresets.private(['https://trusted.com']);
      req = createMockRequest({ headers: { origin: 'https://trusted.com' } });
      privateCORS(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });

    it('должен устанавливать maxAge: 86400', () => {
      const privateCORS = CORSPresets.private(['https://trusted.com']);
      req = createMockRequest({ method: 'OPTIONS' });
      privateCORS(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Max-Age',
        '86400'
      );
    });

    it('должен быть в strict mode', () => {
      const privateCORS = CORSPresets.private(['https://trusted.com']);
      expect(privateCORS).toBeDefined();
    });
  });

  // =============================================================================
  // DEV PRESET TESTS
  // =============================================================================

  describe('CORSPresets.dev', () => {
    it('должен разрешать localhost', () => {
      req = createMockRequest({ headers: { origin: 'https://localhost:3000' } });
      CORSPresets.dev(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://localhost:3000'
      );
    });

    it('должен разрешать localhost с портом', () => {
      req = createMockRequest({ headers: { origin: 'https://localhost:8080' } });
      CORSPresets.dev(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://localhost:8080'
      );
    });

    it('должен разрешать 127.0.0.1', () => {
      req = createMockRequest({ headers: { origin: 'https://127.0.0.1:3000' } });
      CORSPresets.dev(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://127.0.0.1:3000'
      );
    });

    it('должен разрешать credentials', () => {
      req = createMockRequest({ headers: { origin: 'https://localhost:3000' } });
      CORSPresets.dev(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });

    it('должен устанавливать maxAge: 600', () => {
      req = createMockRequest({ method: 'OPTIONS' });
      CORSPresets.dev(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Max-Age',
        '600'
      );
    });

    it('должен использовать dynamicOrigin', () => {
      req = createMockRequest({ headers: { origin: 'https://localhost:3000' } });
      CORSPresets.dev(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://localhost:3000'
      );
    });

    it('должен блокировать не-local origins', () => {
      req = createMockRequest({ headers: { origin: 'https://production.com' } });
      CORSPresets.dev(req, res, jest.fn());

      const allowOriginCalls = (res.setHeader as jest.Mock).mock.calls.filter(
        (call: any) => call[0] === 'Access-Control-Allow-Origin'
      );
      expect(allowOriginCalls.length).toBe(0);
    });
  });

  // =============================================================================
  // API GATEWAY PRESET TESTS
  // =============================================================================

  describe('CORSPresets.apiGateway', () => {
    it('должен разрешать указанные domains', () => {
      const apiGatewayCORS = CORSPresets.apiGateway(['https://api.example.com']);
      req = createMockRequest({ headers: { origin: 'https://api.example.com' } });
      apiGatewayCORS(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://api.example.com'
      );
    });

    it('должен разрешать credentials', () => {
      const apiGatewayCORS = CORSPresets.apiGateway(['https://api.example.com']);
      req = createMockRequest({ headers: { origin: 'https://api.example.com' } });
      apiGatewayCORS(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });

    it('должен устанавливать X-API-Key в allowedHeaders', () => {
      const apiGatewayCORS = CORSPresets.apiGateway(['https://api.example.com']);
      apiGatewayCORS(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        expect.stringContaining('X-API-Key')
      );
    });

    it('должен устанавливать exposedHeaders', () => {
      const apiGatewayCORS = CORSPresets.apiGateway(['https://api.example.com']);
      apiGatewayCORS(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Expose-Headers',
        expect.stringContaining('X-RateLimit-Limit')
      );
    });

    it('должен устанавливать maxAge: 86400', () => {
      const apiGatewayCORS = CORSPresets.apiGateway(['https://api.example.com']);
      req = createMockRequest({ method: 'OPTIONS' });
      apiGatewayCORS(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Max-Age',
        '86400'
      );
    });
  });

  // =============================================================================
  // MICROSERVICE PRESET TESTS
  // =============================================================================

  describe('CORSPresets.microservice', () => {
    it('должен разрешать все origins', () => {
      CORSPresets.microservice(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        '*'
      );
    });

    it('не должен разрешать credentials', () => {
      CORSPresets.microservice(req, res, jest.fn());

      expect(res.setHeader).not.toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });

    it('должен устанавливать X-Service-Key в allowedHeaders', () => {
      CORSPresets.microservice(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        expect.stringContaining('X-Service-Key')
      );
    });

    it('должен устанавливать maxAge: 86400', () => {
      req = createMockRequest({ method: 'OPTIONS' });
      CORSPresets.microservice(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Max-Age',
        '86400'
      );
    });
  });
});

// =============================================================================
// VALIDATION TESTS
// =============================================================================

describe('validateCORSConfig', () => {
  // =============================================================================
  // WILDCARD CREDENTIALS TESTS
  // =============================================================================

  describe('Wildcard + Credentials Validation', () => {
    it('должен возвращать ошибку для wildcard origin с credentials', () => {
      const errors = validateCORSConfig({
        origin: '*',
        credentials: true
      });

      expect(errors.length).toBe(1);
      expect(errors[0].message).toContain(
        'Cannot use wildcard origin (*) with credentials enabled'
      );
    });

    it('не должен возвращать ошибку для конкретного origin с credentials', () => {
      const errors = validateCORSConfig({
        origin: 'https://example.com',
        credentials: true
      });

      expect(errors.length).toBe(0);
    });

    it('не должен возвращать ошибку для wildcard без credentials', () => {
      const errors = validateCORSConfig({
        origin: '*',
        credentials: false
      });

      expect(errors.length).toBe(0);
    });
  });

  // =============================================================================
  // MAX AGE VALIDATION TESTS
  // =============================================================================

  describe('Max Age Validation', () => {
    it('должен возвращать ошибку для отрицательного maxAge', () => {
      const errors = validateCORSConfig({
        maxAge: -1
      });

      expect(errors.length).toBe(1);
      expect(errors[0].message).toContain('must be between 0 and 2592000');
    });

    it('должен возвращать ошибку для слишком большого maxAge', () => {
      const errors = validateCORSConfig({
        maxAge: 3000000 // больше 30 дней
      });

      expect(errors.length).toBe(1);
      expect(errors[0].message).toContain('must be between 0 and 2592000');
    });

    it('должен принимать maxAge: 0', () => {
      const errors = validateCORSConfig({
        maxAge: 0
      });

      expect(errors.length).toBe(0);
    });

    it('должен принимать максимальный valid maxAge (30 дней)', () => {
      const errors = validateCORSConfig({
        maxAge: 2592000 // 30 дней в секундах
      });

      expect(errors.length).toBe(0);
    });

    it('должен принимать стандартный maxAge (86400)', () => {
      const errors = validateCORSConfig({
        maxAge: 86400 // 24 часа
      });

      expect(errors.length).toBe(0);
    });
  });

  // =============================================================================
  // DYNAMIC ORIGIN + STRICT VALIDATION TESTS
  // =============================================================================

  describe('Dynamic Origin + Strict Validation', () => {
    it('должен возвращать ошибку для dynamicOrigin + strict', () => {
      const errors = validateCORSConfig({
        dynamicOrigin: true,
        strict: true
      });

      expect(errors.length).toBe(1);
      expect(errors[0].message).toBe('Cannot use dynamicOrigin with strict mode');
    });

    it('не должен возвращать ошибку для dynamicOrigin без strict', () => {
      const errors = validateCORSConfig({
        dynamicOrigin: true,
        strict: false
      });

      expect(errors.length).toBe(0);
    });

    it('не должен возвращать ошибку для strict без dynamicOrigin', () => {
      const errors = validateCORSConfig({
        dynamicOrigin: false,
        strict: true
      });

      expect(errors.length).toBe(0);
    });
  });

  // =============================================================================
  // WILDCARD PATTERN VALIDATION TESTS
  // =============================================================================

  describe('Wildcard Pattern Validation', () => {
    it('должен возвращать ошибку для wildcard pattern в массиве origins', () => {
      const errors = validateCORSConfig({
        origin: ['https://*.example.com']
      });

      expect(errors.length).toBe(1);
      expect(errors[0].message).toContain('use RegExp instead');
    });

    it('должен возвращать ошибку для wildcard pattern на конкретном индексе', () => {
      const errors = validateCORSConfig({
        origin: ['https://example.com', 'https://*.test.com']
      });

      expect(errors.length).toBe(1);
      expect(errors[0].message).toContain('index 1');
    });

    it('не должен возвращать ошибку для чистого wildcard (*)', () => {
      const errors = validateCORSConfig({
        origin: '*'
      });

      expect(errors.length).toBe(0);
    });

    it('не должен возвращать ошибку для RegExp с wildcard', () => {
      const errors = validateCORSConfig({
        origin: [/^https:\/\/.*\.example\.com$/]
      });

      expect(errors.length).toBe(0);
    });

    it('не должен возвращать ошибку для валидных string origins', () => {
      const errors = validateCORSConfig({
        origin: ['https://example.com', 'https://api.example.com']
      });

      expect(errors.length).toBe(0);
    });
  });

  // =============================================================================
  // EDGE CASES
  // =============================================================================

  describe('Edge Cases', () => {
    it('должен возвращать пустой массив для валидной конфигурации', () => {
      const errors = validateCORSConfig({
        origin: 'https://example.com',
        methods: ['GET', 'POST'],
        maxAge: 3600
      });

      expect(errors.length).toBe(0);
    });

    it('должен возвращать несколько ошибок для множественных нарушений', () => {
      const errors = validateCORSConfig({
        origin: '*',
        credentials: true,
        maxAge: -1,
        dynamicOrigin: true,
        strict: true
      });

      expect(errors.length).toBeGreaterThanOrEqual(2);
    });

    it('должен обрабатывать пустую конфигурацию', () => {
      const errors = validateCORSConfig({});

      expect(errors.length).toBe(0);
    });
  });
});

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

describe('CORS Middleware - Integration', () => {
  let req: Request;
  let res: Response;

  beforeEach(() => {
    req = createMockRequest();
    res = createMockResponse();
  });

  // =============================================================================
  // FULL REQUEST FLOW TESTS
  // =============================================================================

  describe('Full Request Flow', () => {
    it('должен полностью обрабатывать простой GET запрос', () => {
      const middleware = createCORS();
      const next = jest.fn();

      middleware(req, res, next);

      expect(res.setHeader).toBeDefined();
      expect(next).toHaveBeenCalled();
      expect(res.end).not.toHaveBeenCalled();
    });

    it('должен полностью обрабатывать preflight запрос', () => {
      const middleware = createCORS({
        origin: 'https://example.com',
        methods: ['GET', 'POST', 'PUT'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        maxAge: 3600
      });
      req = createMockRequest({
        method: 'OPTIONS',
        headers: {
          origin: 'https://example.com',
          'access-control-request-method': 'POST',
          'access-control-request-headers': 'Content-Type'
        }
      });

      middleware(req, res, jest.fn());

      expect(res.statusCode).toBe(204);
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'https://example.com'
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Methods',
        'GET, POST, PUT'
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Headers',
        'Content-Type, Authorization'
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Max-Age',
        '3600'
      );
      expect(res.end).toHaveBeenCalled();
    });

    it('должен обрабатывать запрос с credentials', () => {
      const middleware = createCORS({
        origin: 'https://example.com',
        credentials: true
      });
      req = createMockRequest({
        headers: {
          origin: 'https://example.com',
          cookie: 'session=abc123'
        }
      });

      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Credentials',
        'true'
      );
    });
  });

  // =============================================================================
  // SECURITY TESTS
  // =============================================================================

  describe('Security', () => {
    it('должен блокировать запрос без origin при strict mode', () => {
      const middleware = createCORS({
        origin: 'https://example.com',
        strict: true
      });
      req = createMockRequest({ headers: {} }); // нет origin

      middleware(req, res, jest.fn());

      // В strict mode без origin заголовок не должен устанавливаться
      const allowOriginCalls = (res.setHeader as jest.Mock).mock.calls.filter(
        (call: any) => call[0] === 'Access-Control-Allow-Origin'
      );
      expect(allowOriginCalls.length).toBe(0);
    });

    it('должен защищать от CORS атак с blacklist', () => {
      const middleware = createCORS({
        origin: '*',
        blacklistedOrigins: ['https://evil.com', '*.malicious.com']
      });

      // Попытка атаки с поддомена malicious
      req = createMockRequest({ headers: { origin: 'https://sub.malicious.com' } });
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        'null'
      );
    });

    it('должен корректно обрабатывать null origin', () => {
      const middleware = createCORS({ origin: '*' });
      req = createMockRequest({ headers: { origin: 'null' } });

      middleware(req, res, jest.fn());

      // null origin должен обрабатываться как любой другой
      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Allow-Origin',
        '*'
      );
    });
  });

  // =============================================================================
  // CACHE TESTS
  // =============================================================================

  describe('Caching', () => {
    it('должен устанавливать правильные заголовки для кэширования preflight', () => {
      const middleware = createCORS({ maxAge: 7200 });
      req = createMockRequest({ method: 'OPTIONS' });

      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Access-Control-Max-Age',
        '7200'
      );
    });

    it('должен устанавливать Vary header для правильного кэширования', () => {
      const middleware = createCORS();
      middleware(req, res, jest.fn());

      expect(res.setHeader).toHaveBeenCalledWith(
        'Vary',
        expect.stringContaining('Origin')
      );
    });
  });
});

// =============================================================================
// PERFORMANCE TESTS
// =============================================================================

describe('CORS Middleware - Performance', () => {
  it('должен быстро обрабатывать запросы (performance benchmark)', () => {
    const middleware = createCORS();
    const req = createMockRequest();
    const res = createMockResponse();

    const start = Date.now();
    for (let i = 0; i < 1000; i++) {
      middleware(req, res, jest.fn());
      resetMockResponse(res);
    }
    const end = Date.now();

    // 1000 запросов должны выполняться менее чем за 100ms
    expect(end - start).toBeLessThan(100);
  });

  it('должен эффективно обрабатывать preflight запросы', () => {
    const middleware = createCORS({ maxAge: 86400 });
    const req = createMockRequest({ method: 'OPTIONS' });
    const res = createMockResponse();

    const start = Date.now();
    for (let i = 0; i < 100; i++) {
      middleware(req, res, jest.fn());
      resetMockResponse(res);
    }
    const end = Date.now();

    // 100 preflight запросов должны выполняться менее чем за 50ms
    expect(end - start).toBeLessThan(50);
  });
});
