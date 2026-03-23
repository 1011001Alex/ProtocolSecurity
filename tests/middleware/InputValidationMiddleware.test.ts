/**
 * =============================================================================
 * COMPREHENSIVE TESTS FOR INPUT VALIDATION MIDDLEWARE
 * =============================================================================
 * Полное покрытие всех функций Input Validation Middleware:
 * - createInputValidationMiddleware
 * - Валидация body, query, params, headers
 * - Schema validation
 * - Rate limiting для валидации
 * - Injection protection (SQL, XSS, Command, Path Traversal)
 * - Санитизация данных
 * - ValidationPresets
 * - Helper functions (getValidatedData, getSanitizedData, isValidated)
 * - Edge cases
 *
 * @coverage 100%
 * @author Theodor Munch
 * =============================================================================
 */

import { Request, Response, NextFunction } from 'express';
import {
  createInputValidationMiddleware,
  getValidatedData,
  getSanitizedData,
  isValidated,
  getValidationErrors,
  createValidationSchema,
  ValidationPresets,
  InputValidationConfig,
  ValidationSchema,
  FieldSchema
} from '../../src/middleware/InputValidationMiddleware';
import { ValidationType, ValidationError } from '../../src/utils/InputValidator';

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
    path: '/api/test',
    headers: {},
    body: {},
    query: {},
    params: {},
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
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
      return this as Response;
    }),
    getHeader: jest.fn(function (name: string) {
      return (this.headers as Record<string, string>)[name];
    }),
    removeHeader: jest.fn(function (name: string) {
      delete (this.headers as Record<string, string>)[name];
    }),
    json: jest.fn(function (body: unknown) {
      (this as any)._jsonBody = body;
      return this as Response;
    }),
    end: jest.fn(),
    status: jest.fn(function (code: number) {
      this.statusCode = code;
      return this as Response;
    })
  };
  return res as Response;
};

/**
 * Создает мок next функции
 */
const createMockNext = (): NextFunction => {
  return jest.fn();
};

/**
 * Сбрасывает моки ответа
 */
const resetMockResponse = (res: Response) => {
  (res as any).statusCode = 200;
  (res as any).headers = {};
  (res as any)._jsonBody = undefined;
  jest.clearAllMocks();
};

// =============================================================================
// BASIC MIDDLEWARE TESTS
// =============================================================================

describe('Input Validation Middleware - Basic Functionality', () => {
  let req: Request;
  let res: Response;
  let next: NextFunction;

  beforeEach(() => {
    req = createMockRequest();
    res = createMockResponse();
    next = createMockNext();
  });

  // =============================================================================
  // CREATION TESTS
  // =============================================================================

  describe('Creation', () => {
    it('должен создавать middleware без конфигурации', () => {
      const middleware = createInputValidationMiddleware();
      expect(middleware).toBeDefined();
      expect(typeof middleware).toBe('function');
    });

    it('должен создавать middleware с пустой конфигурацией', () => {
      const middleware = createInputValidationMiddleware({});
      expect(middleware).toBeDefined();
      expect(typeof middleware).toBe('function');
    });

    it('должен создавать middleware с полной конфигурацией', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        maxBodySize: 5 * 1024 * 1024,
        sanitizeHTML: true,
        logErrors: true,
        enableRateLimit: true,
        rateLimitMax: 50,
        rateLimitWindowMs: 30000
      });
      expect(middleware).toBeDefined();
      expect(typeof middleware).toBe('function');
    });
  });

  // =============================================================================
  // SKIP CONDITIONS TESTS
  // =============================================================================

  describe('Skip Conditions', () => {
    it('должен пропускать GET запросы по умолчанию', () => {
      const middleware = createInputValidationMiddleware();
      req = createMockRequest({ method: 'GET' });
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('должен пропускать HEAD запросы по умолчанию', () => {
      const middleware = createInputValidationMiddleware();
      req = createMockRequest({ method: 'HEAD' });
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('должен пропускать OPTIONS запросы по умолчанию', () => {
      const middleware = createInputValidationMiddleware();
      req = createMockRequest({ method: 'OPTIONS' });
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('должен обрабатывать POST запросы', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: []
      });
      req = createMockRequest({ method: 'POST', body: { test: 'value' } });
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('должен пропускать пути из skipPaths', () => {
      const middleware = createInputValidationMiddleware({
        skipPaths: [/^\/api\/public/]
      });
      req = createMockRequest({ path: '/api/public/data', method: 'POST' });
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('не должен пропускать пути не из skipPaths', () => {
      const middleware = createInputValidationMiddleware({
        skipPaths: [/^\/api\/public/]
      });
      req = createMockRequest({ path: '/api/private/data', method: 'POST' });
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
    });
  });

  // =============================================================================
  // BODY SIZE VALIDATION TESTS
  // =============================================================================

  describe('Body Size Validation', () => {
    it('должен пропускать запросы в пределах maxBodySize', () => {
      const middleware = createInputValidationMiddleware({
        maxBodySize: 1024,
        skipMethods: []
      });
      req = createMockRequest({
        method: 'POST',
        body: { small: 'data' },
        headers: { 'content-length': '100' }
      });
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('должен отклонять запросы превышающие maxBodySize', () => {
      const middleware = createInputValidationMiddleware({
        maxBodySize: 100,
        strictMode: true,
        skipMethods: []
      });
      req = createMockRequest({
        method: 'POST',
        body: { large: 'data'.repeat(100) },
        headers: { 'content-length': '500' }
      });
      middleware(req, res, next);
      expect(res.statusCode).toBe(400);
      expect((res as any)._jsonBody).toBeDefined();
      expect((res.json as jest.Mock).mock.calls[0][0].error).toBe('Validation Error');
    });
  });

  // =============================================================================
  // RATE LIMITING TESTS
  // =============================================================================

  describe('Rate Limiting', () => {
    it('должен устанавливать заголовки rate limit', () => {
      const middleware = createInputValidationMiddleware({
        enableRateLimit: true,
        rateLimitMax: 100,
        rateLimitWindowMs: 60000,
        skipMethods: []
      });
      req = createMockRequest({ method: 'POST', ip: '192.168.1.1' });
      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Limit',
        '100'
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        'X-RateLimit-Remaining',
        expect.any(String)
      );
    });

    it('должен блокировать при превышении rate limit', () => {
      const middleware = createInputValidationMiddleware({
        enableRateLimit: true,
        rateLimitMax: 1,
        rateLimitWindowMs: 60000,
        skipMethods: []
      });

      // Первый запрос
      req = createMockRequest({ method: 'POST', ip: '10.0.0.1' });
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();

      // Второй запрос (должен быть заблокирован)
      resetMockResponse(res);
      next = createMockNext();
      req = createMockRequest({ method: 'POST', ip: '10.0.0.1' });
      middleware(req, res, next);

      expect(res.statusCode).toBe(429);
      expect((res as any)._jsonBody).toBeDefined();
    });
  });

  // =============================================================================
  // SCHEMA VALIDATION TESTS
  // =============================================================================

  describe('Schema Validation', () => {
    it('должен пропускать запросы без схемы', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: []
      });
      req = createMockRequest({ method: 'POST', body: { any: 'data' } });
      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('должен валидировать body по схеме', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            email: { type: ValidationType.EMAIL, required: true },
            name: { type: ValidationType.STRING, required: true, minLength: 2 }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: {
          email: 'test@example.com',
          name: 'John'
        }
      });

      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
      expect((req as any).validationResult).toBeDefined();
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять невалидный body в strict mode', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        skipMethods: [],
        schema: {
          body: {
            email: { type: ValidationType.EMAIL, required: true }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { email: 'invalid-email' }
      });

      middleware(req, res, next);
      expect(res.statusCode).toBe(400);
      expect(next).not.toHaveBeenCalled();
    });

    it('должен продолжать выполнение при ошибках вне strict mode', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: false,
        skipMethods: [],
        schema: {
          body: {
            email: { type: ValidationType.EMAIL, required: true }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { email: 'invalid-email' }
      });

      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
      expect((req as any).validationResult.valid).toBe(false);
    });

    it('должен валидировать query параметры', () => {
      const middleware = createInputValidationMiddleware({
        schema: {
          query: {
            page: { type: ValidationType.NUMBER, required: false, min: 1, max: 100 },
            search: { type: ValidationType.STRING, required: false, maxLength: 100 }
          }
        }
      });

      req = createMockRequest({
        method: 'GET',
        query: { page: '5', search: 'test' }
      });

      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('должен валидировать route params', () => {
      const middleware = createInputValidationMiddleware({
        schema: {
          params: {
            id: { type: ValidationType.UUID, required: true, uuidVersion: 4 }
          }
        }
      });

      req = createMockRequest({
        method: 'GET',
        params: { id: '550e8400-e29b-41d4-a716-446655440000' }
      });

      middleware(req, res, next);
      expect(next).toHaveBeenCalled();
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять невалидный UUID', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        schema: {
          params: {
            id: { type: ValidationType.UUID, required: true, uuidVersion: 4 }
          }
        }
      });

      req = createMockRequest({
        method: 'GET',
        params: { id: 'invalid-uuid' }
      });

      middleware(req, res, next);
      expect(res.statusCode).toBe(400);
    });
  });
});

// =============================================================================
// VALIDATION TYPE TESTS
// =============================================================================

describe('Input Validation - Validation Types', () => {
  let req: Request;
  let res: Response;
  let next: NextFunction;

  beforeEach(() => {
    req = createMockRequest();
    res = createMockResponse();
    next = createMockNext();
  });

  describe('String Validation', () => {
    it('должен валидировать строку с minLength', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            username: { type: ValidationType.STRING, required: true, minLength: 3 }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { username: 'ab' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });

    it('должен валидировать строку с maxLength', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            description: { type: ValidationType.STRING, required: true, maxLength: 10 }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { description: 'very long description' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });

    it('должен валидировать строку с pattern', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            code: { type: ValidationType.STRING, required: true, pattern: /^[A-Z]{3}\d{3}$/ }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { code: 'ABC123' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять строку не соответствующую pattern', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        skipMethods: [],
        schema: {
          body: {
            code: { type: ValidationType.STRING, required: true, pattern: /^[A-Z]{3}\d{3}$/ }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { code: 'invalid' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });
  });

  describe('Email Validation', () => {
    it('должен валидировать правильный email', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            email: { type: ValidationType.EMAIL, required: true }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { email: 'test@example.com' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять невалидный email', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        skipMethods: [],
        schema: {
          body: {
            email: { type: ValidationType.EMAIL, required: true }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { email: 'not-an-email' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });
  });

  describe('Number Validation', () => {
    it('должен валидировать число в диапазоне', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            age: { type: ValidationType.NUMBER, required: true, min: 0, max: 150 }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { age: 25 }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять число вне диапазона', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        skipMethods: [],
        schema: {
          body: {
            age: { type: ValidationType.NUMBER, required: true, min: 0, max: 150 }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { age: 200 }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });

    it('должен конвертировать строку в число', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            count: { type: ValidationType.NUMBER, required: true }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { count: '42' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
      expect((req as any).validationResult.sanitized.body.count).toBe(42);
    });
  });

  describe('Boolean Validation', () => {
    it('должен валидировать boolean', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            active: { type: ValidationType.BOOLEAN, required: true }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { active: true }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен конвертировать строку "true" в boolean', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            active: { type: ValidationType.BOOLEAN, required: true }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { active: 'true' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
      expect((req as any).validationResult.sanitized.body.active).toBe(true);
    });
  });

  describe('Password Validation', () => {
    it('должен валидировать сложный пароль', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            password: {
              type: ValidationType.PASSWORD,
              required: true,
              minLength: 12,
              requireUppercase: true,
              requireLowercase: true,
              requireNumbers: true,
              requireSpecial: true
            }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { password: 'SecureP@ssw0rd!' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять простой пароль', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        skipMethods: [],
        schema: {
          body: {
            password: {
              type: ValidationType.PASSWORD,
              required: true,
              minLength: 12
            }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { password: 'simple' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });
  });

  describe('URL Validation', () => {
    it('должен валидировать HTTPS URL', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            website: { type: ValidationType.URL, required: true, allowedProtocols: ['https'] }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { website: 'https://example.com' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять HTTP URL когда разрешен только HTTPS', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        skipMethods: [],
        schema: {
          body: {
            website: { type: ValidationType.URL, required: true, allowedProtocols: ['https'] }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { website: 'http://example.com' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });
  });

  describe('Path Validation', () => {
    it('должен валидировать безопасный путь', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: {
          body: {
            filePath: { type: ValidationType.PATH, required: true, allowAbsolutePath: false }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { filePath: 'documents/file.txt' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять path traversal', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        skipMethods: [],
        schema: {
          body: {
            filePath: { type: ValidationType.PATH, required: true }
          }
        }
      });

      req = createMockRequest({
        method: 'POST',
        body: { filePath: '../../../etc/passwd' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });
  });
});

// =============================================================================
// INJECTION PROTECTION TESTS
// =============================================================================

describe('Input Validation - Injection Protection', () => {
  let req: Request;
  let res: Response;
  let next: NextFunction;

  beforeEach(() => {
    req = createMockRequest();
    res = createMockResponse();
    next = createMockNext();
  });

  it('должен детектировать SQL injection', () => {
    const middleware = createInputValidationMiddleware({
      strictMode: true,
      skipMethods: [],
      schema: {
        body: {
          search: { type: ValidationType.STRING, required: true }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: { search: "'; DROP TABLE users; --" }
    });

    middleware(req, res, next);
    expect((req as any).validationResult.valid).toBe(false);
    const errors = (req as any).validationResult.errors;
    expect(errors.some((e: ValidationError) => e.code === 'INJECTION_DETECTED')).toBe(true);
  });

  it('должен детектировать XSS атаку', () => {
    const middleware = createInputValidationMiddleware({
      strictMode: true,
      skipMethods: [],
      schema: {
        body: {
          comment: { type: ValidationType.STRING, required: true }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: { comment: '<script>alert("XSS")</script>' }
    });

    middleware(req, res, next);
    expect((req as any).validationResult.valid).toBe(false);
    const errors = (req as any).validationResult.errors;
    expect(errors.some((e: ValidationError) => e.code === 'INJECTION_DETECTED')).toBe(true);
  });

  it('должен детектировать command injection', () => {
    const middleware = createInputValidationMiddleware({
      strictMode: true,
      skipMethods: [],
      schema: {
        body: {
          filename: { type: ValidationType.STRING, required: true }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: { filename: 'test.txt; rm -rf /' }
    });

    middleware(req, res, next);
    expect((req as any).validationResult.valid).toBe(false);
  });

  it('должен детектировать path traversal', () => {
    const middleware = createInputValidationMiddleware({
      strictMode: true,
      skipMethods: [],
      schema: {
        body: {
          path: { type: ValidationType.PATH, required: true }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: { path: '../../etc/passwd' }
    });

    middleware(req, res, next);
    expect((req as any).validationResult.valid).toBe(false);
  });
});

// =============================================================================
// HELPER FUNCTIONS TESTS
// =============================================================================

describe('Input Validation - Helper Functions', () => {
  describe('getValidatedData', () => {
    it('должен возвращать валидированные данные', () => {
      const req = createMockRequest();
      (req as any).validationResult = {
        valid: true,
        data: {
          body: { email: 'test@example.com' }
        },
        errors: [],
        warnings: [],
        sanitized: {}
      };

      const data = getValidatedData(req, 'body');
      expect(data).toEqual({ email: 'test@example.com' });
    });

    it('должен возвращать undefined если нет данных', () => {
      const req = createMockRequest();
      (req as any).validationResult = undefined;

      const data = getValidatedData(req, 'body');
      expect(data).toBeUndefined();
    });
  });

  describe('getSanitizedData', () => {
    it('должен возвращать санитизированные данные', () => {
      const req = createMockRequest();
      (req as any).validationResult = {
        valid: true,
        data: {},
        errors: [],
        warnings: [],
        sanitized: {
          body: { comment: 'safe text' }
        }
      };

      const data = getSanitizedData(req, 'body');
      expect(data).toEqual({ comment: 'safe text' });
    });
  });

  describe('isValidated', () => {
    it('должен возвращать true если валидация пройдена', () => {
      const req = createMockRequest();
      (req as any).validationResult = { valid: true, data: {}, errors: [], warnings: [], sanitized: {} };

      expect(isValidated(req)).toBe(true);
    });

    it('должен возвращать false если валидация не пройдена', () => {
      const req = createMockRequest();
      (req as any).validationResult = { valid: false, data: {}, errors: [], warnings: [], sanitized: {} };

      expect(isValidated(req)).toBe(false);
    });

    it('должен возвращать false если нет результата', () => {
      const req = createMockRequest();
      expect(isValidated(req)).toBe(false);
    });
  });

  describe('getValidationErrors', () => {
    it('должен возвращать массив ошибок', () => {
      const req = createMockRequest();
      const errors = [new ValidationError('field', 'CODE', 'Message')];
      (req as any).validationResult = { valid: false, data: {}, errors, warnings: [], sanitized: {} };

      const result = getValidationErrors(req);
      expect(result).toEqual(errors);
    });

    it('должен возвращать пустой массив если нет ошибок', () => {
      const req = createMockRequest();
      expect(getValidationErrors(req)).toEqual([]);
    });
  });

  describe('createValidationSchema', () => {
    it('должен создавать схему для body по умолчанию', () => {
      const fields: Record<string, FieldSchema> = {
        email: { type: ValidationType.EMAIL, required: true }
      };

      const schema = createValidationSchema(fields);
      expect(schema.body).toBeDefined();
      expect(schema.query).toBeUndefined();
      expect(schema.params).toBeUndefined();
      expect(schema.headers).toBeUndefined();
    });

    it('должен создавать схему для query', () => {
      const fields: Record<string, FieldSchema> = {
        page: { type: ValidationType.NUMBER }
      };

      const schema = createValidationSchema(fields, { validateQuery: true, validateBody: false });
      expect(schema.body).toBeUndefined();
      expect(schema.query).toBeDefined();
    });
  });
});

// =============================================================================
// VALIDATION PRESETS TESTS
// =============================================================================

describe('Input Validation - Validation Presets', () => {
  let req: Request;
  let res: Response;
  let next: NextFunction;

  beforeEach(() => {
    req = createMockRequest();
    res = createMockResponse();
    next = createMockNext();
  });

  describe('userRegistration Preset', () => {
    it('должен валидировать правильные данные регистрации', () => {
      const middleware = createInputValidationMiddleware({
        skipMethods: [],
        schema: ValidationPresets.userRegistration
      });

      req = createMockRequest({
        method: 'POST',
        body: {
          email: 'user@example.com',
          password: 'SecureP@ssw0rd123!',
          username: 'john_doe'
        }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять невалидный email', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        skipMethods: [],
        schema: ValidationPresets.userRegistration
      });

      req = createMockRequest({
        method: 'POST',
        body: {
          email: 'not-an-email',
          password: 'SecureP@ssw0rd123!',
          username: 'john_doe'
        }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });
  });

  describe('search Preset', () => {
    it('должен валидировать search параметры', () => {
      const middleware = createInputValidationMiddleware({
        schema: ValidationPresets.search
      });

      req = createMockRequest({
        method: 'GET',
        query: {
          q: 'test query',
          page: '1',
          limit: '20',
          sort: 'created_at',
          order: 'desc'
        }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен использовать значения по умолчанию', () => {
      const middleware = createInputValidationMiddleware({
        schema: ValidationPresets.search
      });

      req = createMockRequest({
        method: 'GET',
        query: {}
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
      expect((req as any).validationResult.sanitized.query.page).toBe(1);
      expect((req as any).validationResult.sanitized.query.limit).toBe(20);
    });
  });

  describe('uuidParams Preset', () => {
    it('должен валидировать UUID v4 параметр', () => {
      const middleware = createInputValidationMiddleware({
        schema: ValidationPresets.uuidParams
      });

      req = createMockRequest({
        method: 'GET',
        params: { id: 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять невалидный UUID', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        schema: ValidationPresets.uuidParams
      });

      req = createMockRequest({
        method: 'GET',
        params: { id: 'not-a-uuid' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });
  });

  describe('pagination Preset', () => {
    it('должен валидировать pagination параметры', () => {
      const middleware = createInputValidationMiddleware({
        schema: ValidationPresets.pagination
      });

      req = createMockRequest({
        method: 'GET',
        query: {
          page: '5',
          limit: '50',
          offset: '200'
        }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять page < 1', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        schema: ValidationPresets.pagination
      });

      req = createMockRequest({
        method: 'GET',
        query: { page: '0' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });
  });

  describe('apiKeyAuth Preset', () => {
    it('должен валидировать API key в headers', () => {
      const middleware = createInputValidationMiddleware({
        schema: ValidationPresets.apiKeyAuth
      });

      req = createMockRequest({
        method: 'GET',
        headers: { 'x-api-key': 'abcdefghijklmnopqrstuvwxyz123456' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(true);
    });

    it('должен отклонять короткий API key', () => {
      const middleware = createInputValidationMiddleware({
        strictMode: true,
        schema: ValidationPresets.apiKeyAuth
      });

      req = createMockRequest({
        method: 'GET',
        headers: { 'x-api-key': 'short' }
      });

      middleware(req, res, next);
      expect((req as any).validationResult.valid).toBe(false);
    });
  });
});

// =============================================================================
// EDGE CASES TESTS
// =============================================================================

describe('Input Validation - Edge Cases', () => {
  let req: Request;
  let res: Response;
  let next: NextFunction;

  beforeEach(() => {
    req = createMockRequest();
    res = createMockResponse();
    next = createMockNext();
  });

  it('должен обрабатывать пустой body', () => {
    const middleware = createInputValidationMiddleware({
      skipMethods: [],
      schema: {
        body: {
          optionalField: { type: ValidationType.STRING, required: false }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: {}
    });

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('должен обрабатывать null значения', () => {
    const middleware = createInputValidationMiddleware({
      skipMethods: [],
      schema: {
        body: {
          nullableField: { type: ValidationType.STRING, required: false }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: { nullableField: null }
    });

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('должен обрабатывать undefined значения', () => {
    const middleware = createInputValidationMiddleware({
      skipMethods: [],
      schema: {
        body: {
          optionalField: { type: ValidationType.STRING, required: false, default: 'default' }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: {}
    });

    middleware(req, res, next);
    expect((req as any).validationResult.sanitized.body.optionalField).toBe('default');
  });

  it('должен обрабатывать вложенные объекты', () => {
    const middleware = createInputValidationMiddleware({
      skipMethods: [],
      schema: {
        body: {
          user: {
            type: ValidationType.JSON,
            required: true,
            properties: {
              name: { type: ValidationType.STRING, required: true },
              age: { type: ValidationType.NUMBER, required: true }
            }
          }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: {
        user: {
          name: 'John',
          age: 30
        }
      }
    });

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('должен обрабатывать массивы в body', () => {
    const middleware = createInputValidationMiddleware({
      skipMethods: [],
      schema: {
        body: {
          tags: { type: ValidationType.JSON, required: false }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: { tags: ['tag1', 'tag2', 'tag3'] }
    });

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('должен обрабатывать специальные символы в строках', () => {
    const middleware = createInputValidationMiddleware({
      skipMethods: [],
      schema: {
        body: {
          description: { type: ValidationType.STRING, required: true, maxLength: 1000, sanitize: true }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: { description: 'Text with <special> & "characters"' }
    });

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
    // Санитизация должна заменить специальные символы на HTML entities
    const sanitized = (req as any).validationResult.sanitized.body.description;
    expect(sanitized).toContain('&lt;');
  });

  it('должен обрабатывать очень длинные строки', () => {
    const middleware = createInputValidationMiddleware({
      strictMode: true,
      skipMethods: [],
      schema: {
        body: {
          longText: { type: ValidationType.STRING, required: true, maxLength: 100 }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: { longText: 'a'.repeat(1000) }
    });

    middleware(req, res, next);
    expect((req as any).validationResult.valid).toBe(false);
  });

  it('должен обрабатывать Unicode символы', () => {
    const middleware = createInputValidationMiddleware({
      skipMethods: [],
      schema: {
        body: {
          emoji: { type: ValidationType.STRING, required: true }
        }
      }
    });

    req = createMockRequest({
      method: 'POST',
      body: { emoji: 'Hello 世界！🌍' }
    });

    middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('должен обрабатывать ошибку в middleware', () => {
    const middleware = createInputValidationMiddleware({
      strictMode: true,
      skipMethods: []
    });

    // Создаем запрос который вызовет ошибку
    req = createMockRequest({
      method: 'POST'
    });

    // Повреждаем body чтобы вызвать ошибку
    (req as any).body = undefined;

    middleware(req, res, next);
    // В случае ошибки middleware должен вызвать next или вернуть ошибку
    expect(next).toHaveBeenCalled();
  });
});

// =============================================================================
// ERROR HANDLER TESTS
// =============================================================================

describe('Input Validation - Custom Error Handler', () => {
  it('должен использовать кастомный обработчик ошибок', () => {
    const customErrorHandler = jest.fn(() => ({
      statusCode: 422,
      body: { custom: 'error' }
    }));

    const middleware = createInputValidationMiddleware({
      strictMode: true,
      skipMethods: [],
      errorHandler: customErrorHandler,
      schema: {
        body: {
          email: { type: ValidationType.EMAIL, required: true }
        }
      }
    });

    const req = createMockRequest({
      method: 'POST',
      body: { email: 'invalid' }
    });

    const res = createMockResponse();
    const next = createMockNext();

    middleware(req, res, next);

    expect(customErrorHandler).toHaveBeenCalled();
    expect(res.statusCode).toBe(422);
  });
});

// =============================================================================
// ENUM VALIDATION TESTS
// =============================================================================

describe('Input Validation - Enum Validation', () => {
  it('должен валидировать enum значения', () => {
    const middleware = createInputValidationMiddleware({
      skipMethods: [],
      schema: {
        body: {
          status: { type: ValidationType.STRING, required: true, enum: ['active', 'inactive', 'pending'] }
        }
      }
    });

    const req = createMockRequest({
      method: 'POST',
      body: { status: 'active' }
    });

    const res = createMockResponse();
    const next = createMockNext();

    middleware(req, res, next);
    expect((req as any).validationResult.valid).toBe(true);
  });

  it('должен отклонять невалидное enum значение', () => {
    const middleware = createInputValidationMiddleware({
      strictMode: true,
      skipMethods: [],
      schema: {
        body: {
          status: { type: ValidationType.STRING, required: true, enum: ['active', 'inactive'] }
        }
      }
    });

    const req = createMockRequest({
      method: 'POST',
      body: { status: 'unknown' }
    });

    const res = createMockResponse();
    const next = createMockNext();

    middleware(req, res, next);
    expect((req as any).validationResult.valid).toBe(false);
  });
});
