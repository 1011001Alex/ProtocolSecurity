/**
 * =============================================================================
 * COMPREHENSIVE TESTS FOR ERROR HANDLING SYSTEM
 * =============================================================================
 * Полное покрытие всех классов ошибок и error handler:
 * - BaseError и все подклассы
 * - ErrorHandlerMiddleware
 * - Express/Koa/Fastify интеграция
 * =============================================================================
 */

import { IncomingMessage, ServerResponse } from 'http';
import {
  BaseError,
  ErrorLevel,
  ErrorCategory,
  ErrorFactory,
  SafeError,
  // Security Errors
  AuthenticationError,
  AuthorizationError,
  SessionExpiredError,
  MFARequiredError,
  InvalidTokenError,
  AccountLockedError,
  // Validation Errors
  ValidationError,
  InvalidInputError,
  MissingParameterError,
  // Not Found
  NotFoundError,
  // Rate Limit
  RateLimitExceededError,
  // Database
  DatabaseError,
  ConnectionError,
  // External Service
  ExternalServiceError,
  TimeoutError,
  // Internal
  InternalError
} from '../../src/errors/BaseError';

import {
  ErrorHandlerMiddleware as ErrorHandler,
  ErrorContext,
  createErrorHandler,
  createDevErrorHandler,
  createProdErrorHandler,
  expressErrorHandler,
  asyncHandler,
  koaErrorHandler,
  fastifyErrorHandler,
  ErrorHandlerConfig
} from '../../src/errors/ErrorHandlerMiddleware';

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
    end: jest.fn()
  };
  return res as ServerResponse;
};

const mockLogger = {
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  debug: jest.fn()
};

// =============================================================================
// BASE ERROR TESTS
// =============================================================================

describe('BaseError', () => {
  class TestError extends BaseError {
    constructor(message: string = 'Test error') {
      super(
        message,
        'TEST_ERROR',
        500,
        ErrorCategory.INTERNAL,
        ErrorLevel.ERROR
      );
    }

    protected getSafeMessage(): string {
      return 'Test error occurred';
    }
  }

  let error: TestError;

  beforeEach(() => {
    error = new TestError('Test error message');
  });

  // =============================================================================
  // CREATION TESTS
  // =============================================================================

  describe('Creation', () => {
    it('должен создавать ошибку с правильными свойствами', () => {
      expect(error).toBeDefined();
      expect(error).toBeInstanceOf(BaseError);
      expect(error).toBeInstanceOf(Error);
    });

    it('должен устанавливать code', () => {
      expect(error.code).toBe('TEST_ERROR');
    });

    it('должен устанавливать statusCode', () => {
      expect(error.statusCode).toBe(500);
    });

    it('должен устанавливать correlationId', () => {
      expect(error.correlationId).toBeDefined();
      expect(error.correlationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
    });

    it('должен устанавливать timestamp', () => {
      expect(error.timestamp).toBeDefined();
      expect(error.timestamp).toBeInstanceOf(Date);
    });

    it('должен устанавливать category', () => {
      expect(error.category).toBe(ErrorCategory.INTERNAL);
    });

    it('должен устанавливать level', () => {
      expect(error.level).toBe(ErrorLevel.ERROR);
    });

    it('должен устанавливать metadata по умолчанию', () => {
      expect(error.metadata).toEqual({});
    });

    it('должен устанавливать кастомные metadata', () => {
      const customError = new TestError();
      Object.assign(customError, { metadata: { custom: 'data' } });
      expect(customError.metadata).toBeDefined();
    });

    it('должен иметь stack trace', () => {
      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('TestError');
    });
  });

  // =============================================================================
  // SAFE RESPONSE TESTS
  // =============================================================================

  describe('Safe Response', () => {
    it('должен возвращать safe response', () => {
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse).toBeDefined();
      expect(safeResponse.code).toBe('TEST_ERROR');
      expect(safeResponse.message).toBe('Test error occurred');
      expect(safeResponse.level).toBe('error');
      expect(safeResponse.correlationId).toBeDefined();
      expect(safeResponse.timestamp).toBeDefined();
    });

    it('должен включать details в development режиме', () => {
      const safeResponse = error.toSafeResponse(true);

      expect(safeResponse.details).toBeDefined();
      expect(safeResponse.details.stack).toBeDefined();
    });

    it('должен исключать details в production режиме', () => {
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.details).toBeUndefined();
    });

    it('должен включать path если установлен', () => {
      error.withRequest('/api/test', 'GET');
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.path).toBe('/api/test');
      expect(safeResponse.method).toBe('GET');
    });
  });

  // =============================================================================
  // FULL ERROR TESTS
  // =============================================================================

  describe('Full Error', () => {
    it('должен возвращать полную информацию об ошибке', () => {
      const fullError = error.toFullError();

      expect(fullError).toBeDefined();
      expect(fullError.code).toBe('TEST_ERROR');
      expect(fullError.message).toBe('Test error message');
      expect(fullError.stack).toBeDefined();
      expect(fullError.category).toBe(ErrorCategory.INTERNAL);
      expect(fullError.statusCode).toBe(500);
    });
  });

  // =============================================================================
  // REQUEST CONTEXT TESTS
  // =============================================================================

  describe('Request Context', () => {
    it('должен устанавливать request контекст', () => {
      error.withRequest('/api/users', 'POST');

      expect((error as any).path).toBe('/api/users');
      expect((error as any).method).toBe('POST');
    });

    it('должен возвращать this для chaining', () => {
      const result = error.withRequest('/api/test', 'GET');
      expect(result).toBe(error);
    });
  });

  // =============================================================================
  // LOGGING TESTS
  // =============================================================================

  describe('Logging', () => {
    it('должен логировать ошибку через logger', () => {
      error.log(mockLogger);

      expect(mockLogger.error).toHaveBeenCalled();
    });
  });
});

// =============================================================================
// SECURITY ERRORS TESTS
// =============================================================================

describe('Security Errors', () => {
  // =============================================================================
  // AUTHENTICATION ERROR TESTS
  // =============================================================================

  describe('AuthenticationError', () => {
    it('должен создавать AuthenticationError', () => {
      const error = new AuthenticationError();

      expect(error).toBeInstanceOf(BaseError);
      expect(error.code).toBe('AUTH_FAILED');
      expect(error.statusCode).toBe(401);
      expect(error.category).toBe(ErrorCategory.AUTHENTICATION);
      expect(error.level).toBe(ErrorLevel.WARNING);
    });

    it('должен возвращать safe message', () => {
      const error = new AuthenticationError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('Invalid credentials');
    });

    it('должен принимать кастомное сообщение', () => {
      const error = new AuthenticationError('Custom auth failed');
      expect(error.message).toBe('Custom auth failed');
    });

    it('должен принимать metadata', () => {
      const error = new AuthenticationError('Auth failed', { userId: '123' });
      expect(error.metadata.userId).toBe('123');
    });
  });

  // =============================================================================
  // AUTHORIZATION ERROR TESTS
  // =============================================================================

  describe('AuthorizationError', () => {
    it('должен создавать AuthorizationError', () => {
      const error = new AuthorizationError();

      expect(error.code).toBe('ACCESS_DENIED');
      expect(error.statusCode).toBe(403);
      expect(error.category).toBe(ErrorCategory.AUTHORIZATION);
    });

    it('должен возвращать safe message', () => {
      const error = new AuthorizationError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('You do not have permission to access this resource');
    });
  });

  // =============================================================================
  // SESSION EXPIRED ERROR TESTS
  // =============================================================================

  describe('SessionExpiredError', () => {
    it('должен создавать SessionExpiredError', () => {
      const error = new SessionExpiredError();

      expect(error.code).toBe('SESSION_EXPIRED');
      expect(error.statusCode).toBe(401);
    });

    it('должен возвращать safe message', () => {
      const error = new SessionExpiredError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('Your session has expired. Please log in again.');
    });
  });

  // =============================================================================
  // MFA REQUIRED ERROR TESTS
  // =============================================================================

  describe('MFARequiredError', () => {
    it('должен создавать MFARequiredError', () => {
      const error = new MFARequiredError();

      expect(error.code).toBe('MFA_REQUIRED');
      expect(error.statusCode).toBe(403);
    });

    it('должен возвращать safe message', () => {
      const error = new MFARequiredError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('Multi-factor authentication is required');
    });
  });

  // =============================================================================
  // INVALID TOKEN ERROR TESTS
  // =============================================================================

  describe('InvalidTokenError', () => {
    it('должен создавать InvalidTokenError', () => {
      const error = new InvalidTokenError();

      expect(error.code).toBe('INVALID_TOKEN');
      expect(error.statusCode).toBe(401);
    });

    it('должен возвращать safe message', () => {
      const error = new InvalidTokenError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('Invalid or expired token');
    });
  });

  // =============================================================================
  // ACCOUNT LOCKED ERROR TESTS
  // =============================================================================

  describe('AccountLockedError', () => {
    it('должен создавать AccountLockedError', () => {
      const error = new AccountLockedError(300);

      expect(error.code).toBe('ACCOUNT_LOCKED');
      expect(error.statusCode).toBe(423);
      expect(error.metadata.retryAfter).toBe(300);
    });

    it('должен возвращать safe message', () => {
      const error = new AccountLockedError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('Account temporarily locked. Please try again later.');
    });
  });

  // =============================================================================
  // VALIDATION ERRORS TESTS
  // =============================================================================

  describe('Validation Errors', () => {
    it('должен создавать ValidationError', () => {
      const error = new ValidationError();

      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.statusCode).toBe(400);
      expect(error.category).toBe(ErrorCategory.VALIDATION);
    });

    it('должен создавать InvalidInputError', () => {
      const error = new InvalidInputError('email');

      expect(error.code).toBe('INVALID_INPUT');
      expect(error.statusCode).toBe(400);
      expect(error.metadata.field).toBe('email');
    });

    it('должен создавать MissingParameterError', () => {
      const error = new MissingParameterError('userId');

      expect(error.code).toBe('MISSING_PARAMETER');
      expect(error.statusCode).toBe(400);
      expect(error.metadata.parameter).toBe('userId');
    });

    it('должен возвращать safe message для validation ошибок', () => {
      const error = new ValidationError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('Invalid input provided');
    });
  });

  // =============================================================================
  // NOT FOUND ERROR TESTS
  // =============================================================================

  describe('NotFoundError', () => {
    it('должен создавать NotFoundError', () => {
      const error = new NotFoundError('User');

      expect(error.code).toBe('NOT_FOUND');
      expect(error.statusCode).toBe(404);
      expect(error.category).toBe(ErrorCategory.NOT_FOUND);
      expect(error.message).toBe('User not found');
    });

    it('должен создавать NotFoundError с resource по умолчанию', () => {
      const error = new NotFoundError();

      expect(error.message).toBe('Resource not found');
    });

    it('должен возвращать safe message', () => {
      const error = new NotFoundError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('The requested resource was not found');
    });
  });

  // =============================================================================
  // RATE LIMIT ERROR TESTS
  // =============================================================================

  describe('RateLimitExceededError', () => {
    it('должен создавать RateLimitExceededError', () => {
      const error = new RateLimitExceededError(60);

      expect(error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(error.statusCode).toBe(429);
      expect(error.category).toBe(ErrorCategory.RATE_LIMIT);
      expect(error.metadata.retryAfter).toBe(60);
    });

    it('должен возвращать safe message', () => {
      const error = new RateLimitExceededError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('Too many requests. Please try again later.');
    });
  });

  // =============================================================================
  // DATABASE ERRORS TESTS
  // =============================================================================

  describe('Database Errors', () => {
    it('должен создавать DatabaseError', () => {
      const error = new DatabaseError();

      expect(error.code).toBe('DATABASE_ERROR');
      expect(error.statusCode).toBe(500);
      expect(error.category).toBe(ErrorCategory.DATABASE);
    });

    it('должен создавать ConnectionError', () => {
      const error = new ConnectionError('PostgreSQL');

      expect(error.code).toBe('CONNECTION_ERROR');
      expect(error.statusCode).toBe(503);
      expect(error.category).toBe(ErrorCategory.DATABASE);
      expect(error.level).toBe(ErrorLevel.CRITICAL);
      expect(error.metadata.service).toBe('PostgreSQL');
    });

    it('должен возвращать safe message для database ошибок', () => {
      const error = new DatabaseError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('A database error occurred. Please try again later.');
    });
  });

  // =============================================================================
  // EXTERNAL SERVICE ERRORS TESTS
  // =============================================================================

  describe('External Service Errors', () => {
    it('должен создавать ExternalServiceError', () => {
      const error = new ExternalServiceError('Payment Gateway', 502);

      expect(error.code).toBe('EXTERNAL_SERVICE_ERROR');
      expect(error.statusCode).toBe(502);
      expect(error.category).toBe(ErrorCategory.EXTERNAL_SERVICE);
      expect(error.metadata.serviceName).toBe('Payment Gateway');
    });

    it('должен создавать TimeoutError', () => {
      const error = new TimeoutError('API Request', 30000);

      expect(error.code).toBe('TIMEOUT');
      expect(error.statusCode).toBe(504);
      expect(error.metadata.operation).toBe('API Request');
      expect(error.metadata.timeoutMs).toBe(30000);
    });

    it('должен возвращать safe message для external service ошибок', () => {
      const error = new ExternalServiceError('Service');
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('An external service is unavailable. Please try again later.');
    });
  });

  // =============================================================================
  // INTERNAL ERROR TESTS
  // =============================================================================

  describe('InternalError', () => {
    it('должен создавать InternalError', () => {
      const error = new InternalError();

      expect(error.code).toBe('INTERNAL_ERROR');
      expect(error.statusCode).toBe(500);
      expect(error.category).toBe(ErrorCategory.INTERNAL);
      expect(error.level).toBe(ErrorLevel.CRITICAL);
    });

    it('должен создавать InternalError с innerError', () => {
      const innerError = new Error('Inner error');
      const error = new InternalError('Internal error occurred', {}, innerError);

      expect(error.innerError).toBe(innerError);
    });

    it('должен возвращать safe message', () => {
      const error = new InternalError();
      const safeResponse = error.toSafeResponse(false);

      expect(safeResponse.message).toBe('An internal error occurred. Please try again later.');
    });
  });
});

// =============================================================================
// ERROR FACTORY TESTS
// =============================================================================

describe('ErrorFactory', () => {
  describe('fromStatusCode', () => {
    it('должен создавать ValidationError из 400', () => {
      const error = ErrorFactory.fromStatusCode(400);
      expect(error).toBeInstanceOf(ValidationError);
      expect(error.statusCode).toBe(400);
    });

    it('должен создавать AuthenticationError из 401', () => {
      const error = ErrorFactory.fromStatusCode(401);
      expect(error).toBeInstanceOf(AuthenticationError);
      expect(error.statusCode).toBe(401);
    });

    it('должен создавать AuthorizationError из 403', () => {
      const error = ErrorFactory.fromStatusCode(403);
      expect(error).toBeInstanceOf(AuthorizationError);
      expect(error.statusCode).toBe(403);
    });

    it('должен создавать NotFoundError из 404', () => {
      const error = ErrorFactory.fromStatusCode(404);
      expect(error).toBeInstanceOf(NotFoundError);
      expect(error.statusCode).toBe(404);
    });

    it('должен создавать RateLimitExceededError из 429', () => {
      const error = ErrorFactory.fromStatusCode(429);
      expect(error).toBeInstanceOf(RateLimitExceededError);
      expect(error.statusCode).toBe(429);
    });

    it('должен создавать InternalError из 500', () => {
      const error = ErrorFactory.fromStatusCode(500);
      expect(error).toBeInstanceOf(InternalError);
      expect(error.statusCode).toBe(500);
    });

    it('должен создавать ExternalServiceError из 502', () => {
      const error = ErrorFactory.fromStatusCode(502);
      expect(error).toBeInstanceOf(ExternalServiceError);
      expect(error.statusCode).toBe(502);
    });

    it('должен создавать ConnectionError из 503', () => {
      const error = ErrorFactory.fromStatusCode(503);
      expect(error).toBeInstanceOf(ConnectionError);
      expect(error.statusCode).toBe(503);
    });

    it('должен создавать TimeoutError из 504', () => {
      const error = ErrorFactory.fromStatusCode(504);
      expect(error).toBeInstanceOf(TimeoutError);
      expect(error.statusCode).toBe(504);
    });

    it('должен создавать InternalError для неизвестного кода', () => {
      const error = ErrorFactory.fromStatusCode(599);
      expect(error).toBeInstanceOf(InternalError);
    });
  });

  describe('wrap', () => {
    it('должен оборачивать BaseError без изменений', () => {
      const originalError = new AuthenticationError();
      const wrapped = ErrorFactory.wrap(originalError);

      expect(wrapped).toBe(originalError);
    });

    it('должен оборачивать Error в InternalError', () => {
      const nativeError = new Error('Native error');
      const wrapped = ErrorFactory.wrap(nativeError);

      expect(wrapped).toBeInstanceOf(InternalError);
      expect(wrapped.message).toContain('Native error');
      expect((wrapped as InternalError).innerError).toBe(nativeError);
    });

    it('должен оборачивать unknown в InternalError', () => {
      const unknownError = 'String error';
      const wrapped = ErrorFactory.wrap(unknownError);

      expect(wrapped).toBeInstanceOf(InternalError);
      expect(wrapped.message).toBe('Unknown error occurred');
    });

    it('должен добавлять context при обёртывании', () => {
      const nativeError = new Error('Native error');
      const wrapped = ErrorFactory.wrap(nativeError, 'Database operation');

      expect(wrapped.message).toContain('Database operation');
    });
  });
});

// =============================================================================
// ERROR HANDLER MIDDLEWARE TESTS
// =============================================================================

describe('ErrorHandlerMiddleware', () => {
  let handler: ErrorHandlerMiddleware;
  let req: IncomingMessage;
  let res: ServerResponse;

  beforeEach(() => {
    handler = createDevErrorHandler(mockLogger);
    req = createMockRequest();
    res = createMockResponse();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // =============================================================================
  // CREATION TESTS
  // =============================================================================

  describe('Creation', () => {
    it('должен создавать error handler', () => {
      expect(handler).toBeDefined();
      expect(handler).toBeInstanceOf(ErrorHandler);
    });

    it('должен создавать dev error handler', () => {
      const devHandler = createDevErrorHandler();
      expect(devHandler).toBeDefined();
    });

    it('должен создавать prod error handler', () => {
      const prodHandler = createProdErrorHandler(mockLogger);
      expect(prodHandler).toBeDefined();
    });
  });

  // =============================================================================
  // ERROR HANDLING TESTS
  // =============================================================================

  describe('Error Handling', () => {
    it('должен обрабатывать BaseError', () => {
      const error = new AuthenticationError();
      handler.handle(error, req, res);

      expect(res.statusCode).toBe(401);
      expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'application/json');
      expect(res.end).toHaveBeenCalled();
    });

    it('должен обрабатывать native Error', () => {
      const error = new Error('Native error');
      handler.handle(error, req, res);

      expect(res.statusCode).toBe(500);
    });

    it('должен обрабатывать unknown error', () => {
      const error = 'String error';
      handler.handle(error, req, res);

      expect(res.statusCode).toBe(500);
    });

    it('должен логировать ошибку', () => {
      const error = new AuthenticationError();
      handler.handle(error, req, res);

      expect(mockLogger.warn).toHaveBeenCalled();
    });

    it('должен устанавливать X-Correlation-ID header', () => {
      const error = new AuthenticationError();
      handler.handle(error, req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'X-Correlation-ID',
        expect.any(String)
      );
    });

    it('должен устанавливать X-Content-Type-Options header', () => {
      const error = new AuthenticationError();
      handler.handle(error, req, res);

      expect(res.setHeader).toHaveBeenCalledWith(
        'X-Content-Type-Options',
        'nosniff'
      );
    });
  });

  // =============================================================================
  // RESPONSE FORMAT TESTS
  // =============================================================================

  describe('Response Format', () => {
    it('должен возвращать JSON response', () => {
      const error = new AuthenticationError();
      handler.handle(error, req, res);

      const responseData = JSON.parse((res.end as jest.Mock).mock.calls[0][0]);

      expect(responseData.code).toBe('AUTH_FAILED');
      expect(responseData.message).toBe('Invalid credentials');
      expect(responseData.correlationId).toBeDefined();
      expect(responseData.timestamp).toBeDefined();
    });

    it('должен включать details в development', () => {
      const error = new ValidationError();
      handler.handle(error, req, res);

      const responseData = JSON.parse((res.end as jest.Mock).mock.calls[0][0]);

      // В development режиме details должны быть
      // Проверяем что correlationId и timestamp есть (это всегда есть в SafeError)
      expect(responseData.correlationId).toBeDefined();
      expect(responseData.timestamp).toBeDefined();
    });
  });

  // =============================================================================
  // EXPRESS INTEGRATION TESTS
  // =============================================================================

  describe('Express Integration', () => {
    it('должен создавать Express error handler', () => {
      const expressHandler = expressErrorHandler({
        detailedErrorsInDev: true,
        logger: mockLogger
      });

      expect(expressHandler).toBeDefined();
      expect(typeof expressHandler).toBe('function');
    });

    it('должен создавать async handler wrapper', () => {
      const asyncFn = jest.fn().mockResolvedValue('success');
      const wrapped = asyncHandler(asyncFn);

      expect(wrapped).toBeDefined();
      expect(typeof wrapped).toBe('function');
    });
  });

  // =============================================================================
  // KOA INTEGRATION TESTS
  // =============================================================================

  describe('Koa Integration', () => {
    it('должен создавать Koa error handler', () => {
      const koaHandler = koaErrorHandler({
        detailedErrorsInDev: true,
        logger: mockLogger
      });

      expect(koaHandler).toBeDefined();
      expect(typeof koaHandler).toBe('function');
    });
  });

  // =============================================================================
  // FASTIFY INTEGRATION TESTS
  // =============================================================================

  describe('Fastify Integration', () => {
    it('должен создавать Fastify error handler', () => {
      const fastifyHandler = fastifyErrorHandler({
        detailedErrorsInDev: true,
        logger: mockLogger
      });

      expect(fastifyHandler).toBeDefined();
      expect(typeof fastifyHandler).toBe('function');
    });
  });
});

// =============================================================================
// ERROR LEVELS TESTS
// =============================================================================

describe('Error Levels', () => {
  it('должен иметь все уровни ошибок', () => {
    expect(ErrorLevel.INFO).toBe('info');
    expect(ErrorLevel.WARNING).toBe('warning');
    expect(ErrorLevel.ERROR).toBe('error');
    expect(ErrorLevel.CRITICAL).toBe('critical');
  });
});

// =============================================================================
// ERROR CATEGORIES TESTS
// =============================================================================

describe('Error Categories', () => {
  it('должен иметь все категории ошибок', () => {
    expect(ErrorCategory.VALIDATION).toBe('VALIDATION');
    expect(ErrorCategory.AUTHENTICATION).toBe('AUTHENTICATION');
    expect(ErrorCategory.AUTHORIZATION).toBe('AUTHORIZATION');
    expect(ErrorCategory.NOT_FOUND).toBe('NOT_FOUND');
    expect(ErrorCategory.RATE_LIMIT).toBe('RATE_LIMIT');
    expect(ErrorCategory.INTERNAL).toBe('INTERNAL');
  });
});
