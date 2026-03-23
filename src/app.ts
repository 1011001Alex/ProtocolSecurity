/**
 * =============================================================================
 * PROTOCOL SECURITY - EXPRESS APPLICATION
 * =============================================================================
 * Главный файл приложения Express с полной интеграцией security middleware
 *
 * Features:
 * - CORS middleware integration
 * - Security headers
 * - Rate limiting
 * - Error handling
 * - Health checks
 * - Environment validation
 *
 * @author Theodor Munch
 * @license MIT
 * @version 1.0.0
 * =============================================================================
 */

import express, { Application, Request, Response, NextFunction } from 'express';
import { createCORS, CORSPresets, validateCORSConfig, CORSConfig } from './middleware/CORSMiddleware';
import { createSecurityHeadersMiddleware, SecurityHeadersMiddleware } from './middleware/SecurityHeadersMiddleware';
import { RateLimiter, createRateLimiter, createMemoryStore, createPerIPRule, createAPIRule } from './middleware/RateLimitMiddleware';
import { createInputValidationMiddleware, ValidationPresets, ValidationType } from './middleware/InputValidationMiddleware';
import { EnvironmentValidator, validateEnvironmentQuick } from './utils/EnvironmentValidator';

// =============================================================================
// ENVIRONMENT CONFIGURATION
// =============================================================================

/**
 * Выполняет валидацию окружения при старте приложения
 * В production блокирует запуск при критических ошибках
 */
function validateEnvironmentOnStartup(): void {
  const nodeEnv = process.env.NODE_ENV || 'development';
  const isProduction = nodeEnv === 'production';

  console.log(`\n🔐 VALIDATION ENVIRONNEMENT (${nodeEnv})...`);

  const validator = new EnvironmentValidator({
    nodeEnv,
    blockOnCritical: isProduction,
    logWarnings: true,
    minPasswordLength: isProduction ? 32 : 8
  });

  const result = validator.validateEnvironment();

  if (result.isProductionReady) {
    console.log('✅ Environment validation passed\n');
  } else {
    if (isProduction) {
      console.error('\n❌ CRITICAL: Environment NOT ready for production!');
      console.error('Fix the following issues before deploying:\n');
      result.errors.forEach(err => console.error(`  • ${err}`));
      console.error('\n🛑 Application startup aborted. Please fix security issues.\n');
      throw new Error('Production environment validation failed. See logs for details.');
    } else {
      console.warn('\n⚠️  Development mode: Some security warnings ignored');
      console.warn('⚠️  WARNING: This configuration is NOT safe for production!\n');
    }
  }
}

// Вызываем валидацию при импорте модуля (только логи, без блокировки)
// Блокировка будет в startServer для production
try {
  validateEnvironmentOnStartup();
} catch (err) {
  // Игнорируем ошибки в development, логируем в production
  if (process.env.NODE_ENV === 'production') {
    throw err;
  }
}

/**
 * Получает переменную окружения с значением по умолчанию
 */
function getEnv(key: string, defaultValue: string): string {
  return process.env[key] ?? defaultValue;
}

/**
 * Получает boolean переменную окружения
 */
function getEnvBoolean(key: string, defaultValue: boolean): boolean {
  const value = process.env[key];
  if (value === undefined) return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

/**
 * Получает number переменную окружения
 */
function getEnvNumber(key: string, defaultValue: number): number {
  const value = process.env[key];
  if (value === undefined) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

/**
 * Парсит список из строки (разделитель - запятая)
 */
function parseList(value: string): string[] {
  if (!value || value.trim() === '') return [];
  return value.split(',').map(item => item.trim()).filter(item => item.length > 0);
}

// =============================================================================
// CORS CONFIGURATION FROM ENV
// =============================================================================

/**
 * Создаёт CORS конфигурацию из переменных окружения
 */
function createCORSConfigFromEnv(): CORSConfig {
  const mode = getEnv('CORS_MODE', 'dev');
  const origins = getEnv('CORS_ORIGINS', '*');
  const methods = getEnv('CORS_METHODS', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
  const allowedHeaders = getEnv('CORS_ALLOWED_HEADERS', 'Content-Type,Authorization,X-Requested-With,X-Request-ID');
  const exposedHeaders = getEnv('CORS_EXPOSED_HEADERS', 'X-Request-ID,X-RateLimit-Limit,X-RateLimit-Remaining');
  const credentials = getEnvBoolean('CORS_CREDENTIALS', false);
  const maxAge = getEnvNumber('CORS_MAX_AGE', 86400);
  const preflightContinue = getEnvBoolean('CORS_PREFLIGHT_CONTINUE', false);
  const optionsSuccessStatus = getEnvNumber('CORS_OPTIONS_SUCCESS_STATUS', 204);
  const strict = getEnvBoolean('CORS_STRICT', false);
  const blacklist = parseList(getEnv('CORS_BLACKLIST', ''));
  const dynamicOrigin = getEnvBoolean('CORS_DYNAMIC_ORIGIN', false);

  // Парсим origins
  let origin: string | RegExp | Array<string | RegExp>;
  if (origins === '*') {
    origin = '*';
  } else {
    const originList = parseList(origins);
    origin = originList.map(o => {
      // Проверяем, является ли origin RegExp паттерном
      if (o.startsWith('/') && o.endsWith('/')) {
        return new RegExp(o.slice(1, -1));
      }
      return o;
    });
    if (originList.length === 1) {
      origin = origin[0];
    }
  }

  const config: CORSConfig = {
    origin,
    methods: parseList(methods),
    allowedHeaders: parseList(allowedHeaders),
    exposedHeaders: parseList(exposedHeaders),
    credentials,
    maxAge,
    preflightContinue,
    optionsSuccessStatus,
    strict,
    blacklistedOrigins: blacklist,
    dynamicOrigin
  };

  // Валидируем конфигурацию
  const errors = validateCORSConfig(config);
  if (errors.length > 0) {
    console.warn('[CORS] Предупреждения валидации конфигурации:');
    errors.forEach(err => console.warn(`  - ${err.message}`));
  }

  return config;
}

/**
 * Получает CORS middleware на основе режима
 */
function getCORSByMode(mode: string) {
  switch (mode.toLowerCase()) {
    case 'public':
      return CORSPresets.public;
    case 'private':
      const privateOrigins = parseList(getEnv('CORS_ORIGINS', 'https://example.com'));
      return CORSPresets.private(privateOrigins);
    case 'dev':
      return CORSPresets.dev;
    case 'apigateway':
    case 'api-gateway':
      const apiDomains = parseList(getEnv('CORS_ORIGINS', 'https://api.example.com'));
      return CORSPresets.apiGateway(apiDomains);
    case 'microservice':
      return CORSPresets.microservice;
    default:
      return createCORS(createCORSConfigFromEnv());
  }
}

// =============================================================================
// APPLICATION FACTORY
// =============================================================================

/**
 * Интерфейс конфигурации приложения
 */
export interface AppConfig {
  port: number;
  host: string;
  nodeEnv: string;
  corsMode: string;
  enableRateLimit: boolean;
  enableSecurityHeaders: boolean;
  enableHealthCheck: boolean;
  enableInputValidation: boolean;
  inputValidationStrictMode: boolean;
  inputValidationMaxBodySize: number;
  inputValidationSanitizeHTML: boolean;
}

/**
 * Создаёт конфигурацию приложения из переменных окружения
 */
export function createAppConfigFromEnv(): AppConfig {
  return {
    port: getEnvNumber('PORT', 3000),
    host: getEnv('HOST', '0.0.0.0'),
    nodeEnv: getEnv('NODE_ENV', 'development'),
    corsMode: getEnv('CORS_MODE', 'dev'),
    enableRateLimit: getEnvBoolean('ENABLE_RATE_LIMIT', true),
    enableSecurityHeaders: getEnvBoolean('ENABLE_SECURITY_HEADERS', true),
    enableHealthCheck: getEnvBoolean('ENABLE_HEALTH_CHECK', true),
    enableInputValidation: getEnvBoolean('ENABLE_INPUT_VALIDATION', true),
    inputValidationStrictMode: getEnvBoolean('INPUT_VALIDATION_STRICT_MODE', false),
    inputValidationMaxBodySize: getEnvNumber('INPUT_VALIDATION_MAX_BODY_SIZE', 10 * 1024 * 1024),
    inputValidationSanitizeHTML: getEnvBoolean('INPUT_VALIDATION_SANITIZE_HTML', true)
  };
}

/**
 * Factory для создания Express приложения
 */
export function createApp(config?: Partial<AppConfig>): Application {
  const appConfig: AppConfig = {
    ...createAppConfigFromEnv(),
    ...config
  };

  const app = express();

  // =============================================================================
  // TRUST PROXY
  // =============================================================================
  // Доверяем прокси заголовкам (для определения реального IP)
  app.set('trust proxy', true);

  // =============================================================================
  // CORS MIDDLEWARE
  // =============================================================================
  const corsMode = appConfig.corsMode;
  const corsMiddleware = getCORSByMode(corsMode);
  app.use(corsMiddleware);
  console.log(`[CORS] Middleware активирован в режиме: ${corsMode}`);

  // =============================================================================
  // SECURITY HEADERS MIDDLEWARE
  // =============================================================================
  if (appConfig.enableSecurityHeaders) {
    const securityHeadersMiddleware = createSecurityHeadersMiddleware();
    app.use((req: Request, res: Response, next: NextFunction) => {
      securityHeadersMiddleware.handle(req, res);
      next();
    });
    console.log('[SecurityHeaders] Middleware активирован');
  }

  // =============================================================================
  // RATE LIMITING MIDDLEWARE
  // =============================================================================
  if (appConfig.enableRateLimit) {
    // Инициализируем rate limiter асинхронно
    const initRateLimiter = async () => {
      const store = createMemoryStore();
      const rateLimiter = createRateLimiter(store, true);
      await rateLimiter.initialize();

      // Добавляем правила
      rateLimiter.addRule(createPerIPRule());
      rateLimiter.addRule(createAPIRule());

      app.use((req: Request, res: Response, next: NextFunction) => {
        rateLimiter.handle(req, res, next);
      });

      console.log('[RateLimit] Middleware активирован (MemoryStore)');
    };

    initRateLimiter().catch(err => {
      console.error('[RateLimit] Ошибка инициализации:', err);
    });
  }

  // =============================================================================
  // BODY PARSERS
  // =============================================================================
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // =============================================================================
  // INPUT VALIDATION MIDDLEWARE
  // =============================================================================
  if (appConfig.enableInputValidation) {
    // Глобальная валидация для всех POST/PUT/PATCH запросов
    const inputValidationMiddleware = createInputValidationMiddleware({
      strictMode: appConfig.inputValidationStrictMode,
      maxBodySize: appConfig.inputValidationMaxBodySize,
      sanitizeHTML: appConfig.inputValidationSanitizeHTML,
      logErrors: true,
      enableRateLimit: false, // Rate limiting уже есть в RateLimitMiddleware
      skipMethods: ['GET', 'HEAD', 'OPTIONS'], // GET запросы не требуют валидации body
      schema: {
        // Базовая схема для всех запросов может быть расширена в роутах
      }
    });

    app.use(inputValidationMiddleware);
    console.log(`[InputValidation] Middleware активирован (strict: ${appConfig.inputValidationStrictMode}, maxBody: ${appConfig.inputValidationMaxBodySize / 1024 / 1024}MB)`);
  }

  // =============================================================================
  // HEALTH CHECK ENDPOINTS
  // =============================================================================
  if (appConfig.enableHealthCheck) {
    /**
     * Basic health check
     */
    app.get('/health', (req: Request, res: Response) => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: appConfig.nodeEnv
      });
    });

    /**
     * Detailed health check with service status
     */
    app.get('/health/detailed', (req: Request, res: Response) => {
      const memoryUsage = process.memoryUsage();
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: appConfig.nodeEnv,
        version: process.version,
        memory: {
          heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + ' MB',
          heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + ' MB',
          rss: Math.round(memoryUsage.rss / 1024 / 1024) + ' MB',
          external: Math.round(memoryUsage.external / 1024 / 1024) + ' MB'
        },
        cors: {
          mode: corsMode,
          enabled: true
        }
      });
    });

    /**
     * Readiness check (for Kubernetes)
     */
    app.get('/ready', (req: Request, res: Response) => {
      // Здесь можно проверить подключение к БД, Redis и т.д.
      res.status(200).json({
        ready: true,
        timestamp: new Date().toISOString()
      });
    });

    /**
     * Liveness check (for Kubernetes)
     */
    app.get('/live', (req: Request, res: Response) => {
      res.status(200).json({
        live: true,
        timestamp: new Date().toISOString()
      });
    });

    // =============================================================================
    // EXAMPLE: Protected endpoint with input validation
    // =============================================================================
    /**
     * Пример POST endpoint с валидацией данных пользователя
     * Демонстрирует использование ValidationPresets.userRegistration
     */
    app.post('/api/example/register', 
      createInputValidationMiddleware({
        strictMode: true,
        schema: ValidationPresets.userRegistration
      }),
      (req: Request, res: Response) => {
        // Валидированные данные доступны через (req as any).validationResult
        const validationResult = (req as any).validationResult;
        
        res.status(200).json({
          success: true,
          message: 'Данные успешно валидированы',
          validatedData: validationResult?.sanitized?.body,
          timestamp: new Date().toISOString()
        });
      }
    );

    /**
     * Пример endpoint с валидацией search параметров
     * Демонстрирует использование ValidationPresets.search
     */
    app.get('/api/example/search',
      createInputValidationMiddleware({
        schema: ValidationPresets.search
      }),
      (req: Request, res: Response) => {
        const validationResult = (req as any).validationResult;
        
        res.status(200).json({
          success: true,
          message: 'Search параметры валидированы',
          validatedQuery: validationResult?.sanitized?.query,
          timestamp: new Date().toISOString()
        });
      }
    );

    /**
     * Пример endpoint с валидацией UUID параметра
     * Демонстрирует использование ValidationPresets.uuidParams
     */
    app.get('/api/example/resource/:id',
      createInputValidationMiddleware({
        schema: ValidationPresets.uuidParams
      }),
      (req: Request, res: Response) => {
        const validationResult = (req as any).validationResult;
        
        res.status(200).json({
          success: true,
          message: 'UUID параметр валидирован',
          validatedParams: validationResult?.sanitized?.params,
          timestamp: new Date().toISOString()
        });
      }
    );

    console.log('[HealthCheck] Endpoints активированы: /health, /health/detailed, /ready, /live');
    console.log('[Example] Demo endpoints с валидацией: /api/example/register, /api/example/search, /api/example/resource/:id');
  }

  // =============================================================================
  // ROOT ENDPOINT
  // =============================================================================
  app.get('/', (req: Request, res: Response) => {
    res.json({
      name: 'Protocol Security API',
      version: '1.0.0',
      author: 'Theodor Munch',
      documentation: '/api/docs',
      health: '/health'
    });
  });

  // =============================================================================
  // 404 HANDLER
  // =============================================================================
  app.use((req: Request, res: Response) => {
    res.status(404).json({
      error: 'Not Found',
      message: `Route ${req.method} ${req.path} not found`,
      timestamp: new Date().toISOString()
    });
  });

  // =============================================================================
  // GLOBAL ERROR HANDLER
  // =============================================================================
  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    console.error('[GlobalErrorHandler]', err);

    res.status(err instanceof Error && 'status' in err ? (err as any).status : 500).json({
      error: 'Internal Server Error',
      message: appConfig.nodeEnv === 'development' ? err.message : 'Something went wrong',
      timestamp: new Date().toISOString()
    });
  });

  console.log(`[Express] Приложение создано (env: ${appConfig.nodeEnv})`);

  return app;
}

// =============================================================================
// SERVER START
// =============================================================================

/**
 * Запускает сервер
 */
export async function startServer(config?: Partial<AppConfig>): Promise<void> {
  const appConfig: AppConfig = {
    ...createAppConfigFromEnv(),
    ...config
  };

  // Финальная валидация перед запуском в production
  if (appConfig.nodeEnv === 'production') {
    console.log('\n🔒 PRODUCTION MODE: Performing final security validation...\n');
    
    const validator = new EnvironmentValidator({
      nodeEnv: 'production',
      blockOnCritical: true,
      logWarnings: true,
      minPasswordLength: 32
    });

    const result = validator.validateEnvironment();

    if (!result.isProductionReady) {
      console.error('\n❌ PRODUCTION STARTUP ABORTED\n');
      console.error('The following security issues must be resolved:\n');
      
      result.issues
        .filter(issue => issue.severity === 'critical' || issue.severity === 'high')
        .forEach(issue => {
          console.error(`  [${issue.severity.toUpperCase()}] ${issue.variable}: ${issue.message}`);
          console.error(`    → ${issue.recommendation}\n`);
        });

      throw new Error(
        `Production environment validation failed. ` +
        `Critical issues: ${result.errors.length}. ` +
        `Please fix before deploying.`
      );
    }

    console.log('✅ Production security validation passed\n');
  }

  const app = createApp(appConfig);

  return new Promise((resolve, reject) => {
    const server = app.listen(appConfig.port, appConfig.host, () => {
      console.log('');
      console.log('='.repeat(60));
      console.log('  PROTOCOL SECURITY API SERVER');
      console.log('='.repeat(60));
      console.log(`  Environment:    ${appConfig.nodeEnv}`);
      console.log(`  Host:           ${appConfig.host}`);
      console.log(`  Port:           ${appConfig.port}`);
      console.log(`  CORS Mode:      ${appConfig.corsMode}`);
      console.log(`  Security:       ${appConfig.enableSecurityHeaders ? 'Enabled' : 'Disabled'}`);
      console.log(`  Rate Limit:     ${appConfig.enableRateLimit ? 'Enabled' : 'Disabled'}`);
      console.log('='.repeat(60));
      console.log(`  Health Check:   http://${appConfig.host}:${appConfig.port}/health`);
      console.log(`  API Root:       http://${appConfig.host}:${appConfig.port}/`);
      console.log('='.repeat(60));
      console.log('');
      resolve();
    });

    server.on('error', (err: any) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`[Server] Port ${appConfig.port} already in use`);
      } else {
        console.error('[Server] Error:', err);
      }
      reject(err);
    });

    // Graceful shutdown
    const gracefulShutdown = (signal: string) => {
      console.log(`\n[Server] Получен сигнал ${signal}. Завершение работы...`);
      server.close(() => {
        console.log('[Server] HTTP сервер закрыт');
        process.exit(0);
      });

      // Force shutdown after timeout
      setTimeout(() => {
        console.error('[Server] Принудительное завершение работы');
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  });
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================

// Запускаем сервер только если этот файл является точкой входа
if (require.main === module) {
  startServer().catch(err => {
    console.error('[Startup] Критическая ошибка:', err);
    process.exit(1);
  });
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  createApp,
  startServer,
  createAppConfigFromEnv,
  createCORSConfigFromEnv,
  getCORSByMode
};
