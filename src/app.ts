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
import { createSecurityHeadersMiddleware } from './middleware/SecurityHeadersMiddleware';
import { createRateLimiter, createMemoryStore, createPerIPRule, createAPIRule } from './middleware/RateLimitMiddleware';
import { createInputValidationMiddleware, ValidationPresets } from './middleware/InputValidationMiddleware';
import { EnvironmentValidator } from './utils/EnvironmentValidator';
import {
  HealthCheckService,
  getHealthCheckService
} from './health/HealthCheckService';
import { HealthStatus } from './health/HealthCheckTypes';
import { CircuitBreakerManager } from './utils/CircuitBreaker';
import { PerformanceMonitor, getPerformanceMonitor } from './utils/PerformanceMonitor';
import { securityLogger } from './logging';

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

  securityLogger.info(`Validation environnement (${nodeEnv})...`, { nodeEnv });

  const validator = new EnvironmentValidator({
    nodeEnv,
    blockOnCritical: isProduction,
    logWarnings: true,
    minPasswordLength: isProduction ? 32 : 8
  });

  const result = validator.validateEnvironment();

  if (result.isProductionReady) {
    securityLogger.info('Environment validation passed', { isProductionReady: true });
  } else {
    if (isProduction) {
      securityLogger.critical('Environment NOT ready for production!', {
        errorsCount: result.errors.length,
        phase: 'startup_validation'
      });
      result.errors.forEach(err => {
        securityLogger.error(`Validation error: ${err}`, { category: 'validation_error' });
      });
      throw new Error('Production environment validation failed. See logs for details.');
    } else {
      securityLogger.warning('Development mode: Some security warnings ignored', {
        nodeEnv,
        isProductionReady: false
      });
      securityLogger.warning('WARNING: This configuration is NOT safe for production!', {
        phase: 'startup'
      });
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
    securityLogger.warning('CORS configuration validation warnings', {
      warningsCount: errors.length,
      errors: errors.map(e => e.message)
    });
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
  // Health Check конфигурация
  healthCheckEnabled: boolean;
  healthCheckInterval: number;
  healthCheckRedisTimeout: number;
  healthCheckDatabaseTimeout: number;
  healthCheckVaultTimeout: number;
  healthCheckElasticsearchTimeout: number;
  healthCheckEnablePrometheus: boolean;
  healthCheckPrometheusPort: number;
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
    inputValidationSanitizeHTML: getEnvBoolean('INPUT_VALIDATION_SANITIZE_HTML', true),
    // Health Check конфигурация
    healthCheckEnabled: getEnvBoolean('HEALTH_CHECK_ENABLED', true),
    healthCheckInterval: getEnvNumber('HEALTH_CHECK_INTERVAL', 10000),
    healthCheckRedisTimeout: getEnvNumber('HEALTH_CHECK_REDIS_TIMEOUT', 5000),
    healthCheckDatabaseTimeout: getEnvNumber('HEALTH_CHECK_DATABASE_TIMEOUT', 5000),
    healthCheckVaultTimeout: getEnvNumber('HEALTH_CHECK_VAULT_TIMEOUT', 5000),
    healthCheckElasticsearchTimeout: getEnvNumber('HEALTH_CHECK_ELASTICSEARCH_TIMEOUT', 5000),
    healthCheckEnablePrometheus: getEnvBoolean('HEALTH_CHECK_ENABLE_PROMETHEUS', true),
    healthCheckPrometheusPort: getEnvNumber('HEALTH_CHECK_PROMETHEUS_PORT', 9090)
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
  securityLogger.info('CORS middleware activated', { mode: corsMode, component: 'cors' });

  // =============================================================================
  // SECURITY HEADERS MIDDLEWARE
  // =============================================================================
  if (appConfig.enableSecurityHeaders) {
    const securityHeadersMiddleware = createSecurityHeadersMiddleware();
    app.use((req: Request, res: Response, next: NextFunction) => {
      securityHeadersMiddleware.handle(req, res);
      next();
    });
    securityLogger.info('Security headers middleware activated', { component: 'security_headers' });
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

      securityLogger.info('Rate limit middleware activated', { store: 'MemoryStore', component: 'rate_limit' });
    };

    initRateLimiter().catch(err => {
      securityLogger.error('Rate limit initialization error', err, { component: 'rate_limit' });
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
    securityLogger.info('Input validation middleware activated', {
      strictMode: appConfig.inputValidationStrictMode,
      maxBodySizeMB: appConfig.inputValidationMaxBodySize / 1024 / 1024,
      component: 'input_validation'
    });
  }

  // =============================================================================
  // HEALTH CHECK SERVICE INITIALIZATION
  // =============================================================================
  let healthCheckService: HealthCheckService | null = null;
  let circuitBreakerManager: CircuitBreakerManager | null = null;
  let performanceMonitor: PerformanceMonitor | null = null;

  if (appConfig.enableHealthCheck && appConfig.healthCheckEnabled) {
    // Инициализация Circuit Breaker Manager
    circuitBreakerManager = new CircuitBreakerManager();
    
    // Инициализация Performance Monitor
    performanceMonitor = getPerformanceMonitor({
      instanceName: 'protocol-api',
      collectionInterval: appConfig.healthCheckInterval,
      cpuWarningThreshold: appConfig.healthCheckInterval > 0 ? 70 : 70,
      memoryWarningThreshold: 80
    });
    performanceMonitor.start();
    
    // Инициализация Health Check Service
    healthCheckService = getHealthCheckService({
      enabled: appConfig.healthCheckEnabled,
      checkInterval: appConfig.healthCheckInterval,
      redisTimeout: appConfig.healthCheckRedisTimeout,
      databaseTimeout: appConfig.healthCheckDatabaseTimeout,
      vaultTimeout: appConfig.healthCheckVaultTimeout,
      elasticsearchTimeout: appConfig.healthCheckElasticsearchTimeout,
      enablePrometheus: appConfig.healthCheckEnablePrometheus,
      prometheusPort: appConfig.healthCheckPrometheusPort
    });
    
    // Интеграция с Circuit Breaker Manager
    healthCheckService.setCircuitBreakerManager(circuitBreakerManager);
    healthCheckService.setPerformanceMonitor(performanceMonitor);
    
    // Подписка на события
    healthCheckService.on('check:completed', (result) => {
      if (result.status !== HealthStatus.HEALTHY) {
        securityLogger.warning('Health check completed with non-healthy status', {
          status: result.status,
          healthy: result.summary.healthy,
          total: result.summary.total,
          component: 'health_check'
        });
      }
    });

    healthCheckService.on('issue:detected', (component, status) => {
      securityLogger.error(`Health check issue detected: ${component}`, {
        componentStatus: status.status,
        error: status.error || 'unknown error',
        affectedComponent: component,
        component: 'health_check'
      });
    });

    // Запуск периодических проверок
    healthCheckService.start();

    securityLogger.info('Health check service initialized', {
      interval: appConfig.healthCheckInterval,
      endpoints: ['/health', '/health/detailed', '/ready', '/live', '/health/prometheus', '/health/cached'],
      component: 'health_check'
    });
  }

  // =============================================================================
  // HEALTH CHECK ENDPOINTS
  // =============================================================================
  if (appConfig.enableHealthCheck) {
    /**
     * Basic health check - быстрая проверка доступности приложения
     * Используется для Kubernetes liveness probe
     */
    app.get('/health', (req: Request, res: Response) => {
      const result = healthCheckService?.getLastCheckResult();
      
      res.status(200).json({
        status: result?.status || 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: appConfig.nodeEnv,
        version: process.version,
        pid: process.pid
      });
    });

    /**
     * Detailed health check - полная проверка всех компонентов
     * Возвращает детальную информацию о статусе каждого компонента
     */
    app.get('/health/detailed', async (req: Request, res: Response) => {
      try {
        const result = await healthCheckService?.performHealthCheck();
        
        res.status(200).json({
          status: result?.status || 'healthy',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          environment: appConfig.nodeEnv,
          version: process.version,
          components: result?.components,
          summary: result?.summary,
          cors: {
            mode: corsMode,
            enabled: true
          }
        });
      } catch (error) {
        res.status(503).json({
          status: 'unhealthy',
          error: (error as Error).message,
          timestamp: new Date().toISOString()
        });
      }
    });

    /**
     * Readiness check - проверка готовности принимать трафик
     * Проверяет все зависимости: Redis, Database, Vault, Elasticsearch
     * Используется для Kubernetes readiness probe
     */
    app.get('/ready', async (req: Request, res: Response) => {
      try {
        const result = await healthCheckService?.performReadinessCheck();
        const isReady = result?.status === HealthStatus.HEALTHY;
        
        const statusCode = isReady ? 200 : 503;
        res.status(statusCode).json({
          ready: isReady,
          status: result?.status || 'unknown',
          timestamp: new Date().toISOString(),
          summary: result?.summary,
          components: {
            redis: result?.components.redis?.status,
            database: result?.components.database?.status,
            vault: result?.components.vault?.status,
            elasticsearch: result?.components.elasticsearch?.status,
            circuitBreakers: result?.components.circuit_breakers?.status,
            memory: result?.components.memory?.status,
            cpu: result?.components.cpu?.status
          }
        });
      } catch (error) {
        res.status(503).json({
          ready: false,
          status: 'unhealthy',
          error: (error as Error).message,
          timestamp: new Date().toISOString()
        });
      }
    });

    /**
     * Liveness check - проверка что приложение живо
     * Быстрая проверка без проверки зависимостей
     * Используется для Kubernetes liveness probe
     */
    app.get('/live', async (req: Request, res: Response) => {
      try {
        const result = await healthCheckService?.performLivenessCheck();
        const isLive = result?.status !== HealthStatus.UNHEALTHY;
        
        const statusCode = isLive ? 200 : 503;
        res.status(statusCode).json({
          live: isLive,
          status: result?.status || 'unknown',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          pid: process.pid
        });
      } catch (error) {
        res.status(503).json({
          live: false,
          status: 'unhealthy',
          error: (error as Error).message,
          timestamp: new Date().toISOString()
        });
      }
    });

    /**
     * Prometheus metrics endpoint
     * Возвращает метрики в формате Prometheus text format
     * Используется для сбора метрик Prometheus
     */
    app.get('/health/prometheus', (req: Request, res: Response) => {
      const metrics = healthCheckService?.getPrometheusMetrics();
      
      if (!metrics || !metrics.metrics) {
        res.status(503).json({
          error: 'Prometheus metrics not available',
          timestamp: new Date().toISOString()
        });
        return;
      }
      
      res.set('Content-Type', metrics.contentType);
      res.status(200).send(metrics.metrics);
    });

    /**
     * Health check с кэшированным результатом
     * Возвращает последний результат проверки без выполнения новой
     */
    app.get('/health/cached', (req: Request, res: Response) => {
      const result = healthCheckService?.getLastCheckResult();
      
      if (!result) {
        res.status(503).json({
          status: 'unknown',
          error: 'No health check result available yet',
          timestamp: new Date().toISOString()
        });
        return;
      }
      
      res.status(200).json(result);
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

    securityLogger.info('Health check endpoints activated', {
      endpoints: ['/health', '/health/detailed', '/ready', '/live'],
      demoEndpoints: ['/api/example/register', '/api/example/search', '/api/example/resource/:id'],
      component: 'endpoints'
    });
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
    securityLogger.error('Global error handler', err, {
      path: req.path,
      method: req.method,
      component: 'error_handler'
    });

    res.status(err instanceof Error && 'status' in err ? (err as any).status : 500).json({
      error: 'Internal Server Error',
      message: appConfig.nodeEnv === 'development' ? err.message : 'Something went wrong',
      timestamp: new Date().toISOString()
    });
  });

  securityLogger.info('Express application created', {
    env: appConfig.nodeEnv,
    component: 'express'
  });

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
    securityLogger.info('Production mode: Performing final security validation', {
      nodeEnv: appConfig.nodeEnv,
      phase: 'startup'
    });

    const validator = new EnvironmentValidator({
      nodeEnv: 'production',
      blockOnCritical: true,
      logWarnings: true,
      minPasswordLength: 32
    });

    const result = validator.validateEnvironment();

    if (!result.isProductionReady) {
      securityLogger.critical('Production startup aborted', {
        errorsCount: result.errors.length,
        phase: 'production_validation'
      });

      result.issues
        .filter(issue => issue.severity === 'critical' || issue.severity === 'high')
        .forEach(issue => {
          securityLogger.error(`Production validation issue: ${issue.variable}`, {
            severity: issue.severity,
            message: issue.message,
            recommendation: issue.recommendation,
            component: 'validation'
          });
        });

      throw new Error(
        `Production environment validation failed. ` +
        `Critical issues: ${result.errors.length}. ` +
        `Please fix before deploying.`
      );
    }

    securityLogger.info('Production security validation passed', {
      isProductionReady: true,
      phase: 'startup'
    });
  }

  const app = createApp(appConfig);

  return new Promise((resolve, reject) => {
    const server = app.listen(appConfig.port, appConfig.host, () => {
      const startupMessage = {
        message: 'PROTOCOL SECURITY API SERVER started',
        environment: appConfig.nodeEnv,
        host: appConfig.host,
        port: appConfig.port,
        corsMode: appConfig.corsMode,
        security: appConfig.enableSecurityHeaders ? 'Enabled' : 'Disabled',
        rateLimit: appConfig.enableRateLimit ? 'Enabled' : 'Disabled',
        endpoints: {
          healthCheck: `http://${appConfig.host}:${appConfig.port}/health`,
          readiness: `http://${appConfig.host}:${appConfig.port}/ready`,
          liveness: `http://${appConfig.host}:${appConfig.port}/live`,
          prometheus: `http://${appConfig.host}:${appConfig.port}/health/prometheus`,
          apiRoot: `http://${appConfig.host}:${appConfig.port}/`
        }
      };

      // Красивый вывод в консоль для человека
      process.stdout.write('\n');
      process.stdout.write('='.repeat(60) + '\n');
      process.stdout.write('  PROTOCOL SECURITY API SERVER\n');
      process.stdout.write('='.repeat(60) + '\n');
      process.stdout.write(`  Environment:    ${appConfig.nodeEnv}\n`);
      process.stdout.write(`  Host:           ${appConfig.host}\n`);
      process.stdout.write(`  Port:           ${appConfig.port}\n`);
      process.stdout.write(`  CORS Mode:      ${appConfig.corsMode}\n`);
      process.stdout.write(`  Security:       ${startupMessage.security}\n`);
      process.stdout.write(`  Rate Limit:     ${startupMessage.rateLimit}\n`);
      process.stdout.write('='.repeat(60) + '\n');
      process.stdout.write(`  Health Check:   ${startupMessage.endpoints.healthCheck}\n`);
      process.stdout.write(`  Readiness:      ${startupMessage.endpoints.readiness}\n`);
      process.stdout.write(`  Liveness:       ${startupMessage.endpoints.liveness}\n`);
      process.stdout.write(`  Prometheus:     ${startupMessage.endpoints.prometheus}\n`);
      process.stdout.write(`  API Root:       ${startupMessage.endpoints.apiRoot}\n`);
      process.stdout.write('='.repeat(60) + '\n');
      process.stdout.write('\n');

      // Логирование для системы
      securityLogger.info(startupMessage.message, startupMessage, { component: 'server' });

      resolve();
    });

    server.on('error', (err: any) => {
      if (err.code === 'EADDRINUSE') {
        securityLogger.error(`Port ${appConfig.port} already in use`, {
          port: appConfig.port,
          host: appConfig.host,
          component: 'server'
        });
      } else {
        securityLogger.error('Server error', err, { component: 'server' });
      }
      reject(err);
    });

    // Graceful shutdown
    const gracefulShutdown = (signal: string) => {
      securityLogger.info(`Server received signal ${signal}, shutting down`, {
        signal,
        component: 'server'
      });

      // Остановка Health Check Service
      if (healthCheckService) {
        securityLogger.info('HealthCheckService stopping', { component: 'health_check' });
        healthCheckService.stop();
      }

      // Остановка Performance Monitor
      if (performanceMonitor) {
        securityLogger.info('PerformanceMonitor stopping', { component: 'performance' });
        performanceMonitor.stop();
      }

      // Остановка Circuit Breaker Manager
      if (circuitBreakerManager) {
        securityLogger.info('CircuitBreakerManager stopping', { component: 'circuit_breaker' });
        circuitBreakerManager.destroyAll();
      }

      server.close(() => {
        securityLogger.info('HTTP server closed', { component: 'server' });
        process.exit(0);
      });

      // Force shutdown after timeout
      setTimeout(() => {
        securityLogger.critical('Forced server shutdown', {
          timeout: 10000,
          component: 'server'
        });
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
    securityLogger.critical('Startup critical error', err, {
      phase: 'startup',
      component: 'main'
    });
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
