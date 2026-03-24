/**
 * ============================================================================
 * HEALTH CHECK SERVICE - СЕРВИС ПРОВЕРКИ ЗДОРОВЬЯ
 * ============================================================================
 * Комплексная система проверки здоровья всех компонентов системы
 * 
 * Features:
 * - Проверка Redis подключения
 * - Проверка Database подключения
 * - Проверка External APIs (Vault, Elasticsearch)
 * - Проверка памяти/CPU
 * - Проверка circuit breakers
 * - Prometheus metrics integration
 * - Формат JSON со статусом компонентов
 * 
 * @author Theodor Munch
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import * as os from 'os';
import {
  HealthCheckConfig,
  HealthCheckResult,
  ComponentHealthStatus,
  HealthStatus,
  ComponentType,
  DEFAULT_HEALTH_CHECK_CONFIG,
  HealthCheckOptions,
  DEFAULT_HEALTH_CHECK_OPTIONS,
  CircuitBreakerHealthStatus,
  RedisHealthStatus,
  DatabaseHealthStatus,
  ExternalApiHealthStatus,
  MemoryHealthStatus,
  CPUHealthStatus,
  PrometheusMetrics
} from './HealthCheckTypes';
import { CircuitBreaker, CircuitBreakerManager, CircuitState } from '../utils/CircuitBreaker';
import { PerformanceMonitor, getPerformanceMonitor } from '../utils/PerformanceMonitor';

// Ре-экспорт типов для тестов
export {
  HealthStatus,
  ComponentType,
  HealthCheckConfig,
  HealthCheckResult,
  ComponentHealthStatus,
  DEFAULT_HEALTH_CHECK_CONFIG,
  HealthCheckOptions,
  DEFAULT_HEALTH_CHECK_OPTIONS,
  CircuitBreakerHealthStatus,
  RedisHealthStatus,
  DatabaseHealthStatus,
  ExternalApiHealthStatus,
  MemoryHealthStatus,
  CPUHealthStatus,
  PrometheusMetrics
};

/**
 * Health Check Service
 */
export class HealthCheckService extends EventEmitter {
  /** Конфигурация */
  private readonly config: HealthCheckConfig;
  
  /** Менеджер circuit breakers */
  private circuitBreakerManager?: CircuitBreakerManager;
  
  /** Performance monitor */
  private performanceMonitor?: PerformanceMonitor;
  
  /** Последний результат проверки */
  private lastCheckResult?: HealthCheckResult;
  
  /** Таймер периодической проверки */
  private checkTimer: NodeJS.Timeout | null = null;

  /** Флаг остановки */
  private isStopping: boolean = false;
  
  /** Кэш Redis клиента (инжектируется извне) */
  private redisClient?: unknown;
  
  /** Кэш Database подключения (инжектируется извне) */
  private databaseConnection?: unknown;
  
  /** Circuit breakers для внешних сервисов */
  private readonly serviceBreakers: Map<string, CircuitBreaker> = new Map();
  
  /** Внешние API для проверки */
  private readonly externalApis: Array<{
    name: string;
    url: string;
    enabled: boolean;
  }> = [];

  /**
   * Создает health check service
   */
  constructor(config: Partial<HealthCheckConfig> = {}) {
    super();
    
    this.config = {
      ...DEFAULT_HEALTH_CHECK_CONFIG,
      ...config
    };
    
    this.initializeServiceBreakers();
    this.initializeExternalApis();
  }

  /**
   * Инициализация circuit breakers для сервисов
   */
  private initializeServiceBreakers(): void {
    // Circuit breaker для Redis
    this.serviceBreakers.set('redis', new CircuitBreaker({
      name: 'redis',
      failureThreshold: 5,
      successThreshold: 3,
      resetTimeout: 30000,
      operationTimeout: this.config.redisTimeout,
      enableMonitoring: true
    }));
    
    // Circuit breaker для Database
    this.serviceBreakers.set('database', new CircuitBreaker({
      name: 'database',
      failureThreshold: 5,
      successThreshold: 3,
      resetTimeout: 30000,
      operationTimeout: this.config.databaseTimeout,
      enableMonitoring: true
    }));
    
    // Circuit breaker для Vault
    this.serviceBreakers.set('vault', new CircuitBreaker({
      name: 'vault',
      failureThreshold: 3,
      successThreshold: 2,
      resetTimeout: 60000,
      operationTimeout: this.config.vaultTimeout,
      enableMonitoring: true
    }));
    
    // Circuit breaker для Elasticsearch
    this.serviceBreakers.set('elasticsearch', new CircuitBreaker({
      name: 'elasticsearch',
      failureThreshold: 3,
      successThreshold: 2,
      resetTimeout: 60000,
      operationTimeout: this.config.elasticsearchTimeout,
      enableMonitoring: true
    }));
  }

  /**
   * Инициализация внешних API для проверки
   */
  private initializeExternalApis(): void {
    // Vault API
    const vaultUrl = process.env.VAULT_URL || 'https://vault.local:8200';
    this.externalApis.push({
      name: 'vault',
      url: `${vaultUrl}/v1/sys/health`,
      enabled: true
    });
    
    // Elasticsearch API
    const esHost = process.env.ELASTICSEARCH_HOST || 'https://es.local:9200';
    this.externalApis.push({
      name: 'elasticsearch',
      url: `${esHost}/_cluster/health`,
      enabled: true
    });
  }

  /**
   * Установка Circuit Breaker Manager
   */
  setCircuitBreakerManager(manager: CircuitBreakerManager): void {
    this.circuitBreakerManager = manager;
  }

  /**
   * Установка Performance Monitor
   */
  setPerformanceMonitor(monitor: PerformanceMonitor): void {
    this.performanceMonitor = monitor;
  }

  /**
   * Установка Redis клиента
   */
  setRedisClient(client: unknown): void {
    this.redisClient = client;
  }

  /**
   * Установка Database подключения
   */
  setDatabaseConnection(connection: unknown): void {
    this.databaseConnection = connection;
  }

  /**
   * Добавление внешнего API для проверки
   */
  addExternalApi(name: string, url: string, enabled = true): void {
    const existingIndex = this.externalApis.findIndex(api => api.name === name);
    
    if (existingIndex >= 0) {
      this.externalApis[existingIndex] = { name, url, enabled };
    } else {
      this.externalApis.push({ name, url, enabled });
    }
  }

  /**
   * Запуск периодических проверок
   */
  start(): void {
    if (this.checkTimer) {
      return;
    }

    this.log('START', 'Запуск Health Check Service');
    this.isStopping = false;

    // Немедленная первая проверка
    this.performHealthCheck().then(result => {
      this.lastCheckResult = result;
    }).catch(err => {
      this.log('ERROR', `Ошибка первой проверки: ${err.message}`);
    });

    // Периодические проверки
    this.checkTimer = setInterval(() => {
      if (!this.isStopping) {
        this.performHealthCheck().then(result => {
          this.lastCheckResult = result;
        }).catch(err => {
          this.log('ERROR', `Ошибка периодической проверки: ${err.message}`);
        });
      }
    }, this.config.checkInterval);

    this.emit('started');
  }

  /**
   * Остановка проверок
   */
  stop(): void {
    if (this.checkTimer) {
      clearInterval(this.checkTimer);
      this.checkTimer = null;
    }

    this.isStopping = true;
    this.log('STOP', 'Остановка Health Check Service');
    this.emit('stopped');
  }

  /**
   * Выполнение полной проверки здоровья
   */
  async performHealthCheck(
    options: Partial<HealthCheckOptions> = {}
  ): Promise<HealthCheckResult> {
    const opts: HealthCheckOptions = {
      ...DEFAULT_HEALTH_CHECK_OPTIONS,
      ...options
    };
    
    const timestamp = new Date();
    const components: Record<string, ComponentHealthStatus> = {};
    
    // Проверка Redis
    if (opts.checkRedis) {
      components.redis = await this.checkRedis();
    }
    
    // Проверка Database
    if (opts.checkDatabase) {
      components.database = await this.checkDatabase();
    }
    
    // Проверка Vault
    if (opts.checkVault) {
      components.vault = await this.checkVault();
    }
    
    // Проверка Elasticsearch
    if (opts.checkElasticsearch) {
      components.elasticsearch = await this.checkElasticsearch();
    }
    
    // Проверка circuit breakers
    if (opts.checkCircuitBreakers) {
      const breakersStatus = await this.checkCircuitBreakers();
      components.circuit_breakers = breakersStatus;
    }
    
    // Проверка системных ресурсов
    if (opts.checkSystemResources) {
      components.memory = await this.checkMemory();
      components.cpu = await this.checkCPU();
    }
    
    // Проверка external APIs
    if (opts.checkExternalApis) {
      const externalApisStatus = await this.checkExternalApis();
      components.external_apis = externalApisStatus;
    }
    
    // Проверка application
    components.application = this.checkApplication();
    
    // Подсчет статистики
    const summary = this.calculateSummary(components);
    
    const result: HealthCheckResult = {
      status: this.calculateOverallStatus(components),
      timestamp,
      uptime: process.uptime(),
      version: process.version,
      environment: process.env.NODE_ENV || 'development',
      components,
      summary
    };
    
    this.lastCheckResult = result;
    this.emit('check:completed', result);
    
    // Проверка на проблемы
    this.checkForIssues(result);
    
    return result;
  }

  /**
   * Быстрая проверка (liveness)
   */
  async performLivenessCheck(): Promise<HealthCheckResult> {
    return this.performHealthCheck({
      checkRedis: false,
      checkDatabase: false,
      checkVault: false,
      checkElasticsearch: false,
      checkCircuitBreakers: false,
      checkSystemResources: false,
      checkExternalApis: false
    });
  }

  /**
   * Проверка готовности (readiness)
   */
  async performReadinessCheck(): Promise<HealthCheckResult> {
    return this.performHealthCheck({
      checkRedis: true,
      checkDatabase: true,
      checkVault: true,
      checkElasticsearch: true,
      checkCircuitBreakers: true,
      checkSystemResources: true,
      checkExternalApis: false
    });
  }

  /**
   * Получение последнего результата проверки
   */
  getLastCheckResult(): HealthCheckResult | undefined {
    return this.lastCheckResult;
  }

  /**
   * Получение Prometheus metrics
   */
  getPrometheusMetrics(): PrometheusMetrics {
    const result = this.lastCheckResult;
    
    if (!result) {
      return {
        metrics: '',
        contentType: 'text/plain; version=0.0.4; charset=utf-8'
      };
    }
    
    const lines: string[] = [];
    const timestamp = Date.now();
    
    // Help и type для метрик
    lines.push('# HELP protocol_health_status Общий статус здоровья (1=healthy, 0=unhealthy)');
    lines.push('# TYPE protocol_health_status gauge');
    lines.push(`protocol_health_status{environment="${result.environment}"} ${result.status === HealthStatus.HEALTHY ? 1 : 0}`);
    
    lines.push('');
    lines.push('# HELP protocol_health_uptime Uptime процесса в секундах');
    lines.push('# TYPE protocol_health_uptime gauge');
    lines.push(`protocol_health_uptime{environment="${result.environment}"} ${result.uptime}`);
    
    lines.push('');
    lines.push('# HELP protocol_health_component_status Статус компонента (1=healthy, 0=unhealthy)');
    lines.push('# TYPE protocol_health_component_status gauge');
    
    // Метрики компонентов
    for (const [name, component] of Object.entries(result.components)) {
      const value = component.status === HealthStatus.HEALTHY ? 1 : 0;
      lines.push(`protocol_health_component_status{component="${name}",type="${component.type}"} ${value}`);
    }
    
    lines.push('');
    lines.push('# HELP protocol_health_component_response_time Время ответа компонента (ms)');
    lines.push('# TYPE protocol_health_component_response_time gauge');
    
    for (const [name, component] of Object.entries(result.components)) {
      if (component.responseTime !== undefined) {
        lines.push(`protocol_health_component_response_time{component="${name}",type="${component.type}"} ${component.responseTime}`);
      }
    }
    
    lines.push('');
    lines.push('# HELP protocol_health_summary_total Всего компонентов');
    lines.push('# TYPE protocol_health_summary_total gauge');
    lines.push(`protocol_health_summary_total{environment="${result.environment}"} ${result.summary.total}`);
    
    lines.push('');
    lines.push('# HELP protocol_health_summary_healthy Здоровых компонентов');
    lines.push('# TYPE protocol_health_summary_healthy gauge');
    lines.push(`protocol_health_summary_healthy{environment="${result.environment}"} ${result.summary.healthy}`);
    
    lines.push('');
    lines.push('# HELP protocol_health_summary_warning Компонентов с warning');
    lines.push('# TYPE protocol_health_summary_warning gauge');
    lines.push(`protocol_health_summary_warning{environment="${result.environment}"} ${result.summary.warning}`);
    
    lines.push('');
    lines.push('# HELP protocol_health_summary_unhealthy Нездоровых компонентов');
    lines.push('# TYPE protocol_health_summary_unhealthy gauge');
    lines.push(`protocol_health_summary_unhealthy{environment="${result.environment}"} ${result.summary.unhealthy}`);
    
    // Memory метрики
    const memoryUsage = process.memoryUsage();
    lines.push('');
    lines.push('# HELP protocol_memory_heap_used Использовано heap памяти (bytes)');
    lines.push('# TYPE protocol_memory_heap_used gauge');
    lines.push(`protocol_memory_heap_used ${memoryUsage.heapUsed}`);
    
    lines.push('');
    lines.push('# HELP protocol_memory_heap_total Всего heap памяти (bytes)');
    lines.push('# TYPE protocol_memory_heap_total gauge');
    lines.push(`protocol_memory_heap_total ${memoryUsage.heapTotal}`);
    
    lines.push('');
    lines.push('# HELP protocol_memory_rss RSS памяти (bytes)');
    lines.push('# TYPE protocol_memory_rss gauge');
    lines.push(`protocol_memory_rss ${memoryUsage.rss}`);
    
    lines.push('');
    lines.push('# HELP protocol_memory_external External память (bytes)');
    lines.push('# TYPE protocol_memory_external gauge');
    lines.push(`protocol_memory_external ${memoryUsage.external}`);
    
    // Circuit Breaker метрики
    if (this.circuitBreakerManager) {
      const breakers = this.circuitBreakerManager.getAll();

      lines.push('');
      lines.push('# HELP protocol_circuit_breaker_state Состояние circuit breaker (0=CLOSED, 1=OPEN, 2=HALF_OPEN)');
      lines.push('# TYPE protocol_circuit_breaker_state gauge');

      for (const breaker of breakers) {
        const stats = breaker.getStats();
        const breakerName = (breaker as any).config?.name || 'unknown';
        const stateValue = stats.state === CircuitState.OPEN ? 1 : stats.state === CircuitState.HALF_OPEN ? 2 : 0;
        lines.push(`protocol_circuit_breaker_state{name="${breakerName}"} ${stateValue}`);
      }

      lines.push('');
      lines.push('# HELP protocol_circuit_breaker_failures Количество failures circuit breaker');
      lines.push('# TYPE protocol_circuit_breaker_failures counter');

      for (const breaker of breakers) {
        const stats = breaker.getStats();
        const breakerName = (breaker as any).config?.name || 'unknown';
        lines.push(`protocol_circuit_breaker_failures{name="${breakerName}"} ${stats.totalFailures}`);
      }

      lines.push('');
      lines.push('# HELP protocol_circuit_breaker_successes Количество successes circuit breaker');
      lines.push('# TYPE protocol_circuit_breaker_successes counter');

      for (const breaker of breakers) {
        const stats = breaker.getStats();
        const breakerName = (breaker as any).config?.name || 'unknown';
        lines.push(`protocol_circuit_breaker_successes{name="${breakerName}"} ${stats.totalSuccesses}`);
      }
    }
    
    return {
      metrics: lines.join('\n') + '\n',
      contentType: 'text/plain; version=0.0.4; charset=utf-8'
    };
  }

  // ============================================================================
  // ПРОВЕРКИ КОМПОНЕНТОВ
  // ============================================================================

  /**
   * Проверка Redis
   */
  private async checkRedis(): Promise<ComponentHealthStatus> {
    const timestamp = new Date();
    const startTime = Date.now();
    
    try {
      // Проверка circuit breaker
      const breaker = this.serviceBreakers.get('redis');
      if (breaker && !breaker.isAvailable()) {
        return {
          name: 'Redis',
          type: ComponentType.REDIS,
          status: HealthStatus.UNHEALTHY,
          error: 'Circuit breaker в состоянии OPEN',
          timestamp
        };
      }
      
      // Если Redis клиент не установлен
      if (!this.redisClient) {
        return {
          name: 'Redis',
          type: ComponentType.REDIS,
          status: HealthStatus.UNKNOWN,
          error: 'Redis клиент не настроен',
          timestamp
        };
      }
      
      // Проверка подключения (симуляция для демонстрации)
      // В реальной реализации здесь будет ping Redis
      const responseTime = Date.now() - startTime;
      
      if (breaker) {
        await breaker.execute(async () => {
          // Симуляция ping
          await new Promise(resolve => setTimeout(resolve, Math.random() * 10));
          return true;
        });
      }
      
      return {
        name: 'Redis',
        type: ComponentType.REDIS,
        status: HealthStatus.HEALTHY,
        responseTime,
        details: {
          connected: true
        },
        timestamp
      };
    } catch (error) {
      return {
        name: 'Redis',
        type: ComponentType.REDIS,
        status: HealthStatus.UNHEALTHY,
        error: (error as Error).message,
        timestamp
      };
    }
  }

  /**
   * Проверка Database
   */
  private async checkDatabase(): Promise<ComponentHealthStatus> {
    const timestamp = new Date();
    const startTime = Date.now();
    
    try {
      // Проверка circuit breaker
      const breaker = this.serviceBreakers.get('database');
      if (breaker && !breaker.isAvailable()) {
        return {
          name: 'Database',
          type: ComponentType.DATABASE,
          status: HealthStatus.UNHEALTHY,
          error: 'Circuit breaker в состоянии OPEN',
          timestamp
        };
      }
      
      // Если Database подключение не установлено
      if (!this.databaseConnection) {
        return {
          name: 'Database',
          type: ComponentType.DATABASE,
          status: HealthStatus.UNKNOWN,
          error: 'Database подключение не настроено',
          timestamp
        };
      }
      
      // Проверка подключения (симуляция для демонстрации)
      const responseTime = Date.now() - startTime;
      
      if (breaker) {
        await breaker.execute(async () => {
          // Симуляция query
          await new Promise(resolve => setTimeout(resolve, Math.random() * 20));
          return true;
        });
      }
      
      return {
        name: 'Database',
        type: ComponentType.DATABASE,
        status: HealthStatus.HEALTHY,
        responseTime,
        details: {
          connected: true
        },
        timestamp
      };
    } catch (error) {
      return {
        name: 'Database',
        type: ComponentType.DATABASE,
        status: HealthStatus.UNHEALTHY,
        error: (error as Error).message,
        timestamp
      };
    }
  }

  /**
   * Проверка Vault
   */
  private async checkVault(): Promise<ComponentHealthStatus> {
    const timestamp = new Date();
    const startTime = Date.now();
    
    try {
      // Проверка circuit breaker
      const breaker = this.serviceBreakers.get('vault');
      if (breaker && !breaker.isAvailable()) {
        return {
          name: 'Vault',
          type: ComponentType.VAULT,
          status: HealthStatus.UNHEALTHY,
          error: 'Circuit breaker в состоянии OPEN',
          timestamp
        };
      }
      
      const vaultUrl = process.env.VAULT_URL || 'https://vault.local:8200';
      const vaultToken = process.env.VAULT_TOKEN;
      
      // Если Vault не настроен
      if (!vaultToken || vaultToken === 'hvs.your_vault_token_here_generate_before_production') {
        return {
          name: 'Vault',
          type: ComponentType.VAULT,
          status: HealthStatus.WARNING,
          error: 'Vault токен не настроен (development режим)',
          timestamp,
          details: {
            url: vaultUrl,
            configured: false
          }
        };
      }
      
      // Проверка health endpoint
      const responseTime = Date.now() - startTime;
      
      if (breaker) {
        await breaker.execute(async () => {
          // В реальной реализации здесь будет HTTP запрос к Vault
          await new Promise(resolve => setTimeout(resolve, Math.random() * 50));
          return true;
        });
      }
      
      return {
        name: 'Vault',
        type: ComponentType.VAULT,
        status: HealthStatus.HEALTHY,
        responseTime,
        details: {
          url: vaultUrl,
          configured: true
        },
        timestamp
      };
    } catch (error) {
      return {
        name: 'Vault',
        type: ComponentType.VAULT,
        status: HealthStatus.UNHEALTHY,
        error: (error as Error).message,
        timestamp
      };
    }
  }

  /**
   * Проверка Elasticsearch
   */
  private async checkElasticsearch(): Promise<ComponentHealthStatus> {
    const timestamp = new Date();
    const startTime = Date.now();
    
    try {
      // Проверка circuit breaker
      const breaker = this.serviceBreakers.get('elasticsearch');
      if (breaker && !breaker.isAvailable()) {
        return {
          name: 'Elasticsearch',
          type: ComponentType.ELASTICSEARCH,
          status: HealthStatus.UNHEALTHY,
          error: 'Circuit breaker в состоянии OPEN',
          timestamp
        };
      }
      
      const esHost = process.env.ELASTICSEARCH_HOST || 'https://es.local:9200';
      const esUser = process.env.ELASTICSEARCH_USER;
      const esPassword = process.env.ELASTICSEARCH_PASSWORD;
      
      // Если Elasticsearch не настроен
      if (!esPassword || esPassword === 'your_secure_elasticsearch_password_here') {
        return {
          name: 'Elasticsearch',
          type: ComponentType.ELASTICSEARCH,
          status: HealthStatus.WARNING,
          error: 'Elasticsearch пароль не настроен (development режим)',
          timestamp,
          details: {
            host: esHost,
            configured: false
          }
        };
      }
      
      // Проверка cluster health
      const responseTime = Date.now() - startTime;
      
      if (breaker) {
        await breaker.execute(async () => {
          // В реальной реализации здесь будет HTTP запрос к Elasticsearch
          await new Promise(resolve => setTimeout(resolve, Math.random() * 50));
          return true;
        });
      }
      
      return {
        name: 'Elasticsearch',
        type: ComponentType.ELASTICSEARCH,
        status: HealthStatus.HEALTHY,
        responseTime,
        details: {
          host: esHost,
          configured: true
        },
        timestamp
      };
    } catch (error) {
      return {
        name: 'Elasticsearch',
        type: ComponentType.ELASTICSEARCH,
        status: HealthStatus.UNHEALTHY,
        error: (error as Error).message,
        timestamp
      };
    }
  }

  /**
   * Проверка Circuit Breakers
   */
  private async checkCircuitBreakers(): Promise<ComponentHealthStatus> {
    const timestamp = new Date();

    try {
      const breakers: CircuitBreakerHealthStatus[] = [];

      // Проверка service breakers
      const breakerNames = Array.from(this.serviceBreakers.keys());
      for (const name of breakerNames) {
        const breaker = this.serviceBreakers.get(name)!;
        const stats = breaker.getStats();
        breakers.push({
          name,
          state: stats.state as 'CLOSED' | 'OPEN' | 'HALF_OPEN',
          available: breaker.isAvailable(),
          failures: stats.failures,
          successes: stats.successes,
          totalRequests: stats.totalRequests
        });
      }

      // Проверка circuit breakers из manager
      if (this.circuitBreakerManager) {
        for (const breaker of this.circuitBreakerManager.getAll()) {
          const stats = breaker.getStats();
          const breakerName = (breaker as any).config?.name || 'unknown';

          // Избегаем дублирования
          if (!breakers.find(b => b.name === breakerName)) {
            breakers.push({
              name: breakerName,
              state: stats.state as 'CLOSED' | 'OPEN' | 'HALF_OPEN',
              available: breaker.isAvailable(),
              failures: stats.failures,
              successes: stats.successes,
              totalRequests: stats.totalRequests
            });
          }
        }
      }

      // Подсчет статистики
      const openCount = breakers.filter(b => b.state === 'OPEN').length;
      const halfOpenCount = breakers.filter(b => b.state === 'HALF_OPEN').length;

      let status = HealthStatus.HEALTHY;
      if (openCount > 0) {
        status = HealthStatus.UNHEALTHY;
      } else if (halfOpenCount > 0) {
        status = HealthStatus.WARNING;
      }

      return {
        name: 'Circuit Breakers',
        type: ComponentType.CIRCUIT_BREAKER,
        status,
        timestamp,
        details: {
          breakers,
          total: breakers.length,
          open: openCount,
          halfOpen: halfOpenCount,
          closed: breakers.length - openCount - halfOpenCount
        }
      };
    } catch (error) {
      return {
        name: 'Circuit Breakers',
        type: ComponentType.CIRCUIT_BREAKER,
        status: HealthStatus.UNHEALTHY,
        error: (error as Error).message,
        timestamp
      };
    }
  }

  /**
   * Проверка Memory
   */
  private async checkMemory(): Promise<ComponentHealthStatus> {
    const timestamp = new Date();
    
    try {
      const memoryUsage = process.memoryUsage();
      const totalMemory = os.totalmem();
      const freeMemory = os.freemem();
      const usedMemory = totalMemory - freeMemory;
      const usagePercent = (usedMemory / totalMemory) * 100;
      
      let status = HealthStatus.HEALTHY;
      if (usagePercent >= this.config.memoryCriticalThreshold) {
        status = HealthStatus.UNHEALTHY;
      } else if (usagePercent >= this.config.memoryWarningThreshold) {
        status = HealthStatus.WARNING;
      }
      
      return {
        name: 'Memory',
        type: ComponentType.MEMORY,
        status,
        timestamp,
        details: {
          heapUsed: memoryUsage.heapUsed,
          heapTotal: memoryUsage.heapTotal,
          rss: memoryUsage.rss,
          external: memoryUsage.external,
          totalMemory,
          freeMemory,
          usedMemory,
          usagePercent: Math.round(usagePercent * 100) / 100
        }
      };
    } catch (error) {
      return {
        name: 'Memory',
        type: ComponentType.MEMORY,
        status: HealthStatus.UNHEALTHY,
        error: (error as Error).message,
        timestamp
      };
    }
  }

  /**
   * Проверка CPU
   */
  private async checkCPU(): Promise<ComponentHealthStatus> {
    const timestamp = new Date();
    
    try {
      const cpus = os.cpus();
      const loadAvg = os.loadavg() as [number, number, number];
      
      // Расчет CPU usage
      let totalIdle = 0;
      let totalTick = 0;
      
      for (const cpu of cpus) {
        const total = cpu.times.idle + cpu.times.user + cpu.times.nice + cpu.times.sys + cpu.times.irq;
        totalIdle += cpu.times.idle;
        totalTick += total;
      }
      
      const idle = totalIdle / cpus.length;
      const usage = 100 - (idle / (totalTick / cpus.length)) * 100;
      
      let status = HealthStatus.HEALTHY;
      if (usage >= this.config.cpuCriticalThreshold) {
        status = HealthStatus.UNHEALTHY;
      } else if (usage >= this.config.cpuWarningThreshold) {
        status = HealthStatus.WARNING;
      }
      
      return {
        name: 'CPU',
        type: ComponentType.CPU,
        status,
        timestamp,
        details: {
          usage: Math.round(usage * 100) / 100,
          loadAverage: loadAvg,
          cores: cpus.length
        }
      };
    } catch (error) {
      return {
        name: 'CPU',
        type: ComponentType.CPU,
        status: HealthStatus.UNHEALTHY,
        error: (error as Error).message,
        timestamp
      };
    }
  }

  /**
   * Проверка External APIs
   */
  private async checkExternalApis(): Promise<ComponentHealthStatus> {
    const timestamp = new Date();
    const apis: ExternalApiHealthStatus[] = [];
    
    for (const api of this.externalApis) {
      if (!api.enabled) {
        continue;
      }
      
      const startTime = Date.now();
      
      try {
        // В реальной реализации здесь будет HTTP запрос
        // Симуляция для демонстрации
        await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
        
        const responseTime = Date.now() - startTime;
        
        apis.push({
          name: api.name,
          url: api.url,
          available: true,
          statusCode: 200,
          responseTime
        });
      } catch (error) {
        const responseTime = Date.now() - startTime;
        
        apis.push({
          name: api.name,
          url: api.url,
          available: false,
          responseTime,
          error: (error as Error).message
        });
      }
    }
    
    const availableCount = apis.filter(api => api.available).length;
    const totalCount = apis.length;
    
    let status = HealthStatus.HEALTHY;
    if (availableCount === 0 && totalCount > 0) {
      status = HealthStatus.UNHEALTHY;
    } else if (availableCount < totalCount) {
      status = HealthStatus.WARNING;
    }
    
    return {
      name: 'External APIs',
      type: ComponentType.EXTERNAL_API,
      status,
      timestamp,
      details: {
        apis,
        total: totalCount,
        available: availableCount,
        unavailable: totalCount - availableCount
      }
    };
  }

  /**
   * Проверка Application
   */
  private checkApplication(): ComponentHealthStatus {
    const timestamp = new Date();
    
    return {
      name: 'Application',
      type: ComponentType.APPLICATION,
      status: HealthStatus.HEALTHY,
      timestamp,
      details: {
        pid: process.pid,
        uptime: process.uptime(),
        version: process.version,
        environment: process.env.NODE_ENV || 'development',
        platform: process.platform,
        arch: process.arch
      }
    };
  }

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Подсчет статистики компонентов
   */
  private calculateSummary(components: Record<string, ComponentHealthStatus>): {
    total: number;
    healthy: number;
    warning: number;
    unhealthy: number;
    unknown: number;
  } {
    const summary = {
      total: Object.keys(components).length,
      healthy: 0,
      warning: 0,
      unhealthy: 0,
      unknown: 0
    };
    
    for (const component of Object.values(components)) {
      switch (component.status) {
        case HealthStatus.HEALTHY:
          summary.healthy++;
          break;
        case HealthStatus.WARNING:
          summary.warning++;
          break;
        case HealthStatus.UNHEALTHY:
          summary.unhealthy++;
          break;
        case HealthStatus.UNKNOWN:
          summary.unknown++;
          break;
      }
    }
    
    return summary;
  }

  /**
   * Расчет общего статуса
   */
  private calculateOverallStatus(components: Record<string, ComponentHealthStatus>): HealthStatus {
    const statuses = Object.values(components).map(c => c.status);

    // UNHEALTHY компоненты всегда делают статус unhealthy
    if (statuses.some(s => s === HealthStatus.UNHEALTHY)) {
      return HealthStatus.UNHEALTHY;
    }

    // WARNING от критических компонентов (redis, database, application) влияет на статус
    const criticalComponents = ['redis', 'database', 'application'];
    const criticalStatuses = Object.entries(components)
      .filter(([name]) => criticalComponents.includes(name))
      .map(([, c]) => c.status);

    if (criticalStatuses.some(s => s === HealthStatus.WARNING)) {
      return HealthStatus.WARNING;
    }

    // WARNING от опциональных компонентов (vault, elasticsearch) не влияет на общий статус
    // если только все компоненты не в warning
    const nonCriticalStatuses = Object.entries(components)
      .filter(([name]) => !criticalComponents.includes(name))
      .map(([, c]) => c.status);

    if (nonCriticalStatuses.length > 0 && nonCriticalStatuses.every(s => s === HealthStatus.WARNING)) {
      return HealthStatus.WARNING;
    }

    // UNKNOWN возвращаем только если нет healthy компонентов
    const healthyCount = statuses.filter(s => s === HealthStatus.HEALTHY).length;
    const unknownCount = statuses.filter(s => s === HealthStatus.UNKNOWN).length;
    
    if (healthyCount === 0 && unknownCount > 0) {
      return HealthStatus.UNKNOWN;
    }

    return HealthStatus.HEALTHY;
  }

  /**
   * Проверка на проблемы
   */
  private checkForIssues(result: HealthCheckResult): void {
    for (const [name, component] of Object.entries(result.components)) {
      if (component.status === HealthStatus.UNHEALTHY || component.status === HealthStatus.WARNING) {
        this.emit('issue:detected', name, component);
      }
    }
  }

  /**
   * Логирование
   */
  private log(action: string, message: string): void {
    const timestamp = new Date().toISOString();
    logger.debug(`[HealthCheckService] [${action}] ${message}`);
  }
}

/**
 * Singleton экземпляр
 */
let globalHealthCheckService: HealthCheckService | null = null;

/**
 * Получение глобального health check service
 */
export function getHealthCheckService(config?: Partial<HealthCheckConfig>): HealthCheckService {
  if (!globalHealthCheckService) {
    globalHealthCheckService = new HealthCheckService(config);
  }
  return globalHealthCheckService;
}

/**
 * Сброс глобального service (для тестов)
 */
export function resetHealthCheckService(): void {
  if (globalHealthCheckService) {
    globalHealthCheckService.stop();
    globalHealthCheckService = null;
  }
}
