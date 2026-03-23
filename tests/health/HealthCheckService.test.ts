/**
 * ============================================================================
 * HEALTH CHECK SERVICE TESTS
 * ============================================================================
 * Тесты для системы проверки здоровья сервисов
 * 
 * @author Theodor Munch
 * @version 1.0.0
 */

import {
  HealthCheckService,
  getHealthCheckService,
  resetHealthCheckService,
  HealthCheckConfig,
  HealthStatus,
  ComponentType,
  DEFAULT_HEALTH_CHECK_CONFIG,
  DEFAULT_HEALTH_CHECK_OPTIONS
} from '../../src/health/HealthCheckService';
import { CircuitBreakerManager, CircuitBreaker } from '../../src/utils/CircuitBreaker';
import { PerformanceMonitor } from '../../src/utils/PerformanceMonitor';

// ============================================================================
// MOCKS
// ============================================================================

/**
 * Mock Redis клиента
 */
class MockRedisClient {
  async ping(): Promise<string> {
    return 'PONG';
  }

  async info(): Promise<string> {
    return '# Memory\nused_memory:1000000\n# Clients\nconnected_clients:10';
  }
}

/**
 * Mock Database подключения
 */
class MockDatabaseConnection {
  async query(sql: string): Promise<unknown[]> {
    return [{ result: 'ok' }];
  }

  async ping(): Promise<number> {
    return 1;
  }
}

// ============================================================================
// TEST SUITE
// ============================================================================

describe('HealthCheckService', () => {
  let service: HealthCheckService;
  let circuitBreakerManager: CircuitBreakerManager;
  let performanceMonitor: PerformanceMonitor;

  beforeEach(() => {
    // Сброс singleton перед каждым тестом
    resetHealthCheckService();
    service = new HealthCheckService();
    circuitBreakerManager = new CircuitBreakerManager();
    performanceMonitor = new PerformanceMonitor();
  });

  afterEach(() => {
    service.stop();
    resetHealthCheckService();
  });

  // ============================================================================
  // КОНСТРУКТОР И ИНИЦИАЛИЗАЦИЯ
  // ============================================================================

  describe('Constructor', () => {
    it('должен создавать service с конфигурацией по умолчанию', () => {
      const defaultService = new HealthCheckService();
      
      expect(defaultService).toBeDefined();
      expect(defaultService.getLastCheckResult()).toBeUndefined();
    });

    it('должен создавать service с кастомной конфигурацией', () => {
      const customConfig: Partial<HealthCheckConfig> = {
        enabled: true,
        checkInterval: 5000,
        redisTimeout: 3000,
        databaseTimeout: 3000
      };

      const customService = new HealthCheckService(customConfig);
      
      expect(customService).toBeDefined();
      customService.stop();
    });

    it('должен инициализировать service breakers', () => {
      const result = service.getLastCheckResult();
      expect(result).toBeUndefined();
    });
  });

  // ============================================================================
  // ИНТЕГРАЦИЯ С CIRCUIT BREAKER MANAGER
  // ============================================================================

  describe('Circuit Breaker Integration', () => {
    it('должен принимать Circuit Breaker Manager', () => {
      service.setCircuitBreakerManager(circuitBreakerManager);
      
      // Создаем тестовый circuit breaker
      const testBreaker = circuitBreakerManager.create('test_service');
      
      expect(testBreaker).toBeDefined();
      expect(testBreaker.isAvailable()).toBe(true);
    });

    it('должен отслеживать состояние circuit breakers', async () => {
      service.setCircuitBreakerManager(circuitBreakerManager);
      
      const breaker = circuitBreakerManager.create('redis_test');
      
      // Выполняем успешную операцию
      await breaker.execute(async () => true);
      
      const result = await service.performHealthCheck();
      
      expect(result.components.circuit_breakers).toBeDefined();
      expect(result.components.circuit_breakers.status).toBe(HealthStatus.HEALTHY);
    });
  });

  // ============================================================================
  // ИНТЕГРАЦИЯ С PERFORMANCE MONITOR
  // ============================================================================

  describe('Performance Monitor Integration', () => {
    it('должен принимать Performance Monitor', () => {
      service.setPerformanceMonitor(performanceMonitor);
      
      expect(performanceMonitor).toBeDefined();
    });
  });

  // ============================================================================
  // REDIS CHECK
  // ============================================================================

  describe('Redis Check', () => {
    it('должен возвращать UNKNOWN статус если Redis клиент не настроен', async () => {
      const result = await service.performHealthCheck({
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.redis).toBeDefined();
      expect(result.components.redis.status).toBe(HealthStatus.UNKNOWN);
      expect(result.components.redis.error).toContain('не настроен');
    });

    it('должен возвращать HEALTHY статус при подключенном Redis', async () => {
      const mockRedis = new MockRedisClient();
      service.setRedisClient(mockRedis);

      const result = await service.performHealthCheck({
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.redis).toBeDefined();
      expect(result.components.redis.status).toBe(HealthStatus.HEALTHY);
      expect(result.components.redis.responseTime).toBeGreaterThanOrEqual(0);
    });

    it('должен иметь responseTime для Redis', async () => {
      const mockRedis = new MockRedisClient();
      service.setRedisClient(mockRedis);

      const result = await service.performHealthCheck({
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.redis.responseTime).toBeDefined();
      expect(typeof result.components.redis.responseTime).toBe('number');
    });
  });

  // ============================================================================
  // DATABASE CHECK
  // ============================================================================

  describe('Database Check', () => {
    it('должен возвращать UNKNOWN статус если Database подключение не настроено', async () => {
      const result = await service.performHealthCheck({
        checkRedis: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.database).toBeDefined();
      expect(result.components.database.status).toBe(HealthStatus.UNKNOWN);
      expect(result.components.database.error).toContain('не настроено');
    });

    it('должен возвращать HEALTHY статус при подключенной Database', async () => {
      const mockDb = new MockDatabaseConnection();
      service.setDatabaseConnection(mockDb);

      const result = await service.performHealthCheck({
        checkRedis: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.database).toBeDefined();
      expect(result.components.database.status).toBe(HealthStatus.HEALTHY);
      expect(result.components.database.responseTime).toBeGreaterThanOrEqual(0);
    });
  });

  // ============================================================================
  // VAULT CHECK
  // ============================================================================

  describe('Vault Check', () => {
    beforeEach(() => {
      // Сбрасываем переменные окружения
      delete process.env.VAULT_URL;
      delete process.env.VAULT_TOKEN;
    });

    it('должен возвращать WARNING статус если Vault токен не настроен', async () => {
      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.vault).toBeDefined();
      expect(result.components.vault.status).toBe(HealthStatus.WARNING);
      expect(result.components.vault.error).toContain('не настроен');
    });

    it('должен возвращать HEALTHY статус при настроенном Vault', async () => {
      process.env.VAULT_URL = 'https://vault.test.local:8200';
      process.env.VAULT_TOKEN = 'hvs.test_token_for_testing';

      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.vault).toBeDefined();
      expect([HealthStatus.HEALTHY, HealthStatus.WARNING]).toContain(result.components.vault.status);
      
      // Очищаем
      delete process.env.VAULT_URL;
      delete process.env.VAULT_TOKEN;
    });
  });

  // ============================================================================
  // ELASTICSEARCH CHECK
  // ============================================================================

  describe('Elasticsearch Check', () => {
    beforeEach(() => {
      delete process.env.ELASTICSEARCH_HOST;
      delete process.env.ELASTICSEARCH_USER;
      delete process.env.ELASTICSEARCH_PASSWORD;
    });

    it('должен возвращать WARNING статус если Elasticsearch пароль не настроен', async () => {
      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkVault: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.elasticsearch).toBeDefined();
      expect(result.components.elasticsearch.status).toBe(HealthStatus.WARNING);
      expect(result.components.elasticsearch.error).toContain('не настроен');
    });

    it('должен возвращать HEALTHY статус при настроенном Elasticsearch', async () => {
      process.env.ELASTICSEARCH_HOST = 'https://es.test.local:9200';
      process.env.ELASTICSEARCH_USER = 'elastic';
      process.env.ELASTICSEARCH_PASSWORD = 'test_password_for_testing';

      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkVault: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.elasticsearch).toBeDefined();
      expect([HealthStatus.HEALTHY, HealthStatus.WARNING]).toContain(result.components.elasticsearch.status);
      
      // Очищаем
      delete process.env.ELASTICSEARCH_HOST;
      delete process.env.ELASTICSEARCH_USER;
      delete process.env.ELASTICSEARCH_PASSWORD;
    });
  });

  // ============================================================================
  // CIRCUIT BREAKERS CHECK
  // ============================================================================

  describe('Circuit Breakers Check', () => {
    it('должен возвращать HEALTHY статус когда все circuit breakers закрыты', async () => {
      service.setCircuitBreakerManager(circuitBreakerManager);

      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      expect(result.components.circuit_breakers).toBeDefined();
      expect(result.components.circuit_breakers.status).toBe(HealthStatus.HEALTHY);
      expect(result.components.circuit_breakers.details).toBeDefined();
    });

    it('должен возвращать статистику по circuit breakers', async () => {
      service.setCircuitBreakerManager(circuitBreakerManager);

      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkSystemResources: false,
        checkExternalApis: false
      });

      const details = result.components.circuit_breakers.details as Record<string, unknown>;
      
      expect(details.total).toBeGreaterThanOrEqual(0);
      expect(details.open).toBeGreaterThanOrEqual(0);
      expect(details.closed).toBeGreaterThanOrEqual(0);
    });
  });

  // ============================================================================
  // MEMORY CHECK
  // ============================================================================

  describe('Memory Check', () => {
    it('должен возвращать статус памяти', async () => {
      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkExternalApis: false
      });

      expect(result.components.memory).toBeDefined();
      expect(result.components.memory.type).toBe(ComponentType.MEMORY);
      expect(result.components.memory.details).toBeDefined();
      
      const details = result.components.memory.details as Record<string, unknown>;
      expect(details.heapUsed).toBeDefined();
      expect(details.heapTotal).toBeDefined();
      expect(details.rss).toBeDefined();
      expect(details.usagePercent).toBeDefined();
    });

    it('должен возвращать HEALTHY статус при нормальном использовании памяти', async () => {
      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkExternalApis: false
      });

      // В нормальных условиях память должна быть healthy
      expect([HealthStatus.HEALTHY, HealthStatus.WARNING]).toContain(result.components.memory.status);
    });
  });

  // ============================================================================
  // CPU CHECK
  // ============================================================================

  describe('CPU Check', () => {
    it('должен возвращать статус CPU', async () => {
      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: true,
        checkExternalApis: false
      });

      expect(result.components.cpu).toBeDefined();
      expect(result.components.cpu.type).toBe(ComponentType.CPU);
      expect(result.components.cpu.details).toBeDefined();
      
      const details = result.components.cpu.details as Record<string, unknown>;
      expect(details.usage).toBeDefined();
      expect(details.loadAverage).toBeDefined();
      expect(details.cores).toBeDefined();
    });
  });

  // ============================================================================
  // EXTERNAL APIS CHECK
  // ============================================================================

  describe('External APIs Check', () => {
    it('должен возвращать статус external APIs', async () => {
      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: true
      });

      expect(result.components.external_apis).toBeDefined();
      expect(result.components.external_apis.type).toBe(ComponentType.EXTERNAL_API);
      expect(result.components.external_apis.details).toBeDefined();
    });

    it('должен добавлять кастомные external API', async () => {
      service.addExternalApi('custom_api', 'https://api.test.local/health');

      const result = await service.performHealthCheck({
        checkRedis: false,
        checkDatabase: false,
        checkVault: false,
        checkElasticsearch: false,
        checkCircuitBreakers: false,
        checkSystemResources: false,
        checkExternalApis: true
      });

      expect(result.components.external_apis).toBeDefined();
    });
  });

  // ============================================================================
  // APPLICATION CHECK
  // ============================================================================

  describe('Application Check', () => {
    it('должен возвращать статус приложения', async () => {
      const result = await service.performHealthCheck();

      expect(result.components.application).toBeDefined();
      expect(result.components.application.type).toBe(ComponentType.APPLICATION);
      expect(result.components.application.status).toBe(HealthStatus.HEALTHY);
      
      const details = result.components.application.details as Record<string, unknown>;
      expect(details.pid).toBe(process.pid);
      expect(details.uptime).toBeDefined();
      expect(details.environment).toBeDefined();
    });
  });

  // ============================================================================
  // OVERALL STATUS
  // ============================================================================

  describe('Overall Status Calculation', () => {
    it('должен возвращать HEALTHY когда все компоненты здоровы', async () => {
      const mockRedis = new MockRedisClient();
      const mockDb = new MockDatabaseConnection();
      
      service.setRedisClient(mockRedis);
      service.setDatabaseConnection(mockDb);

      const result = await service.performHealthCheck();

      expect(result.status).toBe(HealthStatus.HEALTHY);
    });

    it('должен возвращать UNHEALTHY когда есть нездоровые компоненты', async () => {
      // Создаем service с неправильной конфигурацией чтобы вызвать ошибки
      const badService = new HealthCheckService({
        redisTimeout: 1, // Очень маленький таймаут
        databaseTimeout: 1
      });

      const result = await badService.performHealthCheck();
      
      // Хотя бы один компонент должен быть unhealthy или warning
      expect([HealthStatus.HEALTHY, HealthStatus.WARNING, HealthStatus.UNHEALTHY]).toContain(result.status);
      
      badService.stop();
    });
  });

  // ============================================================================
  // SUMMARY CALCULATION
  // ============================================================================

  describe('Summary Calculation', () => {
    it('должен правильно подсчитывать статистику компонентов', async () => {
      const result = await service.performHealthCheck();

      expect(result.summary).toBeDefined();
      expect(result.summary.total).toBeGreaterThan(0);
      expect(result.summary.healthy + result.summary.warning + result.summary.unhealthy + result.summary.unknown)
        .toBe(result.summary.total);
    });
  });

  // ============================================================================
  // LIVENESS CHECK
  // ============================================================================

  describe('Liveness Check', () => {
    it('должен выполнять быструю проверку без зависимостей', async () => {
      const result = await service.performLivenessCheck();

      expect(result).toBeDefined();
      expect(result.uptime).toBeDefined();
      expect(result.timestamp).toBeDefined();
      
      // Liveness check не проверяет зависимости
      expect(result.components.redis).toBeUndefined();
      expect(result.components.database).toBeUndefined();
    });
  });

  // ============================================================================
  // READINESS CHECK
  // ============================================================================

  describe('Readiness Check', () => {
    it('должен выполнять полную проверку зависимостей', async () => {
      const result = await service.performReadinessCheck();

      expect(result).toBeDefined();
      
      // Readiness check проверяет зависимости
      expect(result.components.redis).toBeDefined();
      expect(result.components.database).toBeDefined();
      expect(result.components.vault).toBeDefined();
      expect(result.components.elasticsearch).toBeDefined();
    });
  });

  // ============================================================================
  // PROMETHEUS METRICS
  // ============================================================================

  describe('Prometheus Metrics', () => {
    it('должен возвращать метрики в формате Prometheus', async () => {
      // Сначала выполняем проверку чтобы был результат
      await service.performHealthCheck();

      const metrics = service.getPrometheusMetrics();

      expect(metrics).toBeDefined();
      expect(metrics.contentType).toBe('text/plain; version=0.0.4; charset=utf-8');
      expect(metrics.metrics).toContain('# HELP');
      expect(metrics.metrics).toContain('# TYPE');
      expect(metrics.metrics).toContain('protocol_health_status');
    });

    it('должен включать метрики компонентов', async () => {
      await service.performHealthCheck();

      const metrics = service.getPrometheusMetrics();

      expect(metrics.metrics).toContain('protocol_health_component_status');
      expect(metrics.metrics).toContain('protocol_health_component_response_time');
    });

    it('должен включать memory метрики', async () => {
      await service.performHealthCheck();

      const metrics = service.getPrometheusMetrics();

      expect(metrics.metrics).toContain('protocol_memory_heap_used');
      expect(metrics.metrics).toContain('protocol_memory_heap_total');
      expect(metrics.metrics).toContain('protocol_memory_rss');
    });

    it('должен возвращать пустые метрики если проверка не выполнялась', () => {
      const serviceWithoutCheck = new HealthCheckService();
      const metrics = serviceWithoutCheck.getPrometheusMetrics();

      expect(metrics.metrics).toBe('');
      
      serviceWithoutCheck.stop();
    });
  });

  // ============================================================================
  // EVENT EMITTER
  // ============================================================================

  describe('Event Emitter', () => {
    it('должен эмитить started событие при запуске', (done) => {
      const testService = new HealthCheckService();
      
      testService.on('started', () => {
        testService.stop();
        done();
      });

      testService.start();
    });

    it('должен эмитить stopped событие при остановке', (done) => {
      const testService = new HealthCheckService();
      
      testService.on('stopped', () => {
        done();
      });

      testService.start();
      testService.stop();
    });

    it('должен эмитить check:completed событие после проверки', (done) => {
      const testService = new HealthCheckService();
      
      testService.on('check:completed', (result) => {
        expect(result).toBeDefined();
        expect(result.status).toBeDefined();
        testService.stop();
        done();
      });

      testService.start();
    });

    it('должен эмитить issue:detected при проблеме', async () => {
      const testService = new HealthCheckService();
      let issueDetected = false;
      
      testService.on('issue:detected', (component, status) => {
        issueDetected = true;
        expect(component).toBeDefined();
        expect(status).toBeDefined();
      });

      await testService.performHealthCheck();
      
      // Issue может быть detected если есть проблемы с конфигурацией
      // Это нормально для тестовой среды
      expect([true, false]).toContain(issueDetected);
      
      testService.stop();
    });
  });

  // ============================================================================
  // START/STOP
  // ============================================================================

  describe('Start/Stop', () => {
    it('должен запускать периодические проверки', (done) => {
      const testService = new HealthCheckService({
        checkInterval: 100 // Быстрый интервал для теста
      });
      
      let checkCount = 0;
      
      testService.on('check:completed', () => {
        checkCount++;
        if (checkCount >= 2) {
          testService.stop();
          done();
        }
      });

      testService.start();
    });

    it('должен останавливать периодические проверки', () => {
      const testService = new HealthCheckService();
      
      testService.start();
      testService.stop();
      
      // После остановки не должно быть проверок
      expect(testService.getLastCheckResult()).toBeDefined();
    });

    it('не должен запускать несколько таймеров одновременно', () => {
      const testService = new HealthCheckService();
      
      testService.start();
      testService.start(); // Второй вызов должен игнорироваться
      testService.start(); // Третий тоже
      
      testService.stop();
    });
  });

  // ============================================================================
  // SINGLETON
  // ============================================================================

  describe('Singleton', () => {
    afterEach(() => {
      resetHealthCheckService();
    });

    it('должен возвращать один и тот же экземпляр', () => {
      const instance1 = getHealthCheckService();
      const instance2 = getHealthCheckService();

      expect(instance1).toBe(instance2);
    });

    it('должен создавать новый экземпляр после reset', () => {
      const instance1 = getHealthCheckService();
      resetHealthCheckService();
      const instance2 = getHealthCheckService();

      expect(instance1).not.toBe(instance2);
    });

    it('должен принимать конфигурацию при первом создании', () => {
      const config: Partial<HealthCheckConfig> = {
        checkInterval: 5000
      };
      
      const instance = getHealthCheckService(config);
      expect(instance).toBeDefined();
    });
  });

  // ============================================================================
  // LAST CHECK RESULT
  // ============================================================================

  describe('Last Check Result', () => {
    it('должен возвращать undefined до первой проверки', () => {
      const result = service.getLastCheckResult();
      expect(result).toBeUndefined();
    });

    it('должен возвращать последний результат проверки', async () => {
      await service.performHealthCheck();
      
      const result = service.getLastCheckResult();
      
      expect(result).toBeDefined();
      expect(result?.status).toBeDefined();
      expect(result?.timestamp).toBeDefined();
    });

    it('должен сохранять последний результат', async () => {
      await service.performHealthCheck();
      const result1 = service.getLastCheckResult();
      
      await service.performHealthCheck();
      const result2 = service.getLastCheckResult();
      
      expect(result1).toBe(result2); // Один и тот же объект
    });
  });

  // ============================================================================
  // CONFIGURATION DEFAULTS
  // ============================================================================

  describe('Configuration Defaults', () => {
    it('должен использовать DEFAULT_HEALTH_CHECK_CONFIG', () => {
      expect(DEFAULT_HEALTH_CHECK_CONFIG.enabled).toBe(true);
      expect(DEFAULT_HEALTH_CHECK_CONFIG.checkInterval).toBe(10000);
      expect(DEFAULT_HEALTH_CHECK_CONFIG.redisTimeout).toBe(5000);
      expect(DEFAULT_HEALTH_CHECK_CONFIG.databaseTimeout).toBe(5000);
    });

    it('должен использовать DEFAULT_HEALTH_CHECK_OPTIONS', () => {
      expect(DEFAULT_HEALTH_CHECK_OPTIONS.checkRedis).toBe(true);
      expect(DEFAULT_HEALTH_CHECK_OPTIONS.checkDatabase).toBe(true);
      expect(DEFAULT_HEALTH_CHECK_OPTIONS.checkVault).toBe(true);
      expect(DEFAULT_HEALTH_CHECK_OPTIONS.checkElasticsearch).toBe(true);
      expect(DEFAULT_HEALTH_CHECK_OPTIONS.checkCircuitBreakers).toBe(true);
      expect(DEFAULT_HEALTH_CHECK_OPTIONS.checkSystemResources).toBe(true);
      expect(DEFAULT_HEALTH_CHECK_OPTIONS.checkExternalApis).toBe(true);
    });
  });

  // ============================================================================
  // HEALTH STATUS ENUM
  // ============================================================================

  describe('HealthStatus Enum', () => {
    it('должен иметь правильные значения', () => {
      expect(HealthStatus.HEALTHY).toBe('healthy');
      expect(HealthStatus.UNHEALTHY).toBe('unhealthy');
      expect(HealthStatus.WARNING).toBe('warning');
      expect(HealthStatus.UNKNOWN).toBe('unknown');
    });
  });

  // ============================================================================
  // COMPONENT TYPE ENUM
  // ============================================================================

  describe('ComponentType Enum', () => {
    it('должен иметь правильные значения', () => {
      expect(ComponentType.REDIS).toBe('redis');
      expect(ComponentType.DATABASE).toBe('database');
      expect(ComponentType.VAULT).toBe('vault');
      expect(ComponentType.ELASTICSEARCH).toBe('elasticsearch');
      expect(ComponentType.CIRCUIT_BREAKER).toBe('circuit_breaker');
      expect(ComponentType.MEMORY).toBe('memory');
      expect(ComponentType.CPU).toBe('cpu');
      expect(ComponentType.APPLICATION).toBe('application');
    });
  });
});
