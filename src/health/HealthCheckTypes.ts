/**
 * ============================================================================
 * HEALTH CHECK TYPES - ТИПЫ И ИНТЕРФЕЙСЫ
 * ============================================================================
 * Типы для системы проверки здоровья сервисов
 * 
 * @author Theodor Munch
 * @version 1.0.0
 */

/**
 * Статусы компонента
 */
export enum HealthStatus {
  /** Компонент здоров */
  HEALTHY = 'healthy',
  /** Компонент нездоров */
  UNHEALTHY = 'unhealthy',
  /** Компонент в предупреждении */
  WARNING = 'warning',
  /** Статус неизвестен */
  UNKNOWN = 'unknown'
}

/**
 * Типы компонентов
 */
export enum ComponentType {
  /** Redis */
  REDIS = 'redis',
  /** Database */
  DATABASE = 'database',
  /** Vault */
  VAULT = 'vault',
  /** Elasticsearch */
  ELASTICSEARCH = 'elasticsearch',
  /** External API */
  EXTERNAL_API = 'external_api',
  /** Circuit Breaker */
  CIRCUIT_BREAKER = 'circuit_breaker',
  /** Memory */
  MEMORY = 'memory',
  /** CPU */
  CPU = 'cpu',
  /** Disk */
  DISK = 'disk',
  /** Network */
  NETWORK = 'network',
  /** Application */
  APPLICATION = 'application'
}

/**
 * Статус отдельного компонента
 */
export interface ComponentHealthStatus {
  /** Название компонента */
  name: string;
  
  /** Тип компонента */
  type: ComponentType;
  
  /** Статус здоровья */
  status: HealthStatus;
  
  /** Время ответа (ms) */
  responseTime?: number;
  
  /** Сообщение об ошибке */
  error?: string;
  
  /** Детали статуса */
  details?: Record<string, unknown>;
  
  /** Timestamp проверки */
  timestamp: Date;
}

/**
 * Конфигурация health check
 */
export interface HealthCheckConfig {
  /** Включить health checks */
  enabled: boolean;
  
  /** Интервал проверки (ms) */
  checkInterval: number;
  
  /** Таймаут проверки Redis (ms) */
  redisTimeout: number;
  
  /** Таймаут проверки Database (ms) */
  databaseTimeout: number;
  
  /** Таймаут проверки Vault (ms) */
  vaultTimeout: number;
  
  /** Таймаут проверки Elasticsearch (ms) */
  elasticsearchTimeout: number;
  
  /** Таймаут проверки external API (ms) */
  externalApiTimeout: number;
  
  /** Порог memory warning (%) */
  memoryWarningThreshold: number;
  
  /** Порог memory critical (%) */
  memoryCriticalThreshold: number;
  
  /** Порог CPU warning (%) */
  cpuWarningThreshold: number;
  
  /** Порог CPU critical (%) */
  cpuCriticalThreshold: number;
  
  /** Порог disk warning (%) */
  diskWarningThreshold: number;
  
  /** Порог disk critical (%) */
  diskCriticalThreshold: number;
  
  /** Включить Prometheus metrics */
  enablePrometheus: boolean;
  
  /** Порт Prometheus metrics */
  prometheusPort: number;
}

/**
 * Конфигурация по умолчанию
 */
export const DEFAULT_HEALTH_CHECK_CONFIG: HealthCheckConfig = {
  enabled: true,
  checkInterval: 10000,
  redisTimeout: 5000,
  databaseTimeout: 5000,
  vaultTimeout: 5000,
  elasticsearchTimeout: 5000,
  externalApiTimeout: 5000,
  memoryWarningThreshold: 80,
  memoryCriticalThreshold: 95,
  cpuWarningThreshold: 70,
  cpuCriticalThreshold: 90,
  diskWarningThreshold: 80,
  diskCriticalThreshold: 95,
  enablePrometheus: true,
  prometheusPort: 9090
};

/**
 * Общий статус health check
 */
export interface HealthCheckResult {
  /** Общий статус */
  status: HealthStatus;
  
  /** Timestamp */
  timestamp: Date;
  
  /** Uptime процесса (seconds) */
  uptime: number;
  
  /** Версия приложения */
  version: string;
  
  /** Окружение */
  environment: string;
  
  /** Статусы компонентов */
  components: Record<string, ComponentHealthStatus>;
  
  /** Сводная статистика */
  summary: {
    /** Всего компонентов */
    total: number;
    /** Здоровых компонентов */
    healthy: number;
    /** Компонентов с warning */
    warning: number;
    /** Нездоровых компонентов */
    unhealthy: number;
    /** Компонентов с неизвестным статусом */
    unknown: number;
  };
}

/**
 * Prometheus metrics формат
 */
export interface PrometheusMetrics {
  /** Метрики в формате Prometheus text */
  metrics: string;
  
  /** Content-Type */
  contentType: string;
}

/**
 * Circuit Breaker статус для health check
 */
export interface CircuitBreakerHealthStatus {
  /** Название circuit breaker */
  name: string;
  
  /** Текущее состояние */
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  
  /** Доступен ли */
  available: boolean;
  
  /** Количество failures */
  failures: number;
  
  /** Количество successes */
  successes: number;
  
  /** Всего запросов */
  totalRequests: number;
}

/**
 * Статистика Circuit Breaker (для Prometheus)
 */
export interface CircuitBreakerStatsExtended {
  /** Название circuit breaker */
  name: string;
  
  /** Текущее состояние */
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  
  /** Доступен ли */
  available: boolean;
  
  /** Количество failures */
  failures: number;
  
  /** Количество successes */
  successes: number;
  
  /** Всего запросов */
  totalRequests: number;
  
  /** Всего failures */
  totalFailures: number;
  
  /** Всего successes */
  totalSuccesses: number;
}

/**
 * Redis статус для health check
 */
export interface RedisHealthStatus {
  /** Подключен ли */
  connected: boolean;
  
  /** Время ответа (ms) */
  responseTime: number;
  
  /** Информация о Redis */
  info?: {
    /** Использовано памяти */
    usedMemory?: string;
    /** Подключено клиентов */
    connectedClients?: number;
    /** Версия Redis */
    redisVersion?: string;
    /** Uptime (seconds) */
    uptimeInSeconds?: number;
  };
}

/**
 * Database статус для health check
 */
export interface DatabaseHealthStatus {
  /** Подключен ли */
  connected: boolean;
  
  /** Время ответа (ms) */
  responseTime: number;
  
  /** Информация о БД */
  info?: {
    /** Название БД */
    database?: string;
    /** Версия */
    version?: string;
    /** Активные подключения */
    activeConnections?: number;
    /** Максимум подключений */
    maxConnections?: number;
  };
}

/**
 * External API статус для health check
 */
export interface ExternalApiHealthStatus {
  /** Название API */
  name: string;
  
  /** URL */
  url: string;
  
  /** Доступен ли */
  available: boolean;
  
  /** Статус код */
  statusCode?: number;
  
  /** Время ответа (ms) */
  responseTime: number;
  
  /** Сообщение об ошибке */
  error?: string;
}

/**
 * Memory статус для health check
 */
export interface MemoryHealthStatus {
  /** Использовано памяти (bytes) */
  heapUsed: number;
  
  /** Всего памяти (bytes) */
  heapTotal: number;
  
  /** RSS (bytes) */
  rss: number;
  
  /** External (bytes) */
  external: number;
  
  /** Процент использования */
  usagePercent: number;
  
  /** Статус */
  status: HealthStatus;
}

/**
 * CPU статус для health check
 */
export interface CPUHealthStatus {
  /** Процент использования */
  usage: number;
  
  /** Load average */
  loadAverage: [number, number, number];
  
  /** Количество ядер */
  cores: number;
  
  /** Статус */
  status: HealthStatus;
}

/**
 * Опции для индивидуальной проверки
 */
export interface HealthCheckOptions {
  /** Проверять Redis */
  checkRedis: boolean;
  
  /** Проверять Database */
  checkDatabase: boolean;
  
  /** Проверять Vault */
  checkVault: boolean;
  
  /** Проверять Elasticsearch */
  checkElasticsearch: boolean;
  
  /** Проверять circuit breakers */
  checkCircuitBreakers: boolean;
  
  /** Проверять memory/CPU */
  checkSystemResources: boolean;
  
  /** Проверять external APIs */
  checkExternalApis: boolean;
}

/**
 * Опции по умолчанию
 */
export const DEFAULT_HEALTH_CHECK_OPTIONS: HealthCheckOptions = {
  checkRedis: true,
  checkDatabase: true,
  checkVault: true,
  checkElasticsearch: true,
  checkCircuitBreakers: true,
  checkSystemResources: true,
  checkExternalApis: true
};

/**
 * События health check service
 */
export interface HealthCheckEvents {
  /** Health check завершен */
  'check:completed': (result: HealthCheckResult) => void;
  
  /** Обнаружена проблема */
  'issue:detected': (component: string, status: ComponentHealthStatus) => void;
  
  /** Компонент восстановлен */
  'component:recovered': (component: string) => void;
  
  /** Сервис запущен */
  'started': () => void;
  
  /** Сервис остановлен */
  'stopped': () => void;
}
