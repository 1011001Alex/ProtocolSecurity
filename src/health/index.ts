/**
 * ============================================================================
 * HEALTH CHECK MODULE - ЭКСПОРТ МОДУЛЕЙ
 * ============================================================================
 * Центральный файл экспорта для системы health check
 *
 * @author Theodor Munch
 * @version 1.0.0
 */

export {
  HealthCheckService,
  getHealthCheckService,
  resetHealthCheckService
} from './HealthCheckService';

export type {
  HealthCheckConfig,
  HealthCheckResult,
  ComponentHealthStatus,
  PrometheusMetrics,
  CircuitBreakerHealthStatus,
  RedisHealthStatus,
  DatabaseHealthStatus,
  ExternalApiHealthStatus,
  MemoryHealthStatus,
  CPUHealthStatus,
  HealthCheckOptions
} from './HealthCheckTypes';

export {
  HealthStatus,
  ComponentType,
  DEFAULT_HEALTH_CHECK_CONFIG,
  DEFAULT_HEALTH_CHECK_OPTIONS
} from './HealthCheckTypes';
