/**
 * ============================================================================
 * BENCHMARK TYPES — ТИПЫ ДЛЯ СИСТЕМЫ ПРОИЗВОДИТЕЛЬНОСТИ
 * ============================================================================
 *
 * Определяет все интерфейсы и типы для системы benchmarks:
 * - Результаты单个 benchmark
 * - Сводные результаты по группе
 * - Конфигурация runner
 * - Пороговые значения (thresholds)
 * - Форматы экспорта (JSON, CLI table)
 */

/**
 * Результат выполнения одного benchmark
 */
export interface BenchmarkResult {
  /** Название benchmark */
  name: string;
  /** Категория (crypto, auth, secrets, logging, threat) */
  category: BenchmarkCategory;
  /** Количество итераций */
  iterations: number;
  /** Минимальное время (ms) */
  min: number;
  /** Максимальное время (ms) */
  max: number;
  /** Среднее время (ms) */
  mean: number;
  /** Медиана / p50 (ms) */
  median: number;
  /** 95-й перцентиль (ms) */
  p95: number;
  /** 99-й перцентиль (ms) */
  p99: number;
  /** Стандартное отклонение (ms) */
  stdDev: number;
  /** Операций в секунду */
  opsPerSec: number;
  /** Delta использования heap (MB) */
  memoryDeltaMB: number;
  /** Пороговое значение (ms) */
  threshold: number;
  /** Пройден ли threshold */
  passed: boolean;
  /** Время выполнения benchmark (ms) */
  totalDuration: number;
  /** Timestamp запуска */
  timestamp: string;
}

/**
 * Категории benchmarks
 */
export type BenchmarkCategory = 'crypto' | 'auth' | 'secrets' | 'logging' | 'threat';

/**
 * Сводные результаты по категории
 */
export interface CategoryResults {
  /** Категория */
  category: BenchmarkCategory;
  /** Массив результатов */
  results: BenchmarkResult[];
  /** Общее количество операций */
  totalOps: number;
  /** Средняя ops/sec по категории */
  avgOpsPerSec: number;
  /** Все thresholds пройдены? */
  allPassed: boolean;
  /** Время выполнения категории (ms) */
  totalDuration: number;
}

/**
 * Полный отчёт по всем benchmarks
 */
export interface BenchmarkReport {
  /** Timestamp запуска */
  timestamp: string;
  /** Общая длительность (ms) */
  totalDuration: number;
  /** Результаты по категориям */
  categories: CategoryResults[];
  /** Все результаты плоским списком */
  allResults: BenchmarkResult[];
  /** Общий итог — все прошли? */
  allPassed: boolean;
  /** Количество пройденных */
  passedCount: number;
  /** Количество проваленных */
  failedCount: number;
  /** Суммарный ops/sec */
  totalOpsPerSec: number;
  /** Метаданные окружения */
  environment: EnvironmentInfo;
}

/**
 * Информация об окружении
 */
export interface EnvironmentInfo {
  /** Node.js версия */
  nodeVersion: string;
  /** Платформа */
  platform: string;
  /** Архитектура */
  arch: string;
  /** CPU cores */
  cpuCount: number;
  /** CPU model */
  cpuModel: string;
  /** Total memory (GB) */
  totalMemoryGB: number;
  /** Hostname */
  hostname: string;
}

/**
 * Конфигурация запуска одного benchmark
 */
export interface BenchmarkConfig {
  /** Название */
  name: string;
  /** Категория */
  category: BenchmarkCategory;
  /** Количество итераций */
  iterations: number;
  /** Порог (ms) */
  thresholdMs: number;
  /** Warmup итерации (не замеряются) */
  warmupIterations?: number;
  /** Отключить замер памяти */
  skipMemoryCheck?: boolean;
}

/**
 * Функция benchmark — выполняемая операция
 */
export type BenchmarkFn = () => void | Promise<void>;

/**
 * Опции BenchmarkRunner
 */
export interface RunnerOptions {
  /** Дефолтное количество итераций */
  defaultIterations?: number;
  /** Дефолтные warmup итерации */
  defaultWarmup?: number;
  /** Выводить ли прогресс в консоль */
  verbose?: boolean;
  /** Формат вывода */
  outputFormat?: 'table' | 'json' | 'both';
}

/**
 * Пороговые значения по умолчанию
 */
export const DEFAULT_THRESHOLDS: Record<string, number> = {
  // Crypto
  'AES-256-GCM Encrypt': 1,
  'AES-256-GCM Decrypt': 1,
  'HMAC-SHA256': 0.5,
  'SHA-256 Hash': 0.5,
  'Kyber Encapsulate': 5,
  'Kyber Decapsulate': 5,
  'Dilithium Sign': 10,
  'Dilithium Verify': 10,
  'Key Generation (AES-256)': 5,

  // Auth
  'JWT Generate (RS256)': 5,
  'JWT Verify (RS256)': 5,
  'Password Hash (Argon2id)': 500,
  'Password Verify (Argon2id)': 500,
  'Password Hash (bcrypt)': 500,
  'Password Verify (bcrypt)': 500,
  'MFA TOTP Generate': 2,
  'MFA TOTP Verify': 2,
  'Session Create': 5,

  // Secrets
  'Secret Read': 10,
  'Secret Write': 20,
  'Secret Cache Hit': 1,
  'Secret Rotation': 50,

  // Logging
  'Log Write (sync)': 2,
  'Log Write (async)': 5,
  'Log Throughput (1000 logs)': 100,

  // Threat Detection
  'ML Inference': 50,
  'Event Processing': 20,
  'Correlation Engine': 10,
  'Risk Scoring': 5,
};

/**
 * Утилиты для percentiles
 */
export function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

/**
 * Среднее значение
 */
export function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

/**
 * Стандартное отклонение
 */
export function stdDev(values: number[]): number {
  if (values.length <= 1) return 0;
  const avg = mean(values);
  const squareDiffs = values.map(v => Math.pow(v - avg, 2));
  return Math.sqrt(mean(squareDiffs));
}

/**
 * Форматирование времени
 */
export function formatTime(ms: number): string {
  if (ms < 0.001) return `${(ms * 1000000).toFixed(0)}ns`;
  if (ms < 1) return `${(ms * 1000).toFixed(2)}µs`;
  if (ms < 1000) return `${ms.toFixed(2)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

/**
 * Форматирование ops/sec
 */
export function formatOps(ops: number): string {
  if (ops >= 1_000_000) return `${(ops / 1_000_000).toFixed(1)}M ops/sec`;
  if (ops >= 1_000) return `${(ops / 1_000).toFixed(1)}K ops/sec`;
  return `${ops.toFixed(0)} ops/sec`;
}

/**
 * Получить информацию об окружении
 */
export function getEnvironmentInfo(): EnvironmentInfo {
  const os = require('os');
  return {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cpuCount: os.cpus().length,
    cpuModel: os.cpus()[0]?.model || 'Unknown',
    totalMemoryGB: Math.round(os.totalmem() / (1024 ** 3)),
    hostname: os.hostname(),
  };
}
