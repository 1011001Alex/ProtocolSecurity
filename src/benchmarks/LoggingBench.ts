/**
 * ============================================================================
 * LOGGING BENCHMARKS — ТЕСТЫ ПРОИЗВОДИТЕЛЬНОСТИ ЛОГИРОВАНИЯ
 * ============================================================================
 *
 * Измеряет производительность:
 * - Log Write (sync) — синхронная запись
 * - Log Write (async) — асинхронная запись
 * - Log Throughput — пропускная способность (1000 logs)
 *
 * Симулирует структурированное логирование с JSON serialization,
 * HMAC signing для tamper-proof, и записью в memory buffer.
 */

import * as crypto from 'crypto';
import { BenchmarkRunner } from './BenchmarkRunner';
import { BenchmarkResult, DEFAULT_THRESHOLDS } from './types';

/**
 * In-memory логгер для benchmark
 */
class InMemoryLogger {
  private logs: string[] = [];
  private readonly hmacKey: Buffer;
  private readonly component: string;
  private readonly hostname: string;

  constructor(component: string = 'BenchmarkLogger') {
    this.hmacKey = crypto.randomBytes(32);
    this.component = component;
    this.hostname = 'benchmark-host';
  }

  /**
   * Синхронная запись лога
   */
  logSync(level: string, message: string, context?: Record<string, unknown>): string {
    const entry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      level,
      component: this.component,
      hostname: this.hostname,
      message,
      context: context ?? {},
    };

    const jsonLine = JSON.stringify(entry);
    const signature = crypto.createHmac('sha256', this.hmacKey).update(jsonLine).digest('hex');
    const signedLine = `${jsonLine}|sig:${signature}`;

    this.logs.push(signedLine);
    return signedLine;
  }

  /**
   * Асинхронная запись лога (с эмуляцией I/O задержки)
   */
  async logAsync(level: string, message: string, context?: Record<string, unknown>): Promise<string> {
    const entry = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      level,
      component: this.component,
      hostname: this.hostname,
      message,
      context: context ?? {},
    };

    const jsonLine = JSON.stringify(entry);
    const signature = crypto.createHmac('sha256', this.hmacKey).update(jsonLine).digest('hex');
    const signedLine = `${jsonLine}|sig:${signature}`;

    // Эмуляция асинхронной задержки записи (очень маленькая)
    await Promise.resolve();

    this.logs.push(signedLine);
    return signedLine;
  }

  /**
   * Получить количество записанных логов
   */
  getLogCount(): number {
    return this.logs.length;
  }

  /**
   * Очистить логи
   */
  clear(): void {
    this.logs = [];
  }
}

/**
 * Benchmark данные для контекста
 */
const BENCHMARK_LOG_CONTEXTS = [
  { userId: 'user-001', requestId: 'req-abc-123', action: 'login' },
  { userId: 'user-042', requestId: 'req-def-456', action: 'read_secret', secretId: 'db-password' },
  { userId: 'user-099', requestId: 'req-ghi-789', action: 'encrypt_data', algorithm: 'AES-256-GCM' },
  { userId: 'admin', requestId: 'req-jkl-012', action: 'rotate_key', keyId: 'master-key' },
  { sourceIp: '192.168.1.100', action: 'threat_detected', severity: 'high', category: 'brute_force' },
];

const BENCHMARK_MESSAGES = [
  'User authentication successful',
  'Secret accessed: db-connection-string',
  'Data encrypted with AES-256-GCM',
  'Key rotation initiated for master-key',
  'Threat detected: brute force attempt from 192.168.1.100',
  'Session created for user admin',
  'API request processed in 45ms',
  'Certificate expiry check: 30 days remaining',
  'RBAC policy evaluation: access granted',
  'Audit log entry: configuration changed',
];

/**
 * Запуск всех logging benchmarks
 */
export async function runLoggingBenchmarks(runner: BenchmarkRunner, iterations?: number): Promise<BenchmarkResult[]> {
  const results: BenchmarkResult[] = [];
  const iters = iterations ?? 1000;

  const logger = new InMemoryLogger('ProtocolSecurity');

  // ========================================================================
  // LOG WRITE (SYNC)
  // ========================================================================
  let syncIdx = 0;
  const logSyncResult = await runner.run(
    'Log Write (sync)',
    () => {
      const msgIdx = syncIdx % BENCHMARK_MESSAGES.length;
      const ctxIdx = syncIdx % BENCHMARK_LOG_CONTEXTS.length;
      logger.logSync(
        'INFO',
        BENCHMARK_MESSAGES[msgIdx],
        BENCHMARK_LOG_CONTEXTS[ctxIdx] as Record<string, unknown>
      );
      syncIdx++;
    },
    iters,
    DEFAULT_THRESHOLDS['Log Write (sync)']
  );
  (logSyncResult as any).category = 'logging';
  runner.setLastCategory('logging');
  results.push(logSyncResult);

  // ========================================================================
  // LOG WRITE (ASYNC)
  // ========================================================================
  logger.clear();
  let asyncIdx = 0;
  const logAsyncResult = await runner.run(
    'Log Write (async)',
    async () => {
      const msgIdx = asyncIdx % BENCHMARK_MESSAGES.length;
      const ctxIdx = asyncIdx % BENCHMARK_LOG_CONTEXTS.length;
      await logger.logAsync(
        'WARNING',
        BENCHMARK_MESSAGES[msgIdx],
        BENCHMARK_LOG_CONTEXTS[ctxIdx] as Record<string, unknown>
      );
      asyncIdx++;
    },
    iters,
    DEFAULT_THRESHOLDS['Log Write (async)']
  );
  (logAsyncResult as any).category = 'logging';
  runner.setLastCategory('logging');
  results.push(logAsyncResult);

  // ========================================================================
  // LOG THROUGHPUT (1000 logs batch)
  // ========================================================================
  logger.clear();
  const batchSize = 1000;
  let throughputIdx = 0;
  const logThroughputResult = await runner.run(
    'Log Throughput (1000 logs)',
    () => {
      for (let i = 0; i < batchSize; i++) {
        const msgIdx = (throughputIdx + i) % BENCHMARK_MESSAGES.length;
        const ctxIdx = (throughputIdx + i) % BENCHMARK_LOG_CONTEXTS.length;
        logger.logSync(
          'DEBUG',
          BENCHMARK_MESSAGES[msgIdx],
          BENCHMARK_LOG_CONTEXTS[ctxIdx] as Record<string, unknown>
        );
      }
      throughputIdx += batchSize;
    },
    Math.max(1, Math.floor(iters / 10)), // Меньше итераций т.к. каждая = 1000 логов
    DEFAULT_THRESHOLDS['Log Throughput (1000 logs)']
  );
  (logThroughputResult as any).category = 'logging';
  runner.setLastCategory('logging');
  results.push(logThroughputResult);

  return results;
}
