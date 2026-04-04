/**
 * ============================================================================
 * SECRETS BENCHMARKS — ТЕСТЫ ПРОИЗВОДИТЕЛЬНОСТИ УПРАВЛЕНИЯ СЕКРЕТАМИ
 * ============================================================================
 *
 * Измеряет производительность:
 * - Secret Read (in-memory cache simulation)
 * - Secret Write (in-memory cache simulation)
 * - Secret Cache Hit
 * - Secret Rotation (HMAC-based)
 *
 * Поскольку реальные бэкенды (Vault, AWS, Azure, GCP) недоступны в benchmark mode,
 * используем in-memory симуляцию с HMAC signing для реалистичности.
 */

import * as crypto from 'crypto';
import { BenchmarkRunner } from './BenchmarkRunner';
import { BenchmarkResult, DEFAULT_THRESHOLDS } from './types';

/**
 * In-memory хранилище секретов для benchmark
 */
interface SecretEntry {
  id: string;
  value: string;
  version: number;
  createdAt: number;
  updatedAt: number;
  signature: string;
}

class InMemorySecretStore {
  private store: Map<string, SecretEntry> = new Map();
  private cache: Map<string, SecretEntry> = new Map();
  private readonly hmacKey: Buffer;

  constructor() {
    this.hmacKey = crypto.randomBytes(32);
  }

  /**
   * Подписать секрет
   */
  private sign(data: string): string {
    return crypto.createHmac('sha256', this.hmacKey).update(data).digest('hex');
  }

  /**
   * Записать секрет
   */
  write(id: string, value: string): SecretEntry {
    const data = `${id}:${value}:${Date.now()}`;
    const entry: SecretEntry = {
      id,
      value,
      version: (this.store.get(id)?.version ?? 0) + 1,
      createdAt: this.store.get(id)?.createdAt ?? Date.now(),
      updatedAt: Date.now(),
      signature: this.sign(data),
    };
    this.store.set(id, entry);
    return entry;
  }

  /**
   * Прочитать секрет (с cache)
   */
  read(id: string): SecretEntry | null {
    // Cache check
    const cached = this.cache.get(id);
    if (cached) {
      return cached;
    }
    // Store lookup
    const entry = this.store.get(id);
    if (entry) {
      this.cache.set(id, entry);
    }
    return entry ?? null;
  }

  /**
   * Прочитать секрет (без cache — принудительный miss)
   */
  readNoCache(id: string): SecretEntry | null {
    return this.store.get(id) ?? null;
  }

  /**
   * Очистить cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Ротация секрета
   */
  rotate(id: string): SecretEntry {
    const existing = this.store.get(id);
    const newValue = crypto.randomBytes(32).toString('hex');
    return this.write(id, existing ? `${existing.value}:rotated` : newValue);
  }
}

/**
 * Запуск всех secrets benchmarks
 */
export async function runSecretsBenchmarks(runner: BenchmarkRunner, iterations?: number): Promise<BenchmarkResult[]> {
  const results: BenchmarkResult[] = [];
  const iters = iterations ?? 1000;

  const store = new InMemorySecretStore();

  // Pre-populate secrets
  for (let i = 0; i < 100; i++) {
    store.write(`secret-${i}`, crypto.randomBytes(64).toString('hex'));
  }

  // ========================================================================
  // SECRET READ (без cache — cache miss каждый раз)
  // ========================================================================
  let readIdx = 0;
  const secretReadResult = await runner.run(
    'Secret Read',
    () => {
      store.clearCache();
      store.readNoCache(`secret-${readIdx % 100}`);
      readIdx++;
    },
    iters,
    DEFAULT_THRESHOLDS['Secret Read']
  );
  (secretReadResult as any).category = 'secrets';
  runner.setLastCategory('secrets');
  results.push(secretReadResult);

  // ========================================================================
  // SECRET WRITE
  // ========================================================================
  let writeIdx = 100;
  const secretWriteResult = await runner.run(
    'Secret Write',
    () => {
      store.write(`new-secret-${writeIdx}`, crypto.randomBytes(64).toString('hex'));
      writeIdx++;
    },
    iters,
    DEFAULT_THRESHOLDS['Secret Write']
  );
  (secretWriteResult as any).category = 'secrets';
  runner.setLastCategory('secrets');
  results.push(secretWriteResult);

  // ========================================================================
  // SECRET CACHE HIT
  // ========================================================================
  // Fill cache
  for (let i = 0; i < 50; i++) {
    store.read(`secret-${i}`);
  }

  let cacheIdx = 0;
  const secretCacheResult = await runner.run(
    'Secret Cache Hit',
    () => {
      store.read(`secret-${cacheIdx % 50}`);
      cacheIdx++;
    },
    iters,
    DEFAULT_THRESHOLDS['Secret Cache Hit']
  );
  (secretCacheResult as any).category = 'secrets';
  runner.setLastCategory('secrets');
  results.push(secretCacheResult);

  // ========================================================================
  // SECRET ROTATION
  // ========================================================================
  // Подготовим секреты для ротации
  for (let i = 0; i < Math.min(iters, 50); i++) {
    store.write(`rotate-secret-${i}`, crypto.randomBytes(32).toString('hex'));
  }

  let rotateIdx = 0;
  const secretRotationResult = await runner.run(
    'Secret Rotation',
    () => {
      store.rotate(`rotate-secret-${rotateIdx % 50}`);
      rotateIdx++;
    },
    Math.min(iters, 50), // rotation тяжелее — меньше итераций
    DEFAULT_THRESHOLDS['Secret Rotation']
  );
  (secretRotationResult as any).category = 'secrets';
  runner.setLastCategory('secrets');
  results.push(secretRotationResult);

  return results;
}
