/**
 * ============================================================================
 * BENCHMARK RUNNER — ОСНОВНОЙ ЗАПУСКАТЕЛЬ BENCHMARKS
 * ============================================================================
 *
 * Высокопроизводительный runner для benchmarks:
 * - Точные замеры через process.hrtime.bigint()
 * - Замер памяти через process.memoryUsage()
 * - Расчет percentiles (p50, p95, p99)
 * - Расчет ops/sec
 * - Проверка thresholds
 * - Форматированный вывод в table
 * - Экспорт в JSON для CI/CD
 * - Warmup итерации для стабилизации
 *
 * ВАЖНО: НИКАКОГО console.log ВНУТРИ benchmark loop — искажает результаты!
 */

import {
  BenchmarkResult,
  BenchmarkCategory,
  CategoryResults,
  BenchmarkReport,
  BenchmarkConfig,
  BenchmarkFn,
  RunnerOptions,
  EnvironmentInfo,
  percentile,
  mean,
  stdDev,
  formatTime,
  formatOps,
  getEnvironmentInfo,
} from './types';

/**
 * Основной класс для запуска benchmarks
 */
export class BenchmarkRunner {
  /** Все результаты */
  private results: BenchmarkResult[] = [];

  /** Опции runner */
  private options: Required<RunnerOptions>;

  /** Информация об окружении */
  private environment: EnvironmentInfo;

  /** Время старта всего прогона */
  private globalStartTime: bigint | null = null;

  constructor(options?: RunnerOptions) {
    this.options = {
      defaultIterations: options?.defaultIterations ?? 1000,
      defaultWarmup: options?.defaultWarmup ?? 10,
      verbose: options?.verbose ?? true,
      outputFormat: options?.outputFormat ?? 'both',
    };
    this.environment = getEnvironmentInfo();
  }

  /**
   * Запустить один benchmark
   *
   * @param name — Название benchmark
   * @param fn — Выполняемая функция
   * @param iterations — Количество итераций
   * @param thresholdMs — Порог (ms)
   * @param warmupIterations — Warmup итерации
   */
  async run(
    name: string,
    fn: BenchmarkFn,
    iterations?: number,
    thresholdMs?: number,
    warmupIterations?: number
  ): Promise<BenchmarkResult> {
    const actualIterations = iterations ?? this.options.defaultIterations;
    const actualWarmup = warmupIterations ?? this.options.defaultWarmup;
    const threshold = thresholdMs ?? 100; // fallback 100ms

    if (this.options.verbose) {
      process.stdout.write(`  Running: ${name} (${actualIterations} iters)...`);
    }

    // Warmup — прогрев JIT / V8
    for (let i = 0; i < actualWarmup; i++) {
      await fn();
    }

    // GC перед замером для чистоты
    if (global.gc) {
      global.gc();
    }

    // Замер памяти до
    const memBefore = process.memoryUsage().heapUsed;

    // Основной замер
    const latencies: number[] = [];
    const totalStart = process.hrtime.bigint();

    for (let i = 0; i < actualIterations; i++) {
      const iterStart = process.hrtime.bigint();
      await fn();
      const iterEnd = process.hrtime.bigint();
      // Конвертируем в миллисекунды
      latencies.push(Number(iterEnd - iterStart) / 1_000_000);
    }

    const totalEnd = process.hrtime.bigint();
    const totalDurationMs = Number(totalEnd - totalStart) / 1_000_000;

    // Замер памяти после
    const memAfter = process.memoryUsage().heapUsed;
    const memoryDeltaMB = (memAfter - memBefore) / (1024 * 1024);

    // Сортируем для percentiles
    latencies.sort((a, b) => a - b);

    const min = latencies[0] ?? 0;
    const max = latencies[latencies.length - 1] ?? 0;
    const meanVal = mean(latencies);
    const medianVal = percentile(latencies, 50);
    const p95 = percentile(latencies, 95);
    const p99 = percentile(latencies, 99);
    const stdDevVal = stdDev(latencies);

    // ops/sec = iterations / totalSeconds
    const opsPerSec = actualIterations / (totalDurationMs / 1000);

    const passed = medianVal <= threshold;

    const result: BenchmarkResult = {
      name,
      category: 'crypto', // будет перезаписан benchmark классами
      iterations: actualIterations,
      min,
      max,
      mean: meanVal,
      median: medianVal,
      p95,
      p99,
      stdDev: stdDevVal,
      opsPerSec,
      memoryDeltaMB,
      threshold,
      passed,
      totalDuration: totalDurationMs,
      timestamp: new Date().toISOString(),
    };

    this.results.push(result);

    if (this.options.verbose) {
      const status = passed ? '✓' : '✗';
      process.stdout.write(` ${status} ${formatTime(medianVal)} | ${formatOps(opsPerSec)}\n`);
    }

    return result;
  }

  /**
   * Установить категорию для последнего результата
   */
  setLastCategory(category: BenchmarkCategory): void {
    if (this.results.length > 0) {
      this.results[this.results.length - 1].category = category;
    }
  }

  /**
   * Получить результаты по категории
   */
  getCategoryResults(category: BenchmarkCategory): CategoryResults {
    const results = this.results.filter(r => r.category === category);
    const totalOps = results.reduce((s, r) => s + r.opsPerSec, 0);
    const allPassed = results.every(r => r.passed);
    const totalDuration = results.reduce((s, r) => s + r.totalDuration, 0);

    return {
      category,
      results,
      totalOps,
      avgOpsPerSec: results.length > 0 ? totalOps / results.length : 0,
      allPassed,
      totalDuration,
    };
  }

  /**
   * Получить полный отчёт
   */
  getReport(): BenchmarkReport {
    const categories: BenchmarkCategory[] = ['crypto', 'auth', 'secrets', 'logging', 'threat'];
    const categoryResults = categories.map(c => this.getCategoryResults(c));

    const allResults = this.results;
    const passedCount = allResults.filter(r => r.passed).length;
    const failedCount = allResults.filter(r => !r.passed).length;
    const totalOpsPerSec = allResults.reduce((s, r) => s + r.opsPerSec, 0);

    // Глобальный таймер
    const globalDuration = allResults.reduce((s, r) => s + r.totalDuration, 0);

    return {
      timestamp: new Date().toISOString(),
      totalDuration: globalDuration,
      categories: categoryResults,
      allResults,
      allPassed: failedCount === 0,
      passedCount,
      failedCount,
      totalOpsPerSec,
      environment: this.environment,
    };
  }

  /**
   * Очистить результаты
   */
  clear(): void {
    this.results = [];
  }

  /**
   * Экспорт в JSON
   */
  exportJSON(): string {
    const report = this.getReport();
    return JSON.stringify(report, null, 2);
  }

  /**
   * Печать результатов в таблицу
   */
  printResults(): void {
    const report = this.getReport();

    this.printHeader();

    for (const cat of report.categories) {
      if (cat.results.length === 0) continue;
      this.printCategoryTable(cat);
    }

    this.printSummary(report);
  }

  /**
   * Полный вывод (table + JSON)
   */
  printFullReport(): void {
    if (this.options.outputFormat === 'json' || this.options.outputFormat === 'both') {
      this.printResults();
    }
    if (this.options.outputFormat === 'json' || this.options.outputFormat === 'both') {
      this.printJSONOutput();
    }
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ ФОРМАТИРОВАНИЯ
  // ============================================================================

  private printHeader(): void {
    const width = 70;
    const border = '┌' + '─'.repeat(width - 2) + '┐';
    const padding = (text: string) => {
      const left = 2;
      const right = width - left - text.length - 1;
      return '│' + ' '.repeat(left) + text + ' '.repeat(Math.max(0, right)) + '│';
    };

    console.log('');
    console.log(border);
    console.log(padding('PROTOCOL SECURITY — PERFORMANCE BENCHMARKS'));
    console.log(padding(`Node: ${this.environment.nodeVersion} | Platform: ${this.environment.platform}`));
    console.log(padding(`CPU: ${this.environment.cpuModel.substring(0, 40)}...`));
    console.log(padding(`Memory: ${this.environment.totalMemoryGB}GB | Cores: ${this.environment.cpuCount}`));
    console.log('├' + '─'.repeat(width - 2) + '┤');
  }

  private printCategoryTable(cat: CategoryResults): void {
    const width = 70;
    const categoryNames: Record<BenchmarkCategory, string> = {
      crypto: 'CRYPTO BENCHMARKS',
      auth: 'AUTH BENCHMARKS',
      secrets: 'SECRETS BENCHMARKS',
      logging: 'LOGGING BENCHMARKS',
      threat: 'THREAT DETECTION BENCHMARKS',
    };

    console.log('│' + ' ' + categoryNames[cat.category] + ' '.repeat(width - 3 - categoryNames[cat.category].length) + '│');
    console.log('├──────────────────────────────┬──────────┬──────────┬──────────┬─────────────┤');
    console.log('│ Metric                       │    p50   │    p95   │    p99   │  Throughput │');
    console.log('├──────────────────────────────┼──────────┼──────────┼──────────┼─────────────┤');

    for (const r of cat.results) {
      const name = r.name.length > 28 ? r.name.substring(0, 25) + '...' : r.name;
      const p50 = formatTime(r.median).padStart(8);
      const p95 = formatTime(r.p95).padStart(8);
      const p99 = formatTime(r.p99).padStart(8);
      const ops = formatOps(r.opsPerSec);
      const status = r.passed ? '✓' : '✗';

      const paddedOps = ops.length > 11 ? ops.substring(0, 11) : ops.padEnd(11);

      console.log(
        `│ ${name.padEnd(28)} │ ${p50} │ ${p95} │ ${p99} │ ${status} ${paddedOps} │`
      );
    }

    console.log('├──────────────────────────────┴──────────┴──────────┴──────────┴─────────────┤');

    // Memory delta
    const totalMem = cat.results.reduce((s, r) => s + r.memoryDeltaMB, 0);
    console.log(
      `│ Memory Delta: ${totalMem.toFixed(2)} MB | All Passed: ${cat.allPassed ? '✓ YES' : '✗ NO'} | Avg: ${(cat.avgOpsPerSec).toFixed(0)} ops/sec`
    );
    console.log('└' + '─'.repeat(width - 2) + '┘');
    console.log('');
  }

  private printSummary(report: BenchmarkReport): void {
    const width = 70;
    const border = '┌' + '─'.repeat(width - 2) + '┐';

    console.log(border);
    console.log('│' + ' SUMMARY'.padEnd(width - 2) + '│');
    console.log('├──────────────────────────────────────────────────────────────┤');

    console.log(`│ Total Benchmarks: ${String(report.allResults.length).padStart(4)}`.padEnd(width - 1) + '│');
    console.log(`│ Passed:           ${String(report.passedCount).padStart(4)}`.padEnd(width - 1) + '│');
    console.log(`│ Failed:           ${String(report.failedCount).padStart(4)}`.padEnd(width - 1) + '│');
    console.log(`│ Total ops/sec:    ${formatOps(report.totalOpsPerSec).padStart(15)}`.padEnd(width - 1) + '│');
    console.log(`│ Total Duration:   ${formatTime(report.totalDuration).padStart(15)}`.padEnd(width - 1) + '│');
    console.log('├──────────────────────────────────────────────────────────────┤');

    const status = report.allPassed ? '✓ ALL THRESHOLDS PASSED' : '✗ SOME THRESHOLDS FAILED';
    console.log('│' + ` ${status}`.padEnd(width - 3) + '│');
    console.log('└' + '─'.repeat(width - 2) + '┘');

    // Показать проваленные
    const failed = report.allResults.filter(r => !r.passed);
    if (failed.length > 0) {
      console.log('\n⚠ FAILED THRESHOLDS:');
      for (const r of failed) {
        console.log(
          `  ✗ ${r.name}: ${formatTime(r.median)} (threshold: ${formatTime(r.threshold)})`
        );
      }
    }

    console.log('');
  }

  private printJSONOutput(): void {
    console.log('\n--- JSON REPORT ---');
    console.log(this.exportJSON());
    console.log('--- END JSON REPORT ---\n');
  }

  /**
   * Получить все результаты (для тестов)
   */
  getResults(): BenchmarkResult[] {
    return [...this.results];
  }
}
