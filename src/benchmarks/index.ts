/**
 * ============================================================================
 * BENCHMARKS — ГЛАВНЫЙ ENTRY POINT
 * ============================================================================
 *
 * Объединяет все benchmark модули и предоставляет единый интерфейс запуска:
 * - runAllBenchmarks() — запустить все benchmarks
 * - runCategoryBenchmarks(category) — запустить benchmarks категории
 * - BenchmarkRunner — экспортируется для кастомных сценариев
 *
 * Usage:
 *   import { runAllBenchmarks, BenchmarkRunner } from './benchmarks';
 *   const report = await runAllBenchmarks();
 *   console.log(report.exportJSON());
 */

import { BenchmarkRunner } from './BenchmarkRunner';
import { BenchmarkReport, RunnerOptions, BenchmarkCategory } from './types';
import { runCryptoBenchmarks } from './CryptoBench';
import { runAuthBenchmarks } from './AuthBench';
import { runSecretsBenchmarks } from './SecretsBench';
import { runLoggingBenchmarks } from './LoggingBench';
import { runThreatBenchmarks } from './ThreatBench';

/**
 * Запустить ВСЕ benchmarks
 *
 * @param iterations — количество итераций (default: 1000)
 * @param options — опции runner
 * @returns BenchmarkReport
 */
export async function runAllBenchmarks(
  iterations?: number,
  options?: RunnerOptions
): Promise<BenchmarkReport> {
  const runner = new BenchmarkRunner({
    defaultIterations: iterations ?? 1000,
    verbose: options?.verbose ?? true,
    outputFormat: options?.outputFormat ?? 'both',
  });

  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║   PROTOCOL SECURITY 3.0 — FULL PERFORMANCE BENCHMARK     ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`   Iterations: ${iterations ?? 1000}`);
  console.log('');

  // Crypto
  console.log('┌──────────────────────────────────────────────────────────┐');
  console.log('│ [1/5] CRYPTO BENCHMARKS                                  │');
  console.log('└──────────────────────────────────────────────────────────┘');
  await runCryptoBenchmarks(runner, iterations);

  // Auth
  console.log('┌──────────────────────────────────────────────────────────┐');
  console.log('│ [2/5] AUTH BENCHMARKS                                    │');
  console.log('└──────────────────────────────────────────────────────────┘');
  await runAuthBenchmarks(runner, iterations);

  // Secrets
  console.log('┌──────────────────────────────────────────────────────────┐');
  console.log('│ [3/5] SECRETS BENCHMARKS                                 │');
  console.log('└──────────────────────────────────────────────────────────┘');
  await runSecretsBenchmarks(runner, iterations);

  // Logging
  console.log('┌──────────────────────────────────────────────────────────┐');
  console.log('│ [4/5] LOGGING BENCHMARKS                                 │');
  console.log('└──────────────────────────────────────────────────────────┘');
  await runLoggingBenchmarks(runner, iterations);

  // Threat Detection
  console.log('┌──────────────────────────────────────────────────────────┐');
  console.log('│ [5/5] THREAT DETECTION BENCHMARKS                        │');
  console.log('└──────────────────────────────────────────────────────────┘');
  await runThreatBenchmarks(runner, iterations);

  // Вывод результатов
  runner.printResults();

  return runner.getReport();
}

/**
 * Запустить benchmarks конкретной категории
 *
 * @param category — категория
 * @param iterations — количество итераций
 * @param options — опции runner
 * @returns BenchmarkReport
 */
export async function runCategoryBenchmarks(
  category: BenchmarkCategory,
  iterations?: number,
  options?: RunnerOptions
): Promise<BenchmarkReport> {
  const runner = new BenchmarkRunner({
    defaultIterations: iterations ?? 1000,
    verbose: options?.verbose ?? true,
    outputFormat: options?.outputFormat ?? 'both',
  });

  const categoryNames: Record<BenchmarkCategory, string> = {
    crypto: 'CRYPTO',
    auth: 'AUTH',
    secrets: 'SECRETS',
    logging: 'LOGGING',
    threat: 'THREAT DETECTION',
  };

  console.log('');
  console.log(`╔══════════════════════════════════════════════════════════╗`);
  console.log(`║   ${categoryNames[category]} BENCHMARKS`.padEnd(60) + '║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`   Iterations: ${iterations ?? 1000}`);
  console.log('');

  switch (category) {
    case 'crypto':
      await runCryptoBenchmarks(runner, iterations);
      break;
    case 'auth':
      await runAuthBenchmarks(runner, iterations);
      break;
    case 'secrets':
      await runSecretsBenchmarks(runner, iterations);
      break;
    case 'logging':
      await runLoggingBenchmarks(runner, iterations);
      break;
    case 'threat':
      await runThreatBenchmarks(runner, iterations);
      break;
  }

  runner.printResults();

  return runner.getReport();
}

/**
 * Создать новый BenchmarkRunner (для кастомных сценариев)
 */
export { BenchmarkRunner };

/**
 * Экспорт типов
 */
export type {
  BenchmarkResult,
  BenchmarkCategory,
  CategoryResults,
  BenchmarkReport,
  BenchmarkConfig,
  RunnerOptions,
  EnvironmentInfo,
} from './types';

export {
  DEFAULT_THRESHOLDS,
  percentile,
  mean,
  stdDev,
  formatTime,
  formatOps,
  getEnvironmentInfo,
} from './types';

/**
 * Экспорт benchmark функций для кастомного использования
 */
export {
  runCryptoBenchmarks,
  runAuthBenchmarks,
  runSecretsBenchmarks,
  runLoggingBenchmarks,
  runThreatBenchmarks,
};
