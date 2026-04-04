/**
 * ============================================================================
 * THREAT DETECTION BENCHMARKS — ТЕСТЫ ПРОИЗВОДИТЕЛЬНОСТИ ОБНАРУЖЕНИЯ УГРОЗ
 * ============================================================================
 *
 * Измеряет производительность:
 * - ML Inference (Isolation Forest simulation)
 * - Event Processing (полный цикл обработки события)
 * - Correlation Engine (корреляция событий)
 * - Risk Scoring (оценка риска)
 *
 * Симулирует ML inference и threat detection pipeline
 * без загрузки реальных TensorFlow моделей для воспроизводимости.
 */

import * as crypto from 'crypto';
import { BenchmarkRunner } from './BenchmarkRunner';
import { BenchmarkResult, DEFAULT_THRESHOLDS } from './types';

/**
 * Упрощённый Isolation Forest для benchmark
 * Симулирует ML inference с математическими операциями
 */
class SimpleIsolationForest {
  private readonly numTrees: number;
  private readonly sampleSize: number;
  private readonly thresholds: number[];

  constructor(numTrees: number = 100, sampleSize: number = 256) {
    this.numTrees = numTrees;
    this.sampleSize = sampleSize;
    // Pre-compute random thresholds для каждого дерева
    this.thresholds = Array.from({ length: numTrees }, () => Math.random());
  }

  /**
   * Предсказание anomaly score
   * @param features — вектор признаков
   * @returns anomaly score [0, 1]
   */
  predict(features: number[]): number {
    let totalScore = 0;

    for (let t = 0; t < this.numTrees; t++) {
      // Симуляция пути по дереву
      const featureHash = this.hashFeatures(features, t);
      const threshold = this.thresholds[t];
      const depth = this.simulateTreeDepth(featureHash, threshold);
      // Нормализованный score
      totalScore += this.anomalyScore(depth, this.sampleSize);
    }

    return totalScore / this.numTrees;
  }

  /**
   * Хэширование признаков + seed дерева
   */
  private hashFeatures(features: number[], treeSeed: number): number {
    const hashInput = features.join(',') + ':' + treeSeed;
    const hash = crypto.createHash('md5').update(hashInput).digest();
    // Нормализуем в [0, 1]
    return (hash.readUInt32LE(0) % 10000) / 10000;
  }

  /**
   * Симуляция глубины дерева
   */
  private simulateTreeDepth(hashValue: number, threshold: number): number {
    let depth = 0;
    let value = hashValue;

    // Симуляция спуска по дереву
    while (depth < 20) {
      value = (value * 1103515245 + 12345) & 0x7fffffff;
      const normalized = (value % 10000) / 10000;
      if (normalized < threshold) {
        depth++;
      } else {
        break;
      }
    }

    return depth;
  }

  /**
   * Расчет anomaly score из глубины
   */
  private anomalyScore(depth: number, n: number): number {
    if (depth === 0) return 1.0;
    // c(n) — average path length
    const cN = 2 * (Math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n;
    return Math.pow(2, -depth / cN);
  }
}

/**
 * Correlation Engine для benchmark
 * Симулирует корреляцию событий безопасности
 */
class SimpleCorrelationEngine {
  private readonly windowSizeMs: number;
  private readonly rules: CorrelationRule[];

  constructor(windowSizeMs: number = 300000) {
    this.windowSizeMs = windowSizeMs;
    this.rules = this.initializeRules();
  }

  /**
   * Инициализация правил корреляции
   */
  private initializeRules(): CorrelationRule[] {
    return [
      {
        id: 'CORR-001',
        name: 'Brute Force Detection',
        minEvents: 5,
        eventType: 'failed_login',
        groupBy: ['userId', 'sourceIp'],
        severity: 'high',
      },
      {
        id: 'CORR-002',
        name: 'Privilege Escalation',
        minEvents: 2,
        eventType: 'privilege_change',
        groupBy: ['userId'],
        severity: 'critical',
      },
      {
        id: 'CORR-003',
        name: 'Data Exfiltration',
        minEvents: 3,
        eventType: 'large_download',
        groupBy: ['userId', 'destinationIp'],
        severity: 'high',
      },
      {
        id: 'CORR-004',
        name: 'Lateral Movement',
        minEvents: 3,
        eventType: 'remote_login',
        groupBy: ['userId'],
        severity: 'medium',
      },
    ];
  }

  /**
   * Обработка события через correlation engine
   * @returns количество сработавших правил
   */
  processEvent(event: SecurityEvent): number {
    let matchedRules = 0;

    for (const rule of this.rules) {
      if (this.matchRule(event, rule)) {
        matchedRules++;
      }
    }

    return matchedRules;
  }

  /**
   * Проверка соответствия события правилу
   */
  private matchRule(event: SecurityEvent, rule: CorrelationRule): boolean {
    // Проверяем тип события
    if (event.eventType !== rule.eventType) {
      return false;
    }

    // Проверяем severity threshold
    const severityScore = this.severityToScore(event.severity);
    if (severityScore < 30) {
      return false;
    }

    // Проверяем groupBy fields
    for (const field of rule.groupBy) {
      if (!(event as any)[field]) {
        return false;
      }
    }

    return true;
  }

  /**
   * Конвертация severity в score
   */
  private severityToScore(severity: string): number {
    const scores: Record<string, number> = {
      info: 10,
      low: 25,
      medium: 50,
      high: 75,
      critical: 95,
    };
    return scores[severity] ?? 0;
  }
}

/**
 * Risk Scorer для benchmark
 * Оценивает риск на основе множества факторов
 */
class SimpleRiskScorer {
  private readonly weights: Record<string, number>;

  constructor() {
    this.weights = {
      entity: 0.25,
      threat: 0.30,
      impact: 0.30,
      context: 0.15,
    };
  }

  /**
   * Оценка риска
   * @returns risk score [0, 100]
   */
  scoreRisk(event: SecurityEvent): number {
    const entityScore = this.scoreEntity(event);
    const threatScore = this.scoreThreat(event);
    const impactScore = this.scoreImpact(event);
    const contextScore = this.scoreContext(event);

    const totalScore =
      entityScore * this.weights.entity +
      threatScore * this.weights.threat +
      impactScore * this.weights.impact +
      contextScore * this.weights.context;

    return Math.min(100, Math.max(0, totalScore));
  }

  private scoreEntity(event: SecurityEvent): number {
    let score = 20;
    if (event.userId) score += 30;
    if (event.sourceIp) score += 20;
    if (event.eventType.includes('failed')) score += 30;
    return Math.min(100, score);
  }

  private scoreThreat(event: SecurityEvent): number {
    const severityScores: Record<string, number> = {
      info: 10,
      low: 25,
      medium: 50,
      high: 75,
      critical: 95,
    };
    return severityScores[event.severity] ?? 20;
  }

  private scoreImpact(event: SecurityEvent): number {
    let score = 10;
    if (event.category === 'data_access') score += 40;
    if (event.category === 'privilege') score += 50;
    if (event.category === 'exploitation') score += 60;
    return Math.min(100, score);
  }

  private scoreContext(event: SecurityEvent): number {
    let score = 15;
    if (event.timestamp) score += 20;
    if (event.source) score += 15;
    if (event.rawEvent && Object.keys(event.rawEvent).length > 0) score += 30;
    return Math.min(100, score);
  }
}

/**
 * Интерфейсы для threat detection
 */
interface CorrelationRule {
  id: string;
  name: string;
  minEvents: number;
  eventType: string;
  groupBy: string[];
  severity: string;
}

interface SecurityEvent {
  id: string;
  timestamp: string;
  eventType: string;
  source: string;
  severity: string;
  category: string;
  userId?: string;
  sourceIp?: string;
  destinationIp?: string;
  rawEvent?: Record<string, unknown>;
}

/**
 * Генератор тестовых событий
 */
function generateTestEvent(index: number): SecurityEvent {
  const eventTypes = [
    'failed_login',
    'successful_login',
    'privilege_change',
    'large_download',
    'remote_login',
    'file_access',
    'api_call',
    'config_change',
  ];
  const severities = ['info', 'low', 'medium', 'high', 'critical'];
  const categories = ['data_access', 'privilege', 'exploitation', 'discovery', 'lateral_movement'];

  return {
    id: `event-${index}`,
    timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
    eventType: eventTypes[index % eventTypes.length],
    source: 'BenchmarkSource',
    severity: severities[index % severities.length],
    category: categories[index % categories.length],
    userId: `user-${index % 50}`,
    sourceIp: `192.168.1.${index % 255}`,
    destinationIp: `10.0.0.${index % 255}`,
    rawEvent: {
      loginAttempts: index % 10,
      dataVolume: Math.floor(Math.random() * 10000),
      cpuUsage: Math.random() * 100,
      memoryUsage: Math.random() * 100,
    },
  };
}

/**
 * Запуск всех threat detection benchmarks
 */
export async function runThreatBenchmarks(runner: BenchmarkRunner, iterations?: number): Promise<BenchmarkResult[]> {
  const results: BenchmarkResult[] = [];
  const iters = iterations ?? 500;

  // Инициализация компонентов
  const isolationForest = new SimpleIsolationForest(100, 256);
  const correlationEngine = new SimpleCorrelationEngine(300000);
  const riskScorer = new SimpleRiskScorer();

  // Pre-generate тестовые события
  const testEvents: SecurityEvent[] = [];
  for (let i = 0; i < iters; i++) {
    testEvents.push(generateTestEvent(i));
  }

  // ========================================================================
  // ML INFERENCE (Isolation Forest)
  // ========================================================================
  const mlFeatures = [0.5, 0.3, 0.8, 0.1, 0.6, 0.4, 0.9, 0.2]; // 8 признаков

  let mlIdx = 0;
  const mlInferenceResult = await runner.run(
    'ML Inference',
    () => {
      // Генерируем немного разные features для каждого вызова
      const features = mlFeatures.map((f, i) => f + (Math.sin(mlIdx + i) * 0.1));
      isolationForest.predict(features);
      mlIdx++;
    },
    iters,
    DEFAULT_THRESHOLDS['ML Inference']
  );
  (mlInferenceResult as any).category = 'threat';
  runner.setLastCategory('threat');
  results.push(mlInferenceResult);

  // ========================================================================
  // EVENT PROCESSING (полный цикл)
  // ========================================================================
  let eventIdx = 0;
  const eventProcessingResult = await runner.run(
    'Event Processing',
    () => {
      const event = testEvents[eventIdx % testEvents.length];

      // 1. ML analysis
      const features = [0.5, 0.3, 0.8, 0.1, 0.6, 0.4, 0.9, 0.2];
      isolationForest.predict(features);

      // 2. Correlation
      correlationEngine.processEvent(event);

      // 3. Risk scoring
      riskScorer.scoreRisk(event);

      eventIdx++;
    },
    iters,
    DEFAULT_THRESHOLDS['Event Processing']
  );
  (eventProcessingResult as any).category = 'threat';
  runner.setLastCategory('threat');
  results.push(eventProcessingResult);

  // ========================================================================
  // CORRELATION ENGINE
  // ========================================================================
  let corrIdx = 0;
  const correlationResult = await runner.run(
    'Correlation Engine',
    () => {
      const event = testEvents[corrIdx % testEvents.length];
      correlationEngine.processEvent(event);
      corrIdx++;
    },
    iters,
    DEFAULT_THRESHOLDS['Correlation Engine']
  );
  (correlationResult as any).category = 'threat';
  runner.setLastCategory('threat');
  results.push(correlationResult);

  // ========================================================================
  // RISK SCORING
  // ========================================================================
  let riskIdx = 0;
  const riskScoringResult = await runner.run(
    'Risk Scoring',
    () => {
      const event = testEvents[riskIdx % testEvents.length];
      riskScorer.scoreRisk(event);
      riskIdx++;
    },
    iters,
    DEFAULT_THRESHOLDS['Risk Scoring']
  );
  (riskScoringResult as any).category = 'threat';
  runner.setLastCategory('threat');
  results.push(riskScoringResult);

  return results;
}
