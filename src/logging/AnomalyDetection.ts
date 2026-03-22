/**
 * ============================================================================
 * ANOMALY DETECTION - ML ОБНАРУЖЕНИЕ АНОМАЛИЙ
 * ============================================================================
 * Модуль для обнаружения аномалий в логах с использованием статистических
 * методов и ML алгоритмов без внешних зависимостей.
 * 
 * Особенности:
 * - Statistical anomaly detection (Z-score, IQR)
 * - Isolation Forest алгоритм
 * - Time-series анализ с сезонностью
 * - Baseline обучение и адаптация
 * - Multi-feature анализ
 * - Contextual anomaly detection
 * - Collective anomaly detection
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  LogEntry,
  LogSource,
  AnomalyDetectionResult,
  AnomalyDetectionConfig,
  FeatureContribution,
  AnomalyContext,
  ProcessingError
} from '../types/logging.types';

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/**
 * Пороги для различных типов аномалий
 */
const ANOMALY_THRESHOLDS = {
  // Z-score пороги
  Z_SCORE_WARNING: 2.0,
  Z_SCORE_CRITICAL: 3.0,
  
  // IQR множитель
  IQR_MULTIPLIER: 1.5,
  
  // Isolation Forest пороги
  ISOLATION_FOREST_ANOMALY: 0.6,
  
  // Минимальный размер выборки
  MIN_SAMPLE_SIZE: 30,
  
  // Максимальный размер выборки (для производительности)
  MAX_SAMPLE_SIZE: 10000,
  
  // Период сезонности по умолчанию (часы)
  DEFAULT_SEASONALITY_HOURS: 24,
  
  // Размер окна для скользящей статистики
  MOVING_WINDOW_SIZE: 100
};

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Точка данных для анализа
 */
interface DataPoint {
  /** Значения признаков */
  features: number[];
  /** Временная метка */
  timestamp: number;
  /** Исходный лог */
  log?: LogEntry;
  /** Метка (для обучения с учителем) */
  label?: number;
}

/**
 * Статистика признака
 */
interface FeatureStatistics {
  /** Среднее значение */
  mean: number;
  /** Стандартное отклонение */
  stdDev: number;
  /** Минимум */
  min: number;
  /** Максимум */
  max: number;
  /** Q1 (25-й перцентиль) */
  q1: number;
  /** Q3 (75-й перцентиль) */
  q3: number;
  /** IQR (Interquartile Range) */
  iqr: number;
  /** Количество наблюдений */
  count: number;
}

/**
 * Модель Isolation Tree
 */
interface IsolationTree {
  /** Тип узла */
  type: 'internal' | 'leaf';
  /** Признак для разделения */
  feature?: number;
  /** Порог разделения */
  threshold?: number;
  /** Левый потомок */
  left?: IsolationTree;
  /** Правый потомок */
  right?: IsolationTree;
  /** Размер узла (для листьев) */
  size?: number;
  /** Высота узла */
  height: number;
}

/**
 * Модель Isolation Forest
 */
interface IsolationForestModel {
  /** Деревья */
  trees: IsolationTree[];
  /** Количество признаков */
  numFeatures: number;
  /** Размер выборки */
  sampleSize: number;
  /** Количество деревьев */
  numTrees: number;
}

/**
 * Временной ряд для сезонного анализа
 */
interface TimeSeries {
  /** Значения */
  values: number[];
  /** Временные метки */
  timestamps: number[];
  /** Период сезонности */
  seasonalityPeriod: number;
  /** Тренд */
  trend?: number[];
  /** Сезонность */
  seasonality?: number[];
  /** Остаток */
  residual?: number[];
}

/**
 * Конфигурация детектора аномалий
 */
interface AnomalyDetectorConfig {
  /** Тип модели */
  modelType: 'zscore' | 'iqr' | 'isolation_forest' | 'hybrid';
  /** Признаки для анализа */
  features: string[];
  /** Порог аномалии */
  anomalyThreshold: number;
  /** Период обучения (часы) */
  trainingPeriodHours: number;
  /** Частота переобучения (часы) */
  retrainingFrequencyHours: number;
  /** Минимальный размер выборки */
  minSampleSize: number;
  /** Метод нормализации */
  normalizationMethod: 'z-score' | 'min-max' | 'robust';
  /** Включить сезонность */
  enableSeasonality: boolean;
  /** Период сезонности (часы) */
  seasonalityPeriodHours: number;
  /** Количество деревьев для Isolation Forest */
  numTrees: number;
  /** Размер подвыборки для деревьев */
  sampleSize: number;
  /** Включить адаптивное обучение */
  enableAdaptiveLearning: boolean;
  /** Скорость адаптации (0-1) */
  adaptationRate: number;
}

/**
 * Статистика детектора
 */
interface DetectorStatistics {
  /** Всего обработано логов */
  totalLogsProcessed: number;
  /** Детектировано аномалий */
  anomaliesDetected: number;
  /** По типам аномалий */
  byAnomalyType: {
    point: number;
    contextual: number;
    collective: number;
  };
  /** По признакам */
  byFeature: Record<string, number>;
  /** Ложные срабатывания */
  falsePositives: number;
  /** Пропущенные аномалии */
  falseNegatives: number;
  /** Средний anomaly score */
  avgAnomalyScore: number;
  /** Среднее время детекта (мс) */
  avgDetectionTime: number;
  /** P99 время детекта (мс) */
  p99DetectionTime: number;
  /** Размер обучающей выборки */
  trainingSampleSize: number;
  /** Последнее переобучение */
  lastRetraining: string | null;
}

// ============================================================================
// КЛАСС STATISTICAL ANALYZER
// ============================================================================

/**
 * Статистический анализатор
 */
class StatisticalAnalyzer {
  /**
   * Расчет статистики признака
   */
  calculateStatistics(values: number[]): FeatureStatistics {
    const sorted = [...values].sort((a, b) => a - b);
    const n = sorted.length;
    
    if (n === 0) {
      return {
        mean: 0,
        stdDev: 0,
        min: 0,
        max: 0,
        q1: 0,
        q3: 0,
        iqr: 0,
        count: 0
      };
    }
    
    // Среднее
    const mean = sorted.reduce((a, b) => a + b, 0) / n;
    
    // Стандартное отклонение
    const variance = sorted.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / n;
    const stdDev = Math.sqrt(variance);
    
    // Минимум и максимум
    const min = sorted[0];
    const max = sorted[n - 1];
    
    // Квартили
    const q1Index = Math.floor(n * 0.25);
    const q3Index = Math.floor(n * 0.75);
    const q1 = sorted[q1Index];
    const q3 = sorted[q3Index];
    const iqr = q3 - q1;
    
    return {
      mean,
      stdDev,
      min,
      max,
      q1,
      q3,
      iqr,
      count: n
    };
  }
  
  /**
   * Расчет Z-score
   */
  calculateZScore(value: number, mean: number, stdDev: number): number {
    if (stdDev === 0) {
      return 0;
    }
    return (value - mean) / stdDev;
  }
  
  /**
   * Расчет Modified Z-score (на основе медианы)
   */
  calculateModifiedZScore(value: number, median: number, mad: number): number {
    if (mad === 0) {
      return 0;
    }
    return 0.6745 * (value - median) / mad;
  }
  
  /**
   * Расчет MAD (Median Absolute Deviation)
   */
  calculateMAD(values: number[]): number {
    const sorted = [...values].sort((a, b) => a - b);
    const n = sorted.length;
    
    if (n === 0) return 0;
    
    const median = n % 2 === 0
      ? (sorted[n / 2 - 1] + sorted[n / 2]) / 2
      : sorted[Math.floor(n / 2)];
    
    const deviations = values.map(v => Math.abs(v - median));
    deviations.sort((a, b) => a - b);
    
    const mad = n % 2 === 0
      ? (deviations[n / 2 - 1] + deviations[n / 2]) / 2
      : deviations[Math.floor(n / 2)];
    
    return mad;
  }
  
  /**
   * Проверка аномалии по Z-score
   */
  isAnomalyZScore(value: number, stats: FeatureStatistics, threshold: number): boolean {
    const zScore = Math.abs(this.calculateZScore(value, stats.mean, stats.stdDev));
    return zScore > threshold;
  }
  
  /**
   * Проверка аномалии по IQR методу
   */
  isAnomalyIQR(value: number, stats: FeatureStatistics): boolean {
    const lowerBound = stats.q1 - ANOMALY_THRESHOLDS.IQR_MULTIPLIER * stats.iqr;
    const upperBound = stats.q3 + ANOMALY_THRESHOLDS.IQR_MULTIPLIER * stats.iqr;
    return value < lowerBound || value > upperBound;
  }
  
  /**
   * Нормализация значения
   */
  normalize(value: number, stats: FeatureStatistics, method: string): number {
    switch (method) {
      case 'z-score':
        return this.calculateZScore(value, stats.mean, stats.stdDev);
      
      case 'min-max':
        const range = stats.max - stats.min;
        if (range === 0) return 0;
        return (value - stats.min) / range;
      
      case 'robust':
        if (stats.iqr === 0) return 0;
        return (value - stats.q1) / stats.iqr;
      
      default:
        return value;
    }
  }
}

// ============================================================================
// КЛАСС ISOLATION FOREST
// ============================================================================

/**
 * Реализация Isolation Forest алгоритма
 */
class IsolationForest {
  private model: IsolationForestModel | null = null;
  private analyzer: StatisticalAnalyzer;
  
  constructor() {
    this.analyzer = new StatisticalAnalyzer();
  }
  
  /**
   * Обучение модели
   */
  fit(data: number[][], numTrees: number = 100, sampleSize: number = 256): void {
    if (data.length === 0) {
      return;
    }
    
    const numFeatures = data[0].length;
    const trees: IsolationTree[] = [];
    
    // Создание деревьев
    for (let i = 0; i < numTrees; i++) {
      // Случайная подвыборка
      const sample = this.randomSample(data, Math.min(sampleSize, data.length));
      
      // Построение дерева
      const tree = this.buildTree(sample, 0, sampleSize);
      trees.push(tree);
    }
    
    this.model = {
      trees,
      numFeatures,
      sampleSize,
      numTrees
    };
  }
  
  /**
   * Расчет anomaly score
   */
  score(point: number[]): number {
    if (!this.model || this.model.trees.length === 0) {
      return 0.5;
    }
    
    // Расчет средней глубины изоляции
    const avgPathLength = this.trees.reduce((sum, tree) => {
      return sum + this.pathLength(point, tree, 0);
    }, 0) / this.model.numTrees;
    
    // Нормализация score
    const n = this.model.sampleSize;
    const c = this.c(n);
    
    return Math.pow(2, -avgPathLength / c);
  }
  
  /**
   * Проверка на аномалию
   */
  isAnomaly(point: number[], threshold: number = ANOMALY_THRESHOLDS.ISOLATION_FOREST_ANOMALY): boolean {
    return this.score(point) > threshold;
  }
  
  /**
   * Построение дерева изоляции
   */
  private buildTree(data: number[][], height: number, maxDepth: number): IsolationTree {
    const n = data.length;
    
    // Лист если достигнут лимит глубины или размер 1
    if (height >= maxDepth || n <= 1) {
      return {
        type: 'leaf',
        size: n,
        height
      };
    }
    
    // Случайный выбор признака
    const numFeatures = data[0].length;
    const feature = Math.floor(Math.random() * numFeatures);
    
    // Получение мин и макс для признака
    const values = data.map(d => d[feature]);
    const min = Math.min(...values);
    const max = Math.max(...values);
    
    // Если все значения одинаковые
    if (min === max) {
      return {
        type: 'leaf',
        size: n,
        height
      };
    }
    
    // Случайный порог
    const threshold = min + Math.random() * (max - min);
    
    // Разделение данных
    const left = data.filter(d => d[feature] < threshold);
    const right = data.filter(d => d[feature] >= threshold);
    
    // Рекурсивное построение
    return {
      type: 'internal',
      feature,
      threshold,
      left: this.buildTree(left, height + 1, maxDepth),
      right: this.buildTree(right, height + 1, maxDepth),
      height
    };
  }
  
  /**
   * Расчет длины пути до точки
   */
  private pathLength(point: number[], tree: IsolationTree, height: number): number {
    if (tree.type === 'leaf') {
      return height + this.c(tree.size || 0);
    }
    
    const feature = tree.feature!;
    const threshold = tree.threshold!;
    
    if (point[feature] < threshold) {
      return this.pathLength(point, tree.left!, height + 1);
    } else {
      return this.pathLength(point, tree.right!, height + 1);
    }
  }
  
  /**
   * Средняя длина пути для unsuccessful search в BST
   */
  private c(n: number): number {
    if (n <= 1) return 0;
    if (n === 2) return 1;
    return 2 * (Math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n;
  }
  
  /**
   * Случайная выборка
   */
  private randomSample(data: number[][], size: number): number[][] {
    const shuffled = [...data].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, size);
  }
}

// ============================================================================
// КЛАСС TIME SERIES ANALYZER
// ============================================================================

/**
 * Анализатор временных рядов
 */
class TimeSeriesAnalyzer {
  /**
   * Декомпозиция временного ряда
   */
  decompose(series: TimeSeries): {
    trend: number[];
    seasonality: number[];
    residual: number[];
  } {
    const { values, seasonalityPeriod } = series;
    const n = values.length;
    
    if (n < seasonalityPeriod * 2) {
      // Недостаточно данных
      return {
        trend: values,
        seasonality: new Array(n).fill(0),
        residual: new Array(n).fill(0)
      };
    }
    
    // Расчет тренда (скользящее среднее)
    const trend = this.calculateMovingAverage(values, seasonalityPeriod);
    
    // Detrending
    const detrended = values.map((v, i) => v - trend[i]);
    
    // Расчет сезонности
    const seasonality = this.calculateSeasonality(detrended, seasonalityPeriod);
    
    // Остаток
    const residual = values.map((v, i) => v - trend[i] - seasonality[i]);
    
    return { trend, seasonality, residual };
  }
  
  /**
   * Расчет скользящего среднего
   */
  private calculateMovingAverage(values: number[], window: number): number[] {
    const result: number[] = [];
    const halfWindow = Math.floor(window / 2);
    
    for (let i = 0; i < values.length; i++) {
      const start = Math.max(0, i - halfWindow);
      const end = Math.min(values.length, i + halfWindow + 1);
      const slice = values.slice(start, end);
      const avg = slice.reduce((a, b) => a + b, 0) / slice.length;
      result.push(avg);
    }
    
    return result;
  }
  
  /**
   * Расчет сезонности
   */
  private calculateSeasonality(values: number[], period: number): number[] {
    const n = values.length;
    const seasonality: number[] = [];
    
    // Расчет среднего для каждой позиции в периоде
    const seasonalAverages: number[] = new Array(period).fill(0);
    const counts: number[] = new Array(period).fill(0);
    
    for (let i = 0; i < n; i++) {
      const pos = i % period;
      seasonalAverages[pos] += values[i];
      counts[pos]++;
    }
    
    for (let i = 0; i < period; i++) {
      seasonalAverages[i] /= counts[i];
    }
    
    // Нормализация
    const overallMean = seasonalAverages.reduce((a, b) => a + b, 0) / period;
    const normalizedSeasonality = seasonalAverages.map(s => s - overallMean);
    
    // Построение полного ряда сезонности
    for (let i = 0; i < n; i++) {
      seasonality.push(normalizedSeasonality[i % period]);
    }
    
    return seasonality;
  }
  
  /**
   * Прогноз следующего значения
   */
  forecast(series: TimeSeries): { value: number; confidence: number } {
    const { values, seasonalityPeriod } = series;
    
    if (values.length < seasonalityPeriod) {
      return {
        value: values[values.length - 1] || 0,
        confidence: 0.5
      };
    }
    
    const { trend, seasonality } = this.decompose(series);
    
    // Экстраполяция тренда
    const recentTrend = trend.slice(-seasonalityPeriod);
    const trendSlope = (recentTrend[recentTrend.length - 1] - recentTrend[0]) / seasonalityPeriod;
    const nextTrend = trend[trend.length - 1] + trendSlope;
    
    // Следующее значение сезонности
    const nextSeasonality = seasonality[seasonality.length % seasonalityPeriod];
    
    // Прогноз
    const forecast = nextTrend + nextSeasonality;
    
    // Расчет уверенности на основе волатильности остатка
    const residual = values.map((v, i) => v - trend[i] - seasonality[i]);
    const residualStdDev = this.calculateStdDev(residual);
    const confidence = Math.max(0, 1 - residualStdDev / (Math.abs(forecast) + 1));
    
    return { value: forecast, confidence };
  }
  
  /**
   * Расчет стандартного отклонения
   */
  private calculateStdDev(values: number[]): number {
    if (values.length === 0) return 0;
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
    return Math.sqrt(variance);
  }
}

// ============================================================================
// КЛАСС FEATURE EXTRACTOR
// ============================================================================

/**
 * Извлекатель признаков из логов
 */
class FeatureExtractor {
  /**
   * Извлечение признаков из лога
   */
  extract(log: LogEntry, featurePaths: string[]): number[] {
    const features: number[] = [];
    
    for (const path of featurePaths) {
      const value = this.getNumericValue(log, path);
      features.push(value);
    }
    
    return features;
  }
  
  /**
   * Получение числового значения по пути
   */
  private getNumericValue(log: LogEntry, path: string): number {
    const parts = path.split('.');
    let value: unknown = log;
    
    for (const part of parts) {
      if (value === null || value === undefined) {
        return 0;
      }
      value = (value as Record<string, unknown>)[part];
    }
    
    // Преобразование в число
    if (typeof value === 'number') {
      return value;
    }
    
    if (typeof value === 'string') {
      // Попытка парсинга числа
      const parsed = parseFloat(value);
      if (!isNaN(parsed)) {
        return parsed;
      }
      
      // Хеш строки для категориальных значений
      return this.hashString(value);
    }
    
    if (typeof value === 'boolean') {
      return value ? 1 : 0;
    }
    
    return 0;
  }
  
  /**
   * Хеш строки в число
   */
  private hashString(str: string): number {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash) % 1000;
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС ANOMALY DETECTOR
// ============================================================================

/**
 * Anomaly Detector - ML обнаружение аномалий
 * 
 * Реализует:
 * - Statistical anomaly detection
 * - Isolation Forest
 * - Time-series анализ
 * - Адаптивное обучение
 * - Multi-feature анализ
 */
export class AnomalyDetector extends EventEmitter {
  private config: AnomalyDetectorConfig;
  private analyzer: StatisticalAnalyzer;
  private isolationForest: IsolationForest;
  private timeSeriesAnalyzer: TimeSeriesAnalyzer;
  private featureExtractor: FeatureExtractor;
  
  /** Обучающие данные */
  private trainingData: DataPoint[];
  /** Статистика признаков */
  private featureStats: Map<string, FeatureStatistics>;
  /** Временные ряды по признакам */
  private timeSeries: Map<string, TimeSeries>;
  /** Модель Isolation Forest */
  private ifModel: IsolationForestModel | null;
  
  /** Статистика */
  private statistics: DetectorStatistics;
  private detectionTimes: number[];
  private enabled: boolean;
  
  constructor(config: Partial<AnomalyDetectorConfig> = {}) {
    super();
    
    this.config = {
      modelType: config.modelType || 'hybrid',
      features: config.features || ['fields.responseTime', 'fields.statusCode'],
      anomalyThreshold: config.anomalyThreshold || 0.6,
      trainingPeriodHours: config.trainingPeriodHours || 24,
      retrainingFrequencyHours: config.retrainingFrequencyHours || 6,
      minSampleSize: config.minSampleSize || ANOMALY_THRESHOLDS.MIN_SAMPLE_SIZE,
      normalizationMethod: config.normalizationMethod || 'z-score',
      enableSeasonality: config.enableSeasonality !== false,
      seasonalityPeriodHours: config.seasonalityPeriodHours || 24,
      numTrees: config.numTrees || 100,
      sampleSize: config.sampleSize || 256,
      enableAdaptiveLearning: config.enableAdaptiveLearning !== false,
      adaptationRate: config.adaptationRate || 0.1
    };
    
    this.analyzer = new StatisticalAnalyzer();
    this.isolationForest = new IsolationForest();
    this.timeSeriesAnalyzer = new TimeSeriesAnalyzer();
    this.featureExtractor = new FeatureExtractor();
    
    // Инициализация хранилищ
    this.trainingData = [];
    this.featureStats = new Map();
    this.timeSeries = new Map();
    this.ifModel = null;
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.detectionTimes = [];
    this.enabled = true;
    
    // Запуск периодического переобучения
    this.startRetrainingSchedule();
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): DetectorStatistics {
    return {
      totalLogsProcessed: 0,
      anomaliesDetected: 0,
      byAnomalyType: {
        point: 0,
        contextual: 0,
        collective: 0
      },
      byFeature: {},
      falsePositives: 0,
      falseNegatives: 0,
      avgAnomalyScore: 0,
      avgDetectionTime: 0,
      p99DetectionTime: 0,
      trainingSampleSize: 0,
      lastRetraining: null
    };
  }
  
  /**
   * Добавление лога для обучения
   */
  addForTraining(log: LogEntry): void {
    const features = this.featureExtractor.extract(log, this.config.features);
    const timestamp = new Date(log.timestamp).getTime();
    
    this.trainingData.push({
      features,
      timestamp,
      log
    });
    
    // Ограничение размера обучающей выборки
    if (this.trainingData.length > ANOMALY_THRESHOLDS.MAX_SAMPLE_SIZE) {
      this.trainingData.shift();
    }
    
    // Обновление статистики признаков
    this.updateFeatureStats(features);
    
    // Обновление временных рядов
    if (this.config.enableSeasonality) {
      this.updateTimeSeries(features);
    }
  }
  
  /**
   * Пакетное добавление для обучения
   */
  addBatchForTraining(logs: LogEntry[]): void {
    for (const log of logs) {
      this.addForTraining(log);
    }
  }
  
  /**
   * Детектирование аномалии в логе
   */
  detect(log: LogEntry): AnomalyDetectionResult | null {
    if (!this.enabled) {
      return null;
    }
    
    const startTime = Date.now();
    this.statistics.totalLogsProcessed++;
    
    try {
      // Извлечение признаков
      const features = this.featureExtractor.extract(log, this.config.features);
      
      // Проверка минимального размера выборки
      if (this.trainingData.length < this.config.minSampleSize) {
        return null;
      }
      
      // Расчет anomaly scores
      const scores = this.calculateAnomalyScores(features);
      
      // Определение типа аномалии
      const anomalyType = this.determineAnomalyType(log, features, scores);
      
      // Проверка порога
      const isAnomaly = scores.combined >= this.config.anomalyThreshold;
      
      if (isAnomaly) {
        this.statistics.anomaliesDetected++;
        this.statistics.byAnomalyType[anomalyType]++;
        
        // Обновление статистики по признакам
        this.updateFeatureAnomalyStats(features, scores.contributions);
      }
      
      // Обновление статистики времени
      const detectionTime = Date.now() - startTime;
      this.updateDetectionTimeStats(detectionTime);
      
      // Обновление среднего anomaly score
      const totalScores = this.statistics.anomaliesDetected + this.statistics.totalLogsProcessed - this.statistics.anomaliesDetected;
      this.statistics.avgAnomalyScore = 
        (this.statistics.avgAnomalyScore * (totalScores - 1) + scores.combined) / totalScores;
      
      // Адаптивное обучение
      if (this.config.enableAdaptiveLearning && isAnomaly) {
        this.adaptToAnomaly(features);
      }
      
      // Эмиссия события
      if (isAnomaly) {
        this.emit('anomaly_detected', {
          log,
          score: scores.combined,
          type: anomalyType,
          contributions: scores.contributions
        });
      }
      
      return {
        isAnomaly,
        anomalyScore: scores.combined,
        anomalyType,
        contributingFeatures: scores.contributions,
        expectedValue: scores.expectedValue,
        actualValue: scores.actualValue,
        deviationSigma: scores.deviationSigma,
        context: this.buildContext(log)
      };
    } catch (error) {
      this.emit('detection_error', {
        logId: log.id,
        error
      });
      
      return null;
    }
  }
  
  /**
   * Пакетное детектирование
   */
  detectBatch(logs: LogEntry[]): AnomalyDetectionResult[] {
    return logs.map(log => this.detect(log)).filter((r): r is AnomalyDetectionResult => r !== null);
  }
  
  /**
   * Расчет anomaly scores
   */
  private calculateAnomalyScores(features: number[]): {
    combined: number;
    zscore: number;
    if: number;
    ts: number;
    expectedValue?: number;
    actualValue?: number;
    deviationSigma?: number;
    contributions: FeatureContribution[];
  } {
    let zscoreScore = 0.5;
    let ifScore = 0.5;
    let tsScore = 0.5;
    let expectedValue: number | undefined;
    let actualValue: number | undefined;
    let deviationSigma: number | undefined;
    
    // Z-score анализ
    const zscoreContributions: FeatureContribution[] = [];
    let maxZScore = 0;
    
    for (let i = 0; i < features.length; i++) {
      const featureName = this.config.features[i];
      const stats = this.featureStats.get(featureName);
      
      if (stats && stats.stdDev > 0) {
        const zScore = Math.abs(this.analyzer.calculateZScore(features[i], stats.mean, stats.stdDev));
        
        zscoreContributions.push({
          feature: featureName,
          contribution: zScore / ANOMALY_THRESHOLDS.Z_SCORE_CRITICAL,
          direction: features[i] > stats.mean ? 'increase' : 'decrease'
        });
        
        if (zScore > maxZScore) {
          maxZScore = zScore;
          expectedValue = stats.mean;
          actualValue = features[i];
          deviationSigma = zScore;
        }
      }
    }
    
    // Нормализация Z-score score (0-1)
    zscoreScore = Math.min(1, maxZScore / ANOMALY_THRESHOLDS.Z_SCORE_CRITICAL);
    
    // Isolation Forest score
    if (this.config.modelType === 'isolation_forest' || this.config.modelType === 'hybrid') {
      ifScore = this.isolationForest.score(features);
    }
    
    // Time-series score
    if (this.config.enableSeasonality && this.config.modelType === 'hybrid') {
      tsScore = this.calculateTimeSeriesAnomaly(features);
    }
    
    // Комбинированный score
    let combined: number;
    
    switch (this.config.modelType) {
      case 'zscore':
        combined = zscoreScore;
        break;
      case 'iqr':
        combined = zscoreScore; // IQR использует те же stats
        break;
      case 'isolation_forest':
        combined = ifScore;
        break;
      case 'hybrid':
        // Взвешенная комбинация
        combined = 0.4 * zscoreScore + 0.4 * ifScore + 0.2 * tsScore;
        break;
      default:
        combined = zscoreScore;
    }
    
    // Расчет вкладов признаков
    const contributions = zscoreContributions.sort((a, b) => b.contribution - a.contribution);
    
    return {
      combined,
      zscore: zscoreScore,
      if: ifScore,
      ts: tsScore,
      expectedValue,
      actualValue,
      deviationSigma,
      contributions
    };
  }
  
  /**
   * Расчет time-series anomaly score
   */
  private calculateTimeSeriesAnomaly(features: number[]): number {
    let maxScore = 0;
    
    for (let i = 0; i < features.length; i++) {
      const featureName = this.config.features[i];
      const series = this.timeSeries.get(featureName);
      
      if (series && series.values.length >= series.seasonalityPeriod * 2) {
        const forecast = this.timeSeriesAnalyzer.forecast(series);
        const residual = Math.abs(features[i] - forecast.value);
        
        // Нормализация residual
        const stdDev = this.analyzer.calculateStatistics(series.residual || []).stdDev;
        const score = stdDev > 0 ? Math.min(1, residual / (3 * stdDev)) : 0;
        
        if (score > maxScore) {
          maxScore = score;
        }
      }
    }
    
    return maxScore;
  }
  
  /**
   * Определение типа аномалии
   */
  private determineAnomalyType(log: LogEntry, features: number[], scores: unknown): 'point' | 'contextual' | 'collective' {
    // Point anomaly: экстремальное значение признака
    for (let i = 0; i < features.length; i++) {
      const stats = this.featureStats.get(this.config.features[i]);
      if (stats && stats.stdDev > 0) {
        const zScore = Math.abs(this.analyzer.calculateZScore(features[i], stats.mean, stats.stdDev));
        if (zScore > ANOMALY_THRESHOLDS.Z_SCORE_CRITICAL) {
          return 'point';
        }
      }
    }
    
    // Contextual anomaly: аномалия в контексте времени
    const hour = new Date(log.timestamp).getHours();
    const day = new Date(log.timestamp).getDay();
    
    if (hour < 6 || hour > 22 || day === 0 || day === 6) {
      return 'contextual';
    }
    
    // Collective anomaly: серия связанных событий
    return 'collective';
  }
  
  /**
   * Построение контекста аномалии
   */
  private buildContext(log: LogEntry): AnomalyContext {
    const date = new Date(log.timestamp);
    
    return {
      timeOfDay: `${date.getHours()}:${date.getMinutes().toString().padStart(2, '0')}`,
      dayOfWeek: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][date.getDay()],
      isHoliday: false, // Можно добавить проверку праздников
      isBusinessHours: date.getHours() >= 9 && date.getHours() <= 18 && date.getDay() >= 1 && date.getDay() <= 5,
      concurrentEvents: 0, // Можно добавить подсчет concurrent events
      historicalPattern: 'unknown'
    };
  }
  
  /**
   * Обновление статистики признаков
   */
  private updateFeatureStats(features: number[]): void {
    for (let i = 0; i < features.length; i++) {
      const featureName = this.config.features[i];
      const value = features[i];
      
      let stats = this.featureStats.get(featureName);
      
      if (!stats) {
        stats = {
          mean: value,
          stdDev: 0,
          min: value,
          max: value,
          q1: value,
          q3: value,
          iqr: 0,
          count: 1
        };
      } else {
        // Инкрементальное обновление статистики
        const oldMean = stats.mean;
        stats.count++;
        stats.mean = oldMean + (value - oldMean) / stats.count;
        stats.min = Math.min(stats.min, value);
        stats.max = Math.max(stats.max, value);
        
        // Инкрементальное обновление stdDev (Welford's algorithm)
        // Для простоты пересчитываем при достижении порога
        if (stats.count % 100 === 0 && stats.count >= 30) {
          this.recalculateFeatureStats(featureName);
        }
      }
      
      this.featureStats.set(featureName, stats);
    }
  }
  
  /**
   * Пересчет статистики признака
   */
  private recalculateFeatureStats(featureName: string): void {
    const values = this.trainingData.map(d => {
      const idx = this.config.features.indexOf(featureName);
      return idx >= 0 ? d.features[idx] : 0;
    });
    
    const stats = this.analyzer.calculateStatistics(values);
    this.featureStats.set(featureName, stats);
  }
  
  /**
   * Обновление временных рядов
   */
  private updateTimeSeries(features: number[]): void {
    const timestamp = Date.now();
    
    for (let i = 0; i < features.length; i++) {
      const featureName = this.config.features[i];
      let series = this.timeSeries.get(featureName);
      
      if (!series) {
        series = {
          values: [],
          timestamps: [],
          seasonalityPeriod: this.config.seasonalityPeriodHours * 3600 // часов в секундах
        };
      }
      
      series.values.push(features[i]);
      series.timestamps.push(timestamp);
      
      // Ограничение размера
      const maxPoints = this.config.seasonalityPeriodHours * 60; // точек в час
      if (series.values.length > maxPoints * 48) { // 48 часов
        series.values = series.values.slice(-maxPoints * 48);
        series.timestamps = series.timestamps.slice(-maxPoints * 48);
      }
      
      this.timeSeries.set(featureName, series);
    }
  }
  
  /**
   * Обновление статистики аномалий по признакам
   */
  private updateFeatureAnomalyStats(features: number[], contributions: FeatureContribution[]): void {
    for (const contrib of contributions) {
      if (contrib.contribution > 0.5) {
        this.statistics.byFeature[contrib.feature] = 
          (this.statistics.byFeature[contrib.feature] || 0) + 1;
      }
    }
  }
  
  /**
   * Адаптация к аномалии
   */
  private adaptToAnomaly(features: number[]): void {
    // Медленное включение аномалии в обучающую выборку
    // Это позволяет модели адаптироваться к новым нормальным паттернам
    
    const adaptationWeight = this.config.adaptationRate;
    
    for (let i = 0; i < features.length; i++) {
      const featureName = this.config.features[i];
      const stats = this.featureStats.get(featureName);
      
      if (stats) {
        stats.mean = stats.mean * (1 - adaptationWeight) + features[i] * adaptationWeight;
        this.featureStats.set(featureName, stats);
      }
    }
  }
  
  /**
   * Переобучение модели
   */
  retrain(): void {
    if (this.trainingData.length < this.config.minSampleSize) {
      return;
    }
    
    // Пересчет статистики всех признаков
    for (const featureName of this.config.features) {
      this.recalculateFeatureStats(featureName);
    }
    
    // Переобучение Isolation Forest
    if (this.config.modelType === 'isolation_forest' || this.config.modelType === 'hybrid') {
      const data = this.trainingData.map(d => d.features);
      this.isolationForest.fit(data, this.config.numTrees, this.config.sampleSize);
    }
    
    this.statistics.lastRetraining = new Date().toISOString();
    this.statistics.trainingSampleSize = this.trainingData.length;
    
    this.emit('retrained', {
      sampleSize: this.trainingData.length,
      featureCount: this.config.features.length
    });
  }
  
  /**
   * Запуск расписания переобучения
   */
  private startRetrainingSchedule(): void {
    const interval = this.config.retrainingFrequencyHours * 3600 * 1000;
    
    setInterval(() => {
      this.retrain();
    }, interval);
  }
  
  /**
   * Обновление статистики времени детекта
   */
  private updateDetectionTimeStats(time: number): void {
    this.detectionTimes.push(time);
    
    if (this.detectionTimes.length > 1000) {
      this.detectionTimes.shift();
    }
    
    this.statistics.avgDetectionTime = 
      this.detectionTimes.reduce((a, b) => a + b, 0) / this.detectionTimes.length;
    
    const sorted = [...this.detectionTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99DetectionTime = sorted[p99Index] || 0;
  }
  
  // ==========================================================================
  // УПРАВЛЕНИЕ И СТАТИСТИКА
  // ==========================================================================
  
  /**
   * Получение статистики
   */
  getStatistics(): DetectorStatistics {
    return { ...this.statistics };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
    this.detectionTimes = [];
  }
  
  /**
   * Маркировка ложного срабатывания
   */
  markFalsePositive(): void {
    this.statistics.falsePositives++;
  }
  
  /**
   * Маркировка пропущенной аномалии
   */
  markFalseNegative(): void {
    this.statistics.falseNegatives++;
  }
  
  /**
   * Получение статистики признаков
   */
  getFeatureStats(): Map<string, FeatureStatistics> {
    return new Map(this.featureStats);
  }
  
  /**
   * Получение размера обучающей выборки
   */
  getTrainingSampleSize(): number {
    return this.trainingData.length;
  }
  
  /**
   * Очистка обучающих данных
   */
  clearTrainingData(): void {
    this.trainingData = [];
    this.featureStats.clear();
    this.timeSeries.clear();
    this.ifModel = null;
  }
  
  /**
   * Включение детектора
   */
  enable(): void {
    this.enabled = true;
  }
  
  /**
   * Выключение детектора
   */
  disable(): void {
    this.enabled = false;
  }
  
  /**
   * Проверка включен ли детектор
   */
  isEnabled(): boolean {
    return this.enabled;
  }
  
  /**
   * Обновление конфигурации
   */
  updateConfig(config: Partial<AnomalyDetectorConfig>): void {
    this.config = { ...this.config, ...config };
  }
  
  /**
   * Экспорт модели
   */
  exportModel(): string {
    return JSON.stringify({
      config: this.config,
      featureStats: Array.from(this.featureStats.entries()),
      trainingSampleSize: this.trainingData.length,
      lastRetraining: this.statistics.lastRetraining
    });
  }
  
  /**
   * Импорт модели
   */
  importModel(modelJson: string): void {
    try {
      const model = JSON.parse(modelJson);
      
      if (model.featureStats) {
        this.featureStats = new Map(model.featureStats);
      }
      
      if (model.config) {
        this.config = { ...this.config, ...model.config };
      }
    } catch (error) {
      this.emit('import_error', { error });
    }
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default AnomalyDetector;
