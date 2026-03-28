/**
 * ============================================================================
 * ML MODELS — МАШИННОЕ ОБУЧЕНИЕ ДЛЯ THREAT DETECTION
 * ============================================================================
 * Полная реализация ML моделей на TensorFlow.js для:
 * - Обнаружения аномалий (Isolation Forest, Autoencoder)
 * - Классификации угроз (Neural Network)
 * - Временных рядов (LSTM)
 * - UEBA (User Behavior Analytics)
 * ============================================================================
 */

import * as tf from '@tensorflow/tfjs-node';
import {
  MLModelConfig,
  MLPrediction,
  TrainingData,
  ModelMetrics,
  MLModelType,
  ThreatSeverity,
  ThreatCategory
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';
import { EventEmitter } from 'events';

/**
 * Интерфейс для всех ML моделей
 */
interface IMLModel {
  modelId: string;
  train(data: TrainingData): Promise<ModelMetrics>;
  predict(input: Record<string, number>): Promise<MLPrediction>;
  predictBatch(inputs: Record<string, number>[]): Promise<MLPrediction[]>;
  save(path: string): Promise<void>;
  load(path: string): Promise<void>;
  getModelMetrics(): ModelMetrics;
  dispose(): void;
}

/**
 * ============================================================================
 * ISOLATION FOREST — ОБНАРУЖЕНИЕ АНОМАЛИЙ
 * ============================================================================
 * Алгоритм для обнаружения аномалий через изоляцию точек данных
 * Реализация на TensorFlow.js для производительности
 */
export class IsolationForest extends EventEmitter implements IMLModel {
  public modelId: string;
  public config: MLModelConfig;
  public modelType: MLModelType = MLModelType.ISOLATION_FOREST;

  // Параметры модели
  private nTrees: number = 100;
  private sampleSize: number = 256;
  private threshold: number = 0.6;
  private maxDepth: number = 8;
  
  // Обученные параметры
  private trees: IsolationTree[] = [];
  private featureMeans: number[] = [];
  private featureStds: number[] = [];
  private isTrained: boolean = false;

  // Метрики
  private metrics: ModelMetrics = {
    modelId: '',
    trainingTime: 0,
    lastTrained: new Date()
  };

  // Внутренние метрики качества
  private internalMetrics = {
    precision: 0,
    recall: 0,
    f1Score: 0,
    auc: 0,
    contamination: 0.1
  };

  constructor(config: MLModelConfig) {
    super();
    this.modelId = config.modelId || uuidv4();
    this.config = config;

    // Извлечение гиперпараметров
    if (config.hyperparameters.nTrees) {
      this.nTrees = config.hyperparameters.nTrees as number;
    }
    if (config.hyperparameters.sampleSize) {
      this.sampleSize = config.hyperparameters.sampleSize as number;
    }
    if (config.hyperparameters.threshold) {
      this.threshold = config.hyperparameters.threshold as number;
    }
    if (config.hyperparameters.maxDepth) {
      this.maxDepth = config.hyperparameters.maxDepth as number;
    }
    if (config.hyperparameters.contamination) {
      this.internalMetrics.contamination = config.hyperparameters.contamination as number;
    }
  }

  /**
   * Обучение модели Isolation Forest
   */
  async train(data: TrainingData): Promise<ModelMetrics> {
    const startTime = Date.now();
    const features = data.features;
    
    if (features.length === 0) {
      throw new Error('Training data is empty');
    }

    const nFeatures = features[0].length;

    // Вычисление статистик для нормализации
    this.featureMeans = new Array(nFeatures).fill(0);
    this.featureStds = new Array(nFeatures).fill(0);

    // Вычисление среднего
    for (let i = 0; i < features.length; i++) {
      for (let j = 0; j < nFeatures; j++) {
        this.featureMeans[j] += features[i][j];
      }
    }
    for (let j = 0; j < nFeatures; j++) {
      this.featureMeans[j] /= features.length;
    }

    // Вычисление стандартного отклонения
    for (let i = 0; i < features.length; i++) {
      for (let j = 0; j < nFeatures; j++) {
        this.featureStds[j] += Math.pow(features[i][j] - this.featureMeans[j], 2);
      }
    }
    for (let j = 0; j < nFeatures; j++) {
      this.featureStds[j] = Math.sqrt(this.featureStds[j] / features.length) || 1;
    }

    // Нормализация данных
    const normalizedData = features.map(row =>
      row.map((val, idx) => (val - this.featureMeans[idx]) / this.featureStds[idx])
    );

    // Построение деревьев изоляции
    this.trees = [];
    for (let i = 0; i < this.nTrees; i++) {
      const sample = this.randomSample(normalizedData, this.sampleSize);
      const tree = this.buildTree(sample, 0);
      this.trees.push(tree);
    }

    this.isTrained = true;

    const trainingTime = Date.now() - startTime;

    // Вычисление метрик на тренировочных данных
    const predictions = await this.predictBatch(features.map((_, idx) => {
      const input: Record<string, number> = {};
      features[idx].forEach((val, i) => input[`feature_${i}`] = val);
      return input;
    }));

    this.calculateMetrics(predictions, data.labels);

    this.metrics = {
      modelId: this.modelId,
      modelType: this.modelType,
      trainingTime,
      lastTrained: new Date(),
      accuracy: this.internalMetrics.f1Score,
      precision: this.internalMetrics.precision,
      recall: this.internalMetrics.recall,
      f1Score: this.internalMetrics.f1Score,
      auc: this.internalMetrics.auc,
      trainingSamples: features.length,
      features: nFeatures,
      hyperparameters: {
        nTrees: this.nTrees,
        sampleSize: this.sampleSize,
        threshold: this.threshold,
        maxDepth: this.maxDepth
      }
    };

    this.emit('trained', this.metrics);
    return this.metrics;
  }

  /**
   * Предсказание для одной точки
   */
  async predict(input: Record<string, number>): Promise<MLPrediction> {
    if (!this.isTrained) {
      throw new Error('Model not trained');
    }

    const featureVector = Object.values(input);
    const normalizedFeatures = featureVector.map((val, idx) =>
      (val - this.featureMeans[idx]) / this.featureStds[idx]
    );

    // Вычисление anomaly score
    let totalPathLength = 0;
    for (const tree of this.trees) {
      totalPathLength += this.pathLength(normalizedFeatures, tree, 0);
    }
    const avgPathLength = totalPathLength / this.trees.length;

    // Anomaly score формула
    const n = this.sampleSize;
    const c = 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
    const anomalyScore = Math.pow(2, -avgPathLength / c);

    const isAnomaly = anomalyScore > this.threshold;

    return {
      prediction: isAnomaly ? 1 : 0,
      confidence: isAnomaly ? anomalyScore : 1 - anomalyScore,
      scores: {
        anomalyScore,
        threshold: this.threshold,
        avgPathLength
      },
      metadata: {
        modelId: this.modelId,
        modelType: this.modelType,
        timestamp: new Date(),
        featureImportance: this.calculateFeatureImportance(featureVector)
      }
    };
  }

  /**
   * Пакетное предсказание
   */
  async predictBatch(inputs: Record<string, number>[]): Promise<MLPrediction[]> {
    const predictions: MLPrediction[] = [];
    for (const input of inputs) {
      predictions.push(await this.predict(input));
    }
    return predictions;
  }

  /**
   * Сохранение модели
   */
  async save(path: string): Promise<void> {
    const modelData = {
      modelId: this.modelId,
      modelType: this.modelType,
      config: this.config,
      trees: this.trees,
      featureMeans: this.featureMeans,
      featureStds: this.featureStds,
      threshold: this.threshold,
      metrics: this.metrics,
      internalMetrics: this.internalMetrics,
      isTrained: this.isTrained
    };

    await tf.io.saveModel(`file://${path}`, tf.tensor([0]));
    // Сохраняем данные модели в JSON
    const fs = require('fs');
    fs.writeFileSync(`${path}.json`, JSON.stringify(modelData, null, 2));
  }

  /**
   * Загрузка модели
   */
  async load(path: string): Promise<void> {
    const fs = require('fs');
    const modelData = JSON.parse(fs.readFileSync(`${path}.json`, 'utf8'));

    this.modelId = modelData.modelId;
    this.config = modelData.config;
    this.trees = modelData.trees;
    this.featureMeans = modelData.featureMeans;
    this.featureStds = modelData.featureStds;
    this.threshold = modelData.threshold;
    this.metrics = modelData.metrics;
    this.internalMetrics = modelData.internalMetrics;
    this.isTrained = modelData.isTrained;
  }

  /**
   * Получение метрик модели
   */
  getModelMetrics(): ModelMetrics {
    return { ...this.metrics };
  }

  /**
   * Очистка ресурсов
   */
  dispose(): void {
    this.trees = [];
    this.emit('disposed');
  }

  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Построение дерева изоляции
   */
  private buildTree(data: number[][], currentDepth: number): IsolationTree {
    const nSamples = data.length;
    const nFeatures = data[0].length;

    // Базовый случай: достигнута максимальная глубина или одна точка
    if (currentDepth >= this.maxDepth || nSamples <= 1) {
      return { type: 'leaf', size: nSamples, depth: currentDepth };
    }

    // Случайный выбор признака
    const featureIndex = Math.floor(Math.random() * nFeatures);

    // Получение мин и макс для выбранного признака
    const featureValues = data.map(row => row[featureIndex]);
    const minVal = Math.min(...featureValues);
    const maxVal = Math.max(...featureValues);

    // Базовый случай: все значения одинаковы
    if (minVal === maxVal) {
      return { type: 'leaf', size: nSamples, depth: currentDepth };
    }

    // Случайный split point
    const splitValue = minVal + Math.random() * (maxVal - minVal);

    // Разделение данных
    const leftData: number[][] = [];
    const rightData: number[][] = [];

    for (const row of data) {
      if (row[featureIndex] < splitValue) {
        leftData.push(row);
      } else {
        rightData.push(row);
      }
    }

    // Рекурсивное построение поддеревьев
    const leftSubtree = this.buildTree(leftData, currentDepth + 1);
    const rightSubtree = this.buildTree(rightData, currentDepth + 1);

    return {
      type: 'node',
      featureIndex,
      splitValue,
      left: leftSubtree,
      right: rightSubtree,
      depth: currentDepth
    };
  }

  /**
   * Вычисление длины пути для точки
   */
  private pathLength(point: number[], node: IsolationTree, currentLength: number): number {
    if (node.type === 'leaf') {
      // Коррекция для листьев
      const n = node.size;
      if (n <= 1) return currentLength;
      
      const c = 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
      return currentLength + c;
    }

    // Переход к соответствующему поддереву
    if (point[node.featureIndex] < node.splitValue) {
      return this.pathLength(point, node.left, currentLength + 1);
    } else {
      return this.pathLength(point, node.right, currentLength + 1);
    }
  }

  /**
   * Случайная выборка
   */
  private randomSample(data: number[][], sampleSize: number): number[][] {
    const shuffled = [...data].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, Math.min(sampleSize, data.length));
  }

  /**
   * Вычисление важности признаков
   */
  private calculateFeatureImportance(featureVector: number[]): Record<string, number> {
    const importance: Record<string, number> = {};
    
    featureVector.forEach((val, idx) => {
      const zScore = Math.abs((val - this.featureMeans[idx]) / this.featureStds[idx]);
      importance[`feature_${idx}`] = zScore;
    });

    return importance;
  }

  /**
   * Вычисление метрик качества
   */
  private calculateMetrics(predictions: MLPrediction[], labels?: number[]): void {
    if (!labels || labels.length === 0) {
      // Без ground truth — используем эвристики
      const anomalyScores = predictions.map(p => p.scores?.anomalyScore || 0);
      const meanScore = anomalyScores.reduce((a, b) => a + b, 0) / anomalyScores.length;
      const variance = anomalyScores.reduce((sum, score) => sum + Math.pow(score - meanScore, 2), 0) / anomalyScores.length;
      
      this.internalMetrics.auc = 0.5 + (variance * 2); // Эвристика
      this.internalMetrics.f1Score = 0.7; // Default
      return;
    }

    // Вычисление precision, recall, F1
    let tp = 0, fp = 0, fn = 0, tn = 0;

    for (let i = 0; i < predictions.length; i++) {
      const predicted = predictions[i].prediction === 1;
      const actual = labels[i] === 1;

      if (predicted && actual) tp++;
      else if (predicted && !actual) fp++;
      else if (!predicted && actual) fn++;
      else tn++;
    }

    const precision = tp / (tp + fp) || 0;
    const recall = tp / (tp + fn) || 0;
    this.internalMetrics.precision = precision;
    this.internalMetrics.recall = recall;
    this.internalMetrics.f1Score = 2 * (precision * recall) / (precision + recall) || 0;
    this.internalMetrics.auc = (recall + (tn / (tn + fp) || 0)) / 2;
  }
}

/**
 * Тип узла дерева изоляции
 */
type IsolationTree = 
  | { type: 'leaf'; size: number; depth: number }
  | {
      type: 'node';
      featureIndex: number;
      splitValue: number;
      left: IsolationTree;
      right: IsolationTree;
      depth: number;
    };

/**
 * ============================================================================
 * AUTOENCODER — НЕЙРОННАЯ СЕТЬ ДЛЯ ОБНАРУЖЕНИЯ АНОМАЛИЙ
 * ============================================================================
 * Глубокое обучение для обнаружения сложных аномалий
 */
export class AutoencoderModel extends EventEmitter implements IMLModel {
  public modelId: string;
  public config: MLModelConfig;
  public modelType: MLModelType = MLModelType.AUTOENCODER;

  private model: tf.LayersModel | null = null;
  private inputDim: number = 0;
  private isTrained: boolean = false;
  private reconstructionThreshold: number = 0;

  private metrics: ModelMetrics = {
    modelId: '',
    trainingTime: 0,
    lastTrained: new Date()
  };

  private internalMetrics = {
    mse: 0,
    mae: 0,
    loss: 0
  };

  constructor(config: MLModelConfig) {
    super();
    this.modelId = config.modelId || uuidv4();
    this.config = config;
  }

  /**
   * Построение архитектуры автоэнкодера
   */
  private buildModel(inputDim: number): tf.LayersModel {
    const model = tf.sequential();

    // Encoder
    model.add(tf.layers.dense({
      inputShape: [inputDim],
      units: 64,
      activation: 'relu',
      kernelInitializer: 'heNormal',
      kernelRegularizer: 'l2'
    }));
    model.add(tf.layers.dropout({ rate: 0.3 }));
    
    model.add(tf.layers.dense({
      units: 32,
      activation: 'relu',
      kernelInitializer: 'heNormal'
    }));

    // Bottleneck
    model.add(tf.layers.dense({
      units: 16,
      activation: 'relu',
      kernelInitializer: 'heNormal'
    }));

    // Decoder
    model.add(tf.layers.dense({
      units: 32,
      activation: 'relu',
      kernelInitializer: 'heNormal'
    }));

    model.add(tf.layers.dense({
      units: 64,
      activation: 'relu',
      kernelInitializer: 'heNormal'
    }));

    // Output layer
    model.add(tf.layers.dense({
      units: inputDim,
      activation: 'linear',
      kernelInitializer: 'heNormal'
    }));

    model.compile({
      optimizer: tf.train.adam(0.001),
      loss: 'meanSquaredError',
      metrics: ['mae']
    });

    return model;
  }

  /**
   * Обучение автоэнкодера
   */
  async train(data: TrainingData): Promise<ModelMetrics> {
    const startTime = Date.now();
    const features = data.features;
    
    if (features.length === 0) {
      throw new Error('Training data is empty');
    }

    this.inputDim = features[0].length;

    // Построение модели
    this.model = this.buildModel(this.inputDim);

    // Подготовка данных
    const inputTensor = tf.tensor2d(features);

    // Нормализация
    const { mean, std } = this.normalizeStats(features);
    const normalizedInput = inputTensor.sub(mean).div(std);

    // Обучение
    const history = await this.model!.fit(normalizedInput, normalizedInput, {
      epochs: this.config.hyperparameters.epochs as number || 50,
      batchSize: this.config.hyperparameters.batchSize as number || 32,
      validationSplit: 0.2,
      verbose: 0,
      callbacks: {
        onEpochEnd: (epoch, logs) => {
          if (epoch % 10 === 0) {
            this.emit('epoch', { epoch, loss: logs?.loss });
          }
        }
      }
    });

    // Вычисление порога реконструкции
    const predictions = this.model!.predict(normalizedInput) as tf.Tensor;
    const reconstructionErrors = tf.metrics.meanSquaredError(normalizedInput, predictions);
    const errorValues = reconstructionErrors.dataSync();
    
    // Порог = mean + 2*std
    const meanError = errorValues.reduce((a, b) => a + b, 0) / errorValues.length;
    const stdError = Math.sqrt(
      errorValues.reduce((sum, val) => sum + Math.pow(val - meanError, 2), 0) / errorValues.length
    );
    this.reconstructionThreshold = meanError + 2 * stdError;

    // Очистка
    inputTensor.dispose();
    normalizedInput.dispose();
    predictions.dispose();
    reconstructionErrors.dispose();

    this.isTrained = true;

    const finalLogs = history.history;
    const finalLoss = finalLogs.loss[finalLogs.loss.length - 1];

    this.internalMetrics = {
      mse: finalLoss,
      mae: finalLogs.mae[finalLogs.mae.length - 1],
      loss: finalLoss
    };

    this.metrics = {
      modelId: this.modelId,
      modelType: this.modelType,
      trainingTime: Date.now() - startTime,
      lastTrained: new Date(),
      accuracy: 1 - finalLoss,
      loss: finalLoss,
      trainingSamples: features.length,
      features: this.inputDim,
      hyperparameters: {
        epochs: this.config.hyperparameters.epochs,
        batchSize: this.config.hyperparameters.batchSize
      }
    };

    this.emit('trained', this.metrics);
    return this.metrics;
  }

  /**
   * Предсказание аномалии
   */
  async predict(input: Record<string, number>): Promise<MLPrediction> {
    if (!this.isTrained || !this.model) {
      throw new Error('Model not trained');
    }

    const featureVector = Object.values(input);
    
    if (featureVector.length !== this.inputDim) {
      throw new Error(`Expected ${this.inputDim} features, got ${featureVector.length}`);
    }

    const inputTensor = tf.tensor2d([featureVector]);
    const { mean, std } = this.normalizeStats([featureVector]);
    const normalizedInput = inputTensor.sub(mean).div(std);

    const prediction = this.model!.predict(normalizedInput) as tf.Tensor;
    const reconstructionError = tf.metrics.meanSquaredError(normalizedInput, prediction);
    const errorValue = reconstructionError.dataSync()[0];

    const isAnomaly = errorValue > this.reconstructionThreshold;

    // Очистка
    inputTensor.dispose();
    normalizedInput.dispose();
    prediction.dispose();
    reconstructionError.dispose();

    return {
      prediction: isAnomaly ? 1 : 0,
      confidence: isAnomaly 
        ? Math.min(1, errorValue / this.reconstructionThreshold)
        : 1 - (errorValue / this.reconstructionThreshold),
      scores: {
        reconstructionError: errorValue,
        threshold: this.reconstructionThreshold
      },
      metadata: {
        modelId: this.modelId,
        modelType: this.modelType,
        timestamp: new Date()
      }
    };
  }

  /**
   * Пакетное предсказание
   */
  async predictBatch(inputs: Record<string, number>[]): Promise<MLPrediction[]> {
    const predictions: MLPrediction[] = [];
    for (const input of inputs) {
      predictions.push(await this.predict(input));
    }
    return predictions;
  }

  /**
   * Сохранение модели
   */
  async save(path: string): Promise<void> {
    if (!this.model) {
      throw new Error('No model to save');
    }
    await this.model.save(`file://${path}`);
  }

  /**
   * Загрузка модели
   */
  async load(path: string): Promise<void> {
    this.model = await tf.loadLayersModel(`file://${path}/model.json`) as tf.LayersModel;
    this.inputDim = this.model.inputs[0].shape[1] as number;
    this.isTrained = true;
  }

  /**
   * Получение метрик
   */
  getModelMetrics(): ModelMetrics {
    return { ...this.metrics };
  }

  /**
   * Очистка ресурсов
   */
  dispose(): void {
    if (this.model) {
      this.model.dispose();
      this.model = null;
    }
    this.emit('disposed');
  }

  /**
   * Нормализация данных
   */
  private normalizeStats(data: number[][]): { mean: tf.Tensor; std: tf.Tensor } {
    const tensor = tf.tensor2d(data);
    const mean = tensor.mean(0);
    const std = tensor.sub(mean).square().mean(0).sqrt().add(1e-8);
    tensor.dispose();
    return { mean, std };
  }
}

/**
 * ============================================================================
 * LSTM — РЕКУРРЕНТНАЯ СЕТЬ ДЛЯ ВРЕМЕННЫХ РЯДОВ
 * ============================================================================
 * Long Short-Term Memory для анализа последовательностей событий
 */
export class LSTMModel extends EventEmitter implements IMLModel {
  public modelId: string;
  public config: MLModelConfig;
  public modelType: MLModelType = MLModelType.LSTM;

  private model: tf.LayersModel | null = null;
  private sequenceLength: number = 0;
  private featureDim: number = 0;
  private isTrained: boolean = false;
  private anomalyThreshold: number = 0;

  private metrics: ModelMetrics = {
    modelId: '',
    trainingTime: 0,
    lastTrained: new Date()
  };

  constructor(config: MLModelConfig) {
    super();
    this.modelId = config.modelId || uuidv4();
    this.config = config;
    this.sequenceLength = config.hyperparameters.sequenceLength as number || 10;
  }

  /**
   * Построение LSTM модели
   */
  private buildModel(): tf.LayersModel {
    const model = tf.sequential();

    // LSTM слои
    model.add(tf.layers.lstm({
      inputShape: [this.sequenceLength, this.featureDim],
      units: 128,
      returnSequences: true,
      dropout: 0.2,
      recurrentDropout: 0.2
    }));

    model.add(tf.layers.lstm({
      units: 64,
      returnSequences: false,
      dropout: 0.2,
      recurrentDropout: 0.2
    }));

    // Dense слои
    model.add(tf.layers.dense({
      units: 32,
      activation: 'relu',
      kernelRegularizer: 'l2'
    }));

    model.add(tf.layers.dropout({ rate: 0.3 }));

    // Output
    model.add(tf.layers.dense({
      units: 1,
      activation: 'sigmoid'
    }));

    model.compile({
      optimizer: tf.train.adam(0.001),
      loss: 'binaryCrossentropy',
      metrics: ['accuracy']
    });

    return model;
  }

  /**
   * Обучение LSTM
   */
  async train(data: TrainingData): Promise<ModelMetrics> {
    const startTime = Date.now();

    if (data.features.length === 0) {
      throw new Error('Training data is empty');
    }

    this.featureDim = data.features[0].length;

    // Построение последовательностей
    const { sequences, labels } = this.createSequences(data.features, data.labels);

    if (sequences.length === 0) {
      throw new Error('Not enough data for sequence creation');
    }

    this.model = this.buildModel();

    const inputTensor = tf.tensor3d(sequences);
    const labelTensor = tf.tensor2d(labels, [labels.length, 1]);

    // Обучение
    const history = await this.model!.fit(inputTensor, labelTensor, {
      epochs: this.config.hyperparameters.epochs as number || 30,
      batchSize: this.config.hyperparameters.batchSize as number || 16,
      validationSplit: 0.2,
      verbose: 0,
      callbacks: {
        onEpochEnd: (epoch, logs) => {
          if (epoch % 5 === 0) {
            this.emit('epoch', { epoch, loss: logs?.loss, acc: logs?.acc });
          }
        }
      }
    });

    // Вычисление порога
    const predictions = this.model!.predict(inputTensor) as tf.Tensor;
    const predValues = predictions.dataSync();
    
    const meanPred = predValues.reduce((a, b) => a + b, 0) / predValues.length;
    const stdPred = Math.sqrt(
      predValues.reduce((sum, val) => sum + Math.pow(val - meanPred, 2), 0) / predValues.length
    );
    this.anomalyThreshold = meanPred + 2 * stdPred;

    // Очистка
    inputTensor.dispose();
    labelTensor.dispose();
    predictions.dispose();

    this.isTrained = true;

    const finalLogs = history.history;
    const finalLoss = finalLogs.loss[finalLogs.loss.length - 1];
    const finalAcc = finalLogs.acc[finalLogs.acc.length - 1];

    this.metrics = {
      modelId: this.modelId,
      modelType: this.modelType,
      trainingTime: Date.now() - startTime,
      lastTrained: new Date(),
      accuracy: typeof finalAcc === 'number' ? finalAcc : (finalAcc as tf.Tensor).dataSync()[0],
      loss: typeof finalLoss === 'number' ? finalLoss : (finalLoss as tf.Tensor).dataSync()[0],
      trainingSamples: sequences.length,
      features: this.featureDim,
      hyperparameters: {
        epochs: this.config.hyperparameters.epochs,
        batchSize: this.config.hyperparameters.batchSize,
        sequenceLength: this.sequenceLength
      }
    };

    this.emit('trained', this.metrics);
    return this.metrics;
  }

  /**
   * Предсказание
   */
  async predict(input: Record<string, number>): Promise<MLPrediction> {
    if (!this.isTrained || !this.model) {
      throw new Error('Model not trained');
    }

    // Преобразование входа в последовательность
    const featureVector = Object.values(input);
    const sequence = this.createSingleSequence(featureVector);

    const inputTensor = tf.tensor3d([sequence]);
    const prediction = this.model!.predict(inputTensor) as tf.Tensor;
    const predValue = prediction.dataSync()[0];

    const isAnomaly = predValue > this.anomalyThreshold;

    inputTensor.dispose();
    prediction.dispose();

    return {
      modelId: this.modelId,
      timestamp: new Date(),
      input,
      prediction: isAnomaly ? 1 : 0,
      confidence: predValue,
      isAnomaly,
      anomalyScore: predValue,
      scores: {
        anomalyScore: predValue,
        threshold: this.anomalyThreshold
      }
    };
  }

  /**
   * Пакетное предсказание
   */
  async predictBatch(inputs: Record<string, number>[]): Promise<MLPrediction[]> {
    const predictions: MLPrediction[] = [];
    for (const input of inputs) {
      predictions.push(await this.predict(input));
    }
    return predictions;
  }

  /**
   * Сохранение модели
   */
  async save(path: string): Promise<void> {
    if (!this.model) {
      throw new Error('No model to save');
    }
    await this.model.save(`file://${path}`);
  }

  /**
   * Загрузка модели
   */
  async load(path: string): Promise<void> {
    this.model = await tf.loadLayersModel(`file://${path}/model.json`) as tf.LayersModel;
    this.isTrained = true;
  }

  /**
   * Получение метрик
   */
  getModelMetrics(): ModelMetrics {
    return { ...this.metrics };
  }

  /**
   * Очистка ресурсов
   */
  dispose(): void {
    if (this.model) {
      this.model.dispose();
      this.model = null;
    }
    this.emit('disposed');
  }

  /**
   * Создание последовательностей
   */
  private createSequences(features: number[][], labels?: number[]): { sequences: number[][][]; labels: number[] } {
    const sequences: number[][][] = [];
    const sequenceLabels: number[] = [];

    for (let i = this.sequenceLength; i < features.length; i++) {
      const sequence: number[][] = [];
      for (let j = i - this.sequenceLength; j < i; j++) {
        sequence.push(features[j]);
      }
      sequences.push(sequence);
      
      if (labels) {
        sequenceLabels.push(labels[i]);
      } else {
        sequenceLabels.push(0);
      }
    }

    return { sequences, labels: sequenceLabels };
  }

  /**
   * Создание одиночной последовательности
   */
  private createSingleSequence(featureVector: number[]): number[][] {
    const sequence: number[][] = [];
    for (let i = 0; i < this.sequenceLength; i++) {
      sequence.push(featureVector);
    }
    return sequence;
  }
}

/**
 * ============================================================================
 * NEURAL NETWORK — КЛАССИФИКАЦИЯ УГРОЗ
 * ============================================================================
 * Полносвязная нейронная сеть для классификации типов угроз
 */
export class NeuralNetworkClassifier extends EventEmitter implements IMLModel {
  public modelId: string;
  public config: MLModelConfig;
  public modelType: MLModelType = MLModelType.RANDOM_FOREST;

  private model: tf.LayersModel | null = null;
  private inputDim: number = 0;
  private numClasses: number = 0;
  private isTrained: boolean = false;
  private classLabels: string[] = [];

  private metrics: ModelMetrics = {
    modelId: '',
    trainingTime: 0,
    lastTrained: new Date()
  };

  constructor(config: MLModelConfig) {
    super();
    this.modelId = config.modelId || uuidv4();
    this.config = config;
    const labels = config.hyperparameters.classLabels;
    this.classLabels = Array.isArray(labels) ? labels : [];
    this.numClasses = this.classLabels.length;
  }

  /**
   * Построение нейронной сети
   */
  private buildModel(): tf.LayersModel {
    const model = tf.sequential();

    model.add(tf.layers.dense({
      inputShape: [this.inputDim],
      units: 256,
      activation: 'relu',
      kernelInitializer: 'heNormal',
      kernelRegularizer: 'l2'
    }));
    model.add(tf.layers.dropout({ rate: 0.4 }));

    model.add(tf.layers.dense({
      units: 128,
      activation: 'relu',
      kernelInitializer: 'heNormal'
    }));
    model.add(tf.layers.dropout({ rate: 0.3 }));

    model.add(tf.layers.dense({
      units: 64,
      activation: 'relu',
      kernelInitializer: 'heNormal'
    }));

    model.add(tf.layers.dense({
      units: this.numClasses,
      activation: 'softmax'
    }));

    model.compile({
      optimizer: tf.train.adam(0.001),
      loss: 'categoricalCrossentropy',
      metrics: ['accuracy']
    });

    return model;
  }

  /**
   * Обучение классификатора
   */
  async train(data: TrainingData): Promise<ModelMetrics> {
    const startTime = Date.now();

    if (data.features.length === 0) {
      throw new Error('Training data is empty');
    }

    this.inputDim = data.features[0].length;

    if (this.numClasses === 0) {
      this.numClasses = Math.max(...(data.labels || [0])) + 1;
    }

    this.model = this.buildModel();

    const inputTensor = tf.tensor2d(data.features);
    
    // One-hot encoding labels
    const labelsOneHot = tf.oneHot(
      tf.tensor1d(data.labels || [], 'int32'),
      this.numClasses
    );

    const history = await this.model!.fit(inputTensor, labelsOneHot, {
      epochs: this.config.hyperparameters.epochs as number || 50,
      batchSize: this.config.hyperparameters.batchSize as number || 32,
      validationSplit: 0.2,
      verbose: 0,
      callbacks: {
        onEpochEnd: (epoch, logs) => {
          if (epoch % 10 === 0) {
            this.emit('epoch', { epoch, loss: logs?.loss, acc: logs?.acc });
          }
        }
      }
    });

    const finalLogs = history.history;
    const finalLoss = finalLogs.loss[finalLogs.loss.length - 1];
    const finalAcc = finalLogs.acc[finalLogs.acc.length - 1];

    inputTensor.dispose();
    labelsOneHot.dispose();

    this.isTrained = true;

    this.metrics = {
      modelId: this.modelId,
      modelType: this.modelType,
      trainingTime: Date.now() - startTime,
      lastTrained: new Date(),
      accuracy: typeof finalAcc === 'number' ? finalAcc : (finalAcc as tf.Tensor).dataSync()[0],
      loss: typeof finalLoss === 'number' ? finalLoss : (finalLoss as tf.Tensor).dataSync()[0],
      trainingSamples: data.features.length,
      features: this.inputDim,
      numClasses: this.numClasses,
      hyperparameters: {
        epochs: this.config.hyperparameters.epochs,
        batchSize: this.config.hyperparameters.batchSize,
        classLabels: this.classLabels as unknown as string | number | boolean
      }
    };

    this.emit('trained', this.metrics);
    return this.metrics;
  }

  /**
   * Классификация
   */
  async predict(input: Record<string, number>): Promise<MLPrediction> {
    if (!this.isTrained || !this.model) {
      throw new Error('Model not trained');
    }

    const featureVector = Object.values(input);
    const inputTensor = tf.tensor2d([featureVector]);

    const prediction = this.model!.predict(inputTensor) as tf.Tensor;
    const probabilities = prediction.dataSync();

    const predictedClass = this.argmax(new Float32Array(probabilities));
    const confidence = probabilities[predictedClass];

    const classProbabilities: Record<string, number> = {};
    this.classLabels.forEach((label, idx) => {
      classProbabilities[label] = probabilities[idx];
    });

    inputTensor.dispose();
    prediction.dispose();

    return {
      modelId: this.modelId,
      timestamp: new Date(),
      input,
      prediction: predictedClass,
      confidence,
      scores: classProbabilities,
      metadata: {
        predictedClass: this.classLabels[predictedClass]
      }
    };
  }

  /**
   * Пакетное предсказание
   */
  async predictBatch(inputs: Record<string, number>[]): Promise<MLPrediction[]> {
    const predictions: MLPrediction[] = [];
    for (const input of inputs) {
      predictions.push(await this.predict(input));
    }
    return predictions;
  }

  /**
   * Сохранение модели
   */
  async save(path: string): Promise<void> {
    if (!this.model) {
      throw new Error('No model to save');
    }
    await this.model.save(`file://${path}`);
  }

  /**
   * Загрузка модели
   */
  async load(path: string): Promise<void> {
    this.model = await tf.loadLayersModel(`file://${path}/model.json`) as tf.LayersModel;
    this.isTrained = true;
  }

  /**
   * Получение метрик
   */
  getModelMetrics(): ModelMetrics {
    return { ...this.metrics };
  }

  /**
   * Очистка ресурсов
   */
  dispose(): void {
    if (this.model) {
      this.model.dispose();
      this.model = null;
    }
    this.emit('disposed');
  }

  /**
   * Поиск индекса максимального значения
   */
  private argmax(array: Float32Array): number {
    let maxIdx = 0;
    for (let i = 1; i < array.length; i++) {
      if (array[i] > array[maxIdx]) {
        maxIdx = i;
      }
    }
    return maxIdx;
  }
}

/**
 * ============================================================================
 * ML MODEL MANAGER — УПРАВЛЕНИЕ МОДЕЛЯМИ
 * ============================================================================
 */
export class MLModelManager extends EventEmitter {
  private models: Map<string, IMLModel> = new Map();
  private modelRegistry: Map<string, MLModelType> = new Map();

  /**
   * Создание и регистрация модели
   */
  createModel(modelType: MLModelType, config: MLModelConfig): IMLModel {
    let model: IMLModel;

    switch (modelType) {
      case MLModelType.ISOLATION_FOREST:
        model = new IsolationForest(config);
        break;
      case MLModelType.AUTOENCODER:
        model = new AutoencoderModel(config);
        break;
      case MLModelType.LSTM:
        model = new LSTMModel(config);
        break;
      case MLModelType.RANDOM_FOREST:
        model = new NeuralNetworkClassifier(config);
        break;
      default:
        throw new Error(`Unknown model type: ${modelType}`);
    }

    this.models.set(config.modelId || model.modelId, model);
    this.modelRegistry.set(config.modelId || model.modelId, modelType);

    this.emit('model_created', { modelId: model.modelId, modelType });
    return model;
  }

  /**
   * Регистрация существующей модели
   */
  registerModel(config: MLModelConfig): void {
    const modelType = config.modelType;
    let model: IMLModel;

    switch (modelType) {
      case MLModelType.ISOLATION_FOREST:
        model = new IsolationForest(config);
        break;
      case MLModelType.AUTOENCODER:
        model = new AutoencoderModel(config);
        break;
      case MLModelType.LSTM:
        model = new LSTMModel(config);
        break;
      default:
        throw new Error(`Unsupported model type for registration: ${modelType}`);
    }

    this.models.set(model.modelId, model);
    this.modelRegistry.set(model.modelId, modelType);
    this.emit('model_registered', { modelId: model.modelId, modelType });
  }

  /**
   * Получение модели по ID
   */
  getModel(modelId: string): IMLModel | undefined {
    return this.models.get(modelId);
  }

  /**
   * Обучение модели
   */
  async trainModel(modelId: string, data: TrainingData): Promise<ModelMetrics> {
    const model = this.models.get(modelId);
    if (!model) {
      throw new Error(`Model ${modelId} not found`);
    }

    this.emit('training_started', { modelId });
    const metrics = await model.train(data);
    this.emit('training_completed', { modelId, metrics });

    return metrics;
  }

  /**
   * Предсказание модели
   */
  async predict(modelId: string, input: Record<string, number>): Promise<MLPrediction> {
    const model = this.models.get(modelId);
    if (!model) {
      throw new Error(`Model ${modelId} not found`);
    }

    return model.predict(input);
  }

  /**
   * Пакетное предсказание
   */
  async predictBatch(modelId: string, inputs: Record<string, number>[]): Promise<MLPrediction[]> {
    const model = this.models.get(modelId);
    if (!model) {
      throw new Error(`Model ${modelId} not found`);
    }

    return model.predictBatch(inputs);
  }

  /**
   * Сохранение модели
   */
  async saveModel(modelId: string, path: string): Promise<void> {
    const model = this.models.get(modelId);
    if (!model) {
      throw new Error(`Model ${modelId} not found`);
    }

    await model.save(path);
    this.emit('model_saved', { modelId, path });
  }

  /**
   * Сохранение всех моделей
   */
  async saveAllModels(directory: string): Promise<void> {
    const fs = require('fs');
    const pathMod = require('path');

    if (!fs.existsSync(directory)) {
      fs.mkdirSync(directory, { recursive: true });
    }

    for (const [modelId, model] of this.models.entries()) {
      const modelPath = pathMod.join(directory, modelId);
      await model.save(modelPath);
    }
  }

  /**
   * Обучение всех моделей
   */
  async trainAllModels(trainingData: Map<string, TrainingData>): Promise<Map<string, ModelMetrics>> {
    const results = new Map<string, ModelMetrics>();

    for (const [modelId, model] of this.models.entries()) {
      const data = trainingData.get(modelId);
      if (data) {
        const metrics = await model.train(data);
        results.set(modelId, metrics);
      }
    }

    return results;
  }

  /**
   * Ensemble предсказание всеми моделями
   */
  async ensemblePredict(features: Record<string, number>): Promise<MLPrediction> {
    const predictions: MLPrediction[] = [];

    for (const model of this.models.values()) {
      try {
        const prediction = await model.predict(features);
        predictions.push(prediction);
      } catch (error) {
        console.error(`Model ${model.modelId} prediction error:`, error);
      }
    }

    if (predictions.length === 0) {
      return {
        modelId: 'ensemble',
        timestamp: new Date(),
        input: features,
        prediction: 0,
        confidence: 0,
        isAnomaly: false,
        anomalyScore: 0
      };
    }

    // Усреднение предсказаний
    const anomalyScores = predictions.map(p => p.anomalyScore || 0);
    const avgScore = anomalyScores.reduce((a, b) => a + b, 0) / anomalyScores.length;
    const avgConfidence = predictions.reduce((sum, p) => sum + p.confidence, 0) / predictions.length;

    return {
      modelId: 'ensemble',
      timestamp: new Date(),
      input: features,
      prediction: avgScore > 0.5 ? 1 : 0,
      confidence: avgConfidence,
      isAnomaly: avgScore > 0.5,
      anomalyScore: avgScore,
      scores: {
        averageScore: avgScore,
        maxScore: Math.max(...anomalyScores),
        minScore: Math.min(...anomalyScores)
      }
    };
  }

  /**
   * Загрузка модели
   */
  async loadModel(modelId: string, path: string, modelType: MLModelType): Promise<void> {
    const config: MLModelConfig = {
      modelId,
      modelType,
      inputFeatures: [],
      trainingWindow: 30,
      retrainingInterval: 24,
      threshold: 0.5,
      hyperparameters: {}
    };

    const model = this.createModel(modelType, config);
    await model.load(path);

    this.emit('model_loaded', { modelId, path });
  }

  /**
   * Удаление модели
   */
  deleteModel(modelId: string): void {
    const model = this.models.get(modelId);
    if (model) {
      model.dispose();
      this.models.delete(modelId);
      this.modelRegistry.delete(modelId);
      this.emit('model_deleted', { modelId });
    }
  }

  /**
   * Список всех моделей
   */
  listModels(): Array<{ modelId: string; modelType: MLModelType; metrics?: ModelMetrics }> {
    const result: Array<{ modelId: string; modelType: MLModelType; metrics?: ModelMetrics }> = [];

    for (const [modelId, model] of this.models.entries()) {
      const modelType = this.modelRegistry.get(modelId)!;
      result.push({
        modelId,
        modelType,
        metrics: model.getModelMetrics()
      });
    }

    return result;
  }

  /**
   * Очистка всех ресурсов
   */
  dispose(): void {
    for (const model of this.models.values()) {
      model.dispose();
    }
    this.models.clear();
    this.modelRegistry.clear();
    this.emit('disposed');
  }
}
