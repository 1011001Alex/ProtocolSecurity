/**
 * ============================================================================
 * ML MODELS - МАШИННОЕ ОБУЧЕНИЕ ДЛЯ THREAT DETECTION
 * Реализация ML моделей для обнаружения аномалий и классификации угроз
 * ============================================================================
 */

import * as tf from '@tensorflow/tfjs-node';
import {
  MLModelConfig,
  MLPrediction,
  TrainingData,
  ModelMetrics,
  MLModelType,
  ThreatSeverity
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Интерфейс для всех ML моделей
 */
interface IMLModel {
  train(data: TrainingData): Promise<ModelMetrics>;
  predict(input: Record<string, number>): Promise<MLPrediction>;
  save(path: string): Promise<void>;
  load(path: string): Promise<void>;
  getModelMetrics(): ModelMetrics;
}

/**
 * ============================================================================
 * ISOLATION FOREST - ОБНАРУЖЕНИЕ АНОМАЛИЙ
 * Алгоритм для обнаружения аномалий через изоляцию точек данных
 * ============================================================================
 */
export class IsolationForest implements IMLModel {
  public modelId: string;
  public config: MLModelConfig;
  
  // Параметры модели
  private nTrees: number = 100;
  private sampleSize: number = 256;
  private threshold: number = 0.6;
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

  constructor(config: MLModelConfig) {
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
  }

  /**
   * Обучение модели Isolation Forest
   */
  async train(data: TrainingData): Promise<ModelMetrics> {
    const startTime = Date.now();
    
    console.log(`[IsolationForest] Начало обучения модели ${this.modelId}`);
    console.log(`[IsolationForest] Количество выборок: ${data.features.length}`);
    console.log(`[IsolationForest] Количество признаков: ${data.features[0]?.length || 0}`);
    
    // Нормализация данных (Z-score normalization)
    const normalizedData = this.normalizeData(data.features);
    
    // Построение деревьев изоляции
    this.trees = [];
    for (let i = 0; i < this.nTrees; i++) {
      // Случайная выборка данных
      const sample = this.randomSample(normalizedData, this.sampleSize);
      
      // Построение дерева
      const tree = this.buildTree(sample, 0);
      this.trees.push(tree);
    }
    
    this.isTrained = true;
    
    const trainingTime = Date.now() - startTime;
    
    this.metrics = {
      modelId: this.modelId,
      trainingTime,
      lastTrained: new Date(),
      accuracy: undefined,  // Для unsupervised learning не применима
      falsePositiveRate: undefined
    };
    
    console.log(`[IsolationForest] Обучение завершено за ${trainingTime}мс`);
    
    return this.metrics;
  }

  /**
   * Предсказание - обнаружение аномалий
   */
  async predict(input: Record<string, number>): Promise<MLPrediction> {
    if (!this.isTrained) {
      throw new Error('Модель не обучена. Вызовите train() сначала.');
    }
    
    // Преобразование входа в вектор признаков
    const featureVector = this.config.inputFeatures.map(f => input[f] || 0);
    
    // Нормализация входа
    const normalizedInput = this.normalizeInput(featureVector);
    
    // Расчет anomaly score
    const pathLengths = this.trees.map(tree => this.pathLength(normalizedInput, tree));
    const avgPathLength = pathLengths.reduce((a, b) => a + b, 0) / pathLengths.length;
    
    // Расчет anomaly score используя формулу Isolation Forest
    const n = this.sampleSize;
    const c = 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
    const anomalyScore = Math.pow(2, -avgPathLength / c);
    
    const isAnomaly = anomalyScore >= this.threshold;
    
    const prediction: MLPrediction = {
      modelId: this.modelId,
      timestamp: new Date(),
      input,
      prediction: anomalyScore,
      confidence: 1 - Math.abs(anomalyScore - 0.5) * 2,
      isAnomaly,
      anomalyScore
    };
    
    return prediction;
  }

  /**
   * Пакетное предсказание
   */
  async predictBatch(inputs: Record<string, number>[]): Promise<MLPrediction[]> {
    const predictions: MLPrediction[] = [];
    
    for (const input of inputs) {
      const prediction = await this.predict(input);
      predictions.push(prediction);
    }
    
    return predictions;
  }

  /**
   * Сохранение модели
   */
  async save(path: string): Promise<void> {
    const modelData = {
      modelId: this.modelId,
      config: this.config,
      nTrees: this.nTrees,
      sampleSize: this.sampleSize,
      threshold: this.threshold,
      trees: this.trees,
      featureMeans: this.featureMeans,
      featureStds: this.featureStds,
      isTrained: this.isTrained,
      metrics: this.metrics
    };
    
    // В реальной реализации здесь будет сохранение в файловую систему
    console.log(`[IsolationForest] Сохранение модели в ${path}`);
    console.log(JSON.stringify(modelData, null, 2));
  }

  /**
   * Загрузка модели
   */
  async load(path: string): Promise<void> {
    // В реальной реализации здесь будет загрузка из файловой системы
    console.log(`[IsolationForest] Загрузка модели из ${path}`);
    this.isTrained = true;
  }

  /**
   * Получение метрик модели
   */
  getModelMetrics(): ModelMetrics {
    return this.metrics;
  }

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Нормализация данных (Z-score)
   */
  private normalizeData(data: number[][]): number[][] {
    const nFeatures = data[0].length;
    this.featureMeans = [];
    this.featureStds = [];
    
    // Расчет mean и std для каждого признака
    for (let j = 0; j < nFeatures; j++) {
      const values = data.map(row => row[j]);
      const mean = values.reduce((a, b) => a + b, 0) / values.length;
      const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
      const std = Math.sqrt(variance) || 1;  // Избегаем деления на 0
      
      this.featureMeans.push(mean);
      this.featureStds.push(std);
    }
    
    // Нормализация
    return data.map(row => 
      row.map((val, j) => (val - this.featureMeans[j]) / this.featureStds[j])
    );
  }

  /**
   * Нормализация входных данных
   */
  private normalizeInput(input: number[]): number[] {
    return input.map((val, j) => {
      const mean = this.featureMeans[j] || 0;
      const std = this.featureStds[j] || 1;
      return (val - mean) / std;
    });
  }

  /**
   * Случайная выборка из данных
   */
  private randomSample(data: number[][], size: number): number[][] {
    const shuffled = [...data].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, Math.min(size, data.length));
  }

  /**
   * Построение дерева изоляции
   */
  private buildTree(data: number[][], height: number): IsolationTree {
    const nSamples = data.length;
    
    // Базовый случай - достигнута максимальная глубина или мало данных
    const maxDepth = Math.ceil(Math.log2(this.sampleSize));
    if (height >= maxDepth || nSamples <= 1) {
      return { type: 'leaf', size: nSamples };
    }
    
    // Случайный выбор признака
    const nFeatures = data[0].length;
    const featureIndex = Math.floor(Math.random() * nFeatures);
    
    // Случайный выбор порога
    const values = data.map(row => row[featureIndex]);
    const minValue = Math.min(...values);
    const maxValue = Math.max(...values);
    
    if (minValue === maxValue) {
      return { type: 'leaf', size: nSamples };
    }
    
    const splitValue = minValue + Math.random() * (maxValue - minValue);
    
    // Разделение данных
    const leftData = data.filter(row => row[featureIndex] < splitValue);
    const rightData = data.filter(row => row[featureIndex] >= splitValue);
    
    // Рекурсивное построение поддеревьев
    const leftSubtree = this.buildTree(leftData, height + 1);
    const rightSubtree = this.buildTree(rightData, height + 1);
    
    return {
      type: 'node',
      featureIndex,
      splitValue,
      left: leftSubtree,
      right: rightSubtree
    };
  }

  /**
   * Расчет длины пути для точки данных
   */
  private pathLength(point: number[], tree: IsolationTree, depth: number = 0): number {
    if (tree.type === 'leaf') {
      // Коррекция на размер листа
      const n = tree.size;
      if (n <= 1) return depth;
      
      const c = 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
      return depth + c;
    }
    
    // Переход к поддереву
    if (point[tree.featureIndex] < tree.splitValue) {
      return this.pathLength(point, tree.left, depth + 1);
    } else {
      return this.pathLength(point, tree.right, depth + 1);
    }
  }
}

/**
 * Тип узла дерева изоляции
 */
type IsolationTree = 
  | { type: 'leaf'; size: number }
  | {
      type: 'node';
      featureIndex: number;
      splitValue: number;
      left: IsolationTree;
      right: IsolationTree;
    };

/**
 * ============================================================================
 * LSTM - LONG SHORT-TERM MEMORY
 * Рекуррентная нейронная сеть для анализа временных рядов
 * ============================================================================
 */
export class LSTMModel implements IMLModel {
  public modelId: string;
  public config: MLModelConfig;
  
  // TensorFlow.js модель
  private model: tf.LayersModel | null = null;
  private isTrained: boolean = false;
  
  // Параметры
  private sequenceLength: number = 50;
  private lstmUnits: number = 64;
  private dropoutRate: number = 0.2;
  private learningRate: number = 0.001;
  private epochs: number = 50;
  private batchSize: number = 32;
  
  // Статистика обучения
  private trainingHistory: tf.io.ModelTrainingConfig['optimizerConfig'] = {};
  private metrics: ModelMetrics = {
    modelId: '',
    trainingTime: 0,
    lastTrained: new Date()
  };

  constructor(config: MLModelConfig) {
    this.modelId = config.modelId || uuidv4();
    this.config = config;
    
    // Извлечение гиперпараметров
    if (config.hyperparameters.sequenceLength) {
      this.sequenceLength = config.hyperparameters.sequenceLength as number;
    }
    if (config.hyperparameters.lstmUnits) {
      this.lstmUnits = config.hyperparameters.lstmUnits as number;
    }
    if (config.hyperparameters.dropoutRate) {
      this.dropoutRate = config.hyperparameters.dropoutRate as number;
    }
    if (config.hyperparameters.learningRate) {
      this.learningRate = config.hyperparameters.learningRate as number;
    }
    if (config.hyperparameters.epochs) {
      this.epochs = config.hyperparameters.epochs as number;
    }
    if (config.hyperparameters.batchSize) {
      this.batchSize = config.hyperparameters.batchSize as number;
    }
  }

  /**
   * Построение LSTM модели
   */
  private buildModel(inputShape: number): tf.LayersModel {
    const model = tf.sequential();
    
    // Первый LSTM слой
    model.add(tf.layers.lstm({
      units: this.lstmUnits,
      inputShape: [this.sequenceLength, inputShape],
      returnSequences: true,
      dropout: this.dropoutRate,
      recurrentDropout: this.dropoutRate
    }));
    
    // Второй LSTM слой
    model.add(tf.layers.lstm({
      units: this.lstmUnits / 2,
      dropout: this.dropoutRate,
      recurrentDropout: this.dropoutRate
    }));
    
    // Dense слой
    model.add(tf.layers.dense({
      units: 32,
      activation: 'relu'
    }));
    
    model.add(tf.layers.dropout({ rate: this.dropoutRate }));
    
    // Выходной слой
    model.add(tf.layers.dense({
      units: 1,
      activation: 'sigmoid'
    }));
    
    // Компиляция модели
    model.compile({
      optimizer: tf.train.adam(this.learningRate),
      loss: 'binaryCrossentropy',
      metrics: ['accuracy']
    });
    
    return model;
  }

  /**
   * Обучение LSTM модели
   */
  async train(data: TrainingData): Promise<ModelMetrics> {
    const startTime = Date.now();
    
    console.log(`[LSTM] Начало обучения модели ${this.modelId}`);
    console.log(`[LSTM] Количество выборок: ${data.features.length}`);
    
    try {
      // Подготовка последовательностей
      const sequences = this.prepareSequences(data.features);
      
      if (sequences.length < this.batchSize) {
        throw new Error('Недостаточно данных для обучения. Требуется минимум ' + this.batchSize + ' выборок.');
      }
      
      const inputShape = data.features[0].length;
      
      // Построение модели
      this.model = this.buildModel(inputShape);
      
      // Подготовка тензоров
      const xTrain = tf.tensor3d(sequences);
      const yTrain = tf.tensor2d(data.labels || Array(sequences.length).fill(0), [sequences.length, 1]);
      
      // Обучение модели
      const history = await this.model.fit(xTrain, yTrain, {
        epochs: this.epochs,
        batchSize: this.batchSize,
        validationSplit: 0.2,
        verbose: 1,
        callbacks: {
          onEpochEnd: (epoch, logs) => {
            console.log(`[LSTM] Epoch ${epoch}: loss = ${logs?.loss}, acc = ${logs?.acc}`);
          }
        }
      });
      
      // Очистка тензоров
      xTrain.dispose();
      yTrain.dispose();
      
      this.isTrained = true;
      
      const trainingTime = Date.now() - startTime;
      const finalLogs = history.history;
      
      this.metrics = {
        modelId: this.modelId,
        trainingTime,
        lastTrained: new Date(),
        accuracy: finalLogs.acc ? finalLogs.acc[finalLogs.acc.length - 1] : undefined,
        loss: finalLogs.loss ? finalLogs.loss[finalLogs.loss.length - 1] : undefined
      };
      
      console.log(`[LSTM] Обучение завершено за ${trainingTime}мс`);
      console.log(`[LSTM] Финальная точность: ${this.metrics.accuracy}`);
      
      return this.metrics;
      
    } catch (error) {
      console.error('[LSTM] Ошибка обучения:', error);
      throw error;
    }
  }

  /**
   * Предсказание с использованием LSTM
   */
  async predict(input: Record<string, number>): Promise<MLPrediction> {
    if (!this.isTrained || !this.model) {
      throw new Error('Модель не обучена. Вызовите train() сначала.');
    }
    
    try {
      // Преобразование входа в последовательность
      const featureVector = this.config.inputFeatures.map(f => input[f] || 0);
      
      // Для LSTM нужна последовательность - используем скользящее окно
      const sequence = this.createSequence(featureVector);
      
      // Создание тензора
      const inputTensor = tf.tensor3d([sequence]);
      
      // Предсказание
      const predictionTensor = this.model.predict(inputTensor) as tf.Tensor;
      const prediction = await predictionTensor.array() as number[][];
      
      const score = prediction[0][0];
      const isAnomaly = score >= this.threshold;
      
      // Очистка
      inputTensor.dispose();
      predictionTensor.dispose();
      
      const result: MLPrediction = {
        modelId: this.modelId,
        timestamp: new Date(),
        input,
        prediction: score,
        confidence: Math.max(score, 1 - score),
        isAnomaly,
        anomalyScore: score
      };
      
      return result;
      
    } catch (error) {
      console.error('[LSTM] Ошибка предсказания:', error);
      throw error;
    }
  }

  /**
   * Предсказание для временного ряда
   */
  async predictTimeSeries(timeSeries: number[][]): Promise<MLPrediction[]> {
    if (!this.isTrained || !this.model) {
      throw new Error('Модель не обучена. Вызовите train() сначала.');
    }
    
    const predictions: MLPrediction[] = [];
    
    // Подготовка последовательностей из временного ряда
    for (let i = this.sequenceLength; i < timeSeries.length; i++) {
      const sequence = timeSeries.slice(i - this.sequenceLength, i);
      const inputTensor = tf.tensor3d([sequence]);
      
      const predictionTensor = this.model.predict(inputTensor) as tf.Tensor;
      const prediction = await predictionTensor.array() as number[][];
      
      predictions.push({
        modelId: this.modelId,
        timestamp: new Date(),
        input: { sequence: i },
        prediction: prediction[0][0],
        confidence: Math.max(prediction[0][0], 1 - prediction[0][0]),
        isAnomaly: prediction[0][0] >= this.threshold,
        anomalyScore: prediction[0][0]
      });
      
      inputTensor.dispose();
      predictionTensor.dispose();
    }
    
    return predictions;
  }

  /**
   * Сохранение модели
   */
  async save(path: string): Promise<void> {
    if (!this.model) {
      throw new Error('Модель не создана.');
    }
    
    console.log(`[LSTM] Сохранение модели в ${path}`);
    await this.model.save(`file://${path}`);
  }

  /**
   * Загрузка модели
   */
  async load(path: string): Promise<void> {
    console.log(`[LSTM] Загрузка модели из ${path}`);
    this.model = await tf.loadLayersModel(`file://${path}/model.json`);
    this.isTrained = true;
  }

  /**
   * Получение метрик модели
   */
  getModelMetrics(): ModelMetrics {
    return this.metrics;
  }

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Подготовка последовательностей для обучения
   */
  private prepareSequences(data: number[][]): number[][][] {
    const sequences: number[][][] = [];
    
    for (let i = this.sequenceLength; i < data.length; i++) {
      const sequence = data.slice(i - this.sequenceLength, i);
      sequences.push(sequence);
    }
    
    return sequences;
  }

  /**
   * Создание последовательности из входа
   */
  private createSequence(currentVector: number[]): number[][] {
    // В реальной реализации здесь будет история значений
    // Для демонстрации создаем последовательность из одинаковых векторов с шумом
    const sequence: number[][] = [];
    
    for (let i = 0; i < this.sequenceLength; i++) {
      const noisyVector = currentVector.map(v => 
        v + (Math.random() - 0.5) * 0.1  // Добавляем небольшой шум
      );
      sequence.push(noisyVector);
    }
    
    return sequence;
  }

  /**
   * Порог для аномалий
   */
  private get threshold(): number {
    return this.config.threshold || 0.5;
  }
}

/**
 * ============================================================================
 * AUTOENCODER - СНИЖЕНИЕ РАЗМЕРНОСТИ
 * Нейронная сеть для обнаружения аномалий через реконструкцию
 * ============================================================================
 */
export class AutoencoderModel implements IMLModel {
  public modelId: string;
  public config: MLModelConfig;
  
  // TensorFlow.js модель
  private model: tf.LayersModel | null = null;
  private isTrained: boolean = false;
  
  // Параметры
  private encodingDim: number = 16;
  private dropoutRate: number = 0.2;
  private learningRate: number = 0.001;
  private epochs: number = 100;
  private batchSize: number = 32;
  
  // Порог реконструкции
  private reconstructionThreshold: number = 0.1;
  
  private metrics: ModelMetrics = {
    modelId: '',
    trainingTime: 0,
    lastTrained: new Date()
  };

  constructor(config: MLModelConfig) {
    this.modelId = config.modelId || uuidv4();
    this.config = config;
    
    // Извлечение гиперпараметров
    if (config.hyperparameters.encodingDim) {
      this.encodingDim = config.hyperparameters.encodingDim as number;
    }
    if (config.hyperparameters.dropoutRate) {
      this.dropoutRate = config.hyperparameters.dropoutRate as number;
    }
    if (config.hyperparameters.learningRate) {
      this.learningRate = config.hyperparameters.learningRate as number;
    }
    if (config.hyperparameters.epochs) {
      this.epochs = config.hyperparameters.epochs as number;
    }
    if (config.hyperparameters.batchSize) {
      this.batchSize = config.hyperparameters.batchSize as number;
    }
    if (config.hyperparameters.reconstructionThreshold) {
      this.reconstructionThreshold = config.hyperparameters.reconstructionThreshold as number;
    }
  }

  /**
   * Построение модели автоэнкодера
   */
  private buildModel(inputShape: number): tf.LayersModel {
    const model = tf.sequential();
    
    // Encoder
    model.add(tf.layers.dense({
      units: 64,
      activation: 'relu',
      inputShape: [inputShape]
    }));
    model.add(tf.layers.dropout({ rate: this.dropoutRate }));
    
    model.add(tf.layers.dense({
      units: 32,
      activation: 'relu'
    }));
    model.add(tf.layers.dropout({ rate: this.dropoutRate }));
    
    // Bottleneck (сжатое представление)
    model.add(tf.layers.dense({
      units: this.encodingDim,
      activation: 'relu'
    }));
    
    // Decoder
    model.add(tf.layers.dense({
      units: 32,
      activation: 'relu'
    }));
    model.add(tf.layers.dropout({ rate: this.dropoutRate }));
    
    model.add(tf.layers.dense({
      units: 64,
      activation: 'relu'
    }));
    model.add(tf.layers.dropout({ rate: this.dropoutRate }));
    
    // Выходной слой (реконструкция входа)
    model.add(tf.layers.dense({
      units: inputShape,
      activation: 'sigmoid'
    }));
    
    // Компиляция модели
    model.compile({
      optimizer: tf.train.adam(this.learningRate),
      loss: 'meanSquaredError'
    });
    
    return model;
  }

  /**
   * Обучение автоэнкодера
   */
  async train(data: TrainingData): Promise<ModelMetrics> {
    const startTime = Date.now();
    
    console.log(`[Autoencoder] Начало обучения модели ${this.modelId}`);
    console.log(`[Autoencoder] Количество выборок: ${data.features.length}`);
    
    try {
      const inputShape = data.features[0].length;
      
      // Построение модели
      this.model = this.buildModel(inputShape);
      
      // Подготовка тензоров (автоэнкодер обучается восстанавливать вход)
      const xTrain = tf.tensor2d(data.features);
      const yTrain = tf.tensor2d(data.features);  // Целевые значения = входные
      
      // Обучение модели
      const history = await this.model.fit(xTrain, yTrain, {
        epochs: this.epochs,
        batchSize: this.batchSize,
        validationSplit: 0.2,
        verbose: 1,
        callbacks: {
          onEpochEnd: (epoch, logs) => {
            console.log(`[Autoencoder] Epoch ${epoch}: loss = ${logs?.loss}`);
          }
        }
      });
      
      // Расчет порога реконструкции на основе training error
      const predictions = this.model.predict(xTrain) as tf.Tensor;
      const errors = tf.sub(xTrain, predictions).square().mean().arraySync() as number;
      this.reconstructionThreshold = errors * 2;  // Порог = 2 * средняя ошибка
      
      // Очистка тензоров
      xTrain.dispose();
      yTrain.dispose();
      predictions.dispose();
      
      this.isTrained = true;
      
      const trainingTime = Date.now() - startTime;
      const finalLogs = history.history;
      
      this.metrics = {
        modelId: this.modelId,
        trainingTime,
        lastTrained: new Date(),
        accuracy: undefined,  // Для автоэнкодера не применима
        auc: undefined
      };
      
      console.log(`[Autoencoder] Обучение завершено за ${trainingTime}мс`);
      console.log(`[Autoencoder] Порог реконструкции: ${this.reconstructionThreshold}`);
      
      return this.metrics;
      
    } catch (error) {
      console.error('[Autoencoder] Ошибка обучения:', error);
      throw error;
    }
  }

  /**
   * Предсказание - обнаружение аномалий через ошибку реконструкции
   */
  async predict(input: Record<string, number>): Promise<MLPrediction> {
    if (!this.isTrained || !this.model) {
      throw new Error('Модель не обучена. Вызовите train() сначала.');
    }
    
    try {
      // Преобразование входа в вектор
      const featureVector = this.config.inputFeatures.map(f => input[f] || 0);
      
      // Создание тензора
      const inputTensor = tf.tensor2d([featureVector]);
      
      // Реконструкция
      const reconstructed = this.model.predict(inputTensor) as tf.Tensor;
      
      // Расчет ошибки реконструкции
      const error = tf.sub(inputTensor, reconstructed).square().mean().arraySync() as number;
      
      // Нормализация ошибки в score (0-1)
      const anomalyScore = Math.min(error / this.reconstructionThreshold, 1);
      const isAnomaly = error > this.reconstructionThreshold;
      
      // Очистка
      inputTensor.dispose();
      reconstructed.dispose();
      
      const result: MLPrediction = {
        modelId: this.modelId,
        timestamp: new Date(),
        input,
        prediction: anomalyScore,
        confidence: 1 - anomalyScore,
        isAnomaly,
        anomalyScore
      };
      
      return result;
      
    } catch (error) {
      console.error('[Autoencoder] Ошибка предсказания:', error);
      throw error;
    }
  }

  /**
   * Сохранение модели
   */
  async save(path: string): Promise<void> {
    if (!this.model) {
      throw new Error('Модель не создана.');
    }
    
    console.log(`[Autoencoder] Сохранение модели в ${path}`);
    await this.model.save(`file://${path}`);
  }

  /**
   * Загрузка модели
   */
  async load(path: string): Promise<void> {
    console.log(`[Autoencoder] Загрузка модели из ${path}`);
    this.model = await tf.loadLayersModel(`file://${path}/model.json`);
    this.isTrained = true;
  }

  /**
   * Получение метрик модели
   */
  getModelMetrics(): ModelMetrics {
    return this.metrics;
  }
}

/**
 * ============================================================================
 * ML MODEL MANAGER - УПРАВЛЕНИЕ ML МОДЕЛЯМИ
 * Централизованное управление всеми ML моделями
 * ============================================================================
 */
export class MLModelManager {
  private models: Map<string, IMLModel> = new Map();
  private predictions: MLPrediction[] = [];
  private maxPredictionsHistory: number = 10000;

  /**
   * Регистрация модели
   */
  registerModel(config: MLModelConfig): IMLModel {
    let model: IMLModel;
    
    switch (config.modelType) {
      case MLModelType.ISOLATION_FOREST:
        model = new IsolationForest(config);
        break;
      case MLModelType.LSTM:
        model = new LSTMModel(config);
        break;
      case MLModelType.AUTOENCODER:
        model = new AutoencoderModel(config);
        break;
      default:
        throw new Error(`Неподдерживаемый тип модели: ${config.modelType}`);
    }
    
    this.models.set(model.modelId, model);
    console.log(`[MLModelManager] Зарегистрирована модель ${model.modelId} типа ${config.modelType}`);
    
    return model;
  }

  /**
   * Получение модели по ID
   */
  getModel(modelId: string): IMLModel | undefined {
    return this.models.get(modelId);
  }

  /**
   * Обучение всех моделей
   */
  async trainAllModels(trainingData: Map<string, TrainingData>): Promise<Map<string, ModelMetrics>> {
    const results = new Map<string, ModelMetrics>();
    
    for (const [modelId, data] of trainingData.entries()) {
      const model = this.models.get(modelId);
      
      if (model) {
        try {
          const metrics = await model.train(data);
          results.set(modelId, metrics);
        } catch (error) {
          console.error(`[MLModelManager] Ошибка обучения модели ${modelId}:`, error);
        }
      } else {
        console.warn(`[MLModelManager] Модель ${modelId} не найдена`);
      }
    }
    
    return results;
  }

  /**
   * Предсказание с использованием всех моделей
   */
  async predictAll(input: Record<string, number>): Promise<Map<string, MLPrediction>> {
    const predictions = new Map<string, MLPrediction>();
    
    for (const [modelId, model] of this.models.entries()) {
      try {
        const prediction = await model.predict(input);
        predictions.set(modelId, prediction);
        
        // Сохранение в историю
        this.predictions.push(prediction);
        if (this.predictions.length > this.maxPredictionsHistory) {
          this.predictions.shift();
        }
      } catch (error) {
        console.error(`[MLModelManager] Ошибка предсказания модели ${modelId}:`, error);
      }
    }
    
    return predictions;
  }

  /**
   * Ensemble предсказание
   */
  async ensemblePredict(input: Record<string, number>): Promise<MLPrediction> {
    const predictions = await this.predictAll(input);
    
    if (predictions.size === 0) {
      throw new Error('Нет доступных моделей для предсказания');
    }
    
    // Усреднение anomaly scores
    const scores: number[] = [];
    const confidences: number[] = [];
    const anomalyVotes: number = 0;
    
    for (const prediction of predictions.values()) {
      if (prediction.anomalyScore !== undefined) {
        scores.push(prediction.anomalyScore);
      }
      confidences.push(prediction.confidence);
      if (prediction.isAnomaly) {
        anomalyVotes++;
      }
    }
    
    const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
    const avgConfidence = confidences.reduce((a, b) => a + b, 0) / confidences.length;
    const isAnomaly = anomalyVotes >= Math.ceil(predictions.size / 2);
    
    const ensemblePrediction: MLPrediction = {
      modelId: 'ensemble',
      timestamp: new Date(),
      input,
      prediction: avgScore,
      confidence: avgConfidence,
      isAnomaly,
      anomalyScore: avgScore
    };
    
    return ensemblePrediction;
  }

  /**
   * Получение истории предсказаний
   */
  getPredictionsHistory(limit: number = 100): MLPrediction[] {
    return this.predictions.slice(-limit);
  }

  /**
   * Сохранение всех моделей
   */
  async saveAllModels(basePath: string): Promise<void> {
    for (const [modelId, model] of this.models.entries()) {
      const path = `${basePath}/${modelId}`;
      await model.save(path);
    }
  }

  /**
   * Загрузка всех моделей
   */
  async loadAllModels(basePath: string, configs: Map<string, MLModelConfig>): Promise<void> {
    for (const [modelId, config] of configs.entries()) {
      const model = this.registerModel(config);
      const path = `${basePath}/${modelId}`;
      await model.load(path);
    }
  }

  /**
   * Получение метрик всех моделей
   */
  getAllModelMetrics(): Map<string, ModelMetrics> {
    const metrics = new Map<string, ModelMetrics>();
    
    for (const [modelId, model] of this.models.entries()) {
      metrics.set(modelId, model.getModelMetrics());
    }
    
    return metrics;
  }

  /**
   * Статистика по предсказаниям
   */
  getPredictionStatistics(): {
    totalPredictions: number;
    anomaliesDetected: number;
    anomalyRate: number;
    averageConfidence: number;
  } {
    const total = this.predictions.length;
    const anomalies = this.predictions.filter(p => p.isAnomaly).length;
    const avgConfidence = this.predictions.reduce((a, b) => a + b.confidence, 0) / total;
    
    return {
      totalPredictions: total,
      anomaliesDetected: anomalies,
      anomalyRate: total > 0 ? anomalies / total : 0,
      averageConfidence: avgConfidence
    };
  }
}

/**
 * Экспорт всех классов
 */
export {
  IsolationForest,
  LSTMModel,
  AutoencoderModel,
  MLModelManager
};
