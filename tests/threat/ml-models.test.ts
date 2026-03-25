/**
 * ============================================================================
 * ML MODELS TESTS
 * ============================================================================
 */

import { describe, it, beforeEach, afterEach } from '@jest/globals';
import * as assert from 'assert';
import {
  IsolationForest,
  AutoencoderModel,
  NeuralNetworkClassifier,
  MLModelManager
} from '../src/threat/MLModels';

describe('ML Models', () => {
  
  describe('IsolationForest', () => {
    let model: IsolationForest;

    beforeEach(() => {
      model = new IsolationForest({
        modelId: 'test-if',
        modelType: 'IsolationForest',
        hyperparameters: {
          nTrees: 50,
          sampleSize: 128,
          threshold: 0.6,
          maxDepth: 8
        }
      });
    });

    afterEach(() => {
      model.dispose();
    });

    it('должен создавать модель', () => {
      assert.ok(model);
      assert.strictEqual(model.modelId, 'test-if');
      assert.strictEqual(model.modelType, 'IsolationForest');
    });

    it('должен обучаться на данных', async () => {
      // Генерация тестовых данных
      const features: number[][] = [];
      const labels: number[] = [];

      // Нормальные данные
      for (let i = 0; i < 100; i++) {
        features.push([Math.random() * 10, Math.random() * 10]);
        labels.push(0);
      }

      // Аномалии
      for (let i = 0; i < 10; i++) {
        features.push([50 + Math.random() * 10, 50 + Math.random() * 10]);
        labels.push(1);
      }

      const metrics = await model.train({ features, labels });

      assert.ok(metrics);
      assert.ok(metrics.trainingTime > 0);
      assert.strictEqual(metrics.trainingSamples, 110);
      assert.ok(metrics.isTrained);
    });

    it('должен делать предсказания', async () => {
      // Обучение
      const features: number[][] = [];
      for (let i = 0; i < 50; i++) {
        features.push([Math.random() * 10, Math.random() * 10]);
      }

      await model.train({ features, labels: [] });

      // Предсказание
      const prediction = await model.predict({
        feature_0: 5,
        feature_1: 5
      });

      assert.ok(prediction);
      assert.ok('prediction' in prediction);
      assert.ok('confidence' in prediction);
      assert.ok(prediction.scores);
    });

    it('должен делать пакетные предсказания', async () => {
      const features: number[][] = [];
      for (let i = 0; i < 50; i++) {
        features.push([Math.random() * 10, Math.random() * 10]);
      }

      await model.train({ features, labels: [] });

      const inputs = [
        { feature_0: 5, feature_1: 5 },
        { feature_0: 6, feature_1: 6 },
        { feature_0: 7, feature_1: 7 }
      ];

      const predictions = await model.predictBatch(inputs);
      
      assert.strictEqual(predictions.length, 3);
      for (const pred of predictions) {
        assert.ok(pred.prediction !== undefined);
      }
    });

    it('должен возвращать метрики', async () => {
      const features: number[][] = [];
      for (let i = 0; i < 50; i++) {
        features.push([Math.random() * 10, Math.random() * 10]);
      }

      await model.train({ features, labels: [] });
      const metrics = model.getModelMetrics();

      assert.ok(metrics);
      assert.ok(metrics.modelId);
      assert.ok(metrics.lastTrained);
    });

    it('должен эмитить события', (done) => {
      model.on('trained', (metrics) => {
        assert.ok(metrics);
        done();
      });

      const features: number[][] = [[1, 2], [3, 4], [5, 6]];
      model.train({ features, labels: [] }).catch(() => {});
    });
  });

  describe('NeuralNetworkClassifier', () => {
    let model: NeuralNetworkClassifier;

    beforeEach(() => {
      model = new NeuralNetworkClassifier({
        modelId: 'test-nn',
        modelType: 'NeuralNetwork',
        hyperparameters: {
          classLabels: ['normal', 'attack', 'suspicious'],
          epochs: 10,
          batchSize: 16
        }
      });
    });

    afterEach(() => {
      model.dispose();
    });

    it('должен создавать классификатор', () => {
      assert.ok(model);
      assert.strictEqual(model.modelType, 'NeuralNetwork');
    });

    it('должен обучаться на данных', async () => {
      const features: number[][] = [];
      const labels: number[] = [];

      // Класс 0
      for (let i = 0; i < 30; i++) {
        features.push([Math.random(), Math.random(), Math.random()]);
        labels.push(0);
      }

      // Класс 1
      for (let i = 0; i < 30; i++) {
        features.push([1 + Math.random(), 1 + Math.random(), 1 + Math.random()]);
        labels.push(1);
      }

      // Класс 2
      for (let i = 0; i < 30; i++) {
        features.push([2 + Math.random(), 2 + Math.random(), 2 + Math.random()]);
        labels.push(2);
      }

      const metrics = await model.train({ features, labels });

      assert.ok(metrics);
      assert.ok(metrics.trainingTime > 0);
      assert.strictEqual(metrics.numClasses, 3);
    });

    it('должен классифицировать', async () => {
      const features: number[][] = [];
      const labels: number[] = [];

      for (let i = 0; i < 20; i++) {
        features.push([Math.random() * 0.3, Math.random() * 0.3]);
        labels.push(0);
      }

      for (let i = 0; i < 20; i++) {
        features.push([0.7 + Math.random() * 0.3, 0.7 + Math.random() * 0.3]);
        labels.push(1);
      }

      await model.train({ features, labels });

      const prediction = await model.predict({
        feature_0: 0.1,
        feature_1: 0.2
      });

      assert.ok(prediction);
      assert.ok(prediction.scores);
      assert.ok(prediction.confidence >= 0);
      assert.ok(prediction.confidence <= 1);
    });
  });

  describe('MLModelManager', () => {
    let manager: MLModelManager;

    beforeEach(() => {
      manager = new MLModelManager();
    });

    afterEach(() => {
      manager.dispose();
    });

    it('должен создавать модели', () => {
      const model = manager.createModel('IsolationForest', {
        modelId: 'managed-if',
        modelType: 'IsolationForest',
        hyperparameters: {}
      });

      assert.ok(model);
      assert.strictEqual(model.modelId, 'managed-if');
    });

    it('должен получать модель по ID', () => {
      manager.createModel('IsolationForest', {
        modelId: 'get-test',
        modelType: 'IsolationForest',
        hyperparameters: {}
      });

      const model = manager.getModel('get-test');
      assert.ok(model);
    });

    it('должен обучать модели', async () => {
      manager.createModel('IsolationForest', {
        modelId: 'train-test',
        modelType: 'IsolationForest',
        hyperparameters: { nTrees: 10 }
      });

      const features: number[][] = [[1, 2], [3, 4], [5, 6]];
      const metrics = await manager.trainModel('train-test', { features, labels: [] });

      assert.ok(metrics);
      assert.ok(metrics.trainingTime > 0);
    });

    it('должен делать предсказания', async () => {
      manager.createModel('IsolationForest', {
        modelId: 'pred-test',
        modelType: 'IsolationForest',
        hyperparameters: { nTrees: 10 }
      });

      const features: number[][] = [[1, 2], [3, 4], [5, 6]];
      await manager.trainModel('pred-test', { features, labels: [] });

      const prediction = await manager.predict('pred-test', {
        feature_0: 2,
        feature_1: 3
      });

      assert.ok(prediction);
    });

    it('должен возвращать список моделей', () => {
      manager.createModel('IsolationForest', {
        modelId: 'list-1',
        modelType: 'IsolationForest',
        hyperparameters: {}
      });

      manager.createModel('IsolationForest', {
        modelId: 'list-2',
        modelType: 'IsolationForest',
        hyperparameters: {}
      });

      const models = manager.listModels();
      assert.strictEqual(models.length, 2);
    });

    it('должен удалять модели', () => {
      manager.createModel('IsolationForest', {
        modelId: 'delete-me',
        modelType: 'IsolationForest',
        hyperparameters: {}
      });

      let models = manager.listModels();
      assert.strictEqual(models.length, 1);

      manager.deleteModel('delete-me');

      models = manager.listModels();
      assert.strictEqual(models.length, 0);
    });

    it('должен эмитить события', (done) => {
      manager.on('model_created', (data) => {
        assert.ok(data.modelId);
        done();
      });

      manager.createModel('IsolationForest', {
        modelId: 'event-test',
        modelType: 'IsolationForest',
        hyperparameters: {}
      });
    });
  });
});
