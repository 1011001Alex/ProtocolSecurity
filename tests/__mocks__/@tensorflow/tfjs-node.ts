/**
 * Mock для @tensorflow/tfjs-node
 * Используется в тестах чтобы избежать проблем с native addon
 */

// Вспомогательная функция для создания mock тензора
function createMockTensor(data?: any) {
  return {
    dataSync: jest.fn(() => (data ? (Array.isArray(data) ? data : [data]) : [0])),
    data: jest.fn().mockResolvedValue(data ? (Array.isArray(data) ? data : [data]) : [0]),
    dispose: jest.fn(),
    reshape: jest.fn(function () { return createMockTensor(data); }),
    sub: jest.fn(function (other: any) { return createMockTensor(data); }),
    div: jest.fn(function (other: any) { return createMockTensor(data); }),
    square: jest.fn(function () { return createMockTensor(data); }),
    mean: jest.fn(function (axis?: any) { return createMockTensor(data); }),
    sqrt: jest.fn(function () { return createMockTensor(data); }),
    add: jest.fn(function (other: any) { return createMockTensor(data); }),
  };
}

// Mock metrics объект
const metrics = {
  meanSquaredError: jest.fn((a: any, b: any) => createMockTensor([0.1])),
  categoricalCrossentropy: 'categoricalCrossentropy',
  accuracy: 'accuracy',
};

// Mock layers объект
const layers = {
  dense: jest.fn((config: any) => config),
  dropout: jest.fn((config: any) => config),
  lstm: jest.fn((config: any) => config),
  activation: jest.fn((config: any) => config),
};

// Mock train объект
const train = {
  adam: jest.fn((lr: any) => ({ lr })),
  sgd: jest.fn((lr: any) => ({ lr })),
};

// Mock sequential функция
const sequential = jest.fn(() => {
  const layersList: any[] = [];
  return {
    add: jest.fn((layer: any) => {
      layersList.push(layer);
    }),
    compile: jest.fn(),
    fit: jest.fn().mockResolvedValue({
      history: {
        loss: [0.5, 0.3, 0.2],
        mae: [0.4, 0.2, 0.1],
        acc: [0.6, 0.8, 0.9],
        accuracy: [0.6, 0.8, 0.9],
      },
    }),
    predict: jest.fn(() => createMockTensor([[0.1]])),
    evaluate: jest.fn().mockResolvedValue([0.2, 0.9]),
    save: jest.fn().mockResolvedValue(undefined),
    loadWeights: jest.fn(),
    dispose: jest.fn(),
    inputs: [{ shape: [null, 10] }],
    outputs: [{ shape: [null, 1] }],
    layers: layersList,
  };
});

// Mock model функция
const model = jest.fn((config: any) => ({
  predict: jest.fn(() => createMockTensor([[0.1]])),
  compile: jest.fn(),
  fit: jest.fn().mockResolvedValue({
    history: {
      loss: [0.5, 0.3, 0.2],
      acc: [0.6, 0.8, 0.9],
    },
  }),
  evaluate: jest.fn().mockResolvedValue([0.2, 0.9]),
  dispose: jest.fn(),
}));

// Mock loadLayersModel
const loadLayersModel = jest.fn().mockResolvedValue({
  predict: jest.fn(() => createMockTensor([[0.1]])),
  compile: jest.fn(),
  fit: jest.fn(),
  dispose: jest.fn(),
  inputs: [{ shape: [null, 10] }],
});

// Mock io объект
const io = {
  saveModel: jest.fn().mockResolvedValue(undefined),
  loadModel: jest.fn().mockResolvedValue({}),
};

// Единый объект tf который содержит всё
const tf = {
  // Tensor functions
  tensor: jest.fn((values: any, shape?: any) => createMockTensor(values)),
  scalar: jest.fn((value: any) => createMockTensor(value)),
  tensor1d: jest.fn((values: any) => createMockTensor(values)),
  tensor2d: jest.fn((values: any, shape?: any) => createMockTensor(values)),
  tensor3d: jest.fn((values: any, shape?: any) => createMockTensor(values)),
  tensor4d: jest.fn((values: any, shape?: any) => createMockTensor(values)),

  // Math operations
  matMul: jest.fn((a: any, b: any) => createMockTensor(a)),
  add: jest.fn((a: any, b: any) => createMockTensor(a)),
  sub: jest.fn((a: any, b: any) => createMockTensor(a)),
  mul: jest.fn((a: any, b: any) => createMockTensor(a)),
  div: jest.fn((a: any, b: any) => createMockTensor(a)),

  // Activation functions
  relu: jest.fn((x: any) => x),
  sigmoid: jest.fn((x: any) => x),
  softmax: jest.fn((x: any) => x),
  tanh: jest.fn((x: any) => x),

  // Layers
  layers,

  // Sequential model
  sequential,

  // Functional model
  model,

  // Load model
  loadLayersModel,

  // Train
  train,

  // Metrics
  metrics,

  // Initializers
  initializers: {
    glorotUniform: jest.fn((config: any) => config),
    heNormal: jest.fn((config: any) => config),
    randomNormal: jest.fn((config: any) => config),
  },

  // Backend
  backend: jest.fn(),
  setBackend: jest.fn(),
  ready: jest.fn().mockResolvedValue(undefined),

  // Dispose
  dispose: jest.fn(),
  disposeVariables: jest.fn(),

  // Memory
  memory: jest.fn().mockReturnValue({ numBytes: 0, numTensors: 0 }),

  // Profiling
  profile: jest.fn().mockResolvedValue({}),

  // Version
  version: 'mock-4.15.0',

  // Data utilities
  data: {
    array: jest.fn((data: any) => ({ data })),
    generator: jest.fn((gen: any) => ({ gen })),
  },

  // Random
  randomNormal: jest.fn((shape: any) => createMockTensor(shape)),
  randomUniform: jest.fn((shape: any) => createMockTensor(shape)),

  // Reshape
  reshape: jest.fn((tensor: any, shape: any) => createMockTensor(tensor)),
  transpose: jest.fn((tensor: any) => tensor),
  concat: jest.fn((tensors: any) => createMockTensor(tensors)),
  stack: jest.fn((tensors: any) => createMockTensor(tensors)),

  // Reduction
  mean: jest.fn((x: any) => createMockTensor(x)),
  sum: jest.fn((x: any) => createMockTensor(x)),
  min: jest.fn((x: any) => createMockTensor(x)),
  max: jest.fn((x: any) => createMockTensor(x)),
  argMax: jest.fn((x: any) => createMockTensor(x)),
  argMin: jest.fn((x: any) => createMockTensor(x)),

  // Comparison
  equal: jest.fn((a: any, b: any) => createMockTensor(a)),
  notEqual: jest.fn((a: any, b: any) => createMockTensor(a)),
  greater: jest.fn((a: any, b: any) => createMockTensor(a)),
  less: jest.fn((a: any, b: any) => createMockTensor(a)),

  // Logical
  logicalAnd: jest.fn((a: any, b: any) => createMockTensor(a)),
  logicalOr: jest.fn((a: any, b: any) => createMockTensor(a)),
  logicalNot: jest.fn((a: any) => a),

  // Casting
  cast: jest.fn((x: any, dtype: any) => x),

  // Clipping
  clipByValue: jest.fn((x: any, min: any, max: any) => x),

  // OneHot
  oneHot: jest.fn((indices: any, depth: any) => createMockTensor(indices)),

  // Pad
  pad: jest.fn((x: any, paddings: any) => x),

  // BatchNorm
  batchNormalization: jest.fn((config: any) => config),

  // Conv
  conv2d: jest.fn((config: any) => config),
  depthwiseConv2d: jest.fn((config: any) => config),
  separableConv2d: jest.fn((config: any) => config),

  // Pool
  avgPool: jest.fn((config: any) => config),
  maxPool: jest.fn((config: any) => config),

  // Normalization
  localResponseNormalization: jest.fn((config: any) => config),

  // RNN
  lstm: jest.fn((config: any) => config),
  gru: jest.fn((config: any) => config),
  simpleRNN: jest.fn((config: any) => config),

  // Environment
  env: jest.fn(),

  // IO
  io,
};

// Экспортируем как default (для import tf from '@tensorflow/tfjs-node')
export default tf;

// Экспортируем как именованный (для import * as tf from '@tensorflow/tfjs-node')
export { tf };
