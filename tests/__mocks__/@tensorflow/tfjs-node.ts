/**
 * Mock для @tensorflow/tfjs-node
 * Используется в тестах чтобы избежать проблем с native addon
 */

export const tf = {
  // Mock tensor functions
  tensor: jest.fn((values: any, shape?: any) => ({ values, shape })),
  scalar: jest.fn((value: any) => ({ value })),
  tensor1d: jest.fn((values: any) => ({ values })),
  tensor2d: jest.fn((values: any, shape?: any) => ({ values, shape })),
  tensor3d: jest.fn((values: any, shape?: any) => ({ values, shape })),
  tensor4d: jest.fn((values: any, shape?: any) => ({ values, shape })),
  
  // Mock math operations
  matMul: jest.fn((a: any, b: any) => ({ a, b })),
  add: jest.fn((a: any, b: any) => ({ a, b })),
  sub: jest.fn((a: any, b: any) => ({ a, b })),
  mul: jest.fn((a: any, b: any) => ({ a, b })),
  div: jest.fn((a: any, b: any) => ({ a, b })),
  
  // Mock activation functions
  relu: jest.fn((x: any) => x),
  sigmoid: jest.fn((x: any) => x),
  softmax: jest.fn((x: any) => x),
  tanh: jest.fn((x: any) => x),
  
  // Mock layers
  layers: {
    dense: jest.fn((config: any) => config),
    convolution2d: jest.fn((config: any) => config),
    maxPooling2d: jest.fn((config: any) => config),
    flatten: jest.fn(() => ({})),
    dropout: jest.fn((rate: any) => ({ rate })),
    activation: jest.fn((config: any) => config),
  },
  
  // Mock sequential model
  sequential: jest.fn((config?: any) => ({
    add: jest.fn(),
    compile: jest.fn(),
    fit: jest.fn(),
    predict: jest.fn(),
    evaluate: jest.fn(),
    save: jest.fn(),
    loadWeights: jest.fn(),
  })),
  
  // Mock functional model
  model: jest.fn((config: any) => ({
    predict: jest.fn(),
    compile: jest.fn(),
    fit: jest.fn(),
    evaluate: jest.fn(),
  })),
  
  // Mock train
  train: {
    adam: jest.fn((lr: any) => ({ lr })),
    sgd: jest.fn((lr: any) => ({ lr })),
  },
  
  // Mock metrics
  metrics: {
    categoricalCrossentropy: 'categoricalCrossentropy',
    accuracy: 'accuracy',
    meanSquaredError: 'meanSquaredError',
  },
  
  // Mock initializers
  initializers: {
    glorotUniform: jest.fn((config: any) => config),
    heNormal: jest.fn((config: any) => config),
    randomNormal: jest.fn((config: any) => config),
  },
  
  // Mock backend
  backend: jest.fn(),
  setBackend: jest.fn(),
  ready: jest.fn().mockResolvedValue(undefined),
  
  // Mock dispose
  dispose: jest.fn(),
  disposeVariables: jest.fn(),
  
  // Mock memory
  memory: jest.fn().mockReturnValue({ numBytes: 0, numTensors: 0 }),
  
  // Mock profiling
  profile: jest.fn().mockResolvedValue({}),
  
  // Mock version
  version: 'mock-4.15.0',
  
  // Mock data utilities
  data: {
    array: jest.fn((data: any) => ({ data })),
    generator: jest.fn((gen: any) => ({ gen })),
  },
  
  // Mock random
  randomNormal: jest.fn((shape: any) => ({ shape })),
  randomUniform: jest.fn((shape: any) => ({ shape })),
  
  // Mock reshape
  reshape: jest.fn((tensor: any, shape: any) => ({ tensor, shape })),
  transpose: jest.fn((tensor: any) => tensor),
  concat: jest.fn((tensors: any) => ({ tensors })),
  stack: jest.fn((tensors: any) => ({ tensors })),
  
  // Mock reduction operations
  mean: jest.fn((x: any) => x),
  sum: jest.fn((x: any) => x),
  min: jest.fn((x: any) => x),
  max: jest.fn((x: any) => x),
  argMax: jest.fn((x: any) => x),
  argMin: jest.fn((x: any) => x),
  
  // Mock comparison operations
  equal: jest.fn((a: any, b: any) => ({ a, b })),
  notEqual: jest.fn((a: any, b: any) => ({ a, b })),
  greater: jest.fn((a: any, b: any) => ({ a, b })),
  less: jest.fn((a: any, b: any) => ({ a, b })),
  
  // Mock logical operations
  logicalAnd: jest.fn((a: any, b: any) => ({ a, b })),
  logicalOr: jest.fn((a: any, b: any) => ({ a, b })),
  logicalNot: jest.fn((a: any) => a),
  
  // Mock casting
  cast: jest.fn((x: any, dtype: any) => x),
  
  // Mock clipping
  clipByValue: jest.fn((x: any, min: any, max: any) => x),
  
  // Mock oneHot
  oneHot: jest.fn((indices: any, depth: any) => ({ indices, depth })),
  
  // Mock pad
  pad: jest.fn((x: any, paddings: any) => x),
  
  // Mock batchNorm
  batchNormalization: jest.fn((config: any) => config),
  
  // Mock conv operations
  conv2d: jest.fn((config: any) => config),
  depthwiseConv2d: jest.fn((config: any) => config),
  separableConv2d: jest.fn((config: any) => config),
  
  // Mock pool operations
  avgPool: jest.fn((config: any) => config),
  maxPool: jest.fn((config: any) => config),
  
  // Mock normalization
  localResponseNormalization: jest.fn((config: any) => config),
  
  // Mock LSTM
  lstm: jest.fn((config: any) => config),
  gru: jest.fn((config: any) => config),
  simpleRNN: jest.fn((config: any) => config),
  
  // Mock environment
  env: jest.fn(),
};

export default tf;
