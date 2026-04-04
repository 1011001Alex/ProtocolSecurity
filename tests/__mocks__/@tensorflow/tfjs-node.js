/**
 * Mock для @tensorflow/tfjs-node (JS версия для Jest)
 */

function createMockTensor(data) {
  return {
    dataSync: () => (data ? (Array.isArray(data) ? data : [data]) : [0]),
    data: () => Promise.resolve(data ? (Array.isArray(data) ? data : [data]) : [0]),
    dispose: () => {},
    reshape: function () { return createMockTensor(data); },
    sub: function (other) { return createMockTensor(data); },
    div: function (other) { return createMockTensor(data); },
    square: function () { return createMockTensor(data); },
    mean: function (axis) { return createMockTensor(data); },
    sqrt: function () { return createMockTensor(data); },
    add: function (other) { return createMockTensor(data); },
  };
}

const metrics = {
  meanSquaredError: (a, b) => createMockTensor([0.1]),
  categoricalCrossentropy: 'categoricalCrossentropy',
  accuracy: 'accuracy',
};

const layers = {
  dense: (config) => config,
  dropout: (config) => config,
  lstm: (config) => config,
  activation: (config) => config,
};

const train = {
  adam: (lr) => ({ lr }),
  sgd: (lr) => ({ lr }),
};

const sequential = () => {
  const layersList = [];
  return {
    add: (layer) => { layersList.push(layer); },
    compile: () => {},
    fit: () => Promise.resolve({
      history: { loss: [0.5, 0.3, 0.2], mae: [0.4, 0.2, 0.1], acc: [0.6, 0.8, 0.9], accuracy: [0.6, 0.8, 0.9] },
    }),
    predict: () => createMockTensor([[0.1]]),
    evaluate: () => Promise.resolve([0.2, 0.9]),
    save: () => Promise.resolve(),
    loadWeights: () => {},
    dispose: () => {},
    inputs: [{ shape: [null, 10] }],
    outputs: [{ shape: [null, 1] }],
    layers: layersList,
  };
};

const model = (config) => ({
  predict: () => createMockTensor([[0.1]]),
  compile: () => {},
  fit: () => Promise.resolve({ history: { loss: [0.5, 0.3, 0.2], acc: [0.6, 0.8, 0.9] } }),
  evaluate: () => Promise.resolve([0.2, 0.9]),
  dispose: () => {},
});

const loadLayersModel = () => Promise.resolve({
  predict: () => createMockTensor([[0.1]]),
  compile: () => {},
  fit: () => {},
  dispose: () => {},
  inputs: [{ shape: [null, 10] }],
});

const io = {
  saveModel: () => Promise.resolve(),
  loadModel: () => Promise.resolve({}),
};

const tf = {
  tensor: (values, shape) => createMockTensor(values),
  scalar: (value) => createMockTensor(value),
  tensor1d: (values) => createMockTensor(values),
  tensor2d: (values, shape) => createMockTensor(values),
  tensor3d: (values, shape) => createMockTensor(values),
  tensor4d: (values, shape) => createMockTensor(values),
  matMul: (a, b) => createMockTensor(a),
  add: (a, b) => createMockTensor(a),
  sub: (a, b) => createMockTensor(a),
  mul: (a, b) => createMockTensor(a),
  div: (a, b) => createMockTensor(a),
  relu: (x) => x,
  sigmoid: (x) => x,
  softmax: (x) => x,
  tanh: (x) => x,
  layers,
  sequential,
  model,
  loadLayersModel,
  train,
  metrics,
  initializers: { glorotUniform: (c) => c, heNormal: (c) => c, randomNormal: (c) => c },
  backend: () => {},
  setBackend: () => {},
  ready: () => Promise.resolve(),
  dispose: () => {},
  disposeVariables: () => {},
  memory: () => ({ numBytes: 0, numTensors: 0 }),
  profile: () => Promise.resolve({}),
  version: 'mock-4.22.0',
  data: { array: (d) => ({ data: d }), generator: (g) => ({ gen: g }) },
  randomNormal: (shape) => createMockTensor(shape),
  randomUniform: (shape) => createMockTensor(shape),
  reshape: (t, s) => createMockTensor(t),
  transpose: (t) => t,
  concat: (t) => createMockTensor(t),
  stack: (t) => createMockTensor(t),
  mean: (x) => createMockTensor(x),
  sum: (x) => createMockTensor(x),
  min: (x) => createMockTensor(x),
  max: (x) => createMockTensor(x),
  argMax: (x) => createMockTensor(x),
  argMin: (x) => createMockTensor(x),
  equal: (a, b) => createMockTensor(a),
  notEqual: (a, b) => createMockTensor(a),
  greater: (a, b) => createMockTensor(a),
  less: (a, b) => createMockTensor(a),
  logicalAnd: (a, b) => createMockTensor(a),
  logicalOr: (a, b) => createMockTensor(a),
  logicalNot: (a) => a,
  cast: (x, dt) => x,
  clipByValue: (x, mn, mx) => x,
  oneHot: (i, d) => createMockTensor(i),
  pad: (x, p) => x,
  batchNormalization: (c) => c,
  conv2d: (c) => c,
  depthwiseConv2d: (c) => c,
  separableConv2d: (c) => c,
  avgPool: (c) => c,
  maxPool: (c) => c,
  localResponseNormalization: (c) => c,
  lstm: (c) => c,
  gru: (c) => c,
  simpleRNN: (c) => c,
  env: () => {},
  io,
};

module.exports = tf;
module.exports.default = tf;
module.exports.tf = tf;
