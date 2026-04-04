/**
 * Jest конфигурация для тестов системы целостности
 */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests', '<rootDir>/src'],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      useESM: true
    }]
  },
  transformIgnorePatterns: [
    'node_modules/(?!(jose|@tensorflow/tfjs)/)'
  ],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '^@integrity/(.*)$': '<rootDir>/src/integrity/$1',
    '^@types/(.*)$': '<rootDir>/src/types/$1',
    '^@utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@tensorflow/tfjs-node$': '<rootDir>/tests/__mocks__/@tensorflow/tfjs-node.js',
    '^jose$': '<rootDir>/tests/__mocks__/jose.js'
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/types/**',
    '!**/node_modules/**',
    '!**/dist/**'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 50,
      functions: 50,
      lines: 50,
      statements: 50
    }
  },
  verbose: true,
  testTimeout: 30000,
  setupFilesAfterEnv: ['<rootDir>/tests/__setup__.ts'],
  // ESM support для Jest 29
  extensionsToTreatAsEsm: []
};
