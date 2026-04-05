/**
 * Setup for threat detection tests - enables fake timers
 */
jest.useFakeTimers();

afterEach(() => {
  jest.useRealTimers();
  jest.useFakeTimers();
});
