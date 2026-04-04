/**
 * Jest setup file
 */

// Глобальные моки для внешних зависимостей — используем automock чтобы избежать бесконечной рекурсии
jest.mock('ioredis', () => {
  // Возвращаем класс напрямую без require чтобы избежать рекурсии
  const MockRedisClient = jest.requireActual('./__mocks__/ioredis');
  return MockRedisClient;
});

jest.mock('elasticsearch', () => {
  return jest.requireActual('./__mocks__/elasticsearch');
});

jest.mock('@elastic/elasticsearch', () => {
  return jest.requireActual('./__mocks__/elasticsearch');
});

// Увеличиваем timeout для тяжелых крипто-тестов
jest.setTimeout(60000);
