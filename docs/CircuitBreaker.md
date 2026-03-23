# Circuit Breaker Pattern - Документация

## Обзор

**Circuit Breaker** (Автоматический выключатель) — паттерн проектирования для защиты системы от каскадных отказов при работе с ненадежными внешними сервисами (Redis, базы данных, API).

## Назначение

- **Защита от каскадных отказов**: Предотвращает лавинообразный рост ошибок при недоступности внешнего сервиса
- **Автоматическое восстановление**: Автоматически пробует восстановить соединение после таймаута
- **Graceful degradation**: Позволяет системе работать в ограниченном режиме при отказах
- **Мониторинг и alerting**: Детальные метрики и события для систем мониторинга

## Состояния Circuit Breaker

```
┌─────────────┐     failureThreshold      ┌─────────────┐
│   CLOSED    │ ────────────────────────> │    OPEN     │
│ (Нормально) │                           │ (Разорван)  │
│             │ <────────────────────────  │             │
│             │    successThreshold        │             │
└──────┬──────┘                           └──────┬──────┘
       │                                         │
       │ resetTimeout                            │ resetTimeout
       │                                         │
       └─────────────────────────────────────────┘
                          ↓
                   ┌─────────────┐
                   │  HALF_OPEN  │
                   │ (Проверка)  │
                   └─────────────┘
```

### CLOSED (Замкнут)

**Нормальный режим работы**

- Запросы проходят к целевому сервису
- Подсчитываются успехи и неудачи
- При превышении `failureThreshold` → переход в OPEN

```typescript
const cb = new CircuitBreaker({ failureThreshold: 5 });

// Запросы выполняются нормально
await cb.execute(async () => {
  return await redis.get('key');
});
```

### OPEN (Разорван)

**Защитный режим**

- Все запросы блокируются немедленно
- Возвращается `CircuitBreakerError`
- Через `resetTimeout` → переход в HALF_OPEN

```typescript
// После 5 failures
cb.getState(); // CircuitState.OPEN

// Запрос будет заблокирован
await cb.execute(async () => {
  // Никогда не выполнится
  return await redis.get('key');
}); // → CircuitBreakerError: Circuit breaker open
```

### HALF_OPEN (Полузамкнут)

**Режим проверки восстановления**

- Разрешаются ограниченные запросы
- При успехе → счетчик успехов увеличивается
- При `successThreshold` успехах → переход в CLOSED
- При любой ошибке → немедленный возврат в OPEN

```typescript
// После resetTimeout
cb.getState(); // CircuitState.HALF_OPEN

// Тестовый запрос
await cb.execute(async () => 'test');

// При успехе счетчик увеличивается
// После 3 успехов → CLOSED
```

## Конфигурация

### Базовые параметры

```typescript
interface CircuitBreakerConfig {
  /** Максимум failures перед разрывом цепи */
  failureThreshold: number; // Default: 5
  
  /** Максимум successes для замыкания в HALF_OPEN */
  successThreshold: number; // Default: 3
  
  /** Таймаут перед попыткой восстановления (ms) */
  resetTimeout: number; // Default: 30000 (30 сек)
  
  /** Таймаут для отдельных операций (ms) */
  operationTimeout: number; // Default: 10000 (10 сек)
  
  /** Включить мониторинг */
  enableMonitoring: boolean; // Default: true
  
  /** Имя для идентификации */
  name: string; // Default: 'default'
}
```

### Рекомендации по настройке

| Параметр | Development | Production | High Availability |
|----------|-------------|------------|-------------------|
| `failureThreshold` | 3 | 5 | 10 |
| `resetTimeout` | 5000 | 30000 | 60000 |
| `successThreshold` | 2 | 3 | 5 |
| `operationTimeout` | 5000 | 10000 | 15000 |

## Использование

### Базовый пример

```typescript
import { CircuitBreaker, CircuitState } from './utils/CircuitBreaker';

// Создание
const circuitBreaker = new CircuitBreaker({
  failureThreshold: 5,
  resetTimeout: 30000,
  successThreshold: 3,
  operationTimeout: 10000,
  name: 'RedisClient'
});

// Выполнение операции
try {
  const result = await circuitBreaker.execute(async () => {
    // Ваша операция с внешним сервисом
    return await redis.get('key');
  });
  
  console.log('Результат:', result);
} catch (error) {
  if (error instanceof CircuitBreakerError) {
    console.error('Circuit breaker отклонил запрос:', error.state);
  } else {
    console.error('Ошибка операции:', error);
  }
}
```

### Интеграция с Redis Store

```typescript
export class RedisStore {
  private circuitBreaker: CircuitBreaker;
  private fallbackStore: MemoryStore;
  
  constructor(config: RedisStoreConfig) {
    this.circuitBreaker = new CircuitBreaker({
      failureThreshold: config.circuitBreaker.failureThreshold,
      resetTimeout: config.circuitBreaker.resetTimeout,
      successThreshold: config.circuitBreaker.successThreshold,
      operationTimeout: config.circuitBreaker.operationTimeout,
      name: 'RedisStore'
    });
    
    this.fallbackStore = new MemoryStore();
  }
  
  async get(key: string): Promise<StoreEntry | null> {
    // Если circuit open, используем fallback
    if (this.circuitBreaker.getState() === CircuitState.OPEN) {
      return this.fallbackStore.get(key);
    }
    
    try {
      return await this.circuitBreaker.execute(async () => {
        return await this.redisClient.get(key);
      });
    } catch (error) {
      // Fallback при ошибке
      return this.fallbackStore.get(key);
    }
  }
}
```

### Обработка событий (EventEmitter)

```typescript
// Подписка на события
circuitBreaker.on('open', (data) => {
  console.alert('Circuit разорван!', data.stats);
  // Отправить alert в мониторинг
});

circuitBreaker.on('close', (data) => {
  console.log('Circuit замкнут, сервис восстановлен', data.stats);
});

circuitBreaker.on('half_open', (data) => {
  console.warn('Попытка восстановления...', data.stats);
});

circuitBreaker.on('failure', (data) => {
  console.error('Failure зафиксирован:', data.error);
});

circuitBreaker.on('reject', (data) => {
  console.warn('Запрос отклонен:', data.state);
});
```

### Метрики и мониторинг

```typescript
// Получение статистики
const stats = circuitBreaker.getStats();

console.log({
  state: stats.state,              // Текущее состояние
  failures: stats.failures,        // Текущие failures
  successes: stats.successes,      // Текущие successes
  totalRequests: stats.totalRequests,
  totalFailures: stats.totalFailures,
  totalSuccesses: stats.totalSuccesses,
  totalRejections: stats.totalRejections,
  averageLatency: stats.averageLatency,
  lastError: stats.lastError,
  lastFailureAt: stats.lastFailureAt,
  lastSuccessAt: stats.lastSuccessAt,
  openedAt: stats.openedAt,
  nextResetAt: stats.nextResetAt
});

// Проверка доступности
if (circuitBreaker.isAvailable()) {
  // Сервис доступен
} else {
  // Использовать fallback
}
```

### Принудительный сброс

```typescript
// Принудительно замкнуть circuit (например, после ручного восстановления)
circuitBreaker.reset();

// Проверка состояния
const state = circuitBreaker.getState(); // CircuitState.CLOSED
```

## Circuit Breaker Manager

Для управления множественными circuit breakers в системе:

```typescript
import { CircuitBreakerManager } from './utils/CircuitBreaker';

const manager = new CircuitBreakerManager();

// Создание breakers для разных сервисов
const redisBreaker = manager.create('redis', {
  failureThreshold: 5,
  resetTimeout: 30000
});

const databaseBreaker = manager.create('database', {
  failureThreshold: 3,
  resetTimeout: 60000
});

const httpBreaker = manager.create('http', {
  failureThreshold: 10,
  resetTimeout: 15000
});

// Получение breaker по имени
const breaker = manager.get('redis');

// Общая статистика
const globalStats = manager.getGlobalStats();
console.log({
  total: globalStats.total,
  open: globalStats.open,      // Сколько в OPEN
  closed: globalStats.closed,  // Сколько в CLOSED
  halfOpen: globalStats.halfOpen
});

// Проброс событий
manager.on('breaker:open', ({ name, breaker }) => {
  console.alert(`Circuit ${name} разорван!`);
});

// Уничтожение всех
manager.destroyAll();
```

## Декоратор @circuitBreaker

Автоматическое применение circuit breaker к методам класса:

```typescript
import { circuitBreaker, CircuitBreaker } from './utils/CircuitBreaker';

const breaker = new CircuitBreaker({
  failureThreshold: 3,
  name: 'MyService'
});

class MyService {
  @circuitBreaker(breaker)
  async fetchData(id: string): Promise<Data> {
    return await this.api.get(`/data/${id}`);
  }
  
  @circuitBreaker(breaker, (error) => ({ id: 'fallback', data: null }))
  async fetchDataWithFallback(id: string): Promise<Data> {
    return await this.api.get(`/data/${id}`);
  }
}

// Использование
const service = new MyService();
const data = await service.fetchData('123');
```

## Environment Variables

Конфигурация через переменные окружения:

```bash
# ===== CIRCUIT BREAKER CONFIGURATION =====
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
CIRCUIT_BREAKER_RESET_TIMEOUT=30000
CIRCUIT_BREAKER_SUCCESS_THRESHOLD=3
CIRCUIT_BREAKER_OPERATION_TIMEOUT=10000
CIRCUIT_BREAKER_ENABLE_MONITORING=true

# ===== RETRY CONFIGURATION =====
CIRCUIT_BREAKER_RETRY_MAX_ATTEMPTS=3
CIRCUIT_BREAKER_RETRY_INITIAL_DELAY=100
CIRCUIT_BREAKER_RETRY_MAX_DELAY=5000
CIRCUIT_BREAKER_RETRY_MULTIPLIER=2
CIRCUIT_BREAKER_RETRY_JITTER=0.2
CIRCUIT_BREAKER_RETRY_STRATEGY=EXPONENTIAL_WITH_JITTER
```

## Best Practices

### 1. Выбор failureThreshold

```typescript
// ❌ Слишком низкий - частые ложные срабатывания
failureThreshold: 1

// ❌ Слишком высокий - медленная реакция на отказы
failureThreshold: 100

// ✅ Оптимальный баланс
failureThreshold: 5
```

### 2. Настройка resetTimeout

```typescript
// ❌ Слишком короткий - нагрузка на восстанавливающийся сервис
resetTimeout: 1000 // 1 секунда

// ❌ Слишком длинный - долгое время простоя
resetTimeout: 300000 // 5 минут

// ✅ Разумный компромисс
resetTimeout: 30000 // 30 секунд
```

### 3. Fallback стратегия

```typescript
async getData(key: string) {
  if (circuitBreaker.getState() === CircuitState.OPEN) {
    // ✅ Graceful degradation
    return cache.get(key) || defaultValue;
  }
  
  return circuitBreaker.execute(async () => {
    return database.get(key);
  });
}
```

### 4. Мониторинг и alerting

```typescript
circuitBreaker.on('open', (data) => {
  // ✅ Отправить alert в PagerDuty/Slack
  alertingService.sendAlert({
    severity: 'critical',
    service: data.stats.name,
    message: 'Circuit breaker opened',
    stats: data.stats
  });
});
```

### 5. Логирование

```typescript
// ✅ Структурированное логирование
logger.warning('Circuit breaker opened', {
  service: 'redis',
  failures: stats.failures,
  threshold: config.failureThreshold,
  timestamp: new Date().toISOString()
});
```

## Тестирование

### Unit тесты

```typescript
import { CircuitBreaker, CircuitState } from './CircuitBreaker';

describe('Circuit Breaker', () => {
  it('должен переходить в OPEN после failureThreshold ошибок', async () => {
    const cb = new CircuitBreaker({ failureThreshold: 3 });
    
    // 3 failures
    for (let i = 0; i < 3; i++) {
      await expect(
        cb.execute(async () => { throw new Error('Fail'); })
      ).rejects.toThrow();
    }
    
    expect(cb.getState()).toBe(CircuitState.OPEN);
  });
  
  it('должен восстанавливаться после resetTimeout', async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 1,
      resetTimeout: 100
    });
    
    // Открыть circuit
    await expect(
      cb.execute(async () => { throw new Error('Fail'); })
    ).rejects.toThrow();
    
    // Ждать reset
    await sleep(150);
    
    // Запрос для проверки восстановления
    await cb.execute(async () => 'ok');
    
    expect(cb.getState()).toBe(CircuitState.HALF_OPEN);
  });
});
```

### Integration тесты с Redis

```typescript
describe('RedisStore with Circuit Breaker', () => {
  it('должен использовать fallback при открытом circuit', async () => {
    const store = new RedisStore({
      host: 'localhost',
      port: 6379,
      circuitBreaker: { failureThreshold: 1 }
    });
    
    await store.initialize();
    
    // Эмулировать отказ Redis
    await store.increment('key', 1000); // failure
    
    // Следующий запрос должен использовать fallback
    const result = await store.increment('key', 1000);
    
    expect(result).toBeDefined(); // Из fallback store
  });
});
```

## Распространенные ошибки

### 1. Игнорирование CircuitBreakerError

```typescript
// ❌ Неправильно
try {
  await cb.execute(operation);
} catch (error) {
  // Все ошибки обрабатываются одинаково
  logger.error(error);
}

// ✅ Правильно
try {
  await cb.execute(operation);
} catch (error) {
  if (error instanceof CircuitBreakerError) {
    // Использовать fallback
    return fallback();
  }
  // Логировать ошибку операции
  logger.error(error);
  throw error;
}
```

### 2. Отсутствие fallback

```typescript
// ❌ Нет fallback - сервис полностью недоступен
async getData() {
  return circuitBreaker.execute(async () => {
    return redis.get('key');
  });
}

// ✅ С fallback
async getData() {
  try {
    return await circuitBreaker.execute(async () => {
      return redis.get('key');
    });
  } catch {
    return memoryCache.get('key');
  }
}
```

### 3. Неправильная настройка таймаутов

```typescript
// ❌ resetTimeout < operationTimeout
const cb = new CircuitBreaker({
  resetTimeout: 1000,      // 1 секунда
  operationTimeout: 5000   // 5 секунд - операция дольше чем reset!
});

// ✅ resetTimeout > operationTimeout
const cb = new CircuitBreaker({
  resetTimeout: 30000,     // 30 секунд
  operationTimeout: 10000  // 10 секунд
});
```

## Метрики для мониторинга

### Ключевые метрики

1. **Circuit State**: Текущее состояние (CLOSED/OPEN/HALF_OPEN)
2. **Failure Rate**: Процент неудачных операций
3. **Rejection Rate**: Процент отклоненных запросов
4. **Average Latency**: Среднее время выполнения
5. **Recovery Time**: Время от OPEN до CLOSED

### Prometheus метрики

```typescript
// Пример экспорта метрик
const circuitBreakerMetrics = {
  state: new Gauge({
    name: 'circuit_breaker_state',
    help: 'Current circuit breaker state (0=CLOSED, 1=OPEN, 2=HALF_OPEN)',
    labelNames: ['service']
  }),
  
  failures: new Counter({
    name: 'circuit_breaker_failures_total',
    help: 'Total number of failures',
    labelNames: ['service']
  }),
  
  rejections: new Counter({
    name: 'circuit_breaker_rejections_total',
    help: 'Total number of rejected requests',
    labelNames: ['service']
  })
};

// Обновление метрик
circuitBreaker.on('open', () => {
  circuitBreakerMetrics.state.set({ service: 'redis' }, 1);
});

circuitBreaker.on('failure', () => {
  circuitBreakerMetrics.failures.inc({ service: 'redis' });
});
```

## См. также

- [RetryHandler Documentation](./RetryHandler.md) - Exponential backoff retry logic
- [RateLimitMiddleware Documentation](./RateLimitMiddleware.md) - Rate limiting с Circuit Breaker
- [Resilience Patterns](https://github.com/App-vNext/Polly/wiki/Resilience-Patterns) - Паттерны устойчивости
- [Martin Fowler: CircuitBreaker](https://martinfowler.com/bliki/CircuitBreaker.html) - Оригинальная статья

## Лицензия

MIT License - см. LICENSE файл в корне проекта.
