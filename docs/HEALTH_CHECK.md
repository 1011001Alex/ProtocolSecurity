# Health Check Service — Документация

## Обзор

**Health Check Service** — это комплексная система проверки здоровья всех компонентов системы Protocol Security. Предназначена для интеграции с Kubernetes, Prometheus и другими системами мониторинга.

## Возможности

- ✅ **Проверка Redis подключения** — мониторинг доступности Redis
- ✅ **Проверка Database подключения** — контроль состояния базы данных
- ✅ **Проверка External APIs** — Vault, Elasticsearch
- ✅ **Проверка памяти/CPU** — мониторинг системных ресурсов
- ✅ **Проверка circuit breakers** — отслеживание состояния защитных механизмов
- ✅ **Prometheus metrics** — экспорт метрик в формате Prometheus
- ✅ **Kubernetes integration** — liveness/readiness/startup probes
- ✅ **JSON формат** — структурированный ответ со статусом компонентов

---

## Быстрый старт

### 1. Настройка переменных окружения

Добавьте в `.env` файл:

```bash
# Health Check конфигурация
HEALTH_CHECK_ENABLED=true
HEALTH_CHECK_INTERVAL=10000
HEALTH_CHECK_REDIS_TIMEOUT=5000
HEALTH_CHECK_DATABASE_TIMEOUT=5000
HEALTH_CHECK_VAULT_TIMEOUT=5000
HEALTH_CHECK_ELASTICSEARCH_TIMEOUT=5000
HEALTH_CHECK_ENABLE_PROMETHEUS=true
HEALTH_CHECK_PROMETHEUS_PORT=9090
```

### 2. Запуск сервера

```bash
npm run build
npm start
```

### 3. Проверка endpoints

```bash
# Базовая проверка
curl http://localhost:3000/health

# Проверка готовности
curl http://localhost:3000/ready

# Проверка жизнеспособности
curl http://localhost:3000/live

# Prometheus метрики
curl http://localhost:3000/health/prometheus
```

---

## API Endpoints

### GET /health

**Описание:** Базовая проверка доступности приложения

**Ответ:**
```json
{
  "status": "healthy",
  "timestamp": "2026-03-23T12:00:00.000Z",
  "uptime": 3600.5,
  "environment": "production",
  "version": "v18.16.0",
  "pid": 12345
}
```

**Статусы:**
- `healthy` — приложение работает нормально
- `warning` — есть незначительные проблемы
- `unhealthy` — критические проблемы
- `unknown` — статус не определен

---

### GET /health/detailed

**Описание:** Полная проверка всех компонентов с детальной информацией

**Ответ:**
```json
{
  "status": "healthy",
  "timestamp": "2026-03-23T12:00:00.000Z",
  "uptime": 3600.5,
  "environment": "production",
  "version": "v18.16.0",
  "components": {
    "redis": {
      "name": "Redis",
      "type": "redis",
      "status": "healthy",
      "responseTime": 5,
      "timestamp": "2026-03-23T12:00:00.000Z"
    },
    "database": {
      "name": "Database",
      "type": "database",
      "status": "healthy",
      "responseTime": 12,
      "timestamp": "2026-03-23T12:00:00.000Z"
    },
    "vault": {
      "name": "Vault",
      "type": "vault",
      "status": "healthy",
      "responseTime": 25,
      "timestamp": "2026-03-23T12:00:00.000Z"
    },
    "elasticsearch": {
      "name": "Elasticsearch",
      "type": "elasticsearch",
      "status": "healthy",
      "responseTime": 30,
      "timestamp": "2026-03-23T12:00:00.000Z"
    },
    "circuit_breakers": {
      "name": "Circuit Breakers",
      "type": "circuit_breaker",
      "status": "healthy",
      "details": {
        "total": 4,
        "open": 0,
        "closed": 4,
        "halfOpen": 0
      }
    },
    "memory": {
      "name": "Memory",
      "type": "memory",
      "status": "healthy",
      "details": {
        "heapUsed": 52428800,
        "heapTotal": 104857600,
        "rss": 83886080,
        "usagePercent": 50
      }
    },
    "cpu": {
      "name": "CPU",
      "type": "cpu",
      "status": "healthy",
      "details": {
        "usage": 25.5,
        "loadAverage": [1.5, 1.2, 0.8],
        "cores": 8
      }
    },
    "application": {
      "name": "Application",
      "type": "application",
      "status": "healthy",
      "details": {
        "pid": 12345,
        "uptime": 3600.5,
        "environment": "production"
      }
    }
  },
  "summary": {
    "total": 8,
    "healthy": 8,
    "warning": 0,
    "unhealthy": 0,
    "unknown": 0
  }
}
```

---

### GET /ready

**Описание:** Проверка готовности принимать трафик (Kubernetes readiness probe)

**Особенности:**
- Проверяет все зависимости: Redis, Database, Vault, Elasticsearch
- Проверяет circuit breakers
- Проверяет системные ресурсы (memory, CPU)
- Возвращает `503 Service Unavailable` если не готов

**Ответ (готов):**
```json
{
  "ready": true,
  "status": "healthy",
  "timestamp": "2026-03-23T12:00:00.000Z",
  "summary": {
    "total": 8,
    "healthy": 8,
    "warning": 0,
    "unhealthy": 0,
    "unknown": 0
  },
  "components": {
    "redis": "healthy",
    "database": "healthy",
    "vault": "healthy",
    "elasticsearch": "healthy",
    "circuitBreakers": "healthy",
    "memory": "healthy",
    "cpu": "healthy"
  }
}
```

**Ответ (не готов):**
```json
{
  "ready": false,
  "status": "unhealthy",
  "error": "Redis connection failed",
  "timestamp": "2026-03-23T12:00:00.000Z"
}
```

---

### GET /live

**Описание:** Проверка жизнеспособности (Kubernetes liveness probe)

**Особенности:**
- Быстрая проверка без проверки зависимостей
- Проверяет что процесс не "завис"
- Возвращает `503 Service Unavailable` если не жив

**Ответ:**
```json
{
  "live": true,
  "status": "healthy",
  "timestamp": "2026-03-23T12:00:00.000Z",
  "uptime": 3600.5,
  "pid": 12345
}
```

---

### GET /health/prometheus

**Описание:** Экспорт метрик в формате Prometheus

**Content-Type:** `text/plain; version=0.0.4; charset=utf-8`

**Пример метрик:**
```
# HELP protocol_health_status Общий статус здоровья (1=healthy, 0=unhealthy)
# TYPE protocol_health_status gauge
protocol_health_status{environment="production"} 1

# HELP protocol_health_uptime Uptime процесса в секундах
# TYPE protocol_health_uptime gauge
protocol_health_uptime{environment="production"} 3600.5

# HELP protocol_health_component_status Статус компонента (1=healthy, 0=unhealthy)
# TYPE protocol_health_component_status gauge
protocol_health_component_status{component="redis",type="redis"} 1
protocol_health_component_status{component="database",type="database"} 1

# HELP protocol_memory_heap_used Использовано heap памяти (bytes)
# TYPE protocol_memory_heap_used gauge
protocol_memory_heap_used 52428800

# HELP protocol_circuit_breaker_state Состояние circuit breaker (0=CLOSED, 1=OPEN, 2=HALF_OPEN)
# TYPE protocol_circuit_breaker_state gauge
protocol_circuit_breaker_state{name="redis"} 0
```

---

### GET /health/cached

**Описание:** Кэшированный результат последней проверки

**Особенности:**
- Возвращает последний результат без выполнения новой проверки
- Полезно для снижения нагрузки при частых запросах

---

## Конфигурация

### Переменные окружения

| Переменная | Описание | По умолчанию | Рекомендуемое (prod) |
|------------|----------|--------------|---------------------|
| `HEALTH_CHECK_ENABLED` | Включить health checks | `true` | `true` |
| `HEALTH_CHECK_INTERVAL` | Интервал проверок (мс) | `10000` | `10000-30000` |
| `HEALTH_CHECK_REDIS_TIMEOUT` | Таймаут Redis (мс) | `5000` | `3000-5000` |
| `HEALTH_CHECK_DATABASE_TIMEOUT` | Таймаут БД (мс) | `5000` | `3000-5000` |
| `HEALTH_CHECK_VAULT_TIMEOUT` | Таймаут Vault (мс) | `5000` | `5000-10000` |
| `HEALTH_CHECK_ELASTICSEARCH_TIMEOUT` | Таймаут Elasticsearch (мс) | `5000` | `5000-10000` |
| `HEALTH_CHECK_ENABLE_PROMETHEUS` | Включить Prometheus | `true` | `true` |
| `HEALTH_CHECK_PROMETHEUS_PORT` | Порт Prometheus | `9090` | `9090` |

---

## Kubernetes Integration

### Liveness Probe

Проверяет что приложение живо. Если проверка не проходит — Kubernetes перезапускает контейнер.

```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 3000
  initialDelaySeconds: 15
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

### Readiness Probe

Проверяет готовность принимать трафик. Если проверка не проходит — pod удаляется из load balancer.

```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 3000
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
```

### Startup Probe

Для приложений с долгим запуском. Защищает от преждевременного restart.

```yaml
startupProbe:
  httpGet:
    path: /health
    port: 3000
  initialDelaySeconds: 0
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 12  # 60 секунд на запуск
```

---

## Prometheus Metrics

### Основные метрики

| Метрика | Тип | Описание |
|---------|-----|----------|
| `protocol_health_status` | gauge | Общий статус (1=healthy, 0=unhealthy) |
| `protocol_health_uptime` | gauge | Uptime процесса в секундах |
| `protocol_health_component_status` | gauge | Статус компонента |
| `protocol_health_component_response_time` | gauge | Время ответа компонента (ms) |
| `protocol_health_summary_total` | gauge | Всего компонентов |
| `protocol_health_summary_healthy` | gauge | Здоровых компонентов |
| `protocol_health_summary_warning` | gauge | Компонентов с warning |
| `protocol_health_summary_unhealthy` | gauge | Нездоровых компонентов |

### Memory метрики

| Метрика | Тип | Описание |
|---------|-----|----------|
| `protocol_memory_heap_used` | gauge | Использовано heap памяти (bytes) |
| `protocol_memory_heap_total` | gauge | Всего heap памяти (bytes) |
| `protocol_memory_rss` | gauge | RSS памяти (bytes) |
| `protocol_memory_external` | gauge | External памяти (bytes) |

### Circuit Breaker метрики

| Метрика | Тип | Описание |
|---------|-----|----------|
| `protocol_circuit_breaker_state` | gauge | Состояние (0=CLOSED, 1=OPEN, 2=HALF_OPEN) |
| `protocol_circuit_breaker_failures` | counter | Количество failures |
| `protocol_circuit_breaker_successes` | counter | Количество successes |

---

## Примеры использования

### Проверка статуса Redis

```bash
curl -s http://localhost:3000/health/detailed | jq '.components.redis'
```

### Мониторинг circuit breakers

```bash
curl -s http://localhost:3000/health/detailed | jq '.components.circuit_breakers.details'
```

### Проверка готовности для CI/CD

```bash
#!/bin/bash
# wait-for-ready.sh

MAX_ATTEMPTS=30
ATTEMPT=0

while [ $ATTEMPT -lt $MAX_ATTEMPTS ]; do
  RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/ready)
  
  if [ "$RESPONSE" = "200" ]; then
    echo "Service is ready!"
    exit 0
  fi
  
  ATTEMPT=$((ATTEMPT + 1))
  echo "Waiting for service to be ready... (attempt $ATTEMPT/$MAX_ATTEMPTS)"
  sleep 2
done

echo "Service failed to become ready"
exit 1
```

### Grafana Dashboard

Пример query для Grafana:

```promql
# Процент здоровых компонентов
sum(protocol_health_component_status{status="healthy"}) 
/ 
sum(protocol_health_component_status) * 100
```

---

## Обработка ошибок

### Статусы компонентов

| Статус | Значение | Когда возвращается |
|--------|----------|-------------------|
| `healthy` | Компонент работает нормально | Все проверки пройдены |
| `warning` | Есть незначительные проблемы | Настройки не полные, но работа возможна |
| `unhealthy` | Критическая проблема | Компонент недоступен |
| `unknown` | Статус не определен | Компонент не настроен |

### Примеры ошибок

**Redis не настроен:**
```json
{
  "name": "Redis",
  "type": "redis",
  "status": "unknown",
  "error": "Redis клиент не настроен"
}
```

**Vault токен не настроен:**
```json
{
  "name": "Vault",
  "type": "vault",
  "status": "warning",
  "error": "Vault токен не настроен (development режим)"
}
```

**Circuit breaker открыт:**
```json
{
  "name": "Redis",
  "type": "redis",
  "status": "unhealthy",
  "error": "Circuit breaker в состоянии OPEN"
}
```

---

## Best Practices

### 1. Настройка таймаутов

Для production среды рекомендуется:

```bash
HEALTH_CHECK_INTERVAL=10000        # 10 секунд
HEALTH_CHECK_REDIS_TIMEOUT=3000    # 3 секунды
HEALTH_CHECK_DATABASE_TIMEOUT=3000 # 3 секунды
```

### 2. Kubernetes probes

- **Liveness:** Частая проверка (5-10s), быстрый failure (2-3)
- **Readiness:** Консервативная проверка (5s), несколько успехов (2)
- **Startup:** Долгий запуск (60-90s), защита от restart

### 3. Alerting

Настройте alerting в Prometheus:

```yaml
groups:
- name: health
  rules:
  - alert: ServiceUnhealthy
    expr: protocol_health_status == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "Service is unhealthy"
```

### 4. Graceful Shutdown

Service автоматически останавливается при получении SIGTERM/SIGINT:

```typescript
process.on('SIGTERM', () => {
  healthCheckService.stop();
  process.exit(0);
});
```

---

## Тестирование

### Запуск тестов

```bash
npm test -- tests/health/HealthCheckService.test.ts
```

### Покрытие

Тесты покрывают:
- ✅ Конструктор и инициализацию
- ✅ Интеграцию с Circuit Breaker Manager
- ✅ Интеграцию с Performance Monitor
- ✅ Проверку Redis
- ✅ Проверку Database
- ✅ Проверку Vault
- ✅ Проверку Elasticsearch
- ✅ Проверку Circuit Breakers
- ✅ Проверку Memory
- ✅ Проверку CPU
- ✅ Проверку External APIs
- ✅ Проверку Application
- ✅ Расчет общего статуса
- ✅ Подсчет статистики
- ✅ Liveness check
- ✅ Readiness check
- ✅ Prometheus metrics
- ✅ Event emitter
- ✅ Start/Stop
- ✅ Singleton pattern
- ✅ Configuration defaults

---

## Архитектура

### Компоненты

```
┌─────────────────────────────────────────────────────────┐
│                  HealthCheckService                     │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │    Redis    │  │  Database   │  │    Vault    │     │
│  │    Check    │  │    Check    │  │    Check    │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │Elasticsearch│  │   Circuit   │  │   Memory/   │     │
│  │    Check    │  │  Breakers   │  │    CPU      │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
├─────────────────────────────────────────────────────────┤
│              Prometheus Metrics Export                  │
│              Event Emitter (issues, status)             │
└─────────────────────────────────────────────────────────┘
```

### Поток данных

1. **Периодическая проверка** (каждые N секунд)
2. **Проверка компонентов** (параллельно или последовательно)
3. **Расчет статуса** (агрегация результатов)
4. **Экспорт метрик** (Prometheus format)
5. **События** (issue detected, status changed)

---

## Расширение

### Добавление внешней API

```typescript
const service = getHealthCheckService();

service.addExternalApi(
  'custom_api',
  'https://api.example.com/health',
  true  // enabled
);
```

### Кастомная проверка

```typescript
const result = await service.performHealthCheck({
  checkRedis: true,
  checkDatabase: true,
  checkVault: false,      // Пропустить Vault
  checkElasticsearch: false,
  checkCircuitBreakers: true,
  checkSystemResources: true,
  checkExternalApis: false
});
```

---

## Troubleshooting

### Проблема: /ready возвращает 503

**Причина:** Зависимость недоступна

**Решение:**
1. Проверьте логи: `kubectl logs <pod>`
2. Проверьте статус зависимостей: `curl /health/detailed`
3. Увеличьте таймауты если зависимости медленные

### Проблема: Circuit breaker открыт

**Причина:** Много failures подряд

**Решение:**
1. Проверьте логи circuit breaker
2. Увеличьте `failureThreshold` если слишком чувствительный
3. Проверьте сеть до зависимостей

### Проблема: Prometheus не собирает метрики

**Причина:** Неправильный path или порт

**Решение:**
1. Проверьте annotations в deployment
2. Проверьте PodMonitor конфигурацию
3. Проверьте доступность endpoint: `curl /health/prometheus`

---

## Лицензия

MIT License — Created by Theodor Munch
