# CORS Middleware Documentation

## Обзор

CORS (Cross-Origin Resource Sharing) Middleware обеспечивает безопасную настройку доступа к API из разных источников.

## Функционал

- ✅ **Domain whitelist/blacklist** - Управление разрешёнными и заблокированными доменами
- ✅ **Dynamic origin validation** - Динамическая проверка origin
- ✅ **Preflight request caching** - Кэширование preflight запросов (maxAge)
- ✅ **Credentials support** - Поддержка cookies и authorization headers
- ✅ **Custom headers/methods** - Настройка разрешённых заголовков и методов
- ✅ **CORS Presets** - Готовые конфигурации для различных сценариев
- ✅ **Configuration validation** - Валидация конфигурации

## Установка

Middleware уже установлен в проекте:

```
src/middleware/CORSMiddleware.ts
```

## Быстрый старт

### Базовое использование

```typescript
import { createCORS } from './middleware/CORSMiddleware';

// Создать middleware с конфигурацией по умолчанию
const corsMiddleware = createCORS();
app.use(corsMiddleware);
```

### Конфигурация

```typescript
import { createCORS } from './middleware/CORSMiddleware';

const corsMiddleware = createCORS({
  origin: 'https://example.com',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['X-Request-ID'],
  credentials: true,
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204,
  strict: true,
  blacklistedOrigins: ['https://malicious.com'],
  dynamicOrigin: false
});

app.use(corsMiddleware);
```

## CORS Presets

Готовые конфигурации для распространённых сценариев:

### Public API

Открытый API для всех источников:

```typescript
import { CORSPresets } from './middleware/CORSMiddleware';

app.use(CORSPresets.public);
```

**Конфигурация:**
- `origin: '*'` - все источники
- `credentials: false` - без cookies
- `maxAge: 3600` - кэш 1 час

### Private API

Закрытый API для конкретных доменов:

```typescript
import { CORSPresets } from './middleware/CORSMiddleware';

const privateCORS = CORSPresets.private([
  'https://app.example.com',
  'https://admin.example.com'
]);

app.use(privateCORS);
```

**Конфигурация:**
- `origin: [...]` - только указанные домены
- `credentials: true` - с cookies
- `maxAge: 86400` - кэш 24 часа
- `strict: true` - строгая валидация

### Development

Разработка с localhost:

```typescript
import { CORSPresets } from './middleware/CORSMiddleware';

app.use(CORSPresets.dev);
```

**Конфигурация:**
- `origin: [/^https?:\/\/localhost(:\d+)?$/]` - localhost
- `credentials: true` - с cookies
- `dynamicOrigin: true` - динамическое отражение
- `maxAge: 600` - кэш 10 минут

### API Gateway

Шлюз с строгой безопасностью:

```typescript
import { CORSPresets } from './middleware/CORSMiddleware';

const apiGatewayCORS = CORSPresets.apiGateway([
  'https://api.example.com',
  'https://gateway.example.com'
]);

app.use(apiGatewayCORS);
```

**Конфигурация:**
- `origin: [...]` - домены шлюза
- `credentials: true` - с cookies
- `allowedHeaders: [..., 'X-API-Key']` - API ключи
- `maxAge: 86400` - кэш 24 часа

### Microservice

Внутренний микросервис:

```typescript
import { CORSPresets } from './middleware/CORSMiddleware';

app.use(CORSPresets.microservice);
```

**Конфигурация:**
- `origin: '*'` - все источники внутри сети
- `credentials: false` - без cookies
- `allowedHeaders: [..., 'X-Service-Key']` - сервис ключи

## Переменные окружения

Настройка через `.env`:

```bash
# ===== CORS CONFIGURATION =====
CORS_MODE=dev
CORS_ORIGINS=*
CORS_METHODS=GET,POST,PUT,DELETE,PATCH,OPTIONS
CORS_ALLOWED_HEADERS=Content-Type,Authorization,X-Requested-With,X-Request-ID
CORS_EXPOSED_HEADERS=X-Request-ID,X-RateLimit-Limit,X-RateLimit-Remaining
CORS_CREDENTIALS=false
CORS_MAX_AGE=86400
CORS_PREFLIGHT_CONTINUE=false
CORS_OPTIONS_SUCCESS_STATUS=204
CORS_STRICT=false
CORS_BLACKLIST=
CORS_DYNAMIC_ORIGIN=false
```

## Валидация конфигурации

```typescript
import { validateCORSConfig } from './middleware/CORSMiddleware';

const errors = validateCORSConfig({
  origin: '*',
  credentials: true  // ОШИБКА: wildcard с credentials
});

if (errors.length > 0) {
  errors.forEach(err => console.error(err.message));
}
```

**Проверяемые правила:**

1. ❌ `origin: '*'` + `credentials: true` - запрещено
2. ❌ `maxAge < 0` или `maxAge > 2592000` - вне диапазона
3. ❌ `dynamicOrigin: true` + `strict: true` - конфликт
4. ❌ Wildcard в массиве origins (`*.example.com`) - используйте RegExp

## Примеры использования

### Разрешить несколько доменов

```typescript
const corsMiddleware = createCORS({
  origin: [
    'https://example.com',
    'https://www.example.com',
    /^https:\/\/.*\.example\.com$/  // RegExp для поддоменов
  ],
  credentials: true
});
```

### Блокировать конкретные домены

```typescript
const corsMiddleware = createCORS({
  origin: '*',
  blacklistedOrigins: [
    'https://malicious.com',
    '*.evil.com'  // wildcard pattern
  ]
});
```

### Динамический origin для разработки

```typescript
const corsMiddleware = createCORS({
  origin: '*',
  dynamicOrigin: true  // Отражает origin из запроса
});
```

### Строгий режим для production

```typescript
const corsMiddleware = createCORS({
  origin: 'https://app.example.com',
  strict: true,  // Требует точного совпадения
  credentials: true,
  maxAge: 86400
});
```

## Интеграция с Express

### Полная конфигурация приложения

```typescript
import express from 'express';
import { createCORS, CORSPresets } from './middleware/CORSMiddleware';
import { createSecurityHeadersMiddleware } from './middleware/SecurityHeadersMiddleware';
import { RateLimiter, createRateLimiter, createMemoryStore } from './middleware/RateLimitMiddleware';

const app = express();

// 1. CORS
app.use(CORSPresets.dev);

// 2. Security Headers
const securityHeaders = createSecurityHeadersMiddleware();
app.use((req, res, next) => {
  securityHeaders.handle(req, res);
  next();
});

// 3. Rate Limiting
const initRateLimiter = async () => {
  const store = createMemoryStore();
  const rateLimiter = createRateLimiter(store, true);
  await rateLimiter.initialize();
  rateLimiter.addRule({
    name: 'api',
    algorithm: 'fixed_window',
    maxRequests: 100,
    windowMs: 60000,
    keyGenerator: (req) => req.ip,
    message: 'Too many requests'
  });
  app.use((req, res, next) => rateLimiter.handle(req, res, next));
};
initRateLimiter();

// 4. Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 5. Routes
app.get('/api/data', (req, res) => {
  res.json({ data: 'Hello World' });
});

app.listen(3000);
```

### Использование с готовым app.ts

```typescript
import { startServer } from './app';

// Запуск с конфигурацией по умолчанию
startServer();

// Или с кастомной конфигурацией
startServer({
  port: 8080,
  corsMode: 'private'
});
```

## Тестирование

Запуск тестов:

```bash
npm test -- tests/middleware/CORSMiddleware.test.ts
```

Покрытие: **100%**

## Безопасность

### Рекомендации

1. **Production**: Используйте `CORSPresets.private` или `CORSPresets.apiGateway`
2. **Development**: Используйте `CORSPresets.dev` для localhost
3. **Public API**: Используйте `CORSPresets.public` без credentials
4. **Blacklist**: Всегда добавляйте известные malicious домены
5. **Credentials**: Никогда не используйте с wildcard origin

### Запрещённые конфигурации

```typescript
// ❌ ОПАСНО: wildcard с credentials
createCORS({
  origin: '*',
  credentials: true
});

// ✅ БЕЗОПАСНО: конкретный origin с credentials
createCORS({
  origin: 'https://example.com',
  credentials: true
});
```

## API Reference

### createCORS(config?)

Создаёт CORS middleware.

**Параметры:**
- `config` (CORSConfig) - конфигурация

**Возвращает:** Express middleware функция

### CORSPresets

Готовые пресеты:
- `public` - публичный API
- `private(domains)` - приватный API
- `dev` - разработка
- `apiGateway(domains)` - API шлюз
- `microservice` - микросервис

### validateCORSConfig(config)

Валидирует конфигурацию.

**Параметры:**
- `config` (CORSConfig) - конфигурация

**Возвращает:** Массив ошибок `Error[]`

## Интерфейс CORSConfig

```typescript
interface CORSConfig {
  origin?: string | RegExp | ((origin: string, callback: Function) => void) | Array<string | RegExp>;
  methods?: string | string[];
  allowedHeaders?: string | string[];
  exposedHeaders?: string | string[];
  credentials?: boolean;
  maxAge?: number;
  preflightContinue?: boolean;
  optionsSuccessStatus?: number;
  strict?: boolean;
  blacklistedOrigins?: string[];
  dynamicOrigin?: boolean;
}
```

## Лицензия

MIT - Theodor Munch
