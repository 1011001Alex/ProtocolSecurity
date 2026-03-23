# Input Validation Middleware - Документация

## 📋 Обзор

**Input Validation Middleware** - комплексная система валидации и санитизации входящих HTTP запросов для Express приложений. Обеспечивает защиту от injection атак, валидацию данных по схеме и автоматическую санитизацию.

## 🔐 Основные возможности

### 1. Валидация данных
- **Body валидация** - проверка JSON/body данных запроса
- **Query валидация** - проверка URL query параметров
- **Params валидация** - проверка route параметров
- **Headers валидация** - проверка HTTP заголовков

### 2. Типы валидации
```typescript
enum ValidationType {
  STRING = 'STRING',           // Строки
  NUMBER = 'NUMBER',           // Числа
  BOOLEAN = 'BOOLEAN',         // Булевы значения
  EMAIL = 'EMAIL',             // Email адреса
  URL = 'URL',                 // URL с проверкой протокола
  IP = 'IP',                   // IPv4/IPv6 адреса
  UUID = 'UUID',               // UUID v1-v5
  DATE = 'DATE',               // Даты в ISO формате
  PATH = 'PATH',               // Файловые пути
  FILENAME = 'FILENAME',       // Имена файлов
  JSON = 'JSON',               // JSON объекты
  JWT = 'JWT',                 // JWT токены
  API_KEY = 'API_KEY',         // API ключи
  PASSWORD = 'PASSWORD'        // Пароли
}
```

### 3. Защита от атак
- **SQL Injection** - детектирование SQL паттернов
- **XSS Attacks** - защита от межсайтового скриптинга
- **Command Injection** - блокировка системных команд
- **Path Traversal** - защита от обхода путей
- **LDAP Injection** - валидация LDAP запросов
- **NoSQL Injection** - защита от NoSQL инъекций

### 4. Дополнительные функции
- **Rate Limiting** - ограничение запросов на валидацию
- **Schema Validation** - валидация по JSON Schema
- **Auto-sanitization** - автоматическая санитизация HTML
- **Error Logging** - детальное логирование ошибок
- **Strict Mode** - строгий режим блокировки

---

## 📦 Установка и настройка

### 1. Базовая настройка

Middleware автоматически интегрируется в `app.ts`:

```typescript
import { createInputValidationMiddleware } from './middleware/InputValidationMiddleware';

// Глобальная валидация для всех запросов
app.use(createInputValidationMiddleware({
  strictMode: true,
  maxBodySize: 10 * 1024 * 1024, // 10MB
  sanitizeHTML: true,
  logErrors: true,
  skipMethods: ['GET', 'HEAD', 'OPTIONS']
}));
```

### 2. Переменные окружения

Добавьте в `.env`:

```bash
# Включить валидацию
ENABLE_INPUT_VALIDATION=true

# Строгий режим (блокировать при ошибках)
INPUT_VALIDATION_STRICT_MODE=true

# Максимальный размер body (байты)
INPUT_VALIDATION_MAX_BODY_SIZE=10485760

# Санитизация HTML
INPUT_VALIDATION_SANITIZE_HTML=true

# Логирование ошибок
INPUT_VALIDATION_LOG_ERRORS=true
INPUT_VALIDATION_LOG_LEVEL=WARNING
```

---

## 📖 Использование

### Пример 1: Валидация регистрации пользователя

```typescript
import { 
  createInputValidationMiddleware, 
  ValidationPresets 
} from './middleware/InputValidationMiddleware';

app.post('/api/users/register',
  createInputValidationMiddleware({
    strictMode: true,
    schema: ValidationPresets.userRegistration
  }),
  (req, res) => {
    // Валидированные данные
    const { email, password, username } = req.body;
    
    // Обработка...
    res.json({ success: true });
  }
);
```

### Пример 2: Кастомная схема валидации

```typescript
import { 
  createInputValidationMiddleware, 
  ValidationType,
  ValidationSchema
} from './middleware/InputValidationMiddleware';

const userSchema: ValidationSchema = {
  body: {
    email: { 
      type: ValidationType.EMAIL, 
      required: true,
      maxLength: 254 
    },
    password: { 
      type: ValidationType.PASSWORD,
      required: true,
      minLength: 12,
      maxLength: 128,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecial: true
    },
    age: { 
      type: ValidationType.NUMBER,
      required: false,
      min: 18,
      max: 100
    },
    website: {
      type: ValidationType.URL,
      required: false,
      allowedProtocols: ['https']
    }
  }
};

app.post('/api/users',
  createInputValidationMiddleware({
    strictMode: true,
    schema: userSchema
  }),
  (req, res) => {
    // Данные уже валидированы
    res.json({ user: req.body });
  }
);
```

### Пример 3: Валидация query параметров

```typescript
import { ValidationPresets } from './middleware/InputValidationMiddleware';

app.get('/api/search',
  createInputValidationMiddleware({
    schema: ValidationPresets.search
  }),
  (req, res) => {
    // Валидированные query параметры
    const { q, page, limit, sort, order } = req.query;
    
    res.json({ results: [] });
  }
);
```

### Пример 4: Валидация route параметров

```typescript
import { ValidationPresets } from './middleware/InputValidationMiddleware';

app.get('/api/resources/:id',
  createInputValidationMiddleware({
    schema: ValidationPresets.uuidParams
  }),
  (req, res) => {
    // Валидированный UUID параметр
    const { id } = req.params;
    
    res.json({ resource: { id } });
  }
);
```

### Пример 5: Валидация API ключа в headers

```typescript
import { ValidationPresets } from './middleware/InputValidationMiddleware';

app.get('/api/secure-data',
  createInputValidationMiddleware({
    schema: ValidationPresets.apiKeyAuth
  }),
  (req, res) => {
    // API ключ валидирован
    const apiKey = req.headers['x-api-key'];
    
    res.json({ data: 'secure' });
  }
);
```

---

## 🔧 Конфигурация

### Полный список опций

```typescript
interface InputValidationConfig {
  /** Строгий режим - блокировать при ошибках */
  strictMode?: boolean;

  /** Максимальный размер body в байтах */
  maxBodySize?: number;

  /** Санитизировать HTML */
  sanitizeHTML?: boolean;

  /** Логировать ошибки */
  logErrors?: boolean;

  /** Уровень логирования */
  logLevel?: LogLevel;

  /** Схема валидации */
  schema?: ValidationSchema;

  /** Пропускать пути (regex) */
  skipPaths?: RegExp[];

  /** Пропускать методы */
  skipMethods?: string[];

  /** Кастомный обработчик ошибок */
  errorHandler?: (errors, req) => { statusCode, body };

  /** Включить rate limiting */
  enableRateLimit?: boolean;

  /** Максимум запросов в минуту */
  rateLimitMax?: number;

  /** Окно rate limiting (мс) */
  rateLimitWindowMs?: number;
}
```

### FieldSchema - схема поля

```typescript
interface FieldSchema {
  /** Тип валидации */
  type: ValidationType;

  /** Обязательно ли поле */
  required?: boolean;

  /** Минимальная длина */
  minLength?: number;

  /** Максимальная длина */
  maxLength?: number;

  /** Минимальное значение (для чисел) */
  min?: number;

  /** Максимальное значение (для чисел) */
  max?: number;

  /** Паттерн (RegExp) */
  pattern?: string | RegExp;

  /** Санитизировать значение */
  sanitize?: boolean;

  /** Сообщение об ошибке */
  message?: string;

  /** Значение по умолчанию */
  default?: unknown;

  /** Перечисление допустимых значений */
  enum?: unknown[];

  /** Вложенная схема */
  properties?: Record<string, FieldSchema>;

  // Для URL
  allowedProtocols?: string[];
  allowedHosts?: string[];

  // Для IP
  ipVersion?: 4 | 6;

  // Для UUID
  uuidVersion?: 1 | 2 | 3 | 4 | 5;

  // Для пути
  allowAbsolutePath?: boolean;
  baseDir?: string;

  // Для пароля
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecial?: boolean;
}
```

---

## 📚 Validation Presets

Готовые пресеты для типичных сценариев:

### 1. userRegistration
```typescript
ValidationPresets.userRegistration = {
  body: {
    email: { type: EMAIL, required: true, maxLength: 254 },
    password: { 
      type: PASSWORD, 
      required: true, 
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecial: true 
    },
    username: { 
      type: STRING, 
      required: true, 
      minLength: 3, 
      maxLength: 50,
      pattern: /^[a-zA-Z0-9_]+$/ 
    }
  }
}
```

### 2. authentication
```typescript
ValidationPresets.authentication = {
  body: {
    email: { type: EMAIL, required: true },
    password: { type: STRING, required: true, minLength: 8 }
  }
}
```

### 3. search
```typescript
ValidationPresets.search = {
  query: {
    q: { type: STRING, maxLength: 500, sanitize: true },
    page: { type: NUMBER, min: 1, max: 10000, default: 1 },
    limit: { type: NUMBER, min: 1, max: 100, default: 20 },
    sort: { type: STRING, maxLength: 50 },
    order: { type: STRING, enum: ['asc', 'desc'], default: 'asc' }
  }
}
```

### 4. uuidParams
```typescript
ValidationPresets.uuidParams = {
  params: {
    id: { type: UUID, required: true, uuidVersion: 4 }
  }
}
```

### 5. pagination
```typescript
ValidationPresets.pagination = {
  query: {
    page: { type: NUMBER, min: 1, max: 10000, default: 1 },
    limit: { type: NUMBER, min: 1, max: 100, default: 20 },
    offset: { type: NUMBER, min: 0, default: 0 }
  }
}
```

### 6. apiKeyAuth
```typescript
ValidationPresets.apiKeyAuth = {
  headers: {
    'x-api-key': { 
      type: API_KEY, 
      required: true, 
      minLength: 32, 
      maxLength: 256 
    }
  }
}
```

### 7. fileUpload
```typescript
ValidationPresets.fileUpload = {
  body: {
    filename: { type: FILENAME, required: true, maxLength: 255 },
    description: { type: STRING, maxLength: 1000, sanitize: true },
    tags: { type: JSON, required: false }
  }
}
```

### 8. webhook
```typescript
ValidationPresets.webhook = {
  body: {
    event: { type: STRING, required: true, maxLength: 100 },
    data: { type: JSON, required: true },
    timestamp: { type: DATE, required: true },
    signature: { type: STRING, required: true, pattern: /^[a-fA-F0-9]{64}$/ }
  }
}
```

---

## 🔍 Helper функции

### getValidatedData
Получить валидированные данные из request:

```typescript
import { getValidatedData } from './middleware/InputValidationMiddleware';

app.post('/api/data',
  createInputValidationMiddleware({ schema: {...} }),
  (req, res) => {
    const validatedBody = getValidatedData(req, 'body');
    const validatedQuery = getValidatedData(req, 'query');
    const validatedParams = getValidatedData(req, 'params');
  }
);
```

### getSanitizedData
Получить санитизированные данные:

```typescript
import { getSanitizedData } from './middleware/InputValidationMiddleware';

app.post('/api/comment',
  createInputValidationMiddleware({ schema: {...} }),
  (req, res) => {
    const sanitizedBody = getSanitizedData(req, 'body');
    // HTML символы заменены на entities
  }
);
```

### isValidated
Проверить успешность валидации:

```typescript
import { isValidated, getValidationErrors } from './middleware/InputValidationMiddleware';

app.post('/api/data',
  createInputValidationMiddleware({ strictMode: false }),
  (req, res) => {
    if (!isValidated(req)) {
      const errors = getValidationErrors(req);
      console.log('Validation errors:', errors);
    }
  }
);
```

### getValidationErrors
Получить массив ошибок валидации:

```typescript
const errors = getValidationErrors(req);
// [ValidationError, ValidationError, ...]
```

### createValidationSchema
Создать схему валидации:

```typescript
import { createValidationSchema, ValidationType } from './middleware/InputValidationMiddleware';

const schema = createValidationSchema(
  {
    email: { type: ValidationType.EMAIL, required: true },
    name: { type: ValidationType.STRING, required: true }
  },
  { validateBody: true, validateQuery: false }
);
```

---

## 🛡️ Защита от атак

### SQL Injection
```typescript
// Блокирует запросы с SQL паттернами
const maliciousInput = "'; DROP TABLE users; --";
// Ошибка: INJECTION_DETECTED (sqlInjection)
```

### XSS Attacks
```typescript
// Блокирует XSS атаки
const xssAttack = '<script>alert("XSS")</script>';
// Ошибка: INJECTION_DETECTED (xss)
```

### Command Injection
```typescript
// Блокирует injection команд
const cmdInjection = 'test.txt; rm -rf /';
// Ошибка: INJECTION_DETECTED (commandInjection)
```

### Path Traversal
```typescript
// Блокирует обход путей
const pathTraversal = '../../../etc/passwd';
// Ошибка: INJECTION_DETECTED (pathTraversal)
```

---

## 📊 Обработка ошибок

### Ответ по умолчанию (400 Bad Request)
```json
{
  "error": "Validation Error",
  "message": "Input validation failed",
  "details": [
    {
      "field": "email",
      "code": "INVALID_FORMAT",
      "message": "Неверный формат email"
    }
  ],
  "timestamp": "2026-03-23T12:00:00.000Z"
}
```

### Кастомный обработчик ошибок
```typescript
const customErrorHandler = (errors, req) => ({
  statusCode: 422,
  body: {
    error: 'Unprocessable Entity',
    validation_errors: errors.map(e => ({
      field: e.field,
      message: e.message
    }))
  }
});

app.use(createInputValidationMiddleware({
  strictMode: true,
  errorHandler: customErrorHandler
}));
```

---

## 🧪 Тестирование

### Запуск тестов
```bash
npm test -- --testPathPattern=InputValidationMiddleware
```

### Покрытие тестов
- ✅ Базовая функциональность middleware
- ✅ Валидация body/query/params/headers
- ✅ Все типы валидации (STRING, EMAIL, NUMBER, etc.)
- ✅ Injection protection (SQL, XSS, Command, Path)
- ✅ Rate limiting
- ✅ Validation presets
- ✅ Helper функции
- ✅ Edge cases
- ✅ Custom error handler

---

## 📝 Примеры использования

### Пример 1: Полный CRUD с валидацией

```typescript
import { 
  createInputValidationMiddleware, 
  ValidationPresets,
  ValidationType,
  ValidationSchema
} from './middleware/InputValidationMiddleware';

// Схема для создания пользователя
const createUserSchema: ValidationSchema = {
  body: {
    email: { type: ValidationType.EMAIL, required: true },
    password: { type: ValidationType.PASSWORD, required: true },
    username: { 
      type: ValidationType.STRING, 
      required: true, 
      minLength: 3, 
      maxLength: 50 
    }
  }
};

// Схема для обновления
const updateUserSchema: ValidationSchema = {
  params: ValidationPresets.uuidParams.params,
  body: {
    email: { type: ValidationType.EMAIL, required: false },
    username: { type: ValidationType.STRING, maxLength: 50, required: false }
  }
};

// CREATE
app.post('/api/users',
  createInputValidationMiddleware({ 
    strictMode: true, 
    schema: createUserSchema 
  }),
  async (req, res) => {
    const { email, password, username } = req.body;
    // Создание пользователя...
  }
);

// READ
app.get('/api/users/:id',
  createInputValidationMiddleware({ 
    schema: ValidationPresets.uuidParams 
  }),
  async (req, res) => {
    const { id } = req.params;
    // Получение пользователя...
  }
);

// UPDATE
app.put('/api/users/:id',
  createInputValidationMiddleware({ 
    strictMode: true, 
    schema: updateUserSchema 
  }),
  async (req, res) => {
    const { id } = req.params;
    const { email, username } = req.body;
    // Обновление пользователя...
  }
);

// DELETE
app.delete('/api/users/:id',
  createInputValidationMiddleware({ 
    schema: ValidationPresets.uuidParams 
  }),
  async (req, res) => {
    const { id } = req.params;
    // Удаление пользователя...
  }
);
```

### Пример 2: API с пагинацией и поиском

```typescript
app.get('/api/products',
  createInputValidationMiddleware({
    schema: {
      query: {
        search: { 
          type: ValidationType.STRING, 
          required: false, 
          maxLength: 500,
          sanitize: true 
        },
        page: { 
          type: ValidationType.NUMBER, 
          min: 1, 
          default: 1 
        },
        limit: { 
          type: ValidationType.NUMBER, 
          min: 1, 
          max: 100, 
          default: 20 
        },
        category: { 
          type: ValidationType.STRING, 
          required: false,
          pattern: /^[a-z0-9-]+$/
        },
        sort: {
          type: ValidationType.STRING,
          enum: ['name', 'price', 'created_at'],
          default: 'created_at'
        },
        order: {
          type: ValidationType.STRING,
          enum: ['asc', 'desc'],
          default: 'desc'
        }
      }
    }
  }),
  async (req, res) => {
    const { search, page, limit, category, sort, order } = req.query;
    // Поиск продуктов...
  }
);
```

### Пример 3: Webhook endpoint

```typescript
app.post('/api/webhooks/payment',
  createInputValidationMiddleware({
    strictMode: true,
    schema: ValidationPresets.webhook
  }),
  async (req, res) => {
    const { event, data, timestamp, signature } = req.body;
    
    // Верификация подписи...
    // Обработка события...
    
    res.json({ received: true });
  }
);
```

---

## 🔐 Безопасность

### Рекомендации

1. **Всегда включайте strictMode в production**
   ```typescript
   strictMode: process.env.NODE_ENV === 'production'
   ```

2. **Используйте санитизацию HTML**
   ```typescript
   sanitizeHTML: true
   ```

3. **Ограничивайте размер body**
   ```typescript
   maxBodySize: 1024 * 1024 // 1MB для API
   ```

4. **Логируйте ошибки валидации**
   ```typescript
   logErrors: true,
   logLevel: 'WARNING'
   ```

5. **Используйте валидацию для всех входящих данных**
   ```typescript
   // Не пропускайте валидацию для важных endpoints
   skipMethods: ['GET', 'HEAD', 'OPTIONS']
   ```

---

## 📈 Производительность

### Оптимизация

1. **Кэширование схем валидации**
   ```typescript
   const cachedSchema = createValidationSchema({...});
   app.use(createInputValidationMiddleware({ schema: cachedSchema }));
   ```

2. **Пропуск ненужных путей**
   ```typescript
   skipPaths: [/^\/health/, /^\/metrics/, /^\/api\/public/]
   ```

3. **Отключение rate limiting** (если используется отдельный middleware)
   ```typescript
   enableRateLimit: false
   ```

---

## 📚 Экспорт

```typescript
export {
  // Middleware
  createInputValidationMiddleware,
  
  // Helper функции
  getValidatedData,
  getSanitizedData,
  isValidated,
  getValidationErrors,
  createValidationSchema,
  
  // Типы
  ValidationType,
  ValidationPresets,
  
  // Интерфейсы
  InputValidationConfig,
  ValidationSchema,
  FieldSchema
}
```

---

## 📞 Поддержка

- **Документация**: `/docs/middleware/InputValidationMiddleware.md`
- **Тесты**: `tests/middleware/InputValidationMiddleware.test.ts`
- **Реализация**: `src/middleware/InputValidationMiddleware.ts`
- **Утилиты**: `src/utils/InputValidator.ts`

---

## 📄 Лицензия

MIT License - см. файл LICENSE
