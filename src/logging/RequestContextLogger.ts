/**
 * ============================================================================
 * КОНТЕКСТНЫЙ ЛОГГЕР ДЛЯ ЗАПРОСОВ
 * ============================================================================
 * Обеспечивает сквозную трассировку запросов с автоматическим добавлением
 * request ID, user ID, session ID и другого контекста безопасности.
 *
 * Использование:
 * - В middleware: RequestContextLogger.setContext(req)
 * - В сервисах: RequestContextLogger.info('message', { extra fields })
 * - Автоматическое наследование контекста в async/await
 */

import { AsyncLocalStorage } from 'async_hooks';
import * as crypto from 'crypto';
import { IncomingMessage } from 'http';

// ============================================================================
// ТИПЫ И ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Контекст запроса для логирования
 */
export interface RequestContext {
  /** Уникальный идентификатор запроса */
  requestId: string;
  
  /** Идентификатор пользователя (если аутентифицирован) */
  userId?: string;
  
  /** Идентификатор сессии */
  sessionId?: string;
  
  /** Идентификатор устройства */
  deviceId?: string;
  
  /** IP адрес клиента */
  clientIp?: string;
  
  /** User Agent */
  userAgent?: string;
  
  /** HTTP метод */
  method?: string;
  
  /** URL путь */
  path?: string;
  
  /** Время начала запроса */
  startTime: number;
  
  /** Дополнительные метаданные */
  metadata?: Record<string, unknown>;
}

/**
 * Стек контекстов для вложенных вызовов
 */
interface ContextStack {
  contexts: RequestContext[];
}

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/**
 * Заголовки для извлечения контекста
 */
const CONTEXT_HEADERS = {
  REQUEST_ID: ['x-request-id', 'x-correlation-id', 'x-trace-id'],
  USER_ID: ['x-user-id', 'x-auth-user-id'],
  SESSION_ID: ['x-session-id', 'x-sess-id'],
  DEVICE_ID: ['x-device-id', 'x-device-fingerprint']
} as const;

/**
 * Символ для хранения контекста в локальном хранилище запроса
 */
const CONTEXT_SYMBOL = Symbol('request-context');

// ============================================================================
// ASYNC LOCAL STORAGE
// ============================================================================

/**
 * AsyncLocalStorage для хранения контекста запроса
 * Позволяет передавать контекст через цепочку async/await вызовов
 */
const asyncLocalStorage = new AsyncLocalStorage<ContextStack>();

/**
 * Получение текущего стека контекстов
 */
function getContextStack(): ContextStack | undefined {
  return asyncLocalStorage.getStore();
}

/**
 * Получение активного контекста (верхний уровень стека)
 */
function getActiveContext(): RequestContext | undefined {
  const store = getContextStack();
  return store?.contexts[store.contexts.length - 1];
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

/**
 * Генерация уникального идентификатора запроса
 */
function generateRequestId(): string {
  return crypto.randomUUID();
}

/**
 * Извлечение значения из заголовков по списку возможных имен
 */
function extractHeader(headers: Record<string, string | string[] | undefined>, names: readonly string[]): string | undefined {
  for (const name of names) {
    const value = headers[name.toLowerCase()];
    if (value) {
      return Array.isArray(value) ? value[0] : value;
    }
  }
  return undefined;
}

/**
 * Извлечение IP адреса из запроса с учетом прокси
 */
function extractClientIp(headers: Record<string, string | string[] | undefined>): string | undefined {
  // X-Forwarded-For может содержать несколько IP: "client, proxy1, proxy2"
  const forwarded = headers['x-forwarded-for'];
  if (forwarded) {
    const value = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    return value.split(',')[0].trim();
  }
  
  // X-Real-IP
  const realIp = headers['x-real-ip'];
  if (realIp) {
    return Array.isArray(realIp) ? realIp[0] : realIp;
  }
  
  return undefined;
}

// ============================================================================
// ОСНОВНОЙ КЛАСС
// ============================================================================

/**
 * Менеджер контекста запросов для сквозной трассировки
 */
export class RequestContextManager {
  /**
   * Инициализация контекста для нового запроса
   * Должно вызываться в начале обработки каждого HTTP запроса
   */
  initializeContext(request: IncomingMessage, existingContext?: Partial<RequestContext>): RequestContext {
    const headers = request.headers as Record<string, string | string[] | undefined>;
    
    const context: RequestContext = {
      requestId: existingContext?.requestId || extractHeader(headers, CONTEXT_HEADERS.REQUEST_ID) || generateRequestId(),
      userId: existingContext?.userId || extractHeader(headers, CONTEXT_HEADERS.USER_ID),
      sessionId: existingContext?.sessionId || extractHeader(headers, CONTEXT_HEADERS.SESSION_ID),
      deviceId: existingContext?.deviceId || extractHeader(headers, CONTEXT_HEADERS.DEVICE_ID),
      clientIp: existingContext?.clientIp || extractClientIp(headers),
      userAgent: existingContext?.userAgent || (headers['user-agent'] as string),
      method: request.method,
      path: request.url,
      startTime: Date.now(),
      metadata: existingContext?.metadata
    };
    
    return context;
  }

  /**
   * Выполнение кода в контексте запроса
   * Все логи внутри callback будут иметь указанный контекст
   */
  runWithContext<T>(context: RequestContext, callback: () => T): T {
    const store = getContextStack();
    
    if (store) {
      // Вложенный контекст - добавляем в стек
      store.contexts.push(context);
      try {
        return callback();
      } finally {
        store.contexts.pop();
      }
    } else {
      // Новый контекст - создаем хранилище
      return asyncLocalStorage.run({ contexts: [context] }, callback);
    }
  }

  /**
   * Обновление текущего контекста
   */
  updateContext(updates: Partial<RequestContext>): void {
    const store = getContextStack();
    if (store && store.contexts.length > 0) {
      const currentContext = store.contexts[store.contexts.length - 1];
      Object.assign(currentContext, updates);
    }
  }

  /**
   * Добавление пользователя в контекст (после аутентификации)
   */
  setUserId(userId: string): void {
    this.updateContext({ userId });
  }

  /**
   * Добавление сессии в контекст
   */
  setSessionId(sessionId: string): void {
    this.updateContext({ sessionId });
  }

  /**
   * Добавление устройства в контекст
   */
  setDeviceId(deviceId: string): void {
    this.updateContext({ deviceId });
  }

  /**
   * Получение текущего request ID
   */
  getRequestId(): string | undefined {
    return getActiveContext()?.requestId;
  }

  /**
   * Получение текущего user ID
   */
  getUserId(): string | undefined {
    return getActiveContext()?.userId;
  }

  /**
   * Получение текущего session ID
   */
  getSessionId(): string | undefined {
    return getActiveContext()?.sessionId;
  }

  /**
   * Получение текущего контекста
   */
  getContext(): RequestContext | undefined {
    return getActiveContext();
  }

  /**
   * Получение длительности текущего запроса в мс
   */
  getRequestDuration(): number | undefined {
    const context = getActiveContext();
    return context ? Date.now() - context.startTime : undefined;
  }

  /**
   * Сброс контекста (вызывается в конце запроса)
   */
  clearContext(): void {
    const store = getContextStack();
    if (store && store.contexts.length > 0) {
      store.contexts.pop();
    }
  }
}

// ============================================================================
// ЭКСПОРТ ЕДИНСТВЕННОГО ЭКЗЕМПЛЯРА
// ============================================================================

export const RequestContextManagerInstance = new RequestContextManager();

// ============================================================================
// EXPRESS MIDDLEWARE
// ============================================================================

/**
 * Express middleware для автоматической инициализации контекста запроса
 * Должен быть добавлен первым middleware в приложении
 */
export function requestContextMiddleware() {
  const manager = RequestContextManagerInstance;
  
  return (req: IncomingMessage & { requestContext?: RequestContext }, res: unknown, next: () => void) => {
    const context = manager.initializeContext(req);
    req.requestContext = context;
    
    manager.runWithContext(context, () => {
      // Добавляем request ID в ответ для трассировки
      if (res && typeof res === 'object' && 'setHeader' in res) {
        const response = res as { setHeader: (name: string, value: string) => unknown };
        response.setHeader('X-Request-ID', context.requestId);
      }
      
      next();
    });
  };
}

// ============================================================================
// УТИЛИТЫ ДЛЯ БЫСТРОГО ДОСТУПА
// ============================================================================

/**
 * Быстрое получение текущего контекста
 */
export function getCurrentRequestContext(): RequestContext | undefined {
  return RequestContextManagerInstance.getContext();
}

/**
 * Быстрое получение request ID
 */
export function getCurrentRequestId(): string | undefined {
  return RequestContextManagerInstance.getRequestId();
}

/**
 * Быстрое получение user ID
 */
export function getCurrentUserId(): string | undefined {
  return RequestContextManagerInstance.getUserId();
}

/**
 * Быстрое получение session ID
 */
export function getCurrentSessionId(): string | undefined {
  return RequestContextManagerInstance.getSessionId();
}

/**
 * Обновление контекста
 */
export function updateRequestContext(updates: Partial<RequestContext>): void {
  RequestContextManagerInstance.updateContext(updates);
}

/**
 * Установка user ID в контекст
 */
export function setRequestUserId(userId: string): void {
  RequestContextManagerInstance.setUserId(userId);
}

/**
 * Установка session ID в контекст
 */
export function setRequestSessionId(sessionId: string): void {
  RequestContextManagerInstance.setSessionId(sessionId);
}

/**
 * Выполнение кода в контексте
 */
export function runInRequestContext<T>(context: RequestContext, callback: () => T): T {
  return RequestContextManagerInstance.runWithContext(context, callback);
}
