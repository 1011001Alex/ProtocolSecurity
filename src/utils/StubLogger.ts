/**
 * Stub Logger для новых модулей
 * Используется чтобы избежать проблем с парсингом основного Logger
 * 
 * Совместим с SecureLogger интерфейсом
 */

class StubLogger {
  info(message: string, source?: any, component?: string, context?: any, fields?: any): any {
    console.log(`[INFO] ${message}`, fields || '');
    return { success: true };
  }

  warning(message: string, source?: any, component?: string, context?: any, fields?: any): any {
    console.warn(`[WARNING] ${message}`, fields || '');
    return { success: true };
  }

  warn(message: string, data?: any): void {
    console.warn(`[WARN] ${message}`, data || '');
  }

  error(message: string, source?: any, component?: string, context?: any, fields?: any, errorObj?: Error): any {
    console.error(`[ERROR] ${message}`, errorObj || '', fields || '');
    return { success: true };
  }

  debug(message: string, source?: any, component?: string, context?: any, fields?: any): any {
    console.debug(`[DEBUG] ${message}`, fields || '');
    return { success: true };
  }

  critical(message: string, source?: any, component?: string, context?: any, fields?: any): any {
    console.error(`[CRITICAL] ${message}`, fields || '');
    return { success: true };
  }

  valid(message: string, source?: any, component?: string, context?: any, fields?: any): any {
    console.log(`[VALID] ${message}`, fields || '');
    return { success: true };
  }

  verbose(message: string, source?: any, component?: string, context?: any, fields?: any): any {
    console.log(`[VERBOSE] ${message}`, fields || '');
    return { success: true };
  }

  fatal(message: string, source?: any, component?: string, context?: any, fields?: any): any {
    console.error(`[FATAL] ${message}`, fields || '');
    return { success: true };
  }

  log(message: string, source?: any, component?: string, context?: any, fields?: any): any {
    console.log(`[LOG] ${message}`, fields || '');
    return { success: true };
  }

  child(context: any): StubLogger {
    return this;
  }
}

export const logger = new StubLogger();
