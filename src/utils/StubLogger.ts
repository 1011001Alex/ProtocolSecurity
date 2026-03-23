/**
 * Stub Logger для новых модулей
 * Используется чтобы избежать проблем с парсингом основного Logger
 */

class StubLogger {
  info(message: string, data?: any): void {
    // Stub
  }

  warn(message: string, data?: any): void {
    // Stub
  }

  error(message: string, error?: any, data?: any): void {
    // Stub
  }

  debug(message: string, data?: any): void {
    // Stub
  }

  critical(message: string, data?: any): void {
    // Stub
  }
}

export const logger = new StubLogger();
