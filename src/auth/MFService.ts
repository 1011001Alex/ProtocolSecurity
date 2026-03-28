/**
 * =============================================================================
 * MULTI-FACTOR AUTHENTICATION SERVICE (MFService)
 * =============================================================================
 * Сервис для управления многофакторной аутентификацией
 * Поддерживает: TOTP (RFC 6238), HOTP (RFC 4226), Backup Codes
 * Соответствует: NIST 800-63B, FIDO Alliance guidelines
 * =============================================================================
 */

import * as OTPAuth from 'otpauth';
import { randomBytes, createHash, timingSafeEqual } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../logging/Logger';
import {
  ITotpMethod,
  IHotpMethod,
  IBackupCode,
  IBackupCodeSet,
  MfaMethodStatus,
  AuthError,
  AuthErrorCode,
} from '../types/auth.types';

/**
 * Конфигурация TOTP
 */
export interface TotpConfig {
  /** Алгоритм хэширования */
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  /** Количество цифр в коде */
  digits: 6 | 8;
  /** Период действия кода (секунды) */
  period: number;
  /** Окно для проверки (количество периодов до/после) */
  window: number;
  /** Минимальная длина секрета (байты) */
  secretLength: number;
}

/**
 * Конфигурация HOTP
 */
export interface HotpConfig {
  /** Алгоритм хэширования */
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  /** Количество цифр в коде */
  digits: 6 | 8;
  /** Окно синхронизации счетчика */
  window: number;
  /** Минимальная длина секрета (байты) */
  secretLength: number;
}

/**
 * Конфигурация backup кодов
 */
export interface BackupCodeConfig {
  /** Количество кодов в наборе */
  codeCount: number;
  /** Длина каждого кода (символы) */
  codeLength: number;
  /** Срок действия набора (мс), 0 = бессрочно */
  expiresIn: number;
  /** Использовать ли префикс для кодов */
  usePrefix: boolean;
  /** Префикс для кодов */
  prefix?: string;
}

/**
 * Конфигурация MFService по умолчанию
 */
const DEFAULT_TOTP_CONFIG: TotpConfig = {
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  window: 1,
  secretLength: 20,
};

const DEFAULT_HOTP_CONFIG: HotpConfig = {
  algorithm: 'SHA1',
  digits: 6,
  window: 5,
  secretLength: 20,
};

const DEFAULT_BACKUP_CODE_CONFIG: BackupCodeConfig = {
  codeCount: 10,
  codeLength: 10,
  expiresIn: 0, // Бессрочно
  usePrefix: true,
  prefix: 'BCKP-',
};

/**
 * Результат генерации TOTP
 */
export interface TotpSetupResult {
  /** ID метода */
  methodId: string;
  /** Секрет (для отображения QR) */
  secret: string;
  /** OTPAuth URL для QR-кода */
  otpauthUrl: string;
  /** Метод TOTP (незавершенный) */
  totpMethod: Omit<ITotpMethod, 'userId' | 'createdAt' | 'lastUsedAt' | 'usageCount'>;
}

/**
 * Результат верификации TOTP
 */
export interface TotpVerifyResult {
  /** Успешна ли верификация */
  valid: boolean;
  /** Дельта времени (для синхронизации) */
  delta?: number;
}

/**
 * Результат генерации backup кодов
 */
export interface BackupCodeGenerationResult {
  /** Набор кодов */
  codeSet: IBackupCodeSet;
  /** Коды в plain text (показать только один раз!) */
  codes: string[];
  /** Захешированные коды для хранения */
  hashedCodes: Omit<IBackupCode, 'id' | 'createdAt'>[];
}

/**
 * =============================================================================
 * MFService CLASS
 * =============================================================================
 */
export class MFService {
  private totpConfig: TotpConfig;
  private hotpConfig: HotpConfig;
  private backupCodeConfig: BackupCodeConfig;

  /**
   * Создает новый экземпляр MFService
   * @param totpConfig - Конфигурация TOTP
   * @param hotpConfig - Конфигурация HOTP
   * @param backupCodeConfig - Конфигурация backup кодов
   */
  constructor(
    totpConfig: TotpConfig = DEFAULT_TOTP_CONFIG,
    hotpConfig: HotpConfig = DEFAULT_HOTP_CONFIG,
    backupCodeConfig: BackupCodeConfig = DEFAULT_BACKUP_CODE_CONFIG
  ) {
    this.totpConfig = totpConfig;
    this.hotpConfig = hotpConfig;
    this.backupCodeConfig = backupCodeConfig;
  }

  // ===========================================================================
  // TOTP (TIME-BASED ONE-TIME PASSWORD) - RFC 6238
  // ===========================================================================

  /**
   * Генерирует новый TOTP секрет для пользователя
   * @param userId - ID пользователя
   * @param label - Метка для отображения (обычно email)
   * @param issuer - Название сервиса (issuer)
   * @returns Результат настройки TOTP
   */
  public generateTotpSecret(
    userId: string,
    label: string,
    issuer: string = 'Protocol'
  ): TotpSetupResult {
    try {
      // Генерация криптографически безопасного секрета
      const secretBytes = randomBytes(this.totpConfig.secretLength);
      const secret = this.base32Encode(secretBytes);

      // Создание TOTP объекта
      const totp = new OTPAuth.TOTP({
        issuer,
        label,
        algorithm: this.totpConfig.algorithm,
        digits: this.totpConfig.digits,
        period: this.totpConfig.period,
        secret,
      });

      // Генерация otpauth:// URL для QR-кода
      const otpauthUrl = totp.toString();

      // Создание объекта метода
      const totpMethod: Omit<ITotpMethod, 'userId' | 'createdAt' | 'lastUsedAt' | 'usageCount'> = {
        id: uuidv4(),
        type: 'totp',
        status: 'pending',
        secret: '', // Будет зашифрован при сохранении
        algorithm: this.totpConfig.algorithm,
        digits: this.totpConfig.digits,
        period: this.totpConfig.period,
        timeSkew: 0,
        otpauthUrl,
        isDefault: false,
      };

      return {
        methodId: totpMethod.id,
        secret, // Показываем пользователю один раз
        otpauthUrl,
        totpMethod,
      };
    } catch (error) {
      throw new AuthError(
        `Ошибка генерации TOTP секрета: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Верифицирует TOTP код
   * @param code - Код от пользователя
   * @param secret - Секрет пользователя
   * @param timeSkew - Смещение времени (если есть)
   * @returns Результат верификации
   */
  public verifyTotpCode(
    code: string,
    secret: string,
    timeSkew: number = 0
  ): TotpVerifyResult {
    try {
      // Нормализация кода (удаление пробелов)
      const normalizedCode = code.replace(/\s/g, '');

      // Валидация формата кода
      if (!/^\d+$/.test(normalizedCode)) {
        return { valid: false };
      }

      // Создание TOTP объекта
      const totp = new OTPAuth.TOTP({
        algorithm: this.totpConfig.algorithm,
        digits: this.totpConfig.digits,
        period: this.totpConfig.period,
        secret,
      });

      // Верификация с окном для учета рассинхронизации времени
      const delta = totp.validate({
        token: normalizedCode,
        window: this.totpConfig.window,
      });

      // delta === null означает неудачу
      // delta === 0 означает точное совпадение
      // delta !== 0 означает смещение на delta периодов
      if (delta === null) {
        return { valid: false };
      }

      // Обновление timeSkew если есть смещение
      const newTimeSkew = delta * this.totpConfig.period;

      return {
        valid: true,
        delta: newTimeSkew,
      };
    } catch (error) {
      logger.error('[MFService] Ошибка верификации TOTP', { error });
      return { valid: false };
    }
  }

  /**
   * Генерирует текущий TOTP код (для тестирования)
   * @param secret - Секрет
   * @param timestamp - Временная метка (опционально)
   * @returns Сгенерированный код
   */
  public generateTotpCode(secret: string, timestamp?: number): string {
    const totp = new OTPAuth.TOTP({
      algorithm: this.totpConfig.algorithm,
      digits: this.totpConfig.digits,
      period: this.totpConfig.period,
      secret,
    });

    return totp.generate({ timestamp: timestamp ? Math.floor(timestamp / 1000) : undefined });
  }

  // ===========================================================================
  // HOTP (HMAC-BASED ONE-TIME PASSWORD) - RFC 4226
  // ===========================================================================

  /**
   * Генерирует новый HOTP секрет для пользователя
   * @param userId - ID пользователя
   * @param label - Метка для отображения
   * @param issuer - Название сервиса
   * @param initialCounter - Начальное значение счетчика
   * @returns Результат настройки HOTP
   */
  public generateHotpSecret(
    userId: string,
    label: string,
    issuer: string = 'Protocol',
    initialCounter: number = 0
  ): {
    methodId: string;
    secret: string;
    otpauthUrl: string;
    hotpMethod: Omit<IHotpMethod, 'userId' | 'createdAt' | 'lastUsedAt' | 'usageCount'>;
  } {
    try {
      // Генерация криптографически безопасного секрета
      const secretBytes = randomBytes(this.hotpConfig.secretLength);
      const secret = this.base32Encode(secretBytes);

      // Создание HOTP объекта
      const hotp = new OTPAuth.HOTP({
        issuer,
        label,
        algorithm: this.hotpConfig.algorithm,
        digits: this.hotpConfig.digits,
        counter: initialCounter,
        secret,
      });

      // Генерация otpauth:// URL
      const otpauthUrl = hotp.toString();

      // Создание объекта метода
      const hotpMethod: Omit<IHotpMethod, 'userId' | 'createdAt' | 'lastUsedAt' | 'usageCount'> = {
        id: uuidv4(),
        type: 'hotp',
        status: 'pending',
        secret: '',
        algorithm: this.hotpConfig.algorithm,
        digits: this.hotpConfig.digits,
        counter: initialCounter,
        window: this.hotpConfig.window,
        isDefault: false,
      };

      return {
        methodId: hotpMethod.id,
        secret,
        otpauthUrl,
        hotpMethod,
      };
    } catch (error) {
      throw new AuthError(
        `Ошибка генерации HOTP секрета: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Верифицирует HOTP код
   * @param code - Код от пользователя
   * @param secret - Секрет пользователя
   * @param counter - Текущий счетчик
   * @returns Результат верификации с новым счетчиком
   */
  public verifyHotpCode(
    code: string,
    secret: string,
    counter: number
  ): {
    valid: boolean;
    newCounter?: number;
  } {
    try {
      // Нормализация кода
      const normalizedCode = code.replace(/\s/g, '');

      // Валидация формата
      if (!/^\d+$/.test(normalizedCode)) {
        return { valid: false };
      }

      // Создание HOTP объекта
      const hotp = new OTPAuth.HOTP({
        algorithm: this.hotpConfig.algorithm,
        digits: this.hotpConfig.digits,
        counter,
        secret,
      });

      // Верификация с окном для синхронизации
      const newCounter = hotp.validate({
        token: normalizedCode,
        window: this.hotpConfig.window,
      });

      if (newCounter === null) {
        return { valid: false };
      }

      return {
        valid: true,
        newCounter: newCounter + 1,
      };
    } catch (error) {
      logger.error('[MFService] Ошибка верификации HOTP', { error });
      return { valid: false };
    }
  }

  /**
   * Генерирует HOTP код для заданного счетчика
   * @param secret - Секрет
   * @param counter - Значение счетчика
   * @returns Сгенерированный код
   */
  public generateHotpCode(secret: string, counter: number): string {
    const hotp = new OTPAuth.HOTP({
      algorithm: this.hotpConfig.algorithm,
      digits: this.hotpConfig.digits,
      counter,
      secret,
    });

    return hotp.generate();
  }

  // ===========================================================================
  // BACKUP CODES
  // ===========================================================================

  /**
   * Генерирует новый набор backup кодов
   * @param userId - ID пользователя
   * @returns Результат генерации с кодами
   */
  public generateBackupCodes(userId: string): BackupCodeGenerationResult {
    try {
      const codeSetId = uuidv4();
      const now = new Date();
      const codes: string[] = [];
      const hashedCodes: Omit<IBackupCode, 'id' | 'createdAt'>[] = [];

      for (let i = 0; i < this.backupCodeConfig.codeCount; i++) {
        // Генерация случайного кода
        const code = this.generateBackupCode();
        codes.push(code);

        // Хэширование кода (не храним в plain text)
        const codeHash = this.hashBackupCode(code);

        hashedCodes.push({
          userId,
          codeHash,
          used: false,
          usedAt: undefined,
          usedSessionId: undefined,
          expiresAt: this.backupCodeConfig.expiresIn > 0
            ? new Date(now.getTime() + this.backupCodeConfig.expiresIn)
            : undefined,
        });
      }

      const codeSet: IBackupCodeSet = {
        id: codeSetId,
        userId,
        codeCount: this.backupCodeConfig.codeCount,
        usedCount: 0,
        createdAt: now,
        expiresAt: this.backupCodeConfig.expiresIn > 0
          ? new Date(now.getTime() + this.backupCodeConfig.expiresIn)
          : undefined,
        isActive: true,
      };

      return {
        codeSet,
        codes,
        hashedCodes,
      };
    } catch (error) {
      throw new AuthError(
        `Ошибка генерации backup кодов: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Генерирует один backup код
   * @private
   */
  private generateBackupCode(): string {
    const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Без похожих символов
    let code = '';

    if (this.backupCodeConfig.usePrefix && this.backupCodeConfig.prefix) {
      code = this.backupCodeConfig.prefix;
    }

    const codeLength = this.backupCodeConfig.usePrefix
      ? this.backupCodeConfig.codeLength - (this.backupCodeConfig.prefix?.length || 0)
      : this.backupCodeConfig.codeLength;

    // ИСПОЛЬЗУЕМ REJECTION SAMPLING для устранения bias
    const randomBytes = cryptoRandomBytes(codeLength);
    for (let i = 0; i < codeLength; i++) {
      let randomValue: number;
      const maxValidValue = Math.floor(256 / charset.length) * charset.length;
      
      do {
        randomValue = randomBytes[i];
      } while (randomValue >= maxValidValue);
      
      code += charset[randomValue % charset.length];
    }

    // Форматирование для удобства чтения (группы по 4 символа)
    if (code.length > 4) {
      const parts = [];
      for (let i = 0; i < code.length; i += 4) {
        parts.push(code.slice(i, i + 4));
      }
      code = parts.join('-');
    }

    return code;
  }

  /**
   * Хэширует backup код
   * @private
   */
  private hashBackupCode(code: string): string {
    // Нормализация (удаление дефисов и пробелов, lower case)
    const normalized = code.replace(/[-\s]/g, '').toLowerCase();
    return createHash('sha256').update(normalized).digest('hex');
  }

  /**
   * Верифицирует backup код
   * @param code - Код от пользователя
   * @param hashedCodes - Массив захешированных кодов
   * @returns Результат верификации с ID использованного кода
   */
  public verifyBackupCode(
    code: string,
    hashedCodes: Array<Pick<IBackupCode, 'id' | 'codeHash' | 'used' | 'expiresAt'>>
  ): {
    valid: boolean;
    usedCodeId?: string;
    reason?: string;
  } {
    try {
      // Нормализация кода
      const normalized = code.replace(/[-\s]/g, '').toLowerCase();
      const codeHash = createHash('sha256').update(normalized).digest('hex');

      // Поиск совпадения
      for (const hashedCode of hashedCodes) {
        // Constant-time comparison
        const hashBuffer = Buffer.from(hashedCode.codeHash, 'hex');
        const inputBuffer = Buffer.from(codeHash, 'hex');

        if (hashBuffer.length !== inputBuffer.length) {
          continue;
        }

        if (timingSafeEqual(hashBuffer, inputBuffer)) {
          // Код найден, проверяем статус
          if (hashedCode.used) {
            return {
              valid: false,
              reason: 'Код уже был использован',
            };
          }

          if (hashedCode.expiresAt && hashedCode.expiresAt < new Date()) {
            return {
              valid: false,
              reason: 'Срок действия кода истек',
            };
          }

          return {
            valid: true,
            usedCodeId: hashedCode.id,
          };
        }
      }

      return {
        valid: false,
        reason: 'Неверный код',
      };
    } catch (error) {
      logger.error('[MFService] Ошибка верификации backup кода', { error });
      return {
        valid: false,
        reason: 'Ошибка верификации',
      };
    }
  }

  /**
   * Проверяет, осталось ли достаточно backup кодов
   * @param codeSet - Набор кодов
   * @param minRemaining - Минимальное количество
   * @returns Требуется ли перегенерация
   */
  public needsBackupCodeRegeneration(codeSet: IBackupCodeSet, minRemaining: number = 3): boolean {
    const remaining = codeSet.codeCount - codeSet.usedCount;
    return remaining < minRemaining || !codeSet.isActive;
  }

  // ===========================================================================
  // УТИЛИТЫ
  // ===========================================================================

  /**
   * Base32 кодирование (RFC 4648)
   * @private
   */
  private base32Encode(buffer: Buffer): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let result = '';
    let bits = 0;
    let value = 0;

    for (let i = 0; i < buffer.length; i++) {
      value = (value << 8) | buffer[i];
      bits += 8;

      while (bits >= 5) {
        result += alphabet[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      result += alphabet[(value << (5 - bits)) & 31];
    }

    // Добавление padding
    while (result.length % 8 !== 0) {
      result += '=';
    }

    return result;
  }

  /**
   * Base32 декодирование
   * @param base32 - Base32 строка
   * @returns Buffer
   */
  public base32Decode(base32: string): Buffer {
    // Удаление padding и пробелов
    const clean = base32.replace(/[\s=]/g, '').toUpperCase();
    
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const bits = clean.split('').reduce((acc, char) => {
      const index = alphabet.indexOf(char);
      if (index === -1) {
        throw new Error('Неверный символ в Base32 строке');
      }
      return acc + index.toString(2).padStart(5, '0');
    }, '');

    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
      const byte = bits.slice(i, i + 8);
      if (byte.length === 8) {
        bytes.push(parseInt(byte, 2));
      }
    }

    return Buffer.from(bytes);
  }

  /**
   * Валидация TOTP секрета
   * @param secret - Секрет для проверки
   * @returns Верен ли секрет
   */
  public validateTotpSecret(secret: string): boolean {
    try {
      // Проверка формата Base32
      const decoded = this.base32Decode(secret);
      return decoded.length >= this.totpConfig.secretLength;
    } catch {
      return false;
    }
  }

  /**
   * Получение оставшегося времени для текущего TOTP кода
   * @param period - Период (секунды)
   * @returns Оставшееся время в секундах
   */
  public getRemainingTime(period: number = this.totpConfig.period): number {
    const now = Math.floor(Date.now() / 1000);
    return period - (now % period);
  }

  /**
   * Расчет оставшихся попыток для MFA
   * @param attempts - Количество попыток
   * @param maxAttempts - Максимальное количество
   * @returns Оставшиеся попытки
   */
  public getRemainingAttempts(attempts: number, maxAttempts: number = 5): number {
    return Math.max(0, maxAttempts - attempts);
  }
}

/**
 * Функция для получения криптографически случайных байтов
 * @private
 */
function cryptoRandomBytes(length: number): Uint8Array {
  return randomBytes(length);
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const mfService = new MFService();

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createMFService(options?: {
  totp?: Partial<TotpConfig>;
  hotp?: Partial<HotpConfig>;
  backupCodes?: Partial<BackupCodeConfig>;
}): MFService {
  return new MFService(
    { ...DEFAULT_TOTP_CONFIG, ...options?.totp },
    { ...DEFAULT_HOTP_CONFIG, ...options?.hotp },
    { ...DEFAULT_BACKUP_CODE_CONFIG, ...options?.backupCodes }
  );
}
