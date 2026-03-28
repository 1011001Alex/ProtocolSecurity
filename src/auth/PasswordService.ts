/**
 * =============================================================================
 * PASSWORD SERVICE
 * =============================================================================
 * Сервис для безопасного хэширования и верификации паролей
 * Поддерживает: bcrypt, argon2id, argon2d, argon2i
 * Соответствует: NIST 800-63B, OWASP Password Storage Cheat Sheet
 * =============================================================================
 */

import * as bcrypt from 'bcrypt';
import * as argon2 from 'argon2';
import { randomBytes, timingSafeEqual } from 'crypto';
import { AuthError, AuthErrorCode } from '../types/auth.types';

/**
 * Типы алгоритмов хэширования паролей
 */
export type PasswordAlgorithm = 'bcrypt' | 'argon2id' | 'argon2d' | 'argon2i';

/**
 * Конфигурация для bcrypt
 */
interface BcryptConfig {
  algorithm: 'bcrypt';
  /** Cost factor (4-31). Рекомендуется 12 для production */
  cost: number;
}

/**
 * Конфигурация для argon2
 */
interface Argon2Config {
  algorithm: 'argon2id' | 'argon2d' | 'argon2i';
  /** Объем памяти в KB */
  memoryCost: number;
  /** Количество итераций */
  timeCost: number;
  /** Параллелизм */
  parallelism: number;
}

/**
 * Конфигурация хэширования
 */
export type PasswordHashConfig = BcryptConfig | Argon2Config;

/**
 * Результат хэширования
 */
export interface HashResult {
  /** Хэш пароля */
  hash: string;
  /** Алгоритм */
  algorithm: PasswordAlgorithm;
  /** Версия для миграции */
  version: number;
}

/**
 * Результат верификации
 */
export interface VerifyResult {
  /** Верен ли пароль */
  valid: boolean;
  /** Требуется ли пере-хэширование */
  needsRehash: boolean;
  /** Алгоритм, использованный для хэша */
  algorithm: PasswordAlgorithm;
  /** Версия хэша */
  version: number;
}

/**
 * Конфигурация PasswordService по умолчанию
 * Соответствует OWASP recommendations 2023
 */
const DEFAULT_CONFIG: PasswordHashConfig = {
  algorithm: 'argon2id',
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
};

/**
 * Минимальная длина пароля по NIST 800-63B
 */
export const MIN_PASSWORD_LENGTH = 8;

/**
 * Максимальная длина пароля (для защиты от DoS)
 */
export const MAX_PASSWORD_LENGTH = 128;

/**
 * Текущая версия хэша для миграции
 */
export const CURRENT_HASH_VERSION = 1;

/**
 * =============================================================================
 * PASSWORD SERVICE CLASS
 * =============================================================================
 */
export class PasswordService {
  private config: PasswordHashConfig;
  private readonly saltRounds: number = 16;

  /**
   * Создает новый экземпляр PasswordService
   * @param config - Конфигурация хэширования
   */
  constructor(config: PasswordHashConfig = DEFAULT_CONFIG) {
    this.config = config;
  }

  /**
   * =============================================================================
   * ПРОВЕРКА ПАРОЛЯ НА СЛОЖНОСТЬ
   * =============================================================================
   * Соответствует NIST 800-63B Appendix A
   */

  /**
   * Проверяет сложность пароля
   * @param password - Пароль для проверки
   * @returns Результат проверки
   * @throws AuthError если пароль не соответствует требованиям
   */
  public validatePasswordStrength(password: string): {
    valid: boolean;
    score: number;
    requirements: string[];
    warnings: string[];
  } {
    const requirements: string[] = [];
    const warnings: string[] = [];
    let score = 0;

    // Проверка длины
    if (password.length < MIN_PASSWORD_LENGTH) {
      requirements.push(`Минимальная длина: ${MIN_PASSWORD_LENGTH} символов`);
    } else if (password.length >= 12) {
      score += 20;
    } else {
      score += 10;
    }

    if (password.length > MAX_PASSWORD_LENGTH) {
      throw new AuthError(
        `Пароль слишком длинный (максимум ${MAX_PASSWORD_LENGTH} символов)`,
        AuthErrorCode.INVALID_CREDENTIALS,
        400
      );
    }

    // Проверка наличия разных типов символов
    const hasLowercase = /[a-zа-яё]/.test(password);
    const hasUppercase = /[A-ZА-ЯЁ]/.test(password);
    const hasDigits = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password);

    const charTypes = [hasLowercase, hasUppercase, hasDigits, hasSpecial].filter(Boolean).length;

    if (charTypes < 3) {
      requirements.push('Используйте буквы (заглавные и строчные), цифры и специальные символы');
    } else {
      score += charTypes * 10;
    }

    // Проверка на распространенные пароли
    const commonPasswords = [
      'password', '123456', '12345678', 'qwerty', 'abc123',
      'пароль', '123456789', '1234567', '12345', '1234567890'
    ];
    
    if (commonPasswords.includes(password.toLowerCase())) {
      warnings.push('Это очень распространенный пароль');
      score -= 50;
    }

    // Проверка на последовательности
    const sequences = [
      '123', '234', '345', '456', '567', '678', '789', '890',
      'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij',
      'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio', 'iop',
      'азб', 'збв', 'бвг', 'вгде', 'гдее',
      'йцу', 'цук', 'укен', 'кенг', 'енга', 'нгаш', 'гашщ',
    ];

    const hasSequence = sequences.some(seq => 
      password.toLowerCase().includes(seq)
    );

    if (hasSequence) {
      warnings.push('Избегайте последовательностей символов');
      score -= 20;
    }

    // Проверка на повторяющиеся символы
    const repeatedChars = /(.)\1{2,}/.test(password);
    if (repeatedChars) {
      warnings.push('Избегайте повторяющихся символов');
      score -= 10;
    }

    // Проверка на наличие email или домена
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (emailPattern.test(password)) {
      warnings.push('Не используйте email в качестве пароля');
      score -= 30;
    }

    // Нормализация score
    score = Math.max(0, Math.min(100, score));

    return {
      valid: score >= 50 && requirements.length === 0,
      score,
      requirements,
      warnings,
    };
  }

  /**
   * =============================================================================
   * ХЭШИРОВАНИЕ ПАРОЛЯ
   * =============================================================================
   */

  /**
   * Хэширует пароль с использованием настроенного алгоритма
   * @param password - Пароль для хэширования
   * @returns Результат хэширования
   * @throws AuthError при ошибке хэширования
   */
  public async hashPassword(password: string): Promise<HashResult> {
    // Валидация входных данных
    this.validatePasswordInput(password);

    try {
      let hash: string;

      switch (this.config.algorithm) {
        case 'bcrypt':
          hash = await this.hashWithBcrypt(password, this.config.cost);
          break;
        case 'argon2id':
        case 'argon2d':
        case 'argon2i':
          hash = await this.hashWithArgon2(password, this.config);
          break;
        default:
          throw new AuthError(
            `Неподдерживаемый алгоритм: ${(this.config as any).algorithm}`,
            AuthErrorCode.INTERNAL_ERROR,
            500
          );
      }

      return {
        hash,
        algorithm: this.config.algorithm,
        version: CURRENT_HASH_VERSION,
      };
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        'Ошибка хэширования пароля',
        AuthErrorCode.INTERNAL_ERROR,
        500,
        { originalError: error instanceof Error ? error.message : 'Unknown error' }
      );
    }
  }

  /**
   * Хэширование с bcrypt
   * @private
   */
  private async hashWithBcrypt(password: string, cost: number): Promise<string> {
    // Генерация соли с криптографически безопасным RNG
    const salt = await bcrypt.genSalt(cost);
    return bcrypt.hash(password, salt);
  }

  /**
   * Хэширование с argon2
   * @private
   */
  private async hashWithArgon2(
    password: string,
    config: Argon2Config
  ): Promise<string> {
    // Определяем тип алгоритма для argon2
    let argon2Type: 0 | 1 | 2; // 0 = argon2d, 1 = argon2i, 2 = argon2id
    if (config.algorithm === 'argon2id') {
      argon2Type = argon2.argon2id;
    } else if (config.algorithm === 'argon2d') {
      argon2Type = argon2.argon2d;
    } else {
      argon2Type = argon2.argon2i;
    }

    const hash = await argon2.hash(password, {
      type: argon2Type as any,
      memoryCost: config.memoryCost,
      timeCost: config.timeCost,
      parallelism: config.parallelism,
      hashLength: 32
    });

    return hash;
  }

  /**
   * =============================================================================
   * ВЕРИФИКАЦИЯ ПАРОЛЯ
   * =============================================================================
   */

  /**
   * Проверяет пароль против хэша
   * Использует constant-time comparison для защиты от timing attacks
   * @param password - Пароль для проверки
   * @param hash - Хэш для верификации
   * @returns Результат верификации
   * @throws AuthError при ошибке верификации
   */
  public async verifyPassword(password: string, hash: string): Promise<VerifyResult> {
    // Валидация входных данных
    this.validatePasswordInput(password);

    if (!hash || typeof hash !== 'string') {
      // Constant-time reject для защиты от timing attacks
      await this.constantTimeReject();
      throw new AuthError(
        'Неверный формат хэша',
        AuthErrorCode.INVALID_CREDENTIALS,
        400
      );
    }

    try {
      let isValid = false;
      let algorithm: PasswordAlgorithm = 'bcrypt';
      let version = 0;

      // Определение алгоритма по формату хэша
      if (hash.startsWith('$argon2')) {
        algorithm = this.detectArgon2Type(hash);
        isValid = await this.verifyWithArgon2(password, hash);
        version = this.extractArgon2Version(hash);
      } else if (hash.startsWith('$2')) {
        algorithm = 'bcrypt';
        isValid = await this.verifyWithBcrypt(password, hash);
        version = this.extractBcryptVersion(hash);
      } else {
        // Неизвестный формат
        await this.constantTimeReject();
        return {
          valid: false,
          needsRehash: false,
          algorithm: 'unknown' as PasswordAlgorithm,
          version: 0,
        };
      }

      // Проверка необходимости пере-хэширования
      const needsRehash = this.checkNeedsRehash(hash, algorithm);

      return {
        valid: isValid,
        needsRehash,
        algorithm,
        version,
      };
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        'Ошибка верификации пароля',
        AuthErrorCode.INTERNAL_ERROR,
        500,
        { originalError: error instanceof Error ? error.message : 'Unknown error' }
      );
    }
  }

  /**
   * Верификация с bcrypt
   * @private
   */
  private async verifyWithBcrypt(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  /**
   * Верификация с argon2
   * @private
   */
  private async verifyWithArgon2(password: string, hash: string): Promise<boolean> {
    return argon2.verify(hash, password);
  }

  /**
   * Определяет тип argon2 по хэшу
   * @private
   */
  private detectArgon2Type(hash: string): PasswordAlgorithm {
    if (hash.startsWith('$argon2id')) return 'argon2id';
    if (hash.startsWith('$argon2d')) return 'argon2d';
    if (hash.startsWith('$argon2i')) return 'argon2i';
    return 'argon2id'; // Default
  }

  /**
   * Извлекает версию из bcrypt хэша
   * @private
   */
  private extractBcryptVersion(hash: string): number {
    // Bcrypt версии: $2a$, $2b$, $2y$
    if (hash.startsWith('$2b$')) return 2;
    if (hash.startsWith('$2a$')) return 1;
    if (hash.startsWith('$2y$')) return 3;
    return 0;
  }

  /**
   * Извлекает версию из argon2 хэша
   * @private
   */
  private extractArgon2Version(hash: string): number {
    // Argon2 версия в формате $argon2$type$v=version$...
    const match = hash.match(/\$v=(\d+)\$/);
    return match ? parseInt(match[1], 10) : 1;
  }

  /**
   * Проверяет необходимость пере-хэширования
   * @private
   */
  private checkNeedsRehash(hash: string, algorithm: PasswordAlgorithm): boolean {
    // Проверка версии
    const version = algorithm === 'bcrypt' 
      ? this.extractBcryptVersion(hash)
      : this.extractArgon2Version(hash);

    if (version < CURRENT_HASH_VERSION) {
      return true;
    }

    // Проверка параметров для argon2
    if (algorithm.startsWith('argon2')) {
      const currentParams = this.config as Argon2Config;
      
      // Извлечение параметров из хэша
      const memoryMatch = hash.match(/m=(\d+)/);
      const timeMatch = hash.match(/t=(\d+)/);
      const pMatch = hash.match(/p=(\d+)/);

      const hashMemory = memoryMatch ? parseInt(memoryMatch[1], 10) : 0;
      const hashTime = timeMatch ? parseInt(timeMatch[1], 10) : 0;
      const hashParallelism = pMatch ? parseInt(pMatch[1], 10) : 0;

      // Если текущие параметры строже - нужно пере-хэширование
      if (
        hashMemory < currentParams.memoryCost ||
        hashTime < currentParams.timeCost ||
        hashParallelism < currentParams.parallelism
      ) {
        return true;
      }
    }

    // Проверка cost для bcrypt
    if (algorithm === 'bcrypt') {
      const costMatch = hash.match(/\$2[aby]?\$(\d+)\$/);
      const hashCost = costMatch ? parseInt(costMatch[1], 10) : 0;
      const currentCost = (this.config as BcryptConfig).cost || 10;

      if (hashCost < currentCost) {
        return true;
      }
    }

    return false;
  }

  /**
   * =============================================================================
   * УТИЛИТЫ
   * =============================================================================
   */

  /**
   * Constant-time reject для защиты от timing attacks
   * @private
   */
  private async constantTimeReject(): Promise<void> {
    // Генерируем фиктивный хэш и сравниваем с фиктивным паролем
    // Это занимает примерно то же время, что и реальная верификация
    const dummyHash = '$2b$10$' + 'a'.repeat(53);
    const dummyPassword = 'a'.repeat(MIN_PASSWORD_LENGTH);
    await bcrypt.compare(dummyPassword, dummyHash);
  }

  /**
   * Валидация входного пароля
   * @private
   */
  private validatePasswordInput(password: string): void {
    if (!password || typeof password !== 'string') {
      throw new AuthError(
        'Пароль должен быть строкой',
        AuthErrorCode.INVALID_CREDENTIALS,
        400
      );
    }

    if (password.length < MIN_PASSWORD_LENGTH) {
      throw new AuthError(
        `Пароль слишком короткий (минимум ${MIN_PASSWORD_LENGTH} символов)`,
        AuthErrorCode.INVALID_CREDENTIALS,
        400
      );
    }

    if (password.length > MAX_PASSWORD_LENGTH) {
      throw new AuthError(
        `Пароль слишком длинный (максимум ${MAX_PASSWORD_LENGTH} символов)`,
        AuthErrorCode.INVALID_CREDENTIALS,
        400
      );
    }
  }

  /**
   * Генерация безопасного временного пароля
   * @param length - Длина пароля (по умолчанию 16)
   * @returns Сгенерированный пароль
   */
  public generateSecurePassword(length: number = 16): string {
    if (length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
      throw new AuthError(
        `Длина пароля должна быть от ${MIN_PASSWORD_LENGTH} до ${MAX_PASSWORD_LENGTH}`,
        AuthErrorCode.INVALID_CREDENTIALS,
        400
      );
    }

    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const digits = '0123456789';
    const special = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    const allChars = lowercase + uppercase + digits + special;

    // Гарантируем наличие хотя бы одного символа каждого типа
    // ИСПОЛЬЗУЕМ REJECTION SAMPLING для устранения bias
    let password = '';
    password += this.getRandomChar(lowercase);
    password += this.getRandomChar(uppercase);
    password += this.getRandomChar(digits);
    password += this.getRandomChar(special);

    // Заполняем оставшуюся длину случайными символами
    for (let i = password.length; i < length; i++) {
      password += this.getRandomChar(allChars);
    }

    // Перемешиваем пароль
    return this.shuffleString(password);
  }

  /**
   * Получение случайного символа из набора с использованием rejection sampling
   * @private
   */
  private getRandomChar(charset: string): string {
    const maxValidValue = Math.floor(256 / charset.length) * charset.length;
    let randomValue: number;
    
    do {
      randomValue = randomBytes(1)[0];
    } while (randomValue >= maxValidValue);
    
    return charset[randomValue % charset.length];
  }

  /**
   * Перемешивание строки (Fisher-Yates shuffle)
   * @private
   */
  private shuffleString(str: string): string {
    const arr = str.split('');
    for (let i = arr.length - 1; i > 0; i--) {
      // ИСПОЛЬЗУЕМ REJECTION SAMPLING для устранения bias
      const maxValidValue = Math.floor(256 / (i + 1)) * (i + 1);
      let j: number;
      
      do {
        j = randomBytes(1)[0];
      } while (j >= maxValidValue);
      
      j = j % (i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr.join('');
  }

  /**
   * Проверка необходимости смены пароля
   * @param passwordHash - Текущий хэш пароля
   * @param passwordVersion - Текущая версия хэша
   * @returns Требуется ли смена
   */
  public needsPasswordRotation(passwordHash: string, passwordVersion: number): boolean {
    // Проверка версии
    if (passwordVersion < CURRENT_HASH_VERSION) {
      return true;
    }

    // Проверка алгоритма
    if (!passwordHash.startsWith('$2') && !passwordHash.startsWith('$argon2')) {
      return true;
    }

    return false;
  }

  /**
   * Получение информации о хэше
   * @param hash - Хэш для анализа
   * @returns Информация о хэше
   */
  public getHashInfo(hash: string): {
    algorithm: PasswordAlgorithm;
    version: number;
    needsRehash: boolean;
    parameters?: Record<string, any>;
  } {
    let algorithm: PasswordAlgorithm = 'bcrypt';
    let version = 0;
    let parameters: Record<string, any> = {};

    if (hash.startsWith('$argon2')) {
      algorithm = this.detectArgon2Type(hash);
      version = this.extractArgon2Version(hash);

      // Извлечение параметров
      const memoryMatch = hash.match(/m=(\d+)/);
      const timeMatch = hash.match(/t=(\d+)/);
      const pMatch = hash.match(/p=(\d+)/);

      if (memoryMatch) parameters.memory = parseInt(memoryMatch[1], 10);
      if (timeMatch) parameters.time = parseInt(timeMatch[1], 10);
      if (pMatch) parameters.parallelism = parseInt(pMatch[1], 10);
    } else if (hash.startsWith('$2')) {
      algorithm = 'bcrypt';
      version = this.extractBcryptVersion(hash);

      const costMatch = hash.match(/\$2[aby]?\$(\d+)\$/);
      if (costMatch) {
        parameters.cost = parseInt(costMatch[1], 10);
      }
    }

    return {
      algorithm,
      version,
      needsRehash: this.checkNeedsRehash(hash, algorithm),
      parameters,
    };
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const passwordService = new PasswordService(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createPasswordService(config: PasswordHashConfig): PasswordService {
  return new PasswordService(config);
}
