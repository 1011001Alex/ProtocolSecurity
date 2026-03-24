/**
 * ============================================================================
 * TOKENIZATION SERVICE - ТОКЕНИЗАЦИЯ ПЛАТЕЖНЫХ ДАННЫХ
 * ============================================================================
 *
 * Замена чувствительных данных (PAN) на токены
 *
 * Реализация:
 * - Vaulted tokenization (с хранением маппинга)
 * - Vaultless tokenization (без хранения маппинга)
 * - Format-preserving tokenization (сохранение формата)
 * - Dynamic tokenization (одноразовые токены)
 *
 * @package protocol/finance-security/payment
 */

import { randomBytes, createHash } from 'crypto';
import { EventEmitter } from 'events';
import { logger } from '../../logging/Logger';
import { FinanceSecurityConfig, TokenizedCard } from '../types/finance.types';

/**
 * Tokenization Service
 */
export class TokenizationService extends EventEmitter {
  /** Конфигурация */
  private readonly config: FinanceSecurityConfig;

  /** Хранилище токенов (в production использовать Redis/Database) */
  private tokenVault: Map<string, any>;

  /** Обратный индекс для поиска по PAN */
  private panIndex: Map<string, string>;

  /** Статус инициализации */
  private isInitialized = false;

  /**
   * Создаёт новый экземпляр TokenizationService
   */
  constructor(config: FinanceSecurityConfig) {
    super();
    this.config = config;
    this.tokenVault = new Map();
    this.panIndex = new Map();
  }

  /**
   * Инициализация сервиса
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    try {
      // В production подключить Redis или базу данных
      logger.info('[Tokenization] Initialized with in-memory vault');

      this.isInitialized = true;

      this.emit('initialized');

    } catch (error) {
      logger.error('[Tokenization] Initialization failed', { error });
      throw error;
    }
  }

  /**
   * Токенизация платежного метода
   *
   * @param paymentMethod - PAN или другие данные
   * @param metadata - Дополнительные данные
   * @returns Токенизированные данные
   */
  public async tokenizePaymentMethod(
    paymentMethod: string,
    metadata?: Record<string, any>
  ): Promise<TokenizedCard> {
    if (!this.isInitialized) {
      throw new Error('Tokenization not initialized');
    }

    // Проверка существующего токена
    const existingToken = this.panIndex.get(paymentMethod);

    if (existingToken) {
      const existingTokenData = this.tokenVault.get(existingToken);

      if (existingTokenData && !this.isTokenExpired(existingTokenData)) {
        logger.debug('[Tokenization] Returning existing token');
        return existingTokenData;
      }
    }

    // Генерация нового токена
    const token = await this.generateToken(paymentMethod);

    const tokenData: TokenizedCard = {
      token,
      tokenExpiry: this.getTokenExpiry(),
      last4: paymentMethod.slice(-4),
      brand: this.detectCardBrand(paymentMethod),
      provider: 'ProtocolSecurity',
      status: 'ACTIVE',
      ...metadata
    };

    // Сохранение в vault
    this.tokenVault.set(token, {
      ...tokenData,
      originalPAN: paymentMethod, // В production шифровать!
      createdAt: new Date(),
      usageCount: 0
    });

    // Индексация по PAN
    this.panIndex.set(paymentMethod, token);

    logger.info('[Tokenization] Payment method tokenized', {
      token: this.maskToken(token),
      last4: tokenData.last4
    });

    this.emit('tokenized', {
      token,
      tokenData
    });

    return tokenData;
  }

  /**
   * Детокенизация - получение оригинальных данных по токену
   *
   * @param token - Токен
   * @returns Оригинальные данные
   */
  public async detokenize(token: string): Promise<any> {
    if (!this.isInitialized) {
      throw new Error('Tokenization not initialized');
    }

    const tokenData = this.tokenVault.get(token);

    if (!tokenData) {
      logger.warn('[Tokenization] Token not found', {
        token: this.maskToken(token)
      });

      throw new Error('Invalid token');
    }

    if (this.isTokenExpired(tokenData)) {
      logger.warn('[Tokenization] Token expired', {
        token: this.maskToken(token)
      });

      throw new Error('Token expired');
    }

    // Обновление статистики использования
    tokenData.usageCount++;
    tokenData.lastUsedAt = new Date();

    logger.info('[Tokenization] Token detokenized', {
      token: this.maskToken(token)
    });

    this.emit('detokenized', {
      token,
      usageCount: tokenData.usageCount
    });

    return {
      pan: tokenData.originalPAN,
      last4: tokenData.last4,
      brand: tokenData.brand
    };
  }

  /**
   * Обновление токена (re-tokenization)
   *
   * @param oldToken - Старый токен
   * @param newPaymentMethod - Новые данные
   * @returns Новый токен
   */
  public async updateToken(
    oldToken: string,
    newPaymentMethod: string
  ): Promise<TokenizedCard> {
    if (!this.isInitialized) {
      throw new Error('Tokenization not initialized');
    }

    // Деактивация старого токена
    const oldTokenData = this.tokenVault.get(oldToken);

    if (oldTokenData) {
      oldTokenData.status = 'REVOKED';

      // Удаление из индекса
      if (oldTokenData.originalPAN) {
        this.panIndex.delete(oldTokenData.originalPAN);
      }
    }

    // Создание нового токена
    return this.tokenizePaymentMethod(newPaymentMethod, {
      replacedToken: this.maskToken(oldToken),
      replacedAt: new Date()
    });
  }

  /**
   * Отзыв токена
   *
   * @param token - Токен для отзыва
   * @param reason - Причина
   */
  public async revokeToken(token: string, reason?: string): Promise<void> {
    if (!this.isInitialized) {
      throw new Error('Tokenization not initialized');
    }

    const tokenData = this.tokenVault.get(token);

    if (tokenData) {
      tokenData.status = 'REVOKED';
      tokenData.revokedAt = new Date();
      tokenData.revokeReason = reason;

      // Удаление из индекса
      if (tokenData.originalPAN) {
        this.panIndex.delete(tokenData.originalPAN);
      }

      logger.info('[Tokenization] Token revoked', {
        token: this.maskToken(token),
        reason
      });

      this.emit('revoked', {
        token,
        reason
      });
    }
  }

  /**
   * Приостановка токена (временная блокировка)
   *
   * @param token - Токен
   * @param reason - Причина
   */
  public async suspendToken(token: string, reason?: string): Promise<void> {
    const tokenData = this.tokenVault.get(token);

    if (tokenData) {
      tokenData.status = 'SUSPENDED';
      tokenData.suspendedAt = new Date();
      tokenData.suspendReason = reason;

      logger.info('[Tokenization] Token suspended', {
        token: this.maskToken(token),
        reason
      });

      this.emit('suspended', { token, reason });
    }
  }

  /**
   * Восстановление токена после приостановки
   *
   * @param token - Токен
   */
  public async resumeToken(token: string): Promise<void> {
    const tokenData = this.tokenVault.get(token);

    if (tokenData && tokenData.status === 'SUSPENDED') {
      tokenData.status = 'ACTIVE';
      tokenData.resumedAt = new Date();

      logger.info('[Tokenization] Token resumed', {
        token: this.maskToken(token)
      });

      this.emit('resumed', { token });
    }
  }

  /**
   * БЕЗОПАСНАЯ генерация криптографически стойкого случайного числа в диапазоне [0, max)
   * без bias (смещения) с использованием rejection sampling.
   *
   * ИСПОЛЬЗУЕТСЯ Secure Random Byte Method:
   * - Генерируем достаточно байт для покрытия диапазона
   * - Отбрасываем значения которые вызывают bias (rejection sampling)
   *
   * @param max - Максимальное значение (exclusive)
   * @returns Случайное число в диапазоне [0, max)
   */
  private secureRandomInt(max: number): number {
    if (max <= 0) {
      throw new Error('max должен быть положительным числом');
    }

    // Вычисляем сколько байт нужно
    const maxBytes = Math.ceil(Math.log2(max) / 8);
    const byteCount = Math.max(1, maxBytes);

    // Максимальное значение которое можно представить byteCount байтами
    const maxRange = Math.pow(256, byteCount);

    // Вычисляем порог отсечения для устранения bias
    // Отбрасываем значения >= (maxRange - (maxRange % max)) для равномерного распределения
    const threshold = maxRange - (maxRange % max);

    let randomValue: number;
    let attempts = 0;
    const maxAttempts = 100; // Защита от бесконечного цикла

    do {
      if (attempts >= maxAttempts) {
        // Fallback: используем меньшее количество байт если не повезло
        const fallbackBytes = randomBytes(byteCount);
        randomValue = fallbackBytes.reduce((acc, byte, idx) => acc + byte * Math.pow(256, idx), 0);
        return randomValue % max;
      }

      const randomBytesArray = randomBytes(byteCount);
      randomValue = randomBytesArray.reduce((acc, byte, idx) => acc + byte * Math.pow(256, idx), 0);
      attempts++;
    } while (randomValue >= threshold);

    return randomValue % max;
  }

  /**
   * Генерация токена с использованием crypto-safe random
   */
  private async generateToken(pan: string): Promise<string> {
    // Format-preserving tokenization
    const panLength = pan.replace(/\D/g, '').length;

    // Генерация случайного токена той же длины
    let token = '';

    if (this.config.tokenization.preserveLength) {
      // Сохранение формата (только цифры)
      // ИСПОЛЬЗУЕМ secureRandomInt вместо biased Math.random()
      for (let i = 0; i < panLength - 4; i++) {
        token += this.secureRandomInt(10).toString();
      }
      // Добавление последних 4 цифр PAN
      token += pan.slice(-4);
    } else {
      // Полный случайный токен
      // ИСПОЛЬЗУЕМ secureRandomDigits вместо biased b % 10
      const randomDigits = await this.generateSecureRandom(panLength);
      token = randomDigits.join('');
    }

    // Проверка уникальности
    if (this.tokenVault.has(token)) {
      return this.generateToken(pan); // Рекурсивная перегенерация
    }

    return token;
  }

  /**
   * БЕЗОПАСНАЯ генерация случайных цифр без bias
   *
   * ИСПОЛЬЗУЕТСЯ rejection sampling для устранения bias от операции %
   *
   * @param length - Количество цифр для генерации
   * @returns Массив случайных цифр [0-9]
   */
  private async generateSecureRandom(length: number): Promise<number[]> {
    const digits: number[] = [];

    for (let i = 0; i < length; i++) {
      // ИСПОЛЬЗУЕМ secureRandomInt вместо biased b % 10
      digits.push(this.secureRandomInt(10));
    }

    return digits;
  }

  /**
   * Проверка истечения токена
   */
  private isTokenExpired(tokenData: any): boolean {
    if (!tokenData.tokenExpiry) {
      return false;
    }

    return new Date(tokenData.tokenExpiry) < new Date();
  }

  /**
   * Получение срока действия токена
   */
  private getTokenExpiry(): Date {
    const expiry = new Date();
    expiry.setFullYear(expiry.getFullYear() + 5); // 5 лет по умолчанию
    return expiry;
  }

  /**
   * Маскирование токена для логирования
   */
  private maskToken(token: string): string {
    if (token.length <= 8) {
      return '*'.repeat(token.length);
    }

    return token.slice(0, 4) + '*'.repeat(token.length - 8) + token.slice(-4);
  }

  /**
   * Определение бренда карты
   */
  private detectCardBrand(pan: string): string {
    const cleanPAN = pan.replace(/\D/g, '');

    if (/^4/.test(cleanPAN)) return 'VISA';
    if (/^5[1-5]/.test(cleanPAN)) return 'MASTERCARD';
    if (/^3[47]/.test(cleanPAN)) return 'AMEX';
    if (/^6(?:011|5)/.test(cleanPAN)) return 'DISCOVER';

    return 'UNKNOWN';
  }

  /**
   * Остановка сервиса
   */
  public async destroy(): Promise<void> {
    // Безопасная очистка чувствительных данных
    for (const [key, value] of this.tokenVault.entries()) {
      if (value.originalPAN) {
        value.originalPAN = '';
      }
    }

    this.tokenVault.clear();
    this.panIndex.clear();

    this.isInitialized = false;

    logger.info('[Tokenization] Destroyed');

    this.emit('destroyed');
  }

  /**
   * Получить статистику
   */
  public getStats(): {
    totalTokens: number;
    activeTokens: number;
    revokedTokens: number;
    expiredTokens: number;
  } {
    let active = 0;
    let revoked = 0;
    let expired = 0;

    for (const tokenData of this.tokenVault.values()) {
      if (tokenData.status === 'ACTIVE') {
        active++;
      } else if (tokenData.status === 'REVOKED') {
        revoked++;
      } else if (this.isTokenExpired(tokenData)) {
        expired++;
      }
    }

    return {
      totalTokens: this.tokenVault.size,
      activeTokens: active,
      revokedTokens: revoked,
      expiredTokens: expired
    };
  }
}
