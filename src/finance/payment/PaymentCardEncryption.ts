/**
 * ============================================================================
 * PAYMENT CARD ENCRYPTION — ШИФРОВАНИЕ ПЛАТЕЖНЫХ КАРТ
 * ============================================================================
 * Полная реализация шифрования данных платёжных карт в соответствии с
 * PCI DSS v4.0 requirements
 * 
 * Функционал:
 * - Шифрование номера карты (PAN) — AES-256-GCM
 * - Токенизация карт
 * - Маскирование для отображения
 * - Luhn валидация
 * - Вычисление CVV/CVV2
 * - Определение типа карты (BIN lookup)
 * - Аудит всех операций
 * ============================================================================
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { HSMIntegration } from '../hsm/HSMIntegration';

/**
 * Типы платёжных карт
 */
export enum CardType {
  VISA = 'VISA',
  MASTERCARD = 'MASTERCARD',
  AMERICAN_EXPRESS = 'AMERICAN_EXPRESS',
  DISCOVER = 'DISCOVER',
  JCB = 'JCB',
  DINERS_CLUB = 'DINERS_CLUB',
  MAESTRO = 'MAESTRO',
  MIR = 'MIR',
  UNKNOWN = 'UNKNOWN'
}

/**
 * Данные платёжной карты
 */
export interface PaymentCardData {
  /** Номер карты (PAN) */
  pan: string;
  /** Срок действия (MM/YY) */
  expiryDate: string;
  /** CVV/CVC код */
  cvv?: string;
  /** Имя держателя */
  cardholderName?: string;
  /** Тип карты */
  cardType?: CardType;
  /** Банк эмитент */
  issuingBank?: string;
  /** Страна эмитента */
  issuingCountry?: string;
}

/**
 * Зашифрованные данные карты
 */
export interface EncryptedCardData {
  /** Зашифрованный PAN */
  encryptedPan: string;
  /** Токен карты */
  cardToken: string;
  /** Последние 4 цифры */
  lastFourDigits: string;
  /** BIN (первые 6 цифр) */
  bin: string;
  /** Тип карты */
  cardType: CardType;
  /** Срок действия (зашифрован) */
  encryptedExpiry?: string;
  /** Metadata шифрования */
  encryptionMetadata: {
    algorithm: string;
    keyId: string;
    encryptedAt: Date;
    iv: string;
    authTag?: string;
  };
}

/**
 * Токен карты
 */
export interface CardToken {
  token: string;
  cardType: CardType;
  lastFourDigits: string;
  bin: string;
  createdAt: Date;
  expiresAt?: Date;
  metadata?: Record<string, unknown>;
}

/**
 * Конфигурация шифрования карт
 */
export interface PaymentCardEncryptionConfig {
  /** Ключ шифрования (32 байта для AES-256) */
  encryptionKey?: Buffer;
  /** Ключ для токенизации */
  tokenizationKey?: Buffer;
  /** Ключ для HMAC */
  hmacKey?: Buffer;
  /** ID ключа в HSM */
  hsmKeyId?: string;
  /** HSM integration */
  hsm?: HSMIntegration;
  /** Алгоритм шифрования */
  algorithm?: 'AES-256-GCM' | 'AES-128-GCM';
  /** Включить токенизацию */
  enableTokenization?: boolean;
  /** TTL токена (часы) */
  tokenTtlHours?: number;
  /** Включить аудит */
  enableAudit?: boolean;
}

/**
 * Payment Card Encryption Service
 */
export class PaymentCardEncryption extends EventEmitter {
  private readonly config: PaymentCardEncryptionConfig;
  private readonly encryptionKey: Buffer;
  private readonly tokenizationKey: Buffer;
  private readonly hmacKey: Buffer;
  private readonly tokenCache: Map<string, CardToken> = new Map();
  private readonly auditLog: AuditEvent[] = [];

  constructor(config: PaymentCardEncryptionConfig) {
    super();

    this.config = {
      algorithm: 'AES-256-GCM',
      enableTokenization: true,
      tokenTtlHours: 24,
      enableAudit: true,
      ...config
    };

    // Генерация или использование предоставленных ключей
    this.encryptionKey = config.encryptionKey || crypto.randomBytes(32);
    this.tokenizationKey = config.tokenizationKey || crypto.randomBytes(32);
    this.hmacKey = config.hmacKey || crypto.randomBytes(32);

    // Валидация ключа шифрования
    if (this.encryptionKey.length !== 32 && this.encryptionKey.length !== 16) {
      throw new Error('Encryption key must be 32 bytes (AES-256) or 16 bytes (AES-128)');
    }

    this.emit('initialized', {
      algorithm: this.config.algorithm,
      tokenizationEnabled: this.config.enableTokenization
    });
  }

  /**
   * Шифрование данных платёжной карты
   */
  async encryptCard(cardData: PaymentCardData): Promise<EncryptedCardData> {
    const startTime = Date.now();
    const operationId = uuidv4();

    try {
      // Валидация карты
      if (!this.validateLuhn(cardData.pan)) {
        throw new Error('Invalid card number (Luhn check failed)');
      }

      // Определение типа карты
      const cardType = this.detectCardType(cardData.pan);

      // Извлечение BIN и last4
      const bin = cardData.pan.substring(0, 6);
      const lastFourDigits = cardData.pan.substring(cardData.pan.length - 4);

      // Шифрование PAN
      const { encrypted: encryptedPan, iv, authTag } = this.encryptPAN(cardData.pan);

      // Шифрование срока действия
      const encryptedExpiry = this.encryptExpiryDate(cardData.expiryDate);

      // Генерация токена
      const cardToken = this.config.enableTokenization
        ? await this.generateCardToken(cardData.pan, cardType, bin, lastFourDigits)
        : '';

      const encryptionMetadata = {
        algorithm: this.config.algorithm,
        keyId: this.config.hsmKeyId || 'local-key',
        encryptedAt: new Date(),
        iv: iv.toString('base64'),
        authTag: authTag?.toString('base64')
      };

      const result: EncryptedCardData = {
        encryptedPan,
        cardToken,
        lastFourDigits,
        bin,
        cardType,
        encryptedExpiry,
        encryptionMetadata
      };

      this.logAuditEvent('CARD_ENCRYPTED', operationId, true, {
        cardType,
        bin,
        lastFourDigits
      });

      this.emit('card_encrypted', { operationId, cardType });
      return result;

    } catch (error) {
      this.logAuditEvent('CARD_ENCRYPTION_FAILED', operationId, false, error);
      this.emit('error', { operationId, error });
      throw error;
    }
  }

  /**
   * Расшифровка данных платёжной карты
   */
  async decryptCard(encryptedData: EncryptedCardData): Promise<PaymentCardData> {
    const startTime = Date.now();
    const operationId = uuidv4();

    try {
      // Расшифровка PAN
      const pan = this.decryptPAN(
        encryptedData.encryptedPan,
        Buffer.from(encryptedData.encryptionMetadata.iv, 'base64'),
        encryptedData.encryptionMetadata.authTag
          ? Buffer.from(encryptedData.encryptionMetadata.authTag, 'base64')
          : undefined
      );

      // Расшифровка срока действия
      const expiryDate = this.decryptExpiryDate(encryptedData.encryptedExpiry!);

      const cardData: PaymentCardData = {
        pan,
        expiryDate,
        cardType: encryptedData.cardType
      };

      this.logAuditEvent('CARD_DECRYPTED', operationId, true, {
        cardType: encryptedData.cardType,
        bin: encryptedData.bin,
        lastFourDigits: encryptedData.lastFourDigits
      });

      this.emit('card_decrypted', { operationId });
      return cardData;

    } catch (error) {
      this.logAuditEvent('CARD_DECRYPTION_FAILED', operationId, false, error);
      this.emit('error', { operationId, error });
      throw error;
    }
  }

  /**
   * Шифрование PAN
   */
  private encryptPAN(pan: string): { encrypted: string; iv: Buffer; authTag?: Buffer } {
    const iv = crypto.randomBytes(12);
    
    let encrypted: Buffer;
    let authTag: Buffer | undefined;

    if (this.config.algorithm === 'AES-256-GCM' || this.config.algorithm === 'AES-128-GCM') {
      const cipher = crypto.createCipheriv(
        this.config.algorithm === 'AES-256-GCM' ? 'aes-256-gcm' : 'aes-128-gcm',
        this.encryptionKey,
        iv
      );

      encrypted = Buffer.concat([cipher.update(pan, 'utf8'), cipher.final()]);
      authTag = cipher.getAuthTag();
    } else {
      // Fallback для других алгоритмов
      const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv.slice(0, 16));
      encrypted = Buffer.concat([cipher.update(pan, 'utf8'), cipher.final()]);
    }

    return {
      encrypted: encrypted.toString('base64'),
      iv,
      authTag
    };
  }

  /**
   * Расшифровка PAN
   */
  private decryptPAN(
    encryptedPan: string,
    iv: Buffer,
    authTag?: Buffer
  ): string {
    const encrypted = Buffer.from(encryptedPan, 'base64');
    let decrypted: Buffer;

    if (this.config.algorithm.includes('GCM') && authTag) {
      const decipher = crypto.createDecipheriv(
        this.config.algorithm === 'AES-256-GCM' ? 'aes-256-gcm' : 'aes-128-gcm',
        this.encryptionKey,
        iv
      );
      decipher.setAuthTag(authTag);
      decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    } else {
      const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv.slice(0, 16));
      decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    }

    return decrypted.toString('utf8');
  }

  /**
   * Шифрование срока действия
   */
  private encryptExpiryDate(expiryDate: string): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.encryptionKey, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(expiryDate, 'utf8'),
      cipher.final()
    ]);

    return Buffer.concat([iv, encrypted]).toString('base64');
  }

  /**
   * Расшифровка срока действия
   */
  private decryptExpiryDate(encryptedExpiry: string): string {
    const data = Buffer.from(encryptedExpiry, 'base64');
    const iv = data.slice(0, 16);
    const encrypted = data.slice(16);

    const decipher = crypto.createDecipheriv('aes-256-cbc', this.encryptionKey, iv);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);

    return decrypted.toString('utf8');
  }

  /**
   * Генерация токена карты
   */
  private async generateCardToken(
    pan: string,
    cardType: CardType,
    bin: string,
    lastFourDigits: string
  ): Promise<string> {
    // Генерация уникального токена
    const tokenData = `${pan}:${this.tokenizationKey.toString('hex')}:${Date.now()}`;
    const token = crypto
      .createHmac('sha256', this.tokenizationKey)
      .update(tokenData)
      .digest('hex')
      .substring(0, 16);

    // Форматирование токена (сохраняет формат карты)
    const formattedToken = this.formatToken(token, pan.length);

    // Кэширование токена
    const cardToken: CardToken = {
      token: formattedToken,
      cardType,
      lastFourDigits,
      bin,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.tokenTtlHours * 60 * 60 * 1000),
      metadata: {
        originalPanHash: this.hashPAN(pan)
      }
    };

    this.tokenCache.set(formattedToken, cardToken);

    return formattedToken;
  }

  /**
   * Форматирование токена
   */
  private formatToken(token: string, length: number): string {
    // Токен должен проходить Luhn проверку
    let result = token.substring(0, length - 1);
    
    // Вычисление контрольной цифры Luhn
    const checkDigit = this.calculateLuhnCheckDigit(result);
    result += checkDigit;

    return result;
  }

  /**
   * Вычисление контрольной цифры Luhn
   */
  private calculateLuhnCheckDigit(partialPan: string): number {
    const digits = partialPan.split('').map(Number).reverse();
    let sum = 0;

    for (let i = 0; i < digits.length; i++) {
      let digit = digits[i];
      
      if (i % 2 === 0) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }
      
      sum += digit;
    }

    return (10 - (sum % 10)) % 10;
  }

  /**
   * Валидация Luhn
   */
  validateLuhn(pan: string): boolean {
    const digits = pan.replace(/\D/g, '').split('').map(Number).reverse();
    let sum = 0;

    for (let i = 0; i < digits.length; i++) {
      let digit = digits[i];
      
      if (i % 2 === 1) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }
      
      sum += digit;
    }

    return sum % 10 === 0;
  }

  /**
   * Определение типа карты
   */
  detectCardType(pan: string): CardType {
    const panRegexes: Record<CardType, RegExp> = {
      [CardType.VISA]: /^4[0-9]{12}(?:[0-9]{3})?$/,
      [CardType.MASTERCARD]: /^5[1-5][0-9]{14}$|^2(2[2-9][0-9]{12}|[3-6][0-9]{13}|7[0-1][0-9]{12}|720[0-9]{11})$/,
      [CardType.AMERICAN_EXPRESS]: /^3[47][0-9]{13}$/,
      [CardType.DISCOVER]: /^6(?:011|5[0-9]{2}|4[4-9][0-9]|22(?:12[6-9]|1[3-9][0-9]|[2-8][0-9]{2}|9[0-1][0-9]|92[0-5])[0-9]{10})$/,
      [CardType.JCB]: /^35(2[89][0-9]|[3-8][0-9]{2})[0-9]{12}$/,
      [CardType.DINERS_CLUB]: /^3(?:0[0-5]|[68][0-9])[0-9]{11}$/,
      [CardType.MAESTRO]: /^(?:5[0678]\d\d|6304|6390|67\d\d)\d{8,15}$/,
      [CardType.MIR]: /^220[0-4][0-9]{12}$/,
      [CardType.UNKNOWN]: /^.*$/
    };

    for (const [cardType, regex] of Object.entries(panRegexes)) {
      if (regex.test(pan)) {
        return cardType as CardType;
      }
    }

    return CardType.UNKNOWN;
  }

  /**
   * Маскирование PAN для отображения
   */
  maskPAN(pan: string, showFirst?: number, showLast: number = 4): string {
    const digits = pan.replace(/\D/g, '');
    const first = showFirst || 0;
    const maskedLength = digits.length - first - showLast;

    if (maskedLength <= 0) {
      return digits;
    }

    const masked = digits.substring(0, first) +
      '•'.repeat(maskedLength) +
      digits.substring(digits.length - showLast);

    // Форматирование по 4 цифры
    return masked.match(/.{1,4}/g)?.join(' ') || masked;
  }

  /**
   * Хэширование PAN (для индексации)
   */
  hashPAN(pan: string): string {
    const normalizedPan = pan.replace(/\D/g, '');
    return crypto
      .createHmac('sha256', this.hmacKey)
      .update(normalizedPan)
      .digest('hex');
  }

  /**
   * Вычисление CVV (для тестирования)
   */
  calculateCVV(pan: string, expiryDate: string, serviceCode: string = '101'): string {
    // CVV вычисляется по алгоритму ISO/IEC 7812
    // Это упрощённая реализация для тестирования
    const data = `${pan}${expiryDate}${serviceCode}`;
    const hash = crypto
      .createHmac('sha256', this.hmacKey)
      .update(data)
      .digest('hex');
    
    return hash.substring(0, 3);
  }

  /**
   * Получение токена по PAN
   */
  async getTokenByPAN(pan: string): Promise<CardToken | null> {
    const panHash = this.hashPAN(pan);
    
    for (const token of this.tokenCache.values()) {
      if (token.metadata?.originalPanHash === panHash) {
        return token;
      }
    }

    return null;
  }

  /**
   * Валидация токена
   */
  async validateToken(token: string): Promise<boolean> {
    const cardToken = this.tokenCache.get(token);
    
    if (!cardToken) {
      return false;
    }

    if (cardToken.expiresAt && new Date() > cardToken.expiresAt) {
      this.tokenCache.delete(token);
      return false;
    }

    return true;
  }

  /**
   * Отозвать токен
   */
  revokeToken(token: string): void {
    this.tokenCache.delete(token);
    this.logAuditEvent('TOKEN_REVOKED', token, true);
  }

  /**
   * Очистка просроченных токенов
   */
  cleanupExpiredTokens(): number {
    const now = new Date();
    let removed = 0;

    for (const [token, cardToken] of this.tokenCache.entries()) {
      if (cardToken.expiresAt && now > cardToken.expiresAt) {
        this.tokenCache.delete(token);
        removed++;
      }
    }

    if (removed > 0) {
      this.logAuditEvent('TOKENS_CLEANUP', 'system', true, { removed });
    }

    return removed;
  }

  /**
   * BIN lookup (определение банка по BIN)
   */
  async binLookup(bin: string): Promise<{
    bank?: string;
    country?: string;
    cardType: CardType;
    cardCategory?: 'DEBIT' | 'CREDIT' | 'PREPAID';
  }> {
    // В production здесь был бы запрос к BIN database
    // Это упрощённая реализация
    
    const cardType = this.detectCardType(bin + '0000000000');
    
    // Примерные данные по BIN
    const binData: Record<string, any> = {
      '4': { cardCategory: 'DEBIT' as const }, // Visa
      '5': { cardCategory: 'CREDIT' as const }, // Mastercard
      '3': { cardCategory: 'CREDIT' as const }, // Amex
      '220': { bank: 'Sberbank', country: 'RU', cardCategory: 'DEBIT' as const } // MIR
    };

    const prefix = bin.substring(0, 3);
    const data = binData[prefix] || binData[bin.substring(0, 2)] || binData[bin.substring(0, 1)] || {};

    return {
      cardType,
      ...data
    };
  }

  /**
   * Логирование аудит события
   */
  private logAuditEvent(
    eventType: string,
    operationId: string,
    success: boolean,
    details?: any
  ): void {
    if (!this.config.enableAudit) {
      return;
    }

    const event: AuditEvent = {
      eventId: uuidv4(),
      timestamp: new Date(),
      eventType,
      operationId,
      success,
      details
    };

    this.auditLog.push(event);

    // Ограничение размера лога
    if (this.auditLog.length > 10000) {
      this.auditLog.shift();
    }

    this.emit('audit', event);
  }

  /**
   * Получение статистики
   */
  getStats(): {
    tokensCached: number;
    auditLogSize: number;
    algorithm: string;
    tokenizationEnabled: boolean;
  } {
    return {
      tokensCached: this.tokenCache.size,
      auditLogSize: this.auditLog.length,
      algorithm: this.config.algorithm,
      tokenizationEnabled: this.config.enableTokenization
    };
  }

  /**
   * Очистка чувствительных данных из памяти
   */
  secureCleanup(): void {
    // Очистка токенов
    this.tokenCache.clear();

    // "Затирание" ключей (в Node.js это не полностью безопасно)
    this.encryptionKey.fill(0);
    this.tokenizationKey.fill(0);
    this.hmacKey.fill(0);

    this.logAuditEvent('SECURE_CLEANUP', 'system', true);
  }
}

/**
 * Аудит событие
 */
interface AuditEvent {
  eventId: string;
  timestamp: Date;
  eventType: string;
  operationId: string;
  success: boolean;
  details?: any;
}

/**
 * Factory функция для создания PaymentCardEncryption
 */
export function createPaymentCardEncryption(
  config: Partial<PaymentCardEncryptionConfig>
): PaymentCardEncryption {
  return new PaymentCardEncryption(config as PaymentCardEncryptionConfig);
}
