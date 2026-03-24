/**
 * ============================================================================
 * SECURE PIN PROCESSING — БЕЗОПАСНАЯ ОБРАБОТКА PIN-КОДОВ
 * ============================================================================
 *
 * Обработка PIN-кодов с соблюдением PCI DSS и PCI PIN Security Requirements
 *
 * Реализация:
 * - PIN Block формирование по ISO 9564
 * - Triple DES / AES шифрование PIN блоков
 * - PIN Verification Value (PVV) генерация
 * - PIN Translation для межбанковских операций
 *
 * @package protocol/finance-security/payment
 * @author Protocol Security Team
 * @version 1.0.0
 */

import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import { EventEmitter } from 'events';
import { logger } from '../../logging/Logger';
import { FinanceSecurityConfig, PINBlock } from '../types/finance.types';

/**
 * Secure PIN Processing Service
 */
export class SecurePINProcessing extends EventEmitter {
  /** Конфигурация */
  private readonly config: FinanceSecurityConfig;

  /** Key Encryption Key для PIN */
  private pinKek?: Buffer;

  /** Working Key для PIN операций */
  private pinWorkingKey?: Buffer;

  /** Terminal PIN Key (TPK) */
  private tpk?: Buffer;

  /** Статус инициализации */
  private isInitialized = false;

  /**
   * Создаёт новый экземпляр SecurePINProcessing
   */
  constructor(config: FinanceSecurityConfig) {
    super();

    this.config = config;

    logger.info('[SecurePIN] Service created');
  }

  /**
   * Инициализация сервиса
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[SecurePIN] Already initialized');
      return;
    }

    try {
      // Генерация ключей для PIN операций
      // В production ключи должны загружаться из HSM
      this.pinKek = randomBytes(32); // AES-256 для KEK
      this.pinWorkingKey = randomBytes(16); // 3DES key
      this.tpk = randomBytes(16); // Terminal PIN Key

      this.isInitialized = true;

      logger.info('[SecurePIN] Initialized with secure key generation');

      this.emit('initialized');

    } catch (error) {
      logger.error('[SecurePIN] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Формирование PIN блока по ISO 9564 Format 0
   *
   * @param pin - PIN код (4-12 цифр)
   * @param pan - Primary Account Number (без последней цифры)
   * @returns PIN Block в формате ISO-0
   */
  public createPINBlockISO0(pin: string, pan: string): string {
    if (!this.isInitialized) {
      throw new Error('SecurePIN not initialized');
    }

    // Валидация PIN
    if (!/^\d{4,12}$/.test(pin)) {
      throw new Error('Invalid PIN: must be 4-12 digits');
    }

    // Очистка PAN от нецифровых символов
    const cleanPAN = pan.replace(/\D/g, '');

    if (cleanPAN.length < 13 || cleanPAN.length > 19) {
      throw new Error('Invalid PAN length');
    }

    // Извлечение 12 цифр PAN (без первой и последней цифры)
    const panDigits = cleanPAN.slice(1, -1).padStart(12, '0').slice(0, 12);

    // Формирование PIN блока Format 0
    // Формат: 0 + PIN Length + PIN + Fillers (F)
    const pinLength = pin.length;
    const paddedPIN = pin.padEnd(12, 'F');

    // XOR PAN и PIN для получения PIN блока
    let xorResult = '';
    for (let i = 0; i < 12; i++) {
      const panNibble = parseInt(panDigits[i], 16);
      const pinNibble = parseInt(paddedPIN[i], 16);
      const xorValue = panNibble ^ pinNibble;
      xorResult += xorValue.toString(16).toUpperCase();
    }

    // Добавление префикса формата (0) и длины PIN
    const pinBlock = '0' + pinLength.toString(16).toUpperCase() + xorResult;

    logger.debug('[SecurePIN] ISO-0 PIN Block created', {
      pinLength,
      panLast4: cleanPAN.slice(-4)
    });

    return pinBlock;
  }

  /**
   * Формирование PIN блока по ISO 9564 Format 1
   *
   * @param pin - PIN код
   * @param pan - PAN
   * @returns PIN Block Format 1
   */
  public createPINBlockISO1(pin: string, pan: string): string {
    if (!this.isInitialized) {
      throw new Error('SecurePIN not initialized');
    }

    const cleanPAN = pan.replace(/\D/g, '');
    const panDigits = cleanPAN.slice(1, -1).padStart(12, '0').slice(0, 12);

    // Format 1: 1 + PIN Length + PIN + Fillers (случайные)
    const pinLength = pin.length;
    const randomFiller = randomBytes(6 - Math.ceil(pinLength / 2))
      .toString('hex')
      .toUpperCase()
      .slice(0, 12 - pinLength);

    const pinData = pin + randomFiller;

    let xorResult = '';
    for (let i = 0; i < 12; i++) {
      const panNibble = parseInt(panDigits[i], 16);
      const pinNibble = parseInt(pinData[i] || '0', 16);
      const xorValue = panNibble ^ pinNibble;
      xorResult += xorValue.toString(16).toUpperCase();
    }

    return '1' + pinLength.toString(16).toUpperCase() + xorResult;
  }

  /**
   * Шифрование PIN блока
   *
   * @param pinBlock - PIN Block (hex string)
   * @param keyType - Тип ключа
   * @returns Зашифрованный PIN Block
   */
  public encryptPINBlock(
    pinBlock: string,
    keyType: 'TPK' | 'TMK' | 'ZPK' = 'TPK'
  ): string {
    if (!this.isInitialized) {
      throw new Error('SecurePIN not initialized');
    }

    // Выбор ключа
    let key: Buffer;
    switch (keyType) {
      case 'TPK':
        key = this.tpk!;
        break;
      case 'TMK':
      case 'ZPK':
        key = this.pinWorkingKey!;
        break;
      default:
        key = this.pinWorkingKey!;
    }

    // Преобразование PIN блока в Buffer
    const pinBlockBuffer = Buffer.from(pinBlock, 'hex');

    // Шифрование с использованием 3DES CBC
    const iv = Buffer.alloc(8, 0); // Null IV для PIN блоков
    const cipher = createCipheriv('des-ede3-cbc', key, iv);

    let encrypted = cipher.update(pinBlockBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const encryptedHex = encrypted.toString('hex').toUpperCase();

    logger.debug('[SecurePIN] PIN Block encrypted', {
      keyType,
      encryptedLength: encryptedHex.length
    });

    return encryptedHex;
  }

  /**
   * Дешифрование PIN блока
   *
   * @param encryptedPINBlock - Зашифрованный PIN Block
   * @param keyType - Тип ключа
   * @returns Дешифрованный PIN Block
   */
  public decryptPINBlock(
    encryptedPINBlock: string,
    keyType: 'TPK' | 'TMK' | 'ZPK' = 'TPK'
  ): string {
    if (!this.isInitialized) {
      throw new Error('SecurePIN not initialized');
    }

    let key: Buffer;
    switch (keyType) {
      case 'TPK':
        key = this.tpk!;
        break;
      case 'TMK':
      case 'ZPK':
        key = this.pinWorkingKey!;
        break;
      default:
        key = this.pinWorkingKey!;
    }

    const encryptedBuffer = Buffer.from(encryptedPINBlock, 'hex');
    const iv = Buffer.alloc(8, 0);

    const decipher = createDecipheriv('des-ede3-cbc', key, iv);
    let decrypted = decipher.update(encryptedBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString('hex').toUpperCase();
  }

  /**
   * Генерация PIN Verification Value (PVV)
   *
   * PVV используется для верификации PIN без его хранения
   *
   * @param pin - PIN код
   * @param pan - PAN
   * @param pvki - PVV Key Index (0-9)
   * @returns PVV (4 цифры)
   */
  public generatePVV(pin: string, pan: string, pvki: number = 0): string {
    if (!this.isInitialized) {
      throw new Error('SecurePIN not initialized');
    }

    if (pvki < 0 || pvki > 9) {
      throw new Error('PVKI must be between 0 and 9');
    }

    const cleanPAN = pan.replace(/\D/g, '');

    // Формирование данных для PVV
    // Формат: PVKI + PAN (без первой и последней цифры) + PIN
    const panData = cleanPAN.slice(1, -1).padEnd(11, '0').slice(0, 11);
    const pvvData = pvki.toString() + panData + pin;

    // Шифрование данных с использованием PIN Key
    const dataBuffer = Buffer.from(pvvData.padEnd(16, '0').slice(0, 16));
    const iv = Buffer.alloc(8, 0);
    const cipher = createCipheriv('des-ede3-cbc', this.pinWorkingKey!, iv);

    let encrypted = cipher.update(dataBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    // Извлечение PVV из зашифрованных данных
    const encryptedHex = encrypted.toString('hex');
    let pvv = '';
    let decimalCount = 0;

    for (let i = 0; i < encryptedHex.length && decimalCount < 4; i++) {
      const digit = parseInt(encryptedHex[i], 16);
      if (digit <= 9) {
        pvv += digit.toString();
        decimalCount++;
      }
    }

    // Если не хватило десятичных цифр, добавляем остальные
    while (pvv.length < 4) {
      const hexDigit = parseInt(encryptedHex[pvv.length], 16);
      pvv += (hexDigit % 10).toString();
    }

    logger.debug('[SecurePIN] PVV generated', {
      pvki,
      panLast4: cleanPAN.slice(-4)
    });

    return pvv;
  }

  /**
   * Верификация PIN через PVV
   *
   * @param pin - Введённый PIN
   * @param pvv - Ожидаемый PVV
   * @param pan - PAN
   * @param pvki - PVV Key Index
   * @returns Результат верификации
   */
  public verifyPINByPVV(
    pin: string,
    pvv: string,
    pan: string,
    pvki: number = 0
  ): {
    valid: boolean;
    generatedPVV: string;
  } {
    const generatedPVV = this.generatePVV(pin, pan, pvki);
    const valid = generatedPVV === pvv;

    logger.debug('[SecurePIN] PIN verification', {
      valid,
      pvki
    });

    if (!valid) {
      this.emit('pin_verification_failed', {
        pan: pan.slice(-4),
        timestamp: new Date()
      });
    }

    return {
      valid,
      generatedPVV
    };
  }

  /**
   * PIN Translation — конвертация PIN блока между ключами
   *
   * Используется при межбанковских операциях
   *
   * @param encryptedPINBlock - Зашифрованный PIN Block
   * @param fromKey - Исходный ключ
   * @param toKey - Целевой ключ
   * @returns Перезашифрованный PIN Block
   */
  public translatePINBlock(
    encryptedPINBlock: string,
    fromKey: 'TPK' | 'TMK',
    toKey: 'TPK' | 'TMK'
  ): string {
    if (!this.isInitialized) {
      throw new Error('SecurePIN not initialized');
    }

    // Дешифрование старым ключом
    const decryptedPINBlock = this.decryptPINBlock(encryptedPINBlock, fromKey);

    // Шифрование новым ключом
    const reencryptedPINBlock = this.encryptPINBlock(decryptedPINBlock, toKey);

    logger.info('[SecurePIN] PIN Block translated', {
      fromKey,
      toKey
    });

    return reencryptedPINBlock;
  }

  /**
   * Генерация случайного PIN для тестирования
   *
   * @param length - Длина PIN (4-12)
   * @returns Случайный PIN
   */
  public generateRandomPIN(length: number = 6): string {
    if (length < 4 || length > 12) {
      throw new Error('PIN length must be between 4 and 12');
    }

    let pin = '';
    for (let i = 0; i < length; i++) {
      pin += Math.floor(Math.random() * 10).toString();
    }

    // Гарантируем, что PIN не состоит из одинаковых цифр
    if (/^(\d)\1+$/.test(pin)) {
      return this.generateRandomPIN(length);
    }

    return pin;
  }

  /**
   * Проверка сложности PIN
   *
   * @param pin - PIN для проверки
   * @returns Результат проверки
   */
  public checkPINStrength(pin: string): {
    valid: boolean;
    weaknesses: string[];
  } {
    const weaknesses: string[] = [];

    // Проверка на простые паттерны
    if (/^(\d)\1+$/.test(pin)) {
      weaknesses.push('All digits are the same');
    }

    if (/^(0123456789)+/.test(pin) || /^(9876543210)+/.test(pin)) {
      weaknesses.push('Sequential digits');
    }

    if (/^(\d\d)\1+$/.test(pin)) {
      weaknesses.push('Repeating pattern');
    }

    // Проверка на распространённые PIN
    const commonPINs = ['1234', '1111', '0000', '1212', '7777', '1313', '123456', '654321'];
    if (commonPINs.includes(pin)) {
      weaknesses.push('Commonly used PIN');
    }

    // Проверка на дату (год)
    const yearPattern = /^(19|20)\d{2}$/;
    if (yearPattern.test(pin)) {
      weaknesses.push('Looks like a year');
    }

    return {
      valid: weaknesses.length === 0,
      weaknesses
    };
  }

  /**
   * Остановка сервиса
   */
  public async destroy(): Promise<void> {
    logger.info('[SecurePIN] Shutting down...');

    // Безопасное удаление ключей
    if (this.pinKek) {
      this.pinKek.fill(0);
    }

    if (this.pinWorkingKey) {
      this.pinWorkingKey.fill(0);
    }

    if (this.tpk) {
      this.tpk.fill(0);
    }

    this.isInitialized = false;

    logger.info('[SecurePIN] Destroyed');

    this.emit('destroyed');
  }

  /**
   * Получить статус сервиса
   */
  public getStatus(): {
    initialized: boolean;
    keysLoaded: boolean;
  } {
    return {
      initialized: this.isInitialized,
      keysLoaded: !!this.pinKek && !!this.pinWorkingKey && !!this.tpk
    };
  }
}
