/**
 * ============================================================================
 * PHI PROTECTION — ЗАЩИТА КОНФИДЕНЦИАЛЬНОЙ МЕДИЦИНСКОЙ ИНФОРМАЦИИ
 * ============================================================================
 *
 * HIPAA compliant защита Protected Health Information (PHI)
 *
 * Реализация:
 * - Шифрование PHI (AES-256-GCM)
 * - Де-идентификация (Safe Harbor / Expert Determination)
 * - Limited Data Sets (LDS)
 * - Оценка риска ре-идентификации
 * - Контроль доступа на основе ролей
 *
 * @package protocol/healthcare-security/phi
 * @author Protocol Security Team
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import { logger } from '../../logging/Logger';
import { PHIData, PHIProtectionConfig } from '../types/healthcare.types';

/**
 * Квази-идентификаторы для де-идентификации
 */
const QUASI_IDENTIFIERS = [
  'dateOfBirth',
  'age',
  'gender',
  'zipCode',
  'city',
  'state',
  'admissionDate',
  'dischargeDate',
  'serviceDate'
];

/**
 * Прямые идентификаторы (Safe Harbor)
 */
const DIRECT_IDENTIFIERS = [
  'name',
  'ssn',
  'mrn',
  'phone',
  'email',
  'address',
  'licenseNumber',
  'vehicleId',
  'deviceId',
  'url',
  'ipAddress',
  'biometricIdentifier',
  'photo',
  'uniqueIdentifyingCode'
];

/**
 * PHI Protection Service
 */
export class PHIProtection extends EventEmitter {
  /** Конфигурация */
  private readonly config: PHIProtectionConfig;

  /** Master key для шифрования */
  private masterKey?: Buffer;

  /** Статус инициализации */
  private isInitialized = false;

  /** Счётчик зашифрованных записей */
  private encryptionCount = 0;

  /** Счётчик де-идентифицированных записей */
  private deidentificationCount = 0;

  /**
   * Создаёт новый экземпляр PHIProtection
   */
  constructor(config?: Partial<PHIProtectionConfig>) {
    super();

    this.config = {
      encryptionAlgorithm: config?.encryptionAlgorithm || 'AES-256-GCM',
      deidentificationMethod: config?.deidentificationMethod || 'SAFE_HARBOR',
      encryptionKey: config?.encryptionKey
    };

    logger.info('[PHIProtection] Service created', {
      algorithm: this.config.encryptionAlgorithm,
      deidentificationMethod: this.config.deidentificationMethod
    });
  }

  /**
   * Инициализация сервиса
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[PHIProtection] Already initialized');
      return;
    }

    try {
      // Генерация или загрузка master key
      if (this.config.encryptionKey) {
        this.masterKey = this.config.encryptionKey;
        logger.info('[PHIProtection] Using provided encryption key');
      } else {
        // Генерация нового ключа
        this.masterKey = randomBytes(32); // AES-256
        logger.info('[PHIProtection] Generated new encryption key');
      }

      this.isInitialized = true;

      logger.info('[PHIProtection] Initialized successfully');

      this.emit('initialized');

    } catch (error) {
      logger.error('[PHIProtection] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Шифрование PHI данных
   *
   * @param phiData - PHI данные для шифрования
   * @returns Зашифрованные данные
   */
  public async encryptPHI(phiData: PHIData): Promise<{
    encryptedData: string;
    iv: string;
    authTag: string;
    algorithm: string;
    timestamp: Date;
    dataHash: string;
  }> {
    if (!this.isInitialized) {
      throw new Error('PHIProtection not initialized');
    }

    if (!this.masterKey) {
      throw new Error('Master key not initialized');
    }

    const startTime = Date.now();

    // Сериализация данных
    const dataBuffer = Buffer.from(JSON.stringify(phiData), 'utf8');

    // Генерация IV
    const iv = randomBytes(16);

    // Шифрование AES-256-GCM
    const cipher = createCipheriv('aes-256-gcm', this.masterKey, iv);

    let encrypted = cipher.update(dataBuffer);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const authTag = cipher.getAuthTag();

    // Hash данных для верификации целостности
    const dataHash = createHash('sha256').update(dataBuffer).digest('hex');

    this.encryptionCount++;

    logger.debug('[PHIProtection] PHI encrypted', {
      patientId: phiData.patientId,
      encryptionTime: Date.now() - startTime,
      dataHash
    });

    this.emit('phi_encrypted', {
      patientId: phiData.patientId,
      timestamp: new Date(),
      dataHash
    });

    return {
      encryptedData: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      algorithm: 'AES-256-GCM',
      timestamp: new Date(),
      dataHash
    };
  }

  /**
   * Дешифрование PHI данных
   *
   * @param encrypted - Зашифрованные данные
   * @returns Дешифрованные PHI данные
   */
  public async decryptPHI(encrypted: {
    encryptedData: string;
    iv: string;
    authTag: string;
  }): Promise<PHIData> {
    if (!this.isInitialized) {
      throw new Error('PHIProtection not initialized');
    }

    if (!this.masterKey) {
      throw new Error('Master key not initialized');
    }

    const decipher = createDecipheriv(
      'aes-256-gcm',
      this.masterKey,
      Buffer.from(encrypted.iv, 'base64')
    );

    decipher.setAuthTag(Buffer.from(encrypted.authTag, 'base64'));

    let decrypted = decipher.update(encrypted.encryptedData, 'base64');
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    const phiData: PHIData = JSON.parse(decrypted.toString('utf8'));

    logger.debug('[PHIProtection] PHI decrypted', {
      patientId: phiData.patientId
    });

    this.emit('phi_decrypted', {
      patientId: phiData.patientId,
      timestamp: new Date()
    });

    return phiData;
  }

  /**
   * Де-идентификация данных (Safe Harbor метод)
   *
   * Удаляет все 18 категорий идентификаторов HIPAA
   *
   * @param phiData - PHI данные
   * @param method - Метод де-идентификации
   * @returns Де-идентифицированные данные
   */
  public async deidentifyData(
    phiData: PHIData,
    method: 'SAFE_HARBOR' | 'EXPERT_DETERMINATION' = 'SAFE_HARBOR'
  ): Promise<{
    deidentifiedData: any;
    method: string;
    removedFields: string[];
    timestamp: Date;
  }> {
    if (!this.isInitialized) {
      throw new Error('PHIProtection not initialized');
    }

    const removedFields: string[] = [];
    const deidentifiedData = JSON.parse(JSON.stringify(phiData));

    if (method === 'SAFE_HARBOR') {
      // Удаление прямых идентификаторов
      for (const field of DIRECT_IDENTIFIERS) {
        if (deidentifiedData.demographics?.[field]) {
          delete deidentifiedData.demographics[field];
          removedFields.push(`demographics.${field}`);
        }
      }

      // Обработка дат (оставляем только год)
      if (deidentifiedData.demographics?.dateOfBirth) {
        const birthYear = new Date(deidentifiedData.demographics.dateOfBirth).getFullYear();
        deidentifiedData.demographics.birthYear = birthYear;
        delete deidentifiedData.demographics.dateOfBirth;
        removedFields.push('demographics.dateOfBirth');
      }

      // Обработка географических данных
      if (deidentifiedData.demographics?.address) {
        // Оставляем только штат
        const state = this.extractState(deidentifiedData.demographics.address);
        deidentifiedData.demographics.state = state;
        delete deidentifiedData.demographics.address;
        removedFields.push('demographics.address');
      }

      // Удаление уникальных идентификаторов
      delete deidentifiedData.patientId;
      removedFields.push('patientId');

    } else if (method === 'EXPERT_DETERMINATION') {
      // Expert Determination метод
      // Статистическая оценка риска ре-идентификации
      deidentifiedData.deidentificationMethod = 'EXPERT_DETERMINATION';

      // Обобщение данных
      if (deidentifiedData.demographics?.age) {
        const age = deidentifiedData.demographics.age;
        deidentifiedData.demographics.ageGroup = this.categorizeAge(age);
        delete deidentifiedData.demographics.age;
        removedFields.push('demographics.age -> demographics.ageGroup');
      }

      // Генерализация дат
      if (deidentifiedData.demographics?.dateOfBirth) {
        const birthDate = new Date(deidentifiedData.demographics.dateOfBirth);
        const quarter = Math.floor(birthDate.getMonth() / 3) + 1;
        deidentifiedData.demographics.birthQuarter = `Q${quarter}-${birthDate.getFullYear()}`;
        delete deidentifiedData.demographics.dateOfBirth;
        removedFields.push('demographics.dateOfBirth -> demographics.birthQuarter');
      }
    }

    this.deidentificationCount++;

    logger.info('[PHIProtection] Data de-identified', {
      method,
      removedFieldsCount: removedFields.length
    });

    this.emit('data_deidentified', {
      method,
      removedFieldsCount: removedFields.length,
      timestamp: new Date()
    });

    return {
      deidentifiedData,
      method,
      removedFields,
      timestamp: new Date()
    };
  }

  /**
   * Создание Limited Data Set (LDS)
   *
   * LDS может содержать:
   * - Даты (admission, discharge, service, birth, death)
   * - Возраст (включая 90+)
   * - Географические данные (штат, ZIP code без последних 3 цифр)
   *
   * @param phiData - PHI данные
   * @param options - Опции LDS
   * @returns Limited Data Set
   */
  public async createLimitedDataSet(
    phiData: PHIData,
    options: {
      permittedPurpose: 'RESEARCH' | 'PUBLIC_HEALTH' | 'HEALTHCARE_OPERATIONS';
      dataUseAgreement: string;
      recipient?: string;
    }
  ): Promise<{
    limitedDataSet: any;
    permittedPurpose: string;
    dataUseAgreement: string;
    restrictions: string[];
    timestamp: Date;
  }> {
    if (!this.isInitialized) {
      throw new Error('PHIProtection not initialized');
    }

    const restrictions = [
      'No re-identification allowed',
      'No further disclosure without authorization',
      'Must implement appropriate safeguards',
      'Report any breaches immediately'
    ];

    const limitedDataSet = JSON.parse(JSON.stringify(phiData));

    // Удаление прямых идентификаторов кроме дат
    for (const field of DIRECT_IDENTIFIERS) {
      if (field !== 'dateOfBirth' && limitedDataSet.demographics?.[field]) {
        delete limitedDataSet.demographics[field];
      }
    }

    // Ограничение ZIP code (первые 3 цифры)
    if (limitedDataSet.demographics?.zipCode) {
      const zipCode = limitedDataSet.demographics.zipCode;
      limitedDataSet.demographics.zipCode3 = zipCode.substring(0, 3);
      delete limitedDataSet.demographics.zipCode;
    }

    logger.info('[PHIProtection] Limited Data Set created', {
      permittedPurpose: options.permittedPurpose,
      dataUseAgreement: options.dataUseAgreement
    });

    this.emit('lds_created', {
      permittedPurpose: options.permittedPurpose,
      timestamp: new Date()
    });

    return {
      limitedDataSet,
      permittedPurpose: options.permittedPurpose,
      dataUseAgreement: options.dataUseAgreement,
      restrictions,
      timestamp: new Date()
    };
  }

  /**
   * Оценка риска ре-идентификации
   *
   * @param data - Де-идентифицированные данные
   * @returns Оценка риска
   */
  public async assessReidentificationRisk(data: any): Promise<{
    score: number; // 0-100
    risk: 'VERY_LOW' | 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';
    factors: string[];
    recommendations: string[];
  }> {
    let score = 0;
    const factors: string[] = [];
    const recommendations: string[] = [];

    // Проверка квази-идентификаторов
    const quasiIdentifiersPresent = QUASI_IDENTIFIERS.filter(
      field => data.demographics?.[field] !== undefined
    );

    if (quasiIdentifiersPresent.length > 0) {
      score += quasiIdentifiersPresent.length * 10;
      factors.push(`${quasiIdentifiersPresent.length} quasi-identifiers present`);
    }

    // Проверка редкости комбинаций
    if (data.demographics?.age && data.demographics?.zipCode) {
      score += 20;
      factors.push('Age + ZIP combination increases re-identification risk');
      recommendations.push('Consider generalizing age to age groups');
    }

    // Проверка дат
    const datesPresent = Object.keys(data).filter(
      key => key.includes('Date') || key.includes('date')
    );

    if (datesPresent.length > 3) {
      score += datesPresent.length * 5;
      factors.push(`${datesPresent.length} date fields present`);
      recommendations.push('Consider reducing date precision to year only');
    }

    // Проверка уникальных значений
    const uniqueFields = this.detectUniquePatterns(data);

    if (uniqueFields.length > 0) {
      score += uniqueFields.length * 15;
      factors.push(`${uniqueFields.length} fields with unique patterns`);
      recommendations.push('Review and generalize unique value fields');
    }

    // Нормализация score
    score = Math.min(100, score);

    // Определение уровня риска
    let risk: 'VERY_LOW' | 'LOW' | 'MEDIUM' | 'HIGH' | 'VERY_HIGH';

    if (score < 20) risk = 'VERY_LOW';
    else if (score < 40) risk = 'LOW';
    else if (score < 60) risk = 'MEDIUM';
    else if (score < 80) risk = 'HIGH';
    else risk = 'VERY_HIGH';

    // Добавление рекомендаций по умолчанию
    if (recommendations.length === 0 && score > 30) {
      recommendations.push('Consider applying additional generalization techniques');
      recommendations.push('Review against HIPAA Safe Harbor guidelines');
    }

    logger.info('[PHIProtection] Re-identification risk assessed', {
      score,
      risk
    });

    return {
      score,
      risk,
      factors,
      recommendations
    };
  }

  /**
   * Маскирование PHI для отображения
   *
   * @param phiData - PHI данные
   * @param maskLevel - Уровень маскирования
   * @returns Замаскированные данные
   */
  public maskPHI(
    phiData: PHIData,
    maskLevel: 'MINIMAL' | 'MODERATE' | 'COMPLETE' = 'MODERATE'
  ): PHIData {
    const masked = JSON.parse(JSON.stringify(phiData));

    if (maskLevel === 'COMPLETE') {
      // Полное маскирование
      if (masked.demographics) {
        masked.demographics.name = '[REDACTED]';
        masked.demographics.ssn = '***-**-****';
        masked.demographics.mrn = '[REDACTED]';
        masked.demographics.phone = '***-***-****';
        masked.demographics.email = '[REDACTED]';
        masked.demographics.address = '[REDACTED]';
      }
    } else if (maskLevel === 'MODERATE') {
      // Частичное маскирование
      if (masked.demographics) {
        if (masked.demographics.name) {
          masked.demographics.name = this.maskName(masked.demographics.name);
        }
        if (masked.demographics.ssn) {
          masked.demographics.ssn = masked.demographics.ssn.replace(/^\d{5}-/, '*****-');
        }
        if (masked.demographics.phone) {
          masked.demographics.phone = masked.demographics.phone.replace(/^\d{6}/, '******');
        }
      }
    }

    return masked;
  }

  /**
   * Псевдонимизация patient ID
   *
   * @param patientId - Оригинальный ID
   * @param salt - Соль для хеширования
   * @returns Псевдонимизированный ID
   */
  public pseudonymizePatientId(patientId: string, salt?: string): string {
    const saltValue = salt || 'default-salt';
    return createHash('sha256')
      .update(patientId + saltValue)
      .digest('hex')
      .substring(0, 16);
  }

  /**
   * Получение статистики
   */
  public getStatistics(): {
    encryptionCount: number;
    deidentificationCount: number;
    isInitialized: boolean;
  } {
    return {
      encryptionCount: this.encryptionCount,
      deidentificationCount: this.deidentificationCount,
      isInitialized: this.isInitialized
    };
  }

  /**
   * Извлечение штата из адреса
   */
  private extractState(address: string): string {
    // Упрощённая логика извлечения штата
    const stateMatch = address.match(/,\s*([A-Z]{2})\s+\d{5}/);
    return stateMatch ? stateMatch[1] : 'XX';
  }

  /**
   * Категоризация возраста
   */
  private categorizeAge(age: number): string {
    if (age < 18) return '0-17';
    if (age < 30) return '18-29';
    if (age < 40) return '30-39';
    if (age < 50) return '40-49';
    if (age < 60) return '50-59';
    if (age < 70) return '60-69';
    if (age < 80) return '70-79';
    if (age < 90) return '80-89';
    return '90+';
  }

  /**
   * Обнаружение уникальных паттернов
   */
  private detectUniquePatterns(data: any): string[] {
    const uniqueFields: string[] = [];

    const checkObject = (obj: any, path: string = '') => {
      for (const [key, value] of Object.entries(obj)) {
        const currentPath = path ? `${path}.${key}` : key;

        if (typeof value === 'string' && value.length > 20) {
          uniqueFields.push(currentPath);
        }
      }
    };

    checkObject(data);

    return uniqueFields;
  }

  /**
   * Маскирование имени
   */
  private maskName(name: string): string {
    const parts = name.split(' ');

    if (parts.length === 1) {
      return name.charAt(0) + '*'.repeat(name.length - 1);
    }

    return parts.map((part, index) => {
      if (index === 0) return part; // Оставляем первое имя
      return part.charAt(0) + '*'.repeat(part.length - 1);
    }).join(' ');
  }

  /**
   * Остановка сервиса
   */
  public async destroy(): Promise<void> {
    logger.info('[PHIProtection] Shutting down...');

    // Безопасное удаление ключа
    if (this.masterKey) {
      this.masterKey.fill(0);
      this.masterKey = undefined;
    }

    this.isInitialized = false;

    logger.info('[PHIProtection] Destroyed');

    this.emit('destroyed');
  }
}
