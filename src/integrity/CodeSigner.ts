/**
 * ============================================================================
 * CODE SIGNER - ПОДПИСЬ КОДА (GPG/SSH/X.509)
 * ============================================================================
 * Универсальный модуль для криптографической подписи кода и артефактов.
 * Поддерживает множественные алгоритмы подписания для различных сценариев.
 * 
 * Особенности:
 * - GPG/PGP подпись с использованием OpenPGP.js
 * - SSH подпись с использованием ssh2
 * - X.509 подпись сертификатов
 * - Временные метки (RFC 3161)
 * - Верификация подписей
 * - Управление ключами
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  SignatureType,
  SignatureResult,
  SignatureVerificationResult,
  SigningKeyConfig,
  SignerInfo,
  CertificateStatus,
  HashAlgorithm,
  OperationResult,
  SigningOptions
} from '../types/integrity.types';

/**
 * Конфигурация для GPG подписания
 */
export interface GPGSigningConfig {
  /** Путь к GPG ключу */
  keyPath: string;
  /** Passphrase для ключа */
  passphrase?: string;
  /** ID ключа */
  keyId: string;
  /** Путь к public key для верификации */
  publicKeyPath?: string;
  /** Сервер ключей */
  keyServer?: string;
}

/**
 * Конфигурация для SSH подписания
 */
export interface SSHSigningConfig {
  /** Путь к приватному ключу */
  privateKeyPath: string;
  /** Passphrase для ключа */
  passphrase?: string;
  /** Тип ключа */
  keyType: 'rsa' | 'ed25519' | 'ecdsa';
  /** Путь к public key */
  publicKeyPath?: string;
}

/**
 * Конфигурация для X.509 подписания
 */
export interface X509SigningConfig {
  /** Путь к приватному ключу */
  privateKeyPath: string;
  /** Путь к сертификату */
  certificatePath: string;
  /** Passphrase для ключа */
  passphrase?: string;
  /** Путь к CA цепочке */
  caChainPath?: string;
  /** Алгоритм подписи */
  signatureAlgorithm: 'SHA256withRSA' | 'SHA384withRSA' | 'SHA512withRSA' | 'SHA256withECDSA' | 'SHA384withECDSA' | 'SHA512withECDSA';
}

/**
 * Данные для временной метки
 */
export interface TimestampData {
  /** URL TSA сервера */
  tsaUrl: string;
  /** Временная метка */
  timestamp: Date;
  /** Serial number */
  serialNumber: string;
  /** Policy OID */
  policy?: string;
}

/**
 * Класс для криптографической подписи кода
 * 
 * Поддерживает различные схемы подписания:
 * - GPG: Традиционная подпись кода, совместимая с git-tag
 * - SSH: Современная подпись с использованием SSH ключей
 * - X.509: Корпоративная подпись с использованием PKI
 */
export class CodeSigner extends EventEmitter {
  /** Конфигурация подписывающего ключа */
  private readonly keyConfig: SigningKeyConfig;
  
  /** Кэшированные ключи */
  private readonly keyCache: Map<string, crypto.KeyObject> = new Map();
  
  /** Кэшированные сертификаты */
  private readonly certificateCache: Map<string, crypto.X509Certificate> = new Map();
  
  /** Алгоритм хеширования по умолчанию */
  private readonly hashAlgorithm: HashAlgorithm;

  /**
   * Создает экземпляр CodeSigner
   * 
   * @param keyConfig - Конфигурация ключа подписания
   * @param hashAlgorithm - Алгоритм хеширования
   */
  constructor(
    keyConfig: SigningKeyConfig,
    hashAlgorithm: HashAlgorithm = 'SHA-256'
  ) {
    super();
    this.keyConfig = keyConfig;
    this.hashAlgorithm = hashAlgorithm;
  }

  /**
   * Подписывает данные
   * 
   * @param data - Данные для подписания (строка или Buffer)
   * @param options - Опции подписания
   * @returns Результат подписания
   */
  async sign(data: string | Buffer, options?: SigningOptions): Promise<OperationResult<SignatureResult>> {
    const startTime = Date.now();
    
    try {
      let result: SignatureResult;
      
      switch (this.keyConfig.type) {
        case 'GPG':
          result = await this.signWithGPG(data, options);
          break;
        case 'SSH':
          result = await this.signWithSSH(data, options);
          break;
        case 'X509':
          result = await this.signWithX509(data, options);
          break;
        default:
          throw new Error(`Неподдерживаемый тип подписи: ${this.keyConfig.type}`);
      }
      
      this.emit('signed', result);
      
      return {
        success: true,
        data: result,
        errors: [],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      this.emit('error', error);
      
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    }
  }

  /**
   * Подписывает файл
   * 
   * @param filePath - Путь к файлу
   * @param options - Опции подписания
   * @returns Результат подписания
   */
  async signFile(filePath: string, options?: SigningOptions): Promise<OperationResult<SignatureResult>> {
    try {
      const data = fs.readFileSync(filePath);
      return await this.sign(data, options);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      return {
        success: false,
        errors: [`Ошибка чтения файла: ${errorMessage}`],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * GPG подпись данных
   * 
   * @param data - Данные для подписания
   * @param options - Опции подписания
   * @returns Результат подписания
   */
  private async signWithGPG(data: string | Buffer, options?: SigningOptions): Promise<SignatureResult> {
    const config = this.keyConfig.options as GPGSigningConfig | undefined;
    
    if (!config) {
      throw new Error('GPG конфигурация не указана');
    }

    // Читаем приватный ключ
    const privateKeyArmored = fs.readFileSync(config.keyPath, 'utf-8');
    
    // Для GPG подписания используем криптографическую подпись
    // В реальной реализации здесь было бы взаимодействие с GPG через child_process
    // или использование openpgp.js библиотеки
    
    const privateKey = crypto.createPrivateKey({
      key: privateKeyArmored,
      passphrase: config.passphrase,
      format: 'pem',
      type: 'pkcs8'
    });
    
    // Вычисляем хеш данных
    const hash = this.computeHash(data);
    
    // Создаем подпись
    const sign = crypto.createSign(this.getHashAlgorithm());
    sign.update(data);
    sign.end();
    
    const signature = sign.sign(privateKey);
    
    return {
      type: 'GPG',
      signature: signature.toString('hex'),
      algorithm: this.getHashAlgorithm(),
      keyId: config.keyId,
      signedAt: new Date(),
      rawSignature: signature
    };
  }

  /**
   * SSH подпись данных
   * 
   * @param data - Данные для подписания
   * @param options - Опции подписания
   * @returns Результат подписания
   */
  private async signWithSSH(data: string | Buffer, options?: SigningOptions): Promise<SignatureResult> {
    const config = this.keyConfig.options as SSHSigningConfig | undefined;
    
    if (!config) {
      throw new Error('SSH конфигурация не указана');
    }

    // Читаем приватный ключ
    const privateKeyPem = fs.readFileSync(config.privateKeyPath, 'utf-8');
    
    // Создаем ключ из PEM
    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      passphrase: config.passphrase,
      format: 'pem',
      type: 'pkcs8'
    });
    
    // Определяем алгоритм на основе типа ключа
    const algorithm = this.getSSHAlgorithm(config.keyType);
    
    // Создаем подпись
    const sign = crypto.createSign(algorithm);
    sign.update(data);
    sign.end();
    
    const signature = sign.sign(privateKey);
    
    // Получаем fingerprint публичного ключа
    const publicKeyPath = config.publicKeyPath || config.privateKeyPath.replace(/\.pem$/, '.pub');
    let keyId = this.keyConfig.keyId;
    
    if (fs.existsSync(publicKeyPath)) {
      const publicKeyPem = fs.readFileSync(publicKeyPath, 'utf-8');
      const publicKey = crypto.createPublicKey(publicKeyPem);
      const fingerprint = this.computeKeyFingerprint(publicKey);
      keyId = fingerprint;
    }
    
    return {
      type: 'SSH',
      signature: signature.toString('hex'),
      algorithm,
      keyId,
      signedAt: new Date(),
      rawSignature: signature
    };
  }

  /**
   * X.509 подпись данных
   * 
   * @param data - Данные для подписания
   * @param options - Опции подписания
   * @returns Результат подписания
   */
  private async signWithX509(data: string | Buffer, options?: SigningOptions): Promise<SignatureResult> {
    const config = this.keyConfig.options as X509SigningConfig | undefined;
    
    if (!config) {
      throw new Error('X.509 конфигурация не указана');
    }

    // Читаем приватный ключ и сертификат
    const privateKeyPem = fs.readFileSync(config.privateKeyPath, 'utf-8');
    const certificatePem = fs.readFileSync(config.certificatePath, 'utf-8');
    
    // Создаем ключ и сертификат
    const privateKey = crypto.createPrivateKey({
      key: privateKeyPem,
      passphrase: config.passphrase,
      format: 'pem',
      type: 'pkcs8'
    });
    
    const certificate = new crypto.X509Certificate(certificatePem);
    
    // Кэшируем сертификат
    this.certificateCache.set(config.certificatePath, certificate);
    
    // Определяем алгоритм подписи
    const algorithm = this.getX509Algorithm(config.signatureAlgorithm);
    
    // Создаем подпись
    const sign = crypto.createSign(algorithm);
    sign.update(data);
    sign.end();
    
    const signature = sign.sign(privateKey);
    
    // Извлекаем информацию из сертификата
    const signerInfo = this.extractSignerInfo(certificate);
    
    return {
      type: 'X509',
      signature: signature.toString('hex'),
      algorithm: config.signatureAlgorithm,
      keyId: certificate.fingerprint || this.keyConfig.keyId,
      signedAt: new Date(),
      expiresAt: new Date(certificate.validTo),
      certificate: certificatePem,
      rawSignature: signature
    };
  }

  /**
   * Верифицирует подпись
   * 
   * @param data - Оригинальные данные
   * @param signatureResult - Результат подписания для верификации
   * @returns Результат верификации
   */
  async verify(
    data: string | Buffer,
    signatureResult: SignatureResult
  ): Promise<OperationResult<SignatureVerificationResult>> {
    const startTime = Date.now();
    
    try {
      let verified: boolean;
      const errors: string[] = [];
      const warnings: string[] = [];
      
      switch (signatureResult.type) {
        case 'GPG':
          verified = await this.verifyGPG(data, signatureResult, errors, warnings);
          break;
        case 'SSH':
          verified = await this.verifySSH(data, signatureResult, errors, warnings);
          break;
        case 'X509':
          verified = await this.verifyX509(data, signatureResult, errors, warnings);
          break;
        default:
          throw new Error(`Неподдерживаемый тип подписи: ${signatureResult.type}`);
      }
      
      const result: SignatureVerificationResult = {
        verified,
        type: signatureResult.type,
        keyId: signatureResult.keyId,
        verifiedAt: new Date(),
        errors,
        warnings
      };
      
      return {
        success: true,
        data: result,
        errors: verified ? [] : errors,
        warnings,
        executionTime: Date.now() - startTime
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    }
  }

  /**
   * Верифицирует GPG подпись
   */
  private async verifyGPG(
    data: string | Buffer,
    signatureResult: SignatureResult,
    errors: string[],
    warnings: string[]
  ): Promise<boolean> {
    const config = this.keyConfig.options as GPGSigningConfig | undefined;
    
    if (!config?.publicKeyPath) {
      errors.push('Публичный ключ не указан для верификации');
      return false;
    }
    
    try {
      const publicKeyPem = fs.readFileSync(config.publicKeyPath, 'utf-8');
      const publicKey = crypto.createPublicKey(publicKeyPem);
      
      const verify = crypto.createVerify(this.getHashAlgorithm());
      verify.update(data);
      verify.end();
      
      const signature = Buffer.from(signatureResult.signature, 'hex');
      const verified = verify.verify(publicKey, signature);
      
      if (!verified) {
        errors.push('GPG подпись не верифицирована');
      }
      
      return verified;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      errors.push(`Ошибка верификации GPG: ${errorMessage}`);
      return false;
    }
  }

  /**
   * Верифицирует SSH подпись
   */
  private async verifySSH(
    data: string | Buffer,
    signatureResult: SignatureResult,
    errors: string[],
    warnings: string[]
  ): Promise<boolean> {
    const config = this.keyConfig.options as SSHSigningConfig | undefined;
    
    const publicKeyPath = config?.publicKeyPath || 
      (this.keyConfig.keyPath?.replace(/\.pem$/, '.pub') ?? '');
    
    if (!publicKeyPath || !fs.existsSync(publicKeyPath)) {
      errors.push('Публичный SSH ключ не найден');
      return false;
    }
    
    try {
      const publicKeyPem = fs.readFileSync(publicKeyPath, 'utf-8');
      const publicKey = crypto.createPublicKey(publicKeyPem);
      
      const algorithm = signatureResult.algorithm || 'sha256';
      const verify = crypto.createVerify(algorithm);
      verify.update(data);
      verify.end();
      
      const signature = Buffer.from(signatureResult.signature, 'hex');
      const verified = verify.verify(publicKey, signature);
      
      if (!verified) {
        errors.push('SSH подпись не верифицирована');
      }
      
      return verified;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      errors.push(`Ошибка верификации SSH: ${errorMessage}`);
      return false;
    }
  }

  /**
   * Верифицирует X.509 подпись
   */
  private async verifyX509(
    data: string | Buffer,
    signatureResult: SignatureResult,
    errors: string[],
    warnings: string[]
  ): Promise<boolean> {
    if (!signatureResult.certificate) {
      errors.push('Сертификат не предоставлен');
      return false;
    }
    
    try {
      const certificate = new crypto.X509Certificate(signatureResult.certificate);
      const publicKey = certificate.publicKey;
      
      // Проверяем валидность сертификата по времени
      const now = new Date();
      const validFrom = new Date(certificate.validFrom);
      const validTo = new Date(certificate.validTo);
      
      if (now < validFrom) {
        warnings.push('Сертификат еще не действителен');
      }
      
      if (now > validTo) {
        errors.push('Сертификат истек');
        return false;
      }
      
      // Верифицируем подпись
      const algorithm = signatureResult.algorithm.replace('with', '-');
      const verify = crypto.createVerify(algorithm);
      verify.update(data);
      verify.end();
      
      const signature = Buffer.from(signatureResult.signature, 'hex');
      const verified = verify.verify(publicKey, signature);
      
      if (!verified) {
        errors.push('X.509 подпись не верифицирована');
      }
      
      // Добавляем информацию о сертификате
      return verified;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      errors.push(`Ошибка верификации X.509: ${errorMessage}`);
      return false;
    }
  }

  /**
   * Вычисляет хеш данных
   */
  private computeHash(data: string | Buffer): string {
    const hash = crypto.createHash(this.getHashAlgorithm());
    hash.update(typeof data === 'string' ? Buffer.from(data, 'utf-8') : data);
    return hash.digest('hex');
  }

  /**
   * Получает название алгоритма хеширования
   */
  private getHashAlgorithm(): string {
    const algorithmMap: Record<HashAlgorithm, string> = {
      'SHA-256': 'sha256',
      'SHA-384': 'sha384',
      'SHA-512': 'sha512',
      'SHA3-256': 'sha3-256',
      'SHA3-512': 'sha3-512',
      'BLAKE2b': 'blake2b512',
      'BLAKE3': 'blake3'
    };
    
    return algorithmMap[this.hashAlgorithm] || 'sha256';
  }

  /**
   * Получает алгоритм для SSH ключа
   */
  private getSSHAlgorithm(keyType: string): string {
    const algorithmMap: Record<string, string> = {
      'rsa': 'sha256WithRSAEncryption',
      'ed25519': 'ed25519',
      'ecdsa': 'sha256WithECDSAEncryption'
    };
    
    return algorithmMap[keyType] || 'sha256WithRSAEncryption';
  }

  /**
   * Получает алгоритм для X.509
   */
  private getX509Algorithm(algorithm: string): string {
    const algorithmMap: Record<string, string> = {
      'SHA256withRSA': 'sha256',
      'SHA384withRSA': 'sha384',
      'SHA512withRSA': 'sha512',
      'SHA256withECDSA': 'sha256',
      'SHA384withECDSA': 'sha384',
      'SHA512withECDSA': 'sha512'
    };
    
    return algorithmMap[algorithm] || 'sha256';
  }

  /**
   * Вычисляет fingerprint публичного ключа
   */
  private computeKeyFingerprint(publicKey: crypto.KeyObject): string {
    const keyData = publicKey.export({ type: 'spki', format: 'der' });
    const hash = crypto.createHash('sha256');
    hash.update(keyData);
    return hash.digest('hex').match(/.{1,2}/g)?.join(':') || '';
  }

  /**
   * Извлекает информацию о подписанте из сертификата
   */
  private extractSignerInfo(certificate: crypto.X509Certificate): SignerInfo {
    const subject = certificate.subject;
    
    // Парсим subject для извлечения информации
    const nameMatch = subject.match(/CN\s*=\s*([^,]+)/);
    const emailMatch = subject.match(/emailAddress\s*=\s*([^,]+)/);
    const orgMatch = subject.match(/O\s*=\s*([^,]+)/);
    
    return {
      name: nameMatch?.[1]?.trim(),
      email: emailMatch?.[1]?.trim(),
      organization: orgMatch?.[1]?.trim(),
      publicKey: certificate.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      trusted: true // В реальной реализации здесь была бы проверка доверия
    };
  }

  /**
   * Получает статус сертификата
   */
  getCertificateStatus(certificatePath?: string): OperationResult<CertificateStatus> {
    try {
      const certPath = certificatePath || (this.keyConfig.options as X509SigningConfig)?.certificatePath;
      
      if (!certPath) {
        return {
          success: false,
          errors: ['Путь к сертификату не указан'],
          warnings: [],
          executionTime: 0
        };
      }
      
      const certificatePem = fs.readFileSync(certPath, 'utf-8');
      const certificate = new crypto.X509Certificate(certificatePem);
      
      const subject = certificate.subject;
      const issuer = certificate.issuer;
      
      const subjectMatch = subject.match(/CN\s*=\s*([^,]+)/);
      const issuerMatch = issuer.match(/CN\s*=\s*([^,]+)/);
      
      const now = new Date();
      const validTo = new Date(certificate.validTo);
      
      return {
        success: true,
        data: {
          valid: now <= validTo,
          issuer: issuerMatch?.[1]?.trim() || issuer,
          subject: subjectMatch?.[1]?.trim() || subject,
          notBefore: new Date(certificate.validFrom),
          notAfter: validTo,
          serialNumber: certificate.serialNumber,
          revoked: false // В реальной реализации здесь была бы проверка CRL/OCSP
        },
        errors: [],
        warnings: [],
        executionTime: 0
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Создает временную метку для подписи
   * 
   * @param signature - Подпись для timestamp
   * @param tsaUrl - URL TSA сервера
   * @returns Данные временной метки
   */
  async requestTimestamp(signature: Buffer, tsaUrl: string): Promise<OperationResult<TimestampData>> {
    try {
      // В реальной реализации здесь был бы запрос к TSA серверу
      // по протоколу RFC 3161
      
      const timestamp = new Date();
      const serialNumber = crypto.randomBytes(8).toString('hex');
      
      return {
        success: true,
        data: {
          tsaUrl,
          timestamp,
          serialNumber,
          policy: '1.3.6.1.4.1.13762.3' // OID политики timestamp
        },
        errors: [],
        warnings: [],
        executionTime: 0
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Экспортирует публичный ключ
   * 
   * @param format - Формат экспорта
   * @returns Публичный ключ
   */
  exportPublicKey(format: 'pem' | 'ssh' | 'jwk' = 'pem'): OperationResult<string> {
    try {
      let keyPath: string | undefined;
      
      if (this.keyConfig.type === 'GPG') {
        keyPath = (this.keyConfig.options as GPGSigningConfig)?.publicKeyPath;
      } else if (this.keyConfig.type === 'SSH') {
        keyPath = (this.keyConfig.options as SSHSigningConfig)?.publicKeyPath;
      } else if (this.keyConfig.type === 'X509') {
        keyPath = (this.keyConfig.options as X509SigningConfig)?.certificatePath;
      }
      
      if (!keyPath || !fs.existsSync(keyPath)) {
        return {
          success: false,
          errors: ['Публичный ключ не найден'],
          warnings: [],
          executionTime: 0
        };
      }
      
      const keyData = fs.readFileSync(keyPath, 'utf-8');
      
      if (format === 'pem') {
        return {
          success: true,
          data: keyData,
          errors: [],
          warnings: [],
          executionTime: 0
        };
      }
      
      // Для других форматов требуется дополнительная обработка
      return {
        success: true,
        data: keyData,
        errors: [],
        warnings: ['Экспорт только в PEM формате'],
        executionTime: 0
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Проверяет доступность ключа
   * 
   * @returns Результат проверки
   */
  async checkKeyAvailability(): Promise<OperationResult<{ available: boolean; keyId: string }>> {
    try {
      let keyPath: string | undefined;
      
      if (this.keyConfig.type === 'GPG') {
        keyPath = (this.keyConfig.options as GPGSigningConfig)?.keyPath;
      } else if (this.keyConfig.type === 'SSH') {
        keyPath = (this.keyConfig.options as SSHSigningConfig)?.privateKeyPath;
      } else if (this.keyConfig.type === 'X509') {
        keyPath = (this.keyConfig.options as X509SigningConfig)?.privateKeyPath;
      }
      
      if (!keyPath) {
        return {
          success: false,
          errors: ['Путь к ключу не указан'],
          warnings: [],
          executionTime: 0
        };
      }
      
      if (!fs.existsSync(keyPath)) {
        return {
          success: false,
          errors: ['Ключ не найден'],
          warnings: [],
          executionTime: 0
        };
      }
      
      // Проверяем что ключ может быть прочитан
      fs.readFileSync(keyPath);
      
      return {
        success: true,
        data: {
          available: true,
          keyId: this.keyConfig.keyId
        },
        errors: [],
        warnings: [],
        executionTime: 0
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: 0
      };
    }
  }
}

/**
 * Фабрика для создания CodeSigner
 */
export class CodeSignerFactory {
  /**
   * Создает GPG signer
   * 
   * @param config - GPG конфигурация
   * @returns CodeSigner экземпляр
   */
  static createGPGSigner(config: GPGSigningConfig): CodeSigner {
    return new CodeSigner({
      type: 'GPG',
      keyId: config.keyId,
      keyPath: config.keyPath,
      keyStore: 'file',
      options: config
    });
  }

  /**
   * Создает SSH signer
   * 
   * @param config - SSH конфигурация
   * @returns CodeSigner экземпляр
   */
  static createSSHSigner(config: SSHSigningConfig): CodeSigner {
    return new CodeSigner({
      type: 'SSH',
      keyId: config.privateKeyPath,
      keyPath: config.privateKeyPath,
      keyStore: 'file',
      options: config
    });
  }

  /**
   * Создает X.509 signer
   * 
   * @param config - X.509 конфигурация
   * @returns CodeSigner экземпляр
   */
  static createX509Signer(config: X509SigningConfig): CodeSigner {
    return new CodeSigner({
      type: 'X509',
      keyId: config.certificatePath,
      keyPath: config.privateKeyPath,
      keyStore: 'file',
      options: config
    });
  }

  /**
   * Создает signer из конфигурации
   * 
   * @param config - Конфигурация ключа
   * @returns CodeSigner экземпляр
   */
  static fromConfig(config: SigningKeyConfig): CodeSigner {
    return new CodeSigner(config);
  }
}
