/**
 * =============================================================================
 * WEBAUTHN / FIDO2 SERVICE
 * =============================================================================
 * Сервис для работы с WebAuthn / FIDO2 аутентификацией
 * Соответствует: W3C Web Authentication API Level 2, FIDO2 specifications
 * Поддерживает: Registration, Authentication, Attestation, Resident Keys
 * =============================================================================
 */

import {
  // Registration
  generateRegistrationOptions,
  verifyRegistrationResponse,
  // Authentication
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  // Types
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
  // Settings
  AuthenticatorTransportFuture,
  WebAuthnCredential,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../logging/Logger';
import {
  IWebAuthnMethod,
  IUser,
  AuthError,
  AuthErrorCode,
  MfaMethodStatus,
} from '../types/auth.types';

/**
 * Типы аутентификаторов
 */
export type AuthenticatorType = 'platform' | 'roaming';

/**
 * Конфигурация WebAuthn сервиса
 */
export interface WebAuthnServiceConfig {
  /** Имя приложения (relying party name) */
  rpName: string;
  
  /** ID приложения (relying party id) */
  rpID: string;
  
  /** URL приложения (origin) */
  origin: string;
  
  /** Требовать resident key */
  requireResidentKey: boolean;
  
  /** Требовать user verification */
  requireUserVerification: boolean;

  /** Предпочтительная аутентификация */
  authenticatorAttachment: AuthenticatorType | 'cross-platform' | 'platform';

  /** Таймаут операций (мс) */
  timeout: number;

  /** Аттестация: 'none', 'direct', 'enterprise' */
  attestationType: 'none' | 'direct' | 'enterprise';
  
  /** Разрешенные алгоритмы */
  supportedAlgorithmIDs: number[];
}

/**
 * Конфигурация по умолчанию
 * Соответствует FIDO2 Best Practices
 */
const DEFAULT_CONFIG: WebAuthnServiceConfig = {
  rpName: 'Protocol Messenger',
  rpID: 'localhost',
  origin: 'http://localhost:3000',
  requireResidentKey: false,
  requireUserVerification: true,
  authenticatorAttachment: 'platform',
  timeout: 60000, // 1 минута
  attestationType: 'direct',
  // Поддерживаемые алгоритмы (по приоритету)
  supportedAlgorithmIDs: [
    -8, // EdDSA
    -257, // RS256
    -7, // ES256
    -258, // ES384
    -259, // ES512
    -37, // PS256
    -38, // PS384
    -39, // PS512
  ],
};

/**
 * Результат генерации options для регистрации
 */
export interface RegistrationOptionsResult {
  /** Options для клиента */
  options: PublicKeyCredentialCreationOptionsJSON;
  /** Challenge для верификации */
  challenge: string;
  /** Временный ID для хранения состояния */
  temporaryId: string;
}

/**
 * Результат регистрации
 */
export interface RegistrationResult {
  /** Успешна ли регистрация */
  success: boolean;
  /** WebAuthn метод (если успешно) */
  webAuthnMethod?: IWebAuthnMethod;
  /** Ошибка (если есть) */
  error?: string;
  /** Информация об аутентификаторе */
  authenticatorInfo?: {
    aaguid: string;
    name: string;
    type: AuthenticatorType;
  };
}

/**
 * Результат генерации options для аутентификации
 */
export interface AuthenticationOptionsResult {
  /** Options для клиента */
  options: PublicKeyCredentialRequestOptionsJSON;
  /** Challenge для верификации */
  challenge: string;
  /** Временный ID для хранения состояния */
  temporaryId: string;
}

/**
 * Результат аутентификации
 */
export interface AuthenticationResult {
  /** Успешна ли аутентификация */
  success: boolean;
  /** ID пользователя (если успешно) */
  userId?: string;
  /** Обновленный счетчик */
  newCounter?: number;
  /** Ошибка (если есть) */
  error?: string;
  /** Информация об аутентификации */
  authInfo?: {
    userVerified: boolean;
    userPresent: boolean;
    backupEligible: boolean;
    backupState: boolean;
  };
}

/**
 * Хранилище challenge (в памяти для примера, в production использовать Redis)
 */
interface ChallengeStore {
  challenge: string;
  userId?: string;
  credentialId?: string;
  createdAt: number;
  expiresAt: number;
}

/**
 * =============================================================================
 * WEBAUTHN SERVICE CLASS
 * =============================================================================
 */
export class WebAuthnService {
  private config: WebAuthnServiceConfig;
  private challengeStore: Map<string, ChallengeStore> = new Map();
  private readonly challengeTimeout: number = 5 * 60 * 1000; // 5 минут

  /**
   * Создает новый экземпляр WebAuthnService
   * @param config - Конфигурация сервиса
   */
  constructor(config: WebAuthnServiceConfig = DEFAULT_CONFIG) {
    this.config = config;
    
    // Очистка старых challenge каждые 10 минут
    setInterval(() => this.cleanupChallenges(), 10 * 60 * 1000);
  }

  // ===========================================================================
  // РЕГИСТРАЦИЯ (REGISTRATION)
  // ===========================================================================

  /**
   * Генерирует options для регистрации нового ключа
   * @param user - Пользователь
   * @param existingCredentials - Существующие ключи пользователя
   * @returns Options для клиента
   */
  public async generateRegistrationOptions(
    user: Pick<IUser, 'id' | 'username' | 'email'>,
    existingCredentials: Pick<IWebAuthnMethod, 'credentialId' | 'transports'>[] = []
  ): Promise<RegistrationOptionsResult> {
    try {
      // Генерация challenge
      const challenge = isoBase64URL.fromBuffer(
        crypto.getRandomValues(new Uint8Array(32))
      );

      // Сохранение challenge
      const temporaryId = uuidv4();
      this.challengeStore.set(temporaryId, {
        challenge,
        userId: user.id,
        createdAt: Date.now(),
        expiresAt: Date.now() + this.challengeTimeout,
      });

      // Преобразование существующих credentials
      const excludeCredentials = existingCredentials.map(cred => ({
        id: cred.credentialId,
        type: 'public-key' as const,
        transports: cred.transports as AuthenticatorTransportFuture[],
      }));

      // Генерация options
      const options = await generateRegistrationOptions({
        rpName: this.config.rpName,
        rpID: this.config.rpID,
        userID: isoBase64URL.toBuffer(user.id),
        userName: user.username || user.email,
        userDisplayName: user.username || user.email,
        challenge,
        attestationType: this.config.attestationType,
        excludeCredentials,
        authenticatorSelection: {
          residentKey: this.config.requireResidentKey ? 'required' : 'preferred',
          userVerification: this.config.requireUserVerification ? 'required' : 'preferred',
          authenticatorAttachment: this.config.authenticatorAttachment === 'platform' 
            ? 'platform' 
            : 'cross-platform',
        },
        supportedAlgorithmIDs: this.config.supportedAlgorithmIDs,
        timeout: this.config.timeout,
      });

      return {
        options,
        challenge,
        temporaryId,
      };
    } catch (error) {
      throw new AuthError(
        `Ошибка генерации options для регистрации: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Верифицирует ответ на регистрацию
   * @param response - Ответ от клиента
   * @param temporaryId - Временный ID challenge
   * @param expectedOrigin - Ожидаемый origin
   * @returns Результат регистрации
   */
  public async verifyRegistrationResponse(
    response: RegistrationResponseJSON,
    temporaryId: string,
    expectedOrigin?: string
  ): Promise<RegistrationResult> {
    try {
      // Получение challenge
      const storedChallenge = this.challengeStore.get(temporaryId);
      if (!storedChallenge) {
        return {
          success: false,
          error: 'Challenge не найден или истек',
        };
      }

      // Проверка срока действия
      if (Date.now() > storedChallenge.expiresAt) {
        this.challengeStore.delete(temporaryId);
        return {
          success: false,
          error: 'Срок действия challenge истек',
        };
      }

      // Верификация ответа
      const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse({
        response,
        expectedChallenge: storedChallenge.challenge,
        expectedOrigin: expectedOrigin || this.config.origin,
        expectedRPID: this.config.rpID,
        requireUserVerification: this.config.requireUserVerification,
        supportedAlgorithmIDs: this.config.supportedAlgorithmIDs,
      });

      const { verified, registrationInfo } = verification;

      // Очистка challenge
      this.challengeStore.delete(temporaryId);

      if (!verified || !registrationInfo) {
        return {
          success: false,
          error: 'Верификация не пройдена',
        };
      }

      const {
        credential,
        userVerified,
        credentialDeviceType,
        credentialBackedUp,
        origin,
        rpID,
      } = registrationInfo;

      // credential содержит publicKey, id и counter
      const { publicKey, id: credentialID, counter } = credential;

      // Определение типа аутентификатора
      let authenticatorType: AuthenticatorType = 'roaming';
      if (response.response.transports?.includes('internal')) {
        authenticatorType = 'platform';
      }

      // Создание WebAuthn метода
      const webAuthnMethod: IWebAuthnMethod = {
        id: uuidv4(),
        userId: storedChallenge.userId!,
        type: 'webauthn',
        status: 'active',
        credentialId: credentialID,
        publicKey: isoBase64URL.fromBuffer(publicKey),
        counter,
        authenticatorType,
        transports: (response.response.transports as any) || [],
        authenticatorFlags: {
          userPresent: true,
          userVerified: userVerified || this.config.requireUserVerification,
          backupEligible: credentialBackedUp ?? false,
          backupState: credentialBackedUp ?? false,
        },
        deviceName: this.getAuthenticatorName(registrationInfo.aaguid),
        createdAt: new Date(),
        lastUsedAt: new Date(),
        usageCount: 0,
        isDefault: false,
      };

      // Информация об аутентификаторе
      const authenticatorInfo = {
        aaguid: registrationInfo.aaguid || 'unknown',
        name: webAuthnMethod.deviceName || 'Unknown Authenticator',
        type: authenticatorType,
      };

      return {
        success: true,
        webAuthnMethod,
        authenticatorInfo,
      };
    } catch (error) {
      logger.error('[WebAuthnService] Ошибка верификации регистрации', { error });

      // Очистка challenge при ошибке
      this.challengeStore.delete(temporaryId);

      if (error instanceof Error) {
        return {
          success: false,
          error: error.message,
        };
      }

      return {
        success: false,
        error: 'Неизвестная ошибка верификации',
      };
    }
  }

  // ===========================================================================
  // АУТЕНТИФИКАЦИЯ (AUTHENTICATION)
  // ===========================================================================

  /**
   * Генерирует options для аутентификации
   * @param userCredentials - Ключи пользователя
   * @param requireUserVerification - Требовать user verification
   * @returns Options для клиента
   */
  public async generateAuthenticationOptions(
    userCredentials: Pick<IWebAuthnMethod, 'credentialId' | 'transports'>[] = [],
    requireUserVerification: boolean = true
  ): Promise<AuthenticationOptionsResult> {
    try {
      // Генерация challenge
      const challenge = isoBase64URL.fromBuffer(
        crypto.getRandomValues(new Uint8Array(32))
      );

      // Сохранение challenge
      const temporaryId = uuidv4();
      this.challengeStore.set(temporaryId, {
        challenge,
        createdAt: Date.now(),
        expiresAt: Date.now() + this.challengeTimeout,
      });

      // Преобразование credential IDs
      const allowCredentials = userCredentials.map(cred => ({
        id: cred.credentialId,
        type: 'public-key' as const,
        transports: cred.transports as AuthenticatorTransportFuture[],
      }));

      // Генерация options
      const options = await generateAuthenticationOptions({
        rpID: this.config.rpID,
        challenge,
        allowCredentials: allowCredentials.length > 0 ? allowCredentials : undefined,
        userVerification: requireUserVerification ? 'required' : 'preferred',
        timeout: this.config.timeout,
      });

      return {
        options,
        challenge,
        temporaryId,
      };
    } catch (error) {
      throw new AuthError(
        `Ошибка генерации options для аутентификации: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Верифицирует ответ на аутентификацию
   * @param response - Ответ от клиента
   * @param temporaryId - Временный ID challenge
   * @param storedCredential - Сохраненные данные ключа
   * @param expectedOrigin - Ожидаемый origin
   * @returns Результат аутентификации
   */
  public async verifyAuthenticationResponse(
    response: AuthenticationResponseJSON,
    temporaryId: string,
    storedCredential: {
      publicKey: string;
      counter: number;
      credentialId: string;
    },
    expectedOrigin?: string
  ): Promise<AuthenticationResult> {
    try {
      // Получение challenge
      const storedChallenge = this.challengeStore.get(temporaryId);
      if (!storedChallenge) {
        return {
          success: false,
          error: 'Challenge не найден или истек',
        };
      }

      // Проверка срока действия
      if (Date.now() > storedChallenge.expiresAt) {
        this.challengeStore.delete(temporaryId);
        return {
          success: false,
          error: 'Срок действия challenge истек',
        };
      }

      // Верификация ответа
      const verification: VerifiedAuthenticationResponse = await verifyAuthenticationResponse({
        response,
        expectedChallenge: storedChallenge.challenge,
        expectedOrigin: expectedOrigin || this.config.origin,
        expectedRPID: this.config.rpID,
        credential: {
          id: storedCredential.credentialId,
          publicKey: isoBase64URL.toBuffer(storedCredential.publicKey),
          counter: storedCredential.counter,
          transports: undefined, // response.response.transports не существует в новом типе
        },
        requireUserVerification: this.config.requireUserVerification,
      });

      const { verified, authenticationInfo } = verification;

      // Очистка challenge
      this.challengeStore.delete(temporaryId);

      if (!verified || !authenticationInfo) {
        return {
          success: false,
          error: 'Верификация не пройдена',
        };
      }

      const { newCounter, userVerified, credentialBackedUp } = authenticationInfo;

      return {
        success: true,
        userId: storedChallenge.userId,
        newCounter,
        authInfo: {
          userVerified,
          userPresent: true, // userPresent всегда true если верификация прошла
          backupEligible: credentialBackedUp ?? false,
          backupState: credentialBackedUp ?? false,
        },
      };
    } catch (error) {
      logger.error('[WebAuthnService] Ошибка верификации аутентификации', { error });

      // Очистка challenge при ошибке
      this.challengeStore.delete(temporaryId);

      if (error instanceof Error) {
        return {
          success: false,
          error: error.message,
        };
      }

      return {
        success: false,
        error: 'Неизвестная ошибка верификации',
      };
    }
  }

  // ===========================================================================
  // УПРАВЛЕНИЕ КЛЮЧАМИ
  // ===========================================================================

  /**
   * Проверяет валидность credential ID
   * @param credentialId - ID ключа
   * @returns Верен ли ID
   */
  public isValidCredentialId(credentialId: string): boolean {
    try {
      // Проверка формата base64url
      isoBase64URL.toBuffer(credentialId);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Определяет тип аутентификатора по AAGUID
   * @param aaguid - AAGUID аутентификатора
   * @returns Название аутентификатора
   */
  private getAuthenticatorName(aaguid?: string): string {
    if (!aaguid) return 'Unknown Authenticator';

    // Известные AAGUID (упрощенная версия)
    const knownAaguids: Record<string, string> = {
      '00000000-0000-0000-0000-000000000000': 'Legacy Authenticator',
      'adce0002-35bc-c60a-648b-0b25f1f05503': 'Windows Hello',
      '5ee2e2a8-4a37-4f20-b2d1-f7a1e9b5c5e5': 'Touch ID',
      'd41f5a69-b817-4142-a7d4-74a888669e5c': 'Apple Touch ID',
      '4ae71336-e44b-39bf-b9d2-752e234818a5': 'Android Key Attestation',
      '5fb64517-92c7-4757-b763-2971888f8240': 'Samsung Pass',
      '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Google Password Manager',
    };

    return knownAaguids[aaguid.toLowerCase()] || `Authenticator (${aaguid.slice(0, 8)}...)`;
  }

  /**
   * Очистка просроченных challenge
   * @private
   */
  private cleanupChallenges(): void {
    const now = Date.now();
    for (const [id, data] of this.challengeStore.entries()) {
      if (now > data.expiresAt) {
        this.challengeStore.delete(id);
      }
    }
  }

  /**
   * Получает статистику challenge
   * @returns Статистика
   */
  public getChallengeStats(): {
    total: number;
    expired: number;
    active: number;
  } {
    const now = Date.now();
    let expired = 0;
    let active = 0;

    for (const data of this.challengeStore.values()) {
      if (now > data.expiresAt) {
        expired++;
      } else {
        active++;
      }
    }

    return {
      total: this.challengeStore.size,
      expired,
      active,
    };
  }

  // ===========================================================================
  // УТИЛИТЫ
  // ===========================================================================

  /**
   * Проверяет поддержку WebAuthn в браузере (для серверной валидации)
   * @param userAgent - User-Agent строка
   * @returns Информация о поддержке
   */
  public checkWebAuthnSupport(userAgent: string): {
    supported: boolean;
    platform: string;
    notes: string[];
  } {
    const notes: string[] = [];
    let supported = true;
    let platform = 'unknown';

    // Определение платформы
    if (/Windows NT 10/.test(userAgent)) {
      platform = 'Windows 10/11';
      if (/Edg/.test(userAgent)) {
        notes.push('Edge с поддержкой Windows Hello');
      } else if (/Chrome/.test(userAgent)) {
        notes.push('Chrome с поддержкой Windows Hello');
      }
    } else if (/Mac OS X/.test(userAgent)) {
      platform = 'macOS';
      if (/Safari/.test(userAgent) && !/Chrome/.test(userAgent)) {
        notes.push('Safari с поддержкой Touch ID');
      }
    } else if (/Android/.test(userAgent)) {
      platform = 'Android';
      if (/Chrome/.test(userAgent)) {
        notes.push('Chrome с поддержкой Android Biometrics');
      }
    } else if (/iPhone|iPad/.test(userAgent)) {
      platform = 'iOS';
      notes.push('Safari с поддержкой Touch ID / Face ID');
    } else {
      supported = false;
      notes.push('Платформа не определена');
    }

    return { supported, platform, notes };
  }

  /**
   * Обновляет конфигурацию сервиса
   * @param config - Новая конфигурация
   */
  public updateConfig(config: Partial<WebAuthnServiceConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Получает текущую конфигурацию
   * @returns Конфигурация
   */
  public getConfig(): WebAuthnServiceConfig {
    return { ...this.config };
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const webAuthnService = new WebAuthnService(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createWebAuthnService(config: Partial<WebAuthnServiceConfig>): WebAuthnService {
  return new WebAuthnService({ ...DEFAULT_CONFIG, ...config });
}
