/**
 * =============================================================================
 * JWT SERVICE
 * =============================================================================
 * Сервис для работы с JWT токенами
 * Поддерживает: RS256, RS384, RS512, ES256, ES384, ES512, EdDSA
 * Реализует: Access tokens, Refresh tokens, ID tokens (OIDC)
 * Соответствует: RFC 7519, RFC 8414, OpenID Connect Core 1.0
 * Интеграция: JWT Blacklist для отзыва токенов
 * =============================================================================
 */

import {
  JwtPayload,
} from 'jsonwebtoken';
import { logger } from '../logging/Logger';
import {
  generateKeyPairSync,
  generateKeyPair,
  createSign,
  createVerify,
  randomBytes,
  createHash,
} from 'crypto';
import { webcrypto } from 'crypto';
import {
  exportJWK,
  importJWK,
  importSPKI,
  importPKCS8,
  JWK,
  calculateJwkThumbprint,
} from 'jose';
import { v4 as uuidv4 } from 'uuid';
import {
  JwtAlgorithm,
  JwtKeyConfig,
  JwkSet,
  AccessTokenPayload,
  RefreshTokenPayload,
  IdTokenPayload,
  IUser,
  ISession,
  AuthError,
  AuthErrorCode,
  AuthenticationMethod,
} from '../types/auth.types';
import {
  JWTBlacklist,
  JWTBlacklistConfig,
  RevokedTokenInfo,
  RevocationCheckResult,
  createJWTBlacklist,
} from './JWTBlacklist';

/**
 * Конфигурация JWT сервиса
 */
export interface JwtServiceConfig {
  /** Issuer (издатель токенов) */
  issuer: string;

  /** Audience (получатель токенов) */
  audience: string | string[];

  /** Время жизни access токена (секунды) */
  accessTokenLifetime: number;

  /** Время жизни refresh токена (секунды) */
  refreshTokenLifetime: number;

  /** Время жизни ID токена (секунды) */
  idTokenLifetime: number;

  /** Алгоритм подписи по умолчанию */
  defaultAlgorithm: JwtAlgorithm;

  /** Минимальная длина ключа для RSA (биты) */
  minRsaKeySize: number;

  /** Кривая для EC ключей */
  ecCurve: 'P-256' | 'P-384' | 'P-521' | 'Ed25519' | 'Ed448';

  /** Конфигурация JWT blacklist */
  blacklist?: Partial<JWTBlacklistConfig>;

  /** Включить ли проверку blacklist */
  enableBlacklistCheck?: boolean;

  /** Улучшения безопасности refresh токенов */
  refreshTokenSecurity?: {
    /** Включить fingerprinting refresh токенов */
    enableFingerprinting?: boolean;
    /** Включить защиту от replay attacks */
    enableReplayProtection?: boolean;
    /** Включить detection аномалий использования */
    enableAnomalyDetection?: boolean;
    /** Максимальное количество использований refresh токена */
    maxTokenUses?: number;
    /** Требуемое совпадение fingerprint (%) */
    fingerprintMatchThreshold?: number;
  };

  /** Настройки key versioning для seamless rotation */
  keyVersioning?: {
    /** Включить версионирование ключей */
    enabled?: boolean;
    /** Поддерживать ли старые ключи для верификации */
    supportOldKeysForVerification?: boolean;
    /** Период поддержки старых ключей (часы) */
    oldKeySupportPeriodHours?: number;
  };
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: JwtServiceConfig = {
  issuer: 'protocol-auth',
  audience: 'protocol-api',
  accessTokenLifetime: 900, // 15 минут
  refreshTokenLifetime: 604800, // 7 дней
  idTokenLifetime: 3600, // 1 час
  defaultAlgorithm: 'RS256',
  minRsaKeySize: 4096, // Увеличено с 2048 до 4096 бит для повышенной безопасности
  ecCurve: 'P-384', // Улучшено с P-256 до P-384
  enableBlacklistCheck: true,
  refreshTokenSecurity: {
    enableFingerprinting: true,
    enableReplayProtection: true,
    enableAnomalyDetection: true,
    maxTokenUses: 1, // Refresh token одноразовый
    fingerprintMatchThreshold: 85, // 85% совпадения fingerprint
  },
  keyVersioning: {
    enabled: true,
    supportOldKeysForVerification: true,
    oldKeySupportPeriodHours: 72, // 3 дня поддержки старых ключей
  },
};

/**
 * Внутреннее представление ключа
 */
interface KeyPair {
  config: JwtKeyConfig;
  privateKey: webcrypto.CryptoKey;
  publicKey: webcrypto.CryptoKey;
  /** Версия ключа для key versioning */
  version: number;
  /** Ключи для верификации (для старых ключей) */
  verificationOnly?: boolean;
  /** Время когда ключ станет verification-only */
  verificationOnlyFrom?: Date;
}

/**
 * Refresh token fingerprint данные
 */
interface RefreshTokenFingerprint {
  /** Уникальный идентификатор fingerprint */
  fingerprintId: string;
  /** Хэш fingerprint данных */
  fingerprintHash: string;
  /** IP адрес использования */
  ipAddress: string;
  /** User-Agent */
  userAgent: string;
  /** Device fingerprint если доступен */
  deviceFingerprint?: string;
  /** Geo location */
  geoLocation?: string;
  /** Время создания */
  createdAt: Date;
  /** Время последнего использования */
  lastUsedAt: Date;
  /** Количество использований */
  useCount: number;
  /** История использования для anomaly detection */
  usageHistory: TokenUsageEvent[];
}

/**
 * Событие использования токена
 */
interface TokenUsageEvent {
  /** Время события */
  timestamp: Date;
  /** IP адрес */
  ipAddress: string;
  /** User-Agent */
  userAgent: string;
  /** Результат использования */
  result: 'success' | 'failure' | 'blocked';
  /** Причина блокировки если была */
  blockReason?: string;
}

/**
 * Данные для верификации refresh токена с fingerprint
 */
interface RefreshTokenVerificationContext {
  /** IP адрес запроса */
  ipAddress: string;
  /** User-Agent запроса */
  userAgent: string;
  /** Device fingerprint если доступен */
  deviceFingerprint?: string;
  /** Geo location если доступен */
  geoLocation?: string;
}

/**
 * =============================================================================
 * JWT SERVICE CLASS
 * =============================================================================
 */
export class JwtService {
  private config: JwtServiceConfig;
  private keyPairs: Map<string, KeyPair> = new Map();
  private activeSigningKeyId: string | null = null;
  private keyRotationInterval: NodeJS.Timeout | null = null;
  private blacklist: JWTBlacklist | null = null;
  
  /** Хранилище refresh token fingerprint для enhanced security */
  private refreshTokensFingerprints: Map<string, RefreshTokenFingerprint> = new Map();
  
  /** Индекс для поиска fingerprint по jti токена */
  private tokenJtiToFingerprint: Map<string, string> = new Map();
  
  /** Статистика безопасности для мониторинга атак */
  private securityStats: {
    replayAttacksDetected: number;
    fingerprintMismatches: number;
    anomalousUsageDetected: number;
    tokensRevoked: number;
  } = {
    replayAttacksDetected: 0,
    fingerprintMismatches: 0,
    anomalousUsageDetected: 0,
    tokensRevoked: 0,
  };

  /**
   * Создает новый экземпляр JwtService
   * @param config - Конфигурация сервиса
   */
  constructor(config: JwtServiceConfig = DEFAULT_CONFIG) {
    this.config = config;
  }

  /**
   * =============================================================================
   * ИНИЦИАЛИЗАЦИЯ BLACKLIST
   * =============================================================================
   */

  /**
   * Инициализирует JWT blacklist
   */
  public async initializeBlacklist(): Promise<void> {
    if (!this.config.enableBlacklistCheck) {
      logger.info('[JwtService] Blacklist проверка отключена');
      return;
    }

    try {
      this.blacklist = createJWTBlacklist(this.config.blacklist || {});
      await this.blacklist.initialize();
      logger.info('[JwtService] Blacklist инициализирован');
    } catch (error) {
      logger.error('[JwtService] Ошибка инициализации blacklist', { error });
      // Не блокируем работу сервиса при ошибке инициализации blacklist
      this.blacklist = null;
    }
  }

  /**
   * =============================================================================
   * ГЕНЕРАЦИЯ КЛЮЧЕЙ
   * =============================================================================
   */

  /**
   * Генерирует новую пару ключей для указанной алгоритма
   * @param algorithm - Алгоритм подписи
   * @param kid - Идентификатор ключа (опционально)
   * @returns Конфигурация ключа
   */
  public async generateKeyPair(
    algorithm: JwtAlgorithm = 'RS256',
    kid?: string
  ): Promise<JwtKeyConfig> {
    let privateKey: string;
    let publicKey: string;

    switch (algorithm) {
      case 'RS256':
      case 'RS384':
      case 'RS512': {
        const rsaKeyPair = generateKeyPairSync('rsa', {
          modulusLength: this.config.minRsaKeySize,
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
          },
        });
        publicKey = rsaKeyPair.publicKey;
        privateKey = rsaKeyPair.privateKey;
        break;
      }

      case 'ES256':
      case 'ES384':
      case 'ES512': {
        const curveMap: Record<string, string> = {
          ES256: 'prime256v1',
          ES384: 'secp384r1',
          ES512: 'secp521r1',
        };
        const ecKeyPair = generateKeyPairSync('ec', {
          namedCurve: curveMap[algorithm],
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
          },
        });
        publicKey = ecKeyPair.publicKey;
        privateKey = ecKeyPair.privateKey;
        break;
      }

      case 'EdDSA': {
        const edKeyPair = generateKeyPairSync('ed25519', {
          publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
          },
          privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
          },
        });
        publicKey = edKeyPair.publicKey;
        privateKey = edKeyPair.privateKey;
        break;
      }

      default:
        throw new AuthError(
          `Неподдерживаемый алгоритм: ${algorithm}`,
          AuthErrorCode.INTERNAL_ERROR,
          500
        );
    }

    const keyConfig: JwtKeyConfig = {
      kid: kid || `key-${uuidv4()}`,
      algorithm,
      privateKey,
      publicKey,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 год
      isActive: true,
      isSigningKey: false,
    };

    // Добавляем ключ в хранилище
    await this.addKey(keyConfig);

    return keyConfig;
  }

  /**
   * Добавляет существующий ключ в хранилище
   * @param keyConfig - Конфигурация ключа
   */
  public async addKey(keyConfig: JwtKeyConfig): Promise<void> {
    try {
      // Импортируем ключи
      const privateKey = await importPKCS8(keyConfig.privateKey, keyConfig.algorithm);
      const publicKey = await importSPKI(keyConfig.publicKey, keyConfig.algorithm);

      const keyPair: KeyPair = {
        config: keyConfig,
        privateKey,
        publicKey,
        version: 1,
      };

      this.keyPairs.set(keyConfig.kid, keyPair);

      // Если это первый активный ключ, делаем его signing key
      if (keyConfig.isActive && !this.activeSigningKeyId) {
        this.activeSigningKeyId = keyConfig.kid;
        keyConfig.isSigningKey = true;
      }
    } catch (error) {
      throw new AuthError(
        `Ошибка импорта ключа: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Удаляет ключ из хранилища
   * @param kid - Идентификатор ключа
   */
  public removeKey(kid: string): void {
    const keyPair = this.keyPairs.get(kid);
    if (keyPair) {
      keyPair.config.isActive = false;
      keyPair.config.isSigningKey = false;
      
      // Если это был signing key, выбираем новый
      if (this.activeSigningKeyId === kid) {
        this.activeSigningKeyId = null;
        // Находим следующий активный ключ
        for (const [id, kp] of this.keyPairs.entries()) {
          if (kp.config.isActive && id !== kid) {
            this.activeSigningKeyId = id;
            kp.config.isSigningKey = true;
            break;
          }
        }
      }
    }
  }

  /**
   * Получает активный signing ключ
   * @returns KeyPair активного ключа
   */
  private getActiveSigningKey(): KeyPair {
    if (!this.activeSigningKeyId) {
      throw new AuthError(
        'Нет активного ключа для подписи',
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }

    const keyPair = this.keyPairs.get(this.activeSigningKeyId);
    if (!keyPair) {
      throw new AuthError(
        'Ключ подписи не найден',
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }

    // Проверка истечения срока действия ключа
    if (keyPair.config.expiresAt < new Date()) {
      throw new AuthError(
        'Срок действия ключа подписи истек',
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }

    return keyPair;
  }

  /**
   * Получает ключ по kid для верификации
   * @param kid - Идентификатор ключа
   * @returns KeyPair ключа
   */
  public getKeyById(kid: string): KeyPair {
    const keyPair = this.keyPairs.get(kid);
    if (!keyPair) {
      throw new AuthError(
        'Ключ не найден',
        AuthErrorCode.TOKEN_INVALID,
        401
      );
    }

    return keyPair;
  }

  /**
   * =============================================================================
   * СОЗДАНИЕ ТОКЕНОВ
   * =============================================================================
   */

  /**
   * Создает access токен
   * @param user - Пользователь
   * @param session - Сессия
   * @param authMethods - Методы аутентификации
   * @param additionalClaims - Дополнительные claims
   * @returns Подписанный JWT
   */
  public async createAccessToken(
    user: Pick<IUser, 'id' | 'roles'>,
    session: ISession,
    authMethods: AuthenticationMethod[],
    additionalClaims?: Record<string, any>
  ): Promise<string> {
    const keyPair = this.getActiveSigningKey();
    const now = Math.floor(Date.now() / 1000);

    // Определение ACR (Authentication Context Class Reference)
    let acr: AccessTokenPayload['acr'];
    const aal = session.authenticationLevel.aal;
    
    switch (aal) {
      case 3:
        acr = 'urn:rfc:4868:aal:3';
        break;
      case 2:
        acr = 'urn:rfc:4868:aal:2';
        break;
      default:
        acr = 'urn:rfc:4868:aal:1';
    }

    const payload: AccessTokenPayload = {
      sub: user.id,
      iss: this.config.issuer,
      aud: this.config.audience,
      iat: now,
      exp: now + this.config.accessTokenLifetime,
      jti: uuidv4(),
      scope: 'openid profile email',
      sid: session.id,
      acr,
      amr: authMethods.map(m => m.method),
      auth_time: Math.floor(session.createdAt.getTime() / 1000),
      roles: user.roles,
      ...additionalClaims,
    };

    // Добавляем атрибуты если есть
    if (session.context?.jitElevated && session.permissions) {
      payload.permissions = session.permissions;
    }

    try {
      // Используем jose library для подписи CryptoKey
      const { SignJWT } = await import('jose');
      const alg = keyPair.config.algorithm as string;
      const token = await new SignJWT(payload as any)
        .setProtectedHeader({ alg, kid: keyPair.config.kid })
        .setIssuedAt()
        .setIssuer(this.config.issuer)
        .setAudience(this.config.audience)
        .setExpirationTime(Math.floor(this.config.accessTokenLifetime / 1000))
        .sign(keyPair.privateKey);
      
      return token;
    } catch (error) {
      throw new AuthError(
        `Ошибка создания access токена: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Создает refresh токен с enhanced security (fingerprinting + replay protection)
   * @param user - Пользователь
   * @param session - Сессия
   * @param refreshTokenFamily - Семейство токенов для rotation
   * @param verificationContext - Контекст верификации для fingerprinting
   * @returns Подписанный JWT с metadata
   */
  public async createRefreshToken(
    user: Pick<IUser, 'id'>,
    session: ISession,
    refreshTokenFamily: string,
    verificationContext?: RefreshTokenVerificationContext
  ): Promise<{
    token: string;
    fingerprintId?: string;
    metadata: {
      requiresFingerprintMatch: boolean;
      maxUses: number;
    };
  }> {
    const keyPair = this.getActiveSigningKey();
    const now = Math.floor(Date.now() / 1000);

    const payload: RefreshTokenPayload = {
      sub: user.id,
      iss: this.config.issuer,
      aud: this.config.audience,
      iat: now,
      exp: now + this.config.refreshTokenLifetime,
      jti: uuidv4(),
      sid: session.id,
      rtf: refreshTokenFamily,
      tok: 'refresh',
    };

    try {
      // Используем jose library для подписи CryptoKey
      const { SignJWT } = await import('jose');
      const alg = keyPair.config.algorithm as string;
      const token = await new SignJWT(payload as any)
        .setProtectedHeader({ alg, kid: keyPair.config.kid })
        .setIssuedAt()
        .setIssuer(this.config.issuer)
        .setAudience(this.config.audience)
        .setExpirationTime(now + this.config.refreshTokenLifetime)
        .sign(keyPair.privateKey);

      // Создаем fingerprint если включена защита
      let fingerprintId: string | undefined;
      const securityConfig = this.config.refreshTokenSecurity;

      if (securityConfig?.enableFingerprinting && verificationContext) {
        fingerprintId = this.createRefreshTokenFingerprint(
          payload.jti,
          verificationContext
        );
      }

      return {
        token,
        fingerprintId,
        metadata: {
          requiresFingerprintMatch: securityConfig?.enableFingerprinting ?? false,
          maxUses: securityConfig?.maxTokenUses ?? 1,
        },
      };
    } catch (error) {
      throw new AuthError(
        `Ошибка создания refresh токена: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Создает fingerprint для refresh токена
   * @private
   */
  private createRefreshTokenFingerprint(
    tokenJti: string,
    context: RefreshTokenVerificationContext
  ): string {
    const fingerprintId = uuidv4();
    const fingerprintData = JSON.stringify({
      ip: context.ipAddress,
      ua: context.userAgent,
      device: context.deviceFingerprint,
      geo: context.geoLocation,
      jti: tokenJti,
    });
    
    const fingerprintHash = createHash('sha256').update(fingerprintData).digest('hex');
    
    const fingerprint: RefreshTokenFingerprint = {
      fingerprintId,
      fingerprintHash,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      deviceFingerprint: context.deviceFingerprint,
      geoLocation: context.geoLocation,
      createdAt: new Date(),
      lastUsedAt: new Date(),
      useCount: 0,
      usageHistory: [],
    };
    
    this.refreshTokensFingerprints.set(fingerprintId, fingerprint);
    this.tokenJtiToFingerprint.set(tokenJti, fingerprintId);
    
    logger.info('[JwtService] Создан fingerprint для refresh токена', {
      fingerprintId,
      tokenJti,
      hasDeviceFingerprint: !!context.deviceFingerprint,
    });
    
    return fingerprintId;
  }

  /**
   * Создает ID токен (OIDC)
   * @param user - Пользователь
   * @param session - Сессия
   * @param authMethods - Методы аутентификации
   * @param nonce - Nonce из authorization request
   * @param accessToken - Access токен для at_hash
   * @param authorizationCode - Код авторизации для c_hash
   * @returns Подписанный JWT
   */
  public async createIdToken(
    user: IUser,
    session: ISession,
    authMethods: AuthenticationMethod[],
    nonce?: string,
    accessToken?: string,
    authorizationCode?: string
  ): Promise<string> {
    const keyPair = this.getActiveSigningKey();
    const now = Math.floor(Date.now() / 1000);

    // Вычисление at_hash
    let at_hash: string | undefined;
    if (accessToken) {
      at_hash = this.calculateTokenHash(accessToken, keyPair.config.algorithm);
    }

    // Вычисление c_hash
    let c_hash: string | undefined;
    if (authorizationCode) {
      c_hash = this.calculateTokenHash(authorizationCode, keyPair.config.algorithm);
    }

    const payload: IdTokenPayload = {
      sub: user.id,
      iss: this.config.issuer,
      aud: this.config.audience,
      iat: now,
      exp: now + this.config.idTokenLifetime,
      jti: uuidv4(),
      auth_time: Math.floor(session.createdAt.getTime() / 1000),
      nonce,
      at_hash,
      c_hash,
      acr: `urn:rfc:4868:aal:${session.authenticationLevel.aal}`,
      amr: authMethods.map(m => m.method),
      email: user.email,
      email_verified: user.status === 'active',
      preferred_username: user.username,
      locale: 'ru',
    };

    try {
      // Используем jose library для подписи CryptoKey
      const { SignJWT } = await import('jose');
      const alg = keyPair.config.algorithm as string;
      return await new SignJWT(payload as any)
        .setProtectedHeader({ alg, kid: keyPair.config.kid })
        .setIssuedAt()
        .setIssuer(this.config.issuer)
        .setAudience(this.config.audience)
        .setExpirationTime(now + this.config.idTokenLifetime)
        .sign(keyPair.privateKey);
    } catch (error) {
      throw new AuthError(
        `Ошибка создания ID токена: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Вычисляет hash токена для at_hash / c_hash
   * @private
   */
  private calculateTokenHash(token: string, algorithm: JwtAlgorithm): string {
    // Выбор хэш-алгоритма в зависимости от алгоритма подписи
    let hashAlgorithm: string;
    let hashLength: number;

    if (algorithm.startsWith('RS') || algorithm.startsWith('ES')) {
      const bits = parseInt(algorithm.slice(-3), 10);
      hashAlgorithm = `SHA${bits}`;
      hashLength = bits / 8 / 2; // Половина длины хэша
    } else if (algorithm === 'EdDSA') {
      hashAlgorithm = 'SHA512';
      hashLength = 32;
    } else {
      hashAlgorithm = 'SHA256';
      hashLength = 16;
    }

    const hash = createHash(hashAlgorithm.toLowerCase()).update(token).digest();
    const truncatedHash = hash.slice(0, hashLength);
    
    // Base64url encoding
    return truncatedHash
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  /**
   * =============================================================================
   * ВЕРИФИКАЦИЯ ТОКЕНОВ
   * =============================================================================
   */

  /**
   * Верифицирует и декодирует JWT токен
   * @param token - JWT токен
   * @param options - Опции верификации
   * @returns Payload токена
   */
  public async verifyToken<T extends JwtPayload>(
    token: string,
    options?: {
      /** Требовать конкретный тип токена */
      tokenType?: 'access' | 'refresh' | 'id';
      /** Ожидаемый session ID */
      sessionId?: string;
      /** Проверять revocation */
      checkRevocation?: boolean;
    }
  ): Promise<T & { kid: string }> {
    try {
      // Сначала декодируем без верификации для получения kid
      const decoded = this.decodeToken(token);
      const kid = decoded.header.kid;

      if (!kid) {
        throw new AuthError(
          'Отсутствует идентификатор ключа (kid)',
          AuthErrorCode.TOKEN_INVALID,
          401
        );
      }

      // Получаем ключ для верификации
      const keyPair = this.getKeyById(kid);

      // Верифицируем токен используя jose library для CryptoKey
      const { jwtVerify } = await import('jose');
      const result = await jwtVerify<T>(
        token,
        keyPair.publicKey,
        {
          issuer: this.config.issuer,
          audience: this.config.audience,
        }
      );
      const payload = result.payload as T;

      // Проверка blacklist (если включена)
      const shouldCheckBlacklist = options?.checkRevocation ?? this.config.enableBlacklistCheck ?? true;
      if (shouldCheckBlacklist && this.blacklist) {
        const jti = (payload as any).jti;
        if (jti) {
          const revocationCheck = await this.blacklist.isRevoked(jti);
          if (revocationCheck.isRevoked) {
            throw new AuthError(
              `Токен отозван: ${revocationCheck.reason || 'Причина не указана'}`,
              AuthErrorCode.TOKEN_REVOKED,
              401
            );
          }
        }
      }

      // Дополнительные проверки
      if (options?.tokenType === 'refresh') {
        const refreshPayload = payload as unknown as RefreshTokenPayload;
        if (refreshPayload.tok !== 'refresh') {
          throw new AuthError(
            'Ожидался refresh токен',
            AuthErrorCode.TOKEN_INVALID,
            401
          );
        }
      }

      if (options?.sessionId) {
        if ((payload as any).sid !== options.sessionId) {
          throw new AuthError(
            'Session ID не совпадает',
            AuthErrorCode.SESSION_INVALID,
            401
          );
        }
      }

      return { ...payload, kid };
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }

      // Обработка ошибок jsonwebtoken
      if (error instanceof Error) {
        if (error.name === 'TokenExpiredError') {
          throw new AuthError(
            'Срок действия токена истек',
            AuthErrorCode.TOKEN_EXPIRED,
            401
          );
        }
        if (error.name === 'JsonWebTokenError') {
          throw new AuthError(
            `Неверный токен: ${error.message}`,
            AuthErrorCode.TOKEN_INVALID,
            401
          );
        }
      }

      throw new AuthError(
        'Ошибка верификации токена',
        AuthErrorCode.TOKEN_INVALID,
        401
      );
    }
  }

  /**
   * Декодирует JWT без верификации (для получения заголовка)
   * @param token - JWT токен
   * @returns Декодированный токен с заголовком
   */
  public decodeToken(token: string): {
    header: Record<string, any>;
    payload: Record<string, any>;
    signature: string;
  } {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Неверный формат JWT');
      }

      const header = JSON.parse(
        Buffer.from(parts[0] || '', 'base64').toString('utf-8')
      );
      const payload = JSON.parse(
        Buffer.from(parts[1] || '', 'base64').toString('utf-8')
      );

      return {
        header,
        payload,
        signature: parts[2] || '',
      };
    } catch (error) {
      throw new AuthError(
        `Ошибка декодирования токена: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.TOKEN_INVALID,
        400
      );
    }
  }

  /**
   * =============================================================================
   * JWKS (JSON WEB KEY SET)
   * =============================================================================
   */

  /**
   * Получает JWKS для публичных ключей
   * @param includeInactive - Включать неактивные ключи
   * @returns JWK Set
   */
  public async getJwks(includeInactive: boolean = false): Promise<JwkSet> {
    const jwks: JwkSet = { keys: [] };

    for (const keyPair of this.keyPairs.values()) {
      if (!includeInactive && !keyPair.config.isActive) {
        continue;
      }

      try {
        // Экспорт в JWK формат
        const jwk = await exportJWK(keyPair.publicKey);
        
        // Добавляем метаданные
        jwk.kid = keyPair.config.kid;
        jwk.alg = keyPair.config.algorithm;
        jwk.use = 'sig';

        jwks.keys.push(jwk);
      } catch (error) {
        logger.error(`Ошибка экспорта ключа ${keyPair.config.kid}`, { error });
      }
    }

    return jwks;
  }

  /**
   * Получает публичный ключ в JWK формате по kid
   * @param kid - Идентификатор ключа
   * @returns JWK ключа
   */
  public async getJwkById(kid: string): Promise<JWK | null> {
    const keyPair = this.keyPairs.get(kid);
    if (!keyPair || !keyPair.config.isActive) {
      return null;
    }

    try {
      const jwk = await exportJWK(keyPair.publicKey);
      jwk.kid = kid;
      jwk.alg = keyPair.config.algorithm;
      jwk.use = 'sig';
      
      return jwk;
    } catch (error) {
      return null;
    }
  }

  /**
   * =============================================================================
   * ROTATION REFRESH TOKENS С ENHANCED SECURITY
   * =============================================================================
   */

  /**
   * Создает новый refresh токен при rotation с enhanced security
   * @param oldToken - Старый refresh токен
   * @param session - Сессия
   * @param refreshTokenFamily - Семейство токенов
   * @param verificationContext - Контекст для fingerprint verification
   * @returns Новый refresh токен с metadata
   */
  public async rotateRefreshToken(
    oldToken: string,
    session: ISession,
    refreshTokenFamily: string,
    verificationContext?: RefreshTokenVerificationContext
  ): Promise<{
    success: boolean;
    newToken?: string;
    newFingerprintId?: string;
    error?: string;
    securityEvents: {
      replayAttackDetected: boolean;
      fingerprintMismatch: boolean;
      anomalyDetected: boolean;
    };
  }> {
    const securityEvents = {
      replayAttackDetected: false,
      fingerprintMismatch: false,
      anomalyDetected: false,
    };

    try {
      // Верифицируем старый токен
      const payload = await this.verifyToken<RefreshTokenPayload>(oldToken, {
        tokenType: 'refresh',
        checkRevocation: true,
      });

      // ПРОВЕРКА 1: Replay attack detection
      // Проверяем не был ли токен уже использован
      if (this.config.refreshTokenSecurity?.enableReplayProtection) {
        const isReplay = await this.detectReplayAttack(payload.jti, verificationContext);
        
        if (isReplay) {
          securityEvents.replayAttackDetected = true;
          this.securityStats.replayAttacksDetected++;
          
          // КРИТИЧЕСКАЯ АТАКА - отзываем ВСЕ токены пользователя
          await this.emergencyRevokeUserTokens(payload.sub, 'Replay attack detected');
          
          logger.error('[JwtService] DETECTED REPLAY ATTACK', {
            userId: payload.sub,
            tokenJti: payload.jti,
            sessionId: session.id,
            ip: verificationContext?.ipAddress,
          });
          
          return {
            success: false,
            error: 'Replay attack detected - all tokens revoked',
            securityEvents,
          };
        }
      }

      // ПРОВЕРКА 2: Fingerprint matching
      if (this.config.refreshTokenSecurity?.enableFingerprinting && verificationContext) {
        const fingerprintMatch = await this.verifyRefreshTokenFingerprint(
          payload.jti,
          verificationContext
        );
        
        if (!fingerprintMatch.valid) {
          securityEvents.fingerprintMismatch = true;
          this.securityStats.fingerprintMismatches++;
          
          logger.warn('[JwtService] Refresh token fingerprint mismatch', {
            userId: payload.sub,
            tokenJti: payload.jti,
            reason: fingerprintMatch.reason,
            matchScore: fingerprintMatch.matchScore,
          });
          
          // Проверяем порог совпадения
          const threshold = this.config.refreshTokenSecurity.fingerprintMatchThreshold ?? 85;
          if (fingerprintMatch.matchScore < threshold) {
            // Подозрительная активность - возможная кража токена
            await this.recordSecurityIncident(payload.sub, 'Fingerprint mismatch', verificationContext);
            
            return {
              success: false,
              error: `Fingerprint mismatch (score: ${fingerprintMatch.matchScore}%, required: ${threshold}%)`,
              securityEvents,
            };
          }
        }
      }

      // ПРОВЕРКА 3: Anomaly detection
      if (this.config.refreshTokenSecurity?.enableAnomalyDetection) {
        const anomalyResult = await this.detectTokenUsageAnomaly(payload.jti, verificationContext);
        
        if (anomalyResult.isAnomalous) {
          securityEvents.anomalyDetected = true;
          this.securityStats.anomalousUsageDetected++;
          
          logger.warn('[JwtService] Anomalous token usage detected', {
            userId: payload.sub,
            tokenJti: payload.jti,
            reasons: anomalyResult.reasons,
          });
        }
      }

      // Проверяем семейство токенов
      if (payload.rtf !== refreshTokenFamily) {
        logger.error('[JwtService] Token family mismatch - possible attack', {
          expected: refreshTokenFamily,
          received: payload.rtf,
          userId: payload.sub,
        });
        
        return {
          success: false,
          error: 'Token family mismatch - possible attack',
          securityEvents,
        };
      }

      // Отзываем старый токен (добавляем в blacklist)
      if (this.blacklist) {
        const oldTokenJti = payload.jti;
        const remainingTtl = (payload.exp || 0) - Math.floor(Date.now() / 1000);

        if (remainingTtl > 0) {
          await this.blacklist.revokeToken(oldTokenJti, remainingTtl, {
            sessionId: session.id,
            userId: payload.sub,
            reason: 'Refresh token rotation - single use token',
          });
        }
      }

      // Создаем новый токен с новым fingerprint
      const newTokenResult = await this.createRefreshToken(
        { id: payload.sub },
        session,
        refreshTokenFamily,
        verificationContext
      );

      logger.info('[JwtService] Refresh token successfully rotated', {
        userId: payload.sub,
        newFingerprintId: newTokenResult.fingerprintId,
      });

      return {
        success: true,
        newToken: newTokenResult.token,
        newFingerprintId: newTokenResult.fingerprintId,
        securityEvents,
      };
    } catch (error) {
      logger.error('[JwtService] Error during refresh token rotation', { error });
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        securityEvents,
      };
    }
  }

  /**
   * Детекция replay attack
   * @private
   */
  private async detectReplayAttack(
    tokenJti: string,
    context?: RefreshTokenVerificationContext
  ): Promise<boolean> {
    // Проверяем был ли токен уже использован
    const fingerprintId = this.tokenJtiToFingerprint.get(tokenJti);
    
    if (!fingerprintId) {
      return false; // Нет данных fingerprint, не можем проверить
    }
    
    const fingerprint = this.refreshTokensFingerprints.get(fingerprintId);
    
    if (!fingerprint) {
      return false;
    }
    
    // Если токен уже был использован (useCount > 0), это replay attack
    // так как refresh токены должны быть одноразовыми
    if (fingerprint.useCount > 0) {
      // Проверяем не было ли это в рамках очень короткого окна (race condition)
      const timeSinceLastUse = Date.now() - fingerprint.lastUsedAt.getTime();
      
      if (timeSinceLastUse < 1000) { // Менее 1 секунды
        logger.warn('[JwtService] Possible race condition on token use', {
          tokenJti,
          timeSinceLastUse,
        });
        return false; // Возможно это легитимное повторное использование
      }
      
      return true; // Точно replay attack
    }
    
    return false;
  }

  /**
   * Верификация fingerprint refresh токена
   * @private
   */
  private async verifyRefreshTokenFingerprint(
    tokenJti: string,
    context: RefreshTokenVerificationContext
  ): Promise<{
    valid: boolean;
    reason?: string;
    matchScore: number;
  }> {
    const fingerprintId = this.tokenJtiToFingerprint.get(tokenJti);
    
    if (!fingerprintId) {
      return { valid: true, matchScore: 100 }; // Нет fingerprint, пропускаем
    }
    
    const fingerprint = this.refreshTokensFingerprints.get(fingerprintId);
    
    if (!fingerprint) {
      return { valid: true, matchScore: 100 };
    }
    
    let matchScore = 100;
    const mismatches: string[] = [];
    
    // Проверяем IP адрес (частичное совпадение для NAT)
    if (context.ipAddress !== fingerprint.ipAddress) {
      const ipMatch = this.compareIpAddresses(context.ipAddress, fingerprint.ipAddress);
      if (!ipMatch) {
        matchScore -= 30;
        mismatches.push('IP address mismatch');
      }
    }
    
    // Проверяем User-Agent (должен совпадать)
    if (context.userAgent !== fingerprint.userAgent) {
      const uaSimilarity = this.calculateUserAgentSimilarity(
        context.userAgent,
        fingerprint.userAgent
      );
      
      if (uaSimilarity < 0.9) {
        matchScore -= 40;
        mismatches.push(`User-Agent mismatch (similarity: ${uaSimilarity})`);
      }
    }
    
    // Проверяем device fingerprint (если доступен)
    if (context.deviceFingerprint && fingerprint.deviceFingerprint) {
      if (context.deviceFingerprint !== fingerprint.deviceFingerprint) {
        matchScore -= 50; // Критичное несоответствие
        mismatches.push('Device fingerprint mismatch');
      }
    }
    
    // Обновляем статистику использования
    fingerprint.useCount++;
    fingerprint.lastUsedAt = new Date();
    fingerprint.usageHistory.push({
      timestamp: new Date(),
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      result: matchScore >= (this.config.refreshTokenSecurity?.fingerprintMatchThreshold ?? 85)
        ? 'success'
        : 'failure',
    });
    
    this.refreshTokensFingerprints.set(fingerprintId, fingerprint);
    
    return {
      valid: matchScore >= (this.config.refreshTokenSecurity?.fingerprintMatchThreshold ?? 85),
      reason: mismatches.length > 0 ? mismatches.join('; ') : undefined,
      matchScore,
    };
  }

  /**
   * Детекция аномалий использования токена
   * @private
   */
  private async detectTokenUsageAnomaly(
    tokenJti: string,
    context?: RefreshTokenVerificationContext
  ): Promise<{
    isAnomalous: boolean;
    reasons: string[];
  }> {
    const fingerprintId = this.tokenJtiToFingerprint.get(tokenJti);
    
    if (!fingerprintId) {
      return { isAnomalous: false, reasons: [] };
    }
    
    const fingerprint = this.refreshTokensFingerprints.get(fingerprintId);
    
    if (!fingerprint || fingerprint.usageHistory.length < 3) {
      return { isAnomalous: false, reasons: [] };
    }
    
    const reasons: string[] = [];
    
    // Аномалия 1: Необычное время использования
    const currentHour = new Date().getHours();
    const usageHours = fingerprint.usageHistory.map(e => new Date(e.timestamp).getHours());
    const avgUsageHour = usageHours.reduce((a, b) => a + b, 0) / usageHours.length;
    const hourDiff = Math.abs(currentHour - avgUsageHour);
    
    if (hourDiff > 6) { // Более 6 часов отклонения
      reasons.push(`Unusual usage time (current: ${currentHour}, avg: ${avgUsageHour.toFixed(1)})`);
    }
    
    // Аномалия 2: Географическая невозможность
    if (context?.geoLocation && fingerprint.geoLocation) {
      const distance = this.calculateDistance(
        fingerprint.geoLocation,
        context.geoLocation
      );
      
      const timeSinceLastUse = Date.now() - fingerprint.lastUsedAt.getTime();
      const hoursSinceLastUse = timeSinceLastUse / (1000 * 60 * 60);
      
      // Если расстояние большое, а время маленькое - это невозможно
      const maxPossibleSpeed = 900; // 900 км/ч (максимум для коммерческих рейсов)
      const maxPossibleDistance = maxPossibleSpeed * hoursSinceLastUse;
      
      if (distance > maxPossibleDistance * 1.5) { // 50% запас
        reasons.push(`Impossible travel (distance: ${distance.toFixed(0)}km, max possible: ${maxPossibleDistance.toFixed(0)}km)`);
      }
    }
    
    // Аномалия 3: Частое использование
    const recentUses = fingerprint.usageHistory.filter(
      e => Date.now() - new Date(e.timestamp).getTime() < 3600000 // 1 час
    );
    
    if (recentUses.length > 10) {
      reasons.push(`High frequency usage (${recentUses.length} times in 1 hour)`);
    }
    
    return {
      isAnomalous: reasons.length > 0,
      reasons,
    };
  }

  /**
   * Экстренный отзыв всех токенов пользователя
   * @private
   */
  private async emergencyRevokeUserTokens(
    userId: string,
    reason: string
  ): Promise<void> {
    if (!this.blacklist) {
      return;
    }
    
    try {
      await this.blacklist.revokeUserTokens(userId, this.config.refreshTokenLifetime, reason);
      this.securityStats.tokensRevoked++;
      
      logger.error('[JwtService] EMERGENCY TOKEN REVOCATION', {
        userId,
        reason,
        action: 'All user tokens revoked due to security incident',
      });
    } catch (error) {
      logger.error('[JwtService] Error during emergency revocation', { error });
    }
  }

  /**
   * Запись security incident
   * @private
   */
  private async recordSecurityIncident(
    userId: string,
    incidentType: string,
    context?: RefreshTokenVerificationContext
  ): Promise<void> {
    logger.error('[JwtService] SECURITY INCIDENT RECORDED', {
      userId,
      incidentType,
      context: {
        ip: context?.ipAddress,
        hasDeviceFingerprint: !!context?.deviceFingerprint,
        geoLocation: context?.geoLocation,
      },
      timestamp: new Date().toISOString(),
    });

    // В реальной реализации здесь была бы отправка в SIEM
    // Для совместимости оставляем как логирование
    logger.warn('[JwtService] Security Incident Event', {
      userId,
      incidentType,
      timestamp: new Date(),
      context,
    });
  }

  /**
   * Сравнение IP адресов (с учетом NAT)
   * @private
   */
  private compareIpAddresses(ip1: string, ip2: string): boolean {
    // Точное совпадение
    if (ip1 === ip2) {
      return true;
    }
    
    // Проверяем совпадение по /24 subnet (для NAT)
    const parts1 = ip1.split('.');
    const parts2 = ip2.split('.');
    
    if (parts1.length === 4 && parts2.length === 4) {
      // Совпадение первых 3 октетов (/24 subnet)
      return parts1[0] === parts2[0] &&
             parts1[1] === parts2[1] &&
             parts1[2] === parts2[2];
    }
    
    return false;
  }

  /**
   * Вычисление схожести User-Agent
   * @private
   */
  private calculateUserAgentSimilarity(ua1: string, ua2: string): number {
    // Простая эвристика: сравнение по основным компонентам
    const extractBrowser = (ua: string) => {
      const match = ua.match(/(Chrome|Firefox|Safari|Edge|Opera)[\/\s](\d+)/i);
      return match ? `${match[1]}${match[2]}` : ua;
    };
    
    const browser1 = extractBrowser(ua1);
    const browser2 = extractBrowser(ua2);
    
    if (browser1 === browser2) {
      return 1.0;
    }
    
    // Проверяем совпадение OS
    const extractOS = (ua: string) => {
      const match = ua.match(/(Windows|Mac OS|Linux|Android|iOS)[\s\/]?(\d+[\._]?\d*)?/i);
      return match ? match[1] : '';
    };
    
    const os1 = extractOS(ua1);
    const os2 = extractOS(ua2);
    
    if (os1 === os2 && os1 !== '') {
      return 0.7; // Та же OS, другой браузер
    }
    
    return 0;
  }

  /**
   * Вычисление расстояния между geo locations (Haversine formula)
   * @private
   */
  private calculateDistance(loc1: string, loc2: string): number {
    try {
      const [lat1, lon1] = loc1.split(',').map(Number);
      const [lat2, lon2] = loc2.split(',').map(Number);
      
      const R = 6371; // Радиус Земли в км
      const dLat = ((lat2 - lat1) * Math.PI) / 180;
      const dLon = ((lon2 - lon1) * Math.PI) / 180;
      
      const a =
        Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos((lat1 * Math.PI) / 180) *
        Math.cos((lat2 * Math.PI) / 180) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);
      
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      const distance = R * c;
      
      return distance;
    } catch {
      return 0;
    }
  }

  /**
   * Получение статистики безопасности
   */
  public getSecurityStats(): typeof this.securityStats {
    return { ...this.securityStats };
  }

  /**
   * Очистка старых fingerprint данных
   */
  public cleanupOldFingerprints(maxAgeHours: number = 24): void {
    const now = Date.now();
    const maxAge = maxAgeHours * 60 * 60 * 1000;
    
    for (const [fingerprintId, fingerprint] of this.refreshTokensFingerprints.entries()) {
      const age = now - fingerprint.lastUsedAt.getTime();
      
      if (age > maxAge) {
        this.refreshTokensFingerprints.delete(fingerprintId);
        
        // Находим и удаляем соответствующий JTI
        for (const [jti, fpId] of this.tokenJtiToFingerprint.entries()) {
          if (fpId === fingerprintId) {
            this.tokenJtiToFingerprint.delete(jti);
            break;
          }
        }
      }
    }
    
    logger.info('[JwtService] Cleanup old fingerprints completed', {
      remainingCount: this.refreshTokensFingerprints.size,
    });
  }

  /**
   * =============================================================================
   * УПРАВЛЕНИЕ КЛЮЧАМИ
   * =============================================================================
   */

  /**
   * Устанавливает активный signing ключ
   * @param kid - Идентификатор ключа
   */
  public setActiveSigningKey(kid: string): void {
    const keyPair = this.keyPairs.get(kid);
    if (!keyPair) {
      throw new AuthError(
        'Ключ не найден',
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }

    // Снимаем флаг isSigningKey со всех ключей
    for (const kp of this.keyPairs.values()) {
      kp.config.isSigningKey = false;
    }

    // Устанавливаем новый signing key
    keyPair.config.isSigningKey = true;
    keyPair.config.isActive = true;
    this.activeSigningKeyId = kid;
  }

  /**
   * Получает информацию о всех ключах
   * @returns Массив конфигураций ключей
   */
  public getAllKeys(): JwtKeyConfig[] {
    return Array.from(this.keyPairs.values()).map(kp => ({ ...kp.config }));
  }

  /**
   * Инициирует ротацию ключей
   * @param intervalMs - Интервал ротации в мс
   */
  public startKeyRotation(intervalMs: number = 30 * 24 * 60 * 60 * 1000): void {
    // 30 дней по умолчанию
    if (this.keyRotationInterval) {
      clearInterval(this.keyRotationInterval);
    }

    this.keyRotationInterval = setInterval(async () => {
      try {
        // Генерируем новый ключ
        const newKey = await this.generateKeyPair(
          this.config.defaultAlgorithm
        );

        // Делаем его активным signing ключом
        this.setActiveSigningKey(newKey.kid);

        // Помечаем старые ключи как неактивные для подписи
        const now = Date.now();
        const keyAgeThreshold = 60 * 24 * 60 * 60 * 1000; // 60 дней

        for (const [kid, keyPair] of this.keyPairs.entries()) {
          if (
            kid !== newKey.kid &&
            now - keyPair.config.createdAt.getTime() > keyAgeThreshold
          ) {
            keyPair.config.isSigningKey = false;
            // Не удаляем полностью, чтобы можно было верифицировать старые токены
          }
        }

        logger.info(`[JwtService] Ключ ротирован: ${newKey.kid}`);
      } catch (error) {
        logger.error('[JwtService] Ошибка ротации ключей', { error });
      }
    }, intervalMs);
  }

  /**
   * Останавливает ротацию ключей
   */
  public stopKeyRotation(): void {
    if (this.keyRotationInterval) {
      clearInterval(this.keyRotationInterval);
      this.keyRotationInterval = null;
    }
  }

  /**
   * =============================================================================
   * УПРАВЛЕНИЕ BLACKLIST
   * =============================================================================
   */

  /**
   * Отзывает токен по его идентификатору
   * @param tokenId - Уникальный идентификатор токена (jti)
   * @param ttl - Время жизни записи в blacklist (секунды)
   * @param options - Дополнительные опции
   * @returns Информация об отозванном токене
   */
  public async revokeToken(
    tokenId: string,
    ttl: number,
    options?: {
      userId?: string;
      deviceId?: string;
      sessionId?: string;
      reason?: string;
    }
  ): Promise<RevokedTokenInfo> {
    if (!this.blacklist) {
      throw new AuthError(
        'Blacklist не инициализирован',
        AuthErrorCode.INTERNAL_ERROR,
        503
      );
    }

    return this.blacklist.revokeToken(tokenId, ttl, options);
  }

  /**
   * Проверяет, отозван ли токен
   * @param tokenId - Уникальный идентификатор токена (jti)
   * @returns Результат проверки
   */
  public async isTokenRevoked(tokenId: string): Promise<RevocationCheckResult> {
    if (!this.blacklist) {
      return { isRevoked: false };
    }

    return this.blacklist.isRevoked(tokenId);
  }

  /**
   * Отзывает все токены пользователя
   * @param userId - ID пользователя
   * @param ttl - Время жизни записей в blacklist (секунды)
   * @param reason - Причина отзыва
   * @param sessionId - ID сессии (опционально)
   * @returns Количество отозванных токенов
   */
  public async revokeUserTokens(
    userId: string,
    ttl: number,
    reason?: string,
    sessionId?: string
  ): Promise<number> {
    if (!this.blacklist) {
      throw new AuthError(
        'Blacklist не инициализирован',
        AuthErrorCode.INTERNAL_ERROR,
        503
      );
    }

    return this.blacklist.revokeUserTokens(userId, ttl, reason, sessionId);
  }

  /**
   * Отзывает все токены устройства
   * @param deviceId - ID устройства
   * @param ttl - Время жизни записей в blacklist (секунды)
   * @param reason - Причина отзыва
   * @returns Количество отозванных токенов
   */
  public async revokeDeviceTokens(
    deviceId: string,
    ttl: number,
    reason?: string
  ): Promise<number> {
    if (!this.blacklist) {
      throw new AuthError(
        'Blacklist не инициализирован',
        AuthErrorCode.INTERNAL_ERROR,
        503
      );
    }

    return this.blacklist.revokeDeviceTokens(deviceId, ttl, reason);
  }

  /**
   * Отзывает все токены сессии
   * @param sessionId - ID сессии
   * @param ttl - Время жизни записей в blacklist (секунды)
   * @param reason - Причина отзыва
   * @returns Количество отозванных токенов
   */
  public async revokeSessionTokens(
    sessionId: string,
    ttl: number,
    reason?: string
  ): Promise<number> {
    if (!this.blacklist) {
      throw new AuthError(
        'Blacklist не инициализирован',
        AuthErrorCode.INTERNAL_ERROR,
        503
      );
    }

    return this.blacklist.revokeSessionTokens(sessionId, ttl, reason);
  }

  /**
   * Получает метрики blacklist
   * @returns Метрики blacklist
   */
  public async getBlacklistMetrics() {
    if (!this.blacklist) {
      return null;
    }

    return this.blacklist.getMetrics();
  }

  /**
   * Получает статус blacklist
   * @returns Статус blacklist
   */
  public getBlacklistStatus() {
    if (!this.blacklist) {
      return {
        initialized: false,
        enabled: false,
        redisConnected: false,
        cleanupRunning: false,
      };
    }

    return this.blacklist.getStatus();
  }

  /**
   * =============================================================================
   * ОЧИСТКА
   * =============================================================================
   */

  /**
   * Очищает ресурсы сервиса
   */
  public destroy(): void {
    this.stopKeyRotation();
    if (this.blacklist) {
      // Асинхронная очистка blacklist
      this.blacklist.destroy().catch((error) => logger.error('[JwtService] Blacklist destroy error', { error }));
    }
    this.keyPairs.clear();
    this.activeSigningKeyId = null;
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const jwtService = new JwtService(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createJwtService(config: Partial<JwtServiceConfig>): JwtService {
  return new JwtService({ ...DEFAULT_CONFIG, ...config });
}
