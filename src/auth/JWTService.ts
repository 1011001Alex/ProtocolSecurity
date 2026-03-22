/**
 * =============================================================================
 * JWT SERVICE
 * =============================================================================
 * Сервис для работы с JWT токенами
 * Поддерживает: RS256, RS384, RS512, ES256, ES384, ES512, EdDSA
 * Реализует: Access tokens, Refresh tokens, ID tokens (OIDC)
 * Соответствует: RFC 7519, RFC 8414, OpenID Connect Core 1.0
 * =============================================================================
 */

import {
  SignJwtPayload,
  verify,
  sign,
  createSigner,
  createVerifier,
  KeyLike,
  JWTPayload,
  JwtHeaderParameters,
} from 'jsonwebtoken';
import {
  generateKeyPairSync,
  generateKeyPair,
  createSign,
  createVerify,
  randomBytes,
  createHash,
} from 'crypto';
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
  minRsaKeySize: 2048,
  ecCurve: 'P-256',
};

/**
 * Внутреннее представление ключа
 */
interface KeyPair {
  config: JwtKeyConfig;
  privateKey: KeyLike;
  publicKey: KeyLike;
  signer: ReturnType<typeof createSigner>;
  verifier: ReturnType<typeof createVerifier>;
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

  /**
   * Создает новый экземпляр JwtService
   * @param config - Конфигурация сервиса
   */
  constructor(config: JwtServiceConfig = DEFAULT_CONFIG) {
    this.config = config;
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
      const publicKey = await importSPKI(keyConfig.publicKey);

      // Создаем signer и verifier
      const signer = createSigner({
        key: keyConfig.privateKey,
        algorithm: keyConfig.algorithm,
        kid: keyConfig.kid,
      });

      const verifier = createVerifier({
        key: keyConfig.publicKey,
        algorithms: [keyConfig.algorithm],
      });

      const keyPair: KeyPair = {
        config: keyConfig,
        privateKey,
        publicKey,
        signer,
        verifier,
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
      return sign(payload, keyPair.config.privateKey, {
        algorithm: keyPair.config.algorithm,
        keyid: keyPair.config.kid,
      });
    } catch (error) {
      throw new AuthError(
        `Ошибка создания access токена: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  /**
   * Создает refresh токен
   * @param user - Пользователь
   * @param session - Сессия
   * @param refreshTokenFamily - Семейство токенов для rotation
   * @returns Подписанный JWT
   */
  public async createRefreshToken(
    user: Pick<IUser, 'id'>,
    session: ISession,
    refreshTokenFamily: string
  ): Promise<string> {
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
      return sign(payload, keyPair.config.privateKey, {
        algorithm: keyPair.config.algorithm,
        keyid: keyPair.config.kid,
      });
    } catch (error) {
      throw new AuthError(
        `Ошибка создания refresh токена: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
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
      return sign(payload, keyPair.config.privateKey, {
        algorithm: keyPair.config.algorithm,
        keyid: keyPair.config.kid,
      });
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
  public async verifyToken<T extends JWTPayload>(
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

      // Верифицируем токен
      const payload = await verify(token, keyPair.config.publicKey, {
        algorithms: [keyPair.config.algorithm],
        issuer: this.config.issuer,
        audience: this.config.audience,
      }) as T;

      // Дополнительные проверки
      if (options?.tokenType === 'refresh') {
        const refreshPayload = payload as RefreshTokenPayload;
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
    header: JwtHeaderParameters;
    payload: JWTPayload;
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
        console.error(`Ошибка экспорта ключа ${keyPair.config.kid}:`, error);
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
   * ROTATION REFRESH TOKENS
   * =============================================================================
   */

  /**
   * Создает новый refresh токен при rotation
   * @param oldToken - Старый refresh токен
   * @param session - Сессия
   * @param refreshTokenFamily - Семейство токенов
   * @returns Новый refresh токен
   */
  public async rotateRefreshToken(
    oldToken: string,
    session: ISession,
    refreshTokenFamily: string
  ): Promise<string> {
    // Верифицируем старый токен
    const payload = await this.verifyToken<RefreshTokenPayload>(oldToken, {
      tokenType: 'refresh',
    });

    // Проверяем семейство токенов
    if (payload.rtf !== refreshTokenFamily) {
      throw new AuthError(
        'Несоответствие семейства токенов - возможная атака',
        AuthErrorCode.TOKEN_REVOKED,
        401
      );
    }

    // Создаем новый токен с новым jti
    return this.createRefreshToken(
      { id: payload.sub },
      session,
      refreshTokenFamily
    );
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

        console.log(`[JwtService] Ключ ротирован: ${newKey.kid}`);
      } catch (error) {
        console.error('[JwtService] Ошибка ротации ключей:', error);
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
   * ОЧИСТКА
   * =============================================================================
   */

  /**
   * Очищает ресурсы сервиса
   */
  public destroy(): void {
    this.stopKeyRotation();
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
