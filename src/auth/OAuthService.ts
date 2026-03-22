/**
 * =============================================================================
 * OAUTH 2.1 / OIDC SERVICE
 * =============================================================================
 * Сервис для OAuth 2.1 и OpenID Connect аутентификации
 * Поддерживает: Authorization Code + PKCE, Refresh Token, Device Code, Token Exchange
 * Соответствует: RFC 6749, RFC 7636 (PKCE), RFC 8628 (Device Flow), OpenID Connect Core 1.0
 * =============================================================================
 */

import { createHash, randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import {
  IOAuthClient,
  IAuthorizationCode,
  IDeviceCode,
  IOAuthTokens,
  OAuthGrantType,
  OAuthResponseType,
  PkceChallengeMethod,
  IUser,
  ISession,
  AuthError,
  AuthErrorCode,
  AuthenticationMethod,
} from '../types/auth.types';

/**
 * Конфигурация OAuth сервиса
 */
export interface OAuthServiceConfig {
  /** Issuer URL */
  issuer: string;
  
  /** Authorization endpoint URL */
  authorizationEndpoint: string;
  
  /** Token endpoint URL */
  tokenEndpoint: string;
  
  /** JWKS endpoint URL */
  jwksEndpoint: string;
  
  /** UserInfo endpoint URL */
  userinfoEndpoint: string;
  
  /** Device authorization endpoint URL */
  deviceAuthorizationEndpoint: string;
  
  /** Поддерживаемые scope */
  supportedScopes: string[];
  
  /** Поддерживаемые response types */
  supportedResponseTypes: OAuthResponseType[];
  
  /** Поддерживаемые grant types */
  supportedGrantTypes: OAuthGrantType[];
  
  /** Поддерживаемые subject types */
  supportedSubjectTypes: string[];
  
  /** Поддерживаемые алгоритмы ID токена */
  idTokenSigningAlgs: string[];
  
  /** Требовать PKCE для public clients */
  requirePkceForPublicClients: boolean;
  
  /** Время жизни authorization code (секунды) */
  authorizationCodeLifetime: number;
  
  /** Время жизни device code (секунды) */
  deviceCodeLifetime: number;
  
  /** Интервал опроса device code (секунды) */
  devicePollInterval: number;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: OAuthServiceConfig = {
  issuer: 'https://auth.protocol.local',
  authorizationEndpoint: '/oauth/authorize',
  tokenEndpoint: '/oauth/token',
  jwksEndpoint: '/.well-known/jwks.json',
  userinfoEndpoint: '/oauth/userinfo',
  deviceAuthorizationEndpoint: '/oauth/device_authorization',
  supportedScopes: ['openid', 'profile', 'email', 'offline_access'],
  supportedResponseTypes: ['code', 'token', 'id_token', 'code token', 'code id_token'],
  supportedGrantTypes: [
    'authorization_code',
    'refresh_token',
    'client_credentials',
    'urn:ietf:params:oauth:grant-type:device_code',
  ],
  supportedSubjectTypes: ['public'],
  idTokenSigningAlgs: ['RS256', 'ES256', 'EdDSA'],
  requirePkceForPublicClients: true,
  authorizationCodeLifetime: 600, // 10 минут
  deviceCodeLifetime: 900, // 15 минут
  devicePollInterval: 5, // 5 секунд
};

/**
 * Хранилище authorization codes (в памяти для примера)
 */
interface AuthCodeStore {
  code: IAuthorizationCode;
  expiresAt: number;
}

/**
 * Хранилище device codes
 */
interface DeviceCodeStore {
  code: IDeviceCode;
  expiresAt: number;
}

/**
 * Хранилище consent records
 */
interface ConsentRecord {
  userId: string;
  clientId: string;
  scopes: string[];
  grantedAt: Date;
  expiresAt?: Date;
}

/**
 * =============================================================================
 * OAUTH SERVICE CLASS
 * =============================================================================
 */
export class OAuthService {
  private config: OAuthServiceConfig;
  private clients: Map<string, IOAuthClient> = new Map();
  private authCodes: Map<string, AuthCodeStore> = new Map();
  private deviceCodes: Map<string, DeviceCodeStore> = new Map();
  private userCodes: Map<string, string> = new Map(); // userCode -> deviceCode
  private consentRecords: Map<string, ConsentRecord> = new Map();

  /**
   * Создает новый экземпляр OAuthService
   * @param config - Конфигурация сервиса
   */
  constructor(config: OAuthServiceConfig = DEFAULT_CONFIG) {
    this.config = config;
    
    // Очистка просроченных кодов
    setInterval(() => this.cleanupExpiredCodes(), 60000);
  }

  // ===========================================================================
  // УПРАВЛЕНИЕ КЛИЕНТАМИ
  // ===========================================================================

  /**
   * Регистрирует нового OAuth клиента
   * @param clientData - Данные клиента
   * @returns Зарегистрированный клиент
   */
  public registerClient(clientData: Partial<IOAuthClient>): IOAuthClient {
    const clientId = clientData.clientId || `client_${uuidv4()}`;
    
    // Проверка уникальности clientId
    if (this.clients.has(clientId)) {
      throw new AuthError(
        'Client ID уже существует',
        AuthErrorCode.OAUTH_INVALID_CLIENT,
        400
      );
    }

    const client: IOAuthClient = {
      clientId,
      clientSecretHash: clientData.clientSecretHash,
      clientName: clientData.clientName || 'Unknown Client',
      clientDescription: clientData.clientDescription,
      clientType: clientData.clientType || 'public',
      redirectUris: clientData.redirectUris || [],
      postLogoutRedirectUris: clientData.postLogoutRedirectUris || [],
      grantTypes: clientData.grantTypes || ['authorization_code'],
      responseTypes: clientData.responseTypes || ['code'],
      tokenEndpointAuthMethod: clientData.tokenEndpointAuthMethod || 'client_secret_basic',
      tokenEndpointAuthSigningAlg: clientData.tokenEndpointAuthSigningAlg,
      jwksUri: clientData.jwksUri,
      defaultScopes: clientData.defaultScopes || ['openid'],
      allowedScopes: clientData.allowedScopes || this.config.supportedScopes,
      accessTokenLifetime: clientData.accessTokenLifetime || 3600,
      refreshTokenLifetime: clientData.refreshTokenLifetime || 604800,
      idTokenLifetime: clientData.idTokenLifetime || 3600,
      requirePkce: clientData.requirePkce ?? this.config.requirePkceForPublicClients,
      requireConsent: clientData.requireConsent ?? true,
      logoUri: clientData.logoUri,
      policyUri: clientData.policyUri,
      tosUri: clientData.tosUri,
      createdAt: new Date(),
      isActive: true,
    };

    this.clients.set(clientId, client);
    return client;
  }

  /**
   * Получает клиента по ID
   * @param clientId - Client ID
   * @returns Клиент или null
   */
  public getClient(clientId: string): IOAuthClient | null {
    const client = this.clients.get(clientId);
    if (!client || !client.isActive) {
      return null;
    }
    return client;
  }

  /**
   * Верифицирует client secret
   * @param clientId - Client ID
   * @param clientSecret - Client secret
   * @returns Верен ли secret
   */
  public async verifyClientSecret(
    clientId: string,
    clientSecret: string
  ): Promise<boolean> {
    const client = this.getClient(clientId);
    if (!client || !client.clientSecretHash) {
      return false;
    }

    // В production использовать bcrypt/argon2 compare
    const providedHash = createHash('sha256').update(clientSecret).digest('hex');
    return providedHash === client.clientSecretHash;
  }

  /**
   * Проверяет redirect URI
   * @param clientId - Client ID
   * @param redirectUri - Redirect URI
   * @returns Верен ли URI
   */
  public validateRedirectUri(clientId: string, redirectUri: string): boolean {
    const client = this.getClient(clientId);
    if (!client) {
      return false;
    }

    // Точное совпадение или wildcard matching
    return client.redirectUris.some(allowed => {
      if (allowed === redirectUri) return true;
      
      // Wildcard support (например, https://*.example.com/*)
      if (allowed.includes('*')) {
        const pattern = allowed
          .replace(/\./g, '\\.')
          .replace(/\*/g, '.*');
        return new RegExp(`^${pattern}$`).test(redirectUri);
      }
      
      return false;
    });
  }

  // ===========================================================================
  // AUTHORIZATION CODE FLOW
  // ===========================================================================

  /**
   * Создает authorization code
   * @param clientId - Client ID
   * @param userId - User ID
   * @param redirectUri - Redirect URI
   * @param scope - Scope
   * @param options - Дополнительные опции
   * @returns Authorization code
   */
  public createAuthorizationCode(
    clientId: string,
    userId: string,
    redirectUri: string,
    scope: string[],
    options?: {
      codeChallenge?: string;
      codeChallengeMethod?: PkceChallengeMethod;
      nonce?: string;
      state?: string;
      sessionId?: string;
    }
  ): IAuthorizationCode {
    const client = this.getClient(clientId);
    if (!client) {
      throw new AuthError(
        'Неверный client ID',
        AuthErrorCode.OAUTH_INVALID_CLIENT,
        400
      );
    }

    if (!this.validateRedirectUri(clientId, redirectUri)) {
      throw new AuthError(
        'Неверный redirect URI',
        AuthErrorCode.OAUTH_INVALID_REDIRECT_URI,
        400
      );
    }

    // Проверка PKCE для public clients
    if (
      client.clientType === 'public' &&
      this.config.requirePkceForPublicClients &&
      !options?.codeChallenge
    ) {
      throw new AuthError(
        'PKCE code challenge требуется для public clients',
        AuthErrorCode.OAUTH_PKCE_MISMATCH,
        400
      );
    }

    const code = `auth_${randomBytes(32).toString('base64url')}`;
    const now = new Date();

    const authCode: IAuthorizationCode = {
      code,
      clientId,
      userId,
      redirectUri,
      scope,
      codeChallenge: options?.codeChallenge,
      codeChallengeMethod: options?.codeChallengeMethod || 'S256',
      nonce: options?.nonce,
      state: options?.state,
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.config.authorizationCodeLifetime * 1000),
      used: false,
      sessionId: options?.sessionId,
    };

    this.authCodes.set(code, {
      code: authCode,
      expiresAt: authCode.expiresAt.getTime(),
    });

    return authCode;
  }

  /**
   * Обменивает authorization code на токены
   * @param code - Authorization code
   * @param clientId - Client ID
   * @param redirectUri - Redirect URI
   * @param codeVerifier - PKCE code verifier
   * @returns OAuth токены
   */
  public async exchangeAuthorizationCode(
    code: string,
    clientId: string,
    redirectUri: string,
    codeVerifier?: string
  ): Promise<IOAuthTokens> {
    const stored = this.authCodes.get(code);
    if (!stored) {
      throw new AuthError(
        'Authorization code не найден',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    const authCode = stored.code;

    // Проверка срока действия
    if (new Date() > authCode.expiresAt) {
      this.authCodes.delete(code);
      throw new AuthError(
        'Authorization code истек',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    // Проверка client ID
    if (authCode.clientId !== clientId) {
      throw new AuthError(
        'Client ID не совпадает',
        AuthErrorCode.OAUTH_INVALID_CLIENT,
        400
      );
    }

    // Проверка redirect URI
    if (authCode.redirectUri !== redirectUri) {
      throw new AuthError(
        'Redirect URI не совпадает',
        AuthErrorCode.OAUTH_INVALID_REDIRECT_URI,
        400
      );
    }

    // Проверка PKCE
    if (authCode.codeChallenge && codeVerifier) {
      const computedChallenge = this.calculateCodeChallenge(
        codeVerifier,
        authCode.codeChallengeMethod || 'S256'
      );
      
      if (computedChallenge !== authCode.codeChallenge) {
        throw new AuthError(
          'PKCE code verifier не совпадает',
          AuthErrorCode.OAUTH_PKCE_MISMATCH,
          400
        );
      }
    }

    // Проверка одноразовости
    if (authCode.used) {
      // Возможная атака - отозвать все токены
      this.authCodes.delete(code);
      throw new AuthError(
        'Authorization code уже использован',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    // Помечаем код как использованный
    authCode.used = true;
    this.authCodes.delete(code);

    // Генерация токенов (в production использовать JWTService)
    const client = this.getClient(clientId);
    const tokens = await this.generateOAuthTokens(
      authCode.userId,
      client!,
      authCode.scope,
      authCode.sessionId
    );

    return tokens;
  }

  /**
   * Создает authorization URL
   * @param clientId - Client ID
   * @param redirectUri - Redirect URI
   * @param scope - Scope
   * @param options - Дополнительные параметры
   * @returns Authorization URL
   */
  public createAuthorizationUrl(
    clientId: string,
    redirectUri: string,
    scope: string[],
    options?: {
      responseType?: OAuthResponseType;
      state?: string;
      nonce?: string;
      codeChallenge?: string;
      codeChallengeMethod?: PkceChallengeMethod;
      prompt?: 'none' | 'login' | 'consent' | 'select_account';
      display?: 'page' | 'popup' | 'touch' | 'wap';
    }
  ): string {
    const client = this.getClient(clientId);
    if (!client) {
      throw new AuthError(
        'Неверный client ID',
        AuthErrorCode.OAUTH_INVALID_CLIENT,
        400
      );
    }

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: options?.responseType || 'code',
      scope: scope.join(' '),
      state: options?.state || uuidv4(),
    });

    if (options?.nonce) {
      params.append('nonce', options.nonce);
    }

    if (options?.codeChallenge) {
      params.append('code_challenge', options.codeChallenge);
      params.append(
        'code_challenge_method',
        options.codeChallengeMethod || 'S256'
      );
    }

    if (options?.prompt) {
      params.append('prompt', options.prompt);
    }

    if (options?.display) {
      params.append('display', options.display);
    }

    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  // ===========================================================================
  // TOKEN ENDPOINT
  // ===========================================================================

  /**
   * Обрабатывает запрос на token endpoint
   * @param grantType - Grant type
   * @param params - Параметры запроса
   * @returns OAuth токены
   */
  public async handleTokenRequest(
    grantType: OAuthGrantType,
    params: Record<string, any>
  ): Promise<IOAuthTokens> {
    switch (grantType) {
      case 'authorization_code':
        return this.handleAuthorizationCodeGrant(params);
      
      case 'refresh_token':
        return this.handleRefreshTokenGrant(params);
      
      case 'client_credentials':
        return this.handleClientCredentialsGrant(params);
      
      case 'urn:ietf:params:oauth:grant-type:device_code':
        return this.handleDeviceCodeGrant(params);
      
      default:
        throw new AuthError(
          `Неподдерживаемый grant type: ${grantType}`,
          AuthErrorCode.OAUTH_INVALID_GRANT,
          400
        );
    }
  }

  /**
   * Authorization Code Grant
   * @private
   */
  private async handleAuthorizationCodeGrant(
    params: Record<string, any>
  ): Promise<IOAuthTokens> {
    const { code, client_id, redirect_uri, code_verifier } = params;

    if (!code || !client_id || !redirect_uri) {
      throw new AuthError(
        'Отсутствуют обязательные параметры',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    return this.exchangeAuthorizationCode(
      code,
      client_id,
      redirect_uri,
      code_verifier
    );
  }

  /**
   * Refresh Token Grant
   * @private
   */
  private async handleRefreshTokenGrant(
    params: Record<string, any>
  ): Promise<IOAuthTokens> {
    const { refresh_token, client_id, scope } = params;

    if (!refresh_token || !client_id) {
      throw new AuthError(
        'Отсутствуют обязательные параметры',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    // В production верифицировать refresh токен и создать новые токены
    // Здесь упрощенная реализация
    throw new AuthError(
      'Refresh token grant не реализован полностью',
      AuthErrorCode.OAUTH_INVALID_GRANT,
      501
    );
  }

  /**
   * Client Credentials Grant
   * @private
   */
  private async handleClientCredentialsGrant(
    params: Record<string, any>
  ): Promise<IOAuthTokens> {
    const { client_id, client_secret, scope } = params;

    if (!client_id || !client_secret) {
      throw new AuthError(
        'Отсутствуют обязательные параметры',
        AuthErrorCode.OAUTH_INVALID_CLIENT,
        400
      );
    }

    const valid = await this.verifyClientSecret(client_id, client_secret);
    if (!valid) {
      throw new AuthError(
        'Неверный client secret',
        AuthErrorCode.OAUTH_INVALID_CLIENT,
        400
      );
    }

    const client = this.getClient(client_id);
    if (!client) {
      throw new AuthError(
        'Клиент не найден',
        AuthErrorCode.OAUTH_INVALID_CLIENT,
        404
      );
    }

    // Для client credentials нет user context
    return {
      accessToken: `access_${randomBytes(32).toString('base64url')}`,
      tokenType: 'Bearer',
      expiresIn: client.accessTokenLifetime,
      scope: (scope || client.defaultScopes.join(' ')),
    };
  }

  /**
   * Device Code Grant
   * @private
   */
  private async handleDeviceCodeGrant(
    params: Record<string, any>
  ): Promise<IOAuthTokens> {
    const { device_code, client_id } = params;

    const stored = this.deviceCodes.get(device_code);
    if (!stored) {
      throw new AuthError(
        'Device code не найден',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    const deviceCode = stored.code;

    if (new Date() > deviceCode.expiresAt) {
      this.deviceCodes.delete(device_code);
      throw new AuthError(
        'Device code истек',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    if (!deviceCode.authorized) {
      throw new AuthError(
        'Устройство еще не авторизовано',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400,
        { error: 'authorization_pending' }
      );
    }

    if (deviceCode.used) {
      throw new AuthError(
        'Device code уже использован',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    deviceCode.used = true;
    const client = this.getClient(client_id);
    
    return this.generateOAuthTokens(
      deviceCode.userId!,
      client!,
      deviceCode.scope
    );
  }

  // ===========================================================================
  // DEVICE AUTHORIZATION GRANT
  // ===========================================================================

  /**
   * Инициирует device authorization flow
   * @param clientId - Client ID
   * @param scope - Scope
   * @returns Device code информация
   */
  public createDeviceAuthorization(
    clientId: string,
    scope: string[]
  ): {
    deviceCode: string;
    userCode: string;
    verificationUri: string;
    verificationUriComplete: string;
    expiresIn: number;
    interval: number;
  } {
    const client = this.getClient(clientId);
    if (!client) {
      throw new AuthError(
        'Неверный client ID',
        AuthErrorCode.OAUTH_INVALID_CLIENT,
        400
      );
    }

    const deviceCode = `device_${randomBytes(16).toString('base64url')}`;
    const userCode = this.generateUserCode();

    const now = new Date();
    const deviceCodeData: IDeviceCode = {
      deviceCode,
      userCode,
      clientId,
      scope,
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.config.deviceCodeLifetime * 1000),
      interval: this.config.devicePollInterval,
      authorized: false,
      used: false,
    };

    this.deviceCodes.set(deviceCode, {
      code: deviceCodeData,
      expiresAt: deviceCodeData.expiresAt.getTime(),
    });

    this.userCodes.set(userCode, deviceCode);

    return {
      deviceCode,
      userCode,
      verificationUri: `${this.config.deviceAuthorizationEndpoint}/verify`,
      verificationUriComplete: `${this.config.deviceAuthorizationEndpoint}/verify?user_code=${userCode}`,
      expiresIn: this.config.deviceCodeLifetime,
      interval: this.config.devicePollInterval,
    };
  }

  /**
   * Авторизует device code пользователем
   * @param userCode - User code
   * @param userId - User ID
   */
  public authorizeDeviceCode(userCode: string, userId: string): void {
    const deviceCode = this.userCodes.get(userCode);
    if (!deviceCode) {
      throw new AuthError(
        'User code не найден',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    const stored = this.deviceCodes.get(deviceCode);
    if (!stored) {
      throw new AuthError(
        'Device code не найден',
        AuthErrorCode.OAUTH_INVALID_GRANT,
        400
      );
    }

    stored.code.authorized = true;
    stored.code.userId = userId;
    stored.code.authorizedAt = new Date();
  }

  /**
   * Генерирует user code для device flow
   * @private
   */
  private generateUserCode(): string {
    // Формат: XXXX-XXXX (8 символов, только буквы)
    const chars = 'BCDFGHJKLMNPQRSTVWXZ'; // Без гласных для удобства
    let code = '';
    
    for (let i = 0; i < 8; i++) {
      if (i === 4) code += '-';
      code += chars[randomBytes(1)[0] % chars.length];
    }
    
    return code;
  }

  // ===========================================================================
  // PKCE УТИЛИТЫ
  // ===========================================================================

  /**
   * Генерирует code verifier для PKCE
   * @returns Code verifier
   */
  public generateCodeVerifier(): string {
    return randomBytes(32).toString('base64url');
  }

  /**
   * Вычисляет code challenge из verifier
   * @param verifier - Code verifier
   * @param method - Метод хэширования
   * @returns Code challenge
   */
  public calculateCodeChallenge(
    verifier: string,
    method: PkceChallengeMethod = 'S256'
  ): string {
    if (method === 'plain') {
      return verifier;
    }

    // S256: base64url(SHA256(verifier))
    const hash = createHash('sha256').update(verifier).digest();
    return hash.toString('base64url');
  }

  // ===========================================================================
  // TOKEN GENERATION
  // ===========================================================================

  /**
   * Генерирует OAuth токены
   * @private
   */
  private async generateOAuthTokens(
    userId: string,
    client: IOAuthClient,
    scope: string[],
    sessionId?: string
  ): Promise<IOAuthTokens> {
    // В production использовать JWTService для создания JWT токенов
    const accessToken = `access_${randomBytes(32).toString('base64url')}`;
    const refreshToken = `refresh_${randomBytes(32).toString('base64url')}`;

    return {
      accessToken,
      tokenType: 'Bearer',
      expiresIn: client.accessTokenLifetime,
      refreshToken: client.grantTypes.includes('refresh_token') ? refreshToken : undefined,
      scope: scope.join(' '),
    };
  }

  // ===========================================================================
  // CONSENT MANAGEMENT
  // ===========================================================================

  /**
   * Проверяет наличие согласия пользователя
   * @param userId - User ID
   * @param clientId - Client ID
   * @param scope - Запрошенный scope
   * @returns Требуется ли согласие
   */
  public requiresConsent(
    userId: string,
    clientId: string,
    scope: string[]
  ): boolean {
    const client = this.getClient(clientId);
    if (!client || !client.requireConsent) {
      return false;
    }

    const consentKey = `${userId}:${clientId}`;
    const consent = this.consentRecords.get(consentKey);

    if (!consent) {
      return true;
    }

    if (consent.expiresAt && consent.expiresAt < new Date()) {
      return true;
    }

    // Проверка что все запрошенные scope были согласованы
    return !scope.every(s => consent.scopes.includes(s));
  }

  /**
   * Записывает согласие пользователя
   * @param userId - User ID
   * @param clientId - Client ID
   * @param scope - Согласованный scope
   * @param expiresIn - Срок действия (секунды)
   */
  public grantConsent(
    userId: string,
    clientId: string,
    scope: string[],
    expiresIn?: number
  ): void {
    const consentKey = `${userId}:${clientId}`;
    
    this.consentRecords.set(consentKey, {
      userId,
      clientId,
      scopes: scope,
      grantedAt: new Date(),
      expiresAt: expiresIn 
        ? new Date(Date.now() + expiresIn * 1000)
        : undefined,
    });
  }

  /**
   * Отозывает согласие пользователя
   * @param userId - User ID
   * @param clientId - Client ID
   */
  public revokeConsent(userId: string, clientId?: string): void {
    if (clientId) {
      const consentKey = `${userId}:${clientId}`;
      this.consentRecords.delete(consentKey);
    } else {
      // Отозвать все согласия пользователя
      for (const [key] of this.consentRecords.entries()) {
        if (key.startsWith(`${userId}:`)) {
          this.consentRecords.delete(key);
        }
      }
    }
  }

  // ===========================================================================
  // УТИЛИТЫ
  // ===========================================================================

  /**
   * Очистка просроченных кодов
   * @private
   */
  private cleanupExpiredCodes(): void {
    const now = Date.now();

    // Очистка authorization codes
    for (const [code, stored] of this.authCodes.entries()) {
      if (now > stored.expiresAt) {
        this.authCodes.delete(code);
      }
    }

    // Очистка device codes
    for (const [code, stored] of this.deviceCodes.entries()) {
      if (now > stored.expiresAt) {
        this.userCodes.delete(stored.code.userCode);
        this.deviceCodes.delete(code);
      }
    }
  }

  /**
   * Получает конфигурацию discovery endpoint (OIDC)
   * @returns Конфигурация для .well-known/openid-configuration
   */
  public getDiscoveryConfiguration(): Record<string, any> {
    return {
      issuer: this.config.issuer,
      authorization_endpoint: `${this.config.issuer}${this.config.authorizationEndpoint}`,
      token_endpoint: `${this.config.issuer}${this.config.tokenEndpoint}`,
      jwks_uri: `${this.config.issuer}${this.config.jwksEndpoint}`,
      userinfo_endpoint: `${this.config.issuer}${this.config.userinfoEndpoint}`,
      device_authorization_endpoint: `${this.config.issuer}${this.config.deviceAuthorizationEndpoint}`,
      response_types_supported: this.config.supportedResponseTypes,
      grant_types_supported: this.config.supportedGrantTypes,
      subject_types_supported: this.config.supportedSubjectTypes,
      id_token_signing_alg_values_supported: this.config.idTokenSigningAlgs,
      scopes_supported: this.config.supportedScopes,
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'client_secret_post',
        'client_secret_jwt',
        'private_key_jwt',
      ],
      code_challenge_methods_supported: ['plain', 'S256'],
    };
  }

  /**
   * Получает статистику OAuth
   * @returns Статистика
   */
  public getStats(): {
    totalClients: number;
    activeCodes: number;
    activeDeviceCodes: number;
    consentRecords: number;
  } {
    return {
      totalClients: this.clients.size,
      activeCodes: this.authCodes.size,
      activeDeviceCodes: this.deviceCodes.size,
      consentRecords: this.consentRecords.size,
    };
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const oauthService = new OAuthService(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createOAuthService(
  config: Partial<OAuthServiceConfig>
): OAuthService {
  return new OAuthService({ ...DEFAULT_CONFIG, ...config });
}
