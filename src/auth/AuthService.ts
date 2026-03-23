/**
 * =============================================================================
 * AUTH SERVICE - MAIN AUTHENTICATION SERVICE
 * =============================================================================
 * Основной сервис аутентификации, объединяющий все компоненты
 * Реализует: регистрацию, login, logout, MFA, session management, security
 * Соответствует: NIST 800-63B, OWASP Authentication Cheat Sheet
 * =============================================================================
 */

import { v4 as uuidv4 } from 'uuid';
import { randomBytes } from 'crypto';
import {
  IUser,
  IUserAttributes,
  ISession,
  ISecurityEvent,
  MfaMethodType,
  AuthResult,
  AuthError,
  AuthErrorCode,
  AuthenticationMethod,
  SecurityEventType,
} from '../types/auth.types';
import { PasswordService, createPasswordService } from './PasswordService';
import { JwtService, createJwtService } from './JWTService';
import { MFService, createMFService } from './MFService';
import { WebAuthnService, createWebAuthnService } from './WebAuthnService';
import { SessionManager, createSessionManager } from './SessionManager';
import { RateLimiterService, createRateLimiterService } from './RateLimiter';
import { DeviceFingerprintService, createDeviceFingerprintService } from './DeviceFingerprint';
import { RBACService, createRBACService } from './RBACService';
import { ABACService, createABACService } from './ABACService';
import { SecureLogger, LogSource } from '../logging/Logger';

/**
 * Конфигурация AuthService
 */
export interface AuthServiceConfig {
  /** Issuer для JWT */
  issuer: string;
  
  /** Audience для JWT */
  audience: string;
  
  /** Время жизни access токена (секунды) */
  accessTokenLifetime: number;
  
  /** Время жизни refresh токена (секунды) */
  refreshTokenLifetime: number;
  
  /** Время жизни сессии (секунды) */
  sessionLifetime: number;
  
  /** Максимальное количество failed login attempts */
  maxFailedLoginAttempts: number;
  
  /** Время блокировки после failed attempts (секунды) */
  lockoutDuration: number;
  
  /** Требовать ли MFA для всех пользователей */
  requireMfa: boolean;
  
  /** Разрешить ли remember device */
  allowRememberDevice: boolean;
  
  /** Срок remember device (дни) */
  rememberDeviceDays: number;
  
  /** Redis конфигурация */
  redis: {
    host: string;
    port: number;
    password?: string;
  };
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: AuthServiceConfig = {
  issuer: 'protocol-auth',
  audience: 'protocol-api',
  accessTokenLifetime: 900, // 15 минут
  refreshTokenLifetime: 604800, // 7 дней
  sessionLifetime: 900, // 15 минут
  maxFailedLoginAttempts: 5,
  lockoutDuration: 900, // 15 минут
  requireMfa: false,
  allowRememberDevice: true,
  rememberDeviceDays: 30,
  redis: {
    host: 'localhost',
    port: 6379,
  },
};

/**
 * Входные данные для регистрации
 */
export interface RegisterInput {
  email: string;
  password: string;
  username?: string;
  phone?: string;
  attributes?: IUserAttributes;
}

/**
 * Входные данные для login
 */
export interface LoginInput {
  email: string;
  password: string;
  mfaCode?: string;
  mfaMethod?: MfaMethodType;
  rememberDevice?: boolean;
  userAgent: string;
  ipAddress: string;
  deviceFingerprint?: string;
}

/**
 * Входные данные для MFA setup
 */
export interface MfaSetupInput {
  userId: string;
  method: MfaMethodType;
  label?: string;
}

/**
 * =============================================================================
 * AUTH SERVICE CLASS
 * =============================================================================
 */
export class AuthService {
  private config: AuthServiceConfig;
  private logger: SecureLogger;
  private passwordService: PasswordService;
  private jwtService: JwtService;
  private mfService: MFService;
  private webAuthnService: WebAuthnService;
  private sessionManager: SessionManager;
  private rateLimiter: RateLimiterService;
  private deviceFingerprint: DeviceFingerprintService;
  private rbacService: RBACService;
  private abacService: ABACService;
  
  // Хранилище пользователей (в памяти для примера)
  private users: Map<string, IUser> = new Map();
  private emailIndex: Map<string, string> = new Map();
  
  // Хранилище MFA методов
  private mfaMethods: Map<string, Array<any>> = new Map();
  
  // Хранилище security events
  private securityEvents: ISecurityEvent[] = [];
  
  // Хранилище MFA сессий (временных)
  private mfaSessions: Map<string, {
    userId: string;
    createdAt: Date;
    expiresAt: Date;
    availableMethods: MfaMethodType[];
  }> = new Map();

  /**
   * Создает новый экземпляр AuthService
   * @param config - Конфигурация сервиса
   */
  constructor(config: AuthServiceConfig = DEFAULT_CONFIG) {
    this.config = config;
    
    // Инициализация подсервисов
    this.passwordService = createPasswordService();
    this.jwtService = createJwtService({
      issuer: config.issuer,
      audience: config.audience,
      accessTokenLifetime: config.accessTokenLifetime,
      refreshTokenLifetime: config.refreshTokenLifetime,
    });
    this.mfService = createMFService();
    this.webAuthnService = createWebAuthnService({
      rpName: 'Protocol Messenger',
      rpID: config.issuer.replace(/^https?:\/\//, ''),
      origin: config.issuer,
    });
    this.sessionManager = createSessionManager({
      sessionLifetime: config.sessionLifetime,
      refreshTokenLifetime: config.refreshTokenLifetime,
      redis: config.redis,
    });
    this.rateLimiter = createRateLimiterService({
      redis: config.redis,
    });
    this.deviceFingerprint = createDeviceFingerprintService();
    this.rbacService = createRBACService();
    this.abacService = createABACService();
    
    // Инициализация соединений
    this.initialize();
  }

  /**
   * Инициализирует сервисы
   * @private
   */
  private async initialize(): Promise<void> {
    try {
      await Promise.all([
        this.sessionManager.initialize(),
        this.rateLimiter.initialize(),
        this.jwtService.initialize(),
      ]);
      console.log('[AuthService] Все сервисы инициализированы');
    } catch (error) {
      console.error('[AuthService] Ошибка инициализации:', error);
    }
  }

  // ===========================================================================
  // РЕГИСТРАЦИЯ
  // ===========================================================================

  /**
   * Регистрирует нового пользователя
   * @param input - Данные для регистрации
   * @returns Зарегистрированный пользователь
   */
  public async register(input: RegisterInput): Promise<IUser> {
    // Проверка rate limiting
    const rateLimitResult = await this.rateLimiter.checkRateLimit(
      `register:${input.email}`,
      this.rateLimiter.createAuthRule(input.email)
    );

    if (!rateLimitResult.allowed) {
      this.logSecurityEvent({
        type: 'brute_force_detected',
        ipAddress: 'unknown',
        details: { email: input.email, action: 'register' },
        riskLevel: 'medium',
        riskScore: 50,
      });
      
      throw new AuthError(
        'Слишком много попыток регистрации',
        AuthErrorCode.RATE_LIMIT_EXCEEDED,
        429
      );
    }

    // Проверка существующего email
    if (this.emailIndex.has(input.email.toLowerCase())) {
      throw new AuthError(
        'Пользователь с таким email уже существует',
        AuthErrorCode.INVALID_CREDENTIALS,
        400
      );
    }

    // Валидация сложности пароля
    const passwordStrength = this.passwordService.validatePasswordStrength(input.password);
    if (!passwordStrength.valid) {
      throw new AuthError(
        `Пароль не соответствует требованиям: ${passwordStrength.requirements.join(', ')}`,
        AuthErrorCode.INVALID_CREDENTIALS,
        400,
        { passwordStrength }
      );
    }

    // Хэширование пароля
    const hashResult = await this.passwordService.hashPassword(input.password);

    // Создание пользователя
    const userId = uuidv4();
    const now = new Date();

    const user: IUser = {
      id: userId,
      email: input.email.toLowerCase(),
      passwordHash: hashResult.hash,
      passwordAlgorithm: hashResult.algorithm,
      passwordVersion: hashResult.version,
      username: input.username,
      phone: input.phone,
      status: 'active',
      createdAt: now,
      updatedAt: now,
      failedLoginAttempts: 0,
      requirePasswordChange: false,
      securityPreferences: {
        requireMfa: this.config.requireMfa,
        allowRememberDevice: this.config.allowRememberDevice,
        rememberDeviceDays: this.config.rememberDeviceDays,
        requireNewDeviceConfirmation: true,
        notifyOnNewLogin: true,
        restrictToTrustedIps: false,
        trustedIps: [],
        maxConcurrentSessions: 10,
        reauthIntervalMinutes: 30,
      },
      enabledMfaMethods: [],
      roles: ['user'],
      attributes: input.attributes || {},
    };

    // Сохранение пользователя
    this.users.set(userId, user);
    this.emailIndex.set(user.email, userId);

    // Логирование события
    this.logSecurityEvent({
      type: 'login_success',
      userId,
      ipAddress: 'unknown',
      details: { action: 'register' },
      riskLevel: 'low',
      riskScore: 0,
    });

    return user;
  }

  // ===========================================================================
  // АУТЕНТИФИКАЦИЯ (LOGIN)
  // ===========================================================================

  /**
   * Выполняет аутентификацию пользователя
   * @param input - Данные для входа
   * @returns Результат аутентификации
   */
  public async login(input: LoginInput): Promise<AuthResult> {
    const normalizedEmail = input.email.toLowerCase();

    // Проверка rate limiting
    const rateLimitResult = await this.rateLimiter.checkRateLimit(
      `login:${input.ipAddress}`,
      this.rateLimiter.createAuthRule(input.ipAddress)
    );

    if (!rateLimitResult.allowed) {
      this.logSecurityEvent({
        type: 'brute_force_detected',
        ipAddress: input.ipAddress,
        details: { email: input.email },
        riskLevel: 'high',
        riskScore: 80,
      });
      
      throw new AuthError(
        'Слишком много попыток входа',
        AuthErrorCode.RATE_LIMIT_EXCEEDED,
        429
      );
    }

    // Поиск пользователя
    const userId = this.emailIndex.get(normalizedEmail);
    if (!userId) {
      // Constant-time response для защиты от enumeration
      await this.constantTimeDelay();
      throw new AuthError(
        'Неверный email или пароль',
        AuthErrorCode.INVALID_CREDENTIALS,
        401
      );
    }

    const user = this.users.get(userId);
    if (!user) {
      throw new AuthError(
        'Пользователь не найден',
        AuthErrorCode.INVALID_CREDENTIALS,
        404
      );
    }

    // Проверка статуса аккаунта
    if (user.status === 'locked') {
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        const remainingTime = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000);
        throw new AuthError(
          `Аккаунт заблокирован. Попробуйте через ${remainingTime} секунд`,
          AuthErrorCode.ACCOUNT_LOCKED,
          423,
          { lockedUntil: user.lockedUntil, retryAfter: remainingTime }
        );
      }
      // Блокировка истекла - разблокируем
      user.status = 'active';
      user.lockedUntil = undefined;
    }

    if (user.status !== 'active') {
      throw new AuthError(
        `Аккаунт ${user.status}`,
        AuthErrorCode.ACCOUNT_DISABLED,
        403
      );
    }

    // Проверка пароля
    const verifyResult = await this.passwordService.verifyPassword(
      input.password,
      user.passwordHash
    );

    if (!verifyResult.valid) {
      await this.handleFailedLogin(user);
      
      this.logSecurityEvent({
        type: 'login_failure',
        userId: user.id,
        ipAddress: input.ipAddress,
        details: { email: input.email, reason: 'invalid_password' },
        riskLevel: 'medium',
        riskScore: 40,
      });
      
      throw new AuthError(
        'Неверный email или пароль',
        AuthErrorCode.INVALID_CREDENTIALS,
        401
      );
    }

    // Успешная верификация пароля - сброс failed attempts
    user.failedLoginAttempts = 0;
    user.lockedUntil = undefined;

    // Проверка необходимости смены пароля
    if (user.requirePasswordChange) {
      throw new AuthError(
        'Требуется смена пароля',
        AuthErrorCode.PASSWORD_EXPIRED,
        403,
        { requirePasswordChange: true }
      );
    }

    // Проверка MFA
    const authMethods: AuthenticationMethod[] = [{
      method: 'password',
      authenticatedAt: new Date(),
    }];

    if (user.enabledMfaMethods.length > 0 || this.config.requireMfa) {
      // Требуется MFA
      if (input.mfaCode && input.mfaMethod) {
        // Верификация MFA кода
        const mfaValid = await this.verifyMfaCode(
          user.id,
          input.mfaCode,
          input.mfaMethod
        );

        if (!mfaValid) {
          this.logSecurityEvent({
            type: 'mfa_challenge',
            userId: user.id,
            ipAddress: input.ipAddress,
            details: { method: input.mfaMethod, result: 'failed' },
            riskLevel: 'medium',
            riskScore: 50,
          });
          
          throw new AuthError(
            'Неверный MFA код',
            AuthErrorCode.MFA_INVALID_CODE,
            401
          );
        }

        authMethods.push({
          method: input.mfaMethod,
          authenticatedAt: new Date(),
        });
      } else {
        // Возвращаем запрос на MFA
        const mfaSessionToken = this.createMfaSession(user.id);
        
        return {
          success: false,
          requiresMfa: true,
          availableMfaMethods: user.enabledMfaMethods.length > 0 
            ? user.enabledMfaMethods 
            : ['totp'],
          mfaSessionToken,
          message: 'Требуется MFA аутентификация',
        };
      }
    }

    // Полная аутентификация успешна
    return this.completeAuthentication(user, authMethods, input);
  }

  /**
   * Обрабатывает неудачную попытку входа
   * @private
   */
  private async handleFailedLogin(user: IUser): Promise<void> {
    user.failedLoginAttempts++;

    if (user.failedLoginAttempts >= this.config.maxFailedLoginAttempts) {
      user.status = 'locked';
      user.lockedUntil = new Date(Date.now() + this.config.lockoutDuration * 1000);
      
      this.logSecurityEvent({
        type: 'account_locked',
        userId: user.id,
        ipAddress: 'unknown',
        details: { failedAttempts: user.failedLoginAttempts },
        riskLevel: 'high',
        riskScore: 70,
      });
    }
  }

  /**
   * Завершает аутентификацию и создает сессию
   * @private
   */
  private async completeAuthentication(
    user: IUser,
    authMethods: AuthenticationMethod[],
    input: LoginInput
  ): Promise<AuthResult> {
    // Обновление lastLoginAt
    user.lastLoginAt = new Date();

    // Анализ устройства
    const deviceAnalysis = this.deviceFingerprint.analyzeFingerprint({
      userAgent: input.userAgent,
      languages: [],
      timezone: 'UTC',
      ipAddress: input.ipAddress,
      deviceFingerprint: input.deviceFingerprint,
    });

    // Проверка на account takeover
    const takeoverCheck = this.rateLimiter.detectAccountTakeover(
      user.id,
      deviceAnalysis.isNewDevice,
      false // В production проверить геолокацию
    );

    if (takeoverCheck.detected) {
      this.logSecurityEvent({
        type: 'suspicious_activity',
        userId: user.id,
        ipAddress: input.ipAddress,
        details: { riskFactors: takeoverCheck.factors },
        riskLevel: 'high',
        riskScore: takeoverCheck.riskScore,
      });
    }

    // Создание сессии
    const sessionResult = await this.sessionManager.createSession(
      user,
      input.userAgent,
      input.ipAddress,
      authMethods,
      undefined,
      deviceAnalysis.fingerprint
    );

    // Trust device если запрошено
    if (input.rememberDevice && user.securityPreferences.allowRememberDevice) {
      await this.sessionManager.trustDevice(sessionResult.session.id);
      this.deviceFingerprint.trustDevice(deviceAnalysis.fingerprint, user.id);
    }

    // Генерация JWT токенов
    const accessToken = await this.jwtService.createAccessToken(
      user,
      sessionResult.session,
      authMethods
    );

    const refreshToken = sessionResult.refreshToken;

    // Логирование успешного входа
    this.logSecurityEvent({
      type: 'login_success',
      userId: user.id,
      ipAddress: input.ipAddress,
      details: {
        deviceFingerprint: deviceAnalysis.fingerprint,
        isNewDevice: deviceAnalysis.isNewDevice,
      },
      riskLevel: deviceAnalysis.isNewDevice ? 'medium' : 'low',
      riskScore: deviceAnalysis.riskScore,
    });

    return {
      success: true,
      user,
      session: sessionResult.session,
      accessToken,
      refreshToken,
      message: 'Аутентификация успешна',
    };
  }

  // ===========================================================================
  // MFA МЕТОДЫ
  // ===========================================================================

  /**
   * Создает MFA сессию
   * @private
   */
  private createMfaSession(userId: string): string {
    const token = `mfa_${randomBytes(16).toString('base64url')}`;
    const user = this.users.get(userId);
    
    this.mfaSessions.set(token, {
      userId,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 300000), // 5 минут
      availableMethods: user?.enabledMfaMethods || ['totp'],
    });

    return token;
  }

  /**
   * Инициализирует TOTP для пользователя
   * @param input - Данные для настройки
   * @returns TOTP секрет и QR URL
   */
  public async setupTotp(input: MfaSetupInput): Promise<{
    secret: string;
    otpauthUrl: string;
    methodId: string;
  }> {
    const user = this.users.get(input.userId);
    if (!user) {
      throw new AuthError('Пользователь не найден', AuthErrorCode.MFA_METHOD_NOT_FOUND, 404);
    }

    const result = this.mfService.generateTotpSecret(
      input.userId,
      input.label || user.email,
      'Protocol'
    );

    return {
      secret: result.secret,
      otpauthUrl: result.otpauthUrl,
      methodId: result.methodId,
    };
  }

  /**
   * Верифицирует и активирует TOTP
   * @param userId - ID пользователя
   * @param code - TOTP код
   * @param secret - Секрет
   * @param methodId - ID метода
   */
  public async verifyAndActivateTotp(
    userId: string,
    code: string,
    secret: string,
    methodId: string
  ): Promise<void> {
    const user = this.users.get(userId);
    if (!user) {
      throw new AuthError('Пользователь не найден', AuthErrorCode.MFA_METHOD_NOT_FOUND, 404);
    }

    const verifyResult = this.mfService.verifyTotpCode(code, secret);
    
    if (!verifyResult.valid) {
      throw new AuthError('Неверный TOTP код', AuthErrorCode.MFA_INVALID_CODE, 401);
    }

    // Добавление метода в список
    const methods = this.mfaMethods.get(userId) || [];
    methods.push({
      id: methodId,
      type: 'totp' as MfaMethodType,
      secret,
      status: 'active',
      isDefault: methods.length === 0,
      createdAt: new Date(),
    });
    this.mfaMethods.set(userId, methods);

    // Обновление пользователя
    if (!user.enabledMfaMethods.includes('totp')) {
      user.enabledMfaMethods.push('totp');
    }
  }

  /**
   * Верифицирует MFA код
   * @private
   */
  private async verifyMfaCode(
    userId: string,
    code: string,
    method: MfaMethodType
  ): Promise<boolean> {
    const methods = this.mfaMethods.get(userId) || [];
    const methodData = methods.find(m => m.type === method);

    if (!methodData) {
      return false;
    }

    switch (method) {
      case 'totp':
        return this.mfService.verifyTotpCode(code, methodData.secret).valid;
      
      case 'hotp':
        const hotpResult = this.mfService.verifyHotpCode(code, methodData.secret, methodData.counter || 0);
        if (hotpResult.valid && hotpResult.newCounter) {
          methodData.counter = hotpResult.newCounter;
        }
        return hotpResult.valid;
      
      case 'backup_code':
        const backupCodes = methodData.backupCodes || [];
        const verifyResult = this.mfService.verifyBackupCode(code, backupCodes);
        if (verifyResult.valid && verifyResult.usedCodeId) {
          // Помечаем код как использованный
          const codeIndex = backupCodes.findIndex(c => c.id === verifyResult.usedCodeId);
          if (codeIndex !== -1) {
            backupCodes[codeIndex].used = true;
          }
        }
        return verifyResult.valid;
      
      default:
        return false;
    }
  }

  /**
   * Генерирует backup коды
   * @param userId - ID пользователя
   * @returns Backup коды (plain text - показать только один раз!)
   */
  public async generateBackupCodes(userId: string): Promise<{
    codes: string[];
    codeSetId: string;
  }> {
    const user = this.users.get(userId);
    if (!user) {
      throw new AuthError('Пользователь не найден', AuthErrorCode.MFA_METHOD_NOT_FOUND, 404);
    }

    const result = this.mfService.generateBackupCodes(userId);
    
    // Сохранение хешированных кодов
    const methods = this.mfaMethods.get(userId) || [];
    methods.push({
      id: result.codeSet.id,
      type: 'backup_code' as MfaMethodType,
      backupCodes: result.hashedCodes,
      status: 'active',
      createdAt: new Date(),
    });
    this.mfaMethods.set(userId, methods);

    return {
      codes: result.codes,
      codeSetId: result.codeSet.id,
    };
  }

  // ===========================================================================
  // LOGOUT
  // ===========================================================================

  /**
   * Выполняет logout пользователя
   * @param sessionId - ID сессии
   */
  public async logout(sessionId: string): Promise<void> {
    await this.sessionManager.terminateSession(sessionId);
    
    this.logSecurityEvent({
      type: 'logout',
      ipAddress: 'unknown',
      details: { sessionId },
      riskLevel: 'low',
      riskScore: 0,
    });
  }

  /**
   * Logout со всех устройств
   * @param userId - ID пользователя
   */
  public async logoutAll(userId: string): Promise<void> {
    await this.sessionManager.terminateAllUserSessions(userId);
    
    this.logSecurityEvent({
      type: 'logout',
      userId,
      ipAddress: 'unknown',
      details: { action: 'logout_all' },
      riskLevel: 'low',
      riskScore: 0,
    });
  }

  // ===========================================================================
  // REFRESH TOKEN
  // ===========================================================================

  /**
   * Обновляет токены с помощью refresh token
   * @param refreshToken - Refresh token
   * @param sessionId - ID сессии
   * @returns Новые токены
   */
  public async refreshTokens(
    refreshToken: string,
    sessionId: string
  ): Promise<{
    accessToken: string;
    refreshToken: string;
  }> {
    // Валидация refresh token
    const validation = await this.sessionManager.validateRefreshToken(
      sessionId,
      refreshToken
    );

    if (!validation.valid || !validation.session) {
      throw new AuthError(
        validation.error || 'Неверный refresh token',
        AuthErrorCode.TOKEN_INVALID,
        401
      );
    }

    // Rotation refresh token
    const rotationResult = await this.sessionManager.rotateRefreshToken(
      sessionId,
      refreshToken
    );

    if (!rotationResult.success || !rotationResult.newRefreshToken) {
      throw new AuthError(
        'Ошибка обновления токена',
        AuthErrorCode.TOKEN_INVALID,
        401
      );
    }

    // Получение пользователя
    const user = this.users.get(validation.session.userId);
    if (!user) {
      throw new AuthError('Пользователь не найден', AuthErrorCode.INTERNAL_ERROR, 500);
    }

    // Генерация нового access token
    const accessToken = await this.jwtService.createAccessToken(
      user,
      validation.session,
      validation.session.authenticationMethods
    );

    return {
      accessToken,
      refreshToken: rotationResult.newRefreshToken,
    };
  }

  // ===========================================================================
  // SECURITY EVENTS
  // ===========================================================================

  /**
   * Логирует security событие
   * @private
   */
  private logSecurityEvent(event: Omit<ISecurityEvent, 'id' | 'timestamp'>): void {
    const securityEvent: ISecurityEvent = {
      ...event,
      id: uuidv4(),
      timestamp: new Date(),
    };

    this.securityEvents.push(securityEvent);

    // Ограничение размера
    if (this.securityEvents.length > 10000) {
      this.securityEvents.shift();
    }

    console.log(`[SecurityEvent] ${event.type}:`, {
      userId: event.userId,
      ipAddress: event.ipAddress,
      riskLevel: event.riskLevel,
      riskScore: event.riskScore,
    });
  }

  /**
   * Получает security events
   * @param userId - ID пользователя (опционально)
   * @param limit - Максимальное количество
   * @returns Security events
   */
  public getSecurityEvents(userId?: string, limit: number = 100): ISecurityEvent[] {
    let events = this.securityEvents;
    
    if (userId) {
      events = events.filter(e => e.userId === userId);
    }

    return events.slice(-limit);
  }

  // ===========================================================================
  // УТИЛИТЫ
  // ===========================================================================

  /**
   * Constant-time delay для защиты от timing attacks
   * @private
   */
  private async constantTimeDelay(): Promise<void> {
    // Случайная задержка 50-150ms
    const delay = 50 + Math.random() * 100;
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Получает пользователя по ID
   * @param userId - ID пользователя
   * @returns Пользователь или null
   */
  public getUserById(userId: string): IUser | null {
    return this.users.get(userId) || null;
  }

  /**
   * Получает пользователя по email
   * @param email - Email
   * @returns Пользователь или null
   */
  public getUserByEmail(email: string): IUser | null {
    const userId = this.emailIndex.get(email.toLowerCase());
    if (!userId) return null;
    return this.users.get(userId) || null;
  }

  /**
   * Закрывает сервис
   */
  public async destroy(): Promise<void> {
    await Promise.all([
      this.sessionManager.destroy(),
      this.rateLimiter.destroy(),
    ]);
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const authService = new AuthService(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createAuthService(config: Partial<AuthServiceConfig>): AuthService {
  return new AuthService({ ...DEFAULT_CONFIG, ...config });
}
