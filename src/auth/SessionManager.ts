/**
 * =============================================================================
 * SESSION MANAGER
 * =============================================================================
 * Менеджер сессий с поддержкой Redis, secure cookies, rotation
 * Соответствует: OWASP Session Management Cheat Sheet
 * Реализует: Secure cookie flags, session fixation protection, concurrent session limits
 * Интеграция: JWT Blacklist для отзыва токенов
 * =============================================================================
 */

import { createHash, randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import Redis from 'ioredis';
import {
  ISession,
  SessionStatus,
  SessionType,
  IUser,
  AuthenticationMethod,
  AuthError,
  AuthErrorCode,
} from '../types/auth.types';
import { JwtService } from './JWTService';
import { JWTBlacklist } from './JWTBlacklist';
import { logger } from '../logging/Logger';

/**
 * Конфигурация Session Manager
 */
export interface SessionManagerConfig {
  /** Префикс для ключей Redis */
  keyPrefix: string;
  
  /** Время жизни сессии (секунды) */
  sessionLifetime: number;
  
  /** Абсолютное время жизни сессии (секунды) */
  absoluteSessionLifetime: number;
  
  /** Время жизни refresh токена (секунды) */
  refreshTokenLifetime: number;
  
  /** Максимальное количество одновременных сессий */
  maxConcurrentSessions: number;
  
  /** Продлевать ли сессию при активности */
  rollingSession: boolean;
  
  /** Интервал продления сессии (секунды) */
  rollingInterval: number;
  
  /** Настройки cookie */
  cookie: {
    /** Имя cookie */
    name: string;
    /** Domain */
    domain?: string;
    /** Path */
    path: string;
    /** Secure flag */
    secure: boolean;
    /** HttpOnly flag */
    httpOnly: boolean;
    /** SameSite */
    sameSite: 'strict' | 'lax' | 'none';
    /** Max-Age (секунды) */
    maxAge: number;
  };
  
  /** Redis конфигурация */
  redis: {
    host: string;
    port: number;
    password?: string;
    db?: number;
    tls?: Record<string, any>;
  };
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: SessionManagerConfig = {
  keyPrefix: 'protocol:session:',
  sessionLifetime: 900, // 15 минут
  absoluteSessionLifetime: 604800, // 7 дней
  refreshTokenLifetime: 604800, // 7 дней
  maxConcurrentSessions: 10,
  rollingSession: true,
  rollingInterval: 300, // 5 минут
  cookie: {
    name: 'protocol_session',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 900,
  },
  redis: {
    host: 'localhost',
    port: 6379,
    db: 0,
  },
};

/**
 * Сериализованная сессия для хранения в Redis
 */
interface SerializedSession {
  id: string;
  userId: string;
  type: SessionType;
  status: SessionStatus;
  refreshTokenHash: string;
  refreshTokenFamily: string;
  deviceId?: string;
  userAgent: string;
  ipAddress: string;
  geoLocation?: ISession['geoLocation'];
  deviceFingerprint?: string;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
  absoluteExpiresAt: string;
  authenticationMethods: AuthenticationMethod[];
  authenticationLevel: ISession['authenticationLevel'];
  permissions?: string[];
  context: ISession['context'];
  metadata: ISession['metadata'];
}

/**
 * Результат создания сессии
 */
export interface SessionCreateResult {
  session: ISession;
  refreshToken: string;
  refreshTokenFamily: string;
  cookieOptions: {
    name: string;
    value: string;
    options: SessionManagerConfig['cookie'];
  };
}

/**
 * Результат валидации сессии
 */
export interface SessionValidationResult {
  valid: boolean;
  session?: ISession;
  error?: string;
  requiresRefresh?: boolean;
}

/**
 * =============================================================================
 * SESSION MANAGER CLASS
 * =============================================================================
 */
export class SessionManager {
  private config: SessionManagerConfig;
  private redis: Redis | null = null;
  private readonly sessionIndexKey = 'protocol:sessions:index:';
  private jwtService: JwtService | null = null;
  private blacklist: JWTBlacklist | null = null;

  /**
   * Создает новый экземпляр SessionManager
   * @param config - Конфигурация менеджера
   */
  constructor(config: SessionManagerConfig = DEFAULT_CONFIG) {
    this.config = config;
  }

  /**
   * Инициализирует соединение с Redis
   * @param dependencies - Зависимости (опционально)
   */
  public async initialize(dependencies?: {
    jwtService?: JwtService;
    blacklist?: JWTBlacklist;
  }): Promise<void> {
    try {
      this.redis = new Redis({
        host: this.config.redis.host,
        port: this.config.redis.port,
        password: this.config.redis.password,
        db: this.config.redis.db,
        tls: this.config.redis.tls,
        retryStrategy: (times) => {
          if (times > 10) {
            return null; // Прекратить попытки
          }
          return Math.min(times * 50, 2000);
        },
      });

      this.redis.on('error', (err) => {
        logger.error('[SessionManager] Redis error', { error: err });
      });

      this.redis.on('connect', () => {
        logger.info('[SessionManager] Connected to Redis');
      });

      // Тестовое подключение
      await this.redis.ping();

      // Инициализация зависимостей
      if (dependencies?.jwtService) {
        this.jwtService = dependencies.jwtService;
      }

      if (dependencies?.blacklist) {
        this.blacklist = dependencies.blacklist;
      }
    } catch (error) {
      logger.warn('[SessionManager] Failed to connect to Redis, using in-memory storage');
      this.redis = null;
    }
  }

  // ===========================================================================
  // СОЗДАНИЕ СЕССИИ
  // ===========================================================================

  /**
   * Создает новую сессию для пользователя
   * @param user - Пользователь
   * @param userAgent - User-Agent строка
   * @param ipAddress - IP адрес
   * @param authMethods - Методы аутентификации
   * @param deviceId - ID устройства (опционально)
   * @param deviceFingerprint - Отпечаток устройства (опционально)
   * @returns Результат создания сессии
   */
  public async createSession(
    user: Pick<IUser, 'id' | 'securityPreferences'>,
    userAgent: string,
    ipAddress: string,
    authMethods: AuthenticationMethod[],
    deviceId?: string,
    deviceFingerprint?: string
  ): Promise<SessionCreateResult> {
    const now = new Date();
    const sessionId = uuidv4();
    const refreshTokenFamily = uuidv4();
    const refreshToken = this.generateRefreshToken();
    const refreshTokenHash = this.hashRefreshToken(refreshToken);

    // Проверка лимита сессий
    await this.enforceSessionLimit(user.id, user.securityPreferences.maxConcurrentSessions);

    // Получение geo-информации
    const geoLocation = await this.getGeoLocation(ipAddress);

    // Создание объекта сессии
    const session: ISession = {
      id: sessionId,
      userId: user.id,
      type: 'web',
      status: 'active',
      refreshTokenHash,
      refreshTokenFamily,
      deviceId,
      userAgent,
      ipAddress,
      geoLocation: geoLocation || undefined,
      deviceFingerprint,
      createdAt: now,
      lastUsedAt: now,
      expiresAt: new Date(now.getTime() + this.config.sessionLifetime * 1000),
      absoluteExpiresAt: new Date(now.getTime() + this.config.absoluteSessionLifetime * 1000),
      authenticationMethods: authMethods,
      authenticationLevel: this.calculateAuthenticationLevel(authMethods),
      permissions: [],
      context: {
        isDeviceTrusted: false,
        isDeviceVerified: false,
        requiresReauth: false,
        jitElevated: false,
      },
      metadata: {
        clientName: this.extractClientName(userAgent),
        platform: this.extractPlatform(userAgent),
        language: 'ru',
      },
    };

    // Сохранение сессии
    await this.saveSession(session);

    // Добавление в индекс сессий пользователя
    await this.addToUserSessionIndex(user.id, sessionId);

    // Генерация cookie
    const cookieOptions = {
      name: this.config.cookie.name,
      value: sessionId,
      options: {
        ...this.config.cookie,
        maxAge: this.config.sessionLifetime,
      },
    };

    return {
      session,
      refreshToken,
      refreshTokenFamily,
      cookieOptions,
    };
  }

  /**
   * Генерирует безопасный refresh токен
   * @private
   */
  private generateRefreshToken(): string {
    // Формат: rt_<base64url random bytes>
    const randomData = randomBytes(32);
    return `rt_${randomData.toString('base64url')}`;
  }

  /**
   * Хэширует refresh токен для хранения
   * @private
   */
  private hashRefreshToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  /**
   * Вычисляет уровень аутентификации на основе использованных методов
   * @private
   */
  private calculateAuthenticationLevel(
    authMethods: AuthenticationMethod[]
  ): { ial: 1 | 2 | 3; aal: 1 | 2 | 3 } {
    // AAL (Authenticator Assurance Level) по NIST 800-63B
    let aal: 1 | 2 | 3 = 1;

    const hasPassword = authMethods.some(m => m.method === 'password');
    const hasMfa = authMethods.some(m => 
      ['totp', 'hotp', 'webauthn', 'sms', 'email'].includes(m.method)
    );
    const hasWebAuthn = authMethods.some(m => m.method === 'webauthn');

    if (hasWebAuthn) {
      aal = 3; // WebAuthn = AAL3
    } else if (hasMfa) {
      aal = 2; // MFA = AAL2
    } else if (hasPassword) {
      aal = 1; // Password only = AAL1
    }

    // IAL (Identity Assurance Level) - упрощенно
    const ial: 1 | 2 | 3 = aal >= 2 ? 2 : 1;

    return { ial, aal };
  }

  // ===========================================================================
  // ВАЛИДАЦИЯ СЕССИИ
  // ===========================================================================

  /**
   * Проверяет валидность сессии по ID
   * @param sessionId - ID сессии
   * @param options - Опции проверки
   * @returns Результат валидации
   */
  public async validateSession(
    sessionId: string,
    options?: {
      /** Проверять IP адрес */
      checkIpAddress?: boolean;
      /** Ожидаемый IP адрес */
      expectedIpAddress?: string;
      /** Проверять user-agent */
      checkUserAgent?: boolean;
      /** Ожидаемый user-agent */
      expectedUserAgent?: string;
    }
  ): Promise<SessionValidationResult> {
    try {
      const session = await this.getSession(sessionId);

      if (!session) {
        return {
          valid: false,
          error: 'Сессия не найдена',
        };
      }

      // Проверка статуса
      if (session.status !== 'active') {
        return {
          valid: false,
          error: `Сессия ${session.status}`,
        };
      }

      // Проверка истечения
      const now = new Date();
      if (session.expiresAt < now) {
        await this.updateSessionStatus(sessionId, 'expired');
        return {
          valid: false,
          error: 'Срок действия сессии истек',
          requiresRefresh: true,
        };
      }

      // Проверка абсолютного истечения
      if (session.absoluteExpiresAt < now) {
        await this.updateSessionStatus(sessionId, 'expired');
        return {
          valid: false,
          error: 'Абсолютный срок действия сессии истек',
          requiresRefresh: true,
        };
      }

      // Проверка IP адреса
      if (options?.checkIpAddress && options.expectedIpAddress) {
        if (session.ipAddress !== options.expectedIpAddress) {
          // Подозрительная активность - смена IP
          return {
            valid: false,
            error: 'IP адрес не совпадает',
          };
        }
      }

      // Проверка User-Agent
      if (options?.checkUserAgent && options.expectedUserAgent) {
        if (!this.userAgentSimilarity(session.userAgent, options.expectedUserAgent)) {
          return {
            valid: false,
            error: 'User-Agent не совпадает',
          };
        }
      }

      // Продление сессии если rollingSession включен
      if (this.config.rollingSession) {
        await this.extendSession(sessionId);
      }

      // Обновление lastUsedAt
      await this.updateSessionLastUsed(sessionId);

      return {
        valid: true,
        session,
      };
    } catch (error) {
      logger.error('[SessionManager] Ошибка валидации сессии', { error });
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Ошибка валидации',
      };
    }
  }

  /**
   * Проверяет refresh токен
   * @param sessionId - ID сессии
   * @param refreshToken - Refresh токен
   * @returns Верен ли токен
   */
  public async validateRefreshToken(
    sessionId: string,
    refreshToken: string
  ): Promise<{ valid: boolean; session?: ISession; error?: string }> {
    const session = await this.getSession(sessionId);

    if (!session) {
      return { valid: false, error: 'Сессия не найдена' };
    }

    if (session.status !== 'active') {
      return { valid: false, error: `Сессия ${session.status}` };
    }

    const tokenHash = this.hashRefreshToken(refreshToken);
    if (tokenHash !== session.refreshTokenHash) {
      // Возможная атака - все токены семьи должны быть отозваны
      await this.revokeRefreshTokenFamily(session.refreshTokenFamily);
      return {
        valid: false,
        error: 'Неверный refresh токен - возможна атака',
      };
    }

    return { valid: true, session };
  }

  // ===========================================================================
  // УПРАВЛЕНИЕ СЕССИЯМИ
  // ===========================================================================

  /**
   * Сохраняет сессию в хранилище
   * @private
   */
  private async saveSession(session: ISession): Promise<void> {
    const key = `${this.config.keyPrefix}${session.id}`;
    const serialized = this.serializeSession(session);
    const ttl = Math.max(
      Math.floor((session.expiresAt.getTime() - Date.now()) / 1000),
      60
    );

    if (this.redis) {
      await this.redis.setex(key, ttl, JSON.stringify(serialized));
    } else {
      // Fallback: in-memory storage (для development)
      // В production всегда использовать Redis
      logger.warn('[SessionManager] Using in-memory storage (not recommended for production)');
    }
  }

  /**
   * Получает сессию из хранилища
   * @param sessionId - ID сессии
   * @returns Сессия или null
   */
  public async getSession(sessionId: string): Promise<ISession | null> {
    const key = `${this.config.keyPrefix}${sessionId}`;

    if (this.redis) {
      const data = await this.redis.get(key);
      if (!data) return null;
      return this.deserializeSession(JSON.parse(data));
    }

    return null;
  }

  /**
   * Обновляет статус сессии
   * @param sessionId - ID сессии
   * @param status - Новый статус
   */
  public async updateSessionStatus(
    sessionId: string,
    status: SessionStatus
  ): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      session.status = status;
      await this.saveSession(session);
    }
  }

  /**
   * Обновляет время последнего использования
   * @param sessionId - ID сессии
   */
  public async updateSessionLastUsed(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      session.lastUsedAt = new Date();
      await this.saveSession(session);
    }
  }

  /**
   * Продлевает сессию
   * @param sessionId - ID сессии
   */
  public async extendSession(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      const now = new Date();
      
      // Проверка абсолютного истечения
      if (session.absoluteExpiresAt > now) {
        session.expiresAt = new Date(now.getTime() + this.config.sessionLifetime * 1000);
        session.lastUsedAt = now;
        await this.saveSession(session);
      }
    }
  }

  /**
   * Завершает сессию (logout)
   * @param sessionId - ID сессии
   * @param options - Опции завершения
   */
  public async terminateSession(
    sessionId: string,
    options?: {
      /** Добавить токены в blacklist */
      addToBlacklist?: boolean;
      /** Причина отзыва */
      reason?: string;
    }
  ): Promise<void> {
    const session = await this.getSession(sessionId);
    
    // Добавляем в blacklist перед завершением сессии
    if (options?.addToBlacklist !== false && this.blacklist && session) {
      try {
        // Вычисляем TTL до истечения сессии
        const ttl = Math.max(
          Math.floor((session.expiresAt.getTime() - Date.now()) / 1000),
          60
        );

        await this.blacklist.revokeToken(sessionId, ttl, {
          sessionId,
          userId: session.userId,
          deviceId: session.deviceId,
          reason: options?.reason || 'User logout',
        });

        logger.info(`[SessionManager] Токен сессии ${sessionId} добавлен в blacklist`);
      } catch (error) {
        logger.error('[SessionManager] Ошибка добавления в blacklist', { error });
        // Не блокируем logout при ошибке blacklist
      }
    }

    await this.updateSessionStatus(sessionId, 'terminated');

    const key = `${this.config.keyPrefix}${sessionId}`;
    if (this.redis) {
      await this.redis.del(key);
    }

    // Удаление из индекса
    if (session) {
      await this.removeFromUserSessionIndex(session.userId, sessionId);
    }
  }

  /**
   * Завершает все сессии пользователя
   * @param userId - ID пользователя
   * @param options - Опции завершения
   */
  public async terminateAllUserSessions(
    userId: string,
    options?: {
      /** Добавить токены в blacklist */
      addToBlacklist?: boolean;
      /** Причина отзыва */
      reason?: string;
    }
  ): Promise<void> {
    const sessionIds = await this.getUserSessionIds(userId);

    // Если нужно добавить в blacklist, делаем это массово
    if (options?.addToBlacklist !== false && this.blacklist) {
      try {
        const ttl = this.config.sessionLifetime;
        await this.blacklist.revokeUserTokens(userId, ttl, options?.reason || undefined);
        logger.info(`[SessionManager] Все токены пользователя ${userId} добавлены в blacklist`);
      } catch (error) {
        logger.error('[SessionManager] Ошибка добавления в blacklist', { error });
      }
    }

    for (const sessionId of sessionIds) {
      await this.terminateSession(sessionId, { addToBlacklist: false });
    }
  }

  /**
   * Принудительно завершает сессию (например, при смене пароля)
   * @param sessionId - ID сессии
   * @param reason - Причина
   * @param addToBlacklist - Добавить ли токены в blacklist
   */
  public async revokeSession(
    sessionId: string,
    reason?: string,
    addToBlacklist: boolean = true
  ): Promise<void> {
    const session = await this.getSession(sessionId);
    
    if (session) {
      // Добавляем в blacklist
      if (addToBlacklist && this.blacklist) {
        try {
          const ttl = Math.max(
            Math.floor((session.expiresAt.getTime() - Date.now()) / 1000),
            60
          );

          await this.blacklist.revokeToken(sessionId, ttl, {
            sessionId,
            userId: session.userId,
            deviceId: session.deviceId,
            reason: reason || 'Session revoked',
          });

          logger.info(`[SessionManager] Токен сессии ${sessionId} добавлен в blacklist: ${reason}`);
        } catch (error) {
          logger.error('[SessionManager] Ошибка добавления в blacklist', { error });
        }
      }

      session.status = 'revoked';
      await this.saveSession(session);

      // Логирование причины
      logger.info(`[SessionManager] Session ${sessionId} revoked`, { reason: reason || 'No reason provided' });
    }
  }

  // ===========================================================================
  // REFRESH TOKEN ROTATION
  // ===========================================================================

  /**
   * Ротирует refresh токен
   * @param sessionId - ID сессии
   * @param oldRefreshToken - Старый refresh токен
   * @returns Новый refresh токен или ошибка
   */
  public async rotateRefreshToken(
    sessionId: string,
    oldRefreshToken: string
  ): Promise<{ success: boolean; newRefreshToken?: string; error?: string }> {
    const validation = await this.validateRefreshToken(sessionId, oldRefreshToken);

    if (!validation.valid || !validation.session) {
      return {
        success: false,
        error: validation.error,
      };
    }

    const session = validation.session;
    const newRefreshToken = this.generateRefreshToken();
    const newRefreshTokenHash = this.hashRefreshToken(newRefreshToken);

    // Обновление сессии
    session.refreshTokenHash = newRefreshTokenHash;
    session.lastUsedAt = new Date();
    await this.saveSession(session);

    // Отзыв старой семьи токенов (защита от replay attacks)
    // Используем blacklist если доступен
    if (this.blacklist) {
      try {
        await this.blacklist.revokeToken(sessionId, this.config.refreshTokenLifetime, {
          sessionId,
          userId: session.userId,
          reason: 'Refresh token rotation - old token revoked',
        });
      } catch (error) {
        logger.error('[SessionManager] Ошибка добавления в blacklist при rotation', { error });
      }
    } else {
      // Fallback: старая реализация
      await this.revokeRefreshTokenFamily(session.refreshTokenFamily);
    }

    return {
      success: true,
      newRefreshToken,
    };
  }

  /**
   * Отзывает все токены семьи
   * @param family - ID семьи токенов
   */
  private async revokeRefreshTokenFamily(family: string): Promise<void> {
    // В production реализовать через blacklist в Redis
    const key = `protocol:revoked:family:${family}`;
    if (this.redis) {
      await this.redis.setex(key, this.config.refreshTokenLifetime, 'revoked');
    }
  }

  // ===========================================================================
  // УПРАВЛЕНИЕ СЕССИЯМИ ПОЛЬЗОВАТЕЛЯ
  // ===========================================================================

  /**
   * Получает все активные сессии пользователя
   * @param userId - ID пользователя
   * @returns Массив сессий
   */
  public async getUserSessions(userId: string): Promise<ISession[]> {
    const sessionIds = await this.getUserSessionIds(userId);
    const sessions: ISession[] = [];

    for (const sessionId of sessionIds) {
      const session = await this.getSession(sessionId);
      if (session && session.status === 'active') {
        sessions.push(session);
      }
    }

    return sessions;
  }

  /**
   * Получает ID всех сессий пользователя
   * @private
   */
  private async getUserSessionIds(userId: string): Promise<string[]> {
    const indexKey = `${this.sessionIndexKey}${userId}`;
    
    if (this.redis) {
      const members = await this.redis.smembers(indexKey);
      return members || [];
    }

    return [];
  }

  /**
   * Добавляет сессию в индекс пользователя
   * @private
   */
  private async addToUserSessionIndex(userId: string, sessionId: string): Promise<void> {
    const indexKey = `${this.sessionIndexKey}${userId}`;
    
    if (this.redis) {
      await this.redis.sadd(indexKey, sessionId);
      await this.redis.expire(indexKey, this.config.absoluteSessionLifetime);
    }
  }

  /**
   * Удаляет сессию из индекса пользователя
   * @private
   */
  private async removeFromUserSessionIndex(userId: string, sessionId: string): Promise<void> {
    const indexKey = `${this.sessionIndexKey}${userId}`;
    
    if (this.redis) {
      await this.redis.srem(indexKey, sessionId);
    }
  }

  /**
   * Принудительно ограничивает количество сессий
   * @private
   */
  private async enforceSessionLimit(
    userId: string,
    maxSessions?: number
  ): Promise<void> {
    const limit = maxSessions || this.config.maxConcurrentSessions;
    const sessions = await this.getUserSessions(userId);

    if (sessions.length >= limit) {
      // Сортировка по lastUsedAt и удаление самых старых
      sessions.sort((a, b) => a.lastUsedAt.getTime() - b.lastUsedAt.getTime());
      
      const sessionsToRemove = sessions.slice(0, sessions.length - limit + 1);
      for (const session of sessionsToRemove) {
        await this.terminateSession(session.id);
      }
    }
  }

  // ===========================================================================
  // TRUSTED DEVICES
  // ===========================================================================

  /**
   * Отмечает устройство как доверенное
   * @param sessionId - ID сессии
   */
  public async trustDevice(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      session.context.isDeviceTrusted = true;
      session.context.isDeviceVerified = true;
      await this.saveSession(session);
    }
  }

  /**
   * Проверяет, является ли устройство доверенным
   * @param sessionId - ID сессии
   */
  public async isDeviceTrusted(sessionId: string): Promise<boolean> {
    const session = await this.getSession(sessionId);
    return session?.context.isDeviceTrusted ?? false;
  }

  // ===========================================================================
  // JIT ACCESS (Just-In-Time Privilege Elevation)
  // ===========================================================================

  /**
   * Предоставляет временный elevated access
   * @param sessionId - ID сессии
   * @param permissions - Разрешения
   * @param durationMinutes - Длительность (минуты)
   */
  public async grantJitAccess(
    sessionId: string,
    permissions: string[],
    durationMinutes: number = 15
  ): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      session.context.jitElevated = true;
      session.context.jitElevatedAt = new Date();
      session.context.jitExpiresAt = new Date(Date.now() + durationMinutes * 60 * 1000);
      session.permissions = permissions;
      await this.saveSession(session);
    }
  }

  /**
   * Проверяет активный JIT access
   * @param sessionId - ID сессии
   * @returns Активен ли JIT access
   */
  public async isJitAccessActive(sessionId: string): Promise<boolean> {
    const session = await this.getSession(sessionId);
    if (!session?.context.jitElevated) return false;

    if (session.context.jitExpiresAt && session.context.jitExpiresAt < new Date()) {
      // JIT access истек
      session.context.jitElevated = false;
      session.permissions = [];
      await this.saveSession(session);
      return false;
    }

    return true;
  }

  /**
   * Отзывает JIT access
   * @param sessionId - ID сессии
   */
  public async revokeJitAccess(sessionId: string): Promise<void> {
    const session = await this.getSession(sessionId);
    if (session) {
      session.context.jitElevated = false;
      session.context.jitElevatedAt = undefined;
      session.context.jitExpiresAt = undefined;
      session.permissions = [];
      await this.saveSession(session);
    }
  }

  // ===========================================================================
  // УТИЛИТЫ
  // ===========================================================================

  /**
   * Сериализует сессию для хранения
   * @private
   */
  private serializeSession(session: ISession): SerializedSession {
    return {
      ...session,
      createdAt: session.createdAt.toISOString(),
      lastUsedAt: session.lastUsedAt.toISOString(),
      expiresAt: session.expiresAt.toISOString(),
      absoluteExpiresAt: session.absoluteExpiresAt.toISOString(),
    };
  }

  /**
   * Десериализует сессию из хранилища
   * @private
   */
  private deserializeSession(data: SerializedSession): ISession {
    return {
      ...data,
      createdAt: new Date(data.createdAt),
      lastUsedAt: new Date(data.lastUsedAt),
      expiresAt: new Date(data.expiresAt),
      absoluteExpiresAt: new Date(data.absoluteExpiresAt),
    };
  }

  /**
   * Проверяет схожесть User-Agent
   * @private
   */
  private userAgentSimilarity(ua1: string, ua2: string): boolean {
    // Упрощенная проверка - основные компоненты должны совпадать
    const extractBrowser = (ua: string) => {
      const match = ua.match(/(Chrome|Firefox|Safari|Edge|Opera)[\/\s](\d+)/);
      return match ? `${match[1]}${match[2]}` : ua;
    };

    return extractBrowser(ua1) === extractBrowser(ua2);
  }

  /**
   * Извлекает название клиента из User-Agent
   * @private
   */
  private extractClientName(userAgent: string): string {
    if (/Chrome/.test(userAgent)) return 'Chrome';
    if (/Firefox/.test(userAgent)) return 'Firefox';
    if (/Safari/.test(userAgent)) return 'Safari';
    if (/Edge/.test(userAgent)) return 'Edge';
    if (/Opera/.test(userAgent)) return 'Opera';
    return 'Unknown';
  }

  /**
   * Извлекает платформу из User-Agent
   * @private
   */
  private extractPlatform(userAgent: string): string {
    if (/Windows/.test(userAgent)) return 'Windows';
    if (/Mac OS/.test(userAgent)) return 'macOS';
    if (/Linux/.test(userAgent)) return 'Linux';
    if (/Android/.test(userAgent)) return 'Android';
    if (/iPhone|iPad/.test(userAgent)) return 'iOS';
    return 'Unknown';
  }

  /**
   * Получает geo-информацию из IP
   * @private
   */
  private async getGeoLocation(ipAddress: string): Promise<ISession['geoLocation'] | null> {
    // Упрощенная реализация - в production использовать geoip-lite или API
    try {
      const geoip = await import('geoip-lite');
      const geo = geoip.lookup(ipAddress);
      if (geo) {
        return {
          country: geo.country,
          region: geo.region || '',
          city: geo.city || '',
          latitude: geo.ll[0],
          longitude: geo.ll[1],
          timezone: geo.timezone || 'UTC',
        };
      }
    } catch {
      // geoip-lite не установлен
    }
    return null;
  }

  /**
   * Генерирует заголовки для secure cookie
   * @param sessionId - ID сессии
   * @returns Заголовок Set-Cookie
   */
  public generateCookieHeader(sessionId: string): string {
    const { name, ...options } = this.config.cookie;
    const parts = [`${name}=${sessionId}`];

    if (options.secure) parts.push('Secure');
    if (options.httpOnly) parts.push('HttpOnly');
    if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
    if (options.path) parts.push(`Path=${options.path}`);
    if (options.domain) parts.push(`Domain=${options.domain}`);
    if (options.maxAge) parts.push(`Max-Age=${options.maxAge}`);

    return parts.join('; ');
  }

  /**
   * Закрывает соединение с Redis
   */
  public async destroy(): Promise<void> {
    if (this.redis) {
      await this.redis.quit();
      this.redis = null;
    }
    this.jwtService = null;
    this.blacklist = null;
  }

  /**
   * Устанавливает JWT blacklist для интеграции
   * @param blacklist - Экземпляр JWTBlacklist
   */
  public setBlacklist(blacklist: JWTBlacklist): void {
    this.blacklist = blacklist;
    logger.info('[SessionManager] Blacklist установлен');
  }

  /**
   * Устанавливает JWT сервис для интеграции
   * @param jwtService - Экземпляр JwtService
   */
  public setJwtService(jwtService: JwtService): void {
    this.jwtService = jwtService;
    logger.info('[SessionManager] JWT Service установлен');
  }

  /**
   * Получает текущий blacklist
   * @returns JWTBlacklist или null
   */
  public getBlacklist(): JWTBlacklist | null {
    return this.blacklist;
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const sessionManager = new SessionManager(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания менеджера с кастомной конфигурацией
 */
export function createSessionManager(
  config: Partial<SessionManagerConfig>
): SessionManager {
  return new SessionManager({ ...DEFAULT_CONFIG, ...config });
}
