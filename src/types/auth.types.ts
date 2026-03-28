/**
 * =============================================================================
 * AUTH TYPES DEFINITIONS
 * =============================================================================
 * Полная система типов для аутентификации и авторизации
 * Включает: OAuth 2.1, OIDC, JWT, MFA, WebAuthn, RBAC, ABAC, Sessions
 * =============================================================================
 */

import { JWK } from 'jose';

// =============================================================================
// БАЗОВЫЕ ТИПЫ ПОЛЬЗОВАТЕЛЯ
// =============================================================================

/**
 * Статус пользователя в системе
 */
export type UserStatus = 'active' | 'inactive' | 'suspended' | 'pending_verification' | 'locked';

/**
 * Основной интерфейс пользователя
 * Соответствует NIST 800-63B Digital Identity Guidelines
 */
export interface IUser {
  /** Уникальный идентификатор пользователя (UUID v4) */
  id: string;
  
  /** Email адрес (уникальный, верифицированный) */
  email: string;
  
  /** Хэш пароля (bcrypt/argon2) */
  passwordHash: string;
  
  /** Алгоритм хэширования пароля */
  passwordAlgorithm: 'bcrypt' | 'argon2id' | 'argon2d' | 'argon2i';
  
  /** Версия хэша для миграции */
  passwordVersion: number;
  
  /** Имя пользователя (уникальное) */
  username?: string;
  
  /** Телефон для SMS/MFA */
  phone?: string;
  
  /** Статус пользователя */
  status: UserStatus;
  
  /** Дата создания аккаунта */
  createdAt: Date;
  
  /** Дата последнего обновления */
  updatedAt: Date;
  
  /** Дата последней успешной аутентификации */
  lastLoginAt?: Date;
  
  /** Дата истечения срока действия пароля */
  passwordExpiresAt?: Date;
  
  /** Количество неудачных попыток входа */
  failedLoginAttempts: number;
  
  /** Дата блокировки после неудачных попыток */
  lockedUntil?: Date;
  
  /** Требует ли смены пароля при следующем входе */
  requirePasswordChange: boolean;
  
  /** Предпочтения безопасности */
  securityPreferences: ISecurityPreferences;
  
  /** Методы MFA, включенные пользователем */
  enabledMfaMethods: MfaMethodType[];
  
  /** Роли пользователя */
  roles: string[];
  
  /** Атрибуты для ABAC */
  attributes: IUserAttributes;
}

/**
 * Атрибуты пользователя для ABAC (Attribute-Based Access Control)
 */
export interface IUserAttributes {
  /** Департамент/отдел */
  department?: string;
  
  /** Должность */
  jobTitle?: string;
  
  /** Уровень доступа (clearance level) */
  clearanceLevel?: number;
  
  /** Географическое расположение */
  location?: string;
  
  /** Тип сотрудника */
  employeeType?: 'full-time' | 'part-time' | 'contractor' | 'intern' | 'admin';
  
  /** Дата найма */
  hireDate?: Date;
  
  /** Менеджер пользователя */
  managerId?: string;
  
  /** Проекты, в которых участвует */
  projects?: string[];
  
  /** Кастомные атрибуты */
  custom?: Record<string, any>;
}

/**
 * Предпочтения безопасности пользователя
 */
export interface ISecurityPreferences {
  /** Требовать MFA для входа */
  requireMfa: boolean;
  
  /** Разрешить запоминание устройства */
  allowRememberDevice: boolean;
  
  /** Срок запоминания устройства (дни) */
  rememberDeviceDays: number;
  
  /** Требовать подтверждение для новых устройств */
  requireNewDeviceConfirmation: boolean;
  
  /** Уведомлять о новых входах */
  notifyOnNewLogin: boolean;
  
  /** Разрешить сессии только с доверенных IP */
  restrictToTrustedIps: boolean;
  
  /** Доверенные IP адреса */
  trustedIps: string[];
  
  /** Максимальное количество одновременных сессий */
  maxConcurrentSessions: number;
  
  /** Требовать повторную аутентификацию для чувствительных операций (мин) */
  reauthIntervalMinutes: number;
}

// =============================================================================
// ТИПЫ MFA (MULTI-FACTOR AUTHENTICATION)
// =============================================================================

/**
 * Типы методов MFA
 */
export type MfaMethodType = 'totp' | 'hotp' | 'webauthn' | 'sms' | 'email' | 'backup_code';

/**
 * Статус MFA метода
 */
export type MfaMethodStatus = 'pending' | 'active' | 'disabled' | 'locked';

/**
 * Базовый интерфейс MFA метода
 */
export interface IMfaMethod {
  /** Уникальный идентификатор метода */
  id: string;
  
  /** ID пользователя */
  userId: string;
  
  /** Тип метода */
  type: MfaMethodType;
  
  /** Статус метода */
  status: MfaMethodStatus;
  
  /** Дата создания */
  createdAt: Date;
  
  /** Дата последнего использования */
  lastUsedAt?: Date;
  
  /** Количество использований */
  usageCount: number;
  
  /** Название/описание метода (для UI) */
  label?: string;
  
  /** Является ли методом по умолчанию */
  isDefault: boolean;
}

/**
 * TOTP метод (Time-based One-Time Password)
 * Соответствует RFC 6238
 */
export interface ITotpMethod extends IMfaMethod {
  type: 'totp';
  
  /** Секретный ключ (зашифрованный) */
  secret: string;
  
  /** Алгоритм хэширования */
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  
  /** Количество цифр в коде */
  digits: 6 | 8;
  
  /** Период действия кода (секунды) */
  period: number;
  
  /** Смещение времени (для синхронизации) */
  timeSkew: number;
  
  /** URI для QR-кода (otpauth://) */
  otpauthUrl?: string;
}

/**
 * HOTP метод (HMAC-based One-Time Password)
 * Соответствует RFC 4226
 */
export interface IHotpMethod extends IMfaMethod {
  type: 'hotp';
  
  /** Секретный ключ (зашифрованный) */
  secret: string;
  
  /** Алгоритм хэширования */
  algorithm: 'SHA1' | 'SHA256' | 'SHA512';
  
  /** Количество цифр в коде */
  digits: 6 | 8;
  
  /** Текущий счетчик */
  counter: number;
  
  /** Окно синхронизации счетчика */
  window: number;
}

/**
 * WebAuthn/FIDO2 метод
 * Соответствует W3C Web Authentication API
 */
export interface IWebAuthnMethod extends IMfaMethod {
  type: 'webauthn';
  
  /** Уникальный идентификатор ключа (credential ID) */
  credentialId: string;
  
  /** Публичный ключ (закодированный) */
  publicKey: string;
  
  /** Счетчик подписей (для обнаружения клонирования) */
  counter: number;
  
  /** Тип аутентификатора */
  authenticatorType: 'platform' | 'roaming';

  /** Транспортные методы аутентификатора WebAuthn */
  transports: AuthenticatorTransport[];

  /** Флаги возможностей аутентификатора */
  authenticatorFlags: {
    userPresent: boolean;
    userVerified: boolean;
    backupEligible: boolean;
    backupState: boolean;
  };

  /** Название устройства (для UI) */
  deviceName?: string;

  /** Дата последней синхронизации счетчика */
  lastCounterSyncAt?: Date;
}

/**
 * Транспортные методы аутентификатора WebAuthn
 */
export type AuthenticatorTransport = 'ble' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb';

/**
 * Резервный код восстановления
 */
export interface IBackupCode {
  /** Уникальный идентификатор кода */
  id: string;
  
  /** ID пользователя */
  userId: string;
  
  /** Хэш кода (не храним в plain text) */
  codeHash: string;
  
  /** Использован ли код */
  used: boolean;
  
  /** Дата использования */
  usedAt?: Date;
  
  /** ID сессии, в которой использован */
  usedSessionId?: string;
  
  /** Дата создания */
  createdAt: Date;
  
  /** Дата истечения срока действия */
  expiresAt?: Date;
}

/**
 * Набор резервных кодов
 */
export interface IBackupCodeSet {
  /** ID набора кодов */
  id: string;
  
  /** ID пользователя */
  userId: string;
  
  /** Количество кодов в наборе */
  codeCount: number;
  
  /** Количество использованных кодов */
  usedCount: number;
  
  /** Дата создания */
  createdAt: Date;
  
  /** Дата истечения срока действия всего набора */
  expiresAt?: Date;
  
  /** Активен ли набор */
  isActive: boolean;
}

// =============================================================================
// ТИПЫ СЕССИЙ
// =============================================================================

/**
 * Статус сессии
 */
export type SessionStatus = 'active' | 'suspended' | 'expired' | 'revoked' | 'terminated';

/**
 * Тип сессии
 */
export type SessionType = 'web' | 'mobile' | 'api' | 'service' | 'oauth';

/**
 * Интерфейс сессии пользователя
 */
export interface ISession {
  /** Уникальный идентификатор сессии */
  id: string;
  
  /** ID пользователя */
  userId: string;
  
  /** Тип сессии */
  type: SessionType;
  
  /** Статус сессии */
  status: SessionStatus;
  
  /** Токен обновления (refresh token) */
  refreshTokenHash: string;
  
  /** Семейство refresh токенов (для rotation) */
  refreshTokenFamily: string;
  
  /** ID устройства */
  deviceId?: string;
  
  /** User-Agent строка */
  userAgent: string;
  
  /** IP адрес создания сессии */
  ipAddress: string;
  
  /** Географическое расположение */
  geoLocation?: {
    country: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
    timezone: string;
  };
  
  /** Отпечаток устройства */
  deviceFingerprint?: string;
  
  /** Дата создания сессии */
  createdAt: Date;
  
  /** Дата последнего использования */
  lastUsedAt: Date;
  
  /** Дата истечения срока действия */
  expiresAt: Date;
  
  /** Дата абсолютного истечения (максимальная длительность) */
  absoluteExpiresAt: Date;
  
  /** Методы аутентификации, использованные для создания сессии */
  authenticationMethods: AuthenticationMethod[];
  
  /** Уровень аутентификации (IAL/AAL по NIST) */
  authenticationLevel: {
    ial: 1 | 2 | 3; // Identity Assurance Level
    aal: 1 | 2 | 3; // Authenticator Assurance Level
  };
  
  /** Разрешения сессии (для JIT access) */
  permissions?: string[];
  
  /** Контекст сессии */
  context: {
    /** Было ли устройство запомнено */
    isDeviceTrusted: boolean;
    
    /** Было ли устройство подтверждено */
    isDeviceVerified: boolean;
    
    /** Требует ли повторной аутентификации */
    requiresReauth: boolean;
    
    /** Причина требования reauth */
    reauthReason?: string;
    
    /** JIT elevation активен */
    jitElevated: boolean;
    
    /** Время JIT elevation */
    jitElevatedAt?: Date;
    
    /** Время истечения JIT elevation */
    jitExpiresAt?: Date;
  };
  
  /** Метаданные */
  metadata: {
    /** Название клиента */
    clientName?: string;
    
    /** Версия клиента */
    clientVersion?: string;
    
    /** Платформа */
    platform?: string;
    
    /** Язык */
    language?: string;
  };
}

/**
 * Метод аутентификации, использованный в сессии
 */
export interface AuthenticationMethod {
  /** Тип метода */
  method: MfaMethodType | 'password' | 'oauth' | 'sso';
  
  /** Время аутентификации */
  authenticatedAt: Date;
  
  /** Дополнительная информация */
  metadata?: Record<string, any>;
}

// =============================================================================
// ТИПЫ JWT ТОКЕНОВ
// =============================================================================

/**
 * Алгоритмы подписи JWT
 */
export type JwtAlgorithm = 'RS256' | 'RS384' | 'RS512' | 'ES256' | 'ES384' | 'ES512' | 'EdDSA';

/**
 * Заголовок JWT
 */
export interface JwtHeader {
  alg: JwtAlgorithm;
  typ: 'JWT' | 'at+jwt';
  kid: string;
}

/**
 * Payload access токена
 */
export interface AccessTokenPayload {
  /** Subject - ID пользователя */
  sub: string;
  
  /** Issuer */
  iss: string;
  
  /** Audience */
  aud: string | string[];
  
  /** Время выпуска */
  iat: number;
  
  /** Время истечения */
  exp: number;
  
  /** JWT ID (уникальный идентификатор токена) */
  jti: string;
  
  /** Scope */
  scope: string;
  
  /** ID сессии */
  sid: string;
  
  /** Уровень аутентификации */
  acr: 'urn:mace:incommon:iap:silver' | 'urn:mace:incommon:iap:bronze' | 'urn:rfc:4868:aal:1' | 'urn:rfc:4868:aal:2' | 'urn:rfc:4868:aal:3';
  
  /** Методы аутентификации */
  amr: string[];
  
  /** Auth time */
  auth_time: number;
  
  /** Роли */
  roles?: string[];
  
  /** Разрешения */
  permissions?: string[];
  
  /** Атрибуты пользователя */
  attributes?: IUserAttributes;
  
  /** Кастомные claims */
  [key: string]: any;
}

/**
 * Payload refresh токена
 */
export interface RefreshTokenPayload {
  /** Subject */
  sub: string;
  
  /** Issuer */
  iss: string;
  
  /** Audience */
  aud: string | string[];
  
  /** Время выпуска */
  iat: number;
  
  /** Время истечения */
  exp: number;
  
  /** JWT ID */
  jti: string;
  
  /** ID сессии */
  sid: string;
  
  /** Семейство токенов (для rotation) */
  rtf: string;
  
  /** Тип токена */
  tok: 'refresh';
}

/**
 * Payload ID токена (OIDC)
 */
export interface IdTokenPayload {
  /** Subject */
  sub: string;
  
  /** Issuer */
  iss: string;
  
  /** Audience */
  aud: string | string[];
  
  /** Время выпуска */
  iat: number;
  
  /** Время истечения */
  exp: number;
  
  /** JWT ID */
  jti: string;
  
  /** Время аутентификации */
  auth_time: number;
  
  /** Nonce */
  nonce?: string;
  
  /** Hash кода авторизации */
  c_hash?: string;
  
  /** Hash access токена */
  at_hash?: string;
  
  /** Уровень аутентификации */
  acr: string;
  
  /** Методы аутентификации */
  amr: string[];
  
  /** Email */
  email?: string;
  
  /** Верифицирован ли email */
  email_verified?: boolean;
  
  /** Имя */
  name?: string;
  
  /** Предпочитаемое имя */
  preferred_username?: string;
  
  /** Picture URL */
  picture?: string;
  
  /** Locale */
  locale?: string;
}

/**
 * Конфигурация ключей JWT
 */
export interface JwtKeyConfig {
  /** ID ключа (kid) */
  kid: string;

  /** Алгоритм */
  algorithm: JwtAlgorithm;

  /** Приватный ключ (PEM) */
  privateKey: string;

  /** Публичный ключ (PEM) */
  publicKey: string;

  /** Дата создания */
  createdAt: Date;

  /** Дата истечения срока действия ключа */
  expiresAt: Date;

  /** Активен ли ключ */
  isActive: boolean;

  /** Используется ли для подписи новых токенов */
  isSigningKey: boolean;

  /** Версия ключа */
  version?: number;
}

/**
 * JWK Set для JWKS endpoint
 */
export interface JwkSet {
  keys: JWK[];
}

// =============================================================================
// ТИПЫ OAuth 2.1 / OIDC
// =============================================================================

/**
 * Grant types по OAuth 2.1
 */
export type OAuthGrantType = 
  | 'authorization_code'
  | 'refresh_token'
  | 'client_credentials'
  | 'urn:ietf:params:oauth:grant-type:device_code'
  | 'urn:ietf:params:oauth:grant-type:token-exchange';

/**
 * Response types по OAuth 2.1 / OIDC
 */
export type OAuthResponseType = 
  | 'code'
  | 'token'
  | 'id_token'
  | 'code token'
  | 'code id_token'
  | 'id_token token'
  | 'code id_token token';

/**
 * PKCE Code Challenge Method
 */
export type PkceChallengeMethod = 'S256' | 'plain';

/**
 * OAuth клиент
 */
export interface IOAuthClient {
  /** Client ID */
  clientId: string;
  
  /** Client Secret (hashed) */
  clientSecretHash?: string;
  
  /** Название клиента */
  clientName: string;
  
  /** Описание */
  clientDescription?: string;
  
  /** Тип клиента */
  clientType: 'confidential' | 'public';
  
  /** Redirect URIs */
  redirectUris: string[];
  
  /** Post logout redirect URIs */
  postLogoutRedirectUris?: string[];
  
  /** Grant types */
  grantTypes: OAuthGrantType[];
  
  /** Response types */
  responseTypes: OAuthResponseType[];
  
  /** Token endpoint auth method */
  tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'client_secret_jwt' | 'private_key_jwt' | 'none';
  
  /** Token endpoint auth signing algorithm */
  tokenEndpointAuthSigningAlg?: JwtAlgorithm;
  
  /** JWK Set URI (для private_key_jwt) */
  jwksUri?: string;
  
  /** Scope по умолчанию */
  defaultScopes: string[];
  
  /** Разрешенные scope */
  allowedScopes: string[];
  
  /** Access token lifetime (секунды) */
  accessTokenLifetime: number;
  
  /** Refresh token lifetime (секунды) */
  refreshTokenLifetime: number;
  
  /** ID token lifetime (секунды) */
  idTokenLifetime: number;
  
  /** Требовать PKCE */
  requirePkce: boolean;
  
  /** Требовать согласие пользователя */
  requireConsent: boolean;
  
  /** Логотип клиента */
  logoUri?: string;
  
  /** Политика конфиденциальности */
  policyUri?: string;
  
  /** Условия использования */
  tosUri?: string;
  
  /** Дата создания */
  createdAt: Date;
  
  /** Дата последнего использования */
  lastUsedAt?: Date;
  
  /** Активен ли клиент */
  isActive: boolean;
}

/**
 * Authorization code
 */
export interface IAuthorizationCode {
  /** Код авторизации */
  code: string;
  
  /** Client ID */
  clientId: string;
  
  /** User ID */
  userId: string;
  
  /** Redirect URI */
  redirectUri: string;
  
  /** Scope */
  scope: string[];
  
  /** Code challenge (PKCE) */
  codeChallenge?: string;
  
  /** Code challenge method (PKCE) */
  codeChallengeMethod?: PkceChallengeMethod;
  
  /** Nonce (OIDC) */
  nonce?: string;
  
  /** State */
  state?: string;
  
  /** Время создания */
  createdAt: Date;
  
  /** Время истечения */
  expiresAt: Date;
  
  /** Использован ли код */
  used: boolean;
  
  /** ID сессии */
  sessionId?: string;
}

/**
 * Device code (для Device Authorization Grant)
 */
export interface IDeviceCode {
  /** Device code */
  deviceCode: string;
  
  /** User code (короткий код для ввода пользователем) */
  userCode: string;
  
  /** Client ID */
  clientId: string;
  
  /** Scope */
  scope: string[];
  
  /** Время создания */
  createdAt: Date;
  
  /** Время истечения */
  expiresAt: Date;
  
  /** Интервал опроса (секунды) */
  interval: number;
  
  /** User ID (после авторизации) */
  userId?: string;
  
  /** Авторизован ли device code */
  authorized: boolean;
  
  /** Дата авторизации */
  authorizedAt?: Date;
  
  /** Использован ли для получения токенов */
  used: boolean;
}

/**
 * OAuth 2.1 токены
 */
export interface IOAuthTokens {
  /** Access token */
  accessToken: string;
  
  /** Token type */
  tokenType: 'Bearer';
  
  /** Expires in (секунды) */
  expiresIn: number;
  
  /** Refresh token */
  refreshToken?: string;
  
  /** Scope */
  scope: string;
  
  /** ID token (OIDC) */
  idToken?: string;
}

// =============================================================================
// ТИПЫ RBAC (ROLE-BASED ACCESS CONTROL)
// =============================================================================

/**
 * Интерфейс роли
 */
export interface IRole {
  /** ID роли */
  id: string;
  
  /** Название роли (уникальное) */
  name: string;
  
  /** Описание */
  description?: string;
  
  /** Иерархия: родительские роли */
  parentRoles: string[];
  
  /** Разрешения роли */
  permissions: string[];
  
  /** Ограничения роли */
  constraints: IRoleConstraints;
  
  /** Дата создания */
  createdAt: Date;
  
  /** Дата обновления */
  updatedAt: Date;
  
  /** Системная роль (нельзя удалить) */
  isSystem: boolean;
}

/**
 * Ограничения роли
 */
export interface IRoleConstraints {
  /** Максимальное количество пользователей с этой ролью */
  maxUsers?: number;
  
  /** Требуемый уровень clearance */
  requiredClearanceLevel?: number;
  
  /** Ограничение по времени (часы активности) */
  timeRestrictions?: {
    daysOfWeek: number[];
    startHour: number;
    endHour: number;
    timezone: string;
  };
  
  /** Ограничение по IP */
  ipRestrictions?: {
    allowedIps: string[];
    deniedIps: string[];
  };
  
  /** Ограничение по местоположению */
  locationRestrictions?: {
    allowedCountries: string[];
    deniedCountries: string[];
  };
}

/**
 * Назначение роли пользователю
 */
export interface IRoleAssignment {
  /** ID назначения */
  id: string;
  
  /** ID пользователя */
  userId: string;
  
  /** ID роли */
  roleId: string;
  
  /** ID назначившего (кто выдал роль) */
  assignedBy: string;
  
  /** Дата назначения */
  assignedAt: Date;
  
  /** Дата истечения срока действия */
  expiresAt?: Date;
  
  /** Причина назначения */
  reason?: string;
  
  /** Активно ли назначение */
  isActive: boolean;
}

// =============================================================================
// ТИПЫ ABAC (ATTRIBUTE-BASED ACCESS CONTROL)
// =============================================================================

/**
 * Тип оператора в policy
 */
export type PolicyOperator = 
  | 'eq' | 'neq' | 'gt' | 'gte' | 'lt' | 'lte'
  | 'in' | 'not_in'
  | 'contains' | 'starts_with' | 'ends_with'
  | 'regex'
  | 'exists' | 'not_exists';

/**
 * Логический оператор
 */
export type LogicalOperator = 'and' | 'or' | 'not';

/**
 * Условие в policy
 */
export interface PolicyCondition {
  /** Атрибут для проверки */
  attribute: string;
  
  /** Оператор сравнения */
  operator: PolicyOperator;
  
  /** Значение для сравнения */
  value: any;
  
  /** Вложенные условия */
  conditions?: PolicyCondition[];
  
  /** Логический оператор для вложенных условий */
  logicalOperator?: LogicalOperator;
}

/**
 * Policy правило
 */
export interface IPolicy {
  /** ID policy */
  id: string;
  
  /** Название policy */
  name: string;
  
  /** Описание */
  description?: string;
  
  /** Тип policy */
  type: 'permit' | 'deny';
  
  /** Приоритет (чем выше, тем важнее) */
  priority: number;
  
  /** Ресурсы, к которым применяется */
  resources: string[];
  
  /** Действия, к которым применяется */
  actions: string[];
  
  /** Условия для subject (пользователь) */
  subjectConditions: PolicyCondition[];
  
  /** Условия для resource */
  resourceConditions?: PolicyCondition[];
  
  /** Условия для action */
  actionConditions?: PolicyCondition[];
  
  /** Условия для context (окружение) */
  contextConditions?: PolicyCondition[];
  
  /** Дата создания */
  createdAt: Date;
  
  /** Дата обновления */
  updatedAt: Date;
  
  /** Дата истечения срока действия */
  expiresAt?: Date;
  
  /** Активна ли policy */
  isActive: boolean;
  
  /** Версия policy */
  version: number;
}

/**
 * Результат оценки policy
 */
export interface PolicyDecision {
  /** Решение */
  decision: 'permit' | 'deny' | 'indeterminate' | 'not_applicable';
  
  /** ID policy, которая приняла решение */
  policyId?: string;
  
  /** Причина решения */
  reason?: string;
  
  /** Обязательства (obligations) для выполнения */
  obligations?: PolicyObligation[];
  
  /** Советы (advice) для информации */
  advice?: PolicyAdvice[];
}

/**
 * Обязательство (требование, которое должно быть выполнено)
 */
export interface PolicyObligation {
  /** ID обязательства */
  id: string;
  
  /** Тип обязательства */
  type: 'log' | 'notify' | 'mfa_required' | 'time_limit' | any;
  
  /** Параметры */
  parameters: Record<string, any>;
}

/**
 * Совет (информация для PEP)
 */
export interface PolicyAdvice {
  /** Тип совета */
  type: string;
  
  /** Сообщение */
  message: string;
}

/**
 * Контекст для оценки policy
 */
export interface PolicyContext {
  /** Subject (пользователь) */
  subject: {
    id: string;
    attributes: IUserAttributes;
    roles: string[];
    authenticationMethods: string[];
    authenticationLevel: number;
  };
  
  /** Resource (ресурс) */
  resource: {
    id: string;
    type: string;
    attributes: Record<string, any>;
    owner?: string;
  };
  
  /** Action (действие) */
  action: {
    id: string;
    type: string;
  };
  
  /** Environment (окружение) */
  environment: {
    currentTime: Date;
    currentLocation?: {
      country: string;
      region: string;
      city: string;
      ip: string;
    };
    deviceInfo?: {
      isTrusted: boolean;
      fingerprint?: string;
      type: string;
    };
    riskScore?: number;
    [key: string]: any;
  };
}

// =============================================================================
// ТИПЫ БЕЗОПАСНОСТИ И ЗАЩИТЫ
// =============================================================================

/**
 * Тип события безопасности
 */
export type SecurityEventType =
  | 'login_success'
  | 'login_failure'
  | 'logout'
  | 'password_change'
  | 'password_reset_request'
  | 'password_reset_complete'
  | 'mfa_enabled'
  | 'mfa_disabled'
  | 'mfa_challenge'
  | 'mfa_verified'
  | 'session_created'
  | 'session_terminated'
  | 'session_hijack_detected'
  | 'brute_force_detected'
  | 'credential_stuffing_detected'
  | 'account_locked'
  | 'account_unlocked'
  | 'suspicious_activity'
  | 'privilege_escalation'
  | 'jit_access_granted'
  | 'jit_access_expired'
  | 'policy_violation'
  | 'rate_limit_exceeded'
  | 'device_trusted'
  | 'device_untrusted'
  | 'oauth_client_created'
  | 'oauth_client_authorized'
  | 'oauth_token_issued'
  | 'oauth_token_revoked';

/**
 * Событие безопасности
 */
export interface ISecurityEvent {
  /** ID события */
  id: string;
  
  /** Тип события */
  type: SecurityEventType;
  
  /** ID пользователя (если применимо) */
  userId?: string;
  
  /** IP адрес */
  ipAddress: string;
  
  /** User-Agent */
  userAgent?: string;
  
  /** Device fingerprint */
  deviceFingerprint?: string;
  
  /** Дата события */
  timestamp: Date;
  
  /** Детали события */
  details: Record<string, any>;
  
  /** Уровень риска */
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  
  /** Оценка риска (0-100) */
  riskScore: number;
}

/**
 * Конфигурация rate limiting
 */
export interface RateLimitConfig {
  /** Уникальное имя правила */
  name: string;
  
  /** Тип правила */
  type: 'fixed_window' | 'sliding_window' | 'token_bucket' | 'leaky_bucket';
  
  /** Максимальное количество запросов */
  maxRequests: number;
  
  /** Окно времени (мс) */
  windowMs: number;
  
  /** Ключ для идентификации клиента */
  keyGenerator: (req: any) => string;
  
  /** Сообщение при превышении лимита */
  message: string;
  
  /** HTTP статус код */
  statusCode: number;
  
  /** Включить заголовки */
  headers: boolean;
  
  /** Skip условие */
  skip?: (req: any) => boolean;
}

/**
 * Статистика rate limiting
 */
export interface RateLimitStats {
  /** Ключ */
  key: string;
  
  /** Количество запросов в текущем окне */
  requestCount: number;
  
  /** Максимальное количество запросов */
  maxRequests: number;
  
  /** Оставшееся количество запросов */
  remaining: number;
  
  /** Время сброса окна (мс timestamp) */
  resetTime: number;
  
  /** Время до сброса (секунды) */
  retryAfter: number;
}

/**
 * Отпечаток устройства
 */
export interface DeviceFingerprintData {
  /** Уникальный хэш отпечатка */
  fingerprint: string;
  
  /** User-Agent */
  userAgent: string;
  
  /** Принятые языки */
  languages: string[];
  
  /** Часовой пояс */
  timezone: string;
  
  /** Разрешение экрана */
  screenResolution: string;
  
  /** Глубина цвета */
  colorDepth: number;
  
  /** Часовой пояс устройства */
  deviceTimezone?: string;
  
  /** Платформа */
  platform: string;
  
  /** Архитектура CPU */
  cpuArchitecture?: string;
  
  /** Количество ядер CPU */
  cpuCores?: number;
  
  /** Объем памяти */
  deviceMemory?: number;
  
  /** Поддерживаемые API браузера */
  supportedApis: string[];
  
  /** Шрифты (для browser fingerprinting) */
  fonts?: string[];
  
  /** Canvas fingerprint */
  canvasFingerprint?: string;
  
  /** WebGL fingerprint */
  webglFingerprint?: string;
  
  /** Audio fingerprint */
  audioFingerprint?: string;
  
  /** Доверенное устройство */
  isTrusted: boolean;
  
  /** Дата первого использования */
  firstSeenAt: Date;
  
  /** Дата последнего использования */
  lastSeenAt: Date;
  
  /** Количество использований */
  usageCount: number;
}

// =============================================================================
// ТИПЫ ОТВЕТОВ И ОШИБОК
// =============================================================================

/**
 * Стандартный ответ API
 */
export interface ApiResponse<T = any> {
  /** Успешен ли запрос */
  success: boolean;
  
  /** Данные ответа */
  data?: T;
  
  /** Сообщение */
  message?: string;
  
  /** Код ошибки */
  errorCode?: string;
  
  /** Детали ошибки */
  errorDetails?: Record<string, any>;
  
  /** Метаданные (пагинация и т.д.) */
  meta?: {
    total?: number;
    page?: number;
    limit?: number;
    totalPages?: number;
  };
}

/**
 * Коды ошибок аутентификации
 */
export enum AuthErrorCode {
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  ACCOUNT_DISABLED = 'ACCOUNT_DISABLED',
  PASSWORD_EXPIRED = 'PASSWORD_EXPIRED',
  MFA_REQUIRED = 'MFA_REQUIRED',
  MFA_INVALID_CODE = 'MFA_INVALID_CODE',
  MFA_METHOD_NOT_FOUND = 'MFA_METHOD_NOT_FOUND',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  SESSION_INVALID = 'SESSION_INVALID',
  SESSION_REVOKED = 'SESSION_REVOKED',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  TOKEN_INVALID = 'TOKEN_INVALID',
  TOKEN_REVOKED = 'TOKEN_REVOKED',
  INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',
  RATE_LIMIT_EXCEEDED = 'RATE_LIMIT_EXCEEDED',
  BRUTE_FORCE_DETECTED = 'BRUTE_FORCE_DETECTED',
  CREDENTIAL_STUFFING_DETECTED = 'CREDENTIAL_STUFFING_DETECTED',
  SUSPICIOUS_ACTIVITY = 'SUSPICIOUS_ACTIVITY',
  DEVICE_UNTRUSTED = 'DEVICE_UNTRUSTED',
  IP_BLOCKED = 'IP_BLOCKED',
  GEO_BLOCKED = 'GEO_BLOCKED',
  OAUTH_INVALID_CLIENT = 'OAUTH_INVALID_CLIENT',
  OAUTH_INVALID_GRANT = 'OAUTH_INVALID_GRANT',
  OAUTH_INVALID_SCOPE = 'OAUTH_INVALID_SCOPE',
  OAUTH_INVALID_REDIRECT_URI = 'OAUTH_INVALID_REDIRECT_URI',
  OAUTH_PKCE_MISMATCH = 'OAUTH_PKCE_MISMATCH',
  OAUTH_CONSENT_REQUIRED = 'OAUTH_CONSENT_REQUIRED',
  INVALID_ARGUMENT = 'INVALID_ARGUMENT',
  INTERNAL_ERROR = 'INTERNAL_ERROR'
}

/**
 * Ошибка аутентификации
 */
export class AuthError extends Error {
  constructor(
    message: string,
    public code: AuthErrorCode,
    public statusCode: number = 401,
    public details?: Record<string, any>
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Результат аутентификации
 */
export interface AuthResult {
  /** Успешна ли аутентификация */
  success: boolean;
  
  /** Пользователь */
  user?: IUser;
  
  /** Сессия */
  session?: ISession;
  
  /** Access токен */
  accessToken?: string;
  
  /** Refresh токен */
  refreshToken?: string;
  
  /** ID токен (OIDC) */
  idToken?: string;
  
  /** Требует ли MFA */
  requiresMfa?: boolean;
  
  /** Доступные методы MFA */
  availableMfaMethods?: MfaMethodType[];
  
  /** MFA session token (временный) */
  mfaSessionToken?: string;
  
  /** Сообщение */
  message?: string;
}

/**
 * Результат проверки доступа
 */
export interface AccessCheckResult {
  /** Разрешен ли доступ */
  allowed: boolean;
  
  /** Причина отказа (если есть) */
  denialReason?: string;

  /** Policy, которая приняла решение */
  policyId?: string;

  /** Обязательства для выполнения */
  obligations?: PolicyObligation[];
}
