/**
 * ============================================================================
 * E-COMMERCE SECURITY TYPES & INTERFACES
 * ============================================================================
 *
 * Типы и интерфейсы для E-commerce Security Branch
 *
 * @package protocol/ecommerce-security
 * @author Protocol Security Team
 * @version 1.0.0
 */

/**
 * Конфигурация E-commerce Security Module
 */
export interface EcommerceSecurityConfig {
  /** Bot Protection конфигурация */
  botProtection: {
    enabled: boolean;
    mode: 'PASSIVE' | 'AGGRESSIVE' | 'PARANOID';
    captchaProvider?: 'recaptcha' | 'hcaptcha' | 'turnstile' | 'custom';
    fingerprinting?: boolean;
    rateLimiting?: boolean;
  };

  /** Fraud Detection конфигурация */
  fraudDetection: {
    enabled: boolean;
    mlModel?: 'ecommerce-fraud-v3' | 'custom';
    threshold?: number;
    realTimeScoring?: boolean;
  };

  /** Account Takeover Prevention конфигурация */
  accountTakeover: {
    enabled: boolean;
    deviceRecognition?: boolean;
    behavioralBiometrics?: boolean;
    mfaRequired?: boolean;
  };

  /** Checkout Security конфигурация */
  checkoutSecurity: {
    enabled: boolean;
    addressValidation?: boolean;
    emailRiskScoring?: boolean;
    phoneVerification?: boolean;
  };

  /** Audit конфигурация */
  audit?: {
    enabled: boolean;
    retentionDays: number;
  };
}

/**
 * Bot score результат
 */
export interface BotScore {
  /** Score (0-100, выше = более вероятно бот) */
  score: number;

  /** Рекомендация */
  recommendation: 'ALLOW' | 'CHALLENGE' | 'BLOCK' | 'MONITOR';

  /** Факторы риска */
  riskFactors: BotRiskFactor[];

  /** IP адрес */
  ipAddress: string;

  /** Fingerprint */
  fingerprint?: string;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Bot risk factor
 */
export interface BotRiskFactor {
  /** Название фактора */
  name: string;

  /** Score вклада (0-1) */
  weight: number;

  /** Score фактора (0-1) */
  score: number;

  /** Описание */
  description: string;

  /** Доказательства */
  evidence?: Record<string, any>;
}

/**
 * Данные для анализа бота
 */
export interface BotAnalysisData {
  /** IP адрес */
  ipAddress: string;

  /** User Agent */
  userAgent: string;

  /** Заголовки */
  headers: Record<string, string>;

  /** Fingerprint устройства */
  fingerprint?: string;

  /** Поведенческие данные */
  behavior?: {
    mouseMovements?: Array<{ x: number; y: number; t: number }>;
    keystrokes?: Array<{ key: string; t: number; d: number }>;
    navigationPattern?: string[];
    timeOnPage?: number;
    scrollDepth?: number;
  };

  /** История запросов */
  requestHistory?: {
    requestsPerMinute: number;
    uniquePages: number;
    errorRate: number;
  };
}

/**
 * ATO (Account Takeover) риск результат
 */
export interface ATORiskResult {
  /** ID попытки входа */
  loginAttemptId: string;

  /** Email пользователя */
  email: string;

  /** Score риска (0-1) */
  riskScore: number;

  /** Уровень риска */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  /** Факторы риска */
  riskFactors: ATORiskFactor[];

  /** Рекомендация */
  recommendedAction: 'ALLOW' | 'REQUIRE_MFA' | 'BLOCK' | 'REVIEW';

  /** Требуется ли верификация */
  requiresVerification: boolean;

  /** Timestamp */
  timestamp: Date;
}

/**
 * ATO risk factor
 */
export interface ATORiskFactor {
  /** Название фактора */
  name: string;

  /** Weight (0-1) */
  weight: number;

  /** Score (0-1) */
  score: number;

  /** Описание */
  description: string;

  /** Доказательства */
  evidence?: Record<string, any>;
}

/**
 * Данные для анализа входа
 */
export interface LoginAttemptData {
  /** Email */
  email: string;

  /** IP адрес */
  ipAddress: string;

  /** Device fingerprint */
  deviceFingerprint?: string;

  /** Geolocation */
  geolocation?: {
    latitude: number;
    longitude: number;
    country: string;
    city?: string;
  };

  /** User Agent */
  userAgent?: string;

  /** Timestamp */
  timestamp: Date;

  /** Метод входа */
  loginMethod: 'PASSWORD' | 'SOCIAL' | 'MAGIC_LINK' | 'BIOMETRIC';

  /** Была ли попытка неудачной */
  failedAttempts?: number;
}

/**
 * Checkout риск результат
 */
export interface CheckoutRiskResult {
  /** ID сессии */
  sessionId: string;

  /** Score риска (0-1) */
  fraudScore: number;

  /** Уровень риска */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  /** Факторы риска */
  riskFactors: CheckoutRiskFactor[];

  /** Рекомендация */
  recommendedAction: 'APPROVE' | 'REVIEW' | 'REQUIRE_VERIFICATION' | 'BLOCK';

  /** Требуется ли дополнительная верификация */
  requiresAdditionalVerification: boolean;

  /** Timestamp */
  timestamp: Date;
}

/**
 * Checkout risk factor
 */
export interface CheckoutRiskFactor {
  /** Название фактора */
  name: string;

  /** Weight (0-1) */
  weight: number;

  /** Score (0-1) */
  score: number;

  /** Описание */
  description: string;

  /** Доказательства */
  evidence?: Record<string, any>;
}

/**
 * Данные для анализа checkout
 */
export interface CheckoutData {
  /** ID сессии */
  sessionId: string;

  /** Корзина */
  cart: {
    items: number;
    totalValue: number;
    highRiskItems?: string[];
    categories?: string[];
  };

  /** Клиент */
  customer: {
    isGuest: boolean;
    emailAge?: 'NEW' | 'RECENT' | 'ESTABLISHED';
    phoneVerified?: boolean;
    accountAge?: number; // дни
    previousOrders?: number;
  };

  /** Доставка */
  shipping: {
    addressRisk?: 'LOW' | 'MEDIUM' | 'HIGH';
    velocityCheck?: 'PASSED' | 'FAILED';
    country?: string;
    shippingMethod?: string;
  };

  /** Платёж */
  payment: {
    method: 'CARD' | 'PAYPAL' | 'CRYPTO' | 'COD' | 'WIRE';
    cardBin?: string;
    cardCountry?: string;
    billingAddressMatch?: boolean;
    cvvMatch?: boolean;
  };

  /** Устройство */
  device: {
    fingerprint?: string;
    ipAddress: string;
    geolocation?: { country: string; city?: string };
  };
}

/**
 * Review анализ результат
 */
export interface ReviewAnalysisResult {
  /** ID отзыва */
  reviewId: string;

  /** Score фейковости (0-1) */
  fakeProbability: number;

  /** Является ли подозрительным */
  isSuspicious: boolean;

  /** Факторы подозрительности */
  suspicionFactors: ReviewSuspicionFactor[];

  /** Рекомендация */
  recommendedAction: 'APPROVE' | 'FLAG' | 'HIDE' | 'REMOVE';

  /** Timestamp */
  timestamp: Date;
}

/**
 * Review suspicion factor
 */
export interface ReviewSuspicionFactor {
  /** Название фактора */
  name: string;

  /** Weight (0-1) */
  weight: number;

  /** Score (0-1) */
  score: number;

  /** Описание */
  description: string;

  /** Доказательства */
  evidence?: Record<string, any>;
}

/**
 * Данные отзыва
 */
export interface ReviewData {
  /** ID отзыва */
  reviewId: string;

  /** ID продукта */
  productId: string;

  /** ID ревьюера */
  reviewerId: string;

  /** Рейтинг (1-5) */
  rating: number;

  /** Текст отзыва */
  text: string;

  /** Timestamp */
  timestamp: Date;

  /** Проверенная покупка */
  verified: boolean;

  /** ID заказа (если есть) */
  orderId?: string;

  /** Помощные голоса */
  helpfulVotes?: number;

  /** Язык */
  language?: string;
}

/**
 * Inventory manipulation alert
 */
export interface InventoryAlert {
  /** ID алерта */
  alertId: string;

  /** ID продукта */
  productId: string;

  /** Тип алерта */
  alertType: 'HOARDING' | 'RAPID_PURCHASE' | 'CART_ABUSE' | 'PRICE_MANIPULATION';

  /** Score риска */
  riskScore: number;

  /** Детали */
  details: {
    userId?: string;
    quantityAttempted: number;
    quantityAllowed: number;
    timeWindow: string;
    pattern: string;
  };

  /** Рекомендация */
  recommendedAction: 'ALLOW' | 'LIMIT' | 'BLOCK' | 'INVESTIGATE';

  /** Timestamp */
  timestamp: Date;
}

/**
 * Coupon abuse результат
 */
export interface CouponAbuseResult {
  /** ID купона */
  couponId: string;

  /** Код купона */
  couponCode: string;

  /** ID пользователя */
  userId: string;

  /** Является ли злоупотреблением */
  isAbuse: boolean;

  /** Тип злоупотребления */
  abuseType?: 'MULTIPLE_USE' | 'SHARING_VIOLATION' | 'ELIGIBILITY_VIOLATION' | 'STACKING_ABUSE';

  /** Score риска */
  riskScore: number;

  /** Рекомендация */
  recommendedAction: 'ALLOW' | 'DENY' | 'REVIEW';

  /** Timestamp */
  timestamp: Date;
}

/**
 * Marketplace seller риск
 */
export interface SellerRiskAssessment {
  /** ID продавца */
  sellerId: string;

  /** Score риска (0-1) */
  riskScore: number;

  /** Уровень риска */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  /** Факторы риска */
  riskFactors: string[];

  /** Метрики */
  metrics: {
    totalSales: number;
    disputeRate: number;
    refundRate: number;
    negativeReviewRate: number;
    accountAge: number; // дни
    verificationStatus: 'UNVERIFIED' | 'PARTIAL' | 'FULL';
  };

  /** Рекомендация */
  recommendedAction: 'APPROVE' | 'MONITOR' | 'RESTRICT' | 'SUSPEND';

  /** Timestamp */
  timestamp: Date;
}

/**
 * Payment fraud результат
 */
export interface PaymentFraudResult {
  /** ID транзакции */
  transactionId: string;

  /** Score мошенничества (0-1) */
  fraudScore: number;

  /** Уровень риска */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

  /** Факторы риска */
  riskFactors: string[];

  /** Рекомендация */
  recommendedAction: 'APPROVE' | 'REVIEW' | 'BLOCK' | 'CHALLENGE';

  /** Требуется ли 3DS */
  requires3DS: boolean;

  /** Timestamp */
  timestamp: Date;
}
