/**
 * ============================================================================
 * E-COMMERCE SECURITY TYPES
 * ============================================================================
 */

/**
 * Bot Protection Config
 */
export interface BotProtectionConfig {
  enabled: boolean;
  mode: 'BLOCK' | 'CHALLENGE' | 'MONITOR' | 'AGGRESSIVE';
  captchaProvider?: 'recaptcha' | 'hcaptcha' | 'turnstile';
  fingerprinting?: boolean;
}

/**
 * Fraud Detection Config
 */
export interface FraudDetectionConfig {
  enabled: boolean;
  mlModel?: string;
  threshold?: number;
  realTimeScoring?: boolean;
}

/**
 * Account Takeover Config
 */
export interface AccountTakeoverConfig {
  enabled: boolean;
  deviceRecognition?: boolean;
  behavioralBiometrics?: boolean;
}

/**
 * Checkout Security Config
 */
export interface CheckoutSecurityConfig {
  enabled: boolean;
  addressValidation?: boolean;
  emailRiskScoring?: boolean;
}

/**
 * E-commerce Security Config
 */
export interface EcommerceSecurityConfig {
  botProtection: BotProtectionConfig;
  fraudDetection: FraudDetectionConfig;
  accountTakeover: AccountTakeoverConfig;
  checkoutSecurity: CheckoutSecurityConfig;
  audit?: {
    enabled: boolean;
    retentionDays: number;
  };
}

/**
 * Bot Score Result
 */
export interface BotScore {
  score: number;
  recommendation: 'ALLOW' | 'CHALLENGE' | 'BLOCK';
  ipAddress: string;
  fingerprint?: string;
}

/**
 * Fraud Analysis Result
 */
export interface FraudAnalysis {
  fraudScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factors: string[];
}

/**
 * Checkout Risk Result
 */
export interface CheckoutRisk {
  fraudScore: number;
  riskLevel: string;
  recommendations: string[];
}
