/**
 * ============================================================================
 * FINANCE SECURITY TYPES & INTERFACES
 * ============================================================================
 */

import { SecuritySeverity, ThreatCategory } from '../types';

/**
 * Конфигурация Finance Security Module
 */
export interface FinanceSecurityConfig {
  /** PCI DSS compliance mode */
  pciCompliant: boolean;
  
  /** HSM provider */
  hsmProvider: 'aws-cloudhsm' | 'thales' | 'utimaco' | 'mock';
  
  /** Tokenization settings */
  tokenization: {
    enabled: boolean;
    algorithm: 'AES-256-GCM' | 'RSA-OAEP';
    preserveLength: boolean;
  };
  
  /** Fraud detection settings */
  fraudDetection: {
    enabled: boolean;
    mlModel: 'xgboost-fraud-v2' | 'random-forest-v1' | 'neural-network-v3';
    threshold: number; // 0.0 - 1.0
    realTimeScoring: boolean;
  };
  
  /** AML settings */
  aml: {
    enabled: boolean;
    transactionThreshold: number; // USD
    reportingCurrency: string;
    sanctionsLists: string[]; // ['OFAC', 'UN', 'EU']
  };
  
  /** Transaction monitoring */
  transactionMonitoring: {
    enabled: boolean;
    velocityChecks: boolean;
    geolocationChecks: boolean;
    amountPatternAnalysis: boolean;
  };
  
  /** Audit logging */
  audit: {
    enabled: boolean;
    retentionDays: number;
    immutable: boolean;
  };
}

/**
 * Payment card data
 */
export interface PaymentCardData {
  /** Primary Account Number (PAN) */
  pan: string;
  
  /** Cardholder name */
  cardholderName?: string;
  
  /** Expiry date (MM/YY) */
  expiryDate?: string;
  
  /** CVV/CVC */
  cvv?: string;
  
  /** Card brand */
  brand?: 'VISA' | 'MASTERCARD' | 'AMEX' | 'DISCOVER' | 'JCB' | 'DINERS';
  
  /** Card type */
  type?: 'CREDIT' | 'DEBIT' | 'PREPAID';
  
  /** Issuing country */
  issuingCountry?: string;
  
  /** Issuing bank */
  issuingBank?: string;
}

/**
 * Tokenized card data
 */
export interface TokenizedCard {
  /** Token value */
  token: string;
  
  /** Token expiry */
  tokenExpiry?: Date;
  
  /** Last 4 digits of original PAN */
  last4: string;
  
  /** Card brand */
  brand: string;
  
  /** Token provider */
  provider: string;
  
  /** Token status */
  status: 'ACTIVE' | 'SUSPENDED' | 'EXPIRED' | 'REVOKED';
}

/**
 * Fraud score result
 */
export interface FraudScore {
  /** Overall fraud score (0.0 - 1.0) */
  score: number;
  
  /** Risk level */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  
  /** Risk factors */
  riskFactors: FraudRiskFactor[];
  
  /** Recommended action */
  recommendedAction: 'APPROVE' | 'REVIEW' | 'BLOCK' | 'CHALLENGE';
  
  /** Transaction ID */
  transactionId: string;
  
  /** ML model confidence */
  confidence: number;
  
  /** Explanation for humans */
  explanation: string;
}

/**
 * Individual fraud risk factor
 */
export interface FraudRiskFactor {
  /** Factor name */
  name: string;
  
  /** Factor weight (0.0 - 1.0) */
  weight: number;
  
  /** Factor score (0.0 - 1.0) */
  score: number;
  
  /** Description */
  description: string;
  
  /** Evidence */
  evidence?: Record<string, any>;
}

/**
 * Transaction data for fraud analysis
 */
export interface TransactionData {
  /** Transaction ID */
  transactionId: string;
  
  /** Amount */
  amount: number;
  
  /** Currency */
  currency: string;
  
  /** Card token or PAN */
  paymentMethod: string;
  
  /** Merchant ID */
  merchantId: string;
  
  /** Merchant category code (MCC) */
  merchantCategoryCode?: string;
  
  /** Customer ID */
  customerId?: string;
  
  /** IP address */
  ipAddress?: string;
  
  /** Device fingerprint */
  deviceFingerprint?: string;
  
  /** Geolocation */
  geolocation?: {
    latitude: number;
    longitude: number;
    country: string;
    city?: string;
  };
  
  /** Timestamp */
  timestamp: Date;
  
  /** Transaction type */
  transactionType: 'PURCHASE' | 'REFUND' | 'WITHDRAWAL' | 'TRANSFER' | 'PAYMENT';
  
  /** Channel */
  channel: 'ONLINE' | 'POS' | 'ATM' | 'MOBILE' | 'PHONE';
  
  /** Additional metadata */
  metadata?: Record<string, any>;
}

/**
 * AML check result
 */
export interface AMLCheckResult {
  /** Passed AML check */
  passed: boolean;
  
  /** Risk score */
  riskScore: number;
  
  /** Sanctions matches */
  sanctionsMatches: SanctionsMatch[];
  
  /** PEP (Politically Exposed Person) check */
  pepMatch: boolean;
  
  /** Adverse media check */
  adverseMediaMatch: boolean;
  
  /** Recommended action */
  recommendedAction: 'PROCEED' | 'REVIEW' | 'BLOCK' | 'REPORT';
  
  /** SAR (Suspicious Activity Report) required */
  sarRequired: boolean;
}

/**
 * Sanctions list match
 */
export interface SanctionsMatch {
  /** List name (OFAC, UN, EU) */
  listName: string;
  
  /** Matched entity name */
  matchedName: string;
  
  /** Match score (0.0 - 1.0) */
  matchScore: number;
  
  /** Entity type */
  entityType: 'INDIVIDUAL' | 'ORGANIZATION' | 'VESSEL' | 'AIRCRAFT';
  
  /** List reference ID */
  referenceId: string;
  
  /** Programs / sanctions programs */
  programs: string[];
}

/**
 * Suspicious Activity Report (SAR)
 */
export interface SuspiciousActivityReport {
  /** SAR ID */
  sarId: string;
  
  /** Filing institution */
  filingInstitution: string;
  
  /** Activity date */
  activityDate: Date;
  
  /** Activity type */
  activityType: string;
  
  /** Amount involved */
  amountInvolved: number;
  
  /** Narrative description */
  narrative: string;
  
  /** Subject information */
  subjects: SARSubject[];
  
  /** Supporting documentation */
  supportingDocs: string[];
  
  /** Filing status */
  status: 'DRAFT' | 'FILED' | 'SUBMITTED' | 'ACCEPTED';
  
  /** Filing date */
  filingDate?: Date;
}

/**
 * SAR Subject (person or organization)
 */
export interface SARSubject {
  /** Subject ID */
  subjectId: string;
  
  /** Subject type */
  type: 'INDIVIDUAL' | 'ORGANIZATION';
  
  /** Name */
  name: string;
  
  /** Address */
  address?: string;
  
  /** Country */
  country?: string;
  
  /** ID document */
  idDocument?: {
    type: string;
    number: string;
    issuingCountry: string;
  };
  
  /** Role in activity */
  role: string;
}

/**
 * HSM configuration
 */
export interface HSMConfig {
  /** HSM provider */
  provider: 'aws-cloudhsm' | 'thales' | 'utimaco' | 'gemalto';
  
  /** HSM cluster endpoints */
  endpoints: string[];
  
  /** Authentication credentials */
  credentials: {
    username: string;
    password?: string;
    certificate?: string;
    privateKey?: string;
  };
  
  /** Key partition */
  partition?: string;
  
  /** FIPS 140-2/140-3 level */
  fipsLevel: 2 | 3;
}

/**
 * PIN block data
 */
export interface PINBlock {
  /** Encrypted PIN block */
  encryptedPINBlock: string;
  
  /** PIN block format */
  format: 'ISO-0' | 'ISO-1' | 'ISO-2' | 'ISO-3' | 'ANSI-X9.8';
  
  /** Key serial number */
  keySerialNumber?: string;
}

/**
 * Behavioral biometrics data
 */
export interface BehavioralBiometricsData {
  /** Typing rhythm */
  typingRhythm?: {
    averageKeyHoldTime: number;
    averageFlightTime: number;
    typingSpeed: number;
  };
  
  /** Mouse dynamics */
  mouseDynamics?: {
    averageSpeed: number;
    clickPatterns: number;
    movementSmoothness: number;
  };
  
  /** Touch dynamics (mobile) */
  touchDynamics?: {
    averageTouchPressure: number;
    swipePatterns: number;
    tapAccuracy: number;
  };
  
  /** Device handling */
  deviceHandling?: {
    tiltAngle: number;
    orientation: string;
    movementPatterns: number;
  };
}

/**
 * Velocity check result
 */
export interface VelocityCheckResult {
  /** Check passed */
  passed: boolean;
  
  /** Check type */
  checkType: 'TRANSACTION_COUNT' | 'TRANSACTION_AMOUNT' | 'GEOLOCATION' | 'DEVICE';
  
  /** Time window */
  timeWindow: string;
  
  /** Current count/amount */
  currentValue: number;
  
  /** Threshold */
  threshold: number;
  
  /** Exceeded by */
  exceededBy?: number;
}

/**
 * 3D Secure authentication data
 */
export interface ThreeDSecureData {
  /** 3DS version */
  version: '1.0' | '2.0' | '2.1' | '2.2' | '2.3';
  
  /** Authentication status */
  authenticationStatus: 'Y' | 'N' | 'U' | 'A' | 'C' | 'R' | 'D';
  
  /** ECI (Electronic Commerce Indicator) */
  eci?: string;
  
  /** CAVV (Cardholder Authentication Verification Value) */
  cavv?: string;
  
  /** XID (Transaction ID) */
  xid?: string;
  
  /** DS (Directory Server) transaction ID */
  dsTransactionId?: string;
  
  /** ACS (Access Control Server) transaction ID */
  acsTransactionId?: string;
}

/**
 * PCI DSS audit log entry
 */
export interface PCIDSSAuditLog {
  /** Log ID */
  logId: string;
  
  /** Timestamp */
  timestamp: Date;
  
  /** Event type */
  eventType: string;
  
  /** User ID */
  userId?: string;
  
  /** Action */
  action: string;
  
  /** Resource */
  resource?: string;
  
  /** Result */
  result: 'SUCCESS' | 'FAILURE';
  
  /** IP address */
  ipAddress?: string;
  
  /** Additional data */
  additionalData?: Record<string, any>;
}

/**
 * Currency exchange rate for AML
 */
export interface ExchangeRate {
  /** Base currency */
  baseCurrency: string;
  
  /** Target currency */
  targetCurrency: string;
  
  /** Rate */
  rate: number;
  
  /** Timestamp */
  timestamp: Date;
  
  /** Source */
  source: string;
}

/**
 * Merchant risk assessment
 */
export interface MerchantRiskAssessment {
  /** Merchant ID */
  merchantId: string;
  
  /** Risk score (0.0 - 1.0) */
  riskScore: number;
  
  /** Risk level */
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  
  /** Risk factors */
  riskFactors: string[];
  
  /** MCC risk */
  mccRisk: 'LOW' | 'MEDIUM' | 'HIGH';
  
  /** Chargeback ratio */
  chargebackRatio: number;
  
  /** Fraud ratio */
  fraudRatio: number;
  
  /** Last assessment date */
  lastAssessmentDate: Date;
}
