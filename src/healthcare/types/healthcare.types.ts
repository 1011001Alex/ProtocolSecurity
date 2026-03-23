/**
 * ============================================================================
 * HEALTHCARE SECURITY TYPES & INTERFACES
 * ============================================================================
 */

/**
 * Конфигурация Healthcare Security Module
 */
export interface HealthcareSecurityConfig {
  /** ID организации */
  organizationId: string;

  /** Название организации */
  organizationName: string;

  /** Юрисдикция */
  jurisdiction: string;

  /** HIPAA compliance mode */
  hipaaCompliant?: boolean;

  /** HIPAA version */
  hipaaVersion?: string;

  /** Audit configuration */
  auditConfig?: {
    enabled: boolean;
    retentionDays: number;
  };

  /** Compliance configuration */
  complianceConfig?: {
    autoCheckEnabled: boolean;
    checkInterval: number;
    minimumScore: number;
  };

  /** Modules configuration */
  modules?: {
    phiProtection?: any;
    consentManager?: any;
    ehrIntegration?: any;
    fhirSecurity?: any;
    deviceSecurity?: any;
    telehealthSecurity?: any;
    identity?: any;
  };
}

/**
 * PHI data interface
 */
export interface PHIData {
  patientId: string;
  data: any;
}

/**
 * Encrypted PHI interface
 */
export interface EncryptedPHI {
  encryptedData: string;
  iv: string;
  authTag?: string;
  algorithm: string;
  timestamp: Date;
}

/**
 * Consent type
 */
export type ConsentType = 'TPO' | 'RESEARCH' | 'TREATMENT' | 'PAYMENT' | 'OPERATIONS';

/**
 * Consent interface
 */
export interface Consent {
  consentId: string;
  patientId: string;
  consentType: ConsentType;
  grantedTo: string[];
  validFrom: Date;
  validUntil: Date;
  restrictions?: Record<string, boolean>;
  isMinor?: boolean;
  guardianConsent?: any;
}

/**
 * Device interface
 */
export interface MedicalDevice {
  deviceId: string;
  deviceType: string;
  manufacturer: string;
  model: string;
  serialNumber: string;
}

/**
 * Identity verification level
 */
export type IdentityAssuranceLevel = 'IAL1' | 'IAL2' | 'IAL3';
