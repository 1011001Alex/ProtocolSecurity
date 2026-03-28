/**
 * ============================================================================
 * HEALTHCARE SECURITY MODULE - ЭКСПОРТЫ
 * ============================================================================
 */

// Main Module
export { HealthcareSecurityModule, createHealthcareSecurityModule } from './HealthcareSecurityModule';

// PHI Protection
export { PHIProtection } from './phi/PHIProtection';

// Consent Management
export { PatientConsentManager } from './consent/PatientConsentManager';

// EHR Integration
export { EHRIntegration } from './ehr/EHRIntegration';

// FHIR Security
export { FHIRSecurity } from './ehr/FHIRSecurity';

// Device Security
export { MedicalDeviceSecurity } from './devices/MedicalDeviceSecurity';

// Telehealth
export { TelehealthSecurity } from './telehealth/TelehealthSecurity';

// Identity
export { HealthcareIdentity } from './identity/HealthcareIdentity';

// Types
export type {
  HealthcareSecurityConfig,
  PHIProtectionConfig,
  ConsentManagerConfig,
  EHRIntegrationConfig,
  FHIRSecurityConfig,
  DeviceSecurityConfig,
  TelehealthSecurityConfig,
  IdentityConfig,
  ConsentType,
  ConsentStatus,
  PHIData,
  Diagnosis,
  Medication,
  Allergy,
  Procedure,
  LabResult,
  VitalSign,
  PatientConsent,
  PHIAccessRequest,
  PHIAccessDecision,
  EmergencyAccess,
  FHIRResource,
  HL7Message,
  MedicalDevice,
  DeviceType,
  DevicePostureStatus,
  TelehealthSession,
  MPIRecord,
  HIPAAComplianceStatus,
  ComplianceViolation,
  BreachNotification
} from './types/healthcare.types';
