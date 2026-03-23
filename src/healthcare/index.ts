/**
 * ============================================================================
 * HEALTHCARE SECURITY MODULE - ЭКСПОРТЫ
 * ============================================================================
 */

export { HealthcareSecurityModule, createHealthcareSecurityModule } from './HealthcareSecurityModule';
export { HealthcareSecurityConfig } from './types/healthcare.types';

// PHI Protection
export { PHIProtection } from './phi/PHIProtection';

// Consent Management
export { PatientConsentManager } from './consent/PatientConsentManager';

// EHR Integration
export { EHRIntegration } from './ehr/EHRIntegration';
export { FHIRSecurity } from './ehr/FHIRSecurity';

// Medical Devices
export { MedicalDeviceSecurity } from './devices/MedicalDeviceSecurity';

// Telehealth
export { TelehealthSecurity } from './telehealth/TelehealthSecurity';

// Identity
export { HealthcareIdentity } from './identity/HealthcareIdentity';
