/**
 * ============================================================================
 * HEALTHCARE SECURITY MODULE - БЕЗОПАСНОСТЬ МЕДИЦИНСКИХ ДАННЫХ
 * ============================================================================
 * 
 * HIPAA compliant система защиты медицинских данных
 * 
 * Compliance:
 * - HIPAA Privacy Rule
 * - HIPAA Security Rule
 * - HITECH Act
 * - GDPR (для EU пациентов)
 * - 21st Century Cures Act
 * - HL7 FHIR Security
 * 
 * @package protocol/healthcare-security
 */

export { HealthcareSecurityModule } from './HealthcareSecurityModule';
export { HealthcareSecurityConfig } from './types/healthcare.types';

// PHI Protection
export { PHIProtection } from './phi/PHIProtection';
export { DataDeIdentification } from './phi/DataDeIdentification';

// Consent Management
export { PatientConsentManager } from './consent/PatientConsentManager';

// EHR Integration
export { EHRIntegration } from './ehr/EHRIntegration';
export { FHIRSecurity } from './ehr/FHIRSecurity';

// Medical Devices
export { MedicalDeviceSecurity } from './devices/MedicalDeviceSecurity';
