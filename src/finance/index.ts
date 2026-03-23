/**
 * ============================================================================
 * FINANCE SECURITY MODULE - БЕЗОПАСНОСТЬ ФИНАНСОВЫХ ПРИЛОЖЕНИЙ
 * ============================================================================
 * 
 * Комплексная система безопасности для финансовых приложений и платежных систем
 * 
 * Compliance:
 * - PCI DSS 4.0 Level 1
 * - PSD2 / SCA (Strong Customer Authentication)
 * - SOX (Sarbanes-Oxley)
 * - GLBA (Gramm-Leach-Bliley Act)
 * - NYDFS Cybersecurity Regulation
 * - AML (Anti-Money Laundering)
 * 
 * @package protocol/finance-security
 * @author Protocol Security Team
 * @version 1.0.0
 */

export { FinanceSecurityModule } from './FinanceSecurityModule';
export { FinanceSecurityConfig } from './types/finance.types';

// Payment Security
export { PaymentCardEncryption } from './payment/PaymentCardEncryption';
export { TokenizationService } from './payment/TokenizationService';
export { SecurePINProcessing } from './payment/SecurePINProcessing';

// Fraud Detection
export { FraudDetectionEngine } from './fraud/FraudDetectionEngine';
export { TransactionMonitoring } from './fraud/TransactionMonitoring';
export { BehavioralBiometrics } from './fraud/BehavioralBiometrics';

// AML & Sanctions
export { AMLChecker } from './aml/AMLChecker';
export { SanctionsScreening } from './aml/SanctionsScreening';
export { SuspiciousActivityReporting } from './aml/SuspiciousActivityReporting';

// HSM Integration
export { HSMIntegration } from './hsm/HSMIntegration';
export { KeyManagement } from './hsm/KeyManagement';
