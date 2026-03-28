/**
 * ============================================================================
 * E-COMMERCE SECURITY MODULE - ЭКСПОРТЫ
 * ============================================================================
 */

export { EcommerceSecurityModule, createEcommerceSecurityModule } from './EcommerceSecurityModule';
export type { EcommerceSecurityConfig } from './types/ecommerce.types';

// Bot Protection
export { BotProtection } from './BotProtection';

// Account Takeover
export { AccountTakeoverPrevention } from './AccountTakeoverPrevention';

// Checkout Security
export { CheckoutSecurity } from './CheckoutSecurity';

// Payment Fraud
export { PaymentFraudDetection } from './PaymentFraudDetection';

// Review Fraud
export { ReviewFraudDetection } from './ReviewFraudDetection';

// Inventory Fraud
export { InventoryFraud } from './InventoryFraud';

// Coupon Abuse
export { CouponAbusePrevention } from './CouponAbusePrevention';

// Marketplace Security
export { MarketplaceSecurity } from './MarketplaceSecurity';
