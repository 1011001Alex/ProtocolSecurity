/**
 * ============================================================================
 * E-COMMERCE SECURITY MODULE TESTS - SIMPLIFIED
 * ============================================================================
 * Working tests for E-commerce Security Branch
 */

import { EcommerceSecurityModule } from '../../src/ecommerce/EcommerceSecurityModule';

describe('EcommerceSecurityModule - Simplified', () => {
  let module: EcommerceSecurityModule;

  beforeEach(() => {
    module = new EcommerceSecurityModule({
      botProtection: { enabled: true, mode: 'AGGRESSIVE' },
      fraudDetection: { enabled: true },
      accountTakeover: { enabled: true },
      checkoutSecurity: { enabled: true }
    });
  });

  describe('constructor', () => {
    it('should create module', () => {
      expect(module).toBeDefined();
    });

    it('should have bot protection active after init', async () => {
      await module.initialize();
      expect(module.isBotProtectionActive()).toBe(true);
    });

    it('should have fraud detection active after init', async () => {
      await module.initialize();
      expect(module.isFraudDetectionActive()).toBe(true);
    });
  });

  describe('initialization', () => {
    it('should initialize successfully', async () => {
      await expect(module.initialize()).resolves.not.toThrow();
      expect(module.isReady()).toBe(true);
    });

    it('should emit initialized event', async () => {
      const eventPromise = new Promise<void>((resolve) => {
        module.on('initialized', () => resolve());
      });

      await module.initialize();
      await expect(eventPromise).resolves.toBeUndefined();
    });
  });

  describe('status', () => {
    it('should get status', async () => {
      await module.initialize();
      const status = module.getStatus();
      expect(status.initialized).toBe(true);
    });

    it('should get dashboard', async () => {
      await module.initialize();
      const dashboard = module.getDashboard();
      expect(dashboard).toBeDefined();
      expect(dashboard.timestamp).toBeDefined();
    });
  });

  describe('destroy', () => {
    it('should destroy module', async () => {
      await module.initialize();
      await expect(module.destroy()).resolves.not.toThrow();
      expect(module.isReady()).toBe(false);
    });
  });
});
