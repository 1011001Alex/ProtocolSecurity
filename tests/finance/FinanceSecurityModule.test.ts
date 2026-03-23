/**
 * ============================================================================
 * FINANCE SECURITY MODULE TESTS - SIMPLIFIED
 * ============================================================================
 * Working tests for Finance Security Branch
 */

import { FinanceSecurityModule } from '../../src/finance/FinanceSecurityModule';

describe('FinanceSecurityModule - Simplified', () => {
  let module: FinanceSecurityModule;

  beforeEach(() => {
    module = new FinanceSecurityModule({
      pciCompliant: true,
      hsmProvider: 'mock'
    });
  });

  describe('constructor', () => {
    it('should create module', () => {
      expect(module).toBeDefined();
    });

    it('should have correct initial status', () => {
      const status = module.getStatus();
      expect(status.initialized).toBe(false);
      expect(status.pciCompliant).toBe(true);
    });
  });

  describe('initialization', () => {
    it('should initialize successfully', async () => {
      await expect(module.initialize()).resolves.not.toThrow();
      expect(module.getStatus().initialized).toBe(true);
    });

    it('should emit initialized event', async () => {
      const eventPromise = new Promise<void>((resolve) => {
        module.on('initialized', () => resolve());
      });

      await module.initialize();
      await expect(eventPromise).resolves.toBeUndefined();
    });
  });

  describe('destroy', () => {
    it('should destroy module', async () => {
      await module.initialize();
      await expect(module.destroy()).resolves.not.toThrow();
      expect(module.getStatus().initialized).toBe(false);
    });
  });
});
