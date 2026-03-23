/**
 * ============================================================================
 * HEALTHCARE SECURITY MODULE TESTS - SIMPLIFIED
 * ============================================================================
 * Working tests for Healthcare Security Branch
 */

import { HealthcareSecurityModule } from '../../src/healthcare/HealthcareSecurityModule';

describe('HealthcareSecurityModule - Simplified', () => {
  let module: HealthcareSecurityModule;

  beforeEach(() => {
    module = new HealthcareSecurityModule({
      organizationId: 'test-hospital',
      organizationName: 'Test Hospital',
      jurisdiction: 'US'
    });
  });

  describe('constructor', () => {
    it('should create module', () => {
      expect(module).toBeDefined();
    });

    it('should have HIPAA compliant status', () => {
      expect(module.isHipaaCompliant()).toBe(true);
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

  describe('compliance', () => {
    it('should run compliance check', async () => {
      await module.initialize();
      const result = await module.runComplianceCheck('full');
      expect(result).toBeDefined();
      expect(result.checkType).toBe('full');
    });

    it('should get compliance score', () => {
      const score = module.getComplianceScore();
      expect(score).toBeDefined();
      expect(score.overallScore).toBeDefined();
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
