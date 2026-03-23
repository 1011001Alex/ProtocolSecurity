/**
 * HEALTHCARE SECURITY MODULE - ГЛАВНЫЙ МОДУЛЬ
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { PHIProtection } from './phi/PHIProtection';
import { PatientConsentManager } from './consent/PatientConsentManager';

export interface HealthcareSecurityConfig {
  hipaaCompliant: boolean;
  ehrProvider: 'epic' | 'cerner' | 'allscripts' | 'mock';
  auditEnabled: boolean;
}

export class HealthcareSecurityModule extends EventEmitter {
  private readonly config: HealthcareSecurityConfig;
  public readonly phi: PHIProtection;
  public readonly consent: PatientConsentManager;
  private isInitialized = false;
  
  constructor(config: HealthcareSecurityConfig) {
    super();
    
    this.config = {
      hipaaCompliant: config.hipaaCompliant ?? true,
      ehrProvider: config.ehrProvider ?? 'mock',
      auditEnabled: config.auditEnabled ?? true
    };
    
    this.phi = new PHIProtection(this.config);
    this.consent = new PatientConsentManager(this.config);
    
    logger.info('[HealthcareSecurity] Module created', {
      hipaaCompliant: this.config.hipaaCompliant
    });
  }
  
  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    
    await this.phi.initialize();
    await this.consent.initialize();
    
    this.isInitialized = true;
    logger.info('[HealthcareSecurity] Initialized');
    this.emit('initialized');
  }
  
  public async destroy(): Promise<void> {
    await this.phi.destroy();
    await this.consent.destroy();
    this.isInitialized = false;
    logger.info('[HealthcareSecurity] Destroyed');
  }
}
