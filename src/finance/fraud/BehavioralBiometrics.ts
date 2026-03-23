/**
 * BEHAVIORAL BIOMETRICS - БИОМЕТРИЯ ПОВЕДЕНИЯ
 */

import { logger } from '../../logging/Logger';
import { FinanceSecurityConfig, BehavioralBiometricsData } from '../types/finance.types';

export class BehavioralBiometrics {
  private readonly config: FinanceSecurityConfig;
  
  constructor(config: FinanceSecurityConfig) {
    this.config = config;
  }
  
  public async analyzeBehavior(data: BehavioralBiometricsData): Promise<{
    score: number;
    confidence: number;
    anomalies: string[];
  }> {
    logger.debug('[BehavioralBiometrics] Analyzing behavior');
    
    const anomalies: string[] = [];
    let score = 0;
    
    // Анализ typing rhythm
    if (data.typingRhythm) {
      if (data.typingRhythm.averageKeyHoldTime > 200) {
        anomalies.push('Unusual typing speed');
        score += 0.3;
      }
    }
    
    // Анализ mouse dynamics
    if (data.mouseDynamics) {
      if (data.mouseDynamics.movementSmoothness < 0.5) {
        anomalies.push('Irregular mouse movement');
        score += 0.2;
      }
    }
    
    return {
      score: Math.min(score, 1.0),
      confidence: 0.85,
      anomalies
    };
  }
}
