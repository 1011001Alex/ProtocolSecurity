/**
 * ============================================================================
 * BOT PROTECTION — ЗАЩИТА ОТ БОТОВ
 * ============================================================================
 *
 * Advanced bot detection and mitigation
 *
 * @package protocol/ecommerce-security
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { BotScore, BotAnalysisData, BotRiskFactor } from './types/ecommerce.types';

export class BotProtection extends EventEmitter {
  private isInitialized = false;
  private blockedIPs: Map<string, { until: Date; reason: string }> = new Map();
  private fingerprints: Map<string, number> = new Map();
  private readonly config = {
    mode: 'AGGRESSIVE' as 'PASSIVE' | 'AGGRESSIVE' | 'PARANOID',
    captchaProvider: 'recaptcha',
    fingerprinting: true,
    rateLimiting: true
  };

  constructor() {
    super();
    logger.info('[BotProtection] Service created');
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    
    // Запуск очистки старых blocked IPs
    setInterval(() => {
      const now = new Date();
      for (const [ip, data] of this.blockedIPs.entries()) {
        if (data.until < now) {
          this.blockedIPs.delete(ip);
        }
      }
    }, 60000); // Каждую минуту

    this.isInitialized = true;
    logger.info('[BotProtection] Initialized');
    this.emit('initialized');
  }

  /**
   * Анализ запроса на бота
   */
  public async analyzeRequest(data: BotAnalysisData): Promise<BotScore> {
    if (!this.isInitialized) {
      throw new Error('BotProtection not initialized');
    }

    const riskFactors: BotRiskFactor[] = [];
    let totalScore = 0;

    // 1. User Agent анализ
    const uaFactor = this.analyzeUserAgent(data.userAgent);
    riskFactors.push(uaFactor);
    totalScore += uaFactor.score * uaFactor.weight * 100;

    // 2. Заголовки анализ
    const headersFactor = this.analyzeHeaders(data.headers);
    riskFactors.push(headersFactor);
    totalScore += headersFactor.score * headersFactor.weight * 100;

    // 3. Поведенческий анализ
    if (data.behavior) {
      const behaviorFactor = this.analyzeBehavior(data.behavior);
      riskFactors.push(behaviorFactor);
      totalScore += behaviorFactor.score * behaviorFactor.weight * 100;
    }

    // 4. Rate limit проверка
    if (data.requestHistory) {
      const rateFactor = this.analyzeRequestRate(data.requestHistory);
      riskFactors.push(rateFactor);
      totalScore += rateFactor.score * rateFactor.weight * 100;
    }

    // 5. IP репутация
    const ipFactor = await this.checkIPReputation(data.ipAddress);
    riskFactors.push(ipFactor);
    totalScore += ipFactor.score * ipFactor.weight * 100;

    // Нормализация score
    const normalizedScore = Math.min(100, Math.max(0, totalScore));

    // Определение рекомендации
    let recommendation: BotScore['recommendation'] = 'ALLOW';

    if (normalizedScore >= 80) {
      recommendation = 'BLOCK';
    } else if (normalizedScore >= 50) {
      recommendation = 'CHALLENGE';
    } else if (normalizedScore >= 30) {
      recommendation = 'MONITOR';
    }

    // Параноидальный режим ужесточает пороги
    if (this.config.mode === 'PARANOID') {
      if (normalizedScore >= 60) recommendation = 'BLOCK';
      else if (normalizedScore >= 30) recommendation = 'CHALLENGE';
    }

    const botScore: BotScore = {
      score: Math.round(normalizedScore),
      recommendation,
      riskFactors,
      ipAddress: data.ipAddress,
      fingerprint: data.fingerprint,
      timestamp: new Date()
    };

    // Логирование и эмиссия событий
    if (recommendation === 'BLOCK') {
      logger.warn('[BotProtection] Bot detected', {
        score: botScore.score,
        ipAddress: data.ipAddress,
        factors: riskFactors.filter(f => f.score > 0.5).map(f => f.name)
      });

      this.emit('bot_detected', botScore);

      // Автоматическая блокировка
      if (this.config.mode !== 'PASSIVE') {
        await this.blockIP(data.ipAddress, 'Automated bot detection');
      }
    }

    return botScore;
  }

  /**
   * Анализ User Agent
   */
  private analyzeUserAgent(userAgent?: string): BotRiskFactor {
    if (!userAgent) {
      return {
        name: 'MISSING_USER_AGENT',
        weight: 0.3,
        score: 1.0,
        description: 'No User-Agent header provided'
      };
    }

    const botPatterns = [
      /bot/i, /crawler/i, /spider/i, /scraper/i,
      /curl/i, /wget/i, /python/i, /httpclient/i
    ];

    const isBot = botPatterns.some(pattern => pattern.test(userAgent));

    if (isBot) {
      return {
        name: 'BOT_USER_AGENT',
        weight: 0.4,
        score: 0.9,
        description: 'Known bot User-Agent detected',
        evidence: { userAgent }
      };
    }

    // Проверка на подозрительные UA
    if (userAgent.length < 20 || userAgent.length > 500) {
      return {
        name: 'SUSPICIOUS_USER_AGENT_LENGTH',
        weight: 0.2,
        score: 0.5,
        description: 'Unusual User-Agent length'
      };
    }

    return {
      name: 'USER_AGENT_NORMAL',
      weight: 0.3,
      score: 0.1,
      description: 'Normal User-Agent'
    };
  }

  /**
   * Анализ заголовков
   */
  private analyzeHeaders(headers: Record<string, string>): BotRiskFactor {
    const requiredHeaders = ['accept', 'accept-language', 'connection'];
    const missingHeaders = requiredHeaders.filter(
      h => !headers[h.toLowerCase()]
    );

    if (missingHeaders.length > 0) {
      return {
        name: 'MISSING_HEADERS',
        weight: 0.2,
        score: Math.min(1, missingHeaders.length / requiredHeaders.length),
        description: `Missing standard headers: ${missingHeaders.join(', ')}`
      };
    }

    return {
      name: 'HEADERS_NORMAL',
      weight: 0.2,
      score: 0.1,
      description: 'Standard headers present'
    };
  }

  /**
   * Поведенческий анализ
   */
  private analyzeBehavior(behavior: NonNullable<BotAnalysisData['behavior']>): BotRiskFactor {
    let score = 0;
    const issues: string[] = [];

    // Анализ движений мыши
    if (behavior.mouseMovements && behavior.mouseMovements.length > 0) {
      const movements = behavior.mouseMovements;
      
      // Боты часто имеют слишком прямые движения
      const avgSpeed = movements.reduce((sum, m, i) => {
        if (i === 0) return sum;
        const prev = movements[i - 1];
        const dx = m.x - prev.x;
        const dy = m.y - prev.y;
        const dt = m.t - prev.t;
        return sum + (Math.sqrt(dx * dx + dy * dy) / dt);
      }, 0) / (movements.length - 1);

      if (avgSpeed > 10 || avgSpeed < 0.1) {
        score += 0.3;
        issues.push('Unnatural mouse speed');
      }
    } else {
      score += 0.2;
      issues.push('No mouse movements');
    }

    // Анализ клавиатуры
    if (behavior.keystrokes && behavior.keystrokes.length > 0) {
      const avgHoldTime = behavior.keystrokes.reduce((sum, k) => sum + k.d, 0) / behavior.keystrokes.length;

      if (avgHoldTime < 50 || avgHoldTime > 500) {
        score += 0.2;
        issues.push('Unnatural keystroke timing');
      }
    }

    return {
      name: 'BEHAVIORAL_ANALYSIS',
      weight: 0.3,
      score: Math.min(1, score),
      description: issues.length > 0 ? issues.join('; ') : 'Normal behavior',
      evidence: { issues }
    };
  }

  /**
   * Анализ частоты запросов
   */
  private analyzeRequestRate(history: NonNullable<BotAnalysisData['requestHistory']>): BotRiskFactor {
    const { requestsPerMinute, errorRate } = history;

    let score = 0;

    if (requestsPerMinute > 100) {
      score += 0.5;
    } else if (requestsPerMinute > 50) {
      score += 0.3;
    }

    if (errorRate > 0.5) {
      score += 0.3;
    }

    return {
      name: 'REQUEST_RATE_ANALYSIS',
      weight: 0.2,
      score: Math.min(1, score),
      description: `RPM: ${requestsPerMinute}, Error rate: ${(errorRate * 100).toFixed(1)}%`
    };
  }

  /**
   * Проверка IP репутации
   */
  private async checkIPReputation(ipAddress: string): Promise<BotRiskFactor> {
    // Проверка локального blacklist
    if (this.blockedIPs.has(ipAddress)) {
      const block = this.blockedIPs.get(ipAddress)!;
      return {
        name: 'BLOCKED_IP',
        weight: 0.5,
        score: 1.0,
        description: `IP is blocked until ${block.until.toISOString()}`,
        evidence: { reason: block.reason }
      };
    }

    // В production проверка внешних сервисов репутации
    // AbuseIPDB, IPQualityScore, и т.д.

    return {
      name: 'IP_REPUTATION',
      weight: 0.2,
      score: 0.1,
      description: 'No reputation issues found'
    };
  }

  /**
   * Блокировка IP
   */
  public async blockIP(ip: string, reason: string, durationMinutes: number = 60): Promise<boolean> {
    this.blockedIPs.set(ip, {
      until: new Date(Date.now() + durationMinutes * 60 * 1000),
      reason
    });

    logger.warn('[BotProtection] IP blocked', {
      ip,
      reason,
      duration: durationMinutes
    });

    this.emit('ip_blocked', { ip, reason, duration: durationMinutes });

    return true;
  }

  /**
   * Serve CAPTCHA
   */
  public async serveCaptcha(): Promise<{
    challengeId: string;
    captchaImage?: string;
    provider: string;
  }> {
    const challengeId = `captcha-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    logger.debug('[BotProtection] CAPTCHA served', {
      challengeId,
      provider: this.config.captchaProvider
    });

    return {
      challengeId,
      provider: this.config.captchaProvider
    };
  }

  /**
   * Verify CAPTCHA
   */
  public async verifyCaptcha(data: {
    challengeId: string;
    response: string;
  }): Promise<{
    success: boolean;
    score?: number;
  }> {
    // В production реальная верификация через провайдера
    const success = Math.random() > 0.1; // 90% success rate для demo

    logger.debug('[BotProtection] CAPTCHA verified', {
      challengeId: data.challengeId,
      success
    });

    return {
      success,
      score: success ? 0.9 : 0.1
    };
  }

  /**
   * Получить заблокированные IP
   */
  public getBlockedIPs(): string[] {
    return Array.from(this.blockedIPs.keys());
  }

  public async destroy(): Promise<void> {
    this.blockedIPs.clear();
    this.fingerprints.clear();
    this.isInitialized = false;
    logger.info('[BotProtection] Destroyed');
    this.emit('destroyed');
  }
}
