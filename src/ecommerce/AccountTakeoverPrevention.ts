/**
 * ============================================================================
 * ACCOUNT TAKEOVER PREVENTION — ПРЕДОТВРАЩЕНИЕ ЗАХВАТА АККАУНТОВ
 * ============================================================================
 *
 * ATO prevention с использованием ML и поведенческого анализа
 *
 * @package protocol/ecommerce-security
 */

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../logging/Logger';
import { ATORiskResult, ATORiskFactor, LoginAttemptData } from './types/ecommerce.types';

export class AccountTakeoverPrevention extends EventEmitter {
  private isInitialized = false;
  private loginAttempts: Map<string, LoginAttemptData[]> = new Map();
  private trustedDevices: Map<string, Set<string>> = new Map();
  private readonly config = {
    deviceRecognition: true,
    behavioralBiometrics: true,
    mfaRequired: false,
    maxFailedAttempts: 5,
    lockoutDurationMinutes: 30
  };

  constructor() {
    super();
    logger.info('[ATO] Service created');
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    logger.info('[ATO] Initialized');
    this.emit('initialized');
  }

  /**
   * Анализ попытки входа
   */
  public async analyzeLoginAttempt(data: LoginAttemptData): Promise<ATORiskResult> {
    if (!this.isInitialized) {
      throw new Error('ATO not initialized');
    }

    const riskFactors: ATORiskFactor[] = [];
    let riskScore = 0;

    // 1. Проверка неудачных попыток
    const failedAttemptsFactor = await this.checkFailedAttempts(data.email);
    riskFactors.push(failedAttemptsFactor);
    riskScore += failedAttemptsFactor.score * failedAttemptsFactor.weight;

    // 2. Проверка устройства
    if (data.deviceFingerprint && this.config.deviceRecognition) {
      const deviceFactor = await this.checkDeviceTrust(data.email, data.deviceFingerprint);
      riskFactors.push(deviceFactor);
      riskScore += deviceFactor.score * deviceFactor.weight;
    }

    // 3. Geolocation анализ
    if (data.geolocation) {
      const geoFactor = await this.checkGeolocationRisk(data.email, data.geolocation);
      riskFactors.push(geoFactor);
      riskScore += geoFactor.score * geoFactor.weight;
    }

    // 4. IP репутация
    const ipFactor = await this.checkIPRisk(data.ipAddress);
    riskFactors.push(ipFactor);
    riskScore += ipFactor.score * ipFactor.weight;

    // 5. Время и паттерны
    const timingFactor = this.analyzeTimingPatterns(data);
    riskFactors.push(timingFactor);
    riskScore += timingFactor.score * timingFactor.weight;

    // Определение уровня риска
    let riskLevel: ATORiskResult['riskLevel'] = 'LOW';
    if (riskScore >= 0.8) riskLevel = 'CRITICAL';
    else if (riskScore >= 0.6) riskLevel = 'HIGH';
    else if (riskScore >= 0.3) riskLevel = 'MEDIUM';

    // Рекомендация
    let recommendedAction: ATORiskResult['recommendedAction'] = 'ALLOW';
    if (riskLevel === 'CRITICAL') recommendedAction = 'BLOCK';
    else if (riskLevel === 'HIGH') recommendedAction = 'REQUIRE_MFA';
    else if (riskLevel === 'MEDIUM') recommendedAction = 'REVIEW';

    const result: ATORiskResult = {
      loginAttemptId: `login-${uuidv4()}`,
      email: data.email,
      riskScore,
      riskLevel,
      riskFactors,
      recommendedAction,
      requiresVerification: recommendedAction !== 'ALLOW',
      timestamp: new Date()
    };

    // Логирование
    if (riskLevel === 'HIGH' || riskLevel === 'CRITICAL') {
      logger.warn('[ATO] High risk login detected', {
        email: data.email,
        riskLevel,
        factors: riskFactors.filter(f => f.score > 0.5).map(f => f.name)
      });

      this.emit('ato_detected', result);
    }

    // Сохранение попытки
    this.saveLoginAttempt(data);

    return result;
  }

  /**
   * Проверка неудачных попыток
   */
  private async checkFailedAttempts(email: string): Promise<ATORiskFactor> {
    const attempts = this.loginAttempts.get(email) || [];
    const recentFailed = attempts.filter(
      a => a.failedAttempts && a.failedAttempts > 0
    ).length;

    if (recentFailed >= this.config.maxFailedAttempts) {
      return {
        name: 'EXCESSIVE_FAILED_ATTEMPTS',
        weight: 0.4,
        score: 1.0,
        description: `${recentFailed} failed attempts detected`,
        evidence: { failedAttempts: recentFailed }
      };
    }

    return {
      name: 'FAILED_ATTEMPTS_NORMAL',
      weight: 0.4,
      score: recentFailed > 0 ? 0.3 : 0.1,
      description: recentFailed > 0 ? `${recentFailed} failed attempts` : 'No failed attempts'
    };
  }

  /**
   * Проверка доверия устройства
   */
  private async checkDeviceTrust(email: string, fingerprint: string): Promise<ATORiskFactor> {
    const trustedDevices = this.trustedDevices.get(email);

    if (trustedDevices?.has(fingerprint)) {
      return {
        name: 'TRUSTED_DEVICE',
        weight: 0.25,
        score: 0.1,
        description: 'Recognized trusted device'
      };
    }

    return {
      name: 'NEW_DEVICE',
      weight: 0.25,
      score: 0.6,
      description: 'Unrecognized device',
      evidence: { fingerprint }
    };
  }

  /**
   * Geolocation риск анализ
   */
  private async checkGeolocationRisk(
    email: string,
    geolocation: LoginAttemptData['geolocation']
  ): Promise<ATORiskFactor> {
    // В production проверка истории локаций пользователя
    // Impossible travel detection

    const highRiskCountries = ['NG', 'RU', 'CN', 'BR', 'ID'];

    if (geolocation?.country && highRiskCountries.includes(geolocation.country)) {
      return {
        name: 'HIGH_RISK_COUNTRY',
        weight: 0.2,
        score: 0.7,
        description: `Login from high-risk country: ${geolocation.country}`
      };
    }

    return {
      name: 'GEOLOCATION_NORMAL',
      weight: 0.2,
      score: 0.1,
      description: 'Normal geolocation'
    };
  }

  /**
   * IP риск анализ
   */
  private async checkIPRisk(ipAddress: string): Promise<ATORiskFactor> {
    // В production проверка proxy/VPN/Tor
    const isProxy = false;
    const isTor = false;

    if (isProxy || isTor) {
      return {
        name: 'ANONYMOUS_IP',
        weight: 0.2,
        score: 0.8,
        description: isTor ? 'Tor exit node detected' : 'Proxy/VPN detected'
      };
    }

    return {
      name: 'IP_NORMAL',
      weight: 0.2,
      score: 0.1,
      description: 'Normal IP'
    };
  }

  /**
   * Анализ временных паттернов
   */
  private analyzeTimingPatterns(data: LoginAttemptData): ATORiskFactor {
    const hour = data.timestamp.getHours();

    // Необычное время входа (2-5 AM локального времени)
    if (hour >= 2 && hour <= 5) {
      return {
        name: 'UNUSUAL_TIMING',
        weight: 0.15,
        score: 0.5,
        description: 'Login at unusual hour'
      };
    }

    return {
      name: 'TIMING_NORMAL',
      weight: 0.15,
      score: 0.1,
      description: 'Normal login time'
    };
  }

  /**
   * Сохранение попытки входа
   */
  private saveLoginAttempt(data: LoginAttemptData): void {
    const attempts = this.loginAttempts.get(data.email) || [];
    attempts.push(data);

    // Хранение только последних 100 попыток
    if (attempts.length > 100) {
      attempts.shift();
    }

    this.loginAttempts.set(data.email, attempts);
  }

  /**
   * Требовать MFA
   */
  public async requireMFA(email: string): Promise<{
    mfaRequired: boolean;
    methods: string[];
  }> {
    logger.info('[ATO] MFA required', { email });

    return {
      mfaRequired: true,
      methods: ['TOTP', 'SMS', 'EMAIL']
    };
  }

  /**
   * Блокировка входа
   */
  public async blockLoginAttempt(result: ATORiskResult): Promise<void> {
    logger.warn('[ATO] Login blocked', {
      email: result.email,
      riskLevel: result.riskLevel
    });

    this.emit('login_blocked', result);
  }

  /**
   * Добавление доверенного устройства
   */
  public async addTrustedDevice(email: string, fingerprint: string): Promise<void> {
    if (!this.trustedDevices.has(email)) {
      this.trustedDevices.set(email, new Set());
    }

    this.trustedDevices.get(email)!.add(fingerprint);

    logger.info('[ATO] Trusted device added', { email, fingerprint });
  }

  public async destroy(): Promise<void> {
    this.loginAttempts.clear();
    this.trustedDevices.clear();
    this.isInitialized = false;
    logger.info('[ATO] Destroyed');
    this.emit('destroyed');
  }
}
