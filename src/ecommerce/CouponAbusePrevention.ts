/**
 * ============================================================================
 * COUPON ABUSE PREVENTION — ПРЕДОТВРАЩЕНИЕ ЗЛОУПОТРЕБЛЕНИЯ КУПОНАМИ
 * ============================================================================
 *
 * Детекция и предотвращение злоупотребления купонами и промокодами
 */

import { EventEmitter } from 'events';
import { createHash } from 'crypto';

interface CouponUsage {
  couponCode: string;
  userId: string;
  orderId: string;
  orderAmount: number;
  ipAddress: string;
  deviceFingerprint?: string;
  timestamp: number;
  success: boolean;
}

interface UserCouponUsage {
  couponCode: string;
  timestamp: number;
  success: boolean;
}

export class CouponAbusePrevention extends EventEmitter {
  private isInitialized = false;
  private readonly couponUsage: Map<string, CouponUsage[]> = new Map();
  private readonly userCouponHistory: Map<string, UserCouponUsage[]> = new Map();
  private readonly blockedCodes: Set<string> = new Set();
  private readonly blockedUsers: Set<string> = new Set();

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    this.emit('initialized');
  }

  public async destroy(): Promise<void> {
    this.couponUsage.clear();
    this.userCouponHistory.clear();
    this.blockedCodes.clear();
    this.blockedUsers.clear();
    this.isInitialized = false;
    this.emit('destroyed');
  }

  public async validateCoupon(data: {
    couponCode: string;
    userId: string;
    orderId: string;
    orderAmount: number;
    ipAddress: string;
    deviceFingerprint?: string;
  }): Promise<{
    isValid: boolean;
    isAbuse: boolean;
    riskScore: number;
    riskFactors: string[];
    errorMessage?: string;
  }> {
    if (!this.isInitialized) {
      throw new Error('CouponAbusePrevention not initialized');
    }

    if (this.blockedCodes.has(data.couponCode)) {
      return { isValid: false, isAbuse: true, riskScore: 1, riskFactors: ['Coupon blocked'], errorMessage: 'Blocked' };
    }

    if (this.blockedUsers.has(data.userId)) {
      return { isValid: false, isAbuse: true, riskScore: 0.9, riskFactors: ['User blocked'], errorMessage: 'Restricted' };
    }

    const riskFactors: string[] = [];
    let riskScore = 0;

    const multiAccountFactor = await this.detectMultiAccountAbuse(data);
    if (multiAccountFactor.detected) {
      riskScore += 0.4;
      riskFactors.push(...multiAccountFactor.indicators);
    }

    const sharingFactor = await this.detectCodeSharing(data);
    if (sharingFactor.detected) {
      riskScore += 0.3;
      riskFactors.push(...sharingFactor.indicators);
    }

    const velocityFactor = this.checkUsageVelocity(data);
    if (velocityFactor.detected) {
      riskScore += 0.3;
      riskFactors.push(...velocityFactor.indicators);
    }

    const limitFactor = this.checkCouponLimits(data);
    if (limitFactor.exceeded) {
      riskScore += 0.5;
      riskFactors.push(...limitFactor.indicators);
    }

    const patternFactor = this.analyzePatterns(data);
    if (patternFactor.suspicious) {
      riskScore += 0.2;
      riskFactors.push(...patternFactor.indicators);
    }

    const isAbuse = riskScore >= 0.6;
    const isValid = !isAbuse && riskScore < 0.5;

    return { isValid, isAbuse, riskScore: Math.min(1, riskScore), riskFactors, errorMessage: isValid ? undefined : 'Suspicious' };
  }

  private async detectMultiAccountAbuse(data: any): Promise<{ detected: boolean; indicators: string[] }> {
    const indicators: string[] = [];
    let detected = false;

    const ipUsage = this.getUsageByIP(data.ipAddress);
    if (ipUsage.length > 5) {
      const uniqueUsers = new Set(ipUsage.map(u => u.userId)).size;
      if (uniqueUsers > 3) {
        indicators.push(`Multiple accounts (${uniqueUsers}) from same IP`);
        detected = true;
      }
    }

    if (data.deviceFingerprint) {
      const deviceUsage = this.getUsageByDevice(data.deviceFingerprint);
      if (deviceUsage.length > 3) {
        const uniqueUsers = new Set(deviceUsage.map(u => u.userId)).size;
        if (uniqueUsers > 2) {
          indicators.push(`Multiple accounts from same device`);
          detected = true;
        }
      }
    }

    return { detected, indicators };
  }

  private async detectCodeSharing(data: any): Promise<{ detected: boolean; indicators: string[] }> {
    const indicators: string[] = [];
    let detected = false;

    const usage = this.couponUsage.get(data.couponCode) || [];
    const recentUsage = usage.filter(u => Date.now() - u.timestamp < 3600000);

    if (recentUsage.length > 10) {
      const uniqueUsers = new Set(recentUsage.map(u => u.userId)).size;
      if (uniqueUsers > 5) {
        indicators.push('Rapid usage by multiple users');
        detected = true;
      }
    }

    return { detected, indicators };
  }

  private checkUsageVelocity(data: any): { detected: boolean; indicators: string[] } {
    const indicators: string[] = [];
    let detected = false;

    const userHistory = this.userCouponHistory.get(data.userId) || [];
    const last24h = userHistory.filter(u => Date.now() - u.timestamp < 86400000);

    if (last24h.length > 10) {
      indicators.push(`Excessive usage (${last24h.length} in 24h)`);
      detected = true;
    }

    return { detected, indicators };
  }

  private checkCouponLimits(data: any): { exceeded: boolean; indicators: string[] } {
    const indicators: string[] = [];
    let exceeded = false;

    const couponUsage = this.couponUsage.get(data.couponCode) || [];
    if (couponUsage.length > 100) {
      indicators.push('Usage limit exceeded');
      exceeded = true;
    }

    if (data.orderAmount < 10) {
      indicators.push('Order amount below minimum');
      exceeded = true;
    }

    return { exceeded, indicators };
  }

  private analyzePatterns(data: any): { suspicious: boolean; indicators: string[] } {
    const indicators: string[] = [];
    let suspicious = false;

    const botPatterns = ['bot', 'crawler', 'spider', 'automation'];
    if (botPatterns.some(p => data.userAgent?.toLowerCase().includes(p))) {
      indicators.push('Bot-like behavior');
      suspicious = true;
    }

    const hour = new Date().getHours();
    if (hour >= 2 && hour <= 5) {
      indicators.push('Unusual usage time');
      suspicious = true;
    }

    return { suspicious, indicators };
  }

  private isSequentialCode(code: string): boolean {
    const alphanumeric = code.replace(/[^A-Z0-9]/gi, '').toUpperCase();
    let sequential = 0;
    for (let i = 1; i < alphanumeric.length; i++) {
      if (alphanumeric.charCodeAt(i) === alphanumeric.charCodeAt(i - 1) + 1) {
        sequential++;
      }
    }
    return sequential > alphanumeric.length / 2;
  }

  public async blockCoupon(code: string, reason: string): Promise<void> {
    this.blockedCodes.add(code);
    this.emit('coupon_blocked', { code, reason, blockedAt: new Date() });
  }

  public async blockUser(userId: string, reason: string): Promise<void> {
    this.blockedUsers.add(userId);
    this.emit('user_blocked', { userId, reason, blockedAt: new Date() });
  }

  public async unblockCoupon(code: string): Promise<void> {
    this.blockedCodes.delete(code);
    this.emit('coupon_unblocked', { code, unblockedAt: new Date() });
  }

  public async unblockUser(userId: string): Promise<void> {
    this.blockedUsers.delete(userId);
    this.emit('user_unblocked', { userId, unblockedAt: new Date() });
  }

  private getUsageByIP(ipAddress: string): CouponUsage[] {
    const allUsage: CouponUsage[] = [];
    for (const usage of this.couponUsage.values()) {
      allUsage.push(...usage.filter(u => u.ipAddress === ipAddress));
    }
    return allUsage;
  }

  private getUsageByDevice(deviceFingerprint: string): CouponUsage[] {
    const allUsage: CouponUsage[] = [];
    for (const usage of this.couponUsage.values()) {
      allUsage.push(...usage.filter(u => u.deviceFingerprint === deviceFingerprint));
    }
    return allUsage;
  }

  private detectEmailPattern(): { detected: boolean; pattern?: string } {
    return { detected: false };
  }

  public async recordUsage(data: {
    couponCode: string;
    userId: string;
    orderId: string;
    orderAmount: number;
    ipAddress: string;
    deviceFingerprint?: string;
    success: boolean;
  }): Promise<void> {
    if (!this.isInitialized) return;

    const usage: CouponUsage = {
      couponCode: data.couponCode,
      userId: data.userId,
      orderId: data.orderId,
      orderAmount: data.orderAmount,
      ipAddress: data.ipAddress,
      deviceFingerprint: data.deviceFingerprint,
      timestamp: Date.now(),
      success: data.success
    };

    if (!this.couponUsage.has(data.couponCode)) {
      this.couponUsage.set(data.couponCode, []);
    }
    this.couponUsage.get(data.couponCode)!.push(usage);

    if (!this.userCouponHistory.has(data.userId)) {
      this.userCouponHistory.set(data.userId, []);
    }
    this.userCouponHistory.get(data.userId)!.push({
      couponCode: data.couponCode,
      timestamp: usage.timestamp,
      success: usage.success
    });

    this.trimHistory();
  }

  private trimHistory(): void {
    const maxHistory = 1000;
    for (const [code, usage] of this.couponUsage.entries()) {
      if (usage.length > maxHistory) {
        this.couponUsage.set(code, usage.slice(-maxHistory));
      }
    }

    for (const [userId, history] of this.userCouponHistory.entries()) {
      if (history.length > 100) {
        this.userCouponHistory.set(userId, history.slice(-100));
      }
    }
  }

  public getStats(): {
    initialized: boolean;
    trackedCoupons: number;
    blockedCodes: number;
    blockedUsers: number;
    totalUsage: number;
  } {
    const totalUsage = Array.from(this.couponUsage.values()).reduce((sum, arr) => sum + arr.length, 0);
    return {
      initialized: this.isInitialized,
      trackedCoupons: this.couponUsage.size,
      blockedCodes: this.blockedCodes.size,
      blockedUsers: this.blockedUsers.size,
      totalUsage
    };
  }
}
