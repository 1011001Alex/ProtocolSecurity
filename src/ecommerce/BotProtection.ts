/**
 * Bot Protection Stub
 */
export class BotProtection {
  async initialize(): Promise<void> {}
  async destroy(): Promise<void> {}

  async analyzeRequest(data: any): Promise<any> {
    return {
      score: data.userAgent?.includes('bot') ? 80 : 10,
      recommendation: 'ALLOW',
      ipAddress: data.ipAddress
    };
  }

  async serveCaptcha(): Promise<any> {
    return { challengeId: 'captcha-' + Date.now() };
  }

  async verifyCaptcha(data: any): Promise<any> {
    return { success: true };
  }

  async blockIP(ip: string): Promise<boolean> {
    return true;
  }

  getBlockedIPs(): string[] {
    return [];
  }
}
