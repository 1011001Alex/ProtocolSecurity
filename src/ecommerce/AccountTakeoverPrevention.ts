/**
 * Account Takeover Prevention Stub
 */
export class AccountTakeoverPrevention {
  async initialize(): Promise<void> {}
  async destroy(): Promise<void> {}

  async analyzeLoginAttempt(data: any): Promise<any> {
    return {
      riskScore: 10,
      riskLevel: 'LOW'
    };
  }

  async requireMFA(email: string): Promise<boolean> {
    return true;
  }

  async detectImpossibleTravel(data: any): Promise<any> {
    return { isImpossible: true, distance: 10000 };
  }

  async blockLoginAttempt(data: any): Promise<boolean> {
    return true;
  }
}
