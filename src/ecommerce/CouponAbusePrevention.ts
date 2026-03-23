/**
 * Coupon Abuse Prevention Stub
 */
export class CouponAbusePrevention {
  async initialize(): Promise<void> {}
  async destroy(): Promise<void> {}

  async validateCoupon(data: any): Promise<any> {
    return { isValid: true };
  }

  async detectCouponAbuse(data: any): Promise<any> {
    return { isAbuse: false };
  }

  async preventStacking(data: any): Promise<any> {
    return { isStackingAllowed: true };
  }
}
