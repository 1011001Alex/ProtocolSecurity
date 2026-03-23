/**
 * Healthcare Identity Stub
 */
export class HealthcareIdentity {
  async initialize(): Promise<void> {}
  async destroy(): Promise<void> {}

  async verifyIdentity(data: any, ial: string): Promise<any> {
    return { verified: true, ial };
  }

  async registerPatient(data: any): Promise<any> {
    return { patientId: 'patient-' + Date.now(), ...data };
  }

  async detectDuplicate(data: any): Promise<any> {
    return { potentialDuplicates: [] };
  }

  async mergePatients(id1: string, id2: string, reason: string): Promise<boolean> {
    return true;
  }
}
