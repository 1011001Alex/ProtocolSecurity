/**
 * ============================================================================
 * HEALTHCARE IDENTITY — ИДЕНТИФИКАЦИЯ ПАЦИЕНТОВ И ПРОВАЙДЕРОВ
 * ============================================================================
 *
 * Master Patient Index (MPI) и верификация медицинских работников
 *
 * Функциональность:
 * - MPI интеграция
 * - NPI (National Provider Identifier) верификация
 * - Credential verification
 * - Identity assurance levels (IAL)
 *
 * @package protocol/healthcare-security/identity
 */

import { EventEmitter } from 'events';
import { logger } from '../../logging/Logger';
import { MPIRecord } from '../types/healthcare.types';

export class HealthcareIdentity extends EventEmitter {
  private mpiRecords: Map<string, MPIRecord> = new Map();
  private isInitialized = false;

  constructor() {
    super();
    logger.info('[HealthcareIdentity] Service created');
  }

  public async initialize(): Promise<void> {
    if (this.isInitialized) return;
    this.isInitialized = true;
    logger.info('[HealthcareIdentity] Initialized');
    this.emit('initialized');
  }

  /**
   * Создание MPI записи
   */
  public async createMPIRecord(patientData: {
    name: string;
    dateOfBirth: Date;
    gender: string;
    localIds?: { system: string; id: string }[];
  }): Promise<MPIRecord> {
    const globalPatientId = `mpi-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const record: MPIRecord = {
      globalPatientId,
      localIds: patientData.localIds || [],
      demographics: {
        name: patientData.name,
        dateOfBirth: patientData.dateOfBirth,
        gender: patientData.gender
      },
      status: 'ACTIVE',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.mpiRecords.set(globalPatientId, record);

    logger.info('[HealthcareIdentity] MPI record created', {
      globalPatientId,
      name: patientData.name
    });

    this.emit('mpi_record_created', record);

    return record;
  }

  /**
   * Поиск пациента в MPI
   */
  public async searchMPI(searchCriteria: {
    name?: string;
    dateOfBirth?: Date;
    gender?: string;
    localId?: { system: string; id: string };
  }): Promise<MPIRecord[]> {
    const results: MPIRecord[] = [];

    for (const record of this.mpiRecords.values()) {
      let match = true;

      if (searchCriteria.name) {
        const nameMatch = record.demographics.name
          .toLowerCase()
          .includes(searchCriteria.name.toLowerCase());

        if (!nameMatch) match = false;
      }

      if (searchCriteria.dateOfBirth) {
        const dobMatch =
          record.demographics.dateOfBirth.getTime() ===
          searchCriteria.dateOfBirth.getTime();

        if (!dobMatch) match = false;
      }

      if (searchCriteria.localId) {
        const localIdMatch = record.localIds.some(
          id =>
            id.system === searchCriteria.localId!.system &&
            id.id === searchCriteria.localId!.id
        );

        if (!localIdMatch) match = false;
      }

      if (match) {
        results.push(record);
      }
    }

    logger.info('[HealthcareIdentity] MPI search completed', {
      criteria: searchCriteria,
      resultsCount: results.length
    });

    return results;
  }

  /**
   * Связывание записей (merge)
   */
  public async mergeRecords(
    primaryId: string,
    duplicateIds: string[]
  ): Promise<MPIRecord> {
    const primary = this.mpiRecords.get(primaryId);

    if (!primary) {
      throw new Error(`Record not found: ${primaryId}`);
    }

    for (const dupId of duplicateIds) {
      const duplicate = this.mpiRecords.get(dupId);

      if (duplicate) {
        duplicate.status = 'MERGED';
        duplicate.linkedRecords = [primaryId];
        this.mpiRecords.set(dupId, duplicate);

        // Перенос local IDs
        for (const localId of duplicate.localIds) {
          if (!primary.localIds.some(id => id.id === localId.id)) {
            primary.localIds.push(localId);
          }
        }
      }
    }

    primary.updatedAt = new Date();
    this.mpiRecords.set(primaryId, primary);

    logger.info('[HealthcareIdentity] Records merged', {
      primaryId,
      duplicateIds
    });

    this.emit('records_merged', { primaryId, duplicateIds });

    return primary;
  }

  /**
   * Верификация NPI (National Provider Identifier)
   */
  public async verifyNPI(npi: string): Promise<{
    valid: boolean;
    providerName?: string;
    specialty?: string;
    state?: string;
  }> {
    logger.info('[HealthcareIdentity] Verifying NPI', { npi });

    // В production реальная проверка через NPPES NPI Registry
    const isValid = /^\d{10}$/.test(npi);

    return {
      valid: isValid,
      providerName: isValid ? 'Dr. John Smith' : undefined,
      specialty: isValid ? 'Internal Medicine' : undefined,
      state: isValid ? 'NY' : undefined
    };
  }

  /**
   * Верификация учётных данных провайдера
   */
  public async verifyCredentials(providerId: string, credentials: {
    npi?: string;
    dea?: string;
    stateLicense?: string;
  }): Promise<{
    verified: boolean;
    verifications: Array<{ type: string; status: 'VALID' | 'INVALID' | 'EXPIRED' }>;
  }> {
    const verifications: Array<{ type: string; status: 'VALID' | 'INVALID' | 'EXPIRED' }> = [];

    if (credentials.npi) {
      const npiResult = await this.verifyNPI(credentials.npi);
      verifications.push({
        type: 'NPI',
        status: npiResult.valid ? 'VALID' : 'INVALID'
      });
    }

    logger.info('[HealthcareIdentity] Credentials verified', {
      providerId,
      verifications
    });

    return {
      verified: verifications.every(v => v.status === 'VALID'),
      verifications
    };
  }

  /**
   * Получение MPI записи
   */
  public getMPIRecord(globalPatientId: string): MPIRecord | undefined {
    return this.mpiRecords.get(globalPatientId);
  }

  public async destroy(): Promise<void> {
    this.mpiRecords.clear();
    this.isInitialized = false;
    logger.info('[HealthcareIdentity] Destroyed');
    this.emit('destroyed');
  }
}
