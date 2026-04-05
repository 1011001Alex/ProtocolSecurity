/**
 * ============================================================================
 * SBOM COMPARATOR — СРАВНЕНИЕ SBOM И RBOM ДЛЯ ОБНАРУЖЕНИЯ DRIFT
 * ============================================================================
 * Сравнивает build-time SBOM с runtime RBOM и обнаруживает:
 * - MISSING: компоненты в SBOM но не загружены в runtime
 * - UNEXPECTED: загружены в runtime но нет в SBOM (potential code injection!)
 * - MODIFIED: версии или хэши не совпадают
 *
 * Это KILLER FEATURE — ни один security инструмент не делает это автоматически.
 * ============================================================================
 */

import * as crypto from 'crypto';
import {
  DriftReport,
  DriftSeverity,
  RBOM,
  RBOMComponent,
  ModifiedComponent
} from './attestation.types';

/** SBOM Component (упрощённый формат из SBOM файлов) */
export interface SBOMComponent {
  name: string;
  version: string;
  hash?: string;
  type: string;
  purl?: string;
}

/** SBOM — Software Bill of Materials */
export interface SBOM {
  bomFormat: string;
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    component: {
      name: string;
      version: string;
    };
    timestamp: string;
  };
  components: SBOMComponent[];
  dependencies?: { ref: string; dependsOn: string[] }[];
}

export class SBOMComparator {
  private sbom: SBOM;
  private hmacSecret: string;

  constructor(sbom: SBOM, hmacSecret: string) {
    this.sbom = sbom;
    this.hmacSecret = hmacSecret;
  }

  /**
   * Сравнивает SBOM с RBOM и генерирует DriftReport
   */
  compare(rbom: RBOM): DriftReport {
    const sbomComponents = this.normalizeSBOMComponents();
    const rbomComponents = this.normalizeRBOMComponents(rbom);

    // Создаём lookup maps
    const sbomMap = new Map<string, SBOMComponent>();
    const rbomMap = new Map<string, RBOMComponent>();

    for (const c of sbomComponents) {
      sbomMap.set(c.name.toLowerCase(), c);
    }
    for (const c of rbomComponents) {
      rbomMap.set(c.name.toLowerCase(), c);
    }

    // MISSING: в SBOM есть, но не в runtime
    const missing: RBOMComponent[] = [];
    for (const [name, sbomComp] of sbomMap) {
      if (!rbomMap.has(name)) {
        missing.push(this.sbomToRBOMComponent(sbomComp));
      }
    }

    // UNEXPECTED: в runtime есть, но нет в SBOM
    const unexpected: RBOMComponent[] = [];
    for (const [name, rbomComp] of rbomMap) {
      if (!sbomMap.has(name)) {
        unexpected.push({ ...rbomComp, status: 'unexpected' });
      }
    }

    // MODIFIED: версии или хэши не совпадают
    const modified: ModifiedComponent[] = [];
    for (const [name, sbomComp] of sbomMap) {
      const rbomComp = rbomMap.get(name);
      if (rbomComp) {
        const versionMismatch = sbomComp.version !== rbomComp.version;
        const hashMismatch = sbomComp.hash && rbomComp.hash && sbomComp.hash !== rbomComp.hash;

        if (versionMismatch || hashMismatch) {
          modified.push({
            name: sbomComp.name,
            expectedVersion: sbomComp.version,
            actualVersion: rbomComp.version,
            expectedHash: sbomComp.hash || 'not-specified',
            actualHash: rbomComp.hash || 'not-available',
            riskDescription: versionMismatch
              ? `Version mismatch: expected ${sbomComp.version}, found ${rbomComp.version}`
              : `Hash mismatch: component may have been modified`
          });
        }
      }
    }

    // Определяем severity
    const severity = this.calculateSeverity(missing, unexpected, modified);

    // Генерируем recommendation
    const recommendation = this.generateRecommendations(missing, unexpected, modified);

    const report: DriftReport = {
      driftId: crypto.randomUUID(),
      timestamp: new Date(),
      sbomHash: crypto.createHash('sha256').update(JSON.stringify(this.sbom)).digest('hex'),
      rbomSerialNumber: rbom.serialNumber,
      missing,
      unexpected,
      modified,
      severity,
      riskSummary: this.generateRiskSummary(missing, unexpected, modified),
      recommendation,
      attestationReportId: rbom.metadata.attestationReportId,
      signature: ''
    };

    // Подписываем отчёт
    report.signature = this.signReport(report);

    return report;
  }

  /**
   * Получает SBOM
   */
  getSBOM(): SBOM {
    return this.sbom;
  }

  /**
   * Обновляет SBOM
   */
  updateSBOM(newSBOM: SBOM): void {
    this.sbom = newSBOM;
  }

  /**
   * Нормализует компоненты SBOM
   */
  private normalizeSBOMComponents(): SBOMComponent[] {
    return this.sbom.components.map(c => ({
      name: c.name,
      version: c.version,
      hash: c.hash,
      type: c.type,
      purl: c.purl
    }));
  }

  /**
   * Нормализует компоненты RBOM
   */
  private normalizeRBOMComponents(rbom: RBOM): RBOMComponent[] {
    return rbom.components.filter(c => c.type === 'library' || c.type === 'framework');
  }

  /**
   * Конвертирует SBOM component в RBOM component
   */
  private sbomToRBOMComponent(sbomComp: SBOMComponent): RBOMComponent {
    return {
      type: 'library',
      name: sbomComp.name,
      version: sbomComp.version,
      hash: sbomComp.hash || '',
      path: `node_modules/${sbomComp.name}`,
      status: 'missing',
      purl: sbomComp.purl
    };
  }

  /**
   * Рассчитывает severity drift
   */
  private calculateSeverity(
    missing: RBOMComponent[],
    unexpected: RBOMComponent[],
    modified: ModifiedComponent[]
  ): DriftSeverity {
    // Unexpected компоненты — самые опасные (potential code injection)
    if (unexpected.length > 0) {
      return 'critical';
    }

    // Modified с hash mismatch — высокий риск
    const hashModifications = modified.filter(m => m.expectedHash !== 'not-specified' && m.actualHash !== 'not-available');
    if (hashModifications.length > 0) {
      return 'high';
    }

    // Version mismatch — средний риск
    if (modified.length > 0) {
      return 'medium';
    }

    // Missing компоненты — низкий риск (могут быть optional dependencies)
    if (missing.length > 0) {
      return 'low';
    }

    return 'none';
  }

  /**
   * Генерирует рекомендации
   */
  private generateRecommendations(
    missing: RBOMComponent[],
    unexpected: RBOMComponent[],
    modified: ModifiedComponent[]
  ): string {
    const recommendations: string[] = [];

    if (unexpected.length > 0) {
      recommendations.push(
        `CRITICAL: Обнаружены ${unexpected.length} компонентов не из SBOM. Возможна code injection. Проверьте: ${unexpected.slice(0, 5).map(c => c.name).join(', ')}`
      );
    }

    if (modified.length > 0) {
      recommendations.push(
        `HIGH: ${modified.length} компонентов имеют изменённые версии/хэши. Проверьте целостность зависимостей.`
      );
    }

    if (missing.length > 0) {
      recommendations.push(
        `LOW: ${missing.length} компонентов из SBOM не загружены. Это может быть нормально для optional dependencies.`
      );
    }

    if (recommendations.length === 0) {
      recommendations.push('Drift не обнаружен. SBOM и RBOM совпадают.');
    }

    return recommendations.join(' ');
  }

  /**
   * Генерирует summary риска
   */
  private generateRiskSummary(
    missing: RBOMComponent[],
    unexpected: RBOMComponent[],
    modified: ModifiedComponent[]
  ): string {
    const parts: string[] = [];

    if (unexpected.length > 0) {
      parts.push(`${unexpected.length} unexpected components (potential injection)`);
    }
    if (modified.length > 0) {
      parts.push(`${modified.length} modified components`);
    }
    if (missing.length > 0) {
      parts.push(`${missing.length} missing components`);
    }

    return parts.length > 0 ? parts.join(', ') : 'No drift detected';
  }

  /**
   * Подписывает отчёт HMAC
   */
  private signReport(report: DriftReport): string {
    const data = JSON.stringify({
      driftId: report.driftId,
      timestamp: report.timestamp.toISOString(),
      sbomHash: report.sbomHash,
      rbomSerialNumber: report.rbomSerialNumber,
      missing: report.missing.map(c => c.name),
      unexpected: report.unexpected.map(c => c.name),
      modified: report.modified.map(m => m.name),
      severity: report.severity
    });

    return crypto.createHmac('sha256', this.hmacSecret).update(data).digest('hex');
  }

  /**
   * Верифицирует подпись DriftReport
   */
  verifyReport(report: DriftReport): boolean {
    if (!report.signature || report.signature.length !== 64) return false;
    try {
      const expectedSignature = this.signReport(report);
      return crypto.timingSafeEqual(
        Buffer.from(expectedSignature),
        Buffer.from(report.signature)
      );
    } catch {
      return false;
    }
  }
}

/**
 * Фабричная функция
 */
export function createSBOMComparator(sbom: SBOM, hmacSecret: string): SBOMComparator {
  return new SBOMComparator(sbom, hmacSecret);
}
