/**
 * ============================================================================
 * INTEGRITY MONITOR — НЕПРЕРЫВНЫЙ МОНИТОРИНГ ЦЕЛОСТНОСТИ
 * ============================================================================
 * Периодически генерирует attestation reports, сравнивает RBOM со SBOM,
 * обнаруживает drift и генерирует alerts. Поддерживает hash chain для
 * immutability истории аттестаций.
 *
 * KILLER FEATURE: Автоматическое обнаружение modification runtime
 * (code injection, dependency tampering, config changes) в реальном времени.
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { AttestationEngine, createAttestationEngine } from './AttestationEngine';
import { RBOMGenerator, createRBOMGenerator } from './RBOMGenerator';
import { SBOMComparator, createSBOMComparator, SBOM } from './SBOMComparator';
import {
  IntegrityMonitorConfig,
  IntegrityMonitorStats,
  IntegrityEvent,
  AttestationReport,
  RBOM,
  DriftReport,
  AttestationVerification,
  DriftSeverity
} from './attestation.types';

/** Default конфигурация */
const DEFAULT_CONFIG: IntegrityMonitorConfig = {
  attestationInterval: 60000, // 1 минута
  autoAlert: true,
  enableHashChain: true,
  hmacSecret: 'default-secret-change-in-production',
  maxHistoryLength: 1000,
  logEachAttestation: true
};

export class IntegrityMonitor extends EventEmitter {
  private config: IntegrityMonitorConfig;
  private engine: AttestationEngine;
  private rbomGenerator: RBOMGenerator;
  private comparator: SBOMComparator | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private running: boolean = false;
  private history: { report: AttestationReport; rbom?: RBOM; drift?: DriftReport }[] = [];
  private stats: {
    totalAttestations: number;
    totalDriftsDetected: number;
    lastAttestationTime: Date | null;
    lastDriftTime: Date | null;
    currentSeverity: DriftSeverity;
    averageAttestationTimeMs: number;
    attestationTimes: number[];
  } = {
    totalAttestations: 0,
    totalDriftsDetected: 0,
    lastAttestationTime: null,
    lastDriftTime: null,
    currentSeverity: 'none',
    averageAttestationTimeMs: 0,
    attestationTimes: []
  };

  constructor(config: Partial<IntegrityMonitorConfig>, sbom?: SBOM) {
    super();

    this.config = { ...DEFAULT_CONFIG, ...config };

    // Валидация hmac secret
    if (!this.config.hmacSecret || this.config.hmacSecret === 'default-secret-change-in-production') {
      this.config.hmacSecret = require('crypto').randomBytes(32).toString('hex');
    }

    this.engine = createAttestationEngine({
      hmacSecret: this.config.hmacSecret,
      componentName: 'protocol-security',
      componentVersion: '3.0.0'
    });

    this.rbomGenerator = createRBOMGenerator(this.engine);

    if (sbom) {
      this.comparator = createSBOMComparator(sbom, this.config.hmacSecret);
    }
  }

  /**
   * Запускает непрерывный мониторинг целостности
   */
  start(): void {
    if (this.running) return;

    this.running = true;
    this.emitEvent('monitor_started', 'low', 'Integrity monitoring started');

    // Первоначальная аттестация
    this.attestate().catch(err => {
      this.emitEvent('verification_failed', 'high', `Initial attestation failed: ${err.message}`);
    });

    // Периодическая аттестация
    this.timer = setInterval(() => {
      this.attestate().catch(err => {
        this.emitEvent('verification_failed', 'high', `Attestation failed: ${err.message}`);
      });
    }, this.config.attestationInterval);
  }

  /**
   * Останавливает мониторинг
   */
  stop(): void {
    if (!this.running) return;

    this.running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }

    this.emitEvent('monitor_stopped', 'low', 'Integrity monitoring stopped');
  }

  /**
   * Выполняет одну аттестацию
   */
  async attestate(): Promise<AttestationVerification> {
    const startTime = Date.now();

    try {
      // 1. Генерируем attestation report
      const report = await this.engine.generateReport('periodic');

      // 2. Генерируем RBOM
      const rbom = await this.rbomGenerator.generateRBOM({ includeAttestation: true });

      // 3. Верифицируем report
      const signatureValid = this.engine.verifyReport(report);
      const hashChainValid = this.engine.verifyHashChain(report);

      let driftReport: DriftReport | undefined;
      let driftDetected = false;

      // 4. Сравниваем со SBOM (если есть comparator)
      if (this.comparator) {
        driftReport = this.comparator.compare(rbom);
        driftDetected = driftReport.severity !== 'none';

        if (driftDetected && this.config.autoAlert) {
          this.emitEvent(
            'drift_detected',
            driftReport.severity,
            `Drift detected: ${driftReport.riskSummary}`,
            { driftReport }
          );
        }
      }

      // 5. Сохраняем в историю
      this.addToHistory({ report, rbom, drift: driftReport });

      // 6. Обновляем статистику
      const elapsed = Date.now() - startTime;
      this.stats.totalAttestations++;
      this.stats.lastAttestationTime = new Date();
      this.stats.attestationTimes.push(elapsed);
      this.stats.averageAttestationTimeMs = this.stats.attestationTimes.reduce((a, b) => a + b, 0) / this.stats.attestationTimes.length;

      if (driftDetected && driftReport) {
        this.stats.totalDriftsDetected++;
        this.stats.lastDriftTime = new Date();
        this.stats.currentSeverity = driftReport.severity;
      }

      // 7. Эмитим событие
      this.emitEvent(
        'attestation_completed',
        driftDetected ? 'high' : 'none',
        driftDetected ? `Drift: ${driftReport?.riskSummary}` : 'No drift detected',
        { reportId: report.reportId, signatureValid, hashChainValid }
      );

      // 8. Эмитим verification result
      this.emit('attestation', {
        report,
        rbom,
        drift: driftReport,
        verified: signatureValid && hashChainValid
      });

      return {
        reportId: report.reportId,
        verified: signatureValid && hashChainValid && !driftDetected,
        signatureValid,
        hashChainValid,
        driftDetected,
        driftReport,
        timestamp: report.timestamp,
        errors: []
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.emitEvent('verification_failed', 'critical', `Attestation failed: ${errorMessage}`);

      return {
        reportId: '',
        verified: false,
        signatureValid: false,
        hashChainValid: false,
        driftDetected: false,
        timestamp: new Date(),
        errors: [errorMessage]
      };
    }
  }

  /**
   * Выполняет on-demand аттестацию (вне расписания)
   */
  async attestateOnDemand(): Promise<AttestationVerification> {
    const report = await this.engine.generateReport('on-demand');
    const rbom = await this.rbomGenerator.generateRBOM({ includeAttestation: true });

    const signatureValid = this.engine.verifyReport(report);
    const hashChainValid = this.engine.verifyHashChain(report);

    let driftReport: DriftReport | undefined;
    let driftDetected = false;

    if (this.comparator) {
      driftReport = this.comparator.compare(rbom);
      driftDetected = driftReport.severity !== 'none';
    }

    this.addToHistory({ report, rbom, drift: driftReport });

    return {
      reportId: report.reportId,
      verified: signatureValid && hashChainValid && !driftDetected,
      signatureValid,
      hashChainValid,
      driftDetected,
      driftReport,
      timestamp: report.timestamp,
      errors: []
    };
  }

  /**
   * Получает статистику монитора
   */
  getStats(): IntegrityMonitorStats {
    return {
      totalAttestations: this.stats.totalAttestations,
      totalDriftsDetected: this.stats.totalDriftsDetected,
      lastAttestationTime: this.stats.lastAttestationTime,
      lastDriftTime: this.stats.lastDriftTime,
      currentSeverity: this.stats.currentSeverity,
      historyLength: this.history.length,
      uptime: this.running ? Date.now() : 0,
      averageAttestationTimeMs: this.stats.averageAttestationTimeMs
    };
  }

  /**
   * Получает историю аттестаций
   */
  getHistory(limit?: number): typeof this.history {
    if (limit) {
      return this.history.slice(-limit);
    }
    return [...this.history];
  }

  /**
   * Получает последнюю аттестацию
   */
  getLastAttestation(): typeof this.history[0] | null {
    return this.history.length > 0 ? this.history[this.history.length - 1] : null;
  }

  /**
   * Обновляет SBOM для сравнения
   */
  updateSBOM(sbom: SBOM): void {
    this.comparator = createSBOMComparator(sbom, this.config.hmacSecret);
  }

  /**
   * Проверяет, запущен ли мониторинг
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Эмитит integrity event
   */
  private emitEvent(
    type: IntegrityEvent['type'],
    severity: DriftSeverity,
    message: string,
    details?: Record<string, unknown>
  ): void {
    const event: IntegrityEvent = {
      eventId: require('crypto').randomUUID(),
      timestamp: new Date(),
      type,
      severity,
      message,
      details
    };

    this.emit('integrity_event', event);

    if (this.config.logEachAttestation) {
      console.log(`[IntegrityMonitor] [${severity.toUpperCase()}] ${message}`);
    }
  }

  /**
   * Добавляет запись в историю с ограничением длины
   */
  private addToHistory(entry: { report: AttestationReport; rbom?: RBOM; drift?: DriftReport }): void {
    this.history.push(entry);

    if (this.history.length > this.config.maxHistoryLength) {
      this.history = this.history.slice(-this.config.maxHistoryLength);
    }
  }

  /**
   * Очищает ресурсы
   */
  destroy(): void {
    this.stop();
    this.history = [];
    this.removeAllListeners();
  }
}

/**
 * Фабричная функция
 */
export function createIntegrityMonitor(
  config: Partial<IntegrityMonitorConfig>,
  sbom?: SBOM
): IntegrityMonitor {
  return new IntegrityMonitor(config, sbom);
}
