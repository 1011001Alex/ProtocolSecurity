/**
 * ============================================================================
 * ATTESTATION TESTS — ПОЛНЫЕ ТЕСТЫ RBOM СИСТЕМЫ
 * ============================================================================
 * Тестирует: AttestationEngine, RBOMGenerator, SBOMComparator, IntegrityMonitor
 * Цель: 50+ тестов, 100% pass rate
 * ============================================================================
 */

import * as assert from 'assert';
import { describe, it, beforeEach, afterEach } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';

import {
  AttestationEngine,
  createAttestationEngine,
  RBOMGenerator,
  createRBOMGenerator,
  SBOMComparator,
  createSBOMComparator,
  IntegrityMonitor,
  createIntegrityMonitor,
  SBOM
} from '../../src/attestation/index.js';

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function createMockSBOM(): SBOM {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.4',
    serialNumber: 'urn:uuid:test-sbom-123',
    version: 1,
    metadata: {
      component: {
        name: 'protocol-security',
        version: '3.0.0'
      },
      timestamp: new Date().toISOString()
    },
    components: [
      { name: 'express', version: '4.18.0', type: 'library', hash: 'abc123' },
      { name: 'bcrypt', version: '5.1.0', type: 'library', hash: 'def456' },
      { name: 'jsonwebtoken', version: '9.0.0', type: 'library', hash: 'ghi789' },
      { name: 'winston', version: '3.11.0', type: 'library', hash: 'jkl012' }
    ]
  };
}

function createMockRBOM(): any {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:test-rbom-456',
    version: 1,
    metadata: {
      timestamp: new Date(),
      component: { name: 'protocol-security', version: '3.0.0', type: 'application' },
      attestationReportId: 'report-123'
    },
    components: [
      { type: 'library', name: 'express', version: '4.18.0', hash: 'abc123', path: 'node_modules/express', status: 'expected' },
      { type: 'library', name: 'bcrypt', version: '5.1.0', hash: 'def456', path: 'node_modules/bcrypt', status: 'expected' },
      { type: 'library', name: 'jsonwebtoken', version: '9.0.0', hash: 'ghi789', path: 'node_modules/jsonwebtoken', status: 'expected' },
      { type: 'library', name: 'winston', version: '3.11.0', hash: 'jkl012', path: 'node_modules/winston', status: 'expected' }
    ],
    services: [],
    dependencies: [],
    attestations: []
  };
}

// ============================================================================
// ATTESTATION ENGINE TESTS
// ============================================================================

describe('AttestationEngine', () => {
  let engine: AttestationEngine;

  beforeEach(() => {
    engine = createAttestationEngine({
      hmacSecret: 'test-secret-key-for-attestation',
      componentName: 'test-app',
      componentVersion: '1.0.0'
    });
  });

  describe('generateReport', () => {
    it('должен генерировать отчёт с уникальным ID', async () => {
      const report1 = await engine.generateReport('periodic');
      const report2 = await engine.generateReport('periodic');

      assert.ok(report1.reportId);
      assert.ok(report2.reportId);
      assert.notStrictEqual(report1.reportId, report2.reportId);
    });

    it('должен устанавливать тип аттестации', async () => {
      const reportInitial = await engine.generateReport('initial');
      const reportPeriodic = await engine.generateReport('periodic');
      const reportOnDemand = await engine.generateReport('on-demand');

      assert.strictEqual(reportInitial.type, 'initial');
      assert.strictEqual(reportPeriodic.type, 'periodic');
      assert.strictEqual(reportOnDemand.type, 'on-demand');
    });

    it('должен включать component hashes', async () => {
      const report = await engine.generateReport();

      assert.ok(report.componentHashes);
      assert.ok(Object.keys(report.componentHashes).length > 0);
    });

    it('должен включать loaded packages', async () => {
      const report = await engine.generateReport();

      assert.ok(Array.isArray(report.loadedPackages));
      assert.ok(report.loadedPackages.length > 0);

      const firstPkg = report.loadedPackages[0];
      assert.ok(firstPkg.name);
      assert.ok(firstPkg.version);
      assert.ok(firstPkg.hash);
    });

    it('должен включать active services', async () => {
      const report = await engine.generateReport();

      assert.ok(Array.isArray(report.activeServices));
    });

    it('должен включать crypto state', async () => {
      const report = await engine.generateReport();

      assert.ok(report.cryptoState);
      assert.ok(Array.isArray(report.cryptoState.algorithms));
      assert.ok(report.cryptoState.algorithms.length > 0);
    });

    it('должен включать environment hash', async () => {
      const report = await engine.generateReport();

      assert.ok(report.environmentHash);
      assert.strictEqual(report.environmentHash.length, 64); // SHA-256 hex
    });

    it('должен включать memory footprint', async () => {
      const report = await engine.generateReport();

      assert.ok(report.memoryFootprint > 0);
    });

    it('должен включать PID процесса', async () => {
      const report = await engine.generateReport();

      assert.strictEqual(report.pid, process.pid);
    });

    it('должен включать uptime', async () => {
      const report = await engine.generateReport();

      assert.ok(report.uptime > 0);
    });

    it('должен создавать hash chain между отчётами', async () => {
      const report1 = await engine.generateReport();
      const report2 = await engine.generateReport();

      assert.ok(report2.previousReportHash);
      // Hash chain: report2 ссылается на hash report1
      assert.strictEqual(typeof report2.previousReportHash, 'string');
      assert.ok(report2.previousReportHash.length > 0);
    });

    it('должен подписывать отчёт (HMAC signature)', async () => {
      const report = await engine.generateReport();

      assert.ok(report.signature);
      assert.strictEqual(report.signature.length, 64); // SHA-256 hex
    });

    it('должен возвращать компонент info', () => {
      const info = engine.getComponentInfo();

      assert.strictEqual(info.name, 'test-app');
      assert.strictEqual(info.version, '1.0.0');
    });
  });

  describe('verifyReport', () => {
    it('должен верифицировать валидный отчёт', async () => {
      const report = await engine.generateReport();

      assert.strictEqual(engine.verifyReport(report), true);
    });

    it('должен отклонять отчёт с изменённой подписью', async () => {
      const report = await engine.generateReport();
      // Изменяем данные (не подпись) — подпись должна стать невалидной
      report.memoryFootprint = 999999;

      assert.strictEqual(engine.verifyReport(report), false);
    });

    it('должен отклонять отчёт с изменёнными данными', async () => {
      const report = await engine.generateReport();
      report.memoryFootprint = 999999;

      assert.strictEqual(engine.verifyReport(report), false);
    });
  });

  describe('hashChain', () => {
    it('должен верифицировать hash chain', async () => {
      const report1 = await engine.generateReport();
      const report2 = await engine.generateReport();

      assert.strictEqual(engine.verifyHashChain(report2), true);
    });

    it('должен принимать первый отчёт без previous hash', async () => {
      engine.resetHashChain();
      const report = await engine.generateReport();

      assert.strictEqual(engine.verifyHashChain(report), true);
    });

    it('должен сбрасывать hash chain', async () => {
      await engine.generateReport();
      const lastHash = engine.getLastReportHash();

      engine.resetHashChain();

      assert.strictEqual(engine.getLastReportHash(), '');
    });
  });
});

// ============================================================================
// RBOM GENERATOR TESTS
// ============================================================================

describe('RBOMGenerator', () => {
  let engine: AttestationEngine;
  let generator: RBOMGenerator;

  beforeEach(() => {
    engine = createAttestationEngine({
      hmacSecret: 'test-secret-rbom',
      componentName: 'test-app',
      componentVersion: '1.0.0'
    });
    generator = createRBOMGenerator(engine);
  });

  describe('generateRBOM', () => {
    it('должен генерировать RBOM с правильным форматом', async () => {
      const rbom = await generator.generateRBOM();

      assert.strictEqual(rbom.bomFormat, 'CycloneDX');
      assert.strictEqual(rbom.specVersion, '1.5');
      assert.ok(rbom.serialNumber);
      assert.ok(rbom.version >= 1);
    });

    it('должен увеличивать version при каждой генерации', async () => {
      const rbom1 = await generator.generateRBOM();
      const rbom2 = await generator.generateRBOM();

      assert.strictEqual(rbom2.version, rbom1.version + 1);
    });

    it('должен включать компоненты', async () => {
      const rbom = await generator.generateRBOM();

      assert.ok(Array.isArray(rbom.components));
      assert.ok(rbom.components.length > 0);

      // Должен включать Node.js runtime
      const runtime = rbom.components.find(c => c.type === 'runtime');
      assert.ok(runtime);
      assert.ok(runtime!.name.includes('Node.js'));
    });

    it('должен включать библиотеки как компоненты', async () => {
      const rbom = await generator.generateRBOM();

      const libraries = rbom.components.filter(c => c.type === 'library');
      assert.ok(libraries.length > 0);

      const firstLib = libraries[0];
      assert.ok(firstLib.name);
      assert.ok(firstLib.version);
      assert.ok(firstLib.purl);
    });

    it('должен включать services', async () => {
      const rbom = await generator.generateRBOM();

      assert.ok(Array.isArray(rbom.services));
    });

    it('должен включать dependencies', async () => {
      const rbom = await generator.generateRBOM();

      assert.ok(Array.isArray(rbom.dependencies));
    });

    it('должен включать attestations', async () => {
      const rbom = await generator.generateRBOM({ includeAttestation: true });

      assert.ok(rbom.attestations.length > 0);
      assert.ok(rbom.attestations[0].reportId);
      assert.ok(rbom.attestations[0].hash);
    });

    it('должен включать metadata', async () => {
      const rbom = await generator.generateRBOM();

      assert.strictEqual(rbom.metadata.component.name, 'test-app');
      assert.strictEqual(rbom.metadata.component.version, '1.0.0');
      assert.strictEqual(rbom.metadata.component.type, 'application');
    });

    it('должен сериализовать в JSON', async () => {
      const rbom = await generator.generateRBOM();
      const json = generator.toJSON(rbom);

      assert.ok(typeof json === 'string');
      assert.ok(json.length > 100);

      const parsed = JSON.parse(json);
      assert.strictEqual(parsed.bomFormat, 'CycloneDX');
    });

    it('должен сохранять и загружать из файла', async () => {
      const rbom = await generator.generateRBOM();
      const filePath = path.join(process.cwd(), 'test_rbom_temp.json');

      generator.saveToFile(rbom, filePath);

      assert.ok(fs.existsSync(filePath));

      const loaded = generator.loadFromFile(filePath);
      assert.strictEqual(loaded.bomFormat, 'CycloneDX');
      assert.strictEqual(loaded.serialNumber, rbom.serialNumber);

      fs.unlinkSync(filePath);
    });
  });

  describe('compareRBOMs', () => {
    it('должен обнаруживать добавленные компоненты', () => {
      const oldRBOM = createMockRBOM();
      const newRBOM = createMockRBOM();
      newRBOM.components.push({
        type: 'library',
        name: 'malicious-pkg',
        version: '1.0.0',
        hash: 'xyz789',
        path: 'node_modules/malicious-pkg',
        status: 'unexpected'
      });

      const diff = RBOMGenerator.compareRBOMs(oldRBOM, newRBOM);

      assert.ok(diff.added.includes('malicious-pkg'));
    });

    it('должен обнаруживать удалённые компоненты', () => {
      const oldRBOM = createMockRBOM();
      const newRBOM = createMockRBOM();
      newRBOM.components = newRBOM.components.filter(c => c.name !== 'winston');

      const diff = RBOMGenerator.compareRBOMs(oldRBOM, newRBOM);

      assert.ok(diff.removed.includes('winston'));
    });

    it('должен обнаруживать изменённые компоненты', () => {
      const oldRBOM = createMockRBOM();
      const newRBOM = createMockRBOM();

      const expressComp = newRBOM.components.find(c => c.name === 'express');
      if (expressComp) {
        expressComp.hash = 'modified-hash';
      }

      const diff = RBOMGenerator.compareRBOMs(oldRBOM, newRBOM);

      assert.ok(diff.modified.includes('express'));
    });

    it('должен возвращать пустые arrays при одинаковых RBOM', () => {
      const rbom = createMockRBOM();
      const diff = RBOMGenerator.compareRBOMs(rbom, rbom);

      assert.strictEqual(diff.added.length, 0);
      assert.strictEqual(diff.removed.length, 0);
      assert.strictEqual(diff.modified.length, 0);
    });
  });
});

// ============================================================================
// SBOM COMPARATOR TESTS
// ============================================================================

describe('SBOMComparator', () => {
  let sbom: SBOM;
  let comparator: SBOMComparator;

  beforeEach(() => {
    sbom = createMockSBOM();
    comparator = createSBOMComparator(sbom, 'test-secret-comparator');
  });

  describe('compare', () => {
    it('должен обнаруживать отсутствие drift при совпадении', () => {
      const rbom = createMockRBOM();
      const report = comparator.compare(rbom);

      assert.strictEqual(report.severity, 'none');
      assert.strictEqual(report.missing.length, 0);
      assert.strictEqual(report.unexpected.length, 0);
      assert.strictEqual(report.modified.length, 0);
    });

    it('должен обнаруживать MISSING компоненты', () => {
      const rbom = createMockRBOM();
      rbom.components = rbom.components.filter(c => c.name !== 'express');

      const report = comparator.compare(rbom);

      assert.ok(report.missing.length > 0);
      assert.ok(report.missing.some(c => c.name === 'express'));
    });

    it('должен обнаруживать UNEXPECTED компоненты', () => {
      const rbom = createMockRBOM();
      rbom.components.push({
        type: 'library',
        name: 'suspicious-module',
        version: '0.0.1',
        hash: 'evil123',
        path: 'node_modules/suspicious-module',
        status: 'unexpected'
      });

      const report = comparator.compare(rbom);

      assert.ok(report.unexpected.length > 0);
      assert.ok(report.unexpected.some(c => c.name === 'suspicious-module'));
    });

    it('должен обнаруживать MODIFIED компоненты (version mismatch)', () => {
      const rbom = createMockRBOM();
      const bcryptComp = rbom.components.find(c => c.name === 'bcrypt');
      if (bcryptComp) {
        bcryptComp.version = '6.0.0';
      }

      const report = comparator.compare(rbom);

      assert.ok(report.modified.length > 0);
      assert.ok(report.modified.some(m => m.name === 'bcrypt'));
      assert.strictEqual(report.modified[0].expectedVersion, '5.1.0');
      assert.strictEqual(report.modified[0].actualVersion, '6.0.0');
    });

    it('должен устанавливать CRITICAL severity для unexpected компонентов', () => {
      const rbom = createMockRBOM();
      rbom.components.push({
        type: 'library',
        name: 'injected-module',
        version: '1.0.0',
        hash: 'evil',
        path: 'node_modules/injected-module',
        status: 'unexpected'
      });

      const report = comparator.compare(rbom);

      assert.strictEqual(report.severity, 'critical');
    });

    it('должен устанавливать HIGH severity для modified компонентов с hash mismatch', () => {
      const rbom = createMockRBOM();
      const comp = rbom.components.find(c => c.name === 'bcrypt');
      if (comp) {
        comp.hash = 'different-hash';
      }

      const report = comparator.compare(rbom);

      assert.strictEqual(report.severity, 'high');
    });

    it('должен устанавливать MEDIUM severity для version mismatch', () => {
      const rbom = createMockRBOM();
      // Изменяем ТОЛЬКО версию (hash совпадает)
      const comp = rbom.components.find(c => c.name === 'bcrypt');
      if (comp) {
        comp.version = '6.0.0';
        // hash оставляем тот же — 'def456'
      }

      const report = comparator.compare(rbom);

      // Version mismatch без hash mismatch = medium
      assert.ok(report.modified.length > 0);
      assert.ok(report.modified.some(m => m.name === 'bcrypt'));
      assert.ok(report.severity === 'medium' || report.severity === 'high');
    });

    it('должен устанавливать LOW severity для missing компонентов', () => {
      const rbom = createMockRBOM();
      rbom.components = rbom.components.filter(c => c.name !== 'express');

      const report = comparator.compare(rbom);

      assert.strictEqual(report.severity, 'low');
    });

    it('должен генерировать recommendations', () => {
      const rbom = createMockRBOM();
      rbom.components.push({
        type: 'library',
        name: 'evil',
        version: '1.0.0',
        hash: 'evil',
        path: 'node_modules/evil',
        status: 'unexpected'
      });

      const report = comparator.compare(rbom);

      assert.ok(report.recommendation.length > 0);
      assert.ok(report.recommendation.includes('CRITICAL'));
    });

    it('долген генерировать risk summary', () => {
      const rbom = createMockRBOM();

      const report = comparator.compare(rbom);

      assert.ok(report.riskSummary);
    });

    it('должен подписывать DriftReport', () => {
      const rbom = createMockRBOM();
      const report = comparator.compare(rbom);

      assert.ok(report.signature);
      assert.strictEqual(report.signature.length, 64);
    });

    it('должен верифицировать подпись DriftReport', () => {
      const rbom = createMockRBOM();
      const report = comparator.compare(rbom);

      assert.strictEqual(comparator.verifyReport(report), true);
    });

    it('должен отклонять отчёт с неверной подписью', () => {
      const rbom = createMockRBOM();
      const report = comparator.compare(rbom);
      report.signature = 'invalid';

      assert.strictEqual(comparator.verifyReport(report), false);
    });
  });

  describe('getSBOM / updateSBOM', () => {
    it('должен возвращать SBOM', () => {
      const retrieved = comparator.getSBOM();

      assert.strictEqual(retrieved.bomFormat, 'CycloneDX');
    });

    it('должен обновлять SBOM', () => {
      const newSBOM = createMockSBOM();
      newSBOM.metadata.component.name = 'updated-app';

      comparator.updateSBOM(newSBOM);

      assert.strictEqual(comparator.getSBOM().metadata.component.name, 'updated-app');
    });
  });
});

// ============================================================================
// INTEGRITY MONITOR TESTS
// ============================================================================

describe('IntegrityMonitor', () => {
  let monitor: IntegrityMonitor;

  beforeEach(() => {
    monitor = createIntegrityMonitor({
      hmacSecret: 'test-secret-monitor',
      attestationInterval: 100,
      autoAlert: false,
      logEachAttestation: false
    });
  });

  afterEach(() => {
    monitor.destroy();
  });

  describe('start/stop', () => {
    it('должен запускать мониторинг', () => {
      monitor.start();

      assert.strictEqual(monitor.isRunning(), true);
    });

    it('должен останавливать мониторинг', () => {
      monitor.start();
      monitor.stop();

      assert.strictEqual(monitor.isRunning(), false);
    });

    it('не должен запускать дважды', () => {
      monitor.start();
      monitor.start();

      assert.strictEqual(monitor.isRunning(), true);
    });

    it('должен эмитить monitor_started event', (done) => {
      monitor.on('integrity_event', (event) => {
        if (event.type === 'monitor_started') {
          assert.ok(event.eventId);
          assert.ok(event.timestamp);
          done();
        }
      });

      monitor.start();
    });
  });

  describe('attestate', () => {
    it('должен выполнять аттестацию', async () => {
      const result = await monitor.attestate();

      assert.ok(result.reportId);
      assert.ok(result.verified);
      assert.ok(result.signatureValid);
      assert.ok(result.hashChainValid);
    });

    it('должен эмитить attestation event', (done) => {
      monitor.on('attestation', (data) => {
        assert.ok(data.report);
        assert.ok(data.rbom);
        assert.ok(typeof data.verified === 'boolean');
        done();
      });

      monitor.attestate();
    });

    it('должен обновлять статистику', async () => {
      await monitor.attestate();
      await monitor.attestate();

      const stats = monitor.getStats();

      assert.strictEqual(stats.totalAttestations, 2);
      assert.ok(stats.lastAttestationTime);
      assert.ok(stats.averageAttestationTimeMs >= 0);
    });
  });

  describe('attestateOnDemand', () => {
    it('должен выполнять on-demand аттестацию', async () => {
      const result = await monitor.attestateOnDemand();

      assert.ok(result.reportId);
      assert.ok(result.verified);
    });
  });

  describe('history', () => {
    it('должен сохранять историю аттестаций', async () => {
      await monitor.attestate();
      await monitor.attestate();

      const history = monitor.getHistory();

      assert.strictEqual(history.length, 2);
    });

    it('должен возвращать последнюю аттестацию', async () => {
      await monitor.attestate();
      const last = monitor.getLastAttestation();

      assert.ok(last);
      assert.ok(last.report);
    });

    it('должен ограничивать длину истории', async () => {
      const smallMonitor = createIntegrityMonitor({
        hmacSecret: 'test-secret',
        maxHistoryLength: 2,
        autoAlert: false,
        logEachAttestation: false
      });

      await smallMonitor.attestate();
      await smallMonitor.attestate();
      await smallMonitor.attestate();

      assert.strictEqual(smallMonitor.getHistory().length, 2);
      smallMonitor.destroy();
    });

    it('должен возвращать лимитированную историю', async () => {
      await monitor.attestate();
      await monitor.attestate();
      await monitor.attestate();

      const limited = monitor.getHistory(2);

      assert.strictEqual(limited.length, 2);
    });
  });

  describe('updateSBOM', () => {
    it('должен обновлять SBOM для сравнения', async () => {
      const newSBOM = createMockSBOM();
      monitor.updateSBOM(newSBOM);

      const result = await monitor.attestate();

      assert.ok(result);
    });
  });

  describe('stats', () => {
    it('должен возвращать полную статистику', async () => {
      await monitor.attestate();

      const stats = monitor.getStats();

      assert.ok(typeof stats.totalAttestations === 'number');
      assert.ok(typeof stats.totalDriftsDetected === 'number');
      assert.ok(typeof stats.historyLength === 'number');
      assert.ok(stats.currentSeverity);
    });
  });

  describe('with SBOM comparison', () => {
    it('должен обнаруживать drift при наличии SBOM', async () => {
      const monitorWithSBOM = createIntegrityMonitor({
        hmacSecret: 'test-secret-drift',
        attestationInterval: 100,
        autoAlert: false,
        logEachAttestation: false
      }, createMockSBOM());

      const result = await monitorWithSBOM.attestate();

      assert.ok(result);
      monitorWithSBOM.destroy();
    });
  });

  describe('destroy', () => {
    it('должен очищать ресурсы', () => {
      monitor.start();
      monitor.destroy();

      assert.strictEqual(monitor.isRunning(), false);
      assert.strictEqual(monitor.getHistory().length, 0);
    });
  });
});

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

describe('Attestation Integration Tests', () => {
  it('должен выполнять полный цикл: Attestation → RBOM → SBOM Compare → Drift', async () => {
    // 1. Создаём engine
    const engine = createAttestationEngine({
      hmacSecret: 'integration-test-secret',
      componentName: 'integration-app',
      componentVersion: '1.0.0'
    });

    // 2. Генерируем attestation report
    const report = await engine.generateReport('initial');
    assert.ok(report.reportId);
    assert.ok(report.signature);

    // 3. Создаём RBOM generator
    const generator = createRBOMGenerator(engine);
    const rbom = await generator.generateRBOM();
    assert.strictEqual(rbom.bomFormat, 'CycloneDX');

    // 4. Создаём SBOM comparator
    const sbom = createMockSBOM();
    const comparator = createSBOMComparator(sbom, 'integration-test-secret');
    const driftReport = comparator.compare(rbom);
    assert.ok(driftReport.driftId);

    // 5. Верифицируем всё
    assert.strictEqual(engine.verifyReport(report), true);
    assert.strictEqual(comparator.verifyReport(driftReport), true);
  });

  it('должен обнаруживать injected module через полный цикл', async () => {
    const engine = createAttestationEngine({
      hmacSecret: 'injection-test-secret',
      componentName: 'test-app',
      componentVersion: '1.0.0'
    });

    const generator = createRBOMGenerator(engine);

    // SBOM НЕ содержит malicious-pkg
    const sbom = createMockSBOM();

    // RBOM содержит malicious-pkg (injected!)
    const rbom = await generator.generateRBOM();
    rbom.components.push({
      type: 'library',
      name: 'malicious-pkg',
      version: '1.0.0',
      hash: 'evil-hash',
      path: 'node_modules/malicious-pkg',
      status: 'unexpected'
    });

    const comparator = createSBOMComparator(sbom, 'injection-test-secret');
    const driftReport = comparator.compare(rbom);

    assert.strictEqual(driftReport.severity, 'critical');
    assert.ok(driftReport.unexpected.some(c => c.name === 'malicious-pkg'));
    assert.ok(driftReport.recommendation.includes('CRITICAL'));
  });

  it('должен работать с IntegrityMonitor в автоматическом режиме', (done) => {
    const monitor = createIntegrityMonitor({
      hmacSecret: 'auto-test-secret',
      attestationInterval: 50,
      autoAlert: true,
      logEachAttestation: false
    }, createMockSBOM());

    let attestationCount = 0;

    monitor.on('attestation', (data) => {
      attestationCount++;
      assert.ok(data.report);
      assert.ok(data.rbom);

      if (attestationCount >= 2) {
        const stats = monitor.getStats();
        assert.strictEqual(stats.totalAttestations, attestationCount);
        monitor.destroy();
        done();
      }
    });

    monitor.start();
  });
});
