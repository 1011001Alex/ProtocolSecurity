/**
 * ============================================================================
 * RBOM GENERATOR — ГЕНЕРАТОР RUNTIME BILL OF MATERIALS
 * ============================================================================
 * Создаёт Runtime Bill of Materials в формате CycloneDX 1.5 на основе
 * данных AttestationEngine. Включает все компоненты, сервисы и зависимости,
 * которые реально загружены в runtime приложения.
 *
 * Отличается от SBOM тем, что SBOM — это что было собрано (build-time),
 * а RBOM — что реально работает (runtime).
 * ============================================================================
 */

import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { AttestationEngine } from './AttestationEngine';
import {
  RBOM,
  RBOMComponent,
  RBOMService,
  AttestationReport,
  ComponentStatus
} from './attestation.types';

export class RBOMGenerator {
  private engine: AttestationEngine;
  private version: number = 1;
  private attestations: { reportId: string; timestamp: Date; hash: string; verified: boolean }[] = [];

  constructor(engine: AttestationEngine) {
    this.engine = engine;
  }

  /**
   * Генерирует RBOM на основе текущей аттестации
   */
  async generateRBOM(options?: { includeAttestation?: boolean }): Promise<RBOM> {
    const includeAttestation = options?.includeAttestation ?? true;

    // Получаем текущий attestation report
    const report = await this.engine.generateReport('periodic');

    // Собираем компоненты
    const components = this.collectComponents(report);
    const services = this.collectServices(report);
    const dependencies = this.collectDependencies(components);

    const componentInfo = this.engine.getComponentInfo();

    const rbom: RBOM = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: uuidv4(),
      version: this.version++,
      metadata: {
        timestamp: report.timestamp,
        component: {
          name: componentInfo.name,
          version: componentInfo.version,
          type: 'application'
        },
        attestationReportId: report.reportId
      },
      components,
      services,
      dependencies,
      attestations: includeAttestation ? [...this.attestations, {
        reportId: report.reportId,
        timestamp: report.timestamp,
        hash: crypto.createHash('sha256').update(JSON.stringify(report)).digest('hex'),
        verified: this.engine.verifyReport(report)
      }] : []
    };

    return rbom;
  }

  /**
   * Добавляет attestation report в историю
   */
  addAttestation(report: AttestationReport): void {
    this.attestations.push({
      reportId: report.reportId,
      timestamp: report.timestamp,
      hash: crypto.createHash('sha256').update(JSON.stringify(report)).digest('hex'),
      verified: this.engine.verifyReport(report)
    });
  }

  /**
   * Сравнивает два RBOM и возвращает differences
   */
  static compareRBOMs(oldRBOM: RBOM, newRBOM: RBOM): {
    added: string[];
    removed: string[];
    modified: string[];
  } {
    const oldComponents = new Set(oldRBOM.components.map(c => `${c.name}@${c.version}`));
    const newComponents = new Set(newRBOM.components.map(c => `${c.name}@${c.version}`));

    const added = newRBOM.components
      .filter(c => !oldComponents.has(`${c.name}@${c.version}`))
      .map(c => c.name);

    const removed = oldRBOM.components
      .filter(c => !newComponents.has(`${c.name}@${c.version}`))
      .map(c => c.name);

    const modified = newRBOM.components
      .filter(c => {
        const oldC = oldRBOM.components.find(oc => oc.name === c.name);
        return oldC && oldC.hash !== c.hash;
      })
      .map(c => c.name);

    return { added, removed, modified };
  }

  /**
   * Сериализует RBOM в JSON строку
   */
  toJSON(rbom: RBOM): string {
    return JSON.stringify(rbom, null, 2);
  }

  /**
   * Сохраняет RBOM в файл
   */
  saveToFile(rbom: RBOM, filePath: string): void {
    fs.writeFileSync(filePath, this.toJSON(rbom), 'utf8');
  }

  /**
   * Загружает RBOM из файла
   */
  loadFromFile(filePath: string): RBOM {
    const content = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(content) as RBOM;
  }

  /**
   * Собирает компоненты из attestation report
   */
  private collectComponents(report: AttestationReport): RBOMComponent[] {
    const components: RBOMComponent[] = [];

    // Добавляем runtime как компонент
    components.push({
      type: 'runtime',
      name: `Node.js ${process.version}`,
      version: process.version,
      hash: crypto.createHash('sha256').update(process.version).digest('hex'),
      path: process.execPath,
      status: 'expected' as ComponentStatus
    });

    // Добавляем загруженные пакеты
    for (const pkg of report.loadedPackages) {
      components.push({
        type: 'library',
        name: pkg.name,
        version: pkg.version,
        hash: pkg.hash,
        path: pkg.path,
        status: pkg.status,
        purl: `pkg:npm/${pkg.name}@${pkg.version}`
      });
    }

    // Добавляем хэшированные файлы как config components
    const configFiles = Object.keys(report.componentHashes)
      .filter(p => p.endsWith('.json') && !p.includes('node_modules'));

    for (const filePath of configFiles.slice(0, 10)) {
      components.push({
        type: 'config',
        name: path.basename(filePath),
        version: '1.0.0',
        hash: report.componentHashes[filePath],
        path: filePath,
        status: 'expected' as ComponentStatus
      });
    }

    return components;
  }

  /**
   * Собирает сервисы из attestation report
   */
  private collectServices(report: AttestationReport): RBOMService[] {
    const services: RBOMService[] = [];

    for (const svc of report.activeServices) {
      services.push({
        name: svc.name,
        protocol: svc.protocol,
        endpoints: svc.host && svc.port ? [`${svc.protocol}://${svc.host}:${svc.port}`] : [],
        authentication: 'internal',
        tlsVersion: svc.tlsEnabled ? '1.3' : 'none'
      });
    }

    // Добавляем сервисы из активных соединений
    const uniquePorts = new Set<number>();
    for (const conn of report.activeConnections) {
      if (conn.state === 'LISTENING' && !uniquePorts.has(conn.localPort)) {
        uniquePorts.add(conn.localPort);
        services.push({
          name: `Service on port ${conn.localPort}`,
          protocol: conn.protocol,
          endpoints: [`tcp://0.0.0.0:${conn.localPort}`],
          authentication: 'unknown',
          tlsVersion: 'unknown'
        });
      }
    }

    return services;
  }

  /**
   * Собирает зависимости между компонентами
   */
  private collectDependencies(components: RBOMComponent[]): { ref: string; dependsOn: string[] }[] {
    const deps: { ref: string; dependsOn: string[] }[] = [];

    // Главный компонент приложения зависит от всех библиотек
    const appComponent = components.find(c => c.type === 'runtime');
    if (appComponent) {
      const libRefs = components
        .filter(c => c.type === 'library')
        .map(c => c.purl || c.name);

      deps.push({
        ref: appComponent.purl || appComponent.name,
        dependsOn: libRefs
      });
    }

    return deps;
  }
}

/**
 * Фабричная функция
 */
export function createRBOMGenerator(engine: AttestationEngine): RBOMGenerator {
  return new RBOMGenerator(engine);
}
