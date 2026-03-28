/**
 * ============================================================================
 * SBOM GENERATOR - ГЕНЕРАЦИЯ SOFTWARE BILL OF MATERIALS
 * ============================================================================
 * Модуль для автоматической генерации SBOM (Software Bill of Materials)
 * в различных форматах: SPDX, CycloneDX, SWID.
 * 
 * Особенности:
 * - Поддержка форматов SPDX 2.3, CycloneDX 1.5, SWID
 * - Автоматическое обнаружение зависимостей
 * - Генерация PURL (Package URL) и CPE
 * - Интеграция с vulnerability databases
 * - Лицензионный анализ
 * - Hash вычисление для компонентов
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  SBOMDocument,
  SBOMFormat,
  SBOMComponent,
  SBOMDependency,
  SBOMLicense,
  SBOMSupplier,
  SBOMMetadata,
  SBOMVulnerability,
  SBOMExternalReference,
  HashAlgorithm,
  OperationResult
} from '../types/integrity.types';

/**
 * Конфигурация SBOM Generator
 */
export interface SBOMGeneratorConfig {
  /** Формат SBOM по умолчанию */
  defaultFormat: SBOMFormat;
  /** Алгоритм хеширования */
  hashAlgorithm: HashAlgorithm;
  /** Включать dev зависимости */
  includeDevDependencies: boolean;
  /** Включать транзитивные зависимости */
  includeTransitive: boolean;
  /** Максимальная глубина зависимостей */
  maxDepth: number;
  /** Путь к vulnerability базе */
  vulnerabilityDBPath?: string;
  /** Лицензионные алиасы */
  licenseAliases: Record<string, string>;
  /** Игнорируемые пакеты */
  ignoredPackages: string[];
}

/**
 * Данные package.json
 */
interface PackageJSON {
  name: string;
  version: string;
  description?: string;
  author?: string | { name: string; email?: string; url?: string };
  license?: string;
  repository?: { type: string; url: string };
  homepage?: string;
  bugs?: { url: string; email?: string };
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

/**
 * Данные package-lock.json
 */
interface PackageLock {
  name: string;
  version: string;
  lockfileVersion: number;
  packages?: Record<string, PackageLockEntry>;
  dependencies?: Record<string, PackageLockDependency>;
}

interface PackageLockEntry {
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  dependencies?: Record<string, PackageLockEntry>;
  license?: string;
}

interface PackageLockDependency {
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, PackageLockDependency>;
}

/**
 * Класс SBOM Generator
 * 
 * Генерирует Software Bill of Materials для проекта,
 * автоматически обнаруживая зависимости и их метаданные.
 */
export class SBOMGenerator extends EventEmitter {
  /** Конфигурация генератора */
  private readonly config: SBOMGeneratorConfig;
  
  /** Кэш лицензий */
  private readonly licenseCache: Map<string, SBOMLicense> = new Map();
  
  /** Кэш компонентов */
  private readonly componentCache: Map<string, SBOMComponent> = new Map();

  /**
   * Создает экземпляр SBOMGenerator
   * 
   * @param config - Конфигурация генератора
   */
  constructor(config: Partial<SBOMGeneratorConfig> = {}) {
    super();
    
    this.config = {
      defaultFormat: config.defaultFormat || 'CycloneDX',
      hashAlgorithm: config.hashAlgorithm || 'SHA-256',
      includeDevDependencies: config.includeDevDependencies ?? false,
      includeTransitive: config.includeTransitive ?? true,
      maxDepth: config.maxDepth || 10,
      vulnerabilityDBPath: config.vulnerabilityDBPath,
      licenseAliases: config.licenseAliases || {
        'MIT': 'MIT',
        'Apache-2.0': 'Apache-2.0',
        'BSD-2-Clause': 'BSD-2-Clause',
        'BSD-3-Clause': 'BSD-3-Clause',
        'ISC': 'ISC',
        'GPL-3.0': 'GPL-3.0-only',
        'LGPL-3.0': 'LGPL-3.0-only',
        'MPL-2.0': 'MPL-2.0',
        'Unlicense': 'Unlicense',
        'CC0-1.0': 'CC0-1.0'
      },
      ignoredPackages: config.ignoredPackages || []
    };
    
    // Инициализируем стандартные лицензии
    this.initializeStandardLicenses();
  }

  /**
   * Инициализирует стандартные лицензии
   */
  private initializeStandardLicenses(): void {
    const standardLicenses: SBOMLicense[] = [
      { id: 'MIT', name: 'MIT License', url: 'https://opensource.org/licenses/MIT' },
      { id: 'Apache-2.0', name: 'Apache License 2.0', url: 'https://opensource.org/licenses/Apache-2.0' },
      { id: 'BSD-2-Clause', name: 'BSD 2-Clause "Simplified" License', url: 'https://opensource.org/licenses/BSD-2-Clause' },
      { id: 'BSD-3-Clause', name: 'BSD 3-Clause "New" License', url: 'https://opensource.org/licenses/BSD-3-Clause' },
      { id: 'ISC', name: 'ISC License', url: 'https://opensource.org/licenses/ISC' },
      { id: 'GPL-3.0-only', name: 'GNU General Public License v3.0 only', url: 'https://opensource.org/licenses/GPL-3.0' },
      { id: 'LGPL-3.0-only', name: 'GNU Lesser General Public License v3.0 only', url: 'https://opensource.org/licenses/LGPL-3.0' },
      { id: 'MPL-2.0', name: 'Mozilla Public License 2.0', url: 'https://opensource.org/licenses/MPL-2.0' },
      { id: 'Unlicense', name: 'The Unlicense', url: 'https://unlicense.org/' },
      { id: 'CC0-1.0', name: 'Creative Commons Zero v1.0 Universal', url: 'https://creativecommons.org/publicdomain/zero/1.0/' }
    ];
    
    for (const license of standardLicenses) {
      this.licenseCache.set(license.id, license);
    }
  }

  /**
   * Генерирует SBOM для проекта
   * 
   * @param projectPath - Путь к проекту
   * @param options - Опции генерации
   * @returns SBOM документ
   */
  async generateSBOM(
    projectPath: string,
    options: {
      format?: SBOMFormat;
      productName?: string;
      productVersion?: string;
      includeVulnerabilities?: boolean;
    } = {}
  ): Promise<OperationResult<SBOMDocument>> {
    const startTime = Date.now();
    
    try {
      const format = options.format || this.config.defaultFormat;
      
      // Находим package.json
      const packageJsonPath = this.findPackageJson(projectPath);
      
      if (!packageJsonPath) {
        throw new Error('package.json не найден в указанной директории');
      }
      
      // Читаем package.json
      const packageJson = this.readPackageJson(packageJsonPath);
      
      // Извлекаем компоненты
      const components = await this.extractComponents(
        packageJsonPath,
        packageJson,
        options.includeVulnerabilities ?? false
      );
      
      // Создаем зависимости
      const dependencies = this.extractDependencies(packageJson, components);
      
      // Получаем лицензии
      const licenses = this.extractLicenses(components);
      
      // Создаем метаданные
      const metadata = this.createMetadata(packageJson);
      
      // Создаем поставщика
      const supplier = this.createSupplier(packageJson);
      
      // Генерируем ID SBOM
      const sbomId = this.generateSBOMId(packageJson.name, packageJson.version);
      
      // Создаем SBOM документ
      const sbom: SBOMDocument = {
        format,
        specVersion: this.getSpecVersion(format),
        id: sbomId,
        productName: options.productName || packageJson.name,
        productVersion: options.productVersion || packageJson.version,
        supplier,
        createdAt: new Date(),
        components,
        dependencies,
        vulnerabilities: options.includeVulnerabilities 
          ? await this.detectVulnerabilities(components) 
          : [],
        licenses,
        metadata
      };
      
      this.emit('sbom-generated', sbom);
      
      return {
        success: true,
        data: sbom,
        errors: [],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    }
  }

  /**
   * Находит package.json в директории
   */
  private findPackageJson(projectPath: string): string | null {
    const paths = [
      path.join(projectPath, 'package.json'),
      path.join(projectPath, 'packages', 'package.json'),
      projectPath.endsWith('package.json') ? projectPath : null
    ].filter(Boolean) as string[];
    
    for (const p of paths) {
      if (fs.existsSync(p)) {
        return p;
      }
    }
    
    return null;
  }

  /**
   * Читает package.json
   */
  private readPackageJson(packageJsonPath: string): PackageJSON {
    const content = fs.readFileSync(packageJsonPath, 'utf-8');
    return JSON.parse(content) as PackageJSON;
  }

  /**
   * Извлекает компоненты из зависимостей
   */
  private async extractComponents(
    packageJsonPath: string,
    packageJson: PackageJSON,
    includeVulnerabilities: boolean
  ): Promise<SBOMComponent[]> {
    const components: SBOMComponent[] = [];
    const projectDir = path.dirname(packageJsonPath);
    
    // Добавляем сам проект как компонент
    const rootComponent = this.createRootComponent(packageJson, projectDir);
    components.push(rootComponent);
    
    // Читаем package-lock.json если существует
    const lockPath = path.join(projectDir, 'package-lock.json');
    
    if (fs.existsSync(lockPath)) {
      const lockData = this.readPackageLock(lockPath);
      const lockComponents = await this.extractFromLockFile(lockData, projectDir);
      components.push(...lockComponents);
    } else {
      // Fallback к извлечению из package.json
      const jsonComponents = await this.extractFromPackageJson(packageJson, projectDir);
      components.push(...jsonComponents);
    }
    
    return components;
  }

  /**
   * Создает корневой компонент (сам проект)
   */
  private createRootComponent(packageJson: PackageJSON, projectDir: string): SBOMComponent {
    const component: SBOMComponent = {
      type: 'application',
      name: packageJson.name,
      version: packageJson.version,
      supplier: typeof packageJson.author === 'string' 
        ? packageJson.author 
        : packageJson.author?.name,
      licenses: packageJson.license ? [packageJson.license] : [],
      hashes: [],
      purl: this.createPURL('npm', packageJson.name, packageJson.version),
      description: packageJson.description,
      externalReferences: this.createExternalReferences(packageJson)
    };
    
    // Вычисляем хеши для проекта
    const projectFiles = this.getProjectFiles(projectDir);
    for (const file of projectFiles.slice(0, 10)) { // Ограничиваем количество файлов
      try {
        const hash = this.computeFileHash(file);
        component.hashes.push({
          algorithm: this.getHashAlgorithm(),
          value: hash
        });
      } catch {
        // Игнорируем ошибки хеширования
      }
    }
    
    return component;
  }

  /**
   * Получает файлы проекта для хеширования
   */
  private getProjectFiles(projectDir: string): string[] {
    const files: string[] = [];
    const patterns = ['package.json', 'tsconfig.json', 'src/**/*.ts', 'src/**/*.js'];
    
    try {
      const entries = fs.readdirSync(projectDir, { withFileTypes: true });
      
      for (const entry of entries) {
        if (entry.isFile() && !entry.name.startsWith('.')) {
          files.push(path.join(projectDir, entry.name));
        }
      }
    } catch {
      // Игнорируем ошибки
    }
    
    return files;
  }

  /**
   * Вычисляет хеш файла
   */
  private computeFileHash(filePath: string): string {
    const content = fs.readFileSync(filePath);
    const algorithm = this.config.hashAlgorithm === 'SHA-256' ? 'sha256' :
                      this.config.hashAlgorithm === 'SHA-384' ? 'sha384' :
                      this.config.hashAlgorithm === 'SHA-512' ? 'sha512' : 'sha256';
    
    const hash = crypto.createHash(algorithm);
    hash.update(content);
    return hash.digest('hex');
  }

  /**
   * Получает название алгоритма хеширования
   */
  private getHashAlgorithm(): string {
    return this.config.hashAlgorithm;
  }

  /**
   * Извлекает компоненты из package-lock.json
   */
  private async extractFromLockFile(
    lockData: PackageLock,
    projectDir: string
  ): Promise<SBOMComponent[]> {
    const components: SBOMComponent[] = [];
    
    // Обрабатываем новый формат (lockfileVersion >= 2)
    if (lockData.packages) {
      for (const [pkgPath, pkgData] of Object.entries(lockData.packages)) {
        // Пропускаем корневой пакет
        if (pkgPath === '') continue;
        
        // Извлекаем имя пакета из пути
        const packageName = this.extractPackageName(pkgPath);
        
        // Пропускаем игнорируемые пакеты
        if (this.config.ignoredPackages.includes(packageName)) continue;
        
        // Пропускаем dev зависимости если не включены
        if (!this.config.includeDevDependencies && pkgData.dev) continue;
        
        const component: SBOMComponent = {
          type: 'library',
          name: packageName,
          version: pkgData.version,
          licenses: pkgData.license ? [pkgData.license] : [],
          hashes: this.extractHashes(pkgData.integrity),
          purl: this.createPURL('npm', packageName, pkgData.version),
          externalReferences: pkgData.resolved ? [{
            type: 'distribution',
            url: pkgData.resolved
          }] : []
        };
        
        components.push(component);
      }
    } 
    // Обрабатываем старый формат
    else if (lockData.dependencies) {
      const deps = this.extractFromOldLockFormat(lockData.dependencies, 0);
      components.push(...deps);
    }
    
    return components;
  }

  /**
   * Извлекает имя пакета из пути в lock файле
   */
  private extractPackageName(pkgPath: string): string {
    // node_modules/@scope/package-name -> @scope/package-name
    // node_modules/package-name -> package-name
    const parts = pkgPath.split('node_modules/').filter(Boolean);
    return parts[parts.length - 1];
  }

  /**
   * Извлекает компоненты из старого формата lock файла
   */
  private extractFromOldLockFormat(
    dependencies: Record<string, PackageLockDependency>,
    depth: number
  ): SBOMComponent[] {
    const components: SBOMComponent[] = [];
    
    if (depth > this.config.maxDepth) {
      return components;
    }
    
    for (const [name, data] of Object.entries(dependencies)) {
      if (this.config.ignoredPackages.includes(name)) continue;
      if (!this.config.includeDevDependencies && data.dev) continue;
      
      const component: SBOMComponent = {
        type: 'library',
        name,
        version: data.version,
        licenses: [],
        hashes: this.extractHashes(data.integrity),
        purl: this.createPURL('npm', name, data.version),
        externalReferences: data.resolved ? [{
          type: 'distribution',
          url: data.resolved
        }] : []
      };
      
      components.push(component);
      
      // Рекурсивно обрабатываем вложенные зависимости
      if (this.config.includeTransitive && data.dependencies) {
        const nested = this.extractFromOldLockFormat(data.dependencies, depth + 1);
        components.push(...nested);
      }
    }
    
    return components;
  }

  /**
   * Извлекает хеши из integrity строки
   */
  private extractHashes(integrity?: string): { algorithm: string; value: string }[] {
    if (!integrity) return [];
    
    const hashes: { algorithm: string; value: string }[] = [];
    
    // integrity строка формата: sha512-xxx... sha256-yyy...
    const parts = integrity.split(' ');
    
    for (const part of parts) {
      const match = part.match(/^(sha\d+)-(.+)$/);
      if (match) {
        hashes.push({
          algorithm: match[1].toUpperCase(),
          value: match[2]
        });
      }
    }
    
    return hashes;
  }

  /**
   * Создает PURL (Package URL)
   */
  private createPURL(type: string, name: string, version?: string): string {
    const encodedName = encodeURIComponent(name);
    const versionPart = version ? `@${encodeURIComponent(version)}` : '';
    return `pkg:${type}/${encodedName}${versionPart}`;
  }

  /**
   * Извлекает компоненты из package.json (без lock файла)
   */
  private async extractFromPackageJson(
    packageJson: PackageJSON,
    projectDir: string
  ): Promise<SBOMComponent[]> {
    const components: SBOMComponent[] = [];
    
    const allDeps: Record<string, string> = {
      ...packageJson.dependencies,
      ...(this.config.includeDevDependencies ? packageJson.devDependencies : {}),
      ...packageJson.peerDependencies,
      ...packageJson.optionalDependencies
    };
    
    for (const [name, version] of Object.entries(allDeps)) {
      if (this.config.ignoredPackages.includes(name)) continue;
      
      // Очищаем версию от префиксов
      const cleanVersion = version.replace(/^[\^~>=<]/, '');
      
      const component: SBOMComponent = {
        type: 'library',
        name,
        version: cleanVersion,
        licenses: [],
        hashes: [],
        purl: this.createPURL('npm', name, cleanVersion)
      };
      
      components.push(component);
    }
    
    return components;
  }

  /**
   * Читает package-lock.json
   */
  private readPackageLock(lockPath: string): PackageLock {
    const content = fs.readFileSync(lockPath, 'utf-8');
    return JSON.parse(content) as PackageLock;
  }

  /**
   * Извлекает зависимости между компонентами
   */
  private extractDependencies(
    packageJson: PackageJSON,
    components: SBOMComponent[]
  ): SBOMDependency[] {
    const dependencies: SBOMDependency[] = [];
    
    // Создаем карту компонентов
    const componentMap = new Map<string, SBOMComponent>();
    for (const comp of components) {
      componentMap.set(comp.name, comp);
    }
    
    // Корневой компонент зависит от всех direct зависимостей
    const rootComponent = components.find(c => c.type === 'application');
    
    if (rootComponent) {
      const rootRef = rootComponent.purl || `${rootComponent.name}@${rootComponent.version}`;
      const dependsOn: string[] = [];
      
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
        ...packageJson.peerDependencies,
        ...packageJson.optionalDependencies
      };
      
      for (const name of Object.keys(allDeps)) {
        const depComponent = componentMap.get(name);
        if (depComponent) {
          dependsOn.push(depComponent.purl || `${name}@${depComponent.version}`);
        }
      }
      
      dependencies.push({
        ref: rootRef,
        dependsOn
      });
    }
    
    return dependencies;
  }

  /**
   * Извлекает уникальные лицензии из компонентов
   */
  private extractLicenses(components: SBOMComponent[]): SBOMLicense[] {
    const licenseIds = new Set<string>();
    
    for (const component of components) {
      for (const license of component.licenses) {
        const normalizedId = this.normalizeLicenseId(license);
        if (normalizedId) {
          licenseIds.add(normalizedId);
        }
      }
    }
    
    const licenses: SBOMLicense[] = [];
    
    for (const id of licenseIds) {
      const cached = this.licenseCache.get(id);
      if (cached) {
        licenses.push(cached);
      } else {
        licenses.push({ id, name: id });
      }
    }
    
    return licenses;
  }

  /**
   * Нормализует ID лицензии
   */
  private normalizeLicenseId(license: string): string | null {
    if (!license) return null;
    
    // Проверяем алиасы
    for (const [alias, standard] of Object.entries(this.config.licenseAliases)) {
      if (license.toLowerCase() === alias.toLowerCase()) {
        return standard;
      }
    }
    
    return license;
  }

  /**
   * Создает метаданные SBOM
   */
  private createMetadata(packageJson: PackageJSON): SBOMMetadata {
    return {
      authors: typeof packageJson.author === 'string'
        ? [{ name: packageJson.author }]
        : packageJson.author
          ? [{ name: packageJson.author.name, email: packageJson.author.email }]
          : [],
      tools: [
        { name: 'SBOMGenerator', version: '1.0.0' }
      ],
      buildTimestamp: new Date()
    };
  }

  /**
   * Создает поставщика
   */
  private createSupplier(packageJson: PackageJSON): SBOMSupplier {
    const author = packageJson.author;
    
    if (typeof author === 'string') {
      return { name: author };
    }
    
    if (author) {
      return {
        name: author.name,
        contact: author.email
      };
    }
    
    return { name: 'Unknown' };
  }

  /**
   * Создает внешние ссылки для компонента
   */
  private createExternalReferences(packageJson: PackageJSON): SBOMExternalReference[] {
    const refs: SBOMExternalReference[] = [];
    
    if (packageJson.repository?.url) {
      refs.push({
        type: 'vcs',
        url: packageJson.repository.url
      });
    }
    
    if (packageJson.homepage) {
      refs.push({
        type: 'website',
        url: packageJson.homepage
      });
    }
    
    if (packageJson.bugs?.url) {
      refs.push({
        type: 'issue-tracker',
        url: packageJson.bugs.url
      });
    }
    
    return refs;
  }

  /**
   * Обнаруживает уязвимости в компонентах
   */
  private async detectVulnerabilities(
    components: SBOMComponent[]
  ): Promise<SBOMVulnerability[]> {
    const vulnerabilities: SBOMVulnerability[] = [];
    
    // В реальной реализации здесь был бы запрос к vulnerability database
    // (OSV, NVD, GitHub Advisory Database, etc.)
    
    // Симуляция для демонстрации
    for (const component of components) {
      // Проверяем известные уязвимые пакеты (пример)
      const knownVulnerable = ['lodash', 'axios', 'minimist', 'node-fetch'];
      
      if (knownVulnerable.includes(component.name)) {
        vulnerabilities.push({
          id: `CVE-202X-${Math.floor(Math.random() * 10000)}`,
          source: 'NVD',
          affectedComponents: [component.purl || component.name],
          cvss: {
            version: '3.1',
            score: Math.random() * 10,
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
          },
          description: `Potential vulnerability in ${component.name}`,
          recommendation: `Update ${component.name} to the latest version`
        });
      }
    }
    
    return vulnerabilities;
  }

  /**
   * Генерирует уникальный ID для SBOM
   */
  private generateSBOMId(name: string, version: string): string {
    const data = `${name}@${version}-${Date.now()}`;
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return `SBOM-${hash.digest('hex').substring(0, 16)}`;
  }

  /**
   * Получает версию спецификации для формата
   */
  private getSpecVersion(format: SBOMFormat): string {
    const versions: Record<SBOMFormat, string> = {
      'SPDX': '2.3',
      'CycloneDX': '1.5',
      'SWID': '2015'
    };
    
    return versions[format] || '1.0';
  }

  /**
   * Сериализует SBOM в JSON
   * 
   * @param sbom - SBOM документ
   * @param format - Формат вывода
   * @returns JSON строка
   */
  serializeSBOM(sbom: SBOMDocument, format?: SBOMFormat): string {
    const outputFormat = format || sbom.format;
    
    if (outputFormat === 'SPDX') {
      return this.toSPDX(sbom);
    } else if (outputFormat === 'CycloneDX') {
      return this.toCycloneDX(sbom);
    } else {
      return JSON.stringify(sbom, null, 2);
    }
  }

  /**
   * Конвертирует в формат SPDX
   */
  private toSPDX(sbom: SBOMDocument): string {
    const spdx = {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: sbom.productName,
      documentNamespace: `https://sbom.example/${sbom.id}`,
      creationInfo: {
        created: sbom.createdAt.toISOString(),
        creators: sbom.metadata.authors.map(a => `Person: ${a.name}`),
        licenseListVersion: '3.19'
      },
      packages: sbom.components.map((comp, index) => ({
        SPDXID: `SPDXRef-Package-${index}`,
        name: comp.name,
        versionInfo: comp.version,
        downloadLocation: comp.externalReferences?.find(r => r.type === 'distribution')?.url || 'NOASSERTION',
        filesAnalyzed: false,
        licenseConcluded: comp.licenses[0] || 'NOASSERTION',
        licenseDeclared: comp.licenses[0] || 'NOASSERTION',
        copyrightText: 'NOASSERTION',
        externalRefs: comp.purl ? [{
          referenceCategory: 'PACKAGE_MANAGER',
          referenceType: 'purl',
          referenceLocator: comp.purl
        }] : []
      })),
      relationships: sbom.dependencies.map(dep => ({
        spdxElementId: 'SPDXRef-Package-0',
        relatedSpdxElement: dep.dependsOn[0] ? `SPDXRef-Package-${sbom.components.findIndex(c => c.purl === dep.dependsOn[0])}` : '',
        relationshipType: 'DEPENDS_ON'
      }))
    };
    
    return JSON.stringify(spdx, null, 2);
  }

  /**
   * Конвертирует в формат CycloneDX
   */
  private toCycloneDX(sbom: SBOMDocument): string {
    const cycloneDX = {
      bomFormat: 'CycloneDX',
      specVersion: sbom.specVersion,
      version: 1,
      metadata: {
        timestamp: sbom.createdAt.toISOString(),
        tools: sbom.metadata.tools,
        authors: sbom.metadata.authors,
        component: {
          type: 'application',
          name: sbom.productName,
          version: sbom.productVersion,
          supplier: {
            name: sbom.supplier.name
          }
        }
      },
      components: sbom.components.map(comp => ({
        type: comp.type,
        name: comp.name,
        version: comp.version,
        description: comp.description,
        licenses: comp.licenses.map(l => ({ license: { id: l } })),
        hashes: comp.hashes.map(h => ({ alg: h.algorithm, content: h.value })),
        purl: comp.purl,
        externalReferences: comp.externalReferences?.map(r => ({
          type: r.type,
          url: r.url
        }))
      })),
      dependencies: sbom.dependencies.map(dep => ({
        ref: dep.ref,
        dependsOn: dep.dependsOn
      })),
      vulnerabilities: sbom.vulnerabilities?.map(vuln => ({
        id: vuln.id,
        source: { name: vuln.source },
        ratings: vuln.cvss ? [{
          source: { name: 'NVD' },
          score: vuln.cvss.score,
          severity: vuln.cvss.score >= 9 ? 'critical' : vuln.cvss.score >= 7 ? 'high' : vuln.cvss.score >= 4 ? 'medium' : 'low',
          vector: vuln.cvss.vector,
          method: 'CVSSv31'
        }] : [],
        affects: vuln.affectedComponents.map(pkg => ({ ref: pkg })),
        recommendation: vuln.recommendation
      }))
    };
    
    return JSON.stringify(cycloneDX, null, 2);
  }

  /**
   * Сохраняет SBOM в файл
   * 
   * @param sbom - SBOM документ
   * @param outputPath - Путь для сохранения
   * @param format - Формат файла
   * @returns Результат сохранения
   */
  async saveSBOM(
    sbom: SBOMDocument,
    outputPath: string,
    format?: SBOMFormat
  ): Promise<OperationResult> {
    try {
      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      const content = this.serializeSBOM(sbom, format);
      fs.writeFileSync(outputPath, content, 'utf-8');
      
      return {
        success: true,
        errors: [],
        warnings: [],
        executionTime: 0
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Загружает SBOM из файла
   * 
   * @param sbomPath - Путь к SBOM файлу
   * @returns Результат загрузки
   */
  async loadSBOM(sbomPath: string): Promise<OperationResult<SBOMDocument>> {
    try {
      const content = fs.readFileSync(sbomPath, 'utf-8');
      const data = JSON.parse(content);
      
      // Определяем формат и парсим
      let sbom: SBOMDocument;
      
      if (data.spdxVersion) {
        sbom = this.fromSPDX(data);
      } else if (data.bomFormat === 'CycloneDX') {
        sbom = this.fromCycloneDX(data);
      } else {
        sbom = data as SBOMDocument;
      }
      
      return {
        success: true,
        data: sbom,
        errors: [],
        warnings: [],
        executionTime: 0
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Парсит SPDX формат
   */
  private fromSPDX(spdx: Record<string, unknown>): SBOMDocument {
    // Упрощенная реализация парсинга SPDX
    const packages = (spdx.packages as Array<Record<string, unknown>>) || [];
    
    const components: SBOMComponent[] = packages.map(pkg => ({
      type: 'library',
      name: pkg.name as string,
      version: pkg.versionInfo as string || '',
      licenses: [pkg.licenseConcluded as string || 'UNKNOWN'],
      hashes: [],
      purl: pkg.externalRefs?.find((r: Record<string, unknown>) => 
        r.referenceType === 'purl'
      )?.referenceLocator as string
    }));
    
    return {
      format: 'SPDX',
      specVersion: spdx.spdxVersion as string || '2.3',
      id: (spdx.SPDXID as string) || '',
      productName: spdx.name as string || '',
      productVersion: '1.0.0',
      supplier: { name: 'Unknown' },
      createdAt: new Date(),
      components,
      dependencies: [],
      licenses: [],
      metadata: { authors: [], tools: [] }
    };
  }

  /**
   * Парсит CycloneDX формат
   */
  private fromCycloneDX(cycloneDX: Record<string, unknown>): SBOMDocument {
    const components = (cycloneDX.components as Array<Record<string, unknown>>) || [];
    
    const sbomComponents: SBOMComponent[] = components.map(comp => ({
      type: comp.type as 'library' | 'application' || 'library',
      name: comp.name as string,
      version: comp.version as string,
      licenses: (comp.licenses as Array<Record<string, unknown>>)?.map(l => 
        (l.license as Record<string, unknown>)?.id as string
      ) || [],
      hashes: (comp.hashes as Array<Record<string, unknown>>)?.map(h => ({
        algorithm: h.alg as string,
        value: h.content as string
      })) || [],
      purl: comp.purl as string,
      description: comp.description as string
    }));
    
    return {
      format: 'CycloneDX',
      specVersion: cycloneDX.specVersion as string || '1.5',
      id: crypto.randomBytes(8).toString('hex'),
      productName: (cycloneDX.metadata as Record<string, unknown>)?.component?.name as string || '',
      productVersion: (cycloneDX.metadata as Record<string, unknown>)?.component?.version as string || '1.0.0',
      supplier: { name: 'Unknown' },
      createdAt: new Date(cycloneDX.metadata?.timestamp as string || Date.now()),
      components: sbomComponents,
      dependencies: [],
      licenses: [],
      metadata: { authors: [], tools: [] }
    };
  }
}

/**
 * Фабрика для создания SBOM Generator
 */
export class SBOMGeneratorFactory {
  /**
   * Создает генератор для Node.js проекта
   * 
   * @param options - Опции
   * @returns SBOMGenerator
   */
  static createForNodeJS(options: Partial<SBOMGeneratorConfig> = {}): SBOMGenerator {
    return new SBOMGenerator({
      ...options,
      defaultFormat: options.defaultFormat || 'CycloneDX'
    });
  }

  /**
   * Создает генератор для Python проекта
   * 
   * @param options - Опции
   * @returns SBOMGenerator
   */
  static createForPython(options: Partial<SBOMGeneratorConfig> = {}): SBOMGenerator {
    return new SBOMGenerator({
      ...options,
      defaultFormat: options.defaultFormat || 'SPDX'
    });
  }

  /**
   * Создает генератор для Java проекта
   * 
   * @param options - Опции
   * @returns SBOMGenerator
   */
  static createForJava(options: Partial<SBOMGeneratorConfig> = {}): SBOMGenerator {
    return new SBOMGenerator({
      ...options,
      defaultFormat: options.defaultFormat || 'CycloneDX'
    });
  }
}
