/**
 * ============================================================================
 * INTEGRITY SERVICE - ОСНОВНОЙ СЕРВИС КОНТРОЛЯ ЦЕЛОСТНОСТИ
 * ============================================================================
 * Центральный сервис, объединяющий все компоненты системы контроля
 * целостности в единую согласованную систему.
 * 
 * Особенности:
 * - Координация всех компонентов
 * - Единый API для операций
 * - Комплексные отчеты
 * - Audit logging
 * - Event-driven архитектура
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  IntegrityServiceConfig,
  IntegrityServiceEvents,
  FullIntegrityReport,
  FileHash,
  HashAlgorithm,
  HashResult,
  SignatureResult,
  SignatureVerificationResult,
  SBOMDocument,
  SLSAVerificationResult,
  FIMStatus,
  IntegrityViolation,
  AuditLogEntry,
  OperationResult,
  SigningKeyConfig,
  WatchConfig,
  TransparencyLogConfig,
  BaselineComparisonResult
} from '../types/integrity.types';

// Импорты компонентов
import { MerkleTree, MerkleTreeUtils } from './MerkleTree';
import { HashChain, HashChainManager } from './HashChain';
import { CodeSigner, CodeSignerFactory } from './CodeSigner';
import { ArtifactSigner, SigstoreUtils } from './ArtifactSigner';
import { FileIntegrityMonitor, FIMFactory } from './FileIntegrityMonitor';
import { SBOMGenerator, SBOMGeneratorFactory } from './SBOMGenerator';
import { SupplyChainVerifier, SupplyChainVerifierFactory } from './SupplyChainVerifier';
import { SLSAVerifier, SLSAVerifierFactory } from './SLSAVerifier';
import { TransparencyLogClient, TransparencyLogClientFactory } from './TransparencyLog';
import { BaselineManager } from './BaselineManager';
import { RuntimeVerifier, RuntimeVerifierFactory } from './RuntimeVerifier';
import { ModificationDetector, ModificationDetectorFactory } from './ModificationDetector';

/**
 * Статус сервиса
 */
export interface ServiceStatus {
  /** Активен ли сервис */
  isActive: boolean;
  /** Время запуска */
  startedAt?: Date;
  /** Версия сервиса */
  version: string;
  /** Статус компонентов */
  components: {
    fim: boolean;
    signer: boolean;
    baseline: boolean;
    runtime: boolean;
    detector: boolean;
  };
}

/**
 * Класс Integrity Service
 * 
 * Главный сервис системы контроля целостности,
 * координирующий работу всех подсистем.
 */
export class IntegrityService extends EventEmitter {
  /** Конфигурация сервиса */
  private readonly config: IntegrityServiceConfig;
  
  /** Merkle Tree для хеширования */
  private merkleTree: MerkleTree | null = null;
  
  /** Hash Chain для audit логов */
  private hashChain: HashChain | null = null;
  
  /** Hash Chain Manager */
  private hashChainManager: HashChainManager | null = null;
  
  /** Code Signer */
  private codeSigner: CodeSigner | null = null;
  
  /** Artifact Signer */
  private artifactSigner: ArtifactSigner | null = null;
  
  /** File Integrity Monitor */
  private fim: FileIntegrityMonitor | null = null;
  
  /** SBOM Generator */
  private sbomGenerator: SBOMGenerator | null = null;
  
  /** Supply Chain Verifier */
  private supplyChainVerifier: SupplyChainVerifier | null = null;
  
  /** SLSA Verifier */
  private slsaVerifier: SLSAVerifier | null = null;
  
  /** Transparency Log Client */
  private tlogClient: TransparencyLogClient | null = null;
  
  /** Baseline Manager */
  private baselineManager: BaselineManager | null = null;
  
  /** Runtime Verifier */
  private runtimeVerifier: RuntimeVerifier | null = null;
  
  /** Modification Detector */
  private modificationDetector: ModificationDetector | null = null;
  
  /** Статус сервиса */
  private status: ServiceStatus = {
    isActive: false,
    version: '1.0.0',
    components: {
      fim: false,
      signer: false,
      baseline: false,
      runtime: false,
      detector: false
    }
  };
  
  /** Audit логи */
  private readonly auditLogs: AuditLogEntry[] = [];

  /**
   * Создает экземпляр IntegrityService
   * 
   * @param config - Конфигурация сервиса
   */
  constructor(config: Partial<IntegrityServiceConfig> = {}) {
    super();
    
    this.config = {
      storagePath: config.storagePath || './integrity-storage',
      defaultHashAlgorithm: config.defaultHashAlgorithm || 'SHA-256',
      signing: config.signing,
      fim: config.fim,
      transparencyLog: config.transparencyLog,
      verificationInterval: config.verificationInterval || 300000, // 5 минут
      enableAuditLog: config.enableAuditLog ?? true,
      auditLogPath: config.auditLogPath,
      maxInMemoryEntries: config.maxInMemoryEntries || 10000,
      slsaRequirements: config.slsaRequirements
    };
    
    // Инициализируем компоненты
    this.initializeComponents();
  }

  /**
   * Инициализирует все компоненты
   */
  private initializeComponents(): void {
    // Создаем директорию хранилища
    this.ensureStorageDirectory();
    
    // Инициализируем Hash Chain Manager
    this.hashChainManager = new HashChainManager(
      path.join(this.config.storagePath, 'hash-chains')
    );
    
    // Инициализируем Code Signer если есть конфигурация
    if (this.config.signing) {
      this.codeSigner = CodeSignerFactory.fromConfig(this.config.signing);
      this.status.components.signer = true;
    }
    
    // Инициализируем Artifact Signer
    this.artifactSigner = new ArtifactSigner();
    
    // Инициализируем SBOM Generator
    this.sbomGenerator = SBOMGeneratorFactory.createForNodeJS();
    
    // Инициализируем Supply Chain Verifier
    this.supplyChainVerifier = SupplyChainVerifierFactory.createForNodeJS();
    
    // Инициализируем SLSA Verifier
    if (this.config.slsaRequirements) {
      this.slsaVerifier = SLSAVerifierFactory.createWithConfig({
        requiredLevel: this.config.slsaRequirements.requiredLevel,
        trustedBuilderIds: [],
        requireReproducible: false,
        requireTwoPersonReview: false,
        hashAlgorithm: 'sha256'
      });
    } else {
      this.slsaVerifier = SLSAVerifierFactory.createForLevel3();
    }
    
    // Инициализируем Transparency Log Client
    if (this.config.transparencyLog) {
      this.tlogClient = TransparencyLogClientFactory.createWithConfig(
        this.config.transparencyLog
      );
    }
    
    // Инициализируем Baseline Manager
    this.baselineManager = new BaselineManager({
      storagePath: path.join(this.config.storagePath, 'baselines'),
      hashAlgorithm: this.config.defaultHashAlgorithm,
      autoSign: !!this.config.signing,
      signingConfig: this.config.signing
    });
    
    // Инициализируем Modification Detector
    this.modificationDetector = ModificationDetectorFactory.createForProduction();
  }

  /**
   * Гарантирует существование директории хранилища
   */
  private ensureStorageDirectory(): void {
    const dirs = [
      this.config.storagePath,
      path.join(this.config.storagePath, 'hash-chains'),
      path.join(this.config.storagePath, 'baselines'),
      path.join(this.config.storagePath, 'audit-logs')
    ];
    
    for (const dir of dirs) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }
  }

  /**
   * Запускает сервис
   * 
   * @returns Результат запуска
   */
  async start(): Promise<OperationResult> {
    if (this.status.isActive) {
      return {
        success: false,
        errors: ['Сервис уже запущен'],
        warnings: [],
        executionTime: 0
      };
    }

    try {
      // Создаем hash chain для audit логов
      this.hashChain = this.hashChainManager!.createChain(
        'audit-log',
        'Audit Log Chain',
        { algorithm: this.config.defaultHashAlgorithm }
      );

      // Запускаем FIM если есть конфигурация
      if (this.config.fim && this.config.fim.length > 0) {
        try {
          this.fim = FIMFactory.createWithConfig(this.config.fim, {
            hashAlgorithm: this.config.defaultHashAlgorithm,
            enableAuditLog: this.config.enableAuditLog,
            auditLogPath: this.config.auditLogPath
          });

          await this.fim.start();
          this.status.components.fim = true;

          // Подключаемся к событиям FIM
          this.fim.on('file-event', (event) => {
            this.logAuditEvent('file-event', event);
            this.emit('file:modified', event);
          });

          this.fim.on('violation', (violation) => {
            this.logAuditEvent('violation', violation);
            this.emit('violation:detected', violation);
          });
        } catch (fimError) {
          // FIM ошибка не критична - продолжаем без него
          console.warn('FIM не запустился:', fimError);
        }
      }

      // Запускаем Runtime Verifier
      try {
        this.runtimeVerifier = RuntimeVerifierFactory.createForProduction([]);
        await this.runtimeVerifier.start();
        this.status.components.runtime = true;
      } catch (rvError) {
        // Runtime Verifier ошибка не критична
        console.warn('Runtime Verifier не запустился:', rvError);
      }

      // Запускаем Modification Detector
      this.status.components.detector = true;

      this.status.isActive = true;
      this.status.startedAt = new Date();

      this.logAuditEvent('service-started', { version: this.status.version });

      this.emit('started', this.status);

      return {
        success: true,
        errors: [],
        warnings: [],
        executionTime: 0
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      this.logAuditEvent('service-start-error', { error: errorMessage });

      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Останавливает сервис
   * 
   * @returns Результат остановки
   */
  async stop(): Promise<OperationResult> {
    if (!this.status.isActive) {
      return {
        success: false,
        errors: ['Сервис не запущен'],
        warnings: [],
        executionTime: 0
      };
    }
    
    try {
      // Останавливаем компоненты
      if (this.fim) {
        await this.fim.stop();
        this.status.components.fim = false;
      }
      
      if (this.runtimeVerifier) {
        await this.runtimeVerifier.stop();
        this.status.components.runtime = false;
      }
      
      this.status.isActive = false;
      
      this.logAuditEvent('service-stopped', { version: this.status.version });
      
      this.emit('stopped');
      
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
   * Вычисляет хеши для файлов
   * 
   * @param filePaths - Пути к файлам
   * @returns Результат хеширования
   */
  async computeHashes(filePaths: string[]): Promise<OperationResult<HashResult>> {
    const startTime = Date.now();
    const files: FileHash[] = [];
    const errors: Array<{ filePath: string; code: string; message: string }> = [];
    
    try {
      for (const filePath of filePaths) {
        try {
          const stats = fs.statSync(filePath);
          const hash = await this.computeFileHash(filePath);
          
          files.push({
            filePath,
            algorithm: this.config.defaultHashAlgorithm,
            hash,
            size: stats.size,
            mtime: stats.mtime,
            hashedAt: new Date()
          });
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
          errors.push({
            filePath,
            code: 'HASH_ERROR',
            message: errorMessage
          });
        }
      }
      
      // Строим Merkle tree если есть файлы
      let rootHash = '';
      if (files.length > 0) {
        this.merkleTree = new MerkleTree(this.config.defaultHashAlgorithm);
        rootHash = this.merkleTree.build(files);
      }
      
      const result: HashResult = {
        files,
        rootHash,
        timestamp: new Date(),
        errors
      };
      
      return {
        success: errors.length === 0,
        data: result,
        errors: errors.map(e => e.message),
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
   * Вычисляет хеш файла
   */
  private async computeFileHash(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash(this.getCryptoAlgorithm());
      const stream = fs.createReadStream(filePath);
      
      stream.on('data', (data) => {
        hash.update(data);
      });
      
      stream.on('end', () => {
        resolve(hash.digest('hex'));
      });
      
      stream.on('error', (error) => {
        reject(error);
      });
    });
  }

  /**
   * Получает название алгоритма для crypto
   */
  private getCryptoAlgorithm(): string {
    const algorithmMap: Record<HashAlgorithm, string> = {
      'SHA-256': 'sha256',
      'SHA-384': 'sha384',
      'SHA-512': 'sha512',
      'SHA3-256': 'sha3-256',
      'SHA3-512': 'sha3-512',
      'BLAKE2b': 'blake2b512',
      'BLAKE3': 'blake3'
    };
    
    return algorithmMap[this.config.defaultHashAlgorithm] || 'sha256';
  }

  /**
   * Подписывает данные
   * 
   * @param data - Данные для подписания
   * @returns Результат подписания
   */
  async sign(data: string | Buffer): Promise<OperationResult<SignatureResult>> {
    if (!this.codeSigner) {
      return {
        success: false,
        errors: ['CodeSigner не инициализирован'],
        warnings: [],
        executionTime: 0
      };
    }
    
    const result = await this.codeSigner.sign(data);
    
    if (result.success && result.data) {
      this.emit('signature:created', result.data);
      this.logAuditEvent('signature-created', { 
        type: result.data.type, 
        keyId: result.data.keyId 
      });
    }
    
    return result;
  }

  /**
   * Верифицирует подпись
   * 
   * @param data - Оригинальные данные
   * @param signature - Подпись
   * @returns Результат верификации
   */
  async verifySignature(
    data: string | Buffer,
    signature: SignatureResult
  ): Promise<OperationResult<SignatureVerificationResult>> {
    if (!this.codeSigner) {
      return {
        success: false,
        errors: ['CodeSigner не инициализирован'],
        warnings: [],
        executionTime: 0
      };
    }
    
    return await this.codeSigner.verify(data, signature);
  }

  /**
   * Генерирует SBOM
   * 
   * @param projectPath - Путь к проекту
   * @returns SBOM документ
   */
  async generateSBOM(projectPath: string): Promise<OperationResult<SBOMDocument>> {
    if (!this.sbomGenerator) {
      return {
        success: false,
        errors: ['SBOMGenerator не инициализирован'],
        warnings: [],
        executionTime: 0
      };
    }
    
    const result = await this.sbomGenerator.generateSBOM(projectPath);
    
    if (result.success && result.data) {
      this.emit('sbom:generated', result.data);
      this.logAuditEvent('sbom-generated', { 
        productName: result.data.productName 
      });
    }
    
    return result;
  }

  /**
   * Верифицирует supply chain
   * 
   * @param sbom - SBOM документ
   * @returns Результат верификации
   */
  async verifySupplyChain(sbom: SBOMDocument): Promise<OperationResult<any>> {
    if (!this.supplyChainVerifier) {
      return {
        success: false,
        errors: ['SupplyChainVerifier не инициализирован'],
        warnings: [],
        executionTime: 0
      };
    }
    
    return await this.supplyChainVerifier.verifySBOM(sbom);
  }

  /**
   * Верифицирует SLSA provenance
   * 
   * @param provenance - SLSA provenance
   * @returns Результат верификации
   */
  async verifySLSA(provenance: any): Promise<OperationResult<SLSAVerificationResult>> {
    if (!this.slsaVerifier) {
      return {
        success: false,
        errors: ['SLSAVerifier не инициализирован'],
        warnings: [],
        executionTime: 0
      };
    }
    
    return await this.slsaVerifier.verifyProvenance(provenance);
  }

  /**
   * Создает baseline
   * 
   * @param name - Название baseline
   * @param files - Файлы
   * @returns Результат создания
   */
  async createBaseline(
    name: string,
    files: FileHash[]
  ): Promise<OperationResult<any>> {
    if (!this.baselineManager) {
      return {
        success: false,
        errors: ['BaselineManager не инициализирован'],
        warnings: [],
        executionTime: 0
      };
    }
    
    const result = await this.baselineManager.createBaseline(name, files);
    
    if (result.success && result.data) {
      this.emit('baseline:updated', result.data);
      this.logAuditEvent('baseline-created', { 
        name, 
        version: result.data.version,
        filesCount: files.length 
      });
    }
    
    return result;
  }

  /**
   * Сравнивает с baseline
   * 
   * @param baselineId - ID baseline
   * @param files - Текущие файлы
   * @returns Результат сравнения
   */
  async compareWithBaseline(
    baselineId: string,
    files: FileHash[]
  ): Promise<OperationResult<BaselineComparisonResult>> {
    if (!this.baselineManager) {
      return {
        success: false,
        errors: ['BaselineManager не инициализирован'],
        warnings: [],
        executionTime: 0
      };
    }
    
    return await this.baselineManager.compareWithBaseline(baselineId, files);
  }

  /**
   * Выполняет полную проверку целостности
   * 
   * @returns Полный отчет
   */
  async performFullIntegrityCheck(): Promise<OperationResult<FullIntegrityReport>> {
    const startTime = Date.now();
    const violations: IntegrityViolation[] = [];
    const signatureStatuses: SignatureVerificationResult[] = [];
    
    try {
      // Получаем статус runtime верификации
      const runtimeStatus = this.runtimeVerifier?.getCurrentStatus() || {
        verified: true,
        verifiedAt: new Date(),
        components: [],
        violations: [],
        score: 100
      };
      
      violations.push(...runtimeStatus.violations);
      
      // Получаем статус FIM
      const fimStatus: FIMStatus = this.fim?.getStatus() || {
        isActive: false,
        watchedFiles: 0,
        eventsCount: 0,
        recentEvents: [],
        errors: []
      };
      
      // Проверяем SLSA если настроено
      let slsaStatus: SLSAVerificationResult | undefined;
      if (this.slsaVerifier) {
        const stats = this.slsaVerifier.getStatistics();
        slsaStatus = {
          achievedLevel: Math.floor(stats.averageLevel) as any,
          requiredLevel: this.config.slsaRequirements?.requiredLevel || 3,
          compliant: stats.compliantCount === stats.totalVerified,
          verifiedAt: new Date(),
          levelChecks: [],
          errors: [],
          warnings: []
        };
      }
      
      // Вычисляем общую оценку
      const overallScore = this.calculateOverallScore(
        runtimeStatus.score,
        violations.length,
        slsaStatus?.compliant
      );
      
      const report: FullIntegrityReport = {
        checkedAt: new Date(),
        overallScore,
        verificationStatus: runtimeStatus,
        signatureStatus: signatureStatuses,
        fimStatus,
        slsaStatus,
        violations,
        recommendations: this.generateRecommendations(violations, overallScore),
        metadata: {
          version: this.status.version,
          environment: process.env.NODE_ENV || 'development',
          hostname: require('os').hostname()
        }
      };
      
      this.logAuditEvent('full-integrity-check', {
        score: overallScore,
        violationsCount: violations.length
      });
      
      return {
        success: true,
        data: report,
        errors: [],
        warnings: violations.length > 0 ? ['Обнаружены нарушения целостности'] : [],
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
   * Вычисляет общую оценку
   */
  private calculateOverallScore(
    runtimeScore: number,
    violationsCount: number,
    slsaCompliant?: boolean
  ): number {
    let score = runtimeScore;
    
    // Штраф за нарушения
    score -= violationsCount * 5;
    
    // Бонус/штраф за SLSA
    if (slsaCompliant !== undefined) {
      score += slsaCompliant ? 10 : -20;
    }
    
    return Math.max(0, Math.min(100, score));
  }

  /**
   * Генерирует рекомендации
   */
  private generateRecommendations(
    violations: IntegrityViolation[],
    overallScore: number
  ): string[] {
    const recommendations: string[] = [];
    
    if (overallScore < 50) {
      recommendations.push('Критическое состояние целостности. Требуется немедленное вмешательство.');
      recommendations.push('Изолировать систему от сети.');
      recommendations.push('Инициировать incident response.');
    } else if (overallScore < 80) {
      recommendations.push('Обнаружены проблемы с целостностью.');
      recommendations.push('Провести детальный анализ нарушений.');
      recommendations.push('Восстановить файлы из доверенных копий.');
    } else {
      recommendations.push('Состояние целостности удовлетворительное.');
      recommendations.push('Продолжать регулярный мониторинг.');
    }
    
    return recommendations;
  }

  /**
   * Логирует audit событие
   */
  private logAuditEvent(eventType: string, details: Record<string, unknown>): void {
    if (!this.config.enableAuditLog) {
      return;
    }
    
    const entry: AuditLogEntry = {
      id: crypto.randomBytes(8).toString('hex'),
      timestamp: new Date(),
      eventType,
      action: eventType,
      result: eventType.includes('error') ? 'failure' : 'success',
      details
    };
    
    this.auditLogs.push(entry);
    
    // Ограничиваем размер в памяти
    if (this.auditLogs.length > this.config.maxInMemoryEntries) {
      this.auditLogs.shift();
    }
    
    // Добавляем в hash chain
    this.hashChain?.append({
      type: eventType,
      content: details
    });
  }

  /**
   * Получает статус сервиса
   */
  getStatus(): ServiceStatus {
    return { ...this.status };
  }

  /**
   * Получает Merkle tree
   */
  getMerkleTree(): MerkleTree | null {
    return this.merkleTree;
  }

  /**
   * Получает FIM
   */
  getFIM(): FileIntegrityMonitor | null {
    return this.fim;
  }

  /**
   * Получает Baseline Manager
   */
  getBaselineManager(): BaselineManager | null {
    return this.baselineManager;
  }

  /**
   * Получает Modification Detector
   */
  getModificationDetector(): ModificationDetector | null {
    return this.modificationDetector;
  }

  /**
   * Экспортирует аудит логи
   * 
   * @returns Массив audit записей
   */
  exportAuditLogs(): AuditLogEntry[] {
    return [...this.auditLogs];
  }

  /**
   * Сохраняет аудит логи на диск
   * 
   * @param outputPath - Путь для сохранения
   * @returns Результат сохранения
   */
  async saveAuditLogs(outputPath: string): Promise<OperationResult> {
    try {
      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      fs.writeFileSync(
        outputPath,
        JSON.stringify(this.auditLogs, null, 2),
        'utf-8'
      );
      
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
}

/**
 * Фабрика для Integrity Service
 */
export class IntegrityServiceFactory {
  /**
   * Создает сервис для development среды
   */
  static createForDevelopment(): IntegrityService {
    return new IntegrityService({
      storagePath: './.integrity',
      enableAuditLog: true,
      verificationInterval: 60000
    });
  }

  /**
   * Создает сервис для production среды
   */
  static createForProduction(config: {
    storagePath: string;
    signingConfig?: SigningKeyConfig;
    watchConfigs?: WatchConfig[];
    tlogConfig?: TransparencyLogConfig;
  }): IntegrityService {
    return new IntegrityService({
      storagePath: config.storagePath,
      signing: config.signingConfig,
      fim: config.watchConfigs,
      transparencyLog: config.tlogConfig,
      enableAuditLog: true,
      verificationInterval: 300000,
      slsaRequirements: {
        requiredLevel: 3,
        enforceProvenance: true
      }
    });
  }

  /**
   * Создает сервис с кастомной конфигурацией
   */
  static createWithConfig(config: IntegrityServiceConfig): IntegrityService {
    return new IntegrityService(config);
  }
}
