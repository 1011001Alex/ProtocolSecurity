/**
 * ============================================================================
 * BASELINE MANAGER - УПРАВЛЕНИЕ БАЗОВЫМИ ЛИНИЯМИ ЦЕЛОСТНОСТИ
 * ============================================================================
 * Модуль для создания, хранения и управления базовыми линиями
 * целостности файлов и артефактов.
 * 
 * Особенности:
 * - Создание baseline с Merkle tree
 * - Верификация против baseline
 * - Управление версиями baseline
 * - Подпись baseline
 * - Сравнение baseline
 * - Rollback защита
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  IntegrityBaseline,
  BaselineMetadata,
  BaselineComparisonResult,
  FileHash,
  FileChange,
  MerkleProof,
  SignatureResult,
  HashAlgorithm,
  OperationResult,
  SigningKeyConfig
} from '../types/integrity.types';
import { MerkleTree } from './MerkleTree';
import { CodeSigner } from './CodeSigner';

/**
 * Конфигурация Baseline Manager
 */
export interface BaselineManagerConfig {
  /** Путь к хранилищу baseline */
  storagePath: string;
  /** Алгоритм хеширования */
  hashAlgorithm: HashAlgorithm;
  /** Автоматически подписывать baseline */
  autoSign: boolean;
  /** Конфигурация подписания */
  signingConfig?: SigningKeyConfig;
  /** Максимум версий baseline */
  maxVersions: number;
  /** Включить сжатие */
  enableCompression: boolean;
}

/**
 * Хранилище baseline
 */
interface BaselineStorage {
  /** ID baseline */
  id: string;
  /** Версии */
  versions: Map<string, IntegrityBaseline>;
  /** Текущая версия */
  currentVersion: string;
  /** Создана */
  createdAt: Date;
  /** Обновлена */
  updatedAt: Date;
}

/**
 * Класс Baseline Manager
 */
export class BaselineManager extends EventEmitter {
  /** Конфигурация */
  private readonly config: BaselineManagerConfig;
  
  /** Хранилище baseline */
  private readonly storage: Map<string, BaselineStorage> = new Map();
  
  /** Code signer для подписания */
  private readonly signer?: CodeSigner;
  
  /** Кэш Merkle trees */
  private readonly merkleTreeCache: Map<string, MerkleTree> = new Map();

  /**
   * Создает экземпляр BaselineManager
   */
  constructor(config: Partial<BaselineManagerConfig> = {}) {
    super();
    
    this.config = {
      storagePath: config.storagePath || './baselines',
      hashAlgorithm: config.hashAlgorithm || 'SHA-256',
      autoSign: config.autoSign ?? false,
      signingConfig: config.signingConfig,
      maxVersions: config.maxVersions || 10,
      enableCompression: config.enableCompression ?? true
    };
    
    // Инициализируем signer если нужно
    if (this.config.autoSign && this.config.signingConfig) {
      this.signer = new CodeSigner(this.config.signingConfig);
    }
    
    // Создаем директорию хранилища
    this.ensureStorageDirectory();
  }

  /**
   * Гарантирует существование директории хранилища
   */
  private ensureStorageDirectory(): void {
    if (!fs.existsSync(this.config.storagePath)) {
      fs.mkdirSync(this.config.storagePath, { recursive: true });
    }
  }

  /**
   * Создает новую baseline
   * 
   * @param name - Название baseline
   * @param files - Файлы для включения
   * @param metadata - Метаданные
   * @returns Результат создания
   */
  async createBaseline(
    name: string,
    files: FileHash[],
    metadata: Partial<BaselineMetadata> = {}
  ): Promise<OperationResult<IntegrityBaseline>> {
    const startTime = Date.now();

    try {
      // Проверяем что файлы не пустые
      if (files.length === 0) {
        return {
          success: false,
          errors: ['Список файлов пуст'],
          warnings: [],
          executionTime: Date.now() - startTime
        };
      }

      // Генерируем ID
      const id = this.generateBaselineId(name);
      const version = '1.0.0';

      // Создаем Merkle tree
      const merkleTree = new MerkleTree(this.config.hashAlgorithm);
      const merkleRoot = merkleTree.build(files);

      // Генерируем Merkle proofs для каждого файла
      const merkleProofs: Record<string, MerkleProof> = {};
      for (const file of files) {
        const proof = merkleTree.generateProof(file.filePath);
        if (proof) {
          merkleProofs[file.filePath] = proof;
        }
      }

      // Кэшируем tree
      this.merkleTreeCache.set(`${id}:${version}`, merkleTree);

      // Создаем baseline
      const baseline: IntegrityBaseline = {
        id,
        name,
        description: metadata.notes || `Baseline для ${name}`,
        version,
        createdAt: new Date(),
        createdBy: process.env.USER || 'unknown',
        baselineHash: this.computeBaselineHash(files, merkleRoot),
        signature: undefined,
        files,
        merkleRoot,
        merkleProofs,
        metadata: {
          environment: metadata.environment || 'development',
          gitBranch: metadata.gitBranch,
          gitCommit: metadata.gitCommit,
          gitTag: metadata.gitTag,
          buildId: metadata.buildId,
          tags: metadata.tags || [],
          notes: metadata.notes
        }
      };

      // Подписываем если включено
      if (this.config.autoSign && this.signer) {
        const signResult = await this.signBaseline(baseline);
        if (signResult.success && signResult.data) {
          baseline.signature = signResult.data;
        }
      }

      // Сохраняем baseline
      this.saveBaseline(baseline);

      this.emit('baseline-created', baseline);

      return {
        success: true,
        data: baseline,
        errors: [],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      console.error('BaselineManager.createBaseline error:', errorMessage);

      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    }
  }

  /**
   * Генерирует ID baseline
   */
  private generateBaselineId(name: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(`${name}-${Date.now()}`);
    return `baseline-${hash.digest('hex').substring(0, 16)}`;
  }

  /**
   * Вычисляет хеш baseline
   */
  private computeBaselineHash(files: FileHash[], merkleRoot: string): string {
    const hash = crypto.createHash(this.getHashAlgorithm());
    
    // Хеш от сортированных путей файлов
    const sortedPaths = files.map(f => f.filePath).sort();
    for (const p of sortedPaths) {
      hash.update(p);
    }
    
    // Добавляем Merkle root
    hash.update(merkleRoot);
    
    return hash.digest('hex');
  }

  /**
   * Получает название алгоритма хеширования
   */
  private getHashAlgorithm(): string {
    const algorithmMap: Record<HashAlgorithm, string> = {
      'SHA-256': 'sha256',
      'SHA-384': 'sha384',
      'SHA-512': 'sha512',
      'SHA3-256': 'sha3-256',
      'SHA3-512': 'sha3-512',
      'BLAKE2b': 'blake2b512',
      'BLAKE3': 'blake3'
    };
    
    return algorithmMap[this.config.hashAlgorithm] || 'sha256';
  }

  /**
   * Подписывает baseline
   */
  private async signBaseline(baseline: IntegrityBaseline): Promise<OperationResult<SignatureResult>> {
    if (!this.signer) {
      return {
        success: false,
        errors: ['Signer не инициализирован'],
        warnings: [],
        executionTime: 0
      };
    }
    
    const data = JSON.stringify({
      id: baseline.id,
      version: baseline.version,
      baselineHash: baseline.baselineHash,
      merkleRoot: baseline.merkleRoot,
      createdAt: baseline.createdAt.toISOString()
    });
    
    return await this.signer.sign(data);
  }

  /**
   * Сохраняет baseline в хранилище
   */
  private saveBaseline(baseline: IntegrityBaseline): void {
    let storage = this.storage.get(baseline.id);
    
    if (!storage) {
      storage = {
        id: baseline.id,
        versions: new Map(),
        currentVersion: baseline.version,
        createdAt: new Date(),
        updatedAt: new Date()
      };
    }
    
    // Ограничиваем количество версий
    if (storage.versions.size >= this.config.maxVersions) {
      const firstKey = storage.versions.keys().next().value;
      if (firstKey) {
        storage.versions.delete(firstKey);
      }
    }
    
    storage.versions.set(baseline.version, baseline);
    storage.currentVersion = baseline.version;
    storage.updatedAt = new Date();
    
    this.storage.set(baseline.id, storage);
    
    // Сохраняем на диск
    this.persistBaseline(baseline);
  }

  /**
   * Сохраняет baseline на диск
   */
  private persistBaseline(baseline: IntegrityBaseline): void {
    const filePath = path.join(
      this.config.storagePath,
      `${baseline.id}-${baseline.version}.json`
    );
    
    const data = {
      ...baseline,
      createdAt: baseline.createdAt.toISOString(),
      signature: baseline.signature ? {
        ...baseline.signature,
        signedAt: baseline.signature.signedAt.toISOString()
      } : undefined
    };
    
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');
  }

  /**
   * Загружает baseline из хранилища
   * 
   * @param baselineId - ID baseline
   * @param version - Версия (опционально)
   * @returns Результат загрузки
   */
  async loadBaseline(
    baselineId: string,
    version?: string
  ): Promise<OperationResult<IntegrityBaseline>> {
    try {
      // Проверяем в памяти
      const storage = this.storage.get(baselineId);
      
      if (storage) {
        const baselineVersion = version || storage.currentVersion;
        const baseline = storage.versions.get(baselineVersion);
        
        if (baseline) {
          return {
            success: true,
            data: baseline,
            errors: [],
            warnings: [],
            executionTime: 0
          };
        }
      }
      
      // Загружаем с диска
      const pattern = version 
        ? `${baselineId}-${version}.json`
        : `${baselineId}-*.json`;
      
      const files = fs.readdirSync(this.config.storagePath)
        .filter(f => f.startsWith(baselineId) && f.endsWith('.json'))
        .sort()
        .reverse();
      
      if (files.length === 0) {
        return {
          success: false,
          errors: ['Baseline не найден'],
          warnings: [],
          executionTime: 0
        };
      }
      
      const filePath = path.join(this.config.storagePath, files[0]);
      const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
      
      const baseline: IntegrityBaseline = {
        ...data,
        createdAt: new Date(data.createdAt),
        signature: data.signature ? {
          ...data.signature,
          signedAt: new Date(data.signature.signedAt)
        } : undefined
      };
      
      // Кэшируем в памяти
      this.cacheBaseline(baseline);
      
      return {
        success: true,
        data: baseline,
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
   * Кэширует baseline в памяти
   */
  private cacheBaseline(baseline: IntegrityBaseline): void {
    let storage = this.storage.get(baseline.id);
    
    if (!storage) {
      storage = {
        id: baseline.id,
        versions: new Map(),
        currentVersion: baseline.version,
        createdAt: baseline.createdAt,
        updatedAt: new Date()
      };
    }
    
    storage.versions.set(baseline.version, baseline);
    this.storage.set(baseline.id, storage);
  }

  /**
   * Сравнивает текущее состояние с baseline
   * 
   * @param baselineId - ID baseline
   * @param currentFiles - Текущие файлы
   * @returns Результат сравнения
   */
  async compareWithBaseline(
    baselineId: string,
    currentFiles: FileHash[]
  ): Promise<OperationResult<BaselineComparisonResult>> {
    const startTime = Date.now();
    
    try {
      // Загружаем baseline
      const baselineResult = await this.loadBaseline(baselineId);
      
      if (!baselineResult.success || !baselineResult.data) {
        return {
          success: false,
          errors: baselineResult.errors,
          warnings: [],
          executionTime: Date.now() - startTime
        };
      }
      
      const baseline = baselineResult.data;
      
      // Создаем карты для сравнения
      const baselineMap = new Map<string, FileHash>();
      const currentMap = new Map<string, FileHash>();
      
      for (const file of baseline.files) {
        baselineMap.set(file.filePath, file);
      }
      
      for (const file of currentFiles) {
        currentMap.set(file.filePath, file);
      }
      
      // Находим изменения
      const modified: FileChange[] = [];
      const added: FileHash[] = [];
      const removed: { filePath: string; lastHash: string }[] = [];
      
      // Проверяем файлы baseline
      for (const [filePath, baselineFile] of baselineMap.entries()) {
        const currentFile = currentMap.get(filePath);
        
        if (!currentFile) {
          removed.push({
            filePath,
            lastHash: baselineFile.hash
          });
        } else if (currentFile.hash !== baselineFile.hash) {
          modified.push({
            filePath,
            oldHash: baselineFile.hash,
            newHash: currentFile.hash,
            changeType: 'content',
            changedAt: currentFile.hashedAt
          });
        }
      }
      
      // Проверяем новые файлы
      for (const [filePath, currentFile] of currentMap.entries()) {
        if (!baselineMap.has(filePath)) {
          added.push(currentFile);
        }
      }
      
      const matches = modified.length === 0 && 
                      added.length === 0 && 
                      removed.length === 0;
      
      const result: BaselineComparisonResult = {
        baselineId,
        comparedAt: new Date(),
        matches,
        modified,
        added,
        removed,
        statistics: {
          totalFiles: baseline.files.length,
          matchedFiles: baseline.files.length - modified.length - removed.length,
          modifiedFiles: modified.length,
          addedFiles: added.length,
          removedFiles: removed.length
        }
      };
      
      this.emit('baseline-compared', result);
      
      return {
        success: true,
        data: result,
        errors: [],
        warnings: matches ? [] : ['Обнаружены изменения'],
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
   * Обновляет baseline новыми файлами
   * 
   * @param baselineId - ID baseline
   * @param files - Новые файлы
   * @returns Результат обновления
   */
  async updateBaseline(
    baselineId: string,
    files: FileHash[]
  ): Promise<OperationResult<IntegrityBaseline>> {
    const startTime = Date.now();
    
    try {
      // Загружаем текущую baseline
      const loadResult = await this.loadBaseline(baselineId);
      
      if (!loadResult.success || !loadResult.data) {
        return {
          success: false,
          errors: loadResult.errors,
          warnings: [],
          executionTime: Date.now() - startTime
        };
      }
      
      const oldBaseline = loadResult.data;
      
      // Увеличиваем версию
      const newVersion = this.incrementVersion(oldBaseline.version);
      
      // Создаем новую baseline
      const newBaseline = await this.createBaseline(
        oldBaseline.name,
        files,
        {
          ...oldBaseline.metadata,
          notes: `Updated from ${oldBaseline.version}`
        }
      );
      
      if (!newBaseline.success || !newBaseline.data) {
        return newBaseline;
      }
      
      newBaseline.data.version = newVersion;
      
      this.emit('baseline-updated', newBaseline.data);
      
      return newBaseline;
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
   * Увеличивает версию
   */
  private incrementVersion(version: string): string {
    const parts = version.split('.').map(Number);
    parts[2] = (parts[2] || 0) + 1;
    return parts.join('.');
  }

  /**
   * Верифицирует подпись baseline
   * 
   * @param baselineId - ID baseline
   * @returns Результат верификации
   */
  async verifyBaselineSignature(baselineId: string): Promise<OperationResult<{ verified: boolean }>> {
    try {
      const loadResult = await this.loadBaseline(baselineId);
      
      if (!loadResult.success || !loadResult.data) {
        return {
          success: false,
          errors: loadResult.errors,
          warnings: [],
          executionTime: 0
        };
      }
      
      const baseline = loadResult.data;
      
      if (!baseline.signature) {
        return {
          success: false,
          errors: ['Подпись отсутствует'],
          warnings: [],
          executionTime: 0
        };
      }
      
      if (!this.signer) {
        return {
          success: false,
          errors: ['Signer не инициализирован'],
          warnings: [],
          executionTime: 0
        };
      }
      
      const signatureData = {
        id: baseline.id,
        version: baseline.version,
        baselineHash: baseline.baselineHash,
        merkleRoot: baseline.merkleRoot,
        createdAt: baseline.createdAt.toISOString()
      };

      const verifyResult = await this.signer.verify(JSON.stringify(signatureData), baseline.signature);
      
      return {
        success: verifyResult.success,
        data: { verified: verifyResult.success && (verifyResult.data?.verified ?? false) },
        errors: verifyResult.errors,
        warnings: verifyResult.warnings,
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
   * Получает список всех baseline
   * 
   * @returns Список baseline
   */
  listBaselines(): Array<{
    id: string;
    name: string;
    currentVersion: string;
    versionsCount: number;
    createdAt: Date;
    updatedAt: Date;
  }> {
    const result: Array<{
      id: string;
      name: string;
      currentVersion: string;
      versionsCount: number;
      createdAt: Date;
      updatedAt: Date;
    }> = [];
    
    for (const storage of this.storage.values()) {
      const firstBaseline = storage.versions.get(storage.currentVersion);
      
      result.push({
        id: storage.id,
        name: firstBaseline?.name || 'Unknown',
        currentVersion: storage.currentVersion,
        versionsCount: storage.versions.size,
        createdAt: storage.createdAt,
        updatedAt: storage.updatedAt
      });
    }
    
    return result;
  }

  /**
   * Удаляет baseline
   * 
   * @param baselineId - ID baseline
   * @returns Результат удаления
   */
  deleteBaseline(baselineId: string): OperationResult {
    try {
      const storage = this.storage.get(baselineId);
      
      if (!storage) {
        return {
          success: false,
          errors: ['Baseline не найден'],
          warnings: [],
          executionTime: 0
        };
      }
      
      // Удаляем файлы с диска
      for (const version of storage.versions.keys()) {
        const filePath = path.join(
          this.config.storagePath,
          `${baselineId}-${version}.json`
        );
        
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      }
      
      // Удаляем из памяти
      this.storage.delete(baselineId);
      
      // Очищаем кэш Merkle trees
      for (const key of this.merkleTreeCache.keys()) {
        if (key.startsWith(baselineId)) {
          this.merkleTreeCache.delete(key);
        }
      }
      
      this.emit('baseline-deleted', baselineId);
      
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
   * Получает Merkle tree для baseline
   */
  getMerkleTree(baselineId: string, version?: string): MerkleTree | null {
    const storage = this.storage.get(baselineId);
    
    if (!storage) {
      return null;
    }
    
    const baselineVersion = version || storage.currentVersion;
    const cacheKey = `${baselineId}:${baselineVersion}`;
    
    return this.merkleTreeCache.get(cacheKey) || null;
  }

  /**
   * Экспортирует baseline в файл
   * 
   * @param baselineId - ID baseline
   * @param outputPath - Путь для экспорта
   * @returns Результат экспорта
   */
  async exportBaseline(baselineId: string, outputPath: string): Promise<OperationResult> {
    try {
      const loadResult = await this.loadBaseline(baselineId);

      if (!loadResult.success || !loadResult.data) {
        return {
          success: false,
          errors: loadResult.errors,
          warnings: [],
          executionTime: 0
        };
      }

      const dir = path.dirname(outputPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      fs.writeFileSync(
        outputPath,
        JSON.stringify(loadResult.data, null, 2),
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
