/**
 * ============================================================================
 * HASH CHAIN - ХЕШ-ЦЕПЬ ДЛЯ TAMPER-EVIDENT ЛОГИРОВАНИЯ
 * ============================================================================
 * Реализация хеш-цепи для создания неизменяемого журнала событий.
 * Каждая запись содержит хеш предыдущей записи, создавая цепочку,
 * где любое изменение нарушает целостность всей последующей цепи.
 * 
 * Особенности:
 * - Cryptographic linking записей
 * - Защита от tampering и rollback attacks
 * - Подпись записей для дополнительной верификации
 * - Эффективная верификация целостности цепи
 * - Поддержка persistence (сохранение/загрузка)
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../logging/Logger';
import {
  HashChainEntry,
  HashAlgorithm,
  OperationResult,
  SignatureResult
} from '../types/integrity.types';

/**
 * Данные для записи в хеш-цепь
 */
export interface ChainData {
  /** Тип записи */
  type: string;
  /** Содержимое записи */
  content: Record<string, unknown>;
  /** Метаданные */
  metadata?: Record<string, unknown>;
}

/**
 * Конфигурация HashChain
 */
export interface HashChainConfig {
  /** ID цепи */
  id: string;
  /** Название цепи */
  name: string;
  /** Алгоритм хеширования */
  algorithm: HashAlgorithm;
  /** Путь к файлу хранения */
  storagePath?: string;
  /** Автосохранение */
  autoSave: boolean;
  /** Максимум записей в памяти */
  maxInMemoryEntries: number;
  /** Включить подпись записей */
  enableSigning: boolean;
}

/**
 * Класс Hash Chain для tamper-evident логирования
 * 
 * Хеш-цепь обеспечивает неизменяемость журнала событий путем
 * криптографического связывания каждой записи с предыдущей.
 * Любая попытка изменения записи требует пересчета всех последующих
 * хешей, что делает tampering легко обнаружимым.
 */
export class HashChain {
  /** Конфигурация цепи */
  private readonly config: HashChainConfig;
  
  /** Записи цепи */
  private entries: HashChainEntry[] = [];
  
  /** Текущий хеш цепи */
  private currentHash: string = '';
  
  /** Генератор хешей */
  private readonly hashAlgorithm: string;
  
  /** Счетчик записей */
  private entryCounter: number = 0;
  
  /** Время создания цепи */
  private readonly createdAt: Date;
  
  /** Время последнего обновления */
  private updatedAt: Date;

  /**
   * Создает новый экземпляр HashChain
   * 
   * @param config - Конфигурация цепи
   */
  constructor(config: HashChainConfig) {
    this.config = {
      ...config,
      autoSave: config.autoSave ?? true,
      maxInMemoryEntries: config.maxInMemoryEntries ?? 10000,
      enableSigning: config.enableSigning ?? false
    };

    this.hashAlgorithm = this.getCryptoAlgorithm(config.algorithm);
    this.createdAt = new Date();
    this.updatedAt = new Date();
    
    // Инициализируем genesis хеш
    this.currentHash = this.computeGenesisHash();
  }

  /**
   * Преобразует название алгоритма в формат Node.js crypto
   */
  private getCryptoAlgorithm(algorithm: HashAlgorithm): string {
    const algorithmMap: Record<HashAlgorithm, string> = {
      'SHA-256': 'sha256',
      'SHA-384': 'sha384',
      'SHA-512': 'sha512',
      'SHA3-256': 'sha3-256',
      'SHA3-512': 'sha3-512',
      'BLAKE2b': 'blake2b512',
      'BLAKE3': 'blake3'
    };
    
    const algo = algorithmMap[algorithm];
    if (!algo) {
      throw new Error(`Неподдерживаемый алгоритм: ${algorithm}`);
    }
    
    if (algorithm === 'BLAKE3') {
      try {
        crypto.createHash('blake3');
        return 'blake3';
      } catch {
        logger.warn('BLAKE3 недоступен, используем SHA-256');
        return 'sha256';
      }
    }
    
    return algo;
  }

  /**
   * Вычисляет genesis хеш для инициализации цепи
   * 
   * @returns Genesis хеш
   */
  private computeGenesisHash(): string {
    const genesisData = {
      id: this.config.id,
      name: this.config.name,
      createdAt: this.createdAt.toISOString(),
      algorithm: this.config.algorithm
    };
    
    return this.hash(JSON.stringify(genesisData));
  }

  /**
   * Вычисляет хеш данных
   * 
   * @param data - Данные для хеширования
   * @returns Hex хеш
   */
  private hash(data: string): string {
    const hash = crypto.createHash(this.hashAlgorithm);
    hash.update(Buffer.from(data, 'utf-8'));
    return hash.digest('hex');
  }

  /**
   * Добавляет новую запись в цепь
   * 
   * @param data - Данные записи
   * @param signature - Опциональная подпись записи
   * @returns Добавленная запись
   */
  append(data: ChainData, signature?: string): HashChainEntry {
    const index = this.entryCounter++;
    const timestamp = new Date();
    
    // Сериализуем данные записи
    const entryData = JSON.stringify({
      index,
      type: data.type,
      content: data.content,
      metadata: data.metadata,
      timestamp: timestamp.toISOString()
    });
    
    // Вычисляем хеш записи
    const entryHash = this.hash(entryData);
    
    // Создаем запись с ссылкой на предыдущий хеш
    const entry: HashChainEntry = {
      index,
      data: entryData,
      hash: entryHash,
      previousHash: this.currentHash,
      timestamp,
      signature
    };
    
    // Обновляем текущий хеш цепи
    this.currentHash = this.hashChainEntry(entry);
    
    // Добавляем запись
    this.entries.push(entry);
    this.updatedAt = new Date();
    
    // Автосохранение если включено
    if (this.config.autoSave && this.config.storagePath) {
      this.save().catch(err => {
        logger.error(`Ошибка сохранения цепи ${this.config.id}`, { error: err });
      });
    }
    
    // Ограничиваем размер в памяти
    if (this.entries.length > this.config.maxInMemoryEntries) {
      this.entries.shift();
    }
    
    return entry;
  }

  /**
   * Вычисляет хеш записи для цепи
   * 
   * @param entry - Запись
   * @returns Хеш записи в цепи
   */
  private hashChainEntry(entry: HashChainEntry): string {
    const chainData = JSON.stringify({
      previousHash: entry.previousHash,
      hash: entry.hash,
      index: entry.index,
      timestamp: entry.timestamp.toISOString()
    });
    
    return this.hash(chainData);
  }

  /**
   * Добавляет пакет записей в цепь
   * 
   * @param dataList - Массив данных для записи
   * @returns Массив добавленных записей
   */
  appendBatch(dataList: ChainData[]): HashChainEntry[] {
    return dataList.map(data => this.append(data));
  }

  /**
   * Получает запись по индексу
   * 
   * @param index - Индекс записи
   * @returns Запись или null
   */
  getEntry(index: number): HashChainEntry | null {
    return this.entries.find(e => e.index === index) || null;
  }

  /**
   * Получает диапазон записей
   * 
   * @param startIndex - Начальный индекс
   * @param endIndex - Конечный индекс
   * @returns Массив записей
   */
  getEntriesRange(startIndex: number, endIndex: number): HashChainEntry[] {
    return this.entries.filter(
      e => e.index >= startIndex && e.index <= endIndex
    );
  }

  /**
   * Получает последние N записей
   * 
   * @param count - Количество записей
   * @returns Массив записей
   */
  getLatestEntries(count: number): HashChainEntry[] {
    return this.entries.slice(-count);
  }

  /**
   * Верифицирует целостность цепи
   * 
   * Проверяет что каждая запись корректно связана с предыдущей
   * и хеши вычислены правильно.
   * 
   * @returns Результат верификации
   */
  verify(): OperationResult<{ validFrom: number; validTo: number }> {
    const errors: string[] = [];
    const warnings: string[] = [];
    
    if (this.entries.length === 0) {
      return {
        success: true,
        data: { validFrom: 0, validTo: -1 },
        errors: [],
        warnings: ['Цепь пуста'],
        executionTime: 0
      };
    }
    
    const startTime = Date.now();
    let validFrom = 0;
    let validTo = this.entries.length - 1;
    
    // Проверяем первую запись
    const firstEntry = this.entries[0];
    if (firstEntry.previousHash !== this.computeGenesisHash()) {
      errors.push(`Первая запись имеет некорректный genesis хеш`);
      validFrom = 1;
    }
    
    // Проверяем связи между записями
    for (let i = 1; i < this.entries.length; i++) {
      const prevEntry = this.entries[i - 1];
      const currentEntry = this.entries[i];
      
      // Проверяем что previousHash совпадает с хешем предыдущей записи в цепи
      const expectedPreviousHash = this.hashChainEntry(prevEntry);
      
      // Для первой проверки после genesis используем genesis хеш
      const actualPreviousHash = i === 1 
        ? this.computeGenesisHash()
        : this.hashChainEntry(this.entries[i - 2]);
      
      if (currentEntry.previousHash !== expectedPreviousHash && i > 1) {
        errors.push(`Запись ${i} имеет некорректную ссылку на предыдущую запись`);
        validTo = i - 1;
        break;
      }
      
      // Проверяем хеш записи
      const entryDataHash = this.hash(currentEntry.data);
      if (currentEntry.hash !== entryDataHash) {
        errors.push(`Запись ${i} имеет некорректный хеш данных`);
        validTo = i - 1;
        break;
      }
      
      // Проверяем последовательность индексов
      if (currentEntry.index !== prevEntry.index + 1) {
        warnings.push(`Нарушена последовательность индексов между ${prevEntry.index} и ${currentEntry.index}`);
      }
    }
    
    // Проверяем текущий хеш цепи
    const lastEntry = this.entries[this.entries.length - 1];
    const expectedCurrentHash = this.hashChainEntry(lastEntry);
    if (this.currentHash !== expectedCurrentHash) {
      errors.push(`Текущий хеш цепи не совпадает с хешем последней записи`);
    }
    
    return {
      success: errors.length === 0,
      data: errors.length === 0 ? { validFrom: 0, validTo: this.entries.length - 1 } : { validFrom, validTo },
      errors,
      warnings,
      executionTime: Date.now() - startTime
    };
  }

  /**
   * Верифицирует отдельную запись в цепи
   * 
   * @param index - Индекс записи
   * @returns Результат верификации
   */
  verifyEntry(index: number): OperationResult<{ verified: boolean }> {
    const entry = this.getEntry(index);
    
    if (!entry) {
      return {
        success: false,
        errors: [`Запись с индексом ${index} не найдена`],
        warnings: [],
        executionTime: 0
      };
    }
    
    const errors: string[] = [];
    
    // Проверяем хеш данных
    const computedHash = this.hash(entry.data);
    if (entry.hash !== computedHash) {
      errors.push('Хеш данных не совпадает');
    }
    
    // Проверяем ссылку на предыдущую запись
    if (index > 0) {
      const prevEntry = this.getEntry(index - 1);
      if (prevEntry) {
        const expectedPreviousHash = this.hashChainEntry(prevEntry);
        if (entry.previousHash !== expectedPreviousHash) {
          errors.push('Ссылка на предыдущую запись некорректна');
        }
      }
    } else {
      // Первая запись должна ссылаться на genesis
      const genesisHash = this.computeGenesisHash();
      if (entry.previousHash !== genesisHash) {
        errors.push('Первая запись имеет некорректный genesis хеш');
      }
    }
    
    return {
      success: errors.length === 0,
      data: { verified: errors.length === 0 },
      errors,
      warnings: [],
      executionTime: 0
    };
  }

  /**
   * Получает proof включения записи
   * 
   * Proof позволяет доказать что запись существовала в определенный момент
   * 
   * @param index - Индекс записи
   * @returns Proof включения или null
   */
  getInclusionProof(index: number): {
    entry: HashChainEntry;
    chainHash: string;
    path: HashChainEntry[];
  } | null {
    const entry = this.getEntry(index);
    
    if (!entry) {
      return null;
    }
    
    // Получаем все записи от target до конца
    const path = this.entries.slice(index, Math.min(index + 10, this.entries.length));
    
    return {
      entry,
      chainHash: this.currentHash,
      path
    };
  }

  /**
   * Сохраняет цепь в файл
   * 
   * @returns Результат сохранения
   */
  async save(): Promise<OperationResult> {
    if (!this.config.storagePath) {
      return {
        success: false,
        errors: ['Путь хранения не указан'],
        warnings: [],
        executionTime: 0
      };
    }
    
    try {
      const startTime = Date.now();
      
      // Создаем директорию если не существует
      const dir = path.dirname(this.config.storagePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      
      // Сериализуем цепь
      const chainData = this.toJSON();
      
      // Вычисляем хеш состояния для верификации
      chainData.stateHash = this.hash(JSON.stringify({
        entries: this.entries.length,
        currentHash: this.currentHash,
        updatedAt: this.updatedAt.toISOString()
      }));
      
      // Записываем файл
      fs.writeFileSync(
        this.config.storagePath,
        JSON.stringify(chainData, null, 2),
        'utf-8'
      );
      
      return {
        success: true,
        errors: [],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      return {
        success: false,
        errors: [`Ошибка сохранения: ${errorMessage}`],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Загружает цепь из файла
   *
   * @param filePath - Путь к файлу
   * @returns Результат загрузки
   */
  static async load(filePath: string): Promise<OperationResult<HashChain>> {
    try {
      const startTime = Date.now();

      if (!fs.existsSync(filePath)) {
        console.error('HashChain.load: файл не найден:', filePath);
        return {
          success: false,
          errors: ['Файл не найден'],
          warnings: [],
          executionTime: 0
        };
      }

      const fileContent = fs.readFileSync(filePath, 'utf-8');
      const data = JSON.parse(fileContent);

      // Восстанавливаем цепь
      const chain = new HashChain({
        id: data.id,
        name: data.name,
        algorithm: data.algorithm as HashAlgorithm,
        storagePath: filePath,
        autoSave: false,
        maxInMemoryEntries: 10000,
        enableSigning: false
      });

      // Восстанавливаем записи
      chain.entries = (data.entries || []).map((entry: any) => ({
        ...entry,
        timestamp: new Date(entry.timestamp)  // Конвертируем строку в Date
      }));
      chain.currentHash = data.currentHash || '';
      chain.entryCounter = data.entryCounter || chain.entries.length;
      chain.createdAt = new Date(data.createdAt);
      chain.updatedAt = new Date(data.updatedAt);

      // Верифицируем загруженную цепь
      const verification = chain.verify();

      // Возвращаем chain в data даже если верификация не прошла
      return {
        success: true,  // Успешно загрузили, верификация отдельный вопрос
        data: chain,
        errors: verification.errors,
        warnings: verification.warnings,
        executionTime: Date.now() - startTime
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      console.error('HashChain.load error:', errorMessage);
      return {
        success: false,
        errors: [`Ошибка загрузки: ${errorMessage}`],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Сериализует цепь в JSON
   * 
   * @returns JSON представление цепи
   */
  toJSON(): Record<string, unknown> {
    return {
      id: this.config.id,
      name: this.config.name,
      algorithm: this.config.algorithm,
      createdAt: this.createdAt.toISOString(),
      updatedAt: this.updatedAt.toISOString(),
      entryCounter: this.entryCounter,
      currentHash: this.currentHash,
      entriesCount: this.entries.length,
      entries: this.entries.map(entry => ({
        index: entry.index,
        data: entry.data,
        hash: entry.hash,
        previousHash: entry.previousHash,
        timestamp: entry.timestamp.toISOString(),
        signature: entry.signature
      }))
    };
  }

  /**
   * Получает статистику цепи
   * 
   * @returns Статистика цепи
   */
  getStatistics(): {
    totalEntries: number;
    currentHash: string;
    createdAt: Date;
    updatedAt: Date;
    averageEntriesPerDay: number;
    storageSize: number;
  } {
    const storageSize = this.entries.reduce(
      (size, entry) => size + Buffer.byteLength(entry.data, 'utf-8'),
      0
    );
    
    const daysSinceCreation = (Date.now() - this.createdAt.getTime()) / (1000 * 60 * 60 * 24);
    const averageEntriesPerDay = daysSinceCreation > 0 
      ? this.entries.length / daysSinceCreation 
      : this.entries.length;
    
    return {
      totalEntries: this.entries.length,
      currentHash: this.currentHash,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      averageEntriesPerDay,
      storageSize
    };
  }

  /**
   * Получает текущий хеш цепи
   * 
   * @returns Текущий хеш
   */
  getCurrentHash(): string {
    return this.currentHash;
  }

  /**
   * Получает количество записей
   * 
   * @returns Количество записей
   */
  getEntriesCount(): number {
    return this.entries.length;
  }

  /**
   * Очищает цепь (только для тестирования)
   * 
   * @warning Используйте с осторожностью
   */
  clear(): void {
    this.entries = [];
    this.entryCounter = 0;
    this.currentHash = this.computeGenesisHash();
    this.updatedAt = new Date();
  }

  /**
   * Экспортирует цепь для аудита
   * 
   * @returns Данные для аудита
   */
  exportForAudit(): {
    chainId: string;
    entries: Array<{
      index: number;
      type: string;
      hash: string;
      previousHash: string;
      timestamp: string;
    }>;
    finalHash: string;
    exportedAt: string;
  } {
    return {
      chainId: this.config.id,
      entries: this.entries.map(entry => {
        const parsedData = JSON.parse(entry.data);
        return {
          index: entry.index,
          type: parsedData.type,
          hash: entry.hash,
          previousHash: entry.previousHash,
          timestamp: entry.timestamp.toISOString()
        };
      }),
      finalHash: this.currentHash,
      exportedAt: new Date().toISOString()
    };
  }
}

/**
 * Менеджер хеш-цепей для управления несколькими цепями
 */
export class HashChainManager {
  /** Хранилище цепей */
  private readonly chains: Map<string, HashChain> = new Map();
  
  /** Путь к хранилищу */
  private readonly storagePath: string;

  /**
   * Создает менеджер хеш-цепей
   * 
   * @param storagePath - Путь к хранилищу цепей
   */
  constructor(storagePath: string) {
    this.storagePath = storagePath;
  }

  /**
   * Создает новую цепь
   * 
   * @param id - ID цепи
   * @param name - Название цепи
   * @param config - Дополнительная конфигурация
   * @returns Экземпляр цепи
   */
  createChain(
    id: string,
    name: string,
    config: Partial<HashChainConfig> = {}
  ): HashChain {
    const chain = new HashChain({
      id,
      name,
      algorithm: config.algorithm || 'SHA-256',
      storagePath: config.storagePath || path.join(this.storagePath, `${id}.chain.json`),
      autoSave: config.autoSave ?? true,
      maxInMemoryEntries: config.maxInMemoryEntries ?? 10000,
      enableSigning: config.enableSigning ?? false
    });
    
    this.chains.set(id, chain);
    
    return chain;
  }

  /**
   * Получает цепь по ID
   * 
   * @param id - ID цепи
   * @returns Цепь или null
   */
  getChain(id: string): HashChain | null {
    return this.chains.get(id) || null;
  }

  /**
   * Загружает цепь из файла
   * 
   * @param id - ID цепи
   * @param filePath - Путь к файлу
   * @returns Результат загрузки
   */
  async loadChain(id: string, filePath: string): Promise<OperationResult<HashChain>> {
    const result = await HashChain.load(filePath);
    
    if (result.success && result.data) {
      this.chains.set(id, result.data);
    }
    
    return result;
  }

  /**
   * Сохраняет все цепи
   * 
   * @returns Результаты сохранения
   */
  async saveAllChains(): Promise<Map<string, OperationResult>> {
    const results = new Map<string, OperationResult>();
    
    for (const [id, chain] of this.chains.entries()) {
      const result = await chain.save();
      results.set(id, result);
    }
    
    return results;
  }

  /**
   * Верифицирует все цепи
   * 
   * @returns Результаты верификации
   */
  verifyAllChains(): Map<string, OperationResult> {
    const results = new Map<string, OperationResult>();
    
    for (const [id, chain] of this.chains.entries()) {
      const result = chain.verify();
      results.set(id, result);
    }
    
    return results;
  }

  /**
   * Удаляет цепь
   * 
   * @param id - ID цепи
   * @returns Успешность удаления
   */
  deleteChain(id: string): boolean {
    return this.chains.delete(id);
  }

  /**
   * Получает список всех цепей
   * 
   * @returns Список ID цепей
   */
  listChains(): string[] {
    return Array.from(this.chains.keys());
  }
}
