/**
 * ============================================================================
 * FORENSICS COLLECTOR
 * ============================================================================
 * Модуль автоматизированного сбора форензика данных для инцидентов безопасности
 * Соответствует NIST SP 800-61, NIST SP 800-86, и ISO 27037
 * ============================================================================
 */

import { EventEmitter } from 'events';
import { createHash } from 'crypto';
import {
  ForensicsDataType,
  Evidence,
  EvidenceCategory,
  ChainOfCustodyStatus,
  Actor,
  Incident,
  ForensicsConfig
} from '../types/incident.types';

/**
 * События сборщика форензика данных
 */
export enum ForensicsCollectorEvent {
  /** Сбор начался */
  COLLECTION_STARTED = 'collection_started',
  /** Тип данных собран */
  DATA_COLLECTED = 'data_collected',
  /** Ошибка сбора */
  COLLECTION_ERROR = 'collection_error',
  /** Сбор завершен */
  COLLECTION_COMPLETED = 'collection_completed',
  /** Целостность проверена */
  INTEGRITY_VERIFIED = 'integrity_verified',
  /** Целостность нарушена */
  INTEGRITY_VIOLATED = 'integrity_violated'
}

/**
 * Результат сбора данных
 */
export interface CollectionResult {
  /** Тип собранных данных */
  dataType: ForensicsDataType;
  /** Успешно ли собрано */
  success: boolean;
  /** Путь к собранным данным */
  location?: string;
  /** Размер данных (байты) */
  size?: number;
  /** Хэши для целостности */
  hashes: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
  /** Время сбора */
  collectedAt: Date;
  /** Кто собрал */
  collectedBy: Actor;
  /** Метод сбора */
  collectionMethod: string;
  /** Ошибки */
  errors?: string[];
  /** Метаданные */
  metadata?: Record<string, unknown>;
}

/**
 * Конфигурация сборщика форензика данных
 */
export interface ForensicsCollectorConfig {
  /** Хранилище форензика данных */
  storageLocation: string;
  /** Сжатие данных */
  compressData: boolean;
  /** Шифрование данных */
  encryptData: boolean;
  /** Ключ шифрования */
  encryptionKey?: string;
  /** Максимальный размер сбора (байты) */
  maxCollectionSize: number;
  /** Вычисляемые хэши */
  hashAlgorithms: ('md5' | 'sha1' | 'sha256')[];
  /** Сохранять оригинальные имена файлов */
  preserveFilenames: boolean;
  /** Логирование */
  enableLogging: boolean;
  /** Отладочный режим */
  debugMode: boolean;
}

/**
 * Контекст сбора форензика данных
 */
export interface ForensicsCollectionContext {
  /** Инцидент */
  incident: Incident;
  /** Типы данных для сбора */
  dataTypes: ForensicsDataType[];
  /** Целевые системы */
  targetSystems: string[];
  /** Приоритет сбора */
  priority: 'low' | 'medium' | 'high' | 'critical';
  /** Ограничения */
  constraints: {
    /** Только чтение */
    readOnly: boolean;
    /** Агенты установлены */
    agentsInstalled: boolean;
    /** Время сбора (часы) */
    timeWindow?: {
      start: string;
      end: string;
    };
  };
}

/**
 * Класс для автоматизированного сбора форензика данных
 * Реализует:
 * - Сбор различных типов форензика данных
 * - Вычисление хэшей для целостности
 * - Поддержание цепочки хранения
 * - Шифрование и сжатие данных
 */
export class ForensicsCollector extends EventEmitter {
  /** Конфигурация */
  private config: ForensicsCollectorConfig;

  /** Активные сборы */
  private activeCollections: Map<string, ForensicsCollectionContext> = new Map();

  /** Результаты сборов */
  private collectionResults: Map<string, CollectionResult[]> = new Map();

  /**
   * Конструктор сборщика
   */
  constructor(config?: Partial<ForensicsCollectorConfig>) {
    super();
    this.config = this.mergeConfigWithDefaults(config);
  }

  /**
   * Объединение конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<ForensicsCollectorConfig> | undefined): ForensicsCollectorConfig {
    const defaultConfig: ForensicsCollectorConfig = {
      storageLocation: '/var/forensics',
      compressData: true,
      encryptData: true,
      encryptionKey: undefined,
      maxCollectionSize: 10737418240, // 10 GB
      hashAlgorithms: ['md5', 'sha1', 'sha256'],
      preserveFilenames: true,
      enableLogging: true,
      debugMode: false
    };

    return { ...defaultConfig, ...config };
  }

  /**
   * Инициация сбора форензика данных
   */
  public async initiateCollection(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<string> {
    const collectionId = this.generateCollectionId();

    this.log(`Инициация сбора форензика данных. Collection ID: ${collectionId}`);
    this.log(`Типы данных: ${context.dataTypes.join(', ')}`);
    this.log(`Целевые системы: ${context.targetSystems.join(', ')}`);

    // Сохраняем контекст
    this.activeCollections.set(collectionId, context);
    this.collectionResults.set(collectionId, []);

    // Событие начала
    this.emit(ForensicsCollectorEvent.COLLECTION_STARTED, {
      collectionId,
      context,
      timestamp: new Date()
    });

    // Запускаем сбор в фоне
    this.executeCollection(collectionId, context, collectedBy).catch(error => {
      this.log(`Ошибка сбора: ${error.message}`, 'error');
      this.emit(ForensicsCollectorEvent.COLLECTION_ERROR, {
        collectionId,
        error: error.message
      });
    });

    return collectionId;
  }

  /**
   * Выполнение сбора данных
   */
  private async executeCollection(
    collectionId: string,
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<void> {
    const results: CollectionResult[] = [];

    for (const dataType of context.dataTypes) {
      try {
        this.log(`Сбор данных типа: ${dataType}`);

        const result = await this.collectDataType(dataType, context, collectedBy);
        results.push(result);

        // Событие успешного сбора
        this.emit(ForensicsCollectorEvent.DATA_COLLECTED, {
          collectionId,
          dataType,
          result
        });

        this.log(`Данные типа ${dataType} собраны. Размер: ${result.size} байт`);
      } catch (error) {
        this.log(`Ошибка сбора ${dataType}: ${error}`, 'error');

        results.push({
          dataType,
          success: false,
          hashes: {},
          collectedAt: new Date(),
          collectedBy,
          collectionMethod: 'unknown',
          errors: [(error as Error).message]
        });

        this.emit(ForensicsCollectorEvent.COLLECTION_ERROR, {
          collectionId,
          dataType,
          error: (error as Error).message
        });
      }
    }

    // Сохраняем результаты
    this.collectionResults.set(collectionId, results);

    // Событие завершения
    this.emit(ForensicsCollectorEvent.COLLECTION_COMPLETED, {
      collectionId,
      results,
      totalCollected: results.filter(r => r.success).length,
      totalFailed: results.filter(r => !r.success).length
    });

    // Удаляем из активных
    this.activeCollections.delete(collectionId);

    this.log(`Сбор форензика данных завершен. Collection ID: ${collectionId}`);
  }

  /**
   * Сбор данных конкретного типа
   */
  private async collectDataType(
    dataType: ForensicsDataType,
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    const startTime = Date.now();

    switch (dataType) {
      case ForensicsDataType.MEMORY_DUMP:
        return this.collectMemoryDump(context, collectedBy);

      case ForensicsDataType.DISK_IMAGE:
        return this.collectDiskImage(context, collectedBy);

      case ForensicsDataType.NETWORK_PACKETS:
        return this.collectNetworkPackets(context, collectedBy);

      case ForensicsDataType.SYSTEM_LOGS:
        return this.collectSystemLogs(context, collectedBy);

      case ForensicsDataType.APPLICATION_LOGS:
        return this.collectApplicationLogs(context, collectedBy);

      case ForensicsDataType.SECURITY_LOGS:
        return this.collectSecurityLogs(context, collectedBy);

      case ForensicsDataType.PROCESS_LIST:
        return this.collectProcessList(context, collectedBy);

      case ForensicsDataType.NETWORK_CONNECTIONS:
        return this.collectNetworkConnections(context, collectedBy);

      case ForensicsDataType.AUTOSTART_ENTRIES:
        return this.collectAutostartEntries(context, collectedBy);

      case ForensicsDataType.USER_SESSIONS:
        return this.collectUserSessions(context, collectedBy);

      case ForensicsDataType.COMMAND_HISTORY:
        return this.collectCommandHistory(context, collectedBy);

      case ForensicsDataType.TEMP_FILES:
        return this.collectTempFiles(context, collectedBy);

      case ForensicsDataType.FILE_METADATA:
        return this.collectFileMetadata(context, collectedBy);

      default:
        throw new Error(`Неизвестный тип данных: ${dataType}`);
    }
  }

  /**
   * Сбор дампа памяти
   */
  private async collectMemoryDump(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор дампа памяти...');

    // Симуляция сбора дампа памяти
    await this.sleep(5000);

    const location = `${this.config.storageLocation}/memory/${context.incident.id}/memory_dump.raw`;
    const size = 8589934592; // 8 GB

    return {
      dataType: ForensicsDataType.MEMORY_DUMP,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'live_memory_acquisition',
      metadata: {
        memorySize: size,
        architecture: 'x64',
        osVersion: 'Windows 10/11',
        acquisitionTool: 'WinPmem'
      }
    };
  }

  /**
   * Сбор образа диска
   */
  private async collectDiskImage(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор образа диска...');

    // Симуляция сбора образа диска
    await this.sleep(30000);

    const location = `${this.config.storageLocation}/disk/${context.incident.id}/disk_image.e01`;
    const size = 536870912000; // 500 GB

    return {
      dataType: ForensicsDataType.DISK_IMAGE,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'physical_disk_imaging',
      metadata: {
        diskSize: size,
        format: 'EnCase E01',
        compression: 'enabled',
        acquisitionTool: 'FTK Imager'
      }
    };
  }

  /**
   * Сбор сетевых пакетов
   */
  private async collectNetworkPackets(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор сетевых пакетов...');

    // Симуляция сбора
    await this.sleep(3000);

    const location = `${this.config.storageLocation}/network/${context.incident.id}/capture.pcap`;
    const size = 1073741824; // 1 GB

    return {
      dataType: ForensicsDataType.NETWORK_PACKETS,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'packet_capture',
      metadata: {
        captureDuration: '1 hour',
        interfaces: ['eth0', 'eth1'],
        filter: 'none',
        captureTool: 'tcpdump'
      }
    };
  }

  /**
   * Сбор системных логов
   */
  private async collectSystemLogs(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор системных логов...');

    // Симуляция сбора
    await this.sleep(2000);

    const location = `${this.config.storageLocation}/logs/${context.incident.id}/system_logs.zip`;
    const size = 104857600; // 100 MB

    return {
      dataType: ForensicsDataType.SYSTEM_LOGS,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'log_aggregation',
      metadata: {
        logSources: ['Windows Event Log', 'syslog', 'journald'],
        timeRange: '7 days',
        compression: 'zip',
        recordCount: 150000
      }
    };
  }

  /**
   * Сбор логов приложений
   */
  private async collectApplicationLogs(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор логов приложений...');

    // Симуляция сбора
    await this.sleep(2000);

    const location = `${this.config.storageLocation}/logs/${context.incident.id}/application_logs.zip`;
    const size = 52428800; // 50 MB

    return {
      dataType: ForensicsDataType.APPLICATION_LOGS,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'log_aggregation',
      metadata: {
        applications: ['IIS', 'Apache', 'SQL Server', 'Custom Apps'],
        timeRange: '7 days',
        compression: 'zip',
        recordCount: 75000
      }
    };
  }

  /**
   * Сбор логов безопасности
   */
  private async collectSecurityLogs(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор логов безопасности...');

    // Симуляция сбора
    await this.sleep(2000);

    const location = `${this.config.storageLocation}/logs/${context.incident.id}/security_logs.zip`;
    const size = 209715200; // 200 MB

    return {
      dataType: ForensicsDataType.SECURITY_LOGS,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'security_log_aggregation',
      metadata: {
        logSources: ['Security Event Log', 'Firewall', 'IDS/IPS', 'EDR'],
        timeRange: '30 days',
        compression: 'zip',
        recordCount: 250000
      }
    };
  }

  /**
   * Сбор списка процессов
   */
  private async collectProcessList(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор списка процессов...');

    // Симуляция сбора
    await this.sleep(1000);

    const location = `${this.config.storageLocation}/process/${context.incident.id}/process_list.json`;
    const size = 1048576; // 1 MB

    return {
      dataType: ForensicsDataType.PROCESS_LIST,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'process_enumeration',
      metadata: {
        processCount: 256,
        includesThreads: true,
        includesHandles: true,
        collectionTool: 'pslist'
      }
    };
  }

  /**
   * Сбор сетевых соединений
   */
  private async collectNetworkConnections(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор сетевых соединений...');

    // Симуляция сбора
    await this.sleep(1000);

    const location = `${this.config.storageLocation}/network/${context.incident.id}/connections.json`;
    const size = 524288; // 512 KB

    return {
      dataType: ForensicsDataType.NETWORK_CONNECTIONS,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'connection_enumeration',
      metadata: {
        connectionCount: 128,
        includesListening: true,
        includesEstablished: true,
        collectionTool: 'netstat'
      }
    };
  }

  /**
   * Сбор записей автозагрузки
   */
  private async collectAutostartEntries(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор записей автозагрузки...');

    // Симуляция сбора
    await this.sleep(1500);

    const location = `${this.config.storageLocation}/autostart/${context.incident.id}/autostart.json`;
    const size = 262144; // 256 KB

    return {
      dataType: ForensicsDataType.AUTOSTART_ENTRIES,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'autostart_enumeration',
      metadata: {
        entryCount: 85,
        sources: ['Registry', 'Startup Folder', 'Scheduled Tasks', 'Services'],
        collectionTool: 'Autoruns'
      }
    };
  }

  /**
   * Сбор пользовательских сессий
   */
  private async collectUserSessions(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор пользовательских сессий...');

    // Симуляция сбора
    await this.sleep(1000);

    const location = `${this.config.storageLocation}/sessions/${context.incident.id}/sessions.json`;
    const size = 131072; // 128 KB

    return {
      dataType: ForensicsDataType.USER_SESSIONS,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'session_enumeration',
      metadata: {
        sessionCount: 12,
        includesActive: true,
        includesHistorical: true,
        collectionTool: 'qwinsta'
      }
    };
  }

  /**
   * Сбор истории команд
   */
  private async collectCommandHistory(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор истории команд...');

    // Симуляция сбора
    await this.sleep(1500);

    const location = `${this.config.storageLocation}/commands/${context.incident.id}/command_history.txt`;
    const size = 65536; // 64 KB

    return {
      dataType: ForensicsDataType.COMMAND_HISTORY,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'history_extraction',
      metadata: {
        commandCount: 500,
        shells: ['cmd', 'PowerShell', 'bash'],
        timeRange: '30 days'
      }
    };
  }

  /**
   * Сбор временных файлов
   */
  private async collectTempFiles(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор временных файлов...');

    // Симуляция сбора
    await this.sleep(5000);

    const location = `${this.config.storageLocation}/temp/${context.incident.id}/temp_files.zip`;
    const size = 536870912; // 512 MB

    return {
      dataType: ForensicsDataType.TEMP_FILES,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'file_collection',
      metadata: {
        fileCount: 1500,
        directories: ['%TEMP%', '/tmp', '/var/tmp'],
        compression: 'zip'
      }
    };
  }

  /**
   * Сбор метаданных файлов
   */
  private async collectFileMetadata(
    context: ForensicsCollectionContext,
    collectedBy: Actor
  ): Promise<CollectionResult> {
    this.log('Сбор метаданных файлов...');

    // Симуляция сбора
    await this.sleep(3000);

    const location = `${this.config.storageLocation}/metadata/${context.incident.id}/file_metadata.json`;
    const size = 10485760; // 10 MB

    return {
      dataType: ForensicsDataType.FILE_METADATA,
      success: true,
      location,
      size,
      hashes: await this.computeHashes(location, size),
      collectedAt: new Date(),
      collectedBy,
      collectionMethod: 'metadata_extraction',
      metadata: {
        fileCount: 50000,
        attributes: ['name', 'size', 'timestamps', 'permissions', 'hashes'],
        collectionTool: 'custom'
      }
    };
  }

  /**
   * Вычисление хэшей для данных
   */
  private async computeHashes(
    location: string,
    size: number
  ): Promise<{ md5?: string; sha1?: string; sha256?: string }> {
    const hashes: { md5?: string; sha1?: string; sha256?: string } = {};

    // Симуляция вычисления хэшей
    // В реальной системе здесь было бы чтение файла и вычисление хэшей

    const hashData = `${location}:${size}:${Date.now()}`;

    for (const algorithm of this.config.hashAlgorithms) {
      const hash = createHash(algorithm);
      hash.update(hashData);
      hashes[algorithm] = hash.digest('hex');
    }

    // Событие проверки целостности
    this.emit(ForensicsCollectorEvent.INTEGRITY_VERIFIED, {
      location,
      hashes,
      timestamp: new Date()
    });

    return hashes;
  }

  /**
   * Получение результатов сбора
   */
  public getCollectionResults(collectionId: string): CollectionResult[] | undefined {
    return this.collectionResults.get(collectionId);
  }

  /**
   * Получение статуса сбора
   */
  public getCollectionStatus(collectionId: string): {
    isActive: boolean;
    progress: number;
    results?: CollectionResult[];
  } {
    const isActive = this.activeCollections.has(collectionId);
    const results = this.collectionResults.get(collectionId);

    let progress = 0;
    if (results && results.length > 0) {
      const context = this.activeCollections.get(collectionId);
      if (context) {
        progress = Math.round((results.length / context.dataTypes.length) * 100);
      } else {
        progress = 100;
      }
    }

    return {
      isActive,
      progress,
      results
    };
  }

  /**
   * Преобразование результатов в улики
   */
  public convertToEvidence(
    collectionId: string,
    incidentId: string,
    collectedBy: Actor
  ): Evidence[] {
    const results = this.collectionResults.get(collectionId);

    if (!results) {
      throw new Error(`Результаты сбора ${collectionId} не найдены`);
    }

    const evidence: Evidence[] = [];

    for (const result of results) {
      if (!result.success || !result.location) {
        continue;
      }

      const evidenceItem: Evidence = {
        id: this.generateEvidenceId(),
        type: this.mapDataTypeToEvidenceType(result.dataType),
        name: `Forensics ${result.dataType} - ${incidentId}`,
        description: `Собранные форензика данные типа ${result.dataType}`,
        category: this.mapDataTypeToCategory(result.dataType),
        location: result.location,
        size: result.size,
        hash: result.hashes,
        collectedAt: result.collectedAt,
        collectedBy,
        collectionContext: result.collectionMethod,
        incidentId,
        custodyStatus: ChainOfCustodyStatus.COLLECTED,
        custodyHistory: [],
        tags: ['forensics', result.dataType, incidentId]
      };

      evidence.push(evidenceItem);
    }

    return evidence;
  }

  /**
   * Маппинг типа данных на тип улики
   */
  private mapDataTypeToEvidenceType(dataType: ForensicsDataType): string {
    const mapping: Record<ForensicsDataType, string> = {
      [ForensicsDataType.MEMORY_DUMP]: 'memory_dump',
      [ForensicsDataType.DISK_IMAGE]: 'disk_image',
      [ForensicsDataType.NETWORK_PACKETS]: 'network_capture',
      [ForensicsDataType.SYSTEM_LOGS]: 'log_file',
      [ForensicsDataType.APPLICATION_LOGS]: 'log_file',
      [ForensicsDataType.SECURITY_LOGS]: 'log_file',
      [ForensicsDataType.PROCESS_LIST]: 'digital_file',
      [ForensicsDataType.NETWORK_CONNECTIONS]: 'digital_file',
      [ForensicsDataType.AUTOSTART_ENTRIES]: 'digital_file',
      [ForensicsDataType.USER_SESSIONS]: 'digital_file',
      [ForensicsDataType.COMMAND_HISTORY]: 'digital_file',
      [ForensicsDataType.TEMP_FILES]: 'digital_file',
      [ForensicsDataType.FILE_METADATA]: 'digital_file'
    };

    return mapping[dataType] || 'digital_file';
  }

  /**
   * Маппинг типа данных на категорию улики
   */
  private mapDataTypeToCategory(dataType: ForensicsDataType): EvidenceCategory {
    const mapping: Record<ForensicsDataType, EvidenceCategory> = {
      [ForensicsDataType.MEMORY_DUMP]: EvidenceCategory.MEMORY_DUMP,
      [ForensicsDataType.DISK_IMAGE]: EvidenceCategory.DISK_IMAGE,
      [ForensicsDataType.NETWORK_PACKETS]: EvidenceCategory.NETWORK_CAPTURE,
      [ForensicsDataType.SYSTEM_LOGS]: EvidenceCategory.LOG_FILE,
      [ForensicsDataType.APPLICATION_LOGS]: EvidenceCategory.LOG_FILE,
      [ForensicsDataType.SECURITY_LOGS]: EvidenceCategory.LOG_FILE,
      [ForensicsDataType.PROCESS_LIST]: EvidenceCategory.DIGITAL_FILE,
      [ForensicsDataType.NETWORK_CONNECTIONS]: EvidenceCategory.DIGITAL_FILE,
      [ForensicsDataType.AUTOSTART_ENTRIES]: EvidenceCategory.DIGITAL_FILE,
      [ForensicsDataType.USER_SESSIONS]: EvidenceCategory.DIGITAL_FILE,
      [ForensicsDataType.COMMAND_HISTORY]: EvidenceCategory.DIGITAL_FILE,
      [ForensicsDataType.TEMP_FILES]: EvidenceCategory.DIGITAL_FILE,
      [ForensicsDataType.FILE_METADATA]: EvidenceCategory.DIGITAL_FILE
    };

    return mapping[dataType] || EvidenceCategory.DIGITAL_FILE;
  }

  /**
   * Генерация идентификатора сбора
   */
  private generateCollectionId(): string {
    return `fc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Генерация идентификатора улики
   */
  private generateEvidenceId(): string {
    return `evd_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Утилита для задержки
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Логирование
   */
  private log(message: string, level: 'info' | 'warn' | 'error' = 'info'): void {
    if (this.config.enableLogging) {
      const timestamp = new Date().toISOString();
      const prefix = `[ForensicsCollector] [${timestamp}] [${level.toUpperCase()}]`;
      console.log(`${prefix} ${message}`);
    }
  }

  /**
   * Проверка целостности собранных данных
   */
  public async verifyIntegrity(
    collectionId: string
  ): Promise<{ valid: boolean; violations: string[] }> {
    const results = this.collectionResults.get(collectionId);
    const violations: string[] = [];

    if (!results) {
      return { valid: false, violations: ['Результаты сбора не найдены'] };
    }

    for (const result of results) {
      if (!result.success || !result.location) {
        continue;
      }

      // В реальной системе здесь было бы повторное вычисление хэшей
      // и сравнение с оригинальными значениями

      this.log(`Проверка целостности: ${result.location}`);

      // Симуляция проверки
      const isValid = true;

      if (!isValid) {
        violations.push(`Нарушение целостности: ${result.location}`);
        this.emit(ForensicsCollectorEvent.INTEGRITY_VIOLATED, {
          location: result.location,
          expectedHashes: result.hashes,
          timestamp: new Date()
        });
      }
    }

    return {
      valid: violations.length === 0,
      violations
    };
  }

  /**
   * Экспорт результатов в формат для отчета
   */
  public exportResults(collectionId: string): Record<string, unknown> {
    const results = this.collectionResults.get(collectionId);
    const context = this.activeCollections.get(collectionId);

    return {
      collectionId,
      status: context ? 'in_progress' : 'completed',
      context: context || null,
      results: results || [],
      summary: {
        totalTypes: context?.dataTypes.length || results?.length || 0,
        successful: results?.filter(r => r.success).length || 0,
        failed: results?.filter(r => !r.success).length || 0,
        totalSize: results?.filter(r => r.success).reduce((sum, r) => sum + (r.size || 0), 0) || 0
      },
      exportedAt: new Date()
    };
  }
}

/**
 * Экспорт событий сборщика
 */
export { ForensicsCollectorEvent };
