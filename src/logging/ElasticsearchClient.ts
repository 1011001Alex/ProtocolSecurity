/**
 * ============================================================================
 * ELASTICSEARCH CLIENT - ИНТЕГРАЦИЯ С ELASTICSEARCH
 * ============================================================================
 * Клиент для работы с Elasticsearch с поддержкой bulk indexing,
 * ILM policies, index templates, и advanced search queries.
 * 
 * Особенности:
 * - Bulk indexing с batching
 * - Index Lifecycle Management (ILM)
 * - Index templates
 * - Advanced search queries
 * - Aggregations
 * - Scroll API для больших результатов
 * - Point-in-time API
 * - Alias management
 */

import * as crypto from 'crypto';
import { EventEmitter } from 'events';
import {
  LogEntry,
  ElasticsearchConfig,
  ElasticsearchSearchResult,
  ElasticsearchHit,
  SearchQuery,
  ILMPolicy,
  ProcessingError
} from '../types/logging.types';

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/**
 * Default настройки bulk indexing
 */
const DEFAULT_BULK_SETTINGS = {
  flushBytes: 5 * 1024 * 1024, // 5MB
  flushInterval: 5000, // 5 seconds
  concurrency: 3
};

/**
 * Default timeout (мс)
 */
const DEFAULT_TIMEOUT = {
  request: 30000,
  ping: 5000
};

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Результат bulk операции
 */
interface BulkResult {
  /** Всего операций */
  total: number;
  /** Успешные */
  successful: number;
  /** Неудачные */
  failed: number;
  /** Ошибки */
  errors: Array<{
    id: string;
    error: string;
  }>;
  /** Время выполнения (мс) */
  took: number;
}

/**
 * Статистика клиента
 */
interface ClientStatistics {
  /** Всего индексировано документов */
  totalIndexed: number;
  /** Всего поисковых запросов */
  totalSearches: number;
  /** Успешные операции */
  successfulOperations: number;
  /** Неудачные операции */
  failedOperations: number;
  /** Bulk операций */
  bulkOperations: number;
  /** Среднее время индексирования (мс) */
  avgIndexTime: number;
  /** P99 время индексирования (мс) */
  p99IndexTime: number;
  /** Среднее время поиска (мс) */
  avgSearchTime: number;
  /** P99 время поиска (мс) */
  p99SearchTime: number;
  /** Размер bulk очереди */
  bulkQueueSize: number;
  /** Последнее подключение */
  lastConnection: string | null;
  /** Статус подключения */
  connectionStatus: 'connected' | 'disconnected' | 'connecting';
}

/**
 * Конфигурация retry
 */
interface RetryConfig {
  maxRetries: number;
  initialDelay: number;
  maxDelay: number;
  factor: number;
}

// ============================================================================
// КЛАСС BULK INDEXER
// ============================================================================

/**
 * Bulk indexer для эффективной пакетной записи
 */
class BulkIndexer {
  private buffer: Array<{ action: object; body?: object }>;
  private bufferSize: number;
  private flushInterval: number;
  private concurrency: number;
  private flushTimer: NodeJS.Timeout | null;
  private isFlushing: boolean;
  private client: ElasticsearchClient;
  
  constructor(
    client: ElasticsearchClient,
    flushBytes: number,
    flushInterval: number,
    concurrency: number
  ) {
    this.client = client;
    this.buffer = [];
    this.bufferSize = flushBytes;
    this.flushInterval = flushInterval;
    this.concurrency = concurrency;
    this.flushTimer = null;
    this.isFlushing = false;
    
    this.startFlushTimer();
  }
  
  /**
   * Добавление документа в буфер
   */
  add(index: string, id: string, document: object): void {
    this.buffer.push(
      { action: { index: { _index: index, _id: id } } },
      { body: document }
    );
    
    // Проверка размера буфера
    const bufferBytes = JSON.stringify(this.buffer).length;
    if (bufferBytes >= this.bufferSize) {
      this.flush();
    }
  }
  
  /**
   * Принудительная отправка буфера
   */
  async flush(): Promise<BulkResult> {
    if (this.isFlushing || this.buffer.length === 0) {
      return { total: 0, successful: 0, failed: 0, errors: [], took: 0 };
    }
    
    this.isFlushing = true;
    
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
    }
    
    try {
      const result = await this.client.bulk(this.buffer);
      this.buffer = [];
      
      return result;
    } catch (error) {
      throw error;
    } finally {
      this.isFlushing = false;
      this.startFlushTimer();
    }
  }
  
  /**
   * Запуск таймера flush
   */
  private startFlushTimer(): void {
    this.flushTimer = setTimeout(() => {
      this.flush();
    }, this.flushInterval);
  }
  
  /**
   * Закрытие indexer
   */
  async close(): Promise<void> {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
    }
    await this.flush();
  }
  
  /**
   * Получение размера буфера
   */
  size(): number {
    return this.buffer.length;
  }
}

// ============================================================================
// КЛАСС QUERY BUILDER
// ============================================================================

/**
 * Builder для Elasticsearch queries
 */
class QueryBuilder {
  private query: Record<string, unknown> = {};
  
  /**
   * Match query
   */
  match(field: string, value: string, options?: { operator?: 'and' | 'or'; fuzziness?: string }): QueryBuilder {
    this.query.match = {
      [field]: {
        query: value,
        operator: options?.operator || 'or',
        fuzziness: options?.fuzziness
      }
    };
    return this;
  }
  
  /**
   * Multi-match query
   */
  multiMatch(query: string, fields: string[]): QueryBuilder {
    this.query.multi_match = {
      query,
      fields
    };
    return this;
  }
  
  /**
   * Term query
   */
  term(field: string, value: unknown): QueryBuilder {
    this.query.term = { [field]: value };
    return this;
  }
  
  /**
   * Terms query
   */
  terms(field: string, values: unknown[]): QueryBuilder {
    this.query.terms = { [field]: values };
    return this;
  }
  
  /**
   * Range query
   */
  range(field: string, options: { gte?: unknown; lte?: unknown; gt?: unknown; lt?: unknown }): QueryBuilder {
    this.query.range = {
      [field]: options
    };
    return this;
  }
  
  /**
   * Exists query
   */
  exists(field: string): QueryBuilder {
    this.query.exists = { field };
    return this;
  }
  
  /**
   * Bool query
   */
  bool(options: {
    must?: Record<string, unknown>[];
    should?: Record<string, unknown>[];
    must_not?: Record<string, unknown>[];
    filter?: Record<string, unknown>[];
  }): QueryBuilder {
    this.query.bool = options;
    return this;
  }
  
  /**
   * Wildcard query
   */
  wildcard(field: string, value: string): QueryBuilder {
    this.query.wildcard = {
      [field]: {
        value,
        case_insensitive: true
      }
    };
    return this;
  }
  
  /**
   * Regexp query
   */
  regexp(field: string, pattern: string): QueryBuilder {
    this.query.regexp = { [field]: { value: pattern } };
    return this;
  }
  
  /**
   * Prefix query
   */
  prefix(field: string, value: string): QueryBuilder {
    this.query.prefix = { [field]: { value } };
    return this;
  }
  
  /**
   * Nested query
   */
  nested(path: string, query: Record<string, unknown>): QueryBuilder {
    this.query.nested = { path, query };
    return this;
  }
  
  /**
   * Добавление sort
   */
  sort(field: string, order: 'asc' | 'desc' = 'asc'): QueryBuilder {
    if (!this.query.sort) {
      this.query.sort = [];
    }
    (this.query.sort as Array<unknown>).push({ [field]: order });
    return this;
  }
  
  /**
   * Добавление aggregation
   */
  aggregation(name: string, agg: Record<string, unknown>): QueryBuilder {
    if (!this.query.aggs) {
      this.query.aggs = {};
    }
    (this.query.aggs as Record<string, unknown>)[name] = agg;
    return this;
  }
  
  /**
   * Построение финального query
   */
  build(): Record<string, unknown> {
    return { query: this.query };
  }
  
  /**
   * Сброс query
   */
  reset(): QueryBuilder {
    this.query = {};
    return this;
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС ELASTICSEARCH CLIENT
// ============================================================================

/**
 * Elasticsearch Client
 * 
 * Реализует:
 * - Bulk indexing
 * - ILM policies
 * - Index templates
 * - Advanced search
 * - Aggregations
 */
export class ElasticsearchClient extends EventEmitter {
  private config: ElasticsearchConfig;
  private bulkIndexer: BulkIndexer | null;
  private queryBuilder: QueryBuilder;
  private connected: boolean;
  private statistics: ClientStatistics;
  private indexTimes: number[];
  private searchTimes: number[];
  private retryConfig: RetryConfig;
  
  constructor(config: ElasticsearchConfig) {
    super();
    
    this.config = {
      nodes: config.nodes || ['http://localhost:9200'],
      apiKey: config.apiKey,
      auth: config.auth,
      tls: config.tls,
      logIndex: config.logIndex || 'logs',
      indexTemplate: config.indexTemplate || 'logs-template',
      ilmPolicy: config.ilmPolicy || this.createDefaultILMPolicy(),
      bulkIndexing: config.bulkIndexing || DEFAULT_BULK_SETTINGS,
      timeouts: config.timeouts || DEFAULT_TIMEOUT
    };
    
    this.bulkIndexer = null;
    this.queryBuilder = new QueryBuilder();
    this.connected = false;
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.indexTimes = [];
    this.searchTimes = [];
    
    // Retry конфигурация
    this.retryConfig = {
      maxRetries: 3,
      initialDelay: 1000,
      maxDelay: 30000,
      factor: 2
    };
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): ClientStatistics {
    return {
      totalIndexed: 0,
      totalSearches: 0,
      successfulOperations: 0,
      failedOperations: 0,
      bulkOperations: 0,
      avgIndexTime: 0,
      p99IndexTime: 0,
      avgSearchTime: 0,
      p99SearchTime: 0,
      bulkQueueSize: 0,
      lastConnection: null,
      connectionStatus: 'disconnected'
    };
  }
  
  /**
   * Создание default ILM policy
   */
  private createDefaultILMPolicy(): ILMPolicy {
    return {
      name: 'logs-policy',
      hot: {
        priority: 100,
        rollover: {
          maxSize: '50gb',
          maxAge: '7d'
        }
      },
      warm: {
        minAge: '7d',
        priority: 50,
        forceMerge: {
          maxNumSegments: 1
        }
      },
      cold: {
        minAge: '30d',
        priority: 0
      },
      frozen: {
        minAge: '90d'
      },
      delete: {
        minAge: '365d'
      }
    };
  }
  
  /**
   * Подключение к Elasticsearch
   */
  async connect(): Promise<void> {
    this.statistics.connectionStatus = 'connecting';
    
    try {
      // В production использовать официальный клиент @elastic/elasticsearch
      // const { Client } = require('@elastic/elasticsearch');
      // this.client = new Client({
      //   nodes: this.config.nodes,
      //   auth: this.config.auth,
      //   tls: this.config.tls
      // });
      
      // Проверка подключения через ping
      await this.ping();
      
      this.connected = true;
      this.statistics.connectionStatus = 'connected';
      this.statistics.lastConnection = new Date().toISOString();
      
      // Создание index template
      await this.createIndexTemplate();
      
      // Создание ILM policy
      await this.createILMPolicy();
      
      // Создание bulk indexer
      this.bulkIndexer = new BulkIndexer(
        this,
        this.config.bulkIndexing.flushBytes,
        this.config.bulkIndexing.flushInterval,
        this.config.bulkIndexing.concurrency
      );
      
      this.emit('connected');
    } catch (error) {
      this.statistics.connectionStatus = 'disconnected';
      this.emit('connection_error', { error });
      throw error;
    }
  }
  
  /**
   * Ping сервера
   */
  async ping(): Promise<boolean> {
    try {
      // В production: await this.client.ping();
      await this.sleep(10); // Эмуляция
      return true;
    } catch {
      return false;
    }
  }
  
  /**
   * Создание index template
   */
  async createIndexTemplate(): Promise<void> {
    const template = {
      index_patterns: [`${this.config.logIndex}-*`],
      template: {
        settings: {
          index: {
            lifecycle: {
              name: this.config.ilmPolicy.name,
              rollover_alias: this.config.logIndex
            },
            number_of_shards: 3,
            number_of_replicas: 1
          }
        },
        mappings: {
          properties: {
            timestamp: { type: 'date' },
            level: { type: 'integer' },
            source: { type: 'keyword' },
            component: { type: 'keyword' },
            hostname: { type: 'keyword' },
            processId: { type: 'integer' },
            message: { type: 'text', analyzer: 'standard' },
            context: {
              properties: {
                userId: { type: 'keyword' },
                clientIp: { type: 'ip' },
                sessionId: { type: 'keyword' },
                requestId: { type: 'keyword' },
                userAgent: { type: 'text' },
                geoLocation: {
                  properties: {
                    country: { type: 'keyword' },
                    city: { type: 'keyword' },
                    latitude: { type: 'float' },
                    longitude: { type: 'float' }
                  }
                }
              }
            },
            fields: { type: 'object', enabled: true }
          }
        }
      }
    };
    
    // В production: await this.client.indices.putTemplate({ name: this.config.indexTemplate, body: template });
    this.emit('template_created', { name: this.config.indexTemplate });
  }
  
  /**
   * Создание ILM policy
   */
  async createILMPolicy(): Promise<void> {
    const policy = {
      policy: {
        phases: {
          hot: {
            min_age: '0ms',
            actions: {
              rollover: this.config.ilmPolicy.hot.rollover,
              set_priority: { priority: this.config.ilmPolicy.hot.priority }
            }
          },
          warm: {
            min_age: this.config.ilmPolicy.warm.minAge,
            actions: {
              set_priority: { priority: this.config.ilmPolicy.warm.priority },
              forcemerge: this.config.ilmPolicy.warm.forceMerge
            }
          },
          cold: {
            min_age: this.config.ilmPolicy.cold.minAge,
            actions: {
              set_priority: { priority: this.config.ilmPolicy.cold.priority }
            }
          },
          frozen: {
            min_age: this.config.ilmPolicy.frozen.minAge,
            actions: {
              searchable_snapshot: {
                snapshot_repository: 'snapshots'
              }
            }
          },
          delete: {
            min_age: this.config.ilmPolicy.delete.minAge,
            actions: {
              delete: {}
            }
          }
        }
      }
    };
    
    // В production: await this.client.ilm.putLifecycle({ name: this.config.ilmPolicy.name, body: policy });
    this.emit('ilm_policy_created', { name: this.config.ilmPolicy.name });
  }
  
  /**
   * Индексирование лога
   */
  async index(log: LogEntry): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const index = this.getIndexName(log.timestamp);
      
      if (this.bulkIndexer) {
        this.bulkIndexer.add(index, log.id, log);
      } else {
        // Прямая индексация без bulk
        await this.doIndex(index, log.id, log);
      }
      
      this.statistics.totalIndexed++;
      this.statistics.successfulOperations++;
      
      const indexTime = Date.now() - startTime;
      this.updateIndexTimeStats(indexTime);
      
      return true;
    } catch (error) {
      this.statistics.failedOperations++;
      this.emit('index_error', { logId: log.id, error });
      return false;
    }
  }
  
  /**
   * Пакетное индексирование
   */
  async indexBatch(logs: LogEntry[]): Promise<BulkResult> {
    const startTime = Date.now();
    
    try {
      const actions: Array<{ action: object; body?: object }> = [];
      
      for (const log of logs) {
        const index = this.getIndexName(log.timestamp);
        actions.push(
          { action: { index: { _index: index, _id: log.id } } },
          { body: log }
        );
      }
      
      const result = await this.bulk(actions);
      
      this.statistics.totalIndexed += result.successful;
      this.statistics.bulkOperations++;
      
      const indexTime = Date.now() - startTime;
      this.updateIndexTimeStats(indexTime);
      
      return result;
    } catch (error) {
      this.statistics.failedOperations++;
      throw error;
    }
  }
  
  /**
   * Выполнение bulk операции
   */
  async bulk(actions: Array<{ action: object; body?: object }>): Promise<BulkResult> {
    // В production: const result = await this.client.bulk({ body: actions });
    
    // Эмуляция
    await this.sleep(50);
    
    return {
      total: actions.length / 2,
      successful: Math.floor(actions.length / 2),
      failed: 0,
      errors: [],
      took: 50
    };
  }
  
  /**
   * Прямая индексация
   */
  private async doIndex(index: string, id: string, document: object): Promise<void> {
    // В production: await this.client.index({ index, id, body: document });
    await this.sleep(10);
  }
  
  /**
   * Поиск
   */
  async search(query: SearchQuery): Promise<ElasticsearchSearchResult> {
    const startTime = Date.now();
    this.statistics.totalSearches++;
    
    try {
      // В production: const result = await this.client.search({
      //   index: query.indices.join(','),
      //   body: {
      //     query: query.query,
      //     filter: query.filters,
      //     aggregations: query.aggregations,
      //     sort: query.sort,
      //     from: query.from,
      //     size: query.size,
      //     _source: query.source,
      //     highlight: query.highlight
      //   },
      //   timeout: query.timeout
      // });
      
      // Эмуляция
      await this.sleep(100);
      
      const result: ElasticsearchSearchResult = {
        total: 0,
        maxScore: 0,
        hits: [],
        took: 100,
        timedOut: false
      };
      
      this.statistics.successfulOperations++;
      
      const searchTime = Date.now() - startTime;
      this.updateSearchTimeStats(searchTime);
      
      return result;
    } catch (error) {
      this.statistics.failedOperations++;
      throw error;
    }
  }
  
  /**
   * Поиск с query builder
   */
  async searchWithBuilder(
    indices: string[],
    builderFn: (builder: QueryBuilder) => void,
    options?: { size?: number; from?: number }
  ): Promise<ElasticsearchSearchResult> {
    const builder = new QueryBuilder();
    builderFn(builder);
    
    const query: SearchQuery = {
      indices,
      query: builder.build().query || {},
      size: options?.size || 100,
      from: options?.from || 0
    };
    
    return this.search(query);
  }
  
  /**
   * Scroll поиск для больших результатов
   */
  async searchScroll(
    query: SearchQuery,
    scrollTime: string = '5m'
  ): Promise<ScrollResult> {
    // В production использовать scroll API
    // const result = await this.client.search({ scroll: scrollTime, ... });
    // while (result.hits.length > 0) { ... }
    
    return {
      hits: [],
      scrollId: crypto.randomUUID(),
      total: 0
    };
  }
  
  /**
   * Point-in-time поиск
   */
  async searchPit(
    indices: string[],
    builderFn: (builder: QueryBuilder) => void,
    keepAlive: string = '5m'
  ): Promise<ElasticsearchSearchResult> {
    // В production использовать PIT API
    // const pit = await this.client.openPointInTime({ index: indices.join(','), keep_alive: keepAlive });
    // ... search with pit id
    // await this.client.closePointInTime({ id: pit.id });
    
    return this.searchWithBuilder(indices, builderFn);
  }
  
  /**
   * Агрегации
   */
  async aggregate(
    indices: string[],
    aggregations: Record<string, unknown>,
    query?: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const searchQuery: SearchQuery = {
      indices,
      query: query || { match_all: {} },
      aggregations,
      size: 0
    };
    
    const result = await this.search(searchQuery);
    return result.aggregations || {};
  }
  
  /**
   * Получение документа по ID
   */
  async get(index: string, id: string): Promise<LogEntry | null> {
    try {
      // В production: const result = await this.client.get({ index, id });
      // return result._source;
      return null;
    } catch {
      return null;
    }
  }
  
  /**
   * Удаление документа
   */
  async delete(index: string, id: string): Promise<boolean> {
    try {
      // В production: await this.client.delete({ index, id });
      return true;
    } catch {
      return false;
    }
  }
  
  /**
   * Обновление документа
   */
  async update(index: string, id: string, doc: Partial<LogEntry>): Promise<boolean> {
    try {
      // В production: await this.client.update({ index, id, body: { doc } });
      return true;
    } catch {
      return false;
    }
  }
  
  /**
   * Alias management - создание alias
   */
  async createAlias(alias: string, indices: string[]): Promise<void> {
    // В production: await this.client.indices.updateAliases({
    //   body: {
    //     actions: indices.map(index => ({ add: { index, alias } }))
    //   }
    // });
    this.emit('alias_created', { alias, indices });
  }
  
  /**
   * Alias management - удаление alias
   */
  async deleteAlias(alias: string, indices: string[]): Promise<void> {
    // В production: await this.client.indices.updateAliases({
    //   body: {
    //     actions: indices.map(index => ({ remove: { index, alias } }))
    //   }
    // });
    this.emit('alias_deleted', { alias, indices });
  }
  
  /**
   * Получение статистики индекса
   */
  async getIndexStats(indices: string[]): Promise<Record<string, unknown>> {
    // В production: const result = await this.client.indices.stats({ index: indices.join(',') });
    // return result;
    return {};
  }
  
  /**
   * Получение health кластера
   */
  async getClusterHealth(): Promise<{ status: string; nodes: number; shards: object }> {
    // В production: const result = await this.client.cluster.health();
    // return result;
    return {
      status: 'green',
      nodes: 1,
      shards: { total: 0, successful: 0, failed: 0 }
    };
  }
  
  /**
   * Получение имени индекса для даты
   */
  private getIndexName(timestamp: string): string {
    const date = new Date(timestamp);
    const dateStr = date.toISOString().split('T')[0].replace(/-/g, '.');
    return `${this.config.logIndex}-${dateStr}`;
  }
  
  /**
   * Обновление статистики времени индексирования
   */
  private updateIndexTimeStats(time: number): void {
    this.indexTimes.push(time);
    
    if (this.indexTimes.length > 1000) {
      this.indexTimes.shift();
    }
    
    this.statistics.avgIndexTime = 
      this.indexTimes.reduce((a, b) => a + b, 0) / this.indexTimes.length;
    
    const sorted = [...this.indexTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99IndexTime = sorted[p99Index] || 0;
  }
  
  /**
   * Обновление статистики времени поиска
   */
  private updateSearchTimeStats(time: number): void {
    this.searchTimes.push(time);
    
    if (this.searchTimes.length > 1000) {
      this.searchTimes.shift();
    }
    
    this.statistics.avgSearchTime = 
      this.searchTimes.reduce((a, b) => a + b, 0) / this.searchTimes.length;
    
    const sorted = [...this.searchTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99SearchTime = sorted[p99Index] || 0;
  }
  
  /**
   * Получение статистики
   */
  getStatistics(): ClientStatistics {
    return {
      ...this.statistics,
      bulkQueueSize: this.bulkIndexer?.size() || 0
    };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
    this.indexTimes = [];
    this.searchTimes = [];
  }
  
  /**
   * Закрытие клиента
   */
  async close(): Promise<void> {
    if (this.bulkIndexer) {
      await this.bulkIndexer.close();
      this.bulkIndexer = null;
    }
    
    this.connected = false;
    this.statistics.connectionStatus = 'disconnected';
    
    this.emit('closed');
  }
  
  /**
   * Проверка подключения
   */
  isConnected(): boolean {
    return this.connected;
  }
  
  /**
   * Получение query builder
   */
  getQueryBuilder(): QueryBuilder {
    return this.queryBuilder;
  }
  
  /**
   * Sleep helper
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Результат scroll поиска
 */
interface ScrollResult {
  hits: ElasticsearchHit[];
  scrollId: string;
  total: number;
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default ElasticsearchClient;
