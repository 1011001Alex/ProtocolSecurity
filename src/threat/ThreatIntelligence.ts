/**
 * ============================================================================
 * THREAT INTELLIGENCE SERVICE
 * Интеграция с STIX/TAXII для обмена threat intelligence данными
 * ============================================================================
 */

import axios, { AxiosInstance, AxiosResponse } from 'axios';
import {
  StixIndicator,
  StixThreatActor,
  StixMalware,
  StixType,
  IndicatorPatternType,
  TaxiiServerConfig,
  ThreatFeed,
  ThreatSeverity,
  KillChainPhase,
  SecurityEvent,
  SecurityAlert
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * ============================================================================
 * STIX 2.1 OBJECTS
 * Реализация основных объектов STIX 2.1
 * ============================================================================
 */

/**
 * Базовый STIX объект
 */
interface StixBaseObject {
  id: string;
  type: string;
  spec_version: string;
  created: string;
  modified: string;
  created_by_ref?: string;
  external_references?: StixExternalRef[];
  labels?: string[];
  confidence?: number;
  description?: string;
  name?: string;
}

/**
 * STIX External Reference
 */
interface StixExternalRef {
  source_name: string;
  description?: string;
  url?: string;
  external_id?: string;
}

/**
 * STIX Indicator объект
 */
interface StixIndicatorObject extends StixBaseObject {
  type: 'indicator';
  pattern: string;
  pattern_type: string;
  pattern_version?: string;
  valid_from: string;
  valid_until?: string;
  kill_chain_phases?: KillChainPhaseRef[];
}

/**
 * STIX Threat-Actor объект
 */
interface StixThreatActorObject extends StixBaseObject {
  type: 'threat-actor';
  actor_types?: string[];
  goals?: string[];
  sophistication?: string;
  resource_level?: string;
  primary_motivation?: string;
  secondary_motivations?: string[];
}

/**
 * STIX Malware объект
 */
interface StixMalwareObject extends StixBaseObject {
  type: 'malware';
  malware_types?: string[];
  is_family: boolean;
  aliases?: string[];
  first_seen?: string;
  last_seen?: string;
  operating_system_refs?: string[];
  architecture_execution_envs?: string[];
  implementation_languages?: string[];
  capabilities?: string[];
}

/**
 * STIX Attack-Pattern объект
 */
interface StixAttackPatternObject extends StixBaseObject {
  type: 'attack-pattern';
  aliases?: string[];
  kill_chain_phases?: KillChainPhaseRef[];
}

/**
 * STIX Kill Chain Phase Reference
 */
interface KillChainPhaseRef {
  kill_chain_name: string;
  phase_name: string;
}

/**
 * TAXII Collection
 */
interface TaxiiCollection {
  id: string;
  title: string;
  description: string;
  can_read: boolean;
  can_write: boolean;
  media_types: string[];
}

/**
 * TAXII Api Root
 */
interface TaxiiApiRoot {
  id: string;
  title: string;
  description: string;
  url: string;
  versions: string[];
}

/**
 * TAXII Discovery Response
 */
interface TaxiiDiscoveryResponse {
  title: string;
  description: string;
  api_roots: string[];
}

/**
 * ============================================================================
 * THREAT INTELLIGENCE SERVICE
 * ============================================================================
 */
export class ThreatIntelligenceService {
  private axiosInstances: Map<string, AxiosInstance> = new Map();
  private feeds: Map<string, ThreatFeed> = new Map();
  private indicators: Map<string, StixIndicator> = new Map();
  private threatActors: Map<string, StixThreatActor> = new Map();
  private malware: Map<string, StixMalware> = new Map();
  private attackPatterns: Map<string, StixAttackPattern> = new Map();
  
  // Кэш для быстрого поиска
  private indicatorCache: Map<string, StixIndicator[]> = new Map();
  private lastSyncTime: Map<string, Date> = new Map();
  
  // Конфигурация
  private pollingInterval: number = 15 * 60 * 1000;  // 15 минут
  private indicatorExpiration: number = 30;  // Дней
  private minConfidence: number = 50;  // Минимальная уверенность (0-100)
  
  // Статистика
  private statistics: ThreatIntelStatistics = {
    totalIndicators: 0,
    totalThreatActors: 0,
    totalMalware: 0,
    totalFeeds: 0,
    lastSyncTime: undefined,
    syncErrors: 0,
    indicatorsMatched: 0
  };

  constructor() {
    console.log('[ThreatIntelligence] Инициализация сервиса');
  }

  // ============================================================================
  // УПРАВЛЕНИЕ FEEDS
  // ============================================================================

  /**
   * Добавление threat feed
   */
  addFeed(feed: ThreatFeed): void {
    this.feeds.set(feed.id, feed);
    this.statistics.totalFeeds++;
    
    console.log(`[ThreatIntelligence] Добавлен feed: ${feed.name} (${feed.type})`);
    
    // Создание axios instance для TAXII серверов
    if (feed.type === 'stix-taxii' && 'config' in feed) {
      const taxiiConfig = feed.config as TaxiiServerConfig;
      this.createTaxiiClient(feed.id, taxiiConfig);
    }
  }

  /**
   * Удаление feed
   */
  removeFeed(feedId: string): void {
    this.feeds.delete(feedId);
    this.axiosInstances.delete(feedId);
    this.statistics.totalFeeds--;
    
    console.log(`[ThreatIntelligence] Удален feed: ${feedId}`);
  }

  /**
   * Получение всех feeds
   */
  getFeeds(): ThreatFeed[] {
    return Array.from(this.feeds.values());
  }

  /**
   * Обновление статуса feed
   */
  updateFeedStatus(feedId: string, status: Partial<ThreatFeed>): void {
    const feed = this.feeds.get(feedId);
    
    if (feed) {
      Object.assign(feed, status);
      this.feeds.set(feedId, feed);
    }
  }

  // ============================================================================
  // TAXII CLIENT
  // ============================================================================

  /**
   * Создание TAXII клиента
   */
  private createTaxiiClient(feedId: string, config: TaxiiServerConfig): void {
    const axiosConfig: any = {
      baseURL: config.url,
      timeout: 30000,
      headers: {
        'Accept': 'application/taxii+json;version=2.1',
        'Content-Type': 'application/taxii+json;version=2.1'
      }
    };
    
    // Аутентификация
    if (config.token) {
      axiosConfig.headers['Authorization'] = `Token ${config.token}`;
    } else if (config.username && config.password) {
      axiosConfig.auth = {
        username: config.username,
        password: config.password
      };
    }
    
    const instance = axios.create(axiosConfig);
    this.axiosInstances.set(feedId, instance);
    
    console.log(`[ThreatIntelligence] TAXII клиент создан для ${feedId}`);
  }

  /**
   * TAXII Discovery запрос
   */
  async discoverApiRoots(feedId: string): Promise<TaxiiApiRoot[]> {
    const client = this.axiosInstances.get(feedId);
    
    if (!client) {
      throw new Error(`TAXII клиент не найден для feed: ${feedId}`);
    }
    
    try {
      const response: AxiosResponse<TaxiiDiscoveryResponse> = await client.get('/taxii2/');
      
      const apiRoots: TaxiiApiRoot[] = [];
      
      for (const url of response.data.api_roots) {
        const rootResponse = await client.get(url);
        apiRoots.push(rootResponse.data);
      }
      
      return apiRoots;
    } catch (error) {
      console.error(`[ThreatIntelligence] Ошибка discovery для ${feedId}:`, error);
      this.statistics.syncErrors++;
      throw error;
    }
  }

  /**
   * Получение коллекций из TAXII
   */
  async getCollections(feedId: string, apiRoot: string): Promise<TaxiiCollection[]> {
    const client = this.axiosInstances.get(feedId);
    
    if (!client) {
      throw new Error(`TAXII клиент не найден для feed: ${feedId}`);
    }
    
    try {
      const response: AxiosResponse<{ collections: TaxiiCollection[] }> = 
        await client.get(`${apiRoot}/collections/`);
      
      return response.data.collections;
    } catch (error) {
      console.error(`[ThreatIntelligence] Ошибка получения коллекций для ${feedId}:`, error);
      this.statistics.syncErrors++;
      throw error;
    }
  }

  /**
   * Получение объектов из коллекции TAXII
   */
  async getObjectsFromCollection(
    feedId: string,
    collectionId: string,
    apiRoot: string,
    options?: {
      added_after?: Date;
      type?: string;
      limit?: number;
    }
  ): Promise<StixBaseObject[]> {
    const client = this.axiosInstances.get(feedId);
    
    if (!client) {
      throw new Error(`TAXII клиент не найден для feed: ${feedId}`);
    }
    
    try {
      const params: any = {};
      
      if (options?.added_after) {
        params.added_after = options.added_after.toISOString();
      }
      
      if (options?.type) {
        params.type = options.type;
      }
      
      if (options?.limit) {
        params.limit = options.limit;
      }
      
      const response: AxiosResponse<{ objects: StixBaseObject[] }> = 
        await client.get(`${apiRoot}/collections/${collectionId}/objects/`, { params });
      
      return response.data.objects;
    } catch (error) {
      console.error(`[ThreatIntelligence] Ошибка получения объектов для ${feedId}:`, error);
      this.statistics.syncErrors++;
      throw error;
    }
  }

  // ============================================================================
  // СИНХРОНИЗАЦИЯ
  // ============================================================================

  /**
   * Синхронизация всех feeds
   */
  async syncAllFeeds(): Promise<SyncResult> {
    const results: FeedSyncResult[] = [];
    let totalIndicators = 0;
    let totalErrors = 0;
    
    console.log('[ThreatIntelligence] Начало синхронизации всех feeds');
    
    for (const feed of this.feeds.values()) {
      if (!feed.enabled) {
        continue;
      }
      
      try {
        const result = await this.syncFeed(feed);
        results.push(result);
        totalIndicators += result.indicatorsAdded;
      } catch (error) {
        console.error(`[ThreatIntelligence] Ошибка синхронизации feed ${feed.name}:`, error);
        totalErrors++;
        results.push({
          feedId: feed.id,
          feedName: feed.name,
          indicatorsAdded: 0,
          error: (error as Error).message
        });
      }
    }
    
    this.statistics.lastSyncTime = new Date();
    this.statistics.totalIndicators = this.indicators.size;
    
    console.log(`[ThreatIntelligence] Синхронизация завершена. Добавлено индикаторов: ${totalIndicators}`);
    
    return {
      success: totalErrors === 0,
      feedsSynced: results.length,
      totalIndicatorsAdded: totalIndicators,
      errors: totalErrors,
      results
    };
  }

  /**
   * Синхронизация отдельного feed
   */
  private async syncFeed(feed: ThreatFeed): Promise<FeedSyncResult> {
    console.log(`[ThreatIntelligence] Синхронизация feed: ${feed.name}`);
    
    let indicatorsAdded = 0;
    
    if (feed.type === 'stix-taxii') {
      const config = feed.config as TaxiiServerConfig;
      indicatorsAdded = await this.syncTaxiiFeed(feed.id, config);
    } else if (feed.type === 'opencti' || feed.type === 'misp') {
      indicatorsAdded = await this.syncCustomFeed(feed);
    } else if (feed.type === 'custom') {
      indicatorsAdded = await this.syncCustomFeed(feed);
    }
    
    this.lastSyncTime.set(feed.id, new Date());
    this.updateFeedStatus(feed.id, {
      lastSync: new Date(),
      syncStatus: 'idle',
      indicatorsCount: this.indicators.size
    });
    
    return {
      feedId: feed.id,
      feedName: feed.name,
      indicatorsAdded,
      error: undefined
    };
  }

  /**
   * Синхронизация TAXII feed
   */
  private async syncTaxiiFeed(feedId: string, config: TaxiiServerConfig): Promise<number> {
    let indicatorsAdded = 0;
    
    try {
      // Получение API roots
      const apiRoots = await this.discoverApiRoots(feedId);
      
      for (const apiRoot of apiRoots) {
        // Получение коллекций
        const collections = await this.getCollections(feedId, apiRoot.url);
        
        for (const collection of collections) {
          if (config.collections.includes(collection.id) || config.collections.length === 0) {
            // Получение индикаторов
            const objects = await this.getObjectsFromCollection(
              feedId,
              collection.id,
              apiRoot.url,
              {
                added_after: this.lastSyncTime.get(feedId),
                type: 'indicator',
                limit: 1000
              }
            );
            
            // Обработка индикаторов
            for (const obj of objects) {
              if (obj.type === 'indicator') {
                const indicator = this.convertStixIndicator(obj as StixIndicatorObject);
                
                if (indicator.confidence >= this.minConfidence) {
                  this.indicators.set(indicator.id, indicator);
                  this.updateIndicatorCache(indicator);
                  indicatorsAdded++;
                }
              }
            }
          }
        }
      }
    } catch (error) {
      console.error(`[ThreatIntelligence] Ошибка синхронизации TAXII ${feedId}:`, error);
      throw error;
    }
    
    return indicatorsAdded;
  }

  /**
   * Синхронизация custom feed
   */
  private async syncCustomFeed(feed: ThreatFeed): Promise<number> {
    let indicatorsAdded = 0;
    
    try {
      const response = await axios.get(feed.url, {
        timeout: 30000
      });
      
      const data = response.data;
      
      // Обработка в зависимости от формата
      if (Array.isArray(data)) {
        for (const item of data) {
          const indicator = this.parseCustomIndicator(feed, item);
          
          if (indicator && indicator.confidence >= this.minConfidence) {
            this.indicators.set(indicator.id, indicator);
            this.updateIndicatorCache(indicator);
            indicatorsAdded++;
          }
        }
      }
    } catch (error) {
      console.error(`[ThreatIntelligence] Ошибка синхронизации custom feed ${feed.name}:`, error);
      throw error;
    }
    
    return indicatorsAdded;
  }

  /**
   * Парсинг custom индикатора
   */
  private parseCustomIndicator(feed: ThreatFeed, data: any): StixIndicator | null {
    try {
      return {
        id: data.id || uuidv4(),
        type: StixType.INDICATOR,
        name: data.name || data.indicator || 'Unknown',
        description: data.description || '',
        pattern: data.pattern || data.indicator || '',
        patternType: this.detectPatternType(data.pattern || data.indicator),
        validFrom: new Date(data.valid_from || data.created || Date.now()),
        validUntil: data.valid_until ? new Date(data.valid_until) : undefined,
        labels: data.labels || [],
        confidence: data.confidence || 50,
        severity: this.mapSeverity(data.severity),
        externalReferences: data.external_references || [],
        killChainPhases: data.kill_chain_phases || [],
        createdBy: feed.id,
        created: new Date(data.created || Date.now()),
        modified: new Date(data.modified || Date.now())
      };
    } catch (error) {
      console.error('[ThreatIntelligence] Ошибка парсинга индикатора:', error);
      return null;
    }
  }

  // ============================================================================
  // КОНВЕРТАЦИЯ STIX ОБЪЕКТОВ
  // ============================================================================

  /**
   * Конвертация STIX индикатора
   */
  private convertStixIndicator(stix: StixIndicatorObject): StixIndicator {
    return {
      id: stix.id,
      type: StixType.INDICATOR,
      name: stix.name || stix.id,
      description: stix.description || '',
      pattern: stix.pattern,
      patternType: this.mapPatternType(stix.pattern_type),
      validFrom: new Date(stix.valid_from),
      validUntil: stix.valid_until ? new Date(stix.valid_until) : undefined,
      labels: stix.labels || [],
      confidence: stix.confidence || 50,
      severity: this.mapSeverity(stix.labels),
      externalReferences: stix.external_references?.map(this.convertExternalRef) || [],
      killChainPhases: stix.kill_chain_phases?.map(kc => this.mapKillChainPhase(kc)) || [],
      createdBy: stix.created_by_ref || '',
      created: new Date(stix.created),
      modified: new Date(stix.modified)
    };
  }

  /**
   * Конвертация STIX Threat Actor
   */
  private convertStixThreatActor(stix: StixThreatActorObject): StixThreatActor {
    return {
      id: stix.id,
      type: StixType.THREAT_ACTOR,
      name: stix.name || stix.id,
      description: stix.description || '',
      aliases: stix.actor_types || [],
      goals: stix.goals || [],
      sophistication: this.mapSophistication(stix.sophistication),
      resourceLevel: this.mapResourceLevel(stix.resource_level),
      primaryMotivation: stix.primary_motivation || '',
      secondaryMotivations: stix.secondary_motivations || [],
      personalMotivations: [],
      externalReferences: stix.external_references?.map(this.convertExternalRef) || [],
      createdBy: stix.created_by_ref || '',
      created: new Date(stix.created),
      modified: new Date(stix.modified)
    };
  }

  /**
   * Конвертация STIX Malware
   */
  private convertStixMalware(stix: StixMalwareObject): StixMalware {
    return {
      id: stix.id,
      type: StixType.MALWARE,
      name: stix.name || stix.id,
      description: stix.description || '',
      aliases: stix.aliases || [],
      malwareTypes: stix.malware_types || [],
      malwareFamilies: [],
      isFamily: stix.is_family,
      firstSeen: stix.first_seen ? new Date(stix.first_seen) : undefined,
      lastSeen: stix.last_seen ? new Date(stix.last_seen) : undefined,
      operatingSystems: stix.operating_system_refs || [],
      architectureExecutionEnvs: stix.architecture_execution_envs || [],
      implementationLanguages: stix.implementation_languages || [],
      capabilities: stix.capabilities || [],
      externalReferences: stix.external_references?.map(this.convertExternalRef) || [],
      createdBy: stix.created_by_ref || '',
      created: new Date(stix.created),
      modified: new Date(stix.modified)
    };
  }

  /**
   * Конвертация External Reference
   */
  private convertExternalRef(ref: StixExternalRef): any {
    return {
      sourceName: ref.source_name,
      description: ref.description,
      url: ref.url,
      externalId: ref.external_id
    };
  }

  // ============================================================================
  // ПОИСК И МАППИНГ
  // ============================================================================

  /**
   * Поиск индикаторов по значению
   */
  findIndicators(value: string): StixIndicator[] {
    // Проверка кэша
    const cached = this.indicatorCache.get(value.toLowerCase());
    
    if (cached) {
      return cached;
    }
    
    const results: StixIndicator[] = [];
    
    for (const indicator of this.indicators.values()) {
      if (this.matchIndicator(indicator, value)) {
        results.push(indicator);
      }
    }
    
    return results;
  }

  /**
   * Проверка события на наличие threat intelligence matches
   */
  matchEventToThreatIntel(event: SecurityEvent): StixIndicator[] {
    const matches: StixIndicator[] = [];
    
    // Проверка IP адресов
    if (event.sourceIp) {
      const ipMatches = this.findIndicators(event.sourceIp);
      matches.push(...ipMatches);
    }
    
    if (event.destinationIp) {
      const ipMatches = this.findIndicators(event.destinationIp);
      matches.push(...ipMatches);
    }
    
    // Проверка хешей файлов
    if (event.hash) {
      const hashMatches = this.findIndicators(event.hash);
      matches.push(...hashMatches);
    }
    
    // Проверка доменов
    if (event.rawEvent.domain) {
      const domainMatches = this.findIndicators(event.rawEvent.domain as string);
      matches.push(...domainMatches);
    }
    
    // Проверка URL
    if (event.rawEvent.url) {
      const urlMatches = this.findIndicators(event.rawEvent.url as string);
      matches.push(...urlMatches);
    }
    
    // Обновление статистики
    if (matches.length > 0) {
      this.statistics.indicatorsMatched += matches.length;
    }
    
    return matches;
  }

  /**
   * Проверка алерта на threat intelligence matches
   */
  matchAlertToThreatIntel(alert: SecurityAlert): ThreatIntelMatch {
    const allMatches: StixIndicator[] = [];
    const relatedThreatActors: StixThreatActor[] = [];
    const relatedMalware: StixMalware[] = [];
    
    // Проверка всех событий алерта
    for (const event of alert.events) {
      const matches = this.matchEventToThreatIntel(event);
      allMatches.push(...matches);
    }
    
    // Поиск связанных threat actors
    for (const indicator of allMatches) {
      const actor = this.findRelatedThreatActor(indicator.id);
      if (actor) {
        relatedThreatActors.push(actor);
      }
    }
    
    // Поиск связанного malware
    for (const indicator of allMatches) {
      const malware = this.findRelatedMalware(indicator.id);
      if (malware) {
        relatedMalware.push(malware);
      }
    }
    
    // Расчет уверенности
    const confidence = allMatches.length > 0 
      ? Math.min(allMatches.reduce((acc, m) => acc + m.confidence, 0) / allMatches.length, 100)
      : 0;
    
    return {
      indicators: allMatches,
      threatActors: relatedThreatActors,
      malware: relatedMalware,
      confidence,
      severity: this.calculateMatchSeverity(allMatches)
    };
  }

  /**
   * Поиск связанного threat actor
   */
  private findRelatedThreatActor(indicatorId: string): StixThreatActor | null {
    // В реальной реализации здесь был бы поиск relationships
    return this.threatActors.values().next().value || null;
  }

  /**
   * Поиск связанного malware
   */
  private findRelatedMalware(indicatorId: string): StixMalware | null {
    // В реальной реализации здесь был бы поиск relationships
    return this.malware.values().next().value || null;
  }

  /**
   * Расчет серьезности matches
   */
  private calculateMatchSeverity(indicators: StixIndicator[]): ThreatSeverity {
    if (indicators.length === 0) {
      return ThreatSeverity.INFO;
    }
    
    const severities = indicators.map(i => i.severity);
    
    if (severities.includes(ThreatSeverity.CRITICAL)) {
      return ThreatSeverity.CRITICAL;
    }
    if (severities.includes(ThreatSeverity.HIGH)) {
      return ThreatSeverity.HIGH;
    }
    if (severities.includes(ThreatSeverity.MEDIUM)) {
      return ThreatSeverity.MEDIUM;
    }
    
    return ThreatSeverity.LOW;
  }

  // ============================================================================
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ============================================================================

  /**
   * Проверка соответствия индикатора значению
   */
  private matchIndicator(indicator: StixIndicator, value: string): boolean {
    const pattern = indicator.pattern.toLowerCase();
    const searchValue = value.toLowerCase();
    
    // Простая проверка по паттерну
    if (pattern.includes(searchValue)) {
      return true;
    }
    
    // Проверка по name
    if (indicator.name?.toLowerCase().includes(searchValue)) {
      return true;
    }
    
    // Проверка по description
    if (indicator.description?.toLowerCase().includes(searchValue)) {
      return true;
    }
    
    return false;
  }

  /**
   * Обновление кэша индикаторов
   */
  private updateIndicatorCache(indicator: StixIndicator): void {
    // Извлечение ключевых значений из паттерна
    const values = this.extractValuesFromPattern(indicator.pattern);
    
    for (const value of values) {
      const lowerValue = value.toLowerCase();
      let cached = this.indicatorCache.get(lowerValue);
      
      if (!cached) {
        cached = [];
        this.indicatorCache.set(lowerValue, cached);
      }
      
      cached.push(indicator);
    }
  }

  /**
   * Извлечение значений из STIX паттерна
   */
  private extractValuesFromPattern(pattern: string): string[] {
    const values: string[] = [];
    
    // Простой парсинг STIX паттернов
    // Пример: [ipv4-addr:value = '192.168.1.1']
    const regex = /\[.*?:value = '([^']+)'\]/g;
    let match;
    
    while ((match = regex.exec(pattern)) !== null) {
      values.push(match[1]);
    }
    
    // Пример для domain: [domain-name:value = 'example.com']
    const domainRegex = /\[domain-name:value = '([^']+)'\]/g;
    while ((match = domainRegex.exec(pattern)) !== null) {
      values.push(match[1]);
    }
    
    // Пример для hash: [file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']
    const hashRegex = /\[file:hashes\..*? = '([^']+)'\]/g;
    while ((match = hashRegex.exec(pattern)) !== null) {
      values.push(match[1]);
    }
    
    return values;
  }

  /**
   * Определение типа паттерна
   */
  private detectPatternType(pattern: string): IndicatorPatternType {
    if (pattern.startsWith('[') && pattern.includes(':value')) {
      return IndicatorPatternType.STIX;
    }
    if (pattern.match(/alert|log|pass|drop/i)) {
      return IndicatorPatternType.SNORT;
    }
    if (pattern.match(/rule\s+\w+/i)) {
      return IndicatorPatternType.YARA;
    }
    if (pattern.match(/title:|logsource:/i)) {
      return IndicatorPatternType.SIGMA;
    }
    
    return IndicatorPatternType.STIX;
  }

  /**
   * Маппинг типа паттерна
   */
  private mapPatternType(type: string): IndicatorPatternType {
    const mapping: Record<string, IndicatorPatternType> = {
      'stix': IndicatorPatternType.STIX,
      'stix-patterning': IndicatorPatternType.STIX,
      'snort': IndicatorPatternType.SNORT,
      'suricata': IndicatorPatternType.SURICATA,
      'yara': IndicatorPatternType.YARA,
      'sigma': IndicatorPatternType.SIGMA,
      'cybox': IndicatorPatternType.CYPATTERN
    };
    
    return mapping[type.toLowerCase()] || IndicatorPatternType.STIX;
  }

  /**
   * Маппинг серьезности
   */
  private mapSeverity(labels: string[] | string): ThreatSeverity {
    const labelArray = Array.isArray(labels) ? labels : [labels];
    
    for (const label of labelArray) {
      const lower = label.toLowerCase();
      
      if (lower.includes('critical')) return ThreatSeverity.CRITICAL;
      if (lower.includes('high')) return ThreatSeverity.HIGH;
      if (lower.includes('medium')) return ThreatSeverity.MEDIUM;
      if (lower.includes('low')) return ThreatSeverity.LOW;
    }
    
    return ThreatSeverity.INFO;
  }

  /**
   * Маппинг Kill Chain фазы
   */
  private mapKillChainPhase(kc: KillChainPhaseRef): KillChainPhase {
    const mapping: Record<string, KillChainPhase> = {
      'reconnaissance': KillChainPhase.RECONNAISSANCE,
      'weaponization': KillChainPhase.WEAPONIZATION,
      'delivery': KillChainPhase.DELIVERY,
      'exploitation': KillChainPhase.EXPLOITATION,
      'installation': KillChainPhase.INSTALLATION,
      'command-and-control': KillChainPhase.COMMAND_AND_CONTROL,
      'actions-on-objectives': KillChainPhase.ACTIONS_ON_OBJECTIVES
    };
    
    return mapping[kc.phase_name.toLowerCase()] || KillChainPhase.RECONNAISSANCE;
  }

  /**
   * Маппинг sophistication
   */
  private mapSophistication(level?: string): StixThreatActor['sophistication'] {
    const mapping: Record<string, StixThreatActor['sophistication']> = {
      'none': 'none',
      'minimal': 'minimal',
      'intermediate': 'intermediate',
      'advanced': 'advanced',
      'expert': 'expert',
      'innovator': 'innovator',
      'strategic': 'strategic'
    };
    
    return mapping[level?.toLowerCase()] || 'intermediate';
  }

  /**
   * Маппинг resource level
   */
  private mapResourceLevel(level?: string): StixThreatActor['resourceLevel'] {
    const mapping: Record<string, StixThreatActor['resourceLevel']> = {
      'individual': 'individual',
      'club': 'club',
      'contest': 'contest',
      'team': 'team',
      'organization': 'organization',
      'government': 'government'
    };
    
    return mapping[level?.toLowerCase()] || 'organization';
  }

  // ============================================================================
  // СТАТИСТИКА И УПРАВЛЕНИЕ
  // ============================================================================

  /**
   * Получение статистики
   */
  getStatistics(): ThreatIntelStatistics {
    return {
      ...this.statistics,
      totalIndicators: this.indicators.size,
      totalThreatActors: this.threatActors.size,
      totalMalware: this.malware.size
    };
  }

  /**
   * Получение всех индикаторов
   */
  getAllIndicators(): StixIndicator[] {
    return Array.from(this.indicators.values());
  }

  /**
   * Получение индикаторов по типу
   */
  getIndicatorsByType(type: StixType): StixIndicator[] {
    return Array.from(this.indicators.values()).filter(i => i.type === type);
  }

  /**
   * Получение индикаторов по серьезности
   */
  getIndicatorsBySeverity(severity: ThreatSeverity): StixIndicator[] {
    return Array.from(this.indicators.values()).filter(i => i.severity === severity);
  }

  /**
   * Очистка устаревших индикаторов
   */
  cleanupExpiredIndicators(): number {
    const now = Date.now();
    const expirationMs = this.indicatorExpiration * 24 * 60 * 60 * 1000;
    let removed = 0;
    
    for (const [id, indicator] of this.indicators.entries()) {
      const validUntil = indicator.validUntil?.getTime() || indicator.created.getTime() + expirationMs;
      
      if (validUntil < now) {
        this.indicators.delete(id);
        this.removeFromCache(indicator);
        removed++;
      }
    }
    
    console.log(`[ThreatIntelligence] Удалено ${removed} устаревших индикаторов`);
    
    return removed;
  }

  /**
   * Удаление индикатора из кэша
   */
  private removeFromCache(indicator: StixIndicator): void {
    const values = this.extractValuesFromPattern(indicator.pattern);
    
    for (const value of values) {
      const cached = this.indicatorCache.get(value.toLowerCase());
      
      if (cached) {
        const index = cached.findIndex(i => i.id === indicator.id);
        
        if (index !== -1) {
          cached.splice(index, 1);
        }
      }
    }
  }

  /**
   * Запуск периодической синхронизации
   */
  startPeriodicSync(): void {
    console.log(`[ThreatIntelligence] Запуск периодической синхронизации (интервал: ${this.pollingInterval}мс)`);
    
    setInterval(async () => {
      try {
        await this.syncAllFeeds();
        this.cleanupExpiredIndicators();
      } catch (error) {
        console.error('[ThreatIntelligence] Ошибка периодической синхронизации:', error);
      }
    }, this.pollingInterval);
  }

  /**
   * Остановка периодической синхронизации
   */
  stopPeriodicSync(): void {
    console.log('[ThreatIntelligence] Остановка периодической синхронизации');
  }
}

/**
 * Результат синхронизации feed
 */
interface FeedSyncResult {
  feedId: string;
  feedName: string;
  indicatorsAdded: number;
  error?: string;
}

/**
 * Общий результат синхронизации
 */
interface SyncResult {
  success: boolean;
  feedsSynced: number;
  totalIndicatorsAdded: number;
  errors: number;
  results: FeedSyncResult[];
}

/**
 * Результат match threat intelligence
 */
interface ThreatIntelMatch {
  indicators: StixIndicator[];
  threatActors: StixThreatActor[];
  malware: StixMalware[];
  confidence: number;
  severity: ThreatSeverity;
}

/**
 * STIX Attack Pattern
 */
interface StixAttackPattern {
  id: string;
  type: string;
  name: string;
  description: string;
  aliases: string[];
  killChainPhases: KillChainPhase[];
  externalReferences: any[];
  created: Date;
  modified: Date;
}

/**
 * Статистика Threat Intelligence
 */
interface ThreatIntelStatistics {
  totalIndicators: number;
  totalThreatActors: number;
  totalMalware: number;
  totalFeeds: number;
  lastSyncTime: Date | undefined;
  syncErrors: number;
  indicatorsMatched: number;
}
