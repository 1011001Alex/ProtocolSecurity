/**
 * ============================================================================
 * SANCTIONS SCREENING — ПРОВЕРКА САНКЦИОННЫХ СПИСКОВ
 * ============================================================================
 *
 * Автоматизированная проверка контрагентов по санкционным спискам
 *
 * Источники:
 * - OFAC SDN (Specially Designated Nationals)
 * - UN Consolidated List
 * - EU Consolidated Sanctions List
 * - UK HM Treasury Sanctions List
 * - Interpol Wanted List
 * - PEP (Politically Exposed Persons) databases
 *
 * @package protocol/finance-security/aml
 * @author Protocol Security Team
 * @version 1.0.0
 */

import { EventEmitter } from 'events';
import { createHash } from 'crypto';
import { logger } from '../../logging/Logger';
import {
  FinanceSecurityConfig,
  SanctionsMatch,
  AMLCheckResult
} from '../types/finance.types';

/**
 * Запись в санкционном списке
 */
interface SanctionsListEntry {
  /** Уникальный ID записи */
  id: string;

  /** Источник списка */
  source: 'OFAC' | 'UN' | 'EU' | 'UK' | 'INTERPOL' | 'PEP';

  /** Тип записи */
  entityType: 'INDIVIDUAL' | 'ORGANIZATION' | 'VESSEL' | 'AIRCRAFT';

  /** Имя / Название */
  name: string;

  /** Альтернативные имена (aliases) */
  aliases: string[];

  /** Дата рождения / регистрации */
  birthDate?: string;

  /** Место рождения / регистрации */
  birthPlace?: string;

  /** Гражданство / Юрисдикция */
  nationality?: string;

  /** Адреса */
  addresses: string[];

  /** Идентификационные документы */
  documents: {
    type: string;
    number: string;
    issuingCountry: string;
    issueDate?: string;
    expiryDate?: string;
  }[];

  /** Программы санкций */
  programs: string[];

  /** Дата добавления в список */
  listedOn: Date;

  /** Дата последнего обновления */
  updatedAt: Date;

  /** Примечания */
  remarks?: string;

  /** Hash записи для быстрого сравнения */
  nameHash: string;
}

/**
 * Результат fuzzy matching
 */
interface FuzzyMatchResult {
  /** Имя из проверяемого списка */
  listName: string;

  /** Проверяемое имя */
  queryName: string;

  /** Score совпадения (0.0 - 1.0) */
  score: number;

  /** Тип совпадения */
  matchType: 'EXACT' | 'FUZZY' | 'ALIAS' | 'PHONETIC';

  /** Детали совпадения */
  details: {
    levenshteinDistance?: number;
    commonSubstrings?: number;
    phoneticMatch?: boolean;
  };
}

/**
 * Sanctions Screening Service
 */
export class SanctionsScreening extends EventEmitter {
  /** Конфигурация */
  private readonly config: FinanceSecurityConfig;

  /** Загруженные санкционные списки */
  private sanctionsLists: Map<string, SanctionsListEntry[]> = new Map();

  /** PEP database */
  private pepDatabase: SanctionsListEntry[] = [];

  /** Adverse media database */
  private adverseMediaDatabase: Map<string, any[]> = new Map();

  /** Статус инициализации */
  private isInitialized = false;

  /** Дата последней загрузки списков */
  private lastListUpdate?: Date;

  /** Конфигурация matching */
  private readonly matchingConfig = {
    // Минимальный score для совпадения
    exactMatchThreshold: 1.0,
    fuzzyMatchThreshold: 0.85,
    aliasMatchThreshold: 0.9,
    phoneticMatchThreshold: 0.8,

    // Минимальная длина имени для проверки
    minNameLength: 3,

    // Игнорировать эти слова при сравнении
    ignoreWords: ['ltd', 'l.l.c.', 'llc', 'inc', 'corp', 'corporation', 'company', 'the', 'a/s', 'a.g.', 'gmbh', 's.a.', 's.p.a.'],

    // Веса для разных типов совпадений
    weights: {
      exactMatch: 1.0,
      fuzzyMatch: 0.85,
      aliasMatch: 0.9,
      phoneticMatch: 0.8
    }
  };

  /**
   * Создаёт новый экземпляр SanctionsScreening
   */
  constructor(config: FinanceSecurityConfig) {
    super();

    this.config = config;

    logger.info('[SanctionsScreening] Service created');
  }

  /**
   * Инициализация сервиса
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('[SanctionsScreening] Already initialized');
      return;
    }

    try {
      // Загрузка санкционных списков
      for (const listName of this.config.aml.sanctionsLists) {
        await this.loadSanctionsList(listName);
      }

      // Загрузка PEP database
      await this.loadPEPDatabase();

      // Загрузка adverse media
      await this.loadAdverseMedia();

      this.isInitialized = true;
      this.lastListUpdate = new Date();

      logger.info('[SanctionsScreening] Initialized', {
        listsLoaded: this.sanctionsLists.size,
        pepEntries: this.pepDatabase.length,
        lastUpdate: this.lastListUpdate
      });

      this.emit('initialized');

    } catch (error) {
      logger.error('[SanctionsScreening] Initialization failed', { error });
      this.emit('error', error);
      throw error;
    }
  }

  /**
   * Загрузка санкционного списка
   */
  private async loadSanctionsList(listName: string): Promise<void> {
    logger.info('[SanctionsScreening] Loading sanctions list', { list: listName });

    // В production загрузка реальных списков из API
    // OFAC: https://sanctionssearch.ofac.treasury.gov/
    // UN: https://www.un.org/security-council/sanctions/information
    // EU: https://fsd.ec.europa.eu/

    const entries: SanctionsListEntry[] = [];

    // Demo данные для тестирования
    if (listName === 'OFAC') {
      entries.push(
        this.createDemoEntry('OFAC', 'INDIVIDUAL', 'John Doe Sanctions', ['J. Doe', 'Johnny Doe']),
        this.createDemoEntry('OFAC', 'ORGANIZATION', 'Sanctioned Corp Ltd', ['Sanctioned Corporation', 'SC Ltd'])
      );
    } else if (listName === 'UN') {
      entries.push(
        this.createDemoEntry('UN', 'INDIVIDUAL', 'UN Target Individual', ['Target I.'])
      );
    } else if (listName === 'EU') {
      entries.push(
        this.createDemoEntry('EU', 'ORGANIZATION', 'EU Sanctioned Entity', ['ESE'])
      );
    }

    this.sanctionsLists.set(listName, entries);

    logger.debug('[SanctionsScreening] List loaded', {
      list: listName,
      entries: entries.length
    });
  }

  /**
   * Загрузка PEP database
   */
  private async loadPEPDatabase(): Promise<void> {
    logger.info('[SanctionsScreening] Loading PEP database');

    // В production загрузка из коммерческих источников
    // World-Check, Dow Jones, Refinitiv и т.д.

    this.pepDatabase = [
      this.createDemoEntry('PEP', 'INDIVIDUAL', 'Politically Exposed Person', ['PEP Individual'])
    ];

    logger.debug('[SanctionsScreening] PEP database loaded', {
      entries: this.pepDatabase.length
    });
  }

  /**
   * Загрузка adverse media
   */
  private async loadAdverseMedia(): Promise<void> {
    logger.info('[SanctionsScreening] Loading adverse media database');

    // В production интеграция с новостными агрегаторами
    // LexisNexis, Factiva, и т.д.

    this.adverseMediaDatabase.set('general', []);

    logger.debug('[SanctionsScreening] Adverse media loaded');
  }

  /**
   * Проверка имени по санкционным спискам
   *
   * @param name - Проверяемое имя
   * @param options - Опции проверки
   * @returns Результаты проверки
   */
  public async screenName(
    name: string,
    options: {
      /** Тип записи */
      entityType?: 'INDIVIDUAL' | 'ORGANIZATION';

      /** Страна / юрисдикция */
      country?: string;

      /** Дата рождения / регистрации */
      birthDate?: string;

      /** Минимальный score совпадения */
      threshold?: number;

      /** Включить PEP проверку */
      includePEP?: boolean;

      /** Включить adverse media проверку */
      includeAdverseMedia?: boolean;
    } = {}
  ): Promise<{
    matches: SanctionsMatch[];
    pepMatch: boolean;
    adverseMediaMatch: boolean;
    riskScore: number;
  }> {
    if (!this.isInitialized) {
      throw new Error('SanctionsScreening not initialized');
    }

    const matches: SanctionsMatch[] = [];
    let pepMatch = false;
    let adverseMediaMatch = false;
    let riskScore = 0;

    const threshold = options.threshold || this.matchingConfig.fuzzyMatchThreshold;

    // Проверка по санкционным спискам
    for (const [listName, entries] of this.sanctionsLists.entries()) {
      const listMatches = this.findMatches(name, entries, threshold, options.entityType);

      for (const match of listMatches) {
        const entry = entries.find(e => e.nameHash === this.hashName(match.listName));

        if (entry) {
          matches.push({
            listName,
            matchedName: entry.name,
            matchScore: match.score,
            entityType: entry.entityType,
            referenceId: entry.id,
            programs: entry.programs
          });

          riskScore = Math.max(riskScore, match.score);
        }
      }
    }

    // PEP проверка
    if (options.includePEP !== false) {
      const pepMatches = this.findMatches(name, this.pepDatabase, threshold, options.entityType);

      if (pepMatches.length > 0) {
        pepMatch = true;
        riskScore = Math.max(riskScore, ...pepMatches.map(m => m.score));

        for (const match of pepMatches) {
          matches.push({
            listName: 'PEP',
            matchedName: match.listName,
            matchScore: match.score,
            entityType: 'INDIVIDUAL',
            referenceId: 'PEP',
            programs: ['PEP']
          });
        }
      }
    }

    // Adverse media проверка
    if (options.includeAdverseMedia !== false) {
      adverseMediaMatch = await this.checkAdverseMedia(name);

      if (adverseMediaMatch) {
        riskScore = Math.max(riskScore, 0.5);
      }
    }

    logger.info('[SanctionsScreening] Name screened', {
      name: this.maskName(name),
      matches: matches.length,
      pepMatch,
      adverseMediaMatch,
      riskScore
    });

    return {
      matches,
      pepMatch,
      adverseMediaMatch,
      riskScore
    };
  }

  /**
   * Проверка транзакции на санкции
   *
   * @param transaction - Данные транзакции
   * @returns Результат AML проверки
   */
  public async screenTransaction(transaction: any): Promise<AMLCheckResult> {
    if (!this.isInitialized) {
      throw new Error('SanctionsScreening not initialized');
    }

    const sanctionsMatches: SanctionsMatch[] = [];
    let riskScore = 0;
    let pepMatch = false;
    let adverseMediaMatch = false;

    // Проверка отправителя
    if (transaction.senderName) {
      const senderResult = await this.screenName(transaction.senderName, {
        entityType: 'INDIVIDUAL',
        includePEP: true,
        includeAdverseMedia: true
      });

      sanctionsMatches.push(...senderResult.matches);
      pepMatch = senderResult.pepMatch;
      adverseMediaMatch = senderResult.adverseMediaMatch;
      riskScore = Math.max(riskScore, senderResult.riskScore);
    }

    // Проверка получателя
    if (transaction.beneficiaryName) {
      const beneficiaryResult = await this.screenName(transaction.beneficiaryName, {
        entityType: 'ORGANIZATION',
        includePEP: false,
        includeAdverseMedia: true
      });

      sanctionsMatches.push(...beneficiaryResult.matches);
      adverseMediaMatch = adverseMediaMatch || beneficiaryResult.adverseMediaMatch;
      riskScore = Math.max(riskScore, beneficiaryResult.riskScore);
    }

    // Проверка страны
    if (transaction.destinationCountry) {
      const sanctionedCountries = ['KP', 'IR', 'SY', 'CU', 'UA-43', 'UA-14']; // Crimea

      if (sanctionedCountries.includes(transaction.destinationCountry)) {
        riskScore = Math.max(riskScore, 0.8);

        sanctionsMatches.push({
          listName: 'COUNTRY_SANCTIONS',
          matchedName: transaction.destinationCountry,
          matchScore: 1.0,
          entityType: 'COUNTRY',
          referenceId: 'GEO',
          programs: ['GEOGRAPHIC_SANCTIONS']
        });
      }
    }

    const passed = riskScore < 0.5 && sanctionsMatches.length === 0;

    return {
      passed,
      riskScore,
      sanctionsMatches,
      pepMatch,
      adverseMediaMatch,
      recommendedAction: passed ? 'PROCEED' : riskScore > 0.8 ? 'BLOCK' : 'REVIEW',
      sarRequired: riskScore >= 0.7
    };
  }

  /**
   * Поиск совпадений в списке
   */
  private findMatches(
    name: string,
    entries: SanctionsListEntry[],
    threshold: number,
    entityType?: 'INDIVIDUAL' | 'ORGANIZATION'
  ): FuzzyMatchResult[] {
    const matches: FuzzyMatchResult[] = [];
    const normalizedName = this.normalizeName(name);

    for (const entry of entries) {
      // Фильтр по типу записи
      if (entityType && entry.entityType !== entityType) {
        continue;
      }

      // Проверка основного имени
      const exactMatch = this.compareNames(normalizedName, entry.nameHash);

      if (exactMatch.score >= threshold) {
        matches.push({
          listName: entry.name,
          queryName: name,
          score: exactMatch.score,
          matchType: exactMatch.matchType,
          details: exactMatch.details
        });
        continue;
      }

      // Проверка aliases
      for (const alias of entry.aliases) {
        const aliasHash = this.hashName(alias);
        const aliasMatch = this.compareNames(normalizedName, aliasHash);

        if (aliasMatch.score >= threshold) {
          matches.push({
            listName: entry.name,
            queryName: name,
            score: aliasMatch.score * this.matchingConfig.weights.aliasMatch,
            matchType: 'ALIAS',
            details: aliasMatch.details
          });
          break;
        }
      }
    }

    return matches.sort((a, b) => b.score - a.score);
  }

  /**
   * Сравнение имён
   */
  private compareNames(
    queryHash: string,
    listHash: string
  ): { score: number; matchType: 'EXACT' | 'FUZZY' | 'PHONETIC'; details: any } {
    // Exact match
    if (queryHash === listHash) {
      return {
        score: 1.0,
        matchType: 'EXACT',
        details: {}
      };
    }

    // Fuzzy match через Levenshtein distance
    const queryName = queryHash; // В production реальное имя
    const listName = listHash;

    const levenshteinDistance = this.calculateLevenshteinDistance(queryName, listName);
    const maxLength = Math.max(queryName.length, listName.length);
    const fuzzyScore = 1 - levenshteinDistance / maxLength;

    if (fuzzyScore >= this.matchingConfig.fuzzyMatchThreshold) {
      return {
        score: fuzzyScore,
        matchType: 'FUZZY',
        details: {
          levenshteinDistance,
          commonSubstrings: this.countCommonSubstrings(queryName, listName)
        }
      };
    }

    // Phonetic match (Soundex)
    const querySoundex = this.soundex(queryName);
    const listSoundex = this.soundex(listName);

    if (querySoundex === listSoundex) {
      return {
        score: this.matchingConfig.weights.phoneticMatch,
        matchType: 'PHONETIC',
        details: {
          phoneticMatch: true,
          soundex: querySoundex
        }
      };
    }

    return {
      score: 0,
      matchType: 'FUZZY',
      details: {}
    };
  }

  /**
   * Проверка adverse media
   */
  private async checkAdverseMedia(name: string): Promise<boolean> {
    // В production реальная проверка по новостным источникам
    // Для demo всегда возвращаем false

    const normalizedName = this.normalizeName(name);

    for (const [, entries] of this.adverseMediaDatabase.entries()) {
      for (const entry of entries) {
        if (this.normalizeName(entry.name) === normalizedName) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Нормализация имени
   */
  private normalizeName(name: string): string {
    let normalized = name.toLowerCase().trim();

    // Удаление игнорируемых слов
    for (const word of this.matchingConfig.ignoreWords) {
      const regex = new RegExp(`\\b${word}\\b`, 'gi');
      normalized = normalized.replace(regex, '');
    }

    // Удаление специальных символов
    normalized = normalized.replace(/[^\w\s]/g, '');

    // Удаление лишних пробелов
    normalized = normalized.replace(/\s+/g, ' ').trim();

    return normalized;
  }

  /**
   * Hash имени для быстрого сравнения
   */
  private hashName(name: string): string {
    return createHash('sha256').update(this.normalizeName(name)).digest('hex').slice(0, 16);
  }

  /**
   * Вычисление расстояния Левенштейна
   */
  private calculateLevenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1, // insertion
            matrix[i - 1][j] + 1 // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Подсчёт общих подстрок
   */
  private countCommonSubstrings(str1: string, str2: string): number {
    let count = 0;
    const minLength = Math.min(str1.length, str2.length);

    for (let i = 0; i < minLength; i++) {
      if (str1[i] === str2[i]) {
        count++;
      }
    }

    return count;
  }

  /**
   * Алгоритм Soundex для phonetic matching
   */
  private soundex(name: string): string {
    if (!name) return '';

    name = name.toUpperCase();

    const soundexMap: { [key: string]: string } = {
      B: '1', F: '1', P: '1', V: '1',
      C: '2', G: '2', J: '2', K: '2', Q: '2', S: '2', X: '2', Z: '2',
      D: '3', T: '3',
      L: '4',
      M: '5', N: '5',
      R: '6'
    };

    let result = name[0];
    let lastCode = soundexMap[result] || '';

    for (let i = 1; i < name.length && result.length < 4; i++) {
      const code = soundexMap[name[i]] || '';

      if (code !== '' && code !== lastCode) {
        result += code;
      }

      lastCode = code || lastCode;
    }

    return result.padEnd(4, '0');
  }

  /**
   * Маскирование имени для логирования
   */
  private maskName(name: string): string {
    if (name.length <= 4) {
      return '*'.repeat(name.length);
    }

    return name[0] + '*'.repeat(name.length - 2) + name[name.length - 1];
  }

  /**
   * Создание демо записи
   */
  private createDemoEntry(
    source: SanctionsListEntry['source'],
    entityType: SanctionsListEntry['entityType'],
    name: string,
    aliases: string[]
  ): SanctionsListEntry {
    return {
      id: `${source}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      source,
      entityType,
      name,
      aliases,
      addresses: [],
      documents: [],
      programs: ['DEMO_PROGRAM'],
      listedOn: new Date(),
      updatedAt: new Date(),
      nameHash: this.hashName(name)
    };
  }

  /**
   * Обновление санкционных списков
   */
  public async refreshLists(): Promise<void> {
    logger.info('[SanctionsScreening] Refreshing sanctions lists');

    for (const listName of this.config.aml.sanctionsLists) {
      await this.loadSanctionsList(listName);
    }

    await this.loadPEPDatabase();
    await this.loadAdverseMedia();

    this.lastListUpdate = new Date();

    logger.info('[SanctionsScreening] Lists refreshed', {
      lastUpdate: this.lastListUpdate
    });

    this.emit('lists_refreshed', {
      lastUpdate: this.lastListUpdate
    });
  }

  /**
   * Остановка сервиса
   */
  public async destroy(): Promise<void> {
    logger.info('[SanctionsScreening] Shutting down...');

    this.sanctionsLists.clear();
    this.pepDatabase = [];
    this.adverseMediaDatabase.clear();
    this.isInitialized = false;

    logger.info('[SanctionsScreening] Destroyed');

    this.emit('destroyed');
  }

  /**
   * Получить статус сервиса
   */
  public getStatus(): {
    initialized: boolean;
    listsLoaded: number;
    pepEntries: number;
    lastUpdate?: Date;
  } {
    return {
      initialized: this.isInitialized,
      listsLoaded: this.sanctionsLists.size,
      pepEntries: this.pepDatabase.length,
      lastUpdate: this.lastListUpdate
    };
  }
}
