/**
 * ============================================================================
 * LOG ENRICHER - ОБОГАЩЕНИЕ ЛОГОВ КОНТЕКСТОМ
 * ============================================================================
 * Модуль для обогащения логов дополнительной информацией из различных
 * источников: GeoIP, Threat Intelligence, User Context, Asset Info и др.
 * 
 * Особенности:
 * - GeoIP обогащение (MaxMind совместимость)
 * - Threat Intelligence интеграция
 * - User/Session контекст
 * - Asset/CMDB интеграция
 * - DNS обратный lookup
 * - enrichment кэширование
 * - Асинхронное обогащение
 */

import * as crypto from 'crypto';
import * as dns from 'dns';
import { EventEmitter } from 'events';
import { logger } from './Logger';
import {
  LogEntry,
  LogContext,
  GeoLocation,
  DeviceInfo,
  ProcessingError,
  ProcessingStage,
  IOC
} from '../types/logging.types';

// ============================================================================
// INTERFACES FOR GEO IP API RESPONSES
// ============================================================================

/**
 * Ответ MaxMind GeoIP API
 */
interface MaxMindResponse {
  country?: { names?: { en?: string }; iso_code?: string };
  subdivisions?: Array<{ names?: { en?: string } }>;
  city?: { names?: { en?: string } };
  location?: { latitude?: number; longitude?: number; time_zone?: string };
  traits?: { isp?: string; autonomous_system_number?: number };
}

/**
 * Ответ ip-api.com
 */
interface IpApiResponse {
  status: string;
  country?: string;
  countryCode?: string;
  regionName?: string;
  city?: string;
  lat?: number;
  lon?: number;
  timezone?: string;
  isp?: string;
  as?: string;
}

// ============================================================================
// КОНСТАНТЫ
// ============================================================================

/**
 * Приватные IP диапазоны (RFC 1918)
 */
const PRIVATE_IP_RANGES = [
  { start: '10.0.0.0', end: '10.255.255.255' },
  { start: '172.16.0.0', end: '172.31.255.255' },
  { start: '192.168.0.0', end: '192.168.255.255' },
  { start: '127.0.0.0', end: '127.255.255.255' },
  { start: '169.254.0.0', end: '169.254.255.255' }
];

/**
 * Известные VPN/Proxy сервисы (частичный список для примера)
 */
const KNOWN_VPN_PROVIDERS = new Set([
  'nordvpn.com', 'expressvpn.com', 'surfshark.com', 'cyberghost.com',
  'ipvanish.com', 'privateinternetaccess.com', 'mullvad.net'
]);

/**
 * Known Tor exit nodes (обновляется динамически)
 */
const TOR_EXIT_NODES = new Set<string>();

/**
 * User Agent паттерны для определения устройств
 */
const UA_PATTERNS = {
  mobile: /Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i,
  tablet: /Tablet|iPad|Android(?!.*Mobile)/i,
  desktop: /Windows NT|Macintosh|Linux x86/i,
  bot: /bot|crawler|spider|crawl|slurp|mediapartners/i,
  iot: /IoT|SmartTV|WebOS|SmartHub|roku|chromecast/i,
  server: /curl|wget|python-requests|axios|node-fetch|Go-http-client/i
};

/**
 * OS паттерны
 */
const OS_PATTERNS = [
  { pattern: /Windows NT 10\.0/i, os: 'Windows', version: '10/11' },
  { pattern: /Windows NT 6\.3/i, os: 'Windows', version: '8.1' },
  { pattern: /Windows NT 6\.2/i, os: 'Windows', version: '8' },
  { pattern: /Windows NT 6\.1/i, os: 'Windows', version: '7' },
  { pattern: /Mac OS X (\d+[._]\d+)/i, os: 'macOS', version: '$1' },
  { pattern: /Linux/i, os: 'Linux', version: '' },
  { pattern: /Android (\d+[.\d]*)/i, os: 'Android', version: '$1' },
  { pattern: /iOS (\d+[._]\d+)/i, os: 'iOS', version: '$1' },
  { pattern: /Ubuntu/i, os: 'Ubuntu', version: '' },
  { pattern: /Debian/i, os: 'Debian', version: '' },
  { pattern: /CentOS/i, os: 'CentOS', version: '' }
];

/**
 * Browser паттерны
 */
const BROWSER_PATTERNS = [
  { pattern: /Chrome\/(\d+)/i, browser: 'Chrome', version: '$1' },
  { pattern: /Firefox\/(\d+)/i, browser: 'Firefox', version: '$1' },
  { pattern: /Safari\/(\d+)/i, browser: 'Safari', version: '$1' },
  { pattern: /Edge\/(\d+)/i, browser: 'Edge', version: '$1' },
  { pattern: /MSIE (\d+)/i, browser: 'Internet Explorer', version: '$1' },
  { pattern: /Trident\/(\d+)/i, browser: 'Internet Explorer', version: '$1' },
  { pattern: /Opera\/(\d+)/i, browser: 'Opera', version: '$1' }
];

// ============================================================================
// ИНТЕРФЕЙСЫ
// ============================================================================

/**
 * Конфигурация LogEnricher
 */
interface LogEnricherConfig {
  /** Включить GeoIP обогащение */
  enableGeoIP: boolean;
  /** Включить Threat Intelligence */
  enableThreatIntel: boolean;
  /** Включить DNS lookup */
  enableDnsLookup: boolean;
  /** Включить User Agent парсинг */
  enableUaParsing: boolean;
  /** Включить кэширование */
  enableCache: boolean;
  /** Размер кэша (записей) */
  cacheSize: number;
  /** TTL кэша (секунды) */
  cacheTtlSeconds: number;
  /** Таймаут внешних запросов (мс) */
  requestTimeout: number;
  /** API ключи для внешних сервисов */
  apiKeys: {
    maxmind?: string;
    virustotal?: string;
    abuseipdb?: string;
    shodan?: string;
  };
  /** Кастомные enrichers */
  customEnrichers?: EnricherFunction[];
}

/**
 * Функция кастомного обогащения
 */
type EnricherFunction = (log: LogEntry) => Promise<Partial<LogContext>>;

/**
 * Результат обогащения
 */
interface EnrichmentResult {
  /** Обогащенный лог */
  log: LogEntry;
  /** Успешность обогащения */
  success: boolean;
  /** Примененные enrichers */
  appliedEnrichers: string[];
  /** Ошибки обогащения */
  errors: ProcessingError[];
  /** Время обогащения (мс) */
  enrichmentTime: number;
  /** Кэш хиты */
  cacheHits: number;
  /** Кэш миссы */
  cacheMisses: number;
}

/**
 * Статистика enricher
 */
interface EnricherStatistics {
  /** Всего обработано логов */
  totalProcessed: number;
  /** Успешные обогащения */
  successCount: number;
  /** Ошибки обогащения */
  errorCount: number;
  /** Кэш хиты */
  cacheHits: number;
  /** Кэш миссы */
  cacheMisses: number;
  /** Hit rate */
  cacheHitRate: number;
  /** Среднее время обогащения (мс) */
  avgEnrichmentTime: number;
  /** P99 время обогащения (мс) */
  p99EnrichmentTime: number;
  /** Статистика по enrichers */
  byEnricher: Record<string, {
    count: number;
    successes: number;
    failures: number;
    avgTime: number;
  }>;
  /** GeoIP статистика */
  geoIP: {
    uniqueCountries: number;
    uniqueCities: number;
    topCountries: Record<string, number>;
  };
  /** Threat Intel статистика */
  threatIntel: {
    maliciousIpsDetected: number;
    torExitsDetected: number;
    vpnDetected: number;
    proxyDetected: number;
  };
}

// ============================================================================
// КЛАСС КЭША
// ============================================================================

/**
 * LRU кэш для результатов обогащения
 */
class EnrichmentCache<T> {
  private cache: Map<string, { value: T; expiry: number }>;
  private maxSize: number;
  private defaultTtl: number;
  
  constructor(maxSize: number, defaultTtlSeconds: number) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.defaultTtl = defaultTtlSeconds * 1000;
  }
  
  /**
   * Получение значения из кэша
   */
  get(key: string): T | null {
    const entry = this.cache.get(key);
    
    if (!entry) {
      return null;
    }
    
    if (Date.now() > entry.expiry) {
      this.cache.delete(key);
      return null;
    }
    
    // Перемещение в конец (для LRU)
    this.cache.delete(key);
    this.cache.set(key, entry);
    
    return entry.value;
  }
  
  /**
   * Сохранение значения в кэш
   */
  set(key: string, value: T, ttlSeconds?: number): void {
    // Удаление oldest если достигнут лимит
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }
    
    const ttl = ttlSeconds ? ttlSeconds * 1000 : this.defaultTtl;
    this.cache.set(key, {
      value,
      expiry: Date.now() + ttl
    });
  }
  
  /**
   * Проверка наличия ключа
   */
  has(key: string): boolean {
    return this.get(key) !== null;
  }
  
  /**
   * Удаление ключа
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }
  
  /**
   * Очистка кэша
   */
  clear(): void {
    this.cache.clear();
  }
  
  /**
   * Размер кэша
   */
  size(): number {
    return this.cache.size;
  }
  
  /**
   * Очистка expired записей
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;
    
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiry) {
        this.cache.delete(key);
        removed++;
      }
    }
    
    return removed;
  }
  
  /**
   * Статистика кэша
   */
  getStats(): { size: number; maxSize: number; utilization: number } {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      utilization: this.cache.size / this.maxSize
    };
  }
}

// ============================================================================
// GEOIP LOOKUP
// ============================================================================

/**
 * GeoIP lookup сервис
 */
class GeoIPService {
  private cache: EnrichmentCache<GeoLocation>;
  private apiKey?: string;
  private timeout: number;
  
  constructor(apiKey?: string, timeout: number = 5000, cacheSize: number = 10000, cacheTtl: number = 3600) {
    this.cache = new EnrichmentCache(cacheSize, cacheTtl);
    this.apiKey = apiKey;
    this.timeout = timeout;
  }
  
  /**
   * Lookup GeoIP информации для IP
   */
  async lookup(ip: string): Promise<GeoLocation | null> {
    // Проверка кэша
    const cached = this.cache.get(ip);
    if (cached) {
      return cached;
    }
    
    // Проверка приватного IP
    if (this.isPrivateIP(ip)) {
      const privateGeo: GeoLocation = {
        country: 'Private Network',
        countryCode: 'XX',
        region: 'Private',
        city: 'Local',
        timezone: 'UTC',
        isp: 'Private Network'
      };
      this.cache.set(ip, privateGeo);
      return privateGeo;
    }
    
    try {
      // Попытка использования MaxMind GeoIP2 (если доступен)
      if (this.apiKey) {
        return await this.lookupWithMaxMind(ip);
      }
      
      // Fallback на бесплатный сервис
      return await this.lookupWithFreeService(ip);
    } catch (error) {
      console.error(`GeoIP lookup failed for ${ip}:`, error);
      return null;
    }
  }
  
  /**
   * Lookup с использованием MaxMind
   */
  private async lookupWithMaxMind(ip: string): Promise<GeoLocation | null> {
    // В production использовать MaxMind GeoIP2 database или API
    // const reader = new geoip2.Reader('./GeoLite2-City.mmdb');
    // const response = reader.city(ip);
    
    // Эмуляция для примера
    const response = await this.fetchGeoData(ip, 'https://geoip.maxmind.com/geoip/v2.1/city/') as MaxMindResponse | null;

    if (response) {
      const geo: GeoLocation = {
        country: response.country?.names?.en,
        countryCode: response.country?.iso_code,
        region: response.subdivisions?.[0]?.names?.en,
        city: response.city?.names?.en,
        latitude: response.location?.latitude,
        longitude: response.location?.longitude,
        timezone: response.location?.time_zone,
        isp: response.traits?.isp,
        asn: response.traits?.autonomous_system_number?.toString()
      };
      
      this.cache.set(ip, geo);
      return geo;
    }
    
    return null;
  }
  
  /**
   * Lookup с использованием бесплатного сервиса
   */
  private async lookupWithFreeService(ip: string): Promise<GeoLocation | null> {
    // Используем ip-api.com (бесплатно для некоммерческого использования)
    const response = await this.fetchGeoData(ip, 'http://ip-api.com/json/') as IpApiResponse | null;

    if (response && response.status === 'success') {
      const geo: GeoLocation = {
        country: response.country,
        countryCode: response.countryCode,
        region: response.regionName,
        city: response.city,
        latitude: response.lat,
        longitude: response.lon,
        timezone: response.timezone,
        isp: response.isp,
        asn: response.as?.toString()
      };
      
      this.cache.set(ip, geo);
      return geo;
    }
    
    return null;
  }
  
  /**
   * Fetch geo данных
   *
   * БЕЗОПАСНОСТЬ: Правильная санитизация URL для предотвращения SSRF
   */
  private async fetchGeoData(ip: string, baseUrl: string): Promise<unknown> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      // ИСПОЛЬЗУЕМ URL API для правильного построения URL вместо конкатенации
      // Это предотвращает SSRF атаки через манипуляцию с путем
      const url = new URL(baseUrl);
      url.pathname = `${url.pathname}${url.pathname.endsWith('/') ? '' : '/'}${encodeURIComponent(ip)}`;

      const response = await fetch(url.toString(), {
        signal: controller.signal,
        headers: {
          'Accept': 'application/json'
        }
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        return null;
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }
  
  /**
   * Проверка приватного IP
   */
  private isPrivateIP(ip: string): boolean {
    const ipNum = this.ipToNumber(ip);
    
    for (const range of PRIVATE_IP_RANGES) {
      const start = this.ipToNumber(range.start);
      const end = this.ipToNumber(range.end);
      
      if (ipNum >= start && ipNum <= end) {
        return true;
      }
    }
    
    return false;
  }
  
  /**
   * Конвертация IP в число
   */
  private ipToNumber(ip: string): number {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }
  
  /**
   * Очистка кэша
   */
  clearCache(): void {
    this.cache.clear();
  }
  
  /**
   * Статистика кэша
   */
  getCacheStats(): { size: number; maxSize: number; utilization: number } {
    return this.cache.getStats();
  }
}

// ============================================================================
// THREAT INTELLIGENCE
// ============================================================================

/**
 * Threat Intelligence сервис
 */
class ThreatIntelService {
  private cache: EnrichmentCache<ThreatIntelResult>;
  private apiKeys: { virustotal?: string; abuseipdb?: string; shodan?: string };
  private timeout: number;
  
  constructor(
    apiKeys: { virustotal?: string; abuseipdb?: string; shodan?: string } = {},
    timeout: number = 5000,
    cacheSize: number = 10000,
    cacheTtl: number = 1800
  ) {
    this.cache = new EnrichmentCache(cacheSize, cacheTtl);
    this.apiKeys = apiKeys;
    this.timeout = timeout;
  }
  
  /**
   * Проверка IP на угрозы
   */
  async checkIP(ip: string): Promise<ThreatIntelResult> {
    // Проверка кэша
    const cached = this.cache.get(ip);
    if (cached) {
      return cached;
    }
    
    const result: ThreatIntelResult = {
      ip,
      isMalicious: false,
      isTor: false,
      isVpn: false,
      isProxy: false,
      reputation: 100,
      categories: [],
      lastReported: null,
      reports: 0
    };
    
    try {
      // Проверка Tor exit nodes
      result.isTor = await this.checkTorExitNode(ip);
      
      // Проверка VPN
      result.isVpn = await this.checkVpn(ip);
      
      // Проверка Proxy
      result.isProxy = await this.checkProxy(ip);
      
      // Проверка репутации в VirusTotal
      if (this.apiKeys.virustotal) {
        const vtResult = await this.checkVirusTotal(ip);
        if (vtResult) {
          result.isMalicious = vtResult.isMalicious;
          result.reputation = vtResult.reputation;
          result.categories = vtResult.categories;
          result.lastReported = vtResult.lastReported;
          result.reports = vtResult.reports;
        }
      }
      
      // Проверка в AbuseIPDB
      if (this.apiKeys.abuseipdb) {
        const abuseResult = await this.checkAbuseIPDB(ip);
        if (abuseResult) {
          result.isMalicious = result.isMalicious || abuseResult.isMalicious;
          result.reputation = Math.min(result.reputation, abuseResult.reputation);
          result.reports = Math.max(result.reports, abuseResult.reports);
        }
      }
      
      // Обновление статуса malicious
      if (result.isTor || result.isVpn || result.isProxy || result.reputation < 50) {
        result.isMalicious = true;
      }
      
      this.cache.set(ip, result);
      return result;
    } catch (error) {
      console.error(`ThreatIntel check failed for ${ip}:`, error);
      return result;
    }
  }
  
  /**
   * Проверка Tor exit node
   */
  private async checkTorExitNode(ip: string): Promise<boolean> {
    // В production загружать список Tor exit nodes регулярно
    // https://check.torproject.org/exit-addresses
    
    // Эмуляция для примера
    return TOR_EXIT_NODES.has(ip);
  }
  
  /**
   * Проверка VPN
   */
  private async checkVpn(ip: string): Promise<boolean> {
    // Проверка через reverse DNS
    try {
      const hostname = await this.reverseDns(ip);
      
      for (const provider of KNOWN_VPN_PROVIDERS) {
        if (hostname.includes(provider)) {
          return true;
        }
      }
    } catch {
      // Игнорируем ошибки DNS
    }
    
    return false;
  }
  
  /**
   * Проверка Proxy
   */
  private async checkProxy(ip: string): Promise<boolean> {
    // В production использовать сервисы типа proxydetect
    // Эмуляция для примера
    return false;
  }
  
  /**
   * Проверка VirusTotal
   */
  private async checkVirusTotal(ip: string): Promise<VirusTotalResult | null> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);
      
      const response = await fetch(
        `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
        {
          signal: controller.signal,
          headers: {
            'x-apikey': this.apiKeys.virustotal!,
            'Accept': 'application/json'
          }
        }
      );
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        return null;
      }
      
      const data = await response.json() as { data?: { attributes?: Record<string, unknown> } };
      const attributes = data.data?.attributes;

      if (!attributes) {
        return null;
      }

      const lastAnalysisStats = attributes.last_analysis_stats as Record<string, number> | undefined;
      const reputation = (attributes.reputation as number) || 0;

      return {
        isMalicious: (lastAnalysisStats?.malicious || 0) > 0,
        reputation: Math.max(0, Math.min(100, 50 + reputation / 10)),
        categories: (attributes.categories as string[]) || [],
        lastReported: (attributes.last_modification_date as string) || '',
        reports: lastAnalysisStats?.malicious || 0
      };
    } catch (error) {
      console.error('VirusTotal check failed:', error);
      return null;
    }
  }
  
  /**
   * Проверка AbuseIPDB
   */
  private async checkAbuseIPDB(ip: string): Promise<AbuseIPDBResult | null> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);
      
      const response = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
        {
          signal: controller.signal,
          headers: {
            'Key': this.apiKeys.abuseipdb!,
            'Accept': 'application/json'
          }
        }
      );
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        return null;
      }
      
      const data = await response.json() as { data?: { abuseConfidenceScore?: number; totalReports?: number } };
      const abuseData = data.data;
      
      return {
        isMalicious: (abuseData?.abuseConfidenceScore || 0) > 10,
        reputation: Math.max(0, 100 - (abuseData?.abuseConfidenceScore || 0)),
        reports: abuseData?.totalReports || 0
      };
    } catch (error) {
      console.error('AbuseIPDB check failed:', error);
      return null;
    }
  }
  
  /**
   * Reverse DNS lookup
   */
  private reverseDns(ip: string): Promise<string> {
    return new Promise((resolve, reject) => {
      dns.reverse(ip, (err, hostnames) => {
        if (err || !hostnames || hostnames.length === 0) {
          reject(err);
        } else {
          resolve(hostnames[0]);
        }
      });
    });
  }
  
  /**
   * Очистка кэша
   */
  clearCache(): void {
    this.cache.clear();
  }
}

/**
 * Результат Threat Intel проверки
 */
interface ThreatIntelResult {
  ip: string;
  isMalicious: boolean;
  isTor: boolean;
  isVpn: boolean;
  isProxy: boolean;
  reputation: number;
  categories: string[];
  lastReported: string | null;
  reports: number;
}

/**
 * Результат VirusTotal
 */
interface VirusTotalResult {
  isMalicious: boolean;
  reputation: number;
  categories: string[];
  lastReported: string;
  reports: number;
}

/**
 * Результат AbuseIPDB
 */
interface AbuseIPDBResult {
  isMalicious: boolean;
  reputation: number;
  reports: number;
}

// ============================================================================
// USER AGENT PARSER
// ============================================================================

/**
 * Парсер User Agent строк
 */
class UserAgentParser {
  /**
   * Парсинг User Agent
   */
  parse(userAgent: string): DeviceInfo {
    if (!userAgent) {
      return { type: 'unknown' };
    }
    
    const device: DeviceInfo = {
      type: this.detectDeviceType(userAgent),
      os: undefined,
      osVersion: undefined,
      browser: undefined,
      browserVersion: undefined
    };
    
    // Определение OS
    for (const { pattern, os, version } of OS_PATTERNS) {
      const match = userAgent.match(pattern);
      if (match) {
        device.os = os;
        device.osVersion = version === '$1' ? (match[1] || '') : version;
        break;
      }
    }
    
    // Определение браузера
    for (const { pattern, browser, version } of BROWSER_PATTERNS) {
      const match = userAgent.match(pattern);
      if (match) {
        device.browser = browser;
        device.browserVersion = version === '$1' ? (match[1] || '') : version;
        break;
      }
    }
    
    return device;
  }
  
  /**
   * Определение типа устройства
   */
  private detectDeviceType(userAgent: string): DeviceInfo['type'] {
    if (UA_PATTERNS.bot.test(userAgent)) {
      return 'unknown'; // Боты не классифицируем
    }
    
    if (UA_PATTERNS.iot.test(userAgent)) {
      return 'iot';
    }
    
    if (UA_PATTERNS.server.test(userAgent)) {
      return 'server';
    }
    
    if (UA_PATTERNS.mobile.test(userAgent)) {
      return 'mobile';
    }
    
    if (UA_PATTERNS.tablet.test(userAgent)) {
      return 'tablet';
    }
    
    if (UA_PATTERNS.desktop.test(userAgent)) {
      return 'desktop';
    }
    
    return 'unknown';
  }
}

// ============================================================================
// ОСНОВНОЙ КЛАСС ENRICHER
// ============================================================================

/**
 * Log Enricher - обогащение логов контекстом
 * 
 * Реализует:
 * - GeoIP обогащение
 * - Threat Intelligence
 * - User Agent парсинг
 * - DNS lookup
 * - Кастомные enrichers
 * - Кэширование результатов
 */
export class LogEnricher extends EventEmitter {
  private config: LogEnricherConfig;
  private geoIPService: GeoIPService;
  private threatIntelService: ThreatIntelService;
  private uaParser: UserAgentParser;
  private cache: EnrichmentCache<Partial<LogContext>>;
  private statistics: EnricherStatistics;
  private enrichmentTimes: number[];
  
  constructor(config: Partial<LogEnricherConfig> = {}) {
    super();
    
    this.config = {
      enableGeoIP: config.enableGeoIP !== false,
      enableThreatIntel: config.enableThreatIntel !== false,
      enableDnsLookup: config.enableDnsLookup || false,
      enableUaParsing: config.enableUaParsing !== false,
      enableCache: config.enableCache !== false,
      cacheSize: config.cacheSize || 10000,
      cacheTtlSeconds: config.cacheTtlSeconds || 3600,
      requestTimeout: config.requestTimeout || 5000,
      apiKeys: config.apiKeys || {},
      customEnrichers: config.customEnrichers || []
    };
    
    // Инициализация сервисов
    this.geoIPService = new GeoIPService(
      this.config.apiKeys.maxmind,
      this.config.requestTimeout,
      this.config.cacheSize,
      this.config.cacheTtlSeconds
    );
    
    this.threatIntelService = new ThreatIntelService(
      {
        virustotal: this.config.apiKeys.virustotal,
        abuseipdb: this.config.apiKeys.abuseipdb,
        shodan: this.config.apiKeys.shodan
      },
      this.config.requestTimeout,
      this.config.cacheSize,
      Math.floor(this.config.cacheTtlSeconds / 2)
    );
    
    this.uaParser = new UserAgentParser();
    this.cache = new EnrichmentCache(this.config.cacheSize, this.config.cacheTtlSeconds);
    
    // Инициализация статистики
    this.statistics = this.createInitialStatistics();
    this.enrichmentTimes = [];
  }
  
  /**
   * Создание начальной статистики
   */
  private createInitialStatistics(): EnricherStatistics {
    return {
      totalProcessed: 0,
      successCount: 0,
      errorCount: 0,
      cacheHits: 0,
      cacheMisses: 0,
      cacheHitRate: 0,
      avgEnrichmentTime: 0,
      p99EnrichmentTime: 0,
      byEnricher: {},
      geoIP: {
        uniqueCountries: 0,
        uniqueCities: 0,
        topCountries: {}
      },
      threatIntel: {
        maliciousIpsDetected: 0,
        torExitsDetected: 0,
        vpnDetected: 0,
        proxyDetected: 0
      }
    };
  }
  
  /**
   * Обогащение лога
   */
  async enrich(log: LogEntry): Promise<EnrichmentResult> {
    const startTime = Date.now();
    this.statistics.totalProcessed++;
    
    const appliedEnrichers: string[] = [];
    const errors: ProcessingError[] = [];
    let cacheHits = 0;
    let cacheMisses = 0;
    
    try {
      // Проверка кэша
      const cacheKey = this.getCacheKey(log);
      let cachedContext: Partial<LogContext> | null = null;
      
      if (this.config.enableCache) {
        cachedContext = this.cache.get(cacheKey);
        if (cachedContext) {
          cacheHits++;
          this.statistics.cacheHits++;
        } else {
          cacheMisses++;
          this.statistics.cacheMisses++;
        }
      }
      
      // Создание enriched контекста
      const enrichedContext: LogContext = {
        ...log.context,
        ...cachedContext
      };
      
      // GeoIP обогащение
      if (this.config.enableGeoIP && log.context.clientIp && !cachedContext?.geoLocation) {
        try {
          const enricherStart = Date.now();
          const geoLocation = await this.geoIPService.lookup(log.context.clientIp);
          
          if (geoLocation) {
            enrichedContext.geoLocation = geoLocation;
            appliedEnrichers.push('geoip');
            this.updateEnricherStats('geoip', true, Date.now() - enricherStart);
            this.updateGeoIPStats(geoLocation);
          }
        } catch (error) {
          errors.push({
            stage: 'geoip_enrichment',
            code: 'GEOIP_ERROR',
            message: error instanceof Error ? error.message : String(error),
            recoverable: true
          });
          this.updateEnricherStats('geoip', false, 0);
        }
      }
      
      // Threat Intelligence обогащение
      if (this.config.enableThreatIntel && log.context.clientIp) {
        try {
          const enricherStart = Date.now();
          const threatInfo = await this.threatIntelService.checkIP(log.context.clientIp);
          
          enrichedContext.metadata = {
            ...enrichedContext.metadata,
            threatIntel: {
              isMalicious: threatInfo.isMalicious,
              isTor: threatInfo.isTor,
              isVpn: threatInfo.isVpn,
              isProxy: threatInfo.isProxy,
              reputation: threatInfo.reputation,
              categories: threatInfo.categories,
              lastReported: threatInfo.lastReported,
              reports: threatInfo.reports
            }
          };
          
          appliedEnrichers.push('threat_intel');
          this.updateEnricherStats('threat_intel', true, Date.now() - enricherStart);
          this.updateThreatIntelStats(threatInfo);
        } catch (error) {
          errors.push({
            stage: 'threat_intel_enrichment',
            code: 'THREAT_INTEL_ERROR',
            message: error instanceof Error ? error.message : String(error),
            recoverable: true
          });
          this.updateEnricherStats('threat_intel', false, 0);
        }
      }
      
      // User Agent парсинг
      if (this.config.enableUaParsing && log.context.userAgent && !cachedContext?.device) {
        try {
          const enricherStart = Date.now();
          const device = this.uaParser.parse(log.context.userAgent);
          
          enrichedContext.device = device;
          appliedEnrichers.push('ua_parser');
          this.updateEnricherStats('ua_parser', true, Date.now() - enricherStart);
        } catch (error) {
          errors.push({
            stage: 'ua_parser_enrichment',
            code: 'UA_PARSER_ERROR',
            message: error instanceof Error ? error.message : String(error),
            recoverable: true
          });
          this.updateEnricherStats('ua_parser', false, 0);
        }
      }
      
      // DNS lookup
      if (this.config.enableDnsLookup && log.context.clientIp) {
        try {
          const enricherStart = Date.now();
          const hostname = await this.reverseDns(log.context.clientIp);
          
          enrichedContext.metadata = {
            ...enrichedContext.metadata,
            reverseDns: hostname
          };
          
          appliedEnrichers.push('dns_lookup');
          this.updateEnricherStats('dns_lookup', true, Date.now() - enricherStart);
        } catch (error) {
          // DNS ошибки не критичны, просто логируем
          this.updateEnricherStats('dns_lookup', false, 0);
        }
      }
      
      // Кастомные enrichers
      if (this.config.customEnrichers) {
        for (const enricherFn of this.config.customEnrichers) {
          try {
            const enricherStart = Date.now();
            const customContext = await enricherFn(log);
            
            Object.assign(enrichedContext, customContext);
            appliedEnrichers.push('custom');
            this.updateEnricherStats('custom', true, Date.now() - enricherStart);
          } catch (error) {
            errors.push({
              stage: 'custom_enrichment',
              code: 'CUSTOM_ENRICHER_ERROR',
              message: error instanceof Error ? error.message : String(error),
              recoverable: true
            });
            this.updateEnricherStats('custom', false, 0);
          }
        }
      }
      
      // Сохранение в кэш
      if (this.config.enableCache && appliedEnrichers.length > 0) {
        this.cache.set(cacheKey, enrichedContext);
      }
      
      // Создание обогащенного лога
      const enrichedLog: LogEntry = {
        ...log,
        context: enrichedContext
      };
      
      // Обновление статистики
      const enrichmentTime = Date.now() - startTime;
      this.updateEnrichmentTimeStats(enrichmentTime);
      
      if (errors.length === 0) {
        this.statistics.successCount++;
      } else {
        this.statistics.errorCount++;
      }
      
      return {
        log: enrichedLog,
        success: errors.length === 0 || enrichedLog.context.geoLocation !== undefined,
        appliedEnrichers,
        errors,
        enrichmentTime,
        cacheHits,
        cacheMisses
      };
    } catch (error) {
      this.statistics.errorCount++;
      
      return {
        log,
        success: false,
        appliedEnrichers,
        errors: [{
          stage: 'enrichment',
          code: 'ENRICHMENT_ERROR',
          message: error instanceof Error ? error.message : String(error),
          recoverable: true
        }],
        enrichmentTime: Date.now() - startTime,
        cacheHits,
        cacheMisses
      };
    }
  }
  
  /**
   * Пакетное обогащение
   */
  async enrichBatch(logs: LogEntry[]): Promise<EnrichmentResult[]> {
    return Promise.all(logs.map(log => this.enrich(log)));
  }
  
  /**
   * Получение ключа для кэша
   *
   * БЕЗОПАСНОСТЬ: Используем SHA-256 вместо MD5
   * MD5 считается криптографически небезопасным (CWE-328)
   */
  private getCacheKey(log: LogEntry): string {
    const parts = [
      log.context.clientIp || '',
      log.context.userAgent || '',
      log.context.userId || ''
    ];

    // ИСПОЛЬЗУЕМ SHA-256 вместо MD5 для соответствия современным стандартам безопасности
    return crypto.createHash('sha256').update(parts.join('|')).digest('hex');
  }
  
  /**
   * Reverse DNS lookup
   */
  private reverseDns(ip: string): Promise<string> {
    return new Promise((resolve, reject) => {
      dns.reverse(ip, (err, hostnames) => {
        if (err || !hostnames || hostnames.length === 0) {
          reject(err || new Error('No hostname found'));
        } else {
          resolve(hostnames[0]);
        }
      });
    });
  }
  
  /**
   * Обновление статистики enricher
   */
  private updateEnricherStats(name: string, success: boolean, time: number): void {
    if (!this.statistics.byEnricher[name]) {
      this.statistics.byEnricher[name] = {
        count: 0,
        successes: 0,
        failures: 0,
        avgTime: 0
      };
    }
    
    const stats = this.statistics.byEnricher[name];
    stats.count++;
    
    if (success) {
      stats.successes++;
    } else {
      stats.failures++;
    }
    
    // Обновление среднего времени
    stats.avgTime = (stats.avgTime * (stats.count - 1) + time) / stats.count;
  }
  
  /**
   * Обновление GeoIP статистики
   */
  private updateGeoIPStats(geo: GeoLocation): void {
    if (geo.countryCode) {
      this.statistics.geoIP.topCountries[geo.countryCode] = 
        (this.statistics.geoIP.topCountries[geo.countryCode] || 0) + 1;
    }
  }
  
  /**
   * Обновление Threat Intel статистики
   */
  private updateThreatIntelStats(threat: ThreatIntelResult): void {
    if (threat.isMalicious) {
      this.statistics.threatIntel.maliciousIpsDetected++;
    }
    if (threat.isTor) {
      this.statistics.threatIntel.torExitsDetected++;
    }
    if (threat.isVpn) {
      this.statistics.threatIntel.vpnDetected++;
    }
    if (threat.isProxy) {
      this.statistics.threatIntel.proxyDetected++;
    }
  }
  
  /**
   * Обновление статистики времени обогащения
   */
  private updateEnrichmentTimeStats(time: number): void {
    this.enrichmentTimes.push(time);
    
    // Ограничение размера массива
    if (this.enrichmentTimes.length > 1000) {
      this.enrichmentTimes.shift();
    }
    
    // Расчет average
    this.statistics.avgEnrichmentTime = 
      this.enrichmentTimes.reduce((a, b) => a + b, 0) / this.enrichmentTimes.length;
    
    // Расчет P99
    const sorted = [...this.enrichmentTimes].sort((a, b) => a - b);
    const p99Index = Math.floor(sorted.length * 0.99);
    this.statistics.p99EnrichmentTime = sorted[p99Index] || 0;
    
    // Расчет cache hit rate
    const totalCacheOps = this.statistics.cacheHits + this.statistics.cacheMisses;
    if (totalCacheOps > 0) {
      this.statistics.cacheHitRate = this.statistics.cacheHits / totalCacheOps;
    }
  }
  
  /**
   * Получение статистики
   */
  getStatistics(): EnricherStatistics {
    return { ...this.statistics };
  }
  
  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = this.createInitialStatistics();
    this.enrichmentTimes = [];
  }
  
  /**
   * Очистка кэша
   */
  clearCache(): void {
    this.cache.clear();
    this.geoIPService.clearCache();
    this.threatIntelService.clearCache();
  }
  
  /**
   * Периодическая очистка кэша
   */
  startCacheCleanup(intervalSeconds: number = 300): void {
    setInterval(() => {
      const removed = this.cache.cleanup();
      if (removed > 0) {
        this.emit('cache_cleanup', { removed });
      }
    }, intervalSeconds * 1000);
  }
  
  /**
   * Добавление кастомного enricher
   */
  addCustomEnricher(fn: EnricherFunction): void {
    if (this.config.customEnrichers) {
      this.config.customEnrichers.push(fn);
    }
  }
  
  /**
   * Обновление API ключей
   */
  updateApiKeys(apiKeys: LogEnricherConfig['apiKeys']): void {
    this.config.apiKeys = { ...this.config.apiKeys, ...apiKeys };
  }
}

// ============================================================================
// ЭКСПОРТ
// ============================================================================

export default LogEnricher;
