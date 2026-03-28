/**
 * =============================================================================
 * DEVICE FINGERPRINT SERVICE
 * =============================================================================
 * Сервис для создания и управления отпечатками устройств
 * Используется для: обнаружения мошенничества, trusted devices, security analytics
 * Соответствует: OWASP Device Fingerprinting guidelines
 * =============================================================================
 */

import { createHash, randomBytes } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import * as UAParser from 'ua-parser-js';
import * as geoip from 'geoip-lite';
import {
  DeviceFingerprintData,
  ISession,
  IUser,
  AuthError,
  AuthErrorCode,
} from '../types/auth.types';

/**
 * Конфигурация DeviceFingerprint сервиса
 */
export interface DeviceFingerprintConfig {
  /** Минимальное количество совпадений для идентификации */
  minMatchScore: number;
  
  /** Срок жизни отпечатка (дни) */
  fingerprintTTL: number;
  
  /** Порог доверия для trusted device */
  trustThreshold: number;
  
  /** Включить ли анализ canvas fingerprint */
  enableCanvasFingerprint: boolean;
  
  /** Включить ли анализ WebGL fingerprint */
  enableWebglFingerprint: boolean;
  
  /** Включить ли анализ audio fingerprint */
  enableAudioFingerprint: boolean;
  
  /** Включить ли анализ шрифтов */
  enableFontFingerprint: boolean;
  
  /** Вес различных компонентов в scoring */
  weights: {
    userAgent: number;
    languages: number;
    timezone: number;
    screen: number;
    platform: number;
    hardware: number;
    browser: number;
    canvas: number;
    webgl: number;
    audio: number;
    fonts: number;
  };
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: DeviceFingerprintConfig = {
  minMatchScore: 0.7,
  fingerprintTTL: 90, // 90 дней
  trustThreshold: 0.85,
  enableCanvasFingerprint: true,
  enableWebglFingerprint: true,
  enableAudioFingerprint: true,
  enableFontFingerprint: true,
  weights: {
    userAgent: 0.15,
    languages: 0.08,
    timezone: 0.05,
    screen: 0.10,
    platform: 0.12,
    hardware: 0.10,
    browser: 0.10,
    canvas: 0.08,
    webgl: 0.07,
    audio: 0.05,
    fonts: 0.10,
  },
};

/**
 * Входные данные для создания отпечатка
 */
export interface FingerprintInput {
  /** User-Agent строка */
  userAgent: string;
  
  /** Принятые языки */
  languages: string[];
  
  /** Часовой пояс */
  timezone: string;
  
  /** Разрешение экрана */
  screenResolution?: string;
  
  /** Глубина цвета */
  colorDepth?: number;
  
  /** Платформа */
  platform?: string;
  
  /** Архитектура CPU */
  cpuArchitecture?: string;
  
  /** Количество ядер CPU */
  cpuCores?: number;
  
  /** Объем памяти (GB) */
  deviceMemory?: number;
  
  /** Поддерживаемые API */
  supportedApis?: string[];
  
  /** Canvas fingerprint (hex) */
  canvasFingerprint?: string;
  
  /** WebGL fingerprint */
  webglFingerprint?: string;
  
  /** Audio fingerprint */
  audioFingerprint?: string;
  
  /** Список шрифтов */
  fonts?: string[];
  
  /** IP адрес */
  ipAddress: string;
  
  /** Do Not Track */
  doNotTrack?: string;
  
  /** Touch support */
  touchSupport?: {
    maxTouchPoints: number;
    touchEvent: boolean;
    touchAction: boolean;
  };
  
  /** Battery status */
  battery?: {
    charging: boolean;
    level: number;
  };
  
  /** Network information */
  network?: {
    connection: string;
    rtt: number;
    downlink: number;
  };
}

/**
 * Результат анализа отпечатка
 */
export interface FingerprintAnalysisResult {
  /** Сгенерированный fingerprint */
  fingerprint: string;
  
  /** Score совпадения с существующим (если есть) */
  matchScore?: number;
  
  /** Существующий fingerprint (если найден) */
  existingFingerprint?: DeviceFingerprintData;
  
  /** Является ли устройство новым */
  isNewDevice: boolean;
  
  /** Оценка риска (0-100) */
  riskScore: number;
  
  /** Факторы риска */
  riskFactors: string[];
  
  /** Рекомендации */
  recommendations: string[];
}

/**
 * Разобранные данные User-Agent
 */
interface ParsedUserAgent {
  browser: { name: string; version: string };
  os: { name: string; version: string };
  device: { type: string; vendor: string; model: string };
  cpu: { architecture: string };
}

/**
 * =============================================================================
 * DEVICE FINGERPRINT SERVICE CLASS
 * =============================================================================
 */
export class DeviceFingerprintService {
  private config: DeviceFingerprintConfig;
  private fingerprints: Map<string, DeviceFingerprintData> = new Map();

  /**
   * Создает новый экземпляр DeviceFingerprintService
   * @param config - Конфигурация сервиса
   */
  constructor(config: DeviceFingerprintConfig = DEFAULT_CONFIG) {
    this.config = config;
    
    // Очистка старых отпечатков
    setInterval(() => this.cleanupOldFingerprints(), 60 * 60 * 1000);
  }

  // ===========================================================================
  // ГЕНЕРАЦИЯ FINGERPRINT
  // ===========================================================================

  /**
   * Генерирует отпечаток устройства из входных данных
   * @param input - Входные данные
   * @returns Сгенерированный fingerprint
   */
  public generateFingerprint(input: FingerprintInput): string {
    try {
      // Компоненты для хэширования
      const components: string[] = [];

      // 1. User-Agent (основной компонент)
      components.push(input.userAgent.toLowerCase());

      // 2. Языки
      if (input.languages && input.languages.length > 0) {
        components.push(input.languages.join('|').toLowerCase());
      }

      // 3. Часовой пояс
      if (input.timezone) {
        components.push(input.timezone);
      }

      // 4. Разрешение экрана
      if (input.screenResolution) {
        components.push(input.screenResolution);
      }

      // 5. Глубина цвета
      if (input.colorDepth) {
        components.push(input.colorDepth.toString());
      }

      // 6. Платформа
      if (input.platform) {
        components.push(input.platform.toLowerCase());
      }

      // 7. CPU информация
      if (input.cpuArchitecture) {
        components.push(input.cpuArchitecture.toLowerCase());
      }
      if (input.cpuCores) {
        components.push(input.cpuCores.toString());
      }

      // 8. Память устройства
      if (input.deviceMemory) {
        components.push(input.deviceMemory.toString());
      }

      // 9. Поддерживаемые API
      if (input.supportedApis && input.supportedApis.length > 0) {
        components.push(input.supportedApis.sort().join('|'));
      }

      // 10. Canvas fingerprint
      if (this.config.enableCanvasFingerprint && input.canvasFingerprint) {
        components.push(input.canvasFingerprint.toLowerCase());
      }

      // 11. WebGL fingerprint
      if (this.config.enableWebglFingerprint && input.webglFingerprint) {
        components.push(input.webglFingerprint.toLowerCase());
      }

      // 12. Audio fingerprint
      if (this.config.enableAudioFingerprint && input.audioFingerprint) {
        components.push(input.audioFingerprint.toLowerCase());
      }

      // 13. Шрифты
      if (this.config.enableFontFingerprint && input.fonts && input.fonts.length > 0) {
        components.push(input.fonts.sort().join('|').toLowerCase());
      }

      // 14. Touch support
      if (input.touchSupport) {
        components.push(
          `${input.touchSupport.maxTouchPoints}|${input.touchSupport.touchEvent}|${input.touchSupport.touchAction}`
        );
      }

      // 15. Do Not Track
      if (input.doNotTrack) {
        components.push(input.doNotTrack);
      }

      // Создание хэша
      const hashInput = components.join('::');
      const hash = createHash('sha256').update(hashInput).digest('hex');

      // Укороченная версия для удобства (первые 64 символа)
      return hash;
    } catch (error) {
      throw new AuthError(
        `Ошибка генерации fingerprint: ${error instanceof Error ? error.message : 'Unknown error'}`,
        AuthErrorCode.INTERNAL_ERROR,
        500
      );
    }
  }

  // ===========================================================================
  // АНАЛИЗ И СРАВНЕНИЕ
  // ===========================================================================

  /**
   * Анализирует отпечаток и сравнивает с существующими
   * @param input - Входные данные
   * @param existingFingerprints - Существующие отпечатки
   * @returns Результат анализа
   */
  public analyzeFingerprint(
    input: FingerprintInput,
    existingFingerprints: DeviceFingerprintData[] = []
  ): FingerprintAnalysisResult {
    const newFingerprint = this.generateFingerprint(input);
    const riskFactors: string[] = [];
    const recommendations: string[] = [];

    // Поиск совпадений
    let bestMatch: DeviceFingerprintData | null = null;
    let bestScore = 0;

    for (const existing of existingFingerprints) {
      const score = this.calculateMatchScore(input, existing);
      if (score > bestScore) {
        bestScore = score;
        bestMatch = existing;
      }
    }

    const isNewDevice = bestScore < this.config.minMatchScore;

    // Расчет risk score
    let riskScore = 0;

    // Фактор 1: Новое устройство
    if (isNewDevice) {
      riskScore += 30;
      riskFactors.push('Новое устройство');
      recommendations.push('Требуется дополнительная верификация');
    }

    // Фактор 2: Низкий score совпадения
    if (bestScore > 0 && bestScore < this.config.trustThreshold) {
      riskScore += 20;
      riskFactors.push('Частичное совпадение отпечатка');
      recommendations.push('Проверить изменения в конфигурации устройства');
    }

    // Фактор 3: Анонимайзеры / VPN
    if (this.detectProxyOrVpn(input.ipAddress)) {
      riskScore += 25;
      riskFactors.push('Обнаружен VPN/Proxy');
      recommendations.push('Проверить геолокацию пользователя');
    }

    // Фактор 4: Подозрительный User-Agent
    if (this.isSuspiciousUserAgent(input.userAgent)) {
      riskScore += 20;
      riskFactors.push('Подозрительный User-Agent');
      recommendations.push('Проверить на автоматизированный доступ');
    }

    // Фактор 5: Несоответствие платформы и User-Agent
    const parsedUA = this.parseUserAgent(input.userAgent);
    if (input.platform && parsedUA.os.name) {
      const platformMismatch = this.detectPlatformMismatch(input.platform, parsedUA.os.name);
      if (platformMismatch) {
        riskScore += 15;
        riskFactors.push('Несоответствие платформы');
      }
    }

    // Фактор 6: Географическая аномалия
    const geoLocation = geoip.lookup(input.ipAddress);
    if (geoLocation) {
      // Проверка на известные проблемные регионы
      if (this.isHighRiskCountry(geoLocation.country)) {
        riskScore += 10;
        riskFactors.push(`Высокорисковый регион: ${geoLocation.country}`);
      }
    }

    // Нормализация risk score
    riskScore = Math.min(100, riskScore);

    // Определение уровня риска
    if (riskScore >= 70) {
      recommendations.push('Рекомендуется блокировка и ручная проверка');
    } else if (riskScore >= 40) {
      recommendations.push('Требуется MFA аутентификация');
    } else if (riskScore >= 20) {
      recommendations.push('Мониторинг активности');
    }

    return {
      fingerprint: newFingerprint,
      matchScore: bestScore,
      existingFingerprint: bestMatch || undefined,
      isNewDevice,
      riskScore,
      riskFactors,
      recommendations,
    };
  }

  /**
   * Вычисляет score совпадения между входными данными и существующим отпечатком
   * @private
   */
  private calculateMatchScore(
    input: FingerprintInput,
    existing: DeviceFingerprintData
  ): number {
    let totalScore = 0;
    let totalWeight = 0;

    const weights = this.config.weights;

    // 1. User-Agent match
    if (input.userAgent === existing.userAgent) {
      totalScore += weights.userAgent;
    } else if (this.userAgentSimilarity(input.userAgent, existing.userAgent) > 0.8) {
      totalScore += weights.userAgent * 0.5;
    }
    totalWeight += weights.userAgent;

    // 2. Languages match
    if (
      input.languages &&
      existing.languages &&
      this.arraysEqual(input.languages, existing.languages)
    ) {
      totalScore += weights.languages;
    }
    totalWeight += weights.languages;

    // 3. Timezone match
    if (input.timezone === existing.timezone) {
      totalScore += weights.timezone;
    }
    totalWeight += weights.timezone;

    // 4. Screen resolution match
    if (input.screenResolution === existing.screenResolution) {
      totalScore += weights.screen;
    }
    totalWeight += weights.screen;

    // 5. Platform match
    if (input.platform === existing.platform) {
      totalScore += weights.platform;
    }
    totalWeight += weights.platform;

    // 6. Hardware match
    if (
      input.cpuArchitecture === existing.cpuArchitecture &&
      input.cpuCores === existing.cpuCores &&
      input.deviceMemory === existing.deviceMemory
    ) {
      totalScore += weights.hardware;
    }
    totalWeight += weights.hardware;

    // 7. Canvas fingerprint match
    if (
      this.config.enableCanvasFingerprint &&
      input.canvasFingerprint &&
      input.canvasFingerprint === existing.canvasFingerprint
    ) {
      totalScore += weights.canvas;
    }
    totalWeight += weights.canvas;

    // 8. WebGL fingerprint match
    if (
      this.config.enableWebglFingerprint &&
      input.webglFingerprint &&
      input.webglFingerprint === existing.webglFingerprint
    ) {
      totalScore += weights.webgl;
    }
    totalWeight += weights.webgl;

    // 9. Audio fingerprint match
    if (
      this.config.enableAudioFingerprint &&
      input.audioFingerprint &&
      input.audioFingerprint === existing.audioFingerprint
    ) {
      totalScore += weights.audio;
    }
    totalWeight += weights.audio;

    // 10. Fonts match
    if (
      this.config.enableFontFingerprint &&
      input.fonts &&
      existing.fonts &&
      this.arraysEqual(input.fonts, existing.fonts)
    ) {
      totalScore += weights.fonts;
    }
    totalWeight += weights.fonts;

    return totalWeight > 0 ? totalScore / totalWeight : 0;
  }

  // ===========================================================================
  // УПРАВЛЕНИЕ ДОВЕРЕННЫМИ УСТРОЙСТВАМИ
  // ===========================================================================

  /**
   * Отмечает устройство как доверенное
   * @param fingerprint - Отпечаток устройства
   * @param userId - ID пользователя
   * @returns Обновленные данные устройства
   */
  public trustDevice(fingerprint: string, userId: string): DeviceFingerprintData {
    const existing = this.fingerprints.get(fingerprint);
    
    if (existing) {
      existing.isTrusted = true;
      existing.lastSeenAt = new Date();
      existing.usageCount++;
      this.fingerprints.set(fingerprint, existing);
      return existing;
    }

    // Создаем новый entry
    const newDevice: DeviceFingerprintData = {
      fingerprint,
      userAgent: '',
      languages: [],
      timezone: '',
      screenResolution: '',
      colorDepth: 0,
      platform: '',
      isTrusted: true,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      usageCount: 1,
      supportedApis: [],
    };

    this.fingerprints.set(fingerprint, newDevice);
    return newDevice;
  }

  /**
   * Удаляет доверие к устройству
   * @param fingerprint - Отпечаток устройства
   */
  public untrustDevice(fingerprint: string): void {
    const existing = this.fingerprints.get(fingerprint);
    if (existing) {
      existing.isTrusted = false;
      this.fingerprints.set(fingerprint, existing);
    }
  }

  /**
   * Проверяет, является ли устройство доверенным
   * @param fingerprint - Отпечаток устройства
   * @returns Является ли доверенным
   */
  public isTrustedDevice(fingerprint: string): boolean {
    const existing = this.fingerprints.get(fingerprint);
    return existing?.isTrusted ?? false;
  }

  /**
   * Получает все доверенные устройства пользователя
   * @param userId - ID пользователя
   * @returns Массив доверенных устройств
   */
  public getTrustedDevices(userId: string): DeviceFingerprintData[] {
    return Array.from(this.fingerprints.values()).filter(
      device => device.isTrusted
    );
  }

  // ===========================================================================
  // ДЕТЕКЦИЯ АНОМАЛИЙ
  // ===========================================================================

  /**
   * Обнаруживает использование VPN/Proxy
   * @private
   */
  private detectProxyOrVpn(ipAddress: string): boolean {
    // Упрощенная проверка (в production использовать API типа IPQualityScore)
    const knownProxyRanges = [
      // Частные диапазоны (для локального тестирования)
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      // Известные VPN провайдеры (пример)
      /^23\.(16|17|18|19)\./, // Некоторые VPN
    ];

    return knownProxyRanges.some(pattern => pattern.test(ipAddress));
  }

  /**
   * Проверяет User-Agent на подозрительность
   * @private
   */
  private isSuspiciousUserAgent(userAgent: string): boolean {
    const suspiciousPatterns = [
      /curl/i,
      /wget/i,
      /python-requests/i,
      /httpclient/i,
      /java\//i,
      /bot/i,
      /spider/i,
      /crawler/i,
      /scraper/i,
      /^\s*$/, // Пустой UA
      /undefined/i,
    ];

    return suspiciousPatterns.some(pattern => pattern.test(userAgent));
  }

  /**
   * Обнаруживает несоответствие платформы
   * @private
   */
  private detectPlatformMismatch(platform: string, osName: string): boolean {
    const platformLower = platform.toLowerCase();
    const osLower = osName.toLowerCase();

    // Проверка на явные несоответствия
    if (platformLower.includes('win') && !osLower.includes('windows')) {
      return true;
    }
    if (platformLower.includes('mac') && !osLower.includes('mac')) {
      return true;
    }
    if (platformLower.includes('linux') && !osLower.includes('linux')) {
      return true;
    }
    if (platformLower.includes('android') && !osLower.includes('android')) {
      return true;
    }
    if (platformLower.includes('iphone') && !osLower.includes('ios')) {
      return true;
    }

    return false;
  }

  /**
   * Проверяет страну на высокий риск
   * @private
   */
  private isHighRiskCountry(countryCode: string): boolean {
    // Упрощенный список (в production использовать актуальные данные)
    const highRiskCountries: string[] = [
      // Список стран с высоким уровнем киберпреступности
      // Это пример, не отражает реальную ситуацию
    ];

    return highRiskCountries.includes(countryCode);
  }

  /**
   * Вычисляет схожесть User-Agent строк
   * @private
   */
  private userAgentSimilarity(ua1: string, ua2: string): number {
    // Упрощенное сравнение по основным компонентам
    const parse1 = this.parseUserAgent(ua1);
    const parse2 = this.parseUserAgent(ua2);

    let matches = 0;
    let total = 0;

    if (parse1.browser.name === parse2.browser.name) matches++;
    total++;

    if (parse1.os.name === parse2.os.name) matches++;
    total++;

    if (parse1.device.type === parse2.device.type) matches++;
    total++;

    return matches / total;
  }

  /**
   * Разбирает User-Agent строку
   * @private
   */
  private parseUserAgent(userAgent: string): ParsedUserAgent {
    const parser = new UAParser.UAParser(userAgent);
    const result = parser.getResult();

    return {
      browser: {
        name: result.browser.name || 'Unknown',
        version: result.browser.version || '0',
      },
      os: {
        name: result.os.name || 'Unknown',
        version: result.os.version || '0',
      },
      device: {
        type: result.device.type || 'desktop',
        vendor: result.device.vendor || 'Unknown',
        model: result.device.model || 'Unknown',
      },
      cpu: {
        architecture: result.cpu.architecture || 'Unknown',
      },
    };
  }

  /**
   * Проверяет равенство массивов
   * @private
   */
  private arraysEqual(a: any[], b: any[]): boolean {
    if (a.length !== b.length) return false;
    return a.every((item, index) => item === b[index]);
  }

  // ===========================================================================
  // УТИЛИТЫ
  // ===========================================================================

  /**
   * Очистка старых отпечатков
   * @private
   */
  private cleanupOldFingerprints(): void {
    const now = Date.now();
    const ttlMs = this.config.fingerprintTTL * 24 * 60 * 60 * 1000;

    for (const [fingerprint, data] of this.fingerprints.entries()) {
      const lastSeen = data.lastSeenAt.getTime();
      if (now - lastSeen > ttlMs) {
        this.fingerprints.delete(fingerprint);
      }
    }
  }

  /**
   * Сохраняет отпечаток в хранилище
   * @param fingerprint - Данные отпечатка
   */
  public saveFingerprint(fingerprint: DeviceFingerprintData): void {
    this.fingerprints.set(fingerprint.fingerprint, fingerprint);
  }

  /**
   * Получает отпечаток по хэшу
   * @param fingerprint - Хэш отпечатка
   * @returns Данные отпечатка или undefined
   */
  public getFingerprint(fingerprint: string): DeviceFingerprintData | undefined {
    return this.fingerprints.get(fingerprint);
  }

  /**
   * Получает все отпечатки
   * @returns Массив всех отпечатков
   */
  public getAllFingerprints(): DeviceFingerprintData[] {
    return Array.from(this.fingerprints.values());
  }

  /**
   * Удаляет отпечаток
   * @param fingerprint - Хэш отпечатка
   */
  public deleteFingerprint(fingerprint: string): boolean {
    return this.fingerprints.delete(fingerprint);
  }

  /**
   * Получает статистику
   * @returns Статистика отпечатков
   */
  public getStats(): {
    total: number;
    trusted: number;
    untrusted: number;
  } {
    const all = Array.from(this.fingerprints.values());
    return {
      total: all.length,
      trusted: all.filter(d => d.isTrusted).length,
      untrusted: all.filter(d => !d.isTrusted).length,
    };
  }

  /**
   * Генерирует уникальный ID устройства
   * @returns UUID устройства
   */
  public generateDeviceId(): string {
    return uuidv4();
  }

  /**
   * Извлекает геоинформацию из IP
   * @param ipAddress - IP адрес
   * @returns Геоинформация
   */
  public getGeoLocation(ipAddress: string): {
    country: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
    timezone: string;
  } | null {
    const geo = geoip.lookup(ipAddress);
    if (!geo) return null;

    return {
      country: geo.country,
      region: geo.region || '',
      city: geo.city || '',
      latitude: geo.ll[0],
      longitude: geo.ll[1],
      timezone: geo.timezone || 'UTC',
    };
  }
}

/**
 * Экспорт экземпляра по умолчанию
 */
export const deviceFingerprintService = new DeviceFingerprintService(DEFAULT_CONFIG);

/**
 * Фабричная функция для создания сервиса с кастомной конфигурацией
 */
export function createDeviceFingerprintService(
  config: Partial<DeviceFingerprintConfig>
): DeviceFingerprintService {
  return new DeviceFingerprintService({ ...DEFAULT_CONFIG, ...config });
}
