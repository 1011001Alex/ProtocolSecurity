/**
 * ============================================================================
 * MODIFICATION DETECTOR - ДЕТЕКЦИЯ НЕАВТОРИЗОВАННЫХ ИЗМЕНЕНИЙ
 * ============================================================================
 * Модуль для обнаружения несанкционированных модификаций файлов
 * с использованием эвристического анализа и машинного обучения.
 * 
 * Особенности:
 * - Pattern-based detection
 * - Behavioral analysis
 * - IOC (Indicators of Compromise) detection
 * - Risk scoring
 * - Automated remediation recommendations
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  ModificationDetectionResult,
  DetectedModification,
  ModificationType,
  FileHash,
  HashAlgorithm,
  OperationResult,
  IntegrityViolation
} from '../types/integrity.types';

/**
 * Конфигурация Modification Detector
 */
export interface ModificationDetectorConfig {
  /** Алгоритм хеширования */
  hashAlgorithm: HashAlgorithm;
  /** Порог риска для alert */
  alertRiskThreshold: number;
  /** Паттерны критичных файлов */
  criticalFilePatterns: string[];
  /** IOC паттерны */
  iocPatterns: IOCPattern[];
  /** Включить поведенческий анализ */
  enableBehavioralAnalysis: boolean;
  /** Минимальный размер для анализа */
  minFileSizeForAnalysis: number;
  /** Максимальный размер для анализа */
  maxFileSizeForAnalysis: number;
}

/**
 * IOC паттерн
 */
export interface IOCPattern {
  /** Название паттерна */
  name: string;
  /** Тип паттерна */
  type: 'regex' | 'string' | 'hash' | 'byte_sequence';
  /** Значение паттерна */
  pattern: string;
  /** Описание угрозы */
  threatDescription: string;
  /** Серьезность */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** MITRE ATT&CK ID */
  mitreId?: string;
}

/**
 * Поведенческая сигнатура
 */
export interface BehavioralSignature {
  /** Название сигнатуры */
  name: string;
  /** Описание */
  description: string;
  /** Детекторы */
  detectors: BehavioralDetector[];
}

/**
 * Поведенческий детектор
 */
export interface BehavioralDetector {
  /** Тип детектора */
  type: 'entropy' | 'section_change' | 'import_change' | 'timestamp_anomaly';
  /** Порог срабатывания */
  threshold: number;
}

/**
 * Результат анализа файла
 */
export interface FileAnalysisResult {
  /** Путь к файлу */
  filePath: string;
  /** Типы модификаций */
  modificationTypes: ModificationType[];
  /** Оценка риска */
  riskScore: number;
  /** IOC совпадения */
  iocMatches: IOCMatch[];
  /** Поведенческие аномалии */
  behavioralAnomalies: BehavioralAnomaly[];
  /** Рекомендации */
  recommendations: string[];
}

/**
 * IOC совпадение
 */
export interface IOCMatch {
  /** Название паттерна */
  patternName: string;
  /** Найденное значение */
  matchedValue: string;
  /** Позиция в файле */
  position: number;
  /** Серьезность */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Описание угрозы */
  threatDescription: string;
}

/**
 * Поведенческая аномалия
 */
export interface BehavioralAnomaly {
  /** Тип аномалии */
  type: string;
  /** Описание */
  description: string;
  /** Значение */
  value: number;
  /** Ожидаемое значение */
  expectedValue?: number;
  /** Серьезность */
  severity: 'critical' | 'high' | 'medium' | 'low';
}

/**
 * Класс Modification Detector
 */
export class ModificationDetector extends EventEmitter {
  /** Конфигурация */
  private readonly config: ModificationDetectorConfig;
  
  /** Baseline хеши */
  private readonly baselineHashes: Map<string, FileHash> = new Map();
  
  /** История изменений */
  private readonly changeHistory: Array<{
    filePath: string;
    timestamp: Date;
    oldHash: string;
    newHash: string;
  }> = new Map();
  
  /** Кэш анализа файлов */
  private readonly analysisCache: Map<string, FileAnalysisResult> = new Map();

  /**
   * Создает экземпляр ModificationDetector
   */
  constructor(config: Partial<ModificationDetectorConfig> = {}) {
    super();
    
    this.config = {
      hashAlgorithm: config.hashAlgorithm || 'SHA-256',
      alertRiskThreshold: config.alertRiskThreshold || 70,
      criticalFilePatterns: config.criticalFilePatterns || [
        '**/*.exe',
        '**/*.dll',
        '**/*.so',
        '**/*.dylib',
        '**/config/**',
        '**/.env*',
        '**/passwd',
        '**/shadow',
        '**/sudoers',
        '**/crontab',
        '**/init.d/**',
        '**/systemd/**'
      ],
      iocPatterns: config.iocPatterns || this.getDefaultIOCPatterns(),
      enableBehavioralAnalysis: config.enableBehavioralAnalysis ?? true,
      minFileSizeForAnalysis: config.minFileSizeForAnalysis || 0,
      maxFileSizeForAnalysis: config.maxFileSizeForAnalysis || 100 * 1024 * 1024 // 100MB
    };
  }

  /**
   * Получает стандартные IOC паттерны
   */
  private getDefaultIOCPatterns(): IOCPattern[] {
    return [
      {
        name: 'PowerShell Download Cradle',
        type: 'regex',
        pattern: 'IEX\\s*\\(\\s*\\(\\s*New-Object\\s+Net\\.WebClient\\)',
        threatDescription: 'Попытка загрузки и выполнения кода через PowerShell',
        severity: 'critical',
        mitreId: 'T1059.001'
      },
      {
        name: 'Base64 Encoded Command',
        type: 'regex',
        pattern: '[A-Za-z0-9+/]{50,}={0,2}',
        threatDescription: 'Длинная Base64 строка может содержать закодированную команду',
        severity: 'medium',
        mitreId: 'T1140'
      },
      {
        name: 'Reverse Shell Pattern',
        type: 'regex',
        pattern: '/bin/(ba)?sh\\s+-i\\s+>&\\s+/dev/tcp/',
        threatDescription: 'Паттерн reverse shell',
        severity: 'critical',
        mitreId: 'T1059'
      },
      {
        name: 'Crypto Miner Domain',
        type: 'string',
        pattern: 'pool.minexmr.com',
        threatDescription: 'Известный домен crypto miner',
        severity: 'high',
        mitreId: 'T1496'
      },
      {
        name: 'Mimikatz Signature',
        type: 'string',
        pattern: 'sekurlsa::logonpasswords',
        threatDescription: 'Сигнатура Mimikatz',
        severity: 'critical',
        mitreId: 'T1003'
      },
      {
        name: 'Cobalt Strike Beacon',
        type: 'hash',
        pattern: 'a1b2c3d4e5f6...', // Пример хеша
        threatDescription: 'Сигнатура Cobalt Strike',
        severity: 'critical',
        mitreId: 'T1071'
      }
    ];
  }

  /**
   * Устанавливает baseline для детекции
   * 
   * @param files - Файлы baseline
   */
  setBaseline(files: FileHash[]): void {
    this.baselineHashes.clear();
    
    for (const file of files) {
      this.baselineHashes.set(file.filePath, file);
    }
    
    this.emit('baseline-set', { count: files.length });
  }

  /**
   * Детектирует модификации в файлах
   * 
   * @param currentFiles - Текущие файлы
   * @returns Результат детекции
   */
  async detectModifications(
    currentFiles: FileHash[]
  ): Promise<OperationResult<ModificationDetectionResult>> {
    const startTime = Date.now();
    const modifications: DetectedModification[] = [];
    const modificationTypes = new Set<ModificationType>();
    
    try {
      // Создаем карту текущих файлов
      const currentMap = new Map<string, FileHash>();
      for (const file of currentFiles) {
        currentMap.set(file.filePath, file);
      }
      
      // Проверяем файлы baseline
      for (const [filePath, baselineFile] of this.baselineHashes.entries()) {
        const currentFile = currentMap.get(filePath);
        
        if (!currentFile) {
          // Файл удален
          modifications.push({
            type: 'deletion',
            filePath,
            description: `Файл удален: ${filePath}`,
            severity: this.isCriticalFile(filePath) ? 'high' : 'medium',
            iocs: [],
            detectedAt: new Date()
          });
          modificationTypes.add('deletion');
        } else if (currentFile.hash !== baselineFile.hash) {
          // Файл изменен - проводим глубокий анализ
          const analysis = await this.analyzeFileModification(
            filePath,
            baselineFile,
            currentFile
          );
          
          if (analysis.modificationTypes.length > 0) {
            for (const modType of analysis.modificationTypes) {
              modificationTypes.add(modType);
            }
            
            modifications.push({
              type: analysis.modificationTypes[0],
              filePath,
              description: `Обнаружена модификация: ${filePath}`,
              severity: this.getSeverity(analysis.riskScore),
              iocs: analysis.iocMatches.map(m => m.patternName),
              detectedAt: new Date(),
              context: {
                riskScore: analysis.riskScore,
                oldHash: baselineFile.hash,
                newHash: currentFile.hash,
                oldSize: baselineFile.size,
                newSize: currentFile.size
              }
            });
          }
        }
      }
      
      // Проверяем новые файлы
      for (const [filePath, currentFile] of currentMap.entries()) {
        if (!this.baselineHashes.has(filePath)) {
          // Новый файл - проверяем на подозрительность
          const analysis = await this.analyzeNewFile(filePath, currentFile);
          
          if (analysis.riskScore > this.config.alertRiskThreshold) {
            modifications.push({
              type: 'addition',
              filePath,
              description: `Подозрительный новый файл: ${filePath}`,
              severity: this.getSeverity(analysis.riskScore),
              iocs: analysis.iocMatches.map(m => m.patternName),
              detectedAt: new Date(),
              context: {
                riskScore: analysis.riskScore,
                hash: currentFile.hash,
                size: currentFile.size
              }
            });
            modificationTypes.add('addition');
          }
        }
      }
      
      const riskScore = this.calculateOverallRisk(modifications);
      const recommendations = this.generateRecommendations(modifications);
      
      const result: ModificationDetectionResult = {
        checkedAt: new Date(),
        modificationsDetected: modifications.length > 0,
        modificationTypes: Array.from(modificationTypes),
        modifications,
        riskScore,
        recommendations
      };
      
      this.emit('modifications-detected', result);
      
      return {
        success: true,
        data: result,
        errors: [],
        warnings: modifications.length > 0 
          ? [`Обнаружено ${modifications.length} модификаций`] 
          : [],
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
   * Анализирует модификацию файла
   */
  private async analyzeFileModification(
    filePath: string,
    baselineFile: FileHash,
    currentFile: FileHash
  ): Promise<FileAnalysisResult> {
    const result: FileAnalysisResult = {
      filePath,
      modificationTypes: [],
      riskScore: 0,
      iocMatches: [],
      behavioralAnomalies: [],
      recommendations: []
    };
    
    // Определяем тип изменения
    if (baselineFile.size !== currentFile.size) {
      result.modificationTypes.push('content_change');
    }
    
    // Проверяем timestamp anomalies
    if (currentFile.mtime < baselineFile.mtime) {
      result.modificationTypes.push('timestamp_manipulation');
      result.behavioralAnomalies.push({
        type: 'timestamp_anomaly',
        description: 'Время модификации меньше чем в baseline',
        value: currentFile.mtime.getTime(),
        expectedValue: baselineFile.mtime.getTime(),
        severity: 'medium'
      });
      result.riskScore += 20;
    }
    
    // Проверяем IOC если файл доступен
    try {
      if (fs.existsSync(filePath)) {
        const iocMatches = await this.scanForIOCs(filePath);
        result.iocMatches = iocMatches;
        result.riskScore += iocMatches.length * 15;
      }
    } catch {
      // Файл недоступен
    }
    
    // Поведенческий анализ
    if (this.config.enableBehavioralAnalysis) {
      const anomalies = await this.performBehavioralAnalysis(filePath, baselineFile, currentFile);
      result.behavioralAnomalies.push(...anomalies);
      result.riskScore += anomalies.length * 10;
    }
    
    // Проверяем критичность файла
    if (this.isCriticalFile(filePath)) {
      result.riskScore += 30;
    }
    
    // Генерируем рекомендации
    result.recommendations = this.generateFileRecommendations(result);
    
    return result;
  }

  /**
   * Анализирует новый файл
   */
  private async analyzeNewFile(
    filePath: string,
    fileHash: FileHash
  ): Promise<FileAnalysisResult> {
    const result: FileAnalysisResult = {
      filePath,
      modificationTypes: ['addition'],
      riskScore: 0,
      iocMatches: [],
      behavioralAnomalies: [],
      recommendations: []
    };
    
    // Проверяем IOC
    try {
      if (fs.existsSync(filePath)) {
        const iocMatches = await this.scanForIOCs(filePath);
        result.iocMatches = iocMatches;
        result.riskScore += iocMatches.length * 20;
      }
    } catch {
      // Файл недоступен
    }
    
    // Проверяем подозрительные расширения
    const suspiciousExtensions = ['.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.js'];
    const ext = path.extname(filePath).toLowerCase();
    
    if (suspiciousExtensions.includes(ext)) {
      result.riskScore += 15;
      result.behavioralAnomalies.push({
        type: 'suspicious_extension',
        description: `Подозрительное расширение: ${ext}`,
        value: 0,
        severity: 'medium'
      });
    }
    
    // Проверяем критичность расположения
    if (this.isCriticalFile(filePath)) {
      result.riskScore += 25;
    }
    
    result.recommendations = this.generateFileRecommendations(result);
    
    return result;
  }

  /**
   * Сканирует файл на IOC
   */
  private async scanForIOCs(filePath: string): Promise<IOCMatch[]> {
    const matches: IOCMatch[] = [];
    
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const size = fs.statSync(filePath).size;
      
      // Проверяем размер
      if (size < this.config.minFileSizeForAnalysis || 
          size > this.config.maxFileSizeForAnalysis) {
        return matches;
      }
      
      // Сканируем паттерны
      for (const iocPattern of this.config.iocPatterns) {
        try {
          if (iocPattern.type === 'regex') {
            const regex = new RegExp(iocPattern.pattern, 'gi');
            let match;
            
            while ((match = regex.exec(content)) !== null) {
              matches.push({
                patternName: iocPattern.name,
                matchedValue: match[0].substring(0, 50),
                position: match.index,
                severity: iocPattern.severity,
                threatDescription: iocPattern.threatDescription
              });
              
              // Ограничиваем количество совпадений
              if (matches.length >= 10) {
                break;
              }
            }
          } else if (iocPattern.type === 'string') {
            const index = content.indexOf(iocPattern.pattern);
            
            if (index !== -1) {
              matches.push({
                patternName: iocPattern.name,
                matchedValue: iocPattern.pattern,
                position: index,
                severity: iocPattern.severity,
                threatDescription: iocPattern.threatDescription
              });
            }
          }
        } catch {
          // Ошибка при проверке паттерна
        }
        
        if (matches.length >= 10) {
          break;
        }
      }
    } catch {
      // Файл не читается (бинарный или нет доступа)
    }
    
    return matches;
  }

  /**
   * Выполняет поведенческий анализ
   */
  private async performBehavioralAnalysis(
    filePath: string,
    baselineFile: FileHash,
    currentFile: FileHash
  ): Promise<BehavioralAnomaly[]> {
    const anomalies: BehavioralAnomaly[] = [];
    
    try {
      // Проверяем изменение размера
      const sizeChangePercent = Math.abs(
        (currentFile.size - baselineFile.size) / baselineFile.size * 100
      );
      
      if (sizeChangePercent > 50) {
        anomalies.push({
          type: 'significant_size_change',
          description: `Значительное изменение размера: ${sizeChangePercent.toFixed(1)}%`,
          value: sizeChangePercent,
          expectedValue: 0,
          severity: sizeChangePercent > 80 ? 'high' : 'medium'
        });
      }
      
      // Проверяем энтропию если файл доступен
      if (fs.existsSync(filePath)) {
        const entropy = await this.calculateFileEntropy(filePath);
        
        if (entropy > 7.5) {
          anomalies.push({
            type: 'high_entropy',
            description: 'Высокая энтропия файла (возможно шифрование или сжатие)',
            value: entropy,
            expectedValue: 5,
            severity: 'medium'
          });
        }
      }
    } catch {
      // Ошибка анализа
    }
    
    return anomalies;
  }

  /**
   * Вычисляет энтропию файла
   */
  private async calculateFileEntropy(filePath: string): Promise<number> {
    return new Promise((resolve) => {
      try {
        const data = fs.readFileSync(filePath);
        const frequency = new Map<number, number>();
        
        for (const byte of data) {
          frequency.set(byte, (frequency.get(byte) || 0) + 1);
        }
        
        let entropy = 0;
        const len = data.length;
        
        for (const count of frequency.values()) {
          const p = count / len;
          entropy -= p * Math.log2(p);
        }
        
        resolve(entropy);
      } catch {
        resolve(0);
      }
    });
  }

  /**
   * Проверяет является ли файл критичным
   *
   * БЕЗОПАСНОСТЬ: Корректная обработка glob patterns для предотвращения
   * уязвимостей regex injection и incomplete regex validation
   */
  private isCriticalFile(filePath: string): boolean {
    return this.config.criticalFilePatterns.some(pattern => {
      // ИСПРАВЛЕНИЕ: Правильный порядок обработки glob patterns
      // 1. Сначала обрабатываем ** (рекурсивный wildcard)
      // 2. Затем обрабатываем * (single level wildcard)
      // 3. Экранируем все остальные специальные regex символы

      let regexPattern = pattern;

      // Временная замена ** на уникальный плейсхолдер
      regexPattern = regexPattern.replace(/\*\*/g, '\x00RECURSIVE_WILDCARD\x00');

      // Временная замена * на уникальный плейсхолдер
      regexPattern = regexPattern.replace(/\*/g, '\x00SINGLE_WILDCARD\x00');

      // Экранируем все специальные regex символы
      regexPattern = regexPattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');

      // Восстанавливаем wildcard паттерны
      // ** соответствует любому пути включая /
      regexPattern = regexPattern.replace(/\x00RECURSIVE_WILDCARD\x00/g, '.*');
      // * соответствует любым символам кроме /
      regexPattern = regexPattern.replace(/\x00SINGLE_WILDCARD\x00/g, '[^/]*');

      const regex = new RegExp(`^${regexPattern}$`, 'i');
      return regex.test(filePath);
    });
  }

  /**
   * Получает серьезность по оценке риска
   */
  private getSeverity(riskScore: number): 'critical' | 'high' | 'medium' | 'low' {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 40) return 'medium';
    return 'low';
  }

  /**
   * Вычисляет общую оценку риска
   */
  private calculateOverallRisk(
    modifications: DetectedModification[]
  ): number {
    if (modifications.length === 0) return 0;
    
    const severityWeights: Record<string, number> = {
      critical: 40,
      high: 25,
      medium: 15,
      low: 5
    };
    
    let totalRisk = 0;
    
    for (const mod of modifications) {
      totalRisk += severityWeights[mod.severity];
    }
    
    return Math.min(totalRisk, 100);
  }

  /**
   * Генерирует рекомендации
   */
  private generateRecommendations(
    modifications: DetectedModification[]
  ): string[] {
    const recommendations = new Set<string>();
    
    if (modifications.length === 0) {
      return ['Продолжать мониторинг'];
    }
    
    const hasCritical = modifications.some(m => m.severity === 'critical');
    const hasIOC = modifications.some(m => m.iocs.length > 0);
    const hasCriticalFile = modifications.some(m => 
      this.isCriticalFile(m.filePath)
    );
    
    if (hasCritical) {
      recommendations.add('Немедленно изолировать систему');
      recommendations.add('Инициировать incident response процедуру');
    }
    
    if (hasIOC) {
      recommendations.add('Собрать IOC для threat intelligence');
      recommendations.add('Проверить другие системы на наличие аналогичных IOC');
    }
    
    if (hasCriticalFile) {
      recommendations.add('Восстановить критичные файлы из доверенной копии');
      recommendations.add('Проверить целостность системы');
    }
    
    recommendations.add('Сохранить логи и артефакты для расследования');
    recommendations.add('Уведомить security team');
    
    return Array.from(recommendations);
  }

  /**
   * Генерирует рекомендации для файла
   */
  private generateFileRecommendations(
    analysis: FileAnalysisResult
  ): string[] {
    const recommendations: string[] = [];
    
    if (analysis.iocMatches.length > 0) {
      recommendations.push('Исследовать IOC совпадения');
      recommendations.push('Проверить файл на VirusTotal');
    }
    
    if (analysis.riskScore >= 70) {
      recommendations.push('Карантин файла');
      recommendations.push('Анализ в песочнице');
    }
    
    if (analysis.behavioralAnomalies.some(a => a.type === 'high_entropy')) {
      recommendations.push('Проверить на наличие шифровальщика');
    }
    
    return recommendations;
  }

  /**
   * Добавляет IOC паттерн
   * 
   * @param pattern - IOC паттерн
   */
  addIOCPattern(pattern: IOCPattern): void {
    this.config.iocPatterns.push(pattern);
    this.emit('ioc-pattern-added', pattern);
  }

  /**
   * Удаляет IOC паттерн
   * 
   * @param patternName - Название паттерна
   */
  removeIOCPattern(patternName: string): boolean {
    const index = this.config.iocPatterns.findIndex(p => p.name === patternName);
    
    if (index !== -1) {
      this.config.iocPatterns.splice(index, 1);
      this.emit('ioc-pattern-removed', patternName);
      return true;
    }
    
    return false;
  }

  /**
   * Получает статистику детектора
   */
  getStatistics(): {
    baselineFilesCount: number;
    iocPatternsCount: number;
    criticalPatternsCount: number;
  } {
    return {
      baselineFilesCount: this.baselineHashes.size,
      iocPatternsCount: this.config.iocPatterns.length,
      criticalPatternsCount: this.config.criticalFilePatterns.length
    };
  }

  /**
   * Очищает кэш анализа
   */
  clearCache(): void {
    this.analysisCache.clear();
  }
}

/**
 * Фабрика для Modification Detector
 */
export class ModificationDetectorFactory {
  /**
   * Создает детектор для production среды
   */
  static createForProduction(): ModificationDetector {
    return new ModificationDetector({
      alertRiskThreshold: 60,
      enableBehavioralAnalysis: true
    });
  }

  /**
   * Создает детектор для high-security среды
   */
  static createForHighSecurity(): ModificationDetector {
    return new ModificationDetector({
      alertRiskThreshold: 40,
      enableBehavioralAnalysis: true,
      criticalFilePatterns: [
        '**/*', // Все файлы критичны
      ]
    });
  }

  /**
   * Создает детектор с кастомной конфигурацией
   */
  static createWithConfig(config: ModificationDetectorConfig): ModificationDetector {
    return new ModificationDetector(config);
  }
}
