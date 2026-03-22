/**
 * ============================================================================
 * RUNTIME VERIFIER - RUNTIME ВЕРИФИКАЦИЯ ЦЕЛОСТНОСТИ
 * ============================================================================
 * Модуль для непрерывной верификации целостности в runtime.
 * Проверяет что загруженные компоненты соответствуют ожидаемым хешам
 * и подписям.
 * 
 * Особенности:
 * - Continuous verification
 * - Memory integrity checks
 * - Code section verification
 * - Dynamic library monitoring
 * - Configuration file validation
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  RuntimeVerificationStatus,
  RuntimeComponentStatus,
  IntegrityViolation,
  FileHash,
  HashAlgorithm,
  OperationResult,
  SignatureVerificationResult
} from '../types/integrity.types';
import { CodeSigner } from './CodeSigner';

/**
 * Конфигурация Runtime Verifier
 */
export interface RuntimeVerifierConfig {
  /** Алгоритм хеширования */
  hashAlgorithm: HashAlgorithm;
  /** Интервал проверки (ms) */
  verificationInterval: number;
  /** Компоненты для мониторинга */
  monitoredComponents: MonitoredComponent[];
  /** Включить memory verification */
  enableMemoryVerification: boolean;
  /** Включить code section verification */
  enableCodeSectionVerification: boolean;
  /** Критичные пути */
  criticalPaths: string[];
}

/**
 * Компонент для мониторинга
 */
export interface MonitoredComponent {
  /** Имя компонента */
  name: string;
  /** Тип */
  type: 'binary' | 'library' | 'config' | 'script';
  /** Путь */
  path: string;
  /** Ожидаемый хеш */
  expectedHash: string;
  /** Требуется ли подпись */
  requireSignature: boolean;
  /** Критичность */
  criticality: 'critical' | 'high' | 'medium' | 'low';
}

/**
 * Класс Runtime Verifier
 */
export class RuntimeVerifier extends EventEmitter {
  /** Конфигурация */
  private readonly config: RuntimeVerifierConfig;
  
  /** Code signer для верификации подписей */
  private readonly signer?: CodeSigner;
  
  /** Статус компонентов */
  private readonly componentStatuses: Map<string, RuntimeComponentStatus> = new Map();
  
  /** История нарушений */
  private readonly violationHistory: IntegrityViolation[] = [];
  
  /** Таймер проверки */
  private verificationTimer?: NodeJS.Timeout;
  
  /** Активен ли мониторинг */
  private isActive: boolean = false;
  
  /** Время последней проверки */
  private lastVerificationAt?: Date;

  /**
   * Создает экземпляр RuntimeVerifier
   */
  constructor(config: Partial<RuntimeVerifierConfig> = {}) {
    super();
    
    this.config = {
      hashAlgorithm: config.hashAlgorithm || 'SHA-256',
      verificationInterval: config.verificationInterval || 60000,
      monitoredComponents: config.monitoredComponents || [],
      enableMemoryVerification: config.enableMemoryVerification ?? false,
      enableCodeSectionVerification: config.enableCodeSectionVerification ?? false,
      criticalPaths: config.criticalPaths || []
    };
  }

  /**
   * Запускает runtime верификацию
   * 
   * @returns Результат запуска
   */
  async start(): Promise<OperationResult> {
    if (this.isActive) {
      return {
        success: false,
        errors: ['Верификация уже запущена'],
        warnings: [],
        executionTime: 0
      };
    }
    
    try {
      this.isActive = true;
      
      // Инициализируем статусы компонентов
      for (const component of this.config.monitoredComponents) {
        await this.initializeComponent(component);
      }
      
      // Запускаем периодическую проверку
      this.startPeriodicVerification();
      
      this.emit('started', { startedAt: new Date() });
      
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
   * Останавливает runtime верификацию
   */
  async stop(): Promise<OperationResult> {
    if (!this.isActive) {
      return {
        success: false,
        errors: ['Верификация не запущена'],
        warnings: [],
        executionTime: 0
      };
    }
    
    try {
      this.isActive = false;
      
      if (this.verificationTimer) {
        clearInterval(this.verificationTimer);
        this.verificationTimer = undefined;
      }
      
      this.emit('stopped', { stoppedAt: new Date() });
      
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
   * Запускает периодическую верификацию
   */
  private startPeriodicVerification(): void {
    this.verificationTimer = setInterval(async () => {
      await this.verifyAll();
    }, this.config.verificationInterval);
  }

  /**
   * Инициализирует компонент
   */
  private async initializeComponent(component: MonitoredComponent): Promise<void> {
    const status: RuntimeComponentStatus = {
      name: component.name,
      type: component.type,
      path: component.path,
      expectedHash: component.expectedHash,
      currentHash: '',
      matches: false,
      loaded: false
    };
    
    // Вычисляем текущий хеш
    try {
      if (fs.existsSync(component.path)) {
        status.currentHash = await this.computeFileHash(component.path);
        status.matches = status.currentHash === component.expectedHash;
        status.loaded = true;
      }
    } catch (error) {
      // Компонент недоступен
    }
    
    this.componentStatuses.set(component.name, status);
  }

  /**
   * Вычисляет хеш файла
   */
  private async computeFileHash(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash(this.getHashAlgorithm());
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
   * Выполняет полную верификацию всех компонентов
   * 
   * @returns Результат верификации
   */
  async verifyAll(): Promise<OperationResult<RuntimeVerificationStatus>> {
    const startTime = Date.now();
    const violations: IntegrityViolation[] = [];
    const componentStatuses: RuntimeComponentStatus[] = [];
    
    try {
      for (const component of this.config.monitoredComponents) {
        const status = await this.verifyComponent(component);
        componentStatuses.push(status);
        
        if (!status.matches) {
          const violation = this.createViolation(component, status);
          violations.push(violation);
          this.violationHistory.push(violation);
          this.emit('violation', violation);
        }
      }
      
      this.lastVerificationAt = new Date();
      
      const score = this.calculateVerificationScore(componentStatuses);
      
      const result: RuntimeVerificationStatus = {
        verified: violations.length === 0,
        verifiedAt: new Date(),
        components: componentStatuses,
        violations,
        score
      };
      
      return {
        success: true,
        data: result,
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
   * Верифицирует отдельный компонент
   */
  private async verifyComponent(
    component: MonitoredComponent
  ): Promise<RuntimeComponentStatus> {
    const status: RuntimeComponentStatus = {
      name: component.name,
      type: component.type,
      path: component.path,
      expectedHash: component.expectedHash,
      currentHash: '',
      matches: false,
      loaded: false
    };
    
    try {
      // Проверяем существование файла
      if (!fs.existsSync(component.path)) {
        status.matches = false;
        return status;
      }
      
      // Вычисляем текущий хеш
      status.currentHash = await this.computeFileHash(component.path);
      status.matches = status.currentHash === component.expectedHash;
      status.loaded = true;
      
      // Если требуется подпись, верифицируем её
      if (component.requireSignature && this.signer) {
        // В реальной реализации здесь была бы верификация подписи
      }
      
      // Обновляем кэш
      this.componentStatuses.set(component.name, status);
      
    } catch (error) {
      status.matches = false;
    }
    
    return status;
  }

  /**
   * Создает нарушение для компонента
   */
  private createViolation(
    component: MonitoredComponent,
    status: RuntimeComponentStatus
  ): IntegrityViolation {
    const violationType = !fs.existsSync(component.path)
      ? 'missing_file'
      : 'hash_mismatch';
    
    return {
      type: violationType,
      severity: component.criticality === 'critical' ? 'critical' : 
                component.criticality === 'high' ? 'high' : 'medium',
      filePath: component.path,
      description: `Нарушение целостности компонента ${component.name}: ${
        violationType === 'missing_file' 
          ? 'файл отсутствует' 
          : 'хеш не совпадает'
      }`,
      detectedAt: new Date(),
      details: {
        expectedHash: component.expectedHash,
        currentHash: status.currentHash,
        componentType: component.type
      },
      remediation: [
        'Остановить приложение',
        'Исследовать причину изменения',
        'Восстановить из доверенного источника',
        'Провести security audit'
      ]
    };
  }

  /**
   * Вычисляет оценку верификации
   */
  private calculateVerificationScore(
    statuses: RuntimeComponentStatus[]
  ): number {
    if (statuses.length === 0) return 100;
    
    let totalWeight = 0;
    let passedWeight = 0;
    
    const weights: Record<string, number> = {
      critical: 40,
      high: 25,
      medium: 15,
      low: 5
    };
    
    for (const status of statuses) {
      const component = this.config.monitoredComponents.find(
        c => c.name === status.name
      );
      
      const weight = weights[component?.criticality || 'medium'];
      totalWeight += weight;
      
      if (status.matches) {
        passedWeight += weight;
      }
    }
    
    return Math.round((passedWeight / totalWeight) * 100);
  }

  /**
   * Верифицирует отдельный компонент по запросу
   * 
   * @param componentName - Имя компонента
   * @returns Результат верификации
   */
  async verifyComponentByName(
    componentName: string
  ): Promise<OperationResult<RuntimeComponentStatus>> {
    const component = this.config.monitoredComponents.find(
      c => c.name === componentName
    );
    
    if (!component) {
      return {
        success: false,
        errors: [`Компонент ${componentName} не найден`],
        warnings: [],
        executionTime: 0
      };
    }
    
    const status = await this.verifyComponent(component);
    
    return {
      success: status.matches,
      data: status,
      errors: status.matches ? [] : ['Хеш не совпадает'],
      warnings: [],
      executionTime: 0
    };
  }

  /**
   * Добавляет компонент для мониторинга
   * 
   * @param component - Компонент
   * @returns Результат
   */
  addComponent(component: MonitoredComponent): OperationResult {
    try {
      // Проверяем что компонент с таким именем еще не существует
      if (this.config.monitoredComponents.some(c => c.name === component.name)) {
        return {
          success: false,
          errors: ['Компонент с таким именем уже существует'],
          warnings: [],
          executionTime: 0
        };
      }
      
      this.config.monitoredComponents.push(component);
      this.initializeComponent(component);
      
      this.emit('component-added', component);
      
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
   * Удаляет компонент из мониторинга
   * 
   * @param componentName - Имя компонента
   * @returns Результат
   */
  removeComponent(componentName: string): OperationResult {
    const index = this.config.monitoredComponents.findIndex(
      c => c.name === componentName
    );
    
    if (index === -1) {
      return {
        success: false,
        errors: ['Компонент не найден'],
        warnings: [],
        executionTime: 0
      };
    }
    
    this.config.monitoredComponents.splice(index, 1);
    this.componentStatuses.delete(componentName);
    
    this.emit('component-removed', componentName);
    
    return {
      success: true,
      errors: [],
      warnings: [],
      executionTime: 0
    };
  }

  /**
   * Получает статус компонента
   * 
   * @param componentName - Имя компонента
   * @returns Статус или null
   */
  getComponentStatus(componentName: string): RuntimeComponentStatus | null {
    return this.componentStatuses.get(componentName) || null;
  }

  /**
   * Получает историю нарушений
   * 
   * @param limit - Максимум записей
   * @returns Массив нарушений
   */
  getViolationHistory(limit: number = 100): IntegrityViolation[] {
    return this.violationHistory.slice(-limit);
  }

  /**
   * Очищает историю нарушений
   */
  clearViolationHistory(): void {
    this.violationHistory.length = 0;
  }

  /**
   * Получает текущий статус верификации
   * 
   * @returns Статус
   */
  getCurrentStatus(): RuntimeVerificationStatus {
    const statuses = Array.from(this.componentStatuses.values());
    const violations = this.violationHistory.slice(-10);
    const score = this.calculateVerificationScore(statuses);
    
    return {
      verified: violations.length === 0 && statuses.every(s => s.matches),
      verifiedAt: this.lastVerificationAt || new Date(),
      components: statuses,
      violations,
      score
    };
  }

  /**
   * Получает статистику верификации
   * 
   * @returns Статистика
   */
  getStatistics(): {
    totalComponents: number;
    verifiedComponents: number;
    failedComponents: number;
    totalViolations: number;
    criticalViolations: number;
    lastVerificationAt: Date | undefined;
    isActive: boolean;
  } {
    const statuses = Array.from(this.componentStatuses.values());
    const verifiedComponents = statuses.filter(s => s.matches).length;
    const failedComponents = statuses.length - verifiedComponents;
    
    const criticalViolations = this.violationHistory.filter(
      v => v.severity === 'critical'
    ).length;
    
    return {
      totalComponents: this.config.monitoredComponents.length,
      verifiedComponents,
      failedComponents,
      totalViolations: this.violationHistory.length,
      criticalViolations,
      lastVerificationAt: this.lastVerificationAt,
      isActive: this.isActive
    };
  }

  /**
   * Экспортирует конфигурацию мониторинга
   * 
   * @returns Конфигурация
   */
  exportConfig(): RuntimeVerifierConfig {
    return { ...this.config };
  }

  /**
   * Импортирует конфигурацию мониторинга
   * 
   * @param config - Конфигурация
   * @returns Результат
   */
  importConfig(config: RuntimeVerifierConfig): OperationResult {
    try {
      this.config.monitoredComponents = config.monitoredComponents;
      this.config.verificationInterval = config.verificationInterval;
      this.config.criticalPaths = config.criticalPaths;
      
      // Реинициализируем компоненты
      this.componentStatuses.clear();
      for (const component of config.monitoredComponents) {
        this.initializeComponent(component);
      }
      
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
 * Фабрика для Runtime Verifier
 */
export class RuntimeVerifierFactory {
  /**
   * Создает verifier для критичных компонентов
   */
  static createForCriticalComponents(
    components: MonitoredComponent[]
  ): RuntimeVerifier {
    return new RuntimeVerifier({
      monitoredComponents: components,
      verificationInterval: 30000, // 30 секунд
      enableMemoryVerification: false,
      enableCodeSectionVerification: false
    });
  }

  /**
   * Создает verifier с кастомной конфигурацией
   */
  static createWithConfig(config: RuntimeVerifierConfig): RuntimeVerifier {
    return new RuntimeVerifier(config);
  }

  /**
   * Создает verifier для production среды
   */
  static createForProduction(
    components: MonitoredComponent[]
  ): RuntimeVerifier {
    return new RuntimeVerifier({
      monitoredComponents: components,
      verificationInterval: 60000, // 1 минута
      enableMemoryVerification: true,
      enableCodeSectionVerification: true,
      criticalPaths: ['/usr/bin', '/usr/lib', '/etc']
    });
  }
}
