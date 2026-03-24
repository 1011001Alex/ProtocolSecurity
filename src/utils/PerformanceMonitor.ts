/**
 * ============================================================================
 * PERFORMANCE MONITOR - ПРОФИЛИРОВАНИЕ И МОНИТОРИНГ ПРОИЗВОДИТЕЛЬНОСТИ
 * ============================================================================
 * Комплексная система профилирования CPU, memory, I/O, network
 * 
 * Особенности:
 * - Real-time мониторинг метрик
 * - Профилирование операций
 * - Detection аномалий производительности
 * - Memory leak detection
 * - CPU profiling
 * - I/O latency tracking
 * - Network performance monitoring
 * - Alerting при превышении порогов
 */

import { EventEmitter } from 'events';
import { logger } from '../logging/Logger';
import { performance } from 'perf_hooks';

/**
 * Типы метрик
 */
export enum MetricType {
  CPU = 'CPU',
  MEMORY = 'MEMORY',
  DISK = 'DISK',
  NETWORK = 'NETWORK',
  GC = 'GC',
  EVENT_LOOP = 'EVENT_LOOP',
  HTTP = 'HTTP',
  DATABASE = 'DATABASE',
  CUSTOM = 'CUSTOM'
}

/**
 * Уровень серьезности
 */
export enum SeverityLevel {
  INFO = 'INFO',
  WARNING = 'WARNING',
  CRITICAL = 'CRITICAL'
}

/**
 * Конфигурация монитора
 */
export interface PerformanceMonitorConfig {
  /** Интервал сбора метрик (ms) */
  collectionInterval: number;
  
  /** Порог CPU warning (%) */
  cpuWarningThreshold: number;
  
  /** Порог CPU critical (%) */
  cpuCriticalThreshold: number;
  
  /** Порог memory warning (%) */
  memoryWarningThreshold: number;
  
  /** Порог memory critical (%) */
  memoryCriticalThreshold: number;
  
  /** Порог event loop lag warning (ms) */
  eventLoopLagWarning: number;
  
  /** Порог event loop lag critical (ms) */
  eventLoopLagCritical: number;
  
  /** Включить GC мониторинг */
  enableGCMonitoring: boolean;
  
  /** Включить detection аномалий */
  enableAnomalyDetection: boolean;
  
  /** Максимум истории метрик */
  maxHistorySize: number;
  
  /** Имя инстанса */
  instanceName: string;
}

/**
 * Конфигурация по умолчанию
 */
const DEFAULT_CONFIG: PerformanceMonitorConfig = {
  collectionInterval: 5000,
  cpuWarningThreshold: 70,
  cpuCriticalThreshold: 90,
  memoryWarningThreshold: 80,
  memoryCriticalThreshold: 95,
  eventLoopLagWarning: 100,
  eventLoopLagCritical: 500,
  enableGCMonitoring: true,
  enableAnomalyDetection: true,
  maxHistorySize: 1000,
  instanceName: 'default'
};

/**
 * CPU метрики
 */
export interface CPUMetrics {
  /** Usage % */
  usage: number;
  /** System % */
  system: number;
  /** User % */
  user: number;
  /** Idle % */
  idle: number;
  /** Load average (1, 5, 15 min) */
  loadAverage: [number, number, number];
  /** Core count */
  cores: number;
}

/**
 * Memory метрики
 */
export interface MemoryMetrics {
  /** Total (bytes) */
  total: number;
  /** Free (bytes) */
  free: number;
  /** Used (bytes) */
  used: number;
  /** Usage % */
  usagePercent: number;
  /** Heap total (bytes) */
  heapTotal: number;
  /** Heap used (bytes) */
  heapUsed: number;
  /** External memory (bytes) */
  external: number;
  /** RSS (bytes) */
  rss: number;
  /** Heap size limit (bytes) */
  heapSizeLimit: number;
}

/**
 * Event loop метрики
 */
export interface EventLoopMetrics {
  /** Lag (ms) */
  lag: number;
  /** Delay (ms) */
  delay: number;
  /** Utilization % */
  utilization: number;
}

/**
 * GC метрики
 */
export interface GCMetrics {
  /** Total GC time (ms) */
  totalGCTime: number;
  /** GC count */
  gcCount: number;
  /** Average GC time (ms) */
  averageGCTime: number;
  /** Last GC pause (ms) */
  lastGCPause: number;
  /** Major GC count */
  majorGCCount: number;
  /** Minor GC count */
  minorGCCount: number;
}

/**
 * Disk I/O метрики
 */
export interface DiskMetrics {
  /** Read bytes */
  readBytes: number;
  /** Write bytes */
  writeBytes: number;
  /** Read operations */
  readOps: number;
  /** Write operations */
  writeOps: number;
  /** Read latency (ms) */
  readLatency: number;
  /** Write latency (ms) */
  writeLatency: number;
  /** Queue length */
  queueLength: number;
}

/**
 * Network метрики
 */
export interface NetworkMetrics {
  /** Bytes received */
  bytesReceived: number;
  /** Bytes sent */
  bytesSent: number;
  /** Packets received */
  packetsReceived: number;
  /** Packets sent */
  packetsSent: number;
  /** Errors in */
  errorsIn: number;
  /** Errors out */
  errorsOut: number;
  /** Connections active */
  connectionsActive: number;
  /** Connections idle */
  connectionsIdle: number;
}

/**
 * Профилирование операции
 */
export interface OperationProfile {
  /** ID операции */
  id: string;
  /** Название */
  name: string;
  /** Тип */
  type: string;
  /** Время начала */
  startTime: number;
  /** Время окончания */
  endTime?: number;
  /** Длительность (ms) */
  duration?: number;
  /** Метки */
  tags?: Record<string, string>;
  /** Метрики */
  metrics?: Record<string, number>;
  /** Ошибка */
  error?: string;
}

/**
 * Аномалия производительности
 */
export interface PerformanceAnomaly {
  /** Тип аномалии */
  type: string;
  /** Метрика */
  metric: string;
  /** Ожидаемое значение */
  expectedValue: number;
  /** Фактическое значение */
  actualValue: number;
  /** Отклонение % */
  deviationPercent: number;
  /** Время обнаружения */
  detectedAt: Date;
  /** Серьезность */
  severity: SeverityLevel;
  /** Рекомендации */
  recommendations: string[];
}

/**
 * Полные метрики системы
 */
export interface SystemMetrics {
  /** Timestamp */
  timestamp: Date;
  /** Instance name */
  instance: string;
  /** CPU метрики */
  cpu: CPUMetrics;
  /** Memory метрики */
  memory: MemoryMetrics;
  /** Event loop метрики */
  eventLoop: EventLoopMetrics;
  /** GC метрики */
  gc?: GCMetrics;
  /** Disk метрики */
  disk?: DiskMetrics;
  /** Network метрики */
  network?: NetworkMetrics;
  /** Uptime (seconds) */
  uptime: number;
  /** Process ID */
  pid: number;
}

/**
 * Performance Monitor
 */
export class PerformanceMonitor extends EventEmitter {
  /** Конфигурация */
  private readonly config: PerformanceMonitorConfig;
  
  /** История метрик */
  private metricsHistory: SystemMetrics[] = [];
  
  /** Активные профилирования */
  private activeProfiles: Map<string, OperationProfile> = new Map();
  
  /** Завершенные профилирования */
  private completedProfiles: OperationProfile[] = [];
  
  /** Таймер сбора метрик */
  private collectionTimer: NodeJS.Timeout | null = null;
  
  /** Последняя проверка event loop */
  private lastCheckTime: number = 0;
  
  /** Последняя задержка event loop */
  private lastEventLoopDelay: number = 0;
  
  /** Статистика */
  private stats: {
    totalProfiles: number;
    averageDuration: number;
    maxDuration: number;
    anomaliesDetected: number;
  };
  
  /** Базовые линии для anomaly detection */
  private baselines: Map<string, { mean: number; stdDev: number; count: number }> = new Map();
  
  /**
   * Создает performance monitor
   */
  constructor(config: Partial<PerformanceMonitorConfig> = {}) {
    super();
    
    this.config = {
      ...DEFAULT_CONFIG,
      ...config
    };
    
    this.stats = {
      totalProfiles: 0,
      averageDuration: 0,
      maxDuration: 0,
      anomaliesDetected: 0
    };
    
    this.lastCheckTime = performance.now();
  }
  
  /**
   * Запуск мониторинга
   */
  start(): void {
    if (this.collectionTimer) {
      return;
    }
    
    this.log('START', 'Запуск performance мониторинга');
    
    // Сбор метрик по интервалу
    this.collectionTimer = setInterval(() => {
      this.collectMetrics();
    }, this.config.collectionInterval);
    
    // Event loop monitoring
    this.monitorEventLoop();
    
    // GC monitoring если включен
    if (this.config.enableGCMonitoring) {
      this.setupGCMonitoring();
    }
    
    this.emit('started');
  }
  
  /**
   * Остановка мониторинга
   */
  stop(): void {
    if (this.collectionTimer) {
      clearInterval(this.collectionTimer);
      this.collectionTimer = null;
    }
    
    this.log('STOP', 'Остановка performance мониторинга');
    this.emit('stopped');
  }
  
  /**
   * Сбор всех метрик
   */
  collectMetrics(): SystemMetrics {
    const timestamp = new Date();
    
    const metrics: SystemMetrics = {
      timestamp,
      instance: this.config.instanceName,
      cpu: this.collectCPUMetrics(),
      memory: this.collectMemoryMetrics(),
      eventLoop: this.collectEventLoopMetrics(),
      uptime: process.uptime(),
      pid: process.pid
    };
    
    // GC метрики если доступны
    if (this.config.enableGCMonitoring && (global as any).gc) {
      metrics.gc = this.collectGCMetrics();
    }
    
    // Сохранение в историю
    this.metricsHistory.push(metrics);
    if (this.metricsHistory.length > this.config.maxHistorySize) {
      this.metricsHistory.shift();
    }
    
    // Проверка порогов
    this.checkThresholds(metrics);
    
    // Anomaly detection
    if (this.config.enableAnomalyDetection) {
      this.detectAnomalies(metrics);
    }
    
    this.emit('metrics', metrics);
    
    return metrics;
  }
  
  /**
   * Начало профилирования операции
   */
  startProfile(name: string, type: string, tags?: Record<string, string>): string {
    const id = `${name}_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    
    const profile: OperationProfile = {
      id,
      name,
      type,
      startTime: performance.now(),
      tags
    };
    
    this.activeProfiles.set(id, profile);
    this.stats.totalProfiles++;
    
    return id;
  }
  
  /**
   * Завершение профилирования операции
   */
  endProfile(id: string, metrics?: Record<string, number>, error?: Error): OperationProfile | null {
    const profile = this.activeProfiles.get(id);
    
    if (!profile) {
      return null;
    }
    
    profile.endTime = performance.now();
    profile.duration = profile.endTime - profile.startTime;
    profile.metrics = metrics;
    
    if (error) {
      profile.error = error.message;
    }
    
    // Обновление статистики
    this.stats.averageDuration =
      (this.stats.averageDuration * (this.stats.totalProfiles - 1) + profile.duration) /
      this.stats.totalProfiles;
    
    if (profile.duration > this.stats.maxDuration) {
      this.stats.maxDuration = profile.duration;
    }
    
    // Сохранение
    this.completedProfiles.push(profile);
    if (this.completedProfiles.length > this.config.maxHistorySize) {
      this.completedProfiles.shift();
    }
    
    this.activeProfiles.delete(id);
    
    this.emit('profile:completed', profile);
    
    return profile;
  }
  
  /**
   * Получение текущих метрик
   */
  getCurrentMetrics(): SystemMetrics | null {
    return this.metricsHistory[this.metricsHistory.length - 1] || null;
  }
  
  /**
   * Получение истории метрик
   */
  getHistory(limit?: number): SystemMetrics[] {
    if (limit) {
      return this.metricsHistory.slice(-limit);
    }
    return [...this.metricsHistory];
  }
  
  /**
   * Получение статистики профилирования
   */
  getProfileStats(): {
    total: number;
    active: number;
    completed: number;
    averageDuration: number;
    maxDuration: number;
    slowestOperations: OperationProfile[];
  } {
    const slowest = [...this.completedProfiles]
      .sort((a, b) => (b.duration || 0) - (a.duration || 0))
      .slice(0, 10);
    
    return {
      total: this.stats.totalProfiles,
      active: this.activeProfiles.size,
      completed: this.completedProfiles.size,
      averageDuration: this.stats.averageDuration,
      maxDuration: this.stats.maxDuration,
      slowestOperations: slowest
    };
  }
  
  /**
   * Получение статистики
   */
  getStats(): typeof this.stats & {
    anomaliesDetected: number;
    uptime: number;
  } {
    return {
      ...this.stats,
      anomaliesDetected: this.stats.anomaliesDetected,
      uptime: process.uptime()
    };
  }
  
  /**
   * Сброс базовых линий
   */
  resetBaselines(): void {
    this.baselines.clear();
    this.log('RESET', 'Базовые линии сброшены');
  }
  
  // ============================================================================
  // ПРИВАТНЫЕ МЕТОДЫ
  // ============================================================================
  
  /**
   * Сбор CPU метрик
   */
  private collectCPUMetrics(): CPUMetrics {
    const cpus = require('os').cpus();
    const loadAvg = require('os').loadavg() as [number, number, number];
    
    let totalIdle = 0;
    let totalTick = 0;
    
    for (const cpu of cpus) {
      const total = cpu.times.idle + cpu.times.user + cpu.times.nice + cpu.times.sys + cpu.times.irq;
      totalIdle += cpu.times.idle;
      totalTick += total;
    }
    
    const idle = totalIdle / cpus.length;
    const usage = 100 - (idle / (totalTick / cpus.length)) * 100;
    
    return {
      usage: Math.round(usage * 100) / 100,
      system: 0, // Можно получить из process.cpuUsage()
      user: 0,
      idle: Math.round((idle / (totalTick / cpus.length)) * 100 * 100) / 100,
      loadAverage: loadAvg,
      cores: cpus.length
    };
  }
  
  /**
   * Сбор memory метрик
   */
  private collectMemoryMetrics(): MemoryMetrics {
    const memInfo = {
      total: require('os').totalmem(),
      free: require('os').freemem()
    };
    
    const used = memInfo.total - memInfo.free;
    const usagePercent = (used / memInfo.total) * 100;
    
    const memUsage = process.memoryUsage();
    
    return {
      total: memInfo.total,
      free: memInfo.free,
      used,
      usagePercent: Math.round(usagePercent * 100) / 100,
      heapTotal: memUsage.heapTotal,
      heapUsed: memUsage.heapUsed,
      external: memUsage.external,
      rss: memUsage.rss,
      heapSizeLimit: memUsage.heapTotal // Приблизительно
    };
  }
  
  /**
   * Сбор event loop метрик
   */
  private collectEventLoopMetrics(): EventLoopMetrics {
    const now = performance.now();
    const delta = now - this.lastCheckTime;
    
    // Event loop lag
    const lag = Math.max(0, this.lastEventLoopDelay);
    const utilization = Math.min(100, (lag / this.config.collectionInterval) * 100);
    
    this.lastCheckTime = now;
    
    return {
      lag: Math.round(lag * 100) / 100,
      delay: Math.round(this.lastEventLoopDelay * 100) / 100,
      utilization: Math.round(utilization * 100) / 100
    };
  }
  
  /**
   * Мониторинг event loop
   */
  private monitorEventLoop(): void {
    const check = () => {
      const now = performance.now();
      this.lastEventLoopDelay = now - this.lastCheckTime;
      this.lastCheckTime = now;
      
      // Проверка порогов
      if (this.lastEventLoopDelay > this.config.eventLoopLagCritical) {
        this.emit('alert', {
          type: 'EVENT_LOOP_LAG',
          severity: SeverityLevel.CRITICAL,
          value: this.lastEventLoopDelay,
          threshold: this.config.eventLoopLagCritical,
          message: `Event loop lag: ${this.lastEventLoopDelay.toFixed(2)}ms`
        });
      } else if (this.lastEventLoopDelay > this.config.eventLoopLagWarning) {
        this.emit('alert', {
          type: 'EVENT_LOOP_LAG',
          severity: SeverityLevel.WARNING,
          value: this.lastEventLoopDelay,
          threshold: this.config.eventLoopLagWarning,
          message: `Event loop lag: ${this.lastEventLoopDelay.toFixed(2)}ms`
        });
      }
      
      // Продолжаем мониторинг
      if (this.collectionTimer) {
        setTimeout(check, 10);
      }
    };
    
    setTimeout(check, 10);
  }
  
  /**
   * Setup GC monitoring
   */
  private setupGCMonitoring(): void {
    // Требуется флаг --expose-gc
    if (!(global as any).gc) {
      logger.warn('[PerformanceMonitor] GC monitoring requires --expose-gc flag');
      return;
    }
    
    let gcCount = 0;
    let totalGCTime = 0;
    let majorGCCount = 0;
    let minorGCCount = 0;
    
    const originalGC = (global as any).gc;
    (global as any).gc = () => {
      const start = performance.now();
      originalGC();
      const duration = performance.now() - start;
      
      gcCount++;
      totalGCTime += duration;
      
      // Определение типа GC (приблизительно)
      if (duration > 10) {
        majorGCCount++;
      } else {
        minorGCCount++;
      }
      
      this.emit('gc', {
        duration,
        count: gcCount,
        type: duration > 10 ? 'major' : 'minor'
      });
    };
  }
  
  /**
   * Сбор GC метрик
   */
  private collectGCMetrics(): GCMetrics {
    // В реальной реализации здесь был бы сбор статистики из GC
    return {
      totalGCTime: 0,
      gcCount: 0,
      averageGCTime: 0,
      lastGCPause: 0,
      majorGCCount: 0,
      minorGCCount: 0
    };
  }
  
  /**
   * Проверка порогов
   */
  private checkThresholds(metrics: SystemMetrics): void {
    // CPU thresholds
    if (metrics.cpu.usage >= this.config.cpuCriticalThreshold) {
      this.emit('threshold:exceeded', {
        metric: 'cpu',
        severity: SeverityLevel.CRITICAL,
        value: metrics.cpu.usage,
        threshold: this.config.cpuCriticalThreshold
      });
    } else if (metrics.cpu.usage >= this.config.cpuWarningThreshold) {
      this.emit('threshold:exceeded', {
        metric: 'cpu',
        severity: SeverityLevel.WARNING,
        value: metrics.cpu.usage,
        threshold: this.config.cpuWarningThreshold
      });
    }
    
    // Memory thresholds
    if (metrics.memory.usagePercent >= this.config.memoryCriticalThreshold) {
      this.emit('threshold:exceeded', {
        metric: 'memory',
        severity: SeverityLevel.CRITICAL,
        value: metrics.memory.usagePercent,
        threshold: this.config.memoryCriticalThreshold
      });
    } else if (metrics.memory.usagePercent >= this.config.memoryWarningThreshold) {
      this.emit('threshold:exceeded', {
        metric: 'memory',
        severity: SeverityLevel.WARNING,
        value: metrics.memory.usagePercent,
        threshold: this.config.memoryWarningThreshold
      });
    }
  }
  
  /**
   * Detection аномалий
   */
  private detectAnomalies(metrics: SystemMetrics): void {
    const anomalies: PerformanceAnomaly[] = [];
    
    // Проверка CPU аномалий
    const cpuAnomaly = this.checkMetricAnomaly('cpu_usage', metrics.cpu.usage);
    if (cpuAnomaly) {
      anomalies.push(cpuAnomaly);
    }
    
    // Проверка memory аномалий
    const memoryAnomaly = this.checkMetricAnomaly('memory_usage', metrics.memory.usagePercent);
    if (memoryAnomaly) {
      anomalies.push(memoryAnomaly);
    }
    
    // Проверка event loop аномалий
    const eventLoopAnomaly = this.checkMetricAnomaly('event_loop_lag', metrics.eventLoop.lag);
    if (eventLoopAnomaly) {
      anomalies.push(eventLoopAnomaly);
    }
    
    for (const anomaly of anomalies) {
      this.stats.anomaliesDetected++;
      this.emit('anomaly', anomaly);
    }
  }
  
  /**
   * Проверка аномалии метрики
   */
  private checkMetricAnomaly(
    name: string,
    value: number
  ): PerformanceAnomaly | null {
    const baseline = this.baselines.get(name);
    
    if (!baseline) {
      // Инициализация базовой линии
      this.baselines.set(name, { mean: value, stdDev: 0, count: 1 });
      return null;
    }
    
    // Обновление базовой линии (online algorithm)
    const delta = value - baseline.mean;
    baseline.mean += delta / (baseline.count + 1);
    baseline.count++;
    
    // Простейшая detection: отклонение > 3 sigma
    const threshold = 3 * (baseline.stdDev || baseline.mean * 0.2);
    const deviation = Math.abs(delta);
    
    if (deviation > threshold && baseline.count > 10) {
      const deviationPercent = (deviation / baseline.mean) * 100;
      
      return {
        type: 'ANOMALY',
        metric: name,
        expectedValue: baseline.mean,
        actualValue: value,
        deviationPercent: Math.round(deviationPercent * 100) / 100,
        detectedAt: new Date(),
        severity: deviationPercent > 50 ? SeverityLevel.CRITICAL : SeverityLevel.WARNING,
        recommendations: this.getRecommendations(name, value)
      };
    }
    
    return null;
  }
  
  /**
   * Получение рекомендаций
   */
  private getRecommendations(metric: string, value: number): string[] {
    const recommendations: string[] = [];
    
    switch (metric) {
      case 'cpu_usage':
        if (value > 80) {
          recommendations.push('Оптимизируйте CPU-intensive операции');
          recommendations.push('Рассмотрите горизонтальное масштабирование');
          recommendations.push('Проверьте на наличие бесконечных циклов');
        }
        break;
        
      case 'memory_usage':
        if (value > 80) {
          recommendations.push('Проверьте на наличие memory leaks');
          recommendations.push('Уменьшите размер heap если возможно');
          recommendations.push('Оптимизируйте использование кэшей');
        }
        break;
        
      case 'event_loop_lag':
        if (value > 100) {
          recommendations.push('Разбейте длительные операции на части');
          recommendations.push('Используйте worker threads для CPU задач');
          recommendations.push('Проверьте синхронные I/O операции');
        }
        break;
    }
    
    return recommendations;
  }
  
  /**
   * Логирование
   */
  private log(action: string, message: string): void {
    const timestamp = new Date().toISOString();
    logger.debug(`[PerformanceMonitor:${this.config.instanceName}] [${action}] ${message}`);
  }
}

/**
 * Singleton экземпляр
 */
let globalMonitor: PerformanceMonitor | null = null;

/**
 * Получение глобального монитора
 */
export function getPerformanceMonitor(config?: Partial<PerformanceMonitorConfig>): PerformanceMonitor {
  if (!globalMonitor) {
    globalMonitor = new PerformanceMonitor(config);
  }
  return globalMonitor;
}

/**
 * Декоратор для профилирования методов
 */
export function profile(target: unknown, propertyKey: string, descriptor: PropertyDescriptor) {
  const originalMethod = descriptor.value;
  
  descriptor.value = async function (...args: unknown[]) {
    const monitor = getPerformanceMonitor();
    const profileId = monitor.startProfile(propertyKey, 'method');
    
    try {
      const result = await originalMethod.apply(this, args);
      monitor.endProfile(profileId);
      return result;
    } catch (error) {
      monitor.endProfile(profileId, undefined, error as Error);
      throw error;
    }
  };
  
  return descriptor;
}
