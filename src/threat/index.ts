/**
 * ============================================================================
 * THREAT DETECTION MODULE EXPORTS
 * Экспорт всех компонентов системы обнаружения угроз
 * ============================================================================
 */

// Основной движок
export { ThreatDetectionEngine } from './ThreatDetectionEngine';

// Сервисы анализа
export { UEBAService } from './UEBAService';
export { MITREAttackMapper } from './MITREAttackMapper';
export { ThreatIntelligenceService } from './ThreatIntelligence';
export { CorrelationEngine } from './CorrelationEngine';
export { RiskScorer } from './RiskScorer';
export { NetworkAnalyzer } from './NetworkAnalyzer';
export { EndpointDetector } from './EndpointDetector';
export { KillChainAnalyzer } from './KillChainAnalyzer';
export { ThreatDashboardService } from './ThreatDashboard';
export { ThreatHuntingService } from './ThreatHunting';
export { AutomatedResponseService } from './AutomatedResponse';

// ML модели
export {
  IsolationForest,
  LSTMModel,
  AutoencoderModel,
  MLModelManager
} from './MLModels';

// Типы
export * from '../types/threat.types';

/**
 * ============================================================================
 * ПРИМЕР ИСПОЛЬЗОВАНИЯ
 * ============================================================================
 * 
 * import {
 *   ThreatDetectionEngine,
 *   ThreatSeverity,
 *   SecurityEvent
 * } from './threat';
 * 
 * // Инициализация движка
 * const engine = new ThreatDetectionEngine({
 *   enabled: true,
 *   mlEnabled: true,
 *   uebaEnabled: true,
 *   threatIntelEnabled: true
 * });
 * 
 * // Обработка события
 * const event: SecurityEvent = {
 *   id: 'event-001',
 *   timestamp: new Date(),
 *   eventType: 'failed_login',
 *   source: 'auth-service',
 *   sourceIp: '192.168.1.100',
 *   severity: ThreatSeverity.MEDIUM,
 *   category: ThreatCategory.CREDENTIAL_ACCESS,
 *   rawEvent: {},
 *   normalizedEvent: {}
 * };
 * 
 * const result = await engine.processEvent(event);
 * console.log('Обработано событий:', result.eventId);
 * console.log('Создано алертов:', result.alerts.length);
 * 
 * // Получение данных дашборда
 * const dashboard = engine.getDashboardData();
 * console.log('Всего алертов:', dashboard.summary.totalAlerts);
 * console.log('Критических:', dashboard.summary.criticalAlerts);
 * 
 * ============================================================================
 */
