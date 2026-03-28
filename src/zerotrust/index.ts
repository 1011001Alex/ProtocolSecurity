/**
 * Zero Trust Network Architecture - Index
 *
 * Центральный экспорт всех компонентов Zero Trust Architecture.
 *
 * @version 1.0.0
 * @author grigo
 * @date 22 марта 2026 г.
 */

// ============================================================================
// TYPES
// ============================================================================

export * from './zerotrust.types';

// ============================================================================
// CORE COMPONENTS
// ============================================================================

/**
 * Policy Decision Point (PDP)
 *
 * Точка принятия решений политик. Оценивает запросы доступа
 * и принимает решения на основе политик, контекста и уровня доверия.
 */
export { PolicyDecisionPoint } from './PolicyDecisionPoint';
export type { PdpConfig } from './PolicyDecisionPoint';

/**
 * Policy Enforcement Point (PEP)
 *
 * Точка принудительного применения политик. Перехватывает запросы,
 * взаимодействует с PDP и применяет решения о доступе.
 */
export { PolicyEnforcementPoint } from './PolicyEnforcementPoint';
export type { PepConfig } from './PolicyEnforcementPoint';

/**
 * Device Posture Checker
 *
 * Проверка состояния устройств. Непрерывная проверка соответствия
 * устройств политикам безопасности организации.
 */
export { DevicePostureChecker } from './DevicePostureChecker';
export type { DevicePostureCheckerConfig } from './DevicePostureChecker';

/**
 * Trust Verifier
 *
 * Непрерывная верификация доверия. Динамическая оценка и пере оценка
 * уровня доверия к субъектам в реальном времени.
 */
export { TrustVerifier } from './TrustVerifier';
export type { TrustVerifierConfig } from './TrustVerifier';

// ============================================================================
// NETWORK SEGMENTATION
// ============================================================================

/**
 * Micro-Segmentation
 *
 * Микросегментация сети для предотвращения lateral movement атак.
 * Создаёт изолированные сегменты и применяет детальные правила трафика.
 */
export { MicroSegmentation } from './MicroSegmentation';
export type { MicroSegmentationConfig } from './MicroSegmentation';

/**
 * Network Access Control (NAC)
 *
 * Контекстно-зависимый контроль доступа к сети на основе идентичности,
 * устройства, местоположения и других факторов.
 */
export { NetworkAccessControl } from './NetworkAccessControl';
export type { NetworkAccessControlConfig } from './NetworkAccessControl';

// ============================================================================
// PERIMETER & PROXY
// ============================================================================

/**
 * Software Defined Perimeter (SDP)
 *
 * Программно-определяемый периметр. Скрывает ресурсы от
 * неавторизованных клиентов. Ресурсы видимы только после
 * успешной аутентификации и авторизации.
 */
export { SoftwareDefinedPerimeter } from './SoftwareDefinedPerimeter';
export type { SdpConfig } from './SoftwareDefinedPerimeter';

/**
 * Identity-Aware Proxy
 *
 * Прокси-сервер с учётом идентичности. Принимает решения о
 * маршрутизации запросов на основе идентичности и контекста.
 */
export { IdentityAwareProxy } from './IdentityAwareProxy';
export type { IdentityAwareProxyConfig } from './IdentityAwareProxy';

// ============================================================================
// SERVICE MESH & TLS
// ============================================================================

/**
 * Service Mesh mTLS
 *
 * Mutual TLS для микросервисов. Автоматическая генерация,
 * ротация и отзыв сертификатов для каждого сервиса.
 */
export { ServiceMeshMTLS } from './ServiceMeshMTLS';
export type { ServiceMeshMtlsConfig } from './ServiceMeshMTLS';

/**
 * TLS Everywhere
 *
 * Управление TLS конфигурацией для обеспечения шифрования
 * всего трафика в системе. TLS 1.3 везде.
 */
export { TlsEverywhere } from './TLSEverywhere';
export type { TlsEverywhereConfig } from './TLSEverywhere';

// ============================================================================
// ACCESS MANAGEMENT
// ============================================================================

/**
 * Just-In-Time Access
 *
 * Временный доступ по запросу. Предоставление временных
 * привилегий с обязательным утверждением и аудитом.
 */
export { JustInTimeAccess } from './JustInTimeAccess';
export type { JustInTimeAccessConfig } from './JustInTimeAccess';

/**
 * Egress Filter
 *
 * Фильтрация исходящего трафика с DLP (Data Loss Prevention)
 * для предотвращения утечек данных.
 */
export { EgressFilter } from './EgressFilter';
export type { EgressFilterConfig } from './EgressFilter';

// ============================================================================
// POLICY ENGINE
// ============================================================================

/**
 * Network Policy Engine
 *
 * Централизованный движок для управления всеми сетевыми
 * политиками Zero Trust архитектуры.
 */
export { NetworkPolicyEngine } from './NetworkPolicyEngine';
export type { NetworkPolicyEngineConfig } from './NetworkPolicyEngine';

// ============================================================================
// MAIN CONTROLLER
// ============================================================================

/**
 * Zero Trust Controller
 *
 * Главный контроллер, координирующий все компоненты
 * Zero Trust Network Architecture.
 */
export { ZeroTrustController } from './ZeroTrustController';
export type { ZeroTrustControllerConfig } from './ZeroTrustController';

// ============================================================================
// DEFAULT EXPORTS
// ============================================================================

import { ZeroTrustController } from './ZeroTrustController';
import { PolicyDecisionPoint } from './PolicyDecisionPoint';
import { PolicyEnforcementPoint } from './PolicyEnforcementPoint';
import { DevicePostureChecker } from './DevicePostureChecker';
import { TrustVerifier } from './TrustVerifier';
import { MicroSegmentation } from './MicroSegmentation';
import { SoftwareDefinedPerimeter } from './SoftwareDefinedPerimeter';
import { IdentityAwareProxy } from './IdentityAwareProxy';
import { ServiceMeshMTLS } from './ServiceMeshMTLS';
import { NetworkAccessControl } from './NetworkAccessControl';
import { JustInTimeAccess } from './JustInTimeAccess';
import { EgressFilter } from './EgressFilter';
import { TlsEverywhere } from './TLSEverywhere';
import { NetworkPolicyEngine } from './NetworkPolicyEngine';

export default {
  ZeroTrustController,
  PolicyDecisionPoint,
  PolicyEnforcementPoint,
  DevicePostureChecker,
  TrustVerifier,
  MicroSegmentation,
  SoftwareDefinedPerimeter,
  IdentityAwareProxy,
  ServiceMeshMTLS,
  NetworkAccessControl,
  JustInTimeAccess,
  EgressFilter,
  TlsEverywhere,
  NetworkPolicyEngine
};
