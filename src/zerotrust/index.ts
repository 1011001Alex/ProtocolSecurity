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

export * from './zerotrust/zerotrust.types';

// ============================================================================
// CORE COMPONENTS
// ============================================================================

/**
 * Policy Decision Point (PDP)
 * 
 * Точка принятия решений политик. Оценивает запросы доступа
 * и принимает решения на основе политик, контекста и уровня доверия.
 */
export { PolicyDecisionPoint, PdpConfig } from './zerotrust/PolicyDecisionPoint';

/**
 * Policy Enforcement Point (PEP)
 * 
 * Точка принудительного применения политик. Перехватывает запросы,
 * взаимодействует с PDP и применяет решения о доступе.
 */
export { 
  PolicyEnforcementPoint, 
  PepConfig, 
  PepRequestContext, 
  PepEnforcementResult 
} from './zerotrust/PolicyEnforcementPoint';

/**
 * Device Posture Checker
 * 
 * Проверка состояния устройств. Непрерывная проверка соответствия
 * устройств политикам безопасности организации.
 */
export { 
  DevicePostureChecker, 
  DevicePostureCheckerConfig 
} from './zerotrust/DevicePostureChecker';

/**
 * Trust Verifier
 * 
 * Непрерывная верификация доверия. Динамическая оценка и пере оценка
 * уровня доверия к субъектам в реальном времени.
 */
export { 
  TrustVerifier, 
  TrustVerifierConfig 
} from './zerotrust/TrustVerifier';

// ============================================================================
// NETWORK SEGMENTATION
// ============================================================================

/**
 * Micro-Segmentation
 * 
 * Микросегментация сети для предотвращения lateral movement атак.
 * Создаёт изолированные сегменты и применяет детальные правила трафика.
 */
export { 
  MicroSegmentation, 
  MicroSegmentationConfig 
} from './zerotrust/MicroSegmentation';

/**
 * Network Access Control (NAC)
 * 
 * Контекстно-зависимый контроль доступа к сети на основе идентичности,
 * устройства, местоположения и других факторов.
 */
export { 
  NetworkAccessControl, 
  NetworkAccessControlConfig 
} from './zerotrust/NetworkAccessControl';

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
export { 
  SoftwareDefinedPerimeter, 
  SdpConfig 
} from './zerotrust/SoftwareDefinedPerimeter';

/**
 * Identity-Aware Proxy
 * 
 * Прокси-сервер с учётом идентичности. Принимает решения о
 * маршрутизации запросов на основе идентичности и контекста.
 */
export { 
  IdentityAwareProxy, 
  IdentityAwareProxyConfig 
} from './zerotrust/IdentityAwareProxy';

// ============================================================================
// SERVICE MESH & TLS
// ============================================================================

/**
 * Service Mesh mTLS
 * 
 * Mutual TLS для микросервисов. Автоматическая генерация,
 * ротация и отзыв сертификатов для каждого сервиса.
 */
export { 
  ServiceMeshMTLS, 
  ServiceMeshMtlsConfig 
} from './zerotrust/ServiceMeshMTLS';

/**
 * TLS Everywhere
 * 
 * Управление TLS конфигурацией для обеспечения шифрования
 * всего трафика в системе. TLS 1.3 везде.
 */
export { 
  TlsEverywhere, 
  TlsEverywhereConfig 
} from './zerotrust/TLSEverywhere';

// ============================================================================
// ACCESS MANAGEMENT
// ============================================================================

/**
 * Just-In-Time Access
 * 
 * Временный доступ по запросу. Предоставление временных
 * привилегий с обязательным утверждением и аудитом.
 */
export { 
  JustInTimeAccess, 
  JustInTimeAccessConfig 
} from './zerotrust/JustInTimeAccess';

/**
 * Egress Filter
 * 
 * Фильтрация исходящего трафика с DLP (Data Loss Prevention)
 * для предотвращения утечек данных.
 */
export { 
  EgressFilter, 
  EgressFilterConfig 
} from './zerotrust/EgressFilter';

// ============================================================================
// POLICY ENGINE
// ============================================================================

/**
 * Network Policy Engine
 * 
 * Централизованный движок для управления всеми сетевыми
 * политиками Zero Trust архитектуры.
 */
export { 
  NetworkPolicyEngine, 
  NetworkPolicyEngineConfig 
} from './zerotrust/NetworkPolicyEngine';

// ============================================================================
// MAIN CONTROLLER
// ============================================================================

/**
 * Zero Trust Controller
 * 
 * Главный контроллер, координирующий все компоненты
 * Zero Trust Network Architecture.
 */
export { 
  ZeroTrustController, 
  ZeroTrustControllerConfig 
} from './zerotrust/ZeroTrustController';

// ============================================================================
// DEFAULT EXPORTS
// ============================================================================

import { ZeroTrustController } from './zerotrust/ZeroTrustController';
import { PolicyDecisionPoint } from './zerotrust/PolicyDecisionPoint';
import { PolicyEnforcementPoint } from './zerotrust/PolicyEnforcementPoint';
import { DevicePostureChecker } from './zerotrust/DevicePostureChecker';
import { TrustVerifier } from './zerotrust/TrustVerifier';
import { MicroSegmentation } from './zerotrust/MicroSegmentation';
import { SoftwareDefinedPerimeter } from './zerotrust/SoftwareDefinedPerimeter';
import { IdentityAwareProxy } from './zerotrust/IdentityAwareProxy';
import { ServiceMeshMTLS } from './zerotrust/ServiceMeshMTLS';
import { NetworkAccessControl } from './zerotrust/NetworkAccessControl';
import { JustInTimeAccess } from './zerotrust/JustInTimeAccess';
import { EgressFilter } from './zerotrust/EgressFilter';
import { TlsEverywhere } from './zerotrust/TLSEverywhere';
import { NetworkPolicyEngine } from './zerotrust/NetworkPolicyEngine';

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
