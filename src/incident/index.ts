/**
 * ============================================================================
 * INCIDENT RESPONSE MODULE
 * ============================================================================
 * Система автоматизированного реагирования на инциденты безопасности
 * Соответствует NIST SP 800-61 и SANS Incident Response Methodology
 * ============================================================================
 */

// ============================================================================
// TYPES
// ============================================================================

export * from '../types/incident.types';

// ============================================================================
// CORE COMPONENTS
// ============================================================================

export {
  IncidentManager,
  IncidentManagerEvent,
  IncidentManagerConfig
} from './IncidentManager';

export {
  IncidentClassifier,
  ClassificationContext,
  ClassificationResult,
  ClassificationFactor
} from './IncidentClassifier';

export {
  PlaybookEngine,
  PlaybookEngineEvent,
  PlaybookEngineConfig,
  PlaybookExecutionContext
} from './PlaybookEngine';

// ============================================================================
// FORENSICS & EVIDENCE
// ============================================================================

export {
  ForensicsCollector,
  ForensicsCollectorEvent,
  ForensicsCollectorConfig,
  ForensicsCollectionContext,
  CollectionResult
} from './ForensicsCollector';

export {
  EvidenceManager,
  EvidenceManagerEvent,
  EvidenceManagerConfig,
  AccessRecord
} from './EvidenceManager';

// ============================================================================
// CONTAINMENT
// ============================================================================

export {
  ContainmentActions,
  ContainmentActionsEvent,
  ContainmentModuleConfig,
  ContainmentActionContext,
  ContainmentActionResult
} from './ContainmentActions';

// ============================================================================
// COMMUNICATION
// ============================================================================

export {
  CommunicationManager,
  CommunicationManagerEvent,
  CommunicationManagerConfig
} from './CommunicationManager';

// ============================================================================
// TIMELINE & ANALYSIS
// ============================================================================

export {
  TimelineReconstructor,
  TimelineReconstructorEvent,
  TimelineReconstructorConfig,
  EventSource
} from './TimelineReconstructor';

export {
  PostIncidentReview,
  PostIncidentReviewEvent,
  PostIncidentReviewConfig
} from './PostIncidentReview';

// ============================================================================
// INTEGRATIONS
// ============================================================================

export {
  ExternalIntegrations,
  ExternalIntegrationsEvent,
  IntegrationResult
} from './ExternalIntegrations';

// ============================================================================
// REPORTING
// ============================================================================

export {
  IncidentReporter,
  IncidentReporterEvent,
  IncidentReporterConfig,
  ReportType,
  IncidentReport
} from './IncidentReporter';

// ============================================================================
// PLAYBOOKS
// ============================================================================

export {
  createMalwareOutbreakPlaybook,
  malwareOutbreakPlaybook
} from './Playbooks/MalwareOutbreak';

export {
  createDataBreachPlaybook,
  dataBreachPlaybook
} from './Playbooks/DataBreach';

export {
  createDDoSAttackPlaybook,
  ddosAttackPlaybook
} from './Playbooks/DDoSAttack';

export {
  createInsiderThreatPlaybook,
  insiderThreatPlaybook
} from './Playbooks/InsiderThreat';

export {
  createCredentialCompromisePlaybook,
  credentialCompromisePlaybook
} from './Playbooks/CredentialCompromise';

export {
  createRansomwareAttackPlaybook,
  ransomwareAttackPlaybook
} from './Playbooks/RansomwareAttack';
