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
  IncidentManagerEvent
} from './IncidentManager';

export type { IncidentManagerConfig } from './IncidentManager';

export {
  IncidentClassifier
} from './IncidentClassifier';

export type {
  ClassificationContext,
  ClassificationResult,
  ClassificationFactor
} from './IncidentClassifier';

export {
  PlaybookEngine,
  PlaybookEngineEvent
} from './PlaybookEngine';

export type {
  PlaybookEngineConfig,
  PlaybookExecutionContext
} from './PlaybookEngine';

// ============================================================================
// FORENSICS & EVIDENCE
// ============================================================================

export {
  ForensicsCollector,
  ForensicsCollectorEvent
} from './ForensicsCollector';

export type {
  ForensicsCollectorConfig,
  ForensicsCollectionContext,
  CollectionResult
} from './ForensicsCollector';

export {
  EvidenceManager,
  EvidenceManagerEvent
} from './EvidenceManager';

export type {
  EvidenceManagerConfig,
  AccessRecord
} from './EvidenceManager';

// ============================================================================
// CONTAINMENT
// ============================================================================

export {
  ContainmentActions,
  ContainmentActionsEvent
} from './ContainmentActions';

export type {
  ContainmentModuleConfig,
  ContainmentActionContext,
  ContainmentActionResult
} from './ContainmentActions';

// ============================================================================
// COMMUNICATION
// ============================================================================

export {
  CommunicationManager,
  CommunicationManagerEvent
} from './CommunicationManager';

export type {
  CommunicationManagerConfig
} from './CommunicationManager';

// ============================================================================
// TIMELINE & ANALYSIS
// ============================================================================

export {
  TimelineReconstructor,
  TimelineReconstructorEvent
} from './TimelineReconstructor';

export type {
  TimelineReconstructorConfig,
  EventSource
} from './TimelineReconstructor';

export {
  PostIncidentReview,
  PostIncidentReviewEvent
} from './PostIncidentReview';

export type {
  PostIncidentReviewConfig
} from './PostIncidentReview';

// ============================================================================
// INTEGRATIONS
// ============================================================================

export {
  ExternalIntegrations,
  ExternalIntegrationsEvent
} from './ExternalIntegrations';

export type {
  IntegrationResult
} from './ExternalIntegrations';

// ============================================================================
// REPORTING
// ============================================================================

export {
  IncidentReporter,
  IncidentReporterEvent,
  ReportType
} from './IncidentReporter';

export type {
  IncidentReporterConfig,
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
