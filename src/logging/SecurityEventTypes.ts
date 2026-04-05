/**
 * =============================================================================
 * SECURITY EVENT TYPES
 * =============================================================================
 * Полная типизация всех security событий
 * 50+ типов событий для всех категорий
 * =============================================================================
 */

import { SecurityCategory, SecuritySeverity, SecurityOutcome, SecurityEvent } from './StructuredSecurityLogger';

// =============================================================================
// AUTHENTICATION EVENTS
// =============================================================================

/**
 * События аутентификации
 */
export interface AuthenticationEvent extends SecurityEvent {
  category: SecurityCategory.AUTHENTICATION;
  eventType: 
    | 'LOGIN_INITIATED'
    | 'LOGIN_SUCCESS'
    | 'LOGIN_FAILURE'
    | 'LOGOUT'
    | 'LOGOUT_ALL'
    | 'PASSWORD_CHANGE_INITIATED'
    | 'PASSWORD_CHANGE_SUCCESS'
    | 'PASSWORD_CHANGE_FAILURE'
    | 'PASSWORD_RESET_REQUESTED'
    | 'PASSWORD_RESET_COMPLETED'
    | 'MFA_ENROLLMENT_INITIATED'
    | 'MFA_ENROLLMENT_COMPLETED'
    | 'MFA_CHALLENGE_SENT'
    | 'MFA_CHALLENGE_SUCCESS'
    | 'MFA_CHALLENGE_FAILURE'
    | 'WEBAUTHN_REGISTRATION'
    | 'WEBAUTHN_AUTHENTICATION'
    | 'SESSION_CREATED'
    | 'SESSION_EXTENDED'
    | 'SESSION_REVOKED'
    | 'TOKEN_ISSUED'
    | 'TOKEN_REFRESHED'
    | 'TOKEN_REVOKED';
  
  actor: {
    id?: string;
    type: 'user' | 'service' | 'system' | 'anonymous';
    identifier?: string;
    roles?: string[];
  };
  
  data: {
    authMethod?: 'password' | 'mfa' | 'webauthn' | 'oauth' | 'saml' | 'oidc';
    mfaMethod?: 'totp' | 'hotp' | 'sms' | 'email' | 'webauthn' | 'backup_code';
    failureReason?: string;
    failureCount?: number;
    lockoutImminent?: boolean;
    newPasswordHash?: string;
    sessionId?: string;
    tokenId?: string;
    oauthProvider?: string;
    samlIssuer?: string;
    deviceFingerprint?: string;
    rememberDevice?: boolean;
  };
}

// =============================================================================
// AUTHORIZATION EVENTS
// =============================================================================

/**
 * События авторизации
 */
export interface AuthorizationEvent extends SecurityEvent {
  category: SecurityCategory.AUTHORIZATION;
  eventType:
    | 'ACCESS_GRANTED'
    | 'ACCESS_DENIED'
    | 'PERMISSION_CHECK'
    | 'ROLE_ASSIGNMENT'
    | 'ROLE_REVOCATION'
    | 'POLICY_EVALUATION'
    | 'PRIVILEGE_ESCALATION'
    | 'JIT_ACCESS_GRANTED'
    | 'JIT_ACCESS_EXPIRED'
    | 'ADMIN_ACTION'
    | 'SENSITIVE_OPERATION';
  
  actor: {
    id: string;
    type: 'user' | 'service';
    identifier: string;
    roles: string[];
  };
  
  data: {
    requestedPermission: string;
    grantedPermissions: string[];
    policyId?: string;
    policyName?: string;
    evaluationResult: 'permit' | 'deny' | 'indeterminate';
    denialReason?: string;
    escalationReason?: string;
    escalationApprovedBy?: string;
    jitDuration?: number;
    jitExpiry?: string;
  };
}

// =============================================================================
// DATA EVENTS
// =============================================================================

/**
 * События доступа к данным
 */
export interface DataEvent extends SecurityEvent {
  category: SecurityCategory.DATA;
  eventType:
    | 'DATA_READ'
    | 'DATA_WRITE'
    | 'DATA_UPDATE'
    | 'DATA_DELETE'
    | 'DATA_EXPORT'
    | 'DATA_IMPORT'
    | 'DATA_MASS_OPERATION'
    | 'DATA_ANONYMIZATION'
    | 'DATA_ENCRYPTION'
    | 'DATA_DECRYPTION'
    | 'BACKUP_CREATED'
    | 'BACKUP_RESTORED'
    | 'DATA_RETENTION_APPLIED';
  
  actor: {
    id: string;
    type: 'user' | 'service' | 'system';
    identifier: string;
  };
  
  data: {
    dataType: string;
    dataClassification: 'public' | 'internal' | 'confidential' | 'restricted' | 'pii' | 'phi';
    recordCount?: number;
    dataSizeBytes?: number;
    queryType?: 'select' | 'insert' | 'update' | 'delete';
    tableName?: string;
    fieldNames?: string[];
    exportFormat?: 'csv' | 'json' | 'xml' | 'pdf';
    destinationPath?: string;
    encryptionAlgorithm?: string;
    retentionDays?: number;
  };
}

// =============================================================================
// NETWORK EVENTS
// =============================================================================

/**
 * Сетевые события
 */
export interface NetworkEvent extends Omit<SecurityEvent, 'actor'> {
  category: SecurityCategory.NETWORK;
  eventType:
    | 'CONNECTION_ESTABLISHED'
    | 'CONNECTION_TERMINATED'
    | 'CONNECTION_REFUSED'
    | 'REQUEST_RECEIVED'
    | 'RESPONSE_SENT'
    | 'FIREWALL_BLOCK'
    | 'FIREWALL_RULE_TRIGGERED'
    | 'RATE_LIMIT_EXCEEDED'
    | 'DDOS_DETECTED'
    | 'PORT_SCAN_DETECTED'
    | 'SUSPICIOUS_TRAFFIC'
    | 'TLS_HANDSHAKE'
    | 'TLS_ERROR'
    | 'DNS_QUERY'
    | 'DNS_RESOLUTION_FAILURE';
  
  actor: {
    type: 'system' | 'external';
    id?: string;
  };
  
  data: {
    sourceIp: string;
    sourcePort?: number;
    destinationIp: string;
    destinationPort?: number;
    protocol: 'TCP' | 'UDP' | 'HTTP' | 'HTTPS' | 'DNS' | 'OTHER';
    bytesSent?: number;
    bytesReceived?: number;
    duration?: number;
    tlsVersion?: string;
    cipherSuite?: string;
    certificateSubject?: string;
    firewallRuleId?: string;
    rateLimitKey?: string;
    requestCount?: number;
    timeWindow?: number;
  };
}

// =============================================================================
// THREAT EVENTS
// =============================================================================

/**
 * События угроз
 */
export interface ThreatEvent extends Omit<SecurityEvent, 'actor'> {
  category: SecurityCategory.THREAT;
  eventType:
    | 'INTRUSION_ATTEMPT'
    | 'MALWARE_DETECTED'
    | 'RANSOMWARE_DETECTED'
    | 'DDOS_ATTACK'
    | 'BRUTE_FORCE_DETECTED'
    | 'CREDENTIAL_STUFFING'
    | 'SQL_INJECTION_ATTEMPT'
    | 'XSS_ATTEMPT'
    | 'CSRF_ATTEMPT'
    | 'PATH_TRAVERSAL_ATTEMPT'
    | 'COMMAND_INJECTION_ATTEMPT'
    | 'ANOMALY_DETECTED'
    | 'UEBA_ALERT'
    | 'MITRE_ATTACK_DETECTED'
    | 'THREAT_INTEL_MATCH'
    | 'ZERO_DAY_INDICATOR';
  
  severity: SecuritySeverity.HIGH | SecuritySeverity.CRITICAL;
  
  actor: {
    type: 'anonymous' | 'threat_actor';
    id?: string;
  };
  
  data: {
    threatType: string;
    threatCategory: 'reconnaissance' | 'initial_access' | 'execution' | 'persistence' | 'privilege_escalation' | 'defense_evasion' | 'credential_access' | 'discovery' | 'lateral_movement' | 'collection' | 'exfiltration' | 'impact';
    mitreAttackId?: string;
    mitreTechniqueId?: string;
    confidence: number;
    severity: number;
    ioc?: {
      type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
      value: string;
    }[];
    targetResources?: string[];
    attackVector?: string;
    payload?: string;
    signature?: string;
    threatIntelSource?: string;
    recommendedActions?: string[];
  };
}

// =============================================================================
// SYSTEM EVENTS
// =============================================================================

/**
 * Системные события
 */
export interface SystemEvent extends SecurityEvent {
  category: SecurityCategory.SYSTEM;
  eventType:
    | 'SYSTEM_STARTUP'
    | 'SYSTEM_SHUTDOWN'
    | 'SYSTEM_RESTART'
    | 'SERVICE_START'
    | 'SERVICE_STOP'
    | 'SERVICE_RESTART'
    | 'CONFIG_CHANGE'
    | 'CONFIG_ROLLBACK'
    | 'PATCH_APPLIED'
    | 'PATCH_FAILED'
    | 'CERTIFICATE_EXPIRING'
    | 'CERTIFICATE_EXPIRED'
    | 'CERTIFICATE_REVOKED'
    | 'SECRET_ROTATED'
    | 'SECRET_EXPIRING'
    | 'BACKUP_STARTED'
    | 'BACKUP_COMPLETED'
    | 'BACKUP_FAILED'
    | 'HEALTH_CHECK_PASSED'
    | 'HEALTH_CHECK_FAILED'
    | 'RESOURCE_EXHAUSTION'
    | 'DISK_SPACE_LOW'
    | 'MEMORY_PRESSURE'
    | 'CPU_HIGH';
  
  actor: {
    type: 'system';
    component: string;
  };
  
  data: {
    componentName: string;
    componentVersion?: string;
    previousConfig?: string;
    newConfig?: string;
    changedBy?: string;
    changeReason?: string;
    patchVersion?: string;
    patchSeverity?: 'critical' | 'important' | 'moderate' | 'low';
    certificateSubject?: string;
    certificateIssuer?: string;
    certificateExpiry?: string;
    secretId?: string;
    secretType?: string;
    resourceType: 'cpu' | 'memory' | 'disk' | 'network';
    currentValue?: number;
    thresholdValue?: number;
    errorCode?: string;
    errorMessage?: string;
  };
}

// =============================================================================
// AUDIT EVENTS
// =============================================================================

/**
 * Audit события (для compliance)
 */
export interface AuditEvent extends SecurityEvent {
  category: SecurityCategory.AUDIT;
  eventType:
    | 'USER_CREATED'
    | 'USER_UPDATED'
    | 'USER_DELETED'
    | 'USER_ENABLED'
    | 'USER_DISABLED'
    | 'ROLE_CREATED'
    | 'ROLE_UPDATED'
    | 'ROLE_DELETED'
    | 'POLICY_CREATED'
    | 'POLICY_UPDATED'
    | 'POLICY_DELETED'
    | 'SECRET_ACCESSED'
    | 'SECRET_CREATED'
    | 'SECRET_UPDATED'
    | 'SECRET_DELETED'
    | 'KEY_GENERATED'
    | 'KEY_USED'
    | 'KEY_REVOKED'
    | 'KEY_ROTATED'
    | 'COMPLIANCE_CHECK'
    | 'COMPLIANCE_VIOLATION'
    | 'AUDIT_LOG_ACCESSED'
    | 'AUDIT_LOG_EXPORTED';
  
  actor: {
    id: string;
    type: 'user' | 'system';
    identifier: string;
    roles: string[];
  };
  
  data: {
    targetUserId?: string;
    targetUserEmail?: string;
    changes?: Record<string, {
      before: any;
      after: any;
    }>;
    policyId?: string;
    policyName?: string;
    secretId?: string;
    secretName?: string;
    keyId?: string;
    keyAlgorithm?: string;
    complianceFramework: 'PCI_DSS' | 'GDPR' | 'HIPAA' | 'SOX' | 'ISO27001' | 'NIST';
    controlId?: string;
    controlName?: string;
    complianceResult: 'pass' | 'fail' | 'warning';
    violationSeverity?: 'minor' | 'major' | 'critical';
    remediationRequired?: boolean;
    remediationDeadline?: string;
  };
}

// =============================================================================
// INCIDENT EVENTS
// =============================================================================

/**
 * События инцидентов
 */
export interface IncidentEvent extends SecurityEvent {
  category: SecurityCategory.THREAT;
  eventType:
    | 'INCIDENT_CREATED'
    | 'INCIDENT_UPDATED'
    | 'INCIDENT_ESCALATED'
    | 'INCIDENT_CONTAINED'
    | 'INCIDENT_RESOLVED'
    | 'INCIDENT_CLOSED'
    | 'PLAYBOOK_EXECUTED'
    | 'CONTAINMENT_ACTION'
    | 'ERADICATION_ACTION'
    | 'RECOVERY_ACTION'
    | 'LESSONS_LEARNED';
  
  severity: SecuritySeverity;
  
  data: {
    incidentId: string;
    incidentType: string;
    incidentTitle: string;
    incidentStatus: 'new' | 'investigating' | 'contained' | 'resolved' | 'closed';
    assignedTo?: string;
    escalatedTo?: string;
    playbookId?: string;
    playbookName?: string;
    containmentActions?: string[];
    affectedAssets?: string[];
    affectedUsers?: string[];
    rootCause?: string;
    impactAssessment?: {
      confidentiality: 'low' | 'medium' | 'high';
      integrity: 'low' | 'medium' | 'high';
      availability: 'low' | 'medium' | 'high';
    };
    timeDetected: string;
    timeContained?: string;
    timeResolved?: string;
    lessonsLearned?: string[];
  };
}

// =============================================================================
// TYPE UNION
// =============================================================================

/**
 * Union тип всех security событий
 */
export type AnySecurityEvent = 
  | AuthenticationEvent
  | AuthorizationEvent
  | DataEvent
  | NetworkEvent
  | ThreatEvent
  | SystemEvent
  | AuditEvent
  | IncidentEvent;

// =============================================================================
// EVENT SCHEMAS
// =============================================================================

/**
 * Схема валидации для каждого типа события
 */
export const EventSchemas = {
  authentication: {
    required: ['actor', 'action', 'outcome', 'context'],
    optional: ['data', 'error', 'tags']
  },
  authorization: {
    required: ['actor', 'action', 'resource', 'outcome', 'context'],
    optional: ['data', 'tags']
  },
  data: {
    required: ['actor', 'action', 'resource', 'outcome', 'context', 'data.dataType'],
    optional: ['data.recordCount', 'data.dataSizeBytes', 'tags']
  },
  network: {
    required: ['action', 'outcome', 'context', 'data.sourceIp', 'data.destinationIp'],
    optional: ['data.protocol', 'data.sourcePort', 'data.destinationPort', 'tags']
  },
  threat: {
    required: ['severity', 'action', 'outcome', 'context', 'data.threatType', 'data.confidence'],
    optional: ['data.mitreAttackId', 'data.ioc', 'tags']
  },
  system: {
    required: ['actor', 'action', 'outcome', 'context', 'data.componentName'],
    optional: ['data.errorCode', 'data.errorMessage', 'tags']
  },
  audit: {
    required: ['actor', 'action', 'outcome', 'context'],
    optional: ['data', 'tags']
  }
};

// =============================================================================
// EVENT CONSTANTS
// =============================================================================

/**
 * Константы для типов событий
 */
export const EventTypes = {
  // Authentication
  LOGIN: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  MFA_SUCCESS: 'MFA_CHALLENGE_SUCCESS',
  MFA_FAILURE: 'MFA_CHALLENGE_FAILURE',
  
  // Authorization
  ACCESS_GRANTED: 'ACCESS_GRANTED',
  ACCESS_DENIED: 'ACCESS_DENIED',
  
  // Data
  DATA_READ: 'DATA_READ',
  DATA_WRITE: 'DATA_WRITE',
  DATA_EXPORT: 'DATA_EXPORT',
  
  // Threat
  BRUTE_FORCE: 'BRUTE_FORCE_DETECTED',
  SQL_INJECTION: 'SQL_INJECTION_ATTEMPT',
  ANOMALY: 'ANOMALY_DETECTED'
} as const;

// =============================================================================
// ЭКСПОРТ — типы уже экспортированы при определении
// =============================================================================
