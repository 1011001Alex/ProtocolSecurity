/**
 * ============================================================================
 * INSIDER THREAT PLAYBOOK
 * ============================================================================
 * Playbook для реагирования на угрозы изнутри
 * Соответствует NIST SP 800-61 и лучшим практикам insider threat detection
 * ============================================================================
 */

import {
  PlaybookConfiguration,
  PlaybookStep,
  PlaybookStepCategory,
  PlaybookActionType,
  PlaybookStepStatus,
  IncidentCategory,
  IncidentSeverity,
  ConditionType,
  ConditionOperator
} from '../../types/incident.types';

/**
 * Создание конфигурации playbook для insider threat
 */
export function createInsiderThreatPlaybook(): PlaybookConfiguration {
  const steps: PlaybookStep[] = [
    // ========================================================================
    // ФАЗА 1: DETECTION & INITIAL ASSESSMENT
    // ========================================================================

    {
      id: 'detect-001',
      name: 'Verify Insider Threat Alert',
      description: 'Верификация сигнала об угрозе изнутри',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'insider_threat_verification',
        checkUEBAAlerts: true,
        checkDLPAlerts: true,
        checkAccessPatterns: true,
        verifyFalsePositive: true
      },
      conditions: [],
      dependencies: [],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-002',
      name: 'Identify Suspected Insider',
      description: 'Идентификация подозреваемого',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'user_identification',
        collectUserInfo: true,
        collectRoleInfo: true,
        collectAccessLevel: true,
        collectDepartment: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 180000,
      retryCount: 1,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-003',
      name: 'Assess Threat Category',
      description: 'Оценка категории угрозы',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'threat_categorization',
        detectDataTheft: true,
        detectSabotage: true,
        detectFraud: true,
        detectEspionage: true,
        detectUnauthorizedAccess: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'detect-004',
      name: 'Collect User Activity History',
      description: 'Сбор истории активности пользователя',
      category: PlaybookStepCategory.FORENSICS,
      actionType: PlaybookActionType.COLLECT_DATA,
      parameters: {
        dataType: 'user_activity',
        collectLogonHistory: true,
        collectFileAccess: true,
        collectEmailActivity: true,
        collectNetworkActivity: true,
        collectPrivilegeUse: true,
        timeRange: '90_days'
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 2: INVESTIGATION
    // ========================================================================

    {
      id: 'investigate-001',
      name: 'Analyze Access Patterns',
      description: 'Анализ паттернов доступа',
      category: PlaybookStepCategory.ANALYSIS,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'access_pattern_analysis',
        detectAnomalies: true,
        compareWithBaseline: true,
        identifyUnusualTimes: true,
        identifyUnusualLocations: true,
        identifyExcessiveAccess: true
      },
      conditions: [],
      dependencies: ['detect-004'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'investigate-002',
      name: 'Review Data Access Logs',
      description: 'Проверка логов доступа к данным',
      category: PlaybookStepCategory.ANALYSIS,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'data_access_review',
        identifySensitiveDataAccessed: true,
        quantifyDataVolume: true,
        identifyDataTransfers: true,
        checkDownloadActivity: true
      },
      conditions: [],
      dependencies: ['detect-004'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'investigate-003',
      name: 'Analyze Communication Patterns',
      description: 'Анализ коммуникационных паттернов',
      category: PlaybookStepCategory.ANALYSIS,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'communication_analysis',
        reviewEmails: true,
        reviewChatLogs: true,
        detectExternalContacts: true,
        detectCompetitorContacts: true,
        detectDataSharing: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 900000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'investigate-004',
      name: 'Check for Policy Violations',
      description: 'Проверка нарушений политик',
      category: PlaybookStepCategory.ANALYSIS,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'policy_violation_check',
        checkSecurityPolicies: true,
        checkDataHandlingPolicies: true,
        checkAcceptableUsePolicy: true,
        checkNDAAgreements: true
      },
      conditions: [],
      dependencies: ['investigate-001', 'investigate-002'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'investigate-005',
      name: 'Interview Witnesses',
      description: 'Опрос свидетелей',
      category: PlaybookStepCategory.ANALYSIS,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'witness_interview',
        interviewColleagues: true,
        interviewSupervisor: true,
        interviewITStaff: true,
        documentFindings: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 3600000,
      retryCount: 1,
      retryInterval: 60000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 3: CONTAINMENT
    // ========================================================================

    {
      id: 'contain-001',
      name: 'Restrict User Access',
      description: 'Ограничение доступа пользователя',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        restrictionType: 'partial',
        revokePrivilegedAccess: true,
        restrictDataAccess: true,
        restrictSystemAccess: false,
        maintainAuditTrail: true
      },
      conditions: [
        {
          type: ConditionType.SEVERITY_LEVEL,
          field: 'incident.severity',
          operator: ConditionOperator.IN,
          value: ['critical', 'high']
        }
      ],
      dependencies: ['detect-003'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 3000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true,
      rollbackAction: {
        id: 'contain-001-rollback',
        name: 'Restore User Access',
        description: 'Восстановление доступа пользователя',
        category: PlaybookStepCategory.RECOVERY,
        actionType: PlaybookActionType.RUN_SCRIPT,
        parameters: {
          scriptType: 'restore_access'
        },
        status: PlaybookStepStatus.PENDING
      }
    },

    {
      id: 'contain-002',
      name: 'Suspend User Account',
      description: 'Приостановка учетной записи пользователя',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.LOCK_ACCOUNT,
      parameters: {
        lockType: 'suspension',
        preserveMailbox: true,
        preserveFiles: true,
        notifyUser: false,
        reason: 'security_investigation'
      },
      conditions: [
        {
          type: ConditionType.SEVERITY_LEVEL,
          field: 'incident.severity',
          operator: ConditionOperator.EQUALS,
          value: 'critical'
        }
      ],
      dependencies: ['investigate-004'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 3000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-003',
      name: 'Revoke Active Sessions',
      description: 'Отзыв активных сессий',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.REVOKE_TOKENS,
      parameters: {
        revokeType: 'all_sessions',
        revokeAPIKeys: true,
        revokeSSOTokens: true,
        revokeVPNAccess: true,
        forceReauthentication: true
      },
      conditions: [],
      dependencies: ['contain-002'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 3000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-004',
      name: 'Secure Physical Access',
      description: 'Обеспечение физического доступа',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'secure_physical_access',
        disableBadgeAccess: true,
        notifySecurity: true,
        escortRequired: true,
        collectBadges: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'incident.details.physicalAccessRisk',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['contain-002'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-005',
      name: 'Preserve Digital Evidence',
      description: 'Сохранение цифровых улик',
      category: PlaybookStepCategory.FORENSICS,
      actionType: PlaybookActionType.COLLECT_DATA,
      parameters: {
        dataType: 'insider_evidence',
        imageWorkstation: true,
        collectEmails: true,
        collectFiles: true,
        collectBrowserHistory: true,
        collectUSBHistory: true,
        maintainChainOfCustody: true
      },
      conditions: [],
      dependencies: ['contain-001'],
      timeout: 1800000,
      retryCount: 1,
      retryInterval: 30000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 4: ERADICATION
    // ========================================================================

    {
      id: 'eradicate-001',
      name: 'Remove Unauthorized Access',
      description: 'Удаление несанкционированного доступа',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'remove_unauthorized_access',
        removeBackdoors: true,
        removeCreatedAccounts: true,
        removeModifiedPermissions: true,
        auditChanges: true
      },
      conditions: [],
      dependencies: ['investigate-004'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'eradicate-002',
      name: 'Recover Exfiltrated Data',
      description: 'Восстановление экфильтрированных данных',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'recover_data',
        identifyExfiltratedData: true,
        attemptRecovery: true,
        notifyRecipients: true,
        requestDeletion: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'investigate-002.dataExfiltrated',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['investigate-002'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 30000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'eradicate-003',
      name: 'Update Security Controls',
      description: 'Обновление средств безопасности',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'insider_threat_controls',
        updateDLP: true,
        updateUEBA: true,
        updateAccessPolicies: true,
        enhanceMonitoring: true
      },
      conditions: [],
      dependencies: ['eradicate-001'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 5: LEGAL & HR COORDINATION
    // ========================================================================

    {
      id: 'legal-001',
      name: 'Notify Legal Team',
      description: 'Уведомление юридического отдела',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'email',
        recipients: ['legal-team'],
        templateId: 'insider-threat-legal-notice',
        priority: 'critical',
        includeEvidence: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 60000,
      retryCount: 3,
      retryInterval: 2000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'hr-001',
      name: 'Notify HR Department',
      description: 'Уведомление HR отдела',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'email',
        recipients: ['hr-team'],
        templateId: 'insider-threat-hr-notice',
        priority: 'critical',
        includeUserInfo: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 60000,
      retryCount: 3,
      retryInterval: 2000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'hr-002',
      name: 'Coordinate Employee Actions',
      description: 'Координация действий с сотрудником',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'hr_coordination',
        planTerminationMeeting: false,
        planAdministrativeLeave: false,
        coordinateWithLegal: true,
        documentHRActions: true
      },
      conditions: [],
      dependencies: ['hr-001', 'legal-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 30000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'legal-002',
      name: 'Assess Legal Action Options',
      description: 'Оценка вариантов юридических действий',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'legal_assessment',
        assessCriminalCharges: true,
        assessCivilAction: true,
        assessRestrainingOrder: true,
        documentLegalOptions: true
      },
      conditions: [
        {
          type: ConditionType.SEVERITY_LEVEL,
          field: 'incident.severity',
          operator: ConditionOperator.IN,
          value: ['critical', 'high']
        }
      ],
      dependencies: ['investigate-004'],
      timeout: 900000,
      retryCount: 1,
      retryInterval: 30000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: false
    },

    // ========================================================================
    // ФАЗА 6: COMMUNICATION & DOCUMENTATION
    // ========================================================================

    {
      id: 'comm-001',
      name: 'Notify Security Team',
      description: 'Уведомление команды безопасности',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'slack',
        recipients: ['security-team'],
        templateId: 'insider-threat-alert',
        priority: 'high'
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 60000,
      retryCount: 3,
      retryInterval: 2000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'comm-002',
      name: 'Notify Management',
      description: 'Уведомление руководства',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'email',
        recipients: ['management'],
        templateId: 'insider-threat-management-brief',
        priority: 'high',
        needToKnow: true
      },
      conditions: [
        {
          type: ConditionType.SEVERITY_LEVEL,
          field: 'incident.severity',
          operator: ConditionOperator.IN,
          value: ['critical', 'high']
        }
      ],
      dependencies: ['detect-003'],
      timeout: 120000,
      retryCount: 3,
      retryInterval: 2000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: true
    },

    {
      id: 'comm-003',
      name: 'Create Incident Ticket',
      description: 'Создание тикета инцидента',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.CREATE_TICKET,
      parameters: {
        system: 'servicenow',
        templateId: 'insider-threat-incident',
        assignTo: 'security-investigations',
        priority: 'high',
        restrictAccess: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'doc-001',
      name: 'Document Investigation Findings',
      description: 'Документирование результатов расследования',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'investigation_report',
        includeTimeline: true,
        includeEvidence: true,
        includeWitnessStatements: true,
        includeConclusions: true,
        classifyAsConfidential: true
      },
      conditions: [],
      dependencies: ['investigate-005'],
      timeout: 900000,
      retryCount: 1,
      retryInterval: 30000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'doc-002',
      name: 'Maintain Chain of Custody',
      description: 'Поддержание цепочки хранения улик',
      category: PlaybookStepCategory.FORENSICS,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'chain_of_custody',
        documentAllEvidence: true,
        recordTransfers: true,
        recordAccess: true,
        maintainIntegrity: true
      },
      conditions: [],
      dependencies: ['contain-005'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: false
    }
  ];

  return {
    id: 'insider-threat-v1.0',
    name: 'Insider Threat Response',
    description: 'Комплексный playbook для реагирования на угрозы изнутри. Включает обнаружение, расследование, сдерживание и координацию с HR/Legal.',
    version: '1.0.0',
    incidentCategory: IncidentCategory.INSIDER_THREAT,
    minSeverity: IncidentSeverity.MEDIUM,
    steps,
    variables: {
      legalHoldEnabled: true,
      preserveEvidenceDays: 2555,
      hrCoordinationRequired: true,
      confidentialInvestigation: true,
      employeeRightsProtected: true,
      unionNotificationRequired: false
    },
    integrations: ['ueba', 'dlp', 'active_directory', 'email', 'servicenow', 'slack'],
    tags: ['insider-threat', 'employee', 'data-theft', 'sabotage', 'investigation'],
    author: 'Security Operations Team',
    lastUpdated: new Date(),
    status: 'active'
  };
}

/**
 * Экспорт конфигурации playbook
 */
export const insiderThreatPlaybook = createInsiderThreatPlaybook();
