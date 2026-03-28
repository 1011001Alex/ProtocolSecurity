/**
 * ============================================================================
 * DATA BREACH PLAYBOOK
 * ============================================================================
 * Playbook для реагирования на утечки данных
 * Соответствует NIST SP 800-61, GDPR, и регуляторным требованиям
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
 * Создание конфигурации playbook для утечки данных
 */
export function createDataBreachPlaybook(): PlaybookConfiguration {
  const steps: PlaybookStep[] = [
    // ========================================================================
    // ФАЗА 1: DETECTION & INITIAL ASSESSMENT
    // ========================================================================

    {
      id: 'detect-001',
      name: 'Verify Data Breach Alert',
      description: 'Верификация сигнала об утечке данных',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'breach_verification',
        checkDLPAlerts: true,
        checkDatabaseLogs: true,
        checkNetworkTraffic: true,
        verifyFalsePositive: true
      },
      conditions: [],
      dependencies: [],
      timeout: 300000,
      retryCount: 2,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-002',
      name: 'Identify Affected Data Types',
      description: 'Идентификация типов затронутых данных',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'data_classification',
        checkForPII: true,
        checkForPHI: true,
        checkForPCI: true,
        checkForCredentials: true,
        checkForIP: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-003',
      name: 'Determine Breach Scope',
      description: 'Определение масштаба утечки',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.COLLECT_DATA,
      parameters: {
        dataType: 'breach_scope',
        countAffectedRecords: true,
        identifyDataVolume: true,
        mapDataFlow: true,
        identifyAccessPoints: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 900000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'detect-004',
      name: 'Identify Breach Vector',
      description: 'Идентификация вектора утечки',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'vector_analysis',
        checkSQLInjection: true,
        checkUnauthorizedAccess: true,
        checkInsiderThreat: true,
        checkThirdParty: true,
        checkPhysicalTheft: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: false
    },

    // ========================================================================
    // ФАЗА 2: CONTAINMENT
    // ========================================================================

    {
      id: 'contain-001',
      name: 'Block Unauthorized Access Paths',
      description: 'Блокировка путей несанкционированного доступа',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.BLOCK_IP,
      parameters: {
        blockType: 'access_paths',
        blockIPs: true,
        blockDomains: true,
        revokeAPIKeys: true,
        disableEndpoints: false
      },
      conditions: [],
      dependencies: ['detect-004'],
      timeout: 120000,
      retryCount: 3,
      retryInterval: 2000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true,
      rollbackAction: {
        id: 'contain-001-rollback',
        name: 'Restore Access Paths',
        description: 'Восстановление путей доступа',
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
      name: 'Revoke Compromised Credentials',
      description: 'Отзыв скомпрометированных учетных данных',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.REVOKE_TOKENS,
      parameters: {
        revokeType: 'all_sessions',
        resetPasswords: true,
        rotateAPIKeys: true,
        invalidateTokens: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'incident.details.credentialsCompromised',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['detect-002'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-003',
      name: 'Lock Compromised Accounts',
      description: 'Блокировка скомпрометированных учетных записей',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.LOCK_ACCOUNT,
      parameters: {
        lockType: 'compromised_accounts',
        notifyUsers: false,
        preserveAccess: true
      },
      conditions: [],
      dependencies: ['detect-004'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 3000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-004',
      name: 'Isolate Affected Systems',
      description: 'Изоляция затронутых систем',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.ISOLATE_HOST,
      parameters: {
        isolationMethod: 'network_segment',
        preserveEvidence: true,
        maintainForensicsAccess: true
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
      timeout: 180000,
      retryCount: 2,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-005',
      name: 'Stop Data Exfiltration',
      description: 'Остановка экфильтрации данных',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'stop_exfiltration',
        blockOutboundTransfers: true,
        monitorDataMovement: true,
        alertOnLargeTransfers: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 120000,
      retryCount: 3,
      retryInterval: 2000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 3: ERADICATION
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
        removeMalware: true,
        patchVulnerabilities: true
      },
      conditions: [],
      dependencies: ['contain-001', 'contain-004'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'eradicate-002',
      name: 'Patch Vulnerabilities',
      description: 'Устранение уязвимостей',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'security_patches',
        applyCriticalPatches: true,
        applyHighPatches: true,
        testBeforeApply: true
      },
      conditions: [],
      dependencies: ['detect-004'],
      timeout: 1800000,
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
        updateType: 'security_rules',
        updateDLP: true,
        updateSIEM: true,
        updateFirewall: true,
        updateIDS: true
      },
      conditions: [],
      dependencies: ['eradicate-001'],
      timeout: 300000,
      retryCount: 2,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    // ========================================================================
    // ФАЗА 4: RECOVERY
    // ========================================================================

    {
      id: 'recover-001',
      name: 'Restore Data from Backup',
      description: 'Восстановление данных из резервной копии',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RESTORE_FROM_BACKUP,
      parameters: {
        backupType: 'pre_breach',
        verifyIntegrity: true,
        scanForMalware: true,
        validateDataCompleteness: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'incident.details.dataCorrupted',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['eradicate-001'],
      timeout: 3600000,
      retryCount: 1,
      retryInterval: 60000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-002',
      name: 'Restore System Access',
      description: 'Восстановление доступа к системам',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'restore_access',
        verifySecurity: true,
        enableMFA: true,
        auditAccess: true
      },
      conditions: [],
      dependencies: ['eradicate-001'],
      timeout: 300000,
      retryCount: 2,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-003',
      name: 'Verify Data Integrity',
      description: 'Проверка целостности данных',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'data_integrity',
        checkChecksums: true,
        validateRecords: true,
        compareWithBackup: true
      },
      conditions: [],
      dependencies: ['recover-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    // ========================================================================
    // ФАЗА 5: LEGAL & COMPLIANCE
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
        templateId: 'data-breach-legal-notice',
        priority: 'critical',
        includeDetails: true
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
      id: 'legal-002',
      name: 'Assess Regulatory Notification Requirements',
      description: 'Оценка требований регуляторного уведомления',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'regulatory_assessment',
        checkGDPR: true,
        checkCCPA: true,
        checkHIPAA: true,
        checkPCI_DSS: true,
        checkLocalLaws: true
      },
      conditions: [],
      dependencies: ['detect-002', 'detect-003'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'legal-003',
      name: 'Prepare Regulatory Notifications',
      description: 'Подготовка регуляторных уведомлений',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'regulatory_notification',
        templates: ['gdpr_notification', 'state_ag_notification'],
        includeTimeline: true,
        includeAffectedCount: true,
        includeRemediation: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'legal-002.requiresNotification',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['legal-002'],
      timeout: 900000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'legal-004',
      name: 'Notify Affected Individuals',
      description: 'Уведомление затронутых лиц',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'email',
        recipients: 'affected_individuals',
        templateId: 'data-breach-notice-individuals',
        priority: 'high',
        includeCreditMonitoring: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'legal-002.requiresIndividualNotification',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['legal-003'],
      timeout: 1800000,
      retryCount: 2,
      retryInterval: 30000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 6: COMMUNICATION & DOCUMENTATION
    // ========================================================================

    {
      id: 'comm-001',
      name: 'Notify Executive Management',
      description: 'Уведомление руководства',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'email',
        recipients: ['executive-team'],
        templateId: 'data-breach-executive-brief',
        priority: 'critical'
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
      id: 'comm-002',
      name: 'Create Incident Ticket',
      description: 'Создание тикета инцидента',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.CREATE_TICKET,
      parameters: {
        system: 'servicenow',
        templateId: 'data-breach-incident',
        assignTo: 'security-operations',
        priority: 'critical'
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
      id: 'comm-003',
      name: 'Prepare PR Statement',
      description: 'Подготовка PR заявления',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'pr_statement',
        tone: 'transparent_and_responsible',
        includeFAQ: true,
        includeContactInfo: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'incident.isPublic',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['legal-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'doc-001',
      name: 'Document Breach Details',
      description: 'Документирование деталей утечки',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'breach_report',
        includeTimeline: true,
        includeIOCs: true,
        includeAffectedData: true,
        includeRemediation: true
      },
      conditions: [],
      dependencies: ['recover-003'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'doc-002',
      name: 'Preserve Evidence for Legal',
      description: 'Сохранение улик для юридических целей',
      category: PlaybookStepCategory.FORENSICS,
      actionType: PlaybookActionType.COLLECT_DATA,
      parameters: {
        dataType: 'legal_evidence',
        createForensicImages: true,
        preserveLogs: true,
        maintainChainOfCustody: true,
        encryptEvidence: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 1800000,
      retryCount: 1,
      retryInterval: 30000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: false
    }
  ];

  return {
    id: 'data-breach-v1.0',
    name: 'Data Breach Response',
    description: 'Комплексный playbook для реагирования на утечки данных. Включает обнаружение, сдерживание, устранение, восстановление, юридические и регуляторные аспекты.',
    version: '1.0.0',
    incidentCategory: IncidentCategory.DATA_BREACH,
    minSeverity: IncidentSeverity.MEDIUM,
    steps,
    variables: {
      legalHoldEnabled: true,
      preserveEvidenceDays: 2555, // 7 лет
      notifyRegulators: true,
      offerCreditMonitoring: true,
      creditMonitoringProvider: 'Experian',
      breachHotlinedEnabled: true
    },
    integrations: ['dlp', 'siem', 'database', 'servicenow', 'slack', 'email'],
    tags: ['data-breach', 'pii', 'phi', 'gdpr', 'compliance', 'exfiltration'],
    author: 'Security Operations Team',
    lastUpdated: new Date(),
    status: 'active'
  };
}

/**
 * Экспорт конфигурации playbook
 */
export const dataBreachPlaybook = createDataBreachPlaybook();
