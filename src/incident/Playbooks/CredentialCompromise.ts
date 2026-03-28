/**
 * ============================================================================
 * CREDENTIAL COMPROMISE PLAYBOOK
 * ============================================================================
 * Playbook для реагирования на компрометацию учетных данных
 * Соответствует NIST SP 800-61 и лучшим практикам identity security
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
 * Создание конфигурации playbook для компрометации учетных данных
 */
export function createCredentialCompromisePlaybook(): PlaybookConfiguration {
  const steps: PlaybookStep[] = [
    // ========================================================================
    // ФАЗА 1: DETECTION & VERIFICATION
    // ========================================================================

    {
      id: 'detect-001',
      name: 'Verify Credential Compromise',
      description: 'Верификация компрометации учетных данных',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'credential_verification',
        checkBreachDatabases: true,
        checkDarkWeb: true,
        checkPhishingReports: true,
        checkBruteForceAttempts: true,
        verifyActiveExploitation: true
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
      name: 'Identify Compromised Credentials',
      description: 'Идентификация скомпрометированных учетных данных',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'credential_identification',
        identifyAffectedAccounts: true,
        identifyCredentialType: true,
        identifyExposureSource: true,
        estimateExposureTime: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-003',
      name: 'Assess Account Privileges',
      description: 'Оценка привилегий учетной записи',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'privilege_assessment',
        checkAdminRights: true,
        checkDataAccess: true,
        checkSystemAccess: true,
        checkAPIAccess: true,
        identifyCriticalResources: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 180000,
      retryCount: 1,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-004',
      name: 'Check for Unauthorized Access',
      description: 'Проверка несанкционированного доступа',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'unauthorized_access_check',
        checkRecentLogins: true,
        checkSessionActivity: true,
        checkResourceAccess: true,
        checkDataAccess: true,
        checkConfigurationChanges: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    // ========================================================================
    // ФАЗА 2: IMMEDIATE CONTAINMENT
    // ========================================================================

    {
      id: 'contain-001',
      name: 'Force Password Reset',
      description: 'Принудительный сброс пароля',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RESET_PASSWORD,
      parameters: {
        resetType: 'forced',
        resetAffectedAccounts: true,
        resetRelatedAccounts: false,
        generateStrongPassword: true,
        requireChangeOnLogin: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 120000,
      retryCount: 3,
      retryInterval: 2000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true,
      rollbackAction: {
        id: 'contain-001-rollback',
        name: 'Restore Previous Password',
        description: 'Восстановление предыдущего пароля (если возможно)',
        category: PlaybookStepCategory.RECOVERY,
        actionType: PlaybookActionType.RESET_PASSWORD,
        parameters: {
          resetType: 'restore'
        },
        status: PlaybookStepStatus.PENDING
      }
    },

    {
      id: 'contain-002',
      name: 'Revoke All Active Sessions',
      description: 'Отзыв всех активных сессий',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.REVOKE_TOKENS,
      parameters: {
        revokeType: 'all_sessions',
        revokeWebSessions: true,
        revokeMobileSessions: true,
        revokeAPISessions: true,
        revokeSSOSessions: true,
        revokeVPNSessions: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 120000,
      retryCount: 3,
      retryInterval: 2000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-003',
      name: 'Invalidate API Keys and Tokens',
      description: 'Отзыв API ключей и токенов',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.REVOKE_TOKENS,
      parameters: {
        revokeType: 'api_credentials',
        revokeAPIKeys: true,
        revokeAccessTokens: true,
        revokeRefreshTokens: true,
        revokeServiceAccounts: true,
        rotateServiceCredentials: true
      },
      conditions: [],
      dependencies: ['detect-003'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 3000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-004',
      name: 'Lock Account',
      description: 'Блокировка учетной записи',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.LOCK_ACCOUNT,
      parameters: {
        lockType: 'security_lockout',
        lockDuration: 'until_verified',
        notifyUser: true,
        preserveEvidence: true,
        allowAdminOverride: true
      },
      conditions: [
        {
          type: ConditionType.SEVERITY_LEVEL,
          field: 'incident.severity',
          operator: ConditionOperator.IN,
          value: ['critical', 'high']
        },
        {
          type: ConditionType.FIELD_VALUE,
          field: 'detect-004.unauthorizedAccessDetected',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['detect-004'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 3000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-005',
      name: 'Block Suspicious IP Addresses',
      description: 'Блокировка подозрительных IP адресов',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.BLOCK_IP,
      parameters: {
        blockType: 'suspicious_sources',
        blockLoginSourceIPs: true,
        blockRelatedIPs: true,
        updateFirewall: true,
        updateWAF: true,
        blockDuration: 'permanent'
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

    // ========================================================================
    // ФАЗА 3: ERADICATION
    // ========================================================================

    {
      id: 'eradicate-001',
      name: 'Remove Unauthorized Access Methods',
      description: 'Удаление методов несанкционированного доступа',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'remove_unauthorized_access',
        removeBackdoors: true,
        removeForwardingRules: true,
        removeDelegatedAccess: true,
        removeTrustedIPs: true,
        removeMFADevices: true
      },
      conditions: [],
      dependencies: ['contain-001', 'contain-002'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'eradicate-002',
      name: 'Enable Multi-Factor Authentication',
      description: 'Включение многофакторной аутентификации',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'mfa_enforcement',
        enableMFA: true,
        mfaMethod: 'authenticator_app',
        requireForAllLogins: true,
        disableSMSMFA: true,
        enableHardwareKey: true
      },
      conditions: [],
      dependencies: ['contain-001'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'eradicate-003',
      name: 'Review and Revoke Permissions',
      description: 'Проверка и отзыв разрешений',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'review_permissions',
        auditPermissions: true,
        revokeUnnecessaryPermissions: true,
        applyLeastPrivilege: true,
        documentChanges: true
      },
      conditions: [],
      dependencies: ['detect-003'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 30000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'eradicate-004',
      name: 'Update Authentication Policies',
      description: 'Обновление политик аутентификации',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'auth_policies',
        strengthenPasswordPolicy: true,
        enableAccountLockout: true,
        enableLoginNotifications: true,
        enableImpossibleTravel: true,
        enableRiskBasedAuth: true
      },
      conditions: [],
      dependencies: ['eradicate-002'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 4: RECOVERY
    // ========================================================================

    {
      id: 'recover-001',
      name: 'Verify Account Security',
      description: 'Проверка безопасности учетной записи',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'security_verification',
        verifyPasswordChanged: true,
        verifyMFAEnabled: true,
        verifySessionsRevoked: true,
        verifyNoBackdoors: true,
        verifyPermissionsCorrect: true
      },
      conditions: [],
      dependencies: ['eradicate-001', 'eradicate-002'],
      timeout: 180000,
      retryCount: 1,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'recover-002',
      name: 'Unlock Account',
      description: 'Разблокировка учетной записи',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'unlock_account',
        verifyIdentity: true,
        verifySecurityControls: true,
        notifyUser: true,
        provideSecurityGuidance: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'contain-004.accountLocked',
          operator: ConditionOperator.EQUALS,
          value: true
        },
        {
          type: ConditionType.FIELD_VALUE,
          field: 'recover-001.securityVerified',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['recover-001'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 3000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-003',
      name: 'Restore User Access',
      description: 'Восстановление доступа пользователя',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'restore_access',
        restoreNormalPermissions: true,
        restoreApplicationAccess: true,
        verifySSO: true,
        testLogin: true
      },
      conditions: [],
      dependencies: ['recover-002'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-004',
      name: 'Monitor for Suspicious Activity',
      description: 'Мониторинг подозрительной активности',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'enhanced_monitoring',
        monitoringPeriod: '30_days',
        alertOnAnyLogin: true,
        alertOnPrivilegeUse: true,
        alertOnDataAccess: true,
        dailyReports: true
      },
      conditions: [],
      dependencies: ['recover-003'],
      timeout: 60000,
      retryCount: 1,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    // ========================================================================
    // ФАЗА 5: USER NOTIFICATION & EDUCATION
    // ========================================================================

    {
      id: 'notify-001',
      name: 'Notify Affected User',
      description: 'Уведомление затронутого пользователя',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'email',
        recipients: 'affected_user',
        templateId: 'credential-compromise-user-notice',
        priority: 'high',
        includeInstructions: true,
        includeSecurityTips: true
      },
      conditions: [],
      dependencies: ['contain-001'],
      timeout: 120000,
      retryCount: 3,
      retryInterval: 5000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'notify-002',
      name: 'Provide Security Awareness Training',
      description: 'Предоставление обучения по безопасности',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'security_training',
        trainingType: 'credential_security',
        includePhishingAwareness: true,
        includePasswordBestPractices: true,
        includeMFAImportance: true,
        requireAcknowledgment: true
      },
      conditions: [],
      dependencies: ['recover-003'],
      timeout: 600000,
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
        templateId: 'credential-compromise-alert',
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
      name: 'Notify IT Operations',
      description: 'Уведомление IT операционной команды',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'slack',
        recipients: ['it-ops'],
        templateId: 'credential-compromise-ops-alert',
        priority: 'medium'
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
      id: 'comm-003',
      name: 'Create Incident Ticket',
      description: 'Создание тикета инцидента',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.CREATE_TICKET,
      parameters: {
        system: 'servicenow',
        templateId: 'credential-compromise-incident',
        assignTo: 'identity-security',
        priority: 'high'
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
      name: 'Document Compromise Details',
      description: 'Документирование деталей компрометации',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'compromise_report',
        includeTimeline: true,
        includeAffectedAccounts: true,
        includeIOCs: true,
        includeRemediationActions: true
      },
      conditions: [],
      dependencies: ['eradicate-001'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'doc-002',
      name: 'Update Breach Database',
      description: 'Обновление базы данных нарушений',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'breach_database_update',
        reportToHaveIBeenPwned: true,
        reportToInternalDB: true,
        shareWithThreatIntel: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 180000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'doc-003',
      name: 'Generate Compliance Report',
      description: 'Генерация отчета соответствия',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'compliance_report',
        checkSOX: true,
        checkPCI_DSS: true,
        checkHIPAA: true,
        checkGDPR: true,
        includeAuditTrail: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'detect-003.hasPrivilegedAccess',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['eradicate-003'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: PlaybookStepStatus.PENDING,
      automatic: true,
      requiresApproval: false
    }
  ];

  return {
    id: 'credential-compromise-v1.0',
    name: 'Credential Compromise Response',
    description: 'Комплексный playbook для реагирования на компрометацию учетных данных. Включает обнаружение, сдерживание, устранение и восстановление.',
    version: '1.0.0',
    incidentCategory: IncidentCategory.CREDENTIAL_COMPROMISE,
    minSeverity: IncidentSeverity.LOW,
    steps,
    variables: {
      forcePasswordComplexity: true,
      minimumPasswordLength: 16,
      requireMFA: true,
      sessionTimeoutMinutes: 60,
      monitoringPeriodDays: 30,
      notifyOnPasswordReuse: true
    },
    integrations: ['active_directory', 'identity_provider', 'mfa_service', 'siem', 'slack', 'servicenow'],
    tags: ['credential', 'password', 'mfa', 'authentication', 'identity', 'account-takeover'],
    author: 'Security Operations Team',
    lastUpdated: new Date(),
    status: 'active'
  };
}

/**
 * Экспорт конфигурации playbook
 */
export const credentialCompromisePlaybook = createCredentialCompromisePlaybook();
