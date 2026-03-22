/**
 * ============================================================================
 * RANSOMWARE ATTACK PLAYBOOK
 * ============================================================================
 * Playbook для реагирования на ransomware атаки
 * Соответствует NIST SP 800-61, CISA Ransomware Guide, и FBI guidelines
 * ============================================================================
 */

import {
  PlaybookConfiguration,
  PlaybookStep,
  PlaybookStepCategory,
  PlaybookActionType,
  IncidentCategory,
  IncidentSeverity,
  ConditionType,
  ConditionOperator
} from '../../types/incident.types';

/**
 * Создание конфигурации playbook для ransomware атаки
 */
export function createRansomwareAttackPlaybook(): PlaybookConfiguration {
  const steps: PlaybookStep[] = [
    // ========================================================================
    // ФАЗА 1: DETECTION & INITIAL RESPONSE
    // ========================================================================

    {
      id: 'detect-001',
      name: 'Verify Ransomware Attack',
      description: 'Верификация ransomware атаки',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'ransomware_verification',
        checkEncryptedFiles: true,
        checkRansomNotes: true,
        checkFileExtensions: true,
        checkShadowCopies: true,
        identifyRansomwareFamily: true
      },
      conditions: [],
      dependencies: [],
      timeout: 180000,
      retryCount: 1,
      retryInterval: 5000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-002',
      name: 'Identify Patient Zero',
      description: 'Идентификация пациента零 (начальной точки заражения)',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'patient_zero_identification',
        analyzeInfectionTimeline: true,
        identifyFirstEncryptedFile: true,
        traceInfectionVector: true,
        identifyInitialAccessMethod: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'detect-003',
      name: 'Assess Encryption Scope',
      description: 'Оценка масштаба шифрования',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.COLLECT_DATA,
      parameters: {
        dataType: 'encryption_scope',
        countEncryptedFiles: true,
        identifyAffectedSystems: true,
        identifyAffectedShares: true,
        estimateDataVolume: true,
        assessBackupStatus: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'detect-004',
      name: 'Check for Data Exfiltration',
      description: 'Проверка экфильтрации данных',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'exfiltration_check',
        checkNetworkTraffic: true,
        checkLargeTransfers: true,
        checkCloudUploads: true,
        checkEmailAttachments: true,
        identifyExfiltratedData: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    // ========================================================================
    // ФАЗА 2: IMMEDIATE CONTAINMENT
    // ========================================================================

    {
      id: 'contain-001',
      name: 'Isolate Infected Systems',
      description: 'Изоляция зараженных систем',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.ISOLATE_HOST,
      parameters: {
        isolationMethod: 'immediate_network_disconnect',
        isolateAllInfected: true,
        isolatePotentiallyInfected: true,
        preservePowerState: true,
        maintainForensicsAccess: false
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 120000,
      retryCount: 3,
      retryInterval: 1000,
      status: 'pending',
      automatic: false,
      requiresApproval: true,
      rollbackAction: {
        id: 'contain-001-rollback',
        name: 'Reconnect Systems',
        description: 'Подключение систем обратно к сети',
        category: PlaybookStepCategory.RECOVERY,
        actionType: PlaybookActionType.RUN_SCRIPT,
        parameters: {
          scriptType: 'reconnect_network'
        },
        status: 'pending'
      }
    },

    {
      id: 'contain-002',
      name: 'Disconnect Backup Systems',
      description: 'Отключение систем резервного копирования',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'disconnect_backups',
        disconnectNetworkBackups: true,
        disconnectCloudBackups: true,
        disconnectTapeLibraries: true,
        protectBackupCredentials: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 2000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-003',
      name: 'Block Ransomware IOCs',
      description: 'Блокировка IOC ransomware',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.BLOCK_IP,
      parameters: {
        blockType: 'ransomware_iocs',
        blockC2Servers: true,
        blockRansomDomains: true,
        blockMaliciousIPs: true,
        updateFirewall: true,
        updateDNS: true,
        updateProxy: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 3000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'contain-004',
      name: 'Disable Shared Folders',
      description: 'Отключение общих папок',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'disable_shares',
        disableNetworkShares: true,
        disableCloudStorage: true,
        disableSyncServices: true,
        preventLateralSpread: true
      },
      conditions: [],
      dependencies: ['detect-003'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 3000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-005',
      name: 'Revoke Compromised Credentials',
      description: 'Отзыв скомпрометированных учетных данных',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.REVOKE_TOKENS,
      parameters: {
        revokeType: 'all_enterprise',
        resetAdminPasswords: true,
        resetServiceAccounts: true,
        revokeAllTokens: true,
        forceReauthentication: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 300000,
      retryCount: 2,
      retryInterval: 5000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 3: ERADICATION
    // ========================================================================

    {
      id: 'eradicate-001',
      name: 'Identify Ransomware Variant',
      description: 'Идентификация варианта ransomware',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'ransomware_identification',
        analyzeRansomNote: true,
        analyzeFileExtensions: true,
        submitSamplesToVT: true,
        checkNoMore_ransom: true,
        identifyDecryptionAvailable: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'eradicate-002',
      name: 'Remove Ransomware Artifacts',
      description: 'Удаление артефактов ransomware',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.REMOVE_MALWARE,
      parameters: {
        removalMethod: 'comprehensive_cleanup',
        removeMalwareExecutables: true,
        removeRansomNotes: true,
        removePersistenceMechanisms: true,
        removeScheduledTasks: true,
        removeRegistryKeys: true
      },
      conditions: [],
      dependencies: ['contain-001'],
      timeout: 900000,
      retryCount: 1,
      retryInterval: 30000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'eradicate-003',
      name: 'Patch Exploited Vulnerabilities',
      description: 'Устранение эксплуатированных уязвимостей',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'emergency_patches',
        patchExploitedVulns: true,
        patchAllCritical: true,
        patchHighSeverity: true,
        updateFirmware: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 1800000,
      retryCount: 1,
      retryInterval: 60000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'eradicate-004',
      name: 'Check for Decryption Tools',
      description: 'Проверка инструментов дешифрования',
      category: PlaybookStepCategory.ERADICATION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'decryptor_check',
        checkNoMore_ransom: true,
        checkEmsiSoft: true,
        checkKaspersky: true,
        checkVendorTools: true,
        testDecryptor: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'eradicate-001.ransomwareFamily',
          operator: ConditionOperator.EXISTS,
          value: true
        }
      ],
      dependencies: ['eradicate-001'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    // ========================================================================
    // ФАЗА 4: RECOVERY
    // ========================================================================

    {
      id: 'recover-001',
      name: 'Assess Backup Integrity',
      description: 'Оценка целостности резервных копий',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'backup_assessment',
        verifyBackupAvailability: true,
        verifyBackupIntegrity: true,
        checkForEncryption: true,
        identifyCleanBackups: true,
        estimateRecoveryTime: true
      },
      conditions: [],
      dependencies: ['contain-002'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 30000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'recover-002',
      name: 'Restore from Backup',
      description: 'Восстановление из резервной копии',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RESTORE_FROM_BACKUP,
      parameters: {
        backupType: 'last_known_clean',
        restoreMethod: 'full_system',
        verifyBeforeRestore: true,
        scanRestoredData: true,
        restoreInIsolation: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'recover-001.backupsAvailable',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['recover-001', 'eradicate-002'],
      timeout: 7200000,
      retryCount: 1,
      retryInterval: 300000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-003',
      name: 'Attempt File Decryption',
      description: 'Попытка дешифрования файлов',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'decrypt_files',
        useDecryptor: 'auto_detected',
        decryptInPlace: false,
        createBackups: true,
        verifyDecryption: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'eradicate-004.decryptorAvailable',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['eradicate-004'],
      timeout: 3600000,
      retryCount: 1,
      retryInterval: 300000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-004',
      name: 'Rebuild Systems',
      description: 'Перестройка систем',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'rebuild_systems',
        rebuildFromGoldImage: true,
        applyAllPatches: true,
        hardening: true,
        verifyBeforeProduction: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'recover-001.backupsAvailable',
          operator: ConditionOperator.EQUALS,
          value: false
        }
      ],
      dependencies: ['eradicate-002', 'eradicate-003'],
      timeout: 14400000,
      retryCount: 1,
      retryInterval: 600000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-005',
      name: 'Restore Data from Decrypted Files',
      description: 'Восстановление данных из дешифрованных файлов',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'restore_decrypted',
        verifyDataIntegrity: true,
        prioritizeCriticalData: true,
        validateApplications: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'recover-003.decryptionSuccessful',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['recover-003'],
      timeout: 3600000,
      retryCount: 1,
      retryInterval: 300000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-006',
      name: 'Gradual System Reconnection',
      description: 'Постепенное подключение систем',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'gradual_reconnection',
        reconnectInPhases: true,
        phasePercentage: 25,
        monitorForEachPhase: true,
        rollbackOnReinfection: true
      },
      conditions: [],
      dependencies: ['recover-002', 'recover-005'],
      timeout: 1800000,
      retryCount: 1,
      retryInterval: 300000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 5: RANSOM DECISION (IF APPLICABLE)
    // ========================================================================

    {
      id: 'ransom-001',
      name: 'Document Ransom Demand',
      description: 'Документирование требования выкупа',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'ransom_demand',
        captureRansomNote: true,
        documentDemandAmount: true,
        documentPaymentMethod: true,
        documentDeadline: true,
        preserveEvidence: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 180000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'ransom-002',
      name: 'Notify Law Enforcement',
      description: 'Уведомление правоохранительных органов',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'phone',
        recipients: ['fbi_ic3', 'local_le', 'secret_service'],
        templateId: 'ransomware-le-notice',
        priority: 'critical',
        includeAllDetails: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 300000,
      retryCount: 3,
      retryInterval: 30000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'ransom-003',
      name: 'Engage Ransomware Negotiation Team',
      description: 'Привлечение команды переговоров',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'negotiation_engagement',
        contactNegotiationFirm: true,
        briefExecutiveTeam: true,
        establishCommunicationChannel: true,
        documentStrategy: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'incident.consideringPayment',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['ransom-002'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 60000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'ransom-004',
      name: 'Executive Decision on Ransom',
      description: 'Решение руководства о выкупе',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'ransom_decision',
        documentDecision: true,
        documentRationale: true,
        includeLegalAdvice: true,
        includeLEGuidance: true
      },
      conditions: [],
      dependencies: ['ransom-003', 'recover-001'],
      timeout: 3600000,
      retryCount: 1,
      retryInterval: 300000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 6: COMMUNICATION & DOCUMENTATION
    // ========================================================================

    {
      id: 'comm-001',
      name: 'Activate Incident Response Team',
      description: 'Активация команды реагирования',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'pagerduty',
        recipients: ['incident-response-team'],
        templateId: 'ransomware-critical-alert',
        priority: 'critical'
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 60000,
      retryCount: 5,
      retryInterval: 1000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'comm-002',
      name: 'Notify Executive Management',
      description: 'Уведомление руководства',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'phone',
        recipients: ['c_suite', 'board'],
        templateId: 'ransomware-executive-brief',
        priority: 'critical',
        includeBusinessImpact: true
      },
      conditions: [],
      dependencies: ['detect-003'],
      timeout: 120000,
      retryCount: 5,
      retryInterval: 2000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'comm-003',
      name: 'Notify Legal and Insurance',
      description: 'Уведомление юридических и страховых',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'email',
        recipients: ['legal-team', 'cyber_insurance'],
        templateId: 'ransomware-legal-insurance',
        priority: 'critical',
        includePolicyNumbers: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 180000,
      retryCount: 3,
      retryInterval: 5000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'comm-004',
      name: 'Create Incident Ticket',
      description: 'Создание тикета инцидента',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.CREATE_TICKET,
      parameters: {
        system: 'servicenow',
        templateId: 'ransomware-critical-incident',
        assignTo: 'executive-security',
        priority: 'critical'
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 5000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'comm-005',
      name: 'Prepare External Communications',
      description: 'Подготовка внешних коммуникаций',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'external_communications',
        preparePRStatement: true,
        prepareCustomerNotice: true,
        preparePartnerNotice: true,
        coordinateWithLegal: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'incident.isPublic',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['detect-003'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 30000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'doc-001',
      name: 'Document Full Incident Timeline',
      description: 'Документирование полной временной шкалы',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'incident_timeline',
        includeAllEvents: true,
        includeAllActions: true,
        includeDecisionPoints: true,
        includeTimestamps: true
      },
      conditions: [],
      dependencies: ['recover-006'],
      timeout: 900000,
      retryCount: 1,
      retryInterval: 30000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'doc-002',
      name: 'Preserve All Evidence',
      description: 'Сохранение всех улик',
      category: PlaybookStepCategory.FORENSICS,
      actionType: PlaybookActionType.COLLECT_DATA,
      parameters: {
        dataType: 'ransomware_evidence',
        imageInfectedSystems: true,
        collectMemoryDumps: true,
        collectNetworkCaptures: true,
        collectRansomNotes: true,
        collectMalwareSamples: true,
        maintainChainOfCustody: true
      },
      conditions: [],
      dependencies: ['contain-001'],
      timeout: 3600000,
      retryCount: 1,
      retryInterval: 300000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'doc-003',
      name: 'Generate Post-Incident Report',
      description: 'Генерация пост-инцидентного отчета',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'post_incident_report',
        includeExecutiveSummary: true,
        includeTechnicalDetails: true,
        includeLessonsLearned: true,
        includeRecommendations: true,
        includeCostAnalysis: true
      },
      conditions: [],
      dependencies: ['recover-006'],
      timeout: 1800000,
      retryCount: 1,
      retryInterval: 60000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    }
  ];

  return {
    id: 'ransomware-attack-v1.0',
    name: 'Ransomware Attack Response',
    description: 'Комплексный playbook для реагирования на ransomware атаки. Включает обнаружение, сдерживание, устранение, восстановление и управление решением о выкупе.',
    version: '1.0.0',
    incidentCategory: IncidentCategory.RANSOMWARE_ATTACK,
    minSeverity: IncidentSeverity.HIGH,
    steps,
    variables: {
      considerRansomPayment: false,
      lawEnforcementNotified: true,
      cyberInsuranceActive: true,
      negotiationTeamEngaged: false,
      backupVerificationRequired: true,
      evidenceRetentionDays: 2555,
      executiveEscalationRequired: true
    },
    integrations: ['edr', 'backup', 'firewall', 'active_directory', 'pagerduty', 'servicenow', 'slack'],
    tags: ['ransomware', 'encryption', 'extortion', 'critical', 'business-continuity'],
    author: 'Security Operations Team',
    lastUpdated: new Date(),
    status: 'active'
  };
}

/**
 * Экспорт конфигурации playbook
 */
export const ransomwareAttackPlaybook = createRansomwareAttackPlaybook();
