/**
 * ============================================================================
 * DDoS ATTACK PLAYBOOK
 * ============================================================================
 * Playbook для реагирования на DDoS атаки
 * Соответствует NIST SP 800-61 и лучшим практикам mitigation
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
 * Создание конфигурации playbook для DDoS атаки
 */
export function createDDoSAttackPlaybook(): PlaybookConfiguration {
  const steps: PlaybookStep[] = [
    // ========================================================================
    // ФАЗА 1: DETECTION & VERIFICATION
    // ========================================================================

    {
      id: 'detect-001',
      name: 'Verify DDoS Attack',
      description: 'Верификация DDoS атаки',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'ddos_verification',
        checkTrafficPatterns: true,
        checkBandwidthUtilization: true,
        checkRequestRates: true,
        distinguishFromFlashCrowd: true
      },
      conditions: [],
      dependencies: [],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 3000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-002',
      name: 'Identify Attack Type',
      description: 'Идентификация типа атаки',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'attack_classification',
        detectVolumetric: true,
        detectProtocol: true,
        detectApplication: true,
        detectAmplification: true,
        identifyVector: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 5000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-003',
      name: 'Identify Attack Sources',
      description: 'Идентификация источников атаки',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.COLLECT_DATA,
      parameters: {
        dataType: 'attack_sources',
        collectSourceIPs: true,
        collectBotnetSignatures: true,
        geoLocateSources: true,
        identifyBotnets: true
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 5000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'detect-004',
      name: 'Assess Impact on Services',
      description: 'Оценка воздействия на сервисы',
      category: PlaybookStepCategory.DETECTION,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'impact_assessment',
        checkServiceAvailability: true,
        measureResponseTimes: true,
        identifyAffectedServices: true,
        estimateUserImpact: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 180000,
      retryCount: 1,
      retryInterval: 5000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    // ========================================================================
    // ФАЗА 2: IMMEDIATE CONTAINMENT
    // ========================================================================

    {
      id: 'contain-001',
      name: 'Activate DDoS Mitigation Service',
      description: 'Активация сервиса mitigation DDoS',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'activate_ddos_protection',
        provider: 'auto',
        enableScrubbing: true,
        enableRateLimiting: true,
        enableGeoBlocking: false
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 120000,
      retryCount: 3,
      retryInterval: 2000,
      status: 'pending',
      automatic: false,
      requiresApproval: true,
      rollbackAction: {
        id: 'contain-001-rollback',
        name: 'Deactivate DDoS Mitigation',
        description: 'Деактивация mitigation DDoS',
        category: PlaybookStepCategory.RECOVERY,
        actionType: PlaybookActionType.RUN_SCRIPT,
        parameters: {
          scriptType: 'deactivate_ddos_protection'
        },
        status: 'pending'
      }
    },

    {
      id: 'contain-002',
      name: 'Implement Rate Limiting',
      description: 'Внедрение ограничения скорости запросов',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'rate_limits',
        applyGlobal: true,
        applyPerIP: true,
        applyPerEndpoint: true,
        thresholds: 'aggressive'
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 3000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-003',
      name: 'Block Attack Source IPs',
      description: 'Блокировка IP адресов источников атаки',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.BLOCK_IP,
      parameters: {
        blockType: 'attack_sources',
        blockIndividualIPs: true,
        blockSubnets: true,
        blockCountries: false,
        updateFirewall: true,
        updateWAF: true
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
      id: 'contain-004',
      name: 'Enable Traffic Scrubbing',
      description: 'Включение очистки трафика',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'enable_scrubbing',
        scrubbingCenter: 'nearest',
        bypassForLegitimate: true,
        enableLearningMode: false
      },
      conditions: [
        {
          type: ConditionType.SEVERITY_LEVEL,
          field: 'incident.severity',
          operator: ConditionOperator.IN,
          value: ['critical', 'high']
        }
      ],
      dependencies: ['contain-001'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 5000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-005',
      name: 'Implement Geographic Blocking',
      description: 'Географическая блокировка трафика',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'geo_blocking',
        blockCountries: 'attack_sources',
        allowList: ['US', 'CA', 'EU'],
        challengeMode: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'detect-003.geoConcentrated',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['detect-003'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 3000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'contain-006',
      name: 'Scale Infrastructure',
      description: 'Масштабирование инфраструктуры',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'scale_infrastructure',
        scaleType: 'horizontal',
        enableAutoScaling: true,
        addCapacity: '50_percent',
        enableCDN: true
      },
      conditions: [],
      dependencies: ['detect-004'],
      timeout: 300000,
      retryCount: 2,
      retryInterval: 10000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 3: ADVANCED MITIGATION
    // ========================================================================

    {
      id: 'mitigate-001',
      name: 'Deploy WAF Rules',
      description: 'Развертывание правил WAF',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'waf_rules',
        enableDDoSRules: true,
        enableBotProtection: true,
        enableAPIProtection: true,
        customRules: 'ddos_specific'
      },
      conditions: [],
      dependencies: ['detect-002'],
      timeout: 180000,
      retryCount: 2,
      retryInterval: 5000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'mitigate-002',
      name: 'Implement Challenge-Response',
      description: 'Внедрение challenge-response проверки',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'challenge_response',
        enableCAPTCHA: true,
        enableJavaScriptChallenge: true,
        enableFingerprinting: true,
        threshold: 'aggressive'
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'detect-002.attackType',
          operator: ConditionOperator.EQUALS,
          value: 'application_layer'
        }
      ],
      dependencies: ['detect-002'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 3000,
      status: 'pending',
      automatic: false,
      requiresApproval: false
    },

    {
      id: 'mitigate-003',
      name: 'Blackhole Routing',
      description: 'Маршрутизация в черную дыру',
      category: PlaybookStepCategory.CONTAINMENT,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'blackhole_routing',
        targetIPs: 'attack_targets',
        duration: 'auto',
        notifyISP: true
      },
      conditions: [
        {
          type: ConditionType.SEVERITY_LEVEL,
          field: 'incident.severity',
          operator: ConditionOperator.EQUALS,
          value: 'critical'
        },
        {
          type: ConditionType.FIELD_VALUE,
          field: 'contain-001.effectiveness',
          operator: ConditionOperator.LESS_THAN,
          value: 50
        }
      ],
      dependencies: ['contain-001'],
      timeout: 60000,
      retryCount: 1,
      retryInterval: 2000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'mitigate-004',
      name: 'Contact Upstream Providers',
      description: 'Связь с провайдерами',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'phone',
        recipients: ['isp_noc', 'hosting_provider', 'cdn_provider'],
        templateId: 'ddos-upstream-assistance',
        priority: 'critical',
        requestMitigation: true
      },
      conditions: [
        {
          type: ConditionType.SEVERITY_LEVEL,
          field: 'incident.severity',
          operator: ConditionOperator.EQUALS,
          value: 'critical'
        }
      ],
      dependencies: ['detect-001'],
      timeout: 300000,
      retryCount: 3,
      retryInterval: 30000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 4: RECOVERY
    // ========================================================================

    {
      id: 'recover-001',
      name: 'Verify Attack Mitigation',
      description: 'Проверка устранения атаки',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.ANALYZE_DATA,
      parameters: {
        analysisType: 'mitigation_verification',
        checkTrafficLevels: true,
        checkServiceHealth: true,
        verifyAttackStopped: true,
        monitorForResurgence: true
      },
      conditions: [],
      dependencies: ['contain-001', 'mitigate-001'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'recover-002',
      name: 'Gradually Restore Normal Traffic',
      description: 'Постепенное восстановление нормального трафика',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'restore_traffic',
        gradualRelease: true,
        releasePercentage: 25,
        monitorImpact: true,
        rollbackOnRegression: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'recover-001.attackMitigated',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['recover-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 30000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-003',
      name: 'Disable Emergency Rules',
      description: 'Отключение аварийных правил',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.UPDATE_RULES,
      parameters: {
        updateType: 'disable_emergency',
        disableRateLimits: false,
        disableGeoBlocking: true,
        disableChallenges: true,
        maintainWAFRules: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'recover-002.trafficNormal',
          operator: ConditionOperator.EQUALS,
          value: true
        }
      ],
      dependencies: ['recover-002'],
      timeout: 120000,
      retryCount: 2,
      retryInterval: 5000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    {
      id: 'recover-004',
      name: 'Full Service Restoration',
      description: 'Полное восстановление сервиса',
      category: PlaybookStepCategory.RECOVERY,
      actionType: PlaybookActionType.RUN_SCRIPT,
      parameters: {
        scriptType: 'full_restoration',
        verifyAllServices: true,
        performanceTesting: true,
        userExperienceCheck: true
      },
      conditions: [],
      dependencies: ['recover-003'],
      timeout: 300000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: false,
      requiresApproval: true
    },

    // ========================================================================
    // ФАЗА 5: COMMUNICATION & DOCUMENTATION
    // ========================================================================

    {
      id: 'comm-001',
      name: 'Notify Security Team',
      description: 'Уведомление команды безопасности',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'pagerduty',
        recipients: ['security-oncall'],
        templateId: 'ddos-attack-alert',
        priority: 'critical'
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 60000,
      retryCount: 3,
      retryInterval: 2000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'comm-002',
      name: 'Notify Operations Team',
      description: 'Уведомление операционной команды',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'slack',
        recipients: ['ops-team'],
        templateId: 'ddos-ops-alert',
        priority: 'high'
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 60000,
      retryCount: 3,
      retryInterval: 2000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'comm-003',
      name: 'Update Status Page',
      description: 'Обновление страницы статуса',
      category: PlaybookStepCategory.COMMUNICATION,
      actionType: PlaybookActionType.SEND_NOTIFICATION,
      parameters: {
        channel: 'webhook',
        recipients: ['status_page'],
        templateId: 'status-page-degraded',
        priority: 'high',
        publicUpdate: true
      },
      conditions: [
        {
          type: ConditionType.FIELD_VALUE,
          field: 'detect-004.userImpact',
          operator: ConditionOperator.GREATER_THAN,
          value: 10
        }
      ],
      dependencies: ['detect-004'],
      timeout: 60000,
      retryCount: 2,
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
        templateId: 'ddos-incident',
        assignTo: 'security-operations',
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
      id: 'doc-001',
      name: 'Document Attack Characteristics',
      description: 'Документирование характеристик атаки',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'ddos_attack_report',
        includeTrafficGraphs: true,
        includeAttackVectors: true,
        includeSourceAnalysis: true,
        includeMitigationEffectiveness: true
      },
      conditions: [],
      dependencies: ['recover-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'doc-002',
      name: 'Collect Attack Evidence',
      description: 'Сбор доказательств атаки',
      category: PlaybookStepCategory.FORENSICS,
      actionType: PlaybookActionType.COLLECT_DATA,
      parameters: {
        dataType: 'ddos_evidence',
        collectPCAP: true,
        collectFlowLogs: true,
        collectFirewallLogs: true,
        collectWAFLogs: true,
        preserveTimestamps: true
      },
      conditions: [],
      dependencies: ['detect-001'],
      timeout: 600000,
      retryCount: 1,
      retryInterval: 30000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    },

    {
      id: 'doc-003',
      name: 'Post-Incident Analysis',
      description: 'Пост-инцидентный анализ',
      category: PlaybookStepCategory.DOCUMENTATION,
      actionType: PlaybookActionType.DOCUMENT,
      parameters: {
        documentType: 'post_incident_analysis',
        includeTimeline: true,
        includeMetrics: true,
        includeLessonsLearned: true,
        includeRecommendations: true
      },
      conditions: [],
      dependencies: ['recover-004'],
      timeout: 900000,
      retryCount: 1,
      retryInterval: 10000,
      status: 'pending',
      automatic: true,
      requiresApproval: false
    }
  ];

  return {
    id: 'ddos-attack-v1.0',
    name: 'DDoS Attack Response',
    description: 'Комплексный playbook для реагирования на DDoS атаки. Включает обнаружение, mitigation, восстановление и анализ.',
    version: '1.0.0',
    incidentCategory: IncidentCategory.DDOS_ATTACK,
    minSeverity: IncidentSeverity.MEDIUM,
    steps,
    variables: {
      ddosMitigationProvider: 'cloudflare',
      scrubbingCenterEnabled: true,
      autoScaleEnabled: true,
      upstreamProviderContacts: ['isp_noc', 'hosting_provider'],
      statusPageEnabled: true,
      evidenceRetentionDays: 365
    },
    integrations: ['ddos_protection', 'waf', 'cdn', 'load_balancer', 'slack', 'pagerduty', 'servicenow'],
    tags: ['ddos', 'dos', 'volumetric', 'application_layer', 'mitigation'],
    author: 'Security Operations Team',
    lastUpdated: new Date(),
    status: 'active'
  };
}

/**
 * Экспорт конфигурации playbook
 */
export const ddosAttackPlaybook = createDDoSAttackPlaybook();
