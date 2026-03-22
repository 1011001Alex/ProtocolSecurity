/**
 * ============================================================================
 * INCIDENT CLASSIFIER
 * ============================================================================
 * Модуль классификации и оценки серьезности инцидентов безопасности
 * Соответствует NIST SP 800-61 и SANS Incident Response Methodology
 * ============================================================================
 */

import {
  IncidentCategory,
  IncidentSeverity,
  IncidentPriority,
  SeverityScore,
  ScoringFactor,
  IncidentDetails,
  IOC,
  IOCType,
  DataClassification,
  MITREAttackTactic,
  ClassificationConfig,
  Actor
} from '../types/incident.types';

/**
 * Контекст для классификации инцидента
 * Содержит всю необходимую информацию для принятия решения
 */
export interface ClassificationContext {
  /** Детали инцидента */
  details: IncidentDetails;
  /** Затронутые системы */
  affectedSystems: SystemInfo[];
  /** Затронутые пользователи */
  affectedUsers: UserInfo[];
  /** Затронутые данные */
  affectedData: DataAssetInfo[];
  /** Время обнаружения */
  detectedAt: Date;
  /** Источник инцидента (если известен) */
  source?: Actor;
  /** Дополнительные метаданные */
  metadata?: Record<string, unknown>;
}

/**
 * Информация о системе
 */
export interface SystemInfo {
  /** Идентификатор системы */
  id: string;
  /** Название системы */
  name: string;
  /** Тип системы */
  type: 'server' | 'workstation' | 'network_device' | 'database' | 'application' | 'cloud_service';
  /** Критичность для бизнеса */
  criticality: 'critical' | 'high' | 'medium' | 'low';
  /** Содержит чувствительные данные */
  hasSensitiveData: boolean;
  /** Публичный доступ */
  isPublicFacing: boolean;
  /** Связь с другими системами */
  connectedSystems?: string[];
}

/**
 * Информация о пользователе
 */
export interface UserInfo {
  /** Идентификатор пользователя */
  id: string;
  /** Имя пользователя */
  username: string;
  /** Роль */
  role: string;
  /** Отдел */
  department?: string;
  /** Уровень доступа */
  accessLevel: 'admin' | 'privileged' | 'standard' | 'limited';
  /** Доступ к чувствительным данным */
  hasSensitiveDataAccess: boolean;
}

/**
 * Информация о активе данных
 */
export interface DataAssetInfo {
  /** Тип данных */
  type: string;
  /** Классификация */
  classification: DataClassification;
  /** Объем данных (байты) */
  volume?: number;
  /** Количество записей */
  recordCount?: number;
  /** Юрисдикция данных */
  dataJurisdiction?: string[];
  /** Регуляторные требования */
  regulatoryRequirements?: string[];
}

/**
 * Результат классификации
 */
export interface ClassificationResult {
  /** Категория инцидента */
  category: IncidentCategory;
  /** Подкатегория */
  subCategory?: string;
  /** Серьезность */
  severity: IncidentSeverity;
  /** Приоритет */
  priority: IncidentPriority;
  /** Оценка серьезности с деталями */
  severityScore: SeverityScore;
  /** Обоснование классификации */
  rationale: string;
  /** Факторы, влияющие на классификацию */
  influencingFactors: ClassificationFactor[];
  /** Рекомендуемые действия */
  recommendedActions: string[];
  /** Уверенность в классификации (0-100) */
  confidence: number;
  /** Требует ручной проверки */
  requiresManualReview: boolean;
  /** Время классификации */
  classifiedAt: Date;
}

/**
 * Фактор классификации
 */
export interface ClassificationFactor {
  /** Название фактора */
  name: string;
  /** Описание */
  description: string;
  /** Влияние на серьезность */
  impact: 'increase' | 'decrease' | 'neutral';
  /** Сила влияния (1-10) */
  strength: number;
}

/**
 * Правила классификации для категорий инцидентов
 */
interface ClassificationRule {
  /** Уникальный идентификатор правила */
  id: string;
  /** Название правила */
  name: string;
  /** Описание */
  description: string;
  /** Категория, которую определяет правило */
  category: IncidentCategory;
  /** Условия срабатывания */
  conditions: ClassificationCondition[];
  /** Приоритет правила (чем выше, тем важнее) */
  priority: number;
  /** Вес правила для уверенности */
  confidenceWeight: number;
}

/**
 * Условие классификации
 */
interface ClassificationCondition {
  /** Поле для проверки */
  field: string;
  /** Оператор */
  operator: 'contains' | 'equals' | 'regex' | 'greater_than' | 'exists';
  /** Значение для сравнения */
  value: unknown;
}

/**
 * Класс для классификации инцидентов безопасности
 * Реализует многофакторную систему оценки на основе:
 * - Воздействия на бизнес
 * - Срочности реагирования
 * - Сложности инцидента
 */
export class IncidentClassifier {
  /** Конфигурация классификации */
  private config: ClassificationConfig;

  /** Правила классификации по категориям */
  private classificationRules: ClassificationRule[];

  /** Весовые коэффициенты для факторов серьезности */
  private readonly severityWeights = {
    // Воздействие на бизнес (40%)
    businessImpact: 0.4,
    // Срочность (35%)
    urgency: 0.35,
    // Сложность (25%)
    complexity: 0.25
  };

  /** Пороговые значения для уровней серьезности */
  private readonly severityThresholds = {
    critical: 80,
    high: 60,
    medium: 40,
    low: 20
  };

  /** Пороговые значения для приоритетов */
  private readonly priorityThresholds = {
    P1: 90,
    P2: 70,
    P3: 50,
    P4: 30,
    P5: 0
  };

  /**
   * Конструктор классификатора
   * @param config - Конфигурация классификации
   */
  constructor(config?: Partial<ClassificationConfig>) {
    this.config = this.mergeConfigWithDefaults(config);
    this.classificationRules = this.initializeClassificationRules();
  }

  /**
   * Объединение пользовательской конфигурации с дефолтной
   */
  private mergeConfigWithDefaults(config: Partial<ClassificationConfig> | undefined): ClassificationConfig {
    const defaultConfig: ClassificationConfig = {
      severityWeights: {
        businessImpact: 0.4,
        urgency: 0.35,
        complexity: 0.25
      },
      severityThresholds: {
        critical: 80,
        high: 60,
        medium: 40,
        low: 20
      },
      autoClassificationEnabled: true,
      requiresConfirmation: false
    };

    if (!config) {
      return defaultConfig;
    }

    return {
      ...defaultConfig,
      ...config,
      severityWeights: { ...defaultConfig.severityWeights, ...config.severityWeights },
      severityThresholds: { ...defaultConfig.severityThresholds, ...config.severityThresholds }
    };
  }

  /**
   * Инициализация правил классификации
   */
  private initializeClassificationRules(): ClassificationRule[] {
    return [
      // Правила для Malware
      {
        id: 'malware-001',
        name: 'Malware Detection',
        description: 'Обнаружение вредоносного ПО',
        category: IncidentCategory.MALWARE,
        conditions: [
          { field: 'title', operator: 'contains', value: 'malware' },
          { field: 'title', operator: 'contains', value: 'virus' },
          { field: 'title', operator: 'contains', value: 'trojan' },
          { field: 'description', operator: 'contains', value: 'malicious software' }
        ],
        priority: 10,
        confidenceWeight: 0.8
      },
      {
        id: 'ransomware-001',
        name: 'Ransomware Detection',
        description: 'Обнаружение ransomware атаки',
        category: IncidentCategory.RANSOMWARE_ATTACK,
        conditions: [
          { field: 'title', operator: 'contains', value: 'ransomware' },
          { field: 'title', operator: 'contains', value: 'encryption' },
          { field: 'description', operator: 'contains', value: 'ransom' },
          { field: 'description', operator: 'contains', value: 'encrypted files' }
        ],
        priority: 20,
        confidenceWeight: 0.9
      },
      // Правила для Data Breach
      {
        id: 'databreach-001',
        name: 'Data Breach Detection',
        description: 'Обнаружение утечки данных',
        category: IncidentCategory.DATA_BREACH,
        conditions: [
          { field: 'title', operator: 'contains', value: 'data breach' },
          { field: 'title', operator: 'contains', value: 'data leak' },
          { field: 'description', operator: 'contains', value: 'unauthorized access to data' },
          { field: 'description', operator: 'contains', value: 'data exfiltration' }
        ],
        priority: 15,
        confidenceWeight: 0.85
      },
      // Правила для DDoS
      {
        id: 'ddos-001',
        name: 'DDoS Attack Detection',
        description: 'Обнаружение DDoS атаки',
        category: IncidentCategory.DDOS_ATTACK,
        conditions: [
          { field: 'title', operator: 'contains', value: 'ddos' },
          { field: 'title', operator: 'contains', value: 'denial of service' },
          { field: 'description', operator: 'contains', value: 'traffic spike' },
          { field: 'description', operator: 'contains', value: 'service unavailable' }
        ],
        priority: 12,
        confidenceWeight: 0.8
      },
      // Правила для Insider Threat
      {
        id: 'insider-001',
        name: 'Insider Threat Detection',
        description: 'Обнаружение угрозы изнутри',
        category: IncidentCategory.INSIDER_THREAT,
        conditions: [
          { field: 'title', operator: 'contains', value: 'insider' },
          { field: 'description', operator: 'contains', value: 'unauthorized access by employee' },
          { field: 'description', operator: 'contains', value: 'policy violation' }
        ],
        priority: 8,
        confidenceWeight: 0.7
      },
      // Правила для Credential Compromise
      {
        id: 'credential-001',
        name: 'Credential Compromise Detection',
        description: 'Обнаружение компрометации учетных данных',
        category: IncidentCategory.CREDENTIAL_COMPROMISE,
        conditions: [
          { field: 'title', operator: 'contains', value: 'credential' },
          { field: 'title', operator: 'contains', value: 'password' },
          { field: 'description', operator: 'contains', value: 'compromised credentials' },
          { field: 'description', operator: 'contains', value: 'brute force' }
        ],
        priority: 10,
        confidenceWeight: 0.75
      },
      // Правила для Phishing
      {
        id: 'phishing-001',
        name: 'Phishing Detection',
        description: 'Обнаружение фишинговой атаки',
        category: IncidentCategory.PHISHING,
        conditions: [
          { field: 'title', operator: 'contains', value: 'phishing' },
          { field: 'description', operator: 'contains', value: 'suspicious email' },
          { field: 'description', operator: 'contains', value: 'malicious link' }
        ],
        priority: 7,
        confidenceWeight: 0.7
      },
      // Правила для Unauthorized Access
      {
        id: 'unauth-001',
        name: 'Unauthorized Access Detection',
        description: 'Обнаружение несанкционированного доступа',
        category: IncidentCategory.UNAUTHORIZED_ACCESS,
        conditions: [
          { field: 'title', operator: 'contains', value: 'unauthorized' },
          { field: 'description', operator: 'contains', value: 'unauthorized access' },
          { field: 'description', operator: 'contains', value: 'privilege escalation' }
        ],
        priority: 9,
        confidenceWeight: 0.75
      }
    ];
  }

  /**
   * Основная метода классификации инцидента
   * @param context - Контекст инцидента
   * @returns Результат классификации
   */
  public classify(context: ClassificationContext): ClassificationResult {
    const startTime = Date.now();

    // 1. Определяем категорию инцидента
    const categoryResult = this.determineCategory(context);

    // 2. Рассчитываем оценку серьезности
    const severityScore = this.calculateSeverityScore(context);

    // 3. Определяем уровень серьезности на основе оценки
    const severity = this.determineSeverity(severityScore.totalScore);

    // 4. Определяем приоритет
    const priority = this.determinePriority(severityScore.totalScore, context);

    // 5. Формируем обоснование
    const rationale = this.generateRationale(categoryResult, severityScore, severity, priority, context);

    // 6. Определяем влияющие факторы
    const influencingFactors = this.identifyInfluencingFactors(context, severityScore);

    // 7. Генерируем рекомендуемые действия
    const recommendedActions = this.generateRecommendedActions(categoryResult.category, severity, context);

    // 8. Рассчитываем уверенность
    const confidence = this.calculateConfidence(categoryResult, context);

    // 9. Определяем, требуется ли ручная проверка
    const requiresManualReview = this.requiresManualReview(confidence, severity, context);

    return {
      category: categoryResult.category,
      subCategory: categoryResult.subCategory,
      severity,
      priority,
      severityScore,
      rationale,
      influencingFactors,
      recommendedActions,
      confidence,
      requiresManualReview,
      classifiedAt: new Date()
    };
  }

  /**
   * Определение категории инцидента
   */
  private determineCategory(context: ClassificationContext): { category: IncidentCategory; subCategory?: string } {
    // Проверяем явное указание категории в деталях
    if (context.details.category) {
      return {
        category: context.details.category,
        subCategory: context.details.subCategory
      };
    }

    // Применяем правила классификации
    const matchedRules = this.classificationRules.filter(rule =>
      this.matchRule(rule, context)
    );

    if (matchedRules.length > 0) {
      // Сортируем по приоритету и выбираем наивысший
      matchedRules.sort((a, b) => b.priority - a.priority);
      const bestMatch = matchedRules[0];

      return {
        category: bestMatch.category,
        subCategory: bestMatch.name
      };
    }

    // Если ничего не подошло, определяем по IOC
    const iocCategory = this.determineCategoryByIOC(context.details.indicatorsOfCompromise || []);
    if (iocCategory) {
      return { category: iocCategory };
    }

    // По умолчанию
    return { category: IncidentCategory.OTHER };
  }

  /**
   * Проверка соответствия правила контексту
   */
  private matchRule(rule: ClassificationRule, context: ClassificationContext): boolean {
    // Проверяем все условия правила
    return rule.conditions.some(condition => {
      const value = this.getFieldValue(condition.field, context);

      switch (condition.operator) {
        case 'contains':
          return String(value).toLowerCase().includes(String(condition.value).toLowerCase());
        case 'equals':
          return String(value).toLowerCase() === String(condition.value).toLowerCase();
        case 'regex':
          try {
            return new RegExp(condition.value as string).test(String(value));
          } catch {
            return false;
          }
        case 'greater_than':
          return Number(value) > Number(condition.value);
        case 'exists':
          return value !== undefined && value !== null && value !== '';
        default:
          return false;
      }
    });
  }

  /**
   * Получение значения поля из контекста
   */
  private getFieldValue(field: string, context: ClassificationContext): unknown {
    const parts = field.split('.');
    let value: unknown = context;

    for (const part of parts) {
      if (value && typeof value === 'object') {
        value = (value as Record<string, unknown>)[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Определение категории по IOC
   */
  private determineCategoryByIOC(iocs: IOC[]): IncidentCategory | null {
    for (const ioc of iocs) {
      switch (ioc.type) {
        case IOCType.FILE_HASH_MD5:
        case IOCType.FILE_HASH_SHA1:
        case IOCType.FILE_HASH_SHA256:
        case IOCType.FILE_NAME:
          return IncidentCategory.MALWARE;
        case IOCType.DOMAIN:
        case IOCType.URL:
          if (ioc.tags?.includes('phishing')) {
            return IncidentCategory.PHISHING;
          }
          break;
        case IOCType.EMAIL_ADDRESS:
          return IncidentCategory.PHISHING;
      }
    }
    return null;
  }

  /**
   * Расчет оценки серьезности
   * Использует многофакторную модель оценки
   */
  private calculateSeverityScore(context: ClassificationContext): SeverityScore {
    const scoringFactors: ScoringFactor[] = [];

    // 1. Факторы воздействия на бизнес
    const businessImpactFactors = this.calculateBusinessImpactFactors(context);
    scoringFactors.push(...businessImpactFactors);

    // 2. Факторы срочности
    const urgencyFactors = this.calculateUrgencyFactors(context);
    scoringFactors.push(...urgencyFactors);

    // 3. Факторы сложности
    const complexityFactors = this.calculateComplexityFactors(context);
    scoringFactors.push(...complexityFactors);

    // Рассчитываем взвешенные баллы
    let totalWeightedScore = 0;
    let totalWeight = 0;

    for (const factor of scoringFactors) {
      factor.weightedScore = factor.weight * factor.value;
      totalWeightedScore += factor.weightedScore;
      totalWeight += factor.weight;
    }

    // Нормализуем общий балл (0-100)
    const normalizedTotalScore = totalWeight > 0
      ? Math.min(100, Math.round((totalWeightedScore / totalWeight) * 100))
      : 0;

    // Рассчитываем баллы по категориям
    const businessImpactScore = this.calculateCategoryScore(
      scoringFactors.filter(f => f.name.startsWith('business_')),
      this.severityWeights.businessImpact
    );

    const urgencyScore = this.calculateCategoryScore(
      scoringFactors.filter(f => f.name.startsWith('urgency_')),
      this.severityWeights.urgency
    );

    const complexityScore = this.calculateCategoryScore(
      scoringFactors.filter(f => f.name.startsWith('complexity_')),
      this.severityWeights.complexity
    );

    // Формируем обоснование
    const rationale = this.generateScoreRationale(scoringFactors, normalizedTotalScore);

    return {
      totalScore: normalizedTotalScore,
      businessImpactScore,
      urgencyScore,
      complexityScore,
      scoringFactors,
      rationale
    };
  }

  /**
   * Расчет факторов воздействия на бизнес
   */
  private calculateBusinessImpactFactors(context: ClassificationContext): ScoringFactor[] {
    const factors: ScoringFactor[] = [];

    // Фактор: Критичность затронутых систем
    const criticalSystemsCount = context.affectedSystems.filter(
      s => s.criticality === 'critical'
    ).length;

    factors.push({
      name: 'business_critical_systems',
      description: `Затронуто критических систем: ${criticalSystemsCount}`,
      weight: 0.25,
      value: Math.min(100, criticalSystemsCount * 25),
      weightedScore: 0
    });

    // Фактор: Чувствительные данные
    const hasSensitiveData = context.affectedData.some(
      d => d.classification === DataClassification.RESTRICTED ||
           d.classification === DataClassification.PII ||
           d.classification === DataClassification.PHI ||
           d.classification === DataClassification.PCI
    );

    factors.push({
      name: 'business_sensitive_data',
      description: hasSensitiveData ? 'Затронуты чувствительные данные' : 'Чувствительные данные не затронуты',
      weight: 0.25,
      value: hasSensitiveData ? 100 : 0,
      weightedScore: 0
    });

    // Фактор: Публичные системы
    const publicFacingSystems = context.affectedSystems.filter(s => s.isPublicFacing).length;

    factors.push({
      name: 'business_public_facing',
      description: `Затронуто публичных систем: ${publicFacingSystems}`,
      weight: 0.15,
      value: Math.min(100, publicFacingSystems * 20),
      weightedScore: 0
    });

    // Фактор: Количество затронутых пользователей
    const affectedUsersCount = context.affectedUsers.length;

    factors.push({
      name: 'business_affected_users',
      description: `Затронуто пользователей: ${affectedUsersCount}`,
      weight: 0.2,
      value: Math.min(100, affectedUsersCount >= 100 ? 100 : affectedUsersCount),
      weightedScore: 0
    });

    // Фактор: Привилегированные пользователи
    const privilegedUsers = context.affectedUsers.filter(
      u => u.accessLevel === 'admin' || u.accessLevel === 'privileged'
    ).length;

    factors.push({
      name: 'business_privileged_users',
      description: `Затронуто привилегированных пользователей: ${privilegedUsers}`,
      weight: 0.15,
      value: Math.min(100, privilegedUsers * 30),
      weightedScore: 0
    });

    return factors;
  }

  /**
   * Расчет факторов срочности
   */
  private calculateUrgencyFactors(context: ClassificationContext): ScoringFactor[] {
    const factors: ScoringFactor[] = [];

    // Фактор: Активная атака
    const isActiveAttack = this.detectActiveAttack(context);

    factors.push({
      name: 'urgency_active_attack',
      description: isActiveAttack ? 'Обнаружена активная атака' : 'Активная атака не обнаружена',
      weight: 0.3,
      value: isActiveAttack ? 100 : 0,
      weightedScore: 0
    });

    // Фактор: Продолжение экфильтрации
    const isExfiltrationOngoing = this.detectOngoingExfiltration(context);

    factors.push({
      name: 'urgency_exfiltration',
      description: isExfiltrationOngoing ? 'Возможна активная экфильтрация данных' : 'Экфильтрация не обнаружена',
      weight: 0.25,
      value: isExfiltrationOngoing ? 100 : 0,
      weightedScore: 0
    });

    // Фактор: Время обнаружения (рабочее/нерабочее)
    const isOutsideBusinessHours = this.isOutsideBusinessHours(context.detectedAt);

    factors.push({
      name: 'urgency_business_hours',
      description: isOutsideBusinessHours ? 'Обнаружено в нерабочее время' : 'Обнаружено в рабочее время',
      weight: 0.15,
      value: isOutsideBusinessHours ? 60 : 20,
      weightedScore: 0
    });

    // Фактор: Скорость распространения
    const spreadRate = this.estimateSpreadRate(context);

    factors.push({
      name: 'urgency_spread_rate',
      description: `Оценка скорости распространения: ${spreadRate}`,
      weight: 0.2,
      value: spreadRate === 'high' ? 100 : spreadRate === 'medium' ? 50 : 20,
      weightedScore: 0
    });

    // Фактор: Доступность эксплойта
    const hasPublicExploit = this.hasPublicExploitAvailable(context);

    factors.push({
      name: 'urgency_public_exploit',
      description: hasPublicExploit ? 'Доступен публичный эксплойт' : 'Публичный эксплойт не обнаружен',
      weight: 0.1,
      value: hasPublicExploit ? 80 : 0,
      weightedScore: 0
    });

    return factors;
  }

  /**
   * Расчет факторов сложности
   */
  private calculateComplexityFactors(context: ClassificationContext): ScoringFactor[] {
    const factors: ScoringFactor[] = [];

    // Фактор: Количество затронутых систем
    const affectedSystemsCount = context.affectedSystems.length;

    factors.push({
      name: 'complexity_affected_systems',
      description: `Затронуто систем: ${affectedSystemsCount}`,
      weight: 0.25,
      value: Math.min(100, affectedSystemsCount * 10),
      weightedScore: 0
    });

    // Фактор: Географическое распределение
    const uniqueLocations = new Set(
      context.affectedUsers.map(u => u.department).filter(Boolean)
    ).size;

    factors.push({
      name: 'complexity_geographic_spread',
      description: `Затронуто отделов/локаций: ${uniqueLocations}`,
      weight: 0.15,
      value: Math.min(100, uniqueLocations * 15),
      weightedScore: 0
    });

    // Фактор: Требуемые навыки для реагирования
    const requiredSkillLevel = this.estimateRequiredSkillLevel(context);

    factors.push({
      name: 'complexity_skill_required',
      description: `Требуемый уровень навыков: ${requiredSkillLevel}`,
      weight: 0.2,
      value: requiredSkillLevel === 'expert' ? 100 : requiredSkillLevel === 'advanced' ? 60 : 30,
      weightedScore: 0
    });

    // Фактор: Доступность информации об атаке
    const attackClarity = this.assessAttackClarity(context);

    factors.push({
      name: 'complexity_attack_clarity',
      description: `Ясность картины атаки: ${attackClarity}`,
      weight: 0.2,
      value: attackClarity === 'unclear' ? 100 : attackClarity === 'partial' ? 50 : 20,
      weightedScore: 0
    });

    // Фактор: Наличие playbook
    const hasPlaybook = this.hasApplicablePlaybook(context);

    factors.push({
      name: 'complexity_playbook_available',
      description: hasPlaybook ? 'Playbook доступен' : 'Playbook отсутствует',
      weight: 0.2,
      value: hasPlaybook ? 20 : 80,
      weightedScore: 0
    });

    return factors;
  }

  /**
   * Расчет балла категории
   */
  private calculateCategoryScore(factors: ScoringFactor[], maxWeight: number): number {
    if (factors.length === 0) return 0;

    const totalWeight = factors.reduce((sum, f) => sum + f.weight, 0);
    const totalScore = factors.reduce((sum, f) => sum + f.weightedScore, 0);

    if (totalWeight === 0) return 0;

    return Math.min(100, Math.round((totalScore / maxWeight) * 100));
  }

  /**
   * Определение уровня серьезности по总分
   */
  private determineSeverity(totalScore: number): IncidentSeverity {
    if (totalScore >= this.severityThresholds.critical) {
      return IncidentSeverity.CRITICAL;
    }
    if (totalScore >= this.severityThresholds.high) {
      return IncidentSeverity.HIGH;
    }
    if (totalScore >= this.severityThresholds.medium) {
      return IncidentSeverity.MEDIUM;
    }
    if (totalScore >= this.severityThresholds.low) {
      return IncidentSeverity.LOW;
    }
    return IncidentSeverity.INFORMATIONAL;
  }

  /**
   * Определение приоритета
   */
  private determinePriority(totalScore: number, context: ClassificationContext): IncidentPriority {
    // Базовый приоритет по总分
    let priority: IncidentPriority;

    if (totalScore >= this.priorityThresholds.P1) {
      priority = IncidentPriority.P1;
    } else if (totalScore >= this.priorityThresholds.P2) {
      priority = IncidentPriority.P2;
    } else if (totalScore >= this.priorityThresholds.P3) {
      priority = IncidentPriority.P3;
    } else if (totalScore >= this.priorityThresholds.P4) {
      priority = IncidentPriority.P4;
    } else {
      priority = IncidentPriority.P5;
    }

    // Корректировка по специальным условиям

    // Атака на критическую инфраструктуру всегда P1
    const hasCriticalInfrastructure = context.affectedSystems.some(
      s => s.criticality === 'critical' && s.isPublicFacing
    );
    if (hasCriticalInfrastructure) {
      priority = IncidentPriority.P1;
    }

    // Компрометация админских учеток - P1
    const hasAdminCompromise = context.affectedUsers.some(
      u => u.accessLevel === 'admin' && context.details.indicatorsOfCompromise?.some(
        ioc => ioc.type === IOCType.EMAIL_ADDRESS || ioc.type === IOCType.USER_AGENT
      )
    );
    if (hasAdminCompromise) {
      priority = IncidentPriority.P1;
    }

    return priority;
  }

  /**
   * Генерация обоснования классификации
   */
  private generateRationale(
    categoryResult: { category: IncidentCategory; subCategory?: string },
    severityScore: SeverityScore,
    severity: IncidentSeverity,
    priority: IncidentPriority,
    context: ClassificationContext
  ): string {
    const parts: string[] = [];

    // Категория
    parts.push(`Категория: ${categoryResult.category}${categoryResult.subCategory ? ` (${categoryResult.subCategory})` : ''}`);

    // Серьезность
    parts.push(`Серьезность: ${severity} (оценка: ${severityScore.totalScore}/100)`);

    // Приоритет
    parts.push(`Приоритет: P${priority}`);

    // Ключевые факторы
    const topFactors = severityScore.scoringFactors
      .sort((a, b) => b.weightedScore - a.weightedScore)
      .slice(0, 3);

    if (topFactors.length > 0) {
      parts.push('Ключевые факторы:');
      topFactors.forEach(f => {
        parts.push(`  - ${f.description} (вес: ${f.weight}, балл: ${f.value})`);
      });
    }

    return parts.join('\n');
  }

  /**
   * Идентификация влияющих факторов
   */
  private identifyInfluencingFactors(
    context: ClassificationContext,
    severityScore: SeverityScore
  ): ClassificationFactor[] {
    const factors: ClassificationFactor[] = [];

    // Положительные факторы (увеличивают серьезность)
    if (context.affectedSystems.some(s => s.criticality === 'critical')) {
      factors.push({
        name: 'Critical Systems Affected',
        description: 'Инцидент затрагивает критически важные системы',
        impact: 'increase',
        strength: 9
      });
    }

    if (context.affectedData.some(d => d.classification === DataClassification.RESTRICTED)) {
      factors.push({
        name: 'Restricted Data Involved',
        description: 'Затронуты данные с ограниченным доступом',
        impact: 'increase',
        strength: 10
      });
    }

    if (this.detectActiveAttack(context)) {
      factors.push({
        name: 'Active Attack Detected',
        description: 'Обнаружена активная продолжающаяся атака',
        impact: 'increase',
        strength: 10
      });
    }

    // Отрицательные факторы (уменьшают серьезность)
    if (context.affectedSystems.every(s => !s.isPublicFacing)) {
      factors.push({
        name: 'Internal Systems Only',
        description: 'Затронуты только внутренние системы',
        impact: 'decrease',
        strength: 3
      });
    }

    if (context.affectedUsers.length === 0) {
      factors.push({
        name: 'No Users Affected',
        description: 'Пользователи не затронуты',
        impact: 'decrease',
        strength: 4
      });
    }

    return factors;
  }

  /**
   * Генерация рекомендуемых действий
   */
  private generateRecommendedActions(
    category: IncidentCategory,
    severity: IncidentSeverity,
    context: ClassificationContext
  ): string[] {
    const actions: string[] = [];

    // Базовые действия для всех инцидентов
    actions.push('Задокументировать все обнаруженные артефакты');
    actions.push('Начать сбор форензика данных');

    // Действия в зависимости от серьезности
    if (severity === IncidentSeverity.CRITICAL || severity === IncidentSeverity.HIGH) {
      actions.push('Немедленно эскалировать руководству безопасности');
      actions.push('Активировать команду экстренного реагирования');
    }

    // Специфичные действия по категориям
    switch (category) {
      case IncidentCategory.MALWARE:
      case IncidentCategory.RANSOMWARE_ATTACK:
        actions.push('Изолировать зараженные системы от сети');
        actions.push('Заблокировать IOC на периметре');
        actions.push('Собрать образцы вредоносного ПО для анализа');
        break;

      case IncidentCategory.DATA_BREACH:
        actions.push('Определить объем и тип скомпрометированных данных');
        actions.push('Заблокировать каналы экфильтрации');
        actions.push('Уведомить юридический отдел о потенциальных регуляторных требованиях');
        break;

      case IncidentCategory.DDOS_ATTACK:
        actions.push('Активировать DDoS mitigation');
        actions.push('Увеличить пропускную способность каналов');
        actions.push('Заблокировать источники атаки на уровне сети');
        break;

      case IncidentCategory.INSIDER_THREAT:
        actions.push('Ограничить доступ подозреваемого до завершения расследования');
        actions.push('Собрать логи активности пользователя');
        actions.push('Уведомить HR и юридический отдел');
        break;

      case IncidentCategory.CREDENTIAL_COMPROMISE:
        actions.push('Принудительно сбросить скомпрометированные учетные данные');
        actions.push('Отозвать все активные сессии');
        actions.push('Включить MFA для затронутых учетных записей');
        break;

      case IncidentCategory.PHISHING:
        actions.push('Заблокировать фишинговые URL и домены');
        actions.push('Удалить фишинговые письма из почтовых ящиков');
        actions.push('Отправить предупреждение пользователям');
        break;
    }

    return actions;
  }

  /**
   * Расчет уверенности в классификации
   */
  private calculateConfidence(
    categoryResult: { category: IncidentCategory; subCategory?: string },
    context: ClassificationContext
  ): number {
    let confidence = 50; // Базовая уверенность

    // Увеличиваем уверенность при совпадении правил
    const matchedRules = this.classificationRules.filter(rule =>
      this.matchRule(rule, context)
    );

    if (matchedRules.length > 0) {
      const bestMatch = matchedRules.sort((a, b) => b.priority - a.priority)[0];
      confidence += bestMatch.confidenceWeight * 40;
    }

    // Увеличиваем уверенность при наличии IOC
    if (context.details.indicatorsOfCompromise && context.details.indicatorsOfCompromise.length > 0) {
      confidence += Math.min(20, context.details.indicatorsOfCompromise.length * 5);
    }

    // Увеличиваем уверенность при наличии MITRE техник
    if (context.details.mitreTechniques && context.details.mitreTechniques.length > 0) {
      confidence += Math.min(15, context.details.mitreTechniques.length * 5);
    }

    return Math.min(100, confidence);
  }

  /**
   * Определение необходимости ручной проверки
   */
  private requiresManualReview(
    confidence: number,
    severity: IncidentSeverity,
    context: ClassificationContext
  ): boolean {
    // Низкая уверенность требует проверки
    if (confidence < 60) {
      return true;
    }

    // Критические инциденты всегда требуют проверки
    if (severity === IncidentSeverity.CRITICAL) {
      return true;
    }

    // Неопределенная категория
    if (context.details.category === IncidentCategory.OTHER) {
      return true;
    }

    // Конфигурация требует подтверждения
    if (this.config.requiresConfirmation) {
      return true;
    }

    return false;
  }

  /**
   * Детектирование активной атаки
   */
  private detectActiveAttack(context: ClassificationContext): boolean {
    // Проверяем наличие IOC, указывающих на активную атаку
    const iocs = context.details.indicatorsOfCompromise || [];

    // Активная атака если есть C2 коммуникация
    const hasC2 = iocs.some(ioc =>
      ioc.type === IOCType.DOMAIN || ioc.type === IOCType.IP_ADDRESS
    );

    // Активная атака если есть признаки выполнения вредоносного кода
    const hasMalwareExecution = context.details.title.toLowerCase().includes('execution') ||
                                context.details.description.toLowerCase().includes('malware');

    return hasC2 || hasMalwareExecution;
  }

  /**
   * Детектирование продолжающейся экфильтрации
   */
  private detectOngoingExfiltration(context: ClassificationContext): boolean {
    return context.details.description.toLowerCase().includes('exfiltration') ||
           context.details.description.toLowerCase().includes('data transfer') ||
           context.details.description.toLowerCase().includes('unusual outbound');
  }

  /**
   * Проверка, является ли время нерабочим
   */
  private isOutsideBusinessHours(date: Date): boolean {
    const hour = date.getHours();
    const day = date.getDay();

    // Выходные
    if (day === 0 || day === 6) {
      return true;
    }

    // Нерабочие часы (до 9 или после 18)
    return hour < 9 || hour >= 18;
  }

  /**
   * Оценка скорости распространения
   */
  private estimateSpreadRate(context: ClassificationContext): 'low' | 'medium' | 'high' {
    const systemsCount = context.affectedSystems.length;

    if (systemsCount >= 10) {
      return 'high';
    }
    if (systemsCount >= 3) {
      return 'medium';
    }
    return 'low';
  }

  /**
   * Проверка наличия публичного эксплойта
   */
  private hasPublicExploitAvailable(context: ClassificationContext): boolean {
    // Проверяем наличие CVE в описании
    const cvePattern = /CVE-\d{4}-\d{4,}/i;
    return cvePattern.test(context.details.description);
  }

  /**
   * Оценка требуемого уровня навыков
   */
  private estimateRequiredSkillLevel(context: ClassificationContext): 'basic' | 'intermediate' | 'advanced' | 'expert' {
    const hasMITRETechniques = context.details.mitreTechniques && context.details.mitreTechniques.length > 0;
    const isComplexAttack = context.details.attackVector && context.details.attackVector.toLowerCase().includes('advanced');

    if (isComplexAttack && hasMITRETechniques) {
      return 'expert';
    }
    if (hasMITRETechniques) {
      return 'advanced';
    }
    if (context.details.indicatorsOfCompromise && context.details.indicatorsOfCompromise.length > 5) {
      return 'intermediate';
    }
    return 'basic';
  }

  /**
   * Оценка ясности картины атаки
   */
  private assessAttackClarity(context: ClassificationContext): 'clear' | 'partial' | 'unclear' {
    const hasSource = !!context.details.source;
    const hasVector = !!context.details.attackVector;
    const hasIOCs = (context.details.indicatorsOfCompromise?.length || 0) > 0;

    if (hasSource && hasVector && hasIOCs) {
      return 'clear';
    }
    if (hasVector || hasIOCs) {
      return 'partial';
    }
    return 'unclear';
  }

  /**
   * Проверка наличия применимого playbook
   */
  private hasApplicablePlaybook(context: ClassificationContext): boolean {
    // В реальной системе здесь была бы проверка наличия playbook для категории
    // Для простоты считаем, что playbook есть для известных категорий
    const knownCategories = [
      IncidentCategory.MALWARE,
      IncidentCategory.DATA_BREACH,
      IncidentCategory.DDOS_ATTACK,
      IncidentCategory.RANSOMWARE_ATTACK,
      IncidentCategory.CREDENTIAL_COMPROMISE,
      IncidentCategory.PHISHING
    ];

    return knownCategories.includes(context.details.category);
  }

  /**
   * Генерация обоснования для оценки серьезности
   */
  private generateScoreRationale(factors: ScoringFactor[], totalScore: number): string {
    const topFactors = factors
      .sort((a, b) => b.weightedScore - a.weightedScore)
      .slice(0, 5);

    const rationale = `Общая оценка: ${totalScore}/100\n\nКлючевые факторы:\n`;

    topFactors.forEach((factor, index) => {
      rationale += `${index + 1}. ${factor.description} (взвешенный балл: ${factor.weightedScore.toFixed(1)})\n`;
    });

    return rationale.trim();
  }

  /**
   * Обновление конфигурации классификации
   */
  public updateConfig(config: Partial<ClassificationConfig>): void {
    this.config = this.mergeConfigWithDefaults(config);
  }

  /**
   * Добавление пользовательского правила классификации
   */
  public addClassificationRule(rule: ClassificationRule): void {
    this.classificationRules.push(rule);
  }

  /**
   * Получение всех правил классификации
   */
  public getClassificationRules(): ClassificationRule[] {
    return [...this.classificationRules];
  }

  /**
   * Валидация контекста классификации
   */
  public validateContext(context: ClassificationContext): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!context.details.title || context.details.title.trim() === '') {
      errors.push('Заголовок инцидента обязателен');
    }

    if (!context.details.description || context.details.description.trim() === '') {
      errors.push('Описание инцидента обязательно');
    }

    if (!context.details.category) {
      errors.push('Категория инцидента обязательна');
    }

    if (context.affectedSystems.length === 0) {
      errors.push('Должна быть указана хотя бы одна затронутая система');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

/**
 * Экспорт дополнительных типов
 */
export type {
  ClassificationRule,
  ClassificationCondition
};
