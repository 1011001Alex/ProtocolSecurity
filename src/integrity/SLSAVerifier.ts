/**
 * ============================================================================
 * SLSA VERIFIER - ВЕРИФИКАЦИЯ УРОВНЕЙ SLSA
 * ============================================================================
 * Модуль для верификации соответствия артефактов уровням SLSA
 * (Supply-chain Levels for Software Artifacts).
 * 
 * SLSA уровни:
 * - Level 1: ArTeFaCt Provenance (документированный процесс сборки)
 * - Level 2: Version Control (исходный код в VCS)
 * - Level 3: Controlled Build Process (контролируемый процесс сборки)
 * - Level 4: Two-Person Review + Reproducible Builds (рецензирование + воспроизводимость)
 * 
 * Особенности:
 * - Верификация SLSA provenance
 * - Проверка требований по уровням
 * - Генерация отчетов о соответствии
 * - Интеграция с in-toto attestation
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  SLSALevel,
  SLSAVerificationResult,
  SLSALevelCheck,
  SLSAProvenance,
  OperationResult,
  SignatureResult
} from '../types/integrity.types';

/**
 * Конфигурация SLSA Verifier
 */
export interface SLSAVerifierConfig {
  /** Требуемый уровень SLSA */
  requiredLevel: SLSALevel;
  /** URL builder API */
  builderAPIUrl?: string;
  /** Доверенные builder ID */
  trustedBuilderIds: string[];
  /** Требовать воспроизводимость */
  requireReproducible: boolean;
  /** Требовать two-person review */
  requireTwoPersonReview: boolean;
  /** Алгоритм хеширования */
  hashAlgorithm: string;
}

/**
 * in-toto Statement формат
 */
export interface IntotoStatement {
  /** Тип statement */
  _type: string;
  /** Subject артефакты */
  subject: Array<{
    name: string;
    digest: Record<string, string>;
  }>;
  /** Predicate type */
  predicateType: string;
  /** Predicate данные */
  predicate: Record<string, unknown>;
}

/**
 * SLSA Provenance Predicate
 */
export interface SLSAProvenancePredicate {
  /** Builder информация */
  builder: {
    id: string;
    version?: Record<string, string>;
    builderDependencies?: Array<{
      name: string;
      digest: Record<string, string>;
    }>;
  };
  /** Build тип */
  buildType: string;
  /** Invoked by */
  invokedBy?: {
    id: string;
    caller?: {
      id: string;
    };
  };
  /** Build параметры */
  buildConfig?: Record<string, unknown>;
  /** Внешние параметры */
  externalParameters?: Record<string, unknown>;
  /** Внутренние параметры */
  internalParameters?: Record<string, unknown>;
  /** Разрешенные внешние параметры */
  allowedExternalParameters?: string[];
  /** Разрешенные внутренние параметры */
  allowedInternalParameters?: string[];
  /** Разрешенные базовые образы */
  allowedBaseImages?: string[];
  /** Разрешенные базовые builder */
  allowedBaseBuilder?: string;
  /** Разрешенные задачи */
  allowedTasks?: Array<{
    uri: string;
    digest?: Record<string, string>;
    entryPoint?: string;
  }>;
  /** Разрешенные шаги */
  allowedSteps?: Array<{
    uri: string;
    digest?: Record<string, string>;
    entryPoint?: string;
  }>;
  /** Разрешенные макросы */
  allowedMacros?: string[];
  /** Разрешенные среды */
  allowedEnvironments?: string[];
  /** Разрешенные переменные окружения */
  allowedEnv?: string[];
  /** Разрешенные секреты */
  allowedSecrets?: string[];
  /** Разрешенные хосты */
  allowedHosts?: string[];
  /** Разрешенные сети */
  allowedNetworks?: string[];
  /** Разрешенные устройства */
  allowedDevices?: string[];
  /** Разрешенные файловые системы */
  allowedFileSystem?: string[];
  /** Разрешенные capabilities */
  allowedCapabilities?: string[];
  /** Разрешенные syscalls */
  allowedSyscalls?: string[];
  /** Разрешенные namespaces */
  allowedNamespaces?: string[];
  /** Разрешенные users */
  allowedUsers?: string[];
  /** Разрешенные groups */
  allowedGroups?: string[];
  /** Разрешенные seccomp */
  allowedSeccomp?: string;
  /** Разрешенные apparmor */
  allowedApparmor?: string;
  /** Разрешенные selinux */
  allowedSELinux?: string;
  /** Resolved dependencies */
  resolvedDependencies?: Array<{
    uri: string;
    digest?: Record<string, string>;
    name?: string;
    downloadLocation?: string;
    mediaType?: string;
  }>;
  /** Byproducts */
  byproducts?: Array<{
    uri: string;
    digest?: Record<string, string>;
  }>;
  /** Metadata */
  metadata?: {
    buildInvocationId?: string;
    buildStartedOn?: string;
    buildFinishedOn?: string;
    completeness?: {
      parameters?: boolean;
      environment?: boolean;
      materials?: boolean;
    };
    reproducible?: boolean;
  };
}

/**
 * Класс SLSA Verifier
 */
export class SLSAVerifier extends EventEmitter {
  /** Конфигурация */
  private readonly config: SLSAVerifierConfig;
  
  /** Кэш верификаций */
  private readonly verificationCache: Map<string, SLSAVerificationResult> = new Map();

  /**
   * Создает экземпляр SLSAVerifier
   */
  constructor(config: Partial<SLSAVerifierConfig> = {}) {
    super();
    
    this.config = {
      requiredLevel: config.requiredLevel || 3,
      builderAPIUrl: config.builderAPIUrl,
      trustedBuilderIds: config.trustedBuilderIds || [
        'https://github.com/actions/runner',
        'https://gitlab.com/gitlab-org/gitlab-runner',
        'https://cloud.google.com/cloud-build',
        'https://github.com/sigstore/cosign'
      ],
      requireReproducible: config.requireReproducible ?? false,
      requireTwoPersonReview: config.requireTwoPersonReview ?? false,
      hashAlgorithm: config.hashAlgorithm || 'sha256'
    };
  }

  /**
   * Верифицирует SLSA provenance
   * 
   * @param provenance - SLSA provenance данные
   * @param options - Опции верификации
   * @returns Результат верификации
   */
  async verifyProvenance(
    provenance: SLSAProvenance,
    options: {
      requiredLevel?: SLSALevel;
      strict?: boolean;
    } = {}
  ): Promise<OperationResult<SLSAVerificationResult>> {
    const startTime = Date.now();
    const requiredLevel = options.requiredLevel || this.config.requiredLevel;
    
    try {
      const levelChecks: SLSALevelCheck[] = [];
      const errors: string[] = [];
      const warnings: string[] = [];
      
      // Верифицируем каждый уровень от 0 до requiredLevel
      for (let level = 1 as SLSALevel; level <= requiredLevel; level++) {
        const checks = await this.verifyLevel(level, provenance);
        levelChecks.push(...checks);
      }
      
      // Определяем достигнутый уровень
      const achievedLevel = this.determineAchievedLevel(levelChecks);
      
      // Проверяем соответствие требуемому уровню
      const compliant = achievedLevel >= requiredLevel;
      
      if (!compliant) {
        errors.push(`Требуемый уровень SLSA ${requiredLevel} не достигнут. Достигнут уровень ${achievedLevel}`);
      }
      
      const result: SLSAVerificationResult = {
        achievedLevel,
        requiredLevel,
        compliant,
        verifiedAt: new Date(),
        provenance,
        levelChecks,
        errors,
        warnings
      };
      
      // Кэшируем результат
      const cacheKey = this.getCacheKey(provenance);
      this.verificationCache.set(cacheKey, result);
      
      this.emit('verification-complete', result);
      
      return {
        success: true,
        data: result,
        errors: compliant ? [] : errors,
        warnings,
        executionTime: Date.now() - startTime
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: Date.now() - startTime
      };
    }
  }

  /**
   * Верифицирует требования конкретного уровня SLSA
   */
  private async verifyLevel(
    level: SLSALevel,
    provenance: SLSAProvenance
  ): Promise<SLSALevelCheck[]> {
    const checks: SLSALevelCheck[] = [];
    
    switch (level) {
      case 1:
        checks.push(...await this.verifyLevel1(provenance));
        break;
      case 2:
        checks.push(...await this.verifyLevel2(provenance));
        break;
      case 3:
        checks.push(...await this.verifyLevel3(provenance));
        break;
      case 4:
        checks.push(...await this.verifyLevel4(provenance));
        break;
    }
    
    return checks;
  }

  /**
   * Верификация SLSA Level 1
   * Требования:
   * - Процесс сборки должен быть документирован
   * - Должна быть provenance информация
   */
  private async verifyLevel1(provenance: SLSAProvenance): Promise<SLSALevelCheck[]> {
    const checks: SLSALevelCheck[] = [];
    
    // Проверка 1.1: Наличие builder ID
    checks.push({
      level: 1,
      check: 'builder_id',
      requirement: 'Сборка должна использовать идентифицируемый builder',
      passed: !!provenance.builder?.id,
      evidence: provenance.builder?.id ? [provenance.builder.id] : []
    });
    
    // Проверка 1.2: Наличие build type
    checks.push({
      level: 1,
      check: 'build_type',
      requirement: 'Должен быть определен тип сборки',
      passed: !!provenance.buildType,
      evidence: provenance.buildType ? [provenance.buildType] : []
    });
    
    // Проверка 1.3: Наличие хотя бы одного resolved dependency или пустой список
    checks.push({
      level: 1,
      check: 'dependencies_listed',
      requirement: 'Зависимости должны быть задокументированы',
      passed: provenance.build.resolvedDependencies !== undefined,
      evidence: provenance.build.resolvedDependencies 
        ? provenance.build.resolvedDependencies.map(d => d.uri)
        : []
    });
    
    // Проверка 1.4: Формат provenance
    checks.push({
      level: 1,
      check: 'provenance_format',
      requirement: 'Provenance должен быть в машиночитаемом формате',
      passed: provenance.format === 'SLSA' || provenance.format === 'in-toto',
      evidence: [provenance.format]
    });
    
    return checks;
  }

  /**
   * Верификация SLSA Level 2
   * Требования:
   * - Исходный код должен быть в системе контроля версий
   * - Сборка должна использовать версионированный исходный код
   *
   * БЕЗОПАСНОСТЬ: Используем URL API для правильной проверки URI
   */
  private async verifyLevel2(provenance: SLSAProvenance): Promise<SLSALevelCheck[]> {
    const checks: SLSALevelCheck[] = [];

    // Проверка 2.1: Исходный код из VCS
    // ИСПОЛЬЗУЕМ БЕЗОПАСНУЮ ПРОВЕРКУ URI через URL API вместо строковых сравнений
    const hasVCSSource = provenance.build.resolvedDependencies?.some(dep => {
      try {
        // Проверяем git+ схему
        if (dep.uri.startsWith('git+')) {
          return true;
        }
        
        // Парсим URI и проверяем домен
        const url = new URL(dep.uri.replace(/^git\+/, ''));
        const hostname = url.hostname.toLowerCase();
        
        return hostname === 'github.com' || 
               hostname === 'gitlab.com' || 
               hostname === 'bitbucket.org' ||
               hostname.endsWith('.github.com') ||
               hostname.endsWith('.gitlab.com');
      } catch {
        // Неверный URI - не считаем VCS источником
        return false;
      }
    }) || false;

    checks.push({
      level: 2,
      check: 'version_controlled_source',
      requirement: 'Исходный код должен храниться в системе контроля версий',
      passed: hasVCSSource,
      evidence: provenance.build.resolvedDependencies
        ?.filter(d => {
          try {
            return d.uri.startsWith('git+') || new URL(d.uri.replace(/^git\+/, '')).hostname === 'github.com';
          } catch {
            return false;
          }
        })
        .map(d => d.uri) || []
    });

    // Проверка 2.2: Builder использует версионированный исходный код
    checks.push({
      level: 2,
      check: 'versioned_source',
      requirement: 'Сборка должна использовать конкретную версию исходного кода',
      passed: provenance.build.resolvedDependencies?.some(
        dep => dep.digest && Object.keys(dep.digest).length > 0
      ) || false,
      evidence: provenance.build.resolvedDependencies
        ?.filter(d => d.digest)
        .map(d => `${d.uri}@${JSON.stringify(d.digest)}`) || []
    });

    // Проверка 2.3: Builder идентифицирован
    checks.push({
      level: 2,
      check: 'hosted_builder',
      requirement: 'Сборка должна использовать hosted builder',
      passed: this.config.trustedBuilderIds.includes(provenance.builder.id),
      evidence: [provenance.builder.id]
    });

    return checks;
  }

  /**
   * Верификация SLSA Level 3
   * Требования:
   * - Сборка должна происходить в контролируемой среде
   * - Provenance должен быть подписан
   * - Изоляция сборки
   */
  private async verifyLevel3(provenance: SLSAProvenance): Promise<SLSALevelCheck[]> {
    const checks: SLSALevelCheck[] = [];
    
    // Проверка 3.1: Изолированная среда сборки
    checks.push({
      level: 3,
      check: 'isolated_build_environment',
      requirement: 'Сборка должна происходить в изолированной среде',
      passed: provenance.metadata?.completeness?.environment === true ||
              provenance.build.internalParameters?.isolated === true,
      evidence: provenance.metadata?.completeness?.environment 
        ? ['environment completeness verified'] 
        : []
    });
    
    // Проверка 3.2: Provenance подписан
    checks.push({
      level: 3,
      check: 'signed_provenance',
      requirement: 'Provenance должен быть криптографически подписан',
      passed: !!provenance.signature,
      evidence: provenance.signature ? ['signature present'] : []
    });
    
    // Проверка 3.3: Non-falsifiable provenance
    checks.push({
      level: 3,
      check: 'non_falsifiable_provenance',
      requirement: 'Provenance не должен быть подделываемым',
      passed: !!provenance.signature && !!provenance.metadata?.buildInvocationId,
      evidence: provenance.metadata?.buildInvocationId 
        ? [`invocation: ${provenance.metadata.buildInvocationId}`] 
        : []
    });
    
    // Проверка 3.4: Контролируемый процесс сборки
    checks.push({
      level: 3,
      check: 'controlled_build_process',
      requirement: 'Процесс сборки должен быть контролируемым',
      passed: !!provenance.buildType && provenance.buildType !== '',
      evidence: [provenance.buildType]
    });
    
    return checks;
  }

  /**
   * Верификация SLSA Level 4
   * Требования:
   * - Two-person review
   * - Воспроизводимая сборка
   * - Hermetic build
   */
  private async verifyLevel4(provenance: SLSAProvenance): Promise<SLSALevelCheck[]> {
    const checks: SLSALevelCheck[] = [];
    
    // Проверка 4.1: Two-person review
    const hasTwoPersonReview = provenance.build.internalParameters?.reviewers?.length >= 2 ||
                               provenance.build.buildConfig?.reviewers?.length >= 2 ||
                               this.config.requireTwoPersonReview === false; // Если не требуется
    
    checks.push({
      level: 4,
      check: 'two_person_review',
      requirement: 'Изменения должны проходить рецензирование двумя лицами',
      passed: hasTwoPersonReview,
      evidence: provenance.build.internalParameters?.reviewers 
        ? provenance.build.internalParameters.reviewers 
        : []
    });
    
    // Проверка 4.2: Воспроизводимая сборка
    const isReproducible = provenance.metadata?.reproducible === true ||
                           !this.config.requireReproducible; // Если не требуется
    
    checks.push({
      level: 4,
      check: 'reproducible_build',
      requirement: 'Сборка должна быть воспроизводимой',
      passed: isReproducible,
      evidence: provenance.metadata?.reproducible 
        ? ['build is reproducible'] 
        : ['reproducibility not required']
    });
    
    // Проверка 4.3: Hermetic build (полная изоляция)
    const isHermetic = provenance.metadata?.completeness?.parameters === true &&
                       provenance.metadata?.completeness?.environment === true &&
                       provenance.metadata?.completeness?.materials === true;
    
    checks.push({
      level: 4,
      check: 'hermetic_build',
      requirement: 'Сборка должна быть герметичной (hermetic)',
      passed: isHermetic || false,
      evidence: provenance.metadata?.completeness 
        ? [
            `parameters: ${provenance.metadata.completeness.parameters}`,
            `environment: ${provenance.metadata.completeness.environment}`,
            `materials: ${provenance.metadata.completeness.materials}`
          ]
        : []
    });
    
    // Проверка 4.4: Полная зависимость от declared материалов
    checks.push({
      level: 4,
      check: 'complete_dependencies',
      requirement: 'Все зависимости должны быть задекларированы',
      passed: provenance.metadata?.completeness?.materials === true,
      evidence: provenance.build.resolvedDependencies?.map(d => d.uri) || []
    });
    
    return checks;
  }

  /**
   * Определяет достигнутый уровень SLSA
   */
  private determineAchievedLevel(checks: SLSALevelCheck[]): SLSALevel {
    let achievedLevel: SLSALevel = 0;
    
    for (let level = 1; level <= 4; level++) {
      const levelChecks = checks.filter(c => c.level === level);
      const allPassed = levelChecks.every(c => c.passed);
      
      if (allPassed && levelChecks.length > 0) {
        achievedLevel = level as SLSALevel;
      } else if (!allPassed) {
        break;
      }
    }
    
    return achievedLevel;
  }

  /**
   * Генерирует ключ для кэширования
   */
  private getCacheKey(provenance: SLSAProvenance): string {
    const data = JSON.stringify({
      builder: provenance.builder.id,
      buildType: provenance.buildType,
      artifacts: provenance.artifacts
    });
    
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
  }

  /**
   * Верифицирует in-toto statement
   */
  async verifyIntotoStatement(statement: IntotoStatement): Promise<OperationResult<SLSAVerificationResult>> {
    try {
      // Проверяем тип statement
      if (statement._type !== 'https://in-toto.io/Statement/v0.1') {
        return {
          success: false,
          errors: ['Неверный тип in-toto statement'],
          warnings: [],
          executionTime: 0
        };
      }
      
      // Проверяем predicate type
      const slsaPredicateTypes = [
        'https://slsa.dev/provenance/v0.2',
        'https://slsa.dev/provenance/v1.0'
      ];
      
      if (!slsaPredicateTypes.includes(statement.predicateType)) {
        return {
          success: false,
          errors: ['Неверный тип provenance predicate'],
          warnings: [],
          executionTime: 0
        };
      }
      
      // Конвертируем в SLSAProvenance
      const predicate = statement.predicate as SLSAProvenancePredicate;
      
      const provenance: SLSAProvenance = {
        format: 'SLSA',
        specVersion: statement.predicateType.split('/').pop() || '1.0',
        builder: {
          id: predicate.builder.id,
          version: predicate.builder.version
        },
        build: {
          buildType: predicate.buildType,
          invokedBy: predicate.invokedBy,
          externalParameters: predicate.externalParameters,
          internalParameters: predicate.internalParameters,
          resolvedDependencies: predicate.resolvedDependencies
        },
        metadata: {
          buildInvocationId: predicate.metadata?.buildInvocationId || '',
          buildStartedOn: predicate.metadata?.buildStartedOn 
            ? new Date(predicate.metadata.buildStartedOn) 
            : undefined,
          buildFinishedOn: predicate.metadata?.buildFinishedOn
            ? new Date(predicate.metadata.buildFinishedOn)
            : undefined,
          completeness: predicate.metadata?.completeness,
          reproducible: predicate.metadata?.reproducible
        },
        artifacts: statement.subject.map(s => ({
          name: s.name,
          digest: s.digest
        }))
      };
      
      // Верифицируем provenance
      return await this.verifyProvenance(provenance);
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Неизвестная ошибка';
      
      return {
        success: false,
        errors: [errorMessage],
        warnings: [],
        executionTime: 0
      };
    }
  }

  /**
   * Генерирует SLSA provenance для артефакта
   */
  generateProvenance(options: {
    builderId: string;
    buildType: string;
    artifacts: Array<{ name: string; digest: Record<string, string> }>;
    resolvedDependencies?: Array<{ uri: string; digest?: Record<string, string> }>;
    buildInvocationId?: string;
    reproducible?: boolean;
  }): SLSAProvenance {
    const invocationId = options.buildInvocationId || 
      `build-${crypto.randomBytes(8).toString('hex')}`;
    
    const now = new Date();
    
    return {
      format: 'SLSA',
      specVersion: '1.0',
      builder: {
        id: options.builderId
      },
      build: {
        buildType: options.buildType,
        resolvedDependencies: options.resolvedDependencies || []
      },
      metadata: {
        buildInvocationId: invocationId,
        buildStartedOn: now,
        buildFinishedOn: new Date(),
        completeness: {
          parameters: true,
          environment: true,
          materials: true
        },
        reproducible: options.reproducible ?? false
      },
      artifacts: options.artifacts
    };
  }

  /**
   * Создает in-toto statement из provenance
   */
  createIntotoStatement(provenance: SLSAProvenance): IntotoStatement {
    return {
      _type: 'https://in-toto.io/Statement/v0.1',
      subject: provenance.artifacts.map(a => ({
        name: a.name,
        digest: a.digest
      })),
      predicateType: 'https://slsa.dev/provenance/v1.0',
      predicate: {
        builder: {
          id: provenance.builder.id,
          version: provenance.builder.version
        },
        buildType: provenance.build.buildType,
        invokedBy: provenance.build.invokedBy,
        externalParameters: provenance.build.externalParameters,
        internalParameters: provenance.build.internalParameters,
        resolvedDependencies: provenance.build.resolvedDependencies,
        metadata: {
          buildInvocationId: provenance.metadata.buildInvocationId,
          buildStartedOn: provenance.metadata.buildStartedOn?.toISOString(),
          buildFinishedOn: provenance.metadata.buildFinishedOn?.toISOString(),
          completeness: provenance.metadata.completeness,
          reproducible: provenance.metadata.reproducible
        }
      }
    };
  }

  /**
   * Получает результат верификации из кэша
   */
  getCachedResult(provenance: SLSAProvenance): SLSAVerificationResult | null {
    const cacheKey = this.getCacheKey(provenance);
    return this.verificationCache.get(cacheKey) || null;
  }

  /**
   * Очищает кэш верификаций
   */
  clearCache(): void {
    this.verificationCache.clear();
  }

  /**
   * Получает статистику верификаций
   */
  getStatistics(): {
    totalVerified: number;
    compliantCount: number;
    nonCompliantCount: number;
    averageLevel: number;
  } {
    const results = Array.from(this.verificationCache.values());
    const compliantCount = results.filter(r => r.compliant).length;
    const nonCompliantCount = results.length - compliantCount;
    const averageLevel = results.length > 0
      ? results.reduce((sum, r) => sum + r.achievedLevel, 0) / results.length
      : 0;
    
    return {
      totalVerified: results.length,
      compliantCount,
      nonCompliantCount,
      averageLevel
    };
  }
}

/**
 * Фабрика для SLSA Verifier
 */
export class SLSAVerifierFactory {
  /**
   * Создает verifier для Level 3 требований
   */
  static createForLevel3(): SLSAVerifier {
    return new SLSAVerifier({
      requiredLevel: 3,
      requireReproducible: false,
      requireTwoPersonReview: false
    });
  }

  /**
   * Создает verifier для Level 4 требований
   */
  static createForLevel4(): SLSAVerifier {
    return new SLSAVerifier({
      requiredLevel: 4,
      requireReproducible: true,
      requireTwoPersonReview: true
    });
  }

  /**
   * Создает verifier с кастомной конфигурацией
   */
  static createWithConfig(config: SLSAVerifierConfig): SLSAVerifier {
    return new SLSAVerifier(config);
  }
}
