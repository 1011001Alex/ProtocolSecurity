/**
 * ============================================================================
 * THREAT HUNTING
 * Проактивный поиск угроз с использованием hunting queries и playbooks
 * ============================================================================
 */

import {
  HuntQuery,
  HuntParameter,
  HuntResult,
  HuntFinding,
  HuntStatistics,
  HuntPlaybook,
  HuntStep,
  SecurityEvent,
  ThreatSeverity,
  ThreatCategory,
  MitreMapping
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * Конфигурация Threat Hunting
 */
interface ThreatHuntingConfig {
  maxQueryExecutionTime: number;  // мс
  maxResultsPerQuery: number;
  defaultTimeRange: number;  // часов
}

/**
 * Источник данных для hunting
 */
interface DataSource {
  id: string;
  name: string;
  type: 'elasticsearch' | 'splunk' | 'sql' | 'custom';
  connectionString: string;
  queryLanguage: 'sql' | 'lucene' | 'kql' | 'spl' | 'custom';
}

/**
 * ============================================================================
 * THREAT HUNTING SERVICE
 * ============================================================================
 */
export class ThreatHuntingService {
  private config: ThreatHuntingConfig;
  
  // Hunting queries
  private queries: Map<string, HuntQuery> = new Map();
  
  // Playbooks
  private playbooks: Map<string, HuntPlaybook> = new Map();
  
  // Источники данных
  private dataSources: Map<string, DataSource> = new Map();
  
  // История выполнений
  private executionHistory: HuntResult[] = [];
  private maxHistorySize: number = 1000;
  
  // Статистика
  private statistics: HuntStatistics = {
    totalEvents: 0,
    uniqueEntities: 0,
    timeRange: {
      start: new Date(Date.now() - 24 * 60 * 60 * 1000),
      end: new Date()
    },
    topFindings: [],
    anomaliesDetected: 0
  };

  constructor(config?: Partial<ThreatHuntingConfig>) {
    this.config = {
      maxQueryExecutionTime: config?.maxQueryExecutionTime || 300000,  // 5 минут
      maxResultsPerQuery: config?.maxResultsPerQuery || 10000,
      defaultTimeRange: config?.defaultTimeRange || 24
    };
    
    this.initializeQueries();
    this.initializePlaybooks();
    
    console.log('[ThreatHunting] Инициализация завершена');
  }

  // ============================================================================
  // ИНИЦИАЛИЗАЦИЯ
  // ============================================================================

  /**
   * Инициализация hunting queries
   */
  private initializeQueries(): void {
    // Query: Обнаружение PowerShell аномалий
    this.addQuery({
      id: 'HUNT-001',
      name: 'PowerShell Аномалии',
      description: 'Поиск аномального использования PowerShell',
      category: ThreatCategory.EXECUTION,
      mitreTechniques: ['T1059'],
      hypothesis: 'Злоумышленники используют PowerShell для выполнения вредоносных команд',
      query: `
        process_name: "powershell.exe" AND (
          command_line: "*-enc*" OR
          command_line: "*-encodedcommand*" OR
          command_line: "*bypass*" OR
          command_line: "*hidden*" OR
          command_line: "*windowstyle hidden*"
        )
      `,
      queryLanguage: 'lucene',
      dataSource: 'endpoint_logs',
      parameters: [
        {
          name: 'timeRange',
          type: 'number',
          required: false,
          defaultValue: 24,
          description: 'Диапазон времени в часах'
        },
        {
          name: 'minSeverity',
          type: 'string',
          required: false,
          defaultValue: 'medium',
          description: 'Минимальная серьезность'
        }
      ],
      expectedResults: 'Список подозрительных PowerShell команд',
      falsePositiveGuidance: 'Проверьте легитимные скрипты администрирования',
      tags: ['powershell', 'execution', 'living-off-the-land'],
      author: 'Security Team',
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    // Query: Обнаружение горизонтального перемещения
    this.addQuery({
      id: 'HUNT-002',
      name: 'Горизонтальное Перемещение',
      description: 'Поиск признаков перемещения внутри сети',
      category: ThreatCategory.LATERAL_MOVEMENT,
      mitreTechniques: ['T1021', 'T1570'],
      hypothesis: 'Злоумышленник перемещается между системами в сети',
      query: `
        event_type: ("remote_login" OR "psexec" OR "wmic" OR "winrm") AND
        unique_destinations > 5
      `,
      queryLanguage: 'lucene',
      dataSource: 'network_logs',
      parameters: [
        {
          name: 'sourceIp',
          type: 'ip',
          required: false,
          description: 'IP адрес источника'
        },
        {
          name: 'timeRange',
          type: 'number',
          required: false,
          defaultValue: 24,
          description: 'Диапазон времени в часах'
        }
      ],
      expectedResults: 'Список хостов с аномальным количеством удаленных подключений',
      falsePositiveGuidance: 'Исключите системы администрирования',
      tags: ['lateral-movement', 'network'],
      author: 'Security Team',
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    // Query: Обнаружение эксфильтрации данных
    this.addQuery({
      id: 'HUNT-003',
      name: 'Эксфильтрация Данных',
      description: 'Поиск крупных исходящих передач данных',
      category: ThreatCategory.EXFILTRATION,
      mitreTechniques: ['T1041', 'T1048'],
      hypothesis: 'Происходит хищение данных из сети',
      query: `
        direction: "outbound" AND
        bytes_sent > 100000000 AND
        destination NOT IN (whitelist)
      `,
      queryLanguage: 'lucene',
      dataSource: 'network_logs',
      parameters: [
        {
          name: 'minBytes',
          type: 'number',
          required: false,
          defaultValue: 100000000,
          description: 'Минимальный размер в байтах'
        },
        {
          name: 'destinationIP',
          type: 'ip',
          required: false,
          description: 'Конкретный IP назначения'
        }
      ],
      expectedResults: 'Список крупных исходящих передач',
      falsePositiveGuidance: 'Проверьте легитимные бэкапы и синхронизации',
      tags: ['exfiltration', 'data-loss'],
      author: 'Security Team',
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    // Query: Обнаружение credential dumping
    this.addQuery({
      id: 'HUNT-004',
      name: 'Credential Dumping',
      description: 'Поиск попыток кражи учетных данных',
      category: ThreatCategory.CREDENTIAL_ACCESS,
      mitreTechniques: ['T1003'],
      hypothesis: 'Злоумышленник пытается получить учетные данные из LSASS',
      query: `
        (process_name: "procdump.exe" OR
         process_name: "mimikatz.exe" OR
         process_name: "lsass.exe") AND
        (command_line: "*lsass*" OR command_line: "*dump*")
      `,
      queryLanguage: 'lucene',
      dataSource: 'endpoint_logs',
      parameters: [
        {
          name: 'hostname',
          type: 'string',
          required: false,
          description: 'Имя хоста для поиска'
        }
      ],
      expectedResults: 'Процессы, связанные с credential dumping',
      falsePositiveGuidance: 'Проверьте легитимные инструменты отладки',
      tags: ['credentials', 'lsass', 'dumping'],
      author: 'Security Team',
      createdAt: new Date(),
      updatedAt: new Date()
    });
    
    // Query: Обнаружение persistence механизмов
    this.addQuery({
      id: 'HUNT-005',
      name: 'Persistence Механизмы',
      description: 'Поиск механизмов закрепления в системе',
      category: ThreatCategory.PERSISTENCE,
      mitreTechniques: ['T1547', 'T1053'],
      hypothesis: 'Злоумышленник настроил механизмы для сохранения доступа',
      query: `
        (registry_key: "*CurrentVersion\\Run*" OR
         scheduled_task_created OR
         service_created) AND
        user NOT IN (admins)
      `,
      queryLanguage: 'lucene',
      dataSource: 'endpoint_logs',
      parameters: [],
      expectedResults: 'Созданные механизмы persistence',
      falsePositiveGuidance: 'Сверьте с утвержденными изменениями',
      tags: ['persistence', 'registry', 'scheduled-tasks'],
      author: 'Security Team',
      createdAt: new Date(),
      updatedAt: new Date()
    });
  }

  /**
   * Инициализация playbooks
   */
  private initializePlaybooks(): void {
    // Playbook: Расследование фишинговой атаки
    this.addPlaybook({
      id: 'PLAYBOOK-001',
      name: 'Расследование Фишинга',
      description: 'Пошаговое руководство по расследованию фишинговой атаки',
      objective: 'Определить масштаб фишинговой атаки и выявить скомпрометированные учетные записи',
      scope: 'Все почтовые ящики и endpoint системы',
      prerequisites: [
        'Доступ к почтовым логам',
        'Доступ к endpoint логам',
        'Доступ к authentication логам'
      ],
      steps: [
        {
          order: 1,
          title: 'Идентификация фишингового письма',
          description: 'Найдите оригинальное фишинговое письмо и извлеките индикаторы',
          query: 'event_type: "email_received" AND subject: "*подозрительная тема*"',
          expectedOutcome: 'Список получателей фишингового письма',
          nextSteps: {
            ifPositive: 'Перейти к шагу 2',
            ifNegative: 'Завершить расследование'
          }
        },
        {
          order: 2,
          title: 'Поиск кликов по ссылкам',
          description: 'Определите, кто кликнул на ссылки в письме',
          query: 'event_type: "url_click" AND url: "*из письма*"',
          expectedOutcome: 'Список пользователей, кликнувших на ссылки',
          nextSteps: {
            ifPositive: 'Перейти к шагу 3',
            ifNegative: 'Перейти к шагу 4'
          }
        },
        {
          order: 3,
          title: 'Анализ активности пользователей',
          description: 'Проверьте аномальную активность пользователей после клика',
          query: 'user_id IN (список) AND event_type: ("login" OR "file_access")',
          expectedOutcome: 'Признаки компрометации учетных записей',
          nextSteps: {
            ifPositive: 'Эскалировать в Incident Response',
            ifNegative: 'Перейти к шагу 4'
          }
        },
        {
          order: 4,
          title: 'Блокировка индикаторов',
          description: 'Добавьте индикаторы в блокировочные списки',
          expectedOutcome: 'Индикаторы заблокированы',
          nextSteps: {
            ifPositive: 'Завершить расследование',
            ifNegative: 'Повторить попытку'
          }
        }
      ],
      estimatedDuration: 60,
      difficulty: 'intermediate',
      mitreTechniques: ['T1566'],
      tags: ['phishing', 'email', 'investigation']
    });
    
    // Playbook: Расследование ransomware
    this.addPlaybook({
      id: 'PLAYBOOK-002',
      name: 'Расследование Ransomware',
      description: 'Руководство по расследованию атаки ransomware',
      objective: 'Определить источник, масштаб и тип ransomware',
      scope: 'Все системы и сети',
      prerequisites: [
        'Доступ к endpoint логам',
        'Доступ к network логам',
        'Доступ к backup системам'
      ],
      steps: [
        {
          order: 1,
          title: 'Идентификация пациента zero',
          description: 'Найдите первую скомпрометированную систему',
          query: 'event_type: "file_encrypt" | sort timestamp ASC | head 1',
          expectedOutcome: 'Первая система с зашифрованными файлами',
          nextSteps: {
            ifPositive: 'Перейти к шагу 2',
            ifNegative: 'Расширить диапазон поиска'
          }
        },
        {
          order: 2,
          title: 'Анализ процесса шифрования',
          description: 'Идентифицируйте процесс, выполняющий шифрование',
          query: 'hostname: "patient-zero" AND process_name: "*"',
          expectedOutcome: 'Имя и хеш вредоносного процесса',
          nextSteps: {
            ifPositive: 'Перейти к шагу 3',
            ifNegative: 'Проверить логи антивируса'
          }
        },
        {
          order: 3,
          title: 'Поиск горизонтального перемещения',
          description: 'Определите, распространилась ли атака на другие системы',
          query: 'event_type: "file_encrypt" AND timestamp > patient-zero-time',
          expectedOutcome: 'Список затронутых систем',
          nextSteps: {
            ifPositive: 'Изолировать затронутые системы',
            ifNegative: 'Перейти к шагу 4'
          }
        },
        {
          order: 4,
          title: 'Проверка бэкапов',
          description: 'Убедитесь в целостности бэкапов',
          expectedOutcome: 'Статус бэкапов',
          nextSteps: {
            ifPositive: 'Начать восстановление',
            ifNegative: 'Искать альтернативные бэкапы'
          }
        }
      ],
      estimatedDuration: 120,
      difficulty: 'advanced',
      mitreTechniques: ['T1486'],
      tags: ['ransomware', 'encryption', 'incident-response']
    });
  }

  // ============================================================================
  // УПРАВЛЕНИЕ QUERIES
  // ============================================================================

  /**
   * Добавление hunting query
   */
  addQuery(query: HuntQuery): void {
    this.queries.set(query.id, query);
  }

  /**
   * Удаление query
   */
  removeQuery(queryId: string): void {
    this.queries.delete(queryId);
  }

  /**
   * Получение query по ID
   */
  getQuery(queryId: string): HuntQuery | undefined {
    return this.queries.get(queryId);
  }

  /**
   * Получение всех queries
   */
  getAllQueries(): HuntQuery[] {
    return Array.from(this.queries.values());
  }

  // ============================================================================
  // УПРАВЛЕНИЕ PLAYBOOKS
  // ============================================================================

  /**
   * Добавление playbook
   */
  addPlaybook(playbook: HuntPlaybook): void {
    this.playbooks.set(playbook.id, playbook);
  }

  /**
   * Удаление playbook
   */
  removePlaybook(playbookId: string): void {
    this.playbooks.delete(playbookId);
  }

  /**
   * Получение playbook по ID
   */
  getPlaybook(playbookId: string): HuntPlaybook | undefined {
    return this.playbooks.get(playbookId);
  }

  /**
   * Получение всех playbooks
   */
  getAllPlaybooks(): HuntPlaybook[] {
    return Array.from(this.playbooks.values());
  }

  // ============================================================================
  // ВЫПОЛНЕНИЕ HUNTING QUERIES
  // ============================================================================

  /**
   * Выполнение hunting query
   */
  async executeQuery(queryId: string, parameters?: Record<string, any>): Promise<HuntResult> {
    const query = this.queries.get(queryId);
    
    if (!query) {
      throw new Error(`Query ${queryId} не найден`);
    }
    
    const startTime = Date.now();
    
    // Применение параметров к query
    const finalQuery = this.applyParameters(query.query, parameters);
    
    // Выполнение query (в реальной реализации - запрос к dataSource)
    const rawResults = await this.executeDataSourceQuery(query.dataSource, finalQuery, query.queryLanguage);
    
    // Анализ результатов
    const findings = this.analyzeQueryResults(rawResults, query);
    
    const executionTime = Date.now() - startTime;
    
    const result: HuntResult = {
      queryId,
      executedAt: new Date(),
      executionTime,
      resultCount: rawResults.length,
      findings,
      statistics: {
        totalEvents: rawResults.length,
        uniqueEntities: new Set(rawResults.map((r: any) => r.entityId)).size,
        timeRange: {
          start: new Date(Date.now() - this.config.defaultTimeRange * 60 * 60 * 1000),
          end: new Date()
        },
        topFindings: findings.slice(0, 5).map(f => f.title),
        anomaliesDetected: findings.length
      },
      recommendations: this.generateRecommendations(findings, query),
    };
    
    // Сохранение в историю
    this.executionHistory.push(result);
    
    if (this.executionHistory.length > this.maxHistorySize) {
      this.executionHistory.shift();
    }
    
    // Обновление статистики
    this.statistics.anomaliesDetected += findings.length;
    
    return result;
  }

  /**
   * Применение параметров к query
   */
  private applyParameters(query: string, parameters?: Record<string, any>): string {
    if (!parameters) {
      return query;
    }
    
    let finalQuery = query;
    
    for (const [key, value] of Object.entries(parameters)) {
      finalQuery = finalQuery.replace(new RegExp(`\\*${key}\\*`, 'g'), String(value));
    }
    
    return finalQuery;
  }

  /**
   * Выполнение запроса к источнику данных
   */
  private async executeDataSourceQuery(
    dataSourceId: string,
    query: string,
    language: string
  ): Promise<any[]> {
    // В реальной реализации здесь был бы вызов к Elasticsearch, Splunk, etc.
    // Для демонстрации возвращаем mock данные
    
    console.log(`[ThreatHunting] Выполнение query к ${dataSourceId}: ${query}`);
    
    // Симуляция задержки
    await new Promise(resolve => setTimeout(resolve, 100));
    
    return [];
  }

  /**
   * Анализ результатов query
   */
  private analyzeQueryResults(results: any[], query: HuntQuery): HuntFinding[] {
    const findings: HuntFinding[] = [];
    
    // В реальной реализации здесь был бы анализ результатов
    // Для демонстрации создаем mock findings
    
    for (const result of results.slice(0, 10)) {
      findings.push({
        id: uuidv4(),
        severity: ThreatSeverity.MEDIUM,
        title: `Подозрительная активность: ${query.name}`,
        description: `Обнаружена активность, соответствующая гипотезе: ${query.hypothesis}`,
        evidence: result,
        mitreMappings: query.mitreTechniques.map(t => ({
          eventId: uuidv4(),
          techniqueId: t,
          tacticId: '',
          confidence: 0.8,
          evidence: []
        })),
        recommendedActions: [
          'Расследовать активность',
          'Собрать дополнительные артефакты',
          'Проверить на ложное срабатывание'
        ],
        falsePositiveProbability: 0.3
      });
    }
    
    return findings;
  }

  /**
   * Генерация рекомендаций
   */
  private generateRecommendations(findings: HuntFinding[], query: HuntQuery): string[] {
    const recommendations: string[] = [];
    
    if (findings.length > 0) {
      recommendations.push(`Обнаружено ${findings.length} потенциальных инцидентов`);
      recommendations.push('Рекомендуется провести глубокое расследование');
      recommendations.push(`Проверить MITRE техники: ${query.mitreTechniques.join(', ')}`);
    } else {
      recommendations.push('Индикаторов компрометации не обнаружено');
      recommendations.push('Продолжить мониторинг');
    }
    
    return recommendations;
  }

  // ============================================================================
  // ВЫПОЛНЕНИЕ PLAYBOOKS
  // ============================================================================

  /**
   * Выполнение playbook
   */
  async executePlaybook(playbookId: string, context?: Record<string, any>): Promise<PlaybookExecutionResult> {
    const playbook = this.playbooks.get(playbookId);
    
    if (!playbook) {
      throw new Error(`Playbook ${playbookId} не найден`);
    }
    
    const results: StepExecutionResult[] = [];
    
    for (const step of playbook.steps) {
      const stepResult = await this.executePlaybookStep(step, context);
      results.push(stepResult);
      
      // Определение следующего шага
      if (stepResult.findingsCount > 0) {
        if (step.nextSteps.ifPositive === 'Завершить расследование') {
          break;
        }
      } else {
        if (step.nextSteps.ifNegative === 'Завершить расследование') {
          break;
        }
      }
    }
    
    return {
      playbookId,
      executedAt: new Date(),
      stepsResults: results,
      completedSteps: results.filter(r => r.completed).length,
      totalSteps: playbook.steps.length,
      findingsCount: results.reduce((acc, r) => acc + r.findingsCount, 0)
    };
  }

  /**
   * Выполнение шага playbook
   */
  private async executePlaybookStep(step: HuntStep, context?: Record<string, any>): Promise<StepExecutionResult> {
    let findingsCount = 0;
    
    if (step.query) {
      // Применение контекста к query
      let query = step.query;
      
      if (context) {
        for (const [key, value] of Object.entries(context)) {
          query = query.replace(new RegExp(`\\${key}`, 'g'), String(value));
        }
      }
      
      // Выполнение query
      // В реальной реализации здесь был бы вызов к dataSource
      findingsCount = Math.floor(Math.random() * 5);  // Mock
    }
    
    return {
      stepId: step.title,
      completed: true,
      findingsCount,
      output: `Выполнено: ${step.description}`,
      nextAction: findingsCount > 0 ? step.nextSteps.ifPositive : step.nextSteps.ifNegative
    };
  }

  // ============================================================================
  // СТАТИСТИКА
  // ============================================================================

  /**
   * Получение статистики
   */
  getStatistics(): HuntStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }

  /**
   * Получение истории выполнений
   */
  getExecutionHistory(limit: number = 50): HuntResult[] {
    return this.executionHistory.slice(-limit);
  }

  /**
   * Получение топ queries по срабатываниям
   */
  getTopQueries(limit: number = 10): { queryId: string; queryName: string; findingsCount: number }[] {
    const queryStats: Map<string, { name: string; count: number }> = new Map();
    
    for (const result of this.executionHistory) {
      const query = this.queries.get(result.queryId);
      
      if (!queryStats.has(result.queryId)) {
        queryStats.set(result.queryId, {
          name: query?.name || 'Unknown',
          count: 0
        });
      }
      
      queryStats.get(result.queryId)!.count += result.findings.length;
    }
    
    return Array.from(queryStats.entries())
      .map(([id, data]) => ({
        queryId: id,
        queryName: data.name,
        findingsCount: data.count
      }))
      .sort((a, b) => b.findingsCount - a.findingsCount)
      .slice(0, limit);
  }

  /**
   * Добавление источника данных
   */
  addDataSource(dataSource: DataSource): void {
    this.dataSources.set(dataSource.id, dataSource);
  }

  /**
   * Получение источников данных
   */
  getDataSources(): DataSource[] {
    return Array.from(this.dataSources.values());
  }
}

/**
 * Результат выполнения шага playbook
 */
interface StepExecutionResult {
  stepId: string;
  completed: boolean;
  findingsCount: number;
  output: string;
  nextAction: string;
}

/**
 * Результат выполнения playbook
 */
interface PlaybookExecutionResult {
  playbookId: string;
  executedAt: Date;
  stepsResults: StepExecutionResult[];
  completedSteps: number;
  totalSteps: number;
  findingsCount: number;
}
