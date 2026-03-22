/**
 * ============================================================================
 * MITRE ATTACK MAPPER
 * Интеграция с фреймворком MITRE ATT&CK для маппинга техник и тактик
 * ============================================================================
 */

import {
  MitreTactic,
  MitreTechnique,
  MitreThreatGroup,
  MitreMapping,
  MitreAttackInfo,
  KillChainPhase,
  SecurityEvent,
  SecurityAlert,
  ThreatCategory,
  ThreatSeverity
} from '../types/threat.types';
import { v4 as uuidv4 } from 'uuid';

/**
 * ============================================================================
 * БАЗА ДАННЫХ MITRE ATT&CK
 * Основные тактики и техники MITRE ATT&CK
 * ============================================================================
 */

/**
 * Все тактики MITRE ATT&CK
 */
const MITRE_TACTICS: MitreTactic[] = [
  {
    id: 'TA0001',
    name: 'Initial Access',
    description: 'Противник пытается получить первоначальный доступ к системе или сети',
    url: 'https://attack.mitre.org/tactics/TA0001/'
  },
  {
    id: 'TA0002',
    name: 'Execution',
    description: 'Противник выполняет вредоносный код на системе',
    url: 'https://attack.mitre.org/tactics/TA0002/'
  },
  {
    id: 'TA0003',
    name: 'Persistence',
    description: 'Противник поддерживает доступ к системе после перезагрузки',
    url: 'https://attack.mitre.org/tactics/TA0003/'
  },
  {
    id: 'TA0004',
    name: 'Privilege Escalation',
    description: 'Противник получает более высокий уровень привилегий',
    url: 'https://attack.mitre.org/tactics/TA0004/'
  },
  {
    id: 'TA0005',
    name: 'Defense Evasion',
    description: 'Противник избегает обнаружения системами защиты',
    url: 'https://attack.mitre.org/tactics/TA0005/'
  },
  {
    id: 'TA0006',
    name: 'Credential Access',
    description: 'Противник крадет учетные данные (логины, пароли, хеши)',
    url: 'https://attack.mitre.org/tactics/TA0006/'
  },
  {
    id: 'TA0007',
    name: 'Discovery',
    description: 'Противник собирает информацию о системе и сети',
    url: 'https://attack.mitre.org/tactics/TA0007/'
  },
  {
    id: 'TA0008',
    name: 'Lateral Movement',
    description: 'Противник перемещается внутри сети к другим системам',
    url: 'https://attack.mitre.org/tactics/TA0008/'
  },
  {
    id: 'TA0009',
    name: 'Collection',
    description: 'Противник собирает данные для кражи',
    url: 'https://attack.mitre.org/tactics/TA0009/'
  },
  {
    id: 'TA0010',
    name: 'Command and Control',
    description: 'Противник управляет скомпрометированными системами',
    url: 'https://attack.mitre.org/tactics/TA0010/'
  },
  {
    id: 'TA0011',
    name: 'Exfiltration',
    description: 'Противник крадет данные из сети',
    url: 'https://attack.mitre.org/tactics/TA0011/'
  },
  {
    id: 'TA0040',
    name: 'Impact',
    description: 'Противник нарушает работу систем или уничтожает данные',
    url: 'https://attack.mitre.org/tactics/TA0040/'
  }
];

/**
 * Основные техники MITRE ATT&CK
 */
const MITRE_TECHNIQUES: MitreTechnique[] = [
  // Initial Access
  {
    id: 'T1566',
    name: 'Phishing',
    description: 'Противник отправляет фишинговые сообщения для получения доступа',
    url: 'https://attack.mitre.org/techniques/T1566/',
    tactics: ['TA0001'],
    platforms: ['Windows', 'macOS', 'Linux', 'Office 365', 'Google Workspace'],
    permissionsRequired: ['User'],
    dataSources: ['Email', 'Web proxy', 'Web server'],
    detection: 'Анализ email заголовков, URL репутация, обучение пользователей',
    mitigation: 'Email фильтрация, MFA, обучение пользователей'
  },
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    description: 'Эксплуатация уязвимостей в публичных приложениях',
    url: 'https://attack.mitre.org/techniques/T1190/',
    tactics: ['TA0001'],
    platforms: ['Windows', 'macOS', 'Linux', 'Containers'],
    permissionsRequired: ['User', 'Administrator'],
    dataSources: ['Application logs', 'Web server logs'],
    detection: 'Мониторинг уязвимостей, WAF, анализ логов',
    mitigation: 'Патч-менеджмент, WAF, минимизация поверхности атаки'
  },
  {
    id: 'T1078',
    name: 'Valid Accounts',
    description: 'Использование легитимных учетных записей для доступа',
    url: 'https://attack.mitre.org/techniques/T1078/',
    tactics: ['TA0001', 'TA0003', 'TA0004', 'TA0005'],
    platforms: ['Windows', 'macOS', 'Linux', 'Cloud'],
    permissionsRequired: ['User', 'Administrator'],
    dataSources: ['Authentication logs', 'Windows event logs'],
    detection: 'UEBA, анализ аномалий входа, мониторинг привилегий',
    mitigation: 'MFA, принцип наименьших привилегий'
  },
  
  // Execution
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    description: 'Выполнение команд через интерпретаторы (PowerShell, Bash, etc.)',
    url: 'https://attack.mitre.org/techniques/T1059/',
    tactics: ['TA0002'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User', 'Administrator'],
    dataSources: ['Process monitoring', 'Script logs', 'PowerShell logs'],
    detection: 'Мониторинг процессов, анализ командной строки, Script Block Logging',
    mitigation: 'AppLocker, WDAC, ограничение скриптов'
  },
  {
    id: 'T1204',
    name: 'User Execution',
    description: 'Злоупотребление действиями пользователя для выполнения кода',
    url: 'https://attack.mitre.org/techniques/T1204/',
    tactics: ['TA0002'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['Process monitoring', 'File monitoring'],
    detection: 'Мониторинг запуска приложений, анализ поведения',
    mitigation: 'Обучение пользователей, Application control'
  },
  
  // Persistence
  {
    id: 'T1547',
    name: 'Boot or Logon Autostart Execution',
    description: 'Настройка автозапуска вредоносного ПО',
    url: 'https://attack.mitre.org/techniques/T1547/',
    tactics: ['TA0003', 'TA0004'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User', 'Administrator', 'SYSTEM'],
    dataSources: ['Registry monitoring', 'File monitoring', 'Process monitoring'],
    detection: 'Мониторинг автозагрузки, анализ реестра',
    mitigation: 'AppLocker, мониторинг реестра'
  },
  {
    id: 'T1053',
    name: 'Scheduled Task/Job',
    description: 'Создание запланированных задач для выполнения кода',
    url: 'https://attack.mitre.org/techniques/T1053/',
    tactics: ['TA0002', 'TA0003', 'TA0004'],
    platforms: ['Windows', 'macOS', 'Linux', 'Cloud'],
    permissionsRequired: ['User', 'Administrator'],
    dataSources: ['Process monitoring', 'Scheduled task logs'],
    detection: 'Мониторинг создания задач, анализ расписаний',
    mitigation: 'Ограничение создания задач, мониторинг'
  },
  
  // Privilege Escalation
  {
    id: 'T1134',
    name: 'Access Token Manipulation',
    description: 'Манипуляция токенами доступа для повышения привилегий',
    url: 'https://attack.mitre.org/techniques/T1134/',
    tactics: ['TA0003', 'TA0004', 'TA0005'],
    platforms: ['Windows'],
    permissionsRequired: ['User', 'Administrator'],
    dataSources: ['Process monitoring', 'Windows event logs'],
    detection: 'Мониторинг токенов, анализ процессов',
    mitigation: 'Принцип наименьших привилегий, LAPS'
  },
  {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    description: 'Эксплуатация уязвимостей для повышения привилегий',
    url: 'https://attack.mitre.org/techniques/T1068/',
    tactics: ['TA0004'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['Process monitoring', 'Windows event logs'],
    detection: 'Мониторинг эксплойтов, анализ сбоев',
    mitigation: 'Патч-менеджмент, EDR'
  },
  
  // Defense Evasion
  {
    id: 'T1070',
    name: 'Indicator Removal',
    description: 'Удаление индикаторов компрометации (очистка логов)',
    url: 'https://attack.mitre.org/techniques/T1070/',
    tactics: ['TA0005'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User', 'Administrator'],
    dataSources: ['Log analysis', 'File monitoring'],
    detection: 'Мониторинг очистки логов, централизованное логирование',
    mitigation: 'Защита логов, SIEM'
  },
  {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    description: 'Сокрытие вредоносного кода через обфускацию',
    url: 'https://attack.mitre.org/techniques/T1027/',
    tactics: ['TA0005'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['File monitoring', 'Process monitoring'],
    detection: 'Анализ обфускации, песочницы',
    mitigation: 'Антивирус, песочницы'
  },
  
  // Credential Access
  {
    id: 'T1003',
    name: 'OS Credential Dumping',
    description: 'Кража учетных данных из операционной системы',
    url: 'https://attack.mitre.org/techniques/T1003/',
    tactics: ['TA0006'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['Administrator', 'SYSTEM'],
    dataSources: ['Process monitoring', 'Windows event logs'],
    detection: 'Мониторинг LSASS, анализ дампов памяти',
    mitigation: 'Credential Guard, LAPS'
  },
  {
    id: 'T1110',
    name: 'Brute Force',
    description: 'Подбор учетных данных методом перебора',
    url: 'https://attack.mitre.org/techniques/T1110/',
    tactics: ['TA0006'],
    platforms: ['Windows', 'macOS', 'Linux', 'Cloud'],
    permissionsRequired: ['User'],
    dataSources: ['Authentication logs', 'Windows event logs'],
    detection: 'Мониторинг неудачных входов, анализ паттернов',
    mitigation: 'MFA, блокировка учетных записей'
  },
  
  // Discovery
  {
    id: 'T1082',
    name: 'System Information Discovery',
    description: 'Сбор информации о системе',
    url: 'https://attack.mitre.org/techniques/T1082/',
    tactics: ['TA0007'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['Process monitoring', 'Command-line logs'],
    detection: 'Мониторинг команд разведки',
    mitigation: 'Ограничение информации'
  },
  {
    id: 'T1083',
    name: 'File and Directory Discovery',
    description: 'Обход файловой системы для поиска данных',
    url: 'https://attack.mitre.org/techniques/T1083/',
    tactics: ['TA0007'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['Process monitoring', 'File monitoring'],
    detection: 'Мониторинг доступа к файлам',
    mitigation: 'Контроль доступа'
  },
  
  // Lateral Movement
  {
    id: 'T1021',
    name: 'Remote Services',
    description: 'Использование легитимных сервисов для удаленного доступа',
    url: 'https://attack.mitre.org/techniques/T1021/',
    tactics: ['TA0008'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User', 'Administrator'],
    dataSources: ['Authentication logs', 'Network logs'],
    detection: 'Мониторинг удаленных подключений',
    mitigation: 'MFA, сегментация сети'
  },
  {
    id: 'T1570',
    name: 'Lateral Tool Transfer',
    description: 'Передача инструментов между системами',
    url: 'https://attack.mitre.org/techniques/T1570/',
    tactics: ['TA0008'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User', 'Administrator'],
    dataSources: ['Network logs', 'File monitoring'],
    detection: 'Мониторинг передачи файлов',
    mitigation: 'Сегментация сети, DLP'
  },
  
  // Collection
  {
    id: 'T1005',
    name: 'Data from Local System',
    description: 'Сбор данных с локальной системы',
    url: 'https://attack.mitre.org/techniques/T1005/',
    tactics: ['TA0009'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['File monitoring', 'Process monitoring'],
    detection: 'Мониторинг доступа к данным',
    mitigation: 'Шифрование, DLP'
  },
  {
    id: 'T1074',
    name: 'Data Staged',
    description: 'Подготовка данных к эксфильтрации',
    url: 'https://attack.mitre.org/techniques/T1074/',
    tactics: ['TA0009'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['File monitoring', 'Network logs'],
    detection: 'Мониторинг сжатия/архивации',
    mitigation: 'DLP, мониторинг'
  },
  
  // Command and Control
  {
    id: 'T1071',
    name: 'Application Layer Protocol',
    description: 'Использование легитимных протоколов для C2',
    url: 'https://attack.mitre.org/techniques/T1071/',
    tactics: ['TA0011'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['Network logs', 'Web proxy logs'],
    detection: 'Анализ сетевого трафика, TLS inspection',
    mitigation: 'Proxy, firewall rules'
  },
  {
    id: 'T1573',
    name: 'Encrypted Channel',
    description: 'Использование шифрования для скрытия C2 трафика',
    url: 'https://attack.mitre.org/techniques/T1573/',
    tactics: ['TA0011'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['Network logs', 'SSL/TLS inspection'],
    detection: 'Анализ TLS метаданных',
    mitigation: 'TLS inspection'
  },
  
  // Exfiltration
  {
    id: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    description: 'Кража данных через канал управления',
    url: 'https://attack.mitre.org/techniques/T1041/',
    tactics: ['TA0010'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['Network logs', 'Data loss prevention'],
    detection: 'Мониторинг исходящего трафика',
    mitigation: 'DLP, egress filtering'
  },
  {
    id: 'T1048',
    name: 'Exfiltration Over Alternative Protocol',
    description: 'Кража данных через альтернативные протоколы',
    url: 'https://attack.mitre.org/techniques/T1048/',
    tactics: ['TA0010'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User'],
    dataSources: ['Network logs', 'Email logs'],
    detection: 'Мониторинг исходящих подключений',
    mitigation: 'Egress filtering, DLP'
  },
  
  // Impact
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    description: 'Шифрование данных для нанесения ущерба (ransomware)',
    url: 'https://attack.mitre.org/techniques/T1486/',
    tactics: ['TA0040'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['User', 'Administrator'],
    dataSources: ['File monitoring', 'Process monitoring'],
    detection: 'Мониторинг массового шифрования',
    mitigation: 'Бэкапы, EDR'
  },
  {
    id: 'T1489',
    name: 'Service Stop',
    description: 'Остановка сервисов для нарушения работы',
    url: 'https://attack.mitre.org/techniques/T1489/',
    tactics: ['TA0040'],
    platforms: ['Windows', 'macOS', 'Linux'],
    permissionsRequired: ['Administrator'],
    dataSources: ['Process monitoring', 'Service logs'],
    detection: 'Мониторинг остановки сервисов',
    mitigation: 'Избыточность, мониторинг'
  }
];

/**
 * Известные группы угроз
 */
const MITRE_THREAT_GROUPS: MitreThreatGroup[] = [
  {
    id: 'G0016',
    name: 'APT29',
    aliases: ['Cozy Bear', 'The Dukes', 'CozyDuke'],
    description: 'Группа, связанная с российскими спецслужбами',
    url: 'https://attack.mitre.org/groups/G0016/',
    associatedTechniques: ['T1566', 'T1078', 'T1059', 'T1071'],
    targets: ['Government', 'Think tanks', 'Healthcare'],
    regions: ['North America', 'Europe']
  },
  {
    id: 'G0007',
    name: 'APT28',
    aliases: ['Fancy Bear', 'Sofacy', 'Pawn Storm'],
    description: 'Группа, связанная с российскими военными',
    url: 'https://attack.mitre.org/groups/G0007/',
    associatedTechniques: ['T1566', 'T1190', 'T1059', 'T1003'],
    targets: ['Government', 'Military', 'Defense contractors'],
    regions: ['North America', 'Europe', 'Middle East']
  },
  {
    id: 'G0032',
    name: 'APT41',
    aliases: ['Barium', 'Winnti', 'Double Dragon'],
    description: 'Китайская группа, занимающаяся шпионажем и финансовыми атаками',
    url: 'https://attack.mitre.org/groups/G0032/',
    associatedTechniques: ['T1190', 'T1059', 'T1068', 'T1486'],
    targets: ['Healthcare', 'Telecom', 'Gaming', 'Technology'],
    regions: ['Asia', 'North America', 'Europe']
  },
  {
    id: 'G0096',
    name: 'Lazarus Group',
    aliases: ['Hidden Cobra', 'Guardians of Peace', 'ZINC'],
    description: 'Северокорейская группа, известная финансовыми атаками',
    url: 'https://attack.mitre.org/groups/G0096/',
    associatedTechniques: ['T1566', 'T1204', 'T1059', 'T1486'],
    targets: ['Financial', 'Cryptocurrency', 'Media', 'Government'],
    regions: ['Asia', 'North America', 'Europe']
  }
];

/**
 * Маппинг Kill Chain фаз на тактики MITRE
 */
const KILL_CHAIN_MITRE_MAPPING: Record<KillChainPhase, string[]> = {
  [KillChainPhase.RECONNAISSANCE]: ['TA0007'],  // Discovery
  [KillChainPhase.WEAPONIZATION]: ['TA0002'],   // Execution
  [KillChainPhase.DELIVERY]: ['TA0001'],        // Initial Access
  [KillChainPhase.EXPLOITATION]: ['TA0001', 'TA0002'],
  [KillChainPhase.INSTALLATION]: ['TA0003'],    // Persistence
  [KillChainPhase.COMMAND_AND_CONTROL]: ['TA0011'],  // C2
  [KillChainPhase.ACTIONS_ON_OBJECTIVES]: ['TA0009', 'TA0010', 'TA0040']  // Collection, Exfil, Impact
};

/**
 * ============================================================================
 * MITRE ATTACK MAPPER CLASS
 * ============================================================================
 */
export class MITREAttackMapper {
  private tactics: Map<string, MitreTactic> = new Map();
  private techniques: Map<string, MitreTechnique> = new Map();
  private threatGroups: Map<string, MitreThreatGroup> = new Map();
  private eventMappings: Map<string, MitreMapping[]> = new Map();
  
  // Статистика
  private statistics: MitreStatistics = {
    totalMappings: 0,
    techniquesDetected: new Set<string>(),
    tacticsDetected: new Set<string>(),
    lastUpdated: new Date()
  };

  constructor() {
    this.initializeDatabase();
    console.log('[MITREAttackMapper] Инициализация завершена');
    console.log(`[MITREAttackMapper] Загружено тактик: ${this.tactics.size}`);
    console.log(`[MITREAttackMapper] Загружено техник: ${this.techniques.size}`);
    console.log(`[MITREAttackMapper] Загружено групп угроз: ${this.threatGroups.size}`);
  }

  /**
   * Инициализация базы данных MITRE ATT&CK
   */
  private initializeDatabase(): void {
    // Загрузка тактик
    for (const tactic of MITRE_TACTICS) {
      this.tactics.set(tactic.id, tactic);
    }
    
    // Загрузка техник
    for (const technique of MITRE_TECHNIQUES) {
      this.techniques.set(technique.id, technique);
    }
    
    // Загрузка групп угроз
    for (const group of MITRE_THREAT_GROUPS) {
      this.threatGroups.set(group.id, group);
    }
  }

  // ============================================================================
  // МАППИНГ СОБЫТИЙ НА MITRE ATT&CK
  // ============================================================================

  /**
   * Маппинг события безопасности на техники MITRE ATT&CK
   */
  mapEventToMitre(event: SecurityEvent): MitreMapping[] {
    const mappings: MitreMapping[] = [];
    
    // Маппинг по типу события
    const techniqueMappings = this.mapEventTypeToTechniques(event);
    
    for (const mapping of techniqueMappings) {
      const technique = this.techniques.get(mapping.techniqueId);
      
      if (technique) {
        mappings.push({
          eventId: event.id,
          techniqueId: mapping.techniqueId,
          tacticId: technique.tactics[0] || 'TA0001',
          confidence: mapping.confidence,
          evidence: mapping.evidence
        });
        
        // Обновление статистики
        this.statistics.techniquesDetected.add(mapping.techniqueId);
        this.statistics.tacticsDetected.add(technique.tactics[0]);
      }
    }
    
    // Сохранение маппинга
    this.eventMappings.set(event.id, mappings);
    this.statistics.totalMappings += mappings.length;
    this.statistics.lastUpdated = new Date();
    
    return mappings;
  }

  /**
   * Маппинг типа события на техники
   */
  private mapEventTypeToTechniques(event: SecurityEvent): Array<{
    techniqueId: string;
    confidence: number;
    evidence: string[];
  }> {
    const mappings: Array<{
      techniqueId: string;
      confidence: number;
      evidence: string[];
    }> = [];
    
    // Маппинг по имени события
    const eventType = event.eventType.toLowerCase();
    
    // PowerShell / Command execution
    if (eventType.includes('powershell') || eventType.includes('cmd') || eventType.includes('bash')) {
      mappings.push({
        techniqueId: 'T1059',
        confidence: 0.9,
        evidence: [`Выполнение команды: ${event.commandLine || event.processName}`]
      });
    }
    
    // Brute force / Failed logins
    if (eventType.includes('failed_login') || eventType.includes('brute')) {
      mappings.push({
        techniqueId: 'T1110',
        confidence: 0.95,
        evidence: [`Множественные неудачные входы для пользователя ${event.username}`]
      });
    }
    
    // Credential dumping
    if (eventType.includes('lsass') || eventType.includes('credential_dump') || eventType.includes('mimikatz')) {
      mappings.push({
        techniqueId: 'T1003',
        confidence: 0.95,
        evidence: ['Обнаружена попытка дампа учетных данных']
      });
    }
    
    // Scheduled tasks
    if (eventType.includes('scheduled_task') || eventType.includes('cron')) {
      mappings.push({
        techniqueId: 'T1053',
        confidence: 0.85,
        evidence: [`Создание запланированной задачи: ${event.processName}`]
      });
    }
    
    // Registry modifications (persistence)
    if (eventType.includes('registry') && (eventType.includes('run') || eventType.includes('startup'))) {
      mappings.push({
        techniqueId: 'T1547',
        confidence: 0.85,
        evidence: ['Модификация автозагрузки в реестре']
      });
    }
    
    // Remote services
    if (eventType.includes('rdp') || eventType.includes('ssh') || eventType.includes('psexec')) {
      mappings.push({
        techniqueId: 'T1021',
        confidence: 0.8,
        evidence: [`Удаленное подключение: ${event.sourceIp} -> ${event.destinationIp}`]
      });
    }
    
    // File encryption (ransomware)
    if (eventType.includes('encrypt') || eventType.includes('ransomware')) {
      mappings.push({
        techniqueId: 'T1486',
        confidence: 0.95,
        evidence: ['Обнаружено массовое шифрование файлов']
      });
    }
    
    // Data exfiltration
    if (eventType.includes('exfil') || eventType.includes('large_transfer')) {
      mappings.push({
        techniqueId: 'T1041',
        confidence: 0.75,
        evidence: [`Подозрительная передача данных: ${event.destinationIp}`]
      });
    }
    
    // Process injection
    if (eventType.includes('inject') || eventType.includes('hollow')) {
      mappings.push({
        techniqueId: 'T1055',
        confidence: 0.9,
        evidence: ['Обнаружена инъекция в процесс']
      });
    }
    
    // Discovery commands
    if (eventType.includes('whoami') || eventType.includes('net_user') || eventType.includes('systeminfo')) {
      mappings.push({
        techniqueId: 'T1082',
        confidence: 0.85,
        evidence: [`Команда разведки: ${event.commandLine}`]
      });
    }
    
    // Phishing
    if (eventType.includes('phishing') || eventType.includes('malicious_email')) {
      mappings.push({
        techniqueId: 'T1566',
        confidence: 0.9,
        evidence: ['Обнаружено фишинговое сообщение']
      });
    }
    
    // Exploitation
    if (eventType.includes('exploit') || eventType.includes('vulnerability')) {
      mappings.push({
        techniqueId: 'T1190',
        confidence: 0.85,
        evidence: [`Эксплуатация уязвимости: ${event.processName}`]
      });
    }
    
    // C2 communication
    if (eventType.includes('c2') || eventType.includes('beacon') || eventType.includes('callback')) {
      mappings.push({
        techniqueId: 'T1071',
        confidence: 0.8,
        evidence: [`C2 коммуникация с: ${event.destinationIp}`]
      });
    }
    
    // Privilege escalation
    if (eventType.includes('privilege') || eventType.includes('escalation') || eventType.includes('admin')) {
      mappings.push({
        techniqueId: 'T1068',
        confidence: 0.75,
        evidence: ['Попытка повышения привилегий']
      });
    }
    
    // Log clearing
    if (eventType.includes('log_clear') || eventType.includes('wevtutil')) {
      mappings.push({
        techniqueId: 'T1070',
        confidence: 0.95,
        evidence: ['Очистка логов событий']
      });
    }
    
    // File discovery
    if (eventType.includes('file_search') || eventType.includes('dir') || eventType.includes('find')) {
      mappings.push({
        techniqueId: 'T1083',
        confidence: 0.8,
        evidence: ['Поиск файлов в системе']
      });
    }
    
    return mappings;
  }

  /**
   * Маппинг алерта на MITRE ATT&CK
   */
  mapAlertToMitre(alert: SecurityAlert): MitreAttackInfo {
    const allMappings: MitreMapping[] = [];
    
    // Сбор маппингов из всех событий алерта
    for (const event of alert.events) {
      const mappings = this.eventMappings.get(event.id) || this.mapEventToMitre(event);
      allMappings.push(...mappings);
    }
    
    // Извлечение уникальных техник и тактик
    const techniqueIds = new Set(allMappings.map(m => m.techniqueId));
    const tacticIds = new Set(allMappings.map(m => m.tacticId));
    
    const techniques: MitreTechnique[] = [];
    const tactics: MitreTactic[] = [];
    
    for (const techId of techniqueIds) {
      const technique = this.techniques.get(techId);
      if (technique) {
        techniques.push(technique);
        
        // Добавление связанных тактик
        for (const tacticId of technique.tactics) {
          const tactic = this.tactics.get(tacticId);
          if (tactic && !tactics.find(t => t.id === tacticId)) {
            tactics.push(tactic);
          }
        }
      }
    }
    
    // Определение Kill Chain фазы
    const killChainPhase = this.determineKillChainPhase(tactics);
    
    // Поиск связанных групп угроз
    const threatGroups = this.findRelatedThreatGroups(techniques);
    
    return {
      tactics,
      techniques,
      killChainPhase,
      threatGroups
    };
  }

  /**
   * Определение Kill Chain фазы на основе тактик
   */
  private determineKillChainPhase(tactics: MitreTactic[]): KillChainPhase | undefined {
    const tacticIds = tactics.map(t => t.id);
    
    for (const [phase, tacticIdsForPhase] of Object.entries(KILL_CHAIN_MITRE_MAPPING)) {
      const hasMatch = tacticIds.some(id => tacticIdsForPhase.includes(id));
      if (hasMatch) {
        return phase as KillChainPhase;
      }
    }
    
    return undefined;
  }

  /**
   * Поиск связанных групп угроз
   */
  private findRelatedThreatGroups(techniques: MitreTechnique[]): MitreThreatGroup[] {
    const techniqueIds = techniques.map(t => t.id);
    const relatedGroups: MitreThreatGroup[] = [];
    
    for (const group of this.threatGroups.values()) {
      const commonTechniques = group.associatedTechniques.filter(t => techniqueIds.includes(t));
      
      if (commonTechniques.length >= 2) {  // Минимум 2 общих техники
        relatedGroups.push(group);
      }
    }
    
    return relatedGroups;
  }

  // ============================================================================
  // ПОИСК И АНАЛИЗ
  // ============================================================================

  /**
   * Получение техники по ID
   */
  getTechnique(techniqueId: string): MitreTechnique | undefined {
    return this.techniques.get(techniqueId);
  }

  /**
   * Получение тактики по ID
   */
  getTactic(tacticId: string): MitreTactic | undefined {
    return this.tactics.get(tacticId);
  }

  /**
   * Получение группы угроз по ID
   */
  getThreatGroup(groupId: string): MitreThreatGroup | undefined {
    return this.threatGroups.get(groupId);
  }

  /**
   * Поиск техник по тактике
   */
  getTechniquesByTactic(tacticId: string): MitreTechnique[] {
    return Array.from(this.techniques.values()).filter(
      t => t.tactics.includes(tacticId)
    );
  }

  /**
   * Поиск техник по платформе
   */
  getTechniquesByPlatform(platform: string): MitreTechnique[] {
    return Array.from(this.techniques.values()).filter(
      t => t.platforms.includes(platform)
    );
  }

  /**
   * Получение всех техник для категории угроз
   */
  getTechniquesByCategory(category: ThreatCategory): MitreTechnique[] {
    const tacticMapping: Record<ThreatCategory, string> = {
      [ThreatCategory.INITIAL_ACCESS]: 'TA0001',
      [ThreatCategory.EXECUTION]: 'TA0002',
      [ThreatCategory.PERSISTENCE]: 'TA0003',
      [ThreatCategory.PRIVILEGE_ESCALATION]: 'TA0004',
      [ThreatCategory.DEFENSE_EVASION]: 'TA0005',
      [ThreatCategory.CREDENTIAL_ACCESS]: 'TA0006',
      [ThreatCategory.DISCOVERY]: 'TA0007',
      [ThreatCategory.LATERAL_MOVEMENT]: 'TA0008',
      [ThreatCategory.COLLECTION]: 'TA0009',
      [ThreatCategory.COMMAND_AND_CONTROL]: 'TA0010',
      [ThreatCategory.EXFILTRATION]: 'TA0011',
      [ThreatCategory.IMPACT]: 'TA0040',
      [ThreatCategory.ANOMALY]: '',
      [ThreatCategory.UNKNOWN]: ''
    };
    
    const tacticId = tacticMapping[category];
    
    if (!tacticId) {
      return [];
    }
    
    return this.getTechniquesByTactic(tacticId);
  }

  /**
   * Получение подтехник для техники
   */
  getSubTechniques(techniqueId: string): MitreTechnique[] {
    const technique = this.techniques.get(techniqueId);
    return technique?.subTechniques || [];
  }

  /**
   * Анализ покрытия техник
   */
  getTechniqueCoverage(): TechniqueCoverage {
    const totalTechniques = this.techniques.size;
    const detectedTechniques = this.statistics.techniquesDetected.size;
    
    const coverageByTactic: Record<string, number> = {};
    
    for (const tactic of this.tactics.values()) {
      const tacticTechniques = this.getTechniquesByTactic(tactic.id);
      const detectedTacticTechniques = tacticTechniques.filter(t => 
        this.statistics.techniquesDetected.has(t.id)
      ).length;
      
      coverageByTactic[tactic.id] = detectedTacticTechniques / tacticTechniques.length;
    }
    
    return {
      totalTechniques,
      detectedTechniques,
      coveragePercent: (detectedTechniques / totalTechniques) * 100,
      coverageByTactic
    };
  }

  // ============================================================================
  // ГЕНЕРАЦИЯ ОТЧЕТОВ
  // ============================================================================

  /**
   * Генерация отчета по алерту
   */
  generateAlertReport(alert: SecurityAlert): MitreAlertReport {
    const mitreInfo = this.mapAlertToMitre(alert);
    
    return {
      alertId: alert.id,
      timestamp: new Date(),
      mitreAttack: mitreInfo,
      techniquesSummary: mitreInfo.techniques.map(t => ({
        id: t.id,
        name: t.name,
        tactic: t.tactics[0],
        severity: alert.severity,
        detection: t.detection,
        mitigation: t.mitigation
      })),
      killChainAnalysis: {
        currentPhase: mitreInfo.killChainPhase,
        phasesCompleted: this.getCompletedKillChainPhases(mitreInfo.tactics),
        progression: this.calculateKillChainProgression(mitreInfo.tactics)
      },
      threatActorAssessment: {
        possibleGroups: mitreInfo.threatGroups,
        confidence: mitreInfo.threatGroups.length > 0 ? 0.6 : 0.2
      },
      recommendations: this.generateRecommendations(mitreInfo)
    };
  }

  /**
   * Получение завершенных фаз Kill Chain
   */
  private getCompletedKillChainPhases(tactics: MitreTactic[]): KillChainPhase[] {
    const phases: KillChainPhase[] = [];
    const tacticIds = tactics.map(t => t.id);
    
    const phaseOrder: KillChainPhase[] = [
      KillChainPhase.RECONNAISSANCE,
      KillChainPhase.WEAPONIZATION,
      KillChainPhase.DELIVERY,
      KillChainPhase.EXPLOITATION,
      KillChainPhase.INSTALLATION,
      KillChainPhase.COMMAND_AND_CONTROL,
      KillChainPhase.ACTIONS_ON_OBJECTIVES
    ];
    
    for (const phase of phaseOrder) {
      const phaseTactics = KILL_CHAIN_MITRE_MAPPING[phase];
      const hasMatch = phaseTactics.some(t => tacticIds.includes(t));
      
      if (hasMatch) {
        phases.push(phase);
      }
    }
    
    return phases;
  }

  /**
   * Расчет прогрессии Kill Chain
   */
  private calculateKillChainProgression(tactics: MitreTactic[]): number {
    const phases = this.getCompletedKillChainPhases(tactics);
    return (phases.length / 7) * 100;  // 7 фаз в Kill Chain
  }

  /**
   * Генерация рекомендаций
   */
  private generateRecommendations(mitreInfo: MitreAttackInfo): string[] {
    const recommendations: string[] = [];
    
    // Рекомендации по техникам
    for (const technique of mitreInfo.techniques) {
      if (technique.mitigation) {
        recommendations.push(`[${technique.id}] ${technique.mitigation}`);
      }
    }
    
    // Рекомендации по тактикам
    for (const tactic of mitreInfo.tactics) {
      recommendations.push(`Блокировать тактику: ${tactic.name}`);
    }
    
    // Рекомендации по группам угроз
    if (mitreInfo.threatGroups.length > 0) {
      const groupNames = mitreInfo.threatGroups.map(g => g.name).join(', ');
      recommendations.push(`Возможный противник: ${groupNames}. Изучить их TTPs.`);
    }
    
    return recommendations;
  }

  // ============================================================================
  // СТАТИСТИКА
  // ============================================================================

  /**
   * Получение статистики
   */
  getStatistics(): MitreStatistics {
    return {
      ...this.statistics,
      lastUpdated: new Date()
    };
  }

  /**
   * Сброс статистики
   */
  resetStatistics(): void {
    this.statistics = {
      totalMappings: 0,
      techniquesDetected: new Set<string>(),
      tacticsDetected: new Set<string>(),
      lastUpdated: new Date()
    };
  }

  /**
   * Получение всех тактик
   */
  getAllTactics(): MitreTactic[] {
    return Array.from(this.tactics.values());
  }

  /**
   * Получение всех техник
   */
  getAllTechniques(): MitreTechnique[] {
    return Array.from(this.techniques.values());
  }

  /**
   * Получение всех групп угроз
   */
  getAllThreatGroups(): MitreThreatGroup[] {
    return Array.from(this.threatGroups.values());
  }
}

/**
 * Покрытие техник
 */
interface TechniqueCoverage {
  totalTechniques: number;
  detectedTechniques: number;
  coveragePercent: number;
  coverageByTactic: Record<string, number>;
}

/**
 * Отчет по алерту MITRE
 */
interface MitreAlertReport {
  alertId: string;
  timestamp: Date;
  mitreAttack: MitreAttackInfo;
  techniquesSummary: Array<{
    id: string;
    name: string;
    tactic: string;
    severity: ThreatSeverity;
    detection: string;
    mitigation: string;
  }>;
  killChainAnalysis: {
    currentPhase: KillChainPhase | undefined;
    phasesCompleted: KillChainPhase[];
    progression: number;
  };
  threatActorAssessment: {
    possibleGroups: MitreThreatGroup[];
    confidence: number;
  };
  recommendations: string[];
}

/**
 * Статистика MITRE
 */
interface MitreStatistics {
  totalMappings: number;
  techniquesDetected: Set<string>;
  tacticsDetected: Set<string>;
  lastUpdated: Date;
}

/**
 * Экспорт основного класса
 */
export { MITREAttackMapper };
