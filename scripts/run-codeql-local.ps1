# ========================================
# PowerShell Script: Local CodeQL Runner
# Protocol Security Project
# ========================================
# Скрипт для локального запуска CodeQL CLI
# Использование: .\scripts\run-codeql-local.ps1 [-Action init|create|analyze|query|report|full] [-Language typescript]

[CmdletBinding()]
param(
    # Действие: init, create, analyze, query, report, full, clean
    [Parameter(Mandatory = $false)]
    [ValidateSet('init', 'create', 'analyze', 'query', 'report', 'full', 'clean')]
    [string]$Action = 'full',
    
    # Язык анализа
    [Parameter(Mandatory = $false)]
    [ValidateSet('typescript', 'javascript')]
    [string]$Language = 'typescript',
    
    # Путь к CodeQL CLI
    [Parameter(Mandatory = $false)]
    [string]$CodeQLPath = $null,
    
    # Путь к базе данных CodeQL
    [Parameter(Mandatory = $false)]
    [string]$DatabasePath = $null,
    
    # Путь к результатам анализа
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = $null,
    
    # Query suite для анализа
    [Parameter(Mandatory = $false)]
    [string]$QuerySuite = 'security-extended',
    
    # Включить verbose логирование
    [Parameter(Mandatory = $false)]
    [switch]$Verbose,
    
    # Количество потоков
    [Parameter(Mandatory = $false)]
    [int]$Threads = 0,
    
    # Путь к проекту
    [Parameter(Mandatory = $false)]
    [string]$ProjectPath = $null
)

# ========================================
# Configuration
# ========================================
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Пути
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

if (!$ProjectPath) {
    $ProjectPath = $RootDir
}

$CodeQLDir = Join-Path $RootDir '.codeql'
$LogsDir = Join-Path $RootDir 'logs'
$ReportsDir = Join-Path $RootDir 'reports'

if (!$DatabasePath) {
    $DatabasePath = Join-Path $CodeQLDir 'db'
}

if (!$OutputPath) {
    $OutputPath = Join-Path $ReportsDir 'codeql'
}

$CodeQLHome = $env:CODEQL_HOME ?? (Join-Path $env:LOCALAPPDATA 'codeql')

# Настройки проекта
$ProjectName = 'Protocol Security'
$ProjectKey = 'protocol-security'

# ========================================
# Helper Functions
# ========================================

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor White
    Write-Host "========================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Info {
    param([string]$Text)
    Write-Host "[INFO] $Text" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Text)
    Write-Host "[WARN] $Text" -ForegroundColor Yellow
}

function Write-Error-Custom {
    param([string]$Text)
    Write-Host "[ERROR] $Text" -ForegroundColor Red
}

function Write-Step {
    param([string]$Text)
    Write-Host "  → $Text" -ForegroundColor Gray
}

function Test-Command {
    param([string]$Command)
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-CodeQL {
    if ($CodeQLPath -and (Test-Path $CodeQLPath)) {
        return $true
    }
    
    # Проверяем CODEQL_HOME
    if ($env:CODEQL_HOME -and (Test-Path (Join-Path $env:CODEQL_HOME 'codeql.exe'))) {
        $script:CodeQLPath = Join-Path $env:CODEQL_HOME 'codeql.exe'
        return $true
    }
    
    # Проверяем PATH
    if (Test-Command 'codeql') {
        $script:CodeQLPath = (Get-Command 'codeql').Source
        return $true
    }
    
    return $false
}

function Install-CodeQL {
    Write-Header "Установка CodeQL CLI"
    
    $CodeQLHome = Join-Path $env:LOCALAPPDATA 'codeql'
    $CodeQLExe = Join-Path $CodeQLHome 'codeql.exe'
    
    if (Test-Path $CodeQLExe) {
        Write-Info "CodeQL CLI уже установлен: $CodeQLExe"
        $script:CodeQLPath = $CodeQLExe
        return $true
    }
    
    Write-Info "Загрузка CodeQL CLI..."
    
    # Создаем директорию
    if (!(Test-Path $CodeQLHome)) {
        New-Item -ItemType Directory -Path $CodeQLHome -Force | Out-Null
    }
    
    # URL для последней версии
    $ReleasesUrl = "https://api.github.com/repos/github/codeql-action/releases/latest"
    
    try {
        Write-Step "Получение последней версии CodeQL..."
        $Release = Invoke-RestMethod -Uri $ReleasesUrl -UseBasicParsing
        $Version = $Release.tag_name -replace '^v', ''
        
        # URL для Windows x64
        $DownloadUrl = "https://github.com/github/codeql-action/releases/download/v$Version/codeql-bundle-win64.zip"
        $ZipPath = Join-Path $CodeQLHome 'codeql-bundle.zip'
        
        Write-Step "Скачивание CodeQL CLI v$Version..."
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
        
        Write-Step "Распаковка..."
        Expand-Archive -Path $ZipPath -DestinationPath $CodeQLHome -Force
        
        Remove-Item -Path $ZipPath -Force
        
        # Добавляем в PATH (для текущей сессии)
        $env:PATH = "$CodeQLHome\codeql\bin;$env:PATH"
        $env:CODEQL_HOME = $CodeQLHome
        
        $script:CodeQLPath = Join-Path $CodeQLHome 'codeql\bin\codeql.exe'
        
        Write-Info "CodeQL CLI установлен успешно"
        Write-Info "Путь: $($script:CodeQLPath)"
        
        return $true
    }
    catch {
        Write-Error-Custom "Ошибка установки CodeQL: $_"
        Write-Warn "Установите CodeQL CLI вручную: https://github.com/github/codeql-action/releases"
        return $false
    }
}

function Initialize-CodeQL {
    Write-Header "Инициализация CodeQL"
    
    if (!(Test-CodeQL)) {
        Write-Warn "CodeQL CLI не найден. Попытка установки..."
        if (!(Install-CodeQL)) {
            return $false
        }
    }
    
    Write-Step "Версия CodeQL:"
    & $CodeQLPath version
    
    # Создаем директории
    $Dirs = @($CodeQLDir, $DatabasePath, $OutputPath, $LogsDir, $ReportsDir)
    $Dirs | ForEach-Object {
        if (!(Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Step "Создана директория: $_"
        }
    }
    
    Write-Info "Инициализация завершена"
    return $true
}

function Build-Project {
    Write-Step "Сборка проекта для CodeQL..."
    
    Set-Location $ProjectPath
    
    # Установка зависимостей
    if (Test-Path 'package-lock.json') {
        npm ci --ignore-scripts
    }
    else {
        npm install --ignore-scripts
    }
    
    # Сборка TypeScript
    npm run build
    
    Write-Info "Проект собран"
}

function Create-Database {
    Write-Header "Создание CodeQL базы данных"
    
    if (!(Test-CodeQL)) {
        Write-Error-Custom "CodeQL CLI не найден"
        return $false
    }
    
    # Очищаем старую базу
    if (Test-Path $DatabasePath) {
        Write-Step "Удаление старой базы данных..."
        Remove-Item -Path $DatabasePath -Recurse -Force
    }
    
    Write-Step "Язык: $Language"
    Write-Step "Путь к базе: $DatabasePath"
    
    # Аргументы для codeql database create
    $CreateArgs = @(
        'database', 'create',
        $DatabasePath,
        '--language', $Language,
        '--source-root', $ProjectPath,
        '--threads', $Threads,
        '--verbose'
    )
    
    # Для TypeScript нужен build
    if ($Language -eq 'typescript') {
        Write-Step "Сборка проекта перед созданием базы..."
        Build-Project
        
        # Добавляем команду сборки
        $BuildCommand = "npm run build"
        $CreateArgs += '--command', $BuildCommand
    }
    
    Write-Step "Создание базы данных..."
    
    try {
        $CreateArgs += '--' '2>&1' | Out-String
        & $CodeQLPath $CreateArgs
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error-Custom "Ошибка создания базы данных"
            return $false
        }
        
        Write-Info "База данных создана успешно"
        
        # Информация о базе
        $DbInfo = Get-ChildItem -Path $DatabasePath
        Write-Step "Размер базы: $(($DbInfo | Measure-Object -Property Length -Sum).Sum / 1MB) MB"
        
        return $true
    }
    catch {
        Write-Error-Custom "Ошибка: $_"
        return $false
    }
}

function Run-Analysis {
    Write-Header "Запуск CodeQL анализа"
    
    if (!(Test-Path $DatabasePath)) {
        Write-Error-Custom "База данных не найдена: $DatabasePath"
        Write-Warn "Запустите сначала создание базы (Action: create)"
        return $false
    }
    
    # Создаем output директорию
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $SarifOutput = Join-Path $OutputPath 'results.sarif'
    $BqrsOutput = Join-Path $OutputPath 'results.bqrs'
    
    Write-Step "Query Suite: $QuerySuite"
    Write-Step "SARIF Output: $SarifOutput"
    Write-Step "BQRS Output: $BqrsOutput"
    
    # Аргументы для codeql database analyze
    $AnalyzeArgs = @(
        'database', 'analyze',
        $DatabasePath,
        '--format=sarif-latest',
        '--output', $SarifOutput,
        '--threads', $Threads,
        '--verbose'
    )
    
    # Добавляем query suite
    $AnalyzeArgs += $QuerySuite
    
    Write-Step "Запуск анализа..."
    
    try {
        & $CodeQLPath $AnalyzeArgs
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error-Custom "Ошибка анализа"
            return $false
        }
        
        Write-Info "Анализ завершен"
        
        # Создаем BQRS для интерактивного просмотра
        Write-Step "Создание BQRS файла для интерактивного просмотра..."
        
        $QueryArgs = @(
            'database', 'run-queries',
            $DatabasePath,
            '--additional-packs', (Join-Path $env:CODEQL_HOME 'codeql\qlpacks'),
            '--threads', $Threads
        )
        
        # Можно добавить кастомные queries
        $CustomQueriesPath = Join-Path $PSScriptRoot '..\.github\codeql\queries'
        if (Test-Path $CustomQueriesPath) {
            $QueryArgs += '--search-path', $CustomQueriesPath
        }
        
        Write-Info "Результаты сохранены в: $SarifOutput"
        
        return $true
    }
    catch {
        Write-Error-Custom "Ошибка: $_"
        return $false
    }
}

function Run-Query {
    param(
        [string]$QueryPath,
        [string]$ResultFormat = 'sarif'
    )
    
    Write-Header "Запуск CodeQL query"
    
    if (!$QueryPath) {
        # Запуск стандартных security queries
        Write-Step "Запуск стандартных security queries..."
        Run-Analysis
        return
    }
    
    if (!(Test-Path $QueryPath)) {
        Write-Error-Custom "Query файл не найден: $QueryPath"
        return $false
    }
    
    $ResultPath = Join-Path $OutputPath "query-result.$ResultFormat"
    
    Write-Step "Query: $QueryPath"
    Write-Step "Результат: $ResultPath"
    
    $QueryArgs = @(
        'query', 'run',
        $QueryPath,
        '--database', $DatabasePath,
        '--output', $ResultPath,
        '--threads', $Threads
    )
    
    try {
        & $CodeQLPath $QueryArgs
        
        if ($LASTEXITCODE -ne 0) {
            Write-Error-Custom "Ошибка выполнения query"
            return $false
        }
        
        Write-Info "Query выполнен успешно"
        return $true
    }
    catch {
        Write-Error-Custom "Ошибка: $_"
        return $false
    }
}

function Generate-Report {
    Write-Header "Генерация отчета"
    
    $SarifFile = Join-Path $OutputPath 'results.sarif'
    
    if (!(Test-Path $SarifFile)) {
        Write-Error-Custom "SARIF файл не найден: $SarifFile"
        Write-Warn "Запустите сначала анализ (Action: analyze)"
        return $false
    }
    
    # Создаем HTML отчет
    $HtmlReport = Join-Path $ReportsDir 'codeql-report.html'
    $JsonReport = Join-Path $ReportsDir 'codeql-report.json'
    $MarkdownReport = Join-Path $ReportsDir 'codeql-report.md'
    
    Write-Step "Генерация отчетов..."
    
    # Читаем SARIF
    $SarifContent = Get-Content -Path $SarifFile -Raw | ConvertFrom-Json
    
    # Подсчет уязвимостей
    $ErrorCount = 0
    $WarningCount = 0
    $NoteCount = 0
    
    if ($SarifContent.runs) {
        foreach ($run in $SarifContent.runs) {
            if ($run.results) {
                foreach ($result in $run.results) {
                    switch ($result.level) {
                        'error' { $ErrorCount++ }
                        'warning' { $WarningCount++ }
                        'note' { $NoteCount++ }
                    }
                }
            }
        }
    }
    
    # JSON отчет
    $Report = @{
        project = $ProjectName
        projectKey = $ProjectKey
        timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'
        language = $Language
        querySuite = $QuerySuite
        results = @{
            errors = $ErrorCount
            warnings = $WarningCount
            notes = $NoteCount
            total = $ErrorCount + $WarningCount + $NoteCount
        }
        sarifFile = $SarifFile
    }
    
    $Report | ConvertTo-Json -Depth 10 | Set-Content -Path $JsonReport -Encoding UTF8
    Write-Step "JSON отчет: $JsonReport"
    
    # Markdown отчет
    $MdContent = @"
# CodeQL Security Analysis Report

## Project Information
- **Project:** $ProjectName
- **Project Key:** $ProjectKey
- **Language:** $Language
- **Query Suite:** $QuerySuite
- **Generated:** $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Error | $ErrorCount |
| 🟡 Warning | $WarningCount |
| 🔵 Note | $NoteCount |
| **Total** | **$($ErrorCount + $WarningCount + $NoteCount)** |

## Security Categories

### OWASP Top 10
$(if ($ErrorCount -gt 0) { "- ⚠️ Обнаружены уязвимости OWASP Top 10" } else { "- ✅ Уязвимостей OWASP Top 10 не обнаружено" })

### CWE
$(if ($ErrorCount -gt 0) { "- ⚠️ Обнаружены CWE уязвимости" } else { "- ✅ CWE уязвимостей не обнаружено" })

## Recommendations

"@
    
    if ($ErrorCount -gt 0) {
        $MdContent += @"
1. 🔴 **Критично:** Немедленно исправьте все ошибки уровня Error
2. 📋 Проверьте Security tab в GitHub для деталей
3. 🔍 Используйте CodeQL CLI для локального анализа
4. 📚 Изучите документацию по исправлению уязвимостей

"@
    }
    else {
        $MdContent += @"
✅ **Отлично!** Критических уязвимостей не обнаружено.

Продолжайте мониторить код на предмет новых уязвимостей.

"@
    }
    
    $MdContent += @"

## Files

- SARIF: `$reports/codeql/results.sarif`
- JSON: `$reports/codeql-report.json`
- Markdown: `$reports/codeql-report.md`

---
*Generated by CodeQL Local Runner*
"@
    
    $MdContent | Set-Content -Path $MarkdownReport -Encoding UTF8
    Write-Step "Markdown отчет: $MarkdownReport"
    
    # HTML отчет
    $HtmlContent = @"
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeQL Security Report - $ProjectName</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007acc; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .card { padding: 20px; border-radius: 8px; text-align: center; }
        .card.error { background: #ffebee; border-left: 4px solid #f44336; }
        .card.warning { background: #fff3e0; border-left: 4px solid #ff9800; }
        .card.note { background: #e3f2fd; border-left: 4px solid #2196f3; }
        .card.total { background: #e8f5e9; border-left: 4px solid #4caf50; }
        .card h3 { margin: 0; font-size: 2.5em; }
        .card p { margin: 5px 0 0; color: #666; }
        .info-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .info-table th, .info-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .info-table th { background: #f5f5f5; font-weight: 600; }
        .status-pass { color: #4caf50; font-weight: bold; }
        .status-fail { color: #f44336; font-weight: bold; }
        .recommendations { background: #fff9c4; padding: 20px; border-radius: 8px; margin: 20px 0; }
        footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #888; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 CodeQL Security Analysis Report</h1>
        
        <table class="info-table">
            <tr><th>Project</th><td>$ProjectName</td></tr>
            <tr><th>Project Key</th><td>$ProjectKey</td></tr>
            <tr><th>Language</th><td>$Language</td></tr>
            <tr><th>Query Suite</th><td>$QuerySuite</td></tr>
            <tr><th>Generated</th><td>$(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')</td></tr>
        </table>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="card error">
                <h3>$ErrorCount</h3>
                <p>🔴 Errors</p>
            </div>
            <div class="card warning">
                <h3>$WarningCount</h3>
                <p>🟡 Warnings</p>
            </div>
            <div class="card note">
                <h3>$NoteCount</h3>
                <p>🔵 Notes</p>
            </div>
            <div class="card total">
                <h3>$($ErrorCount + $WarningCount + $NoteCount)</h3>
                <p>Total</p>
            </div>
        </div>
        
        <h2>Security Status</h2>
        <p>
            $(if ($ErrorCount -gt 0) { 
                '<span class="status-fail">❌ Security Gate FAILED</span> - Обнаружены критические уязвимости'
            } else { 
                '<span class="status-pass">✅ Security Gate PASSED</span> - Критических уязвимостей не обнаружено'
            })
        </p>
        
        <div class="recommendations">
            <h2>Recommendations</h2>
            $(if ($ErrorCount -gt 0) {
                '<ol>
                    <li>Немедленно исправьте все ошибки уровня <strong>Error</strong></li>
                    <li>Проверьте Security tab в GitHub для деталей</li>
                    <li>Используйте CodeQL CLI для локального анализа</li>
                    <li>Изучите документацию по исправлению уязвимостей</li>
                </ol>'
            } else {
                '<p>✅ <strong>Отлично!</strong> Критических уязвимостей не обнаружено. Продолжайте мониторить код.</p>'
            })
        </div>
        
        <footer>
            <p>Generated by CodeQL Local Runner | Protocol Security Project</p>
        </footer>
    </div>
</body>
</html>
"@
    
    $HtmlContent | Set-Content -Path $HtmlReport -Encoding UTF8
    Write-Step "HTML отчет: $HtmlReport"
    
    # Вывод сводки
    Write-Header "Отчет готов"
    Write-Host ""
    Write-Host "  🔴 Errors:    $ErrorCount" -ForegroundColor Red
    Write-Host "  🟡 Warnings:  $WarningCount" -ForegroundColor Yellow
    Write-Host "  🔵 Notes:     $NoteCount" -ForegroundColor Cyan
    Write-Host "  ─────────────────────"
    Write-Host "  Total:        $($ErrorCount + $WarningCount + $NoteCount)" -ForegroundColor White
    Write-Host ""
    
    if ($ErrorCount -gt 0) {
        Write-Host "  ❌ Security Gate FAILED" -ForegroundColor Red
    }
    else {
        Write-Host "  ✅ Security Gate PASSED" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Info "Отчеты сохранены в: $ReportsDir"
    
    return $true
}

function Full-Analysis {
    Write-Header "Полный цикл CodeQL анализа"
    
    # Шаг 1: Инициализация
    if (!(Initialize-CodeQL)) {
        return $false
    }
    
    # Шаг 2: Создание базы данных
    if (!(Create-Database)) {
        return $false
    }
    
    # Шаг 3: Запуск анализа
    if (!(Run-Analysis)) {
        return $false
    }
    
    # Шаг 4: Генерация отчета
    if (!(Generate-Report)) {
        return $false
    }
    
    Write-Header "Анализ завершен"
    Write-Info "Отчеты: $ReportsDir"
    Write-Info "HTML отчет: $(Join-Path $ReportsDir 'codeql-report.html')"
    
    return $true
}

function Clean-CodeQL {
    Write-Header "Очистка CodeQL"
    
    Write-Step "Удаление базы данных..."
    if (Test-Path $DatabasePath) {
        Remove-Item -Path $DatabasePath -Recurse -Force
        Write-Info "База данных удалена"
    }
    
    Write-Step "Удаление результатов..."
    if (Test-Path $OutputPath) {
        Remove-Item -Path $OutputPath -Recurse -Force
        Write-Info "Результаты удалены"
    }
    
    Write-Step "Удаление отчетов..."
    if (Test-Path $ReportsDir) {
        Remove-Item -Path $ReportsDir -Recurse -Force
        Write-Info "Отчеты удалены"
    }
    
    Write-Info "Очистка завершена"
}

# ========================================
# Main
# ========================================

Write-Header "CodeQL Local Runner - Protocol Security"

try {
    switch ($Action) {
        'init' {
            Initialize-CodeQL
        }
        'create' {
            Initialize-CodeQL
            Create-Database
        }
        'analyze' {
            Run-Analysis
        }
        'query' {
            Run-Query
        }
        'report' {
            Generate-Report
        }
        'full' {
            Full-Analysis
        }
        'clean' {
            Clean-CodeQL
        }
    }
}
catch {
    Write-Error-Custom "Произошла ошибка: $_"
    exit 1
}

Write-Host ""
Write-Host "Готово!" -ForegroundColor Green
