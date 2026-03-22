# PowerShell Script
# Массовое обновление зависимостей с проверками
# Использование: .\scripts\batch-update-deps.ps1 [-Mode Safe|All] [-RunTests]

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Safe', 'All')]
    [string]$Mode = 'Safe',
    
    [Parameter(Mandatory=$false)]
    [switch]$RunTests,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup,
    
    [Parameter(Mandatory=$false)]
    [string]$ReportPath = '.\dependency-update-report.md'
)

# =============================================================================
# КОНФИГУРАЦИЯ
# =============================================================================

$ErrorActionPreference = 'Stop'
$StartTime = Get-Date
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$BackupDir = Join-Path $ProjectRoot '.backups'
$PackageJson = Join-Path $ProjectRoot 'package.json'
$PackageLockJson = Join-Path $ProjectRoot 'package-lock.json'

# Цвета для вывода
$ColorSuccess = 'Green'
$ColorWarning = 'Yellow'
$ColorError = 'Red'
$ColorInfo = 'Cyan'

# =============================================================================
# ФУНКЦИИ
# =============================================================================

function Write-Header {
    param([string]$Text)
    Write-Host "`n$('=' * 60)" -ForegroundColor $ColorInfo
    Write-Host $Text -ForegroundColor $ColorInfo
    Write-Host $('=' * 60) -ForegroundColor $ColorInfo
}

function Write-Success {
    param([string]$Text)
    Write-Host "✓ $Text" -ForegroundColor $ColorSuccess
}

function Write-Warning {
    param([string]$Text)
    Write-Host "⚠ $Text" -ForegroundColor $ColorWarning
}

function Write-Error-Custom {
    param([string]$Text)
    Write-Host "✗ $Text" -ForegroundColor $ColorError
}

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Create-Backup {
    if (-not $CreateBackup) {
        return
    }
    
    Write-Header "Создание резервной копии"
    
    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir | Out-Null
        Write-Success "Создана директория для бэкапов: $BackupDir"
    }
    
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupPackage = Join-Path $BackupDir "package-$timestamp.json"
    $backupLock = Join-Path $BackupDir "package-lock-$timestamp.json"
    
    Copy-Item $PackageJson $backupPackage
    Copy-Item $PackageLockJson $backupLock -ErrorAction SilentlyContinue
    
    Write-Success "Резервная копия создана: $backupPackage"
}

function Get-DependencyInfo {
    param([string]$Name)
    
    $info = npm view $name --json | ConvertFrom-Json
    
    return @{
        Name = $info.name
        Latest = $info.'dist-tags'.latest
        Version = $info.version
        Time = $info.time.latest
        License = $info.license
    }
}

function Test-BreakingChanges {
    param(
        [string]$PackageName,
        [string]$CurrentVersion,
        [string]$NewVersion
    )
    
    Write-Host "  Проверка breaking changes для $PackageName..." -ForegroundColor Gray
    
    # Парсинг версий
    $currentMajor = [int]($CurrentVersion -replace '[^\d\.]', '').Split('.')[0]
    $newMajor = [int]($NewVersion -replace '[^\d\.]', '').Split('.')[0]
    
    # Major version change = potential breaking changes
    if ($newMajor -gt $currentMajor) {
        Write-Warning "  MAJOR version change: $CurrentVersion -> $NewVersion"
        
        # Попытка получить CHANGELOG
        try {
            $changelogUrl = "https://github.com/npm/$PackageName/blob/master/CHANGELOG.md"
            # В реальной реализации: проверить наличие CHANGELOG
            Write-Host "  CHANGELOG: $changelogUrl" -ForegroundColor Gray
        } catch {
            Write-Warning "  Не удалось получить CHANGELOG"
        }
        
        return $true
    }
    
    return $false
}

function Update-Dependencies {
    param([string]$Type)
    
    Write-Header "Обновление $Type зависимостей"
    
    $updatedCount = 0
    $failedCount = 0
    $reportData = @()
    
    # Получение списка зависимостей
    $packageJsonContent = Get-Content $PackageJson -Raw | ConvertFrom-Json
    
    $dependencies = switch ($Type) {
        'production' { $packageJsonContent.dependencies }
        'development' { $packageJsonContent.devDependencies }
        'all' { @{} + $packageJsonContent.dependencies + $packageJsonContent.devDependencies }
    }
    
    if (-not $dependencies) {
        Write-Warning "Нет $Type зависимостей для обновления"
        return
    }
    
    foreach ($dep in $dependencies.GetEnumerator()) {
        $name = $dep.Name
        $currentVersion = $dep.Value
        
        Write-Host "`n  [$name] Текущая версия: $currentVersion" -ForegroundColor Cyan
        
        try {
            # Получение информации о последней версии
            $info = npm view $name --json 2>$null | ConvertFrom-Json
            
            if ($null -eq $info) {
                Write-Warning "  Не удалось получить информацию о пакете"
                continue
            }
            
            $latestVersion = $info.'dist-tags'.latest
            
            if ($currentVersion -eq $latestVersion) {
                Write-Success "  Уже актуален: $latestVersion"
                continue
            }
            
            # Проверка breaking changes в Safe режиме
            if ($Mode -eq 'Safe') {
                $hasBreaking = Test-BreakingChanges -PackageName $name `
                                                  -CurrentVersion $currentVersion `
                                                  -NewVersion $latestVersion
                
                if ($hasBreaking) {
                    Write-Warning "  Пропущено из-за breaking changes (используйте -Mode All для принудительного)"
                    $reportData += [PSCustomObject]@{
                        Package = $name
                        Current = $currentVersion
                        Latest = $latestVersion
                        Status = 'Skipped (Breaking Changes)'
                        Action = 'Manual review required'
                    }
                    continue
                }
            }
            
            # Обновление
            Write-Host "  Обновление до $latestVersion..." -ForegroundColor Yellow
            
            $installCmd = "npm install $name@$latestVersion"
            if ($Type -eq 'development') {
                $installCmd += " --save-dev"
            }
            
            Invoke-Expression $installCmd
            
            Write-Success "  Обновлено: $currentVersion -> $latestVersion"
            $updatedCount++
            
            $reportData += [PSCustomObject]@{
                Package = $name
                Current = $currentVersion
                Latest = $latestVersion
                Status = 'Updated'
                Action = 'Auto-updated'
            }
            
        } catch {
            Write-Error-Custom "  Ошибка обновления: $_"
            $failedCount++
            
            $reportData += [PSCustomObject]@{
                Package = $name
                Current = $currentVersion
                Latest = $latestVersion
                Status = 'Failed'
                Action = "Error: $_"
            }
        }
    }
    
    Write-Header "Результаты обновления"
    Write-Success "Обновлено: $updatedCount"
    if ($failedCount -gt 0) {
        Write-Warning "Не удалось: $failedCount"
    }
    
    # Сохранение отчёта
    if ($reportData.Count -gt 0) {
        $reportPath = Join-Path $ProjectRoot $ReportPath
        $reportData | ConvertTo-Markdown | Out-File $reportPath -Encoding UTF8
        Write-Success "Отчёт сохранён: $reportPath"
    }
}

function Run-Tests {
    Write-Header "Запуск тестов"
    
    try {
        npm test
        Write-Success "Все тесты пройдены"
        return $true
    } catch {
        Write-Error-Custom "Тесты не пройдены"
        return $false
    }
}

function Restore-Backup {
    Write-Header "Восстановление резервной копии"
    
    $latestBackup = Get-ChildItem $BackupDir -Filter 'package-*.json' | 
                    Sort-Object LastWriteTime -Descending | 
                    Select-Object -First 1
    
    if ($latestBackup) {
        Copy-Item $latestBackup.FullName $PackageJson -Force
        Write-Success "Восстановлено из: $($latestBackup.Name)"
    } else {
        Write-Warning "Резервные копии не найдены"
    }
}

# =============================================================================
# ОСНОВНОЙ СЦЕНАРИЙ
# =============================================================================

Write-Header "🚀 Массовое обновление зависимостей"
Write-Host "Режим: $Mode" -ForegroundColor $ColorInfo
Write-Host "Запуск тестов: $($RunTests ? 'Да' : 'Нет')" -ForegroundColor $ColorInfo
Write-Host "Бэкап: $($CreateBackup ? 'Да' : 'Нет')" -ForegroundColor $ColorInfo

try {
    # Переход в директорию проекта
    Set-Location $ProjectRoot
    
    # Создание бэкапа
    Create-Backup
    
    # Обновление production зависимостей
    Update-Dependencies -Type 'production'
    
    # Обновление development зависимостей
    Update-Dependencies -Type 'development'
    
    # Запуск тестов если запрошено
    if ($RunTests) {
        $testsPassed = Run-Tests
        
        if (-not $testsPassed) {
            Write-Warning "`nТесты не пройдены! Восстановить резервную копию?"
            $response = Read-Host "Восстановить backup (y/n)"
            
            if ($response -eq 'y' -or $response -eq 'Y') {
                Restore-Backup
            }
        }
    }
    
    # Финальный аудит
    Write-Header "📊 Финальная проверка"
    npm audit --audit-level=moderate
    
    Write-Header "✅ Обновление завершено"
    $duration = (Get-Date) - $StartTime
    Write-Host "Время выполнения: $($duration.Minutes)m $($duration.Seconds)s" -ForegroundColor $ColorInfo
    
} catch {
    Write-Error-Custom "Критическая ошибка: $_"
    
    if ($CreateBackup) {
        Write-Warning "Восстановление резервной копии..."
        Restore-Backup
    }
    
    exit 1
}
