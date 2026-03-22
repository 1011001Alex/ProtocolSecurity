# =============================================================================
# INSTALL SCANNERS POWERSHELL SCRIPT
# Скрипт установки инструментов для secrets scanning
# =============================================================================
# Установка GitLeaks, TruffleHog и дополнительных утилит
# Для Windows PowerShell
# =============================================================================

[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$Verbose,
    [switch]$SkipValidation,
    [string]$InstallPath = "$env:LOCALAPPDATA\Programs\protocol-scanners",
    [ValidateSet("all", "gitleaks", "trufflehog", "pre-commit")]
    [string[]]$Tools = @("all")
)

# =============================================================================
# КОНФИГУРАЦИЯ
# =============================================================================
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$SCANNERS_VERSIONS = @{
    GitLeaks    = "8.18.1"
    TruffleHog  = "3.63.0"
    PreCommit   = "3.6.0"
}

$DOWNLOAD_URLS = @{
    GitLeaks    = "https://github.com/gitleaks/gitleaks/releases/download/v{0}/gitleaks_{0}_windows_x64.zip"
    TruffleHog  = "https://github.com/trufflesecurity/trufflehog/releases/download/v{0}/trufflehog_{0}_Windows_x86_64.tar.gz"
}

# =============================================================================
# ЦВЕТА ДЛЯ ВЫВОДА
# =============================================================================
function Write-Info    { param($msg) Write-Host "[INFO]    $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Warning { param($msg) Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Write-Error   { param($msg) Write-Host "[ERROR]   $msg" -ForegroundColor Red }
function Write-Header  { 
    param($msg) 
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "  $msg" -ForegroundColor Blue
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host ""
}

# =============================================================================
# ПРОВЕРКА ПРАВ АДМИНИСТРАТОРА
# =============================================================================
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# =============================================================================
# ПРОВЕРКА ТРЕБОВАНИЙ
# =============================================================================
function Test-Requirements {
    Write-Info "Проверка системных требований..."
    
    # Проверка PowerShell версии
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Error "Требуется PowerShell 5.0 или выше"
        return $false
    }
    
    # Проверка .NET Framework
    try {
        $dotnetVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release
        if ($dotnetVersion -lt 528040) {
            Write-Warning ".NET Framework 4.8+ рекомендуется"
        }
    } catch {
        Write-Warning ".NET Framework не обнаружен"
    }
    
    # Проверка наличия Chocolatey (опционально)
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Info "Chocolatey обнаружен: $(choco --version)"
        $script:HasChocolatey = $true
    } else {
        Write-Warning "Chocolatey не обнаружен. Будет использована ручная установка."
        $script:HasChocolatey = $false
    }
    
    # Проверка наличия Winget (опционально)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Info "Winget обнаружен: $(winget --version)"
        $script:HasWinget = $true
    } else {
        Write-Warning "Winget не обнаружен."
        $script:HasWinget = $false
    }
    
    # Проверка наличия Git
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Info "Git обнаружен: $(git --version)"
        $script:HasGit = $true
    } else {
        Write-Error "Git не обнаружен. Установите Git для работы сканеров."
        return $false
    }
    
    # Проверка наличия Python для pre-commit
    if (Get-Command python -ErrorAction SilentlyContinue) {
        Write-Info "Python обнаружен: $(python --version)"
        $script:HasPython = $true
    } elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
        Write-Info "Python обнаружен: $(python3 --version)"
        $script:HasPython = $true
    } else {
        Write-Warning "Python не обнаружен. Pre-commit hooks не будут установлены."
        $script:HasPython = $false
    }
    
    return $true
}

# =============================================================================
# УСТАНОВКА GITLEAKS ЧЕРЕZ CHOCOLATEY
# =============================================================================
function Install-GitLeaks-Chocolatey {
    Write-Info "Установка GitLeaks через Chocolatey..."
    
    try {
        choco install gitleaks -y --force:$Force
        Write-Success "GitLeaks успешно установлен через Chocolatey"
        return $true
    } catch {
        Write-Error "Ошибка установки GitLeaks через Chocolatey: $_"
        return $false
    }
}

# =============================================================================
# УСТАНОВКА GITLEAKS ЧЕРЕZ WINGET
# =============================================================================
function Install-GitLeaks-Winget {
    Write-Info "Установка GitLeaks через Winget..."
    
    try {
        winget install --id zricethezav.gitleaks -e --force
        Write-Success "GitLeaks успешно установлен через Winget"
        return $true
    } catch {
        Write-Error "Ошибка установки GitLeaks через Winget: $_"
        return $false
    }
}

# =============================================================================
# РУЧНАЯ УСТАНОВКА GITLEAKS
# =============================================================================
function Install-GitLeaks-Manual {
    Write-Info "Ручная установка GitLeaks..."
    
    try {
        # Создание директории
        $gitleaksDir = Join-Path $InstallPath "gitleaks"
        if (!(Test-Path $gitleaksDir)) {
            New-Item -ItemType Directory -Path $gitleaksDir -Force | Out-Null
        }
        
        # Загрузка
        $downloadUrl = $DOWNLOAD_URLS.GitLeaks -f $SCANNERS_VERSIONS.GitLeaks
        $zipFile = Join-Path $env:TEMP "gitleaks.zip"
        
        Write-Info "Загрузка GitLeaks v${SCANNERS_VERSIONS.GitLeaks}..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing
        
        # Распаковка
        Write-Info "Распаковка..."
        Expand-Archive -Path $zipFile -DestinationPath $gitleaksDir -Force
        
        # Добавление в PATH
        $gitleaksExe = Join-Path $gitleaksDir "gitleaks.exe"
        
        if (Test-Path $gitleaksExe) {
            Write-Success "GitLeaks установлен в: $gitleaksExe"
            
            # Добавление в PATH пользователя
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if ($currentPath -notlike "*$gitleaksDir*") {
                $newPath = "$currentPath;$gitleaksDir"
                [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
                Write-Info "Директория добавлена в PATH пользователя"
            }
            
            # Очистка
            Remove-Item $zipFile -Force
            
            return $true
        } else {
            Write-Error "gitleaks.exe не найден после распаковки"
            return $false
        }
    } catch {
        Write-Error "Ошибка ручной установки GitLeaks: $_"
        return $false
    }
}

# =============================================================================
# УСТАНОВКА GITLEAKS (MAIN)
# =============================================================================
function Install-GitLeaks {
    Write-Header "УСТАНОВКА GITLEAKS"
    
    if ($script:HasChocolatey) {
        if (Install-GitLeaks-Chocolatey) { return $true }
    }
    
    if ($script:HasWinget) {
        if (Install-GitLeaks-Winget) { return $true }
    }
    
    # Fallback на ручную установку
    return Install-GitLeaks-Manual
}

# =============================================================================
# РУЧНАЯ УСТАНОВКА TRUFFLEHOG
# =============================================================================
function Install-TruffleHog-Manual {
    Write-Info "Ручная установка TruffleHog..."
    
    try {
        # Создание директории
        $trufflehogDir = Join-Path $InstallPath "trufflehog"
        if (!(Test-Path $trufflehogDir)) {
            New-Item -ItemType Directory -Path $trufflehogDir -Force | Out-Null
        }
        
        # Загрузка
        $downloadUrl = $DOWNLOAD_URLS.TruffleHog -f $SCANNERS_VERSIONS.TruffleHog
        $tarFile = Join-Path $env:TEMP "trufflehog.tar.gz"
        
        Write-Info "Загрузка TruffleHog v${SCANNERS_VERSIONS.TruffleHog}..."
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tarFile -UseBasicParsing
        
        # Распаковка (требуется tar или 7zip)
        Write-Info "Распаковка..."
        
        if (Get-Command tar -ErrorAction SilentlyContinue) {
            tar -xzf $tarFile -C $trufflehogDir
        } else {
            Write-Error "tar не найден. Установите 7-Zip или используйте Chocolatey."
            return $false
        }
        
        # Поиск исполняемого файла
        $trufflehogExe = Get-ChildItem -Path $trufflehogDir -Filter "trufflehog.exe" -Recurse | Select-Object -First 1
        
        if ($trufflehogExe) {
            Write-Success "TruffleHog установлен в: $($trufflehogExe.FullName)"
            
            # Добавление в PATH
            $trufflehogDir = $trufflehogExe.DirectoryName
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if ($currentPath -notlike "*$trufflehogDir*") {
                $newPath = "$currentPath;$trufflehogDir"
                [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
                Write-Info "Директория добавлена в PATH пользователя"
            }
            
            # Очистка
            Remove-Item $tarFile -Force
            
            return $true
        } else {
            Write-Error "trufflehog.exe не найден после распаковки"
            return $false
        }
    } catch {
        Write-Error "Ошибка установки TruffleHog: $_"
        return $false
    }
}

# =============================================================================
# УСТАНОВКА TRUFFLEHOG ЧЕРЕZ CHOCOLATEY
# =============================================================================
function Install-TruffleHog-Chocolatey {
    Write-Info "Установка TruffleHog через Chocolatey..."
    
    try {
        choco install trufflehog -y --force:$Force
        Write-Success "TruffleHog успешно установлен через Chocolatey"
        return $true
    } catch {
        Write-Error "Ошибка установки TruffleHog через Chocolatey: $_"
        return $false
    }
}

# =============================================================================
# УСТАНОВКА TRUFFLEHOG (MAIN)
# =============================================================================
function Install-TruffleHog {
    Write-Header "УСТАНОВКА TRUFFLEHOG"
    
    if ($script:HasChocolatey) {
        if (Install-TruffleHog-Chocolatey) { return $true }
    }
    
    # Fallback на ручную установку
    return Install-TruffleHog-Manual
}

# =============================================================================
# УСТАНОВКА PRE-COMMIT
# =============================================================================
function Install-PreCommit {
    Write-Header "УСТАНОВКА PRE-COMMIT"
    
    if (!$script:HasPython) {
        Write-Error "Python не обнаружен. Pre-commit требует Python."
        return $false
    }
    
    try {
        Write-Info "Установка pre-commit через pip..."
        
        # Обновление pip
        python -m pip install --upgrade pip --quiet
        
        # Установка pre-commit
        python -m pip install pre-commit==$SCANNERS_VERSIONS.PreCommit --quiet
        
        Write-Success "Pre-commit успешно установлен"
        
        # Проверка установки
        $precommitVersion = pre-commit --version
        Write-Info "Версия pre-commit: $precommitVersion"
        
        return $true
    } catch {
        Write-Error "Ошибка установки pre-commit: $_"
        return $false
    }
}

# =============================================================================
# ПРОВЕРКА УСТАНОВКИ
# =============================================================================
function Test-Installation {
    Write-Header "ПРОВЕРКА УСТАНОВКИ"
    
    $results = @{
        GitLeaks    = $false
        TruffleHog  = $false
        PreCommit   = $false
    }
    
    # Проверка GitLeaks
    if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
        $version = gitleaks version 2>&1 | Select-String "gitleaks" | ForEach-Object { $_.ToString() }
        Write-Success "GitLeaks: $version"
        $results.GitLeaks = $true
    } else {
        Write-Error "GitLeaks: НЕ УСТАНОВЛЕН"
    }
    
    # Проверка TruffleHog
    if (Get-Command trufflehog -ErrorAction SilentlyContinue) {
        $version = trufflehog --version 2>&1 | Select-String "version" | ForEach-Object { $_.ToString() }
        Write-Success "TruffleHog: $version"
        $results.TruffleHog = $true
    } else {
        Write-Error "TruffleHog: НЕ УСТАНОВЛЕН"
    }
    
    # Проверка Pre-Commit
    if (Get-Command pre-commit -ErrorAction SilentlyContinue) {
        $version = pre-commit --version
        Write-Success "Pre-Commit: $version"
        $results.PreCommit = $true
    } else {
        Write-Error "Pre-Commit: НЕ УСТАНОВЛЕН"
    }
    
    return $results
}

# =============================================================================
# НАСТРОЙКА PRE-COMMIT HOOKS
# =============================================================================
function Setup-PreCommitHooks {
    Write-Header "НАСТРОЙКА PRE-COMMIT HOOKS"
    
    $projectRoot = $PSScriptRoot | Split-Path -Parent
    
    if (!(Test-Path (Join-Path $projectRoot ".git"))) {
        Write-Error "Git репозиторий не найден в $projectRoot"
        return $false
    }
    
    try {
        Set-Location $projectRoot
        
        Write-Info "Инициализация pre-commit hooks..."
        pre-commit install
        
        Write-Info "Установка hooks для gitleaks..."
        pre-commit install --hook-type pre-push
        
        Write-Success "Pre-commit hooks настроены успешно"
        return $true
    } catch {
        Write-Error "Ошибка настройки pre-commit hooks: $_"
        return $false
    }
}

# =============================================================================
# ГЕНЕРАЦИЯ ОТЧЁТА
# =============================================================================
function Generate-InstallReport {
    param($Results)
    
    Write-Header "ОТЧЁТ ОБ УСТАНОВКЕ"
    
    $reportFile = Join-Path $PSScriptRoot "install-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    
    $report = @"
═══════════════════════════════════════════════════════════
        PROTOCOL SECURITY - INSTALLATION REPORT
═══════════════════════════════════════════════════════════

Дата установки: $(Get-Date -Format "dd.MM.yyyy HH:mm:ss")
Пользователь: $env:USERNAME
Компьютер: $env:COMPUTERNAME
PowerShell: $($PSVersionTable.PSVersion.ToString())

РЕЗУЛЬТАТЫ УСТАНОВКИ:
───────────────────────────────────────────────────────────
GitLeaks:     $(if ($Results.GitLeaks) { "✓ УСТАНОВЛЕН" } else { "✗ НЕ УСТАНОВЛЕН" })
TruffleHog:   $(if ($Results.TruffleHog) { "✓ УСТАНОВЛЕН" } else { "✗ НЕ УСТАНОВЛЕН" })
Pre-Commit:   $(if ($Results.PreCommit) { "✓ УСТАНОВЛЕН" } else { "✗ НЕ УСТАНОВЛЕН" })

СЛЕДУЮЩИЕ ШАГИ:
───────────────────────────────────────────────────────────
1. Перезапустите PowerShell для применения изменений PATH
2. Запустите: .\scripts\gitleaks-scan.sh
3. Запустите: .\scripts\trufflehog-scan.sh
4. Настройте pre-commit: pre-commit install

ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ:
───────────────────────────────────────────────────────────
- Документация: SECRETS_SCANNING.md
- Конфигурация: .gitleaks.toml, .pre-commit-config.yaml
- CI/CD: .github/workflows/secrets-scan.yml

═══════════════════════════════════════════════════════════
"@

    $report | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Info "Отчёт сохранён: $reportFile"
    
    Write-Host ""
    Write-Host $report -ForegroundColor White
}

# =============================================================================
# ОСНОВНАЯ ФУНКЦИЯ
# =============================================================================
function Main {
    Write-Header "PROTOCOL SECURITY - INSTALL SCANNERS"
    Write-Host "  Установка инструментов для secrets scanning" -ForegroundColor White
    Write-Host ""
    
    # Проверка требований
    if (!(Test-Requirements)) {
        Write-Error "Проверка требований не пройдена. Установка прервана."
        exit 1
    }
    
    $results = @{
        GitLeaks    = $false
        TruffleHog  = $false
        PreCommit   = $false
    }
    
    # Установка GitLeaks
    if ($Tools -contains "all" -or $Tools -contains "gitleaks") {
        $results.GitLeaks = Install-GitLeaks
    }
    
    # Установка TruffleHog
    if ($Tools -contains "all" -or $Tools -contains "trufflehog") {
        $results.TruffleHog = Install-TruffleHog
    }
    
    # Установка Pre-Commit
    if ($Tools -contains "all" -or $Tools -contains "pre-commit") {
        $results.PreCommit = Install-PreCommit
        
        if ($results.PreCommit) {
            Setup-PreCommitHooks
        }
    }
    
    # Финальная проверка
    $finalResults = Test-Installation
    
    # Генерация отчёта
    Generate-InstallReport -Results $finalResults
    
    # Итоговый статус
    Write-Host ""
    if ($finalResults.GitLeaks -and $finalResults.TruffleHog) {
        Write-Success "═══════════════════════════════════════════════════════════"
        Write-Success "  ВСЕ ИНСТРУМЕНТЫ УСПЕШНО УСТАНОВЛЕНЫ!"
        Write-Success "═══════════════════════════════════════════════════════════"
        exit 0
    } else {
        Write-Warning "═══════════════════════════════════════════════════════════"
        Write-Warning "  УСТАНОВКА ЗАВЕРШЕНА С ОШИБКАМИ"
        Write-Warning "  Проверьте отчёт выше"
        Write-Warning "═══════════════════════════════════════════════════════════"
        exit 1
    }
}

# =============================================================================
# ЗАПУСК
# =============================================================================
Main
