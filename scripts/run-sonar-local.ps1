# ========================================
# PowerShell Script: Local SonarQube Runner
# Protocol Security Project
# ========================================
# Скрипт для локального запуска SonarQube через Docker
# Использование: .\scripts\run-sonar-local.ps1 [-Action start|scan|stop|restart|status] [-Port 9000] [-Version latest]

[CmdletBinding()]
param(
    # Действие: start, scan, stop, restart, status, clean
    [Parameter(Mandatory = $false)]
    [ValidateSet('start', 'scan', 'stop', 'restart', 'status', 'clean', 'full')]
    [string]$Action = 'full',
    
    # Порт для SonarQube web интерфейса
    [Parameter(Mandatory = $false)]
    [int]$Port = 9000,
    
    # Версия SonarQube Docker образа
    [Parameter(Mandatory = $false)]
    [string]$Version = '10.4-community',
    
    # Имя контейнера
    [Parameter(Mandatory = $false)]
    [string]$ContainerName = 'sonarqube-protocol',
    
    # Путь к проекту
    [Parameter(Mandatory = $false)]
    [string]$ProjectPath = $PSScriptRoot,
    
    # Включить verbose логирование
    [Parameter(Mandatory = $false)]
    [switch]$Verbose,
    
    # Не удалять контейнер после остановки
    [Parameter(Mandatory = $false)]
    [switch]$Persist
)

# ========================================
# Configuration
# ========================================
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Пути
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$LogsDir = Join-Path $RootDir 'logs'
$TempDir = Join-Path $RootDir 'temp'

# SonarQube настройки
$SonarHostUrl = "http://localhost:$Port"
$SonarToken = 'admin'  # Default token для локальной разработки
$ProjectKey = 'protocol-security'
$ProjectName = 'Protocol Security'

# Docker настройки
$DockerImage = "sonarqube:$Version"
$Volumes = @(
    "$($RootDir)\.sonarqube\data:/opt/sonarqube/data",
    "$($RootDir)\.sonarqube\extensions:/opt/sonarqube/extensions",
    "$($RootDir)\.sonarqube\logs:/opt/sonarqube/logs"
)

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

function Test-Docker {
    try {
        $null = docker --version
        return $true
    }
    catch {
        return $false
    }
}

function Test-DockerRunning {
    try {
        $null = docker ps
        return $true
    }
    catch {
        return $false
    }
}

function Get-ContainerStatus {
    param([string]$Name)
    try {
        $status = docker inspect -f '{{.State.Status}}' $Name 2>$null
        return $status
    }
    catch {
        return 'notfound'
    }
}

function Wait-SonarQubeReady {
    param(
        [int]$Timeout = 120,
        [int]$Interval = 5
    )
    
    Write-Info "Ожидание готовности SonarQube (таймаут: ${Timeout}s)..."
    $elapsed = 0
    
    while ($elapsed -lt $Timeout) {
        try {
            $response = Invoke-WebRequest -Uri "$SonarHostUrl/api/system/status" -TimeoutSec 5 -UseBasicParsing
            $status = ($response.Content | ConvertFrom-Json).status
            
            if ($status -eq 'UP') {
                Write-Info "SonarQube готов!"
                return $true
            }
            else {
                Write-Info "Статус SonarQube: $status..."
            }
        }
        catch {
            Write-Info "SonarQube еще не готов..."
        }
        
        Start-Sleep -Seconds $Interval
        $elapsed += $Interval
    }
    
    Write-Error-Custom "SonarQube не запустился за ${Timeout} секунд"
    return $false
}

function Install-Scanner {
    Write-Info "Установка SonarQube Scanner..."
    
    # Создаем директорию для сканера
    $ScannerDir = Join-Path $TempDir 'sonar-scanner'
    if (!(Test-Path $ScannerDir)) {
        New-Item -ItemType Directory -Path $ScannerDir -Force | Out-Null
    }
    
    # Проверяем наличие сканера
    $ScannerExe = Join-Path $ScannerDir 'sonar-scanner.bat'
    
    if (!(Test-Path $ScannerExe)) {
        Write-Info "Скачивание SonarQube Scanner..."
        
        # URL для скачивания (Windows version)
        $ScannerUrl = "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-windows-x64.zip"
        $ZipPath = Join-Path $TempDir 'sonar-scanner.zip'
        
        try {
            Invoke-WebRequest -Uri $ScannerUrl -OutFile $ZipPath -UseBasicParsing
            Write-Info "Распаковка сканера..."
            Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force
            
            # Перемещаем файлы в нужную директорию
            $ExtractedDir = Get-ChildItem -Path $TempDir -Filter 'sonar-scanner-*' -Directory | Select-Object -First 1
            if ($ExtractedDir) {
                Copy-Item -Path "$($ExtractedDir.FullName)\*" -Destination $ScannerDir -Recurse -Force
                Remove-Item -Path $ExtractedDir.FullName -Recurse -Force
            }
            
            Remove-Item -Path $ZipPath -Force
            Write-Info "Сканер установлен успешно"
        }
        catch {
            Write-Error-Custom "Ошибка установки сканера: $_"
            return $false
        }
    }
    else {
        Write-Info "Сканер уже установлен"
    }
    
    return $ScannerDir
}

function Build-Project {
    Write-Header "Сборка проекта"
    
    Set-Location $RootDir
    
    # Установка зависимостей
    if (Test-Path 'package-lock.json') {
        Write-Info "Установка зависимостей npm..."
        npm ci --ignore-scripts
    }
    else {
        Write-Info "Установка зависимостей npm..."
        npm install --ignore-scripts
    }
    
    # Сборка TypeScript
    Write-Info "Сборка TypeScript проекта..."
    npm run build
    
    # Запуск тестов с покрытием
    Write-Info "Запуск тестов с покрытием..."
    npm run test -- --coverage --coverageReporters=text --coverageReporters=lcov
}

function Run-SonarScan {
    param([string]$ScannerPath)
    
    Write-Header "Запуск SonarQube Scanner"
    
    Set-Location $RootDir
    
    $ScannerExe = Join-Path $ScannerPath 'bin\sonar-scanner.bat'
    
    if (!(Test-Path $ScannerExe)) {
        Write-Error-Custom "Scanner executable не найден: $ScannerExe"
        return $false
    }
    
    # Аргументы для сканера
    $Args = @(
        "-Dsonar.projectKey=$ProjectKey"
        "-Dsonar.projectName=`"$ProjectName`""
        "-Dsonar.host.url=$SonarHostUrl"
        "-Dsonar.login=$SonarToken"
        "-Dsonar.sources=src"
        "-Dsonar.tests=tests"
        "-Dsonar.typescript.tsconfigPath=tsconfig.json"
        "-Dsonar.typescript.lcov.reportPaths=coverage/lcov.info"
        "-Dsonar.sourceEncoding=UTF-8"
        "-Dsonar.verbose=$($Verbose.ToString().ToLower())"
    )
    
    Write-Info "Запуск сканирования: $ScannerExe $($Args -join ' ')"
    
    try {
        & $ScannerExe $Args
        Write-Info "Сканирование завершено успешно"
        return $true
    }
    catch {
        Write-Error-Custom "Ошибка сканирования: $_"
        return $false
    }
}

# ========================================
# Actions
# ========================================

function Start-SonarQube {
    Write-Header "Запуск SonarQube"
    
    if (!(Test-Docker)) {
        Write-Error-Custom "Docker не установлен. Установите Docker Desktop."
        return $false
    }
    
    if (!(Test-DockerRunning)) {
        Write-Error-Custom "Docker daemon не запущен. Запустите Docker Desktop."
        return $false
    }
    
    # Проверяем статус контейнера
    $status = Get-ContainerStatus -Name $ContainerName
    
    if ($status -eq 'running') {
        Write-Info "Контейнер уже запущен: $ContainerName"
        Write-Info "Web интерфейс: $SonarHostUrl"
        return $true
    }
    
    # Удаляем старый контейнер если существует
    if ($status -ne 'notfound') {
        Write-Info "Удаление старого контейнера..."
        docker rm -f $ContainerName 2>$null
    }
    
    # Создаем директории для томов
    $Volumes | ForEach-Object {
        $hostPath = ($_ -split ':')[0]
        if (!(Test-Path $hostPath)) {
            New-Item -ItemType Directory -Path $hostPath -Force | Out-Null
        }
    }
    
    Write-Info "Запуск контейнера $ContainerName..."
    Write-Info "Образ: $DockerImage"
    Write-Info "Порт: $Port"
    
    # Формируем команду docker run
    $DockerArgs = @(
        'run', '-d',
        '--name', $ContainerName,
        '-p', "$Port`:9000",
        '-e', "SONAR_ES_BOOTSTRAP_CHECK_DISABLE=true"
    )
    
    # Добавляем volumes
    $Volumes | ForEach-Object {
        $DockerArgs += '-v', $_
    }
    
    $DockerArgs += $DockerImage
    
    docker @DockerArgs
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error-Custom "Ошибка запуска контейнера"
        return $false
    }
    
    Write-Info "Контейнер запущен"
    
    # Ожидаем готовности SonarQube
    if (Wait-SonarQubeReady -Timeout 180) {
        Write-Info ""
        Write-Info "╔════════════════════════════════════════════════════╗"
        Write-Info "║  SonarQube запущен успешно!                        ║"
        Write-Info "║                                                    ║"
        Write-Info "║  Web интерфейс: $SonarHostUrl"
        Write-Info "║  Логин: admin                                      ║"
        Write-Info "║  Пароль: admin                                     ║"
        Write-Info "║                                                    ║"
        Write-Info "║  Project Key: $ProjectKey"
        Write-Info "╚════════════════════════════════════════════════════╝"
        return $true
    }
    else {
        return $false
    }
}

function Stop-SonarQube {
    Write-Header "Остановка SonarQube"
    
    $status = Get-ContainerStatus -Name $ContainerName
    
    if ($status -eq 'notfound') {
        Write-Info "Контейнер не найден"
        return $true
    }
    
    Write-Info "Остановка контейнера..."
    docker stop $ContainerName
    
    if (!$Persist) {
        Write-Info "Удаление контейнера..."
        docker rm $ContainerName
    }
    
    Write-Info "SonarQube остановлен"
    return $true
}

function Restart-SonarQube {
    Write-Info "Перезапуск SonarQube..."
    Stop-SonarQube
    Start-Sleep -Seconds 3
    Start-SonarQube
}

function Get-SonarQubeStatus {
    Write-Header "Статус SonarQube"
    
    $status = Get-ContainerStatus -Name $ContainerName
    
    Write-Host "Контейнер: $ContainerName" -ForegroundColor Cyan
    Write-Host "Статус: $status" -ForegroundColor $(
        switch ($status) {
            'running' { 'Green' }
            'exited' { 'Yellow' }
            'notfound' { 'Gray' }
            default { 'Gray' }
        }
    )
    
    if ($status -eq 'running') {
        Write-Host "Web интерфейс: $SonarHostUrl" -ForegroundColor Green
        
        try {
            $response = Invoke-WebRequest -Uri "$SonarHostUrl/api/system/status" -TimeoutSec 5 -UseBasicParsing
            $sonarStatus = ($response.Content | ConvertFrom-Json)
            
            Write-Host "Версия SonarQube: $($sonarStatus.version)" -ForegroundColor Cyan
            Write-Host "Статус системы: $($sonarStatus.status)" -ForegroundColor $(
                if ($sonarStatus.status -eq 'UP') { 'Green' } else { 'Red' }
            )
        }
        catch {
            Write-Warn "Не удалось получить детальную информацию"
        }
    }
}

function Clean-SonarQube {
    Write-Header "Очистка SonarQube"
    
    Write-Info "Остановка и удаление контейнера..."
    docker rm -f $ContainerName 2>$null
    
    Write-Info "Удаление данных..."
    $DataDir = Join-Path $RootDir '.sonarqube'
    if (Test-Path $DataDir) {
        Remove-Item -Path $DataDir -Recurse -Force
        Write-Info "Данные удалены: $DataDir"
    }
    
    Write-Info "Удаление временных файлов сканера..."
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force
    }
    
    Write-Info "Очистка завершена"
}

function Full-Analysis {
    Write-Header "Полный цикл анализа SonarQube"
    
    # Шаг 1: Проверка Docker
    if (!(Test-Docker)) {
        Write-Error-Custom "Docker не установлен"
        return $false
    }
    
    # Шаг 2: Запуск SonarQube
    if (!(Start-SonarQube)) {
        return $false
    }
    
    # Шаг 3: Сборка проекта
    Build-Project
    
    # Шаг 4: Установка сканера
    $ScannerPath = Install-Scanner
    if (!$ScannerPath) {
        return $false
    }
    
    # Шаг 5: Запуск сканирования
    if (!(Run-SonarScan -ScannerPath $ScannerPath)) {
        return $false
    }
    
    Write-Header "Анализ завершен"
    Write-Info "Откройте $SonarHostUrl для просмотра результатов"
    Write-Info "Project: $ProjectName"
    Write-Info "Project Key: $ProjectKey"
    
    return $true
}

# ========================================
# Main
# ========================================

Write-Header "SonarQube Local Runner - Protocol Security"

try {
    switch ($Action) {
        'start' {
            Start-SonarQube
        }
        'scan' {
            $ScannerPath = Install-Scanner
            if ($ScannerPath) {
                Run-SonarScan -ScannerPath $ScannerPath
            }
        }
        'stop' {
            Stop-SonarQube
        }
        'restart' {
            Restart-SonarQube
        }
        'status' {
            Get-SonarQubeStatus
        }
        'clean' {
            Clean-SonarQube
        }
        'full' {
            Full-Analysis
        }
    }
}
catch {
    Write-Error-Custom "Произошла ошибка: $_"
    exit 1
}

Write-Host ""
Write-Host "Готово!" -ForegroundColor Green
