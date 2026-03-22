#!/bin/bash
# =============================================================================
# GITLEAKS SCAN SCRIPT FOR PROTOCOL SECURITY
# =============================================================================
# Скрипт для запуска GitLeaks с полной проверкой репозитория
# Поддержка staged changes, истории коммитов, отчёты в JSON и HTML
# =============================================================================
#
# Usage:
#   ./scripts/gitleaks-scan.sh                    # Полное сканирование
#   ./scripts/gitleaks-scan.sh --staged           # Только staged changes
#   ./scripts/gitleaks-scan.sh --history          # Полная история git
#   ./scripts/gitleaks-scan.sh --report           # Генерация отчётов
#   ./scripts/gitleaks-scan.sh --install          # Установка gitleaks
#   ./scripts/gitleaks-scan.sh --help             # Помощь
#
# =============================================================================

set -e

# =============================================================================
# КОНФИГУРАЦИЯ
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_ROOT/reports/secrets"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
GITLEAKS_VERSION="8.18.1"
GITLEAKS_CONFIG="$PROJECT_ROOT/.gitleaks.toml"

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Флаги режимов
MODE_FULL=false
MODE_STAGED=false
MODE_HISTORY=false
MODE_REPORT=false
MODE_INSTALL=false
MODE_CI=false

# =============================================================================
# ФУНКЦИИ ВЫВОДА
# =============================================================================
print_header() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║         PROTOCOL SECURITY - GITLEAKS SCANNER              ║"
    echo "║         Система обнаружения секретов                      ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "${CYAN}─────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}─────────────────────────────────────────────────────────────${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# =============================================================================
# ПРОВЕРКА НАЛИЧИЯ GITLEAKS
# =============================================================================
check_gitleaks() {
    if command -v gitleaks &> /dev/null; then
        local version=$(gitleaks version 2>&1 | head -1)
        print_success "GitLeaks обнаружен: $version"
        return 0
    else
        print_warning "GitLeaks не найден в PATH"
        return 1
    fi
}

# =============================================================================
# УСТАНОВКА GITLEAKS
# =============================================================================
install_gitleaks() {
    print_section "УСТАНОВКА GITLEAKS"
    
    # Проверка наличия package manager
    if command -v brew &> /dev/null; then
        print_info "Установка через Homebrew..."
        brew install gitleaks
        return $?
    fi
    
    if command -v apt-get &> /dev/null; then
        print_info "Установка через apt..."
        sudo apt-get update
        sudo apt-get install -y gitleaks
        return $?
    fi
    
    if command -v yum &> /dev/null; then
        print_info "Установка через yum..."
        sudo yum install -y gitleaks
        return $?
    fi
    
    if command -v choco &> /dev/null; then
        print_info "Установка через Chocolatey (Windows)..."
        choco install gitleaks -y
        return $?
    fi
    
    if command -v winget &> /dev/null; then
        print_info "Установка через Winget (Windows)..."
        winget install --id zricethezav.gitleaks -e
        return $?
    fi
    
    # Ручная установка
    print_info "Ручная установка GitLeaks v${GITLEAKS_VERSION}..."
    
    local temp_dir=$(mktemp -d)
    local download_url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}"
    
    # Определение ОС и архитектуры
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case "$arch" in
        x86_64) arch="x64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) arch="x64" ;;
    esac
    
    case "$os" in
        darwin) os="mac" ;;
        linux) os="linux" ;;
        mingw*|msys*|cygwin*) os="windows" ;;
    esac
    
    local archive_name="${download_url}_${os}_${arch}.tar.gz"
    local archive_path="$temp_dir/gitleaks.tar.gz"
    
    print_info "Загрузка: $archive_name"
    curl -sL "$archive_name" -o "$archive_path"
    
    if [ $? -eq 0 ]; then
        print_success "Загрузка завершена"
        
        # Распаковка
        tar -xzf "$archive_path" -C "$temp_dir"
        
        # Перемещение в локальную директорию
        local local_bin="$HOME/.local/bin"
        mkdir -p "$local_bin"
        mv "$temp_dir/gitleaks" "$local_bin/"
        chmod +x "$local_bin/gitleaks"
        
        print_success "GitLeaks установлен в: $local_bin/gitleaks"
        print_info "Добавьте ~/.local/bin в PATH:"
        echo 'export PATH="$HOME/.local/bin:$PATH"'
        
        # Очистка
        rm -rf "$temp_dir"
        
        return 0
    else
        print_error "Не удалось загрузить GitLeaks"
        return 1
    fi
}

# =============================================================================
# ПРОВЕРКА КОНФИГУРАЦИИ
# =============================================================================
check_config() {
    if [ -f "$GITLEAKS_CONFIG" ]; then
        print_success "Конфигурация найдена: $GITLEAKS_CONFIG"
        return 0
    else
        print_warning "Конфигурация не найдена: $GITLEAKS_CONFIG"
        print_info "Будет использована конфигурация по умолчанию"
        return 1
    fi
}

# =============================================================================
# СКАНИРОВАНИЕ STAGED CHANGES
# =============================================================================
scan_staged() {
    print_section "СКАНИРОВАНИЕ STAGED CHANGES"
    print_info "Проверка файлов, подготовленных к коммиту..."
    
    local exit_code=0
    
    if [ -f "$GITLEAKS_CONFIG" ]; then
        gitleaks detect \
            --source "$PROJECT_ROOT" \
            --staged \
            --config "$GITLEAKS_CONFIG" \
            --report-path "$REPORTS_DIR/gitleaks-staged-${TIMESTAMP}.json" \
            --report-format json \
            --verbose || exit_code=$?
    else
        gitleaks detect \
            --source "$PROJECT_ROOT" \
            --staged \
            --report-path "$REPORTS_DIR/gitleaks-staged-${TIMESTAMP}.json" \
            --report-format json \
            --verbose || exit_code=$?
    fi
    
    if [ $exit_code -eq 0 ]; then
        print_success "Staged changes: уязвимости не обнаружены"
    else
        print_error "Staged changes: обнаружены секреты!"
    fi
    
    return $exit_code
}

# =============================================================================
# СКАНИРОВАНИЕ ВСЕЙ ИСТОРИИ GIT
# =============================================================================
scan_history() {
    print_section "СКАНИРОВАНИЕ GIT HISTORY"
    print_info "Полная проверка истории коммитов..."
    
    local exit_code=0
    
    if [ -f "$GITLEAKS_CONFIG" ]; then
        gitleaks detect \
            --source "$PROJECT_ROOT" \
            --config "$GITLEAKS_CONFIG" \
            --report-path "$REPORTS_DIR/gitleaks-history-${TIMESTAMP}.json" \
            --report-format json \
            --verbose || exit_code=$?
    else
        gitleaks detect \
            --source "$PROJECT_ROOT" \
            --report-path "$REPORTS_DIR/gitleaks-history-${TIMESTAMP}.json" \
            --report-format json \
            --verbose || exit_code=$?
    fi
    
    if [ $exit_code -eq 0 ]; then
        print_success "Git history: уязвимости не обнаружены"
    else
        print_error "Git history: обнаружены секреты!"
    fi
    
    return $exit_code
}

# =============================================================================
# СКАНИРОВАНИЕ ТЕКУЩЕЙ РАБОЧЕЙ ДИРЕКТОРИИ
# =============================================================================
scan_working_dir() {
    print_section "СКАНИРОВАНИЕ РАБОЧЕЙ ДИРЕКТОРИИ"
    print_info "Проверка текущих файлов проекта..."
    
    local exit_code=0
    
    if [ -f "$GITLEAKS_CONFIG" ]; then
        gitleaks detect \
            --source "$PROJECT_ROOT" \
            --config "$GITLEAKS_CONFIG" \
            --report-path "$REPORTS_DIR/gitleaks-working-${TIMESTAMP}.json" \
            --report-format json \
            --verbose || exit_code=$?
    else
        gitleaks detect \
            --source "$PROJECT_ROOT" \
            --report-path "$REPORTS_DIR/gitleaks-working-${TIMESTAMP}.json" \
            --report-format json \
            --verbose || exit_code=$?
    fi
    
    if [ $exit_code -eq 0 ]; then
        print_success "Working directory: уязвимости не обнаружены"
    else
        print_error "Working directory: обнаружены секреты!"
    fi
    
    return $exit_code
}

# =============================================================================
# ГЕНЕРАЦИЯ HTML ОТЧЁТА
# =============================================================================
generate_html_report() {
    print_section "ГЕНЕРАЦИЯ ОТЧЁТОВ"
    
    mkdir -p "$REPORTS_DIR"
    
    # Поиск последнего JSON отчёта
    local latest_json=$(ls -t "$REPORTS_DIR"/gitleaks-*.json 2>/dev/null | head -1)
    
    if [ -z "$latest_json" ]; then
        print_warning "JSON отчёты не найдены для генерации HTML"
        return 1
    fi
    
    print_info "Генерация HTML отчёта на основе: $latest_json"
    
    # Генерация HTML с помощью gitleaks (если поддерживается)
    # Или создание простого HTML отчёта
    local html_report="$REPORTS_DIR/gitleaks-report-${TIMESTAMP}.html"
    
    cat > "$html_report" << 'HTML_TEMPLATE'
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Protocol Security - GitLeaks Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        h1 { font-size: 2em; margin-bottom: 10px; }
        .meta { opacity: 0.8; font-size: 0.9em; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: #16213e;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        .card.critical { border-color: #e74c3c; }
        .card.high { border-color: #e67e22; }
        .card.medium { border-color: #f1c40f; }
        .card.low { border-color: #27ae60; }
        .card h3 { font-size: 2.5em; margin-bottom: 5px; }
        .card p { opacity: 0.7; }
        .findings { background: #16213e; border-radius: 10px; padding: 20px; }
        .finding {
            background: #0f3460;
            margin: 15px 0;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .severity {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .severity.critical { background: #e74c3c; }
        .severity.high { background: #e67e22; }
        .severity.medium { background: #f1c40f; color: #000; }
        .severity.low { background: #27ae60; }
        .finding-detail {
            background: #1a1a2e;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Consolas', monospace;
            font-size: 0.85em;
            overflow-x: auto;
            margin: 10px 0;
        }
        .finding-detail code { color: #00ff88; }
        .redacted { color: #e74c3c; font-weight: bold; }
        footer {
            text-align: center;
            padding: 30px;
            opacity: 0.6;
            font-size: 0.9em;
        }
        .no-findings {
            text-align: center;
            padding: 50px;
            background: #16213e;
            border-radius: 10px;
        }
        .no-findings h2 { color: #27ae60; font-size: 2em; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Protocol Security - GitLeaks Report</h1>
            <p class="meta">Отчёт о сканировании на секреты и чувствительные данные</p>
        </header>
        
        <div class="summary" id="summary">
            <!-- Summary cards will be inserted here -->
        </div>
        
        <div class="findings" id="findings">
            <h2>Обнаруженные уязвимости</h2>
            <div id="findings-list">
                <!-- Findings will be inserted here -->
            </div>
        </div>
        
        <footer>
            <p>Generated by GitLeaks | Protocol Security Project</p>
            <p id="timestamp"></p>
        </footer>
    </div>
    
    <script>
        // Загрузка данных из JSON
        fetch('gitleaks-working-latest.json')
            .then(response => response.json())
            .then(data => {
                document.getElementById('timestamp').textContent = 
                    'Дата генерации: ' + new Date().toLocaleString('ru-RU');
                
                if (!data || !data.Report || data.Report.length === 0) {
                    document.getElementById('findings-list').innerHTML = `
                        <div class="no-findings">
                            <h2>✅ Уязвимости не обнаружены</h2>
                            <p>Сканирование завершено успешно. Секреты не найдены.</p>
                        </div>
                    `;
                    document.getElementById('summary').innerHTML = `
                        <div class="card low">
                            <h3>0</h3>
                            <p>Всего уязвимостей</p>
                        </div>
                    `;
                    return;
                }
                
                const findings = data.Report;
                const severityCount = { critical: 0, high: 0, medium: 0, low: 0 };
                
                findings.forEach(f => {
                    const sev = (f.Secret || '').toLowerCase().includes('critical') ? 'critical' :
                               (f.RuleID || '').includes('aws') ? 'critical' : 'high';
                    severityCount[sev]++;
                });
                
                document.getElementById('summary').innerHTML = `
                    <div class="card critical">
                        <h3>${severityCount.critical}</h3>
                        <p>Critical</p>
                    </div>
                    <div class="card high">
                        <h3>${severityCount.high}</h3>
                        <p>High</p>
                    </div>
                    <div class="card medium">
                        <h3>${severityCount.medium}</h3>
                        <p>Medium</p>
                    </div>
                    <div class="card low">
                        <h3>${severityCount.low}</h3>
                        <p>Low</p>
                    </div>
                    <div class="card">
                        <h3>${findings.length}</h3>
                        <p>Всего</p>
                    </div>
                `;
                
                let findingsHtml = '';
                findings.forEach((f, i) => {
                    findingsHtml += `
                        <div class="finding">
                            <div class="finding-header">
                                <strong>#${i + 1}: ${f.RuleID || 'Unknown Rule'}</strong>
                                <span class="severity ${f.Severity ? f.Severity.toLowerCase() : 'high'}">
                                    ${f.Severity || 'HIGH'}
                                </span>
                            </div>
                            <p><strong>Файл:</strong> ${f.File || 'N/A'}</p>
                            <p><strong>Строка:</strong> ${f.StartLine || 'N/A'} - ${f.EndLine || 'N/A'}</p>
                            <p><strong>Commit:</strong> ${f.Commit ? f.Commit.substring(0, 12) : 'N/A'}</p>
                            <div class="finding-detail">
                                <code>${f.Secret ? f.Secret.substring(0, 50) + '...' : 'N/A'}</code>
                            </div>
                            <p><strong>Match:</strong></p>
                            <div class="finding-detail">
                                <code>${f.Line || 'N/A'}</code>
                            </div>
                        </div>
                    `;
                });
                
                document.getElementById('findings-list').innerHTML = findingsHtml;
            })
            .catch(err => {
                document.getElementById('findings-list').innerHTML = `
                    <div class="no-findings">
                        <h2>⚠ Ошибка загрузки данных</h2>
                        <p>Не удалось загрузить JSON отчёт: ${err.message}</p>
                        <p>Проверьте наличие файла gitleaks-working-latest.json</p>
                    </div>
                `;
            });
    </script>
</body>
</html>
HTML_TEMPLATE

    # Копирование последнего JSON для HTML отчёта
    cp "$latest_json" "$REPORTS_DIR/gitleaks-working-latest.json"
    
    print_success "HTML отчёт создан: $html_report"
    print_info "Откройте в браузере: $html_report"
    
    return 0
}

# =============================================================================
# ПОЛНОЕ СКАНИРОВАНИЕ
# =============================================================================
scan_full() {
    print_section "ПОЛНОЕ СКАНИРОВАНИЕ"
    
    local total_exit_code=0
    
    # 1. Сканирование staged changes
    scan_staged || total_exit_code=$?
    
    # 2. Сканирование рабочей директории
    scan_working_dir || total_exit_code=$?
    
    # 3. Сканирование истории
    scan_history || total_exit_code=$?
    
    return $total_exit_code
}

# =============================================================================
# CI/CD РЕЖИМ
# =============================================================================
scan_ci() {
    print_section "CI/CD MODE"
    print_info "Запуск в режиме CI/CD..."
    
    # В CI режиме сканируем только изменения
    if [ -n "$CI_COMMIT_RANGE" ]; then
        print_info "Сканирование изменений в commit range: $CI_COMMIT_RANGE"
        
        gitleaks detect \
            --source "$PROJECT_ROOT" \
            --config "$GITLEAKS_CONFIG" \
            --log-opts "$CI_COMMIT_RANGE" \
            --report-path "$REPORTS_DIR/gitleaks-ci-${TIMESTAMP}.json" \
            --report-format json \
            --exit-code || return $?
    else
        print_info "CI_COMMIT_RANGE не установлен, сканирование HEAD"
        
        gitleaks detect \
            --source "$PROJECT_ROOT" \
            --config "$GITLEAKS_CONFIG" \
            --report-path "$REPORTS_DIR/gitleaks-ci-${TIMESTAMP}.json" \
            --report-format json \
            --exit-code || return $?
    fi
    
    return 0
}

# =============================================================================
# ВЫВОД СТАТИСТИКИ
# =============================================================================
print_statistics() {
    print_section "СТАТИСТИКА СКАНИРОВАНИЯ"
    
    local latest_json=$(ls -t "$REPORTS_DIR"/gitleaks-*.json 2>/dev/null | head -1)
    
    if [ -z "$latest_json" ]; then
        print_warning "Отчёты не найдены"
        return
    fi
    
    if command -v jq &> /dev/null; then
        local total=$(jq '.Report | length' "$latest_json" 2>/dev/null || echo "0")
        local files=$(jq '[.Report[].File] | unique | length' "$latest_json" 2>/dev/null || echo "0")
        local commits=$(jq '[.Report[].Commit] | unique | length' "$latest_json" 2>/dev/null || echo "0")
        
        echo ""
        echo -e "${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│           СТАТИСТИКА GITLEAKS                           │${NC}"
        echo -e "${CYAN}├─────────────────────────────────────────────────────────┤${NC}"
        printf "${CYAN}│${NC}  Всего уязвимостей:  %-35s ${CYAN}│${NC}\n" "$(if [ "$total" -gt 0 ]; then echo -e "${RED}$total${NC}"; else echo -e "${GREEN}$total${NC}"; fi)"
        printf "${CYAN}│${NC}  Затронуто файлов:   %-35s ${CYAN}│${NC}\n" "$files"
        printf "${CYAN}│${NC}  Затронуто коммитов: %-35s ${CYAN}│${NC}\n" "$commits"
        echo -e "${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
        echo ""
    else
        print_info "Установите jq для подробной статистики"
    fi
}

# =============================================================================
# ПОМОЩЬ
# =============================================================================
print_help() {
    echo ""
    echo "GitLeaks Scan Script - Проверка на секреты"
    echo ""
    echo "Использование:"
    echo "  ./scripts/gitleaks-scan.sh [OPTIONS]"
    echo ""
    echo "Опции:"
    echo "  --staged      Сканировать только staged changes"
    echo "  --history     Сканировать полную git историю"
    echo "  --report      Сгенерировать HTML отчёт"
    echo "  --install     Установить GitLeaks"
    echo "  --ci          Режим CI/CD"
    echo "  --help        Показать эту справку"
    echo ""
    echo "Примеры:"
    echo "  ./scripts/gitleaks-scan.sh                    # Полное сканирование"
    echo "  ./scripts/gitleaks-scan.sh --staged           # Только staged"
    echo "  ./scripts/gitleaks-scan.sh --report           # С отчётом"
    echo ""
}

# =============================================================================
# ПАРСИНГ АРГУМЕНТОВ
# =============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --staged)
            MODE_STAGED=true
            shift
            ;;
        --history)
            MODE_HISTORY=true
            shift
            ;;
        --report)
            MODE_REPORT=true
            shift
            ;;
        --install)
            MODE_INSTALL=true
            shift
            ;;
        --ci)
            MODE_CI=true
            shift
            ;;
        --help|-h)
            print_help
            exit 0
            ;;
        *)
            print_error "Неизвестная опция: $1"
            print_help
            exit 1
            ;;
    esac
done

# =============================================================================
# ОСНОВНАЯ ЛОГИКА
# =============================================================================
main() {
    print_header
    
    # Создание директории для отчётов
    mkdir -p "$REPORTS_DIR"
    
    # Режим установки
    if [ "$MODE_INSTALL" = true ]; then
        install_gitleaks
        exit $?
    fi
    
    # Проверка наличия gitleaks
    if ! check_gitleaks; then
        print_warning "GitLeaks не найден. Запуск установки..."
        install_gitleaks || exit 1
        
        # Повторная проверка
        if ! check_gitleaks; then
            print_error "Не удалось установить GitLeaks"
            exit 1
        fi
    fi
    
    # Проверка конфигурации
    check_config
    
    # Выполнение в зависимости от режима
    local exit_code=0
    
    if [ "$MODE_CI" = true ]; then
        scan_ci
        exit_code=$?
    elif [ "$MODE_STAGED" = true ]; then
        scan_staged
        exit_code=$?
    elif [ "$MODE_HISTORY" = true ]; then
        scan_history
        exit_code=$?
    elif [ "$MODE_REPORT" = true ]; then
        generate_html_report
        exit_code=$?
    else
        # Полное сканирование по умолчанию
        scan_full
        exit_code=$?
    fi
    
    # Вывод статистики
    print_statistics
    
    # Финальный статус
    echo ""
    if [ $exit_code -eq 0 ]; then
        print_success "╔═══════════════════════════════════════════════════════════╗"
        print_success "║  ✓ СКАНИРОВАНИЕ ЗАВЕРШЕНО - Уязвимости не обнаружены     ║"
        print_success "╚═══════════════════════════════════════════════════════════╝"
    else
        print_error "╔═══════════════════════════════════════════════════════════╗"
        print_error "║  ⚠ СКАНИРОВАНИЕ ЗАВЕРШЕНО - Обнаружены секреты!           ║"
        print_error "╚═══════════════════════════════════════════════════════════╝"
        echo ""
        print_warning "Рекомендации:"
        echo "  1. Проверьте отчёты в: $REPORTS_DIR"
        echo "  2. Удалите секреты из кода"
        echo "  3. Используйте переменные окружения"
        echo "  4. См. SECRETS_SCANNING.md для инструкций"
    fi
    
    exit $exit_code
}

# Запуск
main "$@"
