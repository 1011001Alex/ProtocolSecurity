#!/bin/bash
# =============================================================================
# TRUFFLEHOG SCAN SCRIPT FOR PROTOCOL SECURITY
# =============================================================================
# Скрипт для запуска TruffleHog с проверкой git history и filesystem
# Интеграция с CI/CD, поддержка различных режимов сканирования
# =============================================================================
#
# Usage:
#   ./scripts/trufflehog-scan.sh                    # Полное сканирование
#   ./scripts/trufflehog-scan.sh --git              # Только git history
#   ./scripts/trufflehog-scan.sh --filesystem       # Только filesystem
#   ./scripts/trufflehog-scan.sh --ci               # CI/CD режим
#   ./scripts/trufflehog-scan.sh --install          # Установка trufflehog
#   ./scripts/trufflehog-scan.sh --help             # Помощь
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
TRUFFLEHOG_VERSION="3.63.0"

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
MODE_GIT=false
MODE_FILESYSTEM=false
MODE_CI=false
MODE_INSTALL=false
MODE_VERBOSE=false
MODE_JSON=false

# =============================================================================
# ФУНКЦИИ ВЫВОДА
# =============================================================================
print_header() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║       PROTOCOL SECURITY - TRUFFLEHOG SCANNER              ║"
    echo "║       Deep search for secrets in git history              ║"
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
# ПРОВЕРКА НАЛИЧИЯ TRUFFLEHOG
# =============================================================================
check_trufflehog() {
    if command -v trufflehog &> /dev/null; then
        local version=$(trufflehog --version 2>&1 | head -1)
        print_success "TruffleHog обнаружен: $version"
        return 0
    else
        print_warning "TruffleHog не найден в PATH"
        return 1
    fi
}

# =============================================================================
# УСТАНОВКА TRUFFLEHOG
# =============================================================================
install_trufflehog() {
    print_section "УСТАНОВКА TRUFFLEHOG"
    
    # Проверка наличия package manager
    if command -v brew &> /dev/null; then
        print_info "Установка через Homebrew..."
        brew install trufflehog
        return $?
    fi
    
    if command -v apt-get &> /dev/null; then
        print_info "Установка через apt..."
        # TruffleHog требует Go для сборки
        sudo apt-get update
        sudo apt-get install -y golang-go
        go install github.com/trufflesecurity/trufflehog/v3@latest
        return $?
    fi
    
    if command -v choco &> /dev/null; then
        print_info "Установка через Chocolatey (Windows)..."
        choco install trufflehog -y
        return $?
    fi
    
    if command -v winget &> /dev/null; then
        print_info "Установка через Winget (Windows)..."
        winget install --id trufflesecurity.trufflehog -e
        return $?
    fi
    
    # Установка через Go
    if command -v go &> /dev/null; then
        print_info "Установка через Go..."
        go install github.com/trufflesecurity/trufflehog/v3@latest
        
        # Добавление в PATH
        local go_bin="$HOME/go/bin"
        if [ -d "$go_bin" ]; then
            print_info "TruffleHog установлен в: $go_bin/trufflehog"
            print_info "Добавьте ~/go/bin в PATH:"
            echo 'export PATH="$HOME/go/bin:$PATH"'
        fi
        
        return $?
    fi
    
    print_error "Не найдено подходящего способа установки"
    print_info "Установите Go и выполните: go install github.com/trufflesecurity/trufflehog/v3@latest"
    return 1
}

# =============================================================================
# СКАНИРОВАНИЕ GIT HISTORY
# =============================================================================
scan_git() {
    print_section "СКАНИРОВАНИЕ GIT HISTORY"
    print_info "Глубокая проверка истории коммитов..."
    
    local exit_code=0
    local report_file="$REPORTS_DIR/trufflehog-git-${TIMESTAMP}.json"
    
    mkdir -p "$REPORTS_DIR"
    
    if [ "$MODE_JSON" = true ] || [ "$MODE_CI" = true ]; then
        trufflehog git file://. \
            --json \
            --fail \
            --no-update \
            2>&1 | tee "$report_file" || exit_code=$?
    else
        trufflehog git file://. \
            --fail \
            --no-update \
            2>&1 || exit_code=$?
    fi
    
    if [ $exit_code -eq 0 ]; then
        print_success "Git history: уязвимости не обнаружены"
    else
        print_error "Git history: обнаружены секреты!"
    fi
    
    return $exit_code
}

# =============================================================================
# СКАНИРОВАНИЕ FILESYSTEM
# =============================================================================
scan_filesystem() {
    print_section "СКАНИРОВАНИЕ FILESYSTEM"
    print_info "Сканирование файловой системы проекта..."
    
    local exit_code=0
    local report_file="$REPORTS_DIR/trufflehog-fs-${TIMESTAMP}.json"
    
    mkdir -p "$REPORTS_DIR"
    
    # Исключаемые директории
    local exclude_dirs="--exclude-dirs=node_modules,dist,build,coverage,vendor,.git,tmp"
    
    if [ "$MODE_JSON" = true ] || [ "$MODE_CI" = true ]; then
        trufflehog filesystem . \
            $exclude_dirs \
            --json \
            --fail \
            --no-update \
            2>&1 | tee "$report_file" || exit_code=$?
    else
        trufflehog filesystem . \
            $exclude_dirs \
            --fail \
            --no-update \
            2>&1 || exit_code=$?
    fi
    
    if [ $exit_code -eq 0 ]; then
        print_success "Filesystem: уязвимости не обнаружены"
    else
        print_error "Filesystem: обнаружены секреты!"
    fi
    
    return $exit_code
}

# =============================================================================
# СКАНИРОВАНИЕ UNCOMMITTED CHANGES
# =============================================================================
scan_uncommitted() {
    print_section "СКАНИРОВАНИЕ UNCOMMITTED CHANGES"
    print_info "Проверка незакоммиченных изменений..."
    
    local exit_code=0
    
    # Проверка наличия изменений
    if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
        print_info "Нет незакоммиченных изменений"
        return 0
    fi
    
    if [ "$MODE_JSON" = true ] || [ "$MODE_CI" = true ]; then
        trufflehog git diff:// \
            --json \
            --fail \
            --no-update \
            2>&1 || exit_code=$?
    else
        trufflehog git diff:// \
            --fail \
            --no-update \
            2>&1 || exit_code=$?
    fi
    
    if [ $exit_code -eq 0 ]; then
        print_success "Uncommitted changes: уязвимости не обнаружены"
    else
        print_error "Uncommitted changes: обнаружены секреты!"
    fi
    
    return $exit_code
}

# =============================================================================
# СКАНИРОВАНИЕ S3 BUCKETS (если настроено)
# =============================================================================
scan_s3() {
    print_section "СКАНИРОВАНИЕ S3 BUCKETS"
    
    if [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
        print_warning "AWS credentials не настроены. Пропуск S3 сканирования."
        return 0
    fi
    
    print_info "Сканирование S3 buckets..."
    
    local exit_code=0
    
    trufflehog s3 \
        --json \
        --fail \
        2>&1 || exit_code=$?
    
    return $exit_code
}

# =============================================================================
# СКАНИРОВАНИЕ GITHUB REPO (если настроено)
# =============================================================================
scan_github() {
    print_section "СКАНИРОВАНИЕ GITHUB"
    
    if [ -z "$GITHUB_TOKEN" ]; then
        print_warning "GITHUB_TOKEN не настроен. Пропуск GitHub сканирования."
        return 0
    fi
    
    local repo_url="${GITHUB_REPO:-}"
    
    if [ -z "$repo_url" ]; then
        # Попытка получить URL из git remote
        repo_url=$(git remote get-url origin 2>/dev/null | sed 's/git@github.com:/https:\/\/github.com\//' | sed 's/\.git$//')
    fi
    
    if [ -z "$repo_url" ]; then
        print_warning "Не удалось определить GitHub репозиторий"
        return 0
    fi
    
    print_info "Сканирование GitHub репозитория: $repo_url"
    
    local exit_code=0
    
    trufflehog github \
        --repo "$repo_url" \
        --json \
        --fail \
        2>&1 || exit_code=$?
    
    return $exit_code
}

# =============================================================================
# ПОЛНОЕ СКАНИРОВАНИЕ
# =============================================================================
scan_full() {
    print_section "ПОЛНОЕ СКАНИРОВАНИЕ"
    
    local total_exit_code=0
    
    # 1. Сканирование uncommitted changes
    scan_uncommitted || total_exit_code=$?
    
    # 2. Сканирование git history
    scan_git || total_exit_code=$?
    
    # 3. Сканирование filesystem
    scan_filesystem || total_exit_code=$?
    
    return $total_exit_code
}

# =============================================================================
# CI/CD РЕЖИМ
# =============================================================================
scan_ci() {
    print_section "CI/CD MODE"
    print_info "Запуск в режиме CI/CD с JSON выводом..."
    
    MODE_JSON=true
    
    local total_exit_code=0
    
    # В CI режиме сканируем только изменения
    if [ -n "$CI_COMMIT_RANGE" ]; then
        print_info "Сканирование изменений: $CI_COMMIT_RANGE"
        
        trufflehog git file://. \
            --json \
            --fail \
            --no-update \
            2>&1 | tee "$REPORTS_DIR/trufflehog-ci-${TIMESTAMP}.json" || total_exit_code=$?
    else
        # Полное сканирование в JSON формате
        scan_full || total_exit_code=$?
    fi
    
    return $total_exit_code
}

# =============================================================================
# ГЕНЕРАЦИЯ ОТЧЁТА
# =============================================================================
generate_report() {
    print_section "ГЕНЕРАЦИЯ ОТЧЁТА"
    
    mkdir -p "$REPORTS_DIR"
    
    # Поиск последнего JSON отчёта
    local latest_json=$(ls -t "$REPORTS_DIR"/trufflehog-*.json 2>/dev/null | head -1)
    
    if [ -z "$latest_json" ]; then
        print_warning "JSON отчёты не найдены"
        return 1
    fi
    
    print_info "Последний отчёт: $latest_json"
    
    # Подсчёт статистики
    if command -v jq &> /dev/null; then
        local total=$(jq -s 'length' "$latest_json" 2>/dev/null || echo "0")
        local detectors=$(jq -s '[.[].DetectorType] | unique | length' "$latest_json" 2>/dev/null || echo "0")
        
        echo ""
        echo -e "${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│           СТАТИСТИКА TRUFFLEHOG                         │${NC}"
        echo -e "${CYAN}├─────────────────────────────────────────────────────────┤${NC}"
        printf "${CYAN}│${NC}  Всего находок:      %-35s ${CYAN}│${NC}\n" "$(if [ "$total" -gt 0 ]; then echo -e "${RED}$total${NC}"; else echo -e "${GREEN}$total${NC}"; fi)"
        printf "${CYAN}│${NC}  Детекторов:         %-35s ${CYAN}│${NC}\n" "$detectors"
        echo -e "${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
        echo ""
        
        # Вывод топ находок
        if [ "$total" -gt 0 ]; then
            print_info "Топ находок:"
            jq -s '.[0:5] | .[] | "  • \(.DetectorType) в \(.SourceMetadata.Data.Filesystem.path // .SourceMetadata.Data.Git.file)"' "$latest_json" 2>/dev/null || true
        fi
    fi
    
    return 0
}

# =============================================================================
# ВЫВОД СТАТИСТИКИ
# =============================================================================
print_statistics() {
    print_section "СТАТИСТИКА СКАНИРОВАНИЯ"
    
    local git_json=$(ls -t "$REPORTS_DIR"/trufflehog-git-*.json 2>/dev/null | head -1)
    local fs_json=$(ls -t "$REPORTS_DIR"/trufflehog-fs-*.json 2>/dev/null | head -1)
    
    local total_findings=0
    local total_detectors=0
    
    if command -v jq &> /dev/null; then
        if [ -n "$git_json" ]; then
            local git_count=$(jq -s 'length' "$git_json" 2>/dev/null || echo "0")
            total_findings=$((total_findings + git_count))
        fi
        
        if [ -n "$fs_json" ]; then
            local fs_count=$(jq -s 'length' "$fs_json" 2>/dev/null || echo "0")
            total_findings=$((total_findings + fs_count))
        fi
        
        echo ""
        echo -e "${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}│           ОБЩАЯ СТАТИСТИКА                              │${NC}"
        echo -e "${CYAN}├─────────────────────────────────────────────────────────┤${NC}"
        printf "${CYAN}│${NC}  Всего находок:      %-35s ${CYAN}│${NC}\n" "$(if [ "$total_findings" -gt 0 ]; then echo -e "${RED}$total_findings${NC}"; else echo -e "${GREEN}$total_findings${NC}"; fi)"
        echo -e "${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
        echo ""
    fi
}

# =============================================================================
# ПОМОЩЬ
# =============================================================================
print_help() {
    echo ""
    echo "TruffleHog Scan Script - Deep secrets detection"
    echo ""
    echo "Использование:"
    echo "  ./scripts/trufflehog-scan.sh [OPTIONS]"
    echo ""
    echo "Опции:"
    echo "  --git         Сканировать только git history"
    echo "  --filesystem  Сканировать только filesystem"
    echo "  --ci          Режим CI/CD с JSON выводом"
    echo "  --install     Установить TruffleHog"
    echo "  --verbose     Подробный вывод"
    echo "  --json        JSON вывод результатов"
    echo "  --help        Показать эту справку"
    echo ""
    echo "Примеры:"
    echo "  ./scripts/trufflehog-scan.sh                    # Полное сканирование"
    echo "  ./scripts/trufflehog-scan.sh --git              # Только git"
    echo "  ./scripts/trufflehog-scan.sh --ci               # CI/CD режим"
    echo ""
    echo "Переменные окружения:"
    echo "  GITHUB_TOKEN    Токен для сканирования GitHub"
    echo "  AWS_ACCESS_KEY_ID     AWS credentials для S3"
    echo "  AWS_SECRET_ACCESS_KEY"
    echo ""
}

# =============================================================================
# ПАРСИНГ АРГУМЕНТОВ
# =============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --git)
            MODE_GIT=true
            shift
            ;;
        --filesystem)
            MODE_FILESYSTEM=true
            shift
            ;;
        --ci)
            MODE_CI=true
            shift
            ;;
        --install)
            MODE_INSTALL=true
            shift
            ;;
        --verbose|-v)
            MODE_VERBOSE=true
            shift
            ;;
        --json)
            MODE_JSON=true
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
        install_trufflehog
        exit $?
    fi
    
    # Проверка наличия trufflehog
    if ! check_trufflehog; then
        print_warning "TruffleHog не найден. Запуск установки..."
        install_trufflehog || exit 1
        
        # Повторная проверка
        if ! check_trufflehog; then
            print_error "Не удалось установить TruffleHog"
            exit 1
        fi
    fi
    
    # Проверка наличия git
    if ! command -v git &> /dev/null; then
        print_error "Git не найден. TruffleHog требует Git."
        exit 1
    fi
    
    # Проверка, что мы в git репозитории
    if ! git rev-parse --git-dir &> /dev/null; then
        print_warning "Текущая директория не является git репозиторием"
        print_info "Будет выполнено только filesystem сканирование"
        MODE_GIT=false
        MODE_FILESYSTEM=true
    fi
    
    # Выполнение в зависимости от режима
    local exit_code=0
    
    if [ "$MODE_CI" = true ]; then
        scan_ci
        exit_code=$?
    elif [ "$MODE_GIT" = true ]; then
        scan_git
        exit_code=$?
    elif [ "$MODE_FILESYSTEM" = true ]; then
        scan_filesystem
        exit_code=$?
    else
        # Полное сканирование по умолчанию
        scan_full
        exit_code=$?
    fi
    
    # Генерация отчёта
    generate_report
    
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
        echo "  2. Немедленно удалите секреты из кода"
        echo "  3. Смените скомпрометированные ключи"
        echo "  4. См. SECRETS_SCANNING.md для инструкций"
    fi
    
    exit $exit_code
}

# Запуск
main "$@"
