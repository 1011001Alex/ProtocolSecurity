#!/bin/bash
#
# Security Audit Script for Protocol Security Project
# Выполняет полную проверку зависимостей на уязвимости
#
# Usage:
#   ./scripts/security-audit.sh                    # Полный аудит
#   ./scripts/security-audit.sh --json             # JSON вывод
#   ./scripts/security-audit.sh --level=high       # Только high/critical
#   ./scripts/security-audit.sh --fix              # Автофикс
#   ./scripts/security-audit.sh --report           # Генерация отчёта
#

set -e

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Конфигурация
AUDIT_LEVEL="moderate"
OUTPUT_FORMAT="text"
GENERATE_REPORT=false
AUTO_FIX=false
REPORT_DIR="./reports"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# Парсинг аргументов
while [[ $# -gt 0 ]]; do
    case $1 in
        --json)
            OUTPUT_FORMAT="json"
            shift
            ;;
        --level=*)
            AUDIT_LEVEL="${1#*=}"
            shift
            ;;
        --fix)
            AUTO_FIX=true
            shift
            ;;
        --report)
            GENERATE_REPORT=true
            shift
            ;;
        --help)
            echo "Security Audit Script - Проверка уязвимостей зависимостей"
            echo ""
            echo "Использование:"
            echo "  ./scripts/security-audit.sh [OPTIONS]"
            echo ""
            echo "Опции:"
            echo "  --json          Вывод в формате JSON"
            echo "  --level=LEVEL   Уровень аудита (low|moderate|high|critical)"
            echo "  --fix           Автоматическое исправление уязвимостей"
            echo "  --report        Генерация подробного отчёта"
            echo "  --help          Показать эту справку"
            exit 0
            ;;
        *)
            echo -e "${RED}Неизвестная опция: $1${NC}"
            exit 1
            ;;
    esac
done

# Логотип
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║         PROTOCOL SECURITY - SECURITY AUDIT                ║"
echo "║         Проверка зависимостей на уязвимости               ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Функция для проверки наличия npm
check_npm() {
    if ! command -v npm &> /dev/null; then
        echo -e "${RED}Ошибка: npm не найден. Установите Node.js${NC}"
        exit 1
    fi
}

# Функция для проверки package.json
check_package_json() {
    if [ ! -f "package.json" ]; then
        echo -e "${RED}Ошибка: package.json не найден в текущей директории${NC}"
        exit 1
    fi
}

# Функция для установки зависимостей перед аудитом
install_dependencies() {
    echo -e "${YELLOW}[1/4] Проверка node_modules...${NC}"
    if [ ! -d "node_modules" ]; then
        echo -e "${YELLOW}node_modules не найден. Установка зависимостей...${NC}"
        npm ci --prefer-offline || npm install
    else
        echo -e "${GREEN}node_modules найден${NC}"
    fi
}

# Функция для выполнения npm audit
run_npm_audit() {
    echo -e "${YELLOW}[2/4] Запуск npm audit (уровень: ${AUDIT_LEVEL})...${NC}"
    
    if [ "$AUTO_FIX" = true ]; then
        echo -e "${YELLOW}Попытка автоматического исправления уязвимостей...${NC}"
        npm audit fix --audit-level=${AUDIT_LEVEL} || true
    fi
    
    # Выполнение аудита
    if [ "$OUTPUT_FORMAT" = "json" ]; then
        npm audit --audit-level=${AUDIT_LEVEL} --json > audit-results.json 2>&1 || true
        echo -e "${GREEN}Результаты сохранены в audit-results.json${NC}"
    else
        npm audit --audit-level=${AUDIT_LEVEL} || AUDIT_EXIT_CODE=$?
    fi
}

# Функция для проверки на CVE
check_cve() {
    echo -e "${YELLOW}[3/4] Проверка на известные CVE...${NC}"
    
    # Получаем JSON аудит для анализа
    local audit_json
    audit_json=$(npm audit --json 2>/dev/null) || audit_json="{}"
    
    # Извлекаем количество уязвимостей
    local total_vulns=$(echo "$audit_json" | jq -r '.metadata.vulnerabilities.total // 0' 2>/dev/null || echo "0")
    local critical_vulns=$(echo "$audit_json" | jq -r '.metadata.vulnerabilities.critical // 0' 2>/dev/null || echo "0")
    local high_vulns=$(echo "$audit_json" | jq -r '.metadata.vulnerabilities.high // 0' 2>/dev/null || echo "0")
    local moderate_vulns=$(echo "$audit_json" | jq -r '.metadata.vulnerabilities.moderate // 0' 2>/dev/null || echo "0")
    local low_vulns=$(echo "$audit_json" | jq -r '.metadata.vulnerabilities.low // 0' 2>/dev/null || echo "0")
    
    echo ""
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│           СТАТИСТИКА УЯЗВИМОСТЕЙ                        │${NC}"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────┤${NC}"
    printf "${BLUE}│${NC}  Critical:  %-45s ${BLUE}│${NC}\n" "$(if [ "$critical_vulns" -gt 0 ]; then echo -e "${RED}$critical_vulns${NC}"; else echo "$critical_vulns"; fi)"
    printf "${BLUE}│${NC}  High:      %-45s ${BLUE}│${NC}\n" "$(if [ "$high_vulns" -gt 0 ]; then echo -e "${RED}$high_vulns${NC}"; else echo "$high_vulns"; fi)"
    printf "${BLUE}│${NC}  Moderate:  %-45s ${BLUE}│${NC}\n" "$(if [ "$moderate_vulns" -gt 0 ]; then echo -e "${YELLOW}$moderate_vulns${NC}"; else echo "$moderate_vulns"; fi)"
    printf "${BLUE}│${NC}  Low:       %-45s ${BLUE}│${NC}\n" "$(if [ "$low_vulns" -gt 0 ]; then echo -e "${YELLOW}$low_vulns${NC}"; else echo "$low_vulns"; fi)"
    echo -e "${BLUE}├─────────────────────────────────────────────────────────┤${NC}"
    printf "${BLUE}│${NC}  TOTAL:     %-45s ${BLUE}│${NC}\n" "$total_vulns"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # Проверка на критические уязвимости
    if [ "$critical_vulns" -gt 0 ] || [ "$high_vulns" -gt 0 ]; then
        echo -e "${RED}⚠️  ОБНАРУЖЕНЫ КРИТИЧЕСКИЕ УЯЗВИМОСТИ!${NC}"
        echo -e "${RED}Требуется немедленное вмешательство!${NC}"
        echo ""
        
        # Вывод списка уязвимостей с CVE
        echo -e "${YELLOW}Список уязвимостей:${NC}"
        npm audit --json 2>/dev/null | jq -r '
            .vulnerabilities[]? |
            "  • \(.module_name)@\(.version) - \(.severity): \(.title)" +
            (if .cves and (.cves | length > 0) then " [CVE: \(.cves | join(", "))]" else "" end)
        ' 2>/dev/null || echo "  (Не удалось получить детали)"
        
        return 1
    else
        echo -e "${GREEN}✓ Критические уязвимости не обнаружены${NC}"
        return 0
    fi
}

# Функция для генерации отчёта
generate_report() {
    if [ "$GENERATE_REPORT" = false ]; then
        return
    fi
    
    echo -e "${YELLOW}[4/4] Генерация отчёта...${NC}"
    
    # Создаём директорию для отчётов
    mkdir -p "$REPORT_DIR"
    
    # Генерируем полный JSON отчёт
    npm audit --json > "${REPORT_DIR}/audit-${TIMESTAMP}.json" 2>/dev/null || true
    
    # Генерируем текстовый отчёт
    {
        echo "═══════════════════════════════════════════════════════════"
        echo "       PROTOCOL SECURITY - SECURITY AUDIT REPORT"
        echo "       Отчёт о проверке зависимостей на уязвимости"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "Дата: $(date)"
        echo "Проект: $(jq -r '.name // "unknown"' package.json)"
        echo "Версия: $(jq -r '.version // "unknown"' package.json)"
        echo ""
        echo "───────────────────────────────────────────────────────────"
        echo "РЕЗУЛЬТАТЫ NPM AUDIT"
        echo "───────────────────────────────────────────────────────────"
        npm audit --audit-level=${AUDIT_LEVEL} 2>&1 || true
        echo ""
        echo "───────────────────────────────────────────────────────────"
        echo "СПИСОК ЗАВИСИМОСТЕЙ"
        echo "───────────────────────────────────────────────────────────"
        npm list --depth=0 2>&1 || true
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo "КОНЕЦ ОТЧЁТА"
        echo "═══════════════════════════════════════════════════════════"
    } > "${REPORT_DIR}/audit-report-${TIMESTAMP}.txt"
    
    echo -e "${GREEN}Отчёты сохранены:${NC}"
    echo "  • ${REPORT_DIR}/audit-${TIMESTAMP}.json"
    echo "  • ${REPORT_DIR}/audit-report-${TIMESTAMP}.txt"
}

# Функция для отправки уведомления в Slack (если настроено)
send_slack_notification() {
    if [ -z "$SLACK_WEBHOOK_URL" ]; then
        return
    fi
    
    local status=$1
    local vuln_count=$2
    
    local payload=$(cat <<EOF
{
    "text": "🔒 Protocol Security Audit",
    "attachments": [{
        "color": "$(if [ "$status" = "0" ]; then echo "good"; else echo "danger"; fi)",
        "fields": [
            {"title": "Status", "value": "$(if [ "$status" = "0" ]; then echo "✅ Passed"; else echo "❌ Failed"; fi)", "short": true},
            {"title": "Vulnerabilities", "value": "$vuln_count", "short": true},
            {"title": "Project", "value": "$(jq -r '.name // "unknown"' package.json)", "short": true},
            {"title": "Branch", "value": "${GIT_BRANCH:-unknown}", "short": true}
        ]
    }]
}
EOF
)
    
    curl -s -X POST -H 'Content-type: application/json' \
        --data "$payload" \
        "$SLACK_WEBHOOK_URL" || true
}

# Основная функция
main() {
    local start_time=$(date +%s)
    
    echo -e "${BLUE}Начало проверки: $(date)${NC}"
    echo ""
    
    # Предварительные проверки
    check_npm
    check_package_json
    install_dependencies
    
    # Запуск аудита
    run_npm_audit
    local audit_result=$?
    
    # Проверка CVE
    check_cve
    local cve_result=$?
    
    # Генерация отчёта
    generate_report
    
    # Подсчёт времени
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo ""
    echo -e "${BLUE}Время выполнения: ${duration} сек${NC}"
    
    # Отправка уведомления в Slack
    send_slack_notification "$audit_result" "$(npm audit --json 2>/dev/null | jq -r '.metadata.vulnerabilities.total // 0' || echo 0)"
    
    # Финальный статус
    echo ""
    if [ $audit_result -eq 0 ] && [ $cve_result -eq 0 ]; then
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  ✓ AUDIT PASSED - Уязвимости не обнаружены                ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ⚠ AUDIT FAILED - Обнаружены уязвимости                   ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}Рекомендации:${NC}"
        echo "  1. Запустите 'npm audit fix' для автоматического исправления"
        echo "  2. Проверьте SECURITY_AUDIT.md для инструкций"
        echo "  3. Обновите уязвимые пакеты вручную при необходимости"
        exit 1
    fi
}

# Запуск
main "$@"
