#!/bin/bash
#
# Dependency Check Script for Protocol Security Project
# Проверка устаревших и deprecated зависимостей
#
# Usage:
#   ./scripts/dependency-check.sh              # Полная проверка
#   ./scripts/dependency-check.sh --outdated   # Только устаревшие
#   ./scripts/dependency-check.sh --deprecated # Только deprecated
#   ./scripts/dependency-check.sh --report     # Генерация отчёта
#   ./scripts/dependency-check.sh --update     # Интерактивное обновление
#

set -e

# Цвета для вывода
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Конфигурация
CHECK_OUTDATED=true
CHECK_DEPRECATED=true
GENERATE_REPORT=false
INTERACTIVE_UPDATE=false
REPORT_DIR="./reports"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

# Парсинг аргументов
while [[ $# -gt 0 ]]; do
    case $1 in
        --outdated)
            CHECK_DEPRECATED=false
            shift
            ;;
        --deprecated)
            CHECK_OUTDATED=false
            shift
            ;;
        --report)
            GENERATE_REPORT=true
            shift
            ;;
        --update)
            INTERACTIVE_UPDATE=true
            shift
            ;;
        --help)
            echo "Dependency Check Script - Проверка зависимостей"
            echo ""
            echo "Использование:"
            echo "  ./scripts/dependency-check.sh [OPTIONS]"
            echo ""
            echo "Опции:"
            echo "  --outdated    Проверка только устаревших пакетов"
            echo "  --deprecated  Проверка только deprecated пакетов"
            echo "  --report      Генерация подробного отчёта"
            echo "  --update      Интерактивное обновление зависимостей"
            echo "  --help        Показать эту справку"
            exit 0
            ;;
        *)
            echo -e "${RED}Неизвестная опция: $1${NC}"
            exit 1
            ;;
    esac
done

# Логотип
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║      PROTOCOL SECURITY - DEPENDENCY CHECK                 ║"
echo "║      Проверка актуальности зависимостей                   ║"
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

# Функция для проверки npm outdated
check_outdated() {
    if [ "$CHECK_OUTDATED" = false ]; then
        return
    fi
    
    echo -e "${YELLOW}[1/3] Проверка устаревших зависимостей...${NC}"
    echo ""
    
    # Получаем список устаревших пакетов
    local outdated_output
    outdated_output=$(npm outdated 2>&1) || true
    
    if [ -z "$outdated_output" ] || [[ "$outdated_output" == *"up to date"* ]]; then
        echo -e "${GREEN}✓ Все зависимости актуальны${NC}"
        echo ""
        return 0
    fi
    
    echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│           УСТАРЕВШИЕ ЗАВИСИМОСТИ                            │${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    # Парсим вывод npm outdated
    echo "$outdated_output"
    echo ""
    
    # Подсчёт количества устаревших пакетов
    local outdated_count=$(echo "$outdated_output" | tail -n +2 | wc -l | tr -d ' ')
    
    if [ "$outdated_count" -gt 0 ]; then
        echo -e "${YELLOW}Найдено устаревших пакетов: ${outdated_count}${NC}"
        echo ""
        
        # Анализ по типам обновлений
        local major_updates=0
        local minor_updates=0
        local patch_updates=0
        
        while IFS= read -r line; do
            if [ -z "$line" ]; then continue; fi
            
            local current=$(echo "$line" | awk '{print $2}')
            local wanted=$(echo "$line" | awk '{print $3}')
            local latest=$(echo "$line" | awk '{print $4}')
            
            if [ -z "$current" ] || [ "$current" = "MISSING" ]; then continue; fi
            
            local current_major=$(echo "$current" | cut -d. -f1 | tr -d '^~')
            local latest_major=$(echo "$latest" | cut -d. -f1 | tr -d '^~')
            
            if [ "$current_major" != "$latest_major" ]; then
                ((major_updates++))
            else
                local current_minor=$(echo "$current" | cut -d. -f2 | tr -d '^~')
                local latest_minor=$(echo "$latest" | cut -d. -f2 | tr -d '^~')
                
                if [ "$current_minor" != "$latest_minor" ]; then
                    ((minor_updates++))
                else
                    ((patch_updates++))
                fi
            fi
        done <<< "$outdated_output"
        
        echo -e "${BLUE}Типы обновлений:${NC}"
        printf "  Major (breaking):  %-10s ${RED}← Требует внимания${NC}\n" "$major_updates"
        printf "  Minor (features):  %-10s ${YELLOW}← Рекомендуется${NC}\n" "$minor_updates"
        printf "  Patch (fixes):     %-10s ${GREEN}← Безопасно${NC}\n" "$patch_updates"
        echo ""
        
        return 1
    fi
    
    return 0
}

# Функция для проверки deprecated пакетов
check_deprecated() {
    if [ "$CHECK_DEPRECATED" = false ]; then
        return
    fi
    
    echo -e "${YELLOW}[2/3] Проверка deprecated зависимостей...${NC}"
    echo ""
    
    # Получаем список всех зависимостей
    local all_deps
    all_deps=$(npm list --json --depth=0 2>/dev/null) || all_deps="{}"
    
    # Проверяем каждый пакет на deprecated
    local deprecated_packages=()
    local dev_deps=$(echo "$all_deps" | jq -r '.devDependencies // {} | keys[]' 2>/dev/null || echo "")
    local deps=$(echo "$all_deps" | jq -r '.dependencies // {} | keys[]' 2>/dev/null || echo "")
    
    echo -e "${BLUE}Проверка пакетов на deprecated статус...${NC}"
    echo ""
    
    # Используем npm view для проверки каждого пакета
    for pkg in $deps $dev_deps; do
        if [ -z "$pkg" ]; then continue; fi
        
        local pkg_info
        pkg_info=$(npm view "$pkg" --json 2>/dev/null) || continue
        
        local deprecated=$(echo "$pkg_info" | jq -r '.deprecated // empty' 2>/dev/null)
        
        if [ -n "$deprecated" ] && [ "$deprecated" != "null" ]; then
            deprecated_packages+=("$pkg: $deprecated")
            echo -e "  ${RED}✗${NC} $pkg"
            echo -e "    ${YELLOW}Deprecated: $deprecated${NC}"
        else
            echo -e "  ${GREEN}✓${NC} $pkg"
        fi
    done
    
    echo ""
    
    if [ ${#deprecated_packages[@]} -gt 0 ]; then
        echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  ⚠ ОБНАРУЖЕНЫ DEPRECATED ПАКЕТЫ                           ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}Список deprecated пакетов:${NC}"
        for pkg in "${deprecated_packages[@]}"; do
            echo "  • $pkg"
        done
        echo ""
        echo -e "${RED}Рекомендация: Немедленно найдите замену этим пакетам!${NC}"
        return 1
    else
        echo -e "${GREEN}✓ Deprecated пакеты не обнаружены${NC}"
        return 0
    fi
}

# Функция для проверки security advisories
check_security_advisories() {
    echo -e "${YELLOW}[3/3] Проверка security advisories...${NC}"
    echo ""
    
    # Получаем JSON аудит
    local audit_json
    audit_json=$(npm audit --json 2>/dev/null) || audit_json="{}"
    
    local advisories=$(echo "$audit_json" | jq -r '.advisories // {}' 2>/dev/null)
    local advisory_count=$(echo "$advisories" | jq 'keys | length' 2>/dev/null || echo "0")
    
    if [ "$advisory_count" -gt 0 ]; then
        echo -e "${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${BLUE}│           SECURITY ADVISORIES                               │${NC}"
        echo -e "${BLUE}└─────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        
        echo "$advisories" | jq -r '
            to_entries[] |
            "  • " + .value.module_name + " (" + .value.vulnerable_versions + "):" +
            "\n    Title: " + .value.title +
            "\n    Severity: " + .value.severity +
            "\n    CVE: " + (if .value.cves then (.value.cves | join(", ")) else "N/A" end) +
            "\n    Recommendation: " + .value.recommendation +
            "\n"
        ' 2>/dev/null || echo "  (Не удалось получить детали)"
        
        return 1
    else
        echo -e "${GREEN}✓ Security advisories не обнаружены${NC}"
        return 0
    fi
}

# Функция для интерактивного обновления
interactive_update() {
    if [ "$INTERACTIVE_UPDATE" = false ]; then
        return
    fi
    
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}         ИНТЕРАКТИВНОЕ ОБНОВЛЕНИЕ ЗАВИСИМОСТЕЙ              ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo "Выберите действие:"
    echo "  1) Обновить все безопасные пакеты (patch/minor)"
    echo "  2) Обновить конкретный пакет"
    echo "  3) Обновить через npm update"
    echo "  4) Пропустить обновление"
    echo ""
    
    read -p "Ваш выбор [1-4]: " choice
    
    case $choice in
        1)
            echo -e "${YELLOW}Обновление безопасных пакетов...${NC}"
            npm update --save
            ;;
        2)
            read -p "Введите имя пакета: " pkg_name
            if [ -n "$pkg_name" ]; then
                echo -e "${YELLOW}Обновление $pkg_name...${NC}"
                npm install "$pkg_name"@latest --save
            fi
            ;;
        3)
            echo -e "${YELLOW}Запуск npm update...${NC}"
            npm update
            ;;
        4)
            echo -e "${YELLOW}Пропуск обновления${NC}"
            ;;
        *)
            echo -e "${RED}Неверный выбор${NC}"
            ;;
    esac
}

# Функция для генерации отчёта
generate_report() {
    if [ "$GENERATE_REPORT" = false ]; then
        return
    fi
    
    echo -e "${YELLOW}Генерация отчёта...${NC}"
    
    # Создаём директорию для отчётов
    mkdir -p "$REPORT_DIR"
    
    # Генерируем JSON отчёт
    {
        echo "{"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"project\": \"$(jq -r '.name // "unknown"' package.json)\","
        echo "  \"version\": \"$(jq -r '.version // "unknown"' package.json)\","
        echo "  \"outdated\": $(npm outdated --json 2>/dev/null || echo '{}'),"
        echo "  \"dependencies\": $(npm list --json --depth=0 2>/dev/null || echo '{}')"
        echo "}"
    } > "${REPORT_DIR}/dependency-check-${TIMESTAMP}.json"
    
    # Генерируем текстовый отчёт
    {
        echo "═══════════════════════════════════════════════════════════"
        echo "       PROTOCOL SECURITY - DEPENDENCY CHECK REPORT"
        echo "       Отчёт о проверке зависимостей"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "Дата: $(date)"
        echo "Проект: $(jq -r '.name // "unknown"' package.json)"
        echo "Версия: $(jq -r '.version // "unknown"' package.json)"
        echo ""
        echo "───────────────────────────────────────────────────────────"
        echo "УСТАРЕВШИЕ ЗАВИСИМОСТИ (npm outdated)"
        echo "───────────────────────────────────────────────────────────"
        npm outdated 2>&1 || echo "(нет устаревших)"
        echo ""
        echo "───────────────────────────────────────────────────────────"
        echo "ДЕРЕВО ЗАВИСИМОСТЕЙ"
        echo "───────────────────────────────────────────────────────────"
        npm list --depth=0 2>&1 || true
        echo ""
        echo "───────────────────────────────────────────────────────────"
        echo "SECURITY ADVISORIES"
        echo "───────────────────────────────────────────────────────────"
        npm audit 2>&1 | head -50 || echo "(нет advisories)"
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo "КОНЕЦ ОТЧЁТА"
        echo "═══════════════════════════════════════════════════════════"
    } > "${REPORT_DIR}/dependency-report-${TIMESTAMP}.txt"
    
    echo -e "${GREEN}Отчёты сохранены:${NC}"
    echo "  • ${REPORT_DIR}/dependency-check-${TIMESTAMP}.json"
    echo "  • ${REPORT_DIR}/dependency-report-${TIMESTAMP}.txt"
}

# Основная функция
main() {
    local start_time=$(date +%s)
    
    echo -e "${BLUE}Начало проверки: $(date)${NC}"
    echo ""
    
    # Предварительные проверки
    check_npm
    check_package_json
    
    # Проверка устаревших
    local outdated_result=0
    check_outdated || outdated_result=$?
    
    # Проверка deprecated
    local deprecated_result=0
    check_deprecated || deprecated_result=$?
    
    # Проверка security advisories
    local security_result=0
    check_security_advisories || security_result=$?
    
    # Интерактивное обновление
    interactive_update
    
    # Генерация отчёта
    generate_report
    
    # Подсчёт времени
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo ""
    echo -e "${BLUE}Время выполнения: ${duration} сек${NC}"
    
    # Финальный статус
    echo ""
    if [ $outdated_result -eq 0 ] && [ $deprecated_result -eq 0 ] && [ $security_result -eq 0 ]; then
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  ✓ CHECK PASSED - Все зависимости в порядке               ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║  ⚠ CHECK WARNING - Требуются обновления                   ║${NC}"
        echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}Рекомендации:${NC}"
        echo "  1. Запустите 'npm update' для безопасных обновлений"
        echo "  2. Проверьте SECURITY_AUDIT.md для инструкций"
        echo "  3. Для major обновлений тестируйте изменения"
        exit 1
    fi
}

# Запуск
main "$@"
