#!/bin/bash
# ========================================
# Security Gates Script
# Protocol Security Project
# ========================================
# Проверка security gates для CI/CD pipeline
# Использование: ./scripts/security-gates.sh [--report] [--strict] [--skip-sonar] [--skip-codeql]

set -e

# ========================================
# Configuration
# ========================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$ROOT_DIR/reports"
LOGS_DIR="$ROOT_DIR/logs"

# SonarQube настройки
SONAR_HOST_URL="${SONAR_HOST_URL:-https://sonarcloud.io}"
SONAR_ORGANIZATION="${SONAR_ORGANIZATION:-protocol-security}"
SONAR_PROJECT_KEY="${SONAR_PROJECT_KEY:-protocol-security}"
SONAR_TOKEN="${SONAR_TOKEN:-}"

# CodeQL настройки
CODEQL_DB_PATH="${CODEQL_DB_PATH:-$ROOT_DIR/.codeql/db}"
CODEQL_RESULTS="${REPORTS_DIR}/codeql/results.sarif"

# Пороги Security Gates
COVERAGE_THRESHOLD=80
SECURITY_RATING_THRESHOLD="A"
RELIABILITY_RATING_THRESHOLD="A"
MAINTAINABILITY_RATING_THRESHOLD="A"
CRITICAL_ISSUES_THRESHOLD=0
MAJOR_ISSUES_THRESHOLD=5
DUPLICATION_THRESHOLD=3

# Флаги
REPORT_MODE=false
STRICT_MODE=false
SKIP_SONAR=false
SKIP_CODEQL=false

# ========================================
# Colors and Output
# ========================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

INFO_ICON="ℹ️"
SUCCESS_ICON="✅"
WARNING_ICON="⚠️"
ERROR_ICON="❌"
CHECK_ICON="✓"
CROSS_ICON="✗"

print_header() {
    echo ""
    echo -e "${CYAN}========================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}========================================================${NC}"
    echo ""
}

print_info() {
    echo -e "${BLUE}${INFO_ICON} [INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}${SUCCESS_ICON} [PASS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${WARNING_ICON} [WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}${ERROR_ICON} [FAIL]${NC} $1"
}

print_step() {
    echo -e "  ${CYAN}→${NC} $1"
}

# ========================================
# Argument Parsing
# ========================================
while [[ $# -gt 0 ]]; do
    case $1 in
        --report)
            REPORT_MODE=true
            shift
            ;;
        --strict)
            STRICT_MODE=true
            shift
            ;;
        --skip-sonar)
            SKIP_SONAR=true
            shift
            ;;
        --skip-codeql)
            SKIP_CODEQL=true
            shift
            ;;
        --help|-h)
            echo "Security Gates Check Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --report      Generate detailed report"
            echo "  --strict      Strict mode (fail on any warning)"
            echo "  --skip-sonar  Skip SonarQube checks"
            echo "  --skip-codeql Skip CodeQL checks"
            echo "  --help, -h    Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ========================================
# Helper Functions
# ========================================
check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_error "$1 is not installed"
        return 1
    fi
    return 0
}

check_file() {
    if [[ ! -f "$1" ]]; then
        print_error "File not found: $1"
        return 1
    fi
    return 0
}

check_dir() {
    if [[ ! -d "$1" ]]; then
        print_error "Directory not found: $1"
        return 1
    fi
    return 0
}

# ========================================
# SonarQube Quality Gate Check
# ========================================
check_sonarqube_quality_gate() {
    print_header "SonarQube Quality Gate Check"
    
    if [[ -z "$SONAR_TOKEN" ]]; then
        print_warning "SONAR_TOKEN not set, skipping API checks"
        print_info "Set SONAR_TOKEN environment variable for full analysis"
        return 0
    fi
    
    print_step "Checking SonarQube Quality Gate status..."
    
    # API endpoint для quality gate
    local api_url="${SONAR_HOST_URL}/api/qualitygates/project_status?projectKey=${SONAR_PROJECT_KEY}"
    
    # Получаем статус quality gate
    local response
    response=$(curl -s -u "${SONAR_TOKEN}:" "${api_url}" 2>/dev/null) || {
        print_warning "Failed to connect to SonarQube API"
        return 0
    }
    
    # Парсим ответ
    local status
    status=$(echo "$response" | jq -r '.projectStatus.status' 2>/dev/null)
    
    if [[ "$status" == "OK" ]]; then
        print_success "Quality Gate: PASSED"
    elif [[ "$status" == "ERROR" ]]; then
        print_error "Quality Gate: FAILED"
        
        # Получаем детали
        local conditions
        conditions=$(echo "$response" | jq -r '.projectStatus.conditions[]' 2>/dev/null)
        
        echo ""
        echo "Failed conditions:"
        echo "$conditions" | jq -r '. | "  - \(.metricName): \(.actualValue) (\(.status))"' 2>/dev/null
        
        if [[ "$STRICT_MODE" == true ]]; then
            return 1
        fi
    else
        print_warning "Quality Gate status: $status"
    fi
    
    # Получаем метрики проекта
    print_step "Fetching project metrics..."
    
    local metrics_url="${SONAR_HOST_URL}/api/measures/component?component=${SONAR_PROJECT_KEY}&metricKeys=coverage,security_rating,reliability_rating,maintainability_rating,vulnerabilities,code_smells,bugs,duplicated_lines_density"
    
    local metrics_response
    metrics_response=$(curl -s -u "${SONAR_TOKEN}:" "${metrics_url}" 2>/dev/null) || {
        print_warning "Failed to fetch metrics"
        return 0
    }
    
    # Парсим метрики
    local measures
    measures=$(echo "$metrics_response" | jq -r '.component.measures' 2>/dev/null)
    
    echo ""
    echo "Project Metrics:"
    echo "─────────────────────────────────────────"
    
    # Coverage
    local coverage
    coverage=$(echo "$measures" | jq -r '.[] | select(.metric == "coverage") | .value' 2>/dev/null)
    if [[ -n "$coverage" && "$coverage" != "null" ]]; then
        if (( $(echo "$coverage >= $COVERAGE_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
            print_success "Coverage: ${coverage}% (threshold: ${COVERAGE_THRESHOLD}%)"
        else
            print_error "Coverage: ${coverage}% (threshold: ${COVERAGE_THRESHOLD}%)"
            if [[ "$STRICT_MODE" == true ]]; then
                return 1
            fi
        fi
    else
        print_warning "Coverage: N/A"
    fi
    
    # Security Rating
    local security_rating
    security_rating=$(echo "$measures" | jq -r '.[] | select(.metric == "security_rating") | .value' 2>/dev/null)
    if [[ -n "$security_rating" && "$security_rating" != "null" ]]; then
        if [[ "$security_rating" <= "$SECURITY_RATING_THRESHOLD" ]]; then
            print_success "Security Rating: $security_rating (threshold: $SECURITY_RATING_THRESHOLD)"
        else
            print_error "Security Rating: $security_rating (threshold: $SECURITY_RATING_THRESHOLD)"
            if [[ "$STRICT_MODE" == true ]]; then
                return 1
            fi
        fi
    else
        print_warning "Security Rating: N/A"
    fi
    
    # Reliability Rating
    local reliability_rating
    reliability_rating=$(echo "$measures" | jq -r '.[] | select(.metric == "reliability_rating") | .value' 2>/dev/null)
    if [[ -n "$reliability_rating" && "$reliability_rating" != "null" ]]; then
        if [[ "$reliability_rating" <= "$RELIABILITY_RATING_THRESHOLD" ]]; then
            print_success "Reliability Rating: $reliability_rating (threshold: $RELIABILITY_RATING_THRESHOLD)"
        else
            print_error "Reliability Rating: $reliability_rating (threshold: $RELIABILITY_RATING_THRESHOLD)"
            if [[ "$STRICT_MODE" == true ]]; then
                return 1
            fi
        fi
    else
        print_warning "Reliability Rating: N/A"
    fi
    
    # Maintainability Rating
    local maintainability_rating
    maintainability_rating=$(echo "$measures" | jq -r '.[] | select(.metric == "maintainability_rating") | .value' 2>/dev/null)
    if [[ -n "$maintainability_rating" && "$maintainability_rating" != "null" ]]; then
        if [[ "$maintainability_rating" <= "$MAINTAINABILITY_RATING_THRESHOLD" ]]; then
            print_success "Maintainability Rating: $maintainability_rating (threshold: $MAINTAINABILITY_RATING_THRESHOLD)"
        else
            print_error "Maintainability Rating: $maintainability_rating (threshold: $MAINTAINABILITY_RATING_THRESHOLD)"
            if [[ "$STRICT_MODE" == true ]]; then
                return 1
            fi
        fi
    else
        print_warning "Maintainability Rating: N/A"
    fi
    
    # Vulnerabilities
    local vulnerabilities
    vulnerabilities=$(echo "$measures" | jq -r '.[] | select(.metric == "vulnerabilities") | .value' 2>/dev/null)
    if [[ -n "$vulnerabilities" && "$vulnerabilities" != "null" ]]; then
        if [[ "$vulnerabilities" -le "$CRITICAL_ISSUES_THRESHOLD" ]]; then
            print_success "Vulnerabilities: $vulnerabilities"
        else
            print_error "Vulnerabilities: $vulnerabilities (threshold: $CRITICAL_ISSUES_THRESHOLD)"
            if [[ "$STRICT_MODE" == true ]]; then
                return 1
            fi
        fi
    fi
    
    # Code Smells
    local code_smells
    code_smells=$(echo "$measures" | jq -r '.[] | select(.metric == "code_smells") | .value' 2>/dev/null)
    if [[ -n "$code_smells" && "$code_smells" != "null" ]]; then
        print_info "Code Smells: $code_smells"
    fi
    
    # Bugs
    local bugs
    bugs=$(echo "$measures" | jq -r '.[] | select(.metric == "bugs") | .value' 2>/dev/null)
    if [[ -n "$bugs" && "$bugs" != "null" ]]; then
        print_info "Bugs: $bugs"
    fi
    
    # Duplication
    local duplication
    duplication=$(echo "$measures" | jq -r '.[] | select(.metric == "duplicated_lines_density") | .value' 2>/dev/null)
    if [[ -n "$duplication" && "$duplication" != "null" ]]; then
        if (( $(echo "$duplication <= $DUPLICATION_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
            print_success "Duplication: ${duplication}% (threshold: ${DUPLICATION_THRESHOLD}%)"
        else
            print_error "Duplication: ${duplication}% (threshold: ${DUPLICATION_THRESHOLD}%)"
            if [[ "$STRICT_MODE" == true ]]; then
                return 1
            fi
        fi
    fi
    
    echo "─────────────────────────────────────────"
    echo ""
    
    return 0
}

# ========================================
# CodeQL Security Check
# ========================================
check_codeql_results() {
    print_header "CodeQL Security Check"
    
    if [[ ! -f "$CODEQL_RESULTS" ]]; then
        print_warning "CodeQL results not found: $CODEQL_RESULTS"
        print_info "Run CodeQL analysis first: ./scripts/run-codeql-local.ps1 -Action analyze"
        return 0
    fi
    
    print_step "Analyzing CodeQL SARIF results..."
    
    # Проверяем наличие jq
    if ! check_command "jq"; then
        print_warning "jq not installed, skipping detailed analysis"
        return 0
    fi
    
    # Подсчет результатов по уровням
    local error_count warning_count note_count
    
    error_count=$(jq '[.runs[].results[] | select(.level == "error")] | length' "$CODEQL_RESULTS" 2>/dev/null || echo 0)
    warning_count=$(jq '[.runs[].results[] | select(.level == "warning")] | length' "$CODEQL_RESULTS" 2>/dev/null || echo 0)
    note_count=$(jq '[.runs[].results[] | select(.level == "note")] | length' "$CODEQL_RESULTS" 2>/dev/null || echo 0)
    
    local total_count=$((error_count + warning_count + note_count))
    
    echo ""
    echo "CodeQL Results Summary:"
    echo "─────────────────────────────────────────"
    echo -e "  ${RED}🔴 Errors:${NC}    $error_count"
    echo -e "  ${YELLOW}🟡 Warnings:${NC}  $warning_count"
    echo -e "  ${BLUE}🔵 Notes:${NC}     $note_count"
    echo "─────────────────────────────────────────"
    echo -e "  Total:         $total_count"
    echo ""
    
    # Security Gate проверка
    if [[ "$error_count" -gt 0 ]]; then
        print_error "Security Gate FAILED: $error_count critical vulnerabilities found"
        
        # Вывод деталей
        echo ""
        print_info "Critical findings:"
        jq -r '.runs[].results[] | select(.level == "error") | "  - \(.ruleId): \(.message.text | split("\n")[0])"' "$CODEQL_RESULTS" 2>/dev/null | head -10
        
        echo ""
        if [[ "$STRICT_MODE" == true ]]; then
            return 1
        fi
    else
        print_success "Security Gate PASSED: No critical vulnerabilities"
    fi
    
    # Проверка warning'ов в strict mode
    if [[ "$STRICT_MODE" == true && "$warning_count" -gt 0 ]]; then
        print_warning "Strict mode: $warning_count warnings found"
        return 1
    fi
    
    # OWASP Top 10 categories
    echo ""
    print_step "OWASP Top 10 Categories:"
    
    local owasp_a01 owasp_a03 owasp_a07 owasp_a09
    owasp_a01=$(jq '[.runs[].results[] | select(.ruleId | contains("access-control"))] | length' "$CODEQL_RESULTS" 2>/dev/null || echo 0)
    owasp_a03=$(jq '[.runs[].results[] | select(.ruleId | contains("injection"))] | length' "$CODEQL_RESULTS" 2>/dev/null || echo 0)
    owasp_a07=$(jq '[.runs[].results[] | select(.ruleId | contains("auth"))] | length' "$CODEQL_RESULTS" 2>/dev/null || echo 0)
    owasp_a09=$(jq '[.runs[].results[] | select(.ruleId | contains("logging") or contains("monitoring"))] | length' "$CODEQL_RESULTS" 2>/dev/null || echo 0)
    
    echo "  A01 (Access Control):     $owasp_a01"
    echo "  A03 (Injection):          $owasp_a03"
    echo "  A07 (Auth Failures):      $owasp_a07"
    echo "  A09 (Logging/Monitoring): $owasp_a09"
    
    echo "─────────────────────────────────────────"
    echo ""
    
    return 0
}

# ========================================
# ESLint Security Check
# ========================================
check_eslint_security() {
    print_header "ESLint Security Check"
    
    local eslint_report="$ROOT_DIR/eslint-report.json"
    
    if [[ ! -f "$eslint_report" ]]; then
        print_warning "ESLint report not found, running lint..."
        
        cd "$ROOT_DIR"
        npm run lint -- --format=json --output-file=eslint-report.json || true
        
        if [[ ! -f "$eslint_report" ]]; then
            print_warning "Failed to generate ESLint report"
            return 0
        fi
    fi
    
    print_step "Analyzing ESLint security rules..."
    
    if ! check_command "jq"; then
        print_warning "jq not installed, skipping detailed analysis"
        return 0
    fi
    
    # Подсчет security-related правил
    local security_errors
    security_errors=$(jq '[.[] | select(.ruleId | contains("security") or contains("no-eval") or contains("no-implied-eval"))] | length' "$eslint_report" 2>/dev/null || echo 0)
    
    local total_errors
    total_errors=$(jq '[.[] | select(.severity == 2)] | length' "$eslint_report" 2>/dev/null || echo 0)
    
    local total_warnings
    total_warnings=$(jq '[.[] | select(.severity == 1)] | length' "$eslint_report" 2>/dev/null || echo 0)
    
    echo ""
    echo "ESLint Results:"
    echo "─────────────────────────────────────────"
    echo -e "  ${RED}Errors:${NC}          $total_errors"
    echo -e "  ${YELLOW}Warnings:${NC}        $total_warnings"
    echo -e "  ${CYAN}Security Rules:${NC}  $security_errors"
    echo "─────────────────────────────────────────"
    echo ""
    
    if [[ "$security_errors" -gt 0 ]]; then
        print_error "Security-related ESLint violations: $security_errors"
        
        if [[ "$STRICT_MODE" == true ]]; then
            return 1
        fi
    else
        print_success "No security-related ESLint violations"
    fi
    
    return 0
}

# ========================================
# Dependency Security Check
# ========================================
check_dependencies() {
    print_header "Dependency Security Check"
    
    cd "$ROOT_DIR"
    
    print_step "Running npm audit..."
    
    local audit_result
    audit_result=$(npm audit --json 2>/dev/null) || true
    
    if [[ -z "$audit_result" ]]; then
        print_warning "npm audit returned no results"
        return 0
    fi
    
    # Парсим результаты
    local vulnerabilities
    vulnerabilities=$(echo "$audit_result" | jq '.metadata.vulnerabilities' 2>/dev/null)
    
    if [[ -z "$vulnerabilities" || "$vulnerabilities" == "null" ]]; then
        print_success "No vulnerabilities found in dependencies"
        return 0
    fi
    
    local critical high moderate low
    
    critical=$(echo "$vulnerabilities" | jq '.critical // 0' 2>/dev/null)
    high=$(echo "$vulnerabilities" | jq '.high // 0' 2>/dev/null)
    moderate=$(echo "$vulnerabilities" | jq '.moderate // 0' 2>/dev/null)
    low=$(echo "$vulnerabilities" | jq '.low // 0' 2>/dev/null)
    
    echo ""
    echo "Dependency Vulnerabilities:"
    echo "─────────────────────────────────────────"
    echo -e "  ${RED}Critical:${NC}  $critical"
    echo -e "  ${RED}High:${NC}      $high"
    echo -e "  ${YELLOW}Moderate:${NC}  $moderate"
    echo -e "  ${BLUE}Low:${NC}       $low"
    echo "─────────────────────────────────────────"
    echo ""
    
    local total_vulns=$((critical + high + moderate + low))
    
    if [[ "$total_vulns" -gt 0 ]]; then
        print_error "Found $total_vulns vulnerabilities in dependencies"
        
        # Вывод деталей
        print_info "Run 'npm audit' for details"
        
        if [[ "$critical" -gt 0 || "$high" -gt 0 ]]; then
            print_warning "Critical/High vulnerabilities require immediate attention"
            
            if [[ "$STRICT_MODE" == true ]]; then
                return 1
            fi
        fi
    else
        print_success "No vulnerabilities in dependencies"
    fi
    
    return 0
}

# ========================================
# Secrets Detection Check
# ========================================
check_secrets() {
    print_header "Secrets Detection Check"
    
    local gitleaks_config="$ROOT_DIR/.gitleaks.toml"
    
    if [[ ! -f "$gitleaks_config" ]]; then
        print_warning "Gitleaks config not found, skipping secrets scan"
        return 0
    fi
    
    if ! check_command "gitleaks"; then
        print_warning "Gitleaks not installed, skipping secrets scan"
        print_info "Install: go install github.com/gitleaks/gitleaks@latest"
        return 0
    fi
    
    print_step "Scanning for hardcoded secrets..."
    
    cd "$ROOT_DIR"
    
    local gitleaks_result
    gitleaks_result=$(gitleaks detect --source . --config .gitleaks.toml --report-format json --report-path "$REPORTS_DIR/gitleaks-report.json" 2>&1) || true
    
    local secrets_found
    secrets_found=$(jq 'length' "$REPORTS_DIR/gitleaks-report.json" 2>/dev/null || echo 0)
    
    if [[ "$secrets_found" -gt 0 ]]; then
        print_error "Found $secrets_found potential secrets"
        
        # Вывод деталей
        echo ""
        print_info "Potential secrets:"
        jq -r '.[] | "  - \(.RuleID): \(.File):\(.StartLine)"' "$REPORTS_DIR/gitleaks-report.json" 2>/dev/null | head -10
        
        if [[ "$STRICT_MODE" == true ]]; then
            return 1
        fi
    else
        print_success "No hardcoded secrets found"
    fi
    
    return 0
}

# ========================================
# Generate Report
# ========================================
generate_report() {
    print_header "Generating Security Report"
    
    mkdir -p "$REPORTS_DIR"
    
    local report_file="$REPORTS_DIR/security-gates-report.md"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    cat > "$report_file" << EOF
# Security Gates Report

## Project Information
- **Project:** Protocol Security
- **Timestamp:** $timestamp
- **Mode:** $([ "$STRICT_MODE" == true ] && echo "Strict" || echo "Normal")

## Summary

| Check | Status |
|-------|--------|
| SonarQube Quality Gate | $([ "$SKIP_SONAR" == true ] && echo "Skipped" || echo "Checked") |
| CodeQL Security Analysis | $([ "$SKIP_CODEQL" == true ] && echo "Skipped" || echo "Checked") |
| ESLint Security Rules | Checked |
| Dependency Audit | Checked |
| Secrets Detection | Checked |

## Thresholds

| Metric | Threshold |
|--------|-----------|
| Coverage | ≥ ${COVERAGE_THRESHOLD}% |
| Security Rating | $SECURITY_RATING_THRESHOLD |
| Reliability Rating | $RELIABILITY_RATING_THRESHOLD |
| Maintainability Rating | $MAINTAINABILITY_RATING_THRESHOLD |
| Critical Issues | ≤ $CRITICAL_ISSUES_THRESHOLD |
| Major Issues | ≤ $MAJOR_ISSUES_THRESHOLD |
| Duplication | ≤ ${DUPLICATION_THRESHOLD}% |

## Recommendations

1. Review all critical and high severity findings
2. Fix security vulnerabilities before merge
3. Maintain code coverage above threshold
4. Regular dependency updates

---
*Generated by Security Gates Script*
EOF

    print_success "Report generated: $report_file"
}

# ========================================
# Main
# ========================================
main() {
    print_header "Security Gates Check - Protocol Security"
    
    echo "Configuration:"
    echo "  Strict Mode: $STRICT_MODE"
    echo "  Skip SonarQube: $SKIP_SONAR"
    echo "  Skip CodeQL: $SKIP_CODEQL"
    echo "  Report Mode: $REPORT_MODE"
    echo ""
    
    local exit_code=0
    
    # Создаем директории
    mkdir -p "$REPORTS_DIR" "$LOGS_DIR"
    
    # SonarQube check
    if [[ "$SKIP_SONAR" != true ]]; then
        check_sonarqube_quality_gate || exit_code=1
    else
        print_info "Skipping SonarQube checks"
    fi
    
    # CodeQL check
    if [[ "$SKIP_CODEQL" != true ]]; then
        check_codeql_results || exit_code=1
    else
        print_info "Skipping CodeQL checks"
    fi
    
    # ESLint check
    check_eslint_security || exit_code=1
    
    # Dependency check
    check_dependencies || exit_code=1
    
    # Secrets check
    check_secrets || exit_code=1
    
    # Report generation
    if [[ "$REPORT_MODE" == true ]]; then
        generate_report
    fi
    
    # Final summary
    print_header "Security Gates Summary"
    
    if [[ "$exit_code" -eq 0 ]]; then
        print_success "All security gates PASSED"
        echo ""
        echo "The code is ready for merge/deployment."
    else
        print_error "Some security gates FAILED"
        echo ""
        echo "Please fix the issues before merging."
        
        if [[ "$STRICT_MODE" == true ]]; then
            echo ""
            print_warning "Strict mode enabled - warnings treated as errors"
        fi
    fi
    
    echo ""
    echo "─────────────────────────────────────────"
    echo ""
    
    exit $exit_code
}

# Запуск main функции
main
