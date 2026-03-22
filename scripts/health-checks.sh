#!/bin/bash

# =============================================================================
# Health Checks Script for Protocol Security
# =============================================================================
# Usage: ./scripts/health-checks.sh [url]
# =============================================================================

set -e

BASE_URL=${1:-http://localhost:3000}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_passed=0
check_failed=0

health_check() {
    local name=$1
    local url=$2
    
    echo -n "Checking $name... "
    
    response=$(curl -s -o /dev/null -w "%{http_code}" "$url" --max-time 5)
    
    if [ "$response" -eq 200 ]; then
        echo -e "${GREEN}✓ PASS${NC} (HTTP $response)"
        ((check_passed++))
    else
        echo -e "${RED}✗ FAIL${NC} (HTTP $response)"
        ((check_failed++))
    fi
}

echo "============================================="
echo "  Protocol Security Health Checks"
echo "  URL: $BASE_URL"
echo "============================================="
echo ""

# Basic health checks
health_check "Health Endpoint" "$BASE_URL/health"
health_check "Status Endpoint" "$BASE_URL/status"
health_check "Metrics Endpoint" "$BASE_URL/metrics"

# Security headers
echo ""
echo "Security Headers:"
echo "----------------"

check_security_header() {
    local name=$1
    local header=$2
    
    echo -n "Checking $name... "
    
    value=$(curl -s -I "$BASE_URL/health" | grep -i "^$header:" | tr -d '\r')
    
    if [ -n "$value" ]; then
        echo -e "${GREEN}✓ PRESENT${NC}"
        ((check_passed++))
    else
        echo -e "${RED}✗ MISSING${NC}"
        ((check_failed++))
    fi
}

check_security_header "Strict-Transport-Security" "Strict-Transport-Security"
check_security_header "Content-Security-Policy" "Content-Security-Policy"
check_security_header "X-Frame-Options" "X-Frame-Options"
check_security_header "X-Content-Type-Options" "X-Content-Type-Options"
check_security_header "X-XSS-Protection" "X-XSS-Protection"

echo ""
echo "============================================="
echo "  Results: $check_passed passed, $check_failed failed"
echo "============================================="

if [ $check_failed -gt 0 ]; then
    exit 1
fi

exit 0
