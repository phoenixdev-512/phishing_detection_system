#!/bin/bash
set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

BACKEND="http://localhost:8000"
PASS=0
FAIL=0

check() {
    local name="$1"
    local cmd="$2"
    local expect="$3"
    local result
    result=$(eval "$cmd" 2>/dev/null)
    if echo "$result" | grep -q "$expect"; then
        echo -e "${GREEN}[PASS]${NC} $name"
        PASS=$((PASS+1))
    else
        echo -e "${RED}[FAIL]${NC} $name"
        echo -e "       Expected: $expect"
        echo -e "       Got: $(echo $result | cut -c1-100)"
        FAIL=$((FAIL+1))
    fi
}

echo -e "\n${BOLD}TGIS System Smoke Tests${NC}\n"

check "Health endpoint" \
    "curl -sf $BACKEND/api/v1/health" \
    '"status":"ok"'

check "Scan returns 200 with status field" \
    "curl -sf -X POST $BACKEND/api/v1/scan \
     -H 'Content-Type: application/json' \
     -d '{\"url\":\"https://example.com\"}'" \
    '"status"'

check "Scan returns tgis_score field" \
    "curl -sf -X POST $BACKEND/api/v1/scan \
     -H 'Content-Type: application/json' \
     -d '{\"url\":\"https://example.com\"}'" \
    '"tgis_score"'

check "Scan returns graph_json field" \
    "curl -sf -X POST $BACKEND/api/v1/scan \
     -H 'Content-Type: application/json' \
     -d '{\"url\":\"https://example.com\"}'" \
    '"graph_json"'

check "Scan returns domain_age_days field" \
    "curl -sf -X POST $BACKEND/api/v1/scan \
     -H 'Content-Type: application/json' \
     -d '{\"url\":\"https://example.com\"}'" \
    '"domain_age_days"'

check "History endpoint returns array" \
    "curl -sf '$BACKEND/api/v1/history?limit=5'" \
    '\['

check "Stats endpoint returns total_scans" \
    "curl -sf $BACKEND/api/v1/stats" \
    '"total_scans"'

check "Frontend serves HTML" \
    "curl -sf $BACKEND/" \
    'DOCTYPE\|html\|TGIS\|React'

check "Invalid URL returns error" \
    "curl -sf -o /dev/null -w '%{http_code}' -X POST $BACKEND/api/v1/scan \
     -H 'Content-Type: application/json' -d '{\"url\":\"not-a-url\"}'" \
    '422\|400'

check "CORS header present" \
    "curl -sf -I -H 'Origin: http://localhost:5173' $BACKEND/api/v1/health" \
    'access-control\|Access-Control'

echo -e "\n${BOLD}Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}\n"

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}Some tests failed. Check the backend logs.${NC}"
    exit 1
else
    echo -e "${GREEN}All smoke tests passed. System is operational.${NC}"
fi