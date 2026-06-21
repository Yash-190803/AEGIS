#!/bin/bash
set -u

BASE_URL="http://localhost:${PORT:-3001}"
PASS=0
FAIL=0

require_command() {
    local command_name=$1
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $command_name"
        exit 1
    fi
}

count_incidents() {
    curl -s "$BASE_URL/api/incidents" | python3 -c "import sys,json; data=json.load(sys.stdin); print(len(data))"
}

run_scenario() {
    local scenario=$1
    echo "--- Scenario: $scenario ---"
    local response_code
    response_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$BASE_URL/api/scenarios/run" \
        -H "Content-Type: application/json" \
        -d "{\"scenario\":\"$scenario\"}" || echo "000")

    if [ "$response_code" != "200" ] && [ "$response_code" != "202" ]; then
        echo "FAIL: $scenario trigger returned HTTP $response_code"
        FAIL=$((FAIL + 1))
        return
    fi

    sleep 8
    local count
    if ! count=$(count_incidents); then
        echo "FAIL: $scenario could not read incident count"
        FAIL=$((FAIL + 1))
        return
    fi

    if [ "$count" -gt "0" ]; then
        echo "PASS: $scenario"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $scenario"
        FAIL=$((FAIL + 1))
    fi
}

require_command curl
require_command python3

run_scenario "BRUTE_FORCE"
run_scenario "RANSOMWARE_LATERAL"

echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -gt "0" ] && exit 1 || exit 0