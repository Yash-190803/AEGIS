#!/bin/bash
set -u

PORT=${1:-3001}
MAX_WAIT=${2:-15}
URL="http://localhost:${PORT}/api/health"

if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
    echo "ERROR: PORT must be numeric, received: $PORT"
    exit 1
fi

if ! [[ "$MAX_WAIT" =~ ^[0-9]+$ ]] || [ "$MAX_WAIT" -lt 1 ]; then
    echo "ERROR: MAX_WAIT_SECONDS must be a positive integer, received: $MAX_WAIT"
    exit 1
fi

for i in $(seq 1 "$MAX_WAIT"); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$URL" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "AEGIS ready after ${i}s (HTTP 200)"
        if ! curl -s "$URL" | python3 -m json.tool; then
            echo "ERROR: Health endpoint returned invalid JSON"
            exit 1
        fi
        exit 0
    fi
    echo "Attempt ${i}/${MAX_WAIT}: HTTP ${HTTP_CODE}"
    sleep 1
done

echo "ERROR: AEGIS did not start in ${MAX_WAIT}s"
exit 1