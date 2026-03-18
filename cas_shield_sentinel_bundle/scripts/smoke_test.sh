#!/usr/bin/env sh
set -e

SHIELD_BASE="${SHIELD_BASE:-http://127.0.0.1:8080}"

echo "TEST 1: PASS_THROUGH"
curl -i "$SHIELD_BASE/cas/login" | head -n 15

echo "TEST 2: FRICTION (empty UA)"
curl -i -H "User-Agent:" "$SHIELD_BASE/cas/login" | head -n 15

echo "TEST 3: TRAP_SINK /.env"
time curl -i "$SHIELD_BASE/.env" | head -n 15

echo "TEST 4: status"
curl -s "$SHIELD_BASE/__shield/status" | python -m json.tool
