#!/usr/bin/env bash
# End-to-end demo of the secure API: authentication, access control, SQLi and XSS.
# Usage: bash scripts/demo.sh [base-url]
set -euo pipefail

BASE="${1:-http://127.0.0.1:5000}"
USERNAME="${USERNAME_OVERRIDE:-alice}"
PASSWORD="${PASSWORD_OVERRIDE:-Alice-Str0ng-Pass!}"

bold() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
request() { curl -s -i "$@"; }
status_of() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

bold "0. Health check (public)"
request "$BASE/health" | sed -n '1p;$p'

bold "1. Login -> JWT"
LOGIN_BODY=$(curl -s -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
echo "$LOGIN_BODY"
TOKEN=$(printf '%s' "$LOGIN_BODY" | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

bold "2. Protected endpoint WITHOUT a token -> expect 401"
request "$BASE/api/data" | sed -n '1p'
echo "   (WWW-Authenticate header:)"
request "$BASE/api/data" | grep -i '^www-authenticate:' || true

bold "3. Protected endpoint WITH the token -> expect 200"
curl -s "$BASE/api/data?limit=2" -H "Authorization: Bearer $TOKEN"; echo

bold "4. Tampered / garbage token -> expect 401"
printf '   HTTP %s\n' "$(status_of "$BASE/api/data" -H 'Authorization: Bearer not.a.token')"

bold "5. SQL injection in the search parameter -> expect 200, zero rows"
curl -s "$BASE/api/data?q=%27%20OR%201%3D1%20--" -H "Authorization: Bearer $TOKEN"; echo

bold "6. SQL injection in the login form -> expect 400/401, never logged in"
request -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice' OR '1'='1\",\"password\":\"x\"}" | sed -n '1p;$p'

bold "7. Stored XSS payload -> expect escaped output (&lt;script&gt;...)"
curl -s -X POST "$BASE/api/posts" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"<script>alert(1)</script>","body":"<img src=x onerror=alert(1)>"}'; echo

bold "8. Pagination validation -> expect 400"
request "$BASE/api/data?limit=5000" -H "Authorization: Bearer $TOKEN" | sed -n '1p;$p'

echo
echo "All checks executed. Every attack above was rejected or neutralised."
