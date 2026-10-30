#!/bin/bash
# WP REST API Auth Bypass Recon Script
# For authorized bug bounty testing only (Immutable Bugcrowd program)
#
# Usage: ./recon-wp-auth-bypass.sh <target-domain>
# Example: ./recon-wp-auth-bypass.sh gog-prod.mystagingwebsite.com

set -euo pipefail

TARGET="${1:?Usage: $0 <target-domain>}"
OUTDIR="recon-output/${TARGET//[^a-zA-Z0-9.-]/_}"
mkdir -p "$OUTDIR"

echo "=== WP REST API Auth Bypass Recon ==="
echo "Target: $TARGET"
echo "Output: $OUTDIR/"
echo ""

# ─── Step 1: Fetch WP REST route index ───
echo "[1/5] Fetching WordPress REST route index..."
curl -sk "https://${TARGET}/wp-json/" \
  -H "User-Agent: Mozilla/5.0" \
  -o "$OUTDIR/wp-json-index.json" 2>/dev/null

if ! python3 -c "import json; json.load(open('$OUTDIR/wp-json-index.json'))" 2>/dev/null; then
  echo "  ERROR: Not a valid JSON response. Target may not be WordPress."
  echo "  Check: https://${TARGET}/wp-json/"
  exit 1
fi

echo "  Saved to $OUTDIR/wp-json-index.json"

# ─── Step 2: Extract all routes ───
echo "[2/5] Extracting routes..."
python3 -I -c "
import json, sys
with open('$OUTDIR/wp-json-index.json') as f:
    data = json.load(f)
routes = data.get('routes', {})
with open('$OUTDIR/all-routes.txt', 'w') as out:
    for route in sorted(routes.keys()):
        methods = []
        for ep in routes[route].get('endpoints', []):
            methods.extend(ep.get('methods', []))
        methods = sorted(set(methods))
        out.write(f'{route} [{\" \".join(methods)}]\n')
print(f'  Found {len(routes)} routes')
"

# ─── Step 3: Identify high-value routes ───
echo "[3/5] Filtering high-value routes (financial, user, admin)..."
python3 -I -c "
import json
keywords = [
    'withdraw', 'deposit', 'transfer', 'balance', 'payment', 'purchase',
    'order', 'refund', 'claim', 'mint', 'swap', 'convert', 'fee',
    'wallet', 'account', 'user', 'profile', 'admin', 'settings',
    'token', 'nft', 'asset', 'key', 'secret', 'config', 'export',
    'primary-sales', 'checkout', 'subscription', 'credit', 'reward'
]
with open('$OUTDIR/wp-json-index.json') as f:
    data = json.load(f)
routes = data.get('routes', {})
hits = []
for route, info in routes.items():
    route_lower = route.lower()
    matched = [kw for kw in keywords if kw in route_lower]
    if matched:
        methods = []
        for ep in info.get('endpoints', []):
            methods.extend(ep.get('methods', []))
        methods = sorted(set(methods))
        hits.append((route, methods, matched))
with open('$OUTDIR/high-value-routes.txt', 'w') as out:
    for route, methods, matched in sorted(hits):
        out.write(f'{route} [{\" \".join(methods)}] keywords={matched}\n')
print(f'  Found {len(hits)} high-value routes')
"

# ─── Step 4: Test unauthenticated access on high-value routes ───
echo "[4/5] Testing unauthenticated GET on high-value routes..."
echo "  (Only GET requests — safe, read-only probing)"
echo ""

mkdir -p "$OUTDIR/responses"
while IFS= read -r line; do
  route=$(echo "$line" | awk '{print $1}')
  # Replace regex placeholders with test values
  test_route=$(echo "$route" | sed 's/(?P<[^>]*>[^)]*)/test/g' | sed 's/(\\d+)/1/g')

  url="https://${TARGET}${test_route}"
  safename=$(echo "$test_route" | sed 's/[^a-zA-Z0-9]/_/g')

  http_code=$(curl -sk -o "$OUTDIR/responses/${safename}.json" \
    -w "%{http_code}" \
    -H "User-Agent: Mozilla/5.0" \
    "$url" 2>/dev/null || echo "000")

  if [ "$http_code" = "200" ]; then
    echo "  [200 OK]  $test_route  <-- POTENTIAL MISSING AUTH"
  elif [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
    echo "  [$http_code]     $test_route  (auth required - expected)"
  else
    echo "  [$http_code]     $test_route"
  fi
done < "$OUTDIR/high-value-routes.txt"

# ─── Step 5: Summary ───
echo ""
echo "[5/5] Summary"
echo "─────────────"
echo "All routes:        $OUTDIR/all-routes.txt"
echo "High-value routes: $OUTDIR/high-value-routes.txt"
echo "Responses:         $OUTDIR/responses/"
echo ""
echo "NEXT STEPS:"
echo "  1. Review 200 OK responses for data leaks / unauthorized access"
echo "  2. Test POST/PUT/DELETE on promising routes (manually!)"
echo "  3. Check for IDOR by swapping wallet addresses / user IDs"
echo "  4. Look for custom namespaces beyond /wc/v3/"
echo ""
echo "  grep -l '\"balance\"' $OUTDIR/responses/*.json 2>/dev/null"
echo "  grep -l '\"wallet\"' $OUTDIR/responses/*.json 2>/dev/null"
