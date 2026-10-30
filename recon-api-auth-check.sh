#!/bin/bash
# API Auth Check Script — Tests unauthenticated access on known Immutable API paths
# For authorized bug bounty testing only (Immutable Bugcrowd program)
#
# Usage: ./recon-api-auth-check.sh

set -euo pipefail

OUTDIR="recon-output/api-auth-check"
mkdir -p "$OUTDIR"

echo "=== Immutable API Auth Check ==="
echo ""

# Known Immutable API endpoints to test for missing auth
# Source: Immutable X SDK, public docs, OpenAPI definitions
declare -A TARGETS

# Immutable X API
TARGETS["api.x.immutable.com/v1/assets"]="GET"
TARGETS["api.x.immutable.com/v1/balances"]="GET"
TARGETS["api.x.immutable.com/v1/collections"]="GET"
TARGETS["api.x.immutable.com/v1/deposits"]="GET"
TARGETS["api.x.immutable.com/v1/withdrawals"]="GET"
TARGETS["api.x.immutable.com/v1/transfers"]="GET"
TARGETS["api.x.immutable.com/v1/trades"]="GET"
TARGETS["api.x.immutable.com/v1/orders"]="GET"
TARGETS["api.x.immutable.com/v1/users"]="GET"
TARGETS["api.x.immutable.com/v1/tokens"]="GET"
TARGETS["api.x.immutable.com/v1/mints"]="GET"
TARGETS["api.x.immutable.com/v2/assets"]="GET"
TARGETS["api.x.immutable.com/v2/balances"]="GET"
TARGETS["api.x.immutable.com/v2/withdrawals"]="GET"
TARGETS["api.x.immutable.com/v2/transfers"]="GET"
TARGETS["api.x.immutable.com/v2/orders"]="GET"

# Unified Immutable API
TARGETS["api.immutable.com/v1/assets"]="GET"
TARGETS["api.immutable.com/v1/balances"]="GET"
TARGETS["api.immutable.com/v1/collections"]="GET"
TARGETS["api.immutable.com/v1/orders"]="GET"
TARGETS["api.immutable.com/v1/trades"]="GET"
TARGETS["api.immutable.com/v1/transfers"]="GET"
TARGETS["api.immutable.com/v1/withdrawals"]="GET"
TARGETS["api.immutable.com/v1/users"]="GET"

# Passport / Auth endpoints
TARGETS["passport.immutable.com/api/v1/user"]="GET"
TARGETS["passport.immutable.com/api/v1/users"]="GET"
TARGETS["passport.immutable.com/api/v1/wallet"]="GET"
TARGETS["passport.immutable.com/api/v1/config"]="GET"
TARGETS["passport.immutable.com/api/v1/session"]="GET"
TARGETS["passport.immutable.com/.well-known/openid-configuration"]="GET"
TARGETS["passport.immutable.com/.well-known/jwks.json"]="GET"
TARGETS["auth.immutable.com/.well-known/openid-configuration"]="GET"
TARGETS["auth.immutable.com/.well-known/jwks.json"]="GET"
TARGETS["auth.immutable.com/userinfo"]="GET"

# GoG WooCommerce — enumerate beyond known endpoints
TARGETS["gog-prod.mystagingwebsite.com/wp-json/"]="GET"
TARGETS["gog-prod.mystagingwebsite.com/wp-json/wp/v2/users"]="GET"
TARGETS["gog-prod.mystagingwebsite.com/wp-json/wp/v2/settings"]="GET"
TARGETS["gog-prod.mystagingwebsite.com/wp-json/wp/v2/posts"]="GET"
TARGETS["gog-prod.mystagingwebsite.com/wp-json/wc/v3/orders"]="GET"
TARGETS["gog-prod.mystagingwebsite.com/wp-json/wc/v3/products"]="GET"
TARGETS["gog-prod.mystagingwebsite.com/wp-json/wc/v3/customers"]="GET"
TARGETS["gog-prod.mystagingwebsite.com/wp-json/wc/v3/coupons"]="GET"
TARGETS["gog-prod.mystagingwebsite.com/wp-json/wc/v3/payment_gateways"]="GET"

echo "Testing ${#TARGETS[@]} endpoints across 4 targets..."
echo ""

printf "%-8s %-75s %s\n" "STATUS" "ENDPOINT" "NOTES"
printf "%-8s %-75s %s\n" "------" "--------" "-----"

for endpoint in $(echo "${!TARGETS[@]}" | tr ' ' '\n' | sort); do
  method="${TARGETS[$endpoint]}"
  url="https://${endpoint}"
  safename=$(echo "$endpoint" | sed 's/[^a-zA-Z0-9]/_/g')

  http_code=$(curl -sk -o "$OUTDIR/${safename}.json" \
    -w "%{http_code}" \
    -X "$method" \
    -H "User-Agent: Mozilla/5.0" \
    -H "Accept: application/json" \
    "$url" 2>/dev/null || echo "000")

  notes=""
  if [ "$http_code" = "200" ]; then
    # Check if response contains interesting data
    size=$(wc -c < "$OUTDIR/${safename}.json" 2>/dev/null || echo "0")
    if [ "$size" -gt 100 ]; then
      notes="REVIEW — ${size} bytes returned"
    else
      notes="small response"
    fi
    printf "\033[31m%-8s\033[0m %-75s %s\n" "[$http_code]" "$endpoint" "$notes"
  elif [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
    printf "\033[32m%-8s\033[0m %-75s %s\n" "[$http_code]" "$endpoint" "auth enforced"
  elif [ "$http_code" = "404" ]; then
    printf "%-8s %-75s %s\n" "[$http_code]" "$endpoint" "not found"
  else
    printf "\033[33m%-8s\033[0m %-75s %s\n" "[$http_code]" "$endpoint" ""
  fi
done

echo ""
echo "Results saved to: $OUTDIR/"
echo ""
echo "REVIEW red [200] entries — those returned data without authentication."
echo "  For each 200, check: does it expose user data? financial data? admin functions?"
echo ""
echo "NEXT: For any 200 with sensitive data, test IDOR by adding:"
echo "  ?walletAddress=0x<victim>  or  ?user_id=<other_user>"
