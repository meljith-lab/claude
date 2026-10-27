# Immutable Bug Bounty — Hunt Notes

## Your Triaged Finding (P2)
- **Target:** `gog-prod.mystagingwebsite.com` (WooCommerce backend)
- **Vuln class:** Missing `permission_callback` on WP REST API routes (CWE-862)
- **Endpoints:** `/wp-json/wc/v3/primary-sales/g-gog/withdraw`, `ggog-balance`, `withdraw/fee`
- **Upstream:** `gog-api.mineloader.com` (Mineloader = GoG game developer)
- **Impact:** Unauthenticated token drain from any player wallet

---

## Bugcrowd Scope (Verified Targets)

From aggregator + Bugcrowd page (confirm on live page — last updated 15 Oct 2026):

| Target | Type | Tier | Notes |
|--------|------|------|-------|
| `passport.immutable.com` | Web | P1: $5K–$10K | Non-custodial wallet + passwordless SSO |
| `auth.immutable.com` | Web | — | Passport authentication backend |
| `api.immutable.com` | API | — | Unified Immutable API |
| `api.x.immutable.com` | API | — | Immutable X L2 API |
| `gog-prod.mystagingwebsite.com` | API | P1: $2.5K–$5K | GoG WooCommerce backend (YOUR FIND) |
| 2 more targets | — | — | Check Bugcrowd page |

**Immunefi (separate program, up to $1M):** Bridge + adapter smart contracts on Ethereum mainnet and zkEVM.

---

## HIGH-PRIORITY HUNT AREAS

### 1. Same WooCommerce Instance — Route Enumeration
**Why:** Your bug was ONE namespace. The WP REST index exposes ALL registered routes.

```
GET /wp-json/
```
on `gog-prod.mystagingwebsite.com` — look for:
- Other namespaces under `/wc/v3/primary-sales/` (not just `g-gog`)
- Custom plugin routes outside WooCommerce (`/wp-json/<custom-namespace>/`)
- Any route with financial verbs: `purchase`, `deposit`, `transfer`, `refund`, `claim`, `mint`
- WordPress core routes with elevated access: `/wp-json/wp/v2/users`, `/wp-json/wp/v2/settings`

**Pattern to test:** For each discovered route, send an unauthenticated request. Missing `permission_callback` returns data; proper auth returns 401/403.

### 2. Upstream API Direct Access (`gog-api.mineloader.com`)
**Why:** If the WooCommerce layer was just a proxy, the backend might accept direct calls.

Test the same operations directly:
- Withdraw endpoint equivalents
- Balance queries
- Fee endpoints
- Any admin/management endpoints

If it trusts requests from any IP (not just the WP server), you have direct backend access without the WordPress layer.

### 3. Passport & Auth (passport.immutable.com / auth.immutable.com)
**Why:** Highest-paying tier ($5K–$10K P1). Auth systems are complex.

Look for:
- OAuth/OIDC misconfigurations (token leakage, redirect_uri manipulation)
- Account takeover via password reset flows
- Session fixation / token reuse
- IDOR on user profile/wallet endpoints
- JWT validation bypasses (alg=none, key confusion, expired token acceptance)
- Missing rate limits on OTP/MFA endpoints

### 4. Immutable APIs (api.immutable.com / api.x.immutable.com)
**Why:** These handle trades, transfers, mints, and asset management.

Known endpoint groups from Immutable X SDK:
- `/v1/assets` — NFT assets
- `/v1/balances` — Token balances
- `/v1/collections` — NFT collections
- `/v1/deposits` — Deposit operations
- `/v1/withdrawals` — Withdrawal operations
- `/v1/transfers` — Transfer operations
- `/v1/trades` — Trade operations
- `/v1/orders` — Order operations
- `/v1/users` — User management
- `/v1/tokens` — Token operations
- `/v2/` variants of above

**Test for:**
- Unauthenticated access to privileged endpoints
- IDOR on user-scoped operations (change user ID / wallet address)
- Mass data exposure on list endpoints (missing pagination auth)
- Parameter tampering on financial operations (amount, recipient)

### 5. Other *.mystagingwebsite.com Subdomains
**Why:** WP Engine staging pattern. Other Immutable products may use similar WooCommerce setups.

Subdomain patterns to check:
- `imx-prod.mystagingwebsite.com`
- `passport-prod.mystagingwebsite.com`
- `marketplace-prod.mystagingwebsite.com`
- `checkout-prod.mystagingwebsite.com`
- `tokenconverter-prod.mystagingwebsite.com`
- `gog-staging.mystagingwebsite.com`

### 6. Smart Contracts (Immunefi — separate $1M program)
**Why:** Bridge contracts handle real funds.

- zkEVM bridge adapter contracts
- GoG token ($GOG) ERC-20 contract — withdrawal/approval logic
- gGoG in-game token conversion logic
- Bridge deposit/withdrawal signature verification

---

## VULNERABILITY PATTERN REFERENCE

Your finding follows CVE pattern CWE-862 (Missing Authorization). Similar recent CVEs in WooCommerce plugins:

| CVE | Plugin | Issue | Severity |
|-----|--------|-------|----------|
| CVE-2026-86785 | Social Commerce for WooCommerce | No `permission_callback` on settings routes | High |
| CVE-2024-11423 | Ultimate Gift Cards for WooCommerce | Unauth gift card balance manipulation | High |
| CVE-2026-7529 | wiseCampaign | `permission_callback => '__return_true'` on all routes | 7.5 High |
| CVE-2026-92435 | Mailchimp for WooCommerce | Admin endpoints with no capability checks | 5.3 Medium |

---

## QUICK TEST CHECKLIST

For each discovered endpoint:

- [ ] Send request with NO auth headers → does it return data/accept action?
- [ ] Send request with another user's wallet/ID → IDOR check
- [ ] Enumerate via WordPress route index (`GET /wp-json/`)
- [ ] Check for debug/verbose error messages leaking internals
- [ ] Test parameter tampering (amounts, addresses, order IDs)
- [ ] Check rate limiting on sensitive operations
- [ ] Look for API key/secrets in JavaScript bundles or page source

---

## REPORT STRATEGY

Your triaged P2 used a strong pattern: binding oracle → balance check → withdrawal → confirmed drain. For similar findings:

1. **Always show real impact** — actual balance change, not just 200 OK
2. **Chain the primitives** — enumerate → identify → exploit → confirm
3. **CVSS it properly** — Network/Low/None/None + Confidentiality+Integrity = High base
4. **One report per root cause** — if same missing auth pattern, group related endpoints
