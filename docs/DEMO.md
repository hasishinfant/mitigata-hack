# IntegrateX: 5-minute demo script

**Story:** a breached integration hub (the 2025 Drift scenario). We show that IntegrateX gives up as little as possible, notices within seconds, and hands the decision to a human with the evidence.

Every step below is real code. `test/demo-rehearsal.test.ts` runs the same story end to end on every test run.

## Before you present (10 min before)

```sh
cd ~/mitigata-hack
export NODE_EXTRA_CA_CERTS=/opt/homebrew/etc/ca-certificates/cert.pem
alias ix="npx tsx src/cli/ix.ts"

# Terminal 1: the platform plus the mock provider, with DPoP required
MOCK_REQUIRE_DPOP=1 MOCK_PORT=4010 IX_EGRESS_IPS=198.51.100.10 npx pnpm@10.28.0 dev:mock

# Terminal 2: register the two demo connectors, then set their (fake) secrets. Registering first means no host approval is needed.
MOCK_PORT=4010 ix add test/fixtures/configs/mock-okta-dpop.yaml
MOCK_PORT=4010 ix add test/fixtures/configs/mock-okta-logs.yaml
ix secret set mock_client_id        # mock-client-id
ix secret set mock_client_secret    # mock-client-secret-7890
ix secret set mock_ssws             # mock-ssws-token-9012
curl -s "localhost:4010/__attack?ip="      # no attack yet
ix run mock-okta-dpop; ix run mock-okta-logs
ix canary create okta_admin_token --prefix 00
ix canary create slack_webhook_prod --url --print   # copy this URL: you'll "loot" it in step 4
ix incident stop                                     # start the demo in normal mode
open http://localhost:7070
```

Optional: `ix secret set anthropic_api_key` lets the advisor add Claude's explanation. Without it the advisor shows the rules only, which is still a complete demo.

---

## 1. Hook (20 s)
> "In 2025 attackers broke into one integration hub, Salesloft Drift, stole the OAuth tokens it held, and replayed them against hundreds of companies' CRMs. Integration hubs hold keys to everything. IntegrateX is built for the day the hub itself is breached."

## 2. It works, and it's honest about it (45 s)
- Dashboard: both cards are green, and each stream shows **`verified`** (its latest Sync Integrity Receipt).
```sh
ix receipt <id>     # from: ix receipts mock-okta-dpop
```
> "One YAML file per source, one engine. Nothing is published until the whole sync is verified, and every run leaves a receipt: pages, hashes, counts, schema fingerprint, the decision. It separates facts from inferences and is anchored in a tamper-evident ledger."
- Click **Capabilities**:
> "For every connector and every control: enforced, available, unsupported or not applicable. We don't pretend every API supports everything."

## 3. The breach: the attacker steals a token (45 s)
```sh
T=$(curl -s localhost:4010/__dpop/stolen | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $T" "localhost:4010/api/v1/users"   # 401
```
> "That's a real access token lifted from the hub. It's **DPoP-bound** to a key that exists only in broker memory, so on the attacker's machine it's rejected. They'd need the key, and the key never touches disk."

## 4. They try a looted webhook URL (30 s)
```sh
curl -s -X POST "<the slack_webhook_prod URL from setup>" -d '{"text":"hi"}'    # invalid_token
```
- Dashboard: **red banner**, "Decoy credential used … from 127.0.0.1", plus an **amber incident-mode banner**.
> "That webhook was a **canary**: a decoy stored exactly like a real secret. Only the broker can tell the difference. The moment anyone uses one, we know the store was dumped. Incident mode turns on, and the audit-log connector now polls every 2 minutes instead of 15."

## 5. The provider's own log catches the replay (40 s)
```sh
curl -s "localhost:4010/__attack?ip=203.0.113.7"      # the attacker replays our credential elsewhere
ix run mock-okta-logs                                 # incident mode would pick it up within 2 minutes anyway
ix alerts -n 3                                        # foreign_ip_use: 4 events from 203.0.113.7
```
> "Okta's own audit log shows **our** OAuth client used from an IP that isn't the hub. The IP allow-list says the hub is 198.51.100.10, so this is stolen-credential use, recorded in the sync's receipt."

## 6. The advisor (40 s)
- Click **Advisor** (admin token):
> "Fixed rules turn the last 24 hours into one decision: **kill switch recommended**, with every finding citing its evidence: `alert:…`, `ledger:…`. Claude writes the explanation. Any claim citing evidence that doesn't exist is dropped, attacker text in the logs can't change the recommendation, and the advisor never presses the button."

## 7. Kill switch (30 s)
- Click **Kill switch** and enter the admin token.
> "Every connector disabled, queued runs cancelled, the OAuth token **revoked at Okta**, and a checklist for what only a human can revoke. The app's database role can't undo it: re-enabling goes through the broker."
```sh
ix audit verify      # hash chain intact
```

## 8. Close (15 s)
> "One engine and one YAML file per source. Every sync is verified before it's trusted. And a breached hub gives up as little as possible: tokens bound to an in-memory key, decoys that turn theft into an alarm, the provider's own log watching for replays, and one button that revokes everything."

**Honest limits, if asked:**
- An attacker who controls the live broker process can use its keys while they're inside it.
- DPoP and IP allow-lists depend on what each provider supports. The Capabilities panel shows it.
- In dev all processes run as one OS user. That's a documented, accepted risk for this scope.

**After the demo:** `for c in mock-okta-dpop mock-okta-logs; do ix enable $c; done; ix incident stop; curl -s "localhost:4010/__attack?ip="`

## Fallback (no Wi-Fi)
Everything above runs locally against the mock provider; nothing needs the internet. The real connectors (GitHub, Okta, NVD, CISA, Elastic) are optional extra proof: `ix receipts okta-users`.

## Numbers to quote
- About 225 automated tests, including an end-to-end rehearsal of this exact story
- 7 real sources verified live; 5 vendor coverage configs from the mentors' list (`docs/coverage.md`)
- One engine: `grep -riE "github|okta|nvd|cisa" src/engine src/broker` prints nothing
