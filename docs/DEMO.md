# IntegrateX: 5-minute demo script

## Before you present (10 min before)

```sh
cd ~/mitigata-hack
export NODE_EXTRA_CA_CERTS=/opt/homebrew/etc/ca-certificates/cert.pem
alias ix="npx tsx src/cli/ix.ts"

# Terminal 1: the platform (+ mock server for the failure demos)
MOCK_PORT=4010 npx pnpm@10.28.0 dev:mock

# Terminal 2: reset for the live add and warm everything up
ix rm cisa-kev --yes                 # so step 3 can add it from a blank file
for c in github-members github-issues okta-users okta-logs nvd-cves; do ix run $c; done
ix rehearse                          # dry-run: broker, ledger, posture, panic preview (changes nothing)
open http://localhost:7070           # the Kill switch button asks for the admin token (IX_ADMIN_TOKEN in .env)
```

Have ready: `test/fixtures/configs/cisa-kev.yaml` open in a side window (the file you will type).
Offline fallback: if Wi-Fi fails, the mock server (`dev:mock`) serves every failure demo; point CISA at
`http://localhost:4010/public/kev.json` (allowed host `localhost`) instead of www.cisa.gov.

---

## 1. Hook (30 s)
> "In 2025, attackers stole the OAuth tokens stored in one integration hub, Salesloft Drift, and replayed them against hundreds of companies. Integration hubs hold keys to everything. We built a config-driven integration platform designed so that a breached hub gives up as little as possible."

## 2. It works on real sources (45 s)
- Dashboard: GitHub, Okta, NVD cards green.
```sh
ix query users            # GitHub members + Okta users in ONE table (source column)
ix query events -n 5      # NVD CVEs, Okta logs, GitHub issues: same schema
```
> "Four real sources, four auth types (none, API key, Bearer, OAuth2), three paging styles, one common schema."

## 3. Add a new source live, from a blank file (90 s)
```sh
code connectors/cisa-kev.yaml        # type it (copy from the fixture); make ONE typo: trasform
ix validate connectors/cisa-kev.yaml # -> line 17: unknown key "trasform" (did you mean "transform"?)
#   fix the typo
ix test connectors/cisa-kev.yaml     # live: HTTP 200, 1,7xx records, 3 mapped samples, nothing written
ix add connectors/cisa-kev.yaml
ix run cisa-kev                      # fourth card turns green on the dashboard
git status                           # proof: the ONLY change is one new YAML file
grep -riE "github|okta|nvd|cisa" src/engine src/broker   # prints nothing: no provider code
```

## 4. Failures behave the same for every connector (60 s)
Use the mock connectors (`ix add test/fixtures/configs/mock-nvd-cves.yaml` etc. beforehand, with `MOCK_PORT=4010`).
```sh
curl "localhost:4010/__fault?mode=429&count=1&retry_after=30&after=1"; ix run mock-nvd-cves
#   -> waits 30 s (Retry-After), retries the same page, no duplicates
curl "localhost:4010/__fault?mode=drop&count=100&after=1"; ix run mock-nvd-cves
#   -> retries 1 s / 2 s / 4 s, fails, keeps checkpoint
curl "localhost:4010/__fault?mode=clear"; ix run mock-nvd-cves
#   -> "resumed from checkpoint"
curl "localhost:4010/__fault?mode=envelope&count=1&after=1"; ix run mock-nvd-cves
#   -> 200 OK but the wrong shape: failed, "records_path vulnerabilities[*] not found", never "0 records, success"
ix quarantine                        # bad records with reasons; run was "partial", not crashed
ix receipts mock-nvd-cves            # one receipt per run: incomplete (interrupted) -> verified (published once complete)
ix receipt <id>                      # facts vs inferences, schema fingerprint, digest + ledger anchor verified
curl "localhost:4010/__drift?rename_email=1"; ix run mock-okta-users   # schema change -> HELD, nothing published
ix held; ix approve <sync-id>        # a human publishes it (or ix discard); the approval gets its own receipt
```
Bad key: `ix secret set github_org_pat` (type junk) → `ix run github-members` → `auth_failed`, one attempt, alert raised. Then store the real token again.

## 5. The breach part (60 s)
```sh
npx pnpm@10.28.0 leakcheck -- /tmp/ix-dev.log   # zero hits: repo, logs, DB dump, worker/API process memory env
ix add test/fixtures/configs/bad-delete.yaml    # refused: connectors are read-only by contract
ix audit log --deny -n 5                        # runtime calls outside the allow-list, denied and logged
ix posture okta-users                           # blast radius: hosts, paths, scopes, age, revocability
```
- Dashboard: click **Posture** on a card; click **Kill switch** → every connector disabled, Okta token revoked at Okta, checklist for the rest.
```sh
ix audit verify                                 # hash chain intact; an edited row would be detected
```
After the demo: `for c in $(psql -d integratex -tAc "select id from connectors"); do ix enable $c; done`

## 6. Close (15 s)
> "One YAML file per source. The same retries, rate limiting and quarantine for every connector. And a breached hub gives up as little as possible: one broker holds the secrets, configs are signed allow-lists, every call is in a tamper-evident ledger, and one button revokes everything."

**Honest limit, if asked:** none of this stops someone who already stole a provider token from replaying it from their own machine. It shrinks what a breach of the hub itself can hand over.

## Numbers to quote
- 163 automated tests; all 4 PRD failure tests pass
- 6 real connectors (GitHub ×2, Okta ×2, NVD, CISA KEV) plus 5 vendor coverage connectors from the mentors' list
- 35 mentor products rated in `docs/coverage.md`: 12 fit today, 14 need a small generic feature, 9 out of scope
