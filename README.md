# IntegrateX

IntegrateX is a config-driven security integration platform. Adding a security data source means writing one YAML file, not code. Every connector automatically gets:

- auth: API key, Bearer, Basic, OAuth2 client credentials;
- paging (six styles), schedules, retries with backoff, and 429/Retry-After handling;
- quarantine for bad records, checkpoints with resume, and a circuit breaker;
- mapping into a common `users` / `devices` / `events` store.

It is designed for the case where the hub itself is breached. A credential broker is the only component that holds secrets or makes outbound calls. Each config declares the hosts, paths and methods the broker may call. Secrets are envelope-encrypted.

## Setup (macOS, Homebrew Postgres 16)

```sh
npx pnpm@10.28.0 install
cp .env.example .env                      # app settings (no broker secrets)
cp .env.broker.example .env.broker        # IX_MASTER_KEY=$(openssl rand -base64 32), broker + admin DB URLs
cp .env.admin.example .env.admin          # IX_BROKER_ADMIN_TOKEN=$(openssl rand -hex 24); `pnpm dev` creates it if missing
chmod 600 .env .env.broker .env.admin
createdb integratex
npx tsx src/store/migrate.ts      # tables, DB roles, append-only audit ledger
npx pnpm@10.28.0 test             # uses a separate integratex_test database
npx pnpm@10.28.0 lint             # ESLint: TypeScript (typescript-eslint) + dashboard scripts; fails on errors
```

**TLS on Homebrew Node:** if HTTPS calls fail with `UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, your Node build can't find a CA bundle. Add this to `~/.zshrc`:
```sh
export NODE_EXTRA_CA_CERTS=/opt/homebrew/etc/ca-certificates/cert.pem
```

## Using it

```sh
alias ix="npx tsx src/cli/ix.ts"
ix validate connectors/*.yaml           # line-numbered errors and policy warnings
ix secret set github_pat                # hidden prompt; or: ix secret set okta_private_key < key.pem
ix test connectors/github-members.yaml  # auth + first page + 3 mapped records + granted scopes; writes nothing
ix add connectors/github-members.yaml
ix run github-members
ix posture github-members                 # blast radius, granted scopes and policy history
ix rehearse                              # dry-run incident response checks; no changes made
ix panic --yes                            # disable all connectors and show a revocation checklist
ix query users --source github
ix runs github-members
ix quarantine
```

**Try it without any keys:**
```sh
ix add test/fixtures/configs/cisa-kev.yaml && ix run cisa-kev   # live, public feed
npx tsx mock/server.ts                                           # mock providers on :4010
```
The mock server also has `/__fault?mode=429|503|timeout|drop&count=N&retry_after=S&after=K` and `/__drift?rename_email=1`.

## Running the platform (broker, scheduler, worker, API, dashboard)

```sh
npx pnpm@10.28.0 dev          # broker + api + scheduler + worker as separate processes
npx pnpm@10.28.0 dev:mock     # same, plus mock providers on :4010 (broker accepts their fake IX_SECRET_* env)
open http://localhost:7070    # dashboard: health cards, run history, records, quarantine
```

- **Scheduler:** turns each config's `schedule.every` (plus jitter) into queued runs. Paused connectors are skipped until their cool-down ends.
- **Worker:** runs the queued jobs. Only one run per connector can be queued or active at a time.
- **Single-flight runs:** every run, from the worker or `ix run`, holds a PostgreSQL session advisory lock for its connector for the whole run, on a dedicated connection. A second run of the same connector is refused: `ix run` exits with code 2 and "already running", and the worker skips the job. Different connectors run in parallel. If the holding process dies, PostgreSQL drops its session and the lock with it.
  - **Lock loss fails closed.** Before every request a run checks its lock session is alive. Every page-commit transaction, and the final watermark write, re-checks in `pg_locks` that the lock is still granted to that session, and aborts if not. A run that lost its lock commits no more pages, saves no watermark and ends as `failed`. Residual window: between that check and the COMMIT of the same transaction.
- **Atomic finalisation:** a run's final status and its new watermark are written in one transaction. If that transaction fails, the run stays `running`, the watermark is unchanged, and the next run re-fetches the same window.
- **API:** read routes are open on localhost. Routes that change state need `Authorization: Bearer $IX_ADMIN_TOKEN`; the dashboard's "Run now" button asks for the token.
- **Hygiene and alerts:** the scheduler disables connectors past `credential.idle_disable_days`, flags credentials past `max_age_days`, and delivers failure, auth, drift, breaker and panic alerts through the broker. Store webhook URLs as broker secrets; only `hooks.slack.com` is allowed by default (`IX_ALERT_WEBHOOK_HOSTS` can add approved hosts).
- **Incremental sync:** streams can define `incremental.cursor_field`, `param`, `template` and `initial`. `{{now}}` is available for bounded windows such as NVD's `lastModEndDate`. The watermark moves only after a clean run: every page seen, nothing quarantined, not degraded. If a run quarantines anything, the previous watermark is kept and the same window is replayed next run; idempotent upserts absorb the duplicates. Trade-off: until the bad record is fixed, every run re-fetches that window and quarantines the record again. Not loss-proof yet: per-provider cursor rules are not implemented (timestamp precision, inclusive or exclusive filters, overlap windows). Neither is tie-breaking when several records share the watermark timestamp. With an exclusive filter, a record that has the same timestamp as the watermark but arrives after a run can be missed.
- **No false "success":**
  - A 200 response whose shape doesn't match `records_path` fails the run with the keys it did find. That covers a missing envelope, an empty body, or an error object.
  - Pagination that stops without proof of the last page also fails the run: a repeated cursor, a request cycle, a page identical to an earlier one, a missing `total_path`, or `is_last_path` not true.
  - `data: null` and an empty array are valid empty pages.
- **Raw payloads:** `data.store_raw: true` stores a secret-redacted raw record under `attributes._raw`; it is off by default and requires `data.redact_secrets: true`.
- **Incident-response rehearsal:** `ix rehearse` checks broker reachability, audit-ledger integrity and connector posture, then previews the panic actions and manual-revocation checklist. It does not disable connectors, cancel jobs, revoke tokens, send alerts, or purge secrets. Use `ix rehearse --json` for machine-readable output.

| Route | Purpose |
|---|---|
| `GET /v1/health` | Status, last run, records pulled, last error and next run for every connector |
| `GET /v1/records/:entity?source=&since=&type=` | users / devices / events from the common store |
| `GET /v1/connectors/:id/runs` | Run history |
| `GET /v1/connectors/:id/posture` | Reach, mapped fields, credential age/scopes, and policy violations |
| `GET /v1/alerts` | Recent alerts and delivery state |
| `GET /v1/quarantine` | Records that failed mapping, with the reasons |
| `POST /v1/configs/validate` | Validate YAML: line-numbered errors and warnings |
| `POST /v1/connectors`, `PUT /v1/connectors/:id` | Register a connector or store a new version (admin) |
| `POST /v1/connectors/:id/runs` | Run now (admin) |
| `POST /v1/panic` | Disable every connector, cancel queued runs, wipe broker token caches, and return a revocation checklist (admin; accepts `{"purge_secrets":true}`) |

## Security model (what a breached hub gives up)

- **Broker process.** It is the only process with the master key and the broker database role. It listens on two Unix sockets, both mode `0600`.
  - **Request socket** (`/tmp/ix-broker.sock`): workers and the scheduler send "fetch this URL for connector X" and get back status, headers and body. They never see a credential. This socket serves nothing else: no registration, secrets, removal or panic.
  - **Admin socket** (`/tmp/ix-broker-admin.sock`): registration and signing, secrets, re-enabling, removal, panic and ledger verification. Every call needs `IX_BROKER_ADMIN_TOKEN` (in `.env.admin`), which only the API and CLI load. Refused calls are written to the ledger.
  - Worker, API and scheduler **refuse to start** if `IX_MASTER_KEY`, `DATABASE_URL_BROKER`, `DATABASE_URL_ADMIN` or `IX_SECRET_*` are in their environment. The worker and scheduler also refuse `IX_BROKER_ADMIN_TOKEN`.
- **Secrets are bound to hosts.** Registration is refused unless you pass `ix add|update --confirm-hosts` (API: `?confirm_hosts=1`), and the ledger records each approval, in two cases:
  - a config would send a secret that is already in use to a host no approved config sends it to;
  - it would be the first approved use of a secret that is stored but used by no connector. That happens when the secret was set before registering, or kept when its connector was removed.
  - Registering first and then setting the secret needs no confirmation. Host history is rebuilt from active configs and not stored separately, so re-adding a removed connector also asks again.
- **Workers can't flush broker caches.** Cache invalidation (`/v1/forget`) is admin-only and scoped to one connector unless no id is given. The broker drops a connector's OAuth token by itself when a new config version is approved.
- **Abuse limits.**
  - **Alerts:** a caller names a pending row in `alerts`, not a message. The broker builds the text from that row and marks it delivered once sent.
  - **At least once:** an alert already marked delivered is never sent again. If the broker crashes after the webhook accepted a message but before recording it, that alert is sent again; Slack webhooks don't de-duplicate.
  - **Lost broker response:** the scheduler marks an alert as an error only while it is still pending. A delivery the broker committed keeps `channel = 'slack'` and still counts toward the throttle, even if its response never arrived. "Already delivered" counts as done.
  - **Throttle:** delivery is limited per connector and overall, counted from the delivery history in `alerts`, so a broker restart doesn't reset it. Throttled alerts stay pending and are retried.
  - **Gap:** the broker doesn't check where an alert row came from, and the pending queue has no size limit. A compromised worker can insert forged alerts. The throttle limits how fast they are sent, not how many queue up, and forged rows ahead of real ones use up the throttle first, which delays real alerts.
  - **Denial floods:** repeated bad admin tokens or throttled alerts write one ledger row per minute. Each row stores how many requests it stands for in `records`, which is inside the hash chain. Posture counts requests, not rows, and shows both. If the broker crashes without a clean shutdown, denials suppressed in the open window are lost; the first one of each window is always written.
- **The app database role cannot undo the kill switch.** It can disable and pause connectors, but cannot re-enable a disabled one or change the active config version (column grants plus a trigger). `ix enable` goes through the broker.
- **Signed configs.** Configs are registered through the broker, which signs each version (an HMAC keyed from the master key). At request time it only honours versions it signed, so a rogue config row can't point a stored secret at a new host.
  - This holds even if someone writes that row straight into the database.
  - The app database role can't write config versions at all.
- **Write-only secrets.** `ix secret set` / `PUT /v1/secrets/:ref` send values into the broker. No route returns a value, and `ix secret list` shows only names, age and last use.
- **Audit ledger.** Every outbound call, policy denial, token request, secret change and registration is appended to a hash-chained `audit_ledger`.
  - Rows are append-only, enforced by grants and a trigger.
  - `ix audit verify` recomputes the chain; `ix audit log --deny` shows refused calls.
- **Leak check:**
  ```sh
  npx pnpm@10.28.0 leakcheck -- /path/to/logs/*.log
  ```
  It decrypts every stored secret in memory, then searches the repo, `.env`, the given logs, a full database dump and the environments of running app processes, in raw, base64 and URL-encoded form. It prints secret names only.

Limits:
- None of this stops someone who already stole a provider token from replaying it from their own machine. It limits what a breach of IntegrateX itself can hand over.
- A worker can still create ledger rows through policy-denied `/v1/request` calls (one row per denial; posture cards count them). Per-connector request rate limits for denials aren't implemented yet.
- In `pnpm dev`, every process runs as **one OS user**. Code running as that user can read `.env.broker` and `.env.admin` from disk. The socket split stops a worker that can only talk to the broker; it does not stop full code execution as the same user. For real isolation, run the broker as its own OS user and make `.env.broker` readable only by it.

## Accepted residual risks

Accepted on 2026-11-01 for the current development and hackathon scope only. These are **known, unresolved risks, not security controls**. They don't justify any claim of production-grade isolation or alert integrity.

| Risk | What remains possible | Planned fix |
|---|---|---|
| Alert provenance and an unbounded pending queue | The app role can insert alert rows, so a compromised worker can queue forged alerts. The throttle limits how fast they're sent, not how many queue up. Forged rows ahead of real ones can delay real alerts. | T11 |
| Same-UID process isolation | In `pnpm dev` the broker, API, worker and scheduler run as one OS user. Code running as that user can read `.env.broker` and `.env.admin`, which defeats the socket split and the encryption at rest. | T12 |

## Where things are

| Path | What |
|---|---|
| `connectors/` | Real sources: GitHub, NVD, Okta, CISA KEV |
| `connectors/coverage/` | Vendor coverage configs: CrowdStrike, Trend Vision One, Netskope, FortiGate, Elastic. See `docs/coverage.md`. |
| `src/config` | Zod schema, validator, `${env.X}` interpolation |
| `src/broker` | Broker process (socket server and client), policy, auth, OAuth2, retries, rate limits, encrypted secrets, signed configs, audit ledger. **No provider-specific code.** |
| `src/security` | Posture, credential hygiene, panic, alert delivery and leak check |
| `src/engine` | Runner, paging, checkpoints, drift, breaker. **No provider-specific code.** |
| `src/mapping` | Path resolver, transforms, mapper, secret scanner |
| `src/store` | Postgres: upserts, runs, quarantine, connector versions, health |
| `src/scheduler`, `src/worker` | Job queue (pg-boss), schedule ticks, run execution |
| `src/api` | Fastify API and the static dashboard (`public/`) |

Check that the engine and broker stay provider-neutral:
```sh
grep -riE "github|okta|nvd|cisa" src/engine src/broker   # must print nothing
```
