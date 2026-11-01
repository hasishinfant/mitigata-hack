# IntegrateX

IntegrateX is a config-driven security integration platform. Adding a security data source means writing one YAML file, not code. Every connector automatically gets:

- auth: API key, Bearer, Basic, OAuth2 client credentials;
- paging (six styles), schedules, retries with backoff, and 429/Retry-After handling;
- quarantine for bad records, checkpoints with resume, and a circuit breaker;
- mapping into a common `users` / `devices` / `events` store.

It is designed for the case where the hub itself is breached. A credential broker is the only component that holds secrets or makes outbound calls. Each config declares the hosts, paths and methods the broker may call. Secrets are envelope-encrypted.

## Setup (macOS, Homebrew Postgres 16)

**Node 22.19 or later.** That's the real minimum: the broker's HTTP client (`undici` 8) needs Node ≥ 22.19 and the job queue (`pg-boss` 12) needs ≥ 22.12. The ESLint 10 lint gate (Node ≥ 22.13 on the 22 line) fits within that. The earlier `>=20.12` didn't match the dependencies.

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
  - **Writes happen on the lock's session.** Page commits and the final status-plus-watermark transaction run on the connection that holds the lock. PostgreSQL releases the lock only when that session ends, and ending a session rolls back any transaction still open on it. So an old run's write either commits while it still holds the lock or not at all; a replacement can only take the lock after that. A run that lost its lock writes no more records, checkpoints or watermark. Only its own run-history row is marked `failed`, through another connection. A session ping before each request stops it early.
  - **Lock loss is not a provider failure.** Its run is `failed` with an error starting "run lock lost". That never opens the circuit breaker or raises a consecutive-failure alert, and it's left out of failure streaks. A provider request that was already in flight when the session died may still finish, but its results can't be committed.
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

## Data integrity: staged syncs and Sync Integrity Receipts

A run's records are **staged**, not published. The common `users`, `devices` and `events` tables only change when the whole sync is judged trustworthy. A sync is one or more runs of a stream, resumed from checkpoints. Publication then happens in one transaction on the run's lock session, together with the run's status, the watermark and the receipt.

| Decision | When | What happens |
|---|---|---|
| `verified` | Every page seen, the provider signalled the last page, within quality limits | Staged records are published |
| `verified_empty` | Complete, and the provider explicitly returned no records | Nothing to publish; that is a valid result |
| `held` | Complete, but the schema changed (a field the mapping reads disappeared or changed type), too much was quarantined (default over 10%), or fewer records than `expect.min_records` | **Nothing is published.** It waits for `ix approve <sync>` or `ix discard <sync>`, or the dashboard's Receipts panel. Approval is refused if a newer sync has been published since. |
| `incomplete` | A per-run cap was hit, the run failed with a resumable position, or the lock was lost | Staged records are kept; the next run continues the same sync |
| `rejected` | Pagination anomaly, or a failure with no position to resume from | Staged records are discarded |

Per-stream limits: `expect: { max_quarantine_ratio: 0.1, min_records: 0 }`.

**Receipts.** Every run, approval and discard writes a **Sync Integrity Receipt**. It records:
- the config hash and version;
- each page's HTTP status and body sha256;
- record counts for the run and for the sync;
- how pagination ended;
- a recursive **schema fingerprint**, and its difference from the last published sync;
- freshness of the newest record;
- the watermark decision;
- the decision and its reasons;
- what was published.

Receipts separate **facts** (observed) from **inferences** ("pagination complete" is inferred from the provider's last-page signal). They also list what they **don't claim**: that the provider's data is true or complete.

**Tamper evidence.** `digest` is the sha256 of the receipt's canonical JSON. The broker re-reads each receipt, recomputes its digest and anchors it once in the hash-chained audit ledger. The app role can insert receipts but never change or delete one. `ix receipt <id>` (or a click in the dashboard) recomputes the digest and checks the anchor. An edited receipt shows as "does not match".

Commands: `ix receipts <connector>`, `ix receipt <id> [--json]`, `ix held`, `ix approve <sync>`, `ix discard <sync>`.

Limits:
- A receipt proves what IntegrateX saw and decided, not that upstream data is true.
- Staging holds a whole sync in Postgres. Large backfills are bounded by `max_records_per_run`, and continue over several runs.
- Records deleted at the source are still not removed (there's no deletion tracking yet).

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
- **DPoP-bound OAuth tokens (RFC 9449).** With `connection.auth.dpop: true`, every access token is bound to a P-256 key that exists only in broker memory. The key is generated per token, never stored, and dropped with the token.
  - The token request and every API call (including retries) carry a fresh proof. API proofs are tied to the token (`ath`) and to the request's method and URL. Server nonces are handled.
  - **A stolen token is rejected** whether presented as Bearer, with another key, or with a replayed proof.
  - If a provider returns an unbound Bearer token anyway, the broker refuses it. Workers can't set a `DPoP` header.
  - The provider must support DPoP (Okta does for service apps, for example); verify yours before enabling it.
  - Posture shows `token_binding` and flags OAuth connectors without it.
  - It doesn't help if an attacker controls the live broker process: they can sign proofs while they're inside it.
- **Credential canaries (decoys).** `ix canary create okta_admin_token` stores a decoy that looks and is encrypted exactly like a real secret. Its value carries an HMAC tag keyed from the master key, so only the broker can tell it's a decoy (`ix canary list`).
  - **Inside the hub:** if anything makes the broker use a decoy (a config or request referencing it), it's refused before any outbound call, logged, and raised as a critical `canary_triggered` alert.
  - **Outside the hub:** `--url` decoys look like webhooks pointing at the hub's `/hooks/...` listener. Using one alarms with the caller's IP and user agent, and the dashboard shows a red banner. Use `--print` to plant copies in fake files.
  - The leak check ignores decoys.
  - Limit: a decoy API key tried directly at a real provider is only detected if that provider reports it. In production the listener must be reachable at `IX_CANARY_BASE_URL`; in dev the API binds to localhost.
- **IP allow-listing (enforced by the provider, verified and watched by IntegrateX).** The control that defeats a stolen token used elsewhere is the provider's IP allow-list (Okta network zones, GitHub's IP allow list, and so on). IntegrateX makes it checkable:
  - **Declare the hub's egress IPs:** `IX_EGRESS_IPS=198.51.100.10,10.0.0.0/8` in `.env`. These are the IPs to register at each provider.
  - **Declare what's set at the provider:** `credential.provider_ip_allowlist: [198.51.100.0/24]`. The posture card checks the hub's egress IPs are inside it (if not, the provider will reject the hub's calls; high flag), and flags open lists (`/0`) and undeclared egress.
  - **Detect use from elsewhere:** `detect` rules on a stream that reads a provider's audit log. For example:
    ```yaml
    detect:
      - name: hub OAuth client used from outside the hub
        match: { "actor.alternateId": "${env.OKTA_CLIENT_ID}" }   # field names: verify against your tenant's log
        ip_path: client.ipAddress
        allowed_ips: ["${env.IX_EGRESS_IPS}"]
    ```
    Matching records from other IPs raise a `foreign_ip_use` alert and are listed in that sync's receipt.
  - Limit: IntegrateX can't set the provider's allow-list itself, because connectors are read-only. It only declares, verifies and detects.
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
