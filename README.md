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
cp .env.example .env              # fill in DB URLs; IX_MASTER_KEY=$(openssl rand -base64 32)
createdb integratex
npx tsx src/store/migrate.ts      # tables, DB roles, append-only audit ledger
npx pnpm@10.28.0 test             # uses a separate integratex_test database
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

## Running the platform (scheduler, worker, API, dashboard)

```sh
npx pnpm@10.28.0 dev          # api + scheduler + worker as separate processes
npx pnpm@10.28.0 dev:mock     # same, plus the mock providers on :4010
open http://localhost:7070    # dashboard: health cards, run history, records, quarantine
```

- **Scheduler:** turns each config's `schedule.every` (plus jitter) into queued runs. Paused connectors are skipped until their cool-down ends.
- **Worker:** runs the queued jobs. Only one run per connector can be queued or active at a time.
- **API:** read routes are open on localhost. Routes that change state need `Authorization: Bearer $IX_ADMIN_TOKEN`; the dashboard's "Run now" button asks for the token.

| Route | Purpose |
|---|---|
| `GET /v1/health` | Status, last run, records pulled, last error and next run for every connector |
| `GET /v1/records/:entity?source=&since=&type=` | users / devices / events from the common store |
| `GET /v1/connectors/:id/runs` | Run history |
| `GET /v1/quarantine` | Records that failed mapping, with the reasons |
| `POST /v1/configs/validate` | Validate YAML: line-numbered errors and warnings |
| `POST /v1/connectors`, `PUT /v1/connectors/:id` | Register a connector or store a new version (admin) |
| `POST /v1/connectors/:id/runs` | Run now (admin) |

## Where things are

| Path | What |
|---|---|
| `connectors/` | Real sources: GitHub, NVD, Okta |
| `connectors/coverage/` | Vendor coverage configs: CrowdStrike, Trend Vision One, Netskope, FortiGate, Elastic. See `docs/coverage.md`. |
| `src/config` | Zod schema, validator, `${env.X}` interpolation |
| `src/broker` | Policy, auth, OAuth2, retries, rate limits, encrypted secrets. **No provider-specific code.** |
| `src/engine` | Runner, paging, checkpoints, drift, breaker. **No provider-specific code.** |
| `src/mapping` | Path resolver, transforms, mapper, secret scanner |
| `src/store` | Postgres: upserts, runs, quarantine, connector versions, health |
| `src/scheduler`, `src/worker` | Job queue (pg-boss), schedule ticks, run execution |
| `src/api` | Fastify API and the static dashboard (`public/`) |

Check that the engine and broker stay provider-neutral:
```sh
grep -riE "github|okta|nvd|cisa" src/engine src/broker   # must print nothing
```
