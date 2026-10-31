# Integration coverage: the mentors' 35 products

How each product's API maps onto the IntegrateX config format (`apiVersion: ix/v1`).

**Basis:** vendors' public API documentation as we understand it, not live tenants. Most of these products need paid licences or sales-gated trials. Before going live, check every endpoint, field name and paging detail against your own tenant.

**Legend**
- ✅ **Fits today.** A config file is enough.
- 🟡 **Fits with a planned generic feature.** The engine needs a feature that works for any provider; no provider-specific code.
- 🔴 **Out of scope for this build.** Non-HTTP/JSON transport, on-prem only, or no public read API.
- 🧪 **Coverage connector.** We wrote the config in `connectors/coverage/` and test it against a mock that copies the vendor's documented response shape.

## Summary

| Status | Count |
|---|---|
| ✅ Fits today (5 with a coverage connector) | 12 |
| 🟡 Needs a generic feature | 14 |
| 🔴 Out of scope | 9 |

Engine features added in Phase 4 because of this list. All are generic and contain no provider names:
- `body_link` paging: the next-page URL comes from the JSON body.
- `offset` paging without a total: stops on a short page.
- **Read-only POST:** only to paths listed in `policy.read_only_post`, with a fixed body template. Paging params can go in the body.
- `${env.X:-default}` for non-secret values, so one file can target the real host or a mock.

## SIEM / XDR

| Product | Auth | Paging / shape | Status |
|---|---|---|---|
| Elastic Security | `Authorization: ApiKey …` (project API key, read-only on `.alerts-security.alerts-*`) | `POST _search`, `from`/`size` in body, `hits.total.value` | ✅ 🟢 **verified live** on an Elastic Cloud Serverless Security project: real detection alerts, mapped with no config change. `elastic-security-alerts.yaml` (read-only POST) |
| Palo Alto Cortex XSIAM | API key header + non-secret key-id header | POST search with `search_from`/`search_to` in body | ✅ read-only POST; key id goes in `request.headers` |
| ManageEngine Log360 | API key | REST, mostly on-prem | 🔴 on-prem, varies by version |
| LogRhythm | Bearer token | REST (search API is async: submit, then poll) | 🟡 async search jobs |
| OpenText ArcSight | session token login | XML or JSON, on-prem | 🔴 session login + on-prem |
| Gurucul | vendor-specific | not publicly documented | 🔴 no public docs |
| Seceon | vendor-specific | not publicly documented | 🔴 no public docs |
| Binary Search | not identified | none | 🔴 couldn't identify a public API |

## EDR / XDR

| Product | Auth | Paging / shape | Status |
|---|---|---|---|
| CrowdStrike (hosts, cloud security) | OAuth2 client credentials | offset + `meta.pagination.total` | ✅ 🧪 `crowdstrike-devices.yaml`. **Provides Device rows.** |
| Trend Micro Vision One | Bearer API key | `nextLink` in body | ✅ 🧪 `trendmicro-visionone-alerts.yaml` (body_link) |
| Sophos Intercept X (Central) | OAuth2 client credentials | the tenant's data-region host is discovered via a `whoami` call | 🟡 base URL discovered at runtime |
| Kaspersky EDR | API token | on-prem console REST | 🟡 differs per deployment |
| Seqrite XDR | API key | REST JSON | ✅ likely fits; docs need checking |
| Trellix EDR | OAuth2 client credentials | REST JSON | ✅ OAuth2 + offset |
| Symantec Endpoint Security (cloud) | OAuth2 client credentials | REST JSON, `next` cursor | ✅ OAuth2 + cursor |

## DLP

| Product | Auth | Paging / shape | Status |
|---|---|---|---|
| Netskope DLP | `Netskope-Api-Token` header | offset/limit, no total | ✅ 🧪 `netskope-alerts.yaml` |
| Zscaler DLP | session cookie (`/authenticatedSession`) | REST JSON | 🟡 session-login auth |
| Forcepoint DLP | access token from a login call | REST JSON | 🟡 two-step token login |
| Symantec DLP | Basic | REST, on-prem Enforce server | ✅ basic + offset (on-prem) |
| Digital Guardian | OAuth2 client credentials | REST JSON (export API) | ✅ likely fits |
| Trellix DLP | through the ePO console | on-prem | 🔴 on-prem console |
| Safetica | vendor-specific | limited public docs | 🔴 no public docs |

## Firewalls

| Product | Auth | Paging / shape | Status |
|---|---|---|---|
| Fortinet FortiGate | REST admin token as Bearer | single page or `start`/`count` | ✅ 🧪 `fortigate-devices.yaml`. **Provides Device rows.** |
| Check Point | `POST /login` session, then POST for every call | JSON | 🟡 session login + POST-only reads |
| Cisco Secure Firewall (FMC) | token from `POST generatetoken` in response headers | offset/limit, `paging.next` | 🟡 header-token login |
| SonicWall | Basic → session | REST JSON | 🟡 session login |
| Sophos Firewall | XML API | XML | 🔴 XML responses |
| Juniper SRX | NETCONF / XML | not HTTP JSON | 🔴 non-HTTP |
| WatchGuard Firebox (Cloud) | OAuth2 client credentials + a secret API key header | REST JSON | 🟡 two credentials on one request |

## Cloud security

| Product | Auth | Paging / shape | Status |
|---|---|---|---|
| AWS Security Hub / GuardDuty | AWS SigV4 request signing | `POST GetFindings`, `NextToken` in body | 🟡 SigV4 auth + read-only POST |
| Google Security Command Center | service-account JWT (OAuth2 JWT bearer) | `nextPageToken` cursor | 🟡 JWT-bearer grant (close to our private_key_jwt) |
| Wiz | OAuth2 client credentials | GraphQL POST, `endCursor` in variables | 🟡 GraphQL cursor in the body |
| Prisma Cloud | `POST /login`, then `x-redlock-auth` | POST search, `nextPageToken` | 🟡 token login + read-only POST |
| Orca Security | API token header | REST JSON, `next_page_token` | ✅ cursor |
| Lacework FortiCNAPP | access token from key ID + secret | REST, `nextPage` URL in body | 🟡 token exchange, then body_link |

## Generic features, by how many products each one unlocks

1. **Login-then-token auth** (POST credentials, read a token from the body or a header, cache it): Check Point, Cisco FMC, Prisma Cloud, Forcepoint, Lacework, ArcSight, SonicWall, Zscaler. This generalises our OAuth token manager.
2. **AWS SigV4 signing:** Security Hub, GuardDuty and other AWS sources.
3. **Base URL discovered at runtime:** Sophos Central.
4. **GraphQL cursor in body variables:** Wiz.
5. **XML responses:** Sophos Firewall, parts of ArcSight.

## Known limits of the current coverage connectors

- **Mock fidelity:** the mocks copy the documented response *shape*, not the vendors' full behaviour (filters, rate-limit headers, regional hosts).
- **CrowdStrike:** some tenants expose only a two-step flow: a query returns host IDs, then a POST fetches the details. That needs a "fetch details for these IDs" step, which isn't built.
- **Elastic:** `from`/`size` paging is capped at 10,000 hits. Larger backfills need `search_after` (cursor in body).
