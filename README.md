# SentinelTBO

Agentic Real-Time DAST control plane for a B2B travel platform (TBO Security Hackathon 2026).
A 9-stage autonomous loop — **detect → learn → inventory → plan → execute → verify → triage → report → retest** — driven by modular TypeScript agents, with every outbound request passing through an enforced safety layer.

> **Rules of Engagement:** the system only talks to an explicit host allowlist. The bundled target is a loopback-only synthetic staging mock with test accounts for agencies A and B. No production systems, no real credentials, no DoS, no destructive tests, no bulk extraction, no persistence of access. All requests are redacted, hash-chained and replayable.

## Quick start

```bash
npm install
npm run dev
```

- Web UI: <http://127.0.0.1:5173>
- Control plane API + SSE: <http://127.0.0.1:3001>
- Synthetic travel platform (staging only): <http://127.0.0.1:4000>

Open the UI, then press **Demo** in the top bar (or **Deploy v2.1** on Mission Control). The whole loop completes in a few seconds; watch the pipeline, event feed and findings appear live over SSE.

### Scripted 5-minute demo

```bash
npm run demo
```

Spawns the mock + API if needed, runs the full loop with deterministic offline reasoning, streams agent events to the terminal, prints the deploy→verified timer, then shuts the temporary servers down. Use `npm run demo -- --keep` to leave them running for the UI.

### Seed data

```bash
npm run seed          # runs one full loop against an already-running mock
npm run seed -- --reset
```

### Tests / checks

```bash
npm test              # safety unit tests + full end-to-end agent loop
npm run typecheck     # monorepo TypeScript check
npm run build:web     # production frontend bundle
```

## What the demo plants and finds

| Planted issue | Endpoint | Agent / proof | Expected triage |
| --- | --- | --- | --- |
| Booking IDOR across agencies | `GET /api/bookings/:id` | `AccessControl` / `bola` | Critical BOLA |
| Client-controlled fare | `POST /api/book` | `BusinessLogic` / `fare-tamper` | High |
| Double refund on cancel → rebook | `POST /api/cancel` | `BusinessLogic` / `double-refund` | High |
| Sub-agent → admin mass assignment | `POST /api/book` | `Hygiene` / `mass-assignment` | High |
| Coupon replay | `POST /api/pay` | `BusinessLogic` / `coupon-reuse` | High |
| Zombie legacy API | `GET /v1/bookings` | `AccessControl` / `Auth` | Medium/High |
| Shadow debug PII route | `GET /internal/debug` | `DataExposure` | High |
| Supplier webhook SSRF | `POST /api/supplier/webhook` | `SSRF` | High |
| v2.1 unauthenticated coupon stacking (hot deploy) | `GET /api/v2/coupons/stack` | `BusinessLogic` | High |

A deliberately flaky SQLi probe is reproduced once and then dropped by the verifier so the **false positives dropped** tab is populated.

## Monorepo layout

```
apps/
  mock/     Fastify synthetic travel platform (:4000, 127.0.0.1 only)
  api/      Fastify control plane (:3001), REST + Server-Sent Events
  web/      React + Vite + TypeScript + Tailwind + shadcn-style UI, Recharts, React Flow
packages/
  agents/   Agent interface, specialists, proofs, verifier, triage, reporter, retest,
            orchestrator, safety layer, SQLite store, deterministic LLM wrapper, seed
  shared/   Shared types, business-impact severity rubric, ownership map (assets.json)
scripts/    demo.ts (scripted end-to-end demo)
```

### Agent engine

- **Agents** implement a common `Agent<I, O>` interface (`packages/agents/src/agent.ts`).
- **LLM calls** go through one wrapper (`llm.ts`). Default provider is `mock`: deterministic and offline. `SENTINEL_LLM_PROVIDER=openai|anthropic` with `SENTINEL_LLM_API_KEY` switches providers — no paid-key dependency is added by default.
- **Recon**: HAR fixture ingestion, JS bundle route extraction, hidden-path probing (`/v1 /old /internal /test /beta`), CT-log subdomain correlation; optional Playwright crawl behind `SENTINEL_USE_PLAYWRIGHT=true` (falls back to HTTP discovery).
- **Inventory**: diffs the inferred graph against 30/90-day gateway traffic logs → active / zombie / shadow, ownership from `assets.json`, OpenAPI 3 export.
- **Planner**: one targeted test per parameter/role/business context, grouped by class, with reasoning.
- **Executors**: pluggable `AccessControl`, `BusinessLogic`, `Auth`, `Injection`, `Hygiene`, `DataExposure`, `SSRF`. Optional ZAP/Nuclei wrappers behind `SENTINEL_ENABLE_ZAP` / `SENTINEL_ENABLE_NUCLEI` (no tools installed by default).
- **Verifier**: replays each minimal proof twice against a control, dedupes and drops unstable hits; redacts PII and never bulk-extracts data.
- **Triage**: `shared/severity.ts` business-impact rubric (bookings, payments, credit, PII, supplier access), CWE/OWASP API Top 10 tags, owner mapping.
- **Reporter / Retest**: Jira-style markdown tickets, mock Jira/Teams/webhook adapters; "fix deployed" patches the mock, replays the stored proof, and closes or marks still vulnerable.

### Safety layer (`packages/agents/src/safety.ts`)

Every outbound request passes through `SafeHttpClient`, which calls `SafetyLayer.authorize()` before `fetch` and `recordResponse()` afterwards:

1. kill switch (hard stop),
2. scheme + host allowlist (exact host:port),
3. `x-sentinel-synthetic: true` marker and approved test-account token,
4. approval id for destructive methods on booking/payment/refund/cancel paths,
5. per-host token-bucket rate limiting,
6. health-based backoff and automatic pause on elevated error rate,
7. append-only audit record with SHA-256 hash chain and redacted replay payload.

Unit tests prove out-of-scope requests are blocked and logged.

## API endpoints (selected)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/state?window=30\|90` | Full dashboard snapshot |
| GET | `/api/events/stream` | SSE agent event stream |
| POST | `/api/triggers/deploy` | Real deploy webhook; starts a run |
| POST | `/api/triggers/fire` | Fire simulated change (`deploy`, `bundle-diff`, `subdomain`, `traffic-anomaly`) |
| POST | `/api/demo`, `/api/run`, `/api/reset` | Scripted demo / full run / reset |
| POST | `/api/approvals/:id` | `approved` / `rejected` / `modified` |
| POST | `/api/findings/:id/retest` | Deploy fix + replay proof |
| POST | `/api/tickets/:id/send` | Mock Jira / Teams / webhook delivery |
| PUT | `/api/safety`, `/api/webhook` | Scope, rate, kill switch, webhook config |
| GET | `/api/export/openapi`, `/api/export/audit` | Inferred spec / audit JSONL |

## Configuration

| Env var | Default | Meaning |
| --- | --- | --- |
| `SENTINEL_TARGET` | `http://127.0.0.1:4000` | Staging target (must be in allowlist) |
| `SENTINEL_ALLOWLIST` | `127.0.0.1:4000,localhost:4000,staging.travel.internal` | Comma-separated host:port scope |
| `SENTINEL_DB` | `data/sentinel.db` | SQLite database path |
| `SENTINEL_RATE_LIMIT` / `SENTINEL_BURST` | `12` / `20` | Token bucket settings |
| `SENTINEL_LLM_PROVIDER` | `mock` | `mock`, `openai`, `anthropic` |
| `SENTINEL_LLM_API_KEY` | — | Only needed for non-mock providers |
| `SENTINEL_USE_PLAYWRIGHT` | `false` | Enables optional browser crawl |
| `SENTINEL_ENABLE_ZAP` / `SENTINEL_ENABLE_NUCLEI` | `false` | Optional external tool wrappers |

No paid API key is required for any default feature.
