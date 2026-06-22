# CLAUDE.md — CVE Monitoring App (Vnotice)

This file gives Claude Code full context to **continue development** of this project.  
Read all sections before writing any code.

---

## What This Project Is

A full-stack CVE threat monitoring dashboard with:
- RSS/Atom feed ingestion + NVD API 2.0 sync
- Web scraper (regex) for non-RSS sources
- JWT authentication, multi-user profiles
- Multi-channel alert system (Teams implemented; Discord/Telegram/Email/SMS pending)
- Real-time filtering, severity tracking, export to CSV/JSON

**Stack:** FastAPI + PostgreSQL (Docker) / SQLite (local dev) · Next.js 14 + Tailwind

---

## How to Start

```powershell
# Local dev (SQLite, no Docker)
cd backend
.\setup_local.ps1        # creates venv, installs deps, starts uvicorn :8000

cd frontend
npm install && npm run dev   # → http://localhost:3000
```

```bash
# Full stack (Docker)
docker-compose up --build
# backend :8000 · frontend :3000 · postgres :5432
```

---

## Server Deployment (10.4.150.57, bare-metal, no Docker/root)

The `vnotice` user is **not** a sudoer and **not** in the docker group, and port
8000 is taken by Splunk — so the app runs bare-metal under **systemd user
services** with **lingering enabled** (`loginctl enable-linger vnotice`) so they
auto-start on boot without a login session.

| Service | Port | Unit |
|---|---|---|
| Backend (uvicorn, venv at `backend/venv_server`) | 8080 | `vnotice-backend.service` |
| Frontend (Next.js via nvm node v20) | 4000 | `vnotice-frontend.service` |

Unit files live in `deploy/` (repo) and are installed to
`~/.config/systemd/user/`. Manage with `XDG_RUNTIME_DIR=/run/user/$(id -u)`:

```bash
systemctl --user status vnotice-backend vnotice-frontend
systemctl --user restart vnotice-backend       # after backend code change
journalctl --user -u vnotice-backend -f         # or tail ~/backend.log
```

After a code change: upload files, `systemctl --user restart vnotice-backend`;
for frontend, `npm run build` then `systemctl --user restart vnotice-frontend`.
Both have `Restart=always`. Frontend's `getApiBase()` uses `DEFAULT_PORT=8080`.

> **pkill footgun:** `pkill -f 'uvicorn main:app'` over SSH self-matches the
> shell running it (the pattern is in its own argv) and drops the connection
> (exit 128). Use `systemctl --user stop`, a PID, or a `[u]vicorn`-style bracket
> pattern instead.

---

## Company Organisation — 3-Tier Agent Structure

This project follows the same org structure as Doc Template Studio (`../doc-template-studio/docs/COMPANY_POLICY.md`). The same rules apply here.

```
API Layer  (backend/main.py)
    ↓
┌──────────────────────────────────┐
│        MANAGER TIER              │
│  SyncManager   AlertManager      │
│  Orchestrates pipelines.         │
│  Enforces the Reviewer gate.     │
└──────┬───────────────────┬───────┘
       │                   │
  delegates            review gate
       ↓                   ↓
┌──────────────────┐  ┌──────────────────────┐
│   WORKER TIER    │  │   REVIEWER TIER       │
│                  │  │   CveReviewer         │
│ RssParserAgent   │  │   NotifReviewer       │
│ NvdAgent         │  │                       │
│ ScraperAgent     │  │ Validates CVE data    │
│ NotifAgent       │  │ before DB write.      │
│ StorageAgent     │  │ Validates notif       │
│ AuthAgent        │  │ payload before send.  │
└──────────────────┘  └──────────────────────┘
```

**The same inviolable rules apply:**
- Workers never call each other — coordination goes through Managers.
- All CVE data must pass `CveReviewer` before being written to the DB.
- All notification payloads must pass `NotifReviewer` before being sent.
- No external network call outside designated worker agents.

### Current Reality vs Target

The existing `rss_parser.py` and `main.py` contain monolithic inline logic. The migration plan is:

| Existing code | Target agent |
|---|---|
| `rss_parser.fetch_and_parse_rss()` | `RssParserAgent` (worker) |
| `rss_parser.fetch_nvd_api()` | `NvdAgent` (worker) |
| `rss_parser.scrape_webpage_regex()` | `ScraperAgent` (worker) |
| `main.py /sync/ route` logic | `SyncManager` (manager) |
| `main.py /notifications/teams` | `NotifAgent` (worker) + `AlertManager` (manager) |
| `auth.py` | `AuthAgent` (worker, already isolated) |
| DB writes scattered in `main.py` | `StorageAgent` (worker) |

Refactor incrementally — wrap existing functions rather than rewriting them wholesale.

---

## Development Teams

| Team | Code | Files Owned |
|---|---|---|
| **Alpha** — Core Engine | `α` | `backend/main.py`, `backend/rss_parser.py`, `backend/auth.py`, `backend/schemas.py`, `backend/tests/` |
| **Beta** — Frontend Experience | `β` | `frontend/src/` — all Next.js components |
| **Gamma** — Data & Storage | `γ` | `backend/models.py`, `backend/database.py` |
| **Delta** — DevOps | `δ` | `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`, `.github/workflows/` |

Full charters: `docs/teams/team_*.md`  
Full role specs: `docs/roles/*.md`

---

## Current Project State

### What Works ✅
- User registration, login (JWT), profile management
- CVE list (`GET /cves/`) with severity/vendor/product/search filters + pagination
- NVD API 2.0 sync — two-step startIndex approach (real CVSS, severity, CPE vendor/product)
- Splunk Security Advisories sync — `fetch_splunk_advisories()` parses the advisory.splunk.com HTML table for **real** severity/CVSS/CVE/product (routed by `advisory.splunk.com` in feed URL, like the NVD branch)
- Check Point Advisories sync — `fetch_checkpoint_advisories()` hits the support-center JSON API (`iapi-services-ucs.checkpoint.com/.../securityAdvisories/getAllActive`) because the public page is a client-rendered SPA that can't be scraped; returns **real** CVSS/severity/CVE/product (routed by `support.checkpoint.com` in feed URL)
- RSS/Atom feed sync for 13+ vendor feeds (Cisco/F5 XML fault-tolerance applied)
- Custom web regex scraper + Check Point advisory scraper
- All notification channels: Teams, Discord, Telegram, Email (SMTP), SMS (Twilio)
- Notification triggers CRUD (`POST/GET/DELETE /triggers/`)
- Feed & scraper config persisted to `UserConfig` on every `/sync/` call
- Auth required on `/sync/`, `/cves/clear-checkpoint`, all `/notifications/*`
- Health endpoint with system metrics
- Frontend: CVE table, filters, stats, operator console, dark mode, column management
- Docker Compose full-stack deployment
- SQLite local dev mode

> **SQLite schema note:** If you see `table user_configs has no column named smtp_host`,
> delete `backend/cvedb.sqlite` and restart — it will be recreated with the full schema.

### What Is Incomplete / Missing ❌

#### P1 — Frontend: Wire Notification Channels to Backend
Settings UI stores channel config in localStorage. It does not yet call the backend
`/notifications/{channel}` endpoints when a CVE triggers an alert.

Missing:
- When a sync adds CVEs matching `UserConfig.alert_keywords`, evaluate `NotificationTrigger` rules
  and POST to the appropriate `/notifications/{channel}` endpoint
- Settings "Test" buttons should call `POST /notifications/test-{channel}`

**Files to change:** `frontend/src/components/Settings.tsx`, `frontend/src/components/Dashboard.tsx`

---

#### P2 — Backend: Trigger Evaluation After Sync
`NotificationTrigger` CRUD endpoints exist. The sync handler does **not** evaluate them.

Missing:
- After inserting new CVEs, query the current user's triggers
- For each new CVE that matches a trigger (keyword/vendor/severity/cvss), fire the alert
  via the appropriate notification channel configured in `UserConfig`

**Files to change:** `backend/main.py` (bottom of `/sync/` handler)

---

#### P3 — Frontend: Load Feed Config from Backend
On login, frontend should call `GET /users/me/config` and restore `feeds_config` /
`scrapers_config` from the DB instead of only localStorage.

**Files to change:** `frontend/src/components/Dashboard.tsx`, `frontend/src/lib/api.ts`

---

#### P4 — Frontend: Dashboard Refactor
`Dashboard.tsx` is ~3300 lines — all state and UI in one component.

Refactor plan (Team Beta):
- Extract `useCveData()` hook (CVE state + filtering)
- Extract `useSyncState()` hook (sync status, countdown, logs)
- Extract `useAlertRules()` hook (alert rules + notification config)
- Move `mapApiCve()` and `inferVendorProduct()` to `frontend/src/lib/cveUtils.ts`
- Extract `<AlertsPanel>` component from Dashboard

**Files to change:** `frontend/src/components/Dashboard.tsx` (split out)

---

#### P5 — Tests: Missing Coverage
Current tests cover only auth and basic CVE list. Missing:

- `/sync/` test with mocked HTTP responses
- Each notification channel endpoint (mock httpx)
- Trigger CRUD endpoints
- Frontend: React Testing Library tests for `CveTable`, `Filters`

---

### Known Technical Debt
- `_infer_vendor_product()` duplicated in backend and frontend — centralise in backend
- `Dashboard.tsx` monolith (see P4)
- No rate limiting on any endpoint
- Weak default `SECRET_KEY` in `.env` (must be changed before production)
- CI pipeline lints but does not run pytest

---

## Key Files Reference

| File | Lines | Purpose |
|---|---|---|
| `backend/main.py` | 589 | All FastAPI routes — auth, CVEs, sync, notifications, health |
| `backend/models.py` | 132 | `User`, `CVE`, `UserConfig`, `NotificationTrigger` ORM models |
| `backend/rss_parser.py` | 377 | RSS fetch, NVD API 2.0, web scraper, vendor inference |
| `backend/auth.py` | 52 | JWT create/verify, bcrypt password hashing |
| `backend/schemas.py` | 147 | Pydantic request/response models |
| `backend/tests/test_main.py` | 100 | Auth + CVE list tests (in-memory SQLite) |
| `frontend/src/components/Dashboard.tsx` | 3338 | Monolithic main component — all state + UI |
| `frontend/src/components/CveTable.tsx` | 331 | Resizable/sortable CVE table |
| `frontend/src/components/Filters.tsx` | 163 | Severity/keyword/feed filters |
| `frontend/src/lib/api.ts` | — | Axios API client |

---

## API Routes (current)

```
POST  /token                      Login → JWT
POST  /users/                     Register user
GET   /users/me                   Get current user (auth required)
PUT   /users/me                   Update profile (auth required)
GET   /users/me/config            Get user config (auth required)
PUT   /users/me/config            Update user config (auth required)

GET   /cves/                      List CVEs (severity/vendor/product/search/skip/limit)
GET   /cves/{cve_id}              Get single CVE

POST  /sync/                      Trigger feed sync (auth required)
DELETE /cves/clear-checkpoint     Delete Check Point CVEs (auth required)

POST  /notifications/teams        Send Teams alert (auth required)
POST  /notifications/test-teams   Test Teams webhook (auth required)
POST  /notifications/discord      Send Discord alert (auth required)
POST  /notifications/test-discord Test Discord webhook (auth required)
POST  /notifications/telegram     Send Telegram alert (auth required)
POST  /notifications/test-telegram Test Telegram bot (auth required)
POST  /notifications/email        Send email alert via SMTP (auth required)
POST  /notifications/test-email   Test SMTP config (auth required)
POST  /notifications/sms          Send SMS via Twilio (auth required)
POST  /notifications/test-sms     Test Twilio config (auth required)

POST  /triggers/                  Create notification trigger (auth required)
GET   /triggers/                  List user's triggers (auth required)
DELETE /triggers/{id}             Delete a trigger (auth required)

GET   /health/                    System health (uptime, CPU, memory, DB status)
GET   /                           Root health check
```

---

## Database Schema Summary

**`users`** — id(UUID), email, username, password_hash, role, is_active  
**`cves`** — id(UUID), cve_id, title, description, severity, cvss_score, epss, published_date, vendor, product, reference_url, rss_source — unique(cve_id, rss_source)  
**`user_configs`** — theme, polling_interval, notify_* flags, webhook URLs, feeds_config(JSON), scrapers_config(JSON), alert_keywords(JSON)  
**`notification_triggers`** — template_id(FK), keyword, vendor, product, min_severity, min_cvss_score

---

## Documentation

Full policy and role docs in `docs/`:
- `docs/INDEX.md` — navigation
- `docs/COMPANY_POLICY.md` — standards (references shared policy)
- `docs/roles/` — SyncManager, AlertManager, CveReviewer, RssParserAgent, NvdAgent, ScraperAgent, NotifAgent, StorageAgent
- `docs/teams/` — Alpha, Beta, Gamma, Delta charters
- `docs/BACKLOG.md` — full prioritised task list with acceptance criteria

---

## Where to Start in a New Session

1. Read this file top to bottom.
2. Pick the highest priority incomplete item (P1 → Discord/Telegram/Email/SMS endpoints).
3. Check the relevant role doc (`docs/roles/notif_agent.md`) for the interface contract.
4. Implement, run `pytest tests/test_main.py -v`, verify clean.
5. Move to next item.
