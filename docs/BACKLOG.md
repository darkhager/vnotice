# Vnotice — Development Backlog

**Last updated:** 2026-06-12  
**Status key:** 🔴 Not started · 🟡 Partial · ✅ Done

---

## P1 — Notification Channels (Backend) ✅ DONE

### Discord Webhook
- ✅ `POST /notifications/discord`
- ✅ `POST /notifications/test-discord`

### Telegram Bot
- ✅ `POST /notifications/telegram`
- ✅ `POST /notifications/test-telegram`

### Email (SMTP)
- ✅ `POST /notifications/email` — uses stdlib smtplib, STARTTLS + SSL
- ✅ `POST /notifications/test-email`

### SMS (Twilio)
- ✅ `POST /notifications/sms` — uses httpx direct to Twilio REST API
- ✅ `POST /notifications/test-sms`

---

## P2 — Notification Triggers ✅ DONE (CRUD)

- ✅ `POST /triggers/` — create trigger rule for current user
- ✅ `GET /triggers/` — list current user's triggers
- ✅ `DELETE /triggers/{id}` — delete a trigger
- 🔴 Trigger evaluation: after each `/sync/` run, evaluate all triggers against new CVEs and fire the appropriate notification channel(s)
- Acceptance: a trigger with `min_severity=critical` fires a Teams message when a Critical CVE is ingested

---

## P3 — Persistent Feed & Scraper Config ✅ DONE

- ✅ `/sync/` now saves `feeds_config` + `scrapers_config` to `UserConfig` after each run
- ✅ `GET /users/me/config` returns both arrays
- 🟡 Frontend: load feeds from API on mount instead of localStorage (currently falls back to localStorage)

---

## P4 — Dashboard.tsx Refactor (Frontend)

`Dashboard.tsx` is 3338 lines. Extract into focused units.

- 🔴 `frontend/src/hooks/useCveData.ts` — CVE state, filtering logic, `mapApiCve()`, `inferVendorProduct()`
- 🔴 `frontend/src/hooks/useSyncState.ts` — sync status, countdown timers, operator logs
- 🔴 `frontend/src/hooks/useAlertRules.ts` — alert rules state, notification config
- 🔴 `frontend/src/lib/cveUtils.ts` — move `mapApiCve()` + `inferVendorProduct()` here
- 🔴 `frontend/src/components/AlertsPanel.tsx` — extract alerts tab from Dashboard
- 🔴 Remove duplicate `inferVendorProduct()` from frontend — backend `_infer_vendor_product()` is canonical
- Acceptance: Dashboard.tsx < 500 lines; behaviour identical; TypeScript strict passes

---

## P5 — Auth on Sensitive Endpoints

- ✅ `POST /sync/` — auth required
- ✅ `DELETE /cves/clear-checkpoint` — auth required
- ✅ All `POST /notifications/*` — auth required
- 🔴 Update frontend to pass JWT token with sync and notification requests
- Acceptance: unauthenticated `POST /sync/` returns HTTP 401 ✅

---

## P6 — Test Coverage

- 🔴 Test `/sync/` with `httpx.MockTransport` (mock NVD + RSS responses)
- 🔴 Test `CveReviewer.review_cve()` — invalid CVE ID format, CVSS out of range, missing title
- 🔴 Test each notification endpoint (mock HTTP to external services)
- 🔴 Test trigger CRUD endpoints
- 🔴 Fix CI pipeline: add `pytest tests/ -v` to `.github/workflows/ci.yml`
- Acceptance: `pytest` runs clean; CI passes

---

## P7 — Frontend Pagination

API supports `skip` + `limit`. Frontend fetches only 40 CVEs with no load-more.

- 🔴 Add "Load more" button or infinite scroll to `CveTable`
- 🔴 Track current page in `useCveData` hook
- Acceptance: browsing past 40 CVEs is possible without refreshing

---

## P8 — Apply 3-Tier Agent Architecture

Refactor existing monolithic code into the company agent structure (see `CLAUDE.md`).

- 🔴 Extract `SyncManager` from `/sync/` route in `main.py`
- 🔴 Wrap `rss_parser.fetch_and_parse_rss()` as `RssParserAgent`
- 🔴 Wrap `rss_parser.fetch_nvd_api()` as `NvdAgent`
- 🔴 Wrap `rss_parser.scrape_webpage_regex()` as `ScraperAgent`
- 🔴 Create `CveReviewer` — validates CVE ID format, CVSS range, date validity before DB write
- 🔴 Create `NotifReviewer` — validates webhook URLs, credentials present before send
- 🔴 Create `AlertManager` — orchestrates trigger evaluation + notification dispatch
- Do this incrementally; wrap existing functions, don't rewrite them

---

## Done ✅

- JWT auth (register, login, token)
- CVE ingestion from NVD API 2.0 (real CVSS/severity/vendor from CPE)
- RSS/Atom feed sync for 13+ vendor feeds
- Web regex scraper
- Teams webhook notification + test endpoint
- Health endpoint (uptime, CPU, memory, disk, DB status)
- Frontend CVE table (resizable columns, sorting, copy CVE ID)
- Frontend filters (severity, keyword, feed source)
- Frontend dark mode + cyberpunk theme
- Export CSV/JSON
- Docker Compose full-stack deployment
- SQLite local dev mode (auto-detected from DATABASE_URL)
- Basic pytest suite (auth + CVE list)
