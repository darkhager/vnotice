# Team Alpha — Core Engine

**Scope:** FastAPI routes, sync pipeline, notification delivery, all agent files, tests

## Files Owned
`backend/main.py` · `backend/rss_parser.py` · `backend/auth.py` · `backend/schemas.py` · `backend/tests/` · `backend/agents/` (all files)

## Current Sprint Focus (P1–P2)
1. Implement Discord, Telegram, Email, SMS notification endpoints (`notif_agent.md`)
2. Implement Trigger CRUD endpoints + evaluation logic (`alert_manager.md`)
3. Add auth guard (`Depends(get_current_user)`) to `/sync/` and notification routes
4. Incrementally wrap `rss_parser.py` functions as agent classes

## Standards
- All new routes must be gated through a Manager (SyncManager or AlertManager).
- All new CVE writes must pass CveReviewer.
- All new notification sends must pass NotifReviewer.
- `manager_agent.py`, `cve_reviewer.py`, `notif_reviewer.py` changes need Engineering Lead review.
- Tests required for every new endpoint before merge.
