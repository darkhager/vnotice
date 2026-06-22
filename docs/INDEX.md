# Vnotice — Documentation Index

## Start Here
- [CLAUDE.md](../CLAUDE.md) — Full project context, org structure, current state, where to start
- [BACKLOG.md](BACKLOG.md) — Prioritised task list with acceptance criteria (P1–P8)

## Shared Company Policy
- [../doc-template-studio/docs/COMPANY_POLICY.md](../../doc-template-studio/docs/COMPANY_POLICY.md) — All rules that apply to both projects

## Agent Role Docs

| Agent | Tier | Status |
|---|---|---|
| [SyncManager](roles/sync_manager.md) | Manager | 🔴 Not yet extracted |
| [AlertManager](roles/alert_manager.md) | Manager | 🔴 Not yet created |
| [CveReviewer](roles/cve_reviewer.md) | Reviewer | 🔴 Not yet created |
| [NotifReviewer](roles/notif_reviewer.md) | Reviewer | 🔴 Not yet created |
| [RssParserAgent](roles/rss_parser_agent.md) | Worker | 🟡 Logic exists in rss_parser.py |
| [NvdAgent](roles/nvd_agent.md) | Worker | 🟡 Logic exists in rss_parser.py |
| [NotifAgent](roles/notif_agent.md) | Worker | 🟡 Teams done; Discord/TG/Email/SMS pending |
| [StorageAgent](roles/storage_agent.md) | Worker | 🔴 Not yet extracted |

## Team Charters

| Team | Charter |
|---|---|
| Alpha — Core Engine | [team_alpha.md](teams/team_alpha.md) |
| Beta — Frontend | [team_beta.md](teams/team_beta.md) |
| Gamma — Data & Storage | [team_gamma.md](teams/team_gamma.md) |
| Delta — DevOps | [team_delta.md](teams/team_delta.md) |
