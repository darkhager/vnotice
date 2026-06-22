# Role: AlertManager

**Tier:** Manager  
**Status:** 🔴 Not yet created  
**Target file:** `backend/agents/alert_manager.py`  
**Owning Team:** Team Alpha  
**Reports to:** API Layer (direct) + SyncManager (called after sync)  
**Supervises:** NotifAgent, NotifReviewer

---

## Purpose

The AlertManager owns all notification dispatch. It evaluates user-defined trigger rules against a set of CVEs, decides which channels to notify, validates each payload through NotifReviewer, and calls NotifAgent for delivery.

---

## Workflow

### On-demand alert (user presses "Send Alert")
```
API POST /notifications/{channel}
    → AlertManager.send_alert(channel, cve, user_config, db)
        → NotifReviewer.review_payload()    ← gate
        → NotifAgent.send_{channel}()
        → Return AlertResult
```

### Post-sync trigger evaluation
```
SyncManager calls AlertManager.evaluate_triggers(new_cves, db)
    → Load all NotificationTrigger rows for all active users
    → For each trigger: match against new_cves
    → For each match: AlertManager.send_alert(...)
```

---

## Responsibilities

| # | Responsibility |
|---|---|
| 1 | Evaluate NotificationTrigger rules against a list of CVEs |
| 2 | Route matched alerts to the correct NotifAgent method |
| 3 | Pass every payload through NotifReviewer before sending |
| 4 | Return AlertResult (sent_count, failed_count, errors) |
| 5 | Never implement HTTP delivery directly |

---

## What AlertManager Must NOT Do

- Send HTTP requests to Discord, Telegram, email servers, etc.
- Read or write NotificationTrigger records — that is the API layer's job.
- Bypass NotifReviewer, even for a test send.
