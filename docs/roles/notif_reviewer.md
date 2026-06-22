# Role: NotifReviewer

**Tier:** Reviewer  
**Status:** 🔴 Not yet created  
**Target file:** `backend/agents/notif_reviewer.py`  
**Owning Team:** Team Alpha (Engineering Lead approval to change)  
**Reports to:** AlertManager (only caller)

---

## Purpose

The NotifReviewer validates a notification payload before it is delivered. It checks that required credentials/URLs are present and well-formed, that the CVE data being sent is not empty, and that the channel identifier is supported.

---

## Method: `review_payload(channel, cve_data, config) → ReviewResult`

| Check | Severity | Condition |
|---|---|---|
| Unknown channel | Error | `channel` not in `{teams, discord, telegram, email, sms}` |
| Missing webhook URL | Error | `channel in (teams, discord)` and URL is empty |
| Invalid webhook URL | Error | URL does not start with `https://` |
| Missing bot token | Error | `channel == telegram` and `telegram_bot_token` empty |
| Missing chat ID | Error | `channel == telegram` and `telegram_chat_id` empty |
| Missing SMTP credentials | Error | `channel == email` and any of host/port/username/password empty |
| Missing Twilio credentials | Error | `channel == sms` and any of sid/token/phone empty |
| Empty CVE ID in payload | Error | `cve_data.get("cve_id")` is empty |
| No severity in payload | Warning | `cve_data.get("severity")` is empty |

---

## What NotifReviewer Must NOT Do

- Make any HTTP call to test connectivity — that is the test-endpoint's job.
- Modify the payload or config.
- Cache results between calls.
