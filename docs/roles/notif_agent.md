# Role: NotifAgent

**Tier:** Worker  
**Status:** 🟡 Teams implemented in `main.py`; Discord/Telegram/Email/SMS not implemented  
**Target file:** `backend/agents/notif_agent.py`  
**Owning Team:** Team Alpha  
**Reports to:** AlertManager

---

## Purpose

Delivers notifications to external channels. Each method handles one channel. The AlertManager calls the appropriate method after NotifReviewer has validated the payload.

---

## Methods

### `send_teams(webhook_url: str, cve: dict) → bool`
Already implemented in `main.py` as `POST /notifications/teams` logic. Extract here.  
Payload: Adaptive Card JSON with CVE ID, severity badge, CVSS, description, reference link.

### `send_discord(webhook_url: str, cve: dict) → bool` 🔴
Discord Webhook API. POST JSON with `embeds` array.  
Embed fields: CVE ID (title), severity (color-coded), CVSS score, description, URL.  
Color map: Critical=15158332 (red), High=16744272 (orange), Medium=16776960 (yellow), Low=3394611 (blue).

### `send_telegram(bot_token: str, chat_id: str, cve: dict) → bool` 🔴
Telegram Bot API: `POST https://api.telegram.org/bot{token}/sendMessage`.  
`parse_mode=HTML`. Format as: `<b>CVE ID</b>\nSeverity: ...\nCVSS: ...\n<a href="...">Details</a>`.

### `send_email(host, port, username, password, to_address: str, cve: dict) → bool` 🔴
SMTP via stdlib `smtplib` or `aiosmtplib`.  
Subject: `[Vnotice Alert] {cve_id} — {severity}`.  
Body: plain text summary + reference URL.  
Use `STARTTLS` if port 587; SSL if port 465.

### `send_sms(twilio_sid, twilio_token, from_number, to_number: str, cve: dict) → bool` 🔴
Twilio Messages API: `POST https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json`.  
Body: `"[Vnotice] {cve_id} ({severity}, CVSS {score}) — {short_url}"` — keep under 160 chars.

---

## Return Value

All methods return `True` on success, `False` on delivery failure (log the error but do not raise — AlertManager handles retry/fallback logic).

---

## What NotifAgent Must NOT Do

- Validate credentials or payload — that is NotifReviewer's job.
- Write to the database.
- Call other agents.
- Raise exceptions for delivery failures — return `False` and log.
