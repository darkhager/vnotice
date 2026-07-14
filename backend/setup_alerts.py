"""Self-service setup for one account's email alert.

Same principle as setup_teams_alert.py: SMTP credentials are personal (your
own mailbox / app password), so they are never shared across accounts. This
script only ever touches ONE recipient per run, and that recipient is the one
who should be typing their own host/username/app-password. Defaults to the
primary account when run with no argument; anyone else who wants email
alerts runs this themselves, passing their own email:

    cd ~/vnotice/backend && ./venv_server/bin/python setup_alerts.py
    cd ~/vnotice/backend && ./venv_server/bin/python setup_alerts.py phattharaphon_h@mfec.co.th

The app password is typed at a getpass prompt so it never appears in argv,
the environment, or shell history. Re-running for the same email is safe —
it updates the SMTP config and adds any missing triggers, without touching
other accounts.
"""
import getpass
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import SessionLocal
import models
import auth

# Feed sources each known recipient wants alerts for — mirrors their saved UI
# alert rule. Not a secret; only the credentials typed at the prompts below are.
FEED_SOURCES = {
    "chaiyaphat@mfec.co.th": [
        "Palo Alto Networks",
        "Splunk Security Advisories",
        "Fortinet PSIRT",
        "Check Point Advisories",
    ],
    "phattharaphon_h@mfec.co.th": [
        "Check Point Advisories",
        "Fortinet PSIRT",
        "Palo Alto Networks",
    ],
}
DEFAULT_RECIPIENT = "chaiyaphat@mfec.co.th"


def _get_or_create_user(db, email):
    u = db.query(models.User).filter(models.User.email == email).first()
    if not u:
        u = models.User(
            id=uuid.uuid4(), email=email, username=email.split("@")[0],
            password_hash=auth.get_password_hash(uuid.uuid4().hex), role="user",
        )
        db.add(u)
        db.flush()
        print(f"created user {email}")
    return u


def main():
    to_address = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_RECIPIENT
    sources = FEED_SOURCES.get(to_address)
    if sources is None:
        sys.exit(f"unknown recipient {to_address}; add it to FEED_SOURCES first")

    smtp_host = input("SMTP host [smtp.gmail.com]: ").strip() or "smtp.gmail.com"
    smtp_port = input("SMTP port [587]: ").strip() or "587"
    smtp_username = input(f"SMTP username (sending account) [{to_address}]: ").strip() or to_address
    smtp_password = getpass.getpass(f"App password for {smtp_username}: ").strip()
    if not smtp_password:
        sys.exit("aborted: no password entered")

    db = SessionLocal()
    try:
        user = _get_or_create_user(db, to_address)

        cfg = db.query(models.UserConfig).filter(
            models.UserConfig.user_id == user.id).first()
        if not cfg:
            cfg = models.UserConfig(user_id=user.id)
            db.add(cfg)
        cfg.notify_email = True
        cfg.smtp_host = smtp_host
        cfg.smtp_port = int(smtp_port)
        cfg.smtp_username = smtp_username
        cfg.smtp_password = smtp_password   # EncryptedText -> Fernet at rest
        cfg.smtp_to_address = to_address
        print(f"smtp config -> {smtp_host}:{smtp_port} as {smtp_username}, delivering to {to_address}")

        existing = {
            t.feed_source for t in db.query(models.NotificationTrigger).filter(
                models.NotificationTrigger.user_id == user.id).all()
        }
        for src in sources:
            if src in existing:
                continue
            db.add(models.NotificationTrigger(
                id=uuid.uuid4(), user_id=user.id, feed_source=src,
                # severity=all; satisfies the legacy chk_trigger_condition CHECK,
                # which predates feed_source and needs one of its own columns set.
                min_cvss_score=0,
            ))
            print(f"trigger added: {src}")

        db.commit()
        print(f"\ndone. {to_address} will now get email alerts on new CVEs.")
        if to_address == DEFAULT_RECIPIENT:
            others = [e for e in FEED_SOURCES if e != DEFAULT_RECIPIENT]
            if others:
                print("Someone else wants email alerts? They run this script themselves "
                      "with their own email and their own SMTP credentials, e.g.:")
                print(f"  ./venv_server/bin/python setup_alerts.py {others[0]}")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
