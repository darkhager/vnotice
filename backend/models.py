import uuid
from sqlalchemy import Column, String, Text, Numeric, DateTime, ForeignKey, text, CheckConstraint, Float, Boolean, Integer, JSON, UniqueConstraint
from sqlalchemy.types import CHAR, TypeDecorator
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship
from database import Base
import crypto


class EncryptedText(TypeDecorator):
    """Transparently encrypts a secret on write and decrypts it on read.

    Stored as TEXT (ciphertext), so no schema/migration change is needed when an
    existing plaintext column is switched to this type — legacy values pass
    through crypto.decrypt() unchanged and get encrypted on their next save.
    """
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return crypto.encrypt(value)

    def process_result_value(self, value, dialect):
        return crypto.decrypt(value)


class GUID(TypeDecorator):
    """Platform-independent UUID column.
    PostgreSQL stores native UUID; SQLite stores 36-char string.
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
        return str(value if isinstance(value, uuid.UUID) else uuid.UUID(str(value)))

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


class User(Base):
    __tablename__ = "users"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False)
    username = Column(String(100), nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user")       # user | admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=text('CURRENT_TIMESTAMP'))
    updated_at = Column(DateTime(timezone=True), server_default=text('CURRENT_TIMESTAMP'))

    triggers = relationship("NotificationTrigger", back_populates="user", cascade="all, delete-orphan")
    config = relationship("UserConfig", back_populates="user", uselist=False, cascade="all, delete-orphan")


class CVE(Base):
    __tablename__ = "cves"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(50), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    severity = Column(String(20))
    cvss_score = Column(Numeric(3, 1))
    epss = Column(Float)
    published_date = Column(DateTime(timezone=True))
    updated_date = Column(DateTime(timezone=True))
    vendor = Column(String(100))
    product = Column(String(100))
    reference_url = Column(Text)
    rss_source = Column(String(100))
    keywords = Column(JSON, default=list)   # extracted keywords/product terms for this CVE
    created_at = Column(DateTime(timezone=True), server_default=text('CURRENT_TIMESTAMP'))
    # LEGACY: superseded by the cve_insights table (copied over at startup, no
    # longer written). Left in place because SQLite can't drop columns cheaply.
    affected_versions = Column(Text)
    affected_conditions = Column(Text)
    mitigation = Column(Text)
    remediation = Column(Text)
    fixed_versions = Column(Text)
    iocs = Column(Text)
    details_verification = Column(Text)   # JSON: the AI verifier's per-field verdict; cleared on re-fetch
    details_fetched_at = Column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint('cve_id', 'rss_source', name='uq_cve_source'),
    )


class CveInsight(Base):
    """Extracted details + AI summary/verification, ONE row per CVE number.

    Linked to `cves` by cve_id (not a FK: cves has one row per (cve_id, source),
    and the CVE.org record these come from is per CVE number). Filled by
    threat_summary.py for CVEs inside the admin's Threat Summary scope, and on
    demand when someone opens a CVE's details.
    """
    __tablename__ = "cve_insights"

    cve_id = Column(String(50), primary_key=True)
    affected_versions = Column(Text)
    affected_conditions = Column(Text)
    mitigation = Column(Text)
    remediation = Column(Text)
    fixed_versions = Column(Text)
    iocs = Column(Text)
    extracted_at = Column(DateTime(timezone=True))      # when the details were extracted from CVE.org
    ai_summary = Column(Text)                           # plain-language summary written by the AI
    ai_verification = Column(Text)                      # JSON: per-field verdict on the extraction
    ai_model = Column(String(100))
    ai_checked_at = Column(DateTime(timezone=True))     # when the AI last summarised + checked it
    ai_error = Column(Text)                             # last AI failure, cleared on success


class UserConfig(Base):
    """Stores per-user UI preferences, notification settings, and feed configs."""
    __tablename__ = "user_configs"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False)

    # UI Preferences
    theme = Column(String(20), default="dark")          # dark | light
    polling_interval = Column(Integer, default=300)     # seconds between syncs
    default_severity_filter = Column(String(20), default="all")

    # Notification Channels (on/off)
    notify_email = Column(Boolean, default=False)
    notify_discord = Column(Boolean, default=False)
    notify_telegram = Column(Boolean, default=False)
    notify_slack = Column(Boolean, default=False)
    notify_teams = Column(Boolean, default=False)
    notify_line = Column(Boolean, default=False)

    # Notification Channel Targets
    # Secret-bearing columns are encrypted at rest via EncryptedText.
    discord_webhook = Column(EncryptedText, nullable=True)
    telegram_bot_token = Column(EncryptedText, nullable=True)
    telegram_chat_id = Column(String(100), nullable=True)
    slack_webhook = Column(EncryptedText, nullable=True)
    teams_webhook = Column(EncryptedText, nullable=True)
    # LINE Messaging API broadcast — one Channel Access Token per Official Account.
    line_channel_token = Column(EncryptedText, nullable=True)
    smtp_host = Column(String(255), nullable=True)
    smtp_port = Column(Integer, default=587)
    smtp_username = Column(String(255), nullable=True)
    smtp_password = Column(EncryptedText, nullable=True)
    smtp_to_address = Column(String(255), nullable=True)
    sms_twilio_sid = Column(String(100), nullable=True)
    sms_twilio_token = Column(EncryptedText, nullable=True)
    sms_from_number = Column(String(20), nullable=True)
    sms_to_number = Column(String(20), nullable=True)

    notify_sms = Column(Boolean, default=False)

    # Feed & Scraper configs (JSON arrays)
    feeds_config = Column(JSON, default=list)       # [{name, url, active}]
    scrapers_config = Column(JSON, default=list)    # [{id, name, url, regex, active}]

    # Alert Keywords
    alert_keywords = Column(JSON, default=list)     # ["log4j", "apache", ...]

    created_at = Column(DateTime(timezone=True), server_default=text('CURRENT_TIMESTAMP'))
    updated_at = Column(DateTime(timezone=True), server_default=text('CURRENT_TIMESTAMP'))

    user = relationship("User", back_populates="config")


class AppState(Base):
    """Server-side key/value store mirroring the frontend's profile + settings
    bundle (the `vnotice_*` localStorage keys). Keeps profiles/settings in the
    database so they survive a browser cache-clear and are captured by DB backups.
    """
    __tablename__ = "app_state"

    key = Column(String(100), primary_key=True)
    value = Column(JSON)
    updated_at = Column(DateTime(timezone=True), server_default=text('CURRENT_TIMESTAMP'))


class NotificationTrigger(Base):
    __tablename__ = "notification_triggers"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    keyword = Column(String(100))
    vendor = Column(String(100))
    product = Column(String(100))
    min_severity = Column(String(20))
    min_cvss_score = Column(Numeric(3, 1))
    # Exact cves.rss_source match; NULL = any source. Mirrors the UI's
    # "feed sources" alert criterion, which none of the columns above can express.
    feed_source = Column(String(120))
    created_at = Column(DateTime(timezone=True), server_default=text('CURRENT_TIMESTAMP'))

    user = relationship("User", back_populates="triggers")

    __table_args__ = (
        CheckConstraint(
            'keyword IS NOT NULL OR vendor IS NOT NULL OR product IS NOT NULL OR min_severity IS NOT NULL OR min_cvss_score IS NOT NULL',
            name='chk_trigger_condition'
        ),
    )


class SentAlert(Base):
    """One row per (CVE, channel, destination) actually delivered. Checked before
    every send, so overlapping syncs, a CVE arriving from two feeds, or a user
    whose several triggers all match it never produce a second alert. dest_hash
    is a sha256 of the email address / webhook URL -- webhook URLs are secrets,
    so they aren't stored here in the clear."""
    __tablename__ = "sent_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), nullable=False, index=True)
    channel = Column(String(20), nullable=False)
    dest_hash = Column(String(64), nullable=False)
    sent_at = Column(DateTime(timezone=True), server_default=text('CURRENT_TIMESTAMP'))

    __table_args__ = (
        UniqueConstraint('cve_id', 'channel', 'dest_hash', name='uq_sent_alert'),
    )
