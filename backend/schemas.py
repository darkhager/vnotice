from pydantic import BaseModel, EmailStr
from typing import Optional, List, Any
from datetime import datetime
from uuid import UUID


# ---------- Auth ----------

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    username: Optional[str] = None

class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    username: Optional[str] = None
    role: Optional[str] = "user"
    is_active: Optional[bool] = True
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None


# ---------- CVE ----------

class CVEResponse(BaseModel):
    id: UUID
    cve_id: str
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    epss: Optional[float] = None
    published_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    reference_url: Optional[str] = None
    rss_source: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---------- User Config ----------

class UserConfigUpdate(BaseModel):
    """All fields optional — send only what you want to change."""
    theme: Optional[str] = None
    polling_interval: Optional[int] = None
    default_severity_filter: Optional[str] = None

    notify_email: Optional[bool] = None
    notify_discord: Optional[bool] = None
    notify_telegram: Optional[bool] = None
    notify_slack: Optional[bool] = None
    notify_teams: Optional[bool] = None
    notify_sms: Optional[bool] = None

    discord_webhook: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    slack_webhook: Optional[str] = None
    teams_webhook: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_to_address: Optional[str] = None
    sms_twilio_sid: Optional[str] = None
    sms_twilio_token: Optional[str] = None
    sms_from_number: Optional[str] = None
    sms_to_number: Optional[str] = None

    feeds_config: Optional[List[Any]] = None
    scrapers_config: Optional[List[Any]] = None
    alert_keywords: Optional[List[str]] = None

class UserConfigResponse(BaseModel):
    id: UUID
    user_id: UUID
    theme: str
    polling_interval: int
    default_severity_filter: str

    notify_email: bool
    notify_discord: bool
    notify_telegram: bool
    notify_slack: bool
    notify_teams: bool
    notify_sms: bool = False

    discord_webhook: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    slack_webhook: Optional[str] = None
    teams_webhook: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: Optional[int] = None
    smtp_username: Optional[str] = None
    smtp_to_address: Optional[str] = None
    sms_from_number: Optional[str] = None
    sms_to_number: Optional[str] = None

    feeds_config: Optional[List[Any]] = None
    scrapers_config: Optional[List[Any]] = None
    alert_keywords: Optional[List[str]] = None

    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---------- Sync ----------

class FeedSyncItem(BaseModel):
    name: str
    url: str
    active: bool

class ScraperSyncItem(BaseModel):
    id: str
    name: str
    url: str
    regex: str
    active: bool

class SyncRequest(BaseModel):
    feeds: List[FeedSyncItem]
    scrapers: List[ScraperSyncItem]

class SyncResponse(BaseModel):
    status: str
    feeds_checked: int
    scrapers_checked: int
    new_cves_added: int
    message: str


# ---------- Notifications ----------

class NotifAlertRequest(BaseModel):
    """Shared fields for all alert channels."""
    title: str
    severity: str
    cve_id: str
    description: Optional[str] = None
    reference_url: Optional[str] = None

# Teams
class TeamsAlertRequest(NotifAlertRequest):
    webhook_url: str

class TeamsTestRequest(BaseModel):
    webhook_url: str

# Discord
class DiscordAlertRequest(NotifAlertRequest):
    webhook_url: str

class DiscordTestRequest(BaseModel):
    webhook_url: str

# Telegram
class TelegramAlertRequest(NotifAlertRequest):
    bot_token: str
    chat_id: str

class TelegramTestRequest(BaseModel):
    bot_token: str
    chat_id: str

# Email (SMTP)
class EmailAlertRequest(NotifAlertRequest):
    smtp_host: str
    smtp_port: int = 587
    smtp_username: str
    smtp_password: str
    to_address: str

class EmailTestRequest(BaseModel):
    smtp_host: str
    smtp_port: int = 587
    smtp_username: str
    smtp_password: str
    to_address: str

# SMS (Twilio)
class SmsAlertRequest(NotifAlertRequest):
    twilio_sid: str
    twilio_token: str
    from_number: str
    to_number: str

class SmsTestRequest(BaseModel):
    twilio_sid: str
    twilio_token: str
    from_number: str
    to_number: str


# ---------- Notification Triggers ----------

class TriggerCreate(BaseModel):
    keyword: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    min_severity: Optional[str] = None
    min_cvss_score: Optional[float] = None

class TriggerResponse(BaseModel):
    id: UUID
    user_id: UUID
    keyword: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    min_severity: Optional[str] = None
    min_cvss_score: Optional[float] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True
