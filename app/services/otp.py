import hashlib
import hmac
import logging
import smtplib
import secrets
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any

from app.core.config import settings
from app.db.mongodb import get_database

logger = logging.getLogger(__name__)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def generate_otp() -> str:
    return f"{secrets.randbelow(900_000) + 100_000:06d}"


def hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def verify_otp_hash(otp: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(otp), expected_hash)


def _send_email(recipient: str, otp: str, *, subject: str, body: str, expires_in_minutes: int) -> None:
    if not settings.smtp_host or not settings.smtp_from:
        raise RuntimeError("SMTP email settings are not configured")
    message = EmailMessage()
    message["Subject"], message["From"], message["To"] = subject, settings.smtp_from, recipient
    message.set_content(body.format(otp=otp, expires_in_minutes=expires_in_minutes))
    password = settings.smtp_password.get_secret_value() if settings.smtp_password else None
    smtp_class = smtplib.SMTP_SSL if settings.smtp_use_ssl else smtplib.SMTP
    with smtp_class(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
        if not settings.smtp_use_ssl and settings.smtp_use_tls:
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, password or "")
        refused = smtp.send_message(message)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)


def create_and_send_otp(email: str, *, user_id: Any | None = None, expires_in_minutes: int = 5,
                        subject: str = "Your verification code",
                        body_template: str = "Your verification code is {otp}. It expires in {expires_in_minutes} minutes. Do not share this code.") -> None:
    email = email.lower()
    otp = generate_otp()
    now = datetime.now(UTC)
    record = {"email": email, "otp_hash": hash_otp(otp), "user_id": user_id,
              "expires_at": now + timedelta(minutes=expires_in_minutes), "created_at": now}
    database = get_database()
    database.otp_records.replace_one({"email": email}, record, upsert=True)
    try:
        _send_email(email, otp, subject=subject, body=body_template, expires_in_minutes=expires_in_minutes)
    except (OSError, smtplib.SMTPException, RuntimeError):
        database.otp_records.delete_one({"email": email, "otp_hash": hash_otp(otp)})
        raise


def consume_otp(email: str, otp: str) -> dict[str, Any] | None:
    if not isinstance(otp, str) or len(otp) != 6 or not otp.isdecimal():
        return None
    record = get_database().otp_records.find_one({"email": email.lower()})
    if record is None or _as_utc(record["expires_at"]) <= datetime.now(UTC) or not verify_otp_hash(otp, record["otp_hash"]):
        return None
    get_database().otp_records.delete_one({"_id": record["_id"]})
    return record


def verify_otp(email: str, otp: str) -> bool:
    return consume_otp(email, otp) is not None
