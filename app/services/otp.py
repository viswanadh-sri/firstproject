import asyncio
import hashlib
import hmac
import logging
import secrets
import smtplib
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any

from app.core.config import settings
from app.db.mongodb import get_database

OTP_EXPIRY_MINUTES = 5
logger = logging.getLogger(__name__)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def generate_otp() -> str:
    return f"{secrets.randbelow(900_000) + 100_000:06d}"


def hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def verify_otp_hash(otp: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(otp), expected_hash)


def _send_email(
    recipient: str,
    otp: str,
    *,
    subject: str,
    body: str,
    expires_in_minutes: int,
) -> None:
    if not settings.smtp_host or not settings.smtp_from:
        raise RuntimeError("SMTP email settings are not configured")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = recipient
    message.set_content(body.format(otp=otp, expires_in_minutes=expires_in_minutes))

    password = settings.smtp_password.get_secret_value() if settings.smtp_password else None
    smtp_class = smtplib.SMTP_SSL if settings.smtp_use_ssl else smtplib.SMTP
    with smtp_class(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
        if not settings.smtp_use_ssl and settings.smtp_use_tls:
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, password or "")
            logger.info("Logged in to SMTP server as %s", settings.smtp_username)
        logger.info(
            "Sending OTP email from %s to %s",
            message["From"],
            message["To"],
        )
        refused_recipients = smtp.send_message(message)
        if refused_recipients:
            logger.error("SMTP refused recipients: %s", refused_recipients)
            raise smtplib.SMTPRecipientsRefused(refused_recipients)
        logger.info("SMTP accepted OTP email for %s", message["To"])


async def create_and_send_otp(
    email: str,
    *,
    user_id: Any | None = None,
    expires_in_minutes: int = OTP_EXPIRY_MINUTES,
    subject: str = "Your verification code",
    body_template: str = (
        "Your verification code is {otp}. "
        "It expires in {expires_in_minutes} minutes. Do not share this code."
    ),
) -> None:
    normalized_email = email.lower()
    otp = generate_otp()
    created_at = datetime.now(UTC)
    expires_at = created_at + timedelta(minutes=expires_in_minutes)
    database = get_database()

    await database.otp_records.replace_one(
        {"email": normalized_email},
        {
            "email": normalized_email,
            "otp_hash": hash_otp(otp),
            "user_id": user_id,
            "expires_at": expires_at,
            "created_at": created_at,
        },
        upsert=True,
    )
    try:
        await asyncio.to_thread(
            _send_email,
            normalized_email,
            otp,
            subject=subject,
            body=body_template,
            expires_in_minutes=expires_in_minutes,
        )
    except (OSError, smtplib.SMTPException, RuntimeError):
        await database.otp_records.delete_one({"email": normalized_email, "otp_hash": hash_otp(otp)})
        raise


async def consume_otp(email: str, otp: str) -> dict[str, Any] | None:
    if len(otp) != 6 or not otp.isdecimal():
        return None

    normalized_email = email.lower()
    database = get_database()
    record: dict[str, Any] | None = await database.otp_records.find_one(
        {"email": normalized_email}
    )
    if record is None or _as_utc(record["expires_at"]) <= datetime.now(UTC):
        return None
    if not verify_otp_hash(otp, record["otp_hash"]):
        return None

    await database.otp_records.delete_one({"_id": record["_id"]})
    return record


async def verify_otp(email: str, otp: str) -> bool:
    return await consume_otp(email, otp) is not None
