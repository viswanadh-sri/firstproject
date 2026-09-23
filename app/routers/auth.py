import logging
import re
import smtplib
from datetime import UTC, datetime
from secrets import compare_digest, token_urlsafe

from bson import ObjectId
from flask import Blueprint, jsonify, request
from werkzeug.exceptions import BadRequest, Conflict, Forbidden, Unauthorized

from app.core.config import settings
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.db.mongodb import get_database
from app.services.otp import consume_otp, create_and_send_otp

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")
logger = logging.getLogger(__name__)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9 _.-]+$")
AUTH_COOKIE = "access_token"
CSRF_COOKIE = "csrf_token"
COOKIE_MAX_AGE = settings.access_token_expire_minutes * 60


def _json_payload(required: tuple[str, ...]) -> dict:
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise BadRequest("A JSON object is required")
    missing = [field for field in required if field not in payload]
    if missing:
        raise BadRequest(f"Missing required fields: {', '.join(missing)}")
    return payload


def _email(value) -> str:
    value = value.strip() if isinstance(value, str) else ""
    if not EMAIL_RE.fullmatch(value):
        raise BadRequest("Invalid email address")
    return value.lower()


def _password(value, *, minimum: int = 1) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= 128:
        raise BadRequest(f"Password must be between {minimum} and 128 characters")
    if any(ord(character) < 32 for character in value):
        raise BadRequest("Password contains invalid control characters")
    return value


def _user_response(user_id, email: str, display_name: str) -> dict:
    return {"id": str(user_id), "email": email, "display_name": display_name}


def _cookie_options() -> dict:
    return {
        "max_age": COOKIE_MAX_AGE,
        "httponly": True,
        "secure": settings.cookie_secure or settings.environment == "production",
        "samesite": settings.cookie_samesite,
        "domain": settings.cookie_domain,
        "path": "/",
    }


def _set_auth_cookies(response, access_token: str):
    response.set_cookie(AUTH_COOKIE, access_token, **_cookie_options())
    response.set_cookie(
        CSRF_COOKIE,
        token_urlsafe(32),
        **{**_cookie_options(), "httponly": False},
    )
    return response


def _require_csrf() -> None:
    cookie_token = request.cookies.get(CSRF_COOKIE, "")
    header_token = request.headers.get("X-CSRF-Token", "")
    if not cookie_token or not header_token or not compare_digest(cookie_token, header_token):
        raise Forbidden("CSRF validation failed")


def current_user():
    token = request.cookies.get(AUTH_COOKIE)
    if not token:
        raise Unauthorized("Authentication required")
    try:
        user_id = decode_access_token(token)
    except ValueError as exc:
        raise Unauthorized(str(exc)) from exc
    try:
        user = get_database().users.find_one({"_id": ObjectId(str(user_id))})
    except Exception as exc:
        raise Unauthorized("Authentication required") from exc
    if user is None:
        raise Unauthorized("User not found")
    return user


@auth_bp.post("/register")
def register():
    payload = _json_payload(("email", "password", "display_name"))
    email = _email(payload["email"])
    password = _password(payload["password"], minimum=12)
    display_name = payload["display_name"]
    if not isinstance(display_name, str):
        raise BadRequest("Display name is required")
    display_name = display_name.strip()
    if not 1 <= len(display_name) <= 80 or not SAFE_NAME_RE.fullmatch(display_name):
        raise BadRequest("Display name contains unsupported characters")
    database = get_database()
    if database.users.find_one({"email": email}):
        raise Conflict("Email is already registered")
    document = {"email": email, "display_name": display_name, "password_hash": hash_password(password), "created_at": datetime.now(UTC)}
    result = database.users.insert_one(document)
    return jsonify(_user_response(result.inserted_id, email, display_name)), 201


@auth_bp.post("/login")
def login():
    payload = _json_payload(("email", "password"))
    email = _email(payload["email"])
    password = _password(payload["password"])
    user = get_database().users.find_one({"email": email})
    if user is None or not verify_password(password, user["password_hash"]):
        raise Unauthorized("Invalid email or password")
    access_token = create_access_token(str(user["_id"]))
    return _set_auth_cookies(jsonify(message="Login successful"), access_token)


@auth_bp.post("/forgot-password")
def forgot_password():
    email = _email(_json_payload(("email",))["email"])
    user = get_database().users.find_one({"email": email})
    if user is not None:
        try:
            create_and_send_otp(email, user_id=user["_id"], expires_in_minutes=settings.password_reset_expire_minutes,
                                subject="Password reset verification code",
                                body_template="Your password reset code is {otp}. It expires in {expires_in_minutes} minutes. Do not share this code with anyone.")
        except (OSError, RuntimeError, smtplib.SMTPException):
            logger.exception("Password reset email delivery failed for %s", email)
            raise BadRequest("Unable to send password reset email") from None
    return jsonify(message="If that email exists, password reset instructions have been sent")


@auth_bp.post("/reset-password")
def reset_password():
    payload = _json_payload(("email", "token", "new_password"))
    email = _email(payload["email"])
    token = payload["token"]
    if not isinstance(token, str) or len(token) != 6 or not token.isdecimal():
        raise BadRequest("Reset token must be a six-digit OTP")
    new_password = _password(payload["new_password"], minimum=12)
    reset = consume_otp(email, token)
    if reset is None or reset.get("user_id") is None:
        raise BadRequest("Invalid or expired reset token")
    get_database().users.update_one({"_id": reset["user_id"]}, {"$set": {"password_hash": hash_password(new_password)}})
    return jsonify(message="Password reset successful")


@auth_bp.post("/logout")
def logout():
    _require_csrf()
    response = jsonify(message="Logged out")
    delete_options = {
        "path": "/",
        "domain": settings.cookie_domain,
        "secure": settings.cookie_secure or settings.environment == "production",
        "samesite": settings.cookie_samesite,
    }
    response.delete_cookie(AUTH_COOKIE, **delete_options)
    response.delete_cookie(CSRF_COOKIE, **delete_options)
    return response


@auth_bp.get("/me")
def me():
    user = current_user()
    return jsonify(_user_response(user["_id"], user["email"], user["display_name"]))
