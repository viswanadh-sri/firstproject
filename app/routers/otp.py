import smtplib

from flask import Blueprint, jsonify
from werkzeug.exceptions import BadRequest, ServiceUnavailable

from app.services.otp import create_and_send_otp, verify_otp
from app.routers.auth import _email, _json_payload

otp_bp = Blueprint("otp", __name__, url_prefix="/otp")


@otp_bp.post("/request")
def request_otp():
    email = _email(_json_payload(("email",))["email"])
    try:
        create_and_send_otp(email)
    except RuntimeError as exc:
        raise ServiceUnavailable("OTP email service is not configured") from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise BadRequest("Unable to send OTP email") from exc
    return jsonify(message="OTP sent if the email address is eligible"), 202


@otp_bp.post("/verify")
def verify_submitted_otp():
    payload = _json_payload(("email", "otp"))
    email = _email(payload["email"])
    if verify_otp(email, payload["otp"]):
        return jsonify(message="OTP verified successfully")
    raise BadRequest("Invalid or expired OTP")
