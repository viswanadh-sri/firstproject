import smtplib

from fastapi import APIRouter, HTTPException, status

from app.models.otp import OTPRequest, OTPVerifyRequest
from app.services.otp import create_and_send_otp, verify_otp

router = APIRouter(prefix="/otp", tags=["OTP"])


@router.post("/request", status_code=status.HTTP_202_ACCEPTED)
async def request_otp(payload: OTPRequest):
    try:
        await create_and_send_otp(str(payload.email))
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OTP email service is not configured",
        ) from exc
    except (OSError, smtplib.SMTPException) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to send OTP email",
        ) from exc
    return {"message": "OTP sent if the email address is eligible"}


@router.post("/verify")
async def verify_submitted_otp(payload: OTPVerifyRequest):
    if await verify_otp(str(payload.email), payload.otp):
        return {"message": "OTP verified successfully"}
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired OTP",
    )
