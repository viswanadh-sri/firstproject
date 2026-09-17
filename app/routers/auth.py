import logging
import smtplib
from datetime import UTC, datetime

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_password_reset_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.db.mongodb import get_database
from app.services.otp import consume_otp, create_and_send_otp
from app.models.users import (
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    UserCreate,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["authentication"])
bearer = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)


def set_auth_cookies(
    request: Request,
    response: Response,
    access_token: str,
    csrf_token: str,
) -> None:
    request_origin = request.headers.get("origin", "").strip()
    cross_origin_https = (
        request_origin.startswith("https://")
        and request_origin in settings.cors_origins
    )
    secure = settings.cookie_secure or settings.environment == "production" or cross_origin_https
    common = {
        "secure": secure,
        "domain": settings.cookie_domain,
        "path": "/",
        "samesite": "none" if secure else settings.cookie_samesite,
    }
    response.set_cookie("access_token", access_token, httponly=True, max_age=1800, **common)
    response.set_cookie("csrf_token", csrf_token, httponly=False, max_age=1800, **common)


def require_csrf(request: Request) -> None:
    cookie_token = request.cookies.get("csrf_token")
    header_token = request.headers.get("X-CSRF-Token")
    if not cookie_token or not header_token or cookie_token != header_token:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")


async def current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    token = credentials.credentials if credentials else request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        user_id = decode_access_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    user = await get_database().users.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserCreate):
    database = get_database()
    if await database.users.find_one({"email": str(payload.email).lower()}):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered")
    document = {
        "email": str(payload.email).lower(),
        "display_name": payload.display_name,
        "password_hash": hash_password(payload.password),
        "created_at": datetime.now(UTC),
    }
    result = await database.users.insert_one(document)
    return UserResponse(id=str(result.inserted_id), email=document["email"], display_name=document["display_name"])


@router.post("/login")
async def login(request: Request, payload: LoginRequest, response: Response):
    user = await get_database().users.find_one({"email": str(payload.email).lower()})
    if user is None or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    csrf_token = create_password_reset_token()
    set_auth_cookies(request, response, create_access_token(str(user["_id"])), csrf_token)
    return {"message": "Login successful"}


@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest):
    email = str(payload.email).lower()
    user = await get_database().users.find_one({"email": email})
    if user is not None:
        try:
            await create_and_send_otp(
                email,
                user_id=user["_id"],
                expires_in_minutes=settings.password_reset_expire_minutes,
                subject="Password reset verification code",
                body_template=(
                    "Your password reset code is {otp}. "
                    f"It expires in {settings.password_reset_expire_minutes} minutes. "
                    "Do not share this code with anyone."
                ),
            )
        except (OSError, RuntimeError, smtplib.SMTPException):
            logger.exception("Password reset email delivery failed for %s", email)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Unable to send password reset email",
            ) from None
    return {"message": "If that email exists, password reset instructions have been sent"}


@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest):
    database = get_database()
    reset = await consume_otp(str(payload.email), payload.token)
    if reset is None or reset.get("user_id") is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")
    await database.users.update_one(
        {"_id": reset["user_id"]},
        {"$set": {"password_hash": hash_password(payload.new_password)}},
    )
    return {"message": "Password reset successful"}


@router.post("/logout")
async def logout(request: Request, response: Response):
    #require_csrf(request)
    response.delete_cookie("access_token", path="/", domain=settings.cookie_domain)
    response.delete_cookie("csrf_token", path="/", domain=settings.cookie_domain)
    return {"message": "Logged out"}


@router.get("/me", response_model=UserResponse)
async def me(user=Depends(current_user)):
    return UserResponse(id=str(user["_id"]), email=user["email"], display_name=user["display_name"])
