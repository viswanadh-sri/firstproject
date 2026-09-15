from datetime import UTC, datetime, timedelta

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
from app.models.users import (
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    UserCreate,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["authentication"])
bearer = HTTPBearer(auto_error=False)


def set_auth_cookies(response: Response, access_token: str, csrf_token: str) -> None:
    common = {
        "secure": settings.cookie_secure,
        "domain": settings.cookie_domain,
        "path": "/",
        "samesite": "lax",
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
async def login(payload: LoginRequest, response: Response):
    user = await get_database().users.find_one({"email": str(payload.email).lower()})
    if user is None or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    csrf_token = create_password_reset_token()
    set_auth_cookies(response, create_access_token(str(user["_id"])), csrf_token)
    return {"message": "Login successful"}


@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest):
    user = await get_database().users.find_one({"email": str(payload.email).lower()})
    if user is not None:
        token = create_password_reset_token()
        await get_database().password_reset_tokens.insert_one(
            {
                "user_id": user["_id"],
                "token": token,
                "expires_at": datetime.now(UTC) + timedelta(minutes=settings.password_reset_expire_minutes),
            }
        )
        # Integrate this token with an email provider; never return it in production.
    return {"message": "If that email exists, password reset instructions have been sent"}


@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest):
    database = get_database()
    reset = await database.password_reset_tokens.find_one_and_delete({"token": payload.token})
    if reset is None or reset["expires_at"] <= datetime.now(UTC):
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
