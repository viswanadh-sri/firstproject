import re

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

_SAFE_NAME = re.compile(r"^[A-Za-z0-9 _.-]+$")


class UserCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    display_name: str = Field(min_length=1, max_length=80)

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, value: str) -> str:
        if not _SAFE_NAME.fullmatch(value):
            raise ValueError("Display name contains unsupported characters")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("Password contains invalid control characters")
        return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class ForgotPasswordRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    email: EmailStr
    token: str = Field(min_length=6, max_length=6)
    new_password: str = Field(min_length=12, max_length=128)

    @field_validator("token")
    @classmethod
    def validate_otp(cls, value: str) -> str:
        if not value.isdecimal():
            raise ValueError("Reset token must be a six-digit OTP")
        return value

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if any(ord(character) < 32 for character in value):
            raise ValueError("Password contains invalid control characters")
        return value


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    display_name: str
