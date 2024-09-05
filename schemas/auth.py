from pydantic import BaseModel, EmailStr


class UserRegisterRequest(BaseModel):
    email: EmailStr
    name: str
    password: str


class UserRegisterResponse(BaseModel):
    email: EmailStr
    token: str | None
    verified: bool
    message: str


class EmailVerificationRequest(BaseModel):
    email: EmailStr
    confirmation_code: str


class EmailVerificationResponse(BaseModel):
    email: EmailStr
    verified: bool
    message: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    email: EmailStr
    token: str | None
    message: str


class ResendCodeRequest(BaseModel):
    email: EmailStr


class ResendCodeResponse(BaseModel):
    email: EmailStr
    resent: bool
    message: str


