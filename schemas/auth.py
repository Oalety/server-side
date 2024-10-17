from pydantic import BaseModel, EmailStr


class AuthResponse(BaseModel):
    email: EmailStr
    message: str


class TokenData(BaseModel):
    username: str | None = None
    id_token: str | None = None
    access_token: str | None = None


class UserRegisterRequest(BaseModel):
    email: EmailStr
    name: str
    password: str


class UserRegisterResponse(BaseModel):
    email: EmailStr
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
    id_token: str | None
    access_token: str | None
    message: str


class ResendCodeRequest(BaseModel):
    email: EmailStr


class ResendCodeResponse(BaseModel):
    email: EmailStr
    resent: bool
    message: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ForgotPasswordResponse(AuthResponse):
    sent: bool


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str
    code: str


class ResetPasswordResponse(AuthResponse):
    reset: bool


class ChangePasswordRequest(BaseModel):
    email: EmailStr
    current_password: str
    new_password: str


class ChangePasswordResponse(AuthResponse):
    updated: bool


