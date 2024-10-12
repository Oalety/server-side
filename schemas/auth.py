from pydantic import BaseModel, EmailStr

class AuthResponse(BaseModel):
    email: EmailStr
    message: str

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
    email_sent: bool



