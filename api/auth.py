from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import APIKeyHeader
from database import get_db
from schemas.auth import UserRegisterResponse, UserRegisterRequest, EmailVerificationRequest, EmailVerificationResponse, \
    LoginRequest, LoginResponse, ResendCodeResponse, ResendCodeRequest, ForgotPasswordRequest, ForgotPasswordResponse, \
    ResetPasswordRequest, ResetPasswordResponse, ChangePasswordResponse, ChangePasswordRequest
from services.auth_service import AuthService
from services.user_service import UserService
from sqlalchemy.orm import Session

router = APIRouter()


@router.post("/register", response_model=UserRegisterResponse, tags=["Auth"])
def register(request: UserRegisterRequest, session: Session = Depends(get_db)):
    user_service = UserService(session)
    auth_service = AuthService(user_service)
    response = auth_service.register(request)
    return response


@router.post("/verify_email", response_model=EmailVerificationResponse, tags=["Auth"])
def verify_email(request: EmailVerificationRequest, session: Session = Depends(get_db)):
    user_service = UserService(session)
    auth_service = AuthService(user_service)
    response = auth_service.verify_email(request)
    return response


@router.post("/login", response_model=LoginResponse, tags=["Auth"])
def login(request: LoginRequest, session: Session = Depends(get_db)):
    user_service = UserService(session)
    auth_service = AuthService(user_service)
    response = auth_service.login(request)
    return response


@router.post("/resend_code", response_model=ResendCodeResponse, tags=["Auth"])
def resend_code(request: ResendCodeRequest, session: Session = Depends(get_db)):
    user_service = UserService(session)
    auth_service = AuthService(user_service)
    response = auth_service.resend_code(request)
    return response


@router.post("/forgot_password", response_model=ForgotPasswordResponse, tags=["Auth"])
def forgot_password(request: ForgotPasswordRequest, session: Session = Depends(get_db)):
    user_service = UserService(session)
    auth_service = AuthService(user_service)
    response = auth_service.forgot_password(request)
    return response


@router.post("/reset_password", response_model=ResetPasswordResponse, tags=["Auth"])
def reset_password(request: ResetPasswordRequest, session: Session = Depends(get_db)):
    user_service = UserService(session)
    auth_service = AuthService(user_service)
    response = auth_service.reset_password(request)
    return response


api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

@router.post("/change_password", response_model=ChangePasswordResponse, tags=["Auth"])
def change_password(
        request: ChangePasswordRequest,
        access_token: str = Depends(api_key_header),
        session: Session = Depends(get_db)
):
    if not access_token:
        raise HTTPException(status_code=400, detail="Authorization header missing")

    user_service = UserService(session)
    auth_service = AuthService(user_service)
    response = auth_service.change_password(request, access_token)
    return response

