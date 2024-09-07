from fastapi import APIRouter, Depends, HTTPException

from database import get_db
from schemas.auth import UserRegisterResponse, UserRegisterRequest, EmailVerificationRequest, EmailVerificationResponse, \
    LoginRequest, LoginResponse, ResendCodeResponse, ResendCodeRequest
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
