from typing import Optional

import boto3
from sqlalchemy.orm import Session
from core.config import settings
from schemas.auth import UserRegisterResponse, UserRegisterRequest, EmailVerificationRequest, EmailVerificationResponse, \
    LoginRequest, LoginResponse, ResendCodeRequest, ResendCodeResponse
from services.user_service import UserService
from utils.util import generate_secret_hash

cognito_client = boto3.client('cognito-idp', region_name=settings.REGION)


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def register(self, user: UserRegisterRequest) -> UserRegisterResponse:
        # Generate secret_hash
        secret_hash = generate_secret_hash(user.email)

        # Register user with AWS Cognito
        cognito_response = cognito_client.sign_up(
            ClientId=settings.CLIENT_ID,
            SecretHash=secret_hash,
            Username=user.email,
            Password=user.password,
            UserAttributes=[
                {
                    'Name': 'name',  # Standard attribute for the user's full name
                    'Value': user.name
                },
                {
                    'Name': 'email',  # Standard attribute for the user's email
                    'Value': user.email
                }
            ]
        )

        response = UserRegisterResponse(
            email=user.email,
            token=None,
            verified=False,
            message="Registration failed"
        )

        if cognito_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            # Save user in DB
            new_user = self.user_service.save_user(user)

            response.message = "User Registered Successfully"

        return response

    def verify_email(self, request: EmailVerificationRequest) -> EmailVerificationResponse:
        # Generate secret_hash
        secret_hash = generate_secret_hash(request.email)

        # Verify email in AWS Cognito
        cognito_response = cognito_client.confirm_sign_up(
            ClientId=settings.CLIENT_ID,
            SecretHash=secret_hash,
            Username=request.email,
            ConfirmationCode=request.confirmation_code,
        )

        response = EmailVerificationResponse(
            email=request.email,
            verified=False,
            message="Verification Failed"
        )

        if cognito_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            # Update status in DB
            user = self.user_service.get_user_by_email(request.email)
            if user:
                user = self.user_service.update_user_verification(user)

            response.verified = user.is_verified
            response.message = f"Email {request.email} verified successfully"

        return response

    @staticmethod
    def login(request: LoginRequest) -> LoginResponse:
        # Generate secret_hash
        secret_hash = generate_secret_hash(request.email)

        # Initiate Auth
        cognito_response = cognito_client.initiate_auth(
            ClientId=settings.CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': request.email,
                'PASSWORD': request.password,
                'SECRET_HASH': secret_hash
            }
        )

        response = LoginResponse(
            email=request.email,
            token=None,
            message='Login Failed'
        )
        if cognito_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            auth_result = cognito_response['AuthenticationResult']
            access_token = auth_result['AccessToken']
            response.token = access_token
            response.message = 'Logged in successfully'

        return response

    @staticmethod
    def resend_code(request: ResendCodeRequest) -> ResendCodeResponse:
        # Generate secret_hash
        secret_hash = generate_secret_hash(request.email)

        # Resend confirmation code
        cognito_response = cognito_client.resend_confirmation_code(
            ClientId=settings.CLIENT_ID,
            SecretHash=secret_hash,
            Username=request.email,
        )

        response = ResendCodeResponse(
            email=request.email,
            resent=False,
            message=f'Resending Confirmation Code to {request.email} Failed'
        )

        if cognito_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            response.resent = True
            response.message = f'Confirmation code resent successfully to {request.email}'

        return response
