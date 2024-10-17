from cgitb import reset
from http.client import responses
from os import access

import boto3
from fastapi import HTTPException

from core.config import settings
from schemas.auth import UserRegisterResponse, UserRegisterRequest, EmailVerificationRequest, EmailVerificationResponse, \
    LoginRequest, LoginResponse, ResendCodeRequest, ResendCodeResponse, ForgotPasswordRequest, ForgotPasswordResponse, \
    ResetPasswordRequest, ResetPasswordResponse, ChangePasswordRequest, ChangePasswordResponse
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
            id_token=None,
            access_token=None,
            message='Login Failed'
        )
        if cognito_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            auth_result = cognito_response['AuthenticationResult']
            id_token = auth_result['IdToken']
            access_token = auth_result['AccessToken']
            response.id_token = id_token
            response.access_token = access_token
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

    @staticmethod
    def forgot_password(request: ForgotPasswordRequest) -> ForgotPasswordResponse:
        # Generate secret_hash
        secret_hash = generate_secret_hash(request.email)

        # Send a code to the email requesting the 'forgot-password'
        cognito_response = cognito_client.forgot_password(
            ClientId=settings.CLIENT_ID,
            SecretHash=secret_hash,
            Username=request.email,
        )

        response = ForgotPasswordResponse(
            email=request.email,
            sent=False,
            message=f'Sending code [forgot password] to <{request.email}> Failed'
        )

        if cognito_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            response.sent = True
            response.message = f'Code [forgot password] sent successfully to <{request.email}>'

        return response

    @staticmethod
    def reset_password(request: ResetPasswordRequest) -> ResetPasswordResponse:
        # Generate secret_hash
        secret_hash = generate_secret_hash(request.email)

        # Reset the password using the code sent previously
        cognito_response = cognito_client.confirm_forgot_password(
            ClientId=settings.CLIENT_ID,
            SecretHash=secret_hash,
            Username=request.email,
            ConfirmationCode=request.code,
            Password=request.new_password,
        )

        response = ResetPasswordResponse(
            email=request.email,
            reset=False,
            message=f'Reset password attempted by <{request.email}> Failed',
        )

        if cognito_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            response.reset = True
            response.message = f'Reset password went successfully by <{request.email}>'

        return response

    @staticmethod
    def change_password(request: ChangePasswordRequest, access_token: str) -> ChangePasswordResponse:
        try:
            # Change password operation through cognito
            cognito_response = cognito_client.change_password(
                AccessToken=access_token,
                PreviousPassword=request.current_password,
                ProposedPassword=request.new_password,
            )

            response = ChangePasswordResponse(
                email=request.email,
                updated=False,
                message=f'Updating password went wrong by <{request.email}>',
            )

            if cognito_response['ResponseMetadata']['HTTPStatusCode'] == 200:
                response.updated = True
                response.message = f'Password updated successfully for <{request.email}>'

            return response
        except cognito_client.exceptions.NotAuthorizedException:
            raise HTTPException(status_code=403, detail="Invalid access token")
        except cognito_client.exceptions.InvalidPasswordException:
            raise HTTPException(status_code=400, detail="New password does not meet the required policy")
        except cognito_client.exceptions.LimitExceededException:
            raise HTTPException(status_code=400, detail="Attempt limit exceeded, try again later")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
