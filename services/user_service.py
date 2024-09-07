from fastapi import HTTPException
from http import HTTPStatus
from sqlalchemy.orm import Session
from models.user import User
from schemas.auth import UserRegisterRequest


class UserService:
    def __init__(self, db: Session):
        self.db = db

    def save_user(self, user: UserRegisterRequest) -> User:
        """
        Save a new user after registration.
        """
        try:
            new_user = User(
                email=user.email,
                name=user.name,
            )
            self.db.add(new_user)
            self.db.commit()
            self.db.refresh(new_user)

            return new_user
        except Exception as e:
            raise HTTPException(
                status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                detail="Failed to store the new user"
            )

    def get_user_by_email(self, email: str) -> User | None:
        """
        Retrieves a user by their email from the database.
        """
        try:
            return self.db.query(User).filter(User.email == email).first()
        except Exception as e:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail="User not found"
            )

    def update_user_verification(self, user: User) -> User:
        """
        Updates the verification status of a user.
        """
        try:
            user.is_verified = True
            self.db.commit()
            self.db.refresh(user)
            return user
        except Exception as e:
            raise HTTPException(
                status_code=HTTPStatus.NOT_MODIFIED,
                detail="Failed to update user verification"
            )



