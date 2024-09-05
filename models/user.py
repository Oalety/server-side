from database import Base
from sqlalchemy import Column, Integer, String, Boolean, Numeric


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    money = Column(Numeric(precision=12, scale=2), nullable=False, default=0.00)
    is_verified = Column(Boolean, nullable=False, default=False)

    def __str__(self):
        return f"<User = {self.email}, name = {self.name}, money = {self.money}, is_verified = {self.is_verified}>"
