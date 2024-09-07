from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Settings(BaseSettings):
    # DB creds
    DB_USERNAME: str
    DB_PASSWORD: str
    DB_HOST: str
    DB_NAME: str

    # AWS Cognito creds
    REGION: str
    USER_POOL_ID: str
    CLIENT_ID: str
    CLIENT_SECRET: str

    class Config:
        env_file = ".env"


settings = Settings()
