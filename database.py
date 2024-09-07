import os
from sqlalchemy import create_engine, URL
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from core.config import settings

# Get the db creds from core.settings
username = settings.DB_USERNAME
password = settings.DB_PASSWORD
host = settings.DB_HOST
database = settings.DB_NAME

# SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{username}:{password}@{host}/{database}"
SQLALCHEMY_DATABASE_URL = URL.create(
    drivername="mysql+pymysql",
    username=username,
    password=password,
    host=host,
    database=database,
)

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
