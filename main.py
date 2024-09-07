from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api import auth
from database import Base, engine
from models.user import User

app = FastAPI()

app.include_router(auth.router, tags=["Auth"])

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine, tables=[User.__table__], checkfirst=True)


@app.get("/")
def index():
    return "Hello Oalety Server-side"

