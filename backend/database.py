import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# ORM Base (models.py imports this)
Base = declarative_base()

DB_PATH = os.getenv("DB_PATH", "/var/lib/monitor-website/pm.db")
SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL")

if not SQLALCHEMY_DATABASE_URL:
    if DB_PATH.startswith("/"):
        SQLALCHEMY_DATABASE_URL = f"sqlite:////{DB_PATH.lstrip('/')}"
    else:
        SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
