from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings


if settings.database_url:
    engine = create_engine(
        settings.database_url,
    )

    SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )
else:
    engine = None
    SessionLocal = None
