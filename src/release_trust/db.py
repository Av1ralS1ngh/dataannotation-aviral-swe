"""Database engine and request-scoped session management."""

from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings
from .models import Base


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    url = get_settings().database_url
    options = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, pool_pre_ping=True, connect_args=options)


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def init_database() -> None:
    # TODO: replace startup table creation with versioned migrations.
    Base.metadata.create_all(get_engine())


def get_session() -> Generator[Session, None, None]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
