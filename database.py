"""
Database initialization and session management using SQLAlchemy, providing functions to create the database engine,
manage sessions, and perform connectivity checks. This module includes logic to handle database connection pooling, to
provide context-managed sessions for use in route handlers and services, and to ensure proper cleanup of database
resources on application shutdown. It also includes a function to initialize the database schema based on defined
SQLAlchemy models.

Copyright (c) 2026 Stefan Kumarasinghe.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
"""

import logging
import os
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from typing import Protocol

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from db_models import Base

logger = logging.getLogger(__name__)


class _SessionFactory(Protocol):
    def __call__(self) -> Session: ...


def _new_session(factory: _SessionFactory) -> Session:
    return factory()


_ENGINE: Engine | None = None
_SESSION_LOCAL: _SessionFactory | None = None


def ensure_database_exists(database_url: str) -> None:
    url = make_url(database_url)
    db_name = url.database
    if not db_name:
        raise RuntimeError("Database URL must include a database name")

    admin_url = url.set(database="postgres")
    admin_engine = create_engine(admin_url, pool_pre_ping=True)
    try:
        with admin_engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": db_name},
            ).scalar()
            if exists:
                return
            conn.execute(text(f'CREATE DATABASE "{db_name}"'))
            logger.info("Created database %s", db_name)
    finally:
        admin_engine.dispose()


def init_database(
    database_url: str,
    echo: bool = False,
    pool_size: int | None = None,
) -> None:
    if _ENGINE is not None and _SESSION_LOCAL is not None:
        logger.debug("Database already initialized; skipping re-init.")
        return

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        pool_size=pool_size or int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
        pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),
        echo=echo,
    )

    globals()["_ENGINE"] = engine
    globals()["_SESSION_LOCAL"] = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return


def _require_session_factory() -> _SessionFactory:
    if _SESSION_LOCAL is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _SESSION_LOCAL


@contextmanager
def get_db_session() -> Iterator[Session]:
    if _ENGINE is None or _SESSION_LOCAL is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    session: Session = _new_session(_require_session_factory())
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    if _ENGINE is None or _SESSION_LOCAL is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    session: Session = _new_session(_require_session_factory())
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def connection_test() -> bool:
    if _ENGINE is None:
        return False
    try:
        with _ENGINE.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError as exc:
        logger.debug("DB connection test failed: %s", exc)
        return False


def dispose_database() -> None:
    globals()["_SESSION_LOCAL"] = None
    if _ENGINE is not None:
        try:
            _ENGINE.dispose()
        finally:
            globals()["_ENGINE"] = None


def init_db() -> None:
    if _ENGINE is None or not hasattr(_ENGINE, "connect"):
        raise RuntimeError("Database not initialized. Call init_database() first.")

    logger.info("Initializing database tables...")
    Base.metadata.create_all(bind=_ENGINE)
    logger.info("Database tables created successfully.")
