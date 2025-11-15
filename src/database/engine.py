"""
Vulnerability Management Pipeline - Database Engine
SQLAlchemy engine configuration and session management
"""

import os
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool
from contextlib import contextmanager

from .models import Base


# Database URL from environment
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://vmp_admin:changeme_secure_password@localhost:5432/vuln_management"
)

# Create engine with connection pooling
engine = create_engine(
    DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,  # Verify connections before use
    echo=os.getenv("DB_ECHO", "false").lower() == "true",  # SQL logging
)

# Session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


def get_engine():
    """Get SQLAlchemy engine instance"""
    return engine


def init_db():
    """
    Initialize database: create all tables.

    Note: In production, use Alembic migrations instead.
    """
    Base.metadata.create_all(bind=engine)
    print("✓ Database tables created successfully")


def drop_db():
    """
    Drop all database tables.

    WARNING: This deletes all data!
    """
    Base.metadata.drop_all(bind=engine)
    print("✓ Database tables dropped")


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for FastAPI routes to get database session.

    Usage:
        @app.get("/vulnerabilities")
        def get_vulns(db: Session = Depends(get_db)):
            return db.query(Vulnerability).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager for database sessions in non-FastAPI code.

    Usage:
        with get_db_context() as db:
            vulns = db.query(Vulnerability).all()
    """
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


class DatabaseManager:
    """
    Database operations manager for administrative tasks.
    """

    @staticmethod
    def create_tables():
        """Create all database tables"""
        Base.metadata.create_all(bind=engine)

    @staticmethod
    def drop_tables():
        """Drop all database tables"""
        Base.metadata.drop_all(bind=engine)

    @staticmethod
    def reset_database():
        """Drop and recreate all tables (DANGEROUS!)"""
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)

    @staticmethod
    def get_table_names():
        """Get list of all table names"""
        return Base.metadata.tables.keys()

    @staticmethod
    def check_connection() -> bool:
        """Test database connectivity"""
        try:
            with engine.connect() as conn:
                conn.execute("SELECT 1")
            return True
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            return False


# Initialize database on module import (for development)
if __name__ == "__main__":
    print("Initializing Vulnerability Management Database...")
    print(f"Database URL: {DATABASE_URL}")

    if DatabaseManager.check_connection():
        print("✓ Database connection successful")
        init_db()
    else:
        print("✗ Database connection failed")
