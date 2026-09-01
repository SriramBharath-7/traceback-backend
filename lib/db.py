"""
Database models — this is the persistent memory of the whole platform.

Every analyzed email becomes one row in `cases`. This is what makes
campaign correlation possible: instead of comparing emails only within a
single script run, we can ask "has ANY email ever, from day one, shared
this IP / reply-to / domain family?" by querying real stored history.

Works with SQLite (for local testing — zero setup) and Postgres (for
production on Vercel — Neon/Vercel Postgres/Supabase all work identically
here since SQLAlchemy abstracts the difference). Just change DATABASE_URL.
"""

import os
import hashlib
import json
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, Text, DateTime, JSON
)
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./traceback_local.db")

# Postgres URLs from providers often start with "postgres://" but SQLAlchemy
# needs "postgresql://" — normalize automatically so this doesn't trip anyone up.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    # Serverless functions spin up fresh, short-lived processes constantly — without
    # these, stale/dropped connections (common with a cold Postgres connection pool
    # on Neon/Vercel) surface as random, intermittent request failures.
    pool_pre_ping=True,     # test each connection before using it, transparently reconnect if dead
    pool_recycle=280,       # recycle connections before typical managed-Postgres idle timeouts (~300s)
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(64), unique=True, index=True)
    received_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    source = Column(String(32))  # "manual_upload" or "gmail_live"

    # Identity / basic fields
    subject = Column(Text)
    from_address = Column(Text)
    from_domain = Column(String(255), index=True)
    reply_to = Column(Text)
    reply_to_domain = Column(String(255), index=True)
    return_path_domain = Column(String(255), index=True)

    # Origin / infra
    originating_ip = Column(String(64), index=True)
    relay_chain = Column(JSON)             # full hop-by-hop path, for the trace visualization
    geo_country = Column(String(128))
    geo_region = Column(String(128))
    geo_city = Column(String(128))
    geo_isp = Column(String(255))
    is_proxy = Column(Boolean, default=False)
    is_hosting = Column(Boolean, default=False)
    domain_age_days = Column(Integer, nullable=True)

    # Authentication
    spf = Column(String(32))
    dkim = Column(String(32))
    dmarc = Column(String(32))
    dmarc_policy = Column(String(32), nullable=True)

    # Model outputs
    ml_probability = Column(Float)
    bec_score = Column(Float)
    bec_categories = Column(JSON)          # list of strings
    lookalike_domain = Column(JSON)        # dict or null

    # Final verdict
    final_score = Column(Float, index=True)
    risk_level = Column(String(16), index=True)
    explanation = Column(JSON)             # list of strings

    # Evidence / chain-of-custody (Section 6 of the PS checklist)
    raw_email_hash = Column(String(64))    # SHA-256 of the raw email — proves it wasn't altered later
    raw_email = Column(Text)               # full original, for forensic report regeneration


class AccessLog(Base):
    """
    Chain-of-custody log: every time a case is viewed, exported, or re-analyzed,
    record it here. This is what makes the forensic report defensible in a
    legal/law-enforcement handoff — an auditable trail of who touched what, when.
    """
    __tablename__ = "access_log"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(64), index=True)
    action = Column(String(64))            # "viewed", "exported_report", "re_analyzed"
    actor = Column(String(255), nullable=True)  # analyst identity, if you add auth later
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class GmailAccount(Base):
    """Stores OAuth tokens for a connected Gmail inbox used for live ingestion."""
    __tablename__ = "gmail_accounts"

    id = Column(Integer, primary_key=True, index=True)
    email_address = Column(String(255), unique=True)
    refresh_token = Column(Text)
    access_token = Column(Text, nullable=True)
    token_expiry = Column(DateTime, nullable=True)
    history_id = Column(String(64), nullable=True)   # Gmail's cursor for "what's new since last check"
    watch_expiration = Column(DateTime, nullable=True)
    connected_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


def init_db():
    Base.metadata.create_all(bind=engine)


def get_session():
    return SessionLocal()


def hash_raw_email(raw_email: str) -> str:
    return hashlib.sha256(raw_email.encode("utf-8", errors="ignore")).hexdigest()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at: {DATABASE_URL}")
    print("Tables created: cases, access_log, gmail_accounts")
