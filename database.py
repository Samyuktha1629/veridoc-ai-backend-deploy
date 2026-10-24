"""Database access layer; MySQL in deployment, SQLite for local development."""

from __future__ import annotations

import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import Boolean, Date, DateTime, Integer, JSON, String, Text, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    data_dir = Path(__file__).resolve().parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    DATABASE_URL = f"sqlite:///{(data_dir / 'verification.db').as_posix()}"

_engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
_Session = sessionmaker(bind=_engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class ApplicationRecord(Base):
    __tablename__ = "application_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    document_name: Mapped[str] = mapped_column(String(180), nullable=False)
    document_type: Mapped[str] = mapped_column(String(50), nullable=False, default="general")
    risk_level: Mapped[str] = mapped_column(String(30), nullable=False)
    review_status: Mapped[str] = mapped_column(String(30), nullable=False, default="pending_review")
    reviewer_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    report_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class OwnerAccount(Base):
    __tablename__ = "owner_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)


class ComplianceRule(Base):
    __tablename__ = "compliance_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    version: Mapped[str] = mapped_column(String(40), nullable=False, default="demo-1")
    effective_from: Mapped[date] = mapped_column(Date, nullable=False, default=date(2026, 1, 1))


def initialize_database() -> None:
    Base.metadata.create_all(_engine)
    with _Session.begin() as session:
        if session.scalar(select(ComplianceRule.id).limit(1)) is not None:
            return
        session.add_all([
            ComplianceRule(
                rule_id="pan_required_for_tax_application",
                name="PAN required for tax application",
                description="A valid PAN format was detected.",
                rule_type="field_presence",
                config_json={"field": "PAN", "document_types": ["pan", "pan_card", "tax_application"]},
                version="demo-1",
                effective_from=date(2026, 1, 1),
            ),
            ComplianceRule(
                rule_id="aadhaar_checksum",
                name="Aadhaar checksum",
                description="Aadhaar format and Verhoeff checksum are screened; issuance and identity are not verified.",
                rule_type="field_presence",
                config_json={"field": "Aadhaar", "document_types": ["aadhaar", "identity"]},
                version="demo-1",
                effective_from=date(2026, 1, 1),
            ),
            ComplianceRule(
                rule_id="gstin_pan_consistency",
                name="GSTIN and PAN consistency",
                description="The PAN embedded in GSTIN should match the applicant PAN.",
                rule_type="gstin_pan_match",
                config_json={},
                version="demo-1",
                effective_from=date(2026, 1, 1),
            ),
        ])


def has_accounts() -> bool:
    with _Session() as session:
        return session.scalar(select(OwnerAccount.id).limit(1)) is not None


def get_account(username: str) -> OwnerAccount | None:
    with _Session() as session:
        return session.scalar(
            select(OwnerAccount).where(OwnerAccount.username == username)
        )


def create_owner_account(username: str, password_hash: str) -> bool:
    try:
        with _Session.begin() as session:
            session.add(OwnerAccount(username=username, password_hash=password_hash))
        return True
    except IntegrityError:
        return False


def get_compliance_rules() -> list[dict[str, Any]]:
    with _Session() as session:
        rules = session.scalars(select(ComplianceRule).order_by(ComplianceRule.rule_id)).all()
        return [
            {
                "rule_id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "rule_type": rule.rule_type,
                "config": rule.config_json,
                "enabled": rule.enabled,
                "version": rule.version,
                "effective_from": rule.effective_from.isoformat(),
            }
            for rule in rules
        ]


def create_record(
    record_id: str,
    document_name: str,
    document_type: str,
    risk_level: str,
    report_json: dict[str, Any],
    created_at: str,
) -> None:
    with _Session.begin() as session:
        session.add(ApplicationRecord(
            id=record_id,
            document_name=document_name,
            document_type=document_type[:50],
            risk_level=risk_level,
            report_json=report_json,
            created_at=datetime.fromisoformat(created_at),
        ))


def get_record(record_id: str) -> ApplicationRecord | None:
    with _Session() as session:
        return session.get(ApplicationRecord, record_id)


def list_records() -> list[dict[str, Any]]:
    with _Session() as session:
        records = session.scalars(
            select(ApplicationRecord).order_by(ApplicationRecord.created_at.desc()).limit(100)
        ).all()
        return [
            {
                "id": record.id,
                "document_name": record.document_name,
                "document_type": record.document_type,
                "risk_level": record.risk_level,
                "status": record.review_status,
                "reviewer_note": record.reviewer_note,
                "created_at": record.created_at.isoformat(),
            }
            for record in records
        ]


def update_review(record_id: str, decision: str, note: str) -> dict[str, Any] | None:
    with _Session.begin() as session:
        record = session.get(ApplicationRecord, record_id)
        if record is None:
            return None
        record.review_status = decision
        record.reviewer_note = note
        record.reviewed_at = datetime.now(timezone.utc)
        report = dict(record.report_json)
        report["status"] = decision
        report["human_review"] = {
            "decision": decision,
            "note": note,
            "reviewed_at": record.reviewed_at.isoformat(),
        }
        record.report_json = report
        return {
            "id": record.id,
            "status": record.review_status,
            "reviewer_note": record.reviewer_note,
            "reviewed_at": record.reviewed_at.isoformat(),
        }