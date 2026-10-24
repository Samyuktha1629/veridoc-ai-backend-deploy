"""FastAPI service for document validation and compliance review."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator

from backend.auth import (
    TOKEN_LIFETIME_SECONDS,
    hash_password,
    issue_token,
    token_username,
    validate_auth_configuration,
    verify_password,
)
from backend.compliance import check_compliance
from backend.database import (
    create_record,
    create_owner_account,
    get_account,
    get_record,
    has_accounts,
    initialize_database,
    list_records,
    update_review,
)
from backend.fraud_detection import analyze_document
from backend.ocr import OCRFailure, extract_text
from backend.validation import validate_application
from backend.report import build_pdf

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "15")) * 1024 * 1024
ALLOWED_TYPES = {
    ".pdf": "application/pdf",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}

app = FastAPI(
    title="Veridoc AI Document Verification API",
    version="1.0.0",
    description=(
        "Advisory document checks for trained human reviewers. Automated outputs "
        "are not a final eligibility or fraud determination."
    ),
)

configured_origins = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
if not configured_origins and os.getenv("APP_ENV", "").lower() != "production":
    configured_origins = ["*"]

local_network_origin_regex = (
    r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?::\d+)?$"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_origins or ["*"],
    allow_origin_regex=local_network_origin_regex,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


DOCUMENT_TYPES = {
    "general",
    "pan",
    "pan_card",
    "aadhaar",
    "identity",
    "gst",
    "gstin",
    "gst_registration",
    "tax_application",
}


class ValidationRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)
    document_type: str = "general"

    @field_validator("document_type", mode="before")
    @classmethod
    def normalize_document_type(cls, value: str | None) -> str:
        if value is None:
            return "general"
        normalized = str(value).strip().casefold().replace("-", "_").replace(" ", "_")
        allowed_aliases = {
            "pan_card": "pan_card",
            "pancard": "pan_card",
            "aadhaar": "aadhaar",
            "identity": "identity",
            "gst": "gst",
            "gstin": "gstin",
            "gst_registration": "gst_registration",
            "gstregistration": "gst_registration",
            "tax_application": "tax_application",
            "taxapplication": "tax_application",
            "general": "general",
            "pan": "pan",
        }
        candidate = allowed_aliases.get(normalized, normalized)
        if candidate not in DOCUMENT_TYPES:
            raise ValueError("Unsupported document type.")
        return candidate


class ReviewRequest(BaseModel):
    decision: str = Field(pattern="^(verified|needs_information|rejected)$")
    note: str = Field(default="", max_length=2000)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.]+$")
    password: str = Field(min_length=12, max_length=256)


class RegisterRequest(LoginRequest):
    pass


@app.on_event("startup")
def startup() -> None:
    validate_auth_configuration()
    initialize_database()


@app.get("/api/auth/status")
def auth_status() -> dict[str, bool]:
    return {"required": True, "setup_required": not has_accounts()}


@app.post("/api/auth/register", status_code=201)
def register(request: RegisterRequest) -> dict[str, str | int]:
    username = request.username.casefold()
    if not create_owner_account(username, hash_password(request.password)):
        raise HTTPException(409, "That username is already in use.")
    return {
        "access_token": issue_token(username),
        "token_type": "bearer",
        "expires_in": TOKEN_LIFETIME_SECONDS,
    }


@app.post("/api/auth/login")
def login(request: LoginRequest) -> dict[str, str | int]:
    account = get_account(request.username.casefold())
    if account is None or not verify_password(request.password, account.password_hash):
        raise HTTPException(401, "Incorrect username or password.")
    return {
        "access_token": issue_token(account.username),
        "token_type": "bearer",
        "expires_in": TOKEN_LIFETIME_SECONDS,
    }


def require_authenticated(
    authorization: str | None = Header(default=None),
) -> None:
    scheme, _, token = (authorization or "").partition(" ")
    username = token_username(token) if scheme.lower() == "bearer" and token else None
    if username is None:
        raise HTTPException(401, "Sign in to access the verification workspace.")
    if get_account(username) is None:
        raise HTTPException(401, "Sign in to access the verification workspace.")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "Veridoc AI Document Verification"}


@app.post("/api/documents/upload", status_code=201)
async def upload_document(
    file: UploadFile = File(...),
    document_type: str = Form(default="general"),
    _: None = Depends(require_authenticated),
) -> dict[str, Any]:
    document_type = ValidationRequest.model_validate({"text": "placeholder", "document_type": document_type}).document_type
    filename = file.filename or "document"
    suffix = os.path.splitext(filename)[1].lower()
    if suffix not in ALLOWED_TYPES:
        raise HTTPException(415, "Supported formats: PDF, JPG, PNG, and DOCX.")

    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if not content:
        raise HTTPException(400, "The uploaded file is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.")
    if not _signature_matches(suffix, content):
        raise HTTPException(415, "File contents do not match the selected file type.")

    try:
        extraction = extract_text(content, suffix)
    except OCRFailure as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        logger.exception("Document extraction failed")
        raise HTTPException(422, "Could not extract text from this document.") from exc

    validation = validate_application(extraction["text"], document_type)
    compliance = check_compliance(validation, document_type)
    try:
        fraud = analyze_document(content, suffix, filename)
    except ValueError as exc:
        raise HTTPException(422, "Could not analyze document image metadata.") from exc
    risk = _risk_level(validation, compliance, fraud)
    now = datetime.now(timezone.utc).isoformat()
    report = {
        "id": str(uuid.uuid4()),
        "created_at": now,
        "document_name": _safe_filename(filename),
        "document_type": document_type,
        "status": "pending_review",
        "risk_level": risk,
        "review_notice": "Automated signals are advisory. A trained reviewer must make the final decision.",
        "ocr": {
            "pages": extraction["pages"],
            "language": extraction["language"],
            "quality": extraction["quality"],
            "warnings": extraction["warnings"],
        },
        "validation": validation,
        "compliance": compliance,
        "fraud": fraud,
    }
    # The source document and unmasked OCR text are never written to the database.
    create_record(
        record_id=report["id"],
        document_name=report["document_name"],
        document_type=document_type,
        risk_level=risk,
        report_json=report,
        created_at=now,
    )
    return report


@app.post("/api/validate")
def validate_text(
    request: ValidationRequest,
    _: None = Depends(require_authenticated),
) -> dict[str, Any]:
    """Run validation on explicitly supplied text (not persisted)."""
    return validate_application(request.text, request.document_type)


@app.post("/api/compliance/check")
def compliance_check(
    request: ValidationRequest,
    _: None = Depends(require_authenticated),
) -> dict[str, Any]:
    validation = validate_application(request.text, request.document_type)
    return check_compliance(validation, request.document_type)


@app.post("/api/fraud/check")
async def fraud_check(
    file: UploadFile = File(...),
    _: None = Depends(require_authenticated),
) -> dict[str, Any]:
    filename = file.filename or "document"
    suffix = os.path.splitext(filename)[1].lower()
    if suffix not in ALLOWED_TYPES:
        raise HTTPException(415, "Supported formats: PDF, JPG, PNG, and DOCX.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds the configured size limit.")
    if not content or not _signature_matches(suffix, content):
        raise HTTPException(415, "File contents do not match the selected file type.")
    try:
        return analyze_document(content, suffix, filename)
    except ValueError as exc:
        raise HTTPException(422, "Could not analyze document image metadata.") from exc


@app.get("/api/documents")
def dashboard_records(_: None = Depends(require_authenticated)) -> list[dict[str, Any]]:
    return list_records()


@app.get("/api/documents/{record_id}/report")
def get_report(
    record_id: str,
    format: str = "json",
    _: None = Depends(require_authenticated),
) -> Response:
    record = get_record(record_id)
    if record is None:
        raise HTTPException(404, "Verification report not found.")
    if format.lower() == "pdf":
        return Response(
            content=build_pdf(record.report_json),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="verification-{record_id}.pdf"'},
        )
    if format.lower() != "json":
        raise HTTPException(400, "Format must be json or pdf.")
    return Response(json.dumps(record.report_json, ensure_ascii=False), media_type="application/json")


@app.patch("/api/documents/{record_id}/review")
def review_document(
    record_id: str,
    request: ReviewRequest,
    _: None = Depends(require_authenticated),
) -> dict[str, Any]:
    updated = update_review(record_id, request.decision, request.note.strip())
    if updated is None:
        raise HTTPException(404, "Verification report not found.")
    return updated


def _signature_matches(suffix: str, content: bytes) -> bool:
    if suffix == ".pdf":
        return content.startswith(b"%PDF-")
    if suffix in {".jpg", ".jpeg"}:
        return content.startswith(b"\xff\xd8\xff")
    if suffix == ".png":
        return content.startswith(b"\x89PNG\r\n\x1a\n")
    if suffix == ".docx":
        # DOCX is a ZIP container; requiring its signature blocks simple extension spoofing.
        return content.startswith(b"PK\x03\x04")
    return False


def _safe_filename(filename: str) -> str:
    portable_name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    return portable_name.replace("\r", "").replace("\n", "")[:180]


def _risk_level(validation: dict[str, Any], compliance: dict[str, Any], fraud: dict[str, Any]) -> str:
    if fraud["risk_score"] >= 70:
        return "Fraud suspected"
    if compliance["status"] == "warning" or fraud["risk_score"] >= 30 or validation["warnings"]:
        return "Warning"
    return "Pass"