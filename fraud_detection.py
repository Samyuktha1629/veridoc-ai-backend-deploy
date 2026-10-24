"""Conservative document metadata and structure indicators; never a fraud verdict."""

from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any
from xml.etree import ElementTree

import cv2
import numpy as np
import pymupdf
from PIL import Image

MAX_DOCX_MEMBERS = 500
MAX_DOCX_EXPANDED_BYTES = 30_000_000
MAX_PDF_PAGES = 100


def analyze_document(content: bytes, suffix: str, filename: str) -> dict[str, Any]:
    """Inspect supported formats without saving files or executing document content."""
    indicators: list[dict[str, Any]] = []
    if suffix in {".jpg", ".jpeg", ".png"}:
        _analyze_image(content, indicators)
    elif suffix == ".pdf":
        _analyze_pdf(content, indicators)
    elif suffix == ".docx":
        _analyze_docx(content, indicators)

    score = min(
        100,
        sum(
            70 if item["severity"] == "high" else 35 if item["severity"] == "warning" else 10
            for item in indicators
        ),
    )
    format_name = suffix.lstrip(".").upper()
    return {
        "risk_score": score,
        "indicators": indicators,
        "method": f"{format_name.lower()}_metadata_and_structure_heuristics",
        "explanation": (
            "These format-specific heuristics can flag benign editing or miss manipulation. "
            "They do not establish authenticity or prove fraud; inspect the original with a trained reviewer."
        ),
    }


def _analyze_image(content: bytes, indicators: list[dict[str, Any]]) -> None:
    try:
        image = Image.open(io.BytesIO(content))
        if image.width * image.height > 30_000_000:
            raise ValueError("Image exceeds the 30 megapixel analysis limit.")
        software = str(image.getexif().get(305, "")).strip()
        if software:
            _add(
                indicators,
                "editing_software_metadata",
                "info",
                "Image metadata names editing or processing software. This can be normal document processing.",
            )
        if image.width < 700 or image.height < 450:
            _add(
                indicators,
                "low_resolution",
                "warning",
                "Low image resolution may limit verification confidence.",
            )
        if _resampling_score(image) >= 70:
            _add(
                indicators,
                "uneven_compression",
                "warning",
                "Image regions have uneven compression characteristics; ordinary edits and scanning can cause this too.",
            )
    except Exception as exc:
        raise ValueError(f"Could not analyze image metadata: {exc}") from exc


def _analyze_pdf(content: bytes, indicators: list[dict[str, Any]]) -> None:
    try:
        document = pymupdf.open(stream=content, filetype="pdf")
        if document.is_encrypted:
            raise ValueError("Password-protected PDFs cannot be analyzed.")
        if document.page_count > MAX_PDF_PAGES:
            raise ValueError(f"PDF analysis is limited to {MAX_PDF_PAGES} pages.")

        metadata = document.metadata or {}
        creator = (metadata.get("creator") or "").strip()
        producer = (metadata.get("producer") or "").strip()
        if creator or producer:
            _add(
                indicators,
                "pdf_producer_metadata",
                "info",
                "PDF creator/producer metadata is present. Metadata is user-editable and is not proof of origin.",
            )

        created = _parse_pdf_date(metadata.get("creationDate"))
        modified = _parse_pdf_date(metadata.get("modDate"))
        now = datetime.now(timezone.utc)
        if created and created > now + timedelta(days=366):
            _add(indicators, "pdf_creation_date_in_future", "warning", "PDF creation metadata is more than one year in the future.")
        if created and modified and modified < created:
            _add(indicators, "pdf_modified_before_created", "warning", "PDF modification metadata predates its creation metadata.")

        catalog = document.pdf_catalog()
        catalog_object = document.xref_object(catalog) if catalog else ""
        if re.search(r"/(?:OpenAction|AA)\b", catalog_object):
            _add(
                indicators,
                "pdf_document_action",
                "high",
                "The PDF catalog declares an automatic document action. Treat as a security and integrity review signal.",
            )

        javascript_objects = 0
        launch_actions = 0
        embedded_files = document.embfile_count()
        for xref in range(1, document.xref_length()):
            obj = document.xref_object(xref)
            if re.search(r"/(?:JavaScript|JS)\b", obj):
                javascript_objects += 1
            if re.search(r"/Launch\b", obj):
                launch_actions += 1
        if javascript_objects:
            _add(
                indicators,
                "pdf_javascript",
                "high",
                f"PDF object inspection found {javascript_objects} JavaScript-related object(s). Content was not executed.",
            )
        if launch_actions:
            _add(
                indicators,
                "pdf_launch_action",
                "high",
                f"PDF object inspection found {launch_actions} launch action(s). Content was not executed.",
            )
        if embedded_files:
            _add(
                indicators,
                "pdf_embedded_files",
                "warning",
                f"The PDF contains {embedded_files} embedded file(s); review their purpose and provenance.",
            )
        if len(re.findall(rb"%%EOF", content)) > 1:
            _add(
                indicators,
                "pdf_incremental_updates",
                "warning",
                "Multiple PDF end markers may indicate incremental revisions. Digital signatures or normal edits can cause this.",
            )
        for page in document:
            annotations = list(page.annots() or [])
            if annotations:
                _add(
                    indicators,
                    "pdf_annotations",
                    "info",
                    f"PDF annotations are present on at least one page ({len(annotations)} on the first annotated page inspected).",
                )
                break
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError(f"Could not inspect PDF structure: {exc}") from exc


def _analyze_docx(content: bytes, indicators: list[dict[str, Any]]) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            if len(members) > MAX_DOCX_MEMBERS:
                raise ValueError("DOCX archive contains too many entries to analyze safely.")
            if sum(item.file_size for item in members) > MAX_DOCX_EXPANDED_BYTES:
                raise ValueError("DOCX archive expands beyond the 30 MB analysis limit.")
            files = {item.filename.lower(): item.filename for item in members}
            names = set(files)
            if any(name.endswith("vbaproject.bin") for name in names):
                _add(
                    indicators,
                    "docx_macro_payload",
                    "high",
                    "The Office archive contains a VBA project. It was not opened or executed; confirm the file type and source.",
                )
            embedded = [name for name in names if name.startswith("word/embeddings/")]
            if embedded:
                _add(
                    indicators,
                    "docx_embedded_objects",
                    "warning",
                    f"The DOCX contains {len(embedded)} embedded object(s); review their purpose and provenance.",
                )

            external_relationships = 0
            for name in names:
                if not name.endswith(".rels"):
                    continue
                root = ElementTree.fromstring(archive.read(files[name]))
                external_relationships += sum(
                    relationship.attrib.get("TargetMode", "").lower() == "external"
                    for relationship in root
                )
            if external_relationships:
                _add(
                    indicators,
                    "docx_external_relationships",
                    "warning",
                    f"The DOCX references {external_relationships} external resource(s). Links may be legitimate; verify their purpose.",
                )

            tracked_change_count = 0
            hidden_text_count = 0
            for name in names:
                if name.startswith("word/") and name.endswith(".xml") and name in {
                    "word/document.xml", "word/footnotes.xml", "word/endnotes.xml",
                }:
                    root = ElementTree.fromstring(archive.read(files[name]))
                    tracked_change_count += sum(
                        element.tag.rsplit("}", 1)[-1] in {"ins", "del", "moveFrom", "moveTo"}
                        for element in root.iter()
                    )
                    hidden_text_count += sum(
                        element.tag.rsplit("}", 1)[-1] == "vanish"
                        for element in root.iter()
                    )
            if tracked_change_count:
                _add(
                    indicators,
                    "docx_tracked_changes",
                    "warning",
                    f"The document contains {tracked_change_count} tracked insertion/deletion marker(s). Review the change history.",
                )
            if hidden_text_count:
                _add(
                    indicators,
                    "docx_hidden_text",
                    "warning",
                    f"The document contains {hidden_text_count} hidden-text formatting marker(s). This can also be used for legitimate formatting.",
                )

            if "docprops/core.xml" in names:
                core = ElementTree.fromstring(archive.read(files["docprops/core.xml"]))
                creator_present = any(
                    element.tag.rsplit("}", 1)[-1] in {"creator", "lastModifiedBy"} and (element.text or "").strip()
                    for element in core.iter()
                )
                if creator_present:
                    _add(
                        indicators,
                        "docx_author_metadata",
                        "info",
                        "Document author metadata is present. It is user-editable and is not proof of origin.",
                    )
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError(f"Could not inspect DOCX structure: {exc}") from exc


def _add(indicators: list[dict[str, Any]], signal: str, severity: str, explanation: str) -> None:
    indicators.append({"signal": signal, "severity": severity, "explanation": explanation})


def _parse_pdf_date(value: str | None) -> datetime | None:
    if not value:
        return None
    match = re.fullmatch(r"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:Z|([+-])(\d{2})'?(\d{2})'?)?", value)
    if not match:
        return None
    parts = [int(part or default) for part, default in zip(match.groups()[:6], (1, 1, 0, 0, 0, 0))]
    year, month, day, hour, minute, second = parts
    offset_sign, offset_hour, offset_minute = match.groups()[6:]
    offset_minutes = (int(offset_hour or 0) * 60 + int(offset_minute or 0)) * (1 if offset_sign == "+" else -1)
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone(timedelta(minutes=offset_minutes)))


def _resampling_score(image: Image.Image) -> int:
    """Estimate compression variation after a JPEG round trip (indicative only)."""
    gray = cv2.cvtColor(np.array(image.convert("RGB")), cv2.COLOR_RGB2GRAY)
    if min(gray.shape) < 64:
        return 0
    height, width = gray.shape
    gray = cv2.resize(gray, (min(width, 512), min(height, 512)))
    encoded_ok, encoded = cv2.imencode(".jpg", gray, [cv2.IMWRITE_JPEG_QUALITY, 90])
    if not encoded_ok:
        return 0
    decoded = cv2.imdecode(encoded, cv2.IMREAD_GRAYSCALE)
    residual = cv2.absdiff(gray, decoded)
    patch_values = []
    for y in range(0, residual.shape[0] - 31, 32):
        for x in range(0, residual.shape[1] - 31, 32):
            patch_values.append(float(np.mean(residual[y:y + 32, x:x + 32])))
    if len(patch_values) < 4:
        return 0
    spread = float(np.std(patch_values))
    return max(0, min(100, round(spread * 4)))
