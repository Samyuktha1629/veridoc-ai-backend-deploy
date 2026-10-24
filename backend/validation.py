"""Explainable field validation and optional Hugging Face entity extraction."""

from __future__ import annotations

import os
import re
from functools import lru_cache
from typing import Any

PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", re.IGNORECASE)
AADHAAR_PATTERN = re.compile(r"(?<!\d)(?:\d{4}[\s-]?){2}\d{4}(?!\d)")
GSTIN_PATTERN = re.compile(r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b", re.IGNORECASE)


def validate_application(text: str, document_type: str = "general") -> dict[str, Any]:
    normalized_type = str(document_type or "general").lower()
    normalized = text.upper()
    fields: list[dict[str, Any]] = []
    invalid_fields: list[dict[str, Any]] = []
    warnings: list[str] = []

    pan = _first(PAN_PATTERN, normalized)
    if pan:
        valid = _valid_pan(pan)
        _add_field(fields, invalid_fields, "PAN", pan, valid, "PAN should match five letters, four digits, and a final letter.")
    elif normalized_type in {"pan", "pan_card", "tax_application"}:
        invalid_fields.append({"field": "PAN", "value": None, "reason": "PAN was not found in the document."})

    aadhaar_match = _first(AADHAAR_PATTERN, text)
    if aadhaar_match:
        aadhaar = re.sub(r"\D", "", aadhaar_match)
        valid = _verhoeff_valid(aadhaar)
        _add_field(fields, invalid_fields, "Aadhaar", aadhaar, valid, "Aadhaar checksum did not validate.")
    elif normalized_type in {"aadhaar", "identity"}:
        invalid_fields.append({"field": "Aadhaar", "value": None, "reason": "Aadhaar number was not found in the document."})

    gstin = _first(GSTIN_PATTERN, normalized)
    if gstin:
        valid = _valid_gstin(gstin)
        _add_field(fields, invalid_fields, "GSTIN", gstin, valid, "GSTIN format or embedded PAN did not validate.")
    elif normalized_type in {"gst", "gstin", "gst_registration"}:
        invalid_fields.append({"field": "GSTIN", "value": None, "reason": "GSTIN was not found in the document."})

    if not fields and not invalid_fields:
        warnings.append("No supported identifiers were detected. Review the extracted document manually.")
    if len(text.strip()) < 40:
        warnings.append("Short extracted text may reduce validation accuracy.")

    entities = _extract_entities(text) if os.getenv("ENABLE_HF_NER", "false").lower() == "true" else []
    ai_explanation = _explain_with_local_llm(fields, invalid_fields, warnings)
    consistency_checks = []
    if pan and gstin:
        consistent = gstin[2:12] == pan
        consistency_checks.append({
            "check": "GSTIN embedded PAN matches detected PAN",
            "passed": consistent,
            "explanation": (
                "The PAN embedded in the detected GSTIN matches the detected PAN."
                if consistent else "The PAN embedded in the detected GSTIN differs from the detected PAN."
            ),
        })
        if not consistent:
            invalid_fields.append({
                "field": "GSTIN/PAN consistency",
                "value": "mismatch",
                "reason": "PAN embedded in GSTIN does not match the detected PAN.",
            })
    return {
        "fields": fields,
        "invalid_fields": invalid_fields,
        "warnings": warnings,
        "consistency_checks": consistency_checks,
        "entities": entities,
        "ai_explanation": ai_explanation,
        "method": "format_and_checksum_rules" + (" + configured_transformer_ner" if entities else ""),
        "explanation": "Identifiers are checked against format/checksum rules; extracted values are masked in this result.",
    }


def _add_field(
    fields: list[dict[str, Any]], invalid: list[dict[str, Any]],
    name: str, value: str, valid: bool, reason: str,
) -> None:
    item = {"field": name, "value": _mask(value), "valid": valid}
    (fields if valid else invalid).append(
        item if valid else {**item, "reason": reason}
    )


def _mask(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) >= 8:
        return f"****{digits[-4:]}"
    return value[:2] + "*" * max(0, len(value) - 4) + value[-2:]


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(0) if match else None


def _valid_pan(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", value))


def _valid_gstin(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]", value))


def _verhoeff_valid(value: str) -> bool:
    """Validate the Verhoeff check digit; this only checks checksum, not issuance."""
    multiplication = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ]
    permutation = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ]
    if len(value) != 12 or not value.isdigit() or value[0] in "01":
        return False
    checksum = 0
    for index, digit in enumerate(reversed(value)):
        checksum = multiplication[checksum][permutation[index % 8][int(digit)]]
    return checksum == 0


def _extract_entities(text: str) -> list[dict[str, Any]]:
    """Run a locally hosted entity model; never include entity values in reports."""
    extractor = _load_pipeline(os.getenv("HF_NER_MODEL", "dslim/bert-base-NER"), "ner")
    return [
        {"label": entity["entity_group"], "score": round(float(entity["score"]), 3)}
        for entity in extractor(text[:10_000])
    ]


def _explain_with_local_llm(
    valid_fields: list[dict[str, Any]],
    invalid_fields: list[dict[str, Any]],
    warnings: list[str],
) -> str | None:
    """Optionally explain deterministic outcomes using masked findings only."""
    if os.getenv("ENABLE_HF_LLM", "false").lower() != "true":
        return None
    from transformers import pipeline

    model_name = os.getenv("HF_LLM_MODEL", "google/flan-t5-small")
    generator = _load_pipeline(model_name, "text2text-generation")
    prompt_data = {
        "passed": [{"field": item["field"], "masked_value": item["value"]} for item in valid_fields],
        "needs_review": [
            {"field": item["field"], "masked_value": item.get("value"), "reason": item.get("reason")}
            for item in invalid_fields
        ],
        "warnings": warnings,
    }
    prompt = (
        "Explain these deterministic document-screening findings in plain language in no more than 45 words. "
        "Do not decide eligibility, infer fraud, or add facts. Data: " + str(prompt_data)
    )
    result = generator(prompt, max_new_tokens=80, do_sample=False)
    explanation = str(result[0]["generated_text"]).strip()
    return explanation[:600] if explanation else None


@lru_cache(maxsize=4)
def _load_pipeline(model_name: str, task: str) -> Any:
    from transformers import pipeline

    return pipeline(task, model=model_name)