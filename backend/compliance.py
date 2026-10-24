"""Configurable regulatory rule checks with explainable outcomes."""

from __future__ import annotations

from typing import Any

from backend.database import get_compliance_rules


def check_compliance(validation: dict[str, Any], document_type: str = "general") -> dict[str, Any]:
    normalized_type = str(document_type or "general").strip().casefold().replace("-", "_").replace(" ", "_")
    results = []
    for rule in get_compliance_rules():
        if not rule["enabled"]:
            continue
        if rule["rule_type"] == "field_presence":
            applicable_types = rule["config"].get("document_types", [])
            if applicable_types and normalized_type not in {item.lower() for item in applicable_types}:
                continue
            field = rule["config"]["field"]
            found = any(item["field"] == field for item in validation["fields"])
            invalid = any(item["field"] == field for item in validation["invalid_fields"])
            passed = found and not invalid
            results.append({
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "status": "pass" if passed else "warning",
                "explanation": rule["description"] if passed else f"{field} is missing or failed its validation check.",
            })
        elif rule["rule_type"] == "gstin_pan_match":
            consistency = next(
                (item for item in validation.get("consistency_checks", []) if item["check"] == "GSTIN embedded PAN matches detected PAN"),
                None,
            )
            results.append({
                "rule_id": rule["rule_id"],
                "name": rule["name"],
                "status": "pass" if consistency and consistency["passed"] else "warning" if consistency else "not_applicable",
                "explanation": (
                    consistency["explanation"] if consistency else "Not applicable: both GSTIN and PAN were not detected."
                ),
            })

    failed = any(result["status"] == "warning" for result in results)
    return {
        "status": "warning" if failed else "pass",
        "rules_checked": len(results),
        "results": results,
        "explanation": "Rule checks are screening aids; verify current requirements and source documents before deciding.",
    }