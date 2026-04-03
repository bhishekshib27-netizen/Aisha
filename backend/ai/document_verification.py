"""
Onboarda - Clean Document Verification Engine

Purpose:
- run strict gate checks
- run deterministic rule checks
- run optional AI-assisted checks
- aggregate results conservatively
- never let weak extraction silently pass

Design principles:
- no result = no pass
- critical identity mismatches = fail
- low-confidence extraction = review
- AI may assist, but rules drive routing
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import date, datetime
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

from backend.ai.verification_matrix import (
    CheckClassification,
    CheckStatus,
    DOC_TYPE_TO_CHECK_IDS,
    GATE_CHECKS,
    get_ai_checks_for_doc_type,
    get_rule_checks_for_doc_type,
    is_licence_applicable,
)

from backend.config.config import Config

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "image/jpeg",
    "image/jpg",
    "image/png",
}
ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png"}
ALLOWED_MAGIC_BYTES = {
    b"%PDF": "application/pdf",
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG": "image/png",
}

DATE_WINDOW_3_MONTHS = 90
DATE_WINDOW_6_MONTHS = 182
DATE_WINDOW_12_MONTHS = 365
DATE_WINDOW_18_MONTHS = 548
UBO_THRESHOLD_PCT = 25.0


def _result(
    id_: str,
    label: str,
    classification: str,
    result: str,
    message: str,
    *,
    ps_field: Optional[str] = None,
    ps_value: Any = None,
    extracted_value: Any = None,
    confidence: Optional[float] = None,
    source: str = "rule",
    rule_type: Optional[str] = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "id": id_,
        "label": label,
        "classification": classification,
        "type": rule_type or classification,
        "result": result,
        "message": message,
        "source": source,
    }
    if ps_field:
        out["ps_field"] = ps_field
    if ps_value is not None:
        out["ps_value"] = str(ps_value)
    if extracted_value is not None:
        out["extracted_value"] = str(extracted_value)
    if confidence is not None:
        out["confidence"] = round(float(confidence), 3)
    return out


def _pass(id_: str, label: str, classification: str, message: str, **kw: Any) -> Dict[str, Any]:
    return _result(id_, label, classification, CheckStatus.PASS, message, **kw)


def _warn(id_: str, label: str, classification: str, message: str, **kw: Any) -> Dict[str, Any]:
    return _result(id_, label, classification, CheckStatus.WARN, message, **kw)


def _fail(id_: str, label: str, classification: str, message: str, **kw: Any) -> Dict[str, Any]:
    return _result(id_, label, classification, CheckStatus.FAIL, message, **kw)


def _skip(id_: str, label: str, classification: str, message: str, **kw: Any) -> Dict[str, Any]:
    return _result(id_, label, classification, CheckStatus.SKIP, message, source="gate", **kw)


def _normalise_name(name: str) -> str:
    if not name:
        return ""
    name = name.strip().lower()
    name = re.sub(r"[^\w\s]", " ", name)
    name = re.sub(r"\s+", " ", name)
    return name.strip()


def _strip_legal_suffix(name: str) -> str:
    suffixes = [
        "limited",
        "ltd",
        "llc",
        "inc",
        "incorporated",
        "corp",
        "corporation",
        "plc",
        "llp",
        "lp",
        "company",
        "co",
        "gmbh",
        "ag",
        "sa",
        "sas",
        "sarl",
        "bv",
        "nv",
        "pty",
    ]
    cleaned = _normalise_name(name)
    for suffix in sorted(suffixes, key=len, reverse=True):
        if cleaned.endswith(" " + suffix):
            cleaned = cleaned[: -(len(suffix) + 1)].strip()
            break
    return cleaned


def _name_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    a_clean = _strip_legal_suffix(a)
    b_clean = _strip_legal_suffix(b)
    if not a_clean or not b_clean:
        return 0.0
    if a_clean == b_clean:
        return 1.0
    return SequenceMatcher(None, a_clean, b_clean).ratio()


def _parse_date(value: Any) -> Optional[date]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value

    value_str = str(value).strip()
    formats = (
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%d-%m-%Y",
        "%d %B %Y",
        "%d %b %Y",
        "%B %d, %Y",
        "%Y",
    )
    for fmt in formats:
        try:
            parsed = datetime.strptime(value_str, fmt)
            return parsed.date()
        except ValueError:
            continue
    return None


def _normalise_string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _is_suspicious_text(value: Any) -> bool:
    text = _normalise_string(value)
    if not text:
        return True
    bad_patterns = [
        r"^[xX\-\._]{2,}$",
        r"^[0-9]{1,2}$",
        r"^(unknown|n/?a|none|null|not found|unreadable)$",
    ]
    lowered = text.lower()
    for pattern in bad_patterns:
        if re.match(pattern, lowered):
            return True
    return False


def _extract_confidence(extracted_fields: Dict[str, Any], field_name: str, default: float = 0.0) -> float:
    confidences = extracted_fields.get("_field_confidence", {})
    try:
        return float(confidences.get(field_name, default))
    except (TypeError, ValueError):
        return default


def _confidence_gate(field_name: str, confidence: float, *, critical: bool) -> Optional[Dict[str, Any]]:
    if confidence <= 0:
        return _warn(
            "CONF-00",
            f"{field_name} Confidence Missing",
            CheckClassification.RULE,
            f"No confidence score available for {field_name} extraction",
            confidence=confidence,
            rule_type="confidence",
        )

    threshold = Config.MIN_CONFIDENCE_SCORE if critical else Config.MANUAL_REVIEW_THRESHOLD
    if confidence < threshold:
        status = _fail if critical and Config.FAIL_ON_UNCERTAINTY else _warn
        return status(
            "CONF-01",
            f"{field_name} Confidence Too Low",
            CheckClassification.RULE,
            f"{field_name} confidence {confidence:.2f} is below threshold {threshold:.2f}",
            confidence=confidence,
            rule_type="confidence",
        )
    return None


def _check_exact_match(
    id_: str,
    label: str,
    declared: Any,
    extracted: Any,
    *,
    ps_field: Optional[str] = None,
    critical: bool = True,
) -> Dict[str, Any]:
    declared_str = _normalise_string(declared)
    extracted_str = _normalise_string(extracted)

    if not declared_str:
        return _warn(
            id_,
            label,
            CheckClassification.RULE,
            "Declared value missing in pre-screening data",
            ps_field=ps_field,
            ps_value=declared,
            extracted_value=extracted,
            rule_type="exact_match",
        )

    if not extracted_str or _is_suspicious_text(extracted_str):
        return _fail(
            id_,
            label,
            CheckClassification.RULE,
            "Value could not be reliably extracted from document",
            ps_field=ps_field,
            ps_value=declared,
            extracted_value=extracted,
            rule_type="exact_match",
        )

    d_norm = re.sub(r"[\s\-]", "", declared_str.lower())
    e_norm = re.sub(r"[\s\-]", "", extracted_str.lower())

    if d_norm == e_norm:
        return _pass(
            id_,
            label,
            CheckClassification.RULE,
            "Exact match confirmed",
            ps_field=ps_field,
            ps_value=declared,
            extracted_value=extracted,
            rule_type="exact_match",
        )

    return _fail(
        id_,
        label,
        CheckClassification.RULE,
        f"Mismatch: extracted '{extracted_str}' vs declared '{declared_str}'",
        ps_field=ps_field,
        ps_value=declared,
        extracted_value=extracted,
        rule_type="exact_match",
    )


def _check_name_match(
    id_: str,
    label: str,
    declared: Any,
    extracted: Any,
    *,
    ps_field: Optional[str] = None,
    critical: bool = True,
) -> Dict[str, Any]:
    declared_str = _normalise_string(declared)
    extracted_str = _normalise_string(extracted)

    if not declared_str:
        return _warn(
            id_,
            label,
            CheckClassification.RULE,
            "Declared name missing in pre-screening data",
            ps_field=ps_field,
            ps_value=declared,
            extracted_value=extracted,
            rule_type="name",
        )

    if not extracted_str or _is_suspicious_text(extracted_str):
        return _fail(
            id_,
            label,
            CheckClassification.RULE,
            "Name could not be reliably extracted from document",
            ps_field=ps_field,
            ps_value=declared,
            extracted_value=extracted,
            rule_type="name",
        )

    similarity = _name_similarity(extracted_str, declared_str)

    if similarity >= 0.90:
        return _pass(
            id_,
            label,
            CheckClassification.RULE,
            f"Name match confirmed ({int(similarity * 100)}%)",
            ps_field=ps_field,
            ps_value=declared,
            extracted_value=extracted,
            confidence=similarity,
            rule_type="name",
        )

    if similarity >= 0.75 and not critical:
        return _warn(
            id_,
            label,
            CheckClassification.RULE,
            f"Partial name match ({int(similarity * 100)}%) - manual review required",
            ps_field=ps_field,
            ps_value=declared,
            extracted_value=extracted,
            confidence=similarity,
            rule_type="name",
        )

    return _fail(
        id_,
        label,
        CheckClassification.RULE,
        f"Name mismatch: extracted '{extracted_str}' vs declared '{declared_str}' ({int(similarity * 100)}%)",
        ps_field=ps_field,
        ps_value=declared,
        extracted_value=extracted,
        confidence=similarity,
        rule_type="name",
    )


def _check_date_recency(
    id_: str,
    label: str,
    extracted_date: Any,
    *,
    max_days: int,
) -> Dict[str, Any]:
    parsed = _parse_date(extracted_date)
    if not parsed:
        return _fail(
            id_,
            label,
            CheckClassification.RULE,
            "Date could not be reliably extracted",
            extracted_value=extracted_date,
            rule_type="date",
        )

    delta = (date.today() - parsed).days
    if delta < 0:
        return _pass(
            id_,
            label,
            CheckClassification.RULE,
            f"Date appears valid ({abs(delta)} days in future tolerance)",
            extracted_value=extracted_date,
            rule_type="date",
        )

    if delta <= max_days:
        return _pass(
            id_,
            label,
            CheckClassification.RULE,
            f"Date is within allowed recency window ({delta} days old)",
            extracted_value=extracted_date,
            rule_type="date",
        )

    return _fail(
        id_,
        label,
        CheckClassification.RULE,
        f"Date is too old ({delta} days, limit {max_days})",
        extracted_value=extracted_date,
        rule_type="date",
    )


def _check_not_expired(id_: str, label: str, expiry_date: Any, *, warn_days: int = 30) -> Dict[str, Any]:
    parsed = _parse_date(expiry_date)
    if not parsed:
        return _fail(
            id_,
            label,
            CheckClassification.RULE,
            "Expiry date could not be reliably extracted",
            extracted_value=expiry_date,
            rule_type="date",
        )

    days_to_expiry = (parsed - date.today()).days
    if days_to_expiry < 0:
        return _fail(
            id_,
            label,
            CheckClassification.RULE,
            f"Document expired {abs(days_to_expiry)} days ago",
            extracted_value=expiry_date,
            rule_type="date",
        )

    if days_to_expiry <= warn_days:
        return _warn(
            id_,
            label,
            CheckClassification.RULE,
            f"Document expires soon ({days_to_expiry} days left)",
            extracted_value=expiry_date,
            rule_type="date",
        )

    return _pass(
        id_,
        label,
        CheckClassification.RULE,
        f"Document valid for {days_to_expiry} more days",
        extracted_value=expiry_date,
        rule_type="date",
    )


def run_gate_checks(
    file_path: str,
    file_size: int,
    mime_type: str,
    existing_hashes: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    existing_hashes = existing_hashes or []

    file_exists = bool(file_path and os.path.isfile(file_path))
    extension = os.path.splitext(file_path)[1].lower() if file_path else ""

    if not file_exists:
        results.append(
            _fail(
                "GATE-01",
                "File Format",
                CheckClassification.GATE,
                "File not accessible for verification",
                rule_type="enum",
                source="gate",
            )
        )
    else:
        magic_ok = False
        try:
            with open(file_path, "rb") as handle:
                header = handle.read(8)
            for magic in ALLOWED_MAGIC_BYTES:
                if header.startswith(magic):
                    magic_ok = True
                    break
        except OSError:
            magic_ok = False

        mime_ok = mime_type in ALLOWED_MIME_TYPES if mime_type else False
        ext_ok = extension in ALLOWED_EXTENSIONS

        if (mime_ok or ext_ok) and magic_ok:
            results.append(
                _pass(
                    "GATE-01",
                    "File Format",
                    CheckClassification.GATE,
                    f"Accepted file format ({mime_type or extension})",
                    rule_type="enum",
                    source="gate",
                )
            )
        else:
            results.append(
                _fail(
                    "GATE-01",
                    "File Format",
                    CheckClassification.GATE,
                    f"Unsupported or invalid file format ({mime_type or extension})",
                    rule_type="enum",
                    source="gate",
                )
            )

    if file_size > MAX_FILE_SIZE_BYTES:
        results.append(
            _fail(
                "GATE-02",
                "File Size",
                CheckClassification.GATE,
                f"File exceeds limit ({file_size} bytes)",
                rule_type="numeric",
                source="gate",
            )
        )
    else:
        results.append(
            _pass(
                "GATE-02",
                "File Size",
                CheckClassification.GATE,
                "File size within limit",
                rule_type="numeric",
                source="gate",
            )
        )

    if file_exists:
        try:
            with open(file_path, "rb") as handle:
                file_hash = hashlib.sha256(handle.read()).hexdigest()
            if file_hash in existing_hashes:
                results.append(
                    _warn(
                        "GATE-03",
                        "Duplicate Detection",
                        CheckClassification.GATE,
                        "Possible duplicate upload detected",
                        rule_type="hash",
                        source="gate",
                    )
                )
            else:
                results.append(
                    _pass(
                        "GATE-03",
                        "Duplicate Detection",
                        CheckClassification.GATE,
                        "No duplicate detected",
                        rule_type="hash",
                        source="gate",
                    )
                )
        except OSError:
            results.append(
                _warn(
                    "GATE-03",
                    "Duplicate Detection",
                    CheckClassification.GATE,
                    "Duplicate check could not be completed",
                    rule_type="hash",
                    source="gate",
                )
            )
    else:
        results.append(
            _warn(
                "GATE-03",
                "Duplicate Detection",
                CheckClassification.GATE,
                "Duplicate check skipped because file is unavailable",
                rule_type="hash",
                source="gate",
            )
        )

    return results


def _get_ps_value(prescreening_data: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = prescreening_data.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def run_rule_checks(
    doc_type: str,
    category: str,
    extracted_fields: Dict[str, Any],
    prescreening_data: Dict[str, Any],
    risk_level: str = "LOW",
) -> List[Dict[str, Any]]:
    checks = get_rule_checks_for_doc_type(doc_type, category)
    results: List[Dict[str, Any]] = []

    ef = extracted_fields or {}
    ps = prescreening_data or {}

    for check in checks:
        check_id = check["id"]
        label = check["label"]

        if check_id == "DOC-06":
            result = _check_exact_match(
                check_id,
                label,
                _get_ps_value(ps, "incorporation_number", "registration_number", "brn"),
                ef.get("registration_number") or ef.get("incorporation_number"),
                ps_field="incorporation_number",
                critical=True,
            )
            results.append(result)
            continue

        if check_id == "DOC-49A":
            result = _check_exact_match(
                check_id,
                label,
                _get_ps_value(ps, "date_of_birth", "dob"),
                ef.get("date_of_birth") or ef.get("dob"),
                ps_field="date_of_birth",
                critical=True,
            )
            results.append(result)
            continue

        if check_id == "DOC-52":
            result = _check_exact_match(
                check_id,
                label,
                _get_ps_value(ps, "nationality", "country_of_nationality"),
                ef.get("nationality") or ef.get("country"),
                ps_field="nationality",
                critical=False,
            )
            results.append(result)
            continue

        if check_id in {"DOC-56"}:
            result = _check_name_match(
                check_id,
                label,
                _get_ps_value(ps, "full_name", "person_name"),
                ef.get("full_name") or ef.get("name"),
                ps_field="full_name",
                critical=True,
            )
            results.append(result)
            continue

        if check_id in {"DOC-01", "DOC-31", "DOC-61"}:
            extracted_date = ef.get("document_date") or ef.get("issue_date") or ef.get("date")
            results.append(
                _check_date_recency(
                    check_id,
                    label,
                    extracted_date,
                    max_days=DATE_WINDOW_3_MONTHS,
                )
            )
            continue

        if check_id == "DOC-20":
            extracted_date = ef.get("financial_year_end") or ef.get("period_end") or ef.get("date")
            results.append(
                _check_date_recency(
                    check_id,
                    label,
                    extracted_date,
                    max_days=DATE_WINDOW_18_MONTHS,
                )
            )
            continue

        if check_id == "DOC-25":
            extracted_date = ef.get("resolution_date") or ef.get("date")
            results.append(
                _check_date_recency(
                    check_id,
                    label,
                    extracted_date,
                    max_days=DATE_WINDOW_12_MONTHS,
                )
            )
            continue

        if check_id in {"DOC-34", "DOC-49", "DOC-53"}:
            results.append(
                _check_not_expired(
                    check_id,
                    label,
                    ef.get("expiry_date") or ef.get("expiry") or ef.get("validity_to"),
                    warn_days=30,
                )
            )
            continue

        if check_id == "DOC-15":
            shareholders = ef.get("shareholders", [])
            if not shareholders:
                results.append(
                    _fail(
                        check_id,
                        label,
                        CheckClassification.RULE,
                        "Shareholding data could not be extracted",
                        rule_type="ownership",
                    )
                )
            else:
                results.append(
                    _pass(
                        check_id,
                        label,
                        CheckClassification.RULE,
                        f"Shareholding data extracted for {len(shareholders)} holder(s)",
                        rule_type="ownership",
                    )
                )
            continue

        if check_id == "DOC-15A":
            shareholders = ef.get("shareholders", [])
            if not shareholders:
                results.append(
                    _fail(
                        check_id,
                        label,
                        CheckClassification.RULE,
                        "Cannot validate total shares because shareholder extraction failed",
                        rule_type="percentage_sum",
                    )
                )
            else:
                total = 0.0
                valid = True
                for holder in shareholders:
                    try:
                        total += float(holder.get("percentage", 0))
                    except (TypeError, ValueError):
                        valid = False
                        break

                if not valid:
                    results.append(
                        _fail(
                            check_id,
                            label,
                            CheckClassification.RULE,
                            "Invalid shareholder percentage values detected",
                            rule_type="percentage_sum",
                        )
                    )
                elif abs(total - 100.0) <= 0.5:
                    results.append(
                        _pass(
                            check_id,
                            label,
                            CheckClassification.RULE,
                            f"Shareholdings sum to {total:.1f}%",
                            rule_type="percentage_sum",
                        )
                    )
                else:
                    results.append(
                        _fail(
                            check_id,
                            label,
                            CheckClassification.RULE,
                            f"Shareholdings sum to {total:.1f}% instead of 100%",
                            rule_type="percentage_sum",
                        )
                    )
            continue

        if check_id == "DOC-15B":
            declared_ubos = ps.get("ubos", []) or []
            extracted_holders = ef.get("shareholders", []) or []

            declared_names = []
            for ubo in declared_ubos:
                if isinstance(ubo, dict):
                    declared_names.append(_normalise_name(ubo.get("full_name", "")))
                else:
                    declared_names.append(_normalise_name(str(ubo)))

            missing_ubos: List[str] = []
            for holder in extracted_holders:
                try:
                    pct = float(holder.get("percentage", 0))
                except (TypeError, ValueError):
                    pct = 0.0
                if pct >= UBO_THRESHOLD_PCT:
                    holder_name = _normalise_name(holder.get("name", ""))
                    if not holder_name:
                        missing_ubos.append("unknown_holder")
                        continue
                    match_found = any(_name_similarity(holder_name, declared) >= 0.85 for declared in declared_names)
                    if not match_found:
                        missing_ubos.append(holder.get("name", "unknown_holder"))

            if missing_ubos:
                results.append(
                    _fail(
                        check_id,
                        label,
                        CheckClassification.RULE,
                        f"Shareholder(s) above UBO threshold not declared as UBO: {', '.join(missing_ubos)}",
                        rule_type="ubo_threshold",
                    )
                )
            else:
                results.append(
                    _pass(
                        check_id,
                        label,
                        CheckClassification.RULE,
                        "All extracted holders above threshold are declared as UBOs",
                        rule_type="ubo_threshold",
                    )
                )
            continue

        if check_id == "DOC-18":
            declared_directors = ps.get("directors", []) or []
            extracted_directors = ef.get("directors", []) or []

            declared_names = []
            for director in declared_directors:
                if isinstance(director, dict):
                    declared_names.append(_normalise_name(director.get("full_name", "")))
                else:
                    declared_names.append(_normalise_name(str(director)))

            extracted_names = []
            for director in extracted_directors:
                if isinstance(director, dict):
                    extracted_names.append(_normalise_name(director.get("name", "")))
                else:
                    extracted_names.append(_normalise_name(str(director)))

            if not extracted_names:
                results.append(
                    _fail(
                        check_id,
                        label,
                        CheckClassification.RULE,
                        "Director list could not be extracted",
                        rule_type="set_match",
                    )
                )
                continue

            missing = []
            for declared_name in declared_names:
                if not any(_name_similarity(declared_name, extracted_name) >= 0.85 for extracted_name in extracted_names):
                    missing.append(declared_name)

            if missing:
                results.append(
                    _fail(
                        check_id,
                        label,
                        CheckClassification.RULE,
                        f"Declared directors missing from extracted register: {', '.join(missing)}",
                        rule_type="set_match",
                    )
                )
            else:
                results.append(
                    _pass(
                        check_id,
                        label,
                        CheckClassification.RULE,
                        "Director completeness check passed",
                        rule_type="set_match",
                    )
                )
            continue

    return results


def run_cross_document_checks(
    extracted_fields: Dict[str, Any],
    supporting_fields: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Cross-document consistency checks.
    supporting_fields can contain fields from other already-verified documents.
    """
    results: List[Dict[str, Any]] = []
    supporting_fields = supporting_fields or {}

    if Config.REQUIRE_MATCH_ACROSS_DOCS:
        primary_name = extracted_fields.get("full_name") or extracted_fields.get("name")
        secondary_name = supporting_fields.get("full_name") or supporting_fields.get("name")
        if primary_name and secondary_name:
            similarity = _name_similarity(primary_name, secondary_name)
            if similarity >= 0.90:
                results.append(
                    _pass(
                        "XDOC-01",
                        "Cross-Document Name Match",
                        CheckClassification.RULE,
                        "Cross-document name match passed",
                        extracted_value=f"{primary_name} <-> {secondary_name}",
                        confidence=similarity,
                        rule_type="cross_document",
                    )
                )
            else:
                results.append(
                    _fail(
                        "XDOC-01",
                        "Cross-Document Name Match",
                        CheckClassification.RULE,
                        "Cross-document name mismatch detected",
                        extracted_value=f"{primary_name} <-> {secondary_name}",
                        confidence=similarity,
                        rule_type="cross_document",
                    )
                )

        primary_dob = extracted_fields.get("date_of_birth") or extracted_fields.get("dob")
        secondary_dob = supporting_fields.get("date_of_birth") or supporting_fields.get("dob")
        if primary_dob and secondary_dob:
            if _parse_date(primary_dob) == _parse_date(secondary_dob):
                results.append(
                    _pass(
                        "XDOC-02",
                        "Cross-Document DOB Match",
                        CheckClassification.RULE,
                        "Cross-document date of birth match passed",
                        extracted_value=f"{primary_dob} <-> {secondary_dob}",
                        rule_type="cross_document",
                    )
                )
            else:
                results.append(
                    _fail(
                        "XDOC-02",
                        "Cross-Document DOB Match",
                        CheckClassification.RULE,
                        "Cross-document date of birth mismatch detected",
                        extracted_value=f"{primary_dob} <-> {secondary_dob}",
                        rule_type="cross_document",
                    )
                )

    return results


def run_ai_checks(
    doc_type: str,
    extracted_fields: Dict[str, Any],
    *,
    ai_client: Any = None,
    file_name: Optional[str] = None,
    person_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Optional AI checks.
    If AI is unavailable, do not pass silently.
    Return WARNs, not PASSes.
    """
    ai_checks = get_ai_checks_for_doc_type(doc_type)
    if not ai_checks:
        return []

    if ai_client is None:
        return [
            _warn(
                "AI-00",
                "AI Verification Unavailable",
                CheckClassification.AI,
                "AI checks not executed because no AI client was provided",
                rule_type="ai",
                source="ai",
            )
        ]

    try:
        result = ai_client.verify_document(doc_type=doc_type, file_name=file_name, person_name=person_name)
    except Exception as exc:
        return [
            _warn(
                "AI-00",
                "AI Verification Error",
                CheckClassification.AI,
                f"AI checks failed to execute: {exc}",
                rule_type="ai",
                source="ai",
            )
        ]

    checks = result.get("checks", [])
    if not checks:
        return [
            _warn(
                "AI-00",
                "AI Verification Empty",
                CheckClassification.AI,
                "AI returned no checks",
                rule_type="ai",
                source="ai",
            )
        ]

    normalized: List[Dict[str, Any]] = []
    for check in checks:
        normalized.append(
            {
                "id": check.get("id", "AI-UNKNOWN"),
                "label": check.get("label", "AI Check"),
                "classification": check.get("classification", CheckClassification.AI),
                "type": check.get("type", "ai"),
                "result": check.get("result", CheckStatus.WARN),
                "message": check.get("message", "AI returned no message"),
                "source": check.get("source", "ai"),
                "confidence": check.get("confidence"),
            }
        )
    return normalized


def aggregate_results(checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Conservative aggregation:
    - any FAIL => flagged
    - no checks => flagged
    - WARN-heavy or low-confidence => flagged
    - only clean PASS => verified
    """
    if not checks:
        return {
            "checks": [],
            "overall": "flagged",
            "confidence": 0.0,
            "red_flags": ["No verification checks were executed"],
            "engine_version": "clean_v1",
        }

    fail_count = sum(1 for check in checks if check.get("result") == CheckStatus.FAIL)
    warn_count = sum(1 for check in checks if check.get("result") == CheckStatus.WARN)
    pass_count = sum(1 for check in checks if check.get("result") == CheckStatus.PASS)

    confidences = [
        float(check["confidence"])
        for check in checks
        if check.get("confidence") is not None
        and isinstance(check.get("confidence"), (float, int))
    ]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

    red_flags = [check["message"] for check in checks if check.get("result") in {CheckStatus.FAIL, CheckStatus.WARN}]

    overall = "verified"
    if fail_count > 0:
        overall = "flagged"
    elif warn_count > 0 and Config.FAIL_ON_UNCERTAINTY:
        overall = "flagged"
    elif avg_confidence and avg_confidence < Config.MIN_CONFIDENCE_SCORE:
        overall = "flagged"
    elif pass_count == 0:
        overall = "flagged"

    return {
        "checks": checks,
        "overall": overall,
        "confidence": round(avg_confidence, 3),
        "red_flags": red_flags,
        "engine_version": "clean_v1",
    }


def to_legacy_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compatibility helper if old server flow expects legacy keys.
    """
    return {
        "checks": result.get("checks", []),
        "overall": result.get("overall", "flagged"),
        "confidence": result.get("confidence", 0.0),
        "red_flags": result.get("red_flags", []),
        "engine_version": result.get("engine_version", "clean_v1"),
    }


def verify_document_layered(
    *,
    doc_type: str,
    category: str,
    file_path: str,
    file_size: int,
    mime_type: str,
    prescreening_data: Optional[Dict[str, Any]] = None,
    extracted_fields: Optional[Dict[str, Any]] = None,
    supporting_fields: Optional[Dict[str, Any]] = None,
    existing_hashes: Optional[List[str]] = None,
    ai_client: Any = None,
    file_name: Optional[str] = None,
    person_name: Optional[str] = None,
    risk_level: str = "LOW",
) -> Dict[str, Any]:
    """
    Main layered verification entry point.
    """
    prescreening_data = prescreening_data or {}
    extracted_fields = extracted_fields or {}
    supporting_fields = supporting_fields or {}
    existing_hashes = existing_hashes or []

    checks: List[Dict[str, Any]] = []

    # Layer 0 - gate checks
    gate_results = run_gate_checks(file_path, file_size, mime_type, existing_hashes)
    checks.extend(gate_results)

    if any(check["result"] == CheckStatus.FAIL for check in gate_results):
        return aggregate_results(checks)

    # Hard confidence gates for important extracted fields
    critical_fields = [
        "full_name",
        "name",
        "date_of_birth",
        "dob",
        "registration_number",
        "incorporation_number",
    ]
    seen_confidence_gate = False
    for field_name in critical_fields:
        if field_name in extracted_fields:
            seen_confidence_gate = True
            confidence = _extract_confidence(extracted_fields, field_name, 0.0)
            gated = _confidence_gate(field_name, confidence, critical=True)
            if gated:
                checks.append(gated)

    if not seen_confidence_gate and extracted_fields:
        checks.append(
            _warn(
                "CONF-02",
                "Extraction Confidence Missing",
                CheckClassification.RULE,
                "Extracted fields were provided without field-level confidence metadata",
                rule_type="confidence",
            )
        )

    # Layer 1 - deterministic rules
    rule_results = run_rule_checks(
        doc_type=doc_type,
        category=category,
        extracted_fields=extracted_fields,
        prescreening_data=prescreening_data,
        risk_level=risk_level,
    )
    checks.extend(rule_results)

    # Layer 2 - cross-document consistency
    cross_doc_results = run_cross_document_checks(extracted_fields, supporting_fields)
    checks.extend(cross_doc_results)

    # Layer 3 - optional AI
    ai_results = run_ai_checks(
        doc_type=doc_type,
        extracted_fields=extracted_fields,
        ai_client=ai_client,
        file_name=file_name,
        person_name=person_name,
    )
    checks.extend(ai_results)

    return aggregate_results(checks)
