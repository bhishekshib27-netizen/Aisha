"""
Onboarda - Clean Rule Engine

Purpose:
- deterministic risk scoring
- jurisdiction / sector / structural risk logic
- no AI dependency
- predictable and auditable outputs
"""

from __future__ import annotations

from typing import Any, Dict, List

# ─────────────────────────────
# Country / jurisdiction buckets
# ─────────────────────────────
FATF_BLACK = {
    "iran",
    "north korea",
    "democratic people's republic of korea",
}

FATF_GREY = {
    "south africa",
    "nigeria",
    "kenya",
    "syria",
    "myanmar",
    "monaco",
    "venezuela",
    "burkina faso",
    "croatia",
    "cameroon",
    "haiti",
    "mali",
    "philippines",
    "south sudan",
    "tanzania",
    "vietnam",
    "yemen",
}

SANCTIONED = {
    "iran",
    "north korea",
    "syria",
    "russia",
    "belarus",
}

SANCTIONED_COUNTRIES_FULL = SANCTIONED.copy()

LOW_RISK = {
    "united kingdom",
    "uk",
    "singapore",
    "germany",
    "france",
    "netherlands",
    "switzerland",
    "canada",
    "australia",
    "new zealand",
    "luxembourg",
}

HIGH_RISK_COUNTRIES = FATF_BLACK | FATF_GREY | SANCTIONED

# ─────────────────────────────
# Sector scoring
# ─────────────────────────────
SECTOR_SCORES = {
    "financial services": 18,
    "banking": 20,
    "payment services": 20,
    "investment": 18,
    "fund administration": 17,
    "gaming": 19,
    "crypto": 22,
    "real estate": 14,
    "construction": 10,
    "retail": 7,
    "consulting": 8,
    "technology": 8,
    "manufacturing": 9,
    "logistics": 10,
    "corporate services": 16,
    "trust services": 18,
    "insurance": 15,
}

HIGH_RISK_SECTORS = {
    "crypto",
    "payment services",
    "banking",
    "gaming",
    "trust services",
}

MEDIUM_RISK_SECTORS = {
    "financial services",
    "investment",
    "fund administration",
    "corporate services",
    "insurance",
    "real estate",
}

MINIMUM_MEDIUM_SECTORS = MEDIUM_RISK_SECTORS.copy()

# ─────────────────────────────
# Misc rules
# ─────────────────────────────
ALLOWED_CURRENCIES = {
    "USD", "EUR", "GBP", "CHF", "SGD", "AED", "MUR"
}

ALWAYS_RISK_INCREASING = {
    "pep_match",
    "sanctions_match",
    "ubo_missing",
    "high_risk_jurisdiction",
    "complex_structure",
}

ALWAYS_RISK_DECREASING = {
    "clean_screening",
    "simple_structure",
    "verified_ubo",
    "low_risk_jurisdiction",
}

RISK_WEIGHTS = {
    "jurisdiction": 0.25,
    "sector": 0.20,
    "ownership": 0.20,
    "screening": 0.20,
    "documents": 0.15,
}

RISK_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "VERY_HIGH": 4,
}


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def classify_country(country: str) -> Dict[str, Any]:
    """
    Return deterministic country classification.
    """
    c = _norm(country)

    if not c:
        return {
            "bucket": "UNKNOWN",
            "score": 12,
            "reason": "Country not provided",
        }

    if c in FATF_BLACK:
        return {
            "bucket": "FATF_BLACK",
            "score": 30,
            "reason": "Country is on FATF black list",
        }

    if c in SANCTIONED:
        return {
            "bucket": "SANCTIONED",
            "score": 28,
            "reason": "Country is sanctioned or highly restricted",
        }

    if c in FATF_GREY:
        return {
            "bucket": "FATF_GREY",
            "score": 22,
            "reason": "Country is on FATF grey list",
        }

    if c in LOW_RISK:
        return {
            "bucket": "LOW_RISK",
            "score": 4,
            "reason": "Country is treated as low-risk jurisdiction",
        }

    return {
        "bucket": "STANDARD",
        "score": 10,
        "reason": "Country has standard baseline jurisdiction risk",
    }


def score_sector(sector: str) -> Dict[str, Any]:
    """
    Return deterministic sector score.
    """
    s = _norm(sector)

    if not s:
        return {
            "bucket": "UNKNOWN",
            "score": 10,
            "reason": "Sector not provided",
        }

    score = SECTOR_SCORES.get(s, 10)

    if s in HIGH_RISK_SECTORS:
        bucket = "HIGH_RISK"
    elif s in MEDIUM_RISK_SECTORS:
        bucket = "MEDIUM_RISK"
    else:
        bucket = "STANDARD"

    return {
        "bucket": bucket,
        "score": score,
        "reason": f"Sector '{sector}' scored deterministically",
    }


def _score_ownership(
    directors: List[dict] | None,
    ubos: List[dict] | None,
    intermediaries: List[dict] | None,
) -> Dict[str, Any]:
    directors = directors or []
    ubos = ubos or []
    intermediaries = intermediaries or []

    score = 6
    factors: List[str] = []

    if not ubos:
        score += 18
        factors.append("No UBOs declared")
    else:
        factors.append("UBOs declared")

    if intermediaries:
        score += min(12, len(intermediaries) * 4)
        factors.append("Intermediary or layered structure present")

    if len(ubos) > 3:
        score += 6
        factors.append("Multiple UBOs increase complexity")

    if len(directors) == 0:
        score += 8
        factors.append("No directors declared")

    if len(directors) > 5:
        score += 4
        factors.append("Large board adds structural complexity")

    if score <= 8:
        bucket = "LOW"
    elif score <= 16:
        bucket = "MEDIUM"
    elif score <= 24:
        bucket = "HIGH"
    else:
        bucket = "VERY_HIGH"

    return {
        "bucket": bucket,
        "score": min(score, 30),
        "reason": "; ".join(factors) if factors else "Ownership structure assessed",
        "factors": factors,
    }


def _score_screening(application: Dict[str, Any], prescreening_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Use screening report if present. Conservative if missing.
    """
    screening = (prescreening_data or {}).get("screening_report", {}) or {}
    total_hits = int(screening.get("total_hits", 0) or 0)
    flags = screening.get("overall_flags", []) or []

    score = 5
    factors: List[str] = []

    if total_hits > 0:
        score += min(20, total_hits * 6)
        factors.append(f"{total_hits} screening hit(s) detected")
    else:
        factors.append("No screening hits detected")

    if flags:
        score += min(8, len(flags) * 2)
        factors.append("Screening flags present")

    if screening:
        factors.append("Screening report available")
    else:
        score += 6
        factors.append("No screening report available")

    if score <= 8:
        bucket = "LOW"
    elif score <= 16:
        bucket = "MEDIUM"
    elif score <= 24:
        bucket = "HIGH"
    else:
        bucket = "VERY_HIGH"

    return {
        "bucket": bucket,
        "score": min(score, 30),
        "reason": "; ".join(factors),
        "factors": factors,
    }


def _score_documents(application: Dict[str, Any], prescreening_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Conservative baseline for document completeness.
    If no document summary exists, do not give a free pass.
    """
    docs_summary = (prescreening_data or {}).get("document_summary", {}) or {}
    missing_count = int(docs_summary.get("missing_count", 0) or 0)
    mismatch_count = int(docs_summary.get("mismatch_count", 0) or 0)
    verified_count = int(docs_summary.get("verified_count", 0) or 0)

    score = 8
    factors: List[str] = []

    if verified_count > 0:
        score -= min(4, verified_count)
        factors.append(f"{verified_count} verified document(s)")
    else:
        factors.append("No verified documents recorded")

    if missing_count > 0:
        score += min(10, missing_count * 3)
        factors.append(f"{missing_count} missing document(s)")

    if mismatch_count > 0:
        score += min(10, mismatch_count * 4)
        factors.append(f"{mismatch_count} document mismatch(es)")

    if not docs_summary:
        score += 4
        factors.append("No document summary available")

    score = max(3, min(score, 30))

    if score <= 8:
        bucket = "LOW"
    elif score <= 16:
        bucket = "MEDIUM"
    elif score <= 24:
        bucket = "HIGH"
    else:
        bucket = "VERY_HIGH"

    return {
        "bucket": bucket,
        "score": score,
        "reason": "; ".join(factors),
        "factors": factors,
    }


def compute_risk_score(scoring_input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main deterministic risk scoring function.

    Expected scoring_input may contain:
    - application
    - prescreening_data
    - directors
    - ubos
    - intermediaries
    """
    application = scoring_input.get("application", {}) or {}
    prescreening_data = scoring_input.get("prescreening_data", {}) or {}
    directors = scoring_input.get("directors", []) or []
    ubos = scoring_input.get("ubos", []) or []
    intermediaries = scoring_input.get("intermediaries", []) or []

    country_value = (
        application.get("country")
        or prescreening_data.get("country")
        or prescreening_data.get("country_of_incorporation")
        or ""
    )
    sector_value = application.get("sector") or prescreening_data.get("sector") or ""

    jurisdiction = classify_country(country_value)
    sector = score_sector(sector_value)
    ownership = _score_ownership(directors, ubos, intermediaries)
    screening = _score_screening(application, prescreening_data)
    documents = _score_documents(application, prescreening_data)

    weighted_score = (
        jurisdiction["score"] * RISK_WEIGHTS["jurisdiction"]
        + sector["score"] * RISK_WEIGHTS["sector"]
        + ownership["score"] * RISK_WEIGHTS["ownership"]
        + screening["score"] * RISK_WEIGHTS["screening"]
        + documents["score"] * RISK_WEIGHTS["documents"]
    )

    # stretch to 0-100 style score
    final_score = round(min(100, max(0, weighted_score * 4)))

    if final_score >= 85:
        level = "VERY_HIGH"
        lane = "Enhanced Due Diligence"
    elif final_score >= 70:
        level = "HIGH"
        lane = "Enhanced Review"
    elif final_score >= 40:
        level = "MEDIUM"
        lane = "Standard Review"
    else:
        level = "LOW"
        lane = "Fast Track"

    dimensions = {
        "jurisdiction_risk": {
            "score": jurisdiction["score"],
            "bucket": jurisdiction["bucket"],
            "reason": jurisdiction["reason"],
        },
        "sector_risk": {
            "score": sector["score"],
            "bucket": sector["bucket"],
            "reason": sector["reason"],
        },
        "ownership_risk": {
            "score": ownership["score"],
            "bucket": ownership["bucket"],
            "reason": ownership["reason"],
            "factors": ownership["factors"],
        },
        "screening_risk": {
            "score": screening["score"],
            "bucket": screening["bucket"],
            "reason": screening["reason"],
            "factors": screening["factors"],
        },
        "document_risk": {
            "score": documents["score"],
            "bucket": documents["bucket"],
            "reason": documents["reason"],
            "factors": documents["factors"],
        },
    }

    flags: List[str] = []

    if jurisdiction["bucket"] in {"FATF_BLACK", "SANCTIONED", "FATF_GREY"}:
        flags.append(f"Jurisdiction risk: {jurisdiction['bucket']}")

    if sector["bucket"] == "HIGH_RISK":
        flags.append("High-risk sector")

    if ownership["bucket"] in {"HIGH", "VERY_HIGH"}:
        flags.append("Complex ownership / UBO profile")

    if screening["bucket"] in {"HIGH", "VERY_HIGH"}:
        flags.append("Screening risk elevated")

    if documents["bucket"] in {"HIGH", "VERY_HIGH"}:
        flags.append("Document quality / completeness concerns")

    return {
        "score": final_score,
        "level": level,
        "lane": lane,
        "dimensions": dimensions,
        "flags": flags,
    }
