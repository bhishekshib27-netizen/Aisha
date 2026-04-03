"""
Onboarda - Clean Validation Engine

Purpose:
- validate application data before AI/rule processing
- validate generated compliance memos
- generate a conservative fallback memo when AI or memo generation fails

Design rules:
- fail early on missing critical fields
- reject weak or contradictory memos
- fallback memo must never silently approve
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


def generate_fallback_memo(application: Dict[str, Any] | None = None) -> Dict[str, Any]:
    app = application or {}
    company = app.get("company_name", "Unknown Company")
    country = app.get("country", "Unknown")
    sector = app.get("sector", "Unknown")
    risk_level = app.get("risk_level", "MEDIUM")

    return {
        "sections": {
            "executive_summary": {
                "content": f"Compliance memo for {company} could not be generated reliably. Manual review is required."
            },
            "client_overview": {
                "content": f"{company} operating in {sector}, domiciled in {country}."
            },
            "ownership_and_control": {
                "content": "Ownership and control could not be validated automatically.",
                "structure_complexity": "Unknown",
                "control_statement": "Not determined - manual review required.",
            },
            "risk_assessment": {
                "content": "Automated risk assessment incomplete.",
                "sub_sections": {
                    "jurisdiction_risk": {"rating": "MEDIUM", "content": "Not fully assessed."},
                    "business_risk": {"rating": "MEDIUM", "content": "Not fully assessed."},
                    "transaction_risk": {"rating": "MEDIUM", "content": "Not fully assessed."},
                    "ownership_risk": {"rating": "MEDIUM", "content": "Not fully assessed."},
                    "financial_crime_risk": {"rating": "MEDIUM", "content": "Not fully assessed."},
                },
            },
            "screening_results": {
                "content": "Screening output unavailable or incomplete - manual screening required."
            },
            "document_verification": {
                "content": "Document verification incomplete - manual review required."
            },
            "ai_explainability": {
                "content": "AI pipeline unavailable or insufficient for a reliable memo."
            },
            "red_flags_and_mitigants": {
                "red_flags": [
                    "Automated memo generation failed",
                    "Manual review is required before any decision",
                ],
                "mitigants": [
                    "Fallback memo created to preserve audit trail",
                    "Escalate to human compliance review",
                ],
            },
            "compliance_decision": {
                "decision": "REVIEW",
                "content": "Automatic approval is not permitted. Escalate to manual compliance review."
            },
            "ongoing_monitoring": {
                "content": "Monitoring plan cannot be finalized until manual review is complete."
            },
            "audit_and_governance": {
                "content": "Fallback memo generated. Full manual review required before onboarding decision."
            },
        },
        "metadata": {
            "risk_rating": risk_level,
            "risk_score": 50,
            "approval_recommendation": "REVIEW",
            "confidence_level": 0.0,
            "is_fallback": True,
            "fallback_reason": "memo_generation_failure",
        },
    }


def pre_validate_application(application_data: Dict[str, Any] | None) -> Tuple[bool, List[Dict[str, str]]]:
    """
    Validate required fields before entering downstream processing.
    """
    if application_data is None:
        return False, [{"field": "application", "error": "Application data is missing"}]

    errors: List[Dict[str, str]] = []

    required_fields = [
        "company_name",
        "country",
        "sector",
        "entity_type",
    ]

    for field in required_fields:
        value = application_data.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append({"field": field, "error": f"Required field '{field}' is missing or empty"})

    company_name = application_data.get("company_name")
    if company_name is not None and not isinstance(company_name, str):
        errors.append({"field": "company_name", "error": "Company name must be a string"})

    country = application_data.get("country")
    if country is not None and not isinstance(country, str):
        errors.append({"field": "country", "error": "Country must be a string"})

    sector = application_data.get("sector")
    if sector is not None and not isinstance(sector, str):
        errors.append({"field": "sector", "error": "Sector must be a string"})

    entity_type = application_data.get("entity_type")
    if entity_type is not None and not isinstance(entity_type, str):
        errors.append({"field": "entity_type", "error": "Entity type must be a string"})

    return len(errors) == 0, errors


def validate_compliance_memo(memo_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Conservative memo validation.

    Returns:
    {
      "validation_status": "pass" | "pass_with_fixes" | "fail",
      "quality_score": float,
      "issues": [...],
      "summary": str
    }
    """
    issues: List[Dict[str, str]] = []
    scores: Dict[str, float] = {}

    sections = memo_data.get("sections") or {}
    metadata = memo_data.get("metadata") or {}

    required_sections = [
        "executive_summary",
        "client_overview",
        "ownership_and_control",
        "risk_assessment",
        "screening_results",
        "document_verification",
        "ai_explainability",
        "red_flags_and_mitigants",
        "compliance_decision",
        "ongoing_monitoring",
        "audit_and_governance",
    ]

    missing_sections = [section for section in required_sections if section not in sections]
    if missing_sections:
        issues.append({
            "category": "structure",
            "severity": "critical",
            "description": f"Missing required sections: {', '.join(missing_sections)}",
            "fix": "Regenerate memo with all required sections.",
        })
        scores["structure"] = 0.0
    else:
        scores["structure"] = 2.0

    risk_rating = metadata.get("risk_rating", "")
    risk_score = metadata.get("risk_score", 0)
    decision_section = sections.get("compliance_decision", {}) or {}
    decision = decision_section.get("decision") or metadata.get("approval_recommendation", "")

    # Decision alignment
    if risk_rating == "LOW" and decision in {"REJECT"}:
        issues.append({
            "category": "decision_alignment",
            "severity": "critical",
            "description": "LOW risk memo recommends REJECT without clear justification.",
            "fix": "Align decision with stated risk profile or explain rejection explicitly.",
        })
        scores["decision_alignment"] = 0.0
    elif risk_rating in {"HIGH", "VERY_HIGH"} and decision in {"APPROVE"}:
        issues.append({
            "category": "decision_alignment",
            "severity": "critical",
            "description": "HIGH/VERY_HIGH risk memo recommends unconditional APPROVE.",
            "fix": "Use REVIEW or APPROVE_WITH_CONDITIONS with explicit controls.",
        })
        scores["decision_alignment"] = 0.0
    else:
        scores["decision_alignment"] = 2.0

    # Ownership quality
    ownership = sections.get("ownership_and_control", {}) or {}
    ownership_content = str(ownership.get("content", ""))
    control_statement = str(ownership.get("control_statement", ""))
    structure_complexity = str(ownership.get("structure_complexity", ""))

    ownership_score = 0.0
    if structure_complexity:
        ownership_score += 0.5
    else:
        issues.append({
            "category": "ownership",
            "severity": "warning",
            "description": "Structure complexity missing.",
            "fix": "Add structure_complexity.",
        })

    if control_statement:
        ownership_score += 0.75
    else:
        issues.append({
            "category": "ownership",
            "severity": "critical",
            "description": "Control statement missing.",
            "fix": "Specify who exercises effective control.",
        })

    if "%" in ownership_content or "ownership" in ownership_content.lower():
        ownership_score += 0.75
    else:
        issues.append({
            "category": "ownership",
            "severity": "critical",
            "description": "Ownership percentages or clear ownership detail missing.",
            "fix": "State ownership percentages or clearly identify missing ownership evidence.",
        })

    scores["ownership"] = ownership_score

    # Screening defensibility
    screening = sections.get("screening_results", {}) or {}
    screening_content = str(screening.get("content", ""))

    screening_score = 0.0
    if screening_content:
        screening_score += 0.5
    else:
        issues.append({
            "category": "screening",
            "severity": "critical",
            "description": "Screening section is empty.",
            "fix": "Include sanctions / PEP / adverse media outcomes.",
        })

    if any(provider in screening_content for provider in ["OpenSanctions", "World-Check", "Dow Jones", "screening"]):
        screening_score += 0.5
    else:
        issues.append({
            "category": "screening",
            "severity": "warning",
            "description": "Screening source/provider not clearly identified.",
            "fix": "Reference the screening source or engine.",
        })

    scores["screening"] = screening_score

    # Document verification adequacy
    docs = sections.get("document_verification", {}) or {}
    docs_content = str(docs.get("content", ""))

    if docs_content:
        if any(word in docs_content.lower() for word in ["verified", "mismatch", "discrep", "consisten", "missing"]):
            scores["documents"] = 1.5
        else:
            scores["documents"] = 0.75
            issues.append({
                "category": "documents",
                "severity": "warning",
                "description": "Document verification section lacks clear assessment language.",
                "fix": "State whether documents were verified, missing, or inconsistent.",
            })
    else:
        scores["documents"] = 0.0
        issues.append({
            "category": "documents",
            "severity": "critical",
            "description": "Document verification section is empty.",
            "fix": "Add document verification findings.",
        })

    # Red flags and mitigants
    rf = sections.get("red_flags_and_mitigants", {}) or {}
    red_flags = rf.get("red_flags", []) or []
    mitigants = rf.get("mitigants", []) or []

    rf_score = 0.0
    if len(red_flags) >= 1:
        rf_score += 0.75
    else:
        issues.append({
            "category": "red_flags",
            "severity": "critical",
            "description": "No red flags documented.",
            "fix": "Document at least one residual or identified risk.",
        })

    if len(mitigants) >= 1:
        rf_score += 0.75
    else:
        issues.append({
            "category": "red_flags",
            "severity": "warning",
            "description": "No mitigants documented.",
            "fix": "Document at least one mitigating control or follow-up action.",
        })

    scores["red_flags"] = rf_score

    # Explainability
    explainability = sections.get("ai_explainability", {}) or {}
    explainability_content = str(explainability.get("content", ""))
    confidence_level = metadata.get("confidence_level", 0)

    explainability_score = 0.0
    if explainability_content:
        explainability_score += 0.75
    else:
        issues.append({
            "category": "explainability",
            "severity": "warning",
            "description": "AI explainability section is empty.",
            "fix": "Add reasoning or explainability narrative.",
        })

    try:
        confidence_value = float(confidence_level)
        if confidence_value > 0:
            explainability_score += 0.75
        else:
            issues.append({
                "category": "explainability",
                "severity": "warning",
                "description": "Confidence level missing or zero.",
                "fix": "Add confidence_level to metadata.",
            })
    except (TypeError, ValueError):
        issues.append({
            "category": "explainability",
            "severity": "warning",
            "description": "Confidence level invalid.",
            "fix": "Use a numeric confidence_level between 0 and 1.",
        })

    scores["explainability"] = explainability_score

    # Final score
    total_possible = 10.0
    achieved = sum(scores.values())
    quality_score = round(min(10.0, achieved), 2)

    critical_issues = [issue for issue in issues if issue["severity"] == "critical"]
    warning_issues = [issue for issue in issues if issue["severity"] == "warning"]

    if critical_issues:
        validation_status = "fail"
        summary = f"Memo failed validation with {len(critical_issues)} critical issue(s)."
    elif warning_issues:
        validation_status = "pass_with_fixes"
        summary = f"Memo passed with fixes required ({len(warning_issues)} warning issue(s))."
    else:
        validation_status = "pass"
        summary = "Memo passed validation."

    return {
        "validation_status": validation_status,
        "quality_score": quality_score,
        "issues": issues,
        "summary": summary,
    }
