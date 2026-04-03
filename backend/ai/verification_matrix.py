"""
Onboarda - Verification Matrix
Single source of truth for document checks.

This module defines:
- check classifications
- check statuses
- supported document categories
- rule-based and AI-assisted check selection
- applicability logic

It is intentionally strict:
AI can assist interpretation, but the matrix decides what must be checked.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class CheckClassification(str, Enum):
    GATE = "gate"
    RULE = "rule"
    HYBRID = "hybrid"
    AI = "ai"


class CheckStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


class TriggerTiming(str, Enum):
    UPLOAD = "upload"
    REVIEW = "review"
    BOTH = "both"


class EscalationOutcome(str, Enum):
    NONE = "none"
    REVIEW = "review"
    BLOCK = "block"


class PSField(str, Enum):
    COMPANY_NAME = "company_name"
    INCORPORATION_NUMBER = "incorporation_number"
    PERSON_FULL_NAME = "full_name"
    PERSON_DOB = "date_of_birth"
    PERSON_NATIONALITY = "nationality"
    DIRECTORS = "directors"
    SHAREHOLDERS = "shareholders"
    UBOS = "ubos"
    COUNTRY = "country"
    ENTITY_TYPE = "entity_type"
    SOURCE_OF_FUNDS = "source_of_funds"


@dataclass(frozen=True)
class VerificationCheck:
    id: str
    label: str
    classification: CheckClassification
    rule_type: str
    trigger_timing: TriggerTiming = TriggerTiming.BOTH
    escalation_on_fail: EscalationOutcome = EscalationOutcome.REVIEW
    escalation_on_warn: EscalationOutcome = EscalationOutcome.NONE
    ps_field: Optional[PSField] = None
    required: bool = True
    description: str = ""


# ─────────────────────────────
# Gate checks
# ─────────────────────────────
GATE_CHECKS: List[VerificationCheck] = [
    VerificationCheck(
        id="GATE-01",
        label="File Format",
        classification=CheckClassification.GATE,
        rule_type="enum",
        escalation_on_fail=EscalationOutcome.BLOCK,
        description="Allow only supported file types and magic bytes.",
    ),
    VerificationCheck(
        id="GATE-02",
        label="File Size",
        classification=CheckClassification.GATE,
        rule_type="numeric",
        escalation_on_fail=EscalationOutcome.BLOCK,
        description="Reject oversized files.",
    ),
    VerificationCheck(
        id="GATE-03",
        label="Duplicate Detection",
        classification=CheckClassification.GATE,
        rule_type="hash",
        escalation_on_fail=EscalationOutcome.REVIEW,
        escalation_on_warn=EscalationOutcome.REVIEW,
        description="Detect duplicate uploads within the same application.",
    ),
]

# ─────────────────────────────
# Core deterministic checks
# ─────────────────────────────
SECTION_A_CHECKS: List[VerificationCheck] = [
    VerificationCheck(
        id="DOC-01",
        label="Document Date Recency",
        classification=CheckClassification.RULE,
        rule_type="date",
        escalation_on_fail=EscalationOutcome.REVIEW,
    ),
    VerificationCheck(
        id="DOC-06",
        label="Registration Number Match",
        classification=CheckClassification.RULE,
        rule_type="exact_match",
        ps_field=PSField.INCORPORATION_NUMBER,
        escalation_on_fail=EscalationOutcome.BLOCK,
    ),
    VerificationCheck(
        id="DOC-15",
        label="Shareholding Percentages Match",
        classification=CheckClassification.RULE,
        rule_type="ownership",
        ps_field=PSField.SHAREHOLDERS,
        escalation_on_fail=EscalationOutcome.REVIEW,
    ),
    VerificationCheck(
        id="DOC-15A",
        label="Total Shares Sum To 100%",
        classification=CheckClassification.RULE,
        rule_type="percentage_sum",
        escalation_on_fail=EscalationOutcome.BLOCK,
    ),
    VerificationCheck(
        id="DOC-15B",
        label="UBO Identification Threshold",
        classification=CheckClassification.RULE,
        rule_type="ubo_threshold",
        ps_field=PSField.UBOS,
        escalation_on_fail=EscalationOutcome.BLOCK,
    ),
    VerificationCheck(
        id="DOC-18",
        label="Director Completeness",
        classification=CheckClassification.RULE,
        rule_type="set_match",
        ps_field=PSField.DIRECTORS,
        escalation_on_fail=EscalationOutcome.REVIEW,
    ),
    VerificationCheck(
        id="DOC-20",
        label="Financial Period Recency",
        classification=CheckClassification.RULE,
        rule_type="date",
        escalation_on_fail=EscalationOutcome.REVIEW,
    ),
    VerificationCheck(
        id="DOC-25",
        label="Resolution Date Validity",
        classification=CheckClassification.RULE,
        rule_type="date",
        escalation_on_fail=EscalationOutcome.REVIEW,
    ),
    VerificationCheck(
        id="DOC-31",
        label="Proof of Address Recency",
        classification=CheckClassification.RULE,
        rule_type="date",
        escalation_on_fail=EscalationOutcome.REVIEW,
    ),
    VerificationCheck(
        id="DOC-34",
        label="Licence Expiry Check",
        classification=CheckClassification.RULE,
        rule_type="date",
        escalation_on_fail=EscalationOutcome.BLOCK,
    ),
]

SECTION_B_CHECKS: List[VerificationCheck] = [
    VerificationCheck(
        id="DOC-49",
        label="Passport Expiry Check",
        classification=CheckClassification.RULE,
        rule_type="date",
        escalation_on_fail=EscalationOutcome.BLOCK,
    ),
    VerificationCheck(
        id="DOC-49A",
        label="Date of Birth Match",
        classification=CheckClassification.RULE,
        rule_type="exact_match",
        ps_field=PSField.PERSON_DOB,
        escalation_on_fail=EscalationOutcome.BLOCK,
    ),
    VerificationCheck(
        id="DOC-52",
        label="Nationality Match",
        classification=CheckClassification.RULE,
        rule_type="exact_match",
        ps_field=PSField.PERSON_NATIONALITY,
        escalation_on_fail=EscalationOutcome.REVIEW,
    ),
    VerificationCheck(
        id="DOC-53",
        label="National ID Expiry Check",
        classification=CheckClassification.RULE,
        rule_type="date",
        escalation_on_fail=EscalationOutcome.BLOCK,
    ),
    VerificationCheck(
        id="DOC-56",
        label="Person Name Match",
        classification=CheckClassification.RULE,
        rule_type="name",
        ps_field=PSField.PERSON_FULL_NAME,
        escalation_on_fail=EscalationOutcome.BLOCK,
        escalation_on_warn=EscalationOutcome.REVIEW,
    ),
    VerificationCheck(
        id="DOC-61",
        label="Address Document Date Recency",
        classification=CheckClassification.RULE,
        rule_type="date",
        escalation_on_fail=EscalationOutcome.REVIEW,
    ),
    VerificationCheck(
        id="DOC-65",
        label="Bank Statement Recency",
        classification=CheckClassification.RULE,
        rule_type="date",
        escalation_on_fail=EscalationOutcome.REVIEW,
    ),
]

# ─────────────────────────────
# AI / Hybrid checks
# ─────────────────────────────
AI_ONLY_CHECKS: List[VerificationCheck] = [
    VerificationCheck(
        id="AI-01",
        label="Tampering Indicators",
        classification=CheckClassification.AI,
        rule_type="tamper_detection",
        escalation_on_fail=EscalationOutcome.REVIEW,
        escalation_on_warn=EscalationOutcome.REVIEW,
        description="Look for visual or semantic tampering indicators.",
    ),
    VerificationCheck(
        id="AI-02",
        label="Document Authenticity Suspicion",
        classification=CheckClassification.AI,
        rule_type="authenticity",
        escalation_on_fail=EscalationOutcome.REVIEW,
        escalation_on_warn=EscalationOutcome.REVIEW,
        description="AI may flag suspicion, but never makes final authenticity decisions alone.",
    ),
    VerificationCheck(
        id="AI-03",
        label="Cross-Field Semantic Consistency",
        classification=CheckClassification.HYBRID,
        rule_type="semantic_consistency",
        escalation_on_fail=EscalationOutcome.REVIEW,
        escalation_on_warn=EscalationOutcome.REVIEW,
    ),
]

ALL_DOC_CHECKS: List[VerificationCheck] = (
    GATE_CHECKS + SECTION_A_CHECKS + SECTION_B_CHECKS + AI_ONLY_CHECKS
)

# ─────────────────────────────
# Document type mapping
# ─────────────────────────────
DOC_TYPE_TO_CHECK_IDS: Dict[str, List[str]] = {
    # Corporate docs
    "cert_inc": ["DOC-06"],
    "memarts": [],
    "reg_sh": ["DOC-15", "DOC-15A", "DOC-15B"],
    "reg_dir": ["DOC-18"],
    "fin_stmt": ["DOC-20"],
    "board_res": ["DOC-25"],
    "licence": ["DOC-34"],

    # Personal docs
    "passport": ["DOC-49", "DOC-49A", "DOC-52", "DOC-56"],
    "national_id": ["DOC-53", "DOC-49A", "DOC-52", "DOC-56"],
    "poa": ["DOC-31", "DOC-61"],
    "bank_statements": ["DOC-65"],

    # Ownership / support docs
    "structure_chart": [],
    "source_wealth": [],
    "source_funds": [],
    "bankref": [],
    "contracts": [],
    "aml_policy": [],
}

AI_DOC_TYPE_TO_CHECK_IDS: Dict[str, List[str]] = {
    "cert_inc": ["AI-01", "AI-03"],
    "reg_sh": ["AI-03"],
    "reg_dir": ["AI-03"],
    "passport": ["AI-01", "AI-02", "AI-03"],
    "national_id": ["AI-01", "AI-02", "AI-03"],
    "poa": ["AI-01", "AI-03"],
    "licence": ["AI-01", "AI-02", "AI-03"],
}

# ─────────────────────────────
# Helpers
# ─────────────────────────────
_CHECK_INDEX: Dict[str, VerificationCheck] = {c.id: c for c in ALL_DOC_CHECKS}


def get_check_by_id(check_id: str) -> Optional[VerificationCheck]:
    return _CHECK_INDEX.get(check_id)


def get_checks_for_doc_type(doc_type: str, category: Optional[str] = None) -> List[dict]:
    """
    Returns all checks for a document type, including gates.
    Output is list[dict] for compatibility with existing engine code.
    """
    check_ids = DOC_TYPE_TO_CHECK_IDS.get(doc_type, [])
    checks = list(GATE_CHECKS)

    for check_id in check_ids:
        check = get_check_by_id(check_id)
        if check:
            checks.append(check)

    if category == "person":
        pass
    elif category == "company":
        pass

    return [check_to_dict(c) for c in checks]


def get_rule_checks_for_doc_type(doc_type: str, category: Optional[str] = None) -> List[dict]:
    checks = get_checks_for_doc_type(doc_type, category)
    return [c for c in checks if c["classification"] == CheckClassification.RULE]


def get_ai_checks_for_doc_type(doc_type: str) -> List[dict]:
    check_ids = AI_DOC_TYPE_TO_CHECK_IDS.get(doc_type, [])
    checks: List[VerificationCheck] = []
    for check_id in check_ids:
        check = get_check_by_id(check_id)
        if check:
            checks.append(check)
    return [check_to_dict(c) for c in checks]


def is_licence_applicable(prescreening_data: Optional[dict]) -> bool:
    """
    Decide if licence/certificate checks should apply.
    Conservative approach:
    - if sector suggests regulation, return True
    - if entity type or profile explicitly says licensed/regulated, return True
    """
    if not prescreening_data:
        return False

    sector = str(prescreening_data.get("sector", "")).lower()
    entity_type = str(prescreening_data.get("entity_type", "")).lower()
    regulated_flag = str(prescreening_data.get("regulated", "")).lower()

    regulated_keywords = [
        "financial",
        "bank",
        "payment",
        "investment",
        "insurance",
        "fund",
        "trust",
        "corporate services",
        "management company",
        "broker",
        "securities",
    ]

    if regulated_flag in {"true", "yes", "1"}:
        return True

    if any(keyword in sector for keyword in regulated_keywords):
        return True

    if "licensed" in entity_type or "regulated" in entity_type:
        return True

    return False


def check_to_dict(check: VerificationCheck) -> dict:
    return {
        "id": check.id,
        "label": check.label,
        "classification": check.classification,
        "rule_type": check.rule_type,
        "trigger_timing": check.trigger_timing,
        "escalation_on_fail": check.escalation_on_fail,
        "escalation_on_warn": check.escalation_on_warn,
        "ps_field": check.ps_field,
        "required": check.required,
        "description": check.description,
    }
