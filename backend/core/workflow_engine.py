"""
Onboarda - Workflow Engine

Purpose:
- orchestrate full onboarding flow
- connect validation, rule engine, document verification, AI
- enforce conservative decisioning
"""

from __future__ import annotations

from typing import Any, Dict, List

from backend.core.validation_engine import (
    pre_validate_application,
    generate_fallback_memo,
    validate_compliance_memo,
)

from backend.core.rule_engine import compute_risk_score

from backend.ai.document_verification import verify_document_layered
from backend.ai.claude_client import ClaudeClient


class WorkflowEngine:
    def __init__(self, ai_enabled: bool = True):
        self.ai_client = ClaudeClient() if ai_enabled else None

    # ─────────────────────────────
    # MAIN ENTRY POINT
    # ─────────────────────────────
    def run_onboarding(
        self,
        application: Dict[str, Any],
        documents: List[Dict[str, Any]],
        prescreening_data: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:

        prescreening_data = prescreening_data or {}

        # 1️⃣ Pre-validation
        valid, errors = pre_validate_application(application)
        if not valid:
            return {
                "status": "failed",
                "stage": "validation",
                "errors": errors,
            }

        # 2️⃣ Risk scoring
        risk = compute_risk_score({
            "application": application,
            "prescreening_data": prescreening_data,
            "directors": prescreening_data.get("directors", []),
            "ubos": prescreening_data.get("ubos", []),
            "intermediaries": prescreening_data.get("intermediaries", []),
        })

        # 3️⃣ Document verification
        doc_results = []
        for doc in documents:
            result = verify_document_layered(
                doc_type=doc.get("type"),
                category=doc.get("category"),
                file_path=doc.get("file_path"),
                file_size=doc.get("file_size", 0),
                mime_type=doc.get("mime_type"),
                prescreening_data=prescreening_data,
                extracted_fields=doc.get("extracted_fields"),
                supporting_fields=doc.get("supporting_fields"),
                existing_hashes=[],
                ai_client=self.ai_client,
                file_name=doc.get("file_name"),
                person_name=application.get("company_name"),
                risk_level=risk["level"],
            )
            doc_results.append(result)

        # 4️⃣ Aggregate document risk
        doc_flagged = any(d["overall"] == "flagged" for d in doc_results)

        # 5️⃣ Build memo (fallback for now)
        memo = generate_fallback_memo(application)

        # 6️⃣ Validate memo
        memo_validation = validate_compliance_memo(memo)

        # 7️⃣ Final decision logic (STRICT)
        decision = self._final_decision(
            risk=risk,
            doc_results=doc_results,
            memo_validation=memo_validation,
        )

        return {
            "status": "completed",
            "risk": risk,
            "documents": doc_results,
            "memo": memo,
            "memo_validation": memo_validation,
            "decision": decision,
        }

    # ─────────────────────────────
    # FINAL DECISION LOGIC
    # ─────────────────────────────
    def _final_decision(
        self,
        risk: Dict[str, Any],
        doc_results: List[Dict[str, Any]],
        memo_validation: Dict[str, Any],
    ) -> Dict[str, Any]:

        level = risk.get("level", "MEDIUM")

        has_doc_fail = any(
            any(c["result"] == "fail" for c in d["checks"])
            for d in doc_results
        )

        has_doc_warn = any(
            any(c["result"] == "warn" for c in d["checks"])
            for d in doc_results
        )

        memo_failed = memo_validation["validation_status"] == "fail"

        # 🚫 HARD BLOCKS
        if has_doc_fail:
            return {
                "status": "REJECT",
                "reason": "Document verification failure",
            }

        if memo_failed:
            return {
                "status": "REVIEW",
                "reason": "Memo validation failed",
            }

        # ⚠️ HIGH RISK → NEVER AUTO APPROVE
        if level in {"HIGH", "VERY_HIGH"}:
            return {
                "status": "REVIEW",
                "reason": "High risk requires manual review",
            }

        # ⚠️ WARNINGS → REVIEW
        if has_doc_warn:
            return {
                "status": "REVIEW",
                "reason": "Warnings detected in document checks",
            }

        # ✅ ONLY CLEAN LOW/MEDIUM → APPROVE
        if level in {"LOW", "MEDIUM"}:
            return {
                "status": "APPROVE",
                "reason": "All checks passed",
            }

        return {
            "status": "REVIEW",
            "reason": "Default fallback",
        }
