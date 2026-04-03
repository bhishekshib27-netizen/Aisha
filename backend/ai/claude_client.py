"""
Onboarda - Clean Claude Client

Purpose:
- provide controlled AI-assisted document verification
- standardise AI output
- fail safely when AI is unavailable
- never allow AI to make final approval decisions

Design rules:
- low temperature
- strict JSON-only outputs
- schema-normalised responses
- fail closed in production-like environments when configured
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from backend.config.config import Config

logger = logging.getLogger(__name__)

try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    Anthropic = None
    ANTHROPIC_AVAILABLE = False


AGENT_RISK_DIMENSIONS = {
    1: ["D1"],                    # document / identity
    2: ["D1", "D2"],              # registry / geographic
    3: ["D1"],                    # screening
    4: ["D1"],                    # ownership / UBO
    5: ["D1", "D2", "D3", "D4"],  # memo / recommendation
}


def compute_overall_status(checks: List[dict]) -> str:
    if not checks:
        return "NOT_RUN"

    has_fail = any((c.get("result") or "").lower() == "fail" for c in checks)
    has_warn = any((c.get("result") or "").lower() == "warn" for c in checks)

    if has_fail:
        return "FAIL"
    if has_warn:
        return "WARN"
    return "PASS"


def compute_requires_review(checks: List[dict]) -> bool:
    if not checks:
        return True

    for check in checks:
        result = (check.get("result") or "").lower()
        if result in {"fail", "warn"}:
            return True
    return False


def standardise_agent_output(
    checks: Optional[List[dict]] = None,
    summary: str = "",
    *,
    error_message: Optional[str] = None,
) -> Dict[str, Any]:
    checks = checks or []

    if error_message:
        return {
            "status": "ERROR",
            "checks": [],
            "summary": error_message,
            "flags": [error_message],
            "requires_review": True,
            "validated": False,
            "rejected": False,
        }

    status = compute_overall_status(checks)
    flags = [
        check.get("message", "Unknown issue")
        for check in checks
        if (check.get("result") or "").lower() in {"fail", "warn"}
    ]

    return {
        "status": status,
        "checks": checks,
        "summary": summary,
        "flags": flags,
        "requires_review": compute_requires_review(checks),
        "validated": status in {"PASS", "WARN"},
        "rejected": False,
    }


class ClaudeClient:
    """
    Clean Claude wrapper for Onboarda.

    Supports:
    - verify_document()

    It can operate in:
    - live mode: real Anthropic API
    - disabled mode: fail-safe warning output
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        enabled: bool = True,
        fail_closed: bool = True,
    ) -> None:
        self.enabled = enabled and Config.AI_ENABLED
        self.fail_closed = fail_closed
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")

        self.model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        self.max_tokens = int(os.getenv("AI_MAX_TOKENS", str(Config.AI_MAX_TOKENS)))
        self.temperature = float(os.getenv("AI_TEMPERATURE", str(Config.AI_TEMPERATURE)))

        self.client = None

        if not self.enabled:
            logger.warning("ClaudeClient initialised with AI disabled")
            return

        if not ANTHROPIC_AVAILABLE:
            logger.warning("Anthropic SDK not installed")
            return

        if not self.api_key:
            logger.warning("No Anthropic API key configured")
            return

        try:
            self.client = Anthropic(api_key=self.api_key)
            logger.info("ClaudeClient initialised successfully")
        except Exception as exc:
            logger.exception("Failed to initialise Anthropic client: %s", exc)
            self.client = None

    def _sanitize_text(self, value: Any, max_length: int = 1200) -> str:
        if value is None:
            return ""
        text = str(value)

        # strip obvious prompt injection markers
        blocked_patterns = [
            r"(?i)\b(ignore previous instructions)\b",
            r"(?i)\b(system prompt)\b",
            r"(?i)\b(act as)\b",
            r"(?i)\b(you are now)\b",
            r"(?i)\b(role:)\b",
            r"```",
            r"<\|.*?\|>",
        ]
        for pattern in blocked_patterns:
            text = re.sub(pattern, "[BLOCKED]", text)

        text = re.sub(r"[^\S\r\n]+", " ", text).strip()
        return text[:max_length]

    def _is_available(self) -> bool:
        return self.enabled and self.client is not None

    def _unavailable_result(self, reason: str) -> Dict[str, Any]:
        if self.fail_closed:
            return {
                "checks": [
                    {
                        "id": "AI-UNAVAILABLE",
                        "label": "AI Verification Unavailable",
                        "classification": "ai",
                        "type": "ai",
                        "result": "warn",
                        "message": reason,
                        "source": "ai",
                        "confidence": 0.0,
                    }
                ],
                "overall": "flagged",
                "confidence": 0.0,
                "red_flags": [reason],
                "engine_version": "clean_ai_v1",
            }

        return {
            "checks": [],
            "overall": "flagged",
            "confidence": 0.0,
            "red_flags": [reason],
            "engine_version": "clean_ai_v1",
        }

    def _call_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        if not self._is_available():
            raise RuntimeError("Claude API unavailable")

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            system=system_prompt,
            messages=[
                {
                    "role": "user",
                    "content": user_prompt,
                }
            ],
        )

        text_parts: List[str] = []
        for block in response.content:
            if getattr(block, "type", None) == "text":
                text_parts.append(block.text)

        raw_text = "\n".join(text_parts).strip()
        if not raw_text:
            raise ValueError("Claude returned empty response")

        return self._parse_json(raw_text)

    def _parse_json(self, raw_text: str) -> Dict[str, Any]:
        raw_text = raw_text.strip()

        # plain JSON
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError:
            pass

        # fenced JSON
        match = re.search(r"```json\s*(\{.*\})\s*```", raw_text, re.DOTALL)
        if match:
            return json.loads(match.group(1))

        # generic object extraction
        match = re.search(r"(\{.*\})", raw_text, re.DOTALL)
        if match:
            return json.loads(match.group(1))

        raise ValueError("Unable to parse JSON response from Claude")

    def _normalize_document_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        checks = result.get("checks", [])
        if not isinstance(checks, list):
            checks = []

        normalized_checks: List[dict] = []
        for check in checks:
            if not isinstance(check, dict):
                continue
            normalized_checks.append(
                {
                    "id": check.get("id", "AI-UNKNOWN"),
                    "label": check.get("label", "AI Check"),
                    "classification": check.get("classification", "ai"),
                    "type": check.get("type", "ai"),
                    "result": str(check.get("result", "warn")).lower(),
                    "message": check.get("message", "No message provided"),
                    "source": check.get("source", "ai"),
                    "confidence": float(check.get("confidence", 0.0) or 0.0),
                }
            )

        overall = str(result.get("overall", "flagged")).lower()
        if overall not in {"verified", "flagged"}:
            overall = "flagged"

        try:
            confidence = float(result.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0

        red_flags = result.get("red_flags", [])
        if not isinstance(red_flags, list):
            red_flags = []

        # no result = no pass
        if not normalized_checks:
            overall = "flagged"
            red_flags.append("AI returned no usable checks")

        # weak confidence cannot verify
        if confidence < Config.MANUAL_REVIEW_THRESHOLD:
            overall = "flagged"

        return {
            "checks": normalized_checks,
            "overall": overall,
            "confidence": confidence,
            "red_flags": red_flags,
            "engine_version": "clean_ai_v1",
        }

    def verify_document(
        self,
        doc_type: str,
        file_name: Optional[str] = None,
        person_name: Optional[str] = None,
        extracted_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        AI-assisted document verification.

        AI tasks:
        - flag visual / semantic inconsistencies
        - flag authenticity suspicion
        - comment on field coherence

        AI never makes final onboarding decisions.
        """
        if not self._is_available():
            return self._unavailable_result("Claude client unavailable for document verification")

        safe_doc_type = self._sanitize_text(doc_type, 120)
        safe_file_name = self._sanitize_text(file_name or "", 200)
        safe_person_name = self._sanitize_text(person_name or "", 200)
        safe_fields = extracted_fields or {}

        # sanitize extracted fields shallowly
        sanitized_fields = {
            str(key): self._sanitize_text(value, 300)
            for key, value in safe_fields.items()
            if not str(key).startswith("_")
        }

        system_prompt = """
You are a compliance document review assistant.

Your task is to assess a single uploaded document conservatively.

Rules:
- Return ONLY JSON.
- Do not invent facts.
- If uncertain, return warn not pass.
- Do not approve onboarding.
- You may only assess document-level concerns.

Return this exact structure:
{
  "checks": [
    {
      "id": "AI-01",
      "label": "Tampering Indicators",
      "classification": "ai",
      "type": "ai",
      "result": "pass|warn|fail",
      "message": "short explanation",
      "source": "ai",
      "confidence": 0.0
    }
  ],
  "overall": "verified|flagged",
  "confidence": 0.0,
  "red_flags": ["..."]
}
"""

        user_prompt = json.dumps(
            {
                "doc_type": safe_doc_type,
                "file_name": safe_file_name,
                "person_name": safe_person_name,
                "extracted_fields": sanitized_fields,
                "instructions": [
                    "Look for signs of inconsistency, tampering suspicion, or semantic mismatch.",
                    "If evidence is insufficient, use warn.",
                    "Do not assume authenticity from missing evidence.",
                ],
            },
            indent=2,
        )

        try:
            result = self._call_json(system_prompt, user_prompt)
            return self._normalize_document_result(result)
        except Exception as exc:
            logger.exception("Claude verify_document failed: %s", exc)
            return self._unavailable_result(f"AI verification error: {exc}")
