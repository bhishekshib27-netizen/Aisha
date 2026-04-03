"""
Onboarda - Clean Configuration Layer
Strict validation + controlled AI behaviour
"""

import os


class Config:
    # ─────────────────────────────
    # ENVIRONMENT
    # ─────────────────────────────
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")

    # ─────────────────────────────
    # SECURITY
    # ─────────────────────────────
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    TOKEN_EXPIRY_SECONDS = 3600

    # ─────────────────────────────
    # DATABASE
    # ─────────────────────────────
    DB_PATH = os.getenv("DB_PATH", "data/app.db")

    # ─────────────────────────────
    # AI CONFIGURATION
    # ─────────────────────────────
    AI_ENABLED = True

    # VERY IMPORTANT → controls hallucinations
    AI_MAX_TOKENS = 1200
    AI_TEMPERATURE = 0.2   # low = less creativity = fewer mistakes

    # ─────────────────────────────
    # CONFIDENCE THRESHOLDS
    # ─────────────────────────────
    # These are the core of your fix 🔥

    MIN_CONFIDENCE_SCORE = 0.85   # reject below this
    AUTO_APPROVE_THRESHOLD = 0.92
    MANUAL_REVIEW_THRESHOLD = 0.75

    # ─────────────────────────────
    # DOCUMENT VALIDATION RULES
    # ─────────────────────────────
    REQUIRE_MATCH_ACROSS_DOCS = True
    STRICT_NAME_MATCH = True
    STRICT_DOB_MATCH = True

    # mismatch tolerance
    MAX_NAME_DISTANCE = 2   # small typos allowed
    MAX_DOB_VARIANCE = 0    # no DOB mismatch allowed

    # ─────────────────────────────
    # RISK SCORING
    # ─────────────────────────────
    HIGH_RISK_THRESHOLD = 70
    VERY_HIGH_RISK_THRESHOLD = 85

    # ─────────────────────────────
    # HUMAN-IN-THE-LOOP
    # ─────────────────────────────
    REQUIRE_MANUAL_REVIEW_FOR = [
    = [
        "HIGH_RISK",
        "VERY_HIGH_RISK",
        "LOW_CONFIDENCE",
        "DATA_MISMATCH",
        "MISSING_FIELDS"
    ]

    # ─────────────────────────────
    # AUDIT
    # ─────────────────────────────
    ENABLE_AUDIT_LOG = True
    LOG_ALL_AI_DECISIONS = True

    # ─────────────────────────────
    # FAIL-SAFE MODE
    # ─────────────────────────────
    # THIS is what stops AI mistakes from passing
    FAIL_ON_UNCERTAINTY = True
    BLOCK_INCOMPLETE_DATA = True
