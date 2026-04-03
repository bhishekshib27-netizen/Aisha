"""
Onboarda - Backend Server

Simple FastAPI server to:
- receive onboarding requests
- run workflow engine
- return structured results
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any

from backend.core.workflow_engine import WorkflowEngine

app = FastAPI(title="Onboarda Backend")

engine = WorkflowEngine()


# ─────────────────────────────
# REQUEST SCHEMA
# ─────────────────────────────
class Document(BaseModel):
    type: str
    category: str | None = None
    file_path: str | None = None
    file_size: int | None = 0
    mime_type: str | None = None
    file_name: str | None = None
    extracted_fields: Dict[str, Any] | None = {}
    supporting_fields: Dict[str, Any] | None = {}


class OnboardingRequest(BaseModel):
    application: Dict[str, Any]
    documents: List[Document]
    prescreening_data: Dict[str, Any] | None = {}


# ─────────────────────────────
# HEALTH CHECK
# ─────────────────────────────
@app.get("/api/health")
def health():
    return {"status": "ok"}


# ─────────────────────────────
# MAIN ENDPOINT
# ─────────────────────────────
@app.post("/api/onboard")
def onboard(request: OnboardingRequest):
    result = engine.run_onboarding(
        application=request.application,
        documents=[doc.dict() for doc in request.documents],
        prescreening_data=request.prescreening_data,
    )
    return result
