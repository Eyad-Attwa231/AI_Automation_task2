"""Shared Pydantic models (structured outputs) for the IT Incident agent.

Both team members import from here, so keep field names stable.
Validation lives in Python validators (not in the JSON schema), so small local
models still get a simple schema, and bad output is caught safely:

    try:
        result = await Runner.run(triage_agent, text)
        triage = result.final_output          # already a TriageResult
    except Exception:                          # ValidationError / ModelBehaviorError
        ... ask the user again / fall back safely ...
"""
import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Category = Literal["vpn", "account", "device", "network", "security", "other"]
Severity = Literal["low", "medium", "high", "critical"]


def _check_user_id(v: str) -> str:
    v = v.strip()
    if not re.fullmatch(r"u\d{3}", v):
        raise ValueError("user_id must look like 'u001'")
    return v


class TriageResult(BaseModel):
    """Step 1 of the prompt chain: what is the incident?"""
    user_id: str
    category: Category
    severity: Severity
    is_security_incident: bool
    summary: str

    @field_validator("user_id")
    @classmethod
    def _uid(cls, v):
        return _check_user_id(v)

    @field_validator("summary")
    @classmethod
    def _summary(cls, v):
        if len(v.strip()) < 5:
            raise ValueError("summary too short")
        return v.strip()[:300]


class WorkerFinding(BaseModel):
    """Output of one worker agent (network / account / device)."""
    area: Literal["network", "account", "device"]
    issue_found: bool
    findings: str                    # facts taken from tool results only
    tools_used: list[str]


class Resolution(BaseModel):
    """Step 3 of the prompt chain: proposed fix, grounded in tool results."""
    steps: list[str]
    evidence: list[str]              # tool facts that support the steps
    needs_human: bool
    confidence: Literal["low", "medium", "high"]

    @field_validator("steps", "evidence")
    @classmethod
    def _not_empty(cls, v):
        v = [x.strip() for x in v if x and x.strip()]
        if not v:
            raise ValueError("must not be empty")
        return v


class EvalResult(BaseModel):
    """Evaluator output: is the draft supported by the tool results?"""
    approved: bool
    unsupported_claims: list[str]
    feedback: str


class IncidentResponse(BaseModel):
    """What handle_incident() returns to the UI (the agreed interface)."""
    reply: str
    triage: dict | None = None
    steps: list[str] = Field(default_factory=list)   # e.g. ["triage", "routed: normal", ...]
    needs_human: bool = False
    blocked_reason: str | None = None
