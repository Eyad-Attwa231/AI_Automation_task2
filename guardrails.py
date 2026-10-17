"""Guardrails for the IT Incident agent.

Python decides what is allowed, so these are deterministic regex rules.
- check_input_text / check_output_text: plain functions (easy to test)
- input_safety_guardrail / output_safety_guardrail: wrappers the Agents SDK uses

When a guardrail trips, Runner.run raises:
    InputGuardrailTripwireTriggered   /   OutputGuardrailTripwireTriggered
Person B catches these and shows a friendly "blocked" message in the UI.
"""
import json
import re
from typing import Any

from agents import (Agent, GuardrailFunctionOutput, RunContextWrapper,
                    TResponseInputItem, input_guardrail, output_guardrail)

from tools import CONFIRMED_ACTIONS

I = re.IGNORECASE

# ---------- INPUT rules ----------
CREDENTIAL_REQUESTS = [
    r"\b(give|tell|show|send|reveal|share|read out)\s+(me\s+|us\s+)?"
    r"(the\s+|his\s+|her\s+|their\s+|my\s+|admin\s+|root\s+|another user'?s\s+|\w+'s\s+)*"
    r"(password|passcode|credentials?|api[ _-]?key|secret|token|otp)",
    r"\bwhat('?s| is)\s+(the|his|her|their|admin|root|\w+'s)\s+(\w+\s+)?"
    r"(password|passcode|credentials?|api[ _-]?key)",
]
PROMPT_INJECTION = [
    r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)",
    r"disregard\s+.{0,30}(instructions|rules|guidelines)",
    r"(reveal|show|print|repeat)\s+.{0,20}(system|hidden|developer)\s+(prompt|instructions)",
    r"you\s+are\s+now\s+(a|an|in)\b",
    r"\b(developer|jailbreak|dan)\s+mode\b",
    r"act\s+as\s+(an?\s+)?(admin|administrator|root|superuser)",
    r"override\s+(the\s+)?(safety|security|guardrails?|rules)",
]
UNSAFE_ADMIN = [
    r"\b(disable|turn\s+off|bypass)\b.{0,25}\b(firewall|antivirus|mfa|2fa|security|logging|audit)",
    r"\b(delete|wipe|erase|drop)\b.{0,25}\b(all\s+)?(logs|users|accounts|database|tickets)",
    r"\b(grant|give)\b.{0,25}\b(admin|root|superuser)\s+(access|rights|privileges)",
    r"\bchmod\s+777\b|\brm\s+-rf\b",
]

# ---------- OUTPUT rules ----------
# Claims that something is fixed/closed: no tool can confirm this, so block it.
FAKE_RESOLUTION = [
    r"\b(has|have)\s+been\s+(fixed|resolved|solved|closed)\b",
    r"\b(is|are)\s+(now\s+)?(fixed|resolved|solved|closed)\b",
    r"\bI\s+(have\s+|'ve\s+)?(fixed|resolved|solved|closed)\b",
]
CLAIMS_PASSWORD_RESET = r"password\s+(has\s+been|was|is\s+now)\s+reset|I\s+(have\s+|'ve\s+)?reset\s+(your|the)\s+password"
CLAIMS_TICKET_CREATED = r"ticket\s+(has\s+been\s+|was\s+)?(created|opened|filed)|I\s+(have\s+|'ve\s+)?(created|opened|filed)\s+(a|the)\s+ticket"
LEAKED_PASSWORD = r"password\s*(is|:|=)\s*(?=\S*[\d!@#$%^&*])\S{6,}"


def _first_match(patterns, text):
    for p in patterns:
        if re.search(p, text, I):
            return p
    return None


def check_input_text(text: str) -> dict:
    """Return {'blocked': bool, 'reason': str}."""
    if _first_match(CREDENTIAL_REQUESTS, text):
        return {"blocked": True, "reason": "credential_request"}
    if _first_match(PROMPT_INJECTION, text):
        return {"blocked": True, "reason": "prompt_injection"}
    if _first_match(UNSAFE_ADMIN, text):
        return {"blocked": True, "reason": "unsafe_admin_action"}
    return {"blocked": False, "reason": ""}


def check_output_text(text: str) -> dict:
    """Return {'blocked': bool, 'reason': str}. Uses CONFIRMED_ACTIONS from tools."""
    if re.search(LEAKED_PASSWORD, text, I):
        return {"blocked": True, "reason": "leaked_credential"}
    if _first_match(FAKE_RESOLUTION, text):
        return {"blocked": True, "reason": "fabricated_resolution"}
    if re.search(CLAIMS_PASSWORD_RESET, text, I) and not any(
            a.startswith("password_reset:") for a in CONFIRMED_ACTIONS):
        return {"blocked": True, "reason": "unconfirmed_password_reset_claim"}
    if re.search(CLAIMS_TICKET_CREATED, text, I) and not any(
            a.startswith("ticket:") for a in CONFIRMED_ACTIONS):
        return {"blocked": True, "reason": "unconfirmed_ticket_claim"}
    return {"blocked": False, "reason": ""}


# ---------- SDK wrappers ----------
def _input_to_text(inp: str | list[TResponseInputItem]) -> str:
    if isinstance(inp, str):
        return inp
    parts = []
    for item in inp:
        content = item.get("content") if isinstance(item, dict) else None
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts += [c.get("text", "") for c in content if isinstance(c, dict)]
    return "\n".join(parts)


def _output_to_text(output: Any) -> str:
    if isinstance(output, str):
        return output
    if hasattr(output, "model_dump_json"):      # Pydantic model
        return output.model_dump_json()
    try:
        return json.dumps(output, default=str)
    except Exception:
        return str(output)


@input_guardrail
async def input_safety_guardrail(ctx: RunContextWrapper[None], agent: Agent,
                                 input: str | list[TResponseInputItem]) -> GuardrailFunctionOutput:
    result = check_input_text(_input_to_text(input))
    return GuardrailFunctionOutput(output_info=result, tripwire_triggered=result["blocked"])


@output_guardrail
async def output_safety_guardrail(ctx: RunContextWrapper, agent: Agent,
                                  output: Any) -> GuardrailFunctionOutput:
    result = check_output_text(_output_to_text(output))
    return GuardrailFunctionOutput(output_info=result, tripwire_triggered=result["blocked"])
