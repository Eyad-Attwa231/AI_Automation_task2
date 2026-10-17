"""Resolution stage: Evaluator-Optimizer loop (max 3 iterations).

  InvestigationResult (tool evidence) + TriageResult
     -> [LLM: Troubleshooter drafts a Resolution]
     -> [Evaluator = Python checks + LLM check -> EvalResult]
     -> approved?  yes -> done   |   no -> feedback goes back to the Troubleshooter
     -> stop when approved OR after MAX_ITERATIONS (then a human takes over)

CODE-ORCHESTRATED: the loop, the stop condition, the Python checks (fake "fixed"
  claims, unsafe steps, evidence lines that are not in the tool results), the
  "no evidence -> no automatic answer" rule.
LLM-DECIDED: the draft itself and the evaluator's judgement.
An unapproved draft is NEVER shown to the user as a solution.
"""
import re

from agents import Agent, Runner
from pydantic import BaseModel, Field

import tools
from guardrails import check_input_text, check_output_text
from investigation import InvestigationResult, collect_evidence
from llm_setup import MODEL_NAME, SETTINGS, setup_llm
from models import EvalResult, Resolution, TriageResult

setup_llm()

MAX_ITERATIONS = 3

# A deliberately bad first draft, used to DEMO the evaluator rejecting a result (scenario 6)
BAD_DRAFT = Resolution(
    steps=["Your VPN issue has been fixed.", "Your password has been reset to a new one."],
    evidence=["Everything looks great."],
    needs_human=False, confidence="high")

troubleshooter_agent = Agent(
    name="Troubleshooting Agent",
    instructions=(
        "You are the troubleshooting step of an IT helpdesk system. Propose a fix plan for the "
        "employee using ONLY the evidence given (tool results and knowledge-base steps).\n"
        "- steps: 2-5 short, practical steps the employee can follow. If an action needs IT admin "
        "rights (unlocking an account, resetting a password), write 'Ask the IT helpdesk to ...' "
        "and set needs_human to true.\n"
        "- evidence: 1-4 short lines, each quoting a concrete fact from the tool results "
        "(an error code, a version number, a status).\n"
        "- Never say anything is already fixed, resolved or reset. Never invent data or credentials.\n"
        "- confidence: high only if the evidence clearly explains the problem.\n"
        "If you receive review feedback, fix every problem listed."),
    model=MODEL_NAME, model_settings=SETTINGS, output_type=Resolution)

evaluator_agent = Agent(
    name="Resolution Evaluator",
    instructions=(
        "You review a proposed IT resolution against the tool results. Approve ONLY if every step "
        "and every evidence line is supported by the tool results or knowledge-base steps.\n"
        "Reject (approved=false) if: something is claimed to be already fixed/resolved/reset; a fact "
        "is not in the tool results; a step is unsafe (disabling security, sharing passwords); "
        "or admin-only actions are given to the employee as self-service.\n"
        "unsupported_claims: list each problem briefly (empty list if none). "
        "feedback: one or two sentences telling the troubleshooter exactly what to fix."),
    model=MODEL_NAME, model_settings=SETTINGS, output_type=EvalResult)


# ---------- models ----------
class Iteration(BaseModel):
    number: int
    draft: Resolution | None = None
    evaluation: EvalResult | None = None
    note: str = ""


class ResolutionResult(BaseModel):
    approved: bool
    resolution: Resolution | None
    reason: str                       # approved | max_iterations | no_evidence
    iterations: list[Iteration] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)   # for the UI / trace


# ---------- deterministic checks (Python decides) ----------
STATUS_WORDS = {"locked", "active", "offline", "online", "down", "outdated", "healthy",
                "failed", "timeout", "patched", "flagged"}


def _grounded(line: str, evidence_lower: str) -> bool:
    """An evidence line must contain a concrete value (number/code/status) found in the tool results."""
    for tok in re.findall(r"[a-z0-9][a-z0-9.\-]*", line.lower()):
        tok = tok.strip(".-")
        if len(tok) < 2:
            continue
        if (any(c.isdigit() for c in tok) or tok in STATUS_WORDS) and tok in evidence_lower:
            return True
    return False


def python_checks(draft: Resolution, evidence_text: str) -> list[str]:
    """Return a list of problems (empty = passed)."""
    problems: list[str] = []
    steps_text = " ".join(draft.steps)
    out = check_output_text(steps_text + " " + " ".join(draft.evidence))
    if out["blocked"]:
        problems.append(f"output rule violated: {out['reason']}")
    unsafe = check_input_text(steps_text)
    if unsafe["blocked"]:
        problems.append(f"unsafe step: {unsafe['reason']}")
    ev = evidence_text.lower()
    for line in draft.evidence:
        if not _grounded(line, ev):
            problems.append(f"evidence not found in tool results: '{line[:60]}'")
    return problems


# ---------- LLM calls ----------
async def _llm_generate(ctx: dict) -> Resolution:
    prompt = (f"Incident: {ctx['triage'].summary} (category={ctx['triage'].category}, "
              f"severity={ctx['triage'].severity})\n\nWorker findings:\n{ctx['findings_text']}\n\n"
              f"Tool results (raw evidence):\n{ctx['evidence_text']}")
    if ctx.get("feedback"):
        prompt += (f"\n\nYour previous draft was REJECTED.\nPrevious draft: "
                   f"{ctx['previous'].model_dump_json() if ctx.get('previous') else ''}\n"
                   f"Problems to fix: {ctx['feedback']}")
    result = await Runner.run(troubleshooter_agent, prompt)
    out = result.final_output
    return out if isinstance(out, Resolution) else Resolution.model_validate(out)


async def _llm_evaluate(draft: Resolution, evidence_text: str) -> EvalResult:
    prompt = f"Proposed resolution:\n{draft.model_dump_json()}\n\nTool results:\n{evidence_text}"
    result = await Runner.run(evaluator_agent, prompt)
    out = result.final_output
    return out if isinstance(out, EvalResult) else EvalResult.model_validate(out)


async def evaluate_draft(draft: Resolution, evidence_text: str, evaluate_fn=None) -> tuple[EvalResult, str]:
    """Python checks AND the LLM evaluator must both pass."""
    evaluate_fn = evaluate_fn or _llm_evaluate
    py_problems = python_checks(draft, evidence_text)
    note = ""
    try:
        llm = await evaluate_fn(draft, evidence_text)
    except Exception as e:
        # If the LLM evaluator is down, the deterministic checks still decide
        llm = EvalResult(approved=True, unsupported_claims=[], feedback="")
        note = f"LLM evaluator unavailable ({type(e).__name__}); Python checks only"
    problems = list(llm.unsupported_claims) + py_problems
    approved = llm.approved and not py_problems
    feedback = " ".join(x for x in [llm.feedback] + py_problems if x).strip()
    return EvalResult(approved=approved, unsupported_claims=problems,
                      feedback=feedback or ("OK" if approved else "Rejected")), note


# ---------- the loop ----------
async def run_resolution(triage: TriageResult, inv: InvestigationResult, generate_fn=None,
                         evaluate_fn=None, bad_first_draft: bool = False) -> ResolutionResult:
    generate_fn = generate_fn or _llm_generate
    evidence = collect_evidence(inv)
    findings_text = "\n".join(f"- {r.worker}: {r.finding.findings}" for r in inv.reports if r.finding)

    # Rule: no tool evidence -> no automatic resolution (never invent)
    if not evidence:
        return ResolutionResult(approved=False, resolution=None, reason="no_evidence",
                                steps=["no tool evidence available -> human review"])

    kb = tools.search_it_knowledge(f"{triage.category} {triage.summary}")
    if kb.get("articles"):
        evidence.append(f"knowledge base: {kb['articles']}")
    evidence_text = "\n".join(evidence)

    iterations: list[Iteration] = []
    steps: list[str] = []
    feedback, previous = "", None
    for n in range(1, MAX_ITERATIONS + 1):                       # bounded loop
        it = Iteration(number=n)
        try:
            if bad_first_draft and n == 1:
                draft = BAD_DRAFT.model_copy()                   # demo of a rejected result
                it.note = "demo: deliberately bad first draft"
            else:
                draft = await generate_fn({"triage": triage, "findings_text": findings_text,
                                           "evidence_text": evidence_text,
                                           "feedback": feedback, "previous": previous})
        except Exception as e:
            it.note = f"draft failed: {type(e).__name__}"
            iterations.append(it)
            steps.append(f"iteration {n}: troubleshooter failed ({type(e).__name__})")
            continue
        evaluation, note = await evaluate_draft(draft, evidence_text, evaluate_fn)
        it.draft, it.evaluation = draft, evaluation
        it.note = (it.note + " " + note).strip()
        iterations.append(it)
        if evaluation.approved:
            steps.append(f"iteration {n}: evaluator APPROVED")
            return ResolutionResult(approved=True, resolution=draft, reason="approved",
                                    iterations=iterations, steps=steps)
        steps.append(f"iteration {n}: evaluator REJECTED - {'; '.join(evaluation.unsupported_claims)[:200]}")
        feedback, previous = evaluation.feedback, draft
    last = next((i.draft for i in reversed(iterations) if i.draft), None)
    steps.append(f"stopped after {MAX_ITERATIONS} iterations without approval -> human review")
    return ResolutionResult(approved=False, resolution=last, reason="max_iterations",
                            iterations=iterations, steps=steps)


def format_reply(res: ResolutionResult) -> str:
    """User-facing text. Only an APPROVED resolution is shown as advice."""
    if not res.approved or res.resolution is None:
        return ("I could not produce a verified solution automatically, "
                "so this will be reviewed by the IT team.")
    lines = [f"{i}. {s}" for i, s in enumerate(res.resolution.steps, 1)]
    ev = "; ".join(res.resolution.evidence)
    text = "Suggested steps:\n" + "\n".join(lines) + f"\n\nWhat I found: {ev}"
    if res.resolution.needs_human:
        text += "\n\nThis needs an IT admin, so a human will follow up."
    return text
