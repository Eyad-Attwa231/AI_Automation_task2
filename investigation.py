"""Investigation stage: Orchestrator-Workers + Parallelization.

  TriageResult -> [LLM: Orchestrator picks workers] -> [Python: validates the plan]
               -> [Python: asyncio.gather runs the workers at the same time]
               -> InvestigationResult (plan + one report per worker)

LLM-ORCHESTRATED: which workers are needed (Orchestrator agent -> InvestigationPlan)
CODE-ORCHESTRATED: plan validation + fallback, running workers in parallel,
                   retrying on retryable tool errors, checking that workers
                   really called tools, never trusting a "finding" built on a failed tool.
"""
import asyncio
import time
from typing import Literal

from agents import Agent, ModelSettings, Runner
from pydantic import BaseModel, Field

import tools
from llm_setup import MODEL_NAME, SETTINGS, setup_llm
from models import TriageResult, WorkerFinding

setup_llm()

Worker = Literal["network", "account", "device"]
ALL_WORKERS: list[str] = ["network", "account", "device"]


# ---------- models ----------
class InvestigationPlan(BaseModel):
    """Output of the Orchestrator agent."""
    workers: list[Worker]
    reasoning: str


class WorkerReport(BaseModel):
    worker: str
    finding: WorkerFinding | None        # None = the worker could not finish
    tool_results: list[str] = Field(default_factory=list)   # raw evidence for the evaluator
    attempts: int = 1
    error: str | None = None


class InvestigationResult(BaseModel):
    plan: InvestigationPlan
    plan_source: Literal["llm", "fallback"]
    reports: list[WorkerReport]
    steps: list[str] = Field(default_factory=list)


# ---------- agents ----------
_tool = {t.name: t for t in tools.INVESTIGATION_TOOLS}

WORKER_TOOLS = {
    "network": ["check_network_status", "check_vpn_status"],
    "account": ["check_account_status"],
    "device": ["check_device_status"],
}

WORKER_DESCRIPTIONS = {
    "network": "site network health and the user's last VPN attempt",
    "account": "account state (active/locked), failed logins, MFA and security flag",
    "device": "the user's laptop: online, patched, VPN client version",
}


def _worker_instructions(area: str) -> str:
    return (f"You are the {area} investigator in an IT helpdesk system. "
            f"You check {WORKER_DESCRIPTIONS[area]}.\n"
            "ALWAYS call your tool(s) for the given Employee ID first. "
            "Then reply with 1-3 plain sentences using ONLY facts the tools returned; never guess.\n"
            "If a tool returned an error, say that the check failed.")


def _make_tool_agent(area: str, force: bool) -> Agent:
    # NOTE: no output_type here. Small local models skip tools when tools AND a
    # structured output format are given together, so structuring is a 2nd step.
    settings = ModelSettings(temperature=0, tool_choice="required") if force else SETTINGS
    return Agent(name=f"{area.title()} Worker", instructions=_worker_instructions(area),
                 model=MODEL_NAME, model_settings=settings,
                 tools=[_tool[t] for t in WORKER_TOOLS[area]])


TOOL_AGENTS = {n: _make_tool_agent(n, False) for n in WORKER_TOOLS}
TOOL_AGENTS_FORCED = {n: _make_tool_agent(n, True) for n in WORKER_TOOLS}   # tries first

structurer_agent = Agent(
    name="Finding Structurer",
    instructions=(
        "You convert investigation data into a structured finding. "
        "Use ONLY the tool results you are given; do not add facts.\n"
        "area: copy the given area. issue_found: true only if the tool results show a problem "
        "(locked account, offline device, outdated VPN client, network down, security flag, "
        "failed VPN attempt with an error code). findings: 1-3 factual sentences. "
        "tools_used: leave as an empty list."),
    model=MODEL_NAME, model_settings=SETTINGS, output_type=WorkerFinding)

orchestrator_agent = Agent(
    name="Incident Orchestrator",
    instructions=(
        "You plan an IT investigation. Choose which workers to delegate to:\n"
        + "\n".join(f"- {n}: {d}" for n, d in WORKER_DESCRIPTIONS.items())
        + "\nChoose only the workers needed for this incident, at least one.\n"
        "Examples: VPN problem -> network and device. Cannot log in -> account. "
        "Whole site has no internet -> network. Laptop problem -> device.\n"
        "Give a one-sentence reasoning."),
    model=MODEL_NAME, model_settings=SETTINGS, output_type=InvestigationPlan)


# ---------- planning (LLM decides, Python validates) ----------
def normalize_workers(names: list[str]) -> list[str]:
    seen: list[str] = []
    for n in names:
        if n in ALL_WORKERS and n not in seen:
            seen.append(n)
    if not seen:
        raise ValueError("plan contains no valid workers")
    return seen


async def _llm_plan(triage: TriageResult) -> InvestigationPlan:
    prompt = (f"Incident category: {triage.category}\nSeverity: {triage.severity}\n"
              f"Summary: {triage.summary}")
    result = await Runner.run(orchestrator_agent, prompt)
    out = result.final_output
    if not isinstance(out, InvestigationPlan):
        out = InvestigationPlan.model_validate(out)
    return out


async def make_plan(triage: TriageResult, plan_fn=None) -> tuple[InvestigationPlan, str]:
    plan_fn = plan_fn or _llm_plan
    try:
        plan = await plan_fn(triage)
        return InvestigationPlan(workers=normalize_workers(list(plan.workers)),
                                 reasoning=plan.reasoning), "llm"
    except Exception as e:
        # Safe default: check everything
        return InvestigationPlan(
            workers=list(ALL_WORKERS),
            reasoning=f"fallback: orchestrator failed ({type(e).__name__}), checking all areas"), "fallback"


# ---------- workers ----------
def _extract_activity(result) -> tuple[list[str], list]:
    calls, outputs = [], []
    for item in result.new_items:
        if item.type == "tool_call_item":
            calls.append(getattr(item, "tool_name", None) or getattr(item.raw_item, "name", "?"))
        elif item.type == "tool_call_output_item":
            outputs.append(item.output)
    return calls, outputs


async def _call_worker_agent(worker: str, user_id: str, text: str):
    """Step 1: tool-calling agent. Step 2: structure the REAL tool results."""
    prompt = f"Employee ID: {user_id}\nIncident: {text}"
    calls, outputs, notes = [], [], ""
    for agent in (TOOL_AGENTS_FORCED[worker], TOOL_AGENTS[worker]):
        try:
            result = await Runner.run(agent, prompt, max_turns=4)
        except Exception:
            continue                                   # e.g. tool_choice not supported -> plain agent
        calls, outputs = _extract_activity(result)
        notes = str(result.final_output or "")
        if calls:
            break
    if not calls:                                      # run_worker will reject this
        return WorkerFinding(area=worker, issue_found=False, findings="no tool used",
                             tools_used=[]), [], []
    evidence = "\n".join(str(o) for o in outputs)
    s = await Runner.run(structurer_agent,
                         f"Area: {worker}\nTool results:\n{evidence}\nInvestigator notes: {notes}")
    finding = s.final_output
    if not isinstance(finding, WorkerFinding):
        finding = WorkerFinding.model_validate(finding)
    return finding, calls, outputs


def _is_error(o) -> bool:
    return isinstance(o, dict) and o.get("status") == "error"


def _retryable(outputs: list) -> bool:
    return any(_is_error(o) and o.get("retryable") for o in outputs)


async def run_worker(worker: str, user_id: str, text: str, call_fn=None,
                     max_attempts: int = 2) -> WorkerReport:
    """Never raises. Retries once on a retryable tool error or bad worker output."""
    call_fn = call_fn or _call_worker_agent
    last_err = None
    for attempt in range(1, max_attempts + 1):
        try:
            finding, calls, outputs = await call_fn(worker, user_id, text)
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            continue
        if not calls:                               # no tool used = findings cannot be trusted
            last_err = "worker did not call any tool"
            continue
        if _retryable(outputs) and attempt < max_attempts:
            last_err = "tool error, retrying"
            continue
        errors = [o for o in outputs if _is_error(o)]
        # Python decides the facts: tools_used comes from real calls, never from the LLM
        finding = finding.model_copy(update={"area": worker, "tools_used": calls})
        error = None
        if errors:
            error = str(errors[0].get("message", "tool error"))
            finding = finding.model_copy(update={
                "issue_found": False,
                "findings": f"The {worker} check could not be completed ({error})."})
        return WorkerReport(worker=worker, finding=finding, attempts=attempt, error=error,
                            tool_results=[str(o) for o in outputs])
    return WorkerReport(worker=worker, finding=None, attempts=max_attempts,
                        error=last_err or "unknown error")


# ---------- the whole stage ----------
async def investigate(triage: TriageResult, text: str, plan_fn=None, worker_fn=None) -> InvestigationResult:
    plan, source = await make_plan(triage, plan_fn)
    steps = [f"orchestrator ({source}): workers={plan.workers} - {plan.reasoning}"]

    t0 = time.perf_counter()
    raw = await asyncio.gather(
        *[run_worker(w, triage.user_id, text, call_fn=worker_fn) for w in plan.workers],
        return_exceptions=True)                     # PARALLELIZATION
    elapsed = time.perf_counter() - t0

    reports: list[WorkerReport] = []
    for w, r in zip(plan.workers, raw):
        if isinstance(r, Exception):                # extra safety net
            r = WorkerReport(worker=w, finding=None, error=f"{type(r).__name__}: {r}")
        reports.append(r)
    steps.append(f"workers ran in parallel ({elapsed:.1f}s)")
    for r in reports:
        if r.finding is None:
            steps.append(f"  {r.worker}: FAILED after {r.attempts} attempt(s) - {r.error}")
        else:
            note = f" (after {r.attempts} attempts)" if r.attempts > 1 else ""
            steps.append(f"  {r.worker}: issue_found={r.finding.issue_found}{note} - {r.finding.findings}")
    return InvestigationResult(plan=plan, plan_source=source, reports=reports, steps=steps)


def collect_evidence(result: InvestigationResult) -> list[str]:
    """All raw tool results, for the evaluator to check claims against."""
    return [t for r in result.reports for t in r.tool_results]
