"""Run:  py test_investigation.py            (offline tests, then real LLM examples)
       py test_investigation.py --offline   (only offline tests)"""
import asyncio
import sys

import tools
from investigation import (InvestigationPlan, collect_evidence, investigate,
                           normalize_workers, run_worker)
from models import TriageResult, WorkerFinding
from triage import triage_and_route

passed = failed = 0


def check(name, cond):
    global passed, failed
    passed += bool(cond)
    failed += not cond
    print(("PASS  " if cond else "FAIL  ") + name)


TRIAGE = TriageResult(user_id="u001", category="vpn", severity="medium",
                      is_security_incident=False, summary="VPN does not connect")


def finding(area="network", issue=True, text="Looks wrong"):
    return WorkerFinding(area=area, issue_found=issue, findings=text, tools_used=["made_up_tool"])


async def ok_call(worker, uid, text):
    await asyncio.sleep(0.3)
    return finding(worker), [f"check_{worker}_status"], [{"status": "ok", "worker": worker}]


async def plan_all(triage):
    return InvestigationPlan(workers=["network", "device", "account"], reasoning="test")


async def plan_crash(triage):
    raise RuntimeError("orchestrator crashed")


async def offline_tests():
    check("normalize removes duplicates", normalize_workers(["network", "network", "device"]) == ["network", "device"])
    try:
        normalize_workers(["pizza"])
        check("normalize rejects empty plan", False)
    except ValueError:
        check("normalize rejects empty plan", True)

    r = await investigate(TRIAGE, "vpn", plan_fn=plan_crash, worker_fn=ok_call)
    check("orchestrator failure -> fallback to all workers",
          r.plan_source == "fallback" and r.plan.workers == ["network", "account", "device"])

    r = await investigate(TRIAGE, "vpn", plan_fn=plan_all, worker_fn=ok_call)
    elapsed = float(r.steps[1].split("(")[1].split("s")[0])
    check(f"3 workers run in parallel ({elapsed:.1f}s, sequential would be 0.9s)", elapsed < 0.7)
    check("tools_used comes from real calls, not from the LLM",
          all(rep.finding.tools_used != ["made_up_tool"] for rep in r.reports))
    check("evidence collected for evaluator", len(collect_evidence(r)) == 3)

    async def one_crashes(worker, uid, text):
        if worker == "account":
            raise RuntimeError("boom")
        return await ok_call(worker, uid, text)
    r = await investigate(TRIAGE, "vpn", plan_fn=plan_all, worker_fn=one_crashes)
    by = {rep.worker: rep for rep in r.reports}
    check("one worker crashing does not break the others",
          by["account"].finding is None and by["network"].finding and by["device"].finding)

    async def no_tools(worker, uid, text):
        return finding(worker), [], []
    rep = await run_worker("network", "u001", "x", call_fn=no_tools)
    check("worker that calls no tool is rejected", rep.finding is None and "did not call" in rep.error)

    calls = {"n": 0}

    async def timeout_then_ok(worker, uid, text):
        calls["n"] += 1
        if calls["n"] == 1:
            out = {"status": "error", "error_type": "timeout", "message": "timed out", "retryable": True}
        else:
            out = {"status": "ok"}
        return finding(worker), ["check_network_status"], [out]
    rep = await run_worker("network", "u001", "x", call_fn=timeout_then_ok)
    check("retryable tool error -> retried and recovered", rep.attempts == 2 and rep.error is None and rep.finding)

    async def hard_error(worker, uid, text):
        out = {"status": "error", "error_type": "not_found", "message": "No user", "retryable": False}
        return finding(worker, issue=True, text="Everything is broken!"), ["check_network_status"], [out]
    rep = await run_worker("network", "u001", "x", call_fn=hard_error)
    check("failed tool: Python replaces the LLM's claim",
          rep.finding.issue_found is False and "could not be completed" in rep.finding.findings)

    # ---- two-step worker flow (tools first, then structure), with a fake model ----
    import investigation as inv
    from types import SimpleNamespace as NS

    def tool_items(name, out):
        return [NS(type="tool_call_item", tool_name=name, raw_item=NS(name=name)),
                NS(type="tool_call_output_item", output=out)]

    real_runner = inv.Runner
    seen_prompts = []

    class FakeRunner:
        mode = "good"          # good | forced_fails | never_calls_tools

        @staticmethod
        async def run(agent, prompt, max_turns=None):
            if agent is inv.structurer_agent:
                seen_prompts.append(prompt)
                return NS(final_output=finding("network", True, "Network is down"), new_items=[])
            forced = agent in inv.TOOL_AGENTS_FORCED.values()
            if FakeRunner.mode == "forced_fails" and forced:
                raise RuntimeError("tool_choice not supported")
            if FakeRunner.mode == "never_calls_tools":
                return NS(final_output="I think it is fine", new_items=[])
            return NS(final_output="Site is down",
                      new_items=tool_items("check_network_status", {"status": "ok", "site": "Alex-Branch"}))

    inv.Runner = FakeRunner
    try:
        FakeRunner.mode = "good"
        rep = await run_worker("network", "u004", "no internet")
        check("2-step worker: tools called, then structured", rep.finding and rep.finding.tools_used == ["check_network_status"])
        check("structurer receives the REAL tool results", "Alex-Branch" in seen_prompts[-1])

        FakeRunner.mode = "forced_fails"
        rep = await run_worker("network", "u004", "no internet")
        check("forced tool_choice fails -> falls back to plain agent", rep.finding is not None and rep.attempts == 1)

        FakeRunner.mode = "never_calls_tools"
        rep = await run_worker("network", "u004", "no internet")
        check("model never calls a tool -> worker rejected, nothing invented", rep.finding is None)
    finally:
        inv.Runner = real_runner

    # REAL tool with the built-in simulated failure (scenario 10)
    tools.reset_demo_state()

    async def real_network(worker, uid, text):
        return finding(worker), ["check_network_status"], [tools.check_network_status(uid)]
    rep = await run_worker("network", "u005", "vpn", call_fn=real_network)
    check("real u005 timeout then recovery", rep.attempts == 2 and rep.error is None)


EXAMPLES = [
    "u001: I can't connect to the VPN, error 619",
    "u002: I can't log in, it says my account is locked",
    "u005: VPN does not connect for me",
    "u004: The whole Alexandria branch has no internet",
]


async def llm_examples():
    print("\n=== REAL LLM EXAMPLES (can take several minutes) ===")
    for text in EXAMPLES:
        tools.reset_demo_state()
        print(f"\n>>> {text}")
        try:
            d = await triage_and_route(text)
            print("   ", d.steps[-1])
            if d.path != "auto":
                print("    (not auto, skipping investigation)")
                continue
            r = await investigate(d.triage, text)
            for s in r.steps:
                print("   ", s)
        except Exception as e:
            print("    ERROR:", type(e).__name__, e)


async def main():
    await offline_tests()
    print(f"\n{passed} passed, {failed} failed")
    if "--offline" not in sys.argv:
        await llm_examples()
    return failed


raise SystemExit(1 if asyncio.run(main()) else 0)
