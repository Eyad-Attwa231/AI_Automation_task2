"""Run:  py test_resolution.py            (offline tests, then real LLM examples)
       py test_resolution.py --offline   (only offline tests)"""
import asyncio
import sys

import tools
from investigation import InvestigationPlan, InvestigationResult, WorkerReport, investigate
from models import EvalResult, Resolution, TriageResult, WorkerFinding
from resolution import (MAX_ITERATIONS, format_reply, python_checks, run_resolution)
from triage import triage_and_route

passed = failed = 0


def check(name, cond):
    global passed, failed
    passed += bool(cond)
    failed += not cond
    print(("PASS  " if cond else "FAIL  ") + name)


TRIAGE = TriageResult(user_id="u001", category="vpn", severity="medium",
                      is_security_incident=False, summary="VPN error 619")
EVIDENCE = "{'status': 'ok', 'last_attempt': 'failed', 'error_code': 'VPN-619'}\n" \
           "{'status': 'ok', 'vpn_client_version': '2.1', 'vpn_client_outdated': True}"


def inv(with_evidence=True):
    rep = WorkerReport(worker="device",
                       finding=WorkerFinding(area="device", issue_found=True, findings="VPN client outdated",
                                             tools_used=["check_device_status"]),
                       tool_results=[EVIDENCE] if with_evidence else [])
    return InvestigationResult(plan=InvestigationPlan(workers=["device"], reasoning="t"),
                               plan_source="llm", reports=[rep])


GOOD = Resolution(steps=["Update the VPN client to version 3.0 or newer", "Restart the laptop and reconnect"],
                  evidence=["VPN error code VPN-619", "VPN client version 2.1 is outdated"],
                  needs_human=False, confidence="high")


async def approve_all(draft, ev):
    return EvalResult(approved=True, unsupported_claims=[], feedback="")


async def reject_all(draft, ev):
    return EvalResult(approved=False, unsupported_claims=["not supported"], feedback="Fix it")


async def good_gen(ctx):
    return GOOD


async def offline_tests():
    # --- Python checks ---
    check("python checks: good draft passes", python_checks(GOOD, EVIDENCE) == [])
    bad_claim = Resolution(steps=["Your VPN issue has been fixed."], evidence=["VPN error code VPN-619"],
                           needs_human=False, confidence="high")
    check("python checks: fake 'fixed' claim caught",
          any("output rule" in p for p in python_checks(bad_claim, EVIDENCE)))
    invented = Resolution(steps=["Reboot the router"], evidence=["The router firmware is 9.9.9"],
                          needs_human=False, confidence="low")
    check("python checks: invented evidence caught",
          any("not found in tool results" in p for p in python_checks(invented, EVIDENCE)))
    unsafe = Resolution(steps=["Disable the firewall and retry"], evidence=["VPN error code VPN-619"],
                        needs_human=False, confidence="low")
    check("python checks: unsafe step caught", any("unsafe" in p for p in python_checks(unsafe, EVIDENCE)))

    # --- loop behaviour ---
    r = await run_resolution(TRIAGE, inv(), generate_fn=good_gen, evaluate_fn=approve_all)
    check("good draft approved on iteration 1", r.approved and len(r.iterations) == 1 and r.reason == "approved")

    r = await run_resolution(TRIAGE, inv(), generate_fn=good_gen, evaluate_fn=approve_all, bad_first_draft=True)
    check("scenario 6: bad first draft REJECTED, revision approved",
          r.approved and len(r.iterations) == 2 and not r.iterations[0].evaluation.approved)

    r = await run_resolution(TRIAGE, inv(), generate_fn=good_gen, evaluate_fn=reject_all)
    check(f"loop stops after {MAX_ITERATIONS} iterations", (not r.approved) and len(r.iterations) == MAX_ITERATIONS
          and r.reason == "max_iterations")

    calls = {"n": 0}

    async def spy_gen(ctx):
        calls["n"] += 1
        return GOOD
    r = await run_resolution(TRIAGE, inv(with_evidence=False), generate_fn=spy_gen, evaluate_fn=approve_all)
    check("no tool evidence -> no LLM call, human review",
          r.reason == "no_evidence" and not r.approved and calls["n"] == 0)

    async def crashing_gen(ctx):
        raise RuntimeError("model down")
    r = await run_resolution(TRIAGE, inv(), generate_fn=crashing_gen, evaluate_fn=approve_all)
    check("generator crashing is handled (no exception, ends at max)",
          not r.approved and len(r.iterations) == MAX_ITERATIONS)

    seen = {}

    async def feedback_gen(ctx):
        seen.setdefault("feedback", []).append(ctx["feedback"])
        return GOOD
    await run_resolution(TRIAGE, inv(), generate_fn=feedback_gen, evaluate_fn=approve_all, bad_first_draft=True)
    check("evaluator feedback is passed to the next draft", seen["feedback"] and seen["feedback"][0] != "")

    async def evaluator_down(draft, ev):
        raise RuntimeError("evaluator down")
    r = await run_resolution(TRIAGE, inv(), generate_fn=good_gen, evaluate_fn=evaluator_down)
    check("LLM evaluator down -> Python checks still decide", r.approved and "unavailable" in r.iterations[0].note)

    async def bad_gen(ctx):
        return bad_claim
    r = await run_resolution(TRIAGE, inv(), generate_fn=bad_gen, evaluate_fn=evaluator_down)
    check("LLM evaluator down + bad draft -> still rejected by Python", not r.approved)

    # --- user-facing text ---
    check("unapproved result never shown as advice",
          "could not produce a verified solution" in format_reply(r))
    good = await run_resolution(TRIAGE, inv(), generate_fn=good_gen, evaluate_fn=approve_all)
    check("approved result shows steps", "Update the VPN client" in format_reply(good))


async def llm_examples():
    print("\n=== REAL LLM EXAMPLES (can take several minutes) ===")
    cases = [("u001: I can't connect to the VPN, error 619", False),
             ("u001: I can't connect to the VPN, error 619", True),    # scenario 6 demo
             ("u004: The whole Alexandria branch has no internet", False)]
    for text, bad in cases:
        tools.reset_demo_state()
        print(f"\n>>> {text}" + ("   [DEMO: bad first draft]" if bad else ""))
        try:
            d = await triage_and_route(text)
            if d.path != "auto":
                print("    not auto:", d.path)
                continue
            i = await investigate(d.triage, text)
            res = await run_resolution(d.triage, i, bad_first_draft=bad)
            for s in res.steps:
                print("   ", s)
            print("    --- reply to user ---")
            print("    " + format_reply(res).replace("\n", "\n    "))
        except Exception as e:
            print("    ERROR:", type(e).__name__, e)


async def main():
    await offline_tests()
    print(f"\n{passed} passed, {failed} failed")
    if "--offline" not in sys.argv:
        await llm_examples()
    return failed


raise SystemExit(1 if asyncio.run(main()) else 0)
