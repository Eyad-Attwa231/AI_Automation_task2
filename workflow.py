from datetime import datetime

from agents import SQLiteSession, set_tracing_disabled, trace
from agents.tracing import TracingProcessor, custom_span, set_trace_processors

import tools
from guardrails import check_input_text, check_output_text
from investigation import investigate
from llm_setup import setup_llm
from models import IncidentResponse
from resolution import format_reply, run_resolution
from triage import decide_route, find_user_id, run_triage

setup_llm()

LAST_TRACE: list[str] = []


class Collector(TracingProcessor):
    def on_trace_start(self, t):
        LAST_TRACE.clear()
        LAST_TRACE.append(f"{'workflow':<11} {t.name}")

    def on_trace_end(self, t):
        pass

    def on_span_start(self, span):
        pass

    def on_span_end(self, span):
        d = span.span_data
        kind = getattr(d, "type", "span")
        name = getattr(d, "name", None) or getattr(d, "model", None) or ""
        ms = ""
        try:
            a = datetime.fromisoformat(span.started_at)
            b = datetime.fromisoformat(span.ended_at)
            ms = f"{int((b - a).total_seconds() * 1000)} ms"
        except Exception:
            pass
        LAST_TRACE.append(f"{kind:<11} {name}  {ms}".rstrip())

    def shutdown(self):
        pass

    def force_flush(self):
        pass


set_tracing_disabled(False)
set_trace_processors([Collector()])


def verdict(r):
    if not isinstance(r, dict):
        return False, ""
    blocked = any(bool(r.get(k)) for k in ("blocked", "tripwire", "tripwire_triggered", "unsafe", "flagged", "violation"))
    for k in ("allowed", "ok", "safe", "passed"):
        if k in r and not r[k]:
            blocked = True
    reason = next((str(r[k]) for k in ("reason", "rule", "category", "message", "type") if r.get(k)), "")
    return blocked, reason


def workers_of(inv):
    try:
        d = inv.model_dump()
    except Exception:
        return []
    for v in d.values():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            for k in ("worker", "area"):
                if k in v[0]:
                    return [str(x[k]) for x in v]
        if isinstance(v, dict) and isinstance(v.get("workers"), list):
            return [str(x) for x in v["workers"]]
    return []


def open_ticket(user_id, category, priority, summary):
    try:
        r = tools.create_ticket(user_id, category, priority, summary)
    except Exception:
        return None
    if isinstance(r, dict):
        return r.get("ticket_id") or r.get("id")
    return None


def ticket_note(tid):
    return f" Ticket {tid} is open for the IT team." if tid else ""


async def last_user(session):
    try:
        items = await session.get_items()
    except Exception:
        return None
    for it in reversed(items):
        if isinstance(it, dict) and it.get("role") == "user":
            uid = find_user_id(str(it.get("content", "")))
            if uid:
                return uid
    return None


async def remember(session, text, reply):
    try:
        await session.add_items([{"role": "user", "content": text}, {"role": "assistant", "content": reply}])
    except Exception:
        pass


async def pipeline(text, session, steps):
    with custom_span("input guardrail"):
        blocked, reason = verdict(check_input_text(text))
    if blocked:
        steps.append(f"input guardrail: blocked ({reason})")
        return IncidentResponse(
            reply="I can't help with that request. I never share credentials or bypass security controls. Please contact the IT helpdesk if you need access.",
            steps=steps, blocked_reason=reason or "input guardrail")
    steps.append("input guardrail: passed")

    working = text
    if not find_user_id(text):
        prev = await last_user(session)
        if prev:
            working = f"{text} (user {prev})"
            steps.append(f"session: reused user {prev}")

    try:
        with custom_span("triage"):
            triage = await run_triage(working)
    except Exception:
        steps.append("triage: failed")
        uid = find_user_id(working)
        if not uid:
            return IncidentResponse(
                reply="I could not understand the request. Please include your user ID (for example u001) and describe the problem.",
                steps=steps)
        tid = open_ticket(uid, "other", "medium", text[:200])
        return IncidentResponse(
            reply="I could not classify this request automatically, so it was passed to the IT team." + ticket_note(tid),
            steps=steps + ["routed: human"], needs_human=True)
    steps.append(f"triage: {triage.category} / {triage.severity} / security={triage.is_security_incident}")

    with custom_span("routing"):
        route, why = decide_route(triage, working)
    human = ("human" in str(route).lower() or "escalat" in str(route).lower()
             or triage.is_security_incident or triage.severity == "critical")
    steps.append(f"routed: {'human' if human else 'normal'} ({why})")

    if human:
        tid = open_ticket(triage.user_id, triage.category, triage.severity, triage.summary)
        return IncidentResponse(
            reply="This incident must be reviewed by a person and was not handled automatically. An IT specialist will follow up." + ticket_note(tid),
            triage=triage.model_dump(), steps=steps, needs_human=True)

    with custom_span("investigation"):
        inv = await investigate(triage, working)
    ws = workers_of(inv)
    steps.append("investigation: workers=" + (",".join(ws) if ws else "done"))

    with custom_span("resolution"):
        res = await run_resolution(triage, inv)
    for it in res.iterations:
        ev = it.evaluation
        steps.append(f"evaluator loop {it.number}: {'approved' if ev and ev.approved else 'rejected'}")
    steps.append(f"resolution: {'approved' if res.approved else res.reason}")

    reply = format_reply(res)
    needs_human = (not res.approved) or bool(res.resolution and res.resolution.needs_human)

    with custom_span("output guardrail"):
        blocked, reason = verdict(check_output_text(reply))
    if blocked:
        steps.append(f"output guardrail: blocked ({reason})")
        reply = "I could not produce a verified answer, so this will be reviewed by the IT team."
        needs_human = True
    else:
        steps.append("output guardrail: passed")

    if needs_human:
        tid = open_ticket(triage.user_id, triage.category, triage.severity, triage.summary)
        reply += ticket_note(tid)
        steps.append("human review requested")

    return IncidentResponse(reply=reply, triage=triage.model_dump(), steps=steps, needs_human=needs_human)


async def handle_incident(text, session_id="default"):
    session = SQLiteSession(session_id, "sessions.db")
    steps: list[str] = []
    try:
        with trace("IT Incident Response", group_id=session_id):
            resp = await pipeline(text, session, steps)
    except Exception as e:
        resp = IncidentResponse(
            reply="Something went wrong on our side, so this request was passed to the IT team for review.",
            steps=steps + [f"error: {type(e).__name__}"], needs_human=True)
    await remember(session, text, resp.reply)
    return resp
