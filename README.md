# AI IT Incident Response Agent

Agentic AI final project, Project 1. Built with the OpenAI Agents SDK running on a local Ollama model (qwen2.5:7b). The LLM decides what to do; Python decides what is allowed.

## Flow

User -> Gradio UI -> input guardrail -> triage -> router -> orchestrator -> workers (in parallel) -> troubleshooter <-> evaluator loop -> output guardrail -> reply or human review

## Who decides what

| Decision | Style | Where |
|---|---|---|
| Block credential requests, prompt injection, unsafe admin requests | Code-orchestrated | guardrails.py, workflow.py |
| Route critical or security incidents to a human | Code-orchestrated | triage.py (decide_route), workflow.py |
| Evaluator loop, stop condition, max 3 iterations | Code-orchestrated | resolution.py |
| Python checks for fake "fixed" claims, unsafe steps, invented evidence | Code-orchestrated | resolution.py |
| reset_password needs human approval, one-time | Code-orchestrated | tools.py |
| Retry after a retryable tool failure | Code-orchestrated | investigation.py, tools.py |
| Classify the incident (category, severity, security flag) | LLM-orchestrated | triage.py |
| Choose which workers (network, account, device) to run | LLM-orchestrated | investigation.py (orchestrator agent) |
| Draft the fix plan | LLM-orchestrated | resolution.py (troubleshooter agent) |
| Judge whether the draft is supported by tool results | LLM-orchestrated plus Python checks | resolution.py (evaluator agent) |

## Orchestration patterns

- Prompt chaining: triage (TriageResult) -> investigation (InvestigationResult) -> resolution (Resolution). Intermediate outputs are shown in the UI.
- Routing: decide_route sends critical and security incidents to human review, everything else continues automatically.
- Parallelization: the diagnostic workers run concurrently with asyncio.gather in investigation.py.
- Orchestrator-workers: an orchestrator agent picks workers; the network, account and device workers use different tools.
- Evaluator-optimizer: troubleshooter drafts, evaluator rejects or approves, feedback goes back, maximum 3 iterations, then a human takes over.

## Structured outputs

TriageResult, WorkerFinding, Resolution, EvalResult, IncidentResponse in models.py, with validators for user IDs, empty lists and summary length.

## Guardrails

- Input: credential requests, prompt injection, unsafe administrative actions.
- Output: fabricated "fixed", "password reset" and "ticket created" claims, leaked passwords.
- Tool level: reset_password is blocked until a human approves it, and the approval works once.

## Human in the loop

Security and critical incidents are never closed automatically. Unapproved drafts and admin-only fixes open a ticket for the IT team.

## Memory and tracing

SQLiteSession keeps the conversation per session (sessions.db), so a follow-up without a user ID reuses the earlier one. trace() wraps each incident; the Collector in workflow.py shows agents, tools and generations in the UI.

## Run

    pip install openai-agents gradio pydantic
    ollama pull qwen2.5:7b
    $env:OLLAMA_MODEL = "qwen2.5:7b"
    py app.py

## Tests

    py test_resolution.py --offline
    py test_scenarios.py --fast
    py test_scenarios.py

test_scenarios.py covers the 12 required demo scenarios. demo_my_part.py shows scenarios 7 to 10 without an LLM.

## Team

Eyad Mostafa: data, tools, guardrails, tool failure handling. Ahmed Hmdan : agents, workflow, escalation, tracing and sessions. Together: integration, UI, README.
Submitted to Eng.Ahmed Hassan - EyouthxDEPI5 
