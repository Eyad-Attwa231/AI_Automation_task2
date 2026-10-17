"""Domain tools for the IT Incident agent.

Design rule: "LLM decides what to do, Python decides what is allowed".
- Every tool is a plain Python function (easy to test), wrapped at the bottom
  with function_tool so agents can call it.
- Every tool is wrapped by @safe_tool, so errors become clean error dicts
  instead of crashing the app (reliability requirement).
- reset_password is PROTECTED: it only works after a human approved it.
"""
import functools
import re

from agents import function_tool

import data

# ---- shared state (in memory, fine for a demo) ----
CONFIRMED_ACTIONS: set[str] = set()   # filled ONLY when a tool really did something
APPROVED_RESETS: set[str] = set()     # filled ONLY by a human via approve_reset()
TICKETS: list[dict] = []

# Simulated failure: network monitor times out ONCE for u005, then works.
_FAIL_ONCE = {"u005": True}

VALID_CATEGORIES = {"vpn", "account", "device", "network", "security", "other"}
VALID_PRIORITIES = {"low", "medium", "high", "critical"}


def reset_demo_state() -> None:
    """Call between demo runs / tests."""
    CONFIRMED_ACTIONS.clear()
    APPROVED_RESETS.clear()
    TICKETS.clear()
    _FAIL_ONCE.clear()
    _FAIL_ONCE["u005"] = True


# ---- helpers ----
def safe_tool(func):
    """Turn exceptions into error dicts so the workflow can recover."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except TimeoutError as e:
            return {"status": "error", "error_type": "timeout",
                    "message": str(e), "retryable": True}
        except Exception as e:  # noqa
            return {"status": "error", "error_type": type(e).__name__,
                    "message": str(e), "retryable": False}
    return wrapper


def _validate_user(user_id: str):
    """Return (user, None) if OK, else (None, error_dict)."""
    if not isinstance(user_id, str) or not re.fullmatch(r"u\d{3}", user_id.strip()):
        return None, {"status": "error", "error_type": "invalid_input",
                      "message": "user_id must look like 'u001'", "retryable": False}
    user = data.USERS.get(user_id.strip())
    if user is None:
        return None, {"status": "error", "error_type": "not_found",
                      "message": f"No user {user_id}", "retryable": False}
    return user, None


def _version_tuple(v: str):
    return tuple(int(x) for x in v.split("."))


# ---- investigation tools (read-only) ----
@safe_tool
def check_account_status(user_id: str) -> dict:
    """Check a user's account: active/locked, failed logins, MFA, security flag.

    Args:
        user_id: The user ID, for example 'u001'.
    """
    user, err = _validate_user(user_id)
    if err:
        return err
    result = {"status": "ok", "user_id": user_id, "name": user["name"],
              "account_status": user["account_status"],
              "failed_logins": user["failed_logins"],
              "mfa_enabled": user["mfa_enabled"],
              "security_flag": user["security_flag"]}
    if user["security_flag"]:
        result["security_note"] = user.get("security_note", "")
    return result


@safe_tool
def check_vpn_status(user_id: str) -> dict:
    """Check the user's last VPN attempt and error code.

    Args:
        user_id: The user ID, for example 'u001'.
    """
    user, err = _validate_user(user_id)
    if err:
        return err
    vpn = data.VPN_STATUS[user_id]
    return {"status": "ok", "user_id": user_id, **vpn}


@safe_tool
def check_device_status(user_id: str) -> dict:
    """Check the user's laptop: online, patched, VPN client version.

    Args:
        user_id: The user ID, for example 'u001'.
    """
    user, err = _validate_user(user_id)
    if err:
        return err
    dev = data.DEVICES[user["device_id"]]
    outdated = _version_tuple(dev["vpn_client_version"]) < _version_tuple(data.MIN_VPN_CLIENT_VERSION)
    return {"status": "ok", "user_id": user_id, "device_id": user["device_id"],
            **dev, "vpn_client_outdated": outdated,
            "min_vpn_client_version": data.MIN_VPN_CLIENT_VERSION}


@safe_tool
def check_network_status(user_id: str) -> dict:
    """Check the network health of the site where the user works.

    Args:
        user_id: The user ID, for example 'u001'.
    """
    user, err = _validate_user(user_id)
    if err:
        return err
    if _FAIL_ONCE.get(user_id):          # simulated outage of the monitoring service
        _FAIL_ONCE[user_id] = False
        raise TimeoutError("Network monitoring service timed out")
    net = data.NETWORK_STATUS[user["site"]]
    return {"status": "ok", "user_id": user_id, "site": user["site"], **net}


@safe_tool
def search_it_knowledge(query: str) -> dict:
    """Search the IT knowledge base for fix steps.

    Args:
        query: Short keywords such as 'vpn 619' or 'locked account'.
    """
    if not isinstance(query, str) or not query.strip():
        return {"status": "error", "error_type": "invalid_input",
                "message": "query must not be empty", "retryable": False}
    words = set(re.findall(r"[a-z0-9]+", query.lower()))
    scored = []
    for art in data.KNOWLEDGE_BASE:
        score = len(words & set(art["keywords"]))
        if score:
            scored.append((score, art))
    scored.sort(key=lambda x: -x[0])
    return {"status": "ok", "query": query,
            "articles": [a for _, a in scored[:2]]}   # empty list = nothing found


# ---- action tools ----
@safe_tool
def create_ticket(user_id: str, category: str, priority: str, summary: str) -> dict:
    """Create an IT ticket. Security tickets are always escalated to a human.

    Args:
        user_id: The user ID, for example 'u001'.
        category: One of vpn, account, device, network, security, other.
        priority: One of low, medium, high, critical.
        summary: One or two sentences describing the problem.
    """
    user, err = _validate_user(user_id)
    if err:
        return err
    category, priority = str(category).lower().strip(), str(priority).lower().strip()
    if category not in VALID_CATEGORIES:
        return {"status": "error", "error_type": "invalid_input",
                "message": f"category must be one of {sorted(VALID_CATEGORIES)}", "retryable": False}
    if priority not in VALID_PRIORITIES:
        return {"status": "error", "error_type": "invalid_input",
                "message": f"priority must be one of {sorted(VALID_PRIORITIES)}", "retryable": False}
    if not isinstance(summary, str) or len(summary.strip()) < 5:
        return {"status": "error", "error_type": "invalid_input",
                "message": "summary is too short", "retryable": False}

    # Python rule: security or critical tickets are NEVER auto-handled
    needs_human = category == "security" or priority == "critical" or user["security_flag"]
    ticket_id = f"TCK-{len(TICKETS) + 1:03d}"
    ticket = {"ticket_id": ticket_id, "user_id": user_id, "category": category,
              "priority": priority, "summary": summary.strip(),
              "state": "escalated_to_human" if needs_human else "open"}
    TICKETS.append(ticket)
    CONFIRMED_ACTIONS.add(f"ticket:{ticket_id}")
    return {"status": "ok", **ticket}


# ---- PROTECTED action ----
def approve_reset(user_id: str, approver: str) -> dict:
    """NOT a tool. Only the human/UI calls this (for example a Gradio 'Approve' button)."""
    user, err = _validate_user(user_id)
    if err:
        return err
    if not approver or not approver.strip():
        return {"status": "error", "error_type": "invalid_input",
                "message": "approver name required", "retryable": False}
    APPROVED_RESETS.add(user_id)
    return {"status": "ok", "approved": user_id, "by": approver.strip()}


@safe_tool
def reset_password(user_id: str) -> dict:
    """Reset a user's password. PROTECTED: works only after a human approved it.

    Args:
        user_id: The user ID, for example 'u002'.
    """
    user, err = _validate_user(user_id)
    if err:
        return err
    if user["security_flag"]:
        return {"status": "blocked", "reason":
                "Security-flagged account: a human security analyst must handle this."}
    if user_id not in APPROVED_RESETS:
        return {"status": "blocked", "reason":
                "Password reset needs human approval first. Ask a human to approve."}
    APPROVED_RESETS.discard(user_id)           # approval is one-time
    CONFIRMED_ACTIONS.add(f"password_reset:{user_id}")
    return {"status": "ok", "user_id": user_id,
            "message": "Password reset done. Temporary credential sent via the secure channel."}


# ---- what the agents actually receive ----
INVESTIGATION_TOOLS = [function_tool(f) for f in (
    check_account_status, check_vpn_status, check_device_status,
    check_network_status, search_it_knowledge)]
ACTION_TOOLS = [function_tool(f) for f in (create_ticket, reset_password)]
ALL_TOOLS = INVESTIGATION_TOOLS + ACTION_TOOLS
