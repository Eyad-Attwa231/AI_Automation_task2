"""Fake IT data. No real people, passwords or customer info.

Each user is built to trigger one demo scenario:
  u001 -> normal case (VPN fails: outdated VPN client)       [happy path]
  u002 -> locked account (too many failed logins)            [multi-step]
  u003 -> laptop offline for days                            [device worker]
  u004 -> whole branch network is down                       [network worker]
  u005 -> normal user, but network monitor times out once    [tool failure + recovery]
  u006 -> suspicious login from another country              [SECURITY -> human]
"""

USERS = {
    "u001": {"name": "Ahmed Hassan", "site": "Cairo-HQ", "device_id": "d001",
             "account_status": "active", "failed_logins": 0,
             "mfa_enabled": True, "security_flag": False},
    "u002": {"name": "Mona Samir", "site": "Cairo-HQ", "device_id": "d002",
             "account_status": "locked", "failed_logins": 6,
             "mfa_enabled": True, "security_flag": False},
    "u003": {"name": "Omar Khaled", "site": "Cairo-HQ", "device_id": "d003",
             "account_status": "active", "failed_logins": 0,
             "mfa_enabled": True, "security_flag": False},
    "u004": {"name": "Salma Adel", "site": "Alex-Branch", "device_id": "d004",
             "account_status": "active", "failed_logins": 1,
             "mfa_enabled": True, "security_flag": False},
    "u005": {"name": "Youssef Nabil", "site": "Cairo-HQ", "device_id": "d005",
             "account_status": "active", "failed_logins": 0,
             "mfa_enabled": True, "security_flag": False},
    "u006": {"name": "Laila Fathy", "site": "Cairo-HQ", "device_id": "d006",
             "account_status": "active", "failed_logins": 2,
             "mfa_enabled": False, "security_flag": True,
             "security_note": "Login from unusual country (RU) 10 minutes after login from EG"},
}

DEVICES = {
    "d001": {"type": "laptop", "online": True, "os_patched": True,
             "vpn_client_version": "2.1", "last_seen_days": 0},
    "d002": {"type": "laptop", "online": True, "os_patched": True,
             "vpn_client_version": "3.2", "last_seen_days": 0},
    "d003": {"type": "laptop", "online": False, "os_patched": True,
             "vpn_client_version": "3.2", "last_seen_days": 3},
    "d004": {"type": "laptop", "online": True, "os_patched": True,
             "vpn_client_version": "3.2", "last_seen_days": 0},
    "d005": {"type": "laptop", "online": True, "os_patched": True,
             "vpn_client_version": "3.2", "last_seen_days": 0},
    "d006": {"type": "laptop", "online": True, "os_patched": False,
             "vpn_client_version": "3.2", "last_seen_days": 0},
}

MIN_VPN_CLIENT_VERSION = "3.0"

VPN_STATUS = {
    "u001": {"last_attempt": "failed", "error_code": "VPN-619"},
    "u002": {"last_attempt": "failed", "error_code": "VPN-401"},
    "u003": {"last_attempt": "none", "error_code": None},
    "u004": {"last_attempt": "failed", "error_code": "VPN-800"},
    "u005": {"last_attempt": "failed", "error_code": "VPN-800"},
    "u006": {"last_attempt": "success", "error_code": None},
}

NETWORK_STATUS = {
    "Cairo-HQ": {"status": "ok", "latency_ms": 18, "detail": "All links healthy"},
    "Alex-Branch": {"status": "down", "latency_ms": None,
                    "detail": "Uplink failure, ISP ticket ISP-4412 open"},
}

KNOWLEDGE_BASE = [
    {"id": "KB-001", "title": "VPN error 619 / outdated client",
     "keywords": ["vpn", "619", "client", "outdated", "version"],
     "steps": ["Update the VPN client to version 3.0 or newer",
               "Restart the laptop", "Reconnect to the VPN"]},
    {"id": "KB-002", "title": "Locked account",
     "keywords": ["locked", "account", "login", "password", "401"],
     "steps": ["Wait 30 minutes for the automatic unlock, or",
               "Ask the IT helpdesk to verify identity and unlock"]},
    {"id": "KB-003", "title": "Laptop offline",
     "keywords": ["offline", "device", "laptop", "unreachable"],
     "steps": ["Check power and Wi-Fi on the laptop",
               "Connect with a cable if possible", "Contact the helpdesk if still offline"]},
    {"id": "KB-004", "title": "Branch network outage",
     "keywords": ["network", "down", "outage", "branch", "800", "internet"],
     "steps": ["Confirm other colleagues at the site are affected",
               "Check the ISP ticket status", "Use mobile hotspot as a temporary option"]},
    {"id": "KB-005", "title": "Suspicious login",
     "keywords": ["suspicious", "unusual", "hacked", "security", "login", "country"],
     "steps": ["Do NOT self-fix", "Escalate to the security team immediately"]},
]
