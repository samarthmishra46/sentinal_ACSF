from datetime import datetime, timezone
from typing import List
from app.identity.context import RequestContext

# --- TEAM INTEGRATION POINTS ---
# Ryan:    call EIMClient().get_context(user_id) in app/pep/ingress.py
#          — extract user_id from the incoming request header/body before calling PDP
# Samarth: pipeline.py should receive a fully built RequestContext (not a raw user_id)
#          — Ryan builds the context at the PEP layer and passes it downstream
# Day 2 (Anamika): replace _USER_DATA with a real HTTP call to the EIM service

# Seeded user store: 2 Engineers, 1 Support, 1 SecurityReviewer, 1 ComplianceOfficer
_USER_DATA = {
    "u-001": {
        "user_id": "u-001",
        "role": "Engineer",
        "tenant": "org-acme",
        "owned_services": ["dvs-service", "kyc-engine"],
        "session_token": "tok-001",
    },
    "u-002": {
        "user_id": "u-002",
        "role": "Engineer",
        "tenant": "org-acme",
        "owned_services": ["payment-service"],
        "session_token": "tok-002",
    },
    "u-003": {
        "user_id": "u-003",
        "role": "Support",
        "tenant": "org-acme",
        "owned_services": [],
        "session_token": "tok-003",
    },
    "u-004": {
        "user_id": "u-004",
        "role": "SecurityReviewer",
        "tenant": "org-acme",
        "owned_services": ["*"],
        "session_token": "tok-004",
    },
    "u-005": {
        "user_id": "u-005",
        "role": "ComplianceOfficer",
        "tenant": "org-acme",
        "owned_services": ["*"],
        "session_token": "tok-005",
    },
}


class EIMClient:
    """Mock Enterprise Identity Manager — seeded with 5 test users."""

    def get_context(self, user_id: str) -> RequestContext:
        if user_id not in _USER_DATA:
            raise ValueError(f"Unknown user: {user_id}")
        data = _USER_DATA[user_id]
        return RequestContext(
            user_id=data["user_id"],
            role=data["role"],
            tenant=data["tenant"],
            owned_services=list(data["owned_services"]),
            session_token=data["session_token"],
            timestamp=datetime.now(timezone.utc),
        )

    def list_users(self) -> List[str]:
        return list(_USER_DATA.keys())
