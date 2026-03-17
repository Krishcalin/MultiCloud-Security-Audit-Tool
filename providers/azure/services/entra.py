"""Azure Entra ID (formerly Azure AD) service fetcher via Microsoft Graph API.

Collected data shape::

    {
        "users": {
            "<userId>": {
                "id": ..., "displayName": ..., "userPrincipalName": ...,
                "accountEnabled": bool, "userType": "Member"|"Guest",
                "createdDateTime": ..., "lastSignInDateTime": ...,
                "mfaMethods": [...],        # authentication methods registered
                "adminRoles": [...],        # assigned directory roles
                "isGuest": bool,
            }
        },
        "guest_users": {  ...subset of users where userType=="Guest"... },
        "admin_users": {  ...subset where adminRoles is non-empty... },
        "conditional_access_policies": {
            "<policyId>": {
                "id": ..., "displayName": ..., "state": "enabled"|"disabled",
                "conditions": {...}, "grantControls": {...},
            }
        },
        "security_defaults": {
            "isEnabled": bool,
            "id": ...,
        },
        "named_locations": [...],
        "privileged_roles": {
            "<roleId>": {"id": ..., "displayName": ..., "members": [...]}
        },
        "legacy_auth_blocked": bool,  # True if CA policy blocks legacy auth
        "mfa_enforced_all_users": bool,
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

log = logging.getLogger(__name__)

# High-privilege directory roles to enumerate members for
_PRIVILEGED_ROLE_NAMES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Billing Administrator",
    "User Account Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
}


def fetch_entra(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "users":                       {},
        "guest_users":                 {},
        "admin_users":                 {},
        "conditional_access_policies": {},
        "security_defaults":           {},
        "named_locations":             [],
        "privileged_roles":            {},
        "legacy_auth_blocked":         False,
        "mfa_enforced_all_users":      False,
    }

    _fetch_users(facade, data)
    _fetch_conditional_access(facade, data)
    _fetch_security_defaults(facade, data)
    _fetch_named_locations(facade, data)
    _fetch_privileged_roles(facade, data)
    _derive_mfa_status(data)

    return data


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def _fetch_users(facade: Any, data: dict) -> None:
    raw = facade.graph_paginate(
        "/users",
        params={
            "$select": (
                "id,displayName,userPrincipalName,accountEnabled,userType,"
                "createdDateTime,signInActivity,assignedLicenses"
            ),
            "$top": "999",
        },
    )
    for u in raw:
        uid  = u["id"]
        sign_in = u.get("signInActivity") or {}
        entry: Dict[str, Any] = {
            "id":                   uid,
            "displayName":          u.get("displayName", ""),
            "userPrincipalName":    u.get("userPrincipalName", ""),
            "accountEnabled":       u.get("accountEnabled", True),
            "userType":             u.get("userType", "Member"),
            "createdDateTime":      u.get("createdDateTime"),
            "lastSignInDateTime":   sign_in.get("lastSignInDateTime"),
            "isGuest":              u.get("userType") == "Guest",
            "mfaMethods":           [],
            "adminRoles":           [],
        }

        # Authentication methods (MFA)
        methods = facade.graph_get(f"/users/{uid}/authentication/methods")
        entry["mfaMethods"] = [
            m.get("@odata.type", "").split(".")[-1]
            for m in methods.get("value", [])
            if "passwordAuthentication" not in m.get("@odata.type", "")
        ]

        data["users"][uid] = entry
        if entry["isGuest"]:
            data["guest_users"][uid] = entry


def _derive_mfa_status(data: dict) -> None:
    """Set mfa_enforced_all_users based on whether any enabled member user lacks MFA methods."""
    member_users = [
        u for u in data["users"].values()
        if u.get("accountEnabled") and not u.get("isGuest")
    ]
    if not member_users:
        data["mfa_enforced_all_users"] = True
        return
    data["mfa_enforced_all_users"] = all(
        len(u.get("mfaMethods", [])) > 0 for u in member_users
    )


# ---------------------------------------------------------------------------
# Conditional Access
# ---------------------------------------------------------------------------

def _fetch_conditional_access(facade: Any, data: dict) -> None:
    raw = facade.graph_paginate("/identity/conditionalAccess/policies")
    for p in raw:
        pid = p["id"]
        data["conditional_access_policies"][pid] = {
            "id":            pid,
            "displayName":   p.get("displayName", ""),
            "state":         p.get("state", "disabled"),
            "conditions":    p.get("conditions", {}),
            "grantControls": p.get("grantControls") or {},
            "sessionControls": p.get("sessionControls") or {},
        }

    # Detect if any enabled CA policy blocks legacy authentication
    for policy in data["conditional_access_policies"].values():
        if policy.get("state") != "enabled":
            continue
        client_app_types = (
            policy.get("conditions", {})
            .get("clientAppTypes", [])
        )
        legacy_blocked = any(
            cat in client_app_types
            for cat in ("exchangeActiveSync", "other", "exchangeActiveSync,other")
        )
        grant = policy.get("grantControls") or {}
        if legacy_blocked and grant.get("operator") == "OR" and "block" in grant.get("builtInControls", []):
            data["legacy_auth_blocked"] = True
            break
        # Also check for "block" operator alone
        if legacy_blocked and "block" in grant.get("builtInControls", []):
            data["legacy_auth_blocked"] = True
            break


def _fetch_security_defaults(facade: Any, data: dict) -> None:
    resp = facade.graph_get("/policies/identitySecurityDefaultsEnforcementPolicy")
    data["security_defaults"] = {
        "id":        resp.get("id", ""),
        "isEnabled": resp.get("isEnabled", False),
    }


def _fetch_named_locations(facade: Any, data: dict) -> None:
    raw = facade.graph_paginate("/identity/conditionalAccess/namedLocations")
    data["named_locations"] = raw


# ---------------------------------------------------------------------------
# Privileged roles
# ---------------------------------------------------------------------------

def _fetch_privileged_roles(facade: Any, data: dict) -> None:
    # List all directory role templates
    raw_roles = facade.graph_paginate("/directoryRoles")
    for role in raw_roles:
        if role.get("displayName") not in _PRIVILEGED_ROLE_NAMES:
            continue
        role_id = role["id"]
        members_resp = facade.graph_paginate(f"/directoryRoles/{role_id}/members")
        members = [
            {"id": m.get("id"), "displayName": m.get("displayName"),
             "userPrincipalName": m.get("userPrincipalName")}
            for m in members_resp
        ]
        data["privileged_roles"][role_id] = {
            "id":          role_id,
            "displayName": role.get("displayName", ""),
            "members":     members,
        }

        # Tag users with their admin roles
        for m in members:
            uid = m.get("id")
            if uid and uid in data["users"]:
                data["users"][uid]["adminRoles"].append(role.get("displayName", ""))
                data["admin_users"][uid] = data["users"][uid]
