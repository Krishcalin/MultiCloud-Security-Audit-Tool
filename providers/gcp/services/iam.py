"""GCP IAM service fetcher.

Data shape
----------
::

    {
        "project_iam": {
            "hasPrimitiveOwnerEditor": bool,   # roles/owner or roles/editor assigned
            "bindings": [...],                 # raw IAM bindings list
        },
        "service_accounts": {
            "<sa_email>": {
                "email":                str,
                "disabled":             bool,
                "hasAdminRole":         bool,  # bound to owner/editor/iam-admin in project
                "staleKeys":            bool,  # user-managed key older than 90 days
                "userManagedKeysCount": int,
            },
            ...
        },
    }
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

log = logging.getLogger(__name__)

# Roles considered overly privileged for a service account
_SA_ADMIN_ROLES = {
    "roles/owner",
    "roles/editor",
    "roles/iam.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin",
}

# Roles considered primitive (owner / editor)
_PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}

# Keys older than this many days are considered stale
_KEY_AGE_DAYS = 90


def fetch_iam(facade: Any) -> Dict[str, Any]:
    """Fetch IAM project policy and service account metadata."""
    data: Dict[str, Any] = {
        "project_iam":      {},
        "service_accounts": {},
    }

    crm = facade.discovery("cloudresourcemanager", "v3")
    iam = facade.discovery("iam", "v1")

    # ------------------------------------------------------------------
    # 1. Project IAM policy
    # ------------------------------------------------------------------
    bindings: list = []
    try:
        policy = crm.projects().getIamPolicy(
            resource=f"projects/{facade.project_id}",
            body={},
        ).execute()
        bindings = policy.get("bindings", [])
    except Exception as exc:
        log.warning("GCP IAM: could not fetch project IAM policy: %s", exc)

    has_primitive = any(b.get("role") in _PRIMITIVE_ROLES for b in bindings)

    data["project_iam"] = {
        "hasPrimitiveOwnerEditor": has_primitive,
        "bindings":                bindings,
    }

    # ------------------------------------------------------------------
    # 2. Service accounts
    # ------------------------------------------------------------------
    sas: list = []
    try:
        req = iam.projects().serviceAccounts().list(
            name=f"projects/{facade.project_id}"
        )
        while req is not None:
            resp = req.execute()
            sas.extend(resp.get("accounts", []))
            req = iam.projects().serviceAccounts().list_next(req, resp)
    except Exception as exc:
        log.warning("GCP IAM: could not list service accounts: %s", exc)

    now = datetime.now(timezone.utc)

    for sa in sas:
        email   = sa.get("email", "")
        sa_name = sa.get("name", "")

        # Check if SA has admin/privileged roles in the project policy
        sa_member = f"serviceAccount:{email}"
        sa_roles  = {
            b.get("role", "")
            for b in bindings
            if sa_member in b.get("members", [])
        }
        has_admin = bool(sa_roles & _SA_ADMIN_ROLES)

        # User-managed keys (auto-rotated AWS-style keys are NOT listed here)
        keys: list = []
        stale = False
        try:
            keys_resp = iam.projects().serviceAccounts().keys().list(
                name=sa_name,
                keyTypes=["USER_MANAGED"],
            ).execute()
            keys = keys_resp.get("keys", [])
            for key in keys:
                valid_after = key.get("validAfterTime", "")
                if valid_after:
                    try:
                        created = datetime.fromisoformat(
                            valid_after.replace("Z", "+00:00")
                        )
                        if (now - created) > timedelta(days=_KEY_AGE_DAYS):
                            stale = True
                            break
                    except (ValueError, TypeError):
                        pass
        except Exception as exc:
            log.debug("GCP IAM: could not list keys for %s: %s", email, exc)

        data["service_accounts"][email] = {
            "email":                email,
            "disabled":             sa.get("disabled", False),
            "hasAdminRole":         has_admin,
            "staleKeys":            stale,
            "userManagedKeysCount": len(keys),
        }

    return data
