"""AWS IAM service fetcher.

Collected data shape::

    {
        "account_summary":  { "AccountMFAEnabled": 0, ... },
        "password_policy":  { "MinimumPasswordLength": 14, ... },
        "users": {
            "<UserName>": {
                "UserId": ..., "Arn": ..., "CreateDate": ...,
                "LoginProfile": {...} | None,
                "MFADevices": [...],
                "AccessKeys": [...],
                "AttachedPolicies": [...],
                "InlinePolicies": [...],
                "Groups": [...],
                "PasswordLastUsed": ...,
            }
        },
        "roles": {
            "<RoleName>": {
                "RoleId": ..., "Arn": ..., "AssumeRolePolicyDocument": ...,
                "AttachedPolicies": [...],
                "InlinePolicies": [...],
            }
        },
        "policies": {
            "<PolicyArn>": {
                "PolicyName": ..., "Arn": ..., "AttachmentCount": ...,
                "DefaultVersionDocument": { "Statement": [...] },
            }
        },
        "groups": {
            "<GroupName>": {
                "GroupId": ..., "Arn": ...,
                "AttachedPolicies": [...],
                "InlinePolicies": [...],
                "Users": [...],
            }
        },
        "credential_report": [...],   # raw CSV rows as dicts
        "account_root_access_keys": <bool>,
    }
"""

from __future__ import annotations

import csv
import io
import logging
import time
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_iam(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {}

    data["account_summary"]  = _get_account_summary(facade)
    data["password_policy"]  = _get_password_policy(facade)
    data["users"]            = _get_users(facade)
    data["roles"]            = _get_roles(facade)
    data["policies"]         = _get_customer_policies(facade)
    data["groups"]           = _get_groups(facade)
    data["credential_report"] = _get_credential_report(facade)
    data["account_root_access_keys"] = (
        data["account_summary"].get("AccountAccessKeysPresent", 0) > 0
    )
    return data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_account_summary(facade: Any) -> dict:
    resp = facade.call("iam", "get_account_summary")
    return resp.get("SummaryMap", {})


def _get_password_policy(facade: Any) -> dict:
    resp = facade.call("iam", "get_account_password_policy")
    return resp.get("PasswordPolicy", {})


def _get_users(facade: Any) -> Dict[str, dict]:
    raw_users = facade.paginate("iam", "list_users", "Users")
    users: Dict[str, dict] = {}
    for u in raw_users:
        name = u["UserName"]
        entry: Dict[str, Any] = {
            "UserId":           u.get("UserId", ""),
            "Arn":              u.get("Arn", ""),
            "CreateDate":       u.get("CreateDate"),
            "PasswordLastUsed": u.get("PasswordLastUsed"),
            "LoginProfile":     None,
            "MFADevices":       [],
            "AccessKeys":       [],
            "AttachedPolicies": [],
            "InlinePolicies":   [],
            "Groups":           [],
        }

        # Login profile (console access)
        lp = facade.call("iam", "get_login_profile", UserName=name)
        entry["LoginProfile"] = lp.get("LoginProfile")

        # MFA devices
        entry["MFADevices"] = facade.paginate(
            "iam", "list_mfa_devices", "MFADevices", UserName=name
        )

        # Access keys
        keys = facade.paginate(
            "iam", "list_access_keys", "AccessKeyMetadata", UserName=name
        )
        enriched_keys = []
        for k in keys:
            last_used = facade.call(
                "iam", "get_access_key_last_used",
                AccessKeyId=k["AccessKeyId"]
            )
            k["LastUsed"] = last_used.get("AccessKeyLastUsed", {})
            enriched_keys.append(k)
        entry["AccessKeys"] = enriched_keys

        # Attached managed policies
        entry["AttachedPolicies"] = facade.paginate(
            "iam", "list_attached_user_policies", "AttachedPolicies", UserName=name
        )

        # Inline policy names
        entry["InlinePolicies"] = facade.paginate(
            "iam", "list_user_policies", "PolicyNames", UserName=name
        )

        # Groups
        entry["Groups"] = facade.paginate(
            "iam", "list_groups_for_user", "Groups", UserName=name
        )

        users[name] = entry
    return users


def _get_roles(facade: Any) -> Dict[str, dict]:
    raw_roles = facade.paginate("iam", "list_roles", "Roles")
    roles: Dict[str, dict] = {}
    for r in raw_roles:
        name = r["RoleName"]
        entry: Dict[str, Any] = {
            "RoleId":                   r.get("RoleId", ""),
            "Arn":                      r.get("Arn", ""),
            "CreateDate":               r.get("CreateDate"),
            "AssumeRolePolicyDocument": r.get("AssumeRolePolicyDocument", {}),
            "AttachedPolicies":         [],
            "InlinePolicies":           [],
        }
        entry["AttachedPolicies"] = facade.paginate(
            "iam", "list_attached_role_policies", "AttachedPolicies", RoleName=name
        )
        entry["InlinePolicies"] = facade.paginate(
            "iam", "list_role_policies", "PolicyNames", RoleName=name
        )
        roles[name] = entry
    return roles


def _get_customer_policies(facade: Any) -> Dict[str, dict]:
    raw = facade.paginate(
        "iam", "list_policies", "Policies", Scope="Local"
    )
    policies: Dict[str, dict] = {}
    for p in raw:
        arn      = p["Arn"]
        version  = p.get("DefaultVersionId", "v1")
        doc_resp = facade.call(
            "iam", "get_policy_version", PolicyArn=arn, VersionId=version
        )
        policies[arn] = {
            "PolicyName":            p.get("PolicyName", ""),
            "Arn":                   arn,
            "AttachmentCount":       p.get("AttachmentCount", 0),
            "DefaultVersionDocument": doc_resp.get("PolicyVersion", {}).get("Document", {}),
        }
    return policies


def _get_groups(facade: Any) -> Dict[str, dict]:
    raw = facade.paginate("iam", "list_groups", "Groups")
    groups: Dict[str, dict] = {}
    for g in raw:
        name = g["GroupName"]
        entry: Dict[str, Any] = {
            "GroupId":          g.get("GroupId", ""),
            "Arn":              g.get("Arn", ""),
            "AttachedPolicies": [],
            "InlinePolicies":   [],
            "Users":            [],
        }
        entry["AttachedPolicies"] = facade.paginate(
            "iam", "list_attached_group_policies", "AttachedPolicies", GroupName=name
        )
        entry["InlinePolicies"] = facade.paginate(
            "iam", "list_group_policies", "PolicyNames", GroupName=name
        )
        group_detail = facade.call("iam", "get_group", GroupName=name)
        entry["Users"] = [u["UserName"] for u in group_detail.get("Users", [])]
        groups[name] = entry
    return groups


def _get_credential_report(facade: Any) -> list:
    """Generate (or wait for) the IAM credential report and parse it as a list of dicts."""
    iam = facade.client("iam")
    # Trigger generation
    for _ in range(10):
        try:
            resp = iam.generate_credential_report()
            if resp.get("State") == "COMPLETE":
                break
        except Exception:
            break
        time.sleep(1)

    try:
        resp = iam.get_credential_report()
        content = resp["Content"]
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        return list(reader)
    except Exception as exc:
        log.warning("Could not retrieve credential report: %s", exc)
        return []
