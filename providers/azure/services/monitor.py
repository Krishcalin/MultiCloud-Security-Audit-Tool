"""Azure Monitor service fetcher — Activity Log alerts, diagnostic settings, log profiles.

Collected data shape::

    {
        "activity_log_alerts": {
            "<alertId>": {
                "name": ..., "location": ..., "enabled": bool,
                "scopes": [...], "condition": {...}, "actions": {...},
                "operationName": ...,   # derived from condition
            }
        },
        "log_profiles": {
            "<profileName>": {
                "name": ..., "locations": [...], "categories": [...],
                "retentionDays": int, "storageAccountId": ...,
                "serviceBusRuleId": ...,
            }
        },
        "diagnostic_settings_subscription": [...],
        "required_alerts_present": {
            "create_policy":           bool,
            "delete_policy":           bool,
            "create_nsg":              bool,
            "delete_nsg":              bool,
            "create_security_solution": bool,
            "delete_security_solution": bool,
            "create_sql_server_fw":    bool,
            "update_security_policy":  bool,
            "create_update_public_ip": bool,
            "delete_virtual_network":  bool,
            "create_update_nsg_rule":  bool,
        },
        "log_retention_days": int,   # 0 = no profile / no retention configured
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)

# CIS Azure 2.0 — required activity log alert operation names
_REQUIRED_ALERT_OPS = {
    "create_policy":            "Microsoft.Authorization/policyAssignments/write",
    "delete_policy":            "Microsoft.Authorization/policyAssignments/delete",
    "create_nsg":               "Microsoft.Network/networkSecurityGroups/write",
    "delete_nsg":               "Microsoft.Network/networkSecurityGroups/delete",
    "create_security_solution": "Microsoft.Security/securitySolutions/write",
    "delete_security_solution": "Microsoft.Security/securitySolutions/delete",
    "create_sql_server_fw":     "Microsoft.Sql/servers/firewallRules/write",
    "update_security_policy":   "Microsoft.Security/policies/write",
    "create_update_public_ip":  "Microsoft.Network/publicIPAddresses/write",
    "delete_virtual_network":   "Microsoft.Network/virtualNetworks/delete",
    "create_update_nsg_rule":   "Microsoft.Network/networkSecurityGroups/securityRules/write",
}


def fetch_monitor(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "activity_log_alerts":             {},
        "log_profiles":                    {},
        "diagnostic_settings_subscription": [],
        "required_alerts_present":         {k: False for k in _REQUIRED_ALERT_OPS},
        "log_retention_days":              0,
    }

    try:
        from azure.mgmt.monitor import MonitorManagementClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-monitor not installed — skipping monitor fetch")
        return data

    client = MonitorManagementClient(facade.credential, facade.subscription_id)
    sub_scope = f"/subscriptions/{facade.subscription_id}"

    _fetch_activity_log_alerts(client, sub_scope, data)
    _fetch_log_profiles(client, data)
    _derive_required_alerts(data)

    return data


def _fetch_activity_log_alerts(client: Any, sub_scope: str, data: dict) -> None:
    try:
        alerts = list(client.activity_log_alerts.list_by_subscription_id())
    except Exception as exc:
        log.warning("Activity log alerts list failed: %s", exc)
        return

    for alert in alerts:
        aid = alert.id
        conditions = alert.condition.all_of if (alert.condition and alert.condition.all_of) else []
        op_name = ""
        for cond in conditions:
            if getattr(cond, "field", "") == "operationName":
                op_name = getattr(cond, "equals", "")
                break

        data["activity_log_alerts"][aid] = {
            "name":          alert.name,
            "location":      alert.location,
            "enabled":       bool(alert.enabled),
            "scopes":        list(alert.scopes or []),
            "condition":     _parse_condition(alert.condition),
            "actions":       _parse_actions(alert.actions),
            "operationName": op_name,
        }


def _parse_condition(cond: Any) -> dict:
    if not cond:
        return {}
    return {
        "allOf": [
            {"field": getattr(c, "field", ""), "equals": getattr(c, "equals", "")}
            for c in (cond.all_of or [])
        ]
    }


def _parse_actions(actions: Any) -> dict:
    if not actions:
        return {}
    groups = []
    for ag in (getattr(actions, "action_groups", []) or []):
        groups.append({"actionGroupId": ag.action_group_id})
    return {"actionGroups": groups}


def _fetch_log_profiles(client: Any, data: dict) -> None:
    try:
        profiles = list(client.log_profiles.list())
    except Exception as exc:
        log.warning("Log profiles list failed: %s", exc)
        return

    for p in profiles:
        name = p.name
        ret_days = 0
        if p.retention_policy and p.retention_policy.enabled:
            ret_days = p.retention_policy.days or 0

        data["log_profiles"][name] = {
            "name":              name,
            "locations":         list(p.locations or []),
            "categories":        list(p.categories or []),
            "retentionDays":     ret_days,
            "storageAccountId":  p.storage_account_id,
            "serviceBusRuleId":  p.service_bus_rule_id,
        }

        # Track maximum retention
        if ret_days > data["log_retention_days"]:
            data["log_retention_days"] = ret_days


def _derive_required_alerts(data: dict) -> None:
    """Check which CIS-required alert operation names are covered by enabled alerts."""
    enabled_ops = {
        alert["operationName"]
        for alert in data["activity_log_alerts"].values()
        if alert.get("enabled") and alert.get("operationName")
    }
    for key, op in _REQUIRED_ALERT_OPS.items():
        data["required_alerts_present"][key] = (op in enabled_ops)
