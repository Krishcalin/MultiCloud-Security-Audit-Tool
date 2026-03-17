"""Azure Defender for Cloud (Security Center) service fetcher.

Collected data shape::

    {
        "pricings": {
            "<resourceType>": {
                "name": ..., "pricingTier": "Standard"|"Free",
                "subPlan": ...,
            }
        },
        "security_contacts": {
            "<contactName>": {
                "name": ..., "email": ..., "phone": ...,
                "alertNotifications": "On"|"Off",
                "alertsToAdmins": "On"|"Off",
            }
        },
        "auto_provisioning": {
            "<agentName>": {
                "name": ..., "autoProvision": "On"|"Off",
            }
        },
        "secure_score": {
            "currentScore": float, "maxScore": float, "percentage": float,
        },
        "assessments": {
            "<assessmentId>": {
                "displayName": ..., "status": ..., "severity": ...,
                "resourceId": ...,
            }
        },
        "defender_plans_all_standard": bool,
        "security_contact_configured": bool,
        "auto_provisioning_on": bool,
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)

# CIS 2.0 — Defender plans that should be on Standard tier
_REQUIRED_PLANS = {
    "VirtualMachines", "SqlServers", "AppServices",
    "StorageAccounts", "SqlServerVirtualMachines",
    "KubernetesService", "ContainerRegistry",
    "KeyVaults", "Arm", "Dns",
}


def fetch_security(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "pricings":                    {},
        "security_contacts":           {},
        "auto_provisioning":           {},
        "secure_score":                {},
        "assessments":                 {},
        "defender_plans_all_standard": False,
        "security_contact_configured": False,
        "auto_provisioning_on":        False,
    }

    try:
        from azure.mgmt.security import SecurityCenter  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-security not installed — skipping security fetch")
        return data

    client = SecurityCenter(facade.credential, facade.subscription_id)

    _fetch_pricings(client, data)
    _fetch_security_contacts(client, data)
    _fetch_auto_provisioning(client, data)
    _fetch_secure_score(client, facade.subscription_id, data)
    _derive_flags(data)

    return data


def _fetch_pricings(client: Any, data: dict) -> None:
    try:
        for p in client.pricings.list():
            name = p.name
            data["pricings"][name] = {
                "name":        name,
                "pricingTier": str(p.pricing_tier or "Free"),
                "subPlan":     getattr(p, "sub_plan", None),
            }
    except Exception as exc:
        log.warning("Defender pricings list failed: %s", exc)


def _fetch_security_contacts(client: Any, data: dict) -> None:
    try:
        for c in client.security_contacts.list():
            name = c.name
            data["security_contacts"][name] = {
                "name":               name,
                "email":              getattr(c, "email", ""),
                "phone":              getattr(c, "phone", ""),
                "alertNotifications": str(getattr(c, "alert_notifications", "Off") or "Off"),
                "alertsToAdmins":     str(getattr(c, "alerts_to_admins", "Off") or "Off"),
            }
    except Exception as exc:
        log.warning("Security contacts list failed: %s", exc)


def _fetch_auto_provisioning(client: Any, data: dict) -> None:
    try:
        for ap in client.auto_provisioning_settings.list():
            name = ap.name
            data["auto_provisioning"][name] = {
                "name":          name,
                "autoProvision": str(ap.auto_provision or "Off"),
            }
    except Exception as exc:
        log.warning("Auto-provisioning list failed: %s", exc)


def _fetch_secure_score(client: Any, subscription_id: str, data: dict) -> None:
    try:
        score = client.secure_scores.get("ascScore")
        current = score.current if score.current is not None else 0.0
        maximum = score.max     if score.max     is not None else 0.0
        pct     = (current / maximum * 100) if maximum else 0.0
        data["secure_score"] = {
            "currentScore": round(float(current), 2),
            "maxScore":     round(float(maximum), 2),
            "percentage":   round(pct, 1),
        }
    except Exception as exc:
        log.debug("Secure score fetch failed: %s", exc)


def _derive_flags(data: dict) -> None:
    # All required Defender plans on Standard?
    standard_plans = {
        name for name, p in data["pricings"].items()
        if p.get("pricingTier") == "Standard"
    }
    data["defender_plans_all_standard"] = _REQUIRED_PLANS.issubset(standard_plans)

    # At least one security contact configured with email notifications?
    for c in data["security_contacts"].values():
        if c.get("email") and c.get("alertNotifications", "").lower() == "on":
            data["security_contact_configured"] = True
            break

    # MMA / AMA auto-provisioning enabled?
    for ap in data["auto_provisioning"].values():
        if ap.get("autoProvision", "").lower() == "on":
            data["auto_provisioning_on"] = True
            break
