"""Azure Container Registry (ACR) fetcher.

Collected data shape::

    {
        "registries": {
            "<registryName>": {
                "name": str,
                "location": str,
                "resourceGroup": str,
                "sku": str,
                "loginServer": str,
                "adminUserEnabled": bool,
                "publicNetworkAccess": str,    # "Enabled" | "Disabled"
                "networkRuleBypassOptions": str,
                "defenderEnabled": bool,
                "contentTrustEnabled": bool,
                "tags": dict,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_containerregistry(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"registries": {}}

    try:
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-containerregistry not installed — skipping ACR fetch")
        return data

    client = ContainerRegistryManagementClient(facade.credential, facade.subscription_id)

    try:
        registries = list(client.registries.list())
    except Exception as exc:
        log.warning("ACR: list registries failed: %s", exc)
        return data

    for reg in registries:
        name = reg.name
        try:
            entry = _build_registry(client, reg)
            data["registries"][name] = entry
        except Exception as exc:
            log.warning("ACR registry %s: %s", name, exc)
            data["registries"][name] = {"name": name, "error": str(exc)}

    return data


def _build_registry(client: Any, reg: Any) -> Dict[str, Any]:
    rg   = _parse_rg(getattr(reg, "id", ""))
    name = reg.name

    sku_obj = getattr(reg, "sku", None)
    sku_name = str(getattr(sku_obj, "name", "")) if sku_obj else ""

    public_network = str(getattr(reg, "public_network_access", "Enabled") or "Enabled")

    # Content trust (only available on Premium SKU)
    policies = getattr(reg, "policies", None)
    content_trust = False
    if policies:
        trust_policy = getattr(policies, "trust_policy", None)
        if trust_policy:
            content_trust = str(getattr(trust_policy, "status", "disabled")).lower() == "enabled"

    # Defender for Containers — check via Defender plan (best-effort via metadata)
    defender_enabled = False
    try:
        # Try to read the tag set for Defender indication (heuristic)
        tags = dict(getattr(reg, "tags", {}) or {})
        defender_enabled = tags.get("MicrosoftDefenderForContainersEnabled", "").lower() == "true"
    except Exception:
        pass

    return {
        "name":                     name,
        "location":                 getattr(reg, "location", ""),
        "resourceGroup":            rg,
        "sku":                      sku_name,
        "loginServer":              getattr(reg, "login_server", ""),
        "adminUserEnabled":         getattr(reg, "admin_user_enabled", False) or False,
        "publicNetworkAccess":      public_network,
        "networkRuleBypassOptions": str(getattr(reg, "network_rule_bypass_options", "") or ""),
        "defenderEnabled":          defender_enabled,
        "contentTrustEnabled":      content_trust,
        "tags":                     dict(getattr(reg, "tags", {}) or {}),
    }


def _parse_rg(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""
