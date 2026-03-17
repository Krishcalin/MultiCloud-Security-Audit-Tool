"""Azure Cosmos DB fetcher.

Collected data shape::

    {
        "accounts": {
            "<accountName>": {
                "name": str,
                "location": str,
                "resourceGroup": str,
                "kind": str,
                "consistencyLevel": str,
                "publicNetworkAccess": str,    # "Enabled" | "Disabled"
                "ipRulesCount": int,
                "isIpFirewallConfigured": bool,
                "automaticFailover": bool,
                "multipleWriteLocations": bool,
                "backupPolicy": str,           # "Periodic" | "Continuous"
                "locations": list[str],
                "tags": dict,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_cosmosdb(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"accounts": {}}

    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-cosmosdb not installed — skipping Cosmos DB fetch")
        return data

    client = CosmosDBManagementClient(facade.credential, facade.subscription_id)

    try:
        accounts = list(client.database_accounts.list())
    except Exception as exc:
        log.warning("Cosmos DB: list accounts failed: %s", exc)
        return data

    for acct in accounts:
        name = acct.name
        try:
            entry = _build_account(acct)
            data["accounts"][name] = entry
        except Exception as exc:
            log.warning("Cosmos DB account %s: %s", name, exc)
            data["accounts"][name] = {"name": name, "error": str(exc)}

    return data


def _build_account(acct: Any) -> Dict[str, Any]:
    rg = _parse_rg(getattr(acct, "id", ""))

    # Public network access
    public_network = str(getattr(acct, "public_network_access", "Enabled") or "Enabled")

    # IP firewall rules
    ip_rules     = list(getattr(acct, "ip_rules", None) or [])
    ip_rules_count = len(ip_rules)
    # Exclude the Azure portal / AzureCloud catchall rule
    real_ip_rules = [r for r in ip_rules if str(getattr(r, "ip_address_or_range", "")) not in ("0.0.0.0", "")]
    ip_firewall   = len(real_ip_rules) > 0

    # Failover
    auto_failover = getattr(acct, "enable_automatic_failover", False) or False

    # Multi-region writes
    multi_write = getattr(acct, "enable_multiple_write_locations", False) or False

    # Backup policy
    backup_policy = getattr(acct, "backup_policy", None)
    backup_type   = "Unknown"
    if backup_policy:
        backup_type = str(type(backup_policy).__name__).replace("BackupPolicy", "")
        if not backup_type:
            backup_type = str(getattr(backup_policy, "type", "Periodic"))

    # Locations
    locations_raw = list(getattr(acct, "locations", None) or [])
    location_names = [str(getattr(loc, "location_name", "")) for loc in locations_raw]

    # Consistency
    consistency = getattr(acct, "consistency_policy", None)
    consistency_level = str(getattr(consistency, "default_consistency_level", "")) if consistency else ""

    return {
        "name":                   acct.name,
        "location":               getattr(acct, "location", ""),
        "resourceGroup":          rg,
        "kind":                   str(getattr(acct, "kind", "") or ""),
        "consistencyLevel":       consistency_level,
        "publicNetworkAccess":    public_network,
        "ipRulesCount":           ip_rules_count,
        "isIpFirewallConfigured": ip_firewall,
        "automaticFailover":      auto_failover,
        "multipleWriteLocations": multi_write,
        "backupPolicy":           backup_type,
        "locations":              location_names,
        "tags":                   dict(getattr(acct, "tags", {}) or {}),
    }


def _parse_rg(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""
