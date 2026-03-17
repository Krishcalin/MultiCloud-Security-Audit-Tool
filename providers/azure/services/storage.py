"""Azure Storage Accounts service fetcher.

Collected data shape::

    {
        "accounts": {
            "<accountName>": {
                "name": ..., "location": ..., "resourceGroup": ...,
                "kind": ..., "sku": ...,
                "supportsHttpsTrafficOnly": bool,
                "minimumTlsVersion": "TLS1_0"|"TLS1_1"|"TLS1_2",
                "allowBlobPublicAccess": bool,
                "allowSharedKeyAccess": bool,
                "networkAcls": {
                    "defaultAction": "Allow"|"Deny",
                    "bypass": [...], "ipRules": [...], "virtualNetworkRules": [...]
                },
                "encryption": {
                    "services": {...}, "keySource": ..., "keyVaultProperties": {...}
                },
                "blobServiceProperties": {
                    "softDeleteEnabled": bool,
                    "softDeleteRetentionDays": int,
                    "versioningEnabled": bool,
                    "changeFeedEnabled": bool,
                },
                "queueLoggingEnabled": bool,
                "tableLoggingEnabled": bool,
                "privateEndpointConnections": [...],
                "tags": {...},
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_storage(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"accounts": {}}

    try:
        from azure.mgmt.storage import StorageManagementClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-storage not installed — skipping storage fetch")
        return data

    client = StorageManagementClient(facade.credential, facade.subscription_id)

    try:
        accounts = list(client.storage_accounts.list())
    except Exception as exc:
        log.warning("Storage account list failed: %s", exc)
        return data

    for acct in accounts:
        name = acct.name
        try:
            entry = _build_entry(client, acct)
            data["accounts"][name] = entry
        except Exception as exc:
            log.warning("Storage account %s: %s", name, exc)
            data["accounts"][name] = {"name": name, "error": str(exc)}

    return data


def _build_entry(client: Any, acct: Any) -> Dict[str, Any]:
    # Parse resource group from the resource ID
    # ID format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}
    rg = ""
    if acct.id:
        parts = acct.id.split("/")
        try:
            rg = parts[parts.index("resourceGroups") + 1]
        except (ValueError, IndexError):
            pass

    props = acct

    entry: Dict[str, Any] = {
        "name":                      acct.name,
        "location":                  acct.location,
        "resourceGroup":             rg,
        "kind":                      str(acct.kind) if acct.kind else None,
        "sku":                       acct.sku.name if acct.sku else None,
        "supportsHttpsTrafficOnly":  getattr(props, "enable_https_traffic_only", False),
        "minimumTlsVersion":         str(getattr(props, "minimum_tls_version", "TLS1_0") or "TLS1_0"),
        "allowBlobPublicAccess":     getattr(props, "allow_blob_public_access", True),
        "allowSharedKeyAccess":      getattr(props, "allow_shared_key_access", True),
        "networkAcls":               _parse_network_acls(getattr(props, "network_rule_set", None)),
        "encryption":                _parse_encryption(getattr(props, "encryption", None)),
        "blobServiceProperties":     {},
        "queueLoggingEnabled":       False,
        "tableLoggingEnabled":       False,
        "privateEndpointConnections": _parse_pec(getattr(props, "private_endpoint_connections", [])),
        "tags":                      dict(acct.tags or {}),
    }

    # Blob service properties (soft delete, versioning, change feed)
    try:
        blob_props = client.blob_services.get_service_properties(
            rg, acct.name
        )
        entry["blobServiceProperties"] = _parse_blob_props(blob_props)
    except Exception as exc:
        log.debug("Blob service properties for %s: %s", acct.name, exc)

    return entry


def _parse_network_acls(nr: Any) -> Dict[str, Any]:
    if nr is None:
        return {"defaultAction": "Allow", "bypass": [], "ipRules": [], "virtualNetworkRules": []}
    return {
        "defaultAction":        str(nr.default_action or "Allow"),
        "bypass":               [str(b) for b in (nr.bypass or [])],
        "ipRules":              [r.ip_address_or_range for r in (nr.ip_rules or [])],
        "virtualNetworkRules":  [r.virtual_network_resource_id for r in (nr.virtual_network_rules or [])],
    }


def _parse_encryption(enc: Any) -> Dict[str, Any]:
    if enc is None:
        return {}
    svcs = {}
    if enc.services:
        if enc.services.blob:
            svcs["blob"] = {"enabled": enc.services.blob.enabled}
        if enc.services.file:
            svcs["file"] = {"enabled": enc.services.file.enabled}
    kv = {}
    if enc.key_vault_properties:
        kv = {
            "keyName":    enc.key_vault_properties.key_name,
            "keyVersion": enc.key_vault_properties.key_version,
            "keyVaultUri": enc.key_vault_properties.key_vault_uri,
        }
    return {
        "services":          svcs,
        "keySource":         str(enc.key_source or "Microsoft.Storage"),
        "keyVaultProperties": kv,
    }


def _parse_blob_props(bp: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "softDeleteEnabled":      False,
        "softDeleteRetentionDays": 0,
        "versioningEnabled":      False,
        "changeFeedEnabled":      False,
    }
    if not bp:
        return result
    if hasattr(bp, "delete_retention_policy") and bp.delete_retention_policy:
        result["softDeleteEnabled"]       = bool(bp.delete_retention_policy.enabled)
        result["softDeleteRetentionDays"] = bp.delete_retention_policy.days or 0
    if hasattr(bp, "is_versioning_enabled"):
        result["versioningEnabled"] = bool(bp.is_versioning_enabled)
    if hasattr(bp, "change_feed") and bp.change_feed:
        result["changeFeedEnabled"] = bool(bp.change_feed.enabled)
    return result


def _parse_pec(pec_list: Any) -> list:
    result = []
    for pec in (pec_list or []):
        result.append({
            "id":    getattr(pec, "id", None),
            "state": str(getattr(getattr(pec, "private_link_service_connection_state", None), "status", "") or ""),
        })
    return result
