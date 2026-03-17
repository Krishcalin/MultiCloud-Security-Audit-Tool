"""Azure Key Vault service fetcher.

Collected data shape::

    {
        "vaults": {
            "<vaultName>": {
                "name": ..., "location": ..., "resourceGroup": ...,
                "vaultUri": ...,
                "enableSoftDelete": bool,
                "softDeleteRetentionInDays": int,
                "enablePurgeProtection": bool,
                "enableRbacAuthorization": bool,
                "publicNetworkAccess": "Enabled"|"Disabled",
                "networkAcls": {...},
                "keys": {
                    "<keyName>": {
                        "name": ..., "enabled": bool, "keyType": ...,
                        "keySize": ..., "expires": ..., "created": ...,
                        "recoveryLevel": ...,
                    }
                },
                "secrets": {
                    "<secretName>": {
                        "name": ..., "enabled": bool, "expires": ...,
                        "contentType": ...,
                    }
                },
                "diagnosticsEnabled": bool,
                "tags": {...},
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_keyvault(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"vaults": {}}

    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-keyvault not installed — skipping key vault fetch")
        return data

    kv_mgmt = KeyVaultManagementClient(facade.credential, facade.subscription_id)

    try:
        vaults = list(kv_mgmt.vaults.list())
    except Exception as exc:
        log.warning("Key Vault list failed: %s", exc)
        return data

    for v in vaults:
        name = v.name
        try:
            entry = _build_entry(facade, kv_mgmt, v)
            data["vaults"][name] = entry
        except Exception as exc:
            log.warning("Key Vault %s: %s", name, exc)
            data["vaults"][name] = {"name": name, "error": str(exc)}

    return data


def _build_entry(facade: Any, kv_mgmt: Any, vault: Any) -> Dict[str, Any]:
    rg = _parse_rg(vault.id)
    props = vault.properties

    entry: Dict[str, Any] = {
        "name":                     vault.name,
        "location":                 vault.location,
        "resourceGroup":            rg,
        "vaultUri":                 props.vault_uri if props else "",
        "enableSoftDelete":         getattr(props, "enable_soft_delete", False) or False,
        "softDeleteRetentionInDays": getattr(props, "soft_delete_retention_in_days", 0) or 0,
        "enablePurgeProtection":    getattr(props, "enable_purge_protection", False) or False,
        "enableRbacAuthorization":  getattr(props, "enable_rbac_authorization", False) or False,
        "publicNetworkAccess":      getattr(props, "public_network_access", "Enabled") or "Enabled",
        "networkAcls":              _parse_network_acls(getattr(props, "network_acls", None)),
        "keys":                     {},
        "secrets":                  {},
        "diagnosticsEnabled":       False,
        "tags":                     dict(vault.tags or {}),
    }

    vault_uri = entry["vaultUri"]
    if vault_uri:
        entry["keys"]    = _fetch_keys(facade, vault_uri)
        entry["secrets"] = _fetch_secret_metadata(facade, vault_uri)

    # Diagnostic settings via Monitor API
    entry["diagnosticsEnabled"] = _check_diagnostics(facade, vault.id)

    return entry


def _fetch_keys(facade: Any, vault_uri: str) -> Dict[str, Any]:
    keys: Dict[str, Any] = {}
    try:
        from azure.keyvault.keys import KeyClient  # type: ignore[import]
        client = KeyClient(vault_url=vault_uri, credential=facade.credential)
        for key_props in client.list_properties_of_keys():
            name = key_props.name
            keys[name] = {
                "name":          name,
                "enabled":       key_props.enabled,
                "keyType":       key_props.key_type,
                "keySize":       key_props.key_size,
                "expires":       key_props.expires_on.isoformat() if key_props.expires_on else None,
                "created":       key_props.created_on.isoformat() if key_props.created_on else None,
                "recoveryLevel": key_props.recovery_level,
                "vaultName":     vault_uri.split(".")[0].replace("https://", ""),
            }
    except Exception as exc:
        log.debug("Key Vault keys %s: %s", vault_uri, exc)
    return keys


def _fetch_secret_metadata(facade: Any, vault_uri: str) -> Dict[str, Any]:
    secrets: Dict[str, Any] = {}
    try:
        from azure.keyvault.secrets import SecretClient  # type: ignore[import]
        client = SecretClient(vault_url=vault_uri, credential=facade.credential)
        for sp in client.list_properties_of_secrets():
            name = sp.name
            secrets[name] = {
                "name":        name,
                "enabled":     sp.enabled,
                "expires":     sp.expires_on.isoformat() if sp.expires_on else None,
                "contentType": sp.content_type,
            }
    except Exception as exc:
        log.debug("Key Vault secrets %s: %s", vault_uri, exc)
    return secrets


def _check_diagnostics(facade: Any, resource_id: str) -> bool:
    try:
        from azure.mgmt.monitor import MonitorManagementClient  # type: ignore[import]
        monitor = MonitorManagementClient(facade.credential, facade.subscription_id)
        settings = list(monitor.diagnostic_settings.list(resource_id))
        return len(settings) > 0
    except Exception:
        return False


def _parse_network_acls(na: Any) -> Dict[str, Any]:
    if na is None:
        return {"defaultAction": "Allow", "bypass": [], "ipRules": [], "virtualNetworkRules": []}
    return {
        "defaultAction":       str(na.default_action or "Allow"),
        "bypass":              [str(b) for b in (na.bypass or [])],
        "ipRules":             [r.value for r in (na.ip_rules or [])],
        "virtualNetworkRules": [r.id for r in (na.virtual_network_rules or [])],
    }


def _parse_rg(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""
