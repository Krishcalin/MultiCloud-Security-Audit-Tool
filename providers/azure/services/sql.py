"""Azure SQL service fetcher — SQL Servers and databases.

Collected data shape::

    {
        "servers": {
            "<serverName>": {
                "name": ..., "location": ..., "resourceGroup": ...,
                "fullyQualifiedDomainName": ...,
                "version": ..., "administratorLogin": ...,
                "publicNetworkAccess": "Enabled"|"Disabled",
                "minimalTlsVersion": ...,
                "aadAdminConfigured": bool,
                "auditingEnabled": bool,
                "auditingToStorageEnabled": bool,
                "threatDetectionEnabled": bool,
                "vulnerabilityAssessmentEnabled": bool,
                "tdeEnabled": bool,
                "firewallRules": [{"name": ..., "startIp": ..., "endIp": ...}],
                "databases": {
                    "<dbName>": {
                        "name": ..., "status": ...,
                        "tdeEnabled": bool, "edition": ...
                    }
                },
                "tags": {...},
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_sql(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"servers": {}}

    try:
        from azure.mgmt.sql import SqlManagementClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-sql not installed — skipping SQL fetch")
        return data

    client = SqlManagementClient(facade.credential, facade.subscription_id)

    try:
        servers = list(client.servers.list())
    except Exception as exc:
        log.warning("SQL server list failed: %s", exc)
        return data

    for srv in servers:
        name = srv.name
        try:
            entry = _build_server(client, srv)
            data["servers"][name] = entry
        except Exception as exc:
            log.warning("SQL server %s: %s", name, exc)
            data["servers"][name] = {"name": name, "error": str(exc)}

    return data


def _build_server(client: Any, srv: Any) -> Dict[str, Any]:
    rg   = _parse_rg(srv.id)
    name = srv.name

    entry: Dict[str, Any] = {
        "name":                         name,
        "location":                     srv.location,
        "resourceGroup":                rg,
        "fullyQualifiedDomainName":     srv.fully_qualified_domain_name,
        "version":                      srv.version,
        "administratorLogin":           srv.administrator_login,
        "publicNetworkAccess":          str(getattr(srv, "public_network_access", "Enabled") or "Enabled"),
        "minimalTlsVersion":            getattr(srv, "minimal_tls_version", None),
        "aadAdminConfigured":           False,
        "auditingEnabled":              False,
        "auditingToStorageEnabled":     False,
        "threatDetectionEnabled":       False,
        "vulnerabilityAssessmentEnabled": False,
        "tdeEnabled":                   True,   # TDE is on by default in Azure SQL
        "firewallRules":                [],
        "databases":                    {},
        "tags":                         dict(srv.tags or {}),
    }

    # AAD admin
    try:
        admins = list(client.server_azure_ad_administrators.list_by_server(rg, name))
        entry["aadAdminConfigured"] = len(admins) > 0
    except Exception as exc:
        log.debug("SQL AAD admin %s: %s", name, exc)

    # Auditing policy
    try:
        audit = client.server_blob_auditing_policies.get(rg, name)
        entry["auditingEnabled"]          = str(audit.state or "").lower() == "enabled"
        entry["auditingToStorageEnabled"] = bool(getattr(audit, "storage_endpoint", None))
    except Exception as exc:
        log.debug("SQL auditing %s: %s", name, exc)

    # Advanced Threat Protection / Security Alert
    try:
        threat = client.server_security_alert_policies.get(rg, name)
        entry["threatDetectionEnabled"] = str(threat.state or "").lower() == "enabled"
    except Exception as exc:
        log.debug("SQL threat detection %s: %s", name, exc)

    # Vulnerability Assessment
    try:
        va = client.server_vulnerability_assessments.get(rg, name, "default")
        entry["vulnerabilityAssessmentEnabled"] = bool(va)
    except Exception as exc:
        log.debug("SQL vulnerability assessment %s: %s", name, exc)

    # Firewall rules
    try:
        fwrules = list(client.firewall_rules.list_by_server(rg, name))
        entry["firewallRules"] = [
            {"name": r.name, "startIp": r.start_ip_address, "endIp": r.end_ip_address}
            for r in fwrules
        ]
    except Exception as exc:
        log.debug("SQL firewall rules %s: %s", name, exc)

    # Databases
    try:
        dbs = list(client.databases.list_by_server(rg, name))
        for db in dbs:
            if db.name == "master":
                continue
            tde_enabled = True
            try:
                tde = client.transparent_data_encryptions.get(rg, name, db.name, "current")
                tde_enabled = str(getattr(tde, "status", "Enabled")).lower() == "enabled"
            except Exception:
                pass
            entry["databases"][db.name] = {
                "name":       db.name,
                "status":     str(db.status or ""),
                "tdeEnabled": tde_enabled,
                "edition":    str(getattr(db, "edition", "") or ""),
            }
    except Exception as exc:
        log.debug("SQL databases %s: %s", name, exc)

    return entry


def _parse_rg(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""
