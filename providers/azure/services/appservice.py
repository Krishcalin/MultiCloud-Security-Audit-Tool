"""Azure App Service fetcher — Web Apps and Function Apps.

Collected data shape::

    {
        "apps": {
            "<appId>": {
                "name": ..., "location": ..., "resourceGroup": ...,
                "kind": "app"|"functionapp"|...,
                "state": "Running"|"Stopped"|...,
                "httpsOnly": bool,
                "minTlsVersion": "1.0"|"1.1"|"1.2"|"1.3",
                "http20Enabled": bool,
                "authEnabled": bool,
                "ftpState": "AllAllowed"|"FtpsOnly"|"Disabled",
                "remoteDebuggingEnabled": bool,
                "httpLoggingEnabled": bool,
                "detailedErrorLoggingEnabled": bool,
                "clientCertEnabled": bool,
                "managedServiceIdentityEnabled": bool,
                "tags": {...},
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_appservice(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"apps": {}}

    try:
        from azure.mgmt.web import WebSiteManagementClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-web not installed — skipping App Service fetch")
        return data

    client = WebSiteManagementClient(facade.credential, facade.subscription_id)

    try:
        apps = list(client.web_apps.list())
    except Exception as exc:
        log.warning("Web app list failed: %s", exc)
        return data

    for app in apps:
        try:
            data["apps"][app.id] = _build_entry(client, app)
        except Exception as exc:
            log.warning("Web app %s: %s", app.name, exc)

    return data


def _build_entry(client: Any, app: Any) -> Dict[str, Any]:
    rg   = _parse_rg(app.id)
    name = app.name

    # Site config for detailed settings
    site_config: Dict[str, Any] = {}
    try:
        cfg = client.web_apps.get_configuration(rg, name)
        site_config = {
            "minTlsVersion":              str(getattr(cfg, "min_tls_version", "1.0") or "1.0"),
            "http20Enabled":              bool(getattr(cfg, "http20_enabled", False)),
            "ftpState":                   str(getattr(cfg, "ftp_state", "AllAllowed") or "AllAllowed"),
            "remoteDebuggingEnabled":     bool(getattr(cfg, "remote_debugging_enabled", False)),
            "httpLoggingEnabled":         bool(getattr(cfg, "http_logging_enabled", False)),
            "detailedErrorLoggingEnabled": bool(getattr(cfg, "detailed_error_logging_enabled", False)),
        }
    except Exception as exc:
        log.debug("App service config %s: %s", name, exc)

    # Auth settings
    auth_enabled = False
    try:
        auth = client.web_apps.get_auth_settings(rg, name)
        auth_enabled = bool(getattr(auth, "enabled", False))
    except Exception:
        pass

    identity_type = str(getattr(app.identity, "type", "None") or "None") if app.identity else "None"

    return {
        "id":                           app.id,
        "name":                         name,
        "location":                     app.location,
        "resourceGroup":                rg,
        "kind":                         app.kind or "app",
        "state":                        str(app.state or ""),
        "httpsOnly":                    bool(getattr(app, "https_only", False)),
        "minTlsVersion":                site_config.get("minTlsVersion", "1.0"),
        "http20Enabled":                site_config.get("http20Enabled", False),
        "authEnabled":                  auth_enabled,
        "ftpState":                     site_config.get("ftpState", "AllAllowed"),
        "remoteDebuggingEnabled":       site_config.get("remoteDebuggingEnabled", False),
        "httpLoggingEnabled":           site_config.get("httpLoggingEnabled", False),
        "detailedErrorLoggingEnabled":  site_config.get("detailedErrorLoggingEnabled", False),
        "clientCertEnabled":            bool(getattr(app, "client_cert_enabled", False)),
        "managedServiceIdentityEnabled": "SystemAssigned" in identity_type or "UserAssigned" in identity_type,
        "tags":                         dict(app.tags or {}),
    }


def _parse_rg(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""
