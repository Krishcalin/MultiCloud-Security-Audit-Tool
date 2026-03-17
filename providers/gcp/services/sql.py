"""GCP Cloud SQL service fetcher.

Data shape
----------
::

    {
        "instances": {
            "<instance-name>": {
                "name":               str,
                "databaseVersion":    str,
                "publiclyAccessible": bool,   # ipv4Enabled = True (public IP assigned)
                "requireSSL":         bool,
                "backupEnabled":      bool,
                "ipv4Enabled":        bool,
                "authorizedNetworks": list[dict],
            },
            ...
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)

# SSL mode values that enforce encrypted connections
_SSL_ENFORCED_MODES = {
    "ENCRYPTED_ONLY",
    "TRUSTED_CLIENT_CERTIFICATE_REQUIRED",
}


def fetch_sql(facade: Any) -> Dict[str, Any]:
    """Fetch Cloud SQL instance configuration."""
    data: Dict[str, Any] = {"instances": {}}

    sql = facade.discovery("sqladmin", "v1")

    # ------------------------------------------------------------------
    # List all Cloud SQL instances in the project
    # ------------------------------------------------------------------
    instances: list = []
    try:
        req = sql.instances().list(project=facade.project_id)
        while req is not None:
            resp = req.execute()
            instances.extend(resp.get("items", []))
            req = sql.instances().list_next(req, resp)
    except Exception as exc:
        log.warning("GCP SQL: could not list instances: %s", exc)
        return data

    for inst in instances:
        name     = inst.get("name", "")
        settings = inst.get("settings", {})
        ip_cfg   = settings.get("ipConfiguration", {})
        bkp_cfg  = settings.get("backupConfiguration", {})

        ipv4_enabled = ip_cfg.get("ipv4Enabled", False)
        authorized   = ip_cfg.get("authorizedNetworks", [])

        # requireSsl is deprecated in newer API; prefer sslMode
        require_ssl_legacy = ip_cfg.get("requireSsl", False)
        ssl_mode           = ip_cfg.get("sslMode", "")
        require_ssl        = require_ssl_legacy or (ssl_mode in _SSL_ENFORCED_MODES)

        # Backup: enabled flag; for MySQL also binaryLogEnabled
        backup_enabled = bkp_cfg.get("enabled", False)

        data["instances"][name] = {
            "name":               name,
            "databaseVersion":    inst.get("databaseVersion", ""),
            "region":             inst.get("region", ""),
            "publiclyAccessible": ipv4_enabled,   # CIS: any public IP = finding
            "requireSSL":         require_ssl,
            "backupEnabled":      backup_enabled,
            "ipv4Enabled":        ipv4_enabled,
            "authorizedNetworks": authorized,
        }

    return data
