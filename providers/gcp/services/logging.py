"""GCP Cloud Logging service fetcher.

Data shape
----------
::

    {
        "audit_configs_enabled": bool,    # allServices has DATA_READ+DATA_WRITE+ADMIN_READ
        "has_log_sink":          bool,    # at least one non-_Default log sink exists
        "audit_configs": [...],           # raw auditConfigs from project IAM policy
        "sinks": {
            "<sink-name>": {
                "name":        str,
                "destination": str,
                "filter":      str,
                "disabled":    bool,
            },
            ...
        },
    }

Notes
-----
CIS GCP 2.1 requires that audit logging captures DATA_READ, DATA_WRITE and
ADMIN_READ for all services.  This is configured via the ``auditConfigs``
section of the project IAM policy — not via the Cloud Logging API itself.

CIS GCP 2.2 requires at least one project-level log sink that routes logs to
a storage destination outside the project (GCS, Pub/Sub, BigQuery, or another
log bucket).
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)

# Log types required for full audit coverage
_REQUIRED_LOG_TYPES = {"DATA_READ", "DATA_WRITE", "ADMIN_READ"}


def fetch_logging(facade: Any) -> Dict[str, Any]:
    """Fetch Cloud Logging sinks and project audit configuration."""
    data: Dict[str, Any] = {
        "audit_configs_enabled": False,
        "has_log_sink":          False,
        "audit_configs":         [],
        "sinks":                 {},
    }

    # ------------------------------------------------------------------
    # 1. Audit config — lives inside the project IAM policy
    # ------------------------------------------------------------------
    try:
        crm = facade.discovery("cloudresourcemanager", "v3")
        policy = crm.projects().getIamPolicy(
            resource=f"projects/{facade.project_id}",
            body={},
        ).execute()
        audit_configs = policy.get("auditConfigs", [])
        data["audit_configs"] = audit_configs

        # CIS requires allServices with all three log types
        all_svc_cfg = next(
            (ac for ac in audit_configs if ac.get("service") == "allServices"),
            None,
        )
        if all_svc_cfg:
            configured_types = {
                alc.get("logType", "")
                for alc in all_svc_cfg.get("auditLogConfigs", [])
            }
            data["audit_configs_enabled"] = _REQUIRED_LOG_TYPES.issubset(
                configured_types
            )
    except Exception as exc:
        log.warning("GCP Logging: could not fetch audit configs: %s", exc)

    # ------------------------------------------------------------------
    # 2. Log sinks
    # ------------------------------------------------------------------
    try:
        logging_svc = facade.discovery("logging", "v2")
        sinks: list = []
        req = logging_svc.projects().sinks().list(
            parent=f"projects/{facade.project_id}"
        )
        while req is not None:
            resp = req.execute()
            sinks.extend(resp.get("sinks", []))
            req = logging_svc.projects().sinks().list_next(req, resp)

        for sink in sinks:
            sink_name = sink.get("name", "").rsplit("/", 1)[-1]
            data["sinks"][sink_name] = {
                "name":        sink_name,
                "destination": sink.get("destination", ""),
                "filter":      sink.get("filter", ""),
                "disabled":    sink.get("disabled", False),
            }

        # A project has at least one meaningful sink if any non-disabled sink exists
        data["has_log_sink"] = any(
            not s.get("disabled", False) for s in sinks
        )
    except Exception as exc:
        log.warning("GCP Logging: could not fetch log sinks: %s", exc)

    return data
