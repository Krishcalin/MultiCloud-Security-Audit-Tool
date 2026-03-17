"""GCP BigQuery service fetcher.

Data shape
----------
::

    {
        "datasets": {
            "<project:datasetId>": {
                "datasetId":          str,
                "projectId":          str,
                "location":           str,
                "isPubliclyAccessible": bool,   # allUsers or allAuthenticatedUsers in ACL
                "cmekEnabled":        bool,     # Customer-Managed Encryption Key
                "kmsKeyName":         str | None,
                "labels":             dict,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)

_PUBLIC_ENTITIES = {"allUsers", "allAuthenticatedUsers"}


def fetch_bigquery(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"datasets": {}}

    bq = facade.discovery("bigquery", "v2")

    # List all datasets in the project
    try:
        req = bq.datasets().list(projectId=facade.project_id, all=False)
        while req is not None:
            resp = req.execute()
            for ds_ref in resp.get("datasets", []):
                ds_id    = ds_ref["datasetReference"]["datasetId"]
                proj_id  = ds_ref["datasetReference"]["projectId"]
                key      = f"{proj_id}:{ds_id}"
                try:
                    detail = bq.datasets().get(
                        projectId=proj_id, datasetId=ds_id
                    ).execute()
                    data["datasets"][key] = _analyze_dataset(detail)
                except Exception as exc:
                    log.warning("BigQuery: get dataset %s failed: %s", key, exc)
            req = bq.datasets().list_next(req, resp)
    except Exception as exc:
        log.warning("BigQuery: list datasets failed: %s", exc)

    return data


def _analyze_dataset(ds: Dict[str, Any]) -> Dict[str, Any]:
    ds_ref    = ds.get("datasetReference", {})
    ds_id     = ds_ref.get("datasetId", "")
    proj_id   = ds_ref.get("projectId", "")

    # Check ACL for public access
    is_public = False
    for entry in ds.get("access", []):
        # entry has "role" and one of: "userByEmail", "groupByEmail", "specialGroup", "iamMember"
        special_group = entry.get("specialGroup", "")
        iam_member    = entry.get("iamMember", "")
        if special_group in _PUBLIC_ENTITIES or iam_member in _PUBLIC_ENTITIES:
            is_public = True
            break

    # CMEK
    enc = ds.get("defaultEncryptionConfiguration", {})
    kms_key_name = enc.get("kmsKeyName")
    cmek_enabled  = bool(kms_key_name)

    return {
        "datasetId":            ds_id,
        "projectId":            proj_id,
        "location":             ds.get("location", ""),
        "isPubliclyAccessible": is_public,
        "cmekEnabled":          cmek_enabled,
        "kmsKeyName":           kms_key_name,
        "labels":               ds.get("labels", {}),
    }
