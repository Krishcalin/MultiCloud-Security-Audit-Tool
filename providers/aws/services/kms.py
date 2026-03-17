"""AWS KMS service fetcher.

Collected data shape::

    {
        "keys": {
            "<KeyId>": {
                "KeyId": ..., "KeyArn": ..., "KeyState": ...,
                "KeyManager": "CUSTOMER" | "AWS",
                "KeyUsage": ...,
                "KeySpec": ...,
                "Origin": ...,
                "KeyRotationEnabled": bool,
                "DeletionDate": ...,
                "MultiRegion": bool,
                "Description": ...,
                "Tags": [...],
                "Policy": {...},
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_kms(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"keys": {}}

    raw_keys = facade.paginate("kms", "list_keys", "Keys")
    for k in raw_keys:
        kid = k["KeyId"]
        try:
            entry = _fetch_key(facade, kid)
            data["keys"][kid] = entry
        except Exception as exc:
            log.warning("KMS key %s: %s", kid, exc)

    return data


def _fetch_key(facade: Any, key_id: str) -> dict:
    meta = facade.call("kms", "describe_key", KeyId=key_id)
    km   = meta.get("KeyMetadata", {})

    entry: Dict[str, Any] = {
        "KeyId":               key_id,
        "KeyArn":              km.get("Arn"),
        "KeyState":            km.get("KeyState"),
        "KeyManager":          km.get("KeyManager"),
        "KeyUsage":            km.get("KeyUsage"),
        "KeySpec":             km.get("KeySpec") or km.get("CustomerMasterKeySpec"),
        "Origin":              km.get("Origin"),
        "Description":         km.get("Description"),
        "MultiRegion":         km.get("MultiRegion", False),
        "DeletionDate":        km.get("DeletionDate"),
        "KeyRotationEnabled":  False,
        "Tags":                [],
        "Policy":              {},
    }

    # Only customer-managed, enabled keys support rotation queries
    if km.get("KeyManager") == "CUSTOMER" and km.get("KeyState") == "Enabled":
        rot = facade.call("kms", "get_key_rotation_status", KeyId=key_id)
        entry["KeyRotationEnabled"] = rot.get("KeyRotationEnabled", False)

    # Tags
    tags = facade.paginate("kms", "list_resource_tags", "Tags", KeyId=key_id)
    entry["Tags"] = tags

    # Key policy
    pol = facade.call("kms", "get_key_policy", KeyId=key_id, PolicyName="default")
    if pol.get("Policy"):
        import json
        try:
            entry["Policy"] = json.loads(pol["Policy"])
        except Exception:
            entry["Policy"] = pol["Policy"]

    return entry
