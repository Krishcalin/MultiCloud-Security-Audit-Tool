"""AWS Secrets Manager service fetcher.

Collected data shape::

    {
        "secrets": {
            "<Name>": {
                "Name": str,
                "ARN": str,
                "RotationEnabled": bool,
                "LastRotatedDate": str | None,    # ISO-8601
                "LastChangedDate": str | None,
                "LastAccessedDate": str | None,
                "DaysSinceLastRotation": int | None,
                "isStale": bool,                  # >90 days since last change/rotation
                "KmsKeyId": str | None,
            }
        }
    }
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

_STALE_DAYS = 90


def fetch_secretsmanager(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"secrets": {}}

    secrets = facade.paginate("secretsmanager", "list_secrets", "SecretList")
    now = datetime.now(tz=timezone.utc)

    for secret in secrets:
        name = secret.get("Name", secret.get("ARN", ""))
        last_rotated = secret.get("LastRotatedDate")
        last_changed  = secret.get("LastChangedDate")

        # Compute staleness
        reference_date = last_rotated or last_changed
        days_since: Optional[int] = None
        is_stale = False
        if reference_date:
            if isinstance(reference_date, str):
                try:
                    reference_date = datetime.fromisoformat(reference_date.replace("Z", "+00:00"))
                except ValueError:
                    reference_date = None
            if reference_date:
                days_since = (now - reference_date).days
                is_stale   = days_since > _STALE_DAYS

        data["secrets"][name] = {
            "Name":                name,
            "ARN":                 secret.get("ARN"),
            "RotationEnabled":     secret.get("RotationEnabled", False),
            "LastRotatedDate":     str(secret.get("LastRotatedDate")) if secret.get("LastRotatedDate") else None,
            "LastChangedDate":     str(secret.get("LastChangedDate")) if secret.get("LastChangedDate") else None,
            "LastAccessedDate":    str(secret.get("LastAccessedDate")) if secret.get("LastAccessedDate") else None,
            "DaysSinceLastRotation": days_since,
            "isStale":             is_stale,
            "KmsKeyId":            secret.get("KmsKeyId"),
        }

    return data
