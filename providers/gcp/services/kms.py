"""GCP Cloud KMS service fetcher.

Data shape
----------
::

    {
        "keys": {
            "<key-resource-name>": {
                "name":               str,   # full resource name
                "keyRing":            str,
                "location":           str,
                "rotationEnabled":    bool,  # True if rotationPeriod is set
                "rotationPeriodDays": int | None,
                "purpose":            str,   # ENCRYPT_DECRYPT | ASYMMETRIC_SIGN | etc.
                "state":              str,   # ENABLED | DISABLED | DESTROYED
            },
            ...
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)


def _parse_rotation_seconds(period_str: Optional[str]) -> Optional[int]:
    """Convert a duration string like ``"7776000s"`` to days (int)."""
    if not period_str:
        return None
    period_str = period_str.strip()
    if period_str.endswith("s"):
        try:
            return int(period_str[:-1]) // 86400
        except ValueError:
            pass
    return None


def fetch_kms(facade: Any) -> Dict[str, Any]:
    """Fetch Cloud KMS key rings and crypto keys across all locations."""
    data: Dict[str, Any] = {"keys": {}}

    kms = facade.discovery("cloudkms", "v1")

    # ------------------------------------------------------------------
    # 1. List all KMS locations for the project
    # ------------------------------------------------------------------
    locations: list = []
    try:
        req = kms.projects().locations().list(
            name=f"projects/{facade.project_id}"
        )
        while req is not None:
            resp = req.execute()
            locations.extend(resp.get("locations", []))
            req = kms.projects().locations().list_next(req, resp)
    except Exception as exc:
        log.warning("GCP KMS: could not list locations: %s", exc)
        return data

    # ------------------------------------------------------------------
    # 2. For each location, list key rings → crypto keys
    # ------------------------------------------------------------------
    for location in locations:
        location_name = location.get("name", "")

        # List key rings in this location
        key_rings: list = []
        try:
            req = kms.projects().locations().keyRings().list(parent=location_name)
            while req is not None:
                resp = req.execute()
                key_rings.extend(resp.get("keyRings", []))
                req = kms.projects().locations().keyRings().list_next(req, resp)
        except Exception as exc:
            log.debug("GCP KMS: could not list key rings in %s: %s", location_name, exc)
            continue

        for kr in key_rings:
            kr_name  = kr.get("name", "")
            kr_short = kr_name.rsplit("/", 1)[-1]
            loc_short = location_name.rsplit("/", 1)[-1]

            # List crypto keys in this key ring
            try:
                req = kms.projects().locations().keyRings().cryptoKeys().list(
                    parent=kr_name
                )
                while req is not None:
                    resp = req.execute()
                    for key in resp.get("cryptoKeys", []):
                        key_name   = key.get("name", "")
                        key_short  = key_name.rsplit("/", 1)[-1]
                        rotation   = key.get("rotationPeriod")
                        rot_days   = _parse_rotation_seconds(rotation)

                        # Primary version state
                        primary = key.get("primary", {})
                        state   = primary.get("state", "ENABLED")

                        data["keys"][key_name] = {
                            "name":               key_name,
                            "shortName":          key_short,
                            "keyRing":            kr_short,
                            "location":           loc_short,
                            "rotationEnabled":    rotation is not None,
                            "rotationPeriodDays": rot_days,
                            "purpose":            key.get("purpose", ""),
                            "state":              state,
                        }
                    req = kms.projects().locations().keyRings().cryptoKeys().list_next(req, resp)
            except Exception as exc:
                log.debug("GCP KMS: could not list keys in %s: %s", kr_name, exc)

    return data
