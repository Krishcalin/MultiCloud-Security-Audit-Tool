"""AWS GuardDuty service fetcher.

Collected data shape::

    {
        "detectors": {
            "<DetectorId>": {
                "DetectorId": ..., "Status": "ENABLED"|"DISABLED",
                "FindingPublishingFrequency": ...,
                "DataSources": { ... },
                "Features": [...],
                "Tags": {...},
            }
        },
        "enabled": bool,   # True if at least one detector is ENABLED
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_guardduty(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "detectors": {},
        "enabled":   False,
    }

    detector_ids = facade.paginate("guardduty", "list_detectors", "DetectorIds")
    for did in detector_ids:
        try:
            entry = _fetch_detector(facade, did)
            data["detectors"][did] = entry
            if entry.get("Status") == "ENABLED":
                data["enabled"] = True
        except Exception as exc:
            log.warning("GuardDuty detector %s: %s", did, exc)

    return data


def _fetch_detector(facade: Any, detector_id: str) -> dict:
    resp = facade.call("guardduty", "get_detector", DetectorId=detector_id)
    return {
        "DetectorId":                  detector_id,
        "Status":                      resp.get("Status", "DISABLED"),
        "FindingPublishingFrequency":  resp.get("FindingPublishingFrequency"),
        "DataSources":                 resp.get("DataSources", {}),
        "Features":                    resp.get("Features", []),
        "Tags":                        resp.get("Tags", {}),
    }
