"""AWS CloudTrail service fetcher.

Collected data shape::

    {
        "trails": {
            "<TrailName>": {
                "Name": ..., "HomeRegion": ..., "TrailARN": ...,
                "IsMultiRegionTrail": bool,
                "IncludeGlobalServiceEvents": bool,
                "LogFileValidationEnabled": bool,
                "IsLogging": bool,
                "CloudWatchLogsLogGroupArn": ...,
                "CloudWatchLogsRoleArn": ...,
                "KMSKeyId": ...,
                "S3BucketName": ...,
                "S3KeyPrefix": ...,
                "EventSelectors": [...],
                "InsightSelectors": [...],
                "Tags": [...],
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_cloudtrail(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"trails": {}}

    raw = facade.call("cloudtrail", "describe_trails", includeShadowTrails=False)
    for t in raw.get("trailList", []):
        name = t["Name"]
        entry: Dict[str, Any] = {
            "Name":                        name,
            "HomeRegion":                  t.get("HomeRegion"),
            "TrailARN":                    t.get("TrailARN"),
            "IsMultiRegionTrail":          t.get("IsMultiRegionTrail", False),
            "IncludeGlobalServiceEvents":  t.get("IncludeGlobalServiceEvents", False),
            "LogFileValidationEnabled":    t.get("LogFileValidationEnabled", False),
            "CloudWatchLogsLogGroupArn":   t.get("CloudWatchLogsLogGroupArn"),
            "CloudWatchLogsRoleArn":       t.get("CloudWatchLogsRoleArn"),
            "KMSKeyId":                    t.get("KMSKeyId"),
            "S3BucketName":                t.get("S3BucketName"),
            "S3KeyPrefix":                 t.get("S3KeyPrefix"),
            "IsLogging":                   False,
            "EventSelectors":              [],
            "InsightSelectors":            [],
            "Tags":                        [],
        }

        # Logging status
        status = facade.call("cloudtrail", "get_trail_status", Name=t.get("TrailARN", name))
        entry["IsLogging"] = status.get("IsLogging", False)

        # Event selectors
        es = facade.call("cloudtrail", "get_event_selectors", TrailName=t.get("TrailARN", name))
        entry["EventSelectors"]        = es.get("EventSelectors", [])
        entry["AdvancedEventSelectors"] = es.get("AdvancedEventSelectors", [])

        # Insight selectors
        ins = facade.call("cloudtrail", "get_insight_selectors", TrailName=t.get("TrailARN", name))
        entry["InsightSelectors"] = ins.get("InsightSelectors", [])

        # Tags
        tags_resp = facade.call(
            "cloudtrail", "list_tags",
            ResourceIdList=[t.get("TrailARN", name)]
        )
        for rl in tags_resp.get("ResourceTagList", []):
            entry["Tags"] = rl.get("TagsList", [])

        data["trails"][name] = entry

    return data
