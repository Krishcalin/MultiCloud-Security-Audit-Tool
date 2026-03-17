"""AWS Config service fetcher.

Collected data shape::

    {
        "recorders": {
            "<name>": {
                "name": ..., "roleARN": ...,
                "recordingGroup": {...},
                "recording": bool,
                "lastStatus": ...,
            }
        },
        "delivery_channels": {
            "<name>": {
                "name": ..., "s3BucketName": ..., "snsTopicARN": ...,
            }
        },
        "rules": {
            "<ConfigRuleName>": {
                "ConfigRuleName": ..., "Source": {...},
                "ConfigRuleState": ..., "ComplianceType": ...,
            }
        },
        "enabled": bool,
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_config(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "recorders":          {},
        "delivery_channels":  {},
        "rules":              {},
        "enabled":            False,
    }

    _fetch_recorders(facade, data)
    _fetch_delivery_channels(facade, data)
    _fetch_rules(facade, data)

    return data


def _fetch_recorders(facade: Any, data: dict) -> None:
    resp = facade.call("config", "describe_configuration_recorders")
    statuses = facade.call("config", "describe_configuration_recorder_status")
    status_map = {
        s["name"]: s for s in statuses.get("ConfigurationRecordersStatus", [])
    }

    for r in resp.get("ConfigurationRecorders", []):
        name = r["name"]
        st   = status_map.get(name, {})
        recording = st.get("recording", False)
        entry = {
            "name":           name,
            "roleARN":        r.get("roleARN"),
            "recordingGroup": r.get("recordingGroup", {}),
            "recording":      recording,
            "lastStatus":     st.get("lastStatus"),
            "lastStartTime":  st.get("lastStartTime"),
        }
        data["recorders"][name] = entry
        if recording:
            data["enabled"] = True


def _fetch_delivery_channels(facade: Any, data: dict) -> None:
    resp = facade.call("config", "describe_delivery_channels")
    for ch in resp.get("DeliveryChannels", []):
        name = ch["name"]
        data["delivery_channels"][name] = {
            "name":         name,
            "s3BucketName": ch.get("s3BucketName"),
            "snsTopicARN":  ch.get("snsTopicARN"),
            "s3KeyPrefix":  ch.get("s3KeyPrefix"),
        }


def _fetch_rules(facade: Any, data: dict) -> None:
    raw = facade.paginate("config", "describe_config_rules", "ConfigRules")
    for rule in raw:
        name = rule["ConfigRuleName"]
        # Get compliance summary
        comp = facade.call(
            "config", "describe_compliance_by_config_rule",
            ConfigRuleNames=[name]
        )
        comp_type = "NOT_APPLICABLE"
        for c in comp.get("ComplianceByConfigRules", []):
            comp_type = c.get("Compliance", {}).get("ComplianceType", "NOT_APPLICABLE")

        data["rules"][name] = {
            "ConfigRuleName":  name,
            "ConfigRuleArn":   rule.get("ConfigRuleArn"),
            "Source":          rule.get("Source", {}),
            "ConfigRuleState": rule.get("ConfigRuleState"),
            "ComplianceType":  comp_type,
        }
