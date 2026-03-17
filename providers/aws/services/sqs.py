"""AWS SQS service fetcher.

Collected data shape::

    {
        "queues": {
            "<QueueUrl>": {
                "QueueUrl": ..., "QueueArn": ...,
                "KmsMasterKeyId": ...,
                "SqsManagedSseEnabled": bool,
                "Policy": {...},
                "VisibilityTimeout": int,
                "MessageRetentionPeriod": int,
                "Tags": {...},
            }
        }
    }
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

log = logging.getLogger(__name__)

_ATTRS = [
    "QueueArn", "KmsMasterKeyId", "SqsManagedSseEnabled",
    "Policy", "VisibilityTimeout", "MessageRetentionPeriod",
    "ReceiveMessageWaitTimeSeconds",
]


def fetch_sqs(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"queues": {}}

    resp = facade.call("sqs", "list_queues")
    for url in resp.get("QueueUrls", []):
        try:
            data["queues"][url] = _fetch_queue(facade, url)
        except Exception as exc:
            log.warning("SQS queue %s: %s", url, exc)

    return data


def _fetch_queue(facade: Any, url: str) -> dict:
    attrs_resp = facade.call(
        "sqs", "get_queue_attributes",
        QueueUrl=url, AttributeNames=["All"]
    )
    a = attrs_resp.get("Attributes", {})

    policy = None
    if a.get("Policy"):
        try:
            policy = json.loads(a["Policy"])
        except Exception:
            policy = a["Policy"]

    tags_resp = facade.call("sqs", "list_queue_tags", QueueUrl=url)
    tags = tags_resp.get("Tags", {})

    return {
        "QueueUrl":                 url,
        "QueueArn":                 a.get("QueueArn", ""),
        "KmsMasterKeyId":           a.get("KmsMasterKeyId"),
        "SqsManagedSseEnabled":     a.get("SqsManagedSseEnabled", "false").lower() == "true",
        "Policy":                   policy,
        "VisibilityTimeout":        int(a.get("VisibilityTimeout", 30)),
        "MessageRetentionPeriod":   int(a.get("MessageRetentionPeriod", 345600)),
        "ReceiveMessageWaitTime":   int(a.get("ReceiveMessageWaitTimeSeconds", 0)),
        "Tags":                     tags,
    }
