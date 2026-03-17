"""AWS SNS service fetcher.

Collected data shape::

    {
        "topics": {
            "<TopicArn>": {
                "TopicArn": ...,
                "KmsMasterKeyId": ...,
                "SubscriptionsConfirmed": int,
                "SubscriptionsPending": int,
                "DeliveryPolicy": ...,
                "Policy": {...},
                "Tags": [...],
            }
        },
        "subscriptions": {
            "<SubscriptionArn>": {
                "SubscriptionArn": ..., "TopicArn": ...,
                "Protocol": ..., "Endpoint": ...,
            }
        },
    }
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_sns(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"topics": {}, "subscriptions": {}}

    topics = facade.paginate("sns", "list_topics", "Topics")
    for t in topics:
        arn = t["TopicArn"]
        try:
            data["topics"][arn] = _fetch_topic(facade, arn)
        except Exception as exc:
            log.warning("SNS topic %s: %s", arn, exc)

    subs = facade.paginate("sns", "list_subscriptions", "Subscriptions")
    for s in subs:
        arn = s.get("SubscriptionArn", "")
        data["subscriptions"][arn] = {
            "SubscriptionArn": arn,
            "TopicArn":        s.get("TopicArn"),
            "Protocol":        s.get("Protocol"),
            "Endpoint":        s.get("Endpoint"),
            "Owner":           s.get("Owner"),
        }

    return data


def _fetch_topic(facade: Any, topic_arn: str) -> dict:
    attrs = facade.call("sns", "get_topic_attributes", TopicArn=topic_arn)
    a = attrs.get("Attributes", {})

    policy = None
    if a.get("Policy"):
        try:
            policy = json.loads(a["Policy"])
        except Exception:
            policy = a["Policy"]

    tags_resp = facade.call("sns", "list_tags_for_resource", ResourceArn=topic_arn)
    tags = tags_resp.get("Tags", [])

    return {
        "TopicArn":                topic_arn,
        "KmsMasterKeyId":          a.get("KmsMasterKeyId"),
        "SubscriptionsConfirmed":  int(a.get("SubscriptionsConfirmed", 0)),
        "SubscriptionsPending":    int(a.get("SubscriptionsPending", 0)),
        "DeliveryPolicy":          a.get("DeliveryPolicy"),
        "Policy":                  policy,
        "Tags":                    tags,
    }
