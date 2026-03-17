"""AWS S3 service fetcher.

Collected data shape::

    {
        "buckets": {
            "<BucketName>": {
                "Name": ...,
                "Region": ...,
                "CreationDate": ...,
                "PublicAccessBlock": {
                    "BlockPublicAcls": bool, "BlockPublicPolicy": bool,
                    "IgnorePublicAcls": bool, "RestrictPublicBuckets": bool,
                },
                "Versioning": "Enabled" | "Suspended" | "Disabled",
                "Encryption": "AES256" | "aws:kms" | None,
                "Logging": {...} | None,
                "LifecycleRules": [...],
                "BucketPolicy": {...} | None,
                "ACL": [...],
                "ObjectLockEnabled": bool,
                "ReplicationEnabled": bool,
            }
        },
        "account_public_access_block": { ... } | {},
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_s3(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "buckets": {},
        "account_public_access_block": {},
    }

    # Account-level Block Public Access
    resp = facade.call("s3control", "get_public_access_block",
                       AccountId=facade.get_account_id())
    data["account_public_access_block"] = resp.get("PublicAccessBlockConfiguration", {})

    # List all buckets
    resp = facade.call("s3", "list_buckets")
    for b in resp.get("Buckets", []):
        name = b["Name"]
        try:
            entry = _fetch_bucket(facade, name, b)
            data["buckets"][name] = entry
        except Exception as exc:
            log.warning("S3 bucket %s: %s", name, exc)
            data["buckets"][name] = {"Name": name, "error": str(exc)}

    return data


def _fetch_bucket(facade: Any, name: str, raw: dict) -> dict:
    s3 = facade.client("s3")

    # Bucket region
    loc = facade.call("s3", "get_bucket_location", Bucket=name)
    region = loc.get("LocationConstraint") or "us-east-1"

    entry: Dict[str, Any] = {
        "Name":              name,
        "Region":            region,
        "CreationDate":      raw.get("CreationDate"),
        "PublicAccessBlock": {},
        "Versioning":        "Disabled",
        "Encryption":        None,
        "Logging":           None,
        "LifecycleRules":    [],
        "BucketPolicy":      None,
        "ACL":               [],
        "ObjectLockEnabled": False,
        "ReplicationEnabled": False,
    }

    # Block Public Access (bucket-level)
    bpa = facade.call("s3", "get_public_access_block", Bucket=name)
    entry["PublicAccessBlock"] = bpa.get("PublicAccessBlockConfiguration", {})

    # Versioning
    ver = facade.call("s3", "get_bucket_versioning", Bucket=name)
    entry["Versioning"] = ver.get("Status", "Disabled")

    # Server-side encryption
    enc = facade.call("s3", "get_bucket_encryption", Bucket=name)
    rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    if rules:
        sse = rules[0].get("ApplyServerSideEncryptionByDefault", {})
        entry["Encryption"] = sse.get("SSEAlgorithm")

    # Access logging
    log_resp = facade.call("s3", "get_bucket_logging", Bucket=name)
    entry["Logging"] = log_resp.get("LoggingEnabled")

    # Lifecycle rules
    lc = facade.call("s3", "get_bucket_lifecycle_configuration", Bucket=name)
    entry["LifecycleRules"] = lc.get("Rules", [])

    # Bucket policy
    pol = facade.call("s3", "get_bucket_policy", Bucket=name)
    if pol.get("Policy"):
        import json
        try:
            entry["BucketPolicy"] = json.loads(pol["Policy"])
        except Exception:
            entry["BucketPolicy"] = pol["Policy"]

    # ACL
    acl = facade.call("s3", "get_bucket_acl", Bucket=name)
    entry["ACL"] = acl.get("Grants", [])

    # Object Lock
    ol = facade.call("s3", "get_object_lock_configuration", Bucket=name)
    entry["ObjectLockEnabled"] = (
        ol.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"
    )

    # Replication
    rep = facade.call("s3", "get_bucket_replication", Bucket=name)
    entry["ReplicationEnabled"] = bool(rep.get("ReplicationConfiguration"))

    return entry
