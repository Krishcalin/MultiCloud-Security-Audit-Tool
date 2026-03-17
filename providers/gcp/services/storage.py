"""GCP Cloud Storage service fetcher.

Data shape
----------
::

    {
        "buckets": {
            "<bucket-name>": {
                "name":                  str,
                "location":              str,
                "allUsersAccess":        bool,  # IAM grants allUsers or allAuthenticatedUsers
                "uniformBucketAccess":   bool,  # Uniform bucket-level IAM access enabled
                "publicAccessPrevention": str,   # "enforced" | "inherited"
                "versioningEnabled":     bool,
                "loggingEnabled":        bool,
                "defaultKmsKeyName":     str | None,
            },
            ...
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_storage(facade: Any) -> Dict[str, Any]:
    """Fetch Cloud Storage bucket configuration and IAM policies."""
    data: Dict[str, Any] = {"buckets": {}}

    storage = facade.discovery("storage", "v1")

    # ------------------------------------------------------------------
    # 1. List all buckets in the project
    # ------------------------------------------------------------------
    buckets: list = []
    try:
        req = storage.buckets().list(
            project=facade.project_id,
            projection="full",
        )
        while req is not None:
            resp = req.execute()
            buckets.extend(resp.get("items", []))
            req = storage.buckets().list_next(req, resp)
    except Exception as exc:
        log.warning("GCP Storage: could not list buckets: %s", exc)
        return data

    for bucket in buckets:
        name       = bucket.get("name", "")
        iam_config = bucket.get("iamConfiguration", {})

        # Versioning
        versioning = bucket.get("versioning", {})
        versioning_enabled = versioning.get("enabled", False)

        # Logging
        logging_cfg   = bucket.get("logging", {})
        logging_enabled = bool(logging_cfg.get("logBucket"))

        # Uniform bucket access (enforces bucket-level IAM, disables ACLs)
        ubla = iam_config.get("uniformBucketLevelAccess", {})
        uniform_bucket_access = ubla.get("enabled", False)

        # Public access prevention
        public_access_prevention = iam_config.get(
            "publicAccessPrevention", "inherited"
        )

        # Default KMS key
        encryption     = bucket.get("encryption", {})
        default_kms    = encryption.get("defaultKmsKeyName")

        # ------------------------------------------------------------------
        # 2. IAM policy — check for allUsers / allAuthenticatedUsers
        # ------------------------------------------------------------------
        all_users_access = False
        # Skip the IAM check if public access is enforced (no point)
        if public_access_prevention != "enforced":
            try:
                policy = storage.buckets().getIamPolicy(bucket=name).execute()
                for binding in policy.get("bindings", []):
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        all_users_access = True
                        break
            except Exception as exc:
                log.debug("GCP Storage: could not get IAM for bucket %s: %s", name, exc)

        data["buckets"][name] = {
            "name":                   name,
            "location":               bucket.get("location", ""),
            "allUsersAccess":         all_users_access,
            "uniformBucketAccess":    uniform_bucket_access,
            "publicAccessPrevention": public_access_prevention,
            "versioningEnabled":      versioning_enabled,
            "loggingEnabled":         logging_enabled,
            "defaultKmsKeyName":      default_kms,
        }

    return data
