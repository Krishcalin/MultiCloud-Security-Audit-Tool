"""AWS ECR service fetcher.

Collected data shape::

    {
        "repositories": {
            "<repositoryName>": {
                "repositoryName": str,
                "repositoryArn": str,
                "registryId": str,
                "repositoryUri": str,
                "imageScanningOnPush": bool,
                "tagImmutability": bool,        # True if IMMUTABLE
                "encryptionType": str,          # "AES256" | "KMS"
                "kmsKey": str | None,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_ecr(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"repositories": {}}

    repos = facade.paginate("ecr", "describe_repositories", "repositories")
    for repo in repos:
        name = repo["repositoryName"]
        data["repositories"][name] = {
            "repositoryName": name,
            "repositoryArn":  repo.get("repositoryArn"),
            "registryId":     repo.get("registryId"),
            "repositoryUri":  repo.get("repositoryUri"),
            "imageScanningOnPush": repo.get("imageScanningConfiguration", {}).get("scanOnPush", False),
            "tagImmutability":    repo.get("imageTagMutability", "MUTABLE") == "IMMUTABLE",
            "encryptionType": repo.get("encryptionConfiguration", {}).get("encryptionType", "AES256"),
            "kmsKey":         repo.get("encryptionConfiguration", {}).get("kmsKey"),
        }

    return data
