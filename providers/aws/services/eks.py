"""AWS EKS service fetcher.

Collected data shape::

    {
        "clusters": {
            "<clusterName>": {
                "name": str,
                "arn": str,
                "version": str,
                "status": str,
                "endpointPublicAccess": bool,
                "endpointPrivateAccess": bool,
                "publicAccessCidrs": list[str],
                "loggingEnabled": bool,
                "enabledLogTypes": list[str],
                "secretsEncrypted": bool,
                "encryptionProviderArn": str | None,
                "clusterRoleArn": str,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

log = logging.getLogger(__name__)

_ALL_LOG_TYPES = {"api", "audit", "authenticator", "controllerManager", "scheduler"}


def fetch_eks(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"clusters": {}}

    cluster_names: List[str] = facade.paginate("eks", "list_clusters", "clusters")
    for name in cluster_names:
        try:
            detail = facade.call("eks", "describe_cluster", name=name)
            cluster = detail.get("cluster", {})
            data["clusters"][name] = _build_cluster(cluster)
        except Exception as exc:
            log.warning("EKS cluster %s: %s", name, exc)
            data["clusters"][name] = {"name": name, "error": str(exc)}

    return data


def _build_cluster(c: Dict[str, Any]) -> Dict[str, Any]:
    name = c.get("name", "")

    # Endpoint access
    resources_vpc = c.get("resourcesVpcConfig", {})
    endpoint_public  = resources_vpc.get("endpointPublicAccess", True)
    endpoint_private = resources_vpc.get("endpointPrivateAccess", False)
    public_cidrs     = resources_vpc.get("publicAccessCidrs", ["0.0.0.0/0"])

    # Logging
    log_config     = c.get("logging", {}).get("clusterLogging", [])
    enabled_types: List[str] = []
    for cfg in log_config:
        if cfg.get("enabled"):
            enabled_types.extend(cfg.get("types", []))
    logging_enabled = _ALL_LOG_TYPES.issubset({t.lower() for t in enabled_types})

    # Secrets encryption
    secrets_encrypted = False
    encryption_arn    = None
    for enc in c.get("encryptionConfig", []):
        resources = enc.get("resources", [])
        if "secrets" in [r.lower() for r in resources]:
            secrets_encrypted = True
            encryption_arn = enc.get("provider", {}).get("keyArn")

    return {
        "name":                  name,
        "arn":                   c.get("arn"),
        "version":               c.get("version"),
        "status":                c.get("status"),
        "endpointPublicAccess":  endpoint_public,
        "endpointPrivateAccess": endpoint_private,
        "publicAccessCidrs":     public_cidrs,
        "loggingEnabled":        logging_enabled,
        "enabledLogTypes":       enabled_types,
        "secretsEncrypted":      secrets_encrypted,
        "encryptionProviderArn": encryption_arn,
        "clusterRoleArn":        c.get("roleArn", ""),
    }
