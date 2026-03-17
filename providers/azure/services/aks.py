"""Azure AKS (Kubernetes Service) fetcher.

Collected data shape::

    {
        "clusters": {
            "<clusterName>": {
                "name": str,
                "location": str,
                "resourceGroup": str,
                "kubernetesVersion": str,
                "rbacEnabled": bool,
                "aadIntegrated": bool,
                "networkPolicy": str | None,   # "azure" | "calico" | None
                "networkPolicyEnabled": bool,
                "privateCluster": bool,
                "authorizedIpRanges": list[str],
                "httpApplicationRoutingEnabled": bool,
                "monitoringEnabled": bool,
                "tags": dict,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_aks(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"clusters": {}}

    try:
        from azure.mgmt.containerservice import ContainerServiceClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-containerservice not installed — skipping AKS fetch")
        return data

    client = ContainerServiceClient(facade.credential, facade.subscription_id)

    try:
        clusters = list(client.managed_clusters.list())
    except Exception as exc:
        log.warning("AKS: list clusters failed: %s", exc)
        return data

    for cluster in clusters:
        name = cluster.name
        try:
            entry = _build_cluster(cluster)
            data["clusters"][name] = entry
        except Exception as exc:
            log.warning("AKS cluster %s: %s", name, exc)
            data["clusters"][name] = {"name": name, "error": str(exc)}

    return data


def _build_cluster(c: Any) -> Dict[str, Any]:
    props = c

    # RBAC
    rbac_enabled = getattr(props, "enable_rbac", True)
    if rbac_enabled is None:
        rbac_enabled = True

    # AAD Integration
    aad_profile = getattr(props, "aad_profile", None)
    aad_integrated = aad_profile is not None

    # Network policy
    network_profile = getattr(props, "network_profile", None)
    network_policy = None
    if network_profile:
        network_policy = getattr(network_profile, "network_policy", None)
    network_policy_enabled = network_policy is not None

    # Private cluster
    api_server_access = getattr(props, "api_server_access_profile", None)
    private_cluster   = False
    authorized_ranges = []
    if api_server_access:
        private_cluster   = getattr(api_server_access, "enable_private_cluster", False) or False
        authorized_ranges = list(getattr(api_server_access, "authorized_ip_ranges", None) or [])

    # Add-ons
    addon_profiles = getattr(props, "addon_profiles", {}) or {}
    http_routing   = addon_profiles.get("httpApplicationRouting")
    http_routing_enabled = bool(http_routing and getattr(http_routing, "enabled", False))

    monitoring = addon_profiles.get("omsagent") or addon_profiles.get("monitoringAddon")
    monitoring_enabled = bool(monitoring and getattr(monitoring, "enabled", False))

    rg = _parse_rg(getattr(props, "id", ""))

    return {
        "name":                           props.name,
        "location":                       getattr(props, "location", ""),
        "resourceGroup":                  rg,
        "kubernetesVersion":              getattr(props, "kubernetes_version", ""),
        "rbacEnabled":                    rbac_enabled,
        "aadIntegrated":                  aad_integrated,
        "networkPolicy":                  str(network_policy) if network_policy else None,
        "networkPolicyEnabled":           network_policy_enabled,
        "privateCluster":                 private_cluster,
        "authorizedIpRanges":             authorized_ranges,
        "httpApplicationRoutingEnabled":  http_routing_enabled,
        "monitoringEnabled":              monitoring_enabled,
        "tags":                           dict(getattr(props, "tags", {}) or {}),
    }


def _parse_rg(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""
