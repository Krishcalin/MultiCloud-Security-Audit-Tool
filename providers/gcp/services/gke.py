"""GCP GKE (Google Kubernetes Engine) service fetcher.

Data shape
----------
::

    {
        "clusters": {
            "<cluster-id>": {
                "name":                        str,
                "location":                    str,
                "status":                      str,
                "currentMasterVersion":        str,
                "masterEndpointPublic":        bool,
                "masterAuthorizedNetworksEnabled": bool,
                "defaultSaFullApiAccessOnNodes": bool,
                "networkPolicyEnabled":        bool,
                "shieldedNodes":               bool,
                "workloadIdentityEnabled":     bool,
            }
        }
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)

_FULL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_DEFAULT_SA_SUFFIX = "-compute@developer.gserviceaccount.com"


def fetch_gke(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"clusters": {}}

    container = facade.discovery("container", "v1")
    parent = f"projects/{facade.project_id}/locations/-"

    try:
        resp = container.projects().locations().clusters().list(parent=parent).execute()
        clusters = resp.get("clusters", [])
    except Exception as exc:
        log.warning("GKE: list clusters failed: %s", exc)
        return data

    for cluster in clusters:
        cid = cluster.get("id") or cluster.get("name", "")
        name = cluster.get("name", cid)
        location = cluster.get("location", cluster.get("zone", ""))
        cluster_key = f"{location}/{name}" if location else name
        data["clusters"][cluster_key] = _analyze_cluster(cluster)

    return data


def _analyze_cluster(c: Dict[str, Any]) -> Dict[str, Any]:
    # Public master endpoint
    master_auth = c.get("masterAuth", {})
    # If the cluster has a public endpoint IP, the master is publicly accessible
    master_endpoint = c.get("endpoint", "")
    master_public = bool(master_endpoint)  # any endpoint = potentially public unless private config
    # Check private cluster config
    private_config = c.get("privateClusterConfig", {})
    enable_private_endpoint = private_config.get("enablePrivateEndpoint", False)
    if enable_private_endpoint:
        master_public = False  # private cluster, no public endpoint

    # Master authorized networks
    master_auth_networks = c.get("masterAuthorizedNetworksConfig", {})
    auth_networks_enabled = master_auth_networks.get("enabled", False)

    # Node pools — check default SA with full API access
    default_sa_full = False
    for pool in c.get("nodePools", []):
        node_config = pool.get("config", {})
        sa_email    = node_config.get("serviceAccount", "")
        scopes      = node_config.get("oauthScopes", [])
        if (sa_email == "default" or sa_email.endswith(_DEFAULT_SA_SUFFIX)) and _FULL_SCOPE in scopes:
            default_sa_full = True
            break

    # Network policy
    network_policy = c.get("networkPolicy", {})
    network_policy_enabled = network_policy.get("enabled", False)

    # Shielded nodes
    shielded_nodes = c.get("shieldedNodes", {}).get("enabled", False)

    # Workload identity
    workload_identity = c.get("workloadIdentityConfig", {})
    workload_identity_enabled = bool(workload_identity.get("workloadPool"))

    return {
        "name":                             c.get("name", ""),
        "location":                         c.get("location", c.get("zone", "")),
        "status":                           c.get("status", ""),
        "currentMasterVersion":             c.get("currentMasterVersion", ""),
        "masterEndpointPublic":             master_public,
        "masterAuthorizedNetworksEnabled":  auth_networks_enabled,
        "defaultSaFullApiAccessOnNodes":    default_sa_full,
        "networkPolicyEnabled":             network_policy_enabled,
        "shieldedNodes":                    shielded_nodes,
        "workloadIdentityEnabled":          workload_identity_enabled,
    }
