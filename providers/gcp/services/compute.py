"""GCP Compute Engine service fetcher.

Data shape
----------
::

    {
        "instances": {
            "<instance-id>": {
                "name":                   str,
                "zone":                   str,
                "status":                 str,
                "hasPublicIP":            bool,
                "publicIpAddress":        str | None,
                "osLoginEnabled":         bool,
                "serialPortEnabled":      bool,
                "defaultSaFullApiAccess": bool,  # default compute SA + cloud-platform scope
            },
            ...
        },
        "firewalls": {
            "<fw-name>": {
                "name":           str,
                "direction":      str,
                "sourceRanges":   list[str],
                "isPublicIngress": bool,
                "opensSSH":       bool,   # allows TCP/22 from 0.0.0.0/0
                "opensRDP":       bool,   # allows TCP/3389 from 0.0.0.0/0
                "opensAll":       bool,   # allows all traffic from 0.0.0.0/0
                "disabled":       bool,
            },
            ...
        },
        "networks": {
            "<network-name>": {
                "name":                   str,
                "isDefault":              bool,
                "autoCreateSubnetworks":  bool,
            },
            ...
        },
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

# Default Compute Engine service account email suffix
_DEFAULT_SA_SUFFIX = "-compute@developer.gserviceaccount.com"
# Scope that grants full API access
_FULL_API_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
# CIDRs that represent the entire internet
_PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def _port_in_range(port_str: str, target: int) -> bool:
    """Return True if *target* port falls within the *port_str* specification."""
    port_str = port_str.strip()
    if "-" in port_str:
        parts = port_str.split("-", 1)
        try:
            return int(parts[0]) <= target <= int(parts[1])
        except (ValueError, IndexError):
            return False
    try:
        return int(port_str) == target
    except ValueError:
        return False


def _analyze_firewall(fw: Dict[str, Any]) -> Dict[str, Any]:
    """Derive security-relevant flags from a firewall rule dict."""
    direction     = fw.get("direction", "INGRESS")
    source_ranges = fw.get("sourceRanges", [])
    disabled      = fw.get("disabled", False)
    is_public     = any(r in _PUBLIC_CIDRS for r in source_ranges)

    opens_ssh = opens_rdp = opens_all = False

    if is_public and direction == "INGRESS" and not disabled:
        for rule in fw.get("allowed", []):
            protocol = rule.get("IPProtocol", "").lower()
            ports    = rule.get("ports", [])

            if protocol == "all":
                opens_all = opens_ssh = opens_rdp = True
                break

            if protocol in ("tcp", "udp"):
                if not ports:
                    # No port restriction → all ports
                    opens_ssh = opens_rdp = True
                else:
                    for p in ports:
                        if _port_in_range(p, 22):
                            opens_ssh = True
                        if _port_in_range(p, 3389):
                            opens_rdp = True

    return {
        "name":            fw.get("name", ""),
        "direction":       direction,
        "sourceRanges":    source_ranges,
        "isPublicIngress": is_public and direction == "INGRESS",
        "opensSSH":        opens_ssh,
        "opensRDP":        opens_rdp,
        "opensAll":        opens_all,
        "disabled":        disabled,
    }


def _analyze_instance(inst: Dict[str, Any]) -> Dict[str, Any]:
    """Derive security-relevant flags from a VM instance dict."""
    # Public IP from network interfaces / access configs
    public_ip: Optional[str] = None
    for ni in inst.get("networkInterfaces", []):
        for ac in ni.get("accessConfigs", []):
            if ac.get("natIP"):
                public_ip = ac["natIP"]
                break

    # Metadata flags (project-level defaults are NOT visible here;
    # we only see instance-level metadata override)
    meta = {
        item["key"]: item["value"]
        for item in inst.get("metadata", {}).get("items", [])
    }
    os_login_val   = meta.get("enable-oslogin", "").lower()
    serial_val     = meta.get("serial-port-enable", "").lower()
    os_login       = os_login_val in ("true", "1")
    serial_enabled = serial_val in ("true", "1")

    # Default SA with full API access
    default_sa_full = False
    for sa in inst.get("serviceAccounts", []):
        email  = sa.get("email", "")
        scopes = sa.get("scopes", [])
        if email.endswith(_DEFAULT_SA_SUFFIX) and _FULL_API_SCOPE in scopes:
            default_sa_full = True
            break

    return {
        "name":                   inst.get("name", ""),
        "zone":                   inst.get("zone", "").rsplit("/", 1)[-1],
        "status":                 inst.get("status", ""),
        "hasPublicIP":            public_ip is not None,
        "publicIpAddress":        public_ip,
        "osLoginEnabled":         os_login,
        "serialPortEnabled":      serial_enabled,
        "defaultSaFullApiAccess": default_sa_full,
    }


def fetch_compute(facade: Any) -> Dict[str, Any]:
    """Fetch VM instances, firewall rules, and VPC networks."""
    data: Dict[str, Any] = {
        "instances": {},
        "firewalls":  {},
        "networks":   {},
    }

    compute = facade.discovery("compute", "v1")

    # ------------------------------------------------------------------
    # 1. Instances (aggregated across all zones)
    # ------------------------------------------------------------------
    try:
        req = compute.instances().aggregatedList(project=facade.project_id)
        while req is not None:
            resp = req.execute()
            for _zone, zone_data in resp.get("items", {}).items():
                for inst in zone_data.get("instances", []):
                    iid = str(inst.get("id", inst.get("name", "")))
                    data["instances"][iid] = _analyze_instance(inst)
            req = compute.instances().aggregatedList_next(req, resp)
    except Exception as exc:
        log.warning("GCP Compute: could not list instances: %s", exc)

    # ------------------------------------------------------------------
    # 2. Firewall rules
    # ------------------------------------------------------------------
    try:
        req = compute.firewalls().list(project=facade.project_id)
        while req is not None:
            resp = req.execute()
            for fw in resp.get("items", []):
                data["firewalls"][fw["name"]] = _analyze_firewall(fw)
            req = compute.firewalls().list_next(req, resp)
    except Exception as exc:
        log.warning("GCP Compute: could not list firewall rules: %s", exc)

    # ------------------------------------------------------------------
    # 3. VPC Networks
    # ------------------------------------------------------------------
    try:
        req = compute.networks().list(project=facade.project_id)
        while req is not None:
            resp = req.execute()
            for net in resp.get("items", []):
                name = net.get("name", "")
                data["networks"][name] = {
                    "name":                  name,
                    "isDefault":             name == "default",
                    "autoCreateSubnetworks": net.get("autoCreateSubnetworks", False),
                }
            req = compute.networks().list_next(req, resp)
    except Exception as exc:
        log.warning("GCP Compute: could not list networks: %s", exc)

    return data
