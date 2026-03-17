"""Azure Network service fetcher — NSGs, VNets, public IPs and flow logs.

Collected data shape::

    {
        "nsgs": {
            "<nsgId>": {
                "name": ..., "location": ..., "resourceGroup": ...,
                "securityRules": [...],
                "defaultSecurityRules": [...],
                "associatedSubnets": [...],
                "associatedNics": [...],
            }
        },
        "vnets": {
            "<vnetId>": {
                "name": ..., "location": ..., "resourceGroup": ...,
                "addressSpace": [...],
                "subnets": [{"name": ..., "addressPrefix": ..., "nsgId": ...}],
                "flowLogsEnabled": bool,
            }
        },
        "public_ips": {
            "<ipId>": {
                "name": ..., "location": ..., "ipAddress": ...,
                "allocationMethod": ..., "domainLabel": ...,
            }
        },
        "network_watchers": {
            "<region>": {"enabled": bool, "name": ...}
        },
        "flow_logs": {
            "<flowLogId>": {
                "name": ..., "enabled": bool, "targetResourceId": ...,
                "storageId": ..., "retentionDays": int,
            }
        },
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_network(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "nsgs":             {},
        "vnets":            {},
        "public_ips":       {},
        "network_watchers": {},
        "flow_logs":        {},
    }

    try:
        from azure.mgmt.network import NetworkManagementClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-network not installed — skipping network fetch")
        return data

    client = NetworkManagementClient(facade.credential, facade.subscription_id)

    _fetch_nsgs(client, data)
    _fetch_vnets(client, data)
    _fetch_public_ips(client, data)
    _fetch_network_watchers(client, facade, data)

    return data


def _fetch_nsgs(client: Any, data: dict) -> None:
    try:
        for nsg in client.network_security_groups.list_all():
            nid = nsg.id
            data["nsgs"][nid] = {
                "name":                nsg.name,
                "location":            nsg.location,
                "resourceGroup":       _parse_rg(nid),
                "securityRules":       _parse_rules(nsg.security_rules or []),
                "defaultSecurityRules": _parse_rules(nsg.default_security_rules or []),
                "associatedSubnets":   [s.id for s in (nsg.subnets or [])],
                "associatedNics":      [n.id for n in (nsg.network_interfaces or [])],
            }
    except Exception as exc:
        log.warning("NSG list failed: %s", exc)


def _parse_rules(rules: list) -> list:
    result = []
    for r in rules:
        result.append({
            "name":                     r.name,
            "priority":                 r.priority,
            "direction":                str(r.direction or ""),
            "access":                   str(r.access or ""),
            "protocol":                 str(r.protocol or ""),
            "sourceAddressPrefix":      r.source_address_prefix or "",
            "destinationAddressPrefix": r.destination_address_prefix or "",
            "destinationPortRange":     r.destination_port_range or "",
            "destinationPortRanges":    list(r.destination_port_ranges or []),
            "sourcePortRange":          r.source_port_range or "",
        })
    return result


def _fetch_vnets(client: Any, data: dict) -> None:
    try:
        for vnet in client.virtual_networks.list_all():
            vid = vnet.id
            subnets = []
            for s in (vnet.subnets or []):
                subnets.append({
                    "name":          s.name,
                    "addressPrefix": s.address_prefix or "",
                    "nsgId":         s.network_security_group.id if s.network_security_group else None,
                })
            data["vnets"][vid] = {
                "name":             vnet.name,
                "location":         vnet.location,
                "resourceGroup":    _parse_rg(vid),
                "addressSpace":     list(vnet.address_space.address_prefixes or []) if vnet.address_space else [],
                "subnets":          subnets,
                "flowLogsEnabled":  False,  # updated by _fetch_network_watchers
            }
    except Exception as exc:
        log.warning("VNet list failed: %s", exc)


def _fetch_public_ips(client: Any, data: dict) -> None:
    try:
        for ip in client.public_ip_addresses.list_all():
            iid = ip.id
            data["public_ips"][iid] = {
                "name":             ip.name,
                "location":         ip.location,
                "ipAddress":        ip.ip_address,
                "allocationMethod": str(ip.public_ip_allocation_method or ""),
                "domainLabel":      ip.dns_settings.domain_name_label if ip.dns_settings else None,
            }
    except Exception as exc:
        log.warning("Public IP list failed: %s", exc)


def _fetch_network_watchers(client: Any, facade: Any, data: dict) -> None:
    try:
        watchers = list(client.network_watchers.list_all())
        for w in watchers:
            region = w.location
            data["network_watchers"][region] = {
                "enabled": True,
                "name":    w.name,
            }
            # Flow logs for this watcher
            rg = _parse_rg(w.id)
            try:
                flow_logs = list(client.flow_logs.list(rg, w.name))
                for fl in flow_logs:
                    flid = fl.id
                    data["flow_logs"][flid] = {
                        "name":             fl.name,
                        "enabled":          bool(fl.enabled),
                        "targetResourceId": fl.target_resource_id,
                        "storageId":        fl.storage_id,
                        "retentionDays":    fl.retention_policy.days if fl.retention_policy else 0,
                    }
                    # Mark the parent VNet/NSG as having flow logs
                    for vid in data["vnets"]:
                        if fl.target_resource_id and vid in fl.target_resource_id:
                            data["vnets"][vid]["flowLogsEnabled"] = True
            except Exception as exc:
                log.debug("Flow logs for watcher %s: %s", w.name, exc)
    except Exception as exc:
        log.warning("Network watcher list failed: %s", exc)


def _parse_rg(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""
