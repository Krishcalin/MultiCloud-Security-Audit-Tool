"""AWS VPC service fetcher.

Collected data shape::

    {
        "vpcs": {
            "<VpcId>": {
                "VpcId": ..., "CidrBlock": ..., "IsDefault": bool, "State": ...,
                "FlowLogs": [...],
                "Subnets": { "<SubnetId>": { "SubnetId": ..., "MapPublicIpOnLaunch": bool, ... } },
                "InternetGateways": [...],
                "NatGateways": [...],
                "PeeringConnections": [...],
                "RouteTables": [...],
                "NetworkAcls": [...],
            }
        },
        "flow_logs": {
            "<FlowLogId>": { "FlowLogId": ..., "ResourceId": ..., "TrafficType": ...,
                              "LogDestination": ..., "LogStatus": ... }
        },
        "nacls": {
            "<NetworkAclId>": { ... }
        },
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_vpc(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "vpcs":      {},
        "flow_logs": {},
        "nacls":     {},
    }

    _fetch_vpcs(facade, data)
    _fetch_flow_logs(facade, data)
    _fetch_nacls(facade, data)

    return data


def _fetch_vpcs(facade: Any, data: dict) -> None:
    vpcs = facade.paginate("ec2", "describe_vpcs", "Vpcs")
    for v in vpcs:
        vid = v["VpcId"]
        data["vpcs"][vid] = {
            "VpcId":               vid,
            "CidrBlock":           v.get("CidrBlock"),
            "IsDefault":           v.get("IsDefault", False),
            "State":               v.get("State"),
            "Tags":                v.get("Tags", []),
            "FlowLogs":            [],
            "Subnets":             {},
            "InternetGateways":    [],
            "NatGateways":         [],
            "PeeringConnections":  [],
            "RouteTables":         [],
        }

    # Subnets
    subnets = facade.paginate("ec2", "describe_subnets", "Subnets")
    for s in subnets:
        vpc_id = s.get("VpcId", "")
        if vpc_id in data["vpcs"]:
            sid = s["SubnetId"]
            data["vpcs"][vpc_id]["Subnets"][sid] = {
                "SubnetId":              sid,
                "CidrBlock":             s.get("CidrBlock"),
                "AvailabilityZone":      s.get("AvailabilityZone"),
                "MapPublicIpOnLaunch":   s.get("MapPublicIpOnLaunch", False),
                "DefaultForAz":          s.get("DefaultForAz", False),
            }

    # Internet Gateways
    igws = facade.paginate("ec2", "describe_internet_gateways", "InternetGateways")
    for igw in igws:
        for att in igw.get("Attachments", []):
            vid = att.get("VpcId", "")
            if vid in data["vpcs"]:
                data["vpcs"][vid]["InternetGateways"].append(igw["InternetGatewayId"])

    # NAT Gateways
    nats = facade.paginate("ec2", "describe_nat_gateways", "NatGateways")
    for nat in nats:
        vid = nat.get("VpcId", "")
        if vid in data["vpcs"]:
            data["vpcs"][vid]["NatGateways"].append({
                "NatGatewayId": nat["NatGatewayId"],
                "State":        nat.get("State"),
                "ConnectivityType": nat.get("ConnectivityType", "public"),
            })

    # VPC Peering
    peers = facade.paginate("ec2", "describe_vpc_peering_connections", "VpcPeeringConnections")
    for p in peers:
        for vid in [
            p.get("AccepterVpcInfo", {}).get("VpcId"),
            p.get("RequesterVpcInfo", {}).get("VpcId"),
        ]:
            if vid and vid in data["vpcs"]:
                data["vpcs"][vid]["PeeringConnections"].append(p["VpcPeeringConnectionId"])

    # Route Tables
    rts = facade.paginate("ec2", "describe_route_tables", "RouteTables")
    for rt in rts:
        vid = rt.get("VpcId", "")
        if vid in data["vpcs"]:
            data["vpcs"][vid]["RouteTables"].append({
                "RouteTableId": rt["RouteTableId"],
                "Routes":       rt.get("Routes", []),
                "Associations": rt.get("Associations", []),
            })


def _fetch_flow_logs(facade: Any, data: dict) -> None:
    logs = facade.paginate("ec2", "describe_flow_logs", "FlowLogs")
    for fl in logs:
        flid = fl["FlowLogId"]
        data["flow_logs"][flid] = {
            "FlowLogId":      flid,
            "ResourceId":     fl.get("ResourceId"),
            "TrafficType":    fl.get("TrafficType"),
            "LogDestination": fl.get("LogDestination") or fl.get("LogGroupName"),
            "LogStatus":      fl.get("FlowLogStatus"),
        }
        # Also tag into parent VPC
        rid = fl.get("ResourceId", "")
        if rid in data["vpcs"]:
            data["vpcs"][rid]["FlowLogs"].append(flid)


def _fetch_nacls(facade: Any, data: dict) -> None:
    nacls = facade.paginate("ec2", "describe_network_acls", "NetworkAcls")
    for n in nacls:
        nid = n["NetworkAclId"]
        data["nacls"][nid] = {
            "NetworkAclId": nid,
            "VpcId":        n.get("VpcId"),
            "IsDefault":    n.get("IsDefault", False),
            "Entries":      n.get("Entries", []),
        }
