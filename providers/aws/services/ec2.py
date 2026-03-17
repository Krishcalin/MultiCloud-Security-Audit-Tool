"""AWS EC2 service fetcher.

Collected data shape::

    {
        "instances": {
            "<InstanceId>": {
                "InstanceId": ..., "State": ..., "InstanceType": ...,
                "PublicIpAddress": ..., "PrivateIpAddress": ...,
                "SubnetId": ..., "VpcId": ...,
                "MetadataOptions": { "HttpTokens": "required"|"optional", ... },
                "BlockDeviceMappings": [...],
                "IamInstanceProfile": {...} | None,
                "Tags": [...],
                "LaunchTime": ...,
            }
        },
        "security_groups": {
            "<GroupId>": {
                "GroupId": ..., "GroupName": ..., "Description": ..., "VpcId": ...,
                "IpPermissions":       [...],   # ingress
                "IpPermissionsEgress": [...],   # egress
            }
        },
        "ebs_volumes": {
            "<VolumeId>": {
                "VolumeId": ..., "Encrypted": bool, "State": ...,
                "KmsKeyId": ..., "Size": ..., "VolumeType": ...,
            }
        },
        "snapshots": {
            "<SnapshotId>": {
                "SnapshotId": ..., "Encrypted": bool, "Public": bool,
                "OwnerId": ...,
            }
        },
        "amis": {
            "<ImageId>": {
                "ImageId": ..., "Public": bool, "OwnerId": ...,
            }
        },
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_ec2(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "instances":       {},
        "security_groups": {},
        "ebs_volumes":     {},
        "snapshots":       {},
        "amis":            {},
    }

    _fetch_instances(facade, data)
    _fetch_security_groups(facade, data)
    _fetch_volumes(facade, data)
    _fetch_snapshots(facade, data)
    _fetch_amis(facade, data)

    return data


def _fetch_instances(facade: Any, data: dict) -> None:
    reservations = facade.paginate("ec2", "describe_instances", "Reservations")
    for res in reservations:
        for inst in res.get("Instances", []):
            iid = inst["InstanceId"]
            data["instances"][iid] = {
                "InstanceId":         iid,
                "State":              inst.get("State", {}).get("Name"),
                "InstanceType":       inst.get("InstanceType"),
                "PublicIpAddress":    inst.get("PublicIpAddress"),
                "PrivateIpAddress":   inst.get("PrivateIpAddress"),
                "SubnetId":           inst.get("SubnetId"),
                "VpcId":              inst.get("VpcId"),
                "MetadataOptions":    inst.get("MetadataOptions", {}),
                "BlockDeviceMappings": inst.get("BlockDeviceMappings", []),
                "IamInstanceProfile": inst.get("IamInstanceProfile"),
                "Tags":               inst.get("Tags", []),
                "LaunchTime":         inst.get("LaunchTime"),
                "Monitoring":         inst.get("Monitoring", {}).get("State"),
                "SecurityGroups":     inst.get("SecurityGroups", []),
            }


def _fetch_security_groups(facade: Any, data: dict) -> None:
    groups = facade.paginate("ec2", "describe_security_groups", "SecurityGroups")
    for g in groups:
        gid = g["GroupId"]
        data["security_groups"][gid] = {
            "GroupId":             gid,
            "GroupName":           g.get("GroupName", ""),
            "Description":         g.get("Description", ""),
            "VpcId":               g.get("VpcId", ""),
            "IpPermissions":       g.get("IpPermissions", []),
            "IpPermissionsEgress": g.get("IpPermissionsEgress", []),
            "Tags":                g.get("Tags", []),
        }


def _fetch_volumes(facade: Any, data: dict) -> None:
    volumes = facade.paginate("ec2", "describe_volumes", "Volumes")
    for v in volumes:
        vid = v["VolumeId"]
        data["ebs_volumes"][vid] = {
            "VolumeId":   vid,
            "Encrypted":  v.get("Encrypted", False),
            "State":      v.get("State"),
            "KmsKeyId":   v.get("KmsKeyId"),
            "Size":       v.get("Size"),
            "VolumeType": v.get("VolumeType"),
            "Tags":       v.get("Tags", []),
        }


def _fetch_snapshots(facade: Any, data: dict) -> None:
    account_id = facade.get_account_id()
    snaps = facade.paginate(
        "ec2", "describe_snapshots", "Snapshots",
        OwnerIds=[account_id]
    )
    for s in snaps:
        sid = s["SnapshotId"]
        # Check public attribute (SnapshotId permission)
        perms = facade.call(
            "ec2", "describe_snapshot_attribute",
            SnapshotId=sid, Attribute="createVolumePermission"
        )
        is_public = any(
            p.get("Group") == "all"
            for p in perms.get("CreateVolumePermissions", [])
        )
        data["snapshots"][sid] = {
            "SnapshotId": sid,
            "Encrypted":  s.get("Encrypted", False),
            "Public":     is_public,
            "OwnerId":    s.get("OwnerId"),
            "StartTime":  s.get("StartTime"),
        }


def _fetch_amis(facade: Any, data: dict) -> None:
    account_id = facade.get_account_id()
    images = facade.paginate(
        "ec2", "describe_images", "Images",
        Owners=[account_id]
    )
    for img in images:
        iid = img["ImageId"]
        data["amis"][iid] = {
            "ImageId":  iid,
            "Public":   img.get("Public", False),
            "OwnerId":  img.get("OwnerId"),
            "Name":     img.get("Name"),
        }
