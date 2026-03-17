"""AWS RDS service fetcher.

Collected data shape::

    {
        "instances": {
            "<DBInstanceIdentifier>": {
                "DBInstanceIdentifier": ..., "Engine": ..., "EngineVersion": ...,
                "DBInstanceClass": ..., "DBInstanceStatus": ...,
                "PubliclyAccessible": bool,
                "StorageEncrypted": bool,
                "KmsKeyId": ...,
                "BackupRetentionPeriod": int,
                "DeletionProtection": bool,
                "MultiAZ": bool,
                "AutoMinorVersionUpgrade": bool,
                "MonitoringInterval": int,
                "PerformanceInsightsEnabled": bool,
                "CopyTagsToSnapshot": bool,
                "IAMDatabaseAuthenticationEnabled": bool,
                "Endpoint": { "Address": ..., "Port": ... },
                "VpcSecurityGroups": [...],
                "Tags": [...],
            }
        },
        "clusters": {
            "<DBClusterIdentifier>": {
                "DBClusterIdentifier": ..., "Engine": ...,
                "StorageEncrypted": bool,
                "DeletionProtection": bool,
                "BackupRetentionPeriod": int,
                "MultiAZ": bool,
                "IAMDatabaseAuthenticationEnabled": bool,
            }
        },
        "snapshots": {
            "<DBSnapshotIdentifier>": {
                "DBSnapshotIdentifier": ..., "Encrypted": bool,
                "PubliclyRestorableAccess": bool,
            }
        },
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)


def fetch_rds(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "instances":  {},
        "clusters":   {},
        "snapshots":  {},
    }

    _fetch_instances(facade, data)
    _fetch_clusters(facade, data)
    _fetch_snapshots(facade, data)

    return data


def _fetch_instances(facade: Any, data: dict) -> None:
    raw = facade.paginate("rds", "describe_db_instances", "DBInstances")
    for inst in raw:
        iid = inst["DBInstanceIdentifier"]
        data["instances"][iid] = {
            "DBInstanceIdentifier":              iid,
            "Engine":                             inst.get("Engine"),
            "EngineVersion":                      inst.get("EngineVersion"),
            "DBInstanceClass":                    inst.get("DBInstanceClass"),
            "DBInstanceStatus":                   inst.get("DBInstanceStatus"),
            "PubliclyAccessible":                 inst.get("PubliclyAccessible", False),
            "StorageEncrypted":                   inst.get("StorageEncrypted", False),
            "KmsKeyId":                           inst.get("KmsKeyId"),
            "BackupRetentionPeriod":              inst.get("BackupRetentionPeriod", 0),
            "DeletionProtection":                 inst.get("DeletionProtection", False),
            "MultiAZ":                            inst.get("MultiAZ", False),
            "AutoMinorVersionUpgrade":            inst.get("AutoMinorVersionUpgrade", True),
            "MonitoringInterval":                 inst.get("MonitoringInterval", 0),
            "PerformanceInsightsEnabled":         inst.get("PerformanceInsightsEnabled", False),
            "CopyTagsToSnapshot":                 inst.get("CopyTagsToSnapshot", False),
            "IAMDatabaseAuthenticationEnabled":   inst.get("IAMDatabaseAuthenticationEnabled", False),
            "Endpoint":                           inst.get("Endpoint", {}),
            "VpcSecurityGroups":                  inst.get("VpcSecurityGroups", []),
            "Tags":                               inst.get("TagList", []),
        }


def _fetch_clusters(facade: Any, data: dict) -> None:
    raw = facade.paginate("rds", "describe_db_clusters", "DBClusters")
    for c in raw:
        cid = c["DBClusterIdentifier"]
        data["clusters"][cid] = {
            "DBClusterIdentifier":            cid,
            "Engine":                          c.get("Engine"),
            "EngineVersion":                   c.get("EngineVersion"),
            "Status":                          c.get("Status"),
            "StorageEncrypted":                c.get("StorageEncrypted", False),
            "DeletionProtection":              c.get("DeletionProtection", False),
            "BackupRetentionPeriod":           c.get("BackupRetentionPeriod", 0),
            "MultiAZ":                         c.get("MultiAZ", False),
            "IAMDatabaseAuthenticationEnabled": c.get("IAMDatabaseAuthenticationEnabled", False),
            "HttpEndpointEnabled":             c.get("HttpEndpointEnabled", False),
        }


def _fetch_snapshots(facade: Any, data: dict) -> None:
    raw = facade.paginate("rds", "describe_db_snapshots", "DBSnapshots",
                          SnapshotType="manual")
    for s in raw:
        sid = s["DBSnapshotIdentifier"]
        # Check public attribute
        attrs = facade.call(
            "rds", "describe_db_snapshot_attributes",
            DBSnapshotIdentifier=sid
        )
        is_public = False
        for a in attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
            if a.get("AttributeName") == "restore" and "all" in a.get("AttributeValues", []):
                is_public = True

        data["snapshots"][sid] = {
            "DBSnapshotIdentifier":   sid,
            "Encrypted":              s.get("Encrypted", False),
            "PubliclyRestorableAccess": is_public,
            "Engine":                 s.get("Engine"),
            "SnapshotCreateTime":     s.get("SnapshotCreateTime"),
        }
