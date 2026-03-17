"""Azure Compute service fetcher — VMs and managed disks.

Collected data shape::

    {
        "vms": {
            "<vmId>": {
                "id": ..., "name": ..., "location": ..., "resourceGroup": ...,
                "vmSize": ..., "osType": "Windows"|"Linux",
                "powerState": "running"|"deallocated"|"stopped"|...,
                "osDiskEncrypted": bool,
                "dataDiskEncrypted": bool,
                "diskEncryptionExtensionInstalled": bool,
                "identityType": "None"|"SystemAssigned"|"UserAssigned"|...,
                "extensions": [...],
                "networkInterfaces": [...],
                "tags": {...},
                "patchMode": ...,
                "endpointProtectionInstalled": bool,
            }
        },
        "disks": {
            "<diskId>": {
                "name": ..., "location": ..., "resourceGroup": ...,
                "diskSizeGB": ..., "osType": ...,
                "encryptionType": "EncryptionAtRestWithPlatformKey"|"EncryptionAtRestWithCustomerKey"|...,
                "diskState": ...,
            }
        },
        "snapshots": {
            "<snapshotId>": {
                "name": ..., "location": ...,
                "encryptionType": ..., "diskSizeGB": ...,
            }
        },
    }
"""

from __future__ import annotations

import logging
from typing import Any, Dict

log = logging.getLogger(__name__)

_ENDPOINT_PROTECTION_EXTENSIONS = {
    "IaaSAntimalware", "EndpointSecurity", "TrendMicroDSA",
    "Symantec", "McAfeeEndpointSecurity", "CrowdStrikeFalcon",
}

_DISK_ENCRYPTION_EXTENSIONS = {
    "AzureDiskEncryption", "AzureDiskEncryptionForLinux",
}


def fetch_compute(facade: Any) -> Dict[str, Any]:
    data: Dict[str, Any] = {"vms": {}, "disks": {}, "snapshots": {}}

    try:
        from azure.mgmt.compute import ComputeManagementClient  # type: ignore[import]
    except ImportError:
        log.warning("azure-mgmt-compute not installed — skipping compute fetch")
        return data

    client = ComputeManagementClient(facade.credential, facade.subscription_id)

    _fetch_vms(client, data)
    _fetch_disks(client, data)
    _fetch_snapshots(client, data)

    return data


def _fetch_vms(client: Any, data: dict) -> None:
    try:
        vms = list(client.virtual_machines.list_all())
    except Exception as exc:
        log.warning("VM list failed: %s", exc)
        return

    for vm in vms:
        try:
            vmid = vm.id
            rg   = _parse_rg(vmid)
            name = vm.name

            # Instance view for power state and extensions
            try:
                iv = client.virtual_machines.instance_view(rg, name)
                power_state = _parse_power_state(iv.statuses or [])
                extensions  = [e.name for e in (iv.extensions or [])]
            except Exception:
                power_state = "unknown"
                extensions  = []

            os_profile  = vm.storage_profile.os_disk if vm.storage_profile else None
            data_disks  = vm.storage_profile.data_disks if vm.storage_profile else []

            os_disk_enc  = _is_disk_encrypted(os_profile)
            data_disk_enc = all(_is_disk_encrypted(d) for d in (data_disks or [])) if data_disks else True

            identity_type = "None"
            if vm.identity:
                identity_type = str(vm.identity.type or "None")

            # Patch mode
            patch_mode = None
            if vm.os_profile:
                wc = getattr(vm.os_profile, "windows_configuration", None)
                lc = getattr(vm.os_profile, "linux_configuration", None)
                if wc and getattr(wc, "patch_settings", None):
                    patch_mode = str(wc.patch_settings.patch_mode or "")
                elif lc and getattr(lc, "patch_settings", None):
                    patch_mode = str(lc.patch_settings.patch_mode or "")

            data["vms"][vmid] = {
                "id":                              vmid,
                "name":                            name,
                "location":                        vm.location,
                "resourceGroup":                   rg,
                "vmSize":                          vm.hardware_profile.vm_size if vm.hardware_profile else None,
                "osType":                          str(vm.storage_profile.os_disk.os_type or "") if vm.storage_profile and vm.storage_profile.os_disk else None,
                "powerState":                      power_state,
                "osDiskEncrypted":                 os_disk_enc,
                "dataDiskEncrypted":               data_disk_enc,
                "diskEncryptionExtensionInstalled": any(e in _DISK_ENCRYPTION_EXTENSIONS for e in extensions),
                "endpointProtectionInstalled":      any(e in _ENDPOINT_PROTECTION_EXTENSIONS for e in extensions),
                "identityType":                    identity_type,
                "extensions":                      extensions,
                "networkInterfaces":               [ni.id for ni in (vm.network_profile.network_interfaces or [])] if vm.network_profile else [],
                "patchMode":                       patch_mode,
                "tags":                            dict(vm.tags or {}),
            }
        except Exception as exc:
            log.warning("VM %s: %s", vm.name, exc)


def _fetch_disks(client: Any, data: dict) -> None:
    try:
        for disk in client.disks.list():
            enc_type = "EncryptionAtRestWithPlatformKey"
            if disk.encryption and disk.encryption.type:
                enc_type = str(disk.encryption.type)
            data["disks"][disk.id] = {
                "name":           disk.name,
                "location":       disk.location,
                "resourceGroup":  _parse_rg(disk.id),
                "diskSizeGB":     disk.disk_size_gb,
                "osType":         str(disk.os_type or ""),
                "encryptionType": enc_type,
                "diskState":      str(disk.disk_state or ""),
            }
    except Exception as exc:
        log.warning("Disk list failed: %s", exc)


def _fetch_snapshots(client: Any, data: dict) -> None:
    try:
        for snap in client.snapshots.list():
            enc_type = "EncryptionAtRestWithPlatformKey"
            if snap.encryption and snap.encryption.type:
                enc_type = str(snap.encryption.type)
            data["snapshots"][snap.id] = {
                "name":           snap.name,
                "location":       snap.location,
                "encryptionType": enc_type,
                "diskSizeGB":     snap.disk_size_gb,
            }
    except Exception as exc:
        log.warning("Snapshot list failed: %s", exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_power_state(statuses: list) -> str:
    for s in statuses:
        if s.code and s.code.startswith("PowerState/"):
            return s.code.replace("PowerState/", "")
    return "unknown"


def _is_disk_encrypted(disk: Any) -> bool:
    if disk is None:
        return True  # No disk → treat as OK
    enc = getattr(disk, "managed_disk", None)
    if enc:
        sec = getattr(enc, "security_profile", None)
        if sec and getattr(sec, "disk_encryption_set", None):
            return True
    # Check encryption settings on OS disk
    enc_settings = getattr(disk, "encryption_settings", None)
    if enc_settings and getattr(enc_settings, "enabled", False):
        return True
    return False


def _parse_rg(resource_id: str) -> str:
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return ""
