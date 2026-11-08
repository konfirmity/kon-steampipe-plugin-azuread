---
title: "Steampipe Table: azuread_intune_windows_protection_state - Query the Microsoft Defender Antivirus state of Intune managed Windows devices using SQL"
description: "Allows users to query the antivirus protection state Intune reports for each managed Windows device, including real-time protection, tamper protection, signature age and scan history."
---

# Table: azuread_intune_windows_protection_state - Query the Microsoft Defender Antivirus state of Intune managed Windows devices using SQL

Intune collects the Microsoft Defender Antivirus state of every Windows device it manages: whether anti-malware, real-time protection, network inspection and tamper protection are on, whether signatures or scans are overdue, whether the device needs a reboot or a full scan, and the engine and signature versions.

## Table Usage Guide

The `azuread_intune_windows_protection_state` table shows the antivirus posture of each managed Windows device. Use it to find devices with real-time protection off, out-of-date signatures, or a pending reboot after a threat.

Rows are read per device from the Microsoft Graph v1.0 endpoint `/deviceManagement/managedDevices/{id}/windowsProtectionState`. Reading this table requires the `DeviceManagementManagedDevices.Read.All` Microsoft Graph application permission, and the tenant must hold an Intune licence. Without either, Graph rejects the request and the query returns an error rather than an empty result.

**Important Notes**
- You must specify `managed_device_id` in the `where` clause to query this table. An `in (...)` list, or a join from `azuread_intune_managed_device`, reads each device in turn.
- A device without a protection state, such as a macOS or mobile device, or one removed from Intune, returns no rows.
- `product_status` and `device_state` are flag sets, written comma separated, for example `serviceNotRunning,avSignaturesOutOfDate`.

## Examples

### Basic info
Show the protection state of a device.

```sql+postgres
select
  managed_device_id,
  malware_protection_enabled,
  real_time_protection_enabled,
  tamper_protection_enabled,
  signature_update_overdue,
  last_reported_date_time
from
  azuread_intune_windows_protection_state
where
  managed_device_id = '0a1b2c3d-0000-0000-0000-000000000001';
```

```sql+sqlite
select
  managed_device_id,
  malware_protection_enabled,
  real_time_protection_enabled,
  tamper_protection_enabled,
  signature_update_overdue,
  last_reported_date_time
from
  azuread_intune_windows_protection_state
where
  managed_device_id = '0a1b2c3d-0000-0000-0000-000000000001';
```

### List Windows devices with real-time protection off or signatures overdue
Find devices whose antivirus is not keeping up.

```sql+postgres
select
  d.device_name,
  d.user_principal_name,
  p.real_time_protection_enabled,
  p.signature_update_overdue,
  p.signature_version
from
  azuread_intune_managed_device as d
  join azuread_intune_windows_protection_state as p on p.managed_device_id = d.id
where
  d.operating_system = 'Windows'
  and (not p.real_time_protection_enabled or p.signature_update_overdue);
```

```sql+sqlite
select
  d.device_name,
  d.user_principal_name,
  p.real_time_protection_enabled,
  p.signature_update_overdue,
  p.signature_version
from
  azuread_intune_managed_device as d
  join azuread_intune_windows_protection_state as p on p.managed_device_id = d.id
where
  d.operating_system = 'Windows'
  and (not p.real_time_protection_enabled or p.signature_update_overdue);
```

### List devices that need a reboot or a full scan
Find devices left waiting on a step after a threat action.

```sql+postgres
select
  d.device_name,
  p.reboot_required,
  p.full_scan_required,
  p.device_state
from
  azuread_intune_managed_device as d
  join azuread_intune_windows_protection_state as p on p.managed_device_id = d.id
where
  p.reboot_required or p.full_scan_required;
```

```sql+sqlite
select
  d.device_name,
  p.reboot_required,
  p.full_scan_required,
  p.device_state
from
  azuread_intune_managed_device as d
  join azuread_intune_windows_protection_state as p on p.managed_device_id = d.id
where
  p.reboot_required or p.full_scan_required;
```
