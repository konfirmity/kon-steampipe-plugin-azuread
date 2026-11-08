---
title: "Steampipe Table: azuread_intune_device_compliance_setting_state - Query the state of each Intune compliance setting on each device using SQL"
description: "Allows users to query, per managed device, whether each Intune compliance policy setting (BitLocker, Secure Boot, password, minimum OS version and so on) is met."
---

# Table: azuread_intune_device_compliance_setting_state - Query the state of each Intune compliance setting on each device using SQL

An Intune compliance policy is a set of settings a device must meet, for example require BitLocker, require Secure Boot, require a password or a minimum OS version. Intune records, for every setting and every device it applies to, whether the device meets it.

## Table Usage Guide

The `azuread_intune_device_compliance_setting_state` table explains why a device is compliant or not, one row per device and setting. Use it to find which settings a non-compliant device fails, or which setting fails most often across the fleet.

Rows are read from the Microsoft Graph v1.0 endpoints `/deviceManagement/deviceCompliancePolicySettingStateSummaries` and `/deviceManagement/deviceCompliancePolicySettingStateSummaries/{id}/deviceComplianceSettingStates`. Reading this table requires the `DeviceManagementConfiguration.Read.All` Microsoft Graph application permission, and the tenant must hold an Intune licence. Without either, Graph rejects the request and the query returns an error rather than an empty result.

**Important Notes**
- Every query reads all setting summaries in the tenant and then each summary's device states. Filter on `device_id` in the `where` clause to narrow the result; the filter is applied after the read.
- `device_id` is the Intune managed device identifier, the same value as `azuread_intune_managed_device.id`.

## Examples

### Basic info
List each setting's state on each device.

```sql+postgres
select
  device_name,
  setting_name,
  platform_type,
  state
from
  azuread_intune_device_compliance_setting_state;
```

```sql+sqlite
select
  device_name,
  setting_name,
  platform_type,
  state
from
  azuread_intune_device_compliance_setting_state;
```

### List the settings each non-compliant device fails
Explain why Intune marks a device non-compliant.

```sql+postgres
select
  d.device_name,
  d.user_principal_name,
  s.setting_name,
  s.state
from
  azuread_intune_managed_device as d
  join azuread_intune_device_compliance_setting_state as s on s.device_id = d.id
where
  s.state in ('nonCompliant', 'error', 'conflict')
order by
  d.device_name,
  s.setting_name;
```

```sql+sqlite
select
  d.device_name,
  d.user_principal_name,
  s.setting_name,
  s.state
from
  azuread_intune_managed_device as d
  join azuread_intune_device_compliance_setting_state as s on s.device_id = d.id
where
  s.state in ('nonCompliant', 'error', 'conflict')
order by
  d.device_name,
  s.setting_name;
```

### Count failing devices per setting
Find the compliance settings that fail most often.

```sql+postgres
select
  setting_name,
  count(distinct device_id) as failing_devices
from
  azuread_intune_device_compliance_setting_state
where
  state = 'nonCompliant'
group by
  setting_name
order by
  failing_devices desc;
```

```sql+sqlite
select
  setting_name,
  count(distinct device_id) as failing_devices
from
  azuread_intune_device_compliance_setting_state
where
  state = 'nonCompliant'
group by
  setting_name
order by
  failing_devices desc;
```
