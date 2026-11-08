---
title: "Steampipe Table: azuread_defender_machine - Query Microsoft Defender for Endpoint machines using SQL"
description: "Allows users to query the devices Microsoft Defender for Endpoint has seen, including onboarding and sensor health status, exposure level and risk score."
---

# Table: azuread_defender_machine - Query Microsoft Defender for Endpoint machines using SQL

Microsoft Defender for Endpoint keeps a record of every device whose sensor has reported to it: its name, operating system, Microsoft Entra device identifier, onboarding and sensor health status, and the exposure level and risk score Defender evaluates for it.

## Table Usage Guide

The `azuread_defender_machine` table lists the devices Defender for Endpoint knows about. Use it to find devices whose sensor has gone quiet, devices with a high risk score, or to match Defender devices to Intune devices through `aad_device_id`.

Rows are read from the Defender for Endpoint API `GET https://api.securitycenter.microsoft.com/api/machines`, not Microsoft Graph. The connection's credential requests a token for `https://api.securitycenter.microsoft.com/.default`, so the app registration needs the `WindowsDefenderATP` application permission `Machine.Read.All` with admin consent.

**Important Notes**
- A missing permission fails the query with Microsoft's code (`Forbidden` or `Unauthorized`) and a message naming `Machine.Read.All`.
- A tenant without Defender for Endpoint fails the query with a message starting `Microsoft Defender for Endpoint is not enabled for this tenant`, with code `DisabledFeature` or `AADSTS500011`.
- Defender answers `404` when it has no recent machines; the table returns no rows.
- The API allows 100 calls a minute; the table waits out a `429` for its `Retry-After`.
- `aad_device_id` matches `azuread_intune_managed_device.azure_ad_device_id`.

## Examples

### Basic info
List every machine with its health and onboarding status.

```sql+postgres
select
  computer_dns_name,
  os_platform,
  health_status,
  onboarding_status,
  last_seen
from
  azuread_defender_machine;
```

```sql+sqlite
select
  computer_dns_name,
  os_platform,
  health_status,
  onboarding_status,
  last_seen
from
  azuread_defender_machine;
```

### List machines with a high risk score or exposure level
Find the devices Defender rates most at risk.

```sql+postgres
select
  computer_dns_name,
  risk_score,
  exposure_level
from
  azuread_defender_machine
where
  risk_score = 'High'
  or exposure_level = 'High';
```

```sql+sqlite
select
  computer_dns_name,
  risk_score,
  exposure_level
from
  azuread_defender_machine
where
  risk_score = 'High'
  or exposure_level = 'High';
```

### Match Defender machines to Intune managed devices
Join the two inventories through the Microsoft Entra device identifier.

```sql+postgres
select
  i.device_name,
  i.user_principal_name,
  m.health_status,
  m.risk_score
from
  azuread_intune_managed_device as i
  join azuread_defender_machine as m on m.aad_device_id = i.azure_ad_device_id;
```

```sql+sqlite
select
  i.device_name,
  i.user_principal_name,
  m.health_status,
  m.risk_score
from
  azuread_intune_managed_device as i
  join azuread_defender_machine as m on m.aad_device_id = i.azure_ad_device_id;
```
