---
title: "Steampipe Table: azuread_sign_in_report - Query Azure AD Sign-In Reports using SQL"
description: "Allows users to query Azure AD Sign-In Reports, providing detailed information about user sign-in activities, including the location, device, and application used for sign-in."
---

# Table: azuread_sign_in_report - Query Azure AD Sign-In Reports using SQL

Azure Active Directory (Azure AD) is Microsoft's cloud-based identity and access management service. It helps your employees sign in and access resources in external resources, such as Microsoft Office 365, the Azure portal, and thousands of other SaaS applications. Azure AD Sign-In Reports provide details about the usage of managed applications and user sign-in activities.

## Table Usage Guide

The `azuread_sign_in_report` table provides insights into sign-in activities within Microsoft's Azure Active Directory. As a security analyst, explore sign-in specific details through this table, including the location, device, and application used for sign-in. Utilize it to uncover information about sign-in activities, such as failed sign-ins, sign-ins from risky locations or devices, and the verification of user identities.

**Important Notes**

- Graph lists the whole sign-in log by default, which can time out on a busy tenant. A `created_date_time` range (`>`, `>=`, `=`, `<`, `<=`) and `client_app_used =` are sent to Graph as `$filter`, so only matching sign-ins are paged. A `client_app_used in (...)` list runs one Graph call per value, paced to Graph's limit of five report requests per 10 seconds.

## Examples

### Basic info
Discover the segments that highlight user sign-in activities in AzureAD by analyzing the date, user details, and location. This practical application can be used to monitor user activities and track sign-in locations for security purposes.

```sql+postgres
select
  id,
  created_date_time,
  user_display_name,
  user_principal_name,
  ip_address,
  location ->> 'city' as city
from
  azuread_sign_in_report;
```

```sql+sqlite
select
  id,
  created_date_time,
  user_display_name,
  user_principal_name,
  ip_address,
  json_extract(location, '$.city') as city
from
  azuread_sign_in_report;
```

### List an user sign in details
Explore which applications a specific user has accessed within your Azure Active Directory. This can help you monitor user activity, ensuring they're only accessing appropriate resources.

```sql+postgres
select
  user_display_name,
  id,
  app_display_name,
  user_principal_name
from
  azuread_sign_in_report
where
  user_principal_name = 'abc@myacc.onmicrosoft.com';
```

```sql+sqlite
select
  user_display_name,
  id,
  app_display_name,
  user_principal_name
from
  azuread_sign_in_report
where
  user_principal_name = 'abc@myacc.onmicrosoft.com';
```

### List successful IMAP, POP and SMTP AUTH sign-ins in the last 30 days
Find users still signing in with these basic-authentication protocols, which bypass MFA. The time window and client apps are filtered by Microsoft Graph, so the query reads only those sign-ins.

```sql+postgres
select
  user_principal_name,
  client_app_used,
  created_date_time
from
  azuread_sign_in_report
where
  created_date_time >= now() - interval '30 days'
  and client_app_used in ('Authenticated SMTP', 'IMAP4', 'POP3')
  and (status ->> 'errorCode')::int = 0;
```

```sql+sqlite
select
  user_principal_name,
  client_app_used,
  created_date_time
from
  azuread_sign_in_report
where
  created_date_time >= datetime('now', '-30 days')
  and client_app_used in ('Authenticated SMTP', 'IMAP4', 'POP3')
  and json_extract(status, '$.errorCode') = 0;
```
