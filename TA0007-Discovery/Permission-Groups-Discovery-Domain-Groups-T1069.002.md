# 🔍 T1069.002 - Permission Groups Discovery: Domain Groups
**MITRE Tactic:** Discovery (TA0007)

## 📝 Description
**Permission Groups Discovery: Domain Groups (T1069.002)** involves adversaries attempting to enumerate groups and their memberships within an Active Directory environment. By identifying who belongs to high-privilege groups (like "Domain Admins," "Enterprise Admins," or "Backup Operators"), attackers can map out the "keys to the kingdom" and identify targets for credential theft or session hijacking.

In Microsoft Defender XDR, we focus on identifying non-standard execution of group enumeration commands, especially those targeting sensitive administrative groups, and monitoring for LDAP queries that look for specific group SIDs.

---

## 📁 Sub-Techniques Covered
| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1069.002** | Domain Groups | Detection of local and remote enumeration of Active Directory security and distribution groups. |

---

## 🔍 KQL Queries

### 1. High-Privilege Group Enumeration (Net.exe)
Attackers often use `net group` to find the members of the most powerful groups in the domain. This query flags searches specifically for administrative groups.

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "net.exe" or FileName =~ "net1.exe"
| where ProcessCommandLine has "group" and ProcessCommandLine has "/domain"
| where ProcessCommandLine has_any("Domain Admins", "Enterprise Admins", "DnsAdmins", "Exchange Windows Permissions")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### 2. PowerShell Get-ADGroupMember Usage

The Active Directory PowerShell module is a "living off the land" favorite. This query detects the enumeration of group members, which is a common precursor to lateral movement:

```
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any("Get-ADGroupMember", "Get-ADPrincipalGroupMembership", "Get-ADGroup")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 3. Automated Group Discovery via ADSI (LDAP)

Adversaries use ADSI searchers in PowerShell scripts to avoid spawning net.exe. This query looks for LDAP filters specifically designed to find all members of a group:

```
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has "objectCategory=group" or ProcessCommandLine has "objectClass=group"
| where ProcessCommandLine has "adsisearcher"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

### 4. High-Privilege Group Enumeration (Net.exe)

Using Defender for Identity data, we can see when a specific device performs an LDAP query against a sensitive group SID (e.g., Domain Admins is S-1-5-21-*-512):

```
IdentityQueryEvents
| where Timestamp > ago(24h)
| where QueryType == "LDAP query"
| where QueryTarget has_any("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| summarize QueryCount = count() by DeviceName, AccountName, QueryTarget, DestinationDeviceName
| order by QueryCount desc
```