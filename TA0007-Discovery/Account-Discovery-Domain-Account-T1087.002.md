## 👥 T1087.002 - Account Discovery: Domain Account

**MITRE Tactic:** Discovery (TA0007)

### 📝 Description

**Account Discovery: Domain Account (T1087.002)** involves adversaries attempting to enumerate user accounts, service accounts, and privileged accounts within a domain. This reconnaissance is crucial for identifying targets for credential access, lateral movement, and privilege escalation.  Adversaries typically use native Windows utilities and protocols like **PowerShell cmdlets** (e.g., `Get-ADUser`), **Active Directory Service Interfaces (ADSI)**, and command-line tools like `net.exe` and `nltest.exe` to perform these actions.

In the context of Microsoft Defender XDR, detecting this technique requires focusing on the repetitive and programmatic execution of domain enumeration commands.

This section focuses on KQL queries designed to detect the **abnormal frequency and nature** of domain account discovery, such as:

* **High-Volume Command Execution:** Detecting a single user or host running an unusually high number of `net user /domain`, `net group /domain`, or `Get-ADUser` commands in a short period (`DeviceProcessEvents`).
* **Atypical Source:** Hunting for discovery commands originating from non-administrative hosts (e.g., a standard workstation) targeting the entire domain.
* **Rapid Reconnaissance:** Identifying a sequence of discovery commands being executed as part of an automated script or tool designed for fast environment mapping.

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1087.002** | Domain Account | Focuses on command-line analysis to detect attempts at enumerating domain users and groups using native tools (`net.exe`, `PowerShell`). |

#### Queries

**1. Identification of domain enumeration with NET.exe internal tool:**

Identification of the execution of net.exe targeting domain users and domain administrators:

```
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "net.exe" or FileName =~ "net1.exe"
| where ProcessCommandLine has_any("/domain", "group", "user")
| where ProcessCommandLine has_any("Domain Admins", "Enterprise Admins", "Schema Admins")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

**2. PowerShell ADSI/LDAP Reconnaissance:**

Advanced attackers avoid net.exe to bypass basic command-line logging and instead use PowerShell to query LDAP directly via ADSI searchers:

```
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_all("adsisearcher", "findall")
    or ProcessCommandLine has_all("LDAP://", "objectClass=user")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

**3. BloodHound/SharpHound Execution:**

SharpHound is the primary ingestor for BloodHound. It uses specific flags to collect data about domain accounts and their relationships:

```
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any("--CollectionMethod", "-CollectionMethod", "DCOnly", "All,Group", "All")
    or FileName =~ "SharpHound.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

**4. Unusual Domain Controller Queries (IdentityInfo):**

This query identifies when a workstation that doesn't typically perform administrative tasks suddenly starts enumerating a high volume of domain accounts:

```
IdentityQueryEvents
| where Timestamp > ago(24h)
| where QueryType == "LDAP query"
| summarize QueryCount = count() by DeviceName, AccountName, QueryTarget
| where QueryCount > 100
| project DeviceName, AccountName, QueryCount, QueryTarget
| order by QueryCount desc
```