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
| where FileName in ("net.exe", "net1.exe") 
| where ProcessCommandLine has_any ("net  group \"domain admins\" /domain ", "net  users /domain") 
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine 
| order by Timestamp desc 
```