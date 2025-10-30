## 🔑 T1003 - OS Credential Dumping

**MITRE Tactic:** Credential Access (TA0006)

### 📝 Description

**OS Credential Dumping (T1003)** involves adversaries attempting to harvest credentials, such as password hashes, Kerberos tickets, and cleartext passwords, from the operating system's memory or files. The most well-known target is the **Local Security Authority Subsystem Service (LSASS)** memory process. Successful credential dumping often leads directly to Lateral Movement (using Pass-the-Hash or Pass-the-Ticket) and Privilege Escalation. 

In the context of Microsoft Defender XDR, detecting credential dumping is highly reliant on monitoring low-level endpoint activities, specifically process access and file creation events targeting sensitive system files and processes.

This section focuses on KQL queries designed to detect the **abnormal access and manipulation** of system processes and files used to store credentials, across all major sub-techniques.

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1003.001** | LSASS Memory | Detection of non-standard processes accessing the memory of `lsass.exe`. |
| **T1003.002** | Security Account Manager | Detection of unauthorized access to the `SAM` and `SYSTEM` registry hives/files. |
| **T1003.003** | NTDS.dit | Detection of access or transfer of the primary Active Directory database file. |
| **T1003.004** | LSA Secrets | Detection of activities targeting the Local Security Authority secrets storage. |
| **T1003.005** | Cached Domain Credentials | Detection of access to stored cached credentials on workstations. |
| **T1003.006** | DCSync | Monitoring for the use of the DCSync function by non-Domain Controllers. |
| **T1003.007** | Kerberos | Detection of attempts to harvest Kerberos tickets (e.g., using Mimikatz's `kerberos::list`). |

#### Queries

**1. Detection of suspicious access to LSASS from common tools for credentials dumping:**

Query to detect tools like procdump or mimikatz dumping LSASS:

```
// Look for suspicious access to LSASS (commonly targeted for credential dumping)
DeviceProcessEvents
| where ProcessCommandLine contains "lsass.exe"
| where InitiatingProcessCommandLine contains "procdump" or InitiatingProcessCommandLine contains "mimikatz"
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine
```

Checking for LSASS dump with known tools:

```
DeviceProcessEvents
// Looking for Accepteula flag or Write a dump file with all process memory
| where (FileName has_any ("procdump.exe", "procdump64.exe") and ProcessCommandLine has "lsass") or (ProcessCommandLine has "lsass.exe" and (ProcessCommandLine has "-accepteula" or ProcessCommandLine contains "-ma"))
```

```
DeviceProcessEvents 
| where InitiatingProcessFileName in ("mimikatz.exe", "procdump.exe", "rundll32.exe", "powershell.exe", "taskmgr.exe", "cmd.exe", "wmiprvse.exe") 
| where ProcessCommandLine has "lsass" or InitiatingProcessCommandLine has "lsass" 
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine 
| order by Timestamp desc
```

Narrow the search to specific devices and process:

```
DeviceEvents 
| where ActionType in ("OpenProcessApiCall", "ReadProcessMemoryApiCall", "CreateRemoteThreadApiCall", "NtAllocateVirtualMemoryApiCall", "NtMapViewOfSectionRemoteApiCall", "WriteToLsassProcessMemory", "SetThreadContextRemoteApiCall") 
| where FileName == "lsass.exe"  // Target LSASS process 
| where InitiatingProcessFileName == "wmiprvse.exe"  // Detect WMI abuse 
| where DeviceName has "Laptop-123" 
| project Timestamp, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName 
| order by Timestamp desc 
```

**2. SAM/SYSTEM File Access for Dumping**

This KQL query detects suspicious read attempts or file copies of the SAM and SYSTEM files. Adversaries often copy these files to a separate location (like a temporary directory) before extracting the hashes offline.

```
DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed", "FileAccessed")
| where (
    // Target the core SAM and SYSTEM files
    FileName in ("SAM", "SYSTEM") or
    // Look for processes reading them from the common system folder
    FolderPath has_any (@"C:\Windows\System32\config\SAM", @"C:\Windows\System32\config\SYSTEM")
)
// Exclude common and legitimate processes (Tuning required for your environment!)
| where InitiatingProcessFileName !in (
    "lsass.exe",        // Legitimate access by the security subsystem itself
    "services.exe",     // Legitimate service control manager access
    "winlogon.exe",     // Legitimate logon access
    "MsMpEng.exe",      // Defender Antivirus
    "System"            // Kernel activity
)
// Focus on file creation/copy to suspicious locations
| where (
    ActionType == "FileCreated" and FolderPath has_any ("\\Users\\", "\\Temp\\", "\\AppData\\")
    or ActionType == "FileAccessed"
)
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    FileName,
    FolderPath,
    ActionType,
    SHA256
| sort by Timestamp desc
```