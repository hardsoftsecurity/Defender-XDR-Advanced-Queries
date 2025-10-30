## ⌨️ T1059.003 - Windows Command Shell

**MITRE Tactic:** Execution (TA0002)

### 📝 Description

The **Windows Command Shell (T1059.003)** involves adversaries using the native command interpreter, `cmd.exe`, to execute commands and script files (like `.bat`, `.cmd`). While less feature-rich than PowerShell, `cmd.exe` is ubiquitous, highly trusted, and often utilized as a simple wrapper to execute more complex scripts or to perform basic system interactions (e.g., net commands, user creation, file manipulation). 

Its benign nature makes malicious use difficult to detect without deep command-line analysis.

In the context of Microsoft Defender XDR, detecting Command Shell abuse requires rigorous analysis of `cmd.exe` command lines and its process relationships.

This section focuses on KQL queries designed to detect the **abnormal and suspicious use** of `cmd.exe`, such as:

* **Suspicious Parentage:** Identifying `cmd.exe` execution where the initiating process is unexpected (e.g., an Office document, a web browser, or a script host like `wscript.exe`).
* **Execution Proxies:** Hunting for `cmd.exe` used to launch known malicious binary execution methods (e.g., `mshta.exe`, `certutil.exe`, `bitsadmin.exe`).
* **Atypical Commands:** Monitoring command lines for specific commands that are rarely used by regular users but common in post-exploitation phases (e.g., disabling firewalls, creating users, or specific network configuration commands).

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1059.003** | Windows Command Shell | Focuses on command-line analysis of `cmd.exe` for specific malicious keywords, encoding, and dangerous parent-child process relationships. |

#### Queries

**1. Detection of Windows Commmand Shell executions:**

Checking on defender for cmd.exe executions through KQL queries looking for IoCs & TTPs identified during the investigation:

```
DeviceProcessEvents 
| where FileName in ("cmd.exe")
| where ProcessCommandLine has "wmic" or ProcessCommandLine has "winmgmt" or ProcessCommandLine has "wscript" or ProcessCommandLine has "powershell" 
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine 
| order by Timestamp desc 
```