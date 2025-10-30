## 💾 T1547.001 - Registry Run Keys / Startup Folder

**MITRE Tactic:** Persistence (TA0003)

### 📝 Description

**Registry Run Keys / Startup Folder (T1547.001)** is the most common persistence technique on Windows systems. Adversaries configure files, programs, or scripts to execute automatically when a user logs on, either through standard Startup folders or by modifying specific **"Run"** and **"RunOnce"** keys within the Windows Registry. 

This method guarantees that the malicious code will relaunch after reboots or logoffs, ensuring continued access to the system.

In the context of Microsoft Defender XDR, detecting this technique requires deep monitoring of **Registry Events** and subsequent **Process Execution Events**.

This section focuses on KQL queries designed to detect the **creation or modification of persistence mechanisms** in high-value locations, such as:

* **Registry Modification:** Detecting changes to the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` and `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` keys (`DeviceRegistryEvents`).
* **Startup Folder Writes:** Hunting for new executable or script files being written to user or system Startup folders (`DeviceFileEvents`).
* **Atypical Execution:** Identifying processes launched from these persistence locations that exhibit suspicious behavior (e.g., encoded command lines, downloading additional files).

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1547.001** | Registry Run Keys / Startup Folder | Focuses on file and registry events that establish an auto-start mechanism for malicious code upon user logon. |

#### Queries

**1. Detection of new registry keys:**

Detection of new registry keys creation during time of the attack:

```
DeviceRegistryEvents 
| where ActionType == "RegistryValueSet" 
| where RegistryKey has "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" 
| where RegistryValueData has "wscript.exe //B" 
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine 
| order by Timestamp desc 
```