## ⏰ T1053.005 - Scheduled Task/Job: Scheduled Task

**MITRE Tactic:** Persistence (TA0003), Execution (TA0002), Privilege Escalation (TA0004)

### 📝 Description

The **Scheduled Task (T1053.005)** technique is abused by adversaries to execute malicious code on a recurring basis or upon a defined system event (such as system boot or user logon). This technique leverages the legitimate Windows Task Scheduler service and utility (`schtasks.exe` or PowerShell cmdlets) to achieve reliable persistence and can also be used for privilege escalation if tasks are created with higher privileges. 

Detection is critical as scheduled tasks are often "set and forget" persistence mechanisms.

In the context of Microsoft Defender XDR, detecting this technique requires analyzing process execution events and detailed task creation logs.

This section focuses on KQL queries designed to detect the **creation and execution** of suspicious scheduled tasks, such as:

* **Task Creation:** Detecting the use of `schtasks.exe` or PowerShell (`New-ScheduledTask`) with parameters that define suspicious triggers (e.g., repeating, on logon) or point to suspicious actions (e.g., executing files from temporary directories) (`DeviceProcessEvents`).
* **Suspicious Execution:** Hunting for tasks executing commands that lack normal task metadata, run under unusual user contexts, or launch known execution proxies (`DeviceProcessEvents`).
* **Task File Writes:** Monitoring the Task Scheduler directory for new or modified task files (`DeviceFileEvents`).

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1053.005** | Scheduled Task | Focuses on command-line analysis of task creation utilities and monitoring the subsequent execution of the malicious tasks. |

#### Queries

**Enumeration of Created Tasks:**

Enumerate all the created tasks filtering by device:

```
DeviceEvents 
// Filter by device:
| where DeviceName contains "test"
| where ActionType == "ScheduledTaskCreated" and InitiatingProcessAccountSid != "S-1-5-18"
```