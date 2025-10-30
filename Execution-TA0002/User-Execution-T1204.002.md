## 🗃️ T1204.002 - User Execution: Malicious File

**MITRE Tactic:** Execution (TA0002)

### 📝 Description

**User Execution: Malicious File (T1204.002)** describes the method where an adversary relies on social engineering to trick a user into executing or opening a malicious file attachment, often received via phishing or a drive-by download. The malicious files are frequently disguised as common or harmless file types (e.g., PDFs, invoices, password-protected archives, ISO/IMG files).  This technique is essential for initial access and execution across countless attack campaigns.

In the context of Microsoft Defender XDR, detecting this technique requires looking for the immediate **consequences** of the user opening the file, as the malicious code executes.

This section focuses on KQL queries designed to detect the **suspicious process activity** triggered by the malicious file, such as:

* **Office Macro Execution:** Detecting Microsoft Office applications (`winword.exe`, `excel.exe`) spawning execution-related child processes (`cmd.exe`, `powershell.exe`).
* **Archive/Disk Image Abuse:** Monitoring for highly unusual execution patterns stemming from files mounted or extracted from ISO, IMG, or ZIP files.
* **Atypical Parent-Child Relations:** Hunting for common file types (like PDF readers or image viewers) that suddenly launch system execution binaries.
* **Initial Download Location:** Correlating suspicious execution with files recently downloaded from the internet or opened from email attachment folders.

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1204.002** | Malicious File | Focuses on process creation events where the parent process is a common document reader or file handler, and the child process is an execution tool. |

#### Queries

**1. Search for malicious files:**

Identification of malicious files downloaded or transfered during an attack and executed by the user:

```
DeviceFileEvents 
| where SHA1 == "SHA1HASH" or MD5 == "MD5HASH" 
| project Timestamp, DeviceName, FileName, SHA1, MD5, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine 
| order by Timestamp desc 
```