## 📜 T1059.007 - JavaScript/JScript

**MITRE Tactic:** Execution (TA0002)

### 📝 Description

**JavaScript/JScript** utilizes the Windows Script Host (WScript/CScript) to execute code outside of a web browser, making it a popular choice for adversaries to execute malicious files received via email or downloaded from the web. This method provides a "fileless" path for initial execution and subsequent staging. 

Adversaries abuse script interpreters (`wscript.exe` and `cscript.exe`) to execute various forms of malicious code, often obscured or obfuscated to evade detection.

In the context of Microsoft Defender XDR, detecting JScript/JavaScript abuse primarily involves monitoring the script host processes and their command lines for unusual behavior and parameters.

This section focuses on KQL queries designed to detect the **abnormal execution and behavior** of WScript and CScript, such as:

* **Suspicious Execution:** Detecting `wscript.exe` or `cscript.exe` spawning highly suspicious child processes like PowerShell, CMD, or executable downloads (`DeviceProcessEvents`).
* **Unusual File Extensions:** Hunting for script files being executed from non-standard locations or with unusual paths, especially from temporary directories (`DeviceProcessEvents` and `DeviceFileEvents`).
* **Script Host Abuse:** Monitoring command lines for attempts to execute scripts remotely, or containing parameters indicative of obfuscation or persistence mechanisms.

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1059.007** | JavaScript/JScript | Focuses on detection via process monitoring of `wscript.exe` and `cscript.exe` and the subsequent actions they initiate. |

#### Queries

**1. Office Applications Launching wscript.exe to run JScript:**

This query was originally published in the threat analytics report, Trickbot: Pervasive & underestimated.

https://attack.mitre.org/software/S0266/

Trickbot is a very prevalent piece of malware with an array of malicious capabilities. Originally designed to steal banking credentials, it has since evolved into a modular trojan that can deploy other malware, disable security software, and perform command-and-control (C2) operations.

Trickbot is frequently spread through email. An attacker will send a target a message with an attachment containing a malicious macro. If the target enables the macro, it will write a JScript Encoded (JSE) file to disk (JScript is a Microsoft dialect of ECMAScript). The JSE file will then be launched using wscript.exe to perform a variety of malicious tasks, particularly reconnaissance.

The following query detects when Office applications have launched wscript.exe to run a JSE file.

See Detect rundll.exe being used for reconnaissance and command-and-control for another query related to Trickbot activity.

https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Command%20and%20Control/recon-with-rundll.md

```
DeviceProcessEvents 
| where InitiatingProcessFileName in~('winword.exe', 'excel.exe', 'outlook.exe') 
| where FileName =~ "wscript.exe" and ProcessCommandLine has ".jse" or ProcessCommandLine has "JS"
```

**2. Script Hosts Spawning Malicious Binaries:**

This query detects when the native Windows Script Host interpreters (wscript.exe and cscript.exe) spawn a known suspicious process, such as a command prompt, PowerShell, or tools often used for downloading payloads:

```
DeviceProcessEvents
| where ActionType == "ProcessCreated"
// 1. Identify the script host parent processes
| where InitiatingProcessFileName in ("wscript.exe", "cscript.exe")
// 2. Identify the highly suspicious child processes
| where FileName in ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'mshta.exe', 'bitsadmin.exe', 'certutil.exe', 'schtasks.exe', 'regsvr32.exe', 'msiexec.exe')
// 3. Optional: Filter out known benign, though rare, administrative exceptions
// | where not(CommandLine has "legitimate_script_name.js")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName, // The Script Host
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName, // Process that launched the script host (often explorer.exe or outlook.exe)
    FileName, // The suspicious child process (the payload)
    CommandLine, // The full command executed
    FolderPath,
    AccountName
| sort by Timestamp desc
```