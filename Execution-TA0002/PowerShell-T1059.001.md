## 💻 T1059.001 - PowerShell

**MITRE Tactic:** Execution (TA0002)

### 📝 Description

**PowerShell** is a powerful, integrated, command-line shell and scripting language native to Windows. Adversaries widely abuse PowerShell for a broad range of malicious actions, including executing obfuscated code, downloading payloads, performing reconnaissance, and achieving fileless persistence.  The use of PowerShell is a prime example of **"Living off the Land" (LotL)**, as it is a trusted, built-in system utility, making malicious execution difficult to distinguish from legitimate administrative activity.

In the context of Microsoft Defender XDR, detecting PowerShell abuse relies heavily on analyzing **full command-line activity** and **script execution blocks**.

This section focuses on KQL queries designed to detect the **abnormal, obfuscated, or suspicious usage** of PowerShell, such as:

* **Encoded Commands:** Identifying the use of the `-EncodedCommand` parameter, a common method to hide the script's true intent from simple log analysis (`DeviceProcessEvents`).
* **Base64 Payloads:** Hunting for lengthy Base64 strings within the command line, which often conceal next-stage malware or malicious instructions.
* **Atypical Execution:** Detecting PowerShell commands that perform unusual network actions (like using `Net.WebClient` or `IEX` for external downloads) or disable security features.
* **Suspicious Parentage:** Identifying PowerShell execution where the initiating process is unexpected (e.g., a web browser, an Office document, or a seemingly benign application).

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1059.001** | PowerShell | Focuses on detection via command-line analysis for obfuscation, encoding, dangerous keywords, and abnormal process relationships. |

#### Queries

**1. Detect PowerShell script executions:**

Detect commands that contains powershell on the command line (modify the query to looks for most common attacker commands):

```
// Add specific PowerShell commands you expect attackers to use, if known
DeviceProcessEvents
| where ProcessCommandLine contains "powershell"
| project DeviceName, ProcessCommandLine, Timestamp
```

**2. PowerShell Activities after receiving a suspicious email from known suspicous email:**

Malicious emails often contain documents and other specially crafted attachments that run PowerShell commands to deliver additional payloads. If you are aware of emails coming from a known malicious sender, you can use this query to list and review PowerShell activities that occurred within 30 minutes after an email was received from the sender:

```
//Find PowerShell activities right after email was received from malicious sender
let x=EmailEvents
| where SenderFromAddress =~ "MaliciousSender@example.com"
| project TimeEmail = Timestamp, Subject, SenderFromAddress, AccountName = tostring(split(RecipientEmailAddress, "@")[0]);
x
| join (
DeviceProcessEvents
| where FileName =~ "powershell.exe"
//| where InitiatingProcessParentFileName =~ "outlook.exe"
| project TimeProc = Timestamp, AccountName, DeviceName, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName, ProcessCommandLine
) on AccountName 
| where (TimeProc - TimeEmail) between (0min.. 30min)
```

**3. Detect Encoded PowerShell:**

This query will detect encoded powershell based on the parameters passed during process creation. This query will also work if the PowerShell executable is renamed or tampered with since detection is based solely on a regex of the launch string:

```
DeviceProcessEvents
| where ProcessCommandLine matches regex @'(\s+-((?i)encod?e?d?c?o?m?m?a?n?d?|e|en|enc|ec)\s).*([A-Za-z0-9+/]{50,}[=]{0,2})'
| extend DecodedCommand = replace(@'\x00','', base64_decode_tostring(extract("[A-Za-z0-9+/]{50,}[=]{0,2}",0 , ProcessCommandLine)))
```

**4. Detection of PowerShell Downloads**

Query to track PowerShell commands to download remote files:

```
// Finds PowerShell execution events that could involve a download.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "powershell_ise.exe")
| where ProcessCommandLine has "Net.WebClient"
   or ProcessCommandLine has "DownloadFile"
   or ProcessCommandLine has "Invoke-WebRequest"
   or ProcessCommandLine has "Invoke-Shellcode"
   or ProcessCommandLine has "http"
   or ProcessCommandLine has "IEX"
   or ProcessCommandLine has "Start-BitsTransfer"
   or ProcessCommandLine has "mpcmdrun.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| top 100 by Timestamp
```

**5. Detection of uncommon PowerShell Command Execution:**


```
// Find which uncommon Powershell Cmdlets were executed on that machine in a certain time period.
// This covers all Powershell commands executed in the Powershell engine by any process.
let DeviceId = "device-id";
let timestamp = datetime(2025-10-28T00:00:00Z);
// Query for Powershell cmdlets
let powershellCommands =
    DeviceEvents
    | where ActionType == "PowerShellCommand"
    // Extract the powershell command name from the Command field in the AdditionalFields JSON column
    | project PowershellCommand=extractjson("$.Command", AdditionalFields, typeof(string)), InitiatingProcessCommandLine, InitiatingProcessParentFileName, Timestamp, DeviceId
    | where PowershellCommand !endswith ".ps1" and PowershellCommand !endswith ".exe";
// Filter Powershell cmdlets executed on relevant machine and time period
powershellCommands | where DeviceId == DeviceId and Timestamp between ((timestamp-5min) .. 10min)
// Filter out common powershell cmdlets
| join kind=leftanti (powershellCommands | summarize MachineCount=dcount(DeviceId) by PowershellCommand | where MachineCount > 20) on PowershellCommand
```