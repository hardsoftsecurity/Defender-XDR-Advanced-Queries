## 🌐 T1189 - Drive-by Compromise

**MITRE Tactic:** Initial Access (TA0001)

### 📝 Description

The **Drive-by Compromise (T1189)** technique involves adversaries gaining access to a victim's system through a user visiting a compromised or malicious website, often over the normal course of web browsing. Unlike spearphishing, where a malicious link is sent directly, this technique relies on **user execution** of malicious content hosted on a web server. 

In the context of Microsoft Defender XDR, detecting T1189 requires detailed monitoring of network and process creation events, specifically tracing activities originating from web browsers.

This section focuses on KQL queries designed to detect the **initial payload delivery and execution** stemming from a web browser process, such as:

* **Suspicious Downloads:** Detecting executable or script files being written to the file system immediately following a connection to an unusual or known malicious domain (`DeviceFileEvents` correlated with `DeviceNetworkEvents`).
* **Browser Spawning:** Identifying web browsers (`chrome.exe`, `msedge.exe`, `firefox.exe`, etc.) spawning highly suspicious child processes like command shells or script interpreters, which is often indicative of a browser exploit or malvertising chain (`DeviceProcessEvents`).
* **Unusual Network Flows:** Hunting for rapid, unusual network connections (e.g., communication to command and control) initiated by the browser immediately after visiting a new domain.

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1189** | Drive-by Compromise | Focuses on detection of payload download and execution where the initiating process is a common web browser. |

#### Queries

**1. Drive-by Compromise:**

Query to help to detect script executed by browsers to detect driver-by compromise, where the attackers redirect the users to compromised websites to download those scripts:

```
// Detect execution of scripts or downloads initiated by web browsers
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe", "safari.exe")
    // Add or remove browsers as necessary
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".js" or FileName endswith ".vbs"
    // Include file types that could be maliciously downloaded
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, 
InitiatingProcessParentFileName
| order by Timestamp desc
```

**2. Drive-by Compromise:**

This query detects when a standard web browser process initiates the execution of known dangerous child processes (command prompt, PowerShell, script interpreters), a strong indicator of a drive-by download or client-side exploit:

```
DeviceProcessEvents
// 1. Filter for the suspicious process (the payload)
| where FileName in ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'cscript.exe', 'wscript.exe', 'mshta.exe', 'bitsadmin.exe', 'certutil.exe')
// 2. Filter the parent process (the launcher) to common web browsers
| where InitiatingProcessFileName in ('msedge.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe')
| where ActionType == "ProcessCreated"
// 3. Optional: Filter out known benign exceptions (e.g., specific scripts run by the browser itself)
// | where not(InitiatingProcessCommandLine has "safebrowsing")
// | where not(InitiatingProcessCommandLine has "extension")
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName, // The Web Browser
    InitiatingProcessCommandLine,
    FileName, // The suspicious process (e.g., powershell.exe)
    CommandLine, // The full command executed
    FolderPath,
    InitiatingProcessCreationTime,
    InitiatingProcessId,
    ProcessId
```