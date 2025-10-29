## T1566 - Phishing 🎣

**MITRE Tactic:** Initial Access (TA0001)

### 📝 Description

Adversaries frequently rely on **Phishing** to gain their initial foothold, often by leveraging electronic social engineering techniques to trick users into executing malicious code, clicking a malicious link, or providing credentials.

In the context of Microsoft Defender XDR, detecting phishing involves correlating events across the entire security stack, including **Email & Collaboration**, **Endpoint**, and **Identity** logs.

This section focuses on KQL queries designed to detect the **post-delivery actions** that signify a successful or attempted phishing campaign, such as:

* **Attachment Execution:** Detecting suspicious processes spawned by email clients or document readers (`EmailAttachmentInfo` correlated with `DeviceProcessEvents`).
* **Malicious Link Clicks:** Identifying unusual network connections initiated immediately after an email is clicked (`EmailUrlInfo` correlated with `DeviceNetworkEvents`).
* **Credential Harvesting:** Looking for successful sign-ins immediately following a Defender for Office 365 alert on a suspicious link or attachment.

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1566.001** | Spearphishing Attachment | Execution of file types known to harbor malware (e.g., .iso, .img, macro-enabled documents). |
| **T1566.002** | Spearphishing Link | Detection of suspicious browser activity or network connections to known malicious/phishing sites. |
| **T1566.003** | Spearphishing via Service | Malicious messages/files sent via collaboration platforms (e.g., Teams) and subsequent activity. |

#### Queries

**1. Identify who downloaded the malicious attachment:** 

This query will help us to identify all to extract information about the users that have downloaded the malicious attachment.

```
DeviceFileEvents
// Look back for the last 7 days (adjust as needed, max is usually 30 days in AH)
| where Timestamp > ago(7d)
// Modify the hash and the file name to fit your case
| where SHA256 == "16cbe40fb24ce2d422afddb5a90a5801ced32ef52c22c2fc77b25a90837f28ad" or FileName contains "putty.exe"
// Common ActionTypes for new files/downloads
| where ActionType == "FileCreated" or ActionType == "FileDownloaded"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, Folder-Path, SHA256, InitiatingProcessAccountName, FileOriginUrl, ReportId
| sort by Timestamp desc

```


**2. Identify who clicked on the malicious link:**

Query to help to identify fast which users within the company have clicked on the malicious link.

```
UrlClickEvents
| where Url contains "example.com"
```

**3. Identify malcious attachments executed by Email Software:**

Query to help to identify possible malicious files where the parent process responsible of the execution is an email software:

```
// Detect execution of suspicious attachments from email clients
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("outlook.exe", "thunderbird.exe", "winmail.exe")
    // Add other email client executables relevant to your environment
| where FileName endswith ".exe" or FileName endswith ".dll" or FileName endswith ".scr" or FileName endswith ".hta"
    // Modify the list of extensions based on common malicious attachment types
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**4. Detect Word Document Macro Execution from Email Client:**

This query focuses on the DeviceProcessEvents table and uses the parent-child process relationship to spot Microsoft Word (winword.exe) executing known dangerous child processes:

```
DeviceProcessEvents
// 1. Filter the ultimate process being executed (the malicious payload runner)
| where FileName in ('cmd.exe', 'powershell.exe', 'pwsh.exe', 'cscript.exe', 'wscript.exe', 'mshta.exe', 'bitsadmin.exe', 'certutil.exe')
// 2. Filter the immediate parent process (the document reader) to Microsoft Word
| where InitiatingProcessFileName =~ ("winword.exe", "excel.exe", "outlook.exe")
// 3. Filter the grandparent process (the launcher of the document) to common email clients
| where InitiatingProcessParentFileName in ('outlook.exe', 'thunderbird.exe', 'mail.exe', 'opera.exe') // Add other relevant mail clients if needed
| project
    Timestamp,
    DeviceName,
    InitiatingProcessParentFileName, // The email client (Grandparent)
    InitiatingProcessFileName, // The document process (winword.exe - Parent)
    InitiatingProcessCommandLine,
    FileName, // The suspicious process (Child)
    CommandLine, // The command line of the suspicious process
    FolderPath,
    ActionType
```