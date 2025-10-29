# 🛡️ Defender KQL Queries Mapped to MITRE ATT&CK

## 📖 Overview

Welcome to the **Defender KQL Queries Mapped to MITRE ATT&CK** repository!

This public repository is a curated collection of **Kusto Query Language (KQL)** queries specifically designed for use in **Microsoft Defender XDR** (including Defender for Endpoint, Defender for Office 365, etc.)'s Advanced Hunting feature.

The primary goal of this repository is to provide security analysts, threat hunters, and SecOps teams with readily available, high-fidelity queries to detect malicious and suspicious activities mapped directly to the globally recognized **MITRE ATT&CK® framework**. 

## ✨ Features

* **Tactics-First Structure:** Queries are organized primarily by **MITRE ATT&CK Tactics**, making it easy to hunt based on the overarching adversary goal (e.g., Initial Access, Persistence, Defense Evasion).
* **Technique-Specific Detail:** Within each Tactic folder, queries are further broken down by specific **Techniques (T-IDs)** for precise hunting.
* **High-Fidelity:** Focus on queries that minimize false positives and highlight true security events.
* **Ready-to-Use:** All queries are tested and ready to be copied and pasted directly into the Microsoft Defender XDR Advanced Hunting interface.

## 📂 Repository Structure

The core structure is organized by MITRE ATT&CK Tactics:

## 🔎 How to Use

1.  **Identify Your Target:** Determine which **MITRE ATT&CK Tactic** or **Technique** you want to hunt for.
2.  **Navigate:** Go to the corresponding folder (e.g., `TA0003_Persistence`).
3.  **Select Query:** Choose the `.kql` file for the specific technique (e.g., `T1547.001_Registry_Run_Keys.kql`).
4.  **Copy & Paste:** Copy the entire KQL code.
5.  **Execute:** Paste the query into the **Advanced Hunting** section of the Microsoft Defender XDR portal and run it.
6.  **Analyze:** Review the results for potential threats or suspicious activity.

## 💡 Contributing

This repository thrives on community contributions! We welcome and encourage submissions from everyone.

### Guidelines for Submissions:

1.  **Format:** Queries must be in a `.kql` file and fully functional in Microsoft Defender XDR Advanced Hunting.
2.  **Naming:** Name your file using the format: `[Descriptive Name]_[Technique ID].kql` (e.g., `PowerShell_Execution_Detection_T1059.001.kql`).
3.  **Location:** Place the query file in the folder corresponding to its primary **MITRE Tactic**.
4.  **Header Comments:** Each query **must** include a header section with:
    * **Technique ID & Name**
    * **Description** of what the query is detecting.
    * **Severity** (High, Medium, Low).
    * **Author** (Your GitHub Handle).

**Example Header:**

```
kql
// Technique: T1547.001 - Registry Run Keys / Startup Folder
// Description: Detects new registry key additions to the HKCU or HKLM Run keys for persistence.
// Severity: High
// Author: @YourGitHubHandle

// KQL Query starts here...
```

## 🌐 Connect

If you have questions, feedback, or want to discuss threat hunting, please open an issue!

## 🔗 Helpful Links where you can find more queries:

[https://github.com/francoisfried/Defender-Advanced-Hunting-Queries](https://github.com/francoisfried/Defender-Advanced-Hunting-Queries)

[https://github.com/SlimKQL/Hunting-Queries-Detection-Rules](https://github.com/SlimKQL/Hunting-Queries-Detection-Rules)

[https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries)

[https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)

[https://github.com/LearningKijo/KQL](https://github.com/LearningKijo/KQL)

[https://github.com/RoqueNight/DefenderATP-Proactive-Threat-Hunting-Queries-KQL](https://github.com/RoqueNight/DefenderATP-Proactive-Threat-Hunting-Queries-KQL)