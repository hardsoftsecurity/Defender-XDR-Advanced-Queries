# 🛡️ T1562 - Impair Defenses
**MITRE Tactic:** Defense Evasion (TA0006)

## 📝 Description
**Impair Defenses (T1562)** involves adversaries targeting security components to stay under the radar. By disabling or modifying security tools, they ensure their malicious activities don't trigger alerts or get blocked. This is a critical step in the attack lifecycle, often occurring immediately after initial access or during lateral movement.

In Microsoft Defender XDR, we look for unauthorized tampering with the Defender agent itself, the disabling of local firewalls, and the silencing of cloud-native logging (like Azure Activity Logs or Resource Diagnostic settings).

---

## 📁 Sub-Techniques Covered
| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1562.001** | Disable or Modify Tools | Detection of tampering with Antivirus (AV) and Endpoint Detection and Response (EDR) services. |

---

## 🔍 KQL Queries

### 1. Disable or Modify Tools (Defender Tampering)
This query identifies attempts to stop the Microsoft Defender Antivirus service or exclude folders from scanning via PowerShell.

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any("Set-MpPreference -DisableRealtimeMonitoring $true", "Stop-Service WinDefend", "Remove-MpPreference", "Add-MpPreference", "-Command Add-MpPreference -ExclusionProcess")
    or (ProcessCommandLine has "Set-MpPreference" and ProcessCommandLine has "ExclusionPath")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```