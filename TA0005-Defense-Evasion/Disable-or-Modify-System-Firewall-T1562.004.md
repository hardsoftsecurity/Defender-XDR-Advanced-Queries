# 🛡️ T1562 - Impair Defenses
**MITRE Tactic:** Defense Evasion (TA0006)

## 📝 Description
**Impair Defenses (T1562)** involves adversaries targeting security components to stay under the radar. By disabling or modifying security tools, they ensure their malicious activities don't trigger alerts or get blocked. This is a critical step in the attack lifecycle, often occurring immediately after initial access or during lateral movement.

In Microsoft Defender XDR, we look for unauthorized tampering with the Defender agent itself, the disabling of local firewalls, and the silencing of cloud-native logging (like Azure Activity Logs or Resource Diagnostic settings).

---

## 📁 Sub-Techniques Covered
| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1562.004** | Disable or Modify System Firewall | Detection of commands used to disable the host firewall or open unauthorized ports. |

---

## 🔍 KQL Queries

### 1. Disable or Modify System Firewall
Adversaries often disable the netsh firewall or add "Allow" rules for their backdoors. This query flags the disabling of the global firewall state.

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "netsh.exe"
| where ProcessCommandLine has_all("advfirewall", "off") 
    or ProcessCommandLine has "firewall add rule"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp desc
```