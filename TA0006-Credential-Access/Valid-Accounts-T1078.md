## 👥 T1078 - Valid Accounts

**MITRE Tactics:** Credential Access (TA0006)

### 📝 Description

**Valid Accounts (T1078)** describes the abuse of legitimate credentials (usernames and passwords, application keys, or tokens) to access systems, resources, and services. This technique is highly valued by adversaries because it provides instant access, allows them to blend into normal user activity , and helps bypass many signature-based defenses. The compromise of a valid account can be the result of successful phishing, credential dumping, or brute-force attacks.

In the context of Microsoft Defender XDR, detecting the abuse of valid accounts requires comprehensive correlation across **Identity (Azure AD)**, **Endpoint**, and **Cloud App** events.

This section focuses on KQL queries designed to detect the **abnormal and suspicious use** of valid credentials, such as:

* **Impossible Travel:** Identifying logons for the same user from geographically distant locations within an impossible time frame (`IdentityLogonEvents`).
* **Atypical Sign-in Patterns:** Detecting unusual properties (IP address, user agent, time of day) for a user or service account compared to their historical baseline (`IdentityLogonEvents`).
* **Service Principal Abuse:** Hunting for compromised application accounts (service principals) showing a sudden, high volume of resource access (`CloudAppEvents`).
* **Privilege Abuse:** Monitoring accounts for the rapid elevation of roles or access to sensitive data immediately following a successful logon.

### 📁 Sub-Techniques Covered

| Sub-Technique ID | Name | Focus |
| :--- | :--- | :--- |
| **T1078.001** | Domain Accounts | Detection of lateral movement or persistence using standard domain credentials. |
| **T1078.002** | Local Accounts | Detection of lateral movement or persistence using non-privileged local machine accounts. |
| **T1078.003** | Cloud Accounts | Detection of logons and resource access abuse within platforms like Microsoft 365 and Azure. |
| **T1078.004** | Service Accounts | Detection of automated account credentials (service principals) being used in an interactive or unusual manner. |

#### Queries

**1. Enumerating User Sign-ins Interactive & Non-interactive:**

Enumerating the user's login:

```
IdentityLogonEvents
// Filter by user:
//| where AccountName contains "test"
| where AccountDisplayName contains "test"
| where Timestamp > ago(7d) // Adjust lookback window as needed
| project
    Timestamp,
    LogonType,
    AccountUpn,
    AccountDisplayName,
    Application, // The service/client used for the sign-in
    IPAddress,
    Location,
    DeviceName,
    DeviceType,
    AdditionalFields
| sort by Timestamp desc
```

Example of query with exclusions:

```
IdentityLogonEvents
// Filter by user:
//| where AccountName contains "test"
| where AccountDisplayName contains "Test"
| where Timestamp > ago(7d) // Adjust lookback window as needed
// Exclude Sign-in Activity types that are typically too noisy or not relevant for principal logon tracking
| where Application != "Microsoft Defender for Cloud Apps"
| extend IsNonInteractive = (
    // Condition 1: Service Principal/Token refresh indicators
    (Application has_any ("AAD sign-in activity", "Azure AD Sign-in", "Azure Active Directory") and AdditionalFields has_any ("token", "refresh"))
    // OR
    or
    // Condition 2: System or Service Principal accounts accessing common cloud services
    (Application has_any ("Azure Active Directory", "Exchange Online", "SharePoint Online") and AccountObjectId has_any ("system", "service", "app"))
    // OR
    or
    // Condition 3: Missing Application details (often indicates protocol-level or resource logon)
    (isempty(Application))
)
| extend LogonType = iff(
    IsNonInteractive,
    "Non-Interactive (Token/Service/System)",
    "Interactive (User Client or Other)"
)
| project
    Timestamp,
    LogonType,
    AccountUpn,
    AccountDisplayName,
    Application, // The service/client used for the sign-in
    IPAddress,
    DeviceName,
    AdditionalFields
| sort by Timestamp desc
```