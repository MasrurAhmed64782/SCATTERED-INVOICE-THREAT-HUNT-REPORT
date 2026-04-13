# 🛡️ Threat Hunt Report – Scattered Spider BEC Investigation

---

## 📌 Executive Summary

This threat hunt investigated a Business Email Compromise (BEC) attack resulting in a fraudulent £24,500 wire transfer attempt. The attacker leveraged compromised credentials and MFA fatigue techniques to gain access to a corporate account. Post-authentication, the attacker established persistence via inbox rules, exfiltrated sensitive communications, and executed internal phishing. The activity was attributed to the Scattered Spider threat group, highlighting critical gaps in conditional access enforcement and user awareness.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Document evidence, detection gaps, and response opportunities  

---

## 🧭 Scope & Environment

- **Environment:** Microsoft Sentinel (law-cyber-range)  
- **Data Sources:** SigninLogs, EmailEvents, CloudAppEvents  
- **Timeframe:** 2026-02-25 → 2026-02-26  

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The investigation revealed a full attack chain beginning with credential compromise likely sourced from infostealer malware. The attacker conducted an MFA fatigue attack, successfully gaining access after multiple push attempts. Once inside, they accessed Outlook Web, created malicious inbox rules for persistence and evasion, and targeted financial communications.

The attacker executed internal BEC by hijacking an email thread and sending fraudulent banking details. Additional activity showed access to OneDrive and SharePoint, indicating potential data exposure beyond email.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Valid Accounts | T1078 | High |
| 2 | Initial Access | T1078 | High |
| 3 | Geo Anomaly | T1078 | Medium |
| 4 | MFA Required | N/A | High |
| 5 | MFA Fatigue Attempts | T1621 | High |
| 6 | Cloud App Access | T1078 | Medium |
| 7 | Device Profiling | T1204 | Medium |
| 8 | Browser Anomaly | T1204 | Medium |
| 9 | Mail Access | T1114 | High |
| 10 | Inbox Rule Creation | T1564.008 | High |
| 11 | Defense Evasion | T1564.008 | High |
| 12 | Data Exfiltration | T1041 | High |
| 13 | Collection | T1114 | High |
| 14 | Rule Priority Abuse | T1564.008 | High |
| 15 | Defense Evasion | T1564.008 | High |
| 16 | Indicator Removal | T1070 | High |
| 17 | Internal Phishing | T1566.002 | High |
| 18 | Social Engineering | T1566 | High |
| 19 | Lateral Movement | T1021 | Medium |
| 20 | Session Reuse | T1078 | High |
| 21 | Cloud Storage Access | T1530 | Medium |
| 22 | SharePoint Access | T1530 | Medium |
| 23 | Session Correlation | T1078 | High |
| 24 | Defense Evasion | T1562 | High |
| 25 | MFA Fatigue | T1621 | High |
| 26 | Email Rule Hiding | T1564.008 | High |
| 27 | Credential Access | T1555 | High |
| 28 | Incident Response | N/A | Critical |
| 29 | Threat Attribution | N/A | High |
| 30 | Environment Validation | N/A | Low |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary>🚩 <strong>Flag 1: Compromised Account</strong></summary>

- **Finding:** m.smith@lognpacific.org confirmed compromised  
- **Why it matters:** Entry point for full attack chain  

**KQL**
```
SigninLogs
| where UserPrincipalName contains "smith"
| distinct UserPrincipalName
```

</details>

---

<details>
<summary>🚩 <strong>Flag 2: Attacker IP</strong></summary>

- **Finding:** 205.147.16.190  
- **Why it matters:** Primary IOC for attacker activity  

</details>

---

<details>
<summary>🚩 <strong>Flag 3: Attack Origin</strong></summary>

- **Finding:** NL (Netherlands)  
- **Why it matters:** Geographic anomaly  

</details>

---

<details>
<summary>🚩 <strong>Flag 4: MFA Failure Code</strong></summary>

- **Finding:** 50074  
- **Why it matters:** Indicates MFA challenge not satisfied  

</details>

---

<details>
<summary>🚩 <strong>Flag 5: MFA Attempts</strong></summary>

- **Finding:** 3 attempts  
- **Why it matters:** Confirms MFA fatigue attack  

</details>

---

<details>
<summary>🚩 <strong>Flag 6: Application Accessed</strong></summary>

- **Finding:** Outlook Web  
- **Why it matters:** Indicates remote/browser-based access  

</details>

---

<details>
<summary>🚩 <strong>Flag 7: Attacker OS</strong></summary>

- **Finding:** Linux  
- **Why it matters:** Deviates from corporate baseline  

</details>

---

<details>
<summary>🚩 <strong>Flag 8: Browser</strong></summary>

- **Finding:** Firefox 147.0  
- **Why it matters:** Adds anomaly layer  

</details>

---

<details>
<summary>🚩 <strong>Flag 9: First Action</strong></summary>

- **Finding:** MailItemsAccessed  
- **Why it matters:** Confirms reconnaissance  

</details>

---

<details>
<summary>🚩 <strong>Flag 10: Rule Creation</strong></summary>

- **Finding:** New-InboxRule  
- **Why it matters:** Persistence mechanism  

</details>

---

<details>
<summary>🚩 <strong>Flag 11: Rule Name</strong></summary>

- **Finding:** .  
- **Why it matters:** Designed to evade detection  

</details>

---

<details>
<summary>🚩 <strong>Flag 12: Forward Address</strong></summary>

- **Finding:** insights@duck.com  
- **Why it matters:** Data exfiltration  

</details>

---

<details>
<summary>🚩 <strong>Flag 13: Keywords</strong></summary>

- **Finding:** invoice, payment, wire, transfer  
- **Why it matters:** Financial targeting  

</details>

---

<details>
<summary>🚩 <strong>Flag 14: Rule Priority</strong></summary>

- **Finding:** StopProcessingRules  
- **Why it matters:** Ensures dominance over other rules  

</details>

---

<details>
<summary>🚩 <strong>Flag 15: Second Rule</strong></summary>

- **Finding:** ..  
- **Why it matters:** Additional evasion layer  

</details>

---

<details>
<summary>🚩 <strong>Flag 16: Delete Keywords</strong></summary>

- **Finding:** suspicious, security, phishing, unusual, compromised, verify  
- **Why it matters:** Hides alerts  

</details>

---

<details>
<summary>🚩 <strong>Flag 17: Victim</strong></summary>

- **Finding:** j.reynolds@lognpacific.org  
- **Why it matters:** Target of fraud  

</details>

---

<details>
<summary>🚩 <strong>Flag 18: Subject Line</strong></summary>

- **Finding:** RE: Invoice #INV-2026-0892 - Updated Banking Details  
- **Why it matters:** Thread hijacking  

</details>

---

<details>
<summary>🚩 <strong>Flag 19: Email Direction</strong></summary>

- **Finding:** Intra-org  
- **Why it matters:** Bypasses external filters  

</details>

---

<details>
<summary>🚩 <strong>Flag 20: Sender IP</strong></summary>

- **Finding:** 205.147.16.190  
- **Why it matters:** Confirms attack chain  

</details>

---

<details>
<summary>🚩 <strong>Flag 21: OneDrive Access</strong></summary>

- **Finding:** Microsoft OneDrive for Business  
- **Why it matters:** Potential data exposure  

</details>

---

<details>
<summary>🚩 <strong>Flag 22: SharePoint Access</strong></summary>

- **Finding:** SharePoint Online  
- **Why it matters:** Broader impact  

</details>

---

<details>
<summary>🚩 <strong>Flag 23: Session ID</strong></summary>

- **Finding:** 00225cfa-a0ff-fb46-a079-5d152fcdf72a  
- **Why it matters:** Correlates full attack  

</details>

---

<details>
<summary>🚩 <strong>Flag 24: Conditional Access</strong></summary>

- **Finding:** notApplied  
- **Why it matters:** Security control failure  

</details>

---

<details>
<summary>🚩 <strong>Flag 25: MFA Fatigue MITRE</strong></summary>

- **Finding:** T1621  

</details>

---

<details>
<summary>🚩 <strong>Flag 26: Email Rule MITRE</strong></summary>

- **Finding:** T1564.008  

</details>

---

<details>
<summary>🚩 <strong>Flag 27: Credential Source</strong></summary>

- **Finding:** Infostealer  
- **Why it matters:** Initial compromise vector  

</details>

---

<details>
<summary>🚩 <strong>Flag 28: Containment</strong></summary>

- **Finding:** Revoke Sessions  
- **Why it matters:** Immediate mitigation  

</details>

---

<details>
<summary>🚩 <strong>Flag 29: Threat Actor</strong></summary>

- **Finding:** Scattered Spider  
- **Why it matters:** Known advanced threat group  

</details>

---



---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps

- Conditional Access policies not enforced  
- MFA fatigue not detected or blocked  
- Inbox rule creation not alerted  
- Lack of anomaly detection for geo/device  

### Recommendations

- Enforce Conditional Access for risky sign-ins  
- Implement MFA fatigue protection (number matching, limits)  
- Alert on inbox rule creation/modification  
- Monitor impossible travel and device anomalies  
- Block auto-forwarding to external domains  

---

## 🧾 Final Assessment

This incident demonstrates a highly effective BEC attack leveraging modern identity-based techniques rather than malware execution. The attacker successfully bypassed MFA using social engineering and established persistence through inbox rules. The lack of conditional access enforcement significantly contributed to the compromise.

The organization’s detection capabilities must evolve toward identity-focused monitoring and behavioral analytics to defend against similar attacks.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review  
- Evidence reproducible via advanced hunting  
- Techniques mapped directly to MITRE ATT&CK  

---
