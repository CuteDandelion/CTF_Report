# Penetration Test Report: HTB-Blurry (Hack The Box)

**Date**: June 24, 2025  
**Prepared by**: Justin Chin  
**Confidentiality**: For Educational Use Only  

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [Introduction](#introduction)
3. [Methodology](#methodology)
4. [Findings and Vulnerabilities](#findings-and-vulnerabilities)
5. [Recommendations](#recommendations)
6. [Conclusion](#conclusion)
7. [Appendices](#appendices)

---

## Executive Summary
This report details the results of a penetration test conducted on a HTB Capture The Flag (CTF) environment. The objective was to identify and exploit vulnerabilities to capture flags and assess the security of the target systems. 

---

## Introduction
### Objective
The goal of this pentest was to simulate real-world attacks on a home CTF setup to capture flags and identify security weaknesses.

### Scope
- **Targets**: Linux box (10.129.3.211), web server(10.129.3.211:80) => app.blurry.htb api.blurry.htb files.blurry.htb (domains)
- **Testing Type**: Black-box (no prior knowledge) 
- **Constraints**: Testing conducted within a virtualized home lab; no external network access.

---

## Methodology
The pentest followed a structured approach based on CTF best practices:
1. **Reconnaissance**: Identified active hosts and services using tools like Nmap.
2. **Enumeration**: Probed for open ports, services, and application details.
3. **Exploitation**: Attempted to exploit vulnerabilities to gain access or capture flags.
4. **Post-Exploitation**: Escalated privileges or pivoted to other systems (if applicable).
5. **Reporting**: Documented findings with evidence.

**Tools Used**:
- Nmap (network scanning)
- Manual scripting (Python, Bash)

---
## Reconnaissance and enumeration
 ```Bash
  nmap --min-rate 1000 -sC -sV -p- -oN nmap_results.txt 10.129.3.211
```
![nmap](https://github.com/user-attachments/assets/029cf4b6-f424-45af-aed4-b6015a524927)

```Bash
  whatweb app.blurry.htb
  http://app.blurry.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.129.3.211], Script[module], Title[ClearML], nginx[1.18.0]

```

## Findings and Vulnerabilities (Exploitation)

### Finding 1: CVE-2024-24590: Pickle Load on Artifact Get (Affecting clearml < 1.14.x)
- **MITRE**: T1190 (Exploit Public-Facing Application), T1059.004 (Command and Scripting Interpreter-Unix shell)
- **Severity**: Critical
- **Location**: Web server (10.129.3.211:80) , data = artifact_object.get() (get method)
- **Description**: inherent insecurity of pickle files,attacker could create a pickle file containing arbitrary code and upload it as an artifact to a project    via the API. When a user calls the get method within the Artifact class to download and load a file into memory, the pickle file is deserialized on their     system, running any arbitrary code it contains.
- **Evidence**: https://docs.google.com/document/d/1mQaFASzfT1wpp8ShsOi6zicPCo3hMYvIM4LM394lkCs/edit?usp=sharing
- **Impact**: Exposure of sensitive system information, gaining unauthorized initial access / foothold.
- **Recommendation**: Patch --> advised to upgrade clearML python package to 1.14.x or later . 

## Post Exploitation

### Finding 2 : Sudo misconfiguration
- **MITRE**: T1548 (Abuse Elevation Control Mechanism), T1068 (Exploitation for Privilege Escalation)
- **Severity**: Critical
- **Location**: Host (10.129.3.211) , User: administrator (******)
- **Description**: misconfigured & excessive sudo permissions to escalate privileges.
- **Evidence**: 
   ```Bash
  sudo -l (Manual Bash /// linPEAS Scan)
   
  Result:
  Matching Defaults entries for admin on blurry:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

  User admin may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth (suspicious)

   ```
- **Impact**: attacker gaining ROOT access. 
- **Recommendation**:
  - Restrict sudo Permissions
  - Use Capabilities Instead of sudo: Grant Linux capabilities (CAP_NET_RAW, CAP_NET_ADMIN) to run without root privileges.
    (Reduce the need for sudo)
  - Least Privilege Principle: Avoid NOPASSWD and overly broad sudo rules.
  - Monitor & patch


---

## References
- https://hiddenlayer.com/innovation-hub/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/
- https://github.com/clearml
- #GROK (Template/Recommendations/Knowledge)

