# Penetration Test Report: HTB-Strutted (Hack The Box)

**Date**: June 22, 2025  
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
- **Targets**: Linux box (10.129.231.200), web server(10.129.231.200:80) => strutted.htb (domain)
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
- Caido / BurpSuite (web application testing)
- Manual scripting (Python, Bash)

---
## Reconnaissance and enumeration
 ```Bash
  nmap -Pn -p- --min-rate 30 -v strutted.htb -o portscan

  Result:

  Warning: The -o option is deprecated. Please use -oN
  Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-22 09:15 EDT
  Initiating Connect Scan at 09:15
  Scanning strutted.htb (10.129.231.200) [65535 ports]
  Discovered open port 80/tcp on 10.129.231.200
  Discovered open port 22/tcp on 10.129.231.200
  Completed Connect Scan at 09:16, 49.75s elapsed (65535 total ports)
  Nmap scan report for strutted.htb (10.129.231.200)
  Host is up (0.052s latency).
  Not shown: 65533 closed tcp ports (conn-refused)
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http

  Read data files from: /usr/bin/../share/nmap
  Nmap done: 1 IP address (1 host up) scanned in 49.94 seconds

```
 ```Bash
  nmap --script vuln -Pn strutted.htb -p 22,80

  Result:

  Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-22 09:27 EDT
  Nmap scan report for strutted.htb (10.129.231.200)
  Host is up (0.040s latency).

  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
  |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
  |_http-csrf: Couldn't find any CSRF vulnerabilities.
  |_http-dombased-xss: Couldn't find any DOM based XSS.
  | http-enum: 
  |   /wp-json: Possible admin folder
  |   /backup: Possible backup
  |   /852566C90012664F: Lotus Domino
  |   /_app_bin: MS Sharepoint
  |   /_controltemplates: MS Sharepoint
  |   /_layouts: MS Sharepoint
  |   /sitedirectory: MS Sharepoint
  |   /Default?MAIN=DEVICE: TopAccess Toshiba e-Studio520
  |   /README: Interesting, a readme.
  |_  /s/: Potentially interesting folder

Nmap done: 1 IP address (1 host up) scanned in 189.95 seconds
```
 ```Bash
  nmap -sV -Pn strutted.htb -p 22,80

  Result:

  Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-22 09:32 EDT
  Nmap scan report for strutted.htb (10.129.231.200)
  Host is up (0.056s latency).

  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
  80/tcp open  http    nginx 1.18.0 (Ubuntu)
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 7.75 seconds

```
```Bash
  whatweb http://strutted.htb
  http://strutted.htb [200 OK] Bootstrap, Content-Language[en-US], Cookies[JSESSIONID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[JSESSIONID], IP[10.129.231.200], Java, Script, Title[Strutted™ - Instant Image Uploads], UncommonHeaders[cross-origin-embedder-policy-report-only,cross-origin-opener-policy], nginx[1.18.0]
```

## Findings and Vulnerabilities (Exploitation)

### Finding 1: CVE-2024-53677 (apache struts - RCE)
- **MITRE**: T1190 (Exploit Public-Facing Application), T1059.004 (Command and Scripting Interpreter-Unix shell)
- **Severity**: Critical
- **Location**: Web server (10.129.231.200:80), /upload.action;jsessionid={sessid} endpoint
- **Description**: File upload logic in Apache Struts is flawed. An attacker can manipulate file upload params to enable paths traversal and under some circumstances this can lead to uploading a malicious file which can be used to perform Remote Code Execution.
- **Evidence**: 
![CVE](https://github.com/user-attachments/assets/cfe8a515-631d-4227-b831-51617d769ee5)
![webshell](https://github.com/user-attachments/assets/0810e478-59b8-446b-b658-d3dd8d4eb92a)

- **Impact**: Exposure of sensitive system information, gaining unauthorized initial access.
- **Recommendation**: Patch --> advised to upgrade to Apache Struts 6.4.0 or later and migrate to the new file upload mechanism. 


### Finding 2: TBA

---


## Conclusion (TBA)
The pentest successfully identified [X] vulnerabilities in the home CTF environment, with [Y] flags captured. Critical issues, such as SQL injection, pose significant risks and should be addressed immediately. By implementing the recommended remediations, the CTF setup can be made more secure and educational for future practice.

---

## References
- https://github.com/TAM-K592/CVE-2024-53677-S2-067
- https://cybersecuritynews.com/apache-struts-vulnerability/
- https://blog.qualys.com/vulnerabilities-threat-research/2024/12/16/critical-apache-struts-file-upload-vulnerability-cve-2024-53677-risks-implications-and-enterprise-countermeasures

