IN PROGRESS

# Azure-Honeynet-and-Ticketing-System
A hands-on SOC Honeynet & SIEM lab simulating real-world attack detection, incident response, and ticketing workflows


**Tools & Tech**

SIEM: Microsoft Sentinel (Azure), Splunk Enterprise
Endpoint Logging: Sysmon (SwiftOnSecurity config), auditd
Log Forwarding: Splunk Universal Forwarder, Winlogbeat
Ticketing: ServiceNow
Network Analysis: Wireshark
Attack Simulation: Kali Linux, Atomic Red Team, Metasploit, Random threat methods I find on the internet
Framework: MITRE ATT&CK
Virtualization: VirtualBox, Microsoft Azure

**Architecture**

**Honeynet VMs (VirtualBox):**
- Windows Server 2022 — instrumented with Sysmon (SwiftOnSecurity config)
- Ubuntu Server 26.04 — instrumented with auditd and tshark

**SIEM Layer:**
- Microsoft Sentinel (Azure) — cloud SIEM with KQL detection rules
- Splunk Enterprise 9.3 — local SIEM with SPL detection rules

**Log Forwarding:**
- Azure Monitor Agent (Windows → Sentinel)
- Splunk Universal Forwarder (both VMs → Splunk)

**Network:** VirtualBox Host-Only (192.168.56.0/24)
- Windows Honeypot: 192.168.56.101
- Ubuntu Honeypot: 192.168.56.102
- Splunk SIEM: 192.168.56.103

---

**Project Phases**

 Phase 1 — Local VM Honeynet + Splunk
- [x] VirtualBox Host-Only network configured (192.168.56.0/24)
- [x] Windows Server 2022 honeypot VM deployed
- [x] Sysmon installed with SwiftOnSecurity config
- [x] Ubuntu Server honeypot VM deployed
- [x] auditd and tshark installed on Ubuntu
- [x] Splunk Enterprise 9.3 deployed on dedicated VM
- [x] Splunk Universal Forwarder on Windows (Security, System, Sysmon)
- [x] Splunk Universal Forwarder on Ubuntu (auth, syslog, audit)
- [x] SOC Honeynet Security Overview dashboard built
- [x] Windows brute force detection (EventID 4625)
- [x] Sysmon process creation detection (EventID 1)
- [x] SSH brute force detection
- [x] Linux command execution monitoring
- [x] Attack simulations validated across all 4 panels
      Phase 1 finished on 6/2/26

 Phase 2 — Azure + Microsoft Sentinel
- [x] Azure free account created
- [x] Log Analytics Workspace deployed (SOC-Honeynet-Workspace)
- [x] Microsoft Sentinel enabled
- [x] Windows VM onboarded via Azure Arc
- [x] Azure Monitor Agent installed and collecting logs
- [x] Data Collection Rule configured (SOC-Windows-DCR)
- [x] KQL detection rules built and active (7 total)
- [x] First Sentinel incident fired — Brute Force detected
- [x] MITRE ATT&CK coverage map populated
- [ ] Ubuntu VM connected to Sentinel (Ubuntu 26.04 pending Arc support, working on a solution)
      Phase 2 finished on 6/8/26

  Phase 3 - Service Now integration
---

**Rules and Queries**
**KQL Rules (Microsoft Sentinel)**

**Brute Force — Failed Logins (T1110)**
```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by Account, IpAddress, Computer
| where FailedAttempts > 5
```

**New Local User Created (T1136.001)**
```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Computer, Account, SubjectAccount
```

**User Added to Admin Group (T1098)**
```kql
SecurityEvent
| where EventID == 4732
| where TargetAccount contains "Administrators"
| project TimeGenerated, Computer, Account, TargetAccount
```

**Brute Force Success — Failed Then Logged In (T1110)**
```kql
let failedLogins = SecurityEvent
| where EventID == 4625
| summarize FailCount = count() by Account, IpAddress, Computer
| where FailCount > 5;
let successLogins = SecurityEvent
| where EventID == 4624
| project Account, IpAddress, Computer, TimeGenerated;
failedLogins
| join kind=inner successLogins on Account, Computer
| project TimeGenerated, Computer, Account, IpAddress, FailCount
```
**ADDED SEVERAL PRE-CONFIGURED RULES FROM SENTINEL TO INCREASE MITRE ATT&CK MAP COVERAGE**

---
SPL Rules (Splunk)

**Windows Failed Logins (T1110)**
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| stats count by host, Account_Name, Source_Network_Address
| sort -count
```

**Suspicious Process Creation — LOLBins (T1059)**
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "EventID>(?<EventID>\d+)"
| rex field=_raw "Name=\"Image\">(?<Image>[^<]+)<"
| rex field=_raw "Name=\"CommandLine\">(?<CommandLine>[^<]+)<"
| rex field=_raw "Name=\"User\">(?<User>[^<]+)<"
| where EventID="1"
| table _time, host, User, Image, CommandLine
| sort -_time
```

**SSH Brute Force (T1110)**
```spl
index=main (sourcetype="linux_secure" OR sourcetype="auth") "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, host
| sort -count
```

**Linux Commands Executed (T1059)**
```spl
index=main sourcetype="linux_audit" type=EXECVE
| table _time, host, comm, exe
| sort -_time
```
---
 **Key Finds**
- Successfully detected simulated brute force attacks across both 
  Windows and Linux honeypots
- Correlated log-level detections in Splunk with packet-level 
  captures in Wireshark
- Microsoft Sentinel automatically created incidents with MITRE 
  ATT&CK tactic tagging
- Built detection coverage across Credential Access, Persistence, 
  Privilege Escalation, and Defense Evasion tactics
---
  *Currently studying: CompTIA Security+ | AZ-900*
