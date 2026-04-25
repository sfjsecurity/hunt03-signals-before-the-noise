# 🐺 HUNT 03 - Signals Before the Noise
### Threat Hunt Report · MITRE ATT&CK Mapping · PHTG External RDP Compromise

> **Status:** Complete · **Difficulty:** Intermediate · **Flags:** 38/38  
> **Platform:** Microsoft Sentinel (KQL) · **Window:** 9–23 December 2025  
> **Target Host:** `azwks-phtg-02` · **Public IP:** `74.249.82.162`

---

## Executive Summary

A cloud engineer at PHTG posted a photo on LinkedIn showing their workstation with the Azure portal open. The photo inadvertently exposed the hostname and public IP address of a production VM (`azwks-phtg-02`). Within two days, threat actors identified the exposure, conducted automated RDP scanning, brute-forced credentials, established persistent access, disabled Microsoft Defender, and deployed a Meterpreter reverse shell — masquerading as a legitimate internal health monitoring service.

**The attack was never alerted. The hunt was hypothesis-driven from OSINT alone.**

---

## Kill Chain Overview

```
OSINT Exposure → Scanning → Brute Force → Initial Access → Discovery
→ Defense Evasion → Persistence → C2 Execution
```

| Phase | Date | Key Event |
|---|---|---|
| Exposure | Dec 9, 2025 | LinkedIn post with Azure portal visible |
| Scanning | Dec 9–11 | 173 unique IPs probe port 3389 |
| Brute Force | Dec 9–11 | 675 RDP auth attempts from 17 countries |
| Initial Access | Dec 11 11:47 UTC | First successful logon from Uruguay (`173.244.55.131`) |
| Discovery | Dec 11–12 | Notepad, `notes_sarah.txt` accessed |
| Payload Drop | Dec 12 | `Sarah_Chen_Notes.exe.Txt` → `Sarah_Chen_Notes.exe` → `PHTG.exe` |
| Defense Evasion | Dec 12 14:17 UTC | Defender switched to Passive Mode |
| Persistence | Dec 12–13 | Scheduled task `PHTG User Baseline Report` created |
| C2 | Dec 12–13 | Meterpreter beacon to `173.244.55.130:4444` |

---

## MITRE ATT&CK Technique Matrix

### 🔍 Reconnaissance

| ID | Technique | Sub-technique | Evidence |
|---|---|---|---|
| [T1593.001](https://attack.mitre.org/techniques/T1593/001/) | Search Open Websites/Domains: Social Media | LinkedIn | Engineer posted Azure portal screenshot exposing `azwks-phtg-02` and `74.249.82.162` |
| [T1590.005](https://attack.mitre.org/techniques/T1590/005/) | Gather Victim Network Information: IP Addresses | — | Public IP directly visible in LinkedIn photo |

---

### 🌐 Resource Development

| ID | Technique | Sub-technique | Evidence |
|---|---|---|---|
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains | ngrok | C2 testing used `unresuscitating-donnette-smothery.ngrok-free.dev` |
| [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Develop Capabilities: Malware | Meterpreter | `Sarah_Chen_Notes.exe` — `Trojan:Win32/Meterpreter` |

---

### 🚪 Initial Access

| ID | Technique | Sub-technique | Evidence |
|---|---|---|---|
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing | — | 675 RDP auth attempts · `InvalidUserNameOrPassword` · 17 countries |
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Valid Accounts: Default Accounts | — | Account `vmadminusername` — default-style admin credential |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Services: Remote Desktop Protocol | — | 23 successful RDP sessions from Uruguay (`173.244.55.128`, `.131`) |

---

### 🔎 Discovery

| ID | Technique | Sub-technique | Evidence |
|---|---|---|---|
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | — | `notepad.exe` launched by `powershell.exe`; `notes_sarah.txt` and `Notes 12122025.txt` opened |
| [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | — | `taskmgr.exe`, `ms-settings:` launched post-access |
| [T1057](https://attack.mitre.org/techniques/T1057/) | Process Discovery | — | Process enumeration via PowerShell |

---

### 🛡️ Defense Evasion

| ID | Technique | Sub-technique | Evidence |
|---|---|---|---|
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Impair Defenses: Disable or Modify Tools | Defender Passive Mode | Defender switched to Passive Mode after 3 quarantine events (14:11–14:17 Dec 12) |
| [T1036.002](https://attack.mitre.org/techniques/T1036/002/) | Masquerading: Right-to-Left Override | Double Extension | `Sarah_Chen_Notes.exe.Txt` — appeared as text file, executed as binary |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | Masquerading: Match Legitimate Name or Location | — | Final payload renamed `PHTG.exe`, placed in `C:\ProgramData\PHTG\HealthCloud\` |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | — | Multi-stage rename chain: `.Txt` → `.exe` → `PHTG.exe` |

---

### 💾 Persistence

| ID | Technique | Sub-technique | Evidence |
|---|---|---|---|
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Scheduled Task/Job: Scheduled Task | — | Task: `PHTG User Baseline Report` · Daily 10:15 · Executes `phtg_user_baseline_report.ps1` |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell | — | `-NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\PHTG\HealthCloud\phtg_user_baseline_report.ps1"` |

---

### ⚡ Execution

| ID | Technique | Sub-technique | Evidence |
|---|---|---|---|
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Command and Scripting Interpreter: Windows Command Shell | — | `cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat"` |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | — | Payload launcher, scheduled task wrapper |
| [T1047](https://attack.mitre.org/techniques/T1047/) | Windows Management Instrumentation | — | `ProcessCreatedUsingWmiQuery` events during task scheduling |

---

### 📡 Command and Control

| ID | Technique | Sub-technique | Evidence |
|---|---|---|---|
| [T1571](https://attack.mitre.org/techniques/T1571/) | Non-Standard Port | — | C2 on port `4444` (Meterpreter default) |
| [T1095](https://attack.mitre.org/techniques/T1095/) | Non-Application Layer Protocol | — | Meterpreter raw TCP beacon |
| [T1090.003](https://attack.mitre.org/techniques/T1090/003/) | Proxy: Multi-hop Proxy | ngrok | Pre-execution C2 test via ngrok tunnel |

---

## Indicators of Compromise (IOCs)

### Network IOCs

| Type | Value | Context |
|---|---|---|
| IP | `173.244.55.128` | Uruguay · RDP brute force + successful logon |
| IP | `173.244.55.130` | Uruguay · Meterpreter C2 · Port 4444 |
| IP | `173.244.55.131` | Uruguay · First successful RDP logon (Dec 11 11:47 UTC) |
| CIDR | `173.244.55.0/24` | Block entire subnet |
| Domain | `unresuscitating-donnette-smothery.ngrok-free.dev` | Pre-execution C2 test |
| Port | `4444/TCP` | Meterpreter C2 listener |
| Port | `3389/TCP` | RDP — externally exposed |

### File IOCs

| Type | Value | Context |
|---|---|---|
| SHA256 | `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` | Meterpreter payload |
| Filename | `PHTG.exe` | Final payload name (masquerades as HealthCloud) |
| Filename | `Sarah_Chen_Notes.exe` | Intermediate payload name |
| Filename | `Sarah_Chen_Notes.exe.Txt` | Double-extension delivery name |
| Path | `C:\ProgramData\PHTG\HealthCloud\PHTG.exe` | Payload on disk |
| Path | `C:\ProgramData\PHTG\HealthCloud\Launch.bat` | Batch wrapper |
| Path | `C:\ProgramData\PHTG\HealthCloud\phtg_user_baseline_report.ps1` | Persistence script |

### Host IOCs

| Type | Value | Context |
|---|---|---|
| Account | `vmadminusername` | Compromised account |
| Scheduled Task | `\PHTG User Baseline Report` | Malicious persistence |
| Hostname | `azwks-phtg-02` | Compromised host |
| Public IP | `74.249.82.162` | Exposed attack surface |

---

## Detection Opportunities

### KQL — Brute Force Detection (Phase 3)
```kql
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| summarize Failures = count() by RemoteIP, DeviceName, bin(TimeGenerated, 5m)
| where Failures > 10
```

### KQL — Geographic Anomaly (Phase 4)
```kql
let GeoTable = externaldata(network:string, geoname_id:long, continent_code:string,
    continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name != "United States"
```

### KQL — Double Extension File Drop (Phase 5)
```kql
DeviceFileEvents
| where ActionType == "FileRenamed"
| where PreviousFileName matches regex @"\.(exe|dll|ps1)\.[a-zA-Z]{2,4}$"
   or FileName matches regex @"\.(exe|dll)\.[a-zA-Z]{2,4}$"
```

### KQL — Defender State Change (Phase 6)
```kql
DeviceEvents
| where ActionType == "AntivirusDetectionActionType"
| extend Info = parse_json(AdditionalFields)
| where Info.Action contains "Passive" or Info.Action contains "Disabled"
```

### KQL — Meterpreter C2 Beacon (Phase 7)
```kql
DeviceNetworkEvents
| where RemotePort == 4444
| where RemoteIPType == "Public"
| where ActionType == "ConnectionFailed" or ActionType == "ConnectionSuccess"
```

---

## Lessons Learned

| Finding | Risk | Recommendation |
|---|---|---|
| Public IP exposed via LinkedIn OSINT | Critical | OPSEC training · Social media policy for cloud engineers |
| RDP exposed to the internet | Critical | Restrict RDP behind VPN or Azure Bastion only |
| Default-style admin account name | High | Enforce strong, non-predictable admin account naming |
| Defender switched to Passive Mode | Critical | Alert on Defender state changes · Tamper protection enabled |
| Payload hidden in legitimate service directory | High | File integrity monitoring on `C:\ProgramData\` |
| No alert fired during entire compromise | High | Proactive hunting programme · Baseline HealthCloud footprint |

---

## Malware Family

**Meterpreter** (`Trojan:Win32/Meterpreter`)  
Metasploit Framework post-exploitation payload. Provides an interactive shell, file system access, process injection, and pivoting capabilities. Delivered via double-extension evasion, persisted via scheduled task, communicated via raw TCP on port 4444.

---

## Attribution

| Indicator | Value |
|---|---|
| Source Country | Uruguay |
| Source ASN | `173.244.55.0/24` |
| Tooling | Metasploit Framework (Meterpreter) |
| TTPs | RDP brute force → Living-off-the-land → LoLBAS persistence |
| Classification | Opportunistic threat actor · Automated initial access |

---

*Hunt conducted on Microsoft Sentinel · SIEM workspace: `law-cyber-range`*  
*MITRE ATT&CK® is a registered trademark of The MITRE Corporation.*
