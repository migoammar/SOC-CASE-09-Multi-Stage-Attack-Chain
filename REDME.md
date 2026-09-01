# SOC Case 08 — WMI Abuse (Local Process Execution)

## Objective
Investigate suspicious activity involving WMI, potentially indicating
WMI abuse for process execution.

## Environment
* Windows 10 Lab VM (VirtualBox)
* Sysmon (Event ID 1 — Process Create)
* Splunk Enterprise for log analysis
* Atomic Red Team (T1047-5) used to safely simulate the technique

## Hypothesis
IF: WmiPrvSE.exe created notepad.exe, evidenced by EventCode=1 with
ParentImage=WmiPrvSE.exe and Image=notepad.exe

THEN: This may indicate an attacker attempted to execute code via a
trusted system service to avoid antivirus detection — a Living Off
The Land technique

SO: search Splunk using
`index=main ProcessGuid="{a0107c76-07d3-6a8d-7899-000000005500}" | table _time ProcessId Image ParentImage ParentCommandLine ParentUser`

## Investigation Timeline
* Executed Atomic Red Team test T1047-5 (WMI Execute Local Process)
* First query: `index=main ProcessId=11288` — located the process, but PID alone was not specific enough to isolate the correct event
* Second query: `index=main ProcessGuid="{a0107c76-07d3-6a8d-7899-000000005500}"` — used the unique ProcessGuid instead to isolate the exact event
* Third query: `index=main ProcessGuid="{a0107c76-07d3-6a8d-7899-000000005500}" | table _time ProcessId Image ParentImage ParentCommandLine ParentUser` — pulled the full process context in tabular form
* Found suspicious parent-child relationship: ParentImage=WmiPrvSE.exe, Image=notepad.exe
* Built Hypothesis based on this behavior

## Attack Timeline
* 2026-08-25 06:11:15.301 — WmiPrvSE.exe created notepad.exe (Evidence: EventCode 1, ParentImage=WmiPrvSE.exe)

## MITRE ATT&CK Mapping
| Field         | Value                                    |
|---------------|--------------------------------------------|
| Tactic        | Execution                                   |
| Technique ID  | T1047                                       |
| Technique     | Windows Management Instrumentation          |

## Findings
* Time: 2026-08-25 06:11:15.301
* Process: notepad.exe
* ProcessId: 11288
* ParentImage: WmiPrvSE.exe
* ParentProcessId: 12284
* ParentUser: NT AUTHORITY\NETWORK SERVICE
* CommandLine: notepad.exe
* EventCode: 1

## Evidence
**SPL:**
```
index=main ProcessGuid="{a0107c76-07d3-6a8d-7899-000000005500}"
| table _time ProcessId Image ParentImage ParentCommandLine ParentUser
```
* Evidence 1 — Time: 2026-08-25 06:11:15.301
* Evidence 2 — Process: notepad.exe (ProcessId: 11288)
* Evidence 3 — ParentImage: WmiPrvSE.exe (ParentProcessId: 12284)
* Evidence 4 — ParentCommandLine: C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding
* Evidence 5 — ParentUser: NT AUTHORITY\NETWORK SERVICE

## Attacker Mindset
The attacker used WmiPrvSE.exe because it is a trusted, signed Windows
system service, so process creation through it is less likely to be
flagged by antivirus. This tactic — using existing, legitimate system
binaries to execute code or payloads without introducing new files —
is known as Living Off The Land (LOTL).

## False Positive Analysis
* WMI is commonly used for legitimate system administration tasks
  (running scripts, remote management, software deployment), so
  WmiPrvSE.exe appearing as a parent process is not inherently malicious
* However, notepad.exe is not a typical target for administrative WMI
  usage — WMI-driven administration usually spawns scripting or
  management tools (e.g., powershell.exe, cmd.exe), not a simple text
  editor with no administrative purpose
* To reduce false positives, correlate WMI-spawned processes with the
  User field and flag instances where the account is not part of the
  known/authorized admin accounts list

## Detection Logic (Sigma Rule)
```yaml
title: SOC - CASE 8
id: 1987b380-6f9f-4603-83f4-0e109c6ac58c
status: experimental
description: Investigate in WMI Execution
date: 2026/08/26
author: MIRGANI AMMAR
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\notepad.exe'
  condition: selection
falsepositives:
  - Legitimate administrative scripts or remote management tools using WMI
level: high
tags:
  - attack.execution
  - attack.t1047
```

## Recommendations
* Monitor WMI-initiated process creation (ParentImage=WmiPrvSE.exe) and
  correlate with the User field — flag instances where the account is
  not part of the known/authorized admin accounts list

## Lessons Learned
Learned that Process IDs alone are not always specific enough to
isolate the correct event — using the unique ProcessGuid instead of
ProcessId gave a precise, unambiguous result. This case also
reinforced how many techniques an attacker can use to conceal
execution, the most notable being Living Off The Land (LOTL).

## Conclusion
WmiPrvSE.exe (running as NT AUTHORITY\NETWORK SERVICE) created
notepad.exe, consistent with T1047 (Windows Management
Instrumentation). Since notepad.exe is not a typical target for
legitimate WMI-driven administration, this activity was classified
as high severity.

## References
* MITRE ATT&CK — https://attack.mitre.org/techniques/T1047/
