# SOC Case 09: Multi-Stage Attack Chain

## Objective
التحقيق في هجوم على جهاز DESKTOP-R0Q45UL عبر حساب mark عن طريق عده مراحل تشمل Execution و persistence و سرقه CREDENTAIL و مسح ادله و التنقل بين الاجهزة (LATERAL MOVEMENT)

## Environment
- Windows 10 Lab VM (VirtualBox)
- Sysmon (custom config) forwarding to Splunk
- PowerShell Script Block Logging (Event 4104) enabled
- Windows Security Auditing (Other Object Access Events) enabled
- Splunk Enterprise (local indexer on the same VM)
- Host: DESKTOP-R0Q45UL | User: mark
- Attack simulated using Atomic Red Team (T1059.001), native Windows tools (schtasks, wevtutil), procdump64 (Sysinternals), and mimikatz

## Hypothesis

**1. Execution**
- IF: The attacker executed a PowerShell script, evidenced by EventCode=4104 with Message content: `Write-Host 'Hello, from PowerShell!'` and ScriptBlock ID: 0fe3c8b6-2d45-4deb-8958-7954f0bf0b4f
- THEN: this may indicate the attacker used PowerShell to execute arbitrary code, which could allow further actions such as deleting files and stealing information.
- SO: `index=main EventCode=4104 "Hello"`

**2. Persistence**
- IF: The attacker created a Scheduled Task for persistence, evidenced by EventCode=4698 with Task Name=\SystemUpdateCheck, Arguments=/C tasklist
- THEN: this indicates the attacker wanted to establish a Scheduled Task to ensure his return
- SO: `index=main EventCode=4698`

**3. Credential Access**
- IF: The attacker dumped lsass.exe memory using procdump64.exe, evidenced by SourceImage=procdump64.exe, TargetImage=lsass.exe, GrantedAccess=0x1FFFFF
- THEN: In this event, the attacker dumped lsass memory to get credentials, which would allow him to impersonate any user and perform lateral movement.
- SO: `index=main EventCode=10 TargetImage="*lsass.exe*" earliest="08/27/2026 09:44:00" latest="08/27/2026 09:50:00"`

**4. Defense Evasion**
- IF: The attacker cleared the Event Log, evidenced by Account Name=mark, Logon ID=0x6DBBC, Message="The audit log was cleared", EventCode=1102
- THEN: This event indicates the Security Event Log was cleared, suggesting an attacker attempted to cover their tracks by removing audit evidence
- SO: `index=main EventCode=1102`

**5. Lateral Movement**
- IF: The attacker used Pass-the-Hash via mimikatz, evidenced by EventCode=10 with SourceImage=C:\Users\myrgh\Downloads\x64\mimikatz.exe, TargetImage=C:\Windows\system32\lsass.exe, GrantedAccess=0x1038, SourceUser=DESKTOP-R0Q45UL\mark
- THEN: the attacker used Pass-the-Hash to use the Credential without triggering AV detection to move laterally
- SO: `index=main EventCode=10 TargetImage="*lsass.exe*" earliest="08/28/2026:06:00:00" latest="08/28/2026:06:30:00" SourceImage="*mimikatz*"`

## Investigation Timeline

**Execution:**
* First query: `index=main EventCode=4104 "Hello"` — found the PowerShell execution evidence
* Evidence: Message=Creating Scriptblock text (1 of 1): Write-Host 'Hello, from PowerShell!', User=DESKTOP-R0Q45UL\mark

**Persistence:**
* First query: `index=main EventCode=4698` — found the Scheduled Task creation event
* Evidence: ComputerName=DESKTOP-R0Q45UL, Account Name=mark, Account Domain=DESKTOP-R0Q45UL, Task Name=\SystemUpdateCheck

**Credential Access:**
* First query: `index=main EventCode=10 TargetImage="*lsass.exe*"` — broad search, returned noisy results (mostly routine splunkd access)
* Second query: `index=main EventCode=10 TargetImage="*lsass.exe*" SourceImage="*procdump*"` — narrowed to procdump activity
* Third query: `index=main EventCode=10 TargetImage="*lsass.exe*" earliest="08/27/2026 09:44:00" latest="08/27/2026 09:50:00"` — isolated the exact event
* Evidence: ComputerName=DESKTOP-R0Q45UL, SourceProcessId=11052, SourceImage=procdump64.exe, TargetProcessId=676, TargetImage=lsass.exe, TargetUser=NT AUTHORITY\SYSTEM

**Defense Evasion:**
* First query: `index=main EventCode=1102` — found the log clearing event
* Evidence: Message=The audit log was cleared, Account Name=mark, Domain Name=DESKTOP-R0Q45UL, Logon ID=0x6DBBC

**Lateral Movement:**
* First query: `index=main EventCode=10 SourceImage="*mimikatz*" TargetImage="*lsass.exe*"` — broad search across all time
* Second query: `index=main EventCode=10 TargetImage="*lsass.exe*" earliest="08/28/2026:06:00:00" latest="08/28/2026:06:30:00" SourceImage="*mimikatz*"` — isolated the correct time window
* Evidence: SourceImage=C:\Users\myrgh\Downloads\x64\mimikatz.exe, TargetImage=C:\Windows\system32\lsass.exe, GrantedAccess=0x1038, SourceUser=DESKTOP-R0Q45UL\mark

## Attack Timeline
- 8/27/2026 - 8:35:25 AM : Executed powershell by user mark
- 8/27/2026 - 8:54:40 AM : Created Scheduled Task for persistence
- 8/27/2026 - 9:46:56 AM : Dumped lsass.exe memory using procdump64.exe to get the hashes
- 8/27/2026 - 9:50:46 AM : Cleared the Event Log
- 8/28/2026 - 6:10:50 AM : Used Pass-the-Hash by mimikatz

Note: Lateral Movement was executed in a separate lab session (~20 hours later) rather than continuously

## MITRE Mapping
| Stage | Technique ID | Technique Name |
|---|---|---|
| Execution | T1059.001 | PowerShell |
| Persistence | T1053.005 | Scheduled Task |
| Credential Access | T1003.001 | LSASS Memory |
| Defense Evasion | T1070.001 | Clear Windows Event Logs |
| Lateral Movement | T1550.002 | Pass the Hash |

## Findings
* Host: DESKTOP-R0Q45UL
* Account: mark
* Stages executed: Execution → Persistence → Credential Access → Defense Evasion → Lateral Movement
* Execution: EventCode 4104, PowerShell encoded command
* Persistence: EventCode 4698, Scheduled Task \SystemUpdateCheck
* Credential Access: Sysmon EventCode 10, procdump64.exe → lsass.exe, GrantedAccess 0x1FFFFF
* Defense Evasion: EventCode 1102, Security log cleared
* Lateral Movement: Sysmon EventCode 10, mimikatz.exe → lsass.exe, GrantedAccess 0x1038
* Summary: The attacker successfully completed a full attack chain from initial execution to lateral movement. What makes this chain particularly dangerous is that credential theft combined with evidence removal and lateral movement, which makes detection and attribution significantly harder.

## Evidence

SPL (Event 4104 — Execution):
```
index=main EventCode=4104 "Hello"
```
* Evidence 1 — Message: Write-Host 'Hello, from PowerShell!'
* Evidence 2 — User: DESKTOP-R0Q45UL\mark

SPL (Event 4698 — Persistence):
```
index=main EventCode=4698
```
* Evidence 3 — ComputerName: DESKTOP-R0Q45UL
* Evidence 4 — Account Name: mark
* Evidence 5 — Task Name: \SystemUpdateCheck

SPL (Event 10 — Credential Access):
```
index=main EventCode=10 TargetImage="*lsass.exe*" earliest="08/27/2026 09:44:00" latest="08/27/2026 09:50:00"
```
* Evidence 6 — SourceImage: procdump64.exe
* Evidence 7 — TargetImage: lsass.exe
* Evidence 8 — TargetUser: NT AUTHORITY\SYSTEM

SPL (Event 1102 — Defense Evasion):
```
index=main EventCode=1102
```
* Evidence 9 — Account Name: mark
* Evidence 10 — Message: The audit log was cleared

SPL (Event 10 — Lateral Movement):
```
index=main EventCode=10 TargetImage="*lsass.exe*" earliest="08/28/2026:06:00:00" latest="08/28/2026:06:30:00" SourceImage="*mimikatz*"
```
* Evidence 11 — SourceImage: mimikatz.exe
* Evidence 12 — GrantedAccess: 0x1038
* Evidence 13 — SourceUser: DESKTOP-R0Q45UL\mark

## Attacker Mindset
- **Execution:** The attacker used base64 encoding to evade detection by automated security tools.
- **Persistence:** The attacker used a Scheduled Task to guarantee return on system startup, while blending in among the numerous legitimate scheduled tasks typically present on Windows systems.
- **Credential Access:** The attacker used procdump because it is a trusted tool from Microsoft, to dump lsass.exe memory and extract credentials.
- **Defense Evasion:** The attacker cleared the logs so that investigators wouldn't notice the dump.
- **Lateral Movement:** The attacker used the hash because he didn't need the plaintext password, since the hash itself serves as the authentication key.

## False Positive Analysis
- **Execution:** This could be a false positive since an admin might use PowerShell to execute a legitimate code and download something from a website.
- **Persistence:** This could be a false positive since there are many processes that use scheduled tasks daily for legitimate purposes such as system updates.
- **Credential Access:** This could be a false positive since this might be legitimate troubleshooting by technical support.
- **Defense Evasion:** This could be a false positive since this might be routine log maintenance performed by an admin.
- **Lateral Movement:** This could be a false positive since this might be an authorized penetration test.

## Detection Logic

```yaml
title: Encoded PowerShell Command Execution
status: experimental
id: 3c52389d-ca45-4f19-ad1e-6690eb451306
description: Execution
date: 2026/08/31
author: MIRGANT AMMAR
logsource:
  product: windows
  service: powershell
detection:
    selection_encoded:
        ScriptBlockText|contains:
            - '-enc '
            - '-encodedcommand'
    condition: selection_encoded
falsepositives:
    - Legitimate administrative scripts containing encoded commands or download routines.
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

```yaml
title: Persistence
status: experimental
id: d4adf473-90d2-445b-8e85-4485a11a0b76
date: 2026/08/31
description: Detects the creation of scheduled tasks using PowerShell
author: MIRGANT AMMAR
logsource:
  product: windows
  service: security
detection:
    selection:
        EventID: 4698
    condition: selection
falsepositives:
    - Legitimate administrative scripts used for system deployment or maintenance.
level: medium
tags:
    - attack.persistence
    - attack.t1053.005
```

```yaml
title: LSASS Memory Dump via ProcDump
id: 25d85135-34d7-4e85-a920-518ceabd9f30
status: experimental
description: investigation in credential access
date: 2026/08/31
author: MIRGANI AMMAR
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID:
     - 10
    SourceImage: procdump64.exe
    TargetImage: C:\Windows\system32\lsass.exe
  condition: selection
falsepositives:
  - none
level: high
tags:
  - attack.credential_access
  - attack.T1003.001
```

```yaml
title: Defense Evasion
id: 79d5c620-3194-4f9c-b32d-02443b2b354a
status: experimental
description: Detects clearing of the Windows Security Event Log, a common technique used to remove evidence of prior activity.
author: MIRGANI AMMAR
date: 2026/08/31
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
  condition: selection
falsepositives:
  - Legitimate log clearing activities performed by administrators during maintenance
level: medium
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

```yaml
title: Lateral Movement
id: 555cff6a-01bc-4f46-83d8-013998fe95d7
status: experimental
date: 2026/08/31
description: pass the hash
author: MIRGANI AMMAR
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    SourceImage: C:\Users\myrgh\Downloads\x64\mimikatz.exe
    TargetImage: C:\Windows\system32\lsass.exe
  condition: selection
falsepositives:
  - The user could have logged in normally from their usual device
level: medium
tags:
  - attack.lateral_movement
  - attack.t1550.002
```

## Recommendations
- **Execution:** Implement a policy that restricts the execution of encoded PowerShell commands.
- **Persistence:** Enable Advanced Audit Policy (Object Access → Other Object Access Events) across all machines in the network, not just individual hosts.
- **Credential Access:** Enforcing strict access controls and hardening configurations to protect LSASS from unauthorized memory access and credential dumping.
- **Defense Evasion:** Monitor EventCode 1102 across all endpoints as a high-value indicator of anti-forensic activity.
- **Lateral Movement:** Enable Credential Guard to protect sensitive credential material from LSASS memory access.

## Lessons Learned
The lesson I learned was how to distinguish ProcDump activity from benign noise generated by Splunkd/VBoxService when they accessed LSASS in a similar way. This highlighted the importance of using GrantedAccess and SourceImage as precise filters instead of relying only on TargetImage.

## Conclusion
The attacker successfully completed a full attack chain from initial execution to lateral movement. This investigation demonstrates that the Sigma detection rules developed for each stage can effectively identify this type of multi-stage attack across PowerShell, Security, and Sysmon logs.

## References
* MITRE ATT&CK — T1059.001: https://attack.mitre.org/techniques/T1059/001/
* MITRE ATT&CK — T1053.005: https://attack.mitre.org/techniques/T1053/005/
* MITRE ATT&CK — T1003.001: https://attack.mitre.org/techniques/T1003/001/
* MITRE ATT&CK — T1070.001: https://attack.mitre.org/techniques/T1070/001/
* MITRE ATT&CK — T1550.002: https://attack.mitre.org/techniques/T1550/002/
