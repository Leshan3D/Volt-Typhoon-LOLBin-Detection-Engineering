# Volt-Typhoon-LOLBin-Detection-Engineering Lab
Detection engineering lab emulating Volt Typhoon LOLBin techniques (netsh, schtasks, ntdsutil) — SIGMA rules, Wazuh PCRE2 detections, and OpenSearch SIEM visibility, with iterative false-positive tuning documented.


---

## 1. Executive Summary & The Living-off-the-Land Detection Gap

Modern state-sponsored adversaries — exemplified by **Volt Typhoon** — have systematically shifted away from traditional malware payloads in favor of **Living-off-the-Land (LotL)** techniques. By abusing legitimate, pre-installed administrative utilities (often called *LOLBins* and *LOLScripts*), attackers execute their kill chain while blending into normal enterprise noise.

### The Detection Challenge

- **Signature Blindness:** Tools like `netsh`, `schtasks`, and `ntdsutil` are digitally signed and natively trusted, so file-hash and antivirus signatures fail to flag them.
- **Context Blindness:** An admin creating a scheduled task is routine; the same command from an anomalous parent process or with a suspicious payload path is a compromise indicator.
- **The Telemetry Gap:** Organizations collect massive log volumes (Sysmon, WEF) but often lack deterministic, context-aware rules correlating execution arguments with malicious intent.

This project documents a threat detection engineering lifecycle: emulating Volt Typhoon TTPs in a controlled lab, authoring and iteratively tightening SIGMA/Wazuh PCRE2 correlation rules, and building an OpenSearch visualization layer.

**Status note:** these are first-pass detection rules, tuned through several review iterations (documented in Section 5), not yet validated against production-scale traffic. See Section 7 for open items before these should be considered production-ready.

---

## 2. Lab Architecture & Environment Configuration

Isolated, hybrid threat emulation and SIEM pipeline running locally:

- **SIEM Core:** Single-node Dockerized Wazuh deployment (`Omarchy` host environment).
- **Endpoint Target:** Windows 11 Pro VM with Sysmon tracking process creation (Event ID 1) and network telemetry.
- **Configuration Persistence:** Wazuh manager rules/config managed via volume mounts (`./config/wazuh_cluster/wazuh_manager.conf`), ensuring integrity across container restarts.

```
[Windows 11 Endpoint (Sysmon)]
       │ (Sysmon EID 1 Telemetry via Wazuh Agent 001)
       ▼
[Dockerized Wazuh Manager (Omarchy)]
       │ (PCRE2 Regex Evaluation via local_rules.xml)
       ▼
[OpenSearch SIEM Dashboards & Custom Visualization Panels]
```

---

## 3. Threat Emulation & TTP Mapping

Three phases of Volt Typhoon's lifecycle were emulated: C2 tunneling, persistence, and credential staging.

| MITRE ATT&CK TTP | Technique Name | Emulated Tool / Binary | Purpose |
|---|---|---|---|
| **T1090.001** | Proxy: Internal Proxy | `netsh interface portproxy` | Stealthy C2 tunnel |
| **T1053.005** | Scheduled Task/Job | `schtasks.exe` | Persistent execution |
| **T1003.003** | OS Credential Dumping: NTDS | `ntdsutil` (emulated via PowerShell `Write-Output`) | AD database extraction |

> Note: the NTDSutil step was emulated by echoing the target command string via PowerShell rather than invoking `ntdsutil.exe` directly, to keep the test non-destructive. This validates command-line detection logic but does not confirm behavior against the real binary's actual logged output — flagged as an open item in Section 7.

### Execution Vectors (PowerShell Emulation Scripts)

```powershell
# --- 1. T1090.001: Netsh Portproxy C2 Tunneling ---
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=127.0.0.1 connectport=443 connectaddress=127.0.0.1

# --- 2. T1053.005: Scheduled Task Persistence ---
schtasks /create /tn "VaultMaintenance" /tr "cmd.exe /c echo VoltTyphoonTest" /sc daily /st 09:00 /f

# --- 3. T1003.003: NTDSutil Credential Dumping Emulation ---
powershell.exe -NoProfile -Command "Write-Output 'ntdsutil ac i ntds ifm create full C:\PerfLogs\ntds_stage q q'"
```

---

<img width="1600" height="858" alt="image" src="https://github.com/user-attachments/assets/517b8e67-2c43-425a-8dfb-f4856d7c595e" />

Wazuh server is blind to the LoTl as expected because in a standard production environment, an analyst looking at a queue of hundreds or thousands of Level 3 events per hour will never manually inspect them. This background noise is where Volt Typhoon hides.

Manually inspecting the lower rules levels shows them lying there:
data.win.eventdata.commandLine: portproxy OR data.win.eventdata.commandLine: v4tov4



<img width="1600" height="866" alt="image" src="https://github.com/user-attachments/assets/1a1fc433-1202-46e5-b28e-94f2ecb4844c" />


1. The Proxy Setup (C2 Tunneling)
Finds the local port proxy creation attempt. SOCs miss this because netsh.exe runs daily for standard network troubleshooting.


<img width="1600" height="856" alt="image" src="https://github.com/user-attachments/assets/f8cafa89-6544-4e18-acd9-6ad33bb14657" />

There it lies, the SOC won't see it drowning in "normal" traffic






2. The Persistence Trigger
Finds the creation of the VaultMaintenance scheduled task. SOCs miss this because software installers constantly register background scheduled tasks.

data.win.eventdata.commandLine: schtasks AND data.win.eventdata.commandLine: VaultMaintenance


<img width="1600" height="873" alt="image" src="https://github.com/user-attachments/assets/30abc41e-f6af-4e5c-9819-bae23d9032b9" />





<img width="1600" height="837" alt="image" src="https://github.com/user-attachments/assets/4e2ebb5e-31f8-4da9-be6a-c20ffbff785d" />








3. The Active Directory Credential Snapshot
Finds the ntdsutil execution and IFM creation request. SOCs miss this because ntdsutil is signed by Microsoft and classified as a standard system management tool.

data.win.eventdata.commandLine: ntdsutil OR data.win.eventdata.commandLine: ifm


<img width="1600" height="860" alt="image" src="https://github.com/user-attachments/assets/e74c0dc4-bef9-4f6f-9da3-5c8ccf2d91c2" />















## 4. Detections-as-Code

Rules were designed as SIGMA first (for portability/documentation) and ported to Wazuh's native PCRE2 rule engine for local deployment. Each rule went through at least one revision after review — see the "iteration notes" under each.

### 4.1 SIGMA Rules

**Netsh Portproxy C2 Tunneling**

```yaml
title: Volt Typhoon - Netsh Port Forwarding C2 Tunneling
id: 8d1f2a34-7b9c-4e12-8a90-volt1090001
status: test
description: Detects use of netsh portproxy to add v4tov4 port forwarding rules, a technique used by Volt Typhoon for C2 traffic tunneling and lateral pivoting.
author: Prince Leshan
date: 2026-09-09
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
            - '\netsh.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'portproxy'
            - 'add'
            - 'v4tov4'
    condition: selection_img and selection_cli
falsepositives:
    - Legitimate RDP jump host or bastion configuration
    - Developer port forwarding for local testing
    - VPN/NAT traversal workarounds set up by IT admins
    - Authorized network administrative port forwarding
level: high
tags:
    - attack.command_and_control
    - attack.lateral_movement
    - attack.t1090.001
```

*Iteration note: the original draft matched on `portproxy` + `v4tov4` anywhere in the command line, which also matched `netsh interface portproxy show all` (a read-only, non-malicious command). Split into separate `selection_img`/`selection_cli` blocks and added an explicit `add` requirement to eliminate that false positive.*

**Scheduled Task Persistence**

```yaml
title: Volt Typhoon - Persistence via Scheduled Task Creation
id: c92d4f88-1a5b-4c22-8d77-voltt1053005
status: test
description: Detects scheduled task creation via schtasks, cmd, or PowerShell with indicators of suspicious execution (LOLBins, script interpreters, or suspicious paths in the task action), a technique used by Volt Typhoon for persistence.
author: Prince Leshan
date: 2026-09-09
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
            - '\schtasks.exe'
    selection_cli:
        CommandLine|contains|all:
            - '/create'
            - '/tn'
    selection_suspicious_tr:
        CommandLine|contains:
            - '/tr'
        CommandLine|contains:
            - 'powershell'
            - 'cmd.exe'
            - 'wscript'
            - 'cscript'
            - 'mshta'
            - '\Users\Public\'
            - '\Temp\'
            - '\AppData\'
    filter_legit_vendor:
        CommandLine|contains:
            - 'OneDrive Standalone Update'
            - 'GoogleUpdateTaskMachine'
            - 'AdobeAAMUpdater'
            - 'CCleanerSkipUAC'
    condition: selection_img and selection_cli and selection_suspicious_tr and not filter_legit_vendor
falsepositives:
    - IT-deployed scripts that legitimately run from Temp/AppData staging paths
    - Some enterprise software updaters use scripting interpreters in task actions
level: medium
tags:
    - attack.persistence
    - attack.t1053.005
```

*Iteration note: the original draft matched on `/create` + `/tn` alone, which is present in nearly all legitimate scheduled task creation and would generate high alert volume in any real fleet. Added `selection_suspicious_tr` to require a scripting interpreter or suspicious staging path in the task's actual command (`/tr`), turning a generic-syntax match into a technique-specific signature. Also replaced an overly broad SYSTEM-context exclusion (which risked hiding genuine SYSTEM-level persistence, a common Volt Typhoon post-escalation pattern) with a named vendor-task filter. Level dropped from high to medium pending real-world false-positive testing.*

**NTDSutil Active Directory Staging**

```yaml
title: Volt Typhoon - NTDSutil Active Directory Staging
id: b3a2f109-8c4d-4e5a-9f12-voltt1003003
status: test
description: Detects execution of ntdsutil IFM (Install From Media) commands to create a local snapshot of the AD database (ntds.dit) for offline credential extraction, a technique used by Volt Typhoon.
author: Prince Leshan
date: 2026-09-09
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\cmd.exe'
            - '\ntdsutil.exe'
    selection_cli:
        CommandLine|contains: 'activate instance ntds'
    selection_ifm:
        CommandLine|contains: 'ifm'
    selection_create:
        CommandLine|contains: 'create full'
    condition: selection_img and selection_cli and selection_ifm and selection_create
falsepositives:
    - AD administrators performing authorized IFM snapshots for RODC promotion or DC cloning
    - Backup software (e.g. Veeam, Windows Server Backup) invoking ntdsutil IFM APIs for AD-aware backups
level: critical
tags:
    - attack.credential_access
    - attack.t1003.003
```

*Iteration note: anchored to the real IFM command sequence (`activate instance ntds`, `create full`) instead of loose word co-occurrence, and named specific legitimate use cases (RODC promotion, DC cloning, Veeam/Windows Server Backup) in falsepositives. This rule does not cover data exfiltration of the resulting `ntds.dit` snapshot — that is a separate detection surface (file access/copy monitoring), intentionally out of scope here.*

### 4.2 Wazuh PCRE2 Rules (`local_rules.xml`)

```xml
<group name="volt_typhoon, attack,">

  <!-- Rule 100202: Netsh Portproxy C2 Tunneling -->
  <rule id="100202" level="12">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine">(?i)netsh.*interface.*portproxy.*add.*v4tov4</field>
    <description>Volt Typhoon Emulation: C2 Tunneling via Netsh Portproxy Configuration (T1090.001)</description>
    <mitre>
      <id>T1090.001</id>
    </mitre>
  </rule>

  <!-- Rule 100203: Scheduled Task Persistence (tightened) -->
  <rule id="100203" level="10">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine">(?i)schtasks.*\/create.*\/tn.*\/tr.*(powershell|cmd\.exe|wscript|cscript|mshta|\\Users\\Public\\|\\Temp\\|\\AppData\\)</field>
    <description>Volt Typhoon Emulation: Persistence via Scheduled Task Creation with Suspicious Action (T1053.005)</description>
    <mitre>
      <id>T1053.005</id>
    </mitre>
  </rule>

  <!-- Rule 100204: NTDSutil Credential Dumping (regex covers syntax variants) -->
  <rule id="100204" level="13">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.commandLine">(?i)ntdsutil.*(ac\s+i\s+ntds|activate\s+instance\s+ntds).*ifm.*create\s+full</field>
    <description>Volt Typhoon Emulation: Active Directory Credential Dumping via NTDSutil IFM (T1003.003)</description>
    <mitre>
      <id>T1003.003</id>
    </mitre>
  </rule>

</group>
```

*Note: `if_sid 61603` assumes this ID maps to the Sysmon/process-creation base rule in this ruleset — confirm against your own `sysmon` rule group before reuse. Rule 100204's regex has not yet been cross-checked against the raw logged `alerts.json` output from the emulation run in Section 3 — pending validation.*

---













## 5. Engineering & Troubleshooting Journey

### Enabling Raw JSON Log Archiving (`logall_json`)

- **Symptom:** Unmatched or custom low-level log streams were dropped by default, limiting deep-dive debugging.
- **Resolution:** Modified `ossec.conf` in the container config mount:

```xml
<global>
  <logall>no</logall>
  <logall_json>yes</logall_json>
</global>
```

This initialized `archives.json`, capturing raw telemetry for validation. Live alert verification:

```bash
docker exec single-node-wazuh.manager-1 tail -f /var/ossec/logs/alerts/alerts.json | grep -E '100202|100203|100204'
```

<img width="1600" height="858" alt="image" src="https://github.com/user-attachments/assets/4fd86816-207a-4542-ade4-c792bb9ed24a" />

---

## 6. SIEM Visibility & OpenSearch Dashboard Artifacts

A custom SOC dashboard was built in OpenSearch Dashboards using hierarchical split-row aggregations to expose the underlying command-line arguments behind each alert.

### Dashboard Architecture

1. **Rule Distribution & TTP Breakdown:** Alert frequency across Rules `100202`, `100203`, `100204`.
2. **Granular Artifact Triage Table:** Multi-layered terms aggregation nesting `rule.description` above the exact captured `win.eventdata.commandLine`.

<img width="1600" height="834" alt="image" src="https://github.com/user-attachments/assets/0ad168bb-dbc9-444d-b57c-daac54dd2359" />


<img width="1600" height="834" alt="image" src="https://github.com/user-attachments/assets/8ca55ff4-af02-4bcd-8e2d-e9989cfb76f8" />


---

## 7. Conclusion & Open Items

This project walks through a detection engineering lifecycle end to end: emulating documented Volt Typhoon LOLBin techniques, drafting detection logic, catching and fixing false-positive-prone rules through iterative review, and standing up SIEM visibility for the results.

**Open items before these rules should be called production-ready:**

- Rule 100204's regex has not been confirmed against the actual logged `commandLine` field from the NTDSutil emulation run — needs a direct check against `alerts.json`.
- No rule currently checks `ParentImage`/parent-process context, which would materially raise fidelity (e.g. distinguishing admin-driven vs. WMI/PsExec-driven execution).
- Rule 100203's vendor exclusion list is a starting point, not tuned against real enterprise noise — expect additional false positives in a live fleet.
- No companion detection for `ntds.dit` exfiltration (file copy/access monitoring) — the current rule covers staging only, not theft.

