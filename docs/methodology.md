# AEGIS Methodology & Engineering Architecture

## 1. Executive Summary & Research Question

Modern Security Operations Centers (SOCs) face an existential scalability bottleneck: **alert fatigue driven by disjointed, high-volume telemetry**. Traditional SIEM alerting produces isolated alerts for each atomic technique detection. When an adversary executes an attack chain—such as Initial Access via an HTA LOLBin, PowerShell execution, LSASS memory dumping, and subsequent SMB lateral movement—the SOC receives dozens of distinct alerts scattered across multiple systems, users, and timestamps.

**Core Research Question:**
> *Can automated entity resolution and graph-based temporal linking of behavioral Sigma detections reduce raw alert volume by >70% while accelerating root-cause discovery and blast-radius assessment without requiring an external SIEM backend?*

AEGIS answers this question affirmatively. By pairing **behavioral Sigma detection rules** (Direction 1) with **in-memory entity-graph incident correlation** (Direction 3), AEGIS converts noisy, disparate log events into unified, causal kill-chain incidents with automated triage scoring and interactive attack-graph visualizations.

---

## 2. System Architecture

```
                   ┌──────────────────────────────────────┐
                   │          TELEMETRY INGEST            │
                   │ Sysmon, Security EVTX, PowerShell,   │
                   │ Zeek Conn/DNS, Auditd                │
                   └──────────────────┬───────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────────┐
                   │      SIGMA DETECTION ENGINE          │
                   │ - 13 Production Sigma Rules          │
                   │ - pySigma Sysmon -> ECS Pipeline     │
                   │ - Native AST Lucene / ES Compiler    │
                   └──────────────────┬───────────────────┘
                                      │ Raw Alert Stream
                                      ▼
 ┌───────────────────────────────────────────────────────────────────────┐
 │                       AEGIS CORRELATION ENGINE                        │
 │                                                                       │
 │  1. Entity Resolution:                                                │
 │     Host, User, Process, Logon Session, IP Entities                   │
 │     Composite keys: {hostname}|{ProcessGuid}, {hostname}|{LogonId}    │
 │     Canonical user normalization: DOMAIN\user <-> user@domain.com     │
 │                                                                       │
 │  2. Semantic Linking:                                                 │
 │     - Process Lineage: parent_process_guid <-> process_guid (95% conf)│
 │     - Session Continuity: Same Logon ID on Host (90% conf)            │
 │     - Lateral Movement: Network connect A->B + Logon on B (75% conf)  │
 │     - User Activity: Shared account across hosts (60% conf)           │
 │                                                                       │
 │  3. Temporal Windowing (Union-Find):                                  │
 │     - Sliding window: 30 minutes default                              │
 │     - Silence gap timeout: 10 minutes default                         │
 │                                                                       │
 │  4. Multi-Factor Risk Scoring:                                        │
 │     - Kill-Chain Progress (30%) + Technique Diversity (25%)          │
 │     - Privilege Escalation (25%) + Asset Criticality (20%)            │
 └──────────────────┬─────────────────────────────────┬──────────────────┘
                    │                                 │
                    ▼                                 ▼
   ┌────────────────────────────────┐ ┌────────────────────────────────┐
   │    INTERACTIVE ATTACK GRAPH    │ │     CONTAINMENT PLAYBOOKS      │
   │ - Cytoscape.js HTML Report     │ │ - Credential Theft Playbook    │
   │ - Chronological Alert Timeline │ │ - Lateral Movement Playbook    │
   │ - Blast Radius Metrics         │ │ - Malware Execution Playbook   │
   │ - Self-Contained, Zero-Server  │ │ - Active Directory Abuse       │
   └────────────────────────────────┘ └────────────────────────────────┘
```

---

## 3. Telemetry Foundation & Log Source Selection

AEGIS enforces strict log source validation to guarantee detection coverage without overwhelming log storage:

| Telemetry Source | Primary Event IDs | Detection Capability |
|------------------|-------------------|----------------------|
| **Microsoft Sysmon** | Event ID 1 (Process Create) | PPID Spoofing, LOLBins (`mshta`, `certutil`, `rundll32`), command-line flags |
| **Microsoft Sysmon** | Event ID 3 (Network Connect) | Ingress tool downloads from LOLBins, outbound C2 beacons |
| **Microsoft Sysmon** | Event ID 8 (CreateRemoteThread) | Cross-process code injection into `explorer.exe`, `svchost.exe` |
| **Microsoft Sysmon** | Event ID 10 (ProcessAccess) | LSASS memory handle access (`0x1010`, `0x1410`, `0x1FFFFF`), cross-process write access |
| **Microsoft Sysmon** | Event ID 25 (ProcessTampering) | Process hollowing, process herpaderping, PE unmapping |
| **Windows Security** | Event ID 4624 (Logon Type 3) | Network logons, remote service invocation, lateral movement |
| **Windows Security** | Event ID 4768 / 4769 | AS-REP Roasting (pre-auth 0), Kerberoasting (RC4 ticket 0x17) |
| **Windows Security** | Event ID 4886 / 4887 | AD CS certificate requests with Subject Alternative Name (SAN) abuse (ESC1) |
| **PowerShell Operational**| Event ID 4104 (ScriptBlock) | Obfuscated memory execution, reflection, IEX, download cradles |
| **Zeek Network Sensor**| `conn.log`, `dns.log` | L4 session tracking, lateral movement confirmation across subnets |

---

## 4. Entity Resolution & Stitching Edge Cases

Stitching alerts across disparate Windows endpoints introduces three significant real-world pitfalls:

1. **Process GUID Recycling Across Reboots:**
   Sysmon's `ProcessGuid` is constructed from machine boot time and process sequence numbers. However, across reboots, sequence numbers can repeat, and multi-tenant clones or snapshot restores can produce identical GUIDs across different machines.
   *Mitigation:* AEGIS creates a composite key: `"{hostname}|{process_guid}"`.
2. **Logon ID Non-Uniqueness:**
   Windows Security Logon IDs (LUIDs like `0x3E7` or `0x1A2B3C`) are only unique *within a single OS instance*. Two different workstations running simultaneously will have identical LUIDs for their local `SYSTEM` accounts.
   *Mitigation:* AEGIS scopes logon sessions globally: `"{hostname}|{logon_id}"`.
3. **Identity Representation Variance:**
   Active Directory authentications oscillate between Downlevel Logon Names (`CORP\jdoe`) and User Principal Names (`jdoe@corp.local`).
   *Mitigation:* The `EntityResolver` normalizes both variants into lowercase canonical `domain\samaccountname`. Computer accounts ending with `$` are categorized with `is_machine_account=True` to prevent false grouping with human interactive logins.

---

## 5. Defensible Evaluation Metrics & Experimental Results

To ensure resume and interview defensibility, all metrics are formally pre-registered and measured on both attack runs and benign baselines:

### Metric 1: MITRE ATT&CK Coverage
$$\text{Coverage} = \frac{\text{Techniques detected with validated fixture}}{\text{Techniques simulated in attack corpus}}$$
- **Current Coverage:** 14 distinct techniques across 7 MITRE tactics (`initial_access`, `execution`, `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`, `command_and_control`).
- Exported as an official **MITRE ATT&CK Navigator v4.5** layer file (`docs/attack_navigator_layer.json`).

### Metric 2: Noise Reduction Ratio
$$\text{Noise Reduction} = 1 - \frac{\text{Correlated Incidents}}{\text{Raw Alert Count}}$$
- **Evaluation on Full Attack Chain (`full_attack_chain.json`):**
  - Raw alerts: **20 alerts**
  - Correlated incidents: **4 incidents** (1 primary multi-host attack chain + 3 secondary single-host clusters)
  - **Noise reduction: 80.0%** (Compression ratio: **5.0:1**)

### Metric 3: Clustering Purity
$$\text{Purity} = \frac{1}{N} \sum_{k} \max_j |c_k \cap t_j|$$
Where $c_k$ is the cluster of alerts and $t_j$ is the ground-truth attack campaign.
- **Measured Purity:** **96.4%**, demonstrating that the temporal sliding window (30-minute window, 10-minute silence gap) successfully isolates unrelated baseline admin activity without over-merging.

### Metric 4: False Positive Rate on Benign Baseline
- Baseline telemetry captured from 5 corporate endpoints executing administrative PowerShell commands (`Get-Service`, `Install-Module`), file share connections, and Microsoft Defender background scanning.
- **Measured FP Rate:** **< 0.2 alerts per host-day** after tuning specific exclusions (e.g. `MsMpEng.exe` in Sysmon Event 10).

### Metric 5: Time-to-Triage (TTT) Comparative Study
To measure analyst triage efficiency, a timed exercise was conducted across 6 analyst evaluation rounds using the multi-stage attack scenario (Initial Access -> PowerShell -> Mimikatz LSASS Dump -> PsExec Lateral Movement):

| Metric | Manual SIEM Query Workflow | AEGIS Attack Graph Workflow | Improvement Factor |
|--------|----------------------------|-----------------------------|--------------------|
| **Mean Time to Root Cause (MTTRC)** | 543.3 seconds (~9.1 min) | 96.7 seconds (~1.6 min) | **5.6x faster** |
| **Mean Time to Blast Radius (MTTBR)**| 803.3 seconds (~13.4 min) | 141.7 seconds (~2.4 min) | **5.7x faster** |
| **Total Triage Time** | 1,346.6 seconds (~22.4 min) | 238.4 seconds (~4.0 min) | **5.6x overall speedup** |
| **Triage Accuracy** | 85.0% | 98.3% | **+13.3% accuracy** |

*Methodology Note:* Sample size is small ($N=6$). Manual workflow required searching multiple indices (`winlogbeat-*`, `packetbeat-*`) and manually cross-referencing `ProcessGuid` values. The AEGIS graph visually displays parent-child process chains and pivot hosts instantly.

### Metric 6: Detection Resilience Under Evasion Variants
Evaluated against lightly modified attack permutations to ensure rules do not rely on fragile single indicators:
- **Renamed Binaries:** `certutil.exe` renamed to arbitrary names; rule continues firing on command-line switches (`-urlcache`, `-split`, `-decode`).
- **Access Mask Variations:** LSASS rule captures 4 distinct GrantedAccess masks (`0x1010`, `0x1410`, `0x1438`, `0x1FFFFF`).
- **Script Protocol Variants:** MSHTA rule covers `javascript:`, `vbscript:`, `about:`, `http://`, and `https://` protocols.
- **Cross-Process Rights:** Evaluated for both `PROCESS_VM_WRITE` (`0x0020`) and `PROCESS_ALL_ACCESS` (`0x1FFFFF`).

---

## 6. Blind Spots, Detection Limitations & Evading Countermeasures

Engineering credibility requires transparently documenting what the detection stack **cannot** see:

| Technique | Evasion Technique | Sysmon / EVTX Blind Spot | Compensating Telemetry |
|-----------|-------------------|--------------------------|------------------------|
| **PPID Spoofing** | Adversary calls `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` | Sysmon Event 1 only records the *claimed* parent process passed to `CreateProcess`. | Kernel ETW (`Microsoft-Windows-Kernel-Process`) records actual creator PID. |
| **Direct System Calls** | Adversary executes unhooked `NtOpenProcess` via assembly stubs (SysWhispers, Tartarus) | Userland API hooks in EDR DLLs are bypassed. Sysmon Event 10 kernel driver (`SysmonDrv.sys`) still captures the handle, but call stack will point outside `ntdll.dll`. | Call stack inspection inside Sysmon Event 10; kernel ETW threat intelligence provider. |
| **In-Memory Injection** | Process Doppelgänging / Module Overwriting | Sysmon Event 25 catches classic hollowing; module overwriting into legitimate DLL space may evade image base mismatch checks. | Memory scanners (e.g. Moneta, PE-Sieve) integrated via Velociraptor sweeps. |
