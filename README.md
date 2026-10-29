# AEGIS — Automated Event Graph & Incident Synthesis

<p align="center">
  <pre align="center">
    █████╗ ███████╗ ██████╗ ██╗███████╗
   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
   ███████║█████╗  ██║  ███╗██║███████╗
   ██╔══██║██╔══╝  ██║   ██║██║╚════██║
   ██║  ██║███████╗╚██████╔╝██║███████║
   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
   <b>Autonomous Detection Engineering & Attack Graph Correlation Engine</b>
  </pre>
</p>

<p align="center">
  <a href="https://github.com/Akki-74/AEGIS/actions/workflows/ci.yml"><img src="https://github.com/Akki-74/AEGIS/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+"></a>
  <a href="https://mitre-attack.github.io/attack-navigator/"><img src="https://img.shields.io/badge/ATT%26CK%20Navigator-v4.5-orange?style=for-the-badge&logo=mitre&logoColor=white" alt="MITRE ATT&CK Navigator"></a>
  <a href="#-testing--continuous-integration"><img src="https://img.shields.io/badge/Tests-48%20Passed%20(52%20Subtests)-brightgreen?style=for-the-badge" alt="48 Tests Passed"></a>
  <a href="#-testing--continuous-integration"><img src="https://img.shields.io/badge/Coverage-60.2%25-brightgreen?style=for-the-badge" alt="Coverage 60.2%"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License: MIT"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/badge/Code%20Style-Ruff-black?style=for-the-badge" alt="Ruff"></a>
  <a href="#-empirical-evaluation--benchmarks"><img src="https://img.shields.io/badge/Noise%20Reduction-80.0%25%20(Empirical)-success?style=for-the-badge" alt="Noise Reduction 80.0% Empirical"></a>
  <a href="#-empirical-evaluation--benchmarks"><img src="https://img.shields.io/badge/Triage%20Model-5.6x%20(Simulated%20Hypothesis)-blueviolet?style=for-the-badge" alt="Triage Model 5.6x Simulated Hypothesis"></a>
</p>

---

## 📑 Table of Contents

- [🛡️ Executive Overview](#️-executive-overview)
- [🧩 Problem Statement: Why Legacy SIEMs Fail](#-problem-statement-why-legacy-siems-fail)
- [🏗️ Architectural Architecture & Data Pipeline](#️-architectural-architecture--data-pipeline)
- [✨ Key Technical Innovations](#-key-technical-innovations)
  - [1. Resilient Behavioral Sigma Rules](#1-resilient-behavioral-sigma-rules)
  - [2. Graph-Based Entity Resolution & Disambiguation](#2-graph-based-entity-resolution--disambiguation)
  - [3. Multi-Vector Causal Semantic Linker & Evidence Retention](#3-multi-vector-causal-semantic-linker--evidence-retention)
  - [4. Stress-Resilient Temporal Clustering](#4-stress-resilient-temporal-clustering)
  - [5. Multi-Factor Kill-Chain Risk Scoring](#5-multi-factor-kill-chain-risk-scoring)
  - [6. Zero-Server Interactive Attack Graph Visualizer](#6-zero-server-interactive-attack-graph-visualizer)
  - [7. Safety-First Incident Response Playbook Harness](#7-safety-first-incident-response-playbook-harness)
- [🎯 MITRE ATT&CK Detection Matrix](#-mitre-attck-detection-matrix)
- [📊 Empirical Evaluation & Benchmarks](#-empirical-evaluation--benchmarks)
  - [Controlled Time-to-Triage (TTT) Study](#time-to-triage-ttt-study-simulated-cognitive-model-n6-scenarios)
  - [Noise Reduction & Compression Ratio](#empirical-performance-summary)
- [⚡ Quickstart & 1-Command Live Demo](#-quickstart--1-command-live-demo)
- [💻 Production CLI Command Reference](#-production-cli-command-reference)
- [📁 Repository Directory Structure](#-repository-directory-structure)
- [🧪 Testing & Continuous Integration](#-testing--continuous-integration)
- [📜 Automated Operational Session Logging](#-automated-operational-session-logging)
- [🛡️ Adversary Evasion Defense & Documented Limitations](#️-adversary-evasion-defense--documented-limitations)
- [📄 License & Citation](#-license--citation)

---

## 🛡️ Executive Overview

**AEGIS** (Automated Event Graph & Incident Synthesis) is a high-performance detection engineering and incident correlation platform that unifies **Direction 1 (Behavioral Sigma Detection Rules)** with **Direction 3 (Graph-Based Incident Correlation and Attack Graphing)**.

Modern Security Operations Centers (SOCs) drown in disconnected alert streams: a single intrusion generates dozens of atomic notifications across disparate sensors. Analysts are forced to manually correlate process IDs, logon sessions, and network timestamps across hosts to reconstruct what occurred.

AEGIS solves this by **reconstructing the adversary's causal attack graph in real time**. It ingests normalized endpoint (Sysmon, Windows Security, PowerShell) and network telemetry (Zeek), executes robust behavioral Sigma rules, resolves composite multi-host entities, links events along verified causal vectors, and outputs actionable, interactive incident graphs paired with containment playbooks.

---

## 🧩 Problem Statement: Why Legacy SIEMs Fail

```
+----------------------------------------------------------------------------------------------------+
|                                    TRADITIONAL SIEM ALERT FLOOD                                    |
| [Alert 1: Certutil URL]  [Alert 2: MSHTA Spawn]  [Alert 3: RC4 4769]  [Alert 4: LSASS Mask 0x1010] |
|                 -> Analyst spends 45 minutes manually pivoting logs to connect them                |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+----------------------------------------------------------------------------------------------------+
|                                   AEGIS INCIDENT SYNTHESIS ENGINE                                  |
|                                                                                                    |
|    [Certutil Ingress] ──Lineage──> [MSHTA Payload] ──Session──> [LSASS Dump] ──Pivot──> [DC Sync]  |
|                                                                                                    |
|  * 1 Synthesized Incident Graph (Attack Score: 92.5/100, CRITICAL)                                 |
|  * Root Cause: WS01 (PID 4812, User: DOMAIN\victim_user)                                           |
|  * Blast Radius: 2 Hosts (WS01, DC01), 3 Accounts, 5 Techniques                                     |
|  * Automated Safe Dry-Run Containment Playbook Generated in < 2 seconds                            |
+----------------------------------------------------------------------------------------------------+
```

1. **Alert Volume vs. Incident Clarity**: SIEMs alert on symptoms (e.g., `certutil.exe -urlcache`), generating 80%+ redundant alerts during active campaigns.
2. **Entity Ambiguity & LUID Collisions**: Windows Logon IDs (`0x3E7`, `0x4A12`) collide across different workstations; Sysmon Process GUIDs recycle across hypervisor snapshots and reboots.
3. **Absence of Causal Provenance**: Traditional correlation relies on coarse timestamp grouping, merging unrelated admin activity into attacker incidents (cluster pollution).
4. **Slow Time-To-Triage (TTT)**: Junior analysts take an average of 9–15 minutes per alert to trace parent processes, inspect network sessions, and gauge blast radius.

---

## 🏗️ Architectural Architecture & Data Pipeline

The AEGIS pipeline is divided into five strictly decoupled, modular stages:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. TELEMETRY INGESTION & NORMALIZATION                                                 │
│    • Sysmon (Event IDs 1, 3, 7, 8, 10, 11, 13, 25) via SwiftOnSecurity Modular XML     │
│    • Windows Security Event Log (IDs 4624/4625, 4648, 4768, 4769, 4886/4887)          │
│    • PowerShell ScriptBlock Logging (ID 4104)                                          │
│    • Zeek Network Sensors (conn.log, dns.log, http.log)                                │
│    • Shipped via Winlogbeat & Filebeat normalized into Elastic Common Schema (ECS)    │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Normalized ECS Events
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 2. DETECTION COMPILATION & EVALUATION (pySigma AST Engine)                             │
│    • 13 High-Fidelity Behavioral Sigma Rules (Defense Evasion, Credentials, AD CS)     │
│    • Custom pySigma Sysmon-to-ECS Processing Pipeline                                  │
│    • Dual Compilation Engine: LuceneBackend (pySigma) + Native AST Lucene/ES Compiler  │
│    • 26 Positive and Negative Fixture Test Suites per Rule                             │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Raw Alert Stream
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. GRAPH-BASED INCIDENT CORRELATION ENGINE                                             │
│    ┌──────────────────────────────────────────────────────────────────────────────┐    │
│    │ a. Entity Resolution: Composite Host+GUID keys, Host+LUID, UPN Normalization │    │
│    ├──────────────────────────────────────────────────────────────────────────────┤    │
│    │ b. Causal Linker: Process Lineage (0.95 Direct Causal), Session (0.90),      │    │
│    │    Inferred Lateral Movement (0.75), Contextual User Activity (0.60 Isolated)│    │
│    ├──────────────────────────────────────────────────────────────────────────────┤    │
│    │ c. Temporal Windowing: Deduplication, Chronological Sorting, DisjointSet      │    │
│    │    Union-Find, Inactivity Gap Silence Timeout & Host Reboot Boundaries       │    │
│    ├──────────────────────────────────────────────────────────────────────────────┤    │
│    │ d. Multi-Factor Risk Scoring: Kill-Chain (30%) + Technique (25%) +           │    │
│    │    Privilege (25%) + Asset Criticality (20%)                                 │    │
│    └──────────────────────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │ Synthesized Incidents
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ 4. VISUAL SYNTHESIS & CONTAINMENT AUTOMATION                                           │
│    • Zero-Server Cytoscape.js Interactive Attack Graph Report (Self-Contained HTML)   │
│    • Chronological Attack Timeline & Provenance Inspector Drawer                       │
│    • Safe Containment Runner: Dry-Run by default, Senior Approvals, DC Protection,    │
│      and Automated Inverse Rollback/Recovery Plans                                     │
│    • Public Dataset Evaluated: OTRF Security Datasets E2E Verification                 │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Technical Innovations

### 1. Resilient Behavioral Sigma Rules
Rather than matching static filenames or hashes that an adversary can trivially alter, AEGIS detection rules target **immutable system behaviors and operating system primitives**:
- **LSASS Memory Protection**: Evaluates kernel `GrantedAccess` bitmasks (e.g., `0x1010` `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION`, `0x1438`, `0x1FFFFF`) rather than process names, bypassing Mimikatz / ProcDump renames while strictly excluding authenticated security signers.
- **Process Injection & Tampering**: Detects cross-process thread instantiation (`CreateRemoteThread`, Sysmon ID 8) and process hollowing/unmapping (Sysmon ID 25).
- **LOLBin Abuse**: Detects `certutil`, `mshta`, and `rundll32` through parameter anomalies (`-urlcache`, `-split`, script protocols like `javascript:`, `vbscript:`) and abnormal parent-child execution chains.
- **Active Directory Exploitation**: Identifies Kerberoasting via RC4-HMAC ticket requests (Event ID 4769 `TicketEncryptionType=0x17`) filtering out computer accounts (`$`), and AS-REP Roasting (Event ID 4768 pre-authentication type 0).

### 2. Graph-Based Entity Resolution & Disambiguation
To prevent entity collision across enterprise networks:
- **Process Identity**: Sysmon Process GUIDs recycle across hypervisor reboots and clones. AEGIS generates an immutable composite key:
  $$\text{Key}_{\text{proc}} = \text{hostname} \mathbin{\Vert} \text{process\_guid}$$
- **Logon Session Identity**: Windows Logon IDs (LUIDs like `0x3E7`, `0x1A42F`) are unique only per machine. AEGIS prefixes the host:
  $$\text{Key}_{\text{logon}} = \text{hostname} \mathbin{\Vert} \text{logon\_id}$$
- **Identity Canonicalization**: Automatically unifies Downlevel NetBIOS (`CORP\jdoe`), UPN (`jdoe@corp.local`), and bare usernames (`jdoe`) to prevent fragmented user subgraphs.

### 3. Multi-Vector Causal Semantic Linker & Evidence Retention
AEGIS builds directed attack edges between alerts, retaining the underlying evidentiary justification and distinguishing direct causation from inferred associations:
- **Direct Causal Evidence (`DIRECT_CAUSAL`, Confidence = 0.95)**: Deterministic kernel process lineage (`ParentProcessGuid` $\rightarrow$ `ProcessGuid`).
- **Session Continuity (`SESSION_CONTINUITY`, Confidence = 0.90)**: Alerts originating from the exact same authenticated logon session on a given host.
- **Inferred Lateral Movement (`INFERRED_ASSOCIATION`, Confidence = 0.75)**: Network connection followed by logon on the destination host within a strict temporal window.
- **Contextual User Activity (`CONTEXTUAL_ASSOCIATION`, Confidence = 0.60)**: Weak administrative associations. Tagged with `exclude_from_hard_clustering=True` so they provide visual context in the attack graph **without collapsing unrelated incidents across hosts**.
- **Edge Evidence Schema**: Every edge stores contributing `LinkEvidence` objects with source/target alert IDs, timestamps, and causal summaries.

### 4. Stress-Resilient Temporal Clustering
Alerts are clustered into coherent incidents using a stress-hardened sliding-window DisjointSet algorithm:
- **Telemetry Deduplication**: Incoming alerts with identical semantic fingerprints (`host + rule + timestamp + process_guid`) are deduplicated.
- **Chronological Stream Sorting**: Events arriving out-of-order due to network shipper jitter are sorted chronologically before component evaluation.
- **Inactivity Gap Silence Timeout ($T_{gap} = 10\text{m}$)**: Automatically terminates clusters during adversary dormancy, preventing unrelated multi-day activity from improperly merging.
- **Host Reboot Boundary Partitioning**: Detects system restart events (Event IDs 1074, 6005, 6006) and splits temporal continuity across reboots.

### 5. Multi-Factor Kill-Chain Risk Scoring
Incidents are scored on a normalized scale ($0 \text{ to } 100$) using a multi-factor risk model:
$$R_{\text{incident}} = \left( 0.30 \cdot S_{\text{killchain}} + 0.25 \cdot S_{\text{diversity}} + 0.25 \cdot S_{\text{privilege}} + 0.20 \cdot S_{\text{asset}} \right) \times 100$$
Where:
- $S_{\text{killchain}}$: Ratio of unique MITRE ATT&CK tactics represented in the incident chain (Initial Access $\rightarrow$ Execution $\rightarrow$ Defense Evasion $\rightarrow$ Credential Access $\rightarrow$ Lateral Movement).
- $S_{\text{diversity}}$: Technique variety metric penalizing repetitive single-technique flooding.
- $S_{\text{privilege}}$: Presence of elevated access operations (SYSTEM, Domain Admin, LSASS handle acquisition).
- $S_{\text{asset}}$: Criticality multiplier when Tier-0 assets (Domain Controllers, Certificate Authorities) are touched.

### 6. Zero-Server Interactive Attack Graph Visualizer
AEGIS compiles correlated incidents into a **standalone, self-contained HTML report** powered by Cytoscape.js. No web server, database, or backend service is required. 
- **Dark Theme Cybersecurity UI**: Color-coded nodes by entity type (Compromised Host, Process, User Account, Stolen Credential, Domain Controller).
- **Edge Weight & Type Coloring**: Visual distinction between direct process lineage, logon session continuity, and lateral movement hops.
- **Interactive Inspector Drawer**: Click on any node or edge to view full telemetry details, command lines, access masks, and raw event timestamps.
- **Chronological Slider**: Step through the attack campaign sequentially from initial ingress to domain escalation.

### 7. Safety-First Incident Response Playbook Harness
Every incident maps to actionable YAML response playbooks ([aegis/playbooks/runner.py](aegis/playbooks/runner.py)) with production-grade safety guardrails:
- **Dry-Run by Default (`dry_run=True`)**: Generates safe simulation recommendations and execution previews without altering live infrastructure.
- **Senior Approver Signature Required**: Live execution (`dry_run=False`) requires an authorized `approved_by: str` analyst identity; otherwise execution is blocked.
- **Critical Asset Guardrails**: Automatically blocks isolation of Domain Controllers (`DC01`, `DC02`), core gateways (`DNS01`), and system accounts (`SYSTEM`, `krbtgt`, machine accounts `$`) unless overridden with explicit authorization.
- **Automated Rollback & Recovery Procedures**: Every containment action automatically outputs its exact inverse recovery procedure (e.g. `unisolate_endpoint` via firewall reset, `restore_account_access`).

---

## 🎯 MITRE ATT&CK Detection Matrix

AEGIS provides validated, unit-tested coverage across primary offensive vectors. The repository includes an official layer export viewable in [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):

| Tactic | Technique ID | Technique Name | Primary Telemetry | Resilient Detection Logic |
| :--- | :--- | :--- | :--- | :--- |
| **Credential Access** | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory Dumping | Sysmon Event ID 10 | Bitmask filtering: `0x1010`, `0x1410`, `0x1438`, `0x1FFFFF` with signer path validation |
| **Credential Access** | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Security Event ID 4769 | Request for RC4-HMAC (`0x17`/`23`) ticket encryption for user-account SPNs, volume/threshold building block filtering machine accounts (`$`) and `krbtgt` |
| **Credential Access** | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | AS-REP Roasting | Security Event ID 4768 | Pre-authentication Type 0 (`PreAuthType=0`) requests for user accounts |
| **Execution** | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell ScriptBlock | PowerShell Event ID 4104 | Download cradles, `System.Reflection`, `MemoryStream`, Base64 decoding |
| **Execution** | [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | LOLBin: MSHTA | Sysmon Event ID 1 | Command-line script protocols (`javascript:`, `vbscript:`) & Office/browser parents |
| **Execution** | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | LOLBin: Rundll32 | Sysmon Event ID 1 | Comsvcs.dll `MiniDump` export calls and inline script loader execution |
| **Defense Evasion** | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic Link Library Injection | Sysmon Event ID 8 | Cross-process `CreateRemoteThread` instantiation targeting system binaries |
| **Defense Evasion** | [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | Process Hollowing / Tampering | Sysmon Event ID 25 | Image replacement and memory unmapping indicators |
| **Defense Evasion** | [T1134.004](https://attack.mitre.org/techniques/T1134/004/) | Parent PID (PPID) Spoofing | Sysmon Event ID 1 | Parent creation timestamp anomaly (parent started *after* child) & illegal parentage |
| **Defense Evasion** | [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading & Write Rights | Sysmon Event ID 10 | Cross-process access requesting write/thread rights (`0x0020`, `0x1FFFFF`) |
| **Command & Control** | [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | Sysmon Event ID 1 | `certutil.exe` with `-urlcache`, `-split`, or `-decode` arguments |
| **Privilege Escalation** | [T1649](https://attack.mitre.org/techniques/T1649/) | AD CS ESC1 / SAN Abuse | Security Event IDs 4886/4887 | Certificate requests specifying subjectAltName attributes on vulnerable templates |
| **Lateral Movement** | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | SMB / Windows Admin Shares | Security Event ID 4624 | Logon Type 3 network authentications originating from non-domain controller endpoints |

---

## 📊 Empirical Evaluation & Benchmarks

AEGIS evaluation metrics are formally derived and rigorously documented. To maintain strict engineering honesty, metrics are explicitly labeled as either **Empirical Measurements** (tested on raw and public datasets) or **Simulated Benchmarks** (cognitive task model simulations and synthetic baselines):

```
+--------------------------------------------------------------------------------------------------+
|                                  EMPIRICAL PERFORMANCE SUMMARY                                   |
+--------------------------------------+--------------------+--------------------------------------+
| METRIC                               | MEASURED RESULT    | BENCHMARK METHODOLOGY / BASELINE     |
+--------------------------------------+--------------------+--------------------------------------+
| Alert-to-Incident Compression Ratio  | 5.0 : 1            | [Empirical] 20 Raw Alerts -> 4 Incidents
| Noise Reduction Percentage           | 80.0%              | [Empirical] Reduction in triage items
| Incident Clustering Purity           | 96.4%              | [Simulated] Campaign ground truth    |
| Mean Time to Root Cause (MTTRC)      | 96.7 seconds       | [Simulated] 5.6x faster than manual  |
| Mean Time to Blast Radius (MTTBR)    | 141.7 seconds      | [Simulated] 5.7x faster than manual  |
| Triage Classification Accuracy       | 98.3%              | [Simulated] +13.3% over manual       |
| Benign False Positive Rate           | < 0.2 alerts/day   | [Simulated] 5-Host admin trace       |
+--------------------------------------+--------------------+--------------------------------------+
```

### Time-to-Triage (TTT) Study (Simulated Cognitive Model, n=6 Scenarios)
Benchmarked using a standardized cognitive step-level triage model across 6 multi-stage incident scenarios comparing sequential manual SIEM pivoting vs. AEGIS automated attack graph traversal:

$$\text{Triage Speedup} = \frac{\text{MTTRC}_{\text{manual}}}{\text{MTTRC}_{\text{aegis}}} = \frac{543.3\text{s}}{96.7\text{s}} = \mathbf{5.62\times}$$

$$\text{Blast Radius Speedup} = \frac{\text{MTTBR}_{\text{manual}}}{\text{MTTBR}_{\text{aegis}}} = \frac{803.3\text{s}}{141.7\text{s}} = \mathbf{5.67\times}$$

> [!IMPORTANT]
> **Scientific Transparency Note on Benchmarks**:
> - **Empirical**: Alert compression (5:1) and noise reduction (80.0%) are measured directly on repeatable raw and public datasets ([tests/fixtures/public_datasets/otrf_attack_sample.json](tests/fixtures/public_datasets/otrf_attack_sample.json)).
> - **Simulated Hypothesis**: Triage speedups (5.6× MTTRC, 5.7× MTTBR) represent an engineering hypothesis derived from GOMS-style cognitive step modeling across 6 test scenarios. They quantify theoretical analyst keystroke/pivot savings and must be tested in live human-subject trials before being interpreted as field SLA gains.

---

## ⚡ Quickstart & 1-Command Live Demo

Experience the full AEGIS pipeline in under 10 seconds.

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Akki-74/AEGIS.git
cd aegis

# Initialize virtual environment (Python 3.11+)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies in editable mode
pip install -e ".[dev]"
```

### 2. Run the Interactive End-to-End Demo

```bash
python scripts/demo.py
```

The script will ingest an alert flood, perform entity resolution and linking, display the ranked incidents in the terminal, and generate an interactive Cytoscape.js HTML graph at `reports/demo_attack_graph.html`.

Open the resulting visualization in your browser:
```bash
# Windows
start reports/demo_attack_graph.html

# Linux
xdg-open reports/demo_attack_graph.html

# macOS
open reports/demo_attack_graph.html
```

---

## 💻 Production CLI Command Reference

AEGIS includes a production-grade Click CLI accessible via `python -m aegis.cli` or `aegis`:

### Rule Validation & Compilation
```bash
# Validate metadata, UUIDv4 uniqueness, and ATT&CK tags across all rules
python -m aegis.cli rules validate --rules-dir rules/

# Compile Sigma rules into Elasticsearch / OpenSearch Query DSL
python -m aegis.cli rules compile --rules-dir rules/ --backend elasticsearch --output compiled_queries.ndjson
```

### Incident Correlation
```bash
# Correlate a raw alert dataset into multi-stage incidents
python -m aegis.cli correlate run \
  --input tests/fixtures/malicious/full_attack_chain.json \
  --output reports/incidents.json \
  --window 3600 \
  --gap 1800
```

### Interactive Graph Generation
```bash
# Render correlated incidents into a zero-server Cytoscape.js HTML attack graph
python -m aegis.cli graph build \
  --input reports/incidents.json \
  --output reports/attack_graph.html
```

### Metrics & ATT&CK Layer Export
```bash
# Generate MITRE ATT&CK coverage report and export Navigator v4.5 JSON layer
python -m aegis.cli eval coverage --rules-dir rules/ --output docs/attack_navigator_layer.json

# Calculate empirical noise reduction statistics
python -m aegis.cli eval noise \
  --before tests/fixtures/malicious/full_attack_chain.json \
  --after reports/incidents.json
```

### Operational Session Logging
```bash
# Append an analyst operations note to persistent session logs
python -m aegis.cli session log "Completed tuning on LSASS GrantedAccess bitmask rule"

# View recent operational session history
python -m aegis.cli session history --limit 5
```

---

## 📁 Repository Directory Structure

```
AEGIS/
├── rules/                           # 13 Behavioral Sigma detection rules
│   ├── credential_access/           # LSASS memory, Kerberoasting, AS-REP roasting
│   ├── execution/                   # PowerShell ScriptBlock, LOLBins (mshta, certutil, rundll32)
│   ├── defense_evasion/             # CreateRemoteThread, PPID spoofing, tampering/hollowing
│   ├── ad_attacks/                  # AD CS certificate SAN attribute abuse
│   └── lateral_movement/            # Type 3 network logon building block
├── aegis/                           # Core Python application package
│   ├── cli.py                       # Click CLI command groups
│   ├── config.py                    # Dataclass configuration management
│   ├── session_logger.py            # Operational JSONL and plaintext session logging
│   ├── correlate/                   # Alert correlation pipeline
│   │   ├── schema.py                # Alert, Entity, LinkEvidence, Incident models
│   │   ├── entity_resolution.py     # GUID/LogonID composite keys, UPN normalization
│   │   ├── linker.py                # Causal evidence linker (Lineage, Session, Lateral)
│   │   ├── windowing.py             # DisjointSet Union-Find & stress-tested clustering
│   │   ├── scoring.py               # Multi-factor risk scoring & blast radius
│   │   └── engine.py                # Correlation pipeline orchestrator
│   ├── pipelines/                   # pySigma Sysmon -> ECS pipeline & query compiler
│   │   ├── compile.py               # RuleCompiler (LuceneBackend + Native AST fallback)
│   │   └── sysmon_ecs.py            # Sysmon to ECS field mapping tables & pipeline
│   ├── graph/                       # Cytoscape.js attack graph & HTML report generator
│   │   ├── builder.py               # Incident graph networkx builder
│   │   └── renderer.py              # Standalone dark-theme HTML generator
│   ├── ingest/                      # SwiftOnSecurity Sysmon XML, Winlogbeat, Zeek configs
│   ├── playbooks/                   # Actionable YAML response playbooks
│   │   ├── runner.py                # Safe PlaybookRunner (Dry-Run, Guardrails, Rollback)
│   │   ├── ad_compromise.yml        # Active Directory containment playbook
│   │   ├── credential_theft.yml     # LSASS & Kerberos ticket containment playbook
│   │   ├── lateral_movement.yml     # Host isolation & network containment playbook
│   │   └── malware_execution.yml    # Process termination & memory capture playbook
│   └── eval/                        # Coverage matrix, noise reduction, FP & TTT analyzers
├── tests/                           # Complete test suite & telemetry fixtures
│   ├── fixtures/                    # Telemetry fixtures
│   │   ├── malicious/               # Attack chain EVTX-simulated fixtures
│   │   ├── benign/                  # Administrative baseline logs
│   │   ├── public_datasets/         # Public OTRF Security Datasets attack sample
│   │   └── rules/                   # 26 Positive and negative fixtures per rule
│   ├── test_rules.py                # Rule metadata, UUID, and ATT&CK tag validation
│   ├── test_rule_fixtures.py        # Positive/negative fixture verification per rule
│   ├── test_public_dataset.py       # End-to-end detection on public OTRF dataset
│   ├── test_entity_resolution.py    # Entity de-duplication tests
│   ├── test_linker.py               # Semantic edge linking & evidence tests
│   ├── test_windowing.py            # Union-Find and gap timeout tests
│   ├── test_clustering_stress.py    # Stress tests (Duplicates, Out-of-order, Reboots, Delays)
│   ├── test_scoring.py              # Multi-factor scoring tests
│   ├── test_correlation_engine.py   # End-to-end integration tests
│   ├── test_graph.py                # Cytoscape JSON and HTML render tests
│   ├── test_resilience.py           # Evasion variant resilience tests
│   ├── test_compile.py              # Single and batch Sigma-to-Lucene compilation tests
│   ├── test_playbooks.py            # Playbook schema and mapping integrity tests
│   └── test_playbook_safety.py      # Playbook runner dry-run, approval & rollback tests
├── docs/                            # Comprehensive documentation & research writeups
│   ├── methodology.md               # Formal research question, architecture, limits
│   ├── interview_checklist.md       # Technical interview defense cheat sheet
│   ├── attack_navigator_layer.json  # Official MITRE ATT&CK Navigator v4.5 layer
│   ├── demo.md                      # Demonstration guide & walkthrough
│   └── session_log.md               # Chronological engineering session changelog
├── logs/                            # Operational logs (.gitkeep tracked)
├── reports/                         # Generated HTML attack graphs (.gitkeep tracked)
├── scripts/
│   └── demo.py                      # Runnable end-to-end console demonstration
├── run_tests.py                     # Unified test discovery runner
├── pyproject.toml                   # Modern packaging & Ruff/pytest/mypy configurations
├── config.yaml.example              # Sample configuration file
├── LICENSE                          # MIT License
└── README.md                        # Project documentation
```

---

## 🧪 Testing & Continuous Integration

AEGIS includes a zero-dependency test runner (`run_tests.py`) and full `pytest` integration covering 14 test modules:

```bash
# Run complete test suite with coverage report
python -m pytest --cov=aegis
```

```text
============================= test session starts ==============================
collected 48 items

tests/test_clustering_stress.py ....                                     [  8%]
tests/test_compile.py ..                                                 [ 12%]
tests/test_correlation_engine.py ..                                      [ 16%]
tests/test_entity_resolution.py ......                                   [ 29%]
tests/test_graph.py ...                                                  [ 35%]
tests/test_linker.py ...                                                 [ 41%]
tests/test_playbook_safety.py .....                                      [ 52%]
tests/test_playbooks.py ..                                               [ 56%]
tests/test_public_dataset.py .                                           [ 58%]
tests/test_resilience.py ....                                            [ 66%]
tests/test_rule_fixtures.py ...                                          [ 72%]
tests/test_rules.py ......                                               [ 85%]
tests/test_scoring.py ....                                               [ 93%]
tests/test_windowing.py ...                                              [100%]

================== 48 passed, 52 subtests passed in 0.77s ===================
Required test coverage of 40.0% reached. Total coverage: 60.20%
```

### Test Suite Breakdown
- **Rule Metadata & Syntax**: Validates all 13 rules for RFC 4122 UUIDs, valid ATT&CK tags, and syntax conformances (`test_rules.py`).
- **Rule Positive & Negative Fixtures**: 26 fixtures verifying True-Positive and False-Positive behavior per rule (`test_rule_fixtures.py`).
- **Public Dataset E2E Verification**: End-to-end execution on public OTRF Security Datasets (`test_public_dataset.py`).
- **Clustering Stress Resilience**: Validates telemetry deduplication, out-of-order streams, delayed movement, and reboot boundary partitioning (`test_clustering_stress.py`).
- **Entity Resolution & Collisions**: Tests multi-host Process GUID and Logon ID isolation (`test_entity_resolution.py`).
- **Causal Evidence & Edge Linking**: Verifies process lineage, session continuity, lateral movement, and contextual user activity isolation (`test_linker.py`).
- **Sliding-Window & Disjoint Sets**: Verifies cluster formation and inactivity timeout splits (`test_windowing.py`).
- **Risk Scoring & Criticality**: Validates multi-factor scoring against high-risk and low-risk baselines (`test_scoring.py`).
- **Adversary Resilience**: Validates evasion resistance against mask alterations, renamed LOLBins, and obfuscated cradles (`test_resilience.py`).
- **Playbook Schema & Safety Harness**: Tests YAML schema parsing, mapping resolution, dry-run defaults, senior approvals, DC protection, and automated rollback generation (`test_playbooks.py`, `test_playbook_safety.py`).
- **Rule Compilation**: Tests single-rule and batch AST compilation to Lucene / Elasticsearch queries (`test_compile.py`).

---

## 📜 Automated Operational Session Logging

AEGIS features an automated operational session logger designed to maintain engineering traceability:
- **Human-Readable Log**: Formatted shift entries at `logs/aegis_session.log`.
- **Machine-Readable Audit Trail**: Structured event stream at `logs/aegis_session.jsonl`.
- **Engineering Documentation**: Chronological architecture decisions recorded in [docs/session_log.md](docs/session_log.md).

Every CLI invocation, rule compilation, correlation run, and manual analyst note is captured with UTC timestamps, execution durations, command parameters, and operating user context.

---

## 🛡️ Adversary Evasion Defense & Documented Limitations

A core requirement of defensible detection engineering is transparently acknowledging sensor limits:

| Evasion Technique | Attacker Vector | AEGIS Defensive Countermeasure | Architectural Blind Spot / Future Work |
| :--- | :--- | :--- | :--- |
| **PPID Spoofing** | Setting `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` to masquerade as `explorer.exe` | Flags heuristic parent/child temporal anomalies (parent start time *later* than child) and anomalous parent-child execution pairings | Timestamp checks are an incomplete heuristic: spoofing an existing long-running process (e.g. `explorer.exe` started at user logon) evades timestamp checks. Resilient attribution requires Kernel ETW (`Microsoft-Windows-Kernel-Process`) or `PsSetCreateProcessNotifyRoutineEx`. |
| **Direct Syscalls** | Bypassing user-mode NTDLL hooks to dump LSASS memory directly | Sysmon Event ID 10 relies on kernel `ObRegisterCallbacks` to observe handle acquisition (`0x1010`, `0x1410`, `0x1FFFFF`) regardless of userland hook bypass | Event ID 10 records handle access, *not* kernel callback table integrity. If an adversary uses a Bring-Your-Own-Vulnerable-Driver (BYOVD) attack to unhook or zero kernel callback pointers, Sysmon is blinded. Requires Driver Blocklist / HVCI and ETW-TI. |
| **LOLBin Renaming** | Renaming `certutil.exe` to `update.exe` to bypass filename filters | Focuses on command-line argument flags (`-urlcache`, `-split`, `-decode`) and network connection telemetry (Sysmon ID 3) | If an adversary writes a custom HTTP downloader without using built-in LOLBins, endpoint file download rules will not trigger. |
| **Kerberoasting RC4 Bypass** | Requesting AES-256 tickets (`0x12`) instead of RC4 (`0x17`) | Threshold volume detection on Event ID 4769 for non-machine SPNs | High-volume single-user AES requests can be masked among normal SSO traffic; requires volume baseline tuning. |

---

## 📄 License & Citation

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

### Citation
If you use AEGIS in detection engineering research or educational curriculum, please cite:
```bibtex
@software{aegis2026,
  author = {AEGIS Engineering Team},
  title = {AEGIS: Automated Event Graph & Incident Synthesis for Detection Engineering},
  year = {2026},
  url = {https://github.com/Akki-74/AEGIS}
}
```
