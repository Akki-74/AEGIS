# AEGIS Demonstration Guide

This guide walks through the live demonstration of the AEGIS detection engineering and incident correlation pipeline.

---

## 1. Quick Demo Execution (One Command)

To run the automated console demonstration:

```bash
python scripts/demo.py
```

### What Happens in the Demo:
1. **The Raw Alert Flood:** Simulates the reality of modern SOC alert queues—20 disparate, un-correlated alerts firing across 3 endpoints (`WORKSTATION01`, `SERVER01`, `DC01`) spanning multiple users and event IDs.
2. **Automated Graph Correlation:** Demonstrates entity resolution (composite Process GUIDs, host-prefixed Logon IDs, UPN normalization), semantic linking, and temporal sliding-window clustering in milliseconds.
3. **Noise Reduction:** Automatically compresses the 20 raw alerts into **4 ranked incidents** (an **80.0% noise reduction** / 5:1 alert compression).
4. **Blast Radius & Playbook Mapping:** Identifies affected hosts, accounts, privilege level reached, and links response playbooks (e.g. `credential_theft.yml`).
5. **Interactive Attack Graph:** Emits a self-contained, browser-ready Cytoscape.js HTML report at `reports/demo_attack_graph.html`.

---

## 2. Interactive Browser Graph Walkthrough

After running the demo, open the report in your browser:

```bash
# Windows
start reports/demo_attack_graph.html

# macOS
open reports/demo_attack_graph.html

# Linux
xdg-open reports/demo_attack_graph.html
```

### Key Elements to Highlight in Interviews / Demos:
- **Node Color-Coding:**
  - Blue (`#4A90D9`): Host endpoints
  - Orange (`#E67E22`): User identities
  - Green (`#27AE60`): Processes
  - Purple (`#8E44AD`): IP & network destinations
  - Amber (`#F39C12`): Logon sessions
- **Edge Color-Coding by Severity:**
  - Red: Critical detections (e.g. LSASS handle `0x1010` dumping)
  - Orange: High detections (e.g. Process Injection, Kerberoasting)
  - Yellow: Medium detections (e.g. LOLBin execution)
- **Chronological Sidebar Timeline:** Displays the exact causal progression:
  1. `mshta.exe` execution from external URL (`WORKSTATION01`)
  2. PowerShell download cradle execution
  3. Mimikatz LSASS process handle creation
  4. Outbound SMB connection to `SERVER01`
  5. PsExec service creation and lateral execution
