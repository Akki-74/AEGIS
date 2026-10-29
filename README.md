# AEGIS — Detection Engineering & Automated Incident Correlation

[![CI](https://github.com/your-org/aegis/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/aegis/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**AEGIS** (Automated Event Graph & Incident Synthesis) is a detection engineering
platform that compiles Sigma rules into production queries, correlates security
alerts into attack chains, and evaluates detection coverage against MITRE ATT&CK.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          AEGIS Platform                              │
├──────────────┬───────────────┬──────────────────┬────────────────────┤
│  Rule Engine │  Correlation  │   Attack Graph    │   Eval / Metrics  │
│              │    Engine     │     Builder       │                   │
│ ┌──────────┐ │ ┌───────────┐ │ ┌──────────────┐  │ ┌──────────────┐ │
│ │  Sigma   │ │ │ Sliding   │ │ │  NetworkX    │  │ │ ATT&CK       │ │
│ │  Rules   │ │ │ Window    │ │ │  DAG /       │  │ │ Coverage     │ │
│ │  (.yml)  │ │ │ Correlator│ │ │  Kill-Chain   │  │ │ Matrix       │ │
│ └────┬─────┘ │ └─────┬─────┘ │ └──────┬───────┘  │ └──────┬───────┘ │
│      │       │       │       │        │          │        │         │
│ ┌────▼─────┐ │ ┌─────▼─────┐ │ ┌──────▼───────┐  │ ┌──────▼───────┐ │
│ │ pySigma  │ │ │ Scoring & │ │ │  Graph       │  │ │ Noise        │ │
│ │ Compile  │ │ │ Weighting │ │ │  Rendering   │  │ │ Reduction    │ │
│ │ Pipeline │ │ │ Engine    │ │ │  & Export    │  │ │ Metrics      │ │
│ └────┬─────┘ │ └─────┬─────┘ │ └──────┬───────┘  │ └──────────────┘ │
│      │       │       │       │        │          │                   │
│      ▼       │       ▼       │        ▼          │                   │
│  ES/OS       │  Correlated   │   Attack          │                   │
│  Queries     │  Incidents    │   Graph JSON      │                   │
├──────────────┴───────────────┴──────────────────┴────────────────────┤
│                         CLI  (click)                                 │
│  aegis rules compile | test | validate                               │
│  aegis correlate run                                                 │
│  aegis graph build                                                   │
│  aegis eval coverage | noise                                         │
└──────────────────────────────────────────────────────────────────────┘
         │                  │                    │
         ▼                  ▼                    ▼
   Elasticsearch      YAML Config           JSON Reports
   / OpenSearch        (config.yaml)
```

## Quick Start

### Prerequisites

- Python 3.11 or later
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/aegis.git
cd aegis

# Create a virtual environment
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Copy and edit the config
cp config.yaml.example config.yaml
```

### First Run

```bash
# Validate all Sigma rules
aegis rules validate --rules-dir sigma_rules/

# Compile Sigma rules to Elasticsearch queries
aegis rules compile --rules-dir sigma_rules/ --backend elasticsearch

# Run correlation engine against an alerts export
aegis correlate run --input tests/fixtures/malicious/full_attack_chain.json

# Build an interactive HTML attack graph
aegis graph build --input reports/incidents.json --output reports/attack_graph.html

# Generate ATT&CK coverage matrix and Navigator v4.5 layer
aegis eval coverage --rules-dir rules/ --output docs/attack_navigator_layer.json

# Calculate noise reduction metrics
aegis eval noise --before tests/fixtures/malicious/full_attack_chain.json --after reports/incidents.json

# Log operational notes and view session history
aegis session log "Completed detection tuning on Kerberoasting rule"
aegis session history
```

## Repository Layout

```
AEGIS/
├── aegis/                      # Core AEGIS Python package
│   ├── __init__.py             # Package init & version
│   ├── cli.py                  # Click CLI with rules, correlate, graph, eval, session
│   ├── config.py               # Dataclass-based configuration management
│   ├── session_logger.py       # Operational JSONL and plaintext session logging
│   ├── correlate/              # Entity resolution, linking, windowing, scoring, engine
│   │   ├── schema.py           # Alert, Entity, Incident data models
│   │   ├── entity_resolution.py# GUID & Logon ID composite keys, UPN normalization
│   │   ├── linker.py           # Semantic linking (Lineage, Session, Lateral Movement)
│   │   ├── windowing.py        # DisjointSet Union-Find & temporal gap clustering
│   │   ├── scoring.py          # Multi-factor risk scoring & blast radius
│   │   └── engine.py           # Correlation pipeline orchestrator & exporter
│   ├── pipelines/              # pySigma Sysmon -> ECS pipeline & query compiler
│   ├── graph/                  # Cytoscape.js attack graph & HTML report generator
│   │   └── templates/          # Jinja2 responsive dark-theme HTML template
│   ├── ingest/                 # SwiftOnSecurity Sysmon XML, Winlogbeat, & Zeek Beats
│   ├── playbooks/              # Response playbooks (credential_theft, lateral_movement, etc.)
│   └── eval/                   # ATT&CK coverage, noise reduction, & FP analyzer
├── docs/                       # Architecture, methodology, Navigator layer, session log
│   ├── methodology.md          # Research question, architecture, limits, evaluation
│   ├── interview_checklist.md  # Sysmon IDs, GUID stitching, interview answers
│   ├── attack_navigator_layer.json # MITRE ATT&CK Navigator v4.5 layer
│   └── session_log.md          # Chronological engineering session & decision log
├── logs/                       # Persistent session logs (aegis_session.log & .jsonl)
├── rules/                      # 13 Production Sigma rules across 5 MITRE tactics
├── tests/                      # Fixtures (malicious & benign) and unit/integration tests
├── run_tests.py                # Unified test runner (pytest & standard library unittest)
└── .github/workflows/ci.yml    # GitHub Actions CI workflow
```
│       ├── coverage.py         # ATT&CK coverage matrix
│       └── noise.py            # Noise reduction metrics
├── sigma_rules/                # Sigma detection rules (.yml)
│   ├── windows/
│   ├── linux/
│   └── cloud/
├── tests/                      # Test suite
│   ├── conftest.py
│   ├── test_rules/
│   ├── test_correlation/
│   ├── test_graph/
│   └── test_evaluation/
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI pipeline
├── config.yaml.example         # Example configuration file
├── pyproject.toml              # Project metadata & build config
├── .gitignore
└── README.md                   # This file
```

## Dependencies

| Package | Purpose |
|---|---|
| [pySigma](https://github.com/SigmaHQ/pySigma) | Core Sigma rule processing engine |
| [pysigma-backend-elasticsearch](https://github.com/SigmaHQ/pySigma-backend-elasticsearch) | Compile rules to ES/OpenSearch queries |
| [pysigma-pipeline-sysmon](https://github.com/SigmaHQ/pySigma-pipeline-sysmon) | Sysmon log field mappings |
| [pysigma-pipeline-ecs-windows](https://github.com/SigmaHQ/pySigma-pipeline-windows) | ECS Windows field mappings |
| [pandas](https://pandas.pydata.org/) | Alert data manipulation & analysis |
| [networkx](https://networkx.org/) | Attack graph construction & analysis |
| [click](https://click.palletsprojects.com/) | CLI framework |
| [PyYAML](https://pyyaml.org/) | YAML config & rule parsing |
| [Jinja2](https://jinja.palletsprojects.com/) | Report template rendering |
| [rich](https://rich.readthedocs.io/) | Terminal output formatting |

### Dev Dependencies

| Package | Purpose |
|---|---|
| [pytest](https://pytest.org/) | Test framework |
| [pytest-cov](https://pytest-cov.readthedocs.io/) | Coverage reporting |
| [ruff](https://docs.astral.sh/ruff/) | Fast Python linter & formatter |
| [mypy](https://mypy-lang.org/) | Static type checking |

## Running Tests

```bash
# Run the full test suite with coverage
pytest --cov=aegis --cov-report=term-missing

# Run a specific test module
pytest tests/test_rules/ -v

# Lint with ruff
ruff check aegis/ tests/

# Type-check with mypy
mypy aegis/
```

## Adding New Rules

1. Create a new `.yml` file under `sigma_rules/<platform>/`.
2. Ensure the rule includes the required metadata fields:
   - `title`, `id` (UUIDv4), `status`, `level`, `description`
   - `author`, `date`, `modified`
   - `logsource` with `category`, `product`
   - `detection` with at least one `selection` and a `condition`
   - `tags` containing MITRE ATT&CK technique IDs (e.g., `attack.t1059.001`)
3. Validate the rule: `aegis rules validate --rules-dir sigma_rules/`
4. Compile and test: `aegis rules compile --rules-dir sigma_rules/`

## License

MIT — see [LICENSE](LICENSE) for details.
