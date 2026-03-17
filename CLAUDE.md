# CLAUDE.md — MultiCloud Security Audit Tool

## Project Overview

A ScoutSuite-inspired, Python-native multi-cloud security auditing tool (v3.0.0).
Connects to live AWS, Azure, and GCP accounts, evaluates configurations against
JSON rule files, and produces interactive HTML reports with posture scoring,
compliance mapping, remediation playbooks, SARIF/JUnit output, and CI/CD integration.

**Entry point:** `scout.py`
**Version:** 3.0.0
**Primary branch:** `main`

---

## Repository Structure

```
MultiCloud-Security-Audit-Tool/
├── scout.py                        # CLI entrypoint (argparse subcommands)
├── requirements.txt
├── exceptions.yaml.template        # Suppressions file template
├── .github/workflows/
│   └── scout-scan.yml              # GitHub Actions CI/CD (AWS + Azure + GCP)
├── core/
│   ├── finding.py                  # Finding @dataclass + SEVERITY_ORDER/COLOUR
│   ├── conditions.py               # pass_conditions() — 30+ operators
│   ├── rule.py                     # RuleDefinition (JSON loader) + Rule (resolved)
│   ├── ruleset.py                  # Ruleset — loads ruleset JSON, instantiates Rules
│   ├── engine.py                   # ProcessingEngine — walks data dict, flags items
│   ├── scoring.py                  # compute_score() — 0-100 posture score + A-F grade
│   ├── compliance.py               # aggregate_compliance() — per-framework counts
│   └── exceptions.py               # load_exceptions(), apply_exceptions()
├── output/
│   ├── encoder.py                  # ScoutJsonEncoder + save_json()
│   ├── report.py                   # save_html() — self-contained HTML report
│   ├── sarif.py                    # save_sarif() — SARIF 2.1.0 writer
│   ├── junit.py                    # save_junit() — JUnit XML writer
│   └── remediation.py              # get_remediation_commands(), save_remediation_script()
└── providers/
    ├── base/
    │   ├── provider.py             # BaseProvider (ABC)
    │   ├── service.py              # BaseService (ABC)
    │   └── resources.py            # Resources (dict ABC) + CompositeResources
    ├── aws/                        # 16 services · 37 rules
    │   ├── facade.py               # AWSFacade — lazy boto3 clients, paginate/call helpers
    │   ├── provider.py             # AWSProvider — _SERVICE_FETCHERS, fetch_sync()
    │   ├── services/               # iam, s3, ec2, vpc, rds, kms, cloudtrail, guardduty,
    │   │                           # config, sns, sqs, lambda_, eks, ecr,
    │   │                           # secretsmanager, opensearch
    │   └── rules/                  # 37 JSON rule files + aws-cis-3.0-ruleset.json
    ├── azure/                      # 12 services · 33 rules
    │   ├── facade.py               # AzureFacade — DefaultAzureCredential/SP, graph helpers
    │   ├── provider.py             # AzureProvider — _SERVICE_FETCHERS, fetch_sync()
    │   ├── services/               # entra, storage, keyvault, compute, network, sql,
    │   │                           # monitor, security, appservice, aks,
    │   │                           # containerregistry, cosmosdb
    │   └── rules/                  # 33 JSON rule files + azure-cis-2.0-ruleset.json
    └── gcp/                        # 9 services · 28 rules
        ├── facade.py               # GCPFacade — ADC/SA key, discovery() builder
        ├── provider.py             # GCPProvider — _SERVICE_FETCHERS, fetch_sync()
        ├── services/               # iam, storage, compute, sql, logging, kms,
        │                           # gke, bigquery, functions
        └── rules/                  # 28 JSON rule files + gcp-cis-2.0-ruleset.json
```

---

## Core Engine (`core/`)

### `finding.py`
- `Finding` dataclass: `rule_id, name, description, severity, service, provider, resource_path, remediation, compliance, references, flagged_items`
- `SEVERITY_ORDER`: `CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3, INFO=4`
- `Finding.__lt__` enables `sorted(findings)` by severity

### `conditions.py`
- `pass_conditions(conditions, item)` — returns `True` if item **IS flagged**
- Supported operators (30+): null/empty, boolean, equality, string, list, dict, length, network, date, logic (`and`/`or`/`not`)
- Condition formats: `["field", "op"]`, `["field", "op", val]`, `["op", val]`, `["and", [...], [...]]`

### `rule.py`
- `RuleDefinition` — loads JSON rule file; `id, name, description, severity, service, path, conditions` required
- `Rule` — resolves `_ARG_N_` tokens and `_INCLUDE_(path)` includes

### `ruleset.py`
- `Ruleset(ruleset_path, rule_dirs)` — parses ruleset JSON, instantiates enabled `Rule` objects
- Ruleset JSON: `{"about": "...", "rules": {"rule-file.json": [{"enabled": true, "level": "danger"}]}}`

### `engine.py`
- `ProcessingEngine(ruleset).run(data, provider)` — returns sorted `List[Finding]`
- `_walk(current, remaining, item_id)` — generator; `"*"` expands dict values; supports nested paths

### `scoring.py`
- `compute_score(findings)` → `{score, grade, label, color, penalty, breakdown}`
- Penalties: CRITICAL=40, HIGH=15, MEDIUM=5, LOW=1, INFO=0; capped at MAX_PENALTY=300
- Grades: A(≥90), B(≥75), C(≥60), D(≥40), F(<40)

### `compliance.py`
- `aggregate_compliance(findings)` → dict keyed by canonical framework name
- Normalises: CIS Benchmarks, PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST CSF, AWS Well-Architected

### `exceptions.py`
- `Suppression` dataclass: `rule_id, resource, service, provider, reason, expires`
- `ExceptionSet.matches(finding)` — returns first non-expired matching `Suppression`
- `load_exceptions(path)` — parses `exceptions.yaml` via PyYAML
- `apply_exceptions(findings, exc_set)` → `(active_findings, [(finding, suppression), ...])`

---

## Output Layer (`output/`)

### `encoder.py`
- `ScoutJsonEncoder` — handles `datetime`, `set`, `Path`, objects with `to_dict()`
- Strips `_SENSITIVE_KEYS` from serialisation

### `report.py`
- `save_html(findings, path, meta, posture, compliance, suppressed)` — single-file self-contained HTML
- Dark GitHub theme (`#0d1117`); SVG posture gauge; compliance framework cards; service matrix table
- Collapsible "Fix Commands" panel per finding (CLI remediation commands)
- Suppressed findings section (greyed-out, with reason column)

### `sarif.py`
- `save_sarif(findings, path, tool_version, suppressed)` — SARIF 2.1.0
- Severity mapping: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`
- Suppressed findings marked with `suppressions[]` property

### `junit.py`
- `save_junit(findings, path)` — JUnit XML grouped by `provider.service` testsuites
- CRITICAL/HIGH → `<failure>` (CI gate fails); MEDIUM/LOW/INFO → `<skipped>`

### `remediation.py`
- `_CMDS` dict — 50+ `rule_id → {commands, note}` templates for AWS/Azure/GCP
- `get_remediation_commands(finding)` → `[{resource_id, commands, note}, ...]`
- `save_remediation_script(findings, path)` — `#!/usr/bin/env bash` script sorted by severity

---

## Provider Patterns

### AWS (`providers/aws/`)
- **Facade:** `AWSFacade(region, profile)` — lazy boto3 clients; `paginate(service, op, key, **kwargs)` and `call(service, op, **kwargs)` helpers
- **Fetcher signature:** `fetch_<service>(facade) -> Dict[str, Any]`
- **Data shape:** `{"resource_type": {"<name>": {...flags...}}}`
- **Rule IDs:** `IAM-XX`, `S3-XX`, `EC2-XX`, `RDS-XX`, `CT-XX`, `KMS-XX`, `GD-XX`, `VPC-XX`, `LAMBDA-XX`, `EKS-XX`, `ECR-XX`, `SM-XX`, `OS-XX`

### Azure (`providers/azure/`)
- **Facade:** `AzureFacade(subscription_id, tenant_id, client_id, client_secret)` — `DefaultAzureCredential` or SP; `graph_get()` / `graph_paginate()` for Microsoft Graph
- **Fetcher pattern:** import Azure SDK client inside fetcher, instantiate with `facade.credential` + `facade.subscription_id`
- **Rule IDs:** `AKS-XX`, `ACR-XX`, `COSMOS-XX`, `STOR-XX`, `KV-XX`, `SQL-XX`, `NET-XX`, `SEC-XX`, `MON-XX`, etc.

### GCP (`providers/gcp/`)
- **Facade:** `GCPFacade(project_id, service_account_file)` — ADC or SA key; `discovery(api, version)` returns a Discovery API service object
- **Fetcher pattern:** `svc = facade.discovery("compute", "v1")` then `svc.resource().list(project=facade.project_id).execute()`; paginate with `list_next(req, resp)`
- **All GCP services use Discovery API** (not native SDK clients) to avoid protobuf attribute issues
- **Rule IDs:** `GKE-XX`, `BQ-XX`, `FUNC-XX`, `IAM-XX`, `GCS-XX`, `NET-XX`, `INST-XX`, `SQL-XX`, `LOG-XX`, `KMS-XX`

---

## CLI (`scout.py`)

```
python scout.py demo   [--html] [--json] [--sarif] [--junit] [--remediation-script] [--exceptions] [-v]
python scout.py aws    [--region] [--profile] [--sections] [--ruleset] [--html] [--json] [--sarif] [--junit] [--remediation-script] [--exceptions] [-v]
python scout.py azure  [--subscription-id] [--tenant-id] [--client-id] [--client-secret] [--html] [--json] [--sarif] [--junit] [--remediation-script] [--exceptions] [-v]
python scout.py gcp    [--project] [--service-account-file] [--html] [--json] [--sarif] [--junit] [--remediation-script] [--exceptions] [-v]
```

Exit codes: `0` = no CRITICAL/HIGH · `1` = CRITICAL or HIGH findings present · `2` = setup/auth error

---

## Adding a New Rule

1. Create `providers/<cloud>/rules/<rule-id-lowercase>.json` with required fields: `id, name, description, severity, service, path, conditions, remediation, compliance, references`
2. Add entry to `providers/<cloud>/rules/<cloud>-cis-X.Y-ruleset.json` → `"rules"` dict
3. Add remediation CLI template to `output/remediation.py` → `_CMDS[<RULE_ID>]`

## Adding a New Service Fetcher

1. Create `providers/<cloud>/services/<service>.py` with `fetch_<service>(facade) -> Dict`
2. Import and add to `_SERVICE_FETCHERS` in `providers/<cloud>/provider.py`
3. Create rule JSON files for the new service
4. Update the ruleset JSON

---

## Phases

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | Core engine + base classes + HTML report + demo mode | Complete |
| 2 | AWS live provider — 16 services, 37 rules (CIS AWS Foundations v3.0) | Complete |
| 3 | Azure live provider — 12 services, 33 rules (CIS Azure Foundations v2.0) | Complete |
| 4 | GCP live provider — 9 services, 28 rules (CIS GCP Foundations v2.0) | Complete |
| 5 | Posture score, compliance scorecard, enhanced HTML report | Complete |
| 6 | Expanded rule coverage — Lambda, EKS, ECR, SM, OpenSearch, AKS, ACR, Cosmos DB, GKE, BigQuery, Cloud Functions | Complete |
| 7 | Remediation playbooks, exception management, SARIF 2.1.0, JUnit XML, GitHub Actions CI/CD | Complete |

---

## Conventions

- All provider fetchers are **read-only** — never modify cloud resources
- `pass_conditions()` returns `True` = **item IS flagged** (keep consistent)
- GCP uses **Discovery API exclusively** — do not use native GCP SDK clients
- `_count_resources()` in GCP provider skips `bool` scalar flags to avoid overcounting
- Exception suppression is **auditable** — suppressed findings appear greyed-out in HTML report, not hidden
- SARIF severity: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW/INFO → `note`
