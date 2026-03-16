# CLAUDE.md — MultiCloud Security Audit Tool

## Project Overview

A ScoutSuite-inspired, Python-native multi-cloud security auditing tool.
Collects configuration data from live cloud accounts (AWS, Azure, GCP) via
provider SDKs, evaluates it against a library of JSON rule files, and
produces an interactive HTML report.

**Entry point:** `scout.py`
**Primary branch:** `main`

## Repository Structure

```
MultiCloud-Security-Audit-Tool/
├── scout.py                        # CLI entrypoint (argparse subcommands)
├── requirements.txt
├── core/
│   ├── finding.py                  # Finding @dataclass + SEVERITY_ORDER/COLOUR
│   ├── conditions.py               # pass_conditions() — 30+ operators
│   ├── rule.py                     # RuleDefinition (JSON loader) + Rule (resolved)
│   ├── ruleset.py                  # Ruleset — loads ruleset JSON, instantiates Rules
│   └── engine.py                   # ProcessingEngine — walks data dict, flags items
├── output/
│   ├── encoder.py                  # ScoutJsonEncoder + save_json() / encode_findings()
│   └── report.py                   # save_html() — self-contained HTML report
└── providers/
    ├── base/
    │   ├── provider.py             # BaseProvider (ABC)
    │   ├── service.py              # BaseService (ABC)
    │   └── resources.py            # Resources (dict ABC) + CompositeResources
    ├── aws/                        # Phase 2 — AWS provider (boto3)
    ├── azure/                      # Phase 3 — Azure provider (azure-sdk)
    └── gcp/                        # Phase 4 — GCP provider (google-cloud-*)
```

## Core Engine (`core/`)

### `finding.py`
- `Finding` dataclass: `rule_id, name, description, severity, service, provider, resource_path, remediation, compliance, references, flagged_items`
- `SEVERITY_ORDER`: `CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3, INFO=4`
- `Finding.__lt__` enables `sorted(findings)` by severity

### `conditions.py`
- `get_field(item, path)` — resolves dot-notation path within a dict
- `pass_conditions(conditions, item)` — returns `True` if item **IS flagged**
- `_evaluate(op, value, expected)` — single operator evaluation
- Supported operators (30+):
  - Null/empty: `null`, `notNull`, `empty`, `notEmpty`
  - Boolean: `true`, `false`
  - Equality: `equal`, `notEqual`, `greaterThan`, `lessThan`, `greaterThanOrEqual`, `lessThanOrEqual`
  - String: `containString`, `notContainString`, `startsWith`, `endsWith`, `match`, `notMatch`
  - List: `containAtLeastOneOf`, `containNoneOf`, `containAtLeastOneMatching`
  - Dict: `withKey`, `withoutKey`, `withKeyCaseInsensitive`
  - Length: `lengthEqual`, `lengthLessThan`, `lengthMoreThan`
  - Network: `inSubnets`, `notInSubnets`, `isPublicCidr`
  - Date: `olderThanDays`, `newerThanDays`
  - Logic: `and`, `or`, `not` (recursive)

**Condition formats:**
```json
["field.path", "operator"]                   // unary
["field.path", "operator", expected]         // binary
["operator", expected]                       // item-self binary
["and", ["field", "op", val], ["field2", "op2"]]   // logic
```

### `rule.py`
- `RuleDefinition` — loads a JSON rule file; sets all keys as attributes via `setattr()`
- `Rule` — resolves `_ARG_N_` tokens and `_INCLUDE_(path)` includes at construction
- Required rule file fields: `id, name, description, severity, service, path, conditions`

### `ruleset.py`
- `Ruleset(ruleset_path, rule_dirs)` — parses ruleset JSON, instantiates enabled `Rule` objects
- Ruleset JSON format:
```json
{
  "about": "Default ruleset",
  "rules": {
    "iam-root-mfa.json": [{"enabled": true, "level": "danger"}],
    "ec2-sg-port-open.json": [
      {"args": ["SSH", "22"], "enabled": true},
      {"args": ["RDP", "3389"], "enabled": true}
    ]
  }
}
```

### `engine.py`
- `ProcessingEngine(ruleset).run(data, provider)` — returns sorted `List[Finding]`
- `_walk(current, remaining, item_id)` — generator; `"*"` expands to all dict values
- `_evaluate_rule(rule, data, provider)` — collects flagged items, builds one `Finding`

## Output Layer (`output/`)

### `encoder.py`
- `ScoutJsonEncoder` — handles `datetime`, `set`, `Path`, objects with `to_dict()`
- Strips `_SENSITIVE_KEYS` (password, secret, token, etc.) from serialisation
- `save_json(findings, path)` — writes JSON array to file

### `report.py`
- `save_html(findings, path, meta)` — single-file self-contained HTML (no CDN)
- Dark GitHub theme (`#0d1117` background)
- Summary tiles → provider cards → filterable findings table → expandable detail rows
- Inline JS: search, severity/provider/service filtering, expand/collapse

## Provider Base Classes (`providers/base/`)

### `provider.py` — `BaseProvider(ABC)`
- `PROVIDER: str` — class attribute (`"aws"`, `"azure"`, `"gcp"`)
- Abstract: `fetch(services)`, `get_services()`
- `get_data()` → `self._data`

### `service.py` — `BaseService(ABC)`
- `SERVICE_NAME: str` — class attribute
- Abstract: `fetch_all()`
- `get_data()` → `self._resources`

### `resources.py`
- `Resources(dict, ABC)` — abstract dict; implement `fetch_all()`; `KEY` class attr = storage key
- `CompositeResources(Resources, ABC)` — declares `_children: List[Type[Resources]]`
  - `fetch_all()` → `_fetch_all_items()` then `_fetch_children_of_all_resources()` (asyncio.gather)
  - Children stored under `resource_config[child.KEY]` with `resource_config[f"{child.KEY}_count"]`

## CLI (`scout.py`)

```
python scout.py demo   [--html FILE] [--json FILE] [-v]
python scout.py aws    [--region] [--profile] [--sections] [--ruleset] [--html] [--json] [-v]
python scout.py azure  [--subscription-id] [--tenant-id] [--client-id] [--client-secret] [--html] [--json]
python scout.py gcp    [--project] [--service-account-file] [--html] [--json]
```

Exit codes: `0` = clean / no HIGH+CRITICAL, `1` = CRITICAL or HIGH findings present.

## Provider Rule File Convention

```
providers/<name>/rules/
  findings/          # one JSON file per check
  rulesets/
    default.json     # all checks enabled
    cis-X.Y.json     # CIS Benchmark subset
  conditions/        # shared condition snippets (_INCLUDE_ targets)
```

Rule ID format per provider:
- AWS: `IAM-XX`, `S3-XX`, `EC2-XX`, `RDS-XX`, `CT-XX`, `KMS-XX`, `GD-XX`, `VPC-XX`, etc.
- Azure: `AZ-IAM-XX`, `AZ-STOR-XX`, `AZ-NET-XX`, etc.
- GCP: `GCP-IAM-XX`, `GCP-GCS-XX`, `GCP-COMPUTE-XX`, etc.

## Phases

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | Core engine + base classes + HTML report + CLI demo | Complete |
| 2 | AWS provider (57 checks, boto3) | Pending |
| 3 | Azure provider (~50 checks) | Pending |
| 4 | GCP provider (~40 checks) | Pending |
| 5+ | K8s provider, async concurrency, exceptions file, CI integration | Pending |

## Conventions

- All scanners are read-only — never modify cloud resources
- `pass_conditions()` returns `True` = **item is flagged** (counter-intuitive — keep consistent)
- `asyncio` is used for concurrent API calls in provider resource fetchers
- Python 3.10+ (uses `str | Path` union syntax)
