<p align="center">
  <img src="docs/banner.svg" alt="MultiCloud Security Audit Tool" width="900"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/AWS-Phase%202-ff9900?style=flat-square&logo=amazonaws&logoColor=white"/>
  <img src="https://img.shields.io/badge/Azure-Phase%203-0078d4?style=flat-square&logo=microsoftazure&logoColor=white"/>
  <img src="https://img.shields.io/badge/GCP-Phase%204-34a853?style=flat-square&logo=googlecloud&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square"/>
</p>

---

## Overview

A ScoutSuite-inspired, Python-native multi-cloud security auditing tool.
Connects to live cloud accounts via provider SDKs, evaluates configurations
against a library of JSON rule files, and generates an interactive HTML report.

| Provider | Status | Checks |
|----------|--------|--------|
| **AWS**   | Phase 2 — in development | 57 (IAM, S3, EC2, RDS, CloudTrail, KMS, GuardDuty, VPC, …) |
| **Azure** | Phase 3 — planned        | ~50 (Entra ID, Storage, Compute, KeyVault, Monitor, …) |
| **GCP**   | Phase 4 — planned        | ~40 (IAM, GCS, Compute, CloudLogging, KMS, …) |

**Phase 1** (this release) delivers the complete core engine, base provider
classes, output layer, and a demo mode — runnable today without any cloud
credentials.

---

## Quick Start

```bash
git clone https://github.com/Krishcalin/MultiCloud-Security-Audit-Tool.git
cd MultiCloud-Security-Audit-Tool

# Phase 1 — Demo report (no credentials needed)
python scout.py demo --html report.html

# Phase 2 — AWS audit (coming soon)
python scout.py aws --region us-east-1 --html aws_report.html

# Phase 3 — Azure audit (coming soon)
python scout.py azure --subscription-id <SUB_ID> --html azure_report.html

# Phase 4 — GCP audit (coming soon)
python scout.py gcp --project <PROJECT_ID> --html gcp_report.html
```

---

## Architecture

```
MultiCloud-Security-Audit-Tool/
├── scout.py                        # CLI entrypoint
├── core/
│   ├── finding.py                  # Finding dataclass
│   ├── conditions.py               # 30+ condition operators
│   ├── rule.py                     # RuleDefinition + Rule
│   ├── ruleset.py                  # Ruleset loader
│   └── engine.py                   # ProcessingEngine
├── output/
│   ├── encoder.py                  # JSON serialisation
│   └── report.py                   # HTML report generator
└── providers/
    ├── base/                       # Abstract base classes
    │   ├── provider.py
    │   ├── service.py
    │   └── resources.py
    ├── aws/                        # Phase 2
    ├── azure/                      # Phase 3
    └── gcp/                        # Phase 4
```

### How it works

```
CLI (scout.py)
  └── Provider.fetch()           — calls cloud APIs, builds data dict
        └── ProcessingEngine.run()
              └── For each Rule in Ruleset:
                    walk data[rule.path]
                      evaluate pass_conditions(rule.conditions, item)
                        → Finding (rule_id, severity, service, flagged_items)
  └── save_html() / save_json()  — render report
```

---

## Rule Format

Each security check is a single JSON file:

```json
{
    "id":          "IAM-01",
    "name":        "Root account MFA not enabled",
    "description": "The root account does not have MFA enabled.",
    "severity":    "CRITICAL",
    "service":     "iam",
    "path":        "iam.account_summary",
    "conditions":  ["equal", "AccountMFAEnabled", 0],
    "remediation": "Enable MFA on the root account in the IAM console.",
    "compliance":  [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "1.5"}],
    "references":  ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"]
}
```

**Path wildcards** — `"iam.users.*"` iterates all users; `"ec2.regions.*.vpcs.*"` nests.

**Parameterisation** — `_ARG_0_`, `_ARG_1_` tokens let one rule cover multiple checks
(e.g. the same port-exposure rule instantiated once per port).

---

## Condition Operators

| Category | Operators |
|----------|-----------|
| Null/empty | `null`, `notNull`, `empty`, `notEmpty` |
| Boolean | `true`, `false` |
| Equality | `equal`, `notEqual`, `greaterThan`, `lessThan`, `greaterThanOrEqual`, `lessThanOrEqual` |
| String | `containString`, `notContainString`, `startsWith`, `endsWith`, `match`, `notMatch` |
| List | `containAtLeastOneOf`, `containNoneOf`, `containAtLeastOneMatching` |
| Dict | `withKey`, `withoutKey`, `withKeyCaseInsensitive` |
| Length | `lengthEqual`, `lengthLessThan`, `lengthMoreThan` |
| Network | `inSubnets`, `notInSubnets`, `isPublicCidr` |
| Date | `olderThanDays`, `newerThanDays` |
| Logic | `and`, `or`, `not` (recursive) |

---

## CLI Reference

```
usage: scout.py [-h] [--version] PROVIDER ...

  demo    Generate a sample report (no credentials needed)
  aws     Audit a live AWS account  [Phase 2]
  azure   Audit an Azure subscription [Phase 3]
  gcp     Audit a GCP project [Phase 4]

demo options:
  --html FILE       Write HTML report to FILE (default: multicloud_report.html)
  --json FILE       Write JSON findings to FILE
  -v, --verbose

aws options:
  --region REGION   AWS region (default: eu-west-1)
  --profile PROFILE Named AWS profile
  --sections ...    Run specific sections only
  --ruleset FILE    Custom ruleset JSON
  --html / --json / -v

azure options:
  --subscription-id --tenant-id --client-id --client-secret
  --html / --json / -v

gcp options:
  --project PROJECT_ID
  --service-account-file FILE
  --html / --json / -v
```

Exit codes: `0` = no CRITICAL/HIGH findings, `1` = CRITICAL or HIGH present.

---

## Requirements

| Phase | Requirements |
|-------|-------------|
| Phase 1 (demo) | Python 3.10+ — stdlib only |
| Phase 2 (AWS) | + `boto3>=1.34` |
| Phase 3 (Azure) | + `azure-identity`, `azure-mgmt-*`, `msgraph-sdk` |
| Phase 4 (GCP) | + `google-auth`, `google-cloud-*` |

```bash
pip install -r requirements.txt
```

---

## Disclaimer

For **authorised security assessments only**. The tool makes read-only API
calls and never modifies cloud resources. Always ensure you have explicit
authorisation before scanning.

---

## License

MIT License
