#!/usr/bin/env python3
"""MultiCloud Security Audit Tool — CLI entrypoint.

Usage
-----
::

    # Demo report (sample findings, no cloud credentials needed)
    python scout.py demo --html report.html

    # AWS live audit  (Phase 2 — coming soon)
    python scout.py aws --region us-east-1 --html aws_report.html

    # Azure live audit (Phase 3 — coming soon)
    python scout.py azure --subscription-id <SUB_ID> --html azure_report.html

    # GCP live audit   (Phase 4 — coming soon)
    python scout.py gcp --project <PROJECT_ID> --html gcp_report.html

Phase 1 delivers the core engine, base classes, and the ``demo`` subcommand.
Provider subcommands (aws / azure / gcp) are enabled in later phases.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

__version__ = "2.0.0"

# ---------------------------------------------------------------------------
# Demo data — exercises every engine feature and all severity levels
# ---------------------------------------------------------------------------

_DEMO_RULES_DIR   = Path(__file__).parent / "providers" / "demo" / "rules" / "findings"
_DEMO_RULESET_DIR = Path(__file__).parent / "providers" / "demo" / "rules" / "rulesets"

_DEMO_DATA: Dict[str, Any] = {
    "iam": {
        "account_summary": {
            "AccountMFAEnabled": 0,
            "AccountAccessKeysPresent": 1,
        },
        "users": {
            "alice": {
                "name": "alice",
                "LoginProfile": {"CreateDate": "2023-01-10T08:00:00Z"},
                "MFADevices": [],
                "PasswordLastUsed": "2024-06-01T12:00:00Z",
                "AccessKeys": [
                    {"AccessKeyId": "AKIA1111", "Status": "Active", "CreateDate": "2022-03-01T00:00:00Z"}
                ],
            },
            "bob": {
                "name": "bob",
                "LoginProfile": None,
                "MFADevices": ["arn:aws:iam::123:mfa/bob"],
                "PasswordLastUsed": "2025-12-01T12:00:00Z",
                "AccessKeys": [],
            },
        },
        "policies": {
            "admin-wildcard": {
                "PolicyName": "AdminWildcard",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        },
        "password_policy": {
            "MinimumPasswordLength": 6,
            "RequireUppercaseCharacters": False,
            "RequireLowercaseCharacters": False,
            "RequireNumbers": False,
            "RequireSymbols": False,
            "MaxPasswordAge": 0,
        },
    },
    "s3": {
        "buckets": {
            "company-public-data": {
                "Name": "company-public-data",
                "PublicAccessBlock": {
                    "BlockPublicAcls":       False,
                    "BlockPublicPolicy":     False,
                    "IgnorePublicAcls":      False,
                    "RestrictPublicBuckets": False,
                },
                "Versioning": "Disabled",
                "Encryption": None,
                "Logging":    None,
            },
            "company-logs": {
                "Name": "company-logs",
                "PublicAccessBlock": {
                    "BlockPublicAcls":       True,
                    "BlockPublicPolicy":     True,
                    "IgnorePublicAcls":      True,
                    "RestrictPublicBuckets": True,
                },
                "Versioning": "Enabled",
                "Encryption": "AES256",
                "Logging":    "enabled",
            },
        }
    },
    "ec2": {
        "instances": {
            "i-0abc123456": {
                "InstanceId":             "i-0abc123456",
                "State":                  "running",
                "PublicIpAddress":        "52.10.20.30",
                "MetadataOptions":        {"HttpTokens": "optional"},
                "BlockDeviceMappings":    [{"Ebs": {"Encrypted": False}}],
                "Tags":                   [{"Key": "Name", "Value": "web-server"}],
            },
            "i-0def789012": {
                "InstanceId":             "i-0def789012",
                "State":                  "running",
                "PublicIpAddress":        None,
                "MetadataOptions":        {"HttpTokens": "required"},
                "BlockDeviceMappings":    [{"Ebs": {"Encrypted": True}}],
                "Tags":                   [{"Key": "Name", "Value": "app-server"}],
            },
        },
        "security_groups": {
            "sg-0aaa0001": {
                "GroupId":   "sg-0aaa0001",
                "GroupName": "web-sg",
                "IpPermissions": [
                    {"FromPort": 22, "ToPort": 22, "IpProtocol": "tcp",
                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"FromPort": 3389, "ToPort": 3389, "IpProtocol": "tcp",
                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                ],
            }
        },
    },
    "rds": {
        "instances": {
            "prod-postgres": {
                "DBInstanceIdentifier": "prod-postgres",
                "PubliclyAccessible":   True,
                "StorageEncrypted":     False,
                "BackupRetentionPeriod": 0,
                "DeletionProtection":   False,
                "MultiAZ":              False,
                "Engine":               "postgres",
            }
        }
    },
    "cloudtrail": {
        "trails": {
            "main-trail": {
                "Name":                       "main-trail",
                "LogFileValidationEnabled":   False,
                "IsMultiRegionTrail":         False,
                "IncludeGlobalServiceEvents": False,
                "IsLogging":                  True,
            }
        }
    },
    "kms": {
        "keys": {
            "key-0001": {
                "KeyId":              "key-0001",
                "KeyRotationEnabled": False,
                "KeyState":           "Enabled",
                "KeyManager":         "CUSTOMER",
            }
        }
    },
    "guardduty": {
        "detectors": {
            "detector-0001": {
                "DetectorId": "detector-0001",
                "Status":     "DISABLED",
            }
        }
    },
    "vpc": {
        "flow_logs": {}   # empty → no flow logs configured
    },
}

# Inline rule definitions for demo (no external files needed)
_DEMO_FINDINGS: List[Dict[str, Any]] = [
    {
        "rule_id":       "IAM-01",
        "name":          "Root account MFA not enabled",
        "description":   "The AWS root account does not have multi-factor authentication (MFA) enabled. The root account has unrestricted access to all AWS resources.",
        "severity":      "CRITICAL",
        "service":       "iam",
        "provider":      "aws",
        "resource_path": "iam.account_summary",
        "remediation":   "Enable MFA for the root account in the AWS IAM console under 'Security credentials'. Use a hardware MFA device for root accounts.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "1.5"}],
        "references":    ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"],
        "flagged_items": [{"id": "root", "details": {"AccountMFAEnabled": 0}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "IAM-05",
        "name":          "Console user without MFA",
        "description":   "IAM users with console access do not have MFA enabled, leaving accounts vulnerable to credential theft attacks.",
        "severity":      "HIGH",
        "service":       "iam",
        "provider":      "aws",
        "resource_path": "iam.users.*",
        "remediation":   "Enable MFA for all IAM users with console access. Enforce MFA via an IAM policy with a condition on 'aws:MultiFactorAuthPresent'.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "1.10"}],
        "references":    ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"],
        "flagged_items": [{"id": "alice", "details": {"name": "alice", "MFADevices": []}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "IAM-06",
        "name":          "IAM password policy too weak",
        "description":   "The account's IAM password policy does not meet minimum security requirements (length < 14, missing complexity, no expiry).",
        "severity":      "MEDIUM",
        "service":       "iam",
        "provider":      "aws",
        "resource_path": "iam.password_policy",
        "remediation":   "Set MinimumPasswordLength >= 14, enable all complexity requirements, set MaxPasswordAge to 90 days or fewer.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "1.8"}],
        "references":    ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"],
        "flagged_items": [{"id": "account", "details": {"MinimumPasswordLength": 6}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "S3-01",
        "name":          "S3 Block Public Access not fully enabled",
        "description":   "One or more S3 buckets have Block Public Access settings disabled, potentially exposing data to the internet.",
        "severity":      "HIGH",
        "service":       "s3",
        "provider":      "aws",
        "resource_path": "s3.buckets.*",
        "remediation":   "Enable all four S3 Block Public Access settings at both the account and bucket level. Use bucket policies with explicit Deny for public access.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "2.1.4"}],
        "references":    ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        "flagged_items": [{"id": "company-public-data", "details": {"BlockPublicAcls": False}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "EC2-04",
        "name":          "EC2 instance with IMDSv1 enabled",
        "description":   "Instance Metadata Service v1 (IMDSv1) does not require authentication, making instances vulnerable to SSRF-based metadata theft (e.g., credential exfiltration).",
        "severity":      "HIGH",
        "service":       "ec2",
        "provider":      "aws",
        "resource_path": "ec2.instances.*",
        "remediation":   "Set HttpTokens=required in instance metadata options to enforce IMDSv2. Apply via AWS CLI: aws ec2 modify-instance-metadata-options --http-tokens required.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "5.6"}],
        "references":    ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"],
        "flagged_items": [{"id": "i-0abc123456", "details": {"MetadataOptions": {"HttpTokens": "optional"}}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "RDS-01",
        "name":          "RDS instance publicly accessible",
        "description":   "The RDS database instance is configured with PubliclyAccessible=true, exposing the database endpoint to the internet.",
        "severity":      "CRITICAL",
        "service":       "rds",
        "provider":      "aws",
        "resource_path": "rds.instances.*",
        "remediation":   "Set PubliclyAccessible=false. Place RDS instances in private subnets with no direct internet route. Use a bastion host or AWS PrivateLink for access.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "2.3.3"}],
        "references":    ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.html"],
        "flagged_items": [{"id": "prod-postgres", "details": {"PubliclyAccessible": True, "StorageEncrypted": False}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "RDS-02",
        "name":          "RDS storage not encrypted",
        "description":   "RDS storage encryption is disabled. Database data at rest is stored unencrypted, risking exposure in the event of physical media compromise.",
        "severity":      "HIGH",
        "service":       "rds",
        "provider":      "aws",
        "resource_path": "rds.instances.*",
        "remediation":   "Enable storage encryption on the RDS instance. Note: encryption can only be enabled at creation time; migrate existing unencrypted instances via snapshot restore.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "2.3.1"}],
        "references":    ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"],
        "flagged_items": [{"id": "prod-postgres", "details": {"StorageEncrypted": False}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "CT-01",
        "name":          "CloudTrail log file validation disabled",
        "description":   "CloudTrail log file validation is not enabled. Without it, attackers can tamper with audit logs without detection.",
        "severity":      "HIGH",
        "service":       "cloudtrail",
        "provider":      "aws",
        "resource_path": "cloudtrail.trails.*",
        "remediation":   "Enable log file validation on all trails via: aws cloudtrail update-trail --name <trail> --enable-log-file-validation.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "3.2"}],
        "references":    ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"],
        "flagged_items": [{"id": "main-trail", "details": {"LogFileValidationEnabled": False}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "KMS-01",
        "name":          "KMS key rotation not enabled",
        "description":   "Customer-managed KMS keys do not have automatic annual key rotation enabled, increasing the risk of cryptographic key compromise.",
        "severity":      "MEDIUM",
        "service":       "kms",
        "provider":      "aws",
        "resource_path": "kms.keys.*",
        "remediation":   "Enable automatic key rotation: aws kms enable-key-rotation --key-id <key-id>. Keys are rotated annually.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "3.7"}],
        "references":    ["https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"],
        "flagged_items": [{"id": "key-0001", "details": {"KeyRotationEnabled": False}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "GD-01",
        "name":          "GuardDuty detector disabled",
        "description":   "Amazon GuardDuty is not enabled. Without GuardDuty, threat detection for unauthorized behaviour, compromised instances, and account reconnaissance is absent.",
        "severity":      "HIGH",
        "service":       "guardduty",
        "provider":      "aws",
        "resource_path": "guardduty.detectors.*",
        "remediation":   "Enable GuardDuty in all regions. Enable optional protection plans (S3, EKS, RDS, Lambda, Malware). Configure SNS alerts for HIGH/CRITICAL findings.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "4.9"}],
        "references":    ["https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html"],
        "flagged_items": [{"id": "detector-0001", "details": {"Status": "DISABLED"}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "VPC-01",
        "name":          "VPC Flow Logs not enabled",
        "description":   "No VPC Flow Logs are configured. Without flow logs, network traffic to and from EC2 instances cannot be audited or used for incident investigation.",
        "severity":      "MEDIUM",
        "service":       "vpc",
        "provider":      "aws",
        "resource_path": "vpc.flow_logs",
        "remediation":   "Enable VPC Flow Logs for all VPCs. Send logs to CloudWatch Logs or S3. Set retention to at least 90 days.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "3.9"}],
        "references":    ["https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"],
        "flagged_items": [{"id": "vpc", "details": {}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "RDS-03",
        "name":          "RDS automated backups disabled",
        "description":   "RDS automated backup retention is set to 0 days, disabling backups entirely. This prevents point-in-time recovery in the event of data loss or corruption.",
        "severity":      "MEDIUM",
        "service":       "rds",
        "provider":      "aws",
        "resource_path": "rds.instances.*",
        "remediation":   "Set BackupRetentionPeriod to at least 7 days (35 days for compliance-sensitive workloads).",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "2.3.2"}],
        "references":    ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"],
        "flagged_items": [{"id": "prod-postgres", "details": {"BackupRetentionPeriod": 0}}],
        "flagged_count": 1,
    },
    {
        "rule_id":       "IAM-10",
        "name":          "Stale IAM access key (>90 days)",
        "description":   "An active IAM access key has not been rotated in over 90 days, increasing the risk of long-term credential compromise.",
        "severity":      "LOW",
        "service":       "iam",
        "provider":      "aws",
        "resource_path": "iam.users.*",
        "remediation":   "Rotate access keys every 90 days. Disable or delete keys unused for 30+ days. Use IAM roles instead of long-term access keys where possible.",
        "compliance":    [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "1.14"}],
        "references":    ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"],
        "flagged_items": [{"id": "alice", "details": {"AccessKeyId": "AKIA1111", "CreateDate": "2022-03-01"}}],
        "flagged_count": 1,
    },
]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scout.py",
        description="MultiCloud Security Audit Tool v" + __version__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scout.py demo --html report.html
  python scout.py demo --json findings.json --html report.html
  python scout.py aws  --region us-east-1 --html aws_report.html  (Phase 2)
  python scout.py azure --subscription-id <ID> --html azure.html  (Phase 3)
  python scout.py gcp   --project <PROJECT>    --html gcp.html    (Phase 4)
""",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="provider", metavar="PROVIDER")
    sub.required = True

    # ---- demo ----
    demo_p = sub.add_parser("demo", help="Generate a sample report with built-in demo findings (no credentials needed)")
    demo_p.add_argument("--html", metavar="FILE", help="Write HTML report to FILE")
    demo_p.add_argument("--json", metavar="FILE", help="Write JSON findings to FILE")
    demo_p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # ---- aws (Phase 2) ----
    aws_p = sub.add_parser("aws", help="Audit a live AWS account (CIS AWS Foundations v3.0)")
    aws_p.add_argument("--region",   default="eu-west-1", metavar="REGION", help="AWS region (default: eu-west-1)")
    aws_p.add_argument("--profile",  metavar="PROFILE",   help="AWS named profile")
    aws_p.add_argument("--sections", nargs="+",           metavar="SECTION", help="Run specific sections only")
    aws_p.add_argument("--ruleset",  metavar="FILE",      help="Custom ruleset JSON")
    aws_p.add_argument("--html",     metavar="FILE",      help="Write HTML report to FILE")
    aws_p.add_argument("--json",     metavar="FILE",      help="Write JSON findings to FILE")
    aws_p.add_argument("-v", "--verbose", action="store_true")

    # ---- azure (Phase 3) ----
    az_p = sub.add_parser("azure", help="Audit an Azure subscription (Phase 3 — coming soon)")
    az_p.add_argument("--subscription-id", metavar="SUB_ID")
    az_p.add_argument("--tenant-id",       metavar="TENANT_ID")
    az_p.add_argument("--client-id",       metavar="CLIENT_ID")
    az_p.add_argument("--client-secret",   metavar="SECRET")
    az_p.add_argument("--html",            metavar="FILE")
    az_p.add_argument("--json",            metavar="FILE")
    az_p.add_argument("-v", "--verbose",   action="store_true")

    # ---- gcp (Phase 4) ----
    gcp_p = sub.add_parser("gcp", help="Audit a GCP project (Phase 4 — coming soon)")
    gcp_p.add_argument("--project",              metavar="PROJECT_ID")
    gcp_p.add_argument("--service-account-file", metavar="FILE")
    gcp_p.add_argument("--html",                 metavar="FILE")
    gcp_p.add_argument("--json",                 metavar="FILE")
    gcp_p.add_argument("-v", "--verbose",        action="store_true")

    return parser


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------

def _run_demo(args: argparse.Namespace) -> int:
    """Generate a sample HTML/JSON report from built-in demo findings."""
    from core.finding import Finding, SEVERITY_ORDER
    from output.encoder import save_json
    from output.report import save_html

    print(f"[*] MultiCloud Security Audit Tool v{__version__}")
    print("[*] Mode: DEMO (sample findings — no credentials required)")
    print()

    # Convert raw dicts to Finding objects
    findings: List[Finding] = []
    for raw in _DEMO_FINDINGS:
        findings.append(Finding(
            rule_id=raw["rule_id"],
            name=raw["name"],
            description=raw["description"],
            severity=raw["severity"],
            service=raw["service"],
            provider=raw.get("provider", "aws"),
            resource_path=raw["resource_path"],
            remediation=raw.get("remediation", ""),
            compliance=raw.get("compliance", []),
            references=raw.get("references", []),
            flagged_items=raw.get("flagged_items", []),
        ))

    findings.sort()

    # Console summary
    from collections import Counter
    sev_c = Counter(f.severity for f in findings)
    print(f"  Findings : {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sev_c.get(sev, 0)
        if count:
            print(f"  {sev:<10}: {count}")
    print()

    meta = {
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "account":   "demo-account-123456789",
        "version":   __version__,
    }

    # Save JSON
    if args.json:
        save_json(findings, args.json)
        print(f"[+] JSON report saved to: {args.json}")

    # Save HTML
    html_path = args.html or "multicloud_report.html"
    save_html(findings, html_path, meta=meta)
    print(f"[+] HTML report saved to: {html_path}")

    # Open in browser
    import webbrowser
    try:
        webbrowser.open(str(Path(html_path).resolve().as_uri()))
    except Exception:
        pass

    # Exit 1 if any CRITICAL or HIGH
    has_critical = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    return 1 if has_critical else 0


def _run_aws(args: argparse.Namespace) -> int:
    """Live AWS account audit — Phase 2."""
    from core.ruleset import Ruleset
    from core.engine import ProcessingEngine
    from output.encoder import save_json
    from output.report import save_html

    print(f"[*] MultiCloud Security Audit Tool v{__version__}")
    print(f"[*] Provider : AWS")
    print(f"[*] Region   : {args.region}")
    if args.profile:
        print(f"[*] Profile  : {args.profile}")
    print()

    # --- Import provider (requires boto3) ---
    try:
        from providers.aws import AWSProvider
    except ImportError as exc:
        print(f"[!] {exc}")
        return 2

    # --- Load ruleset ---
    _rules_dir = Path(__file__).parent / "providers" / "aws" / "rules"
    ruleset_path = Path(args.ruleset) if args.ruleset else (_rules_dir / "aws-cis-3.0-ruleset.json")
    if not ruleset_path.exists():
        print(f"[!] Ruleset not found: {ruleset_path}")
        return 2

    try:
        ruleset = Ruleset(ruleset_path, rule_dirs=[str(_rules_dir)])
    except Exception as exc:
        print(f"[!] Failed to load ruleset: {exc}")
        return 2

    print(f"[*] Ruleset  : {ruleset_path.name} ({len(ruleset)} rules)")
    print()

    # --- Fetch data ---
    provider = AWSProvider(
        region=args.region,
        profile=args.profile,
        services=args.sections if args.sections else None,
        verbose=args.verbose,
    )
    print("[*] Connecting to AWS …")
    try:
        provider.fetch_sync()
    except Exception as exc:
        print(f"[!] AWS fetch failed: {exc}")
        return 2

    account_id = provider.account_id
    print(f"[*] Account  : {account_id}")
    print()

    # --- Run engine ---
    engine = ProcessingEngine(ruleset)
    findings = engine.run(provider.get_data(), provider="aws")

    # --- Console summary ---
    from collections import Counter
    sev_c = Counter(f.severity for f in findings)
    print(f"  Findings : {len(findings)}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = sev_c.get(sev, 0)
        if count:
            print(f"  {sev:<10}: {count}")
    print()

    meta = {
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "account":   account_id,
        "region":    args.region,
        "version":   __version__,
    }

    # --- Save outputs ---
    if args.json:
        save_json(findings, args.json)
        print(f"[+] JSON report saved to: {args.json}")

    html_path = args.html or f"aws_{account_id}_report.html"
    save_html(findings, html_path, meta=meta)
    print(f"[+] HTML report saved to: {html_path}")

    import webbrowser
    try:
        webbrowser.open(str(Path(html_path).resolve().as_uri()))
    except Exception:
        pass

    return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0


def _run_coming_soon(provider: str) -> int:
    phase_map = {"azure": 3, "gcp": 4}
    phase = phase_map.get(provider, "?")
    print(f"[*] MultiCloud Security Audit Tool v{__version__}")
    print(f"[!] Provider '{provider.upper()}' is implemented in Phase {phase}.")
    print(f"    Run 'python scout.py demo' to see the engine and report in action.")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.provider == "demo":
        return _run_demo(args)
    elif args.provider == "aws":
        return _run_aws(args)
    elif args.provider in ("azure", "gcp"):
        return _run_coming_soon(args.provider)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
