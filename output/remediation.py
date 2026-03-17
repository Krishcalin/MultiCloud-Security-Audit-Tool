"""Remediation command generator.

For each finding, generates provider-native CLI commands (AWS CLI, Azure CLI,
gcloud CLI) that fix the misconfiguration.  Commands use ``{resource_id}`` and
other ``{placeholders}`` that are filled in per flagged resource.

Usage::

    from output.remediation import get_remediation_commands, save_remediation_script
    cmds = get_remediation_commands(finding)
    # cmds = [{"resource_id": "prod-postgres", "commands": ["aws rds modify-db-instance ..."]}]
    save_remediation_script(findings, "remediation.sh")
"""
from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Remediation command templates
# Key: rule_id (uppercase)
# Value: dict with optional keys: "commands" (list of str templates),
#        "note" (free-text instruction for manual steps)
# Templates use {resource_id} placeholder.
# ---------------------------------------------------------------------------

_CMDS: Dict[str, Dict[str, Any]] = {
    # ---- AWS IAM ----
    "IAM-01": {
        "note": "Root account MFA must be enabled via the AWS Console:\n"
                "  AWS Console → Account → Security credentials → Assign MFA device\n"
                "  Use a hardware MFA token (TOTP app is acceptable for non-production).",
    },
    "IAM-05": {
        "note": "Enable MFA for the IAM user via Console or CLI:\n"
                "  aws iam create-virtual-mfa-device --virtual-mfa-device-name {resource_id}-mfa\n"
                "  aws iam enable-mfa-device --user-name {resource_id} --serial-number <mfa-arn> --authentication-code1 <code1> --authentication-code2 <code2>",
    },
    "IAM-06": {
        "commands": [
            "aws iam update-account-password-policy "
            "--minimum-password-length 14 "
            "--require-symbols "
            "--require-numbers "
            "--require-uppercase-characters "
            "--require-lowercase-characters "
            "--allow-users-to-change-password "
            "--max-password-age 90 "
            "--password-reuse-prevention 24",
        ],
    },
    "IAM-STALE": {
        "commands": [
            "# Rotate key for user {resource_id}",
            "aws iam create-access-key --user-name {resource_id}",
            "# Update applications to use the new key, then deactivate old key:",
            "aws iam update-access-key --user-name {resource_id} --access-key-id <OLD_KEY_ID> --status Inactive",
        ],
    },
    # ---- AWS S3 ----
    "S3-01": {
        "commands": [
            "aws s3api put-public-access-block --bucket {resource_id} "
            "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        ],
    },
    "S3-02": {
        "commands": [
            "aws s3api put-bucket-encryption --bucket {resource_id} "
            "--server-side-encryption-configuration "
            "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
        ],
    },
    "S3-03": {
        "commands": [
            "aws s3api put-bucket-logging --bucket {resource_id} "
            "--bucket-logging-status "
            "'{\"LoggingEnabled\":{\"TargetBucket\":\"<YOUR_LOG_BUCKET>\",\"TargetPrefix\":\"{resource_id}/\"}}'",
        ],
    },
    "S3-04": {
        "commands": [
            "aws s3api put-bucket-versioning --bucket {resource_id} "
            "--versioning-configuration Status=Enabled",
        ],
    },
    # ---- AWS EC2 ----
    "EC2-04": {
        "commands": [
            "aws ec2 modify-instance-metadata-options "
            "--instance-id {resource_id} "
            "--http-tokens required "
            "--http-put-response-hop-limit 1",
        ],
    },
    "EC2-SG-SSH": {
        "commands": [
            "# Remove the 0.0.0.0/0 SSH ingress rule from security group {resource_id}",
            "aws ec2 revoke-security-group-ingress --group-id {resource_id} "
            "--protocol tcp --port 22 --cidr 0.0.0.0/0",
            "# Replace with your corporate CIDR:",
            "aws ec2 authorize-security-group-ingress --group-id {resource_id} "
            "--protocol tcp --port 22 --cidr <YOUR_CORPORATE_CIDR>",
        ],
    },
    "EC2-SG-RDP": {
        "commands": [
            "# Remove the 0.0.0.0/0 RDP ingress rule from security group {resource_id}",
            "aws ec2 revoke-security-group-ingress --group-id {resource_id} "
            "--protocol tcp --port 3389 --cidr 0.0.0.0/0",
        ],
    },
    # ---- AWS RDS ----
    "RDS-01": {
        "commands": [
            "aws rds modify-db-instance "
            "--db-instance-identifier {resource_id} "
            "--no-publicly-accessible "
            "--apply-immediately",
        ],
    },
    "RDS-02": {
        "note": "Storage encryption cannot be enabled on an existing RDS instance. "
                "Take a snapshot and restore to a new encrypted instance:\n"
                "  aws rds create-db-snapshot --db-instance-identifier {resource_id} --db-snapshot-identifier {resource_id}-encrypted-migration\n"
                "  aws rds restore-db-instance-from-db-snapshot --db-instance-identifier {resource_id}-new --db-snapshot-identifier {resource_id}-encrypted-migration --storage-encrypted",
    },
    "RDS-03": {
        "commands": [
            "aws rds modify-db-instance "
            "--db-instance-identifier {resource_id} "
            "--backup-retention-period 7 "
            "--apply-immediately",
        ],
    },
    "RDS-04": {
        "commands": [
            "aws rds modify-db-instance "
            "--db-instance-identifier {resource_id} "
            "--deletion-protection "
            "--apply-immediately",
        ],
    },
    # ---- AWS CloudTrail ----
    "CT-01": {
        "commands": [
            "aws cloudtrail update-trail "
            "--name {resource_id} "
            "--enable-log-file-validation",
        ],
    },
    "CT-02": {
        "commands": [
            "aws cloudtrail start-logging --name {resource_id}",
        ],
    },
    "CT-03": {
        "commands": [
            "aws cloudtrail update-trail "
            "--name {resource_id} "
            "--is-multi-region-trail "
            "--include-global-service-events",
        ],
    },
    # ---- AWS KMS ----
    "KMS-01": {
        "commands": [
            "aws kms enable-key-rotation --key-id {resource_id}",
        ],
    },
    # ---- AWS VPC ----
    "VPC-01": {
        "commands": [
            "# Create a CloudWatch Logs group for flow logs:",
            "aws logs create-log-group --log-group-name /aws/vpc/flowlogs",
            "# Enable flow logs for the VPC (replace VPC_ID and ROLE_ARN):",
            "aws ec2 create-flow-logs "
            "--resource-type VPC "
            "--resource-ids <VPC_ID> "
            "--traffic-type ALL "
            "--log-destination-type cloud-watch-logs "
            "--log-group-name /aws/vpc/flowlogs "
            "--deliver-logs-permission-arn <FLOW_LOG_ROLE_ARN>",
        ],
    },
    # ---- AWS GuardDuty ----
    "GD-01": {
        "commands": [
            "aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES",
        ],
    },
    # ---- AWS Lambda ----
    "LAMBDA-01": {
        "commands": [
            "# Option 1: Delete the Function URL (removes unauthenticated access):",
            "aws lambda delete-function-url-config --function-name {resource_id}",
            "# Option 2: Switch to IAM authentication:",
            "aws lambda update-function-url-config --function-name {resource_id} --auth-type AWS_IAM",
        ],
    },
    "LAMBDA-02": {
        "note": "Update the Lambda function runtime via Console or CLI:\n"
                "  aws lambda update-function-configuration --function-name {resource_id} --runtime python3.12\n"
                "  (Choose the appropriate supported runtime for your language)",
    },
    # ---- AWS EKS ----
    "EKS-01": {
        "commands": [
            "aws eks update-cluster-config "
            "--name {resource_id} "
            "--resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true",
        ],
    },
    "EKS-02": {
        "commands": [
            "aws eks update-cluster-config --name {resource_id} "
            "--logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'",
        ],
    },
    "EKS-03": {
        "note": "KMS envelope encryption for Kubernetes secrets must be configured at cluster creation or updated:\n"
                "  aws eks associate-encryption-config --cluster-name {resource_id} "
                "--encryption-config '[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"<KMS_KEY_ARN>\"}}]'",
    },
    # ---- AWS ECR ----
    "ECR-01": {
        "commands": [
            "aws ecr put-image-scanning-configuration "
            "--repository-name {resource_id} "
            "--image-scanning-configuration scanOnPush=true",
        ],
    },
    "ECR-02": {
        "commands": [
            "aws ecr put-image-tag-mutability "
            "--repository-name {resource_id} "
            "--image-tag-mutability IMMUTABLE",
        ],
    },
    # ---- AWS Secrets Manager ----
    "SM-01": {
        "note": "Enable automatic rotation for the secret {resource_id}:\n"
                "  aws secretsmanager rotate-secret --secret-id {resource_id} --rotation-lambda-arn <LAMBDA_ARN>\n"
                "  aws secretsmanager put-rotation-schedule --secret-id {resource_id} --rotation-rules AutomaticallyAfterDays=90",
    },
    "SM-02": {
        "commands": [
            "aws secretsmanager rotate-secret --secret-id {resource_id}",
        ],
    },
    # ---- AWS OpenSearch ----
    "OS-01": {
        "note": "VPC deployment cannot be enabled on an existing OpenSearch domain. "
                "You must create a new domain with VPC configuration:\n"
                "  aws opensearch create-domain --domain-name <NEW_DOMAIN> "
                "--vpc-options SubnetIds=<SUBNET_ID>,SecurityGroupIds=<SG_ID> ...\n"
                "  Reindex data from old domain to new domain, then delete old domain.",
    },
    "OS-02": {
        "note": "Encryption at rest cannot be enabled on an existing OpenSearch domain. "
                "Create a new domain with encryption enabled and migrate data.",
    },
    "OS-03": {
        "note": "Node-to-node encryption cannot be enabled on an existing OpenSearch domain. "
                "Create a new domain with node-to-node encryption and migrate data.",
    },
    # ---- Azure Storage ----
    "STOR-01": {
        "commands": [
            "az storage account update --name {resource_id} --resource-group <RG> --https-only true",
        ],
    },
    "STOR-02": {
        "commands": [
            "az storage account update --name {resource_id} --resource-group <RG> --min-tls-version TLS1_2",
        ],
    },
    "STOR-03": {
        "commands": [
            "az storage account update --name {resource_id} --resource-group <RG> --allow-blob-public-access false",
        ],
    },
    # ---- Azure Key Vault ----
    "KV-01": {
        "commands": [
            "az keyvault update --name {resource_id} --resource-group <RG> --enable-soft-delete true",
        ],
    },
    "KV-02": {
        "commands": [
            "az keyvault update --name {resource_id} --resource-group <RG> --enable-purge-protection true",
        ],
    },
    "KV-03": {
        "commands": [
            "az keyvault update --name {resource_id} --resource-group <RG> --public-network-access Disabled",
        ],
    },
    # ---- Azure SQL ----
    "SQL-01": {
        "commands": [
            "az sql server audit-policy update --name {resource_id} --resource-group <RG> --state Enabled --storage-account <STORAGE_ACCOUNT>",
        ],
    },
    "SQL-02": {
        "commands": [
            "az sql server ad-admin create --server-name {resource_id} --resource-group <RG> --display-name <AAD_GROUP> --object-id <AAD_OBJECT_ID>",
        ],
    },
    # ---- Azure AKS ----
    "AKS-01": {
        "note": "RBAC cannot be enabled on an existing AKS cluster without recreation. "
                "Create a new cluster with RBAC enabled (default since AKS 1.8):\n"
                "  az aks create --name <NEW_CLUSTER> --resource-group <RG> --enable-rbac ...",
    },
    "AKS-02": {
        "commands": [
            "az aks update --name {resource_id} --resource-group <RG> --enable-aad --aad-admin-group-object-ids <GROUP_ID>",
        ],
    },
    "AKS-03": {
        "commands": [
            "az aks update --name {resource_id} --resource-group <RG> --network-policy azure",
        ],
    },
    # ---- Azure ACR ----
    "ACR-01": {
        "commands": [
            "az acr update --name {resource_id} --admin-enabled false",
        ],
    },
    "ACR-02": {
        "commands": [
            "az acr update --name {resource_id} --public-network-enabled false",
        ],
    },
    # ---- Azure Cosmos DB ----
    "COSMOS-01": {
        "commands": [
            "az cosmosdb update --name {resource_id} --resource-group <RG> --public-network-access Disabled",
        ],
    },
    "COSMOS-02": {
        "commands": [
            "# Add IP firewall rules — replace with your IP ranges:",
            "az cosmosdb update --name {resource_id} --resource-group <RG> --ip-range-filter \"<IP_RANGE_1>,<IP_RANGE_2>\"",
        ],
    },
    "COSMOS-03": {
        "commands": [
            "az cosmosdb update --name {resource_id} --resource-group <RG> --enable-automatic-failover true",
        ],
    },
    # ---- GCP Storage ----
    "GCS-01": {
        "commands": [
            "gcloud storage buckets update gs://{resource_id} --no-uniform-bucket-level-access",
            "# Then remove allUsers/allAuthenticatedUsers from IAM:",
            "gcloud storage buckets remove-iam-policy-binding gs://{resource_id} --member=allUsers --role=roles/storage.objectViewer",
        ],
    },
    "GCS-02": {
        "commands": [
            "gcloud storage buckets update gs://{resource_id} --uniform-bucket-level-access",
        ],
    },
    "GCS-03": {
        "commands": [
            "gcloud storage buckets update gs://{resource_id} --public-access-prevention=enforced",
        ],
    },
    "GCS-04": {
        "commands": [
            "gcloud storage buckets update gs://{resource_id} --versioning",
        ],
    },
    # ---- GCP Compute ----
    "INST-01": {
        "commands": [
            "gcloud compute instances add-metadata {resource_id} --zone <ZONE> --metadata enable-oslogin=TRUE",
        ],
    },
    "INST-02": {
        "commands": [
            "gcloud compute instances add-metadata {resource_id} --zone <ZONE> --metadata serial-port-enable=FALSE",
        ],
    },
    # ---- GCP KMS ----
    "KMS-01-GCP": {
        "commands": [
            "gcloud kms keys update {resource_id} --keyring <KEY_RING> --location <LOCATION> --rotation-period 90d --next-rotation-time $(date -d '+90 days' --iso-8601)",
        ],
    },
    # ---- GCP GKE ----
    "GKE-01": {
        "commands": [
            "gcloud container clusters update {resource_id} --zone <ZONE> --enable-private-endpoint --enable-private-nodes --master-ipv4-cidr 172.16.0.32/28",
        ],
    },
    "GKE-02": {
        "note": "Create a dedicated least-privilege service account for GKE nodes:\n"
                "  gcloud iam service-accounts create gke-node-sa --display-name 'GKE Node SA'\n"
                "  gcloud projects add-iam-policy-binding <PROJECT> --member='serviceAccount:gke-node-sa@<PROJECT>.iam.gserviceaccount.com' --role=roles/logging.logWriter\n"
                "  gcloud projects add-iam-policy-binding <PROJECT> --member='serviceAccount:gke-node-sa@<PROJECT>.iam.gserviceaccount.com' --role=roles/monitoring.metricWriter\n"
                "  # Then update node pool to use the new SA",
    },
    "GKE-03": {
        "commands": [
            "gcloud container clusters update {resource_id} --zone <ZONE> --update-addons NetworkPolicy=ENABLED",
            "gcloud container node-pools update <NODE_POOL> --cluster {resource_id} --zone <ZONE> --enable-network-policy",
        ],
    },
    "GKE-04": {
        "commands": [
            "gcloud container clusters update {resource_id} --zone <ZONE> --enable-master-authorized-networks --master-authorized-networks <CIDR_1>,<CIDR_2>",
        ],
    },
    # ---- GCP BigQuery ----
    "BQ-01": {
        "commands": [
            "# Remove allUsers access from BigQuery dataset {resource_id}:",
            "bq update --remove_iam_policy_binding='roles/bigquery.dataViewer:allUsers' {resource_id}",
        ],
    },
    # ---- GCP Cloud Functions ----
    "FUNC-01": {
        "commands": [
            "gcloud functions remove-iam-policy-binding {resource_id} --region <REGION> --member=allUsers --role=roles/cloudfunctions.invoker",
        ],
    },
    "FUNC-02": {
        "note": "Update the Cloud Function runtime:\n"
                "  gcloud functions deploy {resource_id} --runtime python312 --region <REGION> [other flags]\n"
                "  (Choose the appropriate supported runtime for your language)",
    },
    # ---- GCP Logging ----
    "LOG-01": {
        "note": "Enable data access audit logs for all services:\n"
                "  Use gcloud or Console to add an audit config to the project IAM policy:\n"
                "  gcloud projects get-iam-policy <PROJECT> --format=json > policy.json\n"
                "  # Edit policy.json to add auditConfigs for allServices with DATA_READ, DATA_WRITE, ADMIN_READ\n"
                "  gcloud projects set-iam-policy <PROJECT> policy.json",
    },
    "LOG-02": {
        "commands": [
            "gcloud logging sinks create all-logs-sink storage.googleapis.com/<BUCKET_NAME> --log-filter='' --include-children",
        ],
    },
}


def get_remediation_commands(finding: Any) -> List[Dict[str, Any]]:
    """Return a list of per-resource remediation command dicts for *finding*.

    Each entry::

        {
            "resource_id": str,
            "commands":    list[str],   # rendered CLI commands
            "note":        str | None,  # free-text manual step
        }
    """
    rule_id = getattr(finding, "rule_id", "").upper()
    template = _CMDS.get(rule_id)
    if not template:
        return []

    flagged_items = getattr(finding, "flagged_items", []) or []
    if not flagged_items:
        # Still generate one entry with placeholder
        flagged_items = [{"id": "<RESOURCE_ID>", "details": {}}]

    results = []
    for item in flagged_items:
        rid = str(item.get("id", "<RESOURCE_ID>"))
        cmds = [
            c.replace("{resource_id}", rid)
            for c in template.get("commands", [])
        ]
        note = template.get("note", "").replace("{resource_id}", rid) if template.get("note") else None
        results.append({
            "resource_id": rid,
            "commands":    cmds,
            "note":        note,
        })

    return results


def save_remediation_script(findings: List[Any], path: str) -> None:
    """Write a shell script with all CLI remediation commands to *path*."""
    lines = [
        "#!/usr/bin/env bash",
        "# MultiCloud Security Audit Tool — Auto-generated Remediation Script",
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "# WARNING: Review each command carefully before executing.",
        "# Commands marked [MANUAL] require manual steps in the console.",
        "#",
        "set -euo pipefail",
        "",
    ]

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sorted_findings = sorted(
        findings,
        key=lambda f: sev_order.index(getattr(f, "severity", "INFO")) if getattr(f, "severity", "INFO") in sev_order else 99,
    )

    current_sev = None
    for f in sorted_findings:
        sev = getattr(f, "severity", "INFO")
        if sev != current_sev:
            current_sev = sev
            lines += ["", f"# {'='*60}", f"# {sev} Findings", f"# {'='*60}", ""]

        rule_id = getattr(f, "rule_id", "?")
        name    = getattr(f, "name", "")
        lines.append(f"# [{rule_id}] {name}")
        lines.append(f"# Service: {getattr(f, 'service', '?')} | Provider: {getattr(f, 'provider', '?')}")

        remediation_entries = get_remediation_commands(f)
        if not remediation_entries:
            lines.append(f"# Remediation: {getattr(f, 'remediation', 'See HTML report for details.')}")
            lines.append("")
            continue

        for entry in remediation_entries:
            rid = entry["resource_id"]
            if entry["commands"]:
                lines.append(f"# Resource: {rid}")
                for cmd in entry["commands"]:
                    lines.append(cmd)
            if entry["note"]:
                lines.append(f"# [MANUAL] {rid}:")
                for note_line in entry["note"].split("\n"):
                    lines.append(f"#   {note_line}")
        lines.append("")

    Path(path).write_text("\n".join(lines), encoding="utf-8")
