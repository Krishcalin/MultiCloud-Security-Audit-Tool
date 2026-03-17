"""SARIF v2.1.0 output writer.

Generates a SARIF JSON file suitable for upload to GitHub Code Scanning
(actions/upload-sarif), GitLab, or viewing in VS Code.

Usage::

    from output.sarif import save_sarif
    save_sarif(findings, "results.sarif", tool_version="2.0.0")
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "note",
}

_TAG_MAP = {
    "CRITICAL": ["security", "critical"],
    "HIGH":     ["security", "high"],
    "MEDIUM":   ["security", "medium"],
    "LOW":      ["security", "low"],
    "INFO":     ["security", "info"],
}


def save_sarif(
    findings: List[Any],
    path: str,
    tool_version: str = "2.0.0",
    suppressed: List[Any] | None = None,
) -> None:
    """Write a SARIF 2.1.0 file to *path*.

    Parameters
    ----------
    findings:   Active (non-suppressed) findings.
    path:       Output file path.
    tool_version: Tool version string.
    suppressed: Optional list of suppressed findings (marked with suppressions).
    """
    # Build unique rule descriptors
    rules_seen: Dict[str, Any] = {}
    for f in findings + (suppressed or []):
        rid = getattr(f, "rule_id", "UNKNOWN")
        if rid in rules_seen:
            continue
        sev  = getattr(f, "severity", "INFO")
        desc = getattr(f, "description", "")
        rem  = getattr(f, "remediation", "")
        refs = getattr(f, "references", [])
        rules_seen[rid] = {
            "id": rid,
            "name": _snake(getattr(f, "name", rid)),
            "shortDescription": {"text": getattr(f, "name", rid)},
            "fullDescription":  {"text": desc or getattr(f, "name", rid)},
            "defaultConfiguration": {"level": _LEVEL_MAP.get(sev, "warning")},
            "help": {
                "text": rem or "See rule documentation.",
                "markdown": f"**Remediation**\n\n{rem}" if rem else "See rule documentation.",
            },
            "helpUri": refs[0] if refs else "https://github.com/Krishcalin/MultiCloud-Security-Audit-Tool",
            "properties": {
                "tags":     _TAG_MAP.get(sev, ["security"]),
                "severity": sev.lower(),
                "service":  getattr(f, "service", ""),
                "provider": getattr(f, "provider", ""),
            },
        }

    # Build results
    results: List[Dict[str, Any]] = []

    for f in findings:
        results.extend(_finding_to_results(f, suppressed=False))

    for f in (suppressed or []):
        results.extend(_finding_to_results(f, suppressed=True))

    sarif_doc = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name":            "MultiCloud Security Audit Tool",
                        "version":         tool_version,
                        "informationUri":  "https://github.com/Krishcalin/MultiCloud-Security-Audit-Tool",
                        "organization":    "MultiCloud Security",
                        "rules":           list(rules_seen.values()),
                    }
                },
                "results":         results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                ],
            }
        ],
    }

    Path(path).write_text(
        json.dumps(sarif_doc, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _finding_to_results(finding: Any, suppressed: bool) -> List[Dict[str, Any]]:
    """Convert one Finding to one SARIF result per flagged item."""
    rule_id = getattr(finding, "rule_id", "UNKNOWN")
    sev     = getattr(finding, "severity", "INFO")
    level   = _LEVEL_MAP.get(sev, "warning")
    name    = getattr(finding, "name", rule_id)
    service = getattr(finding, "service", "")
    provider = getattr(finding, "provider", "")

    flagged = getattr(finding, "flagged_items", []) or []
    if not flagged:
        flagged = [{"id": "unknown", "details": {}}]

    out = []
    for item in flagged:
        rid     = str(item.get("id", "unknown"))
        details = item.get("details", {})
        detail_str = ", ".join(f"{k}={v}" for k, v in list(details.items())[:5]) if details else ""
        message = f"{name}: {rid}"
        if detail_str:
            message += f" ({detail_str})"

        result: Dict[str, Any] = {
            "ruleId":  rule_id,
            "level":   level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri":       f"{provider}://{service}/{rid}",
                            "uriBaseId": "CLOUDRESOURCE",
                        }
                    }
                }
            ],
            "properties": {
                "severity": sev,
                "service":  service,
                "provider": provider,
            },
        }

        if suppressed:
            result["suppressions"] = [
                {"kind": "inSource", "justification": "Suppressed via exceptions file"}
            ]

        out.append(result)

    return out


def _snake(name: str) -> str:
    """Convert 'Some Finding Name' to 'SomeFindingName' (PascalCase rule name)."""
    return "".join(w.capitalize() for w in name.replace("-", " ").replace("_", " ").split())
