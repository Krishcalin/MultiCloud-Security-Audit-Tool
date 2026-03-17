"""JUnit XML output writer for CI pipeline integration.

Generates a JUnit-compatible XML file where:
- Each provider/service is a ``<testsuite>``
- Each finding is a ``<testcase>``
- CRITICAL/HIGH findings produce ``<failure>`` elements (CI fails)
- MEDIUM/LOW findings produce ``<skipped>`` elements (CI warns)

Usage::

    from output.junit import save_junit
    save_junit(findings, "results.xml")
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def save_junit(findings: List[Any], path: str) -> None:
    """Write a JUnit XML report to *path*.

    Parameters
    ----------
    findings: List of :class:`~core.finding.Finding` instances.
    path:     Output file path.
    """
    # Group by provider + service
    groups: Dict[str, List[Any]] = defaultdict(list)
    for f in findings:
        key = f"{getattr(f, 'provider', 'unknown')}.{getattr(f, 'service', 'unknown')}"
        groups[key].append(f)

    total_tests    = len(findings)
    total_failures = sum(
        1 for f in findings if getattr(f, "severity", "") in ("CRITICAL", "HIGH")
    )

    testsuites = ET.Element("testsuites", {
        "name":     "MultiCloud Security Audit Tool",
        "tests":    str(total_tests),
        "failures": str(total_failures),
        "errors":   "0",
        "time":     "0",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })

    for suite_name, suite_findings in sorted(groups.items()):
        suite_failures = sum(
            1 for f in suite_findings if getattr(f, "severity", "") in ("CRITICAL", "HIGH")
        )
        testsuite = ET.SubElement(testsuites, "testsuite", {
            "name":     suite_name,
            "tests":    str(len(suite_findings)),
            "failures": str(suite_failures),
            "errors":   "0",
            "skipped":  str(len(suite_findings) - suite_failures),
            "time":     "0",
        })

        for f in suite_findings:
            rule_id   = getattr(f, "rule_id",  "UNKNOWN")
            name      = getattr(f, "name",     rule_id)
            sev       = getattr(f, "severity", "INFO")
            provider  = getattr(f, "provider", "")
            service   = getattr(f, "service",  "")
            remediation = getattr(f, "remediation", "")

            testcase = ET.SubElement(testsuite, "testcase", {
                "name":      f"[{rule_id}] {name}",
                "classname": f"{provider}.{service}",
                "time":      "0",
            })

            flagged = getattr(f, "flagged_items", []) or []
            affected = ", ".join(str(i.get("id", "?")) for i in flagged[:5])
            if len(flagged) > 5:
                affected += f" (+{len(flagged)-5} more)"

            body = f"Severity: {sev}\nAffected: {affected}\n\nRemediation:\n{remediation}"

            if sev in ("CRITICAL", "HIGH"):
                failure = ET.SubElement(testcase, "failure", {
                    "type":    sev,
                    "message": f"{name} | Affected: {affected}",
                })
                failure.text = body
            else:
                skipped = ET.SubElement(testcase, "skipped", {
                    "message": f"{sev}: {name} | Affected: {affected}",
                })
                skipped.text = body

    # Pretty-print
    _indent(testsuites)
    tree = ET.ElementTree(testsuites)
    ET.indent(tree, space="  ")

    xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(
        testsuites, encoding="unicode"
    )
    Path(path).write_text(xml_str, encoding="utf-8")


def _indent(elem: ET.Element, level: int = 0) -> None:
    """Add pretty-print indentation (Python < 3.9 fallback)."""
    indent_str = "\n" + "  " * level
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = indent_str + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = indent_str
        for child in elem:
            _indent(child, level + 1)
        if not child.tail or not child.tail.strip():  # type: ignore[possibly-undefined]
            child.tail = indent_str  # type: ignore[possibly-undefined]
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = indent_str
