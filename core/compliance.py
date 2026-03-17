"""Compliance framework aggregation.

Parses the ``compliance`` metadata embedded in each Finding and groups results
by canonical framework name.  Produces a per-framework exposure report showing
how many findings map to each standard and which sections are impacted.

Canonical framework names
-------------------------
Multiple names in rule files map to the same canonical display name:

    "CIS AWS Foundations"     → "CIS Benchmarks"
    "CIS Azure Foundations"   → "CIS Benchmarks"
    "CIS GCP Foundations"     → "CIS Benchmarks"
    "PCI-DSS"                 → "PCI-DSS"
    "HIPAA"                   → "HIPAA"
    "SOC2" / "SOC 2"          → "SOC 2"
    "ISO 27001"               → "ISO 27001"
    "NIST CSF"                → "NIST CSF"
    "AWS Well-Architected"    → "AWS Well-Architected"

Usage::

    from core.compliance import aggregate_compliance
    frameworks = aggregate_compliance(findings)
    # frameworks["PCI-DSS"]["finding_count"] → int
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Framework name normalisation map
# Each entry: (display_name, list_of_matching_substrings)
# ---------------------------------------------------------------------------

_FRAMEWORK_MAP: List[tuple] = [
    ("CIS Benchmarks",       ["CIS "]),
    ("PCI-DSS",              ["PCI-DSS", "PCI DSS"]),
    ("HIPAA",                ["HIPAA"]),
    ("SOC 2",                ["SOC2", "SOC 2", "AICPA"]),
    ("ISO 27001",            ["ISO 27001", "ISO/IEC 27001"]),
    ("NIST CSF",             ["NIST CSF", "NIST Cybersecurity"]),
    ("AWS Well-Architected", ["AWS Well-Architected"]),
]

# Severity display order for breakdown
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _canonicalise(name: str) -> str:
    """Map a raw framework name from a rule file to a canonical display name."""
    for canonical, keywords in _FRAMEWORK_MAP:
        for kw in keywords:
            if kw.lower() in name.lower():
                return canonical
    return name  # unknown framework — return as-is


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def aggregate_compliance(findings: List[Any]) -> Dict[str, Any]:
    """Aggregate compliance framework exposure from a list of Finding objects.

    Parameters
    ----------
    findings:
        List of :class:`~core.finding.Finding` instances.

    Returns
    -------
    Dict keyed by canonical framework name, each value::

        {
            "finding_count": int,
            "critical":      int,
            "high":          int,
            "medium":        int,
            "low":           int,
            "info":          int,
            "refs":          list[str],   # unique framework section refs
            "rule_ids":      list[str],   # rule IDs that reference this framework
        }

    Frameworks are sorted by descending finding_count.
    """
    raw: Dict[str, Any] = defaultdict(lambda: {
        "finding_count": 0,
        "sev_counter":   Counter(),
        "refs":          set(),
        "rule_ids":      set(),
    })

    for f in findings:
        for comp in (getattr(f, "compliance", None) or []):
            fname   = comp.get("name", "")
            canon   = _canonicalise(fname)
            ref     = comp.get("reference", "")
            version = comp.get("version", "")

            entry = raw[canon]
            entry["finding_count"] += 1
            entry["sev_counter"][getattr(f, "severity", "INFO")] += 1
            entry["rule_ids"].add(getattr(f, "rule_id", ""))
            if ref:
                label = f"{fname}"
                if version:
                    label += f" v{version}"
                label += f" §{ref}"
                entry["refs"].add(label)

    # Convert and sort by finding count descending
    result: Dict[str, Any] = {}
    for canon, entry in sorted(
        raw.items(), key=lambda kv: kv[1]["finding_count"], reverse=True
    ):
        sc = entry["sev_counter"]
        result[canon] = {
            "finding_count": entry["finding_count"],
            "critical":      sc.get("CRITICAL", 0),
            "high":          sc.get("HIGH", 0),
            "medium":        sc.get("MEDIUM", 0),
            "low":           sc.get("LOW", 0),
            "info":          sc.get("INFO", 0),
            "refs":          sorted(entry["refs"])[:12],
            "rule_ids":      sorted(entry["rule_ids"]),
        }

    return result
