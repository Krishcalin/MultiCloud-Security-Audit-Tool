"""Finding dataclass — represents a single security finding produced by the rule engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

SEVERITY_COLOUR: Dict[str, str] = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#66b3ff",
    "INFO":     "#aaaaaa",
}


@dataclass
class Finding:
    """A single security finding raised by the rule engine.

    Attributes
    ----------
    rule_id       : Unique rule identifier, e.g. ``IAM-01`` or ``AWS-S3-001``.
    name          : Short human-readable finding name.
    description   : Full description of the misconfiguration.
    severity      : One of CRITICAL | HIGH | MEDIUM | LOW | INFO.
    service       : Cloud service name, e.g. ``iam``, ``s3``, ``compute``.
    provider      : Cloud provider name, e.g. ``aws``, ``azure``, ``gcp``.
    resource_path : Dot-notation path used to locate the resource in the data dict.
    remediation   : Recommended fix.
    compliance    : List of compliance mappings, e.g.
                    ``[{"name": "CIS AWS Foundations", "version": "3.0", "reference": "1.5"}]``.
    references    : List of reference URLs.
    flagged_items : List of ``{"id": str, "details": dict}`` dicts — one per affected resource.
    """

    rule_id:       str
    name:          str
    description:   str
    severity:      str
    service:       str
    provider:      str
    resource_path: str
    remediation:   str                         = ""
    compliance:    List[Dict[str, str]]        = field(default_factory=list)
    references:    List[str]                   = field(default_factory=list)
    flagged_items: List[Dict[str, Any]]        = field(default_factory=list)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def flagged_count(self) -> int:
        """Number of affected resources."""
        return len(self.flagged_items)

    @property
    def severity_rank(self) -> int:
        """Lower is more severe; used for sorting."""
        return SEVERITY_ORDER.get(self.severity.upper(), 99)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (suitable for JSON output)."""
        return {
            "rule_id":       self.rule_id,
            "name":          self.name,
            "description":   self.description,
            "severity":      self.severity,
            "service":       self.service,
            "provider":      self.provider,
            "resource_path": self.resource_path,
            "remediation":   self.remediation,
            "compliance":    self.compliance,
            "references":    self.references,
            "flagged_items": self.flagged_items,
            "flagged_count": self.flagged_count,
        }

    def __lt__(self, other: "Finding") -> bool:
        return self.severity_rank < other.severity_rank
