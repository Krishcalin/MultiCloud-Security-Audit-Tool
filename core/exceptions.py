"""Exception/suppression management.

Loads an ``exceptions.yaml`` file and applies suppressions to a list of
:class:`~core.finding.Finding` objects.

exceptions.yaml format::

    suppressions:
      - rule_id: SM-01
        resource: "my-secret"        # optional: prefix match on flagged_item id
        provider: aws                # optional
        service: secretsmanager      # optional
        reason: "External rotation via Vault"
        expires: "2026-12-31"        # optional ISO date

      - rule_id: ECR-02
        reason: "Tag immutability enforced via CI/CD"

      - service: cosmosdb
        reason: "Managed by separate team"
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


@dataclass
class Suppression:
    reason:   str
    rule_id:  Optional[str] = None
    resource: Optional[str] = None   # prefix match on flagged_item["id"]
    service:  Optional[str] = None
    provider: Optional[str] = None
    expires:  Optional[str] = None   # ISO date string

    def is_expired(self) -> bool:
        if not self.expires:
            return False
        try:
            return date.fromisoformat(self.expires) < date.today()
        except ValueError:
            return False


class ExceptionSet:
    def __init__(self, suppressions: List[Suppression]) -> None:
        self._suppressions = suppressions

    def matches(self, finding: Any) -> Optional[Suppression]:
        """Return the first non-expired Suppression that matches *finding*, or None."""
        for sup in self._suppressions:
            if sup.is_expired():
                continue
            if sup.rule_id  and sup.rule_id.upper()  != getattr(finding, "rule_id", "").upper():
                continue
            if sup.service  and sup.service.lower()  != getattr(finding, "service", "").lower():
                continue
            if sup.provider and sup.provider.lower() != getattr(finding, "provider", "").lower():
                continue
            # If resource specified, at least one flagged_item must match (prefix)
            if sup.resource:
                items = getattr(finding, "flagged_items", []) or []
                if not any(
                    str(item.get("id", "")).startswith(sup.resource)
                    for item in items
                ):
                    continue
            return sup
        return None

    def __len__(self) -> int:
        return len(self._suppressions)


def load_exceptions(path: str) -> ExceptionSet:
    """Load an exceptions YAML file and return an :class:`ExceptionSet`."""
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        # Fall back to simple YAML parser for basic cases
        log.warning("PyYAML not installed — exceptions file will be ignored")
        return ExceptionSet([])

    import pathlib
    text = pathlib.Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}

    suppressions: List[Suppression] = []
    for raw in data.get("suppressions", []):
        suppressions.append(Suppression(
            reason=raw.get("reason", "No reason given"),
            rule_id=raw.get("rule_id"),
            resource=raw.get("resource"),
            service=raw.get("service"),
            provider=raw.get("provider"),
            expires=raw.get("expires"),
        ))
    log.info("Loaded %d suppression(s) from %s", len(suppressions), path)
    return ExceptionSet(suppressions)


def apply_exceptions(
    findings: List[Any],
    exc_set: ExceptionSet,
) -> Tuple[List[Any], List[Tuple[Any, Suppression]]]:
    """Split findings into active and suppressed.

    Returns
    -------
    (active, suppressed)
        active:     findings not matched by any suppression
        suppressed: list of (finding, suppression) tuples
    """
    active     : List[Any]                      = []
    suppressed : List[Tuple[Any, Suppression]]  = []

    for f in findings:
        sup = exc_set.matches(f)
        if sup:
            suppressed.append((f, sup))
        else:
            active.append(f)

    return active, suppressed
