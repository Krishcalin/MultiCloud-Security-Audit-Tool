"""ProcessingEngine — evaluates ruleset rules against a collected data dict.

Data dict structure
-------------------
The data dict is a nested structure built by each provider's ``fetch()`` method.
Example (AWS)::

    {
        "iam": {
            "account_summary": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1},
            "users": {
                "alice": {"name": "alice", "LoginProfile": {...}, "MFADevices": []},
                "bob":   {"name": "bob",   "LoginProfile": None,  "MFADevices": ["arn:..."]}
            }
        },
        "s3": {
            "buckets": {
                "my-public-bucket": {"PublicAccessBlock": {"BlockPublicAcls": False}, ...}
            }
        }
    }

Path wildcards
--------------
``*`` in a path segment means *iterate all values at this level*.

- ``"iam.account_summary"``     → evaluates conditions against the scalar/dict at that path
- ``"iam.users.*"``             → iterates all values in ``data["iam"]["users"]``
- ``"ec2.regions.*.vpcs.*"``    → doubly-nested iteration (each vpc in each region)
"""

from __future__ import annotations

from typing import Any, Dict, Generator, List, Tuple

from .conditions import pass_conditions
from .finding import Finding
from .rule import Rule
from .ruleset import Ruleset


class ProcessingEngine:
    """Evaluates all rules in a *ruleset* against a provider's *data* dict.

    Usage::

        engine = ProcessingEngine(ruleset)
        findings = engine.run(data, provider="aws")
    """

    def __init__(self, ruleset: Ruleset) -> None:
        self.ruleset = ruleset

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, data: Dict[str, Any], provider: str = "") -> List[Finding]:
        """Evaluate every enabled rule against *data*.

        Args
        ----
        data:     Nested dict produced by ``BaseProvider.get_data()``.
        provider: Cloud provider name (``"aws"``, ``"azure"``, ``"gcp"``).

        Returns
        -------
        Sorted list of :class:`~core.finding.Finding` objects (most severe first).
        """
        findings: List[Finding] = []
        for rule in self.ruleset.rules:
            rule_findings = self._evaluate_rule(rule, data, provider)
            findings.extend(rule_findings)
        return sorted(findings)

    # ------------------------------------------------------------------
    # Rule evaluation
    # ------------------------------------------------------------------

    def _evaluate_rule(
        self,
        rule:     Rule,
        data:     Dict[str, Any],
        provider: str,
    ) -> List[Finding]:
        """Walk *rule.path* in *data*, apply conditions to each item."""
        path_parts = [p for p in rule.path.split(".") if p]
        items: List[Tuple[str, Any]] = list(self._walk(data, path_parts, "root"))

        if not items:
            return []

        flagged: List[Dict[str, Any]] = []
        for item_id, item_value in items:
            try:
                if pass_conditions(rule.conditions, item_value):
                    flagged.append({"id": item_id, "details": item_value})
            except Exception:  # noqa: BLE001
                # Condition evaluation errors are non-fatal
                pass

        if not flagged:
            return []

        return [
            Finding(
                rule_id=rule.id,
                name=rule.name,
                description=rule.description,
                severity=rule.severity,
                service=rule.service,
                provider=provider,
                resource_path=rule.path,
                remediation=rule.remediation,
                compliance=rule.compliance,
                references=rule.references,
                flagged_items=flagged,
            )
        ]

    # ------------------------------------------------------------------
    # Path walking
    # ------------------------------------------------------------------

    def _walk(
        self,
        current:   Any,
        remaining: List[str],
        item_id:   str,
    ) -> Generator[Tuple[str, Any], None, None]:
        """Recursively walk *remaining* path segments.

        Yields ``(item_id, item_value)`` tuples at every leaf reached.
        ``"*"`` expands to iterate all values at the current level.
        """
        if not remaining:
            yield (item_id, current)
            return

        seg  = remaining[0]
        rest = remaining[1:]

        if seg == "*":
            # Expand all children
            if isinstance(current, dict):
                for key, val in current.items():
                    yield from self._walk(val, rest, key)
            elif isinstance(current, (list, tuple)):
                for i, val in enumerate(current):
                    yield from self._walk(val, rest, str(i))
            # Scalar with * → nothing to iterate; skip silently

        else:
            # Named navigation
            if isinstance(current, dict):
                child = current.get(seg)
                if child is not None:
                    yield from self._walk(child, rest, seg)
            elif isinstance(current, (list, tuple)):
                try:
                    child = current[int(seg)]
                    yield from self._walk(child, rest, seg)
                except (ValueError, IndexError):
                    pass
