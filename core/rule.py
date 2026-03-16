"""Rule and RuleDefinition classes.

Rule file format (JSON)
-----------------------
.. code-block:: json

    {
        "id":          "IAM-01",
        "name":        "Root account MFA not enabled",
        "description": "The AWS root account does not have MFA enabled.",
        "severity":    "CRITICAL",
        "service":     "iam",
        "path":        "iam.account_summary",
        "conditions":  ["equal", "AccountMFAEnabled", 0],
        "remediation": "Enable MFA on the root account in the IAM console.",
        "compliance":  [{"name": "CIS AWS Foundations", "version": "3.0", "reference": "1.5"}],
        "references":  ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"],
        "enabled":     true
    }

Path conventions
----------------
- ``"iam.account_summary"``    → evaluate conditions against ``data["iam"]["account_summary"]``
- ``"iam.users.*"``            → iterate all values in ``data["iam"]["users"]``
- ``"ec2.regions.*.vpcs.*"``   → nested iteration

Parameterisation
----------------
Tokens ``_ARG_0_``, ``_ARG_1_``, … are replaced with values from the
``args`` list supplied in the ruleset entry.  This lets a single rule
file cover multiple parameterised checks (e.g. per-port SG checks).

Shared conditions
-----------------
``_INCLUDE_(path/to/conditions.json)`` inside a conditions array is
resolved by loading the referenced JSON file and inlining its content.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# RuleDefinition — raw JSON loader
# ---------------------------------------------------------------------------

class RuleDefinition:
    """Loads and exposes every field from a rule JSON file via attributes."""

    REQUIRED_FIELDS = ("id", "name", "description", "severity", "service", "path", "conditions")
    VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def __init__(self, filepath: str | Path) -> None:
        self.filepath = Path(filepath)
        with self.filepath.open("r", encoding="utf-8") as fh:
            raw: Dict[str, Any] = json.load(fh)

        for key, val in raw.items():
            setattr(self, key, val)

        # Validate required fields
        for field in self.REQUIRED_FIELDS:
            if not hasattr(self, field):
                raise ValueError(f"Rule '{filepath}' is missing required field '{field}'")

        self.severity = str(self.severity).upper()
        if self.severity not in self.VALID_SEVERITIES:
            raise ValueError(
                f"Rule '{getattr(self, 'id', filepath)}': invalid severity '{self.severity}'. "
                f"Must be one of {self.VALID_SEVERITIES}."
            )

        # Optional fields with defaults
        if not hasattr(self, "remediation"):
            self.remediation = ""
        if not hasattr(self, "compliance"):
            self.compliance = []
        if not hasattr(self, "references"):
            self.references = []
        if not hasattr(self, "enabled"):
            self.enabled = True

    def __repr__(self) -> str:
        return f"RuleDefinition(id={getattr(self, 'id', '?')!r}, file={self.filepath.name!r})"


# ---------------------------------------------------------------------------
# Rule — instantiated rule with resolved substitutions
# ---------------------------------------------------------------------------

class Rule:
    """An instantiated rule derived from a :class:`RuleDefinition`.

    Args substitution (``_ARG_N_``) and shared-condition includes
    (``_INCLUDE_(path)``) are resolved at construction time.
    """

    _ARG_RE     = re.compile(r"_ARG_(\d+)_")
    _INCLUDE_RE = re.compile(r"_INCLUDE_\(([^)]+)\)")

    def __init__(
        self,
        definition: RuleDefinition,
        args:      Optional[List[Any]] = None,
        enabled:   bool = True,
        level:     Optional[str] = None,
        rule_dirs: Optional[List[Path]] = None,
    ) -> None:
        self.definition = definition
        self.args       = args or []
        self.enabled    = enabled
        self.level      = level        # danger | warning | info (optional ruleset override)
        self._rule_dirs = rule_dirs or []

        self._resolved: Dict[str, Any] = self._resolve()

    # ------------------------------------------------------------------
    # Public properties (resolved values)
    # ------------------------------------------------------------------

    @property
    def id(self) -> str:
        return self._resolved.get("id", self.definition.id)

    @property
    def name(self) -> str:
        return self._resolved.get("name", self.definition.name)

    @property
    def description(self) -> str:
        return self._resolved.get("description", self.definition.description)

    @property
    def severity(self) -> str:
        return self._resolved.get("severity", self.definition.severity)

    @property
    def service(self) -> str:
        return self._resolved.get("service", self.definition.service)

    @property
    def path(self) -> str:
        return self._resolved.get("path", self.definition.path)

    @property
    def conditions(self) -> List:
        return self._resolved.get("conditions", self.definition.conditions)

    @property
    def remediation(self) -> str:
        return self._resolved.get("remediation", self.definition.remediation)

    @property
    def compliance(self) -> List[Dict[str, str]]:
        return self._resolved.get("compliance", self.definition.compliance)

    @property
    def references(self) -> List[str]:
        return self._resolved.get("references", self.definition.references)

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------

    def _resolve(self) -> Dict[str, Any]:
        """Deep-copy all definition attributes and apply token substitutions."""
        resolved: Dict[str, Any] = {}
        for key in vars(self.definition):
            if key.startswith("_"):
                continue
            val = getattr(self.definition, key)
            resolved[key] = self._substitute(deepcopy(val))
        return resolved

    def _substitute(self, obj: Any) -> Any:  # noqa: C901
        """Recursively replace ``_ARG_N_`` tokens and resolve ``_INCLUDE_()``.

        Processes strings, lists, and dicts.
        """
        if isinstance(obj, str):
            # _ARG_N_ substitution
            def _arg_replacer(m: re.Match) -> str:
                idx = int(m.group(1))
                return str(self.args[idx]) if idx < len(self.args) else m.group(0)

            obj = self._ARG_RE.sub(_arg_replacer, obj)
            return obj

        if isinstance(obj, list):
            result: List[Any] = []
            for item in obj:
                if isinstance(item, str):
                    m = self._INCLUDE_RE.fullmatch(item)
                    if m:
                        # Inline the referenced conditions file
                        included = self._load_include(m.group(1))
                        if isinstance(included, list):
                            result.extend(self._substitute(included))
                        continue
                result.append(self._substitute(item))
            return result

        if isinstance(obj, dict):
            return {k: self._substitute(v) for k, v in obj.items()}

        return obj

    def _load_include(self, include_path: str) -> Any:
        """Locate and load a shared conditions JSON file."""
        path = Path(include_path)

        if not path.is_absolute():
            for rule_dir in self._rule_dirs:
                candidate = Path(rule_dir) / include_path
                if candidate.exists():
                    path = candidate
                    break

        try:
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[WARN] Could not load _INCLUDE_({include_path}): {exc}")
            return []

    def __repr__(self) -> str:
        return (
            f"Rule(id={self.id!r}, severity={self.severity!r}, "
            f"service={self.service!r}, path={self.path!r})"
        )
