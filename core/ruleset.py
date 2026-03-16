"""Ruleset — loads a ruleset JSON file and instantiates :class:`Rule` objects.

Ruleset JSON format
-------------------
.. code-block:: json

    {
        "about": "Default ruleset — all providers",
        "rules": {
            "iam-root-mfa.json": [
                {"enabled": true, "level": "danger"}
            ],
            "ec2-sg-ssh-open.json": [
                {"args": ["SSH",  "TCP", "22"],   "enabled": true, "level": "danger"},
                {"args": ["RDP",  "TCP", "3389"], "enabled": true, "level": "danger"}
            ]
        }
    }

Each key in ``"rules"`` is a rule filename (searched in *rule_dirs*).
Each value is a list of instances — the same rule file can be instantiated
multiple times with different ``args``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from .rule import Rule, RuleDefinition


class Ruleset:
    """Parses a ruleset JSON file and exposes the enabled :class:`Rule` objects.

    Args
    ----
    ruleset_path:
        Path to the ruleset JSON file.
    rule_dirs:
        Directories searched (in order) when resolving rule filenames.
        If a rule filename is an absolute path it is used directly.
    """

    def __init__(
        self,
        ruleset_path: str | Path,
        rule_dirs:    Optional[List[str | Path]] = None,
    ) -> None:
        self.ruleset_path = Path(ruleset_path)
        self._rule_dirs: List[Path] = [Path(d) for d in (rule_dirs or [])]
        self.about: str = ""
        self.rules: List[Rule] = []
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Parse the ruleset file and instantiate all enabled rules."""
        with self.ruleset_path.open("r", encoding="utf-8") as fh:
            raw: Dict = json.load(fh)

        self.about = raw.get("about", "")
        rules_map: Dict[str, List[dict]] = raw.get("rules", {})

        for filename, instances in rules_map.items():
            definition = self._load_definition(filename)
            if definition is None:
                continue

            if not instances:
                instances = [{"enabled": True}]

            for instance in instances:
                enabled = instance.get("enabled", True)
                if not enabled:
                    continue
                rule = Rule(
                    definition=definition,
                    args=instance.get("args", []),
                    enabled=True,
                    level=instance.get("level"),
                    rule_dirs=self._rule_dirs,
                )
                self.rules.append(rule)

    def _load_definition(self, filename: str) -> Optional[RuleDefinition]:
        """Search *rule_dirs* for *filename* and return a :class:`RuleDefinition`."""
        candidates = [d / filename for d in self._rule_dirs]
        candidates.append(Path(filename))  # absolute / cwd fallback

        for candidate in candidates:
            if candidate.exists():
                try:
                    return RuleDefinition(candidate)
                except (ValueError, KeyError, json.JSONDecodeError) as exc:
                    print(f"[WARN] Could not load rule '{filename}': {exc}")
                    return None

        print(
            f"[WARN] Rule file not found: '{filename}' "
            f"(searched: {[str(d) for d in self._rule_dirs]})"
        )
        return None

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_rules_for_service(self, service: str) -> List[Rule]:
        """Return all enabled rules whose service matches *service* (case-insensitive)."""
        return [r for r in self.rules if r.service.lower() == service.lower()]

    def get_services(self) -> List[str]:
        """Return a sorted list of unique service names covered by this ruleset."""
        return sorted({r.service for r in self.rules})

    def get_providers(self) -> List[str]:
        """Return services grouped loosely; providers are resolved at scan time."""
        return self.get_services()

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def __repr__(self) -> str:
        return f"Ruleset(path={self.ruleset_path.name!r}, rules={len(self.rules)})"
