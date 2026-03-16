"""JSON encoder for multi-cloud scan results.

Handles:
- :class:`datetime`       → ISO 8601 string
- :class:`set`            → list
- :class:`pathlib.Path`   → string
- Objects with ``to_dict()`` → their dict
- Generic objects with ``__dict__`` → filtered dict
- Strips sensitive credential fields before serialisation
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, List

# Fields that must never appear in serialised output
_SENSITIVE_KEYS = frozenset({
    "password", "passwd", "secret", "secret_key", "access_key",
    "client_secret", "private_key", "token", "api_key", "credentials",
    "auth", "aws_secret_access_key", "aws_session_token", "connection_string",
})


class ScoutJsonEncoder(json.JSONEncoder):
    """Custom :class:`json.JSONEncoder` for scan results."""

    def default(self, obj: Any) -> Any:  # noqa: D102
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return sorted(obj)          # sorted for deterministic output
        if isinstance(obj, Path):
            return str(obj)
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if hasattr(obj, "__dict__"):
            return {
                k: v
                for k, v in obj.__dict__.items()
                if not k.startswith("_") and k.lower() not in _SENSITIVE_KEYS
            }
        return super().default(obj)


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def encode_findings(findings: List[Any], indent: int = 2) -> str:
    """Serialise a list of :class:`~core.finding.Finding` objects to JSON."""
    return json.dumps(
        [f.to_dict() if hasattr(f, "to_dict") else f for f in findings],
        cls=ScoutJsonEncoder,
        indent=indent,
    )


def encode_results(data: Any, indent: int = 2) -> str:
    """Serialise an arbitrary scan result object/dict to JSON."""
    return json.dumps(data, cls=ScoutJsonEncoder, indent=indent)


def save_json(findings: List[Any], path: str | Path) -> None:
    """Write *findings* as a JSON array to *path*."""
    Path(path).write_text(encode_findings(findings), encoding="utf-8")
