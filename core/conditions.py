"""Condition evaluation engine.

Condition format
----------------
Leaf (unary)  : ``["field.path", "operator"]``
Leaf (binary) : ``["field.path", "operator", expected_value]``
Self (unary)  : ``["operator"]``          — evaluates the item itself
Self (binary) : ``["operator", expected]`` — evaluates the item itself
Logic         : ``["and", cond1, cond2, ...]``
              : ``["or",  cond1, cond2, ...]``
              : ``["not", cond]``

Field paths use dot notation.  ``"."`` or ``""`` refers to the item itself.
Nested list indexing is supported: ``"items.0.name"``.

All operator names are case-insensitive.

Returns
-------
``True``  → the item **fails** the check (is flagged as a finding).
``False`` → the item **passes** (no issue detected).
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, List, Optional


# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------

def get_field(item: Any, path: str) -> Any:
    """Resolve a dot-notation *path* within *item*.

    ``"."`` or ``""`` returns *item* unchanged.
    Unknown keys or out-of-range indices return ``None``.
    """
    if not path or path == ".":
        return item
    current = item
    for part in path.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


# ---------------------------------------------------------------------------
# Operator sets
# ---------------------------------------------------------------------------

_LOGIC_OPS = {"and", "or", "not"}

_UNARY_OPS = {
    "null", "notnull",
    "empty", "notempty",
    "true", "false",
    "ispubliccidr",
}

_BINARY_OPS = {
    "equal", "notequal",
    "greaterthan", "lessthan", "greaterthanorequal", "lessthanorequal",
    "containstring", "notcontainstring",
    "startswith", "endswith",
    "match", "notmatch",
    "containatleastoneof", "containnoneof", "containatleastonematching",
    "withkey", "withoutkey", "withkeycaseinsensitive",
    "lengthequal", "lengthlesthan", "lengthmorthan",
    "insubnets", "notinsubnets",
    "olderthandays", "newerthandays",
}

_ALL_OPS = _UNARY_OPS | _BINARY_OPS


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def pass_conditions(conditions: List, item: Any) -> bool:  # noqa: C901
    """Evaluate a *conditions* expression against *item*.

    Returns ``True`` if the item **is flagged** (fails the check).
    """
    if not conditions or not isinstance(conditions, list):
        return False

    first = conditions[0]
    if not isinstance(first, str):
        return False

    op = first.lower()

    # ---- Logic operators --------------------------------------------------
    if op == "and":
        return all(pass_conditions(c, item) for c in conditions[1:])
    if op == "or":
        return any(pass_conditions(c, item) for c in conditions[1:])
    if op == "not":
        return (not pass_conditions(conditions[1], item)) if len(conditions) > 1 else False

    # ---- Leaf conditions --------------------------------------------------
    # Detect layout:
    #   [op]                     — unary, item is the value
    #   [op, expected]           — binary, item is the value
    #   [field, op]              — unary, value = get_field(item, field)
    #   [field, op, expected]    — binary, value = get_field(item, field)

    if op in _ALL_OPS:
        # No field path — evaluate the item directly
        field_value = item
        expected = conditions[1] if len(conditions) > 1 else None
    elif (
        len(conditions) >= 2
        and isinstance(conditions[1], str)
        and conditions[1].lower() in _ALL_OPS
    ):
        # Field path supplied as first element
        field_value = get_field(item, conditions[0])
        op = conditions[1].lower()
        expected = conditions[2] if len(conditions) > 2 else None
    else:
        return False  # Unrecognised format

    return _evaluate(op, field_value, expected)


# ---------------------------------------------------------------------------
# Single-operator evaluation
# ---------------------------------------------------------------------------

def _to_datetime(value: Any) -> Optional[datetime]:
    """Parse *value* into an aware :class:`datetime`, or return ``None``."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        formats = (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d",
        )
        for fmt in formats:
            try:
                dt = datetime.strptime(value.replace("Z", "+00:00"), fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _is_public_cidr(cidr_str: str) -> bool:
    """Return ``True`` if *cidr_str* is publicly routable."""
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
        return not (
            net.is_private
            or net.is_loopback
            or net.is_link_local
            or net.is_reserved
            or net.is_multicast
        )
    except ValueError:
        return False


def _evaluate(op: str, value: Any, expected: Any) -> bool:  # noqa: C901
    """Evaluate a single *op* against *value* and *expected*.

    Returns ``True`` if the item **is flagged**.
    """
    try:
        # Null / empty
        if op == "null":
            return value is None
        if op == "notnull":
            return value is not None
        if op == "empty":
            if value is None:
                return True
            return len(value) == 0 if hasattr(value, "__len__") else False
        if op == "notempty":
            if value is None:
                return False
            return len(value) > 0 if hasattr(value, "__len__") else True

        # Boolean
        if op == "true":
            return value is True or value == 1 or str(value).lower() == "true"
        if op == "false":
            return value is False or value == 0 or str(value).lower() == "false"

        # Equality / comparison
        if op == "equal":
            return value == expected
        if op == "notequal":
            return value != expected
        if op == "greaterthan":
            return value > expected
        if op == "lessthan":
            return value < expected
        if op == "greaterthanorequal":
            return value >= expected
        if op == "lessthanorequal":
            return value <= expected

        # String
        if op == "containstring":
            return isinstance(value, str) and str(expected) in value
        if op == "notcontainstring":
            return isinstance(value, str) and str(expected) not in value
        if op == "startswith":
            return isinstance(value, str) and value.startswith(str(expected))
        if op == "endswith":
            return isinstance(value, str) and value.endswith(str(expected))
        if op == "match":
            return bool(re.search(str(expected), str(value), re.IGNORECASE)) if value is not None else False
        if op == "notmatch":
            return not bool(re.search(str(expected), str(value), re.IGNORECASE)) if value is not None else True

        # List membership
        if op == "containatleastoneof":
            if not isinstance(value, (list, set, tuple)):
                return False
            return any(v in value for v in (expected or []))
        if op == "containnoneof":
            if not isinstance(value, (list, set, tuple)):
                return True
            return not any(v in value for v in (expected or []))
        if op == "containatleastonematching":
            if not isinstance(value, (list, set, tuple)):
                return False
            return any(bool(re.search(str(expected), str(v), re.IGNORECASE)) for v in value)

        # Dict key checks
        if op == "withkey":
            return isinstance(value, dict) and expected in value
        if op == "withoutkey":
            return isinstance(value, dict) and expected not in value
        if op == "withkeycaseinsensitive":
            if not isinstance(value, dict):
                return False
            return any(k.lower() == str(expected).lower() for k in value)

        # Length
        if op == "lengthequal":
            return hasattr(value, "__len__") and len(value) == int(expected)
        if op == "lengthlesthan":
            return hasattr(value, "__len__") and len(value) < int(expected)
        if op == "lengthmorthan":
            return hasattr(value, "__len__") and len(value) > int(expected)

        # Network
        if op == "insubnets":
            addr = ipaddress.ip_address(str(value))
            return any(addr in ipaddress.ip_network(s, strict=False) for s in (expected or []))
        if op == "notinsubnets":
            addr = ipaddress.ip_address(str(value))
            return not any(addr in ipaddress.ip_network(s, strict=False) for s in (expected or []))
        if op == "ispubliccidr":
            return _is_public_cidr(str(value)) if value else False

        # Date
        if op == "olderthandays":
            dt = _to_datetime(value)
            return (datetime.now(timezone.utc) - dt).days > int(expected) if dt else False
        if op == "newerthandays":
            dt = _to_datetime(value)
            return (datetime.now(timezone.utc) - dt).days < int(expected) if dt else False

    except (TypeError, ValueError, AttributeError):
        return False

    return False  # Unknown operator
