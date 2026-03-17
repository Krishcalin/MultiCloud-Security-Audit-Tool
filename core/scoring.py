"""Security posture score engine.

Computes a weighted 0–100 risk score from a list of :class:`~core.finding.Finding`
objects, assigns a letter grade, and provides a per-severity penalty breakdown.

Scoring model
-------------
Each distinct finding (rule) contributes a flat severity penalty:

+----------+---------+
| Severity | Penalty |
+==========+=========+
| CRITICAL |      40 |
| HIGH     |      15 |
| MEDIUM   |       5 |
| LOW      |       1 |
| INFO     |       0 |
+----------+---------+

The total penalty is capped at 300 then mapped linearly to 0–100::

    score = max(0, round(100 - penalty / MAX_PENALTY * 100))

Grade bands
-----------
| Score  | Grade | Label     |
|--------|-------|-----------|
| 90–100 | A     | Excellent |
| 75–89  | B     | Good      |
| 60–74  | C     | Fair      |
| 40–59  | D     | Poor      |
|  0–39  | F     | Critical  |
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 40,
    "HIGH":     15,
    "MEDIUM":    5,
    "LOW":       1,
    "INFO":      0,
}

MAX_PENALTY = 300  # penalty value that maps to score 0

_GRADES = [
    (90, "A", "Excellent", "#3fb950"),
    (75, "B", "Good",      "#58a6ff"),
    (60, "C", "Fair",      "#ffcc00"),
    (40, "D", "Poor",      "#ff8800"),
    ( 0, "F", "Critical",  "#ff4444"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_score(findings: List[Any]) -> Dict[str, Any]:
    """Compute a posture score dict from a list of Finding objects.

    Parameters
    ----------
    findings:
        List of :class:`~core.finding.Finding` instances.

    Returns
    -------
    dict with keys:
    - ``score``      int 0–100
    - ``grade``      str  "A" | "B" | "C" | "D" | "F"
    - ``label``      str  human-readable label
    - ``color``      str  hex colour matching the grade
    - ``penalty``    int  raw penalty (before capping)
    - ``breakdown``  dict  per-severity finding counts
    """
    sev_counter: Counter = Counter()
    penalty = 0

    for f in findings:
        sev    = getattr(f, "severity", "INFO")
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        penalty += weight
        sev_counter[sev] += 1

    capped_penalty = min(penalty, MAX_PENALTY)
    score = max(0, round(100 - capped_penalty / MAX_PENALTY * 100))

    grade, label, color = "F", "Critical", "#ff4444"
    for threshold, g, l, c in _GRADES:
        if score >= threshold:
            grade, label, color = g, l, c
            break

    return {
        "score":     score,
        "grade":     grade,
        "label":     label,
        "color":     color,
        "penalty":   penalty,
        "breakdown": {s: sev_counter.get(s, 0) for s in SEVERITY_WEIGHTS},
    }
