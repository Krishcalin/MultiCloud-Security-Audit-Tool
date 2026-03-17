"""HTML report generator — Phase 7 enhanced edition.

Produces a self-contained, single-file HTML report with:

- **Security Posture Score** — SVG arc gauge (0–100), letter grade, severity breakdown
- **Compliance Exposure** — per-framework cards (CIS, PCI-DSS, HIPAA, ISO 27001, …)
- **Provider Summary** — per-cloud finding cards with severity bars
- **Service Breakdown** — sortable table: service × severity × affected resources
- **Findings Table** — filterable, searchable, expandable detail rows with
  description, remediation, compliance references and affected resource list

Usage::

    from output.report import save_html
    save_html(findings, path="report.html", meta={...}, posture=score_dict, compliance=frameworks_dict)
"""

from __future__ import annotations

import html as _html
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.finding import SEVERITY_COLOUR, Finding

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_SEV_BADGE = {
    "CRITICAL": "badge-critical",
    "HIGH":     "badge-high",
    "MEDIUM":   "badge-medium",
    "LOW":      "badge-low",
    "INFO":     "badge-info",
}

_PROVIDER_COLOUR = {
    "aws":   "#ff9900",
    "azure": "#0078d4",
    "gcp":   "#34a853",
    "demo":  "#8b949e",
}

_FRAMEWORK_ICON = {
    "CIS Benchmarks":       "&#9670;",
    "PCI-DSS":              "&#128179;",
    "HIPAA":                "&#10010;",
    "SOC 2":                "&#10003;",
    "ISO 27001":            "&#9737;",
    "NIST CSF":             "&#9881;",
    "AWS Well-Architected": "&#9729;",
}

# Gauge arc circumference (π × r=80, semicircle)
_GAUGE_CIRC = 251.33


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_html(
    findings:   List[Finding],
    path:       str | Path,
    meta:       Optional[Dict[str, Any]] = None,
    posture:    Optional[Dict[str, Any]] = None,
    compliance: Optional[Dict[str, Any]] = None,
    suppressed: Optional[List[Any]] = None,
) -> None:
    """Render findings to a self-contained HTML file.

    Parameters
    ----------
    findings:   List of Finding objects (sorted before rendering).
    path:       Output file path.
    meta:       Optional scan metadata (scan_date, account, version, …).
    posture:    Optional score dict from :func:`core.scoring.compute_score`.
    compliance: Optional frameworks dict from :func:`core.compliance.aggregate_compliance`.
    suppressed: Optional list of suppressed Finding objects (greyed-out section).
    """
    meta = meta or {}

    # Compute posture and compliance inline if not provided
    if posture is None:
        from core.scoring import compute_score
        posture = compute_score(findings)
    if compliance is None:
        from core.compliance import aggregate_compliance
        compliance = aggregate_compliance(findings)

    html = _render(findings, meta, posture, compliance, suppressed=suppressed or [])
    Path(path).write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# Top-level renderer
# ---------------------------------------------------------------------------

def _render(
    findings:   List[Finding],
    meta:       Dict[str, Any],
    posture:    Dict[str, Any],
    compliance: Dict[str, Any],
    suppressed: List[Any] = None,
) -> str:
    suppressed = suppressed or []
    scan_date = meta.get("scan_date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    version   = meta.get("version", "")
    account   = meta.get("account", "")

    sev_counts:      Counter              = Counter(f.severity for f in findings)
    total_findings   = len(findings)
    total_resources  = sum(f.flagged_count for f in findings)

    providers: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        providers[f.provider or "unknown"].append(f)

    # Service breakdown: service → {sev: count, resources: count}
    services: Dict[str, Any] = defaultdict(lambda: Counter())
    svc_resources: Dict[str, int] = defaultdict(int)
    for f in findings:
        svc = f.service or "unknown"
        services[svc][f.severity] += 1
        svc_resources[svc] += f.flagged_count

    # Build HTML sections
    header_html      = _header(version, scan_date, account, providers, suppressed_count=len(suppressed))
    posture_html     = _posture_section(posture, sev_counts, total_findings, total_resources)
    compliance_html  = _compliance_section(compliance) if compliance else ""
    providers_html   = _providers_section(providers)
    service_html     = _service_section(services, svc_resources)
    findings_html    = _findings_section(findings, providers)
    suppressed_html  = _suppressed_section(suppressed) if suppressed else ""
    findings_json    = _html.escape(json.dumps([f.to_dict() for f in findings], default=str), quote=True)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>MultiCloud Security Audit Report</title>
{_css()}
</head>
<body>

{header_html}

<div class="container">
{posture_html}
{compliance_html}
{providers_html}
{service_html}
{findings_html}
{suppressed_html}
</div>

<div class="footer">
  MultiCloud Security Audit Tool &mdash; For authorised security assessments only.
  Read-only API calls. No resources modified.
</div>

{_js(findings_json)}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

def _header(version: str, scan_date: str, account: str, providers: Dict, suppressed_count: int = 0) -> str:
    prov_badges = ""
    for p in ["aws", "azure", "gcp"]:
        colour = _PROVIDER_COLOUR.get(p, "#888")
        active = "active" if p in providers else ""
        prov_badges += (
            f'<span class="hbadge {active}" style="'
            f'border-color:{colour};'
            f'{"color:" + colour + ";background:rgba(0,0,0,0.3)" if active else "color:#484f58"}'
            f'">{p.upper()}</span>'
        )
    if suppressed_count:
        prov_badges += (
            f'<span class="hbadge" style="border-color:#555;color:#8b949e" '
            f'title="{suppressed_count} finding(s) suppressed via exceptions file">'
            f'&#128683; {suppressed_count} suppressed</span>'
        )
    meta_parts = [_html.escape(scan_date)]
    if account:
        meta_parts.append(_html.escape(account))
    if version:
        meta_parts.append(f"v{_html.escape(version)}")

    return f"""<div class="header">
  <div class="header-inner">
    <div class="logo-row">
      <div class="logo-shield">
        <svg width="40" height="44" viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M20 2 L36 8 L36 22 C36 31 20 42 20 42 C20 42 4 31 4 22 L4 8 Z" fill="#161b22" stroke="#58a6ff" stroke-width="1.5"/>
          <path d="M20 10 L28 13 L28 22 C28 27 20 33 20 33 C20 33 12 27 12 22 L12 13 Z" fill="#58a6ff" opacity="0.2"/>
          <line x1="15" y1="21" x2="19" y2="25" stroke="#58a6ff" stroke-width="2" stroke-linecap="round"/>
          <line x1="19" y1="25" x2="26" y2="17" stroke="#58a6ff" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </div>
      <div>
        <div class="logo-title">MultiCloud Security Audit</div>
        <div class="logo-sub">{" &nbsp;&bull;&nbsp; ".join(meta_parts)}</div>
      </div>
    </div>
    <div class="badge-row">{prov_badges}</div>
  </div>
</div>"""


# ---------------------------------------------------------------------------
# Posture Score section
# ---------------------------------------------------------------------------

def _posture_section(
    posture:    Dict[str, Any],
    sev_counts: Counter,
    total:      int,
    resources:  int,
) -> str:
    score   = posture["score"]
    grade   = posture["grade"]
    label   = posture["label"]
    color   = posture["color"]
    filled  = round(score / 100 * _GAUGE_CIRC, 1)

    # Severity stat rows
    stat_rows = ""
    for sev in _SEV_ORDER:
        cnt    = sev_counts.get(sev, 0)
        sc     = SEVERITY_COLOUR.get(sev, "#aaa")
        badge  = _SEV_BADGE.get(sev, "badge-info")
        stat_rows += (
            f'<div class="stat-row" onclick="filterBySeverity(\'{sev}\')" title="Filter by {sev}">'
            f'  <span class="badge {badge}">{sev}</span>'
            f'  <span class="stat-bar-wrap"><span class="stat-bar" style="width:{min(cnt*4,100)}%;background:{sc}"></span></span>'
            f'  <span class="stat-count" style="color:{sc}">{cnt}</span>'
            f'</div>'
        )

    # Quick summary cards
    quick = (
        f'<div class="qcard"><div class="qcard-n">{total}</div><div class="qcard-l">Total Findings</div></div>'
        f'<div class="qcard"><div class="qcard-n" style="color:#58a6ff">{resources}</div><div class="qcard-l">Affected Resources</div></div>'
    )

    return f"""<section class="section posture-section">
  <h2 class="section-title">Security Posture</h2>
  <div class="posture-row">

    <!-- Gauge -->
    <div class="gauge-wrap">
      <svg viewBox="0 0 200 130" width="200" height="130" xmlns="http://www.w3.org/2000/svg">
        <!-- Track -->
        <path d="M20,105 A80,80 0 0,1 180,105" fill="none" stroke="#21262d" stroke-width="14" stroke-linecap="round"/>
        <!-- Fill -->
        <path d="M20,105 A80,80 0 0,1 180,105" fill="none" stroke="{color}" stroke-width="14"
              stroke-linecap="round" stroke-dasharray="{filled} 999" class="gauge-fill"/>
        <!-- Score -->
        <text x="100" y="92" text-anchor="middle" font-size="40" font-weight="700"
              fill="{color}" font-family="system-ui,sans-serif">{score}</text>
        <!-- Grade label -->
        <text x="100" y="115" text-anchor="middle" font-size="13" fill="#8b949e"
              font-family="system-ui,sans-serif">Grade {_html.escape(grade)} &mdash; {_html.escape(label)}</text>
      </svg>
      <div class="gauge-caption">Posture Score</div>
    </div>

    <!-- Severity stats -->
    <div class="sev-stats">
      <div class="sev-stats-title">Findings by Severity</div>
      {stat_rows}
    </div>

    <!-- Quick cards -->
    <div class="quick-cards">
      {quick}
    </div>

  </div>
</section>"""


# ---------------------------------------------------------------------------
# Compliance Exposure section
# ---------------------------------------------------------------------------

def _compliance_section(compliance: Dict[str, Any]) -> str:
    if not compliance:
        return ""

    cards = ""
    for framework, data in compliance.items():
        icon  = _FRAMEWORK_ICON.get(framework, "&#9632;")
        fc    = data["finding_count"]
        crit  = data.get("critical", 0)
        high  = data.get("high", 0)
        med   = data.get("medium", 0)
        low   = data.get("low", 0)

        # Severity mini-pills
        pills = ""
        for sev, cnt, clr in [
            ("CRIT", crit, "#ff4444"),
            ("HIGH", high, "#ff8800"),
            ("MED",  med,  "#ffcc00"),
            ("LOW",  low,  "#66b3ff"),
        ]:
            if cnt:
                pills += f'<span class="cpill" style="color:{clr};border-color:{clr}">{cnt} {sev}</span>'

        # Control references (first 4)
        refs_html = ""
        for ref in data.get("refs", [])[:4]:
            refs_html += f'<li class="cref-item">{_html.escape(ref)}</li>'
        if len(data.get("refs", [])) > 4:
            refs_html += f'<li class="cref-item cref-more">+{len(data["refs"]) - 4} more&hellip;</li>'

        cards += f"""<div class="comp-card">
  <div class="comp-header">
    <span class="comp-icon">{icon}</span>
    <div>
      <div class="comp-name">{_html.escape(framework)}</div>
      <div class="comp-count">{fc} failing control{"s" if fc != 1 else ""}</div>
    </div>
  </div>
  <div class="comp-pills">{pills}</div>
  {('<ul class="cref-list">' + refs_html + '</ul>') if refs_html else ''}
</div>"""

    return f"""<section class="section">
  <h2 class="section-title">Compliance Exposure</h2>
  <div class="comp-cards">{cards}</div>
</section>"""


# ---------------------------------------------------------------------------
# Providers section
# ---------------------------------------------------------------------------

def _providers_section(providers: Dict[str, List[Finding]]) -> str:
    if not providers:
        return ""

    cards = ""
    for prov, pf in sorted(providers.items()):
        sev_c  = Counter(f.severity for f in pf)
        colour = _PROVIDER_COLOUR.get(prov.lower(), "#8b949e")

        bars = ""
        for sev in _SEV_ORDER:
            cnt = sev_c.get(sev, 0)
            if cnt:
                sc = SEVERITY_COLOUR.get(sev, "#aaa")
                badge = _SEV_BADGE.get(sev, "badge-info")
                bars += (
                    f'<div class="pbar-row" onclick="filterByProvider(\'{_html.escape(prov)}\')">'
                    f'  <span class="badge {badge}" style="min-width:70px;text-align:center">{sev}</span>'
                    f'  <div class="pbar-track"><div class="pbar-fill" style="width:{min(cnt*8,100)}%;background:{sc}"></div></div>'
                    f'  <span class="pbar-count" style="color:{sc}">{cnt}</span>'
                    f'</div>'
                )

        cards += f"""<div class="pcard" onclick="filterByProvider('{_html.escape(prov)}')">
  <div class="pcard-hdr" style="border-left:3px solid {colour}">
    <span class="pcard-name" style="color:{colour}">{_html.escape(prov.upper())}</span>
    <span class="pcard-total">{len(pf)} findings</span>
  </div>
  <div class="pcard-bars">{bars}</div>
</div>"""

    return f"""<section class="section">
  <h2 class="section-title">Providers</h2>
  <div class="pcards">{cards}</div>
</section>"""


# ---------------------------------------------------------------------------
# Service Breakdown section
# ---------------------------------------------------------------------------

def _service_section(
    services:      Dict[str, Counter],
    svc_resources: Dict[str, int],
) -> str:
    if not services:
        return ""

    # Sort by total findings descending
    sorted_svcs = sorted(
        services.items(),
        key=lambda kv: sum(kv[1].values()),
        reverse=True,
    )

    rows = ""
    for svc, sev_c in sorted_svcs:
        total_f = sum(sev_c.values())
        res_cnt = svc_resources.get(svc, 0)

        cells = ""
        for sev in _SEV_ORDER:
            cnt = sev_c.get(sev, 0)
            sc  = SEVERITY_COLOUR.get(sev, "#aaa") if cnt else "#484f58"
            fw  = "700" if cnt else "400"
            cells += f'<td style="text-align:center;color:{sc};font-weight:{fw}">{cnt if cnt else "—"}</td>'

        rows += (
            f'<tr onclick="filterByService(\'{_html.escape(svc)}\')" style="cursor:pointer">'
            f'  <td class="svc-name">{_html.escape(svc)}</td>'
            f'{cells}'
            f'  <td style="text-align:center;color:#58a6ff;font-weight:600">{res_cnt}</td>'
            f'  <td style="text-align:center;font-weight:700;color:#e6edf3">{total_f}</td>'
            f'</tr>'
        )

    return f"""<section class="section">
  <h2 class="section-title">Findings by Service</h2>
  <div class="table-wrap">
    <table id="serviceTable">
      <thead>
        <tr>
          <th>Service</th>
          {''.join(f'<th style="text-align:center;color:{SEVERITY_COLOUR.get(s, "#aaa")}">{s}</th>' for s in _SEV_ORDER)}
          <th style="text-align:center;color:#58a6ff">Resources</th>
          <th style="text-align:center">Total</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>"""


# ---------------------------------------------------------------------------
# Findings section
# ---------------------------------------------------------------------------

def _findings_section(findings: List[Finding], providers: Dict) -> str:
    from output.remediation import get_remediation_commands

    total = len(findings)

    rows = ""
    for i, f in enumerate(findings):
        sev    = _html.escape(f.severity)
        badge  = _SEV_BADGE.get(f.severity, "badge-info")
        colour = SEVERITY_COLOUR.get(f.severity, "#aaa")
        rid    = _html.escape(f.rule_id)
        prov   = _html.escape(f.provider or "")
        svc    = _html.escape(f.service or "")
        name   = _html.escape(f.name)
        count  = f.flagged_count
        desc   = _html.escape(f.description)
        remed  = _html.escape(f.remediation)
        path   = _html.escape(f.resource_path)
        pc     = _PROVIDER_COLOUR.get((f.provider or "").lower(), "#8b949e")

        # Compliance pills
        comp_html = ""
        for c in (f.compliance or []):
            cname = _html.escape(c.get("name", ""))
            cref  = _html.escape(c.get("reference", ""))
            cver  = _html.escape(c.get("version", ""))
            label = cname
            if cver:
                label += f" v{cver}"
            if cref:
                label += f" §{cref}"
            comp_html += f'<span class="comp-pill">{label}</span> '

        # Reference links
        refs_html = ""
        for r in (f.references or []):
            sr = _html.escape(r)
            refs_html += f'<a href="{sr}" target="_blank" rel="noopener noreferrer">{sr}</a><br/>'

        # Affected resources
        res_html = ""
        for item in f.flagged_items[:5]:
            res_html += f'<li>{_html.escape(str(item.get("id", "")))}</li>'
        if count > 5:
            res_html += f'<li><em>&hellip; and {count - 5} more</em></li>'

        # Fix Commands panel
        fix_html = ""
        try:
            rem_entries = get_remediation_commands(f)
        except Exception:
            rem_entries = []
        if rem_entries:
            fix_id = f"fix{i}"
            fix_blocks = ""
            for entry in rem_entries:
                rid_val = _html.escape(entry["resource_id"])
                if entry["commands"]:
                    cmds_escaped = _html.escape("\n".join(entry["commands"]))
                    fix_blocks += f'<div class="fix-resource">Resource: <strong>{rid_val}</strong></div>'
                    fix_blocks += f'<pre class="fix-pre">{cmds_escaped}</pre>'
                if entry["note"]:
                    note_escaped = _html.escape(entry["note"])
                    fix_blocks += f'<div class="fix-note">[MANUAL] {rid_val}:<br/><pre class="fix-pre fix-note-pre">{note_escaped}</pre></div>'
            fix_html = (
                f'<div class="dl mt12">'
                f'<button class="fix-btn" onclick="toggleFix(\'{fix_id}\',this)">&#128295; Fix Commands</button>'
                f'</div>'
                f'<div id="{fix_id}" class="fix-panel" style="display:none">{fix_blocks}</div>'
            )

        did = f"d{i}"
        txt = _html.escape(f"{f.rule_id} {f.name} {f.description} {f.service}", quote=True).lower()

        rows += f"""<tr class="fr" data-severity="{sev}" data-provider="{prov}" data-service="{svc}" data-text="{txt}" style="border-left:3px solid {colour}">
  <td><span class="badge {badge}">{sev}</span></td>
  <td class="mono">{_html.escape(f.rule_id)}</td>
  <td><span class="ptag" style="border-color:{pc};color:{pc}">{prov.upper()}</span></td>
  <td>{svc}</td>
  <td><strong>{name}</strong></td>
  <td style="text-align:center;font-weight:700;color:{colour}">{count}</td>
  <td><button class="xbtn" onclick="toggleDetail('{did}',this)">&#9660;</button></td>
</tr>
<tr id="{did}" class="dr" style="display:none">
  <td colspan="7">
    <div class="dbox">
      <div class="dgrid">
        <div class="dcol">
          <div class="dl">Description</div>
          <div class="dv">{desc}</div>
          <div class="dl mt12">Remediation</div>
          <div class="dv remediation">{remed}</div>
          {fix_html}
          {('<div class="dl mt12">Compliance</div><div class="dv">' + comp_html + '</div>') if comp_html else ''}
          {('<div class="dl mt12">References</div><div class="dv">' + refs_html + '</div>') if refs_html else ''}
          <div class="dl mt12">Resource Path</div>
          <div class="dv mono">{path}</div>
        </div>
        <div class="dcol">
          <div class="dl">Affected Resources ({count})</div>
          <ul class="rlist">{res_html}</ul>
        </div>
      </div>
    </div>
  </td>
</tr>"""

    filter_provs = "".join(
        f'<option value="{_html.escape(p)}">{_html.escape(p.upper())}</option>'
        for p in sorted(providers)
    )
    filter_svcs = "".join(
        f'<option value="{_html.escape(s)}">{_html.escape(s)}</option>'
        for s in sorted({f.service for f in findings})
    )

    return f"""<section class="section">
  <h2 class="section-title">All Findings <span class="count-badge">{total}</span></h2>

  <div class="controls">
    <input id="search" type="text" placeholder="&#128269;  Search findings&hellip;" oninput="applyFilters()"/>
    <select id="fSev"  onchange="applyFilters()">
      <option value="">All Severities</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
      <option value="LOW">LOW</option>
      <option value="INFO">INFO</option>
    </select>
    <select id="fProv" onchange="applyFilters()">
      <option value="">All Providers</option>
      {filter_provs}
    </select>
    <select id="fSvc"  onchange="applyFilters()">
      <option value="">All Services</option>
      {filter_svcs}
    </select>
    <button onclick="clearFilters()">Clear</button>
  </div>

  <div class="table-wrap">
    <table id="ft">
      <thead>
        <tr>
          <th style="width:100px">Severity</th>
          <th style="width:100px">Rule ID</th>
          <th style="width:85px">Provider</th>
          <th style="width:110px">Service</th>
          <th>Finding</th>
          <th style="width:80px;text-align:center">Affected</th>
          <th style="width:40px"></th>
        </tr>
      </thead>
      <tbody id="tb">{rows}</tbody>
    </table>
    <div id="nr" class="no-results" style="display:none">No findings match the current filters.</div>
  </div>
</section>"""


# ---------------------------------------------------------------------------
# Suppressed Findings section
# ---------------------------------------------------------------------------

def _suppressed_section(suppressed_findings: List[Any]) -> str:
    if not suppressed_findings:
        return ""

    count = len(suppressed_findings)
    rows = ""
    for f in suppressed_findings:
        sev    = getattr(f, "severity", "INFO")
        badge  = _SEV_BADGE.get(sev, "badge-info")
        rid    = _html.escape(getattr(f, "rule_id", ""))
        prov   = _html.escape(getattr(f, "provider", "") or "")
        svc    = _html.escape(getattr(f, "service", "") or "")
        name   = _html.escape(getattr(f, "name", ""))
        pc     = _PROVIDER_COLOUR.get((getattr(f, "provider", "") or "").lower(), "#8b949e")
        flagged = getattr(f, "flagged_items", []) or []
        resources = ", ".join(_html.escape(str(item.get("id", ""))) for item in flagged[:3])
        if len(flagged) > 3:
            resources += f" (+{len(flagged) - 3} more)"

        rows += f"""<tr class="sup-row">
  <td><span class="badge {badge}">{_html.escape(sev)}</span></td>
  <td class="mono">{rid}</td>
  <td><span class="ptag" style="border-color:{pc};color:{pc}">{prov.upper()}</span></td>
  <td>{svc}</td>
  <td>{name}</td>
  <td class="sup-resources">{resources}</td>
</tr>"""

    return f"""<section id="suppressed" class="section" style="opacity:0.65">
  <h2 class="section-title">Suppressed Findings <span class="count-badge">{count}</span>
    <span style="font-size:11px;color:#8b949e;font-weight:400;margin-left:8px">&#128683; Matched by exceptions file</span>
  </h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th style="width:100px">Severity</th>
          <th style="width:100px">Rule ID</th>
          <th style="width:85px">Provider</th>
          <th style="width:110px">Service</th>
          <th>Finding</th>
          <th>Affected Resources</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</section>"""


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

def _css() -> str:
    return """<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:14px;line-height:1.6}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}

/* ===== HEADER ===== */
.header{background:linear-gradient(135deg,#161b22 0%,#1a2030 100%);border-bottom:1px solid #30363d;padding:18px 0}
.header-inner{max-width:1400px;margin:0 auto;padding:0 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.logo-row{display:flex;align-items:center;gap:14px}
.logo-shield{flex-shrink:0}
.logo-title{font-size:20px;font-weight:700;color:#e6edf3;letter-spacing:-.3px}
.logo-sub{font-size:12px;color:#8b949e;margin-top:2px}
.badge-row{display:flex;gap:8px}
.hbadge{padding:4px 12px;border-radius:12px;font-size:11px;font-weight:700;letter-spacing:.5px;border:1px solid #30363d;color:#484f58;transition:all .2s}
.hbadge.active{font-weight:800}

/* ===== LAYOUT ===== */
.container{max-width:1400px;margin:0 auto;padding:24px}
.section{margin-bottom:36px}
.section-title{font-size:15px;font-weight:600;color:#e6edf3;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:10px}
.count-badge{background:#21262d;color:#8b949e;border-radius:10px;padding:2px 8px;font-size:12px;font-weight:500}

/* ===== POSTURE SECTION ===== */
.posture-section{}
.posture-row{display:flex;flex-wrap:wrap;gap:24px;align-items:flex-start}
.gauge-wrap{display:flex;flex-direction:column;align-items:center;background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px 28px;min-width:200px}
.gauge-fill{transition:stroke-dasharray 1.2s cubic-bezier(.4,0,.2,1)}
.gauge-caption{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.6px;margin-top:4px}

.sev-stats{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:16px 20px;flex:1;min-width:260px}
.sev-stats-title{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px;font-weight:600}
.stat-row{display:flex;align-items:center;gap:10px;margin-bottom:8px;cursor:pointer;border-radius:6px;padding:3px 6px;transition:background .15s}
.stat-row:hover{background:#21262d}
.stat-bar-wrap{flex:1;height:6px;background:#21262d;border-radius:3px;overflow:hidden}
.stat-bar{height:100%;border-radius:3px;transition:width .8s ease-out;min-width:2px}
.stat-count{font-size:14px;font-weight:700;min-width:28px;text-align:right}

.quick-cards{display:flex;flex-direction:column;gap:12px}
.qcard{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:16px 22px;min-width:150px;text-align:center}
.qcard-n{font-size:32px;font-weight:700;line-height:1;color:#e6edf3}
.qcard-l{font-size:11px;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}

/* ===== COMPLIANCE SECTION ===== */
.comp-cards{display:flex;flex-wrap:wrap;gap:14px}
.comp-card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px 18px;min-width:220px;max-width:320px;flex:1}
.comp-header{display:flex;align-items:flex-start;gap:12px;margin-bottom:10px}
.comp-icon{font-size:22px;color:#58a6ff;flex-shrink:0;margin-top:2px}
.comp-name{font-size:14px;font-weight:700;color:#e6edf3}
.comp-count{font-size:12px;color:#8b949e;margin-top:2px}
.comp-pills{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px}
.cpill{font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;border:1px solid;background:rgba(0,0,0,.3)}
.cref-list{list-style:none;padding:0;border-top:1px solid #21262d;padding-top:8px}
.cref-item{font-size:11px;color:#8b949e;padding:2px 0;line-height:1.4}
.cref-more{font-style:italic;color:#484f58}

/* ===== PROVIDER CARDS ===== */
.pcards{display:flex;flex-wrap:wrap;gap:14px}
.pcard{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px 20px;min-width:220px;flex:1;cursor:pointer;transition:background .15s}
.pcard:hover{background:#1c2128}
.pcard-hdr{padding-left:10px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:baseline}
.pcard-name{font-size:15px;font-weight:700}
.pcard-total{font-size:12px;color:#8b949e}
.pcard-bars{display:flex;flex-direction:column;gap:6px}
.pbar-row{display:flex;align-items:center;gap:8px;border-radius:4px;padding:2px 4px;transition:background .15s}
.pbar-row:hover{background:#21262d}
.pbar-track{flex:1;height:5px;background:#21262d;border-radius:3px;overflow:hidden}
.pbar-fill{height:100%;border-radius:3px;transition:width .8s ease-out;min-width:2px}
.pbar-count{font-size:12px;font-weight:700;min-width:20px;text-align:right}

/* ===== SERVICE TABLE ===== */
#serviceTable tr:hover{background:#161b22;cursor:pointer}
.svc-name{font-weight:600;color:#e6edf3}

/* ===== CONTROLS ===== */
.controls{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;align-items:center}
.controls input,.controls select,.controls button{background:#161b22;border:1px solid #30363d;border-radius:6px;color:#e6edf3;padding:7px 11px;font-size:13px;outline:none}
.controls input{min-width:220px}
.controls input:focus,.controls select:focus{border-color:#58a6ff}
.controls button{cursor:pointer;background:#21262d;color:#8b949e}
.controls button:hover{background:#30363d;color:#e6edf3}

/* ===== TABLE ===== */
.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid #21262d}
table{width:100%;border-collapse:collapse}
thead{background:#161b22}
th{padding:10px 12px;text-align:left;font-size:11px;color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid #21262d;white-space:nowrap}
.fr{background:#0d1117;transition:background .1s}
.fr:hover{background:#161b22}
td{padding:10px 12px;border-bottom:1px solid #21262d;vertical-align:middle}
.dr td{padding:0;background:#0a0d12}
.mono{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace;font-size:12px}
.no-results{padding:32px;text-align:center;color:#8b949e}

/* ===== BADGES ===== */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.4px;white-space:nowrap}
.badge-critical{background:#3d0000;color:#ff4444;border:1px solid #ff4444}
.badge-high{background:#2d1a00;color:#ff8800;border:1px solid #ff8800}
.badge-medium{background:#2d2700;color:#ffcc00;border:1px solid #ffcc00}
.badge-low{background:#001a2d;color:#66b3ff;border:1px solid #66b3ff}
.badge-info{background:#1c1c1c;color:#aaaaaa;border:1px solid #555}

/* Provider tag */
.ptag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:700;border:1px solid;background:rgba(0,0,0,.3);letter-spacing:.3px}

/* Expand button */
.xbtn{background:none;border:none;color:#8b949e;cursor:pointer;font-size:14px;padding:2px 6px;border-radius:4px}
.xbtn:hover{background:#21262d;color:#e6edf3}

/* Detail box */
.dbox{padding:16px 20px;background:#0a0d12;border-top:1px solid #21262d}
.dgrid{display:grid;grid-template-columns:1fr 280px;gap:20px}
@media(max-width:800px){.dgrid{grid-template-columns:1fr}.posture-row{flex-direction:column}.quick-cards{flex-direction:row}}
.dl{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;font-weight:600}
.dv{color:#e6edf3;font-size:13px;line-height:1.6}
.mt12{margin-top:12px}
.remediation{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px 12px}
.comp-pill{display:inline-block;background:#1c2128;border:1px solid #30363d;border-radius:4px;padding:2px 8px;font-size:11px;color:#8b949e;margin:2px 2px 2px 0}
.rlist{margin:4px 0 0 16px;font-size:12px;color:#8b949e;line-height:1.8}

/* Footer */
.footer{text-align:center;padding:20px;color:#484f58;font-size:12px;border-top:1px solid #21262d;margin-top:12px}

/* Fix Commands panel */
.fix-btn{background:#1c2128;border:1px solid #30363d;color:#8b949e;cursor:pointer;font-size:12px;padding:4px 10px;border-radius:5px;margin-top:4px;transition:all .15s}
.fix-btn:hover{background:#21262d;color:#58a6ff;border-color:#58a6ff}
.fix-panel{margin-top:8px;border:1px solid #30363d;border-radius:6px;overflow:hidden}
.fix-resource{font-size:11px;color:#8b949e;padding:6px 12px 2px;background:#0d1117;text-transform:uppercase;letter-spacing:.3px}
.fix-pre{background:#0a0d12;color:#79c0ff;font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace;font-size:12px;padding:10px 14px;margin:0;white-space:pre-wrap;word-break:break-all;border-top:1px solid #21262d}
.fix-note{padding:4px 0}
.fix-note-pre{color:#ffcc00}

/* Suppressed findings */
.sup-row td{color:#484f58}
.sup-row .badge{opacity:0.5}
.sup-row .ptag{opacity:0.5}
.sup-resources{font-size:12px;color:#484f58}
</style>"""


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

def _js(findings_json: str) -> str:
    return f"""<script>
const FINDINGS = JSON.parse(document.getElementById('fd').textContent);

function applyFilters() {{
  const search = document.getElementById('search').value.toLowerCase();
  const fSev   = document.getElementById('fSev').value;
  const fProv  = document.getElementById('fProv').value;
  const fSvc   = document.getElementById('fSvc').value;
  const rows   = document.querySelectorAll('.fr');
  let vis = 0;
  rows.forEach(row => {{
    const ok = (!fSev  || row.dataset.severity === fSev)
            && (!fProv || row.dataset.provider === fProv)
            && (!fSvc  || row.dataset.service  === fSvc)
            && (!search || row.dataset.text.includes(search));
    row.style.display = ok ? '' : 'none';
    if (!ok) {{
      const btn = row.querySelector('.xbtn');
      if (btn) {{
        const m = btn.getAttribute('onclick').match(/'([^']+)'/);
        if (m) {{ const dr = document.getElementById(m[1]); if (dr) dr.style.display='none'; }}
      }}
    }}
    if (ok) vis++;
  }});
  document.getElementById('nr').style.display = vis===0 ? '' : 'none';
}}

function clearFilters() {{
  ['search','fSev','fProv','fSvc'].forEach(id => {{
    const el = document.getElementById(id);
    if (el.tagName==='INPUT') el.value=''; else el.value='';
  }});
  applyFilters();
}}

function filterBySeverity(s) {{
  document.getElementById('fSev').value = s;
  applyFilters();
  document.getElementById('ft').scrollIntoView({{behavior:'smooth'}});
}}
function filterByProvider(p) {{
  document.getElementById('fProv').value = p;
  applyFilters();
  document.getElementById('ft').scrollIntoView({{behavior:'smooth'}});
}}
function filterByService(s) {{
  document.getElementById('fSvc').value = s;
  applyFilters();
  document.getElementById('ft').scrollIntoView({{behavior:'smooth'}});
}}

function toggleDetail(id, btn) {{
  const row = document.getElementById(id);
  if (!row) return;
  const open = row.style.display !== 'none';
  row.style.display = open ? 'none' : '';
  btn.innerHTML = open ? '&#9660;' : '&#9650;';
}}

function toggleFix(id, btn) {{
  const panel = document.getElementById(id);
  if (!panel) return;
  const open = panel.style.display !== 'none';
  panel.style.display = open ? 'none' : '';
  btn.innerHTML = open ? '&#128295; Fix Commands' : '&#128295; Hide Commands';
}}
</script>
<script id="fd" type="application/json">{findings_json}</script>"""
