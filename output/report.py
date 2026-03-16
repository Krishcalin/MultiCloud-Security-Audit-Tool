"""HTML report generator for multi-cloud security scan results.

Produces a self-contained, single-file HTML report (no external CDN
dependencies) with:
- Executive summary tiles (CRITICAL / HIGH / MEDIUM / LOW / INFO counts)
- Per-provider summary cards
- Filterable, searchable findings table
- Expandable per-finding details (description, remediation, compliance, references)

Usage::

    from output.report import save_html
    save_html(findings, path="report.html", meta={"scan_date": "...", "account": "..."})
"""

from __future__ import annotations

import html as html_mod
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.finding import SEVERITY_COLOUR, Finding

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEV_BADGE  = {
    "CRITICAL": "badge-critical",
    "HIGH":     "badge-high",
    "MEDIUM":   "badge-medium",
    "LOW":      "badge-low",
    "INFO":     "badge-info",
}
_PROVIDER_ICON = {
    "aws":   "&#9729;",   # cloud
    "azure": "&#9830;",   # diamond
    "gcp":   "&#9670;",   # diamond (filled)
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_html(
    findings: List[Finding],
    path:     str | Path,
    meta:     Optional[Dict[str, Any]] = None,
) -> None:
    """Render *findings* to a self-contained HTML file at *path*.

    Args
    ----
    findings: List of :class:`~core.finding.Finding` objects.
    path:     Output file path.
    meta:     Optional dict with extra header info:
              ``scan_date``, ``account``, ``region``, ``version``.
    """
    meta = meta or {}
    html = _render(findings, meta)
    Path(path).write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _render(findings: List[Finding], meta: Dict[str, Any]) -> str:
    scan_date = meta.get("scan_date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    version   = meta.get("version", "1.0.0")
    account   = meta.get("account", "")

    # Aggregate counts
    sev_counts: Counter = Counter(f.severity for f in findings)
    total        = len(findings)
    total_resources = sum(f.flagged_count for f in findings)

    # Per-provider breakdown
    providers: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        providers[f.provider or "unknown"].append(f)

    # Build sections
    summary_tiles   = _summary_tiles(sev_counts, total, total_resources)
    provider_cards  = _provider_cards(providers)
    findings_table  = _findings_table(findings)
    findings_json   = html_mod.escape(json.dumps([f.to_dict() for f in findings], default=str), quote=True)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>MultiCloud Security Audit Report</title>
{_css()}
</head>
<body>

<!-- ===== HEADER ===== -->
<div class="header">
  <div class="header-inner">
    <div class="logo-row">
      <span class="logo-icon">&#9749;</span>
      <div>
        <div class="logo-title">MultiCloud Security Audit Tool</div>
        <div class="logo-sub">v{html_mod.escape(version)} &nbsp;&bull;&nbsp; {html_mod.escape(scan_date)}{(' &nbsp;&bull;&nbsp; ' + html_mod.escape(account)) if account else ''}</div>
      </div>
    </div>
    <div class="badge-row">
      <span class="hbadge hbadge-aws">AWS</span>
      <span class="hbadge hbadge-azure">Azure</span>
      <span class="hbadge hbadge-gcp">GCP</span>
    </div>
  </div>
</div>

<!-- ===== SUMMARY TILES ===== -->
<div class="container">
  <section class="section">
    <h2 class="section-title">Executive Summary</h2>
    <div class="tiles">
      {summary_tiles}
    </div>
  </section>

<!-- ===== PROVIDER CARDS ===== -->
{provider_cards}

<!-- ===== FINDINGS TABLE ===== -->
  <section class="section">
    <h2 class="section-title">Findings
      <span class="count-badge">{total}</span>
    </h2>

    <!-- Controls -->
    <div class="controls">
      <input id="search" type="text" placeholder="&#128269;  Search findings..." oninput="applyFilters()"/>
      <select id="filterSeverity" onchange="applyFilters()">
        <option value="">All Severities</option>
        <option value="CRITICAL">CRITICAL</option>
        <option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option>
        <option value="LOW">LOW</option>
        <option value="INFO">INFO</option>
      </select>
      <select id="filterProvider" onchange="applyFilters()">
        <option value="">All Providers</option>
        {''.join(f'<option value="{html_mod.escape(p)}">{html_mod.escape(p.upper())}</option>' for p in sorted(providers))}
      </select>
      <select id="filterService" onchange="applyFilters()">
        <option value="">All Services</option>
        {''.join(f'<option value="{html_mod.escape(s)}">{html_mod.escape(s)}</option>' for s in sorted({f.service for f in findings}))}
      </select>
      <button onclick="clearFilters()">Clear</button>
    </div>

    <!-- Table -->
    <div class="table-wrap">
      <table id="findingsTable">
        <thead>
          <tr>
            <th style="width:100px">Severity</th>
            <th style="width:110px">Rule ID</th>
            <th style="width:90px">Provider</th>
            <th style="width:110px">Service</th>
            <th>Finding</th>
            <th style="width:80px;text-align:center">Affected</th>
            <th style="width:40px"></th>
          </tr>
        </thead>
        <tbody id="tableBody">
          {findings_table}
        </tbody>
      </table>
      <div id="noResults" class="no-results" style="display:none">No findings match the current filters.</div>
    </div>
  </section>

</div><!-- /container -->

<!-- ===== FOOTER ===== -->
<div class="footer">
  MultiCloud Security Audit Tool &mdash; For authorised security assessments only. Read-only API calls. No resources modified.
</div>

{_js(findings_json)}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Summary tiles
# ---------------------------------------------------------------------------

def _summary_tiles(sev_counts: Counter, total: int, total_resources: int) -> str:
    tiles = []
    for sev in _SEV_ORDER:
        count = sev_counts.get(sev, 0)
        colour = SEVERITY_COLOUR.get(sev, "#aaa")
        tiles.append(
            f'<div class="tile" style="border-top:3px solid {colour}" onclick="filterBySeverity(\'{sev}\')">'
            f'  <div class="tile-count" style="color:{colour}">{count}</div>'
            f'  <div class="tile-label">{sev}</div>'
            f'</div>'
        )
    tiles.append(
        f'<div class="tile" style="border-top:3px solid #888">'
        f'  <div class="tile-count" style="color:#e6edf3">{total}</div>'
        f'  <div class="tile-label">TOTAL FINDINGS</div>'
        f'</div>'
    )
    tiles.append(
        f'<div class="tile" style="border-top:3px solid #58a6ff">'
        f'  <div class="tile-count" style="color:#58a6ff">{total_resources}</div>'
        f'  <div class="tile-label">AFFECTED RESOURCES</div>'
        f'</div>'
    )
    return "\n".join(tiles)


# ---------------------------------------------------------------------------
# Provider cards
# ---------------------------------------------------------------------------

def _provider_cards(providers: Dict[str, List[Finding]]) -> str:
    if not providers:
        return ""

    cards = []
    for prov, pfindings in sorted(providers.items()):
        sev_c = Counter(f.severity for f in pfindings)
        icon  = _PROVIDER_ICON.get(prov.lower(), "&#9729;")
        bars  = []
        for sev in _SEV_ORDER:
            c = sev_c.get(sev, 0)
            if c:
                colour = SEVERITY_COLOUR.get(sev, "#aaa")
                bars.append(
                    f'<span class="pbar-item" style="color:{colour}">'
                    f'  <b>{c}</b> {sev}'
                    f'</span>'
                )
        cards.append(
            f'<div class="pcard" onclick="filterByProvider(\'{html_mod.escape(prov)}\')">'
            f'  <div class="pcard-title">{icon} {html_mod.escape(prov.upper())}</div>'
            f'  <div class="pcard-total">{len(pfindings)} findings</div>'
            f'  <div class="pcard-bars">{"".join(bars)}</div>'
            f'</div>'
        )

    return (
        '<section class="section">'
        '<h2 class="section-title">Providers</h2>'
        '<div class="pcards">' + "\n".join(cards) + '</div>'
        '</section>'
    )


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------

def _findings_table(findings: List[Finding]) -> str:
    rows = []
    for i, f in enumerate(findings):
        sev     = html_mod.escape(f.severity)
        badge   = _SEV_BADGE.get(f.severity, "badge-info")
        colour  = SEVERITY_COLOUR.get(f.severity, "#aaa")
        rid     = html_mod.escape(f.rule_id)
        prov    = html_mod.escape(f.provider or "")
        svc     = html_mod.escape(f.service or "")
        name    = html_mod.escape(f.name)
        count   = f.flagged_count
        desc    = html_mod.escape(f.description)
        remed   = html_mod.escape(f.remediation)
        path    = html_mod.escape(f.resource_path)

        # Compliance pills
        comp_html = ""
        for c in (f.compliance or []):
            cname = html_mod.escape(c.get("name", ""))
            cver  = html_mod.escape(c.get("version", ""))
            cref  = html_mod.escape(c.get("reference", ""))
            comp_html += f'<span class="comp-pill">{cname} {cver} &sect;{cref}</span> '

        # Reference links
        refs_html = ""
        for r in (f.references or []):
            safe_r = html_mod.escape(r)
            refs_html += f'<a href="{safe_r}" target="_blank" rel="noopener noreferrer">{safe_r}</a><br/>'

        # Affected resources list (first 5)
        res_html = ""
        for item in f.flagged_items[:5]:
            res_html += f'<li>{html_mod.escape(str(item.get("id", "")))}</li>'
        if count > 5:
            res_html += f'<li><em>… and {count - 5} more</em></li>'

        detail_id = f"detail-{i}"
        rows.append(f"""
<tr class="finding-row"
    data-severity="{sev}"
    data-provider="{prov}"
    data-service="{svc}"
    data-text="{html_mod.escape(f.rule_id + ' ' + f.name + ' ' + f.description, quote=True).lower()}"
    style="border-left: 3px solid {colour}">
  <td><span class="badge {badge}">{sev}</span></td>
  <td class="mono">{rid}</td>
  <td><span class="prov-tag">{prov.upper()}</span></td>
  <td>{svc}</td>
  <td><strong>{name}</strong></td>
  <td style="text-align:center;font-weight:bold;color:{colour}">{count}</td>
  <td><button class="expand-btn" onclick="toggleDetail('{detail_id}', this)">&#9660;</button></td>
</tr>
<tr id="{detail_id}" class="detail-row" style="display:none">
  <td colspan="7">
    <div class="detail-box">
      <div class="detail-grid">
        <div class="detail-col">
          <div class="detail-label">Description</div>
          <div class="detail-value">{desc}</div>
          <div class="detail-label" style="margin-top:12px">Remediation</div>
          <div class="detail-value remediation">{remed}</div>
          {('<div class="detail-label" style="margin-top:12px">Compliance</div><div class="detail-value">' + comp_html + '</div>') if comp_html else ''}
          {('<div class="detail-label" style="margin-top:12px">References</div><div class="detail-value">' + refs_html + '</div>') if refs_html else ''}
          <div class="detail-label" style="margin-top:12px">Resource Path</div>
          <div class="detail-value mono">{path}</div>
        </div>
        <div class="detail-col">
          <div class="detail-label">Affected Resources ({count})</div>
          <ul class="res-list">{res_html}</ul>
        </div>
      </div>
    </div>
  </td>
</tr>""")
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

def _css() -> str:
    return """<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif;font-size:14px;line-height:1.6}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}

/* Header */
.header{background:linear-gradient(135deg,#161b22 0%,#1c2128 100%);border-bottom:1px solid #30363d;padding:20px 0}
.header-inner{max-width:1400px;margin:0 auto;padding:0 24px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
.logo-row{display:flex;align-items:center;gap:14px}
.logo-icon{font-size:36px;color:#58a6ff}
.logo-title{font-size:22px;font-weight:700;color:#e6edf3}
.logo-sub{font-size:12px;color:#8b949e;margin-top:2px}
.badge-row{display:flex;gap:8px}
.hbadge{padding:4px 10px;border-radius:12px;font-size:11px;font-weight:700;letter-spacing:.5px}
.hbadge-aws{background:#1a2332;color:#ff9900;border:1px solid #ff9900}
.hbadge-azure{background:#1a2030;color:#0078d4;border:1px solid #0078d4}
.hbadge-gcp{background:#1a221a;color:#34a853;border:1px solid #34a853}

/* Container */
.container{max-width:1400px;margin:0 auto;padding:24px}
.section{margin-bottom:36px}
.section-title{font-size:16px;font-weight:600;color:#e6edf3;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:10px}
.count-badge{background:#21262d;color:#8b949e;border-radius:10px;padding:2px 8px;font-size:12px;font-weight:500}

/* Summary tiles */
.tiles{display:flex;flex-wrap:wrap;gap:14px}
.tile{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px 22px;min-width:130px;cursor:pointer;transition:background .15s}
.tile:hover{background:#1c2128}
.tile-count{font-size:32px;font-weight:700;line-height:1}
.tile-label{font-size:11px;color:#8b949e;margin-top:4px;letter-spacing:.5px;text-transform:uppercase}

/* Provider cards */
.pcards{display:flex;flex-wrap:wrap;gap:14px}
.pcard{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px 20px;min-width:180px;cursor:pointer;transition:background .15s}
.pcard:hover{background:#1c2128}
.pcard-title{font-size:15px;font-weight:700;color:#e6edf3;margin-bottom:4px}
.pcard-total{font-size:12px;color:#8b949e;margin-bottom:10px}
.pcard-bars{display:flex;flex-direction:column;gap:4px}
.pbar-item{font-size:12px}

/* Controls */
.controls{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px;align-items:center}
.controls input,.controls select,.controls button{background:#161b22;border:1px solid #30363d;border-radius:6px;color:#e6edf3;padding:7px 11px;font-size:13px;outline:none}
.controls input{min-width:220px}
.controls input:focus,.controls select:focus{border-color:#58a6ff}
.controls button{cursor:pointer;background:#21262d;color:#8b949e}
.controls button:hover{background:#30363d;color:#e6edf3}

/* Table */
.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid #21262d}
table{width:100%;border-collapse:collapse}
thead{background:#161b22}
th{padding:10px 12px;text-align:left;font-size:12px;color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid #21262d;white-space:nowrap}
.finding-row{background:#0d1117;transition:background .1s}
.finding-row:hover{background:#161b22}
td{padding:10px 12px;border-bottom:1px solid #21262d;vertical-align:middle}
.detail-row td{padding:0;background:#0a0d12}
.mono{font-family:"SFMono-Regular",Consolas,"Liberation Mono",monospace;font-size:12px}
.no-results{padding:32px;text-align:center;color:#8b949e;font-size:14px}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.4px}
.badge-critical{background:#3d0000;color:#ff4444;border:1px solid #ff4444}
.badge-high{background:#2d1a00;color:#ff8800;border:1px solid #ff8800}
.badge-medium{background:#2d2700;color:#ffcc00;border:1px solid #ffcc00}
.badge-low{background:#001a2d;color:#66b3ff;border:1px solid #66b3ff}
.badge-info{background:#1c1c1c;color:#aaaaaa;border:1px solid #555}

/* Provider tag */
.prov-tag{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;font-weight:700;background:#21262d;color:#8b949e;letter-spacing:.3px}

/* Expand button */
.expand-btn{background:none;border:none;color:#8b949e;cursor:pointer;font-size:14px;padding:2px 6px;border-radius:4px}
.expand-btn:hover{background:#21262d;color:#e6edf3}

/* Detail box */
.detail-box{padding:16px 20px;background:#0a0d12;border-top:1px solid #21262d}
.detail-grid{display:grid;grid-template-columns:1fr 280px;gap:20px}
@media(max-width:768px){.detail-grid{grid-template-columns:1fr}}
.detail-col{}
.detail-label{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.4px;margin-bottom:4px;font-weight:600}
.detail-value{color:#e6edf3;font-size:13px;line-height:1.6;margin-bottom:4px}
.remediation{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px 12px}
.comp-pill{display:inline-block;background:#1c2128;border:1px solid #30363d;border-radius:4px;padding:2px 8px;font-size:11px;color:#8b949e;margin:2px 2px 2px 0}
.res-list{margin:4px 0 0 16px;font-size:12px;color:#8b949e;line-height:1.8}

/* Footer */
.footer{text-align:center;padding:20px;color:#484f58;font-size:12px;border-top:1px solid #21262d;margin-top:12px}
</style>"""


# ---------------------------------------------------------------------------
# JS
# ---------------------------------------------------------------------------

def _js(findings_json_escaped: str) -> str:
    return f"""<script>
// Raw findings data (for future client-side use)
const FINDINGS_DATA = JSON.parse(document.getElementById('findings-data').textContent);

function applyFilters() {{
  const search   = document.getElementById('search').value.toLowerCase();
  const severity = document.getElementById('filterSeverity').value;
  const provider = document.getElementById('filterProvider').value;
  const service  = document.getElementById('filterService').value;
  const rows     = document.querySelectorAll('.finding-row');
  let visible = 0;

  rows.forEach(row => {{
    const matchSev  = !severity || row.dataset.severity === severity;
    const matchProv = !provider || row.dataset.provider === provider;
    const matchSvc  = !service  || row.dataset.service  === service;
    const matchSrch = !search   || row.dataset.text.includes(search);
    const show = matchSev && matchProv && matchSvc && matchSrch;
    row.style.display = show ? '' : 'none';
    // Hide detail row when parent is hidden
    const detailBtn = row.querySelector('.expand-btn');
    if (detailBtn) {{
      const detailId = detailBtn.getAttribute('onclick').match(/'([^']+)'/)[1];
      const detailRow = document.getElementById(detailId);
      if (detailRow) detailRow.style.display = 'none';
    }}
    if (show) visible++;
  }});

  document.getElementById('noResults').style.display = visible === 0 ? '' : 'none';
}}

function clearFilters() {{
  document.getElementById('search').value = '';
  document.getElementById('filterSeverity').value = '';
  document.getElementById('filterProvider').value = '';
  document.getElementById('filterService').value  = '';
  applyFilters();
}}

function filterBySeverity(sev) {{
  document.getElementById('filterSeverity').value = sev;
  applyFilters();
  document.getElementById('findingsTable').scrollIntoView({{behavior:'smooth'}});
}}

function filterByProvider(prov) {{
  document.getElementById('filterProvider').value = prov;
  applyFilters();
  document.getElementById('findingsTable').scrollIntoView({{behavior:'smooth'}});
}}

function toggleDetail(id, btn) {{
  const row = document.getElementById(id);
  if (!row) return;
  const open = row.style.display !== 'none';
  row.style.display = open ? 'none' : '';
  btn.innerHTML = open ? '&#9660;' : '&#9650;';
}}
</script>
<script id="findings-data" type="application/json">{findings_json_escaped}</script>"""
