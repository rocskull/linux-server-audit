"""Self-contained HTML dashboard in the m365-assessor layout.

Every dynamic value is HTML-escaped; evidence is serialised to JSON and then
escaped inside a <pre> block. The page loads no external assets.
"""

from __future__ import annotations

import json
from collections import Counter
from html import escape
from pathlib import Path

from lsa.model import SEVERITIES, AssessmentDocument, CheckResult, to_iso
from lsa.reporting.common import (
    atomic_report_path,
    frameworks_text,
    host_label,
    platform_label,
    profile_level,
    report_title,
    validate_report_filename,
)

CSS = """
:root{--navy:#17324d;--blue:#0b6e99;--ink:#17202a;--muted:#607080;--bg:#f3f6f8;--card:#fff;--red:#b42318;--amber:#b54708;--green:#067647;--line:#d9e2e8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}header{background:linear-gradient(120deg,var(--navy),var(--blue));color:#fff;padding:36px max(24px,calc((100% - 1280px)/2))}header h1{margin:0 0 8px;font-size:30px}header p{margin:2px 0;opacity:.9}.page{max-width:1280px;margin:auto;padding:24px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:0 2px 10px #17324d0d}.metric{font-size:28px;font-weight:750}.label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}.pass{color:var(--green)}.fail,.critical,.high{color:var(--red)}.warning,.medium{color:var(--amber)}.low,.informational{color:var(--blue)}h2{margin:30px 0 12px;font-size:21px}.coverage{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}.bar{height:8px;background:#e8eef2;border-radius:8px;overflow:hidden;margin-top:8px}.bar i{display:block;height:100%;background:var(--blue)}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}.toolbar input,.toolbar select{border:1px solid #b9c7d0;border-radius:7px;padding:9px;background:#fff;min-width:180px}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line)}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line)}th{position:sticky;top:0;background:var(--navy);color:#fff;font-size:12px}tr:hover td{background:#f7fbfd}.badge{display:inline-block;padding:3px 8px;border-radius:999px;background:#edf2f5;font-weight:700;font-size:11px}.badge.FAIL,.badge.ERROR{background:#fee4e2;color:var(--red)}.badge.PASS{background:#dcfae6;color:var(--green)}.badge.NOT_ASSESSED,.badge.WARNING{background:#fef0c7;color:var(--amber)}details{margin-top:8px}pre{white-space:pre-wrap;word-break:break-word;background:#f6f8fa;padding:10px;border-radius:6px;max-height:320px;overflow:auto}.limits li{margin:5px 0}footer{color:var(--muted);padding:20px 0 40px}.meta{color:var(--muted);font-size:12px}.facts{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px}.facts dt{color:var(--muted)}.facts dd{margin:0}@media(max-width:760px){.table-wrap{overflow-x:auto}header{padding:25px}.page{padding:14px}}
""".strip()

SCRIPT = """
function wire(table,search,filters){const q=document.querySelector(search),sel=filters.map(f=>[document.querySelector(f[0]),f[1]]);
function run(){const term=q.value.toLowerCase();document.querySelectorAll(table+' tbody tr').forEach(r=>{r.hidden=!(r.innerText.toLowerCase().includes(term)&&sel.every(([s,k])=>!s.value||r.dataset[k]===s.value));});}
[q,...sel.map(s=>s[0])].forEach(x=>x.addEventListener('input',run));}
wire('#findings','#search',[['#severity','severity'],['#service','service']]);
wire('#controls','#control-search',[['#control-status','status'],['#control-service','service']]);
""".strip()


def _e(value: object) -> str:
    return escape("" if value is None else str(value), quote=True)


def _bars(counts: Counter, maximum: int) -> str:
    rows = []
    for name, count in counts.most_common():
        rows.append(f'<p>{_e(name)} <strong>{count}</strong></p><div class="bar"><i style="width:{100 * count / maximum:.1f}%"></i></div>')
    return "".join(rows)


def _mapping_cell(check: CheckResult) -> str:
    parts = [f"{_e(item.framework)} {_e(item.version)}<br>{_e(item.control)}" for item in check.benchmark]
    return "<hr>".join(parts)


def _finding_row(item: CheckResult, profile: str) -> str:
    evidence = json.dumps(item.evidence, indent=2, ensure_ascii=False, default=str)
    resources = ""
    if item.affected_resources:
        resources = f"<p><strong>Affected:</strong> {_e(', '.join(item.affected_resources[:25]))}{' ...' if len(item.affected_resources) > 25 else ''}</p>"
    return (
        f'<tr data-severity="{_e(item.severity)}" data-service="{_e(item.service)}">'
        f'<td>{_e(item.check_id)}<br><span class="badge {_e(item.status)}">{_e(item.status)}</span></td>'
        f'<td class="{_e(item.severity.lower())}"><strong>{_e(item.severity)}</strong><br><span class="meta">{_e(profile_level(item, profile))}</span></td>'
        f"<td>{_e(item.service)}<br><small>{_e(item.category)}</small></td>"
        f"<td><strong>{_e(item.title)}</strong><p>{_e(item.description)}</p>"
        f"<p><strong>Observation:</strong> {_e(item.observation)}</p>{resources}"
        f"<p><strong>Business impact:</strong> {_e(item.business_impact)}</p>"
        f"<p><strong>Recommendation:</strong> {_e(item.recommendation)}</p>"
        f"<details><summary>Remediation and evidence</summary><p>{_e(item.remediation)}</p><pre>{_e(evidence)}</pre></details></td>"
        f"<td>{_mapping_cell(item)}</td></tr>"
    )


def _control_row(item: CheckResult) -> str:
    cis = item.cis_mapping()
    return (
        f'<tr data-status="{_e(item.status)}" data-service="{_e(item.service)}">'
        f'<td>{_e(item.check_id)}</td><td>{_e(cis.control if cis else "")}</td>'
        f'<td><span class="badge {_e(item.status)}">{_e(item.status)}</span></td><td>{_e(item.severity)}</td>'
        f"<td><strong>{_e(item.title)}</strong><br><small>{_e(item.service)} / {_e(item.category)}</small></td>"
        f"<td>{_e(item.observation)}</td></tr>"
    )


def render(document: AssessmentDocument) -> str:
    summary = document.summary
    host = document.host
    assessment = document.assessment
    severity_counts = Counter(item.severity for item in document.findings)
    service_counts = Counter(item.service for item in document.findings)
    category_counts = Counter(item.category for item in document.findings)
    chart_max = max([*severity_counts.values(), *service_counts.values(), *category_counts.values(), 1])
    completed = to_iso(assessment.completed_at or assessment.started_at)
    profile = host.profile
    benchmark_info = next(iter(document.benchmark_results.values()), {})
    manual = benchmark_info.get("manual_recommendations_not_automated", [])
    top = document.findings[:5]
    priority = "".join(
        f"<li><strong>{_e(item.check_id)} - {_e(item.title)}</strong> <span class=\"{_e(item.severity.lower())}\">({_e(item.severity)})</span><br>{_e(item.recommendation or item.remediation)}</li>"
        for item in top
    ) or "<li>No failing controls were identified in the assessed scope.</li>"
    coverage_cards = []
    for area in document.coverage:
        reasons = "".join(f"<li>{_e(reason)}</li>" for reason in area.reasons[:6])
        more = f"<li>... and {len(area.reasons) - 6} more (see Assessment limitations)</li>" if len(area.reasons) > 6 else ""
        coverage_cards.append(
            f'<article class="card"><div class="label">{_e(area.status)}</div><strong>{_e(area.name)}</strong>'
            f'<div class="metric">{area.coverage_percent:.1f}%</div><div class="bar"><i style="width:{area.coverage_percent}%"></i></div>'
            + (f'<ul class="limits">{reasons}{more}</ul>' if reasons else "")
            + "</article>"
        )
    findings_rows = "".join(_finding_row(item, profile) for item in document.findings) or (
        '<tr><td colspan="5">No FAIL or WARNING results in the assessed scope.</td></tr>'
    )
    services = sorted({item.service for item in document.findings})
    all_services = []
    for item in document.checks:
        if item.service not in all_services:
            all_services.append(item.service)
    limitations = []
    for area in document.coverage:
        for reason in area.reasons:
            limitations.append(f"<li><strong>{_e(area.name)}:</strong> {_e(reason)}</li>")
    if manual and not benchmark_info.get("manual_recommendations_included"):
        limitations.append(
            f"<li><strong>Manual recommendations:</strong> {len(manual)} CIS recommendation(s) require assessor review and are not scored: "
            f"{_e('; '.join(manual))}.</li>"
        )
    if summary.not_applicable_count:
        limitations.append(
            f"<li><strong>Not applicable:</strong> {summary.not_applicable_count} control(s) did not apply to this host, profile or scope "
            "(for example absent services, IPv6 disabled, or Level 2 items outside a Level 1 profile). See the All controls table.</li>"
        )
    for warning in benchmark_info.get("warnings", []):
        limitations.append(f"<li><strong>Benchmark selection:</strong> {_e(warning)}</li>")
    if not limitations:
        limitations.append("<li>No coverage limitations were recorded.</li>")
    ips = ", ".join(host.ip_addresses) or "not collected"
    facts = [
        ("Hostname", host.fqdn or host.hostname),
        ("Platform", platform_label(document)),
        ("Kernel", host.kernel),
        ("Architecture", host.architecture),
        ("Virtualization", host.virtualization or "none detected"),
        ("IP addresses", ips),
        ("Machine ID", host.machine_id),
        ("Platform type / profile", f"{host.platform_type} / {profile}"),
        ("Executed as", f"{document.execution.identity or 'unknown'}" + (f" (via sudo from {document.execution.sudo_user})" if document.execution.sudo_user else "")),
    ]
    facts_html = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in facts)
    severity_options = "".join(f"<option>{s}</option>" for s in SEVERITIES)
    service_options = "".join(f"<option>{_e(s)}</option>" for s in services)
    status_options = "".join(f"<option>{s}</option>" for s in ("PASS", "FAIL", "WARNING", "NOT_ASSESSED", "ERROR", "NOT_APPLICABLE"))
    all_service_options = "".join(f"<option>{_e(s)}</option>" for s in all_services)
    controls_rows = "".join(_control_row(item) for item in document.checks)
    client = f"<p>Client: {_e(assessment.client_name)}</p>" if assessment.client_name else ""
    title = report_title(document)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title>
<style>
{CSS}
</style>
</head>
<body>
<header>
  <h1>{_e(title)}</h1>
  <p>{_e(host_label(document))} - {_e(platform_label(document))}</p>
  <p>{_e(completed)} | {_e(assessment.tool)} {_e(assessment.tool_version)}</p>
  {client}
</header>
<main class="page">
  <section class="grid" aria-label="Executive summary">
    <div class="card"><div class="label">Total checks</div><div class="metric">{summary.total_checks}</div></div>
    <div class="card"><div class="label">Passed</div><div class="metric pass">{summary.pass_count}</div></div>
    <div class="card"><div class="label">Failed</div><div class="metric fail">{summary.fail_count}</div></div>
    <div class="card"><div class="label">Not assessed</div><div class="metric warning">{summary.not_assessed_count}</div></div>
    <div class="card"><div class="label">Pass percentage</div><div class="metric">{summary.pass_percentage:.1f}%</div></div>
    <div class="card"><div class="label">Coverage</div><div class="metric">{summary.coverage_percentage:.1f}%</div></div>
  </section>

  <h2>Risk distribution</h2>
  <section class="grid">
    <article class="card"><div class="label">By severity</div>{_bars(severity_counts, chart_max)}</article>
    <article class="card"><div class="label">By service</div>{_bars(service_counts, chart_max)}</article>
    <article class="card"><div class="label">By category</div>{_bars(category_counts, chart_max)}</article>
  </section>

  <h2>Priority remediation</h2>
  <div class="card"><ol>{priority}</ol></div>

  <h2>Scope and methodology</h2>
  <div class="card">
    <p><strong>Frameworks:</strong> {_e(frameworks_text(document))}</p>
    <p><strong>Profile:</strong> {_e(profile)}</p>
    <p><strong>Scope:</strong> {_e(', '.join(assessment.scope))}</p>
    <dl class="facts">{facts_html}</dl>
    <p>This assessment runs locally with read-only commands, normalizes evidence, and evaluates a versioned, data-driven CIS benchmark definition. Evidence that could not be read is reported as NOT_ASSESSED and does not reduce the pass percentage. Controls outside the selected profile or not relevant to this host are NOT_APPLICABLE.</p>
  </div>

  <h2>Coverage and permissions</h2>
  <section class="coverage">
  {''.join(coverage_cards)}
  </section>

  <h2>Detailed findings</h2>
  <div class="toolbar">
    <input id="search" type="search" placeholder="Search findings" aria-label="Search findings">
    <select id="severity" aria-label="Filter by severity"><option value="">All severities</option>{severity_options}</select>
    <select id="service" aria-label="Filter by service"><option value="">All services</option>{service_options}</select>
  </div>
  <div class="table-wrap">
  <table id="findings"><thead><tr><th>ID</th><th>Severity</th><th>Service</th><th>Title and detail</th><th>Mapping</th></tr></thead><tbody>
  {findings_rows}
  </tbody></table></div>

  <h2>All controls</h2>
  <div class="toolbar">
    <input id="control-search" type="search" placeholder="Search controls" aria-label="Search controls">
    <select id="control-status" aria-label="Filter by status"><option value="">All statuses</option>{status_options}</select>
    <select id="control-service" aria-label="Filter by service"><option value="">All services</option>{all_service_options}</select>
  </div>
  <div class="table-wrap">
  <table id="controls"><thead><tr><th>ID</th><th>CIS</th><th>Status</th><th>Severity</th><th>Control</th><th>Observation</th></tr></thead><tbody>
  {controls_rows}
  </tbody></table></div>

  <h2>Assessment limitations</h2>
  <div class="card"><ul class="limits">
  {''.join(limitations)}
  </ul></div>
  <footer>Generated by {_e(assessment.tool)} {_e(assessment.tool_version)}. No system configuration changes were made.</footer>
</main>
<script>
{SCRIPT}
</script>
</body></html>
"""


def write_html_report(document: AssessmentDocument, output_directory: Path, filename: str = "assessment.html") -> Path:
    validate_report_filename(filename, ".html")
    destination = output_directory.resolve() / filename
    with atomic_report_path(destination) as temporary:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(render(document))
    return destination
