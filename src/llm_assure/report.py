"""Report writers: JSON, JUnit XML, Markdown and a self-contained HTML audit report."""

from __future__ import annotations

import html
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import ERROR, FAIL, PASS, REVIEW, SEVERITY_ORDER, AssessmentResult

FORMATS = ("html", "json", "junit", "md")


def write_reports(result: AssessmentResult, out_dir: str | Path, formats=FORMATS) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    writers = {
        "json": ("assessment.json", to_json),
        "junit": ("junit.xml", to_junit),
        "md": ("summary.md", to_markdown),
        "html": ("report.html", to_html),
    }
    paths = {}
    for fmt in formats:
        name, fn = writers[fmt]
        p = out / name
        p.write_text(fn(result), encoding="utf-8")
        paths[fmt] = p
    return paths


# ---------------------------------------------------------------- JSON
def to_json(result: AssessmentResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


# ---------------------------------------------------------------- JUnit
def to_junit(result: AssessmentResult) -> str:
    root = ET.Element("testsuites", name=f"LLM assurance: {result.target_name}")
    for suite in result.suites:
        rs = [r for r in result.results if r.suite == suite.id]
        ts = ET.SubElement(
            root, "testsuite", name=suite.id, tests=str(len(rs)),
            failures=str(sum(r.status == FAIL for r in rs)),
            errors=str(sum(r.status == ERROR for r in rs)),
            skipped=str(sum(r.status == REVIEW for r in rs)),
        )
        for r in rs:
            tc = ET.SubElement(
                ts, "testcase", classname=f"llm_assure.{suite.id}",
                name=f"{r.probe_id} {r.probe_name} [{r.severity}]",
                time=f"{r.duration_ms / 1000:.3f}",
            )
            if r.status == FAIL:
                reasons = "; ".join(h.detail for h in r.hits if h.vulnerable)
                el = ET.SubElement(tc, "failure", message=f"[{r.severity}] {reasons}", type=r.severity)
                el.text = f"Response:\n{r.last_response}"
            elif r.status == ERROR:
                ET.SubElement(tc, "error", message=r.error)
            elif r.status == REVIEW:
                ET.SubElement(tc, "skipped", message="needs human review (enable --judge)")
    ET.indent(root)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


# ---------------------------------------------------------------- Markdown
def to_markdown(result: AssessmentResult) -> str:
    c = result.counts()
    sev = result.failure_counts_by_severity()
    lines = [
        f"## LLM Assurance Report: {result.target_name}",
        "",
        f"**Score: {result.risk_score}/100 (grade {result.grade})** · "
        f"{c[PASS]} passed · {c[FAIL]} failed · {c[REVIEW]} need review · {c[ERROR]} errors",
        "",
        "| Severity | Failures |",
        "|---|---|",
        *[f"| {s.title()} | {sev[s]} |" for s in SEVERITY_ORDER],
        "",
        "| Category | OWASP | Passed | Failed |",
        "|---|---|---|---|",
        *[f"| {row['title']} | {row['owasp']} | {row['passed']}/{row['total']} | {row['failed']} |"
          for row in result.suite_summary()],
    ]
    if result.failures:
        lines += ["", "### Findings", ""]
        for r in result.failures:
            reason = "; ".join(h.detail for h in r.hits if h.vulnerable)
            lines.append(f"- **[{r.severity.upper()}] {r.probe_id} {r.probe_name}**: {reason}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- HTML
def _e(s: object) -> str:
    return html.escape(str(s), quote=True)


_CSS = """
:root{--bg:#f7f8fa;--card:#fff;--ink:#16181d;--muted:#5d6472;--line:#e3e6eb;--accent:#3a5bd9;
--crit:#b42318;--high:#c4320a;--med:#b54708;--low:#475467;--pass:#067647;--review:#6941c6;
--code:#f1f3f6;}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--ink:#e8eaee;--muted:#9aa1ad;
--line:#2a2f3a;--accent:#7f9cff;--crit:#ff6b5e;--high:#ff8a4c;--med:#f5b14c;--low:#a5adbb;
--pass:#47cd89;--review:#b692f6;--code:#11141a;}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
header{display:flex;justify-content:space-between;gap:24px;flex-wrap:wrap;align-items:flex-end;
border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:28px}
.eyebrow{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h1{font-size:28px;margin:4px 0 6px;line-height:1.2}h2{font-size:19px;margin:36px 0 12px}
.meta{color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.big{font-size:34px;font-weight:700;font-variant-numeric:tabular-nums;line-height:1.1}
.label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.grade{display:inline-block;font-weight:700;font-size:15px;border-radius:6px;padding:2px 8px;
margin-left:8px;vertical-align:middle;border:1px solid currentColor}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:10px}
.bar>span{display:block;height:100%;background:var(--accent)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
border-radius:10px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:600}
td.num{font-variant-numeric:tabular-nums}
.pill{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;
padding:2px 8px;border-radius:999px;border:1px solid currentColor}
.critical{color:var(--crit)}.high{color:var(--high)}.medium{color:var(--med)}.low{color:var(--low)}
.pass{color:var(--pass)}.fail{color:var(--crit)}.needs_review{color:var(--review)}.error{color:var(--muted)}
details{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0}
summary{cursor:pointer;padding:12px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
summary::-webkit-details-marker{display:none}
.body{padding:0 16px 16px}
.turn{margin:10px 0}.role{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:10px 12px;
white-space:pre-wrap;word-break:break-word;font:13px/1.5 ui-monospace,Consolas,monospace;margin:4px 0 0}
ul.hits{margin:8px 0 0;padding-left:18px;font-size:14px}
.rem{color:var(--muted);font-size:14px}
.scroll{overflow-x:auto}
footer{margin-top:48px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:16px}
@media print{details{break-inside:avoid}details:not([open]) .body{display:none}}
"""


def _probe_block(r, open_: bool = False) -> str:
    turns = "".join(
        f'<div class="turn"><div class="role">{"Tester" if m["role"] == "user" else "Assistant"}</div>'
        f"<pre>{_e(m['content'])}</pre></div>"
        for m in r.transcript
    )
    hits = "".join(
        f"<li><b>{_e(h.detector)}</b>: "
        f"{'⚠ vulnerable' if h.vulnerable else ('✓ safe' if h.vulnerable is False else '… inconclusive')}"
        f" · {_e(h.detail)}</li>"
        for h in r.hits
    )
    err = f"<p class='fail'>Error: {_e(r.error)}</p>" if r.error else ""
    return (
        f"<details{' open' if open_ else ''}><summary>"
        f'<span class="pill {r.severity}">{r.severity}</span>'
        f'<span class="pill {r.status}">{r.status.replace("_", " ")}</span>'
        f"<b>{_e(r.probe_id)}</b> {_e(r.probe_name)}</summary>"
        f'<div class="body">{turns}{err}<ul class="hits">{hits}</ul></div></details>'
    )


def to_html(result: AssessmentResult) -> str:
    c = result.counts()
    sev = result.failure_counts_by_severity()
    grade_class = {"A": "pass", "B": "pass", "C": "medium", "D": "high", "F": "critical"}[result.grade]
    suites = {s.id: s for s in result.suites}

    sev_cards = "".join(
        f'<div class="card"><div class="label">{s}</div><div class="big {s}">{sev[s]}</div></div>'
        for s in SEVERITY_ORDER
    )
    rows = "".join(
        f"<tr><td><b>{_e(row['title'])}</b></td><td>{_e(row['owasp'])}</td>"
        f"<td class='num'>{row['passed']}/{row['total']}</td>"
        f"<td class='num {'fail' if row['failed'] else ''}'>{row['failed']}</td>"
        f"<td class='num'>{row['review']}</td></tr>"
        for row in result.suite_summary()
    )
    findings = "".join(_probe_block(r, open_=r.severity in ("critical", "high")) for r in result.failures)
    if not findings:
        findings = "<p class='pass'>No vulnerabilities detected by the selected suites.</p>"

    failed_suites = [suites[sid] for sid in dict.fromkeys(r.suite for r in result.failures) if sid in suites]
    remediation = "".join(
        f"<div class='card' style='margin:10px 0'><b>{_e(s.title)}</b> "
        f"<span class='meta'>· {_e(s.owasp)}</span><p class='rem'>{_e(s.remediation)}</p></div>"
        for s in failed_suites
    )
    others = [r for r in result.results if r.status != FAIL]
    appendix = "".join(_probe_block(r) for r in others)
    judge = f"LLM judge: {_e(result.judge_model)}" if result.judge_model else "Deterministic detectors only"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LLM Assurance Report</title><style>{_CSS}</style></head>
<body><div class="wrap">
<header><div><div class="eyebrow">LLM Assurance Assessment</div>
<h1>{_e(result.target_name)}</h1>
<div class="meta">{_e(result.started_at)} · {c['total']} probes · {judge} · k11-llm-assure {_e(result.toolkit_version)}</div></div>
<div class="card" style="min-width:220px"><div class="label">Assurance score</div>
<div class="big">{result.risk_score}<span style="font-size:18px;color:var(--muted)">/100</span>
<span class="grade {grade_class}">{result.grade}</span></div>
<div class="bar"><span style="width:{result.risk_score}%"></span></div></div></header>

<div class="grid">
<div class="card"><div class="label">Passed</div><div class="big pass">{c[PASS]}</div></div>
<div class="card"><div class="label">Failed</div><div class="big fail">{c[FAIL]}</div></div>
<div class="card"><div class="label">Needs review</div><div class="big needs_review">{c[REVIEW]}</div></div>
<div class="card"><div class="label">Errors</div><div class="big error">{c[ERROR]}</div></div>
</div>

<h2>Failures by severity</h2><div class="grid">{sev_cards}</div>

<h2>Results by category</h2>
<div class="scroll"><table><thead><tr><th>Category</th><th>Framework</th><th>Passed</th><th>Failed</th><th>Review</th></tr></thead>
<tbody>{rows}</tbody></table></div>

<h2>Findings</h2>{findings}

{"<h2>Recommended remediation</h2>" + remediation if remediation else ""}

<h2>Appendix: all other probes</h2>{appendix}

<footer>Generated by the K11 LLM Assurance Toolkit · K11 Software Solutions ·
Automated testing reduces but does not eliminate risk; findings should be reviewed by a qualified engineer.</footer>
</div></body></html>
"""
