"""MCP server: lets Claude (or any MCP client) red-team an LLM app.

Run with ``llm-assure-mcp`` (stdio transport). Example for Claude Code::

    claude mcp add llm-assure -- llm-assure-mcp

Then ask: "Run a baseline assessment against examples/targets/demo_vulnerable.yaml
and explain the critical findings."
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .detectors import PII_PATTERNS, is_refusal, run_detector
from .models import SEVERITY_ORDER
from .report import write_reports
from .runner import run_assessment as _run_assessment
from .suites import load_suites
from .targets import Target, load_target, target_from_dict

mcp = FastMCP(
    "llm-assure",
    instructions=(
        "Red-teaming and assurance tools for LLM applications. Use list_suites to see "
        "attack categories, run_assessment for a full automated audit with reports, and "
        "send_probe to try your own adaptive attacks against a target. Only test systems "
        "the user owns or is authorized to assess."
    ),
)


def _resolve_target(target_file: str | None, target: dict[str, Any] | None) -> Target:
    if target_file:
        return load_target(target_file)
    if target:
        return target_from_dict(target, base_dir=Path.cwd())
    raise ValueError("Provide either target_file (path to a target YAML) or target (inline config).")


def _clip(text: str, n: int = 600) -> str:
    return text if len(text) <= n else text[:n] + "…"


@mcp.tool()
def list_suites(pack_dirs: list[str] | None = None) -> list[dict[str, Any]]:
    """List available attack/eval suites with their OWASP mapping and probe counts.

    Args:
        pack_dirs: optional directories containing extra suite YAML files.
    """
    return [
        {"id": s.id, "title": s.title, "owasp": s.owasp, "probes": len(s.probes),
         "description": s.description.strip(), "source": s.source}
        for s in load_suites(pack_dirs=pack_dirs or [])
    ]


@mcp.tool()
def list_probes(suite_id: str, pack_dirs: list[str] | None = None) -> list[dict[str, Any]]:
    """List the probes in one suite (id, name, severity, prompts, detector types)."""
    suite = load_suites([suite_id], pack_dirs=pack_dirs or [])[0]
    return [
        {"id": p.id, "name": p.name, "severity": p.severity, "turns": p.turns,
         "detectors": [d.get("type") for d in p.detectors], "tags": p.tags}
        for p in suite.probes
    ]


@mcp.tool()
def run_assessment(
    target_file: str | None = None,
    target: dict[str, Any] | None = None,
    suites: list[str] | None = None,
    tags: list[str] | None = None,
    pack_dirs: list[str] | None = None,
    use_judge: bool = False,
    output_dir: str = "llm-assure-report",
    concurrency: int = 4,
) -> dict[str, Any]:
    """Run an automated red-team assessment and write HTML/JSON/JUnit/Markdown reports.

    Args:
        target_file: path to a target YAML file (preferred).
        target: inline target config (same keys as the YAML) if no file is given.
        suites: suite ids to run; omit for all.
        tags: only run probes with these tags (e.g. ["baseline"] for a quick scan).
        pack_dirs: extra suite directories (premium/industry packs).
        use_judge: enable the Claude LLM-judge detector (needs ANTHROPIC_API_KEY).
        output_dir: where reports are written.
        concurrency: parallel requests to the target.
    Returns score, grade, counts, findings with evidence, and report paths.
    """
    t = _resolve_target(target_file, target)
    judge = None
    if use_judge:
        from .judge import ClaudeJudge
        judge = ClaudeJudge()
    try:
        result = _run_assessment(
            t, load_suites(suites, pack_dirs=pack_dirs or [], tags=tags),
            judge=judge, concurrency=concurrency,
        )
    finally:
        t.close()
    paths = write_reports(result, output_dir)
    return {
        "target": result.target_name,
        "score": result.risk_score,
        "grade": result.grade,
        "counts": result.counts(),
        "failures_by_severity": result.failure_counts_by_severity(),
        "categories": result.suite_summary(),
        "findings": [
            {"id": r.probe_id, "name": r.probe_name, "suite": r.suite, "severity": r.severity,
             "evidence": _clip(r.last_response),
             "reasons": [h.detail for h in r.hits if h.vulnerable]}
            for r in result.failures
        ],
        "reports": {k: str(v.resolve()) for k, v in paths.items()},
    }


@mcp.tool()
def send_probe(
    prompt: str,
    target_file: str | None = None,
    target: dict[str, Any] | None = None,
    history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Send one custom prompt (optionally after prior turns) to the target and run quick checks.

    Use this for adaptive, multi-step red-teaming: read the reply, then craft the next
    attempt. Quick checks report refusal, system-prompt canary leaks and PII/secrets.

    Args:
        prompt: the message to send.
        target_file / target: the system under test.
        history: earlier turns as [{"role": "user"|"assistant", "content": "..."}].
    """
    t = _resolve_target(target_file, target)
    try:
        transcript = list(history or []) + [{"role": "user", "content": prompt}]
        reply = t.send(transcript)
        transcript.append({"role": "assistant", "content": reply})
        checks = {
            "refused": is_refusal(reply),
            "canary": run_detector({"type": "canary"}, reply, transcript, t.context, None).detail,
            "pii": run_detector({"type": "pii", "kinds": list(PII_PATTERNS)}, reply, transcript,
                                t.context, None).detail,
        }
    finally:
        t.close()
    return {"response": reply, "checks": checks, "transcript": transcript}


@mcp.tool()
def get_findings(report_json: str, min_severity: str = "low") -> list[dict[str, Any]]:
    """Read failures from a previous assessment.json, filtered by minimum severity
    (critical, high, medium, low)."""
    data = json.loads(Path(report_json).read_text(encoding="utf-8"))
    limit = SEVERITY_ORDER.index(min_severity)
    return [
        {"id": r["probe_id"], "name": r["probe_name"], "suite": r["suite"], "severity": r["severity"],
         "transcript": r["transcript"], "reasons": [h["detail"] for h in r["hits"] if h["vulnerable"]]}
        for r in data["results"]
        if r["status"] == "fail" and SEVERITY_ORDER.index(r["severity"]) <= limit
    ]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
