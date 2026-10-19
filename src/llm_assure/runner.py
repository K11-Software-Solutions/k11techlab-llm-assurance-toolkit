"""Execute probes against a target and evaluate the responses."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable

from .detectors import Judge, render, run_detector
from .models import (
    ERROR, FAIL, PASS, REVIEW,
    AssessmentResult, DetectorHit, Probe, ProbeResult, Suite,
)
from .targets import Target

ProgressFn = Callable[[ProbeResult], None]


def _decide(hits: list[DetectorHit]) -> str:
    """Any detector flagging the response fails the probe.

    If no detector flagged it and at least one gave a definitive "safe"
    verdict, the probe passes. If every detector was inconclusive (e.g. only an
    LLM judge that was disabled), the probe needs human review.
    """
    if any(h.vulnerable is True for h in hits):
        return FAIL
    if any(h.vulnerable is False for h in hits):
        return PASS
    return REVIEW


def run_probe(probe: Probe, target: Target, judge: Judge | None = None) -> ProbeResult:
    ctx = target.context
    transcript: list[dict[str, str]] = []
    start = time.perf_counter()
    try:
        for turn in probe.turns:
            transcript.append({"role": "user", "content": render(turn, ctx)})
            reply = target.send(list(transcript))
            transcript.append({"role": "assistant", "content": reply})
    except Exception as exc:
        return ProbeResult(
            probe_id=probe.id, probe_name=probe.name, suite=probe.suite, severity=probe.severity,
            status=ERROR, transcript=transcript, hits=[],
            duration_ms=int((time.perf_counter() - start) * 1000),
            error=f"{type(exc).__name__}: {exc}",
        )

    response = transcript[-1]["content"]
    hits: list[DetectorHit] = []
    deterministic = [d for d in probe.detectors if d.get("type") != "llm_judge"]
    judges = [d for d in probe.detectors if d.get("type") == "llm_judge"]
    for spec in deterministic:
        hits.append(run_detector(spec, response, transcript, ctx, judge))
    # Only spend judge calls when deterministic checks didn't already find a failure.
    if not any(h.vulnerable for h in hits):
        for spec in judges:
            hits.append(run_detector(spec, response, transcript, ctx, judge))

    return ProbeResult(
        probe_id=probe.id, probe_name=probe.name, suite=probe.suite, severity=probe.severity,
        status=_decide(hits), transcript=transcript, hits=hits,
        duration_ms=int((time.perf_counter() - start) * 1000),
    )


def run_assessment(
    target: Target,
    suites: list[Suite],
    judge: Judge | None = None,
    concurrency: int = 4,
    progress: ProgressFn | None = None,
) -> AssessmentResult:
    from . import __version__

    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    probes = [p for s in suites for p in s.probes]
    results: list[ProbeResult] = []

    def task(p: Probe) -> ProbeResult:
        r = run_probe(p, target, judge)
        if progress:
            progress(r)
        return r

    if concurrency <= 1:
        results = [task(p) for p in probes]
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(task, probes))

    return AssessmentResult(
        target_name=target.name,
        started_at=started,
        finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        suites=suites,
        results=results,
        judge_model=getattr(judge, "model", None),
        toolkit_version=__version__,
    )
