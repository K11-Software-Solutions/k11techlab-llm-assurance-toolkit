"""Load attack/eval suites from YAML.

Built-in suites ship inside the package. Extra suites (e.g. premium industry
packs) can be loaded from any directory with ``--pack DIR``.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any, Iterable

import yaml

from .models import Probe, Suite, SEVERITY_WEIGHTS


class SuiteError(ValueError):
    pass


def _parse_suite(data: dict[str, Any], source: str) -> Suite:
    sid = data.get("id")
    if not sid:
        raise SuiteError(f"{source}: suite is missing 'id'")
    probes = []
    for raw in data.get("probes", []):
        pid = raw.get("id")
        if not pid:
            raise SuiteError(f"{source}: probe without 'id' in suite {sid}")
        severity = raw.get("severity", "medium")
        if severity not in SEVERITY_WEIGHTS:
            raise SuiteError(f"{source}: probe {pid} has invalid severity '{severity}'")
        turns = raw.get("turns") or ([raw["prompt"]] if "prompt" in raw else [])
        if not turns:
            raise SuiteError(f"{source}: probe {pid} needs 'prompt' or 'turns'")
        detectors = raw.get("detectors") or []
        if not detectors:
            raise SuiteError(f"{source}: probe {pid} has no detectors")
        probes.append(Probe(
            id=pid,
            name=raw.get("name", pid),
            severity=severity,
            turns=list(turns),
            detectors=list(detectors),
            suite=sid,
            description=raw.get("description", ""),
            tags=list(raw.get("tags", [])),
        ))
    return Suite(
        id=sid,
        title=data.get("title", sid),
        description=data.get("description", ""),
        owasp=data.get("owasp", ""),
        remediation=data.get("remediation", ""),
        probes=probes,
        source=source,
    )


def _builtin_files() -> list[tuple[str, str]]:
    pkg = resources.files("llm_assure") / "suites"
    out = []
    for entry in sorted(pkg.iterdir(), key=lambda p: p.name):
        if entry.name.endswith((".yaml", ".yml")):
            out.append((f"builtin:{entry.name}", entry.read_text(encoding="utf-8")))
    return out


def _pack_files(pack_dirs: Iterable[str | Path]) -> list[tuple[str, str]]:
    out = []
    for d in pack_dirs:
        d = Path(d)
        if not d.is_dir():
            raise SuiteError(f"pack directory not found: {d}")
        for f in sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml"))):
            out.append((str(f), f.read_text(encoding="utf-8")))
    return out


def load_suites(
    selected: Iterable[str] | None = None,
    pack_dirs: Iterable[str | Path] = (),
    include_builtin: bool = True,
    tags: Iterable[str] | None = None,
) -> list[Suite]:
    files = (_builtin_files() if include_builtin else []) + _pack_files(pack_dirs)
    suites: dict[str, Suite] = {}
    for source, text in files:
        data = yaml.safe_load(text) or {}
        suite = _parse_suite(data, source)
        if suite.id in suites:
            # A pack may extend a built-in suite with extra probes.
            suites[suite.id].probes.extend(suite.probes)
        else:
            suites[suite.id] = suite

    wanted = [s for s in (selected or []) if s and s != "all"]
    if wanted:
        unknown = [s for s in wanted if s not in suites]
        if unknown:
            raise SuiteError(f"unknown suite(s): {', '.join(unknown)}. Available: {', '.join(suites)}")
        result = [suites[s] for s in wanted]
    else:
        result = list(suites.values())

    tag_set = set(tags or [])
    if tag_set:
        for s in result:
            s.probes = [p for p in s.probes if tag_set & set(p.tags)]
        result = [s for s in result if s.probes]
    return result
