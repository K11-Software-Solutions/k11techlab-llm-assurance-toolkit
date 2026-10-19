"""Command-line interface: ``llm-assure``."""

from __future__ import annotations

import argparse
import os
import sys
import threading
from pathlib import Path

from . import __version__
from .models import FAIL, SEVERITY_ORDER
from .report import FORMATS, write_reports
from .runner import run_assessment
from .suites import SuiteError, load_suites
from .targets import load_target

SAMPLE_TARGET = """\
# Target under test. See README for all options.
name: My Support Assistant
type: http                      # http | openai | anthropic | python
url: http://localhost:8000/chat
method: POST
headers:
  Authorization: "Bearer ${BOT_API_TOKEN}"   # ${VAR} is read from the environment
request_template:
  message: "{{prompt}}"          # {{prompt}} = latest user turn
  history: "{{history}}"         # optional: earlier turns as a list
response_path: reply             # dotted path to the reply text in the JSON response
timeout: 60

# Context makes probes realistic and lets detectors judge correctly.
context:
  company: Acme Corp
  purpose: customer support for Acme Corp's online store
  canary: K11-CANARY-REPLACE-ME   # put this exact string in your system prompt
  forbidden_topics: [politics, religion]
"""


def _progress_printer(total: int):
    lock = threading.Lock()
    state = {"n": 0}
    marks = {"pass": ".", "fail": "F", "error": "E", "needs_review": "?"}

    def cb(r):
        with lock:
            state["n"] += 1
            sys.stderr.write(marks.get(r.status, "?"))
            if state["n"] % 50 == 0 or state["n"] == total:
                sys.stderr.write(f" {state['n']}/{total}\n")
            sys.stderr.flush()
    return cb


def cmd_run(args: argparse.Namespace) -> int:
    target = load_target(args.target)
    suites = load_suites(args.suite, pack_dirs=args.pack or [], tags=args.tag)
    total = sum(len(s.probes) for s in suites)
    if total == 0:
        print("No probes selected.", file=sys.stderr)
        return 2

    judge = None
    if args.judge:
        from .judge import ClaudeJudge
        judge = ClaudeJudge(model=args.judge_model, effort=args.judge_effort)

    print(f"Assessing '{target.name}' with {total} probes from {len(suites)} suites...", file=sys.stderr)
    try:
        result = run_assessment(
            target, suites, judge=judge, concurrency=args.concurrency,
            progress=_progress_printer(total),
        )
    finally:
        target.close()

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    paths = write_reports(result, args.out, formats)

    c = result.counts()
    sev = result.failure_counts_by_severity()
    print(f"\nScore {result.risk_score}/100 (grade {result.grade}) | "
          f"passed {c['pass']}  failed {c['fail']}  review {c['needs_review']}  errors {c['error']}")
    print("Failures: " + ", ".join(f"{s} {sev[s]}" for s in SEVERITY_ORDER))
    for fmt, p in paths.items():
        print(f"  {fmt:5} -> {p}")

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file and "md" in paths:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(paths["md"].read_text(encoding="utf-8"))

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        blocking = [r for r in result.results
                    if r.status == FAIL and SEVERITY_ORDER.index(r.severity) <= threshold]
        if blocking:
            print(f"Quality gate FAILED: {len(blocking)} finding(s) at or above '{args.fail_on}'.")
            return 1
        print(f"Quality gate passed (fail-on: {args.fail_on}).")
    return 0


def cmd_adaptive(args: argparse.Namespace) -> int:
    from .adaptive import AdaptiveRunner, save_record

    arm = "adaptive_cold" if args.cold else "adaptive_seeded"
    out_dir = Path(args.out)
    exit_code = 0
    for i in range(1, args.runs + 1):
        target = load_target(args.target)
        try:
            runner = AdaptiveRunner(
                target, model=args.attacker_model, effort=args.attacker_effort,
                budget=args.budget, arm=arm, static_suites=args.static_suite,
                white_box=args.white_box,
            )
            print(f"[{i}/{args.runs}] {arm} run against '{target.name}' (budget {args.budget})...",
                  file=sys.stderr)
            rec = runner.run()
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        finally:
            target.close()
        path = save_record(rec, out_dir)
        u = rec.attacker_usage
        print(f"  status {rec.status} | queries {rec.queries_static} static + {rec.queries_adaptive} adaptive"
              f" | findings {len(rec.findings)} | attacker turns {rec.attacker_turns}"
              f" | tokens in {u['input_tokens']} out {u['output_tokens']}"
              f" cache-read {u['cache_read_input_tokens']} | {rec.duration_s}s")
        if rec.error:
            print(f"  error: {rec.error}")
            exit_code = 1
        print(f"  record -> {path}")
    return exit_code


def cmd_suites(args: argparse.Namespace) -> int:
    suites = load_suites(pack_dirs=args.pack or [])
    for s in suites:
        print(f"{s.id:28} {len(s.probes):3} probes  {s.owasp}")
        if args.verbose:
            for p in s.probes:
                print(f"    {p.id:10} [{p.severity:8}] {p.name}")
    print(f"\n{sum(len(s.probes) for s in suites)} probes in {len(suites)} suites")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    target = load_target(args.target)
    try:
        print(target.send([{"role": "user", "content": args.prompt}]))
    finally:
        target.close()
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    path.write_text(SAMPLE_TARGET, encoding="utf-8")
    print(f"Wrote {path}. Edit it, then run: llm-assure run -t {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llm-assure", description="Red-team and assure LLM applications.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="run an assessment against a target")
    r.add_argument("-t", "--target", required=True, help="target YAML file")
    r.add_argument("-s", "--suite", action="append", help="suite id (repeatable; default: all)")
    r.add_argument("--tag", action="append", help="only probes with this tag, e.g. baseline")
    r.add_argument("--pack", action="append", help="extra suite directory (repeatable)")
    r.add_argument("-o", "--out", default="llm-assure-report", help="output directory")
    r.add_argument("-f", "--format", default=",".join(FORMATS), help=f"comma list of {FORMATS}")
    r.add_argument("--judge", action="store_true", help="enable the Claude LLM-judge detector")
    r.add_argument("--judge-model", default="claude-opus-5-5")
    r.add_argument("--judge-effort", choices=["low", "medium", "high", "xhigh", "max"], default=None)
    r.add_argument("-c", "--concurrency", type=int, default=4)
    r.add_argument("--fail-on", choices=[*SEVERITY_ORDER, "none"], default="high",
                   help="exit 1 if any finding at or above this severity (default: high)")
    r.set_defaults(func=cmd_run)

    a = sub.add_parser("adaptive", help="autonomous adaptive red-teaming with a Claude attacker agent")
    a.add_argument("-t", "--target", required=True, help="target YAML file")
    a.add_argument("--budget", type=int, default=100, help="max target queries per run, static included")
    a.add_argument("--cold", action="store_true", help="cold-start arm: skip the static suite seeding")
    a.add_argument("--static-suite", action="append", help="limit seeding to these suites (repeatable)")
    a.add_argument("--runs", type=int, default=1, help="independent runs (the study uses 5)")
    a.add_argument("--attacker-model", default="claude-opus-5-5")
    a.add_argument("--attacker-effort", choices=["low", "medium", "high", "xhigh", "max"], default=None)
    a.add_argument("--white-box", action="store_true",
                   help="show the attacker instrumented ground truth (tool calls) after each message")
    a.add_argument("-o", "--out", default="adaptive-runs", help="directory for JSON run records")
    a.set_defaults(func=cmd_adaptive)

    s = sub.add_parser("suites", help="list available suites")
    s.add_argument("--pack", action="append")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_suites)

    pr = sub.add_parser("probe", help="send one ad-hoc prompt to a target")
    pr.add_argument("-t", "--target", required=True)
    pr.add_argument("prompt")
    pr.set_defaults(func=cmd_probe)

    i = sub.add_parser("init", help="write a sample target.yaml")
    i.add_argument("path", nargs="?", default="target.yaml")
    i.add_argument("--force", action="store_true")
    i.set_defaults(func=cmd_init)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except SuiteError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
