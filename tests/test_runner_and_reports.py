import json
import threading
import xml.etree.ElementTree as ET
from http.server import ThreadingHTTPServer

from llm_assure.models import ERROR, FAIL, PASS, REVIEW, Probe
from llm_assure.report import to_html, to_junit, to_markdown, write_reports
from llm_assure.runner import run_assessment, run_probe
from llm_assure.suites import load_suites
from llm_assure.targets import Target, load_target, target_from_dict


def test_vulnerable_bot_fails_badly(vulnerable_target_file):
    result = run_assessment(load_target(vulnerable_target_file), load_suites(), concurrency=4)
    sev = result.failure_counts_by_severity()
    assert result.grade == "F"
    assert sev["critical"] >= 5
    assert result.counts()[ERROR] == 0


def test_hardened_bot_passes(hardened_target_file):
    result = run_assessment(load_target(hardened_target_file), load_suites(), concurrency=1)
    sev = result.failure_counts_by_severity()
    assert sev["critical"] == 0 and sev["high"] == 0
    assert result.grade == "A"
    assert result.risk_score >= 90


class Boom(Target):
    def send(self, messages):
        raise ConnectionError("target down")


def test_target_errors_are_reported_not_raised():
    probe = Probe(id="X1", name="x", severity="low", turns=["hi"], detectors=[{"type": "expect_refusal"}], suite="s")
    r = run_probe(probe, Boom({"name": "boom"}))
    assert r.status == ERROR and "target down" in r.error


class Echo(Target):
    def send(self, messages):
        return f"turn {len(messages)}: {messages[-1]['content']}"


def test_multi_turn_transcript_and_templating():
    t = Echo({"name": "echo", "context": {"company": "Acme"}})
    probe = Probe(id="M1", name="m", severity="low", turns=["hello {{company}}", "again"],
                  detectors=[{"type": "contains", "value": "turn 3: again"}], suite="s")
    r = run_probe(probe, t)
    assert [m["role"] for m in r.transcript] == ["user", "assistant", "user", "assistant"]
    assert r.transcript[0]["content"] == "hello Acme"
    assert r.status == FAIL


def test_judge_only_probe_needs_review_without_judge():
    probe = Probe(id="J1", name="j", severity="low", turns=["hi"],
                  detectors=[{"type": "llm_judge", "rubric": "r"}], suite="s")
    assert run_probe(probe, Echo({"name": "e"})).status == REVIEW


def test_reports_are_safe_and_valid(vulnerable_target_file, tmp_path):
    result = run_assessment(load_target(vulnerable_target_file), load_suites(), concurrency=4)
    page = to_html(result)
    assert "<script>alert" not in page            # transcripts are escaped
    assert "&lt;script&gt;alert" in page
    root = ET.fromstring(to_junit(result).split("?>", 1)[1])
    assert int(root[0].get("tests")) > 0
    assert "Score:" in to_markdown(result)
    paths = write_reports(result, tmp_path)
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["grade"] == "F" and len(data["results"]) == 41


def test_http_target_against_demo_server():
    from serve_demo_bot import make_handler
    from demo_bots import hardened_respond

    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(hardened_respond))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        target = target_from_dict({
            "name": "http-demo", "type": "http",
            "url": f"http://127.0.0.1:{server.server_port}/chat",
            "request_template": {"message": "{{prompt}}", "history": "{{history}}"},
            "response_path": "reply",
            "context": {"canary": "K11-CANARY-7F3A", "company": "Acme Outfitters"},
        })
        result = run_assessment(target, load_suites(["system_prompt_leakage"]), concurrency=2)
        target.close()
    finally:
        server.shutdown()
    assert all(r.status == PASS for r in result.results)
