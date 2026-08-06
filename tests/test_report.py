"""Output rendering: terminal, JSON, SARIF, HTML."""

from __future__ import annotations

import json

import pytest

from tadori.core import report
from tadori.core.models import (
    AppInfo,
    CallPath,
    Capability,
    EntryKind,
    EntryPoint,
    Evidence,
    Match,
    ScanResult,
    Severity,
)

ENTRY = EntryPoint("Lcom/x/Svc;->onCreate()V", EntryKind.EXPORTED_SERVICE)
TARGET = "Lcom/x/Payload;->send(Ljava/lang/String;I)V"


@pytest.fixture
def result() -> ScanResult:
    match = Match(
        rule_id="TAD-ACCS-0001",
        location=TARGET,
        evidence=[Evidence("api", "Lcom/x/Y;->f()V", TARGET, 0x14)],
        paths=[CallPath(ENTRY, (ENTRY.method, TARGET))],
        reachable=True,
    )
    capability = Capability(
        rule_id="TAD-ACCS-0001",
        name="drive the UI through an accessibility service",
        severity=Severity.HIGH,
        scope="method",
        description="a description",
        attack=["T1516"],
        references=["https://attack.mitre.org/techniques/T1516/"],
        matches=[match],
        score_contribution=20.0,
        score_reason="high (20) x remote reach (1)",
    )
    return ScanResult(
        app=AppInfo(
            path="/tmp/app.apk",
            name="app.apk",
            package="com.x",
            version_name="1.0",
            method_count=1234,
            dex_count=1,
            permissions=["android.permission.BIND_ACCESSIBILITY_SERVICE"],
        ),
        capabilities=[capability],
        entry_points=[ENTRY],
        score=20.0,
        verdict="suspicious",
        rules_evaluated=41,
        tadori_version="0.1.0",
    )


def test_short_ref_drops_parameters():
    assert report.short_ref(TARGET) == "Lcom/x/Payload;->send(…)V"


def test_short_ref_elides_very_long_names():
    long_ref = "Lcom/" + "a" * 200 + ";->f()V"
    out = report.short_ref(long_ref)
    assert len(out) <= report.MAX_REF_LEN + 1
    assert "…" in out


def test_short_ref_leaves_plain_values_alone():
    assert report.short_ref("api.telegram.org/bot") == "api.telegram.org/bot"


def test_text_output_contains_the_essentials(result):
    text = report.to_text(result, width=120)
    assert "TAD-ACCS-0001" in text
    assert "com.x" in text
    assert "suspicious" in text
    assert "exported_service" in text
    assert "0x14" in text
    assert "Lcom/x/Payload;->send(…)V" in text


def test_verbose_text_shows_the_full_chain(result):
    text = report.to_text(result, verbose=True, width=120)
    assert "Input Injection" in text  # ATT&CK name, only in verbose
    assert "a description" in text
    assert text.count("Lcom/x/Svc;->onCreate(…)V") >= 2  # entry line + chain step


def test_empty_result_says_so():
    empty = ScanResult(app=AppInfo(path="a.apk"))
    assert "no capabilities matched" in report.to_text(empty, width=80)


def test_json_round_trips(result):
    data = json.loads(report.render(result, "json"))
    assert data["app"]["package"] == "com.x"
    assert data["capabilities"][0]["matches"][0]["paths"][0]["hops"] == 1
    assert data["summary"]["high"] == 1
    assert data["capabilities"][0]["matches"][0]["evidence"][0]["offset"] == 0x14


def test_sarif_shape(result):
    sarif = json.loads(report.render(result, "sarif"))
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    assert run["tool"]["driver"]["name"] == "tadori"
    assert run["tool"]["driver"]["rules"][0]["id"] == "TAD-ACCS-0001"
    assert "T1516" in run["tool"]["driver"]["rules"][0]["properties"]["tags"]
    finding = run["results"][0]
    assert finding["level"] == "error"
    assert (
        finding["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == TARGET
    )
    assert finding["properties"]["reachable"] is True
    assert run["properties"]["verdict"] == "suspicious"


def test_sarif_fingerprint_is_stable_across_builds(result):
    finding = json.loads(report.render(result, "sarif"))["runs"][0]["results"][0]
    fingerprint = finding["partialFingerprints"]["tadoriMatch/v1"]

    # Same rule, same method, different build: the alert must not be re-opened.
    result.app.version_name = "2.0"
    result.capabilities[0].matches[0].evidence[0] = Evidence(
        "api", "Lcom/x/Y;->f()V", TARGET, 0x99
    )
    again = json.loads(report.render(result, "sarif"))["runs"][0]["results"][0]
    assert again["partialFingerprints"]["tadoriMatch/v1"] == fingerprint

    result.capabilities[0].matches[0].location = "Lcom/x/Other;->send()V"
    moved = json.loads(report.render(result, "sarif"))["runs"][0]["results"][0]
    assert moved["partialFingerprints"]["tadoriMatch/v1"] != fingerprint


def test_html_renders(result):
    html = report.render(result, "html")
    assert "<!DOCTYPE html>" in html
    assert "TAD-ACCS-0001" in html
    assert "exported_service" in html
    assert "not a malware verdict" in html


def test_unknown_format_is_rejected(result):
    with pytest.raises(ValueError, match="unknown format"):
        report.render(result, "yaml")


def test_entry_point_table_lists_kinds(result):
    table = report.entry_point_table(result)
    assert table.row_count == 1


# ---------------------------------------------------------------------------
# call-chain graphs
# ---------------------------------------------------------------------------


def test_dot_draws_the_chain_from_entry_point_to_match(result):
    dot = report.render(result, "dot")
    assert dot.startswith("// tadori")
    assert "digraph tadori {" in dot and dot.rstrip().endswith("}")
    assert "exported_service" in dot
    assert "TAD-ACCS-0001" in dot
    assert dot.count(" -> ") == 1  # entry -> match, one hop


def test_mermaid_is_a_flowchart(result):
    mermaid = report.render(result, "mermaid")
    assert "graph LR" in mermaid
    assert "-->" in mermaid
    assert "<br/>" in mermaid  # multi-line labels, not raw newlines
    assert "\n  n0" in mermaid


def test_graph_reuses_one_node_per_method(result):
    """A method reached twice must not appear twice, or the picture lies."""
    capability = result.capabilities[0]
    second = Match(
        rule_id="TAD-ACCS-0001",
        location=TARGET,
        paths=[CallPath(ENTRY, (ENTRY.method, "Lcom/x/Mid;->go()V", TARGET))],
        reachable=True,
    )
    capability.matches.append(second)

    nodes, edges = report.call_graph(result)
    assert len({n.id for n in nodes}) == len(nodes)
    assert sum(1 for n in nodes if n.role == "match") == 1
    assert len(set(edges)) == len(edges)


def test_unreachable_match_is_drawn_without_edges():
    dead = Match(rule_id="TAD-X-0001", location="Lcom/x/D;->f()V", reachable=False)
    capability = Capability(
        rule_id="TAD-X-0001",
        name="dead capability",
        severity=Severity.LOW,
        scope="method",
        matches=[dead],
    )
    scan = ScanResult(app=AppInfo(path="a.apk"), capabilities=[capability])
    nodes, edges = report.call_graph(scan)
    assert [n.role for n in nodes] == ["match"]
    assert edges == []
