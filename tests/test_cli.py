"""The command line, driven through click's runner.

Commands that need bytecode are exercised elsewhere; what is checked here is
the wiring — exit codes, stored baselines, and the shape of the output an
analyst or a CI job reads.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from tadori.cli import cli
from tadori.core import engine, score
from tadori.core.models import (
    AppInfo,
    CallPath,
    Capability,
    EntryKind,
    EntryPoint,
    Match,
    ScanResult,
    Severity,
)

REMOTE = EntryPoint("Lcom/x/R;->onReceive()V", EntryKind.EXPORTED_RECEIVER)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def result(*rule_ids: str, severity: Severity = Severity.HIGH, **app) -> ScanResult:
    capabilities = []
    for rule_id in rule_ids:
        target = f"Lcom/x/P;->{rule_id.lower().replace('-', '_')}()V"
        capabilities.append(
            Capability(
                rule_id=rule_id,
                name=f"{rule_id} does a thing",
                severity=severity,
                scope="method",
                matches=[
                    Match(
                        rule_id=rule_id,
                        location=target,
                        paths=[CallPath(REMOTE, (REMOTE.method, target))],
                        reachable=True,
                    )
                ],
            )
        )
    scan = ScanResult(
        app=AppInfo(path="app.apk", package="com.x", **app),
        capabilities=capabilities,
        entry_points=[REMOTE],
    )
    score.apply(scan)
    return scan


def baseline(tmp_path, name: str, scan: ScanResult):
    path = tmp_path / name
    path.write_text(json.dumps(scan.to_dict()))
    return path


# ---------------------------------------------------------------------------
# diff against stored baselines
# ---------------------------------------------------------------------------


def test_diff_between_two_stored_baselines(runner, tmp_path):
    old = baseline(tmp_path, "old.json", result("TAD-KEEP-0001", version_name="1.4.0"))
    new = baseline(
        tmp_path,
        "new.json",
        result("TAD-KEEP-0001", "TAD-NEW-0001", version_name="1.5.0"),
    )

    out = runner.invoke(cli, ["diff", str(old), str(new)])
    assert out.exit_code == 0, out.output
    assert "TAD-NEW-0001" in out.output
    assert "1.4.0" in out.output and "1.5.0" in out.output


def test_diff_fails_the_build_on_a_regression(runner, tmp_path):
    old = baseline(tmp_path, "old.json", result())
    new = baseline(tmp_path, "new.json", result("TAD-NEW-0001"))

    assert runner.invoke(cli, ["diff", str(old), str(new)]).exit_code == 0
    gated = runner.invoke(
        cli, ["diff", str(old), str(new), "--fail-on-regression", "--json"]
    )
    assert gated.exit_code == 1
    assert json.loads(gated.output)["regression"] is True


def test_diff_reports_a_clean_update(runner, tmp_path):
    old = baseline(tmp_path, "old.json", result("TAD-KEEP-0001"))
    new = baseline(tmp_path, "new.json", result("TAD-KEEP-0001"))
    out = runner.invoke(cli, ["diff", str(old), str(new), "--fail-on-regression"])
    assert out.exit_code == 0
    assert "no new capabilities" in out.output


def test_diff_rejects_a_baseline_that_is_not_one(runner, tmp_path):
    junk = tmp_path / "junk.json"
    junk.write_text('["not a result"]')
    other = baseline(tmp_path, "new.json", result())
    out = runner.invoke(cli, ["diff", str(junk), str(other)])
    assert out.exit_code == 2


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


def test_rules_list_json_is_machine_readable(runner):
    out = runner.invoke(cli, ["rules", "list", "--json"])
    assert out.exit_code == 0
    rules = json.loads(out.output)
    assert len(rules) > 40
    assert all(r["id"].startswith("TAD-") for r in rules)


def test_rules_show_explains_one_rule(runner):
    out = runner.invoke(cli, ["rules", "show", "tad-cred-0001"])  # case-insensitive
    assert out.exit_code == 0
    assert "TAD-CRED-0001" in out.output
    assert "condition" in out.output


def test_unknown_rule_exits_two(runner):
    assert runner.invoke(cli, ["rules", "show", "TAD-NOPE-9999"]).exit_code == 2


# ---------------------------------------------------------------------------
# triage
# ---------------------------------------------------------------------------


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    """Three fake APKs whose scans are stubbed out."""
    scores = {
        "calm.apk": [],
        "loud.apk": ["TAD-LOUD-0001", "TAD-LOUD-0002"],
        "mild.apk": ["TAD-MILD-0001"],
    }
    for name in scores:
        (tmp_path / name).write_bytes(b"stub")

    def fake_scan(path, _options=None):
        severity = Severity.HIGH if path.name == "loud.apk" else Severity.LOW
        return result(*scores[path.name], severity=severity, version_name="1.0")

    monkeypatch.setattr(engine, "scan", fake_scan)
    return tmp_path


def test_triage_ranks_apps_worst_first(runner, corpus):
    out = runner.invoke(cli, ["triage", str(corpus)])
    assert out.exit_code == 0, out.output
    assert out.stdout.index("TAD-LOUD-0001") < out.stdout.index("TAD-MILD-0001")


def test_triage_json_is_ordered_and_complete(runner, corpus):
    out = runner.invoke(cli, ["triage", str(corpus), "-f", "json"])
    assert out.exit_code == 0
    data = json.loads(out.stdout)
    assert data["apps"] == 3
    assert data["failures"] == []
    assert [Path(r["path"]).name for r in data["results"]][0] == "loud.apk"
    assert data["results"][0]["high"] == 2


def test_triage_csv_has_a_header_and_a_row_per_app(runner, corpus):
    out = runner.invoke(cli, ["triage", str(corpus), "-f", "csv"])
    lines = out.stdout.strip().splitlines()
    assert lines[0].startswith("path,package,version_name,score,verdict,high")
    assert len(lines) == 4


def test_triage_gates_on_severity(runner, corpus):
    assert (
        runner.invoke(cli, ["triage", str(corpus), "--fail-on", "high"]).exit_code == 1
    )
    calm = runner.invoke(cli, ["triage", str(corpus / "calm.apk"), "--fail-on", "high"])
    assert calm.exit_code == 0


def test_triage_writes_to_a_file(runner, corpus, tmp_path):
    out_path = tmp_path / "triage.json"
    out = runner.invoke(cli, ["triage", str(corpus), "-f", "json", "-o", str(out_path)])
    assert out.exit_code == 0
    assert json.loads(out_path.read_text())["apps"] == 3


def test_triage_without_apps_exits_two(runner, tmp_path):
    (tmp_path / "readme.txt").write_text("nothing to scan")
    assert runner.invoke(cli, ["triage", str(tmp_path)]).exit_code == 2


# ---------------------------------------------------------------------------
# explain: why a rule did not fire
# ---------------------------------------------------------------------------


def test_diagnosis_printer_marks_each_branch(capsys):
    from tadori.cli import _print_diagnosis
    from tadori.core import engine, fixtures
    from tadori.core.rules import load_rules

    rule = next(r for r in load_rules() if r.id == "TAD-CRED-0002")
    subject = fixtures.build_subject(
        {
            "methods": [
                {
                    "ref": "Lcom/x/R;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V",
                    "api": [
                        "Landroid/telephony/SmsMessage;->getMessageBody()Ljava/lang/String;"
                    ],
                }
            ]
        }
    )
    _print_diagnosis(engine.diagnose(subject, rule))

    out = capsys.readouterr().out
    assert "closest site" in out
    assert "✓" in out and "✗" in out
    assert "missing" in out
    assert "RECEIVE_SMS" in out


def test_diagnosis_printer_handles_an_app_with_no_candidate_site(capsys):
    from tadori.cli import _print_diagnosis
    from tadori.core import engine, fixtures
    from tadori.core.rules import load_rules

    rule = next(r for r in load_rules() if r.id == "TAD-CRED-0002")
    subject = fixtures.build_subject({"methods": [{"ref": "Lcom/x/A;->f()V"}]})
    _print_diagnosis(engine.diagnose(subject, rule))
    assert "0 candidate sites" in capsys.readouterr().out
