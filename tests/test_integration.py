"""End-to-end scan against a real APK.

Skipped unless ``TADORI_TEST_APK`` points at one. No sample is committed: use
any benign app you have locally, e.g. an F-Droid build.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from tadori.cli import cli
from tadori.core import diff, engine, report


def test_scan_a_real_apk(real_apk):
    result = engine.scan(real_apk, engine.ScanOptions(timeout=600))

    assert result.app.package
    assert result.app.method_count > 100
    assert result.app.dex_count >= 1
    assert result.entry_points, "a real app declares at least one component"
    assert 0 <= result.score <= 100
    assert result.verdict

    for capability in result.capabilities:
        for match in capability.matches:
            assert match.provenance == "app", "library matches are hidden by default"
            for path in match.paths:
                assert path.methods[-1] == match.location
                assert path.methods[0] == path.entry.method
                assert path.hops == len(path.methods) - 1


def test_every_format_renders_for_a_real_apk(real_apk):
    result = engine.scan(real_apk, engine.ScanOptions(timeout=600))
    for fmt in report.FORMATS:
        assert report.render(result, fmt)
    json.loads(report.render(result, "json"))
    json.loads(report.render(result, "sarif"))


def test_disabling_reachability_is_faster_and_marks_matches_unknown(real_apk):
    quick = engine.scan(real_apk, engine.ScanOptions(reachability=False, timeout=600))
    assert any("reachability analysis disabled" in w for w in quick.warnings)
    for capability in quick.capabilities:
        for match in capability.matches:
            assert match.reachable is None
            assert match.paths == []


def test_diff_of_an_app_against_itself_is_empty(real_apk):
    options = engine.ScanOptions(timeout=600)
    result = engine.scan(real_apk, options)
    delta = diff.compare(result, engine.scan(real_apk, options))

    assert not delta.added
    assert not delta.removed
    assert not delta.escalated
    assert delta.score_delta == 0
    assert not delta.is_regression()
    assert delta.headline() == "no new capabilities"


def test_cli_scan_and_rules_commands(real_apk):
    runner = CliRunner()

    listing = runner.invoke(cli, ["rules", "list", "--json"])
    assert listing.exit_code == 0
    assert len(json.loads(listing.output)) >= 20

    assert runner.invoke(cli, ["rules", "lint"]).exit_code == 0
    assert runner.invoke(cli, ["rules", "show", "TAD-ACCS-0001"]).exit_code == 0
    assert runner.invoke(cli, ["rules", "show", "TAD-NOPE-9999"]).exit_code == 2

    scan = runner.invoke(cli, ["scan", str(real_apk), "-f", "json"])
    assert scan.exit_code == 0
    assert json.loads(scan.output)["app"]["package"]

    explain = runner.invoke(cli, ["explain", "TAD-NAT-0001", str(real_apk)])
    assert explain.exit_code == 0
