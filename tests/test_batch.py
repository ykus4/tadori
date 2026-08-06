"""Scanning a corpus: collection, per-app isolation, ranking."""

from __future__ import annotations

import pytest

from tadori.core import batch, engine, score
from tadori.core.models import AppInfo, Capability, Match, ScanResult, Severity


def fake_result(package: str, *severities: Severity) -> ScanResult:
    capabilities = [
        Capability(
            rule_id=f"TAD-FAKE-{i:04d}",
            name="fake",
            severity=severity,
            scope="method",
            matches=[Match(f"TAD-FAKE-{i:04d}", "Lcom/x/A;->f()V", reachable=True)],
        )
        for i, severity in enumerate(severities, 1)
    ]
    result = ScanResult(
        app=AppInfo(path=f"{package}.apk", package=package, version_name="1.0"),
        capabilities=capabilities,
    )
    score.apply(result)
    return result


@pytest.fixture
def corpus(tmp_path):
    for name in ("a.apk", "b.apk", "notes.txt", "nested/c.apk", "d.APK"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"not really an apk")
    return tmp_path


def test_collect_apps_walks_directories_and_ignores_other_files(corpus):
    found = batch.collect_apps([corpus])
    # Sorted by path, so a nested app comes after the ones beside it.
    assert [p.name for p in found] == ["a.apk", "b.apk", "d.APK", "c.apk"]


def test_collect_apps_honours_the_limit_and_explicit_files(corpus):
    assert len(batch.collect_apps([corpus], limit=2)) == 2
    single = batch.collect_apps([corpus / "a.apk"])
    assert [p.name for p in single] == ["a.apk"]


def test_collect_apps_rejects_a_path_that_is_not_there(tmp_path):
    with pytest.raises(FileNotFoundError, match="input not found"):
        batch.collect_apps([tmp_path / "nope.apk"])


def test_one_unreadable_app_does_not_end_the_run(corpus, monkeypatch):
    def flaky(path, _options=None):
        if path.name == "b.apk":
            raise ValueError("no parsable DEX found in input")
        return fake_result(path.stem, Severity.LOW)

    monkeypatch.setattr(engine, "scan", flaky)
    found = batch.run(batch.collect_apps([corpus]))

    assert len(found.outcomes) == 4
    assert [o.path.name for o in found.failures] == ["b.apk"]
    assert "no parsable DEX" in found.failures[0].error
    assert len(found.scanned) == 3


def test_ranked_puts_the_worst_app_first(corpus, monkeypatch):
    scores = {
        "a.apk": (Severity.LOW,),
        "b.apk": (Severity.HIGH, Severity.HIGH),
        "c.apk": (Severity.MEDIUM,),
        "d.APK": (),
    }
    monkeypatch.setattr(
        engine, "scan", lambda path, _o=None: fake_result(path.stem, *scores[path.name])
    )
    found = batch.run(batch.collect_apps([corpus]))

    assert [o.path.name for o in found.ranked()] == ["b.apk", "c.apk", "a.apk", "d.APK"]
    assert found.ranked()[0].to_dict()["high"] == 2
    assert found.ranked()[0].score > found.ranked()[-1].score


def test_progress_callback_reports_position(corpus, monkeypatch):
    monkeypatch.setattr(engine, "scan", lambda path, _o=None: fake_result(path.stem))
    seen: list[tuple[int, str]] = []
    batch.run(
        batch.collect_apps([corpus]), on_start=lambda n, p: seen.append((n, p.name))
    )
    assert seen[0] == (1, "a.apk")
    assert [n for n, _ in seen] == [1, 2, 3, 4]


def test_outcome_of_a_failure_serialises_without_a_result(corpus, monkeypatch):
    monkeypatch.setattr(
        engine, "scan", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("boom"))
    )
    found = batch.run(batch.collect_apps([corpus], limit=1))
    assert found.outcomes[0].to_dict() == {
        "path": str(corpus / "a.apk"),
        "error": "boom",
    }
    assert found.seconds_per_app() == 0.0
