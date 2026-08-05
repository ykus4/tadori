"""Scoring calibration and the version-to-version diff."""

from __future__ import annotations

from tadori.core import diff, score
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
LOCAL = EntryPoint("Lcom/x/A;-><clinit>()V", EntryKind.STATIC_INIT)


def capability(
    rule_id: str = "TAD-TEST-0001",
    *,
    severity: Severity = Severity.HIGH,
    scope: str = "method",
    entry: EntryPoint | None = REMOTE,
    reachable: bool | None = True,
    sites: int = 1,
) -> Capability:
    matches = []
    for i in range(sites):
        target = f"Lcom/x/P;->send{i}()V"
        paths = [CallPath(entry, (entry.method, target))] if entry else []
        matches.append(
            Match(rule_id=rule_id, location=target, paths=paths, reachable=reachable)
        )
    return Capability(
        rule_id=rule_id, name=rule_id, severity=severity, scope=scope, matches=matches
    )


def result(*capabilities: Capability, **app_kwargs) -> ScanResult:
    scan = ScanResult(
        app=AppInfo(path="app.apk", **app_kwargs), capabilities=list(capabilities)
    )
    score.apply(scan)
    return scan


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def test_remote_reach_scores_higher_than_local():
    remote = result(capability(entry=REMOTE))
    local = result(capability(entry=LOCAL))
    assert remote.score > local.score
    assert "remote reach" in remote.capabilities[0].score_reason


def test_unreachable_matches_are_heavily_damped():
    unreachable = result(capability(entry=None, reachable=False))
    assert unreachable.score < result(capability(entry=LOCAL)).score
    assert "unreachable" in unreachable.capabilities[0].score_reason


def test_reachability_not_computed_is_its_own_band():
    unknown = result(capability(entry=None, reachable=None))
    assert "unknown" in unknown.capabilities[0].score_reason


def test_manifest_scope_is_not_penalised_for_having_no_call_path():
    declared = result(capability(scope="apk", entry=None, reachable=None))
    assert "declared" in declared.capabilities[0].score_reason


def test_extra_sites_add_a_damped_bonus():
    one = result(capability(sites=1)).score
    many = result(capability(sites=6)).score
    assert one < many <= one * (1 + score.MAX_REPEAT_BONUS)


def test_score_is_capped_and_verdicts_are_ordered():
    many = result(*(capability(f"TAD-TEST-{i:04d}") for i in range(20)))
    assert many.score == score.MAX_SCORE
    assert many.verdict == "malicious-capability profile"
    assert result().verdict == "nothing notable"
    assert score.verdict_for(0) == "nothing notable"
    assert score.verdict_for(30) == "suspicious"


def test_a_single_info_capability_stays_unremarkable():
    quiet = result(capability(severity=Severity.INFO))
    assert quiet.verdict == "nothing notable"


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def test_added_high_capability_is_a_regression():
    old = result(capability("TAD-KEEP-0001", severity=Severity.LOW))
    new = result(
        capability("TAD-KEEP-0001", severity=Severity.LOW),
        capability("TAD-NEW-0001", severity=Severity.HIGH),
    )
    delta = diff.compare(old, new)
    assert [c.rule_id for c in delta.added] == ["TAD-NEW-0001"]
    assert delta.is_regression()
    assert "TAD-NEW-0001" in delta.headline()
    assert delta.score_delta > 0


def test_removed_capability_is_not_a_regression():
    old = result(capability("TAD-GONE-0001", severity=Severity.HIGH))
    delta = diff.compare(old, result())
    assert [c.rule_id for c in delta.removed] == ["TAD-GONE-0001"]
    assert not delta.is_regression()
    assert delta.headline() == "no new capabilities"


def test_exposure_escalation_is_a_regression():
    old = result(capability(entry=LOCAL))
    new = result(capability(entry=REMOTE))
    delta = diff.compare(old, new)
    assert not delta.added
    assert delta.escalated
    assert delta.is_regression()
    assert "more exposed" in delta.headline()


def test_new_sensitive_permission_is_a_regression():
    old = result(permissions=["android.permission.INTERNET"])
    new = result(
        permissions=["android.permission.INTERNET", "android.permission.READ_SMS"]
    )
    delta = diff.compare(old, new)
    assert delta.added_permissions == ["android.permission.READ_SMS"]
    assert delta.watched_permissions == ["android.permission.READ_SMS"]
    assert delta.is_regression()


def test_new_harmless_permission_is_not_a_regression():
    old = result(permissions=[])
    new = result(permissions=["android.permission.VIBRATE"])
    delta = diff.compare(old, new)
    assert delta.added_permissions == ["android.permission.VIBRATE"]
    assert not delta.is_regression()


def test_certificate_change_outranks_everything():
    old = result(certificate_sha256="a" * 64)
    new = result(certificate_sha256="b" * 64)
    delta = diff.compare(old, new)
    assert delta.certificate_changed
    assert delta.is_regression()
    assert "not the same publisher" in delta.headline()
    assert delta.to_dict()["certificate_changed"]


def test_new_native_libraries_are_reported():
    old = result(native_libs=["lib/arm64-v8a/libapp.so"])
    new = result(native_libs=["lib/arm64-v8a/libapp.so", "lib/arm64-v8a/libjiagu.so"])
    delta = diff.compare(old, new)
    assert delta.added_native_libs == ["lib/arm64-v8a/libjiagu.so"]
