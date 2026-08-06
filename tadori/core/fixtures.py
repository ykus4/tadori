"""Rule fixtures: synthetic apps that pin a rule's behaviour.

A fixture describes a tiny app in YAML — a few methods, their features, their
call edges, a manifest — and asserts that one rule does or does not fire on it.
It runs through the same matcher, entry-point discovery and reachability code as
a real scan; only DEX decoding (covered by its own unit tests) is bypassed.

That keeps the rule corpus testable with no sample, no APK and no toolchain:

    fixture:
      name: notification listener reads a posted notification
      rule: TAD-CRED-0001
      expect: match
      entry_kind: notification_listener
      app:
        components:
          - {type: service, name: com.x.NotifSvc,
             permission: android.permission.BIND_NOTIFICATION_LISTENER_SERVICE}
        methods:
          - ref: "Lcom/x/NotifSvc;->onNotificationPosted(Landroid/service/notification/StatusBarNotification;)V"
            api: ["Landroid/service/notification/StatusBarNotification;->getNotification()V"]
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tadori.core import engine
from tadori.core.features import AppIndex, MethodFeatures
from tadori.core.ingest import Component, Manifest
from tadori.core.loading import yaml_documents
from tadori.core.models import AppInfo, ScanResult
from tadori.core.rules import AppFacts, Rule, RuleError

EXPECTATIONS = ("match", "no-match")


class FixtureError(ValueError):
    """A fixture file is malformed."""


@dataclass
class Fixture:
    """One synthetic app plus the expectation it pins down."""

    name: str
    rule_id: str
    expect: str = "match"
    entry_kind: str | None = None
    hops: int | None = None
    app: dict[str, Any] = field(default_factory=dict)
    source: Path | None = None

    @property
    def should_match(self) -> bool:
        return self.expect == "match"


@dataclass
class FixtureOutcome:
    fixture: Fixture
    passed: bool
    detail: str = ""
    result: ScanResult | None = None


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------


def builtin_fixtures_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "fixtures"


def load_fixtures(paths: list[Path] | None = None) -> list[Fixture]:
    """Load fixtures from files/directories, defaulting to the bundled set."""
    return [
        _parse(document, path)
        for document, path in yaml_documents(
            paths, builtin_fixtures_dir(), kind="fixture", error=FixtureError
        )
    ]


def _parse(document: dict[str, Any], source: Path) -> Fixture:
    body = document.get("fixture", document)
    if not isinstance(body, dict):
        raise FixtureError(f"{source}: top level must be a 'fixture' mapping")
    for required in ("name", "rule"):
        if required not in body:
            raise FixtureError(f"{source}: fixture is missing '{required}'")

    expect = str(body.get("expect", "match"))
    if expect not in EXPECTATIONS:
        raise FixtureError(
            f"{source}: bad expect {expect!r} (use {' or '.join(EXPECTATIONS)})"
        )

    return Fixture(
        name=str(body["name"]),
        rule_id=str(body["rule"]),
        expect=expect,
        entry_kind=body.get("entry_kind"),
        hops=body.get("hops"),
        app=body.get("app") or {},
        source=source,
    )


# ---------------------------------------------------------------------------
# building a subject
# ---------------------------------------------------------------------------


def build_subject(app: dict[str, Any]) -> engine.Subject:
    """Turn a fixture's ``app`` block into something the matcher can consume."""
    index = _build_index(app)
    manifest = _build_manifest(app)
    facts = AppFacts.from_manifest(
        manifest,
        files=list(app.get("files") or []),
        native_libs=list(app.get("native_libs") or []),
    )
    info = AppInfo(
        path="fixture",
        name="fixture",
        package=manifest.package,
        permissions=sorted(facts.permissions),
        native_libs=sorted(facts.native_libs),
        method_count=index.method_count,
        dex_count=1,
    )
    return engine.Subject(index=index, manifest=manifest, facts=facts, info=info)


def _build_index(app: dict[str, Any]) -> AppIndex:
    index = AppIndex()
    index.supers = {k: list(v) for k, v in (app.get("supers") or {}).items()}
    index.js_bridge_classes = set(app.get("js_bridge_classes") or [])

    methods = app.get("methods") or []
    for spec in methods:
        ref = index.record_method(str(spec["ref"]))
        feats = MethodFeatures(
            api=_hits(spec.get("api")),
            string=_hits(spec.get("string")),
            field=_hits(spec.get("field")),
            type=_hits(spec.get("type")),
            opcode=Counter(spec.get("opcode") or {}),
        )
        if feats:
            index.features[ref] = feats

    for spec in methods:
        for callee in spec.get("calls") or []:
            index.callers[str(callee)].add(str(spec["ref"]))

    index.method_count = len(index.internal_refs)
    return index


def _hits(values: list[str] | None) -> list[tuple[str, int]]:
    return [(str(v), i * 4) for i, v in enumerate(values or [])]


def _build_manifest(app: dict[str, Any]) -> Manifest:
    manifest = Manifest(
        package=str(app.get("package", "com.example.fixture")),
        version_name=str(app.get("version_name", "1.0")),
        version_code=str(app.get("version_code", "1")),
        application_class=app.get("application_class", ""),
        permissions=list(app.get("permissions") or []),
        metadata=dict(app.get("metadata") or {}),
        flags={k: str(v).lower() for k, v in (app.get("flags") or {}).items()},
    )
    for spec in app.get("components") or []:
        actions = [str(a) for a in (spec.get("actions") or [])]
        component = Component(
            type=str(spec["type"]),
            name=str(spec["name"]),
            exported=bool(spec.get("exported", bool(actions))),
            permission=str(spec.get("permission", "")),
            actions=actions,
        )
        manifest.components.append(component)
        manifest.intent_actions.update(actions)
    return manifest


# ---------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------


def run(fixture: Fixture, rules: dict[str, Rule]) -> FixtureOutcome:
    """Evaluate one fixture against its rule."""
    rule = rules.get(fixture.rule_id)
    if rule is None:
        return FixtureOutcome(fixture, False, f"no such rule: {fixture.rule_id}")

    try:
        subject = build_subject(fixture.app)
    except (KeyError, TypeError, ValueError) as exc:
        return FixtureOutcome(fixture, False, f"bad fixture app block: {exc}")

    result = engine.analyze(
        subject,
        [rule],
        engine.ScanOptions(rules=[rule], timeout=None),
    )
    matched = bool(result.capabilities)

    if matched != fixture.should_match:
        if not fixture.should_match:
            return FixtureOutcome(fixture, False, "expected no match", result)
        return FixtureOutcome(fixture, False, _why_not(subject, rule), result)

    if matched:
        problem = _check_path_expectations(fixture, result)
        if problem:
            return FixtureOutcome(fixture, False, problem, result)

    return FixtureOutcome(fixture, True, result=result)


def _why_not(subject: engine.Subject, rule: Rule) -> str:
    """ "expected a match" plus the part of the condition that did not hold."""
    diagnosis = engine.diagnose(subject, rule)
    if diagnosis.matched_sites:
        return "expected a match; the condition held but nothing could reach it"
    if diagnosis.trace is None:
        return "expected a match; no site in the fixture carries a relevant feature"
    if not diagnosis.missing:
        return "expected a match"
    where = f" at {diagnosis.location}" if diagnosis.location else ""
    return f"expected a match; missing{where}: {'; '.join(diagnosis.missing[:3])}"


def _check_path_expectations(fixture: Fixture, result: ScanResult) -> str:
    if fixture.entry_kind is None and fixture.hops is None:
        return ""
    path = result.capabilities[0].matches[0].best_path
    if path is None:
        return "expected a call path, found none"
    if fixture.entry_kind is not None and path.entry.kind.value != fixture.entry_kind:
        return f"entry kind was {path.entry.kind.value}, expected {fixture.entry_kind}"
    if fixture.hops is not None and path.hops != fixture.hops:
        return f"path was {path.hops} hops, expected {fixture.hops}"
    return ""


def run_all(
    fixtures: list[Fixture], rules: list[Rule]
) -> tuple[list[FixtureOutcome], set[str]]:
    """Run every fixture; also report which rules have no positive fixture."""
    by_id = {rule.id: rule for rule in rules}
    outcomes = [run(fixture, by_id) for fixture in fixtures]
    covered = {f.rule_id for f in fixtures if f.should_match}
    uncovered = {rule.id for rule in rules} - covered
    return outcomes, uncovered


def require_known_rules(fixtures: list[Fixture], rules: list[Rule]) -> None:
    """Raise when a fixture names a rule that does not exist."""
    known = {rule.id for rule in rules}
    unknown = sorted({f.rule_id for f in fixtures} - known)
    if unknown:
        raise RuleError(f"fixtures reference unknown rules: {', '.join(unknown)}")
