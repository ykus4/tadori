"""Scan orchestration: load -> index -> match -> reachability -> score."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from tadori import __version__
from tadori.core import entrypoints, graph, ingest, libraries, score
from tadori.core.features import AppIndex, MethodFeatures, build_index, ref_class
from tadori.core.ingest import Manifest
from tadori.core.models import AppInfo, Capability, Match, ScanResult, Severity
from tadori.core.rules import (
    AppFacts,
    EvalContext,
    Rule,
    Trace,
    load_rules,
    vocabulary_for,
)

DEFAULT_TIMEOUT = 300.0


@dataclass
class ScanOptions:
    """Knobs for a scan; the defaults are what ``tadori scan`` uses."""

    rule_paths: list[Path] | None = None
    rules: list[Rule] | None = None
    reachability: bool = True
    max_hops: int = graph.DEFAULT_MAX_HOPS
    keep_unreachable: bool = False
    include_libraries: bool = False
    min_severity: Severity = Severity.INFO
    timeout: float | None = DEFAULT_TIMEOUT
    max_matches_per_rule: int = 50
    progress: object | None = None  # optional callable(str) for CLI feedback

    def note(self, message: str) -> None:
        if callable(self.progress):
            self.progress(message)


@dataclass
class _Run:
    """State threaded through one matching pass.

    Holds what every step needs (the index, the app's facts, the entry-point
    resolver, the options and the deadline), the lazily merged features that
    class- and apk-scope rules evaluate against, and the counters the report
    footer reads back.
    """

    index: AppIndex
    facts: AppFacts
    resolver: entrypoints.EntryPointResolver
    opts: ScanOptions
    deadline: float | None = None
    library_hidden: int = 0
    _class_features: dict[str, MethodFeatures] = field(default_factory=dict, init=False)
    _app_features: MethodFeatures | None = field(default=None, init=False)

    @property
    def expired(self) -> bool:
        return self.deadline is not None and time.monotonic() > self.deadline

    def class_features(self, class_name: str) -> MethodFeatures:
        cached = self._class_features.get(class_name)
        if cached is None:
            cached = self.index.class_features(class_name)
            self._class_features[class_name] = cached
        return cached

    def app_features(self) -> MethodFeatures:
        if self._app_features is None:
            self._app_features = self.index.app_features()
        return self._app_features


@dataclass
class Subject:
    """One app, ready to be matched — however it was obtained.

    ``scan`` builds this from an APK; the fixture runner builds it from a YAML
    description, so both take exactly the same matching path.
    """

    index: AppIndex
    manifest: Manifest
    facts: AppFacts
    info: AppInfo
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def from_app(cls, app: ingest.LoadedApp, index: AppIndex) -> Subject:
        return cls(
            index=index,
            manifest=app.manifest,
            facts=AppFacts.from_manifest(
                app.manifest, files=app.files, native_libs=app.native_libs
            ),
            info=app.app_info(method_count=index.method_count),
            warnings=list(app.warnings),
        )


def scan(target: str | Path, options: ScanOptions | None = None) -> ScanResult:
    """Analyze one app and return its capabilities."""
    opts = options or ScanOptions()
    started = time.monotonic()
    rules = rules_for(opts)
    subject = load_subject(target, rules, opts, started=started)
    return analyze(subject, rules, opts, started=started)


def rules_for(opts: ScanOptions) -> list[Rule]:
    return opts.rules if opts.rules is not None else load_rules(opts.rule_paths)


def load_subject(
    target: str | Path,
    rules: list[Rule],
    opts: ScanOptions | None = None,
    *,
    started: float | None = None,
) -> Subject:
    """Load and index an app, ready for ``analyze`` or ``diagnose``.

    Kept separate from ``scan`` so a caller that wants both a result and an
    explanation pays for the bytecode walk once.
    """
    opts = opts or ScanOptions()
    started = started if started is not None else time.monotonic()
    deadline = started + opts.timeout if opts.timeout else None

    opts.note("loading")
    app = ingest.load(target)

    opts.note("indexing bytecode")
    index = build_index(
        app.analysis,
        vocabulary_for(rules),
        call_graph=opts.reachability,
        deadline=deadline,
    )
    return Subject.from_app(app, index)


def analyze(
    subject: Subject,
    rules: list[Rule],
    opts: ScanOptions | None = None,
    *,
    started: float | None = None,
) -> ScanResult:
    """Match rules against a prepared subject and score the result."""
    opts = opts or ScanOptions()
    started = started if started is not None else time.monotonic()
    deadline = started + opts.timeout if opts.timeout else None

    index = subject.index
    run = _Run(
        index=index,
        facts=subject.facts,
        resolver=entrypoints.discover(subject.manifest, index),
        opts=opts,
        deadline=deadline,
    )

    opts.note(f"matching {len(rules)} rules")
    capabilities: list[Capability] = []
    for rule in rules:
        if rule.severity.rank < opts.min_severity.rank:
            continue
        found = _apply(rule, run)
        if found is not None:
            capabilities.append(found)

    result = ScanResult(
        app=subject.info,
        capabilities=capabilities,
        entry_points=run.resolver.declared,
        rules_evaluated=len(rules),
        scanned_at=datetime.now(UTC).isoformat(timespec="seconds"),
        duration_sec=time.monotonic() - started,
        warnings=list(subject.warnings),
        tadori_version=__version__,
        library_matches_hidden=run.library_hidden,
    )
    if run.library_hidden:
        result.warnings.append(
            f"{run.library_hidden} match(es) inside bundled libraries were hidden "
            "(--include-libraries to show them)"
        )
    if index.truncated:
        result.warnings.append(
            "bytecode walk hit the timeout; results are partial (raise --timeout)"
        )
    if not opts.reachability:
        result.warnings.append("reachability analysis disabled (--no-reachability)")

    score.apply(result)
    result.capabilities.sort(
        key=lambda c: (-c.severity.rank, -c.score_contribution, c.rule_id)
    )
    return result


# ---------------------------------------------------------------------------
# diagnostics
# ---------------------------------------------------------------------------


@dataclass
class Diagnosis:
    """Why a rule did not fire: its condition at the site that came closest."""

    rule_id: str
    location: str = ""
    trace: Trace | None = None
    sites: int = 0
    matched_sites: list[str] = field(default_factory=list)

    @property
    def missing(self) -> list[str]:
        return self.trace.missing if self.trace else []


def diagnose(
    subject: Subject, rule: Rule, opts: ScanOptions | None = None
) -> Diagnosis:
    """Find the candidate site that satisfies the most of ``rule``.

    "No match" is not an answer anyone can act on. This reports the site that
    came closest and which leaves of the condition held there — and, when the
    condition did match but nothing could reach it, says that instead.
    """
    opts = opts or ScanOptions()
    run = _Run(
        index=subject.index,
        facts=subject.facts,
        resolver=entrypoints.discover(subject.manifest, subject.index),
        opts=opts,
    )

    best: Trace | None = None
    best_location = ""
    matched: list[str] = []
    sites = 0
    for location, features in _candidates(rule, run):
        sites += 1
        trace = rule.features.trace(
            EvalContext(features=features, facts=run.facts, location=location)
        )
        if trace.satisfied:
            matched.append(location)
        if best is None or _closer(trace, best):
            best, best_location = trace, location

    return Diagnosis(
        rule_id=rule.id,
        location=best_location,
        trace=best,
        sites=sites,
        matched_sites=matched,
    )


def _closer(candidate: Trace, incumbent: Trace) -> bool:
    """Prefer a satisfied condition, then the site missing the least."""
    return (candidate.satisfied, candidate.satisfied_leaves) > (
        incumbent.satisfied,
        incumbent.satisfied_leaves,
    )


# ---------------------------------------------------------------------------
# matching
# ---------------------------------------------------------------------------


def _apply(rule: Rule, run: _Run) -> Capability | None:
    matches = _match_sites(rule, run)
    if not run.opts.include_libraries:
        app_matches = [m for m in matches if m.provenance == libraries.APP]
        run.library_hidden += len(matches) - len(app_matches)
        matches = app_matches
    if rule.scope == "method" and run.opts.reachability:
        matches = _annotate_reachability(rule, matches, run)
        if not run.opts.keep_unreachable:
            matches = [m for m in matches if m.reachable]
    if not matches:
        return None

    return Capability(
        rule_id=rule.id,
        name=rule.name,
        severity=rule.severity,
        scope=rule.scope,
        description=rule.description,
        attack=rule.attack,
        mbc=rule.mbc,
        references=rule.references,
        matches=matches,
    )


def _match_sites(rule: Rule, run: _Run) -> list[Match]:
    matches: list[Match] = []
    for location, features in _candidates(rule, run):
        if run.expired:
            break
        ok, evidence = rule.features.evaluate(
            EvalContext(features=features, facts=run.facts, location=location)
        )
        if ok:
            matches.append(
                Match(
                    rule_id=rule.id,
                    location=location,
                    evidence=evidence,
                    provenance=libraries.provenance(location),
                )
            )
            if len(matches) >= run.opts.max_matches_per_rule:
                break
    return matches


def _candidates(rule: Rule, run: _Run) -> list[tuple[str, MethodFeatures]]:
    """Sites a rule is evaluated against, given its scope.

    Normally only methods that recorded at least one vocabulary hit are
    considered — a method with no relevant feature cannot satisfy a rule that
    needs one. Rules that match a *name* (``method:``/``class:``) need the full
    set instead.
    """
    index = run.index
    if rule.scope == "method":
        if rule.needs_every_site:
            return [
                (ref, index.features_of(ref)) for ref in sorted(index.internal_refs)
            ]
        return list(index.features.items())
    if rule.scope == "class":
        classes = (
            sorted(index.internal_classes)
            if rule.needs_every_site
            else sorted({ref_class(location) for location in index.features})
        )
        return [(cls, run.class_features(cls)) for cls in classes]
    return [("apk", run.app_features())]


def _annotate_reachability(rule: Rule, matches: list[Match], run: _Run) -> list[Match]:
    max_hops = rule.reach.max_hops if rule.reach else run.opts.max_hops
    for match in matches:
        match.paths = graph.find_paths(
            run.index,
            run.resolver,
            match.location,
            max_hops=max_hops,
            deadline=run.deadline,
        )
        if rule.reach is None:
            match.reachable = bool(match.paths)
            continue
        accepted = [p for p in match.paths if rule.reach.accepts(p.entry.kind, p.hops)]
        match.reachable = bool(accepted)
        if accepted:
            match.paths = accepted
    return matches
