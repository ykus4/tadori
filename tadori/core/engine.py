"""Scan orchestration: load -> index -> match -> reachability -> score."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from tadori import __version__
from tadori.core import entrypoints, graph, ingest, libraries, score
from tadori.core.features import AppIndex, MethodFeatures, build_index
from tadori.core.models import Capability, Match, ScanResult, Severity
from tadori.core.rules import AppFacts, EvalContext, Rule, load_rules, vocabulary_for

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
class _Stats:
    """Counters collected while matching."""

    library_hidden: int = 0


@dataclass
class _ScopeCaches:
    """Lazily merged features for class- and apk-scope evaluation."""

    index: AppIndex
    classes: dict[str, MethodFeatures] = field(default_factory=dict)
    app: MethodFeatures | None = None

    def of_class(self, class_name: str) -> MethodFeatures:
        cached = self.classes.get(class_name)
        if cached is None:
            cached = self.index.class_features(class_name)
            self.classes[class_name] = cached
        return cached

    def of_app(self) -> MethodFeatures:
        if self.app is None:
            self.app = self.index.app_features()
        return self.app


def scan(target: str | Path, options: ScanOptions | None = None) -> ScanResult:
    """Analyze one app and return its capabilities."""
    opts = options or ScanOptions()
    started = time.monotonic()
    deadline = started + opts.timeout if opts.timeout else None

    rules = opts.rules if opts.rules is not None else load_rules(opts.rule_paths)
    vocab = vocabulary_for(rules)

    opts.note("loading")
    app = ingest.load(target)

    opts.note("indexing bytecode")
    index = build_index(
        app.analysis, vocab, call_graph=opts.reachability, deadline=deadline
    )

    resolver = entrypoints.discover(app.manifest, index)
    facts = _facts(app)
    caches = _ScopeCaches(index=index)

    opts.note(f"matching {len(rules)} rules")
    stats = _Stats()
    capabilities: list[Capability] = []
    for rule in rules:
        if rule.severity.rank < opts.min_severity.rank:
            continue
        found = _apply(rule, index, caches, facts, resolver, opts, deadline, stats)
        if found is not None:
            capabilities.append(found)

    result = ScanResult(
        app=app.app_info(method_count=index.method_count),
        capabilities=capabilities,
        entry_points=resolver.declared,
        rules_evaluated=len(rules),
        scanned_at=datetime.now(UTC).isoformat(timespec="seconds"),
        duration_sec=time.monotonic() - started,
        warnings=list(app.warnings),
        tadori_version=__version__,
        library_matches_hidden=stats.library_hidden,
    )
    if stats.library_hidden:
        result.warnings.append(
            f"{stats.library_hidden} match(es) inside bundled libraries were hidden "
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
# matching
# ---------------------------------------------------------------------------


def _apply(
    rule: Rule,
    index: AppIndex,
    caches: _ScopeCaches,
    facts: AppFacts,
    resolver: entrypoints.EntryPointResolver,
    opts: ScanOptions,
    deadline: float | None,
    stats: _Stats,
) -> Capability | None:
    matches = _match_sites(rule, index, caches, facts, opts, deadline)
    if not opts.include_libraries:
        app_matches = [m for m in matches if m.provenance == libraries.APP]
        stats.library_hidden += len(matches) - len(app_matches)
        matches = app_matches
    if rule.scope == "method" and opts.reachability:
        matches = _annotate_reachability(rule, matches, index, resolver, opts, deadline)
        if not opts.keep_unreachable:
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


def _match_sites(
    rule: Rule,
    index: AppIndex,
    caches: _ScopeCaches,
    facts: AppFacts,
    opts: ScanOptions,
    deadline: float | None,
) -> list[Match]:
    matches: list[Match] = []
    for location, features in _candidates(rule, index, caches):
        if deadline is not None and time.monotonic() > deadline:
            break
        ok, evidence = rule.features.evaluate(
            EvalContext(features=features, facts=facts, location=location)
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
            if len(matches) >= opts.max_matches_per_rule:
                break
    return matches


def _candidates(
    rule: Rule, index: AppIndex, caches: _ScopeCaches
) -> list[tuple[str, MethodFeatures]]:
    """Sites a rule is evaluated against, given its scope.

    Normally only methods that recorded at least one vocabulary hit are
    considered — a method with no relevant feature cannot satisfy a rule that
    needs one. Rules that match a *name* (``method:``/``class:``) need the full
    set instead.
    """
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
            else sorted({location.split("->", 1)[0] for location in index.features})
        )
        return [(cls, caches.of_class(cls)) for cls in classes]
    return [("apk", caches.of_app())]


def _annotate_reachability(
    rule: Rule,
    matches: list[Match],
    index: AppIndex,
    resolver: entrypoints.EntryPointResolver,
    opts: ScanOptions,
    deadline: float | None,
) -> list[Match]:
    max_hops = rule.reach.max_hops if rule.reach else opts.max_hops
    for match in matches:
        match.paths = graph.find_paths(
            index,
            resolver,
            match.location,
            max_hops=max_hops,
            deadline=deadline,
        )
        if rule.reach is None:
            match.reachable = bool(match.paths)
            continue
        accepted = [p for p in match.paths if rule.reach.accepts(p.entry.kind, p.hops)]
        match.reachable = bool(accepted)
        if accepted:
            match.paths = accepted
    return matches


def _facts(app: ingest.LoadedApp) -> AppFacts:
    manifest = app.manifest
    return AppFacts(
        package=manifest.package,
        permissions=set(manifest.permissions),
        intent_actions=set(manifest.intent_actions),
        components=[(c.type, c.special_kind) for c in manifest.components],
        files=app.files,
        native_libs=app.native_libs,
        metadata=dict(manifest.metadata),
    )
