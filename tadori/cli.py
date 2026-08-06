"""Command line interface."""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from tadori import __version__
from tadori.core import attack, batch, diff, engine, fixtures, graph, report
from tadori.core.models import ScanResult, Severity
from tadori.core.rules import Rule, RuleError, Trace, lint, load_rules

console = Console()
err = Console(stderr=True)

SEVERITIES = tuple(s.value for s in Severity)

rule_option = click.option(
    "--rules",
    "rule_paths",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Rule file or directory (repeatable). Defaults to the bundled pack.",
)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="tadori")
def cli() -> None:
    """tadori — entry-point-aware capability detection for Android APKs.

    Static triage: what can this app do, and what can reach that behaviour?
    """


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@rule_option
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(report.FORMATS),
    default="text",
    show_default=True,
)
@click.option(
    "-o", "--output", type=click.Path(path_type=Path), help="Write to a file."
)
@click.option(
    "--min-severity",
    type=click.Choice([s.value for s in Severity]),
    default="info",
    show_default=True,
)
@click.option(
    "--no-reachability", is_flag=True, help="Skip call-graph analysis (faster)."
)
@click.option(
    "--max-hops",
    type=int,
    default=graph.DEFAULT_MAX_HOPS,
    show_default=True,
    help="Call-graph depth searched when looking for an entry point.",
)
@click.option(
    "--keep-unreachable",
    is_flag=True,
    help="Report matches with no entry-point path instead of dropping them.",
)
@click.option(
    "--include-libraries",
    is_flag=True,
    help="Also report matches inside bundled third-party libraries.",
)
@click.option(
    "--timeout", type=float, default=engine.DEFAULT_TIMEOUT, show_default=True
)
@click.option("-v", "--verbose", is_flag=True, help="Every site, full call chains.")
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity]),
    help="Exit 1 if a capability of this severity or higher is found (for CI).",
)
def scan(
    target: Path,
    rule_paths: tuple[Path, ...],
    fmt: str,
    output: Path | None,
    min_severity: str,
    no_reachability: bool,
    max_hops: int,
    keep_unreachable: bool,
    include_libraries: bool,
    timeout: float,
    verbose: bool,
    fail_on: str | None,
) -> None:
    """Scan an APK, a bare DEX, or a directory of DEX files."""
    options = engine.ScanOptions(
        rule_paths=list(rule_paths) or None,
        reachability=not no_reachability,
        max_hops=max_hops,
        keep_unreachable=keep_unreachable,
        include_libraries=include_libraries,
        min_severity=Severity(min_severity),
        timeout=timeout or None,
        progress=None if fmt != "text" or output else _progress,
    )
    result = _run(lambda: engine.scan(target, options))

    if fmt == "text" and not output:
        report.print_result(result, console, verbose=verbose)
    else:
        rendered = report.render(result, fmt, verbose=verbose)
        if output:
            output.write_text(rendered)
            console.print(f"[green]wrote[/green] {output}")
        else:
            click.echo(rendered)

    if fail_on:
        threshold = Severity(fail_on)
        if any(c.severity.rank >= threshold.rank for c in result.capabilities):
            sys.exit(1)


# ---------------------------------------------------------------------------
# triage
# ---------------------------------------------------------------------------


@cli.command()
@click.argument(
    "targets", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path)
)
@rule_option
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(("table", "json", "csv")),
    default="table",
    show_default=True,
)
@click.option(
    "-o", "--output", type=click.Path(path_type=Path), help="Write to a file."
)
@click.option("--limit", type=int, help="Scan at most N apps.")
@click.option(
    "--min-severity",
    type=click.Choice([s.value for s in Severity]),
    default="info",
    show_default=True,
)
@click.option(
    "--timeout", type=float, default=engine.DEFAULT_TIMEOUT, show_default=True
)
@click.option(
    "--no-reachability", is_flag=True, help="Skip call-graph analysis (faster)."
)
@click.option(
    "--fail-on",
    type=click.Choice([s.value for s in Severity]),
    help="Exit 1 if any app has a capability of this severity or higher.",
)
def triage(
    targets: tuple[Path, ...],
    rule_paths: tuple[Path, ...],
    fmt: str,
    output: Path | None,
    limit: int | None,
    min_severity: str,
    timeout: float,
    no_reachability: bool,
    fail_on: str | None,
) -> None:
    """Scan many apps and rank them, worst first.

    TARGETS are APKs or directories to walk. The rule pack is loaded once and
    shared across every app.
    """
    apps = _run(lambda: batch.collect_apps(list(targets), limit=limit))
    if not apps:
        err.print("[red]no apps found[/red] (looked for .apk/.apks/.xapk)")
        sys.exit(2)

    rules = _run(lambda: load_rules(list(rule_paths) or None))
    options = engine.ScanOptions(
        rules=rules,
        reachability=not no_reachability,
        min_severity=Severity(min_severity),
        timeout=timeout or None,
    )
    total = len(apps)
    found = batch.run(
        apps,
        options,
        on_start=lambda n, path: err.print(f"[dim][{n}/{total}] {path.name}[/dim]"),
    )

    rendered = _render_batch(found, fmt)
    if fmt == "table" and not output:
        _print_batch_table(found)
    elif output:
        output.write_text(rendered)
        console.print(f"[green]wrote[/green] {output}")
    else:
        click.echo(rendered)

    for outcome in found.failures:
        err.print(f"[yellow]skipped[/yellow] {outcome.path.name}: {outcome.error}")

    if fail_on:
        threshold = Severity(fail_on)
        hit = any(
            c.severity.rank >= threshold.rank
            for outcome in found.scanned
            for c in outcome.result.capabilities
        )
        if hit:
            sys.exit(1)


def _render_batch(found: batch.Batch, fmt: str) -> str:
    if fmt == "json":
        return json.dumps(
            {
                "apps": len(found.scanned),
                "failures": [
                    {"path": str(o.path), "error": o.error} for o in found.failures
                ],
                "seconds_per_app": round(found.seconds_per_app(), 2),
                "results": [o.to_dict() for o in found.ranked()],
            },
            indent=2,
            ensure_ascii=False,
        )
    if fmt == "csv":
        columns = ["path", "package", "version_name", "score", "verdict", *SEVERITIES]
        rows = [",".join(columns)]
        for outcome in found.ranked():
            data = outcome.to_dict()
            rows.append(",".join(_csv_cell(data.get(c, "")) for c in columns))
        return "\n".join(rows) + "\n"
    return _batch_lines(found)


def _csv_cell(value: object) -> str:
    text = str(value)
    return f'"{text}"' if "," in text or '"' in text else text


def _batch_lines(found: batch.Batch) -> str:
    lines = []
    for outcome in found.ranked():
        app = outcome.result.app
        lines.append(
            f"{outcome.result.score:6.1f}  {outcome.result.verdict:<28}  "
            f"{app.package or outcome.path.name} {app.version_name}"
        )
    return "\n".join(lines) + "\n" if lines else ""


def _print_batch_table(found: batch.Batch) -> None:
    table = Table(title=f"{len(found.scanned)} app(s) scanned, worst first")
    table.add_column("score", justify="right")
    table.add_column("verdict")
    table.add_column("package")
    table.add_column("version", style="dim")
    for severity in SEVERITIES:
        table.add_column(severity[0].upper(), justify="right", style="dim")
    table.add_column("top capabilities", style="dim")

    for outcome in found.ranked():
        result = outcome.result
        counts = result.summary
        top = ", ".join(c.rule_id for c in result.capabilities[:3])
        style, _ = report.score_band(result.score)
        table.add_row(
            f"[{style}]{result.score:g}[/{style}]",
            f"[{style}]{result.verdict}[/{style}]",
            result.app.package or outcome.path.name,
            result.app.version_name,
            *(str(counts.get(s, 0) or "") for s in SEVERITIES),
            top,
        )
    console.print(table)
    console.print(
        f"[dim]{found.seconds_per_app():.1f}s per app · "
        f"{len(found.failures)} skipped[/dim]"
    )


# ---------------------------------------------------------------------------
# explain
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("rule_id")
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@rule_option
@click.option("--max-hops", type=int, default=graph.DEFAULT_MAX_HOPS, show_default=True)
def explain(
    rule_id: str, target: Path, rule_paths: tuple[Path, ...], max_hops: int
) -> None:
    """Show why one rule fired (or did not) on an app, with full call chains."""
    rule = _require_rule(rule_id, rule_paths)

    console.print(
        f"[bold]{rule.id}[/bold]  {rule.name}  [dim]({rule.severity.value}, scope {rule.scope})[/dim]"
    )
    if rule.description:
        console.print(f"  {rule.description}")
    for technique in rule.attack:
        console.print(f"  [dim]ATT&CK {technique} — {attack.name_of(technique)}[/dim]")
    console.print(f"\n[bold]condition[/bold]\n  {rule.features.describe()}")
    if rule.reach:
        kinds = ", ".join(k.value for k in rule.reach.entrypoints) or "any"
        console.print(
            f"  [dim]reachable from {kinds} within {rule.reach.max_hops} hops[/dim]"
        )

    options = engine.ScanOptions(
        rules=[rule],
        keep_unreachable=True,
        include_libraries=True,
        max_hops=max_hops,
        progress=_progress,
    )
    subject = _run(lambda: engine.load_subject(target, [rule], options))
    result = _run(lambda: engine.analyze(subject, [rule], options))

    console.print()
    if result.capabilities:
        report.print_result(result, console, verbose=True)
        return

    console.print("[yellow]no match[/yellow] in this app")
    _print_diagnosis(engine.diagnose(subject, rule, options))


def _print_diagnosis(diagnosis: engine.Diagnosis) -> None:
    """Show which parts of the condition held at the closest candidate site."""
    if diagnosis.trace is None:
        console.print("  [dim]nothing to evaluate: 0 candidate sites[/dim]")
        return

    console.print(
        f"\n[bold]closest site[/bold] {report.short_ref(diagnosis.location)}  "
        f"[dim](best of {diagnosis.sites} candidate site(s))[/dim]"
    )
    _print_trace(diagnosis.trace, depth=1)
    if diagnosis.missing:
        console.print(
            f"\n  [yellow]missing[/yellow] {'; '.join(diagnosis.missing[:4])}"
        )


def _print_trace(trace: Trace, depth: int) -> None:
    mark = "[green]✓[/green]" if trace.satisfied else "[red]✗[/red]"
    console.print(f"{'  ' * depth}{mark} {trace.description}")
    for child in trace.children:
        _print_trace(child, depth + 1)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


@cli.group("rules")
def rules_group() -> None:
    """Inspect and validate the rule pack."""


@rules_group.command("list")
@rule_option
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
def rules_list(rule_paths: tuple[Path, ...], as_json: bool) -> None:
    """List available rules."""
    rules = _run(lambda: load_rules(list(rule_paths) or None))
    if as_json:
        click.echo(
            json.dumps(
                [
                    {
                        "id": r.id,
                        "name": r.name,
                        "severity": r.severity.value,
                        "scope": r.scope,
                        "attack": r.attack,
                    }
                    for r in rules
                ],
                indent=2,
            )
        )
        return

    table = Table(title=f"{len(rules)} rules")
    table.add_column("id", style="bold")
    table.add_column("severity")
    table.add_column("scope", style="dim")
    table.add_column("name")
    table.add_column("ATT&CK", style="dim")
    for rule in sorted(rules, key=lambda r: r.id):
        table.add_row(
            rule.id,
            f"[{report.SEVERITY_STYLE[rule.severity]}]{rule.severity.value}[/]",
            rule.scope,
            rule.name,
            ", ".join(rule.attack),
        )
    console.print(table)


@rules_group.command("show")
@click.argument("rule_id")
@rule_option
def rules_show(rule_id: str, rule_paths: tuple[Path, ...]) -> None:
    """Print one rule's metadata, condition and source file."""
    rule = _require_rule(rule_id, rule_paths)
    console.print(f"[bold]{rule.id}[/bold] {rule.name}")
    console.print(f"  severity  {rule.severity.value}")
    console.print(f"  scope     {rule.scope}")
    console.print(
        f"  attack    {', '.join(f'{t} ({attack.name_of(t)})' for t in rule.attack)}"
    )
    if rule.mbc:
        console.print(f"  mbc       {', '.join(rule.mbc)}")
    console.print(f"  source    {rule.source}")
    if rule.description:
        console.print(f"\n  {rule.description}")
    console.print(f"\n[bold]condition[/bold]\n  {rule.features.describe()}")
    for reference in rule.references:
        console.print(f"  [dim]{reference}[/dim]")


@rules_group.command("lint")
@rule_option
def rules_lint(rule_paths: tuple[Path, ...]) -> None:
    """Validate rule metadata: ids, ATT&CK mappings, references, structure."""
    rules = _run(lambda: load_rules(list(rule_paths) or None))
    problems = {rule.id or str(rule.source): lint(rule) for rule in rules}
    broken = {rule_id: found for rule_id, found in problems.items() if found}

    for rule_id, found in sorted(broken.items()):
        console.print(f"[red]{rule_id}[/red]")
        for problem in found:
            console.print(f"  - {problem}")
    if broken:
        err.print(f"\n[red]{len(broken)} of {len(rules)} rules have problems[/red]")
        sys.exit(1)
    console.print(f"[green]ok[/green] {len(rules)} rules, no problems")


@rules_group.command("test")
@rule_option
@click.option(
    "--fixtures",
    "fixture_paths",
    multiple=True,
    type=click.Path(exists=True, path_type=Path),
    help="Fixture file or directory (repeatable). Defaults to the bundled set.",
)
@click.option(
    "--require-coverage",
    is_flag=True,
    help="Fail when a rule has no positive fixture.",
)
def rules_test(
    rule_paths: tuple[Path, ...],
    fixture_paths: tuple[Path, ...],
    require_coverage: bool,
) -> None:
    """Run the rule fixtures: synthetic apps that pin each rule's behaviour."""
    rules = _run(lambda: load_rules(list(rule_paths) or None))
    cases = _run(lambda: fixtures.load_fixtures(list(fixture_paths) or None))
    _run(lambda: fixtures.require_known_rules(cases, rules))

    outcomes, uncovered = fixtures.run_all(cases, rules)
    failures = [o for o in outcomes if not o.passed]

    for outcome in failures:
        console.print(
            f"[red]FAIL[/red] {outcome.fixture.rule_id}  {outcome.fixture.name}\n"
            f"       {outcome.detail}  [dim]({outcome.fixture.source.name})[/dim]"
        )

    positives = sum(1 for c in cases if c.should_match)
    console.print(
        f"\n{len(cases)} fixtures ({positives} positive, {len(cases) - positives} negative)"
        f" · {len(rules)} rules · [{'red' if failures else 'green'}]"
        f"{len(outcomes) - len(failures)}/{len(outcomes)} passed[/]"
    )
    if uncovered:
        style = "red" if require_coverage else "yellow"
        console.print(
            f"[{style}]{len(uncovered)} rule(s) without a positive fixture:[/{style}] "
            + ", ".join(sorted(uncovered))
        )

    if failures or (require_coverage and uncovered):
        sys.exit(1)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


@cli.command("diff")
@click.argument("old", type=click.Path(exists=True, path_type=Path))
@click.argument("new", type=click.Path(exists=True, path_type=Path))
@rule_option
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.option(
    "--fail-on-regression",
    is_flag=True,
    help="Exit 1 when the newer build gained capability or exposure (for CI).",
)
def diff_command(
    old: Path,
    new: Path,
    rule_paths: tuple[Path, ...],
    as_json: bool,
    fail_on_regression: bool,
) -> None:
    """Compare two builds of the same app and report what the update gained.

    Either side may be a scan result stored earlier with
    `tadori scan app.apk -f json -o baseline.json` instead of an app — which is
    what a release gate usually has: the reviewed build's JSON, not its APK.
    """
    options = engine.ScanOptions(progress=_progress)
    if not (diff.is_baseline(old) and diff.is_baseline(new)):
        options.rules = _run(lambda: load_rules(list(rule_paths) or None))

    old_result = _side(old, options)
    new_result = _side(new, options)
    delta = diff.compare(old_result, new_result)

    if as_json:
        click.echo(json.dumps(delta.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_delta(delta)

    if fail_on_regression and delta.is_regression():
        sys.exit(1)


def _side(target: Path, options: engine.ScanOptions) -> ScanResult:
    """One side of a diff: a stored result, or an app to scan now."""
    if diff.is_baseline(target):
        return _run(lambda: diff.load_baseline(target))
    return _run(lambda: engine.scan(target, options))


def _print_delta(delta: diff.Delta) -> None:
    old, new = delta.old, delta.new
    console.print(
        f"[bold]{old.app.package or old.app.name}[/bold]  "
        f"{old.app.version_name or '?'} ({old.app.version_code or '?'})  →  "
        f"{new.app.version_name or '?'} ({new.app.version_code or '?'})"
    )
    style = "red" if delta.score_delta > 0 else "green"
    console.print(
        f"  score {old.score:g} → {new.score:g}  "
        f"([{style}]{delta.score_delta:+g}[/{style}])"
    )
    verdict_style = "bold red" if delta.is_regression() else "green"
    console.print(f"  [{verdict_style}]{delta.headline()}[/{verdict_style}]")

    if delta.certificate_changed:
        console.print("\n[bold red]signing certificate changed[/bold red]")
        for side in (old, new):
            subject = (
                f"  {side.app.certificate_subject}"
                if side.app.certificate_subject
                else ""
            )
            console.print(f"  [dim]{side.app.certificate_sha256[:32]}…{subject}[/dim]")

    for title, caps, colour in (
        ("gained capabilities", delta.added, "red"),
        ("lost capabilities", delta.removed, "green"),
    ):
        if not caps:
            continue
        console.print(f"\n[bold]{title}[/bold]")
        for capability in caps:
            console.print(
                f"  [{colour}]{'+' if colour == 'red' else '-'}[/{colour}] "
                f"{capability.rule_id}  {capability.name} "
                f"[dim]({capability.severity.value})[/dim]"
            )

    if delta.escalated:
        console.print("\n[bold]exposure escalated[/bold]")
        for before, after in delta.escalated:
            console.print(
                f"  [red]![/red] {after.rule_id}  {after.name}  "
                f"[dim]{before.exposure} → {after.exposure}[/dim]"
            )

    for title, values, colour in (
        ("new permissions", delta.added_permissions, "yellow"),
        ("dropped permissions", delta.removed_permissions, "dim"),
        ("new native libraries", delta.added_native_libs, "yellow"),
        ("new entry-point kinds", delta.added_entry_kinds, "yellow"),
    ):
        if not values:
            continue
        console.print(f"\n[bold]{title}[/bold]")
        for value in values:
            marker = "!" if value in diff.WATCHED_PERMISSIONS else "·"
            console.print(f"  [{colour}]{marker}[/{colour}] {value}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _progress(message: str) -> None:
    err.print(f"[dim]{message}…[/dim]")


def _require_rule(rule_id: str, rule_paths: tuple[Path, ...]) -> Rule:
    """Load the pack and pick one rule out of it, or exit 2."""
    rules = _run(lambda: load_rules(list(rule_paths) or None))
    for rule in rules:
        if rule.id.lower() == rule_id.lower():
            return rule
    err.print(f"[red]no such rule:[/red] {rule_id}")
    sys.exit(2)


def _run[T](action: Callable[[], T]) -> T:
    """Tiny error boundary shared by all commands."""
    try:
        return action()
    except RuleError as exc:
        err.print(f"[red]rule error:[/red] {exc}")
        sys.exit(2)
    except (FileNotFoundError, ValueError) as exc:
        err.print(f"[red]error:[/red] {exc}")
        sys.exit(2)


if __name__ == "__main__":  # pragma: no cover
    cli()
