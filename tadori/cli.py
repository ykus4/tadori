"""Command line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from tadori import __version__
from tadori.core import attack, diff, engine, report
from tadori.core.models import Severity
from tadori.core.rules import RuleError, lint, load_rules

console = Console()
err = Console(stderr=True)

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
    default=engine.graph.DEFAULT_MAX_HOPS,
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
# explain
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("rule_id")
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@rule_option
@click.option(
    "--max-hops", type=int, default=engine.graph.DEFAULT_MAX_HOPS, show_default=True
)
def explain(
    rule_id: str, target: Path, rule_paths: tuple[Path, ...], max_hops: int
) -> None:
    """Show why one rule fired (or did not) on an app, with full call chains."""
    rules = _run(lambda: load_rules(list(rule_paths) or None))
    wanted = [r for r in rules if r.id.lower() == rule_id.lower()]
    if not wanted:
        err.print(f"[red]no such rule:[/red] {rule_id}")
        sys.exit(2)
    rule = wanted[0]

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

    result = _run(
        lambda: engine.scan(
            target,
            engine.ScanOptions(
                rules=[rule],
                keep_unreachable=True,
                include_libraries=True,
                max_hops=max_hops,
                progress=_progress,
            ),
        )
    )
    console.print()
    if not result.capabilities:
        console.print("[yellow]no match[/yellow] in this app")
        return
    report.print_result(result, console, verbose=True)


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
    rules = _run(lambda: load_rules(list(rule_paths) or None))
    for rule in rules:
        if rule.id.lower() != rule_id.lower():
            continue
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
        return
    err.print(f"[red]no such rule:[/red] {rule_id}")
    sys.exit(2)


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
    """Compare two builds of the same app and report what the update gained."""
    rules = _run(lambda: load_rules(list(rule_paths) or None))
    options = engine.ScanOptions(rules=rules, progress=_progress)
    old_result = _run(lambda: engine.scan(old, options))
    new_result = _run(lambda: engine.scan(new, options))
    delta = diff.compare(old_result, new_result)

    if as_json:
        click.echo(json.dumps(delta.to_dict(), indent=2, ensure_ascii=False))
    else:
        _print_delta(delta)

    if fail_on_regression and delta.is_regression():
        sys.exit(1)


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
        console.print(f"  [dim]{old.app.certificate_sha256[:32]}…[/dim]")
        console.print(f"  [dim]{new.app.certificate_sha256[:32]}…[/dim]")

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
                f"[dim]{diff._exposure(before)} → {diff._exposure(after)}[/dim]"
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


def _run(action):  # noqa: ANN001 - tiny error boundary shared by all commands
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
