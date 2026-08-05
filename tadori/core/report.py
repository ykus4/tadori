"""Output formats: terminal, JSON, SARIF 2.1.0 and HTML."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from tadori import __version__
from tadori.core import attack
from tadori.core.models import Capability, Evidence, Match, ScanResult, Severity

FORMATS = ("text", "json", "sarif", "html")

SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
SARIF_LEVEL = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(result: ScanResult, fmt: str = "text", *, verbose: bool = False) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    if fmt == "sarif":
        return json.dumps(to_sarif(result), indent=2, ensure_ascii=False)
    if fmt == "html":
        return to_html(result)
    if fmt == "text":
        return to_text(result, verbose=verbose)
    raise ValueError(f"unknown format {fmt!r} (expected one of {', '.join(FORMATS)})")


# ---------------------------------------------------------------------------
# display helpers
# ---------------------------------------------------------------------------

MAX_REF_LEN = 88


def short_ref(ref: str) -> str:
    """Shorten a reference for terminal display.

    Parameter lists become ``(…)`` and an over-long class name keeps its head
    and tail. Machine-readable output (JSON, SARIF) always carries full refs.
    """
    head, arrow, signature = ref.partition("->")
    if arrow and "(" in signature:
        name, _, rest = signature.partition("(")
        returns = rest.rpartition(")")[2]
        signature = f"{name}(…){returns}" if returns else f"{name}(…)"
    out = f"{head}{arrow}{signature}"
    if len(out) <= MAX_REF_LEN:
        return out
    keep = (MAX_REF_LEN - 1) // 2
    return f"{out[:keep]}…{out[-keep:]}"


# ---------------------------------------------------------------------------
# terminal
# ---------------------------------------------------------------------------


def to_text(
    result: ScanResult, *, verbose: bool = False, width: int | None = None
) -> str:
    console = Console(record=True, width=width, no_color=False, highlight=False)
    print_result(result, console, verbose=verbose)
    return console.export_text(styles=False)


def print_result(
    result: ScanResult, console: Console, *, verbose: bool = False
) -> None:
    """Write a scan result to a live console."""
    _print_header(result, console)
    if not result.capabilities:
        console.print("\n[green]no capabilities matched[/green]")
    for capability in result.capabilities:
        _print_capability(capability, console, verbose=verbose)
    _print_footer(result, console)


def _print_header(result: ScanResult, console: Console) -> None:
    app = result.app
    title = app.package or app.name
    version = f" {app.version_name}" if app.version_name else ""
    build = f" ({app.version_code})" if app.version_code else ""
    console.print(
        f"[bold]tadori {__version__}[/bold] — [bold cyan]{title}[/bold cyan]{version}{build}"
    )

    facts = [f"{app.method_count:,} methods", f"{app.dex_count} dex"]
    if app.signed:
        facts.append(f"signed {app.signed}")
    if app.permissions:
        facts.append(f"{len(app.permissions)} permissions")
    if app.native_libs:
        facts.append(f"{len(app.native_libs)} native libs")
    console.print(f"  [dim]{' · '.join(facts)}[/dim]")

    summary = result.summary
    counts = " · ".join(f"{k} {v}" for k, v in summary.items() if v)
    score_style = _score_style(result.score)
    console.print(
        f"  score [{score_style}]{result.score:g}[/{score_style}]/100 → "
        f"[{score_style}]{result.verdict}[/{score_style}]"
        + (f"   [dim]({counts})[/dim]" if counts else "")
    )


def _print_capability(
    capability: Capability, console: Console, *, verbose: bool
) -> None:
    style = SEVERITY_STYLE[capability.severity]
    techniques = ", ".join(
        f"{t} {attack.name_of(t)}" if verbose else t for t in capability.attack
    )
    console.print()
    console.print(
        f"[{style}]{capability.rule_id}[/{style}]  {capability.name}  "
        f"[{style}]\\[{capability.severity.value.upper()}][/{style}]"
        + (f"  [dim]{techniques}[/dim]" if techniques else "")
    )
    if verbose and capability.description:
        console.print(f"  [dim]{capability.description}[/dim]")

    shown = capability.matches if verbose else capability.matches[:3]
    for match in shown:
        _print_match(match, console, verbose=verbose)
    hidden = len(capability.matches) - len(shown)
    if hidden > 0:
        console.print(f"  [dim]… {hidden} more site(s); use --verbose[/dim]")
    console.print(
        f"  [dim]score +{capability.score_contribution:g}  ({capability.score_reason})[/dim]"
    )


def _print_match(match: Match, console: Console, *, verbose: bool) -> None:
    console.print(f"  [bold]↳[/bold] {short_ref(match.location)}")
    path = match.best_path
    if path is not None:
        console.print(
            f"      reachable from [magenta]<{path.entry.kind.value}>[/magenta] "
            f"{short_ref(path.entry.method)}  [dim]({_hops(path.hops)})[/dim]"
        )
        if verbose and path.hops:
            for depth, step in enumerate(path.methods):
                prefix = "└─ " if depth else ""
                console.print(f"        {'  ' * depth}{prefix}{short_ref(step)}")
    elif match.reachable is False:
        console.print(
            "      [dim]no entry-point path found (dead code, reflection, or packed)[/dim]"
        )

    for evidence in match.evidence:
        console.print(
            f"      [dim]{evidence.kind:<10} {short_ref(evidence.value)}{_at(evidence)}[/dim]"
        )


def _hops(count: int) -> str:
    return "direct" if count == 0 else f"{count} hop" + ("s" if count > 1 else "")


def _at(evidence: Evidence) -> str:
    return f" @ 0x{evidence.offset:x}" if evidence.offset is not None else ""


def _print_footer(result: ScanResult, console: Console) -> None:
    for warning in result.warnings:
        console.print(f"\n[yellow]warning[/yellow] {warning}")
    console.print(
        f"\n[dim]{result.rules_evaluated} rules · {result.duration_sec:.1f}s · "
        f"{len(result.entry_points)} declared entry points[/dim]"
    )


def _score_style(score: float) -> str:
    if score >= 60:
        return "bold red"
    if score >= 30:
        return "red"
    if score >= 12:
        return "yellow"
    return "green"


def entry_point_table(result: ScanResult, limit: int = 40) -> Table:
    table = Table(title="declared entry points", show_lines=False)
    table.add_column("kind", style="magenta")
    table.add_column("class")
    for entry in result.entry_points[:limit]:
        table.add_row(entry.kind.value, short_ref(entry.method))
    return table


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """SARIF 2.1.0, so GitHub code scanning can ingest a scan."""
    rules = [
        {
            "id": c.rule_id,
            "name": c.name,
            "shortDescription": {"text": c.name},
            "fullDescription": {"text": c.description or c.name},
            "help": {"text": _help_text(c)},
            "properties": {
                "tags": ["android", "capability", *c.attack],
                "security-severity": _security_severity(c.severity),
                "attack": c.attack,
                "mbc": c.mbc,
            },
        }
        for c in result.capabilities
    ]

    results = []
    for capability in result.capabilities:
        for match in capability.matches:
            path = match.best_path
            reach = (
                f" reachable from <{path.entry.kind.value}> {path.entry.method} "
                f"({_hops(path.hops)})"
                if path
                else " no entry-point path found"
            )
            results.append(
                {
                    "ruleId": capability.rule_id,
                    "level": SARIF_LEVEL[capability.severity],
                    "message": {
                        "text": f"{capability.name} in {match.location}.{reach}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": Path(result.app.path).name}
                            },
                            "logicalLocations": [
                                {"fullyQualifiedName": match.location, "kind": "member"}
                            ],
                        }
                    ],
                    "properties": {
                        "evidence": [e.to_dict() for e in match.evidence],
                        "paths": [p.to_dict() for p in match.paths],
                        "reachable": match.reachable,
                    },
                }
            )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tadori",
                        "version": __version__,
                        "informationUri": "https://github.com/ykus4/tadori",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "score": result.score,
                    "verdict": result.verdict,
                    "package": result.app.package,
                },
            }
        ],
    }


def _help_text(capability: Capability) -> str:
    lines = [capability.description or capability.name]
    if capability.attack:
        lines.append(
            "ATT&CK: "
            + ", ".join(f"{t} ({attack.name_of(t)})" for t in capability.attack)
        )
    lines.extend(capability.references)
    return "\n".join(lines)


def _security_severity(severity: Severity) -> str:
    return {"high": "8.0", "medium": "5.0", "low": "3.0", "info": "1.0"}[severity.value]


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def to_html(result: ScanResult) -> str:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    templates = Path(__file__).resolve().parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(templates)), autoescape=select_autoescape(["html"])
    )
    template = env.get_template("report.html.j2")
    return template.render(
        result=result,
        attack_name=attack.name_of,
        version=__version__,
        score_class=_score_class(result.score),
    )


def _score_class(score: float) -> str:
    if score >= 60:
        return "critical"
    if score >= 30:
        return "high"
    if score >= 12:
        return "medium"
    return "low"
