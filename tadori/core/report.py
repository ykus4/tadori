"""Output formats: terminal, JSON, SARIF 2.1.0, HTML, and call-chain graphs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from tadori import __version__
from tadori.core import attack
from tadori.core.models import Capability, Evidence, Match, ScanResult, Severity

FORMATS = ("text", "json", "sarif", "html", "dot", "mermaid")

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
#: SARIF's numeric severity, so GitHub sorts tadori findings sensibly.
SARIF_SECURITY_SEVERITY = {
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
#: Score bands, strongest first: threshold -> (terminal style, HTML class).
SCORE_BANDS = (
    (60.0, "bold red", "critical"),
    (30.0, "red", "high"),
    (12.0, "yellow", "medium"),
    (0.0, "green", "low"),
)


def render(result: ScanResult, fmt: str = "text", *, verbose: bool = False) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    if fmt == "sarif":
        return json.dumps(to_sarif(result), indent=2, ensure_ascii=False)
    if fmt == "html":
        return to_html(result)
    if fmt == "dot":
        return to_dot(result)
    if fmt == "mermaid":
        return to_mermaid(result)
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
    if app.debug_signed:
        facts.append("[red]debug key[/red]")
    if app.permissions:
        facts.append(f"{len(app.permissions)} permissions")
    if app.native_libs:
        facts.append(f"{len(app.native_libs)} native libs")
    if app.frameworks:
        facts.append(f"[yellow]{', '.join(app.frameworks)}[/yellow]")
    console.print(f"  [dim]{' · '.join(facts)}[/dim]")
    if app.certificate_subject:
        validity = (
            f" · valid to {app.certificate_not_after[:10]}"
            if app.certificate_not_after
            else ""
        )
        console.print(f"  [dim]signer {app.certificate_subject}{validity}[/dim]")

    summary = result.summary
    counts = " · ".join(f"{k} {v}" for k, v in summary.items() if v)
    score_style, _ = score_band(result.score)
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


def score_band(score: float) -> tuple[str, str]:
    """The (terminal style, HTML class) pair a score falls into."""
    for threshold, style, css_class in SCORE_BANDS:
        if score >= threshold:
            return style, css_class
    return SCORE_BANDS[-1][1:]


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
                "security-severity": SARIF_SECURITY_SEVERITY[c.severity],
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
                    "partialFingerprints": {
                        "tadoriMatch/v1": _fingerprint(capability.rule_id, match)
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


def _fingerprint(rule_id: str, match: Match) -> str:
    """Stable identity for one finding, so code scanning can track it.

    Deliberately built from the rule and the matched method only: the app
    version, the bytecode offsets and the call chain all change between builds,
    and a fingerprint that moves with them would open a fresh alert every
    release for the same finding.
    """
    digest = hashlib.sha256(f"{rule_id}\n{match.location}".encode())
    return digest.hexdigest()[:32]


def _help_text(capability: Capability) -> str:
    lines = [capability.description or capability.name]
    if capability.attack:
        lines.append(
            "ATT&CK: "
            + ", ".join(f"{t} ({attack.name_of(t)})" for t in capability.attack)
        )
    lines.extend(capability.references)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# call-chain graphs
# ---------------------------------------------------------------------------

#: Node fill per severity, for the graph exports.
GRAPH_COLOURS = {
    Severity.HIGH: "#d33682",
    Severity.MEDIUM: "#cb8b00",
    Severity.LOW: "#268bd2",
    Severity.INFO: "#93a1a1",
}
ENTRY_COLOUR = "#6c71c4"


@dataclass(frozen=True)
class GraphNode:
    """One method in the exported call-chain graph."""

    id: str
    label: str
    role: str  # entry | step | match
    colour: str = ""


def call_graph(result: ScanResult) -> tuple[list[GraphNode], list[tuple[str, str]]]:
    """Nodes and edges for the best call chain of every reported match.

    Only the best path per match is drawn: the point is a picture an analyst
    can read in a report, not the full reachability relation.
    """
    nodes: dict[str, GraphNode] = {}
    edges: list[tuple[str, str]] = []

    def node(ref: str, role: str, label: str, colour: str = "") -> str:
        existing = nodes.get(ref)
        if existing is not None:
            # A method that both starts a chain and is matched stays an entry.
            if existing.role == "step" and role != "step":
                nodes[ref] = GraphNode(existing.id, label, role, colour)
            return existing.id
        node_id = f"n{len(nodes)}"
        nodes[ref] = GraphNode(node_id, label, role, colour)
        return node_id

    for capability in result.capabilities:
        colour = GRAPH_COLOURS[capability.severity]
        for match in capability.matches:
            target_label = f"{capability.rule_id}\n{short_ref(match.location)}"
            target = node(match.location, "match", target_label, colour)
            path = match.best_path
            if path is None:
                continue
            node(
                path.entry.method,
                "entry",
                f"[{path.entry.kind.value}]\n{short_ref(path.entry.method)}",
                ENTRY_COLOUR,
            )
            steps = list(path.methods)
            for caller, callee in zip(steps, steps[1:], strict=False):
                source = node(caller, "step", short_ref(caller))
                sink = (
                    target
                    if callee == match.location
                    else node(callee, "step", short_ref(callee))
                )
                if (source, sink) not in edges:
                    edges.append((source, sink))

    return list(nodes.values()), edges


def to_dot(result: ScanResult) -> str:
    """Graphviz DOT of the call chains — ``tadori scan -f dot | dot -Tsvg``."""
    lines = [
        f"// tadori {__version__} — {result.app.package or result.app.name}",
        "digraph tadori {",
        "  rankdir=LR;",
        '  node [shape=box, style="rounded,filled", fontname="monospace", '
        'fontsize=10, fillcolor="#ffffff"];',
    ]
    nodes, edges = call_graph(result)
    for node in nodes:
        label = node.label.replace('"', '\\"').replace("\n", "\\n")
        colour = f', color="{node.colour}", penwidth=2' if node.colour else ""
        lines.append(f'  {node.id} [label="{label}"{colour}];')
    lines.extend(f"  {source} -> {sink};" for source, sink in edges)
    lines.append("}")
    return "\n".join(lines) + "\n"


def to_mermaid(result: ScanResult) -> str:
    """Mermaid flowchart of the call chains, for markdown reports."""
    lines = [f"%% tadori {__version__} — {result.app.package or result.app.name}"]
    lines.append("graph LR")
    nodes, edges = call_graph(result)
    for node in nodes:
        label = node.label.replace('"', "'").replace("\n", "<br/>")
        shape = f'{{{{"{label}"}}}}' if node.role == "entry" else f'["{label}"]'
        lines.append(f"  {node.id}{shape}")
    lines.extend(f"  {source} --> {sink}" for source, sink in edges)
    for node in nodes:
        if node.colour:
            lines.append(f"  style {node.id} stroke:{node.colour},stroke-width:2px")
    return "\n".join(lines) + "\n"


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
        score_class=score_band(result.score)[1],
    )
