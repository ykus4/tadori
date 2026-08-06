#!/usr/bin/env python3
"""Measure per-rule hit rates over a corpus of apps you already trust.

    python scripts/fp_bench.py --corpus ~/apks --out docs/false-positives.md

Every rule that fires on a *benign* corpus is a candidate false positive — or a
capability the app genuinely has, which the rule description should already
explain. The point is to make that number visible and reviewable.

This script never downloads anything. Point ``--corpus`` at a directory of APKs
you obtained yourself; only the aggregate result is written out, never a sample.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tadori import __version__  # noqa: E402
from tadori.core import batch, engine  # noqa: E402
from tadori.core.rules import Rule, load_rules  # noqa: E402


@dataclass
class Tally:
    apps: int = 0
    failures: list[str] = field(default_factory=list)
    hits: Counter[str] = field(default_factory=Counter)
    scores: list[float] = field(default_factory=list)
    verdicts: Counter[str] = field(default_factory=Counter)
    seconds: float = 0.0

    def rate(self, rule_id: str) -> float:
        return self.hits[rule_id] / self.apps if self.apps else 0.0


def scan_corpus(paths: list[Path], rules: list[Rule], timeout: float) -> Tally:
    """Scan the corpus with the shared batch runner and tally what fired."""
    tally = Tally()
    options = engine.ScanOptions(rules=rules, timeout=timeout)
    total = len(paths)

    def announce(number: int, path: Path) -> None:
        print(f"[{number}/{total}] {path.name}", file=sys.stderr, flush=True)

    for outcome in batch.scan_all(paths, options, on_start=announce):
        if not outcome.ok:
            tally.failures.append(f"{outcome.path.name}: {outcome.error}")
            continue
        tally.apps += 1
        tally.seconds += outcome.duration_sec
        tally.scores.append(outcome.result.score)
        tally.verdicts[outcome.result.verdict] += 1
        for capability in outcome.result.capabilities:
            tally.hits[capability.rule_id] += 1
    return tally


def to_markdown(tally: Tally, rules: list[Rule]) -> str:
    lines = [
        "# False-positive benchmark",
        "",
        f"Corpus: **{tally.apps} apps** assumed benign · tadori {__version__} · "
        f"{len(rules)} rules · {tally.seconds / max(tally.apps, 1):.1f}s per app.",
        "",
        "A hit rate here is not automatically a false positive: an app store really",
        "does install APKs. Read it as *how often this rule fires on ordinary apps*,",
        "and expect a high-severity rule to be rare.",
        "",
        f"Median score {_median(tally.scores):.1f} · "
        + " · ".join(f"{v} {k}" for k, v in tally.verdicts.most_common()),
        "",
        "| rule | severity | hit rate | apps |",
        "|---|---|---:|---:|",
    ]
    for rule in sorted(
        rules, key=lambda r: (-tally.rate(r.id), -r.severity.rank, r.id)
    ):
        lines.append(
            f"| `{rule.id}` {rule.name} | {rule.severity.value} | "
            f"{tally.rate(rule.id) * 100:.1f}% | {tally.hits[rule.id]} |"
        )
    if tally.failures:
        lines += ["", f"{len(tally.failures)} app(s) failed to parse:", ""]
        lines += [f"- {failure}" for failure in tally.failures[:20]]
    return "\n".join(lines) + "\n"


def to_json(tally: Tally, rules: list[Rule]) -> dict:
    return {
        "tadori_version": __version__,
        "apps": tally.apps,
        "rules": len(rules),
        "seconds_per_app": round(tally.seconds / max(tally.apps, 1), 2),
        "median_score": _median(tally.scores),
        "verdicts": dict(tally.verdicts),
        "hit_rate": {
            rule.id: {
                "name": rule.name,
                "severity": rule.severity.value,
                "apps": tally.hits[rule.id],
                "rate": round(tally.rate(rule.id), 4),
            }
            for rule in rules
        },
        "failures": tally.failures,
    }


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True, help="directory of APKs")
    parser.add_argument("--out", type=Path, help="write a markdown table here")
    parser.add_argument("--json", type=Path, help="write the raw tally here")
    parser.add_argument("--rules", type=Path, action="append", help="rule path")
    parser.add_argument("--limit", type=int, help="scan at most N apps")
    parser.add_argument("--timeout", type=float, default=600.0)
    args = parser.parse_args()

    apks = batch.collect_apps([args.corpus], limit=args.limit)
    if not apks:
        print(f"no .apk found under {args.corpus}", file=sys.stderr)
        return 2

    rules = load_rules(args.rules)
    tally = scan_corpus(apks, rules, args.timeout)

    markdown = to_markdown(tally, rules)
    if args.out:
        args.out.write_text(markdown)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(markdown)
    if args.json:
        args.json.write_text(json.dumps(to_json(tally, rules), indent=2) + "\n")
        print(f"wrote {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
