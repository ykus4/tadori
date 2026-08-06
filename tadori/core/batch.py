"""Scanning a pile of apps instead of one.

Triage of a corpus and the false-positive benchmark are the same loop — walk a
directory, scan each app, keep going when one of them is unreadable, because a
real corpus always contains a few files that are not what they claim to be.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from tadori.core import engine
from tadori.core.models import ScanResult, Severity

#: Extensions ``collect_apps`` picks up when pointed at a directory.
APP_SUFFIXES = (".apk", ".apks", ".xapk")


@dataclass
class Outcome:
    """One app's scan — or the reason there is none."""

    path: Path
    result: ScanResult | None = None
    error: str = ""
    duration_sec: float = 0.0

    @property
    def ok(self) -> bool:
        return self.result is not None

    @property
    def score(self) -> float:
        return self.result.score if self.result else -1.0

    def counts(self) -> dict[str, int]:
        return self.result.summary if self.result else {}

    def to_dict(self) -> dict[str, object]:
        if self.result is None:
            return {"path": str(self.path), "error": self.error}
        app = self.result.app
        return {
            "path": str(self.path),
            "package": app.package,
            "version_name": app.version_name,
            "version_code": app.version_code,
            "score": self.result.score,
            "verdict": self.result.verdict,
            "duration_sec": round(self.duration_sec, 2),
            **self.counts(),
            "capabilities": [c.rule_id for c in self.result.capabilities],
        }


@dataclass
class Batch:
    """Every outcome of one corpus run, in the order the apps were scanned."""

    outcomes: list[Outcome] = field(default_factory=list)

    @property
    def scanned(self) -> list[Outcome]:
        return [o for o in self.outcomes if o.ok]

    @property
    def failures(self) -> list[Outcome]:
        return [o for o in self.outcomes if not o.ok]

    def ranked(self) -> list[Outcome]:
        """Worst first — the order an analyst wants to read."""
        return sorted(
            self.scanned,
            key=lambda o: (
                -o.score,
                -len(o.result.by_severity(Severity.HIGH)),
                o.path.name,
            ),
        )

    def seconds_per_app(self) -> float:
        scanned = self.scanned
        return sum(o.duration_sec for o in scanned) / len(scanned) if scanned else 0.0


def collect_apps(
    paths: Sequence[Path], *, limit: int | None = None, recursive: bool = True
) -> list[Path]:
    """Expand files and directories into a sorted list of apps to scan."""
    found: list[Path] = []
    for target in paths:
        target = Path(target)
        if target.is_dir():
            pattern = "**/*" if recursive else "*"
            found.extend(
                sorted(
                    p
                    for p in target.glob(pattern)
                    if p.is_file() and p.suffix.lower() in APP_SUFFIXES
                )
            )
        elif target.exists():
            found.append(target)
        else:
            raise FileNotFoundError(f"input not found: {target}")

    unique = sorted(dict.fromkeys(found))
    return unique[:limit] if limit else unique


def scan_all(
    paths: Sequence[Path],
    options: engine.ScanOptions | None = None,
    *,
    on_start: Callable[[int, Path], None] | None = None,
) -> Iterator[Outcome]:
    """Scan each app, yielding one outcome per app as it completes.

    An app that fails to load yields an outcome carrying the error rather than
    raising: one bad file must not end a corpus run.
    """
    opts = options or engine.ScanOptions()
    for number, path in enumerate(paths, 1):
        if on_start is not None:
            on_start(number, path)
        started = time.monotonic()
        try:
            result = engine.scan(path, opts)
        except Exception as exc:  # noqa: BLE001 - a corpus always has bad files
            yield Outcome(
                path=path, error=str(exc), duration_sec=time.monotonic() - started
            )
            continue
        yield Outcome(path=path, result=result, duration_sec=time.monotonic() - started)


def run(
    paths: Sequence[Path],
    options: engine.ScanOptions | None = None,
    *,
    on_start: Callable[[int, Path], None] | None = None,
) -> Batch:
    """``scan_all`` collected into a Batch."""
    return Batch(outcomes=list(scan_all(paths, options, on_start=on_start)))
