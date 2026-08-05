"""Data models shared across tadori.

The vocabulary is deliberately capability-centric rather than verdict-centric:
tadori reports *what an app can do and how that behaviour is reachable*, and
leaves "is this malware?" to the analyst.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# ---------------------------------------------------------------------------
# severity / entry points
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class EntryKind(StrEnum):
    """How control can enter the app at a given method."""

    EXPORTED_ACTIVITY = "exported_activity"
    ACTIVITY = "activity"
    EXPORTED_SERVICE = "exported_service"
    SERVICE = "service"
    EXPORTED_RECEIVER = "exported_receiver"
    RECEIVER = "receiver"
    EXPORTED_PROVIDER = "exported_provider"
    PROVIDER = "provider"
    ACCESSIBILITY_SERVICE = "accessibility_service"
    NOTIFICATION_LISTENER = "notification_listener"
    DEVICE_ADMIN = "device_admin"
    INPUT_METHOD = "input_method"
    APPLICATION = "application"
    STATIC_INIT = "static_init"
    JS_BRIDGE = "js_bridge"
    CALLBACK = "callback"

    @property
    def is_remote(self) -> bool:
        """True when an outside party can trigger this entry point directly."""
        return self in {
            EntryKind.EXPORTED_ACTIVITY,
            EntryKind.EXPORTED_SERVICE,
            EntryKind.EXPORTED_RECEIVER,
            EntryKind.EXPORTED_PROVIDER,
            EntryKind.JS_BRIDGE,
            EntryKind.ACCESSIBILITY_SERVICE,
            EntryKind.NOTIFICATION_LISTENER,
            EntryKind.DEVICE_ADMIN,
            EntryKind.INPUT_METHOD,
        }


@dataclass(frozen=True)
class EntryPoint:
    """A method through which execution can enter the app."""

    method: str  # "Lcom/x/Svc;->onCreate()V"
    kind: EntryKind
    origin: str = ""  # manifest class, annotation site, …

    def __str__(self) -> str:
        return f"<{self.kind.value}> {self.method}"


# ---------------------------------------------------------------------------
# matches
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    """One concrete observation that made a rule fire."""

    kind: str  # api | string | field | type | opcode | permission | file | …
    value: str
    location: str = ""  # method / manifest / file the observation lives in
    offset: int | None = None  # bytecode offset, when applicable

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": self.kind, "value": self.value}
        if self.location:
            d["location"] = self.location
        if self.offset is not None:
            d["offset"] = self.offset
        return d

    def render(self) -> str:
        at = f" @ 0x{self.offset:x}" if self.offset is not None else ""
        return f"{self.kind:<10} {self.value}{at}"


@dataclass(frozen=True)
class CallPath:
    """A concrete call chain from an entry point down to the matched method."""

    entry: EntryPoint
    methods: tuple[str, ...]  # entry method first, matched method last

    @property
    def hops(self) -> int:
        return max(len(self.methods) - 1, 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry": self.entry.method,
            "entry_kind": self.entry.kind.value,
            "hops": self.hops,
            "methods": list(self.methods),
        }


@dataclass
class Match:
    """A single site where a rule fired."""

    rule_id: str
    location: str  # method / class / "apk"
    evidence: list[Evidence] = field(default_factory=list)
    paths: list[CallPath] = field(default_factory=list)
    reachable: bool | None = None  # None = reachability not computed
    provenance: str = "app"  # app | library — see tadori.core.libraries

    @property
    def best_path(self) -> CallPath | None:
        if not self.paths:
            return None
        return min(self.paths, key=lambda p: (not p.entry.kind.is_remote, p.hops))

    def to_dict(self) -> dict[str, Any]:
        return {
            "location": self.location,
            "provenance": self.provenance,
            "reachable": self.reachable,
            "evidence": [e.to_dict() for e in self.evidence],
            "paths": [p.to_dict() for p in self.paths],
        }


@dataclass
class Capability:
    """A rule plus every site at which it fired."""

    rule_id: str
    name: str
    severity: Severity
    scope: str
    description: str = ""
    attack: list[str] = field(default_factory=list)
    mbc: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    matches: list[Match] = field(default_factory=list)
    score_contribution: float = 0.0
    score_reason: str = ""

    @property
    def reachable_matches(self) -> list[Match]:
        return [m for m in self.matches if m.reachable is not False]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity.value,
            "scope": self.scope,
            "description": self.description,
            "attack": self.attack,
            "mbc": self.mbc,
            "references": self.references,
            "score_contribution": round(self.score_contribution, 2),
            "score_reason": self.score_reason,
            "match_count": len(self.matches),
            "matches": [m.to_dict() for m in self.matches],
        }


# ---------------------------------------------------------------------------
# result
# ---------------------------------------------------------------------------


@dataclass
class AppInfo:
    path: str
    name: str = ""
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    sdk_min: str = ""
    sdk_target: str = ""
    permissions: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    dex_count: int = 0
    method_count: int = 0
    signed: str = ""
    certificate_sha256: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "sdk_min": self.sdk_min,
            "sdk_target": self.sdk_target,
            "permissions": self.permissions,
            "native_libs": self.native_libs,
            "dex_count": self.dex_count,
            "method_count": self.method_count,
            "signed": self.signed,
            "certificate_sha256": self.certificate_sha256,
        }


@dataclass
class ScanResult:
    app: AppInfo
    capabilities: list[Capability] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    score: float = 0.0
    verdict: str = ""
    scanned_at: str = ""
    rules_evaluated: int = 0
    duration_sec: float = 0.0
    warnings: list[str] = field(default_factory=list)
    tadori_version: str = ""
    library_matches_hidden: int = 0

    def by_severity(self, severity: Severity) -> list[Capability]:
        return [c for c in self.capabilities if c.severity == severity]

    @property
    def summary(self) -> dict[str, int]:
        return {
            s.value: len(self.by_severity(s))
            for s in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tadori_version": self.tadori_version,
            "scanned_at": self.scanned_at,
            "duration_sec": round(self.duration_sec, 2),
            "app": self.app.to_dict(),
            "score": round(self.score, 1),
            "verdict": self.verdict,
            "summary": {**self.summary, "total": len(self.capabilities)},
            "rules_evaluated": self.rules_evaluated,
            "library_matches_hidden": self.library_matches_hidden,
            "entry_points": [
                {"method": e.method, "kind": e.kind.value, "origin": e.origin}
                for e in self.entry_points
            ],
            "capabilities": [c.to_dict() for c in self.capabilities],
            "warnings": self.warnings,
        }
