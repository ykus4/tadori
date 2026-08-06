"""Data models shared across tadori.

The vocabulary is deliberately capability-centric rather than verdict-centric:
tadori reports *what an app can do and how that behaviour is reachable*, and
leaves "is this malware?" to the analyst.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
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
        return _SEVERITY_RANK[self.value]

    @property
    def default_weight(self) -> float:
        """Score weight a rule of this severity carries unless it overrides it."""
        return _SEVERITY_WEIGHT[self.value]


_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
_SEVERITY_WEIGHT = {"high": 20.0, "medium": 7.0, "low": 2.0, "info": 0.5}


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


def _entry_kind(value: Any) -> EntryKind:
    """Parse an entry kind read back from JSON, with a legible error."""
    try:
        return EntryKind(str(value))
    except ValueError as exc:
        valid = ", ".join(k.value for k in EntryKind)
        raise ValueError(
            f"unknown entry-point kind {value!r} (expected one of {valid}); "
            "the file may come from a different tadori version"
        ) from exc


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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        return cls(
            kind=str(data.get("kind", "")),
            value=str(data.get("value", "")),
            location=str(data.get("location", "")),
            offset=data.get("offset"),
        )


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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CallPath:
        entry = EntryPoint(
            method=str(data.get("entry", "")),
            kind=_entry_kind(data.get("entry_kind")),
        )
        return cls(entry=entry, methods=tuple(str(m) for m in data.get("methods", ())))


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

    @classmethod
    def from_dict(cls, data: dict[str, Any], rule_id: str = "") -> Match:
        return cls(
            rule_id=rule_id,
            location=str(data.get("location", "")),
            evidence=[Evidence.from_dict(e) for e in data.get("evidence", ())],
            paths=[CallPath.from_dict(p) for p in data.get("paths", ())],
            reachable=data.get("reachable"),
            provenance=str(data.get("provenance", "app")),
        )


#: How exposed a capability is, weakest first. ``declared`` is what a class- or
#: apk-scope rule gets: a manifest fact or a whole-class pattern has no single
#: call site to trace, so it is either present or absent.
EXPOSURE_ORDER = ("unreachable", "unknown", "local", "declared", "remote")


def _stronger(left: str, right: str) -> str:
    return left if EXPOSURE_ORDER.index(left) >= EXPOSURE_ORDER.index(right) else right


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

    @property
    def exposure(self) -> str:
        """Strongest exposure across this capability's matches.

        One vocabulary, shared by the score, the diff and the terminal output —
        see :data:`EXPOSURE_ORDER`.
        """
        if self.scope != "method":
            return "declared"

        best = "unreachable"
        for match in self.matches:
            if match.reachable is None:
                best = _stronger(best, "unknown")
                continue
            path = match.best_path
            if path is None:
                best = _stronger(best, "unreachable")
            elif path.entry.kind.is_remote:
                return "remote"
            else:
                best = _stronger(best, "local")
        return best

    @property
    def exposure_rank(self) -> int:
        return EXPOSURE_ORDER.index(self.exposure)

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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capability:
        rule_id = str(data.get("rule_id", ""))
        return cls(
            rule_id=rule_id,
            name=str(data.get("name", rule_id)),
            severity=Severity(str(data.get("severity", "info"))),
            scope=str(data.get("scope", "method")),
            description=str(data.get("description", "")),
            attack=[str(a) for a in data.get("attack", ())],
            mbc=[str(m) for m in data.get("mbc", ())],
            references=[str(r) for r in data.get("references", ())],
            matches=[Match.from_dict(m, rule_id) for m in data.get("matches", ())],
            score_contribution=float(data.get("score_contribution", 0.0)),
            score_reason=str(data.get("score_reason", "")),
        )


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
    #: Cross-platform toolkits detected in the package — see ingest.FRAMEWORK_MARKERS.
    frameworks: list[str] = field(default_factory=list)
    dex_count: int = 0
    method_count: int = 0
    signed: str = ""
    certificate_sha256: str = ""
    certificate_subject: str = ""
    certificate_issuer: str = ""
    certificate_not_before: str = ""
    certificate_not_after: str = ""
    debug_signed: bool = False

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
            "frameworks": self.frameworks,
            "dex_count": self.dex_count,
            "method_count": self.method_count,
            "signed": self.signed,
            "certificate_sha256": self.certificate_sha256,
            "certificate_subject": self.certificate_subject,
            "certificate_issuer": self.certificate_issuer,
            "certificate_not_before": self.certificate_not_before,
            "certificate_not_after": self.certificate_not_after,
            "debug_signed": self.debug_signed,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppInfo:
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        """Rebuild a result from its JSON form — see ``tadori diff``.

        Only what the diff and the report read is restored; the bytecode index
        behind a scan is gone, which is the point of storing the result.
        """
        if "app" not in data or "capabilities" not in data:
            raise ValueError(
                "not a tadori scan result (expected 'app' and 'capabilities' keys)"
            )
        return cls(
            app=AppInfo.from_dict(data["app"]),
            capabilities=[Capability.from_dict(c) for c in data["capabilities"]],
            entry_points=[
                EntryPoint(
                    method=str(e.get("method", "")),
                    kind=_entry_kind(e.get("kind")),
                    origin=str(e.get("origin", "")),
                )
                for e in data.get("entry_points", ())
            ],
            score=float(data.get("score", 0.0)),
            verdict=str(data.get("verdict", "")),
            scanned_at=str(data.get("scanned_at", "")),
            rules_evaluated=int(data.get("rules_evaluated", 0)),
            duration_sec=float(data.get("duration_sec", 0.0)),
            warnings=[str(w) for w in data.get("warnings", ())],
            tadori_version=str(data.get("tadori_version", "")),
            library_matches_hidden=int(data.get("library_matches_hidden", 0)),
        )
