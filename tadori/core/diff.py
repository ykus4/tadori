"""Version-to-version capability diff.

The interesting question for an app that is already installed on millions of
devices is not "is this build malicious?" but "did this build gain something it
did not have before?" — the versioning-attack pattern, where a clean app turns
hostile in an update.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tadori.core.models import Capability, ScanResult, Severity

#: Suffix that marks a stored scan result rather than an app to scan.
BASELINE_SUFFIX = ".json"

#: Permissions whose appearance in an update is worth an explicit callout.
WATCHED_PERMISSIONS = frozenset(
    {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
    }
)


@dataclass
class Delta:
    """What changed between two scans of the same package."""

    old: ScanResult
    new: ScanResult
    added: list[Capability] = field(default_factory=list)
    removed: list[Capability] = field(default_factory=list)
    escalated: list[tuple[Capability, Capability]] = field(default_factory=list)
    added_permissions: list[str] = field(default_factory=list)
    removed_permissions: list[str] = field(default_factory=list)
    added_entry_kinds: list[str] = field(default_factory=list)
    added_native_libs: list[str] = field(default_factory=list)
    certificate_changed: bool = False

    @property
    def score_delta(self) -> float:
        return round(self.new.score - self.old.score, 1)

    @property
    def watched_permissions(self) -> list[str]:
        return [p for p in self.added_permissions if p in WATCHED_PERMISSIONS]

    @property
    def added_high(self) -> list[Capability]:
        return [c for c in self.added if c.severity == Severity.HIGH]

    def headline(self) -> str:
        """One sentence an analyst can act on."""
        if self.certificate_changed:
            return "signing certificate changed — this is not the same publisher"
        if self.added_high:
            return (
                f"{len(self.added_high)} new high-severity capability(ies): "
                + ", ".join(c.rule_id for c in self.added_high)
            )
        if self.escalated:
            return f"{len(self.escalated)} capability(ies) became more exposed"
        if self.watched_permissions:
            return "new sensitive permission(s): " + ", ".join(self.watched_permissions)
        if self.added:
            return f"{len(self.added)} new capability(ies), none high severity"
        return "no new capabilities"

    def is_regression(self) -> bool:
        """True when the update added attack-relevant capability or exposure."""
        return bool(
            self.certificate_changed
            or self.added_high
            or self.escalated
            or self.watched_permissions
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "headline": self.headline(),
            "regression": self.is_regression(),
            "old": _side(self.old),
            "new": _side(self.new),
            "score_delta": self.score_delta,
            "certificate_changed": self.certificate_changed,
            "added_capabilities": [c.to_dict() for c in self.added],
            "removed_capabilities": [
                {"rule_id": c.rule_id, "name": c.name} for c in self.removed
            ],
            "escalated_capabilities": [
                {
                    "rule_id": new.rule_id,
                    "name": new.name,
                    "from": old.exposure,
                    "to": new.exposure,
                }
                for old, new in self.escalated
            ],
            "added_permissions": self.added_permissions,
            "removed_permissions": self.removed_permissions,
            "added_entry_kinds": self.added_entry_kinds,
            "added_native_libs": self.added_native_libs,
        }


def is_baseline(path: str | Path) -> bool:
    """True for a stored scan result (``tadori scan -f json``), not an app."""
    return Path(path).suffix.lower() == BASELINE_SUFFIX


def load_baseline(path: str | Path) -> ScanResult:
    """Read a scan result written earlier by ``tadori scan -f json``.

    A release gate wants to compare today's build against the last reviewed
    one, and the reviewed APK is usually not what CI has lying around — the
    JSON it produced is.
    """
    p = Path(path)
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"{p}: not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{p}: not a tadori scan result")
    try:
        return ScanResult.from_dict(data)
    except ValueError as exc:
        raise ValueError(f"{p}: {exc}") from exc


def compare(old: ScanResult, new: ScanResult) -> Delta:
    """Diff two scan results (same package, older build first)."""
    old_caps = {c.rule_id: c for c in old.capabilities}
    new_caps = {c.rule_id: c for c in new.capabilities}

    delta = Delta(old=old, new=new)
    delta.added = [new_caps[k] for k in new_caps.keys() - old_caps.keys()]
    delta.removed = [old_caps[k] for k in old_caps.keys() - new_caps.keys()]
    delta.escalated = [
        (old_caps[k], new_caps[k])
        for k in old_caps.keys() & new_caps.keys()
        if new_caps[k].exposure_rank > old_caps[k].exposure_rank
    ]

    old_perms, new_perms = set(old.app.permissions), set(new.app.permissions)
    delta.added_permissions = sorted(new_perms - old_perms)
    delta.removed_permissions = sorted(old_perms - new_perms)

    old_kinds = {e.kind.value for e in old.entry_points}
    delta.added_entry_kinds = sorted(
        {e.kind.value for e in new.entry_points} - old_kinds
    )
    delta.added_native_libs = sorted(
        set(new.app.native_libs) - set(old.app.native_libs)
    )
    delta.certificate_changed = bool(
        old.app.certificate_sha256
        and new.app.certificate_sha256
        and old.app.certificate_sha256 != new.app.certificate_sha256
    )

    delta.added.sort(key=lambda c: (-c.severity.rank, c.rule_id))
    delta.removed.sort(key=lambda c: (-c.severity.rank, c.rule_id))
    return delta


def _side(result: ScanResult) -> dict[str, Any]:
    return {
        "path": result.app.path,
        "package": result.app.package,
        "version_name": result.app.version_name,
        "version_code": result.app.version_code,
        "score": result.score,
        "capabilities": len(result.capabilities),
    }
