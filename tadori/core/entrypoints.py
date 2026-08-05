"""Entry-point discovery: where can execution enter this app?

Reachability is only meaningful against a notion of "outside". tadori derives
that from the manifest (components, and the bind permission that reveals a
component's framework role), from JavaScript bridges found in the bytecode, and
from framework callback overrides.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tadori.core.features import AppIndex
from tadori.core.ingest import Manifest
from tadori.core.libraries import is_library
from tadori.core.models import EntryKind, EntryPoint

#: Framework callbacks that represent externally triggered execution.
CALLBACK_NAMES = frozenset(
    {
        "onCreate",
        "onStart",
        "onStartCommand",
        "onStartJob",
        "onResume",
        "onReceive",
        "onBind",
        "onHandleIntent",
        "onHandleWork",
        "onDestroy",
        "onTaskRemoved",
        "attachBaseContext",
        "doWork",
        "onAccessibilityEvent",
        "onNotificationPosted",
        "onNotificationRemoved",
        "onMessageReceived",
        "onNewToken",
        "onServiceConnected",
        "onEnabled",
        "onPasswordFailed",
        "onLocationChanged",
        "onSensorChanged",
        "onPageFinished",
        "onKeyEvent",
        "query",
        "openFile",
    }
)

_FRAMEWORK_PREFIXES = ("Landroid", "Lcom/google/android", "Ldalvik", "Ljavax")

_KIND_BY_COMPONENT = {
    ("activity", True): EntryKind.EXPORTED_ACTIVITY,
    ("activity", False): EntryKind.ACTIVITY,
    ("service", True): EntryKind.EXPORTED_SERVICE,
    ("service", False): EntryKind.SERVICE,
    ("receiver", True): EntryKind.EXPORTED_RECEIVER,
    ("receiver", False): EntryKind.RECEIVER,
    ("provider", True): EntryKind.EXPORTED_PROVIDER,
    ("provider", False): EntryKind.PROVIDER,
}


def class_to_smali(class_name: str) -> str:
    """``com.x.Svc`` -> ``Lcom/x/Svc;``"""
    if class_name.startswith("L") and class_name.endswith(";"):
        return class_name
    return "L" + class_name.replace(".", "/") + ";"


@dataclass
class EntryPointResolver:
    """Classifies a method reference as an entry point, or not."""

    index: AppIndex
    explicit: dict[str, EntryPoint] = field(default_factory=dict)
    declared: list[EntryPoint] = field(default_factory=list)

    def classify(self, ref: str) -> EntryPoint | None:
        found = self.explicit.get(ref)
        if found:
            return found

        cls, signature = ref.split("->", 1)
        name = signature.split("(", 1)[0]

        # Entry points are the app's own code. A callback inside a bundled
        # library is a step on a path, not the start of one.
        if is_library(cls):
            return None

        if name == "<clinit>":
            return EntryPoint(ref, EntryKind.STATIC_INIT, cls)
        if cls in self.index.js_bridge_classes:
            return EntryPoint(ref, EntryKind.JS_BRIDGE, cls)
        if name in CALLBACK_NAMES and self._extends_framework(cls):
            return EntryPoint(ref, EntryKind.CALLBACK, cls)
        return None

    def _extends_framework(self, cls: str) -> bool:
        return any(
            ancestor.startswith(_FRAMEWORK_PREFIXES)
            for ancestor in self.index.ancestors(cls)
        )


def discover(manifest: Manifest, index: AppIndex) -> EntryPointResolver:
    """Build a resolver from the manifest and the bytecode index."""
    resolver = EntryPointResolver(index=index)

    for component in manifest.components:
        kind = _kind_of(component.type, component.exported, component.special_kind)
        _register_class(resolver, class_to_smali(component.name), kind)

    if manifest.application_class:
        _register_class(
            resolver, class_to_smali(manifest.application_class), EntryKind.APPLICATION
        )

    for cls in sorted(index.js_bridge_classes):
        resolver.declared.append(EntryPoint(cls, EntryKind.JS_BRIDGE, cls))

    resolver.declared.sort(key=lambda e: (e.kind.value, e.method))
    return resolver


def _kind_of(component_type: str, exported: bool, special: str) -> EntryKind:
    if special:
        return EntryKind(special)
    return _KIND_BY_COMPONENT.get((component_type, exported), EntryKind.CALLBACK)


def _register_class(resolver: EntryPointResolver, cls: str, kind: EntryKind) -> None:
    """Mark a component class — and the app-internal classes it inherits from.

    A component that does not override ``onCreate`` still enters through its
    superclass's ``onCreate``, so inherited internal methods count too — but not
    bundled base classes like ``androidx.activity.ComponentActivity``, which
    every activity shares and which would make half the app look like an entry.
    """
    index = resolver.index
    families = [
        cls,
        *(
            ancestor
            for ancestor in index.ancestors(cls)
            if ancestor in index.internal_classes and not is_library(ancestor)
        ),
    ]
    for family_class in families:
        for ref in index.methods_by_class.get(family_class, ()):
            resolver.explicit.setdefault(ref, EntryPoint(ref, kind, cls))

    if cls in index.internal_classes or cls in index.methods_by_class:
        resolver.declared.append(EntryPoint(cls, kind, cls))
    else:
        # Declared in the manifest but absent from the DEX (split APK, packer,
        # or a stale manifest entry) — still worth surfacing.
        resolver.declared.append(EntryPoint(cls, kind, f"{cls} (not in DEX)"))


def entry_kind_counts(resolver: EntryPointResolver) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in resolver.declared:
        counts[entry.kind.value] = counts.get(entry.kind.value, 0) + 1
    return dict(sorted(counts.items()))
