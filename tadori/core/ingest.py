"""Input loading: APK, bare DEX, or a decoded app directory.

androguard is imported lazily and its loguru logging is silenced, because the
library emits a DEBUG line per cross-reference otherwise.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tadori.core.models import AppInfo

logger = logging.getLogger(__name__)

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

_BIND_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "accessibility_service",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "notification_listener",
    "android.permission.BIND_DEVICE_ADMIN": "device_admin",
    "android.permission.BIND_INPUT_METHOD": "input_method",
}


def _silence_androguard() -> None:
    """androguard 4.x logs through loguru at DEBUG; make it quiet."""
    try:
        from loguru import logger as _loguru

        _loguru.remove()
    except Exception:  # pragma: no cover - loguru always ships with androguard
        pass


@dataclass
class Component:
    """A manifest-declared component."""

    type: str  # activity | service | receiver | provider
    name: str  # fully qualified Java class name
    exported: bool = False
    permission: str = ""
    actions: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def special_kind(self) -> str:
        """Framework role implied by the bind permission, if any."""
        return _BIND_PERMISSIONS.get(self.permission, "")


@dataclass
class Manifest:
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    sdk_min: str = ""
    sdk_target: str = ""
    application_class: str = ""
    permissions: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    intent_actions: set[str] = field(default_factory=set)

    def of_type(self, type_: str) -> list[Component]:
        return [c for c in self.components if c.type == type_]


@dataclass
class LoadedApp:
    """Everything the analysis layer needs about an input artifact."""

    path: Path
    analysis: Any  # androguard Analysis
    manifest: Manifest
    files: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    dex_count: int = 0
    signed: str = ""
    certificate_sha256: str = ""
    warnings: list[str] = field(default_factory=list)

    def app_info(self, method_count: int = 0) -> AppInfo:
        return AppInfo(
            path=str(self.path),
            name=self.path.name,
            package=self.manifest.package,
            version_name=self.manifest.version_name,
            version_code=self.manifest.version_code,
            sdk_min=self.manifest.sdk_min,
            sdk_target=self.manifest.sdk_target,
            permissions=sorted(self.manifest.permissions),
            native_libs=sorted(self.native_libs),
            dex_count=self.dex_count,
            method_count=method_count,
            signed=self.signed,
            certificate_sha256=self.certificate_sha256,
        )


# ---------------------------------------------------------------------------
# manifest parsing
# ---------------------------------------------------------------------------


def _attr(el: Any, name: str) -> str:
    """Read an android:-namespaced attribute, tolerating undecoded manifests."""
    for key in (f"{ANDROID_NS}{name}", name):
        if key in el.attrib:
            return str(el.attrib[key])
    return ""


def _qualify(package: str, name: str) -> str:
    if name.startswith("."):
        return f"{package}{name}"
    if "." not in name and package:
        return f"{package}.{name}"
    return name


def parse_manifest_xml(root: Any) -> Manifest:
    """Build a Manifest from an AndroidManifest XML tree (androguard or stdlib)."""
    man = Manifest()
    man.package = _attr(root, "package") or root.attrib.get("package", "")
    man.version_name = _attr(root, "versionName")
    man.version_code = _attr(root, "versionCode")

    for el in root.iter("uses-sdk"):
        man.sdk_min = _attr(el, "minSdkVersion")
        man.sdk_target = _attr(el, "targetSdkVersion")

    for el in root.iter("uses-permission"):
        name = _attr(el, "name")
        if name:
            man.permissions.append(name)
    for el in root.iter("permission"):
        name = _attr(el, "name")
        if name:
            man.permissions.append(name)

    for app_el in root.iter("application"):
        app_name = _attr(app_el, "name")
        if app_name:
            man.application_class = _qualify(man.package, app_name)
        for md in app_el.iter("meta-data"):
            key = _attr(md, "name")
            if key:
                man.metadata[key] = _attr(md, "value")

    for tag in COMPONENT_TAGS:
        for el in root.iter(tag):
            name = _attr(el, "name") or _attr(el, "targetActivity")
            if not name:
                continue
            actions = [
                _attr(a, "name")
                for f in el.iter("intent-filter")
                for a in f.iter("action")
                if _attr(a, "name")
            ]
            exported_attr = _attr(el, "exported").lower()
            if exported_attr in {"true", "false"}:
                exported = exported_attr == "true"
            else:
                # Android's implicit default: exported when an intent filter exists.
                exported = bool(actions)
            comp = Component(
                type="activity" if tag == "activity-alias" else tag,
                name=_qualify(man.package, name),
                exported=exported,
                permission=_attr(el, "permission"),
                actions=actions,
                metadata={
                    _attr(md, "name"): _attr(md, "value")
                    for md in el.iter("meta-data")
                    if _attr(md, "name")
                },
            )
            man.components.append(comp)
            man.intent_actions.update(actions)

    return man


# ---------------------------------------------------------------------------
# loaders
# ---------------------------------------------------------------------------


def load(path: str | Path) -> LoadedApp:
    """Load an .apk, a .dex, or a directory containing classes*.dex."""
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"input not found: {p}")

    if p.is_dir():
        return _load_dir(p)
    suffix = p.suffix.lower()
    if suffix == ".apk":
        return _load_apk(p)
    if suffix in {".dex", ".odex"}:
        return _load_dex_files(p, [p.read_bytes()], Manifest())
    # APKs are zips; accept .zip/.aab-ish inputs that carry classes.dex
    if suffix in {".zip", ".apks", ".xapk", ".aab"}:
        return _load_apk(p)
    raise ValueError(
        f"unsupported input: {p.name} (expected .apk, .dex, or a directory with classes.dex)"
    )


def _load_apk(p: Path) -> LoadedApp:
    _silence_androguard()
    from androguard.core.apk import APK

    apk = APK(str(p))
    try:
        root = apk.get_android_manifest_axml().get_xml_obj()
        manifest = parse_manifest_xml(root)
    except Exception as exc:  # pragma: no cover - malformed manifest
        logger.debug("manifest parse failed: %s", exc)
        manifest = Manifest()

    warnings: list[str] = []
    if not manifest.package:
        manifest.package = apk.get_package() or ""
        warnings.append(
            "manifest could not be fully decoded; entry points may be incomplete"
        )
    if not manifest.version_name:
        manifest.version_name = apk.get_androidversion_name() or ""
    if not manifest.version_code:
        manifest.version_code = str(apk.get_androidversion_code() or "")
    if not manifest.permissions:
        manifest.permissions = list(apk.get_permissions() or [])

    dexes = list(apk.get_all_dex())
    files = list(apk.get_files())
    native = [f for f in files if f.startswith("lib/") and f.endswith(".so")]

    loaded = _load_dex_files(p, dexes, manifest)
    loaded.files = files
    loaded.native_libs = native
    loaded.warnings.extend(warnings)
    loaded.signed = _signature_schemes(apk)
    loaded.certificate_sha256 = _certificate_sha256(apk)
    return loaded


def _load_dir(p: Path) -> LoadedApp:
    dex_paths = sorted(p.glob("**/classes*.dex")) or sorted(p.glob("**/*.dex"))
    if not dex_paths:
        raise ValueError(f"no .dex found under {p}")

    manifest = Manifest()
    warnings: list[str] = []
    man_path = next(iter(sorted(p.glob("**/AndroidManifest.xml"))), None)
    if man_path is not None:
        try:
            manifest = _parse_manifest_file(man_path)
        except Exception as exc:
            warnings.append(f"could not parse {man_path.name}: {exc}")
    else:
        warnings.append(
            "no AndroidManifest.xml found; manifest entry points unavailable"
        )

    loaded = _load_dex_files(p, [d.read_bytes() for d in dex_paths], manifest)
    loaded.files = [str(f.relative_to(p)) for f in p.glob("**/*") if f.is_file()]
    loaded.native_libs = [f for f in loaded.files if f.endswith(".so")]
    loaded.warnings.extend(warnings)
    return loaded


def _parse_manifest_file(man_path: Path) -> Manifest:
    """Parse a decoded (text) or binary (AXML) AndroidManifest.xml."""
    raw = man_path.read_bytes()
    if raw[:4] == b"\x03\x00\x08\x00":
        _silence_androguard()
        from androguard.core.axml import AXMLPrinter

        return parse_manifest_xml(AXMLPrinter(raw).get_xml_obj())

    import xml.etree.ElementTree as ET

    return parse_manifest_xml(ET.fromstring(raw))


def _load_dex_files(path: Path, dexes: list[bytes], manifest: Manifest) -> LoadedApp:
    _silence_androguard()
    from androguard.core.analysis.analysis import Analysis
    from androguard.core.dex import DEX

    analysis = Analysis()
    warnings: list[str] = []
    ok = 0
    for i, raw in enumerate(dexes):
        try:
            analysis.add(DEX(raw))
            ok += 1
        except Exception as exc:
            warnings.append(f"dex #{i} failed to parse ({exc}); it was skipped")
    if ok == 0:
        raise ValueError("no parsable DEX found in input")

    return LoadedApp(
        path=path,
        analysis=analysis,
        manifest=manifest,
        dex_count=ok,
        warnings=warnings,
    )


def _signature_schemes(apk: Any) -> str:
    schemes = []
    for label, fn in (
        ("v1", "is_signed_v1"),
        ("v2", "is_signed_v2"),
        ("v3", "is_signed_v3"),
    ):
        try:
            if getattr(apk, fn)():
                schemes.append(label)
        except Exception:  # pragma: no cover - androguard variance
            continue
    return "+".join(schemes)


def _certificate_sha256(apk: Any) -> str:
    for fn in (
        "get_certificates_der_v3",
        "get_certificates_der_v2",
        "get_certificates_der_v1",
    ):
        try:
            ders = getattr(apk, fn)()
        except Exception:
            continue
        if ders:
            return hashlib.sha256(ders[0]).hexdigest()
    return ""
