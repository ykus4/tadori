"""Manifest parsing and entry-point kinds."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from tadori.core import entrypoints, ingest
from tadori.core.models import EntryKind
from tests.conftest import index_from_edges

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.x" android:versionName="1.2.3" android:versionCode="42">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="34"/>
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <application android:name=".App" android:debuggable="true"
               android:allowBackup="true" android:usesCleartextTraffic="false">
    <meta-data android:name="com.x.KEY" android:value="v"/>
    <activity android:name=".MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity>
    <activity android:name=".Internal"/>
    <activity android:name=".Explicit" android:exported="false">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
      </intent-filter>
    </activity>
    <service android:name="com.x.AccessSvc"
             android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
    <service android:name=".NotifSvc"
             android:permission="android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"/>
    <receiver android:name=".AdminRcv"
              android:permission="android.permission.BIND_DEVICE_ADMIN"/>
    <receiver android:name=".BootRcv">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
    <provider android:name=".Files" android:exported="true"/>
  </application>
</manifest>
"""


@pytest.fixture
def manifest() -> ingest.Manifest:
    return ingest.parse_manifest_xml(ET.fromstring(MANIFEST))


def test_manifest_metadata(manifest):
    assert manifest.package == "com.x"
    assert manifest.version_name == "1.2.3"
    assert manifest.version_code == "42"
    assert manifest.sdk_min == "23"
    assert manifest.sdk_target == "34"
    assert manifest.application_class == "com.x.App"
    assert manifest.permissions == ["android.permission.RECEIVE_SMS"]
    assert manifest.metadata == {"com.x.KEY": "v"}
    assert "android.intent.action.BOOT_COMPLETED" in manifest.intent_actions


def test_relative_component_names_are_qualified(manifest):
    names = {c.name for c in manifest.components}
    assert "com.x.MainActivity" in names
    assert "com.x.AccessSvc" in names


def test_exported_defaults_follow_android_semantics(manifest):
    by_name = {c.name: c for c in manifest.components}
    assert by_name["com.x.MainActivity"].exported  # has an intent filter
    assert not by_name["com.x.Internal"].exported  # no filter, no attribute
    assert not by_name["com.x.Explicit"].exported  # attribute wins over filter
    assert by_name["com.x.Files"].exported


def test_bind_permission_reveals_the_framework_role(manifest):
    by_name = {c.name: c for c in manifest.components}
    assert by_name["com.x.AccessSvc"].special_kind == "accessibility_service"
    assert by_name["com.x.NotifSvc"].special_kind == "notification_listener"
    assert by_name["com.x.AdminRcv"].special_kind == "device_admin"
    assert by_name["com.x.BootRcv"].special_kind == ""


def test_entry_point_kinds_are_derived_from_the_manifest(manifest):
    index = index_from_edges(
        {
            "Lcom/x/MainActivity;->onCreate(Landroid/os/Bundle;)V": [],
            "Lcom/x/AccessSvc;->onAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V": [],
            "Lcom/x/App;->onCreate()V": [],
        }
    )
    resolver = entrypoints.discover(manifest, index)

    assert (
        resolver.classify("Lcom/x/MainActivity;->onCreate(Landroid/os/Bundle;)V").kind
        is EntryKind.EXPORTED_ACTIVITY
    )
    assert (
        resolver.classify(
            "Lcom/x/AccessSvc;->onAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V"
        ).kind
        is EntryKind.ACCESSIBILITY_SERVICE
    )
    assert resolver.classify("Lcom/x/App;->onCreate()V").kind is EntryKind.APPLICATION
    counts = entrypoints.entry_kind_counts(resolver)
    assert counts["accessibility_service"] == 1
    assert counts["exported_activity"] == 1


def test_inherited_methods_of_an_app_base_class_are_entry_points(manifest):
    index = index_from_edges({"Lcom/x/BaseActivity;->onResume()V": []})
    index.internal_classes.add("Lcom/x/MainActivity;")
    index.supers["Lcom/x/MainActivity;"] = ["Lcom/x/BaseActivity;"]

    resolver = entrypoints.discover(manifest, index)
    entry = resolver.classify("Lcom/x/BaseActivity;->onResume()V")
    assert entry is not None
    assert entry.kind is EntryKind.EXPORTED_ACTIVITY


def test_unsupported_input_is_rejected(tmp_path):
    bogus = tmp_path / "app.txt"
    bogus.write_text("nope")
    with pytest.raises(ValueError, match="unsupported input"):
        ingest.load(bogus)


def test_missing_input_is_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        ingest.load(tmp_path / "absent.apk")


def test_directory_without_dex_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="no .dex found"):
        ingest.load(tmp_path)


# ---------------------------------------------------------------------------
# packaging: cross-platform toolkits and the signing certificate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (["assets/flutter_assets/kernel_blob.bin"], ["flutter"]),
        (["lib/arm64-v8a/libflutter.so"], ["flutter"]),
        (["assets/index.android.bundle"], ["react-native"]),
        (["lib/armeabi-v7a/libunity.so", "assets/bin/Data/x"], ["unity"]),
        (["assemblies/Mono.Android.dll"], ["xamarin/maui"]),
        (["assets/www/index.html"], ["cordova/ionic"]),
        (["classes.dex", "res/layout/main.xml"], []),
    ],
)
def test_framework_markers(files, expected):
    assert ingest.detect_frameworks(files) == expected


def test_framework_detection_warns_that_coverage_is_partial():
    app = ingest.LoadedApp(
        path=Path("app.apk"),
        analysis=None,
        manifest=ingest.Manifest(),
        files=["assets/flutter_assets/kernel_blob.bin"],
    )
    ingest._note_packaging(app)
    assert app.frameworks == ["flutter"]
    assert "outside the DEX" in app.warnings[0]
    assert app.app_info().frameworks == ["flutter"]


def test_debug_key_is_called_out():
    app = ingest.LoadedApp(
        path=Path("app.apk"),
        analysis=None,
        manifest=ingest.Manifest(),
        signed="v1+v2",
        signer=ingest.Signer(
            sha256="a" * 64,
            subject="Common Name: Android Debug, Organization: Android, Country: US",
            not_after="2050-01-01T00:00:00",
        ),
    )
    ingest._note_packaging(app)
    assert app.signer.is_debug_key
    assert any("debug key" in w for w in app.warnings)

    info = app.app_info()
    assert info.debug_signed and info.certificate_sha256 == "a" * 64
    assert info.certificate_not_after.startswith("2050")


def test_v1_only_signing_is_called_out():
    app = ingest.LoadedApp(
        path=Path("app.apk"), analysis=None, manifest=ingest.Manifest(), signed="v1"
    )
    ingest._note_packaging(app)
    assert any("v1 only" in w for w in app.warnings)


def test_a_release_signature_produces_no_packaging_warnings():
    app = ingest.LoadedApp(
        path=Path("app.apk"),
        analysis=None,
        manifest=ingest.Manifest(),
        files=["classes.dex"],
        signed="v2+v3",
        signer=ingest.Signer(sha256="b" * 64, subject="Common Name: Example Corp"),
    )
    ingest._note_packaging(app)
    assert app.warnings == []
    assert not app.app_info().debug_signed


def test_application_flags_are_recorded(manifest):
    assert manifest.flags == {
        "debuggable": "true",
        "allowBackup": "true",
        "usesCleartextTraffic": "false",
    }


def test_exported_components_reach_the_rule_facts(manifest):
    from tadori.core.rules import AppFacts

    facts = AppFacts.from_manifest(manifest)
    assert facts.flags["debuggable"] == "true"
    exported = {(ctype, name) for ctype, name, _ in facts.exported}
    assert ("activity", "com.x.MainActivity") in exported
    assert ("activity", "com.x.Internal") not in exported  # no intent filter
    assert ("activity", "com.x.Explicit") not in exported  # exported="false"
    guarded = {name: permission for _, name, permission in facts.exported}
    assert guarded.get("com.x.BootRcv") == ""
