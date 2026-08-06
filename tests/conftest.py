"""Shared fixtures.

Everything here is synthetic: no malware sample is needed to test the engine.
A real-APK integration test runs only when ``TADORI_TEST_APK`` points at one.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import pytest

from tadori.core.features import AppIndex, MethodFeatures
from tadori.core.rules import AppFacts, EvalContext


def features(
    *,
    api: list[str] | None = None,
    string: list[str] | None = None,
    field: list[str] | None = None,
    type: list[str] | None = None,
    opcode: dict[str, int] | None = None,
) -> MethodFeatures:
    """Build a MethodFeatures with sequential fake offsets."""
    return MethodFeatures(
        api=[(v, i * 4) for i, v in enumerate(api or [])],
        string=[(v, i * 4) for i, v in enumerate(string or [])],
        field=[(v, i * 4) for i, v in enumerate(field or [])],
        type=[(v, i * 4) for i, v in enumerate(type or [])],
        opcode=Counter(opcode or {}),
    )


def context(
    feats: MethodFeatures | None = None,
    *,
    location: str = "Lcom/x/A;->run()V",
    facts: AppFacts | None = None,
) -> EvalContext:
    return EvalContext(
        features=feats or features(),
        facts=facts or AppFacts(),
        location=location,
    )


def index_from_edges(
    edges: dict[str, list[str]],
    *,
    supers: dict[str, list[str]] | None = None,
    js_bridge: set[str] | None = None,
) -> AppIndex:
    """Build an AppIndex from ``caller -> [callees]`` edges."""
    index = AppIndex()
    refs = set(edges) | {callee for callees in edges.values() for callee in callees}
    for ref in sorted(refs):
        index.record_method(ref)
    for caller, callees in edges.items():
        for callee in callees:
            index.callers[callee].add(caller)

    index.supers = supers or {}
    index.js_bridge_classes = js_bridge or set()
    index.method_count = len(index.internal_refs)
    return index


@pytest.fixture
def real_apk() -> Path:
    path = os.environ.get("TADORI_TEST_APK")
    if not path or not Path(path).exists():
        pytest.skip("set TADORI_TEST_APK to a benign APK to run integration tests")
    return Path(path)
