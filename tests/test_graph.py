"""Reachability: entry-point classification and call-chain recovery."""

from __future__ import annotations

from tadori.core import graph
from tadori.core.entrypoints import EntryPointResolver
from tadori.core.ingest import Component, Manifest
from tadori.core.models import EntryKind, EntryPoint
from tests.conftest import index_from_edges

RECEIVER = "Lcom/x/Boot;->onReceive(Landroid/content/Context;)V"
MIDDLE = "Lcom/x/Helper;->step()V"
TARGET = "Lcom/x/Payload;->send()V"


def manifest_with_receiver(*, exported: bool = True) -> Manifest:
    return Manifest(
        package="com.x",
        components=[Component(type="receiver", name="com.x.Boot", exported=exported)],
    )


def test_path_from_exported_receiver_through_two_hops():
    index = index_from_edges({RECEIVER: [MIDDLE], MIDDLE: [TARGET]})
    from tadori.core import entrypoints

    resolver = entrypoints.discover(manifest_with_receiver(), index)

    paths = graph.find_paths(index, resolver, TARGET)
    assert len(paths) == 1
    path = paths[0]
    assert path.entry.kind is EntryKind.EXPORTED_RECEIVER
    assert path.hops == 2
    assert path.methods == (RECEIVER, MIDDLE, TARGET)


def test_non_exported_receiver_is_not_remote():
    index = index_from_edges({RECEIVER: [TARGET]})
    from tadori.core import entrypoints

    resolver = entrypoints.discover(manifest_with_receiver(exported=False), index)
    path = graph.find_paths(index, resolver, TARGET)[0]
    assert path.entry.kind is EntryKind.RECEIVER
    assert not path.entry.kind.is_remote


def test_max_hops_cuts_the_search():
    index = index_from_edges({RECEIVER: [MIDDLE], MIDDLE: [TARGET]})
    from tadori.core import entrypoints

    resolver = entrypoints.discover(manifest_with_receiver(), index)
    assert graph.find_paths(index, resolver, TARGET, max_hops=1) == []
    assert graph.find_paths(index, resolver, TARGET, max_hops=2)


def test_target_that_is_itself_an_entry_point_has_zero_hops():
    index = index_from_edges({RECEIVER: []})
    from tadori.core import entrypoints

    resolver = entrypoints.discover(manifest_with_receiver(), index)
    path = graph.find_paths(index, resolver, RECEIVER)[0]
    assert path.hops == 0
    assert path.methods == (RECEIVER,)


def test_unreachable_target_yields_no_path():
    index = index_from_edges({RECEIVER: [MIDDLE], "Lcom/x/Dead;->d()V": [TARGET]})
    from tadori.core import entrypoints

    resolver = entrypoints.discover(manifest_with_receiver(), index)
    assert graph.find_paths(index, resolver, TARGET) == []


def test_static_initializer_counts_as_an_entry_point():
    clinit = "Lcom/x/Loader;-><clinit>()V"
    index = index_from_edges({clinit: [TARGET]})
    resolver = EntryPointResolver(index=index)
    path = graph.find_paths(index, resolver, TARGET)[0]
    assert path.entry.kind is EntryKind.STATIC_INIT


def test_javascript_bridge_class_is_a_remote_entry_point():
    bridge = "Lcom/x/Bridge;->pay()V"
    index = index_from_edges({bridge: [TARGET]}, js_bridge={"Lcom/x/Bridge;"})
    resolver = EntryPointResolver(index=index)
    path = graph.find_paths(index, resolver, TARGET)[0]
    assert path.entry.kind is EntryKind.JS_BRIDGE
    assert path.entry.kind.is_remote


def test_framework_callback_override_is_an_entry_point():
    callback = "Lcom/x/Svc;->onStartCommand(Landroid/content/Intent;II)I"
    index = index_from_edges(
        {callback: [TARGET]}, supers={"Lcom/x/Svc;": ["Landroid/app/Service;"]}
    )
    resolver = EntryPointResolver(index=index)
    path = graph.find_paths(index, resolver, TARGET)[0]
    assert path.entry.kind is EntryKind.CALLBACK


def test_callback_inside_a_bundled_library_is_not_an_entry_point():
    callback = "Landroidx/work/Runner;->onStartCommand(Landroid/content/Intent;II)I"
    index = index_from_edges(
        {callback: [TARGET]},
        supers={"Landroidx/work/Runner;": ["Landroid/app/Service;"]},
    )
    resolver = EntryPointResolver(index=index)
    assert graph.find_paths(index, resolver, TARGET) == []


def test_virtual_dispatch_resolves_through_a_supertype():
    """A call against the base class reaches the override."""
    caller = "Lcom/x/Runner;->go()V"
    base_call = "Lcom/x/Base;->work()V"
    override = "Lcom/x/Impl;->work()V"
    index = index_from_edges(
        {caller: [base_call]}, supers={"Lcom/x/Impl;": ["Lcom/x/Base;"]}
    )
    index.internal_refs.add(override)
    index.internal_classes.add("Lcom/x/Impl;")
    index.signature_counts["work()V"] += 1

    assert graph.callers_of(index, override) == {caller}


def test_polymorphic_signatures_are_not_resolved_through():
    """Shared signatures would connect unrelated code, so they are skipped."""
    caller = "Lcom/x/Runner;->go()V"
    base_call = "Ljava/lang/Runnable;->run()V"
    override = "Lcom/x/Impl;->run()V"
    index = index_from_edges(
        {caller: [base_call]}, supers={"Lcom/x/Impl;": ["Ljava/lang/Runnable;"]}
    )
    index.signature_counts["run()V"] = graph.POLYMORPHIC_LIMIT + 1

    assert graph.callers_of(index, override) == set()


def test_paths_prefer_remote_entry_points():
    exported = "Lcom/x/Boot;->onReceive(Landroid/content/Context;)V"
    clinit = "Lcom/x/Loader;-><clinit>()V"
    index = index_from_edges({exported: [MIDDLE], clinit: [MIDDLE], MIDDLE: [TARGET]})
    from tadori.core import entrypoints

    resolver = entrypoints.discover(manifest_with_receiver(), index)
    paths = graph.find_paths(index, resolver, TARGET)
    assert paths[0].entry.kind is EntryKind.EXPORTED_RECEIVER
    assert {p.entry.kind for p in paths} == {
        EntryKind.EXPORTED_RECEIVER,
        EntryKind.STATIC_INIT,
    }


def test_entry_point_str_is_readable():
    entry = EntryPoint("Lcom/x/A;->f()V", EntryKind.SERVICE)
    assert str(entry) == "<service> Lcom/x/A;->f()V"
