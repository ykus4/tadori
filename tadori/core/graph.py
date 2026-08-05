"""Reachability: from a matched method back up to an entry point.

This is what separates tadori from API-sequence matchers. A match is only
interesting if something can actually *reach* it, and an analyst wants the
chain, not a yes/no. We walk the reverse call graph breadth-first, so the first
time an entry point is seen it is via a shortest chain.
"""

from __future__ import annotations

import time
from collections import deque

from tadori.core.entrypoints import EntryPointResolver
from tadori.core.features import AppIndex
from tadori.core.models import CallPath, EntryPoint

DEFAULT_MAX_HOPS = 8
DEFAULT_MAX_PATHS = 6
#: Safety valve for pathological graphs (huge fan-in on utility methods).
MAX_VISITED = 20_000
#: A signature declared by more than this many internal methods is treated as
#: too polymorphic to resolve through. Without this, every ``Runnable.run()`` or
#: lifecycle-observer callback merges into one node and the reported chains stop
#: meaning anything.
POLYMORPHIC_LIMIT = 4


def callers_of(index: AppIndex, ref: str) -> set[str]:
    """Methods that can call ``ref``, including calls made against a supertype.

    A virtual call is emitted against the declaring class, so an override is
    also reached through ``Lsuper;->name(desc)`` references. That resolution is
    skipped for signatures shared by many classes: it is an over-approximation
    that would otherwise fabricate call chains between unrelated components.
    """
    found = set(index.callers.get(ref, ()))
    cls, _, signature = ref.partition("->")
    if index.signature_counts.get(signature, 0) <= POLYMORPHIC_LIMIT:
        for ancestor in index.ancestors(cls):
            found |= index.callers.get(f"{ancestor}->{signature}", set())
    return found


def find_paths(
    index: AppIndex,
    resolver: EntryPointResolver,
    target: str,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    max_paths: int = DEFAULT_MAX_PATHS,
    deadline: float | None = None,
) -> list[CallPath]:
    """Shortest call chains from entry points down to ``target``."""
    paths: list[CallPath] = []
    seen_kinds: set[str] = set()

    entry = resolver.classify(target)
    if entry is not None:
        paths.append(CallPath(entry, (target,)))
        seen_kinds.add(entry.kind.value)

    parent: dict[str, str] = {}
    visited = {target}
    queue: deque[tuple[str, int]] = deque([(target, 0)])

    while queue:
        ref, depth = queue.popleft()
        if depth >= max_hops or len(visited) > MAX_VISITED:
            continue
        if deadline is not None and time.monotonic() > deadline:
            break

        for caller in callers_of(index, ref):
            if caller in visited:
                continue
            visited.add(caller)
            parent[caller] = ref

            entry = resolver.classify(caller)
            if entry is not None and entry.kind.value not in seen_kinds:
                seen_kinds.add(entry.kind.value)
                paths.append(_build_path(entry, caller, parent, target))
                if len(paths) >= max_paths:
                    return _ranked(paths)
            queue.append((caller, depth + 1))

    return _ranked(paths)


def _build_path(
    entry: EntryPoint, start: str, parent: dict[str, str], target: str
) -> CallPath:
    chain = [start]
    node = start
    while node != target:
        node = parent[node]
        chain.append(node)
    return CallPath(entry, tuple(chain))


def _ranked(paths: list[CallPath]) -> list[CallPath]:
    """Most interesting first: externally triggerable, then shortest."""
    return sorted(
        paths, key=lambda p: (not p.entry.kind.is_remote, p.hops, p.entry.method)
    )
