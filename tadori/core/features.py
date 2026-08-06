"""Single-pass DEX feature extraction.

One walk over the bytecode produces both things tadori needs:

1. a per-method feature index — invoked APIs, string / field / type constants
   and opcode counts, filtered to what the loaded rules can match, and
2. a reverse call graph (callee -> callers) for reachability analysis.

Doing this ourselves avoids ``Analysis.create_xref()``, which more than
doubles load time on a mid-size APK and builds xrefs we would mostly discard.
"""

from __future__ import annotations

import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from tadori.core.patterns import Pattern, PatternSet, normalize

# androguard encodes operands as ``(kind, index, string)``. ``Operand.KIND`` is
# 0x100 and the low byte is the Kind enum: METH=0, STRING=1, FIELD=2, TYPE=3.
KIND_BASE = 0x100
KIND_METHOD = 0x100
KIND_STRING = 0x101
KIND_FIELD = 0x102
KIND_TYPE = 0x103

FEATURE_KINDS = ("api", "string", "field", "type")

#: Call sites that expose app methods to a JavaScript context.
JS_BRIDGE_APIS = frozenset(
    normalize(api)
    for api in (
        "Landroid/webkit/WebView;->addJavascriptInterface",
        "Landroidx/webkit/WebViewCompat;->addWebMessageListener",
    )
)


def method_ref(class_name: str, name: str, descriptor: str) -> str:
    """Canonical method reference, e.g. ``Lcom/x/A;->run()V``."""
    return normalize(f"{class_name}->{name}{descriptor}")


def ref_class(ref: str) -> str:
    return ref.split("->", 1)[0]


# ---------------------------------------------------------------------------
# vocabulary
# ---------------------------------------------------------------------------


@dataclass
class Vocabulary:
    """Everything the loaded rules could match; used to filter the walk."""

    api: PatternSet = field(default_factory=PatternSet)
    string: PatternSet = field(default_factory=PatternSet)
    field_: PatternSet = field(default_factory=PatternSet)
    type: PatternSet = field(default_factory=PatternSet)
    opcodes: set[str] = field(default_factory=set)

    def add(self, kind: str, pattern: Pattern) -> None:
        if kind == "opcode":
            self.opcodes.add(pattern.raw)
        else:
            self._set(kind).add(pattern)

    def matches(self, kind: str, value: str) -> bool:
        return self._set(kind).matches(value)

    def _set(self, kind: str) -> PatternSet:
        # Called once per constant in the walk, so keep it a dict lookup.
        try:
            return getattr(self, _VOCAB_ATTRIBUTES[kind])
        except KeyError:
            raise KeyError(f"unknown feature kind: {kind}") from None


#: ``field`` is spelled ``field_`` on Vocabulary; the rest match their kind.
_VOCAB_ATTRIBUTES = {
    "api": "api",
    "string": "string",
    "field": "field_",
    "type": "type",
}


# ---------------------------------------------------------------------------
# index
# ---------------------------------------------------------------------------


@dataclass
class MethodFeatures:
    """Vocabulary-relevant observations inside one method or class."""

    __slots__ = ("api", "string", "field", "type", "opcode")

    api: list[tuple[str, int]]
    string: list[tuple[str, int]]
    field: list[tuple[str, int]]
    type: list[tuple[str, int]]
    opcode: Counter[str]

    @classmethod
    def empty(cls) -> MethodFeatures:
        return cls([], [], [], [], Counter())

    def hits(self, kind: str) -> list[tuple[str, int]]:
        return getattr(self, kind)

    def extend(self, other: MethodFeatures) -> None:
        for kind in FEATURE_KINDS:
            self.hits(kind).extend(other.hits(kind))
        self.opcode.update(other.opcode)

    def __bool__(self) -> bool:
        return bool(self.api or self.string or self.field or self.type or self.opcode)


@dataclass
class AppIndex:
    """Feature index plus reverse call graph for one app."""

    features: dict[str, MethodFeatures] = field(default_factory=dict)
    callers: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    methods_by_class: dict[str, list[str]] = field(
        default_factory=lambda: defaultdict(list)
    )
    supers: dict[str, list[str]] = field(default_factory=dict)
    internal_refs: set[str] = field(default_factory=set)
    internal_classes: set[str] = field(default_factory=set)
    #: signature ("name(desc)ret") -> how many internal methods declare it.
    #: A high count means the signature is polymorphic (``run()V``), and
    #: resolving calls through it would connect unrelated code.
    signature_counts: Counter[str] = field(default_factory=Counter)
    js_bridge_classes: set[str] = field(default_factory=set)
    method_count: int = 0
    truncated: bool = False

    def record_method(self, ref: str) -> str:
        """Register one of the app's own methods; returns the interned ref.

        Both the DEX walk and the fixture builder go through here, so the
        bookkeeping reachability depends on — the class map and the signature
        counts behind the polymorphic cut — cannot drift between them.
        """
        ref = sys.intern(ref)
        class_name = ref_class(ref)
        self.internal_refs.add(ref)
        self.internal_classes.add(class_name)
        self.methods_by_class[class_name].append(ref)
        self.signature_counts[ref.partition("->")[2]] += 1
        return ref

    def features_of(self, ref: str) -> MethodFeatures:
        return self.features.get(ref) or MethodFeatures.empty()

    def class_features(self, class_name: str) -> MethodFeatures:
        """Union of the features of every method declared in a class."""
        merged = MethodFeatures.empty()
        for ref in self.methods_by_class.get(class_name, ()):
            found = self.features.get(ref)
            if found:
                merged.extend(found)
        return merged

    def app_features(self) -> MethodFeatures:
        """Union of every recorded feature in the app."""
        merged = MethodFeatures.empty()
        for found in self.features.values():
            merged.extend(found)
        return merged

    def ancestors(self, class_name: str) -> set[str]:
        """Transitive supers and interfaces; framework types included."""
        seen: set[str] = set()
        stack = list(self.supers.get(class_name, ()))
        while stack:
            parent = stack.pop()
            if parent in seen:
                continue
            seen.add(parent)
            stack.extend(self.supers.get(parent, ()))
        return seen


# ---------------------------------------------------------------------------
# the walk
# ---------------------------------------------------------------------------


def build_index(
    analysis: Any,
    vocab: Vocabulary,
    *,
    call_graph: bool = True,
    deadline: float | None = None,
) -> AppIndex:
    """Walk every internal method once, filling the feature index and call graph."""
    index = AppIndex()
    methods = [m for m in analysis.get_methods() if not m.is_external()]
    _map_classes(analysis, methods, index)
    edge_classes = _edge_classes(index) if call_graph else set()

    for count, method in enumerate(methods):
        if deadline is not None and count % 512 == 0 and time.monotonic() > deadline:
            index.truncated = True
            break
        _scan_method(method, index, vocab, edge_classes)

    return index


def _map_classes(analysis: Any, methods: list[Any], index: AppIndex) -> None:
    """Record the app's own methods, classes and class hierarchy."""
    for method in methods:
        index.record_method(
            method_ref(method.class_name, method.name, method.descriptor)
        )
    index.method_count = len(index.internal_refs)

    for klass in analysis.get_classes():
        parents = []
        extends = getattr(klass, "extends", None)
        if extends:
            parents.append(str(extends))
        parents.extend(str(i) for i in (getattr(klass, "implements", None) or []))
        if parents:
            index.supers[str(klass.name)] = parents


def _edge_classes(index: AppIndex) -> set[str]:
    """Classes whose call edges are worth keeping.

    The app's own classes, plus the framework types they extend: a virtual call
    is emitted against the *declaring* class, so ``Landroid/os/AsyncTask;->
    doInBackground`` is how a subclass override gets invoked.
    """
    classes = set(index.internal_classes)
    for cls in index.internal_classes:
        classes |= index.ancestors(cls)
    return classes


def _scan_method(
    method: Any,
    index: AppIndex,
    vocab: Vocabulary,
    edge_classes: set[str],
) -> None:
    """Decode one method, recording its features and outgoing call edges."""
    instructions = _instructions(method)
    if instructions is None:
        return

    ref = method_ref(method.class_name, method.name, method.descriptor)
    feats = MethodFeatures.empty()
    types_seen: list[str] = []
    exposes_js_bridge = False
    offset = 0

    try:
        for instruction in instructions:
            opcode = instruction.get_name()
            if opcode in vocab.opcodes:
                feats.opcode[opcode] += 1

            for kind, value in _constants(instruction):
                if kind == KIND_METHOD:
                    if ref_class(value) in edge_classes:
                        index.callers[sys.intern(value)].add(sys.intern(ref))
                    if value.split("(", 1)[0] in JS_BRIDGE_APIS:
                        exposes_js_bridge = True
                    _record(feats, "api", value, offset, vocab)
                elif kind == KIND_STRING:
                    _record(feats, "string", value, offset, vocab)
                elif kind == KIND_FIELD:
                    _record(feats, "field", value, offset, vocab)
                elif kind == KIND_TYPE:
                    types_seen.append(value)
                    _record(feats, "type", value, offset, vocab)

            offset += instruction.get_length()
    except Exception:
        # One unparsable method must not abort the whole scan.
        return

    if exposes_js_bridge:
        index.js_bridge_classes.update(
            t for t in types_seen if t in index.internal_classes
        )
    if feats:
        index.features[ref] = feats


def _instructions(method: Any) -> Any | None:
    """Instructions of a method, or None when it has no decodable code.

    Abstract and native methods have no code, and a malformed code item makes
    androguard raise — neither may abort the scan.
    """
    try:
        encoded = method.get_method()
        if encoded is None or encoded.get_code() is None:
            return None
        return encoded.get_instructions()
    except Exception:
        return None


def _constants(instruction: Any) -> list[tuple[int, str]]:
    """Extract ``(kind, value)`` constants referenced by an instruction.

    Field references arrive as ``Lcls;->NAME Ltype;``; the space becomes a colon
    so that a rule can write ``Lcls;->NAME`` and mean "any type".
    """
    out = []
    for operand in instruction.get_operands():
        if len(operand) < 3:
            continue
        kind, value = operand[0], operand[2]
        if not isinstance(kind, int) or kind < KIND_BASE or not isinstance(value, str):
            continue
        if kind == KIND_STRING:
            out.append((kind, value))
        elif kind == KIND_FIELD:
            out.append((kind, normalize(value.replace(" ", ":", 1))))
        else:
            out.append((kind, normalize(value)))
    return out


def _record(
    feats: MethodFeatures, kind: str, value: str, offset: int, vocab: Vocabulary
) -> None:
    if vocab.matches(kind, value):
        feats.hits(kind).append((value, offset))
