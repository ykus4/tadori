"""The bytecode walk, exercised through fake androguard objects.

The stubs mimic exactly the parts of the androguard API the walk touches, which
keeps the operand decoding (offsets, field references, call edges) under test
without needing a DEX file.
"""

from __future__ import annotations

from tadori.core.features import (
    KIND_FIELD,
    KIND_METHOD,
    KIND_STRING,
    KIND_TYPE,
    Vocabulary,
    build_index,
)
from tadori.core.patterns import Pattern, PatternSet


class FakeInstruction:
    def __init__(self, name: str, operands: list[tuple], length: int = 4) -> None:
        self._name = name
        self._operands = operands
        self._length = length

    def get_name(self) -> str:
        return self._name

    def get_operands(self) -> list[tuple]:
        return self._operands

    def get_length(self) -> int:
        return self._length


class FakeEncodedMethod:
    def __init__(self, instructions: list[FakeInstruction]) -> None:
        self._instructions = instructions

    def get_code(self) -> object:
        return object()

    def get_instructions(self) -> list[FakeInstruction]:
        return self._instructions


class FakeMethod:
    def __init__(
        self, ref: str, instructions: list[FakeInstruction] | None = None
    ) -> None:
        cls, _, signature = ref.partition("->")
        name, _, rest = signature.partition("(")
        self.class_name = cls
        self.name = name
        self.descriptor = f"({rest}"
        self._encoded = FakeEncodedMethod(instructions or [])

    def is_external(self) -> bool:
        return False

    def get_method(self) -> FakeEncodedMethod:
        return self._encoded


class FakeClass:
    def __init__(self, name: str, extends: str | None = None, implements=()) -> None:
        self.name = name
        self.extends = extends
        self.implements = list(implements)


class FakeAnalysis:
    def __init__(
        self, methods: list[FakeMethod], classes: list[FakeClass] | None = None
    ) -> None:
        self._methods = methods
        self._classes = classes or []

    def get_methods(self) -> list[FakeMethod]:
        return self._methods

    def get_classes(self) -> list[FakeClass]:
        return self._classes


def invoke(ref: str) -> FakeInstruction:
    return FakeInstruction("invoke-virtual", [(0, 1), (KIND_METHOD, 7, ref)], length=6)


def const_string(value: str) -> FakeInstruction:
    return FakeInstruction("const-string", [(0, 2), (KIND_STRING, 9, value)], length=4)


def sget(ref: str) -> FakeInstruction:
    return FakeInstruction("sget-object", [(0, 3), (KIND_FIELD, 5, ref)], length=4)


def new_instance(type_name: str) -> FakeInstruction:
    return FakeInstruction(
        "new-instance", [(0, 4), (KIND_TYPE, 3, type_name)], length=4
    )


def vocabulary(**kinds: list[str]) -> Vocabulary:
    vocab = Vocabulary()
    for kind, patterns in kinds.items():
        for raw in patterns:
            vocab.add(kind, Pattern(raw, reference=kind != "string"))
    return vocab


# ---------------------------------------------------------------------------


def test_api_and_string_features_are_indexed_with_offsets():
    method = FakeMethod(
        "Lcom/x/A;->f()V",
        [
            invoke(
                "Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;)V"
            ),
            const_string("api.telegram.org/bot"),
        ],
    )
    vocab = vocabulary(
        api=["Landroid/telephony/SmsManager;->sendTextMessage"],
        string=["api.telegram.org/bot"],
    )
    index = build_index(FakeAnalysis([method]), vocab)

    feats = index.features_of("Lcom/x/A;->f()V")
    assert feats.api[0][1] == 0
    assert feats.string[0] == ("api.telegram.org/bot", 6)  # after the 6-byte invoke


def test_whitespace_in_descriptors_is_normalised():
    ref_with_spaces = "Lcom/x/B;->g(Ljava/lang/String; I)V"
    method = FakeMethod("Lcom/x/A;->f()V", [invoke(ref_with_spaces)])
    index = build_index(
        FakeAnalysis([method]), vocabulary(api=["Lcom/x/B;->g(Ljava/lang/String;I)V"])
    )
    assert index.features_of("Lcom/x/A;->f()V").api


def test_field_references_get_a_colon_before_the_type():
    method = FakeMethod(
        "Lcom/x/A;->f()V", [sget("Landroid/os/Build;->FINGERPRINT Ljava/lang/String;")]
    )
    index = build_index(
        FakeAnalysis([method]), vocabulary(field=["Landroid/os/Build;->FINGERPRINT"])
    )
    assert index.features_of("Lcom/x/A;->f()V").field[0][0] == (
        "Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;"
    )


def test_features_outside_the_vocabulary_are_not_recorded():
    method = FakeMethod("Lcom/x/A;->f()V", [invoke("Lcom/y/Z;->irrelevant()V")])
    index = build_index(
        FakeAnalysis([method]), vocabulary(api=["Lcom/x/Wanted;->only"])
    )
    assert index.features == {}
    # …but the call edge is still there, because reachability needs it.
    assert index.method_count == 1


def test_call_edges_are_kept_for_app_and_inherited_classes_only():
    caller = FakeMethod(
        "Lcom/x/A;->f()V",
        [invoke("Lcom/x/B;->g()V"), invoke("Lcom/unrelated/C;->h()V")],
    )
    callee = FakeMethod("Lcom/x/B;->g()V")
    index = build_index(FakeAnalysis([caller, callee]), Vocabulary())

    assert index.callers["Lcom/x/B;->g()V"] == {"Lcom/x/A;->f()V"}
    assert "Lcom/unrelated/C;->h()V" not in index.callers


def test_javascript_bridge_targets_are_collected():
    method = FakeMethod(
        "Lcom/x/Web;->setup()V",
        [
            new_instance("Lcom/x/Bridge;"),
            invoke(
                "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V"
            ),
        ],
    )
    bridge = FakeMethod("Lcom/x/Bridge;->pay()V")
    index = build_index(FakeAnalysis([method, bridge]), Vocabulary())
    assert index.js_bridge_classes == {"Lcom/x/Bridge;"}


def test_class_and_app_feature_unions():
    a = FakeMethod("Lcom/x/A;->f()V", [const_string("one")])
    b = FakeMethod("Lcom/x/A;->g()V", [const_string("two")])
    index = build_index(FakeAnalysis([a, b]), vocabulary(string=["one", "two"]))

    assert {v for v, _ in index.class_features("Lcom/x/A;").string} == {"one", "two"}
    assert {v for v, _ in index.app_features().string} == {"one", "two"}


def test_class_hierarchy_is_recorded_transitively():
    classes = [
        FakeClass("Lcom/x/Impl;", extends="Lcom/x/Base;"),
        FakeClass(
            "Lcom/x/Base;",
            extends="Landroid/app/Service;",
            implements=["Lcom/x/Marker;"],
        ),
    ]
    index = build_index(
        FakeAnalysis([FakeMethod("Lcom/x/Impl;->f()V")], classes), Vocabulary()
    )
    assert index.ancestors("Lcom/x/Impl;") == {
        "Lcom/x/Base;",
        "Landroid/app/Service;",
        "Lcom/x/Marker;",
    }


def test_signature_counts_track_polymorphism():
    methods = [FakeMethod(f"Lcom/x/A{i};->run()V") for i in range(5)]
    index = build_index(FakeAnalysis(methods), Vocabulary())
    assert index.signature_counts["run()V"] == 5


def test_unparsable_method_does_not_abort_the_walk():
    class Exploding(FakeMethod):
        def get_method(self):  # noqa: ANN202
            raise RuntimeError("bad code item")

    good = FakeMethod("Lcom/x/A;->f()V", [const_string("kept")])
    index = build_index(
        FakeAnalysis([Exploding("Lcom/x/Bad;->boom()V"), good]),
        vocabulary(string=["kept"]),
    )
    assert index.features_of("Lcom/x/A;->f()V").string


def test_pattern_set_prefers_cheap_lookups():
    patterns = PatternSet()
    patterns.add(Pattern("Lcom/x/A;->f()V", reference=True))
    patterns.add(Pattern("Lcom/x/B;->g", reference=True))
    patterns.add(Pattern("/^Lcom\\/z\\//", reference=True))
    assert len(patterns) == 3
    assert patterns.matches("Lcom/x/A;->f()V")
    assert patterns.matches("Lcom/x/B;->g(I)V")
    assert patterns.matches("Lcom/z/Anything;->h()V")
    assert not patterns.matches("Lcom/x/C;->i()V")
