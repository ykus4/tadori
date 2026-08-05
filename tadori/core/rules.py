"""YAML rule format: parsing, evaluation and validation.

A rule is one file::

    rule:
      meta:
        id: TAD-CRED-0001
        name: read incoming SMS messages
        scope: method
        severity: high
        attack: [T1412]
      features:
        - api: "Landroid/telephony/SmsMessage;->getMessageBody()Ljava/lang/String;"
        - or:
          - permission: android.permission.RECEIVE_SMS
          - intent_action: android.provider.Telephony.SMS_RECEIVED
      reachable_from:
        entrypoint: [exported_receiver, receiver]
        max_hops: 6

The top-level ``features`` list is an implicit AND.
"""

from __future__ import annotations

import fnmatch
import operator
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import yaml

from tadori.core import attack
from tadori.core.features import MethodFeatures, Vocabulary
from tadori.core.models import EntryKind, Evidence, Severity
from tadori.core.patterns import Pattern

SCOPES = ("method", "class", "apk")
RULE_ID_RE = re.compile(r"^TAD-[A-Z][A-Z0-9]{1,7}-\d{4}$")

#: Leaf keys that read the bytecode feature index.
CODE_LEAVES = {
    "api": "api",
    "string": "string",
    "substring": "string",
    "regex": "string",
    "field": "field",
    "type": "type",
    "opcode": "opcode",
}
#: Leaf keys that read manifest / packaging facts.
FACT_LEAVES = (
    "permission",
    "intent_action",
    "component",
    "file",
    "metadata",
    "native_lib",
)
#: Leaf keys that match the site being evaluated, not its contents.
SITE_LEAVES = ("method", "class")
#: Keys whose value denotes a method/field/type reference.
REFERENCE_KEYS = frozenset({"api", "field", "type", "method", "class"})

_COMPARATORS = {
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    ">": operator.gt,
    "<": operator.lt,
}


class RuleError(ValueError):
    """A rule file is malformed."""


# ---------------------------------------------------------------------------
# evaluation context
# ---------------------------------------------------------------------------


@dataclass
class AppFacts:
    """Manifest and packaging facts, independent of any single method."""

    package: str = ""
    permissions: set[str] = field(default_factory=set)
    intent_actions: set[str] = field(default_factory=set)
    components: list[tuple[str, str]] = field(
        default_factory=list
    )  # (type, special_kind)
    files: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass
class EvalContext:
    """One candidate site: its features plus the app-wide facts."""

    features: MethodFeatures
    facts: AppFacts
    location: str


# ---------------------------------------------------------------------------
# nodes
# ---------------------------------------------------------------------------


class Node:
    """A node of a rule's feature tree."""

    def evaluate(self, ctx: EvalContext) -> tuple[bool, list[Evidence]]:
        raise NotImplementedError

    def register(self, vocab: Vocabulary) -> None:
        """Declare to the bytecode walk what this node needs recorded."""

    def children(self) -> list[Node]:
        return []

    def walk(self) -> Iterator[Node]:
        yield self
        for child in self.children():
            yield from child.walk()

    def describe(self) -> str:
        raise NotImplementedError


@dataclass
class CodeLeaf(Node):
    """Matches a bytecode feature: api, string, field, type or opcode."""

    key: str
    pattern: Pattern

    @property
    def kind(self) -> str:
        return CODE_LEAVES[self.key]

    def register(self, vocab: Vocabulary) -> None:
        vocab.add(self.kind, self.pattern)

    def hits(self, ctx: EvalContext) -> list[Evidence]:
        if self.kind == "opcode":
            count = ctx.features.opcode.get(self.pattern.raw, 0)
            if not count:
                return []
            return [Evidence("opcode", self.pattern.raw, ctx.location)] * min(count, 8)
        return [
            Evidence(self.kind, value, ctx.location, offset)
            for value, offset in ctx.features.hits(self.kind)
            if self.pattern.matches(value)
        ]

    def evaluate(self, ctx: EvalContext) -> tuple[bool, list[Evidence]]:
        found = self.hits(ctx)
        return bool(found), found[:4]

    def describe(self) -> str:
        return f"{self.key}: {self.pattern.raw}"


@dataclass
class FactLeaf(Node):
    """Matches a manifest or packaging fact."""

    key: str
    value: str

    def evaluate(self, ctx: EvalContext) -> tuple[bool, list[Evidence]]:
        found = self._lookup(ctx.facts)
        if not found:
            return False, []
        return True, [Evidence(self.key, hit, "manifest") for hit in found[:4]]

    def _lookup(self, facts: AppFacts) -> list[str]:
        if self.key == "permission":
            return [p for p in facts.permissions if fnmatch.fnmatch(p, self.value)]
        if self.key == "intent_action":
            return [a for a in facts.intent_actions if fnmatch.fnmatch(a, self.value)]
        if self.key == "component":
            wanted_type, _, wanted_kind = self.value.partition(":")
            return [
                f"{ctype}:{kind}" if kind else ctype
                for ctype, kind in facts.components
                if ctype == wanted_type and (not wanted_kind or kind == wanted_kind)
            ]
        if self.key == "file":
            return [f for f in facts.files if fnmatch.fnmatch(f, self.value)]
        if self.key == "native_lib":
            return [f for f in facts.native_libs if fnmatch.fnmatch(f, self.value)]
        if self.key == "metadata":
            wanted_key, sep, wanted_value = self.value.partition("=")
            return [
                f"{k}={v}" if v else k
                for k, v in facts.metadata.items()
                if fnmatch.fnmatch(k, wanted_key)
                and (not sep or fnmatch.fnmatch(v, wanted_value))
            ]
        raise RuleError(f"unknown fact feature: {self.key}")

    def describe(self) -> str:
        return f"{self.key}: {self.value}"


@dataclass
class SiteLeaf(Node):
    """Matches the site under evaluation itself — its method or class name.

    This is how a rule detects an *override* (``method: /->onReceive\\(/``): a
    subclass overriding a framework callback never invokes it, so there is no
    api feature to key on.
    """

    key: str
    pattern: Pattern

    def evaluate(self, ctx: EvalContext) -> tuple[bool, list[Evidence]]:
        target = (
            ctx.location if self.key == "method" else ctx.location.split("->", 1)[0]
        )
        if not self.pattern.matches(target):
            return False, []
        return True, [Evidence(self.key, target, ctx.location)]

    def describe(self) -> str:
        return f"{self.key}: {self.pattern.raw}"


@dataclass
class BoolNode(Node):
    """``and`` / ``or`` / ``n_of`` over child nodes."""

    op: str  # and | or | n_of
    nodes: list[Node]
    n: int = 1

    def register(self, vocab: Vocabulary) -> None:
        for child in self.nodes:
            child.register(vocab)

    def children(self) -> list[Node]:
        return list(self.nodes)

    def evaluate(self, ctx: EvalContext) -> tuple[bool, list[Evidence]]:
        evidence: list[Evidence] = []
        satisfied = 0
        for child in self.nodes:
            ok, child_evidence = child.evaluate(ctx)
            if ok:
                satisfied += 1
                evidence.extend(child_evidence)
            elif self.op == "and":
                return False, []
        if self.op == "and":
            return True, evidence
        if self.op == "or":
            return satisfied > 0, evidence
        return satisfied >= self.n, evidence

    def describe(self) -> str:
        joiner = {"and": " AND ", "or": " OR "}.get(self.op, f" {self.n}-of ")
        return "(" + joiner.join(c.describe() for c in self.nodes) + ")"


@dataclass
class NotNode(Node):
    child: Node

    def register(self, vocab: Vocabulary) -> None:
        self.child.register(vocab)

    def children(self) -> list[Node]:
        return [self.child]

    def evaluate(self, ctx: EvalContext) -> tuple[bool, list[Evidence]]:
        ok, _ = self.child.evaluate(ctx)
        return not ok, []

    def describe(self) -> str:
        return f"NOT {self.child.describe()}"


@dataclass
class CountNode(Node):
    """``count`` over a single code leaf, e.g. ``value: ">=3"``."""

    leaf: CodeLeaf
    comparator: str
    threshold: int

    def register(self, vocab: Vocabulary) -> None:
        self.leaf.register(vocab)

    def children(self) -> list[Node]:
        return [self.leaf]

    def evaluate(self, ctx: EvalContext) -> tuple[bool, list[Evidence]]:
        found = self.leaf.hits(ctx)
        ok = _COMPARATORS[self.comparator](len(found), self.threshold)
        return ok, found[:4] if ok else []

    def describe(self) -> str:
        return f"count({self.leaf.describe()}) {self.comparator} {self.threshold}"


# ---------------------------------------------------------------------------
# rule
# ---------------------------------------------------------------------------


@dataclass
class ReachSpec:
    """Reachability requirement attached to a rule."""

    entrypoints: set[EntryKind] = field(default_factory=set)  # empty = any entry point
    max_hops: int = 8

    def accepts(self, kind: EntryKind, hops: int) -> bool:
        if hops > self.max_hops:
            return False
        return not self.entrypoints or kind in self.entrypoints


@dataclass
class Rule:
    id: str
    name: str
    scope: str
    severity: Severity
    features: Node
    description: str = ""
    attack: list[str] = field(default_factory=list)
    mbc: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    author: str = ""
    weight: float | None = None
    reach: ReachSpec | None = None
    source: Path | None = None

    DEFAULT_WEIGHTS: ClassVar[dict[str, float]] = {
        "high": 20.0,
        "medium": 7.0,
        "low": 2.0,
        "info": 0.5,
    }

    @property
    def base_weight(self) -> float:
        if self.weight is not None:
            return self.weight
        return self.DEFAULT_WEIGHTS[self.severity.value]

    @property
    def needs_every_site(self) -> bool:
        """True when the rule can fire on a site that has no bytecode feature.

        ``method:``/``class:`` rules match a name, so the candidate set cannot be
        narrowed to methods that recorded a vocabulary hit.
        """
        return any(isinstance(node, SiteLeaf) for node in self.features.walk())

    def register(self, vocab: Vocabulary) -> None:
        self.features.register(vocab)


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def parse_node(spec: Any, where: str) -> Node:
    """Build a Node from one YAML mapping."""
    if isinstance(spec, list):
        return BoolNode("and", [parse_node(item, where) for item in spec])
    if not isinstance(spec, dict) or len(spec) != 1:
        raise RuleError(
            f"{where}: each feature must be a single-key mapping, got {spec!r}"
        )

    key, value = next(iter(spec.items()))

    if key in {"and", "or"}:
        if not isinstance(value, list) or not value:
            raise RuleError(f"{where}: '{key}' needs a non-empty list")
        return BoolNode(key, [parse_node(item, where) for item in value])

    if key == "not":
        return NotNode(parse_node(value, where))

    if key == "n_of":
        if not isinstance(value, dict) or "n" not in value or "of" not in value:
            raise RuleError(f"{where}: 'n_of' needs 'n' and 'of'")
        return BoolNode(
            "n_of",
            [parse_node(item, where) for item in value["of"]],
            n=int(value["n"]),
        )

    if key == "count":
        return _parse_count(value, where)

    if key in CODE_LEAVES:
        return CodeLeaf(key, _pattern(key, value))

    if key in SITE_LEAVES:
        return SiteLeaf(key, _pattern(key, value))

    if key in FACT_LEAVES:
        return FactLeaf(key, str(value))

    raise RuleError(f"{where}: unknown feature '{key}'")


def _pattern(key: str, value: Any) -> Pattern:
    return Pattern(
        str(value),
        reference=key in REFERENCE_KEYS,
        substring=key == "substring",
    )


def _parse_count(value: Any, where: str) -> CountNode:
    if not isinstance(value, dict):
        raise RuleError(f"{where}: 'count' needs a mapping")
    spec = {k: v for k, v in value.items() if k != "value"}
    if len(spec) != 1:
        raise RuleError(f"{where}: 'count' needs exactly one feature plus 'value'")
    leaf = parse_node(spec, where)
    if not isinstance(leaf, CodeLeaf):
        raise RuleError(f"{where}: 'count' only supports bytecode features")

    raw = str(value.get("value", ">=1")).strip()
    match = re.match(r"^(>=|<=|==|>|<)?\s*(\d+)$", raw)
    if not match:
        raise RuleError(f"{where}: bad count value {raw!r} (expected e.g. '>=2')")
    return CountNode(leaf, match.group(1) or ">=", int(match.group(2)))


def parse_rule(data: dict[str, Any], source: Path | None = None) -> Rule:
    """Build a Rule from the parsed YAML body of a rule file."""
    body = data.get("rule", data)
    if not isinstance(body, dict):
        raise RuleError(f"{source}: top level must be a 'rule' mapping")
    meta = body.get("meta") or {}
    rule_id = str(meta.get("id", "")).strip()
    where = f"{rule_id or source}"

    if "features" not in body:
        raise RuleError(f"{where}: missing 'features'")
    severity_raw = str(meta.get("severity", "medium")).lower()
    if severity_raw not in {s.value for s in Severity}:
        raise RuleError(f"{where}: bad severity {severity_raw!r}")

    scope = str(meta.get("scope", "method")).lower()
    if scope not in SCOPES:
        raise RuleError(
            f"{where}: bad scope {scope!r} (expected one of {', '.join(SCOPES)})"
        )

    reach = _parse_reach(body.get("reachable_from"), where)
    if reach and scope != "method":
        raise RuleError(
            f"{where}: 'reachable_from' is only meaningful for scope: method"
        )

    return Rule(
        id=rule_id,
        name=str(meta.get("name", rule_id)),
        scope=scope,
        severity=Severity(severity_raw),
        features=parse_node(body["features"], where),
        description=str(meta.get("description", "")).strip(),
        attack=[str(a) for a in meta.get("attack", [])],
        mbc=[str(m) for m in meta.get("mbc", [])],
        references=[str(r) for r in meta.get("references", [])],
        author=str(meta.get("author", "")),
        weight=float(meta["weight"]) if "weight" in meta else None,
        reach=reach,
        source=source,
    )


def _parse_reach(spec: Any, where: str) -> ReachSpec | None:
    if spec is None:
        return None
    if not isinstance(spec, dict):
        raise RuleError(f"{where}: 'reachable_from' must be a mapping")
    kinds: set[EntryKind] = set()
    for name in spec.get("entrypoint", []) or []:
        try:
            kinds.add(EntryKind(str(name)))
        except ValueError as exc:
            valid = ", ".join(k.value for k in EntryKind)
            raise RuleError(
                f"{where}: unknown entrypoint {name!r} (valid: {valid})"
            ) from exc
    return ReachSpec(entrypoints=kinds, max_hops=int(spec.get("max_hops", 8)))


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------


def builtin_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "rules"


def load_rules(paths: list[Path] | None = None) -> list[Rule]:
    """Load rules from files/directories, defaulting to the bundled pack."""
    targets = paths or [builtin_rules_dir()]
    files: list[Path] = []
    for target in targets:
        target = Path(target)
        if target.is_dir():
            files.extend(sorted(target.rglob("*.yml")) + sorted(target.rglob("*.yaml")))
        elif target.exists():
            files.append(target)
        else:
            raise RuleError(f"rule path not found: {target}")

    rules: list[Rule] = []
    for path in sorted(set(files)):
        for document in yaml.safe_load_all(path.read_text()):
            if document:
                rules.append(parse_rule(document, path))

    duplicates = sorted(
        rule_id for rule_id, n in Counter(r.id for r in rules).items() if n > 1
    )
    if duplicates:
        raise RuleError(f"duplicate rule ids: {', '.join(duplicates)}")
    return rules


def vocabulary_for(rules: list[Rule]) -> Vocabulary:
    vocab = Vocabulary()
    for rule in rules:
        rule.register(vocab)
    return vocab


# ---------------------------------------------------------------------------
# linting
# ---------------------------------------------------------------------------


def lint(rule: Rule) -> list[str]:
    """Return a list of problems with a rule's metadata (empty when clean)."""
    problems: list[str] = []
    if not RULE_ID_RE.match(rule.id):
        problems.append(f"id {rule.id!r} does not match TAD-<AREA>-<NNNN>")
    if not rule.name or rule.name == rule.id:
        problems.append("missing 'name'")
    if not rule.description:
        problems.append("missing 'description'")
    if not rule.attack:
        problems.append("missing ATT&CK mapping")
    for technique in rule.attack:
        if not attack.TECHNIQUE_ID_RE.match(technique):
            problems.append(f"malformed ATT&CK id {technique!r}")
        elif not attack.is_known(technique):
            problems.append(f"unknown ATT&CK Mobile technique {technique!r}")
    for identifier in rule.mbc:
        if not attack.MBC_ID_RE.match(identifier):
            problems.append(f"malformed MBC id {identifier!r}")
    for reference in rule.references:
        if not reference.startswith(("http://", "https://")):
            problems.append(f"reference is not a URL: {reference!r}")
    if isinstance(rule.features, BoolNode) and not rule.features.nodes:
        problems.append("empty 'features'")
    return problems


def known_feature_keys() -> set[str]:
    """Every key a rule may use — consumed by the docs and the lint tests."""
    return (
        set(CODE_LEAVES)
        | set(FACT_LEAVES)
        | set(SITE_LEAVES)
        | {"and", "or", "not", "n_of", "count"}
    )
