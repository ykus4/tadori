"""Guardrails for the bundled rule pack.

These run in CI, so a rule with a bad ATT&CK id, a duplicate id or an
unparsable condition cannot be merged.
"""

from __future__ import annotations

import pytest
import yaml

from tadori.core import attack
from tadori.core.rules import (
    SCOPES,
    builtin_rules_dir,
    known_feature_keys,
    lint,
    load_rules,
    vocabulary_for,
)

RULES = load_rules()


def test_the_pack_is_not_empty():
    assert len(RULES) >= 20


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_metadata_is_clean(rule):
    assert lint(rule) == []


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_scope_and_condition_are_usable(rule):
    assert rule.scope in SCOPES
    assert rule.features.describe()
    for technique in rule.attack:
        assert attack.tactics_of(technique), f"{technique} has no tactic"


def test_rule_ids_are_unique():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_file_uses_known_keys():
    """Catches a typo like ``permisson:`` that would otherwise parse as unknown."""
    known = known_feature_keys() | {"n", "of", "value"}
    for path in sorted(builtin_rules_dir().rglob("*.yml")):
        for document in yaml.safe_load_all(path.read_text()):
            for key in _feature_keys(document["rule"]["features"]):
                assert key in known, f"{path.name}: unknown key {key!r}"


def _feature_keys(node) -> set[str]:
    if isinstance(node, list):
        return {key for item in node for key in _feature_keys(item)}
    if isinstance(node, dict):
        keys = set()
        for key, value in node.items():
            keys.add(key)
            keys |= _feature_keys(value)
        return keys
    return set()


def test_vocabulary_is_built_from_the_whole_pack():
    vocab = vocabulary_for(RULES)
    assert len(vocab.api) > 40
    assert len(vocab.string) > 15
    assert vocab.matches(
        "api", "Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;)V"
    )
    assert vocab.matches("string", "api.telegram.org/bot123")


def test_reachability_constraints_only_appear_on_method_scope_rules():
    for rule in RULES:
        if rule.reach is not None:
            assert rule.scope == "method", rule.id
            assert rule.reach.max_hops >= 1


def test_high_severity_rules_carry_a_reference():
    for rule in RULES:
        if rule.severity.value == "high":
            assert rule.references, f"{rule.id} has no reference"
