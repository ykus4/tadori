"""Rule parsing, evaluation and linting."""

from __future__ import annotations

import pytest
import yaml

from tadori.core.models import EntryKind, Severity
from tadori.core.rules import AppFacts, RuleError, lint, parse_node, parse_rule
from tests.conftest import context, features


def node(spec: str):
    return parse_node(yaml.safe_load(spec), "test")


# ---------------------------------------------------------------------------
# leaves
# ---------------------------------------------------------------------------


def test_api_leaf_matches_prefix_without_descriptor():
    leaf = node("api: 'Landroid/telephony/SmsManager;->sendTextMessage'")
    ctx = context(
        features(
            api=["Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;)V"]
        )
    )
    ok, evidence = leaf.evaluate(ctx)
    assert ok
    assert evidence[0].kind == "api"
    assert evidence[0].offset == 0


def test_api_leaf_requires_exact_match_with_descriptor():
    leaf = node("api: 'Lcom/x/A;->f(I)V'")
    assert not leaf.evaluate(context(features(api=["Lcom/x/A;->f(J)V"])))[0]
    assert leaf.evaluate(context(features(api=["Lcom/x/A;->f(I)V"])))[0]


def test_field_prefix_matches_any_type():
    leaf = node("field: 'Landroid/os/Build;->FINGERPRINT'")
    assert leaf.evaluate(
        context(features(field=["Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;"]))
    )[0]


def test_string_modes():
    exact = node("string: 'https://c2.example'")
    substring = node("substring: 'telegram.org'")
    regex = node(r"regex: '/^\d{6}$/'")
    ctx = context(
        features(string=["https://c2.example", "api.telegram.org/bot123", "123456"])
    )
    assert exact.evaluate(ctx)[0]
    assert substring.evaluate(ctx)[0]
    assert regex.evaluate(ctx)[0]
    assert not node("string: 'telegram.org'").evaluate(ctx)[0]  # exact, not substring


def test_opcode_leaf_counts():
    leaf = node("opcode: 'invoke-virtual'")
    assert leaf.evaluate(context(features(opcode={"invoke-virtual": 3})))[0]
    assert not leaf.evaluate(context(features(opcode={"invoke-static": 3})))[0]


def test_site_leaf_matches_method_and_class():
    method_leaf = node(r"method: '/->onReceive\(/'")
    class_leaf = node("class: 'Lcom/x/A;'")
    ctx = context(location="Lcom/x/A;->onReceive(Landroid/content/Context;)V")
    assert method_leaf.evaluate(ctx)[0]
    assert class_leaf.evaluate(ctx)[0]
    assert not class_leaf.evaluate(context(location="Lcom/y/B;->onReceive()V"))[0]


# ---------------------------------------------------------------------------
# facts
# ---------------------------------------------------------------------------


def test_fact_leaves_read_manifest():
    facts = AppFacts(
        permissions={"android.permission.RECEIVE_SMS"},
        intent_actions={"android.provider.Telephony.SMS_RECEIVED"},
        components=[("service", "accessibility_service"), ("activity", "")],
        files=["assets/payload.dex"],
        native_libs=["lib/arm64-v8a/libjiagu.so"],
        metadata={"android.accessibilityservice": "@xml/config"},
    )
    ctx = context(facts=facts)
    for spec in (
        "permission: android.permission.RECEIVE_SMS",
        "permission: 'android.permission.*_SMS'",
        "intent_action: android.provider.Telephony.SMS_RECEIVED",
        "component: 'service:accessibility_service'",
        "component: activity",
        "file: 'assets/*.dex'",
        "native_lib: '*libjiagu*'",
        "metadata: android.accessibilityservice",
    ):
        assert node(spec).evaluate(ctx)[0], spec
    assert not node("permission: android.permission.CAMERA").evaluate(ctx)[0]
    assert not node("component: 'service:notification_listener'").evaluate(ctx)[0]


# ---------------------------------------------------------------------------
# combinators
# ---------------------------------------------------------------------------


def test_and_or_not():
    ctx = context(features(api=["Lcom/x/A;->f()V"]))
    assert node("and: [{api: 'Lcom/x/A;->f'}]").evaluate(ctx)[0]
    assert not node("and: [{api: 'Lcom/x/A;->f'}, {api: 'Lcom/x/A;->g'}]").evaluate(
        ctx
    )[0]
    assert node("or: [{api: 'Lcom/x/A;->g'}, {api: 'Lcom/x/A;->f'}]").evaluate(ctx)[0]
    assert node("not: {api: 'Lcom/x/A;->g'}").evaluate(ctx)[0]
    assert not node("not: {api: 'Lcom/x/A;->f'}").evaluate(ctx)[0]


def test_top_level_list_is_implicit_and():
    ctx = context(features(api=["Lcom/x/A;->f()V"], string=["boom"]))
    assert node("[{api: 'Lcom/x/A;->f'}, {string: boom}]").evaluate(ctx)[0]
    assert not node("[{api: 'Lcom/x/A;->f'}, {string: nope}]").evaluate(ctx)[0]


def test_n_of():
    ctx = context(features(string=["a", "b"]))
    assert node("n_of: {n: 2, of: [{string: a}, {string: b}, {string: c}]}").evaluate(
        ctx
    )[0]
    assert not node(
        "n_of: {n: 3, of: [{string: a}, {string: b}, {string: c}]}"
    ).evaluate(ctx)[0]


def test_count():
    ctx = context(features(api=["Lcom/x/A;->f()V", "Lcom/x/A;->f()V"]))
    assert node("count: {api: 'Lcom/x/A;->f', value: '>=2'}").evaluate(ctx)[0]
    assert not node("count: {api: 'Lcom/x/A;->f', value: '>=3'}").evaluate(ctx)[0]
    assert node("count: {api: 'Lcom/x/A;->f', value: '==2'}").evaluate(ctx)[0]


def test_evidence_is_only_collected_from_satisfied_branches():
    ctx = context(features(api=["Lcom/x/A;->f()V"], string=["seen"]))
    ok, evidence = node("or: [{api: 'Lcom/x/A;->missing'}, {string: seen}]").evaluate(
        ctx
    )
    assert ok
    assert [e.value for e in evidence] == ["seen"]


# ---------------------------------------------------------------------------
# rule bodies
# ---------------------------------------------------------------------------


RULE_YAML = """
rule:
  meta:
    id: TAD-TEST-0001
    name: test rule
    scope: method
    severity: high
    attack: [T1516]
    description: a description
    references: ["https://example.com"]
  features:
    - api: "Lcom/x/A;->f"
  reachable_from:
    entrypoint: [exported_receiver]
    max_hops: 3
"""


def test_parse_rule():
    rule = parse_rule(yaml.safe_load(RULE_YAML))
    assert rule.id == "TAD-TEST-0001"
    assert rule.severity is Severity.HIGH
    assert rule.reach is not None
    assert rule.reach.entrypoints == {EntryKind.EXPORTED_RECEIVER}
    assert rule.reach.accepts(EntryKind.EXPORTED_RECEIVER, 3)
    assert not rule.reach.accepts(EntryKind.EXPORTED_RECEIVER, 4)
    assert not rule.reach.accepts(EntryKind.SERVICE, 1)
    assert lint(rule) == []


def test_reach_spec_without_kinds_accepts_any_entry():
    body = yaml.safe_load(RULE_YAML)
    body["rule"]["reachable_from"] = {"max_hops": 2}
    rule = parse_rule(body)
    assert rule.reach.accepts(EntryKind.STATIC_INIT, 2)


def test_needs_every_site_only_for_name_matching_rules():
    body = yaml.safe_load(RULE_YAML)
    assert not parse_rule(body).needs_every_site
    body["rule"]["features"] = [{"method": "/->onReceive\\(/"}]
    assert parse_rule(body).needs_every_site


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"scope": "package"}, "bad scope"),
        ({"severity": "critical"}, "bad severity"),
    ],
)
def test_bad_meta_is_rejected(mutation, message):
    body = yaml.safe_load(RULE_YAML)
    body["rule"]["meta"].update(mutation)
    with pytest.raises(RuleError, match=message):
        parse_rule(body)


def test_reachable_from_rejected_outside_method_scope():
    body = yaml.safe_load(RULE_YAML)
    body["rule"]["meta"]["scope"] = "apk"
    with pytest.raises(RuleError, match="only meaningful for scope: method"):
        parse_rule(body)


def test_unknown_entrypoint_is_rejected():
    body = yaml.safe_load(RULE_YAML)
    body["rule"]["reachable_from"]["entrypoint"] = ["telepathy"]
    with pytest.raises(RuleError, match="unknown entrypoint"):
        parse_rule(body)


def test_unknown_feature_key_is_rejected():
    with pytest.raises(RuleError, match="unknown feature"):
        node("smell: bad")


def test_bad_count_value_is_rejected():
    with pytest.raises(RuleError, match="bad count value"):
        node("count: {api: 'Lcom/x/A;->f', value: 'many'}")


def test_lint_reports_metadata_problems():
    rule = parse_rule(
        {
            "rule": {
                "meta": {
                    "id": "BAD-0001",
                    "severity": "low",
                    "attack": ["T9999", "nope"],
                    "references": ["not-a-url"],
                },
                "features": [{"api": "Lcom/x/A;->f"}],
            }
        }
    )
    problems = " | ".join(lint(rule))
    assert "does not match" in problems
    assert "unknown ATT&CK Mobile technique 'T9999'" in problems
    assert "malformed ATT&CK id 'nope'" in problems
    assert "reference is not a URL" in problems
    assert "missing 'description'" in problems


# ---------------------------------------------------------------------------
# why-not diagnostics
# ---------------------------------------------------------------------------


def trace_of(spec, ctx):
    return parse_node(spec, "test").trace(ctx)


def test_trace_marks_each_branch_of_an_and():
    node = [{"api": "Lcom/x/A;->f"}, {"permission": "android.permission.RECEIVE_SMS"}]
    trace = trace_of(node, context(features(api=["Lcom/x/A;->f()V"])))

    assert not trace.satisfied
    assert trace.kind == "all"
    assert [c.satisfied for c in trace.children] == [True, False]
    assert trace.satisfied_leaves == 1


def test_missing_ignores_alternatives_of_a_satisfied_or():
    node = [
        {"or": [{"api": "Lcom/x/A;->f"}, {"api": "Lcom/x/B;->g"}]},
        {"permission": "android.permission.READ_SMS"},
    ]
    trace = trace_of(node, context(features(api=["Lcom/x/A;->f()V"])))
    assert trace.missing == ["permission: android.permission.READ_SMS"]


def test_missing_of_a_failed_or_lists_the_alternatives_once():
    node = {"or": [{"api": "Lcom/x/A;->f"}, {"api": "Lcom/x/B;->g"}]}
    trace = trace_of(node, context(features(api=["Lcom/x/Z;->z()V"])))
    assert len(trace.missing) == 1
    assert "one of (" in trace.missing[0]
    assert "Lcom/x/A;->f" in trace.missing[0] and "Lcom/x/B;->g" in trace.missing[0]


def test_missing_of_a_negation_says_what_must_not_hold():
    node = {"not": {"api": "Lcom/x/A;->f"}}
    trace = trace_of(node, context(features(api=["Lcom/x/A;->f()V"])))
    assert trace.missing == ["api: Lcom/x/A;->f must NOT hold"]


def test_a_satisfied_condition_is_missing_nothing():
    node = [{"api": "Lcom/x/A;->f"}]
    trace = trace_of(node, context(features(api=["Lcom/x/A;->f()V"])))
    assert trace.satisfied and trace.missing == []


def test_count_trace_reports_how_many_were_found():
    node = {"count": {"api": "Lcom/x/A;->f", "value": ">=3"}}
    trace = trace_of(node, context(features(api=["Lcom/x/A;->f()V"] * 2)))
    assert not trace.satisfied
    assert "found 2" in trace.description
    assert trace.children == ()


# ---------------------------------------------------------------------------
# manifest exposure facts
# ---------------------------------------------------------------------------


def facts_with(**kwargs) -> AppFacts:
    return AppFacts(**kwargs)


def evaluate(spec, facts):
    return parse_node(spec, "test").evaluate(context(facts=facts))


def test_exported_leaf_matches_an_unprotected_component():
    facts = facts_with(
        exported=[
            ("provider", "com.x.Files", ""),
            ("provider", "com.x.Guarded", "com.x.permission.READ"),
        ]
    )
    ok, evidence = evaluate({"exported": "provider:unprotected"}, facts)
    assert ok
    assert [e.value for e in evidence] == ["provider com.x.Files"]


def test_exported_leaf_can_ask_for_the_guarded_ones():
    facts = facts_with(
        exported=[("provider", "com.x.Guarded", "com.x.permission.READ")]
    )
    assert evaluate({"exported": "provider:unprotected"}, facts)[0] is False
    assert evaluate({"exported": "provider:protected"}, facts)[0] is True
    assert evaluate({"exported": "provider"}, facts)[0] is True


def test_exported_leaf_is_typed():
    facts = facts_with(exported=[("activity", "com.x.Main", "")])
    assert evaluate({"exported": "provider"}, facts)[0] is False
    assert evaluate({"exported": "*:unprotected"}, facts)[0] is True


def test_manifest_flag_matches_name_and_value():
    facts = facts_with(flags={"debuggable": "true", "allowBackup": "false"})
    assert evaluate({"manifest": "debuggable=true"}, facts)[0] is True
    assert evaluate({"manifest": "allowBackup=true"}, facts)[0] is False
    assert evaluate({"manifest": "debuggable"}, facts)[0] is True
    assert evaluate({"manifest": "usesCleartextTraffic=true"}, facts)[0] is False


def test_manifest_flag_evidence_carries_the_value():
    facts = facts_with(flags={"debuggable": "true"})
    _, evidence = evaluate({"manifest": "debuggable=*"}, facts)
    assert [e.value for e in evidence] == ["debuggable=true"]
