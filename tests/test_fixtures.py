"""Run the bundled rule fixtures as part of the test suite.

Each fixture is a synthetic app that pins one rule's behaviour, so a rule change
that breaks an expectation fails CI with the fixture's own name.
"""

from __future__ import annotations

import pytest

from tadori.core import fixtures
from tadori.core.rules import load_rules

RULES = load_rules()
FIXTURES = fixtures.load_fixtures()
BY_ID = {rule.id: rule for rule in RULES}


def test_fixtures_reference_existing_rules():
    fixtures.require_known_rules(FIXTURES, RULES)


@pytest.mark.parametrize(
    "fixture", FIXTURES, ids=lambda f: f"{f.rule_id}-{f.expect}-{f.name[:40]}"
)
def test_fixture(fixture):
    outcome = fixtures.run(fixture, BY_ID)
    assert outcome.passed, outcome.detail


def test_every_rule_has_a_positive_fixture():
    _, uncovered = fixtures.run_all(FIXTURES, RULES)
    assert not uncovered, f"rules without a positive fixture: {sorted(uncovered)}"


def test_the_pack_has_negative_fixtures_too():
    """Precision guards, not just 'does it fire at all'."""
    negatives = [f for f in FIXTURES if not f.should_match]
    assert len(negatives) >= 15


def test_bad_fixture_file_is_rejected(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("fixture:\n  name: nameless\n")
    with pytest.raises(fixtures.FixtureError, match="missing 'rule'"):
        fixtures.load_fixtures([bad])

    bad.write_text("fixture:\n  name: x\n  rule: TAD-X-0001\n  expect: maybe\n")
    with pytest.raises(fixtures.FixtureError, match="bad expect"):
        fixtures.load_fixtures([bad])


def test_fixture_naming_a_missing_rule_fails_loudly():
    ghost = fixtures.Fixture(name="ghost", rule_id="TAD-NOPE-9999")
    outcome = fixtures.run(ghost, BY_ID)
    assert not outcome.passed
    assert "no such rule" in outcome.detail
