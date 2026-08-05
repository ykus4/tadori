"""Transparent capability-risk scoring.

The score is a plain weighted sum, and every capability carries the sentence
that explains its own contribution. That is deliberate: a number nobody can
reconstruct is not evidence, and this tool is meant to be arguable.

Not a malware probability. It answers "how much attack-relevant capability is
present, and how exposed is it?".
"""

from __future__ import annotations

from tadori.core.models import Capability, ScanResult

MAX_SCORE = 100.0

#: How much of a rule's weight survives, given how the match is reachable.
REACH_FACTORS = {
    "remote": 1.0,  # triggerable from outside the app
    "declared": 1.0,  # class/apk scope — a fact, not a code path
    "local": 0.8,  # reachable, but only from internal entry points
    "unknown": 0.5,  # reachability was not computed
    "unreachable": 0.25,  # no path found (dead code, reflection-only, packed)
}

#: Repeated hits of the same capability add little; later ones are damped.
REPEAT_FACTOR = 0.08
MAX_REPEAT_BONUS = 0.4

#: Calibrated so that a benign app that legitimately holds strong capabilities
#: (an app store, a launcher, a security tool) lands in "notable" or
#: "suspicious", and only a stack of high-severity, externally reachable
#: capabilities reaches the top band.
VERDICTS = (
    (70.0, "malicious-capability profile"),
    (45.0, "strongly suspicious"),
    (25.0, "suspicious"),
    (8.0, "notable capabilities"),
    (0.0, "nothing notable"),
)


def apply(result: ScanResult) -> None:
    """Fill in ``score_contribution`` / ``score_reason`` and the total score."""
    total = 0.0
    for capability in result.capabilities:
        contribution, reason = _contribution(capability)
        capability.score_contribution = contribution
        capability.score_reason = reason
        total += contribution

    result.score = min(round(total, 1), MAX_SCORE)
    result.verdict = verdict_for(result.score)


def verdict_for(score: float) -> str:
    for threshold, label in VERDICTS:
        if score >= threshold:
            return label
    return VERDICTS[-1][1]


def _contribution(capability: Capability) -> tuple[float, str]:
    from tadori.core.rules import Rule

    base = Rule.DEFAULT_WEIGHTS[capability.severity.value]
    exposure = _exposure(capability)
    factor = REACH_FACTORS[exposure]

    extra_sites = len(capability.reachable_matches) - 1
    repeat = min(max(extra_sites, 0) * REPEAT_FACTOR, MAX_REPEAT_BONUS)

    contribution = base * factor * (1 + repeat)
    reason = (
        f"{capability.severity.value} ({base:g}) x {exposure} reach ({factor:g})"
        + (f" x {1 + repeat:.2f} for {extra_sites} extra site(s)" if repeat else "")
    )
    return round(contribution, 2), reason


def _exposure(capability: Capability) -> str:
    """Strongest exposure across the capability's matches."""
    if capability.scope != "method":
        # A manifest fact or a whole-class pattern has no single call site to
        # trace; it is either present or absent.
        return "declared"

    best = "unreachable"
    for match in capability.matches:
        if match.reachable is None:
            best = _stronger(best, "unknown")
            continue
        path = match.best_path
        if path is None:
            best = _stronger(best, "unreachable")
        elif path.entry.kind.is_remote:
            return "remote"
        else:
            best = _stronger(best, "local")
    return best


_ORDER = ("unreachable", "unknown", "local", "declared", "remote")


def _stronger(left: str, right: str) -> str:
    return left if _ORDER.index(left) >= _ORDER.index(right) else right
