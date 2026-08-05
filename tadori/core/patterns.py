"""Pattern matching shared by the rule engine and the bytecode walk.

A rule writes one string; three forms are understood:

===========================  ===============================================
``/regex/``                  regular expression, searched anywhere in value
``Lcls;->name``              reference prefix — matches any descriptor
``Lcls;->name(...)V``        exact reference (whitespace-insensitive)
===========================  ===============================================

String features additionally support ``substring`` matching.
"""

from __future__ import annotations

import re

_WHITESPACE = re.compile(r"\s+")


def normalize(value: str) -> str:
    """Canonical reference form: whitespace removed.

    androguard renders descriptors with spaces in some code paths and without
    them in others, so every reference is normalized on both sides.
    """
    return _WHITESPACE.sub("", value)


class Pattern:
    """One pattern from a rule.

    ``reference`` marks patterns that denote a method/field/type reference: for
    those, a pattern without a descriptor (``(`` for methods, ``:`` for fields)
    is a prefix match, so rules need not spell out full signatures.
    """

    __slots__ = ("raw", "form", "_needle", "_regex")

    def __init__(
        self, raw: str, *, reference: bool = False, substring: bool = False
    ) -> None:
        self.raw = raw
        self._regex: re.Pattern[str] | None = None
        self._needle = raw

        if len(raw) >= 2 and raw.startswith("/") and raw.endswith("/"):
            self.form = "regex"
            self._regex = re.compile(raw[1:-1])
        elif substring:
            self.form = "substring"
        elif reference and "(" not in raw and ":" not in raw:
            self.form = "prefix"
            self._needle = normalize(raw)
        else:
            self.form = "exact"
            self._needle = normalize(raw) if reference else raw

    @property
    def needle(self) -> str:
        return self._needle

    def matches(self, value: str) -> bool:
        if self.form == "exact":
            return value == self._needle
        if self.form == "prefix":
            return value.split("(", 1)[0].split(":", 1)[0] == self._needle
        if self.form == "substring":
            return self._needle in value
        assert self._regex is not None
        return self._regex.search(value) is not None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Pattern({self.raw!r}, form={self.form})"


class PatternSet:
    """``any(p.matches(value) for p in patterns)`` with the cheap cases first."""

    __slots__ = ("_exact", "_prefix", "_slow")

    def __init__(self) -> None:
        self._exact: set[str] = set()
        self._prefix: set[str] = set()
        self._slow: list[Pattern] = []

    def add(self, pattern: Pattern) -> None:
        if pattern.form == "exact":
            self._exact.add(pattern.needle)
        elif pattern.form == "prefix":
            self._prefix.add(pattern.needle)
        else:
            self._slow.append(pattern)

    def matches(self, value: str) -> bool:
        if value in self._exact:
            return True
        if self._prefix and value.split("(", 1)[0].split(":", 1)[0] in self._prefix:
            return True
        return any(p.matches(value) for p in self._slow)

    def __bool__(self) -> bool:
        return bool(self._exact or self._prefix or self._slow)

    def __len__(self) -> int:
        return len(self._exact) + len(self._prefix) + len(self._slow)
