# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

**tadori** is a static capability-detection CLI for Android APKs. It matches YAML rules
against DEX bytecode and reports, for each match, the call chain from an entry point down
to the matched method. Output: terminal / JSON / SARIF / HTML. Also does a
version-to-version capability diff.

## Commands

Requires [uv](https://docs.astral.sh/uv/). Python 3.13+.

```bash
uv sync                              # install
uv run tadori scan app.apk           # scan
uv run tadori explain TAD-ACCS-0001 app.apk
uv run tadori rules lint             # validate the bundled pack
uv run pytest -q                     # unit tests (no APK needed)
uv run ruff check . && uv run ruff format .
TADORI_TEST_APK=/path/app.apk uv run pytest tests/test_integration.py -q
```

## Architecture

```
tadori/
├── cli.py                 ← click CLI: scan / explain / rules / diff
├── rules/*.yml            ← the bundled rule pack, grouped by area
├── templates/             ← jinja2 HTML report
└── core/
    ├── ingest.py          ← APK / DEX / directory loading, manifest parsing
    ├── features.py        ← ONE bytecode walk: feature index + reverse call graph
    ├── patterns.py        ← Pattern / PatternSet (exact | prefix | substring | regex)
    ├── entrypoints.py     ← entry-point discovery and classification
    ├── graph.py           ← reverse BFS from a match to an entry point
    ├── rules.py           ← YAML rule format: parse, evaluate, lint
    ├── engine.py          ← orchestration: load → index → match → reach → score
    ├── libraries.py       ← app-code vs bundled-library provenance
    ├── score.py           ← transparent weighted score
    ├── diff.py            ← version-to-version capability diff
    ├── report.py          ← text / JSON / SARIF / HTML
    ├── attack.py          ← generated ATT&CK Mobile technique table
    └── models.py          ← Severity, EntryKind, Evidence, CallPath, Match, Capability
```

## Invariants worth preserving

- **One walk.** Do not introduce `Analysis.create_xref()`; it triples load time. Features
  and call edges come from the same instruction pass in `features.py`.
- **Vocabulary-filtered indexing.** Only constants the loaded rules could match are
  stored. A new feature kind must register itself in `Vocabulary`.
- **Entry points are app code.** Library base classes and library callbacks must never be
  entry points (`libraries.is_library`), or reachability becomes meaningless.
- **The polymorphic cut** in `graph.POLYMORPHIC_LIMIT` is load-bearing. Removing it
  fabricates call chains between unrelated components.
- **Score stays explainable.** Every capability carries `score_reason`. No opaque models.
- **No malware in the repo.** No sample is committed or downloaded, and no test requires
  one. Synthetic fixtures only; the real-APK test is opt-in via `TADORI_TEST_APK`.
- **ATT&CK ids are validated.** `attack.py` is generated from the MITRE CTI
  `mobile-attack` STIX bundle; `rules lint` rejects ids outside it.

## Conventions

- Rule ids: `TAD-<AREA>-<NNNN>`, unique across the pack, one YAML document per rule.
- New rules need `description`, `references` (for `high`), and an ATT&CK mapping — CI
  enforces this through `tests/test_builtin_rules.py`.
- Regenerating `core/attack.py` requires the MITRE bundle; keep the module a pure data
  table plus lookups.
- Terminal output shortens references via `report.short_ref`; machine formats always
  carry full references.
