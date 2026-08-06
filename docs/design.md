# Design notes

## The problem with match-only detection

Given a rule "sends SMS", a matcher can tell you `SmsManager.sendTextMessage` appears in
`Lcom/x/A;->f()V`. That is not enough to act on. An analyst still has to answer: is that
the app's own code or a bundled SDK's? Can anything actually call it? What triggers it —
a user tap, a push message, an accessibility event?

tadori answers those alongside the match, because they are what turn a hit into a
finding.

## One walk, two structures

`tadori.core.features.build_index` walks every internal method once and produces:

- **a feature index** — for each method, the invoked APIs, string / field / type
  constants and opcode counts that the loaded rules could possibly match. The rule pack
  is compiled into a `Vocabulary` first, so irrelevant constants are never stored.
- **a reverse call graph** — `callee -> {callers}`, restricted to callees whose class is
  the app's own or a type the app extends.

We deliberately do **not** use `androguard`'s `Analysis.create_xref()`. On a 13 MB APK it
roughly triples load time (≈7 s parse → ≈18 s with xrefs) and produces cross-references
we would mostly discard. Operands are read directly:
`(kind, index, string)` with `Operand.KIND == 0x100` and the low byte being
`METH | STRING | FIELD | TYPE`.

Bytecode offsets come from accumulating `instruction.get_length()`, so every piece of
evidence can point at `@ 0x14`.

## Entry points

Reachability needs a definition of "outside". tadori derives entry points from:

- **manifest components**, with Android's own `exported` default (an intent filter
  implies exported unless the attribute says otherwise)
- **bind permissions**, which reveal a component's framework role —
  `BIND_ACCESSIBILITY_SERVICE` makes a service an `accessibility_service`, and that is a
  *remote* entry point because the framework drives it with events from other apps
- **inherited methods** of an app-internal base class, so a component that does not
  override `onCreate` is still entered through its own base class's `onCreate`
- **JavaScript bridges** — classes passed to `addJavascriptInterface`, found by looking
  at the types referenced in the method that makes that call
- **framework callback overrides** — an app class extending an `android.*` type and
  declaring a known callback name
- **static initializers**

Two exclusions matter. Base classes that belong to bundled libraries
(`androidx.activity.ComponentActivity`) are *not* expanded: every activity shares them,
so treating their methods as entry points makes half the app look externally
triggerable. And a callback inside a library is a step on a path, not the start of one.

## Reachability

`graph.find_paths` does a reverse BFS from the matched method, classifying each visited
node. The first time an entry-point *kind* is reached, that chain is recorded — BFS
order means it is a shortest chain for that kind. Paths are ranked remote-first, then by
hop count.

Virtual dispatch is handled by class-hierarchy analysis: a call emitted against
`Lsuper;->m()` also reaches `Lsub;->m()`. That resolution is skipped when a signature is
declared by more than `POLYMORPHIC_LIMIT` (4) internal methods. Without the cut,
`Runnable.run()V` and lifecycle-observer callbacks collapse into single nodes and the
tool starts reporting chains between components that never call each other — which we
observed and fixed while calibrating against a real app.

This is a sound-ish over-approximation, not a proof: no points-to analysis, no
reflection resolution, no native code.

## App code versus bundled libraries

A released APK is mostly other people's code. AndroidX calls
`setComponentEnabledSetting`, WorkManager enumerates packages, Kotlin reflects into
hidden APIs. Attributing those to the app makes every real app look hostile — the first
calibration run scored F-Droid 100/100.

So every match carries a provenance (`app` / `library`) derived from a curated prefix
list, and library matches are hidden by default with the hidden count reported. The
trade-off is explicit: malware named `androidx.work` would be shielded, which is why
`--include-libraries` exists.

## Scoring

A weighted sum, and nothing more:

```
contribution = severity weight × reach factor × (1 + damped repeat bonus)
```

Every capability stores the sentence that explains its own contribution, so a total can
always be taken apart. The bands are calibrated so an app store or a security tool —
which legitimately hold strong capabilities — lands in "notable"/"suspicious", and only
a stack of high-severity, externally reachable capabilities reaches the top band.

The score is not a probability and does not pretend to be. Per-rule false-positive rates
against a benign corpus are the next calibration step (see ROADMAP).

## Testing without samples

No sample of any kind is bundled or downloaded. Everything is synthetic:

- fake `androguard` objects (`tests/test_features.py`) exercise operand decoding, offset
  accumulation, call-edge filtering and JS-bridge detection
- synthetic call graphs (`tests/test_graph.py`) exercise path recovery, hop limits,
  virtual dispatch and the polymorphic cut
- text manifests (`tests/test_ingest.py`) exercise component parsing and entry kinds
- the bundled pack is linted in CI (`tests/test_builtin_rules.py`)

**Rule fixtures** (`tadori/fixtures/`) carry the rule pack. A fixture is a synthetic app
described in YAML — methods, features, call edges, manifest — plus the expectation that
one rule fires or does not. `tadori.core.fixtures` turns that into an
`engine.Subject`, the same object `scan` builds from an APK, so a fixture exercises the
real matcher, the real entry-point discovery and the real reachability analysis; only
DEX decoding is bypassed. CI requires a positive fixture for every rule.

That refactor — `scan` = ingest + index + `analyze(Subject, …)` — exists precisely so
that rule tests cannot drift away from what a scan does.

`tests/test_integration.py` runs a full scan when `TADORI_TEST_APK` points at any APK you
have locally, and `scripts/fp_bench.py` measures per-rule hit rates over a corpus you
supply. Neither is required, and neither ships data.
