# Contributing

The rule pack is the part of this project that benefits most from other people, so rule
PRs are the most welcome kind.

## Setup

```bash
uv sync
uv run pre-commit install
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
```

Optional end-to-end run against an APK you already have:

```bash
TADORI_TEST_APK=/path/to/benign.apk uv run pytest tests/test_integration.py -q
```

## Writing a rule

1. Pick the area file in `tadori/rules/` (or add one) and append a `---` document.
2. Take the next free id in that area: `TAD-<AREA>-<NNNN>`.
3. Write the condition. Prefer prefix `api:` patterns over full signatures — they survive
   SDK changes. See [`docs/rules.md`](docs/rules.md) for every feature key.
4. Add `reachable_from` when the capability only matters from certain entry points.
5. Validate:

   ```bash
   uv run tadori rules lint
   uv run pytest tests/test_builtin_rules.py -q
   ```

6. Try it on a real app and read the call paths:

   ```bash
   uv run tadori explain TAD-YOUR-0001 some.apk
   ```

### What makes a good rule

- **Name a behaviour, not an API.** "read notifications, including one-time codes" beats
  "calls getNotification".
- **Say what benign looks like** in `description`. Every capability in this pack has a
  legitimate user; the description is where an analyst learns to tell them apart.
- **Require corroboration.** A single ubiquitous API is a bad rule. Pair it with a
  permission, a manifest fact, a second API, or an entry-point constraint — that is what
  `and` / `n_of` / `count` are for.
- **Set severity by consequence, not by suspicion.** `high` is for capabilities that
  directly enable account takeover, credential theft or unremovability.
- **Map to ATT&CK Mobile.** CI rejects ids that are not in the matrix.
- **Check it against a benign app first.** If a well-known app trips your rule, either
  tighten it or explain the benign case in the description and drop the severity.

### Anti-patterns

- A rule that fires on one string that any app might contain.
- `severity: high` with no reference and no reachability constraint.
- Duplicating an existing rule with a different API in the same `or` — extend the
  existing one instead.

## Changing the engine

- Keep public behaviour covered by a synthetic fixture; do not add sample APKs to the
  repository, and do not add tests that require a malware sample.
- If you change matching or reachability semantics, say so in `docs/design.md` — the
  precision trade-offs there are the reason people can trust the output.
- Run a scan on a real app before and after: a change that alters the score of a known
  benign app is worth mentioning in the PR.

## Reporting a problem

For a false positive or a wrong call path, the most useful report includes the rule id,
the package, and the output of:

```bash
uv run tadori explain TAD-XXXX-NNNN app.apk
```

Please do not attach malware samples to issues; a hash and the `explain` output are
enough.
