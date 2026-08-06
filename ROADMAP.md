# Roadmap

## 0.1.0 — current

Engine (single bytecode walk, entry-point discovery, reachability, library provenance,
transparent scoring), four output formats, `scan` / `explain` / `rules` / `diff`,
**58 rules** with **78 fixtures**, a GitHub Action, and release/docs automation.

## Next

- [ ] **Published false-positive numbers.** `scripts/fp_bench.py` measures per-rule hit
      rates over a corpus, but this project bundles and downloads no APKs, so no corpus
      run is published. Someone running it over a few hundred apps they already trust
      would turn the current severity weights from "argued" into "measured".
- [ ] grow the pack past 80 rules — the obvious gaps are crypto-wallet targeting,
      accessibility-driven permission auto-granting, SIM-swap and eSIM abuse, and
      abuse of the new Android 15/16 background restrictions
- [ ] native `.so` capability features via `lief` (imports, symbols) so `TAD-NAT-0001`
      stops being a dead end
- [ ] resolve simple reflection (`Class.forName` on a constant) into real call edges
- [ ] MBC (Malware Behavior Catalog) mappings alongside ATT&CK — the field exists and is
      format-validated, but stays empty until the mappings are checked by hand
- [ ] library provenance from a fingerprint database rather than a prefix list
- [ ] per-rule suppression file for CI use
- [ ] `tadori diff` as a PR comment in the GitHub Action, not just a job summary

## Not planned

- Dynamic analysis. Use [`enma`](https://github.com/ykus4/enma) (Frida) or
  [`shingan`](https://github.com/ykus4/shingan) (which covers the *defensive* side:
  auditing your own app against OWASP MASVS).
- A malware/benign classifier. tadori reports capability and exposure; the verdict is the
  analyst's.
- Bundling or downloading samples of any kind — including benign corpora. Rules are
  developed against synthetic fixtures.
