# Roadmap

## 0.1.0 — current

Engine, rule format, reachability, scoring, four output formats, `diff`, 41 rules.

## Next: rule coverage and a false-positive benchmark

The pack needs to roughly double, and every rule needs a measured false-positive rate
before the numbers can be taken seriously.

- [ ] grow the pack to 50–60 rules (remote access / VNC modules, geofencing guardrails,
      call interception, crypto-clipper address rewriting, Play Integrity evasion,
      `QUERY_ALL_PACKAGES` target-list checks, archive-then-exfiltrate)
- [ ] per-rule fixtures: one smali positive and one near-miss negative per rule,
      assembled in CI with the `smali` assembler, exercised through `tadori scan --dex`
- [ ] false-positive benchmark: scan 200–300 F-Droid APKs, publish a per-rule FP table in
      the README, and re-calibrate severities and score bands against it
- [ ] `tadori rules test` — run the fixture corpus from the CLI

## After that

- [ ] PyPI release and a GitHub Action wrapper (`tadori scan` → SARIF upload,
      `tadori diff` → PR comment)
- [ ] documentation site (mkdocs-material, `ykus4.github.io/tadori`)
- [ ] native `.so` capability features via `lief` (imports, symbols) so that
      `TAD-NAT-0001` stops being a dead end
- [ ] MBC (Malware Behavior Catalog) mappings alongside ATT&CK — the field exists and is
      format-validated, but is intentionally left empty until the mappings are checked
- [ ] resolve simple reflection (`Class.forName` on a constant) into real call edges
- [ ] library provenance from a fingerprint database rather than a prefix list
- [ ] optional per-rule suppression file for CI use

## Not planned

- Dynamic analysis. Use [`enma`](https://github.com/ykus4/enma) (Frida) or
  [`shingan`](https://github.com/ykus4/shingan) (which covers the *defensive* side:
  auditing your own app against OWASP MASVS).
- A malware/benign classifier. tadori reports capability and exposure; the verdict is the
  analyst's.
- Bundling or downloading malware samples.
