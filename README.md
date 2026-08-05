# tadori

**Entry-point-aware capability detection for Android APKs.**

`tadori` (辿り — *to trace a path*) answers two questions about an APK at once:

1. **what can this app do?** — YAML rules matched against DEX bytecode, mapped to MITRE ATT&CK for Mobile
2. **what can reach that behaviour?** — the call chain from an entry point (exported receiver, accessibility service, JS bridge, …) down to the matched method

The second question is the point. A capability nothing can trigger is trivia; a capability an outside party can trigger is a finding.

```
TAD-CRED-0001  read notifications, including one-time codes  [HIGH]  T1517
  ↳ Lcom/x/NotifSvc;->onNotificationPosted(…)V
      reachable from <notification_listener> Lcom/x/NotifSvc;->onNotificationPosted(…)V  (direct)
      api        Landroid/service/notification/StatusBarNotification;->getNotification(…) @ 0x14
      string     \d{6} @ 0x3c
      api        Ljava/net/URL;->openConnection(…) @ 0x88
```

---

## Why another Android analyzer

| | tadori | [quark-engine](https://github.com/quark-engine/quark-engine) | [capa](https://github.com/mandiant/capa) | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) |
|---|---|---|---|---|
| Rule-driven capability detection | ✅ YAML | ✅ JSON | ✅ (not for DEX) | partial |
| Matches **across** methods via the call graph | ✅ | ✗ (same method only) | ✗ | ✗ |
| Reports **which entry point** reaches a match | ✅ | ✗ | ✗ | ✗ |
| Distinguishes app code from bundled libraries | ✅ | ✗ | ✗ | ✗ |
| DEX bytecode | ✅ | ✅ | ✗ (native `.so` only) | ✅ |
| ATT&CK Mobile mapping validated in CI | ✅ | partial | ✅ (Enterprise) | ✗ |
| Version-to-version capability diff | ✅ | ✗ | ✗ | ✗ |
| SARIF output | ✅ | ✗ | ✗ | ✗ |

`quark-engine` asks *"do known malicious API sequences appear inside one method?"*.
`tadori` asks *"which capability exists, whose code is it in, and what path leads to it?"*

## Install

```bash
git clone https://github.com/ykus4/tadori.git
cd tadori
uv sync                      # requires uv + Python 3.13+
uv run tadori scan app.apk
```

## Use

```bash
tadori scan app.apk                       # capability report with call paths
tadori scan app.apk -v                    # every site, full chains, ATT&CK names
tadori scan app.apk -f sarif -o out.sarif # GitHub code scanning
tadori scan app.apk -f html -o report.html
tadori scan app.apk --fail-on high        # CI gate

tadori explain TAD-ACCS-0001 app.apk      # why a rule fired (or did not)
tadori rules list                         # what ships in the pack
tadori rules lint                         # validate rule metadata

tadori diff old.apk new.apk               # what did this update gain?
```

Inputs: an `.apk`, a bare `.dex`, or a directory containing `classes*.dex` (plus an
optional `AndroidManifest.xml`, decoded or binary).

### `tadori diff` — the versioning-attack question

An app that was clean at review time can turn hostile in an update. `diff` compares two
builds of the same package and reports what the newer one *gained*:

```
com.example.app  1.4.0 (140)  →  1.5.0 (150)
  score 8 → 46  (+38)
  2 new high-severity capability(ies): TAD-ACCS-0001, TAD-CRED-0001

gained capabilities
  + TAD-ACCS-0001  drive the UI through an accessibility service (high)
  + TAD-CRED-0001  read notifications, including one-time codes (high)

new permissions
  ! android.permission.BIND_ACCESSIBILITY_SERVICE
```

`--fail-on-regression` exits non-zero when a build gains capability or exposure, so this
works as a release gate.

## How it works

```
APK ──▶ manifest + DEX
         │
         ├─▶ one bytecode walk ──▶ feature index (api / string / field / type / opcode)
         │                    └──▶ reverse call graph
         │
         ├─▶ entry points  (manifest components, bind permissions, JS bridges,
         │                  framework callback overrides, static initializers)
         │
         └─▶ rules ──▶ matches ──▶ reverse BFS to an entry point ──▶ score
```

A single walk builds both the feature index and the call graph, which is why a 13 MB,
128k-method APK scans in ~14 s on a laptop — `androguard`'s own cross-reference pass
alone costs more than that.

Design notes: [`docs/design.md`](docs/design.md).

## Rules

One YAML document per rule, grouped by area in [`tadori/rules/`](tadori/rules/):

```yaml
rule:
  meta:
    id: TAD-CRED-0002
    name: intercept incoming SMS messages
    scope: method            # method | class | apk
    severity: high
    attack: [T1636.004, T1582]
    description: Parses the body of an incoming SMS.
    references: ["https://attack.mitre.org/techniques/T1636/004/"]
  features:
    - api: "Landroid/telephony/SmsMessage;->getMessageBody"   # prefix: any descriptor
    - or:
        - permission: android.permission.RECEIVE_SMS
        - intent_action: android.provider.Telephony.SMS_RECEIVED
  reachable_from:
    entrypoint: [exported_receiver, receiver, callback]
    max_hops: 6
```

Features and combinators: [`docs/rules.md`](docs/rules.md). The pack currently covers
accessibility abuse (on-device ATS fraud), overlay phishing, notification and SMS
credential theft, droppers and runtime code loading, C2 channels, collection, analysis
evasion and persistence.

Writing a rule: [`CONTRIBUTING.md`](CONTRIBUTING.md). `tadori rules lint` runs in CI and
rejects unknown ATT&CK ids, duplicate rule ids and missing metadata.

## Honest limitations

- **The score is a capability-risk score, not a malware verdict.** F-Droid 2.0-rc0 — a
  benign app store — scores 43/100 ("suspicious"), because it genuinely installs APKs,
  tracks the foreground app and enumerates packages. Read the evidence, not the number.
- **Library filtering is a heuristic.** Matches inside a curated list of well-known
  libraries (AndroidX, Kotlin, OkHttp, …) are hidden by default and reported as a count;
  `--include-libraries` shows them. Malware naming itself `androidx.work` would hide
  behind this.
- **Call-graph precision is bounded.** Virtual dispatch is resolved through the class
  hierarchy, but signatures shared by many classes (`run()V`) are deliberately *not*
  resolved through — otherwise unrelated components appear connected. Reflection and
  `DexClassLoader` payloads are reported as capabilities, not followed.
- **Packed and native code.** If `TAD-EVAS-0007` or `TAD-NAT-0001` fires, part of the
  behaviour lives outside the DEX and this tool cannot see it.
- **No false-positive benchmark yet.** Per-rule FP rates measured against a benign
  corpus are on the [roadmap](ROADMAP.md), not in this release.

## Scope and intent

For defensive analysis, triage and research — understanding what an app can do, and
proving it with evidence. No malware sample is bundled or downloaded by this project,
and no test requires one.

## License

[MIT](LICENSE)
