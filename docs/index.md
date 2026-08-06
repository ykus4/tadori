# tadori

**Entry-point-aware capability detection for Android APKs.**

`tadori` (辿り — *to trace a path*) matches YAML rules against DEX bytecode and, for every
match, reports the call chain from an entry point down to the matched method.

```
TAD-CRED-0001  read notifications, including one-time codes  [HIGH]  T1517
  ↳ Lcom/x/NotifSvc;->onNotificationPosted(…)V
      reachable from <notification_listener> Lcom/x/NotifSvc;->onNotificationPosted(…)V  (direct)
      api        Landroid/service/notification/StatusBarNotification;->getNotification(…) @ 0x14
      string     \d{6} @ 0x3c
      api        Ljava/net/URL;->openConnection(…) @ 0x88
```

## Quick start

```bash
pip install tadori     # Python 3.13+
tadori scan app.apk
```

## Commands

| command | what it does |
|---|---|
| `tadori scan APP` | capability report; `-f text\|json\|sarif\|html`, `--fail-on high` |
| `tadori explain RULE APP` | why one rule fired, with full call chains |
| `tadori rules list\|show\|lint\|test` | inspect, validate and fixture-test the rule pack |
| `tadori diff OLD NEW` | what a newer build of the same app gained |

Inputs: `.apk`, a bare `.dex`, or a directory of `classes*.dex`.

## Read next

- [Rule pack](rule-pack.md) — all 58 rules, grouped by ATT&CK tactic
- [Writing rules](rules.md) — every feature key, combinator, scope and fixture field
- [Design notes](design.md) — how the single bytecode walk, entry-point discovery and
  reachability analysis work, and where their precision ends
- [Roadmap](ROADMAP.md)

!!! warning "The score is not a verdict"
    tadori reports capability and exposure. A benign app store scores 38/100 because it
    genuinely installs APKs and enumerates packages. Read the evidence and the call
    paths, not the number.
