# Rule reference

A rule file is YAML. One document per rule; several documents may share a file
(`---` separated), which is how the bundled pack groups rules by area.

```yaml
rule:
  meta:
    id: TAD-AREA-0001        # TAD-<AREA>-<NNNN>, unique across the pack
    name: short imperative phrase
    scope: method            # method | class | apk
    severity: high           # high | medium | low | info
    attack: [T1516]          # MITRE ATT&CK for Mobile, validated against the matrix
    mbc: []                  # optional Malware Behavior Catalog ids
    description: >
      What this means, and what a benign explanation would look like.
    references: ["https://attack.mitre.org/techniques/T1516/"]
    weight: 12               # optional score override; defaults come from severity
  features:
    - api: "Lcom/x/A;->f"
  reachable_from:            # optional, scope: method only
    entrypoint: [exported_receiver]
    max_hops: 6
```

The top-level `features` list is an implicit `and`.

## Scope

| scope | evaluated against | reachability |
|---|---|---|
| `method` | one method's features | yes — a call path is searched |
| `class` | the union of every method in a class | no |
| `apk` | the union of the whole app, plus manifest facts | no |

Use `class` when a capability is a *combination* spread over several methods of one
class (decrypt here, load there). Use `apk` for manifest and packaging facts.

## Bytecode features

| key | matches | example |
|---|---|---|
| `api` | an invoked method reference | `Landroid/telephony/SmsManager;->sendTextMessage` |
| `string` | a string constant, exactly | `android.intent.action.DELETE` |
| `substring` | a string constant, containing | `api.telegram.org` |
| `regex` | a string constant, by pattern | `/^https?:\/\/\d+\./` |
| `field` | a field reference | `Landroid/os/Build;->FINGERPRINT` |
| `type` | a class reference (`new-instance`, `const-class`) | `Landroid/provider/ContactsContract` |
| `opcode` | a Dalvik opcode, by name | `invoke-polymorphic` |

**Pattern forms.** A value wrapped in slashes is a regular expression (`/…/`). For
`api`, `field` and `type`, a value without a descriptor is a *prefix* match, so
`Lcom/x/A;->f` matches every overload of `f`; add the signature to be exact.
Descriptor whitespace is normalised on both sides.

## Site features

These match the *name of the site being evaluated* rather than its contents — the way
to detect an override, since a subclass never invokes the callback it overrides.

| key | matches |
|---|---|
| `method` | the method reference under evaluation |
| `class` | its class |

```yaml
- method: "/->onAccessibilityEvent\\(/"
```

## Manifest and packaging features

| key | matches | notes |
|---|---|---|
| `permission` | a requested or declared permission | glob allowed |
| `intent_action` | an action in any `intent-filter` | glob allowed |
| `component` | `activity` / `service` / `receiver` / `provider`, optionally `type:role` | roles come from bind permissions: `accessibility_service`, `notification_listener`, `device_admin`, `input_method` |
| `file` | a path inside the APK | glob, e.g. `assets/*.dex` |
| `native_lib` | a bundled `.so` | glob, e.g. `*libjiagu*` |
| `metadata` | an application/component `meta-data` name, or `name=value` | glob |
| `exported` | an exported component: `provider`, or `provider:unprotected` / `provider:protected` | `unprotected` means no `android:permission` guards it; `*` matches any type |
| `manifest` | an `<application>` attribute, or `name=value` | glob; `debuggable`, `allowBackup`, `usesCleartextTraffic`, `networkSecurityConfig`, `testOnly`, `hasFragileUserData`, `requestLegacyExternalStorage` |

## Combinators

```yaml
- and: [ … ]                 # all
- or:  [ … ]                 # any
- not: { api: "…" }          # negation (contributes no evidence)
- n_of: { n: 2, of: [ … ] }  # at least n of m
- count: { api: "…", value: ">=2" }   # occurrence count; >=, <=, ==, >, <
```

`count` accepts one bytecode feature plus `value`.

## Reachability constraints

`reachable_from` filters matches by *how* they can be triggered:

```yaml
reachable_from:
  entrypoint: [accessibility_service, callback]   # omit for "any entry point"
  max_hops: 8
```

Entry-point kinds: `exported_activity`, `activity`, `exported_service`, `service`,
`exported_receiver`, `receiver`, `exported_provider`, `provider`,
`accessibility_service`, `notification_listener`, `device_admin`, `input_method`,
`application`, `static_init`, `js_bridge`, `callback`.

The first eight-plus-four are *remote* — an outside party can trigger them — and score
higher than `application`, `static_init` and `callback`.

Without `reachable_from`, a method-scope match is kept when any path exists and dropped
when none does; `--keep-unreachable` reports those instead.

## Scoring

```
contribution = severity weight × reach factor × (1 + damped repeat bonus)
```

Severity weights: high 20, medium 7, low 2, info 0.5 (override per rule with `weight`).
Reach factors: remote 1.0, declared (class/apk scope) 1.0, local 0.8, unknown 0.5,
unreachable 0.25. Every capability reports the sentence that produced its own number.

## Fixtures

Every rule is pinned by at least one fixture: a synthetic app plus the expectation that
the rule does — or does not — fire on it. Fixtures live in `tadori/fixtures/` and run
through the real matcher, entry-point discovery and reachability analysis, so they cover
`reachable_from` semantics as well as the condition itself.

```yaml
fixture:
  name: accessibility service performs a global action
  rule: TAD-ACCS-0001
  expect: match              # match | no-match
  entry_kind: accessibility_service   # optional assertion on the best path
  hops: 0                             # optional assertion on the best path
  app:
    package: com.x                    # optional, defaults to com.example.fixture
    permissions: [android.permission.RECEIVE_SMS]
    application_class: com.x.App
    files: ["assets/payload.dex"]
    native_libs: ["lib/arm64-v8a/libjiagu.so"]
    metadata: {android.accessibilityservice: "@xml/config"}
    flags: {debuggable: true}         # <application> attributes, for `manifest:`
    supers: {"Lcom/x/Svc;": ["Landroid/app/Service;"]}
    js_bridge_classes: ["Lcom/x/Bridge;"]
    components:
      - type: service                 # activity | service | receiver | provider
        name: com.x.Svc
        permission: android.permission.BIND_ACCESSIBILITY_SERVICE
        actions: [android.intent.action.BOOT_COMPLETED]
        exported: true                # defaults to "has an intent filter"
    methods:
      - ref: "Lcom/x/Svc;->onAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)V"
        api: ["Landroid/accessibilityservice/AccessibilityService;->performGlobalAction(I)Z"]
        string: ["…"]
        field: ["Landroid/os/Build;->TAGS:Ljava/lang/String;"]
        type: ["Landroid/provider/ContactsContract;"]
        opcode: {invoke-virtual: 2}
        calls: ["Lcom/x/Other;->helper()V"]   # outgoing call edges
```

A method belonging to a declared component class is itself an entry point, so the
shortest fixtures assert `hops: 0`. To test a chain, add `calls` edges.

Write a negative fixture whenever a rule has a plausible innocent twin — that is what
keeps a rule from drifting into a false-positive generator.

## Validating

```bash
tadori rules lint                        # metadata, ATT&CK ids, references, structure
tadori rules lint --rules mine/          # your own pack
tadori rules test                        # run every fixture
tadori rules test --require-coverage     # …and fail on a rule with no positive fixture
tadori rules test --fixtures mine/       # your own fixtures
tadori rules show TAD-ACCS-0001          # metadata + parsed condition
tadori explain TAD-ACCS-0001 app.apk     # why it fired on a real app
```

## Measuring false positives

`scripts/fp_bench.py` scans a corpus of apps you already have and reports how often each
rule fires:

```bash
python scripts/fp_bench.py --corpus ~/apks --out fp.md --json fp.json
```

Nothing is downloaded and no sample is written out — only the aggregate table. A rule
that fires on most ordinary apps is either too loose or needs its description to explain
the benign case.
