# Differential fuzz review — zod 3.25 oracle vs the merged zod 4.6 build

Run: `run_fuzz` = `npm run build && node fuzz/run.js` — 5000 generated signups + 5000
generated configs, seed `20261016`, `oracle/zod3.js` (the schemas as they were on main)
against `dist/src` (the merged build). `npm test` passes (5 tests, step 28); the build is
clean. `run_fuzz` exits 1 because differences exist — that is the point of the run.

```
  same answer : 7864
  DIFFERENT   : 2136

COVERAGE (an input counts only if every other field is valid):
  covered  UUID version/variant bits                515 isolated inputs
  covered  IPv6 zone ids (fe80::1%eth0)             412 isolated inputs
  covered  IPv6 zone ids in config hosts           1250 isolated inputs
  covered  z.number() rejects Infinity              725 isolated inputs
  covered  .int() means SAFE integer                303 isolated inputs
  covered  .max() counts characters                 362 isolated inputs
  covered  .default({}) and inner defaults          329 isolated inputs
  n/a      datetime() requires seconds (no field uses datetime)
COVERAGE: 7 of 7 reachable behaviour changes
```

## How the generators got to 7 of 7

The first draft threw garbage at every field at once: 3932 differences but COVERAGE
**2 of 7**. `fuzz/run.js` only counts an input as exercising a change when every *other*
field is valid, so a payload with four broken fields proves nothing about any one of them
— it just lands in the "rejected by both, but different fields reported" bucket.

Final `fuzz/generators.js`: start from a `BASE` signup / config that **both** versions
accept (verified field by field by a probe build, step 17), then mutate exactly **one**
field per input. Each pool aims at a documented zod 4 change plus the ordinary edges
around it (uuid version/variant nibbles; astral runs of 41–60 chars = >80 UTF-16 units but
≤80 code points; integral-but-unsafe doubles; IPv6 zone indexes and malformed zone forms;
±Infinity; absent `prefs` so the object default has to fire). Every difference below is
therefore attributable to a single field.

| group heading from run_fuzz | inputs | verdict |
| --- | --- | --- |
| `[1032] config: hosts was REJECTED, now ACCEPTED` | 1032 | **MATTERS** |
| `[392] config: timeoutMs was ACCEPTED, now REJECTED` | 392 | **MATTERS** |
| `[337] signup: ip was REJECTED, now ACCEPTED` | 337 | **MATTERS** |
| `[234] signup: age was ACCEPTED, now REJECTED` | 234 | NOISE |
| `[141] config: rejected by both, but different fields reported` | 141 | NOISE |
| *appendix:* `website` value trimmed — the harness cannot report it | 91 / 3300 probed | **MATTERS** |

---

## [1032] config: hosts was REJECTED, now ACCEPTED

**What changed.** `hosts: z.array(ipAddress).min(1)` with
`ipAddress = z.union([z.ipv4(), z.ipv6(), zonedIpv6])`. `zonedIpv6` (`src/schemas.ts`) was
added to restore the zoned link-local addresses zod 3's `z.string().ip()` accepted and
zod 4's `z.ipv6()` rejects. Its refine splits at the first `%`, requires a non-empty zone,
and validates the part before `%` with `z.ipv6()` — which accepts **more** than zod 3 did.

Evidence, per-value probe (step 19; `signup.ip` uses the same `ipAddress` schema):

| value | zod 3 | current build |
| --- | --- | --- |
| `fe80::1%eth0`, `fe80::1%1` | ok | ok (unchanged) |
| `2001:db8::1%en0` | `ip: Invalid ip` | **ok** |
| `::ffff:1.2.3.4%eth0` | `ip: Invalid ip` | **ok** |
| `fe80::1%eth0%eth1` | `ip: Invalid ip` | **ok** |
| `fe80::1%eth0 ` (trailing space) | `ip: Invalid ip` | **ok** |
| `fe80::1%`, `%eth0`, `%`, `1.2.3.4%eth0` | rejected | rejected (unchanged) |

This group's own samples agree: `{"hosts":["3:ce:1::81.156.185.41%eth0",…]}` zod3 `hosts.0`
→ now `ok`; `{"hosts":["0:0:0:0:0:0:0:1%br-0"]}` and `{"hosts":["2001:db8::1%wlan0",…]}`
likewise (step 21 sweep).

The consistent reading of the probe table is that zod 3 allowed a zone only on the
`fe80:` link-local form with an alphanumeric zone token. *That exact shape is an inference
from probe results — I did not read zod 3's regex.* What is **not** inference: the build
accepts zoned addresses zod 3 rejected, including a zone containing a space and a zone
containing a second `%`.

**How many inputs.** 1032 of 5000 configs (plus the 141 of the group below — same root
cause). In the one-field sweep over 2100 config mutations (step 21) every `hosts`
difference was `REJECTED → ACCEPTED` or a shrinking field list; there was **no**
`hosts: ACCEPTED → REJECTED` group in any run, so the flip is one-directional.

**MATTERS.** `review/corpus-diffs.md` justifies the restore with "reproduces exactly the
set zod 3 matched … so nothing *new* is let in", and the comment in `src/schemas.ts` says
the same. The fuzzer shows that claim is false, and the corpus could not have caught it:
all 4 corpus rows carry the single address `fe80::1%eth0`, which is inside both sets.
`hosts` is a connect list — a zone index is only meaningful for link-local scope, so
`2001:db8::1%en0` is a malformed host the service will now store and try to dial, and
`fe80::1%eth0 ` / `fe80::1%eth0%eth1` pass an unvalidated zone downstream. zod 3 failed
those at the boundary with a clean error.

**What a human should do.**
1. Validate the zone token (e.g. `/^[0-9A-Za-z]+$/`) so spaces, dots and a second `%` are
   rejected again.
2. Decide deliberately whether the address part must be link-local (`fe80::/10`, as zod 3
   effectively required) or whether any-scope zones are wanted — if they are, that is a
   widening and belongs in the PR description, not inherited from a refine.
3. Add unit tests for `2001:db8::1%en0`, `fe80::1%eth0%eth1`, `fe80::1%eth0 `:
   `test/schemas.test.ts` passes today with the loose refine, so nothing guards this.

---

## [392] config: timeoutMs was ACCEPTED, now REJECTED

**What changed.** `timeoutMs: z.number().positive().default(5000)`. zod 3's `z.number()`
accepted any non-NaN double and `Infinity > 0`, so `Infinity` passed. zod 4's `z.number()`
requires a finite number (step 19 probe):

```
timeoutMs=Infinity   zod3: ok {"port":8080,"hosts":["10.0.0.1"],"timeoutMs":Infinity}
                     now : FAIL [timeoutMs: Invalid input: expected number, received Infinity]
```

The neighbours are unchanged: `-Infinity` and `NaN` rejected by both (`.positive()` /
zod 3's NaN check), `0` rejected by both, `1e21` accepted by both, absent → `5000` in both.
The whole group is the single value `+Infinity`.

**How many inputs.** 392 of 5000 configs; all three printed samples are
`{"timeoutMs":Infinity}`. (COVERAGE counts 725, since it also counts inputs whose only
complaint is `timeoutMs`.) The step-21 sweep: 201 of 2100 one-field config mutations.

**MATTERS** — not because `Infinity` is a sensible timeout, but because **nobody has
decided it**. `corpus/signups-2026-10-15.jsonl` is signup traffic; `Config` has **zero**
rows, so the replay reported no difference, `review/corpus-diffs.md` has no section for it
and its sign-off list does not mention it. `probe/blind-spots.js` already names this exact
case as a corpus blind spot. `Config` is "usually read from environment variables"
(`src/schemas.ts`) — it is parsed at **boot**, so a deploy whose config materialises
`Infinity` (`JSON.parse("1e999")`, a computed `x/0`, a deliberate "no timeout" sentinel)
used to start and now refuses to start. That is a worse failure mode than one rejected
signup, and it surfaces in a deploy, not in a request log.

**What a human should do.** Decide explicitly and write it down. Recommended: ACCEPT NEW
(a non-finite timeout is a bug and `setTimeout(Infinity)` fires immediately), but pair it
with (a) a grep of the real config sources for anything that can produce `Infinity`, and
(b) a declared upper bound, e.g. `z.number().positive().max(600_000).default(5000)`, so
the error is about timeouts rather than about IEEE-754. Add a `Config` fixture to the
corpus or a test so config parsing stops being invisible to the replay.

---

## [337] signup: ip was REJECTED, now ACCEPTED

**What changed.** The same `ipAddress` union as group 1, reached through `signup.ip`.
Samples from this group: `{"ip":"fe80::1%eth0 "}`, `{"ip":"0:0:0:0:0:0:0:1%eth0.5"}`,
`{"ip":"::d:e:255.84.43.48%1"}` — all `zod3: ip` → `now: ok`. The probe table in group 1
is the per-value evidence; the step-21 sweep saw 209 of 6300 one-field signup mutations,
again only in the `REJECTED → ACCEPTED` direction.

**How many inputs.** 337 of 5000 signups (412 isolated by COVERAGE).

**MATTERS**, and it matters more than the `hosts` version because `ip` is attacker-facing:
it comes off the signup form, so any client can now get a non-link-local, space-bearing or
double-`%` string stored as an "IP". The corpus shows one well-behaved caller sending
`fe80::1%eth0`; it cannot speak for the rest of the set the refine opened up. KEEP OLD on
`fe80::1%eth0` was the right call — the implementation just overshoots it.

**What a human should do.** Fix `zonedIpv6` once (it is shared by `ip` and `hosts`) per
the three steps in group 1, then re-run `run_fuzz`: groups 1, 3 and 5 should collapse to
zero while the `fe80::1%eth0` corpus rows keep passing. Treat "zoned non-link-local
addresses are accepted at signup" as the decision to record either way.

---

## [234] signup: age was ACCEPTED, now REJECTED

**What changed.** zod 3's `.int()` was `Number.isInteger()`; zod 4's means *safe* integer
and bounds the value by `±Number.MAX_SAFE_INTEGER`. Probe (step 19): `9007199254740992`,
`9007199254740994`, `1e16`, `1e21`, `1e100`, `Number.MAX_VALUE` all went
`zod3: ok` → `now: FAIL [age: Too big: expected int to be <=9007199254740991]`, while
`13`, `30`, `Number.MAX_SAFE_INTEGER` and `13.5`/`12`/`NaN`/`±Infinity` behave identically
in both. The boundary is exactly `MAX_SAFE_INTEGER`.

**How many inputs.** 234 of 5000 signups (303 isolated by COVERAGE); samples `1e+21`,
`1e+17`, `1e+16`.

**NOISE** — in the sense of "no new decision": this is the one difference the corpus
already caught and ruled on. `review/corpus-diffs.md` §`[2] age` records **ACCEPT NEW**
for requests #38 and #204 with the reasoning (above 2^53 the float grid is coarser than 1,
so the stored value is already a lie). The fuzzer adds only confirmation and a precise
boundary, and it confirms the change is *limited* to unsafe integers — no legitimate age
changed verdict. Volume here is an artefact of the generators deliberately oversampling
unsafe integers to reach coverage, not a signal of prevalence.

**What a human should do.** Nothing new in this PR; just tick the existing ACCEPT NEW
sign-off. The already-noted follow-up stands: give `age` a real domain bound (`.max(130)`)
so the rejection message is about ages rather than IEEE-754.

---

## [141] config: rejected by both, but different fields reported

**What changed.** Nothing about the verdict: both versions reject these configs, but the
list of failing `hosts` indexes shrank, because the loose `zonedIpv6` refine now accepts
some array entries while others still fail. Samples:
`{"hosts":["d:74dd:…%lo","fe80::%wlan0","::%1",…]}` was `hosts.0,hosts.2,hosts.3` → now
`hosts.3`; `{"hosts":["0x7f.0.0.1","5:57:d4:…%wlan0"]}` was `hosts.0,hosts.1` → now
`hosts.0`. In the step-21 sweep the same pattern appears as many small
"both reject, fields differ" groups, always with the new field list a **subset** of the old
one — i.e. purely the knock-on of group 1.

**How many inputs.** 141 of 5000 configs.

**NOISE.** The caller-visible answer is unchanged (still a rejection of the same request,
still a 400 at boot/parse time); only *which* indexes are itemised differs, and
`corpus/canon.js` deliberately compares verdict + parsed value + failing field rather than
message text. There is no second root cause hiding here: every sample I inspected contains
a zoned address that group 1 explains, plus at least one genuinely invalid entry.

**What a human should do.** Nothing directly. Use it as a progress check: after tightening
`zonedIpv6` this group should disappear along with groups 1 and 3. If it does *not*, there
is a second, un-diagnosed `hosts` difference and it needs its own look.

---

## Appendix A — a difference the harness cannot report: `website` is trimmed

Not in the group list above, because `fuzz/run.js` **crashes** on it. Line 38 evaluates
`A.ok ? B.fields : …`, so when both versions accept an input but the parsed *value*
differs, `B.fields` is `undefined` and the run throws before printing anything (observed
twice, steps 9 and 13: `TypeError: Cannot read properties of undefined (reading 'map')`).
I may not edit `fuzz/run.js`, so the generators deliberately emit no URL with leading or
trailing whitespace (documented in the header of `fuzz/generators.js`); otherwise the whole
run aborts with 0 groups and 0 coverage.

**What changed**, from the probe build instead (step 19) — both versions accept, the stored
string differs:

```
website="https://x.com "    zod3: "https://x.com "    now: "https://x.com"
website=" https://x.com"    zod3: " https://x.com"    now: "https://x.com"
website="https://x.com\n"   zod3: "https://x.com\n"   now: "https://x.com"
```

**How many inputs.** The step-21 one-field sweep: **91 of 3300** signup `website`
mutations landed in "BOTH ACCEPT, VALUE CHANGED (website)" (e.g. `"\thttps://x.com"`,
`"https://x.com "`). Every other `website` shape I probed — case, port, `..`/`//` paths,
query/fragment, userinfo, IDN, punycode, `ftp:`/`mailto:`/`javascript:`/`data:`,
`example.com`, `""` — was identical in both versions.

**MATTERS**, for two reasons. (1) It is a silent change to *stored data*, not to a verdict:
zod 3 persisted the user's string verbatim, the new build persists a normalised one. zod 4's
behaviour is almost certainly the better one, but "we now rewrite a field we used to store
as-sent" is a decision, and no corpus row has whitespace in `website` so nobody made it.
(2) It means the fuzzer is **blind to this entire class** — any future change where both
versions accept but the value differs will crash the run rather than report it.

**What a human should do.** Guard line 38 of `fuzz/run.js` (e.g. derive the field list from
`A.ok && B.ok ? ["value"] : …`) so "accepted, but the PARSED VALUE changed" can actually be
reported, then drop the whitespace exclusion from `fuzz/generators.js` and re-run. Decide
explicitly whether `website` (and any other `z.url()` field) is stored trimmed; if yes, say
so in the PR and add a test pinning it.

---

## Appendix B — changes exercised with NO difference (the mitigations hold)

Three of the seven covered changes produced **zero** difference groups. That is positive
evidence that the compensating code in `src/schemas.ts` works, and it is worth recording
because a future refactor could remove it silently:

- **UUID version/variant bits** — 515 isolated inputs, 0 differences. `z.guid()` reproduces
  zod 3's shape-only `.uuid()`; the probe confirms the nil uuid, the max uuid and version
  nibble `f` are still accepted, which `z.uuid()` would have rejected.
- **`.max()` counts characters** — 362 isolated inputs, 0 differences. The generators
  concentrate on astral runs of 41–60 characters (>80 UTF-16 units, ≤80 code points), the
  exact window where the two measures disagree; the `.refine(s => s.length <= 80)` keeps
  zod 3's answer on all of them. (The product question raised in `review/corpus-diffs.md`
  — whether the limit *should* be raised — is untouched by this.)
- **`.default({})` and inner defaults** — 329 isolated inputs with `prefs` absent or
  `undefined`, 0 differences. `.prefault({})` + `.prefault("3")` still fill
  `theme: "light"` and transform `"3"` into the number `3`, matching zod 3.

`datetime() requires seconds` is reported `n/a` by the harness: no field uses
`z.iso.datetime()`, so the change is unreachable in this codebase. Nothing to do unless a
datetime field is added later.

---

## Sign-off

- [ ] **MATTERS** `zonedIpv6` accepts more than zod 3 did — affects `hosts` (1032) and
      `ip` (337); tighten the zone token and decide the link-local question; add tests.
- [ ] **MATTERS** `timeoutMs: Infinity` now rejected at boot — 0 corpus rows, no decision
      on record; recommend ACCEPT NEW plus an explicit `.max()` and a config fixture.
- [ ] **MATTERS** `website` is now stored trimmed — fix the `fuzz/run.js` blind spot first,
      then decide and pin it.
- [ ] NOISE `age` unsafe integers — already decided ACCEPT NEW in `review/corpus-diffs.md`.
- [ ] NOISE `hosts` field-list shrinkage — knock-on of the first item; use as a regression
      check.
