# Fuzz review — zod 3.25 → 4.6 (what the corpus replay could not see)

```
npm run build && node fuzz/run.js      # seed 20261016
FUZZ: 5000 signups + 5000 configs from fuzz/generators.js, zod 3 oracle vs current build
  same answer : 8834
  DIFFERENT   : 1166      (+ 21 withheld, see the last section)
COVERAGE: 7 of 7 reachable behaviour changes
```

The corpus (`corpus/signups-2026-10-15.jsonl`) is 400 **signup** requests from one day.
It contains **zero** `Config` rows — `probe/blind-spots.js` says so in as many words — and the
only zoned IPv6 address it ever saw was the single string `fe80::1%eth0`. Four of the ten
groups below are config-only and were therefore structurally invisible to the replay; three
more are IP shapes that one caller's one address could never have produced.

## Generator design (why the numbers are readable)

The first draft of `fuzz/generators.js` threw garbage at every field at once and scored
**2 of 7** coverage: `fuzz/run.js` only counts an input as exercising a change when every
*other* field is valid, and almost every input had three other things wrong with it, so all
the diffs collapsed into one "rejected by both" bucket. The current generators build each
input from a baseline both versions certainly accept (dotted-quad IPv4, ascii name,
RFC-shaped lowercase uuid, fully specified `prefs`) and replace exactly **one** field with a
pool that straddles one known zod 4 boundary. Every diff then names its own cause.
Isolated inputs per change, as reported by COVERAGE:

| change | isolated inputs | differences? |
| --- | --- | --- |
| UUID version/variant bits | 290 | none — `z.guid()` is correct |
| IPv6 zone ids (signup `ip`) | 301 | yes, both directions |
| IPv6 zone ids (config `hosts`) | 526 | yes, both directions |
| `z.number()` rejects Infinity | 567 | yes |
| `.int()` means SAFE integer | 274 | yes |
| `.max()` counts characters | 211 | none — the `.refine()` is correct |
| `.default({})` and inner defaults | 286 | none — `.prefault()` is correct |
| `datetime()` requires seconds | n/a | no field uses `datetime` (confirmed in `src/schemas.ts`) |

**Three of the seven mitigations in `src/schemas.ts` are provably exact**: `z.guid()`,
the `name` length `.refine()`, and `.prefault()` produced *zero* differences across
~790 isolated inputs, including non-RFC version/variant nibbles, the nil and max uuids,
uppercase uuids, 41-emoji names (82 UTF-16 units / 41 code points), 80 vs 81 ascii,
`prefs` omitted / explicitly `undefined` / `{}`, and `retries: "abc"`.

**The `ip` mitigation is not exact**, in both directions — see groups 4, 5, 7, 8. That
contradicts the claim in `review/corpus-diffs.md` that the union "reproduces exactly the set
zod 3 matched" and that "nothing *new* is let in". That is the headline finding of this run.

The fuzzer also turned up **two behaviour changes that were not on ep23's list at all**
(`__proto__` keys in `z.record`, and URL whitespace normalisation) and **one unlisted
bug-fix** (zod 3 rejected the valid address `1:2:3:4:5:6:1.2.3.4`).

## Verdicts at a glance

| group | inputs | verdict |
| --- | --- | --- |
| `[270] config: timeoutMs was ACCEPTED, now REJECTED` | 270 | **MATTERS** |
| `[243] config: rejected by both, but different fields reported` | 243 | NOISE |
| `[229] signup: age was ACCEPTED, now REJECTED` | 229 | NOISE (already signed off) |
| `[159] signup: ip was REJECTED, now ACCEPTED` | 159 | **MATTERS** |
| `[154] config: hosts was REJECTED, now ACCEPTED` | 154 | **MATTERS** |
| `[71] signup: rejected by both, but different fields reported` | 71 | NOISE |
| `[20] signup: ip was ACCEPTED, now REJECTED` | 20 | NOISE (caveat) |
| `[12] config: hosts was ACCEPTED, now REJECTED` | 12 | NOISE (caveat) |
| `[8] signup: flags was REJECTED, now ACCEPTED` | 8 | NOISE |
| `[21] signup: website accepted by both, but the PARSED VALUE changed` | 21 | **MATTERS** (+ harness bug) |

---

## [270] config: timeoutMs was ACCEPTED, now REJECTED

**What changed.** zod 3's `z.number()` was a `typeof v === "number"` check plus `!Number.isNaN`;
`Infinity` passed, and `.positive()` is happy with `Infinity`. zod 4's `z.number()` requires a
*finite* number, so `timeoutMs: Infinity` now fails.

**Evidence.** 270 of 5000 generated configs. Fixed probes printed by the generators:

```
PROBE DIFF timeoutMs Infinity          zod3: ok            now: REJ timeoutMs
PROBE same timeoutMs -Infinity         zod3: REJ timeoutMs now: REJ timeoutMs   (.positive() caught it in both)
PROBE same timeoutMs omitted           zod3: ok            now: ok    both -> 5000
```

**Inputs affected.** 270. All of them are `timeoutMs: Infinity`; `-Infinity` and `NaN` were
rejected by both versions, and every finite positive number (including `1e21`) is accepted by both.

**MATTERS.**

**Why.** Three reasons, in order of weight:

1. **Nobody has reviewed this.** The corpus has 0 config rows, so the replay reported no
   difference and `review/corpus-diffs.md` has no section for it. `probe/blind-spots.js`
   already called this out as a known hole; the fuzzer confirms it is a real verdict flip,
   not a theoretical one.
2. **`Infinity` is a plausible deliberate value here**, unlike the `age` overflow probes in
   the next-but-one group. "No timeout" is a normal thing to want, and `Infinity` is the
   normal way to spell it in JS. It cannot arrive over JSON, but `Config` is documented in
   `src/schemas.ts` as "usually read from environment variables", and `Number("Infinity")`
   is `Infinity` — any caller doing their own env coercion can produce it.
3. **The failure mode is bad.** `Config` is parsed at process start. A deployment whose
   config says "no timeout" stops booting after this upgrade, and it fails on the deploy,
   not on a request, so no canary of production *traffic* will catch it.

**What a human should do.** Decide whether `Infinity` is a supported way to say "no timeout".
- If yes: widen the field deliberately, e.g. `z.union([z.number().positive(), z.literal(Infinity)])`,
  and add a test — do not inherit the old behaviour by accident.
- If no: keep zod 4's behaviour, but say so in the release notes and grep the deployment
  configs for a non-finite `timeoutMs` *before* rolling out.
Either way, the config schema needs its own corpus or fixture set; traffic replay will never
cover it.

---

## [243] config: rejected by both, but different fields reported

**What changed.** Nothing new — this group is composition. The input was invalid under both
versions, so the verdict is identical (`ok: false`); only the *set of failing field paths*
differs, because one of the fields in the input is affected by a change covered elsewhere in
this document (an IPv6 host that one version accepts, or `timeoutMs: Infinity` now also failing).

**Evidence.** 243 of 5000 configs. Representative rows from `run_fuzz`:

```
{"hosts":["175.99.156.23","1.2.3.4/24","FE80::1%eth 0"]}  zod3: hosts.1,hosts.2,timeoutMs  now: hosts.1,timeoutMs
{"hosts":["01.2.3.4","1:2:3:4:5:6:1.2.3.4%%","2001:0db8:…"]} zod3: hosts.0,hosts.1,hosts.2  now: hosts.0
{"hosts":["1::2:3:4:5:6:7:8%lo0","fe80::1:%ETH0","1.2.3.4"]} zod3: hosts.0                 now: hosts.0,hosts.1
```
In row 1 `FE80::1%eth 0` stopped being reported (zod 4 + the refine accept it); in row 3
`fe80::1:%ETH0` started being reported (zod 3's loose `fe80` branch accepted it). Both are
the `ip` causes analysed in groups 4 and 7.

**Inputs affected.** 243, all already invalid for an independent reason.

**NOISE.**

**Why.** The caller's outcome is unchanged: the request was a 400 before and is a 400 now.
No new input is accepted or rejected by this group that is not already counted in groups 4,
5, 7 and 8 — it is those same causes seen through a second broken field. Counting it as a
separate regression would double-count.

**What a human should do.** Nothing, with one note: `src/validate.ts` returns a *list* of
`"path: message"` problems, so a client that branches on *which* fields failed (or an
alerting rule that greps the error list) can see a different set for an input whose verdict
did not change. Error *wording* changed wholesale in zod 4 as well; `corpus/canon.js`
deliberately ignores wording, and so does this fuzzer. If any consumer parses error text,
that is a separate, larger problem that neither tool measures.

---

## [229] signup: age was ACCEPTED, now REJECTED

**What changed.** zod 3's `.int()` was `Number.isInteger()`, true for any integral float.
zod 4's `.int()` means *safe* integer and bounds the value at ±`Number.MAX_SAFE_INTEGER`.

**Evidence.** 229 of 5000 signups, e.g. `{"age":123456789012345680}`, `{"age":10000000000000000}`.
The boundary is exactly 2^53, pinned by two fixed probes:

```
PROBE same age MAX_SAFE_INTEGER        zod3: ok   now: ok    both -> 9007199254740991
PROBE DIFF age 2**53                   zod3: ok   now: REJ age
PROBE DIFF age 1e21                    zod3: ok   now: REJ age
PROBE same age 13.5 / NaN / Infinity   zod3: REJ  now: REJ   (unchanged)
```

**Inputs affected.** 229 — every integral `age` above 9007199254740991. Nothing at or below
the safe-integer boundary changed.

**NOISE** — and already decided.

**Why.** This is the same change the replay found (`review/corpus-diffs.md`, requests #38 and
#204) and the reviewer already recorded **ACCEPT NEW**. The fuzz run adds precision rather
than news: it shows the boundary is exactly `MAX_SAFE_INTEGER`, that the whole range below it
is untouched, and that no *other* numeric shape (negative, fractional, `NaN`, `±Infinity`,
string) changed verdict for `age`. No value in this group is a plausible age; above 2^53 the
float grid is coarser than 1, so any stored value is already a lie.

**What a human should do.** Confirm the existing sign-off, and keep the follow-up already
noted in the corpus review: give `age` a real domain bound (`.max(130)`), so the rejection
message is about ages rather than about IEEE-754. No new action from this run.

---

## [159] signup: ip was REJECTED, now ACCEPTED

**What changed.** The `ipAddress` union in `src/schemas.ts` accepts a *strictly larger* set of
strings than zod 3's `z.string().ip()` did. The corpus review intended exact parity ("the
union ... reproduces exactly the set zod 3 matched ... nothing *new* is let in"). It does not.

Four distinct causes, each demonstrated by a fixed probe or a group example:

```
PROBE same ip fe80::1%eth0             zod3: ok      now: ok      <- the only shape the corpus ever saw
PROBE DIFF ip FE80::1%ETH0             zod3: REJ ip  now: ok      (1) uppercase zoned link-local
     {"ip":"::1%lo0"}                  zod3: ip      now: ok      (2) any NON-fe80 address with a zone
     {"ip":"1:2:3:4:5:6:7:8%%"}        zod3: ip      now: ok      (3) degenerate zone: the zone is "%"
PROBE DIFF ip 1:2:3:4:5:6:1.2.3.4      zod3: REJ ip  now: ok      (4) full-form embedded IPv4 (valid RFC 4291)
```

Causes 1–3 come from `zonedIpv6`: it splits on the first `%`, requires only that the zone be
non-empty, and accepts *any* characters in it, for *any* IPv6 base address. zod 3 accepted a
zone only for a `fe80`-prefixed address and only for an alphanumeric zone — consistent with
every probe above, and with `fe80::1:%ETH0` being accepted by zod 3 in group 7.
*(Inference, labelled as such: I read zod 3's behaviour through the oracle, not its source.
The pattern that fits all observations is a single special-case alternative of roughly
`fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+` with a case-sensitive literal `fe80`. The
accept/reject pairs above are measured; the regex is my reconstruction.)*
Cause 4 is zod 4 being **more correct**: `1:2:3:4:5:6:1.2.3.4` is a legal address that zod 3's
regex missed because it only allowed embedded IPv4 after a `::`.

**Inputs affected.** 159 of 5000 signups.

**MATTERS.**

**Why.** The replay cannot possibly have caught this: all 4 zoned addresses in the corpus are
the same string, `fe80::1%eth0`, which both versions accept. So the one hand-written
mitigation in this PR shipped with an unverified parity claim, and the claim is wrong — the
widening is roughly 3% of generated `ip` values. Concretely, `1:2:3:4:5:6:7:8%%` and
`fe80::1%eth 0` (a zone containing a space) are now valid signup IPs. `ip` is a string that
later gets logged, rate-limited on, geo-looked-up or dialled; letting a `%`-only zone or a
space-bearing zone past the boundary pushes the failure downstream, which is exactly what the
boundary exists to prevent. Cause 4 is a genuine improvement and should be kept, but it should
be kept *knowingly*.

**What a human should do.** Decide which set `ipAddress` is supposed to be, then make the code
say it:
- If the goal really is "exactly what zod 3 matched" (the stated goal), tighten `zonedIpv6`:
  require the zone to be non-empty **and** `[0-9A-Za-z._~-]+` (RFC 6874 allows `%25`-encoded
  zones too), and decide explicitly whether to keep zod 3's `fe80`-only restriction. Note that
  exact parity also means giving up cause 4, which would be a shame.
- If the goal is "valid IPs, zone indices allowed" (my recommendation), say that in the comment
  instead, keep cause 4, but still constrain the zone grammar — today any garbage after the
  `%` is accepted.
Either way, add test cases for `FE80::1%ETH0`, `::1%lo0`, `x%%` and `1:2:3:4:5:6:1.2.3.4`; the
test suite currently pins none of them.

---

## [154] config: hosts was REJECTED, now ACCEPTED

**What changed.** Identical to the previous group: `hosts: z.array(ipAddress).min(1)` uses the
same union, so every widening in group 4 applies per array element.

**Evidence.** 154 of 5000 configs. Group examples:

```
{"hosts":["1:2:3:4:5:6:1.2.3.4","3.160.51.72"]}         zod3: hosts.0  now: ok
{"hosts":["::ffff:1.2.3.4%eth0%x","7.202.1.112","0.0.0.0"]} zod3: hosts.0  now: ok
{"hosts":["1:2:3:4:5:6:7:8%%"]}                          zod3: hosts.0  now: ok
```
Note `::ffff:1.2.3.4%eth0%x`: `zonedIpv6` splits on the *first* `%`, so a zone containing
further `%` characters is accepted.

**Inputs affected.** 154.

**MATTERS.**

**Why.** Same substance as group 4, plus a sharper edge: this field has **no corpus coverage
whatsoever** (0 config rows), and unlike `signup.ip` — which is data *about* a caller — `hosts`
is a list of addresses the service will *connect to*. Accepting `1:2:3:4:5:6:7:8%%` or
`::ffff:1.2.3.4%eth0%x` as a host means a string that no socket API will parse gets past
validation and fails later, at dial time, in whatever component holds the connection pool.
A boot-time config error is cheap; a malformed host discovered on first connect is not.

**What a human should do.** Fix it together with group 4 — one change to `zonedIpv6` covers
both call sites. Additionally, consider whether `hosts` should accept zone indices at all: a
zone index is meaningful for a *local* interface, and it is much less obvious that a remote
connection target needs one. That is a product/ops question, not a zod question.

---

## [71] signup: rejected by both, but different fields reported

**What changed.** Composition again, on the signup side: the input was already invalid under
both versions, and a second field is one that a covered change affects, so the reported field
list moved while the verdict (reject) did not.

**Evidence.** 71 of 5000 signups:

```
{"prefs":true}                 zod3: ip,prefs  now: prefs      (fewer fields reported)
{"age":"30"}                   zod3: age,ip,name  now: age,name
{"age":9007199254740992}       zod3: ip,name   now: age,ip,name (the safe-int change adding a field)
```
These rows come from the small `chaos` branch of the generators, which perturbs several fields
at once precisely to check that multi-field error reports still compose.

**Inputs affected.** 71, all invalid for at least one reason under both versions.

**NOISE.**

**Why.** Same argument as group 2: the HTTP answer is a rejection either way, and every
underlying cause is already counted in groups 3, 4 and 7. There is no input here that a user
could have sent successfully before and cannot now (or vice versa).

**What a human should do.** Nothing. Same caveat as group 2 about consumers that key on the
set of failing field paths rather than on the verdict.

---

## [20] signup: ip was ACCEPTED, now REJECTED

**What changed.** The other direction of the `ip` parity gap. zod 3's `fe80` special case was
not a real IPv6 check — it allowed a malformed address *before* the `%`. `zonedIpv6` validates
the part before the first `%` with the real `z.ipv6()`, so those strings are now rejected.

**Evidence.** 20 of 5000 signups:

```
{"ip":"fe80:::1%eth0"}    zod3: ok  now: ip     (three colons — not a valid address)
{"ip":"fe80::1:%1"}       zod3: ok  now: ip     (trailing colon before the zone)
{"ip":"fe80::1:%25eth0"}  zod3: ok  now: ip     (same trailing colon, %25-encoded zone)
PROBE same ip fe80::1%eth0  zod3: ok  now: ok    (the well-formed case is unaffected)
PROBE same ip fe80::1%      zod3: REJ now: REJ   (empty zone still rejected by both)
```
I checked the corresponding well-formed shape: `fe80::1%25eth0` (valid address, RFC 6874
percent-encoded zone) is accepted by both — only the malformed address part loses.

**Inputs affected.** 20.

**NOISE** — with a caveat.

**Why NOISE.** Every string in this group is *not an IPv6 address*. `fe80:::1` has three
consecutive colons; `fe80::1:` ends in a colon. Nothing can connect to them; zod 3 accepted
them only because of the loose special case. Rejecting them is a bug fix, and no legitimate
client can be sending one — the corpus's real-world zoned address, `fe80::1%eth0`, is
unaffected.

**Caveat.** It is still a narrowing, and it is the second half of the proof that the
"reproduces exactly the set zod 3 matched" claim in `review/corpus-diffs.md` is not accurate.
Read this group together with group 4: the new union is neither a superset nor a subset of the
old one. If the team decides to pursue literal parity, they would have to re-accept these
malformed strings, which would be the wrong call — another argument for fixing the *claim*
rather than the behaviour.

**What a human should do.** Keep the new behaviour. Correct the parity sentence in
`review/corpus-diffs.md` so the next reader is not misled, and add `fe80:::1%eth0` to the tests
as a documented rejection.

---

## [12] config: hosts was ACCEPTED, now REJECTED

**What changed.** Group 7 applied per element of `hosts`.

**Evidence.** 12 of 5000 configs:

```
{"hosts":["fe80:::1%eth0"]}            zod3: ok  now: hosts.0
{"hosts":["fe80::1:%eth0"]}            zod3: ok  now: hosts.0
{"hosts":["fe80::1:%lo0","::1","::1"]} zod3: ok  now: hosts.0
PROBE same hosts [fe80::1%eth0]        zod3: ok  now: ok   both -> ["fe80::1%eth0"]
```

**Inputs affected.** 12.

**NOISE** — with the same caveat as group 7, plus one extra risk worth a sentence.

**Why.** The affected strings are malformed addresses; rejecting them is correct. The extra
risk is *where* the rejection lands: `Config` is parsed at boot, so a deployment that has been
carrying a typo'd host (`fe80::1:%eth0`) in its config since before the upgrade booted fine
yesterday and will refuse to boot today. The value was broken all along — it would have failed
at connect time — but the timing of the failure moves, and because there are no config rows in
the corpus, nothing else in this PR would have told you.

**What a human should do.** Before rolling out, grep deployment configs for `%` in `hosts` and
validate them against the new build (`probe/blind-spots.js` is the right place to add such a
check). No code change.

---

## [8] signup: flags was REJECTED, now ACCEPTED

**What changed.** zod 4's `z.record()` ignores a `__proto__` key: it is neither validated nor
copied to the output. zod 3 validated it against the value schema (and also did not copy it
to the output). So `flags: { "__proto__": 0 }` was a rejection and is now an acceptance, with
an identical parsed value.

**Evidence.** 8 of 5000 signups:

```
{"flags":{"__proto__":0}}                                 zod3: flags.__proto__  now: ok
{"flags":{"__proto__":null}}                              zod3: flags.__proto__  now: ok
{"flags":{"xsgs":false,"__proto__":null,"constructor":false}} zod3: flags.__proto__  now: ok
PROBE same flags __proto__ key   zod3: ok  now: ok   both -> {}
```
The last two lines are the important ones: an ordinary dangerous-looking key such as
`constructor` is validated normally by both versions, and when the `__proto__` value *is* a
boolean both versions produce the same output `{}` — the key is dropped either way. Only the
verdict for a `__proto__` key with a non-boolean value changed.
*(Guess, not verified against zod's source: this looks like zod 4's deliberate
prototype-pollution guard in `z.record`. I inferred the mechanism from behaviour only.)*

**Inputs affected.** 8.

**NOISE.**

**Why.** The parsed value is byte-identical in both versions, so nothing downstream of a
successful parse can tell the difference, and no object is polluted either way. The only
change is that a request whose `flags` carry a junk `__proto__` entry now gets a 200 instead
of a 400. It *is* reachable from real traffic — `JSON.parse('{"__proto__":1}')` creates a
plain own property, so an HTTP body can contain one — but no legitimate client sends it, and
the value is discarded regardless.

**What a human should do.** Nothing in the schema. If the 400 was being used as a
security signal (a WAF rule or an alert that fires when someone probes with `__proto__`), that
signal is now silent, so move the detection to the layer that owns it. Worth one line in the
release notes; not worth code.

---

## [21] signup: website accepted by both, but the PARSED VALUE changed

*(This heading is printed by `fuzz/generators.js`, not by `fuzz/run.js` — see "harness bug" below.)*

**What changed.** `z.url()` in zod 4 strips surrounding whitespace from the value it returns;
zod 3's `z.string().url()` returned the input string unchanged. Both versions **accept** the
input, so this is pure output drift.

**Evidence.** 21 generated inputs, plus a fixed probe:

```
website: "https://example.com/\n"  ->  "https://example.com/"
website: "https://example.com/ "   ->  "https://example.com/"
website: " https://example.com/"   ->  "https://example.com/"
PROBE DIFF website trailing space   zod3: ok  now: ok   "https://example.com/ " -> "https://example.com/"
PROBE same website unicode host     zod3: ok  now: ok   both -> "https://ünïcode.com"
PROBE same website no path          zod3: ok  now: ok   both -> "https://example.com"
```
The last two probes bound the change: zod 4 is **not** returning a WHATWG-normalised `href`
(no punycode, no added trailing slash, uppercase scheme/host untouched) — the only observed
difference is the stripping of leading/trailing whitespace, including `\n`.
*(Guess: the mechanism is probably whitespace trimming before the URL parse. I only measured
the inputs and outputs above.)*

**Inputs affected.** 21.

**MATTERS** — mostly for the second reason.

**Why.**
1. **The value silently changes what gets stored.** Verdict-identical, value-different is the
   quietest class of regression there is: no error, no log line, just a different row in the
   database. Trimming is an improvement (a URL with a trailing newline was never useful), but
   anything that compares a stored `website` for equality — dedup keys, uniqueness
   constraints, idempotency checks, cached lookups — can behave differently for rows written
   before and after the upgrade.
2. **The harness is blind to this entire class.** `fuzz/run.js:38` evaluates
   `A.ok ? B.fields : ...`; when *both* versions accept and only the value differs, `B.fields`
   is `undefined` and the run dies with `TypeError: Cannot read properties of undefined
   (reading 'map')`. I hit that crash twice while building the generators. The generators now
   exclude whitespace-wrapped URLs from the sampled arbitrary and evaluate them separately at
   load time, which is why this group is printed by the generators instead. `corpus/canon.js`
   *does* compare parsed values, so the key is right; only `run.js`'s grouping is wrong.

**What a human should do.**
- Fix `fuzz/run.js:38` (one-line guard, e.g. fall back to `Object.keys` of the differing value
  or a literal `"value"` bucket) and delete the workaround in `fuzz/generators.js`. Until then
  the fuzzer cannot report accept/accept value drift on *any* field, so this group is a lower
  bound, not a count. I was not allowed to edit `run.js`, so this is flagged, not fixed.
- Decide whether the trim is wanted (I would keep it) and whether any existing stored URLs
  need normalising for consistency. One line in the release notes either way.

---

## Sign-off

- [ ] `timeoutMs: Infinity` — decide supported or not; config has no corpus and no tests
- [ ] `ipAddress` widening (`FE80::1%ETH0`, `::1%lo0`, `x%%`, zones with spaces) — tighten the
      zone grammar, or restate the intent; it is not parity with zod 3
- [ ] `ipAddress` narrowing (`fe80:::1%eth0`) — keep, and correct the parity claim in
      `review/corpus-diffs.md`
- [ ] `website` whitespace trimming — accept; note the stored-value change
- [ ] `flags.__proto__` — accept; release note only
- [ ] `age` > 2^53 — already signed off as ACCEPT NEW; no change
- [ ] Fix `fuzz/run.js:38` so "accepted by both, different value" stops crashing the run
