# Differential fuzz review — zod 3.25 oracle vs the merged zod 4.6 build

`npm run build && node fuzz/run.js`: 5000 signups + 5000 configs from `fuzz/generators.js`
(seed 20261016, sandboxed) pushed through `oracle/zod3.js` (the schemas as they were on main)
and the current build side by side. Answers are compared the way the corpus replay compares
them (`corpus/canon.js`): verdict + parsed value + which fields failed — never message
wording. `run_build` is OK and `run_tests` passes (5 tests).

| | |
| --- | --- |
| same answer | 8205 |
| **DIFFERENT** | **1795** |
| coverage | **7 of 7** reachable zod 4 behaviour changes (1 n/a) |

```
COVERAGE (an input counts only if every other field is valid):
  covered  UUID version/variant bits                427 isolated inputs
  covered  IPv6 zone ids (fe80::1%eth0)             406 isolated inputs
  covered  IPv6 zone ids in config hosts            565 isolated inputs
  covered  z.number() rejects Infinity              857 isolated inputs
  covered  .int() means SAFE integer                394 isolated inputs
  covered  .max() counts characters                 425 isolated inputs
  covered  .default({}) and inner defaults          447 isolated inputs
  n/a      datetime() requires seconds (no field uses datetime)
COVERAGE: 7 of 7 reachable behaviour changes
```

The first draft of the generators threw junk at every field at once: zod 3 rejected nearly
every sample for 3–4 unrelated reasons, so `run.js` could not attribute a difference to the
field under test (coverage 2/7, 3932 unreadable diffs). The frozen generators build a base
record *both* versions accept and mutate exactly **one** field per sample, keeping a small
multi-field chaos tail for unknown-unknowns.

| group | n | verdict |
| --- | --- | --- |
| config: hosts was REJECTED, now ACCEPTED | 508 | **MATTERS** |
| config: timeoutMs was ACCEPTED, now REJECTED | 463 | **MATTERS** |
| signup: ip was REJECTED, now ACCEPTED | 357 | **MATTERS** |
| signup: age was ACCEPTED, now REJECTED | 324 | **MATTERS** (already triaged) |
| signup: rejected by both, but different fields reported | 88 | NOISE |
| config: rejected by both, but different fields reported | 47 | NOISE |
| signup: website accepted, but the PARSED VALUE changed | 8 | NOISE (watch item) |

**Headline.** The two largest groups are not zod 4 narrowing anything. They are the compat
shim written *for* this upgrade accepting **more** than zod 3 ever did. The replay could not
see it: yesterday's traffic contained only the one address the shim was written for.

---

## [508] config: hosts was REJECTED, now ACCEPTED

**What changed.** `src/schemas.ts` restores zoned IPv6 with
`zonedIpv6 = z.string().refine(s => at > 0 && at < s.length-1 && ipv6.safeParse(s.slice(0,at)).success)`
(`at = s.indexOf("%")`), unioned with `z.ipv4()` / `z.ipv6()`. That accepts **any** valid IPv6
address followed by **any** non-empty zone string. zod 3's `z.string().ip()` was far narrower —
it allowed `%zone` only on the link-local `fe80:` form:

```
{"hosts":["5ac3::de2a%wlan0","26.42.49.219"]}   zod3: hosts.0  now: ok
{"hosts":["2459::52d2%lo0"]}                    zod3: hosts.0  now: ok
{"hosts":["6e87::9fbf%en0"]}                    zod3: hosts.0  now: ok
```

The first (noisy) run showed the same for zoned addresses with an IPv4 tail
(`87:1800:b:2:8:2:188.223.187.43%eth0`, `eb:c69::3:e2:f0%eth0`: `zod3: hosts.N`). Meanwhile
`review/corpus-diffs.md` records zod 3 **accepting** `fe80::1%eth0` on 4 production requests.

**Inputs affected.** 508 of 5000 configs. Coverage counts 565 isolated zoned-host inputs; the
57-input gap is cases both versions agree on — `fe80::…%eth0` (accepted by both) and
`fe80::1%` / `%eth0` (rejected by both, since the refine needs `at > 0` and `at < len-1`).

**Verdict: MATTERS.**

**Why.** The PR's own claim — *"the union reproduces exactly the set zod 3 matched … so
nothing new is let in"* (`src/schemas.ts`, `review/corpus-diffs.md`) — is false on 508 inputs.
A zone index is only meaningful for link-local addresses, so `2001:db8::1%lo0` is ambiguous
nonsense that will now be stored and handed to a socket API. The refine never inspects the
zone's characters either, so `fe80::1%eth 0` (space) and `::1%eth0%x` (second `%`) pass — that
last point is inference from reading the refine, not from a printed row. A validator looser
than *both* the old and the new library is the worst of the three options, and nothing in
`test/` or `corpus/` covers it.

**What a human should do.** Tighten `zonedIpv6` to the set zod 3 matched — link-local prefix
plus `[0-9a-zA-Z]+` zone (zod 3's own regex alternative was
`fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-zA-Z]{1,}`) — or widen it deliberately and say so in the PR
description. Either way add tests for `2001:db8::1%eth0`, `fe80::1%eth 0`, `::1%eth0%x`;
`test/schemas.test.ts` pins only the happy `fe80::1%eth0` case.

---

## [463] config: timeoutMs was ACCEPTED, now REJECTED

**What changed.** zod 3's `z.number()` accepted any non-NaN number and `.positive()` is true
for `Infinity`, so `timeoutMs: Infinity` parsed and was stored as 'no timeout'. zod 4's
`z.number()` requires a **finite** number: `{"timeoutMs":Infinity}  zod3: ok  now: timeoutMs`
(all three printed rows). `-Infinity` and `NaN` are rejected by both versions, which explains
the 857-covered vs 463-different gap.

**Inputs affected.** 463 of 5000 configs.

**Verdict: MATTERS.**

**Why.** Not because zod 4 is wrong — an infinite timeout is a latent hang — but because
**nobody decided it**. `Config` is read at boot, not from traffic, so the corpus has zero
config rows: the replay reported "no difference" for a path it never executed, and
`review/corpus-diffs.md` has no section for it. `probe/blind-spots.js` flags exactly this
input and says so. The failure mode is a boot-time parse failure for the whole service, not a
400 to one caller, and `Infinity` is reachable in practice:
`JSON.parse('{"timeoutMs":1e999}')` yields it, as does any `x / 0` in a config builder.

**What a human should do.** Ratify the rejection, then make it explicit instead of inherited
from a dependency default: `z.number().positive().finite()` or a real domain cap
(`.max(600_000)`). Add the config case to `test/schemas.test.ts` and confirm the loader fails
loudly at boot rather than silently falling back to a stale/default timeout.

---

## [357] signup: ip was REJECTED, now ACCEPTED

**What changed.** Same root cause as the hosts group: `signup.ip` uses the same `ipAddress`
union, so every non-`fe80` zoned address zod 3 rejected is now accepted.

```
{"ip":"305b:7432:e22d:4c35:1962:71c6:ed4d:69ae%1"}   zod3: ip  now: ok
{"ip":"3d62::9037%1"}                                zod3: ip  now: ok
{"ip":"2001:db8::ff00:42:8329%25"}                   zod3: ip  now: ok
```

**Inputs affected.** 357 of 5000 signups (406 isolated inputs exercised the change; the rest
are the `fe80`/malformed cases both versions agree on).

**Verdict: MATTERS.**

**Why.** Same reasoning, but on *untrusted* input: `ip` arrives on the signup form, so this is
an externally reachable widening of the boundary, in the opposite direction from the one the
upgrade reviewed. `2001:db8::ff00:42:8329%25` is a global address carrying a zone — nonsense
that is now persisted. Anything downstream that re-parses the stored value (geo lookup, abuse
rules, `net.isIP`, a Postgres `inet` column) will see strings it never saw under zod 3. (That
Node's `net.isIP` returns 0 for a zoned address is my recollection, not something this run
measured.)

**What a human should do.** Fix once in `zonedIpv6` — the one shared definition covers `ip`
and `hosts` — and add a signup test for a zoned non-link-local address. If the widening is
kept on purpose, audit the consumers of the stored `ip` value first.

---

## [324] signup: age was ACCEPTED, now REJECTED

**What changed.** zod 3's `.int()` was `Number.isInteger`; zod 4's `.int()` means *safe*
integer and additionally bounds the value at ±`Number.MAX_SAFE_INTEGER`.

```
{"age":1e+21}              zod3: ok  now: age
{"age":9007199254740994}   zod3: ok  now: age
```

**Inputs affected.** 324 of 5000 signups; 394 isolated inputs exercised the change (integral
floats above 2^53: `2**53`, `2**53+2`, `2**60`, `1e21`, `1e30`, `Number.MAX_VALUE`).

**Verdict: MATTERS — but it is already triaged, so the action is small.**

**Why.** `review/corpus-diffs.md` saw 2 of 400 requests (`1e21`, `9007199254740992`) and chose
ACCEPT NEW; the fuzzer confirms that decision generalises — the whole class above 2^53 now
fails, not just the two recorded probes, and nothing *below* the safe-integer boundary
changed. It is listed MATTERS only because the blast radius is much larger than the corpus
implied (any integral float > 2^53, including negatives), so the reviewer should sign off on
the class rather than on two rows.

**What a human should do.** Keep the rejection, and take the follow-up `review/corpus-diffs.md`
already suggests: give `age` a real domain bound (`.max(130)`) so the 400 talks about ages
instead of IEEE-754. Nothing to revert.

---

## [88] signup: rejected by both, but different fields reported

**What changed.** The verdict is identical (rejected before, rejected now); only the set of
reported field paths moved, and every printed row is a side effect of the groups above:

```
{"age":[]}        zod3: age,email,id,ip,plan,prefs,website  now: age,email,id,plan,prefs,website   (ip dropped: zoned IPv6 now accepted)
{"email":"uq8…"}  zod3: email,ip,plan                        now: email,plan                        (same)
{"age":1e+21}     zod3: email,name,plan                      now: age,email,name,plan               (age added: unsafe int)
```

**Inputs affected.** 88 of 5000 signups — these are the chaos-tail samples where several
fields are wrong at once, which is why `run.js` excludes them from coverage.

**Verdict: NOISE.**

**Why.** No request changes outcome: a 400 stays a 400. The only movement is *which* field is
blamed, and it is fully explained by the four substantive groups — nothing new appears here.
Wording differences are deliberately not compared (`corpus/canon.js`).

**What a human should do.** Nothing in the code. One caveat worth a line in the PR: if any
dashboard or alert groups signup failures by field name, the per-field counts will shift (`ip`
failures down, `age` failures up) once this ships.

---

## [47] config: rejected by both, but different fields reported

**What changed.** Same as above, on configs. Printed rows:

```
{"port":{}}                              zod3: hosts.1,port            now: port
{"hosts":["255.255.255.256","9bd2…%…"]}  zod3: hosts.0,hosts.1,timeoutMs  now: hosts.0,timeoutMs
{"hosts":[true,"𾴛򀑣…"]}                 zod3: hosts.0,hosts.1         now: hosts.0,hosts.1,timeoutMs
```

The first two lose a `hosts.N` because a zoned host is now accepted; the third gains
`timeoutMs` because that sample also carried `Infinity`. Both are derivative of groups 1 and 2.

**Inputs affected.** 47 of 5000 configs.

**Verdict: NOISE.**

**Why.** Verdict unchanged (the config is rejected either way) and every field shift traces
to an already-reported group. No independent behaviour change is hiding in here.

**What a human should do.** Nothing. Re-check this group after fixing `zonedIpv6` — it should
shrink to the `timeoutMs`-only rows, which is a cheap confirmation that the fix landed.

---

## [8] signup: website accepted, but the PARSED VALUE changed

**What changed.** Both versions accept the URL, but the **stored string** differs. All printed
rows carry surrounding whitespace: `"https://example.com\n"` and `" https://example.com"`
(`zod3: ok  now: ok`). zod 3's `z.string().url()` returned the input untouched; zod 4's
`z.url()` stores a cleaned value. Note that only 8 of ~5000 signups differ, so zod 4 is *not*
doing full `URL.href` normalisation here — otherwise every plain `https://host.com` would have
gained a trailing slash and this group would be in the thousands. Exactly which transformation
zod 4 applies (trim vs. parse-and-reserialise) is inference from these 8 rows; I did not read
zod's url implementation.

**Inputs affected.** 8 of 5000 signups, all with leading/trailing whitespace or a trailing
newline.

**Verdict: NOISE — with a watch item.**

**Why.** Nobody is accepted or rejected differently, and the new value is the better one: the
old build persisted `"https://example.com\n"` verbatim, which is a latent header-injection /
link-rendering bug. The only way this bites is exact-string comparison of stored URLs
(dedupe keys, allowlist matching, a unique index) across the deploy boundary.

**What a human should do.** Treat it as intentional; mention it in the PR so nobody is
surprised that a stored `website` can change shape. If `website` is compared or indexed as an
exact string anywhere, normalise on read or backfill — otherwise no action.

---

## Confirmed unchanged (the shims that *are* faithful)

The fuzzer also proves four of the upgrade's compat decisions correct at scale — these changes
were exercised hundreds of times with **zero** differences:

- **UUID version/variant bits** — 427 isolated inputs (non-RFC nibbles, nil and max UUIDs,
  v6/v7/v8, uppercase) and not one difference: `z.guid()` reproduces zod 3's shape-only
  `.uuid()`. Using `z.uuid()` would have shown up here.
- **`.max()` counts characters** — 425 isolated inputs with 41–60 astral characters (>80 UTF-16
  units, ≤80 code points), no differences: the explicit `.refine(s => s.length <= 80)` keeps
  zod 3's UTF-16 measure exactly.
- **`.default({})` and inner defaults** — 447 isolated inputs with `prefs` omitted/partial, no
  differences: `.prefault()` still feeds `{}` and `"3"` through the pipeline, so `theme`
  defaults and `retries` still transforms to the number `3`.
- **`datetime()` requires seconds** — n/a, no field uses `datetime()`.

This is the useful contrast: three shims hold up under 5000 adversarial samples each, and the
fourth (`zonedIpv6`) does not.

## Sign-off

- [ ] **Fix `zonedIpv6`** (groups 1 + 3, 865 inputs) — it is looser than zod 3; the PR claims
      it is identical. Highest priority: untrusted input, no test, no corpus row.
- [ ] **Decide `timeoutMs: Infinity`** (group 2, 463 inputs) — never replayed, never reviewed;
      make the bound explicit in the schema either way.
- [ ] **Confirm the `age` class** (group 4, 324 inputs) — ACCEPT NEW already chosen; add
      `.max(130)` as the real fix.
- [ ] Note the field-attribution shift (groups 5 + 6) and the `website` whitespace strip
      (group 7) in the PR description; no code change.
