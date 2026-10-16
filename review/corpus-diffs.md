# Corpus review — zod 3.25 → 4.6

Corpus: `corpus/signups-2026-10-15.jsonl` — 400 recorded production requests, answers
captured under zod 3.25.

| state | same answer | different |
| --- | --- | --- |
| straight port to the zod 4 API | 391 | 9 |
| after the fixes described below | 398 | **2** |

The two remaining differences are deliberate and are flagged ACCEPT NEW below.
Everything else in this PR is a pure API rename with no behavioural change (see
"Silent API moves" at the end).

---

## [4] ip — was ACCEPTED, now REJECTED

**What changed.** zod 3's `z.string().ip()` accepted an IPv6 *zone index*
(`fe80::1%eth0`). zod 4 splits the check into `z.ipv4()` / `z.ipv6()`, and
`z.ipv6()` validates against the strict address grammar, which has no `%zone`
suffix — so every zoned link-local address started failing with `ip: Invalid input`.

**Requests affected.** 4 of 400 (#42, #139, #236, #333) — all the same address,
`fe80::1%eth0`, i.e. one real caller posting repeatedly.

**Recommendation: KEEP OLD** — restored in `src/schemas.ts`.

`fe80::/10` is link-local: the address is *meaningless without* its zone, because
the same address exists on every interface. Dropping the zone is not an option for
the caller, so zod 4's stricter grammar would simply lock an existing, well-behaved
client out of signup. This is a narrowing of accepted input, not a bug fix. The
union `z.union([z.ipv4(), z.ipv6(), zonedIpv6])` reproduces exactly the set zod 3
matched: the zone branch splits on `%`, requires a non-empty zone, and validates
the address part with the same `z.ipv6()`, so nothing *new* is let in.

---

## [3] name — was REJECTED, now ACCEPTED

**What changed.** `z.string().max(80)` changed its unit of measurement. zod 3
counted UTF-16 code units (`String.prototype.length`); zod 4 counts Unicode code
points. Emoji are surrogate pairs, so an emoji-heavy name that is 90 code units is
only 45 code points — it used to be rejected and now passes.

**Requests affected.** 3 of 400 (#89, #177, #265) — emoji-decorated display names.

**Recommendation: KEEP OLD** — restored in `src/schemas.ts` via an explicit
`.refine(s => s.length <= 80)`.

zod 4's measure is the better *user-facing* one (it matches what a person would call
"80 characters"), but this particular 80 is not a UX limit — it guards the storage
column downstream. A 45-code-point name is still 90 UTF-16 units / up to 180 bytes
on the way to the database, so relaxing the check here moves the failure from a
clean 400 at the boundary to a truncation or write error deeper in the stack.

**Follow-up for the human reviewer:** if the column is in fact wide enough, the right
fix is to widen the *limit* (and switch to zod 4's code-point counting) as a separate,
intentional change — not to inherit it silently from a dependency bump. Flagging
rather than deciding: this is a product call about how long a name may be.

---

## [2] age — was ACCEPTED, now REJECTED

**What changed.** zod 3's `.int()` was `Number.isInteger(value)`, which is true for
any integral float, including ones past the 53-bit mantissa. zod 4's `.int()` means
*safe* integer and additionally bounds the value by `±Number.MAX_SAFE_INTEGER`, so
these now fail with `age: Too big: expected int to be <=9007199254740991`.

**Requests affected.** 2 of 400:

- `#38` — `age: 1e+21`
- `#204` — `age: 9007199254740992`

**Recommendation: ACCEPT NEW** — left as zod 4 behaves; no code change.

Neither value is an age; they are the classic overflow probes (`MAX_SAFE_INTEGER + 1`
and `1e21`). Above `2^53` the float grid is coarser than 1, so arithmetic on these
values is already lossy and `9007199254740993` is not even representable — anything
we store is a lie. `age` is declared `.min(13)` with no upper bound, which is the
actual latent bug; zod 4 is closing it for free. The blast radius is 2 requests out
of 400, both nonsense, with no plausible legitimate caller behind them.

**Suggested follow-up (not in this PR):** give `age` a real domain bound, e.g.
`.max(130)`, so the rejection message is about ages rather than about IEEE-754.

---

## Silent API moves (no corpus difference)

Recorded for the reviewer's benefit — these changed in source but produced identical
answers on all 400 requests:

- `z.string().uuid()` → **`z.guid()`**, *not* `z.uuid()`. zod 4's `z.uuid()` is strict
  about the RFC 9562 version/variant nibbles; `z.guid()` is the shape-only check that
  zod 3's `.uuid()` actually performed. Using `z.uuid()` would have been a silent
  tightening.
- `z.string().email()` → `z.email()`, `z.string().url()` → `z.url()` (top-level formats).
- `z.nativeEnum(Plan)` → `z.enum(Plan)` (`nativeEnum` is deprecated in zod 4).
- `z.record(z.boolean())` → `z.record(z.string(), z.boolean())` — zod 4 requires the
  key schema explicitly.
- `.default("3")` / `.default("8080")` / `.default({})` → **`.prefault(...)`**. In zod 4
  `.default()` short-circuits and returns the value as the *output* type (so it would
  have had to be the number `3`, and `{}` would skip the nested defaults). `.prefault()`
  keeps zod 3's semantics: the fallback is fed through the pipeline, so `"3"` still
  transforms to `3` and `{}` still fills in `theme`/`retries`.
- `z.function().args(...).returns(...)` → `z.function({ input: [...], output: ... })`;
  `.implement()` is unchanged, and the test's boundary check still passes.
- `err.errors` → **`err.issues`** in `describe()` (`src/validate.ts`). Error *wording*
  changed throughout, which the corpus intentionally does not compare (`corpus/canon.js`
  keys on verdict + parsed value + failing field, not message text).

## Sign-off

- [ ] KEEP OLD on `ip` (zoned IPv6) — agreed
- [ ] KEEP OLD on `name` (UTF-16 length) — agreed, or raise the limit deliberately
- [ ] ACCEPT NEW on `age` (unsafe integers now rejected) — agreed
