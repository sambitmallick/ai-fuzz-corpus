# ai-upgrade-corpus: the upgrade agent gets yesterday's traffic. Is that enough?

Companion repo to a [DevOps Autopilot](https://www.youtube.com/@DevOpsAutopilot) episode.

**Last episode** an AI agent migrated `signupkit` from zod 3 to zod 4: 11 compile errors fixed, tests
green, merged. Then yesterday's signups went through it and **9 of 12 were rejected**. The dangerous
breaking changes compile. The fix we promised: replay real traffic before you merge, a **golden corpus**.

**This episode** the agent gets the corpus. Same Dependabot bump (zod 3.25.76 → 4.6.5), same
11 compile errors, same $0 setup: a local model call (`claude -p` with its own tools off) and free
Actions minutes.

## The corpus: [`corpus/`](corpus)

| file | what it is |
|---|---|
| `signups-2026-10-15.jsonl` | 400 signup requests from yesterday, each with **the answer production (zod 3) gave it** |
| `capture.js` | how it was recorded: on `main`, through the zod 3 build. Traffic is simulated (seeded) with the shapes real signups have: two ID generators, IPv4 + IPv6, typos, bots, emoji names. Scrubbed: identity removed, *shape* kept |
| `canon.js` | what counts as "the same answer": the verdict, the parsed value, and *which* fields failed. Not the error text: zod 4 rewrote every message |
| `replay.js` | replays the corpus through the current build and groups every changed answer |

## The agent: [`agent/agent.py`](agent/agent.py)

The from-scratch harness from two episodes ago, plus:

- **a new tool**: `run_corpus()`
- **a done-gate the harness enforces**: on `done`, the harness re-runs the tests and the corpus
  itself. The model's word is not evidence.
- **a new hand-back**: exit `4` = "needs a human decision"
- **scope**: `src/` only. The tests *and the corpus* are the contract: readable, never writable.

```bash
npm ci
python agent/agent.py --mode zero      # done = build + tests + ZERO corpus differences
python agent/agent.py --mode review    # done = build + tests + every difference written up for a human
python agent/test_harness.py           # 14 checks, no model, no API call
```

## What happened

### 1. "Zero differences" brought a bug back

The first replay found 9 differences (33 when the agent first reached for the strict `z.uuid()`; the
corpus caught last episode's legacy-ID break and it switched to `z.guid()`). Then it made the rest go
away, in **both runs**:

| group | requests | what zod 4 did | what the agent did |
|---|---|---|---|
| `age` | 2 | rejects `1e21` and `2^53` as ages (`.int()` = *safe* integer) | restored `Number.isInteger`, "so 1e21 and 2^53 are still accepted" |
| `ip` | 4 | rejects IPv6 zone ids (`fe80::1%eth0`) | added a union branch that accepts them |
| `name` | 3 | counts characters, not UTF-16 units | restored the UTF-16 count |

Build green, 5/5 tests, **400/400 same answer**, and the CI corpus step is the cleanest green of any
branch. It is also the upgrade with the bug zod 4 had fixed put back in by hand. "Zero differences"
doesn't mean "safe". It means **"the upgrade undone"**: some differences are the reason you upgraded.
(Branch: `agent-zero-diff`.)

### 2. "Write it up for a human" got it right, mostly

Same agent, one sentence of goal changed. It restored the zone ids and the name length, **left the
age check as zod 4 has it** ("an age above 9e15 is nonsense"), and handed back with exit 4 and
[`review/corpus-diffs.md`](review/corpus-diffs.md) on the PR branch: one section per group, a
recommendation, a sign-off checklist. Two lines in it are wrong, and they're the reason the human
reads it:

- *"The 80 guards a storage column."* There's no column anywhere in this repo. A plausible reason, invented.
- *"Everything else in this PR is a pure API rename with no behavioural change."* The replay can only
  vouch for what's in the traffic. See 3.

### 3. The corpus covers what happened yesterday, not what can happen

```bash
node probe/coverage.js      # which of zod 4's 7 compiling behaviour changes does the traffic exercise?
node probe/blind-spots.js   # run on each branch after `npm run build`
```

The corpus exercises **5 of 7**. JSON can't carry `Infinity`, and no field uses `datetime()`. `Config`
has **0 rows**: config isn't traffic. So `timeoutMs: Infinity`, accepted by zod 3, is rejected by
both branches, and no replay, no review and no human ever looked at it.

## CI: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

PR-only. Build, test, then replay the corpus and print the report to the job summary. Changed answers
are allowed, but only if `review/corpus-diffs.md` covers every group. Otherwise the PR fails.

## The rules

1. **Give the upgrade agent a corpus.** It caught the legacy-ID break that the build and the tests missed.
2. **Never make "zero differences" the goal.** That definition of done restores the bugs the upgrade fixed.
3. **A difference is a decision.** The agent recommends; a human signs it off. Make the hand-back an exit code, not a hope.
4. **Read the review like a diff.** Check each claim, not just the recommendation.
5. **Measure the corpus's coverage.** Anything the traffic never sends is still invisible: config, edge numbers, unused formats.

---
🎬 Full walkthrough: **[DevOps Autopilot](https://www.youtube.com/@DevOpsAutopilot)**
