# ai-fuzz-corpus: the AI found the breaking changes yesterday's traffic never sent

Companion repo to a [DevOps Autopilot](https://www.youtube.com/@DevOpsAutopilot) episode.

**Last episode** the upgrade agent got a golden corpus: 400 recorded signups replayed through the
zod 3 to zod 4 upgrade. It caught real breaks, but it covered 5 of zod 4's 7 behaviour changes. JSON
can't carry `Infinity`, no field uses `datetime()`, and the config schema had **zero rows**.

**This episode** the agent stops fixing and starts investigating. It gets a **differential fuzzer**:
it writes [fast-check](https://fast-check.dev) generators, and the harness runs every generated input
through zod 3 (the code as it was before the upgrade) and the merged zod 4 build, side by side.
$0: a local model call (`claude -p`, its own tools off) and free Actions minutes.

## The pieces

| file | owner | what it does |
|---|---|---|
| [`oracle/zod3.js`](oracle/zod3.js) | harness | the schemas exactly as they were on main, on zod 3.25.76. Reproduces all 400 recorded production answers |
| [`fuzz/generators.js`](fuzz/generators.js) | **agent** | fast-check arbitraries for signups and configs. The only code the agent may write |
| [`fuzz/sample.js`](fuzz/sample.js) | harness | loads the generators in **their own process** under Node's permission model: read-only files, no child processes, no workers. Sends back data only |
| [`fuzz/run.js`](fuzz/run.js) | harness | the differential: groups every different answer, reports **coverage**. An input only counts if every *other* field is valid |
| [`agent/agent.py`](agent/agent.py) | harness | the from-scratch harness from ep22-24, plus `run_fuzz`, a done-gate, a phase gate and a visible budget |

```bash
npm ci && npm run build
node fuzz/run.js                 # the naive generators: 3932 differences, coverage 2 of 7
python agent/agent.py            # the investigator (exit 4 = handed back for a human)
python agent/test_harness.py     # 23 checks, no model, no API call
```

## What happened

**The naive fuzzer drowns.** Junk in every field: 3,932 of 10,000 inputs get a different answer, and
almost all of them are "rejected by both, but different fields reported". Coverage: 2 of 7.

**The agent fixed that itself.** Every run worked out the same technique: start from an input both
versions accept and break exactly **one** field. Coverage went from 2 of 7 to 7 of 7.

**Four runs, five fixes to the harness.**

| run | harness | coverage | outcome | what it taught the harness |
|---|---|---|---|---|
| 1 (first try) | v1 | | crashed at step 8 | the retry caught bad replies, not a model call that never came back. Now retried, and exit 5 hands back |
| 1 | v1 | 7 of 7 | exit 4, 24 steps | my fuzzer crashed whenever both versions accepted with a different **value**. The agent worked around it by turning `generators.js` into its own probe harness |
| 2 | v1 | 7 of 7 | out of budget (30) | same verdicts as run 1; spent the budget fighting my crash |
| 3 | v2 | 7 of 7 at step 11 | out of budget (30) | then polished the generators for 19 more steps and never wrote the findings |
| 4 | v3 | 7 of 7 at step 10 | exit 4, 27 steps | the harness froze the generators at full coverage; it then rewrote its report 5 times because reads were cut off silently |

**The generators are code the harness runs.** In v1, `run.js` `require()`d them. A no-model test
([`transcripts/ep25/attack_old_harness.txt`](transcripts/ep25/attack_old_harness.txt)) proved what that
means: a generators file printed `COVERAGE: 7 of 7`, the done-gate believed it (real coverage: 0 of 7),
and the same file rewrote `fuzz/run.js`, which is outside the writable scope. No agent run did that.
The harness can't rely on it. Now the generators run sandboxed, and the gate only reads the harness's
own output.

## The findings ([`review/fuzz-findings.md`](https://github.com/sambitmallick/ai-fuzz-corpus/blob/agent-run-4/review/fuzz-findings.md), run 4)

| group | inputs | run 4 verdict |
|---|---|---|
| config `hosts` was REJECTED, now ACCEPTED | 508 | MATTERS |
| config `timeoutMs` was ACCEPTED, now REJECTED (`Infinity`) | 463 | MATTERS |
| signup `ip` was REJECTED, now ACCEPTED | 357 | MATTERS |
| signup `age` was ACCEPTED, now REJECTED (unsafe integers) | 324 | MATTERS, already signed off |
| rejected by both, different fields reported | 88 + 47 | NOISE |
| signup `website` accepted, but the PARSED VALUE changed | 8 | NOISE, watch item |

- **Last episode's merged fix is looser than zod 3.** The review said the IPv6 zone-id restore let
  "nothing new" in. zod 3 only allowed a zone on `fe80:` addresses; the restore accepts any IPv6
  address plus any zone, so `2001:db8::1%eth0`, `fe80::1%eth 0` and `::1%eth0%x` now pass.
- **`timeoutMs: Infinity` is now rejected** at config load. The corpus had zero config rows, so
  nobody had looked.
- **Changes nobody had listed:** zod 4's `z.url()` trims surrounding whitespace from the stored value,
  and `z.record()` drops a `__proto__` key that zod 3 rejected.

**Triage is a judgement.** All three reports (runs 1, 2 and 4) agreed on the first three. On the same evidence, runs 1 and 2
called the URL trim MATTERS and run 4 called it NOISE; the age group flipped the other way. And run 1's
summary explained `__proto__` with a "null-prototype object" that doesn't exist. Its report body had
it right.

## The rules

1. **Fuzz what your traffic never sends.** It found the config change and two changes nobody listed.
2. **Change one field at a time.** Otherwise every difference is noise.
3. **A file the agent writes and your harness runs is not data. It's code.** Sandbox it, and never
   let your gate read its output.
4. **Budgets and phases belong in the harness.** Show the budget; freeze what's finished.
5. **The agent triages, a human decides.** Same evidence, different verdicts. Read the evidence.

---
🎬 Full walkthrough: **[DevOps Autopilot](https://www.youtube.com/@DevOpsAutopilot)**
