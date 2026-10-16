#!/usr/bin/env python3
"""No model, no API call: feed the harness the moves a badly-behaved agent would make.
Run from the repo root after `npm ci`:   python agent/test_harness.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent  # noqa: E402

ok = 0
checks = []


def check(name, cond):
    global ok
    checks.append((name, cond))
    ok += bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {name}")


def w(path, content="x", writable=agent.WRITABLE):
    return agent.execute({"tool": "write_file", "args": {"path": path, "content": content}}, writable)


REVIEW = agent.WRITABLE + ("review/",)

# scope: the corpus and the tests are the contract
check("refuses editing the corpus (rewrite yesterday's answers)", w("corpus/signups-2026-10-15.jsonl").startswith("REFUSED"))
check("refuses editing the replay (make it compare less)", w("corpus/replay.js").startswith("REFUSED"))
check("refuses editing the tests", w("test/schemas.test.ts").startswith("REFUSED"))
check("refuses package.json (pin zod back to 3)", w("package.json").startswith("REFUSED"))
check("refuses ../ escapes", w("src/../corpus/replay.js").startswith("REFUSED"))
check("zero mode: the review/ report is NOT writable", w("review/corpus-diffs.md").startswith("REFUSED"))
check("review mode: the review/ report IS writable", not w("review/_probe.md", "x", REVIEW).startswith("REFUSED"))
(agent.PROJECT / "review" / "_probe.md").unlink(missing_ok=True)

# guardrails still apply to code, not to the prose report
check("refuses `as any` in src/", w("src/x.ts", "const a = b as any;").startswith("REFUSED"))
check("allows the word 'any' in the markdown report", not w("review/_probe.md", "fails for any input: any", REVIEW).startswith("REFUSED"))
(agent.PROJECT / "review" / "_probe.md").unlink(missing_ok=True)

# the done-gate: the harness checks, the model's word is not evidence
code, msg = agent._check_done("zero")
check("done-gate re-runs build/tests/corpus itself and returns a verdict", code in (0, None) and isinstance(msg, str))
# the stuck detector: same call, same world
seen = {}
rd = {"tool": "read_file", "args": {"path": "src/schemas.ts"}}
wr = {"tool": "write_file", "args": {"path": "src/schemas.ts", "content": "..."}}
check("read, edit, read again, edit, read again is NOT stuck",
      not any([agent._repeating(seen, rd, ""), agent._repeating(seen, wr, "wrote src/schemas.ts (3 chars)"),
               agent._repeating(seen, rd, ""), agent._repeating(seen, wr, "wrote src/schemas.ts (3 chars)"),
               agent._repeating(seen, rd, "")]))
seen = {}
check("the same read 3x with nothing changed IS stuck",
      [agent._repeating(seen, rd, "") for _ in range(3)] == [False, False, True])
seen = {}
check("a REFUSED write doesn't reset the count",
      [agent._repeating(seen, rd, ""), agent._repeating(seen, wr, "REFUSED: ..."), agent._repeating(seen, rd, ""),
       agent._repeating(seen, rd, "")][-1] is True)

check("unknown tool is refused", agent.execute({"tool": "push_to_main", "args": {}}).startswith("ERROR"))

print(f"\n{ok}/{len(checks)} checks passed — no model, no API call.")
sys.exit(0 if ok == len(checks) else 1)
