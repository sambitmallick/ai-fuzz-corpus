#!/usr/bin/env python3
"""No model, no API call: feed the harness the moves a badly-behaved investigator would make.
Run from the repo root after `npm ci`:   python agent/test_harness.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent  # noqa: E402

ok, checks = 0, []


def check(name, cond):
    global ok
    checks.append(name); ok += bool(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {name}")


def w(path, content="x"):
    return agent.execute({"tool": "write_file", "args": {"path": path, "content": content}})


# scope: it investigates, it doesn't fix
check("refuses editing src/ (make the difference go away)", w("src/schemas.ts").startswith("REFUSED"))
check("refuses editing the oracle (make zod 3 agree)", w("oracle/zod3.js").startswith("REFUSED"))
check("refuses editing the fuzz runner (compare less)", w("fuzz/run.js").startswith("REFUSED"))
check("refuses editing the corpus", w("corpus/signups-2026-10-15.jsonl").startswith("REFUSED"))
check("refuses the tests and package.json", w("test/schemas.test.ts").startswith("REFUSED") and w("package.json").startswith("REFUSED"))
check("refuses ../ escapes", w("fuzz/../src/schemas.ts").startswith("REFUSED"))
check("refuses a look-alike path (fuzz/generators.js.bak)", w("fuzz/generators.js.bak").startswith("REFUSED"))
check("the generators ARE writable", not w("fuzz/generators.js", open(agent.PROJECT / "fuzz" / "generators.js", encoding="utf-8").read()).startswith("REFUSED"))
check("the findings report IS writable", not w("review/_probe.md").startswith("REFUSED"))
(agent.PROJECT / "review" / "_probe.md").unlink(missing_ok=True)

# the done-gate: the harness re-runs the fuzzer itself
code, msg = agent._check_done("triage")
check("done-gate re-runs the fuzzer and refuses at incomplete coverage", code is None and "COVERAGE 2 of 7" in msg)

# the stuck detector
seen = {}
rd = {"tool": "read_file", "args": {"path": "fuzz/run.js"}}
wr = {"tool": "write_file", "args": {"path": "fuzz/generators.js", "content": "..."}}
check("read, edit, read again is NOT stuck",
      not any([agent._repeating(seen, rd, ""), agent._repeating(seen, wr, "wrote fuzz/generators.js (3 chars)"),
               agent._repeating(seen, rd, ""), agent._repeating(seen, wr, "wrote fuzz/generators.js (3 chars)"),
               agent._repeating(seen, rd, "")]))
seen = {}
check("the same read 3x with nothing changed IS stuck", [agent._repeating(seen, rd, "") for _ in range(3)] == [False, False, True])
check("unknown tool is refused", agent.execute({"tool": "merge_pr", "args": {}}).startswith("ERROR"))

# the model call: a call that never returns must be retried, then handed back (ep25 run 1 crashed here)
_real_run, _real_sleep = agent.subprocess.run, agent.time.sleep
calls = []


def _hang(*a, **k):
    calls.append(1)
    raise agent.subprocess.TimeoutExpired(cmd="claude", timeout=k.get("timeout"))


agent.subprocess.run, agent.time.sleep = _hang, (lambda s: None)
try:
    agent.ask_model("sys", "prompt")
    raised = False
except RuntimeError:
    raised = True
finally:
    agent.subprocess.run, agent.time.sleep = _real_run, _real_sleep
check("a model call that times out is retried 3x, then raises for the hand-back (not a crash)", raised and len(calls) == 3)

print(f"\n{ok}/{len(checks)} checks passed -- no model, no API call.")
sys.exit(0 if ok == len(checks) else 1)
