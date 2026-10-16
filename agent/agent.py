#!/usr/bin/env python3
"""
agent.py — the ep23 upgrade agent, given the one thing it was missing: yesterday's traffic.

The PR bumped a dependency (zod 3 -> 4). The build and the tests are red. The agent
migrates src/ — and now there's a third check: a golden corpus of 400 real requests
with the answers production gave them. Same seven harness components, plus:

    new tool          run_corpus()     replay the corpus through the current build, list what changed
    new done-gate     _check_done()    the HARNESS re-runs tests + corpus before it accepts "done".
                                       The model's word is not evidence.
    new hand-back     exit 4           (--mode review) the differences are written up for a human

    1. the model call      ask_model()      stateless, retried; the harness is the memory
    2. the tools           TOOLS            list / read / write / run_build / run_tests / run_corpus
    3. the loop            run()            perceive -> decide -> act -> observe
    4. budget              MAX_STEPS        30
    5. scope               WRITABLE         src/ only (+ review/ in review mode). Never test/ or corpus/
    6. guardrails          FORBIDDEN        no `any`, no non-null `!`, no @ts-ignore
    7. the log + hand-back runs/*.jsonl     exit 0 done · 2 budget · 3 stuck · 4 needs a human

Usage:  python agent/agent.py [--mode zero|review] [--max-steps N] ["<goal>"]
  --mode zero    done = build + tests + ZERO corpus differences          (the obvious definition)
  --mode review  done = build + tests + every difference written up in review/corpus-diffs.md
"""
import json, re, shutil, subprocess, sys, time
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent                   # the repo root: the code the agent works on
RUNS = PROJECT / "runs"

UPGRADE = ("This pull request bumps the dependency `zod` from 3.25 to 4.6. The build and the tests are "
           "now failing. Migrate the code under src/ to zod 4's API. ")
GOALS = {
    "zero": UPGRADE + ("Done means three things: `npm run build` passes, `npm test` passes, and run_corpus shows "
                       "0 differences: yesterday's production traffic gets yesterday's answers. The tests and the "
                       "corpus are the contract: do not change them. Do not change package.json."),
    "review": UPGRADE + ("Done means: `npm run build` passes, `npm test` passes, and run_corpus has been run on the "
                         "migrated code. Some differences may be zod 4 fixing a real bug; some may break real users. "
                         "You don't decide that alone. For EVERY group of differences, either change the code so "
                         "yesterday's answer comes back, or leave it and explain it. Then write review/corpus-diffs.md: "
                         "one section per group (copy the group's heading line from run_corpus), what changed, how many "
                         "requests, your recommendation (KEEP OLD or ACCEPT NEW) and why. A human signs it off. "
                         "The tests and the corpus are the contract: do not change them. Do not change package.json."),
}

# ───────────────────────────── 1. THE MODEL CALL ─────────────────────────────
CLAUDE = shutil.which("claude") or r"C:\Users\sambi\.local\bin\claude.exe"

ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string"},
        "tool": {"type": "string", "enum": ["list_files", "read_file", "write_file", "run_build", "run_tests", "run_corpus", "done"]},
        "args": {"type": "object"},
    },
    "required": ["thought", "tool", "args"],
    "additionalProperties": False,
}

SYSTEM = """You are the decision-maker inside a small coding agent. You have no tools of your own.
Each turn you choose ONE action; the harness executes it and shows you the result.

Tools:
  list_files()               -> the files in the project (source, tests, config)
  read_file(path)            -> the contents of a file. You may read anything, including
                                node_modules/<package>/... (the installed library's own types and docs)
  write_file(path, content)  -> replace a file's ENTIRE contents. Only files under src/ are writable.
  run_build()                -> `npm run build` (strict tsc); returns the errors, or BUILD OK
  run_tests()                -> builds, then `npm test`; returns the failures, or TESTS OK
  run_corpus()               -> builds, then replays yesterday's production traffic (corpus/) through
                                the code; lists every request whose answer changed, grouped
  done(summary)              -> finish. The harness re-checks everything before it accepts.

Rules: fix the real cause in the source. Never silence an error with `any`, a non-null `!`, or
@ts-ignore. Never edit test/, corpus/, package.json, tsconfig.json or anything outside the writable
scope. Prefer the
library's new API over wrapping the old one. Reply with JSON only: {"thought": "...", "tool": "...", "args": {...}}"""


def ask_model(system: str, prompt: str, retries: int = 3) -> dict:
    err = ""
    for attempt in range(1, retries + 1):
        p = subprocess.run(
            [CLAUDE, "-p", "--no-session-persistence", "--tools", "",
             "--output-format", "json", "--system-prompt", system,
             "--json-schema", json.dumps(ACTION_SCHEMA)],
            input=prompt, capture_output=True, text=True, encoding="utf-8", timeout=300,
        )
        try:
            out = json.loads(p.stdout)
            if not out.get("is_error") and "structured_output" in out:
                return out["structured_output"]
            err = str(out.get("result") or out.get("error") or p.stdout)[:200]
        except json.JSONDecodeError:
            err = (p.stdout + p.stderr).strip()[:200]
        print(f"   (model call failed, retry {attempt}/{retries}: {err})", flush=True)
        time.sleep(3 * attempt)
    raise RuntimeError(f"model call failed {retries} times: {err}")


# ─────────────────────────────── 2. THE TOOLS ────────────────────────────────
NPM = shutil.which("npm.cmd") or shutil.which("npm") or "npm"
SKIP = {"node_modules", "dist", "runs", ".git", "__pycache__"}


def list_files() -> str:
    files = [p for p in PROJECT.rglob("*") if p.is_file() and not SKIP & set(p.parts)]
    return "\n".join(str(p.relative_to(PROJECT)).replace("\\", "/") for p in sorted(files))


def read_file(path: str) -> str:
    return (PROJECT / path).read_text(encoding="utf-8")


def write_file(path: str, content: str) -> str:
    (PROJECT / path).write_text(content, encoding="utf-8")
    return f"wrote {path} ({len(content)} chars)"


def run_build() -> str:
    r = subprocess.run([NPM, "run", "build", "--silent"], cwd=PROJECT, capture_output=True, text=True)
    return "BUILD OK (0 errors)" if r.returncode == 0 else (r.stdout + r.stderr).strip()


def run_tests() -> str:
    b = run_build()
    if not b.startswith("BUILD OK"):
        return "BUILD FAILED — fix the build first:\n" + b
    r = subprocess.run([NPM, "test", "--silent"], cwd=PROJECT, capture_output=True, text=True)
    out = (r.stdout + r.stderr)
    if r.returncode == 0:
        n = re.search(r"pass (\d+)", out)
        return f"TESTS OK ({n.group(1) if n else '?'} passed)"
    keep = [ln for ln in out.splitlines() if ln.strip() and not ln.lstrip().startswith(("ℹ duration", "ℹ suites", "ℹ todo", "ℹ cancelled", "ℹ skipped"))]
    return "TESTS FAILED:\n" + "\n".join(keep)


def run_corpus() -> str:
    b = run_build()
    if not b.startswith("BUILD OK"):
        return "BUILD FAILED — fix the build first:\n" + b
    r = subprocess.run(["node", "corpus/replay.js"], cwd=PROJECT, capture_output=True, text=True, encoding="utf-8")
    return (r.stdout + r.stderr).strip()


def write_file_scoped(path: str, content: str) -> str:
    (PROJECT / path).parent.mkdir(parents=True, exist_ok=True)
    return write_file(path, content)


TOOLS = {"list_files": list_files, "read_file": read_file, "write_file": write_file_scoped,
         "run_build": run_build, "run_tests": run_tests, "run_corpus": run_corpus}

# ───────────────────────── 4/5/6. BUDGET · SCOPE · GUARDRAILS ────────────────
MAX_STEPS = 30
MAX_REPEATS = 3
MAX_RESULT_CHARS = 8000

WRITABLE = ("src/",)                  # the tests and the corpus are the contract; package.json is the PR's job
REPORT = "review/corpus-diffs.md"     # review mode: the one extra file the agent may write

FORBIDDEN = {
    "`any`":            r"\bas any\b|:\s*any\b",
    "non-null `!`":     r"[\w)\]]!(?![=])",
    "@ts-ignore":       r"@ts-(ignore|expect-error)",
}


def execute(action: dict, writable: tuple = WRITABLE) -> str:
    tool, args = action["tool"], dict(action.get("args") or {})
    if tool not in TOOLS:
        return f"ERROR: unknown tool '{tool}'"
    if tool == "write_file":
        path = str(args.get("path", "")).replace("\\", "/")
        if ".." in path or not path.startswith(writable):
            return f"REFUSED: '{path}' is outside the writable scope {writable}. Migrate the source; the tests, the corpus and package.json stay as they are."
        hits = [name for name, pat in FORBIDDEN.items() if path.endswith(".ts") and re.search(pat, str(args.get("content", "")))]
        if hits:
            return f"REFUSED: that write would silence an error with {', '.join(hits)}. Fix the real cause instead."
    try:
        return str(TOOLS[tool](**args))[:MAX_RESULT_CHARS]
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


# ──────────────────────────────── 3. THE LOOP ────────────────────────────────
def render(goal: str, history: list) -> str:
    lines = [f"GOAL: {goal}", ""]
    for h in history:
        a = h["action"]
        argtxt = ", ".join(f"{k}={json.dumps(v)[:80]}" for k, v in (a.get("args") or {}).items())
        lines += [f"[step {h['step']}] you called {a['tool']}({argtxt})", "→ " + h["result"], ""]
    lines.append(f"Step {len(history) + 1}. Decide the single next action.")
    return "\n".join(lines)


def _check_done(mode: str) -> tuple:
    """The harness checks the definition of done itself. Returns (exit_code or None, message)."""
    t = run_tests()
    if not t.startswith("TESTS OK"):
        return None, "NOT DONE — the harness re-ran the tests:\n" + t[:1500]
    c = run_corpus()
    m = re.search(r"DIFFERENT\s*:\s*(\d+)", c)
    n = int(m.group(1)) if m else -1
    if n == 0:
        return 0, f"{t} · corpus: 0 differences"
    if mode == "zero":
        return None, f"NOT DONE — the harness re-ran the corpus: {n} differences remain.\n" + c[:2500]
    report = PROJECT / REPORT
    if not report.exists():
        return None, f"NOT DONE — {n} corpus differences remain and {REPORT} doesn't exist yet."
    text = report.read_text(encoding="utf-8")
    groups = re.findall(r"^\[\d+\] (.+)$", c, flags=re.M)
    missing = [g for g in groups if g not in text]
    if missing:
        return None, f"NOT DONE — {REPORT} doesn't cover these groups (copy each heading line exactly): " + "; ".join(missing)
    return 4, f"{t} · corpus: {n} differences, written up in {REPORT}"


def run(goal: str, max_steps: int = MAX_STEPS, mode: str = "zero") -> int:
    RUNS.mkdir(exist_ok=True)
    log_path = RUNS / time.strftime("%Y%m%d-%H%M%S.jsonl")
    history, seen = [], {}
    writable = WRITABLE + (("review/",) if mode == "review" else ())
    print(f"agent: upgrade-fixer   mode = {mode}   budget = {max_steps} steps   log = {log_path.name}", flush=True)
    print(f"goal: {goal[:110]}…\n", flush=True)
    for step in range(1, max_steps + 1):
        action = ask_model(SYSTEM, render(goal, history))
        argtxt = ", ".join(f"{k}={str(v)[:60]!r}" for k, v in (action.get("args") or {}).items() if k != "content")
        print(f"── step {step} ── {action['tool']}({argtxt})", flush=True)
        print(f"   thought: {action['thought'][:160]}", flush=True)
        if action["tool"] == "done":
            code, check = _check_done(mode)
            if code is not None:
                _log(log_path, step, action, "DONE · " + check)
                summary = (action.get("args") or {}).get("summary", "")
                if code == 4:
                    return _finish(4, f"🟡 handing back to a human after {step} steps — {check}\n   agent's summary: {summary}")
                return _finish(0, f"✅ done in {step} steps — {check}\n   agent's summary: {summary}")
            result = check
        else:
            result = execute(action, writable)
        _log(log_path, step, action, result)
        preview = result if len(result) < 400 else result[:400] + " …"
        print("   result : " + preview.replace("\n", "\n            "), flush=True)
        history.append({"step": step, "action": action, "result": result})
        key = json.dumps(action["tool"]) + json.dumps(action.get("args"), sort_keys=True)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] >= MAX_REPEATS:
            return _finish(3, f"⛔ stuck: repeated {action['tool']} {MAX_REPEATS}× with the same arguments. Handing back to a human.")
    return _finish(2, f"⛔ hit the {max_steps}-step budget without finishing. Handing back to a human — last result:\n{history[-1]['result'][:600] if history else ''}")


# ─────────────────────────── 7. THE LOG + HAND-BACK ──────────────────────────
def _log(path: Path, step: int, action: dict, result: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"step": step, "action": action, "result": result}) + "\n")


def _finish(code: int, message: str) -> int:
    print("\n" + message, flush=True)
    return code


if __name__ == "__main__":
    argv = sys.argv[1:]
    mode = argv[argv.index("--mode") + 1] if "--mode" in argv else "zero"
    steps = int(argv[argv.index("--max-steps") + 1]) if "--max-steps" in argv else MAX_STEPS
    flagvals = {argv[i + 1] for i, a in enumerate(argv[:-1]) if a in ("--mode", "--max-steps")}
    goal = next((a for a in argv if not a.startswith("--") and a not in flagvals), GOALS[mode])
    sys.exit(run(goal, steps, mode))
