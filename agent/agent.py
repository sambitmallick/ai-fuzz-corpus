#!/usr/bin/env python3
"""
agent.py -- ep25: the upgrade agent becomes the investigator.

Last episode the corpus replay covered what yesterday's traffic sent, and nothing else. This
episode the agent gets a differential fuzzer: fast-check generators, run through zod 3 (the
oracle, as it was on main) and the current zod 4 build side by side.

    new tool          run_fuzz()       build, then fuzz/run.js: every group of different answers + COVERAGE
    new scope         WRITABLE         ONLY fuzz/generators.js and review/. Not src/: it investigates, it doesn't fix.
    phase gate        run()            once the HARNESS reports complete coverage, the generators freeze
    done-gate         _check_done()    the harness re-runs the fuzzer: coverage must be complete, and
                                       review/fuzz-findings.md must cover every difference group.
    hand-back         exit 4           always: a human decides what matters.

    1. the model call      ask_model()      stateless, retried; the harness is the memory
    2. the tools           TOOLS            list / read / write / run_build / run_tests / run_corpus / run_fuzz
    3. the loop            run()            perceive -> decide -> act -> observe
    4. budget              MAX_STEPS        30
    5. scope               WRITABLE         fuzz/generators.js + review/ only
    6. guardrails          FORBIDDEN        no `any`, no non-null `!`, no @ts-ignore (in .ts)
    7. the log + hand-back runs/*.jsonl     exit 2 budget · 3 stuck · 4 needs a human · 5 model unavailable

Usage:  python agent/agent.py [--max-steps N] ["<goal>"]
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

GOALS = {
    "triage": ("signupkit was upgraded from zod 3.25 to zod 4.6 and merged. The build, the tests and a replay "
               "of yesterday's traffic (corpus/) all passed, but the replay can only see what yesterday's traffic "
               "sent. Your job is to find what it missed. fuzz/run.js runs your generators (fuzz/generators.js) "
               "through zod 3 (oracle/zod3.js, the code as it was before the upgrade) and the current build side "
               "by side, groups every different answer, and reports COVERAGE of zod 4's behaviour changes. "
               "1) Improve fuzz/generators.js until COVERAGE is complete. 2) For EVERY group of differences, decide "
               "MATTERS or NOISE, with evidence and a reason. 3) Write review/fuzz-findings.md: one section per group "
               "(copy the group's heading line from run_fuzz exactly), what changed, how many inputs, MATTERS or "
               "NOISE, why, and what a human should do. You may only write fuzz/generators.js and files under "
               "review/. Do not change src/, test/, corpus/, oracle/ or fuzz/run.js: you investigate, a human decides."),
}

# ───────────────────────────── 1. THE MODEL CALL ─────────────────────────────
CLAUDE = shutil.which("claude") or r"C:\Users\sambi\.local\bin\claude.exe"

ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string"},
        "tool": {"type": "string", "enum": ["list_files", "read_file", "write_file", "run_build", "run_tests", "run_corpus", "run_fuzz", "done"]},
        "args": {"type": "object"},
    },
    "required": ["thought", "tool", "args"],
    "additionalProperties": False,
}

SYSTEM = """You are the decision-maker inside a small coding agent. You have no tools of your own.
Each turn you choose ONE action; the harness executes it and shows you the result.

Tools:
  list_files()               -> the files in the project (source, tests, config)
  read_file(path, offset=0)  -> the contents of a file (long files come in parts; the result says so). Anything, including
                                node_modules/<package>/... (the installed library's own types and docs)
  write_file(path, content)  -> replace a file's ENTIRE contents. Only fuzz/generators.js and review/ are writable.
  run_build()                -> `npm run build` (strict tsc); returns the errors, or BUILD OK
  run_tests()                -> builds, then `npm test`; returns the failures, or TESTS OK
  run_corpus()               -> builds, then replays yesterday's production traffic (corpus/) through
                                the code; lists every request whose answer changed, grouped
  run_fuzz()                 -> builds, then fuzz/run.js: zod 3 vs the current build on 5000 generated
                                signups + 5000 configs; every group of different answers, and COVERAGE
  done(summary)              -> finish. The harness re-checks everything before it accepts.

Rules: you are investigating, not fixing. Base every claim on evidence you got from a tool, and
say when something is a guess. Never edit src/, test/, corpus/, oracle/, fuzz/run.js, package.json
or anything outside the writable scope. Reply with JSON only: {"thought": "...", "tool": "...", "args": {...}}"""


MODEL_TIMEOUT = 600   # a full generators file takes a while to write


def ask_model(system: str, prompt: str, retries: int = 3) -> dict:
    err = ""
    for attempt in range(1, retries + 1):
        try:
            p = subprocess.run(
                [CLAUDE, "-p", "--no-session-persistence", "--tools", "",
                 "--output-format", "json", "--system-prompt", system,
                 "--json-schema", json.dumps(ACTION_SCHEMA)],
                input=prompt, capture_output=True, text=True, encoding="utf-8", timeout=MODEL_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            # ep25 run 1 died here: the retry caught bad replies, not a call that never came back.
            err = f"no reply within {MODEL_TIMEOUT}s"
            print(f"   (model call failed, retry {attempt}/{retries}: {err})", flush=True)
            continue
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


def read_file(path: str, offset: int = 0) -> str:
    text = (PROJECT / path).read_text(encoding="utf-8")
    offset = max(0, int(offset))
    part = text[offset:offset + MAX_RESULT_CHARS]
    rest = len(text) - offset - len(part)
    # ep25 run 4 rewrote its findings five times because reads were cut off SILENTLY and it
    # couldn't tell whether its own file was complete. Say what was cut, and how to get it.
    if rest > 0:
        part += f"\n[... {rest} more chars not shown. read_file(path, offset={offset + len(part)}) for the next part. The file itself is complete: {len(text)} chars.]"
    return part


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


def _fuzz() -> tuple:
    """(harness output, untrusted generator output). The done-gate reads ONLY the first."""
    b = run_build()
    if not b.startswith("BUILD OK"):
        return "BUILD FAILED -- fix the build first:\n" + b, ""
    r = subprocess.run(["node", "fuzz/run.js"], cwd=PROJECT, capture_output=True, text=True, encoding="utf-8")
    return r.stdout.strip(), r.stderr.strip()


def run_fuzz() -> str:
    out, untrusted = _fuzz()
    return out + ("\n\n" + untrusted if untrusted else "")


TOOLS = {"list_files": list_files, "read_file": read_file, "write_file": write_file_scoped,
         "run_build": run_build, "run_tests": run_tests, "run_corpus": run_corpus, "run_fuzz": run_fuzz}

# ───────────────────────── 4/5/6. BUDGET · SCOPE · GUARDRAILS ────────────────
MAX_STEPS = 30
MAX_REPEATS = 3
MAX_RESULT_CHARS = 8000

WRITABLE = ("fuzz/generators.js", "review/")                  # the tests and the corpus are the contract; package.json is the PR's job
REPORT = "review/fuzz-findings.md"     # review mode: the one extra file the agent may write

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
        if ".." in path or not any(path == w or (w.endswith("/") and path.startswith(w)) for w in writable):
            return f"REFUSED: '{path}' is outside the writable scope {writable}. You investigate: only fuzz/generators.js and review/ are writable. The code, the oracle, the corpus and the fuzz runner stay as they are."
        hits = [name for name, pat in FORBIDDEN.items() if path.endswith(".ts") and re.search(pat, str(args.get("content", "")))]
        if hits:
            return f"REFUSED: that write would silence an error with {', '.join(hits)}. Fix the real cause instead."
    try:
        out = str(TOOLS[tool](**args))
        if tool == "read_file" or len(out) <= MAX_RESULT_CHARS + 300:
            return out
        return out[:MAX_RESULT_CHARS] + f"\n[... output truncated: {len(out) - MAX_RESULT_CHARS} more chars not shown]"
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


# ──────────────────────────────── 3. THE LOOP ────────────────────────────────
def render(goal: str, history: list, max_steps: int = MAX_STEPS) -> str:
    lines = [f"GOAL: {goal}", ""]
    for h in history:
        a = h["action"]
        argtxt = ", ".join(f"{k}={json.dumps(v)[:80]}" for k, v in (a.get("args") or {}).items())
        lines += [f"[step {h['step']}] you called {a['tool']}({argtxt})", "→ " + h["result"], ""]
    n = len(history) + 1
    # ep25: two of three runs spent their budget polishing and never wrote the findings. Show the budget.
    lines.append(f"Step {n} of {max_steps} ({max_steps - n} left after this one). Decide the single next action.")
    return "\n".join(lines)


def coverage_complete(fuzz_result: str) -> bool:
    """Read ONLY the harness's part of a run_fuzz result (never the generators' untrusted output)."""
    trusted = fuzz_result.split("--- generator output (untrusted")[0]
    m = re.search(r"^COVERAGE: (\d+) of (\d+)", trusted, flags=re.M)
    return bool(m) and m.group(1) == m.group(2)


FROZEN_NOTE = ("\n\nHARNESS: coverage is complete. fuzz/generators.js is now FROZEN (writes refused): the fuzzer's job "
               "is done. Spend the remaining steps on review/fuzz-findings.md, then call done.")


def _repeating(seen: dict, action: dict, result: str) -> bool:
    """Thrashing = the same call, with the same arguments, against the same world.
    A successful write changes the world, so re-reading a file after editing it isn't a repeat.
    (ep24's first run tripped the old whole-run counter on exactly that.)"""
    if action["tool"] == "write_file" and result.startswith("wrote "):
        seen.clear()
    key = json.dumps(action["tool"]) + json.dumps(action.get("args"), sort_keys=True)
    seen[key] = seen.get(key, 0) + 1
    return seen[key] >= MAX_REPEATS


def _check_done(mode: str) -> tuple:
    """The harness checks the definition of done itself. Returns (exit_code or None, message)."""
    f, _untrusted = _fuzz()   # never parse the generators' own output (ep25: it could forge COVERAGE)
    m = re.search(r"^COVERAGE: (\d+) of (\d+)", f, flags=re.M)
    if not m:
        return None, "NOT DONE -- the harness re-ran the fuzzer and couldn't read COVERAGE:\n" + f[-1500:]
    if m.group(1) != m.group(2):
        return None, f"NOT DONE -- the harness re-ran the fuzzer: COVERAGE {m.group(1)} of {m.group(2)}.\n" + f[-2500:]
    report = PROJECT / REPORT
    if not report.exists():
        return None, f"NOT DONE -- coverage is complete, but {REPORT} doesn't exist yet."
    text = report.read_text(encoding="utf-8")
    groups = re.findall(r"^\[\d+\] (.+)$", f, flags=re.M)
    missing = [g for g in groups if g not in text]
    if missing:
        return None, f"NOT DONE -- {REPORT} doesn't cover these groups (copy each heading line exactly): " + "; ".join(missing)
    return 4, f"COVERAGE {m.group(1)} of {m.group(2)} · {len(groups)} difference groups, all written up in {REPORT}"

def run(goal: str, max_steps: int = MAX_STEPS, mode: str = "triage") -> int:
    RUNS.mkdir(exist_ok=True)
    log_path = RUNS / time.strftime("%Y%m%d-%H%M%S.jsonl")
    history, seen = [], {}
    writable = WRITABLE
    print(f"agent: upgrade-investigator   mode = {mode}   budget = {max_steps} steps   log = {log_path.name}", flush=True)
    print(f"goal: {goal[:110]}…\n", flush=True)
    for step in range(1, max_steps + 1):
        try:
            action = ask_model(SYSTEM, render(goal, history, max_steps))
        except RuntimeError as e:
            _log(log_path, step, {"tool": "(model)", "thought": "", "args": {}}, str(e))
            return _finish(5, f"⛔ the model is unavailable ({e}). Handing back to a human, work so far is in the log.")
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
            # the phase gate: once the HARNESS says coverage is complete, the generators are frozen
            if action["tool"] == "run_fuzz" and "fuzz/generators.js" in writable and coverage_complete(result):
                writable = tuple(w for w in writable if w != "fuzz/generators.js")
                result += FROZEN_NOTE
        _log(log_path, step, action, result)
        preview = result if len(result) < 400 else result[:400] + " …"
        print("   result : " + preview.replace("\n", "\n            "), flush=True)
        history.append({"step": step, "action": action, "result": result})
        if _repeating(seen, action, result):
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
    mode = argv[argv.index("--mode") + 1] if "--mode" in argv else "triage"
    steps = int(argv[argv.index("--max-steps") + 1]) if "--max-steps" in argv else MAX_STEPS
    flagvals = {argv[i + 1] for i, a in enumerate(argv[:-1]) if a in ("--mode", "--max-steps")}
    goal = next((a for a in argv if not a.startswith("--") and a not in flagvals), GOALS[mode])
    sys.exit(run(goal, steps, mode))
