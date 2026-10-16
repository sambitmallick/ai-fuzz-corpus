// Differential fuzzing: zod 3 (the oracle, as it was on main) vs the current build (zod 4).
// HARNESS-OWNED: the agent may read this file, never write it. The generators are the agent's job.
// Run:  npm run build && node fuzz/run.js
const path = require("path");
const v8 = require("v8");
const { spawnSync } = require("child_process");
const { answer, key } = require("../corpus/canon");
const oracle = require("../oracle/zod3");
const now = require("../dist/src");

const N = 5000, SEED = 20261016;

// The generators are the agent's code. They run in a separate process with read-only file access
// (Node's permission model): no writes, no child processes, no workers. Only sample DATA comes back.
// (ep25: the first harness `require`d them here, and a generators file could print a fake COVERAGE
// line or rewrite this file.)
const ROOT = path.resolve(__dirname, "..");
const child = spawnSync(process.execPath,
  ["--permission", `--allow-fs-read=${ROOT}`, path.join(__dirname, "sample.js"), String(N), String(SEED)],
  { cwd: ROOT, encoding: "utf8", maxBuffer: 512 * 1024 * 1024 });
if (child.stderr) process.stderr.write("--- generator output (untrusted, not read by the harness) ---\n" + child.stderr.slice(0, 4000) + "\n");
if (child.status !== 0) {
  console.log(`FUZZ FAILED: fuzz/generators.js could not be sampled (exit ${child.status}). See the generator output.`);
  process.exit(2);
}
const samples = v8.deserialize(Buffer.from(child.stdout, "base64"));

// zod 4 behaviour changes that compile (ep23's probe), and how to tell an input exercises one.
const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RFC = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isInf = (v) => v === Infinity || v === -Infinity;
const CHANGES = [
  ["UUID version/variant bits",        "signup", "id",        (s) => typeof s.id === "string" && UUID_SHAPE.test(s.id) && !RFC.test(s.id)],
  ["IPv6 zone ids (fe80::1%eth0)",     "signup", "ip",        (s) => typeof s.ip === "string" && s.ip.includes("%")],
  ["IPv6 zone ids in config hosts",    "config", "hosts",     (c) => Array.isArray(c.hosts) && c.hosts.some((h) => typeof h === "string" && h.includes("%"))],
  ["z.number() rejects Infinity",      "config", "timeoutMs", (c) => isInf(c.timeoutMs)],
  [".int() means SAFE integer",        "signup", "age",       (s) => typeof s.age === "number" && Number.isInteger(s.age) && !Number.isSafeInteger(s.age)],
  [".max() counts characters",         "signup", "name",      (s) => typeof s.name === "string" && s.name.length > 80 && [...s.name].length <= 80],
  [".default({}) and inner defaults",  "signup", "prefs",     (s) => s.prefs === undefined],
];
const UNREACHABLE = ["datetime() requires seconds (no field uses datetime)"];

function differential(name, xs, a, b) {
  const groups = {};
  const results = [];
  for (const x of xs) {
    const A = answer(a(x)), B = answer(b(x));
    results.push({ x, A });
    if (key(A) === key(B)) continue;
    let g;
    if (!A.ok && !B.ok) g = "rejected by both, but different fields reported";
    else {
      // both accepted, value differs: name the fields whose PARSED VALUE changed (the first harness crashed here)
      const changed = A.ok && B.ok ? Object.keys({ ...A.value, ...B.value }).filter((k) => JSON.stringify(A.value[k]) !== JSON.stringify(B.value[k])) : null;
      const f = [...new Set((changed || (A.ok ? B.fields : A.fields) || ["value"]).map((p) => p.split(".")[0]))].join(",");
      g = A.ok && !B.ok ? `${f} was ACCEPTED, now REJECTED` : !A.ok && B.ok ? `${f} was REJECTED, now ACCEPTED` : `${f} accepted, but the PARSED VALUE changed`;
    }
    (groups[`${name}: ${g}`] ||= []).push({ x, was: A, now: B });
  }
  return { xs: results, groups };
}

const rep = (k, v) => (typeof v === "number" && !Number.isFinite(v) ? `__${v}__` : v);
const short = (v, n = 70) => { const s = JSON.stringify(v, rep)?.replace(/"__(-?Infinity|NaN)__"/g, "$1"); return s === undefined ? "undefined" : s.length > n ? s.slice(0, n - 1) + "…" : s; };

const S = differential("signup", samples.signup, oracle.parseSignup, now.parseSignup);
const C = differential("config", samples.config, oracle.parseConfig, now.parseConfig);
const groups = { ...S.groups, ...C.groups };
const total = Object.values(groups).reduce((n, g) => n + g.length, 0);

console.log(`FUZZ: ${N} signups + ${N} configs from fuzz/generators.js (seed ${SEED}, sandboxed), zod 3 oracle vs current build`);
console.log(`  same answer : ${2 * N - total}`);
console.log(`  DIFFERENT   : ${total}`);
for (const [g, ds] of Object.entries(groups).sort((p, q) => q[1].length - p[1].length)) {
  console.log(`\n[${ds.length}] ${g}`);
  for (const d of ds.slice(0, 3)) {
    const field = (d.now.ok ? (d.was.fields || Object.keys(d.x).filter((k) => JSON.stringify(d.was.value?.[k]) !== JSON.stringify(d.now.value?.[k]))) : d.now.fields || []).map((p) => p.split(".")[0])[0];
    const shown = field && d.x[field] !== undefined ? { [field]: d.x[field] } : d.x;
    console.log(`   ${short(shown)}   zod3: ${d.was.ok ? "ok" : (d.was.fields || []).join(",")}  now: ${d.now.ok ? "ok" : (d.now.fields || []).join(",")}`);
  }
}

// Coverage: an input only counts as exercising a change if NOTHING ELSE about it is wrong
// (zod 3 accepted it, or the only field zod 3 complained about is the field under test).
console.log(`\nCOVERAGE (an input counts only if every other field is valid):`);
let covered = 0;
for (const [what, schema, field, pred] of CHANGES) {
  const pool = schema === "signup" ? S.xs : C.xs;
  const n = pool.filter(({ x, A }) => pred(x) && (A.ok || (A.fields || []).every((f) => f.split(".")[0] === field))).length;
  if (n) covered++;
  console.log(`  ${n ? "covered" : "MISSING"}  ${what.padEnd(38)} ${String(n).padStart(5)} isolated inputs`);
}
for (const u of UNREACHABLE) console.log(`  n/a      ${u}`);
console.log(`COVERAGE: ${covered} of ${CHANGES.length} reachable behaviour changes`);
process.exit(total ? 1 : 0);
