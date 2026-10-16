// Replay the golden corpus through the CURRENT build. Which requests get a different answer?
// Run:  npm run build && node corpus/replay.js [--json]
const fs = require("fs");
const path = require("path");
const { parseSignup } = require("../dist/src");
const { answer, key } = require("./canon");

const file = fs.readdirSync(__dirname).filter((f) => /^signups-.*\.jsonl$/.test(f)).sort().pop();
const rows = fs.readFileSync(path.join(__dirname, file), "utf8").trim().split("\n").map((l) => JSON.parse(l));

const short = (v, n = 52) => { const s = JSON.stringify(v); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

// Where does a value differ? The first differing path, e.g. "prefs.theme".
function where(a, b, p = "") {
  if (JSON.stringify(a) === JSON.stringify(b)) return null;
  if (a && b && typeof a === "object" && typeof b === "object") {
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      const w = where(a[k], b[k], p ? `${p}.${k}` : k);
      if (w) return w;
    }
  }
  return p || "(root)";
}

const diffs = [];
for (const r of rows) {
  const now = answer(parseSignup(r.input));
  if (key(now) === key(r.answer)) continue;
  const was = r.answer;
  let field, change;
  if (was.ok && !now.ok) { field = now.fields.join(","); change = "was ACCEPTED, now REJECTED"; }
  else if (!was.ok && now.ok) { field = was.fields.join(","); change = "was REJECTED, now ACCEPTED"; }
  else if (was.ok && now.ok) { field = where(was.value, now.value); change = "accepted, but the PARSED VALUE changed"; }
  else { field = [...new Set([...was.fields, ...now.fields])].join(","); change = "rejected, but for a different field"; }
  const top = change.startsWith("rejected, but") ? field : field.split(/[.,]/)[0];
  const detail = was.ok && now.ok
    ? `${field}: was ${short(field.split(".").reduce((o, k) => o?.[k], was.value))} now ${short(field.split(".").reduce((o, k) => o?.[k], now.value))}`
    : now.ok ? `${field}: zod 3 said "${(was.problems || [])[0] || "?"}"` : `${now.problems[0]}`;
  diffs.push({ n: r.n, group: `${top} — ${change}`, input: r.input[top.split(",")[0]], detail });
}

if (process.argv.includes("--json")) { console.log(JSON.stringify({ file, total: rows.length, diffs }, null, 1)); process.exit(0); }

console.log(`CORPUS ${file}: ${rows.length} recorded requests (answers from production, zod 3)`);
console.log(`  same answer : ${rows.length - diffs.length}`);
console.log(`  DIFFERENT   : ${diffs.length}`);
const groups = {};
for (const d of diffs) (groups[d.group] ||= []).push(d);
for (const [g, ds] of Object.entries(groups)) {
  console.log(`\n[${ds.length}] ${g}`);
  for (const d of ds.slice(0, 4)) console.log(`   #${String(d.n).padEnd(4)} ${short(d.input, 60).padEnd(62)} ${d.detail}`);
  if (ds.length > 4) console.log(`   … and ${ds.length - 4} more`);
}
if (!diffs.length) console.log("\nCORPUS OK: yesterday's inputs get yesterday's answers.");
process.exit(diffs.length ? 1 : 0);
