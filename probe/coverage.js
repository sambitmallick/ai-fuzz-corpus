// Coverage: zod 4 changed 7 behaviours that compile (ep23's probe). How many of them did
// yesterday's traffic actually exercise? A replay can only catch what the traffic contains.
// Run:  node probe/coverage.js
const fs = require("fs");
const path = require("path");

const dir = path.join(__dirname, "..", "corpus");
const file = fs.readdirSync(dir).filter((f) => /^signups-.*\.jsonl$/.test(f)).sort().pop();
const rows = fs.readFileSync(path.join(dir, file), "utf8").trim().split("\n").map((l) => JSON.parse(l)).map((r) => r.input);

const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RFC = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const units = (s) => s.length, points = (s) => [...s].length;

const CHANGES = [
  ["UUIDs must have RFC version/variant bits", "Signup.id",
    (s) => typeof s.id === "string" && UUID_SHAPE.test(s.id) && !RFC.test(s.id)],
  ["IPv6 zone ids (fe80::1%eth0) rejected", "Signup.ip, Config.hosts",
    (s) => typeof s.ip === "string" && s.ip.includes("%")],
  ["z.number() rejects ±Infinity", "Signup.age, Config.timeoutMs",
    (s) => s.age === Infinity || s.age === -Infinity],          // JSON can't even carry it
  [".int() now means SAFE integer", "Signup.age",
    (s) => typeof s.age === "number" && Number.isInteger(s.age) && !Number.isSafeInteger(s.age)],
  ["datetime() requires seconds", "(no field uses it)",
    () => false],
  [".max() counts characters, not UTF-16 units", "Signup.name",
    (s) => typeof s.name === "string" && units(s.name) > 80 && points(s.name) <= 80],
  [".default({}) no longer fills inner defaults", "Signup.prefs",
    (s) => s.prefs === undefined],
];

console.log(`CORPUS ${file}: ${rows.length} signups. Config: 0 rows (config isn't traffic).\n`);
console.log("zod 4 behaviour change (compiles)              field                          requests");
let hit = 0;
for (const [what, where, pred] of CHANGES) {
  const n = rows.filter(pred).length;
  if (n) hit++;
  console.log(`${what.padEnd(46)} ${where.padEnd(30)} ${n ? String(n).padStart(4) : "   0  ← invisible to the replay"}`);
}
console.log(`\nThe corpus exercises ${hit} of ${CHANGES.length} behaviour changes. The other ${CHANGES.length - hit} can't show up as a difference, however long the agent runs.`);
