// Record yesterday's signup traffic, and the answer production gave it, as a golden corpus.
//
// In production this is a tap on the signup endpoint: every request body (scrubbed) plus the
// verdict the running code returned. Here the traffic is simulated (seeded, reproducible) with
// the shapes real signups have: two ID generators, IPv4 + IPv6, typos, bots, emoji names.
// The answers are real: they come from the zod 3 build that was on main.
//
// Run on main (zod 3):  npm run build && node corpus/capture.js
const fs = require("fs");
const path = require("path");
const { parseSignup } = require("../dist/src");
const { answer } = require("./canon");

const DAY = "2026-10-15";
const N = 400;

let seed = 20261015;
const rnd = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
const pick = (a) => a[Math.floor(rnd() * a.length)];
const int = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
const hex = (n) => Array.from({ length: n }, () => "0123456789abcdef"[Math.floor(rnd() * 16)]).join("");

// Web + new mobile apps: crypto.randomUUID() -> RFC 4122 v4 (version nibble 4, variant 8-b).
const uuidV4 = () => `${hex(8)}-${hex(4)}-4${hex(3)}-${pick(["8", "9", "a", "b"])}${hex(3)}-${hex(12)}`;
// Android app 1.x, still installed on old phones: a home-grown generator, 32 random hex digits
// in UUID shape. Never set the version/variant bits.
const legacyId = () => `${hex(8)}-${hex(4)}-${hex(4)}-${hex(4)}-${hex(12)}`;

const FIRST = ["Ada", "Grace", "Linus", "Margaret", "Ken", "Barbara", "Dennis", "Radia", "Tim", "Hedy",
  "Alan", "Katherine", "Priya", "Wei", "Amara", "Mateo", "Sofía", "Jürgen", "Aiko", "Olu", "Zoë", "Ravi"];
const LAST = ["Lovelace", "Hopper", "Torvalds", "Hamilton", "Thompson", "Liskov", "Ritchie", "Perlman",
  "Berners-Lee", "Lamarr", "Turing", "Johnson", "Nair", "Zhang", "Okafor", "García", "Müller", "Tanaka"];
const DOMAINS = ["example.com", "mail.example.org", "example.co.uk", "corp.example.net"];
const TYPOS = ["{u}@example", "{u}.example.com", "{u}@@example.com", "{u}@example..com", "{u} @example.com"];
// Display names people actually type. Each emoji is 2 UTF-16 units but 1 code point.
const FANCY = ["✨🌸 Priya 🌸✨", "🎮🎮🎮 Mateo 🎮🎮🎮", "🦄"];

function email(first, last, i) {
  // Scrubbed at capture: identity replaced, SHAPE kept (dots, +tags, case, subdomains).
  const u = `${first}.${last}`.toLowerCase().normalize("NFD").replace(/[^a-z.]/g, "") + (i % 7 === 0 ? "+news" : "");
  if (rnd() < 0.03) return pick(TYPOS).replace("{u}", u);
  return `${u}@${pick(DOMAINS)}`;
}

function ip(i) {
  if (i % 97 === 41) return "fe80::1%eth0"; // the office network: link-local IPv6 with a zone id
  if (rnd() < 0.14) return `2001:db8:${hex(4)}::${hex(2)}`;
  return `${pick([10, 81, 103, 172, 203])}.${int(0, 255)}.${int(0, 255)}.${int(1, 254)}`;
}

function signup(i) {
  const first = pick(FIRST), last = pick(LAST);
  const s = {
    id: rnd() < 0.045 ? legacyId() : uuidV4(),
    email: email(first, last, i),
    name: `${first} ${last}`,
    ip: ip(i),
    plan: rnd() < 0.7 ? "free" : rnd() < 0.75 ? "pro" : "team",
    flags: rnd() < 0.5 ? { beta: rnd() < 0.3 } : rnd() < 0.5 ? {} : { beta: true, newCheckout: rnd() < 0.5 },
  };
  if (rnd() < 0.35) s.age = int(16, 74);
  if (rnd() < 0.2) s.website = `https://${last.toLowerCase().normalize("NFD").replace(/[^a-z]/g, "")}.example.com`;
  const p = rnd();
  if (p < 0.3) s.prefs = { theme: "dark" };
  else if (p < 0.45) s.prefs = { theme: pick(["light", "dark"]), retries: String(int(1, 9)) };
  // else: no prefs at all -> the defaults fill them in
  return s;
}

const reqs = [];
for (let i = 0; i < N; i++) reqs.push(signup(i));

// The long tail every real endpoint gets.
reqs[37].age = 1e21;                       // a bot filling every number field with 1e21
reqs[203].age = 9007199254740993;          // ...and one with 2^53 + 1
reqs[311].age = 12;                        // too young: rejected, then and now
reqs[58].name = "";                        // empty name
reqs[129].name = "A".repeat(81);           // pasted something long
reqs[88].name = `${FANCY[0]} ${"🌸".repeat(36)}`;  // 48 code points, 86 UTF-16 units
reqs[176].name = `${FANCY[1]} ${"🎮".repeat(36)}`;  // 50 code points, 92 UTF-16 units
reqs[264].name = FANCY[2].repeat(42);      // 42 unicorns: 42 code points, 84 UTF-16 units
reqs[333].plan = "enterprise";             // a plan that doesn't exist
reqs[150].flags = { beta: "yes" };         // a form that sends strings

const out = path.join(__dirname, `signups-${DAY}.jsonl`);
const lines = reqs.map((input, i) => JSON.stringify({ n: i + 1, at: `${DAY}T${String(Math.floor((i / N) * 24)).padStart(2, "0")}:${String(int(0, 59)).padStart(2, "0")}:00Z`, input, answer: answer(parseSignup(input)) }));
fs.writeFileSync(out, lines.join("\n") + "\n");
const ok = lines.filter((l) => JSON.parse(l).answer.ok).length;
console.log(`recorded ${N} signups from ${DAY} -> ${path.relative(process.cwd(), out)}  (zod 3 accepted ${ok}, rejected ${N - ok})`);
