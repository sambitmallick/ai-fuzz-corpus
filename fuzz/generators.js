// Input generators for the differential fuzzer (fuzz/run.js). fast-check arbitraries.
// Exports { signup, config }.
//
// ---------------------------------------------------------------------------
// WHY IT LOOKS LIKE THIS (1): ONE FIELD AT A TIME
// ---------------------------------------------------------------------------
// fuzz/run.js only counts an input as exercising a zod 4 behaviour change when
// *every other field is valid* (zod 3 accepted it, or the only field zod 3
// complained about is the field under test). The first draft threw garbage at
// every field at once and scored 2/7: nearly every input had three other things
// wrong with it, so it proved nothing about the change under test and its diffs
// all collapsed into one unreadable "rejected by both" bucket.
//
// So each branch below starts from a BASELINE that zod 3 and zod 4 both accept
// (dotted-quad IPv4, ascii name, lowercase RFC uuid, plain user@host.com,
// fully specified prefs so no default machinery is involved) and replaces
// exactly ONE field with a pool aimed at a known change, written to straddle
// that change's boundary (just inside / just outside). Every diff then names
// its own cause. Optional fields are generated both ways -- key omitted and
// key present with value undefined -- because zod 4 can treat those
// differently. One small `chaos` branch still perturbs several fields at once,
// to check that multi-field error reports still compose as they did.
//
// ---------------------------------------------------------------------------
// WHY IT LOOKS LIKE THIS (2): WITHHELD "VALUE ONLY" DIFFERENCES
// ---------------------------------------------------------------------------
// fuzz/run.js:38 does
//     (A.ok ? B.fields : A.fields || ["value"]).map(...)
// so when BOTH versions accept an input but return a DIFFERENT parsed value,
// B.fields is undefined and the fuzzer throws TypeError before printing
// anything -- its own `accepted, but the PARSED VALUE changed` group is
// unreachable. I may not edit run.js, and a crash would hide all the other
// groups, so the exported arbitraries .filter() those inputs out, count them,
// and print them (grouped by the field whose value changed) from a
// process-exit hook, together with a small fixed PROBE table. That output is
// evidence, not decoration: see review/fuzz-findings.md.

const fc = require("fast-check");
const { answer, key } = require("../corpus/canon");
const oracle = require("../oracle/zod3");
const build = require("../dist/src");

/* ----------------------------------------------------------------- helpers */

const W = (weight, arbitrary) => ({ arbitrary, weight });
const hex = (n) => fc.stringMatching(new RegExp(`^[0-9a-f]{${n}}$`));
const pick = (chars) => fc.constantFrom(...chars.split(""));

// A uuid-SHAPED string with chosen version / variant nibbles.
const uuidOf = (versions, variants) =>
  fc
    .tuple(hex(8), hex(4), pick(versions), hex(3), pick(variants), hex(3), hex(12))
    .map(([a, b, ver, c, vari, d, e]) => `${a}-${b}-${ver}${c}-${vari}${d}-${e}`);

// "key present, value undefined" -> "key omitted".
const strip = (o) => {
  const out = {};
  for (const k of Object.keys(o)) if (o[k] !== undefined) out[k] = o[k];
  return out;
};

const repeat = (s, n) => s.repeat(n);
const astral = (min, max) =>
  fc
    .array(fc.constantFrom("\u{1F600}", "\u{1F680}", "\u{1F389}", "\u{1D306}", "\u{1F44D}"), { minLength: min, maxLength: max })
    .map((a) => a.join(""));

const shortJson = (v, n = 46) => {
  let s;
  try {
    s = JSON.stringify(v, (_k, x) => (typeof x === "number" && !Number.isFinite(x) ? String(x) : x));
  } catch {
    s = String(v);
  }
  if (s === undefined) s = "undefined";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
};

/* ------------------------------------------- baseline: accepted by BOTH */

const baseId = uuidOf("1234", "89ab"); // RFC version + variant: fine under either check
const baseEmail = fc
  .tuple(fc.stringMatching(/^[a-z][a-z0-9]{0,6}$/), fc.stringMatching(/^[a-z][a-z0-9]{0,6}$/), fc.constantFrom("com", "org", "io"))
  .map(([local, host, tld]) => `${local}@${host}.${tld}`);
const baseName = fc.stringMatching(/^[A-Za-z][A-Za-z ]{0,18}$/);
const baseAge = fc.integer({ min: 13, max: 120 });
const baseUrl = fc
  .tuple(fc.constantFrom("http", "https"), fc.stringMatching(/^[a-z][a-z0-9]{1,6}$/), fc.constantFrom("com", "org", "io"), fc.constantFrom("", "/"))
  .map(([scheme, host, tld, path]) => `${scheme}://${host}.${tld}${path}`);
const baseIp = fc.ipV4(); // deliberately NOT IPv6: keeps every ip diff attributable
const basePlan = fc.constantFrom("free", "pro", "team");
const baseFlags = fc.dictionary(fc.stringMatching(/^[a-z][a-z0-9_]{0,6}$/), fc.boolean(), { maxKeys: 3 });
const basePrefs = fc.record({ theme: fc.constantFrom("light", "dark"), retries: fc.integer({ min: 0, max: 20 }).map(String) });

const baseSignup = fc.record({
  id: baseId,
  email: baseEmail,
  name: baseName,
  age: baseAge,
  website: baseUrl,
  ip: baseIp,
  plan: basePlan,
  flags: baseFlags,
  prefs: basePrefs,
});

const baseConfig = fc.record({
  port: fc.constantFrom("8080", "3000"),
  hosts: fc.array(fc.ipV4(), { minLength: 1, maxLength: 3 }),
  timeoutMs: fc.constantFrom(5000, 1, 250.5),
});

// Replace exactly one field. keepUndefined=true keeps the key with value
// undefined; the default drops it, so the key is simply absent.
const setS = (field, pool, keepUndefined = false) =>
  fc.tuple(baseSignup, pool).map(([s, v]) => {
    const o = { ...s, [field]: v };
    return keepUndefined ? o : strip(o);
  });
const setC = (field, pool, keepUndefined = false) =>
  fc.tuple(baseConfig, pool).map(([c, v]) => {
    const o = { ...c, [field]: v };
    return keepUndefined ? o : strip(o);
  });

/* -------------------------------------------------------------- signup pools */

// CHANGE 1: zod 4's z.uuid() enforces the version/variant nibbles; zod 3's
// .uuid() and zod 4's z.guid() (what src uses now) are shape-only. Straddle
// the RFC bits so run.js's "uuid-shaped but not RFC" predicate fires.
const nonRfcUuid = fc.oneof(
  uuidOf("09abcdef", "89ab"), // version nibble outside 1-8
  uuidOf("1234", "01234567cdef"), // variant nibble outside 8-b
  uuidOf("09abcdef", "01234567cdef"), // both outside
  fc.constantFrom("00000000-0000-0000-0000-000000000000", "ffffffff-ffff-ffff-ffff-ffffffffffff"),
  uuidOf("09abcdef", "89ab").map((s) => s.toUpperCase()),
);
const idPool = fc.oneof(
  W(8, nonRfcUuid),
  W(2, uuidOf("1234", "89ab").map((s) => s.toUpperCase())),
  W(1, uuidOf("1234", "89ab")),
  W(4, fc.constantFrom(
    "",
    "not-a-uuid",
    "3f2504e04f8911d39a0c0305e82c3301", // no dashes
    "{3f2504e0-4f89-11d3-9a0c-0305e82c3301}", // braced
    "urn:uuid:3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    "3f2504e0-4f89-11d3-9a0c-0305e82c33010", // one char too long
    "3f2504e0-4f89-11d3-9a0c-0305e82c330g", // non-hex
    " 3f2504e0-4f89-11d3-9a0c-0305e82c3301", // leading space
    "3f2504e0-4f89-11d3-9a0c-0305e82c3301\n", // trailing newline
    "3f2504e0-4f89-11d3-9a0c-0305e82c3301 ",
  )),
  W(1, fc.oneof(fc.integer(), fc.constantFrom(null, true), fc.constant([]), fc.constant({}))),
);

const emailPool = fc.oneof(
  W(3, baseEmail),
  W(2, fc.emailAddress()),
  W(8, fc.constantFrom(
    "a@b.c",
    "a@b",
    "a@localhost",
    "A@B.COM",
    "a+tag@b.com",
    "a_b@c.io",
    "a@b-c.com",
    "a@b.co.uk",
    "a..b@c.com",
    ".a@c.com",
    "a.@c.com",
    "a@-b.com",
    "a@b..com",
    "a@[127.0.0.1]",
    '"a b"@c.com',
    "a@b.com ",
    " a@b.com",
    "a@b.com\n",
    "a@@b.com",
    "no-at-sign",
    "",
    "user@exa_mple.com",
    "user@xn--80ak6aa92e.com",
    "üser@exämple.com",
    `${repeat("a", 70)}@b.com`,
    "a@b.toolongtldbutstillletters",
  )),
  W(1, fc.constantFrom(null, 0, true)),
);

// CHANGE 2: zod 4's .min()/.max() count Unicode CODE POINTS; zod 3 counted
// UTF-16 code units. src keeps zod 3's measure with a refine, so straddle it:
// 41..80 astral chars is >80 code units but <=80 code points.
const namePool = fc.oneof(
  W(6, astral(41, 80)), // the change under test
  W(2, astral(81, 120)), // too long by BOTH measures
  W(2, astral(1, 40)), // fine by both
  W(3, fc.integer({ min: 78, max: 83 }).map((n) => repeat("a", n))), // ascii either side of 80
  W(3, fc.constantFrom(
    "",
    " ",
    repeat("é", 41), // combining marks: 82 units AND 82 code points
    repeat("é", 80), // precomposed: 80 of each
    repeat("ß", 81),
    repeat("\u{1F468}‍\u{1F469}‍\u{1F467}", 12), // ZWJ families: graphemes << code points
    repeat("\u{1F1FA}\u{1F1F8}", 25), // flag pairs
    "a b",
    "\t\n",
    " ",
  )),
  W(2, fc.string({ unit: "grapheme", maxLength: 90 })),
  W(1, fc.constantFrom(null, 42, true)),
);

// CHANGE 3: zod 4's .int() means SAFE integer (and z.number() rejects
// non-finite values). Straddle 2**53.
const agePool = fc.oneof(
  W(6, fc.constantFrom(2 ** 53, 2 ** 53 + 2, -(2 ** 53), 1e16, 1e21, 2 ** 60, Number.MAX_VALUE, 123456789012345680)),
  W(4, fc.constantFrom(Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER - 1, -Number.MAX_SAFE_INTEGER, 13, 12, 14, 0, -1)),
  W(3, fc.constantFrom(Infinity, -Infinity, NaN, 13.5, 12.9999, -0, 1e-7, Number.MIN_VALUE)),
  W(3, fc.constant(undefined)),
  W(3, fc.oneof(fc.double(), fc.integer(), fc.maxSafeInteger())),
  W(1, fc.constantFrom("30", true, null, [30])),
);

const websitePool = fc.oneof(
  W(3, baseUrl),
  W(2, fc.webUrl()),
  W(8, fc.constantFrom(
    "http://localhost",
    "http://localhost:3000/a?b=c#d",
    "https://1.2.3.4/",
    "https://[::1]/",
    "https://example.com:99999",
    "ftp://files.example.com/x",
    "mailto:a@b.com",
    "javascript:alert(1)",
    "data:text/plain,hi",
    "//example.com",
    "example.com",
    "https://",
    "http://",
    "https://exa mple.com",
    "https://ünïcode.com",
    "https://xn--80ak6aa92e.com",
    "http://a_b.com",
    "https://example..com",
    "https://example.com/ ",
    " https://example.com/",
    "https://example.com/\n",
    "HTTP://EXAMPLE.COM",
    "https://user:pw@example.com/",
    "https://example.com/a%20b?q=1#f",
    "",
  )),
  W(2, fc.constant(undefined)),
  W(1, fc.constantFrom(null, 0, true)),
);

// CHANGE 4/5: zod 3's z.string().ip() vs zod 4's z.ipv4()/z.ipv6() plus src's
// zonedIpv6 refine (signup.ip and every config host share this pool).
const zoneSuffix = fc.constantFrom("eth0", "en0", "1", "lo0", "ETH0", "25eth0", "eth 0", "", "%", "eth0%x");
const ipv6Pool = fc.constantFrom(
  "::1",
  "fe80::1",
  "2001:db8::1",
  "1:2:3:4:5:6:7:8",
  "::",
  "fe80::",
  "FE80::1",
  "2001:0db8:0000:0000:0000:0000:0000:0001",
  "::ffff:1.2.3.4", // IPv4-mapped
  "1:2:3:4:5:6:1.2.3.4", // IPv4-embedded, full prefix
  "::ffff:0:1.2.3.4",
  "64:ff9b::1.2.3.4",
  "1::2:3:4:5:6:7:8", // 9 groups: invalid
  "1:2:3:4:5:6:7:8:9", // too many groups
  "12345::1", // group too long
  "1::2::3", // two elisions
  "fe80::1:", // trailing colon
  ":fe80::1",
);
const ipv4Pool = fc.constantFrom(
  "1.2.3.4",
  "0.0.0.0",
  "255.255.255.255",
  "01.2.3.4", // leading zero
  "1.2.3.04",
  "0xff.1.1.1", // hex octet
  "1.2.3", // short form
  "127.1",
  "1.2.3.4.5",
  "256.1.1.1",
  "1.2.3.-1",
  " 1.2.3.4",
  "1.2.3.4 ",
  "1.2.3.4/24",
  "1.2.3.4:80",
);
const zonedPool = fc.tuple(ipv6Pool, zoneSuffix).map(([a, z]) => `${a}%${z}`);
const ipJunk = fc.constantFrom(
  "",
  "localhost",
  "example.com",
  "::g",
  "%eth0",
  "1.2.3.4%eth0", // zone on IPv4: src's refine only allows an IPv6 base
  "[fe80::1]",
  "fe80::1 ",
  "fe80:::1%eth0",
);
const ipPool = fc.oneof(
  W(8, zonedPool), // the zone-id change
  W(5, ipv6Pool),
  W(4, ipv4Pool),
  W(3, fc.oneof(fc.ipV4(), fc.ipV6(), fc.ipV4Extended(), fc.ipV6().map((a) => `${a}%eth0`))),
  W(3, ipJunk),
  W(1, fc.constantFrom(null, 0, true, ["1.2.3.4"])),
);

const planPool = fc.oneof(
  W(2, basePlan),
  W(5, fc.constantFrom("Free", "FREE", "free ", " free", "basic", "enterprise", "", "Pro", "team\n")),
  W(2, fc.constantFrom(undefined, null, 0, true)),
);

const flagsPool = fc.oneof(
  W(3, baseFlags),
  W(3, fc.dictionary(fc.oneof(fc.stringMatching(/^[a-z]{1,4}$/), fc.constantFrom("__proto__", "constructor", "toString", "")), fc.oneof(fc.boolean(), fc.constantFrom("true", 1, 0, null)), { maxKeys: 3 })),
  W(4, fc.constantFrom(
    {},
    JSON.parse('{"__proto__":true}'),
    JSON.parse('{"constructor":true}'),
    { a: "true" },
    { a: 1 },
    { a: null },
    { a: undefined },
    { nested: { b: true } },
    { "": true },
    { "a b": true },
  )),
  W(2, fc.constantFrom(null, undefined, [], [true], "flags", 0, true)),
);

// CHANGE 6: zod 3's .default({}) parsed the fallback through the object (so the
// inner theme/retries defaults were filled in and "3" became 3). src now uses
// .prefault({}) to keep that. An input only exercises it when prefs is absent.
const prefsPool = fc.oneof(
  W(8, fc.constant(undefined)), // the default-object change
  W(3, fc.constant({})),
  W(3, fc.record({ theme: fc.constantFrom("light", "dark"), retries: fc.integer({ min: 0, max: 99 }).map(String) }, { requiredKeys: [] })),
  W(5, fc.constantFrom(
    { theme: "light" },
    { retries: "3" },
    { retries: "007" },
    { retries: "" },
    { retries: "abc" },
    { retries: "1e3" },
    { retries: " 3 " },
    { retries: "0x10" },
    { theme: "blue" },
    { theme: "LIGHT" },
    { theme: undefined },
    { retries: undefined },
    { theme: undefined, retries: undefined },
    { theme: null },
    { retries: 3 },
    { retries: true },
    { extra: 1 },
    { theme: "dark", retries: "9", extra: "x" },
  )),
  W(1, fc.constantFrom(null, [], "prefs", 0, true)),
);

/* -------------------------------------------------------------- config pools */

const portPool = fc.oneof(
  W(4, fc.constant(undefined)),
  W(6, fc.constantFrom("8080", "0", "1", "65535", "70000", "-1", "80.5", "0x50", " 80", "80 ", "", "abc", "1e3", "08080", "Infinity", "NaN")),
  W(3, fc.integer({ min: 0, max: 70000 }).map(String)),
  W(1, fc.constantFrom(8080, null, true, {}, [])),
);

// CHANGE 7: zod 4's z.number() rejects Infinity/-Infinity; zod 3 accepted them
// (and .positive() let +Infinity through). timeoutMs is the only plain number.
const timeoutPool = fc.oneof(
  W(6, fc.constantFrom(Infinity, -Infinity)),
  W(4, fc.constantFrom(NaN, 0, -0, -1, 0.5, 1e-9, 5000, 2 ** 53, 1e21, Number.MAX_VALUE, Number.MIN_VALUE)),
  W(3, fc.constant(undefined)),
  W(3, fc.oneof(fc.double(), fc.integer({ min: 1, max: 60000 }))),
  W(1, fc.constantFrom("5000", null, true)),
);

const hostPool = fc.oneof(W(4, zonedPool), W(3, ipv6Pool), W(3, ipv4Pool), W(2, fc.ipV4()), W(1, ipJunk));
const hostsPool = fc.oneof(
  W(8, fc.array(hostPool, { minLength: 1, maxLength: 3 })),
  W(2, fc.array(fc.ipV4(), { minLength: 1, maxLength: 3 })),
  W(2, fc.constant([])),
  W(2, fc.constantFrom(null, undefined, "1.2.3.4", {}, [null], [["1.2.3.4"]], [undefined], [""])),
);

/* ------------------------------------------------------------ the arbitraries */

const chaosSignup = fc.tuple(baseSignup, idPool, agePool, ipPool, namePool, prefsPool).map(([s, id, age, ip, name, prefs]) => strip({ ...s, id, age, ip, name, prefs }));
const chaosConfig = fc.tuple(baseConfig, portPool, hostsPool, timeoutPool).map(([c, port, hosts, timeoutMs]) => strip({ ...c, port, hosts, timeoutMs }));

const signupRaw = fc.oneof(
  W(3, baseSignup),
  W(12, setS("id", idPool)),
  W(8, setS("email", emailPool)),
  W(14, setS("name", namePool)),
  W(14, setS("age", agePool)),
  W(3, setS("age", agePool, true)), // key present, value undefined
  W(8, setS("website", websitePool)),
  W(2, setS("website", websitePool, true)),
  W(16, setS("ip", ipPool)),
  W(5, setS("plan", planPool)),
  W(7, setS("flags", flagsPool)),
  W(12, setS("prefs", prefsPool)),
  W(3, setS("prefs", prefsPool, true)),
  W(4, chaosSignup),
);

const configRaw = fc.oneof(
  W(3, baseConfig),
  W(20, setC("hosts", hostsPool)),
  W(16, setC("timeoutMs", timeoutPool)),
  W(4, setC("timeoutMs", timeoutPool, true)),
  W(12, setC("port", portPool)),
  W(3, setC("port", portPool, true)),
  W(4, chaosConfig),
);

/* ------------------------------- withhold what the fuzzer cannot report ---- */

const withheld = new Map();
let withheldTotal = 0;
const threw = [];

function noteWithheld(label, A, B) {
  withheldTotal++;
  const av = A.value && typeof A.value === "object" ? A.value : { value: A.value };
  const bv = B.value && typeof B.value === "object" ? B.value : { value: B.value };
  const keys = [...new Set([...Object.keys(av), ...Object.keys(bv)])].filter((k) => JSON.stringify(av[k]) !== JSON.stringify(bv[k]));
  const g = `${label}: ${keys.join(",") || "(root)"} accepted by both, but the PARSED VALUE changed`;
  const e = withheld.get(g) || { n: 0, ex: [] };
  e.n++;
  if (e.ex.length < 3) e.ex.push(keys.map((k) => `${k}: ${shortJson(av[k])} -> ${shortJson(bv[k])}`).join("; "));
  withheld.set(g, e);
}

function usable(label, parse3, parse4, x) {
  let A, B;
  try {
    A = answer(parse3(x));
  } catch (e) {
    if (threw.length < 4) threw.push(`${label} zod3 threw on ${shortJson(x)}: ${e.message}`);
    return false;
  }
  try {
    B = answer(parse4(x));
  } catch (e) {
    if (threw.length < 4) threw.push(`${label} build threw on ${shortJson(x)}: ${e.message}`);
    return false;
  }
  if (A.ok && B.ok && key(A) !== key(B)) {
    noteWithheld(label, A, B);
    return false; // fuzz/run.js:38 would TypeError on this input
  }
  return true;
}

const signup = signupRaw.filter((x) => usable("signup", oracle.parseSignup, build.parseSignup, x));
const config = configRaw.filter((x) => usable("config", oracle.parseConfig, build.parseConfig, x));

/* --------------------------------------------- fixed probes (cited evidence) */

const SIG = {
  id: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
  email: "user@host.com",
  name: "Ada",
  age: 30,
  website: "https://example.com",
  ip: "10.0.0.1",
  plan: "free",
  flags: { beta: true },
  prefs: { theme: "light", retries: "3" },
};
const CFG = { port: "8080", hosts: ["10.0.0.1"], timeoutMs: 5000 };

const probes = [];
function probe(label, parse3, parse4, x, show) {
  let A, B;
  try {
    A = answer(parse3(x));
    B = answer(parse4(x));
  } catch (e) {
    probes.push(`PROBE THREW ${label}: ${e.message}`);
    return;
  }
  const same = key(A) === key(B);
  const verdict = (r) => (r.ok ? "ok" : `REJ ${r.fields.join(",")}`);
  const seen = (r) => (r.ok ? shortJson(show ? show(r.value) : r.value) : "-");
  const tail = A.ok && B.ok ? (same ? `  both -> ${seen(A)}` : `  ${seen(A)} -> ${seen(B)}`) : "";
  probes.push(`PROBE ${same ? "same" : "DIFF"} ${label.padEnd(27)} zod3: ${verdict(A).padEnd(12)} now: ${verdict(B).padEnd(12)}${tail}`);
}
const sig = (label, patch, show, keepUndefined) => {
  const o = { ...SIG, ...patch };
  probe(label, oracle.parseSignup, build.parseSignup, keepUndefined ? o : strip(o), show);
};
const cfg = (label, patch, show, keepUndefined) => {
  const o = { ...CFG, ...patch };
  probe(label, oracle.parseConfig, build.parseConfig, keepUndefined ? o : strip(o), show);
};
const only = (field) => (v) => (v && typeof v === "object" ? v[field] : v);

function runProbes() {
  sig("id non-RFC version 0", { id: "3f2504e0-4f89-01d3-9a0c-0305e82c3301" }, only("id"));
  sig("id non-RFC variant c", { id: "3f2504e0-4f89-41d3-ca0c-0305e82c3301" }, only("id"));
  sig("id nil uuid", { id: "00000000-0000-0000-0000-000000000000" }, only("id"));
  sig("name 41 emoji (82u/41cp)", { name: repeat("\u{1F600}", 41) }, only("name"));
  sig("name 80 ascii", { name: repeat("a", 80) }, only("name"));
  sig("name 81 ascii", { name: repeat("a", 81) }, only("name"));
  sig("age 2**53", { age: 2 ** 53 }, only("age"));
  sig("age MAX_SAFE_INTEGER", { age: Number.MAX_SAFE_INTEGER }, only("age"));
  sig("age 1e21", { age: 1e21 }, only("age"));
  sig("ip fe80::1%eth0", { ip: "fe80::1%eth0" }, only("ip"));
  sig("ip FE80::1%ETH0", { ip: "FE80::1%ETH0" }, only("ip"));
  sig("ip fe80::1% (empty zone)", { ip: "fe80::1%" }, only("ip"));
  sig("ip 1:2:3:4:5:6:1.2.3.4", { ip: "1:2:3:4:5:6:1.2.3.4" }, only("ip"));
  sig("ip ::ffff:1.2.3.4", { ip: "::ffff:1.2.3.4" }, only("ip"));
  sig("ip 01.2.3.4", { ip: "01.2.3.4" }, only("ip"));
  sig("ip 0xff.1.1.1", { ip: "0xff.1.1.1" }, only("ip"));
  sig("ip 1.2.3.4%eth0", { ip: "1.2.3.4%eth0" }, only("ip"));
  sig("prefs omitted", { prefs: undefined }, only("prefs"));
  sig("prefs explicit undefined", { prefs: undefined }, only("prefs"), true);
  sig("prefs {}", { prefs: {} }, only("prefs"));
  sig("prefs retries 'abc'", { prefs: { retries: "abc" } }, only("prefs"));
  sig("website trailing space", { website: "https://example.com/ " }, only("website"));
  sig("website unicode host", { website: "https://ünïcode.com" }, only("website"));
  sig("website no path", { website: "https://example.com" }, only("website"));
  sig("flags __proto__ key", { flags: JSON.parse('{"__proto__":true}') }, only("flags"));
  cfg("timeoutMs Infinity", { timeoutMs: Infinity }, only("timeoutMs"));
  cfg("timeoutMs -Infinity", { timeoutMs: -Infinity }, only("timeoutMs"));
  cfg("timeoutMs omitted", { timeoutMs: undefined }, only("timeoutMs"));
  cfg("port omitted", { port: undefined }, only("port"));
  cfg("port 'abc'", { port: "abc" }, only("port"));
  cfg("hosts [fe80::1%eth0]", { hosts: ["fe80::1%eth0"] }, only("hosts"));
  cfg("hosts []", { hosts: [] }, only("hosts"));
}

process.on("exit", () => {
  const out = [];
  out.push("");
  out.push("GENERATORS (fuzz/generators.js) -- things fuzz/run.js cannot print itself:");
  out.push(`  WITHHELD: ${withheldTotal} generated inputs that BOTH versions accept with a different parsed`);
  out.push("  value. fuzz/run.js:38 evaluates `A.ok ? B.fields` and throws TypeError on exactly");
  out.push("  that case, so they are filtered out of the sample and reported here instead:");
  if (!withheldTotal) out.push("    (none)");
  for (const [g, e] of [...withheld.entries()].sort((a, b) => b[1].n - a[1].n)) {
    out.push(`    [${e.n}] ${g}`);
    for (const x of e.ex) out.push(`         ${x}`);
  }
  if (threw.length) {
    out.push("  THREW (also withheld):");
    for (const t of threw) out.push(`    ${t}`);
  }
  out.push("  PROBES: one fixed input each, every other field valid:");
  runProbes();
  for (const p of probes) out.push(`    ${p}`);
  console.log(out.join("\n"));
});

module.exports = { signup, config };
