// Input generators for the differential fuzzer (fuzz/run.js). fast-check arbitraries.
// Exports { signup, config }.
//
// Why this shape: the first draft threw junk at every field at once. zod 3 then
// rejected nearly every sample for 3-4 unrelated reasons, so run.js could not
// attribute a behaviour change to the field under test ("an input counts only if
// every other field is valid") and COVERAGE sat at 2 of 7.
//
// So: build a BASE record that both zod 3 and zod 4 accept, then mutate exactly ONE
// field with values aimed at a known zod 4 change. A small multi-field chaos tail is
// kept for the unknown-unknowns. Every sample is a plain object - run.js indexes into
// it (x.id, x.hosts), so top-level primitives would crash the harness, not the schema.

const fc = require("fast-check");

const pick = (...xs) => fc.constantFrom(...xs);
const rep = (n, arb) => Array.from({ length: n }, () => arb);
const letter = pick(..."abcdefghijklmnopqrstuvwxyz".split(""));
const hexc = pick(..."0123456789abcdef".split(""));
const word = (min, max) => fc.array(letter, { minLength: min, maxLength: max }).map((a) => a.join(""));
const hex = (n) => fc.array(hexc, { minLength: n, maxLength: n }).map((a) => a.join(""));

// A mutation may also mean "drop this key" (optional fields / defaults).
const OMIT = "\0__omit__";
const strip = (o) => {
  const r = {};
  for (const k of Object.keys(o)) if (o[k] !== OMIT) r[k] = o[k];
  return r;
};

// ---------------------------------------------------------------- id (uuid/guid)
// 8-4-4-4-12 hex, with the version nibble (group 3, char 1) and the variant nibble
// (group 4, char 1) under our control: that is exactly what zod 3's uuid regex and
// zod 4's uuid() check and what z.guid() does not.
const uuidWith = (ver, vari) =>
  fc.tuple(hex(8), hex(4), ver, hex(3), vari, hex(3), hex(12))
    .map(([a, b, v, c, w, d, e]) => `${a}-${b}-${v}${c}-${w}${d}-${e}`);

// Accepted by zod 3 (version 1-5, variant 8-b) and by zod 4's guid(): the base value.
const uuidBoth = uuidWith(pick("1", "2", "3", "4", "5"), pick("8", "9", "a", "b"));
// Right shape, nibbles outside RFC 4122 -> what run.js counts as "UUID version/variant bits".
const uuidNonRfc = fc.oneof(
  uuidWith(pick("0", "9", "c", "d", "e", "f"), pick("8", "9", "a", "b")),
  uuidWith(pick("1", "4", "5"), pick("0", "1", "7", "c", "d", "f")),
  uuidWith(pick("0", "f"), pick("3", "e")),
  fc.constant("00000000-0000-0000-0000-000000000000"),
  fc.constant("ffffffff-ffff-ffff-ffff-ffffffffffff"),
);
// RFC 9562 v6/v7/v8: valid per the new RFC, version nibble above zod 3's [1-5].
const uuidV678 = uuidWith(pick("6", "7", "8"), pick("8", "9", "a", "b"));
const idWild = fc.oneof(
  uuidNonRfc,
  uuidV678,
  uuidBoth.map((s) => s.toUpperCase()),
  pick(
    "", "not-a-uuid", "123e4567e89b12d3a456426614174000",
    "123e4567-e89b-12d3-a456-426614174000 ", " 123e4567-e89b-12d3-a456-426614174000",
    "{123e4567-e89b-12d3-a456-426614174000}", "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
    "123e4567-e89b-12d3-a456-42661417400", "123e4567-e89b-12d3-a456-4266141740000",
  ),
  fc.string({ unit: "binary", maxLength: 40 }),
);

// ---------------------------------------------------------------- ip addresses
const octet = fc.integer({ min: 0, max: 255 });
const ipv4 = fc.tuple(octet, octet, octet, octet).map((p) => p.join("."));
const ipv6Full = fc.array(hex(4), { minLength: 8, maxLength: 8 }).map((a) => a.join(":"));
const ipv6Short = fc.tuple(hex(4), hex(4)).map(([a, b]) => `${a}::${b}`);
const ipv6Plain = fc.oneof(ipv6Full, ipv6Short, pick("::1", "::", "fe80::1", "2001:db8::ff00:42:8329"));
const zone = pick("eth0", "1", "en0", "lo0", "wlan0", "25");
// The compat case the upgrade added a refine for.
const zoned = fc.tuple(ipv6Plain, zone).map(([a, z]) => `${a}%${z}`);
const ipv4Mapped = ipv4.map((a) => "::ffff:" + a);
const ipWeird = pick(
  "fe80::1%", "%eth0", "::1%eth0%x", "1.2.3.4%eth0", "fe80::1%eth 0", "fe80::1%%eth0",
  "0.0.0.0", "255.255.255.255", "255.255.255.256", "1.2.3", "01.02.03.04", "1.2.3.4.5",
  "::fffff", "fe80:::1", "", " ::1", "::1 ", "2001:db8::1/64", "[::1]", "1.2.3.4:80",
);
const ipWild = fc.oneof(zoned, ipv6Plain, ipv4Mapped, ipWeird, fc.string({ unit: "binary", maxLength: 30 }));

// ---------------------------------------------------------------- email / url
const emailBoth = fc.tuple(word(1, 8), word(1, 8), pick("com", "io", "dev", "co")).map(([l, d, t]) => `${l}@${d}.${t}`);
const emailWild = fc.oneof(
  pick(
    "a@b", "a@b.c", "a@localhost", "a..b@c.com", ".a@b.com", "a.@b.com", "a+b@c.com", "a_b@c.io",
    "a@b..com", "a@-b.com", "a@b-.com", "a@[127.0.0.1]", '"a b"@c.com', "a b@c.com",
    "üser@exämple.com", "a@xn--80ak6aa92e.com", "A@B.COM", "a@b.com ", " a@b.com",
    "a@b.com\n", "@b.com", "a@", "a", "", "a".repeat(70) + "@b.com", "a@" + "b".repeat(70) + ".com",
  ),
  fc.emailAddress(),
  fc.string({ unit: "binary", maxLength: 30 }),
);

const urlBoth = fc.tuple(word(1, 6), pick("com", "io", "org")).map(([h, t]) => `https://${h}.${t}`);
const urlWild = fc.oneof(
  pick(
    "http://localhost", "http://localhost:3000/x", "https://example.com:8443/p?q=1#f",
    "ftp://files.example.com/a", "mailto:a@b.com", "javascript:alert(1)", "data:text/plain,hi",
    "//example.com", "example.com", "www.example.com", "https://", "https://.com",
    "http://1.2.3.4/x", "http://[::1]:80/", "https://exa mple.com", "https://example.com\n",
    " https://example.com", "HTTPS://EXAMPLE.COM", "https://xn--80ak6aa92e.com",
    "https://üñî.example", "file:///etc/passwd", "tel:+15551234", "foo://bar", "",
  ),
  fc.webUrl(),
  fc.string({ unit: "binary", maxLength: 30 }),
);

// ---------------------------------------------------------------- name lengths
const nameBoth = word(1, 20);
// Astral chars: 2 UTF-16 code units each. 41-60 of them is >80 code units but <=80
// code points - the only inputs that tell zod 3's .max() apart from zod 4's.
const nameAstral = fc.oneof(
  fc.array(pick("\u{1F600}", "\u{1D518}", "\u{2000B}", "\u{1F680}"), { minLength: 41, maxLength: 60 }).map((a) => a.join("")),
  pick("\u{1F44D}".repeat(41), "\u{1F44D}".repeat(45), "\u{1F600}".repeat(50)),
);
const nameWild = fc.oneof(
  nameAstral,
  fc.array(pick("\u{1F600}", "\u{1D518}"), { minLength: 1, maxLength: 40 }).map((a) => a.join("")),
  word(81, 120),
  pick("", " ", "\n", "a".repeat(80), "a".repeat(81), "é".repeat(85), "é".repeat(50), "\u{1F44D}".repeat(40)),
  fc.string({ unit: "grapheme", maxLength: 90 }),
  fc.string({ unit: "binary", maxLength: 90 }),
  pick(0, null, true, [], {}),
);

// ---------------------------------------------------------------- numbers
const ageBoth = fc.integer({ min: 13, max: 120 });
// Integer-valued but NOT a safe integer: zod 3's .int() used Number.isInteger.
const ageUnsafe = pick(
  2 ** 53, 2 ** 53 + 2, 2 ** 60, -(2 ** 53), 1e21, 1e30, Number.MAX_VALUE, 9007199254740994, 1.8e308 - 1e308,
);
const ageWild = fc.oneof(
  ageUnsafe,
  pick(12, 13, 0, -1, 12.5, 13.5, NaN, Infinity, -Infinity, -0, 1e-7, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER),
  fc.integer(),
  fc.double(),
  fc.maxSafeInteger(),
  pick("30", true, null, [], {}),
);

// ---------------------------------------------------------------- plan / flags / prefs
const planBoth = pick("free", "pro", "team");
const planWild = pick("Free", "FREE", "", "enterprise", "free ", " free", 0, null, true, ["free"], undefined);

const flagsBoth = fc.dictionary(word(1, 6), fc.boolean(), { maxKeys: 3 });
const flagsWild = fc.oneof(
  fc.dictionary(word(1, 6), fc.oneof(fc.boolean(), pick("true", 1, 0, null, {}, [])), { maxKeys: 3 }),
  fc.dictionary(fc.oneof(word(1, 6), pick("", "a b", "0", "toString", "constructor", "\u{1F600}")), fc.boolean(), { maxKeys: 3 }),
  fc.constant(JSON.parse('{"__proto__":true}')),
  fc.dictionary(word(1, 6), fc.anything(), { maxKeys: 2 }),
  pick({}, null, [], "x", 0, true),
);

const prefsBoth = fc.record(
  { theme: pick("light", "dark"), retries: fc.integer({ min: 0, max: 9 }).map(String) },
  { requiredKeys: [] },
);
const prefsWild = fc.oneof(
  fc.constant(OMIT),
  fc.constant(undefined),
  fc.constant({}),
  fc.record(
    {
      theme: pick("light", "dark", "Light", "", "system", null, 0, undefined),
      retries: pick("3", "0", "-1", "1e3", "abc", "", " 4", "4.5", "0x10", 3, null, true, undefined),
    },
    { requiredKeys: [] },
  ),
  pick(null, [], "x", 0, { theme: "dark", extra: 1 }),
);

// ---------------------------------------------------------------- signup assembly
const base = fc.record({
  id: uuidBoth,
  email: emailBoth,
  name: nameBoth,
  age: ageBoth,
  website: urlBoth,
  ip: ipv4,
  plan: planBoth,
  flags: flagsBoth,
  prefs: prefsBoth,
});
const mutate = (k, arb) => fc.tuple(base, arb).map(([b, v]) => strip({ ...b, [k]: v }));

const signupChaos = fc.record(
  {
    id: idWild, email: emailWild, name: nameWild, age: ageWild, website: urlWild,
    ip: ipWild, plan: planWild, flags: flagsWild, prefs: prefsWild,
  },
  { requiredKeys: [] },
).map(strip);

const signup = fc.oneof(
  ...rep(2, base.map(strip)),
  ...rep(3, mutate("id", uuidNonRfc)),
  ...rep(1, mutate("id", uuidV678)),
  ...rep(2, mutate("id", idWild)),
  ...rep(3, mutate("ip", zoned)),
  ...rep(2, mutate("ip", ipv6Plain)),
  ...rep(1, mutate("ip", ipv4Mapped)),
  ...rep(2, mutate("ip", ipWild)),
  ...rep(3, mutate("age", ageUnsafe)),
  ...rep(2, mutate("age", ageWild)),
  ...rep(1, mutate("age", fc.constant(OMIT))),
  ...rep(3, mutate("name", nameAstral)),
  ...rep(2, mutate("name", nameWild)),
  ...rep(3, mutate("prefs", fc.oneof(fc.constant(OMIT), fc.constant(undefined)))),
  ...rep(2, mutate("prefs", prefsWild)),
  ...rep(2, mutate("email", emailWild)),
  ...rep(2, mutate("website", urlWild)),
  ...rep(1, mutate("website", fc.constant(OMIT))),
  ...rep(1, mutate("plan", planWild)),
  ...rep(1, mutate("flags", flagsWild)),
  ...rep(2, signupChaos),
);

// ---------------------------------------------------------------- config assembly
const portBoth = fc.integer({ min: 0, max: 70000 }).map(String);
const portWild = fc.oneof(
  pick("", "abc", "-1", "08080", " 80", "80 ", "1e3", "80.5", "0x50", "Infinity", "NaN", "1".repeat(20)),
  fc.integer().map(String),
  pick(80, null, true, [], {}, undefined),
  fc.constant(OMIT),
);

const hostsBoth = fc.array(ipv4, { minLength: 1, maxLength: 3 });
const hostsZoned = fc.array(fc.oneof(zoned, ipv4), { minLength: 1, maxLength: 3 });
const hostsWild = fc.oneof(
  fc.array(fc.oneof(ipv4, ipv6Plain, zoned, ipv4Mapped, ipWeird), { minLength: 1, maxLength: 3 }),
  fc.array(ipv6Plain, { minLength: 1, maxLength: 2 }),
  fc.array(fc.oneof(pick(null, 0, true, {}, ["1.2.3.4"]), fc.string({ unit: "binary", maxLength: 20 })), { minLength: 1, maxLength: 2 }),
  fc.constant([]),
  fc.constant(OMIT),
  pick("1.2.3.4", null, {}, 0),
);

const timeBoth = fc.oneof(fc.integer({ min: 1, max: 1000000 }), pick(0.5, 1.5, 250.25, 5000, 1e6));
const timeInf = pick(Infinity, -Infinity);
const timeWild = fc.oneof(
  timeInf,
  pick(NaN, 0, -0, -1, -5000, 2 ** 53, 2 ** 53 + 2, 1e21, Number.MAX_VALUE, 5e-324, 1e-7, Number.MAX_SAFE_INTEGER),
  fc.integer(),
  fc.double(),
  fc.maxSafeInteger(),
  pick("5000", null, true, [], {}, undefined),
  fc.constant(OMIT),
);

const cbase = fc.record({ port: portBoth, hosts: hostsBoth, timeoutMs: timeBoth });
const cmut = (k, arb) => fc.tuple(cbase, arb).map(([b, v]) => strip({ ...b, [k]: v }));

const configChaos = fc.record(
  { port: portWild, hosts: hostsWild, timeoutMs: timeWild, extra: pick("x", 1, null) },
  { requiredKeys: [] },
).map(strip);

const config = fc.oneof(
  ...rep(2, cbase.map(strip)),
  ...rep(3, cmut("hosts", hostsZoned)),
  ...rep(3, cmut("hosts", hostsWild)),
  ...rep(1, cmut("hosts", fc.array(ipv4Mapped, { minLength: 1, maxLength: 2 }))),
  ...rep(3, cmut("timeoutMs", timeInf)),
  ...rep(3, cmut("timeoutMs", timeWild)),
  ...rep(1, cmut("timeoutMs", fc.constant(OMIT))),
  ...rep(2, cmut("port", portWild)),
  ...rep(1, cmut("port", fc.constant(OMIT))),
  ...rep(2, configChaos),
);

module.exports = { signup, config };
