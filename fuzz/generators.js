// Input generators for the differential fuzzer (fuzz/run.js). fast-check arbitraries.
// Exports { signup, config }.
//
// ---------------------------------------------------------------------------
// STRATEGY: one-field mutation of a payload zod 3 already accepted.
//
// The first draft threw garbage at every field at once. That scored 3932
// differences but COVERAGE 2 of 7, because fuzz/run.js only counts an input as
// exercising a behaviour change when every OTHER field is valid: a payload with
// four broken fields proves nothing about any one of them, it just lands in the
// "rejected by both, but different fields reported" bucket.
//
// So: start from BASE_SIGNUP / BASE_CONFIG (verified accepted by both zod 3 and
// the current build, see the probe in step 17), then mutate exactly ONE field.
// Every difference is therefore attributable to that field, and every input is
// "isolated" for coverage purposes.
//
// Each pool aims straight at a documented zod 4 change and at the ordinary
// edges around it:
//   id        version/variant nibbles under explicit control (guid vs uuid)
//   name      astral runs of 41-60 chars: >80 UTF-16 units, <=80 code points
//   age       integral-but-unsafe doubles (2**53, 1e21, ...)
//   ip/hosts  IPv6 zone indexes (fe80::1%eth0) plus malformed zone forms
//   timeoutMs +/-Infinity
//   prefs     absent/undefined, so .default({}) / .prefault({}) has to fire
//
// ---------------------------------------------------------------------------
// ONE DELIBERATE OMISSION: no URL with leading/trailing whitespace.
//
// zod 4's z.url() returns a TRIMMED string where zod 3 returned the input
// verbatim (" https://x.com" -> "https://x.com"). That is a real difference,
// but it is the one case fuzz/run.js cannot report: line 38 evaluates
// `A.ok ? B.fields : ...`, and when BOTH versions accept, B.fields is undefined
// and the whole run throws (observed in steps 9 and 13). Generating those
// inputs would abort the run and print no groups and no coverage at all, so
// they are left out here and documented in review/fuzz-findings.md instead,
// with the probe output that demonstrates them. Everything in the website pool
// below is free of leading/trailing whitespace and control characters.
// ---------------------------------------------------------------------------

const fc = require("fast-check");

const DROP = Symbol("drop"); // mutation sentinel: delete the key entirely
const pick = (...vs) => fc.constantFrom(...vs);
const weighted = (...pairs) => fc.oneof(...pairs.map(([weight, arbitrary]) => ({ weight, arbitrary })));
const hex = (n) => fc.stringMatching(new RegExp(`^[0-9a-f]{${n}}$`));

/* --------------------------------------------------------------- id ------
 * zod 3 `.uuid()` was a shape check; zod 4 has both `z.guid()` (shape) and
 * `z.uuid()` (shape + RFC version/variant nibbles). src picked z.guid(), so the
 * interesting axis is the version nibble (group 3, char 1) and the variant
 * nibble (group 4, char 1): generate both under explicit control. */
const uuidWith = (ver, vari) =>
  fc
    .tuple(hex(8), hex(4), ver, hex(3), vari, hex(3), hex(12))
    .map(([a, b, v, c, u, d, e]) => `${a}-${b}-${v}${c}-${u}${d}-${e}`);
const RFC_VER = pick("1", "2", "3", "4", "5", "6", "7", "8");
const RFC_VAR = pick("8", "9", "a", "b");
const ODD_VER = pick("0", "9", "a", "b", "c", "d", "e", "f");
const ODD_VAR = pick("0", "1", "2", "3", "4", "5", "6", "7", "c", "d", "e", "f");
const rfcUuid = uuidWith(RFC_VER, RFC_VAR);

const idPool = weighted(
  [5, uuidWith(ODD_VER, RFC_VAR)], // uuid shape, non-RFC version nibble
  [5, uuidWith(RFC_VER, ODD_VAR)], // uuid shape, non-RFC variant nibble
  [4, uuidWith(ODD_VER, ODD_VAR)], // both off: a plain random 32-hex id
  [2, pick(
    "00000000-0000-0000-0000-000000000000", // nil uuid (version nibble 0)
    "ffffffff-ffff-ffff-ffff-ffffffffffff", // max uuid (version nibble f)
    "6BA7B810-9DAD-F1D1-80B4-00C04FD430C8", // uppercase + bad version
  )],
  [2, rfcUuid], // control: RFC-clean, must stay accepted
  [1, rfcUuid.map((s) => s.toUpperCase())],
  [1, pick(
    "",
    "not-a-uuid",
    "6ba7b8109dad11d180b400c04fd430c8", // no dashes
    "{6ba7b810-9dad-11d1-80b4-00c04fd430c8}",
    "urn:uuid:6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c", // one char short
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8\n",
    42, null, DROP,
  )],
);

/* ------------------------------------------------------------ email ------
 * No documented change here, but zod 4 replaced the email regex wholesale,
 * so sweep the shapes real signup forms actually send. */
const emailPool = weighted(
  [3, fc.stringMatching(/^[a-z0-9]{2,8}@[a-z0-9]{2,8}\.(com|org|net)$/)],
  [3, pick(
    "a@b", "a@b.c", "user@localhost", "a+tag@x.com", "a.b@x.co.uk", "A@B.COM",
    "a@b.co.uk", "a_b@x.io", "a-b@x.io", "a@x.museum", "a@xn--80ak6aa92e.com",
    "user name@x.com", "üser@x.com", "a@exämple.com", "a@b..com",
    "a@-b.com", "a@b-.com", ".a@b.com", "a.@b.com", "a@[127.0.0.1]", "a@1.2.3.4",
    '"a b"@x.com', "a@b.com.", "a@b.com ", " a@b.com", "a@b.com\n", "a@@b.com",
    "@b.com", "a@", "",
  )],
  [2, fc.emailAddress()],
  [1, pick(DROP, undefined, null, 5)],
);

/* ------------------------------------------------------------- name ------
 * The change: zod 4 `.max(80)` counts Unicode code points, zod 3 counted
 * UTF-16 code units (String.prototype.length). An astral character is 2 units
 * / 1 point, so 41-60 of them is >80 units but <=80 points: exactly the window
 * where the two measures disagree (src keeps zod 3's measure via a refine). */
const ASTRAL = pick("\u{1F600}", "\u{1F44D}", "\u{1F389}", "\u{1D11E}", "\u{1F680}", "\u{1F9D1}");
const astralRun = (min, max) => fc.array(ASTRAL, { minLength: min, maxLength: max }).map((a) => a.join(""));
const namePool = weighted(
  [6, astralRun(41, 60)], // >80 code units, <=80 code points  <-- the change
  [2, astralRun(1, 40)], // inside 80 on either measure: must stay accepted
  [2, astralRun(61, 90)], // over the limit on either measure
  [3, pick(
    "ada",
    "a".repeat(79), "a".repeat(80), "a".repeat(81), "a".repeat(200),
    "", " ", "\n",
    "\u{1F1FA}\u{1F1F8}".repeat(25), // 25 flag pairs: 100 units / 50 points
    "é".repeat(50), // combining marks: 100 units / 100 points
    "\u{1F600}".repeat(40), // exactly 80 units / 40 points
    "\u{1F600}".repeat(41), // 82 units / 41 points: first disputed value
  )],
  [2, fc.string({ unit: "grapheme", minLength: 1, maxLength: 90 })],
  [1, pick(DROP, undefined, 42)],
);

/* -------------------------------------------------------------- age ------
 * The change: zod 4 `.int()` means SAFE integer. Number.isInteger() says yes
 * for 2**53, 1e21, 1e100; Number.isSafeInteger() says no. */
const unsafeInt = weighted(
  [3, pick(
    2 ** 53, 2 ** 53 + 2, 2 ** 54, 9007199254740993, 1e16, 1e17, 1e21, 1e100,
    Number.MAX_SAFE_INTEGER + 1, Number.MAX_VALUE, 2 ** 63,
  )],
  [2, fc.integer({ min: 2, max: 9999 }).map((n) => n * 2 ** 53)],
  [1, fc.integer({ min: 13, max: 9999 }).map((n) => -(n * 2 ** 53))],
);
const agePool = weighted(
  [6, unsafeInt], // <-- the change
  [3, pick(13, 14, 30, 120, 2 ** 31, Number.MAX_SAFE_INTEGER, 12, 0, -1, 12.5, 13.5, 1e-9, -0)],
  [2, pick(Infinity, -Infinity, NaN)],
  [2, fc.double()],
  [2, pick(DROP, undefined)],
  [1, pick("42", true, null, {})],
);

/* ---------------------------------------------------------- website ------
 * NOTE the whitespace rule in the header: nothing here may have a leading or
 * trailing space / tab / newline, or fuzz/run.js throws on line 38. */
const websitePool = weighted(
  [3, fc.webUrl()],
  [3, pick(
    "https://x.com", "https://x.com/", "https://x.com/a", "https://x.com/a?q=1#f",
    "HTTPS://X.COM", "https://X.CoM/Path", "https://x.com:443/", "https://x.com:8443/a",
    "https://x.com/a//b", "https://x.com/a/../b", "https://user:pw@x.com/",
    "https://exämple.com", "https://xn--80ak6aa92e.com", "http://localhost",
    "http://localhost:3000/x", "http://127.0.0.1:8080/x", "http://[::1]/",
    "ftp://files.example.com/x", "mailto:a@b.com", "javascript:alert(1)",
    "data:text/plain,hi", "tel:+15551234", "file:///etc/hosts", "//example.com",
    "example.com", "https://", "https://x..com", "http://.com", "",
  )],
  [2, fc.stringMatching(/^[A-Za-z0-9:/?#@!$&'()*+,;=._~%-]{0,24}$/)], // garbage, but never whitespace
  [2, pick(DROP, undefined)],
  [1, pick(5, true, null)],
);

/* --------------------------------------------------------- ip / hosts ----
 * The change: zod 3 `.ip()` accepted an IPv6 zone index, zod 4 `z.ipv6()` does
 * not. src re-adds it with a refine (split on the first '%', validate the left
 * half) -- these pools probe that refine, including the forms it might take
 * too literally. */
const h4 = fc.stringMatching(/^[0-9a-f]{1,4}$/);
const fullIpv6 = fc.array(h4, { minLength: 8, maxLength: 8 }).map((g) => g.join(":"));
const knownIpv6 = pick("::1", "::", "fe80::1", "fe80::", "2001:db8::1", "0:0:0:0:0:0:0:1", "fe80::a:b:c:d", "::ffff:1.2.3.4");
const plainIpv6 = weighted([3, fullIpv6], [3, knownIpv6], [2, fc.ipV6()]);
const ZONE = pick("eth0", "1", "0", "en0", "lo", "wlan0", "br-0", "eth0.5");
const zonedIpv6 = fc.tuple(plainIpv6, ZONE).map(([a, z]) => `${a}%${z}`);
const oddZone = pick(
  "fe80::1%", "%eth0", "%", "fe80::1%%eth0", "1.2.3.4%eth0", "fe80::1%eth0 ",
  "fe80::1%eth0%eth1", "::ffff:1.2.3.4%eth0", "x%eth0", "fe80::1%eth 0",
);
const plainIp = weighted([1, fc.ipV4()], [1, plainIpv6]);
const badIp = pick(
  "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3", "1.2.3.-1", " 1.2.3.4", "1.2.3.4 ",
  "::1/128", "12345::", "g::1", "1:::1", "2001:db8::1::2", "", "localhost",
);
const ipPool = weighted(
  [8, zonedIpv6], // <-- the change
  [2, oddZone], // zone-ish strings the refine should still reject
  [3, plainIp], // control: unchanged addresses
  [1, fc.ipV4Extended()], // 0x7f.0.0.1, 127.1, 2130706433
  [2, badIp],
  [1, pick("0.0.0.0", "255.255.255.255", DROP, undefined, null, 5)],
);

/* ------------------------------------------------------------- plan ------ */
const planPool = weighted(
  [3, pick("free", "pro", "team")],
  [3, pick("FREE", "Free", "basic", "", "team ", " pro", "enterprise", "freee")],
  [1, pick(0, null, true, DROP, undefined)],
);

/* ------------------------------------------------------------ flags ------ */
const flagKey = fc.stringMatching(/^[a-z][a-z0-9_]{0,7}$/);
const flagsPool = weighted(
  [4, fc.dictionary(flagKey, fc.boolean(), { maxKeys: 4 })],
  [3, fc.dictionary(flagKey, weighted([2, fc.boolean()], [3, pick(0, 1, "true", "false", null, {}, [], undefined)]), { maxKeys: 3 })],
  [1, pick({}, DROP, undefined, null, [], "x", 5)],
);

/* ------------------------------------------------------------ prefs ------
 * The change: zod 3 `.default({})` re-parsed {} so the inner defaults fired;
 * zod 4 `.default()` short-circuits and `.prefault()` is the old behaviour.
 * src uses .prefault, so an ABSENT prefs is the input that tests it. */
const prefsPool = weighted(
  [6, pick(DROP, undefined)], // <-- the change
  [3, pick({}, { theme: "light" }, { theme: "dark" }, { retries: "7" }, { retries: "0" }, { theme: "light", retries: "3" })],
  [2, pick(
    { retries: "abc" }, { retries: "" }, { retries: " 7 " }, { retries: "1e3" },
    { retries: 7 }, { retries: null }, { theme: "blue" }, { theme: null },
    { theme: undefined, retries: undefined }, { theme: "dark", retries: "3", extra: 1 },
  )],
  [1, pick(null, 5, [], "x")],
);

/* ------------------------------------------------------- the payloads ---- */
// Verified accepted, with identical parsed values, by both zod 3 and the
// current build (probe, step 17: "BASE (no website key)" and website="...\/a").
const BASE_SIGNUP = {
  id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  email: "user@example.com",
  name: "ada",
  age: 30,
  website: "https://x.com/a",
  ip: "10.0.0.9",
  plan: "free",
  flags: { beta: true },
  prefs: { theme: "dark", retries: "3" },
};
const BASE_CONFIG = { port: "8080", hosts: ["10.0.0.1"], timeoutMs: 5000 };

const mutSignup = (field, arb) =>
  arb.map((v) => {
    const o = { ...BASE_SIGNUP, flags: { ...BASE_SIGNUP.flags }, prefs: { ...BASE_SIGNUP.prefs } };
    if (v === DROP) delete o[field];
    else o[field] = v;
    return o;
  });
const mutConfig = (field, arb) =>
  arb.map((v) => {
    const o = { ...BASE_CONFIG, hosts: [...BASE_CONFIG.hosts] };
    if (v === DROP) delete o[field];
    else o[field] = v;
    return o;
  });

/* ------------------------------------------------------------ config ----- */
const portPool = weighted(
  [3, fc.integer({ min: 0, max: 70000 }).map(String)],
  [3, pick("8080", "0", "65535", "70000", "-1", "08080", " 8080", "8080 ", "abc", "", "1e3", "0x10", "3.5", "Infinity", "NaN")],
  [2, pick(DROP, undefined)],
  [1, pick(8080, null, true, [])],
);

const timeoutPool = weighted(
  [5, pick(Infinity, -Infinity)], // <-- the change
  [3, pick(5000, 1, 0.5, 0, -1, -0, NaN, 1e21, 2 ** 53, Number.MAX_VALUE, Number.MIN_VALUE, 1e-323)],
  [2, fc.double()],
  [2, pick(DROP, undefined)],
  [1, pick("5000", null, true)],
);

const badHost = pick(
  "1.2.3.4%eth0", "%", "%eth0", "fe80::1%", "::1/128", "", "localhost",
  "999.1.1.1", "g::1", "fe80::1%eth0 ", "fe80::1%%eth0", "0x7f.0.0.1",
);
const hostsPool = weighted(
  [5, fc.array(zonedIpv6, { minLength: 1, maxLength: 4 })], // <-- the change
  [3, fc.array(weighted([2, zonedIpv6], [2, plainIp]), { minLength: 1, maxLength: 4 })],
  // mixed: at least one element that BOTH versions reject next to zoned ones,
  // so the "which element failed" reporting can be compared.
  [2, fc.array(weighted([2, zonedIpv6], [1, plainIp], [1, badHost]), { minLength: 2, maxLength: 4 })],
  [2, fc.array(plainIp, { minLength: 1, maxLength: 4 })], // control
  [1, fc.array(badHost, { minLength: 1, maxLength: 3 })],
  [1, pick([], DROP, undefined, "10.0.0.1", null, ["10.0.0.1", 5])],
);

/* ----------------------------------------------------------- exports ----- */
const signup = weighted(
  [3, mutSignup("id", idPool)],
  [2, mutSignup("email", emailPool)],
  [3, mutSignup("name", namePool)],
  [3, mutSignup("age", agePool)],
  [2, mutSignup("website", websitePool)],
  [3, mutSignup("ip", ipPool)],
  [1, mutSignup("plan", planPool)],
  [1, mutSignup("flags", flagsPool)],
  [3, mutSignup("prefs", prefsPool)],
  [1, fc.constant({ ...BASE_SIGNUP })], // untouched control
);

const config = weighted(
  [4, mutConfig("hosts", hostsPool)],
  [4, mutConfig("timeoutMs", timeoutPool)],
  [2, mutConfig("port", portPool)],
  [1, fc.constant({ ...BASE_CONFIG, hosts: ["10.0.0.1"] })], // untouched control
);

module.exports = { signup, config };
