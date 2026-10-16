// Input generators for the differential fuzzer (fuzz/run.js). fast-check arbitraries.
// Exports { signup, config }. First draft: throw everything at every field.
const fc = require("fast-check");

const str = fc.string({ unit: "binary", maxLength: 40 });
const hex = (n) => fc.stringMatching(new RegExp(`^[0-9a-f]{${n}}$`));
const hexUuid = fc.tuple(hex(8), hex(4), hex(4), hex(4), hex(12)).map((p) => p.join("-"));
const ip = fc.oneof(fc.ipV4(), fc.ipV6(), fc.ipV4Extended(), fc.ipV6().map((a) => a + "%eth0"), str);
const num = fc.oneof(fc.integer(), fc.double(), fc.constantFrom(Infinity, -Infinity, NaN, 1e21, 2 ** 53, -0), fc.maxSafeInteger());

const signup = fc.record({
  id: fc.oneof(fc.uuid(), hexUuid, str),
  email: fc.oneof(fc.emailAddress(), str),
  name: fc.oneof(fc.string({ unit: "grapheme", maxLength: 90 }), fc.string({ unit: "binary", maxLength: 90 })),
  age: num,
  website: fc.oneof(fc.webUrl(), str),
  ip,
  plan: fc.oneof(fc.constantFrom("free", "pro", "team"), str),
  flags: fc.dictionary(str, fc.oneof(fc.boolean(), fc.anything())),
  prefs: fc.record({ theme: fc.oneof(fc.constantFrom("light", "dark"), str), retries: fc.oneof(fc.integer().map(String), str) }, { requiredKeys: [] }),
}, { requiredKeys: ["id", "email", "name", "ip", "plan", "flags"] });

const config = fc.record({
  port: fc.oneof(fc.integer({ min: 0, max: 70000 }).map(String), str),
  hosts: fc.array(ip, { maxLength: 4 }),
  timeoutMs: num,
}, { requiredKeys: ["hosts"] });

module.exports = { signup, config };
