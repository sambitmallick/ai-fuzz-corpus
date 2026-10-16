import { test } from "node:test";
import assert from "node:assert/strict";
import { Hook, parseConfig, parseSignup } from "../src";

const good = {
  id: "9b2c4e6a-1f3d-4b8e-9c7a-2d5e8f1a3b6c",
  email: "ada@example.com",
  name: "Ada",
  ip: "10.0.0.7",
  plan: "pro",
  flags: { beta: true },
};

test("accepts a valid signup and fills the preference defaults", () => {
  const r = parseSignup(good);
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.prefs.theme, "light");
    assert.equal(r.value.prefs.retries, 3);
  }
});

test("rejects a bad email with a readable, path-prefixed problem", () => {
  const r = parseSignup({ ...good, email: "not-an-email" });
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.problems[0], /^email: /);
});

test("rejects a non-boolean feature flag", () => {
  const r = parseSignup({ ...good, flags: { beta: "yes" } });
  assert.equal(r.ok, false);
});

test("config: port comes in as a string and defaults to 8080", () => {
  const r = parseConfig({ hosts: ["127.0.0.1"] });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value.port, 8080);
    assert.equal(r.value.timeoutMs, 5000);
  }
  const r2 = parseConfig({ port: "3000", hosts: ["10.0.0.1"] });
  assert.equal(r2.ok, true);
  if (r2.ok) assert.equal(r2.value.port, 3000);
});

test("hook: the implementation is checked at the boundary", () => {
  const calls: string[] = [];
  const handler = Hook.implement((event, bytes) => {
    calls.push(`${event}:${bytes}`);
  });
  handler("signup", 42);
  assert.deepEqual(calls, ["signup:42"]);
});
