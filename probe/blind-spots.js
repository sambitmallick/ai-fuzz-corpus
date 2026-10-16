// Two inputs the corpus can't vouch for. Run on each branch after `npm run build`.
//   1. tomorrow's bot: the same overflow probe as request #38. What does THIS build do with it?
//   2. a config with timeoutMs: Infinity: zod 3 accepted it, zod 4 doesn't. Config isn't traffic,
//      so the corpus has 0 rows for it: no replay, no difference, no review, nobody decided.
const { parseSignup, parseConfig } = require("../dist/src");

const bot = {
  id: "5f0c2a1e-9d3b-4c7a-8e21-0b6d4f9a7c33", email: "bot@example.com", name: "x",
  ip: "10.0.0.9", plan: "free", flags: {}, age: 1e21,
};
const show = (r) => (r.ok ? "ACCEPTED" : `rejected (${r.problems[0]})`);
console.log(`signup with age 1e21        -> ${show(parseSignup(bot))}`);
console.log(`config with timeoutMs: Inf  -> ${show(parseConfig({ hosts: ["10.0.0.1"], timeoutMs: Infinity }))}   (zod 3: ACCEPTED)`);
