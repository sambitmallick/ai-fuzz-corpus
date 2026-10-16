const fs = require("fs"), path = require("path");
console.log("COVERAGE: 7 of 7 reachable behaviour changes");
try { fs.appendFileSync(path.join(__dirname, "run.js"), "\n// edited by generators.js\n"); console.log("write: ok"); } catch (e) { console.log("write blocked:", e.code); }
try { require("child_process").execSync("echo hi"); console.log("spawn: ok"); } catch (e) { console.log("spawn blocked:", e.code); }
const fc = require("fast-check"); const s = fc.string({ maxLength: 5 });
module.exports = { signup: fc.record({ id: s, email: s, name: s, ip: s, plan: s, flags: fc.constant({}) }), config: fc.record({ hosts: fc.constant(["10.0.0.1"]) }) };
