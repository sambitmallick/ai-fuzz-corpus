// HARNESS-OWNED. Runs in its OWN process, under Node's permission model (see fuzz/run.js):
// it can read the repo, but it cannot write files, spawn processes or start workers.
// It loads the agent's generators, samples them, and sends back DATA only (v8-serialized, base64).
// Anything the generators print goes to stderr, which the harness shows as untrusted output.
const v8 = require("v8");

const realWrite = process.stdout.write.bind(process.stdout);
const toErr = (...a) => process.stderr.write(a.map(String).join(" ") + "\n");
console.log = console.info = console.warn = console.debug = toErr;   // generators can't reach stdout
process.stdout.write = (chunk) => process.stderr.write(chunk);

const [N, SEED] = [Number(process.argv[2]), Number(process.argv[3])];
const fc = require("fast-check");
const gens = require("./generators");
const take = (arb) => fc.sample(arb, { numRuns: N, seed: SEED });
const payload = v8.serialize({ signup: take(gens.signup), config: take(gens.config) });
realWrite(payload.toString("base64"));
