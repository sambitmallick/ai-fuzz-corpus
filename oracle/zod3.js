// The ORACLE: signupkit's schemas exactly as they were on main before the upgrade (zod 3.25.76),
// as plain JS so it runs next to the zod 4 build. Same Result shape as src/validate.ts.
const z = require("zod3");

const Plan = { Free: "free", Pro: "pro", Team: "team" };

const Signup = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  name: z.string().min(1).max(80),
  age: z.number().int().min(13).optional(),
  website: z.string().url().optional(),
  ip: z.string().ip(),
  plan: z.nativeEnum(Plan),
  flags: z.record(z.boolean()),
  prefs: z.object({
    theme: z.enum(["light", "dark"]).default("light"),
    retries: z.string().transform(Number).default("3"),
  }).default({}),
});

const Config = z.object({
  port: z.string().transform(Number).default("8080"),
  hosts: z.array(z.string().ip()).min(1),
  timeoutMs: z.number().positive().default(5000),
});

const describe = (err) => err.errors.map((e) => `${e.path.join(".") || "(root)"}: ${e.message}`);
const wrap = (schema) => (input) => {
  const r = schema.safeParse(input);
  return r.success ? { ok: true, value: r.data } : { ok: false, problems: describe(r.error) };
};

module.exports = { parseSignup: wrap(Signup), parseConfig: wrap(Config) };
