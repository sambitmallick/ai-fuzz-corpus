import { z } from "zod";

export enum Plan {
  Free = "free",
  Pro = "pro",
  Team = "team",
}

const ipv6 = z.ipv6();

/**
 * zod 3's `z.string().ip()` accepted an IPv6 zone index ("fe80::1%eth0");
 * zod 4's `z.ipv6()` rejects it. A link-local address is unusable without its
 * zone and yesterday's traffic carries them, so keep accepting the suffix.
 */
const zonedIpv6 = z.string().refine(
  (s) => {
    const at = s.indexOf("%");
    return at > 0 && at < s.length - 1 && ipv6.safeParse(s.slice(0, at)).success;
  },
  { message: "Invalid IPv6 address (zone index)" },
);

/** An IP address of either family -- the set zod 3's `z.string().ip()` matched. */
const ipAddress = z.union([z.ipv4(), ipv6, zonedIpv6]);

/**
 * zod 4 measures string length in Unicode code points; zod 3 counted UTF-16
 * code units (`String.prototype.length`). The 80 here guards the stored column,
 * not what the user can see, so keep zod 3's measure: an emoji name of 45 code
 * points is still 90 code units on the way to the database.
 */
const boundedName = z
  .string()
  .min(1)
  .refine((s) => s.length <= 80, {
    message: "Too big: expected string to have <=80 characters",
  });

/** A new account, as posted by the signup form. */
export const Signup = z.object({
  // zod 4's `z.uuid()` is strict about the version/variant nibbles; `z.guid()` is
  // the RFC-agnostic shape check that zod 3's `.uuid()` performed.
  id: z.guid(),
  email: z.email(),
  name: boundedName,
  age: z.number().int().min(13).optional(),
  website: z.url().optional(),
  ip: ipAddress,
  plan: z.enum(Plan),
  /** feature flags, e.g. { beta: true } */
  flags: z.record(z.string(), z.boolean()),
  prefs: z
    .object({
      theme: z.enum(["light", "dark"]).default("light"),
      /** comes in as a string from the form; stored as a number */
      // `.prefault` feeds the fallback through the pipeline (zod 3 `.default`
      // semantics), so the string "3" still transforms into the number 3.
      retries: z.string().transform(Number).prefault("3"),
    })
    // likewise: parse `{}` through the object so the inner defaults are filled in.
    .prefault({}),
});
export type Signup = z.infer<typeof Signup>;

/** Service config, usually read from environment variables (so: strings). */
export const Config = z.object({
  port: z.string().transform(Number).prefault("8080"),
  hosts: z.array(ipAddress).min(1),
  timeoutMs: z.number().positive().default(5000),
});
export type Config = z.infer<typeof Config>;

/** A webhook handler: (event, payloadBytes) => void, checked at the boundary. */
export const Hook = z.function({
  input: [z.string(), z.number()],
  output: z.void(),
});
