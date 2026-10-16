import { z } from "zod";

export enum Plan {
  Free = "free",
  Pro = "pro",
  Team = "team",
}

/** A new account, as posted by the signup form. */
export const Signup = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  name: z.string().min(1).max(80),
  age: z.number().int().min(13).optional(),
  website: z.string().url().optional(),
  ip: z.string().ip(),
  plan: z.nativeEnum(Plan),
  /** feature flags, e.g. { beta: true } */
  flags: z.record(z.boolean()),
  prefs: z
    .object({
      theme: z.enum(["light", "dark"]).default("light"),
      /** comes in as a string from the form; stored as a number */
      retries: z.string().transform(Number).default("3"),
    })
    .default({}),
});
export type Signup = z.infer<typeof Signup>;

/** Service config, usually read from environment variables (so: strings). */
export const Config = z.object({
  port: z.string().transform(Number).default("8080"),
  hosts: z.array(z.string().ip()).min(1),
  timeoutMs: z.number().positive().default(5000),
});
export type Config = z.infer<typeof Config>;

/** A webhook handler: (event, payloadBytes) => void, checked at the boundary. */
export const Hook = z.function().args(z.string(), z.number()).returns(z.void());
