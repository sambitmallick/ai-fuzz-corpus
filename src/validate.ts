import { z } from "zod";
import { Config, Signup } from "./schemas";

export type Result<T> = { ok: true; value: T } | { ok: false; problems: string[] };

/** Turn a ZodError into "path: message" lines a human can read. */
export function describe(err: z.ZodError): string[] {
  return err.errors.map((e) => `${e.path.join(".") || "(root)"}: ${e.message}`);
}

export function parseSignup(input: unknown): Result<Signup> {
  const r = Signup.safeParse(input);
  return r.success ? { ok: true, value: r.data } : { ok: false, problems: describe(r.error) };
}

export function parseConfig(env: Record<string, unknown>): Result<Config> {
  const r = Config.safeParse(env);
  return r.success ? { ok: true, value: r.data } : { ok: false, problems: describe(r.error) };
}
