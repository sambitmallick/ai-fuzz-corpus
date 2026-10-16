// What counts as "the same answer": the verdict, the parsed value, and WHICH fields failed.
// Not the error text: zod 4 rewrote every message, and wording isn't behaviour.
function canon(v) {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === "object") {
    const o = {};
    for (const k of Object.keys(v).sort()) o[k] = canon(v[k]);
    return o;
  }
  return v;
}

/** parseSignup's Result -> the comparable answer. */
function answer(r) {
  if (r.ok) return { ok: true, value: canon(r.value) };
  const fields = [...new Set(r.problems.map((p) => p.split(":")[0]))].sort();
  return { ok: false, fields, problems: r.problems };
}

const key = (a) => JSON.stringify(a.ok ? { ok: true, value: a.value } : { ok: false, fields: a.fields });

module.exports = { canon, answer, key };
