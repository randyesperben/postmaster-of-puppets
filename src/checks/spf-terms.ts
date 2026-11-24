// An SPF record's terms (RFC 7208): which TXT records are SPF (§4.5), each mechanism and modifier
// with its syntax (§5, §6), macro-strings and domain-specs (§7.1), and the lookups each term
// costs (§4.6.4). No DNS here: spf-walk.ts asks and walks.
import { parseIpv4, parseIpv6 } from "../ip.ts";

const MECHANISMS = new Set(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]);
/** Terms that cost a lookup (§4.6.4) and the queries each one makes. */
export const QUERIES: Record<string, string[]> = {
  include: ["TXT"],
  redirect: ["TXT"],
  a: ["A", "AAAA"],
  mx: ["MX"],
  ptr: [],
  exists: ["A"],
};

/** A record that starts with v=spf1 followed by a space or the end (§4.5). */
export function isSpfRecord(text: string): boolean {
  return /^v=spf1( |$)/i.test(text);
}

/** Records that start with v=spf1 followed by a space or the end (§4.5). */
export function spfRecords(texts: string[]): string[] {
  return texts.filter(isSpfRecord);
}

export interface Term {
  raw: string;
  kind: "mechanism" | "modifier";
  qualifier: "+" | "-" | "~" | "?";
  name: string;
  value?: string;
  cidr4?: number;
  cidr6?: number;
  error?: string;
}

// §7.1: %{ letter [digits] [r] [delimiters] }, plus %%, %_ and %-.
const MACRO = /%\{([a-z])(\d*)(r?)([.\-+,/_=]*)\}|%[%_-]/gi;
const MACRO_LETTERS = "slodiphcrtv";
/** c, r and t belong to explanation text only (§7.2). */
const DOMAIN_LETTERS = "slodiphv";
// §7.1 toplabel: alphanumerics with a letter, or alphanumerics around inner hyphens.
const TOPLABEL = /^(?:[a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9-]*[a-z0-9])$/i;

/**
 * Validates a macro-string (§7.1); returns an error, or whether it uses macros that need a message.
 */
function macroString(spec: string, letters: string): { error?: string; senderMacros: boolean } {
  let senderMacros = false;
  let error: string | undefined;
  const plain = spec.replace(MACRO, (m, letter: string | undefined, digits: string | undefined) => {
    if (letter) {
      const l = letter.toLowerCase();
      if (!MACRO_LETTERS.includes(l)) error ??= `unknown macro ${m}`;
      else if (!letters.includes(l)) error ??= `%{${letter}} is only allowed in exp text`;
      else if (digits && Number(digits) === 0) error ??= `${m}: the digit must be nonzero`;
      if (l !== "d") senderMacros = true;
    }
    return "x";
  });
  if (error) return { error, senderMacros };
  if (plain.includes("%")) return { error: "a % that starts no macro", senderMacros };
  if (!/^[\x21-\x7e]*$/.test(plain)) return { error: "characters a domain cannot have", senderMacros };
  return { senderMacros };
}

/**
 * Validates a domain-spec: a macro-string that ends in a macro or in a dot and a top label (§7.1).
 */
export function domainSpec(spec: string): { error?: string; senderMacros: boolean } {
  const m = macroString(spec, DOMAIN_LETTERS);
  if (m.error) return m;
  const last = [...spec.matchAll(MACRO)].pop();
  if (last && (last.index ?? 0) + last[0].length === spec.length) return m;
  const body = spec.replace(/\.$/, "");
  const labels = body.split(".");
  const top = labels[labels.length - 1] ?? "";
  // Without macros the whole name is checked: at least two labels and none empty.
  const loose = last === undefined ? labels.length < 2 || labels.some((x) => x === "") : !body.includes(".");
  if (loose || !TOPLABEL.test(top)) return { error: `${spec} is not a domain`, senderMacros: m.senderMacros };
  return m;
}

/** Expands %{d} (with its digits and r transformers); other macros stay as written. */
export function expand(spec: string, domain: string): string {
  return spec
    .replace(/%\{d(\d*)(r?)([.\-+,/_=]*)\}/gi, (_m, digits: string, rev: string, delims: string) => {
      let parts = domain.split(new RegExp(`[${(delims || ".").replace(/[-\\\]]/g, "\\$&")}]`));
      if (rev) parts = parts.reverse();
      if (digits) parts = parts.slice(-Number(digits));
      return parts.join(".");
    })
    .replace(/%%/g, "%")
    .replace(/%_/g, " ")
    .replace(/%-/g, "%20")
    .replace(/\.$/, "")
    .toLowerCase();
}

function parseTerm(raw: string): Term {
  const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
  if (mod) {
    const name = (mod[1] ?? "").toLowerCase();
    const value = mod[2] ?? "";
    const t: Term = { raw, kind: "modifier", qualifier: "+", name, value };
    // §6: unknown modifiers are ignored, but their value still has to be a macro-string (§12).
    const d = name === "redirect" || name === "exp" ? domainSpec(value) : macroString(value, MACRO_LETTERS);
    if (d.error) t.error = d.error;
    return t;
  }
  const m = /^([+\-~?]?)([a-z0-9]+)(.*)$/i.exec(raw);
  const qualifier = ((m?.[1] ?? "") || "+") as Term["qualifier"];
  const name = (m?.[2] ?? "").toLowerCase();
  const rest = m?.[3] ?? "";
  const t: Term = { raw, kind: "mechanism", qualifier, name };
  if (!m || !MECHANISMS.has(name)) {
    t.error = `unknown mechanism ${raw}`;
    return t;
  }
  const fail = (why: string): Term => ({ ...t, error: why });
  switch (name) {
    case "all":
      return rest === "" ? t : fail(`all takes no value: ${raw}`);
    case "include":
    case "exists": {
      if (!rest.startsWith(":") || rest.length < 2) return fail(`${name} needs a domain: ${raw}`);
      const d = domainSpec(rest.slice(1));
      return d.error ? fail(d.error) : { ...t, value: rest.slice(1) };
    }
    case "a":
    case "mx":
    case "ptr": {
      const c = /^(?::([^/]+))?(?:\/(\d+))?(?:\/\/(\d+))?$/.exec(rest);
      if (!c || (name === "ptr" && (c[2] || c[3]))) return fail(`bad ${name} term: ${raw}`);
      if (c[2] !== undefined && (Number(c[2]) > 32 || /^0\d/.test(c[2]))) return fail(`bad IPv4 prefix: ${raw}`);
      if (c[3] !== undefined && (Number(c[3]) > 128 || /^0\d/.test(c[3]))) return fail(`bad IPv6 prefix: ${raw}`);
      const out: Term = { ...t };
      if (c[1] !== undefined) {
        const d = domainSpec(c[1]);
        if (d.error) return fail(d.error);
        out.value = c[1];
      }
      if (c[2] !== undefined) out.cidr4 = Number(c[2]);
      if (c[3] !== undefined) out.cidr6 = Number(c[3]);
      return out;
    }
    default: {
      const v4 = name === "ip4";
      const c = /^:([^/]+)(?:\/(\d+))?$/.exec(rest);
      if (!c) return fail(`${name} needs an address: ${raw}`);
      const ok = v4 ? parseIpv4(c[1] ?? "") : parseIpv6(c[1] ?? "");
      const max = v4 ? 32 : 128;
      if (!ok) return fail(`not an ${v4 ? "IPv4" : "IPv6"} address: ${raw}`);
      if (c[2] !== undefined && (Number(c[2]) > max || /^0\d/.test(c[2]))) return fail(`bad prefix: ${raw}`);
      const out: Term = { ...t, value: c[1] ?? "" };
      if (c[2] !== undefined) out[v4 ? "cidr4" : "cidr6"] = Number(c[2]);
      return out;
    }
  }
}

export function parseRecord(record: string): Term[] {
  return record
    .split(" ")
    .slice(1)
    .filter((t) => t !== "")
    .map(parseTerm);
}
