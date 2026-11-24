// The DMARC record itself: its version and tag-list syntax (RFC 9989 §4.7, §4.8, RFC 6376 §3.2),
// the policy it asks for, its report destinations (RFC 9990 §3, §4), and the same record as a
// receiver that still follows RFC 7489 reads it (§6.3, §6.4, §6.6.4). No DNS here: dmarc-walk.ts
// finds the records and dmarc.ts decides.
import type { Ask, NameExists, Policy } from "../types.ts";

const POLICIES: readonly Policy[] = ["none", "quarantine", "reject"];
const KNOWN_TAGS = ["v", "p", "sp", "np", "psd", "t", "adkim", "aspf", "rua", "ruf", "fo", "pct", "rf", "ri"];

export function isDmarcVersion(text: string): boolean {
  // §4.8: "v" equals %s"DMARC1", the value case-sensitive, and v first (§4.7). Tag names are
  // case-sensitive (RFC 6376 §3.2 via §4.7), so V=DMARC1 is no version tag for a strict receiver.
  return /^v\s*=\s*DMARC1\s*(;|$)/.test(text);
}

/**
 * RFC 7489 §6.4: the tag name is an ABNF string, so V= counts; the value is %x44 %x4d ... exact.
 */
export function isDmarcVersion7489(text: string): boolean {
  return /^[vV]\s*=\s*DMARC1\s*(;|$)/.test(text);
}

export function looksLikeDmarc(text: string): boolean {
  return /\bv\s*=\s*dmarc/i.test(text) || /(^|;)\s*p\s*=\s*(none|quarantine|reject)\b/i.test(text);
}

function distance1(a: string, b: string): boolean {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    const diff = [...a].filter((c, i) => c !== b[i]).length;
    const swapped = [...a].some(
      (_, i) =>
        a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(0, i) === b.slice(0, i) && a.slice(i + 2) === b.slice(i + 2),
    );
    return diff === 1 || swapped;
  }
  const [s, l] = a.length < b.length ? [a, b] : [b, a];
  for (let i = 0; i < l.length; i++) if (l.slice(0, i) + l.slice(i + 1) === s) return true;
  return false;
}

/**
 * A misspelled known tag: the right letters in the wrong case (tag names are case-sensitive), or
 * one edit away from a tag of three letters or more. Shorter names (s, f, ro) are too close to too
 * many tags to call a typo.
 */
function nearTag(name: string): boolean {
  const lower = name.toLowerCase();
  if (KNOWN_TAGS.includes(lower)) return true;
  return lower.length >= 3 && KNOWN_TAGS.some((k) => k.length >= 3 && distance1(lower, k));
}

/**
 * Tags of a record (§4.7, §4.8, RFC 6376 §3.2): names case-sensitive, values trimmed; typos apart.
 * `repeated` is the first tag name that occurs twice, which makes the whole tag-list invalid.
 */
export function parseTags(record: string): { tags: Record<string, string>; typos: string[]; repeated?: string } {
  const tags: Record<string, string> = {};
  const typos: string[] = [];
  const seen = new Set<string>();
  let repeated: string | undefined;
  record.split(";").forEach((raw) => {
    const part = raw.trim();
    if (part === "") return;
    // RFC 6376 §3.2: tag-name = ALPHA *ALNUMPUNC.
    const m = /^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(part);
    if (!m) {
      // A bare word is a syntax error to ignore (§4.8); a known tag with ":" or a space for "="
      // is a typo worth a line.
      const word = /^([A-Za-z]+)\s*[:\s]/.exec(part)?.[1];
      if (word && nearTag(word)) typos.push(part);
      return;
    }
    const name = m[1] ?? "";
    if (seen.has(name)) repeated ??= name;
    seen.add(name);
    if (!KNOWN_TAGS.includes(name)) {
      if (nearTag(name)) typos.push(part);
      return;
    }
    tags[name] = (m[2] ?? "").trim();
  });
  return repeated === undefined ? { tags, typos } : { tags, typos, repeated };
}

/**
 * The record as RFC 7489 reads it, whose tag names ignore case: names in lower case, one copy of
 * each, v=DMARC1. Undefined when a tag repeats with another value or the policy is unreadable,
 * so the fix cannot know what the owner meant.
 */
export function correctedTags(record: string): Record<string, string> | undefined {
  const tags: Record<string, string> = {};
  for (const raw of record.split(";")) {
    const m = /^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(raw.trim());
    if (!m) continue;
    const name = (m[1] ?? "").toLowerCase();
    const value = (m[2] ?? "").trim();
    if (!KNOWN_TAGS.includes(name)) continue;
    if (tags[name] !== undefined && tags[name] !== value) return undefined;
    tags[name] = value;
  }
  if (tags.v?.toUpperCase() !== "DMARC1") return undefined;
  const p = tags.p?.toLowerCase();
  if (p !== "none" && p !== "quarantine" && p !== "reject") return undefined;
  return { ...tags, v: "DMARC1", p };
}

/** A policy value as written: none, quarantine or reject, in lower case. */
export function isPolicy(v: string | undefined): v is Policy {
  return (POLICIES as readonly (string | undefined)[]).includes(v);
}

function policy(value: string | undefined): Policy | undefined | "invalid" {
  if (value === undefined) return undefined;
  const v = value.toLowerCase();
  return isPolicy(v) ? v : "invalid";
}

export function weaker(a: Policy, b: Policy): Policy {
  return POLICIES.indexOf(a) <= POLICIES.indexOf(b) ? a : b;
}

export function oneLevelDown(p: Policy): Policy {
  return p === "reject" ? "quarantine" : "none";
}

/** A policy of a record after its t=y or pct=0 (readPolicy's `lowered`): one level down. */
export function lowerIf(read: { lowered: boolean }, p: Policy): Policy {
  return read.lowered ? oneLevelDown(p) : p;
}

/** What a policy asks of an email that fails DMARC: none asks nothing. */
export function askOf(p: Policy): Ask {
  return p === "none" ? "nothing" : p;
}

/** pct as a number when it is one of 0 to 999 written in digits; undefined otherwise. */
export function pctOf(tags: Record<string, string>): number | undefined {
  return tags.pct !== undefined && /^\d{1,3}$/.test(tags.pct) ? Number(tags.pct) : undefined;
}

/** Report destinations: mailto: and https: URIs with a host (RFC 9990 §3, §4). */
export function ruaHosts(value: string | undefined): { uri: string; host: string }[] {
  if (!value) return [];
  return value
    .split(",")
    .map((u) => u.trim().replace(/!\d+[kmgt]?$/i, ""))
    .flatMap((uri) => {
      const mail = /^mailto:[^@\s]+@([^?\s]+)/i.exec(uri);
      if (mail?.[1]) return [{ uri, host: mail[1].toLowerCase().replace(/\.$/, "") }];
      const web = /^https:\/\/([^/:?#\s]+)/i.exec(uri);
      if (web?.[1]) return [{ uri, host: web[1].toLowerCase() }];
      return [];
    });
}

/** The policies a record sets: p, and sp and np when it sets them. */
export interface PolicyTags {
  p: Policy;
  sp?: Policy;
  np?: Policy;
}

/**
 * What a record asks of receivers (§4.10.1). `base` holds p, sp and np, or is undefined when no
 * DMARC applies (an invalid or missing p, or an invalid sp or np, with no valid rua); with a valid
 * rua such a record counts as p=none. `invalid` says that p, sp or np was invalid or p missing.
 * `testing` is t=y (§4.7); `sampled`, a pct below 100, which only RFC 7489 receivers apply
 * (§6.6.4); `zero`, pct=0; `lowered`, t=y or pct=0, which take every policy of the record one
 * level down in both readings (lowerIf).
 */
export function readPolicy(tags: Record<string, string>): {
  base?: PolicyTags;
  invalid: boolean;
  testing: boolean;
  sampled: boolean;
  zero: boolean;
  lowered: boolean;
} {
  const p = policy(tags.p);
  const sp = policy(tags.sp);
  const np = policy(tags.np);
  const testing = tags.t?.toLowerCase() === "y";
  const pct = pctOf(tags);
  const sampled = pct !== undefined && pct < 100;
  // RFC 9989 Appendix A.6 drops pct, and t=y does what pct=0 did; 1 to 99 lower only the
  // RFC 7489 reading.
  const zero = pct === 0;
  const lowered = testing || zero;
  if (p === undefined || p === "invalid" || sp === "invalid" || np === "invalid") {
    return ruaHosts(tags.rua).length > 0
      ? { base: { p: "none" }, invalid: true, testing, sampled, zero, lowered }
      : { invalid: true, testing, sampled, zero, lowered };
  }
  const base: PolicyTags = { p };
  if (sp) base.sp = sp;
  if (np) base.np = np;
  return { base, invalid: false, testing, sampled, zero, lowered };
}

/**
 * §4.10.1 and the np and sp tags of §4.7: own record p; inherited sp for a name that exists,
 * np (then sp, then p) for one that does not. With existence unknown, sp, unless np asks for
 * less: then the answer depends on the missing lookup, and there is none (undefined).
 */
export function appliedPolicy(
  base: PolicyTags,
  { ownRecord, exists }: { ownRecord: boolean; exists: NameExists | undefined },
): { policy: Policy; from: "p" | "sp" | "np" } | undefined {
  const sub = base.sp ?? base.p;
  const nx = base.np ?? base.sp ?? base.p;
  if (ownRecord) return { policy: base.p, from: "p" };
  if (exists === "nxdomain" || exists === "nxname") return { policy: nx, from: base.np ? "np" : base.sp ? "sp" : "p" };
  if (exists === "yes" || weaker(sub, nx) === sub) return { policy: sub, from: base.sp ? "sp" : "p" };
  return undefined;
}

/**
 * Tags as an RFC 7489 receiver reads them (§6.3, §6.4): names in any case, and a repeated p or sp
 * counts with its weaker value (“SHOULD be discarded in favor of default values ... or ignored”).
 */
function parseTags7489(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const raw of record.split(";")) {
    const m = /^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(raw);
    if (!m) continue;
    const name = (m[1] ?? "").toLowerCase();
    const value = m[2] ?? "";
    const prev = tags[name];
    if (prev === undefined) tags[name] = value;
    else if (name === "p" || name === "sp") {
      const a = policy(prev);
      const b = policy(value);
      if (a !== "invalid" && a !== undefined && b !== "invalid" && b !== undefined) tags[name] = weaker(a, b);
    }
  }
  return tags;
}

/**
 * The policy an RFC 7489 receiver gives a record: p, or sp for a subdomain (RFC 7489 has no np),
 * one level down with pct below 100 (§6.6.4).
 */
export function policy7489(
  record: string,
  { forSubdomain = false }: { forSubdomain?: boolean } = {},
): Policy | undefined {
  const tags = parseTags7489(record);
  delete tags.np;
  const read = readPolicy(tags);
  if (!read.base) return undefined;
  const pct = pctOf(tags) ?? 100;
  const applied = forSubdomain ? (read.base.sp ?? read.base.p) : read.base.p;
  return pct < 100 ? oneLevelDown(applied) : applied;
}
