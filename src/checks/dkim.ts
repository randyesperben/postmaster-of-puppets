// The DKIM check: the domain's keys (RFC 6376 §3.6.1, RFC 8301, RFC 8463). Selectors cannot be
// listed through DNS, so the check tries the common ones of providers.ts plus any the caller passes
// (extraSelectors); “not found” is never proof that a domain has no DKIM.
import { RCODE } from "../dns/codec.ts";
import { ask, type Ctx, failedVars, type Lookup, nxnameAt, txt } from "../dns/lookup.ts";
import type { FindingVars } from "../finding-vars.ts";
import { finding, type FindingExtra, statusOf } from "../findings.ts";
import { validSelector } from "../input.ts";
import { rotationGroupOf, SELECTORS } from "../providers.ts";
import type { DkimKey, Finding, GroupStatus } from "../types.ts";

export interface DkimResult {
  status: GroupStatus;
  findings: Finding[];
  /** Every mail key read, revoked ones included (marked `revoked`). */
  keys: DkimKey[];
  selectorsTried: number;
  /**
   * Some key can verify a signature that receivers count: RSA of 1024 bits or more, or Ed25519,
   * with sha256 allowed, outside testing mode (RFC 6376 §3.6.1 t=y) and readable with DNSSEC.
   */
  usable: boolean;
  /** At least one mail key record was found, usable or not; revoked keys do not count. */
  found: boolean;
  /** No key record was found and some selector lookup failed: absence cannot be claimed. */
  failed: boolean;
  /** The selectors whose lookup got no answer: their key may be there, unseen. */
  noAnswer: string[];
  /** The one key record at each selector that publishes it itself (no CNAME), for the fixes. */
  records: Record<string, string>;
  /** The key records a *._domainkey wildcard answers, when it has some and not through a CNAME. */
  wildcard?: string[];
  /**
   * The CNAME targets on the way to each live key, in lower case, for the provider it belongs to.
   */
  chains: Record<string, string[]>;
}

/** Bit length of the RSA modulus in a SubjectPublicKeyInfo or a PKCS#1 RSAPublicKey (DER). */
export function rsaModulusBits(der: Uint8Array): number | undefined {
  let pos = 0;
  const read = (): { tag: number; start: number; end: number } | undefined => {
    const tag = der[pos];
    let len = der[pos + 1];
    if (tag === undefined || len === undefined) return undefined;
    pos += 2;
    if (len & 0x80) {
      const n = len & 0x7f;
      if (n === 0 || n > 4) return undefined;
      len = 0;
      for (let i = 0; i < n; i++) len = len * 256 + (der[pos++] ?? 0);
    }
    const start = pos;
    if (start + len > der.length) return undefined;
    return { tag, start, end: start + len };
  };
  const outer = read();
  if (!outer || outer.tag !== 0x30) return undefined;
  let first = read();
  if (!first) return undefined;
  if (first.tag === 0x30) {
    // SubjectPublicKeyInfo: AlgorithmIdentifier, then a BIT STRING holding RSAPublicKey.
    pos = first.end;
    const bits = read();
    if (!bits || bits.tag !== 0x03 || der[bits.start] !== 0) return undefined;
    pos = bits.start + 1;
    const inner = read();
    if (!inner || inner.tag !== 0x30) return undefined;
    first = read();
    if (!first) return undefined;
  }
  if (first.tag !== 0x02) return undefined;
  let i = first.start;
  while (i < first.end && der[i] === 0) i++;
  if (i >= first.end) return undefined;
  const top = der[i] ?? 0;
  return (first.end - i - 1) * 8 + (32 - Math.clz32(top));
}

function base64Bytes(b64: string): Uint8Array | undefined {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64) || b64.length % 4 === 1) return undefined;
  try {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  } catch {
    return undefined;
  }
}

// FWS as it reaches a TXT record: space, tab, CR and LF (RFC 6376 §2.8).
const strip = (s: string): string => s.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");

/**
 * A tag-list (RFC 6376 §3.2): every part is tag=value, tag names start with a letter, are
 * case-sensitive and appear once, and only a final ";" may be empty. Returns the tags in order,
 * or why the whole list is invalid.
 */
function parseTagList(record: string): Map<string, string> | string {
  const parts = record.split(";");
  if (parts.length > 1 && strip(parts[parts.length - 1] ?? "") === "") parts.pop();
  const tags = new Map<string, string>();
  for (const part of parts) {
    const m = /^[ \t\r\n]*([A-Za-z][A-Za-z0-9_]*)[ \t\r\n]*=(.*)$/s.exec(part);
    if (!m) return `"${strip(part)}" is not tag=value`;
    const name = m[1] ?? "";
    if (tags.has(name)) return `${name}= appears twice`;
    tags.set(name, strip(m[2] ?? ""));
  }
  return tags;
}

/**
 * A TXT that means to be a key record, so its errors are worth reporting. Any other TXT at the
 * name (a wildcard's SPF or verification token, RFC 6376 §6.1.2 note) is not a key and is ignored.
 */
export function keyLike(record: string): boolean {
  // Quotes pasted from zone file syntax do not hide a key record (parseKey reports them).
  const t = record.replace(/"/g, "");
  return /^[ \t\r\n]*v[ \t\r\n]*=[ \t\r\n]*DKIM/i.test(t) || /(^|;)[ \t\r\n]*[pk][ \t\r\n]*=/i.test(t);
}

type Problem = {
  id: "dkim-invalid-record" | "dkim-key-under-1024" | "dkim-key-1024" | "dkim-sha1-only" | "dkim-testing-mode";
} & FindingExtra;

interface ParsedKey {
  key?: DkimKey;
  problems: Problem[];
  /** The key can verify a signature that receivers count; revoked keys never can. */
  usable: boolean;
  /** s= lists neither email nor *: mail verifiers ignore the record (RFC 6376 §3.6.1). */
  notForMail?: boolean;
}

/** One key record, by the tags of RFC 6376 §3.6.1, read case-sensitively as §3.2 asks. */
export function parseKey(selector: string, record: string, viaCname?: string): ParsedKey {
  const invalid = (why: string, vars?: FindingVars): ParsedKey => ({
    problems: [{ id: "dkim-invalid-record", found: `${selector}: ${why}`, ...(vars ? { vars } : {}) }],
    usable: false,
  });
  // k=RSA or h=SHA256: a value a verifier would know in lower case.
  const CASE: FindingVars = { reason: "case" };
  const tags = parseTagList(record);
  // The usual panel mistake: a value pasted with its zone file quotes ("…AB" "CD…"). Only n= may
  // hold a quote (qp-section, RFC 6376 §2.11 and §3.6.1); anywhere else it breaks the record.
  const quoted =
    typeof tags === "string"
      ? record.includes('"')
      : [...tags].some(([name, value]) => name !== "n" && value.includes('"'));
  if (quoted)
    return {
      problems: [
        { id: "dkim-invalid-record", found: `${selector}: quote marks inside the record`, vars: { reason: "quotes" } },
      ],
      usable: false,
    };
  if (typeof tags === "string") return invalid(tags);
  const v = tags.get("v");
  if (v !== undefined && (v !== "DKIM1" || tags.keys().next().value !== "v"))
    return invalid("v= must be DKIM1 and come first");
  const list = (tag: string): string[] | undefined => tags.get(tag)?.split(":").map(strip);

  const services = list("s");
  if (services && !services.includes("email") && !services.includes("*")) {
    // A key for another service (RFC 8460 §3 suggests s=tlsrpt) is no mail key: info only.
    return {
      problems: [
        {
          id: "dkim-invalid-record",
          found: `${selector}: s=${tags.get("s") ?? ""}`,
          severity: "info",
          vars: { reason: "service" },
        },
      ],
      usable: false,
      notForMail: true,
    };
  }
  // RFC 6376 §3.2: values are case-sensitive unless the tag says otherwise, and k= and h= do not;
  // k=RSA is not a key type a verifier knows.
  const k = tags.get("k") ?? "rsa";
  if (k !== "rsa" && k !== "ed25519")
    return invalid(`unknown key type k=${k}`, ["rsa", "ed25519"].includes(k.toLowerCase()) ? CASE : undefined);
  const p = tags.get("p");
  if (p === undefined) return invalid("no p= tag");
  const base: DkimKey = { selector, algorithm: k, revoked: false };
  if (viaCname) base.viaCname = viaCname;
  const data = p.replace(/[ \t\r\n]+/g, "");
  if (data === "") return { key: { ...base, revoked: true }, problems: [], usable: false };
  const bytes = base64Bytes(data);
  if (!bytes) return invalid("p= is not base64");

  const problems: Problem[] = [];
  let usable = true;
  if (k === "rsa") {
    const bits = rsaModulusBits(bytes);
    if (bits === undefined) return invalid("p= is not an RSA public key");
    base.bits = bits;
    // RFC 8301 §3.2: at least 1024 bits, 2048 recommended.
    if (bits < 1024) {
      problems.push({ id: "dkim-key-under-1024", found: `${selector}: ${bits} bits` });
      usable = false;
    } else if (bits < 2048) problems.push({ id: "dkim-key-1024", found: `${selector}: ${bits} bits`, vars: { bits } });
  } else if (bytes.length !== 32) return invalid("an Ed25519 key is 32 bytes (RFC 8463 §4.2)");

  const hashes = list("h");
  if (hashes?.includes("")) return invalid(`h=${tags.get("h") ?? ""} has an empty entry`);
  // RFC 6376 §6.1.2 step 6: a signature whose hash is not in h= fails. Both rsa-sha256 and
  // ed25519-sha256 (RFC 8463 §3) need sha256; rsa-sha1 must not be used (RFC 8301 §3.1).
  if (hashes && !hashes.includes("sha256")) {
    usable = false;
    if (hashes.includes("sha1"))
      problems.push({ id: "dkim-sha1-only", found: `${selector}: h=${tags.get("h") ?? ""}` });
    else {
      const cased = hashes.some((h) => h.toLowerCase() === "sha256");
      problems.push({
        id: "dkim-invalid-record",
        found: `${selector}: h=${tags.get("h") ?? ""} allows no sha256`,
        ...(cased ? { vars: CASE } : {}),
      });
    }
  }
  // RFC 6376 §3.6.1 t=y: receivers treat the mail as unsigned, so the key does not count.
  if (list("t")?.includes("y")) {
    problems.push({ id: "dkim-testing-mode", found: `${selector}: t=${tags.get("t") ?? ""}` });
    usable = false;
  }
  return { key: base, problems, usable };
}

interface Probe {
  selector: string;
  lookup: Lookup;
}

/**
 * A selector no provider uses, random so that no zone can publish it on purpose. A TXT answer at
 * it can only come from a *._domainkey wildcard (RFC 4592 §2.2).
 */
export function randomProbeSelector(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  return `pmp-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/** What a name answers, without its own name: equal for every name a wildcard answers. */
function wildcardKey(l: Lookup): string {
  const targets = l.answers.filter((r) => r.type === "CNAME").map((r) => String(r.data).toLowerCase());
  return JSON.stringify([l.status, targets, txt(l).sort()]);
}

function cnameOf(l: Lookup, name: string): string | undefined {
  const c = l.answers.find((r) => r.type === "CNAME" && r.name === name);
  return c ? String(c.data) : undefined;
}

/** What _domainkey.<d> and the random probe say about the names under it. */
type Signal = "none" | "hidden";

/**
 * Case A ("none"): signed DNS, validated by both operators (AD is their AND in confirmed()),
 * denies _domainkey.<d> with an empty answer section, by NXDOMAIN or NXNAME. With precomputed
 * signatures that denial cannot hide names below it: the NSEC or NSEC3 chain gives the
 * descendants away (RFC 8198 Appendix B). A server that signs on the fly (RFC 4470, RFC 9824
 * §7.2, PowerDNS live-signing) signs whatever its data says, so one missing the empty non-terminal
 * would deny it with keys below. Unsigned Route 53 zones deny it that way; signed zones with keys
 * did not, in a sample of 256 domains measured on 2026-11-19, so case A trusts only a denial both
 * operators validated. A DNS host that changes how it signs can change that. Case B
 * ("hidden"): _domainkey.<d> exists with no data of its own (NODATA, no NXNAME), so something sits
 * under it. Both need the probe to be denied (no wildcard, no NSEC without NXNAME) and every
 * selector lookup to come back with nothing at all: an empty p=, a CNAME or another TXT at a
 * selector is enough to make _domainkey exist. So do the ADSP and DKIM reporting records
 * (`others`: RFC 5617 §4.1, RFC 6651 §3.3), which make it exist with no key under it. Anything
 * else, a failure included, says nothing.
 */
function domainkeySignal(
  q0: Lookup | undefined,
  q1: Lookup | undefined,
  probes: readonly Probe[],
  others: readonly Lookup[],
): Signal | undefined {
  if (!q0?.result || !q1?.result) return undefined;
  const empty = (l: Lookup) => (l.status === "nxdomain" || l.status === "nodata") && l.answers.length === 0;
  const denied = (l: Lookup) =>
    l.result?.rcode === RCODE.NXDOMAIN || (l.result !== undefined && nxnameAt(l.result, l.name));
  if (!empty(q0) || !empty(q1) || !denied(q1) || !probes.every((p) => empty(p.lookup)) || !others.every(empty))
    return undefined;
  if (denied(q0)) return q0.result.ad ? "none" : undefined;
  return "hidden";
}

/**
 * The DKIM group of a check: the keys found at the common selectors and at `extraSelectors`, and
 * what the denial of _domainkey and of `probeSelector`, a name no one publishes, says when none is
 * found.
 */
export async function checkDkim(
  ctx: Ctx,
  domain: string,
  extraSelectors: readonly string[] = [],
  probeSelector = randomProbeSelector(),
): Promise<DkimResult> {
  const typed = extraSelectors.map((s) => s.trim().toLowerCase()).filter((s) => validSelector(s, domain));
  const selectors = [...new Set([...SELECTORS, ...typed])].filter((s) => validSelector(s, domain));
  const asking = (selector: string) => ask(ctx, `${selector}._domainkey.${domain}`, "TXT");
  // Q0 and the probe (Q1) carry DO: an NSEC with NXNAME only comes with it (RFC 9824 §5). Q0 is
  // shorter than the probe's name, so it fits DNS whenever the probe does.
  const probing = validSelector(probeSelector, domain);
  // _adsp and _report are shorter than the probe too; validSelector refuses their leading "_".
  const [probes, wild, q0, others]: [Probe[], Lookup | undefined, Lookup | undefined, Lookup[]] = await Promise.all([
    Promise.all(selectors.map(async (selector) => ({ selector, lookup: await asking(selector) }))),
    probing ? ask(ctx, `${probeSelector}._domainkey.${domain}`, "TXT", { dnssecOk: true }) : undefined,
    probing ? ask(ctx, `_domainkey.${domain}`, "TXT", { dnssecOk: true, confirm: true }) : undefined,
    probing ? Promise.all(["_adsp", "_report"].map(asking)) : [],
  ]);
  // A wildcard answers every selector alike, so an equal answer says nothing about that selector:
  // without this, an empty p= wildcard gives a revoked key and a broken one an invalid record at
  // every selector.
  const wildcard = wild && wild.status !== "failed" && wild.answers.length > 0 ? wildcardKey(wild) : undefined;
  const findings: Finding[] = [];
  const keys: DkimKey[] = [];
  const keyRecords: Record<string, string> = {};
  const chains: Record<string, string[]> = {};
  let wildTexts: string[] | undefined;
  if (wild && wildcard !== undefined) {
    const own = txt(wild).filter(keyLike);
    if (own.length > 0 && !cnameOf(wild, `${probeSelector}._domainkey.${domain}`)) wildTexts = own;
    // The wildcard's key is read once as selector "*", with no finding: no selector of the list was
    // found. keys keeps it so the fixes see the no-mail records' empty p= and a live wildcard key.
    const records = txt(wild).filter(keyLike);
    const parsed =
      records.length === 1
        ? parseKey("*", records[0] ?? "", cnameOf(wild, `${probeSelector}._domainkey.${domain}`))
        : undefined;
    if (parsed?.key && !parsed.notForMail) keys.push(parsed.key);
  }
  const usableKeys: DkimKey[] = [];
  const revoked: string[] = [];
  const broken: string[] = [];
  const dangling: { selector: string; target: string }[] = [];
  let found = false;

  for (const { selector, lookup } of probes) {
    const name = `${selector}._domainkey.${domain}`;
    const cname = cnameOf(lookup, name);
    if (lookup.status === "dnssec-broken") broken.push(selector);
    if (wildcard !== undefined && wildcardKey(lookup) === wildcard) continue;
    const records = txt(lookup).filter(keyLike);
    if (records.length === 0) {
      // A CNAME whose target has no key: left behind by a provider (dkim-dangling-cname).
      if (cname && (lookup.status === "nxdomain" || lookup.status === "nodata"))
        dangling.push({ selector, target: cname });
      continue;
    }
    if (records.length > 1) {
      // RFC 6376 §3.6.2.2: with several records at one selector “the results are undefined”, and
      // resolvers rotate the order, so each receiver may read a different key.
      found = true;
      findings.push(
        finding("dkim-invalid-record", { found: `${selector}: ${records.length} key records at one name` }),
      );
      continue;
    }
    const parsed = parseKey(selector, records[0] ?? "", cname);
    if (!cname) keyRecords[selector] = records[0] ?? "";
    for (const { id, ...extra } of parsed.problems) findings.push(finding(id, extra));
    if (parsed.notForMail || !parsed.key) {
      found ||= !parsed.notForMail;
      continue;
    }
    keys.push(parsed.key);
    if (parsed.key.revoked) {
      revoked.push(selector);
      continue;
    }
    found = true;
    chains[selector] = lookup.answers.filter((r) => r.type === "CNAME").map((r) => String(r.data).toLowerCase());
    // A validating receiver gets SERVFAIL for this name, so it never sees the key.
    if (parsed.usable && lookup.status !== "dnssec-broken") usableKeys.push(parsed.key);
  }

  // A provider that rotates through a group of selectors leaves the idle ones empty or dangling
  // while one of them holds the live key.
  const rotating = (selector: string) =>
    rotationGroupOf(selector)?.some((s) => s !== selector && keys.some((k) => k.selector === s && !k.revoked));
  const reported = revoked.filter((s) => !rotating(s));
  if (reported.length > 0) findings.push(finding("dkim-revoked", { found: reported.join(", ") }));
  if (broken.length > 0) {
    const where =
      broken.length === probes.length
        ? `every <selector>._domainkey.${domain}`
        : broken.map((s) => `${s}._domainkey.${domain}`).join(", ");
    findings.push(finding("dnssec-broken", { group: "dkim", found: `${where} TXT` }));
  }

  for (const d of dangling) {
    if (rotating(d.selector)) continue;
    findings.push(finding("dkim-dangling-cname", { found: `${d.selector}._domainkey.${domain} CNAME ${d.target}` }));
  }

  const usable = usableKeys.length > 0;
  const failedAll = probes.every((p) => p.lookup.status === "failed");
  // Whether a wildcard hides the answers is unknown when the probe failed.
  const someFailed = probes.some((p) => p.lookup.status === "failed") || wild?.status === "failed";
  const selectorList = usableKeys.map((k) => k.selector).join(", ");
  let signal: Signal | undefined;
  if (usable && usableKeys.every((k) => k.algorithm === "ed25519"))
    findings.push(finding("dkim-ed25519-only", { found: selectorList }));
  // With no usable key, the selector that did not answer may be the one that works.
  if (someFailed && !usable) {
    const first = probes.find((p) => p.lookup.status === "failed")?.lookup ?? wild;
    findings.push(
      finding("lookup-failed", {
        group: "dkim",
        found: `${failedAll ? "every" : "some"} _domainkey lookup`,
        ...(first ? { vars: failedVars(first) } : {}),
      }),
    );
  } else if (!found) {
    const vars: FindingVars = { tried: selectors.length };
    if (wildcard !== undefined) vars.wildcard = 1;
    signal = domainkeySignal(q0, wild, probes, others);
    if (signal) vars[signal] = 1;
    // The catalog tries the variants in order (catalog/dkim.ts): wildcard, none, typed, hidden.
    // A *._domainkey wildcard with a live key answers the given selector with that key (RFC 4592
    // §2.2), so mail signed with it may pass: “no key at this name” would be false.
    const given = probes.find((p) => p.selector === typed[0]);
    const wildKey =
      wildcard !== undefined &&
      keys.some((k) => k.selector === "*" && !k.revoked) &&
      given !== undefined &&
      wildcardKey(given.lookup) === wildcard;
    // An empty p= at the given selector is a revoked key (RFC 6376 §3.6.1), which dkim-revoked
    // names; “no key at this name” would send the user after a typo.
    if (typed[0] !== undefined && !wildKey && !revoked.includes(typed[0])) vars.typed = typed[0];
    // No key can sit under a _domainkey that signed DNS denies: mail signed as the domain fails
    // DKIM, a warning; check.ts turns it back into info for a domain without mail.
    findings.push(finding("dkim-not-found", { vars, ...(signal === "none" ? { severity: "warning" } : {}) }));
  }
  if (
    usable &&
    !findings.some((f) => (f.severity === "critical" || f.severity === "warning") && f.impact !== "hardening")
  ) {
    findings.push(finding("dkim-ok", { found: selectorList }));
  }
  // Not found is unknown (inconclusive), never a failure, unless signed DNS proves there is no key
  // at all.
  const status = statusOf(findings, { unknown: (!found && signal !== "none") || (someFailed && !usable) });
  return {
    status,
    findings,
    keys,
    selectorsTried: selectors.length,
    usable,
    found,
    failed: !found && someFailed,
    noAnswer: probes.filter((p) => p.lookup.status === "failed").map((p) => p.selector),
    records: keyRecords,
    chains,
    ...(wildTexts ? { wildcard: wildTexts } : {}),
  };
}
