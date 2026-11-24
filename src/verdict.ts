// The three answers of a report: can the domain be spoofed (verdictRules), will its real mail
// arrive (deliveryRules) and does it use mail at all (mailUse). decideVerdict and decideDelivery
// return the index of the rule that fired, in the order of rules.ts, so a test can pin every row
// and a caller can show the condition behind the answer.
import type { LookupStatus } from "./dns/lookup.ts";
import type { Delivery, Finding, FindingId, MailUse, Policy, Verdict } from "./types.ts";

/** What the checks found, reduced to what the rules read. */
export interface Facts {
  /**
   * The time limit (LookupOptions.deadlineMs) or the caller's signal cut lookups short:
   * Report.outcome "partial".
   */
  partial: boolean;
  findings: readonly Finding[];
  mx: { lookup: LookupStatus; nullMx: boolean; hosts: number; usable: number; unknown: boolean };
  spf: { authorizes: boolean };
  dmarc: { failed: boolean; effective?: Policy | undefined; subdomainsOpen: boolean };
  dkim: { found: boolean; usable: boolean; failed: boolean };
}

export interface Decision<T> {
  result: T;
  /** Index into verdictRules or deliveryRules. */
  rule: number;
  /** The finding that made the rule hold, when one did (deliveryRules). */
  cause?: Finding;
}

/** The rows of verdictRules (rules.ts), by what each one holds. */
const VERDICT_ROW = { unanswered: 0, noPolicy: 1, openSpf: 2, quarantineOrOpenSubdomains: 3, reject: 4 } as const;

/** The rows of deliveryRules (rules.ts), by what each one holds. */
export const DELIVERY_ROW = {
  noMail: 0,
  spfPermerror: 1,
  dkimUnusable: 2,
  noUsableMx: 3,
  dnssecBroken: 4,
  noDmarcOrSpf: 5,
  unknown: 6,
  ok: 7,
} as const;

const has = (f: Facts, id: FindingId, group?: string) =>
  f.findings.some((x) => x.id === id && (group === undefined || x.group === group));

// RFC 7208 §4.6.4, §4.5, §5.2 and §6: the cases where a receiver's evaluation ends in permerror.
const SPF_PERMERROR: readonly FindingId[] = [
  "spf-multiple-records",
  "spf-syntax-error",
  "spf-too-many-lookups",
  "spf-too-many-void-lookups",
  "spf-mx-too-many-hosts",
  "spf-include-no-spf",
  "spf-redirect-no-spf",
  "spf-duplicate-modifier",
];

/**
 * Data that could change the verdict is missing: DMARC always, unless the domain's own SPF
 * already lets anyone send; SPF only when DMARC would otherwise stop forged mail, because with
 * no DMARC or p=none the domain is Spoofable whatever SPF says; MX never, since no row of the
 * verdict reads it (RFC 9989 §4.10 finds the policy without MX). The time limit counts through
 * the lookups it cut: one of DMARC or SPF fails like any other, while DKIM selectors, MTA-STS,
 * TLS-RPT or a rua authorization cut short change no row of the verdict, and count as unanswered
 * in their own group only.
 */
function incomplete(f: Facts): boolean {
  const open = ownSpfOpen(f.findings);
  const spfUnanswered = f.findings.some(
    (x) =>
      (x.id === "lookup-failed" || x.id === "dnssec-broken") && x.group === "spf" && spfLookupDecides(f.findings, x),
  );
  // DMARC always, unless the domain's own SPF, answered in full, already lets anyone send: any
  // DMARC answer then gives Spoofable, by row 1 or row 2. An opening in the organizational
  // domain's SPF (vars.org) needs relaxed SPF alignment, which only DMARC says, so it does not
  // stand in for DMARC.
  if (dmarcUnanswered(f)) return spfUnanswered || !open;
  if (f.dmarc.effective === undefined || f.dmarc.effective === "none") return false;
  return spfUnanswered;
}

const dmarcUnanswered = (f: Facts) => f.dmarc.failed || has(f, "dnssec-broken", "dmarc");
const ownSpfOpen = (findings: readonly Finding[]) =>
  findings.some((x) => (x.id === "spf-plus-all" || x.id === "spf-open-range") && x.vars?.org === undefined);

/**
 * Whether an SPF lookup without a usable answer counts for the verdict, so a caller can tell which
 * lookups made it cant-tell. Anywhere in the SPF tree: an unanswered include may hide +all, and
 * a validating receiver gets temperror where DNSSEC is broken (RFC 7208 §5). With the domain's own
 * SPF open, a lookup the forger's evaluation never reaches (past the term that opens it,
 * vars.unreached) and the Organizational Domain's SPF (vars.org) change nothing.
 */
export function spfLookupDecides(findings: readonly Finding[], failed: Finding): boolean {
  return !(ownSpfOpen(findings) && (failed.vars?.unreached !== undefined || failed.vars?.org !== undefined));
}

export function decideVerdict(f: Facts): Decision<Verdict> {
  if (incomplete(f)) return { result: "cant-tell", rule: VERDICT_ROW.unanswered };
  // DMARC that did not answer is no missing policy: past row 0, the domain's own open SPF decides.
  if (!dmarcUnanswered(f) && (f.dmarc.effective === undefined || f.dmarc.effective === "none"))
    return { result: "spoofable", rule: VERDICT_ROW.noPolicy };
  if (has(f, "spf-plus-all") || has(f, "spf-open-range")) return { result: "spoofable", rule: VERDICT_ROW.openSpf };
  if (f.dmarc.effective === "quarantine" || f.dmarc.subdomainsOpen)
    return { result: "partly-protected", rule: VERDICT_ROW.quarantineOrOpenSubdomains };
  return { result: "protected", rule: VERDICT_ROW.reject };
}

/**
 * A sign of sending: SPF that lets some server send, or any DKIM key that is not revoked, usable
 * or not: a key in testing mode, short or mistyped is still someone's signing key. Taking a
 * domain that sends for one that does not breaks its mail; the other way round only gives it steps
 * it did not need.
 */
export function sendsMail(f: Facts): boolean {
  return f.spf.authorizes || f.dkim.found;
}

/** SPF or DKIM got no answer somewhere: whether the domain sends mail is not known. */
const sendingUnknown = (f: Facts) => f.dkim.failed || has(f, "lookup-failed", "spf");

export function decideMailUse(f: Facts): MailUse {
  // RFC 7505 §4.2: a null MX on a domain that sends risks its mail being rejected, so with signs
  // of sending it stays a domain with mail and never gets the no-mail records. An
  // SPF or DKIM lookup without an answer is no proof of no sending: it gets the steps too.
  if (f.mx.nullMx) return sendsMail(f) || sendingUnknown(f) ? "mail" : "none-declared";
  // No MX, no SPF that authorizes a sender and no DKIM key: nothing says the domain sends mail.
  // An MX lookup without an answer counts as no MX here: the report gets both paths, the no-mail
  // records and the DMARC steps. Any other lookup that failed is no evidence
  // either way, so the domain counts as using mail.
  const noMx = f.mx.lookup === "nodata" || f.mx.lookup === "nxdomain" || f.mx.lookup === "failed";
  if (noMx && !f.spf.authorizes && !f.dkim.found && !sendingUnknown(f)) return "probably-none";
  return "mail";
}

// RFC 8301 §3, RFC 6376 §3.2 and §3.6.1: what leaves a DKIM key that was found unusable
// (checks/dkim.ts).
const DKIM_UNUSABLE: readonly FindingId[] = [
  "dkim-key-under-1024",
  "dkim-sha1-only",
  "dkim-invalid-record",
  "dkim-testing-mode",
  "dnssec-broken",
];

/**
 * Each row of deliveryRules with the finding that made it hold, so a caller can name that
 * condition and not merely the first delivery finding. Rows 5 and 6 have no finding of their
 * own when the cause is mail without DMARC, the time limit or a failed lookup.
 */
export function decideDelivery(f: Facts, mailUse: MailUse): Decision<Delivery> {
  const first = (test: (x: Finding) => boolean) => f.findings.find(test);
  const at = (result: Delivery, rule: number, cause: Finding | undefined): Decision<Delivery> =>
    cause ? { result, rule, cause } : { result, rule };
  if (mailUse === "none-declared") return { result: "no-mail", rule: DELIVERY_ROW.noMail };
  const permerror = first((x) => SPF_PERMERROR.includes(x.id));
  if (permerror) return at("at-risk", DELIVERY_ROW.spfPermerror, permerror);
  if (f.dkim.found && !f.dkim.usable)
    return at(
      "at-risk",
      DELIVERY_ROW.dkimUnusable,
      first((x) => x.group === "dkim" && x.severity !== "info" && DKIM_UNUSABLE.includes(x.id)),
    );
  const noUsableHost = f.mx.hosts > 0 && f.mx.usable === 0 && !f.mx.unknown;
  // RFC 5321 §5.1: with no MX the domain itself is the implicit MX; without an address, nothing
  // can reach a domain that sends mail (replies, bounces, DMARC reports to itself).
  const noImplicit =
    mailUse === "mail" ? first((x) => x.id === "mx-missing" && x.vars?.implicit === "none") : undefined;
  const nullButSends = f.mx.nullMx && mailUse === "mail";
  const withOthers = first((x) => x.id === "mx-null-with-others");
  if (withOthers) return at("at-risk", DELIVERY_ROW.noUsableMx, withOthers);
  if (noUsableHost)
    return at(
      "at-risk",
      DELIVERY_ROW.noUsableMx,
      first((x) => x.group === "mx" && x.severity === "critical"),
    );
  if (noImplicit) return at("at-risk", DELIVERY_ROW.noUsableMx, noImplicit);
  if (nullButSends)
    return at(
      "at-risk",
      DELIVERY_ROW.noUsableMx,
      first((x) => x.id === "mx-null"),
    );
  const dnssec = first((x) => x.id === "dnssec-broken");
  if (dnssec) return at("at-risk", DELIVERY_ROW.dnssecBroken, dnssec);
  if (mailUse === "mail" && ((f.dmarc.effective === undefined && !f.dmarc.failed) || has(f, "spf-missing")))
    return { result: "at-risk", rule: DELIVERY_ROW.noDmarcOrSpf };
  // probably-none needs no DKIM key found, so the first test already covers that part of the row.
  if (!f.dkim.found || f.partial || has(f, "lookup-failed"))
    return at("unknown", DELIVERY_ROW.unknown, f.dkim.found ? undefined : first((x) => x.id === "dkim-not-found"));
  return { result: "ok", rule: DELIVERY_ROW.ok };
}
