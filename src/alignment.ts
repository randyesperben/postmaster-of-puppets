// Identifier alignment of a received message, as RFC 9989 §4.4 defines it: whether the envelope
// domain that SPF checked and the d= of each DKIM signature line up with the From domain. adkim
// and aspf come from the DMARC record that applies to the From domain; relaxed alignment compares
// Organizational Domains, which the same DNS Tree Walk as the DMARC check finds (§4.10.2).
import { parseTags } from "./checks/dmarc-tags.ts";
import { inheritedRecord, orgDomainOf, treeWalk } from "./checks/dmarc-walk.ts";
import { deadline } from "./dns/deadline.ts";
import { createDohResolver } from "./dns/doh.ts";
import type { Ctx } from "./dns/lookup.ts";
import type { LookupOptions } from "./types.ts";

/**
 * The domains of a received message: the From, the envelope sender that SPF checked, and the d= of
 * each DKIM signature.
 */
export interface AlignmentInput {
  /** The RFC 5322 From domain, in ASCII (punycode); case and a final dot do not matter. */
  fromDomain: string;
  /** The envelope domain SPF checked (RFC 5321 MAIL FROM), in ASCII; absent when there is none. */
  mailFromDomain?: string;
  /** The d= of each DKIM signature, in ASCII. */
  dkimDomains: readonly string[];
}
/** Identifier alignment of a received message (RFC 9989 §4.4), as `checkAlignment` gives it. */
export interface Alignment {
  /** From the DMARC record that applies to the From domain; "r" with no record. */
  adkim: "r" | "s";
  /** From the same record as adkim; "r" with no record. */
  aspf: "r" | "s";
  /** The envelope domain aligns with the From; absent without an envelope domain. */
  spf?: boolean;
  /** One entry per DKIM signature domain, in the order given, and whether it aligns under adkim. */
  dkim: { d: string; aligned: boolean }[];
  /** A query went unanswered or failed DNSSEC validation, so the alignment is not known. */
  failed: boolean;
}

const clean = (d: string) => d.trim().toLowerCase().replace(/\.$/, "");

/**
 * Whether the domains of a received message align with its From domain under the DMARC record
 * that applies to it (RFC 9989 §4.4). Like checkDomain, it never rejects because of DNS: a lookup
 * without an answer, or one that fails DNSSEC validation, sets `failed`.
 */
export async function checkAlignment(input: AlignmentInput, opts: LookupOptions = {}): Promise<Alignment> {
  const limit = deadline(opts.deadlineMs, opts.signal);
  const resolver =
    opts.resolver ??
    createDohResolver({ ...(opts.resolverOrder ? { order: opts.resolverOrder } : {}), signal: limit.signal });
  const ctx: Ctx = { resolver, signal: limit.signal };
  try {
    const from = clean(input.fromDomain);
    const mailFrom = input.mailFromDomain === undefined ? undefined : clean(input.mailFromDomain);
    const dkim = input.dkimDomains.map(clean);
    // One walk per name: the From domain's gives the record and its Organizational Domain.
    const names = [...new Set([from, ...(mailFrom !== undefined ? [mailFrom] : []), ...dkim])];
    const walks = new Map(await Promise.all(names.map(async (n) => [n, await treeWalk(ctx, n)] as const)));
    const failed = [...walks.values()].some((steps) =>
      steps.some((s) => s.lookup === "failed" || s.lookup === "dnssec-broken"),
    );
    const org = (n: string) => orgDomainOf(walks.get(n) ?? [], n);
    // §4.10.1: the From domain's own record, or the one the walk applies to it from above.
    const steps = walks.get(from) ?? [];
    const record = steps[0]?.record ?? inheritedRecord(steps.slice(1), from)?.record;
    const tags = record ? parseTags(record).tags : {};
    // "r" / "s" in RFC 9989 §4.8 are ABNF strings, so case does not matter (RFC 5234 §2.3).
    const adkim = tags.adkim?.toLowerCase() === "s" ? "s" : "r";
    const aspf = tags.aspf?.toLowerCase() === "s" ? "s" : "r";
    const aligned = (d: string, mode: "r" | "s") => d === from || (mode === "r" && org(d) === org(from));
    return {
      adkim,
      aspf,
      ...(mailFrom !== undefined ? { spf: aligned(mailFrom, aspf) } : {}),
      dkim: dkim.map((d) => ({ d, aligned: aligned(d, adkim) })),
      failed,
    };
  } finally {
    limit.dispose();
  }
}
