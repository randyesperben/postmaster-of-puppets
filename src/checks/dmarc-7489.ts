// The reading of a receiver that still follows RFC 7489: the Organizational Domain from the Public
// Suffix List, no np and no psd (RFC 7489 §3.2, §6.6.3). The DMARC check (dmarc.ts) compares it
// with the RFC 9989 reading, and the weaker of the two counts.
import { withSignal } from "../dns/doh.ts";
import { ask, type Ctx, failedVars, txt } from "../dns/lookup.ts";
import type { FindingVars } from "../finding-vars.ts";
import { type PslLoaders, psdDmarcRules, pslRestRules, publicSuffixIn } from "../psl.ts";
import type { Policy } from "../types.ts";
import { isDmarcVersion7489, policy7489 } from "./dmarc-tags.ts";
import type { WalkStep } from "./dmarc-walk.ts";

export interface Reading7489 {
  effective?: Policy | undefined;
  failed: boolean;
  /** With failed: the lookup that got no answer, for its lookup-failed finding. */
  failure?: { found: string; vars: FindingVars };
  /** The name whose record this reading takes when the checked name has none of its own. */
  at?: string;
  /**
   * Records this reading sees as several where it looks (V=DMARC1 next to v=DMARC1): no DMARC,
   * §6.6.3 step 5. At `at` when set.
   */
  several?: string[];
  /** No record at all at `at`, the Organizational Domain of the list (for the finding's text). */
  missing?: true;
}

/**
 * RFC 7489 §6.6.3 for the checked name: its own records first (several, or none valid, end in no
 * DMARC only when there are several: step 5), then the Organizational Domain of §3.2. That one
 * comes from the PSL rules of psd-dmarc.ts when the record the Tree Walk applies sits at or above
 * the longest of them; below every rule it is the Tree Walk's. Policies of PSDs never apply.
 * Read for `*.<name>` (a step with no record in front of the walk, and the record the Tree Walk
 * applies to the subdomains as inForce), it is what such a receiver applies to the subdomains.
 */
export async function read7489(
  ctx: Ctx,
  domain: string,
  steps: WalkStep[],
  inForce: WalkStep,
  lists: PslLoaders,
): Promise<Reading7489> {
  const own = (steps[0] as WalkStep).texts.filter(isDmarcVersion7489);
  if (own.length > 1) return { failed: false, several: own };
  if (own.length === 1) return { effective: policy7489(own[0] ?? ""), failed: false };

  // Both parts load within the check's own time limit: a slow part ends as a list that did not
  // load, never past the limit.
  let rules: ReadonlySet<string>;
  try {
    rules = await withSignal(psdDmarcRules(lists), ctx.signal);
  } catch {
    return { failed: true };
  }
  const suffix = publicSuffixIn(domain, rules);
  const labels = domain.split(".");
  // The list holds every PSL rule with a DMARC record at it or above (data/psd-dmarc.ts), so a PSL
  // rule below a listed one would be listed too: under a suffix of the list, the Organizational
  // Domain is that suffix plus one label, however far below the record sits. With no listed suffix
  // the TLD stands in, and a PSL rule without DMARC may hide between it and the record. TLD+1 with
  // a record of its own is no such rule (it would be listed); otherwise, with the record two or
  // more labels below the TLD, the rest of the PSL (psl-rest.ts) says which rule, if any, a
  // receiver that follows RFC 7489 stops at: co.uk for shop.example.co.uk. Only a part that does
  // not load leaves the reading unanswered. A psd=y record above the name declares a public suffix
  // the list may not have yet: it stands in before the TLD (RFC 9989 Appendix B.4.3).
  const psd =
    suffix === undefined
      ? steps.slice(1).find((x) => x.texts.some((t) => isDmarcVersion7489(t) && /(^|;)\s*psd\s*=\s*y\s*(;|$)/i.test(t)))
      : undefined;
  const suffixLabels = (suffix ?? psd?.domain)?.split(".").length ?? 1;
  let org = labels.slice(Math.max(0, labels.length - suffixLabels - 1)).join(".");
  if (
    suffix === undefined &&
    psd === undefined &&
    inForce.domain.split(".").length - suffixLabels >= 2 &&
    steps.find((x) => x.domain === org)?.texts.some(isDmarcVersion7489) !== true
  ) {
    let others: ReadonlySet<string>;
    try {
      others = await withSignal(pslRestRules(lists), ctx.signal);
    } catch {
      return { failed: true };
    }
    // No rule of psl-rest.ts sits below one of psd-dmarc.ts (it would have DMARC above it), so
    // with no listed suffix the longest of the rest is the longest of the whole PSL.
    const more = publicSuffixIn(domain, others);
    if (more !== undefined) org = labels.slice(Math.max(0, labels.length - more.split(".").length - 1)).join(".");
  }
  const byList = { at: org };
  if (org === domain) return { failed: false, ...byList };
  let texts = steps.find((x) => x.domain === org)?.texts;
  if (texts === undefined) {
    // A name of nine labels or more skips from the eighth to the seventh (§4.10 step 4): the
    // list's Organizational Domain may be one the walk never asked.
    const l = await ask(ctx, `_dmarc.${org}`, "TXT", { confirm: true });
    if (l.status === "failed") return { failed: true, failure: { found: `_dmarc.${org} TXT`, vars: failedVars(l) } };
    texts = txt(l);
  }
  const recs = texts.filter(isDmarcVersion7489);
  if (recs.length > 1) return { failed: false, ...byList, several: recs };
  if (recs.length === 0) return { failed: false, ...byList, missing: true };
  return { effective: policy7489(recs[0] ?? "", { forSubdomain: true }), failed: false, ...byList };
}
