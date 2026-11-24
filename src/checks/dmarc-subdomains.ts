// What the record in force means for the name's subdomains, in the RFC 9989 reading and in the
// RFC 7489 one, and what a record published at the name would leave to them (Fix.after.sub). The
// DMARC check (dmarc.ts) puts the answer in its result.
import type { Ctx } from "../dns/lookup.ts";
import type { FindingVars } from "../finding-vars.ts";
import { finding } from "../findings.ts";
import type { PslLoaders } from "../psl.ts";
import type { Finding, Policy } from "../types.ts";
import { read7489, type Reading7489 } from "./dmarc-7489.ts";
import { lowerIf, parseTags, policy7489, readPolicy, weaker } from "./dmarc-tags.ts";
import { inheritedRecord, type WalkStep } from "./dmarc-walk.ts";

/**
 * What a record published at _dmarc.<name> would leave to the name's subdomains, in the two
 * readings. "own": that record speaks for them in both, so they get its sp and np. "kept": another
 * name's record speaks for them in one reading or both, which the new record does not change;
 * `policy` is the weaker of those readings (after t=y and pct), and `withOwn` says the new record
 * speaks in the other one, so the weaker of the two applies.
 */
export type SubsAfterOwn = { kind: "own" } | { kind: "kept"; policy: Policy; withOwn: boolean };

export interface SubdomainsInput {
  ctx: Ctx;
  domain: string;
  steps: WalkStep[];
  lists: PslLoaders;
  /** The step whose record applies to the name, and that record as readPolicy reads it. */
  step: WalkStep;
  read: ReturnType<typeof readPolicy>;
  /** The record in force is the name's own. */
  ownRecord: boolean;
  /** aspf=r: a forger aligns with an envelope at the Organizational Domain. */
  relaxed: boolean;
  /** The name's effective policy, the weaker of the two readings. */
  effective: Policy;
  /** The RFC 9989 Organizational Domain. */
  orgDomain: string | undefined;
}

export interface Subdomains {
  /** sp or np ends at none in the weaker reading. */
  open: boolean;
  /** The readings differ on whether the subdomains are open. */
  split: boolean;
  /**
   * What the weaker reading asks of the subdomains that exist (sp) and of those that do not (np).
   */
  sp: Policy;
  np: Policy;
  subsAfterOwn: SubsAfterOwn;
  /**
   * The name's own RFC 7489 Organizational Domain, found on the way, for check.ts to read its SPF.
   */
  pslOrgDomain?: string;
  /** dmarc-subdomains-open, when they are open. */
  finding?: Finding;
}

/**
 * The RFC 7489 reading for x.<name>, a step with no record in front of the name's walk: what such
 * a receiver applies to the name's subdomains, where RFC 9989 applies the record of `forSubs`.
 */
function read7489ForSubdomains(
  ctx: Ctx,
  domain: string,
  steps: WalkStep[],
  forSubs: WalkStep,
  lists: PslLoaders,
): Promise<Reading7489> {
  const child = `*.${domain}`;
  return read7489(
    ctx,
    child,
    [{ domain: child, lookup: "nodata", texts: [], valid: [], badVersion: [] }, ...steps],
    forSubs,
    lists,
  );
}

/**
 * Subdomains of the name, which have no record of their own as far as the check knows, take the
 * record of their Organizational Domain or PSD (§4.10.1), with sp and np after t=y and pct.
 * §4.7 notes sp is ignored on records below the Organizational Domain, so a name's own record
 * speaks for its subdomains only when it is that Organizational Domain (or a PSD). `unanswered`
 * when an RFC 7489 lookup that decides got no answer.
 */
export async function subdomainPolicy(input: SubdomainsInput): Promise<Subdomains | { unanswered: Reading7489 }> {
  const { ctx, domain, steps, lists, step, read } = input;
  const forSubs = inheritedRecord(steps, `*.${domain}`) ?? step;
  const subRead = forSubs === step ? read : readPolicy(parseTags(forSubs.record ?? "").tags);
  // What RFC 9989 asks of the subdomains that exist (sp) and of those that do not (np).
  const existing9989 = subRead.base ? lowerIf(subRead, subRead.base.sp ?? subRead.base.p) : "none";
  const missing9989 = subRead.base ? lowerIf(subRead, subRead.base.np ?? subRead.base.sp ?? subRead.base.p) : "none";
  // The two readings apply to sp as to p: an RFC 7489 receiver reads SP= as sp, keeps the weaker
  // of two copies, has no np and lowers by pct, so p=reject; SP=none leaves its subdomains open.
  // The weaker reading decides.
  let subs7489 = forSubs.record === undefined ? undefined : policy7489(forSubs.record, { forSubdomain: true });
  // That receiver looks for the policy of x.<name> at the Organizational Domain the PSL gives
  // for x.<name>, and applies no DMARC when that name has no record (RFC 7489 §6.6.3 steps 3
  // and 5): shop.example.com at p=reject with nothing at example.com leaves x.shop.example.com
  // open for it. A name of two labels is that Organizational Domain itself, so no list loads for
  // it. For a name the PSL makes a public suffix, that receiver takes each x.<name> as its own
  // Organizational Domain and, with no record there, applies no DMARC (§3.2, §6.6.3 step 5).
  // Those subdomains belong to other owners, so this check keeps the record's sp for them, as
  // for two labels: a choice of scope, not what RFC 7489 does.
  let elsewhere: Reading7489 | undefined;
  // The name the list sends x.<name> to, when it is not x.<name> itself.
  let listAt: string | undefined;
  let pslOrgDomain: string | undefined;
  if (domain.split(".").length > 2) {
    const child = `*.${domain}`;
    const rfc7489 = await read7489ForSubdomains(ctx, domain, steps, forSubs, lists);
    // It decides when the name is at reject and RFC 9989 keeps the subdomains closed, and, for a
    // name with a record of its own, with aspf=r: x.<name> and <name> share the list's
    // Organizational Domain, whose SPF can make the name Spoofable for RFC 7489 receivers.
    const decides =
      (input.effective === "reject" && existing9989 !== "none" && missing9989 !== "none") ||
      (input.ownRecord && input.relaxed);
    if (rfc7489.failed && decides) return { unanswered: rfc7489 };
    // The name's own RFC 7489 Organizational Domain, for check.ts to read its SPF:
    // the read for x.<name> lands on the name's own one, or on x.<name> when the list makes the
    // name a public suffix, which leaves the name as its own.
    if (!rfc7489.failed && rfc7489.at !== undefined && rfc7489.at !== child) {
      pslOrgDomain = rfc7489.at;
      listAt = rfc7489.at;
    }
    if (!rfc7489.failed && rfc7489.at !== child && rfc7489.at !== forSubs.domain) {
      elsewhere = rfc7489;
      subs7489 = rfc7489.effective ?? "none";
    }
  }
  const sp = subs7489 === undefined ? existing9989 : weaker(existing9989, subs7489);
  const np = subs7489 === undefined ? missing9989 : weaker(missing9989, subs7489);
  const open = sp === "none" || np === "none";
  const open9989 = existing9989 === "none" || missing9989 === "none";
  // What a record published at _dmarc.<name> would leave to the subdomains: a reading
  // whose record is another name's stays as it is. RFC 9989: the name speaks for them when it
  // is their Organizational Domain, with or without a record today (orgDomainOf takes the
  // topmost record, a PSD's org or psd=n, none of which a record here moves). RFC 7489: the
  // name the list sends them to, or, when it sends them nowhere else, RFC 9989's record.
  const ownFor9989 = input.orgDomain === domain;
  const ownFor7489 = (listAt ?? (ownFor9989 ? domain : forSubs.domain)) === domain;
  const kept = [ownFor9989 ? undefined : weaker(existing9989, missing9989), ownFor7489 ? undefined : subs7489].filter(
    (p): p is Policy => p !== undefined,
  );
  const out: Subdomains = {
    open,
    split: open !== open9989,
    sp,
    np,
    subsAfterOwn:
      kept.length === 0
        ? { kind: "own" }
        : { kind: "kept", policy: kept.reduce(weaker), withOwn: ownFor9989 || ownFor7489 },
    ...(pslOrgDomain !== undefined ? { pslOrgDomain } : {}),
  };
  if (!open) return out;
  // The subdomains' policy comes from another name for RFC 7489 and leaves them open there:
  // the finding names that name whether or not RFC 9989 opens them too, and keeps sp and np to
  // the RFC 9989 reading, so each reading has its own cause and its own fix. both: RFC 9989
  // opens them as well; pslMissing and pslSeveral say what RFC 7489 finds at that name
  // (§6.6.3 step 5), for the text.
  const vars: FindingVars =
    elsewhere?.at !== undefined && subs7489 === "none"
      ? {
          sp: existing9989,
          np: missing9989,
          at: forSubs.domain,
          pslOrgDomain: elsewhere.at,
          ...(elsewhere.missing ? { pslMissing: 1 } : elsewhere.several ? { pslSeveral: 1 } : {}),
          ...(open9989 ? { both: 1 } : {}),
        }
      : { sp, np, at: forSubs.domain };
  return { ...out, finding: finding("dmarc-subdomains-open", { found: forSubs.record ?? "", vars }) };
}

/**
 * At none with a record of its own and aspf=r, the name's RFC 7489 Organizational Domain still
 * decides alignment: RFC 7489 §3.1.2 aligns an SPF domain with the same Organizational Domain,
 * which §3.2 takes from the public suffix list whatever the policy, so a forger with example.com
 * in the envelope passes DMARC for shop.example.com at those receivers when example.com's SPF is
 * open. RFC 9989 §4.10.2 makes shop.example.com, the topmost name with a record, its own
 * Organizational Domain, so its receivers do not align. The read is the one subdomainPolicy() makes
 * for x.<name>; a list that does not load leaves it unknown, which at none changes no verdict
 * (RFC 9989's reading is none either way).
 */
export async function pslOrgDomainAtNone(
  ctx: Ctx,
  domain: string,
  steps: WalkStep[],
  step: WalkStep,
  lists: PslLoaders,
): Promise<string | undefined> {
  const rfc7489 = await read7489ForSubdomains(ctx, domain, steps, step, lists);
  return !rfc7489.failed && rfc7489.at !== undefined && rfc7489.at !== `*.${domain}` ? rfc7489.at : undefined;
}
