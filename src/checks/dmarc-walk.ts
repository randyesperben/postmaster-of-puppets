// Where a DMARC record is found: the DNS Tree Walk (RFC 9989 §4.10), the Organizational Domain
// it gives (§4.10.2), the record a name inherits (§4.10.1), and whether a report destination
// outside that domain authorizes the reports (RFC 9990 §4).
import { isAtOrBelow } from "../dns/names.ts";
import { ask, type Ctx, failedVars, type Lookup, txt } from "../dns/lookup.ts";
import { MAX_NAME } from "../dns/names.ts";
import type { FindingVars } from "../finding-vars.ts";
import { isDmarcVersion, looksLikeDmarc, parseTags } from "./dmarc-tags.ts";

export interface WalkStep {
  domain: string;
  lookup: Lookup["status"];
  /** Every TXT string at _dmarc.<domain>, joined per record. */
  texts: string[];
  /**
   * The target when _dmarc.<domain> is a CNAME (a hosted DMARC service): a fix changes it there.
   */
  cname?: string;
  /** The single valid record at this name, if there is exactly one and its tag-list is valid. */
  record?: string;
  /** Records starting with v=DMARC1: more than one means all are discarded (§4.10 step 2). */
  valid: string[];
  /** TXT that looks like DMARC but does not start with v=DMARC1 (§4.7). */
  badVersion: string[];
  /** With lookup "failed": the vars of its lookup-failed finding. */
  failure?: FindingVars;
  /** A tag the single v=DMARC1 record repeats, which voids the whole tag-list (RFC 6376 §3.2). */
  repeated?: string;
  psd?: string;
}

/** The names a Tree Walk queries from `start` (§4.10 steps 3 to 7): at most eight. */
export function walkNames(start: string): string[] {
  const labels = start.split(".");
  const names = [start];
  let n = labels.length >= 8 ? 7 : labels.length - 1;
  for (; n >= 1; n--) names.push(labels.slice(labels.length - n).join("."));
  return names;
}

async function step(ctx: Ctx, domain: string, confirm: boolean): Promise<WalkStep> {
  // A name of 247 to 253 octets is valid, but _dmarc.<name> is longer than DNS can carry (253
  // octets, RFC 1035 §2.3.4): no record can be there, so the walk goes on above it instead of
  // failing the lookup.
  if (`_dmarc.${domain}`.length > MAX_NAME) return { domain, lookup: "nodata", texts: [], valid: [], badVersion: [] };
  const l = await ask(ctx, `_dmarc.${domain}`, "TXT", { confirm });
  const texts = txt(l);
  const valid = texts.filter(isDmarcVersion);
  const s: WalkStep = {
    domain,
    lookup: l.status,
    texts,
    valid,
    badVersion: texts.filter((t) => !isDmarcVersion(t) && looksLikeDmarc(t)),
  };
  if (l.status === "failed") s.failure = failedVars(l);
  const owner = `_dmarc.${domain}`;
  const cname = l.answers.find((a) => a.type === "CNAME" && a.name.toLowerCase().replace(/\.$/, "") === owner);
  if (cname) s.cname = String(cname.data).toLowerCase().replace(/\.$/, "");
  if (valid.length === 1 && valid[0] !== undefined) {
    const { tags, repeated } = parseTags(valid[0]);
    if (repeated !== undefined) {
      s.repeated = repeated;
    } else {
      s.record = valid[0];
      const psd = tags.psd?.toLowerCase();
      if (psd) s.psd = psd;
    }
  }
  return s;
}

/**
 * All the Tree Walk queries at once, then the stop rule: a single record with psd=y or n. The RFC
 * walks one name at a time and stops there, so a walk that stops early costs a query or two more
 * here (Appendix B.4.3 for giant.bank.example: three where the RFC makes two) for one round trip
 * instead of up to eight. `confirm: false` asks one operator, for lookups that never decide the
 * verdict (rua authorization).
 */
export async function treeWalk(
  ctx: Ctx,
  start: string,
  { confirm = true }: { confirm?: boolean } = {},
): Promise<WalkStep[]> {
  const steps = await Promise.all(walkNames(start).map((d) => step(ctx, d, confirm)));
  const stop = steps.findIndex((s) => s.psd === "y" || s.psd === "n");
  return stop >= 0 ? steps.slice(0, stop + 1) : steps;
}

/** §4.10.2: psd=n, then one label below psd=y, then the record with the fewest labels. */
export function orgDomainOf(steps: WalkStep[], start: string): string {
  const withRecord = steps.filter((s) => s.record !== undefined);
  const n = withRecord.find((s) => s.psd === "n");
  if (n) return n.domain;
  const y = withRecord.find((s) => s.psd === "y" && s.domain !== start);
  if (y) {
    const labels = start.split(".");
    return labels.slice(labels.length - y.domain.split(".").length - 1).join(".");
  }
  const last = withRecord[withRecord.length - 1];
  return last ? last.domain : start;
}

/**
 * §4.10.1: the record that applies to `name` when `name` has none of its own, from the walk above
 * it: the Organizational Domain's, or the PSD's when the Organizational Domain has none. `name`
 * need not be in `steps`: "*.<domain>" stands for any subdomain of <domain>, whose walk is the
 * same one.
 */
export function inheritedRecord(steps: WalkStep[], name: string): WalkStep | undefined {
  const withRecord = steps.filter((s) => s.record !== undefined);
  const n = withRecord.find((s) => s.psd === "n");
  if (n) return n;
  const y = withRecord.find((s) => s.psd === "y");
  if (y) {
    const labels = name.split(".");
    const org = labels.slice(labels.length - y.domain.split(".").length - 1).join(".");
    return withRecord.find((s) => s.domain === org) ?? y;
  }
  return withRecord[withRecord.length - 1];
}

/**
 * RFC 9990 §4: a destination outside the Organizational Domain of the place the record was found
 * needs <foundAt>._report._dmarc.<host>. The shortcut for a host at or below that Organizational
 * Domain skips the lookup even if the host's own record says psd=n, which would make it a
 * different Organizational Domain; the check accepts that to save the walk.
 */
export async function ruaAuthorized(
  ctx: Ctx,
  foundAt: string,
  org: string,
  host: string,
): Promise<boolean | undefined> {
  if (isAtOrBelow(host, org)) return true;
  // rua authorization goes to one operator: it never decides the verdict.
  const hostSteps = await treeWalk(ctx, host, { confirm: false });
  if (hostSteps.some((s) => s.lookup === "failed")) return undefined;
  if (orgDomainOf(hostSteps, host) === org) return true;
  const name = `${foundAt}._report._dmarc.${host}`;
  if (name.length > MAX_NAME) return false;
  const l = await ask(ctx, name, "TXT");
  if (l.status === "failed") return undefined;
  return txt(l).some(isDmarcVersion);
}
