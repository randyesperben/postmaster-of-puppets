// What the published policy asks of a forged email. A typical forgery comes from a server that
// is not the domain's and carries no DKIM signature of the domain, so its DMARC result follows
// from what the check already read.
// The first row that holds wins; the effective policy is the report's, never computed again.
import type { DmarcResult } from "./checks/dmarc.ts";
import { askOf, oneLevelDown } from "./checks/dmarc-tags.ts";
import type { Ask, Policy, Report, Simulation } from "./types.ts";

/** The requests from least to most. */
export const RANK: Record<Ask, number> = { nothing: 0, quarantine: 1, reject: 2 };

/** RFC 8601 with documentation names: the line a receiver adds, for each kind of result. */
function authResults(
  domain: string,
  kind: "fail" | "open-spf" | "no-dmarc",
  published?: Policy,
  mailFrom = domain,
): string {
  const head = "mx.receiver.example; spf=pass smtp.mailfrom=";
  if (kind === "open-spf") return `${head}${mailFrom}; dkim=none; dmarc=pass header.from=${domain}`;
  if (kind === "no-dmarc") return `${head}sender.example.net; dkim=none; dmarc=none header.from=${domain}`;
  return `${head}sender.example.net; dkim=none; dmarc=fail (p=${published ?? "none"}) header.from=${domain}`;
}

/**
 * Undefined with Can't tell, a name that does not exist without DMARC, or no DNS at all; also when
 * no policy is known because a DMARC lookup got no answer or failed DNSSEC validation: an open SPF
 * can decide Spoofable then, but the simulation would claim there is no record.
 */
export function simulate(
  r: Report,
  dmarc: Pick<DmarcResult, "effective" | "published" | "failed" | "dnssecBroken">,
): Simulation | undefined {
  if (r.verdict === "cant-tell" || r.outcome === "nxdomain" || r.outcome === "unreachable") return undefined;
  const d = r.domain;
  const effective = dmarc.effective;
  if (effective === undefined && (dmarc.failed || dmarc.dnssecBroken)) return undefined;
  if (effective === undefined)
    return { forgedDmarc: "none", asks: "nothing", reason: "no-dmarc", authResults: authResults(d, "no-dmarc") };
  // The forger puts the open domain in the envelope from any address, so SPF passes aligned: the
  // name itself also with aspf=s, its Organizational Domain (vars.org) only with aspf=r, the only
  // case where check.ts reads that domain's SPF.
  const pub = dmarc.published;
  // sp for the subdomains that exist, np for those that do not: the one that asks less, sp on a
  // tie, when it asks less than the name.
  const subdomainOf = (asks: Ask): Simulation["subdomain"] => {
    const sp = pub?.sp === undefined ? undefined : askOf(pub.sp);
    const np = pub?.np === undefined ? undefined : askOf(pub.np);
    const lowest = [
      sp !== undefined ? { asks: sp, tag: "sp" as const } : undefined,
      np !== undefined ? { asks: np, tag: "np" as const } : undefined,
    ]
      .filter((x) => x !== undefined)
      .reduce<{ asks: Ask; tag: "sp" | "np" } | undefined>(
        (a, b) => (a === undefined || RANK[b.asks] < RANK[a.asks] ? b : a),
        undefined,
      );
    return lowest && RANK[lowest.asks] < RANK[asks] ? lowest : undefined;
  };
  const open = r.findings.filter((f) => f.id === "spf-plus-all" || f.id === "spf-open-range");
  if (open.length > 0) {
    const from = open.some((f) => f.vars?.org === undefined) ? d : String(open[0]?.vars?.org);
    // dmarcAsks: what the effective policy, t=y and pct applied, would ask once that SPF is fixed
    // and the email fails DMARC.
    const dmarcAsks = askOf(effective);
    const sim: Simulation = {
      forgedDmarc: "pass",
      asks: "nothing",
      reason: "open-spf",
      dmarcAsks,
      authResults: authResults(d, "open-spf", undefined, from),
    };
    // pct from 1 to 99 took dmarcAsks a level down for RFC 7489 receivers only: the whole request
    // goes in sampled, as with a failing email (RFC 7489 §6.6.4, RFC 9989 Appendix A.6).
    if (
      pub &&
      pub.policy !== "none" &&
      effective === oneLevelDown(pub.policy) &&
      !pub.testing &&
      pub.pct !== undefined &&
      pub.pct !== 0
    ) {
      sim.sampled = { pct: pub.pct, full: askOf(pub.policy) };
    }
    // With strict SPF alignment a forgery of a subdomain cannot use the open domain in its
    // envelope, so it fails DMARC and gets sp or np; with aspf=r, the default, it
    // aligns through the Organizational Domain and passes like the name (RFC 9989 §4.4, §3.2.10.1).
    const sub = r.dmarc.tags.aspf?.toLowerCase() === "s" ? subdomainOf(dmarcAsks) : undefined;
    if (sub) sim.subdomain = sub;
    return sim;
  }
  const fail = (asks: Ask, reason: Simulation["reason"]): Simulation => {
    const sim: Simulation = { forgedDmarc: "fail", asks, reason, authResults: authResults(d, "fail", pub?.policy) };
    const sub = subdomainOf(asks);
    if (sub) sim.subdomain = sub;
    return sim;
  };
  // A quarantine or reject that t=y or pct took one level down says so, also when it lands on
  // none: policy-none is for p=none and an invalid p with a valid rua.
  const lowered = pub !== undefined && pub.policy !== "none" && effective === oneLevelDown(pub.policy);
  if (lowered && (pub.testing || pub.pct === 0)) return fail(askOf(effective), "testing");
  if (lowered && pub.pct !== undefined) {
    return { ...fail(askOf(effective), "sampled"), sampled: { pct: pub.pct, full: askOf(pub.policy) } };
  }
  if (effective === "none") return fail("nothing", "policy-none");
  return fail(askOf(effective), effective);
}
