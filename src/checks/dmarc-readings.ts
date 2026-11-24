// The two readings of the DMARC record in force: RFC 9989's, which the check follows, and the one a
// receiver that still follows RFC 7489 makes (dmarc-7489.ts). The weaker of the two counts; when
// they differ, the finding that names the cause carries weaker: 1.
import { finding } from "../findings.ts";
import type { Finding, Policy } from "../types.ts";
import { read7489, type Reading7489 } from "./dmarc-7489.ts";
import type { Applied, Run } from "./dmarc.ts";
import { lowerIf, weaker } from "./dmarc-tags.ts";

/**
 * The records an RFC 7489 receiver sees as several where it looks, and their name when it is not
 * the checked one.
 */
type Several = { records: string[]; at?: string };

/**
 * An RFC 7489 reading without an answer. Without a lookup, a part of the Public Suffix List did
 * not load: no DNS service is to blame, so the finding says so (catalog variant “list”).
 */
export function unanswered(run: Run, reading: Reading7489): void {
  run.out.failed = true;
  const failure = reading.failure ?? {
    found: "Public Suffix List",
    vars: { reason: "not-loaded", list: "Public Suffix List" },
  };
  run.out.findings.push(finding("lookup-failed", { group: "dmarc", ...failure }));
}

/**
 * The two readings: an RFC 7489 receiver may land on another record, or on none. Gives the
 * effective policy, the weaker of the two, whether the readings differ (split) and the records
 * RFC 7489 sees as several; undefined when its lookup got no answer and that matters.
 */
export async function compareReadings(
  run: Run,
  rec: Applied,
  effective: Policy,
): Promise<{ effective: Policy | undefined; split: boolean; several?: Several } | undefined> {
  const { ctx, domain, opts, steps, walkOk, out } = run;
  if (!walkOk) return { effective, split: false };
  const rfc7489 = await read7489(ctx, domain, steps, rec.step, opts);
  // With RFC 9989 at none the weaker reading is none whatever RFC 7489 reads, so its missing
  // answer changes nothing.
  if (rfc7489.failed && effective !== "none") {
    unanswered(run, rfc7489);
    return undefined;
  }
  // Only when RFC 7489 finds a record to apply there: with none (or several), its receivers apply
  // no DMARC (RFC 7489 §6.6.3), so that domain's SPF aligns for no one.
  if (rfc7489.at !== undefined && rfc7489.effective !== undefined) out.pslOrgDomain = rfc7489.at;
  if (rfc7489.failed || rfc7489.effective === effective) return { effective, split: false };
  const several = rfc7489.several
    ? { records: rfc7489.several, ...(rfc7489.at !== undefined && rfc7489.at !== domain ? { at: rfc7489.at } : {}) }
    : undefined;
  const differs = rfc7489.at !== undefined && rfc7489.at !== rec.step.domain;
  out.rfc7489 = {
    ...(rfc7489.effective ? { effective: rfc7489.effective } : {}),
    ...(differs ? { orgDomain: rfc7489.at } : {}),
  };
  // The two readings take the policy from different names: RFC 9989 from the record the
  // Tree Walk applies, RFC 7489 from the Organizational Domain of the list.
  if (differs) {
    out.findings.push(
      finding("dmarc-org-differs", {
        found: rec.record,
        vars: {
          orgDomain: rec.step.domain,
          policy: effective,
          pslOrgDomain: rfc7489.at ?? "",
          pslPolicy: rfc7489.effective ?? "no DMARC policy",
        },
      }),
    );
  }
  out.stronger =
    rfc7489.effective === undefined || weaker(effective, rfc7489.effective) === rfc7489.effective
      ? effective
      : rfc7489.effective;
  const weakest = rfc7489.effective === undefined ? undefined : weaker(effective, rfc7489.effective);
  return { effective: weakest, split: true, ...(several ? { several } : {}) };
}

/**
 * The weaker reading decides, so part of the receivers apply a stricter policy than the verdict
 * says: the finding that names the cause carries weaker: 1, so the report says which one it is.
 * np against sp on a name that does not exist (RFC 7489 has no np) has no finding of its own
 * unless the subdomains are open: it gets one.
 */
export function markWeaker(run: Run, rec: Applied, several: Several | undefined): void {
  const { own, opts, out, discarded } = run;
  const findings = out.findings;
  const subPolicy = rec.base.sp ?? rec.base.p;
  const nxPolicy = rec.base.np ?? rec.base.sp ?? rec.base.p;
  const npVersusSp =
    rec.step !== own && (opts.exists === "nxdomain" || opts.exists === "nxname") && subPolicy !== nxPolicy;
  let cause: Finding | undefined = findings.find((f) => f.id === "dmarc-org-differs") ?? discarded[0];
  if (!cause && several) {
    // RFC 9989 reads one record where RFC 7489 reads several (its version tag ignores case):
    // the cause is the extra record, which only those receivers see.
    cause = finding("dmarc-multiple-records", {
      found: several.records.join("\n"),
      ...(several.at ? { vars: { at: several.at } } : {}),
    });
    findings.push(cause);
  }
  if (!cause && npVersusSp) {
    cause = findings.find((f) => f.id === "dmarc-subdomains-open");
    if (!cause) {
      cause = finding("dmarc-subdomains-open", {
        found: rec.record,
        vars: { sp: lowerIf(rec.read, subPolicy), np: lowerIf(rec.read, nxPolicy), at: rec.step.domain },
      });
      findings.push(cause);
    }
  }
  // The subdomains' RFC 7489 Organizational Domain is another name, with no record or a weaker
  // one: the finding that names it is the cause.
  cause ??= findings.find((f) => f.id === "dmarc-subdomains-open" && f.vars?.pslOrgDomain !== undefined);
  cause ??= findings.find((f) => f.id === "dmarc-tag-typo") ?? findings.find((f) => f.id === "dmarc-invalid-policy");
  cause ??= findings.find((f) => f.id === "dmarc-pct" || f.id === "dmarc-testing-mode");
  if (cause) cause.vars = { ...cause.vars, weaker: 1 };
  // Several records at the name itself while a parent's record is in force: RFC 9989 discards
  // them and applies the parent's (§4.10, steps 2 and 6), RFC 7489 stops at them (§6.6.3). The
  // text names the parent.
  if (cause && cause === discarded[0] && cause.id === "dmarc-multiple-records" && rec.step !== own)
    cause.vars = { ...cause.vars, inherited: rec.step.domain };
}
