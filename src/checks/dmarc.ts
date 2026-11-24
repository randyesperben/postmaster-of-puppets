// The DMARC check (RFC 9989, with RFC 9990 §4 for report destinations and RFC 6376 §3.2 for the
// tag-list syntax), read on 2026-11-18 from rfc-editor.org. Policy discovery and the
// Organizational Domain both come from the DNS Tree Walk (§4.10, dmarc-walk.ts). Alongside, the
// check reads the same records the way a receiver that still follows RFC 7489 does
// (dmarc-7489.ts), and the weaker of the two readings counts (dmarc-readings.ts). What the record
// leaves to the subdomains is dmarc-subdomains.ts, and the record's syntax dmarc-tags.ts.
import { ask, type Ctx, type Lookup, txt } from "../dns/lookup.ts";
import type { FindingVars } from "../finding-vars.ts";
import { finding, statusOf } from "../findings.ts";
import { MAX_NAME } from "../dns/names.ts";
import { isSpfRecord } from "./spf-terms.ts";
import type { PslLoaders } from "../psl.ts";
import type { Finding, GroupStatus, NameExists, Policy } from "../types.ts";
import { read7489 } from "./dmarc-7489.ts";
import { compareReadings, markWeaker, unanswered } from "./dmarc-readings.ts";
import { pslOrgDomainAtNone, type SubsAfterOwn, subdomainPolicy } from "./dmarc-subdomains.ts";
import {
  appliedPolicy,
  isDmarcVersion,
  isDmarcVersion7489,
  lowerIf,
  parseTags,
  pctOf,
  policy7489,
  type PolicyTags,
  readPolicy,
  ruaHosts,
} from "./dmarc-tags.ts";
import { inheritedRecord, orgDomainOf, ruaAuthorized, treeWalk, type WalkStep } from "./dmarc-walk.ts";

export interface DmarcResult {
  status: GroupStatus;
  findings: Finding[];
  /** record-name-doubled for an SPF record at <domain>.<domain>: it belongs to the SPF group. */
  spfDoubled: Finding[];
  lookup: Lookup["status"];
  record?: string;
  foundAt?: string;
  /** Undefined when a lookup of the walk failed, so the Organizational Domain is unknown. */
  orgDomain?: string;
  policyFrom?: "p" | "sp" | "np";
  tags: Record<string, string>;
  /** The policy receivers apply after t=y and pct; undefined when no DMARC applies. */
  effective?: Policy;
  /**
   * The name is not at none, but its subdomains end at none: the sp or np (after t=y and pct) of
   * the record that applies to them, which is the Organizational Domain's or the PSD's (§4.10.1).
   */
  subdomainsOpen: boolean;
  /** A lookup that decides the policy, for the name or for its subdomains, got no answer. */
  failed: boolean;
  dnssecBroken: boolean;
  /** The CNAME target of _dmarc.<domain>, for the fixes. */
  cname?: string;
  /**
   * The RFC 7489 reading when it differs from the RFC 9989 one: its policy (undefined: no DMARC)
   * and, when the Public Suffix List chose it, its Organizational Domain.
   */
  rfc7489?: { effective?: Policy; orgDomain?: string };
  /**
   * When the readings differ: the stronger one's policy, so the verdict can check that the weaker
   * reading decides it (check.ts drops weaker otherwise).
   */
  stronger?: Policy;
  /**
   * When the readings differ on whether subdomains are open (sp): the stronger one's answer, for
   * the same check.
   */
  strongerOpen?: boolean;
  /**
   * The RFC 7489 Organizational Domain whenever the list gives one with a record to apply, same
   * policy or not (check.ts reads its SPF).
   */
  pslOrgDomain?: string;
  /**
   * For the simulation (simulate.ts): the policy the record publishes for the name before t=y and
   * pct, whether t=y is set, pct when it is below 100, and sp and np (after t=y and pct) of the
   * record that applies to the name's subdomains (§4.10.1).
   */
  published?: { policy: Policy; testing: boolean; pct?: number; sp?: Policy; np?: Policy };
  /**
   * For Fix.after.sub (fixes.ts). Undefined when the check does not know: the walk failed, a
   * record of the name's own at none under a parent with one (the parent's sp is never read
   * then), or no record anywhere on a name of three labels or more (RFC 7489 receivers look where
   * the Public Suffix List says, and the list is not loaded for it).
   */
  subsAfterOwn?: SubsAfterOwn;
}

export interface DmarcOptions extends PslLoaders {
  /** Report.exists of the checked name; undefined when its lookup got no answer. */
  exists?: NameExists;
  /**
   * With exists undefined: the vars of the existence lookup's lookup-failed finding (failedVars).
   */
  existsFailure?: FindingVars;
}

/**
 * record-name-doubled: a TXT at _dmarc.<domain>.<domain> or <domain>.<domain>, the trace of a
 * DNS panel that added the domain after a full name. A wildcard answers those names too, so a
 * probe name tells a wildcard from a real mistake.
 */
async function doubledNames(ctx: Ctx, domain: string): Promise<Finding[]> {
  const names = [`_dmarc.${domain}.${domain}`, `${domain}.${domain}`].filter((n) => n.length <= MAX_NAME);
  const found = await Promise.all(
    names.map(async (name) => ({
      name,
      texts: txt(await ask(ctx, name, "TXT")).filter((t) => isDmarcVersion(t) || isSpfRecord(t)),
    })),
  );
  const hits = found.filter((f) => f.texts.length > 0);
  if (hits.length === 0) return [];
  const probe = txt(await ask(ctx, `_pmp-probe.${domain}`, "TXT"));
  return hits
    .filter((h) => !h.texts.every((t) => probe.includes(t)))
    .map((h) =>
      finding("record-name-doubled", {
        group: h.texts.some(isDmarcVersion) ? "dmarc" : "spf",
        found: `${h.name} ${h.texts[0] ?? ""}`,
      }),
    );
}

/**
 * What the phases of one check share: the Tree Walk, the step whose record applies to the name,
 * the records discarded at the name, and the result they fill in.
 */
export interface Run {
  ctx: Ctx;
  domain: string;
  opts: DmarcOptions;
  steps: WalkStep[];
  /** The checked name's own step. */
  own: WalkStep;
  /** No lookup of the walk failed. */
  walkOk: boolean;
  /**
   * The step whose record applies to the name: its own, or the one it inherits. Undefined when
   * none applies, or when a lookup of the walk failed and the name has no record of its own.
   */
  inForce: WalkStep | undefined;
  out: DmarcResult;
  /** Records discarded at the name itself; their severity waits for both readings (settle). */
  discarded: Finding[];
}

/** The record in force and its policy, as the phases after the policy read them. */
export interface Applied {
  step: WalkStep;
  record: string;
  tags: Record<string, string>;
  read: ReturnType<typeof readPolicy>;
  base: PolicyTags;
  /** The policy the record publishes for the name, before t=y and pct. */
  policy: Policy;
  /** aspf=r: a forger aligns with an envelope at the Organizational Domain. */
  relaxed: boolean;
}

/**
 * The DMARC group of a check: the record in force for the name, its policy in both readings, what
 * it leaves to the subdomains, and whether its report addresses accept the reports.
 */
export async function checkDmarc(ctx: Ctx, domain: string, opts: DmarcOptions = {}): Promise<DmarcResult> {
  const [steps, doubled] = await Promise.all([treeWalk(ctx, domain), doubledNames(ctx, domain)]);
  const own = steps[0] as WalkStep;
  const out: DmarcResult = {
    status: "unknown",
    findings: doubled.filter((f) => f.group === "dmarc"),
    spfDoubled: doubled.filter((f) => f.group === "spf"),
    lookup: own.lookup,
    tags: {},
    subdomainsOpen: false,
    failed: false,
    dnssecBroken: false,
  };
  if (own.cname) out.cname = own.cname;

  // Every step of the walk decides something: the policy of a name without a record of its own,
  // and the record that applies to the subdomains of a name with one. A record with psd=n
  // or psd=y stops the walk (treeWalk), so the names above it never count.
  const failedStep = steps.find((s) => s.lookup === "failed");
  const walkOk = failedStep === undefined;
  const inForce = own.record !== undefined ? own : walkOk ? inheritedRecord(steps.slice(1), domain) : undefined;
  const run: Run = {
    ctx,
    domain,
    opts,
    steps,
    own,
    walkOk,
    inForce,
    out,
    discarded: [discardedAt(own)].filter((f) => f !== undefined),
  };
  out.findings.push(...run.discarded);

  let lostStep: Finding | undefined;
  if (failedStep) {
    out.failed = true;
    lostStep = finding("lookup-failed", {
      group: "dmarc",
      found: `_dmarc.${failedStep.domain} TXT`,
      ...(failedStep.failure ? { vars: failedStep.failure } : {}),
    });
    out.findings.push(lostStep);
    if (!inForce) return done(run, { sameLevel: false });
  }
  const broken = steps.find((s) => s.lookup === "dnssec-broken");
  if (broken) {
    out.dnssecBroken = true;
    out.findings.push(finding("dnssec-broken", { group: "dmarc", found: `_dmarc.${broken.domain} TXT` }));
  }

  if (!inForce?.record) return withoutRecord(run);
  return withRecord(run, inForce, inForce.record, lostStep);
}

// With DNSSEC broken the verdict is Can't tell, so the group is unknown whatever the record
// read through CD says. With `settled`, the discarded records' severity is settled first (settle).
function done(run: Run, settled?: { sameLevel: boolean }): DmarcResult {
  if (settled) settle(run, settled);
  const { out } = run;
  return { ...out, status: out.dnssecBroken ? "unknown" : statusOf(out.findings, { unknown: out.failed }) };
}

/**
 * The record discarded at a step, if any: several, a repeated tag, or none with a valid version.
 * With `parent`, the step is a parent's: a warning that names it with vars.at.
 */
function discardedAt(step: WalkStep, { parent = false }: { parent?: boolean } = {}): Finding | undefined {
  const extra = parent ? { severity: "warning" as const } : {};
  const at = parent ? { at: step.domain } : {};
  if (step.valid.length > 1)
    return finding("dmarc-multiple-records", {
      ...extra,
      found: step.valid.join("\n"),
      ...(parent ? { vars: at } : {}),
    });
  if (step.repeated !== undefined)
    return finding("dmarc-bad-version", {
      ...extra,
      found: step.valid[0] ?? "",
      vars: { ...at, reason: "repeated-tag", tag: step.repeated },
    });
  if (step.valid.length === 0 && step.badVersion.length > 0)
    return finding("dmarc-bad-version", {
      ...extra,
      found: step.badVersion.join("\n"),
      ...(parent ? { vars: at } : {}),
    });
  return undefined;
}

/**
 * The severity of the records discarded at the name: a warning only when a parent's record
 * applies and the RFC 7489 reading gives the same level, or when the walk failed.
 */
function settle(run: Run, { sameLevel }: { sameLevel: boolean }): void {
  if (!run.walkOk || (run.inForce && sameLevel)) for (const f of run.discarded) f.severity = "warning";
}

/** No record in force: the name has no policy, for RFC 9989 at least. */
async function withoutRecord(run: Run): Promise<DmarcResult> {
  const { ctx, domain, opts, steps, own, walkOk, out, discarded } = run;
  if (discarded.length === 0) out.findings.push(finding("dmarc-missing"));
  // A parent's record discarded on the way: the name has no policy because of it, and neither
  // has the parent nor its other names. A warning names it with vars.at; dmarc-missing stays
  // the critical with its fix.
  const parent = walkOk && discarded.length === 0 ? steps.slice(1).find((x) => discardedAt(x)) : undefined;
  const notice = parent && discardedAt(parent, { parent: true });
  if (parent && notice) {
    out.findings.push(notice);
    // RFC 7489 reads tag names without case and a repeated tag with its weaker value (§6.3,
    // §6.4), so its receivers may apply the parent's record that RFC 9989 discards: two levels,
    // so the notice is the critical cause and says so. A reading of none is the same level as no
    // policy.
    const rfc7489 = await read7489(ctx, domain, steps, parent, opts);
    if (rfc7489.effective !== undefined && rfc7489.effective !== "none") {
      out.rfc7489 = { effective: rfc7489.effective, ...(rfc7489.at ? { orgDomain: rfc7489.at } : {}) };
      out.stronger = rfc7489.effective;
      notice.severity = "critical";
      notice.vars = { ...notice.vars, weaker: 1 };
    }
  }
  if (walkOk && ownSpeaksForSubs(domain, orgDomainOf(steps, domain))) out.subsAfterOwn = { kind: "own" };
  // RFC 9989 applies nothing; RFC 7489 may read the discarded record (V=DMARC1, its version tag
  // ignores case): then part of the receivers apply a policy and the cause says so.
  const own7489 = walkOk ? own.texts.filter(isDmarcVersion7489) : [];
  if (own7489.length === 1) {
    const policy = policy7489(own7489[0] ?? "");
    const cause = discarded[0];
    if (policy !== undefined && cause) {
      out.rfc7489 = { effective: policy };
      out.stronger = policy;
      cause.vars = { ...cause.vars, weaker: 1 };
    }
  }
  return done(run);
}

/** The record in force: its policy, the two readings, its subdomains and its report addresses. */
async function withRecord(
  run: Run,
  step: WalkStep,
  record: string,
  lostStep: Finding | undefined,
): Promise<DmarcResult> {
  const { domain, opts, steps, own, walkOk, out } = run;
  const { tags, typos } = parseTags(record);
  out.record = record;
  out.foundAt = step.domain;
  if (walkOk) out.orgDomain = orgDomainOf(steps, domain);
  out.tags = tags;
  for (const t of typos) out.findings.push(finding("dmarc-tag-typo", { found: t }));

  const read = readPolicy(tags);
  if (read.invalid) out.findings.push(finding("dmarc-invalid-policy", { found: record }));
  const base = read.base;
  if (!base) return withoutPolicy(run, step, record);

  const applied = appliedPolicy(base, { ownRecord: step === own, exists: opts.exists });
  if (!applied) {
    out.failed = true;
    out.findings.push(
      finding("lookup-failed", {
        group: "dmarc",
        found: `${domain} A`,
        vars: opts.existsFailure ?? { reason: "no-answer", name: domain },
      }),
    );
    return done(run, { sameLevel: true });
  }
  out.policyFrom = applied.from;
  // With aspf=r a forger aligns with an envelope at the Organizational Domain, so a lookup that
  // decides which name that is can turn the ruling row into Spoofable through its SPF (RFC 9989
  // §4.10.2; check.ts reads that SPF).
  const rec: Applied = {
    step,
    record,
    tags,
    read,
    base,
    policy: applied.policy,
    relaxed: tags.aspf?.toLowerCase() !== "s",
  };
  const ownEffective = lowerIf(rec.read, rec.policy);
  // A parent's step without an answer decides the subdomains and the Organizational Domain. Below
  // reject the subdomains change nothing, so it counts only while the Organizational Domain can:
  // not with none, Spoofable either way, nor with aspf=s.
  if (lostStep && ownEffective !== "reject" && (ownEffective === "none" || !rec.relaxed)) {
    out.findings.splice(out.findings.indexOf(lostStep), 1);
    out.failed = false;
  }

  const readings = await compareReadings(run, rec, ownEffective);
  if (!readings) return done(run, { sameLevel: true });
  settle(run, { sameLevel: out.rfc7489 === undefined });
  const { effective, several } = readings;
  let split = readings.split;
  if (effective === undefined) {
    if (split) markWeaker(run, rec, several);
    return done(run);
  }
  out.effective = effective;
  const pct = pctOf(tags) ?? 100;
  out.published = { policy: rec.policy, testing: read.testing, ...(pct < 100 ? { pct } : {}) };
  if (read.testing && rec.policy !== "none")
    out.findings.push(finding("dmarc-testing-mode", { found: `t=${tags.t ?? ""}` }));
  if (read.sampled && rec.policy !== "none")
    out.findings.push(finding("dmarc-pct", { found: `pct=${tags.pct ?? ""}` }));

  // With the walk incomplete the record that applies to the subdomains is unknown, and so is the
  // answer.
  let open: Finding | undefined;
  if (walkOk && out.effective !== "none") {
    const subs = await subdomainPolicy({
      ctx: run.ctx,
      domain,
      steps,
      lists: opts,
      step,
      read,
      ownRecord: step === own,
      relaxed: rec.relaxed,
      effective: out.effective,
      orgDomain: out.orgDomain,
    });
    if ("unanswered" in subs) {
      unanswered(run, subs.unanswered);
      return done(run);
    }
    if (subs.pslOrgDomain !== undefined && out.pslOrgDomain === undefined) out.pslOrgDomain = subs.pslOrgDomain;
    out.subdomainsOpen = subs.open;
    if (subs.split) {
      split = true;
      out.strongerOpen = false;
    }
    out.published = { ...out.published, policy: rec.policy, testing: read.testing, sp: subs.sp, np: subs.np };
    out.subsAfterOwn = subs.subsAfterOwn;
    open = subs.finding;
  }
  if (
    walkOk &&
    out.effective === "none" &&
    step === own &&
    rec.relaxed &&
    out.pslOrgDomain === undefined &&
    domain.split(".").length > 2
  ) {
    const at = await pslOrgDomainAtNone(run.ctx, domain, steps, step, opts);
    if (at !== undefined) out.pslOrgDomain = at;
  }

  // At none with a parent's record: the subdomains read that same record, whose sp or np is
  // no stronger for them than for the name, which is at none; a record here does not move it.
  if (walkOk && out.effective === "none" && own.record === undefined && out.orgDomain !== domain)
    out.subsAfterOwn = { kind: "kept", policy: "none", withOwn: false };
  else if (walkOk && out.effective === "none" && ownSpeaksForSubs(domain, out.orgDomain))
    out.subsAfterOwn = { kind: "own" };
  if (out.effective === "none") out.findings.push(finding("dmarc-policy-none", { found: record }));
  else if (out.effective === "quarantine") out.findings.push(finding("dmarc-policy-quarantine", { found: record }));
  if (open) out.findings.push(open);
  if (out.effective === "reject" && walkOk && !out.subdomainsOpen)
    out.findings.push(finding("dmarc-enforced", { found: record }));

  if (ruaHosts(tags.rua).length === 0) out.findings.push(finding("dmarc-no-rua"));
  if (tags.ruf) out.findings.push(finding("dmarc-ruf", { found: tags.ruf }));
  if (walkOk) await reportDestinations(run, step, tags);
  if (split) markWeaker(run, rec, several);
  return done(run);
}

/**
 * A record in force that applies no policy: an invalid or missing p, or an invalid sp or np, with
 * no valid rua. P=reject: RFC 7489 tag names ignore case, so those receivers read a policy. The
 * typo, or without one the invalid policy, is the cause.
 */
async function withoutPolicy(run: Run, step: WalkStep, record: string): Promise<DmarcResult> {
  const { ctx, domain, opts, steps, walkOk, out, discarded } = run;
  out.findings.push(finding("dmarc-missing", { found: record }));
  if (walkOk) {
    const rfc7489 = await read7489(ctx, domain, steps, step, opts);
    if (rfc7489.effective !== undefined) {
      out.rfc7489 = { effective: rfc7489.effective };
      out.stronger = rfc7489.effective;
      const cause =
        discarded[0] ??
        out.findings.find((f) => f.id === "dmarc-tag-typo") ??
        out.findings.find((f) => f.id === "dmarc-invalid-policy");
      if (cause) cause.vars = { ...cause.vars, weaker: 1 };
    }
  }
  return done(run, { sameLevel: true });
}

/**
 * Each rua and ruf destination outside the record's domain must authorize the reports. RFC 9990
 * §4 compares with the Organizational Domain of the place the record was found: a PSD's record
 * (Appendix B.4.3) reports to the PSD, not to the name checked.
 */
async function reportDestinations(run: Run, step: WalkStep, tags: Record<string, string>): Promise<void> {
  const { ctx, steps, out } = run;
  const org = orgDomainOf(steps.slice(steps.indexOf(step)), step.domain);
  const rua = ruaHosts(tags.rua);
  // RFC 9991 §5: ruf destinations go through the same procedure, with ruf in place of rua. A
  // host already in rua is asked once and named once.
  for (const r of ruaHosts(tags.ruf)) if (!rua.some((x) => x.host === r.host)) rua.push(r);
  const checks = await Promise.all(
    rua.map(async (r) => ({ ...r, ok: await ruaAuthorized(ctx, step.domain, org, r.host) })),
  );
  for (const c of checks)
    if (c.ok === false) out.findings.push(finding("dmarc-rua-unauthorized", { found: c.uri, vars: { host: c.host } }));
}

/**
 * A record published here, with none above it, speaks for its subdomains in RFC 9989; in RFC 7489
 * only on a name of two labels that is its own Organizational Domain without the list.
 */
function ownSpeaksForSubs(domain: string, orgDomain: string | undefined): boolean {
  return orgDomain === domain && domain.split(".").length <= 2;
}
