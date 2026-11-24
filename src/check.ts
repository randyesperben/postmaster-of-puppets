// One full check of a domain: every group, the verdict, the delivery answer and the fixes. MX
// goes first and alone: it probes the resolvers, so a network that blocks DoH fails fast on one
// name instead of on thirty.
import { checkDkim } from "./checks/dkim.ts";
import { checkDmarc } from "./checks/dmarc.ts";
import { aliasOf, askMx, checkMx, zoneApex } from "./checks/mx.ts";
import { checkSpf, ownOpen } from "./checks/spf.ts";
import { checkTransport } from "./checks/transport.ts";
import { displayText } from "./dns/codec.ts";
import { isAtOrBelow } from "./dns/names.ts";
import { deadline } from "./dns/deadline.ts";
import { createDohResolver, type DohResolver } from "./dns/doh.ts";
import { type Ctx, existence } from "./dns/lookup.ts";
import type { FindingVars } from "./finding-vars.ts";
import { finding, SEVERITY_ORDER, statusOf } from "./findings.ts";
import { attachFixes } from "./fixes.ts";
import { simulate } from "./simulate.ts";
import {
  ownerOf,
  providerList,
  providersForInclude,
  providersForMx,
  reachesTarget,
  sendersForMx,
  SHARED_INCLUDES,
} from "./providers.ts";
import type {
  CheckOptions,
  Finding,
  Group,
  GroupStatus,
  MailUse,
  NameExists,
  ParsedDomain,
  Provider,
  Report,
  SpfNode,
} from "./types.ts";
import { DELIVERY_ROW, decideDelivery, decideMailUse, decideVerdict, type Facts, sendsMail } from "./verdict.ts";

/** An include or redirect term of SPF, with its qualifier. */
const INCLUDE_OR_REDIRECT = /^[+?~-]?(include:|redirect=)/i;

/**
 * Providers seen in each signal, and the two questions that compare them. `chains` holds each
 * live key's selector with the CNAME targets on its way; `written`, the include and redirect terms
 * of the domain's own record, the only ones spf-unused-include asks about.
 */
function detectProviders(
  mxHosts: readonly string[],
  includes: readonly string[],
  written: readonly string[],
  chains: Readonly<Record<string, string[]>>,
) {
  const ids = (list: Provider[]) => new Set(list.map((p) => p.id));
  const byMx = ids(mxHosts.flatMap(providersForMx));
  const bySendingMx = ids(mxHosts.flatMap(sendersForMx));
  const bySpf = ids(includes.flatMap(providersForInclude));
  const owned = Object.entries(chains).flatMap(([s, chain]) => {
    const p = ownerOf(s, chain);
    return p ? [[s, p] as const] : [];
  });
  const byDkim = ids(owned.map(([, p]) => p));
  const all = [...new Set([...byMx, ...bySpf, ...byDkim])];
  const questions: Finding[] = [];
  for (const id of bySpf) {
    const p = providerList.find((x) => x.id === id);
    // Only a provider whose DKIM selectors are probed can be missed by the check; one with
    // secret selectors (Amazon SES tokens) would always look unused. A live key at one of its
    // selectors answers the question even when nothing attributes it (m1 in TXT for SendGrid), and
    // so does one whose CNAME reaches its target under a selector that names no one (cm into
    // sendgrid.net).
    if (!p || p.dkimSelectors.length === 0 || byMx.has(id) || byDkim.has(id)) continue;
    if (p.dkimSelectors.some((s) => s in chains) || Object.values(chains).some((chain) => reachesTarget(p, chain)))
      continue;
    // An include inside another is the host's, not the domain's: no question about it.
    const term = written.find((t) => providersForInclude(t.replace(INCLUDE_OR_REDIRECT, "")).some((x) => x.id === id));
    if (term) questions.push(finding("spf-unused-include", { found: term, vars: { provider: p.name } }));
  }
  // A provider that sends with its own return path (sendOnly), or with no MX or include to
  // compare with, is never asked about: the question would push to delete a key in use. Its
  // fixInclude in the SPF is its own too, though it names no one by itself (Nominalia's page:
  // spf.webapps.net and no MX).
  for (const [sel, p] of owned) {
    if (p.sendOnly || p.mx.length + p.spfIncludes.length === 0 || byMx.has(p.id) || bySpf.has(p.id)) continue;
    if (p.fixInclude && includes.some((i) => isAtOrBelow(i, p.fixInclude as string))) continue;
    if (questions.some((q) => q.vars?.provider === p.name)) continue;
    questions.push(finding("dkim-unused-provider", { found: `${sel}._domainkey`, vars: { provider: p.name } }));
  }
  // Seen only by an MX that says nothing of sending (a gateway, an SES receiving endpoint): not a
  // service that sends as the domain (sendingServices).
  const inboundOnly = [...byMx].filter((id) => !bySendingMx.has(id) && !bySpf.has(id) && !byDkim.has(id));
  return { all, byMx, questions, inboundOnly };
}

/**
 * The include and redirect targets of the SPF tree that can name a provider: all of them but what a
 * shared host include holds, which is the host's (SHARED_INCLUDES). Without a tree (several
 * records), the walk's own list.
 */
function namingIncludes(tree: SpfNode | undefined, all: readonly string[]): string[] {
  if (!tree) return [...all];
  const out: string[] = [];
  const visit = (n: SpfNode) => {
    for (const c of n.children) {
      if (!c.domain || !INCLUDE_OR_REDIRECT.test(c.term)) continue;
      out.push(c.domain);
      if (!SHARED_INCLUDES.some((s) => isAtOrBelow(c.domain as string, s))) visit(c);
    }
  };
  visit(tree);
  return [...new Set(out)];
}

/**
 * Checks a domain's email records (MX, SPF, DKIM, DMARC, MTA-STS and TLS-RPT) and resolves to its
 * report: the verdict, the delivery answer, the findings and the fixes. It never rejects because
 * of DNS: a lookup without an answer is a finding (lookup-failed). The time limit (opts.deadlineMs,
 * 10 s by default) cuts the lookups still in flight, which then count as unanswered, and the
 * outcome says "partial" unless the name does not exist.
 */
export async function checkDomain(input: ParsedDomain, opts: CheckOptions = {}): Promise<Report> {
  const domain = input.domain;
  const limit = deadline(opts.deadlineMs, opts.signal);
  // A new DoH client per check, so checking a domain again starts with every resolver available.
  let doh: DohResolver | undefined;
  if (!opts.resolver) {
    doh = createDohResolver({
      ...(opts.resolverOrder ? { order: opts.resolverOrder } : {}),
      signal: limit.signal,
      onSwitch: (from, to) => opts.onProgress?.({ type: "resolver-switch", from, to }),
    });
  }
  const resolver = opts.resolver ?? (doh as DohResolver);
  const ctx: Ctx = { resolver, signal: limit.signal };
  const emit = (group: Group, status: GroupStatus, findings: Finding[]) =>
    opts.onProgress?.({ type: "group", group, status, findings });

  try {
    const first = await askMx(ctx, domain);
    // Every resolver failed on the first name: DoH is blocked or the network is down. The first
    // failure of the pair already sent the probe (doh.ts); only the probe finding no endpoint says
    // so, since endpoints that answer it while the domain's own DNS is silent mean the network is
    // fine.
    const nobody = doh !== undefined && doh.unreachable();
    if (first.status === "failed" && nobody) {
      return unreachableReport(input, (await checkMx(ctx, domain, first)).findings);
    }

    const track = <T extends { status: GroupStatus; findings: Finding[] }>(group: Group, p: Promise<T>) =>
      p.then((r) => {
        emit(group, r.status, r.findings);
        return r;
      });
    // The rest starts with the MX answer, and the MX hosts' addresses go out with it: one DoH
    // round less.
    const mxDone = track("mx", checkMx(ctx, domain, first));
    const others = Promise.all([
      zoneApex(ctx, domain),
      track("spf", checkSpf(ctx, domain)),
      track("dkim", checkDkim(ctx, domain, opts.extraSelectors ?? [])),
      track("transport", checkTransport(ctx, domain)),
    ]);
    // Whether the name exists decides np against sp for an inherited DMARC policy. An empty MX
    // answer says nothing in zones with Compact Denial of Existence (Cloudflare answers NODATA
    // for names that do not exist), so one query with DO reads NXNAME (RFC 9824 §6).
    // A CNAME at the name means it exists, even when its target does not (RFC 6604 §3).
    const known: NameExists | undefined =
      aliasOf(first, domain) || first.status === "ok" ? "yes" : first.status === "nxdomain" ? "nxdomain" : undefined;
    const { exists, failure } = known ? { exists: known, failure: undefined } : await existence(ctx, domain);
    const dmarcDone = track(
      "dmarc",
      checkDmarc(ctx, domain, exists ? { exists } : failure ? { existsFailure: failure } : {}),
    );
    // With relaxed SPF alignment a forger puts the Organizational Domain in the envelope and SPF
    // aligns (RFC 9989 §4.10.2, “the same Organizational Domain”), so its SPF tree counts too: the
    // RFC 9989 one and the RFC 7489 one when it differs, whatever the two policies.
    const orgSpf = dmarcDone.then((d) => {
      const orgs = d.record === undefined || d.tags.aspf?.toLowerCase() === "s" ? [] : [d.orgDomain, d.pslOrgDomain];
      return Promise.all(
        [...new Set(orgs)]
          .filter((o): o is string => o !== undefined && o !== domain)
          .map(async (o) => ({ o, r: await checkSpf(ctx, o) })),
      );
    });
    const [[zone, spf, dkim, transport], dmarc, orgs, mx] = await Promise.all([others, dmarcDone, orgSpf, mxDone]);

    const partial = limit.expired();
    // A name that does not exist is a result of its own only when no DMARC record covers it; with
    // one, the verdict comes from its np or sp.
    const gone = (exists === "nxdomain" || exists === "nxname") && dmarc.record === undefined && !dmarc.failed;
    const outcome: Report["outcome"] = gone ? "nxdomain" : partial || opts.signal?.aborted ? "partial" : "done";

    const providers = detectProviders(
      mx.hosts.map((h) => h.host),
      namingIncludes(spf.tree, spf.includes),
      spf.written,
      dkim.chains,
    );
    for (const h of mx.hosts) {
      const p = providersForMx(h.host)[0];
      if (p) h.provider = p.id;
    }
    // Only what can open the name or leave it unanswered: the rest of that record is not this
    // name's. vars.org says the record is the Organizational Domain's, for the verdict too;
    // vars.psl that only the public suffix list makes it so (RFC 7489), so receivers that follow
    // RFC 9989 do not align with it.
    const orgFindings: Finding[] = orgs.flatMap(({ o, r }) =>
      r.findings.flatMap((f): Finding[] =>
        ["spf-plus-all", "spf-open-range", "lookup-failed", "dnssec-broken"].includes(f.id)
          ? [{ ...f, vars: { ...f.vars, org: o, ...(o !== dmarc.orgDomain ? { psl: 1 } : {}) } }]
          : [],
      ),
    );
    // The fix of an opening in the name's own record leaves one inside an include it keeps
    // (checks/spf.ts, cleanedVia): vars.cleanedVia marks the name's own opening, whose fix alone
    // leaves the name open.
    const ownSpf = spf.cleanedVia
      ? spf.findings.map((f): Finding => (ownOpen(f) ? { ...f, vars: { ...f.vars, cleanedVia: 1 } } : f))
      : spf.findings;
    // An SPF record published at example.com.example.com is found by the DMARC check's probe.
    const spfFindings = [
      ...ownSpf,
      ...orgFindings,
      ...dmarc.spfDoubled,
      ...providers.questions.filter((q) => q.group === "spf"),
    ];
    const dkimFindings = [...dkim.findings, ...providers.questions.filter((q) => q.group === "dkim")];
    const findings = [...mx.findings, ...spfFindings, ...dkimFindings, ...dmarc.findings, ...transport.findings].sort(
      (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
    );
    // The checks read TXT as octets; people read UTF-8 (cafÃ© would show for café).
    for (const f of findings) if (f.found !== undefined) f.found = displayText(f.found);

    const facts: Facts = {
      partial: outcome === "partial",
      findings,
      mx: {
        lookup: mx.lookup,
        nullMx: mx.nullMx,
        hosts: mx.hosts.length,
        usable: mx.usable,
        unknown: mx.status === "unknown",
      },
      spf: { authorizes: spf.authorizes },
      dmarc: {
        failed: dmarc.failed,
        subdomainsOpen: dmarc.subdomainsOpen,
        ...(dmarc.effective ? { effective: dmarc.effective } : {}),
      },
      dkim: { found: dkim.found, usable: dkim.usable, failed: dkim.failed },
    };
    // weaker only when the weaker reading decides the verdict: with the stronger one the verdict
    // would be the same, e.g. an open SPF makes it Spoofable whatever DMARC asks.
    if (dmarc.stronger !== undefined || dmarc.strongerOpen !== undefined) {
      const strong = decideVerdict({
        ...facts,
        dmarc: {
          ...facts.dmarc,
          effective: dmarc.stronger ?? facts.dmarc.effective,
          subdomainsOpen: dmarc.strongerOpen ?? facts.dmarc.subdomainsOpen,
        },
      }).result;
      // The readings still differ, though the verdict does not depend on it: split says so, since
      // some receivers still apply the weaker policy.
      if (strong === decideVerdict(facts).result) {
        for (const f of findings) {
          if (f.vars?.weaker === undefined) continue;
          f.vars.split = 1;
          delete f.vars.weaker;
        }
      }
    }
    // Whether this name sends mail and whether it arrives are its own records' to say.
    const own: Facts = { ...facts, findings: findings.filter((f) => !orgFindings.includes(f)) };
    const mailUse = decideMailUse(own);
    const { nullMxSends, noKeys } = settleForMailUse(findings, mailUse, own, mx.nullMx);
    const delivery = decideDelivery(own, mailUse);
    const report: Report = {
      domain,
      display: input.display,
      outcome,
      ...(exists ? { exists } : {}),
      verdict: decideVerdict(facts).result,
      delivery: delivery.result,
      deliveryCause: { rule: delivery.rule, ...(delivery.cause ? { finding: delivery.cause.id } : {}) },
      mailUse,
      // The MX group follows its findings: a null MX raised to a warning makes it weak.
      groups: {
        mx: nullMxSends ? statusOf(mx.findings, { unknown: mx.status === "unknown" }) : mx.status,
        spf: statusOf(orgFindings) === "fail" ? "fail" : spf.status,
        dkim: noKeys ? "unknown" : dkim.status,
        dmarc: dmarc.status,
        transport: transport.status,
      },
      findings,
      providers: providers.all,
      ...(providers.inboundOnly.length ? { inboundOnly: providers.inboundOnly } : {}),
      mx: mx.hosts,
      spf: {
        lookups: spf.lookups,
        voidLookups: spf.voidLookups,
        ...(spf.record ? { record: displayText(spf.record) } : {}),
        ...(spf.tree ? { tree: spf.tree } : {}),
      },
      dmarc: {
        tags: dmarc.tags,
        ...(dmarc.record ? { record: displayText(dmarc.record) } : {}),
        ...(dmarc.foundAt ? { foundAt: dmarc.foundAt } : {}),
        ...(dmarc.orgDomain ? { orgDomain: dmarc.orgDomain } : {}),
        ...(dmarc.policyFrom ? { policyFrom: dmarc.policyFrom } : {}),
      },
      dkim: { keys: dkim.keys, selectorsTried: dkim.selectorsTried, noAnswer: dkim.noAnswer },
      resolvers: doh ? doh.responded() : [],
      checkedAt: new Date().toISOString(),
    };
    if (zone) report.zone = zone;
    const simulation = simulate(report, dmarc);
    if (simulation) report.simulation = simulation;
    attachFixes(report, {
      // The providers the MX says the domain sends through (a receiving-only MX writes no include).
      mxProviders: providerList.filter((p) => mx.hosts.some((h) => sendersForMx(h.host).includes(p))),
      spfAuthorizes: spf.authorizes,
      ...(spf.merged ? { spfMerged: spf.merged } : {}),
      ...(spf.cleanedOpen ? { spfCleanedOpen: true } : {}),
      dkimRecords: dkim.records,
      orgSpf: orgs.flatMap(({ o, r }) =>
        r.record ? [[o, displayText(r.record), r.cleanedOpen === true] as const] : [],
      ),
      ...(dmarc.cname ? { dmarcCname: dmarc.cname } : {}),
      ...(dmarc.subsAfterOwn ? { dmarcSubs: dmarc.subsAfterOwn } : {}),
      ...(dkim.wildcard ? { dkimWildcard: dkim.wildcard } : {}),
    });
    return report;
  } finally {
    limit.dispose();
  }
}

/**
 * The severities that depend on mailUse, set once it is known: the null MX of a domain that sends,
 * DKIM's “publishes no keys” and the rua of a domain that declares no mail. Says what the groups
 * need to know: whether the null MX was raised and whether DKIM's finding went back to info.
 */
function settleForMailUse(
  findings: Finding[],
  mailUse: MailUse,
  own: Facts,
  nullMx: boolean,
): { nullMxSends: boolean; noKeys: boolean } {
  // RFC 7505 §4.2: a null MX on a domain that sends puts its own mail at risk of rejection.
  // mailUse is "mail" with a null MX also when an SPF or DKIM lookup got no answer; then the
  // finding says that sending is not known, never that the domain sends.
  const nullMxSends = nullMx && mailUse === "mail";
  if (nullMxSends) {
    const signs: FindingVars = sendsMail(own) ? { sending: 1 } : { sendingUnknown: 1 };
    for (const f of findings) {
      if (f.id !== "mx-null") continue;
      f.severity = "warning";
      f.vars = { ...f.vars, ...signs };
    }
    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }
  // “Publishes no DKIM keys” is a warning only for a domain with mail: without mail it goes back
  // to an info finding that keeps the *._domainkey fix of the no-mail records. A group event
  // (onProgress) may already have given DKIM as weak before mailUse was known; the report's
  // groups say unknown.
  const noKeys =
    mailUse === "mail" ? undefined : findings.find((f) => f.id === "dkim-not-found" && f.vars?.none !== undefined);
  if (noKeys?.vars) {
    delete noKeys.vars.none;
    noKeys.severity = "info";
    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  }
  // A domain that declares no mail needs no aggregate reports: rua is optional for it.
  if (mailUse === "none-declared") for (const f of findings) if (f.id === "dmarc-no-rua") f.severity = "info";
  return { nullMxSends, noKeys: noKeys !== undefined };
}

/** The report when no DNS-over-HTTPS operator answers: only the MX findings, and no verdict. */
function unreachableReport(input: ParsedDomain, findings: Finding[]): Report {
  const unknown: GroupStatus = "unknown";
  return {
    domain: input.domain,
    display: input.display,
    outcome: "unreachable",
    verdict: "cant-tell",
    delivery: "unknown",
    deliveryCause: { rule: DELIVERY_ROW.unknown },
    mailUse: "mail",
    groups: { mx: unknown, spf: unknown, dkim: unknown, dmarc: unknown, transport: unknown },
    findings,
    providers: [],
    mx: [],
    spf: { lookups: 0, voidLookups: 0 },
    dmarc: { tags: {} },
    dkim: { keys: [], selectorsTried: 0, noAnswer: [] },
    resolvers: [],
    checkedAt: new Date().toISOString(),
  };
}
