// The records a report proposes. Rules that keep a fix from breaking mail:
// - DMARC moves by steps (none with reports, quarantine, reject); only a domain that declares or
//   shows no mail gets reject at once.
// - One chain per DMARC record, on the first DMARC finding that needs it, so two findings never
//   propose different values for the same record.
// - SPF fixes only touch the domain's own record and never remove an include or a sender.
// - No fix where the right value depends on what only the owner knows (which host receives mail,
//   which services still send). The finding's text explains those.
import type { SubsAfterOwn } from "./checks/dmarc-subdomains.ts";
import { askOf, parseTags, weaker } from "./checks/dmarc-tags.ts";
import { allQualifier, cleanSpf, mergeSpf } from "./checks/spf-merge.ts";
import { first, type FixDraft, NO_MAIL_DKIM, NO_MAIL_DMARC, NO_MAIL_SPF } from "./fixes-common.ts";
import { dmarcAfter, dmarcFixes } from "./fixes-dmarc.ts";
import { HOST_HINT, HOST_HINT_NO_ZONE, STEP, STEP_FIRST, STEP_SUBDOMAINS } from "./fix-text.ts";
import type { Finding, Fix, Provider, Report } from "./types.ts";

/**
 * Host as DNS panels want it: relative to the zone apex, "@" at the apex. Without the apex the
 * host is the full name: one relative to a guessed zone, typed into a parent's panel, would land
 * on the parent's own record.
 */
function hostFor(name: string, zone: string | undefined): string {
  if (zone === undefined) return name;
  if (name === zone) return "@";
  return name.endsWith(`.${zone}`) ? name.slice(0, -(zone.length + 1)) : name;
}

// ---- SPF ----

/**
 * A term that lets some server pass: a mechanism with the pass qualifier (RFC 7208 §4.6.2, “+”
 * by default) or a redirect, which only counts when no all ends the record (§6.1).
 */
function authorizesSomeone(record: string): boolean {
  const terms = record.split(" ").slice(1).filter(Boolean);
  const hasAll = terms.some((t) => allQualifier(t) !== undefined);
  return terms.some((t) => {
    if (/^redirect=/i.test(t)) return !hasAll;
    return /^\+?(ip4|ip6|a|mx|include|exists|ptr)([:/]|$)/i.test(t);
  });
}

/**
 * The record without its open terms. Without them it might authorize no one, and every real
 * message of the domain would fail SPF: which servers send is the owner's to say (the finding
 * explains it).
 */
function openFix(
  on: Finding | undefined,
  name: string,
  record: string | undefined,
  cleanedOpen?: boolean,
): { on: Finding; fixes: FixDraft[] }[] {
  const cleaned = cleanSpf(record ?? "");
  // A cleaned record that a receiver would still find open is no fix: checks/spf.ts walks it, and
  // one whose walk did not finish counts as open.
  return on && record && cleaned !== record && !cleanedOpen && authorizesSomeone(cleaned)
    ? [{ on, fixes: [{ action: "replace", type: "TXT", name, value: cleaned, replaces: record }] }]
    : [];
}

/**
 * A merged record that a receiver would fault: a critical, or a warning other than hardening, the
 * findings that keep a record from spf-ok (checks/spf.ts). A fix adds no critical or warning the
 * starting records did not have.
 * The two SPF warnings of hardening are never new: spf-neutral-all needs a merged all of ? or
 * none, so neither starting record ended in -all or ~all and neither failed the senders it did not
 * list; spf-terms-after-all cannot come back, since mergeSpf drops the mechanisms after each all.
 */
const faulted = (findings: readonly Finding[]) =>
  findings.some((f) => f.severity === "critical" || (f.severity === "warning" && f.impact !== "hardening"));

function spfFixes(
  r: Report,
  providers: readonly Provider[],
  merged?: FixContext["spfMerged"],
  cleanedOpen?: boolean,
): { on: Finding; fixes: FixDraft[] }[] {
  const name = r.domain;
  const out: { on: Finding; fixes: FixDraft[] }[] = [];
  const multiple = r.findings.find((f) => f.id === "spf-multiple-records");
  if (multiple?.found) {
    const recs = multiple.found.split("\n");
    // A merged record the walk faulted is no record to copy: the finding keeps its steps.
    if (!merged || (merged.finished && !faulted(merged.findings))) {
      out.push({
        on: multiple,
        fixes: [
          { action: "replace", type: "TXT", name, value: merged?.record ?? mergeSpf(recs), replaces: recs[0] ?? "" },
          ...recs.slice(1).map((v): FixDraft => ({ action: "remove", type: "TXT", name, value: v, replaces: v })),
        ],
      });
    }
  }
  // The name's own findings: one with vars.org is about the Organizational Domain's record.
  const mine = { ...r, findings: r.findings.filter((f) => f.vars?.org === undefined) };
  out.push(
    ...openFix(
      first(mine, ["spf-plus-all", "spf-open-range", "spf-neutral-all", "spf-terms-after-all"]),
      name,
      r.spf.record,
      cleanedOpen,
    ),
  );
  const missing = r.findings.find((f) => f.id === "spf-missing");
  // Its first include, or the one its page gives that names no one by itself (fixInclude, Hover).
  const includeOf = (p: Provider) => p.spfIncludes[0] ?? p.fixInclude;
  const senders = providers.filter(
    (p, i, all) => includeOf(p) !== undefined && all.findIndex((q) => q.id === p.id) === i,
  );
  const includes = [...new Set(senders.flatMap((p) => includeOf(p) ?? []))];
  if (missing && includes.length > 0) {
    // A vendor that gives redirect= for a domain where it sends alone gets that record (Strato,
    // flagSources in the sources folder); with other senders, its include like any other.
    const alone = senders.length === 1 && senders[0]?.spfRedirect;
    // The mechanisms a vendor's page writes before its include (fixMechanisms: a mx for ALL-INKL,
    // whose include leaves out the customer's own server), as the page writes them.
    const mechanisms = [...new Set(senders.flatMap((p) => p.fixMechanisms ?? []))];
    const value = alone
      ? `v=spf1 redirect=${includes[0]}`
      : ["v=spf1", ...mechanisms, ...includes.map((i) => `include:${i}`), "~all"].join(" ");
    out.push({ on: missing, fixes: [{ action: "add", type: "TXT", name, value }] });
  }
  return out;
}

// ---- The no-mail records ----

/**
 * The empty key that tells verifiers no selector of the domain signs (RFC 6376 §3.6.1, p= empty),
 * as a wildcard. A broken wildcard is replaced: a second record at the name would leave two keys.
 */
function noMailDkim(r: Report, wildcard: readonly string[]): FixDraft[] {
  if (r.dkim.keys.length > 0) return [];
  const name = `*._domainkey.${r.domain}`;
  const [current, ...rest] = wildcard;
  if (current === undefined) return [{ action: "add", type: "TXT", name, value: NO_MAIL_DKIM }];
  return [
    { action: "replace", type: "TXT", name, value: NO_MAIL_DKIM, replaces: current },
    ...rest.map((v): FixDraft => ({ action: "remove", type: "TXT", name, value: v, replaces: v })),
  ];
}

/** k= and h= in lower case, the only case verifiers know (RFC 6376 §3.2 and §3.6.1). */
export function lowerKeyTags(record: string): string {
  return record.replace(
    /(^|;)([ \t\r\n]*)(k|h)([ \t\r\n]*=)([^;]*)/g,
    (_, sep: string, ws: string, tag: string, eq: string, value: string) =>
      `${sep}${ws}${tag}${eq}${value.toLowerCase()}`,
  );
}

function noMailSet(r: Report, ctx: FixContext): FixDraft[] {
  const d = r.domain;
  const fixes: FixDraft[] = [];
  // An alias holds no records of its own (RFC 1034 §3.6.2): its MX and SPF are the target's.
  const alias = isAlias(r);
  if (!alias) fixes.push({ action: "add", type: "MX", name: d, value: "0 ." });
  const spf = r.spf.record;
  if (alias) {
    // Nothing at the name itself.
  } else if (spf === undefined) fixes.push({ action: "add", type: "TXT", name: d, value: NO_MAIL_SPF });
  else if (spf !== NO_MAIL_SPF)
    fixes.push({ action: "replace", type: "TXT", name: d, value: NO_MAIL_SPF, replaces: spf });
  const dmarc = r.dmarc.record;
  const at = `_dmarc.${d}`;
  if (dmarc === undefined || r.dmarc.foundAt !== d)
    fixes.push({ action: "add", type: "TXT", name: at, value: NO_MAIL_DMARC });
  else if (!enforced(dmarc))
    fixes.push({ action: "replace", type: "TXT", name: at, value: NO_MAIL_DMARC, replaces: dmarc });
  fixes.push(...noMailDkim(r, ctx.dkimWildcard ?? []));
  return fixes;
}

/**
 * The finding that carries the path “If example.com sends no email” when the domain probably
 * sends none: mx-missing, or the MX lookup that got no answer (a missing MX answer shows both
 * paths).
 */
function noMailPath(f: Finding): boolean {
  return f.id === "mx-missing" || (f.id === "lookup-failed" && f.group === "mx" && f.found?.endsWith(" MX") === true);
}

/**
 * A record that already asks for reject everywhere, at full strength: the no-mail records keep it
 * as it is.
 */
function enforced(record: string): boolean {
  const t = parseTags(record).tags;
  return (
    t.p === "reject" &&
    t.sp !== "none" &&
    t.sp !== "quarantine" &&
    t.np !== "none" &&
    t.np !== "quarantine" &&
    t.pct === undefined &&
    t.t === undefined
  );
}

const isAlias = (r: Report) => r.findings.some((f) => f.id === "name-is-alias");

// ---- Entry point ----

export interface FixContext {
  /** Providers detected from the MX hosts, for an SPF record when there is none. */
  mxProviders: readonly Provider[];
  /** The SPF record lets some server send (checks/spf.ts). */
  spfAuthorizes: boolean;
  /** With two SPF records, the merged one and what its walk found (checks/spf.ts, merged). */
  spfMerged?: { record: string; findings: readonly Finding[]; finished: boolean };
  /**
   * The name's own record without its open terms still opens it, or its walk did not finish
   * (checks/spf.ts, cleanedOpen).
   */
  spfCleanedOpen?: boolean;
  /** The CNAME target of _dmarc.<domain>, when it is one (a hosted DMARC service). */
  dmarcCname?: string;
  /**
   * What a record at _dmarc.<domain> leaves to the subdomains (checks/dmarc-subdomains.ts), for
   * Fix.after.sub; absent when unknown.
   */
  dmarcSubs?: SubsAfterOwn | undefined;
  /** The key record at each selector that publishes its own (checks/dkim.ts, records). */
  dkimRecords?: Readonly<Record<string, string>>;
  /** The key records of a *._domainkey wildcard (checks/dkim.ts, wildcard). */
  dkimWildcard?: readonly string[];
  /** The SPF record of each Organizational Domain whose SPF was read, and its cleanedOpen. */
  orgSpf?: readonly (readonly [string, string, boolean])[];
}

/**
 * A name with a CNAME holds no other data (RFC 1034 §3.6.2, RFC 2181 §10.1). The first fix that
 * writes a record there removes the alias first and adds the record; removing a record that sits
 * at the alias's target is not this domain's to do.
 */
function throughAlias(fixes: FixDraft[], aliases: ReadonlyMap<string, string>): FixDraft[] {
  const out: FixDraft[] = [];
  const replaced = new Set<string>();
  for (const f of fixes) {
    const target = aliases.get(f.name);
    if (target === undefined || f.type === "CNAME" || replaced.has(f.name)) {
      out.push(f);
      continue;
    }
    if (f.action === "remove") continue;
    replaced.add(f.name);
    const { replaces: _, ...rest } = f;
    out.push(
      {
        action: "remove",
        type: "CNAME",
        name: f.name,
        value: target,
        replaces: target,
        ...(f.step ? { step: f.step } : {}),
      },
      { ...rest, action: "add" },
    );
  }
  return out;
}

/** Fills `fixes` on the report's findings; the report's verdict and mailUse are already set. */
export function attachFixes(r: Report, ctx: FixContext): void {
  const zone = r.zone;
  const aliases = new Map<string, string>(ctx.dmarcCname ? [[`_dmarc.${r.domain}`, ctx.dmarcCname]] : []);
  // Each fix that publishes a DMARC record says what that record asks (Fix.after): the
  // steps of a chain, a record of the name's own, the no-mail set's reject.
  // A record at the name's own _dmarc speaks for its subdomains only as far as ctx.dmarcSubs says:
  // a reading that another name's record decides stays, and an unknown one leaves sub out.
  const own = `_dmarc.${r.domain}`;
  const subs = ctx.dmarcSubs;
  const after = (f: FixDraft): Pick<Fix, "after"> => {
    // A remove carries its after only as the only fix, from the record that stays.
    const kept = f.after?.sub === undefined ? undefined : { asks: f.after.asks, sub: f.after.sub };
    const read =
      f.type !== "TXT" || !f.name.startsWith("_dmarc.")
        ? undefined
        : f.action === "remove"
          ? kept
          : dmarcAfter(f.value);
    if (!read) return {};
    if (f.name !== own || subs?.kind === "own") return { after: read };
    if (!subs) return { after: { asks: read.asks } };
    const sub = subs.withOwn ? weaker(read.sub === "nothing" ? "none" : read.sub, subs.policy) : subs.policy;
    return { after: { asks: read.asks, sub: askOf(sub) } };
  };
  const put = (on: Finding, fixes: FixDraft[]) => {
    on.fixes = throughAlias(fixes, aliases).map((f): Fix => ({ ...f, host: hostFor(f.name, zone), ...after(f) }));
  };
  for (const f of r.findings) f.fixes = [];
  const alias = isAlias(r);

  // A null MX with signs of sending is a domain with mail (verdict.ts, decideMailUse): reject at
  // once could stop its real mail, so it gets the steps like any domain with mail.
  const sends = r.mailUse === "mail";

  if (r.mailUse === "probably-none") {
    // Two paths, never the first alone: the no-mail records on mx-missing, the DMARC steps on its
    // finding.
    const mx = r.findings.find(noMailPath);
    if (mx) put(mx, noMailSet(r, ctx));
  }
  const nullMx = r.findings.find((f) => f.id === "mx-null" && f.vars?.preference !== undefined);
  if (nullMx && !sends && !alias)
    put(nullMx, [
      { action: "replace", type: "MX", name: r.domain, value: "0 .", replaces: `${nullMx.vars?.preference ?? ""} .` },
    ]);
  if (r.mailUse === "none-declared" && !sends) {
    const spfMissing = r.findings.find((f) => f.id === "spf-missing");
    if (spfMissing && !alias) put(spfMissing, [{ action: "add", type: "TXT", name: r.domain, value: NO_MAIL_SPF }]);
    const dkim = r.findings.find((f) => f.id === "dkim-not-found");
    // Revoked keys (the empty p= of the no-mail records) already say “no key here”.
    if (dkim) put(dkim, noMailDkim(r, ctx.dkimWildcard ?? []));
  }

  const doubledSpf = r.findings.some((f) => f.id === "record-name-doubled" && f.group === "spf");
  const dmarc = dmarcFixes(r, { sendsMail: sends || r.mailUse === "probably-none" });
  if (dmarc) put(dmarc.on, dmarc.fixes);

  if (r.mailUse !== "none-declared" && !alias) {
    for (const s of spfFixes(r, doubledSpf ? [] : ctx.mxProviders, ctx.spfMerged, ctx.spfCleanedOpen))
      if (s.on.fixes.length === 0) put(s.on, s.fixes);
  }
  // The Organizational Domain's record is fixed whatever this name's mail use.
  for (const [org, rec, cleanedOpen] of ctx.orgSpf ?? []) {
    const fix = openFix(
      r.findings.find((f) => f.vars?.org === org),
      org,
      rec,
      cleanedOpen,
    );
    for (const s of fix) put(s.on, s.fixes);
  }

  for (const f of r.findings) {
    if (f.id === "dkim-dangling-cname" && f.found) {
      const m = /^(\S+) CNAME (\S+)$/.exec(f.found);
      if (m) put(f, [{ action: "remove", type: "CNAME", name: m[1] ?? "", value: m[2] ?? "", replaces: m[2] ?? "" }]);
    }
    if (f.id === "dkim-invalid-record" && f.vars?.reason === "case" && f.found) {
      const selector = f.found.slice(0, f.found.indexOf(":"));
      const current = ctx.dkimRecords?.[selector];
      if (current !== undefined)
        put(f, [
          {
            action: "replace",
            type: "TXT",
            name: `${selector}._domainkey.${r.domain}`,
            value: lowerKeyTags(current),
            replaces: current,
          },
        ]);
    }
    if (f.id === "mx-null-with-others" && !alias)
      put(f, [{ action: "remove", type: "MX", name: r.domain, value: "0 .", replaces: "0 ." }]);
    if (f.id === "record-name-doubled" && f.found) {
      const space = f.found.indexOf(" ");
      const name = f.found.slice(0, space);
      const value = f.found.slice(space + 1);
      const fixes: FixDraft[] = [{ action: "remove", type: "TXT", name, value, replaces: value }];
      // A doubled SPF moves to the domain when the domain has none; DMARC's chain above
      // already rebuilds the record from these tags.
      if (f.group === "spf" && !alias && r.findings.some((x) => x.id === "spf-missing"))
        fixes.push({ action: "add", type: "TXT", name: r.domain, value });
      put(f, fixes);
    }
  }
}

// ---- The reports address ----

/**
 * A fix's value with the address `rua` put where {rua} stands, percent-encoded where a
 * mailto URI and the tag list need it: RFC 9989 §4.8 (commas and exclamation points MUST be
 * encoded), RFC 6068 §2 (“%”, “/ ? # [ ]” and “& ; =”); “;” would also end the tag.
 */
export function fillRua(value: string, rua: string): string {
  const encoded = rua.replace(/[%!,/?#[\]&;=]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return value.split("{rua}").join(encoded);
}

// ---- Every fix as one text ----

const VERB: Record<Fix["action"], string> = { add: "Add", replace: "Replace", remove: "Remove" };

function fixText(f: Fix, rua: string | undefined): string {
  const fill = (v: string) => (rua ? fillRua(v, rua) : v);
  const lines = [`${VERB[f.action]} ${f.type} record`, `Host: ${f.host}`, `Full name: ${f.name}`];
  if (f.action === "replace" && f.replaces !== undefined) lines.push(`Current value: ${fill(f.replaces)}`);
  lines.push(`${f.action === "remove" ? "Value" : "New value"}: ${fill(f.value)}`);
  if (f.step) {
    const firstAtNone = f.step.n === 1 && /(^|; )p=none(;|$)/.test(f.value);
    const subdomains =
      f.step.n === 1 && /(^|; )sp=quarantine(;|$)/.test(f.value) && /(^|; )p=reject(;|$)/.test(f.value);
    const line = firstAtNone ? STEP_FIRST : subdomains ? STEP_SUBDOMAINS : STEP;
    lines.push(line.replace("{n}", String(f.step.n)).replace("{o}", String(f.step.of)));
  }
  return lines.join("\n");
}

/**
 * Every fix of a report as one plain text to copy, each record with its host, full name and
 * value. Of a chain of DMARC steps only the first goes in: the next ones wait for the owner to
 * read the reports. A domain that probably sends no email gets both paths, each under its own
 * heading. Empty when the report has no fix.
 * @param rua The address for DMARC aggregate reports, put where {rua} stands (fillRua).
 */
export function fixesAsText(report: Report, rua?: string): string {
  const head = [`DNS changes for ${report.display}`, report.zone === undefined ? HOST_HINT_NO_ZONE : HOST_HINT];
  const blocks: string[] = [];
  const firstSteps = (f: Finding) => {
    const n = Math.min(...f.fixes.map((x) => x.step?.n ?? 1));
    return f.fixes.filter((x) => (x.step?.n ?? 1) === n);
  };
  const add = (title: string | undefined, findings: readonly Finding[]) => {
    const fixes = findings.flatMap(firstSteps);
    if (fixes.length === 0) return;
    blocks.push([...(title ? [title] : []), ...fixes.map((f) => fixText(f, rua))].join("\n\n"));
  };
  if (report.mailUse === "probably-none") {
    add(`If ${report.display} sends no email:`, report.findings.filter(noMailPath));
    add(
      `If it sends email through a service:`,
      report.findings.filter((f) => !noMailPath(f)),
    );
  } else {
    add(undefined, report.findings);
  }
  if (blocks.length === 0) return "";
  return [head.join("\n"), ...blocks].join("\n\n");
}
