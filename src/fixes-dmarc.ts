// The DMARC fixes: one chain of steps per DMARC record, from the current record to an enforced one
// (none with reports, quarantine, reject), on the first DMARC finding that needs it; only a domain
// that declares or shows no mail gets reject at once.
import {
  askOf,
  correctedTags,
  isDmarcVersion,
  isPolicy,
  oneLevelDown,
  parseTags,
  readPolicy,
  ruaHosts,
  weaker,
} from "./checks/dmarc-tags.ts";
import { first, type FixDraft, NO_MAIL_DMARC } from "./fixes-common.ts";
import type { Ask, Finding, FindingId, Policy, Report } from "./types.ts";

const RUA = "mailto:{rua}";

/** v and p first, then the other tags in their order (RFC 9989 §4.7: v first). */
function dmarcValue(tags: Record<string, string>): string {
  const rest = Object.entries(tags).filter(([k]) => k !== "v" && k !== "p");
  return ["v=DMARC1", `p=${tags.p ?? "none"}`, ...rest.map(([k, v]) => `${k}=${v}`)].join("; ");
}

const DMARC_IDS: readonly FindingId[] = [
  "dmarc-missing",
  "dmarc-multiple-records",
  "dmarc-bad-version",
  "dmarc-invalid-policy",
  "dmarc-policy-none",
  "dmarc-pct",
  "dmarc-testing-mode",
  "dmarc-policy-quarantine",
  "dmarc-subdomains-open",
  "dmarc-no-rua",
  "dmarc-org-differs",
];

interface DmarcState {
  name: string;
  /** The records published at that name today, to replace or remove. */
  current: string[];
  tags: Record<string, string>;
  /** The record that would say what applies today when it is not `current[0]`: an inherited one. */
  today?: string;
  /** A mistyped record whose policy can be read: its tags corrected, so the chain starts there. */
  corrected?: boolean;
}

/**
 * Tags that mean something only on the record that holds them for its subdomains, or that the
 * chain drops.
 */
const PARENT_ONLY = ["v", "p", "sp", "np", "psd", "pct", "t"];

function dmarcState(r: Report): DmarcState {
  // Records discarded at the checked name itself; one with vars.at sits at a parent's name.
  const here = (id: FindingId) => r.findings.find((f) => f.id === id && f.vars?.at === undefined)?.found;
  const multiple = here("dmarc-multiple-records");
  const bad = here("dmarc-bad-version");
  const doubled = r.findings.find((f) => f.id === "record-name-doubled" && f.group === "dmarc")?.found;
  const discarded = (multiple ?? bad)?.split("\n") ?? [];
  // The two readings give different levels (a finding carries weaker): a record of the name's own
  // changes what applies even at the current level, since both kinds of receivers then read it.
  const split = r.findings.some((f) => f.vars?.weaker === 1);
  if (r.dmarc.record !== undefined && r.dmarc.foundAt && r.dmarc.foundAt !== r.domain) {
    // An inherited policy: the parent's record also decides for the parent
    // and for every other subdomain, and its p is not what this name gets when sp or np applies.
    // The steps go on a record of this name's own, starting from the strongest level any reading
    // applies today, never below. Under the same owner it keeps the parent's other tags (rua,
    // adkim, aspf…); under a PSD or when the two readings differ (another organization's record,
    // railway.app for myapp.up.railway.app) it starts clean with the owner's rua.
    const differs = r.findings.find((f) => f.id === "dmarc-org-differs");
    const foreign = differs !== undefined || r.dmarc.tags.psd?.toLowerCase() === "y";
    const from = r.dmarc.policyFrom ?? "p";
    const levels = [r.dmarc.tags[from], differs?.vars?.policy, differs?.vars?.pslPolicy].map((v) =>
      policyOf(String(v ?? "").toLowerCase()),
    );
    const level = (["reject", "quarantine", "none"] as const).find((p) => levels.includes(p)) ?? "none";
    if (foreign) return { name: `_dmarc.${r.domain}`, current: discarded, tags: { p: level, rua: RUA } };
    const tags: Record<string, string> = Object.fromEntries(
      Object.entries(r.dmarc.tags).filter(([k]) => !PARENT_ONLY.includes(k)),
    );
    const own = { p: level, ...tags };
    // A parent's record that lowers both readings (t=y, pct=0) applies a level below its p, so the
    // own record at p is no “today”.
    const { lowered } = readPolicy(r.dmarc.tags);
    return {
      name: `_dmarc.${r.domain}`,
      current: discarded,
      tags: own,
      ...(split || lowered ? {} : { today: dmarcValue(own) }),
    };
  }
  if (r.dmarc.record !== undefined && r.dmarc.foundAt) {
    // The record in force first; one that only RFC 7489 reads next to it goes.
    const record = r.dmarc.record;
    const extra = discarded.filter((v) => v !== record);
    // P=reject: RFC 9989 reads no policy, RFC 7489 reads reject.
    const fixed = r.dmarc.tags.p === undefined ? correctedTags(record) : undefined;
    if (fixed) return { name: `_dmarc.${r.dmarc.foundAt}`, current: [record, ...extra], tags: fixed, corrected: true };
    return { name: `_dmarc.${r.dmarc.foundAt}`, current: [record, ...extra], tags: { ...r.dmarc.tags }, today: record };
  }
  const name = `_dmarc.${r.domain}`;
  if (multiple) {
    const records = multiple.split("\n");
    return { name, current: records, tags: parseTags(records[0] ?? "").tags };
  }
  if (bad) {
    const records = bad.split("\n");
    // V=DMARC1, or a tag repeated with the same value: one record whose policy RFC 7489 reads.
    const fixed = records.length === 1 ? correctedTags(records[0] ?? "") : undefined;
    if (fixed) return { name, current: records, tags: fixed, corrected: true };
    return { name, current: records, tags: parseTags(records[0] ?? "").tags };
  }
  // A record published at _dmarc.example.com.example.com: keep its tags for the new one.
  const text = doubled?.slice(doubled.indexOf(" ") + 1);
  return { name, current: [], tags: text ? parseTags(text).tags : {} };
}

/**
 * What a DMARC record asks once it is published (Fix.after), read as the engine reads a record
 * (readPolicy): at its name, p; under it, the weaker of sp and np, which fall back to sp and then p
 * (RFC 9989 §4.7). In the weaker of the two readings, as the effective policy is: t=y (RFC 9989),
 * and pct below 100 for RFC 7489 receivers (§6.6.4), take each one level down. Undefined for a
 * value that publishes no policy.
 */
export function dmarcAfter(value: string): { asks: Ask; sub: Ask } | undefined {
  const read = readPolicy(parseTags(value).tags);
  if (!read.base) return undefined;
  const lower = (p: Policy): Policy => (read.testing || read.sampled ? oneLevelDown(p) : p);
  const { p, sp = p } = read.base;
  const np = read.base.np ?? sp;
  return { asks: askOf(lower(p)), sub: askOf(lower(weaker(sp, np))) };
}

const policyOf = (v: string | undefined): Policy | undefined => (isPolicy(v) ? v : undefined);

interface Chain {
  values: string[];
  /** Steps already behind the owner: p=none with reports is step 1 of 3 done. */
  done: number;
  of: number;
}

/**
 * The record that says what applies today: the one published, or the inherited policy as a record
 * of its own.
 */
const todayOf = (s: DmarcState) => s.today ?? (s.current.length === 1 ? s.current[0] : undefined);

/**
 * The current record as dmarcValue writes the chain's values, so “v=DMARC1; p=reject;” or
 * “v=DMARC1;p=quarantine;rua=…” is the current level too.
 */
function writtenToday(s: DmarcState): string | undefined {
  const today = todayOf(s);
  return today === undefined ? undefined : dmarcValue(parseTags(today).tags);
}

/**
 * p, sp and np in lower case when they hold a policy: the engine reads QUARANTINE as quarantine.
 */
function lowerPolicies(tags: Record<string, string>): Record<string, string> {
  const out = { ...tags };
  for (const k of ["p", "sp", "np"]) {
    const v = policyOf(out[k]?.toLowerCase());
    if (v) out[k] = v;
  }
  return out;
}

/**
 * The current record as the chain would write it, to drop the step equal to it, only when both
 * readings read it alike: a valid version, no tag name in the wrong case or misspelled, no tag
 * twice. Otherwise RFC 7489 reads what RFC 9989 drops (PCT=25, SP=none, V=DMARC1), the step does
 * change something for its receivers, and the record is compared as published.
 * A pct that lowers nothing (100, empty, not a number) is left out, so it makes no step.
 */
function chainToday(s: DmarcState): string | undefined {
  const today = todayOf(s);
  if (today === undefined) return undefined;
  const parsed = parseTags(today);
  if (!isDmarcVersion(today) || parsed.typos.length > 0 || parsed.repeated !== undefined) return today;
  const tags = lowerPolicies(parsed.tags);
  if (!readPolicy(tags).sampled) delete tags.pct;
  return dmarcValue(tags);
}

/**
 * Aggregate reports reach someone: the record in force has a rua address (a mailto: or https URI,
 * so no dmarc-no-rua) at a host that has agreed to take them (no dmarc-rua-unauthorized for it,
 * RFC 9990 §4). Without that, step 1 of the chain is still to do.
 */
export function reportsArrive(r: Report): boolean {
  const refused = new Set(r.findings.filter((f) => f.id === "dmarc-rua-unauthorized").map((f) => f.found));
  return ruaHosts(r.dmarc.tags.rua).some((h) => !refused.has(h.uri));
}

/** The steps from the current DMARC record to an enforced one, each a full record value. */
function dmarcChain(r: Report, s: DmarcState): Chain {
  const base = lowerPolicies(s.tags);
  delete base.v;

  const open = (v: string | undefined) => v === "none";
  // Subdomains move by steps too: sp=none goes to quarantine with p, then follows
  // p=reject; np=none goes at once, since only names that do not exist use it and none sends mail.
  const strict = (t: Record<string, string>, p: string) => {
    const out: Record<string, string> = { ...t, p };
    delete out.pct;
    delete out.t;
    if (open(out.np)) delete out.np;
    if (p === "quarantine" && open(out.sp)) out.sp = "quarantine";
    if (p === "reject" && open(out.sp)) delete out.sp;
    return out;
  };
  const p = policyOf(base.p);
  const valid = (r.dmarc.record !== undefined || s.corrected === true) && p !== undefined;
  const values: Record<string, string>[] = [];
  if (!valid || p === "none") {
    // A rua of the record in force that reaches no one is no step 1 behind the owner, and no step
    // copies it: the owner's address takes its place. Past p=none its own finding says what to
    // do (dmarc-no-rua, dmarc-rua-unauthorized), and a step of its own would only change rua.
    const lost = r.dmarc.record !== undefined && base.rua !== undefined && !reportsArrive(r);
    const withRua = { ...base, ...(lost ? { rua: RUA } : {}) };
    if (!withRua.rua) withRua.rua = RUA;
    const stepOneDone = valid && base.rua !== undefined && !lost && base.pct === undefined && base.t === undefined;
    if (!stepOneDone) values.push(strict(withRua, "none"));
    values.push(strict(withRua, "quarantine"), strict(withRua, "reject"));
    return { values: values.map(dmarcValue), done: stepOneDone ? 1 : 0, of: 3 };
  } else {
    // pct is gone in RFC 9989 (Appendix A.6), whose receivers ignore it as an unknown tag (§4.7),
    // so no step swaps it for t=y, which would lower them by a level: strict() drops pct in the
    // next step, and no step asks less than either reading applies today, also with pct=0.
    if (p === "quarantine") values.push(strict(base, "quarantine"), strict(base, "reject"));
    else {
      // p=reject with sp=none: subdomains through quarantine before they follow reject.
      if (open(base.sp)) values.push(strict({ ...base, sp: "quarantine" }, "reject"));
      values.push(strict(base, "reject"));
    }
  }
  const texts = values.map(dmarcValue);
  // Drop a step that equals the current record (a quarantine without pct or t is already there).
  const today = chainToday(s);
  const kept = texts.filter((v, i) => !(i < texts.length - 1 && v === today));
  return { values: kept, done: 0, of: kept.length };
}

/**
 * The DMARC fixes of a report and the finding that carries them. A domain that sends mail gets
 * the chain of steps; one that does not (`sendsMail` false) gets p=reject at once.
 * Undefined when there is nothing to change.
 */
export function dmarcFixes(
  r: Report,
  { sendsMail }: { sendsMail: boolean },
): { on: Finding; fixes: FixDraft[] } | undefined {
  // Subdomains left open by a parent's record (RFC 9989 §4.7: sp and np count only at the
  // Organizational Domain): a step on this name's record cannot close them, so none is offered and
  // the text names _dmarc.{at}. The next finding on this name's record, such as a missing rua,
  // keeps its fix.
  const elsewhere = (f: Finding) => f.id === "dmarc-subdomains-open" && f.vars?.at !== r.domain;
  const on = first({ ...r, findings: r.findings.filter((f) => !elsewhere(f)) }, DMARC_IDS);
  if (!on) return undefined;
  const s = dmarcState(r);
  const removeExtra = s.current
    .slice(1)
    .map((v): FixDraft => ({ action: "remove", type: "TXT", name: s.name, value: v, replaces: v }));
  const startFrom = (value: string): FixDraft =>
    s.current[0] !== undefined
      ? { action: "replace", type: "TXT", name: s.name, value, replaces: s.current[0] }
      : { action: "add", type: "TXT", name: s.name, value };

  if (!sendsMail) {
    // Nothing to discard: the name's own record alone, or an inherited one and nothing at the name.
    if (r.verdict === "protected" && s.current.length === (r.dmarc.foundAt === r.domain ? 1 : 0)) return undefined;
    // An inherited policy belongs to the parent domain: the no-mail records add this name's own.
    if (r.dmarc.foundAt !== undefined && r.dmarc.foundAt !== r.domain) {
      return { on, fixes: [{ action: "add", type: "TXT", name: `_dmarc.${r.domain}`, value: NO_MAIL_DMARC }] };
    }
    return { on, fixes: [...removeExtra, startFrom(NO_MAIL_DMARC)] };
  }
  const chain = dmarcChain(r, s);
  const { values, done, of } = chain;
  const asWritten = writtenToday(s);
  // With the subdomains' record elsewhere, this record's sp and np change nothing, so the
  // chain's step that drops them is no step: rua alone.
  if (on.id === "dmarc-no-rua" && ((values.length === 1 && values[0] === asWritten) || r.findings.some(elsewhere))) {
    // Protected without reports: add rua and nothing else.
    return { on, fixes: [startFrom(dmarcValue({ ...s.tags, rua: RUA }))] };
  }
  // Only the very same record is no fix: one that differs in how it is written (V=DMARC1, a tag
  // RFC 9989 does not read) still has to be replaced.
  const today = todayOf(s);
  // The extra records alone: their remove says what the record that stays asks.
  if (values.length === 0 || (values.length === 1 && values[0] === today)) {
    const kept = s.current[0] === undefined ? undefined : dmarcAfter(s.current[0]);
    return removeExtra.length > 0
      ? { on, fixes: removeExtra.map((f) => (kept ? { ...f, after: kept } : f)) }
      : undefined;
  }
  const stepped = of > 1;
  const fixes: FixDraft[] = removeExtra.map((f) =>
    stepped ? { ...f, step: { n: done + 1, of, protects: false } } : f,
  );
  values.forEach((value, i) => {
    const fix: FixDraft =
      i === 0
        ? startFrom(value)
        : { action: "replace", type: "TXT", name: s.name, value, replaces: values[i - 1] ?? "" };
    // A step protects once the policy it publishes is quarantine or reject without testing mode.
    const tags = parseTags(value).tags;
    if (stepped) fix.step = { n: done + i + 1, of, protects: tags.p !== "none" && tags.t !== "y" };
    fixes.push(fix);
  });
  return { on, fixes };
}
