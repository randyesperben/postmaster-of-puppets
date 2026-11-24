// The walk of an SPF tree, depth first and left to right, each record up to its first all
// (RFC 7208 §4.6.2, §5.1): lookups counted the way a worst-case receiver would, the cost of every
// branch recorded, and the forger's evaluation (spf-eval.ts) run alongside.
import { ask, type Ctx, failedVars, type Lookup, txt } from "../dns/lookup.ts";
import type { FindingVars } from "../finding-vars.ts";
import { finding } from "../findings.ts";
import { WIDE_PREFIX } from "../ip.ts";
import type { Finding, FindingId, SpfNode } from "../types.ts";
import {
  ADDRESS_BITS,
  type Cause,
  type CloudRuns,
  endWith,
  endWithError,
  FAMILIES,
  type Family,
  type Frame,
  isRunning,
  matchAll,
  type Range,
  rangeOf,
  reachesCloud,
  RESULT,
  type Span,
} from "./spf-eval.ts";
import { domainSpec, expand, parseRecord, QUERIES, spfRecords, type Term } from "./spf-terms.ts";

export const MAX_LOOKUPS = 10; // §4.6.4
export const MAX_VOID = 2; // §4.6.4
const MAX_MX_HOSTS = 10; // §4.6.4

/** Maximum lookups the walk follows, so a loop or a huge tree stays bounded. */
const WALK_BUDGET = 30;
/** Maximum queries sent ahead of the walk; the walk asks the rest when it reaches them. */
const PREFETCH_CAP = 64;

export interface Walk {
  ctx: Ctx;
  cache: Map<string, Promise<Lookup>>;
  /** Lookups in the static tree, and in the forger's evaluation of each family. */
  lookups: number;
  evalLookups: [number, number];
  capped: boolean;
  voids: [number, number];
  evalVoids: [number, number];
  ranges: [Range[], Range[]];
  findings: Finding[];
  keys: Set<string>;
  order: Map<Finding, number[]>;
  includes: Set<string>;
  senderMacros: boolean;
  cloud: CloudRuns;
}

/** Adds a finding once; `pos` is its place in the tree, so the list reads in tree order. */
export function add(w: Walk, pos: number[], id: FindingId, found: string, vars?: FindingVars): FindingId {
  const key = `${id} ${found} ${vars?.via ?? ""}`;
  if (!w.keys.has(key)) {
    w.keys.add(key);
    const f = finding(id, vars ? { group: "spf", found, vars } : { group: "spf", found });
    w.findings.push(f);
    w.order.set(f, pos);
  }
  return id;
}

/** A position of a finding before the terms of its record: the record as a whole. */
export const BEFORE_TERMS = -1;
/** A position after every term: what the whole tree adds up to. */
export const AFTER_RECORD = Infinity;
/** No position at that depth: a shorter path sorts first, ahead of BEFORE_TERMS. */
const NO_POSITION = -2;

export function byPosition(w: Walk): (a: Finding, b: Finding) => number {
  return (a, b) => {
    const x = w.order.get(a) ?? [];
    const y = w.order.get(b) ?? [];
    for (let i = 0; i < Math.max(x.length, y.length); i++) {
      const d = (x[i] ?? NO_POSITION) - (y[i] ?? NO_POSITION);
      if (d !== 0) return d;
    }
    return 0;
  };
}

function isVoid(l: Lookup): boolean {
  return l.status === "nodata" || l.status === "nxdomain";
}

/** Asks once per name and type; answers may arrive in any order, the walk reads them in its own. */
function query(w: Walk, name: string, type: string): Promise<Lookup> {
  const key = `${name} ${type}`;
  let p = w.cache.get(key);
  if (!p) {
    // Every query of the SPF tree decides the verdict: two operators must agree.
    p = ask(w.ctx, name, type, { confirm: true });
    w.cache.set(key, p);
  }
  return p;
}

/**
 * The terms a receiver evaluates, in its order: mechanisms up to all (§5.1), then redirect if there
 * is no all (§6.1).
 */
export function evaluatedTerms(terms: Term[]): { t: Term; i: number }[] {
  const allIndex = terms.findIndex((t) => t.kind === "mechanism" && t.name === "all");
  const out = terms
    .map((t, i) => ({ t, i }))
    .filter(({ t, i }) => t.kind === "mechanism" && t.name !== "all" && (allIndex < 0 || i < allIndex));
  const redirect = allIndex < 0 ? terms.findIndex((t) => t.kind === "modifier" && t.name === "redirect") : -1;
  if (redirect >= 0) out.push({ t: terms[redirect] as Term, i: redirect });
  return out;
}

/**
 * Asks ahead for the lookups of a record, and of the records they lead to as their TXT
 * arrives, so a tree costs about one round trip per level. `from` is a lower bound of the
 * record's place in the depth-first order: a term's place is at least that plus its rank, so
 * terms surely past the budget are never asked. Only the cache changes; the walk still reads
 * every answer in its own order.
 */
function prefetch(w: Walk, domain: string, terms: Term[], chain: string[], from: number): void {
  let n = from;
  for (const t of terms) {
    const types = QUERIES[t.name];
    if (!types) continue;
    if (++n > WALK_BUDGET) return;
    if (t.value !== undefined && domainSpec(t.value).senderMacros) continue;
    const target = expand(t.value ?? domain, domain);
    if (chain.includes(target)) continue;
    for (const type of types) {
      if (w.cache.has(`${target} ${type}`)) continue;
      if (w.cache.size >= PREFETCH_CAP) return;
      const p = query(w, target, type);
      const at = n;
      if (type === "TXT") {
        void p.then((l) => {
          const recs = spfRecords(txt(l));
          const parsed = recs.length === 1 ? parseRecord(recs[0] ?? "") : [];
          if (parsed.some((x) => x.error)) return;
          const terms = evaluatedTerms(parsed).map((e) => e.t);
          prefetch(w, target, terms, [...chain, target], at);
        });
      }
    }
  }
}

/** Counts one void lookup for these families, in the tree and in the evaluation. */
function voided(w: Walk, frame: Frame, families: readonly Family[]): void {
  for (const f of families) {
    w.voids[f]++;
    if (!isRunning(frame, f)) continue;
    if (++w.evalVoids[f] > MAX_VOID) frame.out[f] = { result: "error" };
  }
}

/**
 * The vars of a lookup without a usable answer: unreached when the forger's evaluation no longer
 * reaches it, every family having ended above (an opening term, a permerror), so its answer
 * cannot change the forger's result.
 */
const missed = (frame: Frame, vars: FindingVars): FindingVars =>
  FAMILIES.some((f) => isRunning(frame, f)) ? vars : { ...vars, unreached: 1 };

/** Reads a lookup's status; returns false when no answer came (the term is then skipped). */
function answered(w: Walk, l: Lookup, pos: number[], node: SpfNode, via: string, frame: Frame): boolean {
  if (l.status === "failed") {
    node.finding = add(w, pos, "lookup-failed", `${l.name} ${l.type}`, missed(frame, failedVars(l)));
    return false;
  }
  if (l.status === "dnssec-broken") add(w, pos, "dnssec-broken", `${l.name} ${l.type}`, missed(frame, { via }));
  return true;
}

interface Place {
  domain: string;
  path: string[];
  chain: string[];
  own: boolean;
  frame: Frame;
  pos: number[];
}

/**
 * Walks one record. `own` is the domain's own policy (the record and its redirect chain), where
 * all, the terms after all and wide ranges matter; `path` is the term chain for vars.via and
 * `chain` the domains on the way, to stop include loops.
 */
export async function walk(w: Walk, record: string, at: Place): Promise<SpfNode[]> {
  const { domain, path, own, frame, pos } = at;
  const via = path.join(" > ");
  const terms = parseRecord(record);
  const nodes: SpfNode[] = terms.map((t) => ({ term: t.raw, lookups: 0, children: [] }));

  // §4.6: a syntax error anywhere, after all included, is a permerror before any evaluation.
  const syntax = terms.find((t) => t.error);
  if (syntax) {
    const i = terms.indexOf(syntax);
    // Quote marks inside a term: the record was pasted with its zone file quotes ("…AB" "CD…").
    const reason = syntax.raw.includes('"') ? "quotes" : (syntax.error ?? "");
    (nodes[i] as SpfNode).finding = add(w, [...pos, i], "spf-syntax-error", syntax.raw, { via, reason });
    endWithError(frame);
    return nodes;
  }
  for (const name of ["redirect", "exp"]) {
    if (terms.filter((t) => t.kind === "modifier" && t.name === name).length > 1) {
      add(w, [...pos, BEFORE_TERMS], "spf-duplicate-modifier", name, { via });
      endWithError(frame);
    }
  }

  const allIndex = terms.findIndex((t) => t.kind === "mechanism" && t.name === "all");
  const all = allIndex >= 0 ? terms[allIndex] : undefined;
  const evaluated = evaluatedTerms(terms);
  if (own) {
    const redirect = evaluated.some((e) => e.t.name === "redirect");
    if (all ? all.qualifier === "?" : !redirect)
      add(w, [...pos, terms.length], "spf-neutral-all", all?.raw ?? record, { via });
    if (all && terms.slice(allIndex + 1).some((t) => t.kind === "mechanism"))
      add(w, [...pos, allIndex], "spf-terms-after-all", record, { via });
  }

  const ahead = evaluated.map((e) => e.t);
  prefetch(w, domain, ahead, at.chain, w.lookups);
  for (const { t, i } of evaluated) await term(w, t, nodes[i] as SpfNode, { ...at, pos: [...pos, i] }, via);
  if (all)
    matchAll(frame, FAMILIES, all.qualifier, {
      node: nodes[allIndex] as SpfNode,
      pos: [...pos, allIndex],
      id: "spf-plus-all",
      found: all.raw,
      via,
    });
  endWith(frame, FAMILIES, { result: "neutral" }); // §4.7: no match and no redirect
  return nodes;
}

/** Evaluates one mechanism, or the redirect; `at.pos` is the term's own place. */
async function term(w: Walk, t: Term, node: SpfNode, at: Place, via: string): Promise<void> {
  const { domain, frame, pos } = at;
  const cause = (): Cause => ({ node, pos, id: "spf-open-range", found: t.raw, via });
  const senderMacros = t.value !== undefined && domainSpec(t.value).senderMacros;
  if (senderMacros) w.senderMacros = true;

  if (t.name === "ip4" || t.name === "ip6") {
    const f: Family = t.name === "ip4" ? 0 : 1;
    const prefix = (f === 0 ? t.cidr4 : t.cidr6) ?? ADDRESS_BITS[f];
    if (prefix === 0) return matchAll(frame, [f], t.qualifier, cause());
    const span = rangeOf(f, t.value ?? "", prefix);
    if (wide(w, t, node, at, via, f, [span], prefix)) return;
    if (t.qualifier === "+" && frame.pass && isRunning(frame, f)) w.ranges[f].push({ ...span, prefix, cause: cause() });
    return;
  }

  // Everything below costs a lookup (§4.6.4); past the tenth, the evaluation is a permerror.
  node.lookups = 1;
  w.lookups++;
  for (const f of FAMILIES)
    if (isRunning(frame, f) && ++w.evalLookups[f] > MAX_LOOKUPS) frame.out[f] = { result: "error" };
  if (t.name === "ptr") {
    node.finding = add(w, pos, "spf-ptr", t.raw, { via });
    return;
  }
  const target = expand(t.value ?? domain, domain);
  node.domain = target;
  if (senderMacros) return; // needs a message to expand
  if (w.lookups > WALK_BUDGET) {
    // Its subtree goes uncounted.
    if (t.name === "include" || t.name === "redirect") w.capped = true;
    return;
  }

  if (t.name === "include" || t.name === "redirect") return follow(w, t, node, at, target);

  if (t.name === "mx") {
    const l = await query(w, target, "MX");
    if (!answered(w, l, pos, node, via, frame)) return;
    if (isVoid(l)) return voided(w, frame, FAMILIES);
    const hosts = l.records.map((r) => String(r.data).split(" ")[1] ?? ".").filter((h) => h !== ".");
    if (hosts.length > MAX_MX_HOSTS) {
      node.finding = add(w, pos, "spf-mx-too-many-hosts", t.raw, { via, hosts: hosts.length });
      return endWithError(frame);
    }
    for (const f of FAMILIES) {
      const prefix = f === 0 ? t.cidr4 : t.cidr6;
      if (prefix === undefined || prefix >= WIDE_PREFIX[f] || !isRunning(frame, f)) continue;
      // Each host's answer is read like any lookup: one with no answer is lookup-failed and is
      // left out, so it cannot hide an opening.
      const found = (await Promise.all(hosts.map((h) => query(w, h, f === 0 ? "A" : "AAAA")))).filter((x) =>
        answered(w, x, pos, node, via, frame),
      );
      if (prefix === 0) {
        if (found.some((x) => x.records.length > 0)) matchAll(frame, [f], t.qualifier, cause());
        continue;
      }
      const spans = found.flatMap((x) => x.records.map((r) => rangeOf(f, String(r.data), prefix)));
      wide(w, t, node, at, via, f, spans, prefix);
    }
    return;
  }

  if (t.name === "exists") {
    // §5.7: an A lookup whatever the connection type; any answer matches.
    const l = await query(w, target, "A");
    if (!answered(w, l, pos, node, via, frame)) return;
    if (isVoid(l)) return voided(w, frame, FAMILIES);
    // Broken DNSSEC with no address in the CD answer is no match.
    if (l.records.length === 0) return;
    // With no sender macro, it matches every address.
    return matchAll(frame, FAMILIES, t.qualifier, cause());
  }

  // a: §5.3 looks up A or AAAA by the connection's family, so each family is counted apart.
  const answers = await Promise.all([query(w, target, "A"), query(w, target, "AAAA")]);
  const failed = answers.find((l) => l.status === "failed");
  if (failed)
    node.finding = add(w, pos, "lookup-failed", `${failed.name} ${failed.type}`, missed(frame, failedVars(failed)));
  for (const f of FAMILIES) {
    const l = answers[f] as Lookup;
    if (l.status === "failed" || !answered(w, l, pos, node, via, frame)) continue;
    const prefix = f === 0 ? t.cidr4 : t.cidr6;
    if (isVoid(l)) voided(w, frame, [f]);
    else if (prefix === 0) {
      // No address is no match, as for exists.
      if (l.records.length > 0) matchAll(frame, [f], t.qualifier, cause());
    } else if (prefix !== undefined && prefix < WIDE_PREFIX[f]) {
      const spans = l.records.map((r) => rangeOf(f, String(r.data), prefix));
      wide(w, t, node, at, via, f, spans, prefix);
    }
  }
}

/**
 * A range wider than WIDE_PREFIX (or any non-pass range, which only blocks): a + one that reaches
 * a cloud block lets the forger pass (spf-open-range with reason "cloud"); one that does not is
 * spf-wide-range in the domain's own policy. Returns true when it ended the family's evaluation.
 */
function wide(
  w: Walk,
  t: Term,
  node: SpfNode,
  at: Place,
  via: string,
  f: Family,
  spans: Span[],
  prefix: number,
): boolean {
  const { frame, pos, own } = at;
  if (t.qualifier !== "+") {
    if (isRunning(frame, f)) frame.blocked[f].push(...spans);
    return false;
  }
  if (prefix >= WIDE_PREFIX[f] || spans.length === 0) return false;
  if (isRunning(frame, f) && spans.some((s) => reachesCloud(f, s, w.cloud, frame.blocked[f]))) {
    matchAll(frame, [f], "+", { node, pos, id: "spf-open-range", found: t.raw, via, reason: "cloud" });
    return true;
  }
  if (own) node.finding = add(w, pos, "spf-wide-range", t.raw, { via });
  return false;
}

/** include and redirect: fetches the target's single SPF record and walks it. */
async function follow(w: Walk, t: Term, node: SpfNode, at: Place, target: string): Promise<void> {
  const { frame, pos, path, chain, own } = at;
  const via = path.join(" > ");
  const inner = [...path, t.raw];
  w.includes.add(target);
  if (chain.includes(target)) {
    node.finding = add(w, pos, "spf-too-many-lookups", t.raw, { via, loop: target });
    return endWithError(frame); // a loop runs into the lookup limit
  }
  const l = await query(w, target, "TXT");
  if (!answered(w, l, pos, node, inner.join(" > "), frame)) return;
  const recs = spfRecords(txt(l));
  if (recs.length > 1) {
    node.finding = add(w, pos, "spf-multiple-records", target, { via: inner.join(" > ") });
    return endWithError(frame);
  }
  if (recs[0] === undefined) {
    if (isVoid(l)) voided(w, frame, FAMILIES);
    node.finding = add(w, pos, t.name === "include" ? "spf-include-no-spf" : "spf-redirect-no-spf", t.raw, { via });
    return endWithError(frame); // §5.2 and §6.1: none is a permerror here
  }
  const redirect = t.name === "redirect";
  const child: Frame = {
    live: [isRunning(frame, 0), isRunning(frame, 1)],
    out: [undefined, undefined],
    pass: frame.pass && (redirect || t.qualifier === "+"),
    blocked: [[...frame.blocked[0]], [...frame.blocked[1]]],
  };
  node.children = await walk(w, recs[0], {
    domain: target,
    path: inner,
    chain: [...chain, target],
    own: own && redirect,
    frame: child,
    pos,
  });
  node.lookups += node.children.reduce((n, c) => n + c.lookups, 0);
  for (const f of FAMILIES) {
    const o = child.out[f];
    if (!child.live[f] || !o) continue;
    // §6.1: redirect's result is the record's; §5.2: include matches on pass and passes errors up.
    if (redirect || o.result === "error") endWith(frame, [f], o);
    else if (o.result === "pass") endWith(frame, [f], t.qualifier === "+" ? o : { result: RESULT[t.qualifier] });
  }
}
