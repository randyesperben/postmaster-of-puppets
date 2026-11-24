// The SPF check (RFC 7208). With no sending IP to test, the check walks the tree statically, to
// count lookups the way a worst-case receiver would and to record the cost of every branch.
// Alongside, it runs the evaluation a receiver would make for a forger's address, once per address
// family: such an address matches only terms that match every address (all, a /0 range, a static
// exists), so the domain is open to the whole internet when that evaluation ends in pass. The walk
// goes depth first, left to right, each record only up to its first all (§4.6.2, §5.1), so the
// order of DNS answers never changes it. A + range wider than /16 (IPv4) or /32 (IPv6) that takes
// in addresses anyone can rent from Amazon EC2 or Google Cloud opens the domain too.
import { ask, type Ctx, failedVars, type Lookup, txt } from "../dns/lookup.ts";
import { finding, statusOf } from "../findings.ts";
import { CLOUD_V4_16, CLOUD_V6_32 } from "../data/cloud-ranges.ts";
import { deadline } from "../dns/deadline.ts";
import { cleanSpf, MERGE_WALK_MS, mergeSpf } from "./spf-merge.ts";
import type { Finding, GroupStatus, SpfNode } from "../types.ts";
import {
  type Cause,
  type CloudRuns,
  type CloudTable,
  covers,
  coveringSet,
  FAMILIES,
  type Frame,
  runsOf,
} from "./spf-eval.ts";
import { parseRecord, spfRecords } from "./spf-terms.ts";
import {
  add,
  AFTER_RECORD,
  BEFORE_TERMS,
  byPosition,
  evaluatedTerms,
  MAX_LOOKUPS,
  MAX_VOID,
  type Walk,
  walk,
} from "./spf-walk.ts";

const SIZE_LIMIT = 450; // §3.4: name and every TXT string at it “under 450 octets”

/** The generated table of cloud blocks as runs, built the first time a check needs it. */
let cloudRunsCache: CloudRuns | undefined;

export interface SpfResult {
  status: GroupStatus;
  findings: Finding[];
  lookup: Lookup["status"];
  record?: string;
  /** Lookups in the tree, depth first; a minimum when lookupsAtLeast is true. */
  lookups: number;
  /** True when the walk stopped at its budget, so branches past it are not counted. */
  lookupsAtLeast: boolean;
  /** Void lookups for the worse address family (§4.6.4, §5.3). */
  voidLookups: number;
  tree?: SpfNode;
  /** Every domain reached by include or redirect, for provider detection. */
  includes: string[];
  /**
   * The include and redirect terms of the record itself, as written: spf-unused-include asks only
   * about these, never about an include inside another.
   */
  written: string[];
  /** Whether the record lets any server send: false for no record and for v=spf1 -all. */
  authorizes: boolean;
  /**
   * With two records or more, the one the fix would publish (spf-merge.ts) and what a walk of it
   * finds, so the fix is offered only when it adds no problem.
   */
  merged?: { record: string; findings: Finding[]; finished: boolean };
  /**
   * With an opening in the record itself: true when the record without its open terms (cleanSpf,
   * the fix) still opens it or its walk did not finish, so no fix is offered.
   */
  cleanedOpen?: boolean;
  /**
   * That walk finds an opening inside an include or redirect the cleaned record keeps: the fix
   * takes the record's own open term away and leaves that one open.
   */
  cleanedVia?: boolean;
}

const anyOpen = (f: Finding) => f.id === "spf-plus-all" || f.id === "spf-open-range";
/** An opening in the record itself, not in one it includes or redirects to (vars.via "a > b"). */
export function ownOpen(f: Finding): boolean {
  return anyOpen(f) && !String(f.vars?.via ?? "").includes(" > ");
}

/**
 * The SPF group of a check: the record, its tree with the lookups a receiver counts, and what the
 * forger's evaluation finds. `cloud` replaces the generated table of cloud blocks, for tests. `as`
 * walks `record` in place of what the name publishes, with the name's TXT lookup already made: the
 * merged record of spf-multiple-records.
 */
export async function checkSpf(
  ctx: Ctx,
  domain: string,
  cloud?: CloudTable,
  as?: { lookup: Lookup; record: string },
): Promise<SpfResult> {
  const l = as?.lookup ?? (await ask(ctx, domain, "TXT", { confirm: true }));
  const findings: Finding[] = [];
  const base = {
    findings,
    lookup: l.status,
    lookups: 0,
    lookupsAtLeast: false,
    voidLookups: 0,
    includes: [],
    written: [],
    authorizes: false,
  };
  if (l.status === "failed") {
    findings.push(finding("lookup-failed", { group: "spf", found: `${domain} TXT`, vars: failedVars(l) }));
    return { ...base, status: statusOf(findings, { unknown: true }) };
  }
  if (l.status === "nxdomain") return { ...base, status: "unknown" };
  if (l.status === "dnssec-broken") findings.push(finding("dnssec-broken", { group: "spf", found: `${domain} TXT` }));

  const texts = txt(l);
  const recs = as ? [as.record] : spfRecords(texts);
  if (recs.length === 0) {
    findings.push(finding("spf-missing"));
    return { ...base, status: statusOf(findings) };
  }
  if (recs.length > 1) {
    findings.push(finding("spf-multiple-records", { found: recs.join("\n") }));
    // The record the fix would publish, walked as a receiver would read it once it is the only one:
    // the merge can pass 10 lookups, loop back to the name or carry an empty redirect, which no
    // list of terms shows before the walk.
    // No receiver makes these lookups (two records are a permerror, §4.5), so the walk has a time
    // limit of its own, shorter than the check's: a silent include never holds the check to its
    // 10 s nor marks it partial, and a walk that does not finish leaves no fix to copy.
    const record = mergeSpf(recs);
    const own = deadline(MERGE_WALK_MS, ctx.signal);
    try {
      const merged = await checkSpf({ ...ctx, signal: own.signal }, domain, cloud, { lookup: l, record });
      // Receivers get permerror (§4.5); as a sign of sending, the merge says whom the owner meant
      // to authorize, read from its terms: two v=spf1 -all authorize no one.
      return {
        ...base,
        status: statusOf(findings),
        authorizes: merged.authorizes,
        merged: { record, findings: merged.findings, finished: !own.signal.aborted },
      };
    } finally {
      own.dispose();
    }
  }

  const record = recs[0] ?? "";
  const w: Walk = {
    ctx,
    cache: new Map([[`${domain} TXT`, Promise.resolve(l)]]),
    lookups: 0,
    evalLookups: [0, 0],
    capped: false,
    voids: [0, 0],
    evalVoids: [0, 0],
    ranges: [[], []],
    findings,
    keys: new Set(),
    order: new Map(),
    includes: new Set(),
    senderMacros: false,
    cloud: cloud ? runsOf(cloud) : (cloudRunsCache ??= runsOf({ v4: CLOUD_V4_16, v6: CLOUD_V6_32 })),
  };
  // §3.4 measures the whole TXT answer, so other records at the name count too. When the SPF
  // record and the name alone stay under the limit, those records are what to shorten, and the
  // finding says so with others. The record is the one walked (the merge, with several), as the
  // zone holds it once fixed.
  const others = texts.filter((t) => spfRecords([t]).length === 0);
  const own = domain.length + record.length;
  const size = own + others.reduce((n, s) => n + s.length, 0);
  if (size >= SIZE_LIMIT && own >= SIZE_LIMIT) add(w, [BEFORE_TERMS], "spf-too-large", `${size} octets`);
  else if (size >= SIZE_LIMIT) {
    add(
      w,
      [BEFORE_TERMS],
      "spf-too-large",
      `${size} octets in ${others.length + 1} TXT records; the SPF record is ${record.length}`,
      { others: others.length },
    );
  }
  const root: Frame = { live: [true, true], out: [undefined, undefined], pass: true, blocked: [[], []] };
  const children = await walk(w, record, { domain, path: [domain], chain: [domain], own: true, frame: root, pos: [] });
  const tree: SpfNode = { term: record, domain, lookups: children.reduce((n, c) => n + c.lookups, 0), children };

  // Open to the whole internet: the forger's evaluation passes, or the pass ranges cover a family.
  const open = (c: Cause, marked: Cause[]): void => {
    add(w, c.pos, c.id, c.found, c.reason ? { via: c.via, reason: c.reason } : { via: c.via });
    for (const m of marked) m.node.finding = c.id;
  };
  for (const f of FAMILIES) {
    const o = root.out[f];
    if (o?.cause) {
      open(o.cause, [o.cause]);
      continue;
    }
    const set = coveringSet(f, w.ranges[f]);
    const last = set[set.length - 1];
    if (last && covers(f, set))
      open(
        { ...last.cause, found: set.map((r) => r.cause.found).join(" ") },
        set.map((r) => r.cause),
      );
  }

  if (tree.lookups > MAX_LOOKUPS && !findings.some((f) => f.id === "spf-too-many-lookups")) {
    add(
      w,
      [AFTER_RECORD],
      "spf-too-many-lookups",
      `${tree.lookups} lookups`,
      w.capped ? { count: tree.lookups, atLeast: 1 } : { count: tree.lookups },
    );
  }
  const voids = Math.max(...w.voids);
  if (voids > MAX_VOID) add(w, [AFTER_RECORD], "spf-too-many-void-lookups", `${voids} void lookups`, { count: voids });
  if (w.senderMacros) add(w, [AFTER_RECORD], "spf-sender-macros", record);

  // Only what a receiver evaluates authorizes: mechanisms before all, or redirect without an all.
  const terms = parseRecord(record);
  const all = terms.find((t) => t.kind === "mechanism" && t.name === "all");
  const authorizes = all?.qualifier === "+" || evaluatedTerms(terms).some((e) => e.t.qualifier === "+");
  findings.sort(byPosition(w));
  const status = statusOf(findings);
  if (!findings.some((f) => (f.severity === "critical" || f.severity === "warning") && f.impact !== "hardening")) {
    findings.push(finding("spf-ok", { found: record }));
  }
  const result: SpfResult = {
    status,
    findings,
    lookup: l.status,
    record,
    lookups: tree.lookups,
    lookupsAtLeast: w.capped,
    voidLookups: voids,
    tree,
    includes: [...w.includes],
    written: terms.filter((t) => (t.name === "include" || t.name === "redirect") && t.value).map((t) => t.raw),
    authorizes,
  };
  // The walk stops a family at its first opening, so a second one (a cloud block after
  // ip4:0.0.0.0/0) only shows in a walk of the cleaned record, with the merge's time limit.
  const cleaned = cleanSpf(record);
  if (!as && cleaned !== record && findings.some(ownOpen)) {
    const limit = deadline(MERGE_WALK_MS, ctx.signal);
    try {
      const again = await checkSpf({ ...ctx, signal: limit.signal }, domain, cloud, { lookup: l, record: cleaned });
      // Aborted, not expired: the check's own limit can cut this walk before its 3 s are up.
      result.cleanedOpen = limit.signal.aborted || again.findings.some(ownOpen);
      if (again.findings.some((f) => anyOpen(f) && !ownOpen(f))) result.cleanedVia = true;
    } finally {
      limit.dispose();
    }
  }
  return result;
}
