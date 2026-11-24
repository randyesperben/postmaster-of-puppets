// One SPF record from two (RFC 7208 §3.2 allows one per name): the fix of spf-multiple-records.
// And the record without its open terms (cleanSpf), the fix of an open SPF record, which
// checks/spf.ts also walks before fixes.ts offers it.
// checks/spf.ts walks the merged record as a receiver would read it, and fixes.ts offers it to
// copy only when that walk finds nothing wrong.

/**
 * The time the walk of the merged record may take, a third of the check's 10 s (DEADLINE_MS,
 * dns/deadline.ts): enough for a few rounds of includes, short of the check's own limit.
 */
export const MERGE_WALK_MS = 3_000;

type Qualifier = "+" | "-" | "~" | "?";
const ALL_RANK: Record<Qualifier, number> = { "+": 0, "?": 1, "~": 2, "-": 3 };

/** The qualifier of an all term, or undefined for any other term. */
export function allQualifier(term: string): Qualifier | undefined {
  const m = /^([+\-~?]?)all$/i.exec(term);
  return m ? ((m[1] || "+") as Qualifier) : undefined;
}

/**
 * One SPF record from two: first record's order, then the second's new terms, one exp at most, and
 * the stricter all of the two. Mechanisms after a record's first all are left out, since §5.1
 * ignores them (a range after -all would have moved before the merged all and opened the domain);
 * modifiers there still count, and §6 puts exp at the end. §6.1 ignores redirect in a record with
 * an all: a redirect its own record ignored stays out, and one that counted becomes an include
 * before the merged all, so its sender stays authorized. With no all, the first redirect stays the
 * redirect. Modifier names are case-insensitive (§12, ABNF).
 */
export function mergeSpf(records: readonly string[]): string {
  const terms: string[] = [];
  const redirects: string[] = [];
  let all: Qualifier | undefined;
  let exp: string | undefined;
  const add = (t: string) => {
    if (!terms.some((x) => x.toLowerCase() === t.toLowerCase())) terms.push(t);
  };
  for (const rec of records) {
    const own = rec.split(" ").slice(1).filter(Boolean);
    const at = own.findIndex((t) => allQualifier(t) !== undefined);
    const modifier = (t: string) => /^[a-z][a-z0-9_.-]*=/i.test(t);
    const read = at < 0 ? own : [...own.slice(0, at + 1), ...own.slice(at + 1).filter(modifier)];
    const hasAll = at >= 0;
    for (const t of read) {
      const q = allQualifier(t);
      if (q) {
        if (all === undefined || ALL_RANK[q] > ALL_RANK[all]) all = q;
      } else if (/^redirect=/i.test(t)) {
        const domain = t.slice("redirect=".length);
        if (!hasAll && !redirects.some((d) => d.toLowerCase() === domain.toLowerCase())) redirects.push(domain);
      } else if (/^exp=/i.test(t)) exp ??= t;
      else add(t);
    }
  }
  const redirect = all === undefined ? redirects.shift() : undefined;
  for (const domain of redirects) add(`include:${domain}`);
  const tail = all !== undefined ? [`${all}all`] : redirect !== undefined ? [`redirect=${redirect}`] : [];
  return ["v=spf1", ...terms, ...tail, ...(exp ? [exp] : [])].join(" ");
}

/** A pass term that matches every address: ip4:0.0.0.0/0, ip6:::/0, a/0, mx//0 (§5.3, §5.4). */
function isOpenTerm(term: string): boolean {
  const t = term.toLowerCase();
  if (/^[\-~?]/.test(t)) return false;
  const body = t.replace(/^\+/, "");
  if (/^ip[46]:/.test(body)) return /\/0$/.test(body);
  const m = /^(a|mx)(?::[^/]*)?(\/\d+)?(\/\/\d+)?$/.exec(body);
  return m !== null && (m[2] === "/0" || m[3] === "//0");
}

/** The domain's own record without +all, ?all, open ranges and terms after all. */
export function cleanSpf(record: string): string {
  const terms = record.split(" ").slice(1).filter(Boolean);
  const out: string[] = [];
  for (const t of terms) {
    const q = allQualifier(t);
    if (q) {
      out.push(q === "-" ? "-all" : "~all");
      break; // §5.1: terms after all are never evaluated
    }
    if (isOpenTerm(t)) continue;
    out.push(t);
  }
  return ["v=spf1", ...out].join(" ");
}
