// The Public Suffix List, as receivers that still follow RFC 7489 use it to find the
// Organizational Domain (RFC 7489 §3.2), and as the MX check uses it to tell a public suffix from
// a zone. Each part of the list is loaded with import() on first use, so a bundler can put it in a
// chunk of its own, downloaded only when a check needs the list: an inherited policy, the
// subdomains of a name of three labels or more, or an alias.
import { withSignal } from "./dns/doh.ts";
import type { Ctx } from "./dns/lookup.ts";

/** Where the two parts of the list come from; tests replace them. */
export interface PslLoaders {
  /** Loads the PSL rules with DMARC at or above them (data/psd-dmarc.ts). */
  psl?: () => Promise<readonly string[]>;
  /** Loads the rest of the PSL's rules, grouped (data/psl-rest.ts). */
  pslRest?: () => Promise<Readonly<Record<string, string>>>;
}

/**
 * The longest rule of the list that matches `domain`, by the PSL algorithm (wildcards and
 * exceptions; publicsuffix.org/list/, “Formal algorithm”), as the public suffix it names.
 */
export function publicSuffixIn(domain: string, rules: ReadonlySet<string>): string | undefined {
  const labels = domain.split(".");
  for (let i = 0; i < labels.length; i++) {
    const name = labels.slice(i).join(".");
    if (rules.has(`!${name}`)) return labels.slice(i + 1).join(".");
    if (rules.has(name)) return name;
    if (i + 1 < labels.length && rules.has(`*.${labels.slice(i + 1).join(".")}`)) return name;
  }
  return undefined;
}

let psdDmarcCache: Promise<ReadonlySet<string>> | undefined;
let pslRestCache: Promise<ReadonlySet<string>> | undefined;

/** The rules of psl-rest.ts, { "uk": "ac,co" } read as ac.uk and co.uk. */
function expandRest(groups: Readonly<Record<string, string>>): ReadonlySet<string> {
  const rules = new Set<string>();
  for (const [after, firsts] of Object.entries(groups))
    for (const first of firsts.split(",")) rules.add(`${first}.${after}`);
  return rules;
}

/**
 * The rules with DMARC at or above them, loaded once: for an inherited policy, the subdomains of a
 * name of three labels or more, or an alias. A part that failed to load is asked again by the next
 * check.
 */
function loadPsdDmarc(): Promise<ReadonlySet<string>> {
  return (psdDmarcCache ??= import("./data/psd-dmarc.ts")
    .then((m) => new Set(m.PSD_DMARC))
    .catch((e: unknown) => {
      psdDmarcCache = undefined;
      throw e;
    }));
}

/** The rest of the PSL, loaded once, when psd-dmarc.ts cannot decide or for isPublicSuffix. */
function loadPslRest(): Promise<ReadonlySet<string>> {
  return (pslRestCache ??= import("./data/psl-rest.ts")
    .then((m) => expandRest(m.PSL_REST))
    .catch((e: unknown) => {
      pslRestCache = undefined;
      throw e;
    }));
}

/** The rules with DMARC at or above them, from `loaders.psl` when given. */
export function psdDmarcRules(loaders: PslLoaders = {}): Promise<ReadonlySet<string>> {
  return loaders.psl ? loaders.psl().then((r) => new Set(r)) : loadPsdDmarc();
}

/** The rest of the PSL's rules, from `loaders.pslRest` when given. */
export function pslRestRules(loaders: PslLoaders = {}): Promise<ReadonlySet<string>> {
  return loaders.pslRest ? loaders.pslRest().then(expandRest) : loadPslRest();
}

/**
 * Whether `name` is itself a public suffix by the whole PSL (both parts; a plain one-label rule
 * is always one), within the check's limit; undefined when a part does not load. A rule's
 * exception goes with its wildcard in the same part, so each part can answer alone.
 */
export async function isPublicSuffix(ctx: Ctx, name: string): Promise<boolean | undefined> {
  if (!name.includes(".")) return true;
  try {
    const sets = await withSignal(Promise.all([loadPsdDmarc(), loadPslRest()]), ctx.signal);
    return sets.some((rules) => publicSuffixIn(name, rules) === name);
  } catch {
    return undefined;
  }
}
