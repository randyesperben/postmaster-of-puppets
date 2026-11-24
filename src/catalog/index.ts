// The catalog of findings: every finding the engine can give, with its group, severity, texts,
// fix and sources. Texts may hold {domain} (the checked domain) and the finding's own vars
// (finding-vars.ts, FindingVars). fix is empty for the pass entries and for the two questions
// (spf-unused-include, dkim-unused-provider), which offer no fix.
// One file per group in this folder, joined here in the order of FINDING_IDS; the sources they
// cite are in source.ts.
import type { CatalogEntry, FindingId } from "../types.ts";
import { generalEntries } from "./general.ts";
import { mxEntries } from "./mx.ts";
import { spfEntries } from "./spf.ts";
import { dmarcEntries } from "./dmarc.ts";
import { dkimEntries } from "./dkim.ts";
import { transportEntries } from "./transport.ts";

/** Every finding the engine can give, one entry per id, in the order of FINDING_IDS. */
export const catalog: readonly Readonly<CatalogEntry>[] = [
  ...generalEntries,
  ...mxEntries,
  ...spfEntries,
  ...dmarcEntries,
  ...dkimEntries,
  ...transportEntries,
];

const BY_ID = new Map<string, Readonly<CatalogEntry>>(catalog.map((e) => [e.id, e]));

/** The catalog entry of a finding id. */
export function catalogEntry(id: FindingId): Readonly<CatalogEntry> | undefined {
  return BY_ID.get(id);
}
