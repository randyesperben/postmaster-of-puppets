// A finding's texts as a report says them: the catalog entry's variant for the finding's vars,
// with its placeholders filled.
import { catalogEntry } from "./catalog/index.ts";
import { staticText } from "./static-text.ts";
import type { CatalogEntry, Finding } from "./types.ts";

/** Fills {name} placeholders; an unknown one stays as written. */
export function fillPlaceholders(text: string, values: Readonly<Record<string, string | number | undefined>>): string {
  return text.replace(/\{(\w+)\}/g, (all, k: string) => {
    const v = values[k];
    return v === undefined ? all : String(v);
  });
}

/**
 * A text of a catalog entry for a finding's vars, its placeholders unfilled (types.ts,
 * CatalogEntry.variants): field by field, the first variant whose var the finding carries and
 * that has that field, else the entry's own.
 */
export function variantText(entry: CatalogEntry, field: "title" | "why" | "fix", vars?: Finding["vars"]): string {
  return variantOf(entry, field, vars)?.[field] ?? entry[field];
}

/**
 * The variant whose text that field takes for the finding's vars; undefined when the entry's own
 * text applies.
 */
export function variantOf(
  entry: CatalogEntry,
  field: "title" | "why" | "fix",
  vars?: Finding["vars"],
): NonNullable<CatalogEntry["variants"]>[number] | undefined {
  return entry.variants?.find((v) => vars?.[v.when] !== undefined && v[field] !== undefined);
}

/**
 * A finding's text as a report says it: the variant its vars choose, with the checked domain
 * (`display`, as parseInput gives it) and the vars filled in. If a placeholder is still unfilled,
 * the entry's own text in its generic form (staticText), never a half-filled one.
 */
export function findingText(f: Finding, field: "title" | "why" | "fix", display: string): string {
  const entry = catalogEntry(f.id);
  if (!entry) return "";
  const text = fillPlaceholders(variantText(entry, field, f.vars), { ...f.vars, domain: display });
  return /\{\w+\}/.test(text) ? staticText(entry)[field] : text;
}
