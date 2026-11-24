// Catalog texts without a checked domain, for a static list of everything a check can flag:
// every {placeholder} takes a generic form that reads right in its sentence. A report's findings
// fill the same texts with the real domain and the finding's vars instead.
import type { CatalogEntry } from "./types.ts";

/**
 * The generic form of each placeholder the catalog uses. hosts and count only appear past a
 * limit (RFC 7208 §4.6.4: 10 MX hosts, 2 void lookups), so their generic form says the limit;
 * host is the domain of a report address that is not the checked one; orgDomain and policy
 * (RFC 9989) against pslOrgDomain and pslPolicy (the Public Suffix List) read as one against
 * the other.
 */
export const STATIC_FORMS: Readonly<Record<string, string>> = {
  domain: "your domain",
  provider: "a service",
  host: "the other domain",
  hosts: "more than 10",
  count: "more than 2",
  tried: "the",
  sp: "the sp= value",
  np: "the np= value",
  at: "your domain or its parent",
  target: "another name",
  orgDomain: "one name",
  policy: "one policy",
  pslOrgDomain: "another name",
  pslPolicy: "a different one",
};

/**
 * A catalog text with every placeholder in its generic form. Throws for a placeholder that has
 * none in STATIC_FORMS, which a test rules out for every catalog text.
 */
export function staticForm(text: string): string {
  return text.replace(/\{(\w+)\}/g, (_, name: string, at: number) => {
    const form = STATIC_FORMS[name];
    if (form === undefined) throw new Error(`no static form for {${name}}`);
    // A placeholder that opens a sentence opens it with a capital.
    const opens = at === 0 || /[.?!]\s+$/.test(text.slice(0, at));
    return opens ? form.charAt(0).toUpperCase() + form.slice(1) : form;
  });
}

/** An entry's title, why and fix in words, as staticText gives them. */
export interface StaticText {
  title: string;
  why: string;
  fix: string;
}

/**
 * title, why and fix of an entry with every placeholder in its generic form. Throws for a
 * placeholder with no generic form (staticForm).
 */
export function staticText(entry: CatalogEntry): StaticText {
  return { title: staticForm(entry.title), why: staticForm(entry.why), fix: staticForm(entry.fix) };
}
