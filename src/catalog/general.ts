// The catalog's entries any check may give, and the doubled record name, joined with the other
// groups by index.ts in the catalog's order.
import { rfc } from "./source.ts";
import type { CatalogEntry } from "../types.ts";

export const generalEntries: readonly CatalogEntry[] = [
  {
    id: "lookup-failed",
    group: "any",
    severity: "warning",
    impact: "spoofing",
    title: "A DNS lookup for {domain} got no answer",
    why: "Without that answer, this part of the check cannot give a result. Receivers that hit the same problem cannot read your records either.",
    fix: "Run the check again in a few minutes. If it keeps failing, ask your DNS host whether its name servers answer for {domain}.",
    // list: the Public Suffix List chunk did not load; no DNS lookup failed.
    // Its text names RFC 7489 because only receivers that still follow it use that list: RFC 9989,
    // which replaced it, finds the domain with the DNS Tree Walk (checks/dmarc-walk.ts).
    variants: [
      {
        when: "list",
        title: "The Public Suffix List did not load",
        why: "Receivers that still follow RFC 7489 use this list to find the domain whose DMARC record they apply. Without it, this check cannot tell which policy they apply to {domain} or to its subdomains. Your DNS records are not the cause.",
        fix: "Reload the page and run the check again. If it keeps failing, a browser extension or your network may be blocking files from this site.",
      },
    ],
    source: rfc(1035, "4.1.1"),
  },
  {
    id: "dnssec-broken",
    group: "any",
    severity: "critical",
    impact: "delivery",
    title: "DNSSEC validation fails for {domain}",
    why: "Resolvers that check DNSSEC return an error instead of your records. Mail servers that use them cannot read your mail settings, so your mail can be delayed or bounce.",
    fix: "Compare the DS record at your registrar with the keys your DNS host signs with. If you moved to another DNS host, replace the old DS record with the new one or remove it.",
    source: rfc(4035, "5.5"),
  },
  {
    id: "record-name-doubled",
    group: "dmarc",
    severity: "warning",
    impact: "spoofing",
    title: "A record sits at a name that repeats {domain}",
    why: "Your DNS panel probably added {domain} after a name that already ended in it. Receivers do not look up the doubled name, so they never read this record.",
    fix: "Edit the record and type only the host part, such as _dmarc, in the name field. Most DNS panels add {domain} for you.",
    source: rfc(9989, "4.5"),
  },
  {
    id: "name-is-alias",
    group: "any",
    severity: "info",
    impact: "delivery",
    title: "{domain} is an alias of {target}",
    why: "Receivers read the MX and SPF records of the name the alias points to. A name that is an alias can hold no records of its own.",
    fix: "Change the MX and SPF records where the alias points, or replace the alias with records of your own.",
    source: rfc(1034, "3.6.2"),
  },
];
