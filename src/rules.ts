// Verdict and delivery rules. The first rule whose condition holds wins, so order matters.
// verdict.ts implements these rows in this order, and Report.deliveryCause.rule indexes into
// deliveryRules.
import { GOOGLE_SENDERS, rfc } from "./catalog/source.ts";
import type { Delivery, Source, Verdict } from "./types.ts";

/** A row of verdictRules or deliveryRules: the result, when it holds in words, and its source. */
export interface Rule<T> {
  /** The answer the row gives. */
  result: T;
  /** When the row holds, in words. */
  when: string;
  /** The RFC section or page the row comes from. */
  source: Source;
}

/**
 * When each verdict holds, in words, with its source: the first row whose condition holds decides.
 */
export const verdictRules: readonly Readonly<Rule<Verdict>>[] = [
  {
    result: "cant-tell",
    when: "A lookup that could change the answer got no usable answer: no DNS service answered, two services gave different answers, or only one answered. DMARC lookups count, and so do the lookup of whether the name exists when np asks for less than sp, the lookup at the top-level domain and the Public Suffix List. The Public Suffix List does not count when the policy is none, which leaves the domain open either way. For a name that has a record of its own, a DMARC lookup above it decides the policy of its subdomains and, unless aspf=s is set, which name is its organizational domain, whose SPF counts too. That lookup counts when the effective policy is reject, or when it is quarantine and aspf=s is not set. The Public Suffix List counts for such a name unless aspf=s is set, and with aspf=s only when the effective policy is reject and its subdomains are otherwise closed. None of them counts when the domain’s own SPF, through any branch receivers evaluate, authorizes the whole internet or addresses anyone can rent, and every lookup without an answer comes after the point where that SPF has decided for senders over both IPv4 and IPv6: the domain is then Spoofable whatever DMARC says. SPF lookups count only when DMARC asks for quarantine or reject. A lookup the 10-second limit cut short counts like one that got no answer. MX lookups never count. DNSSEC validation that fails on one of the records that count gives the same answer.",
    source: rfc(4035, "4.3"),
  },
  {
    result: "spoofable",
    when: "No DMARC policy applies to the domain for receivers that follow RFC 9989 or for those that still follow RFC 7489 (none on the name or on its organizational domain, more than one record on the same name, or a malformed v= tag), or the effective policy is none. When the two kinds of receivers read different policies, the weaker one counts.",
    source: rfc(9989, "4.10.1"),
  },
  {
    result: "spoofable",
    when: "A branch of the SPF tree that receivers evaluate authorizes the whole internet or addresses anyone can rent, even with DMARC at reject: +all, ip4:0.0.0.0/0, ip6:::/0, a or mx with a /0 prefix, a range wider than /16 (IPv4) or /32 (IPv6) that holds cloud addresses, or exists without macros on a name with an address.",
    source: rfc(7208, "5.2"),
  },
  {
    result: "partly-protected",
    when: "The effective policy is quarantine, or it is reject while sp=none or np=none leaves subdomains open.",
    source: rfc(9989, "4.10.1"),
  },
  {
    result: "protected",
    when: "The effective policy is reject and no subdomain policy is none.",
    source: rfc(9989, "4.10.1"),
  },
];

/**
 * When each delivery answer holds, in words, with its source: the first row whose condition holds
 * decides.
 */
export const deliveryRules: readonly Readonly<Rule<Delivery>>[] = [
  {
    result: "no-mail",
    when: "The domain publishes a null MX and shows no sign of sending email: SPF and DKIM answered, with no SPF record that authorizes a server and no DKIM key except revoked ones.",
    source: rfc(7505, "3"),
  },
  {
    result: "at-risk",
    when: "SPF ends in permerror: more than one SPF record, more than 10 DNS lookups, more than 2 void lookups, an mx term with more than 10 hosts, a syntax error, redirect= or exp= written twice, or an include or redirect to a domain without SPF.",
    source: rfc(7208, "4.6.4"),
  },
  {
    result: "at-risk",
    when: "Every DKIM key found is unusable: shorter than 1024 bits, limited to sha1, malformed, with k= or h= in capitals, or in testing mode (t=y), which verifiers treat as unsigned mail.",
    source: rfc(8301, "3"),
  },
  {
    result: "at-risk",
    when: "No MX host is usable, a null MX sits next to other MX records, a domain that sends email has no MX and no address of its own, or a domain that sends email, or may send it, publishes a null MX.",
    source: rfc(7505, "3"),
  },
  {
    result: "at-risk",
    when: "DNSSEC validation fails for the domain’s mail records.",
    source: rfc(4035, "4.3"),
  },
  {
    result: "at-risk",
    when: "The domain sends email but has no DMARC record or no SPF record. Gmail, Yahoo and Outlook.com require both from bulk senders.",
    source: GOOGLE_SENDERS,
  },
  {
    result: "unknown",
    when: "None of the above, but DKIM was not found with common selectors, the domain publishes no DKIM keys, a lookup failed, or the domain probably sends no email.",
    source: rfc(6376, "3.6.2.1"),
  },
  {
    result: "ok",
    when: "SPF is valid, at least one DKIM key is usable, DMARC is published and every lookup answered.",
    source: rfc(9989, "4.10.1"),
  },
];
