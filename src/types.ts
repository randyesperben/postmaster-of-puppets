// The engine's types: findings and the catalog, a report and its parts, the provider data, and
// the options of a check. The DNS layer's types are in dns/types.ts; the types of receiverRules,
// verdictRules and checkAlignment are in receivers.ts, rules.ts and alignment.ts.
import type { Resolver, ResolverId } from "./dns/types.ts";
import type { FindingVars } from "./finding-vars.ts";

/** The five groups of a check; a report gives each one a status (Report.groups). */
export type Group = "mx" | "spf" | "dkim" | "dmarc" | "transport";
/** Most serious first; SEVERITY_ORDER (findings.ts) ranks them. */
export const SEVERITIES = ["critical", "warning", "info", "pass"] as const;
/** How serious a finding is; "pass" is a finding that says a record is right. */
export type Severity = (typeof SEVERITIES)[number];
/**
 * What a finding puts at stake: "spoofing", whether others can send email as the domain;
 * "delivery", whether the domain's own mail arrives; "hardening", protection on top of those two,
 * which never fails or weakens its group (statusOf in findings.ts).
 */
export type Impact = "spoofing" | "delivery" | "hardening";
/**
 * A group's result: "pass"; "weak", a warning; "fail", a critical finding; "unknown", the check
 * cannot tell, as when a lookup got no answer or no DKIM key was found.
 */
export type GroupStatus = "pass" | "weak" | "fail" | "unknown";
/** The verdicts, worst first, then cant-tell. */
export const VERDICTS = ["spoofable", "partly-protected", "protected", "cant-tell"] as const;
/**
 * Whether others can send email as the domain: "spoofable"; "partly-protected", a policy of
 * quarantine, or reject with subdomains left open; "protected", reject for the name and its
 * subdomains; "cant-tell", a lookup that could change the answer got none. verdictRules
 * (rules.ts) holds the exact conditions, in the order they are tried.
 */
export type Verdict = (typeof VERDICTS)[number];
/**
 * Whether the domain's own mail arrives: "ok", "at-risk", "unknown", or "no-mail" for a domain
 * that declares it sends none. deliveryRules (rules.ts) holds the exact conditions.
 */
export type Delivery = "ok" | "at-risk" | "unknown" | "no-mail";
/**
 * Whether the domain uses email: "none-declared", a null MX (RFC 7505) and no sign of sending;
 * "probably-none", no MX (or an MX lookup without an answer), no SPF record that lets a server
 * send, no DKIM key, and every SPF and DKIM lookup answered; "mail" otherwise.
 */
export type MailUse = "none-declared" | "probably-none" | "mail";
/** A DMARC policy, as the p=, sp= and np= tags write it. */
export type Policy = "none" | "quarantine" | "reject";
/**
 * Whether a name exists: "yes"; "nxdomain"; or "nxname", denied by Compact Denial of Existence
 * (RFC 9824), a NOERROR answer whose NSEC or NSEC3 record says NXNAME.
 */
export type NameExists = "yes" | "nxdomain" | "nxname";

/**
 * Every finding the engine can give: those of any group first, then MX, SPF, DMARC, DKIM, MTA-STS
 * and TLS-RPT. Each one has its entry in the catalog (catalog/index.ts).
 */
export const FINDING_IDS = [
  "lookup-failed",
  "dnssec-broken",
  "record-name-doubled",
  "name-is-alias",
  "mx-ok",
  "mx-null",
  "mx-missing",
  "mx-null-with-others",
  "mx-cname",
  "mx-ip-literal",
  "mx-unresolvable",
  "mx-private-ip",
  "spf-ok",
  "spf-missing",
  "spf-multiple-records",
  "spf-syntax-error",
  "spf-too-many-lookups",
  "spf-too-many-void-lookups",
  "spf-mx-too-many-hosts",
  "spf-include-no-spf",
  "spf-redirect-no-spf",
  "spf-duplicate-modifier",
  "spf-plus-all",
  "spf-open-range",
  "spf-wide-range",
  "spf-neutral-all",
  "spf-ptr",
  "spf-terms-after-all",
  "spf-too-large",
  "spf-sender-macros",
  "spf-unused-include",
  "dmarc-enforced",
  "dmarc-missing",
  "dmarc-multiple-records",
  "dmarc-bad-version",
  "dmarc-invalid-policy",
  "dmarc-policy-none",
  "dmarc-policy-quarantine",
  "dmarc-testing-mode",
  "dmarc-pct",
  "dmarc-subdomains-open",
  "dmarc-no-rua",
  "dmarc-rua-unauthorized",
  "dmarc-ruf",
  "dmarc-tag-typo",
  "dmarc-org-differs",
  "dkim-ok",
  "dkim-not-found",
  "dkim-invalid-record",
  "dkim-key-under-1024",
  "dkim-key-1024",
  "dkim-sha1-only",
  "dkim-testing-mode",
  "dkim-revoked",
  "dkim-dangling-cname",
  "dkim-ed25519-only",
  "dkim-unused-provider",
  "mta-sts-ok",
  "mta-sts-missing",
  "mta-sts-invalid",
  "mta-sts-policy-unreachable",
  "tls-rpt-missing",
  "tls-rpt-invalid",
] as const;
/** One of FINDING_IDS. */
export type FindingId = (typeof FINDING_IDS)[number];

/**
 * What parseInput makes of the text it is given. With `ok`, `domain` is the name to check in ASCII
 * (punycode), `display` the same name as written, in lower case, and `note` says where it came
 * from: "www-removed" (www. taken off), "from-email" (an email address) or "from-url" (a web
 * address). Otherwise `error` says why there is no domain to check: "empty", "not-a-domain",
 * "ip-address" or "too-long" (longer than DNS allows, RFC 1035 §2.3.4).
 */
export type ParsedInput =
  | { ok: true; domain: string; display: string; note?: "www-removed" | "from-email" | "from-url" }
  | { ok: false; error: "empty" | "not-a-domain" | "ip-address" | "too-long" };
/** A ParsedInput that holds a domain: what checkDomain takes. */
export type ParsedDomain = Extract<ParsedInput, { ok: true }>;

/** One DNS change that fixes a finding: add, replace or remove one record. */
export interface Fix {
  action: "add" | "replace" | "remove";
  type: "TXT" | "MX" | "CNAME";
  /**
   * The name relative to the zone, as DNS panels ask for it: "_dmarc", or "@" at the apex. The
   * full name when the check found no zone apex (Report.zone).
   */
  host: string;
  /** The full name, without the final dot: _dmarc.example.com. */
  name: string;
  /** The record's value, ready to paste; "{rua}" where the reports address goes (fillRua). */
  value: string;
  /** The current value, with replace or remove; with a CNAME, its target. */
  replaces?: string;
  /**
   * On a DMARC fix that is one step of a chain: step `n` of `of`, and whether that step protects,
   * which is when the policy it publishes is quarantine or reject outside testing mode.
   */
  step?: { n: number; of: number; protects: boolean };
  /**
   * On each DMARC fix that publishes a policy: what the record asks once that fix, and the ones
   * before it in its chain, is applied. `asks` is for the checked name and `sub` for the names
   * below it (sp or np, the weaker), each in the weaker of the RFC 9989 and RFC 7489 readings, by
   * the same rule as the effective policy. Compare `after` to find the fix that changes what a
   * forged email gets: it need not be the first of its chain. No `sub` when the engine cannot
   * tell what the record would ask of the names below: under the Organizational Domain another
   * name's record may decide for them, and the engine does not always read it.
   */
  after?: { asks: Ask; sub?: Ask };
}

/** Something a check found, good or bad, with what the DNS showed and the fixes for it. */
export interface Finding {
  id: FindingId;
  /**
   * In lookup-failed and dnssec-broken, the group affected; name-is-alias goes in "mx", and
   * record-name-doubled in "spf" for a doubled SPF record.
   */
  group: Group;
  /**
   * The catalog entry's severity, unless the check set another for this case: a discarded DMARC
   * record, a null MX on a domain that sends, a DKIM key in testing mode and the like.
   */
  severity: Severity;
  impact: Impact;
  /**
   * What the check saw, as text: the record or term at fault, or a short description of the query
   * or value ("example.com TXT", "s1: 1024 bits"). TXT is decoded as UTF-8.
   */
  found?: string;
  /** Details of this case, for its texts and variants (FindingVars). */
  vars?: FindingVars;
  /** The DNS changes that fix it, in order; empty when there is nothing to change. */
  fixes: Fix[];
}

/** A source a text cites: an RFC with its section, or a vendor's page, with its URL. */
export interface Source {
  /** "RFC 7208 §4.6.4", or the publisher and the page's title. */
  readonly label: string;
  readonly url: string;
}

/** What the engine says about one finding id: its group, severity, texts and source. */
export interface CatalogEntry {
  id: FindingId;
  /** "any": lookup-failed, dnssec-broken and name-is-alias, which take the group they affect. */
  group: Group | "any";
  severity: Severity;
  impact: Impact;
  /**
   * One line; it may hold {placeholders} (findingText fills them, staticText gives their generic
   * form).
   */
  title: string;
  /** One or two plain sentences. */
  why: string;
  /**
   * What to do, in one or two sentences; empty for passes and for the two questions,
   * spf-unused-include and dkim-unused-provider.
   */
  fix: string;
  /**
   * Other texts for some cases. Field by field, the first variant whose var `when` the finding
   * carries (vars[when] !== undefined) and that has that field wins; staticText uses the entry's
   * own fields.
   */
  variants?: readonly Readonly<{ when: keyof FindingVars; title?: string; why?: string; fix?: string }>[];
  /** An RFC with its section, or the vendor's documentation. */
  source: Source;
  /**
   * The path of the guide on postmasterofpuppets.com that explains it:
   * "/guides/spf/too-many-dns-lookups/".
   */
  guide?: string;
}

/** An email provider the engine recognizes by its MX hosts, SPF includes or DKIM keys. */
export interface Provider {
  id: string;
  name: string;
  /** Suffixes of its MX hosts. */
  mx: readonly string[];
  /** Suffixes of its SPF includes; spf-missing writes the first one for a domain with its MX. */
  spfIncludes: readonly string[];
  /** The DKIM selectors it documents; the check tries them all (SELECTORS). */
  dkimSelectors: readonly string[];
  /**
   * The MX hosts that say the domain sends through it, when not all do; spf-missing writes its
   * include only for these. Empty for a gateway; SES: not its receiving endpoints.
   */
  sendingMx?: readonly string[];
  /**
   * The include spf-missing writes for its MX when the one its page gives is shared by other
   * services and so names no one (Hover, of Tucows).
   */
  fixInclude?: string;
  /**
   * Suffixes of the CNAME target of its keys; with them, a key is attributed to it only by its
   * target.
   */
  dkimTargets?: readonly string[];
  /**
   * Sends with its own bounce domain or a subdomain, so dkim-unused-provider does not ask about it.
   */
  sendOnly?: boolean;
  /**
   * The mechanisms its page writes before its include (ALL-INKL: a mx); spf-missing writes them the
   * same way.
   */
  fixMechanisms?: readonly string[];
  /**
   * Its page gives redirect=<its include> when it is the only sender (Strato), and the fix writes
   * it that way.
   */
  spfRedirect?: boolean;
  /**
   * Only receives and forwards (Cloudflare Email Routing), so it is not a sending service
   * (sendingServices).
   */
  receiveOnly?: boolean;
  /**
   * Selectors it rotates through, one live at a time (Microsoft 365: [["selector1", "selector2"]]).
   */
  rotationGroups?: readonly (readonly string[])[];
}

/**
 * One term of the SPF record as the check walked it: `domain` is the name it looks up, `lookups`
 * counts its own and its children's (RFC 7208 §4.6.4), `children` are the terms of the record an
 * include or redirect leads to, and `finding` the id of a finding at this term. The root is the
 * whole record, with `domain` the checked name.
 */
export interface SpfNode {
  /** The term as written; for the root, the whole record. */
  term: string;
  /** The name it looks up; for the root, the checked name. */
  domain?: string;
  /** DNS lookups of this term and its children (RFC 7208 §4.6.4). */
  lookups: number;
  /** The terms of the record an include or redirect leads to. */
  children: SpfNode[];
  /** A finding at this term. */
  finding?: FindingId;
}
/**
 * An MX host with its addresses and, when it names one, the provider it belongs to (Provider.id).
 */
export interface MxHost {
  preference: number;
  host: string;
  /** Its A and AAAA addresses. */
  addresses: string[];
  /** The provider it belongs to, as an id of providerList. */
  provider?: string;
}
/**
 * A DKIM key found at a selector: `bits` for RSA, `revoked` for an empty p=, and `viaCname`, the
 * target, when the selector is a CNAME. Selector "*" is the key a *._domainkey wildcard answers.
 */
export interface DkimKey {
  /** The selector; "*" for the key a *._domainkey wildcard answers. */
  selector: string;
  algorithm: "rsa" | "ed25519";
  /** The RSA key's length in bits. */
  bits?: number;
  /** An empty p=: the key was revoked. */
  revoked: boolean;
  /** The CNAME target, when the selector is a CNAME. */
  viaCname?: string;
}

/** What a DMARC policy asks of an email that fails it; "nothing" for p=none. */
export type Ask = "reject" | "quarantine" | "nothing";
/**
 * Why a forged email gets what it gets: no DMARC policy applies (in the weaker reading), an SPF
 * record open to anyone, p=none, testing mode (t=y, or pct=0), a pct between 1 and 99, or the
 * quarantine or reject the policy asks.
 */
export type SimReason = "no-dmarc" | "open-spf" | "policy-none" | "testing" | "sampled" | "quarantine" | "reject";

/**
 * What receivers are asked to do with a typical forged email: one from a server not the domain's,
 * without its DKIM signature.
 */
export interface Simulation {
  /** The DMARC result of a forged message with the domain in its From. */
  forgedDmarc: "pass" | "fail" | "none";
  /** What the effective policy asks for that message. */
  asks: Ask;
  /** Why the forged email gets `asks`. */
  reason: SimReason;
  /**
   * With a pct between 1 and 99: `full` is asked of that share and `asks` of the rest (`dmarcAsks`
   * with "open-spf").
   */
  sampled?: { pct: number; full: Ask };
  /**
   * What sp or np asks of a forged subdomain, only when it asks less than `asks` (with "open-spf",
   * than `dmarcAsks`, and only with aspf=s).
   */
  subdomain?: { asks: Ask; tag: "sp" | "np" };
  /**
   * Only with reason "open-spf": what the effective policy would ask of that message if it failed
   * DMARC, with t=y and pct already applied as in `asks`.
   */
  dmarcAsks?: Ask;
  /** An illustrative Authentication-Results line (RFC 8601) for the simulation. */
  authResults: string;
}

/** The result of checkDomain. */
export interface Report {
  /** ASCII (punycode). */
  domain: string;
  /** The checked name as parseInput gives it: in Unicode, lower case (ParsedInput.display). */
  display: string;
  /**
   * The zone apex, from the SOA, which Fix.host is relative to; for an alias, its parent's, unless
   * the parent is a public suffix or an alias itself.
   */
  zone?: string;
  /** Whether the checked name exists; absent when its lookup got no answer. */
  exists?: NameExists;
  /**
   * "done"; "partial", the time limit (LookupOptions.deadlineMs) or the caller's signal cut some
   * lookups short; "nxdomain", the name does not exist and no DMARC record covers it;
   * "unreachable", no DNS-over-HTTPS operator answered, so the report holds only the MX findings.
   */
  outcome: "done" | "partial" | "nxdomain" | "unreachable";
  /** Can the domain be spoofed (verdictRules). */
  verdict: Verdict;
  /** Will its real mail arrive (deliveryRules). */
  delivery: Delivery;
  /** The row of deliveryRules that decided, and its finding's id when it has one. */
  deliveryCause: { rule: number; finding?: FindingId };
  /** Does the domain use mail at all. */
  mailUse: MailUse;
  /** Each group's status. */
  groups: Record<Group, GroupStatus>;
  /** Most serious first: critical, warning, info, pass. */
  findings: Finding[];
  /** The providers found by MX, SPF or DKIM, as ids of providerList. */
  providers: string[];
  /**
   * Providers seen only through an MX that does not say the domain sends through it (a gateway,
   * SES receiving): they are not sending services.
   */
  inboundOnly?: string[];
  /** The MX hosts read, at most 10, by preference, with their addresses and provider. */
  mx: MxHost[];
  /**
   * The SPF record, its tree, and its DNS lookups and void lookups as a receiver counts them for a
   * sender that matches no term (RFC 7208 §4.6.4), the worst case: a minimum when
   * spf-too-many-lookups carries `atLeast`. With several SPF records, 0 and no record or tree.
   */
  spf: { record?: string; lookups: number; voidLookups: number; tree?: SpfNode };
  /**
   * The DMARC record in force and the name it was found at, the Organizational Domain, the tag
   * that gave the effective policy (sp for an existing subdomain, np for one that does not exist)
   * and the record's tags.
   */
  dmarc: {
    record?: string;
    foundAt?: string;
    orgDomain?: string;
    policyFrom?: "p" | "sp" | "np";
    tags: Record<string, string>;
  };
  /** The keys found, how many selectors were tried, and the selectors whose query got no answer. */
  dkim: { keys: DkimKey[]; selectorsTried: number; noAnswer: string[] };
  /**
   * Absent with cant-tell, nxdomain or unreachable, and when no DMARC policy is known because a
   * DMARC lookup got no usable answer or failed DNSSEC validation.
   */
  simulation?: Simulation;
  /** The DNS-over-HTTPS operators that answered; empty with a resolver of LookupOptions. */
  resolvers: ResolverId[];
  /** ISO 8601. */
  checkedAt: string;
}

/**
 * An event of CheckOptions.onProgress. "group": a group has its result, which the report may
 * still adjust once every group is in: the SPF group takes the Organizational Domain's SPF
 * findings and status, DKIM without keys on a domain without mail becomes unknown, mx-null on a
 * domain that sends becomes a warning that makes the MX group weak, and DMARC vars may change
 * (weaker to split).
 * "resolver-switch": an operator stopped answering and the next one took over.
 */
export type Progress =
  | { type: "group"; group: Group; status: GroupStatus; findings: Finding[] }
  | { type: "resolver-switch"; from: ResolverId; to: ResolverId };

/** The options about lookups, which checkDomain and checkAlignment share. */
export interface LookupOptions {
  /** Cancels the check as the time limit does: the lookups in flight end without an answer. */
  signal?: AbortSignal;
  /**
   * The time limit of the whole check, 10000 by default; the lookups still in flight then end
   * without an answer (checkDomain's outcome "partial", checkAlignment's `failed`).
   */
  deadlineMs?: number;
  /**
   * The DNS-over-HTTPS operators to ask, in order; by default the order of `operators`
   * (operators.ts).
   */
  resolverOrder?: readonly ResolverId[];
  /**
   * Answers every query in place of the DNS-over-HTTPS operators (Resolver); resolverOrder is then
   * ignored.
   */
  resolver?: Resolver;
}

/** The options of checkDomain. */
export interface CheckOptions extends LookupOptions {
  /** Called as each group has its result and when an operator takes over from another. */
  onProgress?: (p: Progress) => void;
  /**
   * DKIM selectors to try on top of the common ones, such as the s= of a message's DKIM-Signature.
   */
  extraSelectors?: readonly string[];
}
