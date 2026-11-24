// The details a finding carries (Finding.vars), key by key: which findings carry each one and
// what it means.
import type { Policy } from "./types.ts";

/**
 * Details of a finding's case: they fill the catalog's {placeholders} and choose its variants
 * (CatalogEntry.variants). A flag is 1 when set and absent otherwise; a count is a number. A type
 * rather than an interface, so it passes where a record of strings and numbers is expected
 * (fillPlaceholders).
 */
export type FindingVars = {
  /**
   * In the SPF findings tied to a term or record of the tree: the chain of names and terms from
   * the checked name to the record at fault, joined by " > "; the checked name alone for its own
   * record.
   */
  via?: string;
  /**
   * In spf-plus-all, spf-open-range, and lookup-failed and dnssec-broken of the SPF group: the
   * Organizational Domain when the finding is in that domain's SPF, which a forger can use with
   * relaxed alignment.
   */
  org?: string;
  /**
   * With `org`: only the Public Suffix List makes it the Organizational Domain (RFC 7489), so
   * receivers that follow RFC 9989 do not align with it.
   */
  psl?: 1;
  /**
   * In lookup-failed and dnssec-broken of the SPF group: the forger's evaluation no longer reaches
   * that query.
   */
  unreached?: 1;
  /**
   * In spf-plus-all and spf-open-range of the name's own record: the fix leaves another opening
   * inside an include it keeps.
   */
  cleanedVia?: 1;
  /**
   * spf-open-range: "cloud" for a wide range that holds cloud addresses. spf-syntax-error:
   * "quotes" for quote marks pasted inside the record, or the error in words. dkim-invalid-record:
   * "quotes", "case" for k= or h= in upper case, or "service" for a key whose s= leaves email out.
   * dmarc-bad-version: "repeated-tag", with the tag in `tag`. lookup-failed: "no-answer",
   * "disagree" (two operators answered differently) or "unconfirmed" (only one answered), with
   * `name`; or "not-loaded" with `list`, when a part of the Public Suffix List did not load.
   */
  reason?: string;
  /** In dmarc-bad-version with reason "repeated-tag": the tag the record repeats. */
  tag?: string;
  /** In spf-too-many-lookups and spf-too-many-void-lookups: how many there are. */
  count?: number;
  /**
   * In spf-too-many-lookups: the walk stopped counting at its own bound, so there may be more than
   * `count`.
   */
  atLeast?: 1;
  /** In spf-too-many-lookups: the name an include or redirect leads back to. */
  loop?: string;
  /** In spf-mx-too-many-hosts: how many hosts the mx term has. */
  hosts?: number;
  /**
   * In spf-too-large: how many more TXT records the name has, when the name and its SPF record
   * stay under 450 octets and those records take the answer past it (RFC 7208 §3.4).
   */
  others?: number;
  /** In spf-unused-include and dkim-unused-provider: the provider's name. */
  provider?: string;
  /** In name-is-alias: the name the alias points to. */
  target?: string;
  /**
   * In mx-missing: what the domain's own address says (RFC 5321 §5.1); "unknown" when its lookup
   * got no answer.
   */
  implicit?: "address" | "none" | "unknown";
  /** In mx-null: the preference of a null MX published with one other than 0. */
  preference?: number;
  /** In mx-null: the domain shows signs of sending. */
  sending?: 1;
  /**
   * In mx-null: only unanswered SPF or DKIM lookups keep the check from saying the domain sends
   * none.
   */
  sendingUnknown?: 1;
  /** In mta-sts-policy-unreachable: mta-sts.<domain> has only AAAA records (RFC 8461 §3.3). */
  ipv6Only?: 1;
  /** In dkim-key-1024: the key's length in bits. */
  bits?: number;
  /** In dkim-not-found: how many selectors the check tried. */
  tried?: number;
  /** In dkim-not-found: a *._domainkey wildcard answers every selector alike. */
  wildcard?: 1;
  /** In dkim-not-found: signed DNS says _domainkey does not exist. */
  none?: 1;
  /** In dkim-not-found: something exists under _domainkey and no selector tried answers. */
  hidden?: 1;
  /**
   * In dkim-not-found: the first valid selector of CheckOptions.extraSelectors, in lower case,
   * which has no key.
   */
  typed?: string;
  /**
   * In dmarc-multiple-records and dmarc-bad-version: the name of the discarded record when it is
   * not the checked name. In dmarc-subdomains-open: the name whose record applies to the
   * subdomains.
   */
  at?: string;
  /**
   * In dmarc-multiple-records: the parent whose record RFC 9989 applies instead of the several
   * records at the name.
   */
  inherited?: string;
  /**
   * In dmarc-subdomains-open: what is asked of the subdomains that exist; RFC 9989's only with
   * `pslOrgDomain`.
   */
  sp?: Policy;
  /**
   * In dmarc-subdomains-open: what is asked of the subdomains that do not exist; RFC 9989's only
   * with `pslOrgDomain`.
   */
  np?: Policy;
  /**
   * In dmarc-subdomains-open: the RFC 7489 reading leaves the subdomains open because they take
   * their policy from this name. In dmarc-org-differs: the name whose record the RFC 7489 reading
   * applies.
   */
  pslOrgDomain?: string;
  /** In dmarc-subdomains-open with `pslOrgDomain`: RFC 9989 opens the subdomains too. */
  both?: 1;
  /** In dmarc-subdomains-open with `pslOrgDomain`: that name has no record. */
  pslMissing?: 1;
  /** In dmarc-subdomains-open with `pslOrgDomain`: that name has several records. */
  pslSeveral?: 1;
  /**
   * In dmarc-org-differs: the name whose record RFC 9989 applies, which may be a public suffix's.
   */
  orgDomain?: string;
  /** In dmarc-org-differs: the policy of the RFC 9989 reading. */
  policy?: Policy;
  /**
   * In dmarc-org-differs: the policy of the RFC 7489 reading, or "no DMARC policy" when it finds
   * none.
   */
  pslPolicy?: Policy | "no DMARC policy";
  /**
   * In dmarc-org-differs, dmarc-multiple-records, dmarc-bad-version, dmarc-tag-typo,
   * dmarc-invalid-policy, dmarc-pct, dmarc-testing-mode and dmarc-subdomains-open (np against
   * sp, or with `pslOrgDomain`): the RFC 9989 and RFC 7489 readings give different levels, this
   * finding is the cause, and the weaker reading decides the verdict.
   */
  weaker?: 1;
  /**
   * In place of `weaker`: the readings differ, but the verdict would be the same with the stronger
   * one.
   */
  split?: 1;
  /** In dmarc-rua-unauthorized: the domain of the report address. */
  host?: string;
  /** In lookup-failed: the name asked; absent with reason "not-loaded". */
  name?: string;
  /**
   * In lookup-failed with reason "disagree": the first operator's answer, "<operator>: <answer>"
   * ("resolver" for a resolver of LookupOptions).
   */
  first?: string;
  /** With reason "disagree": the second operator's answer, as in `first`. */
  second?: string;
  /**
   * In lookup-failed with reason "disagree": the longer TTL of the two answers, when they may
   * agree.
   */
  waitSeconds?: number;
  /** In lookup-failed with reason "not-loaded": the list that did not load. */
  list?: string;
};
