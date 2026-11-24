// The catalog's DMARC entries, joined with the other groups by index.ts in the catalog's order.
import { rfc } from "./source.ts";
import type { CatalogEntry } from "../types.ts";

export const dmarcEntries: readonly CatalogEntry[] = [
  {
    id: "dmarc-enforced",
    group: "dmarc",
    severity: "pass",
    impact: "spoofing",
    title: "DMARC is set to reject",
    why: "Receivers that check DMARC are told to reject mail that fakes {domain}.",
    fix: "",
    source: rfc(9989, "4.7"),
  },
  {
    id: "dmarc-missing",
    group: "dmarc",
    severity: "critical",
    impact: "spoofing",
    guide: "/guides/dmarc/p-none-to-reject/",
    title: "No DMARC policy applies to {domain}",
    why: "Receivers get no instruction for mail that fakes {domain}. Anyone can send email that shows your domain in the From line.",
    fix: "Publish a TXT record at _dmarc.{domain} with v=DMARC1, p=none and a rua address for reports. Once the reports show that your real mail passes, move to quarantine and then to reject.",
    source: rfc(9989, "4.10.1"),
  },
  {
    id: "dmarc-multiple-records",
    group: "dmarc",
    severity: "critical",
    impact: "spoofing",
    title: "{domain} has more than one DMARC record",
    why: "Receivers discard every DMARC record when they find more than one, so {domain} is left with no DMARC policy.",
    fix: "Keep one TXT record at _dmarc.{domain} and delete the others.",
    // The records sit at a parent's name. weaker: only RFC 7489 receivers see two records (one is
    // V=DMARC1), RFC 9989 ones apply the other. A parent's notice is information for whoever
    // manages it, never a fix of the checked name.
    // inherited: the records sit at {domain} itself and a parent's record is in force, which
    // RFC 9989 receivers apply and RFC 7489 ones never reach. Before weaker, which the finding
    // also carries.
    variants: [
      {
        when: "inherited",
        why: "Receivers that follow RFC 9989 discard both records at _dmarc.{domain} and apply the policy that {inherited}’s DMARC record sets for subdomains (sp, or p when sp is absent). Receivers that still follow RFC 7489 stop at the two records and apply no DMARC policy to {domain}.",
      },
      {
        when: "weaker",
        why: "Receivers that still follow RFC 7489 read V=DMARC1 as a second DMARC record and discard both, so for them {domain} has no DMARC policy. Receivers that follow RFC 9989 read only the v=DMARC1 one and apply it.",
      },
      {
        when: "at",
        title: "{at} has more than one DMARC record",
        why: "Receivers discard every DMARC record when they find more than one, so {at} and the names under it without a record of their own, {domain} included, are left with no DMARC policy.",
        fix: "Whoever manages {at} should keep one TXT record at _dmarc.{at} and delete the others.",
      },
    ],
    source: rfc(9989, "4.10"),
  },
  {
    id: "dmarc-bad-version",
    group: "dmarc",
    severity: "critical",
    impact: "spoofing",
    title: "The DMARC record of {domain} is malformed",
    why: "A DMARC record must start with v=DMARC1, written exactly like that, and name each tag once. Receivers ignore a record that breaks either rule, so it does not protect {domain}.",
    fix: "Put v=DMARC1 at the very start of the record, with DMARC1 in capital letters, and keep one copy of each tag.",
    // The record sits at a parent's name. weaker: RFC 7489 receivers read it and apply its policy.
    variants: [
      {
        when: "weaker",
        why: "A DMARC record must start with v=DMARC1, written exactly like that, and name each tag once. Receivers that follow RFC 9989 ignore this one. Receivers that still follow RFC 7489 accept it and apply its policy, so {domain} gets a different policy depending on the receiver.",
      },
      {
        when: "at",
        title: "The DMARC record of {at} is malformed",
        why: "A DMARC record must start with v=DMARC1, written exactly like that, and name each tag once. Receivers ignore the one at _dmarc.{at}, so it protects neither {at} nor the names under it without a record of their own, {domain} included.",
        fix: "Whoever manages {at} should put v=DMARC1 at the very start of the record at _dmarc.{at}, with DMARC1 in capital letters, and keep one copy of each tag.",
      },
    ],
    source: rfc(9989, "4.7"),
  },
  {
    id: "dmarc-invalid-policy",
    group: "dmarc",
    severity: "critical",
    impact: "spoofing",
    title: "The DMARC policy is missing or has an invalid value",
    why: "The only values p, sp and np accept are none, quarantine and reject. With a rua address receivers fall back to none, and without one they skip DMARC for {domain}.",
    fix: "Set p= to none, quarantine or reject, and check sp= and np= for typos.",
    source: rfc(9989, "4.10.1"),
  },
  {
    id: "dmarc-policy-none",
    group: "dmarc",
    severity: "critical",
    impact: "spoofing",
    guide: "/guides/dmarc/p-none-to-reject/",
    title: "DMARC does not stop mail that fakes {domain}",
    why: "The policy in force is none, so receivers get no instruction to block forged mail. Anyone can send email as {domain}.",
    fix: "Read your DMARC reports to confirm that your real mail passes, then move to p=quarantine and later to p=reject.",
    source: rfc(9989, "4.7"),
  },
  {
    id: "dmarc-policy-quarantine",
    group: "dmarc",
    severity: "warning",
    impact: "spoofing",
    guide: "/guides/dmarc/p-none-to-reject/",
    title: "DMARC is set to quarantine instead of reject",
    why: "The policy in force is quarantine, so receivers are asked to treat forged mail as suspicious, for example by putting it in the spam folder. Only p=reject, without t=y or pct, asks them to refuse it.",
    fix: "Once your reports show that your real mail passes, change p=quarantine to p=reject.",
    source: rfc(9989, "4.7"),
  },
  {
    id: "dmarc-testing-mode",
    group: "dmarc",
    severity: "warning",
    impact: "spoofing",
    guide: "/guides/dmarc/p-none-to-reject/",
    title: "DMARC is in testing mode (t=y)",
    why: "With t=y, receivers are asked to apply one level less than your policy: reject becomes quarantine, and quarantine becomes none.",
    fix: "Remove t=y, or set t=n, once your reports show that your real mail passes.",
    source: rfc(9989, "4.7"),
  },
  {
    id: "dmarc-pct",
    group: "dmarc",
    severity: "warning",
    impact: "spoofing",
    guide: "/guides/dmarc/p-none-to-reject/",
    title: "DMARC applies to only part of the mail (pct below 100)",
    why: "RFC 9989 removed pct, but receivers that still follow RFC 7489 are asked to apply your policy to the share of failing mail that pct sets, and one level less to the rest.",
    fix: "Remove the pct tag. To test a stricter policy, add t=y instead and remove it when you are ready.",
    source: {
      label: "RFC 7489 §6.6.4 (pct, removed in RFC 9989)",
      url: "https://www.rfc-editor.org/rfc/rfc7489.html#section-6.6.4",
    },
  },
  {
    id: "dmarc-subdomains-open",
    group: "dmarc",
    severity: "warning",
    impact: "spoofing",
    title: "DMARC leaves subdomains of {domain} open",
    why: "The policy for subdomains that exist is {sp}, and for subdomains that do not exist it is {np}. Where it is none, anyone can send email as a subdomain of {domain}.",
    fix: "Set sp= and np= to reject in the DMARC record of {at}.",
    // pslOrgDomain, a variant of this finding with its own text: receivers that still follow
    // RFC 7489 take the subdomains' policy from another name, the Organizational Domain the PSL
    // gives, and it leaves them open. sp and np are then RFC 9989's alone; pslMissing and
    // pslSeveral say what is at that name, and both that RFC 9989 opens them too, so the fix covers
    // both records.
    variants: [
      {
        when: "pslSeveral",
        why: "Receivers that follow RFC 9989 apply the record at _dmarc.{at} to subdomains of {domain}: its policy for subdomains that exist is {sp}, and for subdomains that do not exist it is {np}. Receivers that still follow RFC 7489 take their policy from {pslOrgDomain} instead, where they find more than one DMARC record and so apply no DMARC. Where a policy is none, or no DMARC applies, anyone can send email as a subdomain of {domain}.",
      },
      {
        when: "pslMissing",
        why: "Receivers that follow RFC 9989 apply the record at _dmarc.{at} to subdomains of {domain}: its policy for subdomains that exist is {sp}, and for subdomains that do not exist it is {np}. Receivers that still follow RFC 7489 take their policy from {pslOrgDomain} instead, where they find no DMARC record. Where a policy is none, or no DMARC applies, anyone can send email as a subdomain of {domain}.",
      },
      {
        when: "both",
        fix: "Set sp= and np= to reject in the record at _dmarc.{at}. Then set sp=reject in the DMARC record at _dmarc.{pslOrgDomain}, or ask whoever manages {pslOrgDomain} to. If there is no record there, it needs a p= tag too, which sets the policy for {pslOrgDomain} itself. If there is more than one, keep one and remove the others. sp=reject also covers the other subdomains of {pslOrgDomain}, so read their DMARC reports before you move them to reject.",
      },
      {
        when: "pslOrgDomain",
        why: "Receivers that follow RFC 9989 apply the record at _dmarc.{at} to subdomains of {domain}: its policy for subdomains that exist is {sp}, and for subdomains that do not exist it is {np}. Receivers that still follow RFC 7489 take their policy from {pslOrgDomain} instead, whose policy for them is none. Where a policy is none, or no DMARC applies, anyone can send email as a subdomain of {domain}.",
        fix: "Set sp=reject in the DMARC record at _dmarc.{pslOrgDomain}, or ask whoever manages {pslOrgDomain} to. If there is no record there, it needs a p= tag too, which sets the policy for {pslOrgDomain} itself. If there is more than one, keep one and remove the others. sp=reject also covers the other subdomains of {pslOrgDomain}, so read their DMARC reports before you move them to reject.",
      },
    ],
    source: rfc(9989, "4.7"),
  },
  {
    id: "dmarc-no-rua",
    group: "dmarc",
    severity: "warning",
    impact: "hardening",
    guide: "/guides/dmarc/aggregate-reports/",
    title: "Your DMARC record asks for no reports",
    why: "Without rua, receivers send no aggregate reports, so you cannot see who sends mail as {domain} or whether your own mail passes.",
    fix: "Add rua=mailto: followed by an address that can receive the reports, such as dmarc-reports@{domain}.",
    source: rfc(9989, "4.7"),
  },
  {
    id: "dmarc-rua-unauthorized",
    group: "dmarc",
    severity: "warning",
    impact: "hardening",
    guide: "/guides/dmarc/aggregate-reports/",
    title: "{host} has not agreed to receive reports for {domain}",
    why: "Reports to another domain arrive only if that domain accepts them for you. {host} publishes no record that does, so receivers ignore that address.",
    fix: "Ask the report service to authorize {domain} in its DNS, or send the reports to an address at {domain}.",
    source: rfc(9990, "4"),
  },
  {
    id: "dmarc-ruf",
    group: "dmarc",
    severity: "info",
    impact: "hardening",
    title: "Your DMARC record asks for failure reports (ruf)",
    why: "Failure reports can carry parts of real messages and personal data. Most receivers refuse to send them.",
    fix: "Remove ruf= unless you have a way to handle the personal data in these reports.",
    source: rfc(9989, "10.2"),
  },
  {
    id: "dmarc-tag-typo",
    group: "dmarc",
    severity: "info",
    impact: "hardening",
    title: "Your DMARC record has a tag that looks like a typo",
    why: "Receivers ignore tags they do not know, so this part of the record has no effect.",
    fix: "Write each tag as name=value and separate tags with semicolons, as in p=reject; rua=mailto:dmarc-reports@{domain}.",
    source: rfc(9989, "4.7"),
  },
  {
    id: "dmarc-org-differs",
    group: "dmarc",
    severity: "warning",
    impact: "spoofing",
    title: "Receivers may apply two different DMARC policies to {domain}",
    why: "Receivers that follow RFC 9989 take the policy from {orgDomain}, which gives {policy}. Receivers that still use the Public Suffix List take it from {pslOrgDomain}, which gives {pslPolicy}. This check counts the weaker one.",
    fix: "Publish a DMARC record of your own at _dmarc.{domain}. Both kinds of receivers then read the same policy.",
    source: { label: "RFC 9989 Appendix C.3", url: "https://www.rfc-editor.org/rfc/rfc9989.html#appendix-C.3" },
  },
];
