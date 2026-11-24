// The catalog's MTA-STS and TLS-RPT entries, joined with the other groups by index.ts in order.
import { rfc } from "./source.ts";
import type { CatalogEntry } from "../types.ts";

export const transportEntries: readonly CatalogEntry[] = [
  {
    id: "mta-sts-ok",
    group: "transport",
    severity: "pass",
    impact: "hardening",
    title: "{domain} publishes an MTA-STS record",
    why: "Senders that support MTA-STS find your record and fetch your policy, which can require encrypted delivery to your mail servers.",
    fix: "",
    source: rfc(8461, "3.1"),
  },
  {
    id: "mta-sts-missing",
    group: "transport",
    severity: "info",
    impact: "hardening",
    title: "{domain} has no MTA-STS record",
    why: "Without MTA-STS, an attacker on the network path can strip encryption from mail sent to {domain}, and senders will deliver it unencrypted.",
    fix: "Publish a policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt and a TXT record at _mta-sts.{domain} with v=STSv1 and an id. Start with mode: testing.",
    source: rfc(8461, "3"),
  },
  {
    id: "mta-sts-invalid",
    group: "transport",
    severity: "warning",
    impact: "hardening",
    title: "The MTA-STS record of {domain} is invalid",
    why: "Senders ignore an MTA-STS record that is malformed or has a second copy, so your policy is never used.",
    fix: "Keep one TXT record at _mta-sts.{domain} in the form v=STSv1; id=20260101, and change the id each time you change the policy file.",
    source: rfc(8461, "3.1"),
  },
  {
    // The policy host has no address, so no sender can fetch the policy; ipv6Only: senders on
    // IPv4 alone cannot.
    id: "mta-sts-policy-unreachable",
    group: "transport",
    severity: "warning",
    impact: "hardening",
    title: "Senders cannot fetch the MTA-STS policy of {domain}",
    // A sender with a cached policy keeps applying it (RFC 8461 §3.3), and §8.3 retires MTA-STS
    // with a mode none policy first.
    why: "Your TXT record at _mta-sts.{domain} announces a policy, but the host mta-sts.{domain} has no address. Senders that have not stored your policy before cannot download it, so they deliver to {domain} as if it had no MTA-STS. Senders that stored it keep applying it until its max_age runs out.",
    fix: "Point mta-sts.{domain} to a web server that serves your policy at https://mta-sts.{domain}/.well-known/mta-sts.txt with a valid certificate for that name. If you no longer use MTA-STS, serve a policy with mode: none and a short max_age there first, and change the id in your TXT record. Remove the TXT record at _mta-sts.{domain} once the old policy’s max_age has passed.",
    variants: [
      {
        when: "ipv6Only",
        title: "Senders without IPv6 cannot fetch the MTA-STS policy of {domain}",
        why: "The host mta-sts.{domain} has an IPv6 address and no IPv4 address. Senders that only use IPv4 and have not stored your policy before cannot download it, so they deliver to {domain} as if it had no MTA-STS. Senders that stored it keep applying it until its max_age runs out.",
        fix: "Add an A record with an IPv4 address for mta-sts.{domain}, or ask whoever hosts your policy file for one.",
      },
    ],
    source: rfc(8461, "3.3"),
  },
  {
    id: "tls-rpt-missing",
    group: "transport",
    severity: "info",
    impact: "hardening",
    title: "{domain} has no TLS-RPT record",
    why: "Without TLS-RPT, senders do not tell you when they fail to deliver to {domain} over an encrypted connection. If you use MTA-STS, those failures go unnoticed.",
    fix: "Publish a TXT record at _smtp._tls.{domain} with v=TLSRPTv1 and rua=mailto: followed by an address for the reports.",
    source: rfc(8460, "3"),
  },
  {
    id: "tls-rpt-invalid",
    group: "transport",
    severity: "warning",
    impact: "hardening",
    title: "The TLS-RPT record of {domain} is invalid",
    why: "It is malformed, has no valid rua, or sits next to a second copy, so senders may send you no reports.",
    fix: "Keep one TXT record at _smtp._tls.{domain} in the form v=TLSRPTv1; rua=mailto:tls-reports@{domain}.",
    source: rfc(8460, "3"),
  },
];
