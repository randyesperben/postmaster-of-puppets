// The six DNS-over-HTTPS operators the engine asks, with each one's endpoint and privacy policy.
// Order and endpoints come from dns/endpoints.ts, so the list cannot drift from the operators the
// engine queries. Every policy URL answered 200 with no redirect (curl -A 'Mozilla/5.0',
// 2026-11-18); CZ.NIC publishes its ODVR privacy notes on the service page.
import { DEFAULT_ORDER, RESOLVER_URLS } from "./dns/endpoints.ts";
import type { ResolverId } from "./dns/types.ts";

const ABOUT: Readonly<Record<ResolverId, { name: string; privacy: string }>> = {
  cloudflare: { name: "Cloudflare", privacy: "https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/" },
  google: { name: "Google", privacy: "https://developers.google.com/speed/public-dns/privacy" },
  quad9: { name: "Quad9", privacy: "https://quad9.net/privacy/policy/" },
  controld: { name: "Control D", privacy: "https://controld.com/privacy" },
  dns4eu: { name: "DNS4EU", privacy: "https://joindns4.eu/privacy-policy" },
  cznic: { name: "CZ.NIC", privacy: "https://www.nic.cz/en/domains/tools/odvr/" },
};

/** A DNS-over-HTTPS operator the engine asks. */
export interface Operator {
  readonly id: ResolverId;
  /** The operator's name as a person knows it. */
  readonly name: string;
  /** Its endpoint by name; the endpoints by IP are in ENDPOINT_URLS. */
  readonly url: string;
  /** Its privacy policy. */
  readonly privacy: string;
}

/**
 * The DNS-over-HTTPS operators the engine asks, in its default order. Cloudflare, Google and
 * Quad9 also have an endpoint by IP that the engine falls back to: a Content-Security-Policy
 * takes ENDPOINT_URLS, which holds both.
 */
export const operators: readonly Operator[] = DEFAULT_ORDER.map((id) => ({
  id,
  name: ABOUT[id].name,
  url: RESOLVER_URLS[id],
  privacy: ABOUT[id].privacy,
}));
