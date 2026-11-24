// The DNS-over-HTTPS endpoints the client asks (doh.ts): each operator's endpoint by name, the
// endpoint by IP of those that have one, and the order operators are asked in.
import type { ResolverId } from "./types.ts";

export const RESOLVER_URLS: Readonly<Record<ResolverId, string>> = {
  cloudflare: "https://cloudflare-dns.com/dns-query",
  google: "https://dns.google/dns-query",
  // 9.9.9.10: no blocklist, DNSSEC validation. dns.quad9.net answers names on its blocklist with
  // NXDOMAIN, AD and EDE 17, a “no DMARC” that is false
  // (quad9.net/service/service-addresses-and-features, 2026-11-18).
  quad9: "https://dns10.quad9.net/dns-query",
  controld: "https://freedns.controld.com/p0",
  dns4eu: "https://unfiltered.joindns4.eu/dns-query",
  cznic: "https://odvr.nic.cz/dns-query",
};

/** Endpoints by IP need no lookup of the service's name; their certificates carry the IP. */
const IP_URLS: Readonly<Partial<Record<ResolverId, string>>> = {
  cloudflare: "https://1.1.1.1/dns-query",
  google: "https://8.8.8.8/dns-query",
  quad9: "https://9.9.9.10/dns-query",
};

/** The order operators are asked in: the first two answer every query that decides. */
export const DEFAULT_ORDER: readonly ResolverId[] = ["cloudflare", "google", "quad9", "controld", "dns4eu", "cznic"];

export interface Endpoint {
  operator: ResolverId;
  url: string;
}

/** Each operator's endpoint by name, then its endpoint by IP. */
export function endpointsFor(order: readonly ResolverId[]): Endpoint[] {
  return order.flatMap((operator) => {
    const ip = IP_URLS[operator];
    return [{ operator, url: RESOLVER_URLS[operator] }, ...(ip ? [{ operator, url: ip }] : [])];
  });
}

/**
 * Every URL the engine may fetch, endpoints by name and by IP, for a Content-Security-Policy's
 * connect-src.
 */
export const ENDPOINT_URLS: readonly string[] = endpointsFor(DEFAULT_ORDER).map((e) => e.url);
