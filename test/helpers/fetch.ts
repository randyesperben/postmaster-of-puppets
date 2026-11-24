// A fake fetch for the DoH client: every endpoint of dns/endpoints.ts (six operators, three of them
// also by IP) behaves as a test tells it, and every request is logged. Answers come from a default
// TXT, from a zone per operator (helpers/zone.ts), or from recorded bytes.
import { typeName } from "../../src/dns/codec.ts";
import { DEFAULT_ORDER, endpointsFor } from "../../src/dns/endpoints.ts";
import type { ResolverId } from "../../src/dns/types.ts";
import { buildMessage, dnsResponse, parseQueryUrl, recordedBy } from "./dns.ts";
import { type Zone, zoneAnswer, type ZoneOptions } from "./zone.ts";

/** Host of each endpoint: its operator and whether it is the endpoint by IP. */
export const ENDPOINTS: ReadonlyMap<string, { op: ResolverId; ip: boolean }> = new Map(
  endpointsFor(DEFAULT_ORDER).map((e) => {
    const host = new URL(e.url).hostname;
    return [host, { op: e.operator, ip: /^[\d.]+$/.test(host) }];
  }),
);

export type Behavior =
  | "answer"
  | "servfail"
  | "http500"
  | "http429"
  | "html"
  | "mute"
  | "network"
  | "wrong-question"
  | "tc"
  | "no-question"
  | "wrong-id"
  | "wrong-class"
  | `rcode-${number}`
  | `filtered-${number}`;

/**
 * A behavior, or a function of n (the endpoint's own requests so far, the probe left out: the
 * probe calls it with n = 0), the name and the type.
 */
export type Rule = Behavior | ((n: number, name: string, type: string) => Behavior);

/** An operator's rule covers both its endpoints; "<operator>-ip" overrides the one by IP. */
export type Rules = Partial<Record<ResolverId | `${ResolverId}-ip`, Rule>>;

/** The same rule on every operator. */
export const all = (b: Behavior): Rules => Object.fromEntries(DEFAULT_ORDER.map((op) => [op, b]));

/**
 * What "answer" sends: recorded bytes or a zone's answer, per operator; undefined for the default
 * TXT.
 */
export type Answerer = (
  op: ResolverId,
  name: string,
  type: string,
  flags: { cd: boolean; dnssecOk: boolean },
) => Uint8Array | "unreachable" | undefined;

/**
 * Each operator's recorded answer; a name the recorder did not save answers NOERROR with no
 * records.
 */
export const recordedOrEmpty: Answerer = (op, name, type, flags) =>
  recordedBy(op, name, type, flags) ?? buildMessage({ qname: name, qtype: type });

export interface Call {
  resolver: ResolverId;
  ip: boolean;
  host: string;
  name: string;
  type: string;
  cd: boolean;
  dnssecOk: boolean;
  /** The relay probe, which finds the endpoints that still answer when a network blocks DoH. */
  probe: boolean;
  init: RequestInit | undefined;
  url: string;
}

export const isProbe = (name: string, type: string): boolean => name === "example.com" && type === "SOA";

/** Zones per operator: `base` for all, with the operator's own changes on top. */
export function zones(
  base: Zone,
  perOperator: Partial<Record<ResolverId, Zone>> = {},
  options: ZoneOptions = {},
): Answerer {
  return (op, name, type, flags) => {
    if (isProbe(name, type) && !base["example.com"]) return undefined;
    return zoneAnswer({ ...base, ...(perOperator[op] ?? {}) }, name, type, flags, options);
  };
}

export function fakeFetch(rules: Rules = {}, answer?: Answerer) {
  const calls: Call[] = [];
  let active = 0;
  let peak = 0;
  const activeBy = new Map<ResolverId, number>();
  const peakBy = new Map<ResolverId, number>();
  const count = new Map<string, number>();
  const fn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const q = parseQueryUrl(url);
    const endpoint = ENDPOINTS.get(q.host);
    if (!endpoint) throw new Error(`fetch to an endpoint off the list: ${q.host}`);
    const { op, ip } = endpoint;
    const type = typeName(q.type);
    const probe = isProbe(q.name, type);
    calls.push({
      resolver: op,
      ip,
      host: q.host,
      name: q.name,
      type,
      cd: q.cd,
      dnssecOk: q.dnssecOk,
      probe,
      init,
      url,
    });
    const n = probe ? 0 : (count.get(q.host) ?? 0) + 1;
    if (!probe) count.set(q.host, n);
    const rule = (ip ? rules[`${op}-ip`] : undefined) ?? rules[op] ?? "answer";
    const mode = typeof rule === "function" ? rule(n, q.name, type) : rule;
    active++;
    peak = Math.max(peak, active);
    activeBy.set(op, (activeBy.get(op) ?? 0) + 1);
    peakBy.set(op, Math.max(peakBy.get(op) ?? 0, activeBy.get(op) ?? 0));
    try {
      await new Promise((r) => setTimeout(r, 1));
      // A real fetch rejects once its signal aborts, also when that happened before it could
      // listen; an "abort" event never fires twice.
      if (init?.signal?.aborted) throw new DOMException("aborted", "AbortError");
      switch (mode) {
        case "mute":
          return await new Promise<Response>((_, reject) => {
            init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
          });
        case "network":
          throw new TypeError("Failed to fetch");
        case "http500":
          return new Response("oops", { status: 500 });
        case "http429":
          return new Response("slow down", { status: 429 });
        case "html":
          return new Response("<html>", { status: 200, headers: { "content-type": "text/html" } });
        case "servfail":
          return dnsResponse(buildMessage({ qname: q.name, qtype: type, rcode: 2, ede: [9] }));
        case "wrong-question":
          return dnsResponse(buildMessage({ qname: `other.${q.name}`, qtype: type }));
        case "tc":
          return dnsResponse(buildMessage({ qname: q.name, qtype: type, tc: true }));
        case "no-question":
          return dnsResponse(buildMessage({ qname: q.name, qtype: type, noQuestion: true }));
        case "wrong-id":
          return dnsResponse(buildMessage({ qname: q.name, qtype: type, id: 4242 }));
        case "wrong-class":
          return dnsResponse(buildMessage({ qname: q.name, qtype: type, qclass: 3 }));
        default: {
          if (mode.startsWith("rcode-"))
            return dnsResponse(buildMessage({ qname: q.name, qtype: type, rcode: Number(mode.slice(6)) }));
          // A filtering resolver: NXDOMAIN with AD and a blocking EDE, as dns.quad9.net answers
          // names on its blocklist.
          if (mode.startsWith("filtered-"))
            return dnsResponse(
              buildMessage({ qname: q.name, qtype: type, rcode: 3, ad: true, ede: [Number(mode.slice(9))] }),
            );
          const bytes = answer?.(op, q.name, type, { cd: q.cd, dnssecOk: q.dnssecOk });
          if (bytes === "unreachable") throw new TypeError("Failed to fetch");
          if (bytes) return dnsResponse(bytes);
          return dnsResponse(
            buildMessage({
              qname: q.name,
              qtype: type,
              ad: true,
              answers: [{ name: q.name, type: "TXT", data: [`from ${op}`] }],
            }),
          );
        }
      }
    } finally {
      active--;
      activeBy.set(op, (activeBy.get(op) ?? 1) - 1);
    }
  }) as typeof fetch;
  return {
    fn,
    calls,
    /** Requests other than the relay probe. */
    queries: () => calls.filter((c) => !c.probe),
    peak: () => peak,
    peakOf: (op: ResolverId) => peakBy.get(op) ?? 0,
  };
}
