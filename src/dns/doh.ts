// DNS-over-HTTPS client (RFC 8484, GET with ?dns=) over six unfiltered operators that send CORS.
//
// - Operators in order, 2.5 s per attempt, at most 96 requests in flight per operator, identical
//   queries shared, cache: "no-store". An operator's endpoint by IP stands in when the one by name
//   fails (filters that block DoH often do it by resolving the service's name wrongly).
// - An endpoint is dropped after 2 failures with no answer of its own between them, counted in
//   arrival order; a timeout while it answered other queries is the name's slowness, so the query
//   moves to the next operator without dropping it.
// - Answers a working resolver gives but nobody can use (rcode other than NOERROR, NXDOMAIN and
//   SERVFAIL, a blocking EDE, TC, another content type, another question) move to the next
//   operator and drop nothing.
// - The first network failure of the pair sends one neutral query (example.com SOA, never the
//   user's domain) to every endpoint left; those that answer stay in the queue. If none answers,
//   every query fails at once and the check reports "unreachable".
// - confirm: the query goes at once to two operators and the answers are compared normalized
//   (compare.ts). Same: agreed. Different: disagree, both kept. Only one operator answers before
//   the queue runs out: unconfirmed. Never a majority.
//
// One client per check: the check's signal is bound at creation and dropped endpoints stay
// dropped. Answers are shared for the check; failures are not kept, so a query asked again goes
// out again.
import { base64url, CLASS_IN, decodeMessage, DnsFormatError, encodeQuery, RCODE, typeCode } from "./codec.ts";
import { canonicalName, normalizeName } from "./names.ts";
import { answerOf, normalize, same } from "./compare.ts";
import { DEFAULT_ORDER, type Endpoint, endpointsFor } from "./endpoints.ts";
import type { DnsResult, QueryOptions, Resolver, ResolverId } from "./types.ts";

/**
 * RFC 8914 §4.5 and §4.16-§4.19: 4 Forged Answer (“for policy reasons (legal obligation or
 * malware filtering, for instance), an answer was forged”), 15 Blocked, 16 Censored, 17 Filtered,
 * 18 Prohibited. The resolver's own policy speaks, not the domain's DNS.
 */
const BLOCKING_EDE = new Set([4, 15, 16, 17, 18]);

/**
 * RFC 8914 §4.4 and §4.20: 3 Stale Answer, 19 Stale NXDOMAIN Answer. The answer is used, but an
 * old cache never confirms the pair.
 */
const isStale = (r: DnsResult): boolean => r.ede?.some((code) => code === 3 || code === 19) === true;

/** The probe asks something every resolver can answer and that says nothing about the user. */
const PROBE = { name: "example.com", type: "SOA" };

/**
 * "unreachable": no resolver gave a usable answer; "aborted": the check was cancelled or ran out
 * of time; "bad-name": DNS cannot carry the name (an empty or 64-octet label, non-ASCII), so no
 * resolver was asked.
 */
export class LookupError extends Error {
  override name = "LookupError";
  readonly reason: "unreachable" | "aborted" | "bad-name";
  constructor(reason: "unreachable" | "aborted" | "bad-name", message: string) {
    super(message);
    this.reason = reason;
  }
}

export interface DohOptions {
  order?: readonly ResolverId[];
  fetch?: typeof fetch;
  timeoutMs?: number;
  /** Requests in flight per operator. */
  maxParallel?: number;
  maxFailures?: number;
  /** false: confirm is ignored and every query goes to one operator, as when recording fixtures. */
  crossCheck?: boolean;
  /** The whole check: aborting it ends every query in flight. */
  signal?: AbortSignal;
  onSwitch?: (from: ResolverId, to: ResolverId) => void;
  /** Every DNS message received, raw, for recording test fixtures. */
  onMessage?: (m: {
    resolver: ResolverId;
    name: string;
    type: string;
    cd: boolean;
    dnssecOk: boolean;
    bytes: Uint8Array;
  }) => void;
}

export interface DohResolver extends Resolver {
  query(name: string, type: string, opts?: QueryOptions): Promise<DnsResult>;
  /** Operators that returned at least one DNS message to a query, in the configured order. */
  responded(): ResolverId[];
  /** True once the probe found no endpoint that answers. */
  unreachable(): boolean;
}

/**
 * counts: whether the failure says the endpoint itself is not working (see fail()). gone: the
 * endpoint left the queue while the attempt waited for its turn, so nothing was sent.
 */
type Attempt = { ok: true; result: DnsResult } | { ok: false; why: string; counts: boolean; gone?: true };

interface Question {
  name: string;
  type: string;
  cd: boolean;
  dnssecOk: boolean;
  /** The ?dns= parameter, encoded once before any resolver is asked. */
  dns: string;
  /** The name as decodeMessage writes it, to check the answer's question. */
  owner: string;
}

function question(name: string, type: string, { cd, dnssecOk }: { cd: boolean; dnssecOk: boolean }): Question {
  return {
    name,
    type,
    cd,
    dnssecOk,
    dns: base64url(encodeQuery(name, type, { cd, dnssecOk })),
    owner: canonicalName(name),
  };
}

export function createDohResolver(options: DohOptions = {}): DohResolver {
  const order = [...(options.order ?? DEFAULT_ORDER)];
  const doFetch = options.fetch ?? ((input, init) => fetch(input, init));
  const timeoutMs = options.timeoutMs ?? 2500;
  const maxFailures = options.maxFailures ?? 2;
  const crossCheck = options.crossCheck !== false;
  const checkSignal = options.signal;
  /** Endpoints still in use, in order; the probe and the drop rule shrink it. */
  let queue = endpointsFor(order);
  const failures = new Map<Endpoint, number>();
  /** DNS messages received per endpoint, to tell a slow name from a dead endpoint. */
  const received = new Map<Endpoint, number>();
  const answered = new Set<ResolverId>();
  const inFlight = new Map<string, Promise<DnsResult>>();
  // 96 in flight per operator: a whole check's wave after MX (every DKIM selector, the DKIM probes,
  // _domainkey, transport, DMARC, SPF and the MX hosts; check-limits.test.ts pins its peak) goes
  // out at once, so DMARC never queues behind DKIM. It stays under the 100 concurrent HTTP/2
  // streams Google announces (Cloudflare: 256). A network that drops DoH still fails fast: the MX
  // query, the probe and the 10 s limit see it before any batch goes out.
  const slots = new Map(order.map((op) => [op, semaphore(options.maxParallel ?? 96)]));
  let probing: Promise<void> | undefined;
  let probed = false;

  function aborted(): LookupError {
    return new LookupError("aborted", "the check was cancelled");
  }

  async function attempt(e: Endpoint, q: Question, { probe = false }: { probe?: boolean } = {}): Promise<Attempt> {
    // The probe skips the per-operator limit: behind queries stuck on a dead endpoint it would
    // wait their full timeout.
    const release = probe ? () => {} : await (slots.get(e.operator) as ReturnType<typeof semaphore>).acquire();
    if (!probe) {
      // Queries that waited for a slot behind a dead endpoint wait for the probe too, and never
      // go out to an endpoint it dropped.
      await settled();
      if (!queue.includes(e)) {
        release();
        return { ok: false, why: "dropped", counts: false, gone: true };
      }
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    const onAbort = (): void => ctrl.abort();
    checkSignal?.addEventListener("abort", onAbort);
    const seenBefore = received.get(e) ?? 0;
    // Counted before the slot is released: a query waiting for it must see the probe this
    // failure starts, or it would go out to the same dead endpoint.
    const broken = (why: string, { counts }: { counts: boolean }): Attempt => {
      if (counts && !probe) fail(e);
      return { ok: false, why, counts };
    };
    try {
      if (checkSignal?.aborted) throw aborted();
      // Only a safelisted header, so the request stays "simple" and needs no preflight (dns.google
      // answers OPTIONS without CORS headers). No Referer and no credentials, so the engine leaks
      // neither, whatever Referrer-Policy the page that runs it sets; neither is a condition of a
      // CORS preflight in the Fetch standard.
      const res = await doFetch(`${e.url}?dns=${q.dns}`, {
        headers: { accept: "application/dns-message" },
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        credentials: "omit",
        signal: ctrl.signal,
      });
      if (!res.ok) return broken(`HTTP ${res.status}`, { counts: true });
      // A server that answers HTTP works; what it sent is not a DNS answer (a captive portal, a
      // filter's block page): the next operator, without dropping this one.
      if (!(res.headers.get("content-type") ?? "").includes("application/dns-message")) {
        return { ok: false, why: "not a DNS message", counts: false };
      }
      const bytes = new Uint8Array(await res.arrayBuffer());
      const msg = decodeMessage(bytes);
      // RFC 8484 §4.1: ID 0; the answer must carry the question asked, class IN.
      const asked = msg.question;
      if (
        msg.id !== 0 ||
        !asked ||
        asked.klass !== CLASS_IN ||
        asked.name !== q.owner ||
        typeCode(asked.type) !== typeCode(q.type)
      ) {
        return { ok: false, why: "answer to another question", counts: false };
      }
      // Any DNS message is an answer of the endpoint's own: its run of failures starts again.
      received.set(e, (received.get(e) ?? 0) + 1);
      failures.set(e, 0);
      if (probe)
        return { ok: true, result: { rcode: msg.rcode, ad: msg.ad, answers: [], authority: [], resolver: e.operator } };
      answered.add(e.operator);
      options.onMessage?.({ resolver: e.operator, name: q.name, type: q.type, cd: q.cd, dnssecOk: q.dnssecOk, bytes });
      // A working resolver that gives no usable answer for this name: the next operator is
      // asked, and this endpoint is not dropped. TC: the server could not get the full answer
      // (RFC 8484 §10).
      if (msg.tc) return { ok: false, why: "truncated (TC)", counts: false };
      if (msg.rcode !== RCODE.NOERROR && msg.rcode !== RCODE.NXDOMAIN && msg.rcode !== RCODE.SERVFAIL) {
        return { ok: false, why: `rcode ${msg.rcode}`, counts: false };
      }
      const blocking = msg.ede.find((code) => BLOCKING_EDE.has(code));
      if (blocking !== undefined) return { ok: false, why: `blocked by the resolver (EDE ${blocking})`, counts: false };
      const result: DnsResult = {
        rcode: msg.rcode,
        ad: msg.ad,
        answers: msg.answers,
        authority: msg.authority,
        resolver: e.operator,
      };
      if (msg.ede.length > 0) result.ede = msg.ede;
      return { ok: true, result };
    } catch (err) {
      if (checkSignal?.aborted) throw aborted();
      // A message DNS cannot read came from a server that answered: same as another content type.
      if (!ctrl.signal.aborted) return broken(String(err), { counts: !(err instanceof DnsFormatError) });
      // Timed out: if the endpoint answered other queries meanwhile, the name is slow (its
      // authoritative servers), not the endpoint.
      return broken("timed out", { counts: (received.get(e) ?? 0) === seenBefore });
    } finally {
      clearTimeout(timer);
      checkSignal?.removeEventListener("abort", onAbort);
      release();
    }
  }

  /** Runs after any change to the queue: says when the first operator in use changes. */
  function changed(before: ResolverId | undefined): void {
    const after = queue[0]?.operator;
    if (before && after && before !== after) options.onSwitch?.(before, after);
  }

  /** The two operators that answer the queries that decide. */
  function pair(): ResolverId[] {
    return [...new Set(queue.map((e) => e.operator))].slice(0, 2);
  }

  function fail(e: Endpoint): void {
    const inPair = pair().includes(e.operator);
    const n = (failures.get(e) ?? 0) + 1;
    failures.set(e, n);
    if (n >= maxFailures && queue.includes(e)) {
      const before = queue[0]?.operator;
      queue = queue.filter((x) => x !== e);
      changed(before);
    }
    if (inPair && !probed) {
      probed = true;
      probing = probe();
    }
  }

  /**
   * Rejects only when the check is cancelled, and the query whose failure started it always
   * waits for it (settled()), so the rejection never goes unhandled.
   */
  async function probe(): Promise<void> {
    const targets = [...queue];
    const q = question(PROBE.name, PROBE.type, { cd: false, dnssecOk: false });
    try {
      const results = await Promise.all(targets.map((e) => attempt(e, q, { probe: true })));
      const alive = new Set(targets.filter((_, i) => results[i]?.ok === true));
      const before = queue[0]?.operator;
      queue = queue.filter((e) => alive.has(e));
      changed(before);
    } finally {
      probing = undefined;
    }
  }

  /**
   * Resolves once no probe is running. The caller then picks from the queue with no await in
   * between, so two lanes of one query never take the same operator.
   */
  async function settled(): Promise<void> {
    while (probing) await probing;
  }

  async function single(q: Question): Promise<DnsResult> {
    let servfail: DnsResult | undefined;
    const reasons: string[] = [];
    const tried = new Set<Endpoint>();
    const done = new Set<ResolverId>();
    for (;;) {
      await settled();
      const e = queue.find((x) => !tried.has(x) && !done.has(x.operator));
      if (!e) break;
      tried.add(e);
      const a = await attempt(e, q);
      if (!a.ok) {
        if (a.gone) continue;
        reasons.push(`${e.url}: ${a.why}`);
        // A network failure leaves the operator's other endpoint to try; any other ends the
        // operator for this query.
        if (!a.counts) done.add(e.operator);
        continue;
      }
      if (a.result.rcode !== RCODE.SERVFAIL) return a.result;
      servfail ??= a.result;
      done.add(e.operator);
    }
    if (servfail) return servfail;
    throw new LookupError(
      "unreachable",
      `no resolver answered ${q.name} ${q.type} (${reasons.join("; ") || "none left"})`,
    );
  }

  async function confirmed(q: Question): Promise<DnsResult> {
    let servfail: DnsResult | undefined;
    const reasons: string[] = [];
    const tried = new Set<Endpoint>();
    /** Operators taken by one of the two lanes, so the lanes never ask the same one. */
    const claimed = new Set<ResolverId>();
    const lane = async (): Promise<DnsResult | undefined> => {
      let mine: ResolverId | undefined;
      /**
       * A stale answer: kept in case no fresh one comes, while the lane moves to the next operator.
       */
      let stale: DnsResult | undefined;
      for (;;) {
        await settled();
        const own = mine;
        const e = queue.find((x) => !tried.has(x) && (own ? x.operator === own : !claimed.has(x.operator)));
        if (!e) {
          if (mine === undefined) return stale;
          mine = undefined;
          continue;
        }
        tried.add(e);
        if (mine === undefined) {
          mine = e.operator;
          claimed.add(mine);
        }
        const a = await attempt(e, q);
        if (!a.ok) {
          if (a.gone) continue;
          reasons.push(`${e.url}: ${a.why}`);
          if (!a.counts) mine = undefined;
          continue;
        }
        if (a.result.rcode !== RCODE.SERVFAIL && !isStale(a.result)) return a.result;
        if (a.result.rcode === RCODE.SERVFAIL) servfail ??= a.result;
        else stale ??= a.result;
        mine = undefined;
      }
    };
    const [x, y] = await Promise.all([lane(), lane()]);
    if (x && y && !isStale(x) && !isStale(y)) {
      // AD counts only when both operators validated the answer: a negation of _domainkey is read
      // as “no keys” only with both signatures checked.
      if (same(normalize(q.name, q.type, answerOf(x)), normalize(q.name, q.type, answerOf(y))))
        return { ...x, ad: x.ad && y.ad, confirm: "agreed" };
      return {
        ...x,
        confirm: "disagree",
        second: { resolver: y.resolver as ResolverId, rcode: y.rcode, answers: y.answers, authority: y.authority },
      };
    }
    const one = [x, y].find((r) => r !== undefined && !isStale(r)) ?? x ?? y;
    if (one) return { ...one, confirm: "unconfirmed" };
    if (servfail) return servfail;
    throw new LookupError(
      "unreachable",
      `no resolver answered ${q.name} ${q.type} (${reasons.join("; ") || "none left"})`,
    );
  }

  function run(
    name: string,
    type: string,
    opts: { cd: boolean; dnssecOk: boolean; confirm: boolean },
  ): Promise<DnsResult> {
    let q: Question;
    try {
      q = question(name, type, opts);
    } catch (err) {
      // Never a resolver's fault: a typo in the domain's own DNS (an include with an empty label)
      // must not drop the resolvers for the rest of the check.
      return Promise.reject(
        new LookupError("bad-name", `${name} cannot be asked: ${err instanceof Error ? err.message : String(err)}`),
      );
    }
    return opts.confirm ? confirmed(q) : single(q);
  }

  return {
    query(name: string, type: string, opts: QueryOptions = {}) {
      const t = type.toUpperCase();
      const n = normalizeName(name);
      const cd = opts.cd === true;
      const dnssecOk = opts.dnssecOk === true;
      const confirm = crossCheck && opts.confirm === true;
      const key = `${n} ${t} ${cd ? 1 : 0} ${dnssecOk ? 1 : 0} ${confirm ? 1 : 0}`;
      let p = inFlight.get(key);
      if (!p) {
        const mine = run(n, t, { cd, dnssecOk, confirm });
        // A failure is not kept: the next caller asks again. The handler also keeps callers that
        // stopped waiting (their own signal) from leaving the rejection unhandled.
        mine.catch(() => {
          if (inFlight.get(key) === mine) inFlight.delete(key);
        });
        inFlight.set(key, mine);
        p = mine;
      }
      return withSignal(p, opts.signal);
    },
    responded: () => order.filter((r) => answered.has(r)),
    unreachable: () => probed && !probing && queue.length === 0,
  };
}

/** p, or a LookupError “aborted” as soon as signal aborts (also the parts of the PSL, psl.ts). */
export function withSignal<T>(p: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return p;
  if (signal.aborted) return Promise.reject(new LookupError("aborted", "the query was cancelled"));
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new LookupError("aborted", "the query was cancelled"));
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

function semaphore(max: number): { acquire(): Promise<() => void> } {
  let active = 0;
  const waiting: (() => void)[] = [];
  const release = (): void => {
    const next = waiting.shift();
    if (next) next();
    else active--;
  };
  return {
    acquire() {
      if (active < max) {
        active++;
        return Promise.resolve(release);
      }
      return new Promise((resolve) => waiting.push(() => resolve(release)));
    },
  };
}
