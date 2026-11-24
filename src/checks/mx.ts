// The MX check: where the domain receives mail (RFC 5321 §5.1, RFC 7505, RFC 2181 §10.3), plus the
// zone apex from the SOA, which the fixes need to write each record's host as DNS panels want it.
import { isAtOrBelow } from "../dns/names.ts";
import { ask, type Ctx, failedVars, type Lookup } from "../dns/lookup.ts";
import { finding, statusOf } from "../findings.ts";
import { isUnreachableAddress, parseIpv4 } from "../ip.ts";
import { isPublicSuffix } from "../psl.ts";
import type { Finding, GroupStatus, MxHost } from "../types.ts";

/**
 * Maximum MX hosts whose addresses are resolved; more MX records than this is far past any real
 * setup.
 */
const MAX_HOSTS = 10;

export interface MxResult {
  status: GroupStatus;
  findings: Finding[];
  hosts: MxHost[];
  /** How the MX lookup itself went: nxdomain means the domain does not exist. */
  lookup: Lookup["status"];
  nullMx: boolean;
  /** Hosts a sender can deliver to (public address, DNSSEC fine). */
  usable: number;
  /** The name is a CNAME: where it points (RFC 1034 §3.6.2). */
  alias?: string;
}

/** An MX as DNS data writes it, "<preference> <host>". */
export function parseMx(data: string): { preference: number; host: string } {
  const [pref = "0", host = "."] = data.split(" ");
  return { preference: Number(pref), host };
}

/** A target that is an address written as a name: 192.0.2.1 or [192.0.2.1]. */
export function isIpLiteral(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "");
  return parseIpv4(h) !== undefined || /^\d+$/.test(h.split(".").pop() ?? "") || h.includes(":");
}

/** The MX of the name and its hosts' addresses decide the verdict: two operators must agree. */
const CONFIRM = { confirm: true };

/** The MX question alone: the engine's probe, asked before anything else (check.ts). */
export function askMx(ctx: Ctx, domain: string): Promise<Lookup> {
  return ask(ctx, domain, "MX", CONFIRM);
}

/** Where a CNAME at the name points (RFC 1034 §3.6.2), read from the MX answer. */
export function aliasOf(l: Lookup, domain: string): string | undefined {
  const owner = domain.toLowerCase();
  const cname = l.answers.find((a) => a.type === "CNAME" && a.name.toLowerCase().replace(/\.$/, "") === owner);
  return cname ? String(cname.data).toLowerCase().replace(/\.$/, "") : undefined;
}

/** The MX group; `first` is the MX answer when the caller already asked it (askMx). */
export async function checkMx(ctx: Ctx, domain: string, first?: Lookup): Promise<MxResult> {
  const l = first ?? (await askMx(ctx, domain));
  const findings: Finding[] = [];
  // A receiver follows the alias and reads the MX and SPF of its target, as this check does.
  const alias = aliasOf(l, domain);
  if (alias)
    findings.push(
      finding("name-is-alias", { group: "mx", found: `${domain} CNAME ${alias}`, vars: { target: alias } }),
    );
  const result = (
    hosts: MxHost[],
    { nullMx = false, unknown = false, usable = 0 }: { nullMx?: boolean; unknown?: boolean; usable?: number } = {},
  ): MxResult => ({
    status: statusOf(findings, { unknown }),
    findings,
    hosts,
    lookup: l.status,
    nullMx,
    usable,
    ...(alias ? { alias } : {}),
  });

  if (l.status === "failed") {
    findings.push(finding("lookup-failed", { group: "mx", found: `${domain} MX`, vars: failedVars(l) }));
    return result([], { unknown: true });
  }
  if (l.status === "nxdomain") return result([], { unknown: true });
  if (l.status === "dnssec-broken") findings.push(finding("dnssec-broken", { group: "mx", found: `${domain} MX` }));
  if (l.records.length === 0) {
    // RFC 5321 §5.1: with no MX the domain itself is the implicit MX, so its address decides
    // whether mail can arrive at all (“the implicit MX is unusable” must be reported).
    const [a, aaaa] = await Promise.all([ask(ctx, domain, "A", CONFIRM), ask(ctx, domain, "AAAA", CONFIRM)]);
    const addresses = [...a.records, ...aaaa.records].map((r) => String(r.data));
    if (addresses.length > 0) {
      findings.push(finding("mx-missing", { found: addresses.join(" "), vars: { implicit: "address" } }));
    } else if (a.status === "failed" || aaaa.status === "failed") {
      findings.push(
        finding("lookup-failed", {
          group: "mx",
          found: `${domain} A/AAAA`,
          vars: failedVars(a.status === "failed" ? a : aaaa),
        }),
      );
      findings.push(finding("mx-missing", { vars: { implicit: "unknown" } }));
      return result([], { unknown: true });
    } else {
      findings.push(finding("mx-missing", { vars: { implicit: "none" } }));
    }
    return result([]);
  }

  const all = l.records
    .map((r) => parseMx(String(r.data)))
    .sort((a, b) => a.preference - b.preference || a.host.localeCompare(b.host));
  if (all.some((m) => m.host === ".")) {
    if (all.length === 1) {
      // RFC 7505 §3: a null MX has preference 0. Another preference still says “no mail” in
      // intent, and senders reach the same end, but the record is not the standard form.
      const preference = all[0]?.preference ?? 0;
      if (preference === 0) findings.push(finding("mx-null", { found: "0 ." }));
      else findings.push(finding("mx-null", { severity: "warning", found: `${preference} .`, vars: { preference } }));
      return result([], { nullMx: true });
    }
    findings.push(finding("mx-null-with-others", { found: all.map((m) => `${m.preference} ${m.host}`).join(", ") }));
  }

  const real = all.filter((m) => m.host !== ".");
  const targets = real.slice(0, MAX_HOSTS);
  const truncated = real.length > targets.length;
  type Problem = { id: "mx-ip-literal" | "mx-unresolvable" | "mx-private-ip" | "dnssec-broken"; found: string };
  const problems: Problem[] = [];
  const hosts = await Promise.all(
    targets.map(async ({ preference, host }): Promise<{ mx: MxHost; usable: boolean; unknown: boolean }> => {
      const mx: MxHost = { preference, host, addresses: [] };
      if (isIpLiteral(host)) {
        problems.push({ id: "mx-ip-literal", found: `${preference} ${host}` });
        return { mx, usable: false, unknown: false };
      }
      const [a, aaaa] = await Promise.all([ask(ctx, host, "A", CONFIRM), ask(ctx, host, "AAAA", CONFIRM)]);
      // RFC 2181 §10.3: the MX target must be the name that holds the address, not an alias.
      if ([a, aaaa].some((x) => x.answers.some((r) => r.type === "CNAME" && r.name === host))) {
        findings.push(finding("mx-cname", { found: host }));
      }
      mx.addresses = [...a.records, ...aaaa.records].map((r) => String(r.data));
      // A validating sender gets SERVFAIL for these addresses, so it cannot use the host.
      if (a.status === "dnssec-broken" || aaaa.status === "dnssec-broken") {
        problems.push({ id: "dnssec-broken", found: `${host} A/AAAA` });
        return { mx, usable: false, unknown: false };
      }
      if (mx.addresses.length === 0) {
        if (a.status === "failed" || aaaa.status === "failed") {
          findings.push(
            finding("lookup-failed", {
              group: "mx",
              found: `${host} A/AAAA`,
              vars: failedVars(a.status === "failed" ? a : aaaa),
            }),
          );
          return { mx, usable: false, unknown: true };
        }
        problems.push({ id: "mx-unresolvable", found: host });
        return { mx, usable: false, unknown: false };
      }
      const unreachable = mx.addresses.filter((ip) => isUnreachableAddress(ip));
      if (unreachable.length === mx.addresses.length) {
        problems.push({ id: "mx-private-ip", found: `${host} ${mx.addresses.join(" ")}` });
        return { mx, usable: false, unknown: false };
      }
      // Some senders use one address family only: an unreachable A next to a reachable AAAA leaves
      // IPv4-only senders with nowhere to deliver.
      if (unreachable.length > 0)
        findings.push(finding("mx-private-ip", { severity: "warning", found: `${host} ${unreachable.join(" ")}` }));
      return { mx, usable: true, unknown: false };
    }),
  );

  const usable = hosts.filter((h) => h.usable).length;
  const unknown = hosts.some((h) => h.unknown);
  // Every host broken means mail cannot arrive; one broken host among good ones is a warning.
  // Past MAX_HOSTS the hosts left unread may work, so the count never reaches critical.
  const severity = usable === 0 && !unknown && !truncated ? "critical" : "warning";
  for (const p of problems) findings.push(finding(p.id, { group: "mx", severity, found: p.found }));
  if (usable > 0 && !findings.some((f) => f.severity === "critical" || f.severity === "warning")) {
    findings.push(finding("mx-ok", { found: targets.map((m) => `${m.preference} ${m.host}`).join(", ") }));
  }
  return result(
    hosts.map((h) => h.mx),
    { unknown: (unknown || truncated) && usable === 0, usable },
  );
}

/**
 * The zone apex from the SOA: the answer's owner, or the owner of the SOA in authority. A name
 * with a CNAME holds no SOA, so it is never an apex (RFC 1034 §3.6.2, RFC 2181 §10.1): its zone is
 * its parent's, which is where _dmarc.<name> is written. Unknown when the lookup gets no answer,
 * when the parent is an alias too, and when the parent is a public suffix by the PSL (co.uk,
 * github.io), which is no panel the domain's owner manages. `followAlias: false` stops at the
 * parent: the walk follows one alias at most.
 */
export async function zoneApex(
  ctx: Ctx,
  domain: string,
  { followAlias = true }: { followAlias?: boolean } = {},
): Promise<string | undefined> {
  const l = await ask(ctx, domain, "SOA");
  if (l.status === "failed") return undefined;
  if (aliasOf(l, domain) !== undefined) {
    const dot = domain.indexOf(".");
    const parent = domain.slice(dot + 1);
    return followAlias && dot > 0 && (await isPublicSuffix(ctx, parent)) === false
      ? zoneApex(ctx, parent, { followAlias: false })
      : undefined;
  }
  if (l.records.length > 0) return l.records[0]?.name === domain ? domain : undefined;
  if (l.answers.some((r) => r.type === "CNAME")) return undefined;
  const soa = l.authority.find((r) => r.type === "SOA");
  return soa && isAtOrBelow(domain, soa.name) ? soa.name : undefined;
}
