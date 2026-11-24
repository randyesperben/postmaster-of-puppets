// The transport check: the MTA-STS TXT record (RFC 8461 §3.1) and TLS-RPT (RFC 8460 §3). The
// MTA-STS policy file itself is not fetched: most hosts send no CORS headers, so a browser could
// not read it, and the engine fetches nothing but its DNS-over-HTTPS operators.
import { ask, type Ctx, failedVars, txt } from "../dns/lookup.ts";
import { finding, statusOf } from "../findings.ts";
import type { Finding, GroupStatus } from "../types.ts";

export interface TransportResult {
  status: GroupStatus;
  findings: Finding[];
}

// Both records split their fields by *WSP ";" *WSP, WSP being a space or a tab (RFC 5234 B.1),
// and allow a final delimiter. An extension is a name and a value without "=", ";", SP or CTLs.
function fields(record: string): string[] {
  return record.replace(/[ \t]*;[ \t]*$/, "").split(/[ \t]*;[ \t]*/);
}
const EXTENSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}=[\x21-\x3a\x3c\x3e-\x7e]+$/;

// RFC 8461 §3.1: sts-version first, then fields; id is 1 to 32 letters or digits.
export function validMtaSts(record: string): boolean {
  const [version, ...rest] = fields(record);
  if (version !== "v=STSv1") return false;
  return rest.some((f) => /^id=[A-Za-z0-9]{1,32}$/.test(f)) && rest.every((f) => EXTENSION.test(f));
}

// RFC 8460 §3: tlsrpt-version first, then fields; each rua is a list of mailto: or https: URIs
// joined by *WSP "," *WSP, with commas, "!" and ";" inside a URI percent-encoded.
export function validTlsRpt(record: string): boolean {
  const [version, ...rest] = fields(record);
  if (version !== "v=TLSRPTv1") return false;
  const ruas = rest.filter((f) => f.startsWith("rua="));
  const uri = (u: string) =>
    /^mailto:[^\s@,;!]+@[^\s@,;!]+$/.test(u) || /^https:\/\/[^\s/?#,;!]+(?:[/?#][^\s,;!]*)?$/.test(u);
  return (
    ruas.length > 0 &&
    ruas.every((r) =>
      r
        .slice(4)
        .split(/[ \t]*,[ \t]*/)
        .every(uri),
    ) &&
    rest.every((f) => f.startsWith("rua=") || EXTENSION.test(f))
  );
}

/** The transport group of a check: the MTA-STS and TLS-RPT records of the domain. */
export async function checkTransport(ctx: Ctx, domain: string): Promise<TransportResult> {
  const [sts, rpt] = await Promise.all([
    ask(ctx, `_mta-sts.${domain}`, "TXT"),
    ask(ctx, `_smtp._tls.${domain}`, "TXT"),
  ]);
  const findings: Finding[] = [];
  let unknown = false;
  // A valid MTA-STS record whose policy host is not known to be missing: senders use the policy.
  let mtaSts = false;

  if (sts.status === "failed") {
    unknown = true;
    findings.push(
      finding("lookup-failed", { group: "transport", found: `_mta-sts.${domain} TXT`, vars: failedVars(sts) }),
    );
  } else {
    // A validating sender gets SERVFAIL here, so for it the domain has no policy (as in mx.ts).
    const broken = sts.status === "dnssec-broken";
    if (broken) findings.push(finding("dnssec-broken", { group: "transport", found: `_mta-sts.${domain} TXT` }));
    // RFC 8461 §3.1: records that do not begin with "v=STSv1;" are discarded; anything but
    // exactly one valid record means no policy.
    const candidates = txt(sts).filter((t) => t.startsWith("v=STSv1;"));
    if (candidates.length === 0) findings.push(finding("mta-sts-missing"));
    else if (candidates.length > 1) findings.push(finding("mta-sts-invalid", { found: candidates.join("\n") }));
    else if (!validMtaSts(candidates[0] ?? ""))
      findings.push(finding("mta-sts-invalid", { found: candidates[0] ?? "" }));
    else if (!broken) {
      // §3.3: with no policy to fetch, senders deliver as though the domain had no MTA-STS. The
      // engine does not fetch it, but it can ask whether its host has an address. A lookup that
      // fails proves nothing, so then the record alone decides.
      const host = `mta-sts.${domain}`;
      const [a, aaaa] = await Promise.all([ask(ctx, host, "A"), ask(ctx, host, "AAAA")]);
      const none = (l: typeof a) => l.status === "nodata" || l.status === "nxdomain";
      if (none(a) && none(aaaa)) findings.push(finding("mta-sts-policy-unreachable", { found: `${host} A/AAAA` }));
      else if (none(a) && aaaa.status === "ok") {
        mtaSts = true;
        findings.push(
          finding("mta-sts-policy-unreachable", { severity: "info", found: `${host} A/AAAA`, vars: { ipv6Only: 1 } }),
        );
      } else {
        mtaSts = true;
        findings.push(finding("mta-sts-ok", { found: candidates[0] ?? "" }));
      }
    }
  }

  if (rpt.status === "failed") {
    unknown = true;
    findings.push(
      finding("lookup-failed", { group: "transport", found: `_smtp._tls.${domain} TXT`, vars: failedVars(rpt) }),
    );
  } else {
    const broken = rpt.status === "dnssec-broken";
    if (broken) findings.push(finding("dnssec-broken", { group: "transport", found: `_smtp._tls.${domain} TXT` }));
    // RFC 8460 §3: records that do not begin with "v=TLSRPTv1;" are discarded.
    const candidates = txt(rpt).filter((t) => t.startsWith("v=TLSRPTv1;"));
    // With MTA-STS and no TLS-RPT nobody hears about delivery failures: a warning, not info.
    if (candidates.length === 0) findings.push(finding("tls-rpt-missing", mtaSts ? { severity: "warning" } : {}));
    else if (candidates.length > 1 || !validTlsRpt(candidates[0] ?? ""))
      findings.push(finding("tls-rpt-invalid", { found: candidates.join("\n") }));
  }
  return { status: statusOf(findings, { unknown }), findings };
}
