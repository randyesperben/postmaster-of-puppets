import { describe, expect, it } from "vitest";
import { checkTransport, validMtaSts, validTlsRpt } from "../src/checks/transport.ts";
import { fixtureResolver } from "./helpers/dns.ts";
import { ids } from "./helpers/findings.ts";
import { type Zone, zoneResolver } from "./helpers/zone.ts";

describe("transport", () => {
  it("MTA-STS record syntax (RFC 8461 §3.1)", () => {
    expect(validMtaSts("v=STSv1; id=20210803T010101;")).toBe(true);
    expect(validMtaSts("v=STSv1;id=abc")).toBe(true);
    expect(validMtaSts("v=STSv1; id=abc; ext=1")).toBe(true);
    for (const bad of [
      "v=STSv1;",
      "v=STSv1; id=",
      `v=STSv1; id=${"a".repeat(33)}`,
      "v=STSv1; id=ab-c",
      "v=STSv2; id=1",
      "id=1; v=STSv1",
      "v=STSv1; id=1; bad",
    ]) {
      expect(validMtaSts(bad), bad).toBe(false);
    }
  });

  it("TLS-RPT record syntax (RFC 8460 §3)", () => {
    expect(validTlsRpt("v=TLSRPTv1;rua=mailto:sts-reports@google.com")).toBe(true);
    expect(validTlsRpt("v=TLSRPTv1; rua=mailto:a@example.com, https://r.example.com/tls")).toBe(true);
    for (const bad of [
      "v=TLSRPTv1;",
      "v=TLSRPTv1; rua=ftp://x",
      "rua=mailto:a@example.com; v=TLSRPTv1",
      "v=TLSRPTv1; rua=a@example.com",
    ]) {
      expect(validTlsRpt(bad), bad).toBe(false);
    }
  });

  it("mta-sts-ok and TLS-RPT present, recorded from google.com", async () => {
    const r = await checkTransport({ resolver: fixtureResolver() }, "google.com");
    expect(ids(r)).toEqual(["mta-sts-ok"]);
    // MTA-STS in use (mta-sts-ok) and a valid TLS-RPT record (no tls-rpt- finding).
    expect(r.findings.some((f) => f.id.startsWith("tls-rpt-"))).toBe(false);
  });

  const t = (zone: Zone) => checkTransport({ resolver: zoneResolver(zone) }, "example.com");

  it("mta-sts-missing and tls-rpt-missing as info", async () => {
    const r = await t({});
    expect(r.findings.map((f) => `${f.id}:${f.severity}`)).toEqual(["mta-sts-missing:info", "tls-rpt-missing:info"]);
    expect(r.status).toBe("pass");
  });

  const STS = { "_mta-sts.example.com": { TXT: ["v=STSv1; id=2026111801"] } };

  it("tls-rpt-missing is a warning next to MTA-STS", async () => {
    const r = await t({ ...STS, "mta-sts.example.com": { A: ["192.0.2.10"] } });
    expect(r.findings.map((f) => `${f.id}:${f.severity}`)).toEqual(["mta-sts-ok:pass", "tls-rpt-missing:warning"]);
  });

  // RFC 8461 §3.3: a valid record whose policy cannot be fetched counts as no MTA-STS. The
  // browser cannot fetch the policy, but it can ask whether its host has an address.
  it("mta-sts-policy-unreachable: the policy host has no address", async () => {
    const r = await t(STS);
    expect(r.findings.map((f) => `${f.id}:${f.severity}`)).toEqual([
      "mta-sts-policy-unreachable:warning",
      "tls-rpt-missing:info",
    ]);
    expect(ids(r)).toContain("mta-sts-policy-unreachable");
    expect(r.findings[0]?.found).toBe("mta-sts.example.com A/AAAA");
    expect(r.findings[0]?.vars).toBeUndefined();
    // No MTA-STS in use: no mta-sts-ok, and tls-rpt-missing stays info.
    expect(ids(r)).not.toContain("mta-sts-ok");
  });

  it("mta-sts-policy-unreachable: an IPv6 address only, info for senders on IPv4", async () => {
    const r = await t({ ...STS, "mta-sts.example.com": { AAAA: ["2001:db8::10"] } });
    expect(r.findings.map((f) => `${f.id}:${f.severity}`)).toEqual([
      "mta-sts-policy-unreachable:info",
      "tls-rpt-missing:warning",
    ]);
    expect(r.findings[0]?.vars).toEqual({ ipv6Only: 1 });
    // MTA-STS in use for senders on IPv6: tls-rpt-missing is the warning that goes with it.
    expect(r.findings.find((f) => f.id === "tls-rpt-missing")?.severity).toBe("warning");
  });

  it("mta-sts-ok through a CNAME to a host with an address, and when the host lookup fails", async () => {
    const viaCname = await t({
      ...STS,
      "mta-sts.example.com": { CNAME: ["policy.example.net"] },
      "policy.example.net": { A: ["192.0.2.11"] },
    });
    expect(ids(viaCname)).toEqual(["mta-sts-ok", "tls-rpt-missing"]);
    // No answer proves nothing about the host, so nothing is claimed.
    const failed = await t({ ...STS, "mta-sts.example.com": { $unreachable: true } });
    expect(ids(failed)).toEqual(["mta-sts-ok", "tls-rpt-missing"]);
  });

  it("asks for the policy host only next to a valid record", async () => {
    const resolver = zoneResolver({ "_mta-sts.example.com": { TXT: ["v=STSv1; id=bad-id"] } });
    await checkTransport({ resolver }, "example.com");
    expect(resolver.asked.filter((q) => q.startsWith("mta-sts."))).toEqual([]);
  });

  it("mta-sts-invalid: a bad record, or two", async () => {
    expect(ids(await t({ "_mta-sts.example.com": { TXT: ["v=STSv1; id=bad-id"] } }))).toContain("mta-sts-invalid");
    expect(ids(await t({ "_mta-sts.example.com": { TXT: ["v=STSv1; id=1", "v=STSv1; id=2"] } }))).toContain(
      "mta-sts-invalid",
    );
  });

  it("tls-rpt-invalid", async () => {
    expect(ids(await t({ "_smtp._tls.example.com": { TXT: ["v=TLSRPTv1; rua=ftp://x"] } }))).toEqual([
      "mta-sts-missing",
      "tls-rpt-invalid",
    ]);
  });

  it("lookup-failed in the transport group", async () => {
    const r = await t({
      "_mta-sts.example.com": { $unreachable: true },
      "_smtp._tls.example.com": { $unreachable: true },
    });
    expect(r.findings.map((f) => `${f.id}:${f.group}`)).toEqual(["lookup-failed:transport", "lookup-failed:transport"]);
    expect(r.status).toBe("unknown");
  });
});

describe("transport, strict reading (RFC 8461 §3.1, RFC 8460 §3)", () => {
  const t = (zone: Zone) => checkTransport({ resolver: zoneResolver(zone) }, "example.com");

  it("records that do not begin with v=STSv1; or v=TLSRPTv1; are discarded", async () => {
    expect(ids(await t({ "_mta-sts.example.com": { TXT: ["v=STSv10; id=1"] } }))).toEqual([
      "mta-sts-missing",
      "tls-rpt-missing",
    ]);
    expect(ids(await t({ "_mta-sts.example.com": { TXT: ["v=STSv1 ; id=1"] } }))).toEqual([
      "mta-sts-missing",
      "tls-rpt-missing",
    ]);
    expect(ids(await t({ "_smtp._tls.example.com": { TXT: ["v=TLSRPTv10;rua=mailto:a@example.com"] } }))).toEqual([
      "mta-sts-missing",
      "tls-rpt-missing",
    ]);
  });

  it("WSP is a space or a tab, never a line break", () => {
    expect(validMtaSts("v=STSv1;\tid=1")).toBe(true);
    expect(validMtaSts("v=STSv1;\nid=1")).toBe(false);
    expect(validTlsRpt("v=TLSRPTv1;\trua=mailto:a@example.com")).toBe(true);
    expect(validTlsRpt("v=TLSRPTv1;\nrua=mailto:a@example.com")).toBe(false);
    expect(validTlsRpt("v=TLSRPTv1; rua=mailto:a@example.com,\nhttps://r.example.com/")).toBe(false);
  });

  it("TLS-RPT checks every field and every rua", () => {
    expect(validTlsRpt("v=TLSRPTv1; rua=mailto:a@example.com; ext.v1=on")).toBe(true);
    expect(validTlsRpt("v=TLSRPTv1; rua=mailto:a@example.com; rua=https://r.example.com/tls")).toBe(true);
    for (const bad of [
      "v=TLSRPTv1; rua=mailto:a@example.com; bad",
      "v=TLSRPTv1; rua=mailto:a@example.com; rua=ftp://x",
      "v=TLSRPTv1; rua=mailto:a@example.com;; x=1",
      "v=TLSRPTv1; rua=mailto:a@example.com, ftp://x",
    ]) {
      expect(validTlsRpt(bad), bad).toBe(false);
    }
  });

  // Behind broken DNSSEC a valid MTA-STS record is no policy in use, so a missing TLS-RPT record
  // stays info: the warning is for a domain whose senders apply MTA-STS.
  it("_mta-sts alone behind broken DNSSEC: tls-rpt-missing stays info", async () => {
    const r = await t({ "_mta-sts.example.com": { TXT: ["v=STSv1; id=1"], $servfail: true } });
    expect(r.findings.map((f) => `${f.id}:${f.severity}`)).toEqual(["dnssec-broken:critical", "tls-rpt-missing:info"]);
  });

  it("_mta-sts and _smtp._tls behind broken DNSSEC", async () => {
    const r = await t({
      "_mta-sts.example.com": { TXT: ["v=STSv1; id=1"], $servfail: true },
      "_smtp._tls.example.com": { TXT: ["v=TLSRPTv1; rua=mailto:a@example.com"], $servfail: true },
    });
    expect(r.findings.map((f) => `${f.id}:${f.group}`)).toEqual(["dnssec-broken:transport", "dnssec-broken:transport"]);
    expect(r.findings.map((f) => f.found)).toEqual(["_mta-sts.example.com TXT", "_smtp._tls.example.com TXT"]);
    // Neither record counts behind broken DNSSEC: no mta-sts-ok, and the group fails.
    expect(ids(r)).not.toContain("mta-sts-ok");
    expect(r.status).toBe("fail");
  });
});
