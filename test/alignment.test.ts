// checkAlignment(): relaxed with a subdomain of the same Organizational Domain, strict, a null
// envelope, several signatures and a lookup that failed. RFC 9989 §4.4: relaxed alignment compares
// Organizational Domains, strict compares the names.
import { describe, expect, it } from "vitest";
import { checkAlignment } from "../src/index.ts";
import { SOA } from "./helpers/check.ts";
import { type Zone, zoneResolver } from "./helpers/zone.ts";

const zone = (record: string): Zone => ({ "example.com": { SOA }, "_dmarc.example.com": { TXT: [record] } });
const run = (z: Zone, input: Parameters<typeof checkAlignment>[0]) =>
  checkAlignment(input, { resolver: zoneResolver(z) });

describe("checkAlignment", () => {
  it("relaxed: an envelope and a signature on subdomains of the same Organizational Domain align", async () => {
    const a = await run(zone("v=DMARC1; p=reject"), {
      fromDomain: "example.com",
      mailFromDomain: "bounce.example.com",
      dkimDomains: ["mail.example.com"],
    });
    expect(a).toEqual({
      adkim: "r",
      aspf: "r",
      spf: true,
      dkim: [{ d: "mail.example.com", aligned: true }],
      failed: false,
    });
  });

  it("relaxed also from a subdomain in the From: the record of the Organizational Domain applies", async () => {
    const a = await run(zone("v=DMARC1; p=reject"), {
      fromDomain: "news.example.com",
      mailFromDomain: "example.com",
      dkimDomains: ["example.com"],
    });
    expect(a).toMatchObject({ spf: true, dkim: [{ d: "example.com", aligned: true }], failed: false });
  });

  it("strict: only the same name aligns, read from adkim=s and aspf=s", async () => {
    const z = zone("v=DMARC1; p=reject; adkim=s; aspf=s");
    const sub = await run(z, {
      fromDomain: "example.com",
      mailFromDomain: "bounce.example.com",
      dkimDomains: ["mail.example.com"],
    });
    expect(sub).toEqual({
      adkim: "s",
      aspf: "s",
      spf: false,
      dkim: [{ d: "mail.example.com", aligned: false }],
      failed: false,
    });
    const same = await run(z, {
      fromDomain: "Example.COM.",
      mailFromDomain: "example.com",
      dkimDomains: ["example.com"],
    });
    expect(same).toMatchObject({ spf: true, dkim: [{ d: "example.com", aligned: true }] });
    // From a subdomain, the Organizational Domain's adkim=s applies (§4.10.1).
    const child = await run(z, { fromDomain: "news.example.com", dkimDomains: ["example.com"] });
    expect(child).toMatchObject({ adkim: "s", dkim: [{ d: "example.com", aligned: false }] });
  });

  // RFC 9989 §4.8, dmarc-rors = "r" / "s", quoted ABNF strings with no %s, so case does not matter
  // (RFC 5234 §2.3), as the engine already reads p, sp and np.
  it("strict also when written in capitals: adkim=S and aspf=S", async () => {
    const a = await run(zone("v=DMARC1; p=reject; adkim=S; aspf=S"), {
      fromDomain: "example.com",
      mailFromDomain: "bounce.example.com",
      dkimDomains: ["mail.example.com"],
    });
    expect(a).toEqual({
      adkim: "s",
      aspf: "s",
      spf: false,
      dkim: [{ d: "mail.example.com", aligned: false }],
      failed: false,
    });
  });

  it("a null envelope (MAIL FROM:<>) leaves spf out", async () => {
    const a = await run(zone("v=DMARC1; p=reject"), { fromDomain: "example.com", dkimDomains: ["example.com"] });
    expect(a).not.toHaveProperty("spf");
    expect(a.dkim).toEqual([{ d: "example.com", aligned: true }]);
  });

  it("several signatures: each one on its own, in order", async () => {
    const z: Zone = {
      ...zone("v=DMARC1; p=reject"),
      "example.net": { SOA },
      "_dmarc.example.net": { TXT: ["v=DMARC1; p=none"] },
    };
    const a = await run(z, {
      fromDomain: "example.com",
      mailFromDomain: "sender.example.net",
      dkimDomains: ["sender.example.net", "example.com", "x.example.com"],
    });
    expect(a.spf).toBe(false);
    expect(a.dkim).toEqual([
      { d: "sender.example.net", aligned: false },
      { d: "example.com", aligned: true },
      { d: "x.example.com", aligned: true },
    ]);
  });

  it("no DMARC record: relaxed by default (r), and a name aligns only with itself", async () => {
    const a = await run(
      { "example.com": { SOA } },
      { fromDomain: "example.com", mailFromDomain: "example.com", dkimDomains: ["mail.example.com"] },
    );
    expect(a).toEqual({
      adkim: "r",
      aspf: "r",
      spf: true,
      dkim: [{ d: "mail.example.com", aligned: false }],
      failed: false,
    });
  });

  it("a lookup with no answer sets failed, so the caller knows the result is incomplete", async () => {
    const z: Zone = { ...zone("v=DMARC1; p=reject"), "_dmarc.mail.example.com": { $unreachable: true } };
    const a = await run(z, { fromDomain: "example.com", dkimDomains: ["mail.example.com"] });
    expect(a.failed).toBe(true);
    const own = await run(
      { "example.com": { SOA }, "_dmarc.example.com": { $unreachable: true } },
      { fromDomain: "example.com", dkimDomains: [] },
    );
    expect(own.failed).toBe(true);
  });
});
