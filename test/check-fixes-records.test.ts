// The records the fixes write, through full checks: DKIM records rewritten, the reason a lookup
// failed, and the host of a fix when the zone apex is not the checked name. A zone goes through
// checkDomain, and each fix is applied back to it.
import { describe, expect, it } from "vitest";
import { HOST_HINT, HOST_HINT_NO_ZONE } from "../src/fix-text.ts";
import { checkDomain, fixesAsText } from "../src/index.ts";
import type { Fix, Report } from "../src/types.ts";
import { applyFix, check, googleZone, input, P4, RSA2048, RUA, SOA } from "./helpers/check.ts";
import { ids } from "./helpers/findings.ts";
import { allFixes, failing } from "./helpers/fixes.ts";
import type { Node, Zone } from "./helpers/zone.ts";

describe("DKIM records the fixes rewrite", () => {
  it("k=RSA and h=SHA256: replaced by the same record in lower case (RFC 6376 §3.2)", async () => {
    const zone = googleZone();
    const upper = `v=DKIM1; k=RSA; h=SHA256; p=${RSA2048}`;
    zone["google._domainkey.example.com"] = { TXT: [upper] };
    const r = await check(zone);
    const f = r.findings.find((x) => x.id === "dkim-invalid-record");
    expect(f?.vars?.reason).toBe("case");
    expect(f?.fixes).toEqual([
      {
        action: "replace",
        type: "TXT",
        host: "google._domainkey",
        name: "google._domainkey.example.com",
        value: `v=DKIM1; k=rsa; h=sha256; p=${RSA2048}`,
        replaces: upper,
      },
    ]);
    const after = await check(applyFix(zone, f?.fixes[0] as Fix));
    expect(ids(after)).not.toContain("dkim-invalid-record");
    expect(after.delivery).toBe("ok");
  });

  it("a broken *._domainkey wildcard on a domain without mail is replaced, never doubled", async () => {
    const zone: Zone = {
      "example.com": { SOA, MX: ["0 ."], TXT: ["v=spf1 -all"] },
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
      "*._domainkey.example.com": { TXT: ["v=DKIM1; p=not-base64!"] },
    };
    const r = await check(zone);
    expect(r.mailUse).toBe("none-declared");
    const wild = allFixes(r).filter((f) => f.name === "*._domainkey.example.com");
    expect(wild).toEqual([
      {
        action: "replace",
        type: "TXT",
        host: "*._domainkey",
        name: "*._domainkey.example.com",
        value: "v=DKIM1; p=",
        replaces: "v=DKIM1; p=not-base64!",
      },
    ]);
    let z = zone;
    for (const fix of wild) z = applyFix(z, fix);
    expect((z["*._domainkey.example.com"] as Node).TXT).toEqual(["v=DKIM1; p="]);
  });
});

describe("lookup-failed carries its reason in the DKIM and transport groups", () => {
  it("DKIM and transport lookups with no answer say why", async () => {
    const zone = googleZone();
    delete zone["google._domainkey.example.com"];
    const unanswered = ["_mta-sts.example.com TXT", "_smtp._tls.example.com TXT", "google._domainkey.example.com TXT"];
    const r = await checkDomain(input(), { resolver: failing(zone, unanswered) });
    const failed = r.findings.filter(
      (x) => x.id === "lookup-failed" && (x.group === "dkim" || x.group === "transport"),
    );
    expect(failed.map((f) => f.vars)).toEqual([
      { reason: "no-answer", name: "google._domainkey.example.com" },
      { reason: "no-answer", name: "_mta-sts.example.com" },
      { reason: "no-answer", name: "_smtp._tls.example.com" },
    ]);
  });
});

describe("the host of a fix when the zone apex is not the checked name", () => {
  // A host typed into example.com's panel lands at <host>.example.com: “_dmarc” for
  // _dmarc.shop.example.com would write a second DMARC record next to example.com's own.
  const parent = (shop: Node): Zone => ({
    "example.com": { SOA, MX: ["10 mx.example.com"], TXT: ["v=spf1 -all"] },
    "mx.example.com": { A: [P4] },
    "shop.example.com": shop,
    "host.example.net": { SOA },
    "shops.host.example.net": { A: [P4], TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
    "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; sp=none; rua=mailto:${RUA}`] },
  });
  const dmarcFixes = (r: Report) => allFixes(r).filter((f) => f.name === "_dmarc.shop.example.com");

  // RFC 1034 §3.6.2.
  it("a subdomain that is an alias: the zone is its parent's, as a CNAME is never a zone apex", async () => {
    const r = await check(parent({ CNAME: ["shops.host.example.net"] }), "shop.example.com");
    expect(r.zone).toBe("example.com");
    expect(dmarcFixes(r).length).toBeGreaterThan(0);
    for (const f of dmarcFixes(r)) expect(f.host).toBe("_dmarc.shop");
  });

  it("the SOA lookup unanswered: no zone, and the host is the full name, never one relative to a guess", async () => {
    const zone = parent({ A: [P4], MX: ["10 mx.example.com"], TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] });
    const r = await checkDomain(input("shop.example.com"), { resolver: failing(zone, ["shop.example.com SOA"]) });
    expect(r.zone).toBeUndefined();
    expect(dmarcFixes(r).length).toBeGreaterThan(0);
    for (const f of allFixes(r)) expect(f.host).toBe(f.name);
    // fixesAsText says why the host is the full name (HOST_HINT_NO_ZONE) instead of HOST_HINT.
    expect(fixesAsText(r)).toContain(`\n${HOST_HINT_NO_ZONE}\n`);
    expect(fixesAsText(r)).not.toContain(HOST_HINT);
    const known = await check(zone, "shop.example.com");
    expect(fixesAsText(known)).toContain(`\n${HOST_HINT}\n`);
    expect(fixesAsText(known)).not.toContain(HOST_HINT_NO_ZONE);
  });

  it("an alias whose parent is an alias too: no zone, full names", async () => {
    const zone: Zone = {
      "example.com": { SOA },
      "a.example.com": { CNAME: ["shops.host.example.net"] },
      "shop.a.example.com": { CNAME: ["shops.host.example.net"] },
      "host.example.net": { SOA },
      "shops.host.example.net": { A: [P4], TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
    };
    const r = await check(zone, "shop.a.example.com");
    expect(r.zone).toBeUndefined();
    for (const f of allFixes(r)) expect(f.host).toBe(f.name);
  });
});
