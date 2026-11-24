// The SPF of the Organizational Domain through full checks: with relaxed SPF alignment (RFC 9989
// §4.4) an envelope there aligns with a subdomain, so an open SPF at example.com opens
// shop.example.com.
import { describe, expect, it } from "vitest";
import type { Finding, Report } from "../src/types.ts";
import { bad, check, DKIM, googleZone, P4, RUA, SOA, stepThrough } from "./helpers/check.ts";
import { ids } from "./helpers/findings.ts";
import type { Node, Zone } from "./helpers/zone.ts";

describe("SPF open at the Organizational Domain, with relaxed SPF alignment", () => {
  // shop.example.com sends through Google and has an SPF of its own; example.com applies DMARC to
  // it.
  const orgZone = (orgSpf: string, dmarc = `v=DMARC1; p=reject; rua=mailto:${RUA}`): Zone => ({
    "example.com": { SOA, TXT: [orgSpf] },
    "_dmarc.example.com": { TXT: [dmarc] },
    "shop.example.com": { MX: ["1 smtp.google.com"], TXT: ["v=spf1 include:_spf.google.com -all"] },
    "smtp.google.com": { A: [P4] },
    "_spf.google.com": { TXT: ["v=spf1 ip4:192.0.32.0/24 ~all"] },
    "google._domainkey.shop.example.com": { TXT: [DKIM] },
  });
  const shop = (z: Zone) => check(z, "shop.example.com");

  it("example.com with +all and p=reject makes shop.example.com Spoofable, with vars.org", async () => {
    const r = await shop(orgZone("v=spf1 +all"));
    expect(r.verdict).toBe("spoofable");
    const open = r.findings.find((f) => f.id === "spf-plus-all");
    expect(open?.vars?.org).toBe("example.com");
    expect(open?.found).toBe("+all");
    expect(r.groups.spf).toBe("fail");
    // The parent's SPF says nothing about this name's own mail.
    expect([r.mailUse, r.delivery]).toEqual(["mail", "ok"]);
    const range = await shop(orgZone("v=spf1 ip4:0.0.0.0/0 include:_spf.google.com ~all"));
    expect(range.verdict).toBe("spoofable");
    expect(range.findings.find((f) => f.id === "spf-open-range")?.vars?.org).toBe("example.com");
  });

  it("aspf=s stays Protected: the envelope must be the name itself", async () => {
    const r = await shop(orgZone("v=spf1 +all", `v=DMARC1; p=reject; aspf=s; rua=mailto:${RUA}`));
    expect(r.verdict).toBe("protected");
    expect(ids(r)).not.toContain("spf-plus-all");
  });

  it("the Organizational Domain itself: its SPF is read once, without vars.org", async () => {
    const z = googleZone();
    (z["example.com"] as Node).TXT = ["v=spf1 +all"];
    const r = await check(z);
    expect(r.findings.filter((f) => f.id === "spf-plus-all").map((f) => f.vars?.org)).toEqual([undefined]);
  });

  it("the Organizational Domain's SPF unanswered: Can't tell with reject, Spoofable anyway with none", async () => {
    const z = orgZone("v=spf1 -all");
    (z["example.com"] as Node).$unreachable = true;
    const r = await shop(z);
    expect(r.verdict).toBe("cant-tell");
    expect(r.findings.find((f) => f.id === "lookup-failed" && f.group === "spf")?.vars?.name).toBe("example.com");
    expect([r.mailUse, r.delivery]).toEqual(["mail", "ok"]);
    (z["_dmarc.example.com"] as Node).TXT = [`v=DMARC1; p=none; rua=mailto:${RUA}`];
    expect((await shop(z)).verdict).toBe("spoofable");
  });

  it("the fix goes on the Organizational Domain's own record, and none when it would authorize no one", async () => {
    const z = orgZone("v=spf1 include:_spf.google.com +all");
    const r = await shop(z);
    const f = r.findings.find((x) => x.id === "spf-plus-all") as Finding;
    expect(f.fixes.map((x) => [x.action, x.name, x.host, x.value, x.replaces])).toEqual([
      ["replace", "example.com", "@", "v=spf1 include:_spf.google.com ~all", "v=spf1 include:_spf.google.com +all"],
    ]);
    const [after] = await stepThrough(z, f, "shop.example.com");
    expect(after?.verdict).toBe("protected");
    expect(bad(after as Report)).toEqual([]);
    const only = await shop(orgZone("v=spf1 +all"));
    expect(only.findings.flatMap((x) => x.fixes)).toEqual([]);
  });

  it("each record keeps its own fix when the name and its Organizational Domain both need one", async () => {
    const z = orgZone("v=spf1 include:_spf.google.com +all");
    (z["shop.example.com"] as Node).TXT = ["v=spf1 include:_spf.google.com ?all"];
    const r = await shop(z);
    const fixOf = (id: string) => r.findings.find((x) => x.id === id)?.fixes.map((x) => [x.name, x.value]);
    expect(fixOf("spf-plus-all")).toEqual([["example.com", "v=spf1 include:_spf.google.com ~all"]]);
    expect(fixOf("spf-neutral-all")).toEqual([["shop.example.com", "v=spf1 include:_spf.google.com ~all"]]);
  });

  // shop.example.com with a record of its own under example.com, whose SPF is +all. With aspf=r an
  // envelope at example.com aligns whenever example.com is the Organizational Domain: for RFC 9989
  // when _dmarc.example.com has a record (§4.10.2), for RFC 7489 by the Public Suffix List (§3.2).
  describe("a name with a record of its own under an open parent", () => {
    const own = (record: string, parent?: Node): Zone => {
      const z = orgZone("v=spf1 +all");
      delete z["_dmarc.example.com"];
      if (parent) z["_dmarc.example.com"] = parent;
      z["_dmarc.shop.example.com"] = { TXT: [`${record}; rua=mailto:${RUA}`] };
      return z;
    };
    const lost = { $unreachable: true } as Node;

    // The parent's _dmarc without an answer counts unless p=none (Spoofable either way) or aspf=s
    // (the parent never aligns).
    it("p=quarantine and p=reject; t=y with the parent's _dmarc unanswered: Can't tell", async () => {
      for (const record of ["v=DMARC1; p=quarantine", "v=DMARC1; p=reject; t=y"]) {
        const r = await shop(own(record, lost));
        expect(r.verdict, record).toBe("cant-tell");
        expect(r.simulation, record).toBeUndefined();
      }
    });

    it("aspf=s control: the parent's _dmarc does not count below reject", async () => {
      for (const record of ["v=DMARC1; p=quarantine; aspf=s", "v=DMARC1; p=reject; t=y; aspf=s"]) {
        expect((await shop(own(record, lost))).verdict, record).toBe("partly-protected");
      }
      expect((await shop(own("v=DMARC1; p=reject; aspf=s", lost))).verdict).toBe("cant-tell");
    });

    // With no _dmarc.example.com, RFC 9989 makes shop its own Organizational Domain, RFC 7489 still
    // takes example.com from the list, and the weaker reading decides.
    // The RFC 7489 one is the Organizational Domain the list gives.
    it("p=reject or p=quarantine, no record at the parent: +all at the RFC 7489 one makes it Spoofable", async () => {
      for (const record of ["v=DMARC1; p=reject", "v=DMARC1; p=quarantine"]) {
        const r = await shop(own(record));
        expect(r.verdict, record).toBe("spoofable");
        expect(r.findings.find((f) => f.id === "spf-plus-all")?.vars?.org, record).toBe("example.com");
        expect(r.simulation?.reason, record).toBe("open-spf");
      }
    });

    it("aspf=s control: the parent's SPF is not read", async () => {
      const r = await shop(own("v=DMARC1; p=reject; aspf=s"));
      expect(ids(r)).not.toContain("spf-plus-all");
      expect(r.verdict).toBe("partly-protected");
    });
  });
});
