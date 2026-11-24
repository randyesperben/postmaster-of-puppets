import { describe, expect, it } from "vitest";
import { checkDmarc } from "../src/checks/dmarc.ts";
import { isDmarcVersion, parseTags, ruaHosts } from "../src/checks/dmarc-tags.ts";
import { orgDomainOf, treeWalk, walkNames } from "../src/checks/dmarc-walk.ts";
import { dmarc, run } from "./helpers/dmarc.ts";
import { ids } from "./helpers/findings.ts";
import { type Zone, zoneResolver } from "./helpers/zone.ts";

// A valid name of 247 to 253 octets makes _dmarc.<name> longer than DNS can carry (253 octets in
// text, RFC 1035 §2.3.4), so no record can exist there: the walk goes on to the names above
// instead of failing the lookup and giving Can't tell.
describe("a name too long for a record of its own", () => {
  it("_dmarc.<name> past 253 octets is no record, and the policy comes from above", async () => {
    const domain = `${"a".repeat(60)}.${"b".repeat(60)}.${"c".repeat(60)}.${"d".repeat(55)}.example.com`;
    expect(domain.length).toBe(250);
    const r = await run(dmarc("v=DMARC1; p=reject; sp=reject"), domain);
    expect(r.failed).toBeFalsy();
    expect(ids(r)).not.toContain("lookup-failed");
    expect(r.foundAt).toBe("example.com");
  });
});

describe("record format (RFC 9989 §4.7, §4.8)", () => {
  it("v=DMARC1 first, the value case-sensitive", () => {
    expect(isDmarcVersion("v=DMARC1; p=reject")).toBe(true);
    expect(isDmarcVersion("v = DMARC1 ;p=none")).toBe(true);
    // Tag names are case-sensitive (RFC 6376 §3.2 via RFC 9989 §4.7), so V= is no v=.
    expect(isDmarcVersion("V=DMARC1")).toBe(false);
    expect(isDmarcVersion("v=dmarc1; p=reject")).toBe(false);
    expect(isDmarcVersion("p=reject; v=DMARC1")).toBe(false);
    expect(isDmarcVersion("v=DMARC10; p=reject")).toBe(false);
  });

  it("reads tags with spaces around =, case-sensitive tag names, and spots typos", () => {
    const { tags, typos, repeated } = parseTags(
      "v=DMARC1; P = Reject ; p = none ; rua:mailto:a@example.com; rau=mailto:b@example.com; xyz=bar; ;",
    );
    // RFC 6376 §3.2: “Tags MUST be interpreted in a case-sensitive manner”, so P is not p.
    expect(tags).toEqual({ v: "DMARC1", p: "none" });
    expect(typos).toEqual(["P = Reject", "rua:mailto:a@example.com", "rau=mailto:b@example.com"]);
    expect(repeated).toBeUndefined();
  });

  it("a repeated tag makes the whole tag-list invalid (RFC 6376 §3.2 via RFC 9989 §4.7)", () => {
    expect(parseTags("v=DMARC1; p=reject; p=none").repeated).toBe("p");
    expect(parseTags("v=DMARC1; p=reject; foo=1; foo=2").repeated).toBe("foo");
    expect(parseTags("v=DMARC1; p=reject; P=none").repeated).toBeUndefined();
  });

  it("V=DMARC1 is not the version tag for a strict receiver", () => {
    expect(parseTags("V=DMARC1; p=reject").tags).toEqual({ p: "reject" });
  });

  it("no typo for short unknown tags, bare words, or digits and _ in tag names", () => {
    const { tags, typos } = parseTags(
      "v=DMARC1; p=reject; s=x; ro=1; f=1; reject; x_1=a; ab9=b; aspff=r; p2=quarantine",
    );
    expect(tags).toEqual({ v: "DMARC1", p: "reject" });
    expect(typos).toEqual(["aspff=r"]);
    expect(parseTags("v=DMARC1; p:reject; sp reject").typos).toEqual(["p:reject", "sp reject"]);
  });

  it("reads report URIs, mailto and https, without the obsolete size suffix", () => {
    expect(
      ruaHosts(
        "mailto:a@Example.COM, mailto:b@vendor.example.net!10m , https://r.example.org/x, ftp://x, mailto:nohost",
      ),
    ).toEqual([
      { uri: "mailto:a@Example.COM", host: "example.com" },
      { uri: "mailto:b@vendor.example.net", host: "vendor.example.net" },
      { uri: "https://r.example.org/x", host: "r.example.org" },
    ]);
    expect(ruaHosts(undefined)).toEqual([]);
  });
});

describe("Tree Walk (§4.10)", () => {
  it("queries at most eight names, jumping to seven labels first", () => {
    expect(walkNames("a.b.c.d.e.f.g.h.i.j.mail.example.com")).toEqual([
      "a.b.c.d.e.f.g.h.i.j.mail.example.com",
      "g.h.i.j.mail.example.com",
      "h.i.j.mail.example.com",
      "i.j.mail.example.com",
      "j.mail.example.com",
      "mail.example.com",
      "example.com",
      "com",
    ]);
    expect(walkNames("example.com")).toEqual(["example.com", "com"]);
  });

  it("the jump starts at exactly eight labels (§4.10 step 4: x >= 8)", () => {
    expect(walkNames("a.b.c.d.e.f.example.com")).toEqual([
      "a.b.c.d.e.f.example.com",
      "b.c.d.e.f.example.com",
      "c.d.e.f.example.com",
      "d.e.f.example.com",
      "e.f.example.com",
      "f.example.com",
      "example.com",
      "com",
    ]);
    expect(walkNames("b.c.d.e.f.example.com")).toHaveLength(7);
  });

  it("B.4.1 query count: two _dmarc queries for example.com, three for signing.example.com", async () => {
    const zone = {
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
      "_dmarc.signing.example.com": { TXT: ["v=DMARC1; p=none"] },
    };
    for (const [domain, expected] of [
      ["example.com", ["_dmarc.example.com TXT", "_dmarc.com TXT"]],
      ["signing.example.com", ["_dmarc.signing.example.com TXT", "_dmarc.example.com TXT", "_dmarc.com TXT"]],
    ] as const) {
      const resolver = zoneResolver(zone);
      await checkDmarc({ resolver }, domain);
      expect(
        resolver.asked.filter((q) => q.startsWith("_dmarc.") && !q.includes(`${domain}.${domain}`)),
        domain,
      ).toEqual(expected);
    }
  });

  it("B.4.3 query count: every name of the walk at once, one more than the RFC's sequential walk", async () => {
    const zone: Zone = {
      "_dmarc.bank.example": { TXT: ["v=DMARC1; p=reject; psd=y; rua=mailto:psd@bank.example"] },
      "_dmarc.giant.bank.example": { TXT: ["v=DMARC1; p=quarantine; rua=mailto:d@giant.bank.example"] },
    };
    for (const [domain, expected] of [
      // The RFC stops at bank.example (psd=y) and never asks _dmarc.example.
      ["giant.bank.example", ["_dmarc.giant.bank.example TXT", "_dmarc.bank.example TXT", "_dmarc.example TXT"]],
      [
        "mail.mega.bank.example",
        [
          "_dmarc.mail.mega.bank.example TXT",
          "_dmarc.mega.bank.example TXT",
          "_dmarc.bank.example TXT",
          "_dmarc.example TXT",
        ],
      ],
    ] as const) {
      const resolver = zoneResolver(zone);
      await checkDmarc({ resolver }, domain, { exists: "yes" });
      expect(
        resolver.asked.filter((q) => q.startsWith("_dmarc.") && !q.includes(`${domain}.${domain}`)),
        domain,
      ).toEqual(expected);
    }
  });

  // RFC 9990 §4.
  it("B.4.3: the PSD's rua needs no authorization, as the record was found at bank.example", async () => {
    const resolver = zoneResolver({
      "_dmarc.bank.example": { TXT: ["v=DMARC1; p=reject; psd=y; rua=mailto:psd@bank.example"] },
      "_dmarc.giant.bank.example": { TXT: ["v=DMARC1; p=quarantine; rua=mailto:d@giant.bank.example"] },
    });
    const r = await checkDmarc({ resolver }, "mail.mega.bank.example", { exists: "yes" });
    expect(r).toMatchObject({ foundAt: "bank.example", orgDomain: "mega.bank.example" });
    expect(ids(r)).not.toContain("dmarc-rua-unauthorized");
    expect(resolver.asked.some((q) => q.includes("_report"))).toBe(false);
  });

  it("psd=y on the name itself: it is its own Organizational Domain and its p applies", async () => {
    const r = await run(
      dmarc("v=DMARC1; p=reject; psd=y; rua=mailto:psd@bank.example", {}, "bank.example"),
      "bank.example",
    );
    expect(r).toMatchObject({
      foundAt: "bank.example",
      orgDomain: "bank.example",
      policyFrom: "p",
      effective: "reject",
      failed: false,
    });
    expect(ids(r)).toEqual(["dmarc-enforced"]);
  });

  // example.com and signing.example.com.
  it("B.4.1: both names have records, and example.com is the Organizational Domain of both", async () => {
    const ctx = {
      resolver: zoneResolver({
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject"] },
        "_dmarc.signing.example.com": { TXT: ["v=DMARC1; p=none"] },
      }),
    };
    expect(orgDomainOf(await treeWalk(ctx, "example.com"), "example.com")).toBe("example.com");
    expect(orgDomainOf(await treeWalk(ctx, "signing.example.com"), "signing.example.com")).toBe("example.com");
    const r = await checkDmarc(ctx, "example.com");
    expect(r).toMatchObject({ foundAt: "example.com", orgDomain: "example.com", policyFrom: "p", effective: "reject" });
  });

  it("B.4.2: the deep Author Domain takes example.com's record after the eight RFC queries", async () => {
    const resolver = zoneResolver({
      "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
      "_dmarc.signing.example.com": { TXT: ["v=DMARC1; p=none"] },
    });
    const domain = "a.b.c.d.e.f.g.h.i.j.k.example.com";
    const r = await checkDmarc({ resolver }, domain, { exists: "yes" });
    expect(r).toMatchObject({ foundAt: "example.com", orgDomain: "example.com", policyFrom: "p", effective: "reject" });
    const dmarcQueries = resolver.asked.filter((q) => q.startsWith("_dmarc.") && !q.includes(`${domain}.${domain}`));
    expect(dmarcQueries).toEqual([
      "_dmarc.a.b.c.d.e.f.g.h.i.j.k.example.com TXT",
      "_dmarc.g.h.i.j.k.example.com TXT",
      "_dmarc.h.i.j.k.example.com TXT",
      "_dmarc.i.j.k.example.com TXT",
      "_dmarc.j.k.example.com TXT",
      "_dmarc.k.example.com TXT",
      "_dmarc.example.com TXT",
      "_dmarc.com TXT",
    ]);
  });

  it("B.4.3: psd=y at bank.example makes the name below it the Organizational Domain", async () => {
    const zone: Zone = {
      "_dmarc.bank.example": { TXT: ["v=DMARC1; p=reject; psd=y; rua=mailto:psd@bank.example"] },
      "_dmarc.giant.bank.example": { TXT: ["v=DMARC1; p=quarantine; rua=mailto:d@giant.bank.example"] },
    };
    const ctx = { resolver: zoneResolver(zone) };
    expect(orgDomainOf(await treeWalk(ctx, "giant.bank.example"), "giant.bank.example")).toBe("giant.bank.example");
    expect(orgDomainOf(await treeWalk(ctx, "mail.giant.bank.example"), "mail.giant.bank.example")).toBe(
      "giant.bank.example",
    );
    expect(orgDomainOf(await treeWalk(ctx, "mail.mega.bank.example"), "mail.mega.bank.example")).toBe(
      "mega.bank.example",
    );
    const own = await checkDmarc(ctx, "giant.bank.example");
    expect(own).toMatchObject({
      foundAt: "giant.bank.example",
      orgDomain: "giant.bank.example",
      effective: "quarantine",
    });
    // mega.bank.example has no record, so for RFC 9989 the PSD's record applies, through sp/np/p.
    // RFC 7489 has no psd=y: no DMARC there, and the weaker reading counts.
    const psd = await checkDmarc(ctx, "mail.mega.bank.example", { exists: "yes" });
    expect(psd).toMatchObject({
      foundAt: "bank.example",
      orgDomain: "mega.bank.example",
      rfc7489: { orgDomain: "mega.bank.example" },
    });
    expect(psd.effective).toBeUndefined();
    expect(ids(psd)).toContain("dmarc-org-differs");
  });

  it("psd=n stops the walk and makes that name the Organizational Domain", async () => {
    const ctx = {
      resolver: zoneResolver({
        "_dmarc.mail.example.com": { TXT: ["v=DMARC1; p=reject; psd=n"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=none"] },
      }),
    };
    const steps = await treeWalk(ctx, "a.mail.example.com");
    expect(steps.map((s) => s.domain)).toEqual(["a.mail.example.com", "mail.example.com"]);
    expect(orgDomainOf(steps, "a.mail.example.com")).toBe("mail.example.com");
  });

  it("a subdomain with an intermediate record takes the highest one: a.mail.example.com is Protected", async () => {
    const r = await run(
      {
        "_dmarc.mail.example.com": { TXT: ["v=DMARC1; p=none"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; sp=reject; rua=mailto:d@example.com"] },
      },
      "a.mail.example.com",
      "yes",
    );
    expect(r).toMatchObject({
      foundAt: "example.com",
      orgDomain: "example.com",
      policyFrom: "sp",
      effective: "reject",
    });
    expect(ids(r)).toEqual(["dmarc-enforced"]);
  });
});

describe("repeated tags", () => {
  it("a repeated tag discards the record, like a bad v=", async () => {
    const r = await run(dmarc("v=DMARC1; p=reject; p=none; rua=mailto:d@example.com"));
    expect(ids(r)).toEqual(["dmarc-bad-version"]);
    expect(r.findings[0]).toMatchObject({
      severity: "critical",
      found: "v=DMARC1; p=reject; p=none; rua=mailto:d@example.com",
      vars: { reason: "repeated-tag", tag: "p" },
    });
    expect(r.effective).toBeUndefined();
    expect(r.record).toBeUndefined();
    expect(r.status).toBe("fail");
  });

  it("on a subdomain, the parent's record then applies and the finding is a warning when RFC 7489 agrees", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com; rua=mailto:e@example.com"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
      },
      "shop.example.com",
      "yes",
    );
    expect(ids(r)).toEqual(["dmarc-bad-version", "dmarc-enforced"]);
    expect(r.findings[0]?.severity).toBe("warning");
    expect(r).toMatchObject({ foundAt: "example.com", effective: "reject", status: "weak" });
  });

  it("p=reject; p=none under a parent at reject gives p=none: RFC 7489 counts the weaker value", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["v=DMARC1; p=reject; p=none"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
      },
      "shop.example.com",
      "yes",
    );
    expect(r).toMatchObject({ foundAt: "example.com", effective: "none", rfc7489: { effective: "none" } });
    expect(r.findings.find((f) => f.id === "dmarc-bad-version")?.severity).toBe("critical");
  });

  it("a repeated psd does not stop the walk", async () => {
    const ctx = {
      resolver: zoneResolver({
        "_dmarc.mail.example.com": { TXT: ["v=DMARC1; p=reject; psd=n; psd=n"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=none"] },
      }),
    };
    const steps = await treeWalk(ctx, "a.mail.example.com");
    expect(steps.map((s) => s.domain)).toEqual(["a.mail.example.com", "mail.example.com", "example.com", "com"]);
    expect(orgDomainOf(steps, "a.mail.example.com")).toBe("example.com");
  });
});
