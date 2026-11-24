import { describe, expect, it } from "vitest";
import { checkDmarc } from "../src/checks/dmarc.ts";
import { catalog, variantText } from "../src/index.ts";
import type { CatalogEntry } from "../src/types.ts";
import { dmarc } from "./helpers/dmarc.ts";
import { ids } from "./helpers/findings.ts";
import { type Zone, zoneResolver } from "./helpers/zone.ts";

// A receiver that follows RFC 7489 looks for the policy of x.<name> at the Organizational Domain
// the PSL gives for x.<name> (RFC 7489 §6.6.3 steps 3 and 5), never at a record of <name> below it.
// With no record there it applies no DMARC, so the subdomains are open for it while RFC 9989 closes
// them with the record of <name>: a variant of dmarc-subdomains-open with its own text and fix.
describe("subdomains read by RFC 7489 at their own Organizational Domain", () => {
  const RUA = "rua=mailto:d@example.com";
  const runR = (zone: Zone, domain: string, rest: Readonly<Record<string, string>> = {}) =>
    checkDmarc({ resolver: zoneResolver(zone) }, domain, {
      exists: "yes",
      psl: () => Promise.resolve([]),
      pslRest: () => Promise.resolve(rest),
    });
  const entry = catalog.find((c) => c.id === "dmarc-subdomains-open") as CatalogEntry;
  const text = (field: "why" | "fix", vars: Record<string, string | number> | undefined) =>
    variantText(entry, field, vars);

  for (const [domain, org, rest] of [
    ["shop.example.com", "example.com", {}],
    ["shop.example.co.uk", "example.co.uk", { uk: "co" }],
  ] as const) {
    it(`${domain} at p=reject with no record at ${org}: open for RFC 7489, the weaker reading counts`, async () => {
      const r = await runR({ [`_dmarc.${domain}`]: { TXT: [`v=DMARC1; p=reject; ${RUA}`] } }, domain, rest);
      expect(r).toMatchObject({ effective: "reject", subdomainsOpen: true, strongerOpen: false, status: "weak" });
      expect(ids(r)).not.toContain("dmarc-enforced");
      const open = r.findings.find((f) => f.id === "dmarc-subdomains-open");
      // sp and np are RFC 9989's, which closes them.
      expect(open?.vars).toEqual({
        sp: "reject",
        np: "reject",
        at: domain,
        pslOrgDomain: org,
        pslMissing: 1,
        weaker: 1,
      });
      expect(text("why", open?.vars)).toContain("where they find no DMARC record");
      expect(text("fix", open?.vars)).toMatch(/^Set sp=reject in the DMARC record at _dmarc\.\{pslOrgDomain\}/);
    });
  }

  it("a record at the RFC 7489 Organizational Domain that rejects closes them for both readings", async () => {
    const r = await runR(
      {
        "_dmarc.shop.example.com": { TXT: [`v=DMARC1; p=reject; ${RUA}`] },
        "_dmarc.example.com": { TXT: [`v=DMARC1; p=none; sp=reject; ${RUA}`] },
      },
      "shop.example.com",
    );
    expect(r).toMatchObject({ subdomainsOpen: false });
    expect(ids(r)).toEqual(["dmarc-enforced"]);
  });

  it("one with sp=none opens them for RFC 7489 only, and says where", async () => {
    const r = await runR(
      {
        "_dmarc.shop.example.com": { TXT: [`v=DMARC1; p=reject; psd=n; ${RUA}`] },
        "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; sp=none; ${RUA}`] },
      },
      "shop.example.com",
    );
    expect(r).toMatchObject({ subdomainsOpen: true, strongerOpen: false });
    const open = r.findings.find((f) => f.id === "dmarc-subdomains-open");
    expect(open?.vars).toEqual({
      sp: "reject",
      np: "reject",
      at: "shop.example.com",
      pslOrgDomain: "example.com",
      weaker: 1,
    });
    expect(text("why", open?.vars)).toContain("whose policy for them is none");
  });

  // RFC 9989 opens them with np=none, and the RFC 7489 Organizational Domain keeps them closed: the
  // base text, never “whose policy for them is none”.
  for (const parent of ["p=reject", "p=quarantine"]) {
    it(`np=none at the name and ${parent} at the list's Organizational Domain: the base variant`, async () => {
      const r = await runR(
        {
          "_dmarc.shop.example.com": { TXT: [`v=DMARC1; p=reject; np=none; psd=n; ${RUA}`] },
          "_dmarc.example.com": { TXT: [`v=DMARC1; ${parent}; ${RUA}`] },
        },
        "shop.example.com",
      );
      const open = r.findings.find((f) => f.id === "dmarc-subdomains-open");
      // The weaker reading of sp: quarantine when the list's Organizational Domain is at
      // quarantine.
      expect(open?.vars).toEqual({
        sp: parent === "p=reject" ? "reject" : "quarantine",
        np: "none",
        at: "shop.example.com",
      });
      expect(text("why", open?.vars)).not.toContain("whose policy for them is none");
    });
  }

  it("two records there (V=DMARC1 next to v=DMARC1): no DMARC for RFC 7489, and the text says why", async () => {
    const r = await runR(
      {
        "_dmarc.shop.example.com": { TXT: [`v=DMARC1; p=reject; psd=n; ${RUA}`] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject", "V=DMARC1; p=reject"] },
      },
      "shop.example.com",
    );
    const open = r.findings.find((f) => f.id === "dmarc-subdomains-open");
    expect(open?.vars).toEqual({
      sp: "reject",
      np: "reject",
      at: "shop.example.com",
      pslOrgDomain: "example.com",
      pslSeveral: 1,
      weaker: 1,
    });
    expect(text("why", open?.vars)).toContain("where they find more than one DMARC record");
    expect(text("fix", open?.vars)).toContain("If there is more than one, keep one and remove the others.");
  });

  // What cannot change the ruling row gives no Can't tell. Below reject, or with the subdomains
  // open, the subdomains change nothing; with aspf=r the list and a parent's _dmarc still decide
  // the Organizational Domain, whose SPF can make the name Spoofable, so they count unless the
  // policy is none (aspf=s is the control).
  describe("a reading without an answer that cannot change the ruling row", () => {
    const listless = (record: string, extra: Zone = {}) =>
      checkDmarc(
        { resolver: zoneResolver({ "_dmarc.shop.example.com": { TXT: [record] }, ...extra }) },
        "shop.example.com",
        { exists: "yes", psl: () => Promise.reject(new Error("chunk")) },
      );
    for (const tags of [
      "p=quarantine",
      "p=reject; sp=none",
      "p=reject; sp=none; np=reject",
      "p=reject; np=none",
      "p=reject; t=y",
      "p=reject; pct=50",
    ]) {
      it(`no list with ${tags}: answered with aspf=s, unanswered with aspf=r`, async () => {
        const strict = await listless(`v=DMARC1; ${tags}; aspf=s; ${RUA}`);
        expect(strict.failed).toBe(false);
        expect(ids(strict)).not.toContain("lookup-failed");
        const relaxed = await listless(`v=DMARC1; ${tags}; ${RUA}`);
        expect(relaxed.failed).toBe(true);
        expect(relaxed.findings.find((f) => f.id === "lookup-failed")?.found).toBe("Public Suffix List");
      });
    }
    it("no list with p=reject: unanswered, also with aspf=s (the subdomains)", async () => {
      expect((await listless(`v=DMARC1; p=reject; ${RUA}`)).failed).toBe(true);
      expect((await listless(`v=DMARC1; p=reject; aspf=s; ${RUA}`)).failed).toBe(true);
    });
    it("no list with p=none: answered", async () => {
      expect((await listless(`v=DMARC1; p=none; ${RUA}`)).failed).toBe(false);
    });
    const cases = [
      ["p=none", false],
      ["p=quarantine", true],
      ["p=reject", true],
      ["p=reject; t=y", true],
      ["p=none; aspf=s", false],
      ["p=quarantine; aspf=s", false],
      // effective (quarantine), not applied (reject), decides.
      ["p=reject; t=y; aspf=s", false],
      ["p=reject; aspf=s", true],
    ] as const;
    for (const [tags, failed] of cases) {
      it(`the parent's _dmarc unanswered, the name's own ${tags}: ${failed ? "unanswered" : "answered"}`, async () => {
        const zone: Zone = {
          "_dmarc.shop.example.com": { TXT: [`v=DMARC1; ${tags}; ${RUA}`] },
          "_dmarc.example.com": { $unreachable: true },
        };
        const r = await checkDmarc({ resolver: zoneResolver(zone) }, "shop.example.com", { exists: "yes" });
        expect(r.failed).toBe(failed);
        expect(ids(r).includes("lookup-failed")).toBe(failed);
      });
    }
  });

  it("a name of three labels the PSL makes a public suffix: its sp stands for its subdomains", async () => {
    const zone: Zone = { "_dmarc.app.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] } };
    const r = await checkDmarc({ resolver: zoneResolver(zone) }, "app.example.net", {
      exists: "yes",
      psl: () => Promise.resolve(["app.example.net"]),
    });
    expect(r).toMatchObject({ failed: false, effective: "reject", subdomainsOpen: false });
    expect(ids(r)).toContain("dmarc-enforced");
  });

  it("the rest of the PSL that does not load leaves DMARC unanswered", async () => {
    const r = await checkDmarc(
      { resolver: zoneResolver({ "_dmarc.shop.example.co.uk": { TXT: [`v=DMARC1; p=reject; ${RUA}`] } }) },
      "shop.example.co.uk",
      {
        exists: "yes",
        psl: () => Promise.resolve([]),
        pslRest: () => Promise.reject(new Error("chunk")),
      },
    );
    expect(r).toMatchObject({ failed: true, status: "unknown" });
    expect(r.findings.find((f) => f.id === "lookup-failed")).toMatchObject({
      found: "Public Suffix List",
      vars: { reason: "not-loaded" },
    });
  });

  it("two labels and a record of its own load no list: the name is its subdomains' Organizational Domain", async () => {
    let loads = 0;
    const never = () => (loads++, Promise.reject(new Error("not expected")));
    const r = await checkDmarc({ resolver: zoneResolver(dmarc(`v=DMARC1; p=reject; ${RUA}`)) }, "example.com", {
      exists: "yes",
      psl: never,
      pslRest: never,
    });
    expect(r).toMatchObject({ subdomainsOpen: false, status: "pass" });
    expect(loads).toBe(0);
  });
});
