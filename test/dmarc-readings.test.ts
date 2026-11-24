import { describe, expect, it } from "vitest";
import { checkDmarc } from "../src/checks/dmarc.ts";
import { isDmarcVersion7489 } from "../src/checks/dmarc-tags.ts";
import { walkNames } from "../src/checks/dmarc-walk.ts";
import { catalog } from "../src/index.ts";
import type { NameExists } from "../src/types.ts";
import { dmarc, run } from "./helpers/dmarc.ts";
import { ids } from "./helpers/findings.ts";
import { type Zone, zoneResolver } from "./helpers/zone.ts";

describe("two readings, RFC 9989 and RFC 7489", () => {
  const RUA = "rua=mailto:d@example.net";
  const runL = (
    zone: Zone,
    domain: string,
    list: readonly string[],
    exists: NameExists | undefined = "yes",
    rest: Readonly<Record<string, string>> = {},
  ) =>
    checkDmarc({ resolver: zoneResolver(zone) }, domain, {
      ...(exists ? { exists } : {}),
      psl: () => Promise.resolve(list),
      pslRest: () => Promise.resolve(rest),
    });

  it("V=DMARC1 is dmarc-bad-version; P=reject is a typo; p=REJECT applies", async () => {
    // RFC 7489 §6.4: the tag name is case-insensitive and the value exact, so V=DMARC1 counts there
    // and v=dmarc1 does not.
    expect(isDmarcVersion7489("V=DMARC1; p=none")).toBe(true);
    expect(isDmarcVersion7489("v=dmarc1; p=none")).toBe(false);
    const v = await run(dmarc("V=DMARC1; p=reject"));
    expect(ids(v)).toEqual(["dmarc-bad-version"]);
    expect(v.effective).toBeUndefined();
    expect((await run(dmarc("v=DMARC1; P=reject; rua=mailto:d@example.com"))).findings.map((f) => f.id)).toContain(
      "dmarc-tag-typo",
    );
    expect((await run(dmarc("v=DMARC1; p=REJECT; rua=mailto:d@example.com"))).effective).toBe("reject");
  });

  it("V=DMARC1; p=none under a parent at reject gives p=none (RFC 7489 reads V=)", async () => {
    const r = await run(
      {
        "_dmarc.shop.example.com": { TXT: ["V=DMARC1; p=none"] },
        "_dmarc.example.com": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] },
      },
      "shop.example.com",
      "yes",
    );
    expect(r).toMatchObject({ foundAt: "example.com", effective: "none" });
    expect(r.findings.find((f) => f.id === "dmarc-bad-version")?.severity).toBe("critical");
  });

  it("NXNAME with sp=reject; np=none applies none", async () => {
    expect(
      await run(
        dmarc("v=DMARC1; p=reject; sp=reject; np=none; rua=mailto:d@example.com"),
        "gone.example.com",
        "nxname",
      ),
    ).toMatchObject({ effective: "none", policyFrom: "np" });
  });

  // RFC 7489 reads sp=none for a name that does not exist; with sp absent or at reject it stays at
  // reject.
  it("np=reject with sp=none: a missing name is Spoofable for RFC 7489 receivers", async () => {
    expect(
      (
        await run(
          dmarc("v=DMARC1; p=reject; sp=none; np=reject; rua=mailto:d@example.com"),
          "gone.example.com",
          "nxdomain",
        )
      ).effective,
    ).toBe("none");
    for (const rec of [
      "v=DMARC1; p=reject; np=reject; rua=mailto:d@example.com",
      "v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:d@example.com",
    ]) {
      expect(await run(dmarc(rec), "gone.example.com", "nxdomain"), rec).toMatchObject({
        effective: "reject",
        policyFrom: "np",
      });
    }
  });

  // The Tree Walk reading is stronger; the weaker one (no DMARC) counts, with dmarc-org-differs.
  it("a.example.net under a listed example.net: the weaker PSL reading counts", async () => {
    const r = await runL({ "_dmarc.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] } }, "a.example.net", [
      "example.net",
    ]);
    expect(r.effective).toBeUndefined();
    expect(r.rfc7489).toEqual({ orgDomain: "a.example.net" });
    expect(r.findings.find((f) => f.id === "dmarc-org-differs")?.vars).toEqual({
      orgDomain: "example.net",
      policy: "reject",
      pslOrgDomain: "a.example.net",
      pslPolicy: "no DMARC policy",
      weaker: 1,
    });
  });

  // The PSL reading is stronger; the weaker one (the Tree Walk) counts, with dmarc-org-differs.
  it("b.a.example.net under a listed example.net: the weaker Tree Walk reading counts", async () => {
    const zone: Zone = {
      "_dmarc.example.net": { TXT: [`v=DMARC1; p=none; ${RUA}`] },
      "_dmarc.a.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] },
    };
    const r = await runL(zone, "b.a.example.net", ["example.net"]);
    expect(r).toMatchObject({
      foundAt: "example.net",
      effective: "none",
      rfc7489: { effective: "reject", orgDomain: "a.example.net" },
    });
    expect(r.findings.find((f) => f.id === "dmarc-org-differs")?.vars).toMatchObject({
      policy: "none",
      pslPolicy: "reject",
    });
    // Without the list both readings take example.net: no finding.
    expect(ids(await runL(zone, "b.a.example.net", []))).not.toContain("dmarc-org-differs");
  });

  it("the RFC 7489 record is read its own way: np is no tag there, pct lowers one level", async () => {
    const zone = (rec: string): Zone => ({
      "_dmarc.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] },
      "_dmarc.a.example.net": { TXT: [rec] },
    });
    expect((await runL(zone("v=DMARC1; p=reject; np=bogus"), "b.a.example.net", ["example.net"])).effective).toBe(
      "reject",
    );
    expect(await runL(zone(`v=DMARC1; p=reject; pct=50; ${RUA}`), "b.a.example.net", ["example.net"])).toMatchObject({
      effective: "quarantine",
      rfc7489: { effective: "quarantine", orgDomain: "a.example.net" },
    });
  });

  it("a suffix nested under a listed one takes the longest", async () => {
    const zone: Zone = {
      "_dmarc.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] },
      "_dmarc.y.x.example.net": { TXT: [`v=DMARC1; p=quarantine; ${RUA}`] },
    };
    const r = await runL(zone, "z.y.x.example.net", ["example.net", "x.example.net"]);
    expect(r).toMatchObject({ effective: "quarantine", rfc7489: { orgDomain: "y.x.example.net" } });
  });

  // As up.railway.app under railway.app.
  it("a rule under a non-rule ancestor at reject: no DMARC and dmarc-org-differs", async () => {
    const r = await runL({ "_dmarc.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] } }, "myapp.up.example.net", [
      "up.example.net",
    ]);
    expect(r.effective).toBeUndefined();
    expect(ids(r)).toContain("dmarc-org-differs");
  });

  // As a store under myshopify.com.
  it("a psd=y PSD over an Organizational Domain without a record: no DMARC for RFC 7489", async () => {
    const r = await runL(
      { "_dmarc.shop.example": { TXT: [`v=DMARC1; p=reject; psd=y; ${RUA}`] } },
      "store.shop.example",
      ["shop.example"],
    );
    expect(r).toMatchObject({ foundAt: "shop.example", rfc7489: { orgDomain: "store.shop.example" } });
    expect(r.effective).toBeUndefined();
    expect(ids(r)).toContain("dmarc-org-differs");
  });

  describe("an RFC 7489 Organizational Domain the list cannot give", () => {
    const orgDiffers = (r: Awaited<ReturnType<typeof runL>>) =>
      r.findings.find((f) => f.id === "dmarc-org-differs")?.vars;

    // The rest of the PSL decides where the list cannot, so these names get an answer.
    // TLD+1 has no record of its own.
    it("no listed suffix and the record two labels below TLD+1: the rest of the PSL decides", async () => {
      const zone: Zone = { "_dmarc.mail.example.com": { TXT: [`v=DMARC1; p=reject; sp=reject; ${RUA}`] } };
      // example.com is no rule: RFC 7489 stops there, with no record.
      const none = await runL(zone, "news.mail.example.com", []);
      // With no record there, RFC 7489 applies no DMARC: the list's Organizational Domain is named
      // (rfc7489, the finding's vars) but its SPF is not read (pslOrgDomain).
      expect(none).toMatchObject({ failed: false, rfc7489: { orgDomain: "example.com" } });
      expect(none.pslOrgDomain).toBeUndefined();
      expect(none.effective).toBeUndefined();
      expect(orgDiffers(none)).toEqual({
        orgDomain: "mail.example.com",
        policy: "reject",
        pslOrgDomain: "example.com",
        pslPolicy: "no DMARC policy",
        weaker: 1,
      });
      // example.com is a rule of the rest: mail.example.com is the Organizational Domain, as for
      // RFC 9989.
      const rule = await runL(zone, "news.mail.example.com", [], "yes", { com: "example" });
      expect(rule).toMatchObject({ failed: false, pslOrgDomain: "mail.example.com", effective: "reject" });
      expect(orgDiffers(rule)).toBeUndefined();
    });

    it("the rest of the PSL that does not load: Can't tell, the list's lookup failed", async () => {
      const zone: Zone = { "_dmarc.mail.example.com": { TXT: [`v=DMARC1; p=reject; ${RUA}`] } };
      const r = await checkDmarc({ resolver: zoneResolver(zone) }, "news.mail.example.com", {
        exists: "yes",
        psl: () => Promise.resolve([]),
        pslRest: () => Promise.reject(new Error("chunk")),
      });
      expect(r.failed).toBe(true);
      expect(r.status).toBe("unknown");
      // A list that did not load is not a DNS lookup that got no answer.
      expect(r.findings.find((f) => f.id === "lookup-failed")).toMatchObject({
        found: "Public Suffix List",
        vars: { reason: "not-loaded", list: "Public Suffix List" },
      });
    });

    // The text is the catalog's for that case.
    it("psd-dmarc that does not load: the same finding, with the text for a list that did not load", async () => {
      const zone: Zone = { "_dmarc.mail.example.com": { TXT: [`v=DMARC1; p=reject; ${RUA}`] } };
      const r = await checkDmarc({ resolver: zoneResolver(zone) }, "news.mail.example.com", {
        exists: "yes",
        psl: () => Promise.reject(new Error("chunk")),
      });
      const f = r.findings.find((x) => x.id === "lookup-failed");
      expect(f).toMatchObject({
        found: "Public Suffix List",
        vars: { reason: "not-loaded", list: "Public Suffix List" },
      });
      const entry = catalog.find((c) => c.id === "lookup-failed");
      const text = entry?.variants?.find((v) => f?.vars?.[v.when] !== undefined);
      expect(text?.title).toBe("The Public Suffix List did not load");
      expect(text?.fix).not.toMatch(/DNS host/);
    });

    it("the same with RFC 9989 at none and the list loaded: nothing failed, the group weak", async () => {
      const r = await runL(
        { "_dmarc.mail.example.com": { TXT: [`v=DMARC1; p=none; sp=none; ${RUA}`] } },
        "news.mail.example.com",
        [],
      );
      expect(r).toMatchObject({ failed: false, status: "weak" });
    });

    // With the RFC 9989 reading at none, the weaker of the two is none whatever RFC 7489 reads, so
    // a list chunk that does not load changes nothing: Spoofable. With any other policy it stays
    // unanswered.
    for (const [chunk, opts] of [
      ["psd-dmarc", { psl: () => Promise.reject(new Error("chunk")) }],
      ["psl-rest", { psl: () => Promise.resolve([]), pslRest: () => Promise.reject(new Error("chunk")) }],
    ] as const) {
      it(`${chunk} that does not load with RFC 9989 at none: no failure, the policy none stands`, async () => {
        const zone = (p: string): Zone => ({ "_dmarc.mail.example.com": { TXT: [`v=DMARC1; p=${p}; ${RUA}`] } });
        const none = await checkDmarc({ resolver: zoneResolver(zone("none")) }, "news.mail.example.com", {
          exists: "yes",
          ...opts,
        });
        expect(none).toMatchObject({ failed: false, effective: "none", status: "fail" });
        expect(ids(none)).not.toContain("lookup-failed");
        expect(ids(none)).toContain("dmarc-policy-none");
        // quarantine too: RFC 7489 may find no DMARC, so the list still decides.
        for (const p of ["reject", "quarantine"]) {
          const r = await checkDmarc({ resolver: zoneResolver(zone(p)) }, "news.mail.example.com", {
            exists: "yes",
            ...opts,
          });
          expect(r, p).toMatchObject({ failed: true, status: "unknown" });
        }
        const reject = await checkDmarc({ resolver: zoneResolver(zone("reject")) }, "news.mail.example.com", {
          exists: "yes",
          ...opts,
        });
        expect(reject.findings.find((f) => f.id === "lookup-failed")).toMatchObject({
          found: "Public Suffix List",
          vars: { reason: "not-loaded" },
        });
      });
    }

    it("TLD+1 with a record of its own is no hidden PSL rule: its record is the RFC 7489 one", async () => {
      const zone: Zone = {
        "_dmarc.example.com": { TXT: [`v=DMARC1; p=none; ${RUA}`] },
        "_dmarc.mail.example.com": { TXT: [`v=DMARC1; p=reject; sp=reject; ${RUA}`] },
      };
      const r = await runL(zone, "news.mail.example.com", []);
      // RFC 9989 takes example.com too (the record with the fewest labels): both readings agree.
      expect(r).toMatchObject({ failed: false, pslOrgDomain: "example.com", effective: "none" });
      expect(orgDiffers(r)).toBeUndefined();
    });

    it("under a listed suffix the record may sit far below: the suffix plus one label", async () => {
      const zone: Zone = {
        "_dmarc.example.com": { TXT: [`v=DMARC1; p=reject; ${RUA}`] },
        "_dmarc.b.a.example.com": { TXT: [`v=DMARC1; p=quarantine; ${RUA}`] },
      };
      const r = await runL(zone, "c.b.a.example.com", ["example.com"]);
      expect(r).toMatchObject({ failed: false, rfc7489: { orgDomain: "a.example.com" } });
      expect(r.pslOrgDomain).toBeUndefined();
      expect(orgDiffers(r)).toMatchObject({ pslOrgDomain: "a.example.com", pslPolicy: "no DMARC policy" });
    });

    it("a wildcard rule: listed, its instance is the suffix; in the rest of the PSL, the same", async () => {
      const zone: Zone = {
        "_dmarc.w.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] },
        "_dmarc.b.foo.w.example.net": { TXT: [`v=DMARC1; p=quarantine; ${RUA}`] },
      };
      const listed = await runL(zone, "c.b.foo.w.example.net", ["*.w.example.net"]);
      expect(listed).toMatchObject({
        failed: false,
        pslOrgDomain: "b.foo.w.example.net",
        rfc7489: { effective: "quarantine" },
      });
      // A record in an instance of a wildcard of the rest: the instance plus one label is the
      // Organizational Domain, with no record there.
      const instance: Zone = { "_dmarc.foo.w.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] } };
      const unlisted = await runL(instance, "a.foo.w.example.net", [], "yes", { "w.example.net": "*" });
      expect(unlisted).toMatchObject({ failed: false, rfc7489: { orgDomain: "a.foo.w.example.net" } });
      expect(unlisted.pslOrgDomain).toBeUndefined();
      expect(unlisted.effective).toBeUndefined();
    });

    it("an exception rule: its name is the Organizational Domain under the wildcard's parent", async () => {
      const zone: Zone = { "_dmarc.w.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] } };
      const r = await runL(zone, "a.keep.w.example.net", ["*.w.example.net", "!keep.w.example.net"]);
      expect(r).toMatchObject({ failed: false, rfc7489: { orgDomain: "keep.w.example.net" } });
      expect(r.pslOrgDomain).toBeUndefined();
      expect(orgDiffers(r)).toMatchObject({
        orgDomain: "w.example.net",
        pslOrgDomain: "keep.w.example.net",
        pslPolicy: "no DMARC policy",
      });
    });
  });

  it("a name of 9 labels whose RFC 7489 Organizational Domain the walk skips: that name is asked", async () => {
    const domain = "x.y.r6.r5.r4.r3.r2.example.net";
    const zone: Zone = {
      "_dmarc.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] },
      "_dmarc.y.r6.r5.r4.r3.r2.example.net": { TXT: [`v=DMARC1; p=quarantine; ${RUA}`] },
    };
    expect(walkNames(domain)).not.toContain("y.r6.r5.r4.r3.r2.example.net");
    const r = await runL(zone, domain, ["r6.r5.r4.r3.r2.example.net"]);
    expect(r).toMatchObject({
      effective: "quarantine",
      rfc7489: { effective: "quarantine", orgDomain: "y.r6.r5.r4.r3.r2.example.net" },
    });
  });

  it("the list that does not load leaves DMARC unanswered; a name with its own record never loads it", async () => {
    const zone: Zone = { "_dmarc.example.net": { TXT: [`v=DMARC1; p=reject; ${RUA}`] } };
    let loads = 0;
    const failing = () => (loads++, Promise.reject(new Error("chunk failed")));
    const r = await checkDmarc({ resolver: zoneResolver(zone) }, "a.example.net", { exists: "yes", psl: failing });
    expect(r).toMatchObject({ failed: true, status: "unknown" });
    expect(r.effective).toBeUndefined();
    const own = await checkDmarc({ resolver: zoneResolver(zone) }, "example.net", { exists: "yes", psl: failing });
    expect(own.effective).toBe("reject");
    expect(loads).toBe(1);
  });

  // up.railway.app is a real rule of src/data/psd-dmarc.ts; the record at railway.app is made up.
  it("the default loader loads src/data/psd-dmarc.ts: up.railway.app is a rule", async () => {
    const r = await checkDmarc(
      { resolver: zoneResolver({ "_dmarc.railway.app": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@example.com"] } }) },
      "myapp.up.railway.app",
      { exists: "yes" },
    );
    expect(r.rfc7489?.orgDomain).toBe("myapp.up.railway.app");
  });

  it("a CNAME at _dmarc is kept for the fixes", async () => {
    const r = await run({
      "_dmarc.example.com": { CNAME: ["example-com.dmarc.example.net"] },
      "example-com.dmarc.example.net": { TXT: ["v=DMARC1; p=none; rua=mailto:d@example.com"] },
    });
    expect(r).toMatchObject({ cname: "example-com.dmarc.example.net", effective: "none" });
  });
});
